#!/usr/bin/env python3
"""Offline, packet-local evidence extraction. Never executes or exports objects."""
import argparse
import csv
import hashlib
import ipaddress
import json
import socket
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
import dpkt


def utc(ts):
    return datetime.fromtimestamp(float(ts), timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def tlvs(data):
    """Definite-length DER only; reject truncated/high-tag/indefinite encodings."""
    result, i = [], 0
    while i < len(data):
        if i + 2 > len(data): raise ValueError('truncated DER')
        tag, length = data[i:i+2]; i += 2
        if tag & 31 == 31: raise ValueError('high tag unsupported')
        if length & 128:
            count = length & 127
            if not 1 <= count <= 4 or i + count > len(data): raise ValueError('bad DER length')
            length = int.from_bytes(data[i:i+count], 'big'); i += count
        if i + length > len(data): raise ValueError('truncated DER value')
        result.append((tag, data[i:i+length])); i += length
    return result


def at(data, *path):
    for tag in path:
        values = [v for t, v in tlvs(data) if t == tag]
        if len(values) != 1: raise ValueError('missing or ambiguous field')
        data = values[0]
    return data


def as_request(payload):
    """Single TCP segment containing complete length-prefixed Kerberos AS-REQ."""
    if len(payload) < 4 or int.from_bytes(payload[:4], 'big') != len(payload)-4: return None
    try:
        body = at(payload[4:], 0x6a, 0x30, 0xa4, 0x30)
        principal = at(body, 0xa1, 0x30, 0xa1, 0x30)
        names = [v.decode('utf-8') for t, v in tlvs(principal) if t == 0x1b]
        realm = at(body, 0xa2, 0x1b).decode('utf-8')
        return {'principal': '/'.join(names), 'realm': realm} if names else None
    except (ValueError, UnicodeError): return None


def http_request(payload):
    # No TCP reassembly. A header must start and end in this packet.
    normalized = payload.replace(b'\r\n', b'\n')
    if b'\n\n' not in normalized: return None
    head, body = normalized.split(b'\n\n', 1)
    lines = head.split(b'\n')
    first = lines[0].split(b' ')
    if len(first) != 3 or first[0] not in (b'GET', b'POST', b'HEAD', b'PUT') or not first[2].startswith(b'HTTP/1.'): return None
    headers = {}
    for line in lines[1:]:
        if b':' not in line: return None
        k,v = line.split(b':',1); k=k.decode('ascii', 'replace').lower()
        if k in headers: return None  # avoid ambiguous duplicate fields
        headers[k] = v.strip().decode('ascii','replace')
    uri = first[1].decode('ascii','replace')
    return {'method':first[0].decode(), 'uri':uri, 'path':urlsplit(uri).path,
            'host':headers.get('host',''), 'user_agent':headers.get('user-agent',''),
            'poll_command': b'CMD=POLL' in body.splitlines()}


def classify(r, approved):
    """Triage candidates, not a malware verdict. Exact endpoint-pair allowlist."""
    if r['method'] != 'POST' or r['path'] != '/fakeurl.htm' or r['user_agent'].lower() != 'netsupport manager/1.3': return None
    if (r['src'], r['dst']) in approved: return 'approved_remote_support'
    return 'review_remote_support'


def analyze(path, approved=()):
    counts=Counter(); flows={}; http=[]; dns=[]; identities=[]; responses=[]; seen=set(); first=None; last=None
    with open(path,'rb') as f:
        reader=dpkt.pcap.Reader(f)
        if reader.datalink() != dpkt.pcap.DLT_EN10MB: raise ValueError('Ethernet PCAP required')
        for frame,(ts,buf) in enumerate(reader,1):
            ts=float(ts); first=ts if first is None else first; last=ts; counts['frames']+=1
            try:
                eth=dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data,dpkt.ip.IP): counts['non_ipv4']+=1; continue
                ip=eth.data
                if ip.offset or ip.mf: counts['fragmented_ipv4_skipped']+=1; continue
                t=ip.data
                if not isinstance(t,(dpkt.tcp.TCP,dpkt.udp.UDP)): counts['other_ipv4']+=1; continue
                src=socket.inet_ntoa(ip.src);dst=socket.inet_ntoa(ip.dst)
                proto='tcp' if isinstance(t,dpkt.tcp.TCP) else 'udp'
                base={'frame':frame,'time_utc':utc(ts),'src':src,'sport':t.sport,'dst':dst,'dport':t.dport}
                endpoints=sorted([(src,t.sport),(dst,t.dport)])
                key=(proto,*endpoints[0],*endpoints[1])
                flow=flows.setdefault(key,{'protocol':proto,'a_ip':key[1],'a_port':key[2],'b_ip':key[3],'b_port':key[4], 'first_frame':frame,'first_utc':utc(ts),'last_frame':frame,'last_utc':utc(ts),'packets':0,'captured_bytes':0})
                flow['last_frame']=frame;flow['last_utc']=utc(ts);flow['packets']+=1;flow['captured_bytes']+=len(buf)
                payload=bytes(t.data)
                if proto=='tcp':
                    fingerprint=(src,t.sport,dst,t.dport,t.seq,hashlib.sha256(payload).digest())
                    if payload and fingerprint in seen: counts['duplicate_tcp_payload_segments']+=1; continue
                    if payload: seen.add(fingerprint)
                    request=http_request(payload)
                    if request:
                        request={**base,**request};request['classification']=classify(request,approved) or 'other_http';http.append(request)
                    if payload.startswith(b'HTTP/1.'):
                        normalized=payload.replace(b'\r\n',b'\n')
                        if b'\n\n' in normalized:
                            head,body=normalized.split(b'\n\n',1)
                            # Header-only excerpts; never retain or export response objects.
                            responses.append({**base,'headers':head.decode('ascii','replace'),'body_prefix_hex':body[:12].hex()})
                    if t.dport==88:
                        identity=as_request(payload)
                        if identity:identities.append({**base,'kind':'kerberos_as_request',**identity})
                elif t.sport==53 or t.dport==53:
                    try:
                        message=dpkt.dns.DNS(payload)
                        if message.qr:
                            for answer in message.an:
                                if answer.type==dpkt.dns.DNS_A:dns.append({**base,'name':answer.name,'address':socket.inet_ntoa(answer.ip)})
                    except (dpkt.UnpackError,ValueError):counts['dns_parse_errors']+=1
                if proto=='udp' and {t.sport,t.dport}=={67,68}:
                    try:
                        dhcp=dpkt.dhcp.DHCP(payload)
                        options=dict(dhcp.opts)
                        if 12 in options:
                            identity={**base,'kind':'dhcp_hostname','hostname':options[12].decode('ascii','replace'),'client_mac':dhcp.chaddr[:dhcp.hln].hex(':')}
                            if len(options.get(50,b''))==4:identity['requested_ip']=socket.inet_ntoa(options[50])
                            identities.append(identity)
                    except dpkt.UnpackError:counts['dhcp_parse_errors']+=1
            except (dpkt.UnpackError,ValueError,IndexError): counts['packet_parse_errors']+=1
    candidates=[r for r in http if r['classification']=='review_remote_support']
    groups={}
    for r in candidates:groups.setdefault((r['src'],r['dst']),[]).append(r)
    cadence=[]
    for (src,dst),rows in groups.items():
        times=[datetime.fromisoformat(r['time_utc'].replace('Z','+00:00')).timestamp() for r in rows]
        intervals=[b-a for a,b in zip(times,times[1:])]
        cadence.append({'src':src,'dst':dst,'requests':len(rows),'first_frame':rows[0]['frame'],'last_frame':rows[-1]['frame'], 'median_interval_seconds':round(statistics.median(intervals),6) if intervals else None, 'intervals_under_1_second':sum(x<1 for x in intervals),'note':'Packet-local deduplicated request starts. Regular timing alone does not prove C2.'})
    return {'capture_sha256':hashlib.sha256(Path(path).read_bytes()).hexdigest(),'capture_bytes':Path(path).stat().st_size,'first_utc':utc(first) if first is not None else None,'last_utc':utc(last) if last is not None else None,'counts':dict(sorted(counts.items())),'flows':list(flows.values()),'http_requests':http,'response_headers':responses,'dns_answers':dns,'identities':identities,'triage_groups':cadence,'limitations':['Ethernet classic PCAP and IPv4 only.','No TCP reassembly, IP fragment reassembly, TLS decryption, object export, or execution.','HTTP headers and Kerberos AS-REQ must fit in one segment. Missing output is not evidence of absence.','Flow rows aggregate endpoint tuples across the capture, not individual TCP sessions.','Identity observations do not establish who executed a process.']}


def write_outputs(result,output):
    output=Path(output);output.mkdir(parents=True,exist_ok=True)
    (output/'analysis.json').write_text(json.dumps(result,indent=2)+'\n')
    for name in ('http_requests','response_headers','dns_answers','identities','flows','triage_groups'):
        rows=result[name]
        keys=list(dict.fromkeys(k for row in rows for k in row))
        with (output/(name+'.csv')).open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=keys);w.writeheader();w.writerows(rows)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('pcap',type=Path);p.add_argument('--out',type=Path,default=Path('evidence'));p.add_argument('--approved-pairs',type=Path)
    a=p.parse_args();approved=[]
    if a.approved_pairs:
        approved=[tuple(x) for x in json.loads(a.approved_pairs.read_text())]
        for pair in approved:
            if len(pair)!=2:raise ValueError('allowlist entries must contain source and destination')
            for address in pair:ipaddress.ip_address(address)
    write_outputs(analyze(a.pcap,approved),a.out)
