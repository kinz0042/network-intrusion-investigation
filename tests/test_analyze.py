"""Synthetic boundary cases. No external capture needed for CI."""
import importlib.util
import io
from pathlib import Path
import socket
import tempfile
import unittest
import dpkt

spec=importlib.util.spec_from_file_location('analyze',Path(__file__).resolve().parents[1]/'scripts/analyze.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)


def request(ua='NetSupport Manager/1.3',uri='http://203.0.113.9/fakeurl.htm',method='POST'):
    return f'{method} {uri} HTTP/1.1\r\nHost: 203.0.113.9\r\nUser-Agent: {ua}\r\n\r\nCMD=POLL\n'.encode()


def packet(payload,seq=1,src='10.0.0.8',dst='203.0.113.9',port=443):
    tcp=dpkt.tcp.TCP(sport=50000,dport=port,seq=seq,flags=dpkt.tcp.TH_ACK|dpkt.tcp.TH_PUSH,data=payload)
    ip=dpkt.ip.IP(src=socket.inet_aton(src),dst=socket.inet_aton(dst),p=6,data=tcp);ip.len=len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b'\x00'*6,dst=b'\x01'*6,type=0x800,data=ip))


def der(tag,value):
    n=len(value)
    length=bytes([n]) if n<128 else b'\x81'+bytes([n])
    return bytes([tag])+length+value


def asreq(name):
    principal=der(0xa1,der(0x30,der(0xa1,der(0x30,der(0x1b,name.encode())))))
    body=der(0x6a,der(0x30,der(0xa4,der(0x30,principal+der(0xa2,der(0x1b,b'EXAMPLE.TEST'))))))
    return len(body).to_bytes(4,'big')+body


class DetectionTests(unittest.TestCase):
    def classified(self,payload,approved=(),port=443):
        r=a.http_request(payload)
        return a.classify({**r,'src':'10.0.0.8','dst':'203.0.113.9','dport':port},approved) if r else None

    def test_match_on_443(self):self.assertEqual(self.classified(request()),'review_remote_support')
    def test_match_on_8080(self):self.assertEqual(self.classified(request(),port=8080),'review_remote_support')
    def test_approved_pair(self):self.assertEqual(self.classified(request(),[('10.0.0.8','203.0.113.9')]),'approved_remote_support')
    def test_other_source_not_suppressed(self):self.assertEqual(self.classified(request(),[('10.0.0.7','203.0.113.9')]),'review_remote_support')
    def test_ua_only_insufficient(self):self.assertIsNone(self.classified(request(uri='/support')))
    def test_path_only_insufficient(self):self.assertIsNone(self.classified(request(ua='Mozilla/5.0')))
    def test_get_not_post(self):self.assertIsNone(self.classified(request(method='GET')))
    def test_tls_not_http(self):self.assertIsNone(a.http_request(b'\x16\x03\x03\x00\x08encrypted'))
    def test_incomplete_header(self):self.assertIsNone(a.http_request(request().split(b'\r\n\r\n')[0]))
    def test_duplicate_header_rejected(self):self.assertIsNone(a.http_request(request().replace(b'Host:',b'Host: other\r\nHost:')))
    def test_lf_headers(self):self.assertEqual(self.classified(request().replace(b'\r\n',b'\n')),'review_remote_support')
    def test_absolute_uri_query(self):self.assertEqual(self.classified(request(uri='http://203.0.113.9/fakeurl.htm?x=1')),'review_remote_support')
    def test_principal_structural(self):self.assertEqual(a.as_request(asreq('analyst'))['principal'],'analyst')
    def test_principal_length_mismatch(self):self.assertIsNone(a.as_request(asreq('analyst')[:-1]))
    def test_no_string_scanning(self):self.assertIsNone(a.as_request(b'analyst EXAMPLE.TEST'))
    def test_der_truncated(self):
        with self.assertRaises(ValueError):a.tlvs(b'\x30\x82\x01')
    def test_der_indefinite(self):
        with self.assertRaises(ValueError):a.tlvs(b'\x30\x80\x00\x00')
    def test_pipeline_retransmission_and_cadence(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'synthetic.pcap'
            with path.open('wb') as f:
                w=dpkt.pcap.Writer(f)
                for ts,seq in [(0,1),(1,1),(60,1000),(120,2000)]:w.writepkt(packet(request(),seq),ts=1700000000+ts)
            r=a.analyze(path)
            self.assertEqual(r['counts']['frames'],4)
            self.assertEqual(r['counts']['duplicate_tcp_payload_segments'],1)
            self.assertEqual(len(r['http_requests']),3)
            self.assertEqual(r['triage_groups'][0]['median_interval_seconds'],60)
            self.assertEqual(r['flows'][0]['packets'],4)
    def test_malformed_frame_counted(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'bad.pcap'
            with path.open('wb') as f:dpkt.pcap.Writer(f).writepkt(b'x',ts=1)
            self.assertEqual(a.analyze(path)['counts']['packet_parse_errors'],1)
    def test_unsupported_linktype_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'raw.pcap'
            with path.open('wb') as f:dpkt.pcap.Writer(f,linktype=101).writepkt(b'x',ts=1)
            with self.assertRaises(ValueError):a.analyze(path)


if __name__=='__main__':unittest.main()
