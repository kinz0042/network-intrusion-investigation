#!/usr/bin/env python3
"""Fail closed when saved or freshly generated case evidence changes."""
import json
from pathlib import Path
import sys

r=json.loads(Path(sys.argv[1] if len(sys.argv)>1 else 'evidence/analysis.json').read_text())
assert r['capture_sha256']=='b52bd2a4ec9d747266206e10df01283197cc3e8ace8af20f1c1e5fb8f0b61533'
assert r['capture_bytes']==31077208
assert r['counts']['frames']==30182
assert len(r['http_requests'])==139
assert len(r['dns_answers'])==322
assert len(r['identities'])==12
assert len(r['flows'])==392
assert r['counts']['dns_parse_errors']==8
assert r['counts']['duplicate_tcp_payload_segments']==562
assert len(r['triage_groups'])==1
assert r['triage_groups'][0]['requests']==125
assert r['triage_groups'][0]['median_interval_seconds']==60.134689
first=next(x for x in r['http_requests'] if x['frame']==24675)
assert (first['src'],first['dst'],first['dport'])==('10.11.10.147','93.152.209.36',443)
assert first['poll_command'] and first['user_agent']=='NetSupport Manager/1.3'
assert first['time_utc']=='2026-11-10T18:22:07.728744Z'
assert any(x['frame']==3 and x['hostname']=='DESKTOP-5OMVI3L' and x['requested_ip']=='10.11.10.147' and x['client_mac']=='00:12:f0:e5:17:43' for x in r['identities'])
assert any(x['frame']==902 and x['principal']=='edward.winslow' for x in r['identities'])
assert any(x['frame']==24677 and 'NetSupport Gateway/1.92' in x['headers'] for x in r['response_headers'])
print('Case evidence assertions passed')
