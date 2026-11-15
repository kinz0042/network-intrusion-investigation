#!/usr/bin/env python3
"""Fetch only the source PCAP. Verify archive and capture before use."""
import hashlib
from pathlib import Path
import urllib.request
import zipfile

URL='https://www.malware-traffic-analysis.net/2026/11/10/2026-11-10-traffic-analysis-exercise.pcap.zip'
CAPTURE='2026-11-10-traffic-analysis-exercise.pcap'
PCAP_SHA='b52bd2a4ec9d747266206e10df01283197cc3e8ace8af20f1c1e5fb8f0b61533'
ZIP_SHA='315c1d40f49578d48063c73dcec5746604d5d7b5c9082661e4bd0df5db5fbfa5'

def main():
    root=Path('source');root.mkdir(exist_ok=True)
    archive=root/'capture.zip'
    with urllib.request.urlopen(URL,timeout=60) as response: blob=response.read(40_000_001)
    if len(blob)>40_000_000:raise ValueError('archive exceeds expected size limit')
    if hashlib.sha256(blob).hexdigest()!=ZIP_SHA:raise ValueError('archive digest mismatch')
    archive.write_bytes(blob)
    with zipfile.ZipFile(archive) as z:
        if z.namelist()!=[CAPTURE] or z.getinfo(CAPTURE).file_size!=31_077_208:raise ValueError('unexpected archive contents')
        # Public archive password scheme documented on the source About page.
        data=z.read(CAPTURE,pwd=b'infected_20261110')
    if hashlib.sha256(data).hexdigest()!=PCAP_SHA:raise ValueError('capture digest mismatch')
    (root/CAPTURE).write_bytes(data)
    print(root/CAPTURE)

if __name__=='__main__':main()
