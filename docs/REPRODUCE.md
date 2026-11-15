# Reproduce the investigation

Use an isolated Linux analysis environment. The workflow reads packets offline. It never connects to the captured destinations, executes a captured script or exports downloaded objects.

## Source

Brad Duncan / Malware-Traffic-Analysis.net, [The Lucky Turkey, 10 November 2026](https://www.malware-traffic-analysis.net/2026/11/10/index.html). The prompt names the alert destination before analysis. This is not a blind malware-family benchmark.

The raw PCAP remains with the source provider. No redistribution license for the full capture was established, so it is excluded from this repository. Source material remains under its owner's terms. Original project code may be reviewed and run, but this repository does not grant rights to third-party captures.

The fetch script checks the archive SHA-256, permits exactly the expected PCAP member, checks its size and checks the extracted SHA-256. It writes the member directly without using an archive path as an output path. The public archive password scheme is described on the provider's About page.

## Local run

Run commands from the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
python3 scripts/fetch_capture.py
python3 scripts/analyze.py source/2026-11-10-traffic-analysis-exercise.pcap --out rerun
python3 scripts/verify_case.py rerun/analysis.json
diff evidence/analysis.json rerun/analysis.json
```

The saved JSON should reproduce byte-for-byte. CSV files are convenience exports from the same result. The original capture does not need to be uploaded to GitHub. The input file name is not used as an integrity check. Its digest is.

## Optional independent check

Install TShark from your operating system's official package source, then run:

```bash
python3 scripts/verify_tshark.py source/2026-11-10-traffic-analysis-exercise.pcap
```

The independent check produces `tshark-validation.json`. The GitHub workflow runs this on a hosted Ubuntu runner. Source availability can affect the network-dependent job. The synthetic test job does not download a capture.

## Limits

- Classic PCAP, Ethernet, IPv4. Unsupported link types fail explicitly.
- TCP payload duplicates are identified by endpoint tuple, sequence and payload digest. This is not full TCP session reconstruction.
- HTTP headers and Kerberos AS-REQ must fit in one packet. IP fragments are skipped and counted.
- DNS A answers are observations. Duplicate observations are retained. Eight DNS parsing failures are reported for this capture.
- Kerberos parsing reads a strict definite-length DER field path. It does not decrypt tickets or assert successful human authentication.
- DHCP fields are client claims, not independently verified inventory.
- Response evidence stores headers and a 12-byte body prefix, never reconstructed files.
- No checksums, capture authenticity or endpoint behavior can be established merely by matching a download hash. The hash establishes byte identity with the recorded source copy.
