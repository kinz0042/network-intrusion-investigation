# Validation

## Executed locally

Python 3.12.14, dpkt 1.9.8, 15 November 2026.

20 synthetic tests passed. Cases cover matching traffic on ports 443 and 8080, an approved endpoint pair, an unapproved source, UA-only and path-only false positives, GET requests, TLS bytes, incomplete and duplicate headers, LF-only headers, absolute URIs, structured principal parsing, truncated lengths, indefinite DER, retransmission deduplication, cadence, malformed Ethernet and unsupported capture link types.

The real capture analysis passed the case assertions. These pin integrity and expected observations for regression detection. They are not independent ground truth. Synthetic fixtures exercise boundaries without redistributing the source capture.

## Hosted checks

The workflow has two jobs. One runs synthetic tests and saved-evidence assertions. The other installs TShark from Ubuntu packages, obtains the original hash-pinned capture, regenerates the evidence, compares it byte-for-byte and independently verifies the key HTTP frame and total frame count.

Check the run conclusion before claiming hosted checks passed. TShark was not available on the initial local runtime. No local Zeek, Suricata or Wireshark GUI execution is claimed.

## Not established

No enterprise false-positive rate, recall benchmark, production deployment, endpoint process execution, successful containment, credential compromise or exfiltration verdict. The sample is one alert-led training case. Approval-list tests are synthetic, not a measured enterprise baseline.
