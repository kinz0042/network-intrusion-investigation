# Remote-support triage logic

Status: Python implementation tested against the source capture and synthetic cases. This is a triage heuristic, not a production IDS signature.

Match a packet-local HTTP request when all three conditions hold:

- Method is POST.
- Parsed URI path is /fakeurl.htm.
- User-Agent equals NetSupport Manager/1.3, case-insensitively.

Apply an explicit approved source/destination pair list after the match. Retain approved matches as `approved_remote_support` rather than deleting them. Unapproved matches become `review_remote_support`. Destination port and exact external IP are not match requirements. This allows detection when the same visible protocol moves to another port or address.

## Tuning and failure modes

A legitimate NetSupport deployment can match. Approval records, expected destinations and software inventory decide whether to escalate. The included approved-pair JSON uses documentation addresses only. Do not add the exercise endpoint to your real approval list.

An attacker can change the user agent or URI, use TLS or split headers between TCP segments. This extractor will miss those cases. A truncated header is rejected. A conflicting duplicate header is rejected. Packet-local HTTP is only one visibility layer. Deploy equivalent normalized HTTP logic in an established network sensor after validating its field semantics and reassembly behavior.

Cadence is reported separately. It does not turn a generic HTTP exchange into a malware verdict. The exact IP and domains are historical exercise indicators, not a maintained blocklist.

## Commands

```bash
python3 scripts/analyze.py source/2026-11-10-traffic-analysis-exercise.pcap --out rerun
python3 scripts/analyze.py your-capture.pcap --approved-pairs detections/approved-pairs.example.json --out rerun
```

## Independent Wireshark review

Open the source PCAP offline. Use `ip.addr == 93.152.209.36 && tcp.port == 443`. Inspect frame 24675. If automatic dissection does not expose HTTP, use Decode As → HTTP for that TCP port. Inspect the readable request bytes and frame 24677 response. Port 443 is not proof of TLS.

CLI equivalent:

```bash
tshark -n -r source/2026-11-10-traffic-analysis-exercise.pcap -d tcp.port==443,http -Y 'frame.number == 24675' -V
```

The workflow runs a narrow independent TShark check. See its actual run before claiming it passed. The check verifies frame count and key packet fields, not complete agreement on all HTTP transactions.
