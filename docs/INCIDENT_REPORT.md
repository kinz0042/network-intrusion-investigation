# NetSupport traffic investigation

Case NS-2026-1110 | Analyst: Kingsley Eze | Analysis: 15 November 2026

## Decision

Escalate the Windows client 10.11.10.147 for suspected unauthorized remote access. The exercise supplied a NetSupport alert. Packet inspection independently confirms readable NetSupport protocol markers, request/response exchange and repeated polling to that destination. Confirm whether the software and destination are approved before treating the activity as an organizational incident.

This is an investigation of a public training capture, not an incident at a real employer. The source answer page was not used. The capture alone does not prove credential theft, lateral movement, persistence or data exfiltration.

## Scope and integrity

30,182 frames, 31,077,208 bytes. Capture window: 2026-11-10 18:19:52.691329 through 20:24:53.906422 UTC.

SHA-256: `b52bd2a4ec9d747266206e10df01283197cc3e8ace8af20f1c1e5fb8f0b61533`

Evidence is indexed by original frame number. The parser performs no reassembly or decryption. It extracted 139 packet-local HTTP requests, 322 DNS A-answer observations, 12 identity observations and 392 endpoint-tuple flow aggregates. These are observations, not unique domains, users or TCP sessions. It counted 562 duplicate TCP payload segments and eight DNS parse errors. DNS failures remain a visibility gap.

## Evidence ledger

| Finding | Frame | UTC | Interpretation and limit |
| --- | ---: | --- | --- |
| DHCP host name DESKTOP-5OMVI3L, MAC 00:12:f0:e5:17:43, requested IP 10.11.10.147 | 3 | 18:19:52.746570 | DHCP request binds these fields as a client claim. Corroborate with DHCP lease and endpoint inventory. |
| Kerberos AS-REQ principal edward.winslow from 10.11.10.147 | 902 | 18:20:14.476774 | Protocol field extracted structurally, not by searching random text. Does not identify the person who launched the remote tool. |
| DNS answer vericheckusgo[.]com → 96.62.224[.]200 | 11073 | See DNS CSV | Resolution precedes a request from this client. A DNS answer alone does not establish maliciousness. |
| HTTP GET / to vericheckusgo[.]com with WindowsPowerShell user agent | 11078 | 18:21:49.930518 | Consistent with scripted retrieval. A user agent can be spoofed and is not endpoint process evidence. |
| HTTP 200 response declared text/html | 11080 | See response CSV | Packet body begins with script-like text. No script was executed or exported. |
| GET /5555.mp4 from 96.62.224[.]200 | 19855 | 18:21:59.047002 | Retrieval precedes NetSupport traffic. Temporal order alone does not prove causal execution. |
| HTTP 200 declares video/mp4 and Content-Length 6045311 | 19857 | See response CSV | Body prefix contains an MP4 ftyp marker. Filename, MIME type and prefix do not establish whether content is safe or how it was used. |
| DNS answer dasiiiitt[.]com → 93.152.209[.]36 | 24671 | See DNS CSV | Links a name to the alert endpoint at this point in the capture. |
| First TCP connection packet to alert endpoint, destination port 443 | 24672 | 18:22:07.509531 | Connection start. This is earlier than the first application request. |
| POST /fakeurl.htm, NetSupport Manager/1.3, CMD=POLL | 24675 | 18:22:07.728744 | First observed NetSupport request. Readable HTTP on port 443. Port 443 does not establish TLS encryption. |
| HTTP 200 with NetSupport Gateway/1.92 server header | 24677 | 18:22:07.906857 | Corroborates request marker with a responding peer. Product strings remain spoofable. |
| Last matching POST | 30177 | 20:24:25.096613 | Capture ends shortly afterward. This is not evidence that the activity stopped permanently. |

Full timestamps and endpoint ports are in [HTTP requests](../evidence/http_requests.csv), [DNS answers](../evidence/dns_answers.csv), [identity observations](../evidence/identities.csv) and [response headers](../evidence/response_headers.csv).

## Competing explanations

| Explanation | Evidence for it | Evidence still needed |
| --- | --- | --- |
| Unauthorized remote access | Source alert, NetSupport request and response markers, repeated traffic to the alert endpoint, preceding retrieval activity | Endpoint process tree, signed binary and hash, configuration, installation source, approval records |
| Approved remote support | NetSupport can serve legitimate remote-support purposes | Ticket, approved source/destination pair, application owner, documented maintenance window |
| Spoofed protocol markers | HTTP headers can be copied | Independent endpoint telemetry or protocol validation beyond markers |

125 deduplicated packet-local requests match the combined method, path and user-agent logic. Their median consecutive interval is 60.134689 seconds. Two initial intervals are under one second. Cadence supports repeated communication, not proof of C2 by itself.

## Response plan

1. Validate the host and current address against DHCP leases and endpoint inventory. Preserve the original capture and hash.
2. Check approved remote-support inventory and tickets for this host and destination. Record the decision and approver.
3. If unauthorized, isolate through the endpoint platform under the incident procedure. Preserve volatile evidence before destructive remediation where feasible.
4. Collect process ancestry, executable signatures and hashes, scheduled tasks, services, recent downloads, PowerShell logs and remote-tool configuration. Investigate the retrieval sequence without executing recovered content.
5. Scope DNS/proxy/flow history for both destination addresses and domains. Distinguish historical indicators from current reputation. Hunt the behavior as well as the exact indicators.
6. Review account sign-ins and sessions for edward.winslow. Revoke or rotate credentials if evidence and policy justify it. The packet principal alone does not prove credential compromise.
7. Remove unauthorized software after preservation. Rebuild if required by the incident findings. Confirm clean telemetry and restore access through the incident owner.

These are proposed actions. No real endpoint was isolated, account changed or external indicator contacted during this project.

## ATT&CK interpretation

T1219 Remote Access Tools is a supported hypothesis for the observed remote-tool exchange in the supplied alert context. T1071.001 Web Protocols describes the HTTP transport. This mapping describes behavior and does not establish attribution. PowerShell execution and ingress transfer are investigative leads until endpoint or fuller content evidence supports them.

## Sources

- [Source exercise and context](https://www.malware-traffic-analysis.net/2026/11/10/index.html)
- [Source handling and archive scheme](https://www.malware-traffic-analysis.net/about.html)
- [MITRE T1219](https://attack.mitre.org/techniques/T1219/)
- [MITRE T1071.001](https://attack.mitre.org/techniques/T1071/001/)
