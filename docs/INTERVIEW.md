# Explain the case in an interview

Use these prompts to understand the work. Do not claim steps you have not personally reviewed or performed.

## Two-minute walkthrough

- Start with the decision: the client needs investigation for suspected unauthorized remote access, subject to checking approved support activity.
- Explain integrity: name the source, hash the capture, keep frame numbers and use UTC.
- Show frame 3 for the client DHCP identity and frame 902 for the Kerberos principal. Explain why neither proves who ran the remote tool.
- Show frame 24675. Its readable HTTP request goes to TCP port 443. Explain why port number and encryption are different facts.
- Show frame 24677 to corroborate the peer response. Explain that headers remain spoofable.
- Describe the 125 matching requests and cadence, then explain why timing alone is weak evidence.
- Close with the next evidence you would request: process tree, binary signature/hash, installation source, approval record and host logs.

## Questions you must be able to answer

1. Why are the first TCP packet and first NetSupport request different timestamps?
2. What can a PowerShell User-Agent prove, and what can it not prove?
3. How would TCP segmentation or TLS defeat the custom extractor?
4. Why does the allowlist use a source/destination pair rather than a domain suffix?
5. Why do DNS rows and flow rows not equal unique domains or TCP sessions?
6. Which checks are independent, and which only catch regressions against saved expectations?
7. Would you reset the user's password from this evidence alone?
8. Why is the MP4 name insufficient to classify the retrieved content?

If you cannot answer these using the evidence, the project is not ready for your CV walkthrough yet.
