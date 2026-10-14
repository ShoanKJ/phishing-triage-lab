# Incident Report: <ID>

| Field | Value |
|---|---|
| Date analysed | |
| Sample source | (public dataset / own inbox, PII removed) |
| Verdict | True positive (malicious) / False positive (legitimate) |
| Severity | Low / Medium / High |
| MITRE ATT&CK | T1566.00X <name> |

## 1. Summary
2-3 sentences: what the email claimed to be, what it really was.

## 2. Header analysis
- Received chain (origin IP, hops, anything odd):
- From / Return-Path / Reply-To alignment:
- SPF / DKIM / DMARC results and what they mean here:

## 3. Content analysis
- Social engineering technique (urgency, impersonation, etc.):
- Links (displayed vs actual) / attachments:

## 4. IOCs (defanged)
| Type | Value | VirusTotal | URLScan | AbuseIPDB |
|---|---|---|---|---|

## 5. Verdict reasoning
Why malicious or legitimate. For false positives: what looked suspicious and why it was benign.

## 6. Recommended actions
- [ ] Block sender / domain / IP / hash
- [ ] Purge from mailboxes / quarantine
- [ ] Notify affected users, reset creds if clicked
- [ ] Report (abuse contact, PhishTank, etc.)
