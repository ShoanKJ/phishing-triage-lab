# Incident Report: P01_ms_signin_phish

| Field | Value |
|---|---|
| Date analysed | 2026-10-06 |
| Email date | 2023-09-08 |
| Sample source | phishing_pot public honeypot corpus (`sample-10.eml`); recipient already anonymised |
| Verdict | **True positive: malicious (credential phishing)** |
| Confidence | High |
| Severity | Medium (no evidence of a click; credential theft if clicked) |
| MITRE ATT&CK | T1566.002 Phishing: Spearphishing Link (expected follow-on: T1204.001 User Execution: Malicious Link) |

## 1. Summary
A fake "Microsoft account team" alert claims a sign-in from Russia and urges the recipient to click "Report The User". The link goes to `thebandalisty[.]com`, which VirusTotal flags as phishing (9/92 vendors). The sender domain, envelope domain and Reply-To address are three unrelated identities, and nothing in the message authenticates.

## 2. Header analysis
- **From:** display name "Microsoft account team", address `no-reply@access-accsecurity[.]com`. The header is malformed (stray comma and underscore after the display name), which breaks some parsers.
- **Return-Path:** `bounce@thcultarfdes[.]co[.]uk`. **Reply-To:** `sotrecognizd@gmail[.]com`. Microsoft security notices do not come from this domain or ask for replies at a Gmail address.
- **Received chain:** hop 1 is the origin, `thcultarfdes[.]co[.]uk` (`89[.]144[.]44[.]2`), handing the message to Microsoft Exchange Online Protection. Hops 2-4 are Microsoft's internal receiving hops and are not part of the sender. The Message-ID ends in `outlook.com` because the receiving side stamped it, which does not mean the mail came from Microsoft.

| Check | Result | Meaning |
|---|---|---|
| SPF | none | The envelope domain `thcultarfdes[.]co[.]uk` publishes no SPF record |
| DKIM | none | Message is unsigned |
| DMARC | permerror | The receiver could not evaluate the policy for `access-accsecurity[.]com`. The From header was parsed correctly, so the likely cause is a malformed or duplicate DMARC DNS record (DNS not checked) |

Net result: nothing authenticates the claimed sender domain, and the three identities (From, Return-Path, Reply-To) do not match.

## 3. Content analysis
- **Lure:** fear of account takeover. It cites a sign-in from "Russia/Moscow" on Windows 10 and Firefox, from `103[.]225[.]77[.]255`, an address unrelated to the sender. The sign-in time in the body is 7 seconds before the email's send time, so the text is auto-generated.
- **Filter evasion:** "sign.in" is spelled with a dot, and random filler words are appended to the bottom of the body.
- **Link:** "Report The User" points to `hxxp://thebandalisty[.]com/track/o43062rdzG...` (path truncated; it is a unique tracking token). It is plain HTTP on a domain unrelated to Microsoft.
- **Attachments:** none.

## 4. IOCs and lookups
Lookups run 2026-10-06 against a 2023 sample, so results reflect today's reputation.

| Indicator | Role | VirusTotal | Other |
|---|---|---|---|
| `thebandalisty[.]com` | Link domain (click-through) | **9/92 malicious** (BitDefender, Fortinet, Sophos, G-Data, Webroot and others; ESET suspicious); tags: phishing and fraud; registrar NameCheap; created about 3 years ago; community score -44 | urlscan: domain no longer resolves (DNS error) |
| `access-accsecurity[.]com` | Spoofed From domain | 0/92; created about 3 years ago | none |
| `thcultarfdes[.]co[.]uk` | Envelope / sending host name | 0/92 | none |
| `89[.]144[.]44[.]2` | Origin IP | 0/92; AS201132 (MSCode, Poland); 2 detected files communicating (not reviewed) | AbuseIPDB: 0% confidence, 1 report (Sept 2026 honeypot port scan, unrelated to email); data-center hosting |
| `sotrecognizd@gmail[.]com` | Reply-To address | not looked up | block as an address, not as the Gmail domain |
| Full tracking URL | Click-through URL | not checked separately | domain result already covers it |

## 5. Verdict reasoning
Malicious because the link domain is flagged as phishing by nine vendors, the message impersonates Microsoft from unrelated domains, the From, Return-Path and Reply-To identities all differ, and no authentication passes.

Limits of the evidence: the sender and envelope domains show 0/92 on VirusTotal, so a reputation check alone would have missed them. Only the link domain is flagged, and it no longer resolves, so the findings describe 2023-era infrastructure. The origin IP is a data-center address with no email-abuse history, and it may have been reassigned since 2023.

## 6. Recommended actions
- [x] Block `thebandalisty[.]com`, `access-accsecurity[.]com` and `thcultarfdes[.]co[.]uk` at the mail gateway and DNS/proxy.
- [x] Block or rate-limit `89[.]144[.]44[.]2` at the mail gateway, time-limited because it is a shared hosting address.
- [x] Filter on the Reply-To address `sotrecognizd@gmail[.]com` (address level, never the whole Gmail domain).
- [x] Purge matching messages from mailboxes, and search proxy and DNS logs for lookups of `thebandalisty[.]com` to find any clicks.
- [x] If a user clicked or entered credentials: reset the password, revoke sessions, review sign-in logs and MFA.
- [x] Report to NameCheap (registrar), MSCode.pl (hosting) and Microsoft (phishing report).

Related samples: `sample-1001` and `sample-1002` (same From domain, link domain and decoy IP; Campaign A).

## Open items
- Review the "Communicating files" list on the VirusTotal IP page for `89[.]144[.]44[.]2`.
- Record the exact registration date of `access-accsecurity[.]com` (VirusTotal Details tab).
