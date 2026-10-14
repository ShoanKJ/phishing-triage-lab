# Incident Report: P02_binance_phish

| Field | Value |
|---|---|
| Date analysed | 2026-10-07 |
| Sample source | Public dataset (phishing_pot, sample-1007.eml); recipient is a placeholder (phishing@pot), no PII |
| Verdict | True positive (malicious) |
| Severity | High |
| MITRE ATT&CK | T1566.002 Spearphishing Link |

## 1. Summary
The email imitated a Binance "Withdraw Successful" alert and pressed the reader to click "Cancel Transaction". The button points to shylshom[.]com, a domain registered on the day the email was sent, and the message was sent from an unrelated Australian domain through Amazon SES. It passes SPF and DKIM, but only for amazonses.com, not for the From domain.

## 2. Header analysis
- **Received chain:** The first hop is `b224-12.smtp-out.eu-central-1.amazonses.com` (69[.]169[.]224[.]12) handing the message to Microsoft Exchange Online Protection. The remaining hops are internal Microsoft relays, and the whole path took about one second (23:57:35 to 23:57:36 UTC on 2023-07-30). The origin is Amazon SES (eu-central-1), a shared sending service. Which SES account sent it cannot be determined from the headers.
- **From / Return-Path / Reply-To:**
  - From is `Binance <noreply-supportbinancewallet.irs@auswestbc[.]com[.]au>`: the display name says Binance, but the domain is unrelated.
  - Return-Path is an `amazonses.com` bounce address, which does not match the From domain.
  - There is no Reply-To header.
- **SPF / DKIM / DMARC:**
  - SPF = pass, but for `eu-central-1.amazonses.com` (the envelope domain), not `auswestbc.com.au`. It is not aligned.
  - DKIM = pass, but for `amazonses.com`, not the From domain. It is not aligned.
  - DMARC: no result in the headers, and a DNS lookup (2026-10-07) found no `_dmarc` TXT record for `auswestbc.com.au` (NXDOMAIN). The From domain published no policy, so a receiver had nothing to enforce. The pass results do not show the message is legitimate: they only show Amazon sent it, which any SES customer can do.

## 3. Content analysis
- **Social engineering:** Impersonation of a crypto exchange plus fear of loss (a withdrawal the reader did not make). The subject contains an impossible timestamp, `51:51:51(UTC)`, which suggests a hurried copy of a real template. Most of the HTML, images and footer links are copied from genuine Binance email.
- **Links:**
  - The "Cancel Transaction" button leads to `https://shylshom[.]com/`, which is not a Binance domain.
  - Other links go to genuine Binance and social-media addresses (binance.com anti-phishing page, bnbstatic.com images, mgdirectmail.binance.com tracking, Telegram, Facebook, etc.). They make the email look real and are **not** indicators.
- **Attachments:** None.

## 4. IOCs (defanged)
| Type | Value | VirusTotal | URLScan | AbuseIPDB |
|---|---|---|---|---|
| Domain (link) | shylshom[.]com | URL `http://shylshom.com/`: 9/92 vendors flag phishing/malicious (BitDefender, CRDF, CyRadar, Fortinet, G-Data, Kaspersky, Lionic, Sophos, VIPRE; alphaMountain suspicious). WHOIS: created 2023-07-30, registrar GoDaddy, expiry 2024-07-30 (snapshot 2023-07-31) | Search: 0 results in the 30-day free window (not conclusive) | n/a |
| URL | hxxps://shylshom[.]com/ | Same host as above (VT result was for the http:// variant) | as above | n/a |
| Domain (sender) | auswestbc[.]com[.]au | 3/92 (BitDefender and G-Data phishing, Chong Lua Dao malicious; alphaMountain suspicious, category Business/Economy) | Not checked | n/a |
| Email address | noreply-supportbinancewallet.irs@auswestbc[.]com[.]au | n/a | n/a | n/a |
| IP (relay, do not block) | 69[.]169[.]224[.]12 | Not checked | n/a | Not checked |

Lookups were run on 2026-10-07, more than three years after the email was sent, so reputation reflects today's data and not the data at delivery time.

## 5. Verdict reasoning
This is a malicious phishing email. The evidence:
1. The action link goes to a non-Binance domain that was registered on the same day the email was sent, and 9 of 92 vendors flag it.
2. The sender domain is unrelated to Binance, is flagged by 3 of 92 vendors, and has no DMARC record. Its category (Business/Economy) suggests it may be a real business domain that was abused, but this is not verified.
3. SPF and DKIM pass only for Amazon SES, not for the From domain. This email is an example of "authenticated but not aligned": the pass results prove the message came through SES, not that Binance sent it.
4. Impersonation of a known brand, a fear-based call to action, and an impossible timestamp in the subject.

A single check would not be enough here. The sender-side authentication looks fine, and the genuine Binance links look fine. The link domain, domain age and misalignment are what give it away.

## 6. Recommended actions
- [ ] Block `shylshom.com` (web proxy and email gateway) and sender domain `auswestbc.com.au`
- [ ] Do **not** block `amazonses.com`, its IP ranges, `binance.com`, or `bnbstatic.com` (shared service or genuine brand)
- [ ] Search mailboxes for the From address and for links to shylshom.com, then purge
- [ ] Notify any recipient who clicked, and advise them to review their Binance account activity and reset credentials and 2FA
- [ ] Report to Amazon SES/AWS abuse, to GoDaddy (registrar), and to Binance (impersonation)
