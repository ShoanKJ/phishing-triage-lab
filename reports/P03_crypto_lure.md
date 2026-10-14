# Incident Report: P03_crypto_lure

| Field | Value |
|---|---|
| Date analysed | 2026-10-07 |
| Sample source | Public dataset (phishing_pot, sample-1003.eml); recipient is a placeholder (phishing@pot). The recipient identifier embedded in the link path is redacted below |
| Verdict | True positive (malicious). Confidence: Medium-High (link destination was deliberately not visited) |
| Severity | High |
| MITRE ATT&CK | T1566.002 Spearphishing Link |

## 1. Summary
The email posed as a CoinDesk newsletter promoting a Ripple "Token Allocation Program". It was sent through Mailgun from a sender domain that is unrelated to CoinDesk and that passes SPF, DKIM and DMARC alignment. Its clickable links go to `mail123-ripple[.]net`, a domain registered seven days before the email was sent, while the images were copied from a real CoinDesk newsletter. It is a good example of an email that passes every authentication check and is still malicious.

## 2. Header analysis
- **Received chain:** Hop 1 shows the message injected into Mailgun over HTTP (`by 47a34c698db9 with HTTP`), so it was sent through the Mailgun web API. Hop 2 is `so254-55.mailgun.net` (198[.]61[.]254[.]55) handing it to Microsoft Exchange Online Protection. The remaining hops are internal Microsoft relays. Total transit was about 5 seconds (15:06:03 to 15:06:08 UTC on 2023-07-27). The real sender is hidden behind Mailgun, so the origin cannot be traced from the headers.
- **From / Return-Path / Reply-To:**
  - From is `CoinDesk <coindesk@mg.areafellowship[.]com>`: the display name says CoinDesk, but the domain is unrelated.
  - The Return-Path is a Mailgun bounce address (`bounce+<VERP token>@mg.areafellowship[.]com`) on the same domain as From, so these two are consistent.
  - There is no Reply-To header.
- **SPF / DKIM / DMARC:**
  - SPF = pass and DKIM = pass. The analyzer found no misalignment, so both passed for the sender's own domain.
  - DMARC = `bestguesspass` in the headers, which means Microsoft evaluated it without a published policy at the time.
  - A DNS lookup on 2026-10-07 found that the parent domain `areafellowship[.]com` now publishes `v=DMARC1; p=quarantine; adkim=r; aspf=r`. The subdomain `mg.areafellowship[.]com` was not queried separately. The record is a current snapshot, and it may not have existed in 2023.
  - Meaning: the sender is a properly configured Mailgun customer on an old domain. Authentication proves who sent the message, not that it is safe.

## 3. Content analysis
- **Social engineering:** Impersonation of a trusted crypto news brand (CoinDesk) combined with a financial lure (a Ripple "Token Allocation Program"). The message is built from a copied real newsletter, so it looks professional.
- **Links:**
  - All clickable links and the tracking pixel go to `https://mail123-ripple[.]net/<REDACTED>`. The path contains the recipient's address in hex, which is personalised tracking (also used by legitimate marketing, so it is only supporting evidence).
  - Some images load from genuine CoinDesk infrastructure (`link.coindesk.com`) and from `media.sailthru.com` and `getbee.io`. These are shared or genuine services and are **not** indicators.
  - The destination page was not visited, so the exact payload (credential harvesting, wallet connection or something else) is unconfirmed.
- **Attachments:** None.

## 4. IOCs (defanged)
| Type | Value | VirusTotal | URLScan | AbuseIPDB |
|---|---|---|---|---|
| Domain (link) | mail123-ripple[.]net | URL report for the root page `http://mail123-ripple.net/`: 0/92 (analysed 2026-07-06). WHOIS: created 2023-07-20, registrar NiceNic International Group (Hong Kong), Cloudflare name servers, expiry 2024-07-20, status redemptionPeriod (record updated 2024-08-29) | Not checked (free search window covers only 30 days) | n/a |
| URL pattern | hxxps://mail123-ripple[.]net/<REDACTED> (also `.gif` and `.link` variants, with a `c_id` campaign parameter) | Only the root URL was checked | as above | n/a |
| Domain (sender) | mg[.]areafellowship[.]com | Parent `areafellowship.com`: 0/92, created about 7 years ago, registrar GoDaddy | Not checked | n/a |
| IP (relay, do not block) | 198[.]61[.]254[.]55 (so254-55.mailgun.net) | Not checked | n/a | Not checked |

Lookups were run on 2026-10-07, over three years after the email was sent, so reputation data does not reflect what was known at delivery time.

## 5. Verdict reasoning
This is a malicious phishing email, with reasoning that does **not** depend on reputation scores:
1. **Wrong destination for the brand:** every clickable link goes to `mail123-ripple.net`, which has nothing to do with CoinDesk or Ripple, while the images come from the real CoinDesk newsletter. A real newsletter would link to its own site.
2. **Brand-new link domain:** it was registered on 2023-07-20, seven days before the email, with a one-year registration that was not renewed (redemptionPeriod in the 2024 WHOIS record). That fits a throwaway campaign domain.
3. **Financial lure:** a "token allocation program" is a typical crypto-scam theme.
4. **Display-name mismatch:** CoinDesk branding on an unrelated sender domain.

Why reputation and authentication misled: the link domain has 0 vendor detections on its root URL, and the sender passes SPF, DKIM and DMARC alignment on a domain that is about seven years old. The most likely explanation is an abused or compromised Mailgun account, but this is not verified. A reputation-only or authentication-only workflow would have let this through.

Confidence is Medium-High and not High because the landing page was never inspected.

## 6. Recommended actions
- [ ] Block `mail123-ripple.net` (web proxy and email gateway)
- [ ] Quarantine mail from `mg.areafellowship.com` while the sender is investigated; do not block the parent domain `areafellowship.com` without further checks
- [ ] Do **not** block Mailgun (`mailgun.net` or its IPs), `link.coindesk.com`, `media.sailthru.com` or `getbee.io` (shared services or genuine brand)
- [ ] Search mailboxes for links to `mail123-ripple.net` and purge
- [ ] Notify any recipient who clicked; advise them to check wallet and exchange accounts, and revoke any wallet connections
- [ ] Report to Mailgun abuse, to the registrar's abuse contact (NiceNic) and to CoinDesk (brand impersonation)
