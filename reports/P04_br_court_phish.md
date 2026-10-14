# Incident Report: P04_br_court_phish

| Field | Value |
|---|---|
| Date analysed | 2026-10-07 |
| Sample source | Public dataset (phishing_pot, sample-1005.eml); recipient is a placeholder (phishing@pot). Encoded recipient data in tracking URLs is redacted below |
| Verdict | True positive (malicious). Confidence: High (landing page deliberately not visited) |
| Severity | High |
| MITRE ATT&CK | T1566.002 Spearphishing Link |

## 1. Summary
The email posed as an electronic court notice ("Ação Trabalhista", a labour lawsuit) from a "cartorio" (registry office) and pushed the reader to open a link to a "protected content" login page. It was sent by an account on a commercial bulk-mail platform, connected from a rented VPS, using a From domain that has no link to any Brazilian court. SPF and DKIM pass, but for the platform and not for the From domain. The attached image is a plain JPEG used as a visual lure, not malware.

## 2. Header analysis
- **Received chain:**
  - Hop 1 is an authenticated submission from a host named `vultr-guest` at 64[.]176[.]7[.]85 (a Vultr VPS) into a bulk-mail platform (`correio.pw`). The account username is omitted from this report. The Message-ID ends in `@VULTRGUEST`, which matches that VPS hostname. Hops 1 and 2 are the same header listed twice.
  - The platform's relay (`smtp363t7f252.saaspmta0002.correio.biz`, 179[.]188[.]7[.]252) then handed the message to Microsoft Exchange Online Protection, about 15 seconds after submission (01:37:42 to 01:37:57 UTC on 2023-07-30).
  - So the real origin is the VPS, and the platform relay is only a shared sending service.
- **From / Return-Path / Reply-To:**
  - From is `Intimação eletronica! <cartorio02@uorak[.]com>`.
  - Return-Path is a bounce address at `smtplw-01[.]com`, which does not match the From domain.
  - There is no Reply-To header.
- **SPF / DKIM / DMARC:**
  - SPF = pass, but for `smtplw-01.com` (the platform), not `uorak.com`. It is not aligned.
  - DKIM = pass, but for `smtplw-01.com`. It is not aligned.
  - DMARC: no result in the headers. A DNS lookup on 2026-10-07 found `_dmarc.uorak.com` publishing `v=DMARC1; p=reject`. This is a current snapshot, and it is not known whether it existed in 2023. Either way, an enforcing receiver would have failed this message on alignment.
  - Meaning: the passes prove the bulk platform sent it. They say nothing about whether `uorak.com` did.

## 3. Content analysis
- **Social engineering:** Impersonation of a Brazilian judicial authority (a labour-court summons), with fear and legal pressure to make the reader open the link quickly. The subject is "Ação Trabalhista !" and the sender name is "Intimação eletronica!".
- **Links:**
  - The main call-to-action leads to `https://login6[.]conteudo-protegido[.]one/_z2[.]html` (a "protected content" login page on an unrelated `.one` domain).
  - Other links go to the bulk platform's open and click tracking (`open-click.smtplw.com.br`) and to `vhsys.com.br`, with a `BoletoEmail` tracking parameter. These look like copied template content or platform plumbing. `vhsys.com.br` was not checked and is **not** treated as an indicator.
  - The tracking URLs contain encoded recipient data, which is redacted in this report.
  - The landing page was not visited, so the exact payload (credential theft or something else) is unconfirmed.
- **Attachment:** `11trt-14.jpeg` is a valid JPEG image used as a visual lure (the "TRT" in the name refers to the Brazilian labour courts). The analyzer only hashed it and never opened it. It is not an executable or a script.

## 4. IOCs (defanged)
| Type | Value | VirusTotal | URLScan | AbuseIPDB |
|---|---|---|---|---|
| Domain (landing) | login6[.]conteudo-protegido[.]one | URL report for the root `http://login6.conteudo-protegido.one/`: 2/92 (Forcepoint ThreatSeeker malicious, Fortinet malware; alphaMountain and Sophos spam). Report dated 2026-08-14. Registration date and registrar not checked | Not checked | n/a |
| URL | hxxps://login6[.]conteudo-protegido[.]one/_z2[.]html | Only the root URL was checked | Not checked | n/a |
| Email address | cartorio02@uorak[.]com | n/a | n/a | n/a |
| Domain (From) | uorak[.]com | 0/92 (Gridinsoft suspicious), created about 6 years ago, tags: content servers, general business, top-1M; "8 detected files communicating with this domain" (Relations tab not reviewed) | Not checked | n/a |
| IP (origin VPS) | 64[.]176[.]7[.]85 | 0/92, all vendors "unrated", AS20473 (The Constant Company, LLC), country listed as CL | n/a | Not checked |
| File | 11trt-14.jpeg, SHA-256 `c13fb305907d9740d02db69cc465f7571aaabcf0db1cdadbe4a5297b5d0b35ba` | Not checked | n/a | n/a |
| IP (relay, do not block) | 179[.]188[.]7[.]252 | Not checked | n/a | Not checked |

Lookups were run on 2026-10-07, over three years after the email was sent, so reputation reflects today's data.

## 5. Verdict reasoning
This is a malicious phishing email. The evidence:
1. **Impersonation with no connection:** a court-style notice from `uorak.com`, an established general-business domain (about 6 years old, top-1M) with nothing to do with a Brazilian court or registry. The From address was most likely forged or the domain abused, but which one is not verified.
2. **Authentication does not cover the From domain:** SPF and DKIM pass only for the bulk platform, and `uorak.com` publishes `p=reject` today.
3. **Attacker infrastructure is visible:** an authenticated login from a rented VPS (`vultr-guest`) into a bulk-mail service, the typical way to send campaigns in volume.
4. **Landing domain:** `login6.conteudo-protegido.one` has nothing to do with the claimed sender, uses a numbered host name (suggesting a set of kit hosts), and is flagged by 2 vendors.
5. **Lure-only attachment:** an image carrying the "official" look, with no executable payload.

Confidence is High, not Certain, because the landing page was never inspected. A reputation-only workflow would have been unreliable here (the From domain scores 0/92 and the VPS scores 0/92 with every vendor unrated).

## 6. Recommended actions
- [ ] Block `login6.conteudo-protegido.one` (web proxy and email gateway); consider the parent `conteudo-protegido.one` after checking its registration date and other subdomains
- [ ] Block the sender address `cartorio02@uorak.com`; do **not** block the whole `uorak.com` domain without checking, since it is an established domain that appears to be forged or abused
- [ ] Add 64.176.7.85 to hunting and monitoring lists (low-confidence block, because VPS addresses are reassigned)
- [ ] Do **not** block the bulk-mail platform (`smtplw-01.com`, `smtplw.com.br`, `correio.pw`, `correio.biz`, 179.188.7.252) or `vhsys.com.br` (shared services or unverified)
- [ ] Search mailboxes for links to `login6.conteudo-protegido.one` and purge
- [ ] Notify any recipient who clicked; reset any credentials they entered
- [ ] Report to the bulk-mail platform's abuse team (naming the authenticated account), to Vultr (origin VPS) and to the registrar of `conteudo-protegido.one`
