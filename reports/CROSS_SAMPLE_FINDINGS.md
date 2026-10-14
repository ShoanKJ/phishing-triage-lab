# Cross-Sample Findings

Findings from triaging 10 real phishing_pot samples (5 with full investigations and reports, P01 to P05). All lookups were run on 2026-10-06 and 2026-10-07, more than three years after the emails were sent, so reputation data reflects today and not delivery time. Landing pages were never visited.

## 1. Campaign A: three samples, one operation
Samples 10, 1001 and 1002 (fake Microsoft sign-in alerts) share the same From domain (`access-accsecurity[.]com`), the same link domain (`thebandalisty[.]com`) and the same decoy IP, based on first-pass triage. Sample 1001 uses a different envelope domain and sending IP (`nonkfrgr[.]co[.]uk`, 89[.]144[.]9[.]87), which shows the operator rotating the sender side while keeping the link domain constant. P01 (sample 10) is the fully investigated example; 1001 and 1002 are treated as duplicates of it.

**Detection lesson:** in P01 the sender-side domains scored 0/92 on VirusTotal and only the link domain `thebandalisty.com` was flagged (9/92). The link domain is the stable indicator for this campaign. It no longer resolves in DNS, so blocking it protects against later reuse and not against live clicks.

## 2. Passing SPF and DKIM does not mean safe
Three of the seven phishing emails (samples 1003, 1005 and 1007) pass SPF and DKIM, because they were sent through legitimate services.

| Case | SPF / DKIM | Aligned with From domain? | Sent through |
|---|---|---|---|
| P02 (Binance lure) | pass / pass | No (passes for amazonses.com) | Amazon SES |
| P03 (CoinDesk/Ripple lure) | pass / pass | Yes (the sender's own domain) | Mailgun |
| P04 (Brazilian court) | pass / pass | No (passes for smtplw-01.com) | Commercial bulk-mail platform |
| P05 (Bradesco/Livelo) | temperror / none | n/a | Own VPS, Postfix as root |

- **Check alignment, not just the result.** In P02 and P04 the passes belong to the sending service, not to the From domain. A DMARC policy on the From domain would have caught both, but neither From domain enforced one at the time (P02 has no record at all).
- **P03 is the hard case.** It authenticates for its own domain. The sender is a properly configured Mailgun customer on an old domain, so authentication alone cannot catch it. The decisive signal was the content: every clickable link goes to `mail123-ripple[.]net`, a domain registered seven days before the email, while the images came from a real CoinDesk newsletter.

## 3. A clean reputation does not mean safe
| Indicator | Result today | Reality |
|---|---|---|
| P01 sender domains | 0/92 | Part of a phishing campaign |
| P03 link domain `mail123-ripple.net` (root URL) | 0/92 | Registered 7 days before the email; lapsed after one year |
| P04 From domain `uorak.com` | 0/92 | Established domain, apparently forged or abused |
| P04 and P05 sending IPs | 0/92 | Rented VPS addresses |

Domain age, the mismatch between link destination and claimed brand, and infrastructure (a droplet or VPS sending directly) were more reliable signals than vendor scores. Vendor results are supporting evidence only.

## 4. What to block, and what never to block
**Block (campaign-specific):**
- Link and landing domains: `thebandalisty.com`, `shylshom.com`, `mail123-ripple.net`, `login6.conteudo-protegido.one`, `blog1seguimentmydomaine2bra.me`
- Specific sender addresses (for example `cartorio02@uorak.com`, `banco.bradesco@atendimento.com.br`) and, where nothing legitimate uses them, sender domains such as `auswestbc.com.au`
- Origin VPS addresses such as 137.184.34.4, **with a review date** (cloud addresses are reassigned)

**Never block (shared services or genuine brands):**
- Sending services: `amazonses.com`, Mailgun, the bulk-mail platform used in P04 (`smtplw-01.com`, `smtplw.com.br`) and their relay IPs. Blocking them would break legitimate mail from thousands of senders.
- `gmail.com` as a domain (P01 used a Gmail Reply-To address; block that single address instead).
- Genuine brand domains copied into the lures: `binance.com`, `bnbstatic.com`, `coindesk.com`.
- Page-asset hosts such as Google Fonts and shared image hosts.

## 5. Limits of this analysis
- The analyses use public sample emails from 2023, so the lookups cannot show what defenders knew at the time.
- Landing pages were not visited, so payloads (credential theft, wallet connection or something else) are inferred from the delivery chain, not observed.
- urlscan search on a free account covers only the last 30 days, so it could not confirm or rule out historical scans.
- The set contains phishing, advance-fee scams and spam only. No legitimate emails were included, so this project makes no claim about false-positive rates.
