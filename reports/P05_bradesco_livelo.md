# Incident Report: P05_bradesco_livelo

| Field | Value |
|---|---|
| Date analysed | 2026-10-07 |
| Sample source | Public dataset (phishing_pot, sample-1.eml); recipient is a placeholder (phishing@pot) |
| Verdict | True positive (malicious). Confidence: High (link destination deliberately not visited) |
| Severity | High |
| MITRE ATT&CK | T1566.002 Spearphishing Link |

## 1. Summary
The email claimed that a "Bradesco Livelo" card had 92,990 Livelo points expiring today and told the reader to act as a "CLIENTE PRIME". It was sent directly from a freshly built DigitalOcean server running default mail software as root, using a From domain that has no connection to the bank or the loyalty program. Its only link goes to an unrelated domain, `blog1seguimentmydomaine2bra[.]me`.

## 2. Header analysis
- **Received chain:**
  - Hop 1 shows Postfix on a host named `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` creating the message locally (`from userid 0`, meaning root).
  - Hop 2 shows the same host at 137[.]184[.]34[.]4 connecting straight to Microsoft Exchange Online Protection, about 55 seconds later (18:35:49 to 18:36:44 UTC on 2023-09-19).
  - The hostname follows the default naming pattern of a DigitalOcean droplet, and the IP's ASN (AS14061, DigitalOcean) confirms the provider. There is no relay or bulk-mail service, so the origin is this one server.
  - The same hostname appears in the Message-ID and in the Return-Path, which shows the mail server was never configured with a real identity.
- **From / Return-Path / Reply-To:**
  - From is `BANCO DO BRADESCO LIVELO <banco.bradesco@atendimento[.]com[.]br>`, a bank and loyalty-program name on a generic "customer service" domain.
  - The Return-Path is `root@<droplet hostname>`, which is a local hostname and not a domain; the analyzer flagged it as a mismatch because of that.
  - There is no Reply-To header.
- **SPF / DKIM / DMARC:**
  - SPF = temperror and DMARC = temperror: the receiver hit a temporary DNS problem during the check. This does not describe the domain's configuration, and the original cause cannot be determined now.
  - DKIM is absent because no signing was set up.
  - A DNS lookup on 2026-10-07 found no `_dmarc` record for `atendimento.com.br`, and no TXT records at all (so no visible SPF record). The domain publishes no way for a receiver to validate mail, which is typical of a forged sender.

## 3. Content analysis
- **Social engineering:** Impersonation of a bank and a loyalty program, plus a prize-style loss threat ("92.990 pontos LIVELO expirando hoje") and a status label ("CLIENTE PRIME") to create urgency and a feeling of exclusivity.
- **Links:** Every link goes to `https://blog1seguimentmydomaine2bra[.]me/`, which is unrelated to the From domain, the bank or the loyalty program. The only other URLs are Google Fonts assets, which are page styling and not indicators. The destination was not visited, so the exact payload is unconfirmed.
- **Attachments:** None.

## 4. IOCs (defanged)
| Type | Value | VirusTotal | URLScan | AbuseIPDB |
|---|---|---|---|---|
| Domain (link) | blog1seguimentmydomaine2bra[.]me | 0/92 on the domain page. Registrar ENOM, Inc., created about 3 years before the lookup (exact date not captured). VirusTotal tags it "dga" (a heuristic label for algorithm-like names) | Not checked | n/a |
| URL | hxxps://blog1seguimentmydomaine2bra[.]me/ | Domain checked, not the URL | Not checked | n/a |
| IP (origin server) | 137[.]184[.]34[.]4 | 0/92 (Gridinsoft: suspicious), AS14061 DigitalOcean, LLC, US | n/a | Not checked |
| Domain (From) | atendimento[.]com[.]br | 0/92, tags: top-1M, nxdomain. Today: no `_dmarc` record, no TXT records, zone hosted at Cloudflare | Not checked | n/a |
| Email address | banco.bradesco@atendimento[.]com[.]br | n/a | n/a | n/a |
| Hostname | ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06 | n/a | n/a | n/a (hunting indicator, not a domain) |

Lookups were run on 2026-10-07, over three years after the email was sent, so reputation reflects today's data. The two tags on `atendimento.com.br` conflict (top-1M suggests a domain with some traffic, while nxdomain suggests it has not always resolved), and who owns the domain is not verified.

## 5. Verdict reasoning
This is a malicious phishing email, with the verdict resting on content and infrastructure, not on reputation scores:
1. **Direct-to-MX from a throwaway server:** a DigitalOcean droplet with default hostname, mail created by root. Real banks and loyalty programs send through managed mail infrastructure.
2. **Brand with no connection:** a bank and loyalty-program display name on a generic customer-service domain that publishes no email authentication records.
3. **Unrelated link domain:** the only destination is `blog1seguimentmydomaine2bra.me`, an unrelated domain with an algorithm-like name, which VirusTotal tags "dga".
4. **Pressure language:** points "expiring today" and a "prime customer" label.
5. **Authentication could not rescue it:** SPF and DMARC returned temperror and DKIM was absent, so nothing supports the From address.

Reputation was misleading here: the link domain and the origin IP both score 0 vendor detections on VirusTotal (the IP carries one "suspicious" from Gridinsoft). Confidence is High, not Certain, because the landing page was never inspected.

## 6. Recommended actions
- [ ] Block `blog1seguimentmydomaine2bra.me` (web proxy and email gateway)
- [ ] Block the sender address `banco.bradesco@atendimento.com.br`; investigate before blocking the whole `atendimento.com.br` domain
- [ ] Block 137.184.34.4 at the email gateway with a review date (cloud IP addresses get reassigned, so a permanent block is not appropriate)
- [ ] Hunt for the hostname `ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06` in Message-IDs and Return-Paths
- [ ] Do **not** block Google Fonts or other page-asset domains
- [ ] Search mailboxes for links to the blog domain and purge
- [ ] Notify any recipient who clicked; advise them to change bank and loyalty-program credentials and to check card activity
- [ ] Report to DigitalOcean abuse (origin server), the registrar ENOM (link domain), and to the impersonated brands (Bradesco, Livelo)
