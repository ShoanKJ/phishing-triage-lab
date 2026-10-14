# Analysis: samples/S01_synthetic_credential_phish.eml

- **From:** Microsoft Account Team <security@micros0ft-support.example>
- **To:** victim@corp.example
- **Subject:** Action required: your password expires within 24 hours
- **Date:** Tue, 29 Sep 2026 09:13:50 +0000
- **Message-ID:** <a1b2c3@evil-host.example>
- **Return-Path:** <bounce@evil-host.example>
- **Reply-To:** helpdesk.recovery@freemail.example

**Auth:** SPF=fail  DKIM=none  DMARC=fail

## Received chain (oldest first)
1. from [10.0.0.5] (unknown [198.51.100.23]) by mail.evil-host.example with ESMTP; Tue, 29 Sep 2026 09:13:58 +0000
2. from mail.evil-host.example (mail.evil-host.example [203.0.113.45]) by mx.corp.example with ESMTP; Tue, 29 Sep 2026 09:14:02 +0000

## Red flags (8)
- SPF fail
- DKIM not present
- DMARC fail
- Return-Path domain (evil-host.example) differs from From domain (micros0ft-support.example)
- Reply-To domain (freemail.example) differs from From domain (micros0ft-support.example)
- Display name mentions 'microsoft' but sender domain is micros0ft-support.example
- Urgency/pressure language: immediately, suspended, verify your, unusual activity
- Link text shows 'https://login.microsoftonline.com' but points to login-portal.evil-host.example

## IOCs (defanged)
- ip: 198[.]51[.]100[.]23
- ip: 203[.]0[.]113[.]45
- url: hxxp://login-portal[.]evil-host[.]example/office365/signin?u=victim
- url: hxxps://login[.]microsoftonline[.]com
- domain: evil-host[.]example
- domain: freemail[.]example
- domain: login-portal[.]evil-host[.]example
- domain: login[.]microsoftonline[.]com
- domain: micros0ft-support[.]example

## Manual lookups
- IP 198.51.100.23: https://www.abuseipdb.com/check/198.51.100.23 | https://www.virustotal.com/gui/ip-address/198.51.100.23
- IP 203.0.113.45: https://www.abuseipdb.com/check/203.0.113.45 | https://www.virustotal.com/gui/ip-address/203.0.113.45
- Domain evil-host.example: https://www.virustotal.com/gui/domain/evil-host.example | https://urlscan.io/search/#domain:evil-host.example
- Domain freemail.example: https://www.virustotal.com/gui/domain/freemail.example | https://urlscan.io/search/#domain:freemail.example
- Domain login-portal.evil-host.example: https://www.virustotal.com/gui/domain/login-portal.evil-host.example | https://urlscan.io/search/#domain:login-portal.evil-host.example
- Domain login.microsoftonline.com: https://www.virustotal.com/gui/domain/login.microsoftonline.com | https://urlscan.io/search/#domain:login.microsoftonline.com
- Domain micros0ft-support.example: https://www.virustotal.com/gui/domain/micros0ft-support.example | https://urlscan.io/search/#domain:micros0ft-support.example
