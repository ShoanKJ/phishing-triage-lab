# Analysis: samples/S04_synthetic_legit_via_esp.eml

- **From:** Shop Example <news@shop.example>
- **To:** user@corp.example
- **Subject:** Confirm your subscription preferences
- **Date:** Tue, 29 Sep 2026 07:30:00 +0000
- **Message-ID:** <m9@esp-mail.example>
- **Return-Path:** <bounces+123@bounce.esp-mail.example>
- **Reply-To:** 

**Auth:** SPF=pass  DKIM=pass  DMARC=pass

## Received chain (oldest first)
1. from mta1.esp-mail.example (mta1.esp-mail.example [192.0.2.99]) by mx.corp.example with ESMTP; Tue, 29 Sep 2026 07:30:00 +0000

## Red flags (1)
- Return-Path domain (bounce.esp-mail.example) differs from From domain (shop.example)

## IOCs (defanged)
- ip: 192[.]0[.]2[.]99
- url: hxxps://click[.]esp-mail[.]example/r/abc123
- domain: bounce[.]esp-mail[.]example
- domain: click[.]esp-mail[.]example
- domain: shop[.]example

## Manual lookups
- IP 192.0.2.99: https://www.abuseipdb.com/check/192.0.2.99 | https://www.virustotal.com/gui/ip-address/192.0.2.99
- Domain bounce.esp-mail.example: https://www.virustotal.com/gui/domain/bounce.esp-mail.example | https://urlscan.io/search/#domain:bounce.esp-mail.example
- Domain click.esp-mail.example: https://www.virustotal.com/gui/domain/click.esp-mail.example | https://urlscan.io/search/#domain:click.esp-mail.example
- Domain shop.example: https://www.virustotal.com/gui/domain/shop.example | https://urlscan.io/search/#domain:shop.example
