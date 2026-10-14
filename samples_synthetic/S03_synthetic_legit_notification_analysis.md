# Analysis: samples/S03_synthetic_legit_notification.eml

- **From:** GitHub-like Service <notifications@github-like.example>
- **To:** user@corp.example
- **Subject:** New sign-in to your account
- **Date:** Tue, 29 Sep 2026 08:00:00 +0000
- **Message-ID:** <n1@github-like.example>
- **Return-Path:** <notifications@github-like.example>
- **Reply-To:** 

**Auth:** SPF=pass  DKIM=pass  DMARC=pass

## Received chain (oldest first)
1. from mail.github-like.example (mail.github-like.example [192.0.2.55]) by mx.corp.example with ESMTP; Tue, 29 Sep 2026 08:00:00 +0000

## Red flags (0)
- none

## IOCs (defanged)
- ip: 192[.]0[.]2[.]55
- url: hxxps://github-like[.]example/settings/security
- domain: github-like[.]example

## Manual lookups
- IP 192.0.2.55: https://www.abuseipdb.com/check/192.0.2.55 | https://www.virustotal.com/gui/ip-address/192.0.2.55
- Domain github-like.example: https://www.virustotal.com/gui/domain/github-like.example | https://urlscan.io/search/#domain:github-like.example
