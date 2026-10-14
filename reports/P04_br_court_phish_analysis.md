# Analysis: samples\P04_br_court_phish.eml

- **From:** Intima├º├úo eletronica! <cartorio02@uorak.com>
- **To:** phishing@pot
- **Subject:** A├º├úo Trabalhista !
- **Date:** Sun, 30 Jul 2023 01:37:42 +0000
- **Message-ID:** <20230730013742BDEF4B63F6$6F4196D4B4@VULTRGUEST>
- **Return-Path:** bounce-166231d7947f993fad240d07f78c03fc@smtplw-01.com
- **Reply-To:** 

**Auth:** SPF=pass  DKIM=pass  DMARC=none

## Received chain (oldest first)
1. from vultr-guest (unknown [64.176.7.85]) (Authenticated sender: alexandrejoacy2) by saasauth0008.correio.pw (Postfix) with ESMTPSA id 5E5E417FF31 for <phishing@pot>; Sat, 29 Jul 2023 22:37:42 -0300 (-03)
2. from vultr-guest (unknown [64.176.7.85]) (Authenticated sender: alexandrejoacy2) by saasauth0008.correio.pw (Postfix) with ESMTPSA id 5E5E417FF31 for <phishing@pot>; Sat, 29 Jul 2023 22:37:42 -0300 (-03)
3. from saasqueue0004.correio.biz (unknown [10.32.64.7]) by saasmilter0017.correio.biz (Postfix) with ESMTPS id D828FDFC22 for <phishing@pot>; Sat, 29 Jul 2023 22:37:42 -0300 (-03)
4. from saasmilter0017.correio.biz (10.32.64.17) by smtp363t7f252.saaspmta0002.correio.biz id homuvo2oqm4k for <phishing@pot>; Sat, 29 Jul 2023 22:33:33 -0300 (envelope-from <bounce-166231d7947f993fad240d07f78c03fc@smtplw-01.com>)
5. from smtp363t7f252.saaspmta0002.correio.biz (179.188.7.252) by HE1EUR01FT029.mail.protection.outlook.com (10.152.0.155) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6631.29 via Frontend Transport; Sun, 30 Jul 2023 01:37:57 +0000
6. from HE1EUR01FT029.eop-EUR01.prod.protection.outlook.com (2603:10a6:150:b:cafe::b4) by GV3P280CA0022.outlook.office365.com (2603:10a6:150:b::12) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6631.42 via Frontend Transport; Sun, 30 Jul 2023 01:37:58 +0000
7. from GV3P280CA0022.SWEP280.PROD.OUTLOOK.COM (2603:10a6:150:b::12) by SN7PR19MB4782.namprd19.prod.outlook.com (2603:10b6:806:109::6) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6609.31; Sun, 30 Jul 2023 01:37:59 +0000
8. from SN7PR19MB4782.namprd19.prod.outlook.com (::1) by MN0PR19MB6312.namprd19.prod.outlook.com with HTTPS; Sun, 30 Jul 2023 01:38:01 +0000

## Red flags (5)
- DMARC not present
- SPF passed for smtplw-01.com, not the From domain (uorak.com): not aligned
- DKIM passed for smtplw-01.com, not the From domain (uorak.com): not aligned
- Return-Path domain (smtplw-01.com) differs from From domain (uorak.com)
- No link points to the From domain (uorak.com); links go to: app.vhsys.com.br, login6.conteudo-protegido.one, open-click.smtplw.com.br, vhsys.com.br

## IOCs (defanged)
- ip: 179[.]188[.]7[.]252
- ip: 64[.]176[.]7[.]85
- url: hxxp://app[.]vhsys[.]com[.]br/ControleEmail[.]php?registrar=MjA4NzM5I1JlY183MTQ2OTEwMyNsY2ZlcXVpcGFtZW50b3NAdGVycmEuY29tLmJyOyA=
- url: hxxp://app[.]vhsys[.]com[.]br/images/email/logo-footer-small[.]png
- url: hxxps://login6[.]conteudo-protegido[.]one/_z2[.]html
- url: hxxps://open-click[.]smtplw[.]com[.]br/openings/m/166231d7947f993fad240d07f78c03fc-1690681062[.]91/a/166231d7947f993fad240d07f78c03fc/r/NzI2ZjY0NzI2OTY3NmYyZDY2MmQ3MDQwNjg2Zjc0NmQ2MTY5NmMyZTYzNmY2ZA==/v/d3a2a39af65b09f13c1d70e3320a285b23d8093b
- url: hxxps://vhsys[.]com[.]br/?utm_source=crm_internal&amp;utm_medium=email&amp;utm_campaign=BoletoEmail
- url: hxxps://vhsys[.]com[.]br/?utm_source=crm_internal&utm_medium=email&utm_campaign=BoletoEmail
- domain: app[.]vhsys[.]com[.]br
- domain: login6[.]conteudo-protegido[.]one
- domain: open-click[.]smtplw[.]com[.]br
- domain: smtplw-01[.]com
- domain: uorak[.]com
- domain: vhsys[.]com[.]br
- attachment: 11trt-14.jpeg sha256=c13fb305907d9740d02db69cc465f7571aaabcf0db1cdadbe4a5297b5d0b35ba

## Manual lookups
- IP 179.188.7.252: https://www.abuseipdb.com/check/179.188.7.252 | https://www.virustotal.com/gui/ip-address/179.188.7.252
- IP 64.176.7.85: https://www.abuseipdb.com/check/64.176.7.85 | https://www.virustotal.com/gui/ip-address/64.176.7.85
- Domain app.vhsys.com.br: https://www.virustotal.com/gui/domain/app.vhsys.com.br | https://urlscan.io/search/#domain:app.vhsys.com.br
- Domain login6.conteudo-protegido.one: https://www.virustotal.com/gui/domain/login6.conteudo-protegido.one | https://urlscan.io/search/#domain:login6.conteudo-protegido.one
- Domain open-click.smtplw.com.br: https://www.virustotal.com/gui/domain/open-click.smtplw.com.br | https://urlscan.io/search/#domain:open-click.smtplw.com.br
- Domain smtplw-01.com: https://www.virustotal.com/gui/domain/smtplw-01.com | https://urlscan.io/search/#domain:smtplw-01.com
- Domain uorak.com: https://www.virustotal.com/gui/domain/uorak.com | https://urlscan.io/search/#domain:uorak.com
- Domain vhsys.com.br: https://www.virustotal.com/gui/domain/vhsys.com.br | https://urlscan.io/search/#domain:vhsys.com.br
- Hash c13fb305907d9740...: https://www.virustotal.com/gui/file/c13fb305907d9740d02db69cc465f7571aaabcf0db1cdadbe4a5297b5d0b35ba
