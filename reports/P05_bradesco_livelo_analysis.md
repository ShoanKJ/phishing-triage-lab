# Analysis: samples\P05_bradesco_livelo.eml

- **From:** BANCO DO BRADESCO LIVELO <banco.bradesco@atendimento.com.br>
- **To:** phishing@pot
- **Subject:** CLIENTE PRIME - BRADESCO LIVELO: Seu cartão tem 92.990 pontos LIVELO expirando hoje!
- **Date:** Tue, 19 Sep 2023 18:35:49 +0000
- **Message-ID:** <20230919183549.39DEA3F725@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06>
- **Return-Path:** root@ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06
- **Reply-To:** 

**Auth:** SPF=temperror  DKIM=none  DMARC=temperror

## Received chain (oldest first)
1. by ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06 (Postfix, from userid 0) id 39DEA3F725; Tue, 19 Sep 2023 18:35:49 +0000 (UTC)
2. from ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06 (137.184.34.4) by BN8NAM11FT066.mail.protection.outlook.com (10.13.177.138) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6813.19 via Frontend Transport; Tue, 19 Sep 2023 18:36:44 +0000
3. from BN8NAM11FT066.eop-nam11.prod.protection.outlook.com (2603:10b6:408:e6:cafe::23) by BN0PR03CA0023.outlook.office365.com (2603:10b6:408:e6::28) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6792.28 via Frontend Transport; Tue, 19 Sep 2023 18:36:45 +0000
4. from BN0PR03CA0023.namprd03.prod.outlook.com (2603:10b6:408:e6::28) by SA3PR19MB7370.namprd19.prod.outlook.com (2603:10b6:806:317::17) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6792.27; Tue, 19 Sep 2023 18:36:45 +0000
5. from SA3PR19MB7370.namprd19.prod.outlook.com (::1) by MN0PR19MB6312.namprd19.prod.outlook.com with HTTPS; Tue, 19 Sep 2023 18:36:46 +0000

## Red flags (7)
- SPF temperror
- DKIM not present
- DMARC temperror
- Return-Path domain (ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06) differs from From domain (atendimento.com.br)
- Display name mentions 'bradesco' but sender domain is atendimento.com.br
- Display name mentions 'livelo' but sender domain is atendimento.com.br
- No link points to the From domain (atendimento.com.br); links go to: blog1seguimentmydomaine2bra.me

## IOCs (defanged)
- ip: 137[.]184[.]34[.]4
- url: hxxps://blog1seguimentmydomaine2bra[.]me/
- url: hxxps://fonts[.]googleapis[.]com/css2?family=Signika:wght@300;500;700&amp;display=swap
- url: hxxps://fonts[.]gstatic[.]com
- domain: atendimento[.]com[.]br
- domain: blog1seguimentmydomaine2bra[.]me
- domain: fonts[.]googleapis[.]com
- domain: fonts[.]gstatic[.]com
- domain: ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06

## Manual lookups
- IP 137.184.34.4: https://www.abuseipdb.com/check/137.184.34.4 | https://www.virustotal.com/gui/ip-address/137.184.34.4
- Domain atendimento.com.br: https://www.virustotal.com/gui/domain/atendimento.com.br | https://urlscan.io/search/#domain:atendimento.com.br
- Domain blog1seguimentmydomaine2bra.me: https://www.virustotal.com/gui/domain/blog1seguimentmydomaine2bra.me | https://urlscan.io/search/#domain:blog1seguimentmydomaine2bra.me
- Domain fonts.googleapis.com: https://www.virustotal.com/gui/domain/fonts.googleapis.com | https://urlscan.io/search/#domain:fonts.googleapis.com
- Domain fonts.gstatic.com: https://www.virustotal.com/gui/domain/fonts.gstatic.com | https://urlscan.io/search/#domain:fonts.gstatic.com
- Domain ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06: https://www.virustotal.com/gui/domain/ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06 | https://urlscan.io/search/#domain:ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06
