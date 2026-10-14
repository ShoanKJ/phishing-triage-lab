# Analysis: samples\P01_ms_signin_phish.eml

- **From:** "Microsoft account team", _ <no-reply@access-accsecurity.com>
- **To:** phishing@pot
- **Subject:** Microsoft account unusual signin activity
- **Date:** Fri, 08 Sep 2023 05:47:04 +0000
- **Message-ID:** <032672b4-77ca-42f8-a036-9711e91bd1f3@DB8EUR06FT032.eop-eur06.prod.protection.outlook.com>
- **Return-Path:** bounce@thcultarfdes.co.uk
- **Reply-To:** sotrecognizd@gmail.com

**Auth:** SPF=none  DKIM=none  DMARC=permerror

## Received chain (oldest first)
1. from thcultarfdes.co.uk (89.144.44.2) by DB8EUR06FT032.mail.protection.outlook.com (10.233.253.34) with Microsoft SMTP Server id 15.20.6768.30 via Frontend Transport; Fri, 8 Sep 2023 05:47:04 +0000
2. from DB8EUR06FT032.eop-eur06.prod.protection.outlook.com (2603:10a6:10:130:cafe::9b) by DB8P191CA0014.outlook.office365.com (2603:10a6:10:130::24) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6768.30 via Frontend Transport; Fri, 8 Sep 2023 05:47:04 +0000
3. from DB8P191CA0014.EURP191.PROD.OUTLOOK.COM (2603:10a6:10:130::24) by SJ0PR19MB6679.namprd19.prod.outlook.com (2603:10b6:a03:477::19) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6768.30; Fri, 8 Sep 2023 05:47:04 +0000
4. from SJ0PR19MB6679.namprd19.prod.outlook.com (::1) by MN0PR19MB6312.namprd19.prod.outlook.com with HTTPS; Fri, 8 Sep 2023 05:47:06 +0000

## Red flags (7)
- SPF not present
- DKIM not present
- DMARC permerror
- Return-Path domain (thcultarfdes.co.uk) differs from From domain (access-accsecurity.com)
- Reply-To domain (gmail.com) differs from From domain (access-accsecurity.com)
- Display name mentions 'microsoft' but sender domain is access-accsecurity.com
- No link points to the From domain (access-accsecurity.com); links go to: thebandalisty.com

## IOCs (defanged)
- ip: 89[.]144[.]44[.]2
- url: hxxp://thebandalisty[.]com/track/o43062rdzGz18708448Gdrw1821750fYo33632dSjh176
- domain: access-accsecurity[.]com
- domain: gmail[.]com
- domain: thcultarfdes[.]co[.]uk
- domain: thebandalisty[.]com

## Manual lookups
- IP 89.144.44.2: https://www.abuseipdb.com/check/89.144.44.2 | https://www.virustotal.com/gui/ip-address/89.144.44.2
- Domain access-accsecurity.com: https://www.virustotal.com/gui/domain/access-accsecurity.com | https://urlscan.io/search/#domain:access-accsecurity.com
- Domain gmail.com: https://www.virustotal.com/gui/domain/gmail.com | https://urlscan.io/search/#domain:gmail.com
- Domain thcultarfdes.co.uk: https://www.virustotal.com/gui/domain/thcultarfdes.co.uk | https://urlscan.io/search/#domain:thcultarfdes.co.uk
- Domain thebandalisty.com: https://www.virustotal.com/gui/domain/thebandalisty.com | https://urlscan.io/search/#domain:thebandalisty.com
