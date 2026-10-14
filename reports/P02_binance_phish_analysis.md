# Analysis: samples\P02_binance_phish.eml

- **From:** Binance <noreply-supportbinancewallet.irs@auswestbc.com.au>
- **To:** phishing@pot
- **Subject:** [Binance] Withdraw Successful - 2023-07-30 51:51:51(UTC)
- **Date:** Sun, 30 Jul 2023 23:57:35 +0000
- **Message-ID:** <01070189a93c67a5-2d72e19a-1525-41c6-92cb-347e9e7f27a5-000000@eu-central-1.amazonses.com>
- **Return-Path:** 01070189a93c67a5-2d72e19a-1525-41c6-92cb-347e9e7f27a5-000000@eu-central-1.amazonses.com
- **Reply-To:** 

**Auth:** SPF=pass  DKIM=pass  DMARC=none

## Received chain (oldest first)
1. from b224-12.smtp-out.eu-central-1.amazonses.com (69.169.224.12) by MW2NAM12FT067.mail.protection.outlook.com (10.13.181.33) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6631.42 via Frontend Transport; Sun, 30 Jul 2023 23:57:36 +0000
2. from MW2NAM12FT067.eop-nam12.prod.protection.outlook.com (2603:10b6:303:8f:cafe::39) by MW4PR03CA0010.outlook.office365.com (2603:10b6:303:8f::15) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6631.42 via Frontend Transport; Sun, 30 Jul 2023 23:57:36 +0000
3. from MW4PR03CA0010.namprd03.prod.outlook.com (2603:10b6:303:8f::15) by SJ2PR19MB7507.namprd19.prod.outlook.com (2603:10b6:a03:4c3::16) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6631.29; Sun, 30 Jul 2023 23:57:36 +0000
4. from SJ2PR19MB7507.namprd19.prod.outlook.com (2603:10b6:a03:4c3::16) by MN0PR19MB6312.namprd19.prod.outlook.com with HTTPS; Sun, 30 Jul 2023 23:57:38 +0000

## Red flags (6)
- DMARC not present
- SPF passed for eu-central-1.amazonses.com, not the From domain (auswestbc.com.au): not aligned
- DKIM passed for amazonses.com, not the From domain (auswestbc.com.au): not aligned
- Return-Path domain (eu-central-1.amazonses.com) differs from From domain (auswestbc.com.au)
- Display name mentions 'binance' but sender domain is auswestbc.com.au
- No link points to the From domain (auswestbc.com.au); links go to: email.mgdirectmail.binance.com, public.bnbstatic.com, shylshom.com, www.binance.com, www.google-analytics.com

## IOCs (defanged)
- ip: 69[.]169[.]224[.]12
- url: hxxp://email[.]mgdirectmail[.]binance[.]com/o/eJxEzEsSwiAMANDTlF2ZfCAhCw4TpL-xaMd6_3HpBV6vgBlIw1JRDMQKUg57Xbl5UexMrXDTLsaFoKms7krewlGVUYXYMBKLqcU_IMmmBGO5b9-WWbukXFbVPO-vr43wqc_L4-2bX376lGAbfpzx8R6_AAAA__8p7CcC
- url: hxxp://www[.]w3[.]org/1999/xhtml
- url: hxxps://instagram[.]com/binance
- url: hxxps://public[.]bnbstatic[.]com/image/social/facebook-dark[.]png
- url: hxxps://public[.]bnbstatic[.]com/image/social/instagram-dark[.]png
- url: hxxps://public[.]bnbstatic[.]com/image/social/linkedin-dark[.]png
- url: hxxps://public[.]bnbstatic[.]com/image/social/reddit-dark[.]png
- url: hxxps://public[.]bnbstatic[.]com/image/social/telegram-dark[.]png
- url: hxxps://public[.]bnbstatic[.]com/image/social/twitter-dark[.]png
- url: hxxps://public[.]bnbstatic[.]com/image/social/youtube-dark[.]png
- url: hxxps://public[.]bnbstatic[.]com/image/ufo/20210831/1e00bd49-0695-4eaa-8ab0-6dd89a7087fb[.]png
- url: hxxps://shylshom[.]com/
- url: hxxps://telegram[.]me/BinanceExchange
- url: hxxps://twitter[.]com/binance
- url: hxxps://www[.]binance[.]com/en/my/security/anti-phishing-code
- url: hxxps://www[.]facebook[.]com/binance
- url: hxxps://www[.]google-analytics[.]com/collect?v=1&amp;t=event&amp;tid=UA-237515680-1&amp;cid=19b769f4-1d97-4423-8d74-18dae0f859cb&amp;ec=email-mp&amp;ea=τö╡σ¡ÉΘé«Σ╗╢µëôσ╝Ç
- url: hxxps://www[.]linkedin[.]com/company/binance
- url: hxxps://www[.]reddit[.]com/r/binance/
- url: hxxps://www[.]youtube[.]com/c/BinanceYoutube/featured
- domain: auswestbc[.]com[.]au
- domain: email[.]mgdirectmail[.]binance[.]com
- domain: eu-central-1[.]amazonses[.]com
- domain: instagram[.]com
- domain: public[.]bnbstatic[.]com
- domain: shylshom[.]com
- domain: telegram[.]me
- domain: twitter[.]com
- domain: www[.]binance[.]com
- domain: www[.]facebook[.]com
- domain: www[.]google-analytics[.]com
- domain: www[.]linkedin[.]com
- domain: www[.]reddit[.]com
- domain: www[.]w3[.]org
- domain: www[.]youtube[.]com

## Manual lookups
- IP 69.169.224.12: https://www.abuseipdb.com/check/69.169.224.12 | https://www.virustotal.com/gui/ip-address/69.169.224.12
- Domain auswestbc.com.au: https://www.virustotal.com/gui/domain/auswestbc.com.au | https://urlscan.io/search/#domain:auswestbc.com.au
- Domain email.mgdirectmail.binance.com: https://www.virustotal.com/gui/domain/email.mgdirectmail.binance.com | https://urlscan.io/search/#domain:email.mgdirectmail.binance.com
- Domain eu-central-1.amazonses.com: https://www.virustotal.com/gui/domain/eu-central-1.amazonses.com | https://urlscan.io/search/#domain:eu-central-1.amazonses.com
- Domain instagram.com: https://www.virustotal.com/gui/domain/instagram.com | https://urlscan.io/search/#domain:instagram.com
- Domain public.bnbstatic.com: https://www.virustotal.com/gui/domain/public.bnbstatic.com | https://urlscan.io/search/#domain:public.bnbstatic.com
- Domain shylshom.com: https://www.virustotal.com/gui/domain/shylshom.com | https://urlscan.io/search/#domain:shylshom.com
- Domain telegram.me: https://www.virustotal.com/gui/domain/telegram.me | https://urlscan.io/search/#domain:telegram.me
- Domain twitter.com: https://www.virustotal.com/gui/domain/twitter.com | https://urlscan.io/search/#domain:twitter.com
- Domain www.binance.com: https://www.virustotal.com/gui/domain/www.binance.com | https://urlscan.io/search/#domain:www.binance.com
- Domain www.facebook.com: https://www.virustotal.com/gui/domain/www.facebook.com | https://urlscan.io/search/#domain:www.facebook.com
- Domain www.google-analytics.com: https://www.virustotal.com/gui/domain/www.google-analytics.com | https://urlscan.io/search/#domain:www.google-analytics.com
- Domain www.linkedin.com: https://www.virustotal.com/gui/domain/www.linkedin.com | https://urlscan.io/search/#domain:www.linkedin.com
- Domain www.reddit.com: https://www.virustotal.com/gui/domain/www.reddit.com | https://urlscan.io/search/#domain:www.reddit.com
- Domain www.w3.org: https://www.virustotal.com/gui/domain/www.w3.org | https://urlscan.io/search/#domain:www.w3.org
- Domain www.youtube.com: https://www.virustotal.com/gui/domain/www.youtube.com | https://urlscan.io/search/#domain:www.youtube.com
