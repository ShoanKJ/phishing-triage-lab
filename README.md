# Phishing Email Triage Lab

Tier 1 SOC-style investigation of phishing emails: header forensics (Received chain, SPF/DKIM/DMARC),
IOC extraction and enrichment, ATT&CK mapping, and a per-email verdict with recommended action.

## Workflow
1. Put samples in `samples/` as `.eml` (mix of phishing AND legitimate mail). Remove personal data first.
2. `python tools/analyze.py samples/<id>.eml --json analysis/<id>.json > reports/<id>_analysis.md`
3. Look up each IOC (links are generated in the output) in VirusTotal, URLScan, AbuseIPDB.
4. Copy `reports/TEMPLATE_incident_report.md` to `reports/<id>.md` and fill it in.
5. Add a row to `verdicts.csv`, then `python tools/summarize.py > SUMMARY.md`.

## What the script flags
Auth failures, Return-Path/Reply-To mismatches, brand-in-display-name spoofing, urgency language,
link text vs real destination, raw-IP and punycode URLs, risky/double-extension attachments.
It is a triage aid, not a verdict: you decide (see S04, a legitimate ESP email that still trips a flag).

## Sample sources
- Public: Nazario phishing corpus, PhishTank, malware-traffic-analysis.net (email-based posts).
- Own spam folder: save as .eml, redact recipients and tracking IDs.
- `S01`-`S04` are **synthetic** (reserved domains and documentation IPs) so the tooling can be tested.
  Replace them with real samples before quoting any numbers.

## Safety
Never open attachments or click links on your host. Analyse text only; use defanged IOCs in reports.

## Results
See `SUMMARY.md`.

Raw samples are not included. They come from phishing_pot (github.com/rf-peixoto/phishing_pot).
