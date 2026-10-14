#!/usr/bin/env python3
"""Merge analysis/*.json with your verdicts.csv into the summary table + headline numbers.
Usage: python tools/summarize.py > SUMMARY.md
"""
import csv, glob, json, os, collections

analysis = {os.path.splitext(os.path.basename(p))[0]: json.load(open(p)) for p in glob.glob("analysis/*.json")}
rows = list(csv.DictReader(open("verdicts.csv")))
print("# Phishing Triage Summary\n")
print("| ID | Verdict | Technique | Action | SPF | DKIM | DMARC | Flags | IOCs | Notes |")
print("|---|---|---|---|---|---|---|---|---|---|")
tot = collections.Counter(); fails = collections.Counter(); iocs = 0
for r in rows:
    a = analysis.get(r["id"])
    if not a:
        print(f"| {r['id']} | {r['verdict']} | {r['technique']} | {r['action']} | ? | ? | ? | ? | ? | run analyze.py |"); continue
    n = sum(len(v) for v in a["iocs"].values())
    if r["verdict"] == "malicious": iocs += n
    tot[r["verdict"]] += 1
    for m, v in a["auth"].items():
        if v in ("fail", "softfail", "none"): fails[m.upper()] += 1
    print(f"| {r['id']} | {r['verdict']} | {r['technique']} | {r['action']} | {a['auth']['spf']} | {a['auth']['dkim']} | {a['auth']['dmarc']} | {a['risk_score']} | {n} | {r['notes']} |")
print(f"\n**Samples:** {sum(tot.values())} | **Malicious:** {tot['malicious']} | **Legitimate:** {tot['legitimate']} | **IOCs from malicious samples:** {iocs}")
print("\n**Auth failures/missing (all samples):** " + ", ".join(f"{k}: {v}" for k, v in fails.items()))
