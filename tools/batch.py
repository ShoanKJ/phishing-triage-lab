import csv, glob, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from analyze import analyze, domain_of

OUT = os.path.join(BASE, "triage")
os.makedirs(OUT, exist_ok=True)
rows = []
for p in sorted(glob.glob("raw_private/*.eml")):
    try:
        r = analyze(p)
    except Exception as e:
        print("FAILED", p, e); continue
    rows.append({
        "file": os.path.basename(p),
        "subject": r["headers"]["Subject"][:60],
        "from_domain": domain_of(r["headers"]["From"]),
        "return_path_domain": domain_of(r["headers"]["Return-Path"]),
        "spf": r["auth"]["spf"], "dkim": r["auth"]["dkim"], "dmarc": r["auth"]["dmarc"],
        "flag_count": r["risk_score"],
        "ips": " ".join(r["iocs"]["ips"]),
        "domains": " ".join(r["iocs"]["domains"]),
        "url_count": len(r["iocs"]["urls"]),
        "attachments": " ".join(a["filename"] for a in r["attachments"]),
        "flags": " | ".join(r["flags"]),
        "my_verdict": "", "my_notes": "",
    })

with open(os.path.join(OUT, "triage.csv"), "w", newline="", encoding="utf-8-sig") as f: 
    w = csv.DictWriter(f, fieldnames=rows[0].keys())
    w.writeheader(); w.writerows(rows)

print(f"{'FILE':16} {'SPF':9} {'DKIM':9} {'DMARC':10} {'FLAGS':5} FROM-DOMAIN")
for x in rows:
    print(f"{x['file']:16} {x['spf']:9} {x['dkim']:9} {x['dmarc']:10} {x['flag_count']:<5} {x['from_domain']}")
print(f"\n{len(rows)} samples -> triage/triage.csv")