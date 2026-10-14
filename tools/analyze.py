#!/usr/bin/env python3
"""Phishing triage helper: parse an .eml, flag header/content red flags, extract IOCs.
Stdlib only. Makes NO network calls - IOC lookups are done by you (links are generated).
Usage: python tools/analyze.py samples/01.eml [--json analysis/01.json]
"""
import argparse, email, hashlib, ipaddress, json, re, sys
from email import policy
from html.parser import HTMLParser

PRIVATE = [ipaddress.ip_network(n) for n in
           ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")]
RISKY_EXT = {".exe", ".scr", ".js", ".vbs", ".jar", ".iso", ".img", ".lnk", ".html", ".htm",
             ".hta", ".docm", ".xlsm", ".zip", ".rar", ".one", ".bat", ".cmd", ".ps1"}
URGENCY = ["urgent", "immediately", "suspended", "verify your", "action required",
           "password expires", "unusual activity", "within 24 hours", "final notice", "confirm your"]
BRANDS = ("microsoft", "paypal", "amazon", "apple", "google", "docusign", "dhl", "bank",
          "binance", "coindesk", "ripple", "bradesco", "livelo", "netflix", "dropbox")
IGNORE_HOSTS = ("w3.org", "googleapis.com", "gstatic.com", "facebook.com", "twitter.com",
                "instagram.com", "linkedin.com", "youtube.com", "imgur.com", "telegram.me",
                "reddit.com", "getbee.io")
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.links = []; self._href = None; self._text = ""
    def handle_starttag(self, tag, attrs):
        if tag == "a": self._href = dict(attrs).get("href"); self._text = ""
    def handle_data(self, d):
        if self._href is not None: self._text += d
    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, self._text.strip())); self._href = None


def domain_of(addr):
    addr = str(addr or "")
    m = re.findall(r"<([^<>\s]+@[^<>\s]+)>", addr) or re.findall(r"[\w.+-]+@[\w.-]+", addr)
    return m[-1].split("@")[-1].lower() if m else ""

def host_of(url):
    m = re.match(r"https?://([^/:?#]+)", url, re.I)
    return m.group(1).lower() if m else ""

def is_public(ip):
    try: o = ipaddress.ip_address(ip)
    except ValueError: return False
    return not any(o in n for n in PRIVATE)

def defang(s):
    return s.replace("http", "hxxp").replace(".", "[.]")

def safe_content(part):
    """Decode a text part; fall back to raw bytes if the charset is bad."""
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")

def auth_result(msg, mech):
    """Return pass/fail/softfail/none/... for spf|dkim|dmarc from Authentication-Results."""
    for h in msg.get_all("Authentication-Results", []):
        m = re.search(rf"\b{mech}\s*=\s*(\w+)", str(h), re.I)
        if m: return m.group(1).lower()
    if mech == "spf":
        for h in msg.get_all("Received-SPF", []):
            m = re.match(r"\s*(\w+)", str(h))
            if m: return m.group(1).lower()
    return "none"

def related(a, b):
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def analyze(path):
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
    r = {"file": path, "flags": [], "iocs": {}}
    frm, rp, reply = msg["From"] or "", msg["Return-Path"] or "", msg["Reply-To"] or ""
    r["headers"] = {k: str(msg[k] or "") for k in ("From", "To", "Subject", "Date", "Message-ID", "Return-Path", "Reply-To")}
    fd, rd, rpd = domain_of(frm), domain_of(rp), domain_of(reply)

    # Received chain (oldest first) and public IPs
    hops, ips = [], []
    for h in reversed(msg.get_all("Received", [])):
        h = " ".join(str(h).split()); hops.append(h)
        ips += [i for i in IP_RE.findall(h) if is_public(i)]
    r["received_chain"] = hops
    r["iocs"]["ips"] = sorted(set(ips))

    # Authentication results
    r["auth"] = {m: auth_result(msg, m) for m in ("spf", "dkim", "dmarc")}
    for m, v in r["auth"].items():
        if v in ("fail", "softfail", "permerror", "temperror"): r["flags"].append(f"{m.upper()} {v}")
        elif v == "none": r["flags"].append(f"{m.upper()} not present")

    # Alignment: did SPF/DKIM pass for the From domain, or for someone else?
    ar_text = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    m_spf = re.search(r"smtp\.mailfrom=([^;\s)]+)", ar_text, re.I)
    m_dkim = re.search(r"header\.d=([^;\s)]+)", ar_text, re.I)
    spf_dom = m_spf.group(1).split("@")[-1].lower() if m_spf else ""
    dkim_dom = m_dkim.group(1).lower() if m_dkim else ""
    if r["auth"]["spf"] == "pass" and spf_dom and fd and not related(spf_dom, fd):
        r["flags"].append(f"SPF passed for {spf_dom}, not the From domain ({fd}): not aligned")
    if r["auth"]["dkim"] == "pass" and dkim_dom not in ("", "none") and fd and not related(dkim_dom, fd):
        r["flags"].append(f"DKIM passed for {dkim_dom}, not the From domain ({fd}): not aligned")

    # Identity mismatches
    if fd and rd and not related(fd, rd):
        r["flags"].append(f"Return-Path domain ({rd}) differs from From domain ({fd})")
    if fd and rpd and not related(fd, rpd):
        r["flags"].append(f"Reply-To domain ({rpd}) differs from From domain ({fd})")
    name = re.sub(r"<[^>]*>", "", str(frm)).lower()
    for brand in BRANDS:
        if brand in name and brand not in fd:
            r["flags"].append(f"Display name mentions '{brand}' but sender domain is {fd}")

    # Body text and links
    text, html = "", ""
    for part in msg.walk():
        ct = part.get_content_type()
        if part.get_content_disposition() == "attachment": continue
        if ct == "text/plain": text += safe_content(part)
        elif ct == "text/html": html += safe_content(part)
    body = (text + " " + html).lower()
    hit = [w for w in URGENCY if w in body]
    if hit: r["flags"].append("Urgency/pressure language: " + ", ".join(hit))

    urls = set(URL_RE.findall(text + " " + html))
    lp = LinkParser(); lp.feed(html)
    for href, label in lp.links:
        if not href: continue
        urls.add(href)
        lh = re.search(r"(?:https?://)?([\w.-]+\.[a-z]{2,})", label, re.I)
        if lh and host_of(href) and lh.group(1).lower() not in host_of(href):
            r["flags"].append(f"Link text shows '{label}' but points to {host_of(href)}")
    urls = {u.rstrip(".,;") for u in urls if u.lower().startswith("http")}
    hosts = {host_of(u) for u in urls}

    # Do any links go to the sender's own domain?
    link_hosts = {h for h in hosts if h and not any(h == s or h.endswith("." + s) for s in IGNORE_HOSTS)}
    if fd and link_hosts and not any(related(h, fd) for h in link_hosts):
        r["flags"].append(f"No link points to the From domain ({fd}); links go to: " + ", ".join(sorted(link_hosts)))

    for h in hosts:
        if IP_RE.fullmatch(h): r["flags"].append(f"URL uses raw IP host: {h}")
        if "xn--" in h: r["flags"].append(f"Punycode domain in URL: {h}")
    r["iocs"]["urls"] = sorted(urls)
    r["iocs"]["domains"] = sorted({h for h in hosts if h and not IP_RE.fullmatch(h)} | {d for d in (fd, rd, rpd) if d})

    # Attachments (hashed only, never opened)
    atts = []
    for part in msg.iter_attachments():
        data = part.get_payload(decode=True) or b""
        fn = part.get_filename() or "(unnamed)"
        atts.append({"filename": fn, "type": part.get_content_type(), "size": len(data),
                     "sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest()})
        parts = fn.lower().split(".")
        if len(parts) > 2: r["flags"].append(f"Double extension on attachment: {fn}")
        if "." + parts[-1] in RISKY_EXT: r["flags"].append(f"Risky attachment type: {fn}")
    r["attachments"] = atts
    r["iocs"]["hashes"] = [a["sha256"] for a in atts]
    r["risk_score"] = len(r["flags"])
    return r


def lookup_links(r):
    out = []
    for ip in r["iocs"]["ips"]:
        out.append(f"- IP {ip}: https://www.abuseipdb.com/check/{ip} | https://www.virustotal.com/gui/ip-address/{ip}")
    for d in r["iocs"]["domains"]:
        out.append(f"- Domain {d}: https://www.virustotal.com/gui/domain/{d} | https://urlscan.io/search/#domain:{d}")
    for h in r["iocs"]["hashes"]:
        out.append(f"- Hash {h[:16]}...: https://www.virustotal.com/gui/file/{h}")
    return out

def report(r):
    L = [f"# Analysis: {r['file']}", ""]
    for k, v in r["headers"].items(): L.append(f"- **{k}:** {v}")
    L += ["", f"**Auth:** SPF={r['auth']['spf']}  DKIM={r['auth']['dkim']}  DMARC={r['auth']['dmarc']}", "",
          "## Received chain (oldest first)"] + [f"{i}. {h}" for i, h in enumerate(r["received_chain"], 1)]
    L += ["", f"## Red flags ({r['risk_score']})"] + ([f"- {f}" for f in r["flags"]] or ["- none"])
    L += ["", "## IOCs (defanged)"]
    L += [f"- ip: {defang(i)}" for i in r["iocs"]["ips"]] + [f"- url: {defang(u)}" for u in r["iocs"]["urls"]]
    L += [f"- domain: {defang(d)}" for d in r["iocs"]["domains"]]
    L += [f"- attachment: {a['filename']} sha256={a['sha256']}" for a in r["attachments"]]
    L += ["", "## Manual lookups"] + lookup_links(r)
    return "\n".join(L)


if __name__ == "__main__":
    # Windows consoles default to cp1252; force UTF-8 so emoji/accents do not crash printing.
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(); ap.add_argument("eml"); ap.add_argument("--json")
    a = ap.parse_args(); res = analyze(a.eml)
    print(report(res))
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2, ensure_ascii=False)