import email, glob, os
from email import policy

print(f"{'FILE':32} {'AUTH':5} {'SPF':5} {'DKIM':5} {'RCVD':5} {'ATT':4} SUBJECT")
for p in sorted(glob.glob("raw_private/*.eml")):
    with open(p, "rb") as f:
        m = email.message_from_binary_file(f, policy=policy.default)
    auth = bool(m.get_all("Authentication-Results"))
    spf = bool(m.get_all("Received-SPF")) or auth
    dkim = bool(m.get_all("DKIM-Signature"))
    rcvd = len(m.get_all("Received", []))
    att = sum(1 for _ in m.iter_attachments())
    print(f"{os.path.basename(p)[:32]:32} {str(auth):5} {str(spf):5} {str(dkim):5} {rcvd:<5} {att:<4} {str(m['Subject'])[:50]}")