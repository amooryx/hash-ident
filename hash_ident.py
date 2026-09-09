import re, rclib
def run(ctx):
    h = ctx.target.strip()
    hx = bool(re.fullmatch(r"[0-9a-fA-F]+", h))
    n = len(h)
    cands = []
    if hx and n==32: cands=["MD5","NTLM","MD4","LM (half)"]
    elif hx and n==40: cands=["SHA-1","MySQL5.x (with *)"]
    elif hx and n==56: cands=["SHA-224"]
    elif hx and n==64: cands=["SHA-256","SHA3-256","BLAKE2s"]
    elif hx and n==96: cands=["SHA-384"]
    elif hx and n==128: cands=["SHA-512","SHA3-512","Whirlpool"]
    if h.startswith("$2a$") or h.startswith("$2b$") or h.startswith("$2y$"): cands=["bcrypt"]
    elif h.startswith("$1$"): cands=["md5crypt"]
    elif h.startswith("$5$"): cands=["sha256crypt"]
    elif h.startswith("$6$"): cands=["sha512crypt"]
    elif h.startswith("$argon2"): cands=["Argon2"]
    elif h.startswith("$krb5tgs$"): cands=["Kerberos TGS-REP (kerberoast)"]
    elif h.startswith("$krb5asrep$"): cands=["Kerberos AS-REP (asreproast)"]
    elif ":" in h and re.fullmatch(r"[0-9a-fA-F]{32}:[0-9a-fA-F]{32}", h): cands=["NetNTLM / PWDUMP"]
    if not cands:
        ctx.warn("unrecognised format"); return 0
    ctx.good(f"length {n}" + (" hex" if hx else ""))
    for c in cands: ctx.finding(f"candidate: {c}", "info")
    # hashcat mode hints
    modes = {"MD5":"0","NTLM":"1000","SHA-1":"100","SHA-256":"1400","SHA-512":"1800",
             "bcrypt":"3200","sha512crypt":"1800","Kerberos TGS-REP (kerberoast)":"13100",
             "Kerberos AS-REP (asreproast)":"18200","NetNTLM / PWDUMP":"5600"}
    for c in cands:
        if c in modes: ctx.step(f"hashcat -m {modes[c]}  ({c})")
    ctx.data["candidates"] = cands
    return 0
rclib.main("hash-ident", "Identify hash type + hashcat mode", run)
