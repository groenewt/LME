#!/usr/bin/env python3
"""MA-ES fidelity: semantic-diff each rendered unit vs its current quadlet-optional
counterpart. Reuses G1's normalize() (order/comment/whitespace-insensitive,
section-set). Authoritative proof: the delta must be ONLY the intended B4 mount
change + deliberate uid drop (+ logstash env quote-form normalization)."""
import re, os

REPO = "/home/tristan/gitters/LME"
OLD = os.path.join(REPO, "quadlet-optional/elastic-services")
NEW = "/tmp/claude-1000/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/scratchpad/ma-es/rendered/default"

COMMENT_LINE = re.compile(r"^\s*#")
INLINE_ANNOT = re.compile(r"(#@+.*$)|(#TO[OA]?D.*$)|(\s+#.*$)")
SECTION = re.compile(r"^\[[A-Za-z]+\]\s*$")


def normalize(text):
    out, cur = {}, None
    for raw in text.splitlines():
        line = raw.rstrip()
        if SECTION.match(line.strip()):
            cur = line.strip(); out.setdefault(cur, set()); continue
        if not line.strip() or COMMENT_LINE.match(line):
            continue
        line = INLINE_ANNOT.sub("", line).rstrip()
        if not line:
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            line = k.rstrip() + "=" + v.lstrip()
        if cur is None:
            cur = "(preamble)"; out.setdefault(cur, set())
        out[cur].add(line)
    return {s: sorted(v) for s, v in out.items()}


def sdiff(old, new):
    o, n = normalize(old), normalize(new)
    rep = []
    for sec in sorted(set(o) | set(n)):
        oset, nset = set(o.get(sec, [])), set(n.get(sec, []))
        rem, add = sorted(oset - nset), sorted(nset - oset)
        if rem or add:
            rep.append((sec, rem, add))
    return rep


pairs = [
    ("lme-apm-server.container", "lme-apm-server.container"),
    ("lme-heartbeat.container", "lme-heartbeat.container"),
    ("lme-metricbeat.container", "lme-metricbeat.container"),
    ("lme-logstash.container", "lme-logstash.container"),
    ("lme-filebeatdata.volume", "lme-filebeatdata.volume"),
]

for oldn, newn in pairs:
    old = open(os.path.join(OLD, oldn)).read()
    new = open(os.path.join(NEW, newn)).read()
    print("\n" + "=" * 74)
    print("SEMANTIC DIFF  %s   (OLD static  ->  NEW rendered)" % oldn)
    print("=" * 74)
    rep = sdiff(old, new)
    if not rep:
        print("  *** NO SEMANTIC DIFF (identical modulo comments/order/whitespace) ***")
    for sec, rem, add in rep:
        print("  %s" % sec)
        for r in rem:
            print("    - %s" % r)
        for a in add:
            print("    + %s" % a)

# ---- acceptance greps over MY FIVE rendered units (+ filebeat exemplar) --------
print("\n" + "=" * 74)
print("ACCEPTANCE GREP  (no rendered unit in my pack mounts lme_certs or ca.key)")
print("=" * 74)
mine = ["lme-apm-server.container", "lme-heartbeat.container",
        "lme-metricbeat.container", "lme-logstash.container",
        "lme-filebeatdata.volume", "lme-filebeat.container"]  # filebeat = pack exemplar
bad = 0
for u in mine:
    txt = open(os.path.join(NEW, u)).read()
    hits = [ln for ln in txt.splitlines()
            if ("lme_certs" in ln or "ca.key" in ln or "ca/ca.key" in ln)]
    tag = "CLEAN" if not hits else "!!!! HIT"
    if hits:
        bad += 1
    print("  [%s] %s" % (tag, u))
    for h in hits:
        print("        %s" % h)
print("  --> %s" % ("ALL CLEAN (zero lme_certs / ca.key mounts)" if bad == 0
                     else "%d unit(s) STILL MOUNT forbidden material" % bad))

# ---- show the exact B4 Volume lines my units DO carry --------------------------
print("\n" + "=" * 74)
print("B4 CERT MOUNTS actually emitted by my units (must be per-svc bundle, ro, no idmap)")
print("=" * 74)
for u in mine[:5] + ["lme-filebeat.container"]:
    txt = open(os.path.join(NEW, u)).read()
    for ln in txt.splitlines():
        if "/certs" in ln and ln.startswith("Volume="):
            print("  %-28s %s" % (u, ln))
