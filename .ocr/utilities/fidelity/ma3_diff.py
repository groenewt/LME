#!/usr/bin/env python3
"""MA3 fidelity diff: rendered LLM-stack units (produced under real ansible in
ma3_rendered/default/) vs their current static targets. Reuses the G1 harness'
order/comment/whitespace-insensitive semantic normaliser (the annotation-stripping
regex recovers glued-annotation values, e.g. dashboard SSL_KEYFILE...#@@TODO)."""
import re, difflib, os

REPO = "/home/tristan/gitters/LME"
REND = "/tmp/claude-1000/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/scratchpad/ma3_rendered/default"

# pairs: (label, rendered_file, static_target_abs)
PAIRS = [
    ("pgvector.container",       "lme-pgvector.container",     f"{REPO}/quadlet/lme-pgvector.container"),
    ("pgvectordata.volume",      "lme-pgvectordata.volume",    f"{REPO}/quadlet/lme-pgvectordata.volume"),
    ("llama-cpp.container",      "lme-llama-cpp.container",     f"{REPO}/quadlet/lme-llama-cpp.container"),
    ("embeddings.container",     "lme-embeddings.container",    f"{REPO}/quadlet/lme-embeddings.container"),
    ("dashboard.container",      "lme-dashboard.container",     f"{REPO}/quadlet/lme-dashboard.container"),
    ("log-analyzer.container",   "lme-log-analyzer.container",  f"{REPO}/quadlet/lme-log-analyzer.container"),
    ("llama-model.path",         "lme-llama-model.path",        f"{REPO}/systemd/lme-llama-model.path"),
    ("llama-model.service",      "lme-llama-model.service",     f"{REPO}/systemd/lme-llama-model.service"),
]

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
            k, v = line.split("=", 1); line = k.rstrip() + "=" + v.lstrip()
        if cur is None:
            cur = "(preamble)"; out.setdefault(cur, set())
        out[cur].add(line)
    return {s: sorted(v) for s, v in out.items()}


def semantic_diff(old_text, new_text):
    o, n = normalize(old_text), normalize(new_text)
    rep = []
    for sec in sorted(set(o) | set(n)):
        oset, nset = set(o.get(sec, [])), set(n.get(sec, []))
        rem, add = sorted(oset - nset), sorted(nset - oset)
        if rem or add:
            rep.append((sec, rem, add))
    return rep


all_clean = True
for label, rf, sf in PAIRS:
    new = open(os.path.join(REND, rf)).read()
    old = open(sf).read()
    print("=" * 78)
    print(f"{label}   [rendered]  vs  [static {os.path.relpath(sf, REPO)}]")
    print("=" * 78)
    rd = "".join(difflib.unified_diff(old.splitlines(keepends=True),
                                      new.splitlines(keepends=True),
                                      fromfile="static", tofile="rendered", n=1))
    print("--- RAW unified diff (cosmetic + intended) ---")
    print(rd if rd.strip() else "(byte-identical)")
    sd = semantic_diff(old, new)
    print("--- SEMANTIC diff (order/comment/whitespace/annotation-insensitive) ---")
    if not sd:
        print("*** NO SEMANTIC DIFF -- identical modulo comments/order/whitespace/annotations ***")
    else:
        all_clean = False
        for sec, rem, add in sd:
            print(f"  {sec}")
            for r in rem:
                print(f"    - {r}")
            for a in add:
                print(f"    + {a}")
    print()

print("=" * 78)
print("SUMMARY:", "ALL CLEAN (no unintended semantic delta)" if all_clean
      else "SEE DELTAS ABOVE")
