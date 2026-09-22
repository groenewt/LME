#!/usr/bin/env python3
"""Purely-additive tailnet ACL patch: add 4 LME svc autoApprovers + one reachability grant.
Byte-exact: two unique-anchored insertions, assert each matches exactly once, everything else identical."""
import sys, re, difflib, json

SRC = sys.argv[1]          # tailnet-acl.live.hujson
DST = sys.argv[2]          # tailnet-acl.patched.hujson
live = open(SRC).read()

# --- Insertion A: one reachability grant, appended inside the grants array (after the last tmptag grant) ---
anchor_a = (
    '\t\t{\n'
    '\t\t\t"src": ["tag:tmptag-client"],\n'
    '\t\t\t"dst": ["svc:tmptag-tcp"],\n'
    '\t\t\t"ip":  ["tcp:15045"],\n'
    '\t\t},\n'
)
add_a = anchor_a + (
    '\t\t// LME host-facing UI/API VIPs (opt-in via manifest tailnet_service; wave-12).\n'
    '\t\t// Reach the four fronted services from the operator\'s own devices. ip:["*"]\n'
    '\t\t// keeps the served ports in the manifests, not duplicated in policy.\n'
    '\t\t{\n'
    '\t\t\t"src": ["tag:personal", "famgroenewoldt@gmail.com"],\n'
    '\t\t\t"dst": ["svc:lme-kibana", "svc:lme-dashboard", "svc:lme-log-analyzer", "svc:lme-litellm"],\n'
    '\t\t\t"ip":  ["*"],\n'
    '\t\t},\n'
)

# --- Insertion B: 4 svc autoApprovers, appended inside autoApprovers.services (after the last tmptag svc) ---
anchor_b = '\t\t\t"svc:tmptag-tcp":  ["tag:machine-silmaril", "tag:tmptag-svc"],\n'
LME_TAGS = '["tag:machine-graph", "tag:machine-trixie", "tag:machine-silmaril", "tag:machine-type-cluster-main"]'
add_b = anchor_b + (
    f'\t\t\t"svc:lme-kibana":       {LME_TAGS},\n'
    f'\t\t\t"svc:lme-dashboard":    {LME_TAGS},\n'
    f'\t\t\t"svc:lme-log-analyzer": {LME_TAGS},\n'
    f'\t\t\t"svc:lme-litellm":      {LME_TAGS},\n'
)

for name, anchor in (("A/grant", anchor_a), ("B/autoApprovers", anchor_b)):
    n = live.count(anchor)
    if n != 1:
        sys.exit(f"ABORT: anchor {name} matched {n} times (want exactly 1) — not patching.")

patched = live.replace(anchor_a, add_a, 1).replace(anchor_b, add_b, 1)

# Additivity proof: deleting the exact lines I added must return the original, byte-for-byte.
reverted = patched.replace(add_a, anchor_a, 1).replace(add_b, anchor_b, 1)
if reverted != live:
    sys.exit("ABORT: patch is not purely additive (reverting added lines != original).")

# Structural sanity: strip // comments + trailing commas, then json.loads the result.
def hujson_to_json(s):
    s = re.sub(r'//[^\n]*', '', s)                 # line comments
    s = re.sub(r',(\s*[}\]])', r'\1', s)           # trailing commas
    return s
try:
    doc = json.loads(hujson_to_json(patched))
except Exception as e:
    sys.exit(f"ABORT: patched doc is not structurally valid JSON after comment/comma strip: {e}")

# Confirm exactly the 4 new services + they carry the 4 tags; co-tenant tmptag intact.
svcs = doc["autoApprovers"]["services"]
assert set(svcs) == {"svc:tmptag-echo","svc:tmptag-tcp","svc:lme-kibana","svc:lme-dashboard","svc:lme-log-analyzer","svc:lme-litellm"}, svcs
for s in ("svc:lme-kibana","svc:lme-dashboard","svc:lme-log-analyzer","svc:lme-litellm"):
    assert svcs[s] == ["tag:machine-graph","tag:machine-trixie","tag:machine-silmaril","tag:machine-type-cluster-main"], (s, svcs[s])
assert svcs["svc:tmptag-echo"] == ["tag:machine-silmaril","tag:tmptag-svc"]   # co-tenant untouched
# allow-all grant still present + identical
assert {"src":["tag:personal","*"],"dst":["tag:personal","*"],"ip":["*"]} in doc["grants"], "allow-all grant changed!"
ng = len(doc["grants"])

open(DST, "w").write(patched)
print(f"OK: patched written to {DST}")
print(f"grants: {len(json.loads(hujson_to_json(live))['grants'])} -> {ng} (added 1)")
print(f"autoApprovers.services: {len(svcs)-4} -> {len(svcs)} (added 4)")
print(f"bytes: {len(live)} -> {len(patched)} (+{len(patched)-len(live)})")
print("\n===== UNIFIED DIFF (live -> patched) =====")
for line in difflib.unified_diff(live.splitlines(True), patched.splitlines(True),
                                 "tailnet-acl.live.hujson", "tailnet-acl.patched.hujson"):
    sys.stdout.write(line)
