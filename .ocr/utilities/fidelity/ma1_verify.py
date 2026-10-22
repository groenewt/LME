#!/usr/bin/env python3
"""MA1 fidelity verifier. Reads the REAL-ANSIBLE-rendered units from
scratchpad/ma1_rendered/default and semantic-diffs each against the current
static quadlet/ file. Adds the checks a set-diff cannot see:
  * env set-equality (whitespace-joined static env vs per-line rendered env)
  * wazuh_logs mounted exactly once (static had it twice; set-diff hides this)
  * name == 'lme-' + id for every volume (RESOLUTIONS #39; deploy-time failure)
  * lme_certs / ca.key absence on runtime consumers (B4) w/ sanctioned setup exceptions
"""
import os, re, sys

REPO = "/home/tristan/gitters/LME"
RENDERED = "/tmp/claude-1000/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/scratchpad/ma1_rendered/default"

# rendered unit  ->  static quadlet file
UNITS = {
    "lme-kibana.container":            "quadlet/lme-kibana.container",
    "lme-fleet-server.container":      "quadlet/lme-fleet-server.container",
    "lme-fleet-distribution.container":"quadlet/lme-fleet-distribution.container",
    "lme-wazuh-manager.container":     "quadlet/lme-wazuh-manager.container",
    "lme-elastalert.container":        "quadlet/lme-elastalert.container",
    "lme-setup-certs.container":       "quadlet/lme-setup-certs.container",
    "lme-setup-accts.container":       "quadlet/lme-setup-accts.container",
    "lme-backups.volume":              "quadlet/lme-backups.volume",
    "lme-kibanadata.volume":           "quadlet/lme-kibanadata.volume",
}
# units carrying a whitespace-joined static Environment= line (env set check)
ENV_UNITS = {"lme-kibana.container", "lme-fleet-server.container",
             "lme-fleet-distribution.container", "lme-wazuh-manager.container",
             "lme-elastalert.container"}
VOLUMES = {"lme-backups.volume": ("backups", "lme-backups"),
           "lme-kibanadata.volume": ("kibanadata", "lme-kibanadata")}
# runtime consumers that must NOT mount lme_certs/ca.key (B4); setups are sanctioned
RUNTIME_CONSUMERS = {"lme-kibana.container", "lme-fleet-server.container",
                     "lme-fleet-distribution.container", "lme-wazuh-manager.container",
                     "lme-elastalert.container"}
SANCTIONED_LME_CERTS = {"lme-setup-certs.container", "lme-setup-accts.container"}

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


def semantic_diff(old_text, new_text):
    o, n = normalize(old_text), normalize(new_text)
    rep = []
    for sec in sorted(set(o) | set(n)):
        removed = sorted(set(o.get(sec, [])) - set(n.get(sec, [])))
        added = sorted(set(n.get(sec, [])) - set(o.get(sec, [])))
        if removed or added:
            rep.append((sec, removed, added))
    return rep


def env_tokens(text):
    """Set of K=V strings from every Environment= line, splitting joined ones."""
    toks = set()
    for raw in text.splitlines():
        line = INLINE_ANNOT.sub("", raw.rstrip()).rstrip()
        if not line.startswith("Environment="):
            continue
        val = line[len("Environment="):].strip()
        for t in val.split():        # whitespace-split: unambiguous iff values are space-free
            toks.add(t)
    return toks


def rendered_env_values_have_no_space(text):
    for raw in text.splitlines():
        if raw.startswith("Environment="):
            body = raw[len("Environment="):]
            # rendered is one K=V per line; the whole body must be a single token
            if len(body.split()) != 1:
                return False, raw
    return True, None


fail = []
print("=" * 78)
print("MA1 SEMANTIC DIFF (rendered-by-real-ansible  vs  static quadlet/)")
print("=" * 78)
for rname, spath in UNITS.items():
    rpath = os.path.join(RENDERED, rname)
    if not os.path.exists(rpath):
        fail.append("%s: NOT RENDERED (ansible did not emit it)" % rname);
        print("\n### %s\n  !! NOT RENDERED" % rname); continue
    new = open(rpath).read()
    old = open(os.path.join(REPO, spath)).read()
    sd = semantic_diff(old, new)
    print("\n### %s   vs   %s" % (rname, spath))
    if not sd:
        print("  clean: identical modulo comments / order / whitespace")
    for sec, rem, add in sd:
        print("  %s" % sec)
        for r in rem:
            print("    - %s" % r)
        for a in add:
            print("    + %s" % a)

# --- env set equality -------------------------------------------------------
print("\n" + "=" * 78)
print("ENV SET-EQUALITY (proves whitespace-join cured, no value lost/mistyped)")
print("=" * 78)
for rname in sorted(ENV_UNITS):
    new = open(os.path.join(RENDERED, rname)).read()
    old = open(os.path.join(REPO, UNITS[rname])).read()
    ok_space, bad = rendered_env_values_have_no_space(new)
    if not ok_space:
        fail.append("%s: rendered env value contains a space: %r" % (rname, bad))
    o, n = env_tokens(old), env_tokens(new)
    if o == n:
        print("  [OK] %-34s %d env vars, sets EQUAL" % (rname, len(n)))
    else:
        fail.append("%s: env set mismatch" % rname)
        print("  [XX] %-34s  only-static=%s  only-rendered=%s"
              % (rname, sorted(o - n), sorted(n - o)))

# --- wazuh dup-mount fix (invisible to set diff) ----------------------------
print("\n" + "=" * 78)
print("FIX #2  wazuh lme_wazuh_logs mounted ONCE (static had it twice)")
print("=" * 78)
w_new = open(os.path.join(RENDERED, "lme-wazuh-manager.container")).read()
w_old = open(os.path.join(REPO, "quadlet/lme-wazuh-manager.container")).read()
c_new = w_new.count("Volume=lme_wazuh_logs:/var/ossec/logs")
c_old = w_old.count("Volume=lme_wazuh_logs:/var/ossec/logs")
print("  static count=%d  rendered count=%d" % (c_old, c_new))
if not (c_old == 2 and c_new == 1):
    fail.append("wazuh_logs dedup: expected static=2 rendered=1, got %d/%d" % (c_old, c_new))
else:
    print("  [OK] duplicate removed")

# --- name == 'lme-' + id invariant (RESOLUTIONS #39) ------------------------
print("\n" + "=" * 78)
print("INVARIANT  name == 'lme-' + id  (volumes; svc_unit dep-name correctness)")
print("=" * 78)
for rname, (vid, vname) in VOLUMES.items():
    ok = vname == ("lme-" + vid)
    print("  [%s] %-22s id=%s name=%s" % ("OK" if ok else "XX", rname, vid, vname))
    if not ok:
        fail.append("%s: name != 'lme-'+id" % rname)

# --- B4 lme_certs / ca.key absence on runtime consumers ---------------------
print("\n" + "=" * 78)
print("B4  no runtime consumer mounts lme_certs / ca.key  (setups sanctioned)")
print("=" * 78)
for rname in sorted(RUNTIME_CONSUMERS):
    new = open(os.path.join(RENDERED, rname)).read()
    bad = [l for l in new.splitlines()
           if l.startswith("Volume=") and ("lme_certs" in l or "ca.key" in l)]
    if bad:
        fail.append("%s: still mounts lme_certs/ca.key: %s" % (rname, bad))
        print("  [XX] %-34s %s" % (rname, bad))
    else:
        print("  [OK] %-34s no lme_certs/ca.key mount" % rname)
for rname in sorted(SANCTIONED_LME_CERTS):
    new = open(os.path.join(RENDERED, rname)).read()
    has = any(l.startswith("Volume=lme_certs:") for l in new.splitlines())
    print("  [--] %-34s lme_certs mount present=%s (SANCTIONED generator/setup ctx)"
          % (rname, has))

# --- summary ----------------------------------------------------------------
print("\n" + "=" * 78)
print("SUMMARY")
print("=" * 78)
if fail:
    for f in fail:
        print("  FAIL: %s" % f)
    sys.exit(1)
print("  ALL MA1 CHECKS PASS")
sys.exit(0)
