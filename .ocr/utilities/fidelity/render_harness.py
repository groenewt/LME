#!/usr/bin/env python3
"""G1 fidelity harness: render the exemplar manifests through the new
templates+filters and diff each rendered unit against the CURRENT artifact.

For ES the current artifact is the templated lme-elasticsearch.container.j2
rendered in a default (single-node/localhost) context and, separately, a cluster
context. For litellm/filebeat/volume/network/target/path_service the current
artifact is the static file on disk.

Output: for each unit a RAW unified diff and a SEMANTIC (order/comment/whitespace
-insensitive) section-set diff. The semantic diff is the authoritative proof:
it must show ONLY the intended changes (annotation removal, B1 caps, B4 mount).
"""
import sys, os, re, glob, copy, yaml, difflib

REPO = "/home/tristan/gitters/LME"
UNITS = os.path.join(REPO, "ansible/templates/units")
FILTERS = os.path.join(REPO, "ansible/roles/podman/filter_plugins")
MAN = os.path.join(REPO, "manifests")
sys.path.insert(0, FILTERS)
from lme_manifests import FilterModule  # noqa: E402
from jinja2 import Environment, FileSystemLoader, Undefined  # noqa: E402

env = Environment(loader=FileSystemLoader(UNITS), trim_blocks=True,
                  lstrip_blocks=True, undefined=Undefined, keep_trailing_newline=True)
env.filters.update(FilterModule().filters())

# ---- load manifests -------------------------------------------------------
gl = yaml.safe_load(open(os.path.join(MAN, "global.yml")))["lme_global"]


def load_profile(n):
    return yaml.safe_load(open(os.path.join(MAN, "profiles", n + ".yml")))["profile_overlay"]


services = {}
for f in sorted(glob.glob(os.path.join(MAN, "services", "*.yml"))):
    d = yaml.safe_load(open(f))
    services[d["id"]] = d

# kinds map: from exemplars + supplementary kinds for referenced non-exemplar deps
# (in the real deploy every services/*.yml is loaded, so all kinds are present).
kinds = {sid: s["kind"] for sid, s in services.items()}
kinds.update({"setup-certs": "container", "kibana": "container",
              "llama-cpp": "container", "filebeatdata": "volume"})


def merge(base, over):
    """recursive combine; lists REPLACE (ansible combine default)."""
    r = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(r.get(k), dict):
            r[k] = merge(r[k], v)
        else:
            r[k] = copy.deepcopy(v)
    return r


def compose_global(profile):
    return merge(gl, profile.get("lme_global", {}) or {})


def compose_service(sid, profile):
    return merge(services[sid], (profile.get("services", {}) or {}).get(sid, {}))


def render_new(sid, profile, part=None):
    svc = compose_service(sid, profile)
    lme_global = compose_global(profile)
    tmpl = env.get_template(svc["kind"] + ".j2")
    return tmpl.render(service=svc, lme_global=lme_global, kinds=kinds,
                       flags={}, render_part=part)


# ---- render the OLD elasticsearch .j2 as the ES fidelity target ------------
old_env = Environment(loader=FileSystemLoader(os.path.join(REPO, "ansible/templates")),
                      trim_blocks=True, lstrip_blocks=True, undefined=Undefined,
                      keep_trailing_newline=True)


def render_old_es(ctx):
    return old_env.get_template("lme-elasticsearch.container.j2").render(**ctx)


# ---- semantic normalisation ----------------------------------------------
COMMENT_LINE = re.compile(r"^\s*#")
INLINE_ANNOT = re.compile(r"(#@+.*$)|(#TO[OA]?D.*$)|(\s+#.*$)")
SECTION = re.compile(r"^\[[A-Za-z]+\]\s*$")


def normalize(text):
    """{section: sorted(set(directive))} with comments/blank/annotations/order
    removed and KEY= value left-trimmed. Order-insensitive semantic view."""
    out, cur = {}, None
    for raw in text.splitlines():
        line = raw.rstrip()
        if SECTION.match(line.strip()):
            cur = line.strip()
            out.setdefault(cur, set())
            continue
        if not line.strip() or COMMENT_LINE.match(line):
            continue
        line = INLINE_ANNOT.sub("", line).rstrip()
        if not line:
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            line = k.rstrip() + "=" + v.lstrip()
        if cur is None:
            cur = "(preamble)"
            out.setdefault(cur, set())
        out[cur].add(line)
    return {s: sorted(v) for s, v in out.items()}


def semantic_diff(old_text, new_text):
    o, n = normalize(old_text), normalize(new_text)
    report = []
    for sec in sorted(set(o) | set(n)):
        oset, nset = set(o.get(sec, [])), set(n.get(sec, []))
        removed = sorted(oset - nset)
        added = sorted(nset - oset)
        if removed or added:
            report.append((sec, removed, added))
    return report


def raw_diff(old_text, new_text, a, b):
    return "".join(difflib.unified_diff(
        old_text.splitlines(keepends=True), new_text.splitlines(keepends=True),
        fromfile=a, tofile=b, n=1))


def show(title, old_text, new_text, a, b):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)
    rd = raw_diff(old_text, new_text, a, b)
    print("--- RAW unified diff (cosmetic + intended) ---")
    print(rd if rd.strip() else "(byte-identical)")
    sd = semantic_diff(old_text, new_text)
    print("--- SEMANTIC diff (order/comment/whitespace-insensitive) ---")
    if not sd:
        print("*** NO SEMANTIC DIFF -- identical modulo comments/order/whitespace ***")
    for sec, rem, add in sd:
        print("  %s" % sec)
        for r in rem:
            print("    - %s" % r)
        for a2 in add:
            print("    + %s" % a2)
    return sd


results = {}

# 1. Elasticsearch DEFAULT (single-node) vs old .j2 single-node render
es_new_default = render_new("elasticsearch", load_profile("default"))
es_old_default = render_old_es({"inventory_hostname": "localhost"})
results["elasticsearch (default/single-node)"] = show(
    "1. lme-elasticsearch.container  [NEW default]  vs  [OLD .j2 single-node]",
    es_old_default, es_new_default, "OLD .j2 (single-node)", "NEW render (default)")

# 2. Elasticsearch CLUSTER vs old .j2 cluster render (proves B1 + transport)
es_new_cluster = render_new("elasticsearch", load_profile("cluster"))
es_old_cluster = render_old_es({"inventory_hostname": "lme-elasticsearch",
                                "es_discovery_type": "cluster"})
results["elasticsearch (cluster)"] = show(
    "2. lme-elasticsearch.container  [NEW cluster]  vs  [OLD .j2 cluster]  (B1 proof)",
    es_old_cluster, es_new_cluster, "OLD .j2 (cluster)", "NEW render (cluster profile)")

# 3. litellm vs static file
lit_old = open(os.path.join(REPO, "quadlet/lme-litellm.container")).read()
lit_new = render_new("litellm", load_profile("default"))
results["litellm"] = show(
    "3. lme-litellm.container  [NEW]  vs  [static quadlet/]",
    lit_old, lit_new, "static", "NEW render")

# 4. filebeat vs static file (B4)
fb_old = open(os.path.join(REPO, "quadlet-optional/elastic-services/lme-filebeat.container")).read()
fb_new = render_new("filebeat", load_profile("default"))
results["filebeat"] = show(
    "4. lme-filebeat.container  [NEW]  vs  [static]  (B4 proof)",
    fb_old, fb_new, "static", "NEW render")

# 5. esdata01 volume
v_old = open(os.path.join(REPO, "quadlet/lme-esdata01.volume")).read()
v_new = render_new("esdata01", load_profile("default"))
results["esdata01.volume"] = show(
    "5. lme-esdata01.volume  [NEW]  vs  [static]",
    v_old, v_new, "static", "NEW render")

# 6. network
n_old = open(os.path.join(REPO, "quadlet/lme.network")).read()
n_new = render_new("network", load_profile("default"))
results["lme.network"] = show(
    "6. lme.network  [NEW]  vs  [static]",
    n_old, n_new, "static", "NEW render")

# 7. target
t_old = open(os.path.join(REPO, "quadlet/lme.service")).read()
t_new = render_new("lme", load_profile("default"))
results["lme.service (target)"] = show(
    "7. lme.service  [NEW]  vs  [static]",
    t_old, t_new, "static", "NEW render")

# 8. path_service pair
p_old = open(os.path.join(REPO, "systemd/lme-llm-keys.path")).read()
p_new = render_new("llm-keys", load_profile("default"), part="path")
results["lme-llm-keys.path"] = show(
    "8a. lme-llm-keys.path  [NEW]  vs  [static]",
    p_old, p_new, "static", "NEW render")
s_old = open(os.path.join(REPO, "systemd/lme-llm-keys.service")).read()
s_new = render_new("llm-keys", load_profile("default"), part="service")
results["lme-llm-keys.service"] = show(
    "8b. lme-llm-keys.service  [NEW]  vs  [static]",
    s_old, s_new, "static", "NEW render")

# ---- derivation + gating assertions --------------------------------------
print("\n" + "=" * 78)
print("DERIVATION + GATING CHECKS (filter_plugins/lme_manifests.py)")
print("=" * 78)
F = FilterModule().filters()
checks = [
    ("userns ES", F["render_userns"]({"mode": "auto", "slot": "elasticsearch"}, gl),
     "auto:uidmapping=0:165536:3048,gidmapping=0:165536:3048"),
    ("userns kibana", F["render_userns"]({"mode": "auto", "slot": "kibana"}, gl),
     "auto:uidmapping=0:168584:3048,gidmapping=0:168584:3048"),
    ("userns share setup-accts", F["render_userns"]({"mode": "share_with", "service": "elasticsearch"}, gl),
     "container:lme-elasticsearch"),
    ("userns auto_unpinned", F["render_userns"]({"mode": "auto_unpinned"}, gl), "auto"),
    ("cert_owner ES uid1000", F["cert_owner"]({"slot": "elasticsearch", "in_container_uid": 1000}, gl), 166536),
    ("cert_owner kibanadata", F["cert_owner"]({"slot": "kibana", "in_container_uid": 1000}, gl), 169584),
    ("cert_owner filebeat(noslot)", F["cert_owner"]({"slot": "filebeat", "in_container_uid": 0}, gl), 165536),
    ("cert_owner backups", F["cert_owner"]({"in_container_uid": 0}, gl), 165536),
    ("mem 4g*1.5", F["mem_derive"]("4g", 1.5), "6G"),
    ("mem 4g*2", F["mem_derive"]("4g", 2), "8G"),
    ("mem 8g*1.5", F["mem_derive"]("8g", 1.5), "12G"),
    ("mem 8g*2", F["mem_derive"]("8g", 2), "16G"),
    ("jvm_opts ES", F["jvm_opts"]({"heap": "4g", "jvm_base": "-Des.entitlements.enabled=false"}),
     '"-Des.entitlements.enabled=false -Xms4g -Xmx4g"'),
    ("svc_unit network", F["svc_unit"]("network", "network"), "lme-network.service"),
    ("svc_unit volume", F["svc_unit"]("filebeatdata", "volume"), "lme-filebeatdata-volume.service"),
    ("svc_unit target", F["svc_unit"]("lme", "target"), "lme.service"),
    ("svc_unit container", F["svc_unit"]("setup-certs", "container"), "lme-setup-certs.service"),
    ("is_enabled always", F["is_enabled"](["always"], {}), True),
    ("is_enabled install_llm off", F["is_enabled"](["install_llm"], {"install_llm": False}), False),
    ("is_enabled install_llm on", F["is_enabled"](["install_llm"], {"install_llm": True}), True),
    ("render_port bind", F["render_port"]({"host": 5044, "container": 5044, "bind": "127.0.0.1"}), "127.0.0.1:5044:5044"),
    ("render_port udp", F["render_port"]({"host": 514, "container": 514, "protocol": "udp"}), "514:514/udp"),
]


def compose_flags(profile):
    """Mirror load_manifests.yml: defaults (llm true, others false), profile vars override."""
    v = profile.get("vars", {}) or {}
    return {"install_llm": bool(v.get("install_llm", True)),
            "install_elastic_services": bool(v.get("install_elastic_services", False)),
            "offline_mode": bool(v.get("offline_mode", False))}


dflags = compose_flags(load_profile("default"))
checks += [
    # End-to-end enable gating (the render_units.yml gate) with COMPOSED flags:
    ("gate: litellm on (default)", F["is_enabled"](services["litellm"]["enabled_when"], dflags), True),
    ("gate: llm-keys on (default)", F["is_enabled"](services["llm-keys"]["enabled_when"], dflags), True),
    ("gate: elasticsearch on (always)", F["is_enabled"](services["elasticsearch"]["enabled_when"], dflags), True),
    ("gate: filebeat OFF (opt-in default)", F["is_enabled"](services["filebeat"]["enabled_when"], dflags), False),
    ("gate: litellm OFF when llm off", F["is_enabled"](services["litellm"]["enabled_when"], dict(dflags, install_llm=False)), False),
    ("gate: filebeat ON w/ elastic-svcs", F["is_enabled"](services["filebeat"]["enabled_when"], dict(dflags, install_elastic_services=True)), True),
    # Cluster discovery null-skip + B1 heap in the actual cluster render:
    ("cluster drops discovery.type", "discovery.type" in es_new_cluster, False),
    ("cluster has -Xms8g", "-Xms8g -Xmx8g" in es_new_cluster, True),
    ("default keeps discovery.type=single-node", "discovery.type=single-node" in es_new_default, True),
]
ok = True
for name, got, want in checks:
    good = got == want
    ok = ok and good
    print("  [%s] %-28s got=%r want=%r" % ("OK" if good else "XX", name, got, want))

print("\n" + "=" * 78)
print("SUMMARY")
print("=" * 78)
clean = True
for name, sd in results.items():
    tag = "clean" if not sd else ("%d section(s) w/ delta" % len(sd))
    print("  %-32s : %s" % (name, tag))
print("  derivation/gating checks         : %s" % ("ALL PASS" if ok else "FAILURES"))
sys.exit(0 if ok else 1)
