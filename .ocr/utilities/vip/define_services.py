#!/usr/bin/env python3
"""Define the LME svc:lme-* Tailscale Services (allocate TailVIPs) via the Tailscale API.

Root cause it fixes: a Tailscale Service VIP needs THREE things -- a tagged node (have),
an autoApprovers entry (have, via patch_acl.py), and a SERVICE DEFINITION that allocates
the VIP (MISSING). The definition is a tailnet-side object (console/API), NOT expressible
in the ACL. This creates it via the REST API so `tailscale serve --service` then advertises
a real VIP -> CapMap["services/<name>"] populates -> the armed liveness assert passes.

Names + ports are sourced ONLY from manifests/services/lme-*.yml (tailnet_service +
publish_ports) -- no hardcoded svc-id or port list. Additive + verified: GET before/after,
assert every co-tenant (non-lme) service is byte-identical afterwards.

  DRY-RUN (default): python3 define_services.py           # prints plan + live state, mutates nothing
  APPLY:             python3 define_services.py --apply    # PUTs each service, then re-GETs to verify

Auth: source ~/.temp.sh first (exports TS_API_TOKEN), same as patch_acl.py / restore_acl.sh.
"""
import os, sys, json, glob, urllib.request, urllib.error
from urllib.parse import quote
try:
    import yaml
except ImportError:
    sys.exit("PyYAML required (pip install pyyaml)")

TAILNET = "-"
BASE = f"https://api.tailscale.com/api/v2/tailnet/{TAILNET}/vip-services"
TOKEN = os.environ.get("TS_API_TOKEN")
if not TOKEN:
    sys.exit("TS_API_TOKEN not set -- run:  set -a; . ~/.temp.sh; set +a")
APPLY = "--apply" in sys.argv
REPO = os.environ.get("LME_REPO", "/home/tristan/gitters/LME")

def api(method, url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {TOKEN}")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        return e.code, {"_error": e.read().decode()[:400]}
    except Exception as e:
        return -1, {"_error": str(e)}

# --- source names + ports from manifests (NO hardcoding) ---
plan = {}
for mf in sorted(glob.glob(f"{REPO}/manifests/services/lme-*.yml")):
    doc = yaml.safe_load(open(mf))
    svc = doc.get("tailnet_service")
    if not svc:
        continue
    name = svc if str(svc).startswith("svc:") else f"svc:{svc}"
    ports = sorted({f"tcp:{p['host']}" for p in (doc.get("publish_ports") or []) if p.get("host")},
                   key=lambda s: int(s.split(":")[1]))
    plan[name] = {"ports": ports, "displayName": doc.get("description") or name,
                  "manifest": os.path.basename(mf)}
if not plan:
    sys.exit("No manifests/services/lme-*.yml carry `tailnet_service:` -- nothing to define.")

# --- pre-GET (capture live + co-tenant snapshot) ---
st, cur = api("GET", BASE)
if st != 200:
    sys.exit(f"GET {BASE} -> HTTP {st}: {cur.get('_error')}")
before = {s["name"]: s for s in cur.get("vipServices", [])}
cotenant = {n: s for n, s in before.items() if not n.startswith("svc:lme-")}
print(f"== BEFORE == {len(before)} vip-service(s) live")
for n, s in before.items():
    print(f"   {n}: addrs={s.get('addrs')} ports={s.get('ports')}")
print(f"\n== PLAN ({'APPLY' if APPLY else 'DRY-RUN'}) == {len(plan)} LME service(s) from manifests, co-tenant to preserve: {list(cotenant)}")
for n, p in plan.items():
    print(f"   [{'EXISTS->update' if n in before else 'CREATE'}] {n}  ports={p['ports']}  <- {p['manifest']}")

if not APPLY:
    print("\nDRY-RUN only -- nothing mutated. Re-run with --apply to create the VIPs.")
    sys.exit(0)

# --- apply: PUT each (auto-VIP: addrs omitted) ---
print()
for n, p in plan.items():
    body = {"name": n, "ports": p["ports"], "displayName": p["displayName"]}
    st, resp = api("PUT", f"{BASE}/{quote(n, safe='')}", body)
    print(f"   PUT {n} -> HTTP {st}  " + (f"addrs={resp.get('addrs')}" if st < 400 else f"ERR {resp.get('_error')}"))

# --- post-GET verify: 4 allocated + every co-tenant byte-identical ---
st, cur2 = api("GET", BASE)
after = {s["name"]: s for s in cur2.get("vipServices", [])}
ok = True
print(f"\n== AFTER == {len(after)} vip-service(s) live")
for n in plan:
    s = after.get(n)
    if s and s.get("addrs"):
        print(f"   LIVE  {n}: addrs={s['addrs']} ports={s.get('ports')}")
    else:
        print(f"   DEAD  {n}: NOT allocated"); ok = False
for n, s in cotenant.items():
    same = after.get(n) == s
    print(f"   co-tenant {n}: {'UNTOUCHED' if same else 'CHANGED -- ' + str(after.get(n))}")
    ok = ok and same
print("\nRESULT:", "ALL LME VIPs ALLOCATED + co-tenant intact" if ok else "PROBLEM -- see above")
sys.exit(0 if ok else 1)
