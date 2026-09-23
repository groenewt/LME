#!/usr/bin/env python3
"""Validate C's credential-material proposal against the REAL engine filters
(lme_manifests.py), not safe_load alone. Proves:
  1. C's distributable catalog defs PASS lme_validate_material_catalog.
  2. A distributed obligation referencing a C distributable def PASSES.
  3. A DISTRIBUTED obligation whose material_ref is a private_key FAILS at the
     distributability line -- documents the gap the local-production form fills.
  4. Under the PROPOSED schema delta (record.production + production_forms), a
     local_host obligation's record/placement/profile/mode checks all PASS; the
     ONLY remaining failure is that single distributability conditional -- i.e. the
     shape is valid and one value-pure conditional is what C1 must add.
Run: python3 config/credentials/verify_credential_proposal.py"""
import importlib.util, os, sys, copy, yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MOD = os.path.join(REPO, "ansible/roles/podman/filter_plugins/lme_manifests.py")
spec = importlib.util.spec_from_file_location("lme_manifests", MOD)
lm = importlib.util.module_from_spec(spec); spec.loader.exec_module(lm)

g = yaml.safe_load(open(os.path.join(REPO, "manifests/global.yml")))
lg = g["lme_global"]
catalog_schema = lg["material_catalog_schema"]
base_catalog = dict(lg.get("material_catalog") or {})
req_schema = g["lme_config_registry"]["material_requirements_schema"]

prop = yaml.safe_load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "credential-material-and-obligations.proposal.yaml")))

def strip_owner(defn):
    return {k: v for k, v in defn.items() if k in ("kind", "payload_validity", "description")}

PASS = FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: print("PASS  " + name); PASS += 1
    else: print(f"FAIL  {name}  {detail}"); FAIL += 1

# ---- 1. C's distributable + private-key defs fold + validate ----
merged = dict(base_catalog)
for name, defn in prop["c_material_catalog_definitions"].items():
    merged[name] = strip_owner(defn)
try:
    lm.lme_validate_material_catalog(merged, catalog_schema, context="c-proposal")
    check("1 C catalog defs PASS lme_validate_material_catalog", True)
except Exception as e:
    check("1 C catalog defs PASS", False, str(e))

# ---- 2. a DISTRIBUTED obligation referencing a C distributable def PASSES ----
ob_ok = {"pg_service_conf": {
    "material_ref": "lme_pg_service_conf", "placement_class": "config",
    "consumer": "postgresql", "profile_condition": "dual-owned-ha",
    "destination": "/run/config/pg_service.conf", "owner_role": "hzu", "mode": "0640"}}
try:
    lm.lme_validate_material_requirements(merged, ob_ok, req_schema, catalog_schema, context="ok")
    check("2 distributed obligation -> distributable def PASSES", True)
except Exception as e:
    check("2 distributed obligation PASSES", False, str(e))

# ---- 3. a DISTRIBUTED obligation referencing a private_key FAILS (gap doc) ----
ob_bad = {"server_key": {
    "material_ref": "lme_pg_server_key", "placement_class": "secrets",
    "consumer": "postgresql", "profile_condition": "dual-owned-ha",
    "destination": "/run/secrets/server.key", "owner_role": "hzu", "mode": "0600"}}
try:
    lm.lme_validate_material_requirements(merged, ob_bad, req_schema, catalog_schema, context="bad")
    check("3 distributed private_key REJECTED", False, "did NOT raise")
except ValueError as e:
    check("3 distributed private_key REJECTED at distributability", "NOT distributable" in str(e), str(e))

# ---- 4. local_host obligation under the PROPOSED schema delta ----
# apply the proposed record.production field to a COPY of the real schema
prop_schema = copy.deepcopy(req_schema)
prop_schema["record"]["production"] = prop["local_production_obligation_form"]["proposed_record_field"]["production"]
lh = copy.deepcopy(prop["local_production_obligation_form"]["unblocked_obligations"]["elasticsearch_tls_key_local"])
# fold E's owner:C private_key def so material_ref resolves
merged["elasticsearch_tls_key"] = {"kind": "private_key", "payload_validity": "non_empty_pem_private_key"}
try:
    lm.lme_validate_material_requirements(merged, {"es_tls": lh}, prop_schema, catalog_schema, context="local")
    check("4 local_host obligation PASSES", False, "unexpectedly passed (distributability not enforced?)")
except ValueError as e:
    msg = str(e)
    # the ONLY failure must be the distributability conditional -- every record/placement/
    # profile/mode/vocab check must already have passed (proves shape validity).
    only_distributability = ("NOT distributable" in msg) and ("undeclared field" not in msg) \
        and ("not in the declared vocab" not in msg) and ("missing required field" not in msg) \
        and ("requires a non-empty" not in msg) and ("not a complete octal" not in msg)
    check("4 local_host shape VALID; only distributability conditional remains", only_distributability, msg)

print(f"================= CREDENTIAL PROPOSAL: {PASS} passed, {FAIL} failed =================")
sys.exit(FAIL)
