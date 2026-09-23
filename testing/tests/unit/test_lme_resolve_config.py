# -*- coding: utf-8 -*-
"""Unit tests for the C1 resolved-config engine (lme_resolve_config /
lme_validate_config in ansible/roles/podman/filter_plugins/lme_manifests.py).

These prove the DECLARED-PRECEDENCE contract from
codex-manager-caller-contract-decisions-20260923-0200:

  extra_var > inventory > profile > observation(schema-permitted) > default

plus the preservation rules (explicit false-like honoured; detection never
overrides an explicit selection; optional-unset absent; required-missing fails;
no snapshot -- a pure function of its inputs). The engine is value-pure: every
default/type/tier eligibility is read from manifests/global.yml
lme_config_registry, never hardcoded here.

Run from the repo root:  pytest testing/tests/unit/
"""

import importlib.util
import os

import pytest
import yaml

_HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(_HERE, os.pardir, os.pardir, os.pardir))
RESOLVER_PATH = os.path.join(
    REPO_ROOT, "ansible", "roles", "podman", "filter_plugins", "lme_manifests.py"
)
GLOBAL_YML = os.path.join(REPO_ROOT, "manifests", "global.yml")
PROFILES_DIR = os.path.join(REPO_ROOT, "manifests", "profiles")

assert os.path.exists(RESOLVER_PATH), "resolver not found at %s" % RESOLVER_PATH


def _load_resolver():
    spec = importlib.util.spec_from_file_location("lme_manifests", RESOLVER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_MOD = _load_resolver()
FILTERS = _MOD.FilterModule().filters()
resolve = FILTERS["lme_resolve_config"]
validate = FILTERS["lme_validate_config"]


def _registry():
    with open(GLOBAL_YML, "r") as fh:
        return yaml.safe_load(fh)["lme_config_registry"]


REGISTRY = _registry()


def _profile_vars(name):
    with open(os.path.join(PROFILES_DIR, "%s.yml" % name), "r") as fh:
        doc = yaml.safe_load(fh) or {}
    return (doc.get("profile_overlay") or {}).get("vars") or {}


def R(profile="default", selections=None, observations=None, origins=None):
    return resolve(
        REGISTRY,
        _profile_vars(profile),
        selections or {},
        observations or {},
        origins or {},
    )


# --- the registry itself is well-formed (the schema half of the contract) ----

def test_registry_declares_expected_shape():
    fields = REGISTRY["fields"]
    assert REGISTRY["precedence"] == ["extra_var", "inventory", "profile", "observation", "default"]
    enable = sorted(k for k, v in fields.items() if v.get("enable_flag"))
    assert enable == sorted(
        ["install_llm", "install_elastic_services", "offline_mode", "install_otel", "install_legacy_beats"]
    )
    # only these two carry the observation-backed upgrade fallback
    fb = sorted(k for k, v in fields.items() if v.get("upgrade_fallback"))
    assert fb == ["install_elastic_services", "offline_mode"]
    # the optional fields declare NO default (absent when unset). tailscale_require_vip_live
    # is the original optional; lme_deployment_identity + lme_database_membership are the
    # C1 material/identity inputs (codex-0430 dec 4+5) -- optional here, hard-required only
    # under a persistent-resource/DB profile (armed with the still-gated DB selectors).
    optional = sorted(k for k, v in fields.items() if not v.get("required"))
    assert optional == sorted([
        "tailscale_require_vip_live",
        "lme_deployment_identity",
        "lme_database_membership",
    ])
    for k in optional:
        assert "default" not in fields[k], k


def test_every_profile_var_key_is_declared():
    """Managed-key universe = registry keys must cover every profile var key."""
    declared = set(REGISTRY["fields"])
    for name in ["default", "offline", "tailscale", "cluster", "consumer", "multinode"]:
        assert set(_profile_vars(name)) <= declared, name


# --- tier precedence ---------------------------------------------------------

def test_default_profile_uses_declared_defaults():
    r = R("default")
    assert r["resolved"]["offline_mode"] is False
    assert r["origins"]["offline_mode"] == "default"
    assert r["resolved"]["install_llm"] is True


def test_profile_overrides_default():
    r = R("offline")
    assert r["resolved"]["offline_mode"] is True
    assert r["origins"]["offline_mode"] == "profile"


def test_extra_var_beats_profile():
    r = R("offline", selections={"offline_mode": False}, origins={"offline_mode": "extra_var"})
    assert r["resolved"]["offline_mode"] is False
    assert r["origins"]["offline_mode"] == "extra_var"


def test_inventory_false_beats_detected_true():
    r = R(
        "default",
        selections={"install_elastic_services": False},
        observations={"install_elastic_services": True},
        origins={"install_elastic_services": "inventory"},
    )
    assert r["resolved"]["install_elastic_services"] is False
    assert r["origins"]["install_elastic_services"] == "inventory"


def test_observation_drives_when_permitted_and_unset():
    r = R("default", observations={"offline_mode": True})
    assert r["resolved"]["offline_mode"] is True
    assert r["origins"]["offline_mode"] == "observation"


def test_observation_ignored_when_field_forbids_fallback():
    # install_llm.upgrade_fallback is false -> an observation must NOT apply;
    # its compatibility `true` is a DECLARED DEFAULT, not observed state.
    r = R("default", observations={"install_llm": False})
    assert r["resolved"]["install_llm"] is True
    assert r["origins"]["install_llm"] == "default"


# --- preservation rules ------------------------------------------------------

def test_explicit_profile_false_not_overwritten_by_detection():
    r = R("offline", observations={"install_elastic_services": True})
    assert r["resolved"]["install_elastic_services"] is False
    assert r["origins"]["install_elastic_services"] == "profile"


def test_optional_absent_when_unset():
    r = R("default")
    assert "tailscale_require_vip_live" not in r["resolved"]


def test_optional_present_when_profile_supplies_it():
    r = R("tailscale")
    assert r["resolved"]["tailscale_require_vip_live"] is True


def test_enable_flags_are_exactly_the_five():
    r = R("default")
    assert sorted(r["enable_flags"]) == sorted(
        ["install_llm", "install_elastic_services", "offline_mode", "install_otel", "install_legacy_beats"]
    )


# --- no snapshot: pure function of inputs ------------------------------------

def test_changed_input_reflected_on_reresolve():
    a = R("default")
    b = R("default", selections={"install_llm": False}, origins={"install_llm": "extra_var"})
    assert a["resolved"]["install_llm"] is True
    assert b["resolved"]["install_llm"] is False


# --- fail-closed --------------------------------------------------------------

def test_unknown_profile_key_raises():
    with pytest.raises(ValueError) as ei:
        resolve(REGISTRY, {"bogus_key": True})
    assert "undeclared config key" in str(ei.value)


def test_required_missing_raises_when_no_default():
    # synthesise a registry whose required field has no default and no input
    # (channels reused from the real registry -- the engine's shape gate now
    # requires a declared channel per precedence tier, A2)
    reg = {"precedence": REGISTRY["precedence"], "channels": REGISTRY["channels"],
           "fields": {"needed": {"type": "bool", "required": True, "nullable": False}}}
    with pytest.raises(ValueError) as ei:
        resolve(reg, {})
    assert "no value from any tier" in str(ei.value)


def test_bool_field_rejects_non_bool():
    reg = {"precedence": REGISTRY["precedence"], "channels": REGISTRY["channels"],
           "fields": {"flag": {"type": "bool", "required": True, "nullable": False, "default": True}}}
    with pytest.raises(ValueError):
        resolve(reg, {}, {"flag": "yes-please"})


def test_string_bools_coerced():
    reg = {"precedence": REGISTRY["precedence"], "channels": REGISTRY["channels"],
           "fields": {"flag": {"type": "bool", "required": True, "nullable": False, "default": True}}}
    r = resolve(reg, {}, {"flag": "false"})
    assert r["resolved"]["flag"] is False


def test_str_field_preserved():
    r = R("cluster")
    assert r["resolved"]["es_discovery"] == "cluster"
    assert r["origins"]["es_discovery"] == "profile"


# --- validate ----------------------------------------------------------------

def test_validate_passes_on_good_resolved():
    good = R("default")["resolved"]
    assert validate(REGISTRY, good) is good


def test_validate_raises_on_missing_required():
    bad = R("default")["resolved"]
    del bad["install_llm"]
    with pytest.raises(ValueError) as ei:
        validate(REGISTRY, bad)
    assert "missing from resolved" in str(ei.value)


# --- durable regressions for the audit findings (Codex re-audit; pure-engine tier) ----
# The integration-tier equivalents live in G's loader_integration suite; these are the
# unit-tier pure-function guards so the findings cannot silently regress in the engine.

def test_reversed_validate_args_fail_closed():
    """A1 / C1-VALIDATE-CALL: the Jinja pipe `resolved | lme_validate_config(registry)`
    reverses to lme_validate_config(resolved, registry) -- registry bound to the resolved
    dict. A resolved dict has no `fields`, so the registry-shape gate RAISES rather than
    passing silently. Fail-closed by construction, not merely by argument order."""
    resolved = R("default")["resolved"]
    with pytest.raises(ValueError) as ei:
        validate(resolved, REGISTRY)  # arguments reversed on purpose
    assert "no fields" in str(ei.value)


def test_reordered_precedence_changes_selection():
    """A2: the engine READS registry.precedence -- it is not a hardcoded ladder. With a
    field carrying both a profile value and an observation, whichever tier is DECLARED
    first wins. `default` stays last (shape-gate requirement)."""
    fields = {"flag": {"type": "bool", "required": True, "nullable": False,
                       "default": False, "upgrade_fallback": True}}
    ch = {"profile": REGISTRY["channels"]["profile"],
          "observation": REGISTRY["channels"]["observation"],
          "default": REGISTRY["channels"]["default"]}
    reg_pf = {"precedence": ["profile", "observation", "default"], "channels": ch, "fields": fields}
    r = resolve(reg_pf, {"flag": False}, {}, {"flag": True})
    assert r["resolved"]["flag"] is False and r["origins"]["flag"] == "profile"
    reg_ob = {"precedence": ["observation", "profile", "default"], "channels": ch, "fields": fields}
    r2 = resolve(reg_ob, {"flag": False}, {}, {"flag": True})
    assert r2["resolved"]["flag"] is True and r2["origins"]["flag"] == "observation"


def test_extended_types_preserve_declared_zero_values():
    """A4 / RC-OPEN-6: int / list / map / nullable coverage. A declared 0 / [] / {} /
    None is a real value, preserved by resolve and accepted canonical by validate; an
    explicit non-zero selection is preserved and type-checked."""
    reg = {"precedence": REGISTRY["precedence"], "channels": REGISTRY["channels"],
           "fields": {
               "count": {"type": "int", "required": True, "nullable": False, "default": 0},
               "items": {"type": "list", "required": True, "nullable": False, "default": []},
               "cfg":   {"type": "map", "required": True, "nullable": False, "default": {}},
               "maybe": {"type": "str", "required": True, "nullable": True, "default": None}}}
    r = resolve(reg, {})["resolved"]
    assert r["count"] == 0 and r["items"] == [] and r["cfg"] == {} and r["maybe"] is None
    assert validate(reg, r) is r
    r2 = resolve(reg, {}, {"count": 5, "items": ["a"], "cfg": {"k": "v"}, "maybe": "x"})["resolved"]
    assert r2 == {"count": 5, "items": ["a"], "cfg": {"k": "v"}, "maybe": "x"}


def test_int_field_rejects_bool():
    """A4: a bool is NOT an int -- an int field handed True must raise, not coerce to 1."""
    reg = {"precedence": REGISTRY["precedence"], "channels": REGISTRY["channels"],
           "fields": {"count": {"type": "int", "required": True, "nullable": False, "default": 0}}}
    with pytest.raises(ValueError):
        resolve(reg, {}, {"count": True})


def test_caller_origin_lie_discarded_for_honest_operator():
    """A5: a caller `origins` map claiming `default` for a value it SELECTED is a lie;
    the engine discards it and records the honest combined `operator`, never `default`.
    A truthful finer origin (extra_var / inventory) IS preserved."""
    r = R("default", selections={"install_llm": False}, origins={"install_llm": "default"})
    assert r["resolved"]["install_llm"] is False
    assert r["origins"]["install_llm"] == "operator"
    r2 = R("default", selections={"install_llm": False}, origins={"install_llm": "inventory"})
    assert r2["origins"]["install_llm"] == "inventory"


def test_validate_rejects_non_mapping_resolved_even_all_optional():
    """C1-OPTIONAL-NONMAPPING: a non-mapping resolved input ([]/None/scalar) must be
    rejected INDEPENDENTLY of whether any field is required -- it was silently coerced to
    {} and 'validated' as empty when the registry had only optional fields."""
    reg = {"precedence": REGISTRY["precedence"], "channels": REGISTRY["channels"],
           "fields": {"maybe": {"type": "bool", "required": False, "nullable": False, "default": True}}}
    for bad in ([], None, "x", 3):
        with pytest.raises(ValueError) as ei:
            validate(reg, bad)
        assert "must be a mapping" in str(ei.value)


def test_unsupported_type_rejected_even_when_nullable_null():
    """C1-UNKNOWN-NULLABLE-TYPE: the schema (supported-type declaration) is validated by
    the shape gate BEFORE any value, so a nullable field declaring an unsupported type can
    no longer slip a null past resolve OR validate via the None short-circuit."""
    reg = {"precedence": REGISTRY["precedence"], "channels": REGISTRY["channels"],
           "fields": {"weird": {"type": "bogus", "required": False, "nullable": True}}}
    with pytest.raises(ValueError) as ei:
        resolve(reg, {}, {"weird": None})
    assert "unsupported/absent type" in str(ei.value)
    with pytest.raises(ValueError):
        validate(reg, {"weird": None})
