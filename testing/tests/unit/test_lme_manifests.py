# -*- coding: utf-8 -*-
"""Unit tests for the LME manifest render resolver (OCR round-4 should-fix B5).

`ansible/roles/podman/filter_plugins/lme_manifests.py` is the single, load-bearing
source of truth for every derived value in the rendered quadlet units: userns
id-mapping bases, per-consumer cert-owner uids, systemd unit-name resolution,
PublishPort=/Volume= assembly, the enable/skip decision from profile flags, and the
Elasticsearch JVM heap -> cgroup memory-cap derivation. It shipped with ZERO tests.

These tests load the FilterModule directly (no ansible runtime) and assert exact
derived values, grounded in the REAL manifest data (manifests/global.yml + the
service manifests). They are robust to additive changes to the resolver: filters
are pulled out of `FilterModule().filters()` by their documented public key, and the
corpus sweep iterates whatever manifests are on disk (it never asserts a count).

Run from the repo root:  pytest testing/tests/unit/
"""

import glob
import importlib.util
import os

import pytest
import yaml

# --- locate the repo + the resolver under test ------------------------------
# testing/tests/unit/test_lme_manifests.py -> parents[3] == repo root
_HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(_HERE, os.pardir, os.pardir, os.pardir))
RESOLVER_PATH = os.path.join(
    REPO_ROOT, "ansible", "roles", "podman", "filter_plugins", "lme_manifests.py"
)
GLOBAL_YML = os.path.join(REPO_ROOT, "manifests", "global.yml")
SERVICES_DIR = os.path.join(REPO_ROOT, "manifests", "services")
PROFILES_DIR = os.path.join(REPO_ROOT, "manifests", "profiles")

# Fail legibly if the directory depth is wrong (a moved test file), rather than
# with an opaque ImportError deep in the loader.
assert os.path.exists(RESOLVER_PATH), "resolver not found at %s" % RESOLVER_PATH
assert os.path.exists(GLOBAL_YML), "manifests/global.yml not found at %s" % GLOBAL_YML


def _load_resolver():
    spec = importlib.util.spec_from_file_location("lme_manifests", RESOLVER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_MOD = _load_resolver()
# The public contract is the filters() mapping -- pull each filter out by its
# documented key so renaming an internal helper (or adding new filters alongside
# these) never breaks the suite.
FILTERS = _MOD.FilterModule().filters()

userns_base = FILTERS["userns_base"]
render_userns = FILTERS["render_userns"]
cert_owner = FILTERS["cert_owner"]
svc_unit = FILTERS["svc_unit"]
unit_refs = FILTERS["unit_refs"]
wanted_by = FILTERS["wanted_by"]
render_port = FILTERS["render_port"]
render_volume = FILTERS["render_volume"]
podman_args = FILTERS["podman_args"]
is_enabled = FILTERS["is_enabled"]
jvm_opts = FILTERS["jvm_opts"]
mem_derive = FILTERS["mem_derive"]
service_memory_max = FILTERS["service_memory_max"]
memory_budget = FILTERS["memory_budget"]


def _load_global():
    with open(GLOBAL_YML, "r") as fh:
        return yaml.safe_load(fh)["lme_global"]


LME_GLOBAL = _load_global()


def _all_service_manifests():
    out = []
    for path in sorted(glob.glob(os.path.join(SERVICES_DIR, "*.yml"))):
        with open(path, "r") as fh:
            out.append((os.path.basename(path), yaml.safe_load(fh)))
    return out


# ONE parse, ONE consistent snapshot of the manifest tree, taken at import time.
# The whole suite reads from this constant instead of re-opening files per test:
# with a concurrent editor writing these manifests, a live re-read could catch a
# half-written YAML and surface a parse error that looks like a resolver bug.
_MANIFESTS = _all_service_manifests()
_MANIFEST_BY_NAME = {name: doc for name, doc in _MANIFESTS}


def _load_service(basename):
    return _MANIFEST_BY_NAME[basename]


def _build_kinds():
    """id -> kind map, exactly as load_manifests.yml builds lme_service_kinds."""
    kinds = {}
    for _name, doc in _MANIFESTS:
        if doc and "id" in doc and "kind" in doc:
            kinds[doc["id"]] = doc["kind"]
    return kinds


KINDS = _build_kinds()


# ===========================================================================
# Seed-constant guard (first, so a change to the derivation seeds fails LOUDLY
# here rather than as a mysterious arithmetic mismatch further down).
# ===========================================================================
def test_seed_constants_are_the_documented_contract():
    assert int(LME_GLOBAL["subuid_base"]) == 165536
    assert int(LME_GLOBAL["slot_size"]) == 3048
    assert LME_GLOBAL["slots"] == {
        "elasticsearch": 0,
        "kibana": 1,
        "fleet-server": 2,
        "wazuh-manager": 3,
        "elastalert": 4,
    }
    assert LME_GLOBAL["certs"]["host_tree"] == "/opt/lme/certs"
    assert LME_GLOBAL["certs"]["default_in_container_uid"] == 0


# ===========================================================================
# userns_base : subuid_base + slot*slot_size ; unknown/None slot -> subuid_base
# ===========================================================================
@pytest.mark.parametrize(
    "slot,expected",
    [
        ("elasticsearch", 165536),  # slot 0
        ("kibana", 168584),         # 165536 + 1*3048
        ("fleet-server", 171632),   # 165536 + 2*3048
        ("wazuh-manager", 174680),  # 165536 + 3*3048
        ("elastalert", 177728),     # 165536 + 4*3048
        (None, 165536),             # no pinned mapping -> raw subuid_base
        ("not-a-slot", 165536),     # absent from slots -> raw subuid_base
    ],
)
def test_userns_base_slot_math(slot, expected):
    assert userns_base(slot, LME_GLOBAL) == expected


def test_userns_base_is_the_lme_backups_owner_for_unslotted():
    # A consumer with no numbered slot resolves to the observed lme_backups
    # host-side owner (165536 = 165536 + 0 + 0).
    assert userns_base(None, LME_GLOBAL) == 165536


# ===========================================================================
# render_userns : the UserNS= directive value
# ===========================================================================
def test_render_userns_auto_pinned_mapping():
    # base(kibana slot 1) = 168584, size = slot_size = 3048
    assert render_userns({"mode": "auto", "slot": "kibana"}, LME_GLOBAL) == (
        "auto:uidmapping=0:168584:3048,gidmapping=0:168584:3048"
    )


def test_render_userns_share_with_uses_container_ref():
    # setup-accts shares elasticsearch's namespace.
    accts = _load_service("lme-setup-accts.yml")
    assert accts["userns"] == {"mode": "share_with", "service": "elasticsearch"}
    assert render_userns(accts["userns"], LME_GLOBAL) == "container:lme-elasticsearch"


def test_render_userns_auto_unpinned():
    assert render_userns({"mode": "auto_unpinned"}, LME_GLOBAL) == "auto"


# ===========================================================================
# cert_owner : userns_base(slot)+in_container_uid, OR base-0+in_uid for host_userns
# ===========================================================================
def test_cert_owner_elasticsearch_real_manifest():
    es = _load_service("lme-elasticsearch.yml")
    # slot elasticsearch (base 165536) + in_container_uid 1000
    assert cert_owner(es["certs"], LME_GLOBAL) == 166536


def test_cert_owner_kibana_real_manifest():
    kib = _load_service("lme-kibana.yml")
    # slot kibana (base 168584) + in_container_uid 1000
    assert cert_owner(kib["certs"], LME_GLOBAL) == 169584


def test_cert_owner_host_userns_root_is_base_zero():
    # fleet-distribution: host_userns:true, in_container_uid:0 -> owner 0 (no subuid).
    fd = _load_service("lme-fleet-distribution.yml")
    assert fd["certs"]["host_userns"] is True
    assert cert_owner(fd["certs"], LME_GLOBAL) == 0

    # litellm: same host_userns root case, from a different manifest.
    ll = _load_service("lme-litellm.yml")
    assert cert_owner(ll["certs"], LME_GLOBAL) == 0


def test_cert_owner_host_userns_nonroot_is_in_container_uid():
    # heartbeat: host_userns:true, in_container_uid:1000 -> owner 1000 (image uid,
    # NO subuid offset).
    hb = _load_service("lme-heartbeat.yml")
    assert cert_owner(hb["certs"], LME_GLOBAL) == 1000
    # synthetic equivalent -- pins the base-0 semantics independent of the manifest.
    assert cert_owner({"host_userns": True, "in_container_uid": 1000}, LME_GLOBAL) == 1000


def test_cert_owner_defaults_in_container_uid_from_global():
    # certs.default_in_container_uid is 0, so a slotted consumer that omits
    # in_container_uid owns its bundle at the slot base exactly.
    assert cert_owner({"slot": "kibana"}, LME_GLOBAL) == 168584
    # unslotted + no in_uid -> raw subuid_base (the lme_backups owner).
    assert cert_owner({}, LME_GLOBAL) == 165536


# ===========================================================================
# svc_unit / unit_refs / wanted_by : logical name -> systemd unit name
# ===========================================================================
@pytest.mark.parametrize(
    "logical,kind,expected",
    [
        ("lme", "target", "lme.service"),               # umbrella target
        ("elasticsearch", "container", "lme-elasticsearch.service"),
        ("network", "network", "lme-network.service"),
        ("kibanadata", "volume", "lme-kibanadata-volume.service"),
    ],
)
def test_svc_unit_name_resolution(logical, kind, expected):
    assert svc_unit(logical, kind) == expected


def test_svc_unit_specials_resolve_without_a_kind():
    # 'lme' is always the target; 'network' is always lme-network.service, even
    # when the (default) kind is container.
    assert svc_unit("lme") == "lme.service"
    assert svc_unit("network") == "lme-network.service"
    # default kind is container.
    assert svc_unit("wazuh-manager") == "lme-wazuh-manager.service"


def test_unit_refs_real_dependency_list_with_real_kinds():
    # kibana Requires=[setup-accts, elasticsearch, kibanadata]. This single
    # assertion exercises unit_refs + the id->kind map + the volume suffix rule.
    kib = _load_service("lme-kibana.yml")
    assert kib["dependencies"]["requires"] == ["setup-accts", "elasticsearch", "kibanadata"]
    assert unit_refs(kib["dependencies"]["requires"], KINDS) == (
        "lme-setup-accts.service lme-elasticsearch.service lme-kibanadata-volume.service"
    )


def test_unit_refs_defaults_missing_names_to_container():
    assert unit_refs(["foo", "bar"]) == "lme-foo.service lme-bar.service"
    assert unit_refs([]) == ""
    assert unit_refs(None) == ""


def test_wanted_by_passes_raw_targets_and_resolves_logical_names():
    # elasticsearch install.wanted_by = [default.target, lme]
    es = _load_service("lme-elasticsearch.yml")
    assert es["install"]["wanted_by"] == ["default.target", "lme"]
    assert wanted_by(es["install"]["wanted_by"], KINDS) == "default.target lme.service"
    # a bare .service/.path passes through verbatim too.
    assert wanted_by(["multi-user.target", "lme-network.service"]) == (
        "multi-user.target lme-network.service"
    )


# ===========================================================================
# render_port : {host, container, bind?, protocol?} -> PublishPort= value
# ===========================================================================
@pytest.mark.parametrize(
    "port,expected",
    [
        # No-bind is now the EXCEPTION form (default posture is CLOSED, so every
        # real host-published port carries bind:127.0.0.1). render_port still emits
        # the bare host:container when no bind is present -- which is exactly what a
        # bind:0.0.0.0 (the LAN opt-in) also produces the wide-open publish for.
        ({"host": 9200, "container": 9200}, "9200:9200"),
        ({"host": 9200, "container": 9200, "bind": "127.0.0.1"}, "127.0.0.1:9200:9200"),
        ({"host": 9300, "container": 9300, "bind": "0.0.0.0"}, "0.0.0.0:9300:9300"),
        ({"host": 5044, "container": 5044, "bind": "127.0.0.1"}, "127.0.0.1:5044:5044"),
        ({"host": 514, "container": 514, "protocol": "udp"}, "514:514/udp"),
        ({"host": 514, "container": 514, "protocol": "udp", "bind": "127.0.0.1"},
         "127.0.0.1:514:514/udp"),
        # unknown 'serve' key is silently dropped (logstash carries serve:tcp).
        ({"host": 5044, "container": 5044, "bind": "127.0.0.1", "serve": "tcp"},
         "127.0.0.1:5044:5044"),
    ],
)
def test_render_port(port, expected):
    assert render_port(port) == expected


def test_render_port_from_real_manifests():
    # Default posture is CLOSED: the ES client port now binds to loopback.
    es = _load_service("lme-elasticsearch.yml")
    assert render_port(es["publish_ports"][0]) == "127.0.0.1:9200:9200"
    logstash = _load_service("lme-logstash.yml")
    # loopback beats port stays bound to 127.0.0.1 (the isolation invariant).
    assert render_port(logstash["publish_ports"][0]) == "127.0.0.1:5044:5044"
    # UDP syslog port comes from the global ports table -- now loopback-bound too.
    assert render_port(LME_GLOBAL["ports"]["wazuh_syslog"]) == "127.0.0.1:514:514/udp"


# ===========================================================================
# DEFAULT NETWORK POSTURE = CLOSED (exposure-binds fix). The baseline manifests
# must publish NOTHING to the LAN: every host-published port binds to loopback,
# and LAN exposure is an EXPLICIT profile opt-in (a present bind:0.0.0.0), never
# an absent bind. These sweeps are the enforcement the data-only approach needs:
# without them, the next manifest anyone adds is wide open and nothing catches it.
# ===========================================================================
def test_every_service_published_port_is_loopback_by_default():
    # Every publish_ports entry in every service manifest must carry an EXPLICIT
    # bind of 127.0.0.1. render_port emits 0.0.0.0 (wide open) for any entry with
    # no bind, so a missing bind here IS a LAN exposure -- this fails loudly on it.
    offenders = []
    for name, doc in _MANIFESTS:
        if not doc:
            continue
        for port in doc.get("publish_ports", []) or []:
            if port.get("bind") != "127.0.0.1":
                offenders.append("%s -> %r" % (name, port))
    assert offenders == [], (
        "host-published ports not bound to loopback (default posture is CLOSED; "
        "open a port via a profile bind:0.0.0.0, not in the service manifest): %s"
        % offenders
    )
    # And each one actually renders as a loopback publish.
    for _name, doc in _MANIFESTS:
        if not doc:
            continue
        for port in doc.get("publish_ports", []) or []:
            assert render_port(port).startswith("127.0.0.1:")


def test_every_global_canonical_port_is_loopback_by_default():
    # The canonical global.ports table mirrors the same closed posture.
    for key, port in LME_GLOBAL["ports"].items():
        assert port.get("bind") == "127.0.0.1", "%s not loopback-bound" % key


def _load_profile(basename):
    with open(os.path.join(PROFILES_DIR, basename), "r") as fh:
        return yaml.safe_load(fh)


def test_default_and_offline_profiles_open_no_ports():
    # The default and offline profiles must NOT re-open any service to the LAN:
    # they carry no publish_ports override at all, so the loopback service binds
    # stand -- a fresh single-node / air-gapped install exposes nothing off-box.
    for prof in ("default.yml", "offline.yml"):
        overlay = _load_profile(prof)["profile_overlay"]
        for _svc, body in (overlay.get("services") or {}).items():
            assert "publish_ports" not in (body or {}), (
                "%s overrides publish_ports -- must stay fully loopback" % prof
            )


def test_tailscale_profile_stays_loopback():
    # tailscale fronts services via `tailscale serve`, so every port it re-declares
    # must remain loopback-bound (the ingress reaches them on 127.0.0.1).
    overlay = _load_profile("tailscale.yml")["profile_overlay"]
    for _svc, body in (overlay.get("services") or {}).items():
        for port in (body or {}).get("publish_ports", []) or []:
            assert port.get("bind") == "127.0.0.1", "tailscale %s not loopback" % _svc


def test_cluster_profile_opens_only_the_transport_port():
    # cluster is the one baseline profile that opts a port back open: ONLY the ES
    # transport port (9300, which must cross hosts to form a cluster). The client
    # HTTP API (9200) stays loopback. "Open" is a present bind:0.0.0.0.
    overlay = _load_profile("cluster.yml")["profile_overlay"]
    ports = overlay["services"]["elasticsearch"]["publish_ports"]
    by_host = {p["host"]: p for p in ports}
    assert by_host[9200]["bind"] == "127.0.0.1"
    assert by_host[9300]["bind"] == "0.0.0.0"
    assert render_port(by_host[9300]) == "0.0.0.0:9300:9300"


def test_multinode_profile_opens_fleet_and_es_client_ports(tmp_path, monkeypatch):
    # Preserve the legacy direct-publication contract after resolving its
    # defaults. Tailscale composition tests additionally exercise explicit node
    # binds and frontend 9200 -> private backend 19200.
    monkeypatch.setenv('ANSIBLE_LOCAL_TEMP', str(tmp_path))
    from ansible.parsing.dataloader import DataLoader
    from ansible.template import Templar, trust_as_template
    def trusted(value):
        if isinstance(value, str):
            return trust_as_template(value)
        if isinstance(value, list):
            return [trusted(item) for item in value]
        if isinstance(value, dict):
            return {key: trusted(item) for key, item in value.items()}
        return value
    overlay = Templar(loader=DataLoader(), variables={}).template(
        trusted(_load_profile("multinode.yml")["profile_overlay"]), fail_on_undefined=True)
    fleet_by_host = {p["host"]: p
                     for p in overlay["services"]["fleet-server"]["publish_ports"]}
    es_by_host = {p["host"]: p
                  for p in overlay["services"]["elasticsearch"]["publish_ports"]}
    assert fleet_by_host[8220]["bind"] == "0.0.0.0"
    assert render_port(fleet_by_host[8220]) == "0.0.0.0:8220:8220"
    assert es_by_host[9200]["bind"] == "0.0.0.0"
    assert render_port(es_by_host[9200]) == "0.0.0.0:9200:9200"
    # one ES node with remote agents, not a cluster: no transport port opened.
    assert 9300 not in es_by_host


def test_default_profile_keeps_fleet_and_es_client_ports_loopback():
    # Regression guard for the single-node default: the fleet-server (8220) and
    # elasticsearch (9200) client ports stay loopback. Two halves are load-bearing:
    #   (1) the service manifests supply the loopback bind, AND
    #   (2) default.yml's overlay is SILENT on these services (no publish_ports), so
    #       combine() never replaces the loopback list. If a future edit opened either
    #       port in the base manifest OR added an override to default.yml, this fails.
    fleet = _load_service("lme-fleet-server.yml")
    es = _load_service("lme-elasticsearch.yml")
    fleet_by_host = {p["host"]: p for p in fleet["publish_ports"]}
    es_by_host = {p["host"]: p for p in es["publish_ports"]}
    assert render_port(fleet_by_host[8220]) == "127.0.0.1:8220:8220"
    assert render_port(es_by_host[9200]) == "127.0.0.1:9200:9200"
    default_services = _load_profile("default.yml")["profile_overlay"].get("services") or {}
    assert "publish_ports" not in (default_services.get("fleet-server") or {})
    assert "publish_ports" not in (default_services.get("elasticsearch") or {})


def test_webui_auth_secret_wired_into_both_uis():
    # CONTRACT: both web UIs receive the webui_api_key podman secret as env
    # WEBUI_API_KEY, wired exactly like litellm_master_key -> LITELLM_MASTER_KEY.
    for svc in ("lme-dashboard.yml", "lme-log-analyzer.yml"):
        doc = _load_service(svc)
        webui = [s for s in doc["secrets"]
                 if s.get("name") == "webui_api_key"]
        assert webui == [{"name": "webui_api_key", "type": "env",
                          "target": "WEBUI_API_KEY"}], svc


# ===========================================================================
# render_volume : {source, dest, options[]} -> Volume= value, incl. cert:<svc>
# ===========================================================================
def test_render_volume_cert_expansion_real_manifest():
    kib = _load_service("lme-kibana.yml")
    cert_vol = kib["volumes"][0]
    assert cert_vol["source"] == "cert:kibana"
    # cert:<svc> -> <certs.host_tree>/<svc>  (== /opt/lme/certs/kibana)
    assert render_volume(cert_vol, LME_GLOBAL) == (
        "/opt/lme/certs/kibana:/usr/share/kibana/config/certs:ro,Z"
    )


def test_render_volume_named_and_absolute_sources_pass_through():
    # named podman volume, no options
    assert render_volume(
        {"source": "lme_certs", "dest": "/usr/share/elasticsearch/config/certs"},
        LME_GLOBAL,
    ) == "lme_certs:/usr/share/elasticsearch/config/certs"
    # absolute host path, with options
    assert render_volume(
        {"source": "/opt/lme/config/elasticsearch.yml",
         "dest": "/usr/share/elasticsearch/config/elasticsearch.yml",
         "options": ["ro"]},
        LME_GLOBAL,
    ) == "/opt/lme/config/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml:ro"


def test_render_volume_cert_synthetic_uses_global_host_tree():
    assert render_volume(
        {"source": "cert:fleet-server", "dest": "/certs", "options": ["ro", "Z"]},
        LME_GLOBAL,
    ) == "/opt/lme/certs/fleet-server:/certs:ro,Z"


# ===========================================================================
# is_enabled : AND over flags, with the 'always' sentinel as a no-op
# ===========================================================================
@pytest.mark.parametrize(
    "enabled_when,flags,expected",
    [
        (["always"], {}, True),                                   # sentinel -> always on
        ([], {}, True),                                           # empty list -> render
        (None, {}, True),                                         # omitted -> render
        (["install_llm"], {"install_llm": True}, True),           # gate satisfied
        (["install_llm"], {"install_llm": False}, False),         # gate unmet
        (["install_llm"], {}, False),                             # missing flag -> False
        (["install_elastic_services"], {"install_elastic_services": True}, True),
        (["install_elastic_services"], {"install_elastic_services": False}, False),
        # 'always' is a NO-OP, never an override: a real gate still applies.
        (["always", "install_llm"], {"install_llm": False}, False),
        (["always", "install_llm"], {"install_llm": True}, True),
    ],
)
def test_is_enabled_table(enabled_when, flags, expected):
    assert is_enabled(enabled_when, flags) is expected


def test_is_enabled_rejects_misspelled_flag_but_allows_known_absent_flag():
    # CRUX distinction (OCR quality-1): a KNOWN flag merely ABSENT from the passed
    # dict is an unset gate -> False, NEVER an error (the (["install_llm"], {}, False)
    # contract that the table above also asserts, restated here beside the raise).
    assert is_enabled(["install_llm"], {}) is False
    # A MISSPELLED / unknown flag would otherwise resolve False and SILENTLY drop
    # the service from the render; it must raise loudly instead, naming the token.
    with pytest.raises(ValueError) as exc:
        is_enabled(["install_lmm"], {"install_llm": True})
    assert "install_lmm" in str(exc.value)
    # The typo must be caught even when an EARLIER gate is legitimately unmet: a
    # two-pass validate-then-evaluate means the unmet gate cannot short-circuit
    # past the misspelled flag (which is exactly the silent-drop this guard exists
    # to prevent -- the raise, not a quiet False, is the required behaviour).
    with pytest.raises(ValueError):
        is_enabled(["install_elastic_services", "install_lmm"],
                   {"install_elastic_services": False})
    # The 'always' sentinel is still a no-op, not a flag -> never raises.
    assert is_enabled(["always"], {}) is True


def test_is_enabled_always_service_renders_and_gated_service_skips():
    # At least one 'always' service IS enabled and one disabled gated service is NOT.
    es = _load_service("lme-elasticsearch.yml")          # enabled_when: [always]
    litellm = _load_service("lme-litellm.yml")           # enabled_when: [install_llm]
    no_llm = {"install_llm": False, "install_elastic_services": False}
    assert is_enabled(es["enabled_when"], no_llm) is True
    assert is_enabled(litellm["enabled_when"], no_llm) is False


def test_is_enabled_against_offline_profile_flag_set():
    # Flag set an offline install produces: load_manifests.yml defaults
    # (install_llm=true, install_elastic_services=false, offline_mode=false) with
    # profiles/offline.yml vars applied (offline_mode=true, elastic_services=false).
    offline_flags = {
        "install_llm": True,
        "install_elastic_services": False,
        "offline_mode": True,
    }
    for _name, doc in _MANIFESTS:
        if not doc or "enabled_when" not in doc:
            continue
        ew = doc["enabled_when"]
        got = is_enabled(ew, offline_flags)
        if ew == ["always"] or not ew:
            assert got is True, "%s (%r) should render" % (_name, ew)
        elif ew == ["install_llm"]:
            assert got is True, "%s should render (install_llm on)" % _name
        elif ew == ["install_elastic_services"]:
            assert got is False, "%s should skip (elastic-services off)" % _name


# ===========================================================================
# jvm_opts : fully-quoted ES_JAVA_OPTS value assembled from resources.heap
# ===========================================================================
def test_jvm_opts_real_elasticsearch():
    es = _load_service("lme-elasticsearch.yml")
    assert jvm_opts(es["resources"]) == (
        '"-Des.entitlements.enabled=false -Xms4g -Xmx4g"'
    )


def test_jvm_opts_is_fully_quoted():
    # The surrounding quotes are load-bearing (systemd Environment= would split on
    # the internal spaces otherwise).
    out = jvm_opts({"heap": "2g", "jvm_base": "-Dfoo=bar"})
    assert out.startswith('"') and out.endswith('"')
    assert out == '"-Dfoo=bar -Xms2g -Xmx2g"'


def test_jvm_opts_without_jvm_base():
    assert jvm_opts({"heap": "8g"}) == '"-Xms8g -Xmx8g"'


# ===========================================================================
# mem_derive : heap * factor -> systemd MemoryHigh=/MemoryMax= value
# ===========================================================================
@pytest.mark.parametrize(
    "heap,factor,expected",
    [
        ("4g", 1.5, "6G"),   # single-node MemoryHigh
        ("4g", 2, "8G"),     # single-node MemoryMax
        ("8g", 1.5, "12G"),  # cluster node MemoryHigh
        ("8g", 2, "16G"),    # cluster node MemoryMax
        ("512m", 2, "1024M"),  # unit normalised to uppercase
        ("4", 2, "8"),         # bare number keeps empty unit
        ("3g", 1.5, "4.5G"),   # non-integer result keeps the fraction
    ],
)
def test_mem_derive(heap, factor, expected):
    assert mem_derive(heap, factor) == expected


def test_mem_derive_matches_elasticsearch_resource_factors():
    es = _load_service("lme-elasticsearch.yml")
    res = es["resources"]
    assert mem_derive(res["heap"], res["memory_high_factor"]) == "6G"
    assert mem_derive(res["heap"], res["memory_max_factor"]) == "8G"


def test_mem_derive_rejects_unparseable_heap():
    with pytest.raises(ValueError):
        mem_derive("not-a-size", 1.5)


# ===========================================================================
# service_memory_max : the MemoryMax a service's `resources` block renders to.
# Mirrors container.j2's two forms EXACTLY so the summed budget == what is emitted.
# ===========================================================================
def test_service_memory_max_jvm_heap_derived():
    # JVM form: heap * memory_max_factor -- the value container.j2:84 emits.
    assert service_memory_max({"heap": "4g", "memory_max_factor": 2}) == "8G"


def test_service_memory_max_jvm_default_factor_is_two():
    assert service_memory_max({"heap": "4g"}) == "8G"


def test_service_memory_max_non_jvm_verbatim():
    assert service_memory_max({"memory_max": "2G"}) == "2G"


def test_service_memory_max_uncapped_is_none():
    assert service_memory_max({}) is None
    assert service_memory_max(None) is None
    # MemoryHigh without MemoryMax is still an uncapped MAX.
    assert service_memory_max({"memory_high": "1G"}) is None


def test_service_memory_max_real_elasticsearch_is_8g():
    es = _load_service("lme-elasticsearch.yml")
    assert service_memory_max(es["resources"]) == "8G"


# ===========================================================================
# memory_budget : SF-8 co-residency. over_budget is ADVISORY (over-commit of
# per-service kill ceilings); oversized is the HARD gate (a single service that
# cannot be backed by the host at all).
# ===========================================================================
def _svc(sid, cap=None, heap=None, enabled_when=None, kind="container"):
    res = {}
    if heap is not None:
        res["heap"] = heap
    if cap is not None:
        res["memory_max"] = cap
    svc = {"id": sid, "kind": kind, "enabled_when": enabled_when or ["always"]}
    if res:
        svc["resources"] = res
    return svc


def test_memory_budget_default_plus_llm_over_commits_but_is_not_blocked():
    # Real stack on a 16G host: ES(8)+kibana(5)+llm(10) = 23G of ceilings exceeds
    # usable 14G -> over_budget True (ADVISORY), yet NO single service exceeds
    # usable -> oversized empty (deploy NOT blocked). This is the exact
    # graph-default+llm-on-14G reality the hard gate must NEVER false-fail.
    services = {doc["id"]: doc for _n, doc in _MANIFESTS if doc and "id" in doc}
    flags = {"install_llm": True, "install_elastic_services": False, "offline_mode": False}
    b = memory_budget(services, flags, LME_GLOBAL)
    assert b["over_budget"] is True
    assert b["oversized"] == []


def test_memory_budget_single_service_over_host_is_the_hard_gate():
    # A 5G-capped service on a 4G host (usable 4G) cannot fit -> oversized names it.
    services = {"big": _svc("big", cap="5G")}
    g = {"budget": {"host_ram_gb": 4, "reserve_gb": 0}}
    b = memory_budget(services, {}, g)
    assert b["oversized"] == ["big"]
    assert b["over_budget"] is True


def test_memory_budget_service_that_fits_is_not_oversized():
    services = {"ok": _svc("ok", cap="5G")}
    g = {"budget": {"host_ram_gb": 16, "reserve_gb": 0}}
    b = memory_budget(services, {}, g)
    assert b["oversized"] == []
    assert b["over_budget"] is False


def test_memory_budget_math_with_cluster_override():
    # UNIT-LEVEL math only: given a budget dict declaring host_ram_gb=32, an 8g-heap
    # ES (capped MemoryMax 16G) is NOT `oversized` (16G < usable 30G). This proves the
    # pure memory_budget() arithmetic when it is HANDED the cluster override budget
    # (line below feeds the declared 32 directly). It does NOT model a real deploy: the
    # live SF-8 preflight (container_setup.yml:38-46) OVERRIDES host_ram_gb with
    # ansible_memtotal_mb (facts win), so on a real <=16G node the declared 32 is dead
    # and the node's ACTUAL RAM governs -- do NOT read this test as "install proceeds".
    cluster = _load_profile("cluster.yml")["profile_overlay"]["lme_global"]
    eff = dict(LME_GLOBAL)
    eff_budget = dict(LME_GLOBAL["budget"])
    eff_budget.update(cluster.get("budget", {}))
    eff["budget"] = eff_budget
    # cluster ES data node: heap 8g (as the cluster profile sets it).
    services = {"elasticsearch": _svc("elasticsearch", heap="8g")}
    b = memory_budget(services, {}, eff)
    assert eff_budget["host_ram_gb"] == 32
    assert b["capped"]["elasticsearch"] == "16G"
    assert b["oversized"] == []   # given the 32G budget, 16G is not oversized (math only)

    # Guard the regression: on the un-raised default budget the same node WOULD
    # be oversized (proving the profile fix is load-bearing, not cosmetic).
    d = memory_budget(services, {}, LME_GLOBAL)
    assert d["oversized"] == ["elasticsearch"]


def test_memory_budget_excludes_disabled_and_uncapped():
    services = {
        "on":   _svc("on", cap="2G", enabled_when=["install_llm"]),
        "off":  _svc("off", cap="9G", enabled_when=["install_elastic_services"]),
        "bare": _svc("bare"),  # enabled, no cap -> uncapped, excluded from the sum
    }
    g = {"budget": {"host_ram_gb": 16, "reserve_gb": 2}}
    b = memory_budget(services, {"install_llm": True, "install_elastic_services": False}, g)
    assert set(b["capped"].keys()) == {"on"}   # only the enabled + capped service
    assert "bare" in b["uncapped"]
    assert b["oversized"] == []


# ===========================================================================
# podman_args : --network-alias per alias, then verbatim extra tokens
# ===========================================================================
def test_podman_args_assembly():
    assert podman_args(["lme-elasticsearch"], ["--health-interval=2s"]) == (
        "--network-alias lme-elasticsearch --health-interval=2s"
    )
    assert podman_args() == ""


# ===========================================================================
# Corpus sweep: every declared block in every real service manifest resolves
# without raising and yields a well-shaped value. Iterates what is on disk and
# NEVER asserts a service count, so adding a manifest cannot fail this.
# ===========================================================================
def test_every_manifest_block_resolves():
    assert _MANIFESTS, "no service manifests found -- wrong path?"
    for name, doc in _MANIFESTS:
        if not doc:
            continue

        if "enabled_when" in doc:
            assert isinstance(is_enabled(doc["enabled_when"], {}), bool), name

        for certs in [doc["certs"]] if "certs" in doc else []:
            owner = cert_owner(certs, LME_GLOBAL)
            assert isinstance(owner, int) and owner >= 0, "%s cert_owner" % name

        if "userns" in doc:
            val = render_userns(doc["userns"], LME_GLOBAL)
            assert isinstance(val, str) and val, "%s render_userns" % name

        for port in doc.get("publish_ports", []) or []:
            val = render_port(port)
            assert isinstance(val, str) and str(port["host"]) in val, "%s render_port" % name

        for vol in doc.get("volumes", []) or []:
            val = render_volume(vol, LME_GLOBAL)
            assert isinstance(val, str) and ":" in val, "%s render_volume" % name

        deps = doc.get("dependencies", {}) or {}
        for key in ("requires", "after", "partof"):
            names = deps.get(key, []) or []
            resolved = unit_refs(names, KINDS)
            for token in resolved.split():
                assert token.endswith(".service"), "%s dependencies.%s" % (name, key)

        if "resources" in doc and "heap" in doc["resources"]:
            opts = jvm_opts(doc["resources"])
            assert opts.startswith('"') and opts.endswith('"'), "%s jvm_opts" % name


# ===========================================================================
# cert BUNDLE owners under LLM-off  (round-6 blocker regression guard)
# ---------------------------------------------------------------------------
# Faithful in-Python mirror of the certs role's owner derivation
# (ansible/roles/certs/tasks/main.yml:30-36): a service is a per-service
# cert:<svc> BUNDLE owner iff it carries a top-level `certs:` key AND its
# enabled_when passes is_enabled(flags) AND it mounts at least one `cert:`
# volume. The last condition is what excludes Elasticsearch, which owns a
# `certs:` key but mounts the shared lme_certs WORKSPACE (not a cert:<svc>
# bundle). upgrade_lme.yml now runs that role UNCONDITIONALLY (the publish
# was formerly gated on lme_llm_enabled, which left these core bundles
# unpublished on a pre-2.3.0 -> 2.3.0 LLM-off upgrade and crash-looped kibana).
# ===========================================================================
def _derive_cert_bundle_owners(flags):
    owners = set()
    for _name, doc in _MANIFESTS:
        if not doc or "certs" not in doc:
            continue
        if not is_enabled(doc.get("enabled_when", ["always"]), flags):
            continue
        vol_sources = [
            (v or {}).get("source", "") for v in (doc.get("volumes") or [])
        ]
        if any(str(s).startswith("cert:") for s in vol_sources):
            owners.add(doc["id"])
    return owners


def test_llm_off_upgrade_still_publishes_core_cert_bundles():
    # install_llm=false is a first-class upgrade path (install.sh compute_effective_flags);
    # the always-on core cert:<svc> consumers MUST still be published, or core kibana bricks.
    no_llm = {"install_llm": False, "install_elastic_services": False}
    owners = _derive_cert_bundle_owners(no_llm)
    for core in ("kibana", "fleet-server", "fleet-distribution", "wazuh-manager"):
        assert core in owners, (
            "core cert bundle owner %s missing on LLM-off upgrade -> core brick" % core
        )
    # AI-UI bundles are excluded by is_enabled (NOT by the removed task gate), so they
    # must NOT appear when LLM is off -- publishing them would target deleted AI leaves.
    for ai in ("dashboard", "log-analyzer", "litellm", "embeddings", "llama-cpp"):
        assert ai not in owners, (
            "AI-UI cert bundle owner %s leaked into the LLM-off publish set" % ai
        )
    # ES owns a certs: key but mounts the shared lme_certs workspace, not a cert:<svc>
    # bundle -- guards the second (cert-volume) derivation condition against drift.
    assert "elasticsearch" not in owners


def test_llm_on_upgrade_publishes_both_core_and_ai_ui_cert_bundles():
    # Ungating the publish must NOT change the LLM-on set: both core and AI-UI owners present.
    llm_on = {"install_llm": True, "install_elastic_services": False}
    owners = _derive_cert_bundle_owners(llm_on)
    for svc in ("kibana", "fleet-server", "fleet-distribution", "wazuh-manager",
                "dashboard", "log-analyzer", "litellm"):
        assert svc in owners, "%s missing from LLM-on cert bundle owners" % svc


# ---------------------------------------------------------------------------------
# typed material_requirements validator (SCHEMA-REQUIRED-MATERIAL; codex-0430 dec 1+2;
# C convergence ack 0429; D b87f313 record_shape). Value-pure: catalog + schema read
# from manifests/global.yml, never hardcoded in the engine.
# ---------------------------------------------------------------------------------
validate_material = FILTERS["lme_validate_material_requirements"]
validate_catalog = FILTERS["lme_validate_material_catalog"]


def _material_schema():
    with open(GLOBAL_YML, "r") as fh:
        return yaml.safe_load(fh)["lme_config_registry"]["material_requirements_schema"]


def _catalog_schema():
    with open(GLOBAL_YML, "r") as fh:
        return yaml.safe_load(fh)["lme_global"]["material_catalog_schema"]


_MAT_CATALOG = LME_GLOBAL["material_catalog"]
_MAT_SCHEMA = _material_schema()
_MAT_CAT_SCHEMA = _catalog_schema()


def _vm(obligations, **kw):
    """Thread the real catalog + both schemas; default context."""
    kw.setdefault("context", "svcA")
    return validate_material(_MAT_CATALOG, obligations, _MAT_SCHEMA, _MAT_CAT_SCHEMA, **kw)


def _good_obligation():
    return {
        "guardian_pub_proxy": {
            "material_ref": "guardian_public_key",
            "placement_class": "config",
            "destination": "/data/{owner}/config/postgresql/guardian.pub",
            "owner_role": "lmedbhb",
            "mode": "0644",
            "consumer": "fenced proxy mount",
            "profile_condition": "always",
        }
    }


# --- catalog validation (C1-MATERIAL-CATALOG-DEFINITION-VALIDATION) --------------
def test_material_catalog_validates_clean():
    assert validate_catalog(_MAT_CATALOG, _MAT_CAT_SCHEMA) == _MAT_CATALOG


def test_material_catalog_guardian_is_public_key_only():
    # the shared definition is a PUBLIC key -- a shared ref never distributes private material
    assert _MAT_CATALOG["guardian_public_key"]["kind"] == "public_key"


@pytest.mark.parametrize("defn", [None, {}, {"payload_validity": "x"},
                                  {"kind": "bogus_kind", "payload_validity": "x"}])
def test_material_catalog_bad_definition_rejected(defn):
    # null/empty definition, absent kind, unknown kind all FAIL (bare membership no longer passes)
    with pytest.raises(ValueError):
        validate_catalog({"d": defn}, _MAT_CAT_SCHEMA)


# --- the three empty cases ------------------------------------------------------
def test_material_declared_none_passes():
    assert _vm({}) == {}


def test_material_missing_field_fails_not_implicitly_empty():
    with pytest.raises(ValueError) as e:
        _vm(None)
    assert "MISSING" in str(e.value)


def test_material_declared_none_contradicting_ref_is_invalid():
    with pytest.raises(ValueError) as e:
        _vm({}, referenced_ids=["o1"])
    assert "INVALID" in str(e.value)


# --- typed obligation happy path + references -----------------------------------
def test_material_valid_typed_obligation_resolves():
    good = _good_obligation()
    assert _vm(good, referenced_ids=["guardian_pub_proxy"]) == good


def test_material_lifecycle_and_retention_optional_refs_accepted():
    good = _good_obligation()
    good["guardian_pub_proxy"]["lifecycle"] = "bootstrap"
    good["guardian_pub_proxy"]["retention"] = "prior_revision"
    good["guardian_pub_proxy"]["producer_ref"] = "guardian_signer_producer"
    good["guardian_pub_proxy"]["custody_ref"] = "guardian_custody"
    good["guardian_pub_proxy"]["trust_ref"] = "guardian_public_key"
    assert _vm(good) == good


def test_material_lifecycle_vocab_enforced():
    bad = _good_obligation()
    bad["guardian_pub_proxy"]["lifecycle"] = "nonsense"
    with pytest.raises(ValueError):
        _vm(bad)


def test_material_trust_ref_named_must_resolve():
    bad = _good_obligation()
    bad["guardian_pub_proxy"]["trust_ref"] = "ghost_trust"   # no colon => must resolve
    with pytest.raises(ValueError) as e:
        _vm(bad)
    assert "trust_ref" in str(e.value)


def test_material_ref_must_resolve_to_catalog_definition():
    bad = _good_obligation()
    bad["guardian_pub_proxy"]["material_ref"] = "no_such_def"
    with pytest.raises(ValueError) as e:
        _vm(bad)
    assert "material_catalog" in str(e.value)


def test_material_ref_private_kind_is_not_distributable():
    # a catalog NAME alone cannot authorize private-material distribution
    priv_cat = {"signer_priv": {"kind": "private_key", "payload_validity": "x"}}
    obl = _good_obligation()
    obl["guardian_pub_proxy"]["material_ref"] = "signer_priv"
    with pytest.raises(ValueError) as e:
        validate_material(priv_cat, obl, _MAT_SCHEMA, _MAT_CAT_SCHEMA, context="svcA")
    assert "distributable" in str(e.value)


def test_material_placement_class_must_be_in_vocab():
    bad = _good_obligation()
    bad["guardian_pub_proxy"]["placement_class"] = "elsewhere"
    with pytest.raises(ValueError) as e:
        _vm(bad)
    assert "vocab" in str(e.value)


# --- placement-FORM conditionals (C1-MATERIAL-CANONICAL-REFERENCE-SHAPE) ---------
def test_material_file_form_requires_destination_owner_mode():
    bad = _good_obligation()
    del bad["guardian_pub_proxy"]["mode"]
    with pytest.raises(ValueError) as e:
        _vm(bad)
    assert "requires" in str(e.value)


def test_material_env_form_needs_no_path_or_mode():
    obl = {"db_dsn_env": {
        "material_ref": "guardian_public_key",   # any distributable def; env carries no file
        "placement_class": "env",
        "consumer": "litellm process env",
        "profile_condition": "install_llm",
    }}
    assert _vm(obl) == obl


def test_material_env_form_forbids_destination_and_mode():
    obl = {"db_dsn_env": {
        "material_ref": "guardian_public_key",
        "placement_class": "env",
        "destination": "/should/not/be/here",
        "consumer": "x",
        "profile_condition": "always",
    }}
    with pytest.raises(ValueError) as e:
        _vm(obl)
    assert "must NOT declare" in str(e.value)


# --- mode boundary regressions (C1-MATERIAL-MODE-TRAILING-NEWLINE) ---------------
@pytest.mark.parametrize("mode", ["0644\n", " 0644", "0644 ", "8888", "0o644", "rwx", "12"])
def test_material_mode_malformed_rejected(mode):
    bad = _good_obligation()
    bad["guardian_pub_proxy"]["mode"] = mode
    with pytest.raises(ValueError):
        _vm(bad)


@pytest.mark.parametrize("mode", ["0600", "600", "0644", "0755"])
def test_material_mode_valid_octal_accepted(mode):
    good = _good_obligation()
    good["guardian_pub_proxy"]["mode"] = mode
    assert _vm(good) == good


# --- identifier + reference input (C1-MATERIAL-IDENTIFIER-AND-REFERENCE-VALIDATION)
@pytest.mark.parametrize("bad_id", [1, "", "Bad_Caps", "9leading", "has space"])
def test_material_obligation_id_must_be_a_valid_name(bad_id):
    rec = _good_obligation()["guardian_pub_proxy"]
    with pytest.raises(ValueError):
        _vm({bad_id: rec})


def test_material_empty_string_required_field_rejected():
    bad = _good_obligation()
    bad["guardian_pub_proxy"]["consumer"] = ""
    with pytest.raises(ValueError) as e:
        _vm(bad)
    assert "empty" in str(e.value)


def test_material_empty_optional_string_field_rejected_A3():
    # A3: a PRESENT-but-empty OPTIONAL str field (producer_ref) is rejected -- omit it instead
    # of declaring it empty (an empty reference silently resolved to nothing).
    bad = _good_obligation()
    bad["guardian_pub_proxy"]["producer_ref"] = ""
    with pytest.raises(ValueError) as e:
        _vm(bad)
    assert "empty" in str(e.value)


def test_material_colon_trust_ref_undeclared_namespace_rejected_A3():
    # A3: a colon-form trust_ref whose namespace is absent from the declared (empty)
    # trust_ref_namespaces is unresolved and rejected -- no silent `:` bypass of closure.
    bad = _good_obligation()
    bad["guardian_pub_proxy"]["trust_ref"] = "producer:some_ca"
    with pytest.raises(ValueError) as e:
        _vm(bad)
    assert "trust_ref_namespaces" in str(e.value) or "namespace" in str(e.value)


def test_material_record_bool_int_instance_types_enforced_A4():
    # A4: a declared bool/int record field rejects a list / wrong type (synthetic schema, since
    # the current real record declares only str fields). Correct types pass.
    schema = {
        "record": {
            "material_ref": {"type": "str", "required": True},
            "placement_class": {"type": "str", "required": True, "vocab": ["env"]},
            "consumer": {"type": "str", "required": True},
            "profile_condition": {"type": "str", "required": True},
            "flag": {"type": "bool", "required": False},
            "count": {"type": "int", "required": False},
        },
        "obligation_id_pattern": r"\A[a-z][a-z0-9_-]*\Z",
        "mode_pattern": r"\A[0-7]{3,4}\Z",
        "placement_forms": {"env": {"requires": [], "forbids": ["destination", "mode"]}},
        "profile_condition_vocab": ["always"],
        "empty_semantics": {"declared_none_passes": True, "missing_field_fails": True,
                            "empty_contradicting_refs_invalid": True},
    }
    cat = {"m": {"kind": "public_key", "payload_validity": "x"}}
    cat_schema = {
        "definition": {"kind": {"type": "str", "required": True, "vocab": ["public_key"]},
                       "payload_validity": {"type": "str", "required": True}},
        "distributable_kinds": ["public_key"],
    }
    base = {"material_ref": "m", "placement_class": "env", "consumer": "c",
            "profile_condition": "always"}
    with pytest.raises(ValueError):   # bool field given a list
        validate_material(cat, {"o": dict(base, flag=[1, 2])}, schema, cat_schema, context="s")
    with pytest.raises(ValueError):   # int field given a bool
        validate_material(cat, {"o": dict(base, count=True)}, schema, cat_schema, context="s")
    assert validate_material(cat, {"o": dict(base, flag=True, count=3)},
                             schema, cat_schema, context="s")


@pytest.mark.parametrize("bad_refs", ["ghost", {"a": 1}, 5, True])
def test_material_referenced_ids_must_be_a_list(bad_refs):
    with pytest.raises(ValueError) as e:
        _vm(_good_obligation(), referenced_ids=bad_refs)
    assert "referenced_ids" in str(e.value)


def test_material_profile_condition_must_be_in_vocab():
    bad = _good_obligation()
    bad["guardian_pub_proxy"]["profile_condition"] = "whenever"
    with pytest.raises(ValueError) as e:
        _vm(bad)
    assert "profile_condition" in str(e.value)


def test_material_unresolved_reference_is_a_config_error():
    good = _good_obligation()
    with pytest.raises(ValueError) as e:
        _vm(good, referenced_ids=["ghost"])
    assert "pre-generation configuration error" in str(e.value)


def test_material_missing_required_record_field_fails():
    bad = {"x": {"material_ref": "guardian_public_key", "placement_class": "config"}}
    with pytest.raises(ValueError) as e:
        _vm(bad)
    assert "missing required" in str(e.value)


def test_material_undeclared_record_field_rejected():
    bad = _good_obligation()
    bad["guardian_pub_proxy"]["surprise"] = "x"
    with pytest.raises(ValueError) as e:
        _vm(bad)
    assert "undeclared" in str(e.value)


# --- schema self-validation (C1-MATERIAL-SCHEMA-VALIDATION + empty-policy) -------
def test_material_schema_empty_record_rejected():
    broken = {**_MAT_SCHEMA, "record": {}}
    with pytest.raises(ValueError):
        validate_material(_MAT_CATALOG, _good_obligation(), broken, _MAT_CAT_SCHEMA)


def test_material_schema_unsupported_field_type_rejected():
    broken = {**_MAT_SCHEMA,
              "record": {**_MAT_SCHEMA["record"],
                         "consumer": {"type": "list", "required": True}}}
    with pytest.raises(ValueError):
        validate_material(_MAT_CATALOG, _good_obligation(), broken, _MAT_CAT_SCHEMA)


@pytest.mark.parametrize("policy", [
    {"declared_none_passes": False, "missing_field_fails": True, "empty_contradicting_refs_invalid": True},
    {"missing_field_fails": True, "empty_contradicting_refs_invalid": True},   # missing key
    {"declared_none_passes": True, "missing_field_fails": True,
     "empty_contradicting_refs_invalid": True, "surprise": True},             # unknown key
])
def test_material_empty_semantics_policy_must_be_complete_and_true(policy):
    broken = {**_MAT_SCHEMA, "empty_semantics": policy}
    with pytest.raises(ValueError):
        validate_material(_MAT_CATALOG, {}, broken, _MAT_CAT_SCHEMA)


# ===========================================================================
# RESOLVED PROJECTIONS (C1 part C/D): required_material, datastore_clients,
# database membership, deployment identity, dependency closure.
# ===========================================================================
project_required_material = FILTERS["lme_project_required_material"]
project_datastore_clients = FILTERS["lme_project_datastore_clients"]
project_database_membership = FILTERS["lme_project_database_membership"]
validate_deployment_identity = FILTERS["lme_validate_deployment_identity"]
material_resource_id = FILTERS["lme_material_resource_id"]
validate_dependency_closure = FILTERS["lme_validate_dependency_closure"]

# every enable flag on so most services are selected in the sweep
_ALL_FLAGS = {"install_llm": True, "install_elastic_services": True, "offline_mode": False,
              "install_otel": True, "install_legacy_beats": True}


def _all_services_map():
    """id -> manifest doc, as load_manifests.yml builds lme_services (no overlay)."""
    return {doc["id"]: doc for _n, doc in _MANIFESTS if doc and "id" in doc}


def test_projection_over_real_manifests_emits_no_declared_material_yet():
    # 0/29 services declare material_requirements -> required_material empty, but EVERY
    # selected container service is surfaced as status:undeclared (visible debt, not hidden).
    services = _all_services_map()
    out = project_required_material(services, "n1", _MAT_CATALOG, _MAT_SCHEMA,
                                    _MAT_CAT_SCHEMA, enable_flags=_ALL_FLAGS,
                                    deployment_identity="lmedeploy1")
    assert out["required_material"] == {}
    status = out["required_material_status"]["n1"]
    assert status, "expected some selected container services"
    assert all(v["status"] == "undeclared" for v in status.values())
    # elasticsearch bears certs/secrets evidence -> flagged, not empty
    assert "elasticsearch" in status
    assert status["elasticsearch"]["evidence"]


def test_projection_declares_and_binds_a_resource_id():
    svc = {"id": "svcx", "kind": "container", "enabled_when": ["always"],
           "material_requirements": _good_obligation()}
    out = project_required_material({"svcx": svc}, "n1", _MAT_CATALOG, _MAT_SCHEMA,
                                    _MAT_CAT_SCHEMA, deployment_identity="lmedeploy1")
    assert out["required_material"]["n1"]["svcx"] == _good_obligation()
    rid = out["required_material_status"]["n1"]["svcx"]["resource_ids"]["guardian_pub_proxy"]
    assert isinstance(rid, str) and len(rid) == 32
    assert out["required_material_status"]["n1"]["svcx"]["status"] == "declared"


def test_projection_declared_none_with_evidence_fails():
    svc = {"id": "svcx", "kind": "container", "enabled_when": ["always"],
           "secrets": [{"name": "es_pw"}], "material_requirements": {}}
    with pytest.raises(ValueError) as e:
        project_required_material({"svcx": svc}, "n1", _MAT_CATALOG, _MAT_SCHEMA,
                                  _MAT_CAT_SCHEMA)
    assert "declared-none" in str(e.value)


def test_projection_declared_none_without_evidence_is_ok():
    svc = {"id": "svcx", "kind": "container", "enabled_when": ["always"],
           "material_requirements": {}}
    out = project_required_material({"svcx": svc}, "n1", _MAT_CATALOG, _MAT_SCHEMA,
                                    _MAT_CAT_SCHEMA)
    assert out["required_material"] == {}
    assert out["required_material_status"]["n1"]["svcx"]["status"] == "declared_none"


def test_material_resource_id_is_stable_and_deployment_bound():
    a = material_resource_id("dep1", "n1", "svc", "o1")
    assert a == material_resource_id("dep1", "n1", "svc", "o1")      # stable
    assert a != material_resource_id("dep2", "n1", "svc", "o1")      # deployment-bound
    assert material_resource_id(None, "n1", "svc", "o1") is None     # unbound without identity


@pytest.mark.parametrize("ok", ["lmedeploy1", "LME-Prod_01", "a"])
def test_deployment_identity_valid(ok):
    assert validate_deployment_identity(ok) == ok


@pytest.mark.parametrize("bad", ["", "has space", "has/slash", 5, None, "a.b"])
def test_deployment_identity_invalid(bad):
    with pytest.raises(ValueError):
        validate_deployment_identity(bad)


def test_project_datastore_clients_shape():
    svc = {"id": "log-analyzer", "kind": "container", "enabled_when": ["always"],
           "datastore_clients": {"vec": {
               "domain_ref": "vectors", "database_ref": "lme_vectors",
               "principal_ref": "lmedbhb", "endpoint_ref": "vectors_writer",
               "material_requirement_refs": ["vec_pgpass"]}}}
    out = project_datastore_clients({"log-analyzer": svc}, "n1")
    assert out["hosts"]["n1"]["resolved_services"]["log-analyzer"]["datastore_clients"]["vec"][
        "domain_ref"] == "vectors"


def test_project_datastore_clients_missing_ref_fails():
    svc = {"id": "x", "kind": "container", "enabled_when": ["always"],
           "datastore_clients": {"vec": {"domain_ref": "vectors"}}}
    with pytest.raises(ValueError):
        project_datastore_clients({"x": svc}, "n1")


def test_project_database_membership_ok_and_absent():
    m = {"domains": {"vectors": {"members": ["graph", "trixie"]}},
         "etcd_groups": {"vec_etcd": {"members": ["graph", "trixie", "silmaril"]}}}
    out = project_database_membership(m)
    assert out["database"]["domains"]["vectors"]["members"] == ["graph", "trixie"]
    assert project_database_membership(None) == {"database": {}}


@pytest.mark.parametrize("bad", [
    {"domains": {"d": {"members": ["a", "a"]}}},   # duplicate
    {"domains": {"d": {"members": []}}},           # empty
    {"domains": {"d": {}}},                         # no members
])
def test_project_database_membership_rejects_bad(bad):
    with pytest.raises(ValueError):
        project_database_membership(bad)


def test_dependency_closure_real_manifests_all_resolve():
    # every requires/after/wants/partof/binds_to id in the real tree resolves to a manifest
    assert validate_dependency_closure(_all_services_map()) == _all_services_map()


def test_dependency_closure_unknown_name_fails():
    svc = {"id": "x", "kind": "container",
           "dependencies": {"requires": ["elasticsarch"]}}   # typo
    with pytest.raises(ValueError) as e:
        validate_dependency_closure({"x": svc})
    assert "resolves to no declared manifest service id" in str(e.value)


selection_conflicts = FILTERS["lme_selection_conflicts"]


def test_selection_conflicts_detects_only_disagreements():
    # agreeing key -> not a conflict; disagreeing key -> conflict; caller-only key -> fine
    op = {"install_llm": False, "offline_mode": True}
    caller = {"install_llm": True, "offline_mode": True, "install_otel": True}
    assert selection_conflicts(op, caller) == ["install_llm"]
    assert selection_conflicts(op, {"install_llm": False}) == []   # agrees
    assert selection_conflicts({}, caller) == []
    assert selection_conflicts(op, None) == []


def test_selection_conflicts_canonicalize_by_declared_type():
    """C1-CONFLICT-GATE-BOOLEAN-REPRESENTATION-REGRESSION: with the registry supplied, a
    REPRESENTATION difference is not a conflict; only a real value disagreement is."""
    reg = _registry()  # the real lme_config_registry (install_llm declared bool)
    # -e install_llm=false yields the STRING 'false'; a namespaced/JSON caller yields bool
    # False. Raw compare (no registry) FALSELY flags them; type-canonical compare does not.
    assert selection_conflicts({"install_llm": "false"}, {"install_llm": False}) == ["install_llm"]
    assert selection_conflicts({"install_llm": "false"}, {"install_llm": False}, reg) == []
    assert selection_conflicts({"install_llm": "true"}, {"install_llm": True}, reg) == []
    # a genuine disagreement is STILL a conflict after canonicalization
    assert selection_conflicts({"install_llm": "true"}, {"install_llm": False}, reg) == ["install_llm"]
    assert selection_conflicts({"install_llm": True}, {"install_llm": "false"}, reg) == ["install_llm"]
    # an unknown key or an uncoercible value falls back to a raw compare (fail-closed)
    assert selection_conflicts({"nope": "x"}, {"nope": "y"}, reg) == ["nope"]


def _registry():
    with open(GLOBAL_YML, "r") as fh:
        return yaml.safe_load(fh)["lme_config_registry"]
