"""Composition tests for manifest-driven Tailscale and Fleet endpoints.

These tests render the expressions shipped in the Ansible task files with
Ansible's own Jinja environment.  They deliberately do not reimplement the
publisher: a wrong field name, default, command argument, or guard in the real
task changes the rendered result and fails here.
"""

from __future__ import annotations

import os
import json
from pathlib import Path
import uuid

import pytest
import yaml


# ansible-core initializes its local temp directory at import time.  Keep that
# state inside the writable test workspace instead of ~/.ansible.
os.environ.setdefault("ANSIBLE_LOCAL_TEMP", "/tmp/lme-ansible-local")
os.environ.setdefault("ANSIBLE_REMOTE_TEMP", "/tmp/lme-ansible-remote")

from ansible.parsing.dataloader import DataLoader  # noqa: E402
from ansible.plugins.loader import filter_loader  # noqa: E402
from ansible.template import Templar, trust_as_template  # noqa: E402


ROOT = Path(__file__).resolve().parents[3]
SERVICE_TASKS = ROOT / "ansible/roles/podman/tasks/tailscale_service.yml"
INGRESS_TASKS = ROOT / "ansible/roles/podman/tasks/tailscale_ingress.yml"
FLEET_TASKS = ROOT / "ansible/roles/fleet/tasks/main.yml"
PROFILES = ROOT / "manifests/profiles"
SERVICES = ROOT / "manifests/services"

filter_loader.add_directory(str(ROOT / "ansible/roles/podman/filter_plugins"))


def _load_yaml(path: Path):
    return yaml.safe_load(path.read_text())


def _task(path: Path, name: str):
    matches = [task for task in _load_yaml(path) if task.get("name") == name]
    assert len(matches) == 1, f"expected one task named {name!r}, got {len(matches)}"
    return matches[0]


def _trusted(value):
    if isinstance(value, str):
        return trust_as_template(value)
    if isinstance(value, list):
        return [_trusted(item) for item in value]
    if isinstance(value, dict):
        return {key: _trusted(item) for key, item in value.items()}
    return value


def _render(value, variables):
    loader = DataLoader()
    templar = Templar(loader=loader, variables=_trusted(variables))
    return templar.template(_trusted(value), fail_on_undefined=True)


def _render_task_value(task, value, variables):
    scoped = dict(variables)
    scoped.update(task.get("vars", {}))
    return _render(value, scoped)


def _derive_service_target(port):
    task = _task(
        SERVICE_TASKS,
        "Derive one tailnet VIP target per opt-in (tailnet_service-marked) host-facing service",
    )
    item = {
        "key": "example",
        "value": {
            "id": "example",
            "tailnet_service": "example",
            "enabled_when": ["always"],
            "publish_ports": [port],
        },
    }
    variables = {
        "item": item,
        "ts_svc_targets": [],
        "lme_enable_flags": {},
        "lme_host_services": [],
    }
    return _render_task_value(
        task, task["ansible.builtin.set_fact"]["ts_svc_targets"], variables
    )[0]


def _derive_ingress_target(port):
    task = _task(
        INGRESS_TASKS,
        "Derive one host ingress target per tailnet_ingress-marked publish_port (enabled services only)",
    )
    item = [
        {
            "key": "example",
            "value": {"id": "example", "enabled_when": ["always"]},
        },
        port,
    ]
    variables = {
        "item": item,
        "ts_ingress_targets": [],
        "lme_enable_flags": {},
        "lme_host_services": [],
    }
    module = task.get("ansible.builtin.set_fact", task.get("set_fact"))
    return _render_task_value(task, module["ts_ingress_targets"], variables)[0]


def _assertions_pass(task, variables):
    module = task.get("ansible.builtin.assert", task.get("assert"))
    return all(_condition(task, expression, variables) for expression in module["that"])


def _condition(task, expression, variables):
    """Render an Ansible ``when`` expression (which intentionally lacks {{ }})."""
    return bool(_render_task_value(task, "{{ " + str(expression) + " }}", variables))


def test_vip_tailnet_port_separates_frontend_from_loopback_backend():
    target = _derive_service_target(
        {
            "host": 19200,
            "container": 9200,
            "bind": "127.0.0.1",
            "tailnet_port": 9200,
            "serve": "tcp",
        }
    )
    assert target == {
        "service": "example",
        "front_port": 9200,
        "backend_port": 19200,
        "scheme": "tcp",
    }

    publish = _task(
        SERVICE_TASKS,
        "Publish enabled LME service VIPs as raw TCP passthrough (raw-TLS backends)",
    )
    command = _render(publish["ansible.builtin.command"], {"item": target})
    assert command == (
        "tailscale serve --bg --service=svc:example "
        "--tcp=9200 tcp://127.0.0.1:19200"
    )


def test_vip_without_tailnet_port_keeps_legacy_same_port_behavior():
    target = _derive_service_target(
        {"host": 8443, "container": 8443, "bind": "127.0.0.1"}
    )
    assert target["front_port"] == 8443
    assert target["backend_port"] == 8443


@pytest.mark.parametrize("field,value", [("front_port", None), ("front_port", 0), ("front_port", 65536), ("backend_port", "19200")])
def test_vip_invalid_frontend_or_backend_port_fails_closed(field, value):
    validate = _task(
        SERVICE_TASKS, "Assert derived tailnet VIP frontend and backend ports are valid"
    )
    target = {
        "service": "example",
        "front_port": 9200,
        "backend_port": 19200,
        "scheme": "tcp",
    }
    target[field] = value
    assert not _assertions_pass(validate, {"item": target})


def test_vip_wildcard_frontend_conflict_fails_without_weakening_guard_1b():
    conflict = _task(
        SERVICE_TASKS,
        "Assert tailnet VIP frontends do not overlap wildcard host publications",
    )
    service = {
        "id": "elasticsearch",
        "tailnet_service": "lme-elasticsearch",
        "enabled_when": ["always"],
        "publish_ports": [
            {
                "host": 19200,
                "container": 9200,
                "bind": "127.0.0.1",
                "tailnet_port": 9200,
            },
            {"host": 9200, "container": 9200, "bind": "0.0.0.0"},
        ],
    }
    variables = {
        "item": {"key": "elasticsearch", "value": service},
        "lme_enable_flags": {},
        "lme_host_services": [],
        "ts_wildcard_tcp_fronts": [9200],
    }
    assert not _assertions_pass(conflict, variables)

    guard = _task(
        SERVICE_TASKS,
        "Assert each opt-in (tailnet_service) service derives at least one loopback VIP front port",
    )
    assert _assertions_pass(guard, variables)

    variables["item"]["value"]["publish_ports"] = [service["publish_ports"][1]]
    assert not _assertions_pass(guard, variables)


def test_wildcard_conflict_detection_is_global_across_services_and_ingress():
    vip = _task(
        SERVICE_TASKS,
        "Assert tailnet VIP frontends do not overlap wildcard host publications",
    )
    vip_item = {
        "key": "elasticsearch",
        "value": {
            "id": "elasticsearch",
            "tailnet_service": "lme-elasticsearch",
            "enabled_when": ["always"],
            "publish_ports": [
                {
                    "host": 19200,
                    "container": 9200,
                    "bind": "127.0.0.1",
                    "tailnet_port": 9200,
                }
            ],
        },
    }
    variables = {
        "item": vip_item,
        "lme_enable_flags": {},
        "lme_host_services": [],
        # Derived from a different enabled service.
        "ts_wildcard_tcp_fronts": [9200],
    }
    assert not _assertions_pass(vip, variables)

    ingress = _task(
        INGRESS_TASKS,
        "Assert derived ingress frontend and backend ports are valid and unique",
    )
    target = {
        "name": "collector",
        "front_port": 14418,
        "backend_port": 14318,
        "mode": "https",
    }
    assert not _assertions_pass(
        ingress,
        {
            "item": target,
            "ts_ingress_targets": [target],
            "ts_wildcard_tcp_fronts": [14418],
        },
    )


def test_vip_guard_and_derivation_keep_the_same_host_roster_clause():
    names = [
        "Assert each opt-in (tailnet_service) service derives at least one loopback VIP front port",
        "Assert tailnet VIP frontends do not overlap wildcard host publications",
        "Derive one tailnet VIP target per opt-in (tailnet_service-marked) host-facing service",
    ]
    variables = {
        "item": {
            "key": "elasticsearch",
            "value": {
                "id": "elasticsearch",
                "tailnet_service": "lme-elasticsearch",
                "enabled_when": ["always"],
                "publish_ports": [
                    {"host": 9200, "container": 9200, "bind": "127.0.0.1"}
                ],
            },
        },
        "lme_enable_flags": {},
        "lme_host_services": ["kibana"],
    }
    for name in names:
        task = _task(SERVICE_TASKS, name)
        assert not _condition(task, task["when"][-1], variables), name


def test_ingress_tailnet_port_separates_frontend_and_drift_uses_both_ports():
    target = _derive_ingress_target(
        {
            "host": 14000,
            "container": 4000,
            "bind": "127.0.0.1",
            "tailnet_port": 4000,
            "tailnet_ingress": "https",
        }
    )
    assert target == {
        "name": "example",
        "front_port": 4000,
        "backend_port": 14000,
        "mode": "https",
    }

    publish = _task(
        INGRESS_TASKS, "Front host-facing HTTPS ingress services with the node's ts.net cert"
    )
    command = _render(publish["ansible.builtin.command"], {"item": target})
    assert command == (
        "tailscale serve --bg --https=4000 "
        "https+insecure://127.0.0.1:14000"
    )

    drift = _task(INGRESS_TASKS, "Detect drift in configured host ingress routes")
    current = {
        "item": {
            "front_port": 4000,
            "mode": "https",
            "target": "https+insecure://127.0.0.1:14000",
            "signature": "https|4000|https+insecure://127.0.0.1:14000",
            "root_only": True,
        },
        "ts_ingress_owned_signatures": [
            "https|4000|https+insecure://127.0.0.1:14000"
        ],
        "ts_ingress_desired_signatures": [
            "https|4000|https+insecure://127.0.0.1:14000"
        ],
    }
    assert not all(_condition(drift, clause, current) for clause in drift["when"])

    # Moving the frontend retains the backend target, so the old listener is
    # recognized as owned drift and the command clears the old port itself.
    current["item"]["front_port"] = 5000
    current["item"]["signature"] = (
        "https|5000|https+insecure://127.0.0.1:14000"
    )
    current["ts_ingress_owned_signatures"] = [current["item"]["signature"]]
    assert all(_condition(drift, clause, current) for clause in drift["when"])
    command = _render(drift["ansible.builtin.command"], current)
    assert command == "tailscale serve --https=5000 off"

    # A protected prior signature supplies stable ownership when the backend
    # itself changes; ownership is not inferred from the newly desired target.
    current["item"]["front_port"] = 4000
    current["item"]["signature"] = (
        "https|4000|https+insecure://127.0.0.1:14000"
    )
    current["ts_ingress_owned_signatures"] = [current["item"]["signature"]]
    current["ts_ingress_desired_signatures"] = [
        "https|4000|https+insecure://127.0.0.1:24000"
    ]
    assert all(_condition(drift, clause, current) for clause in drift["when"])


def test_node_ingress_uses_real_status_json_and_protects_non_proxy_handlers():
    config_reads = [
        task["ansible.builtin.command"]
        for task in _load_yaml(INGRESS_TASKS)
        if "full tailscale serve config" in task.get("name", "").lower()
        and "ansible.builtin.command" in task
    ]
    assert config_reads == [
        "tailscale serve status --json",
        "tailscale serve status --json",
    ]

    derive = _task(
        INGRESS_TASKS,
        "Derive persisted HTTPS host ingress listeners and all handler occupancy",
    )
    route = _render_task_value(
        derive,
        derive["ansible.builtin.set_fact"]["ts_ingress_current_routes"],
        {
            "ts_ingress_current_routes": [],
            "ts_serve_config_object": {
                "TCP": {"4000": {"HTTPS": True}},
                "Web": {
                    "node.example.ts.net:4000": {
                        "Handlers": {"/": {"Text": "occupied"}}
                    }
                },
            },
            "item": {
                "key": "node.example.ts.net:4000",
                "value": {"Handlers": {"/": {"Text": "occupied"}}},
            },
        },
    )[0]
    assert route["front_port"] == 4000
    assert route["root_only"] is False

    protect = _task(INGRESS_TASKS, "Refuse to replace a cross-owner route on a desired frontend")
    assert not _assertions_pass(
        protect,
        {
            "item": route,
            "ts_ingress_desired_fronts": [4000],
            "ts_ingress_desired_signatures": [
                "https|4000|https+insecure://127.0.0.1:14000"
            ],
            "ts_ingress_owned_signatures": [],
        },
    )

    raw = _task(
        INGRESS_TASKS,
        "Derive persisted raw TCP routes and orphaned TCP listener occupancy",
    )
    terminated = _render_task_value(
        raw,
        raw["ansible.builtin.set_fact"]["ts_ingress_current_routes"],
        {
            "ts_ingress_current_routes": [],
            "item": {
                "key": "9200",
                "value": {
                    "TCPForward": "127.0.0.1:9200",
                    "TerminateTLS": "node.example.ts.net",
                },
            },
        },
    )[0]
    assert terminated["root_only"] is False


def test_vip_drift_compares_only_the_selected_services_exact_endpoint_map():
    drift = _task(
        SERVICE_TASKS,
        "Clear a VIP's stale serve config when its frontend or backend route has drifted",
    )
    target = {
        "service": "selected",
        "front_port": 9200,
        "backend_port": 19200,
        "scheme": "tcp",
    }
    variables = {
        "item": target,
        "ts_service_config_object": {
            "version": "0.0.1",
            "services": {
                "svc:selected": {
                    "endpoints": {"tcp:9200": "tcp://127.0.0.1:29200"}
                },
                # These desired substrings must not conceal drift on selected.
                "svc:unrelated": {
                    "endpoints": {"tcp:9200": "tcp://127.0.0.1:19200"}
                },
            },
        },
    }
    assert all(_condition(drift, clause, variables) for clause in drift["when"])
    variables["ts_service_config_object"]["services"]["svc:selected"]["endpoints"] = {
        "tcp:9200": "tcp://127.0.0.1:19200"
    }
    assert not all(_condition(drift, clause, variables) for clause in drift["when"])


def test_ingress_rejects_duplicate_frontends_and_missing_front_port():
    validate = _task(
        INGRESS_TASKS, "Assert derived ingress frontend and backend ports are valid and unique"
    )
    first = {
        "name": "one",
        "front_port": 4000,
        "backend_port": 14000,
        "mode": "https",
    }
    duplicate = dict(first, name="two", backend_port=24000)
    variables = {
        "item": first,
        "ts_ingress_targets": [first, duplicate],
        "ts_wildcard_tcp_fronts": [],
    }
    assert not _assertions_pass(validate, variables)

    missing = dict(first, front_port=None)
    assert not _assertions_pass(
        validate,
        {
            "item": missing,
            "ts_ingress_targets": [missing],
            "ts_wildcard_tcp_fronts": [],
        },
    )


@pytest.mark.parametrize("path", [SERVICE_TASKS, INGRESS_TASKS])
def test_skipped_drift_rereads_preserve_the_original_serve_snapshots(path):
    status_reread = next(
        task
        for task in _load_yaml(path)
        if task.get("name", "").startswith("Re-read tailscale serve status after")
    )
    config_reread = next(
        task
        for task in _load_yaml(path)
        if task.get("name", "").startswith("Re-read full tailscale serve")
        and "after" in task.get("name", "")
    )
    assert status_reread["register"] != "ts_serve_status"
    assert config_reread["register"] != "ts_serve_cfg"

    effective = next(
        task
        for task in _load_yaml(path)
        if task.get("name") == "Select effective tailscale serve snapshots"
    )
    facts = effective["ansible.builtin.set_fact"]
    variables = {
        "ts_serve_status": {"stdout": "original-status"},
        "ts_serve_cfg": {"stdout": "original-config"},
        status_reread["register"]: {"skipped": True},
        config_reread["register"]: {"skipped": True},
    }
    assert _render(facts, variables) == {
        "ts_serve_status_effective": {"stdout": "original-status"},
        "ts_serve_cfg_effective": {"stdout": "original-config"},
    }


def _render_profile_port(profile_name, service_name, variables):
    profile = _load_yaml(PROFILES / profile_name)
    raw = profile["profile_overlay"]["services"][service_name]["publish_ports"]
    return _render(raw, variables)


def test_multinode_tailscale_uses_isolated_backend_without_wildcard_overlap():
    ports = _render_profile_port(
        "multinode.yml",
        "elasticsearch",
        {
            "tailscale_serve_services": True,
            "fleet_output_bind_address": "100.70.80.90",
            "fleet_enrollment_bind_address": "100.70.80.90",
            "lme_lab_mode": True,
        },
    )
    assert ports == [
        {
            "host": 19200,
            "container": 9200,
            "bind": "127.0.0.1",
            "tailnet_port": 9200,
            "serve": "tcp",
        }
    ]
    assert not any(p["host"] == 9200 and p["bind"] in ("0.0.0.0", "::") for p in ports)


def test_multinode_direct_mode_binds_only_the_configured_tailscale_address():
    variables = {
        "tailscale_serve_services": False,
        "fleet_output_bind_address": "100.70.80.90",
        "fleet_enrollment_bind_address": "100.70.80.90",
        "lme_lab_mode": True,
    }
    es_ports = _render_profile_port("multinode.yml", "elasticsearch", variables)
    fleet_ports = _render_profile_port("multinode.yml", "fleet-server", variables)
    assert es_ports == [
        {
            "host": 9200,
            "container": 9200,
            "bind": "100.70.80.90",
            "tailnet_port": 9200,
            "serve": "tcp",
        }
    ]
    assert fleet_ports == [
        {"host": 8220, "container": 8220, "bind": "100.70.80.90"}
    ]


def test_elasticsearch_overlays_preserve_tailnet_frontend_metadata():
    base = _load_yaml(SERVICES / "lme-elasticsearch.yml")["publish_ports"]
    cluster = _load_yaml(PROFILES / "cluster.yml")["profile_overlay"]["services"][
        "elasticsearch"
    ]["publish_ports"]
    assert base[0]["tailnet_port"] == 9200
    assert cluster[0]["tailnet_port"] == 9200
    assert base[0]["serve"] == cluster[0]["serve"] == "tcp"


def test_fleet_resolves_distinct_endpoints_with_legacy_fallback():
    host_task = _task(FLEET_TASKS, "Resolve separate Fleet enrollment and output hosts")
    host_facts = host_task["ansible.builtin.set_fact"]
    legacy = {
        "fleet_advertise_host": "legacy.example",
        "ipvar": "10.0.0.2",
    }
    assert _render(host_facts, legacy) == {
        "fleet_enrollment_host": "legacy.example",
        "fleet_output_host": "legacy.example",
    }
    split = dict(
        legacy,
        fleet_enrollment_host="graph.tail.example",
        fleet_output_host="lme-elasticsearch.tail.example",
    )
    assert _render(host_facts, split) == {
        "fleet_enrollment_host": "graph.tail.example",
        "fleet_output_host": "lme-elasticsearch.tail.example",
    }

    url_task = _task(FLEET_TASKS, "Resolve separate Fleet enrollment and output URLs")
    urls = _render(
        url_task["ansible.builtin.set_fact"],
        dict(split, fleet_port=8220),
    )
    assert urls == {
        "fleet_enrollment_url": "https://graph.tail.example:8220",
        "fleet_output_url": "https://lme-elasticsearch.tail.example:9200",
    }

    wait = _task(FLEET_TASKS, "Wait for fleet-server to be ready")
    assert _render(
        wait["wait_for"]["host"],
        {"fleet_enrollment_probe_host": "100.70.80.90"},
    ) == "100.70.80.90"


def test_fleet_output_requires_full_tls_and_exact_persisted_readback():
    configure = _task(FLEET_TASKS, "Set Fleet default output endpoint contract")
    body = _render(
        configure["ansible.builtin.uri"]["body"],
        {
            "fleet_output_url": "https://lme-elasticsearch.tail.example:9200",
            "ca_fingerprint": "ABCD",
        },
    )
    assert body == {
        "hosts": ["https://lme-elasticsearch.tail.example:9200"],
        "ca_trusted_fingerprint": "ABCD",
        "config_yaml": "ssl.verification_mode: full\n",
    }

    verify = _task(FLEET_TASKS, "Assert persisted Fleet output endpoint contract")
    variables = {
        "fleet_output_url": "https://lme-elasticsearch.tail.example:9200",
        "ca_fingerprint": "ABCD",
        "fleet_output_readback": {
            "status": 200,
            "json": {
                "item": {
                    "hosts": ["https://lme-elasticsearch.tail.example:9200"],
                    "ca_trusted_fingerprint": "ABCD",
                    "config_yaml": "ssl.verification_mode: full\n",
                }
            }
        },
    }
    assert _assertions_pass(verify, variables)
    variables["fleet_output_readback"]["json"]["item"]["hosts"].append(
        "https://stale.tail.example:9200"
    )
    assert not _assertions_pass(verify, variables)
    variables["fleet_output_readback"]["json"]["item"]["hosts"] = [
        "https://lme-elasticsearch.tail.example:9200"
    ]
    variables["fleet_output_readback"]["json"]["item"]["config_yaml"] = (
        "ssl.verification_mode: certificate\n"
    )
    assert not _assertions_pass(verify, variables)
    variables["fleet_output_readback"]["json"]["item"]["config_yaml"] = (
        "# ssl.verification_mode: full\nssl.verification_mode: none\n"
    )
    assert not _assertions_pass(verify, variables)


def test_fleet_enrollment_readback_requires_one_exact_configured_object():
    verify = _task(FLEET_TASKS, "Assert persisted Fleet enrollment endpoint contract")
    exact = {
        "fleet_enrollment_url": "https://graph.tail.example:8220",
        "fleet_server_hosts_readback": {
            "json": {
                "items": [
                    {
                        "id": "lme-fleet-server",
                        "host_urls": ["https://graph.tail.example:8220"],
                    }
                ]
            }
        },
    }
    assert _assertions_pass(verify, exact)

    stale = yaml.safe_load(yaml.safe_dump(exact))
    stale["fleet_server_hosts_readback"]["json"]["items"][0]["host_urls"].append(
        "https://stale.tail.example:8220"
    )
    assert not _assertions_pass(verify, stale)

    duplicate = yaml.safe_load(yaml.safe_dump(exact))
    duplicate["fleet_server_hosts_readback"]["json"]["items"].append(
        {
            "id": "lme-fleet-server",
            "host_urls": ["https://graph.tail.example:8220"],
        }
    )
    assert not _assertions_pass(verify, duplicate)


def test_fleet_policy_and_collection_verification_use_configured_inventory():
    policy = _task(FLEET_TASKS, "Select only the configured Fleet endpoint policy")
    variables = {
        "fleet_endpoint_policy_id": "configured-policy",
        "existing_policies": {
            "json": {
                "items": [
                    {"id": "other-active", "name": "Endpoint Policy"},
                    {"id": "configured-policy", "name": "Lab Endpoint Policy"},
                ]
            }
        },
    }
    assert _render(policy["ansible.builtin.set_fact"]["policy_id"], variables) == (
        "configured-policy"
    )

    verify = _task(FLEET_TASKS, "Assert every expected lab source is uniquely online on the configured policy")
    variables = {
        "fleet_expected_agent_hostnames": ["graph", "trixie"],
        "fleet_endpoint_policy_id": "configured-policy",
        "fleet_verified_agent_hostnames": ["graph", "trixie"],
    }
    assert _assertions_pass(verify, variables)
    variables["fleet_verified_agent_hostnames"] = ["graph", "graph"]
    assert not _assertions_pass(verify, variables)






class _RouteRunner:
    def __init__(self):
        self.calls = []

    def run_guest(self, host, port, script, stdin=None, known_hosts=None):
        payload = json.loads(stdin)
        self.calls.append(
            {
                "host": host,
                "port": port,
                "script": script,
                "payload": payload,
                "known_hosts": known_hosts,
            }
        )
        effects = ([
                    {"id": route["id"], "status": "retired",
                     "frontend_port": route["frontend_port"]}
                    for route in payload["routes"]
                ] + [{"id": "tailscale-identity:" + payload["node"], "status": "logged-out",
                      "frontend_port": 0}]) if payload["operation"] == "retire" else [
                    {"id": route["id"], "status": "verified"}
                    for route in payload["routes"]
                ]
        return json.dumps(
            {
                "ok": True,
                "operation": payload["operation"],
                "node": payload["node"],
                "effects": effects,
                "config_digest": "b" * 64,
            }
        )
















