"""Offline contracts for the Malcolm platform role and manifest."""
from __future__ import annotations

import pathlib
import importlib.util
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[3]


class MalcolmPlatformTests(unittest.TestCase):
    def setUp(self):
        self.manifest_path = ROOT / "config/malcolm-platform/platform.yml"
        self.role_root = ROOT / "ansible/roles/malcolm_platform"

    def factory(self):
        path = self.role_root / "filter_plugins/lme_malcolm.py"
        spec = importlib.util.spec_from_file_location("lme_malcolm", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def resolved_fixture(self):
        image_names = self.factory().MALCOLM_IMAGES
        topology = {
            "schema_version": 1,
            "run_id": "fixture",
            "hosts": {
                "silmaril": {
                    "fqdn": "lme-e2e-fixture-silmaril.lab.ts.net",
                    "tailscale_address": "100.100.100.3",
                    "services": ["malcolm", "malcolm-fixture"],
                    "owners": {"malcolm": "lmemalcolm", "malcolm-fixture": "lmecapture"},
                    "owner_identities": {
                        "lmemalcolm": {"uid": 2205, "gid": 2205, "home": "/home/lmemalcolm", "data": "/data/lmemalcolm"},
                        "lmecapture": {"uid": 2204, "gid": 2204, "home": "/home/lmecapture", "data": "/data/lmecapture"},
                    },
                    "guest": {"name": "lme-e2e-fixture-silmaril", "uuid": "00000000-0000-0000-0000-000000000003", "vcpus": 8, "memory_mib": 49152},
                }
            },
            "providers": {
                "malcolm": {
                    "kind": "role", "role": "malcolm_platform", "runtime": "docker", "memory_mib": 32768,
                    "runtime_units": ["malcolm-sink-proxy.service"],
                    "system_units": ["lme-malcolm.slice"],
                },
                "malcolm-fixture": {"kind": "role", "role": "malcolm_platform", "runtime": "podman", "rootless": True, "memory_mib": 32, "artifacts": ["python311"]},
            },
            "artifacts": {**{"malcolm-" + name: {"reference": "ghcr.io/idaholab/malcolm/" + name + "@sha256:" + chr(97 + i % 6) * 64, "requested": "ghcr.io/idaholab/malcolm/" + name + ":26.08.0"} for i, name in enumerate(image_names)},
                          "python311": {"reference": "docker.io/library/python@sha256:" + "a" * 64}},
        }
        credential = {
            "run_id": "fixture",
            "malcolm_bundles": {"silmaril": "/controller/private/malcolm-bundle"},
            "bootstrap_admins": {"malcolm": {"username": "lme-admin", "password_file": "/controller/private/malcolm-admin"}},
            "malcolm_client_sources": {"lme-fixture-" + scope + "-" + node: {"source_id": scope + ":" + node, "certificate_sha256": chr(97 + i) * 64, "canonical_field": "lme.source_node"} for i, (scope, node) in enumerate((scope, node) for scope in ("physical", "guest") for node in ("graph", "trixie", "silmaril"))},
            "sink_policies": {"malcolm": {"node": "silmaril", "owner": "lmemalcolm", "destination": "/data/lmemalcolm/secrets/malcolm/sink-policy.json", "policy_sha256": "f" * 64, "origin": "https://lme-e2e-fixture-silmaril.lab.ts.net:14459"}},
            "grants": [{"node": "silmaril", "owner": "lmemalcolm", "source_path": "/controller/" + name, "destination": "/data/lmemalcolm/secrets/malcolm-mtls/" + name, "mode": 0o600} for name in self.factory().BUNDLE_FILES]
            + [{"node": "silmaril", "owner": "lmemalcolm", "source_path": "/controller/" + name, "destination": "/data/lmemalcolm/secrets/malcolm/" + name, "mode": 0o600} for name in ("sink-policy.json", "admin-authorization", "gateway-ca.pem")]
            + [{"node": "silmaril", "owner": "lmemalcolm", "source_path": "/controller/malcolm-admin", "destination": "/data/lmemalcolm/secrets/malcolm-bootstrap/admin-password", "mode": 0o600}],
        }
        return topology, credential

    def test_pure_factory_derives_application_role_without_manual_flags(self):
        topology, credential = self.resolved_fixture()
        role_vars = self.factory().resolved_role_config(topology, "silmaril", credential)
        self.assertEqual(set(role_vars), {"malcolm_platform_config"})
        result = role_vars["malcolm_platform_config"]
        self.assertEqual(result["phase"], "application")
        self.assertEqual(result["application"]["runtime"], "docker")
        self.assertIs(result["application"]["runtime_exception"], True)
        self.assertEqual(result["application"]["vcpus"], 8)
        self.assertEqual(result["application"]["memory_mib"], 32768)
        self.assertEqual(result["application"]["slice_memory_mib"], 32704)
        self.assertEqual(
            result["application"]["slice_memory_mib"] + result["sink_gateway"]["memory_mib"],
            result["application"]["memory_mib"],
        )
        self.assertEqual(result["application"]["uid"], 2205)
        self.assertEqual(result["capture_fixture"]["helper"]["owner"], "lmecapture")
        self.assertEqual(result["capture_fixture"]["helper"]["uid"], 2204)
        self.assertTrue(result["capture_fixture"]["helper"]["image"].startswith("docker.io/library/python@sha256:"))
        self.assertEqual(result["sink_gateway"]["listen_port"], 1459)
        self.assertEqual(result["sink_gateway"]["backend_port"], 8445)
        self.assertEqual(result["browser_ui"]["route_id"], "ui:silmaril:malcolm")
        self.assertEqual(result["browser_ui"]["origin"], "https://lme-e2e-fixture-silmaril.lab.ts.net")
        self.assertEqual(result["browser_ui"]["frontend_port"], 443)
        self.assertEqual(result["browser_ui"]["native_backend_port"], 8445)
        self.assertEqual(result["browser_ui"]["serve_target"], "https+insecure://127.0.0.1:8445")
        self.assertEqual(result["browser_ui"]["authentication"], "basic")
        self.assertEqual(result["browser_ui"]["username"], "lme-admin")
        self.assertEqual(result["browser_ui"]["authorization_file"], "/data/lmemalcolm/secrets/malcolm/admin-authorization")
        self.assertEqual(result["browser_ui"]["unauthenticated_statuses"], [401, 403])
        self.assertEqual(result["browser_ui"]["authenticated_statuses"], [200, 301, 302, 303, 307, 308])
        self.assertEqual(result["acceptance"]["malcolm"]["query_owner"], "lmemalcolm")
        self.assertEqual(result["acceptance"]["malcolm"]["native_backend_port"], 8445)
        self.assertEqual(result["authorization_probe"]["receipt_binding"], "malcolm_listener_authorization")
        self.assertEqual(result["authorization_probe"]["listener_port"], 5045)
        self.assertEqual(result["credential_bundle_dir"], "/data/lmemalcolm/secrets/malcolm-mtls")
        self.assertEqual(result["bootstrap_admin"], {"username": "lme-admin", "password_file": "/data/lmemalcolm/secrets/malcolm-bootstrap/admin-password"})
        self.assertEqual(set(result["images"]), set(self.factory().MALCOLM_IMAGES))
        self.assertEqual(len(result["runtime_services"]), 27)
        self.assertEqual(result["runtime_services"]["upload"], "malcolm-file-upload")
        self.assertEqual(result["runtime_services"]["postgres"], "malcolm-postgresql")
        roster = result["runtime_roster"]
        self.assertEqual(roster["install_dir"], "/opt/malcolm/Malcolm")
        self.assertEqual(roster["compose_file"], "/opt/malcolm/Malcolm/docker-compose.tailnet.yml")
        self.assertEqual(roster["compose_project"], "malcolm")
        self.assertEqual(roster["profile"], "malcolm")
        self.assertEqual(roster["cgroup_parent"], "lme-malcolm.slice")
        self.assertEqual(len(roster["services"]), 27)
        self.assertEqual(roster["services"]["upload"]["artifact"], "malcolm-file-upload")
        self.assertEqual(roster["services"]["postgres"]["artifact"], "malcolm-postgresql")
        self.assertEqual(roster["services"]["logstash"]["artifact"], "malcolm-logstash-oss")
        self.assertEqual(roster["services"]["filebeat"]["artifact"], "malcolm-filebeat-oss")
        self.assertTrue(all(item["expected_state"] == "running" for item in roster["services"].values()))
        self.assertEqual(
            {item["reference"] for item in roster["services"].values()},
            set(result["images"].values()),
        )
        self.assertEqual(set(result["source_acl"].values()), {scope + ":" + node for scope in ("physical", "guest") for node in ("graph", "trixie", "silmaril")})
        self.assertNotIn("apply", result)

    def test_factory_rejects_wrong_node_budget_or_unqualified_image(self):
        topology, credential = self.resolved_fixture()
        with self.assertRaises(ValueError):
            self.factory().resolved_role_config(topology, "graph", credential)
        topology["providers"]["malcolm"]["memory_mib"] = 16000
        with self.assertRaises(ValueError):
            self.factory().resolved_role_config(topology, "silmaril", credential)
        topology["providers"]["malcolm"]["memory_mib"] = 32768
        topology["providers"]["malcolm"]["runtime_units"] = ["unexpected.service"]
        with self.assertRaises(ValueError):
            self.factory().resolved_role_config(topology, "silmaril", credential)
        topology["providers"]["malcolm"]["runtime_units"] = ["malcolm-sink-proxy.service"]
        topology["artifacts"]["malcolm-api"]["reference"] = "ghcr.io/idaholab/malcolm/api:latest"
        with self.assertRaises(ValueError):
            self.factory().resolved_role_config(topology, "silmaril", credential)

    def test_topology_declares_docker_exception_and_rootless_fixture_helper(self):
        self.assertTrue(self.manifest_path.is_file())
        doc = yaml.safe_load(self.manifest_path.read_text())
        app = doc["malcolm_platform"]["application"]
        helper = doc["malcolm_platform"]["fixture_helper"]
        self.assertEqual(app["runtime"], "docker")
        self.assertIs(app["privileged_exception"], True)
        self.assertEqual(app["guest"], "silmaril")
        self.assertEqual(app["memory_gib"], 32)
        self.assertEqual(app["vcpus"], 8)
        self.assertEqual(app["guest_memory_gib"], 48)
        self.assertEqual(helper["runtime"], "podman")
        self.assertIs(helper["rootless"], True)
        self.assertEqual(helper["endpoint_scope"], "designated_guest")
        self.assertNotIn("any", yaml.safe_dump(doc).lower().split())

    def test_role_has_fail_closed_inventory_and_apply_gates(self):
        defaults = yaml.safe_load((self.role_root / "defaults/main.yml").read_text())
        tasks = (self.role_root / "tasks/main.yml").read_text()
        self.assertEqual(defaults["malcolm_platform_config"], {})
        self.assertNotIn("playbook_dir", (self.role_root / "defaults/main.yml").read_text())
        self.assertIn("role_path", defaults["malcolm_platform_runner_source"])
        self.assertIn("malcolm_platform_config", tasks)
        self.assertNotIn("malcolm_platform_apply", tasks)
        self.assertIn("capture_fixture", tasks)
        self.assertIn("docker", tasks)
        self.assertIn("rootless", tasks)
        self.assertNotIn('src: "{{ malcolm_platform_runner_source }}/"', tasks)
        self.assertNotIn('src: "{{ malcolm_platform_runner_source }}/{{ item }}/"', tasks)
        self.assertIn("runner_runtime_files", tasks)
        self.assertIn("Reconcile the dedicated Malcolm runner root", tasks)
        self.assertIn("lib/guest_fixture.py", tasks)
        self.assertNotIn("mode: preserve", tasks)
        self.assertIn("--pull=never", tasks)
        self.assertIn("slice_memory_mib", tasks)
        self.assertIn("sink_gateway.memory_mib", tasks)

    def test_main_handoff_is_a_concrete_include_role_invocation(self):
        handoff = (ROOT / "config/malcolm-platform/MAIN-HANDOFF.yml").read_text()
        self.assertIn("ansible.builtin.include_role", handoff)
        self.assertIn("name: malcolm_platform", handoff)
        self.assertIn("lme_malcolm_resolved_role_config", handoff)
        self.assertIn("lme_credential_material", handoff)


if __name__ == "__main__":
    unittest.main()
