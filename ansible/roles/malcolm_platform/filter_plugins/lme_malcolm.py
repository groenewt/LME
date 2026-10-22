"""Resolve the Malcolm application contract from MAIN-owned inputs only."""
from __future__ import annotations

import posixpath
import re
from collections.abc import Mapping


MALCOLM_IMAGES = (
    "api", "arkime", "dashboards", "dashboards-helper", "file-upload",
    "filebeat-oss", "filescan", "freq", "htadmin", "keycloak",
    "logstash-oss", "netbox", "nginx-proxy", "opensearch", "pcap-capture",
    "pcap-monitor", "postgresql", "strelka-backend", "strelka-frontend",
    "strelka-manager", "suricata", "valkey", "zeek",
)
# Frozen from the pinned v26.08.0 compose graph.  Service names are runtime
# identities, while values name the independently pinned image artifacts.
MALCOLM_SERVICE_IMAGES = {
    "opensearch": "opensearch",
    "dashboards-helper": "dashboards-helper",
    "dashboards": "dashboards",
    "logstash": "logstash-oss",
    "filebeat": "filebeat-oss",
    "arkime": "arkime",
    "arkime-live": "arkime",
    "zeek": "zeek",
    "zeek-live": "zeek",
    "suricata": "suricata",
    "suricata-live": "suricata",
    "filescan": "filescan",
    "strelka-backend": "strelka-backend",
    "strelka-frontend": "strelka-frontend",
    "strelka-manager": "strelka-manager",
    "pcap-capture": "pcap-capture",
    "pcap-monitor": "pcap-monitor",
    "upload": "file-upload",
    "htadmin": "htadmin",
    "freq": "freq",
    "netbox": "netbox",
    "postgres": "postgresql",
    "valkey": "valkey",
    "valkey-cache": "valkey",
    "api": "api",
    "keycloak": "keycloak",
    "nginx-proxy": "nginx-proxy",
}
BUNDLE_FILES = (
    "ca.crt", "server.crt", "server.key", "client.crt", "client.key",
    "server-name.txt",
)
_PINNED_COMMIT = "07bbccdfe2732fb5c5147070cdfca2857b85bacc"
_DIGEST = re.compile(r"^ghcr\.io/idaholab/malcolm/([a-z0-9-]+)@sha256:([0-9a-f]{64})$")


def _mapping(value, label):
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be a mapping")
    return value


def _credential_directory(credential_material, node, owner):
    material = _mapping(credential_material, "credential_material")
    bundles = _mapping(material.get("malcolm_bundles"), "malcolm_bundles")
    if not isinstance(bundles.get(node), str) or not bundles[node]:
        raise ValueError(f"missing controller-owned Malcolm bundle for {node}")
    grants = material.get("grants")
    if not isinstance(grants, list):
        raise ValueError("credential grants must be a list")
    destinations = []
    for grant in grants:
        if not isinstance(grant, Mapping) or grant.get("node") != node:
            continue
        destination = grant.get("destination")
        if not isinstance(destination, str) or posixpath.dirname(destination) != "/data/lmemalcolm/secrets/malcolm-mtls":
            continue
        if grant.get("owner") != owner or grant.get("mode") not in (0o600, "0600", 600):
            raise ValueError("Malcolm credential grants require owner lmemalcolm and mode 0600")
        if posixpath.basename(destination) not in BUNDLE_FILES:
            raise ValueError("unexpected Malcolm credential destination")
        destinations.append(destination)
    if sorted(posixpath.basename(path) for path in destinations) != sorted(BUNDLE_FILES):
        raise ValueError("Malcolm credential grant must contain exactly the six public/leaf files")
    directories = {posixpath.dirname(path) for path in destinations}
    if directories != {"/data/lmemalcolm/secrets/malcolm-mtls"}:
        raise ValueError("Malcolm credential bundle has an unsupported guest destination")
    return directories.pop()


def resolved_role_config(topology, node, credential_material):
    """Return a deterministic, non-secret application-phase role input."""
    topology = _mapping(topology, "topology")
    if topology.get("schema_version") != 1:
        raise ValueError("topology schema_version must be integer 1")
    if node != "silmaril":
        raise ValueError("Malcolm is placed only on silmaril")
    run_id = topology.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("topology run_id is required")
    if _mapping(credential_material, "credential_material").get("run_id") != run_id:
        raise ValueError("Malcolm credential material belongs to another run")

    host = _mapping(_mapping(topology.get("hosts"), "hosts").get(node), "silmaril host")
    guest = _mapping(host.get("guest"), "silmaril guest")
    provider = _mapping(_mapping(topology.get("providers"), "providers").get("malcolm"), "malcolm provider")
    fixture_provider = _mapping(topology["providers"].get("malcolm-fixture"), "malcolm fixture provider")
    if (provider.get("kind") != "role" or provider.get("role") != "malcolm_platform"
            or provider.get("runtime") != "docker" or provider.get("memory_mib") != 32768):
        raise ValueError("Malcolm provider must be the bounded 32 GiB Docker role exception")
    runtime_units = provider.get("runtime_units", ["malcolm-sink-proxy.service"])
    if not isinstance(runtime_units, list) or set(runtime_units) != {"malcolm-sink-proxy.service"}:
        raise ValueError("Malcolm provider runtime unit roster is invalid")
    # The application log reader belongs to telemetry_sources and is added
    # dynamically when that role is configured; Malcolm owns only its slice.
    system_units = provider.get("system_units", ["lme-malcolm.slice"])
    if not isinstance(system_units, list) or set(system_units) != {"lme-malcolm.slice"}:
        raise ValueError("Malcolm provider system unit roster is invalid")
    if "malcolm" not in host.get("services", ()) or _mapping(host.get("owners"), "silmaril owners").get("malcolm") != "lmemalcolm":
        raise ValueError("Malcolm placement and owner disagree with the application contract")
    if (fixture_provider.get("kind") != "role" or fixture_provider.get("role") != "malcolm_platform"
            or fixture_provider.get("runtime") != "podman" or fixture_provider.get("rootless") is not True
            or fixture_provider.get("memory_mib") != 32 or fixture_provider.get("artifacts") != ["python311"]
            or "malcolm-fixture" not in host.get("services", ())
            or host["owners"].get("malcolm-fixture") != "lmecapture"):
        raise ValueError("Malcolm fixture must use the declared 32 MiB rootless helper")
    identities = _mapping(host.get("owner_identities"), "silmaril owner identities")
    fixture_identity = _mapping(identities.get("lmecapture"), "lmecapture identity")
    app_identity = _mapping(identities.get("lmemalcolm"), "lmemalcolm identity")
    for owner, identity in (("lmecapture", fixture_identity), ("lmemalcolm", app_identity)):
        if (type(identity.get("uid")) is not int or type(identity.get("gid")) is not int
                or identity.get("home") != f"/home/{owner}" or identity.get("data") != f"/data/{owner}"):
            raise ValueError(f"{owner} runtime identity is incomplete")
    if guest.get("vcpus") != 8 or guest.get("memory_mib") != 49152:
        raise ValueError("silmaril guest must remain bounded at 8 vCPU and 48 GiB")
    if not isinstance(host.get("fqdn"), str) or not host["fqdn"]:
        raise ValueError("silmaril FQDN is required for certificate identity verification")

    artifacts = _mapping(topology.get("artifacts"), "artifacts")
    helper_image = _mapping(artifacts.get("python311"), "python311 artifact").get("reference")
    if not re.fullmatch(r"docker\.io/library/python@sha256:[0-9a-f]{64}", helper_image or ""):
        raise ValueError("rootless fixture helper requires the qualified Python 3.11 artifact")
    images = {}
    for image in MALCOLM_IMAGES:
        item = _mapping(artifacts.get(f"malcolm-{image}"), f"malcolm-{image} artifact")
        reference = item.get("reference")
        match = _DIGEST.fullmatch(reference or "")
        if not match or match.group(1) != image:
            raise ValueError(f"malcolm-{image} must use its qualified upstream manifest digest")
        if item.get("requested") not in ("26.08.0", "v26.08.0", f"ghcr.io/idaholab/malcolm/{image}:26.08.0"):
            raise ValueError(f"malcolm-{image} must resolve release 26.08.0")
        images[image] = reference
    if set(MALCOLM_SERVICE_IMAGES.values()) != set(MALCOLM_IMAGES):
        raise ValueError("frozen Malcolm service roster does not cover the image lock")

    bundle_dir = _credential_directory(credential_material, node, "lmemalcolm")
    bootstrap = _mapping(_mapping(credential_material.get("bootstrap_admins"), "bootstrap_admins").get("malcolm"), "Malcolm bootstrap admin")
    if bootstrap.get("username") != "lme-admin" or not isinstance(bootstrap.get("password_file"), str):
        raise ValueError("Malcolm fresh-run bootstrap administrator contract is missing")
    bootstrap_destination = "/data/lmemalcolm/secrets/malcolm-bootstrap/admin-password"
    bootstrap_grants = [g for g in credential_material.get("grants", []) if isinstance(g, Mapping) and g.get("node") == node and g.get("destination") == bootstrap_destination]
    if len(bootstrap_grants) != 1 or bootstrap_grants[0].get("owner") != "lmemalcolm" or bootstrap_grants[0].get("mode") not in (0o600, "0600", 600):
        raise ValueError("Malcolm bootstrap password must be a single owner-only guest grant")
    sink_paths = {
        "policy_file": "/data/lmemalcolm/secrets/malcolm/sink-policy.json",
        "authorization_file": "/data/lmemalcolm/secrets/malcolm/admin-authorization",
        "ca_file": "/data/lmemalcolm/secrets/malcolm/gateway-ca.pem",
    }
    for destination in sink_paths.values():
        matches = [g for g in credential_material.get("grants", []) if isinstance(g, Mapping)
                   and g.get("node") == node and g.get("owner") == "lmemalcolm" and g.get("destination") == destination]
        if len(matches) != 1 or matches[0].get("mode") not in (0o600, "0600", 600):
            raise ValueError("Malcolm sink gateway requires exact owner-only policy grants")
    sink_policy = _mapping(_mapping(credential_material.get("sink_policies"), "sink_policies").get("malcolm"), "Malcolm sink policy")
    expected_origin = f"https://{host['fqdn']}:14459"
    if (sink_policy.get("node") != node or sink_policy.get("owner") != "lmemalcolm"
            or sink_policy.get("destination") != sink_paths["policy_file"] or sink_policy.get("origin") != expected_origin
            or not re.fullmatch(r"[0-9a-f]{64}", sink_policy.get("policy_sha256", ""))):
        raise ValueError("Malcolm sink policy disagrees with the resolved owner and Serve contract")
    client_sources = _mapping(credential_material.get("malcolm_client_sources"), "malcolm_client_sources")
    expected_sources = {f"{scope}:{source_node}" for scope in ("physical", "guest") for source_node in ("graph", "trixie", "silmaril")}
    source_acl = {}
    for common_name, record in client_sources.items():
        record = _mapping(record, f"Malcolm source {common_name}")
        if not re.fullmatch(r"lme-[a-z0-9-]+-(physical|guest)-(graph|trixie|silmaril)", common_name or ""):
            raise ValueError("Malcolm source certificate common name is invalid")
        if (record.get("source_id") not in expected_sources or record.get("canonical_field") != "lme.source_node"
                or not re.fullmatch(r"[0-9a-f]{64}", record.get("certificate_sha256", ""))):
            raise ValueError("Malcolm source certificate binding is incomplete")
        source_acl[f"CN={common_name}"] = record["source_id"]
    if set(source_acl.values()) != expected_sources or len(source_acl) != 6:
        raise ValueError("Malcolm listener requires exactly six certificate/source bindings")
    config = {
        "schema_version": 1,
        "phase": "application",
        "node": node,
        "run_id": run_id,
        "guest_identity": {"name": guest.get("name"), "uuid": guest.get("uuid")},
        "application": {
            "owner": "lmemalcolm",
            "uid": app_identity["uid"],
            "gid": app_identity["gid"],
            "runtime": "docker",
            "runtime_exception": True,
            "vcpus": 8,
            "memory_mib": 32768,
            # The owner-local gateway has its own 64 MiB user cgroup. The
            # Docker stack and root log reader share this slice, preserving
            # the provider's exact 32 GiB aggregate ceiling.
            "slice_memory_mib": 32704,
            "guest_memory_mib": 49152,
            "install_dir": "/opt/malcolm/Malcolm",
        },
        "source": {
            "repository": "https://github.com/cisagov/Malcolm.git",
            "release": "v26.08.0",
            "commit": _PINNED_COMMIT,
        },
        "images": images,
        "runtime_services": {
            service: f"malcolm-{image}"
            for service, image in MALCOLM_SERVICE_IMAGES.items()
        },
        "runtime_roster": {
            "install_dir": "/opt/malcolm/Malcolm",
            "compose_file": "/opt/malcolm/Malcolm/docker-compose.tailnet.yml",
            "compose_project": "malcolm",
            "profile": "malcolm",
            "owner": "lmemalcolm",
            "cgroup_parent": "lme-malcolm.slice",
            "services": {
                service: {
                    "artifact": f"malcolm-{image}",
                    "reference": images[image],
                    "expected_state": "running",
                }
                for service, image in MALCOLM_SERVICE_IMAGES.items()
            },
            "logging": {
                "driver": "local",
                "options": {"max-size": "10m", "max-file": "3", "compress": "true"},
            },
        },
        "credential_bundle_dir": bundle_dir,
        "credential_files": list(BUNDLE_FILES),
        "bootstrap_admin": {"username": "lme-admin", "password_file": bootstrap_destination},
        "source_acl": source_acl,
        "sink_gateway": {
            "enabled": True,
            "listen_host": "127.0.0.1",
            "listen_port": 1459,
            "external_port": 14459,
            "backend_host": "127.0.0.1",
            "backend_port": 8445,
            "backend_tls_server_name": host["fqdn"],
            "backend_ca_file": sink_paths["ca_file"],
            "policy_file": sink_paths["policy_file"],
            "authorization_file": sink_paths["authorization_file"],
            "policy_sha256": sink_policy["policy_sha256"],
            "memory_mib": 64,
        },
        "browser_ui": {
            "route_id": "ui:silmaril:malcolm",
            "origin": f"https://{host['fqdn']}",
            "frontend_port": 443,
            "native_backend_host": "127.0.0.1",
            "native_backend_port": 8445,
            # Tailscale Serve supplies the system-trusted browser leaf. The
            # owner-local backend leaf is independently verified by the role.
            "serve_target": "https+insecure://127.0.0.1:8445",
            "public_tls": "tailscale-serve-system-trust",
            "authentication": "basic",
            "username": "lme-admin",
            "authorization_file": sink_paths["authorization_file"],
            "unauthenticated_statuses": [401, 403],
            "authenticated_statuses": [200, 301, 302, 303, 307, 308],
        },
        "tls": {
            "certificate_producer": "main_credential_materializer",
            "listener_port": 5045,
            "client_authentication": "required",
            "server_name": host["fqdn"],
            "verify_mode": "full",
        },
        "authorization_probe": {
            "executable": "/opt/lme/integrations/malcomrunner/bin/verify-source-authorization.py",
            "listener_host": host["fqdn"],
            "listener_port": 5045,
            "listener_tls_server_name": host["fqdn"],
            "readback_origin": expected_origin,
            "receipt_binding": "malcolm_listener_authorization",
            "required_receipt_fields": ["run_id", "source_id", "source_bound", "negative_probe_verified"],
            "execution_phase": "sinkauthverify_after_network_before_source_activation",
        },
        "capture_fixture": {
            "endpoint_scope": "designated_guest",
            "designated_guest_id": "silmaril-malcolm",
            "capture_on_analysis_host": False,
            "helper": {"runtime": "podman", "rootless": True, "owner": "lmecapture", "uid": fixture_identity["uid"], "gid": fixture_identity["gid"], "memory_mib": 32, "image": helper_image},
        },
        "acceptance": {
            "malcolm": {
                "owner": "lmecapture",
                "query_owner": "lmemalcolm",
                "config_path": "/data/lmemalcolm/config/malcolm/sink-proxy.json",
                "native_backend_host": "127.0.0.1",
                "native_backend_port": 8445,
                "native_tls_server_name": host["fqdn"],
                "native_ca_file": sink_paths["ca_file"],
                "native_authorization_file": sink_paths["authorization_file"],
                "fixture_cli": "/opt/lme/integrations/malcomrunner/bin/guest-capture-fixture.py",
            }
        },
    }
    return {"malcolm_platform_config": config}


class FilterModule:
    def filters(self):
        return {"lme_malcolm_resolved_role_config": resolved_role_config}
