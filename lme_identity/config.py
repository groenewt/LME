"""Pure identity-proxy role configuration derived from resolved inventory."""

from __future__ import annotations

import re
from pathlib import PurePosixPath


CAPABILITY = "cisa.gov/cap/lme-observer"
PROVIDER = "identity-proxy"
NODE = "trixie"
OWNER = "lmeui"
BACKEND_KEY = "/data/lmeui/secrets/webui_api_key"
BACKEND_CA = "/data/lmeui/config/certs/dashboard/ca/ca.crt"


def _personal_login(value: object) -> str:
    if not isinstance(value, str) or value != value.strip() or len(value) > 254:
        raise ValueError("operator login must be an explicit personal identity")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+", value) or any(char in value for char in "\r\n"):
        raise ValueError("operator login must be an explicit personal identity")
    return value


def _grant(grants: object, *, node: str, owner: str, destination: str, private: bool = False) -> dict:
    if not isinstance(grants, list):
        raise ValueError("credential grants are missing")
    matches = [item for item in grants if isinstance(item, dict)
               and item.get("node") == node and item.get("owner") == owner
               and item.get("destination") == destination]
    if len(matches) != 1:
        raise ValueError("required identity proxy credential grant is missing or ambiguous")
    item = matches[0]
    source = item.get("source_path")
    mode = item.get("mode")
    disallowed_mode = 0o077 if private else 0o022
    if (not isinstance(source, str) or not PurePosixPath(source).is_absolute()
            or not isinstance(mode, int) or mode & disallowed_mode):
        raise ValueError("identity proxy credential grant is not protected")
    return item


def resolved_role_config(topology, node, credential_material):
    """Return complete Ansible variables without enabling flags or secret values.

    The manifest must place the proxy and select one login from its explicit
    personal-device allowlist. This function never invents either identity.
    """
    try:
        if node != NODE:
            raise ValueError("identity proxy is placed only on trixie")
        if credential_material["run_id"] != topology["run_id"]:
            raise ValueError("credential material is not bound to this run")

        provider = topology["providers"][PROVIDER]
        if provider.get("kind") != "role" or provider.get("role") != "identity_proxy":
            raise ValueError("identity proxy role provider is not explicitly declared")
        host = topology["hosts"][node]
        if PROVIDER not in host["services"] or "dashboard" not in host["services"]:
            raise ValueError("identity proxy and dashboard must be explicitly co-located")
        owner = host["owners"][PROVIDER]
        if owner != OWNER or host["owners"].get("dashboard") != owner:
            raise ValueError("identity proxy must use the declared trixie lmeui owner")
        owner_identity = host["owner_identities"][owner]
        uid, gid = owner_identity["uid"], owner_identity["gid"]
        if (type(uid) is not int or type(gid) is not int or uid < 1 or gid < 1
                or owner_identity.get("data") != f"/data/{owner}"):
            raise ValueError("identity proxy owner runtime identity is incomplete")

        identity = topology["identity"]
        login = _personal_login(identity["operator_login"])
        allowed = identity["operator_logins"]
        if (not isinstance(allowed, list) or not allowed
                or len({_personal_login(item).casefold() for item in allowed}) != len(allowed)
                or login.casefold() not in {item.casefold() for item in allowed}):
            raise ValueError("operator login is not in the manifest personal identity allowlist")

        fqdn = host["fqdn"]
        if not isinstance(fqdn, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.ts\.net", fqdn):
            raise ValueError("identity proxy requires the resolved trixie tailnet FQDN")
        _grant(credential_material["grants"], node=node, owner=owner, destination=BACKEND_KEY, private=True)
        _grant(credential_material["grants"], node=node, owner=owner, destination=BACKEND_CA)
        denied_owner = host["owners"]["otel-collector"]
        if denied_owner == owner or denied_owner not in host["owner_identities"]:
            raise ValueError("identity proxy cross-owner acceptance identity is unavailable")

        acceptance = {
            "node": node,
            "owner": owner,
            "denied_owner": denied_owner,
            "backend": "https://127.0.0.1:8502",
            "ca_file": BACKEND_CA,
            "api_key_file": BACKEND_KEY,
            "operator_file": "/etc/lme/identity/operator-login",
            "public_origin": f"https://{fqdn}",
            "capability": CAPABILITY,
            "socket": "/run/lme-identity/proxy.sock",
        }

        return {
            "identity_proxy_user": owner,
            "identity_proxy_group": owner,
            "identity_proxy_expected_uid": uid,
            "identity_proxy_expected_gid": gid,
            "identity_proxy_socket": "/run/lme-identity/proxy.sock",
            "identity_proxy_backend_url": "https://127.0.0.1:8502",
            "identity_proxy_backend_ca_file": BACKEND_CA,
            "identity_proxy_backend_api_key_source_file": BACKEND_KEY,
            "identity_proxy_backend_api_key_file": "/run/credentials/lme-identity-proxy.service/webui-api-key",
            "identity_proxy_operator_login": login,
            "identity_proxy_operator_login_file": "/etc/lme/identity/operator-login",
            "identity_proxy_required_capability": CAPABILITY,
            "identity_proxy_public_origin": f"https://{fqdn}",
            "identity_proxy_serve_port": 443,
            "identity_proxy_acceptance": acceptance,
        }
    except (KeyError, TypeError) as error:
        raise ValueError("resolved identity proxy contract is incomplete: " + str(error)) from None
