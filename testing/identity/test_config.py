import copy

import pytest

from lme_identity.config import resolved_role_config


def fixture():
    owner = "lmeui"
    topology = {
        "run_id": "fixture",
        "identity": {
            "operator_login": "operator@example.org",
            "operator_logins": ["operator@example.org"],
        },
        "providers": {
            "identity-proxy": {
                "kind": "role",
                "role": "identity_proxy",
                "memory_mib": 128,
            }
        },
        "hosts": {
            "trixie": {
                "fqdn": "lme-e2e-fixture-trixie.example.ts.net",
                "services": ["dashboard", "identity-proxy"],
                "owner_identities": {
                    owner: {"uid": 2207, "gid": 2207, "home": "/home/lmeui", "data": "/data/lmeui"},
                    "lmetelemetry": {"uid": 2210, "gid": 2210, "home": "/home/lmetelemetry", "data": "/data/lmetelemetry"},
                },
                "owners": {"dashboard": owner, "identity-proxy": owner, "otel-collector": "lmetelemetry"},
                "resolved_services": {"dashboard": {}},
            }
        },
    }
    credential = {
        "run_id": "fixture",
        "grants": [
            {
                "node": "trixie",
                "owner": owner,
                "source_path": "/controller/webui-api-key",
                "destination": "/data/lmeui/secrets/webui_api_key",
                "mode": 0o600,
            },
            {
                "node": "trixie",
                "owner": owner,
                "source_path": "/controller/application-ca.crt",
                "destination": "/data/lmeui/config/certs/dashboard/ca/ca.crt",
                "mode": 0o644,
            },
        ],
    }
    return topology, credential


def test_factory_derives_complete_role_vars_without_enable_flag_or_secret_value():
    topology, credential = fixture()
    result = resolved_role_config(topology, "trixie", credential)

    assert result["identity_proxy_user"] == "lmeui"
    assert result["identity_proxy_expected_uid"] == 2207
    assert result["identity_proxy_backend_url"] == "https://127.0.0.1:8502"
    assert result["identity_proxy_backend_api_key_source_file"] == "/data/lmeui/secrets/webui_api_key"
    assert result["identity_proxy_backend_ca_file"] == "/data/lmeui/config/certs/dashboard/ca/ca.crt"
    assert result["identity_proxy_public_origin"] == "https://lme-e2e-fixture-trixie.example.ts.net"
    assert result["identity_proxy_required_capability"] == "cisa.gov/cap/lme-observer"
    assert result["identity_proxy_operator_login"] == "operator@example.org"
    assert result["identity_proxy_acceptance"] == {
        "node": "trixie", "owner": "lmeui", "denied_owner": "lmetelemetry",
        "backend": "https://127.0.0.1:8502",
        "ca_file": "/data/lmeui/config/certs/dashboard/ca/ca.crt",
        "api_key_file": "/data/lmeui/secrets/webui_api_key",
        "operator_file": "/etc/lme/identity/operator-login",
        "public_origin": "https://lme-e2e-fixture-trixie.example.ts.net",
        "capability": "cisa.gov/cap/lme-observer",
        "socket": "/run/lme-identity/proxy.sock",
    }
    assert all("enable" not in key and "apply" not in key for key in result)
    assert "secret" not in repr(result).lower().replace("secrets/", "")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda topology, credential: topology["providers"].pop("identity-proxy"),
        lambda topology, credential: topology["hosts"]["trixie"]["owners"].pop("identity-proxy"),
        lambda topology, credential: topology["hosts"]["trixie"]["owner_identities"].pop("lmeui"),
        lambda topology, credential: topology["identity"].update(operator_login="invented@example.org"),
        lambda topology, credential: credential["grants"].pop(0),
    ],
)
def test_factory_fails_closed_for_missing_inventory_identity_or_key_grant(mutation):
    topology, credential = fixture()
    mutation(topology, credential)
    with pytest.raises(ValueError):
        resolved_role_config(topology, "trixie", credential)


def test_factory_rejects_wrong_node_run_owner_or_public_identity():
    topology, credential = fixture()
    with pytest.raises(ValueError):
        resolved_role_config(topology, "graph", credential)
    wrong = copy.deepcopy(credential)
    wrong["run_id"] = "another-run"
    with pytest.raises(ValueError):
        resolved_role_config(topology, "trixie", wrong)
    topology["hosts"]["trixie"]["owners"]["identity-proxy"] = "lmeother"
    with pytest.raises(ValueError):
        resolved_role_config(topology, "trixie", credential)


def test_factory_rejects_world_or_group_readable_backend_key_grant():
    topology, credential = fixture()
    credential["grants"][0]["mode"] = 0o644
    with pytest.raises(ValueError):
        resolved_role_config(topology, "trixie", credential)
