import json
from pathlib import Path

import pytest

from lme_identity.proxy import IdentityPolicy, ProxyConfiguration, forwarded_scheme, prepare_backend_headers


def policy(tmp_path: Path) -> IdentityPolicy:
    operator = tmp_path / "operator-login"
    operator.write_text("operator@example.test\n", encoding="utf-8")
    return IdentityPolicy(operator_login_file=operator, required_capability="cisa.gov/cap/lme-observer")


def test_proxy_requires_operator_and_personal_capability(tmp_path):
    p = policy(tmp_path)
    headers = {
        "tailscale-user-login": "operator@example.test",
        "tailscale-app-capabilities": json.dumps({"cisa.gov/cap/lme-observer": [{"role": "operator"}]}),
    }
    assert p.authorize(headers).login == "operator@example.test"


def test_tagged_personal_device_without_user_login_uses_trusted_operator_capability(tmp_path):
    headers = {
        "tailscale-app-capabilities": json.dumps({
            "cisa.gov/cap/lme-observer": [{"role": "operator"}],
        }),
    }
    assert policy(tmp_path).authorize(headers).login == "capability-operator"


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"tailscale-user-login": "operator@example.test"},
        {
            "tailscale-user-login": "other@example.test",
            "tailscale-app-capabilities": json.dumps({"cisa.gov/cap/lme-observer": [{"role": "operator"}]}),
        },
        {
            "tailscale-user-login": "operator@example.test",
            "tailscale-app-capabilities": "not-json",
        },
        {"tailscale-app-capabilities": json.dumps({"cisa.gov/cap/lme-observer": []})},
        {"tailscale-app-capabilities": json.dumps({"cisa.gov/cap/lme-observer": [{}]})},
        {"tailscale-app-capabilities": json.dumps({"cisa.gov/cap/lme-observer": [{"role": "viewer"}]})},
    ],
)
def test_proxy_fails_closed_for_missing_capability_or_cross_owner(headers, tmp_path):
    with pytest.raises(PermissionError):
        policy(tmp_path).authorize(headers)


def test_proxy_strips_forged_credentials_and_identity_then_injects_file_key(tmp_path):
    secret = tmp_path / "webui-api-key"
    secret.write_text("backend-only-key\n", encoding="utf-8")
    secret.chmod(0o600)
    config = ProxyConfiguration(backend_api_key_file=secret)
    incoming = {
        "authorization": "Bearer forged",
        "x-api-key": "forged",
        "tailscale-user-login": "forged@example.test",
        "tailscale-app-capabilities": "forged",
        "x-lme-identity": "forged",
        "sec-websocket-key": "caller-handshake-key",
        "cookie": "session=caller-controlled",
        "x-authenticated-user": "forged-extension",
        "accept": "text/event-stream",
    }
    result = prepare_backend_headers(incoming, config, identity_login="operator@example.test")
    assert result["x-api-key"] == "backend-only-key"
    assert result["x-lme-authenticated-login"] == "operator@example.test"
    assert result["accept"] == "text/event-stream"
    assert "authorization" not in result
    assert "tailscale-user-login" not in result
    assert "tailscale-app-capabilities" not in result
    assert "x-lme-identity" not in result
    assert "sec-websocket-key" not in result
    assert "cookie" not in result
    assert "x-authenticated-user" not in result


def test_proxy_key_file_is_required_and_must_not_be_group_or_world_readable(tmp_path):
    missing = tmp_path / "missing"
    with pytest.raises(RuntimeError):
        ProxyConfiguration(backend_api_key_file=missing).backend_api_key()

    secret = tmp_path / "key"
    secret.write_text("secret", encoding="utf-8")
    secret.chmod(0o640)
    with pytest.raises(RuntimeError):
        ProxyConfiguration(backend_api_key_file=secret).backend_api_key()


def test_https_backend_requires_a_ca_file(tmp_path):
    secret = tmp_path / "key"
    secret.write_text("secret", encoding="utf-8")
    secret.chmod(0o600)
    config = ProxyConfiguration(backend_api_key_file=secret, backend_url="https://dashboard.internal:8502")
    with pytest.raises(RuntimeError):
        config.backend_tls_verify()


def test_plain_http_backend_is_rejected_even_with_private_socket(tmp_path):
    secret = tmp_path / "key"
    secret.write_text("secret", encoding="utf-8")
    secret.chmod(0o600)
    config = ProxyConfiguration(backend_api_key_file=secret, backend_url="http://127.0.0.1:8502")
    with pytest.raises(RuntimeError):
        config.backend_tls_verify()


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_mutations_require_same_origin(method, tmp_path):
    p = policy(tmp_path)
    with pytest.raises(PermissionError):
        p.require_same_origin(method, {"origin": "https://evil.test", "host": "lme.test"}, "https")
    p.require_same_origin(method, {"origin": "https://lme.test", "host": "lme.test"}, "https")


def test_serve_forwarded_https_scheme_is_used_for_origin_validation():
    assert forwarded_scheme({"X-Forwarded-Proto": "https"}, "http") == "https"


def test_direct_automation_api_key_boundary_is_not_implemented_by_proxy():
    source = Path("lme_identity/proxy.py").read_text(encoding="utf-8")
    assert "direct_api_key" not in source
    assert "WEBUI_API_KEY" not in source
    dashboard = Path("lme-dashboard/app.py").read_text(encoding="utf-8")
    assert 'request.url.path.startswith("/api/")' in dashboard
    assert 'request.headers.get("x-api-key")' in dashboard
    assert 'request.headers.get("authorization", "")' in dashboard
    assert "hmac.compare_digest" in dashboard
