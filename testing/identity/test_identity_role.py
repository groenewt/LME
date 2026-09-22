from pathlib import Path


ROLE = Path("ansible/roles/identity_proxy")


def test_role_runs_proxy_on_private_unix_socket_with_no_tcp_listener():
    unit = (ROLE / "templates/lme-identity-proxy.service.j2").read_text(encoding="utf-8")
    assert "--uds" in unit
    assert "--host" not in unit
    assert "--port" not in unit
    tasks = (ROLE / "tasks/main.yml").read_text(encoding="utf-8")
    assert "mode: '0660'" in tasks
    assert "identity_proxy_group" in tasks
    assert "ansible.builtin.getent" in tasks
    assert "identity_proxy_expected_uid" in tasks
    assert "identity_proxy_expected_gid" in tasks
    assert "ansible.builtin.user" not in tasks
    assert "ansible.builtin.group" not in tasks


def test_role_reads_backend_key_from_credential_file_and_configures_serve_to_socket():
    defaults = (ROLE / "defaults/main.yml").read_text(encoding="utf-8")
    unit = (ROLE / "templates/lme-identity-proxy.service.j2").read_text(encoding="utf-8")
    serve = (ROLE / "templates/lme-identity-serve.service.j2").read_text(encoding="utf-8")
    assert "identity_proxy_backend_api_key_file" in defaults
    assert "identity_proxy_backend_api_key_source_file" in defaults
    assert "LME_BACKEND_API_KEY_FILE" in unit
    assert "LoadCredential=webui-api-key:" in unit
    assert "unix:" in serve
    assert "tailscale serve" in serve
    assert "--accept-app-caps={{ identity_proxy_required_capability }}" in serve
    assert "--https={{ identity_proxy_serve_port }} off" in serve
    assert "reset" not in serve


def test_role_installs_proxy_runtime_and_configures_verified_backend_tls():
    defaults = (ROLE / "defaults/main.yml").read_text(encoding="utf-8")
    tasks = (ROLE / "tasks/main.yml").read_text(encoding="utf-8")
    unit = (ROLE / "templates/lme-identity-proxy.service.j2").read_text(encoding="utf-8")
    assert "identity_proxy_source_dir" in defaults
    assert "identity_proxy_backend_ca_file" in defaults
    assert "lme_identity" in tasks
    assert "requirements.txt" in tasks
    assert "LME_BACKEND_CA_FILE" in unit
    assert "LME_PUBLIC_ORIGIN" in unit
    assert "identity_proxy_public_origin" in tasks
    assert "identity_proxy_operator_login" in tasks
    assert "mode: preserve" not in tasks
    assert "- proxy.py" in tasks
    assert "- config.py" in tasks
    assert "state: restarted" in tasks
    assert "UMask=0117" in unit


def test_identity_runtime_units_fit_provider_budget_and_keep_owner_boundary():
    proxy = (ROLE / "templates/lme-identity-proxy.service.j2").read_text(encoding="utf-8")
    serve = (ROLE / "templates/lme-identity-serve.service.j2").read_text(encoding="utf-8")
    assert "User={{ identity_proxy_user }}" in proxy
    assert "Group={{ identity_proxy_group }}" in proxy
    assert "MemoryHigh=192M" in proxy
    assert "MemoryMax=224M" in proxy
    assert "User=" not in serve
    assert "Type=oneshot" in serve
    assert "RemainAfterExit=true" in serve
    assert "MemoryHigh=24M" in serve
    assert "MemoryMax=32M" in serve
