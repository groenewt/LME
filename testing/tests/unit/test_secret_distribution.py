"""Behavioral regression tests for host-scoped, redacted secret distribution.

The suite invokes the real Ansible task files with the default stdout callback and
an enabled aggregate callback.  The Podman boundary is synthetic; all task flow,
fact scoping, callback redaction, failure handling, and rerun behavior are real.
"""

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURE = Path(__file__).parent / "fixtures" / "secret_distribution"
ANSIBLE_PLAYBOOK = shutil.which("ansible-playbook")

pytestmark = pytest.mark.skipif(
    ANSIBLE_PLAYBOOK is None, reason="ansible-playbook is required for callback coverage"
)

CANARY = "LME_SYNTHETIC_CANARY_9f8f9ba7_DO_NOT_LOG"


def _service(service_id, secrets):
    return {
        "id": service_id,
        "name": service_id,
        "kind": "container",
        "secrets": [{"name": name, "type": "env", "target": name.upper()} for name in secrets],
    }


def _inventory(host_services):
    hosts = {
        "producer": {"ansible_connection": "local"},
    }
    for hostname, services in host_services.items():
        hosts[hostname] = {
            "ansible_connection": "local",
            "lme_host_services": list(services),
        }
    return {
        "all": {
            "hosts": hosts,
            "children": {"consumers": {"hosts": {name: {} for name in host_services}}},
        }
    }


def _ansible_config(tmp_path):
    config = tmp_path / "ansible.cfg"
    config.write_text(
        "\n".join(
            [
                "[defaults]",
                "stdout_callback = default",
                "callbacks_enabled = lme_capture",
                "callback_plugins = %s" % (FIXTURE / "callback_plugins"),
                "filter_plugins = %s"
                % (REPO_ROOT / "ansible" / "roles" / "podman" / "filter_plugins"),
                "roles_path = %s" % (REPO_ROOT / "ansible" / "roles"),
                "display_args_to_stdout = True",
                "retry_files_enabled = False",
                "log_path = %s" % (tmp_path / "ansible.log"),
                "local_tmp = %s" % (tmp_path / "local-tmp"),
                "remote_tmp = %s" % (tmp_path / "remote-tmp"),
                "interpreter_python = auto_silent",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return config


def _run_ansible(
    tmp_path,
    host_services,
    services,
    roster,
    *,
    playbook="distribute.yml",
    active=False,
    start_at_task=None,
):
    inventory = tmp_path / "inventory.yml"
    inventory.write_text(yaml.safe_dump(_inventory(host_services)), encoding="utf-8")
    callback_log = tmp_path / "callback.jsonl"
    callback_log.touch(exist_ok=True)
    fake_root = tmp_path / "podman"
    fake_root.mkdir(exist_ok=True)
    (fake_root / "error-canary").write_text(CANARY, encoding="utf-8")
    extra = {
        "lme_repo_root": str(REPO_ROOT),
        "lme_fixture_bin": str(FIXTURE / "bin"),
        "lme_fake_podman_root": str(fake_root),
        "lme_fake_service_active": "1" if active else "0",
        "lme_services": services,
        "lme_enable_flags": {},
        "lme_secrets_source_host": "producer",
        "lme_distribute_secrets": True,
        "lme_cross_host_file_secrets": roster,
        "lme_known_password_secrets": ["elastic", "kibana_system", "wazuh", "wazuh_api"],
        "lme_secrets_deferred": ["pgvector", "llm-keys", "litellm_master_key", "webui_api_key"],
        "lme_secret_distribution_become": False,
    }
    env = os.environ.copy()
    env.update(
        {
            "ANSIBLE_CONFIG": str(_ansible_config(tmp_path)),
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local-tmp"),
            "ANSIBLE_REMOTE_TEMP": str(tmp_path / "remote-tmp"),
            "ANSIBLE_NOCOLOR": "1",
            "HOME": str(tmp_path / "home"),
            "LME_CALLBACK_LOG": str(callback_log),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    (tmp_path / "home").mkdir(exist_ok=True)
    command = [
        ANSIBLE_PLAYBOOK,
        "-vvv",
        "-i",
        str(inventory),
        str(FIXTURE / playbook),
        "--extra-vars",
        json.dumps(extra),
    ]
    if start_at_task:
        command.extend(["--start-at-task", start_at_task])
    completed = subprocess.run(
        command,
        cwd=REPO_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    artifacts = completed.stdout + completed.stderr
    for path in (tmp_path / "ansible.log", callback_log):
        if path.exists():
            artifacts += "\n" + path.read_text(encoding="utf-8", errors="replace")
    return completed, artifacts, fake_root


def _put_secret(root, host, name, payload):
    path = root / host / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


@pytest.mark.parametrize(
    "failure,expected_code",
    [
        ("malformed", "malformed-multiline"),
        ("absent", "source-absent"),
        ("permission-denied", "source-permission-denied"),
    ],
)
def test_verbose_failure_callbacks_never_expose_synthetic_canary(tmp_path, failure, expected_code):
    secret_name = "ui_api_key"
    services = {"ui": _service("ui", [secret_name])}
    fake_root = tmp_path / "podman"
    if failure == "malformed":
        _put_secret(fake_root, "producer", secret_name, CANARY + "\nsecond-line")
    elif failure == "permission-denied":
        _put_secret(fake_root, "producer", secret_name + ".error", "permission-denied")

    completed, artifacts, _ = _run_ansible(
        tmp_path, {"consumer-a": ["ui"]}, services, [secret_name]
    )

    assert completed.returncode != 0
    assert expected_code in artifacts
    encoded_forms = {
        CANARY,
        base64.b64encode(CANARY.encode()).decode(),
        base64.urlsafe_b64encode(CANARY.encode()).decode(),
        json.dumps(CANARY)[1:-1],
    }
    assert not encoded_forms.intersection(artifacts.split())
    for encoded in encoded_forms:
        assert encoded not in artifacts
    assert "consumer-a" in artifacts
    assert secret_name in artifacts
    assert "source-read" in artifacts


def test_valid_four_secret_consumer_inventory_is_host_scoped_and_rotates_in_place(tmp_path):
    services = {
        "ui": _service(
            "ui", ["elastic", "pgvector", "litellm_master_key", "webui_api_key"]
        ),
        "metrics": _service("metrics", ["elastic"]),
    }
    host_services = {"consumer-a": ["ui"], "consumer-b": ["metrics"]}
    roster = ["elastic", "pgvector", "litellm_master_key", "webui_api_key"]
    fake_root = tmp_path / "podman"
    values = {
        "elastic": "elastic-synthetic-value",
        "pgvector": "pgvector-synthetic-value",
        "litellm_master_key": "litellm-synthetic-value",
        "webui_api_key": "webui-synthetic-value-v1",
    }
    for name, value in values.items():
        _put_secret(fake_root, "producer", name, value)

    first, first_artifacts, root = _run_ansible(
        tmp_path, host_services, services, roster, playbook="role.yml"
    )
    assert first.returncode == 0, first_artifacts
    for payload in values.values():
        assert payload not in first_artifacts
        assert base64.b64encode(payload.encode()).decode() not in first_artifacts
    assert (root / "consumer-a" / "elastic").read_text() == values["elastic"]
    assert (root / "consumer-a" / "pgvector").read_text() == values["pgvector"]
    assert (root / "consumer-a" / "litellm_master_key").read_text() == values["litellm_master_key"]
    assert (root / "consumer-a" / "webui_api_key").read_text() == values["webui_api_key"]
    assert (root / "consumer-b" / "elastic").read_text() == values["elastic"]
    assert not (root / "consumer-b" / "pgvector").exists()
    assert not (root / "consumer-b" / "litellm_master_key").exists()
    assert not (root / "consumer-b" / "webui_api_key").exists()
    operations = (root / "operations.log").read_text().splitlines()
    assert len(operations) == 5

    index_sentinel = root / "consumer-a" / "secrets.json"
    index_sentinel.write_text("target-owned-index-sentinel", encoding="utf-8")

    second, second_artifacts, _ = _run_ansible(
        tmp_path, host_services, services, roster, playbook="role.yml"
    )
    assert second.returncode == 0, second_artifacts
    assert (root / "operations.log").read_text().splitlines() == operations
    assert index_sentinel.read_text() == "target-owned-index-sentinel"

    rotated = "webui-synthetic-value-v2"
    _put_secret(root, "producer", "webui_api_key", rotated)
    third, third_artifacts, _ = _run_ansible(
        tmp_path, host_services, services, roster, playbook="role.yml"
    )
    assert third.returncode == 0, third_artifacts
    assert rotated not in third_artifacts
    assert base64.b64encode(rotated.encode()).decode() not in third_artifacts
    after_rotation = (root / "operations.log").read_text().splitlines()
    assert len(after_rotation) == 6
    assert after_rotation[-1].split("|")[1:3] == ["consumer-a", "webui_api_key"]
    assert (root / "consumer-a" / "webui_api_key").read_text() == rotated
    assert not (root / "consumer-b" / "webui_api_key").exists()


def test_b3_rejects_enabled_consumer_secret_missing_from_distribution_roster(tmp_path):
    services = {
        "ui": _service(
            "ui", ["elastic", "pgvector", "litellm_master_key", "webui_api_key"]
        )
    }
    completed, artifacts, _ = _run_ansible(
        tmp_path,
        {"consumer-a": ["ui"]},
        services,
        ["elastic", "pgvector", "litellm_master_key"],
        playbook="b3.yml",
        start_at_task="Reset required-secret accumulator",
    )

    assert completed.returncode != 0
    assert "B3 guard -- every enabled-service secret has a creation recipe" in artifacts
    assert "webui_api_key" in artifacts
    assert "No rendered unit may reference an uncreated secret (B3)" in artifacts


def test_cluster_distribution_hands_verified_global_secrets_to_postconfig_without_bundle(tmp_path):
    services = {"elasticsearch": _service("elasticsearch", ["elastic", "kibana_system"])}
    values = {
        "elastic": CANARY + "_elastic",
        "kibana_system": CANARY + "_kibana",
    }
    fake_root = tmp_path / "podman"
    for name, value in values.items():
        _put_secret(fake_root, "producer", name, value)

    completed, artifacts, root = _run_ansible(
        tmp_path,
        {"cluster-consumer": ["elasticsearch"]},
        services,
        ["elastic", "kibana_system"],
        playbook="handoff.yml",
    )

    assert completed.returncode == 0, artifacts
    assert "postconfig-authenticated" in artifacts
    assert (root / "postconfig.log").read_text() == (
        "authenticated|cluster-consumer|elastic,kibana_system\n"
    )
    assert not (root / "cluster-consumer" / "secrets.json").exists()
    for payload in values.values():
        assert payload not in artifacts
        assert base64.b64encode(payload.encode()).decode() not in artifacts


def test_target_payload_mismatch_blocks_activation_with_sanitized_diagnostic(tmp_path):
    services = {"ui": _service("ui", ["webui_api_key"])}
    payload = CANARY + "_target-readback"
    fake_root = tmp_path / "podman"
    _put_secret(fake_root, "producer", "webui_api_key", payload)
    _put_secret(fake_root, "consumer-a", "webui_api_key.corrupt-create", "armed")

    completed, artifacts, _ = _run_ansible(
        tmp_path,
        {"consumer-a": ["ui"]},
        services,
        ["webui_api_key"],
    )

    assert completed.returncode != 0
    assert "target-value-mismatch" in artifacts
    assert "stage" in artifacts and "target-readback" in artifacts
    assert payload not in artifacts
    assert base64.b64encode(payload.encode()).decode() not in artifacts


def test_active_consumer_blocks_secret_reconfiguration_before_any_write(tmp_path):
    services = {"ui": _service("ui", ["webui_api_key"])}
    fake_root = tmp_path / "podman"
    _put_secret(fake_root, "producer", "webui_api_key", "synthetic-value")

    completed, artifacts, root = _run_ansible(
        tmp_path,
        {"consumer-a": ["ui"]},
        services,
        ["webui_api_key"],
        playbook="role.yml",
        active=True,
    )

    assert completed.returncode != 0
    assert "secret-reconfiguration-active" in artifacts
    assert "consumer-a" in artifacts
    assert not (root / "operations.log").exists()


def test_fleet_debug_mode_cannot_disable_secret_redaction_or_print_secret_facts():
    tasks = (REPO_ROOT / "ansible/roles/fleet/tasks/main.yml").read_text()
    assert 'no_log: "{{ not debug_mode }}"' not in tasks
    assert "no_log: '{{ not debug_mode }}'" not in tasks
    for name in ("elastic_password", "wazuh_password", "kibana_system_password", "wazuh_api_password"):
        assert f'"{name.replace("_password", "")}={{{{ {name} }}}}"' not in tasks
    first = yaml.safe_load(tasks)[0]
    assert first["ansible.builtin.set_fact"]["elastic_password"] == "{{ global_secrets.elastic | default('') }}"
    assert first["no_log"] is True
    assert first["diff"] is False
