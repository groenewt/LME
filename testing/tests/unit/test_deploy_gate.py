import json
import hashlib
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
GATE = ROOT / "testing/e2e/deploy_gate.sh"
FIXTURES = Path(__file__).with_name("fixtures") / "deploy_gate"


def bash(script: str, *, env=None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update({key: str(value) for key, value in env.items()})
    return subprocess.run(
        ["bash", "-c", script],
        cwd=ROOT,
        env=merged,
        text=True,
        capture_output=True,
        check=False,
    )


def source_prelude() -> str:
    return f"source {GATE!s}\n"


def gate_results(output: str) -> list[dict]:
    return [
        json.loads(line.removeprefix("GATE_RESULT "))
        for line in output.splitlines()
        if line.startswith("GATE_RESULT ")
    ]


def make_fake(tmp_path: Path, name: str, body: str) -> Path:
    fake = tmp_path / name
    fake.write_text("#!/usr/bin/env bash\n" + body)
    fake.chmod(0o755)
    return fake






def test_http_failure_normalizes_curl_000_once(tmp_path):
    make_fake(tmp_path, "curl", "printf 000\nexit 7\n")
    result = bash(
        source_prelude()
        + "eval \"$(remote_http_helper)\"\n"
        + "set +e\n"
        + "code=$(gate_http_code https://unreachable.invalid)\n"
        + "rc=$?\n"
        + "printf 'code=%s rc=%s\\n' \"$code\" \"$rc\"\n"
        + "exit 0\n",
        env={"PATH": f"{tmp_path}:{os.environ['PATH']}"},
    )
    assert result.returncode == 0, result.stderr
    assert "code=000 rc=7" in result.stdout
    assert "000000" not in result.stdout


def test_required_vip_probe_with_zero_endpoints_is_blocked(tmp_path):
    result = bash(
        source_prelude()
        + f"LOG={tmp_path / 'gate.log'}\nRESULTS={tmp_path / 'results.jsonl'}\n"
        + f"SRC={FIXTURES!s}\n"
        + "HOST=producer\nFLAGS='--profile tailscale --no-llm'\nEXTRA_VARS=''\n"
        + "export LME_GATE_REQUIRE_VIP_REACHABLE=true LME_GATE_PROBE_FROM=consumer\n"
        + "set +e\ndo_vip_probe\nrc=$?\nprintf 'rc=%s\\n' \"$rc\"\nexit 0\n"
    )
    assert "rc=1" in result.stdout
    record = gate_results(result.stdout)[-1]
    assert record == {
        "check": "vip_reachability",
        "required": True,
        "applicable": True,
        "executed": False,
        "status": "BLOCKED",
        "evidence": "none",
        "reason": "selected_route_has_no_endpoints",
    }


def test_required_vip_probe_cannot_be_disabled(tmp_path):
    result = bash(
        source_prelude()
        + f"LOG={tmp_path / 'gate.log'}\nRESULTS={tmp_path / 'results.jsonl'}\n"
        + f"SRC={FIXTURES!s}\n"
        + "HOST=producer\nFLAGS='--profile tailscale'\nEXTRA_VARS=''\n"
        + "export LME_GATE_REQUIRE_VIP_REACHABLE=1\n"
        + "unset LME_GATE_PROBE_FROM\n"
        + "set +e\ndo_vip_probe\nrc=$?\nprintf 'rc=%s\\n' \"$rc\"\nexit 0\n"
    )
    assert "rc=1" in result.stdout
    record = gate_results(result.stdout)[-1]
    assert record["required"] is True
    assert record["applicable"] is True
    assert record["executed"] is False
    assert record["status"] == "BLOCKED"
    assert record["reason"] == "probe_from_required"


def test_required_vip_probe_rejects_disabled_route(tmp_path):
    result = bash(
        source_prelude()
        + f"LOG={tmp_path / 'gate.log'}\nRESULTS={tmp_path / 'results.jsonl'}\n"
        + f"SRC={FIXTURES!s}\n"
        + "HOST=producer\nFLAGS='--profile default'\nEXTRA_VARS=''\n"
        + "export LME_GATE_REQUIRE_VIP_REACHABLE=1 LME_GATE_PROBE_FROM=consumer\n"
        + "set +e\ndo_vip_probe\nrc=$?\nprintf 'rc=%s\\n' \"$rc\"\nexit 0\n"
    )
    assert "rc=1" in result.stdout
    record = gate_results(result.stdout)[-1]
    assert record == {
        "check": "vip_reachability",
        "required": True,
        "applicable": False,
        "executed": False,
        "status": "BLOCKED",
        "evidence": "none",
        "reason": "required_vip_route_not_selected",
    }


def test_unselected_vip_route_is_explicitly_not_applicable(tmp_path):
    result = bash(
        source_prelude()
        + f"LOG={tmp_path / 'gate.log'}\nRESULTS={tmp_path / 'results.jsonl'}\n"
        + f"SRC={FIXTURES!s}\n"
        + "HOST=producer\nFLAGS='--profile default'\nEXTRA_VARS=''\n"
        + "unset LME_GATE_REQUIRE_VIP_REACHABLE LME_GATE_PROBE_FROM\n"
        + "do_vip_probe\n"
    )
    assert result.returncode == 0, result.stderr
    record = gate_results(result.stdout)[-1]
    assert record["required"] is False
    assert record["applicable"] is False
    assert record["executed"] is False
    assert record["status"] == "NOT_APPLICABLE"
    assert record["reason"] == "vip_route_not_selected"


def test_invalid_required_boolean_fails_before_network(tmp_path):
    result = bash(
        source_prelude()
        + f"LOG={tmp_path / 'gate.log'}\nRESULTS={tmp_path / 'results.jsonl'}\n"
        + f"SRC={FIXTURES!s}\n"
        + "HOST=producer\nFLAGS='--profile tailscale'\nEXTRA_VARS=''\n"
        + "ssh() { echo NETWORK_CALLED; return 0; }\n"
        + "export LME_GATE_REQUIRE_VIP_REACHABLE=perhaps LME_GATE_PROBE_FROM=consumer\n"
        + "set +e\ndo_vip_probe\nrc=$?\nprintf 'rc=%s\\n' \"$rc\"\nexit 0\n"
    )
    assert "rc=2" in result.stdout
    assert "NETWORK_CALLED" not in result.stdout
    record = gate_results(result.stdout)[-1]
    assert record["status"] == "FAIL"
    assert record["executed"] is False
    assert record["reason"] == "invalid_required_boolean"


def test_invalid_derived_vip_endpoint_fails_before_network(tmp_path):
    result = bash(
        source_prelude()
        + f"LOG={tmp_path / 'gate.log'}\nRESULTS={tmp_path / 'results.jsonl'}\n"
        + f"SRC={FIXTURES.parent / 'deploy_gate_invalid'!s}\n"
        + "HOST=producer\nFLAGS='--profile tailscale'\nEXTRA_VARS=''\n"
        + "ssh() { echo NETWORK_CALLED; return 0; }\n"
        + "export LME_GATE_REQUIRE_VIP_REACHABLE=1 LME_GATE_PROBE_FROM=consumer\n"
        + "set +e\ndo_vip_probe\nrc=$?\nprintf 'rc=%s\\n' \"$rc\"\nexit 0\n"
    )
    assert "rc=2" in result.stdout
    assert "NETWORK_CALLED" not in result.stdout
    record = gate_results(result.stdout)[-1]
    assert record["required"] is True
    assert record["applicable"] is True
    assert record["executed"] is False
    assert record["status"] == "FAIL"
    assert record["reason"] == "invalid_endpoint_contract"


def _vip_fake_ssh(tmp_path: Path, curl_body: str):
    make_fake(tmp_path, "curl", curl_body)
    make_fake(
        tmp_path,
        "ssh",
        "payload=$(cat)\n"
        + "VIP_ENDPOINTS=lme-route:9443:https DOMAIN='' TIMEOUT=15 bash -s <<<\"$payload\"\n",
    )


def test_required_vip_probe_executes_remote_payload_and_records_pass(tmp_path):
    _vip_fake_ssh(tmp_path, "printf 503\nexit 0\n")
    result = bash(
        source_prelude()
        + f"LOG={tmp_path / 'gate.log'}\nRESULTS={tmp_path / 'results.jsonl'}\n"
        + f"SRC={FIXTURES!s}\n"
        + "HOST=producer\nFLAGS='--profile tailscale'\nEXTRA_VARS=''\n"
        + "export LME_GATE_REQUIRE_VIP_REACHABLE=1 LME_GATE_PROBE_FROM=consumer\n"
        + "do_vip_probe\n",
        env={"PATH": f"{tmp_path}:{os.environ['PATH']}"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "HTTP 503" in result.stdout
    record = gate_results(result.stdout)[-1]
    assert record["required"] is True
    assert record["applicable"] is True
    assert record["executed"] is True
    assert record["status"] == "PASS"


def test_required_vip_probe_transport_failure_records_fail_once(tmp_path):
    _vip_fake_ssh(tmp_path, "printf 000\nexit 7\n")
    result = bash(
        source_prelude()
        + f"LOG={tmp_path / 'gate.log'}\nRESULTS={tmp_path / 'results.jsonl'}\n"
        + f"SRC={FIXTURES!s}\n"
        + "HOST=producer\nFLAGS='--profile tailscale'\nEXTRA_VARS=''\n"
        + "export LME_GATE_REQUIRE_VIP_REACHABLE=1 LME_GATE_PROBE_FROM=consumer\n"
        + "set +e\ndo_vip_probe\nrc=$?\nprintf 'rc=%s\\n' \"$rc\"\nexit 0\n",
        env={"PATH": f"{tmp_path}:{os.environ['PATH']}"},
    )
    assert "rc=1" in result.stdout
    assert "000000" not in result.stdout
    assert "UNREACHABLE" in result.stdout
    record = gate_results(result.stdout)[-1]
    assert record["executed"] is True
    assert record["status"] == "FAIL"
    assert record["reason"] == "endpoint_unreachable"


def test_runtime_roster_separates_exact_owned_persistent_and_init_jobs():
    result = bash(
        source_prelude()
        + f"SRC={FIXTURES!s}\n"
        + f"derive_host_runtime_rosters {FIXTURES / 'host_vars/owned.yml'} 0 0 0\n"
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "persistent\ttelemetry\tlme-persistent",
        "init\ttelemetry\tlme-init.service",
    ]


def _health_fake_bin(
    tmp_path: Path,
    *,
    es_code="401",
    es_exit=0,
    wide=False,
    container_name="lme-elasticsearch",
):
    make_fake(
        tmp_path,
        "systemctl",
        """
case "$1" in
  list-units) exit 0 ;;
  show) printf 'ActiveState=active\\nSubState=exited\\nResult=success\\n'; exit 0 ;;
  is-active) exit 0 ;;
esac
exit 0
""",
    )
    make_fake(
        tmp_path,
        "sudo",
        f"""
if [ "$1" = -i ]; then shift; fi
if [ "$1" = podman ]; then printf '{container_name}\\n'; exit 0; fi
exit 64
""",
    )
    addr = "0.0.0.0" if wide else "127.0.0.1"
    make_fake(
        tmp_path,
        "ss",
        f"""
case "$1" in
  -ltnH) printf 'LISTEN 0 128 {addr}:9200 0.0.0.0:*\\nLISTEN 0 128 127.0.0.1:22 0.0.0.0:*\\n' ;;
  -lunH) : ;;
esac
""",
    )
    make_fake(
        tmp_path,
        "curl",
        f"""
case "$*" in
  *127.0.0.1:9200*) printf '{es_code}'; exit {es_exit} ;;
esac
printf 000
exit 7
""",
    )


def run_health_payload(
    tmp_path: Path,
    *,
    es_local: int,
    wide=False,
    es_code="401",
    es_exit=0,
    container_name="lme-elasticsearch",
):
    _health_fake_bin(
        tmp_path,
        es_code=es_code,
        es_exit=es_exit,
        wide=wide,
        container_name=container_name,
    )
    return bash(
        source_prelude()
        + "health_remote_payload > \"$TMPDIR/health-payload.sh\"\n"
        + "bash \"$TMPDIR/health-payload.sh\"\n",
        env={
            "PATH": f"{tmp_path}:{os.environ['PATH']}",
            "TMPDIR": tmp_path,
            "EXPECT_MIN": "1",
            "EXPECTED_PERSISTENT": "root:lme-elasticsearch",
            "EXPECTED_INIT_JOBS": "",
            "LLM_ON": "0",
            "ES_LOCAL": str(es_local),
            "KIBANA_LOCAL": "0",
            "DASHBOARD_LOCAL": "0",
            "LOG_ANALYZER_LOCAL": "0",
            "LOOPBACK_PORTS": "9200",
            "LAN_OK": "",
            "PROFILE_OPEN": "",
            "PROFILE_NAME": "",
            "TAILNET_PORTS": "",
        },
    )


def test_rm3_required_reachable_branch_passes(tmp_path):
    result = run_health_payload(tmp_path, es_local=1)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ES http_code=401" in result.stdout
    assert "service: ES :9200" in result.stdout


def test_rm3_required_unreachable_branch_fails_without_000000(tmp_path):
    result = run_health_payload(tmp_path, es_local=1, es_code="000", es_exit=7)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "ES http_code=000" in result.stdout
    assert "000000" not in result.stdout
    assert "FAIL: ES not up behind TLS" in result.stdout


def test_rm3_intentionally_inapplicable_branch_does_not_connect(tmp_path):
    result = run_health_payload(tmp_path, es_local=0, es_code="401", es_exit=99)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "SKIP (not host-local" in result.stdout
    assert "ES http_code=" not in result.stdout


def test_rm3_prohibited_wide_exposure_fails_even_when_es_answers(tmp_path):
    result = run_health_payload(tmp_path, es_local=1, wide=True)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "FAIL: port 9200 LAN-open" in result.stdout
    assert "ES http_code=401" in result.stdout


def test_exact_roster_rejects_same_count_wrong_container(tmp_path):
    result = run_health_payload(tmp_path, es_local=0, container_name="wrong-container")
    assert result.returncode == 1, result.stdout + result.stderr
    assert "persistent container roster mismatch" in result.stdout
    assert "missing=root:lme-elasticsearch" in result.stdout
    assert "unexpected=root:wrong-container" in result.stdout


def test_failed_all_stage_retains_state_and_does_not_teardown(tmp_path):
    result = bash(
        source_prelude()
        + f"LOG={tmp_path / 'gate.log'}\nRESULTS={tmp_path / 'results.jsonl'}\n"
        + "do_rsync() { return 0; }\ndo_wipe() { return 0; }\ndo_install() { return 0; }\n"
        + "do_health() { return 9; }\ndo_vip_probe() { return 0; }\n"
        + "do_teardown() { echo TEARDOWN_CALLED; return 0; }\n"
        + "set +e\nrun_stage all\nrc=$?\nprintf 'rc=%s\\n' \"$rc\"\nexit 0\n"
    )
    assert "rc=9" in result.stdout
    assert "TEARDOWN_CALLED" not in result.stdout
    assert "failed state retained" in result.stdout


def test_physical_silmaril_blanket_wipe_is_refused(tmp_path):
    result = bash(
        source_prelude()
        + f"LOG={tmp_path / 'gate.log'}\nRESULTS={tmp_path / 'results.jsonl'}\n"
        + "HOST=silmaril\nREMOTE_DIR=/root/LME-gate\n"
        + "run_remote() { echo MUTATION_CALLED; return 0; }\n"
        + "set +e\ndo_wipe\nrc=$?\nprintf 'rc=%s\\n' \"$rc\"\nexit 0\n"
    )
    assert "rc=1" in result.stdout
    assert "MUTATION_CALLED" not in result.stdout
    assert "blanket wipe forbidden" in result.stdout




















