"""Behavioral tests for the ``Restore Podman secrets from backup`` shell task in
ansible/restore_lme_master.yml.

These render the ACTUAL shell body out of the playbook with jinja2 and run it
against stub ``podman`` and ``ansible-vault`` executables, so we exercise the
real control flow rather than a paraphrase. They pin the recovery guarantees:

  * a create failure halts (rc 3) WITHOUT any destructive prune
    (RESTORE-MASTER-CREATE-FAILURE);
  * an empty-decrypting payload is refused at preverify (rc 2) with NO
    destruction (RESTORE-EMPTY-SECRET-PREFLIGHT);
  * a clean restore replaces the backed-up secrets and prunes stale ones ONLY
    after every create succeeds (RESTORE-EARLY-DESTRUCTION).
"""
import os
import re
import stat
import subprocess
from pathlib import Path

import jinja2
import yaml

REPO = Path(__file__).resolve().parents[3]
PLAYBOOK = REPO / "ansible" / "restore_lme_master.yml"


def _secret_shell_body() -> str:
    doc = yaml.safe_load(PLAYBOOK.read_text())
    for task in doc[0]["tasks"]:
        if task.get("name", "").startswith("Restore Podman secrets"):
            body = task["shell"]
            # Render the jinja-escaped go-template markers ({{ '{{' }}.Name{{ '}}' }})
            # and the selected_backup_dir substitution; keep everything else literal.
            return jinja2.Environment().from_string(body).render(
                selected_backup_dir="{{SELECTED}}"
            )
    raise AssertionError("Restore Podman secrets task not found")


PODMAN_STUB = r"""#!/usr/bin/env bash
# Stub podman: logs every invocation and maintains a flat secret-name store.
echo "$*" >> "$PODMAN_LOG"
if [ "$1" = "secret" ] && [ "$2" = "ls" ]; then
  # print current names regardless of --format (ids==names for the test)
  cat "$SECRET_STATE" 2>/dev/null || true
  exit 0
fi
if [ "$1" = "secret" ] && [ "$2" = "create" ]; then
  cat >/dev/null   # drain stdin payload
  name=""
  prev=""
  for a in "$@"; do
    if [ "$prev" = "--replace" ]; then name="$a"; fi
    prev="$a"
  done
  if [ -n "$FAIL_NAME" ] && [ "$name" = "$FAIL_NAME" ]; then
    exit 1
  fi
  grep -qxF "$name" "$SECRET_STATE" 2>/dev/null || printf '%s\n' "$name" >> "$SECRET_STATE"
  echo "$name"
  exit 0
fi
if [ "$1" = "secret" ] && [ "$2" = "rm" ]; then
  name="$3"
  if [ -f "$SECRET_STATE" ]; then
    grep -vxF "$name" "$SECRET_STATE" > "$SECRET_STATE.tmp" 2>/dev/null || true
    mv "$SECRET_STATE.tmp" "$SECRET_STATE"
  fi
  exit 0
fi
exit 0
"""

# Stub ansible-vault: `view PATH` just cats PATH (the file content IS the "plaintext").
VAULT_STUB = r"""#!/usr/bin/env bash
if [ "$1" = "view" ]; then
  cat "$2"
  exit 0
fi
exit 0
"""


def _make_exec(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def _run_case(tmp_path, manifest_lines, vault_files, live_names, fail_name=None):
    """Set up a sandbox backup + stub bin, run the rendered body, return
    (returncode, podman_log_lines, final_secret_names)."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    _make_exec(bindir / "podman", PODMAN_STUB)
    _make_exec(bindir / "ansible-vault", VAULT_STUB)

    backup = tmp_path / "backup"
    (backup / "etc_lme" / "vault").mkdir(parents=True)
    (backup / "etc_lme" / "pass.sh").write_text("#!/bin/sh\necho x\n")
    for rel, content in vault_files.items():
        (backup / "etc_lme" / "vault" / rel).write_text(content)
    if manifest_lines is not None:
        (backup / "secret_manifest.txt").write_text("\n".join(manifest_lines) + "\n")

    state = tmp_path / "secret_state"
    state.write_text(("\n".join(live_names) + "\n") if live_names else "")
    podman_log = tmp_path / "podman.log"
    podman_log.write_text("")

    body = _secret_shell_body().replace("{{SELECTED}}", str(backup))
    script = tmp_path / "run.sh"
    script.write_text(body)

    env = dict(os.environ)
    env["PATH"] = f"{bindir}:{env['PATH']}"
    env["SECRET_STATE"] = str(state)
    env["PODMAN_LOG"] = str(podman_log)
    if fail_name:
        env["FAIL_NAME"] = fail_name

    proc = subprocess.run(
        ["bash", str(script)], env=env, capture_output=True, text=True
    )
    log_lines = [l for l in podman_log.read_text().splitlines() if l.strip()]
    final = [l for l in state.read_text().splitlines() if l.strip()]
    return proc.returncode, log_lines, final, proc.stderr


def _first_index(log, prefix):
    for i, l in enumerate(log):
        if l.startswith(prefix):
            return i
    return None


def test_create_failure_halts_without_destruction(tmp_path):
    # alpha decrypts fine; beta decrypts fine but its create fails.
    rc, log, final, stderr = _run_case(
        tmp_path,
        manifest_lines=["alpha|a|shell|alpha.vault|", "beta|b|shell|beta.vault|"],
        vault_files={"alpha.vault": "alpha-secret", "beta.vault": "beta-secret"},
        live_names=["alpha", "beta", "stale"],
        fail_name="beta",
    )
    assert rc == 3, f"expected rc 3 on create failure, got {rc}; stderr={stderr}"
    # The create-failure gate must fire BEFORE any prune -- no destruction at all.
    assert _first_index(log, "secret rm") is None, f"prune ran despite create failure: {log}"
    assert "stale" in final, "stale secret was destroyed despite a failed restore"


def test_empty_payload_refused_before_destruction(tmp_path):
    rc, log, final, stderr = _run_case(
        tmp_path,
        manifest_lines=["alpha|a|shell|alpha.vault|"],
        vault_files={"alpha.vault": ""},  # decrypts to EMPTY
        live_names=["alpha", "stale"],
    )
    assert rc == 2, f"expected rc 2 on empty-payload preflight, got {rc}; stderr={stderr}"
    assert _first_index(log, "secret rm") is None, f"destruction ran on empty payload: {log}"
    assert _first_index(log, "secret create") is None, f"create ran on empty payload: {log}"
    assert set(final) == {"alpha", "stale"}, "live secrets were mutated on a refused restore"


def test_clean_restore_prunes_stale_after_creates(tmp_path):
    rc, log, final, stderr = _run_case(
        tmp_path,
        manifest_lines=["alpha|a|shell|alpha.vault|"],
        vault_files={"alpha.vault": "alpha-secret"},
        live_names=["alpha", "stale"],
    )
    assert rc == 0, f"expected rc 0 on clean restore, got {rc}; stderr={stderr}"
    last_create = None
    for i, l in enumerate(log):
        if l.startswith("secret create"):
            last_create = i
    first_rm = _first_index(log, "secret rm")
    assert last_create is not None, "no create was issued"
    assert first_rm is not None, "stale secret was not pruned"
    assert first_rm > last_create, "prune ran BEFORE creates completed (early destruction)"
    assert set(final) == {"alpha"}, f"final secret set wrong: {final}"


def test_stale_prune_targets_only_names_absent_from_restore(tmp_path):
    # Two live, only one in the backup -> exactly the other is pruned.
    rc, log, final, _ = _run_case(
        tmp_path,
        manifest_lines=["keep|k|shell|keep.vault|"],
        vault_files={"keep.vault": "keep-secret"},
        live_names=["keep", "drop"],
    )
    assert rc == 0
    rm_lines = [l for l in log if l.startswith("secret rm")]
    assert rm_lines == ["secret rm drop"], f"unexpected prune set: {rm_lines}"
    assert set(final) == {"keep"}
