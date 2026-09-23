"""Behavioral + structural tests for the backup-bundle content-integrity contract.

These bind to the REAL D-owned files:
  * roles/backup_lme/vars/integrity.yml           (declaration)
  * roles/backup_lme/templates/content_integrity.sh.j2 (rendered producer+verifier)
  * ansible/restore_lme_master.yml                (verifier wiring + ordering)
  * ansible/roles/backup_lme/tasks/main.yml       (producer gate)

They prove RESTORE-CONTENT-DIGEST is NON-VACUOUS (a same-name/same-size single
byte change is refused, which the old listing_sha256 misses) and record the
HONEST limit of BACKUP-MANIFEST-CERTIFICATION (self-consistency only: an
under-declared OPTIONAL payload with a recomputed self-digest still passes).
"""
import re
import subprocess
import stat
from pathlib import Path

import jinja2
import yaml

REPO = Path(__file__).resolve().parents[3]
VARS = REPO / "ansible/roles/backup_lme/vars/integrity.yml"
TEMPLATE = REPO / "ansible/roles/backup_lme/templates/content_integrity.sh.j2"
RESTORE = REPO / "ansible/restore_lme_master.yml"
BACKUP_TASKS = REPO / "ansible/roles/backup_lme/tasks/main.yml"

# The tasks reference the rendered library as a bare {{ lme_integrity_lib }} fact
# (or, historically, an inline lookup('template', ...)). Either is replaced with the
# rendered library for behavioral extraction.
LOOKUP_RE = re.compile(
    r"\{\{\s*lookup\('template',\s*'[^']*content_integrity\.sh\.j2'\)\s*\}\}"
    r"|\{\{\s*lme_integrity_lib\s*\}\}")


def _render_library() -> str:
    decl = yaml.safe_load(VARS.read_text())
    return jinja2.Environment(keep_trailing_newline=True).from_string(
        TEMPLATE.read_text()
    ).render(**decl)


def _run(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True)


def _lib_plus(call: str) -> str:
    return _render_library() + "\n" + call


def _fabricate(root: Path, volume_byte: bytes = b"vol-data-1\n") -> None:
    """A minimal, well-formed backup bundle with one volume + content_manifest."""
    for d in ("lme", "etc_lme/vault", "etc_containers_systemd", "secrets",
              "volumes/lme_x/data"):
        (root / d).mkdir(parents=True, exist_ok=True)
    (root / "lme/a.txt").write_bytes(b"install-a")            # 9 bytes
    (root / "etc_lme/vault/0001").write_bytes(b"cipher-1\n")
    (root / "etc_containers_systemd/lme.container").write_bytes(b"quad\n")
    (root / "secrets/x.vault").write_bytes(b"captured-cipher\n")
    (root / "secret_manifest.txt").write_bytes(b"n|i|shell|0001|\n")
    (root / "volumes/lme_x/data/f1").write_bytes(volume_byte)
    # Produce the volume content_manifest (content_sha256 from the shared library).
    data = root / "volumes/lme_x/data"
    man = root / "volumes/lme_x/content_manifest.txt"
    csha = _run(_lib_plus(f'lme_content_sha256 "{data}"')).stdout.strip()
    man.write_text(f"file_count=1\ntotal_bytes={len(volume_byte)}\n"
                   f"listing_sha256=x\ncontent_sha256={csha}\n")


def _certify(root: Path) -> subprocess.CompletedProcess:
    return _run(_lib_plus(f'lme_bundle_certify "{root}"'))


def _verify(root: Path) -> subprocess.CompletedProcess:
    return _run(_lib_plus(f'lme_bundle_verify "{root}"'))


# ---------------------------------------------------------------------------
# Case 1 -- NON-VACUITY: same-name/same-size single-byte change is refused.
# ---------------------------------------------------------------------------
def test_content_digest_detects_same_size_byte_change(tmp_path):
    root = tmp_path / "b"
    _fabricate(root)
    assert _certify(root).returncode == 0
    assert _verify(root).returncode == 0
    # Same name, same size (9 bytes), one byte changed. listing_sha256 (paths+sizes)
    # would MISS this; content_sha256 catches it.
    (root / "lme/a.txt").write_bytes(b"install-b")
    r = _verify(root)
    assert r.returncode == 5, r.stderr
    assert "content mismatch" in r.stderr


# ---------------------------------------------------------------------------
# Case 2 -- HONEST LIMIT: self-consistency != completeness. Dropping an OPTIONAL
# payload line and recomputing the self-digest still passes (documents why
# BACKUP-MANIFEST-CERTIFICATION is PARTIAL, not closed).
# ---------------------------------------------------------------------------
def test_self_digest_does_not_catch_recomputed_optional_underdeclaration(tmp_path):
    root = tmp_path / "b"
    _fabricate(root)
    assert _certify(root).returncode == 0
    cert = root / "bundle_certification.txt"
    lines = [l for l in cert.read_text().splitlines()
             if not l.startswith("payload=secrets|")]          # drop optional 'secrets'
    payload_lines = "\n".join(l for l in lines if l.startswith("payload="))
    new_self = subprocess.run(
        ["bash", "-c", f'printf "%s\\n" "$0" | LC_ALL=C sort | sha256sum | '
                       f'awk "{{print \\$1}}"', payload_lines],
        capture_output=True, text=True).stdout.strip()
    rebuilt = [l for l in lines if not l.startswith("bundle_sha256=")]
    rebuilt.append(f"bundle_sha256={new_self}")
    cert.write_text("\n".join(rebuilt) + "\n")
    # secrets dir removed too, so nothing on disk contradicts the trimmed cert.
    import shutil
    shutil.rmtree(root / "secrets")
    r = _verify(root)
    assert r.returncode == 0, (
        "expected the self-consistency check to PASS a recomputed optional "
        f"under-declaration (documented honest limit); got rc={r.returncode} {r.stderr}")


# ---------------------------------------------------------------------------
# Case 3 -- missing certification is refused (rc 3), no listing fallback.
# ---------------------------------------------------------------------------
def test_missing_certification_refused(tmp_path):
    root = tmp_path / "b"
    _fabricate(root)
    assert _certify(root).returncode == 0
    (root / "bundle_certification.txt").unlink()
    r = _verify(root)
    assert r.returncode == 3, r.stderr


# ---------------------------------------------------------------------------
# Case 3b -- torn/truncated cert (line removed WITHOUT recomputing self) -> rc4.
# ---------------------------------------------------------------------------
def test_torn_certification_refused(tmp_path):
    root = tmp_path / "b"
    _fabricate(root)
    assert _certify(root).returncode == 0
    cert = root / "bundle_certification.txt"
    kept = [l for l in cert.read_text().splitlines()
            if not l.startswith("payload=secret_manifest|")]
    cert.write_text("\n".join(kept) + "\n")   # self-digest NOT recomputed
    r = _verify(root)
    assert r.returncode == 4, r.stderr


# ---------------------------------------------------------------------------
# Case 4 -- producer NEVER certifies a partial/unclean bundle (gate present).
# ---------------------------------------------------------------------------
def test_certify_task_is_gated_on_clean_success():
    doc = yaml.safe_load(BACKUP_TASKS.read_text())
    cert = next(t for t in doc if t.get("name", "").startswith("Certify the backup bundle"))
    whens = " ".join(cert["when"])
    assert "lme_backup_result is success" in whens
    assert "lme_backup_clean_container_stop" in whens
    assert "secret_mapping_result" in whens
    assert "selectattr('failed', 'eq', true)" in whens


# ---------------------------------------------------------------------------
# Case 5 -- ORDERING: cert-verify precedes the first destructive task.
# ---------------------------------------------------------------------------
def test_cert_verify_precedes_first_destructive_task():
    doc = yaml.safe_load(RESTORE.read_text())
    tasks = doc[0]["tasks"]
    names = [t.get("name", "") for t in tasks]
    verify_idx = next(i for i, n in enumerate(names)
                      if n.startswith("Verify backup bundle certification before any destructive"))
    install_idx = next(i for i, n in enumerate(names)
                       if n.startswith("Restore LME installation and system state from backup"))
    assert verify_idx < install_idx, (verify_idx, install_idx)


# ---------------------------------------------------------------------------
# Case 6 -- restore volume verify refuses a manifest lacking content_sha256
# (no fallback to listing_sha256). Extracts the REAL task body.
# ---------------------------------------------------------------------------
def _restore_volume_verify_body() -> str:
    doc = yaml.safe_load(RESTORE.read_text())
    for t in doc[0]["tasks"]:
        if t.get("name", "").startswith("Verify each selected volume matches its backup content manifest"):
            body = LOOKUP_RE.sub(lambda m: _render_library(), t["shell"])
            return jinja2.Environment().from_string(body).render(
                selected_backup_dir="{{SEL}}", item="lme_x")
    raise AssertionError("volume verify task not found")


def test_restore_volume_verify_refuses_missing_content_sha256(tmp_path):
    body = _restore_volume_verify_body()
    sel = tmp_path / "sel"
    data = sel / "volumes/lme_x/data"
    data.mkdir(parents=True)
    (data / "f1").write_bytes(b"x\n")
    # A pre-content-digest manifest: listing_sha256 present, content_sha256 ABSENT.
    (sel / "volumes/lme_x/content_manifest.txt").write_text(
        "file_count=1\ntotal_bytes=2\nlisting_sha256=deadbeef\n")
    script = body.replace("{{SEL}}", str(sel))
    r = _run(script)
    assert r.returncode == 3, (r.returncode, r.stderr)
    assert "content_sha256 missing" in r.stderr


# ---------------------------------------------------------------------------
# Cases 7-9 -- NON-CIRCULAR: drive the REAL task bodies (producer + certify +
# restore gate), not the library directly. Case 6 and 1-4 render the library and
# call its functions; these extract the actual "Backup each volume", "Certify the
# backup bundle" and restore "Verify backup bundle certification" shell bodies,
# render them with jinja2 (the ansible lookup('template') render was cross-checked
# to be functionally identical), and run them against bash/podman stubs. This is
# what proves the producer writes a bundle the real verifier accepts end to end.
# ---------------------------------------------------------------------------
def _task_body(doc_tasks, name_prefix, **render_vars) -> str:
    for t in doc_tasks:
        if t.get("name", "").startswith(name_prefix):
            body = LOOKUP_RE.sub(lambda m: _render_library(), t["shell"])
            return jinja2.Environment().from_string(body).render(**render_vars)
    raise AssertionError(f"task {name_prefix!r} not found")


def _volume_task_body(**v) -> str:
    doc = yaml.safe_load(BACKUP_TASKS.read_text())
    return _task_body(doc, "Backup each volume", **v)


def _certify_task_body(**v) -> str:
    doc = yaml.safe_load(BACKUP_TASKS.read_text())
    return _task_body(doc, "Certify the backup bundle", **v)


def _restore_gate_body(**v) -> str:
    doc = yaml.safe_load(RESTORE.read_text())
    return _task_body(doc[0]["tasks"], "Verify backup bundle certification before any destructive", **v)


def _podman_stub_dir(tmp_path, mountpoint: Path) -> Path:
    """A PATH dir whose `podman volume inspect ... --format ...` prints mountpoint."""
    b = tmp_path / "stubbin"
    b.mkdir(exist_ok=True)
    p = b / "podman"
    p.write_text('#!/usr/bin/env bash\n'
                 'if [ "$1" = "volume" ] && [ "$2" = "inspect" ]; then\n'
                 f'  echo "{mountpoint}"\n  exit 0\nfi\nexit 0\n')
    p.chmod(0o755)
    return b


def _run_env(script: str, path_prepend: Path):
    import os
    env = dict(os.environ)
    env["PATH"] = f"{path_prepend}:{env['PATH']}"
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)


def _fabricate_trees(root: Path) -> None:
    """Required trees so the real certify task does not refuse (rc1)."""
    (root / "lme").mkdir(parents=True, exist_ok=True)
    (root / "etc_lme").mkdir(parents=True, exist_ok=True)
    (root / "etc_containers_systemd").mkdir(parents=True, exist_ok=True)
    (root / "lme/a.txt").write_bytes(b"install-a")
    (root / "etc_lme/pass.sh").write_bytes(b"cipher\n")
    (root / "etc_containers_systemd/lme.container").write_bytes(b"quad\n")


def test_producer_volume_task_writes_matching_content_sha256(tmp_path):
    src = tmp_path / "vol_src"
    (src / "sub").mkdir(parents=True)
    (src / "f1").write_bytes(b"alpha\n")
    (src / "sub/f2").write_bytes(b"beta\n")
    stub = _podman_stub_dir(tmp_path, src)
    body = _volume_task_body(item="lme_x", backup_base_dir=str(tmp_path / "bk"),
                             backup_timestamp="T", cp_preserve_cmd="cp -a")
    r = _run_env(body, stub)
    assert r.returncode == 0, r.stderr
    vdir = tmp_path / "bk/backups/T/volumes/lme_x"
    assert (vdir / "backup_status.txt").read_text().strip() == "SUCCESS"
    man = (vdir / "content_manifest.txt").read_text()
    assert "content_sha256=" in man
    recorded = next(l.split("=", 1)[1] for l in man.splitlines() if l.startswith("content_sha256="))
    # The recorded digest must equal the library's digest of the COPIED data dir.
    actual = _run(_lib_plus(f'lme_content_sha256 "{vdir}/data"')).stdout.strip()
    assert recorded == actual and recorded not in ("", "MISSING")


def test_producer_volume_task_torn_copy_refused_no_manifest(tmp_path):
    src = tmp_path / "vol_src"
    src.mkdir()
    (src / "f1").write_bytes(b"one\n")
    (src / "f2").write_bytes(b"two\n")           # >=2 files so a dropped file tears the subtree
    stub = _podman_stub_dir(tmp_path, src)
    torn = tmp_path / "torn_cp.sh"
    torn.write_text('#!/usr/bin/env bash\n'
                    'cp -a "$1" "$2"\n'
                    'f=$(find "$2" -type f | LC_ALL=C sort | head -n1)\n'
                    '[ -n "$f" ] && rm -f "$f"\n'   # cp returns 0 but the copy is silently short
                    'exit 0\n')
    torn.chmod(0o755)
    body = _volume_task_body(item="lme_x", backup_base_dir=str(tmp_path / "bk"),
                             backup_timestamp="T", cp_preserve_cmd=str(torn))
    r = _run_env(body, stub)
    vdir = tmp_path / "bk/backups/T/volumes/lme_x"
    assert r.returncode != 0, "torn copy must fail the volume"
    assert (vdir / "backup_status.txt").read_text().strip() == "FAILED"
    assert not (vdir / "content_manifest.txt").exists(), "a torn copy must leave NO manifest"


def test_real_producer_to_restore_gate_roundtrip(tmp_path):
    """Real volume task -> real certify task -> real restore verify gate, end to end."""
    root = tmp_path / "bundle"
    _fabricate_trees(root)
    # Produce the volume via the REAL producer task body.
    src = tmp_path / "vol_src"
    src.mkdir()
    (src / "f1").write_bytes(b"vol-1\n")
    stub = _podman_stub_dir(tmp_path, src)
    vbody = _volume_task_body(item="lme_x", backup_base_dir=str(tmp_path / "stage"),
                              backup_timestamp="T", cp_preserve_cmd="cp -a")
    assert _run_env(vbody, stub).returncode == 0
    import shutil
    shutil.copytree(tmp_path / "stage/backups/T/volumes", root / "volumes")
    # Certify with the REAL certify task body (root = stage bundle level).
    cbody = _certify_task_body(backup_base_dir=str(tmp_path), backup_timestamp="X")
    # point the certify body's fixed root at our bundle:
    cbody = cbody.replace(f'"{tmp_path}/backups/X"', f'"{root}"')
    assert _run(cbody).returncode == 0, "real certify task must certify a clean bundle"
    assert (root / "bundle_certification.txt").exists()
    # Verify with the REAL restore gate body.
    gbody = _restore_gate_body(selected_backup_dir=str(root))
    assert _run(gbody).returncode == 0, "real restore gate must accept the freshly certified bundle"
    # Tamper a REQUIRED tree (same-size byte change) -> gate refuses (rc5).
    (root / "lme/a.txt").write_bytes(b"install-Z")
    assert _run(gbody).returncode == 5


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
