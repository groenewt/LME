import ast
import os
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[3]
DASHBOARD_APP = ROOT / "lme-dashboard" / "app.py"
INGESTERS = (ROOT / "scripts" / "ingest_docs.py", ROOT / "lme-dashboard" / "scripts" / "ingest_docs.py")


def _load_symbols(path: Path, names: set[str], namespace: dict):
    tree = ast.parse(path.read_text(), filename=str(path))
    selected = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names:
            selected.append(node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id in names for target in targets):
                selected.append(node)
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


def _credential_files(tmp_path: Path):
    files = {
        "PGVECTOR_SSLROOTCERT": tmp_path / "ca.crt",
        "PGVECTOR_SSLCERT": tmp_path / "tls.crt",
        "PGVECTOR_SSLKEY": tmp_path / "tls.key",
        "PGVECTOR_PASSFILE": tmp_path / ".pgpass",
    }
    for name, path in files.items():
        path.write_text("fixture")
        path.chmod(0o600 if name in {"PGVECTOR_SSLKEY", "PGVECTOR_PASSFILE"} else 0o644)
    return {name: str(path) for name, path in files.items()}


def _dashboard_pg_api(tmp_path: Path, **overrides):
    namespace = {
        "os": os,
        "PGVECTOR_HOST": "pg-vector-rw",
        "PGVECTOR_PORT": 5432,
        "PGVECTOR_DB": "lme_vectors",
        "PGVECTOR_USER": "lme_vectors_app",
        "PGVECTOR_SSLMODE": "verify-full",
        "EMBED_URL": "https://embeddings.example.test:8081",
        "EMBEDDINGS_SSL_VERIFY": "true",
        "EMBEDDINGS_CA_CERT": "/certs/ca/embeddings-ca.crt",
        **_credential_files(tmp_path),
        **overrides,
    }
    return _load_symbols(
        DASHBOARD_APP,
        {"_pg_connection_kwargs", "_pg_conn", "_pg_ready", "_ingest_environment"},
        namespace,
    )


def test_dashboard_builds_verify_full_mtls_connection_without_password(tmp_path):
    api = _dashboard_pg_api(tmp_path)

    kwargs = api["_pg_connection_kwargs"]()

    assert kwargs == {
        "host": "pg-vector-rw",
        "port": 5432,
        "dbname": "lme_vectors",
        "user": "lme_vectors_app",
        "sslmode": "verify-full",
        "sslrootcert": api["PGVECTOR_SSLROOTCERT"],
        "sslcert": api["PGVECTOR_SSLCERT"],
        "sslkey": api["PGVECTOR_SSLKEY"],
        "passfile": api["PGVECTOR_PASSFILE"],
        "connect_timeout": 5,
    }
    assert "password" not in kwargs


@pytest.mark.parametrize("bad_mode", ["disable", "allow", "prefer", "require", "verify-ca", ""])
def test_dashboard_rejects_non_verify_full_pg_modes(tmp_path, bad_mode):
    api = _dashboard_pg_api(tmp_path, PGVECTOR_SSLMODE=bad_mode)
    with pytest.raises(RuntimeError, match="PGVECTOR_SSLMODE"):
        api["_pg_connection_kwargs"]()


@pytest.mark.parametrize("missing_name", ["PGVECTOR_SSLROOTCERT", "PGVECTOR_SSLCERT", "PGVECTOR_SSLKEY", "PGVECTOR_PASSFILE"])
def test_dashboard_rejects_missing_pg_credential_files(tmp_path, missing_name):
    api = _dashboard_pg_api(tmp_path)
    Path(api[missing_name]).unlink()
    with pytest.raises(RuntimeError, match=missing_name):
        api["_pg_connection_kwargs"]()


@pytest.mark.parametrize("unsafe_name", ["PGVECTOR_SSLKEY", "PGVECTOR_PASSFILE"])
def test_dashboard_rejects_pg_private_files_readable_by_group_or_other(tmp_path, unsafe_name):
    api = _dashboard_pg_api(tmp_path)
    Path(api[unsafe_name]).chmod(0o644)
    with pytest.raises(RuntimeError, match=unsafe_name):
        api["_pg_connection_kwargs"]()


def test_dashboard_readiness_runs_authenticated_select_one(tmp_path):
    calls = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, sql):
            calls.append(sql)

        def fetchone(self):
            return (1,)

    class Connection:
        def cursor(self):
            return Cursor()

        def close(self):
            calls.append("close")

    api = _dashboard_pg_api(tmp_path)
    api["_pg_conn"] = lambda: Connection()
    assert api["_pg_ready"]() is True
    assert calls == ["SELECT 1", "close"]


def test_dashboard_ingestion_environment_removes_password_and_forwards_file_contract(tmp_path, monkeypatch):
    monkeypatch.setenv("PGVECTOR_PASS", "must-not-cross-process-boundary")
    api = _dashboard_pg_api(tmp_path)

    environment = api["_ingest_environment"]()

    assert "PGVECTOR_PASS" not in environment
    assert environment["PGVECTOR_USER"] == "lme_vectors_app"
    assert environment["PGVECTOR_SSLMODE"] == "verify-full"
    assert environment["PGVECTOR_PASSFILE"] == api["PGVECTOR_PASSFILE"]


@pytest.mark.parametrize("script", INGESTERS)
def test_ingesters_use_same_strict_file_based_connection(script, tmp_path, monkeypatch):
    for name in (
        "PGVECTOR_HOST",
        "PGVECTOR_PORT",
        "PGVECTOR_DB",
        "PGVECTOR_USER",
        "PGVECTOR_SSLMODE",
        "PGVECTOR_SSLROOTCERT",
        "PGVECTOR_SSLCERT",
        "PGVECTOR_SSLKEY",
        "PGVECTOR_PASSFILE",
        "PGVECTOR_PASS",
    ):
        monkeypatch.delenv(name, raising=False)
    namespace = {"os": os}
    api = _load_symbols(
        script,
        {
            "PG_HOST", "PG_PORT", "PG_DB", "PG_USER", "PG_SSLMODE", "PG_SSLROOTCERT",
            "PG_SSLCERT", "PG_SSLKEY", "PG_PASSFILE", "_pg_connection_kwargs",
        },
        namespace,
    )

    assert api["PG_HOST"] == "pg-vector-rw"
    assert api["PG_USER"] == "lme_vectors_app"
    assert api["PG_SSLMODE"] == "verify-full"
    kwargs = api["_pg_connection_kwargs"](validate_files=False)
    assert kwargs["passfile"] == "/run/secrets/postgresql/.pgpass"
    assert "password" not in kwargs


def test_manifests_bind_actual_pg_principals_and_no_password_environment_secret():
    dashboard = yaml.safe_load((ROOT / "manifests/services/lme-dashboard.yml").read_text())
    dashboard_env = dashboard["environment"]
    assert dashboard_env["PGVECTOR_HOST"] == "pg-vector-rw"
    assert dashboard_env["PGVECTOR_USER"] == "lme_vectors_app"
    assert dashboard_env["PGVECTOR_SSLMODE"] == "verify-full"
    assert dashboard_env["PGVECTOR_SSLROOTCERT"] == "/run/secrets/postgresql/ca.crt"
    assert dashboard_env["PGVECTOR_SSLCERT"] == "/run/secrets/postgresql/tls.crt"
    assert dashboard_env["PGVECTOR_SSLKEY"] == "/run/secrets/postgresql/tls.key"
    assert dashboard_env["PGVECTOR_PASSFILE"] == "/run/secrets/postgresql/.pgpass"
    pgvector_secret = next(secret for secret in dashboard["secrets"] if secret["name"] == "pgvector")
    assert pgvector_secret["type"] == "mount"
    assert "PGVECTOR_PASS" not in str(pgvector_secret)

    litellm = yaml.safe_load((ROOT / "manifests/services/lme-litellm.yml").read_text())
    litellm_env = litellm["environment"]
    assert litellm_env["PGVECTOR_HOST"] == "pg-vector-rw"
    assert litellm_env["PGVECTOR_USER"] == "litellm_app"
    assert litellm_env["PGVECTOR_SSLMODE"] == "verify-full"
    assert litellm_env["PGVECTOR_PASSFILE"] == "/run/secrets/postgresql/.pgpass"
    assert "$${PGVECTOR_PASS}" not in litellm["exec"]
    for parameter in ("sslmode", "sslrootcert", "sslcert", "sslkey", "passfile"):
        assert parameter + "=" in litellm["exec"]


def test_log_analyzer_does_not_receive_unused_database_credentials():
    analyzer = yaml.safe_load((ROOT / "manifests/services/lme-log-analyzer.yml").read_text())
    assert not any(name.startswith("PGVECTOR_") for name in analyzer["environment"])
    assert not any(secret["name"] == "pgvector" for secret in analyzer["secrets"])
