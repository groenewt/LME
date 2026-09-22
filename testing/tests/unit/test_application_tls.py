import ast
import asyncio
import ipaddress
import os
import ssl
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
import requests
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from jinja2 import Environment, StrictUndefined


ROOT = Path(__file__).resolve().parents[3]
DASHBOARD_APP = ROOT / "lme-dashboard" / "app.py"
ANALYZER_APP = ROOT / "lme-log-analyzer" / "app_simple.py"
INGESTERS = (
    ROOT / "scripts" / "ingest_docs.py",
    ROOT / "lme-dashboard" / "scripts" / "ingest_docs.py",
)


def _load_symbols(path: Path, names: set[str], namespace: dict):
    """Execute selected production definitions without starting either web UI."""
    tree = ast.parse(path.read_text(), filename=str(path))
    selected = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in names:
                selected.append(node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            assigned = {
                target.id
                for target in targets
                if isinstance(target, ast.Name)
            }
            if assigned & names:
                selected.append(node)
    module = ast.Module(body=selected, type_ignores=[])
    exec(compile(module, str(path), "exec"), namespace)
    return namespace


def _tls_api(path: Path, **overrides):
    namespace = {"os": os, "ssl": ssl, "httpx": httpx, "requests": requests,
                 "LITELLM_KEY": "fixture-key", **overrides}
    return _load_symbols(
        path,
        {
            "_strict_bool",
            "_tls_verify",
            "_TLS_TRUTHY",
            "_TLS_FALSY",
            "_es_transport",
            "_llm_transport",
            "es_client",
            "llm_client",
            "embedding_client",
        },
        namespace,
    )


class _OKHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = b'{"data":[{"index":0,"embedding":[1.0]}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def _write_certificate(path: Path, cert: x509.Certificate):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _write_key(path: Path, key):
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def _certificate_fixture(tmp_path: Path, *, san_matches: bool = True, expired: bool = False):
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LME fixture CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture-server")])
    san = (
        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
        if san_matches
        else x509.DNSName("wrong.fixture.invalid")
    )
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=2))
        .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=7))
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    stem = f"{'right' if san_matches else 'wrong'}-{'expired' if expired else 'valid'}"
    ca_path = tmp_path / f"{stem}-ca.crt"
    cert_path = tmp_path / f"{stem}.crt"
    key_path = tmp_path / f"{stem}.key"
    _write_certificate(ca_path, ca_cert)
    _write_certificate(cert_path, leaf_cert)
    _write_key(key_path, leaf_key)
    return ca_path, cert_path, key_path


@contextmanager
def _https_server(cert_path: Path, key_path: Path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _OKHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


async def _httpx_get(factory, url: str):
    async with factory() as client:
        return await client.get(url)


@pytest.mark.parametrize("path", [DASHBOARD_APP, ANALYZER_APP, *INGESTERS])
def test_tls_boolean_parser_rejects_unknown_values(path):
    api = _tls_api(path)
    parse = api["_strict_bool"]

    assert parse("TLS_VERIFY", "true") is True
    assert parse("TLS_VERIFY", "OFF") is False
    with pytest.raises(ValueError, match="TLS_VERIFY"):
        parse("TLS_VERIFY", "truthy")


@pytest.mark.parametrize("script", INGESTERS)
def test_ingester_embedding_client_verifies_chain_and_matching_san(tmp_path, script):
    ca, cert, key = _certificate_fixture(tmp_path)
    api = _load_symbols(
        script,
        {"embed_texts"},
        {"requests": requests, "EMBEDDINGS_VERIFY": str(ca)},
    )
    with _https_server(cert, key) as url:
        api["EMBED_URL"] = url
        assert api["embed_texts"](["fixture"]) == [[1.0]]


@pytest.mark.parametrize("script", INGESTERS)
def test_ingester_embedding_client_rejects_wrong_san(tmp_path, script):
    ca, cert, key = _certificate_fixture(tmp_path, san_matches=False)
    api = _load_symbols(
        script,
        {"embed_texts"},
        {"requests": requests, "EMBEDDINGS_VERIFY": str(ca)},
    )
    with _https_server(cert, key) as url:
        api["EMBED_URL"] = url
        with pytest.raises(requests.exceptions.SSLError, match="certificate verify failed"):
            api["embed_texts"](["fixture"])


def test_dashboard_es_client_verifies_chain_and_matching_san(tmp_path):
    ca, cert, key = _certificate_fixture(tmp_path)
    api = _tls_api(DASHBOARD_APP)
    api["ES_VERIFY"] = api["_tls_verify"]("ELASTICSEARCH_SSL_VERIFY", "true", str(ca))
    assert api["ES_VERIFY"].check_hostname is True

    with _https_server(cert, key) as url:
        response = asyncio.run(_httpx_get(api["es_client"], url))

    assert response.status_code == 200


def test_analyzer_es_transport_verifies_chain_and_matching_san(tmp_path):
    ca, cert, key = _certificate_fixture(tmp_path)
    api = _tls_api(ANALYZER_APP)
    api["ES_VERIFY"] = api["_tls_verify"]("ELASTICSEARCH_SSL_VERIFY", "true", str(ca))
    http, verify = api["_es_transport"]()

    with _https_server(cert, key) as url:
        response = http.get(url, verify=verify, timeout=3)

    assert response.status_code == 200


@pytest.mark.parametrize("client_kind", ["dashboard", "analyzer"])
def test_application_es_clients_reject_wrong_san(tmp_path, client_kind):
    ca, cert, key = _certificate_fixture(tmp_path, san_matches=False)

    with _https_server(cert, key) as url:
        if client_kind == "dashboard":
            api = _tls_api(DASHBOARD_APP)
            api["ES_VERIFY"] = api["_tls_verify"]("ELASTICSEARCH_SSL_VERIFY", "true", str(ca))
            with pytest.raises(httpx.ConnectError, match="certificate verify failed"):
                asyncio.run(_httpx_get(api["es_client"], url))
        else:
            api = _tls_api(ANALYZER_APP)
            api["ES_VERIFY"] = api["_tls_verify"]("ELASTICSEARCH_SSL_VERIFY", "true", str(ca))
            http, verify = api["_es_transport"]()
            with pytest.raises(requests.exceptions.SSLError, match="certificate verify failed"):
                http.get(url, verify=verify, timeout=3)


@pytest.mark.parametrize("client_kind", ["dashboard", "analyzer"])
def test_application_es_clients_reject_expired_leaf(tmp_path, client_kind):
    ca, cert, key = _certificate_fixture(tmp_path, expired=True)

    with _https_server(cert, key) as url:
        if client_kind == "dashboard":
            api = _tls_api(DASHBOARD_APP)
            api["ES_VERIFY"] = api["_tls_verify"]("ELASTICSEARCH_SSL_VERIFY", "true", str(ca))
            with pytest.raises(httpx.ConnectError, match="certificate verify failed"):
                asyncio.run(_httpx_get(api["es_client"], url))
        else:
            api = _tls_api(ANALYZER_APP)
            api["ES_VERIFY"] = api["_tls_verify"]("ELASTICSEARCH_SSL_VERIFY", "true", str(ca))
            http, verify = api["_es_transport"]()
            with pytest.raises(requests.exceptions.SSLError, match="certificate verify failed"):
                http.get(url, verify=verify, timeout=3)


def test_application_clients_fail_when_ca_file_is_missing(tmp_path):
    missing = str(tmp_path / "missing-ca.crt")
    dashboard = _tls_api(DASHBOARD_APP)
    with pytest.raises(FileNotFoundError):
        dashboard["_tls_verify"]("ELASTICSEARCH_SSL_VERIFY", "true", missing)

    analyzer = _tls_api(ANALYZER_APP)
    with pytest.raises(FileNotFoundError):
        analyzer["_tls_verify"]("ELASTICSEARCH_SSL_VERIFY", "true", missing)


def test_dashboard_internal_client_keeps_separate_backend_trust(tmp_path):
    internal_ca, internal_cert, internal_key = _certificate_fixture(tmp_path)
    other_dir = tmp_path / "producer"
    other_dir.mkdir()
    producer_ca, _, _ = _certificate_fixture(other_dir)
    api = _tls_api(DASHBOARD_APP)
    api["ES_VERIFY"] = api["_tls_verify"](
        "ELASTICSEARCH_SSL_VERIFY", "true", str(producer_ca)
    )
    api["LITELLM_VERIFY"] = api["_tls_verify"](
        "LITELLM_SSL_VERIFY", "true", str(internal_ca)
    )
    api["EMBEDDINGS_VERIFY"] = api["_tls_verify"](
        "EMBEDDINGS_SSL_VERIFY", "true", str(internal_ca)
    )

    with _https_server(internal_cert, internal_key) as url:
        llm_response = asyncio.run(_httpx_get(api["llm_client"], url))
        embedding_response = asyncio.run(_httpx_get(api["embedding_client"], url))
        with pytest.raises(httpx.ConnectError, match="certificate verify failed"):
            asyncio.run(_httpx_get(api["es_client"], url))

    assert llm_response.status_code == 200
    assert embedding_response.status_code == 200


def test_service_manifests_enable_tls_and_use_dedicated_es_ca(monkeypatch):
    for variable in (
        "ELASTICSEARCH_SSL_VERIFY",
        "ELASTICSEARCH_CA_CERT",
        "LITELLM_SSL_VERIFY",
        "LITELLM_CA_CERT",
        "EMBEDDINGS_SSL_VERIFY",
        "EMBEDDINGS_CA_CERT",
    ):
        monkeypatch.delenv(variable, raising=False)
    apps = (
        ("lme-dashboard.yml", DASHBOARD_APP),
        ("lme-log-analyzer.yml", ANALYZER_APP),
    )
    for name, app_path in apps:
        manifest = yaml.safe_load((ROOT / "manifests" / "services" / name).read_text())
        environment = manifest["environment"]
        assert environment["ELASTICSEARCH_SSL_VERIFY"] == "true"
        assert environment["ELASTICSEARCH_CA_CERT"] == "/certs/ca/elasticsearch-ca.crt"
        assert environment["LITELLM_SSL_VERIFY"] == "true"
        assert environment["LITELLM_CA_CERT"] == "/certs/ca/litellm-ca.crt"
        if name == "lme-dashboard.yml":
            assert environment["EMBEDDINGS_SSL_VERIFY"] == "true"
            assert environment["EMBEDDINGS_CA_CERT"] == "/certs/ca/embeddings-ca.crt"

        app_defaults = _load_symbols(
            app_path,
            {
                "ES_SSL_VERIFY",
                "ES_CA_CERT",
                "LITELLM_SSL_VERIFY",
                "LITELLM_CA_CERT",
                "EMBEDDINGS_SSL_VERIFY",
                "EMBEDDINGS_CA_CERT",
            },
            {"os": os},
        )
        assert app_defaults["ES_SSL_VERIFY"] == "true"
        assert app_defaults["ES_CA_CERT"] == "/certs/ca/elasticsearch-ca.crt"
        assert app_defaults["LITELLM_SSL_VERIFY"] == "true"
        assert app_defaults["LITELLM_CA_CERT"] == "/certs/ca/litellm-ca.crt"
        if app_path == DASHBOARD_APP:
            assert app_defaults["EMBEDDINGS_SSL_VERIFY"] == "true"
            assert app_defaults["EMBEDDINGS_CA_CERT"] == "/certs/ca/embeddings-ca.crt"


def test_analyzer_image_healthcheck_verifies_local_server_identity():
    dockerfile = (ROOT / "lme-log-analyzer" / "Dockerfile").read_text()
    healthcheck = next(line for line in dockerfile.splitlines() if "CMD curl" in line)
    assert " -k" not in healthcheck
    assert "--cacert /certs/ca/ca.crt" in healthcheck
    assert "https://localhost:8501/_stcore/health" in healthcheck

    manifest = yaml.safe_load(
        (ROOT / "manifests" / "services" / "lme-log-analyzer.yml").read_text()
    )
    assert manifest["health"] == {
        "cmd": "curl --fail --silent --show-error --cacert /certs/ca/ca.crt "
               "https://localhost:8501/_stcore/health",
        "interval": "30s",
        "timeout": "10s",
        "retries": 3,
        "start_period": "5s",
    }


def test_cert_role_preserves_explicit_source_host():
    tasks = yaml.safe_load((ROOT / "ansible" / "roles" / "certs" / "tasks" / "main.yml").read_text())
    task = next(task for task in tasks if "ansible.builtin.set_fact" in task)
    facts = task["ansible.builtin.set_fact"]
    assert "lme_certs_source_host" not in facts
    expression = facts["lme_certs_effective_source_host"]
    rendered = Environment(undefined=StrictUndefined).from_string(expression).render(
        lme_certs_source_host="profile-producer",
        groups={"elasticsearch": ["inventory-producer"]},
        inventory_hostname="consumer",
    )
    assert rendered.strip() == "profile-producer"


def test_producer_ca_distribution_uses_dedicated_readable_path():
    tasks = yaml.safe_load(
        (ROOT / "ansible" / "roles" / "podman" / "tasks" / "distribute_ca.yml").read_text()
    )
    copy_index, copy_task = next(
        (index, task)
        for index, task in enumerate(tasks)
        if "ansible.builtin.copy" in task
    )
    copy_args = copy_task["ansible.builtin.copy"]
    assert copy_args["dest"].endswith("/ca/elasticsearch-ca.crt")
    assert copy_args["mode"] == "0644"
    assert any(
        index > copy_index and "restart" in task.get("name", "").lower()
        for index, task in enumerate(tasks)
    )
