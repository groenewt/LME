import asyncio
import importlib.util
import os
from pathlib import Path

import httpx


MODULE_PATH = Path("lme-dashboard/telemetry_views.py")
SPEC = importlib.util.spec_from_file_location("telemetry_views", MODULE_PATH)
telemetry_views = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(telemetry_views)


def run(coro):
    return asyncio.run(coro)


def test_logs_query_uses_authenticated_elasticsearch_and_reports_fresh_rows():
    observed = {}

    def handler(request: httpx.Request):
        observed["authorization"] = request.headers.get("authorization")
        observed["path"] = request.url.path
        return httpx.Response(200, json={
            "hits": {
                "total": {"value": 1},
                "hits": [{"_id": "1", "_index": "logs-system", "_source": {
                    "@timestamp": "2026-09-22T12:00:00Z", "message": "real row"
                }}],
            }
        })

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://es.test")
    service = telemetry_views.TelemetryViewService(
        es_url="https://es.test", es_user="elastic", es_password="secret", client=client,
        now=lambda: telemetry_views.parse_timestamp("2026-09-22T12:00:30Z"),
    )
    result = run(service.logs(time_from="now-15m", query=None, source=None))
    run(client.aclose())
    assert observed["authorization"].startswith("Basic ")
    assert observed["path"].endswith("/_search")
    assert "lme-typed-logs-" in observed["path"]
    assert result["state"] == "fresh"
    assert result["items"][0]["message"] == "real row"


def test_filtered_empty_is_distinct_from_source_empty():
    def handler(request: httpx.Request):
        body = request.content.decode()
        total = 4 if '"size":0' in body else 0
        return httpx.Response(200, json={"hits": {"total": {"value": total}, "hits": []}})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://es.test")
    service = telemetry_views.TelemetryViewService("https://es.test", "u", "p", client=client)
    result = run(service.logs(time_from="now-15m", query="needle", source=None))
    run(client.aclose())
    assert result["state"] == "filtered_empty"
    assert result["items"] == []


def test_backend_failure_is_unavailable_and_never_fabricates_rows():
    def handler(_request):
        raise httpx.ConnectError("offline")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://es.test")
    service = telemetry_views.TelemetryViewService("https://es.test", "u", "p", client=client)
    result = run(service.metrics(time_from="now-15m", query=None, source=None))
    run(client.aclose())
    assert result == {
        "state": "unavailable",
        "items": [],
        "total": None,
        "freshness": None,
        "reason": "elasticsearch_unavailable",
    }


def test_windows_source_is_explicitly_not_applicable_without_inspection():
    service = telemetry_views.TelemetryViewService("https://es.test", "u", "p", client=None)
    result = run(service.source("windows-physical"))
    assert result["state"] == "not_applicable"
    assert result["reason"] == "windows_inspection_not_authorized"
    assert result["items"] == []


def test_hertzbeat_source_uses_real_result_dataset_query(tmp_path):
    observed = {}
    auth_file = tmp_path / "authorization"
    auth_file.write_text("Bearer synthetic-hb-read-token-00000000000000001\n")
    auth_file.chmod(0o600)

    def handler(request: httpx.Request):
        observed["path"] = request.url.path
        observed["query"] = str(request.url.query)
        observed["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json={"code": 0, "data": {"content": [{
            "resource": {"host.name": "guest:trixie"},
            "body": '{"source_node":"guest:trixie","event_id":"event-1","observed_at":"2026-09-22T12:00:00Z"}',
        }]}})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    hb = telemetry_views.HertzBeatResultService(
        "https://trixie.example.ts.net:14458", auth_file, client=client,
        now=lambda: telemetry_views.parse_timestamp("2026-09-22T12:00:30Z"),
    )
    service = telemetry_views.TelemetryViewService("https://es.test", "u", "p", hertzbeat=hb)
    result = run(service.source("hertzbeat", query="event-1"))
    run(client.aclose())
    assert observed["path"] == "/api/observability/logs"
    assert "search=event-1" in observed["query"]
    assert "resource=" not in observed["query"]
    assert observed["authorization"].startswith("Bearer ")
    assert result["state"] == "fresh"
    assert result["items"][0]["event_id"] == "event-1"


def test_hertzbeat_view_requires_exact_search_and_never_borrows_es_or_admin_credentials(tmp_path):
    auth_file = tmp_path / "authorization"
    auth_file.write_text("Bearer source-scoped-token-000000000000000000\n")
    auth_file.chmod(0o600)
    hb = telemetry_views.HertzBeatResultService("https://trixie.example.ts.net:14458", auth_file)
    service = telemetry_views.TelemetryViewService("https://es.test", "elastic", "admin-password", hertzbeat=hb)
    result = run(service.source("hertzbeat"))
    assert result["state"] == "unavailable"
    assert result["reason"] == "exact_event_id_required"

    auth_file.chmod(0o644)
    result = run(service.source("hertzbeat", query="event-1"))
    assert result["state"] == "unavailable"
    assert result["reason"] == "hertzbeat_unavailable"


def test_hertzbeat_reader_map_queries_all_six_scoped_datasets(tmp_path):
    sources = [f"{scope}:{node}" for scope in ("physical", "guest")
               for node in ("graph", "trixie", "silmaril")]
    paths = {}
    tokens = {}
    for index, source in enumerate(sources):
        path = tmp_path / (source.replace(":", "-") + ".authorization")
        token = f"scoped-reader-{index}-" + "x" * 32
        path.write_text("Bearer " + token + "\n")
        path.chmod(0o600)
        paths[source] = str(path)
        tokens[token] = source
    mapping = tmp_path / "readers.json"
    mapping.write_text(__import__("json").dumps(paths))
    mapping.chmod(0o600)

    def handler(request: httpx.Request):
        token = request.headers["authorization"].removeprefix("Bearer ")
        source = tokens[token]
        rows = [] if source != "physical:graph" else [{
            "resource": {"host.name": source},
            "body": '{"source_node":"physical:graph","event_id":"event-1","observed_at":"2026-09-22T12:00:00Z"}',
        }]
        return httpx.Response(200, json={"code": 0, "data": {"content": rows}})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    hb = telemetry_views.HertzBeatResultService(
        "https://trixie.example.ts.net:14458", authorization_map_file=mapping,
        client=client, now=lambda: telemetry_views.parse_timestamp("2026-09-22T12:00:30Z"),
    )
    result = run(hb.query("event-1", "now-5m"))
    run(client.aclose())
    assert result["state"] == "fresh"
    assert len(result["datasets"]) == 6
    assert result["items"][0]["source_node"] == "physical:graph"


def test_ai_configuration_is_separate_from_collection_configuration():
    source = MODULE_PATH.read_text(encoding="utf-8")
    assert "LME_AI_API_BASE" not in source
    assert "LITELLM" not in source


def test_environment_service_uses_strict_existing_elasticsearch_tls_contract(monkeypatch):
    monkeypatch.setenv("ELASTICSEARCH_SSL_VERIFY", "true")
    monkeypatch.setenv("ELASTICSEARCH_CA_CERT", "/certs/ca/elasticsearch-ca.crt")
    service = telemetry_views.service_from_environment()
    assert service.ca_file == "/certs/ca/elasticsearch-ca.crt"
    monkeypatch.setenv("ELASTICSEARCH_SSL_VERIFY", "maybe")
    try:
        telemetry_views.service_from_environment()
    except RuntimeError as exc:
        assert "ELASTICSEARCH_SSL_VERIFY" in str(exc)
    else:
        raise AssertionError("invalid TLS boolean did not fail closed")


def test_dashboard_image_contains_registered_telemetry_module():
    dockerfile = Path("lme-dashboard/Dockerfile").read_text(encoding="utf-8")
    assert "COPY telemetry_views.py ." in dockerfile
