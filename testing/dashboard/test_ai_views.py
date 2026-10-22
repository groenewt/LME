import asyncio
import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest


MODULE_PATH = Path("lme-dashboard/ai_views.py")


def load_module():
    assert MODULE_PATH.is_file(), "ai_views.py must provide the isolated model probe"
    spec = importlib.util.spec_from_file_location("ai_views", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(coro):
    return asyncio.run(coro)


def test_model_probe_calls_actual_completion_and_returns_bounded_provenance():
    ai_views = load_module()
    observed = {}

    def handler(request: httpx.Request):
        observed["path"] = request.url.path
        observed["authorization"] = request.headers.get("authorization")
        observed["payload"] = json.loads(request.content)
        return httpx.Response(200, json={
            "id": "chatcmpl-provider-1",
            "model": "reported-model",
            "created": 1790078400,
            "choices": [{
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": "probe-00000000-0000-4000-8000-000000000001"},
            }],
            "usage": {"prompt_tokens": 12, "completion_tokens": 3, "total_tokens": 15},
        })

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    service = ai_views.ModelProbeService(
        "https://litellm.test:4000", "private-key", "requested-model", "a" * 64, client=client,
        now=lambda: datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc),
    )
    result = run(service.probe("probe-00000000-0000-4000-8000-000000000001"))
    run(client.aclose())

    assert observed["path"] == "/v1/chat/completions"
    assert observed["authorization"] == "Bearer private-key"
    assert observed["payload"]["model"] == "requested-model"
    assert "probe-00000000-0000-4000-8000-000000000001" in json.dumps(observed["payload"])
    assert result == {
        "state": "available",
        "probe_id": "probe-00000000-0000-4000-8000-000000000001",
        "requested_model": "requested-model",
        "reported_model": "reported-model",
        "model_revision": "a" * 64,
        "provider_response_id": "chatcmpl-provider-1",
        "provider_created": 1790078400,
        "finish_reason": "stop",
        "response_sha256": hashlib.sha256(
            b"probe-00000000-0000-4000-8000-000000000001"
        ).hexdigest(),
        "nonce_round_trip": True,
        "usage": {"prompt_tokens": 12, "completion_tokens": 3, "total_tokens": 15},
        "observed_at": "2026-09-22T12:00:00Z",
    }
    assert "content" not in result


def test_model_probe_failure_is_structured_and_does_not_query_collection_backends():
    ai_views = load_module()
    requests = []

    def handler(request: httpx.Request):
        requests.append(str(request.url))
        raise httpx.ConnectError("model offline", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    service = ai_views.ModelProbeService(
        "https://litellm.test:4000", "private-key", "requested-model", "a" * 64, client=client,
    )
    with pytest.raises(ai_views.ModelUnavailable) as caught:
        run(service.probe("probe-00000000-0000-4000-8000-000000000002"))
    run(client.aclose())

    assert caught.value.detail == {
        "state": "unavailable",
        "reason": "model_unreachable",
        "probe_id": "probe-00000000-0000-4000-8000-000000000002",
        "requested_model": "requested-model",
        "model_revision": "a" * 64,
    }
    assert requests == ["https://litellm.test:4000/v1/chat/completions"]


@pytest.mark.parametrize("probe_id", ["", "short", "spaces are forbidden", "x" * 129])
def test_model_probe_rejects_unbounded_or_ambiguous_probe_ids(probe_id):
    ai_views = load_module()
    service = ai_views.ModelProbeService(
        "https://litellm.test:4000", "private-key", "requested-model", "a" * 64,
        client=httpx.AsyncClient(transport=httpx.MockTransport(lambda _: None)),
    )
    with pytest.raises(ai_views.InvalidProbeId):
        run(service.probe(probe_id))
    run(service.client.aclose())


def test_model_probe_configuration_requires_https_and_strict_tls(monkeypatch, tmp_path):
    ai_views = load_module()
    with pytest.raises(ValueError, match="HTTPS origin"):
        ai_views.ModelProbeService("http://litellm.test:4000", "private-key", "model", "a" * 64)

    monkeypatch.setenv("LITELLM_URL", "https://litellm.test:4000")
    monkeypatch.setenv("LITELLM_API_KEY", "private-key")
    monkeypatch.setenv("LITELLM_MODEL", "model")
    provenance = tmp_path / "model.json"
    provenance.write_text(json.dumps({"model": "model.gguf", "alias": "model", "sha256": "a" * 64}))
    monkeypatch.setenv("LME_AI_MODEL_PROVENANCE_FILE", str(provenance))
    monkeypatch.setenv("LITELLM_SSL_VERIFY", "maybe")
    with pytest.raises(RuntimeError, match="LITELLM_SSL_VERIFY"):
        ai_views.service_from_environment()


def test_dashboard_image_and_app_register_ai_probe_module():
    load_module()
    dockerfile = Path("lme-dashboard/Dockerfile").read_text(encoding="utf-8")
    app = Path("lme-dashboard/app.py").read_text(encoding="utf-8")
    assert "COPY ai_views.py ." in dockerfile
    assert "from ai_views import router as ai_router" in app
    assert "app.include_router(ai_router)" in app
