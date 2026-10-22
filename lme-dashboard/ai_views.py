"""Bounded model probe with artifact-backed provenance and no data retrieval."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx

try:
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel
except ModuleNotFoundError:  # The service remains usable by validation tooling.
    APIRouter = None

    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: Any):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    class BaseModel:
        pass


PROBE_ID = re.compile(r"^[A-Za-z0-9_.:-]{16,128}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
TRUE_VALUES = {"1", "true", "yes", "on"}


class InvalidProbeId(ValueError):
    """The supplied probe identifier cannot be used as a bounded nonce."""


class ModelUnavailable(Exception):
    """A real completion could not produce trustworthy provenance."""

    def __init__(self, detail: dict[str, Any]):
        super().__init__(detail["reason"])
        self.detail = detail


class ModelProbeService:
    def __init__(
        self,
        origin: str,
        api_key: str,
        model: str,
        model_revision: str,
        *,
        ca_file: str | bool = True,
        client: httpx.AsyncClient | None = None,
        now: Callable[[], datetime] | None = None,
    ):
        parsed = urlsplit(origin)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.path
                or parsed.query or parsed.fragment or parsed.username or parsed.password):
            raise ValueError("LiteLLM model probe requires an HTTPS origin")
        if not api_key or not model:
            raise ValueError("LiteLLM model probe requires a key and model")
        if not SHA256.fullmatch(model_revision):
            raise ValueError("model revision must be an artifact SHA-256")
        self.origin = origin.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.model_revision = model_revision
        self.ca_file = ca_file
        self.client = client
        self.now = now or (lambda: datetime.now(timezone.utc))

    def _unavailable(self, probe_id: str, reason: str, **extra: Any) -> ModelUnavailable:
        return ModelUnavailable({
            "state": "unavailable",
            "reason": reason,
            "probe_id": probe_id,
            "requested_model": self.model,
            "model_revision": self.model_revision,
            **extra,
        })

    async def probe(self, probe_id: str) -> dict[str, Any]:
        if not PROBE_ID.fullmatch(probe_id):
            raise InvalidProbeId("probe_id must be 16-128 bounded token characters")
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": "Return the supplied probe token exactly and add no other text.",
                },
                {"role": "user", "content": probe_id},
            ],
            "temperature": 0,
            "max_tokens": 64,
            "stream": False,
        }
        owned_client = self.client is None
        client = self.client or httpx.AsyncClient(verify=self.ca_file, timeout=15.0)
        try:
            try:
                response = await client.post(
                    self.origin + "/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                    json=payload,
                )
            except httpx.HTTPError as exc:
                raise self._unavailable(probe_id, "model_unreachable") from exc
            if response.status_code >= 400:
                raise self._unavailable(
                    probe_id, "model_upstream_rejected", upstream_status=response.status_code
                )
            try:
                result = response.json()
                choice = result["choices"][0]
                content = choice["message"]["content"]
                reported_model = result["model"]
                response_id = result["id"]
                finish_reason = choice["finish_reason"]
                created = result.get("created")
                usage_raw = result.get("usage") or {}
                if not all(isinstance(value, str) and value for value in (
                    content, reported_model, response_id, finish_reason
                )):
                    raise ValueError("missing completion provenance")
                usage = {
                    name: int(usage_raw[name])
                    for name in ("prompt_tokens", "completion_tokens", "total_tokens")
                    if isinstance(usage_raw.get(name), int) and usage_raw[name] >= 0
                }
            except (ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError) as exc:
                raise self._unavailable(probe_id, "invalid_model_response") from exc
            observed = self.now().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            return {
                "state": "available",
                "probe_id": probe_id,
                "requested_model": self.model,
                "reported_model": reported_model,
                "model_revision": self.model_revision,
                "provider_response_id": response_id,
                "provider_created": created,
                "finish_reason": finish_reason,
                "response_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                "nonce_round_trip": probe_id in content,
                "usage": usage,
                "observed_at": observed,
            }
        finally:
            if owned_client:
                await client.aclose()


def _model_revision(path: str | Path, expected_alias: str) -> str:
    source = Path(path)
    try:
        info = source.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("model provenance must be a regular file")
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("model provenance file is unavailable or invalid") from exc
    revision = document.get("sha256")
    alias = document.get("alias")
    if not SHA256.fullmatch(revision or "") or alias != expected_alias:
        raise RuntimeError("model provenance does not match the active model alias")
    return revision


def service_from_environment() -> ModelProbeService:
    raw_verify = os.getenv("LITELLM_SSL_VERIFY", "true").strip().lower()
    if raw_verify not in TRUE_VALUES:
        raise RuntimeError("LITELLM_SSL_VERIFY must remain enabled for the model probe")
    model = os.getenv("LITELLM_MODEL", "lfm2.5-1.2b-instruct")
    provenance_file = os.getenv(
        "LME_AI_MODEL_PROVENANCE_FILE",
        os.getenv("LLAMA_MODEL_CONFIG", "/opt/lme/config/llama-cpp-model.json"),
    )
    return ModelProbeService(
        os.getenv("LITELLM_URL", "https://lme-litellm:4000"),
        os.getenv("LITELLM_API_KEY", ""),
        model,
        _model_revision(provenance_file, model),
        ca_file=os.getenv("LITELLM_CA_CERT", "/certs/ca/litellm-ca.crt"),
    )


class ProbeRequest(BaseModel):
    probe_id: str


def create_router(service: ModelProbeService | None = None):
    if APIRouter is None:
        raise RuntimeError("FastAPI is required to create AI routes")
    api = APIRouter(prefix="/api/ai", tags=["ai"])

    @api.post("/model-probe")
    async def model_probe(request: ProbeRequest):
        try:
            return await (service or service_from_environment()).probe(request.probe_id)
        except InvalidProbeId as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except (RuntimeError, ValueError) as exc:
            detail = {"state": "unavailable", "reason": "model_configuration_unavailable",
                      "probe_id": request.probe_id}
            raise HTTPException(status_code=503, detail=detail) from exc
        except ModelUnavailable as exc:
            raise HTTPException(status_code=503, detail=exc.detail) from exc

    return api


router = create_router() if APIRouter is not None else None
