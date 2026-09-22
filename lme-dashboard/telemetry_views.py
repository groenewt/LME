"""Generic live telemetry views backed by authenticated Elasticsearch queries."""

from __future__ import annotations

import os
import re
import json
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx

try:
    from fastapi import APIRouter, HTTPException, Query
except ModuleNotFoundError:  # Query service remains usable by validation tooling.
    APIRouter = None

    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    def Query(default):
        return default


TIME_RANGE = re.compile(r"^now-(\d+)([mhd])$")
DEFAULT_STALE_SECONDS = 300
TRUE_VALUES = {"1", "true", "yes", "on"}
FALSE_VALUES = {"0", "false", "no", "off"}
EVENT_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


class HertzBeatResultService:
    """Read one source-scoped native HertzBeat result dataset by exact event ID."""

    def __init__(self, origin: str, authorization_file: str | Path | None = None, *,
                 authorization_map_file: str | Path | None = None, ca_file: str | bool = True,
                 client: httpx.AsyncClient | None = None, now: Callable[[], datetime] | None = None):
        parsed = urlsplit(origin)
        if parsed.scheme != "https" or not parsed.hostname or parsed.path or parsed.query or parsed.fragment:
            raise ValueError("HertzBeat scoped read origin must be an HTTPS origin")
        self.origin = origin.rstrip("/")
        if not authorization_file and not authorization_map_file:
            raise ValueError("HertzBeat scoped read authorization is required")
        self.authorization_file = Path(authorization_file) if authorization_file else None
        self.authorization_map_file = Path(authorization_map_file) if authorization_map_file else None
        self.ca_file = ca_file
        self.client = client
        self.now = now or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def _private_text(path: Path) -> str:
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError("authorization file must be private and regular")
            return path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ValueError("authorization file is unavailable") from exc

    def _authorization(self, path: Path) -> str:
        value = self._private_text(path)
        if not re.fullmatch(r"Bearer [A-Za-z0-9_.~-]{32,512}", value):
            raise ValueError("authorization file is invalid")
        return value

    def _readers(self) -> dict[str, Path]:
        if self.authorization_map_file is None:
            return {"configured-source": self.authorization_file}
        try:
            value = json.loads(self._private_text(self.authorization_map_file))
        except (ValueError, json.JSONDecodeError) as exc:
            raise ValueError("HertzBeat reader map is invalid") from exc
        expected = {f"{scope}:{node}" for scope in ("physical", "guest")
                    for node in ("graph", "trixie", "silmaril")}
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("HertzBeat reader map must cover all six Linux sources")
        result = {}
        for source, raw_path in value.items():
            path = Path(raw_path)
            if not path.is_absolute() or ".." in path.parts:
                raise ValueError("HertzBeat reader path is invalid")
            result[source] = path
        return result

    @staticmethod
    def _seconds(time_from: str) -> int:
        match = TIME_RANGE.fullmatch(time_from)
        if not match:
            raise HTTPException(status_code=422, detail="time_from must be now-<integer><m|h|d>")
        scale = {"m": 60, "h": 3600, "d": 86400}[match.group(2)]
        return min(int(match.group(1)) * scale, 300)

    async def query(self, event_id: str, time_from: str) -> dict[str, Any]:
        if not EVENT_ID.fullmatch(event_id):
            raise HTTPException(status_code=422, detail="HertzBeat queries require an exact bounded event ID")
        seconds = self._seconds(time_from)
        end = int(self.now().timestamp() * 1000)
        params = {"start": max(0, end - seconds * 1000), "end": end, "search": event_id,
                  "pageIndex": 0, "pageSize": 200}
        owned_client = self.client is None
        client = self.client or httpx.AsyncClient(verify=self.ca_file, timeout=10.0)
        try:
            items = []
            datasets = []
            for expected_source, authorization_path in self._readers().items():
                try:
                    response = await client.get(
                        self.origin + "/api/observability/logs", params=params,
                        headers={"Authorization": self._authorization(authorization_path),
                                 "Accept": "application/json"},
                    )
                    response.raise_for_status()
                    payload = response.json()
                    if payload.get("code") != 0 or not isinstance(payload.get("data"), dict):
                        raise ValueError("invalid HertzBeat response")
                    rows = payload["data"].get("content")
                    if not isinstance(rows, list) or len(rows) > 200:
                        raise ValueError("invalid HertzBeat result dataset")
                    for row in rows:
                        if not isinstance(row, dict) or not isinstance(row.get("resource"), dict):
                            raise ValueError("invalid HertzBeat result row")
                        source = row["resource"].get("host.name")
                        body = row.get("body")
                        body = json.loads(body) if isinstance(body, str) else body
                        if (not isinstance(source, str) or not isinstance(body, dict)
                                or (expected_source != "configured-source" and source != expected_source)
                                or body.get("source_node") != source or body.get("event_id") != event_id):
                            raise ValueError("HertzBeat result binding mismatch")
                        items.append({"resource": row["resource"], **body})
                    datasets.append({"source": expected_source, "state": "fresh" if rows else "empty"})
                except (httpx.HTTPError, ValueError, KeyError, TypeError, json.JSONDecodeError, OSError):
                    datasets.append({"source": expected_source, "state": "unavailable"})
            result = {"state": "empty", "items": [], "total": 0, "freshness": None, "reason": None}
            if items:
                stamp = items[0].get("occurred_at", items[0].get("observed_at"))
                freshness = None
                state = "stale"
                if stamp:
                    age = max(0, int((self.now() - parse_timestamp(str(stamp))).total_seconds()))
                    freshness = {"observed_at": stamp, "age_seconds": age,
                                 "threshold_seconds": DEFAULT_STALE_SECONDS}
                    state = "stale" if age > DEFAULT_STALE_SECONDS else "fresh"
                result.update(state=state, items=items, total=len(items), freshness=freshness)
            unavailable = sum(dataset["state"] == "unavailable" for dataset in datasets)
            if unavailable:
                reason = "hertzbeat_unavailable" if unavailable == len(datasets) else "hertzbeat_partial_unavailable"
                result.update(state="unavailable", reason=reason)
            result["datasets"] = datasets
            result["query_window"] = {"requested": time_from, "effective_seconds": seconds,
                                      "clipped": seconds < int(TIME_RANGE.fullmatch(time_from).group(1)) *
                                      {"m": 60, "h": 3600, "d": 86400}[TIME_RANGE.fullmatch(time_from).group(2)]}
            return result
        except HTTPException:
            raise
        except (httpx.HTTPError, ValueError, KeyError, TypeError, json.JSONDecodeError, OSError):
            return {"state": "unavailable", "items": [], "total": None, "freshness": None,
                    "reason": "hertzbeat_unavailable"}
        finally:
            if owned_client:
                await client.aclose()


class TelemetryViewService:
    def __init__(
        self,
        es_url: str,
        es_user: str,
        es_password: str,
        *,
        ca_file: str | bool = False,
        stale_seconds: int = DEFAULT_STALE_SECONDS,
        client: httpx.AsyncClient | None = None,
        now: Callable[[], datetime] | None = None,
        hertzbeat: HertzBeatResultService | None = None,
    ):
        self.es_url = es_url.rstrip("/")
        self.auth = (es_user, es_password)
        self.ca_file = ca_file
        self.stale_seconds = stale_seconds
        self.client = client
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.hertzbeat = hertzbeat

    async def _request(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        owned_client = self.client is None
        client = self.client or httpx.AsyncClient(verify=self.ca_file, timeout=10.0)
        try:
            response = await client.post(f"{self.es_url}/{index}/_search", auth=self.auth, json=body)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload.get("hits"), dict):
                raise ValueError("missing Elasticsearch hits")
            return payload
        finally:
            if owned_client:
                await client.aclose()

    @staticmethod
    def _query_body(time_from: str, query: str | None, source: str | None, size: int) -> dict[str, Any]:
        if not TIME_RANGE.fullmatch(time_from):
            raise HTTPException(status_code=422, detail="time_from must be now-<integer><m|h|d>")
        filters: list[dict[str, Any]] = [{"range": {"@timestamp": {"gte": time_from, "lte": "now"}}}]
        if source:
            filters.append({"term": {"event.dataset": source}})
        must = []
        if query:
            must.append({"simple_query_string": {"query": query, "fields": ["message", "event.*", "service.*", "host.*"]}})
        return {
            "size": size,
            "sort": [{"@timestamp": "desc"}],
            "track_total_hits": True,
            "query": {"bool": {"filter": filters, "must": must}},
        }

    def _result(self, payload: dict[str, Any], *, filtered: bool) -> dict[str, Any]:
        hits = payload["hits"]
        raw_total = hits.get("total", 0)
        total = raw_total.get("value", 0) if isinstance(raw_total, dict) else int(raw_total)
        items = [
            {"id": hit.get("_id"), "index": hit.get("_index"), **(hit.get("_source") or {})}
            for hit in hits.get("hits", [])
        ]
        if not items:
            return {"state": "filtered_empty" if filtered else "empty", "items": [], "total": total,
                    "freshness": None, "reason": None}
        latest_raw = items[0].get("@timestamp")
        freshness = None
        state = "fresh"
        if latest_raw:
            try:
                age = max(0, int((self.now() - parse_timestamp(str(latest_raw))).total_seconds()))
                freshness = {"observed_at": latest_raw, "age_seconds": age, "threshold_seconds": self.stale_seconds}
                state = "stale" if age > self.stale_seconds else "fresh"
            except (TypeError, ValueError):
                state = "stale"
        else:
            state = "stale"
        return {"state": state, "items": items, "total": total, "freshness": freshness, "reason": None}

    async def _view(self, index: str, time_from: str, query: str | None, source: str | None) -> dict[str, Any]:
        filtered = bool(query or source)
        try:
            payload = await self._request(index, self._query_body(time_from, query, source, 100))
            result = self._result(payload, filtered=False)
            if result["state"] == "empty" and filtered:
                baseline = await self._request(index, self._query_body(time_from, None, None, 0))
                baseline_total = baseline["hits"].get("total", 0)
                if isinstance(baseline_total, dict):
                    baseline_total = baseline_total.get("value", 0)
                if int(baseline_total) > 0:
                    result["state"] = "filtered_empty"
            return result
        except HTTPException:
            raise
        except (httpx.HTTPError, ValueError, KeyError, TypeError, RuntimeError, OSError):
            return {"state": "unavailable", "items": [], "total": None, "freshness": None,
                    "reason": "elasticsearch_unavailable"}

    async def logs(self, time_from: str, query: str | None, source: str | None):
        return await self._view("lme-typed-logs-*,logs-*,filebeat-*,wazuh-*", time_from, query, source)

    async def metrics(self, time_from: str, query: str | None, source: str | None):
        return await self._view("lme-native-metrics-*,metrics-*,hertzbeat-metrics-*", time_from, query, source)

    async def monitoring(self, time_from: str, query: str | None, source: str | None):
        return await self._view("logs-lme.monitoring-*,lme-monitoring-*", time_from, query, source)

    async def source(self, source_id: str, time_from: str = "now-15m", query: str | None = None):
        if source_id == "windows-physical":
            return {"source": source_id, "state": "not_applicable", "items": [], "total": None,
                    "freshness": None, "reason": "windows_inspection_not_authorized"}
        if source_id == "hertzbeat":
            if self.hertzbeat is None:
                return {"source": source_id, "state": "unavailable", "items": [], "total": None,
                        "freshness": None, "reason": "hertzbeat_unconfigured"}
            if not query:
                return {"source": source_id, "state": "unavailable", "items": [], "total": None,
                        "freshness": None, "reason": "exact_event_id_required"}
            result = await self.hertzbeat.query(query, time_from)
            return {"source": source_id, **result}
        indexes = {
            "elastic-logs": "lme-typed-logs-*,logs-*",
            "elastic-metrics": "lme-native-metrics-*,metrics-*",
            "monitoring": "logs-lme.monitoring-*,lme-monitoring-*",
        }
        if source_id not in indexes:
            raise HTTPException(status_code=404, detail="unknown telemetry source")
        result = await self._view(indexes[source_id], time_from, None, None)
        return {"source": source_id, **result}


def service_from_environment() -> TelemetryViewService:
    raw_verify = os.getenv("ELASTICSEARCH_SSL_VERIFY", "true").strip().lower()
    if raw_verify in TRUE_VALUES:
        verify_value: str | bool = os.getenv("ELASTICSEARCH_CA_CERT", "/certs/ca/elasticsearch-ca.crt")
    elif raw_verify in FALSE_VALUES:
        verify_value = False
    else:
        raise RuntimeError("ELASTICSEARCH_SSL_VERIFY must be an explicit boolean")
    hb_origin = os.getenv("HERTZBEAT_SCOPED_READ_URL", "")
    hb_auth = os.getenv("HERTZBEAT_SCOPED_READ_AUTH_FILE", "")
    hb_readers = os.getenv("HERTZBEAT_SCOPED_READERS_FILE", "")
    hb = None
    if hb_origin and (hb_auth or hb_readers):
        hb_verify: str | bool = os.getenv("HERTZBEAT_SCOPED_READ_CA_CERT") or True
        hb = HertzBeatResultService(hb_origin, hb_auth or None,
                                    authorization_map_file=hb_readers or None, ca_file=hb_verify)
    return TelemetryViewService(
        os.getenv("ELASTICSEARCH_URL", "https://lme-elasticsearch:9200"),
        os.getenv("ELASTICSEARCH_USER", "elastic"),
        os.getenv("ELASTICSEARCH_PASSWORD", ""),
        ca_file=verify_value,
        stale_seconds=int(os.getenv("LME_TELEMETRY_STALE_SECONDS", str(DEFAULT_STALE_SECONDS))),
        hertzbeat=hb,
    )


def create_router(service: TelemetryViewService | None = None):
    if APIRouter is None:
        raise RuntimeError("FastAPI is required to create telemetry routes")
    api = APIRouter(prefix="/api/telemetry", tags=["telemetry"])

    def current() -> TelemetryViewService:
        return service or service_from_environment()

    @api.get("/logs")
    async def logs(time_from: str = "now-15m", q: str | None = None, source: str | None = None):
        return await current().logs(time_from, q, source)

    @api.get("/metrics")
    async def metrics(time_from: str = "now-15m", q: str | None = None, source: str | None = None):
        return await current().metrics(time_from, q, source)

    @api.get("/monitoring")
    async def monitoring(time_from: str = "now-15m", q: str | None = None, source: str | None = None):
        return await current().monitoring(time_from, q, source)

    @api.get("/sources")
    async def sources(time_from: str = Query("now-15m")):
        names = ("elastic-logs", "elastic-metrics", "monitoring", "hertzbeat", "windows-physical")
        return {"sources": [await current().source(name, time_from) for name in names]}

    @api.get("/sources/{source_id}")
    async def source(source_id: str, time_from: str = Query("now-15m"), q: str | None = None):
        return await current().source(source_id, time_from, q)

    @api.get("/hertzbeat-results")
    async def hertzbeat_results(event_id: str, time_from: str = Query("now-5m")):
        return await current().source("hertzbeat", time_from, event_id)

    return api


router = create_router() if APIRouter is not None else None
