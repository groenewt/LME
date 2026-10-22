"""Tailscale Serve identity and capability boundary for the LME browser UI.

The service is intended to listen only on a filesystem-protected Unix socket.
Automation continues to call the dashboard directly with its API key; browser
requests reach this proxy through Tailscale Serve and never receive that key.
"""

from __future__ import annotations

import asyncio
import json
import os
import ssl
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

import httpx

try:
    from fastapi import FastAPI, Request, WebSocket
    from fastapi.responses import JSONResponse, StreamingResponse
except ModuleNotFoundError:  # Policy helpers remain usable without dashboard extras.
    FastAPI = Request = WebSocket = JSONResponse = StreamingResponse = None


IDENTITY_HEADERS = {
    "tailscale-user-login",
    "tailscale-user-name",
    "tailscale-user-profile-pic",
    "tailscale-app-capabilities",
    "x-lme-identity",
    "x-lme-authenticated-login",
}
SECRET_HEADERS = {"authorization", "proxy-authorization", "x-api-key"}
HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "te", "trailer",
    "transfer-encoding", "upgrade",
}
FORWARDING_HEADERS = {"forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto"}
WEBSOCKET_HANDSHAKE_HEADERS = {
    "sec-websocket-extensions", "sec-websocket-key", "sec-websocket-protocol", "sec-websocket-version",
}
FORWARDED_REQUEST_HEADERS = {
    "accept", "accept-encoding", "accept-language", "cache-control", "content-type",
    "if-match", "if-modified-since", "if-none-match", "if-unmodified-since",
    "last-event-id", "origin", "pragma", "range", "user-agent",
}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass(frozen=True)
class Identity:
    login: str


@dataclass(frozen=True)
class ProxyConfiguration:
    backend_api_key_file: Path
    backend_url: str = ""
    backend_ca_file: Path | None = None
    public_origin: str | None = None

    @classmethod
    def from_environment(cls) -> "ProxyConfiguration":
        return cls(
            backend_api_key_file=Path(os.getenv("LME_BACKEND_API_KEY_FILE", "/run/credentials/webui-api-key")),
            backend_url=os.getenv("LME_DASHBOARD_BACKEND_URL", ""),
            backend_ca_file=Path(os.environ["LME_BACKEND_CA_FILE"]) if os.getenv("LME_BACKEND_CA_FILE") else None,
            public_origin=os.getenv("LME_PUBLIC_ORIGIN") or None,
        )

    def backend_api_key(self) -> str:
        try:
            info = self.backend_api_key_file.stat()
        except OSError as exc:
            raise RuntimeError("backend API key file is unavailable") from exc
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise RuntimeError("backend API key file must be a private regular file")
        try:
            value = self.backend_api_key_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError("backend API key file is unreadable") from exc
        if not value:
            raise RuntimeError("backend API key file is empty")
        return value

    def backend_tls_verify(self) -> str | bool:
        parsed = urlsplit(self.backend_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise RuntimeError("dashboard backend URL must use HTTPS")
        if self.backend_ca_file is None or not self.backend_ca_file.is_file():
            raise RuntimeError("HTTPS dashboard backend requires a CA file")
        return str(self.backend_ca_file)


@dataclass(frozen=True)
class IdentityPolicy:
    operator_login_file: Path
    required_capability: str
    public_origin: str | None = None

    @classmethod
    def from_environment(cls) -> "IdentityPolicy":
        return cls(
            operator_login_file=Path(os.getenv("LME_OPERATOR_LOGIN_FILE", "/etc/lme/identity/operator-login")),
            required_capability=os.getenv("LME_REQUIRED_CAPABILITY", "cisa.gov/cap/lme-observer"),
            public_origin=os.getenv("LME_PUBLIC_ORIGIN") or None,
        )

    def _operator_login(self) -> str:
        try:
            login = self.operator_login_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise PermissionError("operator identity is not configured") from exc
        if not login or "\n" in login or "\r" in login:
            raise PermissionError("operator identity is not configured")
        return login.casefold()

    def authorize(self, headers: Mapping[str, str]) -> Identity:
        if "/" not in self.required_capability or self.required_capability.startswith("tailscale."):
            raise PermissionError("valid private application capability is required")
        normalized = {name.lower(): value for name, value in headers.items()}
        login = normalized.get("tailscale-user-login", "").strip()
        if login and login.casefold() != self._operator_login():
            raise PermissionError("tailnet operator identity required")
        raw_capabilities = normalized.get("tailscale-app-capabilities", "")
        try:
            capabilities = json.loads(raw_capabilities)
        except (TypeError, json.JSONDecodeError) as exc:
            raise PermissionError("personal device capability required") from exc
        if not isinstance(capabilities, dict):
            raise PermissionError("personal device capability required")
        grants = capabilities.get(self.required_capability)
        if (not isinstance(grants, list) or not grants
                or not any(isinstance(grant, dict) and grant.get("role") == "operator"
                           for grant in grants)):
            raise PermissionError("personal device capability required")
        return Identity(login=login or "capability-operator")

    def require_same_origin(self, method: str, headers: Mapping[str, str], scheme: str) -> None:
        if method.upper() not in MUTATING_METHODS:
            return
        normalized = {name.lower(): value for name, value in headers.items()}
        origin = normalized.get("origin", "")
        if not origin:
            raise PermissionError("mutation requires an Origin header")
        expected = self.public_origin
        if expected is None:
            host = normalized.get("host", "")
            if not host:
                raise PermissionError("mutation host is unavailable")
            expected = f"{scheme}://{host}"
        parsed_origin = urlsplit(origin)
        parsed_expected = urlsplit(expected)
        actual_tuple = (parsed_origin.scheme.lower(), parsed_origin.netloc.lower(), parsed_origin.path.rstrip("/"))
        expected_tuple = (parsed_expected.scheme.lower(), parsed_expected.netloc.lower(), parsed_expected.path.rstrip("/"))
        if actual_tuple != expected_tuple:
            raise PermissionError("cross-origin mutation denied")


def prepare_backend_headers(
    incoming: Mapping[str, str], config: ProxyConfiguration, identity_login: str
) -> dict[str, str]:
    blocked = (IDENTITY_HEADERS | SECRET_HEADERS | HOP_HEADERS | FORWARDING_HEADERS |
               WEBSOCKET_HANDSHAKE_HEADERS | {"host", "content-length", "cookie"})
    outgoing = {name.lower(): value for name, value in incoming.items()
                if name.lower() in FORWARDED_REQUEST_HEADERS and name.lower() not in blocked}
    outgoing["x-api-key"] = config.backend_api_key()
    outgoing["x-lme-authenticated-login"] = identity_login
    return outgoing


def forwarded_scheme(headers: Mapping[str, str], fallback: str) -> str:
    value = next((value for name, value in headers.items() if name.lower() == "x-forwarded-proto"), fallback)
    scheme = value.split(",", 1)[0].strip().lower()
    return scheme if scheme in {"http", "https"} else fallback


def create_app(
    config: ProxyConfiguration | None = None,
    policy: IdentityPolicy | None = None,
) -> object:
    if FastAPI is None:
        raise RuntimeError("FastAPI is required to run the identity proxy")
    config = config or ProxyConfiguration.from_environment()
    policy = policy or IdentityPolicy.from_environment()
    application = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @application.api_route("/{path:path}", methods=["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"])
    async def proxy_http(path: str, request: Request):
        try:
            identity = policy.authorize(request.headers)
            policy.require_same_origin(request.method, request.headers, forwarded_scheme(request.headers, request.url.scheme))
            headers = prepare_backend_headers(request.headers, config, identity.login)
            backend_verify = config.backend_tls_verify()
        except PermissionError as exc:
            return JSONResponse(status_code=401 if "identity" in str(exc) or "capability" in str(exc) else 403,
                                content={"detail": str(exc), "code": "identity_required"})
        except RuntimeError:
            return JSONResponse(status_code=503, content={"detail": "identity proxy is unavailable"})

        url = f"{config.backend_url.rstrip('/')}/{path}"
        if request.url.query:
            url = f"{url}?{request.url.query}"
        body = await request.body()
        client = httpx.AsyncClient(timeout=None, follow_redirects=False, verify=backend_verify)
        backend_request = client.build_request(request.method, url, headers=headers, content=body)
        try:
            response = await client.send(backend_request, stream=True)
        except httpx.HTTPError:
            await client.aclose()
            return JSONResponse(status_code=502, content={"detail": "dashboard backend unavailable"})

        response_headers = {
            name: value for name, value in response.headers.items()
            if name.lower() not in HOP_HEADERS and name.lower() != "content-length"
        }

        async def stream():
            try:
                async for chunk in response.aiter_raw():
                    yield chunk
            finally:
                await response.aclose()
                await client.aclose()

        return StreamingResponse(stream(), status_code=response.status_code,
                                 headers=response_headers, media_type=response.headers.get("content-type"))

    @application.websocket("/{path:path}")
    async def proxy_websocket(path: str, websocket: WebSocket):
        try:
            identity = policy.authorize(websocket.headers)
            # WebSockets can carry mutations, so an exact browser origin is mandatory.
            scheme = forwarded_scheme(websocket.headers, websocket.url.scheme.replace("ws", "http", 1))
            policy.require_same_origin("POST", websocket.headers, scheme)
            headers = prepare_backend_headers(websocket.headers, config, identity.login)
            backend_verify = config.backend_tls_verify()
        except (PermissionError, RuntimeError):
            await websocket.close(code=1008)
            return
        try:
            from websockets.asyncio.client import connect
            target = config.backend_url.replace("http://", "ws://", 1).replace("https://", "wss://", 1)
            target = f"{target.rstrip('/')}/{path}"
            if websocket.url.query:
                target = f"{target}?{websocket.url.query}"
            ssl_context = None
            if target.startswith("wss://"):
                ssl_context = ssl.create_default_context(cafile=str(backend_verify))
            subprotocols = [
                item.strip()
                for item in websocket.headers.get("sec-websocket-protocol", "").split(",")
                if item.strip()
            ]
            async with connect(target, additional_headers=headers, ssl=ssl_context,
                               subprotocols=subprotocols or None) as backend:
                await websocket.accept(subprotocol=backend.subprotocol)
                async def browser_to_backend():
                    while True:
                        message = await websocket.receive()
                        if message["type"] == "websocket.disconnect":
                            return
                        await backend.send(message.get("bytes") if message.get("bytes") is not None else message.get("text", ""))

                async def backend_to_browser():
                    async for message in backend:
                        if isinstance(message, bytes):
                            await websocket.send_bytes(message)
                        else:
                            await websocket.send_text(message)

                pumps = {
                    asyncio.create_task(browser_to_backend()),
                    asyncio.create_task(backend_to_browser()),
                }
                _done, pending = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pumps, return_exceptions=True)
        except Exception:
            await websocket.close(code=1011)

    return application


try:
    app = create_app()
except RuntimeError:  # Allows policy-only tooling where dashboard extras are absent.
    app = None
