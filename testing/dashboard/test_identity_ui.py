from pathlib import Path
import hashlib
import json
import re


HTML = Path("lme-dashboard/static/index.html").read_text(encoding="utf-8")
JS = Path("lme-dashboard/static/dashboard.js").read_text(encoding="utf-8")
UI = HTML + JS


def test_browser_handles_identity_proxy_401_without_api_key_prompt():
    assert "identityRequired" in UI
    assert "response.status === 401" in JS
    assert "Sign in through your tailnet" in HTML


def test_ui_renders_all_telemetry_states_and_source_views():
    for state in ("fresh", "stale", "empty", "filtered_empty", "unavailable", "not_applicable"):
        assert state in UI
    for endpoint in ("/api/telemetry/logs", "/api/telemetry/metrics", "/api/telemetry/monitoring", "/api/telemetry/sources"):
        assert endpoint in UI
    assert "/api/telemetry/hertzbeat-results" in JS
    assert "Exact event ID" in HTML
    assert "windows_inspection_not_authorized" in JS


def test_failed_ai_state_does_not_block_telemetry_loading():
    assert "loadTelemetry" in JS
    init = JS.split("async init()", 1)[1].split("async loadHealth()", 1)[0]
    assert "loadTelemetry" in init


def test_streamed_ai_answer_is_complete_only_after_done_and_marks_partial_failures():
    send_chat = JS.split("async sendChat()", 1)[1].split("scrollChat()", 1)[0]
    assert "new AbortController()" in send_chat
    assert "status: 'pending'" in send_chat
    assert "payload === '[DONE]'" in send_chat
    assert "status = 'completed'" in send_chat
    assert "status = 'failed'" in send_chat
    assert "Incomplete response" in send_chat
    assert "if (!completed)" in send_chat
    assert send_chat.index("status = 'completed'") < send_chat.index("this.chat.thinking = false")


def test_frontend_executes_only_pinned_local_assets_under_csp():
    assert not re.search(r"<script(?![^>]*\bsrc=)", HTML)
    assert "https://cdn.tailwindcss.com" not in HTML
    assert "https://unpkg.com" not in HTML
    assert "script-src &apos;self&apos;" in HTML
    assert "unsafe-eval" not in HTML
    assert '/static/dashboard.js' in HTML
    assert '/static/vendor/alpine-csp.min.js' in HTML
    assert '/static/app.css' in HTML

    lock = json.loads(Path("lme-dashboard/frontend-assets.lock.json").read_text())
    alpine = Path("lme-dashboard/static/vendor/alpine-csp.min.js").read_bytes()
    assert hashlib.sha256(alpine).hexdigest() == lock["assets"]["alpine-csp"]["sha256"]
    app = Path("lme-dashboard/app.py").read_text(encoding="utf-8")
    assert "Content-Security-Policy" in app
    assert "script-src 'self'" in app
    assert "unsafe-eval" not in app
    assert "frame-ancestors 'none'" in app
