import streamlit as st
import requests
import os
import hmac
import ssl
import urllib3
import json

from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

st.set_page_config(page_title="LME Security Alerts", layout="wide")

# Initialize chat history in session state
if "chat_messages" not in st.session_state:
    st.session_state.chat_messages = []

# Get credentials
ES_URL = os.getenv("ELASTICSEARCH_URL", "https://lme-elasticsearch:9200")
ES_USER = os.getenv("ELASTICSEARCH_USER", "elastic")
ES_PASS = os.getenv("ELASTICSEARCH_PASSWORD", "")
# ── Elasticsearch TLS verification (env-gated; manifest-declared) ─────────────
# DEFAULT ("false") preserves today's posture: verify=False on the ES call. When
# ELASTICSEARCH_SSL_VERIFY is enabled the ES call verifies the certificate chain
# against ELASTICSEARCH_CA_CERT but SKIPS hostname (Path-1): the cross-host
# consumer dials a ts.net FQDN absent from the internal-CA leaf SAN. The CA-path
# VALUE is manifest-declared (not baked in) and lands in-container at
# /certs/ca/ca.crt (where the podman distribute-CA step overlays the CA).
ES_SSL_VERIFY = os.getenv("ELASTICSEARCH_SSL_VERIFY", "false")
ES_CA_CERT = os.getenv("ELASTICSEARCH_CA_CERT", "/certs/ca/ca.crt")
LITELLM_URL = os.getenv("LITELLM_URL", "https://lme-litellm:4000")
LITELLM_KEY = os.getenv("LITELLM_API_KEY")
if not LITELLM_KEY:
    # Fail closed: never fall back to a hardcoded proxy key. LITELLM_API_KEY is
    # injected from the per-install podman secret `litellm_master_key`.
    raise RuntimeError(
        "LITELLM_API_KEY is not set. The log analyzer requires the LiteLLM proxy "
        "master key (podman secret 'litellm_master_key') to be injected as "
        "LITELLM_API_KEY. Refusing to start without proxy credentials."
    )
LITELLM_MODEL = os.getenv("LITELLM_MODEL", "lfm2.5-1.2b-instruct")

# ── Inbound auth (WebUI API key) ─────────────────────────────────────────────
# Mirror of the outbound LiteLLM master-key guard above: production injects
# WEBUI_API_KEY from the per-install podman secret `webui_api_key`. This is a
# real viewer gate (not the server-side ES password check below): when the key
# is set, raw alert _source data is never served until the viewer presents it.
WEBUI_API_KEY = os.getenv("WEBUI_API_KEY")


# ── ES TLS transport (honors the env-gated toggle declared above) ─────────────
_ES_TRUTHY = {"1", "true", "yes", "on"}
_ES_FALSY = {"0", "false", "no", "off", ""}


def _es_verify_enabled(raw) -> bool:
    """Interpret ELASTICSEARCH_SSL_VERIFY. Allowlist-truthy so a typo degrades to
    today's behavior (verification OFF) instead of silently claiming a
    verification the operator did not actually get. A non-empty *unrecognized*
    value warns and still defaults OFF (avoids the insecure-success failure class).
    """
    val = str(raw).strip().lower()
    if val in _ES_TRUTHY:
        return True
    if val in _ES_FALSY:
        return False
    st.warning(
        f"ELASTICSEARCH_SSL_VERIFY={raw!r} not recognized; "
        "Elasticsearch TLS verification is OFF."
    )
    return False


class _CAVerifyAdapter(HTTPAdapter):
    """requests adapter: verify the ES chain against a CA but SKIP hostname.

    requests' verify= cannot take an ssl.SSLContext, so the context is injected
    into the urllib3 PoolManager. check_hostname=False is the primary skip-
    hostname mechanism; assert_hostname=False is belt-and-suspenders. Path-1: the
    cross-host consumer dials a ts.net FQDN not in the internal-CA leaf SAN, so a
    full hostname check would fail without a SAN mint.
    """

    def __init__(self, cafile, *args, **kwargs):
        self._cafile = cafile
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context(cafile=self._cafile)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        kwargs["ssl_context"] = ctx
        kwargs["assert_hostname"] = False
        return super().init_poolmanager(*args, **kwargs)


def _es_transport():
    """Return (http, verify) for the ES call, honoring the env-gated toggle.

    OFF (default): (requests, False) -- byte-identical to today's
    `requests.post(..., verify=False)`. We return the module itself, not a
    Session: the module opens a fresh connection per call, whereas a Session
    would silently add connection pooling (a behavior change).
    ON: (Session mounted with _CAVerifyAdapter, ELASTICSEARCH_CA_CERT). Passing
    the CA *path* as verify= keeps requests' internal cert_reqs=CERT_REQUIRED
    aligned with the injected context and pins trust to exactly this CA
    (verify=False would reset the context to CERT_NONE; verify=True would widen
    the anchor set with certifi).
    """
    if not _es_verify_enabled(ES_SSL_VERIFY):
        return requests, False
    session = requests.Session()
    session.mount("https://", _CAVerifyAdapter(ES_CA_CERT))
    return session, ES_CA_CERT


# NOTE: Streamlit re-executes this whole script on every interaction, so this
# rebuilds the Session/adapter/SSLContext (and re-reads the CA) each rerun. Left
# uncached for a minimal diff; @st.cache_resource is the declined optimization.
# The OFF (default) path builds no context and touches no filesystem.
_ES_HTTP, _ES_VERIFY = _es_transport()


def require_webui_auth():
    """Gate the whole app on WEBUI_API_KEY before any alert data is rendered.

    Fail-closed when the key is set (always, in production): the viewer must
    enter it at the password prompt. Unset (local dev) leaves the app open,
    mirroring the dashboard middleware. The key is deliberately NOT accepted
    via a URL query parameter -- a `?api_key=` GET leaks the secret into
    browser history, the Referer header, and reverse-proxy/access logs
    (flagged by the automated security review). The prompt keeps it in
    server-side st.session_state only.
    """
    if not WEBUI_API_KEY:
        return
    if st.session_state.get("_webui_authed"):
        return

    st.title("🔒 LME Security Alerts")
    entered = st.text_input(
        "API key", type="password", help="Enter the WebUI API key to continue"
    )
    if entered and hmac.compare_digest(entered.encode(), WEBUI_API_KEY.encode()):
        st.session_state["_webui_authed"] = True
        st.rerun()
    elif entered:
        st.error("Invalid API key")
    st.stop()


require_webui_auth()

# Define LLM functions
def chat_with_llm(messages):
    """Send chat messages to LLM"""
    try:
        response = requests.post(
            f"{LITELLM_URL}/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {LITELLM_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": LITELLM_MODEL,
                "messages": messages,
                "temperature": 0.7,
                "max_tokens": 500
            },
            verify=False,
            timeout=300
        )
        response.raise_for_status()
        result = response.json()
        return result["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Error: {e}"

def analyze_with_llm(alert_data):
    """Send alert to LLM for analysis"""
    prompt = f"""You are a security analyst. Analyze this alert SUCCINCTLY (3-5 sentences max):

Alert Data:
{json.dumps(alert_data, indent=2)}

Provide:
1. What happened (1 sentence)
2. Risk level and why (1 sentence)
3. What to do next (1-2 sentences)

Be brief and direct."""

    return chat_with_llm([{"role": "user", "content": prompt}])

# Sidebar - Chat Interface
with st.sidebar:
    st.title("💬 AI Assistant")

    # Display chat history
    for message in st.session_state.chat_messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Chat input
    if prompt := st.chat_input("Ask me anything..."):
        # Add user message to chat history
        st.session_state.chat_messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # Get AI response
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                response = chat_with_llm(st.session_state.chat_messages)
                st.markdown(response)

        # Add assistant response to chat history
        st.session_state.chat_messages.append({"role": "assistant", "content": response})
        st.rerun()

# Main content
st.title("🔍 LME Security Alerts")

# Check password
if not ES_PASS:
    st.error("ELASTICSEARCH_PASSWORD not set!")
    st.stop()

st.success(f"✓ Connected to Elasticsearch as {ES_USER}")

# Query the alerts index
try:
    response = _ES_HTTP.post(
        f"{ES_URL}/.alerts-security.alerts-*/_search",
        auth=(ES_USER, ES_PASS),
        verify=_ES_VERIFY,
        headers={"Content-Type": "application/json"},
        json={
            "size": 50,
            "sort": [{"@timestamp": {"order": "desc"}}]
        },
        timeout=10
    )
    response.raise_for_status()
    data = response.json()

    hits = data.get("hits", {}).get("hits", [])
    total = data.get('hits', {}).get('total', {}).get('value', 0)

    st.metric("Total Alerts", total)
    st.write(f"Showing {len(hits)} most recent alerts")

    # Display each alert
    for idx, hit in enumerate(hits):
        source = hit.get("_source", {})
        alert_name = source.get('kibana.alert.rule.name', 'Unknown Alert')
        timestamp = source.get('@timestamp', 'No timestamp')
        severity = source.get('kibana.alert.severity', 'unknown')

        # Color code by severity
        severity_colors = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢',
            'unknown': '⚪'
        }
        severity_icon = severity_colors.get(severity, '⚪')

        st.divider()

        # Header row
        col1, col2 = st.columns([4, 1])
        with col1:
            st.subheader(f"{severity_icon} {alert_name}")
            st.caption(f"🕐 {timestamp} | Severity: {severity.upper()}")
        with col2:
            analyze_button = st.button("🤖 Analyze", key=f"analyze_{idx}")

        # Alert details
        if 'host.name' in source:
            st.write(f"🖥️ **Host:** `{source['host.name']}`")
        if 'user.name' in source:
            st.write(f"👤 **User:** `{source['user.name']}`")
        if 'source.ip' in source:
            st.write(f"📍 **Source IP:** `{source['source.ip']}`")
        if 'destination.ip' in source:
            st.write(f"🎯 **Destination IP:** `{source['destination.ip']}`")
        if 'process.command_line' in source:
            st.write("**Command:**")
            st.code(source['process.command_line'], language="bash")
        if 'kibana.alert.reason' in source:
            st.info(f"**Reason:** {source['kibana.alert.reason']}")

        # Show analysis if button clicked
        if analyze_button:
            with st.spinner("🤖 Analyzing alert with AI..."):
                analysis = analyze_with_llm(source)
                st.success("**AI Analysis:**")
                st.markdown(analysis)

        # JSON details in expander
        with st.expander("📄 View Full JSON"):
            st.json(source)

except Exception as e:
    st.error(f"Error querying Elasticsearch: {e}")
    st.write(f"URL: {ES_URL}")
    st.write(f"User: {ES_USER}")
    st.write(f"Password set: {bool(ES_PASS)}")
