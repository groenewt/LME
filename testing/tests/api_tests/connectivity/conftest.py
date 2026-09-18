# conftest.py for connectivity tests

import os
import warnings
import pytest
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Addresses that count as the host's own loopback. Used both to decide whether the
# suite is running *on* the LME host and to classify a socket's bind address.
_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


@pytest.fixture(autouse=True)
def suppress_insecure_request_warning():
    warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)

@pytest.fixture
def es_host():
    return os.getenv("ES_HOST", os.getenv("ELASTIC_HOST", "localhost"))

@pytest.fixture
def es_port():
    return os.getenv("ES_PORT", os.getenv("ELASTIC_PORT", "9200"))

@pytest.fixture
def username():
    return os.getenv("ES_USERNAME", os.getenv("ELASTIC_USERNAME", "elastic"))

@pytest.fixture
def password():
    return os.getenv(
        "elastic",
        os.getenv("ES_PASSWORD", os.getenv("ELASTIC_PASSWORD", "password1")),
    )

# --- Authoritative LME host port surface (default-CLOSED posture) -----------
# NOTE(composability): under the composability refactor this port surface will
# move to manifests/* (per-service port manifests). Until manifests/ is the sole
# reader, the fixtures below mirror manifests/global.yml `ports` + each service's
# publish_ports and encode the network invariant the deployment must satisfy.
#
# INVARIANT (hardened): the default network posture is CLOSED. Every port LME
# publishes on the host binds to 127.0.0.1 -- manifests/global.yml carries a
# default `bind: 127.0.0.1` on host-published ports and the render_port resolver
# (filter_plugins/lme_manifests.py) emits an 0.0.0.0 publish ONLY for a port dict
# with NO bind. LAN exposure is therefore the EXCEPTION: a service is opted back
# onto the routable interface per-profile via expose_lan, never by default. These
# tests assert that hardened invariant -- NOT the pre-hardening state in which
# ES/kibana/pgvector/embeddings/... were published on all interfaces by design.

# The full host-published port surface (superset across all install groups: core,
# elastic_services, llm). A deny assertion over this set is safe regardless of
# which groups are deployed -- an undeployed port simply is not listening, which
# already satisfies "not reachable on the LAN". Source of truth:
# manifests/global.yml `ports` + each manifests/services/*.yml publish_ports.
_PUBLISHED_TCP = [
    9200,               # elasticsearch http
    5601, 443,          # kibana (http + https)
    8220,               # fleet server
    8080,               # fleet distribution (package registry)
    1514, 1515, 55000,  # wazuh manager (registration, enrollment, api)
    8200,               # apm server
    5432,               # pgvector
    8081,               # embeddings (llama.cpp)
    4000,               # litellm proxy
    8501,               # log-analyzer (streamlit)
    8502,               # dashboard (fastapi)
    5044, 8085,         # logstash (beats input, http monitoring)
]
_PUBLISHED_UDP = [514]  # wazuh syslog


@pytest.fixture
def expose_lan_ports():
    """Ports the operator DELIBERATELY opted back onto the LAN via a profile's
    expose_lan -- the ONLY sanctioned way out of the default-closed posture.

    A running host cannot be introspected for manifest intent, so the opt-in set
    is supplied at test time via LME_EXPOSE_LAN_PORTS (comma- or space-separated
    port numbers), mirroring LME_EXTERNAL_HOST / LME_ELASTIC_SERVICES. Default
    EMPTY: a stock install exposes NOTHING on the routable interface, so every
    published port must be loopback-only.
    """
    raw = os.getenv("LME_EXPOSE_LAN_PORTS", "")
    ports = set()
    for tok in raw.replace(",", " ").split():
        try:
            ports.add(int(tok))
        except ValueError:
            continue
    return ports


@pytest.fixture
def published_ports():
    """The full host-published port surface, split by transport so callers
    TCP-connect only the TCP ports: UDP 514 (wazuh syslog) is connectionless and
    must not be probed with connect_ex.
    """
    return {'tcp': list(_PUBLISHED_TCP), 'udp': list(_PUBLISHED_UDP)}


@pytest.fixture
def default_closed_ports(expose_lan_ports):
    """DENY-SET: every host-published TCP port that MUST NOT be reachable on a
    non-loopback interface -- the full published surface minus the ports the
    operator explicitly opted onto the LAN via expose_lan.

    This INVERTS the pre-hardening invariant. Formerly only logstash 5044/8085
    were loopback-only while ES (9200), kibana (5601/443), pgvector (5432),
    embeddings (8081), litellm (4000), fleet (8220/8080), wazuh (1514/1515/55000),
    apm (8200), log-analyzer (8501) and dashboard (8502) were published on
    0.0.0.0 by design. Under the default-CLOSED posture that relationship flips:
    LAN exposure is the opt-in exception, so the deny-set is the WHOLE surface
    save the opt-ins.
    """
    return [p for p in _PUBLISHED_TCP if p not in expose_lan_ports]


@pytest.fixture
def external_host(es_host):
    """The host's LAN/routable interface address, for the isolation deny-test.

    Must be the routable interface, NOT the tailscale (100.x / *.ts.net)
    address: the opt-in ingress legitimately fronts services on the tailnet, so a
    tailnet address would red-fail a correctly hardened deployment.

    Resolution: explicit LME_EXTERNAL_HOST wins; else fall back to es_host only
    when it is already a non-loopback address; else None -> the deny-test skips
    (a pure-localhost run has no external interface to probe).
    """
    explicit = os.getenv("LME_EXTERNAL_HOST")
    if explicit:
        return explicit
    if es_host not in _LOOPBACK_HOSTS:
        return es_host
    return None
