# conftest.py for connectivity tests

import os
import warnings
import pytest
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

# --- Authoritative LME host port surface ------------------------------------
# NOTE(composability): under the composability refactor this port surface will
# move to manifests/* (per-service port manifests). Until manifests/ exists,
# the two fixtures below are the single source of truth -- keep the
# intentionally-exposed set and the loopback-only deny-set here, together.

@pytest.fixture
def all_service_ports():
    """Ports LME intentionally exposes on the host's external interface.

    Split by transport so callers TCP-connect only the TCP ports: UDP 514
    (wazuh syslog) is connectionless and must not be probed with connect_ex.
    """
    return {
        'tcp': [
            9200,               # elasticsearch
            5601, 443,          # kibana
            8220,               # fleet_server
            1514, 1515, 55000,  # wazuh manager
        ],
        'udp': [
            514,                # wazuh syslog
        ],
    }

@pytest.fixture
def loopback_only_ports():
    """Ports that MUST stay bound to 127.0.0.1 on the host and NOT be reachable
    on the external interface -- the network-isolation invariant.

    Source: quadlet-optional/elastic-services/lme-logstash.container
        PublishPort=127.0.0.1:5044:5044   # beats input (TLS)
        PublishPort=127.0.0.1:8085:8085   # logstash http monitoring

    ASYMMETRY: with the opt-in tailscale ingress enabled
    (ansible/roles/podman/tasks/tailscale_ingress.yml) 5044 is deliberately
    fronted on the *tailnet* address; 8085 is never fronted and is
    unconditionally loopback-only. The deny-test therefore probes the
    LAN/routable interface (external_host), never the tailnet address.
    """
    return [5044, 8085]

@pytest.fixture
def external_host(es_host):
    """The host's LAN/routable interface address, for the isolation deny-test.

    Must be the routable interface, NOT the tailscale (100.x / *.ts.net)
    address: the opt-in ingress legitimately fronts 5044 on the tailnet, so a
    tailnet address would red-fail a correct deployment.

    Resolution: explicit LME_EXTERNAL_HOST wins; else fall back to es_host only
    when it is already a non-loopback address; else None -> the deny-test skips
    (a pure-localhost run has no external interface to probe).
    """
    explicit = os.getenv("LME_EXTERNAL_HOST")
    if explicit:
        return explicit
    if es_host not in ("localhost", "127.0.0.1", "::1"):
        return es_host
    return None

