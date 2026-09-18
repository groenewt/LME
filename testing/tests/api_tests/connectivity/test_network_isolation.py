import os
import socket
import pytest
from contextlib import closing

# When ES_HOST is one of these the suite is running *on* the LME host, so the
# external-interface deny-test has no external address to probe (and, contrariwise,
# the host's own 127.0.0.1 is meaningful to probe for loopback-bound services).
_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


def _tcp_open(host, port, timeout=10):
    """Return True iff a TCP connection to host:port succeeds.

    Returns False on connection refused, timeout, or any socket error, so a
    filtered/dropped port (the slow path) never leaks an exception and turns a
    clean 'blocked' assertion into a test error rather than a failure.
    """
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


class TestNetworkIsolation:

    def test_expected_ports_open(self, es_host, all_service_ports):
        """Liveness half: every port LME intentionally exposes is reachable.

        Renamed from test_expected_ports_accessible: this asserts only that the
        expected ports are UP. It is NOT an isolation test -- the isolation
        invariant (unexpected/loopback ports are blocked) lives in the
        deny-tests below.
        """
        for port in all_service_ports['tcp']:
            assert _tcp_open(es_host, port), \
                f"Expected LME port {port} is not accessible on {es_host}"

    def test_loopback_only_ports_blocked_externally(self, external_host, loopback_only_ports):
        """Isolation invariant: loopback-bound services (logstash beats 5044,
        monitoring 8085) must NOT be reachable on the external interface.

        This is an explicit DENY-SET, not the complement of the expected-open
        set: LME also publishes pgvector (5432), litellm (4000), embeddings
        (8081), fleet-distribution (8080), log-analyzer (8501) and dashboard
        (8502) on all interfaces, so "any port not in the expected set is
        blocked" is false in this repo. This targets the specific ports the
        branch tightened to 127.0.0.1 binds and catches a regression that
        re-exposes them (PublishPort=127.0.0.1:5044:5044 -> PublishPort=5044:5044).
        """
        if external_host is None:
            pytest.skip(
                "no external interface to probe: ES_HOST is loopback and "
                "LME_EXTERNAL_HOST is unset (suite is running on the host itself)"
            )
        for port in loopback_only_ports:
            # Short timeout: a refusal is instant; a dropped (filtered) packet is
            # the only slow path, so 5s bounds the worst case.
            assert not _tcp_open(external_host, port, timeout=5), (
                f"Loopback-only port {port} is reachable on external interface "
                f"{external_host} -- network-isolation regression (must be bound "
                f"to 127.0.0.1 only)"
            )

    def test_loopback_only_ports_reachable_on_loopback(self, es_host, loopback_only_ports):
        """Complement of the deny-test: the same services ARE up, just bound to
        loopback, so they answer on 127.0.0.1.

        Guarded twice, because both conditions must hold or the positive assert
        is a false failure:
          * ES_HOST must be loopback -- from a remote/dev-container runner
            (ES_HOST="lme") 127.0.0.1 is the runner's own loopback, where these
            ports do not exist.
          * The optional Elastic services pack (--elastic-services, which owns
            logstash) must be deployed -- signalled at test time by truthy
            LME_ELASTIC_SERVICES. On a base install 5044/8085 do not exist at
            all, so this stays skipped rather than failing.
        """
        if es_host not in _LOOPBACK_HOSTS:
            pytest.skip(
                "not running on the LME host (ES_HOST is remote): cannot probe "
                "the host's own 127.0.0.1"
            )
        if os.getenv("LME_ELASTIC_SERVICES", "").lower() not in ("1", "true", "yes"):
            pytest.skip(
                "Elastic services pack not deployed (set LME_ELASTIC_SERVICES=1 "
                "when installed with --elastic-services): 5044/8085 not present"
            )
        for port in loopback_only_ports:
            assert _tcp_open("127.0.0.1", port), (
                f"Loopback-bound port {port} is not reachable on 127.0.0.1 "
                f"(service down or its 127.0.0.1 bind was changed)"
            )

    def test_udp_port_514_accessible(self, es_host):
        """Test that UDP port 514 (syslog) is accessible for Wazuh"""
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
            sock.settimeout(5)
            try:
                # Send a test syslog message
                test_message = b"<14>Jan  1 00:00:00 test-host test: connectivity test"
                sock.sendto(test_message, (es_host, 514))
                # UDP is connectionless, so we just verify we can send
            except Exception as e:
                pytest.fail(f"UDP port 514 (syslog) test failed: {e}")
