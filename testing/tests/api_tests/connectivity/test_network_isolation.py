import os
import shutil
import socket
import subprocess
import pytest
from contextlib import closing

# When ES_HOST is one of these the suite is running *on* the LME host, so the
# external-interface deny-test has no external address to probe (and, contrariwise,
# the host's own listening sockets are meaningful to introspect for a loopback bind).
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


# A wildcard listen address binds every interface (LAN included). The render_port
# resolver (filter_plugins/lme_manifests.py) emits ONLY two kinds of publish for an
# LME service: an explicit `127.0.0.1:` loopback bind, or -- for a port dict with
# NO bind -- a bare `host:container` that podman publishes on the wildcard. It never
# emits a specific routable IP. So a wildcard bind on an LME port is exactly the
# "bind:127.0.0.1 was dropped" regression, while a specific-IP listener (a tailnet
# 100.x/fd7a address from `tailscale serve`, or an unrelated host service) is NOT
# something render_port can produce.
_WILDCARD_BINDS = ("0.0.0.0", "::", "*", "")


def _is_loopback_bind(addr):
    """True iff a listen-socket bind ADDRESS is a loopback address.

    Handles the spellings `ss`/`podman port` emit: bare IPv4 (127.0.0.1), an
    IPv6 in brackets ([::1]) or bare (::1). A wildcard (0.0.0.0, ::, *) or any
    routable IP is NOT loopback.
    """
    a = addr.strip().strip("[]")
    if a == "::1":
        return True
    if a.startswith("127."):
        return True
    return False


def _is_wildcard_bind(addr):
    """True iff a listen-socket bind ADDRESS is an all-interfaces wildcard."""
    return addr.strip().strip("[]") in _WILDCARD_BINDS


def _lme_podman_binds():
    """port -> set(host bind_addr) for ports published by LME's OWN containers.

    Scoped to containers whose name marks them LME (``lme...``) via `podman port`,
    which reports the host-side publish address (e.g. `8502/tcp -> 127.0.0.1:8502`)
    -- exactly the bind the invariant governs. Scoping to LME containers keeps
    unrelated host services and `tailscale serve` listeners out of the picture, so
    the check is precise on a shared host. Returns None when podman is
    unavailable/unusable; an empty dict means podman ran but no LME container is
    currently publishing (nothing deployed here).
    """
    if shutil.which("podman") is None:
        return None
    try:
        ps = subprocess.run(
            ["podman", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if ps.returncode != 0:
        return None
    binds = {}
    for name in ps.stdout.split():
        if not name.startswith("lme"):
            continue
        try:
            pr = subprocess.run(
                ["podman", "port", name], capture_output=True, text=True, timeout=10
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if pr.returncode != 0:
            continue
        for line in pr.stdout.splitlines():
            if "->" not in line or "/tcp" not in line:
                continue
            _proto, host_side = line.split("->", 1)
            addr, sep, port_s = host_side.strip().rpartition(":")
            if not sep:
                continue
            try:
                port = int(port_s)
            except ValueError:
                continue
            binds.setdefault(port, set()).add(addr)
    return binds


def _ss_listening_binds():
    """port -> set(bind_addr) for every TCP LISTEN socket, via `ss -Hltn`.

    Fallback for hosts without podman. Reads ALL listening sockets on the box, so
    it cannot tell an LME publish from an unrelated service -- the caller therefore
    treats only a WILDCARD bind as a violation here (a specific routable IP is not
    a shape render_port can emit). Returns None when `ss` is unavailable/unusable.
    """
    if shutil.which("ss") is None:
        return None
    try:
        proc = subprocess.run(
            ["ss", "-Hltn"], capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    binds = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        # ss -Hltn columns: State Recv-Q Send-Q Local:Port Peer:Port
        if len(parts) < 4:
            continue
        addr, sep, port_s = parts[3].rpartition(":")
        if not sep:
            continue
        try:
            port = int(port_s)
        except ValueError:
            continue
        binds.setdefault(port, set()).add(addr)
    return binds


class TestNetworkIsolation:

    def test_default_closed_ports_blocked_externally(self, external_host, default_closed_ports):
        """Isolation invariant (default-CLOSED): NO host-published port may be
        reachable on the LAN/routable interface unless the operator explicitly
        opted it in via expose_lan (LME_EXPOSE_LAN_PORTS).

        This is the HARDENED inversion of the old test: it no longer probes a
        narrow 5044/8085 deny-set while treating ES/kibana/pgvector/embeddings/...
        as legitimately exposed. Under the default-closed posture EVERY published
        port binds to 127.0.0.1 (manifests/global.yml `ports.*.bind`), so the
        deny-set is the WHOLE published surface minus the opt-ins. A port reachable
        here that was not opted-in is the regression this catches
        (bind:127.0.0.1 dropped -> render_port emits an 0.0.0.0 publish).

        Probes the routable interface (external_host), NEVER the tailnet address:
        the opt-in tailscale ingress legitimately fronts services on the tailnet.
        """
        if external_host is None:
            pytest.skip(
                "no external interface to probe: ES_HOST is loopback and "
                "LME_EXTERNAL_HOST is unset (suite is running on the host itself)"
            )
        for port in default_closed_ports:
            # Short timeout: a refusal is instant; a dropped (filtered) packet is
            # the only slow path, so 5s bounds the worst case.
            assert not _tcp_open(external_host, port, timeout=5), (
                f"Default-closed port {port} is reachable on external interface "
                f"{external_host} -- network-isolation regression. It must be "
                f"bound to 127.0.0.1 (opt it onto the LAN via a profile's "
                f"expose_lan / LME_EXPOSE_LAN_PORTS if exposure is intended)."
            )

    def test_published_ports_bound_to_loopback(self, es_host, published_ports, expose_lan_ports):
        """Positive encoding of the same invariant, read from the host's own
        publish table: every published LME port that is ACTUALLY listening must be
        bound to a loopback address unless it was opted onto the LAN via
        expose_lan (LME_EXPOSE_LAN_PORTS).

        Stronger than the remote deny-probe -- it asserts the bind ADDRESS itself
        rather than inferring it from an interface being unreachable, so it catches
        a 0.0.0.0 bind even when no routable interface is configured. Ports that are
        not published are skipped (service not deployed / group not installed),
        which is why this needs no per-group gate.

        Source, in order of precision:
          * `podman port` scoped to LME's own containers (authoritative -- the
            exact host publish bind, immune to unrelated host services); a wildcard
            OR any other non-loopback address there is a violation.
          * fallback `ss -ltn` when podman is absent: reads ALL host sockets and so
            cannot attribute a port to LME, so ONLY a wildcard bind (0.0.0.0/::/*)
            is treated as a violation -- a specific routable IP (e.g. a tailnet
            `tailscale serve` address, or another service) is not a shape
            render_port can emit for an LME publish.

        Guarded to on-host runs: from a remote/dev-container runner (ES_HOST="lme")
        the local publish table is the runner's, not the LME host's.
        """
        if es_host not in _LOOPBACK_HOSTS:
            pytest.skip(
                "not running on the LME host (ES_HOST is remote): cannot read the "
                "host's own publish table"
            )
        binds = _lme_podman_binds()
        source = "podman"
        if binds is None:
            binds = _ss_listening_binds()
            source = "ss"
        if binds is None:
            pytest.skip(
                "neither `podman` nor `ss` is available to read socket binds"
            )
        if not binds:
            pytest.skip(
                "no LME container is publishing ports on this host "
                "(nothing deployed yet)"
            )
        checked = 0
        for port in published_ports['tcp']:
            addrs = binds.get(port)
            if not addrs:
                continue  # not published: service not deployed / port not published
            if port in expose_lan_ports:
                continue  # deliberately LAN-exposed via expose_lan
            checked += 1
            if source == "podman":
                offending = sorted(a for a in addrs if not _is_loopback_bind(a))
            else:
                offending = sorted(a for a in addrs if _is_wildcard_bind(a))
            assert not offending, (
                f"Published port {port} is bound to {offending} but was not opted "
                f"onto the LAN (expose_lan / LME_EXPOSE_LAN_PORTS) -- default-closed "
                f"posture regression (expected a 127.0.0.1 bind)."
            )
        if checked == 0:
            pytest.skip(
                "no published LME ports are currently listening on this host "
                "(nothing deployed yet, or introspection returned nothing)"
            )

    def test_expose_lan_opt_ins_reachable_externally(self, external_host, expose_lan_ports):
        """The escape hatch works: a port the operator DELIBERATELY opted onto the
        LAN via expose_lan (LME_EXPOSE_LAN_PORTS) IS reachable on the external
        interface. Complements the deny-test so opting-in is proven functional,
        not merely permitted.

        Skips on a stock (default-closed) install -- with no opt-ins there is, by
        design, nothing to reach off-box.
        """
        if external_host is None:
            pytest.skip(
                "no external interface to probe: ES_HOST is loopback and "
                "LME_EXTERNAL_HOST is unset (suite is running on the host itself)"
            )
        if not expose_lan_ports:
            pytest.skip(
                "no expose_lan opt-ins declared (LME_EXPOSE_LAN_PORTS empty): "
                "default-closed install, nothing is meant to be LAN-reachable"
            )
        for port in sorted(expose_lan_ports):
            assert _tcp_open(external_host, port, timeout=5), (
                f"expose_lan opt-in port {port} is NOT reachable on external "
                f"interface {external_host} -- the LAN opt-in did not take effect "
                f"(service down, or its publish bind was not opened)."
            )

    def test_udp_syslog_514_loopback(self, es_host):
        """UDP 514 (wazuh syslog) smoke test.

        Under the default-closed posture 514 is loopback-only by default (opt onto
        the LAN via expose_lan). UDP is connectionless, so this only verifies a
        datagram can be sent to the host's own loopback -- it does not (and cannot
        cheaply) assert external reachability, so it stays a liveness smoke rather
        than an isolation assertion. Runs only on-host, where es_host is loopback.
        """
        if es_host not in _LOOPBACK_HOSTS:
            pytest.skip(
                "not running on the LME host (ES_HOST is remote): 514 is "
                "loopback-only under the default-closed posture"
            )
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
            sock.settimeout(5)
            try:
                test_message = b"<14>Jan  1 00:00:00 test-host test: connectivity test"
                sock.sendto(test_message, (es_host, 514))
                # UDP is connectionless, so we just verify we can send.
            except Exception as e:
                pytest.fail(f"UDP port 514 (syslog) test failed: {e}")
