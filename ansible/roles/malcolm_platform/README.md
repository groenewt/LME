# Malcolm platform role

This role consumes the pure `resolved_role_config(topology, node, credential_material)` output and controller-materialized credentials. It installs the bounded Docker exception on the dedicated 8-vCPU guest, applies the 23 manifest-qualified image references to an immutable 27-service runtime roster, pins bounded local container logs, bootstraps fresh-run Basic backend authentication, installs strict mTLS, and starts the instance for pre-publication validation. The Docker stack and root log reader share a 32704 MiB slice; the separate 64 MiB owner gateway keeps the provider total at exactly 32768 MiB.

The role has no independent apply flag: MAIN invokes it only for the ordered application phase. The bootstrap adapter refuses existing authentication state and never mints forwarder identities. It derives upstream password hashes in-process from the owner-only materialized file so hashes do not enter the kernel process command line. MAIN remains responsible for publishing Tailscale services and for recording live source-authorization/readback receipts.

The optional fixture stage writes a deterministic offline PCAP only to the designated Malcolm guest upload endpoint. The helper opens no capture interface. Its output is `staged`, and becomes a passing network-analysis result only when actual `/mapi/document` responses satisfy the Zeek, harmless Suricata rule `9000001`, and Arkime checks.

Use [config/malcolm-platform/MAIN-HANDOFF.yml](../../../config/malcolm-platform/MAIN-HANDOFF.yml) as the concrete MAIN include-role invocation.
