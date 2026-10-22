## Summary

Fixes the Debian 13 install path and lands the round-1 OCR-reviewed hardening, plus the optional Elastic services pack behind `--elastic-services`.

**Round-1 blockers addressed**
- **B1** — LiteLLM no longer renders the pgvector password at rest: `Secret=…,type=env` + a runtime `$$`-assembled `DATABASE_URL`.
- **B2** — cert keys tightened (`ca.key` 0600 / service `*.key` 0640) with `,idmap` on the cert volumes (closes the world-readable CA-signing-key MITM on fresh installs).
- **B3** — `-g/--graph-root` now plumbed through `install.sh` → `storage_graphroot` on the single-node path (store lands off the tight `/var`).

**Live e2e on Debian 13 (`graph`, `-g /data --elastic-services`) surfaced + fixed in-tree**
- `setup_passwords.yml`: HIBP `when:` was a `NoneType` filter result → ansible-core 2.19 rejected the non-boolean conditional and broke every install; guarded with `is not none`.
- `lme-apm-server.container`: `User=root` so the image reads the 0640 cert key under `,idmap` (CAP_DAC_OVERRIDE).
- `lme-logstash.container`: quoted `Environment="LS_JAVA_OPTS=-Xms512m -Xmx512m"` (systemd `Environment=` splits on whitespace; unquoted left `Xms1g > Xmx512m` → JVM heap abort).

## Review status

Round-2 OCR verdict: **REQUEST CHANGES** — 3 blockers, 3 should-fix, 3 suggestions. B1/B3 resolved & e2e-proven; B2 partial. **One open blocker:** the `init-setup.sh` chmod block is inside the `if [ ! -f certs.zip ]` fresh-install guard, so in-place upgrades keep `ca.key` at 0644 (hoist pending). Full round-2 synthesis posted as a comment.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
