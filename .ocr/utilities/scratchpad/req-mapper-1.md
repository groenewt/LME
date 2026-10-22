# Requirements Mapping — Requirements Mapper 1

**Target**: PR #2 · branch `fix/debian-13-selinux-apt` · changeset `git diff origin/main...HEAD` (32 files, +379/−84)
**Method**: READ-ONLY. Every line-number citation re-verified with `grep -n` against the working tree (not derived from diff-hunk arithmetic, and not trusted from flow-analysis).
**Verdict key**: Full / Partial / None / Cannot-Assess.

---

## Requirements Identified

1. **R1** — No hardcoded credentials. Podman secrets + env; never cleartext at rest / in logs / `podman inspect`.
2. **R2** — No hardcoded connection URIs / hosts / ports / DB-names. Flag **every** baked host/port/URI/DB as environment-fragility, classified by blast radius.
3. **R3** — Fit the 16 GB iron (ES heap, JVM heaps, pack, llama_cpp/pgvector fit ~16 GB; store off tight `/var` onto `/data` via `-g`).
4. **Seal gate (forward)** — QEMU/KVM-validated deployment across 1-node / 3-node cluster / airgapped.
5. **R4 (tailscale closure, forward)** — host-facing tailscale INGRESS / EGRESS / SVC.

---

## Coverage Matrix

| Req | Status | Notes |
|-----|--------|-------|
| **R1** | ⚠️ **Partial** | B1 (pgvector password at-rest) **fully fixed** → podman secret + runtime URL assembly + `no_log`. Residual: hardcoded `LITELLM_API_KEY=sk-lme-llama-proxy` in two units this PR edits; CA private key world-readable on the upgrade path. |
| **R2** | ⚠️ **Partial — round-3 `EnvironmentFile=` blocker UNRESOLVED** | Password parameterized (via the R1 secret); host/port/db/user **still baked** — went from 1 baked URI to 4 baked literals across 3 units. No `EnvironmentFile=` anywhere. (If R2 acceptance = single-source-of-truth, this dimension is **None**.) |
| **R3** | ⚠️ **Partial** (single-node caps effective; cluster uncapped; empirical fit = Cannot-Assess) | ES caps 8G/4g + logstash 512m apply **only on single-node**. On any cluster-mode node (`es_discovery_type='cluster'`) the caps are skipped, so the 16 GB protection does NOT extend to the 3-node profile. `-g` plumbed but defaults to `/var`. |
| **Seal gate** | ⚠️ **Partial** + Cannot-Assess | 1-node online + 3-node online + airgapped-1-node-core supported. Hard gaps: airgapped cluster rejected; no offline pack bundle; `sudo -v` pipeline blocker. QEMU validation itself needs a live run. |
| **R4** | ⚠️ **Partial (1 of 3 legs)** | INGRESS present (opt-in). EGRESS + SVC ABSENT. tailscaled itself an external prereq (no role installs it). |

---

## Evidence by Requirement

### R1 — No hardcoded credentials — **Partial**

**Fixed (the motivating example, B1):**
- `ansible/templates/lme-litellm.container.j2:27` — `Secret=pgvector,type=env,target=PGVECTOR_PASS`; the old `Environment=DATABASE_URL=postgresql://lme:{{ global_secrets.pgvector }}@lme-pgvector:5432/litellm` line is **removed**. `:37` `Exec=… export DATABASE_URL=postgresql://$${PGVECTOR_USER}:$${PGVECTOR_PASS}@$${PGVECTOR_HOST}:$${PGVECTOR_PORT}/$${PGVECTOR_DB}` — assembled at container runtime; no pgvector password at rest in the rendered unit.
- `ansible/roles/podman/tasks/quadlet_setup.yml:159` — render task gained `no_log: true`.
- Grep confirms **no `global_secrets` remains in any unit or template**.
- `config/logstash/pipeline/lme.conf:32` (new) — `password => "${ELASTICSEARCH_PASSWORD}"`, env-injected via the logstash unit's `Secret=elastic,type=env,target=ELASTICSEARCH_PASSWORD`. Correct.

**Basis for the "not in `podman inspect`" claim** (asserted statically, no live inspect run): secrets are referenced by name only (`Secret=…,type=env`); the value never appears as an `Environment=` literal or in the rendered template. Live `podman inspect` confirmation is a Cannot-Assess item.

**Residual R1 exposures (NOT addressed):**
- **Hardcoded LiteLLM proxy key** `sk-lme-llama-proxy` in cleartext (visible via `podman inspect`) in units this PR edits:
  - `quadlet/lme-dashboard.container:28` — `Environment=LITELLM_API_KEY=sk-lme-llama-proxy` (edited this PR for `,idmap`).
  - `quadlet/lme-log-analyzer.container:27-28` — same literal (edited this PR for `,idmap`).
  - `config/litellm_config.yaml:100` — `master_key: sk-lme-llama-proxy` (the at-rest source; file NOT in this changeset).
- **CA private key world-readable on upgrade.** `config/setup/init-setup.sh:40` (`*.key`→0640), `:43` (`*.zip`→0600), `:44-45` (`ca/ca.key`→0600) all sit inside the `if [ ! -f "${CERTS_DIR}/certs.zip" ]` **fresh-install guard** (`init-setup.sh:22`). On upgrade (`certs.zip` present) the block is skipped; the top-up loop (`:56-82`) re-chmods only per-service dirs from `instances.yml` and never touches `ca/ca.key`. Older installs left `ca.key` at 0644 → upgrade leaves the CA private key world-readable. Round-2 open blocker, still open.

### R2 — No hardcoded connection URIs / hosts / ports / DB-names — **Partial (round-3 blocker unresolved)**

The litellm refactor traded **one** baked URI for **four** baked literals + a secret:
- `ansible/templates/lme-litellm.container.j2:33-36` — `PGVECTOR_HOST=lme-pgvector`, `PGVECTOR_PORT=5432`, `PGVECTOR_DB=litellm`, `PGVECTOR_USER=lme`. Only the password is parameterized.
- **Round-3 R2 blocker's named fix — single-source via `EnvironmentFile=` — is NOT implemented** (no `EnvironmentFile=` in the changeset). The `lme-pgvector:5432` coordinates are baked in **three** independent places: litellm (`:33-36`), dashboard (`quadlet/lme-dashboard.container:30-33`), pgvector (`quadlet/lme-pgvector.container` `POSTGRES_DB`/`POSTGRES_USER`, `PublishPort=5432:5432`).
- DB-name distinctness **is** preserved per the round-3 note: litellm db `litellm` vs dashboard/pgvector db `lme_vectors` — no collision.

**Complete baked-coordinate enumeration across the changed surface** (R2 says flag *every* one; classified by blast radius):

*High (introduced / reshaped by this PR):*
- `lme-litellm.container.j2:33-36` — pgvector host/port/db/user literals (new; no EnvironmentFile).
- `config/logstash/pipeline/lme.conf:30` `hosts => ["https://lme-elasticsearch:9200"]`, `:31` `user => "elastic"`, `:19` `port => 5044`, `:26` `http { port => 8085 }` (new file).
- `quadlet-optional/elastic-services/lme-logstash.container:28-29` — `PublishPort=127.0.0.1:5044:5044` / `:8085:8085` (lines modified this PR — loopback bind added), `:51` HealthCmd `localhost:9600`.
- `ansible/roles/podman/tasks/tailscale_ingress.yml` — ports `8200`/`4000`/`5044` and `127.0.0.1` backends hardcoded in the `tailscale serve` commands (new file; loopback + fixed publish ports).

*Low (pre-existing literals in units whose only changed line is the `,idmap` cert mount):*
- `quadlet/lme-dashboard.container` — `:25` `ELASTICSEARCH_URL=https://lme-elasticsearch:9200`, `:27` `LITELLM_URL=https://lme-litellm:4000`, `:30-33` `PGVECTOR_*`, `:34` `EMBED_URL=https://lme-embeddings:8081`, `:24` `PublishPort=8502:8502`.
- `quadlet/lme-log-analyzer.container` — `:25` / `:27` ES + LiteLLM URLs, `:24` `PublishPort=8501:8501`.
- `quadlet/lme-embeddings.container:23` `PublishPort=8081:8081`, `:26` HealthCmd `localhost:8081`.
- `quadlet/lme-fleet-server.container:20` — a single `Environment=` line bakes `KIBANA_HOST=https://lme-kibana:5601`, `FLEET_URL=https://lme-fleet-server:8220`, and five ES-host vars all `https://lme-elasticsearch:9200`; `:27` `PublishPort=8220:8220`.
- `quadlet/lme-fleet-distribution.container:25` `PublishPort=8080:8080`, `:31` HealthCmd `localhost:8080`.
- `quadlet/lme-llama-cpp.container:28` HealthCmd `localhost:8080` (+ Exec `--port 8080`).
- `quadlet-optional/elastic-services/lme-apm-server.container:24` `PublishPort=8200:8200`, `:35` HealthCmd `127.0.0.1:8200`.

Environment-fragility verdict: **still fragile** — a change to the pgvector host/port/db (or ES host) requires editing multiple units by hand. Password dimension improved; URI/host/port/db dimension did not.

### R3 — Fit the 16 GB iron — **Partial**

Single-node caps (effective, verified):
- `ansible/templates/lme-elasticsearch.container.j2:20-21` — `MemoryHigh={{ es_memory_high | default('6G') }}` / `MemoryMax={{ es_memory_max | default('8G') }}`, gated `:12` on single-node.
- `ansible/templates/lme-elasticsearch.container.j2:92` — `ES_JAVA_OPTS="… -Xms{{ es_heap_size | default('4g') }} -Xmx…"`, gated `:91` on single-node.
- `es_heap_size`/`es_memory_high`/`es_memory_max` are **never assigned repo-wide** (grep) → the single-node render is heap 4g / MemoryHigh 6G / MemoryMax 8G. Invariant honored (4g ≤ ~50% of 8G).
- `quadlet-optional/elastic-services/lme-logstash.container:39` — `Environment="LS_JAVA_OPTS=-Xms512m -Xmx512m"` (quoted — avoids the whitespace-split + append trap).
- `quadlet/lme-llama-cpp.container` — model `LFM2.5-1.2B-Instruct-Q4_K_M.gguf` (~1 GB Q4); no explicit cap, small footprint.
- pgvector / embeddings / litellm / dashboard carry **no memory caps**.

**Cluster caveat (evidence-backed correction):** `es_discovery_type` **is assigned** (not merely commented) at `ansible/site.yml:46` and `ansible/elasticsearch.yml:59` — `"{{ 'cluster' if lme_cluster_mode | default(false) else 'single-node' }}"`. On a fresh cluster the master gets `lme_cluster_mode=True` (`install.sh:847`) and the data-node playbook hardcodes `lme_cluster_mode: true` (`ansible/elasticsearch.yml:51`), so **every ES node resolves to `es_discovery_type='cluster'` → the MemoryMax/heap caps are skipped on all cluster nodes**. This matches the template's stated intent ("dedicated cluster data nodes keep their sizing", `.j2:14-15`), but for the 16 GB-iron seal gate it means **the 16 GB protection covers only the single-node profile; 3-node cluster ES is unbounded**. (My first-pass grep had filtered these assignment lines via `grep -v "default("` — corrected here.)

**graphroot `-g`:** plumbed end-to-end — `install.sh:98-99` sets `GRAPH_ROOT`; passed as `storage_graphroot` (`install.sh:683/685` single-node, `:838` cluster `BASE_EXTRA_VARS`); consumed at `ansible/roles/base/tasks/setup_passwords.yml:153` (`graphroot = {{ storage_graphroot | default('…', true) }}` — the `true` arg makes an empty `-g ""` fall back), running in the **base** role before any image is stored. **But** the default is `GRAPH_ROOT="/var/lib/containers/storage"` (`install.sh:18`) → the store lands on tight `/var` unless the operator passes `-g /data/...`. The "off `/var` onto `/data`" expectation is a mechanism, not a default.

Empirical "full stack runs within 16 GB on graph/trixie" = **Cannot-Assess** (needs a live run).

### Seal gate — QEMU/KVM across 1-node / 3-node / airgapped — **Partial** (+ Cannot-Assess)

- **1-node online**: fully supported. `compute_effective_flags()` (`install.sh:617`, called `:671` single / `:836` cluster) hoisted so a flag means the same on both entrypoints; `install_llm`, `install_elastic_services`, `storage_graphroot` all flow (`install.sh:683/685`).
- **3-node cluster online**: supported. `-g` reaches all nodes via `BASE_EXTRA_VARS` (`install.sh:838`); children set `lme_child_es_only=true` so pack/LLM/dashboard/pgvector run master-only. Per-node host-fixed `PublishPort`s + podman aliases → no stable cross-node name (the gap the missing tailscale SVC/egress layer would fill). **ES uncapped on all cluster nodes** (see R3 caveat).
- **Airgapped 1-node**: core only (LLM only if `--llm` bundle pre-staged). Pack forced off offline (`compute_effective_flags`, `install.sh:626-636`) and **not staged**: `scripts/prepare_offline.sh` has **zero** references to the pack / `config/containers-elastic-services.txt` (which exists but is unconsumed).
- **Airgapped cluster**: **impossible** — `--cluster` + `--offline` rejected outright, `install.sh:891-895` (`exit 1`, message `:892`).
- **`sudo -v` pipeline blocker**: `install.sh:602`, `:650`, `:816` — hangs a non-interactive ssh run unless the target has passwordless sudo.
- No QEMU / nested-virt assumption is encoded anywhere in the changeset (pure infra concern).

QEMU/KVM *validation* across the three profiles = **Cannot-Assess** statically.

### R4 — tailscale closure (INGRESS / EGRESS / SVC) — **Partial (1 of 3 legs)**

- **INGRESS — present (opt-in)**: `ansible/roles/podman/tasks/tailscale_ingress.yml` (new, 85 lines) — `tailscale serve --bg --https=8200/4000 https+insecure://127.0.0.1:<port>` (apm-server, litellm) + `--tcp=5044` raw passthrough (beats see logstash's internal-CA leaf). Included from `elastic_services_setup.yml:103` gated `tailscale_serve_ingress | default(false)` (`:104`) — off by default. Fails fast if the node isn't on the tailnet (`tailscale_ingress.yml:39-45`). Internal-CA-vs-ts.net reasoning sound.
- **EGRESS — absent**: no `tailscale up` / `--advertise-routes` / `--exit-node`.
- **SVC (VIP) — absent**: no `tailscale serve --service=svc:` (the leg that gives the 3-node cluster a stable cross-node name).
- **tailscaled install — absent**: no role installs tailscale/tailscaled (external prereq).

Two of three operator-required legs missing.

---

## Section Annotations (for the Map Architect)

- **§1 Install entrypoint & flag plumbing** — R3 graphroot plumbing (full) + seal-gate flag semantics. Gaps: `-g` default `/var` (`install.sh:18`); `sudo -v` blocker (`:602/650/816`); `--cluster`+`--offline` rejected (`:891-895`).
- **§2 Base role** — R1 cert-perm hardening (fresh-install only, `init-setup.sh:22` guard) + R3 graphroot write (`setup_passwords.yml:153`). Gap: CA key world-readable on upgrade.
- **§3 Podman orchestration** — R1 `no_log` render (`quadlet_setup.yml:159`); static litellm copy removed (`llama_cpp_setup.yml`) → `quadlet/lme-litellm.container` now dead as an install input yet still edited in this PR.
- **§4 LiteLLM ↔ pgvector** — R1 full (pgvector password) + R2 partial (host/port/db baked, no `EnvironmentFile=`).
- **§5 Elastic-services pack + certs/idmap** — B2 (`,idmap` on all cert mounts; `User=root` on apm-server `:29`-region + logstash `:50`-region), R3 (logstash 512m `:39`, ES single-node caps). Gaps: offline pack absent; `es_*` sizing vars undefined (defaults effective); cluster ES uncapped.
- **§6 Core cert-consumer quadlets** — B2 `,idmap`. Residual R1 (`sk-lme-llama-proxy` in dashboard:28 + log-analyzer:27-28). `app.py:81` flips litellm verify to `/certs/ca/ca.crt` (safe direction).
- **§7 Tailscale host ingress** — R4 INGRESS leg only.
- **§8 Upgrade / offline / misc** — upgrade auto-detect + pack re-land (`upgrade_lme.yml:886`, `when` `:890`); offline `--network=host` build fixes. Gap: the re-land at `:886-890` lacks the `not lme_child_es_only` guard the install path carries → risks running pack setup on child nodes during a cluster upgrade.

---

## Gaps (unaddressed / partial requirements)

1. **R2 single-source-of-truth NOT delivered** (round-3 blocker open) — no `EnvironmentFile=`; `lme-pgvector:5432` baked in 3 units. *Missing: an `EnvironmentFile=` (e.g. `/etc/lme/pgvector.env`) referenced by every consumer.*
2. **R1 hardcoded proxy key** `sk-lme-llama-proxy` at rest (`lme-dashboard.container:28`, `lme-log-analyzer.container:27-28`, `litellm_config.yaml:100`). *Missing: move to a podman secret like the pgvector password just was.*
3. **R1 CA private key world-readable on upgrade** — hardening trapped behind `init-setup.sh:22` fresh-install guard. *Missing: re-apply `ca.key` 0600 / `*.key` 0640 on the upgrade/top-up path.*
4. **R3 — cluster ES uncapped** — MemoryMax/heap caps skipped on all `es_discovery_type='cluster'` nodes (`elasticsearch.yml:51/59`, `install.sh:847`), so 3-node nodes on 16 GB irons are unbounded. *Missing: cluster-node memory sizing for the 16 GB seal-gate profile.*
5. **Seal gate — airgapped cluster impossible** (`install.sh:891-895`) and **offline pack absent** (`prepare_offline.sh` stages no pack images). *Missing: offline pack bundle; a supported `--cluster --offline` path.*
6. **Seal gate — `sudo -v` pipeline blocker** (`install.sh:602/650/816`). *Missing: passwordless-sudo / root-over-ssh handling for non-interactive runs.*
7. **R4 — EGRESS + SVC legs absent**; no role installs tailscaled. *Missing: `tailscale up`/routes/exit-node tasks; `serve --service=svc:` VIP tasks; a tailscaled install role.*
8. **R3 — `-g` defaults to `/var`** (`install.sh:18`); `/data` relocation is operator-action-dependent.
9. **Upgrade re-land missing child guard** (`upgrade_lme.yml:886-890`) — no `not lme_child_es_only`.
10. **`lme-curator` SAN dangling** (`config/setup/instances.yml:42`) — SAN minted, no curator quadlet consumes it.

---

## Cannot-Assess (needs a live, orchestrator-sanctioned run)

- **R3 empirical fit** — base + `--elastic-services` + LLM + llama_cpp + pgvector concurrently within ~16 GB on graph/trixie. *Settled by*: `podman stats` / peak-RSS during a full `--elastic-services --llm` deploy on a 16 GB node.
- **R1 `podman inspect` cleanliness** — that no secret value surfaces in `inspect`/logs at runtime. *Settled by*: `podman inspect lme-litellm` on a live host (statically: secrets referenced by name only, no literal).
- **Seal-gate QEMU/KVM validation** across all three profiles. *Settled by*: the orchestrator-driven QEMU-on-silmaril deploy of each profile.
- **fleet-server cert-read under `UserNS=auto` × host-uid-166536 idmap** — the one cert-reader with no runtime proof (`ConditionPathExists=…FLEET_SETUP_FINISHED` unmet on the prior e2e). *Settled by*: a run reaching FLEET_SETUP_FINISHED.
- **Cluster upgrade with pack on child nodes** — whether the unguarded re-land (`upgrade_lme.yml:886-890`) fails on a `lme_child_es_only` node. *Settled by*: a 3-node cluster upgrade with the pack enabled.

---

## Questions

1. **R2 acceptance**: does R2 require single-sourcing via `EnvironmentFile=` (the round-3 blocker wording), or is "password out of the URI + discrete env vars" sufficient? This decides Partial vs None on R2.
2. **`sk-lme-llama-proxy`**: real credential (→ R1 violation to fix) or intentional static shared dev token (→ documented acceptance)? `litellm_config.yaml` is outside this changeset — in scope for this PR or a follow-up?
3. **CA-key upgrade perms**: is fresh-install-only hardening acceptable (installs re-imaged), or must the upgrade path re-tighten `ca.key`?
4. **3-node caps**: should cluster nodes also get MemoryMax/heap caps for the 16 GB seal-gate profile, or is uncapped-on-dedicated-iron the intended posture?
5. **R4 scope for this PR**: are EGRESS + SVC expected here, or is INGRESS-only the intended increment?
