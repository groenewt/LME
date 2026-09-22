# Requirements Mapping — Requirements Mapper 2

**Target**: PR #2, branch `fix/debian-13-selinux-apt`, changeset `origin/main...HEAD` (32 files, +379/−84)
**Method**: READ-ONLY. Verdicts verified against actual code via `git diff origin/main...HEAD`, `grep`, `cat`. No live run, no MCP mutation, no ssh/deploy.
**Independence note**: Formed independently. Divergence points from an independent mapper are called out inline.

---

## Requirements Identified
- **R1** — No hardcoded credentials at rest / in logs / `podman inspect`.
- **R2** — No hardcoded connection URIs / hosts / ports / DB-names (environment-fragility).
- **R3** — Fit the 16 GB iron (ES heap/memory caps, effective single-node render).
- **Seal gate (forward)** — 1-node / 3-node cluster / airgapped, QEMU-instanced.
- **R4 (tailscale closure, forward)** — INGRESS vs EGRESS + VIP SVC; tailscaled prereq.

---

## Coverage Matrix

| Req | Status | Verdict basis |
|-----|--------|---------------|
| R1 | ✅ **Full (for changeset)** | pgvector password moved to podman env-secret; no cleartext at rest in the changed template/unit. Pre-existing plaintext internal proxy key is a documented, out-of-scope sibling. |
| R2 | ⚠️ **Partial** | Secret single-sourced, but host/port/db/user still baked into template/units as discrete `Environment=` lines. Prescribed `EnvironmentFile=` single-source NOT implemented. New `lme.conf` adds another baked ES host. |
| R3 | ⚠️ **Partial** | Caps exist and bound ES (the biggest consumer) on single-node, but rely entirely on undefined-repo-wide Jinja defaults with NO plumbed operator override; 8 G ES + pack + LLM on 16 G is a thin fit; cluster data nodes get no cap. |
| Seal gate | 🔶 **Partial / Cannot-Assess** | Code paths present & correct (cluster+offline rejected, master-only pack via `lme_child_es_only`, no offline pack, NI knobs). Actual QEMU 1/3/airgapped validation needs the live run. `sudo -v` is a non-root pipeline blocker. |
| R4 | ⚠️ **Partial** | Ingress present (opt-in, off). Egress + VIP-svc ABSENT. No role installs tailscaled (external prereq). |

---

## R1 — Hardcoded credentials — **FULL (changeset scope)**

**Fix verified (B1).** `ansible/templates/lme-litellm.container.j2:26,37` replaces the old build-time
`Environment=DATABASE_URL=postgresql://lme:{{ global_secrets.pgvector }}@lme-pgvector:5432/litellm`
(cleartext password baked into the rendered unit at rest) with:
- `Secret=pgvector,type=env,target=PGVECTOR_PASS` (`:26`) — podman env-secret injection.
- `Exec=... export DATABASE_URL=postgresql://$${PGVECTOR_USER}:$${PGVECTOR_PASS}@...` (`:37`) — URL assembled **at container runtime** from the env-secret; `$$` escapes so systemd/podman never substitutes the value into the on-disk unit.

Evidence the password never lands cleartext on disk:
- Secret is generated in-memory and piped straight to podman: `ansible/roles/podman/tasks/llama_cpp_setup.yml:22-33` — `password=$(</dev/urandom tr -dc A-Za-z0-9 | head -c30); echo -n $password | podman secret create --driver file pgvector -`. The literal never enters an ansible var (it is generated server-side inside the `shell:` body), so `-vvv` logging cannot leak it.
- `ansible/roles/podman/tasks/quadlet_setup.yml:159` adds `no_log: true` to the template render (defensive; the template no longer carries a secret anyway).
- No residual `global_secrets.pgvector` reference exists repo-wide (grep: remaining `global_secrets.*` refs are elastic/kibana/wazuh only — `ansible/roles/kibana/tasks/main.yml:11`, `.../wazuh/tasks/main.yml:9-10`). So no other template still renders the pgvector password.
- The dashboard already used the same safe pattern: `quadlet/lme-dashboard.container:54` `Secret=pgvector,type=env,target=PGVECTOR_PASS`. The litellm change **aligns litellm to the dashboard's existing podman-secret pattern.**

**`podman inspect` leg (explicitly named in R1) — positive finding.** The old
`Environment=DATABASE_URL=postgresql://lme:PASSWORD@...` sat in the container's static `Config`, so the
password appeared in `podman inspect` (`Config.Env`) and in the on-disk unit. The new form assembles
`DATABASE_URL` at runtime **inside `Exec=`** (`:37`), so it never enters the static unit config → that
`inspect` leak closes for `DATABASE_URL`. **Cannot-Assess (settled by `podman inspect lme-litellm` on the
QEMU e2e):** whether `Secret=pgvector,type=env` surfaces the injected `PGVECTOR_PASS` in `inspect`'s
`Config.Env` is podman-version-dependent and not statically decidable here. Honest caveat: the
runtime-assembled `DATABASE_URL` and `PGVECTOR_PASS` do live in the litellm **process** env
(`/proc/<pid>/environ`, `podman exec … env`) — a narrower surface than on-disk config, but not zero.

**`llm-keys` secret (named in scope; mechanism is out of changeset).** Fresh-install placeholder is created
empty in-memory (`llama_cpp_setup.yml:157-162`, `echo -n '# empty' | podman secret create --driver file
llm-keys -`). Real keys are loaded by `scripts/sync_llm_keys.py` (NOT in this changeset), which Fernet-decrypts
`/opt/lme/config/llm_keys.enc` **in memory** and pipes the result via **stdin** to
`podman secret create --driver shell --replace llm-keys -` (`update_podman_secret`) — no cleartext temp file
touches disk; the `.enc` source stays encrypted at rest. No R1 concern from the llm-keys path.

**R1 SIBLING (flagged, NOT introduced by this PR, out of changeset scope):** a plaintext internal
LiteLLM proxy key `sk-lme-llama-proxy` lives at rest in:
- `quadlet/lme-log-analyzer.container:31` `Environment=LITELLM_API_KEY=sk-lme-llama-proxy`
- `quadlet/lme-dashboard.container` (mirrored) and `config/litellm_config.yaml:100 master_key: sk-lme-llama-proxy`.

This is a hardcoded credential at rest that WOULD show in `podman inspect`. However it is **pre-existing**
(introduced in commit `de20df4` "LME 2.3.0", not this PR — the only diff line touching
`lme-log-analyzer.container` is the `,idmap` cert mount, confirmed by diff) and is **explicitly documented
as an accepted plaintext internal key** in `ansible/PASSWORD_README.md:22` ("Plain string in
config/litellm_config.yaml, mirrored in quadlet/lme-dashboard.container and quadlet/lme-log-analyzer.container").
It is an internal proxy key, not a cloud provider credential (those go through the `llm-keys` file-secret).
**→ R1 for the changeset = Full. Repo-wide, an unresolved documented plaintext internal key remains — recommend a follow-up to move it to a podman secret, but it is not a regression from this PR.**

*Divergence point:* a strict/repo-wide mapper may score R1 **Partial** because of `sk-lme-llama-proxy`. I score
the **changeset** Full and the sibling as a separately-tracked, pre-existing, documented item.

---

## R2 — Hardcoded connection URIs / hosts / ports / DB-names — **PARTIAL**

The prior round-3 Blocker-1 prescribed fix was **"single-source via `EnvironmentFile=`"**. That was **NOT**
implemented. Instead the inline `DATABASE_URL` was decomposed into four discrete `Environment=` lines that
are **still baked into the template/unit**:

`ansible/templates/lme-litellm.container.j2:32-35` (byte-identical in rendered `quadlet/lme-litellm.container:32-35`):
```
Environment=PGVECTOR_HOST=lme-pgvector
Environment=PGVECTOR_PORT=5432
Environment=PGVECTOR_DB=litellm
Environment=PGVECTOR_USER=lme
```
Net effect: the *secret* is now single-sourced (podman), and the two-sources mismatch changed from
"inline URI (litellm) vs discrete env (dashboard)" to "discrete env (litellm) vs discrete env (dashboard)" —
**format harmonized, but connection params are still hardcoded in both units, in no fewer places.** No
env-var/inventory/`EnvironmentFile=` parameterization was added. The intentional DB-name distinction the
adjudication asked to preserve IS preserved: litellm DB `litellm` vs dashboard/pgvector DB `lme_vectors`
(`quadlet/lme-dashboard.container:32`, `quadlet/lme-pgvector.container:26,29 POSTGRES_DB=lme_vectors`,
`lme-dashboard/app.py:171` default `lme_vectors`, `scripts/ingest_docs.py:39`).

**Concrete multi-source blast radius (verified):** the db name `litellm` must agree across THREE places —
the template env `PGVECTOR_DB=litellm` (`:35`), the runtime URL assembly (`:37`), AND the imperative
`CREATE DATABASE litellm` in `ansible/roles/podman/tasks/llama_cpp_setup.yml:377-378` (run against
`lme-pgvector` as user `lme`). A rename of the db/user/alias must be edited in all of these in lockstep —
that is the real environment-fragility, stronger than "two units disagree in format."

### Enumerated baked-in connection params (environment-fragility findings)

| # | Location | Baked value(s) | In changeset? | Blast radius |
|---|----------|----------------|---------------|--------------|
| 1 | `lme-litellm.container.j2:32-35` + `quadlet/lme-litellm.container:32-35` | host `lme-pgvector`, port `5432`, db `litellm`, user `lme` | **Yes** | LOW single-node (podman `lme` net alias is internal DNS, stable) / **MED–HIGH cross-node** (podman aliases are per-node; no stable cross-host name — the exact gap the missing VIP-svc layer would fill) |
| 2 | `config/logstash/pipeline/lme.conf:30` | ES output `https://lme-elasticsearch:9200` (+ user `elastic`) | **Yes (new file)** | LOW single-node / MED cross-node |
| 3 | `quadlet/lme-log-analyzer.container` | `LITELLM_URL=https://lme-litellm:4000`, `ELASTICSEARCH_USER=elastic` | pre-existing (context only) | LOW single-node |
| 4 | `quadlet/lme-dashboard.container:30-33` | host/port `lme-pgvector:5432`, db `lme_vectors`, user `lme` | pre-existing (only `,idmap` changed) | LOW single-node |
| 5 | `quadlet/lme-pgvector.container:26,29` | `POSTGRES_DB=lme_vectors` | not in changeset | LOW |
| 6 | `ansible/roles/podman/tasks/tailscale_ingress.yml:66,72` | ports `8200/4000/5044`, backends `127.0.0.1:*` | **Yes (new file)** | LOW (loopback-bound; MagicDNS name is DISCOVERED via `tailscale status --json`, not hardcoded — a genuine parameterization plus) |
| 7 | `config/{filebeat,heartbeat,metricbeat,apm-server}.yml` | `lme-elasticsearch:9200`, `lme-kibana:5601` | pre-existing (NOT in changeset) — but **newly ACTIVATED** by `--elastic-services` (dormant before) | LOW single-node / MED cross-node |

**Blast-radius verdict:** for the **single-node** target these aliases resolve over the internal `lme` podman
network and are effectively stable, so real-world fragility is LOW. The fragility is **real for the
cluster/tailnet direction**: flow-analysis confirms podman aliases + host-fixed `PublishPort`s are per-node
with no stable cross-node name — hardcoded aliases will not address a service on another node. This is the
same gap the absent VIP-service layer (R4) would close. **R2 = Partial: the credential is de-hardcoded, but
every connection host/port/db/user remains baked; no operator-facing parameterization was introduced, and
the new `lme.conf` adds one more baked ES host.**

*Divergence point:* a lenient mapper may call R2 **Full** ("Blocker-1 resolved — no more inline URI, DB names
distinct, e2e-proven"). I hold R2 **Partial** because the prescribed `EnvironmentFile=` single-source was not
done and the host/port/db values are still hardcoded (just reshaped). This is the most likely inter-mapper split.

---

## R3 — Fit the 16 GB iron — **PARTIAL**

**Verified**: `es_heap_size`, `es_memory_high`, `es_memory_max` are **UNDEFINED repo-wide** — grep finds them
ONLY inside `ansible/templates/lme-elasticsearch.container.j2` `default()` filters and comments (no assignment
anywhere). So the Jinja defaults ARE the effective render. `es_discovery_type` IS actively computed (not
commented): `ansible/site.yml:46` and `ansible/elasticsearch.yml:59` both set
`es_discovery_type: "{{ 'cluster' if lme_cluster_mode|default(false) else 'single-node' }}"`. The effective
values:
- `lme-elasticsearch.container.j2:91` → `ES_JAVA_OPTS="...-Xms{{ es_heap_size|default('4g') }} -Xmx{{ es_heap_size|default('4g') }}"` → **heap 4g**, gated `es_heap_size is defined OR es_discovery_type default 'single-node' == 'single-node'`.
- `lme-elasticsearch.container.j2:19-20` → `MemoryHigh={{ es_memory_high|default('6G') }}`, `MemoryMax={{ es_memory_max|default('8G') }}`, gated `es_memory_max is defined OR single-node`.

**Fit judgment (16 GB single-node):** ES is hard-cgroup-capped at **MemoryMax=8G** with a **4g mlocked heap**
(comment at `:16-19` documents the invariant heap ≤ ~50% MemoryMax to avoid OOM-kill instead of throttle —
4g vs 8G satisfies it). This is a genuine, correct mitigation: without it ES defaults to ~50% of host RAM and
mlocks it. But 8 G for ES leaves ~8 G for pgvector + embeddings + llama_cpp (GGUF resident, ~1–2 G) + litellm
+ dashboard + log-analyzer + fleet-server + fleet-distribution + kibana (~1–1.5 G Node) + wazuh, and — with
`--elastic-services` — logstash (512m heap + JVM overhead ~1 G), apm-server, filebeat, metricbeat, heartbeat.
That is a **thin fit with little headroom** on 16 G; MemoryMax=8G is a HARD cap (OOM-kill on breach), mitigated
by the 4g mlock keeping ES under it in steady state.

**Gaps against R3:**
1. **No plumbed override.** Unlike `storage_graphroot` (which got full `-g` CLI→extra-vars plumbing), there is
   NO CLI flag / inventory var / extra-var wiring for `es_heap_size`/`es_memory_*`. To right-size a tighter box
   an operator must hand-edit or pass a bare `-e`; the "fit the iron" knob is effectively hardcoded defaults.
2. **Cluster path is uncapped (verified via `lme_cluster_mode`).** The `--cluster` install path sets
   `lme_cluster_mode=true` — `install.sh:847` `base['lme_cluster_mode'] = True` (Phase-1 master), and
   `ansible/elasticsearch.yml:51 lme_cluster_mode: true` (Phase-2 data nodes). So `es_discovery_type`
   resolves to `'cluster'` on the cluster path → both heap and MemoryMax gates
   (`es_memory_max is defined OR ...=='single-node'`) evaluate FALSE with the vars undefined → **ES runs
   UNCAPPED on BOTH master AND data nodes** (implicit ~50%-of-RAM heap, no `MemoryMax` cgroup). The
   single-node install path leaves `lme_cluster_mode=false` → `'single-node'` → capped. The template comment
   at `:83-88` ("cluster data nodes keep ES's implicit sizing unless es_heap_size is set explicitly") is
   therefore ACCURATE — no stated-vs-effective contradiction — but on 16 G cluster iron it means no backstop.

**→ R3 = Partial:** meaningful single-node backstop for the largest consumer, but reliant on undefined defaults,
no operator knob, thin 16 G margin with the full pack + LLM, and no cap on cluster data nodes.

---

## Seal gate (forward) — **PARTIAL / CANNOT-ASSESS**

Static code paths verified present and correct:
- **`--cluster` + `--offline` rejected outright**: `install.sh:891-895` → `exit 1` ("Offline cluster
  installation is not supported at this time"). ✅
- **Master-only pack/LLM on cluster**: `lme_child_es_only: "{{ (ansible_connection|default('ssh')) != 'local' }}"`
  (`ansible/elasticsearch.yml:97`; default `false` in `ansible/roles/podman/defaults/main.yml:9`). Gates the
  pack (`elastic_services_setup.yml:30 when: not lme_child_es_only`) and prunes non-ES quadlets on children
  (`quadlet_setup.yml:70,104,113,120,129,140`). ✅ So SSH data nodes run ES-only; pack/LLM/dashboard/pgvector
  live master-only.
- **No offline pack bundle (verified directly)**: `install.sh:636` warns `--elastic-services` is skipped under
  `--offline`; AND `scripts/prepare_offline.sh` reads ONLY `config/containers.txt` (`:14`) and
  `config/containers-llm.txt` (`:15`) — it **never references** `config/containers-elastic-services.txt`
  (which does list apm-server/logstash/beats), so the pack images are structurally absent from offline
  bundles. Note: the `prepare_offline.sh` change **in this PR** is unrelated to staging — it only adds
  `--network=host` to three `podman build` calls (ingest, log-analyzer, dashboard) so their `RUN apt/pip`
  steps get host connectivity; it does not alter what is bundled. Airgapped 1-node = core (+LLM if a `--llm`
  bundle staged). ✅
- **Non-interactive knobs present**: `NON_INTERACTIVE`, `AUTO_CREATE_ENV`, `AUTO_IP`
  (`install.sh:29-31`); cluster-nodes-only auto-enables `AUTO_CREATE_ENV` when NI + no env file
  (`install.sh:228-229`). ✅ Directly supports the rsync→ssh pipeline model.

**Blocker (pipeline, non-root path):** `sudo -v` at `install.sh:602,650,816` will hang / fail a
non-interactive ssh run unless the target has passwordless sudo. Moot when driving as **root over
`tailscale ssh`** (the stated deploy model), but any non-root path must handle it. With `NON_INTERACTIVE` set
and no `AUTO_IP`, IP resolution errors → the pipeline must set `AUTO_IP` per host.

**Cannot-Assess (needs live run):** the actual QEMU-instanced 1-node / 3-node-cluster / airgapped validation
(graph + trixie + QEMU-on-silmaril) is not statically decidable — no QEMU/nested-virt assumption is encoded in
these files (VM layer is pure infra; the repo installs the same inside it). **Settled by the QEMU/KVM e2e run**
the seal gate calls for. fleet-server's `UserNS=auto:uidmapping=0:171632:3048` × host-cert-uid-166536 idmap
path (`quadlet/lme-fleet-server.container:27`) is the one cert-reader still without runtime proof (its
`ConditionPathExists=…FLEET_SETUP_FINISHED` was unmet on the prior e2e) — also a live-run item.

---

## R4 — Tailscale closure (forward) — **PARTIAL**

- **INGRESS present, opt-in, OFF by default**: `ansible/roles/podman/tasks/tailscale_ingress.yml` (new, 85 lines),
  included from `ansible/roles/podman/tasks/elastic_services_setup.yml:99-104` gated
  `when: tailscale_serve_ingress | default(false) | bool`. Implements `tailscale serve --bg --https=8200/4000`
  (TLS-terminate to `https+insecure://127.0.0.1:*`) for apm/litellm and `--tcp=5044` raw passthrough for
  logstash beats (`tailscale_ingress.yml:60-73`). Idempotent against `tailscale serve status`; discovers
  MagicDNS name via `tailscale status --json` (`:48-50`). ✅
- **EGRESS ABSENT**: no `tailscale up`, `--advertise-routes`, or `--exit-node` anywhere (grep empty). ❌
- **VIP SERVICES ABSENT**: no `tailscale serve --service=svc:` anywhere (grep empty). ❌
- **tailscaled NOT installed by any role** (grep empty) → `tailscale_ingress.yml:31-45` fails fast if
  `tailscale status` rc≠0. **External execution prerequisite**: orchestrator must provision + login tailscaled
  (MagicDNS + HTTPS certs) before `-e tailscale_serve_ingress=true`. ❌ (unmanaged)

**→ R4 = Partial: 1 of 3 required legs (ingress) present as opt-in; egress + VIP-svc are the two missing legs;
tailscaled is an unmanaged external prereq.** Egress/svc need new tasks.

---

## Section Annotations (map)
- **S4 (LiteLLM↔pgvector):** R1 **Full** (secret-at-rest fixed). R2 **Partial** (host/port/db still baked).
- **S5 (Elastic pack):** R3 **Partial** (ES caps here). R2 **Partial** (new `lme.conf` ES host). Seal-gate:
  pack is master-only + offline-absent.
- **S6 (core cert-consumers):** R1 sibling `sk-lme-llama-proxy` lives in `lme-log-analyzer.container` (pre-existing).
- **S7 (tailscale ingress):** R4 **Partial** (ingress only).
- **S1/S2 (install/base):** seal-gate knobs + `sudo -v` blocker; R3 has no plumbed override (contrast the
  fully-plumbed `storage_graphroot`).

---

## Gaps
1. **R2**: prescribed `EnvironmentFile=` single-source not done; host/port/db/user still hardcoded in
   litellm/dashboard/pgvector units and the new `lme.conf` — no operator parameterization. (Partial, not Full.)
2. **R1 (repo-wide)**: plaintext `sk-lme-llama-proxy` proxy key at rest in 3 files (pre-existing, documented) —
   not fixed by this PR; recommend follow-up to podman-secret it.
3. **R3**: `es_heap_size`/`es_memory_*` have no CLI/inventory/extra-var plumbing (undefined repo-wide, defaults
   only); cluster data nodes are uncapped; 8 G ES + pack + LLM is a thin 16 G fit.
4. **R4**: egress + VIP-svc absent; tailscaled unmanaged (external prereq).
5. **Seal gate**: `sudo -v` (`install.sh:602/650/816`) blocks non-root non-interactive pipeline; QEMU 1/3/airgapped
   validation is Cannot-Assess without the live run.
6. **Adjacent (verified directly, bears on cluster seal):** `ansible/upgrade_lme.yml:882-890` re-land task
   `include_role: name=podman tasks_from=elastic_services_setup.yml` is gated `when: lme_pack_enabled | ...`
   ONLY — it does NOT add `not lme_child_es_only` (the install path relies on internal guards inside
   `elastic_services_setup.yml:30`, which gate the pack-quadlet COPY on `not lme_child_es_only`). Nuance:
   `upgrade_lme.yml` does not set `lme_child_es_only`, so it defaults `false` (`podman/defaults/main.yml:9`)
   and the internal guard is a no-op during upgrade. Practical risk is LOW for a master/single-host upgrade
   but the pack COULD re-land if `upgrade_lme.yml` is ever run against a cluster data node. Also new in this
   diff: pack detection `stat lme-apm-server.container` → `lme_pack_enabled` (`:146-160`), and AI-stack
   upgrade steps newly gated on `lme_llm_enabled` (`:672-674`, `:875-877`). Worth a reviewer check.
7. **Adjacent**: `lme-curator` SAN added (`config/setup/instances.yml:42`) with no curator quadlet consumer
   (dangling); `init-setup.sh` chmod discipline sits inside the `if [ ! -f certs.zip ]` fresh-install guard →
   upgrade may leave `ca.key` at old 0644 (round-2 open blocker, per flow-analysis — I did not re-verify the
   upgrade run but the guard placement in the diff is consistent with the claim).

## Questions
- **R2 scope**: Is decomposing `DATABASE_URL` into discrete baked `Environment=` lines (matching the dashboard)
  considered acceptable closure of round-3 Blocker-1, or does the operator still require `EnvironmentFile=`
  single-sourcing? This determines R2 Full vs Partial.
- **R1 scope**: Is `sk-lme-llama-proxy` (internal proxy key) in-scope for R1 in this PR, or explicitly deferred
  as a documented accepted plaintext?
- **R3 knob**: Should `es_heap_size`/`es_memory_*` get the same CLI→extra-vars plumbing as `storage_graphroot`
  so the 16 G iron can be right-sized without editing the template?

## Cannot-Assess (live-run items) — which run settles each
- Seal gate 1-node / 3-node / airgapped success on **QEMU/KVM** (graph+trixie+QEMU-on-silmaril e2e).
- fleet-server idmap cert-read (`FLEET_SETUP_FINISHED` gate) — same QEMU e2e.
- Actual peak RSS of full stack vs 16 G with `--elastic-services`+LLM — a monitored deploy run.
- `sudo -v` behaviour on a non-root ssh target — a non-root pipeline run (moot for root-over-tailscale-ssh).
- Whether `Secret=pgvector,type=env` surfaces `PGVECTOR_PASS` in `podman inspect lme-litellm` `Config.Env`
  (podman-version-dependent) — settled by an `inspect` on the QEMU e2e. (`DATABASE_URL` itself no longer
  appears there — moved into `Exec=` runtime.)
