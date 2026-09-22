# Flow Analyst — Sections 1–3 (branch `fix/debian-13-selinux-apt` vs `origin/main`)

Navigation map only — mechanism + `file:line`, no critique.

Backbone include order:
- `install.sh` → `ansible/site.yml` (roles: **base → nix → podman → elasticsearch → kibana → dashboards → wazuh → fleet → cleanup**, `site.yml:71-89`).
- `base/tasks/main.yml`: OS vars (`:3-10`) → SELinux (`:12-14`) → **common OS tasks = `debian.yml`** (`:17-22`) → **version-specific = `debian_13.yml`** (`:25-31`) → `setup_directories` (`:34`) → `load_env` (`:37`) → **`setup_passwords.yml`** (`:39-40`).
- `podman/tasks/main.yml`: OS vars/tasks → Nix/SELinux/podman install → sysctl/quadlet-link → **`container_setup.yml`** (`:233`) → **`setup_secrets.yml`** (`:237`) → **`quadlet_setup.yml`** (`:241`) → **`elastic_services_setup.yml`** (`:248-252`, gated `install_elastic_services` AND `not lme_child_es_only`) → **`llama_cpp_setup.yml`** (`:260-264`, gated `install_llm` AND `not lme_child_es_only`).

---

## Flow Analysis: install.sh
### Upstream (what invokes this)
- Operator entrypoint. Not invoked by anything else in-repo; sets defaults `PLAYBOOK_PATH=ansible/site.yml` (`:11`), `GRAPH_ROOT=/var/lib/containers/storage` (`:18`), `INSTALL_LLM=false` (`:19`), `INSTALL_ELASTIC_SERVICES=false` (`:20`).
- Flag parsing: `-o/--offline`→`OFFLINE_MODE`, `--llm`→`INSTALL_LLM` (`:86-87`), `--elastic-services`→`INSTALL_ELASTIC_SERVICES` (`:90-91`), `-p`→`PLAYBOOK_PATH` (`:95`), `-g/--graph-root`→`GRAPH_ROOT` (`:99`).
- Terminal dispatch: `run_cluster_playbooks` if `CLUSTER_MODE=true` (`:1381`), else `run_playbook` (`:1383`).
### Downstream (what it invokes / depends on)
- **New `compute_effective_flags()` (`:612-638`)** — hoisted out of `run_playbook` so both entrypoints share it. Sets globals `EFFECTIVE_INSTALL_LLM` / `EFFECTIVE_INSTALL_ELASTIC_SERVICES` (explicitly non-`local`). Rules: offline w/o `--llm` → LLM off; elastic-services only when flag set AND not offline.
- `run_playbook` (`:642`) calls `compute_effective_flags` (`:670`) then `ansible-playbook … site.yml` with extra-vars now including **`storage_graphroot: GRAPH_ROOT`** added at `:683` and `:685` (inventory / no-inventory branches).
- `run_cluster_playbooks` (`:808`) now also calls `compute_effective_flags` (`:836`); `BASE_EXTRA_VARS` (`:838`) gains `install_llm`, `install_elastic_services`, `storage_graphroot`. Phase 1 wraps it via `python3` into `master_extra_vars` (adds cluster keys) → `site.yml` (`:844-857`). Phase 2 passes **`BASE_EXTRA_VARS` verbatim** → `ansible/elasticsearch.yml` on data nodes (`:874`) — so `-g`, `install_llm`, `install_elastic_services` reach data nodes (extra-vars outrank `elasticsearch.yml`'s own play-var defaults at `elasticsearch.yml:32/40`).
- Produces the extra-vars consumed by `site.yml:12-13` defaults and `setup_passwords.yml:153`.
### Related Files
- `ansible/site.yml` (target playbook), `ansible/elasticsearch.yml` (cluster phase-2), `ansible/roles/base/tasks/setup_passwords.yml` (`storage_graphroot` consumer), `scripts/prepare_offline.sh` (offline `--llm` bundle referenced in preflight `:131-210`).
### Flow Context
Top of the install funnel: turns CLI flags into three extra-vars (`install_llm`, `install_elastic_services`, `storage_graphroot`) that gate role includes and the global storage.conf; single-node and cluster paths now share flag semantics.

---

## Flow Analysis: config/setup/instances.yml
### Upstream (what invokes this)
- Static SAN manifest. Staged to `/opt/lme/config/setup/instances.yml` by (a) `quadlet_setup.yml:4-11` whole-`config/` copy (`force: {{ lme_force_config | default(false) }}` — normally only fresh installs) and (b) **force-copied** by `elastic_services_setup.yml:10-18` (`config/setup/`, `force: true`).
- On upgrade also copied by `upgrade_lme.yml:591` (`src: config/setup/instances.yml`).
### Downstream (what it invokes / depends on)
- Read inside the **`lme-setup-certs`** container: `/opt/lme/config/setup` mounted at `lme-setup-certs.container:26` → `init-setup.sh` `INSTANCES_PATH` (`init-setup.sh:14`), consumed by `elasticsearch-certutil cert --in` (fresh mint) and the per-service `awk` top-up loop (`init-setup.sh:56`).
- Diff adds DNS SANs **`lme-logstash`** (logstash) and **`lme-curator`** (curator). `lme-logstash` SAN is dialed via `quadlet-optional/elastic-services/lme-logstash.container:20` `ContainerName=lme-logstash` + `:23` `--network-alias lme-logstash`. No curator quadlet exists in this pack (only `lme-logstash.container` present under `quadlet-optional/elastic-services/`); `lme-curator` SAN is minted but has no in-pack consumer traced here.
### Related Files
- `config/setup/init-setup.sh` (reader), `quadlet/lme-setup-certs.container` (mount + exec), `quadlet-optional/elastic-services/lme-logstash.container` (alias consumer), `config/logstash/pipeline/lme.conf` (logstash TLS endpoint, changed in this branch).
### Flow Context
SAN source for the ES-CA mesh; new aliases only matter after a cert (re)mint — pairs with the `LME_FORCE_CERT_REMINT` escape hatch added to init-setup.sh.

---

## Flow Analysis: ansible/roles/base/tasks/debian_13.yml
### Upstream (what invokes this)
- `base/tasks/main.yml:25-31` "Include version-specific tasks" `with_first_found`: `debian_13.yml` (wins for Debian 13) before falling back to `common.yml`.
- Distinct from `base/vars/debian_13.yml` (a *vars* file picked up separately at `main.yml:3-10` `include_vars`) — same basename, different dir; not a task include.
### Downstream (what it invokes / depends on)
- Now a **deliberate no-op** (comment only). Previously re-`include_tasks: debian.yml` (double-run, since `debian.yml` already runs at `main.yml:17-22`) and installed undefined `debian_13_packages` (no-op var). Removing the file would let the dispatch fall through to `common.yml` (installs `common_packages`, `common.yml:4-7`); keeping it empty pins resolution here for Debian 13.
### Related Files
- `base/tasks/debian.yml` (the common OS tasks already run once), `base/tasks/common.yml` (the fallback it suppresses), `base/vars/debian_13.yml` (sibling vars file).
### Flow Context
Pure dispatch anchor in the base role; changes nothing at runtime beyond preventing a duplicate `debian.yml` run and the common.yml fallthrough.

---

## Flow Analysis: ansible/roles/base/tasks/setup_passwords.yml
### Upstream (what invokes this)
- Last step of the base role: `base/tasks/main.yml:39-40` `include_tasks: setup_passwords.yml`. Runs in the **base** role, i.e. before the **podman** role pulls any image or writes any quadlet.
### Downstream (what it invokes / depends on)
- **HIBP block**: adds `status_code: 200` to the pwnedpasswords GET (`:42`); new debug warns when `hibp_response is failed` (`:52-61`); the fail gate now requires `hibp_response is not failed` and upper-cases the suffix `regex_search(suffix | upper)` (`:70-75`) — depends on `offline_mode`, `prefix`/`suffix` (SHA-1 split computed earlier in this file).
- **Global storage.conf**: task "setup global overlay-fs usage" writes `{{ global_storage_conf }}` = `/etc/containers/storage.conf` (`site.yml:25`), `graphroot = {{ storage_graphroot | default('/var/lib/containers/storage', **true**) }}` (`:153`). The `true` second arg makes `default` also replace an empty string (so an empty `-g ""`/blank extra-var falls back instead of writing an empty graphroot).
- Also writes `{{ user_storage_conf }}` (`:125`), `{{ password_file }}`/`/etc/lme/pass.sh`, and `/etc/lme/vault` (vault-pass tooling earlier in file) — those feed every unit that sets `Environment=ANSIBLE_VAULT_PASSWORD_FILE=/etc/lme/pass.sh` (e.g. `lme-setup-certs.container:10`, `lme-litellm.container.j2:13`).
### Related Files
- `install.sh` (produces `storage_graphroot`), `ansible/site.yml` (`global_storage_conf`/`storage_graphroot` defaults), `ansible/elasticsearch.yml` & `convert_to_cluster.yml` (re-declare the same vars for their plays).
### Flow Context
Writes the global podman graphroot **before** the podman role stores any image at that path — this is the "cert/secret created relative to consumer" ordering for `-g`; also the breach-check correctness path.

---

## Flow Analysis: config/setup/init-setup.sh
### Upstream (what invokes this)
- Executed only inside the `lme-setup-certs` oneshot container: `quadlet/lme-setup-certs.container:20` `Exec=/bin/bash …/config/setup/init-setup.sh` (`Type=oneshot`, `RemainAfterExit=yes`). That unit is `Requires`/`After` of ES, fleet-distribution, setup-accts, and every elastic-services pack unit (`*.container:4-5`).
- Re-fired on upgrade by `elastic_services_setup.yml:72-77` (`systemd: name=lme-setup-certs state=restarted`) and by the same include re-run from `upgrade_lme.yml` (see below).
### Downstream (what it invokes / depends on)
- Reads `INSTANCES_PATH=/usr/share/elasticsearch/config/setup/instances.yml` (mounted from `/opt/lme/config/setup`), mints CA + per-service certs into the **`lme_certs`** volume.
- **New perm discipline** (`:39-63`): `*.key` → `chmod 640` (owner+group `elasticsearch`), other files → `644`, `*.zip` → `600`, `ca/ca.key` → `600`. Top-up loop applies the same `640`/`644` split per service (`:80-82`).
- **New `LME_FORCE_CERT_REMINT`** (`:57-63`): env (`true`/`1`) from `/opt/lme/lme-environment.env` (`EnvironmentFile`, `lme-setup-certs.container:17`) forces re-mint of an existing `<svc>.crt`; otherwise `continue` (idempotent skip). This is the operator hook that makes the new `instances.yml` SANs take effect on an installed host.
- Depends on `ELASTIC_PASSWORD`/`KIBANA_PASSWORD` podman secrets (`lme-setup-certs.container:18-19`).
### Related Files
- Consumers of the `lme_certs` volume keys/chains: ES/kibana (mount at `config/certs`), and `:ro,idmap` readers `lme-litellm`, `lme-llama-cpp`, `lme-embeddings`, `lme-dashboard`, `lme-fleet-server`, `lme-fleet-distribution`, and pack beats `lme-apm-server`/`heartbeat`/`metricbeat`/`filebeat`/`logstash` (all `User=root` in-container, `ro,idmap` mount). The new `640` key mode is read by these mounts — mapping only; relevant to the MEMORY round-3 cert-0600/idmap blocker.
### Flow Context
The single cert-minting chokepoint; this branch tightens key perms and adds a forced-remint switch so `instances.yml` SAN edits propagate to already-installed hosts.

---

## Flow Analysis: ansible/roles/podman/tasks/container_setup.yml
### Upstream (what invokes this)
- `podman/tasks/main.yml:233` `include_tasks: container_setup.yml` (runs before `setup_secrets`/`quadlet_setup`).
### Downstream (what it invokes / depends on)
- Pulls/tags Elastic-services images; pull registered `pull_elastic_services_result` (`:153`), tag registered `tag_elastic_services_result` (`:181`). Both gated `not offline_mode` AND `install_elastic_services`.
- **New**: two `debug` display-loops iterate `pull_elastic_services_result.results` (`:163-172`) and `tag_elastic_services_result.results` (`:189-200`), item-level `when: item is failed`, `loop_control.label: item.item` — read exactly those registers.
### Related Files
- `config/containers-elastic-services.txt` (image list, same list used by `upgrade_lme.yml:416/437`), `elastic_services_setup.yml` (later stage that stages quadlets/config for these images).
### Flow Context
Image-acquisition stage for the opt-in pack; the added tasks only surface per-image pull/tag failures (matches the failure-visibility pattern already in upgrade_lme.yml).

---

## Flow Analysis: ansible/roles/podman/tasks/quadlet_setup.yml
### Upstream (what invokes this)
- `podman/tasks/main.yml:241` `include_tasks: quadlet_setup.yml` — after `setup_secrets.yml` (`:237`), before the pack/LLM includes.
### Downstream (what it invokes / depends on)
- Whole-`config/`→`/opt/lme/config/` copy (`:4-11`, `force: {{ lme_force_config | default(false) }}`) — the default-off propagation of `config/setup/instances.yml` (why `elastic_services_setup.yml` force-copies `config/setup/` separately).
- **Changed task**: "Render LiteLLM quadlet from template" (`:151-161`) renders `ansible/templates/lme-litellm.container.j2` → `/etc/containers/systemd/lme-litellm.container`, now with **`no_log: true`** (`:159`), gated `install_llm` (`:161`). The template assembles `DATABASE_URL` at container runtime from the `pgvector` env-secret (see template `:37`), not at render time.
- Renders `lme-elasticsearch.container.j2` (`:143-149`); prunes non-ES quadlets on child nodes (`:163-169`, `lme_child_es_only`).
### Related Files
- `ansible/templates/lme-litellm.container.j2` (rendered here; changed this branch), `llama_cpp_setup.yml` (creates the `pgvector`/`llm-keys` secrets the rendered unit consumes, and starts `lme-litellm.service`).
### Flow Context
Materializes quadlet unit files; the LiteLLM unit is now template-rendered (with `no_log`) here instead of statically copied downstream — render happens before the secrets it needs are created, which is fine because the unit is started later in `llama_cpp_setup.yml`.

---

## Flow Analysis: ansible/roles/podman/tasks/llama_cpp_setup.yml
### Upstream (what invokes this)
- `podman/tasks/main.yml:260-264` `include_tasks: llama_cpp_setup.yml`, gated `install_llm | default(true)` AND `not lme_child_es_only`. Last podman-role include.
### Downstream (what it invokes / depends on)
- **Removed** (diff): the old `copy: quadlet/lme-litellm.container → /etc/containers/systemd/` task. That responsibility moved upstream to `quadlet_setup.yml:151-161` (template render). Net effect: `quadlet/lme-litellm.container` (the static file, still modified in this branch's diff) is no longer an install input — the rendered `.j2` supersedes it.
- Still creates the `pgvector` podman secret (`:22-28`), `llm-keys` placeholder secret (`:157-162`), pulls/tags pgvector+litellm images (`:63-109`), stages `litellm_config.yaml` (`:179-180`), runs doc-ingestion into pgvector (`:301-325`), and enables/starts `lme-pgvector.service` (`:277`) then `lme-litellm.service` (`:358`).
### Related Files
- `ansible/templates/lme-litellm.container.j2` (the now-authoritative unit), `quadlet/lme-litellm.container` (now dead as install input), `quadlet/lme-pgvector.container`, `config/litellm_config.yaml`, `scripts/ingest_docs.py`.
### Flow Context
Builds the LLM stack; this branch removes its duplicate LiteLLM-quadlet copy so the template render in quadlet_setup.yml is the single source for that unit.

---

## Flow Analysis: ansible/roles/podman/tasks/elastic_services_setup.yml
### Upstream (what invokes this)
- **Install path**: `podman/tasks/main.yml:248-252`, gated `install_elastic_services` AND `not lme_child_es_only`.
- **Upgrade path (new)**: `upgrade_lme.yml` "Re-land Elastic services pack" `include_role: name=podman tasks_from=elastic_services_setup.yml`, gated `lme_pack_enabled` only (no `lme_child_es_only` guard on this second upstream — descriptive note vs the install-path guard). Reachable because `upgrade_lme.yml:8-9` defines `clone_directory` and `install_user`, which this file's tasks require.
### Downstream (what it invokes / depends on)
- Force-copies `config/setup/` (`:10-18`, `force: true`), copies pack quadlets `quadlet-optional/elastic-services/` → `/etc/containers/systemd/` (`:22-30`, skipped on child nodes), re-owns pack configs to root (`:38-58`), disables host `apm-server` (`:62-68`), **restarts `lme-setup-certs`** to run cert top-up (`:72-77`), starts pack units apm/heartbeat/metricbeat/filebeat/logstash (`:86-96`).
- **New downstream include** (`:98-104`): `include_tasks: tailscale_ingress.yml`, gated `tailscale_serve_ingress | default(false)` (opt-in, off by default).
### Related Files
- `quadlet-optional/elastic-services/*.container` (units started), `config/setup/instances.yml` + `init-setup.sh` (cert top-up via restarted `lme-setup-certs`), `ansible/roles/podman/tasks/tailscale_ingress.yml` (new, its only caller), `config/{apm-server,heartbeat,metricbeat,filebeat}.yml` + `config/logstash/` (re-owned configs).
### Flow Context
Single reusable "land the pack" task file now shared by install and upgrade; new tail is the opt-in tailscale ingress and the cert top-up trigger.

---

## Flow Analysis: ansible/upgrade_lme.yml
### Upstream (what invokes this)
- Operator-run per `scripts/upgrade/detect_version.sh` / `scripts/upgrade/version_upgrade.md:69`. Programmatic caller: **`.github/workflows/upgrade.yml`** (CI). Also referenced by `ansible/galaxy.yml`.
### Downstream (what it invokes / depends on)
- **New detection block**: `stat` `/etc/containers/systemd/lme-apm-server.container` → `elastic_pack_quadlet` (`:146-149`); `set_fact lme_pack_enabled = install_elastic_services | default(elastic_pack_quadlet.stat.exists)` and `lme_llm_enabled = install_llm | default(true)` (`:158-166`). Distinct fact names so an operator `-e install_elastic_services=…` override is honored (extra-vars outrank self-referential set_fact).
- Pack pull/tag gates flipped from `install_elastic_services` to **`lme_pack_enabled`** (`:422`, `:443`).
- AI-stack teardown (`:669-671`) and doc-ingestion (`:872-874`) now additionally gated on `lme_llm_enabled` (plus `< 2.3.0`).
- **New re-land task** (`:882-890`): `include_role: name=podman tasks_from=elastic_services_setup.yml`, gated `lme_pack_enabled` — this is the second upstream of elastic_services_setup.yml above. Also copies updated `instances.yml`/`init-setup.sh` (`:591/600`) before pack re-land.
### Related Files
- `scripts/upgrade/detect_version.sh` (announces the command + override), `ansible/roles/podman/tasks/elastic_services_setup.yml` (re-invoked role file), `config/containers-elastic-services.txt` (pack image list), `.github/workflows/upgrade.yml` (CI caller).
### Flow Context
Upgrade counterpart of the install flow: auto-detects an installed pack and re-lands its quadlets/config/cert-top-up (previously only re-pulled images), with `-e install_elastic_services=true` as the manual override.

---

## Flow Analysis: scripts/upgrade/detect_version.sh
### Upstream (what invokes this)
- Operator-run (`version_upgrade.md:20` `sudo …/detect_version.sh`); no programmatic in-repo consumer of its `exit 100` found (CI `upgrade.yml` invokes `upgrade_lme.yml` directly). Map entry: operator-invoked gate.
### Downstream (what it invokes / depends on)
- On upgrade-needed prints the `ansible-playbook upgrade_lme.yml` command; **new lines (`:66-67`)** document that an installed Elastic-services pack is auto-detected/re-applied and give the manual override `-e install_elastic_services=true`. Pure advisory text — mirrors the detection logic added in `upgrade_lme.yml`.
### Related Files
- `ansible/upgrade_lme.yml` (the command it prints), `scripts/upgrade/version_upgrade.md` (docs wrapper).
### Flow Context
Version-gate advisor at the head of the upgrade flow; the diff only adds guidance about the new pack auto-detection.

---

## Cross-File Flows

1. **Graphroot**: `install.sh -g` → `GRAPH_ROOT` → extra-var `storage_graphroot` (`install.sh:683/685/838`) → `setup_passwords.yml:153` writes `/etc/containers/storage.conf` graphroot — executed in the **base** role, **before** the **podman** role stores any image there. Cluster phase-2 passes `BASE_EXTRA_VARS` to `elasticsearch.yml` (`install.sh:874`), so `-g` reaches data nodes (extra-var overrides `elasticsearch.yml:32`).
2. **LLM flag**: `install.sh --llm`/offline logic → `compute_effective_flags` → `install_llm` extra-var → gates `podman/main.yml:260-264` (`llama_cpp_setup.yml`) and `quadlet_setup.yml:161` (LiteLLM render); upgrade side uses `lme_llm_enabled` (`upgrade_lme.yml:159`, default-on).
3. **Elastic-services flag**: `install.sh --elastic-services` → `install_elastic_services` extra-var → gates `container_setup.yml` pull/tag + display loops and `podman/main.yml:248-252` (`elastic_services_setup.yml`). Upgrade side: `detect_version.sh` → operator runs `upgrade_lme.yml` → `stat lme-apm-server.container` → `lme_pack_enabled` → re-land `elastic_services_setup.yml` (via `include_role`).
4. **Cert/SAN chain**: `instances.yml` SANs (`+lme-logstash`,`+lme-curator`) → staged to `/opt/lme/config/setup/instances.yml` (force-copied by `elastic_services_setup.yml:10-18`) → mounted `lme-setup-certs.container:26` → `init-setup.sh` mint/top-up into `lme_certs` volume with new `640` key perms → consumed `:ro,idmap` by pack beats + LiteLLM/llama/embeddings/dashboard/fleet; `LME_FORCE_CERT_REMINT` (init-setup.sh:57) is the operator switch to re-mint after a SAN edit; logstash SAN dialed via `lme-logstash.container` alias, `lme-curator` SAN has no in-pack quadlet consumer.
5. **LiteLLM unit relocation**: static copy removed from `llama_cpp_setup.yml` → now template-rendered in `quadlet_setup.yml:151-161` (`no_log`), gated `install_llm`; secrets `pgvector`/`llm-keys` created later in `llama_cpp_setup.yml:22-28/157-162`; `DATABASE_URL` assembled at container runtime (template `:37`); unit started `llama_cpp_setup.yml:358` (render-before-secret is safe because start is last). `quadlet/lme-litellm.container` is now dead as an install input though still edited in this diff.
6. **Vault plumbing**: `setup_passwords.yml` creates `/etc/lme/pass.sh` + `/etc/lme/vault` → referenced by `Environment=ANSIBLE_VAULT_PASSWORD_FILE=/etc/lme/pass.sh` in `lme-setup-certs.container:10` and `lme-litellm.container.j2:13`.

## Unresolved
- No hard unresolved upstream/downstream. Two descriptive gaps for reviewers: (a) `lme-curator` SAN added to `instances.yml` has no curator quadlet under `quadlet-optional/elastic-services/` (only `lme-logstash.container`), so its consumer is out of this changeset's scope; (b) the upgrade-path re-land of `elastic_services_setup.yml` (`upgrade_lme.yml`) is gated on `lme_pack_enabled` only, without the `not lme_child_es_only` guard the install path carries at `podman/main.yml:250-252` — noted as mechanism, not judged.

---

## Upcoming-direction readiness (1-node / 3-node cluster / airgapped)

Map of what supports vs. what's absent for the planned multimachine e2e (rsync repo → ssh prune+install across `graph` + `trixie` + a QEMU VM on `silmaril`). Descriptive only.

### install.sh: single-node vs 3-node cluster paths
- **Entry fork** (`install.sh:1380-1383`): `CLUSTER_MODE=true` → `run_cluster_playbooks`; else `run_playbook`. Cluster set by `--cluster` / `--cluster-inventory PATH` / `--cluster-master-only` / `--cluster-nodes-only` (`:102-118`) or env `LME_CLUSTER=true` (`:23`). Default cluster inventory `ansible/inventory/cluster.yml` (`:222-223`).
- **Single-node** (`run_playbook`): one `ansible-playbook site.yml` locally; extra-vars carry `install_llm`, `install_elastic_services`, `storage_graphroot` (`:683/685`).
- **3-node cluster** (`run_cluster_playbooks`): validates inventory exists (`:701`), parses `ansible-inventory --list` (`:712`), derives `CLUSTER_SEED_HOSTS` + `CLUSTER_MASTER_PUBLISH_HOST` via python (`:766-767`), pings the `elasticsearch` host group unless `--cluster-master-only` (`:781-793`). **Phase 1** = `site.yml` on master with `lme_cluster_mode=true`+seed/publish injected into `master_extra_vars` (`:840-857`). **Phase 2** = `elasticsearch.yml` on data nodes with `BASE_EXTRA_VARS` verbatim (`:868-874`).
- **Flag/extra-var deltas between paths**:
  - `storage_graphroot` (`-g`): reaches **both** master (via `master_extra_vars` built from `BASE_EXTRA_VARS`) and data nodes (Phase 2 `BASE_EXTRA_VARS`) — so `-g` lands in `/etc/containers/storage.conf` on all cluster nodes (extra-var overrides `elasticsearch.yml:32` default).
  - `--elastic-services` / `install_elastic_services`: passed to all nodes, but on data nodes `elasticsearch.yml:97` sets `lme_child_es_only = (ansible_connection != 'local') = true` for SSH children → `podman/main.yml:250-252` gates the pack **off** there and prunes non-ES quadlets. Net: pack installs on the **master only**; children stay ES-only.
  - `install_llm`: same child gating (`podman/main.yml:262-264`) — LLM stack master-only in cluster.
- **Cluster-specific stubs / single-node-only**: `--cluster` + `--offline` is **rejected outright** (`:891-892`) → no airgapped cluster path. `--cluster-master-only`/`--cluster-nodes-only` are mutually exclusive (`:897-898`). Phase-2 targets the inventory `elasticsearch` group only; no non-ES roles run on children by design.

### Airgapped / offline path (single-node only)
- **Detection**: `-o/--offline` → `OFFLINE_MODE=true` (`:79`); banner + hard requirement that `offline_resources/` exists, else exit 1 with staging instructions (`:912-925`). Optional integrity check via `scripts/validate_offline_archive.sh` (`:928`). Writes `/opt/lme/OFFLINE_MODE` sentinel (`:1208`). `offline_mode` extra-var gates `not offline_mode` tasks across roles (HIBP check `setup_passwords.yml:44`, image pulls in `container_setup.yml`/`llama_cpp_setup.yml`, nix-daemon mgmt `podman/main.yml`).
- **Pre-staged requirements**: repo extracted from `lme-offline-*.tar.gz` (built by `scripts/prepare_offline.sh` on an internet host) containing `offline_resources/`; nix podman pre-imported from `.nar` (per `podman/main.yml:208-211` offline skip). For `--offline --llm`, preflight (`:131-210`) additionally requires `offline_resources/MANIFEST` (`LLM_INCLUDED=true`, matching `arch`), six container image tars (llama.cpp, litellm, pgvector, ingest, log-analyzer, dashboard), two model ggufs (chat+embed), and `docs/lme-docs-scrape/index.tsv` row count matching `DOCS_PAGES`. Rebuild: `prepare_offline.sh --llm --arch <arch>`.
- **Gaps for airgapped**: `--elastic-services` has **no offline bundle** → `compute_effective_flags` (`install.sh:629-637`) forces it off (with warning) under `--offline`; the pack cannot be exercised airgapped. Offline w/o `--llm` also skips the LLM stack. So an airgapped e2e covers core only unless a `--llm` bundle is pre-staged; pack coverage requires an online node.

### Non-interactive / pipeline driveability (rsync → ssh prune+install)
- **Supported knobs**: `NON_INTERACTIVE=true` (`:29`) skips the install-choice prompt (`:370-374`) and IP prompts (`:515`,`:530`); `AUTO_IP=<ip>` supplies the IP non-interactively (`:461-464`); `AUTO_CREATE_ENV=true` (`:30`) auto-writes `lme-environment.env` (`:1231`) instead of erroring (`:1248`). The cluster-nodes-only path auto-enables `AUTO_CREATE_ENV` when `NON_INTERACTIVE` and no env file exists (`:228-229`) — this directly supports the "rsync repo to a fresh data node, ssh in, install" model.
- **Local/interactive assumptions that can block a pipeline**:
  - `sudo -v` password prompts (`:602`, `:650`, `:816`) will hang a non-interactive ssh run unless the target has **passwordless sudo** — the main gating precondition for driving `graph`/`trixie`/QEMU VM over ssh.
  - With `NON_INTERACTIVE=true` but no `AUTO_IP`, IP resolution errors out (`:515`) — pipeline must set `AUTO_IP` per host.
  - Phase-2 connectivity checks (`ansible … -m ping`, `:784`) assume the master can already ssh the data nodes — ordering constraint for the pipeline (nodes reachable before Phase 1/2).
- **Already non-interactively driveable in my files**: cert re-mint via `LME_FORCE_CERT_REMINT` env in `/opt/lme/lme-environment.env` (`init-setup.sh:57-63`); upgrade + pack re-land via `ansible-playbook upgrade_lme.yml -e install_elastic_services=true` (proven by CI caller `.github/workflows/upgrade.yml`); the `lme-setup-certs` restart/top-up in `elastic_services_setup.yml:72-77` runs under Ansible, no TTY.
- **Mutating steps I did NOT run (per orchestrator read-only constraint) — flagged as recommendations only**: the opt-in `tailscale_serve_ingress` path (`elastic_services_setup.yml:98-104` → `tailscale_ingress.yml`) performs host-facing `tailscale serve`-class mutations; if the QEMU-VM-on-silmaril leg needs host ingress, that include must be enabled at deploy time by the orchestrator (`-e tailscale_serve_ingress=true`), not by this analysis. No systemctl/podman/ssh state changes were performed.

### Readiness summary per target
- **1-node (local or ssh w/ passwordless sudo)**: fully supported; all three new extra-vars flow; pack + LLM available online.
- **3-node cluster**: supported online only; `-g` and pack/LLM flags propagate but pack/LLM are master-only (children `lme_child_es_only`); **no airgapped cluster** (`--cluster`+`--offline` rejected).
- **Airgapped 1-node**: supported for core (and LLM if `--llm` bundle pre-staged); **Elastic-services pack unavailable offline** by design.
