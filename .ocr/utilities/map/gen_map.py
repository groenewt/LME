#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Map run-6 generator. Single source of truth -> map.md + complete_map.json."""
import json, os, sys

SCRATCH = "/tmp/claude-1000/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/scratchpad"
MAP_MD = "/home/tristan/gitters/LME/.ocr/sessions/2026-09-18-fix-debian-13-selinux-apt/map/runs/run-6/map.md"
CANON = "/home/tristan/gitters/LME/.ocr/sessions/2026-09-18-fix-debian-13-selinux-apt/map/runs/run-6/canonical-files.txt"

# ---- numstat (added, deleted) per path -------------------------------------
NUM = {}
with open(os.path.join(SCRATCH, "numstat.txt")) as f:
    for line in f:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        a, d, p = line.split("\t")
        NUM[p] = (0 if a == "-" else int(a), 0 if d == "-" else int(d))

# ---- section definitions ----------------------------------------------------
# each: number, title, description (JSON), hypothesis (md narrative),
# flow, requirements-line, suggestions[], files[(path, role)]
SECTIONS = [
 {
  "number": 1,
  "title": "Manifest render engine (B0/B4 + SF-8 budget)",
  "description": "The resolution backbone the whole B0 cutover rests on: merges service manifests + profile + global into a rendered unit model. R2/B0 (nothing hand-held) and R3 both route here — memory_budget() computes the SF-8 co-residency budget from lme_global.budget {host_ram_gb, reserve_gb} in global.yml; the hard oversized==[] gate is asserted downstream in container_setup.yml (S07).",
  "hypothesis": "Appears to be the resolver backbone the entire B0 render cutover rests on: `lme_manifests.py` merges the per-service manifests, the selected profile overlay, and the global defaults into one resolved unit model, and derives the SF-8 co-residency budget. Everything downstream (templates, orchestration, tests) is a consumer of what this section produces.",
  "flow": "`lme_manifests.py` (resolver filters + `memory_budget` SF-8) ← `load_manifests.yml` invokes the merge contract (global.yml | profile | override; service | profile.services | overrides) → `render_units.yml` writes units from the resolved model through the S02 templates.",
  "reqs": "R2-B0 ✅, R3 ✅, T3-B5 ✅ (exercised by S13)",
  "suggestions": [
    "Verify whether `memory_budget()` splits advisory `over_budget` (WARN) from hard `oversized` (FAIL) exactly as S07's preflight assumes — the R3 gate polarity lives across the two files.",
    "Confirm the `load_manifests` merge precedence (operator override LAST) matches what `wipe_lme.sh` re-derives in bash (S05) so teardown and deploy agree on the service set.",
    "Check that a fresh OFFLINE render reproduces every semantic the deleted static tree (S15) carried — this is the B0/Blocker-1 pivot.",
  ],
  "files": [
    ("ansible/roles/podman/filter_plugins/lme_manifests.py", "Resolver filters + memory_budget SF-8 co-residency"),
    ("manifests/global.yml", "Global defaults + budget block the resolver merges"),
    ("ansible/roles/podman/tasks/load_manifests.yml", "Loads manifests+profile, invokes resolver merge contract"),
    ("ansible/roles/podman/tasks/render_units.yml", "Writes systemd units from the resolved model"),
  ],
 },
 {
  "number": 2,
  "title": "Unit templates (render targets)",
  "description": "The Jinja2 targets render_units.yml fills — where ports/mounts/secrets/MemoryMax/:idmap actually land in a unit; B4 cert wiring and budget caps are visible here. The deleted lme-elasticsearch.container.j2 is the last hand-rolled template the generic renderer replaces.",
  "hypothesis": "Appears to be the render targets the resolver drives: the generic Jinja2 unit templates where ports, mounts, secret refs, `MemoryMax`, and `:idmap` actually materialize. The deleted ES-specific template suggests the intent is to replace every hand-rolled unit with one generic renderer.",
  "flow": "`render_units.yml` (S01) fills `container.j2` (workhorse) / `volume.j2` / `network.j2` / `path_service.j2` / `target.j2`; `lme-elasticsearch.container.j2` deleted — the renderer must reproduce it.",
  "reqs": "R2-B0 ✅, R3 ✅ (MemoryMax caps), B4 ✅ (cert mounts)",
  "suggestions": [
    "In `container.j2`, verify whether every value (ports/mounts/secrets/MemoryMax/idmap) reads from the resolved model with no literal fallback — a hidden default would reintroduce hardcoding (R2-B0).",
    "Confirm the deleted `lme-elasticsearch.container.j2` has no unique directive that the generic `container.j2` drops.",
  ],
  "files": [
    ("ansible/templates/units/container.j2", "Container unit template: ports/mounts/secrets/MemoryMax/idmap"),
    ("ansible/templates/units/volume.j2", "Volume unit template"),
    ("ansible/templates/units/network.j2", "Network unit template"),
    ("ansible/templates/units/path_service.j2", "Path+service unit template"),
    ("ansible/templates/units/target.j2", "Target unit template"),
    ("ansible/templates/lme-elasticsearch.container.j2", "Deleted hand-rolled ES template the renderer replaces"),
  ],
 },
 {
  "number": 3,
  "title": "Service manifests (declarative source of truth)",
  "description": "The per-service declarations the resolver consumes — every port, mount, secret name, image ref, uid/gid, MemoryMax cap (R1/R2/R3 live or die here). lme-kibana.yml (kibana-CA rewrite) and lme-wazuh-manager.yml (wazuh-CVE mount) are the render EQUIVALENTS the Blocker-1 check turns on; pair with S15 deletions + S08 role tasks.",
  "hypothesis": "Appears to be the declarative source of truth the resolver consumes: one manifest per service naming every port, mount, secret, image ref, uid/gid, and MemoryMax cap. R1/R2/R3 stand or fall here. `lme-kibana.yml` and `lme-wazuh-manager.yml` look like the render equivalents that close Blocker-1.",
  "flow": "Consumed by the S01 resolver; the two ⚑ manifests are the render leg of the Blocker-1 triad (deleted unit S15 ↔ manifest here ↔ role task S08). Manifests mount static config from S11.",
  "reqs": "R1 ✅ (secret names, no cleartext), R2-B0 ✅ (all literals here), R3 ✅ (per-service caps)",
  "suggestions": [
    "`lme-kibana.yml` — verify the kibana-CA rewrite that the deleted `quadlet/lme-kibana.container` carried is reproduced (Blocker-1).",
    "`lme-wazuh-manager.yml` — verify the wazuh-CVE mount (offline `enabled_when`) is present so an offline render does not DROP it (Blocker-1).",
    "`lme-litellm.yml` — verify master_key is a per-install podman secret (env type) and the bind defaults to loopback (R1 / Round-4 Blocker-2).",
    "Spot-check each manifest's MemoryMax against the S01 budget so the aggregate clears `oversized` on a 16 GB node (R3).",
  ],
  "files": [
    ("manifests/services/lme-network.yml", "Network infra unit declaration"),
    ("manifests/services/lme.service.yml", "Root lme.service target declaration"),
    ("manifests/services/lme-backups.volume.yml", "Backups volume declaration"),
    ("manifests/services/lme-esdata01.volume.yml", "Elasticsearch data volume declaration"),
    ("manifests/services/lme-filebeatdata.volume.yml", "Filebeat data volume declaration"),
    ("manifests/services/lme-kibanadata.volume.yml", "Kibana data volume declaration"),
    ("manifests/services/lme-pgvectordata.volume.yml", "pgvector data volume declaration"),
    ("manifests/services/lme-elasticsearch.yml", "Elasticsearch service manifest (ports/caps/certs)"),
    ("manifests/services/lme-kibana.yml", "Kibana manifest — ⚑ Blocker-1 kibana-CA rewrite equivalent"),
    ("manifests/services/lme-setup-certs.yml", "Cert-setup one-shot manifest"),
    ("manifests/services/lme-setup-accts.yml", "Account-setup one-shot manifest"),
    ("manifests/services/lme-fleet-server.yml", "Fleet server manifest"),
    ("manifests/services/lme-fleet-distribution.yml", "Fleet artifact distribution manifest"),
    ("manifests/services/lme-filebeat.yml", "Filebeat manifest"),
    ("manifests/services/lme-metricbeat.yml", "Metricbeat manifest"),
    ("manifests/services/lme-heartbeat.yml", "Heartbeat manifest"),
    ("manifests/services/lme-apm-server.yml", "APM server manifest"),
    ("manifests/services/lme-logstash.yml", "Logstash manifest"),
    ("manifests/services/lme-elastalert.yml", "Elastalert manifest"),
    ("manifests/services/lme-wazuh-manager.yml", "Wazuh manifest — ⚑ Blocker-1 CVE-mount equivalent"),
    ("manifests/services/lme-litellm.yml", "LiteLLM proxy manifest (per-install master key, loopback)"),
    ("manifests/services/lme-llm-keys.yml", "LLM keys secret manifest"),
    ("manifests/services/lme-llama-cpp.yml", "llama.cpp server manifest"),
    ("manifests/services/lme-llama-model.yml", "llama model fetch/volume manifest"),
    ("manifests/services/lme-embeddings.yml", "Embeddings service manifest"),
    ("manifests/services/lme-pgvector.yml", "pgvector Postgres manifest"),
    ("manifests/services/lme-dashboard.yml", "Dashboard WebUI manifest"),
    ("manifests/services/lme-log-analyzer.yml", "Log-analyzer WebUI manifest"),
  ],
 },
 {
  "number": 4,
  "title": "Manifest profiles (the profile matrix)",
  "description": "The --profile switches the resolver overlays onto the base set — the input contract for the setup->deploy->teardown matrix. Kept together so a reviewer sees the whole matrix at once. Cross-refs: tailscale.yml->S06, offline.yml->S05/S09, cluster.yml+multinode.yml->S10.",
  "hypothesis": "Appears to be the input contract for the profile matrix (anchor 2): each `--profile` is a resolver overlay onto the base manifest set. Grouped so the reviewer sees the whole matrix at once.",
  "flow": "Overlaid by the S01 resolver; `tailscale.yml`→S06 legs, `offline.yml`→S05 airgapped + S09 apt-cache, `cluster.yml`/`multinode.yml`→S10 cross-machine.",
  "reqs": "R4 ✅ (tailscale profile wiring), SEAL ⚠️ (matrix legs proving), D1 ⚠️, D2 ⚠️",
  "suggestions": [
    "`tailscale.yml` — verify it wires all three legs' service-binds (the profile is the only place VIP service-binds come from, per install.sh).",
    "`cluster.yml` — verify it raises `host_ram_gb` (to 32) so the full stack clears `oversized` on a roomy VM (R3).",
    "`multinode.yml` — confirm 8220/9200 are opened intentionally for fleet, and only under this profile.",
  ],
  "files": [
    ("manifests/profiles/default.yml", "Baseline profile (no overlay)"),
    ("manifests/profiles/tailscale.yml", "Tailscale profile — wires the 3 serve legs"),
    ("manifests/profiles/offline.yml", "Offline/airgapped profile overlay"),
    ("manifests/profiles/cluster.yml", "Cluster profile (raises RAM budget)"),
    ("manifests/profiles/multinode.yml", "Multinode profile (opens 8220/9200 fleet)"),
  ],
 },
 {
  "number": 5,
  "title": "Deploy/gate pipeline harness + AIRGAPPED leg",
  "description": "Anchor (2)+(4): the REAL rsync+ssh pipeline (deploy_gate.sh -> install.sh/ansible -> wipe_lme.sh), never ad-hoc. Owns the qemu-airgapped leg (validating now): prepare_offline.sh builds the offline bundle (cross-refs offline.yml S04, base/debian.yml apt-cache gate S09, install.sh offline path). HEALTH Finding A (tailnet allowance for ingress 8200/4000/5044 only) and surfaced wipe accept-routes host-global revert [C] + derive-svc [B] live here.",
  "hypothesis": "Appears to be the real seal-gate pipeline (anchors 2 and 4): `deploy_gate.sh` rsyncs the whole tree to `root@HOST:/root/LME-gate` over tailnet ssh, then invokes only the tree's own entrypoints — `wipe_lme.sh` → `install.sh` → a remote HEALTH probe → `wipe_lme.sh`. This section also owns the qemu-airgapped leg via `prepare_offline.sh`.",
  "flow": "`deploy_gate.sh` (harness + HEALTH gate + Finding A tailnet allowance) → `install.sh` (deploy arm: flag→profile derivation, `--extra-vars` passthrough) → `prepare_offline.sh` (airgapped bundle) → `wipe_lme.sh` (teardown: derive-svc [B] + guarded accept-routes revert [C]).",
  "reqs": "SEAL ⚠️ (legs proving), D2 ⚠️, D3 ⚠️ (surfaced items b/d live here), D4 ✅ (no ad-hoc — tree scripts only)",
  "suggestions": [
    "`deploy_gate.sh` — the HEALTH tailnet allowance (Finding A) widens only for ingress ports 8200/4000/5044; verify whether a `--profile tailscale` run's services-leg VIP ports 443/8502/8501 would FALSE-FAIL the exposure check (anchor 1 / D3-b OPEN).",
    "`wipe_lme.sh` — the `accept-routes` revert is host-global; flag the surfaced co-tenant impact on a shared node (D3-d) — this is a flag, not a verdict.",
    "`wipe_lme.sh` — verify the bash service-derivation [B] agrees with the S01 resolver's set so teardown removes exactly what deploy created (fail-closed, B2).",
    "`prepare_offline.sh` — confirm the deb13 root-hostile `nix curl|sh` path is resolved for the qemu-airgapped leg (cross-ref S09 apt-cache gate).",
  ],
  "files": [
    ("testing/e2e/deploy_gate.sh", "Pipeline harness: rsync→wipe→install→health→teardown + HEALTH gate"),
    ("install.sh", "Deploy arm: flag→profile derivation + --extra-vars passthrough"),
    ("scripts/prepare_offline.sh", "Airgapped offline bundle builder"),
    ("scripts/wipe_lme.sh", "Teardown arm: derive-svc + guarded accept-routes revert"),
  ],
 },
 {
  "number": 6,
  "title": "Tailscale 3-leg closure (ingress/egress/SVC)",
  "description": "Anchor (1): the three serve legs + daemon install. OPEN question routed here — does a full --profile tailscale deploy pass deploy_gate HEALTH on the services-leg VIP ports 443/8502/8501 (wave-4b widened HEALTH only for ingress ports 8200/4000/5044, see deploy_gate.sh S05); Finding D operator svc-grants in tailnet policy. Legs are included from podman main.yml (S07) and gated by tailscale.yml (S04).",
  "hypothesis": "Appears to close R4's three tailscale legs plus a daemon-install prerequisite: ingress (host TLS serve on 8200/4000/5044, DONE), egress (accept-routes), and services (serve --service=svc:NAME on VIP 443/8502/8501, wired+gated). The open question is whether the services leg passes the HEALTH exposure gate.",
  "flow": "`tailscale_install.yml` (daemon prereq, hoisted before elastic pack) → `tailscale_ingress.yml` (serve --https) → `tailscale_egress.yml` (accept-routes) → `tailscale_service.yml` (serve --service VIP). Included from S07 podman main.yml, gated by S04 tailscale profile; HEALTH probed by S05.",
  "reqs": "R4 ✅ (all three legs present + install path), D1 ⚠️ (services-leg HEALTH + svc-grants OPEN)",
  "suggestions": [
    "`tailscale_service.yml` — the VIP ports 443/8502/8501 are NOT in the deploy_gate HEALTH tailnet-OK set (only 8200/4000/5044 are); verify whether a full `--profile tailscale` run passes HEALTH or needs `LME_GATE_TAILNET_OK` widening (anchor 1 / D1).",
    "Finding D: verify whether operator svc-grants in the tailnet ACL policy are a documented prerequisite for the services leg (out-of-repo dependency to flag).",
    "`tailscale_install.yml` — confirm daemon install is idempotent and correctly ordered before the elastic pack nests the ingress leg (S07).",
  ],
  "files": [
    ("ansible/roles/podman/tasks/tailscale_install.yml", "Tailscale daemon install (hoisted before elastic pack)"),
    ("ansible/roles/podman/tasks/tailscale_ingress.yml", "Ingress leg: serve --https 8200/4000/5044"),
    ("ansible/roles/podman/tasks/tailscale_egress.yml", "Egress leg: accept-routes + opt-in exit-node"),
    ("ansible/roles/podman/tasks/tailscale_service.yml", "Services leg: serve --service VIP 443/8502/8501"),
  ],
 },
 {
  "number": 7,
  "title": "Podman role orchestration (secrets / budget preflight / include-wiring)",
  "description": "The include/gating hub that sequences setup->secrets->render->packs->tailscale legs. R3 hard gate is asserted here (SF-8 preflight oversized==[], WARN-only on over_budget, in container_setup.yml). Surfaced-not-fixed (anchor 3): container_setup.yml:231 podman shell-secret non-root HOME mode (fails as non-root; the real pipeline runs as root so graph/trixie pass). quadlet_setup.yml invokes load_manifests->render_units (S01).",
  "hypothesis": "Appears to be the include/gating hub that sequences the podman role: setup → secrets → render → optional packs → tailscale legs. The R3 hard budget gate is asserted here, and a non-root shell-secret HOME-mode item is surfaced for review.",
  "flow": "`main.yml` (include wiring + leg/pack gating) → `container_setup.yml` (secrets + SF-8 preflight, asserts `oversized==[]`) → `quadlet_setup.yml` (invokes S01 load_manifests→render_units) → `elastic_services_setup.yml` (nests S06 ingress leg) → `llama_cpp_setup.yml`; `defaults/main.yml`, `link_latest_podman_quadlet.sh` support.",
  "reqs": "R2-B0 ✅ (render cutover), R3 ✅ (hard oversized gate + WARN over_budget), R1 ✅ (secret preflight B3), D3 ⚠️ (L231 non-root item)",
  "suggestions": [
    "`container_setup.yml:231` — surfaced: the podman shell-secret uses a non-root HOME mode that fails as non-root; the real pipeline runs as root (graph/trixie pass). Flag for review — do NOT adjudicate (D3-a).",
    "`container_setup.yml` — verify the SF-8 preflight FAILS hard on `oversized` before any image pull, and only WARNs on advisory `over_budget` (R3).",
    "`container_setup.yml` — the B3 secret preflight should assert every rendered-unit secret has a creation recipe; verify no rendered secret is unbacked (R1).",
  ],
  "files": [
    ("ansible/roles/podman/tasks/main.yml", "Include/gating hub: setup→secrets→render→packs→legs"),
    ("ansible/roles/podman/tasks/container_setup.yml", "Secrets + SF-8 budget preflight (hard oversized gate)"),
    ("ansible/roles/podman/tasks/quadlet_setup.yml", "Drives load_manifests→render_units pipeline"),
    ("ansible/roles/podman/tasks/elastic_services_setup.yml", "--elastic-services pack (nests ingress leg)"),
    ("ansible/roles/podman/tasks/llama_cpp_setup.yml", "LLM pack setup"),
    ("ansible/roles/podman/defaults/main.yml", "Podman role defaults"),
    ("scripts/link_latest_podman_quadlet.sh", "nix→systemd generator-binary symlink helper"),
  ],
 },
 {
  "number": 8,
  "title": "Site / upgrade orchestration + secondary roles",
  "description": "Top-level play wiring + the upgrade path. Surfaced-not-fixed (anchor 3): upgrade LLM-off core cert bundles still unpublished (pre-existing) — trace in upgrade_lme.yml (wave-4b cert-publish added). The kibana + wazuh role tasks are the third leg of the Blocker-1 equivalence triad (S15 deleted unit <-> S03 manifest <-> this role task).",
  "hypothesis": "Appears to be the top-level play orchestration plus the upgrade path. `site.yml` sequences base→nix→podman→certs with `lme_autostart:false`; `upgrade_lme.yml` ports the upgrade to the render pipeline. The kibana/wazuh role tasks are the third leg of the Blocker-1 triad.",
  "flow": "`site.yml` (play orchestration; sole lme.service start after certs published) invokes S07 podman role, S09 base/nix, S10 certs/cluster. `upgrade_lme.yml` (render cutover + cert-publish). Role tasks kibana/wazuh ⚑ pair with S03 manifests + S15 deletions.",
  "reqs": "R2-B0 ✅ (upgrade render cutover), B4 ⚠️ (LLM-off core cert bundles surfaced), D3 ⚠️ (c)",
  "suggestions": [
    "`upgrade_lme.yml` — surfaced: with LLM off, core cert bundles remain unpublished (pre-existing); flag whether the wave-4b cert-publish covers the non-LLM path (D3-c).",
    "`site.yml` — verify the deferred `elastic_services_setup`/`llama_cpp_setup` includes run AFTER the certs role publishes per-svc bundles (B4 ordering).",
    "`roles/kibana/tasks/main.yml` + `roles/wazuh/tasks/main.yml` — the role-task leg of the Blocker-1 triad; verify they no longer depend on the deleted static units.",
  ],
  "files": [
    ("ansible/site.yml", "Top-level play orchestration + role sequencing"),
    ("ansible/upgrade_lme.yml", "Upgrade path: render cutover + cert-publish"),
    ("scripts/upgrade/detect_version.sh", "Upgrade version detector"),
    ("scripts/upgrade/version_upgrade.md", "Upgrade version note"),
    ("ansible/roles/kibana/tasks/main.yml", "Kibana role task — ⚑ Blocker-1 triad leg"),
    ("ansible/roles/wazuh/tasks/main.yml", "Wazuh role task — ⚑ Blocker-1 triad leg"),
    ("ansible/roles/dashboards/tasks/main.yml", "Dashboards import role task"),
    ("ansible/roles/backup_lme/tasks/main.yml", "Backup role task"),
  ],
 },
 {
  "number": 9,
  "title": "Base role / SELinux / Nix (Debian-13 OS-family)",
  "description": "The OS-family branching this branch is named for. deb13 offline apt-cache gate (wave-4a, debian.yml) supports the S05 airgapped leg. selinux_redhat.yml (+138) is UNVERIFIED (no RedHat node in the tailnet — source-only). setup_passwords.yml is the R1 password bootstrap.",
  "hypothesis": "Appears to implement the OS-family branching the branch is named for: base/SELinux/Nix tasks split by family/version and dispatched from `main.yml`. The deb13 offline apt-cache gate supports the airgapped leg; the RedHat SELinux half is source-only (no RH node in the tailnet).",
  "flow": "`base/tasks/main.yml` (family dispatcher) → `debian.yml` (offline apt-cache gate) / `debian_13.yml` / `redhat.yml`; `selinux_setup.yml` (dispatcher) → `selinux_common/debian/redhat.yml`; `setup_passwords.yml` (R1 bootstrap); `nix/tasks/*` install path.",
  "reqs": "R1 ✅ (password bootstrap), SEAL ⚠️ (deb13 apt-cache gate feeds airgapped), coverage-gap: SELinux is a Debian no-op; `selinux_redhat.yml` UNVERIFIED",
  "suggestions": [
    "`selinux_redhat.yml` (+138) — UNVERIFIED on real iron (no RedHat node in this tailnet); review from source only and flag as an unproven leg.",
    "`base/tasks/debian.yml` — verify the wave-4a apt-cache 'Update apt cache' is correctly gated on `offline_mode` so the airgapped leg does not try the network (SEAL / S05).",
    "`setup_passwords.yml` — verify per-install password minting, nothing cleartext (R1).",
  ],
  "files": [
    ("ansible/roles/base/tasks/main.yml", "OS-family dispatcher"),
    ("ansible/roles/base/tasks/debian.yml", "Debian base + offline apt-cache gate"),
    ("ansible/roles/base/tasks/debian_13.yml", "Debian-13 specifics"),
    ("ansible/roles/base/vars/debian_13.yml", "Debian-13 vars"),
    ("ansible/roles/base/defaults/main.yml", "Base role defaults"),
    ("ansible/roles/base/tasks/redhat.yml", "RedHat base (reduced)"),
    ("ansible/roles/base/tasks/selinux_setup.yml", "SELinux dispatcher (family-split)"),
    ("ansible/roles/base/tasks/selinux_common.yml", "SELinux common tasks"),
    ("ansible/roles/base/tasks/selinux_debian.yml", "SELinux Debian (no-op path)"),
    ("ansible/roles/base/tasks/selinux_redhat.yml", "SELinux RedHat (UNVERIFIED — no RH node)"),
    ("ansible/roles/base/tasks/setup_directories.yml", "Directory bootstrap"),
    ("ansible/roles/base/tasks/setup_passwords.yml", "R1 password bootstrap"),
    ("ansible/roles/nix/tasks/main.yml", "Nix role dispatcher"),
    ("ansible/roles/nix/tasks/debian.yml", "Nix Debian path"),
    ("ansible/roles/nix/tasks/debian-13.yml", "Nix Debian-13 install path"),
  ],
 },
 {
  "number": 10,
  "title": "Cluster / multinode / fleet enroll + certs",
  "description": "Anchor (2) cross-machine leg — graph<->trixie TLS-SAN proven (M2a), live-agent-enroll (M3) OPEN. Certs (B4 CA/MITM) + SAN list drive the cross-node TLS; fleet/tasks/main.yml carries the wave-3 host-registration polarity fix. Pairs with cluster.yml/multinode.yml profiles (S04).",
  "hypothesis": "Appears to be the cross-machine leg (anchor 2): cluster ES plays, per-node inventory, the certs role (CA/MITM + SAN list driving cross-node TLS), and the fleet host-registration polarity fix. graph↔trixie TLS-SAN is proven (M2a); live-agent-enroll (M3) is open.",
  "flow": "`elasticsearch.yml` (cluster ES play) + `convert_to_cluster.yml` + inventory `group_vars`/`host_vars` es1/2/3; `certs/tasks/main.yml` (CA mint, B4) + `instances.yml.j2` (SAN list) drive cross-machine TLS; `fleet/tasks/main.yml` (host-reg polarity, M3 enroll). Pairs with S04 cluster/multinode profiles.",
  "reqs": "B4 ✅ (CA/cert mint), D2 ⚠️ (M2a proven / M3 live-agent-enroll OPEN), SEAL ⚠️",
  "suggestions": [
    "`certs/templates/instances.yml.j2` — verify the SAN list includes the cross-node identities (graph & trixie) so cross-machine TLS validates (M2a).",
    "`fleet/tasks/main.yml` — verify the wave-3 host-registration polarity fix and flag M3 (live-agent-enroll) as the open cross-machine item.",
    "Inventory `host_vars/es{1,2,3}.yml` — confirm per-node identities are consistent with the cluster profile (S04).",
  ],
  "files": [
    ("ansible/elasticsearch.yml", "Cluster ES play"),
    ("ansible/convert_to_cluster.yml", "Single→cluster conversion play"),
    ("ansible/inventory/group_vars/elasticsearch.yml", "Cluster ES group vars"),
    ("ansible/inventory/host_vars/es1.yml", "Cluster node es1 host vars"),
    ("ansible/inventory/host_vars/es2.yml", "Cluster node es2 host vars"),
    ("ansible/inventory/host_vars/es3.yml", "Cluster node es3 host vars"),
    ("ansible/roles/certs/tasks/main.yml", "CA/cert mint (B4)"),
    ("ansible/roles/certs/templates/instances.yml.j2", "Cert SAN list (cross-machine TLS-SAN)"),
    ("ansible/roles/fleet/tasks/main.yml", "Fleet host-reg polarity + M3 enroll surface"),
  ],
 },
 {
  "number": 11,
  "title": "Config (beats / setup bootstrap / LLM proxy)",
  "description": "The static config the containers consume. litellm_config.yaml is the R1 surface (per-install master key via env + loopback bind). config/setup/* bootstraps certs/instances.",
  "hypothesis": "Appears to be the static config the service containers mount: beats configs, the cert/instances bootstrap, the logstash pipeline, and the LiteLLM proxy config. `litellm_config.yaml` reading `master_key` from the environment is the R1 surface.",
  "flow": "Mounted by the S03 service manifests. `config/setup/init-setup.sh` + `instances.yml` bootstrap certs; `litellm_config.yaml` reads master_key from `LITELLM_MASTER_KEY` env (R1); beats/logstash configs consumed by their manifests.",
  "reqs": "R1 ✅ (litellm master_key via env, no cleartext)",
  "suggestions": [
    "`config/litellm_config.yaml` — verify `master_key: os.environ/LITELLM_MASTER_KEY` (no committed literal key) so Round-4 Blocker-2 stays closed (R1).",
    "`config/setup/init-setup.sh` — confirm the bootstrap does not emit secrets to disk in cleartext.",
  ],
  "files": [
    ("config/setup/init-setup.sh", "Setup bootstrap script (certs/instances)"),
    ("config/setup/instances.yml", "Cert instances config"),
    ("config/litellm_config.yaml", "LiteLLM config — R1 master_key via env"),
    ("config/filebeat.yml", "Filebeat config"),
    ("config/metricbeat.yml", "Metricbeat config"),
    ("config/heartbeat.yml", "Heartbeat config"),
    ("config/apm-server.yml", "APM server config"),
    ("config/logstash/logstash.yml", "Logstash base config"),
    ("config/logstash/pipeline/lme.conf", "Logstash pipeline"),
    ("config/containers-elastic-services.txt", "Elastic services container list"),
  ],
 },
 {
  "number": 12,
  "title": "WebUI apps (inbound auth)",
  "description": "The dashboard/log-analyzer apps whose auth the HEALTH gate asserts (dashboard /api/health :8502 with no key -> 401/403; log-analyzer gates in-app). These back the tailscale services-leg VIP ports 443/8502/8501 (S06 OPEN question).",
  "hypothesis": "Appears to add inbound auth to the two Python WebUI apps whose auth the HEALTH gate asserts: the dashboard (`/api/health` :8502 with no key → 401/403) and the log-analyzer (streamlit in-app gate). These back the tailscale services-leg VIP ports.",
  "flow": "`lme-dashboard/app.py` (WebUI auth gate, asserted by S05 HEALTH) → `lme-log-analyzer/app_simple.py` (streamlit in-app auth). Fronted by S06 services-leg VIP ports.",
  "reqs": "R1 ✅ (auth enforced), D1 ⚠️ (services-leg exposure OPEN)",
  "suggestions": [
    "`lme-dashboard/app.py` — verify `/api/health` returns 401/403 with no key (the HEALTH gate asserts webui auth); confirm loopback-default bind.",
    "`lme-log-analyzer/app_simple.py` — the streamlit gate is in-app (HTTP 200); confirm the HEALTH gate's non-assertion at the HTTP layer is intentional.",
  ],
  "files": [
    ("lme-dashboard/app.py", "Dashboard WebUI + auth gate (/api/health 401/403)"),
    ("lme-log-analyzer/app_simple.py", "Log-analyzer streamlit in-app auth"),
    ("lme-log-analyzer/README.md", "Log-analyzer readme"),
  ],
 },
 {
  "number": 13,
  "title": "Tests + CI (resolver / network-isolation / matrix)",
  "description": "B5 evidence — resolver unit tests + CI matrix leg + network-isolation/exposure assertions that back the HEALTH exposure gate.",
  "hypothesis": "Appears to be the B5 test evidence: resolver unit tests + a CI matrix leg for `lme_manifests.py`, plus network-isolation/exposure assertions that mirror the HEALTH exposure gate.",
  "flow": "`.github/workflows/resolver-tests.yml` (CI matrix leg) runs `test_lme_manifests.py` (exercises the S01 resolver); `conftest.py` + `test_network_isolation.py` assert exposure/isolation (mirror S05 HEALTH).",
  "reqs": "T3-B5 ✅ (resolver tests + CI leg), R2-B0 ✅ (verified by tests), R3 ✅ (budget tests)",
  "suggestions": [
    "`test_lme_manifests.py` — confirm coverage of the merge contract, budget (advisory vs oversized), and stale-unit prune so the resolver source-of-truth is guarded (B5).",
    "`test_network_isolation.py` — verify the exposure assertions match the deploy_gate HEALTH loopback/tailnet contract.",
  ],
  "files": [
    (".github/workflows/resolver-tests.yml", "CI matrix leg (B5)"),
    ("testing/tests/unit/test_lme_manifests.py", "Resolver unit tests (B5)"),
    ("testing/tests/api_tests/connectivity/conftest.py", "Connectivity test fixtures"),
    ("testing/tests/api_tests/connectivity/test_network_isolation.py", "Network-isolation/exposure assertions"),
    ("testing/ludus/bugs.md", "Ludus bug notes"),
  ],
 },
 {
  "number": 14,
  "title": "Docs + gitignore",
  "description": "Docs kept in sync with behaviour (the project's 'docs colocated' convention). PASSWORD_README.md documents the R1 secret model.",
  "hypothesis": "Appears to keep the colocated docs in sync with behaviour; `PASSWORD_README.md` documents the R1 secret model. Low behavioural risk.",
  "flow": "Documentation only — no execution path. `PASSWORD_README.md` documents the R1 secret model.",
  "reqs": "R1 ✅ (documented in PASSWORD_README)",
  "suggestions": [
    "`ansible/PASSWORD_README.md` — verify the documented secret model matches the per-install minting in S03/S07/S11 (R1).",
  ],
  "files": [
    ("ansible/README.md", "Ansible readme"),
    ("ansible/UPGRADE_README.md", "Upgrade readme"),
    ("ansible/BACKUP_README.md", "Backup readme"),
    ("ansible/PASSWORD_README.md", "Password/secret model docs (R1)"),
    ("LITELLM_USAGE.md", "LiteLLM usage docs"),
    ("testing/v2/development/CLUSTER_INSTALL.md", "Cluster install docs"),
    ("testing/v2/development/OFFLINE_INSTALL.md", "Offline install docs"),
    ("testing/v2/installers/cluster_installer/README.md", "Cluster installer readme"),
    (".gitignore", "Ignore rules update"),
  ],
 },
 {
  "number": 15,
  "title": "Static quadlet deletions — the Blocker-1 equivalence check",
  "description": "NOT a rubber-stamp. The run-5->run-6 delta: 10 NEW deletions complete the B0 static-tree removal (full 20-unit tree gone). The review question the WHOLE B0 cutover turns on (Blocker 1): does each deleted unit's semantics have a render/manifest counterpart, or does a fresh offline render DROP it? Two NEW deletions are the high-risk pairs — quadlet/lme-kibana.container (kibana-CA rewrite) and quadlet/lme-wazuh-manager.container (wazuh-CVE mount) — each verified across the triad: deleted unit <-> manifest (S03) <-> role task (S08).",
  "hypothesis": "Appears to complete the B0 static-tree removal: the full 20-unit hand-held quadlet tree is deleted. This is NOT a rubber-stamp — the review question the whole B0 cutover turns on is whether each deleted unit's semantics have a render/manifest counterpart (S03/S02) or a fresh offline render DROPs it.",
  "flow": "Equivalence check against S03 manifests + S02 templates + S08 role tasks. Two ⚑ pairs (`lme-kibana.container` CA rewrite, `lme-wazuh-manager.container` CVE mount) are the high-risk triad checks.",
  "reqs": "R2-B0 ✅ (static tree gone), Blocker-1 ⚠️ (verify each deletion has a render equivalent)",
  "suggestions": [
    "For each deleted `.container`/`.volume`/`.network`, verify a 1:1 `manifests/services/*.yml` (S03) + template (S02) equivalent exists — a missing equivalent = a dropped unit on fresh offline render (Blocker-1).",
    "`quadlet/lme-kibana.container` and `quadlet/lme-wazuh-manager.container` — the two high-risk pairs; confirm the CA rewrite and CVE mount survive in S03/S08.",
    "Confirm `git ls-files quadlet/` is empty on HEAD (full cutover, no orphan static units).",
  ],
  "files": [
    ("quadlet/lme.service", "Deleted root target unit"),
    ("quadlet/lme.network", "Deleted network unit"),
    ("quadlet/lme-backups.volume", "Deleted backups volume unit"),
    ("quadlet/lme-esdata01.volume", "Deleted ES data volume unit"),
    ("quadlet/lme-kibanadata.volume", "Deleted kibana data volume unit"),
    ("quadlet/lme-pgvectordata.volume", "Deleted pgvector data volume unit"),
    ("quadlet/lme-kibana.container", "Deleted kibana unit — ⚑ Blocker-1 CA pair"),
    ("quadlet/lme-wazuh-manager.container", "Deleted wazuh unit — ⚑ Blocker-1 CVE pair"),
    ("quadlet/lme-setup-certs.container", "Deleted cert-setup unit"),
    ("quadlet/lme-setup-accts.container", "Deleted acct-setup unit"),
    ("quadlet/lme-elastalert.container", "Deleted elastalert unit"),
    ("quadlet/lme-pgvector.container", "Deleted pgvector unit"),
    ("quadlet/lme-elasticsearch.container", "Deleted ES unit"),
    ("quadlet/lme-dashboard.container", "Deleted dashboard unit"),
    ("quadlet/lme-embeddings.container", "Deleted embeddings unit"),
    ("quadlet/lme-fleet-server.container", "Deleted fleet-server unit"),
    ("quadlet/lme-fleet-distribution.container", "Deleted fleet-distribution unit"),
    ("quadlet/lme-litellm.container", "Deleted litellm unit"),
    ("quadlet/lme-llama-cpp.container", "Deleted llama-cpp unit"),
    ("quadlet/lme-log-analyzer.container", "Deleted log-analyzer unit"),
  ],
 },
]

# ---- dependencies (caller/consumer section -> callee/source section) --------
TITLE = {s["number"]: s["title"] for s in SECTIONS}
DEPS = [
 (5, 8, "harness invokes install.sh then site.yml"),
 (8, 7, "site.yml invokes podman render role"),
 (8, 9, "site.yml runs base/nix OS prep first"),
 (8, 10, "site.yml drives certs and cluster plays"),
 (7, 1, "quadlet_setup invokes resolver and render"),
 (7, 6, "podman main includes tailscale legs"),
 (1, 2, "render_units fills the unit templates"),
 (1, 3, "resolver consumes the service manifests"),
 (1, 4, "resolver overlays the selected profile"),
 (3, 11, "manifests mount the static config"),
 (6, 4, "tailscale legs gated by profile"),
 (10, 4, "cluster/multinode consume profiles"),
 (5, 6, "HEALTH probes tailscale-fronted ports"),
 (5, 12, "HEALTH gate asserts WebUI auth"),
 (5, 4, "airgapped leg uses offline profile"),
 (5, 9, "airgapped leg relies on apt-cache gate"),
 (13, 1, "unit tests exercise the resolver"),
 (15, 3, "deleted units must map to manifests"),
 (15, 8, "Blocker-1 triad: role-task leg"),
]

# ---- build JSON -------------------------------------------------------------
def build_json():
    secs = []
    for s in SECTIONS:
        files = []
        for path, role in s["files"]:
            add, dele = NUM[path]
            files.append({"file_path": path, "role": role,
                          "lines_added": add, "lines_deleted": dele})
        secs.append({"section_number": s["number"], "title": s["title"],
                     "description": s["description"], "files": files})
    deps = [{"from_section": a, "from_title": TITLE[a],
             "to_section": b, "to_title": TITLE[b], "relationship": r}
            for (a, b, r) in DEPS]
    return {"schema_version": 1, "sections": secs, "dependencies": deps}

DATA = build_json()

# ---- validate 137, no dupes, matches canonical ------------------------------
all_paths = [f["file_path"] for s in DATA["sections"] for f in s["files"]]
assert len(all_paths) == 137, f"count={len(all_paths)}"
dupes = sorted({p for p in all_paths if all_paths.count(p) > 1})
assert not dupes, f"dupes={dupes}"
with open(CANON) as f:
    canon = sorted(l.strip() for l in f if l.strip())
assert sorted(all_paths) == canon, "canonical mismatch:\n" + \
    "only-json=" + str(sorted(set(all_paths) - set(canon))) + "\n" + \
    "only-canon=" + str(sorted(set(canon) - set(all_paths)))

json_str = json.dumps(DATA, indent=2)
with open(os.path.join(SCRATCH, "complete_map.json"), "w") as f:
    f.write(json_str)

# ---- render map.md ----------------------------------------------------------
def esc(x):
    return x

lines = []
w = lines.append
w("# Code Review Map")
w("")
w("**Session**: 2026-09-18-fix-debian-13-selinux-apt | **Generated**: 2026-09-18 | **Files**: 137 | **Sections**: 15")
w("")
w("> Mark `X` in the Done column as you complete review. Requirements: ✅ full | ⚠️ partial | ❌ none | ❓ cannot assess")
w("> This map is a navigation aid. It **flags** areas; it does not re-adjudicate the round verdict.")
w("")
w("---")
w("")
w("## Executive Summary")
w("")
w("This branch (`fix/debian-13-selinux-apt`, 137 files vs `main`, head `154a8c7`) appears to complete a B0 **manifest-render cutover**: the hand-held static `quadlet/` tree (20 units, deleted here in S15) is replaced by a single generic resolver — `lme_manifests.py` (S01) merges per-service manifests (S03), the selected profile overlay (S04), and global defaults, then `render_units.yml` fills generic Jinja2 unit templates (S02). Layered on top are the e2e-closure concerns the review is organized around: the three Tailscale serve legs (S06), an aggregate SF-8 memory budget (S01/S07), a per-install LiteLLM secret model (S03/S11), and a REAL rsync+ssh seal-gate pipeline (S05) that drives every profile through the tree's own `deploy_gate.sh → install.sh/ansible → wipe_lme.sh` with a HEALTH exposure gate.")
w("")
w("The map is deliberately organized around the **upcoming e2e-closure direction**, not just the retrospective diff. The open frontier is: (1) does a full `--profile tailscale` deploy pass the HEALTH gate on the services-leg VIP ports 443/8502/8501 (the wave-4b allowance widened only for ingress ports 8200/4000/5044); (2) the profile matrix — bare-metal(trixie) DONE, qemu-deb13 DONE, qemu-airgapped validating, cluster/multinode graph↔trixie TLS-SAN proven (M2a) with live-agent-enroll (M3) open; (3) four surfaced-not-fixed items from `154a8c7`; and (4) the standing rule that no deploy is ever ad-hoc.")
w("")
w("**Hypothesis**: This changeset replaces the hand-held quadlet tree with a resolver-driven render pipeline and closes the deploy surface (tailscale 3-leg, memory budget, per-install secrets, real seal-gate pipeline) so every profile can setup→deploy→teardown on real iron.")
w("")
w("**Key Approaches**:")
w("- **Render cutover (B0/R2)**: one resolver + generic templates + declarative manifests; the static tree is deleted, not maintained.")
w("- **Real seal-gate pipeline (SEAL/D4)**: `deploy_gate.sh` rsyncs the whole tree and invokes only the tree's own scripts on the target, with a HEALTH exposure gate — never ad-hoc.")
w("- **Profile matrix (D2)**: `--profile`/`--tailscale` overlays feed default / cluster / offline / tailscale / multinode legs.")
w("- **Budget + secrets (R3/R1)**: an SF-8 co-residency budget gates oversized co-residency; secrets are per-install podman secrets, nothing cleartext.")
w("")
w("**Status basis** — this matrix distinguishes *mechanism landed in-repo* (what the code does) from *proven on iron* (what the seal gate has demonstrated). The requirements mappers judged the in-repo mechanism; the anchor tracks the live gate, which is still open (REQUEST CHANGES). Rows below carry both.")
w("")
w("---")
w("")
w("## Questions & Clarifications")
w("")
w("### Questions for Author")
w("")
w("- **Services-leg HEALTH (anchor 1 / D1)**: should a full `--profile tailscale` run's VIP ports 443/8502/8501 be added to the HEALTH `LME_GATE_TAILNET_OK` set, or is a different bind expected? Today only ingress 8200/4000/5044 are allowed a tailnet bind, so a services-leg deploy may FALSE-FAIL the exposure gate.")
w("- **Finding D svc-grants**: are operator svc-grants in the tailnet ACL policy a documented prerequisite for the services leg? That is an out-of-repo dependency the gate cannot mint.")
w("- **Surfaced items (anchor 3 / D3)**: are these accepted-as-is or deferred — (a) `container_setup.yml:231` non-root shell-secret HOME mode; (b) services-leg 443/8502/8501 HEALTH; (c) upgrade LLM-off core cert bundles unpublished (pre-existing); (d) wipe `accept-routes` revert host-global on a shared node?")
w("- **M3 live-agent-enroll**: cross-machine TLS-SAN is proven (M2a); is live fleet agent-enroll in-scope for this branch or a follow-up?")
w("- **RedHat SELinux**: `selinux_redhat.yml` (+138) is source-only (no RH node in the tailnet). Is source review acceptable, or is a RedHat seal-gate leg required?")
w("")
w("### Assumptions Made")
w("")
w("- The 15-section grouping mirrors the render dependency chain (manifests+profiles+global → resolver → templates → orchestration → pipeline), not the git directory layout.")
w("- Requirement statuses reflect **in-repo mechanism**; SEAL/D1/D2/D3 are marked ⚠️ because the live gate is still open per the anchor, even where the mechanism is complete.")
w("- The real deploy targets are `graph` + `trixie` (bare Debian 13, ~16 GB); `silmaril` is off-limits for launch; no RedHat node exists in the tailnet (per discovered-standards).")
w("- All 137 files are in-scope branch changes; there are no unrelated/opportunistic files.")
w("")
w("---")
w("")
w("## Requirements Coverage")
w("")
w("Statuses reflect **in-repo mechanism** unless the Basis column says otherwise. The live seal gate is REQUEST CHANGES; a ✅ mechanism does not by itself mean the leg is proven on iron.")
w("")
w("| Requirement | Status | Basis | Implementing Files |")
w("|-------------|--------|-------|--------------------|")
w("| R1 — No hardcoded credentials (per-install secrets, nothing cleartext) | ✅ Full | in-repo | `manifests/services/lme-litellm.yml`, `lme-llm-keys.yml`, `container_setup.yml`, `config/litellm_config.yaml`, `setup_passwords.yml` |")
w("| R2-B0 — No hardcoding; every literal in manifests + resolver, rendered never hand-held | ✅ Full | in-repo | `lme_manifests.py`, `load_manifests.yml`, `render_units.yml`, `templates/units/*.j2`, `manifests/services/*.yml`, `quadlet/*` (deleted) |")
w("| R3 — Host budget: per-service caps + aggregate SF-8 co-residency budget | ✅ Full | in-repo | `lme_manifests.py` (memory_budget), `manifests/global.yml`, `container_setup.yml` (preflight), `cluster.yml`, `test_lme_manifests.py` |")
w("| R4 — Tailscale three legs (ingress + egress + services), each install-pathed | ✅ Full (mechanism) | services-leg HEALTH pending | `tailscale_install.yml`, `tailscale_ingress.yml`, `tailscale_egress.yml`, `tailscale_service.yml`, `profiles/tailscale.yml` |")
w("| SEAL — Every profile setup→deploy→teardown via the real pipeline | ⚠️ Partial | proving on iron | `deploy_gate.sh`, `install.sh`, `wipe_lme.sh`, `prepare_offline.sh` |")
w("| D1 — `--profile tailscale` passes HEALTH on services-leg VIP 443/8502/8501 + svc-grants | ⚠️ Partial | OPEN | `deploy_gate.sh`, `tailscale_service.yml`, `lme-dashboard/app.py` |")
w("| D2 — Profile matrix on real rsync+ssh (bare-metal / deb13 / airgapped / cluster) | ⚠️ Partial | trixie+deb13 DONE; airgapped+M3 OPEN | `deploy_gate.sh`, `install.sh`, `prepare_offline.sh`, `elasticsearch.yml`, `fleet/tasks/main.yml` |")
w("| D3 — Surfaced-not-fixed adjudication (4 items) | ⚠️ Partial | flagged, not resolved | `container_setup.yml`, `deploy_gate.sh`, `upgrade_lme.yml`, `wipe_lme.sh` |")
w("| D4 — No ad-hoc invocations; every deploy via the tree's own scripts | ✅ Full | in-repo | `deploy_gate.sh`, `install.sh`, `wipe_lme.sh` |")
w("| T3-B5 — Resolver unit tests + a CI matrix leg | ✅ Full | in-repo | `test_lme_manifests.py`, `.github/workflows/resolver-tests.yml` |")
w("")
w("**Gaps**: SEAL/D1/D2/D3 remain the open frontier — the mechanism is largely landed in-repo, but the services-leg HEALTH surface, the qemu-airgapped leg, M3 live-agent-enroll, and the four surfaced items are unproven or unadjudicated. `selinux_redhat.yml` is a declared source-only coverage gap (no RedHat node); SELinux is a Debian no-op on the real targets.")
w("")
w("---")
w("")
w("## Critical Review Focus")
w("")
w("> High-value areas where human judgment matters most. Phrased as *verify whether X holds*, not *X is broken* — the map flags, it does not adjudicate.")
w("")
w("| Focus Area | Files | Why It Matters | Req / Concern |")
w("|------------|-------|----------------|---------------|")
w("| B0 render equivalence | `manifests/services/lme-kibana.yml`, `lme-wazuh-manager.yml`, `quadlet/*` (deleted), `render_units.yml` | Verify each deleted static unit has a render/manifest counterpart — a fresh offline render must not DROP the kibana-CA rewrite or wazuh-CVE mount | Blocker-1 / R2-B0 |")
w("| Services-leg exposure | `testing/e2e/deploy_gate.sh`, `ansible/roles/podman/tasks/tailscale_service.yml` | Verify whether a `--profile tailscale` deploy passes HEALTH on VIP 443/8502/8501 (only 8200/4000/5044 are tailnet-allowed today) | anchor 1 / D1 |")
w("| SF-8 budget gate | `lme_manifests.py`, `container_setup.yml`, `manifests/global.yml` | Verify advisory `over_budget` (WARN) vs hard `oversized` (FAIL) polarity, and that the hard gate runs before any image pull | R3 |")
w("| Fail-closed teardown | `scripts/wipe_lme.sh` | Verify bash service-derivation matches the resolver set, and flag the host-global `accept-routes` revert on a shared node | B2 / D3-d |")
w("| Per-install secrets | `manifests/services/lme-litellm.yml`, `config/litellm_config.yaml`, `container_setup.yml` | Verify no committed master_key and loopback-default bind (Round-4 Blocker-2 closure) | R1 |")
w("| Cross-machine TLS | `ansible/roles/certs/templates/instances.yml.j2`, `certs/tasks/main.yml`, `fleet/tasks/main.yml` | Verify SAN list covers cross-node identities (M2a) and flag M3 live-agent-enroll as open | B4 / D2 |")
w("| Surfaced non-root secret | `ansible/roles/podman/tasks/container_setup.yml` (~L231) | Flag the non-root shell-secret HOME mode (real pipeline runs as root); do not adjudicate | D3-a |")
w("")
w("---")
w("")
w("## Manual Verification")
w("")
w("> The seal-gate is a REAL pipeline (anchor 4): NEVER run ad-hoc per-file commands. Every leg below is one `deploy_gate.sh` invocation that rsyncs the whole tree and runs only the tree's own `wipe_lme.sh` / `install.sh` on the target. `--flags` are passed through to `install.sh`. Stages: `all` (rsync→wipe→install→health→teardown), `deploy` (HOLD before teardown for inspection), `wipe`, `install`, `health`, `teardown`.")
w("")
w("### Critical Path — the profile matrix (SEAL / D2)")
w("")
w("- [ ] **bare-metal(some) = trixie** (SEAL) — `testing/e2e/deploy_gate.sh --host trixie --graphroot /data/lme-storage --flags \"--elastic-services\" --label trixie-some --stage all` → Expected: LEG END rc=0 (DONE).")
w("- [ ] **qemu(some) = deb13** (SEAL) — same harness against the deb13 qemu VM: `--host <deb13vm> --flags \"--elastic-services\" --label deb13-some --stage all` → Expected: rc=0 (DONE).")
w("- [ ] **qemu(airgapped)** (SEAL / D2) — build the bundle first with the tree's own `scripts/prepare_offline.sh`, then `deploy_gate.sh --host <airgap-vm> --flags \"--offline\" --label airgap --stage all` → Expected: rc=0; verify the deb13 apt-cache gate keeps the run off the network (validating now).")
w("- [ ] **cluster / multinode (graph↔trixie)** (D2) — `deploy_gate.sh --host graph --flags \"--cluster\" --extra-vars '{\"fleet_advertise_host\":\"<ip>\"}' --label cluster --stage deploy` then the node leg → Expected: TLS-SAN validates cross-node (M2a proven); flag M3 live-agent-enroll as OPEN.")
w("")
w("### Tailscale closure (anchor 1 / R4 / D1)")
w("")
w("- [ ] **Three legs compose** (R4) — `deploy_gate.sh --host <vm> --flags \"--tailscale\" --label ts-ingress --stage deploy` → Expected: rc=0; ingress ports 8200/4000/5044 pass HEALTH with a tailnet bind allowed.")
w("- [ ] **Services-leg VIP HEALTH** (D1 — the OPEN question) — `deploy_gate.sh --host <vm> --flags \"--profile tailscale\" --label ts-svc --stage deploy` → Expected/OPEN: verify whether VIP ports 443/8502/8501 pass HEALTH, or whether `LME_GATE_TAILNET_OK=\"443 8502 8501\"` must be set (only 8200/4000/5044 are tailnet-allowed by default). Confirm operator svc-grants exist in the tailnet policy (Finding D).")
w("")
w("### Edge Cases & Error Handling")
w("")
w("- [ ] **Fail-closed teardown** (B2, `scripts/wipe_lme.sh`) — `deploy_gate.sh --host <vm> --stage wipe` on a CLEAN host → Expected: rc=0 self-verify; on a dirty host, teardown removes exactly the resolver-derived services.")
w("- [ ] **SF-8 oversized gate** (R3, `container_setup.yml`) — deploy the full stack on a ~16 GB node with default budget → Expected: HARD FAIL on `oversized` before any image pull; `--profile cluster` (raised RAM) clears it.")
w("- [ ] **Reduced online profile** (R1/R3, `install.sh`) — `--flags \"--no-llm\"` → Expected: LLM stack skipped, HEALTH min-containers auto-lowered.")
w("- [ ] **Resolver unit tests** (B5) — the CI leg `.github/workflows/resolver-tests.yml` runs `pytest testing/tests/unit/test_lme_manifests.py` → Expected: green (merge contract + budget + stale-prune).")
w("")
w("### Non-Functional")
w("")
w("- [ ] **Security — exposure**: every host-published port that should be loopback-only (9200/5601/443/8220, llm 5432/8081/8502/8501/4000) is bound to 127.0.0.1/::1 and NOT LAN-open (deploy_gate HEALTH; `test_network_isolation.py`).")
w("- [ ] **Security — WebUI auth**: dashboard `/api/health` :8502 with no key → 401/403 (`lme-dashboard/app.py`).")
w("- [ ] **Correctness — no orphan static units**: `git ls-files quadlet/` is empty on HEAD (S15 full cutover).")
w("")
w("---")
w("")
w("## File Review")
w("")
w("Review sections in render-dependency order: manifests/profiles/global feed the resolver (S01), which fills the templates (S02); the podman role (S07) and the site/pipeline (S05/S08) drive it; the rest close the deploy surface.")
w("")

for s in SECTIONS:
    w(f"### Section {s['number']}: {s['title']}")
    w("")
    w(s["hypothesis"])
    w("")
    w("| Done | File | +/− | Role |")
    w("|:----:|------|:---:|------|")
    for path, role in s["files"]:
        add, dele = NUM[path]
        w(f"|  | `{path}` | +{add}/-{dele} | {role} |")
    w("")
    w(f"**Flow**: {s['flow']}")
    w("")
    w(f"**Requirements**: {s['reqs']}")
    w("")
    if s["suggestions"]:
        w("**Review Suggestions**:")
        for sug in s["suggestions"]:
            w(f"- {sug}")
        w("")
    w("---")
    w("")

w("### Unrelated Changes")
w("")
w("> None — all 137 files are in-scope branch changes on `fix/debian-13-selinux-apt`; each is assigned to exactly one section above.")
w("")
w("---")
w("")
w("## Section Dependencies")
w("")
w("> Direction follows call/data flow: the invoking/consuming section → the section it invokes or consumes.")
w("")
w("| From | To | Relationship |")
w("|------|-----|-------------|")
for (a, b, r) in DEPS:
    w(f"| {a}: {TITLE[a]} | {b}: {TITLE[b]} | {r} |")
w("")
w("---")
w("")
w("## File Index")
w("")
w("| File | Section |")
w("|------|---------|")
index = []
for s in SECTIONS:
    for path, _ in s["files"]:
        index.append((path, f"{s['number']}: {s['title']}"))
for path, sec in sorted(index, key=lambda t: t[0]):
    w(f"| `{path}` | {sec} |")
w("")
w("**Total**: 137 files")
w("")
w("---")
w("")
w("## Map Metadata")
w("")
w("**Run**: run-6 | **Date**: 2026-09-18 | **Flow Analysts**: 2 | **Requirements Mappers**: 2 | **Completeness**: 137/137 ✅")
w("")

md = "\n".join(lines)
with open(MAP_MD, "w") as f:
    f.write(md)

print("OK map.md bytes:", len(md))
print("OK json sections:", len(DATA["sections"]), "files:", len(all_paths),
      "deps:", len(DATA["dependencies"]))
print("sum added:", sum(NUM[p][0] for p in all_paths),
      "sum deleted:", sum(NUM[p][1] for p in all_paths))
