# .ocr/utilities — durable OCR / deploy tooling index

Centralized, durable home for reusable OCR/deploy helpers that were otherwise
stranded in a session scratchpad, plus **pointers** to the repo-canonical homes
of tools that already live in the tree. First compiled 2026-09-21 (OCR run-14
indexing/compaction, 8 scripts + 2 snapshots). **Rebuilt 2026-09-22** as a
*complete* pass: every ad-hoc script in both known scratchpad locations was
read (not filename-matched) and triaged, so "complete" is now a checkable
reconciliation identity — see below — instead of a claim.

Every file found is triaged into exactly one disposition — **Centralized**
(copied here, grouped by function into subdirectories such as `gate/`, `vip/`,
`probe/`), **Pointer** (left in its repo-canonical home, recorded with sha256),
or **Throwaway** (read and dispositioned, not kept). The per-category counts,
the three disposition totals, and the on-disk file count all tie back to the
**reconciliation identity** below.

> This index **describes** each tool. It deliberately does **not** inline any
> deployable value (hosts, IPs, SSH keys, API tokens, tailnet names, leg labels,
> ports). Read the script itself for its configuration.

Shorthand used throughout this file for origin paths:
- **SCRATCHPAD-A** = `/tmp/claude-1000/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/scratchpad/` (Claude Code session scratchpad — evaporates when the session ends)
- **SCRATCHPAD-B** = `/home/tristan/gitters/LME/scratchpad/` (repo working tree, **untracked** — `git status` shows `?? scratchpad/`)

---

## Reconciliation identity

```
N_found (62 *.sh/*.py + 4 shebang shims in SCRATCHPAD-A) + (7 in SCRATCHPAD-B) = 73
N_centralized (copied verbatim, sha256-verified; 10 from 2026-09-21 + 41 this pass + 3 rescued post-HC-4) = 54
N_pointered   (fork/copy of a repo-canonical file; NOT copied, recorded as a pointer) =  5
N_throwaway   (one-off / test-mock / superseded churn; NOT copied)                    = 14
                                                                              residue =  0   ✓ 54 + 5 + 14 = 73
```

Every one of the 73 files found in Step 1 is accounted for in exactly one of
the three tables below (Centralized / Pointer / Throwaway). Nothing was
skipped, and nothing appears in more than one bucket.

This identity covers only the 73 files enumerated by this pass's exhaustive
`find` of SCRATCHPAD-A and SCRATCHPAD-B. The pre-existing pointer rows for
`tailscale_service.yml`, `tailscale_ingress.yml`, and `.ocr/tools/populate_agent_row.py`
(carried over unchanged from the 2026-09-21 pass, see the end of the POINTERS
table) are **not** part of this N=73 — their scratchpad-side origin, if any,
predates this pass's sweep and was never a `.sh`/`.py`/shebang file this pass's
`find` would have matched.

---

## ⚠️ WARNING — several of these MUTATE live systems, write live secrets, or write the local OCR DB when RUN

The files below are catalogued here to be **read**. Do **not** execute any of
them outside an explicit operator gate. Running them changes real state (or,
for the credential/DB rows, writes sensitive or durable local data):

| tool | what it does when run |
|------|--------------------------|
| `vip/restore_acl.sh` | **Highest blast radius.** Force-`POST`s the whole tailnet ACL via the Tailscale API with **no `If-Match`** — it deliberately **overwrites whatever ACL is live** with its local snapshot. A stale/foreign snapshot beside it becomes a loaded gun. |
| `vip/define_services.py --apply` | `PUT`s Tailscale VIP-Service definitions (allocates VIPs) via the API. **Default (no `--apply`) is dry-run / read-only** — always run dry first. |
| `gate/run_gate.sh` | Drives the canonical deploy gate `--stage all` → rsync + ssh + install + wipe against a live target VM. Invocation template — target/key/flags/label hardcoded. |
| `gate/allfuncs.sh.snapshot` | **Under-flagged until HC-4.** A function *library* — inert as a file, but the run-note below tells you to copy it to `allfuncs.sh` and `source` it (to run `gate_dryrun.sh`/`probe_states.sh`); doing so silently **arms `do_rsync` (`rsync -a --delete` to a remote), `do_wipe`/`do_teardown` (remote `wipe_lme.sh`), and `do_install` (remote `./install.sh`) in your shell** with no further warning. Same blast radius as `run_gate.sh`/`run_install.sh`; source it only inside an offline dry-run harness. |
| `gate/rerun_elastic.sh` | Same live pipeline, `--stage deploy` (HOLD, no teardown) against host "graph" with `--tailscale --elastic-services --no-llm`, then SSHes in to assert the container roster. Invocation template — edit host/IP before reuse. |
| `gate/run-trixie-cluster-a2b2-run2.sh` | Same live pipeline, `--stage all` (full rsync→wipe→install→health→**teardown**) against host "trixie" with a `--cluster --no-llm` + heap-override extra-vars. Invocation template — edit host/IP before reuse. |
| `gate/run_install.sh` | Runs the tree's own `./install.sh --offline` (NON_INTERACTIVE/AUTO_CREATE_ENV) **on the host it is executed on**. Hardcoded to `/home/vmuser/LME` + `/opt/lme-storage`. |
| `probe/teardown_verify.sh` | Its **first action** is `sudo bash scripts/wipe_lme.sh` on the host it runs on — a full live teardown — before self-verifying the host is clean. |
| `probe/graph-seal/seal.sh` | `POST`s a document into a scratch Elasticsearch index, searches it back, then `DELETE`s the index. Live write+delete against `$ES_HOST` (self-cleans, but is a live mutation while it runs). |
| `probe/operator_access.sh` | Read-only against the remote host (no state mutation there), but **captures and tees to a local plaintext file**: `litellm_master_key`, `webui_api_key`, and elastic/kibana_system/wazuh/pgvector passwords. Treat its output file as a secret; never commit it. |
| `airgap/airgap_cut.sh`, `airgap/airgap-cut-and-prove.sh` | Delete the host default route (+ start a route-recut guard) on the machine they run on — cut network egress. |
| `lane-authoring/insert_3node_lane.py`, `lane-authoring/insert_airgap_lane.py` | `INSERT` a hardcoded row into the **local** `.ocr/data/ocr.db` (`command_executions` table). uid-guarded (refuses to double-insert), WAL-safe. Local dev-DB write, not a live/remote system. |
| `lane-authoring/populate_3node_lane.py`, `lane-authoring/populate_airgap_lane.py` | `UPDATE`s a row's `output` column in `.ocr/data/ocr.db` and **overwrites** that row's events journal file under `.ocr/data/events/`. Local dev-DB write. |
| POINTER `testing/e2e/deploy_gate.sh` | Full deploy/teardown pipeline against a live target. |
| POINTER `scripts/wipe_lme.sh` | Tears down an LME install on the host it runs on. |
| POINTER `install.sh` | Full Ansible-driven install on the host it runs on. |
| POINTER `ansible/.../tailscale_service.yml`, `tailscale_ingress.yml` | Advertise VIPs / serve ingress when applied via Ansible. |

Read-here / run-only-under-operator-gate.

---

## Index — Centralized (54)

`sha256` is recorded for every centralized file so drift from its origin is
detectable. All copies are verbatim `cp -p` (mode + timestamp preserved).

### airgap/ (2 — unchanged from 2026-09-21)

| file | purpose (1 line) | origin (SCRATCHPAD-A unless noted) | sha256 |
|---|---|---|---|
| `airgap/airgap_cut.sh` | Enforce an airgap for a **non-root** (`/home/vmuser`) run: cut the default route (keep the on-link mgmt route), start a 5s route-recut guard, record egress-failure proofs. | `airgap_cut.sh` | `e0ac6497aee468a908aacfe7c9b077da0b359b10b5756cd7803267b1e90b34ab` |
| `airgap/airgap-cut-and-prove.sh` | Same airgap enforcement for a **root** (`/root`) run: 3s recut guard **plus** a 30s route/mem/disk sampler and a pre-cut egress sanity curl. | `airgap-cut-and-prove.sh` | `5fac457395b23c894bda0a9d5bafd8de83f11d580b0939e613b0db3e145cdab6` |

### vip/ (5 unchanged + 3 new = 8)

| file | purpose (1 line) | origin | sha256 | new? |
|---|---|---|---|---|
| `vip/define_services.py` | Allocate LME `svc:lme-*` Tailscale VIP-Services via the REST API; names/ports sourced only from `manifests/services/lme-*.yml`; dry-run default, `--apply` to create. | `define_services.py` | `555d1abed960f250e8fbe2adb1b4c6189a919e1c8f2164a99786196267141bd0` | no |
| `vip/patch_acl.py` | Purely-additive tailnet-ACL hujson patcher: reads a live hujson, writes a patched one, with a byte-exact additivity proof + structural re-parse. | `patch_acl.py` | `4c73487d674f543a851b9ac883297fc95fa9d9e3e4185ba9ff8f903d38a04c7f` | no |
| `vip/restore_acl.sh` | Revert the tailnet ACL to a local pre-change snapshot via the Tailscale API (force `POST`, no `If-Match`). | `restore_acl.sh` | `e949ce893e875a2765f423cfee3c210eb0efc44368cec942377bdc864004d77a` | no |
| `vip/derive_check.sh` | Diagnostic probe: list the LME service names + count derived from loopback-bound manifests. | `derive_check.sh` | `5580b79c4810cf9abc95c251e19da4769906e43c64c535b165fd2c18c9e2ae6b` | no |
| `vip/derive.py.snapshot` | Union every published `{host: N}` port across `manifests/global.yml` + `services/*.yml` + `profiles/*.yml`. **EXTRACT** of `deploy_gate.sh` `derive_published_ports()`. | `derive.py` | `0c551212d2d994b48435324cbf6bf19eaf1561b7b80833145c31c3e67eb5379c` | no |
| `vip/branch.py` | Derive the list of `tailnet_service`-opt-in VIP names from `manifests/services/*.yml`, mirroring `tailscale_service.yml`'s publisher gate (loopback bind + non-udp + explicit key, **no** id-fallback). | `branch.py` | `3d119daf4611b53be38640f8f103866dee1b8ab870752f2e96fa9269c28c52d1` | **yes** |
| `vip/harness2.sh` | Newest of the `harness`/`harness2` churn pair: offline test harness for `scripts/wipe_lme.sh`'s `LME_SVC_NAMES`/`LME_MANIFEST_NAMES` derivation (PyYAML-primary, sed/awk fallback) — prints both sets, no live ssh/wipe. | `harness2.sh` | `1e92163398144e037007998b5d76eafe6156f7895ad5ec65ce1c40f2a22b8a68` | **yes** |
| `vip/profile.py` | Single-manifest-file scanner: given one YAML path (argv[1]), print every port whose entry has `bind==0.0.0.0`. | `profile.py` | `49b4f76dc838ef7bac440e927c875247a59b9d45a9cfdc2cfaa0ee4445fec444` | **yes** |

### gate/ (3 unchanged + 8 new = 11)

| file | purpose (1 line) | origin | sha256 | new? |
|---|---|---|---|---|
| `gate/gate_dryrun.sh` | Preview harness: source the gate derivation funcs and print ingress-allow ports + VIP endpoints per flag-combo, without deploying. | `gate_dryrun.sh` | `fadbd5cc16d3e748952c07e9a18166a7dab6a8589bb138cc4bff99126cd5214a` | no |
| `gate/gate_funcs.sh.snapshot` | The three gate derivation funcs `effective_pack_flags` / `derive_tailnet_ingress_ports` / `derive_vip_endpoints`. **EXTRACT** of canonical `deploy_gate.sh`. | `gate_funcs.sh` | `15c10c59a03ffb6caf3fb9f21172f10fc87e68b2f3b47e919663ddee726a8174` | no |
| `gate/run_gate.sh` | Reference **single-leg** driver for `testing/e2e/deploy_gate.sh`. Invocation template — hardcoded, edit before reuse. | `run_gate.sh` | `9917c7be0a573bc9f485edc63a4e6b06b4a7081c6fbbdca6d55bb23c8d056dd4` | no |
| `gate/allfuncs.sh.snapshot` | **EXTRACT** of canonical `deploy_gate.sh`'s **entire** internal function library as of this session — superset of `gate_funcs.sh.snapshot`: `do_rsync`/`do_wipe`/`do_install`/`derive_published_ports`/`explicit_profile`/`profile_lan_ports`/`effective_pack_flags`/`derive_tailnet_ingress_ports`/`derive_vip_endpoints`/`do_health`/`loopback_ok`/`tailnet_ok`/`do_vip_probe`/`do_teardown`. Verified: every function name present in canonical `testing/e2e/deploy_gate.sh`; the 3 funcs shared with `gate_funcs.sh.snapshot` are byte-identical. MAY DRIFT — repo is source of truth. | `allfuncs.sh` | `f91b6f7884385e91a5d1ff0e8547f2e0980a2c0ed5679b65fed177a8fb6a80f3` | **yes** |
| `gate/health_payload.sh.snapshot` | **EXTRACT**: the complete `HEALTH_SH` remote payload heredoc from canonical `do_health()` — failed-units + running-count + UDP-aware exposure (both tcp+udp `ss`, TCP-blind guard, `LAN_OK`+`PROFILE_OPEN` rules) + ES/Kibana/LLM checks. Verified byte-line-matching canonical `testing/e2e/deploy_gate.sh:701-727` (same comment text, same `ss -lunH` two-call parse, same `PROFILE_OPEN` clause). | `health_payload.sh` | `d65d0b28949ca42521b2fc2743b9708f89c0f29c4c4bd094d4f777a1f613a468` | **yes** |
| `gate/expo_new.sh.snapshot` | **EXTRACT**: the UDP-aware exposure-check fragment alone (needs `loopback_ok`/`tailnet_ok`/`$fail` predefined by the caller) — newest of the `expo_old`/`expo_new` churn pair. | `expo_new.sh` | `ce3614d1d53db318cbf55cba3f0187ef0ee500b294457ff75951c50a45c22913` | **yes** |
| `gate/funcs_new.sh.snapshot` | **EXTRACT**: the `loopback_ok()`/`tailnet_ok()` predicate pair alone. Newest of the `funcs_old`/`funcs_new` churn pair — **byte-identical** to `funcs_old.sh` (zero functional delta; pure churn). | `funcs_new.sh` | `eb67c31dee63080ba3fd06cfc6be5f8f1e92ea37c9dd6251851ba6bf869950de` | **yes** |
| `gate/run_new.sh.snapshot` | **EXTRACT**: funcs + exposure-check fragment combined into one standalone-runnable script. Newest of the `run_old`/`run_new` churn pair — a minimal subset of `health_payload.sh.snapshot` (exposure section only). | `run_new.sh` | `60371f0fa19c9372ae56fb8b4f6430a95a0155770617e46e6e1e9f365668e6b2` | **yes** |
| `gate/rerun_elastic.sh` | Live invocation template: `deploy_gate.sh --stage deploy` (HOLD) for `--tailscale --elastic-services --no-llm` on host "graph", then asserts the container roster by name over ssh. Host/IP/label hardcoded. | `rerun_elastic.sh` | `9ca1c751203eabd3b3bc826cbb9cc8d9125d26f669e527841d2de28a57989fb3` | **yes** |
| `gate/run_install.sh` | Invocation template: runs the tree's own `./install.sh --offline` with `NON_INTERACTIVE=true AUTO_CREATE_ENV=true` on the VM it executes on. Hardcoded `/home/vmuser/LME` + `/opt/lme-storage`. | `run_install.sh` | `5bab6ed5e766ef87b5e12ded8a8a1a31888732d399f3c0a1d367b76ff014edfc` | **yes** |
| `gate/run-trixie-cluster-a2b2-run2.sh` | Live invocation template (newest of the `-run2` churn pair): `deploy_gate.sh --stage all` for `--cluster --no-llm` on host "trixie" with a heap-2g extra-vars override (empirical BLOCKER-2 test: does the cluster path drop the heap override). Host/IP/label hardcoded. | `run-trixie-cluster-a2b2-run2.sh` | `f2b83bb44509a06e5d99e25ba5adaf657e0105e15391dfbd4f3326744a55d950` | **yes** |

> **Snapshot lineage (drift unit — 7 files):** `gate/gate_funcs.sh.snapshot`,
> `gate/allfuncs.sh.snapshot`, `gate/health_payload.sh.snapshot`,
> `gate/expo_new.sh.snapshot`, `gate/funcs_new.sh.snapshot`,
> `gate/run_new.sh.snapshot`, and `vip/derive.py.snapshot` are **all** extracts
> of the **same** canonical file, `testing/e2e/deploy_gate.sh`
> (sha256 `c3dec3c99ecb4e9ec7e59dd6cdbccf73ba473319406ac8eb3b971388c18d83cc`
> as of 2026-09-22). They nest (`funcs_new` ⊂ `expo_new` ⊂ `run_new` ⊂
> `health_payload` ⊂ `allfuncs`; `gate_funcs` and `derive.py` are separate
> extracts of different functions in the same file). **When the canonical's
> sha256 changes, treat all seven as suspect** and re-diff each against the
> new canonical before trusting it — none of the seven update automatically.

> **Running `gate/gate_dryrun.sh` / `probe/probe_states.sh`:** both `source` a
> file expected to be **literally named** `allfuncs.sh` (or `gate_funcs.sh`)
> next to them. `probe_states.sh`'s own copy still reads
> `source ".../08a6f002.../scratchpad/allfuncs.sh"` — that absolute `/tmp` path
> is gone once the session ends. To actually run either, copy (or symlink)
> `gate/allfuncs.sh.snapshot` to a file named `allfuncs.sh` in the directory
> you run from, or extract the funcs fresh from `testing/e2e/deploy_gate.sh`
> (the source of truth).

### fidelity/ (6 — 3 render/diff tools + 3 rescued unique-coverage checks, HC-4)

| file | purpose (1 line) | origin | sha256 |
|---|---|---|---|
| `fidelity/render_test.py` | Standalone CLI: renders one manifest service id (given a profile) through the real Ansible Jinja2 templates + `lme_manifests` filter plugin and prints the resulting unit text. `fidelity.py`'s rendering engine — also usable alone. | `render_test.py` | `8e9bb89adb047fb4a4647adcb644479bb3f6d98100296366b37dfbc27d8d92e4` |
| `fidelity/fidelity.py` | General render-vs-static fidelity checker for all 17 quadlet containers: imports `render_test.py` (same directory — keep them together), diffs each live-rendered unit's directive set against its static `quadlet/lme-<id>.container`. | `fidelity.py` | `6c35ad30c47b303c2b1dc9fc50cd9efabde2809be609b258b7ed8aba59a4f270` |
| `fidelity/render_harness.py` | "G1" foundational fidelity harness: renders exemplar manifests through the real templates+filters and semantic-diffs each against the current artifact (ES default **and** cluster context; litellm/filebeat/volume/network/target/path_service), plus derivation/gating assertions (memory caps, B4 cert mounts). Self-contained — no dependency on a pre-rendered snapshot directory. | `render_harness.py` | `b989112940ba586a1c301d64d719ae3e1231049fdc3b3f193633c86670fe5a3a` |
| `fidelity/ma1_verify.py` | **Rescued post-HC-4.** Covers **9 units neither `fidelity.py` nor `render_harness.py` touches** (kibana, fleet-server, fleet-distribution, wazuh-manager, elastalert, setup-certs, setup-accts, backups.volume, kibanadata.volume) AND does a **duplicate-mount `.count()` check the set-diff tools are structurally blind to** (catches the wazuh `lme_wazuh_logs` mounted-twice regression). Input dir is ephemeral; the checker is the durable asset. | `ma1_verify.py` (SCRATCHPAD-A) | `727222a7e00ad0e6f5afa3aefe22ca50ad3c04f4073ce5dd4cd6a87dd4384ea2` |
| `fidelity/ma3_diff.py` | **Rescued post-HC-4.** Same G1 lineage; covers **7 more uncovered units** (pgvector, pgvectordata.volume, llama-cpp, embeddings, dashboard, log-analyzer, llama-model.service). | `ma3_diff.py` (SCRATCHPAD-A) | `7ad66faa9fe95dbeda82075b8078c62785045fb6ab519edbc0565885082896f4` |
| `fidelity/ma_es_sdiff.py` | **Rescued post-HC-4** (was `ma-es/sdiff.py`). Same G1 lineage; covers **5 more uncovered units** (apm-server, heartbeat, metricbeat, logstash, filebeatdata.volume). | `ma-es/sdiff.py` (SCRATCHPAD-A) | `22c9ddd12df29e181c3ba231e238e7a4db139272b72e255fd4e04b3f70dd04f3` |

### lint/ (1 new)

| file | purpose (1 line) | origin | sha256 |
|---|---|---|---|
| `lint/dod_acceptance_grep.sh` | DoD acceptance grep for the "no-hardcoding" doctrine: greps `ansible/ scripts/ config/` for hardcode-corruption markers and specific uid/seed literals (allow-listing `manifests/`, the filter plugin, and generated-banner files); optional Part 2 scans a rendered-units dir for unsanctioned `lme_certs`/`ca.key` mounts. Rerunnable regression check, `Usage: dod_acceptance_grep.sh [RENDERED_DIR]`. | `dod_acceptance_grep.sh` | `321807c615b14a6432d65218499f69f4360ed3a6f1fb7d983922747eac408785` |

### map/ (3 new — OCR Code-Review-Map generation)

| file | purpose (1 line) | origin | sha256 |
|---|---|---|---|
| `map/gen_map.py` | "Map run-6" generator: renders a 15-section, 137-file Code Review Map (`map.md` + `complete_map.json`) from a hardcoded `SECTIONS` model joined against `numstat.txt`. **Worked template** — `SECTIONS`/paths hardcoded to one past changeset; copy+edit for a new one. | `gen_map.py` | `ec6fdb9b217321f4b86f7b6118b37b5be4c56c934a5dba1632a1f0dc57283746` |
| `map/gen_map_meta.py` | Generates the `ocr state complete-map --file` JSON payload: joins a hardcoded path→section/role `HOMING` dict against `git diff main...HEAD --numstat`, with a completeness self-check (every diffed path must be homed, and vice versa — aborts on mismatch). Same worked-template caveat. | `gen_map_meta.py` | `8bd900357f6be5522cbc6ab6d4a306aff7c35e4d48a4e793635f0ac53648726e` |
| `map/synth_map.py` | Synthesizes a severity-ranked findings digest from a map-swarm subagent workflow's `journal.jsonl` (verify + flow-analyst results) plus `numstat`. **Dead path today**: `J=` points at one specific past workflow-run id's journal — worked template only. | `synth_map.py` | `3b2978047574b69de5861544ee88ac51cebe3e7ae65b667431f25c3ba2a01a48` |

### transcript/ (2 new — Claude session .jsonl extraction)

| file | purpose (1 line) | origin | sha256 |
|---|---|---|---|
| `transcript/extract_human.py` | Extracts genuine human-authored turns (skips tool-result/meta noise) from a Claude session `.jsonl`, prints the last N (argv, default 45). `F=` is hardcoded to **this session's own** transcript path — edit before reuse on another session. | `extract_human.py` | `aa628a5b039774ce0cbf4942cab526fbb6b5ee31c06e363e087dcd84553533a7` |
| `transcript/full_turns.py` | Prints the full text of a hardcoded **set of specific line numbers** from a Claude session `.jsonl`. Both `F=` and the line-number set are hardcoded to one past investigation — edit both before reuse. | `full_turns.py` | `80380f743ac4e1ba198814cd864ffe925ce22d01a16a9a86cfb6b5829a350e5a` |

### probe/ (15 new — read-mostly diagnostics; see WARNING for the 3 that mutate)

| file | purpose (1 line) | origin | sha256 |
|---|---|---|---|
| `probe/graph-seal/kb.sh` | Kibana data-views probe via curl (reads `$ES_USERNAME`/`$ES_PASSWORD` from env); checks both `:5601` and `:443`. | `graph-seal/kb.sh` | `e842894f254bcfc8f7d17e77cd83baf9715326edf0a8a659a709b783dc8bb688` |
| `probe/graph-seal/probe.sh` | Elasticsearch cluster-health / data-streams / ILM / template-count probe via curl (env-driven `$ES_HOST`/`$ES_PORT`/creds). | `graph-seal/probe.sh` | `99a1ee29e08a82a6f10ba1e7f31ef4cb080f2b8f481bee5b1facfe9d3ce96d6e` |
| `probe/graph-seal/seal.sh` | ES round-trip probe: POST a doc into a scratch index, search it back, DELETE the index, confirm it's gone. **Live POST+DELETE — see WARNING.** | `graph-seal/seal.sh` | `d4a355a2fa30d658739f0c0b914e543ff46d21e1b31888c1f611bf853126104d` |
| `probe/health.sh` | Standalone post-deploy health check: `lme.service` / failed-units / podman-running-count / loopback-exposure (9200/5601/443/8220) / ES+Kibana HTTP checks. Self-contained. | `health.sh` | `d11d50d281285295ce7dc5a228ae5a1f1d85a41d7a66da372675a6ab0e859261` |
| `probe/hold_proof.sh` | Live HOLD-window evidence capture over ssh (read-only): CapMap keys, `tailscale serve status`, per-svc reachability from trixie, accept-routes state on host "graph". Hardcoded SS/TS/host/svc-list — edit before reuse. | `hold_proof.sh` | `eaff758aadf930644f76755fe5fd165332750624ce95fdbb887f1228479d129b` |
| `probe/jsontest2.sh` | Newest of the `jsontest`/`jsontest2` churn pair: argv-parameterized validator that the `install.sh` extra-vars JSON payload construction is well-formed; prints its keys. | `jsontest2.sh` | `7129a45b811bce0ddb7721db601bcf37013c83e177eab0cfafc8c7524bfdd364` |
| `probe/kb_fleet_probe.sh` | Kibana Fleet-agents status probe via curl; resolves the elastic password from an env file or a podman secret. | `kb_fleet_probe.sh` | `a8126cdaa7434402ee642cd006888c6b0c9d4ab2e8cf8265a6970dab200f8f21` |
| `probe/kb_status_summary.sh` | Kibana Fleet agents `statusSummary` probe via curl + inline python3 parse; asserts `total>0` and `online>0`. | `kb_status_summary.sh` | `ebde31e6454bdb3c15360c7f8a9e687b934138c612a3078e336486180b267b3e` |
| `probe/listen.py` | Binds `127.0.0.1:5044` and `:8085` for 20s — a port-availability pre-check double. (Filename resembles the `transcript/` tools; content is unrelated — classified by content, not name.) | `listen.py` | `2a5a4256b20875584c1bfd22440aae444f191a56ca6b85d42273f916a02e4bee` |
| `probe/operator_access.sh` | Live ssh capture of operator-facing URLs + **credentials** (`litellm_master_key`/`webui_api_key`/elastic/kibana_system/wazuh/pgvector), teed to a local file. Read-only against the remote — **see WARNING for the secret-dump caveat.** | `operator_access.sh` | `13f51fb01f957d4a9ac6460d4d41a44a16861009171537e0b77fa96ed02ea63f` |
| `probe/probe_payload.sh` | VIP-endpoint reachability checker: loops `$VIP_ENDPOINTS`, raw-tcp connect or HTTPS GET per scheme, reports unreachable svc names. | `probe_payload.sh` | `dfa0fb54c06724d2a9d8e9b58bab2d5fb16792536a7c3a796bbaff4e768cc852` |
| `probe/probe_states.sh` | Offline state-matrix test of `do_vip_probe()` with an `ssh` trip-wire that fails loudly if control flow ever reaches a real ssh call. **Sources `allfuncs.sh` by a now-dead `/tmp` path — see the `gate/` run-note above.** | `probe_states.sh` | `eade1490059ff73873133a95c8d1c20655c6fb9a2a7cce338d7c5111cf40ab39` |
| `probe/sol_probe.sh` | One-shot probe confirming `opencode run -m openai/gpt-5.6-sol` runs headless and its tailscale MCP loads with auth (lists MCP tool names, makes one read-only tailnet call). | `sol_probe.sh` | `d3b0dfc403af93cff9c4b58abdce7c673fab8801dcbba23d3060ff87bdfd82be` |
| `probe/tailnet_read.sh` | Read-only tailnet status probe: dumps this node's `Self.CapMap` `service-host`/`services/*` keys plus any peer advertising a service/vip field, from `tailscale status --json`. Takes a label arg; no hardcoded paths. | SCRATCHPAD-B `tailnet_read.sh` | `cf3b436e2b3eee58205c6d1fc70888bef1c20b780290bfecded136ded680e19b` |
| `probe/teardown_verify.sh` | Runs the canonical `scripts/wipe_lme.sh` **(live wipe — see WARNING)**, then self-verifies: podman containers/images/`lme_*` volumes/systemd units/`/opt/lme*` all empty. | `teardown_verify.sh` | `e78b2c428dcf01a87a152c06310cf80c0a102c26e792dfcce035f66c8009bd87` |

### lane-authoring/ (6 new — OCR board lane backfill; all from SCRATCHPAD-B)

Worked examples of the "genuine transcript, no fabricated events" OCR-board
backfill pattern (the same fix documented in the pre-existing
`populate_agent_row.py` POINTER row below). Every value (row id / agent id /
timestamps / narrative text) is hardcoded to one specific historical lane —
copy+edit before reuse for a different lane. See WARNING for which of these
write to the local OCR DB.

| file | purpose (1 line) | origin (SCRATCHPAD-B) | sha256 |
|---|---|---|---|
| `lane-authoring/insert_3node_lane.py` | WAL-safe, uid-idempotent `INSERT` of the 3-node-cluster validation row into `.ocr/data/ocr.db`'s `command_executions` table. | `insert_3node_lane.py` | `21f25a386e10b35662153142f4a0e4fd5b8669690ce3b0b806a4366b8fa08d6c` |
| `lane-authoring/insert_airgap_lane.py` | Same pattern as `insert_3node_lane.py`, for the airgapped-target validation row. | `insert_airgap_lane.py` | `f91fa28cb5ec9137df68008df7816770ea841e5049b83b3df66024e54f92933e` |
| `lane-authoring/populate_3node_lane.py` | Populates the 3-node lane's DB `output` column + writes its events journal from the **genuine** sub-agent transcript, reusing `.ocr/tools/populate_agent_row.py`. | `populate_3node_lane.py` | `93b95b14f4adc686bc09d7268d4f7717b2a3f6f4b6d04cb9e3cf21e36294b25a` |
| `lane-authoring/populate_airgap_lane.py` | Same pattern as `populate_3node_lane.py`, for the airgapped-target lane. | `populate_airgap_lane.py` | `eb79759cd19e646aa1bf8e01527f88f5017367d57e9a4206878b244614f24b7c` |
| `lane-authoring/emit_3node_files.py` | Files-only step for the 3-node lane: writes the raw-output text to a scratchpad file + the genuine transcript timeline to `.ocr/data/events/30.jsonl`. **No DB write.** | `emit_3node_files.py` | `56abfaa9e1fd914c764e646301bb9d7c181b09bdbfdd54958f3a408e6547d8a1` |
| `lane-authoring/emit_out30_text_only.py` | Writes only row-30's raw-output text to a plain temp file (no DB/events write). Hardcoded to a **different** prior session's scratchpad path/row than the other five files here. | `emit_out30_text_only.py` | `ea69cb845fc54a8b006f74d74ed784750b551f57d76cd96a0a3b7959b2d2e799` |

---

## POINTERS (repo-canonical — NOT copied; edit these in place)

Do **not** fork these into `.ocr/utilities/`; the repo path is the single
source of truth. Recorded here with sha256 (both source and canonical target)
so drift — or a stale fork being mistaken for current — is detectable.

### New this pass (5) — historical/stale forks of a canonical file, all superseded

| origin (SCRATCHPAD-A) | sha256 (origin) | POINTER → repo-canonical | sha256 (canonical @ 2026-09-22) | why superseded |
|---|---|---|---|---|
| `deploy_gate.sh` | `339bdc6ed75d4749807f0177ef887d07455deb9490ff0d9f2879b7fb46a503e9` | `testing/e2e/deploy_gate.sh` | `c3dec3c99ecb4e9ec7e59dd6cdbccf73ba473319406ac8eb3b971388c18d83cc` | Self-labeled "session tooling, NOT part of the LME tree"; 145 lines; predates and is **not** a snapshot of the canonical. Do not use. |
| `old_gate.sh` | `6ef5180a5d68858d457c731ebbd4eb81a8694acf4d50ca0e9fce4967fb76ca07` | `testing/e2e/deploy_gate.sh` | `c3dec3c99ecb4e9ec7e59dd6cdbccf73ba473319406ac8eb3b971388c18d83cc` | A fuller (390-line) but still superseded early iteration: same `do_rsync`/`do_wipe`/`do_install`/`do_health`/`do_teardown` stage design, but its embedded health payload is the **pre-UDP** exposure check (matches the throwaway `payload.sh`/`expo_old.sh`) and it lacks `PROFILE_OPEN`/`LME_GATE_TAILNET_OK`. Fully superseded. |
| `install.orig.sh` | `d3973fdad653e82801551bbf46a0f25e269fec1321ac7bd4e81df50ca788a1f3` | `install.sh` | `02477e50af8e2089960d055140056bb95034bfed7557a1b609d6b36c34b445b7` | Stale pre-edit snapshot: 1481 lines vs canonical's 1610; sha256 differs. A copy here would be a drift trap. |
| `wipe_harness.sh` | `2abac8d1bfae65d36325e663cdbb65d8f6566d4c739fcd014571b5c1ec219af1` | `scripts/wipe_lme.sh` | `35dc73802cd2f5a3cb98bc37c287e100a43224b7deef2623767c9bbd8b3b88e4` | Superseded historical draft: 271 lines vs canonical's 627. |
| `wipe_head.sh` | `7ff04ae463ab4bdb5d05cd888e9b7ecf47a5c578f83f8472e95e2a7484135381` | `scripts/wipe_lme.sh` | `35dc73802cd2f5a3cb98bc37c287e100a43224b7deef2623767c9bbd8b3b88e4` | Superseded historical draft, later than `wipe_harness.sh` (417 lines) but still predates the current canonical (627 lines). |

### Carried over from 2026-09-21 (outside this pass's N=73; unchanged)

| tool | POINTER → repo-canonical path | purpose (1 line) | sha256 (repo file @ 2026-09-21) | executes-live? |
|---|---|---|---|---|
| deploy gate | `testing/e2e/deploy_gate.sh` | Versioned E2E deploy-gate pipeline (setup→deploy→health→teardown per profile/target, real rsync+ssh pipeline). | `c3dec3c99ecb4e9ec7e59dd6cdbccf73ba473319406ac8eb3b971388c18d83cc` | **yes** |
| wipe | `scripts/wipe_lme.sh` | Tear down an LME install (svc-name derivation mirrors the gate/ingress derivation). | `35dc73802cd2f5a3cb98bc37c287e100a43224b7deef2623767c9bbd8b3b88e4` | **yes** |
| tailscale service (VIP) | `ansible/roles/podman/tasks/tailscale_service.yml` | Advertise per-service VIPs; select the front port by manifest marker (K1). | `e1942e699a11d2e6b41a394ad92a369a95bc1ce7fb70eb71871132b11dd91061` | yes (via Ansible) |
| tailscale ingress | `ansible/roles/podman/tasks/tailscale_ingress.yml` | Serve host ingress; derive fronted ports from manifest markers (R4). | `51d60c734526391ed1db53925699c7d217d29834c64e275f65c3011c64535a40` | yes (via Ansible) |
| board row backfill | `.ocr/tools/populate_agent_row.py` | WAL-safe backfill of an OCR board agent row (UPDATE output + write events jsonl) — the "No output recorded" fix; the `lane-authoring/populate_*` scripts above reuse this module directly. | `f0c4e0757de6d657a8aed6c31767797834ea95e96139146f65dd7b59c757b4cf` | no (writes the local OCR board DB/jsonl, not a deploy target) |

---

## THROWAWAY (14 — not copied; was 17 before HC-4 rescued the 3 fidelity checks to `fidelity/`)

Every file below was **read**, not filename-matched, before this disposition.

**Churn — superseded by a centralized newest-of-pair (7):**

| origin | sha256 | superseded by | why |
|---|---|---|---|
| `expo_old.sh` | — | `gate/expo_new.sh.snapshot` | Pre-UDP exposure check; `expo_new` adds udp probing + a TCP-blind guard + `PROFILE_OPEN`. |
| `funcs_old.sh` | `eb67c31dee63080ba3fd06cfc6be5f8f1e92ea37c9dd6251851ba6bf869950de` | `gate/funcs_new.sh.snapshot` | **Byte-identical** to funcs_new.sh — zero functional delta, pure churn. |
| `harness.sh` | — | `vip/harness2.sh` | harness2 suppresses a stray stderr traceback from a malformed-manifest parse and cleans up two output labels. |
| `jsontest.sh` | — | `probe/jsontest2.sh` | jsontest2 is argv-parameterized instead of all-hardcoded. |
| `payload.sh` | — | `gate/health_payload.sh.snapshot` | Pre-UDP draft of the same payload heredoc; superseded by the UDP-aware version. |
| `run_old.sh` | — | `gate/run_new.sh.snapshot` | Pre-UDP exposure check (same delta as expo_old/new). |
| `run-trixie-cluster-a2b2.sh` | — | `gate/run-trixie-cluster-a2b2-run2.sh` | run2 adds a single-node `cluster.yml`-presence test for BLOCKER-2. |

**~~One-off fidelity checks superseded (3)~~ → RECLASSIFIED to centralized `fidelity/` (HC-4 refuted the "superseded" call):** the hostile auditor proved these three are **not** superseded — together they cover 9+7+5 = 21 rendered units the general tools never touch, plus a duplicate-mount `.count()` check the set-diff tools are structurally incapable of. They were **rescued from SCRATCHPAD-A into `.ocr/utilities/fidelity/`** (`ma1_verify.py`, `ma3_diff.py`, `ma_es_sdiff.py`) before session-end evaporation — see the `fidelity/` catalog above. (This is why N_centralized moved 51→54 and N_throwaway 17→14; N_found stays 73.)

**Session/round-specific orchestration drivers — not reusable without a full rewrite (2):**

| origin | why |
|---|---|
| `address_sol.sh` | "Sol lane" driver hardcoded to OCR review round-13's exact directory + task prompts citing that round's file:line findings. |
| `map_swarm.sh` | 8-subagent OCR-map orchestration driver, same round-13 hardcoding (K1/A1 finding citations embedded in the launch prompts). |

**Test scaffold, filename-coupled and logic-superseded (1):**

| origin | why |
|---|---|
| `drive.sh` | sed/awk-extracts `loopback_ok`/`tailnet_ok` out of a co-located file literally named `payload.sh` (itself now superseded) and adds a `check_port()` driver. Fragile filename-coupled extraction; the same logic is already inline in `probe/health.sh` and `gate/health_payload.sh.snapshot`. |

**Test mocks (4 — pre-identified; confirmed by inspection):**

| origin | what it mocks |
|---|---|
| `bin/ss` | Fakes `ss` tcp/udp listener-table output from `$SS_TCP`/`$SS_UDP` env files, for offline exposure-check unit tests. |
| `fakebin/python3` | A `python3` stub that fails any `import yaml` probe, emulating a host without PyYAML (exercises the sed/awk fallback paths in `harness2.sh`/`wipe_lme.sh`). |
| `r-tailscale/bin/tailscale` | Fakes the `tailscale` CLI (`status`/`serve`/`debug prefs`) for an "r-tailscale" test device (`DNSName=lme-rtailscale...`). |
| `ts-proof/bin/tailscale` | Same, for a "ts-proof" test device (`DNSName=lme-proof...`). |

---

## Selection criteria

- **Centralize** a genuine reusable ad-hoc tool that was stranded in a session
  scratchpad with **no repo-canonical home**, verified by reading the file
  (never by filename alone) plus a `git ls-files` / `git grep` check for an
  existing canonical home.
- Where a script's real value is that it **extracts logic already embedded in
  a canonical file** (a heredoc payload, a function library), it is centralized
  as a **`.snapshot`** — same treatment the 2026-09-21 pass established for
  `gate_funcs.sh.snapshot` / `vip/derive.py.snapshot` — labeled "MAY DRIFT;
  repo is source of truth," with the extract verified against the canonical
  (function names present, shared bodies byte-diffed) before being labeled
  that way rather than asserted.
- **Pointer, do not copy**, anything that already has a repo-canonical home —
  including a **historical/stale fork** of one (`old_gate.sh`, the scratchpad
  `deploy_gate.sh`, `install.orig.sh`, `wipe_harness.sh`, `wipe_head.sh`).
  Forking a live or superseded-but-similar script here would create a drift
  trap or, worse, a false sense that the stale copy is current.
- **Old/new iteration pairs** (`funcs_old`/`funcs_new`, `expo_old`/`expo_new`,
  `run_old`/`run_new`, `harness`/`harness2`, `jsontest`/`jsontest2`,
  `run-trixie-cluster-a2b2` / `-run2`) are resolved by **centralizing the
  newest only**; the superseded half is recorded under THROWAWAY with the
  concrete diff that justified "newest" (not assumed from the filename).
- **Session-specific worked templates** (`gen_map.py`, `gen_map_meta.py`,
  `synth_map.py` in `map/`; `extract_human.py`, `full_turns.py` in
  `transcript/`; every file in `lane-authoring/`; several `gate/`/`probe/`
  invocation drivers) are centralized **despite** hardcoded paths/ids/row
  values, because the reusable value is the *pattern*, not the literal
  constants — each such row says so explicitly and says what to edit.
- **Throwaways excluded**: churn losers, one-off checks against ephemeral
  pre-rendered directories, session/round-specific orchestration drivers with
  deeply embedded one-round prompts, a filename-coupled test scaffold, and
  test mocks are **not** tooling.
- Every copied file is a **verbatim `cp -p`** (mode preserved) and sha256
  matched against its origin immediately after copy (see the per-category
  tables above — every row was verified, not assumed).

## How originals relate

- **Copies under `.ocr/utilities/` are durable** — committed to the repo (once
  staged/committed by an operator), they survive independent of either
  scratchpad.
- **SCRATCHPAD-A** (`/tmp/claude-1000/.../scratchpad/`) **evaporates when the
  session ends.** Every file centralized from there would otherwise be lost
  entirely — this is the primary reason this index exists.
- **SCRATCHPAD-B** (`/home/tristan/gitters/LME/scratchpad/`) is the repo
  working tree but **untracked** (`git status` → `?? scratchpad/`) — it
  survives a session but not a `git clean`, a fresh clone, or another
  operator's checkout. The 7 files found there (all centralized) had the same
  durability gap, just a longer fuse.
- Data / state artifacts (rendered-unit snapshots like `ma1_rendered/`,
  `ma3_rendered/`, ES/tailnet json/hujson dumps, gate logs, `.md` evidence
  files such as `operator-access.txt`/`hold-proof-evidence.txt`) are
  **inputs/outputs** the tools above read or write at runtime, not tools
  themselves — intentionally **not** copied. In particular, no captured
  credential/evidence output is stored beside `probe/operator_access.sh` or
  `probe/hold_proof.sh`.

---

## ADDENDUM — operator reorg of SCRATCHPAD-B (mid-pass, ~06:0XZ; NOT authored by this lane)

After this catalog was written (00:48Z), the **operator** relocated SCRATCHPAD-B
(`/home/tristan/gitters/LME/scratchpad/`) wholesale into **`.ocr/utilities/scratchpad/`**
(26 files) and `git add`-ed all of `.ocr/utilities/` — self-described as "just organizing
(staging/moving)." This is a **raw move**, not a curation; this lane neither authored nor
de-duplicated it, and leaves it untouched (never-delete). It is recorded here only so the
on-disk count reconciles — the curated tables above (the `73 = 54 + 5 + 14` identity)
are **unchanged by this move**.

**On-disk effect:** `find .ocr/utilities -type f` = **81** = 54 curated (9 categories, tables above)
+ 26 raw `scratchpad/` + 1 (this README).

**The 26 raw files partition exactly (verified):**
- **7 duplicate curated scripts** — the 6 `lane-authoring/` emit/insert/populate `*.py`
  + `probe/tailnet_read.sh` (already catalogued above from SCRATCHPAD-B).
- **18 duplicate `../../index/salvage/`** — the research/evidence artifacts
  (`flow-analyst-*`, `req-mapper-*`, `round3/8/9-*`, `pr-body.md`, validations, canonical
  `.txt`, `tailnet-readings.log`); **all sha256-identical (18/18)** to the salvage copies.
- **1 net-new** — `ocr.db.bak-20260917T004634Z`, a **1 MB binary DB backup**, deliberately
  *not* copied by this lane; **now staged for commit** (would enter git history).

**Operator decisions flagged (not resolved here — this lane runs no git-state command):**
1. **De-dup** — keep EITHER the curated 9-category split OR the raw `scratchpad/`
   dump, not both. If de-duping, prefer `git rm --cached` (un-stage, keep the file
   on disk) over `rm -rf` — the raw dump may be the only copy of the DB backup
   (see item 2).
2. **Binary in history** — `ocr.db.bak-20260917T004634Z` (1 MB) is **net-new** (not
   a dup of any curated or salvage file) and **may be the only copy**; decide whether
   it should enter git history, and do not blind-`rm` it while de-duping.
3. **PII before commit** — the staged file `vip/patch_acl.py` line 23 hardcodes a real
   operator email in an ACL `src` grant; scrub or confirm it before committing
   `.ocr/utilities/` to any shared/public remote. (Separate from the secret scan, which is CLEAN.)
4. **Commit** — all of `.ocr/utilities/` is staged but not yet committed (not on origin).
