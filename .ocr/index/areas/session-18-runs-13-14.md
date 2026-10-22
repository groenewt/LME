# Session `2026-09-18-fix-debian-13-selinux-apt` — Index Area: run-13 + run-14 + run-15 (CURRENT)

> **Superseded-in-part (as-of 06:23Z):** this file's run-14 enumeration is the **05:26Z snapshot summing to 85**. The MAP lane kept writing run-14 `lanes/` to **≥05:59Z** (HC-5), so run-14 is now **90** files (`30 + 90 = 120`); the `-18` session has since **closed** (05:51:39Z). The per-file breakdown below stands for its snapshot; authoritative live totals: `../MASTER-INDEX.md` §1 + §8.
>
> **Extended to runs 13-15 (this pass, 2026-09-22 22:09Z):** a **run-15** landed under this session
> *after* the MASTER-INDEX 06:23Z stamp — completed ~16:18Z (map twin ran it under the still-`closed`
> `-18` row; DB `updated_at` → `2026-09-22 16:21:39Z`; row remains `closed`,
> `current_round=10`). This file now covers **run-13 + run-14 + run-15**; run-15 is folded in
> **§3** below with its **own** reconciliation identity. §0-§2 and the trailing **115** identity
> block are the **frozen 05:26Z run-13+run-14 snapshot** — left intact, not rewritten. Since the
> stamp, run-14 grew **90→98** (address-lane, §3). **Session total now `390`**
> (`241 + 30 + 98 + 21`, residue 0; delta vs the index's 361 = **+29 = run-14 +8 + run-15 +21**).
> Authoritative live totals: `../MASTER-INDEX.md`.

**Author:** IDX-S18-CUR (INDEXING/COMPACTION swarm, current-portion worker). READ-ONLY throughout: no writes
outside this file, no `ocr state` transition, no git state change, nothing deleted/moved.
**As-of (reconciliation instant):** `2026-09-22T05:26:09Z` (files older than this reflect their last real
mtime; three run-14 subtrees were observed to still be growing at and after this instant — see §0 and §2).
**Scope:** `/home/tristan/gitters/LME/.ocr/sessions/2026-09-18-fix-debian-13-selinux-apt/map/runs/{run-13,run-14}/`
only. Sibling areas (`rounds/`, `run-1`..`run-12`, session-root docs, `acl-snapshots/`) are out of scope — see
`run-14/_index/INDEX.md` Appendix A/B for those.

---

## 0. Spec-vs-disk delta (read this first — the highest-signal finding in this pass)

My dispatch instructions described run-13/run-14 in terms that don't fully match what's on disk. Recorded
precisely rather than silently reconciled:

| Dispatch said | Disk has | Resolution |
|---|---|---|
| `run-14/map/` (a directory), LIVE | **No such directory.** run-14 has a top-level `map.md` **file** and (as of 05:24Z, mid-inventory) a `map-meta.json` **file** — no `map/` dir at any level. | Interpreted "`run-14/map/`" as `run-14/map.md` + `run-14/map-meta.json`. Both treated as LIVE (§2.1). |
| `run-14/_index/` = 3 files (INDEX.md, blockers-status.md, state-validation.md) | **5 files.** Two more exist: `fragment-rounds.md`, `fragment-mapruns.md` — the SA6/SA7 verbatim inventories that `INDEX.md` incorporates as its own Appendix A/B. | All 5 listed in §2.5. |
| `run-14/lanes/` characterized only via `lanes/deploy/prune-resetup-invocation.md` | `lanes/` has **two** subdirs: `deploy/` (2 files) and `design/` (8 files, not mentioned at all in dispatch). | Both characterized in §2.4. |
| Only `run-14/map/` + `run-14/_context/` flagged LIVE | **Disk evidence says `lanes/design/` and `analysts/` are also live.** `lanes/design/` grew from 6 files to 8 between two of my own listings taken minutes apart (`tls-routing-matrix.md` landed 00:24:15 CDT, `secrets-scoping-closure.md` 00:25:11 CDT, and `requirement-matrix.md` was rewritten at 00:25:56 CDT). `analysts/` (14 files) is the MAP-lane's raw per-analyst output feeding `map.md`; `run-14/_index/state-validation.md` (a sibling deliverable, rewritten ~05:20Z) independently confirms via `ocr session list`: "~14 `flow-*`/`req-*` instances running, `flow-probe` crashed" — matching the 14-file count and explaining the one absent `flow-probe.*` output. | **Correcting the dispatch's LIVE set**, not silently extending it: LIVE = `map.md`, `map-meta.json`, `_context/**` (6 files), `analysts/**` (14 files), `lanes/design/**` (8 files). See §2. |
| `run-14/_archive/`: "README.md; currently zero moves" | Confirmed exactly. 1 file, empty move-log table. | No delta. §2.6. |
| — (not in dispatch) | `run-13` has no status word in the dispatch's five-value vocabulary (live / gated-plan / this-lane-deliverable / migrated / archive). | Using **`historical/settled`** for run-13 as a sixth value; flagged as a vocabulary gap, not silently forced into one of the five. |

---

## 1. `run-13/` — historical/settled

**Status:** historical/settled. **Disposition:** leave in place; the `map_runs` DB row is the MAP lane's to
reconcile — flagged below, not touched.

On disk: `map.md` (present, 10664 B, mtime 2026-09-21 19:21 local) + `analysts/` (18 files) + `_context/` (4
files) + `lanes/{address,registry}/` (5 + 2 files) = **30 files total**. **No `map-meta.json`** anywhere under
run-13 (grep-confirmed: 0 matches for `run-13/map-meta.json` in the reconciliation snapshot).

**`map.md` content (read in full):** "Code Review Map — run-13 (fix/debian-13-selinux-apt, 76-file delta)",
8 numbered sections, substantive and complete — a 12-agent dual-swarm review (4 Claude + 8 sol/gpt-5.6-sol)
anchored on the forward multi-machine architecture. Live e2e evidence section (deploy `rc=0`, 3/4 VIPs compose
cross-machine). Two headline findings: **K1** (kibana VIP dead — registry pins `[443,5601]`, graph serves 443
only → route withheld) and **A1** (armed liveness assert proves allocation, not reachability — false-green).
Findings ledger: 5 blockers (B1 wipe co-tenant nuke, B2 cluster not one pipeline, B3 ingress hardcodes
ports, B4 Phase-1 drops discovery identity, B5 secret names duplicated) + 10 should-fix + suggestions +
positives-to-preserve. Closes with an address plan naming `lanes/registry/` (graph-as-image-registry design,
2 Claude bg) and `lanes/address/` (sol address-diff drafting, bg) as **open lanes in flight** — i.e. run-13's
own map.md documents that `lanes/` was still being written when run-13 closed.

**Subdirectories (one-line each):**
- `analysts/` (18 = 10 `.md` reports + 8 `.out` raw transcripts): per-specialist outputs — `claude-{forward-arch,kibana-forensics,pipeline-security,topology-verify}.md`, `flow-{ansible,quadlet-manifests,testing-scripts}.{md,out}`, `spec-{devops,forward-arch,security,tailscale-live}.{md,out}`, `topology.out`. Raw audit-trail input to `map.md`.
- `_context/` (4): `canonical-files.txt` (file-scope snapshot), `changeset.md` (76-file diff summary, 36 commits), `forward-anchor.md` (operator's forward-direction brief), `live-findings.md` (the graph `--profile tailscale` HOLD e2e evidence cited above).
- `lanes/address/` (5): `CONTRACT.md` (wave-13 K1+A1+Ingress-R4 composable contract, 17260 B), `baseline-evidence.md` (pre-fix live proof), `wave13-results.md` (subagent results log, 21740 B), `sol-address-{ingress,vip-probe}.out` (raw transcripts).
- `lanes/registry/` (2): `design-service-exposure.md` (graph as manifest-driven OCI image hub) and `design-pullpush-airgap-cluster.md` (distribution: pull/push/airgap-seed/cluster wiring) — explicitly a design-only, read-only pair (no repo edits, no deploy).

**DB reconciliation — three-way mismatch (sharper than "0/0 vs on-disk differs"):**

| Source | Value |
|---|---|
| On-disk `map.md` | 8 numbered sections, 10664 B, substantive, complete narrative |
| `map_sections` table (`map_run_id=30`) | **6 rows** (ids 263–268: Live e2e evidence, K1, A1, Forward-architecture coverage, Findings ledger, Address plan) — every row has `file_count=0` |
| `map_runs` table (`id=30`) | `file_count=0`, `section_count=0`, `source='parser'`, `parsed_at='2026-09-22 00:21:33'`, `map_md_path` populated (points at the real file), **no `map-meta.json` on disk** |

Reading: the parser back-fill **partially** populated `map_sections` (6 rows, titles correctly extracted from
`map.md`'s headings) but never populated `map_files` under them (`file_count=0` on every row) and never updated
the denormalized `map_runs.file_count`/`section_count` counters (left at 0/0 despite 6 real section rows
existing underneath). The likely cause: no `map-meta.json` was ever written for run-13, so the ingestion path
that normally derives file-level detail had nothing structured to parse and fell back to a bare
heading-extraction pass. **Net: run-13's DB footprint under-reports even its own already-degenerate state** —
the section skeleton exists in the DB; the file-level and summary-count layers do not. Flagged for the MAP
lane; not corrected here (read-only).

---

## 2. `run-14/` — the big one; ACTIVE session, mid-synthesis

Corroborating evidence this is genuinely live, captured **during** this inventory (not asserted, observed):
`run-14/_index/state-validation.md` (a sibling this-lane deliverable, rewritten ~05:20Z) records the session
was `session_resumed` at `2026-09-22 04:44:55` and reached phase `synthesis (5)` by `05:16:32`, driven by a
live MAP-lane swarm (~14 `flow-*`/`req-*` agent rows). My own two listings of `run-14/lanes/design/` (taken a
few minutes apart) show it grow from 6 to 8 files. `run-14/map-meta.json` (3912 B) and
`run-14/_context/complete-map-run14.json` did not exist at my first pass (~05:23Z) and were present with mtimes
05:24Z / 05:25Z at my reconciliation snapshot (05:26:09Z) — i.e. they were written **inside my own inventory
window**.

### 2.1 `run-14/map.md` + `run-14/map-meta.json` — **LIVE, MAP-lane-owned, as-of 2026-09-22T05:26:09Z**

**Status:** live. **Disposition:** read-only; re-snapshot before citing; do not treat this section as final.

- `map.md`: 15541 B, mtime `2026-09-22 00:22:01` local (`05:22:01Z`) — landed ~1 minute before my first
  orientation pass.
- `map-meta.json`: 3912 B, mtime `2026-09-22 00:24` local (`~05:24Z`) — **did not exist at my first `find`
  pass**; appeared during this inventory.
- DB corroboration (`map_runs id=31`): `run_number=14`, `file_count=10`, `section_count=3`,
  `source='orchestrator'`, `parsed_at='2026-09-22 05:24:32'` — **after** my initial as-of stamp
  (`05:23:31Z`), consistent with `map-meta.json` landing right around then and being parsed immediately.
- `map_sections` for `map_run_id=31` (3 rows, files sum to 10, matching `map_runs.file_count=10` — internally
  consistent, unlike run-13): "Manifest markers (the opt-in data surface)" (5 files), "Derivation engine (both
  tailnet legs + arm var)" (3 files), "The four-site mirror (teardown + gate)" (2 files).
- I did **not** read `map.md`'s prose content in full — per the LIVE-area instruction, I limited myself to
  metadata (size/mtime) and the DB's structured section breakdown, which is itself an as-of-parse-time snapshot.

### 2.2 `run-14/_context/` — **LIVE, MAP-lane-owned, as-of 2026-09-22T05:26:09Z**

**Status:** live. **Disposition:** read-only; re-snapshot before citing.

6 files (grew from 5 during this inventory): `canonical-files.txt` (360 B, 23:46 CDT), `changeset.md` (4698 B,
23:46 CDT, "wave-13, 103626a..d5625ba, 10 files"), `complete-map-run14.json` (3912 B — **new, 00:25 CDT**),
`forward-anchor.md` (4729 B, 23:47 CDT), `input-index.md` (17778 B, 22:53 CDT — oldest, ~2.5h settled),
`ocr-grounding.md` (18626 B, 22:54 CDT). mtimes span 22:53→00:25 CDT (~92 minutes of continuous activity, tail
still warm at the reconciliation instant). Not read in full content, per LIVE-area instruction — counted and
stamped only.

### 2.3 `run-14/analysts/` — **LIVE, MAP-lane-owned** (not named in dispatch scope — added; see §0)

**Status:** live (raw per-analyst output feeding `map.md` synthesis). **Disposition:** read-only.

14 files, mtimes 23:54–00:02 CDT (this bucket looks to have stopped growing ~85 min before the reconciliation
snapshot, unlike `_context`/`design`/`map.md`): `flow-{deploy-gate,gap1-es-vip,gap4-secrets,ingress,
manifest-markers,mirror,render-path,vip-service}.md`, `req-{completeness,forward-matrix,gap1-crosshost-es,
gap2-tls-trust,gap3-per-host-scoping,gap4-cross-host-secrets}.md`. Naming and count match
`state-validation.md`'s independent `ocr session list` observation (~14 `flow-*`/`req-*` instances); no
`flow-probe.*` file exists, consistent with that doc's note that `flow-probe` `crashed`.

### 2.4 `run-14/lanes/` — mixed: `deploy/` (gated plan, settled) + `design/` (LIVE)

#### 2.4a `lanes/deploy/` (2 files) — gated deploy plan; design-only; **nothing executed**

**Status:** gated-plan. **Disposition:** design-only, operator-gated; both files self-declare read-only.

- **`prune-resetup-invocation.md`** (24763 B, mtime 23:05 CDT — the older/settled of the pair). "Prune +
  Re-setup Invocation — Multi-machine e2e relaunch (graph producer + trixie consumer)". Own header: *"READ-ONLY;
  this doc is a gated plan, nothing here was executed."* Content:
  - **Verdict up front:** CAN close the **litellm VIP leg** cross-host this cycle (graph re-published as
    Tailscale-Services host; trixie plain-client consumes `svc:lme-litellm` VIP, proven by an armed
    consumer-node probe). CANNOT close: ES cross-host (**hard stop** — graph ES `:9200` loopback-only, no
    tailnet marker, TLS SAN mismatch), "trixie as thin service-host" (no flag combination yields it), OCI
    push→pull image distribution (no push path exists in-repo).
  - **Freeze scope (§1):** in-scope to mutate = host `graph`, host `trixie`, the 4 `svc:lme-*` VIP defs only.
    Explicitly out of scope: tailnet ACL/grants/autoApprovers, `svc:vncserverwindow`, `svc:tmptag-*`, silmaril,
    any other tailnet node.
  - **Live state snapshot (§2, read-only, captured this session):** graph (100.73.170.86, 12cpu/15Gi,
    /data=916G/848G avail) and trixie (100.127.117.27, 20cpu/15Gi, chosen graphroot `/home` ext4 797G avail)
    host facts.
  - **Ground-truth correction:** a live registry GET shows `svc:lme-kibana` is **ABSENT** (not the
    memory-noted `[443,5601]`-partial state) — 3 of 4 LME VIP defs correct/live, only kibana needs
    (re)creation; `autoApprovers` already covers it, so no ACL edit is needed.
  - **5 ordered phases (A–E)** with an explicit **[GATED-LIVE]** vs **[safe]** tag per step (a full index table
    at §2b): A = tailnet VIP registry prune/repair (PUT-create `svc:lme-kibana`, recommended surgical variant vs
    a higher-mutation "delete-all-4-then-recreate" ALT), B = graph from-scratch re-setup
    (`deploy_gate.sh --host graph --stage deploy`, HOLD not `all`), C = cross-host VIP reachability probe
    (`--stage vip-probe`, safe/read-only, run FROM trixie), D = trixie plain-client deploy (+ optional D′:
    manual `litellm_master_key` cross-host copy), E = teardown (only after B–D bank).
  - **7 open risks/blockers (§3):** VIP-define ordering (Phase A must precede B or the CapMap assert
    hard-fails), ES cross-host hard stop, per-host service scoping gap, no OCI push path, litellm_master_key
    cross-host has no turnkey path, an `install.sh` cluster `-e`-drop hazard (inapplicable here — both legs are
    single-node), graphroot residue/mount notes.
- **`es-leg-phase-sequence.md`** (6916 B, mtime **00:23:39 CDT** — landed almost exactly at my first
  orientation stamp; borderline-live). Explicit **COMPANION** to `prune-resetup-invocation.md`, not a
  replacement: layers the cross-host **ES**-consumer topology (GAP-1..4) onto the same phase sequence.
  Sequencing: GAP-1 (cheap, transport-only) → **GAP-2 = critical-path blocker** (new cert transport, invisible
  to `do_vip_probe`) → GAP-4 (secrets, blocks authenticated use) → GAP-3 (per-host scoping, parallel). Self-header:
  *"run-14 is DESIGN-only — the `/ocr:address` wave implements the repo edits before any of this runs."*

#### 2.4b `lanes/design/` (8 files) — **LIVE** (grew 6→8 during this inventory; correction to dispatch's LIVE set)

**Status:** live. **Disposition:** read-only; re-snapshot before citing.

All 8 self-declare read-only / manifest-derived (R6 doctrine) / no ansible-manifest edits / no git / no
ocr-state; all feed the follow-on `/ocr:address` implementation wave, not run-14 itself:

| file | mtime (CDT) | one-line |
|---|---|---|
| `address-targets.md` | 00:12:17 | Verified `/ocr:address` target ledger for GAP-1..4 + wave-13 deltas; every `gap-designs.md` citation adversarially re-read against live HEAD `d5625ba` — "all EXACT except ONE drift" |
| `deadvar-vip-reachable.md` | 00:15:10 | Deep validation of whether `tailscale_require_vip_reachable` is dead code; roots cause and designs the composable (not bare-minimum) fix |
| `composability-audit.md` | 00:15:49 | Audits wave-13 for "gate-satisfying but incomplete" defects — green checks that are secretly shallow |
| `probe-completeness.md` | 00:16:01 | Designs the complete probe so "green == GAP-2 actually closed"; proves what `do_vip_probe`/`do_health` validate today |
| `gap-designs.md` | 00:17:56 | The four deploy GAPs, file-level, manifest-derived; reuses the one existing derivation (no second impl) |
| `tls-routing-matrix.md` | **00:24:15 (new)** | Full cross-host TLS+routing matrix for ALL consumer legs (not just ES:9200) — dashboard is a 4-backend TLS client |
| `secrets-scoping-closure.md` | **00:25:11 (new)** | Extends GAP-3/GAP-4 (scoping/secrets) from "ES+litellm only" to the full real consumer set |
| `requirement-matrix.md` | 00:25:56 (rewritten) | Consumer cross-host requirement matrix; machine-generated by `.ocr/utility/derive_consumer_requirements.py` |

### 2.5 `run-14/_index/` — this-lane's own deliverables (cite as-of; **2 claims superseded mid-window**)

**Status:** this-lane-deliverable. **Disposition:** cite with the as-of timestamp attached; the two items
flagged below should not be re-cited without an independent re-check.

Disk has **5** files (dispatch named 3):

| file | deliverable | one-line |
|---|---|---|
| `INDEX.md` (50026 B) | B+C | Master inventory: `rounds/` 93 + `map/runs` 184 (pre-existing, Appendix A/B) + `promoted/` 47 + `.ocr/utilities/` 11 + `_index/` 5 + `_archive/` 1 (new). Archive decision: zero moves. Snapshot stamped "as of 2026-09-22 ~00:05". |
| `blockers-status.md` (8737 B) | D | Honest run-13-failure accounting: "SQLite map closed" ≠ "deployment succeeded"; reconciles two sources on the kibana silent-dead-VIP timeline; B1/B2/S1-S4 ledger with disposition tags. |
| `state-validation.md` (4889 B) | F | **Rewritten ~05:20Z**, explicitly retracts its own 2026-09-21 predecessor's "closed, resumability inferred" verdict as false; documents `session_resumed 04:44:55` → `synthesis(5)` by `05:16:32`. |
| `fragment-rounds.md` (14463 B) | B (Appendix A) | SA6 verbatim inventory of `rounds/` (93 files; 0 cruft candidates by mechanical scan). |
| `fragment-mapruns.md` (25645 B) | B (Appendix B) | SA7 verbatim inventory of `map/runs/`+session-root+`acl-snapshots/` (184 files; 5 checksum-identical `canonical-files.txt` dupes noted, not archived). |

**Two claims falsified within my own inventory window** (both docs were correct as of their own stated
timestamp; both are now stale — recorded so no later reader re-cites them uncorrected):

1. `state-validation.md` §3 (written ~05:20Z): *"14 | — | — | — | **NO row yet** (MAP lane still mid-synthesis)"*.
   **Superseded ~4 minutes later:** I directly observed `map_runs id=31` for run-14 at
   `parsed_at='2026-09-22 05:24:32'` (`file_count=10`, `section_count=3`, `source='orchestrator'`; the 3
   `map_sections` rows sum 5+3+2=10, internally consistent).
2. `INDEX.md` §2 (own header stamp "as of 2026-09-22 ~00:05"): *"there is no `run-14/map.md`/`map-meta.json`"*.
   **Superseded ~19–21 minutes later:** both now exist — `map.md` (15541 B, mtime `05:22Z`) and `map-meta.json`
   (3912 B, mtime `~05:24Z`).

Neither document was wrong when written; both are **as-of-superseded**. This is the exact failure mode this
indexing lane exists to catch, here applied reflexively to two of its own sibling deliverables.

### 2.6 `run-14/promoted/` — migrated scratchpad research (durable, safe to cite)

**Status:** migrated. **Disposition:** durable, verbatim (sha256-provenanced per directory), safe to cite as-is
— not part of the live churn (all mtimes settled 23:5x CDT or earlier, one file from 2026-09-18).

**47 files** (grep-verified against the frozen snapshot) — **exact cross-source corroboration** with
`INDEX.md`'s own stated count of 47 (agreement recorded, not just disagreements). Top-level `README.md` (1,
the topic→path map) + 8 topic directories, exact per-directory counts from the frozen file list:

| dir | files | notable finding (from its own `reconciliation.md`) |
|---|---:|---|
| `vm-nesting/` (+`_ocr_vms/`) | 8 | Firmware tension split: "SeaBIOS-needed" refuted via an OVMF airgap-proof domain; "bootloop=secure-boot" corroborated (0/4 XMLs enable secure-boot); XMLs declare 12GiB vs map's "16G" sizing — flagged. |
| `tailnet-in-vm/` (+`vip-define-audit/`) | 12 | `ts-api.md` = 88-byte redirect stub confirms tailnet-in-vm and cross-host-certs share one unmet API-token blocker; kibana root-cause is a temporal progression, not a contradiction. |
| `es-cluster/` | 8 | HELD-Q1 typed obstruction; `es_master_publish_host` has no consumer (dead var). |
| `patroni/` | 3 | Net-new HA design (etcd/DCS/HAProxy); forward-arch logical-data-endpoint contract. |
| `cross-host-certs/` | 7 | Two-CA mesh; `verify=False`/SAN cross-machine gap. |
| `airgap-supply-chain/` | 3 | Single-node airgap CLOSED, kept distinct from multi-node BLOCKED. |
| `_cross-cutting/` | 2 | `manifests-architecture.md` — the no-hardcoding manifest-render spine underpinning all lanes. |
| `disk-partition-seeds/` | 3 | Only author-from-zero lane; seeds only, no design authored yet. |

Minor cross-source variance (recorded, not chased further): `INDEX.md`'s own per-lane table states
`cross-host-certs=6` / `tailnet-in-vm=13`, one apart from the disk counts above in each direction (7/12) — the
two errors cancel in the row-sum (46 either way), so `INDEX.md`'s grand total of 47 is still exactly right;
likely a one-file mis-attribution between two adjacent table rows, not a real count error.

Of 48 scratchpad research `.md` files, 27 were promoted; 21 were deliberately excluded (8 single-node
"graph-seal" wiring seals superseded by promoted content, 13 prior-round OCR-workflow drafts) — enumerated in
`promoted/README.md` for auditability before the scratchpad evaporates.

### 2.7 `run-14/_archive/` — reversible archive area (confirmed exactly as dispatched)

**Status:** archive. **Disposition:** no action; recipe-only.

1 file (`README.md`, 2354 B). Policy: archive only mechanically-detectable cruft (zero-byte / checksum-identical
/ self-declared-superseded), never audit-trail or CLI-referenced files, never delete. Mechanical scan found 5
checksum-identical `canonical-files.txt` dupes (runs 6–10) but ruled them **not** cruft (each is its own run's
completeness oracle; the identity is itself signal that the changeset was stable across those runs) — **zero
files archived this pass**, move-log table empty. Full rationale lives in `_index/INDEX.md` §6; this file is
just the archive area's own marker + move-log.

---

## 3. `run-15/` — GAP-1..5 cross-host-consumer map (added post-06:23Z; **this file now covers runs 13-15**)

**Status:** completed orchestrator map (real 14-agent swarm). **Disposition:** durable, safe to
cite as-is. DB row is still `closed` / `current_round=10` — the map twin ran run-15 under it
(`updated_at` → `2026-09-22 16:21:39Z`). This **extends the MASTER-INDEX §3 map-run curve past
run-14**: run-15 = **21 files / 6 sections, source=orchestrator** (curve ended at run-14 in the
index).

**`map.md` header (read in full):** "Code Review Map — run-15 (GAP-1..5 cross-host-consumer
wave)", Generated 2026-09-22, **Files 21, Sections 6**, changeset `d5625ba..2b3c96d` (15 commits
`d0a6fe6..2b3c96d`), **+1478 / −91**, built by a **14-agent swarm** (8 flow analysts + 6
requirements mappers) against R1–R10.

**Thesis (1-2 lines):** the GAP-1..5 wave is the **cross-host consumer READ-path substrate** — a
second machine (`trixie`) reads a producer's (`graph`) Elasticsearch over the tailnet — with
**every gap gated default-off / backward-compatible** (the swarm verified a plain single-host
install renders byte-for-byte unchanged). It is **NOT** a collection repair: 6 agents converged
that the producer **ship path** is untouched (Fleet output URL, ES loopback bind, `ignore_errors`
all unchanged in `d5625ba..2b3c96d`) → a fully-armed consumer would read an ES that still collects
nothing.

**6 sections (from `map-meta.json`, files sum to 21):** (1) Producer tailnet VIP exposure (GAP-1,
5) · (2) Cross-host consumer TLS trust (GAP-2, 5) · (3) Per-host service scoping (GAP-3, 4) · (4)
Cross-host consumer secrets (GAP-4/5b, 4) · (5) Host-scoped orchestration (GAP-5, 2) · (6)
Cross-host acceptance harness / `deploy_gate` (1). 7 inter-section dependencies declared.

**Layout (21 files, residue 0):**
```
  map.md 1 + map-meta.json 1
+ flow/ 8   (FA-1..8: tailnet-vip, consumer-tls, host-scoping, consumer-secrets,
             site-orchestration, deploy-gate, render-engine, dataplane-r10)
+ reqs/ 6   (RM-1..6: r1-r2, r6, r10a-r10c, r10b-d-e, r5-r7, r3-r4-r8)
+ 4 aux .md (PARTIAL-adjudication.md, flow-analysis.md, requirements-mapping.md, topology.md)
+ canonical-files.txt 1
= 21
```

**⚠ As-of-superseded artifact (the reflexive §2.5 pattern, applied to run-15's own tree):**
`PARTIAL-adjudication.md` (mtime **10:39 CDT**) declares *"Status: PARTIAL … the 14-analyst swarm
did NOT run … there is deliberately no `map.md` and no `map-meta.json`"* — because a 60-min loop
cron re-fired the map mandate after an operator "Hold — pass off", and the doc (correctly, at 10:39)
refused to stamp a swarm that had not launched. **That doc is now stale.** The swarm ran ~25 min
later — mtime ordering is the evidence, not assertion (all CDT): `flow/FA-*` + `reqs/RM-*` land
**11:04–11:11**, `flow-analysis.md`/`requirements-mapping.md` **11:13–11:14**, `map.md` **11:16**,
`map-meta.json` **11:18 (= 16:18Z)** (DB parse `updated_at` `16:21:39Z` ≈ 11:21 CDT, after). Real 14-analyst
output **preceded** synthesis, so `map.md` is **not** the "phantom stamp" the doc warned against —
it is backed by 14 on-disk analyst files. **Cite the completed `map.md`/`map-meta.json`; treat
`PARTIAL-adjudication.md` as a superseded 10:39 warning, retained (not deleted) for audit.**

**gippidy vs run-15 — do NOT conflate:** run-15 is the **GAP-1..5** map. The **gippidy collection
pivot** is a *separate* artifact — the 5-agent read-only fanout in
`.ocr/index/salvage/gippidy-fanout-findings.md` (mtime 10:15 CDT, **outside** this session tree, not
in run-15's 21). At 10:39 `PARTIAL-adjudication.md` had presented that fanout as the round's
*pre-swarm stand-in* intelligence; the run-15 14-agent swarm is a **distinct, later** product.
Different lane, different file home, different count bucket.

**run-14 growth 90→98 (+8) — all in `lanes/address/`:** the address lane is **absent from the
§2.4 / MASTER-INDEX §4.4 run-14 enumeration** (which listed only `design/`+`deploy/`). It now holds
**12 files** (mtimes CDT): 5 already inside the index's 90 — `execution-plan.md` (01:06) ·
`lead-brief.md` (01:18) · `orchestration-plan.md` (01:25) · `gap4-file-driver-verdict.md` (01:26) ·
`gap2-findings.md` (01:48) — and the **7 the caller flagged as post-stamp completions** (02:51→08:22):
`stage-c-plan.md` · `gap3-contract.md` · `stage-d-plan.md` · `stage-e-plan.md` · `gap5/design.md` ·
`gap5/validation.md` · `handback.md` (address-lane staged plans + contracts + handback; not read in
full). **The +8 delta (90→98) = `gap2-findings.md` + those 7** — the lane grew 4→12 since the index's
count instant; the other 4 files above were already inside the 90.

**Also newly described (baseline, not delta):** `lanes/deploy/` is now **3** files, not the frozen
§2.4a **2** — a third, `es-leg-sequence.md` (00:40 CDT / 05:40Z; near-dup name of the §2.4a-described
`es-leg-phase-sequence.md`), landed 14 min after the 05:26Z snapshot. Born before the index's ~06:26Z
count instant, so it sits **inside the 90 / 361 baseline, not the +29 delta** — it is why run-14
non-`address` = **86** vs the frozen 85 enumeration. This accounts for the last undescribed run-14 file.

### Reconciliation identity — runs 13-15 (partition, residue 0; supersedes nothing below)
```
find .../2026-09-18-fix-debian-13-selinux-apt -type f | wc -l  = 390

partition (each bucket a direct find-count; residue 0):
   241  root + runs 1-12   (FROZEN; requirements.md was MODIFIED 10:24, not added → 0 net files)
+   30  run-13             (FROZEN)
+   98  run-14             (was 90 @06:23Z; +8 = lanes/address growth, above)
+   21  run-15             (NEW; 0 → 21)
=  390

delta vs MASTER-INDEX 361 = +29 = run-14 (+8) + run-15 (+21)      [requirements.md edit = +0]
```
> **Why partition, not `-newer`:** a `find … -newer MASTER-INDEX.md` sweep returns **29** paths,
> but that is a coincidence of two cancelling errors — it **over**-counts `requirements.md` (a
> 10:24 CDT *modification* already inside the 241 bucket, +0 real files) and **under**-counts run-14
> by 1: it catches only 7 of the 8 address delta files, missing `gap2-findings.md` (06:48Z), born
> after the index's actual count instant (~06:26Z — 3 min past its imprecise 06:23Z text label) but
> before the index file's own ~07:12Z mtime, so invisible to `-newer`. The **partition identity above
> is the residue-0 proof**; the `-newer` sweep is not.

---

## Reconciliation identity

```
as-of 2026-09-22T05:26:09Z
find /home/tristan/gitters/LME/.ocr/sessions/2026-09-18-fix-debian-13-selinux-apt/map/runs/{run-13,run-14} \
     -type f | wc -l
  = 115
```

All counts below are derived from that **single frozen `find` capture** (not re-queried piecemeal), so the
identity holds by construction despite the tree actively changing around it:

```
run-13 = 30  (historical/settled)
  map.md 1 + analysts/** 18 + _context/** 4 + lanes/address/** 5 + lanes/registry/** 2 = 30
  map-meta.json = 0  (confirmed absent, matches dispatch)

run-14 = 85
  map.md 1                [LIVE]
  + map-meta.json 1       [LIVE]
  + _context/** 6         [LIVE]
  + analysts/** 14        [LIVE]
  + lanes/design/** 8     [LIVE]
  + lanes/deploy/** 2     [gated-plan, design-only]
  + _index/** 5           [this-lane-deliverable]
  + promoted/** 47        [migrated, durable]
  + _archive/** 1         [archive, zero moves]
  = 85

30 + 85 = 115  ✓ (matches find count exactly)
```

**Caveat (explicit, per dispatch instruction):** `run-14/map.md`, `run-14/map-meta.json`, `run-14/_context/**`,
`run-14/analysts/**`, and `run-14/lanes/design/**` are **LIVE, MAP-lane-owned** and were directly observed
changing during this inventory (`map-meta.json` and `_context/complete-map-run14.json` did not exist at my
first pass ~05:23Z; `lanes/design/` grew 6→8 files between two of my own listings; the DB's `map_runs` row for
run-14 was written at `05:24:32Z`, after my initial stamp). **Any of these five subtrees may already differ
from the counts above by the time this file is read.** The counts are exact **for the single instant
`05:26:09Z`**, proven internally consistent by construction (one frozen file list, not resampled per-subtree),
not guaranteed current.

**Residue: none.** Completeness is established by per-bucket closure, not by a search-root grep: run-13's five
buckets sum to 30, run-14's nine buckets sum to 85, 30+85=115 = the frozen `find` count. No file is
unattributed and none is double-counted. (A `grep -v '/run-13/\|/run-14/'` check returns zero rows but is
vacuous — both are the search roots — so it is not cited as evidence.)

---

## Unclassifiable / anything else worth flagging

- **Nothing was unclassifiable at the file level** — every one of the 115 files landed cleanly in exactly one
  bucket.
- **What *is* unresolved** is upstream of files: (a) the run-13 `map_runs`/`map_sections` three-way count
  mismatch (§1), and (b) the two as-of-superseded claims in sibling `_index/` deliverables (§2.5) — both are
  DB-state / cross-document drift, not filesystem ambiguity, and both are explicitly the MAP lane's or a future
  reader's to act on, not mine to fix from a read-only seat.
- **Spec-vs-disk deltas** are consolidated in §0 rather than scattered, since that was the single most
  actionable output of this pass.
