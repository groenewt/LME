# `.ocr` MASTER INDEX — complete inventory of Open Code Review state

**Scope:** the ENTIRE `/home/tristan/gitters/LME/.ocr/` tree — all 3 session directories (5 DB sessions), the top-level config/skills/data/tools surface, and every map run 1-14. Not just one session's run-14 subtree.
**Home:** `.ocr/index/` because it is **git-visible** (durable, trackable). Per-session working state under `.ocr/sessions/` + `.ocr/data/` is **gitignored**, so it is the wrong home for an index of *complete* `.ocr`.
**As-of:** `2026-09-22 06:23Z`. **The tree is now settling:** the `2026-09-18` session completed run-14 (05:24:32Z) and then **closed** (05:51:39Z), so all five DB sessions are closed. The surfaces that moved *during* the pass: `.ocr/index/` (this lane + its hostile-confirmation swarm), `.ocr/utilities/` (the operator's mid-pass reorg + 3 HC-4-driven fidelity rescues), and the MAP lane's run-14 `lanes/` (to ≥05:59Z). Final counts reconciled at close (§8).
**Author:** INDEXING/COMPACTION lane lead. READ-ONLY on all live systems; ran NO `ocr state` transition; nothing deleted.

**Lineage:** SUPERSEDES `sessions/2026-09-18-…/map/runs/run-14/_index/INDEX.md` (which indexed only run-14) **by inclusion** — that file is now the run-14 detail leaf (linked in §4.4). Companion docs: **`./PROGRESS-LOSS.md`** (why it looks like we lost so much progress) and **`../utilities/README.md`** (the complete ad-hoc-script centralization catalog). Per-area detail: `areas/*.md`.

**How to read:** §1-§3 inventory, partition counts, and session/map-run history; §4 per-area detail; §5-§6 centralization and the progress-loss narrative; §7-§9 constraints, close-out, and adversarial (hostile-confirmation) verification.

---

## 1. Completeness as a reconciliation identity (not a claim)

"Complete" is a checkable number, not an assertion. Each area was inventoried by an independent agent that published its own file-level `find`-count = (listed) + (glob-counted), residue 0; the lead cross-checked each against an independently computed partition. All six reconcile.

| area | detail file | count | reconciled |
|------|-------------|------:|:----------:|
| top-level (non-sessions, incl. `index/`) | `areas/top-level.md` + `../utilities/README.md` + this index | **217** (186 catalogued + 31 `index/`) | ✓ §8; the area file's own "183" is an earlier stamp that predates the +3 fidelity rescue |
| session `2026-09-16` | `areas/sessions-16-21.md` | **38** | ✓ residue 0 |
| session `2026-09-21` | `areas/sessions-16-21.md` | **18** | ✓ residue 0 |
| session `2026-09-18` runs 1-12 + root/rounds | `areas/session-18-runs-1-12.md` | **241** (142 + 99) | ✓ residue 0 |
| session `2026-09-18` run-13 | `areas/session-18-runs-13-14.md` | **30** | ✓ residue 0 |
| session `2026-09-18` run-14 (complete 05:24:32Z) | `areas/session-18-runs-13-14.md` | **90** | ✓ as-of 06:23Z (85→90; MAP lane wrote `lanes/` to ≥05:59Z, HC-5) |

**Identity (as-of `06:05Z` — a LIVE tree; read this as a drift monitor, not a constant):** `find .ocr -type f` = **634** = **217** non-sessions + **38** `2026-09-16` + **18** `2026-09-21` + **361** `2026-09-18` (= 241 + 30 + 90). **Residue 0** at this instant. Of the 217 non-sessions, `.ocr/index/` = **31** (this lane's own output).
- **Scope caveat (HC-1 + advisor):** the **217** *includes* `index/`; the non-sessions surface *excluding* `index/` is **186** (was 183 before the 3 HC-4 fidelity rescues) — `217 = 186 + 31`. Same tree, two scopes; the area files' "183" is their own earlier stamp — don't conflate it with the total.
- **Coverage, not just sum (HC-1):** the four-bucket sum is a `find`-count that *cannot* fail to close — it is a drift alarm, not proof of description. The real "is every file inventoried?" answer: every file is either inventoried in an area file, OR is this lane's own self-referential `index/` output, OR sits in a **named live-writer area**. Three live writers move the tree during the pass, so any single total is a timestamp: (a) this lane + the hostile-confirmation swarm writing `.ocr/index/`; (b) the **operator** reorganizing `.ocr/utilities/` (a raw `scratchpad/` move, now staged — §5); (c) the MAP lane's run-14 `lanes/`. The two closed sessions (−16, −21), run-13 and runs 1-12 are **frozen**; −18 closed 05:51:39Z. §8 re-stamps at close.

## 2. The `.ocr` surface at a glance

```
.ocr/
├── cli-config.json · config.yaml · model-profiles.yaml ·        ← 6 top-level config/doc files
│   reviewers-meta.json · PATCHES-no-output-recorded.md · .gitignore
├── commands/   11 *.md  (the ocr slash-commands)                → areas/top-level.md
├── skills/     47        (SKILL.md · AGENTS.md · references/{reviewers 29, map-personas 3, …} · assets)
├── tools/      2         (populate_agent_row.py + __pycache__ [root-gitignored])
├── data/       38  [gitignored]  (ocr.db [18 tables] · events/ 30 jsonl · exec-logs/ 2 · dashboard-active-spawn/ empty · .cache/)
├── utilities/  (plural) [git-visible]  centralized ad-hoc scripts   → ../utilities/README.md  ★ CENTRALIZE
├── utility/    (SINGULAR, 1 file: derive_consumer_requirements.py) [git-visible]  ⚠ different agent; near-dup name — see §4.1
├── index/      (THIS index) [git-visible]
└── sessions/   [gitignored working state]
    ├── 2026-09-16-…  38  closed  (-18's cited predecessor)         → areas/sessions-16-21.md
    ├── 2026-09-21-…  18  closed  (a different model's OCR-tooling map, mislanded)  → areas/sessions-16-21.md
    └── 2026-09-18-…  361  CLOSED 05:51:39Z (run-14 complete 05:24:32Z)
        ├── root: context/requirements/rounds (241 w/ runs1-12)     → areas/session-18-runs-1-12.md
        └── map/runs/run-13 (30) · run-14 (90: map.md+map-meta.json FILES, analysts/, lanes/{design,deploy,address}, _index/, promoted/, _archive/)  → areas/session-18-runs-13-14.md
```
> Correction to the earlier tree model: run-14 has **no `map/` subdirectory** — it has top-level `map.md` + `map-meta.json` files, plus `analysts/` (14) and `lanes/design/` (8).

## 3. Sessions & map-run history (DB, read-only `?mode=ro`, as-of 05:33Z)

**Five session rows (3 map + 2 directory-less `-review` twins):**

| session id | status | phase | round | map_run | updated |
|------------|--------|-------|------:|--------:|---------|
| 2026-09-16-…-apt | closed | complete (6) | 3 | 1 | 09-18 08:06 |
| 2026-09-16-…-apt-review | closed | complete (8) | 3 | 1 | 09-16 21:40 |
| **2026-09-18-…-apt** | **closed 05:51:39Z** | complete (6) | 10 | **14** | 09-22 05:51 |
| 2026-09-18-…-apt-review | closed | complete (8) | 10 | 1 | 09-19 12:34 |
| 2026-09-21-…-apt | closed | complete (3) | 1 | 1 | 09-21 22:29 |

-18 completed run-14 (`map_completed 05:24:32Z`) and then **closed** (`session_closed 05:51:39Z`; `ocr state show` now returns "No active session found" — confirmed HC-3), so **all five DB sessions are now closed** and the tree is frozen except `.ocr/index/`. A DB slug artifact (`fix-debian-…` vs real branch `fix/debian-…`) contributes to "which session is current" confusion (`areas/progress-loss-evidence.md` §2).

**Map-run curve — read it as a MODE chart, not a loss chart** (`map_runs.file_count` = Σ `map-meta.json` section file_paths, a *map-content* metric, **not** on-disk files):

| run | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| files | 52 | 32 | 116 | 124 | 127 | **137** | 24 | 137 | 137 | 137 | 1 | 6 | **0** | 10 |
| src | orch | orch | orch | orch | orch | orch | orch | orch | orch | orch | orch | orch | **parser** | orch |

- Runs **1→6** = full-topology growth to the 137/15 plateau. Runs **8/9/10** repeat 137/15 because **no commits landed between them** — identical only in *structural payload* (meta + canonical-files); their prose differs 90-410 lines with distinct HEADs (run-8 even has a unique `LEG-B-DELTA-addendum.md`).
- Runs **7, 11, 12** are **delta-anchored maps by design** (run-7's header verbatim: "cycle-continuation map, not a re-catalog"; 11/12 say the same in different words — HC-2) — full topology carried forward by reference, only the round's touched files enumerated. **Low counts here are a mode-shift, not degradation.**
- Run **13 is the one genuine defect**: a `source=parser` back-fill (only non-orchestrator row) — partial section rows, zero file rows, counters never updated; a **3-way** on-disk / `map_sections`(6 rows, all file_count=0) / `map_runs`(section_count=0, self-inconsistent with its own 6 children) mismatch. HC-2/HC-3 resolved the "8-vs-6": `map.md` has an **8-item TOC list** under "## Sections" *and* **6 real content headings** — the parser extracted the 6 headings (titles match the DB rows), not the TOC. Residual MAP-lane cleanup.
- Run **14 = a real orchestrator map (10/3), completed 05:24:32Z.** The earlier "phantom run-14 / counter-ahead-of-board" condition is **resolved**.

Full analysis + the honest "how much did we really lose" answer: **`./PROGRESS-LOSS.md`**.

## 4. Per-area synthesis

### 4.1 Top-level surface — `areas/top-level.md` ✓ (non-index scope now **186** @06:23Z, was 117 @05:27Z; the +69 is chiefly `utilities/` growth [54 curated + 26 operator `scratchpad/` + README] — the area file's own utilities row is superseded by `../utilities/README.md`; residue 0; advisor caught+fixed 5 factual errors pre-handback)
Config (6), `commands/` (11, one-liners from frontmatter), `skills/` (47, incl. reviewers/ 29 + map-personas/ 3), `tools/` (populate_agent_row.py read in full), `data/` (18 sqlite tables with row counts; `events/` keyed by executionId, none empty; `dashboard-active-spawn/` empty). Gitignore verified against BOTH `.ocr/.gitignore` (sessions/, data/) AND root `.gitignore` (`**/__pycache__/`).
- **⚠ Naming collision:** `.ocr/utility/` (SINGULAR, 1 file `derive_consumer_requirements.py`, born 00:25:09 by a *different* concurrent agent) vs `.ocr/utilities/` (plural, this lane's catalog). Both untracked. Re-snapshot + disambiguate.
- **Flag:** `PATCHES-no-output-recorded.md` FIX 1 patches a *global npm file*; current `dashboard.pid=540741` ≠ the PIDs the doc verified against → dashboard has restarted → patch survival unconfirmed from a static read.

### 4.2 Sessions -16 / -21 — `areas/sessions-16-21.md` ✓ (38 / 18, residue 0)
- **`2026-09-16` = -18's direct, self-cited predecessor** (`-18/rounds/round-1/final.md:7` re-reviews `-16/round-3` at the same head). -16's rounds 2-3 reviewed a folded worktree of **16 fix branches** verified **NOT merged** (`git branch --merged` returns only main+HEAD). The branch **refs** all survive; **8 of the 16** are checked out as worktrees under `/home/tristan/gitters/_ocr_wt/` (`az-b1, az-cert, az-dash, az-sf1, az-wazuh, s1, sf6, sf7`), the other 8 are ref-only, and `_ocr_wt/`'s `r2/r3/r4integ` dirs hold *separate* fold/integration branches (precision from HC-3; the source `sessions-16-21.md` already hedged "several checked out"). This is why -18 re-found the identical defect. Unique salvage not in -18's `requirements.md`: the R2 (`DATABASE_URL`) elevation rationale + the 5-namespace (166536/169584/171632/174680/177728) cert `:idmap` adjudication.
- **`2026-09-21` = NOT an abandoned LME restart** — a *different model's* (`openai/gpt-5.6-sol`) **incomplete map of the OCR tooling itself** (65 `.ocr/**` files), mislanded here by the **root-caused session-drift bug**: `SESSION_DIR="${DATE}-${BRANCH}"` is date-anchored (`map-workflow.md:31-39`). Highest-value salvage; OCR-tooling defect, not LME code.
- **`-review` DB rows are directory-less** (5 DB rows, 3 dirs). **OPEN (-18's territory):** whether the 16 fix-branch changes were later hand-reapplied under different SHAs — `--merged` only rules out a direct merge.

### 4.3 Session -18, runs 1-12 + root/rounds — `areas/session-18-runs-1-12.md` ✓ (241, residue 0; advisor-corrected an r8 misread)
- **Supersession chains:** run-1→6 full-topology growth (run-2 a contraction, different base ref); run-6 = plateau origin (never superseded; 7 references it, 8/9/10 re-emit it); run-11/12 on a separate commit-delta axis. Pre-session lineage traces to -16 round-3.
- **Round verdicts r1-r10** (round-meta.json ⋂ final.md agree): r1-r5 REQUEST CHANGES (r3 largest panel = 11 reviewers; r5 split 2RC/3APPROVE), **r6 APPROVE (first)**, r7 APPROVE, r8 REQUEST CHANGES (wave-8 diff itself clean; blocked on the unlabeled undeployable `cluster` profile R8-2, not a single-node regression), r9 NEEDS DISCUSSION, r10 NEEDS DISCUSSION (conditional on operator Q1). No round-11/12 review dirs exist (only map runs).
- **Stale root docs (real):** `discovered-standards.md` frozen at run-1 vintage; `context.md`/`requirements.md` carry Round-5 content verbatim (later mtimes, no regen) — neither reflects rounds 6-10.
- **Absences:** no `lanes/`/`_context/` in runs 1-12; no `analysts/` dir (closest: `agents/` [run-4:47; run-5 EMPTY despite map.md describing a 7-agent fleet]); canonical-files snapshot appears under two names across runs.

### 4.4 Session -18, runs 13-14 — `areas/session-18-runs-13-14.md` ✓ (30 + 90 = 120 @06:23Z; the per-file enumeration below is the 05:26Z snapshot summing to 85, +5 landed post-completion in the MAP-lane-owned `lanes/` to ≥05:59Z [HC-5]; residue 0) · supersedes `run-14/_index/INDEX.md`
- **run-13** (30): substantive `map.md` (8 sections) but degenerate DB (§3); `lanes/{address,registry}`.
- **run-14** (85): `map.md`+`map-meta.json` [complete] · `_context/` (6) · `analysts/` (14) · `lanes/design/` (8) · `lanes/deploy/` (2, gated plan) · **`_index/` (5: INDEX.md, blockers-status.md, state-validation.md + fragment-rounds.md + fragment-mapruns.md)** · `promoted/` (47 migrated) · `_archive/` (1). This lane wrote only `_index/` here; the rest is MAP-lane-owned.
- The prior `run-14/_index/INDEX.md`'s promoted table has two off-by-one lane rows that **cancel** (grand total 47 still exact). This master index is now the authoritative entry point; the session INDEX carries an upward pointer.

## 5. Ad-hoc script centralization → `../utilities/`

The prior pass centralized ~8 scripts and stopped — the denominator was undercounted. **Corrected + closed:** an exhaustive sweep found **73** ad-hoc scripts (62 `*.sh`/`*.py` + 4 shims in the `/tmp` scratchpad [1238 files total, 56% quadlet/manifest fixtures] + 7 in the repo-root `scratchpad/`, which is untracked-AND-unignored — a real loss surface, PROGRESS-LOSS B3). **Triage identity (mechanically verified, residue 0): `73 = 54 centralized + 5 pointered + 14 throwaway`** (was 51/·/17; **HC-4 proved 3 "throwaway" fidelity checks carry unique coverage** a set-diff structurally cannot — 21 units the general tools miss + a duplicate-mount `.count()` — so they were **rescued into `utilities/fidelity/`** before session-end evaporation, §9) — README↔disk bijection confirmed by empty diff. Complete catalog (sha256 per file, 9 categories, the 7-extract `deploy_gate.sh` snapshot-drift unit, and a blast-radius WARNING table): **`../utilities/README.md`** (364 lines). ⚠ utilities/ now holds high-blast-radius tools — `vip/restore_acl.sh` (force-POSTs the whole tailnet ACL), `probe/operator_access.sh` (dumps live secrets to local plaintext *at runtime*), `probe/teardown_verify.sh` (runs `wipe_lme.sh`), `probe/graph-seal/seal.sh` (live ES POST+DELETE) — each flagged in the README; **no *hardcoded* secret exists in any centralized file** — HC-4 independently re-scanned all 51 + 7 snapshots + the operator's DB backup: **CLEAN** (the one credential-shaped literal `sk-lme-llama-proxy` is a non-novel, already-fixed placeholder, not a live secret). HC-4 also caught one under-flagged hazard — `gate/allfuncs.sh.snapshot` arms `do_rsync --delete`/`do_wipe`/`do_install`/`do_teardown` once sourced — now **added to the WARNING table**.

**⚠ Live operator reorg (mid-pass, ~06:0XZ):** the **operator** relocated the repo-root `scratchpad/` into **`.ocr/utilities/scratchpad/` (26 files)** and `git add`-ed all of `.ocr/utilities/` ("just organizing — staging/moving"). This directly executes PROGRESS-LOSS Part-D #2 (the B3 rescue) — good — but as a *raw* move it now **duplicates** curated work: of the 26, **7** re-copy curated scripts (the 6 `lane-authoring/` emit/insert/populate `.py` + `probe/tailnet_read.sh`) and **18** re-copy `index/salvage/` (all **sha256-identical**, verified). Only **1** is net-new: `ocr.db.bak-20260917T004634Z` (1 MB binary), **now staged for commit**. This lane did **not** author `utilities/scratchpad/` and leaves it untouched (never-delete; it is the operator's area now). **Operator decisions (flagged, not resolved here — HC-4 concurs):** (1) **de-dup** — keep EITHER the curated 9-category split OR the raw `scratchpad/` dump, not both; HC-4's mechanism: `git rm -r --cached .ocr/utilities/scratchpad/` drops it from the commit *index-only, leaving the working file* — which matters because the moved `ocr.db.bak` may now be the **only surviving copy** (its source `scratchpad/` is gone), so do **not** `rm -rf`. (2) **binary in history** — decide whether the 1 MB `ocr.db.bak` should be committed. (3) **PII** — `vip/patch_acl.py:23` hardcodes a real personal email as a tailnet-ACL principal (not a credential; scrub-before-public-push is an operator call).

## 6. Why it looks like we lost so much progress → `./PROGRESS-LOSS.md`

**Evidence verdict: REFINED.** Two truths at once: (1) **the code is safe and remote-backed** — 51 commits ahead of `main`, zero reverts/divergence, `origin == HEAD` (`0 0`); the MEMORY "not pushed" belief is stale. (2) **What shattered is the context layer** — split across 5 sessions, half the review transcripts invisible behind a dashboard wiring gap, 1238 scratchpad files evaporating, tooling re-derived each cycle. The alarming signals (map "collapse," phantom run-14, "No output recorded"/"crashes") are **artifacts** (mode-shift, live-session-in-flight, wiring gap), not losses. The **real, bounded** losses: 26/101 DB-unrecoverable reviewer *rows* (content intact on disk — **0/26** lost, HC-2); session splintering (root-caused `SESSION_DIR`); the untracked-unignored repo `scratchpad/` (since operator-relocated + staged); an out-of-repo stopgap patch. Fix is **structural** — this index + centralized utilities + three root-cause fixes — not a code recovery. Full narrative + remediation ladder: `./PROGRESS-LOSS.md`.

## 7. Constraints honored
Board-native, git-visible durable outputs. **READ-ONLY on the live MAP-lane-owned run-14 subtrees** (`map.md`, `map-meta.json`, `_context/`, `analysts/`, `lanes/`, `promoted/`) and all live systems — HC-5 found no cross-writes by content. Nothing deleted **by this lane** (centralization + salvage are **copies**; this lane's originals untouched — note: the repo-root `scratchpad/` *originals* were later **relocated by the operator**, not by this lane). No `ocr state` transition. **No git state-changing command** (HEAD still `d5625ba`; the staging of `.ocr/index|utilities` was the operator's, HC-5-dated to after this lane finished). **Freeze-Mode — this lane's three write areas, stated exactly:** (1) `.ocr/index/` (index + `salvage/` + `hostile-confirmation/`); (2) `.ocr/utilities/` (the CENTRALIZE catalog + the 3 rescued `fidelity/` checks — **not** the operator's `scratchpad/` dump); (3) **`run-14/_index/`** (this lane's own board deliverables B/C/F — `INDEX.md`, `state-validation.md`, `blockers-status.md`, `_archive/README.md`; the HC-5 pointer fix + the fact-#4 correction landed here, in this lane's own files, never in MAP-lane content).

## 8. Close-out reconciliation — as-of `2026-09-22 06:05Z` (hostile-confirmation swarm 5/5 landed; tree LIVE)
- **Reconciliation identity closes at each instant, residue 0:** `find .ocr -type f` = **634** = non-sessions **217** (incl. `index/` **31**) + `2026-09-16` **38** + `2026-09-21` **18** + `2026-09-18` **361** (= 241 + 30 + 90). This number is a **drift monitor, not a constant** (HC-1): it moved 596→597→624→626→634→**635** across the pass (the trailing +1 is run-14 `lanes/` still writing past the 06:05Z stamp), every step from a **named** live writer (this lane's `index/` + the 3 fidelity rescues; the operator's `utilities/` reorg; the MAP lane's run-14 `lanes/`, still writing to ≥05:59Z per HC-5). Nothing grew *unaccounted*.
- **Coverage — the real completeness question (HC-1):** the four-bucket sum is a `find`-count tautology; the substantive check is "is every file *described*?" Answer: every file is (i) inventoried in an area file, (ii) this lane's own self-referential `index/` output (`MASTER-INDEX`, `PROGRESS-LOSS`, `areas/`, `salvage/`, `hostile-confirmation/`), or (iii) in a **named live-writer area** (`utilities/scratchpad/` = operator move; run-14 `lanes/address/` = MAP lane). No orphan outside those three classes.
- **Utilities on disk = 81 = 54 (this lane, 9 categories) + 26 (operator `scratchpad/` reorg, staged) + 1 README.** Curated triage `73 = 54 + 5 + 14` (HC-4 reclassified 3 throwaway→centralized + rescued), residue 0; the 51 audited by HC-4 are bijection-clean + secret-clean, +3 rescued. The operator's 26 = **7** duplicate curated scripts + **18** duplicate `index/salvage/` (all **sha256-identical**, lossless 18/18) + **1** net-new binary (`ocr.db.bak-…`, **staged**, possibly the only surviving copy → operator's call, §5).
- **Salvage:** `index/salvage/` = 19 (18 + README); the 18 are sha256-identical to both the (now-relocated) originals and the operator's copy — redundant-but-verified insurance, not unique custody any more.
- **Archive (Deliverable C):** `run-14/_archive/README.md` present; the reasoned ZERO-move decision holds.
- **Secret scan:** no hardcoded credentials or private keys in any centralized script (the flagged tools *invoke* danger at runtime; they do not *contain* secrets).
- **Hostile-confirmation swarm (§9):** 5 adversarial auditors. **In:** HC-1 completeness (NO on *static* coverage — folded above), HC-2 progress-loss (**SOUND**, 7/7 CONFIRM — B1 content-loss reconciled to **0/26**), HC-3 sessions/maps (**SOUND**, 4/4 + 6/6 CONFIRM), HC-4 utilities-safety (**centralization CLEAN** — bijection + sha256 + secret-scan all pass; blocker = the operator `scratchpad/` dump [§5]; should-fix = `allfuncs` WARNING [fixed]; 3 fidelity checks rescued), HC-5 constraints (**4/5 honored; 1 real pointer defect — FIXED**). **All 5 landed; see §9.**

## 9. Hostile-confirmation swarm — verdicts & dispositions

Five adversarial auditors, write-disjoint, read-only on live systems, each re-deriving from filesystem/git/DB rather than trusting this lane's self-report. Full reports: `hostile-confirmation/hc-{1..5}-*.md`. **Net: the work holds — the swarm found 1 real defect (fixed), 1 misclassification (fixed by rescue), and precision refinements (folded); it also independently corroborated the operator's live reorg.**

| # | auditor | verdict | what it changed here |
|---|---------|---------|----------------------|
| HC-1 | completeness | **NO on *static* coverage** (the 4-bucket sum is a tautology) | Reframed §1/§8 as a **drift monitor + described-by coverage** (3 classes), not a constant; caught the now-false "frozen" claim → corrected. |
| HC-2 | progress-loss | **SOUND** — thesis + 7/7 CONFIRM | **Closed B1**: the 26 DB-null rows map 1:1 to on-disk `reviews/*.md` → **content-loss 0/26** (loss *smaller* than stated). Precision: run-7-only quote, 1.49 MB, `map-workflow.md:31-39`, B3=26 files. |
| HC-3 | sessions/maps | **SOUND** — 4/4 + 6/6 CONFIRM | Precision: only **8/16** fix-branches are worktrees (rest ref-only) → §4.2 corrected; confirmed −18 **closed**; explained run-13 "8-vs-6" (TOC list vs content headings). |
| HC-4 | utilities-safety | **centralization CLEAN**; 1 blocker + findings | Bijection/sha256/secret-scan all pass. **Rescued 3 misclassified fidelity checks** (unique coverage a set-diff can't do) → `54+5+14`; added `allfuncs` WARNING; flagged operator `scratchpad/` dump + PII + `git rm --cached`. |
| HC-5 | constraints/lineage | **4/5 honored; 1 real defect** | **Fixed the broken upward pointer** (5→6 `../`, 3 sites) — the one navigational link the pass exists to provide. Confirmed copy-only (8/8 sha256), HEAD unchanged `d5625ba`, no MAP-subtree writes (by content), state-doc honest-by-design. |

**Two cross-cutting facts the swarm surfaced independently (3+ auditors each):**
1. **The tree is live/self-referential during the pass** — every "exact N" is a timestamp; HC-1/HC-2/HC-5 each watched counts move. The index now says so (§1/§8) instead of asserting a frozen number.
2. **The operator reorganized `.ocr/utilities/` + staged `.ocr/` mid-pass** — HC-2/HC-4/HC-5 each caught it forensically (cp-signature mtime, deleted source, hc-3-staged-but-not-hc-1/2 tell); the operator then confirmed it directly. Not this lane's work: documented + flagged for de-dup, never adopted or undone.

**Explicitly NOT this lane's work (operator-gated):** committing the staged `.ocr/index|utilities` (HEAD is still `d5625ba` — this lane ran no git-state command); de-duplicating the operator's raw `scratchpad/` dump; deciding the 1 MB `ocr.db.bak` in history; the three root-cause fixes (B2 `SESSION_DIR` date-anchoring, FIX 3 output-wiring, a `scratchpad/` `.gitignore`/track policy) are **recommendations**, not changes performed.
