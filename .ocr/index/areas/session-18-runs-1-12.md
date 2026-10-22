# Session `2026-09-18-fix-debian-13-selinux-apt` — Historical Index (session-root, rounds/, map/runs run-1..12)

**Scope:** session-root docs, `rounds/round-1`..`round-10` (all rounds that exist), `map/runs/run-1`..`run-12`.
Excluded by mandate: `map/runs/run-13`, `map/runs/run-14` (owned by a different indexing agent; confirmed present
on disk with 30 and 85 files respectively at scan time — not counted anywhere below). Their authoritative
inventory and live totals live in `session-18-runs-13-14.md` and `../MASTER-INDEX.md` §1 + §8.
**Method:** read-only `find`/`diff`/`sqlite3` against
`/home/tristan/gitters/LME/.ocr/sessions/2026-09-18-fix-debian-13-selinux-apt/` and
`/home/tristan/gitters/LME/.ocr/data/ocr.db`. No files moved, deleted, or mutated.

Pre-session lineage (evidence, not scope): `rounds/round-1/final.md` opens as a re-review of a **prior**
session, `2026-09-16-fix-debian-13-selinux-apt`, round-3 (verdict REQUEST CHANGES, blockers B1
LiteLLM `DATABASE_URL` / B2 cert permissions) — both still unresolved when this session's round-1 opened.
The branch's review history predates 2026-09-18.

---

## 1. Session-root docs

| File | Bytes | mtime | Content vintage |
|---|---|---|---|
| `context.md` | 31,463 | 2026-09-19 07:19:12 | **Round 5** ("Round: 5 (round-4 verdict was REQUEST CHANGES — 2 blockers)"), target through commit `6d1c7ef`, 137 files |
| `requirements.md` | 10,997 | 2026-09-21 15:04:43 | **Round 5** ("Round 5 (settled branch through `6d1c7ef`)"; "supersedes the round-1..4 requirements") |
| `discovered-standards.md` | 4,360 | 2026-09-18 00:47:03 | **run-1** vintage ("Generated: 2026-09-18", "52 files, +988/−225", head `14c7c0b`) |
| `acl-snapshots/acl-prePOST-20260921T161024Z.headers` | 353 | 2026-09-21 16:10 | pre-POST tailnet ACL HTTP headers snapshot (round-11/12 era) |
| `acl-snapshots/acl-prePOST-20260921T161024Z.hujson` | 6,199 | 2026-09-21 16:10 | pre-POST tailnet ACL body snapshot |
| `acl-snapshots/.latest-prePOST-stamp` | 17 | 2026-09-21 16:10 | pointer/stamp file to the latest pre-POST snapshot pair above |

**Finding — unresolved mtime/content-vintage mismatch (facts only, mechanism not diagnosed):**
`discovered-standards.md` was written once, before round-1 even closed (its mtime 00:47:03 predates
`rounds/round-1/round-meta.json` at 01:53:03), and was never touched again across the rest of the
session (11 more map runs, 10 review rounds, 3+ days). Its content is frozen at run-1's state.
`context.md` and `requirements.md` both carry **Round 5** content verbatim, but their filesystem
mtimes are far later than round-5's close (`rounds/round-5/round-meta.json` mtime 2026-09-18
19:26:33): `context.md`'s mtime (2026-09-19 07:19:12) falls *between* `run-10/map.md` (06:56:44) and
`rounds/round-10/round-meta.json` (07:34:29); `requirements.md`'s mtime (2026-09-21 15:04:43) falls
*between* `run-11/map.md` (13:52:41) and `run-12/map.md` (15:55:34). Both files were evidently
touched/rewritten at those later points without their content being regenerated — neither reflects
rounds 6–10 (verdicts APPROVE, APPROVE, REQUEST CHANGES, NEEDS DISCUSSION, NEEDS DISCUSSION; see §2).
No `lanes/` or `_context/` directory or any other top-level session-root file exists beyond the six
listed above (confirmed via `find -maxdepth 1` on session root and on `acl-snapshots/`).

---

## 2. `rounds/` — review rounds 1–10 (all rounds that exist; no round-11/12 review dir yet)

Every round directory has the same skeleton: `discourse.md`, `final.md`, `round-meta.json`, `reviews/*`
(one file per reviewer persona), plus round-specific extras. `round-meta.json.verdict` and `final.md`
verdict lines agree in all 10 rounds (cross-checked).

| Round | Verdict | Reviewers (`reviews/`) | Root extras | Root files | Total files | One-line |
|---|---|---|---|---|---|---|
| round-1 | REQUEST CHANGES | 5 | — | 3 | 8 | Re-review of prior session's round-3; B1/B2 still open + new B3 (logstash pipeline git-ignored) |
| round-2 | REQUEST CHANGES | 5 | `b1-upgrade-convergence-proof.md`, `e2e-evidence.md` | 5 | 10 | Narrowed to one surviving security blocker (B2) |
| round-3 | REQUEST CHANGES | **11** | — | 3 | 14 | Unanimous across 11 reviewers (principal×2, quality×2, security×2, devops, infrastructure, reliability, performance, testing) — largest reviewer panel in the session |
| round-4 | REQUEST CHANGES | 5 | — | 3 | 8 | Unanimous across 5 reviewers (principal×2, quality×2, security×1) |
| round-5 | REQUEST CHANGES | 5 | — | 3 | 8 | 1 blocker (upgrade-path scoped), 8 should-fix, 6 suggestions; split 2 RC / 3 APPROVE (principals RC, quality+security APPROVE) |
| round-6 | **APPROVE** | 5 | `round6.diff` | 4 | 9 | 0 blockers, unanimous; first APPROVE of the session |
| round-7 | **APPROVE** | 5 | `changeset.diff` | 4 | 9 | 0 blockers / 6 should-fix / 8 suggestions, unanimous; cluster-in-scope question raised (routing question, not a blocker) |
| round-8 | REQUEST CHANGES | 5 | `changeset.diff` | 4 | 9 | wave-8 diff clean in isolation (5/5 reviewers, 83/83 tests green) — REQUEST CHANGES because the branch also ships an unlabeled, categorically undeployable `cluster` profile (R8-2: from-scratch install renders Phase-1 master with zero discovery keys, ES refuses startup); the single-node/default path itself is unaffected and SEAL-proven green |
| round-9 | NEEDS DISCUSSION | 5 | `tech-lead-guidance.md` | 4 | 9 | wave-9 delta clean/APPROVE-able per all 5 reviewers, but merge gate depends on operator Q1 (cluster-ship decision) |
| round-10 | NEEDS DISCUSSION | 5 | `changeset.diff` | 4 | 9 | Conditional: Q1=NO → APPROVE; Q1=YES → REQUEST CHANGES (R8-2 hard blocker) |

**Round file total: 93** (37 root files across 10 rounds + 56 `reviews/*` files across 10 rounds).
No `round-11` or `round-12` directory exists under `rounds/` — the round-11/round-12 *map* runs
(§3) exist, but no corresponding review-round output has landed yet as of this index.

---

## 3. `map/runs/run-1` … `run-12`

### 3.0 Critical semantic finding: what `map_runs.file_count` actually measures

The DB `file_count` column (52, 32, 116, 124, 127, 137, 24, 137, 137, 137, 1, 6 for runs 1–12) is
**not** a count of artifact files on disk in the run directory. It is the sum of
`sections[].files[].file_path` entries inside that run's `map-meta.json` — i.e. how many
changeset/topology files the map's content covers. Verified exactly for all 12 runs
(all file_path entries are unique per run, so sum == distinct count too):

| Run | DB file_count | Σ `map-meta.json` files (verified) | `section_count` | Σ `map-meta.json` sections (verified) |
|---|---|---|---|---|
| 1 | 52 | 52 ✓ | 7 | 7 ✓ |
| 2 | 32 | 32 ✓ | 8 | 8 ✓ |
| 3 | 116 | 116 ✓ | 13 | 13 ✓ |
| 4 | 124 | 124 ✓ | 15 | 15 ✓ |
| 5 | 127 | 127 ✓ | 14 | 14 ✓ |
| 6 | 137 | 137 ✓ | 15 | 15 ✓ |
| 7 | 24 | 24 ✓ | 9 | 9 ✓ |
| 8 | 137 | 137 ✓ | 15 | 15 ✓ |
| 9 | 137 | 137 ✓ | 15 | 15 ✓ |
| 10 | 137 | 137 ✓ | 15 | 15 ✓ |
| 11 | 1 | 1 ✓ | 4 | 4 ✓ |
| 12 | 6 | 6 ✓ | 2 | 2 ✓ |

On-disk artifact-file counts (§3.1 table) are a **completely different, uncorrelated metric** — e.g.
run-4's DB file_count is 124 but its directory holds 52 files; run-6's DB file_count is 137 but its
directory holds only 4 files. Do not conflate the two when reading the DB quality curve.

### 3.1 Per-run artifact inventory

Recursive on-disk file counts (`find run-N -type f`), confirmed against a named-files + subdir-glob
decomposition (used again in §5's identity):

| Run | Files (all, recursive) | Top-level artifacts | Subdirs | Disposition |
|---|---|---|---|---|
| run-1 | 5 | `flow-analysis.md`, `map.md`, `map-meta.json`, `requirements-mapping.md`, `topology.md` | none | historical-superseded (by run-2) |
| run-2 | 5 | same 5-file shape as run-1 | none | historical-superseded (by run-3) |
| run-3 | 11 | + `buckets.txt`, `flow-analyst-1.md`, `flow-analyst-2.md`, `numstat.txt`, `req-mapper-1.md`, `req-mapper-2.md` (first per-analyst files + pipeline intermediates) | none | historical-superseded (by run-4) |
| run-4 | 52 | `complete-map.json`, `flow-analysis.md`, `map.md`, `map-meta.json`, `topology.md` (5 named) | `agents/` = 47 `.md` files (`flow-S0N-<slice>-M.md`, keyed to section+fleet-slice) | historical-superseded (by run-5) |
| run-5 | 8 | `canonical-files.txt`, `complete-map.json`, `flow-analysis.md`, `map.md`, `map-meta.json`, `numstat.txt`, `requirements-mapping.md`, `topology.md` (8 named) | `agents/` = **0 files** (empty dir) | historical-superseded (by run-6) — see anomaly note below |
| run-6 | 4 | `canonical-files.txt`, `map.md`, `map-meta.json`, `topology.md` — leanest full-topology run | none | plateau-duplicate (**plateau ORIGINATOR** — run-6 is what 8/9/10 duplicate; it duplicates nothing itself; see §4) |
| run-7 | 8 | `_canonical_files.txt` (renamed, underscore-prefixed), `flow-analysis.md`, `flow-analyst-1.md`, `flow-analyst-2.md`, `map.md`, `map-meta.json`, `requirements-mapping.md`, `topology.md` | none | anomaly (dip) — see §4 |
| run-8 | 9 | `_canonical_files.txt`, `flow-analysis.md`, `flow-analyst-1.md`, `flow-analyst-2.md`, `LEG-B-DELTA-addendum.md` (**unique to run-8**), `map.md`, `map-meta.json`, `requirements-mapping.md`, `topology.md` | none | plateau-duplicate (structural only — see §4 correction) |
| run-9 | 8 | same shape as run-7 (no `LEG-B-DELTA-addendum.md`) | none | plateau-duplicate |
| run-10 | 8 | same shape as run-9 | none | plateau-duplicate |
| run-11 | 5 | `flow-analysis.md`, `map.md`, `map-meta.json`, `requirements-mapping.md`, `topology.md` — no canonical-files snapshot, no per-analyst files despite a claimed 13-analyst swarm | none | anomaly (collapse) — see §4 |
| run-12 | 19 | `flow-analysis.md`, `map.md`, `map-meta.json`, `requirements-mapping.md`, `topology.md` (5 named) | `reviews/` = 14 files (`flow-*.md` ×8, `req-*.md` ×6) | anomaly (collapse) — see §4; supersedes run-11 within the delta axis only |

**Confirmed absences (searched, zero hits):** no directory named `lanes/` or `_context/` anywhere
under `map/runs/run-1` through `run-12`. No directory literally named `analysts/`; the closest
analogues at different points in the session are `agents/` (run-4, run-5) and `reviews/` (run-12).
Canonical-files snapshots exist under two different names at different times —
`canonical-files.txt` (run-5, run-6 only) and `_canonical_files.txt` (run-7 through run-10 only,
underscore-prefixed) — and are absent entirely from run-1–4, run-11, run-12. This naming/location
churn (analyst-output location changed 4 times across 12 runs: flat files → `agents/` → flat files
again → `reviews/`) reflects an evolving map-generation pipeline, not corruption.

---

## 4. Disposition detail: the two flagged anomalies, and the byte-identical correction

### 4.1 run-7 "dip" (24/9 vs run-6's 137/15) — deliberate delta mode, not a failed run

`run-7/map.md` states explicitly: *"This is a **cycle-continuation map, not a re-catalog**... the
137-file topology is unchanged since run-6 and is **carried forward verbatim** (`../run-6/map.md`
§1–§15... mirrored in `topology.md`). Run-7's analytical effort is spent on the **upcoming
direction**."* Its `map-meta.json` only enumerates the 24 files touched by the round-7 address
targets (A1/A2 in `deploy_gate.sh`, B2 in `cluster.yml`, B3 in `install.sh`, B4 in
`roles/fleet/tasks/main.yml`), not the full topology. The 137/15 figure in the header prose is a
*reference* to run-6, not a re-verified structural claim in run-7's own `map-meta.json`. Label:
**anomaly** (per requested taxonomy) — annotated as intentional direction-anchored/delta mapping,
first appearance of a mode later fully adopted in run-11/run-12.

### 4.2 run-11 / run-12 "collapse" (1/4, then 6/2) — same delta mode, fully adopted

`run-11/map.md` header: *"Round-11 (run-11)... **Delta since round-10 (e5a5d7a..fa0c034)**: 1 file,
+91/-20 · **Swarm**: 13 LOCAL-only analysts."* `run-12/map.md` header: *"**Range**: `fa0c034..52bf2bb`
... map run 12 / round 12 · 8 flow analysts + 6 requirements mappers."* Both runs map an explicit
**commit-range delta**, not `main...HEAD`. run-12's `reviews/` directory (14 files: 8 flow + 6
requirements) matches its stated 14-analyst panel exactly, and its File Index closes with an explicit
completeness note ("**Total**: 6 files... Treat any 7th-file reference as a labeling slip"). Neither
run is a degraded/failed re-run of the 137-file topology — they are a **different mapping mode**
(commit-delta-scoped, not full-branch-scoped), triggered because real code changes (wave-11, wave-12)
resumed after the run-6→run-10 plateau. Label: **anomaly** (per requested taxonomy) — annotated as a
deliberate mode switch, evidenced by explicit delta-range headers and swarm-size/file-count agreement.

### 4.3 Correction to the "runs 8/9/10 are byte-identical re-runs" premise

**True only for the structural payload.** `diff -q` confirms `map-meta.json` is byte-identical
across all three runs (8≡9≡10), and `_canonical_files.txt` is byte-identical across all three.
This is why DB `file_count`/`section_count` read 137/15 for all three (§3.0) — the underlying
137-file → 15-section assignment genuinely did not change, because no commits landed between
round-7's close and round-9's close (confirmed in run-8's own map.md: *"No commits have landed
since, so the 137-file topology is carried verbatim"*).

**False for every prose artifact.** `map.md`, `flow-analysis.md`, `flow-analyst-1.md`,
`flow-analyst-2.md`, `requirements-mapping.md`, and `topology.md` all differ substantially between
every pair (8-vs-9, 9-vs-10): 90–410 differing lines per file, against totals of 44–300 lines —
i.e. roughly half to nearly all lines differ. Each carries a distinct `HEAD` commit
(run-8 `868f6d2`, run-9 `c33f567`, run-10 `1584970`) and distinct round-verdict framing
("post-round-7" / "post-round-8" / "post-round-9", matching §2's round outcomes). Additionally,
**run-8 has a unique file, `LEG-B-DELTA-addendum.md`** (3,410 bytes), absent from both run-9 and
run-10 — which alone breaks a strict "identical re-run" claim at the file-inventory level, before
any content diff is even considered.

Net: runs 8/9/10 are best read as **plateau-duplicate at the structural/topology layer, freshly
regenerated at the narrative layer each round** — not literal byte-identical re-runs of the whole
directory.

### 4.4 run-5 agents/ discrepancy (noted, not resolved)

`run-5/map.md`'s own header claims a *"Workflow wmtx65j6j (5 flow analysts + 2 requirements
mappers; 1 slice filled by Map Architect after a schema failure)"*, and an `agents/` directory
exists in run-5 to hold such per-agent output (by analogy with run-4's 47-file `agents/`) — but
run-5's `agents/` directory is **empty** (0 files). The described 7-agent fleet's individual
transcripts were not persisted to disk for this run.

---

## 5. Supersession chain summary

**Full-topology growth axis (run-1 → run-6):** `main...HEAD` file counts step
52 → 32 → 116 → 124 → 127 → **137**, sections 7 → 8 → 13 → 15 → 14 → **15**. Each run supersedes
the previous as the authoritative full-topology snapshot. Note run-1→run-2 is a *contraction*
(52→32 files, diff shrinks from +988/−225 to +379/−84 against a different base ref —
`main...HEAD` vs `origin/main...HEAD`) rather than growth; recorded as fact, cause not determined
from these artifacts alone.

**run-6 is the plateau originator, not superseded, on that axis** (labeled `plateau-duplicate`
in §3.1 per the requested taxonomy, annotated as the origin — the taxonomy has no distinct slot
for "thing that gets duplicated" vs. "the duplicate," so run-6/8/9/10 are grouped under one
label). 137/15 is the ceiling the topology reaches and never exceeds in the historical window.
run-7 references it by pointer ("carried forward verbatim... `../run-6/map.md` §1–§15"); runs
8, 9, 10 re-emit its exact structural payload byte-identically in
`map-meta.json`/`_canonical_files.txt` each round (§4.3).

**run-11 / run-12 sit on a separate, delta-range axis**, keyed to explicit commit ranges
(`e5a5d7a..fa0c034`, then `fa0c034..52bf2bb`) rather than to `main...HEAD`. run-12 supersedes
run-11 only within that axis (advances the frontier commit fa0c034 → 52bf2bb). Neither supersedes
run-6's topology snapshot — run-6 remains the last full-topology map produced in runs 1–12.

**Round verdicts do not map 1:1 to map runs.** Interleaving observed from headers/timestamps:
round-N closes → next map run is generated "post-round-N" to scope the address wave → that wave is
reviewed as round-(N+1). E.g. run-7 = "post-round-6", run-8 = "post-round-7", run-9 = "post-round-8",
run-10 = "post-round-9". run-11/run-12 (dated 2026-09-21, ~2.3 days after run-10's 2026-09-19) have
no corresponding `rounds/round-11` or `round-12` directory yet (§2).

---

## 6. Reconciliation identity

Scoped ground truth (excludes `run-13`, `run-14` via `-prune`; regular files only; 0 symlinks and
0 other-type entries confirmed separately):

```
find /home/tristan/gitters/LME/.ocr/sessions/2026-09-18-fix-debian-13-selinux-apt \
  -path /home/tristan/gitters/LME/.ocr/sessions/2026-09-18-fix-debian-13-selinux-apt/map/runs/run-13 -prune -o \
  -path /home/tristan/gitters/LME/.ocr/sessions/2026-09-18-fix-debian-13-selinux-apt/map/runs/run-14 -prune -o \
  -type f -print | wc -l
= 241
```

Listed + glob-counted decomposition (every number independently verified above):

| Component | Count |
|---|---|
| Session-root named files (`context.md`, `requirements.md`, `discovered-standards.md`) | 3 |
| `acl-snapshots/*` (2 snapshot files + `.latest-prePOST-stamp`) | 3 |
| `rounds/round-{1..10}` root named files (3,5,3,3,3,4,4,4,4,4) | 37 |
| `rounds/round-{1..10}/reviews/*` (5,5,11,5,5,5,5,5,5,5) | 56 |
| `map/runs/run-{1..12}` root named files (5,5,11,5,8,4,8,9,8,8,5,5) | 81 |
| Run subdir globs: `run-4/agents/*.md`=47, `run-5/agents/*`=0 (empty dir, counted explicitly), `run-12/reviews/*.md`=14 | 61 |
| **Total** | **241** |

`3 + 3 + 37 + 56 + 81 + 61 = 241` — **matches the scoped `find` total exactly. Residue = 0.**

Directories themselves are not counted as files anywhere in this identity (by design, per `-type f`);
`run-5/agents/` is the one directory in scope that is empty (0-file contribution, stated explicitly
so its presence isn't silently invisible). Verified separately: 0 symlinks and 0 non-regular/non-dir
entries in the scoped tree; write target `.ocr/index/areas/` existed prior to this write.
`run-13` (30 files) and `run-14` (85 files) exist on disk and were confirmed excluded by the prune,
not merely absent — for the sibling agent that owns them.
