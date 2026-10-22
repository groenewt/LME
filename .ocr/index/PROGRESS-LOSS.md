# Why it looks like we lost so much progress — and what we actually lost

**As-of `2026-09-22 06:05Z`** · INDEXING/COMPACTION lane lead · READ-ONLY, no git/state mutation · **hostile-verified** — HC-2 confirmed the central thesis + all 7 headline claims; precision corrections folded inline and cited. Companion index: **`./MASTER-INDEX.md`**. Evidence base and full verdict derivation: **Appendix**, below.

---

## The short answer

**Two things are true at once, and holding only one of them is why the situation feels worse than it is:**

1. **The code is safe — provably, and at the remote.** The branch is 51 commits ahead of `main`, **zero reverts, zero divergence**, and `git rev-list --left-right --count origin/<branch>...HEAD = 0 0` — local `HEAD` *is* `origin` (`d5625ba`, pushed 2026-09-21). Nothing that was engineered has been lost from the durable record. (This also corrects a standing belief: several MEMORY.md notes say waves 6/7/10/12 were "NOT pushed" — true when written, but a push has since landed all 51 on origin.)

2. **What shattered is the *context* layer — the story of the work, not the work.** It is split across 5 database sessions, half the review transcripts are invisible in the dashboard, ~1200 files of working context evaporate with the scratchpad, and the tooling gets re-derived every cycle. You cannot *see* the progress even though the committed code embodies it. That is a real problem — but it is a **legibility** problem, not a **code-loss** problem, and it has a small number of nameable root causes.

**So "we lost so much progress" is mostly the felt experience of an illegible, fragmented context layer sitting on top of intact, remote-backed code — plus a bounded, precisely-countable set of genuine evidence losses.** The fix is therefore *structural* (a durable index, centralized tooling, three root-cause fixes), not a code-recovery effort.

---

## Part A — Three alarming signals that are NOT progress loss

These are the signals that make it *look* catastrophic. Each is an artifact, and the evidence says so.

### A1. The map "collapse" `137 → 24 → … → 1 → 6 → 0 → 10` is a tooling **mode-shift**, not lost maps
The `map_runs.file_count` column is **not** on-disk files — it is `Σ map-meta.json sections[].files[].file_path`, a *map-content* metric (verified exact across all 12 runs; on-disk run-6 = 4 files, DB = 137). Runs **7, 11, 12** are **delta-anchored maps by design**: run-7's `map.md` header says verbatim "cycle-continuation map, not a re-catalog" (runs 11/12 convey the same substance in different words — HC-2 precision) — they carry the full topology forward *by reference* and enumerate only the files that round touched (run-7 = 24 touched files, run-11/12 = the wave-11/12 commit deltas). Runs **8/9/10** are identical only in *structural payload* (meta + canonical-files, because no commits landed between them); their prose differs 90-410 lines with distinct HEADs. **The only genuinely degenerate run is run-13** — a `source=parser` back-fill (the sole non-`orchestrator` row) that wrote partial section rows but zero file rows and never updated counters (a 3-way on-disk/`map_sections`/`map_runs` mismatch). And run-14 already recovered to a real orchestrator map (10/3) at 05:24:32Z. **Reading the curve as "the map collapsed to zero" overstates the loss by conflating a metric-mode change with a data loss.**

### A2. The "phantom run-14 / counter ahead of the board" resolved itself *during this compaction*
At 05:10Z there was no run-14 `map_runs` row and the session read "closed" then "synthesis." By 05:24:32Z the MAP lane ran `map_completed` and a real run-14 row exists (orchestrator, 10/3). This was a **live-session-in-flight artifact**, not a lost run. (It is why `run-14/_index/state-validation.md` had to be rewritten twice — the target was moving, not broken.)

### A3. "No output recorded" / "flow-probe crashed" is a **dashboard wiring gap**, not vanished work
The dashboard renders `command_executions.output` and falls back to the literal `"No output recorded."` when it is null. Task sub-agents journaled via `ocr session start-instance` only ever write `notes` (via `--note`); `output` is populated by a different code path they never take (`PATCHES-no-output-recorded.md`). So the card looks empty while **the content exists**: 98 reviewer `.md` files (≈1.5 MB — 1.49 MB measured, HC-2) survive on disk across all three sessions. And the "crashes" didn't crash — all **15 null-exit-code rows** (9 flow-analyst + 6 requirements-mapper, feeding map run-14) **finished normally with `notes` populated**; "finished with no recorded exit code" is an instrumentation gap, not a crash. Zero of the 30 `events/*.jsonl` files are empty or corrupt.

---

## Part B — What we ACTUALLY lost (bounded, named, evidence-cited)

Naming these precisely is the point — this is where real remediation applies.

| # | Real loss | Magnitude (cited) | Root cause | Durable? |
|---|-----------|-------------------|------------|----------|
| B1 | **DB-unrecoverable reviewer *rows*** (instrumentation, **not content**) | **26 / 101** instance rows have *both* `output` and `notes` null; **81 / 101** have no per-instance `events/<id>.jsonl` — **but HC-2 proved all 26 map 1:1 to a real on-disk `reviews/*.md`: content-loss = 0/26** | dashboard `output` wiring gap; FIX 3 (durable upstream fix) not done | DB rows permanently null; **review content intact on disk** |
| B2 | **Session splintering** | one topic across **5 DB sessions** / 3 dirs; `-21` is a *different model's* map mislanded here | **root-caused:** `SESSION_DIR="${DATE}-${BRANCH}"` is date-anchored, not branch-anchored (`map-workflow.md:31-39`, verbatim-confirmed HC-2) — a same-branch run on a later date forks a new session | fixable at that line |
| B3 | **Was untracked *and un-ignored* repo scratchpad — operator-relocated mid-pass** | `/home/tristan/gitters/LME/scratchpad/` held **26 files ~1.3 MB** = **18 real map/review artifacts** (`flow-analyst-*`, `req-mapper-*`, `round3/8/9-*` evidence, `pr-body.md`, validations) + 7 already-centralized scripts + 1 MB `ocr.db.bak`; the 18 had **no git copy** | never added, never gitignored — pure oversight | **Downgraded** this pass — mostly handled; see the B3 note below |
| B4 | **Out-of-repo stopgap patch** | `PATCHES.md` FIX 1 lives in the global npm package (`~/.nvm/.../@open-code-review/cli/dist/dashboard/server.js`) | applied outside any repo; wiped by next `ocr` reinstall | instructions durable (staged); patch not |
| B5 | **Scratchpad evaporation** | `/tmp` session scratchpad = **1238 files** (56% quadlet/manifest test fixtures, but also 48 `.md`, 45 `.sh`, real tooling) | never in the repo; evaporates at session end | gone at session end unless centralized |
| B6 | **Iteration churn** | **10+** re-derivation pairs (`funcs_old/new`, `run-trixie-cluster-a2b2` vs `-run2`, `serve_v2.go`, …) | tooling re-authored per cycle instead of reused | the churn is *why* B5 is so large |

**Nuance on B1 — reconciliation now CLOSED (HC-2):** the 26 was previously only an upper bound (not reconciled row-by-row). HC-2 completed the join: all 26 `output`+`notes`-null rows map **1:1** (proven bijection via an `orchestration_events`-round join, no duplicate personas) to real, substantive on-disk `reviews/*.md`. **Content-loss is 0/26** — the loss is *DB-instrumentation only*, not review content, so the true loss is *smaller* than the "permanent" label reads; that label holds only in the narrow DB-row sense. (Tangential, outside the 26: rounds 6/7/10 have **zero** DB rows at all despite having on-disk files — a further DB-completeness gap, still not a content loss.)

**Downgrade on B3 — the scratchpad rescue is mostly done this pass:** (a) this lane mirrored the 18 artifacts → `index/salvage/` (sha256-verified); (b) the **operator then moved the whole dir → `.ocr/utilities/scratchpad/` and `git add`-ed it**, so it now **survives `git clean -fd`** (staged, not untracked). Residual: still **uncommitted** (not on origin / not in history) → it dies only to `git reset --hard`.

**One more durability nuance, not a loss yet:** the **staged-but-uncommitted `.ocr/` toolkit** (the entire OCR review tooling + this index area + — after the operator's mid-pass staging — all of `.ocr/utilities/`) is `git add`-ed but **not committed**: it survives a crash and `git clean`, but is *not* on `origin` and *not* in the 51-commit history until committed. (The exact staged-file count **drifts** as the operator stages more — HC-2 watched it move across ~13 min — so treat any specific "N staged" figure as timestamped, not current.)

---

## Part C — Why it *feels* like catastrophic loss (the real operator experience)

The code being safe does not make the feeling wrong. Every legibility surface is broken at once: the **history is fragmented** (B2) so there is no single "where are we" view; the **dashboard shows blanks** (A3/B1) so the review work looks undone; the **richest working context evaporates** (B5) so each session starts cold; and the **tooling keeps getting rebuilt** (B6) so effort visibly repeats. That combination reads as "we lost everything" even though what was lost is a bounded evidence slice and the code is intact and pushed. **This index exists to make the intact work legible again.**

---

## Part D — Structural remediation (what actually fixes it)

Ordered by leverage. None of these is a code recovery, because the code does not need recovering.

1. **Commit the durable artifacts that are only staged/untracked** — the 66 staged `.ocr` files (as-of `06:05Z`; a snapshot, per the drift caveat above) + this `.ocr/index/` + `.ocr/utilities/`. They are the legibility layer; keep them out of the ephemeral zone. (Orchestrator's call; this lane runs no git-state command.)
2. **Finish the B3 scratchpad rescue.** (Largely handled already: the operator relocated `scratchpad/` → `.ocr/utilities/scratchpad/` and staged it so it survives `git clean`, and this lane mirrored the 18 curated artifacts → `index/salvage/`.) Remaining, in order: **(a) commit it** — it rides along with step 1, still not on origin; **(b) de-duplicate** the raw dump against the curated `utilities/` split + `index/salvage/` (26 = 7 script dupes + 18 salvage dupes + 1 net-new `ocr.db.bak`); **(c) decide** whether the 1 MB `ocr.db.bak` belongs in history; **(d) add** working dirs like `scratchpad/` to `.gitignore`-or-track, so real work is never again untracked-and-unignored.
3. **Fix B2 at the line** — make `SESSION_DIR` branch-anchored (`map-workflow.md:31-39`) so same-topic runs rejoin one session instead of splintering.
4. **Land FIX 3** — wire reviewer sub-agent output to `command_executions.output` durably, so future review transcripts stop being invisible (and stop depending on a global-npm stopgap, B4).
5. **Centralize scratchpad tooling every cycle** — the `.ocr/utilities/` deliverable; the churn (B6) and evaporation (B5) are why this must be routine, not one-off.

---

## Appendix — verdict lineage & evidence base

**Evidence base** (every figure above is cited in these; this file is the synthesis, not the raw evidence): `areas/progress-loss-evidence.md` (git/DB/scratchpad, advisor-reviewed twice) · `areas/session-18-runs-1-12.md` (map-mode analysis) · `areas/sessions-16-21.md` (session-drift root cause).

**Hypothesis under test:** "durable code safe; loss = gitignored/ephemeral context." **Evidence verdict: REFINED** — code safe *and remote-backed*; loss is concentrated in the context layer as hypothesized, but two surfaces sit *outside* the gitignored/ephemeral binary (B3 unignored working tree, B4 out-of-repo patch), and inside the gitignored layer the loss is a bounded 26-row/81-file gap, not a wholesale wipe. Full derivation: `areas/progress-loss-evidence.md` §Hypothesis Verdict.
