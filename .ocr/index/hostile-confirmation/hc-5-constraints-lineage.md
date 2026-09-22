# HC-5 — Hostile Confirmation: Constraints & Lineage

**Auditor:** HC5-CONSTRAINTS (hostile confirmation lane). **Read-only** (git read-only; only this file written).
**Subject:** the INDEXING/COMPACTION lane lead's work under `.ocr/index/` and `.ocr/utilities/` (session `2026-09-18-fix-debian-13-selinux-apt`, run-14).
**Method:** every claim below was independently re-derived from the filesystem, git, and the live SQLite DB (`?mode=ro`) — not taken from the lead's own self-report, except where explicitly noted as corroboration.
**Note on this document itself:** `MASTER-INDEX.md` was observed to change content between two of my own reads during this audit (it is genuinely live/self-referential, as it claims — its own §8 moved from "05:50Z, 6 agents" to "06:05Z, hostile-confirmation swarm 3/5 landed" while I was working). Facts below are cited against the content as read at the time stated.
**As-of / liveness:** this report is current as of `2026-09-22 06:23:41Z`. The INDEXING/COMPACTION lane lead (background agent `a17eec7f809e44ab3`) is **still running** at that instant (last observed progress: "Reclassifying `fidelity/` header in `README.md`"). Everything below is a snapshot, not a closed book — in particular, the three broken pointers under Constraint 4 should be re-checked before anyone acts on them, since the still-running lead may fix them itself before it finishes.

---

## Constraint 1 — NO deletion (copy-only): **CONFIRMED**

**Tmp scratchpad originals** (`/tmp/claude-1000/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/scratchpad/`): populated, 379 files (birth 2026-09-18 00:27:30, last modified 2026-09-22 00:59:07 — a long-lived session scratchpad, not wiped). Contains all the scripts the centralization manifest (`scratchpad/readme_centralized.txt`, 51 entries) names as sources: `allfuncs.sh`, `address_sol.sh`, `airgap-cut-and-prove.sh`, `airgap_cut.sh`, `gate_dryrun.sh`, etc. — all present under their original flat names.

**Repo scratchpad salvage, verified at copy time** (`/home/tristan/gitters/LME/scratchpad/`, as it existed earlier in this audit): all 18 files named in `.ocr/index/salvage/README.md`'s provenance table were present (`flow-analyst-1.md`, `flow-analyst-2.md`, `req-mapper-1.md`, `req-mapper-2.md`, `round3-diff.txt`/`-meta.json`/`-agent-ids.txt`, `round8-e2e-evidence.md`, `round9-e2e-multihost.md`/`-qemu-profiles.md`/`-qemu-profiles-v2.md`/`-reviewer-ids.txt`, `espack-cell6-validation.md`, `wipe-hardening-validation.md`, `pr-body.md`, `ocr-map-canonical-files.txt`, `ocr-run2-canonical.txt`, `tailnet-readings.log`). The remaining files in that directory at the time (7 scripts + 1 DB backup) matched the README's own "NOT copied (deliberately)" list exactly — nothing unaccounted for.

**Byte-level verification (8/8 exact matches), not just presence:**
```
sha256sum scratchpad/flow-analyst-1.md .ocr/index/salvage/flow-analyst-1.md   → 9b5ac104…  MATCH
sha256sum scratchpad/flow-analyst-2.md .ocr/index/salvage/flow-analyst-2.md   → 50347b27…  MATCH
sha256sum scratchpad/round3-diff.txt   .ocr/index/salvage/round3-diff.txt     → edc4bfe7…  MATCH
sha256sum scratchpad/tailnet-readings.log .ocr/index/salvage/tailnet-readings.log → 92c471a4…  MATCH
sha256sum <tmp>/allfuncs.sh  .ocr/utilities/gate/allfuncs.sh.snapshot         → f91b6f78…  MATCH
sha256sum <tmp>/airgap_cut.sh .ocr/utilities/airgap/airgap_cut.sh            → e0ac6497…  MATCH
sha256sum <tmp>/airgap-cut-and-prove.sh .ocr/utilities/airgap/airgap-cut-and-prove.sh → 5fac4573…  MATCH
sha256sum <tmp>/gate_dryrun.sh .ocr/utilities/gate/gate_dryrun.sh            → fadbd5cc…  MATCH
```
Both legs (salvage → `.ocr/index/salvage/`, centralization → `.ocr/utilities/`) verified copy-only, byte-identical, at the moment of copying.

**Post-lead event — operator relocation, re-verified just now, not a deletion:** `.ocr/index/salvage/README.md` carries a `06:05Z` update (added after the lead's original `05:52Z` authorship) stating the **operator** subsequently relocated the source directory: `scratchpad/` → `.ocr/utilities/scratchpad/`, then `git add`-ed it. I mechanically re-checked this just now:
```
$ ls -d /home/tristan/gitters/LME/scratchpad
ls: cannot access '/home/tristan/gitters/LME/scratchpad': No such file or directory
$ ls -1 /home/tristan/gitters/LME/.ocr/utilities/scratchpad | wc -l
26
```
Confirmed: `scratchpad/` at repo root is gone, and `.ocr/utilities/scratchpad/` holds exactly 26 entries — reconciling exactly against the pre-move inventory (18 salvaged files + 7 not-copied scripts + 1 `ocr.db.bak-20260917T004634Z`). This is a **rename, not a deletion**: nothing is lost — the same 18 artifacts now live in two places, `.ocr/utilities/scratchpad/` (the operator's moved-and-staged original tree) and `.ocr/index/salvage/` (the lead's independently-made copies). The directory's own mtime/ctime corroborate a rename rather than fresh content: mtime `2026-09-19 06:57:09` (last entry added/removed — old, pre-dates this session) vs. ctime `2026-09-22 06:04:45Z` (metadata-only change — the rename), one minute before the README's own `06:05Z` update stamp. The README's claim that the 18 salvage copies are sha256-identical to the operator's moved copy (18/18) is the **lead's own claim**, not independently re-verified by me beyond the 4 salvage-file hashes already checked above; I did not hash all 18 against the moved copy, and the README's claim in any case only covers those 18 — it says nothing about the 7 not-copied scripts or the `.bak` file that make up the other 8 of the 26.
This event post-dates the lead's own salvage work and is attributed to the operator by the lead's own document — it does not implicate the lead in any deletion, and constraint 1 ("no deletion, copy-only") remains **CONFIRMED** for the lead's own actions.

---

## Constraint 2 — NO git-state change by this lane: **CONFIRMED**, with one flagged observation

- `git log --oneline -3` on `fix/debian-13-selinux-apt` (re-checked fresh at the end of the audit): still `d5625ba` on top, unchanged. Reflog confirms zero new commits landed on this branch.
- Exactly one new commit exists anywhere in the repo: `e5e3bed` "snapshot(ocr): board baseline entering run-14 tandem work", on a side branch `ocr/board-pre-run14` (also pushed to `origin`). Fully investigated and **exonerated**:
  - Author: `groenewt <famgroenewoldt@gmail.com>` — the human operator's own git identity, not an anonymous agent commit.
  - Timestamp: `2026-09-21 23:28:01 -0500` = `04:28:01Z` — the whole checkout→commit→checkout-back episode spans **3 seconds** (reflog: 23:28:01 → 23:28:04). This is **before** the MAP lane even resumed the session (`session_resumed` 04:44:55Z) and **~1h32m before** the compaction lead's first observed write. `git merge-base --is-ancestor e5e3bed HEAD` → not an ancestor; it never touched `fix/debian-13-selinux-apt`'s history.
  - Content: `git show --stat e5e3bed` — 65 files changed, exactly the pre-existing staged `.ocr/commands|skills|tools|config` toolkit files (the same set visible as `A` in git status at the start of this conversation). **Zero** `.ocr/index/` or `.ocr/utilities/` content. Commit message confirms intent: *"Base = fix/debian-13-selinux-apt so PR#2's branch stays clean (.ocr only)."*
  - **"The lead committed/pushed nothing" = CONFIRMED.**

- **Observed state drift (staged ≠ committed, but real):** at the start of this audit, `.ocr/index/` and `.ocr/utilities/` were untracked (`??`). By the end, `git status --porcelain` shows them **staged** (`A`/`AM`): 27 of 29 `index/` entries, 78 of 78 `utilities/` entries. Nothing is committed — this is index (staging-area) state only, and `git add` leaves no reflog trace, so it cannot be time-boxed via git history alone. **Mechanical attribution, not self-report:** `.ocr/index/hostile-confirmation/hc-3-sessions-maps.md` — a sibling hostile-confirmation agent's output, written *after* the compaction lead had already finished — is **also staged**, while `hc-1-completeness.md` and `hc-2-progress-loss.md` remain untracked. A staging sweep that catches hc-3 but not hc-1/hc-2 could only have run during the hostile-confirmation phase, after the lead's own work concluded. `MASTER-INDEX.md` §8 (read live, as-of `06:05Z`) independently corroborates this from the lead's own side, attributing the parallel `.ocr/utilities/scratchpad/` duplication to "the operator … reorg … staged for commit → operator's call" — i.e. the lead's own monitoring also observes this as external, not self-caused. **A second, independent mechanical corroboration**, with an actual clock on it this time (unlike the staging-area tell, which has no timestamp of its own): the `.ocr/utilities/scratchpad/` directory's ctime — the metadata-change timestamp a rename bumps without touching mtime — is `2026-09-22 01:04:45.097751345 -0500` = `06:04:45Z`, one minute before the salvage README's own `06:05Z` update stamp that first documents the operator's move. Its mtime (`2026-09-19 06:57:09`, last entry add/remove) is untouched, exactly the signature of a `mv` of a pre-existing directory rather than new content being written into it. Both tells (hc-3/hc-1/hc-2 ordering, and this ctime) independently date the staging/relocation activity to the post-lead, hostile-confirmation window; the hc-3 tell remains the primary evidence since it directly brackets `.ocr/index/`, the location this constraint is actually about.
  **Verdict on this sub-point:** the "must appear as untracked" expectation no longer holds **as of the current instant**, but the change is (a) staging only, no commit; (b) dated to after the lead's own completion via the hc-3/hc-1/hc-2 tell; (c) independently corroborated by the lead's own live document as an operator-side action. Not attributable to the compaction lead. Flagged for the operator as a state fact to be aware of before any future commit sweep.

---

## Constraint 3 — NO writes to the MAP-lane's live run-14 subtrees (outside `_index/`): **CONFIRMED**, with a correction to the stated premise

**The task's stated MAP-lane window ("04:44-05:24") is incomplete — worth flagging so it isn't reused.** That window is the DB phase-transition span only (`session_resumed` 04:44:55Z → `map_completed` 05:24:32Z — the latter verified byte-exact against `map-meta.json`'s own mtime, `2026-09-22 05:24:32.815Z`, and against the live `map_runs` row). **Actual file-writing activity in run-14 continues well past 05:24Z**, e.g. `lanes/design/gap-designs.md` (05:48:24Z), `lanes/address/execution-plan.md` (05:59:21Z, an orchestrator dispatch plan). This wider real window genuinely **overlaps** the compaction lead's own writing window (~05:31Z–06:00Z, established from its own authored, non-copied files in `.ocr/index/areas/`).

Because the overlap is real and the lead's own `INDEX.md` explicitly says "the MAP lane is running in tandem" (its §6 Archive Decision cites this as the reason it moved zero files), **mtime alone cannot discriminate who wrote what** — I do not present timing as exoneration. Two things do carry the finding:

1. **Content.** `map.md` and `lanes/address/execution-plan.md` were read in full/excerpt: `map.md` is a self-consistent MAP-lane artifact (Executive Summary, Section Dependencies, "File Index 10/10", a completeness self-check against `_context/canonical-files.txt`); `execution-plan.md` is an orchestrator/subagent-allocation plan (host resource envelope, model/profile assignment). Neither contains any indexing/compaction vocabulary or self-reference. No content evidence of cross-contamination found anywhere sampled.
2. **Contemporaneous documentary evidence.** The lead's own `run-14/_index/INDEX.md`, itself saved at `05:41:09Z`, states: *"`run-14/_context/`, `run-14/lanes/`, and the still-pending `run-14/analysts/` + `run-14/map.md` are MAP-lane-owned and actively growing … do not cite the counts for that MAP-lane subtree as final."* `map.md` did not exist yet at that moment — its actual mtime is `05:45:12Z`, four minutes later. The lead's own live notes describe `map.md` as not-yet-existing shortly before it appeared — consistent with watching the MAP lane produce it, not producing it.

**Operator note:** any future audit that keys "the MAP-lane window" to `04:44–05:24` will misclassify `lanes/design/*`, `lanes/deploy/*`, and `lanes/address/execution-plan.md` as suspect. The real window extends to at least `05:59:21Z`.

---

## Constraint 4 — Lineage intact: **VIOLATION on 4(a)**; 4(b) and 4(c) confirmed for the named set

### 4(a) — `run-14/_index/INDEX.md` upward pointer: **BROKEN (mechanically verified)**

`_index/` sits **six** directory levels below `.ocr/` (`sessions/2026-09-18-…/map/runs/run-14/_index/`). The pointer as written uses only **five** `../`:

```
$ [ -f ".../run-14/_index/../../../../../index/MASTER-INDEX.md" ] && echo RESOLVES || echo "DOES NOT RESOLVE"
DOES NOT RESOLVE
$ realpath -m ".../run-14/_index/../../../../../index/MASTER-INDEX.md"
/home/tristan/gitters/LME/.ocr/sessions/index/MASTER-INDEX.md      ← does not exist
$ realpath -m ".../run-14/_index/../../../../../../index/MASTER-INDEX.md"   (6 dots)
/home/tristan/gitters/LME/.ocr/index/MASTER-INDEX.md               ← the real file; RESOLVES
```

Same off-by-one, **three occurrences**, all missing exactly one `../`:
- `run-14/_index/INDEX.md:5` — `` ../../../../../index/MASTER-INDEX.md `` (the file's central "SUPERSEDED — by inclusion" pointer)
- `run-14/_index/state-validation.md:27` — `` ../../../../../index/PROGRESS-LOSS.md `` (also broken, same defect)
- `run-14/_index/state-validation.md:28` — `` ../../../../../index/MASTER-INDEX.md ``

**Fix:** add one `../` to each (six total). One token, three call sites. This is on-theme: MASTER-INDEX.md's own stated purpose is to make a fragmented, illegible context layer navigable again, and this is the one pointer a reader standing in `run-14/_index/` has to reach it.

### 4(b) — `.ocr/index/MASTER-INDEX.md` cross-references: **CONFIRMED** for the named set

Mechanically resolved from `.ocr/index/`: `./PROGRESS-LOSS.md`, `../utilities/README.md`, `areas/top-level.md`, `areas/sessions-16-21.md`, `areas/session-18-runs-1-12.md`, `areas/session-18-runs-13-14.md`, `areas/progress-loss-evidence.md`, `salvage/README.md` — **all exist at the target path.**

**Additionally flagged** (outside the task's named set, found during a full grep sweep of relative-path-shaped references): two other mentions do **not** resolve as literal paths relative to `.ocr/index/` — `run-14/_index/INDEX.md` (§4.4 heading, twice: "supersedes `run-14/_index/INDEX.md`") and `run-14/_archive/README.md` (§7: "the `_archive/` area exists (`run-14/_archive/README.md`)"). Both would resolve to non-existent `.ocr/index/run-14/...` if read as relative links. Read in context, neither is phrased as a "see X" navigational pointer the way the four confirmed links are — they read as prose naming a session-relative location. I judge these **not** dangling links, just ambiguous path notation, and flag them as a minor clarity nit rather than a lineage violation.

### 4(c) — `.ocr/index/PROGRESS-LOSS.md` references: **CONFIRMED**

`areas/progress-loss-evidence.md`, `areas/session-18-runs-1-12.md`, `areas/sessions-16-21.md` all resolve. (One further prose mention of `run-14/_index/state-validation.md` in the appendix has the same non-navigational character noted above.)

---

## Constraint 5 — State doc matches reality: **CONFIRMED**

Live check performed:
```
$ ocr state show
No active session found.
```
Direct read-only SQLite query confirms why: the session **closed** since the doc was written.
```
sessions: 2026-09-18-fix-debian-13-selinux-apt | closed | map | complete | 6 | 10 | 14 | updated_at 2026-09-22 06:06:53
map_runs: run 13 → 0 | 0 | parser      | parsed_at 2026-09-22 00:21:33
map_runs: run 14 → 10 | 3 | orchestrator | parsed_at 2026-09-22 05:24:32
```
This closure (`updated_at` 06:06:53Z) happened **after** the compaction lead's last observed write (`MASTER-INDEX.md`, 06:00:21Z) — consistent with its repeated claim of running zero state transitions itself.

`state-validation.md` v3 is explicitly built to survive exactly this transition: its header labels itself "A TRAJECTORY, NOT A POINT CLAIM," stamps the one instantaneous-status line as "as-of `05:32:56Z`," and twice (lines 6, 33) instructs the reader not to cite that line without re-running `ocr state show` — which I did. Its **durable facts** (§2) are verified **byte-exact** against the live DB right now: run-14's row (`10/3/orchestrator/05:24:32Z`) and run-13's row (`0/0/parser/00:21:33`) match the document's claims character-for-character.

**One nuance for the record, not a downgrade:** line 18 ("active · phase complete (6) · round 10 · map_run 14") is now stale — the session is closed, not active. But it is explicitly labeled instantaneous/as-of, and the document tells the reader twice not to trust it without re-checking. It does **not** wrongly assert a stale point-status as current fact; it does exactly what it says it does. Confirmed as designed.

---

## Lead verdict

**4 of 5 constraints fully honored** (1 copy-only, 2 no-git-mutation, 3 no-live-subtree-writes, 5 state-doc-honesty). Every byte-level check performed (8 sha256 pairs) matched exactly; every DB fact cross-checked matched exactly; no content evidence of the lead writing into MAP-lane-owned run-14 subtrees was found anywhere sampled.

**Constraint 4 fails on its (a) sub-part: lineage is not intact.** The upward pointer from `run-14/_index/` to the master index — the single navigational link the whole compaction pass exists to provide — is broken in all three places it appears, by an identical one-`../`-short mistake. This does not call into question the accuracy or good faith of the compaction work itself (which independently checks out very well: exact hashes, exact DB facts, honest self-flagging of its own limitations throughout, and a live document that keeps correcting itself as new information arrives). It is a mechanical, one-token, three-occurrence defect that should be fixed before this index is treated as reliably navigable:
- `run-14/_index/INDEX.md:5`
- `run-14/_index/state-validation.md:27`
- `run-14/_index/state-validation.md:28`
(each: `../../../../../index/` → `../../../../../../index/`)

**Re-check before acting:** the lead (background agent `a17eec7f809e44ab3`) was still running as of this report's `06:23:41Z` as-of stamp (last seen progress: "Reclassifying `fidelity/` header in `README.md`"). It is possible it fixes these three pointers itself before finishing. Re-run the three `[ -f ]` checks above before treating this as an outstanding fix-item.

**Also flagged for operator attention (not a lead violation):**
1. `.ocr/index/` and `.ocr/utilities/` are currently `git add`-staged rather than untracked — real, verified, and dated to the hostile-confirmation phase (after the lead's own work concluded) by two independent mechanical tells: the hc-3/hc-1/hc-2 staging-order tell, and the `.ocr/utilities/scratchpad/` directory's ctime — `06:04:45Z`, itself the moment of the relocation (a rename bumps ctime without touching mtime), one minute before the salvage README's own `06:05Z` update stamp that first documents that move. Nothing is committed; `HEAD` on `fix/debian-13-selinux-apt` is unchanged at `d5625ba`.
2. The repo-root `scratchpad/` directory (source of the salvage copies checked under Constraint 1) no longer exists — re-verified moments ago with `ls -d`. Per the salvage README's own `06:05Z` update, the **operator** relocated it to `.ocr/utilities/scratchpad/` (now staged, 26 files, reconciling exactly with the pre-move inventory) and this happened *after* the lead's salvage copy was already made. This is a rename, not a deletion — the content survives in two places — but it means "the originals" for the salvage leg of Constraint 1 are no longer at the path this task named; they are at `.ocr/utilities/scratchpad/` instead.
