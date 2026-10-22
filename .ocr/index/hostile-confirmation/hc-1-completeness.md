# HC1-COMPLETENESS — hostile confirmation audit of `.ocr` index completeness

**Auditor:** HC1-COMPLETENESS. Read-only on all of `.ocr` except this file. No deletes, no git-state
changes, no live mutation. All evidence below is raw command output, independently re-run, not copied
from the documents under audit.

## VERDICT: **NO** — complete-`.ocr` coverage does not hold, even though every raw arithmetic identity
closes (residue 0) at each instant it is measured.

Two different questions get conflated by the documents under audit, and they have different answers:

- **Does `top-level + session-16 + session-21 + session-18 = find .ocr -type f` balance?** Yes, at every
  instant sampled — because that identity is a `find`-count tautology (four disjoint path-scoped counts
  summed against the union of those same paths). It cannot fail to close; it closes by construction, not
  because coverage was verified.
- **Is every file under `.ocr` actually described by some area file's inventory?** **No.** A live,
  named, growing set of files sits under `.ocr/index/` and (newly, discovered mid-audit)
  `.ocr/utilities/scratchpad/` that no area file's stated scope reaches. See Claim 4.

**A second, compounding problem: the tree is live across at least three independent subtrees
simultaneously** (`sessions/2026-09-18/map/runs/run-14/lanes/**`, `utilities/` itself, and
`index/hostile-confirmation/` as sibling hostile-auditors land their own files), not the single
"one active session" liveness the indexed documents describe. Every number below is stamped with the
UTC instant it was measured; none of them are durable facts, including the ones in this report.

**Measurement basis:** `find /home/tristan/gitters/LME/.ocr ! -type f ! -type d | wc -l` → **0**. No
symlinks/sockets/other node types exist under `.ocr`; `-type f` is the whole non-directory universe, so
every count in this report and in the documents under audit is comparing like with like.

**Live-document caveat:** `MASTER-INDEX.md` was rewritten at least twice *during* this audit (ctime
advanced `1790056273 → 1790057132 → 1790057199` across my checks). Quotations of it below are each
tagged with which read they came from; none should be read as "the document says," only "the document
said, as of that ctime." Its most recent revision (ctime `1790057199`) is discussed in §4.

---

## Claim-by-claim

| # | Claim | Verdict | Evidence |
|---|---|---|---|
| 1 | `find .ocr -type f`=596 closes as top-level 183 + s16 38 + s21 18 + s18 357, residue 0 | **CONFIRMED at t0, then DRIFTED** | See §1 |
| 2 | session-18 357 = runs1-12+root 241 + run-13 30 + run-14 86 | **CONFIRMED at t1, then DRIFTED** | See §2 |
| 3 | Each of the 5 area files states its own reconciliation, matching disk | **2 CONFIRM / 2 DRIFTED / 1 REFUTED** | See §3 |
| 4 | Residue hunt: any file covered by no area file? | **REFUTE ("no orphans") — orphans found and named** | See §4 |
| 5 | utilities: 51 non-README on disk; README's 73=51+5+17; bijection | **CONFIRMED (as stated) — but superseded live** | See §5 |
| 6 | salvage: 18 artifacts + README = 19 | **CONFIRMED** | See §6 |

---

## §1. Claim 1 — the top-level identity

First command run this session, before touching anything else:

```
$ find /home/tristan/gitters/LME/.ocr -type f | wc -l
596
```

Independently re-deriving the four buckets in the same window:

```
top-level (non-sessions): 183
sessions/2026-09-16-...:   38
sessions/2026-09-21-...:   18
sessions/2026-09-18-...:  357
183+38+18+357 = 596   ✓ matches, residue 0
```

**This is an exact, independently-reproduced match of the claim as literally stated.** CONFIRMED at
`t0`.

**Then it drifted, twice, while this audit was running**, entirely from live writers this audit did not
touch:

| instant (UTC) | total | top-level | s16 | s21 | s18 | still closes? |
|---|--:|--:|--:|--:|--:|:--:|
| t0 (start) | 596 | 183 | 38 | 18 | 357 | yes |
| 06:01:41Z | 597 | 183 | 38 | 18 | 358 | yes |
| 06:05:48Z | 624 | 210 | 38 | 18 | 358 | yes |
| 06:06:33Z (final) | 624 | 210 | 38 | 18 | 358 | yes |

The identity **re-closes at every instant** (that's structural, see verdict above) but the **596 the
claim cites was already stale within minutes**, and by audit end the true count was **624**, not 596 —
a 28-file gap, none of it residue, all of it attributable to named live writers (§4, §5).

## §2. Claim 2 — session-18's internal breakdown

```
$ find .../run-13 -type f | wc -l   → 30
$ find .../run-14 -type f | wc -l   → 86   (at first measurement, ~05:58Z)
$ find session-18 -type f -not -path '*run-13*' -not -path '*run-14*' | wc -l   → 241
241 + 30 + 86 = 357   ✓ matches disk session-18 total exactly at that instant
```

**CONFIRMED, exact, at the instant measured.** But `run-14` was watched moving *during this audit*:

```
run-14 count:  85 (area file / MASTER-INDEX's stated number)
            →  86 (my first direct measurement, ~05:58Z)
            →  87 (my second direct measurement, ~06:01Z; new file confirmed via
                    /usr/bin/find -mmin -10 → run-14/lanes/address/execution-plan.md,
                    mtime 2026-09-22 00:59:21 local — landed inside this audit's own runtime)
```

`lanes/address/` did not exist as a bucket in any prior document — it is not one of the nine buckets
`session-18-runs-13-14.md` enumerates for run-14 (map.md, map-meta.json, `_context/`, `analysts/`,
`lanes/design/`, `lanes/deploy/`, `_index/`, `promoted/`, `_archive/`). A tenth, undocumented bucket
appeared live.

**Unreconciled cross-references inside `MASTER-INDEX.md` itself (softer than an arithmetic error, still
real):** at my first read, §1 (stamped `as-of 05:33Z`), §2/§4.4 (stamped `@05:26Z`/`05:26:09Z`), and §8
(stamped `as-of 05:50Z`) all state run-14 = **85**, but §8's session-18 grand total of **357** only
balances if run-14=86 (357 − 241 − 30 = 86). Each section is internally honest about its own as-of stamp,
and 85→86→87 is exactly the live drift this report independently documents (§2 above) — so the most
likely explanation is that §8 silently absorbed one instant of drift that §1/§2/§4.4 did not, not a
hand-arithmetic slip. **But no section says so**: nothing in the document flags that §8's total requires
a different run-14 count than the three sections that state one explicitly, so a reader citing "run-14 is
85 files" (§2's own table, §4.4's own prose) is citing a number the document's own §8 close-out
contradicts, with no cross-reference connecting the two. (Update, later read: `MASTER-INDEX.md`'s current
revision has since corrected §1's table to 87 — see §4 — but §4.4's prose beneath its own updated header
still reads "run-14 (85)" with the old bucket list. The unreconciled-reference problem persists; it moved,
it did not close.)

## §3. Claim 3 — each area file's own reconciliation vs. disk

Re-ran each area file's cited `find` scope independently.

| area file | stated | disk (current) | verdict |
|---|---|---|---|
| `top-level.md` | 117 (85 maxdepth-3 + 32 depth-4), snapshot 05:27:43–05:28:06Z | maxdepth-3 command re-run fresh = **148**; depth-4 reviewers+personas unchanged = 32; **+3 more depth-4+ files now exist that fit neither bucket** (`utilities/probe/graph-seal/{kb,probe,seal}.sh`, a nested subdir that didn't exist at snapshot time); full non-sessions = **183→210** across this audit | **DRIFTED.** File is explicit about being a timestamped snapshot and explicitly *excludes* `.ocr/index/` from its own scope (except the one `MASTER-INDEX.md` file it caught mid-scan) — it is honest, not fabricated, but its number does not match current disk, entirely from `utilities/` (11→52→78) and `index/` (1→26+ counted files) growing after its snapshot. |
| `sessions-16-21.md` | 38 + 18, residue 0 | `find sessions/2026-09-16 -type f \| wc -l` = **38**; `find sessions/2026-09-21 -type f \| wc -l` = **18** | **CONFIRMED**, exact, stable — both sessions are closed/historical, no drift observed. |
| `session-18-runs-1-12.md` | 241, residue 0 | `find session-18 -type f -not -path '*run-13*' -not -path '*run-14*'` = **241** | **CONFIRMED**, exact, stable across the entire audit — this bucket does not move. |
| `session-18-runs-13-14.md` | 30 + 85 = 115, residue 0, "per-bucket closure" | 30 + 86→87 = **116→117** (moving) | **DRIFTED**, and more sharply than a simple count miss: the file's own explicit live-subtree caveat names *five* buckets that "may already differ" (`map.md`, `map-meta.json`, `_context/**`, `analysts/**`, `lanes/design/**`) — but the actual drift happened in `lanes/deploy/**` (stated 2, disk 3) and in a wholly new `lanes/address/**` bucket the file never enumerated at all. The file's own risk list did not cover where the drift actually occurred. |
| `progress-loss-evidence.md` | *(claimed by task prompt to state a reconciliation like the other 4)* | Targeted search: `grep -n -i "residue\|find \.ocr\|reconcil.*identity\|= find count" progress-loss-evidence.md` → **one hit**, and it is not a completeness identity: *"`find .ocr/sessions -path '*/reviews/*.md'` → 98 files, 1.6 MB"*, an unrelated content-survival spot-check the file itself says *"was not matched row-by-row... not done here."* Its actual section headers are GIT / MAP QUALITY CURVE / VANISHED AGENT OUTPUT / SCRATCHPAD EVAPORATION SCOPE / ITERATION CHURN / HYPOTHESIS VERDICT — narrative evidence, not a file-inventory bucket, and it does not appear as a row in `MASTER-INDEX.md` §1's 6-row area table either. | **REFUTED.** The premise that this file "states its own reconciliation (listed+glob=total, residue 0)" is false on its face — it never makes that claim, about anything. |

Net: of the 5 area files, only **2 of 5** currently match disk (and are stable). 2 of 5 were accurate at
their own snapshot instant but are now stale. 1 of 5 never made the claim being audited in the first
place.

## §4. Claim 4 — the residue hunt (the real attack)

Built the union of every area file's own **literally stated** find-scope (not an assumption — the exact
paths each file's reconciliation section names), then diffed against a full `find .ocr -type f`:

```
full set:     597 files (at diff time)
covered set:  572 files  (sessions/2026-09-16/** ∪ sessions/2026-09-21/** ∪
                           sessions/2026-09-18/** [root+rounds+acl-snapshots+runs1-12+run-13+run-14] ∪
                           commands/** ∪ skills/** ∪ tools/** ∪ data/** ∪ utilities/** ∪ utility/** ∪
                           6 loose top-level files ∪ index/MASTER-INDEX.md)
orphans:       25 files — ALL under .ocr/index/, none of them MASTER-INDEX.md:
   19  index/salvage/*
    5  index/areas/*.md
    1  index/PROGRESS-LOSS.md
```

Severity split (these are not the same finding):

- **`index/salvage/` (19 files) — was a hard orphan at every close-out instant this audit checked; a
  later edit, made *during* this audit, has since acknowledged it.**
  ```
  $ grep -rn "index/salvage\|salvage/README\|salvage/\*" .ocr/index/*.md .ocr/index/areas/*.md
  (zero matches — against the MASTER-INDEX.md revision current at the time this check was run)
  ```
  At that read, no index document — not `MASTER-INDEX.md`, not any of the 5 area files — mentioned this
  directory by path or name. (`MASTER-INDEX.md` used the word "salvage" twice at that revision, both as
  prose about *findings* worth salvaging, e.g. "Unique salvage not in -18's `requirements.md`" — never as
  a reference to the directory.) Ctime evidence places `salvage/README.md` landing (ctime `1790056523`)
  **after** that revision's own §8 "close-out reconciliation... all 6 swarm agents complete... residue 0"
  claim was last edited (file mtime `1790056273` at that read) — so that specific close-out claim was
  already incomplete at the moment it asserted completeness, not just later superseded.
  **Re-checked against the current revision** (ctime `1790057199`, per the live-document caveat above):
  `MASTER-INDEX.md` §8 now explicitly names `index/salvage/` ("18 research artifacts rescued... into
  `index/salvage/`... See `salvage/README.md`") and now names the hostile-confirmation swarm too. **This
  specific orphan-invisibility finding is resolved in the current revision** — recorded here as "was
  orphaned through every close-out this audit observed until one edit made during the audit itself,"
  which is a real finding about the document's process (completeness claims preceded actual completeness,
  repeatedly) even though the disk-vs-text mismatch no longer holds for salvage specifically.

- **New, current finding found while re-checking the above: `MASTER-INDEX.md`'s latest revision makes a
  "frozen" claim that is false at the moment it was written.** Lines 25 and 113 of the current revision
  (ctime `1790057199`) state *"every other component is frozen"* / *"Every non-index component is
  frozen"* — i.e. everything outside `.ocr/index/` has stopped changing, and the document's own
  projected final total is `597 + N_hc` (room only for `.ocr/index/` to keep growing). But
  `.ocr/utilities/scratchpad/` — a new subdirectory, **not under `.ocr/index/`** — has ctime
  `1790057085`, **114 seconds before** that "frozen" text's own ctime, and independently measured disk
  shows `utilities/` grew from 52 to 78 files (51→77 non-`README.md`) inside this audit's window (see
  §5). The "frozen" claim and the observed growth are not just close in time, the growth *precedes* the
  claim — the document asserted a freeze on a component that had already moved. `utilities/README.md`'s
  own reconciliation table (§5) was not updated to include this directory either.

- **`index/areas/*.md` (5) + `index/PROGRESS-LOSS.md` (1) — soft orphan, uncounted by design.**
  These are referenced and linked by `MASTER-INDEX.md` §4 and §6 as its own detail leaves/companion
  doc, so a human reader would find them — but no document assigns them to a file-count bucket the way
  `top-level.md` does for `commands/`, `skills/`, etc. `top-level.md` explicitly disclaims them
  ("self-referential, not a subject of this inventory"). Understandable — a document that indexes
  itself is a regress problem — but it means the task's premise ("each area file's coverage, unioned,
  equals the whole tree") is false by construction, not by oversight, for this slice.

**A second, independent orphan pocket appeared live, mid-audit, in a completely different part of the
tree:** `.ocr/utilities/scratchpad/` — a new subdirectory with **26 files** — was not present at this
audit's start and is **not** in `utilities/README.md`'s own reconciliation table (still reads
`N_centralized = 51`, `73 = 51+5+17`, unchanged text, at the time this was discovered). This means the
orphan count is not a fixed 25; it grew by 26 more (in a different subsystem, under a different
document's stated authority) within the ~15 minutes of this audit. See §5.

**And this audit's own output is a third instance of the same failure mode**: the moment this file is
written, `.ocr/index/hostile-confirmation/hc-1-completeness.md` becomes one more file under `.ocr/index/`
that no area file's scope covers (a sibling, `hc-3-sessions-maps.md`, already landed in that same
directory during this audit, confirmed via direct `ls`). An audit that finds the index doesn't cover its
own outputs should say so about itself: **it doesn't, and this file is proof.**

## §5. Claim 5 — utilities: 51 / 73 / bijection

```
$ find .ocr/utilities -type f ! -name README.md | wc -l
51
```
**Matches exactly** at the instant checked. `utilities/README.md`'s reconciliation text:
`N_found=73`, `N_centralized=51`, `N_pointered=5`, `N_throwaway=17`, `51+5+17=73` — arithmetic checks out
as written.

**Bijection spot-check** (extracted every backtick-quoted `dir/file.ext` token from the README's tables,
diffed against the 51 on-disk files):
- Disk → README direction (does every disk file have a README row?): **0 misses.** Clean.
- README → disk direction (does every README-mentioned path exist?): 7 raw misses, all explained, none a
  real defect:
  - `graph-seal/{kb,probe,seal}.sh` — these are the README's *origin*-column (SCRATCHPAD-A-relative)
    spellings; the real files are at `probe/graph-seal/{kb,probe,seal}.sh`, which **are** on disk and
    **are** in the README's `file` column. Extraction artifact of my own regex, not a document defect.
  - `ma-es/sdiff.py` — listed only in the THROWAWAY table (never copied by design). Correctly absent.
  - `.ocr/tools/populate_agent_row.py`, `scripts/wipe_lme.sh`, `testing/e2e/deploy_gate.sh` — POINTER
    rows, explicitly "do NOT fork into `.ocr/utilities/`." Correctly absent.

**Claim 5 as literally stated: CONFIRMED**, cleanly, with a genuine (not hand-waved) bijection check.

**But — discovered live, during this same audit, ~10 minutes after the above check** — `utilities/`
grew from 52 files (51 + README) to **78** (77 + README). The entire delta is one new subdirectory,
`utilities/scratchpad/` (26 files), absent from `README.md`'s reconciliation table, which still asserts
`51/73` unchanged. This is the exact same failure pattern as §4: a document's own "complete, residue 0"
claim was true when written and is no longer true, and the growth landed in a bucket the document's own
table does not name. Not re-audited in detail (out of scope for claim 5's literal ask, and this tree
will not hold still long enough to matter) — flagged as a live finding, not chased to ground.

## §6. Claim 6 — salvage: 18 + README = 19

```
$ find .ocr/index/salvage -type f | wc -l
19
$ find .ocr/index/salvage -type f ! -name README.md | wc -l
18
```
**CONFIRMED, exact.** `salvage/README.md`'s own "Provenance (18 files, `cp -p`, sha256 verified)" table
lists exactly 18 rows, one per non-README file, with 2 explicitly-declared exclusions (already-centralized
scripts; a 1 MB DB backup left in place, correctly not copied). Internally consistent. (Its external
invisibility to the rest of the index is a §4 finding, not a defect in this file itself.)

---

## Bottom line for the caller

- **Numeric identity (claim 1/2):** closes by construction at every instant; CONFIRMED, exactly, at the
  instant the task's own numbers (596/357/86) were cited — this audit's first command reproduced 596
  independently before reading any of the documents under audit. Then superseded repeatedly during the
  ~25 minutes of this audit: `596→597→624→626` total, top-level `183→210`, session-18 `357→358`, run-14
  `85→86→87`. Last independently-measured total: **626** at `06:10:24Z`. Not a durable fact — treat any
  "EXACTLY N" claim about this tree as a timestamp, not a constant.
- **Enumerated coverage (claim 3/4, the actual completeness question):** does **not** hold, currently.
  At every close-out instant this audit observed prior to `MASTER-INDEX.md` ctime `1790057199`,
  `index/salvage/` (19 files) was a true orphan — unmentioned anywhere outside its own README. That
  specific gap has since been closed by a live edit to `MASTER-INDEX.md` made during this audit (now
  names `salvage/` and the hostile-confirmation swarm explicitly) — but the same edit introduced a new,
  checkable false claim ("every non-index component is frozen") contradicted by `.ocr/utilities/scratchpad/`
  (26 files, ctime *preceding* the frozen claim's own ctime by 114 seconds). `index/areas/*.md` (5) and
  `index/PROGRESS-LOSS.md` (1) remain soft orphans by the top-level area file's own explicit design
  (self-referential, out of scope). One of the "5 area files" (`progress-loss-evidence.md`) never
  contained the reconciliation claim being audited — confirmed absent, not just outdated.
  `MASTER-INDEX.md`'s own cross-references on run-14's count were unreconciled at every read taken
  (85 in prose vs. 86/87 required by its own totals), and remain unreconciled in its current revision
  even after the header number was updated.
- **utilities/salvage bijection (claim 5/6):** both genuinely check out, cleanly, as stated, at 51 and 18
  respectively — before `utilities/` kept growing by a further 26 files the README does not yet count.

**Everything in this report is stamped** with the UTC instant or epoch-second ctime it was measured
against. Given the observed rate of change (multiple independent subtrees writing concurrently, one
document rewriting its own completeness claims mid-audit), any single number quoted from this report,
from `MASTER-INDEX.md`, or from any area file should be read as "true as of its stamp," never as current.
