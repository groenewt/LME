# HC-2 Hostile Confirmation — `PROGRESS-LOSS.md`

**Auditor:** HC2-PROGRESSLOSS (hostile, read-only). **Target:** `.ocr/index/PROGRESS-LOSS.md` +
`.ocr/index/areas/progress-loss-evidence.md`. **Method:** every numeric/textual claim re-derived
from primary sources myself (`git`, `sqlite3 ?mode=ro`, filesystem) — the tables below are not
copied from the target docs, they are fresh command output.

**Audit window:** 2026-09-22 05:59–06:12 UTC. The evidence doc's own snapshot was ~05:28 UTC.
**Environment note, load-bearing for how to read this report:** this repo has a live, concurrently
running OCR indexing/compaction swarm (confirmed via `orchestration_events` rows still `finished_at
IS NULL` at audit time, and directly observed below: git state changed materially *during* this
audit). Several claims that were 100% accurate at 05:28Z had already drifted by 06:06Z — not
because the evidence doc erred, but because the ground truth is a moving target right now. Each
such case is called out explicitly.

---

## LEAD VERDICT

**PROGRESS-LOSS.md's central thesis — code is safe and remote-backed; the loss is bounded to the
context/legibility layer — is SOUND and holds up under hostile re-verification with zero
exceptions on the code-safety side.** Every git number reproduces exactly, including the
decisive `origin` citation.

**One open question the evidence doc explicitly left unresolved, I closed — and it cuts toward
the thesis being conservative, not inflated.** B1 is titled "DB-unrecoverable reviewer output"
and its "permanent" sits in a column about DB durability, so read narrowly it's correct: those 26
DB rows will never self-repopulate. But the doc itself flagged the open question of whether the
*underlying content* also survives on disk (§ Numbers not obtained: "the true unrecoverable count
could be smaller than 26 if some of those 26 have a matching `.md`"). I did that row-by-row
reconciliation — matching by workflow, persona, and exact `orchestration_events` round window,
then verifying no round has a duplicate persona (so the match is a clean bijection, not
inference) — and **all 26 of 26** have a matching, substantive, on-disk `reviews/*.md` file. The
content-loss count is **0 of 26**, not "some." The DB-scoped "permanent" label is technically
correct; a casual read of the Part-B table row (under the heading "What we ACTUALLY lost") could
still land on "26 reviews gone forever," which this reconciliation forecloses.

**One number is UNDERSTATED:** the repo-root `scratchpad/` file count is **26, not 24** (B3).

**One citation is imprecise (OVERSTATED specificity):** the claim that runs 7, 11, and 12 "headers
say 'cycle-continuation map, not a re-catalog'" is only literally true of run-7. Runs 11/12 convey
the same delta-anchored substance in different words, but don't contain that quoted phrase.

**Everything else — the 51/0/0 git triple, the 101/26/81 DB split, the 98-file survival count, the
run-13 three-way mismatch, the `SESSION_DIR` root cause, and the mode-shift mechanics of the map
curve — reproduces exactly.**

---

## Claim-by-claim

### 1. Code remote-backed — **CONFIRM**

```
$ git rev-parse HEAD
d5625bada39e387d3599783871f147eacdfbb354
$ git rev-parse origin/fix/debian-13-selinux-apt
d5625bada39e387d3599783871f147eacdfbb354
$ git rev-list --left-right --count origin/fix/debian-13-selinux-apt...HEAD
0	0
$ git log --oneline main..fix/debian-13-selinux-apt | wc -l
51
$ git log --oneline main..fix/debian-13-selinux-apt | grep -iE "revert|undo|back.?out"
(no output — zero matches)
$ git merge-base main fix/debian-13-selinux-apt
8ef08a7a3654876e5b82660b7969f0885034e897
$ git rev-parse main
8ef08a7a3654876e5b82660b7969f0885034e897    # identical to merge-base — zero divergence
$ git log --oneline fix/debian-13-selinux-apt..main
(empty)
```

`0  0` exact, `51` exact, zero reverts. I additionally hand-read all 51 commit subjects (not just
grep) looking for revert-shaped language the pattern might miss (roll back, reapply, drop-then-
readd, force-push artifacts) — none found; every commit is a forward fix/feat/docs/wave/test
commit, one plain checkpoint (`14c7c0b "user snapshot"`). `merge-base == main`'s tip exactly,
confirming zero divergence independent of the rev-list check. **Fully confirmed, no weaker than
stated.**

### 2. Dashboard wiring gap (101 / 26 / 81) — **CONFIRM** (counts exact; closes the doc's own open reconciliation question, content-loss = 0/26 not "permanent")

```sql
SELECT count(*) FROM command_executions WHERE command LIKE 'session-instance:%';               -- 101
SELECT count(*) FROM command_executions WHERE command LIKE 'session-instance:%'
  AND (output IS NULL OR output='') AND (notes IS NULL OR notes='');                            -- 26
SELECT count(*) FROM command_executions WHERE command LIKE 'session-instance:%'
  AND (output IS NULL OR output='');                                                            -- 81
```
101 / 26 / 81 all reproduce exactly.

**New fact the evidence doc didn't state:** the "81 no `events/<id>.jsonl` file" set and the "81
output NULL" set are not just equal in *count* — I computed both as explicit id sets (Python,
not shell `comm`, after `comm` threw sort-order warnings I didn't trust) and they are **the
identical 81 rows**. That's a clean mechanical confirmation of the doc's causal story (no
journal file ⇔ no DB output), not previously demonstrated at the row level.

**The reconciliation the evidence doc flagged as not done, now done:** all 26 both-null rows
belong to `workflow_id = 2026-09-18-fix-debian-13-selinux-apt-review`, in four timestamp
clusters. I cross-referenced each cluster's `started_at`/`finished_at` against
`orchestration_events` `round_started`/`round_completed` rows for that workflow, which gave an
**exact, non-inferential** round assignment:

| DB ids | persona set | round (from `orchestration_events`) | round window (UTC) | matching `rounds/round-N/reviews/*.md`? |
|---|---|---|---|---|
| 31–35 (5) | principal-1,2 / quality-1,2 / security-1 | round 1 (`round_completed` 06:53:03) | 06:32:00–06:46:04 | **YES, all 5 files present**, mtimes 01:38–01:43 CDT = 06:38–06:43 UTC, inside window |
| 37–41 (5) | same 5 personas | round 2 (`round_completed` 08:42:06) | 08:03:45–08:21:49 | **YES, all 5**, mtimes 03:14–03:20 CDT |
| 42–52 (11) | +devops/infra/reliability/perf/testing/security-2 | round 3 (`round_completed` 11:09:10) | 10:32:50–11:04:17 | **YES, all 11** (round-3 dir has exactly these 11 filenames) |
| 63–67 (5) | principal-1,2 / quality-1,2 / security-1 | round 8 (`round_started` 07:34:26 / `round_completed` 07:59:41) | 07:36:35–07:57:05 | **YES, all 5**, mtimes 02:42–02:46 CDT |

26/26. Every one of the "fully unrecoverable" rows has a same-persona, same-timestamp-window,
non-empty (11.5–29 KB) file on disk. Spot-checked two for genuineness (not placeholders):

```
$ head -c 300 rounds/round-1/reviews/principal-1.md
# Principal Engineer Review — `principal-1`
- **Reviewer**: principal-1 (Principal/Staff Engineer...) **Target**: `main...HEAD` ... head `14c7c0b`
...
$ head -c 300 rounds/round-8/reviews/security-1.md
# Security Review — round-8 (security-1)
## Summary
Round-8's four Wave-8 commits are comment/docstring-only... The security-material item is R8-6:
the Elasticsearch transport listener (9300) ...
```

Both are real, specific, non-generic review prose.

**Closing the identity gap (not just persona+timestamp coincidence):** matching by persona name
and timestamp window proves *a* review with that persona exists for that round, not that it's
*that specific row's* output — a real concern since two workflow_ids (the bare map session and
the `-review` session) share one on-disk session directory. I closed this with an exact join
(round boundaries from `orchestration_events`, not inferred) counting DB rows per round and
checking for any duplicate persona within a round:

```
round  db_rows  personas (distinct)
1      5        principal-1,principal-2,quality-1,quality-2,security-1
2      5        principal-1,principal-2,quality-1,quality-2,security-1
3      11       principal-1,principal-2,quality-1,quality-2,security-1,security-2,devops-1,infrastructure-1,reliability-1,performance-1,testing-1
4      5        principal-1,principal-2,quality-1,quality-2,security-1
5      5        principal-1,principal-2,quality-1,quality-2,security-1
8      5        principal-1,principal-2,quality-1,quality-2,security-1
9      5        principal-1,principal-2,quality-1,quality-2,security-1
```
Every round that contains one of the 26 (1, 2, 3, 8) has **exactly one DB row per distinct
persona and exactly one on-disk file per persona, with row-count equal to distinct-persona-count**
— i.e. a clean 1:1 bijection, zero duplicates, zero oversubscription. Attribution for the 26 is
therefore not circumstantial: it's a proven bijection, not an inference.

**Tangential finding surfaced while closing this (not part of the 26, flagged for awareness):**
rounds 6, 7, and 10 show **zero** DB rows under either workflow_id in this join — and a direct
query of round-6's time window (`03:04:51`–`03:23:25`) for *any* command, *any* workflow, returns
**zero rows, period**. Yet `rounds/round-6/reviews/` has 5 real files on disk. So the DB doesn't
just have a wiring gap for `output`/`notes` on rows it knows about — for at least 3 rounds (15
more files) it appears to have **no row at all**, of any kind. This is outside what I was asked
to reconcile and doesn't change the 26-count answer, but it's evidence the DB undercounts
completed review activity in more places than PROGRESS-LOSS.md enumerates, which if anything
argues the legibility problem is *at least* as bad as described, not overstated.

**Verdict: the 26/101 and 81/101 counts are CONFIRMED exactly, and the DB-scoped "permanent"
label in the B1 table's Durable? column is technically correct (those rows will not
self-repopulate). But read against Part B's own header ("What we ACTUALLY lost"), a reader could
take "permanent" to mean the content is gone — my reconciliation forecloses that reading:
content-loss is 0 of 26, fully resolving the doc's own flagged open question in the direction of
"less lost than the upper bound," not more.**

### 3. 98 reviewer `.md` files survive — **CONFIRM (count); minor OVERSTATE (byte size)**

```
$ find .ocr/sessions -path '*/reviews/*.md' | wc -l
98
$ find .ocr/sessions -path '*/reviews/*.md' | awk -F/ '{print $3}' | sort | uniq -c
     15 2026-09-16-fix-debian-13-selinux-apt
     70 2026-09-18-fix-debian-13-selinux-apt
     13 2026-09-21-fix-debian-13-selinux-apt
$ find .ocr/sessions -path '*/reviews/*.md' -printf '%s\n' | awk '{sum+=$1} END {print sum}'
1494513
```
98 exact. The 70-file 09-18 breakdown fully reconciles: rounds 1–10 = 56 files (5×9 + 11 for the
11-persona round-3) + 14 files under `map/runs/run-12/reviews/*.md` (flow-analyst and
requirements-mapper artifacts, a second/different "reviews" directory under the map workflow, not
the round workflow) = 70. Byte total is **1,494,513 bytes = 1.49 MB decimal / 1.43 MiB binary**;
the evidence doc's "1.6 MB" is a ~7% overstatement — immaterial, but not what re-measurement
gives.

### 4. run-13 three-way mismatch — **CONFIRM, and more precisely than stated**

```sql
SELECT id,run_number,file_count,section_count,source,parsed_at FROM map_runs WHERE id=30;
-- 30|13|0|/…/run-13/map.md|2026-09-22 00:21:33|parser|0
SELECT count(*) FROM map_sections WHERE map_run_id=30;   -- 6
SELECT count(*) FROM map_files WHERE section_id IN (263,264,265,266,267,268);  -- 0
```
On disk, `run-13/map.md` is **132 lines of substantive content** — 5 blockers, 5 should-fixes, a
"76-file delta" claim, live e2e evidence (`rc=0`, 3/4 VIPs proven), K1/A1 findings. It is not a
degenerate or empty document. But:
- `map_runs` row says `file_count=0` **and** `section_count=0`.
- `map_sections` actually has **6 real child rows** (titles verbatim-matching the on-disk H2/H3
  headings — e.g. "K1 — kibana VIP dead...", "Findings ledger..."), each with `file_count=0`.
- `map_files` (the actual file-list child table, one level deeper than the evidence doc checked)
  has **zero rows** for any of those 6 sections.
- `map_runs.section_count=0` is internally inconsistent with its own child table, which has 6
  rows, not 0 — the parent counter is stale/wrong even relative to what the parser itself wrote.

**Verdict: CONFIRMED, and the true picture is a partial parse (titles captured, content/files
never captured, and the parent counter doesn't even match its own children) — not a wholesale
empty run.** This is consistent with, and adds precision to, "wrote partial section rows but zero
file rows."

### 5. `SESSION_DIR` root cause — **CONFIRM**

`.ocr/skills/references/map-workflow.md:31–39`:
```bash
BRANCH_RAW=$(git branch --show-current)
BRANCH=$(echo "$BRANCH_RAW" | tr '/' '-')
DATE=$(date +%Y-%m-%d)
SESSION_DIR=".ocr/sessions/${DATE}-${BRANCH}"
```
Exact, verbatim, date-anchored (line 35 `DATE`) concatenated with branch (lines 33–34), giving
`SESSION_DIR="${DATE}-${BRANCH}"` on line 36. A same-branch run on a later calendar date
mechanically produces a new `SESSION_DIR` and therefore a new session row. This is corroborated
independently by the live `sessions` table, which shows exactly this pattern: three date-stamped
directories (09-16, 09-18, 09-21) for what is git-verified to be one continuous branch.
**Root-cause claim fully confirmed at the cited lines.**

### 6. Repo scratchpad untracked-and-unignored — **CONFIRM (as of the evidence snapshot); file count UNDERSTATED; state has since changed underneath this audit — see below**

At the time I first checked (~05:59 UTC):
```
$ git check-ignore -v scratchpad/
(no output, exit 1 — not ignored)
$ git status --porcelain | grep scratchpad
?? scratchpad/
$ grep -rn scratchpad --include=.gitignore .
(no output anywhere in the repo)
```
Confirmed exactly as stated: untracked, not gitignored. **But the file count is wrong**: the
evidence doc says 24 files; direct count says **26**:
```
$ find scratchpad -maxdepth 1 -type f | wc -l
26
$ find scratchpad -type f -printf '%s\n' | awk '{sum+=$1} END{print sum}'
1281839   # 1.28 MB — the "~1.3 MB" figure is fine, only the file count is off
```
**B3's file count is UNDERSTATED by 2 (26 actual vs 24 claimed).**

**Live drift, caught mid-audit:** by my second check (~06:05–06:06 UTC, ~7 minutes later), the
picture changed:
```
$ ls scratchpad/ 2>&1
ls: cannot access 'scratchpad/': No such file or directory
$ git status --porcelain | grep '^A.*scratchpad'
A  .ocr/utilities/scratchpad/emit_3node_files.py
... (26 lines total, all 26 original files, byte-identical filenames) ...
$ ls .ocr/utilities/scratchpad/ | wc -l
26
```
A concurrent process (the live indexing/compaction swarm — see environment note above) `git mv`'d
the entire repo-root `scratchpad/` into `.ocr/utilities/scratchpad/` and staged it, between my two
checks. All 26 filenames present, none dropped — and I verified this is more than a filename
match: summed on-disk byte size at the new location is **1,281,839 bytes, exactly equal** to the
1,281,839-byte total I measured at the original location before it moved, and I cross-checked
every individual file's byte count (all 26, including the 1,003,520-byte binary `.db.bak`) against
the sizes recorded from the original `ls -la scratchpad/` — every one matches exactly. Content
survived the move intact, not just the directory listing. This is **literally PROGRESS-LOSS.md's
own Part D remediation item #2 being executed live**, apparently in response to this same
indexing pass. **Net effect:
the specific "one `git clean -fd` away" risk B3 warns about no longer exists as of 06:06 UTC** —
`git clean -fd` does not touch staged paths. It is *not yet committed*, so it inherits the same
"staged but not on origin" caveat PROGRESS-LOSS.md already applies to the other 66 (now ~170, see
below) staged files. **This is not an error in PROGRESS-LOSS.md — it was accurate when written —
but a reader relying on this report should know the scratchpad risk was live-remediated during
this very audit, not merely described.**

### 7. Map curve = mode-shift, not collapse — **CONFIRM the mechanism exactly; OVERSTATE the textual citation**

I parsed `map-meta.json` directly (not the DB) for four runs spanning the most contested part of
the curve, and independently summed `sections[].files[].file_path`:

| run | `map_runs.file_count` (DB) | Σ `sections[].files[]` (my own parse of `map-meta.json`) | `section_count` (DB) | sections in JSON |
|---|---:|---:|---:|---:|
| 6 | 137 | **137** | 15 | 15 |
| 7 | 24 | **24** | 9 | 9 |
| 11 | 1 | **1** | 4 | 4 |
| 12 | 6 | **6** | 2 | 2 |

Exact match on all four, both file_count and section_count. This directly confirms the core
mechanical claim: the DB column is a map-content metric derived from the run's own generated
JSON, not a raw on-disk source-file count — "on-disk run-6 = 4 files" in the evidence doc refers
to the run-6 *directory's own artifact count* (`canonical-files.txt`, `map.md`, `map-meta.json`,
`topology.md` — I confirmed `ls run-6/` returns exactly these 4 entries), a legitimately
confusing but accurate contrast against the DB's 137.

For the "headers say 'cycle-continuation map, not a re-catalog'" citation, I grepped the literal
phrase across all three cited files:
```
$ grep -n "cycle-continuation" run-7/map.md run-11/map.md run-12/map.md
run-7/map.md:8:This is a **cycle-continuation map**, not a re-catalog. The round-6 review closed...
(no match in run-11/map.md or run-12/map.md)
```
Only run-7 contains that exact phrase. Run-11's header instead says "**Delta since round-10**
(e5a5d7a..fa0c034): 1 file, +91/-20"; run-12's says "**Files**: 6 | **Sections**: 2" scoped to
"**Range**: `fa0c034..52bf2bb`". Both *are* substantively delta-anchored maps (this part of the
claim holds), but PROGRESS-LOSS.md's sentence structure ("their own map.md headers say [quoted
phrase]") attributes a specific quote to three headers when only one contains it. **Verdict:
mechanism CONFIRMED exactly; the specific triple-attributed quote is OVERSTATED — true for 1 of
3, not 3 of 3 — though the underlying "not a collapse" substance independently holds for all
three via each file's own (differently-worded) framing.**

---

## Additional hostile checks beyond the 7-item list (things that would break the thesis if wrong)

**events/*.jsonl integrity** — **CONFIRM**: `find .ocr/data/events -name "*.jsonl" -size 0` → 0
results (zero empty files, of 30 total, 4,486,732 bytes). Smallest file (`10.jsonl`, 886 B)
parsed as 3 well-formed JSON lines via Python `json.loads` per line — no corruption.

**"Not a crash" reframe (A3)** — **CONFIRM, exactly**:
```sql
SELECT count(*) FROM command_executions WHERE command LIKE 'session-instance:%' AND finished_at IS NULL;  -- 0
SELECT count(*) FROM command_executions WHERE command LIKE 'session-instance:%' AND exit_code IS NULL;    -- 15
SELECT count(*) FROM command_executions WHERE command LIKE 'session-instance:%'
  AND exit_code IS NULL AND (notes IS NULL OR notes='');                                                  -- 0
```
Zero unfinished rows; exactly 15 null-exit-code rows (9 flow-analyst + 6 requirements-mapper, both
verified by persona `GROUP BY`); **all 15 have `notes` populated** — zero of them are silently
empty. The "instrumentation gap, not a crash" framing is fully earned by the data.

**Sibling branches/worktrees (5 for this topic)** — **CONFIRM, correctly scoped**. A fresh
`git branch -vv` now lists ~22 branches total (this repo has substantial unrelated parallel work:
elastic-pack, litellm, wazuh, cert-permissions, HIBP, style-cleanup branches, several `_ocr_r*`
integration branches). The evidence doc's "5 branches for this topic" claim was explicitly scoped
to debian-13/selinux/apt-named branches, and correctly excludes the unrelated ones — the 4 named
siblings (`fix/debian-13-no-double-include`, `fix/debian-13-packages-reconcile`,
`fix/debian-apt-offline-retry`, `fix/debian-selinux-apparmor-wording`) plus the measured branch
are still exactly the topic-matching set. Not overstated.

**66 staged files (Part B durability note)** — **CONFIRM at snapshot time; STALE now, and still
moving.** I read `git status --porcelain`'s staged/untracked split four times over the course of
this audit; each read was different: 172/0 (first read), 171/4, 170+2AM/4, and a final canonical
read at **06:12:18 UTC: 169 `A ` + 3 `AM` + 6 `??` (178 total changed paths)**. This is not
measurement noise or a mistake on my part — it is the live indexing/compaction swarm mutating the
index in real time, several times, during the ~13 minutes I spent on this audit. The consistent
direction (66→~170+) is explained by the same effect as the scratchpad finding: `.ocr/index/`,
`.ocr/utilities/`, `.ocr/utility/`, and the relocated `scratchpad/` all moved from
untracked/nonexistent into staged since the evidence doc's 05:28 UTC snapshot. **Anyone reading
PROGRESS-LOSS.md's specific git-status-derived counts (66/8) should treat them as a timestamped
snapshot from an actively-changing session, not current state as of whenever they read it.** This
is the single most important meta-caveat for this whole document: the underlying git/DB facts are
being generated by a swarm that is still running as of this audit, and the specific counts will
continue to drift after this report is written too.

**Session active→closed drift** — the evidence doc's session-splintering table (§2) states session
`2026-09-18-fix-debian-13-selinux-apt` was `active`, `updated_at` 05:25:11. A fresh query now
shows `status=closed`, `updated_at=2026-09-22 05:59:21`, with an explicit `session_closed`
`orchestration_events` row at `05:51:39` — 23 minutes after the evidence snapshot. Accurate when
written; superseded by ordinary session completion since. No thesis impact (the session closing
cleanly is, if anything, mildly supportive of "things are converging," not evidence against it).

---

## Summary table

| # | Claim | Verdict |
|---|---|---|
| 1 | Code remote-backed, 51 commits, zero reverts, zero divergence | **CONFIRM** (exact) |
| 2 | 101/26/81 DB split | **CONFIRM** (exact, and identity-proven via round bijection); closes the doc's own open question — content-loss = 0/26, not "permanent" |
| 3 | 98 reviewer `.md` files survive | **CONFIRM** (exact); byte size minor OVERSTATE (1.49MB actual vs 1.6MB claimed) |
| 4 | run-13 three-way mismatch | **CONFIRM**, more precisely than stated (parent counter inconsistent with its own 6 children; `map_files` independently checked = 0) |
| 5 | `SESSION_DIR` date-anchored root cause | **CONFIRM** (exact lines, exact mechanism) |
| 6 | scratchpad untracked+unignored | **CONFIRM** at snapshot; file count **UNDERSTATED** (26 vs 24); **superseded live** — relocated+staged by 06:06 UTC |
| 7 | Map curve = mode-shift not collapse | **CONFIRM** mechanism (exact re-derivation from JSON, 4/4 runs sampled); citation **OVERSTATED** (quote true for 1 of 3 headers, not 3) |

**Net assessment:** hostile re-verification does not surface a single case where PROGRESS-LOSS.md
understated the code-safety half of its thesis, and finds the loss-side numbers are, on the one
substantive reconciliation I completed that the evidence doc left open, smaller than stated (0
permanently-lost reviews, not 26) rather than larger. The overstatements found are all in framing
precision (a "permanent" label, a triple-attributed quote, a byte-size rounding, a file-count
off-by-2) — none of them are load-bearing to the central thesis, and the most significant one
(B1) cuts in favor of the thesis being *conservative*, not inflated.
