# Progress-Loss Evidence — branch `fix/debian-13-selinux-apt`

> **Refined by the hostile-confirmation swarm (as-of 06:23Z):** this file is the raw investigation snapshot; three figures were tightened by adversarial re-audit and are superseded by `../PROGRESS-LOSS.md`: (a) the repo `scratchpad/` is **26 files / 18 real artifacts** (not "24 / six") and has since been **operator-relocated + staged** into `.ocr/utilities/scratchpad/`; (b) reviewer content-loss is **0/26** — HC-2 proved all 26 DB-null rows map 1:1 to on-disk `reviews/*.md` (the 26 here was an unreconciled upper bound); (c) the 98 reviews are **1.49 MB** ("1.6 MB" was rounded). The evidence and reasoning below otherwise stand. Authoritative live totals: `../MASTER-INDEX.md` §1 + §8.

Agent: PROGRESS-LOSS (evidence-only, read-only). All commands run from
`/home/tristan/gitters/LME`. DB queried read-only via
`file:/home/tristan/gitters/LME/.ocr/data/ocr.db?mode=ro`. Snapshot time:
2026-09-22 ~00:28 CDT (DB timestamps below are UTC, i.e. ~05:28).

---

## 1. GIT — the durable record

**Commit count.** `git log --oneline main..fix/debian-13-selinux-apt | wc -l` → **51**, exactly matching the operator's figure. Full list captured; newest is `d5625ba`, oldest is `79ad755`.

**Revert check.** `git log --oneline main..fix/debian-13-selinux-apt | grep -iE "revert|undo|back.?out"` → **NONE FOUND**. Zero of the 51 commit subjects contain those words.

**Divergence check.** `git merge-base main fix/debian-13-selinux-apt` → `8ef08a7a3654876e5b82660b7969f0885034e897`, which is *exactly* `main`'s current tip (`git branch -vv`: `main 8ef08a7 [upstream/main] Update README.md (#814)`). `git log --oneline fix/debian-13-selinux-apt..main` → **empty**. Conclusion: the branch is a clean, linear 51 commits ahead of `main` with zero divergence — nothing on `main` is missing from the branch, and no rebase/history-rewrite gap exists.

**Remote-backed, not just local.** `git rev-list --left-right --count origin/fix/debian-13-selinux-apt...HEAD` → **`0  0`**. Local `HEAD` and `origin/fix/debian-13-selinux-apt` are the *same commit* (`d5625ba`, pushed `2026-09-21T20:22:32-05:00`). This directly supersedes several MEMORY.md notes claiming waves were "NOT pushed" (e.g. round-6/7/10/12 notes) — those were accurate *at the time they were written*; a push has since landed all 51 commits on the remote. **The 51 commits are not disk-only — they are confirmed on `origin`.**

**Commit-message taxonomy** (hand-verified against the full 51-line log, non-overlapping buckets):

| Bucket | Count | Detail |
|---|---:|---|
| Conventional `fix(...)`  | 7 | e.g. `fix(wipe_lme,deploy_gate): ...`, `fix(tailscale_service): ...` |
| Conventional `feat(...)` | 2 | `feat(profiles/tailscale)`, `feat(tailscale_service)` |
| Conventional `docs(...)` | 6 | manifest/host_vars/deploy_gate clarity commits |
| Conventional `test(...)` | 1 | cluster-budget test rename |
| `Wave-N ...` (address / doc-accuracy) | 20 | Waves 2–8, all OCR-review-response commits |
| Free-form sentence (`Fix`, `Add`, `Address`, `Gate`, `Use`, `Drop`, `Connect`, `Round-5 address`, `harness:`) | 15 | pre-"Wave" convention adoption |
| **Total** | **51** | matches `git log` count exactly |

Only one commit doesn't fit a work-type label at all: `14c7c0b "user snapshot"` — a checkpoint commit, not a revert.

**Working tree at snapshot time** (`git status --porcelain`):

| Status | Count | What |
|---|---:|---|
| `A ` (staged, uncommitted) | 66 | the entire `.ocr/` OCR-review toolkit (commands, skills, reviewer personas, `PATCHES-no-output-recorded.md`) + `AGENTS.md` |
| `??` (untracked) | 8 | `.current.json`, `.cursor/`, `.ocr/index/`, `.ocr/utilities/`, `.ocr/utility/`, `.opencode/`, `docs/`, **`scratchpad/`** |

Provenance note on `.ocr/index/`: this directory and its `MASTER-INDEX.md` already existed (created 00:20–00:26, before this agent was invoked) — it is the current indexing/compaction swarm's own output area, not a pre-existing-and-forgotten artifact. This agent's only filesystem action was `mkdir -p` on the already-present `areas/` subdirectory to hold this file; nothing else in that `??` row was created or touched by this evidence-gathering pass.

The 66 staged files are the OCR tooling itself — staged but **not yet in any commit**. This is a secondary durability nuance: it survives a crash/`reset --soft` but is not yet part of the 51-commit durable history and is not on `origin` until committed.

**Sibling branches/worktrees found** (`git branch -vv`): besides the 51-commit branch, four related topic branches exist, three in separate worktrees — `fix/debian-13-no-double-include` (`_ocr_wt/sf6`), `fix/debian-13-packages-reconcile` (`_ocr_wt/s1`), `fix/debian-apt-offline-retry` (`_ocr_wt/sf7`), `fix/debian-selinux-apparmor-wording`. Work related to this topic is spread across 5 branches total, not just the one being measured.

---

## 2. MAP QUALITY CURVE

`SELECT run_number,file_count,section_count,source,parsed_at FROM map_runs WHERE session_id='2026-09-18-fix-debian-13-selinux-apt' ORDER BY run_number;`

| run | file_count | section_count | source | parsed_at (UTC) |
|---:|---:|---:|---|---|
| 1 | 52 | 7 | orchestrator | 2026-09-18 06:20:29 |
| 2 | 32 | 8 | orchestrator | 2026-09-18 09:31:50 |
| 3 | 116 | 13 | orchestrator | 2026-09-18 15:32:28 |
| 4 | 124 | 15 | orchestrator | 2026-09-18 17:26:07 |
| 5 | 127 | 14 | orchestrator | 2026-09-18 20:13:45 |
| 6 | 137 | 15 | orchestrator | 2026-09-18 23:25:56 |
| 7 | 24 | 9 | orchestrator | 2026-09-19 03:51:33 |
| 8 | 137 | 15 | orchestrator | 2026-09-19 05:52:37 |
| 9 | 137 | 15 | orchestrator | 2026-09-19 08:44:08 |
| 10 | 137 | 15 | orchestrator | 2026-09-19 11:56:44 |
| 11 | 1 | 4 | orchestrator | 2026-09-21 18:52:55 |
| 12 | 6 | 2 | orchestrator | 2026-09-21 21:00:57 |
| 13 | 0 | 0 | **parser** | 2026-09-22 00:21:33 |
| 14 | 10 | 3 | orchestrator | **2026-09-22 05:24:32** |

Confirms the operator-cited curve 52,32,116,124,127,137,24,137,137,137,1,6,0 for runs 1–13, **plus a 14th run the task brief didn't have**: 10 files / 3 sections, `source=orchestrator`, parsed at 05:24:32 — **~4 minutes before this evidence-gathering swarm was invoked** (self-consistent with §3 below). The curve does not bottom out at 0 and stay there; run 13 is a distinct `source='parser'` row (the DB's own schema corroborates "back-fill parser pass," not a normal map run — it is the only non-`orchestrator` row in the table), and run 14 shows a partial-recovery map generation that was still degraded (10 vs. the 137-file peak) and in flight at the moment of complaint.

**Session splintering** — `sessions` table (5 rows):

| session id | status | branch (as recorded) | started_at | updated_at | current_map_run |
|---|---|---|---|---|---:|
| 2026-09-16-fix-debian-13-selinux-apt | closed | fix-debian-13-selinux-apt | 09-16 17:06:59 | 09-18 08:06:39 | 1 |
| 2026-09-16-fix-debian-13-selinux-apt-review | closed | fix-debian-13-selinux-apt | 09-16 17:29:18 | 09-16 21:40:00 | 1 |
| 2026-09-18-fix-debian-13-selinux-apt | **active** | fix/debian-13-selinux-apt | 09-18 05:44:47 | **09-22 05:25:11** | 14 |
| 2026-09-18-fix-debian-13-selinux-apt-review | closed | fix/debian-13-selinux-apt | 09-18 06:28:51 | 09-19 12:34:41 | 1 |
| 2026-09-21-fix-debian-13-selinux-apt | closed | fix-debian-13-selinux-apt | 09-21 21:14:06 | 09-21 22:29:35 | 1 |

Work on this one topic is recorded under three different date-stamped session IDs (09-16, 09-18, 09-21) plus the still-active 09-18 session being touched again right now (09-22). The `branch` column is inconsistent — two rows record the slug `fix-debian-13-selinux-apt` (hyphenated) where the real git branch is `fix/debian-13-selinux-apt` (slash); this looks like a display/slug artifact of the OCR tool rather than a real second git branch (no such hyphenated branch exists in `git branch -vv`), but it is a source of operator confusion about "which session is current."

---

## 3. VANISHED AGENT OUTPUT

**Documented root cause** (`.ocr/PATCHES-no-output-recorded.md`, read in full): the dashboard command-detail card renders `command_executions.output`, falling back to the literal string `"No output recorded."` when null. Reviewer/persona rows journaled via `ocr session start-instance` never get `output` written — only `notes` (via `--note`). `output` is populated solely by the dashboard's own detached-child-process stdout capture path, which Task sub-agents never go through. Stopgap FIX 1 (server-side `output ?? notes` fallback) and FIX 2 (SKILL.md protocol requiring a meaningful `--note`) were applied; a durable upstream fix (FIX 3) is explicitly out of scope and not done.

**Important caveat on where FIX 1 actually lives**: the patched file is `/home/tristan/.nvm/versions/node/v26.7.0/lib/node_modules/@open-code-review/cli/dist/dashboard/server.js` — **outside this repo entirely, not gitignored-in-repo, not scratchpad**. PATCHES.md lines 22–28 state this stopgap is overwritten by any `ocr` reinstall/self-update and "must be re-applied." The *instructions* to redo it are durable (the doc itself is one of the 66 staged files in §1). The *applied patch* is not durable at all — a global npm package file, untracked by any git repo, one `npm i -g` away from silently reverting.

**Empty-file sub-check (refutes the "0 bytes" premise).** `.ocr/data/events/` contains 30 `.jsonl` files, 4,486,732 bytes total. **Zero are 0 bytes or empty arrays.** The ten smallest (886–898 B: ids 2–11) each contain exactly 3 well-formed JSON lines — a start `notice` plus 2 `message` events for round-1/round-2 reviewer instances (principal-1/2, quality-1/2, security-1). The journal files that exist are intact; nothing on disk is corrupt.

**The real gap is file coverage, not file emptiness.** Cross-referencing every `command LIKE 'session-instance:%'` row's `id` against `events/<id>.jsonl`:

| | count |
|---|---:|
| Total `session-instance:*` rows in DB | 101 |
| Rows **with** a matching `events/<id>.jsonl` file | 20 |
| Rows **with no file at all** | **81** |

For the 20 with a file (e.g. id 12 → `12.jsonl`, 95 KB), PATCHES.md's own worked example proves this is a **wiring gap, not data loss**: id 12's DB `output` was `null` even though the 95 KB transcript exists on disk and `notes` held `"principal-1 round-3: 0 blockers, ..."`. For the 81 with no file, there is no per-instance transcript at all — only whatever the DB captured.

**DB-column recoverability, quantified:**

| | count / 101 |
|---|---:|
| `output` NULL or empty | 81 |
| `notes` NULL or empty | 36 |
| **Both** `output` and `notes` NULL/empty (fully unrecoverable from DB) | **26** |

Those 26 are genuine irrecoverable-from-database instances (PATCHES.md names one explicitly: id 2, rounds 1–2, predates the FIX-2 "always attach a note" protocol).

**Content survival check** — the actual review prose largely exists outside the DB: `find .ocr/sessions -path '*/reviews/*.md'` → **98 files, 1.6 MB total**, spanning all three session directories back to round-2 (e.g. `2026-09-16-.../rounds/round-2/reviews/security-1.md`). This was not matched row-by-row against the 81 file-less DB rows, but it establishes that reviewer *content* is substantially preserved on disk (gitignored, but present) even where the DB's index of it is broken.

**The "flow-probe crash" — precise finding, corrected framing.** The task brief's premise that `flow-probe` "CRASHED" overstates what the data shows. Global check: `session-instance:*` rows with `finished_at IS NULL` (i.e., never finished) = **0**. Rows with `exit_code IS NULL` = **15**. Every one of those 15 has a `finished_at` timestamp — the process *ended*, but no exit code was ever recorded. Correct framing: **"finished with no recorded exit code" (an instrumentation gap), not a proven crash.**

All 15 belong to exactly two persona batches, both feeding map run 14 (§2):

| ids | persona | started | finished | exit_code | notes present? |
|---|---|---|---|---:|---|
| 108–116 (9) | flow-analyst (incl. literal `flow-probe`, id 108) | 04:47:45–04:48:17 | 05:24:20–05:24:21 | NULL (all 9) | **yes, all 9** |
| 117–122 (6) | requirements-mapper | 04:51:58 | 05:24:21 (all 6) | NULL (all 6) | **yes, all 6** |

9 + 6 = 15 — this accounts for **100%** of the DB's null-exit-code rows; the gap is not scattered through history, it is entirely concentrated in the single most recent map-generation pass, which finished at 05:24:2x, 11 seconds before map run 14 was parsed (05:24:32) and ~4 minutes before this swarm was invoked. Both batches have `output` empty but **`notes` populated for every row** — i.e., recoverable via the dashboard's notes-fallback, not lost.

**Self-referential confirmation the DB is live**: ids 123–125, immediately following, are `persona=compaction`, `name=IDX-TOP` / `IDX-S16-S21` / `IDX-S18-HIST`, started 05:22:04, `finished_at` still NULL — these are rows for the *current* indexing/compaction swarm this agent is part of, direct confirmation this table is being written to live, right now, by this very swarm. (Their `finished_at` is still NULL, so they cannot yet show whether the exit_code gap recurs for this run — that remains open.)

**exec-logs/** (2 files, matches expectation): `a00ee466-...log` (2,389,649 B, 2026-09-16 12:19) and `e2ac9b6e-...log` (1,278,458 B, 2026-09-21 15:42). Both timestamps exactly match `events/1.jsonl` (2,063,472 B, same 09-16 12:19) and `events/87.jsonl` (922,870 B, same 09-21 15:42) respectively — these two heavyweight orchestrator-level runs are the only ones with a raw stdout exec-log; everything else relies solely on the per-instance jsonl journal or DB row.

---

## 4. SCRATCHPAD EVAPORATION SCOPE

**Session scratchpad** (`/tmp/claude-1000/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/scratchpad`): `find -type f | wc -l` → **1238** files (task estimate ~1237, confirmed). Breakdown by extension (all rows sum to 1238):

| ext | count | ext | count | ext | count |
|---|---:|---|---:|---|---:|
| yml | 402 | container | 289 | log | 90 |
| txt | 78 | volume | 73 | md | 48 |
| sh | 45 | out | 39 | json | 28 |
| err | 26 | py | 17 | network | 17 |
| service | 15 | crt | 11 | xml | 6 |
| key | 6 | go | 5 | diff | 5 |
| pem | 4 | ini | 4 | hujson | 4 |
| path | 2 | msg | 2 | headers | 2 |
| tgz | 1 | response | 1 | pyc | 1 |
| (extensionless) | 17 | | | | |

`yml` + `container` (quadlet unit files) alone are 691/1238 (56%) of the volume — dominated by Podman Quadlet / Ansible-manifest test fixtures from iterating the ES-cluster and tailnet-VIP rendering work, not hand-authored source. This entire directory is scoped to one Claude Code session and evaporates when the session ends — it was never gitignored because it was never inside the repo to begin with.

**Repo working-tree `scratchpad/`** (`/home/tristan/gitters/LME/scratchpad/`, distinct from the above): 24 files, ~1.3 MB. **Confirmed untracked AND NOT gitignored** — `git check-ignore -v scratchpad/` returns no match ("NOT IGNORED"), and the repo's root `.gitignore` has no `scratchpad` entry anywhere in it. Contents include real map/review artifacts that exist nowhere else checked in this investigation: `flow-analyst-1.md` (28 KB), `flow-analyst-2.md` (30 KB), `req-mapper-1.md` (18 KB), `req-mapper-2.md` (22 KB), `round3-diff.txt` (48 KB), `round3-meta.json`, `round8-e2e-evidence.md` (21 KB), `round9-e2e-multihost.md` (22 KB), `round9-qemu-profiles.md` + `round9-qemu-profiles-v2.md`, `pr-body.md`, plus a stale `ocr.db.bak-20260917T004634Z` (1.0 MB DB backup). **This is a third risk category the "gitignored-or-ephemeral" hypothesis does not name**: not gitignored (so its absence from git history is a pure oversight, not a deliberate exclusion), not ephemeral-by-design (it persists across sessions, unlike `/tmp`), currently intact, but one `git clean -fd` away from silent, total, non-recoverable deletion with zero git trace.

---

## 5. ITERATION CHURN (re-derivation evidence)

Old/new and versioned-rerun pairs found in the session scratchpad, confirming the task's named examples and surfacing more of the same pattern:

| Base | Rework/rerun | Base exists? |
|---|---|---|
| `funcs_old.sh` | `funcs_new.sh` | both present |
| `run_old.sh` | `run_new.sh` | both present |
| `expo_old.sh` | `expo_new.sh` | both present |
| `out_old.txt` | `out_new.txt` | both present |
| `harness.sh` | `harness2.sh` | **base confirmed present** |
| `jsontest.sh` | `jsontest2.sh` | **base confirmed present** |
| `run-trixie-cluster-a2b2.sh` (+ `.log`) | `run-trixie-cluster-a2b2-run2.sh` (+ `-run2.log`, + `-FINDINGS.md`) | both present, full second cluster run + fresh findings doc |
| (not found under this name) | `map-meta-run2.json` | base not found in scratchpad |
| (not found under this name) | `install-cluster-run2.log` | base not found in scratchpad |
| (not found under this name) | `serve_v2.go` | base not found in scratchpad |

8 confirmed same-directory before/after pairs (6 with both halves verified present on disk) plus 3 more "-run2/v2"-named files whose predecessor was not found under a matching name in this directory (either overwritten in place or named differently) — at minimum **10 distinct instances** of a script, test, or full cluster install being redone and re-captured rather than reused, concentrated in the same ES-cluster/tailnet-VIP problem space flagged in §4.

---

## HYPOTHESIS VERDICT: REFINED

The core claim — **the durable git record is healthy** — is not just confirmed, it is confirmed more strongly than stated: 51 commits ahead of `main`, zero reverts, zero divergence (`merge-base` == `main` tip exactly), **and `rev-list --left-right --count origin/...HEAD` returns `0 0`**, meaning all 51 commits are already on `origin`, not merely sitting on local disk. That is the decisive citation: code is safe at the remote, not just "safe until this disk dies."

But the hypothesis's binary — "everything lost is gitignored (`.ocr/sessions/`, `.ocr/data/`) or ephemeral (`/tmp`), therefore only context/tooling/evidence is lost, never code" — is too clean for what the evidence shows. Three refinements:

1. **A location the binary doesn't name, holding real content, at real risk**: `/home/tristan/gitters/LME/scratchpad/` is untracked *and not gitignored* (§4) — 24 files including six map/review artifact files (`flow-analyst-*.md`, `req-mapper-*.md`, `round3/8/9-*.md`) with no copy in git and no gitignore rule protecting them from `git clean -fd`. It isn't lost yet, but it is neither "gitignored" nor "ephemeral" — it's simply exposed.
2. **A location entirely outside the repo**: PATCHES.md's FIX 1 lives in the globally-installed npm package (`~/.nvm/.../@open-code-review/cli/dist/dashboard/server.js`), explicitly documented as being wiped by the next `ocr` reinstall. The instructions to reapply it are durable (staged in git); the applied fix itself is not, and isn't covered by "gitignored or ephemeral" either.
3. **Inside the gitignored DB/dashboard layer itself, the loss is two-tier, not uniform**: most of what looks like "lost output" is a wiring/index gap — 98 reviewer `.md` files (1.6 MB) survive on disk, and PATCHES.md proves at least one file-backed row (id 12) had recoverable `notes` despite a null `output`. Only a bounded, precisely-countable slice — 26 of 101 reviewer rows with *both* `output` and `notes` null, and separately 81 of 101 rows with no per-instance `events/<id>.jsonl` transcript — has no DB-recoverable trace. The most recent, most alarming-looking instance of this (`flow-probe` et al.) is *not* a crash: all 15 of the DB's null-exit-code rows (9 flow-analyst + 6 requirements-mapper, 100% accounted for) finished normally with `notes` populated, from the single map-generation pass that fed map run 14, ending 4 minutes before this investigation began.

**So: code is confirmed safe (and remote-backed). "Lost progress" is confirmed to be concentrated in context/tooling/evidence, as hypothesized — but that ephemeral/gitignored layer is not the whole story. Two additional, evidence-backed loss surfaces exist outside it (an unignored working-tree scratchpad, and an out-of-repo global patch), and within the gitignored layer the loss is smaller and more specific than "everything" — a ~20-26-row DB gap and an 81-file journal gap, not a wholesale wipe.**

### Top 3 evidence-backed causes of "lost progress"

1. **Dashboard `output`-column wiring gap** (PATCHES.md, §3): reviewer/persona sub-agent output was never wired to `command_executions.output`; visible today as 81/101 rows with no per-instance journal file and 26/101 with no recoverable text anywhere in the DB. Mitigated by two stopgaps, but the durable fix (FIX 3) is undone, and the stopgap that touches the dashboard server lives outside git entirely (risk #2 above).
2. **Session splintering** (§2): the same branch/topic is spread across 3 separate date-stamped OCR session directories (09-16, 09-18, 09-21) plus the actively-running 09-18 session — no single continuous session/history view exists, which is itself a source of "where did that go" confusion independent of any data actually being missing.
3. **Untracked, unignored working-tree scratchpad** (§4): six real map/review artifacts exist only in `/home/tristan/gitters/LME/scratchpad/`, invisible to `git status` as "safe" in the way gitignored files at least signal intentional exclusion — these are one destructive-git-command away from silent loss with no history to recover from.

### Numbers not obtained
- Row-by-row reconciliation between the 81 file-less/output-less DB rows and the 98 surviving `rounds/**/reviews/*.md` files (would require matching by round+persona+instance-index; not done here, so the true "fully unrecoverable" count could be smaller than 26 if some of those 26 have a matching `.md`).
- Identity of the other 6 rows contributing to "20 HAS_FILE" beyond what was spot-checked (ids 2–11); not itemized past confirming the 20/81 split.
- Contents/diff of the 3 "-run2/v2" files in §5 against any predecessor that may exist under a different name or have already been overwritten — could not locate a same-named base file for `map-meta-run2.json`, `install-cluster-run2.log`, `serve_v2.go`.
