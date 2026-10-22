# `.ocr/` top-level surface — evaluated inventory

> **Superseded-in-part (as-of 06:23Z):** this file counted `.ocr/utilities/` at **11** scripts at scan time; it is now **81** files = **54** curated (`73 = 54 + 5 + 14`; +3 fidelity checks rescued post-HC-4) + **26** the operator's mid-pass `scratchpad/` reorg + 1 README. Authoritative catalog: `../../utilities/README.md`; treat it as the source of truth for the utilities surface — the rest of this inventory stands. Authoritative whole-`.ocr` totals: `../MASTER-INDEX.md` §1 + §8.

**Scope:** everything under `/home/tristan/gitters/LME/.ocr/` EXCEPT `.ocr/sessions/` (owned by sibling
indexing workers) and EXCEPT `.ocr/index/` itself (the indexing/compaction swarm's own meta-layer —
self-referential, not a subject of this inventory; see the Reconciliation note at the end for how it's
handled in the numbers).

**Method:** every file below was opened and read, not inferred from its name. All commands were
read-only (`sqlite3 ... ?mode=ro`, `find`, `cat`/`head`/`diff`/`stat`). No file was deleted, moved, or
written outside `.ocr/index/areas/top-level.md`. No git state was changed.

**Snapshot discipline — the tree is LIVE:** this repo had other agents actively writing into `.ocr/`
while this inventory was being taken. Two things appeared mid-scan that were **not** present at the
start: `.ocr/utility/derive_consumer_requirements.py` (born 2026-09-22 00:25:09 local, confirmed by
`stat`) and `.ocr/index/MASTER-INDEX.md` (a sibling coordinator's rollup, appeared between two of my own
`find` checks). All counts in this file are a single, tight, final snapshot taken
**2026-09-22T05:27:43Z–05:28:06Z UTC**; anything that changed after that is not reflected here.

---

## 1. Top-level config/doc files (6 — listed individually)

| file | what it is | authored vs tooling | status | disposition |
|---|---|---|---|---|
| `cli-config.json` | `{configuredTools:["claude","cursor","opencode"], lastUpdated, cliVersion:"2.5.0"}` — which AI-CLI surfaces OCR is wired for. | tooling-managed (machine-written timestamp/version) | live-config | keep |
| `config.yaml` | OCR's per-project config: context-discovery file list, (commented-out) review rules, `default_team` reviewer counts, `models.aliases`, `code-review-map.agents` counts, `output.session_dir`, `discourse`, `github`, `dashboard`. | **mixed** — ships as an `ocr init` template (most sections commented out) but carries live operator edits: `default_team` (lines 70–77) and `code-review-map.agents` (146–152) both carry a dated comment *"SWARM is the mechanism (operator directive 2026-09-21): 12+ reviewers/round, NOT light"*; `models.aliases` (98–126) is a 27-entry hand-built model-alias table (openai-gpt-5.6-sol/luna, 24 ollama-cloud entries, cursor-grok-4.6-xhigh) — the same 27 ids as `model-profiles.yaml`'s 27 `profiles[]` entries below; the two files mirror each other exactly. | live-config | keep |
| `model-profiles.yaml` | `schema_version:1`, `active_profile` pointer + 27 `profiles[]` entries (surface `opencode`/`cursor-agent`, provider, model string, `status: active\|placeholder`). | tooling-managed/generated — every entry's `source` field literally cites the CLI probe that produced it (`ocr models list --vendor opencode --json`, `cursor-agent --list-models`); operator only flips `active_profile`. | live-config | keep |
| `reviewers-meta.json` | `schema_version:1`, `generated_at:"2026-09-21T20:40:35.824177+00:00"`, `reviewers[]` — 29 entries (id, name, tier, icon, description, focus_areas, is_default, is_builtin, +known_for/philosophy for the 10 "persona" tier: anders-hejlsberg, john-ousterhout, kamil-mysliwiec, kent-beck, kent-dodds, martin-fowler, rich-hickey, sandi-metz, tanner-linsley, vladimir-khorikov). | **derived** — proof: the 29 `id`s match exactly the 29 files in `skills/references/reviewers/*.md` (see §3), and `commands/sync-reviewers.md` documents the exact generation path: "Reads all reviewer markdown files in `.ocr/skills/references/reviewers/`... pipes the result to the CLI for validated, atomic persistence to `reviewers-meta.json`." One entry (`docs-writer`) is marked `"is_builtin": false` — the sole non-built-in reviewer; all other 28 are `true`. | derived | keep |
| `PATCHES-no-output-recorded.md` | Hand-authored incident/patch log: root-cause + reversible stopgap fix for the dashboard's "No output recorded." bug. FIX 1 patches an **installed npm package file outside this repo** (`~/.nvm/.../@open-code-review/cli/dist/dashboard/server.js`, adds `output: persisted.output ?? persisted.notes ?? null`); FIX 2 adds a protocol paragraph to `skills/SKILL.md` (verified present, see §3); FIX 3 (durable upstream fix) is explicitly deferred/out of scope. Includes a verification log (two live dashboards, PIDs 671108/764687 on ports 4173/4174) and ends "Operator action required: restart the OCR dashboard(s))." | operator/agent-authored | doc | keep — **note:** current `data/dashboard.pid`=540741 and `data/server-port`=4174 do **not** match either PID this doc verified against (671108, 764687), meaning the dashboard has restarted at least once since. Whether FIX 1 is live in the *currently running* server process cannot be confirmed from a static file read. |
| `.gitignore` | OCR-managed block: `sessions/`, `data/`, `*.db-shm`, `*.db-wal` inside a `# OCR:START — managed by open-code-review ... # OCR:END` marker. | tooling-managed | live-config | keep — byte-**identical** (verified via `diff`, output "IDENTICAL") to `skills/assets/ocr-gitignore` — that file is the template this one is stamped from on `ocr init`. |

**Gitignore reality check:** the task brief says ".ocr/.gitignore: it lists sessions/ and data/" — true, but there is a **second, independent** ignore mechanism the brief didn't anticipate: the **repo root** `.gitignore:23` has `**/__pycache__/`, which is what actually ignores `tools/__pycache__/populate_agent_row.cpython-313.pyc` (§4) — `.ocr/.gitignore` never mentions `__pycache__`.

---

## 2. `commands/` — 11 files (glob-counted: `commands/*.md` = 11)

All depth-2, all `/ocr:*` slash-command definitions shipped by the tool. One-line purpose from each file's frontmatter `description:`:

| file | purpose |
|---|---|
| `address.md` | Address code review feedback — corroborate, validate, and implement changes from a review's final.md. |
| `create-reviewer.md` | Create a new custom reviewer from a natural language description. |
| `doctor.md` | Check OCR installation and verify all dependencies are available. |
| `history.md` | List past OCR review sessions. |
| `map.md` | Generate a Code Review Map to help navigate large, complex changesets. |
| `post.md` | Post the current OCR review to a GitHub PR. |
| `review.md` | Run an AI-powered multi-agent code review on your changes. |
| `reviewers.md` | List all available reviewer personas for code review. |
| `show.md` | Display a past OCR review session. |
| `sync-reviewers.md` | Sync reviewer metadata from markdown files to reviewers-meta.json for the dashboard. |
| `translate-review-to-single-human.md` | Translate a multi-reviewer code review into a single human-voice GitHub PR comment. |

Authored: tooling-shipped. Status: doc (prompt/instruction markdown, not structured config). Disposition: keep.

---

## 3. `skills/` — 47 files total (15 within the maxdepth-3 window, 32 beyond it)

`SKILL.md` (frontmatter: `author: spencermarx`, `repository: github.com/spencermarx/open-code-review`,
`version:"2.5.0"` — matches `cli-config.json`'s `cliVersion`) is the primary entrypoint; the project's
`/home/tristan/gitters/LME/CLAUDE.md` managed block points AI assistants at
`.ocr/skills/SKILL.md`. `AGENTS.md` is an alternate/legacy quick-reference entrypoint (Quick Start +
command table + workflow summary) covering the same ground. Both: tooling-shipped, status=doc, keep.

**`assets/` (2 files, listed individually):**
- `ocr-gitignore` — the template `.ocr/.gitignore` is stamped from (verified byte-identical, §1).
- `reviewer-template.md` — `{placeholder}`-parametrized skeleton for authoring a new custom reviewer, used by `/ocr:create-reviewer`.
Both tooling-shipped, doc, keep.

**`references/` top-level (11 files, glob-counted: `references/*.md` = 11 — excludes the `reviewers/` and `map-personas/` subdirs below):**
`context-discovery.md`, `discourse.md`, `final-template.md`, `map-agent-task.md`, `map-template.md`,
`map-workflow.md`, `reviewer-task.md`, `session-files.md`, `session-state.md`, `setup-guard.md`,
`workflow.md`. Each is a sub-skill loaded at a specific workflow phase (setup-guard.md is explicitly
"a sub-skill that MUST be called at the start of ALL OCR skills and commands"). `session-state.md` is
the direct documentation source for `data/ocr.db` (§5): *"OCR uses SQLite as the primary state store
for reliable progress tracking... managed through the `ocr state` CLI commands."* `workflow.md`
documents the 8-phase review pipeline and an explicit anti-pattern: don't end a turn mid-pipeline
between phases 4–7. All 11: tooling-shipped, doc, keep.

**`references/reviewers/` (29 files, glob-counted — BEYOND the maxdepth-3 reconciliation window, depth 4):**
`accessibility, ai, anders-hejlsberg, architect, backend, data, devops, docs-writer, dx, frontend,
fullstack, infrastructure, john-ousterhout, kamil-mysliwiec, kent-beck, kent-dodds, martin-fowler,
mobile, performance, principal, quality, reliability, rich-hickey, sandi-metz, security, staff-engineer,
tanner-linsley, testing, vladimir-khorikov`.md — the **authoritative source** `reviewers-meta.json` is
generated from (§1); each is a reviewer-persona system prompt (specialist/holistic/persona tiers; the
persona-tier files like `anders-hejlsberg.md`/`kent-beck.md` carry `known_for`/`philosophy` framing).
Tooling-shipped, doc, keep.

**`references/map-personas/` (3 files, glob-counted — BEYOND the maxdepth-3 window, depth 4):**
`architect.md` (Map Architect — orchestrates the Code Review Map), `flow-analyst.md` (traces
upstream/downstream dependencies), `requirements-mapper.md` (maps changes to requirements/specs).
Cross-referenced by `config.yaml`'s `code-review-map.agents.flow_analysts`/`requirements_mappers`
counts. Tooling-shipped, doc, keep.

---

## 4. `tools/` — 2 files (listed individually)

| file | what it is | authored | status | disposition |
|---|---|---|---|---|
| `populate_agent_row.py` | 303-line CLI (read in full). Backfills one `command_executions` row's `output` column AND installs `data/events/<id>.jsonl` **without restarting the dashboard**. Three timeline sources: `--events-file` (pre-built, re-validated JSON per line), `--transcript` (converts a **real** Claude Code stream-json sub-agent transcript into the dashboard's event vocabulary: `message`/`thinking_delta`/`tool_call`/`tool_result`/`notice`), `--sparse` (emits a truthful 3-event notice/message/notice journal from known facts only — its own docstring: "No fabricated tool events"). Writes atomically (`.tmp` → `os.replace`). Explicitly documented as the operational fix in `PATCHES-no-output-recorded.md` (§1) and pointed to from `utilities/README.md` (§6): *"board row backfill \| `.ocr/tools/populate_agent_row.py` \| WAL-safe backfill... \| no (writes the local OCR board DB/jsonl, not a deploy target)"*. | operator/agent-authored (not part of the upstream `@open-code-review/cli` package) | doc (maintenance script) | keep |
| `__pycache__/populate_agent_row.cpython-313.pyc` | Compiled bytecode cache — proof the script has actually been executed at least once. | tooling-managed (CPython auto-generated) | derived | note — ignored by **root** `.gitignore:23` `**/__pycache__/`, not by `.ocr/.gitignore` (§1) |

---

## 5. `data/` — 38 files (5+1 listed individually, 2 globs, 1 empty dir)

**Gitignored wholesale**: `.ocr/.gitignore`'s `data/` line covers this entire subtree (confirmed via
`git check-ignore -v .ocr/data` → matched `.ocr/.gitignore:3:data/`), plus belt-and-suspenders
`*.db-shm`/`*.db-wal` entries.

**Authored (applies to every item in this section):** tooling-managed — everything under `data/` is
written by the `ocr` CLI or the dashboard server at runtime; nothing here is hand-authored.

**`ocr.db` + `ocr.db-shm` + `ocr.db-wal` (listed individually, 3 files):** SQLite, WAL mode active
(`ocr.db`=3,653,632 B; `ocr.db-wal`=4,124,152 B of uncheckpointed writes — larger than the base file;
`ocr.db-shm`=32,768 B). Read via `sqlite3 "file:...?mode=ro" ...` only (never opened read-write).
**18 tables**, row counts:

| table | rows | table | rows | table | rows |
|---|---|---|---|---|---|
| `chat_conversations` | 1 | `map_files` | 1081 | `review_rounds` | 27 |
| `chat_messages` | 2 | `map_runs` | 15 | `reviewer_outputs` | 76 |
| `command_executions` | 128 | `map_sections` | 150 | `schema_version` | 14 |
| `markdown_artifacts` | 161 | `orchestration_events` | 276 | `session_completeness` | 5 |
| `review_findings` | 302 | `sessions` | 5 | `user_file_progress` | 0 |
| `user_finding_progress` | 0 | `user_notes` | 0 | `user_round_progress` | 5 |

Per `skills/references/session-state.md`: "the primary state store for reliable progress tracking."
Authored: tooling-managed (all rows written by the `ocr` CLI/dashboard). Status: derived. Disposition:
note — live, WAL-active; `populate_agent_row.py`'s own safety rules (§4) explicitly forbid
`VACUUM`/`wal_checkpoint`/touching `-shm`/`-wal` on the live DB.

**`dashboard.pid`** (listed individually) = `540741`; **`server-port`** (listed individually) = `4174`.
Current live-dashboard pointers — do **not** match the PIDs (671108/764687) `PATCHES-no-output-recorded.md`
verified against, though the port (4174) matches one of the two (§1). Status: telemetry. Note.

**`events/` (glob-counted: `events/*.jsonl` = 30):** one journal per `command_executions.id`, filename =
`<id>.jsonl`. Keyed by `executionId` — verified by opening two: every line of `1.jsonl` carries
`"executionId":1`, every line of `87.jsonl` carries `"executionId":87`. **None are empty** — line
counts range from 3 (minimal `session_id`-type stub, ids 2–11) up to two rich transcripts: `1.jsonl`
(11,166 lines) and `87.jsonl` (4,619 lines); ids 12–29 fall in between (26–165 lines, minimum at
id 17). Coverage gap:
`command_executions` holds 128 rows (ids 1–128) but only **30** have any journal (ids 1–29, 87) — **98
rows have none**. This is exactly the gap `PATCHES-no-output-recorded.md` documents (reviewer/agent
sub-process rows never enter the dashboard's own output-capture path). I did **not** find evidence
either way of whether `87.jsonl` was hand-backfilled by `populate_agent_row.py` or captured natively —
its content alone can't distinguish the two, so I'm not asserting a mechanism. Status: telemetry. Note.

**`exec-logs/` (glob-counted: `exec-logs/*.log` = 2):** raw Claude-Code stream-json session
transcripts, one per dashboard-hosted `session_id`: `a00ee466-*.log` (2,389,649 B, session
`6539b11f`, 2026-09-16) and `e2ac9b6e-*.log` (1,278,458 B, session `9c9d987f`, 2026-09-18 →
matches the current `dashboard.pid`/`server-port`). These are the full raw transcripts referenced by
`PATCHES-no-output-recorded.md`'s verification section. Status: telemetry. Note — full conversation
transcripts, same sensitivity as any session log.

**`.cache/command-history.jsonl`** (listed individually, 1 file): 6-line NDJSON log of
dashboard-detached CLI start/finish events (`v, uid, db_id, command, args, exit_code, started_at,
finished_at, is_detached, event, writer:"dashboard"`). First row is the detached spawn of
`ocr map recent commits --fresh`, `db_id:1` — matches `command_executions` id=1 and `events/1.jsonl`'s
rich transcript exactly. Status: telemetry. Note.

**`dashboard-active-spawn/`**: empty directory, 0 files, confirmed at every snapshot taken during this
scan. Name implies a marker/lock dir for an in-flight dashboard-launched detached command; empty = none
in flight right now. Status: telemetry (runtime marker). Note.

---

## 6. `utilities/` (plural) — 11 files, listed individually — NOT OCR-tool content

Per its own `README.md` (read in full): a **durable catalog compiled 2026-09-21 by a prior "OCR run-14
indexing/compaction" pass**, centralizing **LME project deploy/ops tooling** ("stranded in a session
scratchpad" with no repo-canonical home) — this is not part of the shipped OCR review tool; a previous
swarm chose `.ocr/utilities/` as its durable home. Every copied file carries a recorded sha256 for
drift detection; several **mutate live systems if run** (README's own warning table):

| file | purpose | executes-live? |
|---|---|---|
| `README.md` | the catalog/index document itself, incl. a warning table and selection criteria | — |
| `airgap/airgap_cut.sh` | enforce airgap (cut default route) for a non-root run | **yes** — mutates host routing |
| `airgap/airgap-cut-and-prove.sh` | same, for a root run, + sampler + pre-cut sanity curl | **yes** — mutates host routing |
| `gate/gate_dryrun.sh` | preview gate derivation (ingress ports/VIP endpoints) | no (prints only) |
| `gate/gate_funcs.sh.snapshot` | extract of 3 funcs from canonical `testing/e2e/deploy_gate.sh` | no — **MAY DRIFT**, repo is source of truth |
| `gate/run_gate.sh` | invokes canonical `deploy_gate.sh` for one leg (hardcoded target/key/flags — "invocation template, edit before reuse") | **yes** — drives live deploy pipeline |
| `vip/define_services.py` | allocate Tailscale VIP-Services via REST API | **yes**, but only with `--apply`; dry-run default |
| `vip/derive_check.sh` | read-only diagnostic probe (service name/count cross-check) | no |
| `vip/derive.py.snapshot` | extract of `derive_published_ports()` from canonical `deploy_gate.sh` | no — **MAY DRIFT** |
| `vip/patch_acl.py` | additive tailnet-ACL hujson patcher (file→file, byte-exact additivity proof) | no (transform only) |
| `vip/restore_acl.sh` | **highest blast radius** — force-`POST`s a local ACL snapshot over the live tailnet ACL, **no `If-Match`** | **yes** |

Authored: agent/operator-authored (prior swarm), verbatim `cp -p` from scratchpad. Status: doc (the
scripts are executable tooling, not OCR config/state — no enum value fits "script" precisely).
Disposition: keep — but flagged: **the entire `utilities/` tree is untracked** (`git status` → `??
.ocr/utilities/`), unlike every genuine OCR-tool file in this inventory (all staged `A`). I did not
execute any file in this directory — per the task's hard constraint and the README's own warning.

---

## 7. `utility/` (singular) — 1 file — LIVE CONCURRENT-WRITE FINDING

`derive_consumer_requirements.py` (327 lines, read in full): a manifest-driven, self-declared read-only
script (*"READ-ONLY. Never writes to manifests/ or ansible/"*) that loads `manifests/services/*.yml`,
computes transitive requires/wants closures for consumer services (default: `log-analyzer`,
`dashboard`), derives per-backend-leg routing/TLS/scheme/tailnet-front recommendations, unions required
secrets, and diffs against a hardcoded "GAP-1..4" baseline (routing/tls=`{elasticsearch}`,
secrets=`{elastic, litellm_master_key}`), printing Markdown to stdout.

**This file was not present when this scan started.** `stat` shows Birth = `2026-09-22 00:25:09` local
— it appeared roughly midway through this inventory (confirmed absent from my first `find -maxdepth 1`
snapshot, present in every check after). This is direct, timestamped evidence of a **different,
concurrently-running agent** writing into `.ocr/` during this indexing pass — unrelated to §6's
`utilities/` (that catalog is dated 2026-09-21 and self-described as closed/compiled; this one is
fresh, un-catalogued, and its content matches ongoing "multi-machine consumer split" work, not
indexing/compaction work).

Authored: operator/agent-authored, in-progress elsewhere. Status: doc (script). Disposition: **note —
flag to the swarm coordinator**: `utility/` (singular) vs `utilities/` (plural) is a one-character,
easily-confused near-duplicate directory name; both are untracked (`?? .ocr/utility/`); the next
indexing pass over this area should re-snapshot this specific path since it was mid-write when
observed here, and should check whether `utility/` was meant to merge into `utilities/`.

---

## 8. `index/` — self-referential, excluded from the inventoried surface

`.ocr/index/` is the indexing/compaction swarm's own coordination and output area (this file lives at
`.ocr/index/areas/top-level.md`; a sibling has already placed `areas/sessions-16-21.md` there). A
sibling coordinator agent placed `.ocr/index/MASTER-INDEX.md` here (92+ lines) during this scan,
timestamped `as-of 2026-09-22 05:25:11Z`, self-described as living at `.ocr/index/` "because it is
git-visible (durable, trackable)" in contrast to gitignored `sessions/`/`data/`. It independently
states the "top-level (non-sessions)" bucket should total **116** files (its own breakdown: commands
11 · skills 47 · data 38 · tools 2 · loose 6 · utilities ~12), a figure that **excludes `index/` itself**
by its own taxonomy — see Reconciliation below for how this cross-checks against this file's count.
Authored: swarm-agent-authored. Status: doc. Disposition: keep (it is this task's actual deliverable),
but out of scope for "the `.ocr` top-level surface" as a subject — it's the index *of* that surface,
not part of it.

---

## Reconciliation identity

**Primary — per the task's literal command, single snapshot 2026-09-22T05:27:43Z–05:28:06Z UTC:**

```
find /home/tristan/gitters/LME/.ocr -maxdepth 3 -type f -not -path '*/sessions/*' | wc -l
→ 85
```

| bucket | listed individually | glob-counted |
|---|---:|---:|
| §1 top-level config/doc | 6 | — |
| §2 `commands/*.md` | — | 11 |
| §3 `skills/` (SKILL.md+AGENTS.md=2, assets/*=2, `references/*.md`=11) | 4 | 11 |
| §4 `tools/` | 2 | — |
| §5 `data/` (5 singletons + `.cache/command-history.jsonl`=1; `events/*.jsonl`=30 + `exec-logs/*.log`=2; `dashboard-active-spawn/`=0) | 6 | 32 |
| §6 `utilities/` (plural) | 11 | — |
| §7 `utility/` (singular) | 1 | — |
| §8 `index/MASTER-INDEX.md` (meta-layer, counted here only because the task's literal find command doesn't exclude it — see cross-check below) | 1 | — |
| **subtotal** | **31** | **54** |

**Total = 31 + 54 = 85 = 85 found. Residue = 0.**

**Outside the maxdepth-3 window** (inventoried in §3 prose, not in the count above):
`skills/references/reviewers/*.md` = 29, `skills/references/map-personas/*.md` = 3 → **32 files at depth 4**.

**Full-tree total**, same snapshot (`find .ocr -type f -not -path '*/sessions/*' | wc -l`) = **117** = 85 + 32. Confirmed by direct recount, not arithmetic alone.

**Independent cross-check:** `.ocr/index/MASTER-INDEX.md` (§8), computed 3 minutes earlier by a
different agent, states the "top-level (non-sessions)" bucket = **116** — which is exactly my full-tree
117 **minus the 1 file that bucket's own taxonomy excludes** (`index/MASTER-INDEX.md` itself, the
meta-layer describing the surface rather than belonging to it). Two independently-run inventories agree
to the file.

**Nothing could not be classified.** The only open items are the two flagged as live/in-progress rather
than unclassifiable: `utility/derive_consumer_requirements.py` (§7, a different agent's work-in-progress,
timestamped mid-scan) and the exact current in-memory state of the running dashboard server re: whether
`PATCHES-no-output-recorded.md`'s FIX 1 is still applied after its PID changed (§1/§5).
