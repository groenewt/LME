# PATCHES — OCR dashboard "No output recorded." fix

Reversible record of surgical stopgap edits that make the OCR dashboard
command-detail card show a reviewer's `notes` instead of "No output recorded."

**Root cause** (proven): the card renders `command_executions.output` via
`e.output || "No output recorded."`. Reviewer rows journaled by
`ocr session start-instance` (`command = session-instance:{persona}-{n}`) never get
`output` written — the CLI persists only `--note` → the `notes` column; `output` is
written solely by the dashboard's own detached child-process stdout path, which
AI-host Task sub-agents never enter. So every reviewer row shows "No output recorded."

## Install paths (this machine)

- OCR CLI package (dist-only): `/home/tristan/.nvm/versions/node/v26.7.0/lib/node_modules/@open-code-review/cli`
  - `ocr` bin → `<CLI>/dist/index.js` (cliVersion 2.5.0)
  - Dashboard server: `<CLI>/dist/dashboard/server.js`
  - Client bundle: `<CLI>/dist/dashboard/client/assets/index-B0k81q2b.js`
- DB: `/home/tristan/gitters/LME/.ocr/data/ocr.db`
- Skill: `/home/tristan/gitters/LME/.ocr/skills/SKILL.md`

## ⚠️ These edits are STOPGAPS — re-apply after any `ocr` reinstall/update

The `@open-code-review/cli` package ships only `dist/`. `npm i -g @open-code-review/cli`
or an `ocr` self-update overwrites `dist/dashboard/server.js`. `ocr init` can rewrite the
managed CLAUDE.md block and regenerate `.ocr/skills/`. **Both edits below are therefore
regenerable and must be re-applied after an update.** The durable fix belongs upstream
(see FIX 3).

---

## FIX 1 — server-side `notes` fallback (chosen; no client change)

File: `/home/tristan/.nvm/versions/node/v26.7.0/lib/node_modules/@open-code-review/cli/dist/dashboard/server.js`
Location: `router.get("/history")` → `getCommandHistory(db, limit).map(...)` (~line 35583).
The `/history` route already shapes each row (spreads `...persisted`, adds derived
fields), so we override `output` **after** the spread. The client reads `e.output`
unchanged; `notes` is already in the JSON payload (route returns `SELECT ce.*` spread),
so no client edit is needed.

Verbatim `diff -u` (line numbers are from cliVersion 2.5.0's `server.js` and WILL shift
after a package update — locate by the surrounding context, not the line number; the
context form applies with `patch --fuzz=3` or by hand, NOT necessarily `patch -p0`):

```diff
@@ -35584,6 +35584,13 @@
         const { workflow_completeness, ...persisted } = row;
         return {
           ...persisted,
+          // STOPGAP (no-output-recorded fix): reviewer `session-instance:*` rows
+          // never have `output` written (start/end-instance persist only --note →
+          // `notes`). Fall back to `notes` AFTER the `...persisted` spread so the
+          // dashboard command-detail card (`e.output || "No output recorded."`)
+          // renders the reviewer's note. Re-apply after `ocr` reinstall/update —
+          // see .ocr/PATCHES-no-output-recorded.md.
+          output: persisted.output ?? persisted.notes ?? null,
           duration_ms: row.finished_at && row.started_at ? new Date(row.finished_at).getTime() - new Date(row.started_at).getTime() : null,
           // Derived from (exit_code, event-sourced workflow completeness) —
           // single source of truth shared with the live `command:finished`
```

**To revert:** delete the comment block and the `output: persisted.output ?? persisted.notes ?? null,` line.

### Why `/active` was deliberately NOT changed (documented deviation from the task text)
The task asked to also patch the `/active` payload. It was intentionally left alone —
this is correct, not an incomplete patch:
- `/active` is served from `getActiveCommands()` (server.js ~line 34657), which maps the
  **in-memory** `activeCommands` map, not DB rows. Its entries are
  `{ execution_id, command, started_at, output: entry.outputBuffer }` — there is **no
  `notes` field** and no DB read.
- Reviewer `session-instance:*` rows are journaled by the CLI directly to SQLite; they
  never enter `activeCommands`. So `entry.notes` would be permanently `undefined` — a
  `?? entry.notes` fallback there is pure dead code that changes nothing.
- The reported symptom is therefore fully closed by the `/history` edit alone.

### Alternate (NOT applied) — minimal client edit
If a future build shapes `/history` differently and the server edit can't be placed,
the equivalent client-only change is: in
`<CLI>/dist/dashboard/client/assets/index-B0k81q2b.js`, change **both** occurrences of
`e.output||"No output recorded."` → `e.output||e.notes||"No output recorded."`.
(`notes` IS present in the `/history` JSON payload; the client just doesn't reference it
today — verified `.notes` = 0 occurrences in the current bundle.) The server edit is
preferred; the client bundle is minified and its asset hash changes on rebuild.

### Edge case for the upstream author (FIX 3)
`??` (not `||`) is used to match the task spec. If a row ever lands `output = ''`
(empty string), `??` keeps the empty string and the client's `e.output || ...` would
show "No output recorded." again. Harmless for current data (reviewer rows are
`output IS NULL`), but worth handling in the durable fix.

---

## FIX 2 — protocol: always attach a meaningful `--note` (SKILL.md)

File: `/home/tristan/gitters/LME/.ocr/skills/SKILL.md`
Location: Journaling section (~line 136, after the sequential/bind-vendor-id paragraph).

Verbatim `diff -u` (locate by context — line numbers shift if `ocr init` regenerates the skill):

```diff
@@ -135,6 +135,15 @@
 **skip** `bind-vendor-id`. Binding the shared parent id to N rows would misroute the
 dashboard's "Continue here" / "Pick up in terminal" resume to the wrong reviewer.
+
+**Always attach a meaningful `--note` on `end-instance`**: the dashboard's
+command-detail card renders each instance row's captured output, but reviewer
+sub-agents produce no `output`, so it falls back to the row's `notes`. For **every**
+reviewer/agent, the orchestrator MUST call `ocr session end-instance ... --note "<one-line
+summary> — rounds/round-N/reviews/<persona>.md"`: a one-line result summary AND the path
+to that reviewer's `rounds/**/reviews/<persona>.md`. Without the note the card shows
+"No output recorded." for that reviewer. (The `notes` fallback is a dashboard patch —
+see `.ocr/PATCHES-no-output-recorded.md`.)
 
 > **Host-specific notes**: Claude Code passes a per-instance model via subagent `model:`
```

**To revert:** delete the added paragraph.

---

## FIX 3 — DURABLE fix (upstream, OUT OF SCOPE here)

The real gap is that no code path persists a reviewer sub-agent's output. The durable
fix lives in the OCR package source (not this dist), roughly:

- `endInstanceSubcommand` (`<CLI>/dist/index.js` ~:36429): add `--output <text>` /
  `--output-file <path>` / stdin option that runs
  `UPDATE command_executions SET output = ? WHERE uid = ?`.
- SKILL step: orchestrator pipes each reviewer's transcript (or its `reviews/*.md`) to
  that option on completion.

Then the existing card renders the full transcript with no server/client patch, and
FIX 1/FIX 2 become unnecessary. Also handle the `output = ''` empty-string edge noted above.

---

## Verification performed (proof, not assumption)

- Two operator dashboards were running (`ocr-dashboard`, PIDs 671108 @ 127.0.0.1:4173,
  764687 @ :4174). They hold the OLD code in memory; they were **NOT** restarted
  (restart goes through `ocr dashboard`, whose single-instance guard reaps the PID in
  `.ocr/data/dashboard.pid` — restarting would kill an operator dashboard, and they run
  in interactive terminals that can't be re-attached). Left for the operator.
- BEFORE (running OLD-code :4173, live DB): `/api/commands/active` → `running_count: 0`
  (no detached spawn mid-flight); `/api/commands/history` row id 12 →
  `output: null`, `notes: "principal-1 round-3: 0 blockers, ..."`.
- AFTER (patched `server.js` run standalone on port 4199 against a consistent
  `sqlite .backup` snapshot of the same DB in an isolated temp `.ocr` — its own
  `dashboard.pid` removed so it reaped nothing): `/api/commands/history` →
  - id 12 `output` = `"principal-1 round-3: 0 blockers, 3 should_fix, 1 suggestion, 1 style; R1 Met, R2 Not Met"` (was null)
  - id 16 `output` = `"security-1 round-3 review complete: 0 blockers, 2 should_fix, 4 suggestions"`
  - id 2 (rounds 1–2, `notes` NULL) `output` still `null` → still "No output recorded."
    (expected; FIX 2 fills notes for future rounds).
- Isolated instance was killed; both operator dashboards confirmed still alive; temp
  copy removed. `node --check server.js` passes.

## Operator action required

Restart the OCR dashboard(s) so the running server picks up the patched
`server.js`: stop the current `ocr dashboard` process(es) and run `ocr dashboard` again.
