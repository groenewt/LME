# Session `2026-09-22-fix-debian-13-selinux-apt` — Index Area: Codex-worktree hostile review (round-1)

**Author:** INDEXING sub-lane (per-area detail worker for the `.ocr` MASTER-INDEX).
**As-of (reconciliation instant):** `2026-09-22 ~22:01Z`.
**Scope:** `/home/tristan/gitters/LME/.ocr/sessions/2026-09-22-fix-debian-13-selinux-apt/` only —
the on-disk directory of the **bare-id / ACTIVE** twin. Sibling `.ocr` areas (other sessions, the
top-level surface, map runs) are out of scope; see `../MASTER-INDEX.md`.
**Constraint declaration:** READ-ONLY on everything except this file. No host/ssh/MCP access, no
`ocr state` transition, no git state-changing command, no deploy. Nothing existing was modified,
moved, or deleted. This file is the **only** write; it adds 1 file to `.ocr/index/` and is **not**
counted in the 424 below (which is the session tree, not the index).

---

## 0. What this session is

A **hostile static review of an ACTIVE Codex worktree**, not of the branch checkout. Per
`context.md:4-5` and `final.md:4-5`: target = frozen snapshot of the live worktree
`.worktrees/observability-implementation` (branch `implement/observability-integration`), base
commit **`2b3c96d`**, produced by a Codex session under the operator's **manifest-reconciliation
directive** (`requirements-src/2026-09-22-manifest-reconciliation.md`). Reviewers read **only** the
frozen `snapshot/`; the live worktree was off-limits (Codex still writing it).

Snapshot integrity: **digest `f1e86eda…`** — verified on disk to be
`sha256(SHA256SUMS.txt)` (`DIGEST.txt` == `sha256sum SHA256SUMS.txt` == `f1e86eda97ac…c8a7ab58`),
where `SHA256SUMS.txt` is the 365-entry per-file hash manifest of the changeset (34 modified-full +
327 untracked + 4 snapshot-metadata list files).

The changeset is a large parallel-framework build (I count **175 `.py` files** under
`snapshot/untracked/`; `context.md:16` characterizes it as "~200 new modules") under `lme_lab/`,
`lme_sources/`, `lme_telemetry/`, `lme_security/`, `lme_identity/`, `lme_sink_proxy/`,
`scripts/postgresql_platform/`, plus new Ansible roles, new `manifests/`, new installer selectors,
and large new test suites — laid on top of 34 modified tracked files (`context.md:11-24`).

## 1. Reconciled file count (residue 0)

`find <session dir> -type f | wc -l` = **424** (re-confirmed at the as-of instant;
`find ! -type f ! -type d` = **0**, so no symlink/special file escaped the `-type f` count).

| bucket | files |
|---|---:|
| root docs — `context.md`, `discovered-standards.md`, `requirements.md` | 3 |
| `requirements-src/` — 2 plan `.md` (`2026-09-22-manifest-reconciliation.md`, `2026-09-22-observability-implementation.md`) + 4 `.temp.REBUTTAL.0N.md` | 6 |
| `rounds/round-1/` root — `agent-ids.txt`, `final.md`, `discourse.md`, `round-meta.json` | 4 |
| `rounds/round-1/reviews/` — 12 reviewer `.md` (principal-1..4, quality-1..4, security-1..2, testing-1..2) | 12 |
| `rounds/round-1/snapshot/` — the frozen review input (§2) | 399 |
| **total** | **424** |

`3 + 6 + 4 + 12 + 399 = 424`. **Residue 0.**

### 2. `snapshot/` composition (bucketed; ~400 files not listed individually)

`find snapshot -type f | wc -l` = **399**, bucketed by top-level subdir + snapshot-root metadata:

| bucket | files |
|---|---:|
| snapshot-root metadata — `DIGEST.txt`, `SHA256SUMS.txt`, `tracked.diff`, `modified.list.txt`, `tracked.name-status.txt`, `untracked.list.txt` | 6 |
| `modified-full/` (full copies of modified tracked files) — `ansible/`16, `manifests/`9, `lme-dashboard/`4, `lme-log-analyzer/`3, `testing/`2, `scripts/`1, `install.sh`1 | 36 |
| `untracked/` (new files) — `ansible/`87, `config/`70, `testing/`58, `lme_lab/`43, `scripts/`19, `lme_sources/`18, `lme_security/`12, `lme_telemetry/`12, `lme-dashboard/`11, `lme_identity/`6, `tests/`6, `manifests/`3, `lme_sink_proxy/`3, `docs/`2, `__pycache__/`1, + 6 loose (`AGENTS.md`, `lme_hertzbeat.py`, 4 `.temp.REBUTTAL.0N.md`) | 357 |
| **snapshot total** | **399** |

`6 + 36 + 357 = 399`. **Residue 0.**

**Two-scope note (physical vs logical — mirrors the MASTER-INDEX 217/186 framing).** The
reviewers' and snapshot manifest's **logical changeset is 361 files** (`34` modified tracked +
`327` untracked; stated at `final.md:6` and `context.md:6`, and exactly the `SHA256SUMS.txt` content
minus its 4 metadata rows). The **physical mirror is 399**. The gap is fully accounted:
`361 (logical changeset) + 32 (byte-compiled __pycache__/*.pyc the copy tooling pulled in, git-
and manifest-excluded: 2 under modified-full/, 30 under untracked/) + 6 (snapshot-root metadata,
of which SHA256SUMS.txt + DIGEST.txt are not self-hashed) = 399`. Same tree, two scopes — do not
conflate the `361` figure with the on-disk count.

## 3. Round-1 outcome (CLOSED)

From `round-meta.json` (`verdict`, `synthesis_counts`, `reviewers[]`) and `final.md:22-24`, which
agree:

- **VERDICT: REQUEST CHANGES** — **2 blockers · 10 should-fix · 7 suggestions.** Unanimous
  direction across all 12 reviewers.
- **Team = 12 native subagents:** principal×4, quality×4, security×2, testing×2. **principal-1 and
  quality-2 ran COLD** (standards + snapshot only, no accusation given — `final.md:8-9`; each cold
  seat's blocker is tagged "COLD seat" in `round-meta.json`) for independent corroboration.
- **B1** (`final.md:92`) — *C1: `lme_lab/` is a parallel deployment backend on the execution path
  (Ansible is a facade).* For the multi-host target only `python3 -m lme_lab deploy` runs — it
  generates its own inventory + plays and shells `ansible-playbook`; `site.yml` is never invoked.
  Even a plain single-host install now hard-depends on the rejected package via an **ungated import**
  (`lme_manifests.py:481` → `lme_lab.model`; `load_manifests.yml:100-105`). **Both cold seats
  reached this independently.**
- **B2** (`final.md:118-139`) — *C5: two deploy-gate legs pass on a real failure (false green).*
  (a) the **VIP-probe** leg scores a dead backend as PASS even when armed — `deploy_gate.sh:1386-1389`
  scores every HTTP code except `000` as "backend answered", a dead `tailscale serve` returns
  **502 → PASS**, and `test_deploy_gate.py:311` asserts **503 → PASS** under
  `LME_GATE_REQUIRE_VIP_REACHABLE=1` (cementing the defect); (b) the **Fleet** delivery leg
  (`network_acceptance.py:207-252`) PASSes on Serve-route exactness + agent `online` while the agent
  is enrolled inert (`inputs==[]`) — check-in treated as delivery, no seeded record read back. Union
  of quality-2 + security-2 (VIP) and principal-4 (Fleet), promoted to blocker on rubric grounds.
- Contract adjudication (`final.md:38-59, 85`): CONFIRMED on C1 (merge-gating), C2, C4; **PARTIAL**
  on C5 (native collection core judged **honest** — real readback, fail-closed; two gate legs are
  the B2 defect); **REFUTED on C6** — secrets/certs/exposure sound, changeset **net-reduces**
  exposure vs base. The "lying" pattern does not extend to secrets.

## 4. The hinge and the DISSOLVE decision

Every C1 finding's severity assumes the reconciliation directive still stands — that `lme_lab` is
to be **dissolved** into `lme_manifests.py` + overlays + `site.yml`, this changeset having done the
opposite. `final.md:61-73` poses this as the one operator hinge ("B1 is 'remove the backend' or
'rewrite the doctrine and re-scope the review'"), quoting the directive verbatim.

**Resolved 2026-09-22 = DISSOLVE** (operator decision, per this indexing lane's dispatch — a
governance fact, **not** an on-disk artifact of this session). The directive stands; `lme_lab` is
to be folded into `lme_manifests.py`; the sole-authority doctrine
(`discovered-standards.md:16`, "The existing manifest engine is the SOLE authority.") and its
**derived rule 3** (`discovered-standards.md:35-39`, "The rejected framework must not remain an
alternative backend … removed from the execution path, not kept as a second backend") are
**ENFORCED, not rewritten** — rule 3 is exactly the rule B1/C1 finds violated. B1 is therefore a
**settled fix scope**, not an open doctrine question. Per operator memory, remediation is the Codex
worker's (not this review lane's), and the next step is a round-2 re-review on a fresh snapshot under
operator approval.

**Provenance guard (`final.md:11-18`):** this round is an **independent static cross-check**,
explicitly **NOT** the plan's step-6 CLI-worker review, and must not be fed back into
`lme_lab/review_acceptance.py` as one. Because the verdict is REQUEST CHANGES with blockers, it
does not satisfy that framework's `_remediation` cell (which greens only on a self-declared
`APPROVE`/`blockers:0`) — the hazard being a hand-edited meta (security-2's SF-6).

## 5. DB-twin note

Two DB rows share this date (state already queried by the dispatch; recorded, not re-queried):

| session id | status | round | note |
|---|---|---:|---|
| `2026-09-22-fix-debian-13-selinux-apt` | **ACTIVE** | 1 | the bare / map twin; **owns this on-disk directory** |
| `2026-09-22-fix-debian-13-selinux-apt-review` | closed | 1 | the review-lane twin that **produced round-1's artifacts** |

This matches the index's existing **bare-vs-`-review` twin** observation (MASTER-INDEX §3, §4.2).
Corroboration on disk: `final.md:3` and `context.md:3` both self-label as
`…-fix-debian-13-selinux-apt-review` while physically living in the **bare-id** directory — i.e. the
`-review` twin wrote into the bare twin's tree. **This bare twin is ACTIVE**, so this directory is a
**named live-writer area**: any single file total is a timestamp, and a round-2 pass is expected to
grow it. (Consequence for the parent index: MASTER-INDEX §3's "all five DB sessions are now closed"
is **stale** — with this date's two rows there are now **≥7 DB rows** (5 per MASTER-INDEX §3 as of
05:33Z + 2 for this date per dispatch; not re-queried here) against **4 on-disk session dirs**
(`ls -d .ocr/sessions/*/` — 2026-09-16/-18/-21/-22), one of them ACTIVE.)

**Provenance of the plan/rebuttal inputs (sha256-verified, index-worthy per house practice):** the
2 `requirements-src/` plans are **byte-identical** to their `snapshot/untracked/docs/superpowers/
plans/` copies, and the 4 `requirements-src/.temp.REBUTTAL.0N.md` are byte-identical to their
`snapshot/untracked/.temp.REBUTTAL.0N.md` copies — redundant-but-verified, not divergent forks.

## 6. Detail-leaf pointer

For authoritative per-round detail, read the round's own files (this area file is an inventory, not
a substitute):
- **`rounds/round-1/final.md`** — the synthesized verdict, B1/B2 write-ups, the C1–C6 contract
  table, the SF/suggestion ledger, and the operator hinge.
- **`rounds/round-1/round-meta.json`** — the machine-readable verdict + `synthesis_counts` + the
  full 12-reviewer findings array with severities and `flagged_by` cross-refs.
- **`rounds/round-1/discourse.md`** — the Phase-6 cross-reviewer debate record (opens with D1, the
  "is `lme_lab` a legitimate generic extension or the forbidden parallel backend?" adjudication) and
  how the synthesizer resolved each dispute; notes the two cold seats' independent convergence.
- Supporting: `rounds/round-1/reviews/*.md` (12 raw persona reviews), `agent-ids.txt` (the roster),
  and `rounds/round-1/snapshot/{DIGEST.txt,SHA256SUMS.txt,tracked.diff}` (the frozen review input +
  its integrity manifest).

## 7. Reconciliation identity

```
as-of 2026-09-22 ~22:01Z
find /home/tristan/gitters/LME/.ocr/sessions/2026-09-22-fix-debian-13-selinux-apt -type f | wc -l = 424
find … ! -type f ! -type d | wc -l = 0   (no symlink/special file)

424 = 3   root docs
    +  6   requirements-src/           (2 plans + 4 REBUTTALs)
    +  4   rounds/round-1/ root        (agent-ids.txt, final.md, discourse.md, round-meta.json)
    + 12   rounds/round-1/reviews/     (12 reviewer .md)
    + 399  rounds/round-1/snapshot/
             = 6   snapshot-root metadata
             + 36  modified-full/**
             + 357 untracked/**
             (equivalently: 361 logical changeset + 32 __pycache__/*.pyc + 6 metadata)
    = 424   ✓  residue 0
```

Completeness is established by per-bucket closure, not by a search-root grep. Every file lands in
exactly one bucket; none is double-counted; the physical/logical two-scope gap is fully attributed
(§2).
