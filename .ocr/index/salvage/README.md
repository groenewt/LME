# `index/salvage/` — rescued from the untracked-and-unignored repo scratchpad

**Author:** INDEXING/COMPACTION lane lead. `2026-09-22 05:52Z`. COPY only — originals untouched at copy time, nothing deleted.

> **UPDATE `06:05Z`:** *after* this salvage, the **operator relocated** the source `scratchpad/` → `.ocr/utilities/scratchpad/` and `git add`-ed it (repo-root `scratchpad/` no longer exists). These 18 copies are **sha256-identical to the operator's staged copy (18/18 verified)**, so `index/salvage/` is now **redundant-but-verified insurance**, not unique custody. It stays the curated (script-free, `ocr.db.bak`-free) subset; de-dup is the operator's call — see MASTER-INDEX §5/§8.

**Why this exists:** `PROGRESS-LOSS.md` §B3 names `/home/tristan/gitters/LME/scratchpad/` a top-3 real loss surface — it is **untracked AND not gitignored** (`git check-ignore` finds no match), so its real map/review artifacts are one `git clean -fd` from silent permanent deletion with **no git trace**. The CENTRALIZE pass already copied that dir's *scripts* into `../../utilities/`; this area copies its *research/evidence artifacts* into a git-visible location so they survive. **This is a mirror, not a move** — at copy time the originals still lived in `scratchpad/`, and rescuing them (commit-or-relocate) was the operator's call, not this lane's; the **UPDATE above** records that the operator has since done exactly that.

## Provenance (18 files, `cp -p`, sha256 verified identical to source at copy time)

| file | sha256 (head) | what it is |
|------|---------------|------------|
| flow-analyst-1.md / -2.md | 9b5ac104… / 50347b27… | map flow-analyst outputs (28/31 KB) — exist nowhere in git |
| req-mapper-1.md / -2.md | 6aa1893b… / be71e8f7… | requirements-mapper outputs (18/23 KB) |
| round3-diff.txt / -meta.json / -agent-ids.txt | edc4bfe7… / d9b730ff… / d60e8eb3… | round-3 review evidence bundle |
| round8-e2e-evidence.md | d4e49299… | round-8 e2e evidence |
| round9-e2e-multihost.md / -qemu-profiles.md / -qemu-profiles-v2.md / -reviewer-ids.txt | aebcd14c… / b02b9a06… / 82b51e5b… / 66b6aad0… | round-9 multihost + qemu profiles (note the -v2 iteration churn pair) |
| espack-cell6-validation.md / wipe-hardening-validation.md | 42d0c987… / ec63e7f2… | validation write-ups |
| pr-body.md | f8bfd297… | drafted PR body |
| ocr-map-canonical-files.txt / ocr-run2-canonical.txt | b83bbcfd… / b83bbcfd… | **byte-identical pair** (same sha) — a canonical-files snapshot re-emitted under a second name (churn evidence) |
| tailnet-readings.log | 92c471a4… | tailnet probe log |

## NOT copied (deliberately)
- `emit_*.py`, `insert_*.py`, `populate_*.py`, `tailnet_read.sh` — the dir's **scripts**, already centralized in `../../utilities/` (lane-authoring/, probe/).
- `ocr.db.bak-20260917T004634Z` — a **1 MB binary DB backup**, left in place; not an authored artifact, not copied into the index (note it for the operator; it is itself a stranded backup).

## Post-pass authored addition — NOT a scratchpad rescue
- `gippidy-fanout-findings.md` (sha `b532b6c4…`, 265 lines, authored **2026-09-22 ~10:15Z**, *after* this salvage pass) — the durable record of the operator's pre-`/ocr:map run-15` "bring new information in" fanout over `/home/tristan/gitters/configurations/gippidy` (otel-hertzbeat / tailscale-hertzbeat / maka-observability kits), anchored on the **collection-failure pivot** ("the deployed stack links up but collects nothing; collection + cross-host are ONE e2e goal"). This is **not** a `cp` mirror of the old repo `scratchpad/` — it is a genuine authored analysis artifact deliberately placed in `index/salvage/` for durability. **Salvage dir is now 20 files = 18 rescued mirrors + 1 post-pass authored (`gippidy-fanout-findings.md`) + README.**

## Restore / disposition
The durable fix was to **commit these (or relocate them) out of `scratchpad/`** so they become tracked, and to add `scratchpad/` to `.gitignore` or make it a tracked area — see `PROGRESS-LOSS.md` §D. Per the **UPDATE above**, the operator has since relocated the originals to `.ocr/utilities/scratchpad/` and staged them, so this mirror is no longer the only git-visible copy; it remains the curated, redundant-but-verified subset.
