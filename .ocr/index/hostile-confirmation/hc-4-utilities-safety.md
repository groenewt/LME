# HC-4 — Hostile Confirmation: `.ocr/utilities/` Safety & Centralization Claims

Auditor: HC4-UTILITIES-SAFETY. Read-only (scripts read, not executed; git read-only). All paths absolute.

## LEAD VERDICT

**NOT safe to commit as-is.** One must-fix blocker, unrelated to the audited centralization work itself:

- **`git status --short .ocr/utilities/scratchpad` shows 26 files (1.3MB, `A`/staged)** that are **not part of the documented 73-file centralization pass** and appeared **during this audit**, not before it (timestamp evidence below). 25 of the 26 are byte-identical duplicates of files already staged elsewhere in this same changeset; the 26th is a 980KB raw SQLite DB backup with no documentation anywhere, and its apparent source directory has since vanished (§5) so it may be the last surviving copy. **Recommend: `git rm -r --cached .ocr/utilities/scratchpad/` before commit** — index-only, leaves the working-tree files in place, does not delete anything. (I did not run this — read-only mandate.)

Everything the README actually describes — the 51 centralized files, the 5 pointers, the 17 throwaways — is **clean**:

- **Credential scan: CLEAN.** No hardcoded password/token/API-key/master-key, no PEM/private-key material, no AWS-style keys, no literal `Authorization:` bearer values, across all 51 centralized files, all 7 `.snapshot` extracts, and (extended scope, see below) the stray `scratchpad/` directory and its `ocr.db.bak`.
- **Identity/bijection: CONFIRMED.** 51 = 51, exact set match, zero diff. 5 new-pass pointers + 17 throwaways also confirmed by direct count.
- **sha256 integrity: CONFIRMED.** All 51 files' actual sha256 is correctly bound to that file's own row in README.md (not just present somewhere in the file). Zero mismatches, zero transpositions.
- **1 must-fix WARNING-table omission**: `gate/allfuncs.sh.snapshot` contains the same live-mutating primitives (`do_rsync --delete`, `do_wipe`, `do_install`, `do_teardown`) as the explicitly-flagged `gate/run_*.sh` templates, but has no WARNING-table row.
- **1 disposition-accuracy finding**: the three "one-off fidelity" THROWAWAY scripts (`ma1_verify.py`, `ma3_diff.py`, `ma-es/sdiff.py`) are not actually superseded by the centralized `fidelity/` tools — they cover different units and one check class the centralized tools are structurally incapable of performing. Time-sensitive: these three files exist only in SCRATCHPAD-A, which evaporates at session end.
- **1 operator-call, non-secret PII item**: a real email address hardcoded in `vip/patch_acl.py:23`, already staged.

---

## 1. Identity / reconciliation claim

Claim: `73 found = 51 centralized + 5 pointered + 17 throwaway`, residue 0.

```
find .ocr/utilities -type f ! -name README.md | wc -l   → 51
```

Bijection check — set of on-disk filenames vs set of filenames in the README's "Index — Centralized (51)" table:

```
find .ocr/utilities -type f ! -name README.md | sed 's#^\.ocr/utilities/##' | sort  > disk_files.txt
awk '/^## Index — Centralized/,/^## POINTERS/' README.md | grep -oP '^\|\s*`\K[^`]+(?=`)' | sort > readme_centralized.txt
diff disk_files.txt readme_centralized.txt   → (empty, exit 0)
```

**Result: CONFIRMED.** Exact 1:1 match, no orphan files on disk, no phantom rows in the README, no duplicates.

Table-count checks:
- New-this-pass POINTER table: 5 data rows (grep-counted). CONFIRMED = 5.
- THROWAWAY table: 17 data rows across 5 sub-tables (7 churn + 3 fidelity one-offs + 2 orchestration drivers + 1 filename-coupled scaffold + 4 test mocks). CONFIRMED = 17.
- 51 + 5 + 17 = 73. CONFIRMED.

**Caveat on the identity's scope** (not a defect, but worth stating precisely because the report table is easy to mis-scan): the file also carries a **second** POINTER table, "Carried over from 2026-09-21" (5 more rows: `deploy_gate.sh`, `wipe_lme.sh`, `tailscale_service.yml`, `tailscale_ingress.yml`, `populate_agent_row.py`), explicitly headed "outside this pass's N=73." That's accurate and self-declared — the body text names only 3 of those 5 explicitly, but the section header scopes all 5, so this is not a miscount, just slightly under-explicit prose. Total pointer rows in the file = 10; only 5 count toward the 73.

**sha256 integrity (extended beyond the task's spot-check ask, to close the README's own claim that "sha256 is recorded for every centralized file so drift... is detectable")**. First pass checked only set-membership (hash present *somewhere* in the file, which would pass even if two rows' hashes were transposed); tightened to bind each hash to the README line that names that exact file path:
```bash
while read -r f; do
  s=$(sha256sum "$f" | cut -d' ' -f1)
  grep -F "\`$f\`" README.md | grep -q "$s" || echo "ROW MISMATCH: $f"
done < <(find . -type f ! -name README.md ! -path './scratchpad/*' | sed 's#^\./##')
→ ALL 51: sha256 correctly bound to its own row. Zero mismatches, zero transpositions.
```

---

## 2. DEEP SECRET SCAN

Scope: all 51 centralized files, all 7 `.snapshot`s (subset of the 51), plus — extended after a mid-audit discovery (§5) — the stray `scratchpad/` subtree including its binary DB backup.

Commands run (from `/home/tristan/gitters/LME/.ocr/utilities`):

```bash
# 1. password/secret/token/api_key/master_key literal-looking assignments
grep -rniE '(password|passwd|secret|token|api[_-]?key|master_key)[[:space:]]*[:=][[:space:]]*["'"'"'A-Za-z0-9]' \
  --include='*.sh' --include='*.py' --include='*.snapshot' .

# 2. BEGIN ... PRIVATE KEY / CERTIFICATE blocks
grep -rn 'BEGIN.*\(PRIVATE KEY\|CERTIFICATE\|RSA\|OPENSSH\)' .

# 3. AWS-style access keys
grep -rnE 'AKIA[0-9A-Z]{16}' .

# 4. Authorization header with literal value
grep -rniE 'Authorization:[[:space:]]*(Bearer|Basic)' .

# 5. .pem/.key content refs
grep -rniE '\.(pem|key)["'"'"']' .

# 6/7. long hex / base64 blobs
grep -rnoE '[0-9a-f]{32,}' .
grep -rnoE '[A-Za-z0-9+/]{40,}={0,2}' .

# 8-13: tailscale auth-key prefix, JWT blobs, inline curl -u basic-auth,
#       committed .env/.pem/id_rsa/credential files, fallback-default
#       credential literals (bash ${VAR:-lit} / python .get(k,'lit')),
#       Python requests/urllib POST/PUT/PATCH/DELETE verbs
grep -rn 'tskey-' .
grep -rn 'eyJ[A-Za-z0-9_-]\{10,\}' .
grep -rnE "curl.*-u[[:space:]]+['\"a-zA-Z0-9]+:['\"]?[a-zA-Z0-9]" .
find . -iname '*.env' -o -iname '*credential*' -o -iname '*.pem' -o -iname '*.pfx' \
     -o -iname 'id_rsa*' -o -iname 'id_ed25519*'
grep -rniE '\$\{?[A-Z_]*(PASS|PWD|SECRET|TOKEN|KEY)[A-Z_]*:-[^}]*\}' .
grep -rniE "(pass|pwd|secret|token|key)[A-Za-z_]*['\"]?\s*[,)]\s*['\"][A-Za-z0-9]{4,}['\"]" --include='*.py' . | grep -iE '\.get\('
grep -rnE '\.(post|put|patch|delete)\(|method[[:space:]]*=[[:space:]]*["'"'"'](POST|PUT|PATCH|DELETE)|HTTPConnection|urlopen' --include='*.py' -i .

# 14. destructive-pattern sweep (rm -rf, dd if=, curl -X, wipe, DROP, mv,
#     truncate, shred, mkfs, iptables -F, ip route flush, systemctl
#     stop/disable, podman rm/prune, kill, pkill, chmod 777, SQL DML)
grep -rnE '\brm[[:space:]]+-[a-zA-Z]*r|dd[[:space:]]+if=|-X[[:space:]]*(POST|PUT|DELETE|PATCH)|\bwipe\b|DROP[[:space:]]+(TABLE|INDEX|DATABASE)|\bmv[[:space:]]|truncate|shred|mkfs|iptables[[:space:]]+-F|ip[[:space:]]+route[[:space:]]+(del|flush)|systemctl[[:space:]]+(stop|disable|mask)|podman[[:space:]]+(rm|rmi|prune|volume rm)|\bkill\b|pkill|chmod[[:space:]]+777|\bINSERT[[:space:]]+INTO\b|\bUPDATE[[:space:]]+\w+[[:space:]]+SET\b|\bDELETE[[:space:]]+FROM\b' -i .

# 15. Python destructive-call sweep
grep -rnE 'shutil\.rmtree|os\.remove|os\.unlink|os\.chmod|os\.chown|os\.system|subprocess\.(run|call|Popen|check_call|check_output)|eval\(|exec\(' --include='*.py' .
```

### Hits and disposition

| hit | file:line | verdict |
|---|---|---|
| `EP="$(grep -iE '^elastic_password=...' "$ENVF" ...)"` | `probe/kb_fleet_probe.sh:7` | CLEAN — reads from an external env file / podman secret at runtime, not a literal. Script also echoes only `${#EP}` (length), never the value, before use. |
| `TOKEN = os.environ.get("TS_API_TOKEN")` | `vip/define_services.py:28` | CLEAN — env var, not hardcoded. |
| `"master_key: os.environ/LITELLM_MASTER_KEY (no committed literal key)"` | `map/gen_map.py:273` | CLEAN — this is a findings-digest STRING asserting the *absence* of a hardcoded key elsewhere in the repo; not itself a credential. |
| `-H "Authorization: Bearer $TS_API_TOKEN"` | `vip/restore_acl.sh:9` | CLEAN — shell variable, not a literal token. |
| `grep -rnE 'lme_certs\|ca\.key\|ca/ca\.key' ...` | `lint/dod_acceptance_grep.sh:77` | CLEAN — searching for the *path string* "ca.key" as a lint pattern, not key material. |
| all sha256 hex strings | `README.md` (excluded from the 51, but scanned anyway) | CLEAN — legitimate checksums documenting file identity, all 64-hex-char sha256 values. |
| Python HTTP-mutation-verb sweep | `vip/define_services.py:41` (`urllib.request.urlopen`) | Already covered under blast-radius (§3) — dry-run gated, not a secret. |
| destructive-pattern sweep | only inside already-WARNING-flagged files, **plus `gate/allfuncs.sh.snapshot`** | see §3/§4 — behavioral hazard, not a secret. |

**No password, passwd, secret, token, api_key, or master_key literal assignment found anywhere in the 51 files. No PEM/private-key block, no AWS-style key, no literal Authorization value, no fallback-default credential (`${VAR:-literal}` / `.get(k,'literal')`), no tskey-, no JWT-looking blob, no committed `.env`/`.pem`/`id_rsa*`/credential file. Credential scan verdict: CLEAN.**

The only literal, human-meaningful, non-credential values found were: a real personal email address (§6), and real tailnet hostnames/domain (`tail6c2eb6.ts.net`, seen in `probe/hold_proof.sh:7`, `probe/probe_states.sh:16`, and comments in `gate/allfuncs.sh.snapshot:683,709`) and host aliases (`graph`, `trixie`) consistent with the README's own admitted pattern — the README's own WARNING table already discloses that `gate/rerun_elastic.sh`, `gate/run_gate.sh`, etc. have "Host/IP/label hardcoded," so a tailnet domain name appearing in scripts is the *documented*, accepted design (the README's no-inline-deployable-values promise is scoped to the *index prose*, verified clean in §7, not to the scripts).

---

## 3. Blast-radius flags — the 4 mandated deep reads

| script | README claim | full read confirms |
|---|---|---|
| `vip/restore_acl.sh` | Force-POSTs whole tailnet ACL, no If-Match | **CONFIRMED.** `curl -sS -X POST ... "https://api.tailscale.com/api/v2/tailnet/-/acl"` with zero `If-Match`/conditional headers — deliberately overwrites live state with `$SCR/tailnet-acl.live.hujson`. Note: that companion snapshot file is **not present** in `.ocr/utilities/vip/` — the actual ACL content was never centralized, so no live tailnet policy data is exposed by this commit. |
| `probe/operator_access.sh` | Dumps live secrets to local plaintext | **CONFIRMED.** Read-only ssh against the remote (`podman secret ls`, `extract_secrets.sh -p`, `podman secret inspect --showsecret`), but tees `litellm_master_key`/`webui_api_key`/elastic/kibana_system/wazuh/pgvector credentials to a local file (`$OUT`, hardcoded to this session's own `/tmp` scratchpad — not a repo path). Script itself carries no hardcoded secret. |
| `probe/teardown_verify.sh` | Runs `wipe_lme.sh` | **CONFIRMED.** Line 4, first action: `sudo bash scripts/wipe_lme.sh`, before any self-verification. |
| `probe/graph-seal/seal.sh` | Live ES POST+DELETE | **CONFIRMED.** 4-step curl sequence: `-XPOST` doc write, `-XGET` search readback, `-XDELETE` index, confirm-gone GET. Creds from `$ES_USERNAME`/`$ES_PASSWORD` env, not literal. |

All 4 descriptions are accurate.

### Remaining flagged (non-mandated) rows — read for completeness

The brief mandated deep reads of 4 scripts; the other 11 WARNING-table rows were cross-checked at varying depth. Stating that depth explicitly rather than leaving it implicit:

| script | verification depth | result |
|---|---|---|
| `gate/rerun_elastic.sh` | full read | CONFIRMED — `deploy_gate.sh --stage deploy` (HOLD, no teardown) on host "graph" (`IP=100.73.170.86`, hardcoded) with `--tailscale --elastic-services --no-llm`, then ssh roster-assertion by container name. No secrets. |
| `gate/run_install.sh` | full read | CONFIRMED — `NON_INTERACTIVE=true AUTO_CREATE_ENV=true ./install.sh --offline -g /opt/lme-storage` on the executing host, `cd /home/vmuser/LME` hardcoded. No secrets. |
| `gate/run-trixie-cluster-a2b2-run2.sh` | full read | CONFIRMED — `deploy_gate.sh --stage all` (full rsync→wipe→install→health→teardown) on host "trixie" (`100.127.117.27`, hardcoded) with `--cluster --no-llm` + a heap:2g `--extra-vars` JSON override. No secrets. |
| `airgap/airgap_cut.sh` | full read | CONFIRMED — non-root path (`LOG=/home/vmuser/airgap`), `sudo ip route del default`, 5s re-cut guard loop, egress-failure curl proofs against `1.1.1.1`/`8.8.8.8`/`cloud.debian.org`. No secrets. |
| `airgap/airgap-cut-and-prove.sh` | grep-verified only (destructive-pattern sweep hit `ip route del default` at the claimed 2 call sites; root path `/root` vs the sibling's `/home/vmuser`, per `ls`) | consistent with README claim; not independently full-read. |
| `lane-authoring/insert_airgap_lane.py` | full read, diffed against `insert_3node_lane.py` | CONFIRMED same INSERT + uid-idempotent-guard pattern, only the row payload (uid/timestamps/notes) differs. No secrets (uid is an opaque agent-id string). |
| `lane-authoring/populate_3node_lane.py`, `populate_airgap_lane.py` | full read | CONFIRMED — **both `import populate_agent_row as P`** and call into it; **neither contains a direct `UPDATE` statement** (my destructive-pattern SQL sweep correctly found none — the README's "UPDATEs... overwrites events journal" describes the *delegated* behavior of `.ocr/tools/populate_agent_row.py`, consistent with the POINTER-table row for that file). No secrets. |

No new hazards found in any of these 7. All descriptions hold.

## 4. Blast-radius flags — scanning the other 47 for under-flagging

Cross-referenced every WARNING-table row against the 51-file inventory (15 of 51 are flagged: `airgap/`×2, `gate/run_gate.sh`, `gate/rerun_elastic.sh`, `gate/run-trixie-cluster-a2b2-run2.sh`, `gate/run_install.sh`, `lane-authoring/`×4, `probe/`×3, `vip/restore_acl.sh`, `vip/define_services.py`), then ran the destructive-pattern/Python-HTTP-verb sweeps (§2, items 14–15) across all 51 and individually read or spot-verified the remainder (`probe/kb_fleet_probe.sh`, `probe/hold_proof.sh`, `probe/listen.py`, `lint/dod_acceptance_grep.sh`, `vip/patch_acl.py`, `vip/define_services.py` full read, `map/gen_map_meta.py`, `map/synth_map.py`, `gate/run_gate.sh` full read, plus grep-verified `probe/graph-seal/kb.sh`, `probe/graph-seal/probe.sh`, `probe/kb_status_summary.sh`, `probe/health.sh`, `probe/probe_payload.sh`, `probe/probe_states.sh`, `probe/sol_probe.sh`, `probe/tailnet_read.sh`, `probe/jsontest2.sh`, `vip/branch.py`, `vip/derive_check.sh`, `vip/profile.py`, `vip/harness2.sh`, `fidelity/*.py`, `transcript/*.py`, `lane-authoring/emit_*.py`, `gate/gate_dryrun.sh`, the 6 non-`allfuncs` `.snapshot` files).

**Confirmed correctly unflagged**: `vip/patch_acl.py` (pure local-file-to-file hujson transform — no `import requests`/`urllib`, no network call at all, despite the word "live" in its docstring referring to its *input's provenance*, not a live write); `vip/define_services.py` (full read confirms `APPLY = "--apply" in sys.argv` really gates every `PUT`, and the script `sys.exit(0)` before any mutation when not set — dry-run-by-default claim holds); `probe/listen.py` (binds `127.0.0.1` only, never `0.0.0.0`); `lint/dod_acceptance_grep.sh` (pure grep, no writes); all `map/`, `transcript/` tools (only `subprocess.check_output(["git","diff",...])`, read-only); 6 of 7 `.snapshot` files (pure derivation/health-check logic, no state-changing primitive).

### ★ New finding: `gate/allfuncs.sh.snapshot` is under-flagged

The README describes this file only as an inert "EXTRACT... MAY DRIFT — repo is source of truth," in the same register as its genuinely-inert sibling `.snapshot`s. But it is the **only** one of the 7 nested snapshot extracts that contains the canonical gate's live-mutating stage functions:

```
grep -oE 'do_wipe\(\)|do_rsync\(\)|do_install\(\)|do_teardown\(\)' gate/*.snapshot
→ gate_funcs / funcs_new / expo_new / run_new / health_payload: NONE
→ allfuncs.sh.snapshot: do_health() do_install() do_rsync() do_teardown() do_vip_probe() do_wipe()
```

Full read confirms these are the real thing, not stubs:
- `do_rsync()` — `rsync -e "ssh ..." -a --delete ... "$SRC/" "root@${HOST}:${REMOTE_DIR}/"` (live delete-sync to a remote host).
- `do_wipe()` / `do_teardown()` — `run_remote "cd '$REMOTE_DIR' && bash scripts/wipe_lme.sh"` (live remote teardown, identical action to the flagged `probe/teardown_verify.sh`).
- `do_install()` — `"${SSH[@]}" "cd '$REMOTE_DIR' && NON_INTERACTIVE=true AUTO_CREATE_ENV=true ./install.sh ..."` (live remote install, identical action to the flagged `gate/run_install.sh`).

Nothing fires merely by the file sitting in the repo — it is a function library, not an executable driver. But the README's *own* run-note (right below the WARNING table) instructs a reader to copy/symlink this exact file to `allfuncs.sh` and `source` it so `gate/gate_dryrun.sh` / `probe/probe_states.sh` can run — and sourcing it arms `do_wipe`/`do_rsync --delete`/`do_install`/`do_teardown` in the caller's shell with zero additional warning that those four destructive primitives came along for the ride. This is exactly the blast radius the WARNING table exists to call out for `gate/run_gate.sh` et al., and it is currently invisible for `allfuncs.sh.snapshot`.

**Should-fix**: add a WARNING-table row for `gate/allfuncs.sh.snapshot` (or a callout in its own description) naming `do_rsync`/`do_wipe`/`do_install`/`do_teardown` as live-mutating once sourced+invoked. Not a commit blocker by itself.

No other under-flagged destructive/exfil action was found in the remaining files.

---

## 5. ★★ NEW, more serious finding: undocumented `scratchpad/` directory staged inside `.ocr/utilities/`

This was **not** requested by name in the task brief but surfaced from the mandated identity check (§1) plus a git-status sanity pass, and is the most consequential finding in this audit.

**What it is**: `/home/tristan/gitters/LME/.ocr/utilities/scratchpad/` — 26 files, 1.3MB, `git status --short` shows all 26 as `A` (staged for commit; recount immediately before writing this report, 2026-09-22 ~01:17 local/-0500 (06:17Z): still 26). It is **not mentioned anywhere in README.md** as a subdirectory (grepped for every occurrence of the string `scratchpad` in the README — all hits are the `SCRATCHPAD-A`/`SCRATCHPAD-B` origin-path shorthand or unrelated prose; none describe a `.ocr/utilities/scratchpad/` output location). It is not part of the 51/5/17 = 73 reconciliation.

**Attribution — important to get right**: this is *not* a residue defect in the audited centralization pass. At the start of this audit (before any of the above sections), `find .ocr/utilities -maxdepth 2 -type d` returned no `scratchpad` entry and the file-count/bijection check (§1) was already an *exact* 51/51 match with zero diff. The directory's own `ctime` is `2026-09-22 01:04:45`, **after** this audit's baseline check. I cannot identify *which* process wrote it — only that **a concurrent process in this session** did, while this audit was running (this subagent shares write-visibility into the session's SCRATCHPAD-A, which shows file writes continuing at 00:58–01:04 throughout; the timing overlaps but doesn't by itself name the actor).

Stronger, direct evidence of *how* it was produced: `.ocr/utilities/scratchpad`'s own directory `mtime` is `2026-09-19 06:57:09` — which is not "recent," it is **byte-identical to the newest file's mtime I had already observed inside the repo's top-level `scratchpad/`** (`round9-qemu-profiles-v2.md`, `Sep 19 06:57`, from an earlier `ls -la` in this same audit). A directory's mtime tracks its own last content change; a destination directory acquiring the *exact* source mtime is the signature of a metadata-preserving copy (`cp -a`/`cp -rp`), not files added one at a time. That is direct evidence this was produced by copying the repo's top-level `scratchpad/` (SCRATCHPAD-B) wholesale into `.ocr/utilities/scratchpad/`.

**Follow-on, discovered while re-verifying just before writing this report**: the source directory, `/home/tristan/gitters/LME/scratchpad/`, **no longer exists** — `ls -la` on it now returns "No such file or directory," where earlier in this same audit it returned a full 26-entry listing. So between then and now, something removed it. Read together with the mtime evidence, the most consistent explanation is an in-progress consolidation by a concurrent process (copy SCRATCHPAD-B's content out to its real destinations, then remove the original) that has not yet cleaned up the intermediate/erroneous copy sitting in `.ocr/utilities/scratchpad/` — plausible, not confirmed; I have no visibility into the other process's intent, only its filesystem effects. **Practical consequence**: `.ocr/utilities/scratchpad/ocr.db.bak-20260917T004634Z` may now be the only surviving copy of that 980KB file on disk (its apparent source is gone). The recommended remedy below is `git rm -r --cached` (index-only, leaves the working-tree file in place) specifically *because* of this — do not `rm -rf` the directory outright without confirming nothing still needs that file.

Do not read this finding as "the centralization pass left residue" — it didn't; the documented 51/5/17 work was exact and clean at baseline. Something unrelated is landing on top of it mid-review, in real time. It still must not ship as part of this commit.

**Contents, fully accounted for**:

| category | count | disposition |
|---|---|---|
| byte-identical duplicate of a file already staged at `.ocr/utilities/lane-authoring/*.py` (`insert_3node_lane.py`, `insert_airgap_lane.py`, `populate_3node_lane.py`, `populate_airgap_lane.py`, `emit_3node_files.py`, `emit_out30_text_only.py`) | 6 | pure redundant bloat |
| byte-identical duplicate of a file already staged at `.ocr/utilities/probe/tailnet_read.sh` | 1 | pure redundant bloat |
| byte-identical duplicate of a file already staged at `.ocr/index/salvage/*` (`espack-cell6-validation.md`, `flow-analyst-1.md`, `flow-analyst-2.md`, `ocr-map-canonical-files.txt`, `ocr-run2-canonical.txt`, `pr-body.md`, `req-mapper-1.md`, `req-mapper-2.md`, `round3-agent-ids.txt`, `round3-diff.txt`, `round3-meta.json`, `round8-e2e-evidence.md`, `round9-e2e-multihost.md`, `round9-qemu-profiles.md`, `round9-qemu-profiles-v2.md`, `round9-reviewer-ids.txt`, `tailnet-readings.log`, `wipe-hardening-validation.md`) | 18 | pure redundant bloat (this same changeset stages the identical bytes at the correct path already) |
| no counterpart anywhere else: `ocr.db.bak-20260917T004634Z`, a **980KB raw SQLite database backup** | 1 | undocumented binary in a scripts/markdown index dir; see secret-scan below |

25 of 26 verified via `diff -q` against their counterpart path — all report identical. The 26th (`ocr.db.bak-...`) has no counterpart; it is the only "novel" content in the directory.

**Secret-scanned the DB backup specifically** (binary-safe `grep -a` / `strings`, same credential patterns as §2, extended with capture-format checks for the exact strings `operator_access.sh`/`hold_proof.sh` would have produced):

```
strings ocr.db.bak-... | grep -E '^\s*(litellm_master_key|webui_api_key)\s*=\s*\S'        → no hits
strings ocr.db.bak-... | grep -iE 'Exported (elastic|kibana|wazuh|pgvector)'              → no hits
strings ocr.db.bak-... | grep -E 'OPERATOR ACCESS|HOLD PROOF|SecretData'                  → no hits
strings ocr.db.bak-... | grep -oE '\bsk-[A-Za-z0-9_-]{6,}\b' | sort -u                    → sk-lme-llama-proxy (only hit)
```

The one credential-shaped literal, `sk-lme-llama-proxy`, is **not a novel disclosure**: it is a low-entropy, human-readable placeholder (not random-looking secret material), and it is **already byte-identically present**, in the exact same review-commentary form, in `.ocr/utilities/scratchpad/req-mapper-1.md`, `req-mapper-2.md`, `round3-diff.txt`, `round3-meta.json` (all separately staged at `.ocr/index/salvage/` in this same changeset), and independently in the already-tracked `testing/ludus/bugs.md`, which describes it in the **past tense** as an already-fixed issue ("Was: hardcoded `sk-lme-llama-proxy` in config file. Now a per-install random Podman..."). This is historical OCR-review commentary about a resolved, pre-existing, out-of-scope-for-`.ocr/utilities` defect, not a live secret this directory is newly exposing. No other credential-shaped literal exists anywhere in the DB backup or the 25 duplicate files.

**Verdict on `scratchpad/`**: no fresh credential leak, but it is 1.3MB of pure duplication plus one undocumented binary DB blob, entirely absent from the README's accounting, currently staged. **Must be removed from the index before commit**: `git rm -r --cached .ocr/utilities/scratchpad/` (recommended, not executed — this audit is read-only).

---

## 6. PII observation (not a credential — operator judgment call)

`vip/patch_acl.py:23` hardcodes a real personal email address as a Tailscale ACL principal:
```python
'\t\t\t"src": ["tag:personal", "famgroenewoldt@gmail.com"],\n'
```
This is normal, expected Tailscale-ACL syntax (grants are addressed to a login identity) — knowing the string grants no access by itself, so it does not meet this audit's credential bar and is **not counted as a secret-scan hit**. It's flagged separately because: (a) it's a real, identifying email address, not a placeholder; (b) it's already staged (`git status --short` → `A  .ocr/utilities/vip/patch_acl.py`); (c) the README's own preamble states the *index* deliberately inlines no deployable values — this is in a *script*, which the README's "read the script for its configuration" model explicitly accepts as legitimate elsewhere (hosts/IPs/tailnet labels are already accepted in the flagged gate templates), so this is consistent with established repo practice, not a new violation. Whether an email address specifically should be scrubbed before any public push is an operator call, not a code-safety defect.

No other email address or PII literal was found in any of the 51 files (full-tree email/tailnet-domain/`tag:machine-*` regex swept every file type, not just `.sh`/`.py`/`.snapshot`).

---

## 7. Pointer resolution (5 new-pass POINTER entries)

```
git -C /home/tristan/gitters/LME ls-files | grep -xF "testing/e2e/deploy_gate.sh"   → found
git -C /home/tristan/gitters/LME ls-files | grep -xF "install.sh"                    → found
git -C /home/tristan/gitters/LME ls-files | grep -xF "scripts/wipe_lme.sh"           → found
```
All 5 POINTER rows (`deploy_gate.sh`→`testing/e2e/deploy_gate.sh`, `old_gate.sh`→same, `install.orig.sh`→`install.sh`, `wipe_harness.sh`→`scripts/wipe_lme.sh`, `wipe_head.sh`→same) resolve to real, tracked, repo-canonical files. **CONFIRMED.**

Bonus (not required, done for completeness): the 4 recorded canonical sha256 values for these targets were re-hashed live — `testing/e2e/deploy_gate.sh`, `install.sh`, `scripts/wipe_lme.sh` all **MATCH** the README's recorded hash exactly (no drift as of this audit). The 5 "carried over from 2026-09-21" pointer rows also resolve to real tracked files (`ansible/roles/podman/tasks/tailscale_service.yml`, `tailscale_ingress.yml`, `.ocr/tools/populate_agent_row.py` — all found via `git ls-files`).

Also confirmed clean: the README's own no-inline-deployable-values promise for the *index itself* — grepped README.md for tailnet IPs/domains/emails: zero hits (the only matches were `127.0.0.1`/`0.0.0.0` used generically to describe what `listen.py`/`profile.py` do, not a real deployment target).

---

## 8. Throwaway spot-check (5 of 17)

| file | category | verdict |
|---|---|---|
| `funcs_old.sh` | churn loser | **CONFIRMED correctly classified.** `diff funcs_old.sh funcs_new.sh` → byte-identical, exactly as claimed. |
| `drive.sh` | filename-coupled scaffold | **CONFIRMED correctly classified.** Reads exactly as described: `eval "$(sed -n '/^loopback_ok()/p' payload.sh)"` — fragile sed/awk extraction from a co-located, itself-superseded `payload.sh`. Its `check_port()` logic is structurally the same per-port accept/reject loop already present verbatim in `gate/allfuncs.sh.snapshot`'s `HEALTH_SH` heredoc (lines 601–630) and `probe/health.sh` — no unique logic lost. |
| `bin/ss` | test mock | **CONFIRMED correctly classified.** Trivial `ss` stub reading `$SS_TCP`/`$SS_UDP` env files, exactly as described. |
| `map_swarm.sh` | session-specific orchestration driver | **Minor classification quibble, not a safety issue.** Full read confirms it's genuinely round-13-hardcoded (paths, K1/A1 citations) as claimed — but its `launch()` dispatch pattern (parallel `opencode run` subagent waves behind a shared `PREAMBLE`) is structurally the same kind of "reusable pattern behind hardcoded constants" that justified centralizing `gen_map.py`/`gen_map_meta.py`/`synth_map.py` as "worked templates" despite equal hardcoding. The README's own stated selection criteria would arguably have kept this one too; its exclusion isn't wrong, just inconsistent with the precedent set two sections earlier in the same document. No functional or safety concern either way. |
| `ma1_verify.py` | one-off fidelity check | **★ Misclassified — genuine coverage loss, not just lineage.** See below. |

### ★ `ma1_verify.py` / `ma3_diff.py` / `ma-es/sdiff.py` — lineage ≠ coverage

The README justifies discarding all three as "same normalize/semantic-diff lineage as `fidelity/render_harness.py`... which is centralized and self-contained." The *lineage* claim is true — `render_harness.py`'s `normalize()`/`semantic_diff()` is near-identical code. The *coverage* claim does not hold:

- **`render_harness.py`** renders/checks 8 units: `elasticsearch` (default+cluster), `litellm`, `filebeat`, `esdata01.volume`, `lme.network`, `lme.service`, `llm-keys.path`+`.service`.
- **`fidelity/fidelity.py`** (the other centralized tool, claimed to cover "all 17 quadlet containers") — verified by reading it: it does cover 17 named containers, but **only `.container` files**; it never touches any `.volume` or `.service` unit, and its 17-name list excludes `setup-certs`/`setup-accts`.
- **`ma1_verify.py`** (discarded) checks 9 units neither centralized tool touches at all: `kibana`, `fleet-server`, `fleet-distribution`, `wazuh-manager`, `elastalert`, `setup-certs`, `setup-accts`, `backups.volume`, `kibanadata.volume`.
- **`ma3_diff.py`** (discarded) checks 7 more untouched units: `pgvector`, `pgvectordata.volume`, `llama-cpp`, `embeddings`, `dashboard`, `log-analyzer`, `llama-model.service`.
- **`ma-es/sdiff.py`** (discarded) checks 5 more: `apm-server`, `heartbeat`, `metricbeat`, `logstash`, `filebeatdata.volume`.

More importantly, **`ma1_verify.py` performs a check class that both centralized tools are structurally incapable of**: it `.count()`s a specific `Volume=` directive to catch a duplicate-mount regression (the wazuh `lme_wazuh_logs` mounted-twice bug it documents fixing). Both `fidelity.py` and `render_harness.py` compare **Python `set()`s** of directives — a duplicate collapses to one set member by construction, so a regression back to "mounted twice" would show as **zero diff** in either centralized tool. `ma1_verify.py`'s own docstring says this explicitly: *"Adds the checks a set-diff cannot see... wazuh_logs mounted exactly once (static had it twice; set-diff hides this)."* That is not hand-wavy — I confirmed it by reading `fidelity.py`'s diff method (`set(norm(x) for x in directives(...))`) and `render_harness.py`'s `normalize()` (buckets into `out[cur].add(line)`, a `set`).

Also worth a factual correction: the README states `ma1_rendered/default/` "no longer exists." As of this audit it **does** still exist (19 files, in the live session scratchpad) — the claim is premature, though harmless, since that directory is inherently ephemeral (SCRATCHPAD-A) and will in fact be gone once the session ends regardless.

**Time-sensitive, actionable**: `ma1_verify.py`, `ma3_diff.py`, and `ma-es/sdiff.py` exist **only** in SCRATCHPAD-A (`/tmp/claude-1000/.../scratchpad/`), which the README itself notes "evaporates when the session ends." If the operator wants to keep the duplicate-mount detection capability and the setup-certs/setup-accts/volume/LLM-pack/elastic-pack-container coverage these three scripts uniquely provide, they need to be copied out of SCRATCHPAD-A **before this session ends** — after that they are unrecoverable by this centralization pass's own logic.

---

## Summary table

| check | result |
|---|---|
| Identity (51+5+17=73, bijection) | CONFIRMED |
| sha256 integrity (all 51, row-bound not just present) | CONFIRMED, zero mismatches |
| Credential/secret scan (51 files + snapshots) | **CLEAN** |
| Credential/secret scan (stray `scratchpad/` incl. DB backup) | CLEAN (one non-novel, already-fixed placeholder string) |
| 4 mandated blast-radius scripts | all 4 descriptions CONFIRMED accurate |
| Other 47 for under-flagged hazards | 1 found: `gate/allfuncs.sh.snapshot` (should-fix) |
| 5 pointer entries resolve | CONFIRMED, all 5 (+ bonus: 5 carried-over also resolve, 0 sha256 drift) |
| 5 throwaway spot-checks | 3 confirmed correct, 1 minor quibble, 1 genuine miscoverage finding |
| **Undocumented staged `scratchpad/` dir** | **★★ MUST-FIX before commit — not part of audited pass, appeared mid-audit** |
