# wipe_lme.sh hardening — QEMU/KVM validation

Branch/worktree: `_ocr_r4_integration` @ `/home/tristan/gitters/_ocr_wt/r4integ`
Base HEAD before change: `8b1f6f8` (cert idmap fix)
New commit: **`8f24240e3a2c969266e90b971dede1c4463dd04b`** (not pushed, no PR)
File changed: `scripts/wipe_lme.sh` — `1 file changed, 132 insertions(+), 24 deletions(-)`

## 1. Diff summary (what changed)
- **cwd-independent stop (CONFIRMED bug #1):** replaced unquoted `systemctl stop lme*`
  (which glob-expands against the cwd — from ~/LME it became
  `systemctl stop lme-dashboard lme-log-analyzer`, missing the ~20 real units) with
  systemd-side enumeration: `systemctl list-units --all --plain --no-legend | awk | grep -E '^lme[-._]'`
  plus quoted `systemctl stop 'lme.service' 'lme-*'`. The orchestrator `lme.service`
  (no dash) is named explicitly. No shell glob is ever used to name a unit.
- **stop AND disable BEFORE file removal (bug #2):** disable clears enable symlinks
  (`default.target.wants/lme.service`, `multi-user.target.wants/lme-{llm-keys,llama-model}.path`);
  a `find /etc/systemd/system -name 'lme*' -type l -delete` sweep removes any leftover.
- **.backup + fit-all file removal (bug #3):** `find /etc/containers/systemd -name 'lme*'`
  and `find /etc/systemd/system -name 'lme*'` replace the 8 suffix-specific `rm -f` lines;
  catches `.container.backup*`, `.volume`, `.network`, drop-ins, and future suffixes.
- **/etc/lme purge (bug #4):** `rm -rf /etc/lme` (vault + pass.sh).
- **secrets (bug #5):** keep `secret rm -a`, PLUS remove known lme secrets by name
  (llm-keys, pgvector, elastic, wazuh, wazuh_api, kibana_system), PLUS enumerate and
  remove any remainder (dynamic per-user secret).
- **robustness (bug #6):** dropped `set -e`; steps stay tolerant but real removals are
  unconditional, and a glob-free **self-verifying tail exits non-zero** if any lme
  unit/container/volume/secret/dir survives. The tail's secret check is anchored
  (`^name$`) so an unrelated secret name cannot trip a false residue failure.
- **bug #7:** inactive child-node `lme-litellm` unit is caught by the `find` sweep.
- Order: stop -> disable -> daemon-reload -> remove unit files (+.backup) -> podman rm ->
  volume/secret rm -> rm -rf /opt/lme /etc/lme -> daemon-reload + reset-failed -> self-verify.
- `bash -n` clean; shellcheck -S warning clean.

## 2. VM
- libvirt domain `ocr-wipe-test` on `qemu:///system` (no sudo), 4 vCPU / 12 GB (within ≤4 vCPU/14 GB budget).
- Fresh Ubuntu 24.04 qcow2 overlay (45 GB) on read-only backing `noble-base.img`; SSH key
  `_ocr_vms/id_ed25519`, user `vmuser`. IP `192.168.122.92`. Did not touch lme-deb13/oss-build/others.

## 3. Install — online, single-node, LLM-ON (operator's host scenario)
Command: `sudo NON_INTERACTIVE=true AUTO_CREATE_ENV=true bash install.sh`
ansible extra-vars: `offline_mode:false, install_llm:true, install_elastic_services:false`

```
PLAY RECAP *********************************************************************
localhost : ok=245  changed=104  unreachable=0  failed=0  skipped=101  rescued=1  ignored=0
✓ Main installation playbook completed successfully!
```
install rc=0. Containers healthy pre-wipe (resurrection-prone ones present):
lme-elasticsearch (healthy), lme-embeddings (healthy), lme-llama-cpp (healthy), lme-litellm,
lme-pgvector (healthy), lme-kibana (healthy), lme-wazuh-manager (healthy), lme-elastalert2,
lme-dashboard, lme-log-analyzer, lme-fleet-server — 11 containers total.

## 4. Pre-wipe residue baseline (probe run from ~/LME)
- glob demo: in ~/LME `echo lme*` -> `lme-dashboard lme-log-analyzer` (the bug's expansion)
- 22 loaded lme systemd units; 24 lme unit files; 29 on-disk lme files
  incl. enable symlinks `default.target.wants/lme.service`,
  `multi-user.target.wants/lme-llm-keys.path`, `multi-user.target.wants/lme-llama-model.path`
- 11 lme containers; 18 `lme_*` volumes (underscore); 6 secrets
  (elastic, pgvector, llm-keys, kibana_system, wazuh, wazuh_api); /opt/lme + /etc/lme PRESENT
- Planted a synthetic `/etc/containers/systemd/lme-elasticsearch.container.backup.certfix`
  to exercise the .backup removal path (bug #3).

## 5. THE FIX PROOF — patched wipe from the FAILING cwd
Command: `cd ~/LME && sudo bash ~/LME/scripts/wipe_lme.sh`
- Script stopped/disabled all enumerated units, removed unit files (incl. the planted .backup),
  removed 18 volumes, removed all 6 secrets, pruned images, removed /opt/lme + /etc/lme.
- Final line: `Wipe complete and verified: no LME units, containers, volumes, secrets, or config remain.`
- **`WIPE_EXIT_CODE=0`** (the self-verifying tail passed).

## 6. Independent post-wipe probes (glob-free)
From **~/LME** and from **/** — identical results (only the glob-demo line differs:
`lme-dashboard lme-log-analyzer` vs literal `lme*`, which is exactly the bug mechanism and
proves the script/probes do not depend on cwd):
```
loaded lme units      = 0
lme unit files        = 0
on-disk lme files     = 0   (no not-found/dangling lme.service)
dangling enable syml. = 0
lme containers        = 0
lme volumes           = 0
podman secrets (all)  = 0
/opt/lme              = absent
/etc/lme              = absent
```

## 7. No-resurrection + idempotency re-checks
- **+35s** (from ~/LME): all counts 0; /opt/lme + /etc/lme absent.
- **After a 2nd `systemctl daemon-reload`**: all counts 0; `podman ps -a` lme = 0;
  generated lme units = 0. No quadlet regeneration.
- **Idempotent:** re-running the wipe on the already-clean host exits 0 from **~/LME**
  (`IDEMPOTENT_LME_EXIT=0`) and again from **/** (`IDEMPOTENT_ROOT_EXIT=0`) — the self-verify
  tail does not false-fail on an empty host, and the script itself is proven from cwd `/`.

## 8. Result
PASS. Clean stop/rm/uninstall from any cwd, verified on the operator's exact
single-node online LLM-on scenario, and idempotent on re-run. Committed as
`8f24240` (not pushed, no PR).
Raw probe captures (copied to _ocr_vms/): PROBE_PRE_from_LME.txt, WIPE_from_LME.txt,
PROBE_POST_from_LME.txt, PROBE_POST_from_root.txt, PROBE_RECHECK.txt.
