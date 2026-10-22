# OCR round-9 — QEMU profile-matrix e2e legs (v2)

Tree: /home/tristan/gitters/LME  branch fix/debian-13-selinux-apt  HEAD 1584970 (MUST stay)
Harness: testing/e2e/deploy_gate.sh (real pipeline: rsync whole tree -> tree's own install.sh/ansible -> health -> tree's own scripts/wipe_lme.sh)
SSH key: /home/tristan/gitters/_ocr_vms/id_ed25519  (VM-internal root)
Host control: virsh -c qemu:///system as user tristan (libvirt group, NO sudo on silmaril host)
Budget: ONE VM at a time. win11-2026-6-1 (co-tenant) + tailnet ACL/grants: DO NOT TOUCH.

Prior-close reference (round8, same 5-core floor): qemu-some LEG END rc=0, expect_min=5, running=5.

Domains used (PRIOR-CLOSE, root-enrolled + network-capable, verified this session):
- lme-qemu-some (16G) — booted, lease 192.168.122.238, ssh root OK — Debian 13 trixie. QEMU-SOME target.
- lme-qemu-airgapped-legc (12G, shut off) — COMPLETE-bundle airgap VM (podman-closure.nar). QEMU-AIRGAPPED target.

---

## LEG 1 — qemu-some / lme-qemu-some / 192.168.122.238

Invocation:
```
testing/e2e/deploy_gate.sh --host 192.168.122.238 --ip 192.168.122.238 \
  --ssh-key /home/tristan/gitters/_ocr_vms/id_ed25519 \
  --flags "--no-llm" --label qemu-some-r9 --stage all
```
Log: /tmp/lme-gate-logs/qemu-some-r9.log

Derived floor (from flags): online, --no-llm => llm_on=0, elastic_on=0, offline_on=0 => expect_min = core_floor(5).

Actual invocation run (log /tmp/lme-gate-logs/qemu-some-r9.log):
`testing/e2e/deploy_gate.sh --host 192.168.122.238 --ip 192.168.122.238 --ssh-key .../id_ed25519 --flags "--no-llm" --label qemu-some-r9 --stage all`
(NOTE: `--ip 192.168.122.238` added deliberately to match round8 exactly and remove install.sh auto-detect as a variable; does not affect the health floor. No `--strict` — matches banked close.)

### Stage rc table
| stage | rc | notes |
|-------|----|-------|
| rsync | 0 | 11:18:06 |
| wipe | 0 | host verified CLEAN |
| install | 0 | rescued=0; INSTALL rc=0 at 11:33:42 (~15.5 min) |
| health | 0 | HEALTH result fail=0; rc=0 |
| teardown | 0 | host verified CLEAN |
| **LEG END** | **0** | stage=all rc=0 at 11:34:07 |

### PLAY RECAP: `localhost : ok=353 changed=70 unreachable=0 failed=0 skipped=153 rescued=0 ignored=1`
Parity vs round8 (`ok=285 changed=62 skipped=114 failed=0 rescued=0 ignored=1`): pass invariants IDENTICAL (failed=0, rescued=0, ignored=1, running=5, all-loopback, ES 401, Kibana 302). ok/changed/skipped grew (+68 ok). FORENSICS: c33f567 (round-8/9 map anchor) IS an ancestor of HEAD 1584970, but only 6 commits separate them (all committed 2026-09-19 04:06; ansible/manifests-touching = 4, only 1 real change: `633b241 fix(selinux): fail loud on Debian+SELinux Enforcing`; 0 ansible/manifests commits since 06:00). A +68-task delta cannot come from those 6 commits => round8's qemu-some leg ran from an OLDER checkout than c33f567 (likely an _ocr_wt worktree at an earlier review HEAD), NOT the wave-9 tree. Consequence: this r9 LEG 1 is the first genuine qemu-some leg on HEAD 1584970's ansible tree, and it PASSES the full pass contract. The count difference is checkout provenance, NOT a runtime regression (all r9 tasks failed=0). ignored=1 = known fleet.yml metrics-idx timeout baseline.
### HEALTH floor vs running: expect>=5 vs running=5 (exact floor, matches round8). llm_on=0, profile=none. No failed lme units.
### R8-9 selinux_debian.yml skip confirmation: CONFIRMED
```
TASK [base : Include OS-family SELinux management tasks]
skipping: [localhost] => (item=/root/LME-gate/ansible/roles/base/tasks/selinux_debian.yml)
```
Debian trixie, selinux_available=false => Debian OS-family SELinux management path skips (R8-9 Debian+Enforcing guard, no assert fires).
### Exposure (all loopback?): YES. Full per-port verdict (health payload, fail=0):
```
== exposure: loopback-only binds (443 514 1514 1515 4000 5044 5432 5601 8080 8081 8085 8200 8220 8501 8502 9200 9300 55000) ==
  ok: port 443 loopback-only [127.0.0.1]
  ok: port 514 loopback-only [127.0.0.1]
  ok: port 1514 loopback-only [127.0.0.1]
  ok: port 1515 loopback-only [127.0.0.1]
  ok: port 5601 loopback-only [127.0.0.1]
  ok: port 8220 loopback-only [127.0.0.1]
  ok: port 9200 loopback-only [127.0.0.1]
  ok: port 55000 loopback-only [127.0.0.1]
```
Ports not listening (correct for online --no-llm core-only: 4000/5044/8081/8085/8200/8501/8502/9300/5432 belong to llm/elastic/cluster packs not installed) -> reported "not listening", never a FAIL. No 0.0.0.0/LAN bind on any port. lan_ok=[], profile_open=[], tailnet_ports=[].
### Service checks: ES :9200 http_code=401 (ok), Kibana :5601 http_code=302 (ok). LLM probes correctly NOT run (llm_on=0).
### VM shutdown: graceful `virsh shutdown lme-qemu-some` -> domstate "shut off" (no destroy needed) at 11:35:48Z. Host left CLEAN (teardown rc=0).
### OUTCOME CLASS: (c) CLEAN PASS — reproduces round8 pass contract exactly on wave-9 HEAD 1584970.

---

## LEG 2 — qemu-airgapped / lme-qemu-airgapped-legc

Prior-close (wave7) reference — reproduce EXACTLY:
- host/ip = legc lease IP (poll after boot); REMOTE_DIR = /home/vmuser/LME (bundle lives there; rsync excludes offline_resources so it must pre-exist)
- flags = "--offline --no-llm" (== bare --offline: offline forces install_llm=false; both yield profile=offline, floor=6)
- wave7 banked: expect_min=6, running=6, all loopback, PLAY RECAP failed=0 ignored=1 (fleet metrics-idx timeout = known-good baseline), selinux_debian.yml SKIPPED, podman imported from .nar, HEALTH rc=0, TEARDOWN rc=0

Invocation (airgapped): `--flags "--offline --no-llm"` => offline_on=1 => elastic off, llm off, core_floor=6 => expect_min=6.
Log: /tmp/lme-gate-logs/qemu-airgapped-legc-r9.log
Pre-check: podman-closure.nar (~579762752 bytes) present on target before offline install.

Actual invocation (log /tmp/lme-gate-logs/qemu-airgapped-legc-r9.log):
`testing/e2e/deploy_gate.sh --host 192.168.122.157 --ip 192.168.122.157 --ssh-key .../id_ed25519 --remote-dir /home/vmuser/LME --flags "--offline --no-llm" --label qemu-airgapped-legc-r9 --stage all`

Domain `lme-qemu-airgapped-legc` started 11:36:12Z; DHCP lease hostname is `lme-legc` (short name, not full domain — grep-by-domain missed it); IP confirmed via ARP + lease = 192.168.122.157 (MAC 52:54:00:3b:ac:89), matches banked provenance.

Prechecks (ssh root@192.168.122.157, all PASS):
- hostname=lme-legc, whoami=root, Debian 13 trixie
- rsync=/usr/bin/rsync PRESENT (airgapped rsync-ensure step is a no-op; won't hit apt)
- REMOTE_DIR=/home/vmuser/LME (offline_resources dir lives there; rsync --delete EXCLUDES offline_resources so 21G bundle survives)
- podman-closure.nar = /home/vmuser/LME/offline_resources/packages/nix/podman-closure.nar, **579762752 bytes** (EXACT expected size)
- du offline_resources = 21G (full bundle intact)

### Stage rc table
| stage | rc | notes |
|-------|----|-------|
| start+ip+ssh | 0 | VM up, root ssh OK, IP=.157 |
| nar precheck | 0 | 579762752 bytes present |
| rsync | 0 | 11:38:53; rsync present on target (no apt), bundle excluded/survived |
| wipe | 0 | host verified CLEAN |
| install | 0 | rescued=0; INSTALL rc=0 at 11:54:13 (~15 min) |
| health | 0 | HEALTH result fail=0; rc=0 |
| teardown | 0 | host verified CLEAN |
| **LEG END** | **0** | stage=all rc=0 at 11:54:39 |

### PLAY RECAP: `localhost : ok=286 changed=58 unreachable=0 failed=0 skipped=116 rescued=0 ignored=1`
Recap NUMBERS match the wave7 banked airgapped close EXACTLY (286/58/116, failed=0 rescued=0 ignored=1) — and this is stronger than byte-identity: wave7 ran bare `--offline` on a tree PREDATING `633b241`, whereas r9 ran `--offline --no-llm` on HEAD 1584970. The identical counts show the redundant `--no-llm` and the intervening selinux-guard commit `633b241` both cost ZERO tasks on the offline path. ignored=1 = known fleet.yml metrics-idx timeout baseline (no_log).
### HEALTH floor vs running: expect>=6 vs running=6 (exact floor, matches wave7). llm_on=0, profile=offline. lme.service active. No failed lme units.
### 6 running containers — roster DERIVED (not enumerated): the health probe logs only the COUNT (running=6), never a `podman ps` name list, and the containers are gone post-teardown. Derived roster = 5 core (elasticsearch, kibana, fleet-server, wazuh-manager, elastalert2) + fleet-distribution (offline-only, the +1 vs LEG 1's floor 5), derived from three independent signals: (a) port 8080 listening loopback in the exposure check — fleet-distribution's port, ABSENT in online LEG 1; (b) enabled-manifest set at install log lines 1352-1375; (c) SF-8 preflight lists fleet-distribution as uncapped enabled. HARNESS OBSERVATION (small should-fix for do_health): the gate asserts a running-COUNT with no roster, so a floor met by the WRONG container set would pass silently — recommend the health probe log the container names alongside the count.
### Exposure (all loopback?): YES. fail=0. Per-port verdict:
```
== exposure: loopback-only binds (443 514 1514 1515 4000 5044 5432 5601 8080 8081 8085 8200 8220 8501 8502 9200 9300 55000) ==
  ok: port 443 loopback-only [127.0.0.1]
  ok: port 514 loopback-only [127.0.0.1]
  ok: port 1514 loopback-only [127.0.0.1]
  ok: port 1515 loopback-only [127.0.0.1]
  ok: port 5601 loopback-only [127.0.0.1]
  ok: port 8080 loopback-only [127.0.0.1]   <- fleet-distribution (offline-only)
  ok: port 8220 loopback-only [127.0.0.1]
  ok: port 9200 loopback-only [127.0.0.1]
  ok: port 55000 loopback-only [127.0.0.1]
```
No 0.0.0.0/LAN bind. lan_ok=[], profile_open=[], tailnet_ports=[]. ES :9200=401 (ok), Kibana :5601=302 (ok). LLM probes correctly NOT run.
### Install ran OFFLINE confirmation (scope: install.sh took the OFFLINE CODE PATH — VM is network-reachable/DHCP+ssh, NOT physically isolated): CONFIRMED. Banner "⚠ OFFLINE MODE ENABLED" + "Manifest profile: offline (install_llm=false, elastic_services=false)". Discriminating path evidence (same task, opposite verdict vs online LEG 1):
- install.sh: "Importing podman into Nix store from offline archive..."
- "TASK [nix : Skip Nix installation in offline mode]" (skipped online-only install)
- "podman already imported from .nar file by install.sh"
- "TASK [podman : Load and tag containers from offline resources]" => `included:` (RAN) here; in online LEG 1 the same task => `skipping:`
- "✓ Container images already loaded" (images from the 21G offline bundle, not pulled)
SF-8 preflight advisory WARN on 11.7G host (over_budget advisory=True, oversized hard-gate=[]) — same known-good advisory as wave7, health passed.
### R8-9 selinux_debian.yml skip confirmation: CONFIRMED
```
TASK [base : Include OS-family SELinux management tasks]
skipping: [localhost] => (item=/home/vmuser/LME/ansible/roles/base/tasks/selinux_debian.yml)
```
### VM shutdown: graceful `virsh shutdown lme-qemu-airgapped-legc` -> domstate "shut off" (no destroy needed) at 11:55:56Z. Host left CLEAN (teardown rc=0). Note: rsync --delete EXCLUDED offline_resources, so the 21G bundle + podman-closure.nar survive for future re-close.
### OUTCOME CLASS: (c) CLEAN PASS — byte-identical reproduction of the wave7 banked airgapped close, now on wave-9 HEAD 1584970.

---

## Final state (verified 2026-09-19 ~11:56Z)
- HEAD: 1584970c597f61ec27c523743d7c0a34bcb0b1db (UNCHANGED — no tracked edits, no commits)
- git status --short: only untracked `.cursor/ .ocr/ .opencode/ AGENTS.md scratchpad/` (expected set; scratchpad writes live under already-untracked scratchpad/)
- Domains: win11-2026-6-1 RUNNING (co-tenant untouched); lme-qemu-some shut off; lme-qemu-airgapped-legc shut off
- Tailnet ACL/grants: NOT touched (no tailscale/ACL commands issued this session)
- No sudo used on the silmaril host; all domain control via `virsh -c qemu:///system` as tristan (libvirt group); VM-internal root via id_ed25519.

## Summary
| Leg | Domain | IP | Flags | Floor/running | Exposure | Stages | Outcome |
|-----|--------|----|-------|---------------|----------|--------|---------|
| qemu-some | lme-qemu-some | .238 | --no-llm | 5/5 | all loopback | rsync/wipe/install/health/teardown all rc=0, LEG END 0 | (c) CLEAN PASS |
| qemu-airgapped | lme-qemu-airgapped-legc | .157 | --offline --no-llm | 6/6 (incl fleet-distribution) | all loopback | rsync/wipe/install/health/teardown all rc=0, LEG END 0 | (c) CLEAN PASS |

Both QEMU matrix legs converted from the prior round-9 class-(b) OBSTRUCTION (wrong fresh domains: baseline-key-only vmuser, not root) to class-(c) CLEAN PASS on HEAD 1584970 by using the root-enrolled PRIOR-CLOSE domains. This closes the QEMU-some and QEMU-airgapped matrix legs; it does NOT resolve the round's other open blockers (R8-2/R8-6 conditional, cluster deferral, etc.).
Logs: /tmp/lme-gate-logs/qemu-some-r9.log ; /tmp/lme-gate-logs/qemu-airgapped-legc-r9.log (+ .install.<ts>.log each).
