# Round-9 QEMU Profile-Matrix E2E Legs (CONFIRMATORY)

- Tree: /home/tristan/gitters/LME  branch fix/debian-13-selinux-apt
- HEAD (must stay): 1584970c597f61ec27c523743d7c0a34bcb0b1db
- No tracked edits / commits / policy-ACL edits made. Only untracked scratchpad writes.
- Date: 2026-09-19
- Runtime delta vs prior 868f6d2 qemu closes: ONLY the R8-9 SELinux assert
  (ansible/roles/base/tasks/selinux_debian.yml), which is inert on non-enforcing
  Debian guests (see "R8-9 assert path" below).

## R8-9 assert path (static confirmation from tree)
- Assert lives in `ansible/roles/base/tasks/selinux_debian.yml`:
  "Fail loud on Debian + SELinux Enforcing (LME container policy is RHEL-only)"
  -> `assert: that: [ not (selinux_was_enforcing | bool) ]`.
- It is reached only via `selinux_setup.yml`:
  `include_tasks` with `with_first_found: [selinux_{{ansible_os_family|lower}}.yml, selinux_common.yml]`
  gated `when: selinux_available | default(false)`.
- `selinux_available` is set from `which getenforce` rc (selinux_setup.yml:14-16).
  On a Debian guest WITHOUT getenforce, selinux_available=false, so the
  include_tasks task ("Include OS-family SELinux management tasks") SKIPS and the
  assert never runs. Runtime observation to look for in an install log is a
  `skipping:` on that include task -- NOT a literal "selinux_debian.yml" string
  (Ansible prints task names, not source filenames).

---

## LEG 1 -- qemu-some on domain `lme-gate-a` (12G/4vCPU)

OUTCOME CLASS: (b) OBSTRUCTION -- VM never reached a networked/enrolled state.
No code/config finding. Pipeline could NOT be run (no reachable IP).

### Evidence
- Domain state: `running`, Id 24. CPU time climbed 475s -> 605s -> 658s over the
  observation window (guest is consuming CPU, i.e. not frozen at power-on).
- Disk: /var/lib/libvirt/images/lme-gate-a.qcow2 backed by
  /var/lib/libvirt/images/lme-gate-base.qcow2, plus cloud-init seed
  /var/lib/libvirt/images/lme-gate-a-seed.iso.
  This is a NEW domain built from `lme-gate-base` + a fresh cloud-init seed --
  a DIFFERENT lineage from the prior-close VM `lme-qemu-some`
  (/home/tristan/gitters/_ocr_vms/lme-qemu-some.qcow2). Matches the task's warning
  that gate-a is NOT one of the prior close VMs.
- Firmware: no `<loader secure=...>` / `<nvram>` in dumpxml -> BIOS/SeaBIOS boot,
  so this is NOT the known secure-boot bootloop env gap.
- NIC: `<interface type='network' source=default>` virtio, MAC 52:54:00:eb:03:f4.
- DHCP lease (net `default`): NONE for 52:54:00:eb:03:f4 after ~11 min uptime
  (only co-tenant windows_vm 52:54:00:b8:9e:5f -> 192.168.122.181 holds a lease).
  Polled repeatedly over ~4 min of active retries plus earlier attempts.
- ARP (`ip neigh` / virbr0): NO entry for the gate-a MAC -> the guest has NEVER
  transmitted a packet on the bridge. So this is a guest-side failure to reach
  networking, not a DHCP-server-side miss.
- Console: `virsh screenshot` -> "no screens to take screenshot from" (domain is
  headless: serial pty only, no graphics/video device). Root-cause deeper dig
  blocked by env constraints: qemu log /var/log/libvirt/qemu/lme-gate-a.log is
  root-only (no sudo on host per constraints); `virsh console` needs a
  controlling TTY (unavailable in this harness).

### Why OBSTRUCTION, not FAILURE
No IP => the REAL deploy_gate pipeline (rsync/wipe/install/health/teardown) cannot
target the host at all. What was actually OBSERVED (not inferred): over ~11 min of
steadily-climbing CPU time, ZERO ARP frames ever reached virbr0 from MAC
52:54:00:eb:03:f4, and `virsh shutdown` went unanswered for 130s. Those two facts
are the finding.
CAVEATS on what was NOT established (all un-inspectable under no-sudo / no-TTY /
no-screen): the guest OS was never confirmed to be Debian; no getenforce state was
observed; the backing image lme-gate-base.qcow2 was NOT verified non-blank
(`qemu-img info` was not run) -- so "guest never booted to network" is the most
likely reading but a blank/mis-seeded base is not excluded. Either way this is a
VM-not-provisioned env gap in a freshly-built domain, not a wave-9 code regression.
The _ocr_vms key enrollment could not even be tested (no reachable host). No
brute-force / host SSH reconfig attempted, per constraints.

### Stage rc table (LEG 1)
| stage    | rc  | note                                                        |
|----------|-----|-------------------------------------------------------------|
| (pre) IP | N/A | OBSTRUCTION: no DHCP lease / no ARP after ~11 min; no IP    |
| rsync    | --  | not reached (no target)                                     |
| wipe     | --  | not reached                                                 |
| install  | --  | not reached                                                 |
| health   | --  | not reached                                                 |
| teardown | --  | not reached                                                 |

Teardown of the LME stack: N/A (nothing was installed). gate-a shut down after
this leg to free the 16G budget for LEG 2 (see below).

### gate-a shutdown
- `virsh shutdown` NOT honored (still running after ~130s) -- consistent with a
  guest that never reached a normal running state (no acpid responding).
- `virsh destroy` -> domstate `shut off`. Budget freed for LEG 2.

---

## LEG 2 -- qemu-airgapped on domain `lme-airgap-target` (16G/4vCPU)

OUTCOME CLASS: (b) OBSTRUCTION -- VM reachable but the _ocr_vms key is NOT
enrolled. No code/config finding. Pipeline could NOT proceed past transport.

### Evidence
- Started clean: `virsh start lme-airgap-target` -> running.
- Lineage: disk /home/tristan/gitters/_ocr_vms/lme-airgap-target.qcow2 + seed
  /home/tristan/gitters/_ocr_vms/seed-airgap-target.img (SAME dir as the
  prior-close VMs, unlike gate-a). BIOS boot (no secure-boot loader/nvram).
  NIC virtio on `default`, MAC 52:54:00:f2:51:62, 16 GiB.
- DHCP lease acquired promptly: 192.168.122.170 (hostname `lme-airgap-target`).
  Note .170 matches the prior airgap-proof VM IP -- but see enrollment below.
- SSH: host REACHABLE (TCP+SSH handshake OK, host key added), server offers ONLY
  publickey. The designated key /home/tristan/gitters/_ocr_vms/id_ed25519 is a
  valid ed25519 key (SHA256:zUfpsIe/7gDvoJjPxPR27s14xGdT2c9DmdBnqWR0JXk,
  comment "lme-vm-baseline"). It was OFFERED and REJECTED; ssh-agent keys also
  rejected. Result: `Permission denied (publickey)` for root@192.168.122.170.
  => key NOT in the target's authorized_keys => VM not enrolled.
- REAL pipeline exercised (not ad-hoc): `deploy_gate.sh --host 192.168.122.170
  --ssh-key .../_ocr_vms/id_ed25519 --flags "--offline --no-llm"
  --label airgap-target-qemu-airgapped --stage rsync`
  -> `RSYNC ensure-rsync-on-target FAILED rc=255` (publickey denied)
  -> `=== LEG END stage=rsync rc=255 ===`. Log:
  /tmp/lme-gate-logs/airgap-target-qemu-airgapped.log
- Per task rules: key-auth failure = typed OBSTRUCTION (VM not enrolled), NOT a
  code defect. No brute-force / no host SSH reconfig attempted, per constraints.

### AIRGAP TRAP (podman-closure.nar) -- NOT EVALUABLE
The bundle completeness pre-check (verify offline_resources/packages/nix/
podman-closure.nar ~579762752 bytes exists on the target) requires SSH into the
target to stat the file. With key auth denied there is NO way to inspect the
target's bundle. So the airgap trap is UNDETERMINED for this run -- neither
confirmed-complete nor confirmed-missing. (Do NOT confuse this with the prior .59
env gap, which was a confirmed-missing .nar; here we simply cannot look.)
Consequently the offline install was NOT attempted (correctly -- no transport,
and no verified bundle).

### Stage rc table (LEG 2)
| stage    | rc  | note                                                            |
|----------|-----|-----------------------------------------------------------------|
| rsync    | 255 | FAIL at ensure-rsync-on-target: Permission denied (publickey)   |
| wipe     | --  | not reached (leg ended at rsync)                                |
| install  | --  | not reached                                                     |
| health   | --  | not reached                                                     |
| teardown | --  | not reached                                                     |

Teardown of the LME stack: N/A (nothing installed; no SSH to run wipe_lme.sh).
airgap-target `virsh shutdown` honored -> `shut off` (~15s), confirming it WAS a
properly-booting VM (contrast gate-a) that is simply not key-enrolled.

---

## SUMMARY
- LEG 1 (qemu-some / lme-gate-a): OBSTRUCTION (b) -- no DHCP/no ARP, no IP, could
  not reach pipeline. Env gap in a freshly-provisioned domain, not a regression.
- LEG 2 (qemu-airgapped / lme-airgap-target): OBSTRUCTION (b) -- reachable but
  _ocr_vms key not enrolled; real deploy_gate rsync stage FAILED rc=255
  (publickey). Airgap-trap bundle check not evaluable (no SSH).
- NEITHER leg produced a class (a) code/config FAILURE and NEITHER produced a
  class (c) clean PASS. Both are class (b) VM-provisioning/enrollment env gaps.
- Wave-9 runtime delta (R8-9 SELinux assert): static reading establishes only the
  GATE -- the assert include is `when: selinux_available | default(false)`, and
  selinux_available is set from `which getenforce` rc. So the assert is UNREACHABLE
  whenever getenforce is absent, which is the expected Debian condition. This was
  NOT verified at runtime this session (no leg reached install; no guest observed).
- VM IDENTITY IS UNRELIABLE BY IP HERE: domain `lme-airgap-target` today holds the
  `.170` lease that prior memory notes attribute to "the airgap-proof VM," yet it
  rejects the lme-vm-baseline key. Whether the DHCP pool reassigned .170 or this is
  simply a different domain, IP is not a stable VM identity. Future legs should
  anchor evidence to DOMAIN NAME + DISK PATH, not IP.
- UNBLOCK ACTION: enrolling id_ed25519.pub (SHA256:zUfpsIe.../"lme-vm-baseline")
  into these domains' cloud-init seeds/authorized_keys (or being pointed at domains
  where it already is + that actually reach the network) is the single change that
  turns both obstructions into runnable legs.
- No tracked edits, commits, or policy/ACL edits. Co-tenant win11-2026-6-1 and the
  tailnet ACL/grants untouched. Only untracked scratchpad written.
- Both target VMs left `shut off`.
