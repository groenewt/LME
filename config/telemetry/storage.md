# Dedicated telemetry filesystem

`storage.example.json` describes one run-owned 20 GiB regular image, an exact 2 GiB ext4 root reserve, and five kernel project quotas. MAIN must resolve the writer UID/GID values from the actual host mappings of rootless services before provisioning. Template IDs are examples, never identities discovered from the host.

Use `/data/lme-telemetry/<run>/volume` on guests and graph/silmaril physical sources; use `/home/lme-telemetry/<run>/volume` on the trixie physical source. The regular backing image is its sibling `telemetry.ext4`. Physical source images reserve 20 GiB beyond guest commitments while retaining the parent's 100 GiB free-space floor. Guest images are inside the guest's allocated data disk; set `parent_reserve_bytes` to the guest's approved parent reserve, at least 2 GiB. Preallocation reserves actual backing blocks, including holes an ext4 formatter may create; sparse backing storage is rejected.

Preview the exact plan without mutation:

```sh
python3 -m lme_telemetry.storage --config /etc/lme/telemetry-storage.json plan
```

After MAIN reviews it, run each stage separately as host root:

```sh
python3 -m lme_telemetry.storage --config /etc/lme/telemetry-storage.json prepare
python3 -m lme_telemetry.storage --config /etc/lme/telemetry-storage.json mount
python3 -m lme_telemetry.storage --config /etc/lme/telemetry-storage.json verify
```

`prepare` exclusively creates a new run directory and 0600 regular image. It refuses existing paths, symlinks, nonregular objects and insufficient parent free space. Only its held new-file descriptor goes to mkfs.ext4/tune2fs; no block-device or existing filesystem formatting interface exists. The format enables project quota metadata, preinitializes inode tables/journal, and sets exactly 524288 reserved 4096-byte blocks belonging to UID/GID0. An fsynced image receipt records the plan hash, inode, backing device, UUID and geometry. Partial failure retains the exact run for inspection and prevents implicit reformat/retry.

`mount` attaches only that receipt-identified file with losetup, immediately writes its exact `/dev/loopN` in `mount-receipt.json`, then mounts ext4 with `rw,nodev,nosuid,noexec,prjquota`. It sets inherited directory project IDs and kernel `quotactl(PRJQUOTA)` hard byte/inode limits, assigns host non-root writer identities, and performs readback. No `/etc/fstab`, existing mount, global reserved-block setting, kernel/sysctl, partition or host disk is changed. Existing mounts/receipts are refused for manual diagnosis; this helper does not guess recovery authority.

| Directory | Physical hard cap | Purpose |
|---|---:|---|
| logs | 14 GiB | 4 GiB pending + 8 GiB verified archive, SQLite/WAL overhead |
| metrics-elastic | 512 MiB | 256 MiB logical OTel queue and physical overhead |
| metrics-hertzbeat | 512 MiB | 256 MiB logical OTel queue and physical overhead |
| hertzbeat-native | 512 MiB | HB durable native outbox, accepted copies and receipts |
| sources | 512 MiB | Source offsets/reconciliation/adapter state |

The sum of project caps is 16 GiB. A further 2 GiB accommodates filesystem metadata/overhead and 2 GiB is reserved from non-root allocation. Core logical telemetry capacity remains 12.5 GiB per full-mirror source node; 20 GiB is the physical commitment. Quota exhaustion yields ordinary ENOSPC/EDQUOT pressure and must preserve pending source data. It does not authorize deleting unverified records. Tune physical headroom only after actual workload qualification.

Bind each writer directory into its owner container/runtime; all five must live on this same dedicated mount. The HB receipt worker uses the HB host-mapped UID. Writers must not have host UID0, membership in reserved host GID0, host CAP_SYS_RESOURCE/CAP_SYS_ADMIN, or access to the backing image/loop device. Rootless container UID0 is acceptable only when mapped to the configured non-root host UID. The reserve protects this filesystem from these writers; it is not protection against arbitrary host root. Filesystem `f_bavail` excludes reserved blocks, so existing application checks for another 2 GiB available remain conservative.

`verify` requires actual ext4 mount identity, exact loop backing file, image inode/UUID/size/private ownership, root reserve, project inheritance, and kernel quota hard-limit readback; none are inferred from configuration. It reports both total free bytes (`f_bfree`) and non-root available bytes (`f_bavail`). Start writers only after this succeeds. Service startup must depend on this verified mount and fail if it is absent, preventing fallback writes into the unmounted host directory.

Cleanup is explicit: stop only the run-owned writers; inspect `mount-receipt.json` and `losetup --json` for its exact image, then unmount only the recorded mountpoint and detach only its recorded `/dev/loopN`. Never use lazy/forced unmount, `losetup -D`, wildcard cleanup, or delete the image as part of pressure handling. A mounted/partial run remains evidence until MAIN authorizes retention cleanup.

Offline qualification creates only a temporary 64 MiB regular image with an 8 MiB synthetic reserve, exercises actual mkfs.ext4/tune2fs, and verifies superblock reserve ownership, project quota inode/features, full physical allocation and private permissions. The production geometry is fixed at 20 GiB/2 GiB. No live loop mount or project-quota enforcement test was performed by the implementation agent; MAIN must qualify those exact stages before claiming runtime storage protection.

Reboot recovery uses `python3 -m lme_telemetry.storage --config FILE remount`. It accepts only a previous `ready` receipt (or an interrupted remount of that qualified image), checks the exact image/plan identity, and uses an existing unmounted association or attaches that same image again. The loop number may change after reboot; the new exact device is recorded before mounting. It never formats, recreates writer directories, changes ownership, or resets quotas. Existing project metadata and persisted kernel hard limits must pass full `verify`; mismatches fail startup. A wrong/partial initial-provisioning receipt, occupied mountpoint, ambiguous association, or mount elsewhere is refused.

`lme-telemetry-storage.service.example` is the managed boot contract. MAIN must render the exact package path, storage config, parent path (trixie physical uses `/home/lme-telemetry`) and writer unit dependencies. Install it as a root system unit after successful initial prepare/mount/verify; source, log, OTel and HB writer services must require and order after it. The helper needs the host mount namespace, so filesystem namespace hardening such as `ProtectSystem` or `PrivateMounts=yes` must not hide its mount from writers. It grants only the system-administration capability needed for the exact loop mount and quota readback. The unit does not unmount/delete anything on stop. Tests exercise the recovery decisions with mocked privileged mount boundaries, plus the existing real offline image tests; no live remount occurred here.
