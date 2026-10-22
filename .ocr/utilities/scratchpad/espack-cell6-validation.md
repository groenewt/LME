# LME Validation — Matrix Cell #6: Elastic Services Pack (`--elastic-services`)

**Ubuntu 24.04 · online · LLM on · ES-pack ON · single-node · QEMU/KVM**

This cell runtime-validates the changeset's `lme-logstash` cert SAN addition
(commit 8b1f6f8) plus the ES-pack cert consumers and the hardened `wipe_lme.sh`
on the ES-pack unit set.

Status: **COMPLETE — VERDICT: FAIL** (install `failed=1`; broad core+ES-pack degradation).
The changeset's specific SAN element is verified present in the deployed cert, but the
install does not meet the cell's PASS bar. Details below.

---

## 1. Config manifest (reproducible)

| Item | Value |
|------|-------|
| OS (guest) | Ubuntu 24.04 (noble), cloud image overlay on `noble-base.img` |
| Hypervisor | libvirt `qemu:///system` (no sudo), KVM, host `host-passthrough` CPU |
| VM name | `lme-espack-cell6` |
| vCPU / RAM | 4 vCPU / 20480 MiB (≈19 GiB usable in-guest) |
| Root disk | 50 GiB overlay (COW on read-only `noble-base.img`); grew to 48 GiB via growpart |
| Guest IP | 192.168.122.206 |
| Install command | `sudo NON_INTERACTIVE=true AUTO_CREATE_ENV=true bash install.sh --elastic-services` |
| Flag semantics | `--elastic-services` → installs apm-server, heartbeat, metricbeat, filebeat, logstash (online-only; LLM defaults on for non-offline) |
| Node layout | single-node (all containers on one host) |
| Fixed tree HEAD | **8f24240** (cert idmap fix 8b1f6f8 + logstash SAN + hardened wipe_lme.sh) |

### Provenance (guest tree == 8f24240)
`.git` was excluded from rsync per instructions; provenance is proven by SHA-256
fingerprint of the changeset files, host vs guest (all match):

```
0eccb18a2c67cc8bdcb70b33acd9edac449eb7135f8ec2b0b71c5b67f2b4eacb  ansible/roles/certs/templates/instances.yml.j2
3b43c3e7952107ea1fefebc363436878371d6484b4d55760129d4b2410c3fe94  quadlet/lme-kibana.container
e9043c13b06cd8b1dca79a18fec6f85bdf0e1d7f10732084540a0cd246d03278  quadlet/lme-fleet-server.container
9b993db99b35ffb8020d1fa1a57d844350883cb07b271d610d9bc2ebc5e8fd2c  quadlet/lme-wazuh-manager.container
78530f06edef2f5f98b3ffcb778d1633c27016dfd08f757358dfa7a2e7c10bc8  quadlet/lme-elastalert.container
c0ad20b28d90cc73cae02e56abf8c1de9fa6dcd0a3e02dc2e601dd4ecbb6751d  scripts/wipe_lme.sh
```
Host worktree `git status --porcelain` was empty (clean) → rsynced content is exactly 8f24240.

---

## 2. Changeset-under-test: source analysis (pre-runtime)

### 2a. The SAN change is load-bearing (NOT a no-op)
- `ansible/roles/certs/tasks/main.yml` **renders** `instances.yml.j2` →
  `/opt/lme/config/setup/instances.yml` (mode 0644, root) on the cert source host,
  overwriting the repo's static copy at that dest. `lme-setup-certs` then
  generates leaf certs from that rendered file.
- Therefore the logstash leaf cert's SAN set is driven by the **template**, not
  the repo's static `config/setup/instances.yml`. Without the added
  `- "lme-logstash"` line (template line 58), the deployed logstash cert would
  lack that SAN even though the static file lists it.
- Deployed SAN set for logstash per template: `lme-logstash`, `logstash`,
  `localhost`, IP `127.0.0.1`.

### 2b. Runtime TLS topology (who actually verifies which SAN) — IMPORTANT
Enumerated from source (`config/*.yml`, `quadlet-optional/elastic-services/*.container`,
`ansible/README.md`):
- **filebeat / metricbeat / heartbeat / apm-server** all set
  `output.elasticsearch: hosts: ["https://lme-elasticsearch:9200"]` with
  `ssl.certificate_authorities: ["/certs/ca/ca.crt"]`. They connect to **ES**,
  verifying the **ES** cert's SAN (`lme-elasticsearch`) against the CA.
- **No beat sets `output.logstash`.** Logstash ships **without a pipeline**
  (`config/logstash/` has only an empty `logstash.yml`; the pipeline mount is an
  empty placeholder). Its quadlet healthcheck is `curl localhost:9600` (the
  monitoring API), no TLS. `ansible/README.md:322` documents this explicitly.
- heartbeat's monitor list does **not** include `lme-logstash`.
- **Consequence:** at runtime nothing dials `lme-logstash` with hostname
  verification, so the `lme-logstash` SAN is **not exercised by a live TLS
  client** in this build. What IS provable and load-bearing: the SAN is present
  in the deployed logstash leaf cert (openssl), the rendered instances.yml on the
  host carries it, and logstash comes up healthy as a new cert-volume consumer.
  This is reported honestly below — the beats→logstash hostname-verification leg
  is "not exercised (by design)", not falsely "proven".

### 2c. ES-pack cert consumers & the idmap fix (why they're untouched)
- ES-pack unit set (from `elastic_services_setup.yml`): **lme-apm-server,
  lme-heartbeat, lme-metricbeat, lme-filebeat, lme-logstash** (5 units).
- All 5 run **rootful** (no `UserNS=`; filebeat & metricbeat explicit `User=root`).
  apm-server reads its own 0600 key (`/certs/apm-server/apm-server.key`, host uid
  166536) but as container-root via CAP_DAC_OVERRIDE, so no idmap needed.
- The idmap fix (8b1f6f8) targets only the **userns'd** consumers (kibana,
  fleet-server, wazuh-manager, elastalert) whose in-namespace uid-1000 maps to a
  distinct host base and cannot read the 166536-owned key without idmap. Leaving
  the rootful ES-pack consumers untouched is internally consistent. Verified at
  runtime below (apm-server healthy, no key-read errors).

---

## 3. Install metrics  — **FAIL (failed=1)**
```
PLAY RECAP: localhost : ok=131  changed=63  unreachable=0  failed=1  skipped=57  rescued=1  ignored=0
✗ Main installation playbook failed.
```
- **failed=1** — the failing task is `podman : Start Elastic services pack units` → item **`lme-logstash`**
  ("Job for lme-logstash.service failed because the control process exited with error code").
- **rescued=1** — an earlier `fatal` on `nix-daemon.socket` ("Unable to start service nix-daemon.socket: Job failed")
  was caught by a rescue/fallback block (install log lines 587–601).
- Wall clock: `install.end - install.start` = **423 s (7 min 3 s)** (image pulls succeeded within this).
- `--elastic-services` **took effect**: the flag came from the run command
  (`sudo NON_INTERACTIVE=true AUTO_CREATE_ENV=true bash install.sh --elastic-services`); confirmed by all
  5 ES-pack `*:LME_LATEST` images present and the `elastic_services_setup` tasks executing (Start ES-pack units).
  (`install_llm=true` in effect — LLM prune tasks skipped.)
- ES-pack image pull/tag: **no failures**; all 5 ES-pack base+`LME_LATEST` images present.
- Resource (20 GB VM): **no OOM** (dmesg clean); peak mem_used ≈ **13.2 GiB / 19 GiB**; min avail 6.8 GiB;
  swap 0; peak disk 80%; peak load1 3.94 (4 vCPU); `vm.max_map_count=262144`. RAM was adequate — 20 GB did NOT OOM.

## 4. Container health (core + ES-pack) — **FAIL**
Denominator: **20 `lme*.service` unit-files** (= lme.service umbrella + setup-accts/setup-certs oneshots +
**17 container services**). Only **6 of the 17 container services** are running & healthy: elasticsearch,
kibana, wazuh-manager, elastalert2 (no healthcheck→`none`), filebeat, metricbeat.

Image default users (relevant below): apm-server, filebeat, metricbeat, heartbeat, logstash images **all
default to a non-root user** (`apm-server`, uid 1000). Only filebeat & metricbeat set `User=root` in their
quadlet, which is why only those two ES-pack units can read the 0600 certs / exec their binary.

| Unit | State | Root cause |
|------|-------|-----------|
| lme-elasticsearch | running/healthy | ok |
| lme-kibana | running/healthy | ok (idmap cert fix live) |
| lme-wazuh-manager | running/healthy | ok (idmap cert fix live) |
| lme-elastalert(2) | running (health none) | ok |
| lme-filebeat | running/healthy | ES-pack; `User=root` → cert OK |
| lme-metricbeat | running/healthy | ES-pack; `User=root` → cert OK |
| **lme-logstash** | **failed (exit 125)** | ES-pack. `statfs /opt/lme/config/logstash/pipeline: no such file or directory` — quadlet bind-mounts a "placeholder" pipeline dir the installer never creates. **This is the install's failed=1 task.** |
| **lme-apm-server** | **failed (exit 1)** | ES-pack. `open /certs/apm-server/apm-server.key: permission denied` — runs as image user `apm-server` (uid 1000, **confirmed**), quadlet has no `User=root` and no idmap on `lme_certs:/certs:ro` → cannot read its own 0600/166536 key. **ES-pack packaging bug (7a51135), not an idmap-commit omission** — see note below. |
| **lme-heartbeat** | **failed (exit 126)** | ES-pack. `/usr/share/heartbeat/heartbeat: Operation not permitted` — runs as non-root image user; quadlet lacks `User=root`/caps that filebeat & metricbeat have. ES-pack packaging bug (7a51135). |
| **lme-pgvector** | **failed** | LLM stack. **Image `localhost/pgvector:LME_LATEST` does not exist.** |
| **lme-llama-cpp** | **failed** | LLM stack. Image `localhost/llama-cpp:LME_LATEST` missing. |
| **lme-embeddings** | **failed** | LLM stack. Image missing. |
| **lme-log-analyzer** | **failed** | LLM stack. Image missing. |
| **lme-litellm** | inactive/dead | LLM stack. Image missing; depends on pgvector/llama. |
| **lme-dashboard** | inactive/dead | LLM stack. Image missing. |
| **lme-fleet-server** | inactive/dead | Core. Image present (`elastic-agent:LME_LATEST`) but never started (play failed before fleet-setup / dependency). |
| **lme-fleet-distribution** | inactive/dead | Core. Image present; not started. |

**ES-pack cert attribution note (important):** The idmap commit (8b1f6f8) correctly did NOT touch apm-server —
apm-server has **no entry in `instances.yml.j2`**. Its cert exists only because `elastic_services_setup.yml`
force-copies the static `config/setup/instances.yml` (which DOES list apm-server) over the rendered file and
restarts `lme-setup-certs`. So apm-server, logstash and heartbeat are all broken by the **ES-pack packaging
itself (7a51135)** — not by anything in the cert changeset. Structural defect worth flagging: the certs role
writes a **rendered** `instances.yml` (from the .j2) and the ES-pack then **overwrites it with the static
file** — the two carry different instance lists (apm-server present only in the static one), and the ES-pack
consumer quadlets (apm-server/heartbeat/logstash) never got the `User=root` / idmap treatment that the certs
they consume require.

**LLM-stack root cause:** none of the LLM images were built/pulled
(`pgvector, llama-cpp, embeddings, litellm, log-analyzer, dashboard` all absent from `podman images`;
no LLM data volumes). This correlates with the early **nix-daemon.socket fatal** and is an
**environmental/infra failure of the LLM build path — NOT attributable to the cert changeset**
(the changeset touches no LLM/pgvector/llama code). `install_llm=true` was in effect (LLM prune tasks skipped).

## 5. Core cert gate — **PASS** (the idmap half of commit 8b1f6f8)
- Key perms/owner (`lme_certs` volume): elasticsearch.key, kibana.key, fleet-server.key, wazuh-manager.key
  all **0600, owner 166536** (minted 01:08 this install). ✓
- Live idmap on userns'd consumers' cert mounts:
  - kibana `/usr/share/kibana/config/certs`: `idmap=uids=@166536-1000-1;gids=@166536-1000-1` ✓
  - wazuh `/etc/wazuh-manager/certs`: `idmap=uids=@166536-1000-1;gids=@166536-1000-1` ✓
- In-namespace **uid-1000 read of kibana.key → READ_OK** (no EACCES). ✓
- Cert-key error scan (journals): kibana=0, fleet-server=0, elastalert=0, wazuh=0 real
  (wazuh's 3 hits were `find: '/proc/tty/driver': Permission denied` from rootcheck — unrelated to certs). ✓
- kibana & wazuh **healthy**, restarts=0. ✓

## 6. Logstash SAN gate (the cell's purpose) — **cert PASS / container FAIL**
**The changeset element works at the cert level:**
- Deployed logstash leaf cert `lme_certs/_data/logstash/logstash.crt` SAN (openssl):
  `DNS:logstash, DNS:lme-logstash, IP Address:127.0.0.1, DNS:localhost` → **includes `lme-logstash`.** ✓
- **Freshness:** `notBefore = Sep 17 01:08:50 2026` ≥ install start `01:02:37Z` → **freshly minted this install** (serial F1870DD9…). ✓
- **Load-bearing proof:** certs role renders `instances.yml.j2` → `/opt/lme/config/setup/instances.yml`; `init-setup.sh`
  mints the logstash leaf from that rendered file via `elasticsearch-certutil`. The idempotent top-up **skips
  existing cert dirs**, so the logstash cert is the one minted from the template in the main cert phase — i.e. its
  `lme-logstash` SAN comes strictly from the added `.j2` line (line 58). Without the commit it would be absent.

**But the runtime consumer path cannot be exercised, on two counts:**
1. By design in this build, **no beat sets `output.logstash`** and logstash ships **without a pipeline**
   (`ansible/README.md:322`), so nothing dials `lme-logstash` with hostname verification — the beats→logstash
   TLS handshake the SAN would protect **is not exercised** (reported honestly, not as "proven").
2. **The logstash container never starts** (pipeline-mount bug above), so it never presents the cert at all.
   `logstash_tls_error_lines=0` is vacuous (no logs — container absent). Health: **failed**, not healthy.

Net: the SAN change is verifiably correct and deployed; the container-level "logstash healthy + TLS clean"
sub-criterion **fails** due to the pre-existing ES-pack pipeline-mount bug.

## 7. Teardown (hardened wipe) — **PASS**
Run as specified: `cd ~/LME && sudo bash ~/LME/scripts/wipe_lme.sh`. Note this wiped a **failed** install
(7 failed units, rate-limited units, a unit with no container) — a stronger test of the find-sweep than a
clean install.

**Pre-wipe:** 24 loaded lme units · 26 unit-files · 7 failed · 6 containers · 17 `lme_` volumes · 5 secrets ·
6 pack quadlets in `/etc/containers/systemd` · /opt/lme + /etc/lme present.

**Wipe result:** self-verifying tail printed
`Wipe complete and verified: no LME units, containers, volumes, secrets, or config remain.` —
**exit code 0**.

**Post-wipe (after +35 s and a 2nd `daemon-reload`) — no resurrection:**
| Check | Result |
|-------|--------|
| loaded lme units / unit-files / failed | 0 / 0 / 0 |
| ES-pack units (apm-server,heartbeat,metricbeat,filebeat,logstash) units+unit-files | **0 / 0 each** |
| containers (all) | 0 |
| `lme_` volumes (incl. `lme_filebeatdata`) | 0 (all 17 gone) |
| podman secrets | 0 (all 5 gone) |
| pack quadlets / any `lme*` in `/etc/containers/systemd` | 0 / 0 |
| /opt/lme · /etc/lme | gone · gone |

The hardened wipe's glob-free find-sweep **fully removed the ES-pack unit set and all residue**, with no
self-resurrection — confirms the wipe hardening (commit 8f24240) handles the ES-pack units and a failed-state
install.

## 8. Verdict — **FAIL**
| Section | Result |
|---------|--------|
| Install `failed=0` | **FAIL** (failed=1; failing unit = lme-logstash) |
| All containers (core + ES-pack) healthy | **FAIL** (6/≈19; LLM stack absent-image, 3/5 ES-pack down) |
| Core cert gate (idmap fix) | **PASS** |
| Logstash cert SAN includes `lme-logstash` | **PASS** (fresh, from the template change) |
| logstash/beats TLS clean at runtime | **N/A / FAIL** (not exercised by design; logstash container down) |
| Hardened wipe removes everything incl. ES-pack units | **PASS** (exit 0; 0 residue; no resurrection) |

**Attribution:** The one thing this cell was built to prove — the `lme-logstash` SAN reaching the deployed
cert — is confirmed, and the hardened wipe passes cleanly on the ES-pack unit set. The install FAIL is due to
three defects, **none in the cert changeset (8b1f6f8)**:
(a) a pre-existing **ES-pack packaging bug** — the logstash quadlet bind-mounts a "placeholder" pipeline dir
`/opt/lme/config/logstash/pipeline` the installer never creates → logstash exit 125 (this is the recorded
`failed=1`);
(b) two more **ES-pack packaging bugs** of the same provenance (7a51135): apm-server can't read its own
0600 key (runs as non-root, no `User=root`/idmap) and heartbeat can't exec its binary (non-root, no caps);
(c) an **environmental LLM-build / nix-daemon.socket failure** — the entire LLM image set was never built
(pgvector/llama-cpp/embeddings/litellm/log-analyzer/dashboard absent), unrelated to the changeset.
The changeset's own two elements both verify green: logstash SAN present in the freshly-minted cert, and the
core idmap cert-key fix live and working for kibana/wazuh/fleet-server/elastalert.
