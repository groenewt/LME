
---
## LEG HANDBACKS (2026-09-19, HEAD 868f6d2)

### LEG A — AIRGAPPED = CLOSED ✓ (earlier; see memory ocr-round8-progress)

### LEG B — 3-NODE CLUSTER = TYPED OBSTRUCTION (structural, NOT wave-7 regression)
Real pipeline `./install.sh --cluster --no-llm`, master es1=lme-qemu-some(32G,.238), es2=lme-deb13(.250), es3=lme-builder(Ubuntu,.88).
- **Stage:** Phase-1 site.yml (implicit localhost) → elasticsearch role → ES health-wait → `fatal: Elasticsearch is not ready after 15 minutes`. INSTALL_RC=1. **Phase-2 never started.**
- **ROOT CAUSE (sharper than map R8-2):** Phase-1 renders master ES quadlet with **ZERO discovery keys** (no discovery.seed_hosts / cluster.initial_master_nodes / network.publish_host / discovery.type). Cluster profile drops `discovery.type:single-node` → `network.host:0.0.0.0` → ES enters production mode → **bootstrap check hard-refuses startup** ("at least one of [discovery.seed_hosts, discovery.seed_providers, cluster.initial_master_nodes] must be configured"). ES crash-loops → 60×15s wait exhausts.
  - Why keys absent: host_vars/es1.yml keyed to inventory host `es1`, but Phase-1 runs on `localhost` (no -i) → don't load; legacy shim gated `when: es_node_name is defined`, install.sh master_extra_vars never passes it (passes es_cluster_seed_hosts + es_master_publish_host, the latter has **NO consumer in the tree**).
- **CLOBBER (R8-7) verdict:** real STATIC defect (combine() makes host_vars example IPs win LAST) BUT **unobservable by construction on a real run** — Phase-1 dies before Phase-2 ever renders host_vars. CLOBBER bites only IF Phase-1 discovery is fixed first.
- **TWO STACKED blockers:** (c) missing Phase-1 discovery keys + (2) even if plumbed, `cluster.initial_master_nodes:"lme-elasticsearch,es2,es3"` needs 2/3 majority but install.sh runs Phase-1 master health-wait to completion BEFORE Phase-2 starts es2/es3 → lone master can never reach quorum. **Real fix surface = Phase-1/Phase-2 ordering** (bootstrap Phase-1 master as single initial master, then join es2/es3), not just var plumbing.
- **Not-the-blocker (excluded w/ evidence):** SSH wire clean (✓ all nodes reachable), SF-8 pass ("No single service exceeds usable host RAM", 32G master), inventory/prereqs clean.
- **SECONDARY finding (R8-9, NEW, on-branch!):** LME on Debian-13 **SELinux Enforcing** dies at `lme-setup-certs` — container `exec /bin/tini: Permission denied` (systemd-service SELinux context; bare `podman run --userns auto` works). Cause: `roles/base/tasks/selinux_common.yml` deploys container SELinux policy **RedHat-family ONLY** ("SELinux policy management not supported on Debian; skipping"). So Debian+SELinux-Enforcing can't start certs. Directly in fix/debian-13-selinux-apt domain, previously unrecorded.
- **Teardown:** wipe_lme all 3 nodes rc=0 verified clean; `git checkout host_vars/` done → tree byte-identical to HEAD (only 5 untracked tooling entries); cluster.yml gitignored → no commit contaminated. All VMs shut off + defined. win11/airgap untouched.

### LEG C — BARE-METAL-SOME on GRAPH = IN FLIGHT (self-completing via real pipeline)
`deploy_gate.sh --host graph --ip 100.73.170.86 --graphroot /data/lme-storage --flags --no-llm --stage all` (PID 893199 alive, ~19min). rsync✓ wipe rc=0 ✓ → install.sh --no-llm running. Currently: Kibana→ES connection rescue/retry loop (Errno111 Connection refused, 10 inner attempts exhausted → outer rescue restart-Kibana, bounded retry counter). 4 LME containers up. `--stage all` will drive to INSTALL_RC → health → teardown automatically → clean verdict. MONITOR /tmp/lme-gate-logs/baremetal-some-graph-round8.console.log to PIPELINE_EXIT.

### MATRIX (HEAD 868f6d2, round-8): airgapped=CLOSED, cluster=OBSTRUCTION(structural Phase-1), bare-some=in-flight, qemu-some=pending(silmaril freed), tailscale=CLOSED(prior).

### LEG C UPDATE — bare-metal-some GRAPH = CLOSE-in-progress (health passed)
Real pipeline `deploy_gate --host graph --ip 100.73.170.86 --graphroot /data/lme-storage --flags --no-llm --stage all`:
- WIPE (pre) complete; **INSTALL rc=0** (Kibana warmup race + fleet metrics-idx soft point both resolved).
- **HEALTH rc=0** — running=5 (core --no-llm floor met), Kibana :5601 http_code=302 ok, **fail=0**, exposure gate passed (loopback-only: ES 127.0.0.1:9200, kibana 443/5601, wazuh 1514/1515/55000/514, all 127.0.0.1).
- TEARDOWN (wipe_lme.sh) in progress at capture ("Stopping 18 lme unit(s)"). Awaiting agent handback for teardown rc + co-tenant preservation confirm → then bare-metal-some CLOSED on HEAD 868f6d2.

### LEG C FINAL — bare-metal-some GRAPH = **CLOSED** ✓ (HEAD 868f6d2)
Handback verdict CLOSE. Real pipeline all stages rc=0: RSYNC/WIPE/INSTALL(rescued=1)/HEALTH/TEARDOWN.
- LEG START→END rc=0; PLAY RECAP ok=359 changed=70 failed=0 rescued=1 ignored=1.
- HEALTH rc=0: running=5 ≥ core floor 5 (--no-llm), fail=0; ES :9200=401, Kibana :5601=302; deny-by-default exposure clean over full 18-port manifest set — 8 listeners ALL loopback (443/514/1514/1515/5601/8220/9200/55000), NO 0.0.0.0 TCP/UDP.
- TEARDOWN rc=0 co-tenant preserved (graphroot-aware verify): /data/lme-storage=496K == pre-deploy baseline; 0 LME containers (default-root AND --root /data); /opt/lme + /etc/lme absent; tailscale serve baseline untouched; only sshd+tailscale+dhcp listeners survive == baseline.
- Deviations (justified+pre-verified): --graphroot /data/lme-storage (siting; root fs 26G vs /data 870G); --ip 100.73.170.86 advertise-only (AUTO_IP→env, NOT a bind; all ports hard-bind 127.0.0.1) — empirically confirmed by exposure gate.
- **REVIEW-LANE note:** rescued=1 (Kibana warmup verify-loop self-heal, roles/kibana/tasks/main.yml:21) is WARN-only without --strict; a --strict re-run WOULD flag it FAIL. Whether bare-metal-some must run --strict = operator call (round-8 review should-fix/Q). Honest caveat: agent did not `podman ps` while up → count met floor + 2/5 services probed, not all 5 names observed.

### MATRIX (round-8, HEAD 868f6d2): airgapped=CLOSED✓ | bare-metal-some=CLOSED✓ | cluster=OBSTRUCTION(Phase-1 structural) | qemu-some=RUNNING | tailscale=CLOSED(prior)

### LEG qemu-some FINAL = **CLOSED** ✓ (HEAD 868f6d2, VM lme-qemu-some .238, 16G)
Handback CLOSE. deploy_gate --host 192.168.122.238 --flags --no-llm --stage all; all 5 stages rc=0.
- LEG START→END rc=0; PLAY RECAP ok=285 changed=62 failed=0 rescued=0 ignored=1.
- INSTALL rc=0 (rescued=0 — no masked rescue); HEALTH rc=0: running=5 ≥ floor 5 (**first DIRECT observation of online core-only --no-llm floor**, 4618d53 called it derived-not-observed); fail=0; exposure all-loopback over 18-port set (443/514/1514/1515/5601/8220/9200/55000 =127.0.0.1, rest not-listening), NO 0.0.0.0; ES :9200=401, Kibana :5601=302. Exposure set from PRIMARY manifest walk (PyYAML present).
- SF-8 **advisory WARN** (honest 16G box, NOT masked by 32G): "capped MemoryMax total 16.0G exceeds usable 13.6G on 15.6G host... Consider --no-llm" — hard-fail check separately PASSED ("No single service exceeds usable host RAM"); --no-llm used, ran fine at floor=5 no OOM. (This is the SF-8 behavior the 16G revert was meant to surface.)
- TEARDOWN rc=0; VM clean (0 LME containers/units/listeners), shut off, DEFINED; win11 untouched.
- Tree fidelity: rsync 07:12:53Z BEFORE wave-8 commits (c33f567 @07:15:13Z); diff 868f6d2..c33f567 = comment/docstring only + cluster-only host_vars (unreachable single-node) → faithful 868f6d2 test. Transport: added ~/.ssh/config Host 192.168.122.238 block (outside repo, authorized).

### ===== MATRIX COMPLETE (round-8, HEAD 868f6d2, REAL pipelines) =====
airgapped=CLOSED✓ | bare-metal-some=CLOSED✓ | qemu-some=CLOSED✓ | tailscale=CLOSED✓(prior) | cluster=TYPED OBSTRUCTION (Phase-1 structural, honest — not a faked pass)

---
## TAILSCALE SVC-SERVE LEG (single-host, graph, HEAD)
Date: 2026-09-19. HEAD = c33f567 (wave-8 tip). Host = graph (100.73.170.86, graph.tail6c2eb6.ts.net), tailscale 1.102.4.
Purpose: re-validate the post-refactor tailscale SVC/VIP leg. `tailscale_service.yml` now derives its `svc:<name>` VIPs from `lme_services` via the `load_manifests.yml` render refactor (commit 25c7214), which landed AFTER the prior tailscale close (a6d92fca). This proves the post-refactor SVC leg renders + advertises on HEAD.

### Leg command (exact)
```
testing/e2e/deploy_gate.sh --host graph --graphroot /data/lme-storage \
  --flags "--tailscale --profile tailscale" --stage all --label ts-svc-head
```
online+llm deploy (`--profile tailscale` flips UI/API binds to loopback; `--tailscale` enables ingress+egress+services legs via install.sh:764 EFFECTIVE_TAILSCALE_OVERRIDE). Log: /tmp/lme-gate-logs/ts-svc-head.log

### Wiring verified (static, on HEAD) BEFORE run
- `tailscale_service.yml` IS included in `ansible/roles/podman/tasks/main.yml:329-331`, gated `tailscale_serve_services | default(false)` (G2 done).
- `install.sh:764`: `--tailscale` (TAILSCALE_MODE=true) sets `-e tailscale_serve_ingress/egress/services=true` — enables all three legs composed with the profile.
- `manifests/profiles/tailscale.yml` flips kibana(443+5601), dashboard(8502), log-analyzer(8501), litellm(4000) to bind:127.0.0.1 and sets serve_ingress/egress/services:true.
- SVC VIP name = `tailnet_service | default(id)`; NO `tailnet_service` declared anywhere → every VIP name = service id.

### Manifest-derived SVC set I expect (install_llm=true, install_elastic_services=false; enabled_when + loopback host publish_ports):
- svc:kibana --https=443 (kibana [always]; lowest of 443/5601)
- svc:elasticsearch --https=9200 (elasticsearch [always])
- svc:fleet-server --https=8220 (fleet-server [always])
- svc:dashboard --https=8502 (dashboard [install_llm])
- svc:log-analyzer --https=8501 (log-analyzer [install_llm])
- svc:litellm --https=4000 (litellm [install_llm])
- svc:pgvector --https=5432 (pgvector [install_llm])
- svc:embeddings --https=8081 (embeddings [install_llm])
NOTE: task's stated "expected" set (kibana_https/litellm/dashboard/log-analyzer) is the UI/API subset; the FULL derivation also fronts the [always]/[install_llm] backend loopback services above. Ground truth = the `Show the derived tailnet VIP endpoints` debug line + live `serve status`. logstash/apm-server are [install_elastic_services] → OFF this leg (no --elastic-services); their ingress serves (5044/8200) will NOT be present.

### PRE-STATE (co-tenant baseline, captured 2026-09-19 before launch)
```
=== serve status ===
No serve config
=== serve get-config --all ===
{
  "version": "0.0.1"
}
=== lme-storage ===
496K	/data/lme-storage
```
graph self: 100.73.170.86  graph  graph.tail6c2eb6.ts.net  linux
**No co-tenant serve entries present** (no svc:vncserverwindow / svc:windows11 / svc:webui). Baseline is EMPTY. => co-tenant SCOPING cannot be exercised this run (nothing to protect). The teardown's scoped-removal commands (wipe_lme.sh 4a: `serve --https/--tcp <port> off` for 8200/4000/5044; 4b: `serve clear svc:<name>` per LME-owned VIP present in status; 4c: blanket reset ONLY when no foreign svc present) will be reported verbatim from the log as the scoping evidence, since the empty-in/empty-out diff alone cannot discriminate scoped vs blanket.

### RESULTS

#### RSYNC / WIPE
- RSYNC rc=0 (08:12:37Z). WIPE (pre-install teardown+self-verify via tree's own scripts/wipe_lme.sh) ran; pre-wipe reset "Resetting LME-owned tailscale serve/ingress config (co-tenant serves left intact)..." (console line 16). Install stage proceeded.
- SF-8 preflight (advisory) on the 15.5G graph host: "capped MemoryMax total 28.0G of usable 13.5G ... over_budget(advisory)=True oversized(hard-gate)=[]"; HARD-FAIL check PASSED ("No single service exceeds usable host RAM"). Enabled capped set includes llm pack (pgvector/embeddings/log-analyzer/litellm/dashboard/llama-cpp) => confirms install_llm=TRUE.

#### SVC ADVERTISE — captured LIVE during install window @ 08:21:37Z (ground truth)
DERIVED set from ansible debug task "Show the derived tailnet VIP endpoints and their serve mode" (console lines 1298-1327) — 10 targets, ALL scheme=https:
```
svc:pgvector         -> https 127.0.0.1:5432
svc:wazuh-manager    -> https 127.0.0.1:1514
svc:embeddings       -> https 127.0.0.1:8081
svc:log-analyzer     -> https 127.0.0.1:8501
svc:litellm          -> https 127.0.0.1:4000
svc:elasticsearch    -> https 127.0.0.1:9200
svc:kibana           -> https 127.0.0.1:443
svc:fleet-server     -> https 127.0.0.1:8220
svc:dashboard        -> https 127.0.0.1:8502
svc:fleet-distribution -> https 127.0.0.1:8080
```
LIVE `tailscale serve status` (advertised VIPs, tailnet-only) — 10 svc:<name> entries, EXACTLY matching the derived set:
```
https://dashboard.tail6c2eb6.ts.net:8502 (tailnet only) (svc:dashboard)          -> https+insecure://127.0.0.1:8502
https://elasticsearch.tail6c2eb6.ts.net:9200 (tailnet only) (svc:elasticsearch)  -> https+insecure://127.0.0.1:9200
https://embeddings.tail6c2eb6.ts.net:8081 (tailnet only) (svc:embeddings)        -> https+insecure://127.0.0.1:8081
https://fleet-distribution.tail6c2eb6.ts.net:8080 (tailnet only) (svc:fleet-distribution) -> 127.0.0.1:8080
https://fleet-server.tail6c2eb6.ts.net:8220 (tailnet only) (svc:fleet-server)    -> https+insecure://127.0.0.1:8220
https://kibana.tail6c2eb6.ts.net (tailnet only) (svc:kibana)                     -> https+insecure://127.0.0.1:443
https://litellm.tail6c2eb6.ts.net:4000 (tailnet only) (svc:litellm)              -> https+insecure://127.0.0.1:4000
https://log-analyzer.tail6c2eb6.ts.net:8501 (tailnet only) (svc:log-analyzer)    -> https+insecure://127.0.0.1:8501
https://pgvector.tail6c2eb6.ts.net:5432 (tailnet only) (svc:pgvector)            -> https+insecure://127.0.0.1:5432
https://wazuh-manager.tail6c2eb6.ts.net:1514 (tailnet only) (svc:wazuh-manager)  -> https+insecure://127.0.0.1:1514
```
`tailscale serve get-config --all` version 0.0.1 lists the SAME 10 svc: entries under "services" (each endpoint tcp:<port> -> https+insecure://127.0.0.1:<port>).
INGRESS leg node-scoped serves ALSO present (NOT svc: VIPs — this node's own ts.net name):
```
tcp://graph.tail6c2eb6.ts.net:5044 (tailnet only) -> tcp://127.0.0.1:5044   (logstash beats, raw --tcp)
https://graph.tail6c2eb6.ts.net:4000 (tailnet only) -> https+insecure://127.0.0.1:4000  (litellm)
https://graph.tail6c2eb6.ts.net:8200 (tailnet only) -> https+insecure://127.0.0.1:8200  (apm-server)
```

VERDICT on advertise: **SVC leg rendered + advertised 10/10 VIPs, NOT rejected by tailnet policy.** DERIVED==ADVERTISED (no VIP derived-but-rejected; none expected-but-missing). The task's named UI/API subset is ALL present: kibana@443, litellm@4000, dashboard@8502, log-analyzer@8501. The full manifest-derived set additionally (and correctly) fronts every enabled host-facing loopback backend service: elasticsearch@9200, embeddings@8081, fleet-distribution@8080, fleet-server@8220, pgvector@5432, wazuh-manager@1514. wazuh-manager fronts 1514 (lowest of 1514/1515/55000; udp 514 correctly excluded per _ts_lo). apm-server(8200)+logstash(5044) appear ONLY as ingress node-scoped serves, NOT svc: VIPs — consistent with them being install_elastic_services-gated (OFF this leg) while ingress fronts its fixed node-port set (8200/4000/5044).

#### INSTALL + PLAY RECAP
- INSTALL rc=0 (rescued=1). WARN: "rescued=1 task(s) recovered via an Ansible rescue block". The rescued=1 is the KNOWN benign Kibana warmup self-heal: `TASK [kibana : Attempt to verify Kibana connection]` exhausted 10 retries -> caught by rescue -> `Increment retry counter` -> `Restart Kibana service` -> succeeded on restart (NOT a hard abort; same self-heal as prior bare-metal/qemu legs; WARN-only without --strict).
- PLAY RECAP: `localhost : ok=353 changed=86 unreachable=0 failed=0 skipped=126 rescued=1 ignored=1`

#### HEALTH (deep gate) — rc=0
- HEALTH expects: `containers>=11 llm_on=1 profile=[tailscale] loopback=[443 514 1514 1515 4000 5044 5432 5601 8080 8081 8085 8200 8220 8501 8502 9200 9300 55000] lan_ok=[] profile_open=[] tailnet_ports=[8200 4000 5044]`
- expect_min (floor) = 11 (= 5 core + 6 llm pack; NO +5 elastic => install_elastic_services OFF, consistent with apm-server/logstash not being svc: VIPs).
- running = 11  (meets floor 11)
- fail = 0
- EXPOSURE gate = PASS (deny-by-default over full 18-port manifest set): every LISTENING port loopback-only [127.0.0.1] — 443, 514, 1514, 1515, 5432, 5601, 8081, 8220, 8501, 8502, 9200, 55000 all "ok: loopback-only". NO 0.0.0.0 bind. Ports 4000/8200/5044 are the tailnet-ingress allowance (`tailnet_ports=[8200 4000 5044]`), checked as tailnet-only ingress (allowed), not as LAN exposure. Service probes: log-analyzer :8501 http_code=200 ok (+ others).
- HEALTH rc=0 (all gate checks passed). **The 10 advertised svc:<name> VIPs did NOT trip the exposure gate** — they are tailscale-overlay VIPs (`tailscale serve --service`), not host 0.0.0.0 binds, so the loopback-only host posture is preserved.

#### PUBLISH proof (ansible, console lines 1283-1293) — all 10 VIPs newly published, NOT idempotent-skip, NOT rejected
```
changed: [localhost] => (item=svc:pgvector --https=5432)
changed: [localhost] => (item=svc:wazuh-manager --https=1514)
changed: [localhost] => (item=svc:embeddings --https=8081)
changed: [localhost] => (item=svc:log-analyzer --https=8501)
changed: [localhost] => (item=svc:litellm --https=4000)
changed: [localhost] => (item=svc:elasticsearch --https=9200)
changed: [localhost] => (item=svc:kibana --https=443)
changed: [localhost] => (item=svc:fleet-server --https=8220)
changed: [localhost] => (item=svc:dashboard --https=8502)
changed: [localhost] => (item=svc:fleet-distribution --https=8080)
```
The raw-TCP publish task had 0 items (all 10 targets scheme=https; logstash — the only serve:tcp candidate — is install_elastic_services-gated OFF this leg). Continuous-advertise proof: background poller captured 52 NON-EMPTY `serve status` snapshots, #13 @08:21:31Z through #64 @08:55:59Z, each showing all 10 svc:<name> VIPs — VIPs stayed advertised across the whole install->health window (~34 min).

#### TEARDOWN — rc=0 (via tree's own scripts/wipe_lme.sh)
- Console: "Resetting LME-owned tailscale serve/ingress config (co-tenant serves left intact)..." -> "Verifying host is clean..." -> "Wipe complete and verified clean." -> `TEARDOWN rc=0 (0 => host verified CLEAN)` @08:56:11Z.
- Scoping mechanism (verified from wipe_lme.sh code; the per-command `tailscale serve ... off/clear` calls run with `2>/dev/null || true`, so only the summary prints): 4a removes node-scoped serves by EXACT port (`serve --https/--tcp <port> off` for LME_SERVE_NODE_PORTS=8200/4000/5044); 4b removes each LME-owned `svc:<name>` present in status by EXACT identity (`serve clear svc:<name>`); 4c blanket reset ONLY when NO foreign svc:<name> present. LME_SVC_NAMES / node-port set are derived from the SAME manifest source the publisher reads, so a co-tenant svc (windows11/vncserverwindow/webui) can never enter the reset set.

#### POST-TEARDOWN state (re-probe @08:56:40Z, same as before-probe)
```
--- serve status ---       => No serve config
--- serve get-config --all => { "version": "0.0.1" }
--- lme-storage ---        => 496K  /data/lme-storage
--- lme containers ---     => 0 (default root) / 0 (--root /data/lme-storage/storage)
```
- LME-owned serves ALL GONE: 10 svc:<name> VIPs + 3 node-scoped serves (8200/4000/5044) removed; back to bare "No serve config" / `{"version":"0.0.1"}`.
- Co-tenant before/after: pre=EMPTY, post=EMPTY -> byte-identical (nothing to diff). **Co-tenant SCOPING was NOT exercised this run — graph had ZERO co-tenant serve entries pre-leg, so there was nothing to protect.** (On a host with no foreign svc, wipe_lme.sh's 4c blanket-reset path is even eligible and provably harmless; scoped removal by exact port/name is proven only by code-read + the clean-empty result, not by an exercised co-tenant.)
- /data/lme-storage = 496K == pre-deploy baseline (restored).

#### STAGE rc SUMMARY (VERBATIM from console)
```
RSYNC rc=0        @08:12:37Z
WIPE rc=0         @08:12:40Z  (host verified CLEAN)
INSTALL rc=0      @08:54:26Z  (rescued=1 — Kibana warmup self-heal, WARN-only)
HEALTH rc=0       @08:54:26Z  (all gate checks passed)
TEARDOWN rc=0     @08:56:11Z  (host verified CLEAN)
=== LEG END stage=all rc=0 === @08:56:11Z
```

### ===== VERDICT: TAILSCALE SVC-SERVE LEG = CLOSED (single-host, graph, HEAD c33f567) =====
All 5 stages rc=0. The post-refactor SVC/VIP leg (`tailscale_service.yml` deriving `svc:<name>` from `lme_services` via `load_manifests.yml`, commit 25c7214) RENDERED and ADVERTISED correctly on HEAD: 10/10 derived VIPs published (DERIVED==ADVERTISED, none rejected by tailnet policy, none expected-but-missing). Exposure gate PASS (all host binds loopback-only, no 0.0.0.0; tailnet-ingress ports 8200/4000/5044 allowed). Teardown removed all LME serves and restored the empty baseline (serve config + 496K storage). **This proves the single-host tailscale-serve topology (ingress + egress + SVC) renders + advertises on HEAD post-refactor.** It does NOT prove multi-host VIP replication (same svc:<name> advertised from 2 nodes simultaneously) — that remains an OPEN leg. Co-tenant scoping was not exercised (no co-tenant serves present on graph this run); scoped removal is evidenced by code-read + the clean empty-baseline result.

