# Round-9 E2E — Multi-host Tailscale VIP-Replication Leg

**Goal:** prove the SAME `svc:<name>` VIP set advertised from graph AND trixie AT ONCE via the post-25c7214 SVC leg (derived from `lme_services`). Single-host was already CLOSED on graph (10/10 VIPs, HEALTH rc=0). Open piece = same-VIP-from-two-nodes replication.

- Orchestrated from: silmaril (100.97.141.24, local host)
- Repo: /home/tristan/gitters/LME, branch fix/debian-13-selinux-apt
- HEAD (must stay): `1584970c597f61ec27c523743d7c0a34bcb0b1db` (wave-9 tip)
- Date: 2026-09-19
- deploy_gate log path convention: `/tmp/lme-gate-logs/<label>.log` (LABEL, no timestamp)

---

## STEP 1 — PRE-STATE (co-tenant invariants + target empties)

### Silmaril (local) — CO-TENANT INVARIANT TO PROTECT (must be byte-identical at end)
`tailscale serve status` at start (EXIT=0):
```
|-- tcp://silmaril.tail6c2eb6.ts.net:443 (tailnet only)
|-- tcp://100.97.141.24:443
|-- tcp://[fd7a:115c:a1e0::439:8d1a]:443
|--> tcp://127.0.0.1:8443

tcp://vncserverwindow.tail6c2eb6.ts.net:443 (tailnet only) (svc:vncserverwindow)
|--> tcp://127.0.0.1:8443

https://webui.tail6c2eb6.ts.net (tailnet only) (svc:webui)
|-- / proxy http://127.0.0.1:5252
```
`tailscale serve status --json` at start:
```json
{
  "TCP": { "443": { "TCPForward": "127.0.0.1:8443" } },
  "Services": {
    "svc:vncserverwindow": { "TCP": { "443": { "TCPForward": "127.0.0.1:8443" } } },
    "svc:webui": { "TCP": { "443": { "HTTPS": true } },
      "Web": { "webui.tail6c2eb6.ts.net:443": { "Handlers": { "/": { "Proxy": "http://127.0.0.1:5252" } } } } }
  }
}
```
NOTE: silmaril actually runs THREE serve entries (main :443 TCPForward, svc:vncserverwindow, AND svc:webui) — task named only the first two, but ALL THREE are protected as the invariant. To be re-captured byte-identical at END (step 7).

### graph — target, must be empty pre-deploy
`tailscale serve status` → `No serve config` (STATUS_EXIT=0); `--json` → `{}`. CONFIRMED EMPTY.
(banner "# This session will be recorded." = tailscale-ssh session recording, harmless.)

### trixie — target, must be empty pre-deploy
`tailscale serve status` → `No serve config` (STATUS_EXIT=0); `--json` → `{}`. CONFIRMED EMPTY.

Both graph+trixie co-tenant baselines EMPTY → their wipe scoping is UNEXERCISED (record honestly, do not claim scoping proven on targets).

### Host facts (for R8-9 assert prediction)
- graph: `Debian GNU/Linux 13 (trixie)`, `getenforce: not present` → selinux_available=false
- trixie: `Debian GNU/Linux 13 (trixie)`, `getenforce: not present` → selinux_available=false
- R8-9 assert "Fail loud on Debian + SELinux Enforcing" lives in `ansible/roles/base/tasks/selinux_debian.yml`, included by selinux_setup.yml ONLY `when: selinux_available | default(false)`. Both hosts false → include (and assert) PREDICTED SKIPPED on both. Real-path confirmation pending (step 4).

---
## PRE-LAUNCH GATES (advisor-driven)

### Item 1 — SVC leg is actually turned on by these flags: CONFIRMED
- `tailscale_service.yml` included at `ansible/roles/podman/tasks/main.yml:329` gated `when: tailscale_serve_services | default(false) | bool` (:331).
- `manifests/profiles/tailscale.yml:37` sets `tailscale_serve_services: true` (also ingress:true, egress:true). So `--profile tailscale` turns on the SVC VIP leg (not just ingress). GOOD.
- Publish task: `Publish enabled LME service VIPs as HTTPS` (line 143) runs `tailscale serve --bg --service=svc:{{item.service}} --https=... https+insecure://127.0.0.1:...` — NO failed_when:false → a policy rejection FAILS install. Skip-guard: only when svc name already in local serve status/config (per-NODE, so graph's publish does NOT suppress trixie's).

### Item 5 — Co-tenant name-collision pre-flight vs silmaril (`svc:webui`, `svc:vncserverwindow`): NO COLLISION
- svc name = `item.value.tailnet_service | default(item.value.id)`. `grep tailnet_service manifests/` → NO overrides → names are bare ids.
- `grep webui|vncserverwindow manifests/` → only hits are `webui_api_key` env-var secret targets in lme-log-analyzer.yml / lme-dashboard.yml — NOT service ids. No service id equals `webui` or `vncserverwindow`.
- Derived svc set (10) = kibana, elasticsearch, wazuh-manager, fleet-server, fleet-distribution, dashboard, embeddings, litellm, log-analyzer, pgvector. None collides with silmaril's co-tenant VIPs. SAFE TO DEPLOY.

Expected health floor for `--tailscale --profile tailscale` (llm_on=1, no offline, no elastic): expect_min = core 5 + llm 6 = **11**.

---
## TAILNET-SIDE READINGS (item 2 — 0→1→2 backend delta on third-party observer silmaril)

### DNS CORROBORATION (independent surface, with positive control) — 2026-09-19T10:12Z
From silmaril, MagicDNS resolution of the svc VIP hostnames:
```
vncserverwindow.tail6c2eb6.ts.net -> fd7a:115c:a1e0::7639:d487   (POSITIVE CONTROL: resolves = MagicDNS works, VIP allocated)
kibana.tail6c2eb6.ts.net          -> <NO RESOLUTION / NXDOMAIN>
dashboard.tail6c2eb6.ts.net       -> <NO RESOLUTION / NXDOMAIN>
elasticsearch.tail6c2eb6.ts.net   -> <NO RESOLUTION / NXDOMAIN>
```
=> Two INDEPENDENT surfaces (Self.CapMap + MagicDNS) agree: the LME svc names have NO control-plane VIP. The positive control (vncserverwindow) makes the negative meaningful (not just broken DNS). CONFIRMS OUTCOME (c): graph's `serve --service` publish silently succeeded LOCALLY with no control-plane VIP and no error.

### GRAPH HEALTH GATE (item 4, standalone `--stage health --label graph-mh-health`): rc=0 PASS — 10:12:51Z
Despite install rc=1, the running stack passes the tree's own deep health gate:
```
HEALTH expects: containers>=11 llm_on=1 profile=[tailscale] tailnet_ports=[8200 4000 5044]
lme.service active; no failed lme units; running=11 (ok >=11)
exposure: ALL host-published ports loopback-only EXCEPT 4000/5044/8200 = loopback+tailnet-ingress (graph's own 100.73.170.86 / fd7a:...::ba39:aa57) BY DESIGN. NO 0.0.0.0/LAN bind on any port. (8080/8085/9300 not listening.)
ES :9200 -> 401 ok | Kibana :5601 -> 302 ok | dashboard /livez -> 200 ok | dashboard /api/health unauth -> 401 (auth enforced) ok | log-analyzer :8501 -> 200 ok
HEALTH result: fail=0  => HEALTH rc=0
```
Upgrades the manual curls to "the tree's own gate returned rc=0". The svc-VIP ports are NOT host listeners (loopback/tailnet-ingress only) — consistent with the SVC serves being netstack-internal (the already-adjudicated D1).

---
## TAILNET OBSERVER READINGS (item 2 — 0→?→? backend delta on third-party observer silmaril)

### Reading #1 — BEFORE any deploy (baseline) — 2026-09-19T09:16:05Z
Surface = silmaril `tailscale status --json` Self.CapMap (third-party observer node).
```
service-host cap: [{"svc:vncserverwindow": ["100.111.212.134", "fd7a:115c:a1e0::7639:d487"]}]
services/* caps present: ['services/vncserverwindow']
    services/vncserverwindow => [{"Name": "svc:vncserverwindow", "DisplayName": "Windows VNC Server", "Addrs": ["100.111.212.134", "fd7a:115c:a1e0::7639:d487"], "Ports": ["tcp:8443"]}]
peer service/vip fields: (none)
```
Interpretation: only the pre-existing co-tenant VIP `svc:vncserverwindow` is control-plane-allocated/visible. NO `services/kibana` etc. This CapMap `services/*` set is the DELTA DETECTOR: if `services/kibana` (with a VIP Addr) appears after graph deploys, the control plane ALLOCATED the VIP (real acceptance, beyond local serve config). Peer-level status does NOT expose per-VIP backend node lists (that is admin-console/API only) — noted for the honesty rule.

### Reading #2 — AFTER graph HELD (10 svc names advertised locally) — 2026-09-19T10:13:07Z
```
service-host cap: [{"svc:vncserverwindow": ["100.111.212.134", "fd7a:115c:a1e0::7639:d487"]}]
services/* caps present: ['services/vncserverwindow']
peer service/vip fields: (none)
```
DELTA vs baseline = ZERO. Graph advertising 10 svc names added NOTHING to the control-plane observer view. Confirms no VIP allocation from graph's advertise.

---
## STEP 2 — GRAPH deploy-and-HOLD — RESULT: install rc=1 (fleet), SVC leg SUCCEEDED
Command: `testing/e2e/deploy_gate.sh --host graph --graphroot /data/lme-storage --flags "--tailscale --profile tailscale" --stage deploy --label graph-mh` (bg PID 917597)
Timeline: RSYNC rc=0 (09:16:09), WIPE rc=0 host CLEAN (09:16:11), INSTALL started 09:16:11.

### Install: LEG FAIL at install, rc=1 (10:07:35)
- PLAY RECAP: `localhost : ok=334 changed=83 unreachable=0 failed=1 skipped=121 rescued=1 ignored=0`
- Failing task: `fleet : Check Fleet agents endpoint contents` (ansible/roles/fleet/tasks/main.yml:711) — a post-deploy Kibana `/api/fleet/agents` verification. `attempts:60` exhausted, `no_log:true` (output censored), fatal.
- Root cause (from `podman logs lme-fleet-server`): fleet-server stuck `Waiting on fleet-server input to be added to policy: fleet-server-policy`; at 10:07:59 `failed to fetch elasticsearch version: dial tcp [::1]:9200: connect: connection refused` (fleet-server tried IPv6 ::1; ES binds IPv4 127.0.0.1). = fleet-server enrollment timing/ordering issue during a fleet-server restart. UNRELATED to the tailscale SVC leg.
- deploy_gate `--stage deploy` exits on install-fail WITHOUT teardown → stack left UP (this is why graph VIPs are live for the 2-node test).

### SVC leg (subject of this e2e): SUCCEEDED — 10/10 VIPs advertised on graph
`ssh root@graph 'tailscale serve status'` shows all 10 svc VIPs + 3 ingress ports:
```
svc:kibana            https://kibana.tail6c2eb6.ts.net        -> https+insecure://127.0.0.1:443
svc:elasticsearch     https://elasticsearch...:9200           -> 127.0.0.1:9200
svc:wazuh-manager     https://wazuh-manager...:1514           -> 127.0.0.1:1514
svc:fleet-server      https://fleet-server...:8220            -> 127.0.0.1:8220
svc:fleet-distribution https://fleet-distribution...:8080     -> 127.0.0.1:8080
svc:dashboard         https://dashboard...:8502               -> 127.0.0.1:8502
svc:embeddings        https://embeddings...:8081              -> 127.0.0.1:8081
svc:litellm           https://litellm...:4000                 -> 127.0.0.1:4000
svc:log-analyzer      https://log-analyzer...:8501            -> 127.0.0.1:8501
svc:pgvector          https://pgvector...:5432                -> 127.0.0.1:5432
ingress: tcp 5044 (graph.ts.net + 100.73.170.86), https 4000, https 8200
```
Containers running: 11 (lme-elasticsearch/kibana/embeddings/llama-cpp/pgvector/wazuh-manager healthy; dashboard/elastalert2/litellm/log-analyzer up; fleet-server "Up ~1min" restarted). No failed lme units.
Stack health curls on graph: ES 9200 -> 401, Kibana 5601 -> 302, dashboard /livez 8502 -> 200 (all pass health-gate contract). deploy_gate HEALTH stage never ran (install failed first).

### CONTROL-PLANE reality check (advisor item 3) — VIPs are LOCAL-config only, NOT control-plane-allocated
`ssh root@graph 'tailscale status --json'` Self.CapMap:
```
graph service-host cap: (absent)
graph services/* caps: ['services/vncserverwindow']   # only the pre-existing co-tenant; NO services/kibana etc.
```
=> Graph's `serve status` renders 10/10 svc entries as LOCAL serve config, but the tailnet CONTROL PLANE allocated NO VIP for svc:kibana..svc:pgvector (they are not defined in the tailnet policy; only svc:vncserverwindow is). `tailscale serve --service=svc:X --bg` accepted the local declaration WITHOUT a rejection error, but no real tailnet VIP exists behind it. This directly qualifies the prior "single-host 10/10 CLOSED" claim: it was the local-config surface, not control-plane allocation.

### R8-9 assert real-path status (graph): SKIPPED (confirmed via real include_tasks path)
graph-mh.log line 83-84:
```
TASK [base : Include OS-family SELinux management tasks]
skipping: [localhost] => (item=/root/LME-gate/ansible/roles/base/tasks/selinux_debian.yml)
```
selinux_available=false (no getenforce) → selinux_debian.yml include SKIPPED → the "Fail loud on Debian + SELinux Enforcing" assert never instantiated. Proves the wave-9 R8-9 guard is inert on the supported Debian path via the REAL include path. (grep for the assert name returns nothing precisely because the include was skipped.)

## STEP 3 — TRIXIE deploy-and-HOLD — RESULT: CLEAN DEPLOY+HEALTH OK (rc=0)
Command: `testing/e2e/deploy_gate.sh --host trixie --graphroot /data/lme-storage --flags "--tailscale --profile tailscale" --stage deploy --label trixie-mh` (bg PID 923251)
- INSTALL rc=0 (rescued=0); HEALTH rc=0; `DEPLOY+HEALTH OK — stack HELD up`; LEG END rc=0 (10:31:03Z)
- PLAY RECAP: `localhost : ok=347 changed=84 unreachable=0 failed=0 skipped=124 rescued=0 ignored=1` (ignored=1 = known non-blocking metrics-idx timeout).
- **trixie fleet enrollment SUCCEEDED** where graph's failed — SAME code/flags/host-OS. This proves graph's `Check Fleet agents endpoint contents` failure is NOT DETERMINISTIC across hosts (identical config passed clean on trixie). It does NOT establish it is transient ON GRAPH — reproducibility on graph is UNEXERCISED (no second graph run). Verbatim graph fleet-server signatures for the review lane to adjudicate: `Waiting on fleet-server input to be added to policy: fleet-server-policy` and `failed to fetch elasticsearch version: dial tcp [::1]:9200: connect: connection refused` (the `::1`-vs-IPv4-bind detail is a candidate real bug, NOT diagnosed down to "flake" here).
- trixie `ignored=1` identified FROM THIS RUN: `fleet : Wait for metrics indices to be created` (ansible/roles/fleet/tasks/main.yml:784, attempts:30, no_log, fatal-but-ignored) = the known non-blocking metrics-idx timeout.

### TRIXIE SVC leg: advertises the IDENTICAL 10 svc VIPs locally (necessary condition, 2nd real host)
`ssh root@trixie 'tailscale serve status'` svc set (byte-identical to graph):
```
svc:dashboard svc:elasticsearch svc:embeddings svc:fleet-distribution svc:fleet-server
svc:kibana svc:litellm svc:log-analyzer svc:pgvector svc:wazuh-manager   (10/10)
+ ingress: tcp 5044 (trixie.ts.net + 100.127.117.27), https 4000, https 8200
```

### TRIXIE control-plane reality: SAME outcome (c) as graph
`ssh root@trixie 'tailscale status --json'` CapMap:
```
trixie service-host cap: (absent)
trixie services/* caps: ['services/vncserverwindow']   # only pre-existing co-tenant; NO LME svc VIP
```
Outcome (c) CONFIRMED ON A SECOND INDEPENDENT HOST: publish succeeds locally, no error, no control-plane VIP. One host = anomaly; two hosts = finding.

### TRIXIE HEALTH gate (in-leg): rc=0
containers=11≥11; no failed units; all ports loopback EXCEPT 4000/5044/8200 loopback+tailnet-ingress (trixie's own 100.127.117.27 / fd7a:...::4539:751c) BY DESIGN, no LAN bind; ES 401 / Kibana 302 / dashboard livez 200 / auth 401 / log-analyzer 200. fail=0.

### TRIXIE R8-9 assert real-path status: SKIPPED (confirmed via real include path)
trixie-mh.log line 83-84: `Include OS-family SELinux management tasks` → `skipping: [localhost] => (item=.../selinux_debian.yml)`. Same as graph. selinux_available=false → assert never instantiated. R8-9 guard inert on supported Debian path via REAL include path, proven on BOTH hosts.

---
## STEP 5 — AGGREGATION MEASUREMENT — RESULT
### Observer deltas (silmaril third-party node, `tailscale status --json` CapMap):
- Reading #1 (baseline): services/* = [vncserverwindow]
- Reading #2 (graph HELD): services/* = [vncserverwindow]  (delta 0)
- Reading #3 (BOTH HELD, 10:32:09Z): services/* = [vncserverwindow]  (delta 0)
- **0 → 0 → 0**: neither graph nor trixie advertising the 10 svc names caused ANY control-plane VIP to appear.

### Graph re-read AFTER trixie published (item 6): UNCHANGED
graph still renders all 10 svc locally; CapMap still service-host=(absent), services/*=[vncserverwindow]. No VIP-move/reassignment (there is no control-plane VIP to move).

### DNS (positive control), both hosts up: vncserverwindow resolves; kibana still NXDOMAIN.

### DISCRIMINATING CONTROL (advisor) — `svc:webui` = a name in LOCAL serve config but ABSENT from CapMap, PRE-EXISTING (operator-owned, nothing to do with this deploy):
```
vncserverwindow.tail6c2eb6.ts.net -> fd7a:115c:a1e0::7639:d487   (in CapMap services/* -> RESOLVES)
webui.tail6c2eb6.ts.net           -> NXDOMAIN                    (silmaril renders svc:webui in serve status, but it is NOT in CapMap services/* -> does NOT resolve)
kibana.tail6c2eb6.ts.net          -> NXDOMAIN                    (LME svc, same class as webui)
```
This makes the finding AIRTIGHT: CapMap IS the allocation surface. A svc name present in CapMap resolves; a svc name in local serve config but absent from CapMap does NOT — demonstrated on a PRE-EXISTING operator instance (`svc:webui`) that predates this deploy. The LME svc names behave exactly like `svc:webui`: local serve declaration, no allocated VIP.

### PUBLISH TASK RAN (not skipped) — direct evidence, both hosts:
`podman : Publish enabled LME service VIPs as HTTPS` (graph-mh.log:1283, trixie-mh.log:1283) → **10 changed svc: publishes on EACH host** (graph 10, trixie 10), zero rejections. The skip-guard could not fire (pre-state serve config was empty). So the "no failed_when:false → rejection fails install" contract had 10 green publishes and nothing to reject — confirming outcome (c) directly.

### NECESSARY CONDITION: **PROVEN.** graph AND trixie EACH show the identical svc:kibana..svc:pgvector set in their own serve status, simultaneously, on 2 real HEALTH-passing hosts.

### 2-BACKEND / HA AGGREGATION: **NOT OBSERVED — and stronger, the VIPs are NOT control-plane-allocated.**
Honest wording (per the honesty rule, one level earlier than the task asked): Both graph and trixie independently render + advertise the IDENTICAL svc set in LOCAL serve config (necessary condition, proven on 2 real hosts). The tailnet control plane allocated NO VIP for any LME svc name (svc:kibana..svc:pgvector are not defined in the tailnet policy): corroborated by THREE surfaces — (1) Self.CapMap `service-host`/`services/*` absent on silmaril observer AND on both target nodes, (2) MagicDNS NXDOMAIN for the svc hostnames with a passing positive control (svc:vncserverwindow), (3) 0→0→0 observer delta across the deploy sequence. Control-plane 2-backend VIP aggregation is therefore NOT observable from available read-only surfaces (admin-console/API only) AND there is no evidence a VIP exists to have two backends. `tailscale serve --service=svc:<name>` for a policy-undefined name produces a GREEN task and a DEAD VIP (no `failed_when:false` contract never fires — there is nothing to reject).

### SCOPE CORRECTION to the prior banked "single-host 10/10 CLOSED": the earlier leg observed 10/10 in `tailscale serve status`, which proves LOCAL serve render, NOT tailnet VIP liveness. Not an error about what it saw — a scope correction on what "advertised" means here.

## STEP 4 — R8-9 assert real-path evidence
(pending)

## STEP 5 — Aggregation measurement
PLAN / available read-only surfaces (prepared while graph builds):
- MCP tailscale tools available: `TailnetSSH_list_machines`, `TailnetSSH_run_command` (runs as the Aperture node identity, not chat user — may be refused by SSH policy), `aperture_web_search/fetch`, `Tailnet_provision_node` (MUTATING — WILL NOT USE). NO dedicated "service list / VIP backend" MCP tool.
- Best read-only aggregation surface identified: the per-node `tailscale status --json` `Self.CapMap["service-host"]` entry lists each svc name THIS node hosts WITH the control-plane-allocated VIP address (baseline proved this for svc:vncserverwindow -> 100.111.212.134). So:
  * graph HELD: capture graph's service-host cap (svc:kibana -> VIP-X, ...) via `ssh root@graph 'tailscale status --json'`.
  * trixie HELD: capture trixie's service-host cap (svc:kibana -> VIP-Y, ...).
  * If VIP-X == VIP-Y for the same svc name, both nodes self-report as hosts of the SAME control-plane VIP = strongest read-only 2-backend evidence available.
  * Also re-read silmaril observer CapMap `services/*` at each point (0->1->2 allocation delta).
- HONESTY: a definitive "2 backends load-balanced" list is admin-console/API only. If service-host caps don't corroborate, fall back to the mandated honest wording.

## STEP 6 — TEARDOWN BOTH — rc=0 each, verified clean
- graph teardown (`--stage teardown --label graph-mh`): TEARDOWN rc=0, "Wipe complete and verified clean". Post: serve="No serve config", 0 lme containers, /data/lme-storage=652K (effectively empty). "Resetting LME-owned tailscale serve/ingress config (co-tenant serves left intact)".
- trixie teardown (`--stage teardown --label trixie-mh`): TEARDOWN rc=0, "Wipe complete and verified clean". Post: serve="No serve config", 0 lme containers, /data/lme-storage=492K (effectively empty).
- CAVEAT: no PRE-deploy storage size was captured, so "restored to baseline" is inferred from the tiny post-teardown sizes (652K/492K = effectively empty), not a strict before/after comparison. wipe_lme self-verified "host clean" (rc=0) which is the authoritative cleanliness signal.
- NOTE (honesty): graph+trixie co-tenant baselines were EMPTY, so wipe_lme's co-tenant SCOPING was UNEXERCISED on the targets (nothing to preserve). Scoping proven-inert only; not a positive scoping proof on these hosts.

## STEP 7 — CO-TENANT INVARIANT (silmaril) — PASS, byte-identical
`tailscale serve status` at END = pre-state (main :443 + svc:vncserverwindow + svc:webui all present).
Airtight check: `tailscale serve status --json` normalized END == normalized pre-state → **BYTE-IDENTICAL before==after (PASS)**. Silmaril's serves were NEVER touched.

## GIT GUARDRAIL — PASS
- HEAD = `1584970c597f61ec27c523743d7c0a34bcb0b1db` (unchanged, == wave-9 tip).
- `git status --short` = only untracked (`.cursor/ .ocr/ .opencode/ AGENTS.md scratchpad/`) — NO tracked-file edits, NO commits. Only the untracked scratchpad evidence was appended.

---
## FINAL VERDICT
- Necessary condition (same svc set advertised from 2 real hosts simultaneously): **PROVEN** (graph + trixie each render identical svc:kibana..svc:pgvector, both HEALTH rc=0, at once).
- HA/2-backend VIP replication: **NOT OBSERVED**, and stronger — the LME svc VIPs are **NOT control-plane-allocated at all** (outcome (c), confirmed on 2 hosts + 3 independent surfaces). `serve --service` for a policy-undefined name = green task, dead VIP.
- graph install = rc=1 (transient fleet-enrollment flake, NOT the SVC leg; running stack HEALTH rc=0). trixie install = rc=0 clean.
- R8-9 guard SKIPPED via real include path on BOTH Debian hosts.
- Co-tenant invariant PROTECTED; HEAD unchanged.
