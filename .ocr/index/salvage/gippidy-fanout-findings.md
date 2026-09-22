# Gippidy pre-map fanout — durable findings (2026-09-22)

**Purpose:** the "bring new information in" pass the operator asked for BEFORE `/ocr:map` run-15,
anchored on the operator pivot: the deployed LME stack's UIs link up but it **collects nothing**
(no logs/metrics/events into ES, no working collectors, "improper realization of purpose").

**Unified goal (operator correction):** collection and cross-host are ONE e2e goal — "what is the
point of just another machine if it's not through it." A 2nd machine (trixie) is pointless unless
REAL data flows through it. So: make LME actually collect/populate, AND prove that real data crosses
machines. The four operator points: I=nothing collecting/no collectors; II=tailscale cert + tailscale
metric crons/collectors → elastic; III=no population, improper realization of purpose; IV=incorporate
`/home/tristan/gitters/configurations/gippidy` via subagent fanout before mapping.

**Fanout agents (read-only investigation):**
| id | target | status |
|----|--------|--------|
| ab265eb1 | A — gippidy/otel-hertzbeat-fabric-v4 | ✅ captured below |
| a4418d3a | B — gippidy/maka-ocr-observability-ansible-v3 | ✅ captured below |
| ab76fe87 | C — gippidy/tailscale-hertzbeat-kit (= point II) | ⏳ in-flight |
| aef12eee | D — LIVE graph data-plane diagnosis (why ES empty) | ⏳ in-flight |
| ac6d7214 | E — LME repo intended-collection architecture + gap | ⏳ in-flight |

---

## ★ CONVERGENT SYNTHESIS (A + B) — the strategic picture

Both gippidy observability kits (otel-hertzbeat-fabric AND maka-observability) are the SAME shape:
1. **Manifest-driven OTel-Collector fabrics** (good philosophical fit for LME's no-hardcode rule; both
   render collector configs from a single site manifest, exactly like LME's `container.j2`).
2. **They BOLT ON A PARALLEL ingest lane** (OTel Collector → [Kafka or loopback bridge] → ES) writing
   to a **NEW dedicated index** (`logs-silmaril-otel` / `logs-silmaril-*`), **bypassing LME's native
   elastic-agent/Fleet→ES pipeline entirely.**
3. **Both HARDWIRE mandatory HertzBeat** — you cannot render an ES-only / HertzBeat-free collector.
   (A: `render.py:51-56` requires HertzBeat 1.9+greptimedb, every non-Kafka pipeline hardwires
   `hertzbeat_export`; B: `lib/compose.py:67 raise Invalid('HertzBeat is mandatory')`.)
4. **ES gets LOGS ONLY.** Metrics + traces route to HertzBeat/GreptimeDB, never Elasticsearch.
5. **Neither ships the ES-side prerequisites** (index template, ECS mapping, scoped write-only API-key
   role, ILM) — those must be authored LME-side.
6. **Neither is live-validated** — every native/live acceptance case is explicitly NOT RUN. Prototypes.

**⇒ Decisive implication for the operator's "nothing collects" complaint:** these kits are an
**ALTERNATIVE ingest path, NOT a repair** of why LME's *native* collection is dead. The real
root-cause of "nothing collects" is almost certainly a **native LME Fleet/elastic-agent
misconfiguration** (no agent policy / no integrations / no enrolled endpoint) — which agents **D
(live diag)** and **E (repo architecture gap)** are pinning down. Sequence the decision on their
findings: (a) if native Fleet is merely UNCONFIGURED → fixing that is the direct repair; (b) the
gippidy OTel lane is a *supplement* (host metrics/logs + tailscale audit/flow into ES) or a fallback,
not the first move.

**Cleanest incorporation IF we lift from the kits** (both agents independently converge here):
- Do NOT import `render.py`/`compose.py` wholesale (mandatory-HertzBeat coupling). Instead lift the
  **receiver blocks** (hostmetrics + filelog + journald) and the **ES `elasticsearch` exporter block**
  into a new `manifests/services/lme-otel-collector.yml` + an LME-templated `otel-collector.yaml.j2`,
  fed from `manifests/`, reusing LME's secret→env model, CA workspace, network model, image registry,
  and the hostfs mount set already solved in `manifests/services/lme-metricbeat.yml:52-54`.
- Add the ES index template + scoped API-key role LME-side (kits ship neither).
- **Lower-friction native alternative flagged by A:** LME already ships
  `manifests/services/lme-apm-server.yml` (Elastic APM Server on :8200) which natively accepts OTLP —
  possibly a lighter ES ingest target than a bespoke OTel→ES exporter. Evaluate in the map.
- Smoke test for "does it collect": both kits ship a canary generator (A: `tools/canary.py` emits one
  correlated log+metric+trace OTLP-JSON, `delivery: NOT SENT`) → POST to the OTLP receiver, read back
  from ES by id. Matches acceptance case LME-01-01-A (NOT RUN).

---

## A — otel-hertzbeat-fabric-v4  (agent ab265eb1)

**Canonical:** flat `otel-hertzbeat-fabric-v4/` is authoritative; `-v4-1/` is the same zip re-extracted
under an extra wrapper (byte-identical, same zip sha256 `43aea0b5…901cd9`, 91 files). Not a git repo.

**What it is:** an OTel-Collector **config + Python tooling + OpenSpec** packet. NOT HertzBeat monitor
YAMLs (zero of those). HertzBeat appears only as a downstream OTLP sink. Signals: logs, metrics, traces.
- **Sources** (edge-agent.yaml + hec-ingress.yaml + render.py): hostmetrics (cpu/mem/load/disk/fs/net,
  30s); filelog over bounded `/var/log/silmaril/*.log` globs; app OTLP loopback 4317/4318; optional
  Prometheus HTTPS scrape; **Tailscale audit + network-flow via Splunk-HEC receivers :8443/:8444**;
  optional legacy-JSON Kafka converter.
- **Flow** (docs/ARCHITECTURE.md): edge collector → mTLS OTLP gateway → Kafka OTLP topics → 3 independent
  consumer groups fan out to (a) HertzBeat, (b) LME Elasticsearch, (c) Malcolm. All signals→HertzBeat;
  **LME + Malcolm = LOGS ONLY** (README.md:112-113).

**ES ship path** (examples/kafka-triad/lme-consumer.yaml:67-81) — the OTel `elasticsearch/lme` exporter:
`endpoint https://lme-elasticsearch.example.ts.net:9200`, `api_key ${env:LME_ELASTICSEARCH_API_KEY}`,
`tls.ca_file /run/tls/lme-ca.crt` (verify on), `logs_index: logs-silmaril-otel` (static classic index,
opts out of data-stream routing), `mapping.allowed_modes: [ecs]`, `logs_dynamic_id.enabled: true`
(record-supplied `_id` = idempotent dedup). **No ingest pipeline referenced.** Consumes topics
`silmaril.{tailscale.audit,tailscale.flow,otel.logs}.v1`.
- **⚠ render.py CANNOT emit an ES-only/HertzBeat-free config** (validate() hard-requires HertzBeat 1.9 +
  greptimedb; every non-Kafka pipeline hardwires hertzbeat_export, lme_export only appended for logs).

**Deploy shape:** Podman **Quadlet** `.container.example` (Network=host, all REPLACE_* placeholders,
Image=…@sha256:REPLACE — unnamed; must be `opentelemetry-collector-contrib` since all components are
contrib-only) + one plain systemd unit for the Malcolm bridge. No compose, no cron, no ready Ansible.
`render.py` does no deployment writes.

**LME-native grounding A verified:** `container.j2` is a pure literal-free renderer ("ZERO deployment
literals"); secrets model `Secret=…,type=env,target=ENV` maps straight onto the kit's `${env:…}`;
images via `lme_global.images.<svc>.local` (offline `Pull=never`); **LME has NO existing otel/otlp/
collector** (genuine gap); `lme-apm-server.yml` already does native OTLP on :8200.

**Two gate conflicts to resolve:** (1) `Network=host` contradicts LME's network+alias model and the
deploy_gate loopback-only/no-0.0.0.0 exposure rule → rework onto LME network with `publish_ports`
default `bind:127.0.0.1`; (2) image is an unnamed blocker → add `opentelemetry-collector-contrib` to
`lme_global.images` + bake into the airgapped podman-closure bundle.
**Status:** every native/live gate NOT RUN; 64 acceptance cases NOT RUN; 61 offline component tests only.

---

## B — maka-ocr-observability-ansible-v3  (agent a4418d3a)

**Canonical:** `-v3` and `-v3 (2)` are byte-identical clones (aggregate sha256 `47a7079…`, diff empty).
Primarily an **OpenSpec spec package** for a MAKA plugin (silmaril.ocr) targeting the OCR repo; the real
observability part is the secondary sub-tree `payload/ops/observability/`. `check.py` PASSES (read-only).

**Observability sub-tree = OTel-Collector(otelcol-contrib)+Vector+bespoke `siem_bridge.py`**, manifest-
driven; attaches to existing backends (NOT an installer for ES/HertzBeat/Kafka).
- Receivers (lib/compose.py:230-257): otlp 4317/4318; hostmetrics 30s; prometheus(+JMX); filelog;
  journald (named units only); tailscale config-audit + network-flow via private TLS HEC on node IPv6.
- **ES ship (siem_bridge.py:132-146):** `POST <es>/_bulk` ndjson, `Authorization: ApiKey…`
  (env `LME_AUTHORIZATION`), verified TLS≥1.2, deterministic `_id`=sha256, retry 429/5xx. Index
  regex-locked **`logs-silmaril-*`** (new owned index, NOT a data stream). Doc = ECS-ish (event.*,
  message, service.*, labels.silmaril_tenant, @timestamp, + flattened silmaril.otlp_attributes_json).
- **Ansible:** single play → role `telemetry`, gated `telemetry_action∈{plan,stage,apply,verify,
  rollback}`+`telemetry_approve` (default plan/false); `deploy_guard.py` = immutable-release/seal/
  rollback. `install.py` = content installer HARDCODED to OCR repo remotes (spencermarx/groenewt
  open-code-review) — **cannot target LME**. `check.py` = offline validator.

**Hard blockers:** HertzBeat MANDATORY (compose.py:67/:96/:111); LME/Malcolm = LOGS ONLY (host metrics→
HertzBeat only); throughput 1 doc/HTTPS round-trip (siem_bridge.py:156 LIMIT 1 → prototype); LME docs
mis-tagged Malcolm metadata unconditionally (siem_bridge.py:89); readback needs an index template the
kit doesn't ship (event.id must be keyword). Maturity: 91 offline unit tests 0-fail, ZERO live
acceptance (VALIDATION.md:33-46).

**Useful lifts:** the `_bulk` writer pattern (self-contained ES probe/writer, test ES independent of
Fleet); the profiles.yaml+sites+compose.py parameterization model (fits LME no-hardcode); the OTel
receiver set; index-template guidance (destinations.md:24-26).

---

## ★★★ ROOT CAUSE FOUND — D (live) + E (repo) CONVERGE independently ★★★

**The deployed LME stands up the full Elastic/Wazuh CONTROL PLANE and self-enrolls the fleet-server's
own agent, but NO data producer can ship to ES — not even the local agent. Containers Up, dashboards
linked, indices empty. Exactly the operator's report. Diagnosed BOTH empirically (D, live on graph)
and structurally (E, from the repo); they agree on every point.**

### CRUX A / D1 — Fleet's ES output is advertised at an address nothing binds  ← THE hard defect
- Fleet's **default output** (the ES URL every enrolled agent ships to) = `https://<LAN-IP>:9200`
  (`fleet/tasks/main.yml:439`, `fleet_advertise_host` = env IPVAR = host LAN IP). On graph that is
  `https://192.168.68.73:9200`.
- But ES 9200 binds **loopback-only**: `manifests/services/lme-elasticsearch.yml:75`
  `{bind: 127.0.0.1} # default-closed; cluster.yml opts the LAN back open`. Nothing listens on the LAN IP.
- **Live proof (D):** `ss -ltnp` → ES only on `127.0.0.1:9200`; `curl https://192.168.68.73:9200` → 000
  (cannot connect), `curl https://127.0.0.1:9200` → 200. fleet-server logs: **200+ `connection refused`
  to 192.168.68.73:9200** for its metricbeat/filebeat monitoring outputs. `_data_stream` shows ONLY
  `metrics-fleet_server.agent_status/versions` (the binary's own path over the internal podman alias) —
  **no `logs/metrics-elastic_agent.*`, no `logs/metrics-system.*`, no endpoint data. ES genuinely empty.**
- Why it still goes GREEN: the fleet-server CONTROL-plane writes (agent check-in) use
  `FLEET_SERVER_ELASTICSEARCH_HOST=https://lme-elasticsearch:9200` (podman alias — resolves + works,
  `lme-fleet-server.yml:39`), so the agent registers "online." Contrast confirms the bug is isolated to
  the Fleet OUTPUT URL: beats + wazuh-manager filebeat use the working alias `lme-elasticsearch:9200`.
- `manifests/profiles/multinode.yml:73` re-opens 9200→0.0.0.0 "so agents can ship" — i.e. by default they cannot.

### CRUX B — the collectors sit on a policy with ZERO agents
- Install creates "Endpoint Policy" with **System** + **Elastic Defend** integrations
  (`fleet/tasks/main.yml:492-527,583-623`), but the only agent that enrolls (the fleet-server's own) is
  pinned to `fleet-server-policy` (`lme-fleet-server.yml:36`) = fleet_server integration + self-mon only.
- **Live proof (D):** Fleet API → Endpoint Policy **agents: 0**; fleet-server agent runs only
  `fleet`+`elastic-agent` (no System collector). Wazuh `agent_control -l` → only `000` (the manager
  itself). So even if D1 were fixed, no agent runs the actual collectors, and the server never
  self-collects its own OS logs/metrics.

### D2 — enrollment/transport ports also loopback-bound (the cross-host blocker)
- Fleet-server host advertised `https://<LAN-IP>:8220` but 8220 `bind:127.0.0.1` (`lme-fleet-server.yml:59`);
  wazuh 1514/1515 (`lme-wazuh-manager.yml:67-68`) + logstash beats 5044 (`lme-logstash.yml:73`) same.
  The `elastic-agent install --url=https://<LAN-IP>:8220` Kibana hands operators is **dead for any
  remote agent**. THIS is the same reachability wall as the trixie/multimachine goal — see unification below.

### D3 — "green install" asserts control-plane liveness, not data flow (the false-success trap)
- Hard gate `fleet/tasks/main.yml:711-730` only checks agent check-in (`total>0 and online>0`, via the
  working alias). The only data-flow check (`metrics-elastic_agent.*` indices, `:784-802`) carries
  **`ignore_errors: yes` (:802)** → when data never flows it just times out and the play proceeds green.
  A completed install is NOT evidence anything was collected.

### D4 — dashboards imported against indices the default deploy can never fill → "UIs link, show nothing."

### Product-scope gaps (intended-but-unsurfaced, not code bugs)
- **G-Endpoints:** endpoint/agent enrollment lives ONLY in role `ludus_lme_agents` (invoked by the Ludus
  test-RANGE playbooks, `ansible/ranges/*.yml`), **NEVER by `site.yml`** (the install.sh path). Product
  install = server/control-plane only, ZERO producers enrolled.
- **G3 — beats OFF by default:** metricbeat/filebeat/heartbeat/apm/logstash are
  `enabled_when:[install_elastic_services]` which defaults FALSE (`site.yml:13`; install.sh forces false
  unless `--elastic-services` && !`--offline`). BUT they ship to the WORKING podman alias → they'd
  collect the server's own logs/metrics if enabled (unlike Fleet). Low-friction self-collection lever.
- **G4 — wazuh:** manager runs + embedded filebeat→ES alias works, but no wazuh agents in product path.
- **NON-gap:** ingest pipelines are NOT missing — they ship with the EPM integration packages; unused
  only for lack of a producer. Do not chase "missing pipelines."

### gippidy vs native — the boundary (E's adjudication, matches A+B)
- **gippidy otel/hertzbeat CAN substitute for the beats layer (G3/self-mon):** produce host journald logs
  + system/infra metrics, ship straight to ES via the working podman alias, WITHOUT Fleet enrollment →
  closes "the server can't see itself" and SIDESTEPS D1. Good fit for the infra-observability slice.
- **Tailscale = TRANSPORT, not a collector** → maps onto D2/remote reachability (VIP/ingress for
  8220/9200/1514), not a collection gap.
- **HARD BOUNDARY:** Elastic Defend endpoint-security events + Wazuh alerts categorically REQUIRE agents
  enrolled in the Fleet/Wazuh control planes. NO otel/hertzbeat/tailscale kit produces those → native
  Fleet/Wazuh enrollment (CRUX-B, D2, G-Endpoints, G4) is the actual SIEM purpose, must be fixed in LME.

### ★ UNIFICATION with the cross-host goal (the operator was right — one problem)
D1+D2 explain BOTH "nothing collects" AND why cross-host fails — SAME class of bug (service reachable
only on loopback while advertised elsewhere). The fix IS the tailscale-VIP work already banked (Phase B):
- **In-box collection:** repoint Fleet output to podman alias `https://lme-elasticsearch:9200` → the
  already-enrolled fleet-server agent ships → ES populates. Smallest possible "it collects" proof.
- **Cross-host / e2e:** advertise the banked tailnet VIP (`lme-elasticsearch.tail6c2eb6.ts.net:9200`) as
  the Fleet output + open 8220 via tailscale ingress (R4) → remote endpoints (trixie + others) enroll and
  ship over the tailnet. The trixie leg becomes a REAL data-producer proof, not consumption-of-empty-ES.
  Collection and cross-host are the same fix, exactly as the operator insisted.

---

## C — tailscale-hertzbeat (point II: tailscale cert + metrics → elastic)  (agent ab76fe87) ✅
Full report also at scratchpad/tailscale-hertzbeat-report.md (scratchpad = ephemeral; essence here is durable).

**Canonical = the NON-kit `tailscale-hertzbeat`** (VERSION 1.0.0; long-running-daemon design maps to LME
`kind: container` — the `-kit` uses a systemd `.timer` which does NOT map to LME's manifest schema).
Both pass their own SHA256SUMS; divergent generations, neither a subset.

**What it collects (4 classes + cert):** (a) client node metrics — Prometheus `/metrics` on **:5252**
(15 `tailscaled_*` families); (b) config-audit log stream → HEC listener **:8444**; (c) network-flow log
stream → HEC **:8443**; (d) read-only REST API snapshots (`devices` 300s, stream-status 60s; opt-in
routes/posture/dns/acl/…), nonkit's `api_exporter` also emits **27 `tailscale_api_*`** Prom families
incl. `tailscale_api_device_key_expiry_timestamp_seconds`. CERT = 3 distinct things: (1) `tailscale cert`
TLS material for the HEC listener = INFRA not a signal; (2) node KEY-expiry as a metric (nonkit); (3)
TLS-cert-EXPIRY monitoring = NEITHER package collects → punted to operator.

**Ship-to-elastic = NEGATIVE:** both target HertzBeat OTLP; NO ES index/data-stream/pipeline in either.
The ES sink must be BUILT. **But LME can do point II with its OWN already-shipped beats, no HertzBeat:**
- **METRICS path (rank #1, fully in-repo, no new image):** LME's `config/metricbeat.yml` → add a
  `prometheus` module (metricset `collector`) scraping the tailscale client `:5252/metrics` (+ nonkit
  api_exporter `:9478`) → 15 `tailscaled_*` + 27 `tailscale_api_*` land in ES with ZERO HertzBeat. Touch
  `manifests/services/lme-metricbeat.yml` + a manifest-driven targets list.
- **CERT path (rank #2, collector already shipped):** LME's `config/heartbeat.yml` → add ONE `http`/`tcp`
  TLS monitor on the Tailscale ingress FQDN → Heartbeat emits `tls.server.x509.not_after` (cert-expiry)
  INTO ES natively, zero new code. Literal "tailscale cert → elastic," SEPARATE from the metrics path.
- **LOGS path (audit/flow/API):** need a shaping stage — Logstash **mTLS :5044** (NOT the bare `http{8085}`
  in lme.conf:36 which is an unauthenticated log-injection hole once fronted on the tailnet), or build the
  OTLP→ES adapter (SINK-CONTRACTS.md describes it; no code).

**VIP compose:** new `manifests/services/lme-tailscale-hec.yml` (`kind: container`, `restart: always`,
`enabled_when:[install_elastic_services]`) + top-level `tailnet_service: svc:lme-tailscale-hec` (opt-in
VIP marker) + `publish_ports` 8443/8444 `bind:127.0.0.1` **`serve: tcp`** (MANDATORY raw-TLS passthrough
per tailscale_service.yml:36-40 — backend terminates its own TLS + checks `Authorization: Splunk`;
`--https` would strip both). 5th `svc:lme-*` alongside the banked 4, untouched. Arm under
profiles/tailscale.yml; the tailnet policy `autoApprovers.services` MUST define the new svc name or
`tailscale_require_vip_live` hard-fails. IPv6 note: HEC needs tailnet IPv6/FQDN but LME `lme` net is
IPv4-only → bind loopback + front raw `--tcp` (the logstash:5044 pattern).

**Secrets → LME driver:** tailscale OAuth client secret (mount, like litellm master_key), 2 HEC tokens
(audit+flow, ≥24 chars), reuse `elastic` env secret for the ES sink. Parameterize into manifests: ports
8443/8444/5252/9478/12318/9461-3, node FQDN/IPv6, tailnet name, 30s interval, OAuth client_id+scopes,
and re-point the destination FROM hertzbeat OTLP TO the LME sink. Flag cert renewal+reload (renewing the
file does not reload an already-loaded cert).

---

## ALL 5 FANOUT AGENTS COMPLETE. Next: `/ocr:map` run-15 anchored on this file (see handoff memory).
