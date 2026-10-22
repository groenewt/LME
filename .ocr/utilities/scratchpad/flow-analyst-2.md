# Flow Analyst 2 — Sections 4–8 (branch `fix/debian-13-selinux-apt` vs `origin/main`)

Navigation aid only — traces how these files fit together (deploy path, systemd
ordering, cert/secret flow). No critique.

Deploy substrate: `install.sh` → `ansible-playbook` (podman role) →
`/etc/containers/systemd/*.container` (Quadlet) → podman-system-generator emits
`*.service` units → `lme.service` umbrella (`PartOf=`/`WantedBy=lme.service`).
Ansible include order (podman `main.yml`): `container_setup.yml` (base secrets +
image pull) → `setup_secrets.yml` → `quadlet_setup.yml` (copies `quadlet/` tree,
renders ES + LiteLLM templates) → `elastic_services_setup.yml`
(gated `install_elastic_services`) → `llama_cpp_setup.yml` (gated `install_llm`).

---

## Flow Analysis: ansible/templates/lme-litellm.container.j2
### Upstream (what deploys/starts this)
- Rendered by `quadlet_setup.yml` task "Render LiteLLM quadlet from template …"
  → `/etc/containers/systemd/lme-litellm.container`, `when: install_llm`, now
  with `no_log: true` (secret no longer in the rendered text, but task hardened).
- The static `quadlet/lme-litellm.container` is also staged by the whole-dir
  quadlet copy, but the template render to the same dest is authoritative. The
  old redundant copy in `llama_cpp_setup.yml` ("Copy LiteLLM quadlet file …")
  was REMOVED in this branch, so the template is the single source now.
- systemd: `Requires=lme-network.service lme-llama-cpp.service`,
  `After=lme.service lme-network lme-llama-cpp`, `PartOf=lme.service`,
  `WantedBy=default.target lme.service`. Started/enabled + restarted by
  `llama_cpp_setup.yml` ("Enable and start LiteLLM service", then "Restart
  LiteLLM to pick up DATABASE_URL").
### Downstream (secrets/certs/aliases/ports it depends on)
- Network alias `lme-litellm`; `PublishPort=4000:4000` (all interfaces —
  fronted by tailscale ingress when opted in).
- Cert volume `lme_certs:/certs:ro,idmap` (NEW `,idmap`); reads its own leaf
  `/certs/litellm/litellm.{key,crt}` (0640 key) + `/certs/ca/ca.crt`.
- Secrets: `llm-keys,type=mount` (→ `/run/secrets/llm_keys`) and NEW
  `pgvector,type=env,target=PGVECTOR_PASS`.
- `DATABASE_URL` is now assembled at RUNTIME inside the container `sh -c`:
  `postgresql://$${PGVECTOR_USER}:$${PGVECTOR_PASS}@$${PGVECTOR_HOST}:$${PGVECTOR_PORT}/$${PGVECTOR_DB}`
  from `Environment=PGVECTOR_{HOST=lme-pgvector,PORT=5432,DB=litellm,USER=lme}`
  plus the `pgvector` env secret. Replaces the old build-time
  `{{ global_secrets.pgvector }}` interpolation (secret no longer baked into
  the unit file). `$$`→literal `$`: systemd unescapes, the in-container shell
  expands.
### Related Files
- `quadlet/lme-litellm.container` (kept byte-identical to the rendered form).
- `quadlet/lme-pgvector.container` (DB target, alias `lme-pgvector:5432`;
  `pgvector` file-driver secret and the `litellm` database created in
  `llama_cpp_setup.yml`).
- `config/setup/init-setup.sh` + `instances.yml` (mint the litellm leaf).
### Flow Context
LiteLLM connects to pgvector for persistent UI/key management; the DB URL is now
built at container start from discrete env parts + a podman env secret, so the
password never lands in the on-disk unit or ansible logs.

---

## Flow Analysis: quadlet/lme-litellm.container
### Upstream (what deploys/starts this)
- Staged by `quadlet_setup.yml` "Copy full quadlet files …" then overwritten at
  the same path by the template render above. Effectively a checked-in mirror of
  the template output; the template wins at deploy.
### Downstream / Related / Flow Context
- Same secrets/certs/aliases/ports/DATABASE_URL as the template (see above).
  This branch updated the static file to match (`,idmap`, `pgvector` env secret,
  runtime `DATABASE_URL`) so the two never diverge.

---

## Flow Analysis: ansible/templates/lme-elasticsearch.container.j2
### Upstream (what deploys/starts this)
- Rendered by `quadlet_setup.yml` "Render Elasticsearch quadlet from template
  (cluster-aware)" → `/etc/containers/systemd/lme-elasticsearch.container`
  (always; overwrites the static copy).
- systemd: `Requires=lme-network.service lme-setup-certs.service`,
  `After=` same, `PartOf=lme.service`, `WantedBy=default.target lme.service`.
- Render inputs (NEW conditional block): `es_memory_high` (default `6G`),
  `es_memory_max` (default `8G`), `es_heap_size` (default `4g`),
  `es_discovery_type`. Only `es_discovery_type` is actually defined anywhere
  (`ansible/elasticsearch.yml` / `site.yml`: `single-node` vs `cluster` from
  `lme_cluster_mode`); `es_heap_size`/`es_memory_*` are NOT defined in the repo,
  so their `default()` values ARE the effective single-node render. The caps +
  `-Xms/-Xmx` bounding apply only when `es_discovery_type == single-node` (or a
  var is set explicitly), so cluster data nodes keep implicit ES sizing.
### Downstream (secrets/certs/aliases/ports it depends on)
- Alias `lme-elasticsearch`; `PublishPort` `9200:9200` + `9300:9300`
  (overridable via `es_http_publish_port`/`es_transport_publish_port`).
- Cert volume `lme_certs:/usr/share/elasticsearch/config/certs` (this is the
  cert CONSUMER that shares the volume filled by `lme-setup-certs`).
- Secrets: `elastic` (ELASTIC_PASSWORD), `kibana_system`
  (ELASTICSEARCH_PASSWORD + KIBANA_PASSWORD).
### Related Files
- `config/setup/init-setup.sh` (runs in the ES image; mints the CA + all leaves
  into `lme_certs`), `instances.yml`, `quadlet/lme-setup-certs.container`.
- Every unit with `Requires=lme-elasticsearch.service` (all elastic-services
  pack units, fleet-server/distribution, dashboard, log-analyzer).
### Flow Context
Adds cgroup `MemoryHigh`/`MemoryMax` backstops + explicit JVM heap bounding on
single-node so ES can't OOM the shared box; the mlocked heap is kept below
`MemoryMax`. ES is the root of the internal-CA mesh and the ordering anchor for
most other units.

---

## Flow Analysis: quadlet-optional/elastic-services/lme-apm-server.container
### Upstream (what deploys/starts this)
- Copied by `elastic_services_setup.yml` "Copy Elastic services pack quadlets …"
  (`quadlet-optional/elastic-services/` → `/etc/containers/systemd/`), gated
  `install_elastic_services` (install.sh `--elastic-services`) and skipped on
  `lme_child_es_only`. Started by "Start Elastic services pack units".
- systemd: `Requires=/After= lme-elasticsearch.service lme-setup-certs.service`,
  `PartOf=lme.service`, `WantedBy=default.target lme.service`.
- `elastic_services_setup.yml` also "Restart cert setup unit to run the cert
  top-up" — REQUIRED here: apm-server is NOT in `init-setup.sh`'s line-29
  pre-mint list, so its leaf is minted only by the top-up loop (from
  `instances.yml`), and it disables the host `apm-server.service` squatting :8200.
### Downstream (secrets/certs/aliases/ports it depends on)
- Alias `lme-apm-server`; `PublishPort=8200:8200` (fronted by tailscale ingress
  when opted in). Config `/opt/lme/config/apm-server.yml`.
- Cert volume `lme_certs:/certs:ro,idmap` (NEW). Reads its 0640 leaf
  `/certs/apm-server/apm-server.key`.
- NEW `User=root`: the image's non-root uid does not map to the key owner
  (166536) under idmap, so it reads the 0640 key via CAP_DAC_OVERRIDE.
- Secret: `elastic` (ELASTICSEARCH_PASSWORD).
### Related Files
- Sibling pack units (logstash/filebeat/heartbeat/metricbeat), `instances.yml`
  (`apm-server` SAN), `init-setup.sh` top-up loop, `elastic_services_setup.yml`.
### Flow Context
`,idmap` + `User=root` together let apm-server read its own private key under
the tightened (0640) cert regime; the pack-restart of `lme-setup-certs` is what
actually creates that key.

---

## Flow Analysis: quadlet-optional/elastic-services/lme-logstash.container
### Upstream (what deploys/starts this)
- Same pack copy/start path + cert top-up as apm-server. systemd
  `Requires=/After= lme-elasticsearch.service lme-setup-certs.service`,
  `PartOf=lme.service`.
### Downstream (secrets/certs/aliases/ports it depends on)
- Alias `lme-logstash` (container→logstash traffic uses this, unaffected by the
  host publish binding). `PublishPort` CHANGED to loopback:
  `127.0.0.1:5044:5044` + `127.0.0.1:8085:8085` (was all-interfaces). Host-facing
  5044 is fronted by the opt-in tailscale ingress (`--tcp` passthrough).
- `Environment="LS_JAVA_OPTS=-Xms512m -Xmx512m"` (quoted; both Xms+Xmx set to
  avoid Xms>Xmx JVM abort from the appended in-image `-Xms1g`).
- Cert volume `lme_certs:/certs:ro,idmap` (NEW) + NEW `User=root` → reads 0640
  `/certs/logstash/logstash.key`.
- Config volumes `/opt/lme/config/logstash/logstash.yml` and
  `…/logstash/pipeline` (carries `lme.conf`). Secret `elastic`
  (ELASTICSEARCH_PASSWORD, consumed by the pipeline output).
### Related Files
- `config/logstash/pipeline/lme.conf` (the pipeline this unit runs),
  `instances.yml` (adds `lme-logstash` SAN to the logstash leaf),
  `tailscale_ingress.yml` (fronts 5044), `init-setup.sh`.
### Flow Context
Logstash now terminates beats TLS itself with its internal-CA leaf; ports are
loopback-bound and only exposed via opt-in tailscale passthrough; `,idmap` +
`User=root` + the JVM/quoting fixes make it boot under the tightened cert regime.

---

## Flow Analysis: quadlet-optional/elastic-services/lme-filebeat.container
### Upstream
- Pack copy/start path (gated `install_elastic_services`). systemd
  `Requires= lme-elasticsearch.service lme-setup-certs.service
  lme-filebeatdata-volume.service`; `After=` adds `lme-kibana.service`;
  `PartOf=lme.service`.
### Downstream
- Alias `lme-filebeat` (no PublishPort). Cert volume `lme_certs:/certs:ro,idmap`
  (NEW). Already carries pre-existing `User=root` (verified) — so it reads any
  0640 material via CAP_DAC_OVERRIDE. Reads journald mounts + `filebeat.yml`.
### Related Files
- Sibling pack units; `lme-filebeatdata.volume`; `init-setup.sh`.
### Flow Context
`,idmap`-only change (already root); aligns filebeat with the tightened cert
volume — this is the pattern apm-server/logstash now copy.

---

## Flow Analysis: quadlet-optional/elastic-services/lme-heartbeat.container
### Upstream
- Pack copy/start path. systemd `Requires= lme-elasticsearch.service
  lme-setup-certs.service`; `After=` adds `lme-kibana.service`.
### Downstream
- Alias `lme-heartbeat`, `--cap-add=NET_RAW`. Cert volume
  `lme_certs:/certs:ro,idmap` (NEW). NO `User=root` — heartbeat has no leaf in
  `instances.yml`, so it only needs the world-readable `/certs/ca/ca.crt`
  (0644); idmap alone suffices. Secret `elastic`.
### Related Files
- Sibling pack units; `init-setup.sh` (CA cert only).
### Flow Context
Only reads the CA (0644), so `,idmap` without `User=root` is sufficient — the
discriminator vs apm-server/logstash (which own 0640 private keys).

---

## Flow Analysis: quadlet-optional/elastic-services/lme-metricbeat.container
### Upstream
- Pack copy/start path. systemd `Requires= lme-elasticsearch.service
  lme-setup-certs.service`; `After=` adds `lme-kibana.service`.
### Downstream
- Alias `lme-metricbeat`. Cert volume `lme_certs:/certs:ro,idmap` (NEW).
  Pre-existing `User=root` (verified). hostfs mounts `/proc`, `/sys/fs/cgroup`.
  Secret `elastic`.
### Related Files
- Sibling pack units; `init-setup.sh`.
### Flow Context
`,idmap`-only change (already root); same cert-volume alignment as filebeat.

---

## Flow Analysis: config/logstash/pipeline/lme.conf  (NEW FILE)
### Upstream (what deploys/starts this)
- Deployed as part of the whole-dir config copy in `quadlet_setup.yml` ("Copy
  config files /opt/lme/config", `force: {{ lme_force_config | default(false) }}`)
  → `/opt/lme/config/logstash/pipeline/lme.conf`. DEPLOY BEHAVIOR: first install
  copies it; later edits do NOT propagate unless `lme_force_config=true` (new
  file, so first install is fine). `elastic_services_setup.yml` re-owns
  `config/logstash` to root recursively (state=directory, recurse) so the tree
  stays traversable for the container user.
- Mounted read-only into `lme-logstash` via
  `/opt/lme/config/logstash/pipeline:/usr/share/logstash/pipeline:ro`.
### Downstream (secrets/certs/aliases/ports it depends on)
- beats input: TLS on `:5044` using `/certs/logstash/logstash.crt` +
  `/certs/logstash/logstash.key` (the logstash leaf; mTLS lines commented out).
- http input `:8085`.
- elasticsearch output → `https://lme-elasticsearch:9200`, `cacert
  /certs/ca/ca.crt`, `password => "${ELASTICSEARCH_PASSWORD}"` — that env comes
  from the `elastic` podman secret in `lme-logstash.container`.
### Related Files
- `lme-logstash.container` (runs it; supplies certs+secret+`User=root`),
  `instances.yml` (mints the logstash leaf w/ `lme-logstash`,`logstash`,
  `localhost`,`127.0.0.1` SANs), `tailscale_ingress.yml` (fronts 5044 as raw TCP
  so external beats still see the internal-CA leaf).
### Flow Context
Encrypts the previously-plaintext beats→logstash leg with the internal LME CA;
key path + SANs + the logstash unit's cert perms all have to line up for it to
listen.

---

## Flow Analysis: quadlet/lme-dashboard.container
### Upstream
- Whole-dir quadlet copy (`quadlet_setup.yml`). `llama_cpp_setup.yml` builds the
  `localhost/lme-dashboard:LME_LATEST` image and manages the service. systemd
  `Requires=/After= lme-elasticsearch lme-litellm lme-pgvector lme-embeddings`,
  `PartOf=lme.service`.
### Downstream
- Alias `lme-dashboard`, `PublishPort=8502:8502`. Cert volume
  `lme_certs:/certs:ro,idmap` (NEW). Secrets `elastic` (ELASTICSEARCH_PASSWORD)
  + `pgvector` (PGVECTOR_PASS). Reads `/certs/ca/ca.crt` for outbound TLS verify
  (see app.py).
### Related Files
- `lme-dashboard/app.py` (the app running in this image),
  `lme-litellm.container`, `lme-pgvector.container`, `lme-embeddings.container`.
### Flow Context
The dashboard is the top of the LLM-stack ordering chain (Requires four
services); `,idmap` aligns it with the tightened cert volume.

---

## Flow Analysis: quadlet/lme-embeddings.container
### Upstream
- Whole-dir quadlet copy; `llama_cpp_setup.yml` (LLM path). systemd
  `Requires=/After= lme-network.service`, `PartOf=lme.service`.
### Downstream
- Alias `lme-embeddings`, `PublishPort=8081:8081`, model mount
  `/opt/lme/llama-models:/models:Z`. Cert volume `lme_certs:/certs:ro,idmap`
  (NEW). HTTPS healthcheck on 8081.
### Related Files
- `lme-llama-cpp.container` (sibling model server), `lme-dashboard.container`
  (Requires embeddings), `init-setup.sh` (embeddings leaf).
### Flow Context
`,idmap`-only cert-volume alignment; leaf-serving embeddings endpoint.

---

## Flow Analysis: quadlet/lme-fleet-server.container
### Upstream
- Whole-dir quadlet copy. systemd `Requires= lme-elasticsearch.service`,
  `After=` adds `lme-kibana.service`, `PartOf=lme.service`. Also podman-level
  `PodmanArgs=--requires 'lme-elasticsearch,lme-kibana'`.
### Downstream
- Alias `lme-fleet-server`, `PublishPort=8220:8220`. Cert volume
  `lme_certs:/certs:ro,idmap` (NEW) + `lme_fleet_data`. Secret `elastic`
  (KIBANA_FLEET_PASSWORD). NOTE: carries an explicit
  `UserNS=auto:uidmapping=0:171632:3048` (differs from the 165536 base that owns
  the certs) — stated, not judged; idmap remaps ownership into the container's
  range.
### Related Files
- `lme-fleet-distribution.container`, `lme-kibana.container`, `init-setup.sh`.
### Flow Context
`,idmap`-only cert change on a unit with a non-default UserNS mapping.

---

## Flow Analysis: quadlet/lme-fleet-distribution.container
### Upstream
- Whole-dir quadlet copy. systemd `Requires=/After= lme-elasticsearch.service
  lme-setup-certs.service`, `PartOf=lme.service`.
### Downstream
- Alias `lme-fleet-distribution`, `PublishPort=8080:8080`. Cert volume
  `lme_certs:/certs:ro,idmap` (NEW). Serves EPR over TLS with
  `/certs/fleet-distribution/fleet-distribution.{crt,key}` (its own leaf).
### Related Files
- `lme-fleet-server.container`, `init-setup.sh` (fleet-distribution leaf),
  offline Kibana `registryUrl` block in `quadlet_setup.yml`.
### Flow Context
`,idmap` alignment for a unit that serves its own private-key leaf (needs the
0640 key readable — runs default image user, relies on idmap ownership remap).

---

## Flow Analysis: quadlet/lme-llama-cpp.container
### Upstream
- Whole-dir quadlet copy; `llama_cpp_setup.yml` copies+manages it (LLM path).
  systemd `Requires=/After= lme-network.service`, `PartOf=lme.service`. It is a
  `Requires=` dep of `lme-litellm.service`.
### Downstream
- Alias `lme-llama-cpp`, model mount `/opt/lme/llama-models:/models:Z`. Cert
  volume `lme_certs:/certs:ro,idmap` (NEW). Serves TLS with
  `/certs/llama-cpp/llama-cpp.{crt,key}`.
### Related Files
- `lme-litellm.container` (upstream consumer), `lme-embeddings.container`,
  `init-setup.sh`.
### Flow Context
`,idmap`-only cert-volume alignment; the model backend LiteLLM depends on.

---

## Flow Analysis: quadlet/lme-log-analyzer.container
### Upstream
- Whole-dir quadlet copy; `llama_cpp_setup.yml` builds
  `localhost/lme-log-analyzer:LME_LATEST`. systemd — NOTE this is the ONLY unit
  in the set using `Wants=` (soft) not `Requires=`:
  `Wants=/After= lme-elasticsearch.service lme-litellm.service`,
  `PartOf=lme.service`.
### Downstream
- Alias `lme-log-analyzer`, `PublishPort=8501:8501`. Cert volume
  `lme_certs:/certs:ro,idmap` (NEW), serves TLS with its own leaf
  `/certs/log-analyzer/log-analyzer.{crt,key}`. Talks to
  `LITELLM_URL=https://lme-litellm:4000` (`LITELLM_MODEL=lfm2.5-1.2b-instruct`)
  and ES. Secret `elastic` (ELASTICSEARCH_PASSWORD).
### Related Files
- `lme-litellm.container`, `lme-elasticsearch.container.j2`,
  `lme-dashboard/app.py` (sibling LiteLLM client).
### Flow Context
`,idmap`-only cert change; soft-wants ES/LiteLLM so it starts even if they are
degraded.

---

## Flow Analysis: ansible/roles/podman/tasks/tailscale_ingress.yml  (NEW FILE)
### Upstream (what deploys/starts this)
- `include_tasks` from `elastic_services_setup.yml`, gated
  `when: tailscale_serve_ingress | default(false)` (opt-in,
  `-e tailscale_serve_ingress=true`). Runs only inside the elastic-services pack
  path, i.e. also requires `install_elastic_services`.
### Downstream (what it depends on)
- Depends on a working `tailscale`/`tailscaled` binary on the host, MagicDNS +
  HTTPS certs enabled, node logged in. FAILS FAST if `tailscale status` rc!=0.
  Derives the node ts.net name from `tailscale status --json` `.Self.DNSName`.
- Fronts loopback-bound published ports: `tailscale serve --bg --https=8200
  https+insecure://127.0.0.1:8200` (apm-server) and `--https=4000` (litellm) —
  TLS-terminated with the ts.net LE cert, re-encrypted to the self-signed
  backend; and `tailscale serve --bg --tcp=5044 tcp://127.0.0.1:5044` (logstash
  beats) — raw TCP passthrough so external beats still receive logstash's
  internal-CA leaf.
### Related Files
- `lme-logstash.container` / `lme-apm-server.container` / `lme-litellm.container`
  (the loopback-bound backends it fronts), `elastic_services_setup.yml` (the
  gate), `config/logstash/pipeline/lme.conf` (beats TLS terminated by logstash,
  not tailscale).
### Flow Context
Opt-in host-facing ingress layer; deliberately does NOT touch the internal
ES-CA mesh. NO role installs tailscale — it is an EXTERNAL execution
prerequisite the operator must provision first.

---

## Flow Analysis: scripts/prepare_offline.sh
### Upstream (what invokes it)
- Run MANUALLY on an internet-connected machine before an air-gapped install
  (`scripts/prepare_offline.sh [--llm] [--arch ARCH]`); referenced throughout
  `install.sh` (offline preflight messages at lines 142/210/915/1005/1373) and
  in `.github/workflows/offline.yml:468`. Not called by ansible.
### Downstream (what it produces / who consumes)
- `main()` order: `check_internet` → `check_podman` → `download_containers`
  (from `config/containers.txt`) → if `--llm`: `download_llm_containers`
  (`containers-llm.txt`) + `build_ingest_image` + `download_llm_models` (2 GGUFs)
  + `build_lme_images` → `download_packages` → `download_agents` →
  `download_cve_database`. Each image saved via `save_container_tar` into the
  offline bundle/MANIFEST.
- The CHANGE: adds `--network=host` to the three in-repo `podman build`s
  (`localhost/lme-ingest`, `localhost/lme-log-analyzer`, `localhost/lme-dashboard`)
  so their RUN steps (apt/pip) use the host netns that `check_internet` already
  validated. Build-time only; runtime image unchanged.
- Consumers: `container_setup.yml` → `load_offline_containers.yml`;
  `llama_cpp_setup.yml` → `load_offline_llm.yml`, and `lme-ingest` is used by
  `llama_cpp_setup.yml:328` (docs ingestion). Built images back
  `lme-log-analyzer.container` / `lme-dashboard.container`.
### Related Files
- `config/containers.txt`, `config/containers-llm.txt`, `load_offline_*.yml`,
  `lme-log-analyzer.container`, `lme-dashboard.container`, `install.sh` offline
  preflight.
### Flow Context
The offline image factory. `--network=host` unblocks the image builds on
Tailscale/proxy/split-DNS prep machines whose container netns lacks egress.

---

## Flow Analysis: lme-dashboard/app.py
### Upstream (what deploys/starts this)
- Baked into `localhost/lme-dashboard:LME_LATEST` (built online in
  `llama_cpp_setup.yml`, or offline by `prepare_offline.sh build_lme_images`);
  runs as the `lme-dashboard` service.
### Downstream (what it depends on)
- `_sync_active_model_from_litellm()` GETs `{LITELLM_URL}/v1/models` — the
  single-line CHANGE flips `verify=False` → `verify="/certs/ca/ca.crt"`, i.e.
  it now validates LiteLLM's leaf against the internal CA. Depends on the
  `lme_certs` volume being mounted at `/certs` in `lme-dashboard.container`
  (`,idmap`) and on `lme-litellm`'s leaf being CA-signed with the `lme-litellm`
  SAN (from `instances.yml`).
### Related Files
- `lme-dashboard.container` (mounts `/certs`, sets `LITELLM_URL`),
  `lme-litellm.container` (the TLS endpoint), `init-setup.sh`/`instances.yml`
  (CA + litellm leaf).
### Flow Context
Turns off TLS-verification-disabled on the dashboard→LiteLLM call; correctness
of the change hinges on the CA cert being present in the dashboard container and
the litellm leaf carrying the container-alias SAN.

---

## Quadlet Unit Dependency Graph
(`R`=Requires, `A`=After, `W`=Wants; all pack + LLM units are `PartOf=lme.service`)

```
lme-network.service ──────────────┐
lme-esdata01-volume ──┐           │
lme-kibanadata-volume ┴─ R/A ─> lme-setup-certs.service  (oneshot, mints certs into lme_certs)
                                        │
lme-elasticsearch.service  R/A: lme-network, lme-setup-certs
        ├─ R/A <── lme-fleet-distribution.service   (R/A: lme-setup-certs too)
        ├─ R  <── lme-fleet-server.service          (A: +lme-kibana; podman --requires es,kibana)
        ├─ R/A <── lme-apm-server.service            (R/A: +lme-setup-certs)      [pack]
        ├─ R/A <── lme-logstash.service              (R/A: +lme-setup-certs)      [pack]
        ├─ R    <── lme-filebeat.service   (R:+lme-setup-certs,+filebeatdata; A:+kibana) [pack]
        ├─ R/A <── lme-heartbeat.service   (R/A:+setup-certs; A:+kibana)          [pack]
        ├─ R/A <── lme-metricbeat.service  (R/A:+setup-certs; A:+kibana)          [pack]
        ├─ R    <── lme-dashboard.service  (R/A: +litellm,+pgvector,+embeddings)
        └─ W    <── lme-log-analyzer.service (W/A: +litellm)   <-- only Wants= in set

lme-network.service
        ├─ R/A <── lme-pgvector.service
        ├─ R/A <── lme-embeddings.service
        ├─ R/A <── lme-llama-cpp.service  <── R/A ── lme-litellm.service
        └─ (litellm R/A: lme-network + lme-llama-cpp; NOTE no lme-pgvector.service dep)
```

Cross-cut (NOT expressed as systemd deps — imperative in `llama_cpp_setup.yml`):
`lme-litellm` consumes the `pgvector` secret and points `DATABASE_URL` at
`lme-pgvector:5432`, but its `Requires=`/`After=` list only `lme-network` +
`lme-llama-cpp`. DB readiness is instead enforced by the playbook order: start
pgvector → `pg_isready` (30×10s) → `CREATE DATABASE litellm` → "Restart LiteLLM
to pick up DATABASE_URL".

---

## Cert & Secret Flow

Producer (certs): `lme-setup-certs.service` (oneshot, `User=0`, `UserNS=auto`)
runs `config/setup/init-setup.sh` inside the ES image, writing into the shared
`lme_certs` volume:
- `elasticsearch-certutil ca` → `/certs/ca/ca.{crt,key}`.
- `elasticsearch-certutil cert --in instances.yml --ca-cert ca.crt --ca-key
  ca.key` → per-instance leaves `/certs/<name>/<name>.{crt,key}` +
  `<name>.chain.pem`. `instances.yml` is the SAN source of truth (this branch
  adds `lme-logstash` and `lme-curator` SANs).
- Line-29 loop pre-creates dirs for a fixed service list; any `instances.yml`
  entry NOT in it (e.g. `apm-server`) is minted by the idempotent TOP-UP loop.
  `elastic_services_setup.yml` "Restart cert setup unit to run the cert top-up"
  re-fires the oneshot so pack leaves (apm-server, logstash) exist.
- NEW permission discipline (init-setup.sh): public material (`*.crt`,
  `*.chain.pem`) `0644`; private keys `*.key` `0640` (group-only); `ca/ca.key`
  and `*.zip` bundles `0600`. Owner `elasticsearch:elasticsearch` (host uid
  166536 = ES `UserNS` base 165536 + in-container uid 1000). New
  `LME_FORCE_CERT_REMINT` env forces re-mint after a SAN/instances.yml edit.

Consumers (certs): every unit mounts `lme_certs:/certs:ro,idmap` (this branch
adds `,idmap` to 13 units). `idmap` remaps the 166536 owner into the container's
uid range so the leaf is reachable. DISCRIMINATOR:
- Units that read only the world-readable CA (`/certs/ca/ca.crt`, 0644) work
  with `,idmap` alone — e.g. `lme-heartbeat` (no leaf, no `User=root`).
- Units that must open their own 0640 private key while running as a non-root
  in-container uid also set `User=root` (read via CAP_DAC_OVERRIDE):
  NEW `User=root` on `lme-apm-server` + `lme-logstash`; pre-existing `User=root`
  on `lme-filebeat` + `lme-metricbeat` (verified). `lme-fleet-server` instead
  carries an explicit `UserNS=auto:uidmapping=0:171632:3048`.

Producer (secrets):
- `container_setup.yml` "Set podman secret passwords" (shell driver):
  `elastic`, `kibana_system`, `wazuh_api`, `wazuh` (skipped on cluster nodes,
  which receive them via secrets_distribution).
- `llama_cpp_setup.yml`: `pgvector` (file driver, random 30-char) and `llm-keys`
  (file driver, `# empty` placeholder) — created only if absent.
Consumers (secrets): `elastic` → ES/logstash/heartbeat/metricbeat/filebeat/
apm-server/log-analyzer/dashboard/fleet-*; `kibana_system` → ES/setup-certs;
`pgvector` (type=env PGVECTOR_PASS) → litellm + dashboard (+ ingest job);
`llm-keys` (type=mount) → litellm.

---

## Upcoming-direction readiness

### Tailscale: ingress vs egress vs services
- INGRESS — PRESENT (opt-in). `tailscale_ingress.yml` uses only `tailscale
  serve` on the node's OWN ts.net MagicDNS name: `serve --bg --https=8200/4000`
  (TLS-terminated → local HTTPS backend) and `serve --bg --tcp=5044` (raw TCP
  passthrough). Confirmed ingress-only; no `--service=` and no egress verbs.
- EGRESS — ABSENT. No `tailscale up --advertise-routes`, `--accept-routes`,
  `--exit-node`, or subnet-router config anywhere in the repo. Nothing lets LME
  containers reach OFF-tailnet destinations via a tailscale exit/subnet node.
  Would hook in as a new task alongside `tailscale_ingress.yml` (or a host
  prereq) + per-container routing; not present.
- SERVICES (VIP `tailscale serve --service=svc:<name>`) — ABSENT. Current code
  binds serve to the single node's ts.net name only (comment explicitly notes
  the ts.net leaf SAN = this node only, so it can't stand in for cluster
  aliases). A VIP-service front (stable name across nodes, needed for a 3-node
  cluster) would replace the per-node `--https=/--tcp=` lines here; not present.
- PREREQ GAP: no role installs `tailscale`/`tailscaled`; the task fails fast if
  the node is not already up on the tailnet with MagicDNS + HTTPS certs.

### Airgapped / offline completeness
- `prepare_offline.sh` pre-stages: base container images (`containers.txt`);
  with `--llm` also LLM images (`containers-llm.txt`), the built `lme-ingest`,
  2 GGUF models, and the built `lme-log-analyzer` + `lme-dashboard` images; plus
  OS packages, agents, and the CVE database.
- GAP for a FULLY offline install: `install.sh:636` explicitly REJECTS
  `--elastic-services` together with `--offline` ("pack will be skipped"), so
  the Elastic services pack does not run on airgapped installs. Consistent with
  that, none of the five pack base images (apm/logstash/filebeat/heartbeat/
  metricbeat) appear in `config/containers.txt` or `config/containers-llm.txt`
  (verified by grep: no match). So airgapped == core stack only; the pack (and
  therefore
  `lme.conf`/logstash TLS ingest and the tailscale ingress that fronts it)
  cannot run offline as wired.
- The `--network=host` build fix is what makes the offline IMAGE BUILD itself
  succeed on locked-down prep hosts; without it the offline bundle can't be
  produced on Tailscale/proxy/split-DNS machines.

### Single-node vs 3-node cluster (and virt assumptions)
- ES sizing block in `lme-elasticsearch.container.j2` is SINGLE-NODE specific:
  `MemoryHigh/MemoryMax` caps + `-Xms/-Xmx` heap bounding apply only when
  `es_discovery_type == single-node` (from `lme_cluster_mode`); dedicated
  cluster data nodes deliberately keep implicit ES sizing. `es_heap_size`/
  `es_memory_*` are undefined repo-wide, so single-node uses the literal
  defaults (4g heap / 6G high / 8G max) — assumes a ~16 GB single box.
- Child (ES-only) cluster nodes: `quadlet_setup.yml` prunes every non-ES quadlet
  (computed from `quadlet/` minus active lists) and `elastic_services_setup.yml`
  skips the pack quadlet copy when `lme_child_es_only`. So on a 3-node cluster
  the pack + LLM + dashboard units run on the MASTER only; `pgvector`/`llm-keys`
  secrets are master-only (change_passwords notes pgvector is master-only).
- Network ALIASES are per-node podman aliases (`lme-elasticsearch`,
  `lme-logstash`, …) — fine within one node's `lme` network, but they do NOT
  give a cluster a stable cross-node name; the tailscale ingress cert is also
  single-node-named (see Services gap above). PublishPorts are host-fixed
  (`8200`, `4000`, `9200`, etc.); only logstash `5044/8085` were moved to
  `127.0.0.1`. Same host port on every node → cross-node fan-in would need the
  missing VIP-service/egress layer.
- QEMU / nested-virt: no explicit assumption found in THESE files; the
  single-node memory defaults (16 GB box) are the only sizing premise. (The
  QEMU/KVM 1/3-node/airgapped validation gating referenced in the review lane is
  a test-harness concern, not encoded in these units.)
```
