# Verified LME, HertzBeat and Malcolm implementation

Status: executing the operator-approved final plan; no commits or pushes authorized.

The binding specification is the final approved plan in this conversation, refined by `.temp.REBUTTAL.00.md` through `.03.md`. The original OCR run-15 lives in `/home/tristan/gitters/LME/.ocr/sessions/2026-09-18-fix-debian-13-selinux-apt/map/runs/run-15/`. Preserve its reported severities and separate reproduction, patch, regression, integration and independent-review states.

## Global constraints

- MAIN owns integration and serialized manifest, credential, network-policy, database and lifecycle changes. Bounded coordinators use the configured Cursor-Grok/OpenCode CLIs; record actual responses and never manufacture reviews.
- Preserve staged/untracked original and sibling-repository work. Work in isolated checkouts; no commits/pushes without explicit confirmation.
- No Windows inspection, enumeration, collection, capture, lifecycle or cleanup. Physical silmaril only permits pre-read allowlisted sources and aggregate totals. Never reboot or power off physical hosts for tests.
- No real credential distribution through unrepaired secret handling. Synthetic sentinel tests precede credential-bearing deployment.
- No host partitions, kernel/sysctl or comparable broad host changes without the operator's requested approval. No implicit GPU passthrough. No blanket wipe.
- One Debian13 guest per graph/trixie/silmaril: respectively 8vCPU/13GiB/40+256GiB, 8/12/40+160, 8/48/40+320. OS reserve2GiB each; Malcolm32GiB within silmaril46GiB application/support ceiling. Full virtual commitments plus100GiB physical reserve. Existing image roots /data/lme-e2e (graph/silmaril), /home/lme-e2e (trixie).
- graph=LME/ES8.18.8/security; trixie=HB1.9.0/Greptime1.1.3/telemetry; silmaril=Malcolm/LiteLLM/preserved small model/embeddings. Each guest hosts both PostgreSQL-domain members and an etcd voter. Actual rootless user Quadlets except declared Malcolm Docker and narrow privileged helpers.
- No Kafka, RabbitMQ, Open Semantic Search deployment. Atlas/Ranger identifiers/ownership/classification/lineage interfaces only.

## Interfaces and invariants

Independent selectors: --profile; --database-profile dual-owned-ha|shared-ha; --telemetry-profile elastic-only|elastic-plus-hertzbeat|full-mirror; optional --telemetry-destinations elastic|elastic,hertzbeat|elastic,hertzbeat,malcolm requiring a telemetry profile. Preset then explicit destination override; normalize effective label. Omission preserves existing collector selection. Reject unsupported/empty/duplicate/conflicting selectors.

Resolved inventory is the single source for host services, owners, sources, routes, credentials, TLS, queues, publications, resource budgets and acceptance. One reader/sampler per semantic family. Runtime secrets must satisfy enabled service union, not an all-host bundle. Current trixie UI requires elastic,pgvector,litellm_master_key,webui_api_key. Keep B3; GAP5 is shipped. Per-host overrides already exist; preserve explicit certificate producer.

Supported clients require chain+hostname TLS; invalid booleans fail. ES multinode+Tailscale keeps guard1b with optional tailnet_port: frontend9200 -> loopback19200 -> container9200. No overlapping wildcard9200/loopback9200 bindings. Fleet advertised enrollment and output endpoints are separate, fully verified contracts. RM3 misplaced-else is not reproduced at2b3c96d; curl000000, empty required endpoints and disabled-required probes are real false passes.

DB default two PostgreSQL17/Patroni groups, three members each, separate namespaces; shared three-voter etcd. HB authoritative hertzbeat initialtrixie; vector authoritative lme_vectors+litellm initialgraph. Owner-local TCP proxies pg-hertzbeat-rw/pg-vector-rw choose current DCS-authorized fenced primary with end-to-end verify-full TLS. strict synchronous physical replication one standby, synchronous_commit=on for apps and subscription workers; failsafe_mode=false. No same-table multiwriter, imports never republished.

Three logical paths: hertzbeat -> vector-domain hertzbeat_replica; lme_vectors -> HB-domain lme_vectors_replica; litellm -> HB-domain litellm_replica. Native initial columns: hzb_monitor(id,intervals,status,type,gmt_create,gmt_update), hzb_collector(id,status,gmt_create,gmt_update), docs_chunks(id,chunk_index,created_at). Synthetic lme_vector_probe(probe_id UUID PK,generation bigint,fixture_version integer,embedding vector(768),updated_at timestamptz); synthetic e1,normalized(e1+e2),e2 cosine ranking. New sanitized lme_litellm_status(service_id text PK,status smallint,version text,artifact_digest text,observed_at,last_success_at) has no raw responses/prompts/credentials. Production corpus/embeddings and unknown native LiteLLM tables excluded. Same schema/table names, selected columns/types/PK at subscriber; INSERT/UPDATE/DELETE only; origin=none plus disjoint ownership; failover slots and completed tablesync slots verified on candidates. Shared-ha is separate fresh deployment, no reciprocal subscriptions.

Fencing: coordinated ledger across domains; exact domain process stop+restart inhibit; independent hypervisor-side guardian may fence only recorded QEMU generation; valid receipt required before promotion/bootstrap/rejoin. Quorum/authority/fence uncertainty means unavailable writes. Returning fenced nodes quarantined for verified replica rebuild. No shared watchdog or host power actions.

Schema-only initialization before subscriptions and normal apps. HB Hibernate-before-Flyway one-shot command; normal ddl-auto=validate, Flyway disabled. Replace both docs_chunks DROP resets with transactional DELETE preserving relation/sequences. Off-domain backups/WAL and isolated restore required.

OTel generic logs/remaining metric families, HertzBeat selected SSH/SQL/REST/genuineJMX families, Wazuh security, Malcolm guest-scoped network analysis. Native metrics to selected Elastic/HB; typed monitoring/lifecycle logs to selected log sinks. HB immutable sample capture before history/Arrow lifetime ends, bounded durable outbox; lifecycle state+outbox same transaction, suppression and notification decisions explicit; opaque IDs not raw label fingerprints. No export loops.

SQLite per-source-node spool4GiB pending plus8GiB verified archive, retention24h after ALL admission-time sink obligations verified. Atomic admission/classification; never purge unverified. Metric queues256MiB/destination;2GiB filesystem floor shared. Sixnodes total logical75GiB full profile beforephysicaloverhead. Selection changes affectnewadmissions; old obligations persist. ACK localfsync != transportaccepted != destinationreadback. Verify canonical payload from retrieved content, not copied hash. Local spool does not cover permanent disk destruction.

Tailscale metrics30s, nonoverlapcheckpointedAPI60s, audit/flow ingress+reconciliation dedup, Serve-managedHTTPS, stagedfilecertcheck12h+reload+servedidentity. QualifyTailscale1.102.4; privilegedServeUnixsocketconfig; no forwardedsecretSSHenv. BrowsercapabilityproxyrestrictedUnixsocket, existingoperator/personaldevices, internalkeyinjection, automationkeys, streaming/WebSockets, sameoriginchecks, forgedheader/crossownerdenial. AIfailuredoesnotstopcollection; provenance/citations retained.

## Tasks

### Task 1: Secret-path OCR remediation
Ownership: secret tasks and dedicated tests. Unconditional no_log/diff suppression, sanitized diagnostics, scoped requirements/distribution including heterogeneous hosts, B3 intact, payload readability before activation, rotation/recreate contract. Prove synthetic raw/encodedcanaries absent in real Ansible callbacks under verbose failure paths.

### Task 2: Application TLS and certificate source
Ownership: dashboard/analyzer clients/manifests, cert source tasks, dedicated TLS tests. True defaults, strictbooleans, chain+SAN in actual clients, nofallback, hosttrustsourcepreservation and namespace-readableCA. Certchangesbeforeclientrestart.

### Task 3: Gate correctness
Ownership: deploy_gate and dedicated tests. Fixcurl000000, requiredprobeempty/disabled failures, applicability/executed/status split, exactrosters, preserveRM3truth table, extendreal-source readback interface and retainfailedruns/evidencebeforecleanup.

### Task 4: Tailscale composition
Ownership: tailscale publication/ingress tasks, ES/multinode/cluster port metadata, tests. Implementtailnet_port frontend/backend separation and driftcorrectness with1bretained, separateFleetoutput/enrollment contracts.

### Task 5: Durable telemetry
Ownership: new telemetry runtime/package and tests. DurableSQLitelogadmission, independentpersistentobligations, retries, canonicalreadback, quotas/archive, nativequeueinterfaces, authenticatedprivateingress, selectedsinkadapters.

### Task 6: Database infrastructure
Ownership: newPostgreSQLplatformrole/config/migrations/tests and vectoringestionschema/reset. Renderdual/sharedHA, namespaces/roles/TLS, selectedpubs/subs, slotreadiness, ownerlocalproxies, schema/backup/fencingcontracts. No livepromotionuntilcoordinatedgate.

### Task 7: MAIN topology and rootless integration
Ownership: sharedresolver, installer, topologymanifest, siteorchestration, newrootlessandQEMU lifecycle. Implementselectors, consumerprofile, ownership/resources/routesclosure, preflight/render/bootstrap/deploy/readback/scopedteardown. ExactUUIDs/images/state recorded; protectedhostsourcespre-read.

### Task 8: HertzBeat source and deployment integration
Ownership: isolatedHertzBeatworktree plusLMEnewHBrole/config. Qualify1.9artifact, SSH/HTTPS/JMX security, reconcilemonitors, samples/lifecycleoutboxes, schema-onlycommand, nativeESmetricsandselectedtypedevents. No secrets/advisorpayloadsdumped.

### Task 9: Malcolm and UI integration
Ownership: isolatedMalcolmworktree, LMEidentityproxy and UIafterTLS handoff. Strict5045mTLS, stablehostreadback, guest-onlyZeek/Suricata/Arkimeproof; capabilityauth/UIstates/AIroutes.

### Task 10: Review and full lab acceptance
SixtelemetryxDBcombinations plusexistingdeploymentconnectivity especiallymultinode+tailscale. Realjournal/application/securitymarkers on6Linuxnodesreadback120s; nativevalues3intervals; completeHBlifecycle; noexcludedmirrors. Syntheticnegativeguardsmustnotcountasoperationalpass.
DBwitnessoutsidefaileddomain recordsacknowledgedtransactionIDs; zeromissingtested1domainfailure; ambiguousoutcomesreconciled.90s onlysurvivingapplicationclientDBoperationwhensafequorum/fenceexists; singletonappsarenotHA.
Replay1GiBaggregatebacklog whileeachsixsourcescontinues32KiB/s; deterministicrecordcountmix50%1KiB,40%4KiB,10%19KiB finaladjustment. Allrestorationwatermarkobligationsverified300s. Full4GiB/node saturationseparatequalification measuredrecovery, nouniversal300spromise. Testrestart/partialreject/indexdelay/queuefull/retention/rotation/identity/sourcefailure/reboot/fresh-overlays/restore.
Eachcheck recordsrequired/applicable/executed/status/evidenceandallrevisiondigests. Requiredunexecuted/stale/transportonlyneverpasses. Configured12reviewers+discourse andactualCursor/OpenCoderesponsesrequired; preservehistoricreceiptsasrevisionbound. Retainfailedstateandunresolvedpayloads; revokeonlysessionownedcredswithoutdestroyingrecovery; exactresourcecleanup; no commits/push.
