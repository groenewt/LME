# HertzBeat platform integration

The source anchor is public Apache tag `v1.9.0`, commit
`a85bd46c18d33130298f0e223bd84ea6e29a17de`. Its internal Maven reactor coordinate
is `2.0-SNAPSHOT`, while `hzb.version=1.9.0` names the distribution. It requires
Java 25 and Spring Boot 4.0.3. The source and final OCI digest must both be recorded;
an upstream unpatched image does not satisfy this integration.

`ansible/roles/hertzbeat_platform` takes one `hertzbeat_platform` object from the
resolved inventory. It renders rootless user Quadlets. The default `hertzbeat_platform_phase=render` only renders. Explicit `schema` runs
the one-shot initializer; explicit `application` starts Greptime and then HertzBeat. Supply a digest-pinned patched
image, service user/UID/home/data_home, `database.url` with PostgreSQL `sslmode=verify-full`,
`database.username`, runtime mTLS directory, separate `schema_database` migrator
URL/username/secret_directory, `secret_directory`, public-CA-only PKCS12 `truststore_file`,
preverified `known_hosts_file`, `native_export` and `lifecycle` objects. Each
PostgreSQL URL must also reference its mounted CA (for example
`sslrootcert=/run/secrets/hertzbeat/pg-ca.pem`). Use a certificate-only truststore
with no password containing the required private CAs AND system public roots for Tailscale Serve.

Runtime secret directory entries: `spring.datasource.password`, service-specific
Spring auth secrets, `native-export-authorization` (full authorization header),
`lifecycle-token` (delivery bearer token), `greptime-users`,
`warehouse.store.greptime.runtime-password`, strong `sureness.yml`, and PostgreSQL CA. The role never
reads or generates their values. Existing rootless service user/linger/network
and verified producers remain prerequisites owned by MAIN.

Initialization order:

1. Build and qualify patched source, then assemble the Java25 image from
   `Containerfile` with a resolved `JAVA_IMAGE` digest and extracted distribution.
2. Render inventory and runtime files. Run the user unit `hertzbeat-schema.service`
   once against the authoritative write proxy. It invokes
   `java -jar /opt/hertzbeat/apache-hertzbeat-1.9.0.jar --schema-only
   --spring.config.additional-location=file:/opt/hertzbeat/config/schema-application.yml`.
   Only the migrator mTLS/password bundle is mounted in this process. Hibernate creates mapped entities before the release Flyway migrations, then
   seeds lifecycle quota; no application component scan, collectors, scheduler,
   HTTP listener or application repository runs. Success creates `schema-<image-sha256>.ready`, bound to that immutable image.
3. MAIN's database catalog exporter qualifies native selected columns and PKs,
   produces the subscriber schema, and installs publications/subscriptions before
   normal service activation. `qualify-native-schema.sql` is an additional
   non-vacuous read-only type/PK assertion. All ten requested columns exist in
   this release's entity source; actual PostgreSQL catalog qualification is required.
4. Start the normal user unit. The normal Java entrypoint enforces
   `ddl-auto=validate` and Flyway disabled, including conflicting CLI flags.
5. Render an inventory-owned monitor desired JSON and run the installed
   `reconcile_monitors.py --url https://<verified-api> --ca-file <ca>
   --token-file <private-token> --desired-file <private-json>` to preview; append
   `--apply` to mutate. API endpoints are actual release `/api/monitors/{app}`
   and `/api/monitor` POST/PUT. No unmanaged deletion occurs. Each record has
   opaque UUID `service_id`, UUID `revision`, and native `definition` with
   `monitor` and `params`. Credential params may reference private `secret_file`;
   revisions explicitly signal credential rotation because the API masks secrets.

Native metrics use `native_export.{enabled,endpoint,sinks,host_id,host_name}` and
optional `allowed_labels`. Endpoint is a fixed HTTPS `/v1/metrics` gateway route
persisted per admission; this integration fixes the native export sink to `elastic`. Native HB history
is stored directly in Greptime; sending these samples back through HB ingress is prohibited. The exporter
copies Arrow values before history dispatch, admits to a fsynced bounded queue,
and retains accepted records pending verified destination readback. Gateway
transport acceptance is never called destination verification. Provision the native queue
256MiB logical/512MiB project quota at `/data/lme-telemetry/<run>/volume/hertzbeat-native`,
plus the shared filesystem floor2GiB separately from the delivery spool.

Typed alarm events use `lifecycle.{enabled,source_node,admission_url}`; the URL is
HTTPS `/v1/logs`. Admission joins the native state transaction, includes explicit
suppression and notification decisions, and consumes bounded database quota.
TLS uses CA plus hostname verification. Notifications and metrics do not export
raw label fingerprints as event identities.

JVM monitors expose `ssl` in the actual template and all five JMX metric blocks.
The supplied Java security property installs a hostname-verifying default SSL
factory used by the registry and returned RMI stubs. Targets must use JMX TLS
for registry and RMI endpoints plus authentication; plaintext stubs fail closed.
SSH trusts only the preverified known-hosts file. New hosts require explicit
trusted key provisioning outside collection.

Local tests: `python3 -m unittest discover -s config/hertzbeat-platform -p 'test_*.py'`.
No runtime deployment or credential distribution is implied by these artifacts.

`lme_hertzbeat.resolved_role_config(topology,node,credential_material)` derives all
role variables from resolved ownership, runtime UID mapping, qualified artifact
records and file grants. It requires the declared Serve endpoint map (14418 native
ES metrics, 14469 lifecycle logs), never guessed HTTPS on a plaintext receiver port.
Greptime 1.1.3 and HB share the isolated owner network/pod. Greptime exposes only
HTTP to host loopback; gRPC remains pod-loopback. PostgreSQL traffic uses the
owner-local `pg-hertzbeat-rw` proxy with end-to-end mTLS/verify-full. Greptime's
1GiB cgroup uses explicit conservative cache/query/write-buffer limits and synced
local WAL; runtime capacity acceptance remains required.

The tested distribution preserves original Greptime sample timestamps to
millisecond precision. H2 has a follow-up V190.1 migration aligning four legacy
CLOB columns with the native Hibernate text mappings; original release migration
checksums remain intact. PostgreSQL migration files remain unchanged.

The native probe roster also requires `credential_material.hertzbeat_monitors`:
`ssh`, `rest`, and `jmx` lists bound to canonical source IDs and exact inventory
FQDNs, plus granted `known_hosts_file` and `jmx_client_options_file`. Every SSH
source has a dedicated key and opaque service tokens. The remote forced command
maps each token to one approved unit and returns numeric active state; no broad
Linux template is activated. The three packaged custom templates are
`lme-service-ssh`, `lme-elasticsearch-rest`, and `lme-elasticsearch-jmx`. REST reads
only cluster health; JMX reads thread and garbage-collection counters with GC bean
identity preserved. JMX client keys/passwords come through a private Java argument
file, never public unit text. Credentials and remote forced-command installation
remain the credential/runtime producer's responsibility.

In every profile, the role runs `lme_sink_proxy` on
owner-local loopback1457 behind the registered verified HTTPS14458 frontend. It
checks each bearer principal's exact source and operation, injects the private
backend administrator credential, and permits bounded typed routes. Operators
use the separate protected administration frontend14457. The gateway and native receipt worker each reserve
64MiB inside the aggregate HertzBeat memory allocation; schema/application use
the remaining896MiB and never run concurrently. An elastic-only profile retains source-scoped read operations for native history and excluded-log proof; its policy has no HertzBeat write grants. See `config/sink-proxy/README.md` for precise read contracts.

Multi-source native export reads private `native-source-endpoints.json` and
`native-source-authorization.json` maps keyed by canonical `physical:<node>` /
`guest:<node>`. Each entry selects that source's verified HTTPS14418 endpoint and
own bridge authorization file. Endpoint and authorization-file references are
fixed in the outbox at admission; secret values are not written into queue
records. Missing or conflicting source identities fail admission/send and remain
observable failures rather than falling back to a broader shared credential.

Native history readback uses the same source gateway's typed
`POST /_lme/metrics` route with `{table,columns,start,end,labels}`. The public role
configuration allows only the five packaged native table layouts returned by
`native_query_tables()`. The gateway generates bounded SQL, injects the authenticated
source predicate, requires `host.name` and the timestamp column, and checks returned
source identities. The private policy supplies a separate Greptime credential;
callers never receive it or submit SQL. `GET /_lme/backend-authentication` proves
backend credentials through fixed HB `/api/summary` and Greptime `SELECT 1` requests,
independently of whether native metric/log tables have received their first rows.


The role also installs `lme_telemetry` under the HertzBeat owner and activates
`hertzbeat-native-receipts.timer`. Its non-overlapping one-shot service runs the
`verify-native-metrics` CLI every15 seconds after completion, with a120-second
process limit and64MiB memory cap. It reads the native outbox under the same UID,
uses source-specific read-only Elasticsearch credentials, and writes fsynced
content-bearing receipts in `readbacks/`; the Java exporter validates those
receipts before retirement. No manual background task or cross-owner queue access
is required. The pure factory consumes `hertzbeat_native_readback[source_id]`
origin/index/CA/auth-file descriptors and requires matching HertzBeat-owner grants.
The total service budget is896MiB HB/schema +64MiB sink gateway +64MiB receipt
worker. Actual JVM startup and six-source load measurements remain acceptance gates.


Qualified generic OTLP query tables are supplied before role resolution through
`topology.generic_metric_bindings`, separately from native collector tables. Their
source/time/value fields are `host_name`, `greptime_timestamp` and `greptime_value`.
Required point metadata columns are `lme_metric_unit`, `lme_metric_type`, and
`lme_metric_temporality`; the source producer must attach these before export.
The factory accepts only explicit qualified `lme_host_`, `tailscaled_`, or
`otelcol_` tables and their bounded column lists. It never accepts caller SQL.

Physical sources consume their declared OpenSSH port (22 or the isolated2223
listener); guest sources use22. Tailscale SSH is not used as a substitute for the
forced-command OpenSSH account. Trusted known-host entries must match the selected
hostname and port, including `[fqdn]:2223` for nonstandard listeners. Non-secret
parameter changes are included in the opaque reconciliation revision.
