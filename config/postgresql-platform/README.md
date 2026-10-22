# PostgreSQL platform

`python3 -m scripts.postgresql_platform render --config NODE.json --output DIR`
is an offline renderer. `resolved_role_config(topology, node, credential_material)`
derives that input and the Ansible owner map from the resolved inventory and
credential file grants; it does not open credential files. It rejects missing
images, observed identities, required grants, backup policy and physical slot
guards. No floating image is supplied. Build the provided Containerfile with the
source archives identified in artifacts.json and a qualified Debian 13 base;
the artifact pipeline must record and distribute the resulting immutable image.

The resolved `database` object must include:

```json
{
  "backup": {
    "repository_host": "off-guest-backup.example.test",
    "repository_path": "/backup/lme",
    "retention_full": 2
  },
  "slot_guard_standby": {
    "hertzbeat": {"graph": "trixie", "trixie": "graph", "silmaril": "trixie"},
    "vector": {"graph": "trixie", "trixie": "graph", "silmaril": "graph"}
  }
}
```

These are format examples, not deployment identities or measured eligibility.
The guardian calls `lme_lab.postgresql_reconcile.reconcile_once` every ten seconds
to reconcile each guard with the DCS-authorized synchronous physical standby. A single guarded slot prevents logical output from running
ahead of that standby without requiring both standbys to acknowledge every
logical transaction. Other candidates still require explicit synchronized slot
readback before admission. Non-initial members start with `nofailover=true`;
the reconciler clears it only after current lineage, WAL and synchronized logical
slot readback. Its authority compare-and-set binds the leader lease, DCS synchronous
member, consumed admission and coordinated writer ledger. Promotion issue and
consume both call `qualify_promotion` again, including current subscriber main and
completed table-sync slots. Missing or expired eligibility leaves promotion unavailable.

## Ordered deployment

Invoke role `postgresql_platform` with `postgresql_platform_phase` in this order:

1. `configure`: validate and stage owner-scoped files and Quadlets. No starts.
2. `etcd`: start the three existing rootless etcd owners.
3. `bootstrap` starts Patroni. Its `gate-live --action bootstrap` initializer
   requests a real leased bootstrap reservation and signed permit from the
   external guardian, checks its observed QEMU generation and consumes the permit
   before initdb. Only the configured initial member may initialize. No static
   context/receipt files are provisioned.
4. `schema`: initialize roles/passwords/databases, vectors and sanitized status.
   Passwords come only from the repaired `/run/secrets/role-passwords.json`
   contract and are supplied to psql on stdin without logging captured output.
5. Run HertzBeat's qualified schema-only image:
   `java -jar /opt/hertzbeat/apache-hertzbeat-1.9.0.jar --schema-only --spring.config.additional-location=file:/opt/hertzbeat/config/application.yml`.
   Hibernate precedes Flyway; the normal application uses validate and disables
   Flyway. Use its separately mounted migration principal.
6. `replication`: all authoritative publications, then all subscriptions. The
   play must use linear strategy across all members; serial=1 is incompatible
   with this cross-node barrier. Native HertzBeat subscriber DDL is exported from
   source catalog types/PK/nullability. No native LiteLLM tables are guessed.
7. Install the physical backup repository using the separate role below, then
   `backup`: create each initial primary's stanza, check WAL archiving and take a
   full physical backup. This is an initial-deployment stage; it refuses a member
   that has become a standby.
8. `ready`: read actual primary TLS/synchronous state, exact publication columns
   and operations, complete initial copies, subscription options, physical
   standby state and failover slots. Nonzero means applications stay stopped.

The root orchestrator owns admission and app activation. The role does not
schedule normal applications. Every source owner needs its `pg_service.conf`
with `<domain>_admin`, `<db>_source`, imported `<db>_replica`, and
`<domain>_candidate_<node>` sections. The credential provider generates these
with matching CA/client cert/passfile references. CLI service connections force
`sslmode=verify-full`. Publication initial-copy credentials use origin-domain
`replication-<db>.crt/key` and `replication-<db>-ca.crt`.

Domain users own `/data/<owner>/{config,secrets,volumes}/postgresql`.
Quadlets live in `/home/<owner>/.config/containers/systemd` and use that owner's
rootless network. Only the observed guest Tailscale IP publishes physical ports
5433/5434, Patroni 8008/8009 and etcd 2379/2380. Each client owner receives
`pg-hertzbeat-rw`/`pg-vector-rw` aliases on its own network. These proxies pass TLS
bytes through and refresh signed DCS/fencing authority every second; authority
loss, expiry or leader change closes existing sessions. Certificates include
the appropriate endpoint alias. Proxy signatures are not a replacement for
server certificate verification. Both aliases exist under shared HA and select
the same shared-domain writer. Route requests bind the requesting guest `node`
and actual rootless `owner`; signed responses preserve them and identify the
selected backend separately as `primary_node`.

## Guardian contract

Rendered Patroni bootstrap and pre_promote commands use `gate-live --config
FILE --domain DOMAIN --action bootstrap|promote --public-key FILE
--authority-socket SOCKET`. The role factory requires the observed canonical
QEMU generation in each host record. The client sends only operation=authorize,
run/domain/node/generation/action and a fresh challenge. The guardian derives
nonce, complete writer ledger and current leased authority; it fences prior
writers and returns a signed identity-bound context plus receipt. The client
checks outer Ed25519 signature, all request bindings and 30-second freshness,
then invokes the inner receipt and consume protocol below. Authorize transport
is bounded to 180 seconds for fencing; consume transport allows 15 seconds for
actual candidate/slot requalification while its signed result still must be
fresh within five seconds. Failure at any step prevents initdb or promotion.
The legacy explicit-file gate remains a low-level inspection/invocation surface;
it is not used by the rendered runtime hooks.

`gate --context FILE --receipt FILE --public-key FILE --authority-socket SOCKET`
accepts `{payload: {...}, signature: "BASE64"}`. Sign canonical UTF-8 JSON using
`json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False)`
and detached Ed25519. Bind `run_id`, `domain`,
`candidate:{node,qemu_generation}`, `authority:{epoch,lease}`, `action`
(`bootstrap|promote|rejoin`), `request_nonce`, `issued_at`, `expires_at`,
`quarantined_candidate:true`, and `prior_writers` entries containing exact
node/generation plus `stopped:true,restart_inhibited:true`. Validity is at most
60 seconds. An empty writer ledger requires explicit bootstrap initial-generation
permission in both context and receipt. Rejoin still requires independently
verified replica rebuild evidence.

After signature/binding checks, the gate sends newline-delimited JSON to the
guardian Unix socket: `{operation:"consume",receipt_sha256,challenge,context}`.
It requires a signed response with exact bindings, challenge and receipt digest,
`consumed:true`, `quorum:true`, `leader_authorized:true`, and validity at most five
seconds. The lifecycle guardian owns real etcd leader/reservation verification
and nonce/epoch compare-and-set. Static signed booleans cannot satisfy this
challenge exchange. Initial bootstrap uses a separate leased reservation because
Patroni has no leader key until after initialization.

The guardian creates root-owned persistent inhibitor
`/var/lib/lme-fencing/inhibit/<run>/<domain>/<node>` before stopping the exact
domain service. Quadlet ExecCondition prevents restart while that marker exists.
Independent hypervisor fencing may target only the recorded QEMU generation.
An unavailable guardian or missing proof leaves writes unavailable.

## Physical repository

`lme_lab.postgresql_backup.resolved_backup_config(topology, credential_material)`
returns `postgresql_backup_config` for role `postgresql_backup`, invoked only on
physical trixie through the root orchestrator. It requires actual observed
Tailscale IPv4, the generated physical `backup_material` grants, the qualified
local image archive and policy `/home/lme-backups/<run>`, retention two fulls.
It does not run PostgreSQL on the physical machine.

The role verifies identity, paths, subordinate UID ranges, free space and existing
run ownership before creating the dedicated `lmebackup` identity and an exact
100GiB file-backed ext4 repository. Its persistent mount is root-controlled;
existing unrecognized images or contents fail closed. No host partitions or
sysctl values change. The rootless pgBackRest TLS server publishes only the
observed physical IP on 8432, admits exact per-domain/member certificate CNs,
and has 256MiB memory, one CPU and 64-task caps. Prerequisite binaries must already
exist; the preflight refuses a missing tool. The repository subtree is
`<root>/<run>/<domain>` inside the bounded filesystem, matching the database
client renderer's explicit run/domain suffix.

## Recovery and verification

`backup --domain DOMAIN --type full` runs pgBackRest check then backup.
`restore --domain DOMAIN --data-dir /tmp/lme-pg-restore-UNIQUE --target-time TIME`
restores only into a separate empty directory, disables archiving there, and
requests shutdown at the recovery target. It never starts or promotes that tree.
The remote TLS repository/server, archive retention, isolated recovery startup,
checksums and requested RPO/RTO must be independently verified before recovery
is called qualified. Creating a backup or rendered configuration is insufficient.

`schema-export --service NAME --database hertzbeat` reads catalog metadata only.
`slots-check --subscriber-service NAME --candidate-service NAME` includes
completed table-sync slots and rejects absent/invalid/temporary/unsynced slots.
`provision --config FILE --domain DOMAIN --phase ready` emits the actual readback
values; it does not mutate the database or authorize promotion.

Offline tests:
`python3 -m unittest discover -s testing/tests/unit -p 'test_postgresql_platform*.py'`.
SQL tests require explicitly set `LME_PG17_TEST_PSQL` and a task-owned
`LME_PG17_TEST_SOCKET=/tmp/lme-...`; they use only uniquely named test databases.

Reference behavior follows PostgreSQL 17
[logical failover slot requirements](https://www.postgresql.org/docs/17/logical-replication-failover.html),
[subscription options](https://www.postgresql.org/docs/17/sql-createsubscription.html),
Patroni's [replication modes](https://patroni.readthedocs.io/en/latest/replication_modes.html),
and pgBackRest's [configuration reference](https://pgbackrest.org/configuration.html).
The explicit `pg1-socket-path=/tmp` matches Patroni's local socket regardless of
the distribution libpq default.

## Bounded deployed SQL acceptance probes

`acceptance --config FILE --domain DOMAIN --probe PROBE --generation N` emits
raw evidence, not a pass assertion. It runs inside the domain owner's container
with the existing `PGSERVICEFILE=/run/secrets/pg_service.conf` mount. A zero CLI
exit means evidence was emitted; the acceptance evaluator must inspect every
query's return code, SQLSTATE, session identity, TLS state and returned rows.
Timeouts and failed statements retain their output and cannot count as passing.

- `import-denial`: actual `lme_replica_reader` login through each fixed
  `<db>_replica_reader` verify-full service. Every imported table receives
  `UPDATE ... WHERE false` inside a rolled-back transaction, so an unexpected
  privilege never changes rows. Expected SQLSTATE is 42501. SQLSTATE 00000,
  failed connection or missing identity fails this check. Shared HA has no imported tables; it instead queries all three source databases
  for actual publication, subscription and logical-slot rows under
  `observation_kind=logical-topology-catalog`. Empty catalog results plus valid
  query/session/TLS evidence prove the expected topology absence; they do not
  claim that a privilege-denial attempt occurred.
- `vector-seed`: only the authoritative vector/shared domain; commits three
  synthetic `lme_vector_probe` rows for e1, normalized(e1+e2), e2. UUIDs derive
  from run, generation and vector label, with fixture_version=1. It never reads
  or writes the corpus table. Successful statement and commit SQLSTATE plus
  actual returned rows are required before later readback.
- `vector-baseline`: source `lme_vectors_reader` or imported
  `lme_vectors_replica_reader` login; reads those exact three run/generation UUIDs,
  actual vectors and cosine distances with indexscan and bitmapscan disabled.
  The evaluator checks exact vectors, UUID ordering, generation, fixture version,
  TLS and expected runtime role on both authoritative and imported domains.
- `vector-cleanup`: separate explicit source-only deletion of those exact three
  run/generation/version rows. It is never automatic after a failed probe.

Evidence includes run/domain/node/source/probe/generation bindings and each fixed
query's text, stdout, stderr, SQLSTATE, commit SQLSTATE, current/session user,
actual database/server/TLS identity and rows. Only synthetic fixture contents and
fixed privilege-probe SQL can appear in captured failed-query output. Passwords
stay in protected libpq files; PGPASSWORD is removed from the child environment.

## Exact backup retirement

The physical backup role installs a root-owned `config/retire.py` under the exact
run directory and records its unit, immutable image and Quadlet hash in
`runtime-identity.json`. `lme_lab.postgresql_backup.retire_backup(topology,
credential_material, physical_runner, retention_reason=...)` invokes only that
helper over the resolved physical-trixie SSH target. It verifies the current
container's image, labels and exact mount set before any stop, writes and fsyncs
a root-owned persistent `retired.json` inhibitor, stops and masks only the
recorded user service, then stops any remaining exact container ID. It requires
native masked/inactive systemd readback, no unrecorded same-name timer, and a
stopped or absent container. The controller independently validates this proof.

No archive, certificate, configuration, backing image or filesystem is deleted.
The result explicitly retains six named resources with their owners and the
caller's reason. The existing mount may remain available for recovery; it has
no active backup service authority. The role's preflight rejects a retired run,
and the Quadlet's root-controlled inhibitor prevents ordinary restart across
reboot. Missing records, changed runtime identity, an unexpected timer or an
uncertain native stop result fail closed. The helper is code-tested only until
executed as part of the authorized lab cleanup.
