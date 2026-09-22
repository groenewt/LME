# Executable native lifecycle acceptance

Controller entrypoint:

```python
from lme_lab.hertzbeat_lifecycle_acceptance import run
run(probes, checks, evidence_directory)
```

The acceptance coordinator invokes this after normal collection and native
monitor reconciliation. It modifies the four existing required check records
using `lme_lab.verify._finish` and writes one JSON evidence file per check.
It consumes the resolved `role_configs.trixie.hertzbeat_platform` variables,
the exact `guest:trixie` source owner, pinned guest SSH access, and the resolved
destination list. It accepts no uploaded PASS receipt or replacement result.

Remote operations use the installed module's stdin JSON CLI as the HertzBeat
owner or source owner. Native API calls use HTTPS on the actual trixie FQDN at
14457, system CA verification, redirects disabled, and the private existing
`admin-authorization` file. The module does not print or copy credentials.

## What each check executes

- `hertzbeat.history_failure_sample_capture`: observes an active Greptime unit,
  stops the exact guest/rootless unit through `managed_action`, verifies it is
  inactive, and reads actual pending/accepted HertzBeat native outbox envelopes.
  At least three distinct original sample times, separated by at least 27
  seconds, must occur during the outage in the same metric/dimension series.
  File creation time or repeated copies of one sample cannot satisfy the check.
  Greptime is started and its active state is checked in `finally`.
- `hertzbeat.lifecycle_creation_update_recovery`: sends a unique run-marked
  alert through `/api/alerts/report/default`, reads the native single and group
  alert APIs, requires repeat updates to retain the native ID and increase
  `triggerTimes`, then sends recovery and requires the original ID to resolve.
  Creation and recovery decisions must appear as immutable canonical events.
- `hertzbeat.lifecycle_silence_inhibition_manual_notification`: creates exact
  run-scoped native silence and inhibition rules, requires persisted suppression
  decisions, performs a native group status update, then creates a native
  webhook receiver, template and matching rule. Notification selection, queue
  admission, handler completion, and the actual received body must agree with
  the native alert. Run-created rules, template and receiver are deleted in
  `finally`; alert state and evidence remain available for review.
- `hertzbeat.lifecycle_transaction_crashes`: creates a committed alert and
  arms an exact-subject `PRE_COMMIT` barrier, submits a native manual update,
  observes the pending PostgreSQL write and transaction identity, then kills the
  actual container. The original state must remain after restart and the
  uncommitted event must be absent from both outbox and delivery spool. It then
  arms `AFTER_LOCAL_FSYNC`, performs another native update, observes actual
  durable admission while the committed outbox still retains the immutable
  event, kills the container, and requires an actual replay acknowledgement
  from the new JVM, identical source content, and eventual outbox retirement.

The fault controller is
`lme_lab.probes.operations.managed_action(probes, 'trixie', service, operation,
unit=...)`, with `service='greptimedb', unit='greptime.service'` or
`service='hertzbeat', unit='hertzbeat.service'`. It requires
`acceptance.operations.guest_faults_authorized=True`, resolves actual runtime
owner/UID/unit placement, and validates the protected guest run marker and DMI
UUID before acting. No physical-host or arbitrary-unit fault is exposed here.

## Native event evidence

The source owner's `/etc/lme-sources/runtime.json` identifies its actual SQLite
admission store. The probe opens it read-only, checks the stored `source_node`,
and selects only the relevant native subject UUIDs and invocation time window.
It verifies canonical bytes against the stored digest before using an event.
Subject UUIDs match the patched Java `UUID.nameUUIDFromBytes` mapping over
`guest:trixie:<single|group>:<persisted numeric ID>`.

These records are the delivery spool's immutable post-handoff custody copies.
The crash scenarios separately query the actual PostgreSQL lifecycle outbox
through the authenticated lab diagnostic interface before and after the fault.
For the lifecycle and reduction checks, each captured event is queried through
the actual configured destination adapters. Every returned canonical body must
equal the source body; a copied digest or transport acknowledgement is rejected.
History-outage capture checks original source retention, not sink delivery;
the independent native metrics acceptance checks establish sink content.

## Isolated notification receiver

The controller compiles the reviewed `WEBHOOK_SOURCE` constant with JDK tools
using Java 21 class compatibility, which is accepted by the pinned JRE 25
runtime. No image rebuild or guest compiler is required. It stages the class
under the owner-private mounted HertzBeat data directory and uses owner Podman
to execute it inside the existing `lme-hertzbeat` container. Evidence records
the source hash, class hash and actual container ID.

The fixture binds only `127.0.0.1:19470` **inside the HertzBeat pod**. Its URL
contains the fresh probe UUID; it accepts only a bounded POST containing that
UUID, forces the received body to disk before responding, and exits after the
first receipt or a 90-second maximum wait. The helper uses `-Xmx24m` and a 32 MiB
metaspace ceiling; heap, native overhead and compiler-free execution remain
charged to the existing HertzBeat container limit. No service memory limit is
increased. Insufficient headroom produces a failed probe.

Before alert injection, any existing enabled notification rule causes the
scenario to stop. The test creates only its localhost receiver and UUID-scoped
rule, avoiding external or human recipients. Silence uses `matchAll=false` with
only the unique probe label: the native API's `matchAll=true` means global
silencing and must never be used for this test.

## Authenticated lab-only transaction barriers

The production default is `lme.lifecycle.acceptance.enabled=false`. The resolved
topology must explicitly set `hertzbeat_acceptance_faults: true` for the controlled
lab invocation, binding `lme.lifecycle.acceptance.run-id` to its actual run ID.
Only the authenticated `admin` role can use `/api/lab/lifecycle/**`; there is no
authentication allowlist bypass. Disabled endpoints, a missing barrier, a wrong
run or nonce, and an unobserved transaction remain failed checks.

The native API contract uses normal HertzBeat `{code: 0, data: ...}` responses:

- `POST /api/lab/lifecycle/arm`: `{run_id, nonce, phase, subject_id, decision,
  timeout_seconds}`. Phase is `PRE_COMMIT` or `AFTER_LOCAL_FSYNC`. The former
  selects one exact subject and `MANUAL_STATE_CHANGED` decision. The maximum
  barrier duration is 90 seconds.
- `GET /api/lab/lifecycle/status?run_id=...&nonce=...`: actual JVM `boot_id`,
  barrier state, transaction identity, native event rows, and bounded recent
  validated local-fsync acknowledgement observations. The pre-commit barrier
  also reads `uncommitted_status` through the actual transaction connection.
- `GET /api/lab/lifecycle/outbox?run_id=...&nonce=...&event_id=...` (or
  `subject_id=...`): bounded, committed native outbox rows from an independent
  database read, without taking the lifecycle quota lock.
- `POST /api/lab/lifecycle/release`: `{run_id, nonce}` releases that exact arm.

`PRE_COMMIT` must occur in Spring's transaction `beforeCommit` callback, after
the native manual status SQL and outbox insertion have executed. Pausing earlier
inside the projection would fail to establish a pending state write. The
controller requires PostgreSQL product identity, positive backend PID and
transaction ID, an actual uncommitted `acknowledged` status, and an independently
visible old `firing` status before killing the container. It then independently
checks native state, outbox absence and source-spool absence after restart.

`AFTER_LOCAL_FSYNC` pauses only after the sender validates the real HTTP 202
`ack=local_fsync` receipt and before local queue handoff/removal. This simulates
loss of the acknowledgement at the sender's durable bookkeeping boundary. The
event must already exist in the real source SQLite store and still exist in the
PostgreSQL outbox. After restart, the observer's new `boot_id` and actual receipt
must show `replayed > 0` for the same event, followed by outbox retirement and
unchanged source content. Old observations, inserted-only acknowledgements,
changed payloads and digest-only claims cannot satisfy this check.

These barriers expose bounded lab diagnostics and affect the actual transaction
or sender path; they are not uploaded receipts or randomized timing guesses.
Barriers are released in failure cleanup, with the server's bounded timeout as
a fallback. A native API failure or unavailable barrier preserves partial
evidence and fails the complete requirement.

## Retirement quiescence

`quiesce_for_retirement(probes, evidence_directory)` returns a private, verified
receipt for the HertzBeat native metric pipeline and alarm lifecycle outbox.
It validates every desired
monitor's actual persisted ID, run/service/revision labels, app, host, name and
interval against the bound runtime inventory before changing state. Native
status `0` means paused; statuses `1` and `2` are active monitoring states.
Only initially active monitors receive `DELETE /api/monitors/manage?ids=...`.
The native API also pauses bound children. The executor reads actual database
bindings first and rejects any transition reaching an unowned or initially
paused child.

The authenticated diagnostic endpoint is
`GET /api/native-metrics/drain?run_id=...&monitor_ids=...`. Its observations must
contain the exact native roster and the same JVM `boot_id`. Retirement requires
two complete, drained observations at least one second apart, all monitors
paused, and strict integer zero for every counter: scheduled and temporary
jobs, collector running/queued/dispatch/tracked work, storage dispatcher work,
alert/storage queues, metric pipeline ownership, native pending/accepted files,
and native bytes. Two additional counters, `lifecycle_pending_records` and
`lifecycle_pending_bytes`, come from an actual read-only PostgreSQL
`hzb_lifecycle_outbox` count and payload-byte sum. Both must also be zero; an
event not yet handed to source admission cannot disappear behind empty metric
queues. A missing component or failed database query, a JVM restart, or an empty queue with
in-flight work cannot pass. Polling is bounded to 300 seconds.

Every attempt writes immutable, owner-only, fsynced JSON before mutations and
after native readbacks. The returned receipt has `run_id`,
`scope: hertzbeat_native_and_lifecycle`, lower-case `status: pass|fail`, `quiesced`,
`receipt_verified`, and an evidence reference containing an absolute path and
SHA-256. `native_pending: 0` is present only on successful quiescence. Initial
monitor states, attempted and confirmed pauses, raw diagnostics, and observed
transitions are retained in the referenced document. A failure returns its
recovery receipt; it does not authorize retirement.

`resume_after_retirement_failure(probes, receipt)` verifies those private file
bytes, the current run inventory, and fresh native identities and bindings. It
resumes only confirmed pauses from this attempt with the native
`GET /api/monitors/manage?ids=...` action, and verifies resulting native state.
Initially paused monitors remain paused. Ambiguous unconfirmed pauses remain
an explicit recovery failure. The caller must retain the run if quiescence or
recovery fails.

This receipt covers the fifteen native metric and lifecycle outbox counters
above. Generic OTLP producer queues and six-source destination obligations
require separate retirement evidence before a whole run can be removed.

## Local verification

```sh
python3 -m unittest discover -s tests -p test_hertzbeat_lifecycle_acceptance.py -v
```

Twenty-four tests pass, including a real temporary SQLite store, an actual synthetic
TLS API server, and the compiled bounded Java receiver. Tests reject absent
committed events, digest-only destination results, incomplete API pagination,
wrong source identity, public spool files, stale/repeated sample times, and
unobservable crash windows, missing pending database writes, old JVM receipts,
inserted-only acknowledgements and changed replay payloads. Retirement tests
cover binding expansion, partial pause recovery, unchanged initially paused
monitors, private receipt integrity, changed ownership, missing/nonzero counters,
JVM restart during drain, and unhanded lifecycle records despite an empty metric
pipeline. These tests qualify
the executors, not a live lab; the Java barrier implementation has separate
transaction, transport and authorization tests.
