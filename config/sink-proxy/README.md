# Owner-local source-scoped sink gateway

`lme_sink_proxy` uses Python 3.10+ and only the standard library. It binds literal
`127.0.0.1`. Verified external Serve listeners terminate client TLS: HertzBeat
`:14458` forwards to `127.0.0.1:1457`; Malcolm `:14459` forwards to
`127.0.0.1:1459`; Wazuh `:14460` forwards to `127.0.0.1:1460`.
The gateway does not configure Serve, provision credentials,
change native product accounts, or expose an administrative proxy.

Run from an installation directory containing `lme_sink_proxy`:

```sh
python3 -m lme_sink_proxy check-config --config /etc/lme-sink-proxy/config.json
python3 -m lme_sink_proxy run --config /etc/lme-sink-proxy/config.json
```

The public HertzBeat configuration is:

```json
{
  "mode": "hertzbeat",
  "listen_host": "127.0.0.1",
  "listen_port": 1457,
  "backend_host": "127.0.0.1",
  "backend_port": 1157,
  "policy_file": "/run/secrets/sink-policy.json",
  "max_body_bytes": 1048576,
  "max_response_bytes": 1048576,
  "max_connections": 2,
  "timeout_seconds": 10
}
```

For Malcolm use `mode: "malcolm"`, `listen_port: 1459`, `backend_port: 8445`, and
`backend_tls_server_name` equal to the resolved guest FQDN on its native HTTPS
certificate. Set `backend_ca_file` to the native CA bundle path when system trust
is insufficient. The TCP connection remains on literal loopback, with verified
TLS SNI and the HTTP Host header set to that FQDN. There is no TLS verification
bypass. HertzBeat's backend uses HTTP inside the owner boundary; the external
client connection uses verified Serve TLS.

The controller creates the private policy. The gateway requires a regular,
non-symlink file owned by its effective UID, with no group/other permissions.
Policy schema (angle-bracket strings describe required generated values):

```json
{
  "backend_admin": {
    "username": "lme-admin",
    "password": "<generated strong native backend password, minimum 24 characters>"
  },
  "principals": [
    {
      "name": "graph-write",
      "token": "<unique generated bearer token, 32-512 URL-safe characters>",
      "source": "physical:graph",
      "operations": ["write_logs", "write_metrics"]
    },
    {
      "name": "graph-read",
      "token": "<different generated bearer token, 32-512 URL-safe characters>",
      "source": "physical:graph",
      "operations": ["read_logs", "read_metrics"]
    }
  ]
}
```

Each principal binds exactly one source. Names, tokens, JSON keys, and operation
entries cannot be duplicated. The native username/password becomes a Basic
Authorization header only on the backend request. Client credentials use
`Authorization: Bearer <token>`. Each client's Authorization file contains that
complete header value; its token must match its private policy entry.

The following routes are the entire exposed API:

| Mode | Route | Required operation | Boundary |
|---|---|---|---|
| All | `GET /_lme/authorization` | Valid bearer | Returns only caller principal, source, declared operations, and SHA-256 of exact private policy bytes |
| HertzBeat | `POST /api/otlp/v1/logs` | `write_logs` | OTLP JSON; every resource must have exactly one `host.name` matching caller source |
| HertzBeat | `POST /api/otlp/v1/metrics` | `write_metrics` | Same resource boundary for OTLP metrics |
| HertzBeat | `GET /api/observability/logs` | `read_logs` | Bounded typed event lookup with injected exact resource filter and verified response sources |
| HertzBeat | `POST /_lme/metrics` | `read_metrics` | Typed allowlisted metric query compiled to source-filtered bounded native SQL |
| HertzBeat | `GET /_lme/backend-authentication` | `read_logs` | Fixed native authentication checks; only two booleans returned |
| Malcolm | `POST /mapi/document` | `read_logs` | Exact host receipt query; verified source, event ID, and event hash in every result |
| Wazuh | `POST /_lme/security-event` | `read_security` | Fixed canary lookup bound to registered agent ID and name |
| Wazuh | `POST /_lme/security-events` | `read_security` | Complete bounded real-alert window with the same source binding |

HertzBeat log query parameters are `start`, `end` (Unix milliseconds, at most
five minutes apart), `search` (bounded event ID using letters, digits, `_.:-`),
optional `pageIndex` (0–4), and `pageSize` (1–200). The gateway injects
`resource=host.name = '<caller source>'`; an explicitly supplied resource must
match that exact expression. Other parameters and duplicate keys are refused.
Every returned native LogEntry must have `resource["host.name"]` matching the
caller. A canonical JSON body with `source_node` must agree too. The response is
`{"code":0,"data":{"content":[...]}}`; native page totals are omitted.

Malcolm accepts exactly:

```json
{
  "doctype": "host",
  "limit": 2,
  "filter": {
    "event.id": "<bounded event identifier>",
    "event.hash": "<64 lowercase hex characters>",
    "host.name": "physical:graph"
  }
}
```

The caller's source must equal `host.name`. The native response retains only
`results[*]._index`, `_id`, and `_source`, with zero results indicating absent
readback. More than one result is an ambiguous receipt and fails closed. A
result's host name, event ID, event hash, and any canonical `lme.source_node`
must agree. Raw OpenSearch queries, network document queries, broad date-range
searches, and administration routes are absent. Malcolm writes continue through
the separately managed source-authenticated mTLS pipeline.

For native metric reads, the private HertzBeat policy additionally contains
`metrics_backend_admin: {"username":"hertzbeat","password":"<generated Greptime runtime password>"}`.
This credential is separate from `backend_admin`; it is sent only to literal
`127.0.0.1:4000` (configurable `metrics_backend_port`). There is no external
Greptime listener exposed by this module.

Configure an explicit metric table and column allowlist in the public gateway
configuration, for example:

```json
{
  "metrics_backend_port": 4000,
  "metrics_tables": {
    "lme-service-ssh_service_status": {
      "timestamp_column": "ts",
      "columns": ["ts", "host.name", "active", "__lme_unit_active", "__lme_type_active", "instance"]
    }
  }
}
```

`POST /_lme/metrics` accepts a JSON object with `table`, `columns`, `start`, `end`,
and optional `labels`. Start and end are integer Unix milliseconds no more than
five minutes apart. Requested columns must be in the table's configured allowlist
and must include both its timestamp column and configured source column. Labels add exact
conjunctive filters using selected columns and bounded plain string values;
source and timestamp filters cannot be supplied through labels. For example:

```json
{
  "table": "lme-service-ssh_service_status",
  "columns": ["ts", "host.name", "active", "__lme_unit_active", "__lme_type_active"],
  "start": 1789999800000,
  "end": 1790000100000
}
```

Each table may set `source_column` to `host.name` (the default for native
HertzBeat tables) or `host_name` (qualified generic OTLP storage). Other source
column names are refused. Generic tables use `greptime_timestamp`,
`greptime_value`, and stored `lme_metric_unit`, `lme_metric_type`, and
`lme_metric_temporality` columns. Clients cannot override the configured source
column or supply source aliases as label filters.

The gateway generates one `SELECT` with quoted allowlisted identifiers, an exact
predicate on that table's configured source column, inclusive start/end predicates, timestamp
descending order, and `LIMIT 1000`. Clients cannot supply SQL, functions,
unions, comments, subqueries, or additional statements. Both methods of the raw
`/v1/sql` route are refused. Each native result row must have exactly the requested
schema width and the caller's literal source in its configured source column. Responses
preserve native `output[0].records.schema.column_schemas` and `rows`, including
stored timestamp precision, numeric values, units, and types; `total_rows` is
computed from the returned rows. An empty allowlist permits no metric queries.

`GET /_lme/backend-authentication` performs fixed backend requests to HertzBeat
`/api/summary` and Greptime `SELECT 1`, with their separate private Basic credentials.
It accepts no query parameters and returns only
`{"hertzbeat_authenticated":true,"greptime_authenticated":true}` after both responses
pass validation. Rejected credentials, error wrappers, unexpected SQL result
shapes, or invalid values fail closed. It does not query a metric table, so it can
run before first ingestion creates tables. Native summaries and SQL result data
are never exposed through this endpoint.

Introspection proves the loaded policy and caller binding; the fixed authentication
probe proves that both configured backend credentials are accepted. Native data
creation, metric readback, and source-to-sink acceptance remain separate gates.

Wazuh uses a separate policy and listener: `mode: "wazuh"`, `listen_port: 1460`,
`backend_port: 9200`, and exact `backend_tls_server_name` plus `backend_ca_file`
for the graph guest's native Elasticsearch HTTPS listener. The TLS socket stays
on literal `127.0.0.1`; native credentials remain only inside this owner boundary.
The policy's `backend_admin` field contains a dedicated native Elasticsearch
reader credential with `read` and `view_index_metadata` only on
`wazuh-alerts-4.x-*`. Its permissions do not rely on licensed document-level
security, and this credential is never distributed to source callers.

Each Wazuh principal has exactly `operations: ["read_security"]`, plus
`agent_id` and `agent_name` copied from the server's verified registration for its
canonical `source`. Both fields are mandatory. The policy refuses an agent ID
or name bound to multiple canonical sources, and refuses differing agent
registrations for one canonical source. These fields are also included in
that principal's authenticated introspection response.

`POST /_lme/security-event` accepts exactly
`{"run_id":"example-run","event_id":"<event identifier>","start":0,"end":1000}`.
Run IDs use 1–32 lowercase letters, digits, or hyphens; event identifiers are
bounded tokens (UUIDs are supported). Start and end are integer Unix milliseconds
no more than five minutes apart. The native query always uses the fixed Wazuh
index, the principal's registered `agent.id` and `agent.name`, rule `100550`,
the exact `LME_SECURITY_CANARY run_id=... event_id=...` marker, and that time range.
The response contains at most one hit, newest first; an absent canary returns
HTTP 200 with an empty `hits.hits` array.

`POST /_lme/security-events` accepts exactly `{"start":0,"end":1000}` with the
same time bounds. It reads real alerts without the canary rule/marker predicate,
but always adds both registered agent predicates. The fixed native request asks
for 101 hits, exact total counts, and ascending timestamp order. More than 100
matches returns HTTP 409 with no alert data. A successful response requires an
exact native count equal to the returned hit count; partial, approximate, or
duplicate results fail closed. The mirroring client can recursively split a 409
window, deduplicate native index/ID pairs, durably admit its canonical records,
and advance its private time cursor only after every record is acknowledged.
A window that still exceeds the limit at one millisecond cannot be silently
advanced. Rechecking overlapping windows is needed to recover delayed indexing.

Both Wazuh routes verify every hit's native index, registered agent ID/name,
timestamp, bounded rule fields, and bounded original `full_log`. The canary
route additionally rechecks its exact marker and rule. The only exposed hit
fields are `_id`, `_index`, and `_source` containing `timestamp`, `agent.id/name`,
`rule.id/level/description`, `full_log`, and the canonical `source_node` bound by
the gateway. An existing conflicting `source_node` is refused. The plural route
also returns `hits.total: {"value": <returned count>, "relation": "eq"}`. Sources
cannot supply Elasticsearch queries, indices, rule filters, agent predicates,
source overrides, SQL, or raw native paths. This is a source-enforced native
read boundary; ongoing mirroring and its durable cursor live in `lme_security`.

Bodies and backend responses default to 1 MiB, requests time out after ten
seconds of socket inactivity, and at most two request handlers run concurrently.
The server closes excess connections; it has no unbounded worker queue. The
role should enforce a 64 MiB cgroup limit. Operators can lower bounds; larger
configured bounds require a corresponding memory budget.

Only uncompressed JSON is accepted. HTTP transfer encoding, ambiguous framing,
JSON duplicate keys, mixed or missing resource identities, contradictory attribute aliases that
normalize to `host_name` (including `host_name`, `host-name`, and `host name`), unsupported routes,
and unauthorized operations are refused before backend access. Forwarding and
identity headers from Serve or callers never grant permissions and never reach
the backend. Response headers, cookies, backend error text, and credentials are
not relayed; request/error logs contain no headers or bodies. Loaded policy is
immutable for the process lifetime; rotate the private file then restart the
gateway and verify its introspection digest.

Verification uses synthetic ephemeral loopback HTTP and TLS servers in
`tests/test_sink_proxy.py`. These tests prove gateway behavior, not live Serve,
HertzBeat, Malcolm, or source mTLS deployment.
