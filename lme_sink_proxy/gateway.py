"""Explicit typed routes only; caller tokens never reach the administrative backend."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import threading
from urllib.parse import parse_qsl, urlencode, urlsplit


class Rejected(Exception):
    def __init__(self, status):
        self.status = status


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw, object_pairs_hook=_unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid JSON number')))


def _private_bytes(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError('policy must be an owner-only regular file')
            raw = stream.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError('policy exceeds bounded limit')
            return raw
    except OSError:
        raise ValueError('cannot open private policy') from None


@dataclass(frozen=True, repr=False)
class Principal:
    name: str
    token: str
    source: str
    operations: tuple
    agent_id: str | None = None
    agent_name: str | None = None


@dataclass(frozen=True, repr=False)
class Policy:
    authorization: str
    principals: tuple
    sha256: str
    secrets: tuple
    metrics_authorization: str | None = None

    @classmethod
    def load(cls, path):
        try:
            raw = _private_bytes(path)
            value = _json(raw)
            if not {'backend_admin', 'principals'} <= set(value) or not set(value) <= {'backend_admin', 'principals', 'metrics_backend_admin'}:
                raise ValueError()
            admin = value['backend_admin']
            if set(admin) != {'username', 'password'}:
                raise ValueError()
            username, password = admin['username'], admin['password']
            if not isinstance(username, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', username):
                raise ValueError()
            if not isinstance(password, str) or len(password) < 24 or any(ord(c) < 32 for c in password):
                raise ValueError()
            auth = 'Basic ' + base64.b64encode((username + ':' + password).encode()).decode()
            principals, tokens, names = [], set(), set()
            agent_sources, source_agents = {}, {}
            if not isinstance(value['principals'], list) or not value['principals']:
                raise ValueError()
            for row in value['principals']:
                if not {'name', 'token', 'source', 'operations'} <= set(row) or not set(row) <= {'name', 'token', 'source', 'operations', 'agent_id', 'agent_name'}:
                    raise ValueError()
                name, token, source, operations = (row[k] for k in ('name', 'token', 'source', 'operations'))
                if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', name) or name in names:
                    raise ValueError()
                if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_.~-]{32,512}', token) or token in tokens:
                    raise ValueError()
                if not isinstance(source, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', source):
                    raise ValueError()
                if not isinstance(operations, list) or not operations or any(op not in ('write_logs', 'write_metrics', 'read_logs', 'read_metrics', 'read_security') for op in operations) or len(set(operations)) != len(operations):
                    raise ValueError()
                agent_id, agent_name = row.get('agent_id'), row.get('agent_name')
                if 'read_security' in operations:
                    if operations != ['read_security'] or not isinstance(agent_id, str) or not re.fullmatch(r'[0-9]{1,8}', agent_id) or not isinstance(agent_name, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,256}', agent_name):
                        raise ValueError()
                    identity = (str(int(agent_id)), agent_name)
                    if source in source_agents and source_agents[source] != identity:
                        raise ValueError()
                    for agent_key in (('id', identity[0]), ('name', agent_name)):
                        if agent_key in agent_sources and agent_sources[agent_key] != source:
                            raise ValueError()
                        agent_sources[agent_key] = source
                    source_agents[source] = identity
                elif 'agent_id' in row or 'agent_name' in row:
                    raise ValueError()
                names.add(name); tokens.add(token)
                principals.append(Principal(name, token, source, tuple(operations), agent_id, agent_name))
            secrets = (password, auth, auth[6:], *tokens)
            metrics_auth = None
            if 'metrics_backend_admin' in value:
                metrics_admin = value['metrics_backend_admin']
                if not isinstance(metrics_admin, dict) or set(metrics_admin) != {'username', 'password'}:
                    raise ValueError()
                metric_user, metric_password = metrics_admin['username'], metrics_admin['password']
                if not isinstance(metric_user, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', metric_user):
                    raise ValueError()
                if not isinstance(metric_password, str) or len(metric_password) < 24 or any(ord(c) < 32 for c in metric_password):
                    raise ValueError()
                metrics_auth = 'Basic ' + base64.b64encode((metric_user + ':' + metric_password).encode()).decode()
                secrets += (metric_password, metrics_auth, metrics_auth[6:])
            return cls(auth, tuple(principals), hashlib.sha256(raw).hexdigest(), secrets, metrics_auth)
        except (ValueError, TypeError, KeyError, RecursionError, AttributeError):
            raise ValueError('invalid private sink policy') from None

    def authenticate(self, authorization):
        if not authorization or not authorization.startswith('Bearer '):
            raise Rejected(401)
        token = authorization[7:]
        # Compare all entries; neither the backend principal nor proxy headers grant access.
        matched = None
        for principal in self.principals:
            if hmac.compare_digest(token.encode(), principal.token.encode()):
                matched = principal
        if matched is None:
            raise Rejected(401)
        return matched


@dataclass(frozen=True)
class GatewayConfig:
    backend_port: int = 1157
    listen_port: int = 1457
    listen_host: str = '127.0.0.1'
    backend_host: str = '127.0.0.1'
    mode: str = 'hertzbeat'
    max_body_bytes: int = 1024 * 1024
    max_response_bytes: int = 1024 * 1024
    timeout_seconds: int = 10
    max_connections: int = 2
    backend_ca_file: str | None = None
    backend_tls_server_name: str | None = None
    metrics_backend_port: int = 4000
    metrics_tables: dict = field(default_factory=dict)

    def __post_init__(self):
        if self.mode not in ('hertzbeat', 'malcolm', 'wazuh') or self.listen_host != '127.0.0.1' or self.backend_host != '127.0.0.1':
            raise ValueError('gateway requires the supported mode and literal loopback addresses')
        if self.mode in ('malcolm', 'wazuh') and (not isinstance(self.backend_tls_server_name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}', self.backend_tls_server_name)):
            raise ValueError('native HTTPS backend requires an explicit TLS server name')
        if self.mode == 'hertzbeat' and (self.backend_tls_server_name or self.backend_ca_file):
            raise ValueError('HertzBeat backend is owner-local HTTP')
        if not isinstance(self.metrics_tables, dict) or len(self.metrics_tables) > 128:
            raise ValueError('invalid metric table allowlist')
        if self.mode != 'hertzbeat' and self.metrics_tables:
            raise ValueError('metric tables require HertzBeat mode')
        for table, binding in self.metrics_tables.items():
            if not isinstance(table, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,191}', table):
                raise ValueError('invalid metric table')
            if not isinstance(binding, dict) or not {'timestamp_column', 'columns'} <= set(binding) or not set(binding) <= {'timestamp_column', 'columns', 'source_column'}:
                raise ValueError('invalid metric table binding')
            columns = binding['columns']
            if not isinstance(columns, list) or not 2 <= len(columns) <= 64 or any(not isinstance(column, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,191}', column) for column in columns) or len(set(columns)) != len(columns):
                raise ValueError('invalid metric columns')
            source_column = binding.get('source_column', 'host.name')
            if source_column not in ('host.name', 'host_name'):
                raise ValueError('metric source column must use a qualified native name')
            if source_column not in columns or binding['timestamp_column'] not in columns or binding['timestamp_column'] == source_column:
                raise ValueError('metric binding requires timestamp and source columns')
        for name in ('listen_port', 'backend_port', 'metrics_backend_port'):
            value = getattr(self, name)
            if type(value) is not int or not (0 if name == 'listen_port' else 1) <= value <= 65535:
                raise ValueError('invalid port')
        for name, maximum in [('max_body_bytes', 16 * 1024 * 1024), ('max_response_bytes', 16 * 1024 * 1024), ('timeout_seconds', 60), ('max_connections', 128)]:
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError('invalid gateway bound')


def _attributes(attributes, source, require_host=False):
    if not isinstance(attributes, list):
        raise Rejected(403)
    seen = set()
    for item in attributes:
        if not isinstance(item, dict) or set(item) != {'key', 'value'} or not isinstance(item['key'], str) or item['key'] in seen:
            raise Rejected(403)
        seen.add(item['key'])
        if re.sub(r'[^A-Za-z0-9]', '_', item['key']) == 'host_name' and item['value'] != {'stringValue': source}:
            raise Rejected(403)
    if require_host and 'host.name' not in seen:
        raise Rejected(403)


def _check_nested(value, source, depth=0):
    if depth > 64:
        raise Rejected(403)
    if isinstance(value, dict):
        if 'attributes' in value:
            _attributes(value['attributes'], source)
        if 'source_node' in value and value['source_node'] != source:
            raise Rejected(403)
        if 'host.name' in value and value['host.name'] != source:
            raise Rejected(403)
        # Canonical records are carried as JSON in an OTLP string body.
        body = value.get('body')
        if isinstance(body, dict) and isinstance(body.get('stringValue'), str):
            try:
                candidate = _json(body['stringValue'])
            except (ValueError, RecursionError):
                if body['stringValue'].lstrip().startswith(('{', '[')):
                    raise Rejected(403) from None
                candidate = None
            if isinstance(candidate, dict) and 'source_node' in candidate and candidate['source_node'] != source:
                raise Rejected(403)
        for item in value.values():
            _check_nested(item, source, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_nested(item, source, depth + 1)


def _write_payload(value, source, signal):
    root, scopes, records = ('resourceLogs', 'scopeLogs', 'logRecords') if signal == 'logs' else ('resourceMetrics', 'scopeMetrics', 'metrics')
    if not isinstance(value, dict) or set(value) != {root} or not isinstance(value[root], list) or not value[root]:
        raise Rejected(403)
    for resource in value[root]:
        if not isinstance(resource, dict) or not set(resource) <= {'resource', scopes, 'schemaUrl'}:
            raise Rejected(403)
        identity = resource.get('resource')
        if not isinstance(identity, dict) or not set(identity) <= {'attributes', 'droppedAttributesCount'}:
            raise Rejected(403)
        _attributes(identity.get('attributes'), source, require_host=True)
        groups = resource.get(scopes)
        if not isinstance(groups, list) or not groups:
            raise Rejected(403)
        for group in groups:
            if not isinstance(group, dict) or not set(group) <= {'scope', records, 'schemaUrl'} or not isinstance(group.get(records), list) or not group[records]:
                raise Rejected(403)
    _check_nested(value, source)
    return json.dumps(value, allow_nan=False, separators=(',', ':')).encode()


def _log_query(query, source):
    pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True, max_num_fields=7)
    params = dict(pairs)
    if len(params) != len(pairs) or not {'start', 'end', 'search'} <= set(params) or not set(params) <= {'start', 'end', 'search', 'pageIndex', 'pageSize', 'resource'}:
        raise Rejected(400)
    for key, default, maximum in [('start', None, 2**63-1), ('end', None, 2**63-1), ('pageIndex', '0', 4), ('pageSize', '200', 200)]:
        text = params.get(key, default)
        if not re.fullmatch(r'[0-9]{1,19}', text) or int(text) > maximum or (key == 'pageSize' and int(text) == 0):
            raise Rejected(400)
        params[key] = str(int(text))
    if not 0 <= int(params['end']) - int(params['start']) <= 300000 or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,256}', params['search']):
        raise Rejected(400)
    scope = "host.name = '" + source + "'"
    if 'resource' in params and params['resource'] != scope:
        raise Rejected(403)
    params['resource'] = scope
    return '/api/observability/logs?' + urlencode(params)


def _read_response(value, source):
    if not isinstance(value, dict) or value.get('code') != 0 or not isinstance(value.get('data'), dict):
        raise Rejected(502)
    rows = value['data'].get('content')
    if not isinstance(rows, list) or len(rows) > 200:
        raise Rejected(502)
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('resource'), dict) or row['resource'].get('host.name') != source:
            raise Rejected(502)
        body = row.get('body')
        if isinstance(body, str):
            try:
                body = _json(body)
            except (ValueError, RecursionError):
                if body.lstrip().startswith(('{', '[')):
                    raise Rejected(502) from None
                body = None
        receipt_filters = None
        metric_columns = None
        metric_source_column = None
        security_witness = None
        if isinstance(body, dict) and 'source_node' in body and body['source_node'] != source:
            raise Rejected(502)
    # Pagination metadata is not needed by the adapter and can conceal unscoped counts.
    return {'code': 0, 'data': {'content': rows}}


def _malcolm_query(value, source):
    if not isinstance(value, dict) or set(value) != {'doctype', 'limit', 'filter'} or value['doctype'] != 'host' or type(value['limit']) is not int or value['limit'] != 2:
        raise Rejected(400)
    filters = value['filter']
    if not isinstance(filters, dict) or set(filters) != {'event.id', 'event.hash', 'host.name'}:
        raise Rejected(400)
    if filters['host.name'] != source:
        raise Rejected(403)
    if not isinstance(filters['event.id'], str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,256}', filters['event.id']):
        raise Rejected(400)
    if not isinstance(filters['event.hash'], str) or not re.fullmatch(r'[a-f0-9]{64}', filters['event.hash']):
        raise Rejected(400)
    return json.dumps(value, allow_nan=False, separators=(',', ':')).encode(), filters


def _field(document, dotted):
    nested = document
    for part in dotted.split('.'):
        nested = nested.get(part) if isinstance(nested, dict) else None
    if dotted in document and nested is not None and document[dotted] != nested:
        raise Rejected(502)
    return document.get(dotted, nested)


def _malcolm_response(value, filters):
    if not isinstance(value, dict) or not isinstance(value.get('results'), list) or len(value['results']) > 1:
        raise Rejected(502)
    rows = value['results']
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('_source'), dict):
            raise Rejected(502)
        source = row['_source']
        if any(_field(source, field) != expected for field, expected in filters.items()):
            raise Rejected(502)
        if isinstance(source.get('lme'), dict) and source['lme'].get('source_node') != filters['host.name']:
            raise Rejected(502)
    return {'results': [{key: row[key] for key in ('_index', '_id', '_source') if key in row} for row in rows]}


def _metric_query(value, source, config):
    if not isinstance(value, dict) or not {'table', 'columns', 'start', 'end'} <= set(value) or not set(value) <= {'table', 'columns', 'start', 'end', 'labels'}:
        raise Rejected(400)
    table = value['table']
    if not isinstance(table, str) or table not in config.metrics_tables:
        raise Rejected(403)
    binding = config.metrics_tables[table]
    columns = value['columns']
    if not isinstance(columns, list) or not 2 <= len(columns) <= 32 or any(not isinstance(column, str) or column not in binding['columns'] for column in columns) or len(set(columns)) != len(columns):
        raise Rejected(400)
    timestamp = binding['timestamp_column']
    source_column = binding.get('source_column', 'host.name')
    if source_column not in columns or timestamp not in columns:
        raise Rejected(400)
    start, end = value['start'], value['end']
    if type(start) is not int or type(end) is not int or not 0 <= start <= end <= 2**63-1 or end-start > 300000:
        raise Rejected(400)
    labels = value.get('labels', {})
    if not isinstance(labels, dict) or len(labels) > 16:
        raise Rejected(400)
    for key, label in labels.items():
        if key not in columns or key in ('host.name', 'host_name', timestamp) or not isinstance(label, str) or not re.fullmatch(r'[A-Za-z0-9_.:/@ -]{1,128}', label):
            raise Rejected(400)
    quote = lambda name: '"' + name + '"'
    predicates = [quote(source_column) + "='" + source + "'",
                  quote(timestamp) + '>=to_timestamp_millis(' + str(start) + ')',
                  quote(timestamp) + '<=to_timestamp_millis(' + str(end) + ')']
    predicates.extend(quote(key) + "='" + label + "'" for key, label in labels.items())
    statement = ('SELECT ' + ','.join(quote(column) for column in columns) + ' FROM ' + quote(table)
                 + ' WHERE ' + ' AND '.join(predicates) + ' ORDER BY ' + quote(timestamp) + ' DESC LIMIT 1000')
    return '/v1/sql?' + urlencode({'db': 'public', 'sql': statement}), columns, source_column


def _metric_response(value, source, columns, source_column):
    if not isinstance(value, dict) or value.get('code', 0) != 0 or not isinstance(value.get('output'), list) or len(value['output']) != 1:
        raise Rejected(502)
    output = value['output'][0]
    records = output.get('records') if isinstance(output, dict) else None
    schema = records.get('schema') if isinstance(records, dict) else None
    declared = schema.get('column_schemas') if isinstance(schema, dict) else None
    rows = records.get('rows') if isinstance(records, dict) else None
    if not isinstance(declared, list) or any(not isinstance(column, dict) for column in declared) or [column.get('name') for column in declared] != columns:
        raise Rejected(502)
    if not isinstance(rows, list) or len(rows) > 1000:
        raise Rejected(502)
    source_index = columns.index(source_column)
    if any(not isinstance(row, list) or len(row) != len(columns) or row[source_index] != source for row in rows):
        raise Rejected(502)
    return {'code': 0, 'output': [{'records': {'schema': {'column_schemas': declared}, 'rows': rows, 'total_rows': len(rows)}}]}


def _security_query(value, principal, *, batch=False):
    fields = {'start', 'end'} if batch else {'run_id', 'event_id', 'start', 'end'}
    if not isinstance(value, dict) or set(value) != fields:
        raise Rejected(400)
    marker = None
    if not batch:
        run_id, event_id = value['run_id'], value['event_id']
        if not isinstance(run_id, str) or not re.fullmatch(r'[a-z0-9-]{1,32}', run_id) or not isinstance(event_id, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', event_id):
            raise Rejected(400)
        marker = 'LME_SECURITY_CANARY run_id=' + run_id + ' event_id=' + event_id
    start, end = value['start'], value['end']
    if type(start) is not int or type(end) is not int or not 0 <= start <= end <= 2**63-1 or end-start > 300000:
        raise Rejected(400)
    filters = [{'term': {'agent.id': principal.agent_id}}, {'term': {'agent.name': principal.agent_name}}]
    if not batch:
        filters.extend([{'term': {'rule.id': '100550'}}, {'match_phrase': {'full_log': marker}}])
    filters.append({'range': {'timestamp': {'gte': start, 'lte': end, 'format': 'epoch_millis'}}})
    query = {'size': 101 if batch else 1, 'query': {'bool': {'filter': filters}},
        'sort': [{'timestamp': 'asc' if batch else 'desc'}],
        '_source': ['timestamp', 'agent.id', 'agent.name', 'rule.id', 'rule.level', 'rule.description', 'full_log', 'source_node']}
    if batch:
        query['track_total_hits'] = True
    return json.dumps(query, separators=(',', ':')).encode(), (marker, start, end)


def _security_timestamp(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise Rejected(502)
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            raise Rejected(502)
        delta = stamp.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
        return delta.days * 86400000 + delta.seconds * 1000 + delta.microseconds // 1000
    except (ValueError, OverflowError):
        raise Rejected(502) from None


def _security_response(value, principal, witness):
    if not isinstance(value, dict) or 'error' in value or value.get('timed_out', False) is not False:
        raise Rejected(502)
    if '_shards' in value and (not isinstance(value['_shards'], dict) or value['_shards'].get('failed') != 0):
        raise Rejected(502)
    container = value.get('hits')
    hits = container.get('hits') if isinstance(container, dict) else None
    if not isinstance(hits, list):
        raise Rejected(502)
    marker, start, end = witness
    if marker is None:
        total = container.get('total')
        if not isinstance(total, dict) or type(total.get('value')) is not int or total['value'] < 0:
            raise Rejected(502)
        if total['value'] > 100 or len(hits) > 100:
            raise Rejected(409)
        if total.get('relation') != 'eq' or total['value'] != len(hits):
            raise Rejected(502)
    elif len(hits) > 1:
        raise Rejected(502)
    result, seen = [], set()
    for hit in hits:
        if not isinstance(hit, dict) or not isinstance(hit.get('_source'), dict) or not isinstance(hit.get('_id'), str) or not 1 <= len(hit['_id']) <= 512 or not isinstance(hit.get('_index'), str) or not re.fullmatch(r'wazuh-alerts-4\.x-[A-Za-z0-9._-]{1,160}', hit['_index']):
            raise Rejected(502)
        identity = (hit['_index'], hit['_id'])
        if identity in seen:
            raise Rejected(502)
        seen.add(identity)
        source = hit['_source']
        agent, rule, full_log = source.get('agent'), source.get('rule'), source.get('full_log')
        if not isinstance(agent, dict) or agent.get('id') != principal.agent_id or agent.get('name') != principal.agent_name:
            raise Rejected(502)
        if not isinstance(rule, dict) or not isinstance(rule.get('id'), (str, int)) or not re.fullmatch(r'[0-9]{1,8}', str(rule['id'])) or (marker is not None and str(rule['id']) != '100550') or type(rule.get('level')) is not int or not 0 <= rule['level'] <= 16 or not isinstance(rule.get('description'), str) or not 1 <= len(rule['description']) <= 1024:
            raise Rejected(502)
        if not isinstance(full_log, str) or len(full_log.encode()) > 8192 or (marker is not None and not re.search(r'(?<!\S)' + re.escape(marker) + r'(?!\S)', full_log)):
            raise Rejected(502)
        if source.get('source_node', principal.source) != principal.source or not start <= _security_timestamp(source.get('timestamp')) <= end:
            raise Rejected(502)
        result.append({'_id': hit['_id'], '_index': hit['_index'], '_source': {
            'timestamp': source['timestamp'], 'agent': {'id': principal.agent_id, 'name': principal.agent_name},
            'rule': {key: rule[key] for key in ('id', 'level', 'description')}, 'full_log': full_log,
            'source_node': principal.source}})
    container = {'hits': result}
    if marker is None:
        container['total'] = {'value': len(result), 'relation': 'eq'}
    return {'hits': container}


class LoopbackTLSConnection(http.client.HTTPSConnection):
    """Verify the configured native FQDN while keeping the socket owner-local."""
    def __init__(self, config):
        self.tls_server_name = config.backend_tls_server_name
        context = ssl.create_default_context(cafile=config.backend_ca_file)
        super().__init__(config.backend_host, config.backend_port, timeout=config.timeout_seconds, context=context)

    def connect(self):
        super(http.client.HTTPSConnection, self).connect()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.tls_server_name)


class GatewayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # Base implementation prints exception details; never log headers or payloads.
        pass


class GatewayHandler(BaseHTTPRequestHandler):
    server_version = 'LME-sink-gateway'
    sys_version = ''

    def setup(self):
        self.request.settimeout(self.server.config.timeout_seconds)
        super().setup()

    def log_message(self, *_):
        pass

    def send_error(self, code, message=None, explain=None):
        self._reply(code, {'error': 'request rejected'})

    def _reply(self, status, value):
        self.close_connection = True
        raw = json.dumps(value, allow_nan=False, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def _handle(self):
        try:
            self._dispatch()
        except Rejected as failure:
            self._reply(failure.status, {'error': 'request rejected'})
        except (OSError, http.client.HTTPException):
            self._reply(502, {'error': 'backend unavailable'})
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
            self._reply(400, {'error': 'invalid request'})

    def _dispatch(self):
        cfg, policy = self.server.config, self.server.policy
        if len(self.path) > 4096 or not self.path.startswith('/') or self.path.startswith('//') or '#' in self.path:
            raise Rejected(400)
        for key in ('Authorization', 'Content-Length', 'Content-Type', 'Host'):
            if len(self.headers.get_all(key, [])) > 1:
                raise Rejected(400)
        if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Encoding') or self.headers.get('Expect') or self.headers.get('Proxy-Authorization'):
            raise Rejected(400)
        principal = policy.authenticate(self.headers.get('Authorization'))
        target = urlsplit(self.path)
        body = None
        receipt_filters = None
        metric_columns = None
        metric_source_column = None
        security_witness = None
        if self.command == 'GET':
            if self.headers.get('Content-Length') not in (None, '0'):
                raise Rejected(400)
            if self.path == '/_lme/authorization':
                introspection = {'principal': principal.name, 'source': principal.source, 'operations': list(principal.operations), 'policy_sha256': policy.sha256}
                if principal.agent_id is not None:
                    introspection.update(agent_id=principal.agent_id, agent_name=principal.agent_name)
                self._reply(200, introspection)
                return
            if cfg.mode == 'hertzbeat' and self.path == '/_lme/backend-authentication':
                if 'read_logs' not in principal.operations or policy.metrics_authorization is None:
                    raise Rejected(403)
                summary = self._backend('/api/summary', None, method='GET')
                if not isinstance(summary, dict) or type(summary.get('code')) is not int or summary['code'] != 0 or not isinstance(summary.get('data'), dict):
                    raise Rejected(502)
                query = self._backend('/v1/sql?' + urlencode({'db': 'public', 'sql': 'SELECT 1'}), None, metrics=True)
                if not isinstance(query, dict) or query.get('code', 0) != 0 or not isinstance(query.get('output'), list) or len(query['output']) != 1:
                    raise Rejected(502)
                output = query['output'][0]
                records = output.get('records') if isinstance(output, dict) else None
                schema = records.get('schema') if isinstance(records, dict) else None
                columns = schema.get('column_schemas') if isinstance(schema, dict) else None
                rows = records.get('rows') if isinstance(records, dict) else None
                if not isinstance(columns, list) or len(columns) != 1 or not isinstance(columns[0], dict) or columns[0].get('data_type') not in ('Int64', 'UInt64') or rows != [[1]] or type(rows[0][0]) is not int:
                    raise Rejected(502)
                self._reply(200, {'hertzbeat_authenticated': True, 'greptime_authenticated': True})
                return
            if cfg.mode != 'hertzbeat' or target.path != '/api/observability/logs':
                raise Rejected(404)
            if 'read_logs' not in principal.operations:
                raise Rejected(403)
            path = _log_query(target.query, principal.source)
        else:
            if cfg.mode == 'wazuh':
                if self.path not in ('/_lme/security-event', '/_lme/security-events'):
                    raise Rejected(404)
                if 'read_security' not in principal.operations or principal.agent_id is None or principal.agent_name is None:
                    raise Rejected(403)
            elif cfg.mode == 'hertzbeat' and self.path == '/_lme/metrics':
                if 'read_metrics' not in principal.operations or policy.metrics_authorization is None:
                    raise Rejected(403)
            elif cfg.mode == 'malcolm':
                if self.path != '/mapi/document':
                    raise Rejected(404)
                if 'read_logs' not in principal.operations:
                    raise Rejected(403)
            else:
                if self.path not in ('/api/otlp/v1/logs', '/api/otlp/v1/metrics'):
                    raise Rejected(404)
                signal = self.path.rsplit('/', 1)[1]
                if 'write_' + signal not in principal.operations:
                    raise Rejected(403)
            if self.headers.get('Content-Type', '').lower() not in ('application/json', 'application/json; charset=utf-8'):
                raise Rejected(415)
            length = self.headers.get('Content-Length', '')
            if not re.fullmatch(r'[0-9]{1,10}', length):
                raise Rejected(411)
            if not 0 < int(length) <= cfg.max_body_bytes:
                raise Rejected(413)
            raw = self.rfile.read(int(length))
            if len(raw) != int(length):
                raise Rejected(400)
            if cfg.mode == 'wazuh':
                body, security_witness = _security_query(_json(raw), principal, batch=self.path == '/_lme/security-events')
                path = '/wazuh-alerts-4.x-*/_search'
            elif cfg.mode == 'hertzbeat' and self.path == '/_lme/metrics':
                path, metric_columns, metric_source_column = _metric_query(_json(raw), principal.source, cfg)
                body = None
            elif cfg.mode == 'malcolm':
                body, receipt_filters = _malcolm_query(_json(raw), principal.source)
            else:
                body = _write_payload(_json(raw), principal.source, signal)
            if metric_columns is None and security_witness is None:
                path = self.path
        response = self._backend(path, body, metrics=metric_columns is not None)
        if security_witness is not None:
            response = _security_response(response, principal, security_witness)
        elif metric_columns is not None:
            response = _metric_response(response, principal.source, metric_columns, metric_source_column)
        elif receipt_filters is not None:
            response = _malcolm_response(response, receipt_filters)
        elif self.command == 'GET':
            response = _read_response(response, principal.source)
        elif not isinstance(response, dict) or ('code' in response and response['code'] != 0):
            raise Rejected(502)
        else:
            response = {key: response[key] for key in ('partialSuccess',) if key in response}
        self._reply(200, response)

    def _backend(self, path, body, *, metrics=False, method=None):
        cfg, policy = self.server.config, self.server.policy
        if metrics:
            if policy.metrics_authorization is None:
                raise Rejected(403)
            connection = http.client.HTTPConnection('127.0.0.1', cfg.metrics_backend_port, timeout=cfg.timeout_seconds)
        else:
            connection = LoopbackTLSConnection(cfg) if cfg.mode in ('malcolm', 'wazuh') else http.client.HTTPConnection(cfg.backend_host, cfg.backend_port, timeout=cfg.timeout_seconds)
        try:
            # Only these generated headers cross the boundary. Serve identity/forwarding
            # headers are discarded and can neither grant scope nor override credentials.
            headers = {'Authorization': policy.metrics_authorization if metrics else policy.authorization, 'Content-Type': 'application/json', 'Accept': 'application/json'}
            if cfg.mode in ('malcolm', 'wazuh'):
                headers['Host'] = cfg.backend_tls_server_name
            connection.request(method or ('GET' if metrics else self.command), path, body, headers)
            response = connection.getresponse()
            if response.status not in (200, 201, 202) or response.getheader('Content-Encoding') or response.getheader('Content-Type', '').split(';')[0].lower() != 'application/json':
                raise Rejected(502)
            raw = response.read(cfg.max_response_bytes + 1)
            if len(raw) > cfg.max_response_bytes:
                raise Rejected(502)
            try:
                value = _json(raw) if raw else {}
                normalized = json.dumps(value, ensure_ascii=False)
            except (ValueError, UnicodeError, RecursionError):
                raise Rejected(502) from None
            if any(secret in normalized for secret in policy.secrets):
                raise Rejected(502)
            return value
        finally:
            connection.close()


def make_server(config, policy):
    server = GatewayServer((config.listen_host, config.listen_port), GatewayHandler)
    server.config = config
    server.policy = policy
    server.slots = threading.BoundedSemaphore(config.max_connections)
    return server


def load_config(path):
    """Load public listener settings and its separately protected policy."""
    value = _json(Path(path).read_bytes())
    if not isinstance(value, dict) or 'policy_file' not in value:
        raise ValueError('config requires policy_file')
    policy_path = value.pop('policy_file')
    if not isinstance(policy_path, str) or not Path(policy_path).is_absolute():
        raise ValueError('policy_file must be absolute')
    return GatewayConfig(**value), Policy.load(policy_path)
