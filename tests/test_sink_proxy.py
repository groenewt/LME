"""Real loopback tests: removing a boundary check must expose a denied request."""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from lme_sink_proxy import GatewayConfig, Policy, make_server


SOURCE = 'physical:graph'
TOKEN = 'synthetic-source-write-token-0000000000000001'
READ_TOKEN = 'synthetic-source-read-token-00000000000000001'
ADMIN = 'synthetic-backend-secret-000000000000000000'


def payload(source=SOURCE, kind='Logs'):
    scope = 'scopeLogs' if kind == 'Logs' else 'scopeMetrics'
    items = {'logRecords': [{'body': {'stringValue': json.dumps({'source_node': source, 'event_id': 'event-1'})}}]} if kind == 'Logs' else {'metrics': [{'name': 'synthetic', 'gauge': {'dataPoints': [{'asInt': '1'}]}}]}
    return {'resource'+kind: [{'resource': {'attributes': [{'key': 'host.name', 'value': {'stringValue': source}}]}, scope: [items]}]}


class Backend(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.server.received.append((self.command, self.path, dict(self.headers), json.loads(body)))
        self.respond()

    def do_GET(self):
        self.server.received.append((self.command, self.path, dict(self.headers), None))
        self.respond()

    def respond(self):
        target = urlsplit(self.path).path
        result = getattr(self.server, 'results', {}).get(target, self.server.result)
        status = self.server.status
        expected = getattr(self.server, 'required_auth', {}).get(target)
        if expected and self.headers.get('Authorization') != expected:
            status = 401
            result = {'error': 'synthetic native credential rejected'}
        raw = json.dumps(result).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Set-Cookie', 'admin-secret='+ADMIN)
        self.send_header('Authorization', ADMIN)
        self.end_headers()
        self.wfile.write(raw)


class GatewayFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.policy_path = Path(self.temp.name)/'policy.json'
        self.policy_path.write_text(json.dumps({'backend_admin': {'username': 'admin', 'password': ADMIN}, 'principals': [
            {'name': 'graph-write', 'token': TOKEN, 'source': SOURCE, 'operations': ['write_logs', 'write_metrics']},
            {'name': 'graph-read', 'token': READ_TOKEN, 'source': SOURCE, 'operations': ['read_logs', 'read_metrics']},
        ]}))
        self.policy_path.chmod(0o600)
        self.backend = ThreadingHTTPServer(('127.0.0.1', 0), Backend)
        self.backend.received = []
        self.backend.result = {}
        self.backend.status = 200
        self.bt = threading.Thread(target=self.backend.serve_forever, daemon=True)
        self.bt.start()
        cfg = GatewayConfig(backend_port=self.backend.server_port, listen_port=0, max_body_bytes=4096, max_response_bytes=4096)
        self.gateway = make_server(cfg, Policy.load(self.policy_path))
        self.gt = threading.Thread(target=self.gateway.serve_forever, daemon=True)
        self.gt.start()

    def tearDown(self):
        self.gateway.shutdown()
        self.gateway.server_close()
        self.backend.shutdown()
        self.backend.server_close()
        self.temp.cleanup()

    def request(self, method='POST', path='/api/otlp/v1/logs', value=None, token=TOKEN, headers=None):
        body = json.dumps(payload() if value is None else value).encode() if method == 'POST' else None
        req_headers = {'Content-Type': 'application/json'}
        if token is not None:
            req_headers['Authorization'] = 'Bearer '+token
        req_headers.update(headers or {})
        connection = http.client.HTTPConnection('127.0.0.1', self.gateway.server_port, timeout=3)
        try:
            connection.request(method, path, body, req_headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def read(self, **kwargs):
        return self.request('GET', '/api/observability/logs?start=100&end=2100&search=event-1&pageIndex=0&pageSize=200', token=READ_TOKEN, **kwargs)


class GatewayTests(GatewayFixture):
    def test_valid_writes_use_backend_auth_and_never_forward_caller_token(self):
        for kind, path in [('Logs', '/api/otlp/v1/logs'), ('Metrics', '/api/otlp/v1/metrics')]:
            with self.subTest(kind=kind):
                status, headers, body = self.request(path=path, value=payload(kind=kind))
                self.assertEqual(status, 200)
                received = self.backend.received[-1]
                self.assertEqual(received[2]['Authorization'], 'Basic '+base64.b64encode(('admin:'+ADMIN).encode()).decode())
                self.assertNotIn(TOKEN, str(received))
                self.assertNotIn(ADMIN, str(headers)+body.decode())

    def test_missing_wrong_identity_and_operation_are_denied_before_backend(self):
        for token in [None, 'forged', READ_TOKEN]:
            with self.subTest(token=token):
                self.assertIn(self.request(token=token)[0], (401, 403))
        self.assertEqual(self.backend.received, [])

    def test_cross_source_missing_duplicate_and_mixed_resources_are_denied(self):
        missing = payload(); del missing['resourceLogs'][0]['resource']
        duplicate = payload(); duplicate['resourceLogs'][0]['resource']['attributes'].append({'key': 'host.name', 'value': {'stringValue': SOURCE}})
        mixed = payload(); mixed['resourceLogs'].extend(payload('guest:graph')['resourceLogs'])
        alias = payload(); alias['resource_logs'] = payload('guest:graph')['resourceLogs']
        wrongbody = payload(); wrongbody['resourceLogs'][0]['scopeLogs'][0]['logRecords'][0]['body']['stringValue'] = json.dumps({'source_node': 'guest:graph'})
        for value in [payload('guest:graph'), missing, duplicate, mixed, alias, wrongbody, {'resourceLogs': []}]:
            with self.subTest(value=value):
                self.assertEqual(self.request(value=value)[0], 403)
        self.assertEqual(self.backend.received, [])

    def test_unknown_routes_raw_queries_and_forged_proxy_headers_are_denied(self):
        for path in ['/api/account', '/api/observability/logs/overview', '/api/otlp/v1/logs?admin=1', '/api/otlp/v1/traces']:
            self.assertIn(self.request(path=path)[0], (400, 403, 404))
        for headers in [{'Proxy-Authorization': 'Basic forged'}, {'Content-Encoding': 'gzip'}, {'Content-Type': 'application/x-protobuf'}]:
            self.assertIn(self.request(headers=headers)[0], (400, 403, 415))
        self.assertEqual(self.backend.received, [])

    def test_forwarded_identity_headers_are_stripped_and_cannot_grant_scope(self):
        headers = {'Forwarded': 'for=other', 'X-Forwarded-For': 'other', 'X-Forwarded-Proto': 'https', 'X-Remote-User': 'admin', 'Tailscale-User-Login': 'admin'}
        self.assertEqual(self.request(headers=headers)[0], 200)
        forwarded = {key.lower() for key in self.backend.received[-1][2]}
        self.assertFalse(forwarded.intersection(key.lower() for key in headers))
        self.assertEqual(self.request(headers=headers, token=None)[0], 401)
        self.assertEqual(self.request(headers=headers, value=payload('guest:graph'))[0], 403)

    def test_metrics_mixed_resource_sources_are_denied(self):
        value = payload(kind='Metrics')
        value['resourceMetrics'].extend(payload('guest:graph', kind='Metrics')['resourceMetrics'])
        self.assertEqual(self.request(path='/api/otlp/v1/metrics', value=value)[0], 403)
        self.assertEqual(self.backend.received, [])

    def test_normalized_metric_source_aliases_cannot_override_resource_identity(self):
        for alias in ('host_name', 'host-name', 'host name'):
            value = payload(kind='Metrics')
            value['resourceMetrics'][0]['scopeMetrics'][0]['metrics'][0]['gauge']['dataPoints'][0]['attributes'] = [
                {'key': alias, 'value': {'stringValue': 'guest:graph'}}]
            with self.subTest(alias=alias):
                self.assertEqual(self.request(path='/api/otlp/v1/metrics', value=value)[0], 403)
        self.assertEqual(self.backend.received, [])

    def test_body_limit_is_enforced_before_backend(self):
        self.assertEqual(self.request(value={'padding': 'x'*5000})[0], 413)
        self.assertEqual(self.backend.received, [])

    def test_read_injects_exact_source_and_preserves_typed_records(self):
        row = {'resource': {'host.name': SOURCE}, 'body': json.dumps({'source_node': SOURCE, 'event_id': 'event-1'})}
        self.backend.result = {'code': 0, 'data': {'content': [row], 'totalElements': 1, 'totalPages': 1}}
        status, _, raw = self.read()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)['data']['content'], [row])
        params = parse_qs(urlsplit(self.backend.received[-1][1]).query)
        self.assertEqual(params['resource'], ["host.name = 'physical:graph'"])
        self.assertEqual(params['search'], ['event-1'])

    def test_read_forbids_arbitrary_filter_duplicate_and_unbounded_query(self):
        for extra in ['&resource=host.name%20%3D%20guest:graph', '&sql=SELECT+*', '&search=other', '&pageSize=10000', '&end=9999999999']:
            status = self.request('GET', '/api/observability/logs?start=100&end=2100&search=event-1&pageIndex=0&pageSize=200'+extra, token=READ_TOKEN)[0]
            self.assertIn(status, (400, 403))
        self.assertEqual(self.backend.received, [])

    def test_response_source_is_verified_and_bad_response_is_not_leaked(self):
        for row in [{'resource': {'host.name': 'guest:graph'}, 'body': 'private-other'}, {'body': 'missing-source'}, {'resource': {'host.name': SOURCE}, 'body': json.dumps({'source_node': 'guest:graph'})}]:
            self.backend.result = {'code': 0, 'data': {'content': [row]}}
            status, _, raw = self.read()
            self.assertEqual(status, 502)
            self.assertNotIn(b'guest:graph', raw)
            self.assertNotIn(b'private-other', raw)

    def test_backend_error_secret_and_oversized_responses_are_redacted(self):
        for result, status in [({'error': ADMIN}, 500), ({'code': 0, 'debug': ADMIN, 'data': {'content': []}}, 200), ({'padding': 'x'*5000}, 200)]:
            self.backend.result = result; self.backend.status = status
            actual, headers, raw = self.read()
            self.assertEqual(actual, 502)
            self.assertNotIn(ADMIN, str(headers)+raw.decode())

    def test_authenticated_introspection_contains_only_own_scope(self):
        status, _, raw = self.request('GET', '/_lme/authorization', token=READ_TOKEN)
        self.assertEqual(status, 200)
        result = json.loads(raw)
        self.assertEqual(result['principal'], 'graph-read')
        self.assertEqual(result['source'], SOURCE)
        self.assertEqual(result['operations'], ['read_logs', 'read_metrics'])
        self.assertEqual(result['policy_sha256'], hashlib.sha256(self.policy_path.read_bytes()).hexdigest())
        self.assertNotIn(TOKEN, raw.decode()); self.assertNotIn(ADMIN, raw.decode())
        self.assertEqual(self.backend.received, [])

    def test_ambiguous_canonical_source_json_cannot_bypass_write_or_read_scope(self):
        ambiguous = '{"source_node":"physical:graph","source_node":"guest:graph"}'
        value = payload()
        value['resourceLogs'][0]['scopeLogs'][0]['logRecords'][0]['body']['stringValue'] = ambiguous
        self.assertEqual(self.request(value=value)[0], 403)
        self.backend.result = {'code': 0, 'data': {'content': [{'resource': {'host.name': SOURCE}, 'body': ambiguous}]}}
        self.assertEqual(self.read()[0], 502)

    def test_duplicate_authorization_length_and_chunked_framing_are_denied(self):
        for extra in ['Authorization: Bearer forged\r\n', 'Content-Length: 999\r\n', 'Transfer-Encoding: chunked\r\n']:
            raw = ('POST /api/otlp/v1/logs HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer '+TOKEN+'\r\nContent-Length: 2\r\nContent-Type: application/json\r\n'+extra+'\r\n{}').encode()
            with socket.create_connection(('127.0.0.1', self.gateway.server_port), timeout=3) as connection:
                connection.sendall(raw)
                response = http.client.HTTPResponse(connection); response.begin()
                self.assertEqual(response.status, 400)
                response.read()
        self.assertEqual(self.backend.received, [])

    def test_concurrency_limit_closes_excess_connection_and_recovers(self):
        connections = []
        try:
            # A partial authenticated request occupies each permitted handler.
            for _ in range(2):
                connection = socket.create_connection(('127.0.0.1', self.gateway.server_port), timeout=3)
                connection.sendall(b'GET /_lme/authorization HTTP/1.1\r\n')
                connections.append(connection)
            import time
            deadline = time.monotonic()+2
            while self.gateway.slots._value and time.monotonic() < deadline:
                time.sleep(0.01)
            with socket.create_connection(('127.0.0.1', self.gateway.server_port), timeout=3) as excess:
                self.assertEqual(excess.recv(1), b'')
        finally:
            for connection in connections:
                connection.close()
        deadline = time.monotonic()+2
        while self.gateway.slots._value != 2 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.request()[0], 200)

    def test_private_policy_rejects_public_files_symlinks_duplicate_tokens(self):
        self.policy_path.chmod(0o644)
        with self.assertRaises(ValueError): Policy.load(self.policy_path)
        self.policy_path.chmod(0o600)
        link = self.policy_path.with_name('link'); link.symlink_to(self.policy_path)
        with self.assertRaises(ValueError): Policy.load(link)
        policy = json.loads(self.policy_path.read_text()); policy['principals'][1]['token'] = TOKEN
        self.policy_path.write_text(json.dumps(policy))
        with self.assertRaises(ValueError): Policy.load(self.policy_path)


class MalcolmGatewayTests(GatewayFixture):
    """Native receipt route connects through real TLS with a temporary test CA."""
    def setUp(self):
        super().setUp()
        import subprocess
        import ssl
        self.gateway.shutdown(); self.gateway.server_close()
        self.backend.shutdown(); self.backend.server_close()
        cert = Path(self.temp.name)/'cert.pem'; key = Path(self.temp.name)/'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=gateway.test', '-addext', 'subjectAltName=DNS:gateway.test', '-keyout', str(key), '-out', str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
        self.backend = ThreadingHTTPServer(('127.0.0.1', 0), Backend)
        self.backend.socket = context.wrap_socket(self.backend.socket, server_side=True)
        self.backend.received = []; self.backend.result = {'results': []}; self.backend.status = 200
        self.bt = threading.Thread(target=self.backend.serve_forever, daemon=True); self.bt.start()
        self.cfg = dict(mode='malcolm', backend_port=self.backend.server_port, listen_port=0, max_body_bytes=4096, max_response_bytes=4096, backend_tls_server_name='gateway.test', backend_ca_file=str(cert))
        self.gateway = make_server(GatewayConfig(**self.cfg), Policy.load(self.policy_path))
        self.gt = threading.Thread(target=self.gateway.serve_forever, daemon=True); self.gt.start()

    def receipt(self, value=None, token=READ_TOKEN):
        return self.request('POST', '/mapi/document', value=value or {'doctype': 'host', 'limit': 2, 'filter': {'event.id': 'event-1', 'event.hash': 'a'*64, 'host.name': SOURCE}}, token=token)

    def test_native_receipt_forces_source_and_checks_returned_document(self):
        row = {'_index': 'synthetic', '_id': 'event-1', '_source': {'host': {'name': SOURCE}, 'event': {'id': 'event-1', 'hash': 'a'*64}, 'lme': {'source_node': SOURCE}}}
        self.backend.result = {'results': [row], 'debug': 'not-needed'}
        status, headers, raw = self.receipt()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), {'results': [row]})
        self.assertEqual(self.backend.received[-1][3]['filter']['host.name'], SOURCE)
        self.assertEqual(self.backend.received[-1][2]['Host'], 'gateway.test')
        self.assertNotIn(ADMIN, str(headers)+raw.decode())

    def test_arbitrary_native_query_and_wrong_operation_are_denied(self):
        for value in [
            {'doctype': 'host', 'limit': 2, 'filter': {'event.id': 'event-1', 'event.hash': 'a'*64, 'host.name': 'guest:graph'}},
            {'doctype': 'network', 'limit': 2, 'filter': {'event.id': 'event-1', 'event.hash': 'a'*64, 'host.name': SOURCE}},
            {'doctype': 'host', 'limit': 100, 'filter': {'event.id': 'event-1'}},
            {'doctype': 'host', 'limit': 2, 'filter': {'event.id': 'event-1', 'event.hash': 'a'*64, 'host.name': SOURCE}, 'query': '*'},
        ]:
            self.assertIn(self.receipt(value)[0], (400, 403))
        self.assertEqual(self.receipt(token=TOKEN)[0], 403)
        self.assertEqual(self.backend.received, [])

    def test_wrong_source_id_hash_and_duplicate_results_fail_closed(self):
        source = {'host': {'name': SOURCE}, 'event': {'id': 'event-1', 'hash': 'a'*64}}
        for field, value in [('host', {'name': 'guest:graph'}), ('event', {'id': 'other', 'hash': 'a'*64}), ('event', {'id': 'event-1', 'hash': 'b'*64})]:
            self.backend.result = {'results': [{'_source': dict(source, **{field: value})}]}
            self.assertEqual(self.receipt()[0], 502)
        self.backend.result = {'results': [{'_source': source}, {'_source': source}]}
        self.assertEqual(self.receipt()[0], 502)

    def test_backend_tls_wrong_hostname_is_refused(self):
        self.gateway.shutdown(); self.gateway.server_close()
        self.gateway = make_server(GatewayConfig(**dict(self.cfg, backend_tls_server_name='wrong.test')), Policy.load(self.policy_path))
        self.gt = threading.Thread(target=self.gateway.serve_forever, daemon=True); self.gt.start()
        self.assertEqual(self.receipt()[0], 502)
        self.assertEqual(self.backend.received, [])



class MetricGatewayTests(GatewayFixture):
    def setUp(self):
        super().setUp()
        self.gateway.shutdown(); self.gateway.server_close()
        policy = json.loads(self.policy_path.read_text())
        policy['metrics_backend_admin'] = {'username': 'hertzbeat', 'password': 'synthetic-greptime-secret-00000000000000000'}
        self.policy_path.write_text(json.dumps(policy))
        self.columns = ['ts', 'usage', 'host.name', '__lme_unit_usage', '__lme_type_usage']
        config = GatewayConfig(backend_port=1, listen_port=0, metrics_backend_port=self.backend.server_port,
            metrics_tables={'linux_cpu': {'timestamp_column': 'ts', 'columns': self.columns}}, max_body_bytes=4096, max_response_bytes=4096)
        self.gateway = make_server(config, Policy.load(self.policy_path))
        self.gt = threading.Thread(target=self.gateway.serve_forever, daemon=True); self.gt.start()
        self.backend.result = {'code': 0, 'output': [{'records': {'schema': {'column_schemas': [
            {'name': name, 'data_type': kind} for name, kind in zip(self.columns, ['TimestampMillisecond', 'Float64', 'String', 'String', 'String'])]},
            'rows': [[500, 42.5, SOURCE, '%', 'gauge']], 'total_rows': 1}}]}

    def metrics(self, value=None, token=READ_TOKEN):
        return self.request('POST', '/_lme/metrics', value=value or {'table': 'linux_cpu', 'columns': self.columns, 'start': 0, 'end': 1000}, token=token)

    def test_metrics_read_generates_bounded_source_sql_and_uses_separate_secret(self):
        status, headers, raw = self.metrics()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)['output'][0]['records']['rows'], [[500, 42.5, SOURCE, '%', 'gauge']])
        method, path, forwarded, body = self.backend.received[-1]
        self.assertEqual(method, 'GET')
        query = parse_qs(urlsplit(path).query)
        self.assertEqual(query['db'], ['public'])
        self.assertEqual(query['sql'], ['SELECT "ts","usage","host.name","__lme_unit_usage","__lme_type_usage" FROM "linux_cpu" WHERE "host.name"=\'physical:graph\' AND "ts">=to_timestamp_millis(0) AND "ts"<=to_timestamp_millis(1000) ORDER BY "ts" DESC LIMIT 1000'])
        self.assertEqual(forwarded['Authorization'], 'Basic '+base64.b64encode(b'hertzbeat:synthetic-greptime-secret-00000000000000000').decode())
        self.assertNotIn(ADMIN, str(headers)+raw.decode())

    def test_sql_injection_unknown_tables_columns_and_unbounded_windows_never_reach_backend(self):
        good = {'table': 'linux_cpu', 'columns': self.columns, 'start': 0, 'end': 1000}
        for changed in [{'table': 'linux_cpu UNION SELECT secret'}, {'table': 'accounts'}, {'columns': ['host.name', 'secret']},
                        {'columns': ['ts', 'usage']}, {'start': -1}, {'end': 9999999999999}, {'sql': 'SELECT 1'},
                        {'labels': {'host.name': 'guest:graph'}}, {'labels': {'usage': "x' OR '1'='1"}}]:
            self.assertIn(self.metrics(dict(good, **changed))[0], (400, 403))
        self.assertEqual(self.metrics(token=TOKEN)[0], 403)
        self.assertEqual(self.request('GET', '/v1/sql?db=public&sql=SELECT+1', token=READ_TOKEN)[0], 404)
        self.assertEqual(self.backend.received, [])

    def test_mixed_source_and_missing_source_schema_fail_closed(self):
        records = self.backend.result['output'][0]['records']
        records['rows'].append([501, 33, 'guest:graph', '%', 'gauge'])
        status, _, raw = self.metrics()
        self.assertEqual(status, 502); self.assertNotIn(b'guest:graph', raw)
        records['rows'] = [[500, 42.5, SOURCE, '%', 'gauge']]
        records['schema']['column_schemas'][2]['name'] = 'other'
        self.assertEqual(self.metrics()[0], 502)


class GenericMetricGatewayTests(GatewayFixture):
    def setUp(self):
        super().setUp()
        self.gateway.shutdown(); self.gateway.server_close()
        policy = json.loads(self.policy_path.read_text())
        policy['metrics_backend_admin'] = {'username': 'hertzbeat', 'password': 'synthetic-greptime-secret-00000000000000000'}
        self.policy_path.write_text(json.dumps(policy))
        self.columns = ['greptime_timestamp', 'greptime_value', 'host_name', 'lme_metric_unit', 'lme_metric_type', 'lme_metric_temporality', 'state']
        config = GatewayConfig(backend_port=1, listen_port=0, metrics_backend_port=self.backend.server_port,
            metrics_tables={'lme_host_cpu_seconds_total': {'timestamp_column': 'greptime_timestamp', 'source_column': 'host_name', 'columns': self.columns}})
        self.gateway = make_server(config, Policy.load(self.policy_path))
        self.gt = threading.Thread(target=self.gateway.serve_forever, daemon=True); self.gt.start()
        self.backend.result = {'code': 0, 'output': [{'records': {'schema': {'column_schemas': [
            {'name': name, 'data_type': kind} for name, kind in zip(self.columns, ['TimestampMillisecond', 'Float64', 'String', 'String', 'String', 'String', 'String'])]},
            'rows': [[500, 42.5, SOURCE, 's', 'sum', 'cumulative', 'user']], 'total_rows': 1}}]}
        self.query = {'table': 'lme_host_cpu_seconds_total', 'columns': self.columns, 'start': 0, 'end': 1000, 'labels': {'state': 'user'}}

    def test_generic_native_row_uses_configured_source_column_and_preserves_types(self):
        status, _, raw = self.request('POST', '/_lme/metrics', value=self.query, token=READ_TOKEN)
        self.assertEqual(status, 200)
        result = json.loads(raw)['output'][0]['records']
        self.assertEqual(result['rows'], [[500, 42.5, SOURCE, 's', 'sum', 'cumulative', 'user']])
        self.assertEqual(result['schema']['column_schemas'][0]['data_type'], 'TimestampMillisecond')
        sql = parse_qs(urlsplit(self.backend.received[-1][1]).query)['sql'][0]
        self.assertIn('WHERE "host_name"=\'physical:graph\' AND "greptime_timestamp">=to_timestamp_millis(0)', sql)
        self.assertNotIn('"host.name"', sql)

    def test_generic_cross_source_rows_and_caller_source_column_overrides_are_denied(self):
        for changed in [{'source_column': 'host.name'}, {'columns': [name for name in self.columns if name != 'host_name']}, {'labels': {'host_name': 'guest:graph'}}]:
            self.assertEqual(self.request('POST', '/_lme/metrics', value=dict(self.query, **changed), token=READ_TOKEN)[0], 400)
        self.assertEqual(self.backend.received, [])
        self.backend.result['output'][0]['records']['rows'][0][2] = 'guest:graph'
        status, _, raw = self.request('POST', '/_lme/metrics', value=self.query, token=READ_TOKEN)
        self.assertEqual(status, 502)
        self.assertNotIn(b'guest:graph', raw)


class BackendAuthenticationTests(GatewayFixture):
    def setUp(self):
        super().setUp()
        self.gateway.shutdown(); self.gateway.server_close()
        policy = json.loads(self.policy_path.read_text())
        policy['metrics_backend_admin'] = {'username': 'hertzbeat', 'password': 'synthetic-greptime-secret-00000000000000000'}
        self.policy_path.write_text(json.dumps(policy))
        config = GatewayConfig(backend_port=self.backend.server_port, listen_port=0, metrics_backend_port=self.backend.server_port)
        self.gateway = make_server(config, Policy.load(self.policy_path))
        self.gt = threading.Thread(target=self.gateway.serve_forever, daemon=True); self.gt.start()
        self.backend.results = {'/api/summary': {'code': 0, 'data': {'monitors': 'native-private-detail'}},
            '/v1/sql': {'code': 0, 'output': [{'records': {'schema': {'column_schemas': [{'name': 'Int64(1)', 'data_type': 'Int64'}]}, 'rows': [[1]], 'total_rows': 1}}]}}
        self.backend.required_auth = {'/api/summary': 'Basic '+base64.b64encode(('admin:'+ADMIN).encode()).decode(),
            '/v1/sql': 'Basic '+base64.b64encode(b'hertzbeat:synthetic-greptime-secret-00000000000000000').decode()}

    def probe(self, token=READ_TOKEN):
        return self.request('GET', '/_lme/backend-authentication', token=token)

    def test_native_admin_and_greptime_credentials_are_proven_by_fixed_queries_only(self):
        status, _, raw = self.probe()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), {'hertzbeat_authenticated': True, 'greptime_authenticated': True})
        self.assertEqual(self.backend.received[0][1], '/api/summary')
        self.assertEqual(parse_qs(urlsplit(self.backend.received[1][1]).query), {'db': ['public'], 'sql': ['SELECT 1']})
        self.assertNotIn(b'native-private-detail', raw)
        self.assertNotIn(ADMIN.encode(), raw)
        self.assertEqual(self.probe(token=TOKEN)[0], 403)
        self.assertEqual(self.probe(token=None)[0], 401)
        self.assertEqual(len(self.backend.received), 2)

    def test_rejected_native_credentials_and_invalid_query_results_never_claim_authentication(self):
        self.backend.required_auth['/v1/sql'] = 'Basic different'
        self.assertEqual(self.probe()[0], 502)
        self.backend.required_auth['/v1/sql'] = 'Basic '+base64.b64encode(b'hertzbeat:synthetic-greptime-secret-00000000000000000').decode()
        self.backend.results['/v1/sql']['output'][0]['records']['rows'] = [[0]]
        self.assertEqual(self.probe()[0], 502)
        self.backend.results['/api/summary'] = {'code': 1, 'data': {}}
        self.assertEqual(self.probe()[0], 502)


class WazuhGatewayTests(GatewayFixture):
    def setUp(self):
        super().setUp()
        import subprocess
        import ssl
        self.gateway.shutdown(); self.gateway.server_close()
        self.backend.shutdown(); self.backend.server_close()
        policy = json.loads(self.policy_path.read_text())
        policy['principals'][1].update(operations=['read_security'], agent_id='003', agent_name='graph-physical')
        self.policy_path.write_text(json.dumps(policy))
        cert = Path(self.temp.name)/'cert.pem'; key = Path(self.temp.name)/'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=gateway.test', '-addext', 'subjectAltName=DNS:gateway.test', '-keyout', str(key), '-out', str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
        self.backend = ThreadingHTTPServer(('127.0.0.1', 0), Backend)
        self.backend.socket = context.wrap_socket(self.backend.socket, server_side=True)
        self.backend.received = []; self.backend.status = 200
        self.backend.required_auth = {'/wazuh-alerts-4.x-*/_search': 'Basic '+base64.b64encode(('admin:'+ADMIN).encode()).decode()}
        self.backend.result = {'timed_out': False, '_shards': {'failed': 0}, 'hits': {'hits': [{'_id': 'canary-1', '_index': 'wazuh-alerts-4.x-1970.01.01', '_source': {
            'timestamp': '1970-01-01T00:00:00.500Z', 'agent': {'id': '003', 'name': 'graph-physical', 'private': 'extra'},
            'rule': {'id': '100550', 'level': 12, 'description': 'Synthetic canary'},
            'full_log': 'LME_SECURITY_CANARY run_id=test-run event_id=event-1', 'unrelated': 'native-private-detail'}}]}}
        self.bt = threading.Thread(target=self.backend.serve_forever, daemon=True); self.bt.start()
        self.cfg = dict(mode='wazuh', backend_port=self.backend.server_port, listen_port=0, max_body_bytes=4096, max_response_bytes=65536, backend_tls_server_name='gateway.test', backend_ca_file=str(cert))
        self.gateway = make_server(GatewayConfig(**self.cfg), Policy.load(self.policy_path))
        self.gt = threading.Thread(target=self.gateway.serve_forever, daemon=True); self.gt.start()
        self.query = {'run_id': 'test-run', 'event_id': 'event-1', 'start': 0, 'end': 1000}

    def canary(self, value=None, token=READ_TOKEN, headers=None):
        return self.request('POST', '/_lme/security-event', value=value or self.query, token=token, headers=headers)

    def test_tls_canary_query_injects_registered_agent_and_returns_only_bound_fields(self):
        status, headers, raw = self.canary()
        self.assertEqual(status, 200)
        returned = json.loads(raw)['hits']['hits'][0]['_source']
        self.assertEqual(returned['source_node'], SOURCE)
        self.assertEqual(returned['agent'], {'id': '003', 'name': 'graph-physical'})
        self.assertEqual(returned['rule']['id'], '100550')
        self.assertNotIn(b'native-private-detail', raw)
        self.assertNotIn(ADMIN, str(headers)+raw.decode())
        method, path, sent_headers, body = self.backend.received[-1]
        self.assertEqual((method, path), ('POST', '/wazuh-alerts-4.x-*/_search'))
        self.assertEqual(sent_headers['Host'], 'gateway.test')
        self.assertEqual(body['query']['bool']['filter'], [
            {'term': {'agent.id': '003'}}, {'term': {'agent.name': 'graph-physical'}}, {'term': {'rule.id': '100550'}},
            {'match_phrase': {'full_log': 'LME_SECURITY_CANARY run_id=test-run event_id=event-1'}},
            {'range': {'timestamp': {'gte': 0, 'lte': 1000, 'format': 'epoch_millis'}}}])
        self.assertEqual(body['size'], 1)
        self.assertEqual(body['sort'], [{'timestamp': 'desc'}])

    def test_wrong_operation_raw_paths_and_client_query_or_agent_overrides_are_denied(self):
        self.assertEqual(self.canary(token=TOKEN)[0], 403)
        self.assertEqual(self.canary(token=None)[0], 401)
        for extra in [{'agent_id': '999'}, {'agent_name': 'other'}, {'source_node': 'guest:graph'}, {'query': {'match_all': {}}}, {'index': '*'}, {'end': 99999999}, {'event_id': "x' OR 1=1"}]:
            self.assertIn(self.canary(dict(self.query, **extra))[0], (400, 403))
        for path in ['/_search', '/wazuh-alerts-4.x-*/_search', '/_security/user', '/_bulk', '/api/otlp/v1/logs']:
            self.assertEqual(self.request('POST', path, value={}, token=READ_TOKEN)[0], 404)
        self.assertEqual(self.backend.received, [])

    def test_tampered_agent_rule_marker_index_and_timestamp_responses_fail_closed(self):
        original = json.loads(json.dumps(self.backend.result))
        for change in [('agent', {'id': '004', 'name': 'graph-physical'}), ('agent', {'id': '003', 'name': 'other'}),
                       ('rule', {'id': '100551', 'level': 12, 'description': 'other'}),
                       ('full_log', 'LME_SECURITY_CANARY run_id=test-run event_id=event-10'),
                       ('timestamp', '1970-01-01T00:10:00.000Z'), ('source_node', 'guest:graph')]:
            self.backend.result = json.loads(json.dumps(original))
            self.backend.result['hits']['hits'][0]['_source'][change[0]] = change[1]
            status, _, raw = self.canary()
            self.assertEqual(status, 502, change[0])
            self.assertNotIn(b'guest:graph', raw)
        self.backend.result = original
        self.backend.result['hits']['hits'][0]['_index'] = 'other-index'
        self.assertEqual(self.canary()[0], 502)

    def test_empty_readback_and_own_registration_introspection_are_bounded(self):
        self.backend.result = {'hits': {'hits': []}}
        self.assertEqual(json.loads(self.canary()[2]), {'hits': {'hits': []}})
        result = json.loads(self.request('GET', '/_lme/authorization', token=READ_TOKEN)[2])
        self.assertEqual(result['agent_id'], '003')
        self.assertEqual(result['agent_name'], 'graph-physical')
        self.assertEqual(result['source'], SOURCE)
        self.assertNotIn(ADMIN, json.dumps(result))

    def test_real_alert_batch_has_fixed_source_filters_and_reports_complete_total(self):
        self.backend.result['hits']['total'] = {'value': 1, 'relation': 'eq'}
        source = self.backend.result['hits']['hits'][0]['_source']
        source['rule']['id'] = '5710'; source['full_log'] = 'Failed password for invalid user synthetic'
        status, _, raw = self.request('POST', '/_lme/security-events', value={'start': 0, 'end': 1000}, token=READ_TOKEN)
        self.assertEqual(status, 200)
        result = json.loads(raw)['hits']
        self.assertEqual(result['total'], {'value': 1, 'relation': 'eq'})
        self.assertEqual(result['hits'][0]['_source']['rule']['id'], '5710')
        self.assertEqual(result['hits'][0]['_source']['source_node'], SOURCE)
        body = self.backend.received[-1][3]
        self.assertEqual(body['size'], 101)
        self.assertTrue(body['track_total_hits'])
        self.assertEqual(body['query']['bool']['filter'], [
            {'term': {'agent.id': '003'}}, {'term': {'agent.name': 'graph-physical'}},
            {'range': {'timestamp': {'gte': 0, 'lte': 1000, 'format': 'epoch_millis'}}}])
        self.assertEqual(body['sort'], [{'timestamp': 'asc'}])

    def test_alert_batch_overflow_truncation_and_cross_source_never_advance_a_complete_window(self):
        original = json.loads(json.dumps(self.backend.result))
        self.backend.result['hits']['total'] = {'value': 101, 'relation': 'eq'}
        self.backend.result['hits']['hits'] = [dict(original['hits']['hits'][0], _id=str(index)) for index in range(101)]
        self.assertEqual(self.request('POST', '/_lme/security-events', value={'start': 0, 'end': 1000}, token=READ_TOKEN)[0], 409)
        self.backend.result = json.loads(json.dumps(original))
        self.backend.result['hits']['total'] = {'value': 2, 'relation': 'eq'}
        self.assertEqual(self.request('POST', '/_lme/security-events', value={'start': 0, 'end': 1000}, token=READ_TOKEN)[0], 502)
        self.backend.result['hits']['hits'] *= 2
        self.assertEqual(self.request('POST', '/_lme/security-events', value={'start': 0, 'end': 1000}, token=READ_TOKEN)[0], 502)
        self.backend.result['hits']['hits'] = self.backend.result['hits']['hits'][:1]
        self.backend.result['hits']['total'] = {'value': 1, 'relation': 'eq'}
        self.backend.result['hits']['hits'][0]['_source']['agent']['id'] = '004'
        self.assertEqual(self.request('POST', '/_lme/security-events', value={'start': 0, 'end': 1000}, token=READ_TOKEN)[0], 502)
        before = len(self.backend.received)
        self.assertEqual(self.request('POST', '/_lme/security-events', value={'start': 0, 'end': 1000, 'agent_id': '004'}, token=READ_TOKEN)[0], 400)
        self.assertEqual(len(self.backend.received), before)

    def test_wrong_backend_tls_hostname_is_rejected(self):
        self.gateway.shutdown(); self.gateway.server_close()
        self.gateway = make_server(GatewayConfig(**dict(self.cfg, backend_tls_server_name='wrong.test')), Policy.load(self.policy_path))
        self.gt = threading.Thread(target=self.gateway.serve_forever, daemon=True); self.gt.start()
        self.assertEqual(self.canary()[0], 502)
        self.assertEqual(self.backend.received, [])

    def test_security_policy_requires_registered_unique_agent_bindings(self):
        original = json.loads(self.policy_path.read_text())
        for changed in [{'agent_id': None}, {'agent_name': ''}, {'agent_id': '003 OR 1=1'}]:
            candidate = json.loads(json.dumps(original)); candidate['principals'][1].update(changed)
            self.policy_path.write_text(json.dumps(candidate))
            with self.assertRaises(ValueError): Policy.load(self.policy_path)
        candidate = json.loads(json.dumps(original))
        other = dict(candidate['principals'][1], name='other-reader', token='synthetic-other-security-token-000000000000', source='guest:graph')
        candidate['principals'].append(other); self.policy_path.write_text(json.dumps(candidate))
        with self.assertRaises(ValueError): Policy.load(self.policy_path)


class ConfigCliTests(unittest.TestCase):
    def test_check_config_reads_private_policy_without_listening_or_printing_secrets(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory)/'policy.json'
            policy.write_text(json.dumps({'backend_admin': {'username': 'admin', 'password': ADMIN}, 'principals': [{'name': 'test', 'token': TOKEN, 'source': SOURCE, 'operations': ['read_logs']}]}))
            policy.chmod(0o600)
            config = Path(directory)/'config.json'
            config.write_text(json.dumps({'policy_file': str(policy), 'listen_port': 1457}))
            completed = subprocess.run([sys.executable, '-m', 'lme_sink_proxy', 'check-config', '--config', str(config)], capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(json.loads(completed.stdout)['valid'])
            self.assertNotIn(TOKEN, completed.stdout+completed.stderr)
            self.assertNotIn(ADMIN, completed.stdout+completed.stderr)
            policy.chmod(0o644)
            refused = subprocess.run([sys.executable, '-m', 'lme_sink_proxy', 'check-config', '--config', str(config)], capture_output=True, text=True)
            self.assertEqual(refused.returncode, 2)
            self.assertNotIn(TOKEN, refused.stdout+refused.stderr)
            self.assertNotIn(ADMIN, refused.stdout+refused.stderr)

    def test_metric_source_columns_are_restricted_to_qualified_native_names(self):
        for source_column in ['agent.id', 'source_node', 'host_name OR 1=1', None]:
            with self.assertRaises(ValueError):
                GatewayConfig(metrics_tables={'metric': {'timestamp_column': 'ts', 'source_column': source_column, 'columns': ['ts', 'host.name', 'host_name', 'source_node', 'agent.id']}})

    def test_config_refuses_nonlocal_backends_and_listeners(self):
        for kwargs in [{'listen_host': '0.0.0.0'}, {'backend_host': 'example.com'}, {'mode': 'generic'}, {'mode': 'malcolm'}]:
            with self.assertRaises(ValueError):
                GatewayConfig(**kwargs)


if __name__ == '__main__':
    unittest.main()
