"""Actual HTTPS fixtures test the CLI boundary; they are not live HB acceptance."""
import copy
import importlib.util
import json
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


ROOT = Path(__file__).resolve().parents[2]
FILE = ROOT / 'ansible/roles/hertzbeat_platform/files/native_probe.py'
spec = importlib.util.spec_from_file_location('native_probe', FILE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)
AUTH = 'Basic c3ludGhldGljOm5vdC1hLXJlYWwtc2VjcmV0'
SERVICE = '11111111-1111-4111-8111-111111111111'
REVISION = '22222222-2222-4222-8222-222222222222'
TOKEN = '33333333-3333-4333-8333-333333333333'


def expected(app='lme-elasticsearch-jmx', identifier=101):
    value = {'id': identifier, 'service_id': SERVICE, 'revision': REVISION,
             'source_id': 'guest:graph', 'app': app, 'host': 'synthetic-graph.invalid',
             'port': {'lme-elasticsearch-jmx': 19010, 'lme-elasticsearch-rest': 9200, 'lme-service-ssh': 22}[app]}
    if app == 'lme-service-ssh':
        value['service_token'] = TOKEN
    return value


def dto(value):
    params = [{'field': key, 'paramValue': val} for key, val in
              [('host', value['host']), ('port', str(value['port'])), ('username', 'synthetic-only')]]
    params.append({'field': 'privateKey' if value['app'] == 'lme-service-ssh' else 'password',
                   'paramValue': '********', 'type': 2})
    if value['app'] == 'lme-service-ssh':
        params.append({'field': 'serviceToken', 'paramValue': TOKEN})
    return {'monitor': {'id': value['id'], 'app': value['app'], 'name': 'synthetic-only',
                        'labels': {'lme.managed': 'true', 'lme.run_id': 'synthetic-only', 'lme.service_id': SERVICE,
                                   'lme.revision': REVISION, 'host.name': value['source_id']}},
            'params': params}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, value):
        raw = json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self.server.calls.append(('GET', self.path))
        if self.headers.get('Authorization') != AUTH:
            self.reply(401, {'code': 15, 'msg': 'synthetic denied'})
        elif self.path.startswith('/api/apps/'):
            app = self.path.split('/')[3]
            text = (ROOT / '.integrations/hertzbeat/hertzbeat-manager/src/main/resources/define' / ('app-' + app + '.yml')).read_text()
            self.reply(200, {'code': 0, 'data': text + self.server.template_suffix})
        else:
            identifier = int(self.path.rsplit('/', 1)[1])
            self.reply(200, {'code': 0, 'data': self.server.monitors[identifier]})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers['Content-Length']))
        self.server.calls.append(('POST', self.path))
        self.server.posts.append(json.loads(raw))
        self.reply(*self.server.detect_response)


class NativeProbeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.material = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.material.name) / 'server.crt'
        cls.key = Path(cls.material.name) / 'server.key'
        cls.other = Path(cls.material.name) / 'other.crt'
        for cert, key in [(cls.cert, cls.key), (cls.other, Path(cls.material.name) / 'other.key')]:
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=synthetic-only', '-addext', 'subjectAltName=DNS:localhost',
                            '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.material.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.auth = Path(self.temp.name) / 'authorization'
        self.auth.write_text(AUTH); self.auth.chmod(0o600)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert, self.key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.server.calls, self.server.posts = [], []
        self.server.template_suffix = ''
        self.server.detect_response = (200, {'code': 0, 'msg': 'Detect success.', 'data': None})
        self.config = {'run_id': 'synthetic-only', 'deadline_seconds': 30,
                       'api': {'origin': 'https://localhost:' + str(self.server.server_port),
                               'ca_file': str(self.cert), 'authorization_file': str(self.auth)},
                       'monitors': [expected()]}
        self.server.monitors = {101: dto(self.config['monitors'][0])}
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.temp.cleanup()

    def test_real_https_native_request_and_no_invented_collector_negotiation(self):
        result = probe.run(self.config)
        self.assertTrue(result['passed'])
        row = result['results'][0]
        self.assertEqual(row['priority_zero_group'], 'threads')
        self.assertEqual(row['native_detect']['code'], 0)
        self.assertIn(row['api_tls']['version'], ('TLSv1.2', 'TLSv1.3'))
        self.assertIsNone(row['collector_negotiated_transport'])
        self.assertIsNone(row['sample_fields'])
        self.assertEqual(self.server.posts[0]['params'], self.server.monitors[101]['params'])

    def test_ssh_rest_and_jmx_all_use_exact_qualified_native_templates(self):
        self.config['monitors'] = [expected(app, index) for index, app in enumerate(probe.TEMPLATES, 101)]
        self.server.monitors = {item['id']: dto(item) for item in self.config['monitors']}
        result = probe.run(self.config)
        self.assertEqual(len(result['results']), 3)
        self.assertTrue(result['passed'])
        self.assertEqual(len(self.server.posts), 3)

    def test_template_drift_and_wrong_target_rejected_before_detect(self):
        self.server.template_suffix = '\n# synthetic drift\n'
        with self.assertRaises(ValueError): probe.run(self.config)
        self.assertEqual(self.server.posts, [])
        self.server.template_suffix = ''
        self.server.monitors[101]['params'][0]['paramValue'] = 'unapproved.invalid'
        with self.assertRaises(ValueError): probe.run(self.config)
        self.assertEqual(self.server.posts, [])

    def test_unowned_monitor_is_not_detected(self):
        self.server.monitors[101]['monitor']['labels']['lme.managed'] = 'false'
        with self.assertRaises(ValueError): probe.run(self.config)
        self.assertEqual(self.server.posts, [])

    def test_native_failure_code_is_distinct_from_validation_failure(self):
        self.config['monitors'][0].update(expect='detect_failed', failure_category='certificate')
        self.server.detect_response = (400, {'code': 2, 'msg': 'PKIX certificate rejected, synthetic-secret-must-not-leak'})
        result = probe.run(self.config)
        self.assertTrue(result['passed'])
        self.assertNotIn('synthetic-secret-must-not-leak', json.dumps(result))
        self.server.detect_response = (400, {'code': 1, 'msg': 'PKIX certificate invalid parameter'})
        self.assertFalse(probe.run(self.config)['passed'])

    def test_timeout_or_generic_success_cannot_pass_a_security_fixture(self):
        self.config['monitors'][0].update(expect='detect_failed', failure_category='authentication')
        self.server.detect_response = (400, {'code': 2, 'msg': 'Collect Timeout No Response'})
        self.assertFalse(probe.run(self.config)['passed'])
        self.config['monitors'][0]['expect'] = 'detect_success'
        self.server.detect_response = (200, {'code': 0, 'msg': 'Healthy'})
        self.assertFalse(probe.run(self.config)['passed'])

    def test_wrong_ca_wrong_hostname_and_wrong_authorization_fail(self):
        self.config['api']['ca_file'] = str(self.other)
        with self.assertRaises(ssl.SSLCertVerificationError): probe.run(self.config)
        self.config['api']['ca_file'] = str(self.cert)
        self.config['api']['origin'] = 'https://127.0.0.1:' + str(self.server.server_port)
        with self.assertRaises(ssl.SSLCertVerificationError): probe.run(self.config)
        self.config['api']['origin'] = 'https://localhost:' + str(self.server.server_port)
        self.auth.write_text('Bearer synthetic-invalid-token')
        with self.assertRaises(ValueError): probe.run(self.config)
        self.assertEqual(self.server.posts, [])

    def test_cli_emits_bounded_safe_native_observation(self):
        path = Path(self.temp.name) / 'config.json'
        path.write_text(json.dumps(self.config))
        result = subprocess.run([sys.executable, str(FILE), '--config', str(path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)['passed'])
        self.assertNotIn(AUTH, result.stdout)
        self.assertNotIn('********', result.stdout)

    def test_invalid_roster_and_public_or_symlink_secret_rejected(self):
        self.auth.chmod(0o644)
        with self.assertRaises(ValueError): probe.run(self.config)
        self.auth.chmod(0o600)
        linked = Path(self.temp.name) / 'link'; linked.symlink_to(self.auth)
        self.config['api']['authorization_file'] = str(linked)
        with self.assertRaises(OSError): probe.run(self.config)
        self.config['monitors'][0]['app'] = 'windows'
        with self.assertRaises(ValueError): probe.run(self.config)
        self.assertEqual(self.server.calls, [])


if __name__ == '__main__':
    unittest.main()
