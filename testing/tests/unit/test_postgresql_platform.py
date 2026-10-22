"""Offline database contracts; run with python3 -m unittest discover here."""
import ast
import copy
import importlib
import json
import pathlib
import base64
import subprocess
import tempfile
import time
from unittest.mock import patch
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]


class PlatformTests(unittest.TestCase):
    def api(self):
        try:
            return importlib.import_module('scripts.postgresql_platform.platform')
        except ModuleNotFoundError:
            self.fail('PostgreSQL platform implementation is missing')

    def test_dual_ownership_and_shared_has_no_imports(self):
        api = self.api()
        dual = api.topology('dual-owned-ha')
        self.assertEqual(dual['domains']['hertzbeat']['initial_owner'], 'trixie')
        self.assertEqual(dual['domains']['vector']['databases'], ['lme_vectors', 'litellm'])
        self.assertEqual(len(dual['paths']), 3)
        shared = api.topology('shared-ha')
        self.assertEqual(list(shared['domains']), ['shared'])
        self.assertEqual(shared['paths'], [])
        with self.assertRaises(ValueError):
            api.topology('')

    def test_publications_exclude_corpus_and_imports(self):
        api = self.api()
        sql = api.publication_sql('lme_vectors')
        self.assertIn('docs_chunks (id, chunk_index, created_at)', sql)
        self.assertNotIn('content', sql)
        self.assertNotIn('url', sql)
        self.assertNotIn('TRUNCATE', sql)
        with self.assertRaises(ValueError):
            api.publication_sql('lme_vectors_replica')

    def test_subscription_strict_tls_and_failover(self):
        api = self.api()
        sql = api.subscription_sql('lme_vectors', 'pg-vector-rw', '/run/secrets/replication.pass')
        for required in ('sslmode=verify-full', 'origin = none', 'failover = true', "synchronous_commit = on"):
            self.assertIn(required, sql)
        with self.assertRaises(ValueError):
            api.subscription_sql('lme_vectors', "host' sslmode=disable", '/tmp/pass')

    def test_slot_readiness_rejects_missing_and_incomplete_sync(self):
        api = self.api()
        good = {'slot_name': 'sub_vectors', 'synced': True, 'temporary': False, 'invalidation_reason': None, 'failover': True}
        self.assertTrue(api.slots_ready(['sub_vectors'], [good]))
        self.assertFalse(api.slots_ready(['sub_vectors', 'pg_10_sync_11_12'], [good]))
        self.assertFalse(api.slots_ready([], []))
        self.assertFalse(api.slots_ready(['sub_vectors'], [{**good, 'synced': False}]))

    def test_render_has_strict_sync_distinct_namespaces_and_pinned_images(self):
        api = self.api()
        config = {'profile': 'dual-owned-ha', 'run_id': 'fixture', 'node': 'graph', 'qemu_generation':'00000000-0000-0000-0000-000000000001',
                  'hosts': {name: {'address': name + '.example.test', 'cidr': '10.1.1.' + str(i) + '/32'} for i, name in enumerate(('graph', 'trixie', 'silmaril'), 1)},
                  'images': {'patroni': 'localhost/lme-patroni:17.11-4.1.3@sha256:' + 'a' * 64,
                             'etcd': 'quay.io/coreos/etcd:v3.6.4@sha256:' + 'b' * 64},
                  'backup': {'repository_host': 'backup.example.test', 'repository_path': '/backup/lme', 'retention_full': 2}}
        result = api.render(config)
        self.assertIn('pg1-socket-path=/tmp', result['pgbackrest-vector.conf'])
        first, second = json.loads(result['patroni-hertzbeat.json']), json.loads(result['patroni-vector.json'])
        self.assertNotEqual(first['namespace'], second['namespace'])
        for member in (first, second):
            dcs = member['bootstrap']['dcs']
            self.assertIs(dcs['synchronous_mode_strict'], True)
            self.assertIs(dcs['failsafe_mode'], False)
            self.assertEqual(dcs['synchronous_node_count'], 1)
            self.assertEqual(dcs['postgresql']['parameters']['synchronous_commit'], 'on')
            self.assertIn('gate-live', member['postgresql']['pre_promote'])
            self.assertIn('--action promote', member['postgresql']['pre_promote'])
            self.assertIn('--action bootstrap', member['bootstrap']['guarded']['command'])
            self.assertNotIn('context.json', member['postgresql']['pre_promote'])
        for unit in ('pg-hertzbeat.container','pg-vector.container','pg-etcd.container'):
            self.assertIn('LogDriver=journald',result[unit])
        with self.assertRaises(ValueError):
            api.render({**config, 'images': {**config['images'], 'patroni': 'image:latest'}})
        with self.assertRaises(ValueError):
            api.render({**config, 'backup': {**config['backup'], 'repository_host': 'graph.example.test'}})

    def test_fence_receipt_binding_expiry_and_no_empty_writer_bypass(self):
        api = self.api()
        context = {'run_id': 'test', 'domain': 'vector', 'candidate': {'node': 'graph', 'qemu_generation': 'g2'}, 'authority': {'epoch': 3, 'lease': 'lease'}, 'action': 'promote', 'request_nonce': 'nonce', 'prior_writers': [{'node': 'trixie', 'qemu_generation': 'g1'}]}
        receipt = {**context, 'issued_at': 100, 'expires_at': 150, 'quarantined_candidate': True, 'initial_generation_permit': False, 'prior_writers': [{**context['prior_writers'][0], 'stopped': True, 'restart_inhibited': True}]}
        api.validate_receipt(receipt, context, now=110)
        for update in ({'expires_at': 105}, {'prior_writers': []}, {'quarantined_candidate': False}, {'domain': 'hertzbeat'}):
            with self.assertRaises(ValueError):
                api.validate_receipt({**receipt, **update}, context, now=110)
        with self.assertRaises(ValueError):
            api.validate_receipt({**receipt, 'prior_writers': []}, {**context, 'prior_writers': []}, now=110)

    def test_signed_gate_requires_fresh_matching_consumption_and_rejects_replay(self):
        api = self.api()
        now = time.time()
        context = {'run_id': 'test', 'domain': 'vector', 'candidate': {'node': 'graph', 'qemu_generation': 'g2'}, 'authority': {'epoch': 3, 'lease': 'lease'}, 'action': 'promote', 'request_nonce': 'nonce', 'prior_writers': [{'node': 'trixie', 'qemu_generation': 'g1'}]}
        payload = {**context, 'issued_at': now, 'expires_at': now + 30, 'quarantined_candidate': True, 'prior_writers': [{**context['prior_writers'][0], 'stopped': True, 'restart_inhibited': True}]}
        with tempfile.TemporaryDirectory() as tmp:
            private, public = pathlib.Path(tmp) / 'key', pathlib.Path(tmp) / 'pub'
            subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(private)], check=True, capture_output=True)
            subprocess.run(['openssl','pkey','-in',str(private),'-pubout','-out',str(public)], check=True, capture_output=True)
            def sign(value):
                message = pathlib.Path(tmp) / 'message'
                message.write_bytes(api.canonical(value))
                sig = subprocess.run(['openssl','pkeyutl','-sign','-inkey',str(private),'-rawin','-in',str(message)], check=True,capture_output=True).stdout
                return {'payload': value, 'signature': base64.b64encode(sig).decode()}
            receipt = sign(payload)
            used = set()
            def consume(path, request, timeout=3):
                self.assertEqual(timeout,15)
                # Boundary stand-in: production CAS implementation is guardian-owned.
                consumed = context['request_nonce'] not in used
                used.add(context['request_nonce'])
                return sign({**context, 'issued_at': time.time(), 'expires_at': time.time()+4,
                             'challenge':request['challenge'], 'receipt_sha256':request['receipt_sha256'],
                             'consumed':consumed,'quorum':True,'leader_authorized':True})
            with patch.object(api, 'authority_request', side_effect=consume):
                self.assertTrue(api.gate(context, receipt, public, '/tmp/guardian.sock'))
                with self.assertRaises(ValueError):
                    api.gate(context, receipt, public, '/tmp/guardian.sock')
            receipt['payload'] = {**payload, 'domain':'hertzbeat'}
            with self.assertRaises(ValueError):
                api.verify_envelope(receipt, public)

    def test_live_gate_requests_fresh_guardian_context_and_rejects_response_rebinding(self):
        api=self.api()
        config={'profile':'dual-owned-ha','run_id':'fixture','node':'graph','qemu_generation':'00000000-0000-0000-0000-000000000001'}
        def authorize(path,request,timeout=3):
            context={'run_id':request['run_id'],'domain':request['domain'],'candidate':{'node':request['node'],'qemu_generation':request['qemu_generation']},'action':request['action'],'authority':{'epoch':5,'lease':'6'},'request_nonce':'fresh','prior_writers':[]}
            return {'payload':dict(request,context=context,receipt={'payload':context},issued_at=time.time(),expires_at=time.time()+20)}
        with patch.object(api,'authority_request',side_effect=authorize) as request, patch.object(api,'verify_envelope',side_effect=lambda envelope,key: envelope['payload']), patch.object(api,'gate',return_value=True) as consume:
            self.assertTrue(api.live_gate(config,'vector','promote','public','/run/guardian.sock'))
            self.assertEqual(request.call_args.kwargs['timeout'],180)
            self.assertEqual(consume.call_args.args[0]['authority'],{'epoch':5,'lease':'6'})
            def rebound(path,request,timeout=3):
                envelope=authorize(path,request,timeout)
                envelope['payload']['context']['candidate']['qemu_generation']='other'
                return envelope
            request.side_effect=rebound
            with self.assertRaises(ValueError): api.live_gate(config,'vector','promote','public','/run/guardian.sock')
            self.assertEqual(consume.call_count,1)

    def test_proxy_route_rejects_stale_unfenced_or_unlisted_primary(self):
        api = self.api()
        context = {'run_id': 'test', 'domain': 'vector', 'node': 'graph', 'owner': 'lmedbvector', 'challenge': 'random'}
        route = {**context, 'quorum': True, 'leader_authorized': True, 'fenced': True,
                 'primary_node': 'graph', 'host': 'graph.test', 'port': 5434,
                 'authority': {'epoch': 1, 'lease': 'a'}, 'issued_at': 100, 'expires_at': 104}
        allowed = {'graph': {'host': 'graph.test', 'port': 5434}}
        api.validate_route(route, context, allowed, now=101)
        for change in ({'host':'attacker.test'}, {'fenced':False}, {'quorum':False}, {'challenge':'old'}, {'expires_at':100}):
            with self.assertRaises(ValueError):
                api.validate_route({**route, **change}, context, allowed, now=101)

    def test_resolved_role_config_rejects_missing_artifacts_before_render(self):
        api = self.api()
        topo = {'run_id':'test','profiles':{'database':'dual-owned-ha'},'hosts':{},'artifacts':{}}
        with self.assertRaises(ValueError):
            api.resolved_role_config(topo, 'graph', {'run_id':'test','grants':[]})



class ResetTests(unittest.TestCase):
    def test_reset_preserves_relation_and_sequence(self):
        # Execute the actual setup function through a transactional SQL boundary.
        # A DROP or TRUNCATE is forbidden because it changes logical identity or sequences.
        for path in ('scripts/ingest_docs.py', 'lme-dashboard/scripts/ingest_docs.py'):
            tree = ast.parse((ROOT / path).read_text())
            function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'setup_db')
            namespace = {'EMBED_DIMS': 768}
            exec(compile(ast.Module(body=[function], type_ignores=[]), path, 'exec'), namespace)
            conn = ResetConnection()
            namespace['setup_db'](conn, reset=True)
            self.assertEqual(conn.rows, [])
            self.assertEqual(conn.sequence, 42)
            self.assertEqual(conn.oid, 1234)
            self.assertEqual(conn.commits, 1)


class ResetConnection:
    def __init__(self):
        self.rows, self.sequence, self.oid, self.commits = [1, 2], 42, 1234, 0
    def cursor(self): return self
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def execute(self, sql):
        sql = sql.strip().upper()
        if sql.startswith(('DROP', 'TRUNCATE')):
            raise AssertionError('reset must preserve publication relation identity and sequence')
        if sql.startswith('DELETE FROM DOCS_CHUNKS'):
            self.rows = []
    def commit(self): self.commits += 1


if __name__ == '__main__': unittest.main()
