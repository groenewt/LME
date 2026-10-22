"""Synthetic tests cover ownership, idempotency, TLS inputs and secret handling."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

path = Path(__file__).resolve().parents[2] / 'ansible/roles/hertzbeat_platform/files/reconcile_monitors.py'
spec = importlib.util.spec_from_file_location('reconcile', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture():
    return [{'service_id': '11111111-1111-4111-8111-111111111111',
             'revision': '22222222-2222-4222-8222-222222222222',
             'definition': {'monitor': {'name': 'synthetic', 'app': 'jvm', 'intervals': 30},
                            'params': [{'field': 'ssl', 'paramValue': 'true'},
                                       {'field': 'username', 'paramValue': 'fixture'},
                                       {'field': 'password', 'paramValue': 'synthetic-only'}]}}]


class ReconcileTest(unittest.TestCase):
    def test_create_is_dry_run_by_default(self):
        calls = []
        def request(method, url, payload=None):
            calls.append(method)
            return []
        self.assertEqual(module.reconcile(module.prepare(fixture(), "fixture"), request, run_id="fixture")['created'], 1)
        self.assertEqual(calls, ['GET'] * len(module.MANAGED_APPS))

    def test_existing_identity_is_idempotent(self):
        desired = module.prepare(fixture(), "fixture")
        previous = copy.deepcopy(desired[0]['monitor'])
        previous['id'] = 4
        calls = []
        def request(method, url, payload=None):
            calls.append(method)
            return [previous] if url == '/api/monitors/jvm' else []
        self.assertEqual(module.reconcile(desired, request, True, run_id="fixture")['unchanged'], 1)
        self.assertEqual(calls, ['GET'] * len(module.MANAGED_APPS))

    def test_revision_rotation_updates_owned_identity(self):
        desired = module.prepare(fixture(), "fixture")
        previous = copy.deepcopy(desired[0]['monitor'])
        previous['id'] = 4
        previous['labels']['lme.revision'] = 'old'
        writes = []
        def request(method, url, payload=None):
            if method == 'GET':
                return [previous] if url == '/api/monitors/jvm' else []
            writes.append((method, payload['monitor']['id']))
        module.reconcile(desired, request, True, run_id="fixture")
        self.assertEqual(writes, [('PUT', 4)])

    def test_unmanaged_identity_is_never_modified(self):
        desired = module.prepare(fixture(), "fixture")
        unmanaged = copy.deepcopy(desired[0]['monitor'])
        unmanaged['labels']['lme.managed'] = 'false'
        methods = []
        def request(method, url, payload=None):
            methods.append(method)
            return [unmanaged] if url == '/api/monitors/jvm' else []
        module.reconcile(desired, request, True, run_id="fixture")
        self.assertEqual(methods, ['GET'] * len(module.MANAGED_APPS) + ['POST'])

    def test_reject_plaintext_and_duplicate_before_mutation(self):
        value = fixture()
        value[0]['definition']['params'][0]['paramValue'] = 'false'
        with self.assertRaises(ValueError):
            module.prepare(value, "fixture")
        with self.assertRaises(ValueError):
            module.prepare(fixture() * 2, "fixture")

    def test_empty_desired_deletes_only_exact_run_owned_monitors(self):
        owned = module.prepare(fixture(), 'fixture')[0]['monitor']
        owned['id'] = 4
        other = copy.deepcopy(owned)
        other['id'] = 5
        other['labels']['lme.run_id'] = 'another-run'
        legacy = copy.deepcopy(owned)
        legacy['id'] = 6
        del legacy['labels']['lme.run_id']
        unmanaged = copy.deepcopy(owned)
        unmanaged['id'] = 7
        unmanaged['labels']['lme.managed'] = 'false'
        calls = []
        def request(method, url, payload=None):
            calls.append((method, url))
            if url == '/api/monitors/jvm':
                return [owned, other, legacy, unmanaged]
            if url == '/api/monitor/4' and method == 'GET':
                return {'monitor': owned}
            return []
        result = module.reconcile([], request, True, run_id='fixture')
        self.assertEqual(result['deleted'], 1)
        self.assertEqual([call for call in calls if call[0] == 'DELETE'], [('DELETE', '/api/monitor/4')])

    def test_stale_removed_family_is_discovered_and_dry_run_preserves_it(self):
        owned = module.prepare(fixture(), 'fixture')[0]['monitor']
        owned['id'] = 4
        calls = []
        def request(method, url, payload=None):
            calls.append(method)
            return [owned] if url == '/api/monitors/jvm' else []
        self.assertEqual(module.reconcile([], request, run_id='fixture')['deleted'], 1)
        self.assertTrue(all(call == 'GET' for call in calls))

    def test_changed_ownership_prevents_delete(self):
        owned = module.prepare(fixture(), 'fixture')[0]['monitor']
        owned['id'] = 4
        changed = copy.deepcopy(owned)
        changed['labels']['lme.run_id'] = 'another-run'
        calls = []
        def request(method, url, payload=None):
            calls.append(method)
            if url == '/api/monitors/jvm':
                return [owned]
            if url == '/api/monitor/4':
                return {'monitor': changed}
            return []
        with self.assertRaises(ValueError):
            module.reconcile([], request, True, run_id='fixture')
        self.assertNotIn('DELETE', calls)

    def test_failed_desired_write_prevents_stale_delete(self):
        desired = module.prepare(fixture(), 'fixture')
        stale = copy.deepcopy(desired[0]['monitor'])
        stale['id'] = 4
        stale['labels']['lme.service_id'] = '33333333-3333-4333-8333-333333333333'
        calls = []
        def request(method, url, payload=None):
            calls.append(method)
            if method == 'POST':
                raise ValueError('synthetic native API rejection')
            return [stale] if url == '/api/monitors/jvm' else []
        with self.assertRaises(ValueError):
            module.reconcile(desired, request, True, run_id='fixture')
        self.assertNotIn('DELETE', calls)

    def test_missing_or_mismatched_run_rejected_before_api(self):
        with self.assertRaises(ValueError):
            module.prepare([], '')
        calls = []
        with self.assertRaises(ValueError):
            module.reconcile(module.prepare(fixture(), 'other'), lambda *args: calls.append(args), True, run_id='fixture')
        self.assertEqual(calls, [])

    def test_secrets_require_private_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic'
            path.write_text('sentinel-only')
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                module.private_text(path)
            path.chmod(0o600)
            self.assertEqual(module.private_text(path), 'sentinel-only')


if __name__ == '__main__':
    unittest.main()
