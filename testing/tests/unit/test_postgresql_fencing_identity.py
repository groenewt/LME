"""D wave: deployment-identity threading, required-material superset, observed-generation
fence and rejoin restart-serialization. Offline only -- no guests, DB, sockets or host.

Covers finding IDs:
  D-REQUIRED-MATERIAL-PLACEMENTS   (guardian.pub db-owner + etcd-owner set superset)
  FENCE-CURRENT-GENERATION-AND-AUTHORITY (deployment_identity threaded; observed-gen check)
  REJOIN-RESTART-SERIALIZATION     (authorization revoked before the datadir rename)
  DEPLOYMENT-IDENTITY (storage/fencing side): missing/malformed identity rejects pre-mutation
"""
import json
import subprocess
import time
import unittest
import uuid
from pathlib import Path

from scripts.postgresql_platform import platform, rejoin


DB_FILES = ('pg-ca.crt', 'pg-server.crt', 'pg-server.key', 'admin.crt', 'admin.key', 'admin.pgpass',
            'pg_service.conf', 'role-passwords.json', 'patroni.env', 'etcd-ca.crt', 'etcd-client.crt',
            'etcd-client.key', 'backup-ca.crt', 'backup-client.crt', 'backup-client.key', 'guardian.pub')
ETCD_FILES = ('etcd-ca.crt', 'etcd-server.crt', 'etcd-server.key')


def grants_for_graph():
    grants = []
    for domain, owner in (('hertzbeat', 'lmedbhb'), ('vector', 'lmedbvector')):
        for name in DB_FILES:
            grants.append({'node': 'graph', 'owner': owner, 'destination': f'/data/{owner}/secrets/postgresql/{name}'})
    for name in ETCD_FILES:
        grants.append({'node': 'graph', 'owner': 'lmedcs', 'destination': f'/data/lmedcs/secrets/postgresql/{name}'})
    return grants


def full_resolved():
    owners_map = {'db-hertzbeat': 'lmedbhb', 'db-vector': 'lmedbvector', 'etcd': 'lmedcs'}
    hosts = {}
    for i, name in enumerate(('graph', 'trixie', 'silmaril'), 1):
        hosts[name] = {'fqdn': name + '.example.test', 'tailscale_address': '100.64.0.' + str(i),
                       'owners': dict(owners_map), 'resolved_services': {},
                       'qemu_generation': '00000000-0000-0000-0000-00000000000' + str(i)}
    guard = {'graph': 'trixie', 'trixie': 'silmaril', 'silmaril': 'graph'}
    return {'run_id': 'fixture', 'deployment_identity': 'lmedeploy01', 'profiles': {'database': 'dual-owned-ha'},
            'artifacts': {'patroni': {'reference': 'localhost/lme-patroni:17@sha256:' + 'a' * 64},
                          'etcd': {'reference': 'quay.io/etcd:v3@sha256:' + 'b' * 64}},
            'hosts': hosts,
            'database': {'backup': {'repository_host': 'backup.example.test', 'repository_path': '/backup/lme', 'retention_full': 2},
                         'slot_guard_standby': {'hertzbeat': dict(guard), 'vector': dict(guard)}},
            'providers': {'db-hertzbeat': {'memory_mib': 768}, 'db-vector': {'memory_mib': 768},
                          'etcd': {'memory_mib': 256}, 'db-proxy-hertzbeat': {'memory_mib': 64}}}


class DeploymentIdentityAndMaterial(unittest.TestCase):
    def test_full_grant_set_threads_deployment_identity(self):
        result = platform.resolved_role_config(full_resolved(), 'graph', {'run_id': 'fixture', 'grants': grants_for_graph()})
        cfg = result['postgresql_platform_config']
        self.assertEqual(cfg['deployment_identity'], 'lmedeploy01')
        self.assertEqual(cfg['node'], 'graph')

    def test_missing_or_malformed_identity_rejects_before_mutation(self):
        base = full_resolved()
        for bad in (None, '', 'has space', 'bad!id', 'a' * 65):
            resolved = full_resolved()
            if bad is None:
                del resolved['deployment_identity']
            else:
                resolved['deployment_identity'] = bad
            with self.assertRaises(ValueError):
                platform.resolved_role_config(resolved, 'graph', {'run_id': 'fixture', 'grants': grants_for_graph()})
        # control: the same fixture with a valid identity succeeds
        platform.resolved_role_config(base, 'graph', {'run_id': 'fixture', 'grants': grants_for_graph()})

    def test_each_added_obligation_is_required(self):
        # guardian.pub in a db-owner secrets dir, and each etcd-owner file, must be granted.
        for owner, missing in (('lmedbvector', 'guardian.pub'), ('lmedbhb', 'guardian.pub'),
                               ('lmedcs', 'etcd-ca.crt'), ('lmedcs', 'etcd-server.crt'), ('lmedcs', 'etcd-server.key')):
            grants = [g for g in grants_for_graph()
                      if g['destination'] != f'/data/{owner}/secrets/postgresql/{missing}']
            with self.assertRaises(ValueError):
                platform.resolved_role_config(full_resolved(), 'graph', {'run_id': 'fixture', 'grants': grants})

    def test_proxy_config_guardian_pub_does_not_satisfy_db_owner_secrets_obligation(self):
        # Replace the db-owner SECRETS guardian.pub with the proxy CONFIG-dir placement only.
        grants = [g for g in grants_for_graph()
                  if g['destination'] != '/data/lmedbvector/secrets/postgresql/guardian.pub']
        grants.append({'node': 'graph', 'owner': 'lmedbvector', 'destination': '/data/lmedbvector/config/postgresql/guardian.pub'})
        with self.assertRaises(ValueError):
            platform.resolved_role_config(full_resolved(), 'graph', {'run_id': 'fixture', 'grants': grants})


def render_config(deployment_identity='lmedeploy01'):
    cfg = {'profile': 'dual-owned-ha', 'run_id': 'fixture', 'node': 'graph',
           'qemu_generation': '00000000-0000-0000-0000-000000000001',
           'hosts': {name: {'address': name + '.example.test', 'cidr': '10.1.1.' + str(i) + '/32'}
                     for i, name in enumerate(('graph', 'trixie', 'silmaril'), 1)},
           'images': {'patroni': 'localhost/lme-patroni:17@sha256:' + 'a' * 64,
                      'etcd': 'quay.io/coreos/etcd:v3.6.4@sha256:' + 'b' * 64},
           'backup': {'repository_host': 'backup.example.test', 'repository_path': '/backup/lme', 'retention_full': 2}}
    if deployment_identity is not None:
        cfg['deployment_identity'] = deployment_identity
    return cfg


class ObservedGenerationFence(unittest.TestCase):
    GEN = '00000000-0000-0000-0000-000000000001'

    def fence_body(self, tmp, authz_path, instance_path):
        files = platform.render(render_config())
        unit = files['pg-vector.container']
        line = next(l for l in unit.splitlines() if l.startswith('ExecStartPre=/bin/sh -c '))
        body = line.split("-c '", 1)[1].rsplit("'", 1)[0]
        # Simulate systemd $-/%-expansion, then redirect the two absolute paths at tmp files.
        body = body.replace('$$', '$').replace('%%', '%')
        body = body.replace('/var/lib/lme-fencing/authorize/lmedeploy01/vector/graph', str(authz_path))
        body = body.replace('/var/lib/cloud/data/instance-id', str(instance_path))
        return body

    def run_body(self, body):
        return subprocess.run(['sh', '-c', body]).returncode

    def test_allow_and_all_deny_cases(self):
        import tempfile
        with tempfile.TemporaryDirectory(prefix='lme-fence-') as d:
            tmp = Path(d)
            authz, instance = tmp / 'authz', tmp / 'instance-id'
            body = self.fence_body(tmp, authz, instance)
            future, past = int(time.time()) + 3600, int(time.time()) - 10
            good_line1 = f'authorize lmedeploy01 vector graph {self.GEN}'

            def write(gen, line1, epoch, make_authz=True, make_instance=True):
                if make_instance:
                    instance.write_text(gen)
                elif instance.exists():
                    instance.unlink()
                if make_authz:
                    authz.write_text(line1 + '\n' + str(epoch) + '\n')
                elif authz.exists():
                    authz.unlink()

            # allow
            write(self.GEN, good_line1, future)
            self.assertEqual(self.run_body(body), 0)
            # observed-generation drift (guest rebooted to a new generation)
            write(str(uuid.UUID('00000000-0000-0000-0000-0000000000ff')), good_line1, future)
            self.assertEqual(self.run_body(body), 255)
            # missing observed instance-id -> deny
            write(self.GEN, good_line1, future, make_instance=False)
            self.assertEqual(self.run_body(body), 255)
            # missing authorization -> deny
            write(self.GEN, good_line1, future, make_authz=False)
            self.assertEqual(self.run_body(body), 255)
            # stale epoch -> deny
            write(self.GEN, good_line1, past)
            self.assertEqual(self.run_body(body), 255)
            # wrong-domain authorization -> deny
            write(self.GEN, f'authorize lmedeploy01 hertzbeat graph {self.GEN}', future)
            self.assertEqual(self.run_body(body), 255)

    def test_unresolved_identity_denies_unconditionally(self):
        files = platform.render(render_config(deployment_identity=None))
        unit = files['pg-vector.container']
        self.assertIn('stable deployment identity unresolved', unit)


def rejoin_fixture(tmp_path, deployment_identity='lmedeploy01'):
    config = {'run_id': 'owned-run', 'node': 'graph', 'profile': 'dual-owned-ha',
              'owners': {'vector': 'lmedbvector'}, 'deployment_identity': deployment_identity,
              'hosts': {node: {'address': node + '.example.ts.net'} for node in rejoin.NODES}}
    request = {'schema_version': 1, 'run_id': 'owned-run', 'domain': 'vector', 'node': 'graph',
               'qemu_generation': 'owned-generation', 'request_nonce': 'a' * 32}
    root = tmp_path / 'member'
    old = root / 'vector'
    old.mkdir(parents=True)
    (old / 'PG_VERSION').write_text('17\n')
    (old / 'valuable-old-data').write_text('retain this')
    inhibit = tmp_path / 'inhibit' / 'owned-run' / 'vector' / 'graph'
    inhibit.parent.mkdir(parents=True)
    inhibit.write_text('owned-generation')
    identity = tmp_path / 'instance-id'
    identity.write_text('owned-generation')
    authorize_root = tmp_path / 'authorize'
    route = {'primary_node': 'trixie', 'authority': {'epoch': 20, 'lease': '30'}}
    observed = {'system_identifier': '123456789', 'timeline': 3, 'lsn': '0/200', 'recovery': False,
                'ssl': True, 'server_address': '100.64.0.2', 'server_port': 5434}
    calls = []

    def command(argv, **kwargs):
        calls.append(argv)
        if argv[0] == 'psql':
            return subprocess.CompletedProcess(argv, 0, json.dumps(observed), '')
        if argv[0] == 'pg_basebackup':
            stage = Path(argv[argv.index('--pgdata') + 1])
            stage.mkdir()
            (stage / 'PG_VERSION').write_text('17\n')
            (stage / 'postgresql.auto.conf').write_text('')
            (stage / 'backup_manifest').write_text(json.dumps({'PostgreSQL-Backup-Manifest-Version': 2,
                'System-Identifier': 123456789, 'WAL-Ranges': [{'Timeline': 3, 'Start-LSN': '0/100', 'End-LSN': '0/300'}]}))
        if argv[0] == 'pg_controldata':
            return subprocess.CompletedProcess(argv, 0, "Database system identifier:            123456789\nLatest checkpoint's TimeLineID:        3\n", '')
        return subprocess.CompletedProcess(argv, 0, '', '')

    def probe(stage, minimum, **kwargs):
        return dict(observed, recovery=True, read_only='on', receiver_status='streaming', lsn='0/300')

    kwargs = {'root': root, 'inhibitor_root': tmp_path / 'inhibit', 'identity_path': identity,
              'authorize_root': authorize_root, 'command': command,
              'route_reader': lambda cfg, domain: dict(route), 'replica_probe': probe}
    return config, request, kwargs, calls, authorize_root


class RejoinRestartSerialization(unittest.TestCase):
    def test_live_authorization_refuses_rebuild_before_any_native_access(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            config, request, kwargs, calls, authorize_root = rejoin_fixture(Path(d))
            authz = authorize_root / 'lmedeploy01' / 'vector' / 'graph'
            authz.parent.mkdir(parents=True)
            authz.write_text('authorize lmedeploy01 vector graph owned-generation\n9999999999\n')
            with self.assertRaises(ValueError):
                rejoin.rebuild(config, 'vector', request, **kwargs)
            self.assertEqual(calls, [])   # refused at quarantine(), before native commands

    def test_revoked_authorization_absent_allows_verified_rebuild(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            config, request, kwargs, calls, _ = rejoin_fixture(Path(d))
            result = rejoin.rebuild(config, 'vector', request, **kwargs)   # no authorize file present
            self.assertEqual(result['replica']['recovery'], True)
            self.assertTrue(Path(result['retained_directory']).joinpath('valuable-old-data').read_text() == 'retain this')


if __name__ == '__main__':
    unittest.main()
