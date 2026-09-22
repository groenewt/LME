"""Rebuild tests use disposable trees and a native-command boundary, never guests."""
import json
from pathlib import Path
import subprocess
import pytest

from scripts.postgresql_platform import rejoin


def fixture(tmp_path):
    config = {'run_id': 'owned-run', 'node': 'graph', 'profile': 'dual-owned-ha',
              'owners': {'vector': 'lmedbvector'},
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
        assert (stage / 'standby.signal').is_file()
        assert 'sslmode=verify-full' in (stage / 'postgresql.auto.conf').read_text()
        return dict(observed, recovery=True, read_only='on', receiver_status='streaming', lsn='0/300')
    kwargs = {'root': root, 'inhibitor_root': tmp_path / 'inhibit', 'identity_path': identity,
              'command': command, 'route_reader': lambda cfg, domain: dict(route), 'replica_probe': probe}
    return config, request, kwargs, calls, route


def test_verified_replacement_retains_old_tree_and_never_releases_inhibitor(tmp_path):
    config, request, kwargs, calls, _ = fixture(tmp_path)
    result = rejoin.rebuild(config, 'vector', request, **kwargs)
    assert result['replica']['recovery'] is True
    assert result['replica']['lsn'] == '0/300'
    assert Path(result['retained_directory']).joinpath('valuable-old-data').read_text() == 'retain this'
    assert (kwargs['root'] / 'vector' / 'standby.signal').exists()
    assert (kwargs['inhibitor_root'] / 'owned-run/vector/graph').exists()
    assert result['verification']['returncode'] == 0
    assert all('promote' not in command and 'systemctl' not in command for command in calls)


@pytest.mark.parametrize('failure', ['wrong-identity', 'missing-inhibitor', 'aliased-data'])
def test_rejects_unowned_or_unquarantined_target_before_native_access(tmp_path, failure):
    config, request, kwargs, calls, _ = fixture(tmp_path)
    if failure == 'wrong-identity':
        kwargs['identity_path'].write_text('another-generation')
    elif failure == 'missing-inhibitor':
        (kwargs['inhibitor_root'] / 'owned-run/vector/graph').unlink()
    else:
        (kwargs['root'] / 'vector').rename(kwargs['root'] / 'other')
        (kwargs['root'] / 'vector').symlink_to(kwargs['root'] / 'other', target_is_directory=True)
    with pytest.raises(ValueError):
        rejoin.rebuild(config, 'vector', request, **kwargs)
    assert calls == []


@pytest.mark.parametrize('failure', ['stale-authority', 'wrong-system', 'behind-wal', 'writable', 'checksum-failed'])
def test_failed_qualification_never_replaces_original_data(tmp_path, failure):
    config, request, kwargs, _, route = fixture(tmp_path)
    probe = kwargs['replica_probe']
    def changed(*args, **kw):
        row = probe(*args, **kw)
        if failure == 'stale-authority': route['authority'] = {'epoch': 21, 'lease': '31'}
        elif failure == 'wrong-system': row['system_identifier'] = '999'
        elif failure == 'behind-wal': row['lsn'] = '0/100'
        elif failure == 'writable': row['recovery'] = False
        return row
    kwargs['replica_probe'] = changed
    if failure == 'checksum-failed':
        command = kwargs['command']
        kwargs['command'] = lambda argv, **kw: subprocess.CompletedProcess(argv, 1, '', 'bad checksum') if argv[0] == 'pg_verifybackup' else command(argv, **kw)
    with pytest.raises(ValueError):
        rejoin.rebuild(config, 'vector', request, **kwargs)
    assert (kwargs['root'] / 'vector/valuable-old-data').read_text() == 'retain this'
    assert not list(kwargs['root'].glob('*.retained-*'))


def test_manifest_must_cover_observed_wal_and_same_timeline():
    source = {'system_identifier': '42', 'timeline': 3, 'lsn': '0/200'}
    for ranges in ([], [{'Timeline': 2, 'Start-LSN': '0/100', 'End-LSN': '0/300'}],
                   [{'Timeline': 3, 'Start-LSN': '0/100', 'End-LSN': '0/199'}]):
        with pytest.raises(ValueError):
            rejoin.verify_manifest({'PostgreSQL-Backup-Manifest-Version': 2, 'System-Identifier': 42, 'WAL-Ranges': ranges}, source)
