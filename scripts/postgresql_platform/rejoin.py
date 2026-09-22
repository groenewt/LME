"""Rebuild one fenced lab member from a freshly authorized primary.

The caller runs this in a disposable container with the exact owner's parent
volume mounted at /var/lib/postgresql/member. This helper never releases a fence
or promotes a server. Old data and failed staging trees are retained.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import time

from .platform import HOSTS as NODES, proxy_route, safe_token, topology

SOURCE_SQL = """SELECT json_build_object('system_identifier',s.system_identifier::text,
 'timeline',c.timeline_id,'lsn',CASE WHEN pg_is_in_recovery() THEN pg_last_wal_replay_lsn()::text
 ELSE pg_current_wal_flush_lsn()::text END,'recovery',pg_is_in_recovery(),
 'ssl',(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),
 'server_address',inet_server_addr(),'server_port',inet_server_port(),
 'read_only',current_setting('transaction_read_only'),
 'receiver_status',(SELECT status FROM pg_stat_wal_receiver),
 'observed_at',clock_timestamp()) FROM pg_control_system() s,pg_control_checkpoint() c;"""


def lsn(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9A-F]{1,8}/[0-9A-F]{1,8}', value):
        raise ValueError('invalid native WAL position')
    high, low = value.split('/')
    return (int(high, 16) << 32) + int(low, 16)


def _run(argv, *, input=None, timeout=300):
    # Credential material stays in mounted passfiles; neither environment values
    # nor secret-bearing libpq diagnostics are returned to the controller.
    environment = {k: v for k, v in os.environ.items() if not k.startswith('PG') and not k.startswith('PATRONI_')}
    environment.update(PGSERVICEFILE='/run/secrets/pg_service.conf', LC_ALL='C')
    return subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout, env=environment)


def checked(command, argv, **kwargs):
    result = command(argv, **kwargs)
    if result.returncode != 0:
        raise ValueError('native ' + argv[0] + ' failed; restricted logs retained')
    return result


def read_route(config, domain):
    port = topology(config['profile'])['domains'][domain]['port']
    return proxy_route({'run_id': config['run_id'], 'domain': domain, 'node': config['node'],
        'owner': config['owners'][domain], 'public_key': '/run/secrets/guardian.pub',
        'authority_socket': '/run/lme-fencing/control.sock',
        'allowed': {node: {'host': peer['address'], 'port': port} for node, peer in config['hosts'].items()}})


def source_readback(config, domain, route, command):
    node = route['primary_node']
    if node not in NODES or node == config['node']:
        raise ValueError('rebuild source must be another admitted member')
    result = checked(command, ['psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1',
        'service=' + domain + '_candidate_' + node + ' sslmode=verify-full connect_timeout=5'], input=SOURCE_SQL, timeout=15)
    observed = json.loads(result.stdout)
    if (observed.get('recovery') is not False or observed.get('ssl') is not True
            or not re.fullmatch(r'[1-9][0-9]+', observed.get('system_identifier', ''))
            or type(observed.get('timeline')) is not int or observed['timeline'] <= 0):
        raise ValueError('source is not a verified TLS primary with native lineage')
    lsn(observed['lsn'])
    return observed


def verify_manifest(manifest, source):
    ranges = manifest.get('WAL-Ranges', [])
    if (manifest.get('PostgreSQL-Backup-Manifest-Version') != 2
            or str(manifest.get('System-Identifier')) != source['system_identifier']
            or len(ranges) != 1 or ranges[0].get('Timeline') != source['timeline']
            or lsn(ranges[0]['End-LSN']) < lsn(source['lsn'])
            or lsn(ranges[0]['Start-LSN']) >= lsn(ranges[0]['End-LSN'])):
        raise ValueError('backup manifest lineage/timeline/WAL does not cover the observed primary')


def verify_replica(replica, source):
    if (replica.get('recovery') is not True or replica.get('read_only') != 'on'
            or replica.get('receiver_status') != 'streaming'
            or replica.get('system_identifier') != source['system_identifier']
            or replica.get('timeline') != source['timeline'] or lsn(replica['lsn']) < lsn(source['lsn'])):
        raise ValueError('actual read-only streaming replica has not reached the required lineage/WAL')


def isolated_replica(stage, minimum, *, command=_run):
    """Start only the staged standby, on a private Unix socket without TCP."""
    stage = Path(stage)
    with tempfile.TemporaryDirectory(prefix='lme-pg-rejoin-', dir='/tmp') as directory:
        socket_dir = Path(directory)
        hba = socket_dir / 'pg_hba.conf'
        hba.write_text('local all postgres peer\n')
        arguments = ['-c', 'data_directory=' + str(stage), '-c', 'listen_addresses=',
                     '-c', 'unix_socket_directories=' + str(socket_dir), '-c', 'port=5449',
                     '-c', 'hba_file=' + str(hba), '-c', 'ssl=off', '-c', 'archive_mode=off',
                     '-c', 'default_transaction_read_only=on', '-c', 'hot_standby=on',
                     '-c', 'sync_replication_slots=off']
        attempted = False
        try:
            attempted = True
            checked(command, ['pg_ctl', '-D', str(stage), '-l', str(socket_dir / 'postgres.log'),
                             '-o', shlex.join(arguments), '-w', '-t', '60', 'start'], timeout=70)
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                result = checked(command, ['psql', '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-h', str(socket_dir),
                    '-p', '5449', '-U', 'postgres', '-d', 'postgres'], input=SOURCE_SQL, timeout=10)
                observed = json.loads(result.stdout)
                try:
                    verify_replica(observed, minimum)
                    return observed
                except ValueError:
                    time.sleep(1)
            raise ValueError('isolated replica did not replay required WAL within 60 seconds')
        finally:
            if attempted:
                # A timed-out start may still own a process. Exact datadir stop
                # must succeed before any directory can replace the old member.
                status = command(['pg_ctl', '-D', str(stage), 'status'], timeout=10)
                if status.returncode == 0:
                    checked(command, ['pg_ctl', '-D', str(stage), '-m', 'immediate', '-w', '-t', '30', 'stop'], timeout=40)
                elif status.returncode not in (3, 4):
                    raise ValueError('isolated replica process exit could not be verified')


def _unalias(path):
    if not path.is_absolute() or path.is_symlink() or path.resolve() != path:
        raise ValueError('member filesystem aliases are forbidden')


def rebuild(config, domain, request, *, root=Path('/var/lib/postgresql/member'),
            inhibitor_root=Path('/var/lib/lme-fencing/inhibit'), identity_path=Path('/run/lme-rejoin/instance-id'),
            command=_run, route_reader=read_route, replica_probe=isolated_replica):
    safe_token(config['run_id'], r'[a-z0-9][a-z0-9-]{0,31}')
    safe_token(request['request_nonce'], r'[a-f0-9]{32}')
    if (domain not in topology(config['profile'])['domains'] or config['node'] not in NODES
            or request.get('schema_version') != 1
            or any(request.get(key) != value for key, value in {'run_id': config['run_id'], 'domain': domain, 'node': config['node']}.items())
            or not isinstance(request.get('qemu_generation'), str) or not request['qemu_generation']):
        raise ValueError('rebuild identity differs from the resolved owned member')
    root = Path(root)
    data = root / domain
    inhibit = Path(inhibitor_root) / config['run_id'] / domain / config['node']
    identity_path = Path(identity_path)
    for path in (root, data, inhibit, identity_path):
        _unalias(path)
    def quarantine():
        if (not inhibit.is_file() or inhibit.read_text() != request['qemu_generation']
                or identity_path.read_text().strip() != request['qemu_generation']
                or not data.is_dir() or (data / 'PG_VERSION').read_text().strip() != '17'):
            raise ValueError('exact stopped PostgreSQL 17 member and matching persistent quarantine required')
    quarantine()
    nonce = request['request_nonce']
    stage, retained = root / (domain + '.rebuild-' + nonce), root / (domain + '.retained-' + nonce)
    if stage.exists() or retained.exists() or stage.is_symlink() or retained.is_symlink():
        raise ValueError('rebuild nonce cannot reuse any previous staging or retained tree')
    before_route = route_reader(config, domain)
    if (request.get('source_authority', before_route['authority']) != before_route['authority']
            or request.get('source_node', before_route['primary_node']) != before_route['primary_node']):
        raise ValueError('fresh source authority differs from guardian rejoin reservation')
    before = source_readback(config, domain, before_route, command)
    host = safe_token(config['hosts'][before_route['primary_node']]['address'], r'[A-Za-z0-9.-]+')
    port = topology(config['profile'])['domains'][domain]['port']
    conninfo = (f'host={host} port={port} user=replicator dbname=replication '
                'sslmode=verify-full sslrootcert=/run/secrets/pg-ca.crt sslcert=/run/secrets/replicator.crt '
                'sslkey=/run/secrets/replicator.key passfile=/run/secrets/physical.pgpass connect_timeout=5 '
                'application_name=lme_rebuild_' + config['node'])
    checked(command, ['pg_basebackup', '--dbname', conninfo, '--pgdata', str(stage), '--format=plain',
        '--wal-method=stream', '--checkpoint=fast', '--manifest-checksums=SHA256', '--no-password'], timeout=900)
    manifest_bytes = (stage / 'backup_manifest').read_bytes()
    manifest = json.loads(manifest_bytes)
    verify_manifest(manifest, before)
    verification = checked(command, ['pg_verifybackup', str(stage)], timeout=300)
    control = checked(command, ['pg_controldata', str(stage)], timeout=15).stdout
    fields = dict(line.split(':', 1) for line in control.splitlines() if ':' in line)
    if (fields.get('Database system identifier', '').strip() != before['system_identifier']
            or fields.get("Latest checkpoint's TimeLineID", '').strip() != str(before['timeline'])):
        raise ValueError('backup control file differs from the authorized source lineage')
    # Create recovery settings only after pg_verifybackup checks the original manifest.
    auto = stage / 'postgresql.auto.conf'
    _unalias(auto)
    with auto.open('a') as stream:
        stream.write("\nprimary_conninfo = '" + conninfo + "'\nprimary_slot_name = ''\nrecovery_target_timeline = 'latest'\n")
        stream.flush()
        os.fsync(stream.fileno())
    (stage / 'standby.signal').touch(mode=0o600)
    replica = replica_probe(stage, before, command=command)
    verify_replica(replica, before)
    after_route = route_reader(config, domain)
    if any(after_route.get(key) != before_route.get(key) for key in ('primary_node', 'authority')):
        raise ValueError('guardian authority changed while rebuilding; quarantine retained')
    after = source_readback(config, domain, after_route, command)
    if any(after[key] != before[key] for key in ('system_identifier', 'timeline')):
        raise ValueError('source changed lineage while rebuilding')
    quarantine()
    # The helper has stopped its isolated server. Retain both trees if installing
    # fails; never roll back to an unfenced writable former primary automatically.
    data.rename(retained)
    stage.rename(data)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return {**request, 'operation': 'rebuild', 'source_route': after_route, 'source_before': before,
            'source_after': after, 'replica': replica, 'backup_control': control,
            'backup_manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(), 'wal_ranges': manifest['WAL-Ranges'],
            'verification': {'program': 'pg_verifybackup', 'returncode': verification.returncode},
            'installed_directory': str(data), 'retained_directory': str(retained),
            'restart_inhibited': inhibit.exists(), 'completed_at': time.time()}
