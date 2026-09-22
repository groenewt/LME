"""Pure, fail-closed PostgreSQL platform contracts. No credential values needed."""
import base64
import hashlib
import ipaddress
import json
import pathlib
import re
import secrets
import socket
import subprocess
import tempfile
import time
import uuid

HOSTS = ('graph', 'trixie', 'silmaril')
TABLES = {
    'hertzbeat': {'hzb_monitor': ('id', 'intervals', 'status', 'type', 'gmt_create', 'gmt_update'),
                  'hzb_collector': ('id', 'status', 'gmt_create', 'gmt_update')},
    'lme_vectors': {'docs_chunks': ('id', 'chunk_index', 'created_at'),
                    'lme_vector_probe': ('probe_id', 'generation', 'fixture_version', 'embedding', 'updated_at')},
    'litellm': {'lme_litellm_status': ('service_id', 'status', 'version', 'artifact_digest', 'observed_at', 'last_success_at')},
}


def topology(profile):
    if profile == 'dual-owned-ha':
        return {'profile': profile, 'fresh_deployment_only': True, 'domains': {
            'hertzbeat': {'initial_owner': 'trixie', 'databases': ['hertzbeat'], 'imports': ['lme_vectors_replica', 'litellm_replica'], 'port': 5433, 'api_port': 8008},
            'vector': {'initial_owner': 'graph', 'databases': ['lme_vectors', 'litellm'], 'imports': ['hertzbeat_replica'], 'port': 5434, 'api_port': 8009}},
            'paths': [{'source': db, 'destination': db + '_replica', 'publication': 'lme_' + db, 'subscription': 'sub_' + db} for db in TABLES]}
    if profile == 'shared-ha':
        return {'profile': profile, 'fresh_deployment_only': True, 'domains': {
            'shared': {'initial_owner': 'graph', 'databases': list(TABLES), 'imports': [], 'port': 5433, 'api_port': 8008}}, 'paths': []}
    raise ValueError('unsupported database profile')


def publication_sql(database):
    if database not in TABLES:
        raise ValueError('only authoritative databases can publish')
    tables = ', '.join('public.' + table + ' (' + ', '.join(cols) + ')' for table, cols in TABLES[database].items())
    return f"CREATE PUBLICATION lme_{database} FOR TABLE {tables} WITH (publish = 'insert, update, delete', publish_via_partition_root = false);\n"


def safe_token(value, pattern=r'[a-zA-Z0-9_.:/-]+'):
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise ValueError('unsafe identifier or path')
    return value


def subscription_sql(database, host, passfile):
    if database not in TABLES:
        raise ValueError('unsupported subscription database')
    safe_token(host, r'[a-zA-Z0-9.-]+')
    safe_token(passfile)
    if not passfile.startswith('/'):
        raise ValueError('passfile must be absolute')
    connection = (f'host={host} port=5432 dbname={database} user=lme_replicator '
                  f'passfile={passfile} sslmode=verify-full sslrootcert=/run/secrets/replication-{database}-ca.crt '
                  f'sslcert=/run/secrets/replication-{database}.crt sslkey=/run/secrets/replication-{database}.key connect_timeout=5')
    return (f"CREATE SUBSCRIPTION sub_{database} CONNECTION '{connection}' PUBLICATION lme_{database} "
            "WITH (origin = none, failover = true, synchronous_commit = on, copy_data = true, enabled = true);\n")


def slots_ready(expected, rows):
    if not expected or len(set(expected)) != len(expected):
        return False
    actual = {row['slot_name']: row for row in rows}
    return all(name in actual and actual[name].get('synced') is True
               and actual[name].get('temporary') is False
               and actual[name].get('failover') is True
               and actual[name].get('invalidation_reason') is None for name in expected)


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def verify_envelope(envelope, public_key):
    data = canonical(envelope['payload'])
    signature = base64.b64decode(envelope['signature'], validate=True)
    key = subprocess.run(['openssl', 'pkey', '-pubin', '-in', str(public_key), '-outform', 'DER'], capture_output=True)
    if key.returncode or len(key.stdout) != 44 or not key.stdout.startswith(bytes.fromhex('302a300506032b6570032100')):
        raise ValueError('guardian key must be Ed25519 SubjectPublicKeyInfo')
    with tempfile.TemporaryDirectory(prefix='lme-pg-signature-') as directory:
        message, sig = pathlib.Path(directory) / 'message', pathlib.Path(directory) / 'signature'
        message.write_bytes(data)
        sig.write_bytes(signature)
        result = subprocess.run(['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(public_key), '-rawin', '-in', str(message), '-sigfile', str(sig)], capture_output=True)
    if result.returncode:
        raise ValueError('guardian signature rejected')
    return envelope['payload']


def fresh(payload, now, maximum=60):
    issued, expires = payload['issued_at'], payload['expires_at']
    if type(issued) not in (int, float) or type(expires) not in (int, float):
        raise ValueError('invalid receipt times')
    if not (0 <= now - issued <= maximum and now < expires <= issued + maximum):
        raise ValueError('stale or future guardian evidence')


def validate_receipt(payload, context, now=None):
    fresh(payload, time.time() if now is None else now)
    for field in ('run_id', 'domain', 'candidate', 'authority', 'action', 'request_nonce'):
        if not context.get(field) or payload.get(field) != context[field]:
            raise ValueError('receipt binding mismatch: ' + field)
    if context['action'] not in ('bootstrap', 'promote', 'rejoin'):
        raise ValueError('unsupported guardian action')
    if payload.get('quarantined_candidate') is not True:
        raise ValueError('candidate quarantine/rebuild proof required')
    expected = context['prior_writers']
    if not expected and not (context['action'] == 'bootstrap' and payload.get('initial_generation_permit') is True and context.get('initial_generation_permit') is True):
        raise ValueError('empty prior-writer ledger is not a fence')
    writers = payload['prior_writers']
    identities = lambda rows: {(row['node'], row['qemu_generation']) for row in rows}
    if len(writers) != len(expected) or identities(writers) != identities(expected):
        raise ValueError('prior-writer ledger mismatch')
    if any(row.get('stopped') is not True or row.get('restart_inhibited') is not True for row in writers):
        raise ValueError('exact process stop and restart inhibition required')


def authority_request(path, request, timeout=3):
    safe_token(path)
    if not path.startswith('/'):
        raise ValueError('authority socket must be absolute')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(path)
        connection.sendall(canonical(request) + b'\n')
        data = b''
        while b'\n' not in data:
            block = connection.recv(4096)
            if not block or len(data) + len(block) > 65536:
                raise ValueError('authority response missing or oversized')
            data += block
    return json.loads(data.split(b'\n')[0])


def gate(context, envelope, public_key, authority_socket):
    payload = verify_envelope(envelope, public_key)
    validate_receipt(payload, context)
    digest, challenge = hashlib.sha256(canonical(payload)).hexdigest(), secrets.token_hex(32)
    request = {'operation': 'consume', 'receipt_sha256': digest, 'challenge': challenge, 'context': context}
    authority = verify_envelope(authority_request(authority_socket, request, timeout=15), public_key)
    fresh(authority, time.time(), maximum=5)
    for field in ('run_id', 'domain', 'candidate', 'authority', 'action', 'request_nonce'):
        if authority.get(field) != context[field]:
            raise ValueError('fresh authority binding mismatch')
    if authority.get('challenge') != challenge or authority.get('receipt_sha256') != digest:
        raise ValueError('authority response replay')
    if any(authority.get(field) is not True for field in ('consumed', 'quorum', 'leader_authorized')):
        raise ValueError('quorum, leader authority and nonce CAS are required')
    return True


def live_gate(config, domain, action, public_key, authority_socket):
    plan=topology(config['profile'])
    if domain not in plan['domains'] or config['node'] not in HOSTS or action not in ('bootstrap','promote'):
        raise ValueError('live gate identity outside resolved topology')
    generation=str(uuid.UUID(config['qemu_generation']))
    if generation != config['qemu_generation']:
        raise ValueError('canonical observed QEMU generation required')
    if action=='bootstrap' and config['node'] != plan['domains'][domain]['initial_owner']:
        raise ValueError('bootstrap only accepts the configured initial member')
    request={'operation':'authorize','run_id':config['run_id'],'domain':domain,'node':config['node'],
             'qemu_generation':generation,'action':action,'challenge':secrets.token_hex(32)}
    authorization=verify_envelope(authority_request(authority_socket,request,timeout=180),public_key)
    fresh(authorization,time.time(),maximum=30)
    if any(authorization.get(field)!=value for field,value in request.items()):
        raise ValueError('authorization response binding mismatch')
    context=authorization['context']
    if (context.get('run_id'),context.get('domain'),context.get('candidate'),context.get('action')) != (
            request['run_id'],domain,{'node':request['node'],'qemu_generation':generation},action):
        raise ValueError('guardian context was rebound to a different transition')
    # The guardian derives the complete ledger and leased authority. Existing
    # gate verification then checks the inner receipt and consumes its nonce CAS.
    return gate(context,authorization['receipt'],public_key,authority_socket)


def validate_route(route, context, allowed, now=None):
    fresh(route, time.time() if now is None else now, maximum=5)
    for field in ('run_id', 'domain', 'node', 'owner', 'challenge'):
        if route.get(field) != context[field]:
            raise ValueError('route binding mismatch')
    if any(route.get(field) is not True for field in ('quorum', 'leader_authorized', 'fenced')):
        raise ValueError('route lacks current fenced DCS authority')
    if not route.get('authority', {}).get('lease') or not route['authority'].get('epoch'):
        raise ValueError('route lacks leader lease and epoch')
    if allowed.get(route.get('primary_node')) != {'host': route.get('host'), 'port': route.get('port')}:
        raise ValueError('route destination outside resolved inventory')


def proxy_route(config):
    context = {key: config[key] for key in ('run_id', 'domain', 'node', 'owner')}
    context['challenge'] = secrets.token_hex(32)
    response = authority_request(config['authority_socket'], {'operation': 'route', **context})
    route = verify_envelope(response, config['public_key'])
    validate_route(route, context, config['allowed'])
    return route


def resolved_role_config(resolved, node, credential_material):
    """Derive role variables from observed topology and file grants, never secrets."""
    try:
        if node not in HOSTS or credential_material['run_id'] != resolved['run_id']:
            raise ValueError('credential material is not bound to this run')
        profile = resolved['profiles']['database']
        plan = topology(profile)
        images = {}
        for kind in ('patroni', 'etcd'):
            artifact = resolved['artifacts'][kind]
            reference = artifact['reference']
            if not re.fullmatch(r'(?:[a-zA-Z0-9./:_-]+@)?sha256:[a-f0-9]{64}', reference):
                raise ValueError('qualified immutable database image required')
            if reference.startswith('sha256:') and (not pathlib.Path(artifact['archive']).is_absolute()
                    or not re.fullmatch(r'[a-f0-9]{64}', artifact['archive_sha256']) or not artifact['source_digest']):
                raise ValueError('local image qualification metadata missing')
            images[kind] = reference
        hosts = {name: {'address': resolved['hosts'][name]['fqdn'],
                        'cidr': str(ipaddress.ip_address(resolved['hosts'][name]['tailscale_address'])) + '/32'} for name in HOSTS}
        owners = {domain: resolved['hosts'][node]['owners']['db-' + domain] for domain in plan['domains']}
        owners['etcd'] = resolved['hosts'][node]['owners']['etcd']
        # Physical members retain the same role/account names across guests.
        for member in HOSTS:
            for domain in plan['domains']:
                if resolved['hosts'][member]['owners']['db-' + domain] != owners[domain]:
                    raise ValueError('database owner differs across physical members')
        grants = {(entry['node'], entry['owner'], entry['destination']) for entry in credential_material['grants']}
        for domain in plan['domains']:
            owner = owners[domain]
            for filename in ('pg-ca.crt', 'pg-server.crt', 'pg-server.key', 'admin.crt', 'admin.key', 'admin.pgpass',
                             'pg_service.conf', 'role-passwords.json', 'patroni.env', 'etcd-ca.crt', 'etcd-client.crt', 'etcd-client.key',
                             'backup-ca.crt', 'backup-client.crt', 'backup-client.key'):
                if (node, owner, f'/data/{owner}/secrets/postgresql/{filename}') not in grants:
                    raise ValueError('database credential grant missing: ' + filename)
        services = {domain + '_admin': domain + '_admin' for domain in plan['domains']}
        services.update({db + '_source': db + '_source' for db in TABLES})
        if plan['paths']:
            services.update({db + '_replica': db + '_replica' for db in TABLES})
        for domain in plan['domains']:
            services.update({domain + '_candidate_' + member: domain + '_candidate_' + member for member in HOSTS})
        host = resolved['hosts'][node]
        clients = {owners[domain] for domain in plan['domains']}
        for sid, service in host['resolved_services'].items():
            if sid in ('hertzbeat', 'litellm', 'dashboard', 'log-analyzer') or any(secret['name'] == 'pgvector' for secret in service.get('secrets', [])):
                clients.add(host['owners'][sid])
        if 'hertzbeat' in host['owners']:
            clients.add(host['owners']['hertzbeat'])
        config = {'profile': profile, 'run_id': resolved['run_id'], 'node': node, 'qemu_generation': str(uuid.UUID(host['qemu_generation'])), 'hosts': hosts, 'images': images,
                  'owners': owners, 'services': services, 'proxy_owners': sorted(clients),
                  'backup': resolved['database']['backup'], 'slot_guard_standby': resolved['database']['slot_guard_standby'],
                  'memory_mib': {domain: resolved['providers']['db-' + domain]['memory_mib'] for domain in plan['domains']},
                  'proxy_memory_mib': resolved['providers'].get('db-proxy-hertzbeat', {}).get('memory_mib', 64)}
        config['memory_mib']['etcd'] = resolved['providers']['etcd']['memory_mib']
        for domain in plan['domains']:
            if set(config['slot_guard_standby'][domain]) != set(HOSTS):
                raise ValueError('every member requires an explicit eligible physical slot guard')
        render(config)
        return {'postgresql_platform_config': config,
                'postgresql_platform_owners': {domain: {'name': owner, 'home': '/home/' + owner} for domain, owner in owners.items()}}
    except (KeyError, TypeError) as error:
        raise ValueError('resolved database contract is incomplete: ' + str(error)) from None


def render(config):
    """Render one resolved inventory node; never resolve secrets or start services."""
    plan = topology(config['profile'])
    node, run_id = config['node'], safe_token(config['run_id'], r'[a-zA-Z0-9_-]+')
    if node not in HOSTS or set(config['hosts']) != set(HOSTS):
        raise ValueError('exact three-member guest inventory required')
    for item in config['hosts'].values():
        safe_token(item['address'], r'[a-zA-Z0-9.-]+')
        ipaddress.ip_network(item['cidr'], strict=True)
    if str(uuid.UUID(config['qemu_generation'])) != config['qemu_generation']:
        raise ValueError('canonical observed QEMU generation required')
    images = config['images']
    for kind in ('patroni', 'etcd'):
        if not re.fullmatch(r'(?:[a-zA-Z0-9./:_-]+@)?sha256:[a-f0-9]{64}', images[kind]):
            raise ValueError('qualified immutable image required: ' + kind)
    backup = config['backup']
    safe_token(backup['repository_host'], r'[a-zA-Z0-9.-]+')
    safe_token(backup['repository_path'])
    if backup['repository_host'] in [h['address'] for h in config['hosts'].values()] or not backup['repository_path'].startswith('/'):
        raise ValueError('backup must leave all three database member guests')
    if type(backup['retention_full']) is not int or backup['retention_full'] < 2:
        raise ValueError('at least two full backup generations required')
    files = {'topology.json': json.dumps(plan, indent=2) + '\n'}
    address = config['hosts'][node]['address']
    bind_address = str(ipaddress.ip_network(config['hosts'][node]['cidr']).network_address)
    owners = {'hertzbeat': 'lmedbhb', 'vector': 'lmedbvector', 'shared': 'lmedbshared', 'etcd': 'lmedcs', **config.get('owners', {})}
    for owner in owners.values():
        safe_token(owner, r'[a-z_][a-z0-9_-]*')
    for domain, spec in plan['domains'].items():
        name = f'pg-{domain}'
        owner = owners[domain]
        memory = config.get('memory_mib', {}).get(domain, 768)
        if type(memory) is not int or memory < 256:
            raise ValueError('database memory cap must be an admitted integer MiB budget')
        guarded_standby = config.get('slot_guard_standby', {}).get(domain, {}).get(node, next(h for h in HOSTS if h != node))
        if guarded_standby not in HOSTS or guarded_standby == node:
            raise ValueError('slot guard must name one distinct physical standby')
        path = f'/etc/lme/postgresql/{domain}'
        gate_command = f'python3 -m scripts.postgresql_platform gate-live --config {path}/resolved.json --domain {domain} --action promote --public-key /run/secrets/guardian.pub --authority-socket /run/lme-fencing/control.sock'
        parameters = {'wal_level': 'logical', 'max_wal_senders': 16, 'max_replication_slots': 32,
                      'shared_buffers': '128MB', 'max_connections': 64,
                      'max_logical_replication_workers': 8, 'max_worker_processes': 16,
                      'synchronous_commit': 'on', 'hot_standby_feedback': 'on', 'sync_replication_slots': 'on',
                      'ssl': 'on', 'ssl_min_protocol_version': 'TLSv1.2',
                      'unix_socket_directories': '/tmp',
                      'ssl_ca_file': '/run/secrets/pg-ca.crt', 'ssl_cert_file': '/run/secrets/pg-server.crt',
                      'ssl_key_file': '/run/secrets/pg-server.key', 'password_encryption': 'scram-sha-256',
                      'archive_mode': 'on', 'archive_command': f'pgbackrest --stanza={domain} archive-push %p'}
        hba = ['local all postgres peer']
        for peer in config['hosts'].values():
            hba += [f"hostssl replication replicator {peer['cidr']} scram-sha-256 clientcert=verify-full",
                    f"hostssl all all {peer['cidr']} scram-sha-256 clientcert=verify-full"]
        hba += ['host all all 0.0.0.0/0 reject', 'host all all ::/0 reject']
        member = {'scope': name, 'namespace': f'/lme/{run_id}/{domain}/', 'name': node,
                  'restapi': {'listen': f'0.0.0.0:{spec["api_port"]}', 'connect_address': f'{address}:{spec["api_port"]}',
                              'certfile': '/run/secrets/pg-server.crt', 'keyfile': '/run/secrets/pg-server.key', 'cafile': '/run/secrets/pg-ca.crt', 'verify_client': 'required'},
                  'etcd3': {'hosts': [h['address'] + ':2379' for h in config['hosts'].values()], 'protocol': 'https',
                            'cacert': '/run/secrets/etcd-ca.crt', 'cert': '/run/secrets/etcd-client.crt', 'key': '/run/secrets/etcd-client.key'},
                  'bootstrap': {'method': 'guarded', 'guarded': {'command': gate_command.replace('--action promote', '--action bootstrap') + ' --data-dir /var/lib/postgresql/data', 'no_params': True},
                                'dcs': {'ttl': 30, 'loop_wait': 5, 'retry_timeout': 5, 'synchronous_mode': True, 'synchronous_mode_strict': True,
                                        'synchronous_node_count': 1, 'failsafe_mode': False,
                                        'postgresql': {'use_pg_rewind': False, 'use_slots': True, 'parameters': parameters}}},
                  'postgresql': {'listen': f'0.0.0.0:{spec["port"]}', 'connect_address': f'{address}:{spec["port"]}', 'data_dir': '/var/lib/postgresql/data',
                                 'parameters': {'synchronized_standby_slots': guarded_standby},
                                 'authentication': {'superuser': {'username': 'postgres'},
                                                    'replication': {'username': 'replicator', 'sslmode': 'verify-full', 'sslrootcert': '/run/secrets/pg-ca.crt',
                                                                    'sslcert': '/run/secrets/replicator.crt', 'sslkey': '/run/secrets/replicator.key'}},
                                 'pgpass': '/tmp/physical.pgpass', 'pg_hba': hba, 'pre_promote': gate_command,
                                 'remove_data_directory_on_rewind_failure': False, 'remove_data_directory_on_diverged_timelines': False},
                  'tags': {'nofailover': node != spec['initial_owner']}}
        files[f'patroni-{domain}.json'] = json.dumps(member, indent=2) + '\n'
        files[f'{name}.container'] = f'''[Unit]
Description=LME PostgreSQL {domain} (guarded Patroni)
After=network-online.target
[Container]
Image={images['patroni']}
ContainerName={name}
LogDriver=journald
UserNS=keep-id:uid=999,gid=999
Network=lme-{owner}.network
PublishPort={bind_address}:{spec["port"]}:{spec["port"]}
PublishPort={bind_address}:{spec["api_port"]}:{spec["api_port"]}
Exec=patroni {path}/patroni.json
Volume=/data/{owner}/config/postgresql/{domain}:{path}:ro
Volume=/data/{owner}/volumes/postgresql/{domain}:/var/lib/postgresql/data:Z
Volume=/data/{owner}/secrets/postgresql:/run/secrets:ro
Volume=/data/{owner}/config/postgresql/pgbackrest-{domain}.conf:/etc/pgbackrest/pgbackrest.conf:ro
Volume=/run/lme-fencing:/run/lme-fencing:ro
EnvironmentFile=/data/{owner}/secrets/postgresql/patroni.env
NoNewPrivileges=true
[Service]
Restart=on-failure
MemoryMax={memory}M
ExecCondition=/usr/bin/test ! -e /var/lib/lme-fencing/inhibit/{run_id}/{domain}/{node}
TimeoutStartSec=300
[Install]
WantedBy=default.target
'''
        files[f'pgbackrest-{domain}.conf'] = f'''[global]
log-path=/tmp/pgbackrest-log
lock-path=/tmp/pgbackrest-lock
log-level-file=off
repo1-host={backup['repository_host']}
repo1-host-type=tls
repo1-host-ca-file=/run/secrets/backup-ca.crt
repo1-host-cert-file=/run/secrets/backup-client.crt
repo1-host-key-file=/run/secrets/backup-client.key
repo1-path={backup['repository_path']}/{run_id}/{domain}
repo1-retention-full={backup['retention_full']}
archive-async=n
[{domain}]
pg1-path=/var/lib/postgresql/data
pg1-socket-path=/tmp
pg1-port={spec['port']}
'''
        databases = spec['databases'] + spec['imports']
        cluster_sql = pathlib.Path(__file__).with_name('sql').joinpath('roles.sql').read_text()
        for database in databases:
            cluster_sql += f"SELECT format('CREATE DATABASE %I OWNER lme_schema', '{database}') WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='{database}') \\gexec\n"
            cluster_sql += f"REVOKE ALL ON DATABASE {database} FROM PUBLIC;\n"
            if database in spec['databases']:
                for suffix in ('app', 'migrator', 'adapter', 'reader'):
                    role = database + '_' + suffix
                    cluster_sql += f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION; END IF; END $$;\nALTER ROLE {role} SET synchronous_commit=on;\nGRANT CONNECT ON DATABASE {database} TO {role};\n"
                cluster_sql += f"GRANT CONNECT ON DATABASE {database} TO lme_replicator;\nGRANT CREATE ON DATABASE {database} TO {database}_migrator;\n"
            else:
                cluster_sql += f"GRANT CONNECT ON DATABASE {database} TO lme_replica_reader;\n"
        files[f'{domain}-databases.sql'] = cluster_sql
    etcd_memory = config.get('memory_mib', {}).get('etcd', 256)
    proxy_memory = config.get('proxy_memory_mib', 64)
    if any(type(value) is not int or value < 32 for value in (etcd_memory, proxy_memory)):
        raise ValueError('etcd and proxy memory caps must be admitted integer MiB budgets')
    peers = ','.join(f'{name}=https://{host["address"]}:2380' for name, host in config['hosts'].items())
    files['pg-etcd.container'] = f'''[Unit]
Description=LME shared three-voter etcd
[Container]
Image={images['etcd']}
ContainerName=pg-etcd
LogDriver=journald
Network=lme-{owners["etcd"]}.network
PublishPort={bind_address}:2379:2379
PublishPort={bind_address}:2380:2380
Exec=etcd --name {node} --data-dir /var/lib/etcd --listen-client-urls https://0.0.0.0:2379 --advertise-client-urls https://{address}:2379 --listen-peer-urls https://0.0.0.0:2380 --initial-advertise-peer-urls https://{address}:2380 --initial-cluster {peers} --initial-cluster-state new --initial-cluster-token lme-{run_id} --client-cert-auth --trusted-ca-file /run/secrets/etcd-ca.crt --cert-file /run/secrets/etcd-server.crt --key-file /run/secrets/etcd-server.key --peer-client-cert-auth --peer-trusted-ca-file /run/secrets/etcd-ca.crt --peer-cert-file /run/secrets/etcd-server.crt --peer-key-file /run/secrets/etcd-server.key
Volume=/data/{owners["etcd"]}/volumes/postgresql/etcd:/var/lib/etcd:Z
Volume=/data/{owners["etcd"]}/secrets/postgresql:/run/secrets:ro
NoNewPrivileges=true
[Service]
Restart=on-failure
MemoryMax={etcd_memory}M
[Install]
WantedBy=default.target
'''
    for database in TABLES:
        files[f'{database}-publication.sql'] = publication_sql(database) if plan['paths'] else '-- shared-ha has no reciprocal publications\n'
        files[f'{database}-subscription.sql'] = subscription_sql(database, 'pg-hertzbeat-rw' if database == 'hertzbeat' else 'pg-vector-rw', '/run/secrets/logical.pgpass') if plan['paths'] else '-- shared-ha has no reciprocal subscriptions\n'
        grants = f'REVOKE CREATE ON SCHEMA public FROM PUBLIC;\nGRANT USAGE ON SCHEMA public TO {database}_app, {database}_adapter, {database}_reader, lme_replicator;\nGRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {database}_app;\nALTER DEFAULT PRIVILEGES FOR ROLE {database}_migrator IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {database}_app;\nALTER DEFAULT PRIVILEGES FOR ROLE {database}_migrator IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {database}_app;\n'
        for table, columns in TABLES[database].items():
            grants += f'GRANT SELECT, INSERT, UPDATE, DELETE ON public.{table} TO {database}_app;\nGRANT SELECT ({", ".join(columns)}) ON public.{table} TO lme_replicator;\n'
            grants += f'GRANT SELECT ({", ".join(columns)}) ON public.{table} TO {database}_reader;\n'
            if table in ('lme_vector_probe', 'lme_litellm_status'):
                grants += f'GRANT SELECT, INSERT, UPDATE, DELETE ON public.{table} TO {database}_adapter;\n'
        grants += f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {database}_app;\n'
        files[f'{database}-source-grants.sql'] = grants
        files[f'{database}-replica-grants.sql'] = ('REVOKE CREATE ON SCHEMA public FROM PUBLIC;\nGRANT USAGE ON SCHEMA public TO lme_replica_reader;\n' + ''.join(f'REVOKE ALL ON public.{table} FROM PUBLIC;\nGRANT SELECT ON public.{table} TO lme_replica_reader;\n' for table in TABLES[database]))
    # Client owners come from the enabled service union in resolved inventory.
    # Each proxy is installed in that client's rootless network namespace.
    for owner in config.get('proxy_owners', []):
        safe_token(owner, r'[a-z_][a-z0-9_-]*')
        for alias, domain in (('pg-hertzbeat-rw', 'hertzbeat'), ('pg-vector-rw', 'vector')):
            actual = domain if config['profile'] == 'dual-owned-ha' else 'shared'
            port = plan['domains'][actual]['port']
            proxy_config = {'run_id': run_id, 'domain': actual, 'node': node, 'owner': owner,
                            'authority_socket': '/run/lme-fencing/control.sock', 'public_key': '/run/guardian/public.pem',
                            'allowed': {h: {'host': config['hosts'][h]['address'], 'port': port} for h in HOSTS}}
            files[f'{owner}-{alias}.json'] = json.dumps(proxy_config, indent=2) + '\n'
            files[f'{owner}-{alias}.container'] = f'''[Unit]
Description=LME fenced {alias} endpoint for {owner}
[Container]
Image={images['patroni']}
ContainerName={alias}
LogDriver=journald
UserNS=keep-id:uid=999,gid=999
Network=lme-{owner}.network
NetworkAlias={alias}
Exec=python3 -m scripts.postgresql_platform proxy --config /etc/lme/proxy.json
Volume=/data/{owner}/config/postgresql/{alias}.json:/etc/lme/proxy.json:ro
Volume=/data/{owner}/config/postgresql/guardian.pub:/run/guardian/public.pem:ro
Volume=/run/lme-fencing:/run/lme-fencing:ro
NoNewPrivileges=true
[Service]
Restart=on-failure
MemoryMax={proxy_memory}M
[Install]
WantedBy=default.target
'''
    return files
