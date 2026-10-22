"""Ordered schema and replication phases, called by the Ansible role barriers."""
import json
import os
import pathlib
import re
import subprocess

from .__main__ import SQL, native_schema, psql
from .platform import HOSTS, TABLES, publication_sql, render, slots_ready, subscription_sql, topology


def local_psql(port, database, query):
    result = subprocess.run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-h', '/tmp', '-p', str(port), '-U', 'postgres', '-d', database],
                            input=query, text=True, capture_output=True,
                            env={**os.environ, 'PGOPTIONS': '-c synchronous_commit=on -c log_statement=none -c log_min_error_statement=panic'})
    if result.returncode:
        raise ValueError('local schema operation failed; inspect restricted database logs')


def initialize_passwords(domain, spec):
    paths = json.loads(pathlib.Path('/run/secrets/role-passwords.json').read_text())
    allowed = {'postgres', 'lme_replicator', 'lme_replica_reader', 'replicator'} | {db + '_' + suffix for db in spec['databases'] for suffix in ('app', 'migrator', 'adapter', 'reader')}
    required = {'lme_replicator'} | {db + '_' + suffix for db in spec['databases'] for suffix in ('app', 'migrator', 'adapter', 'reader')}
    if not required <= set(paths) or not set(paths) <= allowed:
        raise ValueError('runtime role password map does not match owning domain')
    statements = []
    for role, filename in paths.items():
        path = pathlib.Path(filename)
        if path.parent != pathlib.Path('/run/secrets/roles') or path.is_symlink():
            raise ValueError('role password outside its mounted credential contract')
        password = path.read_text().strip()
        if not re.fullmatch(r'[A-Za-z0-9_-]{24,128}', password):
            raise ValueError('credential generator must supply bounded URL-safe secrets')
        statements.append(f"ALTER ROLE {role} PASSWORD '{password}';")
    local_psql(spec['port'], 'postgres', '\n'.join(statements))


def provision(config, domain, phase):
    plan = topology(config['profile'])
    spec = plan['domains'][domain]
    if config['node'] != spec['initial_owner']:
        raise ValueError('initial schema phases run only on declared initial owner')
    services = config['services']
    # Resolve every service before the first mutation in this phase.
    required = [domain + '_admin'] + [db + '_source' for db in spec['databases']] + spec['imports']
    if any(not services.get(name) for name in required):
        raise ValueError('missing owner-scoped libpq service contract')
    if phase == 'schema':
        local_psql(spec['port'], 'postgres', render(config)[domain + '-databases.sql'])
        initialize_passwords(domain, spec)
        for db in spec['databases']:
            local_psql(spec['port'], db, f'REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT USAGE, CREATE ON SCHEMA public TO {db}_migrator;')
            if db == 'lme_vectors':
                psql(services[db + '_source'], (SQL / 'vector-source.sql').read_text())
            elif db == 'litellm':
                psql(services[db + '_source'], (SQL / 'litellm-status.sql').read_text())
        return
    if phase == 'publications':
        for db in spec['databases']:
            service = services[db + '_source']
            psql(service, render(config)[db + '-source-grants.sql'])
            if plan['paths']:
                exists = psql(service, f"SELECT count(*) FROM pg_publication WHERE pubname='lme_{db}'", True).strip()
                if exists == '0':
                    psql(service, publication_sql(db))
                elif exists != '1':
                    raise ValueError('ambiguous publication')
        return
    if phase == 'subscriptions':
        for replica in spec['imports']:
            db = replica.removesuffix('_replica')
            target = services[replica]
            existing = psql(target, f"SELECT count(*) FROM pg_subscription WHERE subname='sub_{db}'", True).strip()
            if existing == '0':
                if db == 'hertzbeat':
                    schema = native_schema(services[db + '_source'], db)
                elif db == 'lme_vectors':
                    schema = (SQL / 'vector-replica.sql').read_text()
                else:
                    schema = (SQL / 'litellm-status.sql').read_text()
                psql(target, schema)
                psql(target, subscription_sql(db, 'pg-hertzbeat-rw' if db == 'hertzbeat' else 'pg-vector-rw', '/run/secrets/logical.pgpass'))
            psql(target, render(config)[db + '-replica-grants.sql'])
        return
    if phase == 'ready':
        evidence = {'schema_version': 1, 'node': config['node'], 'domain': domain, 'run_id': config['run_id'], 'checks': {}}
        for db in spec['databases']:
            service = services[db + '_source']
            security = psql(service, "SELECT NOT pg_is_in_recovery() AND current_setting('synchronous_commit')='on' AND EXISTS(SELECT 1 FROM pg_stat_ssl WHERE pid=pg_backend_pid() AND ssl)", True).strip()
            if security != 't':
                raise ValueError('primary verified TLS/synchronous commit unavailable')
            actual, safe_ops = {}, None
            if plan['paths']:
                actual = json.loads(psql(service, f"SELECT coalesce(json_object_agg(tablename,attnames),'{{}}'::json) FROM pg_publication_tables WHERE pubname='lme_{db}'", True))
                if actual != {table: list(cols) for table, cols in TABLES[db].items()}:
                    raise ValueError('publication column drift')
                safe_ops = psql(service, f"SELECT pubinsert AND pubupdate AND pubdelete AND NOT pubtruncate FROM pg_publication WHERE pubname='lme_{db}'", True).strip()
                if safe_ops != 't':
                    raise ValueError('publication operation drift')
            evidence['checks'][db] = {'primary_tls_sync': security, 'publication_columns': actual, 'publication_safe_operations': safe_ops}
        for replica in spec['imports']:
            db, service = replica.removesuffix('_replica'), services[replica]
            safe = psql(service, f"SELECT subfailover AND suborigin='none' AND subsynccommit='on' AND subenabled FROM pg_subscription WHERE subname='sub_{db}'", True).strip()
            copies = json.loads(psql(service, f"SELECT coalesce(json_agg(json_build_object('table',n.nspname||'.'||c.relname,'state',r.srsubstate)),'[]'::json) FROM pg_subscription_rel r JOIN pg_subscription s ON s.oid=r.srsubid JOIN pg_class c ON c.oid=r.srrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE s.subname='sub_{db}'", True))
            if safe != 't' or len(copies) != len(TABLES[db]) or {row['table'] for row in copies} != {'public.' + table for table in TABLES[db]} or any(row['state'] != 'r' for row in copies):
                raise ValueError('subscription not ready or initial copy incomplete')
            evidence['checks'][replica] = {'subscription_safe': safe, 'tables': copies}
        if plan['paths']:
            required_slots = psql(services[domain + '_admin'], 'SELECT slot_name FROM pg_replication_slots WHERE failover AND NOT temporary', True).split()
            if len(required_slots) < len(spec['databases']):
                raise ValueError('required logical slots are absent on publisher')
            for candidate in HOSTS:
                if candidate == spec['initial_owner']:
                    continue
                candidate_service = services[domain + '_candidate_' + candidate]
                recovery = psql(candidate_service, 'SELECT pg_is_in_recovery()', True).strip()
                if recovery != 't':
                    raise ValueError('candidate is not a physical standby')
                rows = json.loads(psql(candidate_service, "SELECT coalesce(json_agg(row_to_json(t)),'[]'::json) FROM (SELECT slot_name,synced,temporary,failover,invalidation_reason FROM pg_replication_slots WHERE slot_type='logical') t", True))
                if not slots_ready(required_slots, rows):
                    raise ValueError('candidate missing synchronized failover/tablesync slot')
                evidence['checks']['slots_' + candidate] = {'required': required_slots, 'rows': rows, 'candidate_in_recovery': recovery}
        # Runtime failover/slot/restore witnesses remain separate; this receipt
        # cannot on its own authorize promotion or claim recovery qualification.
        return evidence
    raise ValueError('unknown provisioning phase')
