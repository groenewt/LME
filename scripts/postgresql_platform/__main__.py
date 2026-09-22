"""Offline rendering and explicit database operations; errors do not print secrets."""
import argparse
import json
import os
import pathlib
import subprocess
import sys

from .platform import TABLES, gate, live_gate, render, safe_token, slots_ready, topology

SQL = pathlib.Path(__file__).with_name('sql')


def psql(service, query, tuples=False):
    safe_token(service, r'[a-zA-Z0-9_-]+')
    command = ['psql', '-X', '-v', 'ON_ERROR_STOP=1', f'service={service} sslmode=verify-full']
    if tuples:
        command += ['-A', '-t']
    result = subprocess.run(command, input=query, text=True, capture_output=True,
                            env={**os.environ, 'PGOPTIONS': '-c synchronous_commit=on'})
    if result.returncode:
        # A libpq error can include conninfo. Never print captured output here.
        raise ValueError('PostgreSQL operation failed; inspect restricted database logs')
    return result.stdout


def native_schema(service, database):
    """Read catalog metadata only. Match actual types and selected native PKs."""
    if database not in TABLES:
        raise ValueError('unknown source database')
    statements = []
    for table, columns in TABLES[database].items():
        if table in ('lme_vector_probe', 'lme_litellm_status'):
            continue  # New tables use the exact constrained schema files on both ends.
        names = ','.join("'" + col + "'" for col in columns)
        query = f"""SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (
SELECT a.attname AS name, format_type(a.atttypid,a.atttypmod) AS type,
       a.attnotnull AS not_null,
       EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid=a.attrelid AND i.indisprimary AND a.attnum=ANY(i.indkey)) AS pk
FROM pg_attribute a WHERE a.attrelid='public.{table}'::regclass
  AND a.attnum>0 AND NOT a.attisdropped AND a.attname IN ({names}) ORDER BY a.attnum) t;"""
        rows = json.loads(psql(service, query, True))
        if {row['name'] for row in rows} != set(columns) or not any(row['pk'] for row in rows):
            raise ValueError('native schema missing selected columns or primary key')
        # PostgreSQL format_type output is trusted catalog SQL, never row data.
        definitions = ['"' + row['name'] + '" ' + row['type'] + (' NOT NULL' if row['not_null'] else '') for row in rows]
        definitions.append('PRIMARY KEY (' + ','.join('"' + row['name'] + '"' for row in rows if row['pk']) + ')')
        statements.append(f'CREATE TABLE public.{table} (' + ', '.join(definitions) + ');')
    return '\n'.join(statements) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    renderer = sub.add_parser('render')
    renderer.add_argument('--config', required=True)
    renderer.add_argument('--output', required=True)
    proxy = sub.add_parser('proxy')
    proxy.add_argument('--config', required=True)
    phase = sub.add_parser('provision')
    phase.add_argument('--config', required=True)
    phase.add_argument('--domain', choices=('hertzbeat', 'vector', 'shared'), required=True)
    phase.add_argument('--phase', choices=('schema', 'publications', 'subscriptions', 'ready'), required=True)
    for name in ('gate', 'bootstrap'):
        command = sub.add_parser(name)
        for option in ('context', 'receipt', 'public-key', 'authority-socket'):
            command.add_argument('--' + option, required=True)
        if name == 'bootstrap':
            command.add_argument('--data-dir', required=True)
    live = sub.add_parser('gate-live')
    live.add_argument('--config', required=True)
    live.add_argument('--domain', choices=('hertzbeat','vector','shared'), required=True)
    live.add_argument('--action', choices=('bootstrap','promote'), required=True)
    live.add_argument('--public-key', required=True)
    live.add_argument('--authority-socket', required=True)
    live.add_argument('--data-dir')
    schema = sub.add_parser('schema-export')
    schema.add_argument('--service', required=True)
    schema.add_argument('--database', choices=TABLES, required=True)
    slots = sub.add_parser('slots-check')
    slots.add_argument('--subscriber-service', action='append', required=True)
    slots.add_argument('--candidate-service', required=True)
    sql = sub.add_parser('apply')
    sql.add_argument('--service', required=True)
    sql.add_argument('--file', required=True)
    acceptance = sub.add_parser('acceptance')
    acceptance.add_argument('--config', required=True)
    acceptance.add_argument('--domain', choices=('hertzbeat','vector','shared'), required=True)
    acceptance.add_argument('--probe', choices=('import-denial','vector-seed','vector-baseline','vector-cleanup'), required=True)
    acceptance.add_argument('--generation', type=int, required=True)
    backup = sub.add_parser('backup')
    backup.add_argument('--domain', choices=('hertzbeat', 'vector', 'shared'), required=True)
    backup.add_argument('--type', choices=('full', 'diff', 'incr'), default='full')
    recovery = sub.add_parser('restore')
    recovery.add_argument('--domain', choices=('hertzbeat', 'vector', 'shared'), required=True)
    recovery.add_argument('--data-dir', required=True)
    recovery.add_argument('--target-time')
    rejoin = sub.add_parser('rejoin')
    rejoin.add_argument('--config', required=True)
    rejoin.add_argument('--domain', choices=('hertzbeat', 'vector', 'shared'), required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'render':
            files = render(json.loads(pathlib.Path(args.config).read_text()))
            output = pathlib.Path(args.output)
            output.mkdir(parents=True, exist_ok=True, mode=0o700)
            for name, content in files.items():
                (output / name).write_text(content)
                (output / name).chmod(0o600)
        elif args.command == 'proxy':
            from .proxy import serve
            serve(json.loads(pathlib.Path(args.config).read_text()))
        elif args.command == 'provision':
            from .provision import provision
            evidence = provision(json.loads(pathlib.Path(args.config).read_text()), args.domain, args.phase)
            if evidence is not None:
                print(json.dumps(evidence, sort_keys=True))
        elif args.command == 'gate-live':
            config = json.loads(pathlib.Path(args.config).read_text())
            if args.action == 'bootstrap':
                if args.data_dir != '/var/lib/postgresql/data':
                    raise ValueError('bootstrap requires the exact mounted data directory')
                directory = pathlib.Path(args.data_dir)
                if directory.exists() and any(directory.iterdir()):
                    raise ValueError('bootstrap requires empty data before authorization')
            elif args.data_dir is not None:
                raise ValueError('promotion does not accept a data directory')
            live_gate(config, args.domain, args.action, args.public_key, args.authority_socket)
            if args.action == 'bootstrap':
                subprocess.run(['initdb', '-D', args.data_dir, '--auth-local=peer', '--auth-host=scram-sha-256', '--data-checksums'], check=True)
        elif args.command in ('gate', 'bootstrap'):
            context = json.loads(pathlib.Path(args.context).read_text())
            if args.command == 'bootstrap' and context['action'] != 'bootstrap':
                raise ValueError('bootstrap context required')
            gate(context, json.loads(pathlib.Path(args.receipt).read_text()), args.public_key, args.authority_socket)
            if args.command == 'bootstrap':
                directory = pathlib.Path(args.data_dir)
                if directory.exists() and any(directory.iterdir()):
                    raise ValueError('bootstrap only accepts a fresh empty data directory')
                subprocess.run(['initdb', '-D', str(directory), '--auth-local=peer', '--auth-host=scram-sha-256', '--data-checksums'], check=True)
        elif args.command == 'schema-export':
            print(native_schema(args.service, args.database), end='')
        elif args.command == 'slots-check':
            expected = set()
            for service in args.subscriber_service:
                expected.update(psql(service, (SQL / 'slots-required.sql').read_text(), True).split())
            query = 'SELECT COALESCE(json_agg(row_to_json(t)),\'[]\'::json) FROM (' + (SQL / 'slots-candidate.sql').read_text().rstrip().rstrip(';') + ') t;'
            rows = json.loads(psql(args.candidate_service, query, True))
            if not slots_ready(sorted(expected), rows):
                raise ValueError('failover slots missing, unsynchronized, temporary or invalid')
        elif args.command == 'apply':
            psql(args.service, pathlib.Path(args.file).read_text())
        elif args.command == 'acceptance':
            from .acceptance import probe
            evidence = probe(json.loads(pathlib.Path(args.config).read_text()), args.domain, args.probe, args.generation)
            print(json.dumps(evidence, sort_keys=True))
        elif args.command == 'backup':
            subprocess.run(['pgbackrest', '--stanza=' + args.domain, 'check'], check=True)
            subprocess.run(['pgbackrest', '--stanza=' + args.domain, '--type=' + args.type, 'backup'], check=True)
        elif args.command == 'restore':
            from .recovery import restore
            restore(args.domain, args.data_dir, args.target_time)
        elif args.command == 'rejoin':
            from .rejoin import rebuild
            evidence = rebuild(json.loads(pathlib.Path(args.config).read_text()), args.domain, json.load(sys.stdin))
            print(json.dumps(evidence, sort_keys=True))
    except (ValueError, KeyError, OSError, subprocess.SubprocessError, json.JSONDecodeError):
        print('PostgreSQL platform action rejected or failed; no readiness asserted.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
