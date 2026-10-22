"""Opt-in, task-owned PostgreSQL17 integration tests. No default live connection."""
import ast
import json
import os
import pathlib
import pwd
import subprocess
import tempfile
import time
import unittest
import uuid

from scripts.postgresql_platform.platform import publication_sql, subscription_sql

ROOT = pathlib.Path(__file__).resolve().parents[3]
SQL = ROOT / 'scripts/postgresql_platform/sql'


@unittest.skipUnless(os.environ.get('LME_PG17_TEST_SOCKET'), 'isolated PG17 socket not supplied')
class PostgreSQL17Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.psql = os.environ['LME_PG17_TEST_PSQL']
        cls.socket = os.environ['LME_PG17_TEST_SOCKET']
        if not cls.socket.startswith('/tmp/lme-'):
            raise RuntimeError('only task-owned /tmp sockets accepted')
        cls.database = 'task6_' + uuid.uuid4().hex
        cls.query('postgres', 'CREATE DATABASE ' + cls.database)
        version = int(cls.query(cls.database, 'SHOW server_version_num').strip())
        if not 170000 <= version < 180000:
            raise RuntimeError('PostgreSQL17 required')

    @classmethod
    def tearDownClass(cls):
        cls.query('postgres', 'DROP DATABASE ' + cls.database)

    @classmethod
    def query(cls, database, sql, check=True):
        result = subprocess.run([cls.psql, '-X', '-At', '-v', 'ON_ERROR_STOP=1', '-U', pwd.getpwuid(os.getuid()).pw_name, '-h', cls.socket, '-p', '55432', '-d', database], input=sql, text=True, capture_output=True)
        if check and result.returncode:
            raise AssertionError(result.stderr)
        return result.stdout if check else result

    def test_new_tables_constraints_publications_and_subscription_options(self):
        self.query(self.database, (SQL / 'vector-source.sql').read_text() + (SQL / 'litellm-status.sql').read_text())
        self.query(self.database, publication_sql('lme_vectors'))
        columns = self.query(self.database, "SELECT attnames::text FROM pg_publication_tables WHERE pubname='lme_lme_vectors' AND tablename='docs_chunks'")
        self.assertEqual(columns.strip(), '{id,chunk_index,created_at}')
        operations = self.query(self.database, "SELECT pubinsert AND pubupdate AND pubdelete AND NOT pubtruncate FROM pg_publication WHERE pubname='lme_lme_vectors'")
        self.assertEqual(operations.strip(), 't')
        generated = subscription_sql('litellm', 'pg-vector-rw', '/run/secrets/logical.pgpass')
        # Parse the actual generated PG17 options without opening any network connection.
        generated = generated.replace('copy_data = true, enabled = true', 'connect = false')
        self.query(self.database, generated)
        options = self.query(self.database, "SELECT subfailover, suborigin, subsynccommit FROM pg_subscription WHERE subname='sub_litellm'")
        self.assertEqual(options.strip(), 't|none|on')
        self.query(self.database, 'ALTER SUBSCRIPTION sub_litellm SET (slot_name = NONE); DROP SUBSCRIPTION sub_litellm;')
        rejected = self.query(self.database, "INSERT INTO lme_litellm_status VALUES ('a',4,'v','sha256:'||repeat('a',64),now(),NULL)", check=False)
        self.assertNotEqual(rejected.returncode, 0)
        rejected = self.query(self.database, "INSERT INTO lme_litellm_status VALUES ('a',1,'v','bad-digest',now(),NULL)", check=False)
        self.assertNotEqual(rejected.returncode, 0)
        self.query(self.database, 'DROP PUBLICATION lme_lme_vectors')

    def test_reset_preserves_actual_oid_sequence_and_publication(self):
        self.query(self.database, (SQL / 'vector-source.sql').read_text())
        self.query(self.database, publication_sql('lme_vectors'))
        for relative in ('scripts/ingest_docs.py', 'lme-dashboard/scripts/ingest_docs.py'):
            self.query(self.database, "INSERT INTO docs_chunks(url,content) VALUES ('synthetic','fixture')")
            before = self.query(self.database, "SELECT 'docs_chunks'::regclass::oid,last_value FROM docs_chunks_id_seq").strip()
            tree = ast.parse((ROOT / relative).read_text())
            function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'setup_db')
            namespace = {'EMBED_DIMS': 768}
            exec(compile(ast.Module(body=[function], type_ignores=[]), relative, 'exec'), namespace)
            connection = SQLBatch(self)
            namespace['setup_db'](connection, reset=True)
            after = self.query(self.database, "SELECT 'docs_chunks'::regclass::oid,last_value FROM docs_chunks_id_seq").strip()
            self.assertEqual(before, after)
            self.assertEqual(self.query(self.database, 'SELECT count(*) FROM docs_chunks').strip(), '0')
            self.assertEqual(self.query(self.database, "SELECT count(*) FROM pg_publication_tables WHERE pubname='lme_lme_vectors'").strip(), '2')
        self.query(self.database, 'DROP PUBLICATION lme_lme_vectors')

    def test_synthetic_vector_cosine_ranking(self):
        self.query(self.database, (SQL / 'vector-source.sql').read_text())
        vector = lambda a, b: '[' + ','.join(map(str, [a, b] + [0] * 766)) + ']'
        e1, mixed, e2 = vector(1, 0), vector(2 ** -.5, 2 ** -.5), vector(0, 1)
        for i, embedding in enumerate((e1, mixed, e2), 1):
            self.query(self.database, f"INSERT INTO lme_vector_probe VALUES ('00000000-0000-0000-0000-{i:012}',1,1,'{embedding}',now()) ON CONFLICT(probe_id) DO UPDATE SET embedding=EXCLUDED.embedding")
        ranking = self.query(self.database, f"SELECT right(probe_id::text,1) FROM lme_vector_probe ORDER BY embedding <=> '{e1}'::vector")
        self.assertEqual(ranking.split(), ['1', '2', '3'])

    def test_native_logical_insert_update_delete_preserves_safe_projection(self):
        self.query(self.database, (SQL / 'vector-source.sql').read_text())
        target, slot = 'task6_replica_' + uuid.uuid4().hex, 'task6_slot_' + uuid.uuid4().hex
        self.query('postgres', 'CREATE DATABASE ' + target)
        subscription_created = False
        try:
            self.query(target, (SQL / 'vector-replica.sql').read_text())
            self.query(self.database, publication_sql('lme_vectors'))
            self.query(self.database, f"SELECT * FROM pg_create_logical_replication_slot('{slot}','pgoutput',false,false,true)")
            connection = f'host={self.socket} port=55432 user={pwd.getpwuid(os.getuid()).pw_name} dbname={self.database}'
            self.query(target, f"CREATE SUBSCRIPTION task6_sub CONNECTION '{connection}' PUBLICATION lme_lme_vectors WITH(create_slot=false,slot_name='{slot}',failover=true,origin=none,synchronous_commit=on)")
            subscription_created = True
            def await_value(query, expected):
                end = time.monotonic() + 20
                while time.monotonic() < end:
                    if self.query(target, query).strip() == expected:
                        return
                    time.sleep(.1)
                self.fail('logical replication did not reach expected committed state')
            await_value("SELECT count(*) FROM pg_subscription_rel WHERE srsubstate='r'", '2')
            ident = self.query(self.database, "INSERT INTO docs_chunks(url,content,chunk_index) VALUES ('synthetic-sentinel','never-publish-this-content',7) RETURNING id").splitlines()[0]
            await_value(f'SELECT chunk_index FROM docs_chunks WHERE id={ident}', '7')
            self.assertEqual(self.query(target, "SELECT count(*) FROM information_schema.columns WHERE table_name='docs_chunks' AND column_name IN ('url','content','embedding')").strip(), '0')
            self.query(self.database, f'UPDATE docs_chunks SET chunk_index=8 WHERE id={ident}')
            await_value(f'SELECT chunk_index FROM docs_chunks WHERE id={ident}', '8')
            self.query(self.database, f'DELETE FROM docs_chunks WHERE id={ident}')
            await_value(f'SELECT count(*) FROM docs_chunks WHERE id={ident}', '0')
            self.query(target, (SQL / 'roles.sql').read_text() + 'GRANT CONNECT ON DATABASE ' + target + ' TO lme_replica_reader; GRANT USAGE ON SCHEMA public TO lme_replica_reader; GRANT SELECT ON ALL TABLES IN SCHEMA public TO lme_replica_reader;')
            result = self.query(target, "SET ROLE lme_replica_reader; INSERT INTO docs_chunks(id) VALUES (999999)", check=False)
            self.assertNotEqual(result.returncode, 0)
            source_constraints = self.query(self.database, "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='lme_vector_probe'::regclass ORDER BY pg_get_constraintdef(oid)")
            replica_constraints = self.query(target, "SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='lme_vector_probe'::regclass ORDER BY pg_get_constraintdef(oid)")
            self.assertEqual(source_constraints, replica_constraints)
        finally:
            if subscription_created:
                self.query(target, 'DROP SUBSCRIPTION task6_sub')
            else:
                self.query(self.database, f"SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name='{slot}'")
            self.query(self.database, 'DROP PUBLICATION IF EXISTS lme_lme_vectors')
            self.query('postgres', 'DROP DATABASE ' + target)

    def test_isolated_logical_dump_restore_reconciles_schema_and_rows(self):
        self.query(self.database, (SQL / 'vector-source.sql').read_text())
        self.query(self.database, "INSERT INTO docs_chunks(url,content,chunk_index) VALUES ('synthetic-backup','fixture',6)")
        expected = self.query(self.database, 'SELECT count(*),sum(chunk_index) FROM docs_chunks')
        target = 'task6_restore_' + uuid.uuid4().hex
        self.query('postgres', 'CREATE DATABASE ' + target)
        try:
            with tempfile.TemporaryDirectory(prefix='lme-pg-dump-test-') as directory:
                archive = pathlib.Path(directory) / 'source.dump'
                common = ['-h', self.socket, '-p', '55432', '-U', pwd.getpwuid(os.getuid()).pw_name]
                dump = pathlib.Path(self.psql).with_name('pg_dump')
                restore = pathlib.Path(self.psql).with_name('pg_restore')
                subprocess.run([str(dump), *common, '-Fc', '-f', str(archive), self.database], check=True, capture_output=True)
                subprocess.run([str(restore), *common, '--exit-on-error', '-d', target, str(archive)], check=True, capture_output=True)
                self.assertEqual(self.query(target, 'SELECT count(*),sum(chunk_index) FROM docs_chunks'), expected)
                self.assertEqual(self.query(target, "SELECT extversion FROM pg_extension WHERE extname='vector'").strip(), '0.8.1')
        finally:
            self.query('postgres', 'DROP DATABASE ' + target)


class SQLBatch:
    def __init__(self, test): self.test, self.statements = test, []
    def cursor(self): return self
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def execute(self, sql): self.statements.append(sql)
    def commit(self): self.test.query(self.test.database, 'BEGIN;\n' + '\n'.join(self.statements) + '\nCOMMIT;')


if __name__ == '__main__': unittest.main()
