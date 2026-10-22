import importlib
import json
import os
import pathlib
import pwd
import subprocess
import unittest
import uuid
from unittest.mock import patch


class ProbeTests(unittest.TestCase):
    def api(self):
        return importlib.import_module('scripts.postgresql_platform.acceptance')

    def test_denial_retains_actual_sqlstate_and_uses_reader_login(self):
        calls = []
        def execute(service, sql):
            calls.append((service,sql))
            return {'returncode':0,'stdout':'lme_identity={"current_user":"lme_replica_reader"}\nlme_sqlstate=42501\n','stderr':'ERROR: permission denied for table docs_chunks\n'}
        result = self.api().probe({'run_id':'fixture','profile':'dual-owned-ha','node':'trixie'},'hertzbeat','import-denial',1,execute)
        self.assertEqual(len(result['queries']),3)
        self.assertTrue(all(row['sqlstate']=='42501' for row in result['queries']))
        self.assertTrue(all(service.endswith('_replica_reader') for service,_ in calls))
        self.assertTrue(all('WHERE false' in sql and 'ROLLBACK;' in sql for _,sql in calls))
        self.assertIn('permission denied',result['queries'][0]['stderr'])

    def test_shared_absence_requires_actual_catalog_queries(self):
        calls=[]
        def execute(service,sql):
            calls.append((service,sql))
            return {'returncode':0,'stdout':'lme_sqlstate=00000\nlme_commit_sqlstate=00000\nlme_rows=[{"publications":[],"subscriptions":[],"logical_slots":[]}]\n','stderr':''}
        result=self.api().probe({'run_id':'fixture','profile':'shared-ha','node':'graph'},'shared','import-denial',1,execute)
        self.assertEqual(len(result['queries']),3)
        self.assertTrue(all(row['observation_kind']=='logical-topology-catalog' for row in result['queries']))
        for service,sql in calls:
            self.assertIn('pg_publication',sql)
            self.assertIn('pg_subscription',sql)
            self.assertIn('pg_replication_slots',sql)
            self.assertNotIn('subconninfo',sql)
            self.assertIn('BEGIN READ ONLY',sql)

    def test_transport_forces_tls_and_does_not_forward_password_environment(self):
        api=self.api()
        completed=subprocess.CompletedProcess([],0,stdout='',stderr='')
        with patch.dict(os.environ,{'PGPASSWORD':'synthetic-secret'}), patch.object(api.subprocess,'run',return_value=completed) as run:
            api.execute('lme_vectors_reader','SELECT 1;')
        argv=run.call_args.args[0]
        self.assertIn('sslmode=verify-full',argv[-1])
        self.assertNotIn('PGPASSWORD',run.call_args.kwargs['env'])
        self.assertNotIn('synthetic-secret',repr(argv))
        self.assertEqual(run.call_args.kwargs['timeout'],25)

    def test_vector_fixture_is_run_and_generation_scoped(self):
        api=self.api()
        self.assertNotEqual(api.fixture_ids('one',1),api.fixture_ids('two',1))
        self.assertNotEqual(api.fixture_ids('one',1),api.fixture_ids('one',2))
        calls=[]
        def execute(service,sql):
            calls.append((service,sql))
            return {'returncode':0,'stdout':'lme_sqlstate=00000\nlme_rows=[]\n','stderr':''}
        config={'run_id':'fixture','profile':'dual-owned-ha','node':'graph'}
        api.probe(config,'vector','vector-baseline',1,execute)
        self.assertEqual(calls[0][0],'lme_vectors_reader')
        self.assertIn('enable_indexscan=off',calls[0][1])
        self.assertIn('enable_bitmapscan=off',calls[0][1])
        self.assertNotIn('docs_chunks',calls[0][1])
        with self.assertRaises(ValueError): api.probe(config,'hertzbeat','vector-seed',1,execute)


@unittest.skipUnless(os.environ.get('LME_PG17_TEST_SOCKET'),'isolated PG17 socket not supplied')
class ActualProbeTests(unittest.TestCase):
    def test_actual_reader_denial_seed_exact_baseline_and_scoped_cleanup(self):
        from scripts.postgresql_platform import acceptance as api
        directory=pathlib.Path(__file__).resolve().parents[3]/'scripts/postgresql_platform/sql'
        psql=os.environ['LME_PG17_TEST_PSQL']
        socket=os.environ['LME_PG17_TEST_SOCKET']
        self.assertTrue(socket.startswith('/tmp/lme-'))
        database='task6_accept_'+uuid.uuid4().hex
        role='task6_reader_'+uuid.uuid4().hex[:16]
        user=pwd.getpwuid(os.getuid()).pw_name
        base=[psql,'-X','-At','-h',socket,'-p','55432']
        def sql(query,db='postgres'):
            result=subprocess.run(base+['-U',user,'-d',db,'-v','ON_ERROR_STOP=1'],input=query,text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            return result.stdout
        sql('CREATE DATABASE '+database)
        try:
            sql('CREATE ROLE '+role+' LOGIN; GRANT CONNECT ON DATABASE '+database+' TO '+role)
            sql((directory/'vector-source.sql').read_text()+(directory/'litellm-status.sql').read_text()+f'GRANT USAGE ON SCHEMA public TO {role}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO {role};',database)
            def execute(service,query):
                login=role if service.endswith('_reader') else user
                result=subprocess.run(base+['-U',login,'-d',database],input=query,text=True,capture_output=True)
                return {'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
            cfg={'run_id':'actual-fixture','profile':'dual-owned-ha','node':'graph'}
            absent=api.probe({**cfg,'profile':'shared-ha'},'shared','import-denial',1,execute)
            self.assertTrue(all(row['sqlstate']=='00000' for row in absent['queries']))
            self.assertTrue(all(row['rows']==[{'publications':[],'subscriptions':[],'logical_slots':[]}] for row in absent['queries']))
            sql('CREATE PUBLICATION task6_unexpected FOR TABLE lme_vector_probe',database)
            unexpected_catalog=api.probe({**cfg,'profile':'shared-ha'},'shared','import-denial',1,execute)
            self.assertEqual(unexpected_catalog['queries'][0]['rows'][0]['publications'][0]['pubname'],'task6_unexpected')
            sql('DROP PUBLICATION task6_unexpected',database)
            denied=api.probe(cfg,'hertzbeat','import-denial',1,execute)
            self.assertTrue(all(row['sqlstate']=='42501' for row in denied['queries']))
            self.assertTrue(all(row['identity']['current_user']==role for row in denied['queries']))
            sql(f'GRANT UPDATE ON docs_chunks TO {role}',database)
            unexpected=api.probe(cfg,'hertzbeat','import-denial',1,execute)
            self.assertEqual(unexpected['queries'][0]['sqlstate'],'00000')
            self.assertEqual(sql('SELECT count(*) FROM docs_chunks',database).strip(),'0')
            sql(f'REVOKE UPDATE ON docs_chunks FROM {role}',database)
            seeded=api.probe(cfg,'vector','vector-seed',1,execute)
            self.assertEqual(seeded['queries'][0]['sqlstate'],'00000')
            baseline=api.probe(cfg,'vector','vector-baseline',1,execute)
            rows=baseline['queries'][0]['rows']
            self.assertEqual([row['probe_id'] for row in rows],api.fixture_ids('actual-fixture',1))
            self.assertEqual([round(row['distance'],6) for row in rows],[0.0,0.292893,1.0])
            api.probe(cfg,'vector','vector-seed',2,execute)
            api.probe(cfg,'vector','vector-cleanup',1,execute)
            self.assertEqual(sql('SELECT count(*) FROM lme_vector_probe',database).strip(),'3')
            self.assertEqual(sql('SELECT min(generation) FROM lme_vector_probe',database).strip(),'2')
        finally:
            sql('DROP DATABASE '+database)
            sql('DROP ROLE IF EXISTS '+role)

if __name__=='__main__': unittest.main()
