"""Bounded deployed probes. Results contain SQL evidence, never pass assertions."""
import json
import os
import re
import subprocess
import time
import uuid

from .platform import TABLES, safe_token, topology

IDENTITY = """SELECT 'lme_identity=' || json_build_object(
 'current_user',current_user,'session_user',session_user,'database',current_database(),
 'server_address',inet_server_addr(),'server_port',inet_server_port(),
 'ssl',(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),
 'synchronous_commit',current_setting('synchronous_commit'),
 'enable_indexscan',current_setting('enable_indexscan'),
 'enable_bitmapscan',current_setting('enable_bitmapscan'),
 'backend_pid',pg_backend_pid(),'observed_at',clock_timestamp())::text;
"""


def fixture_ids(run, generation):
    safe_token(run, r'[a-z0-9][a-z0-9-]{0,31}')
    if type(generation) is not int or generation <= 0 or generation > 2**63-1:
        raise ValueError('positive bigint fixture generation required')
    return [str(uuid.uuid5(uuid.NAMESPACE_URL,f'lme:{run}:vector:{generation}:{label}')) for label in ('e1','mixed','e2')]


def execute(service, query):
    safe_token(service, r'[a-zA-Z0-9_-]+')
    env={key:value for key,value in os.environ.items() if key not in ('PGPASSWORD','PGOPTIONS')}
    env['PGOPTIONS']='-c synchronous_commit=on -c statement_timeout=15000 -c lock_timeout=3000'
    argv=['psql','-X','-A','-t','-v','ON_ERROR_STOP=0',f'service={service} sslmode=verify-full connect_timeout=5']
    try:
        result=subprocess.run(argv,input=query,text=True,capture_output=True,env=env,timeout=25)
        return {'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
    except subprocess.TimeoutExpired as error:
        def string(value): return value.decode(errors='replace') if isinstance(value,bytes) else value or ''
        return {'returncode':None,'timeout':True,'stdout':string(error.stdout),'stderr':string(error.stderr)}


def _query(service, query, executor):
    result=dict(executor(service,query),service=service,query=query)
    result.update(sqlstate=None,commit_sqlstate=None,identity=None,rows=None)
    for line in result['stdout'].splitlines():
        if line.startswith('lme_sqlstate='):
            value=line.partition('=')[2]
            if re.fullmatch(r'[0-9A-Z]{5}',value): result['sqlstate']=value
        elif line.startswith('lme_commit_sqlstate='):
            value=line.partition('=')[2]
            if re.fullmatch(r'[0-9A-Z]{5}',value): result['commit_sqlstate']=value
        elif line.startswith('lme_identity='):
            try: result['identity']=json.loads(line.partition('=')[2])
            except json.JSONDecodeError: result.setdefault('parse_errors',[]).append('identity JSON incomplete')
        elif line.startswith('lme_rows='):
            try: result['rows']=json.loads(line.partition('=')[2])
            except json.JSONDecodeError: result.setdefault('parse_errors',[]).append('rows JSON incomplete')
    return result


def probe(config, domain, operation, generation, executor=execute):
    plan=topology(config['profile'])
    if domain not in plan['domains'] or config['node'] not in ('graph','trixie','silmaril'):
        raise ValueError('probe domain/node is outside resolved topology')
    ids=fixture_ids(config['run_id'],generation)
    result={'schema_version':1,'run_id':config['run_id'],'domain':domain,'node':config['node'],
            'source':'postgresql','probe':operation,'generation':generation,'issued_at':time.time(),'queries':[]}
    if operation=='import-denial':
        result['imports']=plan['domains'][domain]['imports']
        if domain=='shared':
            catalog="""SELECT 'lme_rows=' || jsonb_build_array(jsonb_build_object(
 'publications',(SELECT COALESCE(jsonb_agg(p),'[]'::jsonb) FROM
   (SELECT pubname,pubinsert,pubupdate,pubdelete,pubtruncate FROM pg_publication ORDER BY pubname) p),
 'subscriptions',(SELECT COALESCE(jsonb_agg(s),'[]'::jsonb) FROM
   (SELECT subname,subenabled,subfailover,suborigin FROM pg_subscription
    WHERE subdbid=(SELECT oid FROM pg_database WHERE datname=current_database()) ORDER BY subname) s),
 'logical_slots',(SELECT COALESCE(jsonb_agg(r),'[]'::jsonb) FROM
   (SELECT slot_name,database,failover,temporary,synced,invalidation_reason FROM pg_replication_slots
    WHERE slot_type='logical' AND database=current_database() ORDER BY slot_name) r)))::text;
"""
            query='BEGIN READ ONLY;\n'+IDENTITY+catalog+'\\echo lme_sqlstate=:SQLSTATE\nCOMMIT;\n\\echo lme_commit_sqlstate=:SQLSTATE\n'
            for database in plan['domains'][domain]['databases']:
                row=_query(database+'_source',query,executor)
                result['queries'].append(dict(row,database=database,expected_role='postgres',observation_kind='logical-topology-catalog'))
            return result
        for database in result['imports']:
            source=database.removesuffix('_replica')
            for table,columns in TABLES[source].items():
                query='BEGIN;\n'+IDENTITY+f'UPDATE public.{table} SET {columns[0]}={columns[0]} WHERE false;\n\\echo lme_sqlstate=:SQLSTATE\nROLLBACK;\n'
                row=_query(database+'_reader',query,executor)
                result['queries'].append(dict(row,database=database,table='public.'+table,expected_role='lme_replica_reader'))
        return result
    if operation not in ('vector-seed','vector-baseline','vector-cleanup'):
        raise ValueError('unknown bounded probe')
    imported=domain=='hertzbeat'
    if imported and operation!='vector-baseline':
        raise ValueError('synthetic fixture writes require the authoritative vector domain')
    result.update(fixture_ids=ids,database='lme_vectors_replica' if imported else 'lme_vectors',fixture_version=1)
    where='probe_id IN ('+','.join("'"+identifier+"'::uuid" for identifier in ids)+') AND generation='+str(generation)+' AND fixture_version=1'
    prefix='BEGIN;\n'
    if operation=='vector-baseline':
        prefix+='SET LOCAL enable_indexscan=off; SET LOCAL enable_bitmapscan=off;\n'
    query=prefix+IDENTITY
    if operation=='vector-baseline':
        vector='['+','.join(map(str,[1,0]+[0]*766))+']'
        query+="SELECT 'lme_rows=' || COALESCE(jsonb_agg(t),'[]'::jsonb)::text FROM (SELECT probe_id,generation,fixture_version,embedding::text AS embedding,updated_at,embedding <=> '"+vector+"'::vector AS distance FROM public.lme_vector_probe WHERE "+where+" ORDER BY distance,probe_id) t;\n"
        service='lme_vectors_replica_reader' if imported else 'lme_vectors_reader'
    elif operation=='vector-seed':
        vectors=([1,0],[2**-.5,2**-.5],[0,1])
        values=[]
        for identifier, first in zip(ids,vectors):
            vector='['+','.join(map(str,first+[0]*766))+']'
            values.append(f"('{identifier}',{generation},1,'{vector}',clock_timestamp())")
        query+="WITH written AS (INSERT INTO public.lme_vector_probe(probe_id,generation,fixture_version,embedding,updated_at) VALUES "+','.join(values)+" ON CONFLICT(probe_id) DO UPDATE SET generation=EXCLUDED.generation,fixture_version=EXCLUDED.fixture_version,embedding=EXCLUDED.embedding,updated_at=EXCLUDED.updated_at RETURNING probe_id,generation,fixture_version,updated_at) SELECT 'lme_rows=' || jsonb_agg(written)::text FROM written;\n"
        service='lme_vectors_source'
    else:
        query+="WITH deleted AS (DELETE FROM public.lme_vector_probe WHERE "+where+" RETURNING probe_id,generation) SELECT 'lme_rows=' || COALESCE(jsonb_agg(deleted),'[]'::jsonb)::text FROM deleted;\n"
        service='lme_vectors_source'
    query+='\\echo lme_sqlstate=:SQLSTATE\nCOMMIT;\n\\echo lme_commit_sqlstate=:SQLSTATE\n'
    result['queries'].append(_query(service,query,executor))
    return result
