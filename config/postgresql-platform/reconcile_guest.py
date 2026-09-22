#!/usr/bin/env python3
"""Forced-command helper: inspect and reconcile only one owned Patroni domain."""
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import tempfile

OWNERS = {'hertzbeat':'lmedbhb','vector':'lmedbvector','shared':'lmedbshared'}
NODES = ('graph','trixie','silmaril')


def lsn(value):
    if not isinstance(value,str) or not re.fullmatch(r'[0-9A-F]+/[0-9A-F]+',value):
        raise ValueError('invalid WAL position')
    upper,lower = value.split('/')
    return (int(upper,16)<<32)+int(lower,16)


def ready(observed, request):
    if observed['recovery'] is not True or observed['inhibited'] or observed['system_identifier'] != request['expected_system_identifier']:
        raise ValueError('candidate recovery, lineage or quarantine mismatch')
    if lsn(observed['lsn']) < lsn(request['minimum_lsn']):
        raise ValueError('candidate WAL has not reached the observed primary')
    required = request['required_slots']
    if request['domain'] != 'shared' and not required:
        raise ValueError('logical slot readiness cannot be empty')
    rows = {row['slot_name']:row for row in observed['slots']}
    if any(name not in rows or rows[name].get('synced') is not True or rows[name].get('temporary') is not False
           or rows[name].get('failover') is not True or rows[name].get('invalidation_reason') is not None for name in required):
        raise ValueError('candidate failover slots are not complete')


def main(request):
    domain,node,run = request['domain'],request['node'],request['run_id']
    if os.geteuid() != 0 or domain not in OWNERS or node not in NODES or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}',run):
        raise ValueError('invalid reconciliation identity')
    if Path('/var/lib/cloud/data/instance-id').read_text().strip() != request['qemu_generation']:
        raise ValueError('actual guest generation differs')
    owner = OWNERS[domain]
    user = pwd.getpwnam(owner)
    prefix = ['runuser','-u',owner,'--','env','XDG_RUNTIME_DIR=/run/user/'+str(user.pw_uid),'podman']
    def run_command(command):
        result = subprocess.run(prefix+command,capture_output=True,text=True,timeout=30)
        if result.returncode:
            raise ValueError('owned database reconciliation command failed')
        return result.stdout
    port = '5434' if domain == 'vector' else '5433'
    query = """SELECT json_build_object(
'recovery',pg_is_in_recovery(),
'system_identifier',(SELECT system_identifier::text FROM pg_control_system()),
'lsn',CASE WHEN pg_is_in_recovery() THEN pg_last_wal_replay_lsn()::text ELSE pg_current_wal_flush_lsn()::text END,
'current_guard',current_setting('synchronized_standby_slots'),
'physical',COALESCE((SELECT json_agg(json_build_object('application_name',application_name,'state',state,'sync_state',sync_state,'flush_lsn',flush_lsn::text)) FROM pg_stat_replication),'[]'::json),
'slots',COALESCE((SELECT json_agg(json_build_object('slot_name',slot_name,'synced',synced,'temporary',temporary,'failover',failover,'invalidation_reason',invalidation_reason)) FROM pg_replication_slots WHERE slot_type='logical'),'[]'::json));"""
    observed = json.loads(run_command(['exec','pg-'+domain,'psql','-X','-h','/tmp','-U','postgres','-p',port,'-d','postgres','-Atqc',query]))
    observed['inhibited'] = Path('/var/lib/lme-fencing/inhibit',run,domain,node).exists()
    path = Path('/data',owner,'config/postgresql',domain,'patroni.json')
    if path.is_symlink() or path.resolve() != path:
        raise ValueError('Patroni configuration aliases are forbidden')
    config = json.loads(path.read_text())
    observed['nofailover'] = config.get('tags',{}).get('nofailover',False)
    operation = request['operation']
    if operation == 'inspect':
        return observed
    if operation == 'subscriber_slots':
        databases = {'hertzbeat':['lme_vectors_replica','litellm_replica'],'vector':['hertzbeat_replica'],'shared':[]}[domain]
        slots = []
        query = "SELECT subslotname FROM pg_subscription WHERE subfailover AND subslotname IS NOT NULL UNION SELECT CONCAT('pg_',r.srsubid,'_sync_',r.srrelid,'_',ctl.system_identifier) FROM pg_control_system() ctl,pg_subscription_rel r,pg_subscription s WHERE r.srsubstate='f' AND s.oid=r.srsubid AND s.subfailover;"
        for database in databases:
            slots.extend(run_command(['exec','pg-'+domain,'psql','-X','-h','/tmp','-U','postgres','-p',port,'-d',database,'-Atqc',query]).split())
        return {'slots':sorted(set(slots)),'recovery':observed['recovery']}
    if observed['system_identifier'] != request['expected_system_identifier']:
        raise ValueError('database lineage changed before reconciliation')
    if operation == 'set_guard':
        guard = request['standby']
        if observed['recovery'] or observed['inhibited'] or guard not in NODES or guard == node:
            raise ValueError('guard update requires current unquarantined primary')
        config['postgresql'].setdefault('parameters',{})['synchronized_standby_slots'] = guard
    elif operation == 'eligibility':
        if type(request['nofailover']) is not bool:
            raise ValueError('nofailover must be a boolean')
        if request['nofailover'] is False:
            ready(observed,request)
        config.setdefault('tags',{})['nofailover'] = request['nofailover']
    else:
        raise ValueError('reconciliation operation is not authorized')
    info = path.stat()
    with tempfile.NamedTemporaryFile(mode='w',dir=path.parent,prefix='.reconcile-',delete=False) as output:
        json.dump(config,output,sort_keys=True)
        output.flush()
        os.fsync(output.fileno())
        os.fchmod(output.fileno(),0o600)
        os.fchown(output.fileno(),info.st_uid,info.st_gid)
        temporary = output.name
    os.replace(temporary,path)
    run_command(['kill','--signal','HUP','pg-'+domain])
    return {'changed':True,'operation':operation,'domain':domain,'node':node}
