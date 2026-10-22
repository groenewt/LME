"""Run from the installed package root: python3 -m lme_telemetry --config FILE COMMAND."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
from .delivery import Elastic, HertzBeat, Malcolm, work_once
from .server import admission_server, open_spool
from .spool import MAX_BATCH_BYTES, Conflict, validate_destinations


def ingest_file(spool,path,destinations):
    count=0
    with open(path,'rb') as stream:
        fcntl.flock(stream,fcntl.LOCK_SH|fcntl.LOCK_NB)
        info=os.fstat(stream.fileno())
        source=f'file:{Path(path).resolve()}:{info.st_dev}:{info.st_ino}'
        offset=spool.checkpoint(source) or 0
        if info.st_size<offset:
            raise Conflict('source truncated in place; rotate to a new inode/generation')
        stream.seek(offset)
        while True:
            line=stream.readline(MAX_BATCH_BYTES+1)
            if not line:
                break
            if len(line)>MAX_BATCH_BYTES:
                raise ValueError('source line exceeds 1MiB')
            if not line.endswith(b'\n'):
                break  # incomplete writes remain unread until a subsequent invocation
            record=json.loads(line)
            result=spool.admit([record],destinations,{'source':source,'offset':stream.tell()})
            count+=result['inserted']
    return {'ack':'local_fsync','inserted':count}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True)
    commands=parser.add_subparsers(dest='command',required=True)
    for command in ('serve','worker','work-once','status','gc'):
        commands.add_parser(command)
    ingest=commands.add_parser('ingest-file');ingest.add_argument('path')
    native=commands.add_parser('verify-native-metrics');native.add_argument('--outbox-dir',required=True)
    args=parser.parse_args(argv)
    try:
        with open(args.config) as stream:
            config=json.load(stream)
        validate_destinations(config['destinations'])
        if args.command=='verify-native-metrics':
            from .native_metrics import NativeElastic, NativeSourceAdapters, verify_outbox
            native=config['native_metrics']
            if 'sources' in native:
                adapters=NativeSourceAdapters({source:{'elastic':NativeElastic(sinks['elastic'])}
                                               for source,sinks in native['sources'].items()})
            else:
                adapters={'elastic':NativeElastic(native['elastic'])}
            result=verify_outbox(args.outbox_dir,adapters)
            print(json.dumps(result,sort_keys=True))
            return 1 if result['pending'] else 0
        if args.command=='serve':
            server=admission_server(config)
            try:
                server.serve_forever()
            finally:
                server.server_close()
            return 0
        spool=open_spool(config)
        try:
            if args.command=='status':
                print(json.dumps(spool.status(),sort_keys=True));return 0
            if args.command=='gc':
                print(json.dumps({'deleted':spool.gc()}));return 0
            if args.command=='ingest-file':
                print(json.dumps(ingest_file(spool,args.path,config['destinations'])));return 0
            # One worker process per spool. Admission remains concurrent through SQLite.
            with open(str(spool.path)+'.worker.lock','a') as lock:
                os.chmod(lock.name,0o600)
                fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                adapters={name:{'elastic':Elastic,'hertzbeat':HertzBeat,'malcolm':Malcolm}[name](cfg)
                          for name,cfg in config.get('sinks',{}).items()}
                while True:
                    spool.gc()
                    result=work_once(spool,adapters)
                    # The daemon's journal is itself a collected source. Emitting each
                    # successful export here would produce another export forever.
                    if args.command=='work-once':
                        print(json.dumps(result,sort_keys=True),flush=True)
                        return 1 if result['missing_adapters'] or result['retry'] else 0
                    time.sleep(1)
        finally:
            spool.close()
    except KeyboardInterrupt:
        return 130
    except (OSError,ValueError,KeyError,RuntimeError,sqlite3.Error) as exc:
        # Class only: config/transport errors can contain secret values or remote raw bodies.
        print('telemetry operation failed: '+type(exc).__name__,file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(main())
