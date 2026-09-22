#!/usr/bin/env python3
"""Stop only a recorded run-owned backup endpoint; retain every data file."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


USER_PREFIX=['/usr/sbin/runuser','-u','lmebackup','--','/usr/bin/env','XDG_RUNTIME_DIR=/run/user/2400']


def run(argv):
    result=subprocess.run(argv,text=True,capture_output=True,timeout=90)
    return {'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}


def properties(result):
    return dict(line.split('=',1) for line in result['stdout'].splitlines() if '=' in line)


def validate_runtime(request,identity,container):
    run_id=request['run_id']
    root='/home/lme-backups/'+run_id
    expected={'run_id':run_id,'owner':'lmebackup','unit':'pgbackrest-'+run_id+'.service',
              'container_name':'pgbackrest-'+run_id,'image_id':request['image_id'],'root':root}
    if any(identity.get(key)!=value for key,value in expected.items()):
        raise ValueError('backup runtime identity differs from the resolved run')
    if container is not None:
        image=container['Image']
        if not image.startswith('sha256:'): image='sha256:'+image
        labels=container['Config'].get('Labels',{})
        if (container['Name'].lstrip('/')!=expected['container_name'] or image!=request['image_id']
                or labels.get('lme.run_id')!=run_id or labels.get('lme.role')!='postgresql-backup'
                or not re.fullmatch(r'[a-f0-9]{64}',container['Id'])):
            raise ValueError('current backup container does not match the recorded runtime')
        mounts={(row['Source'],row['Destination']) for row in container['Mounts']}
        required={(root+'/data',root),(root+'/config/pgbackrest.conf','/etc/pgbackrest/pgbackrest.conf'),(root+'/config','/etc/pgbackrest/tls')}
        if mounts!=required:
            raise ValueError('backup container has unexpected mount ownership')


def retire_owned(request,identity,mark_retired,execute=run):
    name='pgbackrest-'+request['run_id']
    unit=name+'.service'
    timer=execute(USER_PREFIX+['/usr/bin/systemctl','--user','show',name+'.timer','--property=LoadState,ActiveState,SubState'])
    if timer['returncode'] not in (0,1) or properties(timer).get('LoadState')!='not-found':
        raise ValueError('unrecorded backup timer exists; refusing unrelated timer mutation')
    exists=execute(USER_PREFIX+['/usr/bin/podman','container','exists',name])
    if exists['returncode'] not in (0,1):
        raise ValueError('backup container existence could not be read')
    container=None
    if exists['returncode']==0:
        observation=execute(USER_PREFIX+['/usr/bin/podman','inspect','--type','container',name])
        if observation['returncode']!=0: raise ValueError('backup container readback failed')
        rows=json.loads(observation['stdout'])
        if len(rows)!=1: raise ValueError('ambiguous backup container readback')
        container=rows[0]
    validate_runtime(request,identity,container)
    # Root-owned marker participates in the Quadlet ExecCondition across reboot.
    mark_retired()
    stop=execute(USER_PREFIX+['/usr/bin/systemctl','--user','stop',unit])
    if stop['returncode']!=0: raise ValueError('backup user service stop failed')
    mask=execute(USER_PREFIX+['/usr/bin/systemctl','--user','mask',unit])
    if mask['returncode']!=0: raise ValueError('backup user service mask failed')
    reload=execute(USER_PREFIX+['/usr/bin/systemctl','--user','daemon-reload'])
    if reload['returncode']!=0: raise ValueError('backup user manager reload failed')
    if container is not None:
        remaining=execute(USER_PREFIX+['/usr/bin/podman','container','exists',container['Id']])
        if remaining['returncode']==0:
            stopped=execute(USER_PREFIX+['/usr/bin/podman','stop','--time','20',container['Id']])
            if stopped['returncode']!=0: raise ValueError('exact backup container stop failed')
        elif remaining['returncode']!=1: raise ValueError('exact backup container state unknown')
    service=execute(USER_PREFIX+['/usr/bin/systemctl','--user','show',unit,'--property=LoadState,ActiveState,SubState,UnitFileState'])
    fields=properties(service)
    if service['returncode']!=0 or fields.get('LoadState')!='masked' or fields.get('ActiveState') not in ('inactive','failed'):
        raise ValueError('backup service is still active or can restart')
    after=execute(USER_PREFIX+['/usr/bin/podman','container','exists',name])
    state={'exists_returncode':after['returncode']}
    if after['returncode']==0:
        inspected=execute(USER_PREFIX+['/usr/bin/podman','inspect','--type','container',name])
        if inspected['returncode']!=0: raise ValueError('retired backup container cannot be inspected')
        rows=json.loads(inspected['stdout'])
        if len(rows)!=1: raise ValueError('ambiguous retired container')
        validate_runtime(request,identity,rows[0])
        if container is None or rows[0]['Id']!=container['Id'] or rows[0]['State']['Running'] is not False:
            raise ValueError('backup container changed identity or remains running')
        state.update(container_id=rows[0]['Id'],state=rows[0]['State'])
    elif after['returncode']!=1:
        raise ValueError('final container absence is unverified')
    return {'service':service,'service_properties':fields,'timer':timer,'container':state,
            'stop':stop,'mask':mask,'restart_inhibited':True}


def root_file(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or path.stat().st_mode & 0o022:
        raise ValueError('backup control file is not privately root-controlled')


def main(request):
    if os.geteuid()!=0: raise ValueError('retirement requires the scoped root helper')
    if set(request)!={'run_id','image_id','retention_reason'} or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}',request['run_id']):
        raise ValueError('retirement request does not match the bounded schema')
    reason=request['retention_reason']
    if not isinstance(reason,str) or not 10<=len(reason)<=500 or any(ord(char)<32 for char in reason):
        raise ValueError('explicit bounded retention reason required')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}',request['image_id']): raise ValueError('qualified image identity required')
    root=Path('/home/lme-backups')/request['run_id']
    for path in (root.parent,root,root/'config'):
        if path.is_symlink() or not path.is_dir() or path.stat().st_uid!=0 or path.stat().st_mode & 0o022:
            raise ValueError('backup control path is not root-controlled')
    identity_path=root/'runtime-identity.json'
    root_file(identity_path)
    identity=json.loads(identity_path.read_text())
    quadlet=Path('/home/lmebackup/.config/containers/systemd')/('pgbackrest-'+request['run_id']+'.container')
    if quadlet.is_symlink() or hashlib.sha256(quadlet.read_bytes()).hexdigest()!=identity['quadlet_sha256']:
        raise ValueError('backup Quadlet changed since recorded installation')
    retained=[{'path':str(root/name),'owner':'lmebackup' if name in ('data','image.oci.tar') else 'root','reason':reason}
              for name in ('repository.img','data','config','image.oci.tar','runtime-identity.json','ownership.json')]
    marker=root/'retired.json'
    def mark():
        if marker.exists():
            root_file(marker)
            previous=json.loads(marker.read_text())
            if previous.get('run_id')!=request['run_id'] or previous.get('image_id')!=request['image_id'] or previous.get('retention_reason')!=reason:
                raise ValueError('existing retirement record belongs to another runtime')
            return
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW
        fd=os.open(marker,flags,0o600)
        with os.fdopen(fd,'w') as stream:
            json.dump(dict(request,owner='lmebackup',retained=retained,issued_at=time.time()),stream)
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    evidence=retire_owned(request,identity,mark)
    return {'status':'retired','run_id':request['run_id'],'owner':'lmebackup','retention_reason':reason,
            'retained':retained,'native_inactive_proof':evidence,'observed_at':time.time()}


if __name__=='__main__':
    try:
        request=json.loads(sys.stdin.read(8193))
        print(json.dumps(main(request),sort_keys=True))
    except (ValueError,KeyError,OSError,subprocess.SubprocessError):
        print('Backup retirement failed; no inactive proof asserted.',file=sys.stderr)
        raise SystemExit(1)
