"""Owned regular-image ext4 provisioning; never accepts a block-device target.

Planning is read-only. MAIN explicitly invokes prepare/mount after reviewing the
plan. Runtime writer processes must be non-root without CAP_SYS_RESOURCE.
"""
import argparse
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

GIB=1024**3
BLOCK=4096
IMAGE_BYTES=20*GIB
RESERVED_BYTES=2*GIB
WRITERS={'logs','metrics-elastic','metrics-hertzbeat','hertzbeat-native','sources'}


def run(argv,**kwargs):
    return subprocess.run(argv,check=True,capture_output=True,text=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},**kwargs).stdout


def no_symlink(path):
    path=Path(path)
    if not path.is_absolute():raise ValueError('absolute path required')
    for parent in [*reversed(path.parents),path]:
        if parent.is_symlink():raise ValueError('symlink paths are refused')
    return path


def sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def atomic_json(path,payload):
    path=Path(path);tmp=path.with_name(path.name+'.'+str(os.getpid())+'.tmp')
    fd=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(payload,stream,sort_keys=True,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,path);sync_directory(path.parent)
    finally:tmp.unlink(missing_ok=True)


def format_command(path,reserved_bytes):
    return ['/usr/sbin/mkfs.ext4','-q','-F','-b',str(BLOCK),'-m','0','-U','random',
            '-L','lme-telemetry','-O','quota,project','-E',
            'nodiscard,lazy_itable_init=0,lazy_journal_init=0,quotatype=prjquota,root_owner=0:0',str(path)]


def create_image(path,image_bytes,reserved_bytes,*,parent_reserve_bytes):
    """Exclusive creation; supports small synthetic images for offline tests."""
    path=Path(path)
    if path.exists() or path.is_symlink():raise FileExistsError(path)
    path=no_symlink(path)
    if any(type(x) is not int or x<0 for x in (image_bytes,reserved_bytes,parent_reserve_bytes)):
        raise ValueError('byte counts must be nonnegative integers')
    if image_bytes<64*1024**2 or image_bytes%BLOCK or reserved_bytes%BLOCK or reserved_bytes>=image_bytes:
        raise ValueError('invalid ext4 image geometry')
    if shutil.disk_usage(path.parent).free<image_bytes+parent_reserve_bytes:
        raise OSError(errno.ENOSPC,'preallocation would violate parent reserve')
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        os.posix_fallocate(fd,0,image_bytes);os.fsync(fd)
        original=os.fstat(fd)
        # The formatter receives the held descriptor, never a user-supplied device path.
        descriptor=f'/proc/self/fd/{fd}'
        run(format_command(descriptor,reserved_bytes),pass_fds=(fd,))
        run(['/usr/sbin/tune2fs','-r',str(reserved_bytes//BLOCK),'-u','0','-g','0',descriptor],pass_fds=(fd,))
        # e2fsprogs may punch zero ranges even with nodiscard; reallocate every hole.
        os.posix_fallocate(fd,0,image_bytes)
        os.fsync(fd)
        current=path.stat(follow_symlinks=False)
        if not stat.S_ISREG(current.st_mode) or (current.st_dev,current.st_ino)!=(original.st_dev,original.st_ino):
            raise RuntimeError('owned image path changed during format')
        if current.st_blocks*512<image_bytes:
            raise RuntimeError('image is sparse; fixed physical allocation required')
    finally:
        os.close(fd)
        # On failure retain the exact partial image for diagnosis; never unlink/reformat blindly.
        sync_directory(path.parent)
    info=inspect_image(path)
    if info['reserved_bytes']!=reserved_bytes or info['reserved_uid'] or info['reserved_gid']:
        raise RuntimeError('ext4 reserve verification failed')
    if not {'quota','project'}<=set(info['features']) or not info['project_quota_inode']:
        raise RuntimeError('ext4 project quota metadata absent')
    return info


def inspect_image(path):
    path=no_symlink(path)
    info=path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
        raise ValueError('one owned regular image required')
    output=run(['/usr/sbin/dumpe2fs','-h',str(path)])
    fields={line.split(':',1)[0].strip():line.split(':',1)[1].strip() for line in output.splitlines() if ':' in line}
    number=lambda key:int(fields[key].split()[0])
    return {'uuid':fields['Filesystem UUID'],'block_size':number('Block size'),
            'reserved_bytes':number('Reserved block count')*number('Block size'),
            'reserved_uid':number('Reserved blocks uid'),'reserved_gid':number('Reserved blocks gid'),
            'features':fields['Filesystem features'].split(),
            'project_quota_inode':number('Project quota inode'),
            'device':info.st_dev,'inode':info.st_ino,'owner_uid':info.st_uid,'mode':stat.S_IMODE(info.st_mode),'image_bytes':info.st_size,'allocated_bytes':info.st_blocks*512}


class Dqblk(ctypes.Structure):
    _fields_=[(name,ctypes.c_uint64) for name in ('bhardlimit','bsoftlimit','curspace','ihardlimit','isoftlimit','curinodes','btime','itime')]+[('valid',ctypes.c_uint32)]


def project_quota(device,project_id,limits=None):
    """Linux quotactl using PRJQUOTA; all limits are kernel-enforced per project."""
    if not re.fullmatch(r'/dev/loop[0-9]+',device):raise ValueError('exact owned loop device required')
    data=Dqblk()
    operation=0x800007  # Q_GETQUOTA
    if limits is not None:
        operation=0x800008  # Q_SETQUOTA
        data.bhardlimit=limits['hard_bytes']//1024
        data.ihardlimit=limits['inode_limit']
        data.valid=1|4  # QIF_BLIMITS | QIF_ILIMITS; zero soft limits, hard limits only.
    library=ctypes.CDLL(None,use_errno=True)
    library.quotactl.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_void_p]
    library.quotactl.restype=ctypes.c_int
    result=library.quotactl(ctypes.c_int((operation<<8)|2),device.encode(),project_id,ctypes.byref(data))
    if result:
        err=ctypes.get_errno();raise OSError(err,os.strerror(err))
    return {'hard_bytes':data.bhardlimit*1024,'inode_limit':data.ihardlimit,'used_bytes':data.curspace,'used_inodes':data.curinodes}


class StoragePlan:
    def __init__(self,config):
        if set(config)-{'schema_version','run_id','base_path','image_bytes','reserved_bytes','parent_reserve_bytes','writers'}:
            raise ValueError('unknown storage configuration field')
        if config.get('schema_version')!=1 or type(config.get('schema_version')) is not int:
            raise ValueError('storage schema_version must be1')
        self.config=config
        if config.get('base_path') not in ('/data/lme-telemetry','/home/lme-telemetry'):
            raise ValueError('only dedicated telemetry roots allowed')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',config.get('run_id','')):
            raise ValueError('run_id must be a bounded path component')
        if config.get('image_bytes',IMAGE_BYTES)!=IMAGE_BYTES or config.get('reserved_bytes',RESERVED_BYTES)!=RESERVED_BYTES:
            raise ValueError('qualified geometry is20GiB with2GiB reserve')
        self.parent_reserve=config.get('parent_reserve_bytes',100*GIB)
        if type(self.parent_reserve) is not int or self.parent_reserve<2*GIB:
            raise ValueError('parent reserve must be at least2GiB; physical hosts require100GiB')
        self.writers=config.get('writers',{})
        if set(self.writers)!=WRITERS:raise ValueError('all five isolated writer projects required')
        ids=set()
        for writer in self.writers.values():
            if set(writer)!={'uid','gid','project_id','hard_bytes','inode_limit'}:
                raise ValueError('invalid writer quota contract')
            if any(type(writer[k]) is not int or writer[k]<=0 for k in writer):
                raise ValueError('writers require nonroot numeric uid/gid and positive limits')
            if writer['uid']>2**31-1 or writer['gid']>2**31-1 or not 10000<=writer['project_id']<=2**31-1:
                raise ValueError('writer identity outside allowed bounds')
            if writer['project_id'] in ids or writer['hard_bytes']%BLOCK:
                raise ValueError('duplicate project or unaligned quota')
            ids.add(writer['project_id'])
        if sum(w['hard_bytes'] for w in self.writers.values())>16*GIB:
            raise ValueError('project caps must leave2GiB filesystem overhead and2GiB reserve')
        self.root=no_symlink(Path(config['base_path'])/config['run_id'])
        self.image=self.root/'telemetry.ext4';self.mount=self.root/'volume'

    def describe(self):
        result={'image_path':str(self.image),'mount_path':str(self.mount),'image_bytes':IMAGE_BYTES,
                'reserved_bytes':RESERVED_BYTES,'parent_reserve_bytes':self.parent_reserve,'writers':self.writers,
                'format':format_command(self.image,RESERVED_BYTES),
                'reserve_command':['/usr/sbin/tune2fs','-r','524288','-u','0','-g','0',str(self.image)],
                'mount_options':['rw','nodev','nosuid','noexec','prjquota'],
                'kernel_quota_operation':'quotactl(Q_SETQUOTA, PRJQUOTA, exact_loop_device, project_id, hard_byte_and_inode_limits)',
                'loop_cleanup':'Only the exact loop device recorded in mount-receipt.json; never losetup -D'}
        result['plan_sha256']=hashlib.sha256(json.dumps(result,sort_keys=True).encode()).hexdigest()
        return result

    def _require_root(self):
        if os.geteuid()!=0:raise PermissionError('dedicated filesystem provisioning requires root')
        for path in [*reversed(self.root.parents),self.root]:
            if path.exists():
                info=path.stat(follow_symlinks=False)
                if info.st_uid!=0 or info.st_mode&0o022:
                    raise PermissionError('provisioning ancestors must be root-owned and not group/world-writable')

    def prepare(self):
        self._require_root()
        self.root.mkdir(parents=True,mode=0o755,exist_ok=False)
        self.mount.mkdir(mode=0o755)
        info=create_image(self.image,IMAGE_BYTES,RESERVED_BYTES,parent_reserve_bytes=self.parent_reserve)
        atomic_json(self.root/'image-receipt.json',{'plan':self.describe(),'image':info})
        return info

    def _owned_image(self):
        saved=json.loads((self.root/'image-receipt.json').read_text())
        info=inspect_image(self.image)
        if saved['plan']['plan_sha256']!=self.describe()['plan_sha256']:
            raise ValueError('storage plan differs from owned image receipt')
        if any(info[k]!=saved['image'][k] for k in ('uuid','device','inode','image_bytes')):
            raise ValueError('owned image identity differs')
        if info['owner_uid']!=0 or info['mode']!=0o600:
            raise ValueError('owned image must remain root-owned0600')
        if info['image_bytes']!=IMAGE_BYTES or info['allocated_bytes']<IMAGE_BYTES or info['reserved_bytes']!=RESERVED_BYTES or info['reserved_uid'] or info['reserved_gid']:
            raise ValueError('owned image reserve/allocation differs')
        return info

    def mount_image(self):
        self._require_root();info=self._owned_image()
        if os.path.ismount(self.mount) or any(self.mount.iterdir()) or (self.root/'mount-receipt.json').exists():
            raise ValueError('mountpoint must be unused and empty; existing receipt requires explicit diagnosis')
        device=run(['/usr/sbin/losetup','--find','--show','--nooverlap',str(self.image)]).strip()
        if not re.fullmatch(r'/dev/loop[0-9]+',device):raise RuntimeError('unexpected loop device identity')
        # Record immediately, before mounting: interrupted operations remain exactly identifiable.
        atomic_json(self.root/'mount-receipt.json',{'device':device,'image_uuid':info['uuid'],'stage':'loop-attached','plan_sha256':self.describe()['plan_sha256']})
        run(['/usr/bin/mount','-t','ext4','-o',','.join(self.describe()['mount_options']),device,str(self.mount)])
        os.chmod(self.mount,0o755)
        for name,writer in self.writers.items():
            path=self.mount/name;path.mkdir(mode=0o700)
            run(['/usr/bin/chattr','-p',str(writer['project_id']),'+P',str(path)])
            project_quota(device,writer['project_id'],writer)
            os.chown(path,writer['uid'],writer['gid'])
        result=self.verify()
        atomic_json(self.root/'mount-receipt.json',dict(result,stage='ready',plan_sha256=self.describe()['plan_sha256']))
        return result

    def remount(self):
        """Recover a previously qualified mount after reboot, without initialization."""
        self._require_root()
        lock=os.open(self.root/'.remount.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            info=self._owned_image()
            receipt=json.loads((self.root/'mount-receipt.json').read_text())
            if (receipt.get('stage') not in ('ready','remount-attached') or receipt.get('image_uuid')!=info['uuid'] or
                receipt.get('plan_sha256')!=self.describe()['plan_sha256']):
                raise ValueError('remount requires the exact previously qualified image receipt')
            if os.path.ismount(self.mount):
                return self.verify()
            no_symlink(self.mount)
            if not self.mount.is_dir() or any(self.mount.iterdir()):
                raise ValueError('unmounted target must be the existing empty mountpoint')
            associated=json.loads(run(['/usr/sbin/losetup','--json','--list','--associated',str(self.image),
                                       '--output','NAME,BACK-FILE']))['loopdevices']
            if len(associated)>1:raise ValueError('ambiguous owned image loop attachment')
            if associated:
                device=associated[0]['name']
                if Path(associated[0]['back-file']).resolve()!=self.image:
                    raise ValueError('loop backing image differs')
                try:
                    mounted=json.loads(run(['/usr/bin/findmnt','--json','--source',device,'-o','TARGET']))
                except subprocess.CalledProcessError as exc:
                    if exc.returncode!=1 or exc.stdout.strip():raise
                    mounted={'filesystems':[]}
                if mounted.get('filesystems'):raise ValueError('owned loop is mounted at another target')
            else:
                device=run(['/usr/sbin/losetup','--find','--show','--nooverlap',str(self.image)]).strip()
            if not re.fullmatch(r'/dev/loop[0-9]+',device):raise ValueError('invalid exact loop device')
            atomic_json(self.root/'mount-receipt.json',dict(receipt,stage='remount-attached',
                        previous_device=receipt['device'],device=device))
            run(['/usr/bin/mount','-t','ext4','-o',','.join(self.describe()['mount_options']),device,str(self.mount)])
            # Existing project IDs, ownership and persisted kernel limits are verified,
            # never recreated or repaired silently during boot recovery.
            result=self.verify()
            atomic_json(self.root/'mount-receipt.json',dict(result,stage='ready',plan_sha256=self.describe()['plan_sha256']))
            return result
        finally:
            os.close(lock)

    def verify(self):
        self._require_root();info=self._owned_image()
        receipt=json.loads((self.root/'mount-receipt.json').read_text());device=receipt['device']
        if not re.fullmatch(r'/dev/loop[0-9]+',device):raise ValueError('invalid exact loop receipt')
        loops=json.loads(run(['/usr/sbin/losetup','--json','--output','NAME,BACK-FILE',device]))['loopdevices']
        if len(loops)!=1 or Path(loops[0]['back-file']).resolve()!=self.image:
            raise ValueError('loop device no longer refers to the owned image')
        mount=json.loads(run(['/usr/bin/findmnt','--json','--mountpoint',str(self.mount),'-o','SOURCE,TARGET,FSTYPE,OPTIONS']))['filesystems'][0]
        options=set(mount['options'].split(','))
        if mount['source']!=device or mount['target']!=str(self.mount) or mount['fstype']!='ext4' or not {'rw','nodev','nosuid','noexec','prjquota'}<=options:
            raise ValueError('mounted filesystem identity/options differ')
        observed={}
        for name,writer in self.writers.items():
            path=self.mount/name;identity=path.stat(follow_symlinks=False)
            if not stat.S_ISDIR(identity.st_mode) or identity.st_uid!=writer['uid'] or identity.st_gid!=writer['gid']:
                raise ValueError('writer directory ownership differs')
            attributes=run(['/usr/bin/lsattr','-pd',str(path)]).split()
            if int(attributes[0])!=writer['project_id'] or 'P' not in attributes[1]:
                raise ValueError('project inheritance differs')
            quota=project_quota(device,writer['project_id'])
            if quota['hard_bytes']!=writer['hard_bytes'] or quota['inode_limit']!=writer['inode_limit']:
                raise ValueError('kernel project quota differs')
            observed[name]=quota
        filesystem=os.statvfs(self.mount)
        free=filesystem.f_bfree*filesystem.f_frsize
        if free<RESERVED_BYTES:raise RuntimeError('dedicated filesystem reserve already violated')
        return {'device':device,'image_uuid':info['uuid'],'mount_path':str(self.mount),'total_free_bytes':free,
                'nonroot_available_bytes':filesystem.f_bavail*filesystem.f_frsize,'reserved_bytes':RESERVED_BYTES,'projects':observed}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True)
    parser.add_argument('command',choices=('plan','prepare','mount','remount','verify'))
    args=parser.parse_args(argv)
    try:
        plan=StoragePlan(json.loads(Path(args.config).read_text()))
        result={'plan':plan.describe,'prepare':plan.prepare,'mount':plan.mount_image,'remount':plan.remount,'verify':plan.verify}[args.command]()
        print(json.dumps(result,sort_keys=True,indent=2));return 0
    except (OSError,ValueError,RuntimeError,KeyError,subprocess.CalledProcessError) as exc:
        print('telemetry storage operation failed: '+type(exc).__name__,file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
