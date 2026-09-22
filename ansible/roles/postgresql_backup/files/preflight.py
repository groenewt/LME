#!/usr/bin/env python3
"""Read-only validation of exact physical backup paths and identities."""
import grp
import json
import os
import pathlib
import pwd
import re
import shutil
import stat
import subprocess
import sys


def reject_control_symlinks(root):
    for name in ('ownership.json','repository.img','config','data','image.oci.tar','runtime-identity.json','retired.json'):
        if (root / name).is_symlink():
            raise ValueError('backup control entry is a symlink: '+name)
    config = root / 'config'
    if config.exists():
        if not config.is_dir():
            raise ValueError('backup configuration is not a directory')
        for path in config.iterdir():
            if path.name not in ('backup-ca.crt','server.crt','server.key','pgbackrest.conf','retire.py') or path.is_symlink() or not path.is_file():
                raise ValueError('unrecorded or unsafe backup configuration entry')


def validate(run, capacity, reserve, expected_ip):
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,31}', run) or capacity != 100*1024**3:
        raise ValueError('invalid run or capacity')
    if os.geteuid() != 0:
        raise ValueError('physical preflight requires the scoped root installer')
    for executable in ('podman','fallocate','mkfs.ext4','systemctl','loginctl','tailscale','findmnt','losetup'):
        if not shutil.which(executable):
            raise ValueError('required backup runtime tool is absent: '+executable)
    addresses = subprocess.run(['tailscale','ip','-4'], check=True, capture_output=True, text=True).stdout.split()
    if addresses != [expected_ip]:
        raise ValueError('physical host Tailscale identity does not match observed trixie')
    for key in ('lmebackup', 2400):
        try:
            user = pwd.getpwnam(key) if isinstance(key,str) else pwd.getpwuid(key)
        except KeyError:
            continue
        if (user.pw_name,user.pw_uid,user.pw_gid,user.pw_dir) != ('lmebackup',2400,2400,'/home/lmebackup'):
            raise ValueError('backup account conflicts with an existing identity')
    for key in ('lmebackup', 2400):
        try:
            group = grp.getgrnam(key) if isinstance(key,str) else grp.getgrgid(key)
        except KeyError:
            continue
        if (group.gr_name,group.gr_gid) != ('lmebackup',2400):
            raise ValueError('backup group conflicts with an existing identity')
    for filename in ('/etc/subuid','/etc/subgid'):
        for line in pathlib.Path(filename).read_text().splitlines():
            if not line.strip():
                continue
            owner, start, count = line.split(':')
            start,count = int(start),int(count)
            overlap = start < 20000000+65536 and start+count > 20000000
            if owner == 'lmebackup' and (start,count) != (20000000,65536):
                raise ValueError('backup account has an incompatible subordinate mapping')
            if overlap and owner != 'lmebackup':
                raise ValueError('backup subordinate range overlaps another identity')
    root = pathlib.Path('/home/lme-backups') / run
    for path in (pathlib.Path('/home'), root.parent, root):
        if path.is_symlink():
            raise ValueError('backup path contains a symlink')
        if path.exists() and path.stat().st_uid != 0:
            raise ValueError('backup control path is not root-owned')
    reject_control_symlinks(root)
    if (root/'retired.json').exists():
        raise ValueError('retired backup authority cannot be restarted by a fresh profile')
    marker = root / 'ownership.json'
    if root.exists():
        if marker.is_symlink() or not marker.is_file():
            raise ValueError('existing run path has no ownership record')
        if json.loads(marker.read_text()) != {'run_id':run,'capacity_bytes':capacity,'owner':'lmebackup'}:
            raise ValueError('existing ownership record does not match this run')
        if set(p.name for p in root.iterdir()) - {'ownership.json','repository.img','config','data','image.oci.tar','runtime-identity.json','retired.json'}:
            raise ValueError('unrecorded files exist in the exact backup run directory')
    image = root / 'repository.img'
    if image.exists():
        info = image.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_size != capacity:
            raise ValueError('existing backing image identity/size is invalid')
        with image.open('rb') as stream:
            stream.seek(1080)
            if stream.read(2) != b'\x53\xef':
                raise ValueError('existing image is not the previously initialized ext4 filesystem')
    data = root / 'data'
    if data.is_symlink():
        raise ValueError('backup mountpoint is a symlink')
    if data.exists() and os.path.ismount(data):
        source = subprocess.run(['findmnt','-rn','-o','SOURCE','--target',str(data)], check=True,capture_output=True,text=True).stdout.strip()
        if not re.fullmatch(r'/dev/loop[0-9]+', source):
            raise ValueError('existing mount is not a file-backed loop device')
        backing = subprocess.run(['losetup','-no','BACK-FILE',source],check=True,capture_output=True,text=True).stdout.strip()
        if backing != str(image):
            raise ValueError('existing loop mount belongs to a different image')
    elif data.exists() and any(data.iterdir()):
        raise ValueError('unmounted target contains existing files')
    available = shutil.disk_usage('/home').free
    if available < reserve + (0 if image.exists() else capacity):
        raise ValueError('full backup commitment plus existing commitments and reserve do not fit')


if __name__ == '__main__':
    try:
        validate(sys.argv[1],int(sys.argv[2]),int(sys.argv[3]),sys.argv[4])
    except (ValueError,OSError,KeyError,subprocess.SubprocessError) as error:
        print('Backup preflight rejected: '+str(error),file=sys.stderr)
        raise SystemExit(1)
