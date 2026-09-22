"""Owned regular-image provisioning tests; never mount or format a real device."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
try:
    from lme_telemetry.storage import StoragePlan, create_image, inspect_image
except ImportError:
    StoragePlan=None

GIB=1024**3


def config():
    return {'schema_version':1,'run_id':'synthetic-20260922','base_path':'/data/lme-telemetry',
            'parent_reserve_bytes':100*GIB,
            'writers':{name:{'uid':1001,'gid':1001,'project_id':41001+i,'hard_bytes':budget,'inode_limit':100000}
                       for i,(name,budget) in enumerate([('logs',14*GIB),('metrics-elastic',GIB//2),('metrics-hertzbeat',GIB//2),('hertzbeat-native',GIB//2),('sources',GIB//2)])}}


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(StoragePlan,'isolated telemetry filesystem provisioner missing')

    def test_plan_contains_only_owned_image_mount_and_exact_project_limits(self):
        plan=StoragePlan(config()).describe()
        self.assertEqual(plan['image_bytes'],20*GIB)
        self.assertEqual(plan['reserved_bytes'],2*GIB)
        self.assertEqual(plan['image_path'],'/data/lme-telemetry/synthetic-20260922/telemetry.ext4')
        self.assertEqual(plan['mount_path'],'/data/lme-telemetry/synthetic-20260922/volume')
        self.assertEqual(sum(w['hard_bytes'] for w in plan['writers'].values()),16*GIB)
        self.assertEqual(plan['format'][0],'/usr/sbin/mkfs.ext4')
        self.assertIn('prjquota',plan['mount_options'])
        self.assertIn('nodev',plan['mount_options'])
        self.assertIn('nosuid',plan['mount_options'])
        self.assertNotIn('/dev/',plan['image_path'])

    def test_invalid_paths_root_writers_duplicate_projects_and_overcommit_fail(self):
        cases=[]
        for field,value in [('base_path','/dev'),('run_id','../disk'),('image_bytes',19*GIB),('reserved_bytes',GIB)]:
            cfg=config();cfg[field]=value;cases.append(cfg)
        cfg=config();cfg['writers']['logs']['uid']=0;cases.append(cfg)
        cfg=config();cfg['writers']['logs']['project_id']=41002;cases.append(cfg)
        cfg=config();cfg['writers']['logs']['hard_bytes']=18*GIB;cases.append(cfg)
        for cfg in cases:
            with self.assertRaises(ValueError):StoragePlan(cfg)

    def test_existing_file_symlink_and_nonregular_targets_never_modified(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'existing';path.write_bytes(b'preserve')
            with self.assertRaises(FileExistsError):create_image(path,64*1024**2,8*1024**2,parent_reserve_bytes=0)
            self.assertEqual(path.read_bytes(),b'preserve')
            link=Path(tmp)/'link';link.symlink_to(path)
            with self.assertRaises(FileExistsError):create_image(link,64*1024**2,8*1024**2,parent_reserve_bytes=0)
            fifo=Path(tmp)/'pipe';os.mkfifo(fifo)
            with self.assertRaises(FileExistsError):create_image(fifo,64*1024**2,8*1024**2,parent_reserve_bytes=0)

    def test_preallocated_offline_ext4_has_exact_reserved_blocks_and_project_quota(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'synthetic.ext4'
            create_image(path,64*1024**2,8*1024**2,parent_reserve_bytes=0)
            info=inspect_image(path)
            self.assertEqual(info['block_size'],4096)
            self.assertEqual(info['reserved_bytes'],8*1024**2)
            self.assertEqual(info['reserved_uid'],0)
            self.assertEqual(info['reserved_gid'],0)
            self.assertIn('quota',info['features'])
            self.assertIn('project',info['features'])
            self.assertGreater(info['project_quota_inode'],0)
            self.assertGreaterEqual(path.stat().st_blocks*512,path.stat().st_size)
            self.assertEqual(path.stat().st_mode&0o777,0o600)

    def test_parent_reserve_failure_does_not_create_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'image'
            with self.assertRaises(OSError):create_image(path,64*1024**2,8*1024**2,parent_reserve_bytes=10**30)
            self.assertFalse(path.exists())

class StorageRemountTests(unittest.TestCase):
    def test_reboot_remount_uses_existing_image_and_never_reinitializes_projects(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            plan=StoragePlan(config());plan.root=Path(tmp);plan.mount=Path(tmp)/'volume';plan.mount.mkdir();plan.image=Path(tmp)/'telemetry.ext4';plan.image.write_bytes(b'owned')
            receipt={'stage':'ready','device':'/dev/loop7','image_uuid':'fixed-uuid','plan_sha256':plan.describe()['plan_sha256']}
            (plan.root/'mount-receipt.json').write_text(json.dumps(receipt))
            commands=[]
            def command(args,**kwargs):
                commands.append(args)
                if args[0].endswith('losetup') and '--associated' in args:return '{"loopdevices":[]}'
                if args[0].endswith('losetup'):return '/dev/loop9\n'
                if args[0].endswith('mount'):return ''
                self.fail('unexpected mutation/query '+str(args))
            with patch.object(plan,'_require_root'),patch.object(plan,'_owned_image',return_value={'uuid':'fixed-uuid'}),patch.object(plan,'verify',return_value={'device':'/dev/loop9','image_uuid':'fixed-uuid'}),patch('lme_telemetry.storage.run',side_effect=command):
                result=plan.remount()
            self.assertEqual(result['device'],'/dev/loop9')
            self.assertTrue(any(cmd[0].endswith('mount') for cmd in commands))
            self.assertFalse(any(any(x in cmd[0] for x in ('mkfs','tune2fs','chattr')) for cmd in commands))
            self.assertEqual(plan.image.read_bytes(),b'owned')
            self.assertEqual(list(plan.mount.iterdir()),[])
            self.assertEqual(json.loads((plan.root/'mount-receipt.json').read_text())['stage'],'ready')

    def test_remount_refuses_unqualified_or_different_image_receipt_before_attach(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            plan=StoragePlan(config());plan.root=Path(tmp);plan.mount=Path(tmp)/'volume';plan.mount.mkdir();plan.image=Path(tmp)/'telemetry.ext4'
            for stage,uuid in [('loop-attached','fixed'),('ready','other')]:
                (plan.root/'mount-receipt.json').write_text(json.dumps({'stage':stage,'image_uuid':uuid,'plan_sha256':plan.describe()['plan_sha256'],'device':'/dev/loop7'}))
                with patch.object(plan,'_require_root'),patch.object(plan,'_owned_image',return_value={'uuid':'fixed'}),patch('lme_telemetry.storage.run') as command:
                    with self.assertRaises(ValueError):plan.remount()
                    command.assert_not_called()
