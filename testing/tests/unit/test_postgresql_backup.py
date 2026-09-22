import importlib
import unittest
import importlib.util
import pathlib
import tempfile
import json
from unittest.mock import patch


class BackupTests(unittest.TestCase):

    def test_preflight_rejects_symlinked_control_files_before_copy(self):
        path = pathlib.Path(__file__).resolve().parents[3] / 'ansible/roles/postgresql_backup/files/preflight.py'
        spec = importlib.util.spec_from_file_location('backup_preflight', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'config').mkdir()
            (root / 'config/server.key').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError): module.reject_control_symlinks(root)
            (root / 'config/server.key').unlink()
            (root / 'config').rmdir()
            (root / 'config').symlink_to('/etc')
            with self.assertRaises(ValueError): module.reject_control_symlinks(root)


    def test_retirement_only_stops_matching_container_and_checks_native_inactivity(self):
        path=pathlib.Path(__file__).resolve().parents[3]/'ansible/roles/postgresql_backup/files/retire.py'
        spec=importlib.util.spec_from_file_location('backup_retire',path)
        api=importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
        request={'run_id':'fixture','image_id':'sha256:'+'a'*64,'retention_reason':'Preserved test recovery evidence'}
        identity={'run_id':'fixture','root':'/home/lme-backups/fixture','owner':'lmebackup','unit':'pgbackrest-fixture.service','container_name':'pgbackrest-fixture','image_id':request['image_id']}
        calls=[]
        marked=[]
        def execute(argv):
            calls.append(argv)
            if '--property=LoadState,ActiveState,SubState' in argv:
                return {'returncode':1,'stdout':'LoadState=not-found\nActiveState=inactive\n','stderr':''}
            if 'exists' in argv: return {'returncode':1,'stdout':'','stderr':''}
            if '--property=LoadState,ActiveState,SubState,UnitFileState' in argv:
                return {'returncode':0,'stdout':'LoadState=masked\nActiveState=inactive\nUnitFileState=masked\n','stderr':''}
            return {'returncode':0,'stdout':'','stderr':''}
        evidence=api.retire_owned(request,identity,lambda:marked.append(True),execute)
        self.assertEqual(marked,[True])
        self.assertEqual(evidence['container']['exists_returncode'],1)
        self.assertTrue(any(argv[-2:]==['mask','pgbackrest-fixture.service'] for argv in calls))
        container={'Id':'c'*64,'Name':'pgbackrest-fixture','Image':request['image_id'],'Config':{'Labels':{'lme.run_id':'fixture','lme.role':'postgresql-backup'}},'Mounts':[{'Source':'/home/lme-backups/fixture/'+source,'Destination':destination} for source,destination in [('data','/home/lme-backups/fixture'),('config/pgbackrest.conf','/etc/pgbackrest/pgbackrest.conf'),('config','/etc/pgbackrest/tls')]]}
        api.validate_runtime(request,identity,container)
        with self.assertRaises(ValueError): api.validate_runtime(request,identity,{**container,'Image':'sha256:'+'d'*64})
        with self.assertRaises(ValueError): api.validate_runtime(request,identity,{**container,'Mounts':[]})
        bad={**identity,'image_id':'sha256:'+'b'*64}
        with self.assertRaises(ValueError): api.retire_owned(request,bad,lambda:marked.append(True),execute)
        self.assertEqual(marked,[True])



if __name__ == '__main__': unittest.main()
