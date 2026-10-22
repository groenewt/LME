import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from test_spool import record
from lme_telemetry.spool import Spool


class CliTests(unittest.TestCase):
    def test_ingest_file_restart_only_advances_complete_lines_and_rejects_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); config=root/'config.json'; source=root/'source.ndjson'; db=root/'spool.db'
            config.write_text(json.dumps({'spool_path':str(db),'source_node':'graph','destinations':['elastic']}))
            first=json.dumps(record()).encode()+b'\n'; second=json.dumps(record('two')).encode()
            source.write_bytes(first+second)
            command=[sys.executable,'-m','lme_telemetry','--config',str(config),'ingest-file',str(source)]
            result=subprocess.run(command,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            with source.open('ab') as stream: stream.write(b'\n')
            self.assertEqual(subprocess.run(command,capture_output=True).returncode,0)
            s=Spool(db,source_node='graph');self.addCleanup(s.close)
            self.assertEqual(s.status()['records'],2)
            self.assertEqual(subprocess.run(command,capture_output=True).returncode,0)
            source.write_bytes(first)
            self.assertNotEqual(subprocess.run(command,capture_output=True).returncode,0)
            self.assertEqual(s.status()['records'],2)
