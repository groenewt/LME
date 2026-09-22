import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from lme_telemetry.__main__ import main

class WorkerOutputTests(unittest.TestCase):
    def test_daemon_cycle_does_not_generate_exportable_journal_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg=Path(tmp)/'runtime.json'
            cfg.write_text(json.dumps({'destinations':['elastic'],'source_node':'graph','spool_path':str(Path(tmp)/'spool.db'),'budgets':{'reserve_bytes':0}}))
            output=io.StringIO()
            with contextlib.redirect_stdout(output),patch('lme_telemetry.__main__.time.sleep',side_effect=KeyboardInterrupt):
                self.assertEqual(main(['--config',str(cfg),'worker']),130)
            self.assertEqual(output.getvalue(),'')
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(['--config',str(cfg),'work-once']),0)
            self.assertEqual(json.loads(output.getvalue())['verified'],0)
