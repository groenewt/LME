"""Loss, quota and replay regression tests using real SQLite and process crashes."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    from lme_telemetry.spool import Spool, QuotaExceeded, Conflict, canonical
except ImportError:
    Spool = None


def record(eid='event-1'):
    return dict(schema_version=1, event_id=eid, source_node='graph', observed_at='2026-09-22T12:00:00Z',
                kind='monitoring', severity='INFO', body={'message': 'sample', 'value': 2.5}, attributes={'service.name': 'probe'})


class SpoolTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(Spool, 'durable spool must be implemented')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'spool.db'

    def spool(self, **kw):
        obj = Spool(self.path, source_node='graph', reserve_bytes=0, **kw)
        self.addCleanup(obj.close)
        return obj

    def test_replay_retains_original_obligations_and_checkpoint(self):
        s = self.spool()
        s.admit([record()], ['elastic', 'hertzbeat'], {'source': 'journal:generation-1', 'offset': 10})
        s.close()
        s = self.spool()
        s.admit([record()], ['elastic'], {'source': 'journal:generation-1', 'offset': 10})
        self.assertEqual(s.obligations('event-1'), {'elastic': 'pending', 'hertzbeat': 'pending'})
        self.assertEqual(s.checkpoint('journal:generation-1'), 10)
        self.assertEqual(s.status()['records'], 1)

    def test_collision_and_nonfinite_batch_leave_no_offset_or_partial_rows(self):
        s = self.spool()
        s.admit([record()], ['elastic'])
        changed = record(); changed['body']['value'] = 7
        with self.assertRaises(Conflict):
            s.admit([record('event-2'), changed], ['elastic'], {'source': 'file', 'offset': 40})
        self.assertEqual(s.status()['records'], 1)
        self.assertIsNone(s.checkpoint('file'))
        bad = record('bad'); bad['body']['value'] = float('nan')
        with self.assertRaises(ValueError):
            s.admit([record('event-3'), bad], ['elastic'])
        self.assertEqual(s.status()['records'], 1)

    def test_payload_and_node_validation(self):
        s = self.spool()
        for changes in ({'source_node':'other'}, {'kind':'metric'}, {'schema_version':True}, {'observed_at':'yesterday'}, {'severity':'WHATEVER'}, {'attributes':[]}, {'unexpected':1}):
            bad = record(); bad.update(changes)
            with self.assertRaises(ValueError, msg=str(changes)):
                s.admit([bad], ['elastic'])
        with self.assertRaises(ValueError):
            s.admit([record()], ['elastic', 'elastic'])

    def test_pending_quota_batch_is_atomic(self):
        s = self.spool(pending_bytes=6000)
        with self.assertRaises(QuotaExceeded):
            s.admit([record('a'), record('b')], ['elastic'], {'source':'file', 'offset':20})
        self.assertEqual(s.status()['records'], 0)
        self.assertIsNone(s.checkpoint('file'))

    def test_filesystem_floor_prevents_ack(self):
        s = Spool(self.path, source_node='graph', reserve_bytes=10**30)
        self.addCleanup(s.close)
        with self.assertRaises(QuotaExceeded):
            s.admit([record()], ['elastic'])
        self.assertEqual(s.status()['records'], 0)

    def test_all_sinks_readback_then_archive_retention(self):
        s = self.spool(retention_seconds=100)
        s.admit([record()], ['elastic','hertzbeat'])
        s.accept('event-1', 'elastic')
        self.assertEqual(s.status()['archived_records'], 0)
        tampered = record(); tampered['body']['value'] = 99
        self.assertFalse(s.verify('event-1','elastic',tampered, now=100))
        self.assertTrue(s.verify('event-1','elastic',record(), now=100))
        self.assertEqual(s.status()['archived_records'], 0)
        self.assertTrue(s.verify('event-1','hertzbeat',record(), now=120))
        self.assertEqual(s.status()['archived_records'], 1)
        self.assertEqual(s.gc(now=219), 0)
        self.assertEqual(s.gc(now=220), 1)

    def test_archive_quota_cannot_delete_unexpired_or_unverified(self):
        s = self.spool(archive_bytes=6000, retention_seconds=100)
        s.admit([record('a'),record('b')], ['elastic'])
        s.verify('a','elastic',record('a'),now=100)
        with self.assertRaises(QuotaExceeded):
            s.verify('b','elastic',record('b'),now=110)
        self.assertEqual(s.obligations('b'), {'elastic':'pending'})
        self.assertEqual(s.gc(now=199),0)
        self.assertEqual(s.gc(now=200),1)
        self.assertTrue(s.verify('b','elastic',record('b'),now=201))

    def test_crash_rolls_back_inflight_record_and_checkpoint(self):
        s = self.spool(); s.admit([record()], ['elastic'], {'source':'file','offset':10}); s.close()
        script = '''import sqlite3,os,sys
c=sqlite3.connect(sys.argv[1]); c.execute("BEGIN IMMEDIATE")
c.execute("UPDATE checkpoints SET offset=999")
c.execute("DELETE FROM obligations")
os._exit(23)
'''
        proc = subprocess.run([sys.executable,'-c',script,str(self.path)])
        self.assertEqual(proc.returncode,23)
        s = self.spool()
        self.assertEqual(s.checkpoint('file'),10)
        self.assertEqual(s.obligations('event-1'),{'elastic':'pending'})
        self.assertEqual(s.db.execute('PRAGMA integrity_check').fetchone()[0],'ok')

    def test_cursor_regression_rejects_batch(self):
        s=self.spool(); s.admit([record()],['elastic'],{'source':'file','offset':20})
        with self.assertRaises(Conflict):
            s.admit([record('later')],['elastic'],{'source':'file','offset':19})
        self.assertEqual(s.status()['records'],1)
