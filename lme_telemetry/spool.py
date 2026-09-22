"""SQLite admission is the local durable boundary, never a sink-delivery receipt."""
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import sqlite3
import time

GIB = 1024 ** 3
MAX_BATCH_BYTES = 1024 ** 2
DESTINATIONS = frozenset(('elastic', 'hertzbeat', 'malcolm'))
KINDS = frozenset(('monitoring', 'lifecycle', 'security', 'network', 'audit', 'journal', 'application', 'system', 'collector'))
SEVERITIES = ('TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL')


class QuotaExceeded(RuntimeError):
    pass


class Conflict(ValueError):
    pass


def _json_value(value, depth=0):
    if depth > 24:
        raise ValueError('JSON nesting exceeds 24')
    if value is None or type(value) in (bool, str, int):
        return
    if type(value) is float and math.isfinite(value):
        return
    if isinstance(value, list):
        for item in value:
            _json_value(item, depth + 1)
        return
    if isinstance(value, dict) and all(isinstance(k, str) for k in value):
        for item in value.values():
            _json_value(item, depth + 1)
        return
    raise ValueError('only finite JSON values and string object keys are accepted')


def canonical(record):
    required = {'schema_version','event_id','source_node','observed_at','kind','severity','body','attributes'}
    optional = {'source_cursor', 'dataset', 'occurred_at'}
    if not isinstance(record, dict) or not required <= record.keys() or record.keys() - required - optional:
        raise ValueError('invalid typed log fields')
    if type(record['schema_version']) is not int or record['schema_version'] != 1:
        raise ValueError('schema_version must be integer 1')
    for key in ('event_id', 'source_node'):
        if not isinstance(record[key],str) or not re.fullmatch(r'[A-Za-z0-9_.:@/-]{1,256}',record[key]):
            raise ValueError('invalid source_node or event_id')
    for key in ('observed_at','occurred_at'):
        if key in record:
            if not isinstance(record[key],str):
                raise ValueError('timestamp must be an ISO8601 string')
            try:
                dt = datetime.fromisoformat(record[key].replace('Z','+00:00'))
            except ValueError as exc:
                raise ValueError('invalid ISO8601 timestamp') from exc
            if dt.tzinfo is None:
                raise ValueError('timestamp requires timezone')
    if not isinstance(record['kind'],str) or not isinstance(record['severity'],str) or record['kind'] not in KINDS or record['severity'] not in SEVERITIES:
        raise ValueError('unknown kind or severity')
    if not isinstance(record['attributes'],dict):
        raise ValueError('attributes must be an object')
    for key in ('source_cursor','dataset'):
        if key in record and (not isinstance(record[key],str) or not 1 <= len(record[key]) <= 4096):
            raise ValueError('optional cursor/dataset must be bounded strings')
    _json_value(record)
    data = json.dumps(record, sort_keys=True, separators=(',',':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
    if len(data) > MAX_BATCH_BYTES:
        raise ValueError('record exceeds 1MiB')
    return data


def validate_destinations(destinations):
    if (not isinstance(destinations,list) or not destinations or
        any(not isinstance(d,str) or d not in DESTINATIONS for d in destinations) or
        len(set(destinations)) != len(destinations)):
        raise ValueError('destinations must be a nonempty unique supported list')


class Spool:
    def __init__(self, path, *, source_node, pending_bytes=4*GIB, archive_bytes=8*GIB,
                 reserve_bytes=2*GIB, retention_seconds=86400):
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.source_node = source_node
        for value in (pending_bytes, archive_bytes, reserve_bytes, retention_seconds):
            if type(value) is not int or value < 0:
                raise ValueError('quotas must be nonnegative integers')
        self.pending_bytes, self.archive_bytes = pending_bytes, archive_bytes
        self.reserve_bytes, self.retention_seconds = reserve_bytes, retention_seconds
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.chmod(self.path, 0o600)
        self.db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA foreign_keys=ON')
        self.db.execute('PRAGMA auto_vacuum=INCREMENTAL')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA wal_autocheckpoint=256')
        self.db.execute('PRAGMA journal_size_limit=4194304')
        self.db.executescript('''
CREATE TABLE IF NOT EXISTS records (
 event_id TEXT PRIMARY KEY, payload BLOB NOT NULL, digest TEXT NOT NULL,
 charge INTEGER NOT NULL, admitted_at REAL NOT NULL, verified_at REAL);
CREATE TABLE IF NOT EXISTS obligations (
 event_id TEXT NOT NULL REFERENCES records(event_id) ON DELETE CASCADE,
 destination TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0,
 last_error TEXT, PRIMARY KEY(event_id,destination));
CREATE INDEX IF NOT EXISTS obligations_due ON obligations(destination,state,next_attempt);
CREATE TABLE IF NOT EXISTS checkpoints(source TEXT PRIMARY KEY, offset INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
''')
        with self.transaction():
            old = self.db.execute("SELECT value FROM metadata WHERE key='source_node'").fetchone()
            if old and old[0] != source_node:
                raise Conflict('spool belongs to another source_node')
            self.db.execute("INSERT OR IGNORE INTO metadata VALUES('source_node',?)", (source_node,))
        directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def close(self):
        self.db.close()

    @contextmanager
    def transaction(self):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK')
            raise

    def _used(self, archived):
        clause = 'IS NOT NULL' if archived else 'IS NULL'
        return self.db.execute(f'SELECT COALESCE(SUM(charge),0) FROM records WHERE verified_at {clause}').fetchone()[0]

    def admit(self, records, destinations, checkpoint=None):
        validate_destinations(destinations)
        if not isinstance(records,list) or not 1 <= len(records) <= 1000:
            raise ValueError('batch must contain 1..1000 records')
        encoded = [canonical(r) for r in records]
        if sum(map(len,encoded)) > MAX_BATCH_BYTES:
            raise ValueError('batch exceeds 1MiB')
        if any(r['source_node'] != self.source_node for r in records):
            raise ValueError('source_node does not match this ingress')
        if checkpoint is not None:
            if (not isinstance(checkpoint,dict) or set(checkpoint) != {'source','offset'} or
                not isinstance(checkpoint['source'],str) or not 1 <= len(checkpoint['source']) <= 4096 or
                type(checkpoint['offset']) is not int or not 0 <= checkpoint['offset'] <= 2**63-1):
                raise ValueError('checkpoint requires bounded source and nonnegative integer offset')
        inserted = 0
        with self.transaction():
            used = self._used(False)
            transaction_charge = 0
            for record, data in zip(records, encoded):
                previous = self.db.execute('SELECT payload FROM records WHERE event_id=?',(record['event_id'],)).fetchone()
                if previous:
                    if bytes(previous[0]) != data:
                        raise Conflict('event_id already exists with different content')
                    continue
                charge = len(data) + 4096 + 256*len(destinations)
                if used + charge > self.pending_bytes:
                    raise QuotaExceeded('pending quota exhausted; retry without advancing source')
                # Reserve for SQLite page, index and WAL amplification. Shared metric queue users
                # must enforce the same filesystem floor through their volume quota/guardian.
                if shutil.disk_usage(self.path.parent).free < self.reserve_bytes + 4*(transaction_charge+charge) + 65536:
                    raise QuotaExceeded('filesystem reserve reached')
                self.db.execute('INSERT INTO records VALUES(?,?,?,?,?,NULL)',
                                (record['event_id'],data,hashlib.sha256(data).hexdigest(),charge,time.time()))
                self.db.executemany('INSERT INTO obligations(event_id,destination) VALUES(?,?)',
                                    [(record['event_id'],d) for d in destinations])
                used += charge
                transaction_charge += charge
                inserted += 1
            if checkpoint is not None:
                old = self.checkpoint(checkpoint['source'])
                if old is not None and checkpoint['offset'] < old:
                    raise Conflict('checkpoint regression; use a new source generation')
                self.db.execute('INSERT INTO checkpoints VALUES(?,?) ON CONFLICT(source) DO UPDATE SET offset=excluded.offset',
                                (checkpoint['source'],checkpoint['offset']))
        return {'ack':'local_fsync','inserted':inserted,'replayed':len(records)-inserted}

    def checkpoint(self, source):
        row = self.db.execute('SELECT offset FROM checkpoints WHERE source=?',(source,)).fetchone()
        return row[0] if row else None

    def obligations(self, event_id):
        return dict(self.db.execute('SELECT destination,state FROM obligations WHERE event_id=?',(event_id,)))

    def accept(self, event_id, destination):
        with self.transaction():
            self.db.execute("UPDATE obligations SET state='accepted' WHERE event_id=? AND destination=? AND state='pending'",(event_id,destination))

    def verify(self, event_id, destination, returned, *, now=None):
        try:
            data = canonical(returned)
        except (ValueError,TypeError,UnicodeError):
            return False
        now = time.time() if now is None else now
        with self.transaction():
            row = self.db.execute('SELECT payload,charge,verified_at FROM records WHERE event_id=?',(event_id,)).fetchone()
            if not row or bytes(row['payload']) != data:
                return False
            states = self.obligations(event_id)
            if destination not in states:
                return False
            last = all(d == destination or state == 'verified' for d,state in states.items())
            if last and row['verified_at'] is None:
                if self._used(True) + row['charge'] > self.archive_bytes:
                    raise QuotaExceeded('archive quota exhausted; preserving pending obligation')
                self.db.execute('UPDATE records SET verified_at=? WHERE event_id=?',(now,event_id))
            self.db.execute("UPDATE obligations SET state='verified',last_error=NULL WHERE event_id=? AND destination=?",(event_id,destination))
        return True

    def due(self, destination, *, now=None, limit=100):
        now = time.time() if now is None else now
        return self.db.execute('''SELECT r.payload,o.* FROM obligations o JOIN records r USING(event_id)
WHERE o.destination=? AND o.state!='verified' AND o.next_attempt<=? ORDER BY o.next_attempt,r.admitted_at LIMIT ?''',(destination,now,limit)).fetchall()

    def retry(self, event_id, destination, error, *, now=None):
        now = time.time() if now is None else now
        with self.transaction():
            row = self.db.execute('SELECT attempts FROM obligations WHERE event_id=? AND destination=?',(event_id,destination)).fetchone()
            if row:
                delay = min(300,2**min(row[0],8))
                self.db.execute('''UPDATE obligations SET attempts=attempts+1,next_attempt=?,last_error=?
WHERE event_id=? AND destination=? AND state!='verified' ''',(now+delay,error[:120],event_id,destination))

    def gc(self, *, now=None):
        now = time.time() if now is None else now
        with self.transaction():
            count = self.db.execute('DELETE FROM records WHERE verified_at IS NOT NULL AND verified_at<=?',(now-self.retention_seconds,)).rowcount
        self.db.execute('PRAGMA incremental_vacuum(256)')
        self.db.execute('PRAGMA wal_checkpoint(PASSIVE)')
        return count

    def status(self):
        return {'records':self.db.execute('SELECT COUNT(*) FROM records').fetchone()[0],
                'archived_records':self.db.execute('SELECT COUNT(*) FROM records WHERE verified_at IS NOT NULL').fetchone()[0],
                'pending_bytes':self._used(False),'archive_bytes':self._used(True),
                'obligations':[dict(r) for r in self.db.execute('SELECT destination,state,COUNT(*) AS count,SUM(attempts) AS attempts FROM obligations GROUP BY destination,state')]}
