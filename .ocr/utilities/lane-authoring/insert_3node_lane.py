#!/usr/bin/env python3
"""INSERT the 3-node cluster validation lane row into command_executions.
WAL-safe: busy_timeout=5000, short txn, no journal_mode/VACUUM/checkpoint.
Idempotent guard: refuses to double-insert if uid already present."""
import sqlite3, sys, time

DB = "/home/tristan/gitters/LME/.ocr/data/ocr.db"

ROW = dict(
    command="task-agent:3node-cluster",
    args=None,
    exit_code=0,
    started_at="2026-09-16T23:32:57.970Z",   # transcript first ts (lane start)
    finished_at="2026-09-17T00:24:36.376Z",  # transcript last ts (lane end)
    output=None,                              # populate step sets this
    pid=None,
    is_detached=0,
    uid="a0d13148540b65321",                  # real agentId (unique)
    workflow_id="2026-09-16-fix-debian-13-selinux-apt",
    vendor="claude",
    vendor_session_id=None,
    persona=None,
    instance_index=None,
    name="3node-cluster",
    resolved_model="claude-opus-4-8",
    last_heartbeat_at=None,
    notes=("3-node cluster validation (seal topology 2 of 3): cluster GREEN 3 nodes / 120 shards "
           "(60 primary) 100%; all PLAY RECAPs failed=0 (site.yml localhost ok=245; es1 ok=296, "
           "es2/es3 ok=195); cert idmap fix holds every node (es1 4 consumers 0600/166536 + live "
           "idmap + INNS read OK; es2/es3 ES key 0600/166536 INNS_ES_READ_OK via UserNS, idmap "
           "legitimately absent); mlockall all 3, 0 OOM. Verdict: install+cluster+cert seal PASS; "
           "teardown PASS-with-confirmed-gap (dirty ~/LME cwd unquoted `systemctl stop lme*` glob "
           "self-resurrected 3 containers/9 units, remedied by clean-cwd re-wipe)."),
)

def main():
    con = sqlite3.connect(DB, timeout=6.0)
    try:
        con.execute("PRAGMA busy_timeout=5000;")
        cur = con.execute("SELECT id FROM command_executions WHERE uid=?", (ROW["uid"],))
        hit = cur.fetchone()
        if hit:
            print("ALREADY-PRESENT id=%s uid=%s (no insert)" % (hit[0], ROW["uid"]))
            return 0
        cols = list(ROW.keys())
        placeholders = ",".join("?" for _ in cols)
        sql = "INSERT INTO command_executions (%s) VALUES (%s)" % (",".join(cols), placeholders)
        for attempt in range(2):
            try:
                cur = con.execute(sql, tuple(ROW[c] for c in cols))
                con.commit()
                print("INSERTED id=%d" % cur.lastrowid)
                return 0
            except sqlite3.OperationalError as e:
                if ("locked" in str(e).lower() or "busy" in str(e).lower()) and attempt == 0:
                    con.rollback(); time.sleep(0.4); continue
                raise
    finally:
        con.close()

if __name__ == "__main__":
    sys.exit(main())
