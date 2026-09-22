#!/usr/bin/env python3
"""INSERT the airgapped-target validation lane row into command_executions.
WAL-safe: busy_timeout=5000, short txn, no journal_mode/VACUUM/checkpoint.
Idempotent guard: refuses to double-insert if uid already present."""
import sqlite3, sys, time

DB = "/home/tristan/gitters/LME/.ocr/data/ocr.db"

ROW = dict(
    command="task-agent:airgapped-target",
    args=None,
    exit_code=0,
    started_at="2026-09-16T23:45:23.201Z",   # transcript first ts (lane start)
    finished_at="2026-09-17T00:10:19.081Z",  # transcript last ts (lane end)
    output=None,                              # populate step sets this
    pid=None,
    is_detached=0,
    uid="ad33f9ee9f636b24f",                  # real agentId (unique)
    workflow_id="2026-09-16-fix-debian-13-selinux-apt",
    vendor="claude",
    vendor_session_id=None,
    persona=None,
    instance_index=None,
    name="airgapped-target",
    resolved_model="claude-opus-4-8",
    last_heartbeat_at=None,
    notes=("airgapped offline target install validation (seal topology #3 target half): "
           "airgap PROVEN (default route cut; raw-IP 1.1.1.1/8.8.8.8 + podman pull unreachable), "
           "offline install ok=199 changed=67 failed=0 (~6m52s), cert idmap 0600/166536 holds offline, "
           "wipe_lme.sh clean no-resurrection. Verdict PASS."),
)

def main():
    con = sqlite3.connect(DB, timeout=6.0)
    try:
        con.execute("PRAGMA busy_timeout=5000;")
        # guard: unique uid
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
