#!/usr/bin/env python3
"""populate_agent_row.py — safely backfill an OCR dashboard agent row's
   raw output (command_executions.output) AND its Timeline event journal
   (.ocr/data/events/<id>.jsonl) with NO server restart.

WHY THIS EXISTS
---------------
The OCR dashboard renders two per-command panes purely from data read fresh on
every request by the *already-running* (unpatched) server:
  * Raw output  <- command_executions.output          (SQLite column)
  * Timeline    <- <ocrDir>/data/events/<id>.jsonl     (on-disk journal, client `x9` reducer)
Agent rows journaled by `ocr session start-instance/end-instance` never get either
written, so the operator sees "No output recorded." / "No timeline data captured."
This tool writes both, safely, while the dashboard stays live.

SAFETY (matches the verified WAL rules)
  * Back up the DB with `VACUUM INTO` BEFORE calling this (not done here).
  * PRAGMA busy_timeout=5000; short transaction; retry once on SQLITE_BUSY.
  * NEVER touch/delete ocr.db-wal / ocr.db-shm; NEVER run VACUUM /
    wal_checkpoint / journal_mode on the live DB; NEVER restart the server.
  * Journal is written to <id>.jsonl.tmp, every line re-parsed with json.loads,
    then atomically os.replace()'d into place — a concurrent reader never sees a
    half-written / unparseable line (which would 500 that one request).

TIMELINE CONTENT — GENUINE ONLY
  * transcript mode: converts a REAL Claude Code sub-agent stream-json transcript
    (agentId known/bindable) into the client's event shapes. No invented events.
  * sparse mode: when no real transcript can be bound to the row, emits a TRUTHFUL
    SPARSE journal (notice/message) from facts that actually exist (timestamps,
    exit code, the review-file path, the row's note). No fabricated tool events.

The event `type` vocabulary the client `x9` reducer renders:
  message{seq,agentId,text} text_delta{...} thinking_delta{seq,agentId,text}
  tool_call{seq,agentId,toolId,name,input} tool_input_delta{toolId,deltaJson}
  tool_result{toolId,isError,output} error{seq,agentId,source,message,detail?}
  notice{seq,agentId,level,message}   (unknown types are silently skipped)
"""
import argparse
import json
import os
import sqlite3
import sys
import time

DEFAULT_DB = "/home/tristan/gitters/LME/.ocr/data/ocr.db"
DEFAULT_EVENTS = "/home/tristan/gitters/LME/.ocr/data/events"

# ---- size caps so a single journal stays small & readable (honest truncation) --
CAP_MSG = 8000
CAP_THINK = 2000
CAP_INPUT = 2000
CAP_TOOLRES = 3000


def _clip(s, n):
    if s is None:
        return ""
    s = str(s)
    if len(s) <= n:
        return s
    return s[:n] + "\n…[truncated %d chars for timeline; full content on disk]" % (len(s) - n)


# ---------------------------------------------------------------------------
# DB write (raw output)
# ---------------------------------------------------------------------------
def set_output(db_path, row_id, text):
    """Set command_executions.output for one existing row. Safe under WAL."""
    last = None
    for attempt in range(2):
        con = None
        try:
            con = sqlite3.connect(db_path, timeout=6.0)
            con.execute("PRAGMA busy_timeout=5000;")
            cur = con.execute(
                "UPDATE command_executions SET output=? WHERE id=?", (text, row_id)
            )
            if cur.rowcount != 1:
                con.rollback()
                raise RuntimeError(
                    "expected to update exactly 1 row for id=%s, got %d" % (row_id, cur.rowcount)
                )
            con.commit()
            return True
        except sqlite3.OperationalError as e:
            last = e
            if con:
                con.rollback()
            if "locked" in str(e).lower() or "busy" in str(e).lower():
                time.sleep(0.4)
                continue
            raise
        finally:
            if con:
                con.close()
    raise last


# ---------------------------------------------------------------------------
# Journal write (timeline)
# ---------------------------------------------------------------------------
def install_journal(events_dir, row_id, events):
    """Atomically write <events_dir>/<id>.jsonl, validating every line first."""
    os.makedirs(events_dir, exist_ok=True)
    final = os.path.join(events_dir, "%d.jsonl" % row_id)
    tmp = final + ".tmp.%d" % os.getpid()
    lines = []
    for ev in events:
        line = json.dumps(ev, ensure_ascii=False)
        json.loads(line)  # re-parse guard: never install a line the server can't parse
        lines.append(line)
    data = "\n".join(lines) + "\n"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, final)  # atomic on same filesystem
    return final, len(lines)


# ---------------------------------------------------------------------------
# GENUINE transcript -> event shapes
# ---------------------------------------------------------------------------
def transcript_to_events(transcript_path, agent_id, cap_start=1):
    """Convert a REAL Claude Code sub-agent stream-json transcript to x9 events.
    Emits, in file order: thinking_delta / message / tool_call / tool_result.
    Nothing is invented; blocks that don't exist in the transcript are not emitted."""
    events = []
    seq = cap_start
    with open(transcript_path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                o = json.loads(raw)
            except Exception:
                continue
            t = o.get("type")
            msg = o.get("message")
            content = msg.get("content") if isinstance(msg, dict) else None
            if not isinstance(content, list):
                continue
            if t == "assistant":
                for c in content:
                    if not isinstance(c, dict):
                        continue
                    ct = c.get("type")
                    if ct == "thinking":
                        txt = (c.get("thinking") or "").strip()
                        if txt:
                            events.append({"type": "thinking_delta", "seq": seq,
                                           "agentId": agent_id, "text": _clip(txt, CAP_THINK)})
                            seq += 1
                    elif ct == "text":
                        txt = (c.get("text") or "").strip()
                        if txt:
                            events.append({"type": "message", "seq": seq,
                                           "agentId": agent_id, "text": _clip(txt, CAP_MSG)})
                            seq += 1
                    elif ct == "tool_use":
                        events.append({"type": "tool_call", "seq": seq, "agentId": agent_id,
                                       "toolId": c.get("id") or ("tool-%d" % seq),
                                       "name": c.get("name") or "tool",
                                       "input": _shrink_input(c.get("input"))})
                        seq += 1
            elif t == "user":
                for c in content:
                    if not isinstance(c, dict) or c.get("type") != "tool_result":
                        continue
                    events.append({"type": "tool_result", "seq": seq, "agentId": agent_id,
                                   "toolId": c.get("tool_use_id") or ("tool-%d" % seq),
                                   "isError": bool(c.get("is_error", False)),
                                   "output": _clip(_flatten_toolresult(c.get("content")), CAP_TOOLRES)})
                    seq += 1
    return events, seq


def _shrink_input(inp):
    if inp is None:
        return {}
    try:
        s = json.dumps(inp, ensure_ascii=False)
    except Exception:
        return {"_repr": _clip(repr(inp), CAP_INPUT)}
    if len(s) <= CAP_INPUT:
        return inp
    return {"_truncated": _clip(s, CAP_INPUT)}


def _flatten_toolresult(content):
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, dict):
                if b.get("type") == "text":
                    parts.append(b.get("text") or "")
                else:
                    parts.append("[%s content]" % b.get("type", "non-text"))
            elif isinstance(b, str):
                parts.append(b)
        return "\n".join(parts)
    return str(content)


# ---------------------------------------------------------------------------
# TRUTHFUL SPARSE (facts only) -> event shapes
# ---------------------------------------------------------------------------
def build_sparse_events(agent_id, started, finished, exit_code, phase, source_path,
                        note=None, cap_start=1):
    """Emit a truthful sparse journal from facts that actually exist. No tool events."""
    seq = cap_start
    ev = []
    ev.append({"type": "notice", "seq": seq, "agentId": agent_id, "level": "info",
               "message": "session-instance %s started %s (%s)" % (agent_id, started, phase)})
    seq += 1
    body = (
        "Sparse backfill (no live transcript could be bound to this row). "
        "This agent ran as an isolated sub-agent journaled only for liveness via "
        "`ocr session start-instance/end-instance`; its per-reviewer stream was not "
        "captured to a bindable journal, so this Timeline reports facts only.\n"
        "Genuine review body is in the Raw output pane, sourced from:\n  %s\n"
        "Ran %s → %s, exit=%s." % (source_path, started, finished, exit_code)
    )
    if note:
        body += "\nRecorded note: " + note.replace("\n", " / ")
    ev.append({"type": "message", "seq": seq, "agentId": agent_id, "text": body})
    seq += 1
    ev.append({"type": "notice", "seq": seq, "agentId": agent_id, "level": "info",
               "message": "session-instance %s completed %s exit=%s" % (agent_id, finished, exit_code)})
    seq += 1
    return ev, seq


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Backfill OCR agent row output + timeline (no restart).")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--events-dir", default=DEFAULT_EVENTS)
    ap.add_argument("--id", type=int, required=True, help="existing command_executions.id")
    # raw output
    ap.add_argument("--output-file")
    ap.add_argument("--output-text")
    ap.add_argument("--no-output", action="store_true", help="skip the output UPDATE")
    # timeline source (choose one)
    ap.add_argument("--events-file", help="pre-built x9-shape jsonl to install verbatim (validated)")
    ap.add_argument("--transcript", help="real stream-json transcript to convert (genuine)")
    ap.add_argument("--agent-id", help="agentId to group timeline blocks under")
    ap.add_argument("--sparse", action="store_true", help="build a truthful sparse journal")
    ap.add_argument("--started"); ap.add_argument("--finished")
    ap.add_argument("--exit-code", default="0"); ap.add_argument("--phase", default="")
    ap.add_argument("--source-path", default=""); ap.add_argument("--note")
    ap.add_argument("--no-timeline", action="store_true", help="skip the journal write")
    args = ap.parse_args(argv)

    did = []
    # 1) raw output
    if not args.no_output:
        if args.output_file:
            text = _read_text(args.output_file)
        elif args.output_text is not None:
            text = args.output_text
        else:
            ap.error("provide --output-file or --output-text (or --no-output)")
        set_output(args.db, args.id, text)
        did.append("output(len=%d)" % len(text))

    # 2) timeline
    if not args.no_timeline:
        if args.events_file:
            events = [json.loads(l) for l in _read_text(args.events_file).splitlines() if l.strip()]
        elif args.transcript:
            aid = args.agent_id or ("agent-%d" % args.id)
            events, _ = transcript_to_events(args.transcript, aid)
            if not events:
                ap.error("transcript produced 0 events: %s" % args.transcript)
        elif args.sparse:
            aid = args.agent_id or ("agent-%d" % args.id)
            events, _ = build_sparse_events(aid, args.started, args.finished, args.exit_code,
                                            args.phase, args.source_path, args.note)
        else:
            ap.error("provide --events-file / --transcript / --sparse (or --no-timeline)")
        path, n = install_journal(args.events_dir, args.id, events)
        did.append("journal(%s, %d events)" % (path, n))

    print("id=%d: %s" % (args.id, "; ".join(did)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
