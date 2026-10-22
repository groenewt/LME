#!/usr/bin/env python3
"""Populate the airgapped-target lane row: raw output (summary md) + GENUINE
transcript timeline, matching sibling lane rows (leading truthful notice + real
transcript events). Reuses the sanctioned populate_agent_row.py functions.
No fabricated tool_call/tool_result — every message/tool event comes straight
from the real sub-agent transcript."""
import sys
sys.path.insert(0, "/home/tristan/gitters/LME/.ocr/tools")
import populate_agent_row as P

DB = "/home/tristan/gitters/LME/.ocr/data/ocr.db"
EVENTS_DIR = "/home/tristan/gitters/LME/.ocr/data/events"
ROW_ID = int(sys.argv[1])
AGENT_ID = "ad33f9ee9f636b24f"
TRANSCRIPT = ("/home/tristan/.claude/projects/-home-tristan-gitters-LME/"
              "6539b11f-6582-4ca9-899d-8a9e286bccad/subagents/agent-ad33f9ee9f636b24f.jsonl")
OUTPUT_MD = "/home/tristan/gitters/_ocr_vms/airgapped-target-validation.md"
STARTED = "2026-09-16T23:45:23.201Z"
FINISHED = "2026-09-17T00:10:19.081Z"

def main():
    # 1) raw output <- provenance/verdict header + genuine validation summary (md verbatim below)
    md = P._read_text(OUTPUT_MD)
    header = (
        "=== JOURNALED LANE: airgapped offline target install validation "
        "(seal topology #3, target half) ===\n"
        "Status: COMPLETED — Verdict PASS (see \"## Verdict: PASS\" section below).\n"
        "lane/command : task-agent:airgapped-target   agentId/uid : %s   row id : %d\n"
        "run window   : %s → %s   exit : 0\n"
        "result       : offline install ok=199 changed=67 unreachable=0 failed=0 (~6m52s); "
        "airgap PROVEN & held entire window (default route cut; raw-IP 1.1.1.1/8.8.8.8 + "
        "cloud.debian.org + post-install podman pull all network-unreachable); cert keys 0600 "
        "owner 166536 with live idmap uids=@166536-1000-1 (holds OFFLINE, zero EACCES); "
        "wipe_lme.sh clean, no resurrection.\n"
        "source       : %s\n"
        "NOTE: the \"Status: IN PROGRESS (skeleton ...)\" line in the summary below is the "
        "author's original skeleton marker written before evidence landed; it is SUPERSEDED by "
        "this completion header and by the Verdict: PASS section. Full evidence verbatim follows.\n"
        "%s\n\n"
        % (AGENT_ID, ROW_ID, STARTED, FINISHED, OUTPUT_MD, "=" * 78)
    )
    text = header + md
    P.set_output(DB, ROW_ID, text)

    # 2) timeline: truthful header notice (seq 1) + real transcript events (seq 2+)
    header = {
        "type": "notice", "seq": 1, "agentId": AGENT_ID, "level": "info",
        "message": ("task-agent:airgapped-target — genuine transcript agent-%s (%s → %s)"
                    % (AGENT_ID, STARTED, FINISHED)),
    }
    tx_events, _ = P.transcript_to_events(TRANSCRIPT, AGENT_ID, cap_start=2)
    if not tx_events:
        raise SystemExit("transcript produced 0 events — aborting")
    events = [header] + tx_events
    path, n = P.install_journal(EVENTS_DIR, ROW_ID, events)

    from collections import Counter
    tc = Counter(e.get("type") for e in events)
    print("id=%d output(len=%d) journal(%s, %d events) types=%s"
          % (ROW_ID, len(text), path, n, dict(tc)))

if __name__ == "__main__":
    main()
