#!/usr/bin/env python3
"""Files-only step for the 3-node lane: writes (a) the raw-output text to a
scratchpad file (for a transparent, auditable inline `UPDATE ... readfile()`),
and (b) the GENUINE transcript timeline journal to .ocr/data/events/30.jsonl.
NO database writes here. No fabricated tool events."""
import sys
sys.path.insert(0, "/home/tristan/gitters/LME/.ocr/tools")
import populate_agent_row as P

EVENTS_DIR = "/home/tristan/gitters/LME/.ocr/data/events"
ROW_ID = 30
AGENT_ID = "a0d13148540b65321"
TRANSCRIPT = ("/home/tristan/.claude/projects/-home-tristan-gitters-LME/"
              "6539b11f-6582-4ca9-899d-8a9e286bccad/subagents/agent-a0d13148540b65321.jsonl")
OUTPUT_MD = "/home/tristan/gitters/_ocr_vms/cluster-3node-validation.md"
OUT_TXT = "/tmp/claude-1000/-home-tristan-gitters-LME/6539b11f-6582-4ca9-899d-8a9e286bccad/scratchpad/out30.txt"
STARTED = "2026-09-16T23:32:57.970Z"
FINISHED = "2026-09-17T00:24:36.376Z"

def main():
    md = P._read_text(OUTPUT_MD)
    header = (
        "=== JOURNALED LANE: 3-node cluster validation (seal topology 2 of 3) ===\n"
        "Status: COMPLETED — Verdict: install+cluster+cert seal PASS; teardown "
        "PASS-with-confirmed-gap (see \"## VERDICT\" section below).\n"
        "lane/command : task-agent:3node-cluster   agentId/uid : %s   row id : %d\n"
        "run window   : %s → %s   exit : 0\n"
        "result       : cluster GREEN, 3 ES nodes joined, 120 active shards (60 primary) = 100%%; "
        "all PLAY RECAPs failed=0 (site.yml localhost ok=245; elasticsearch.yml es1 ok=296, "
        "es2 ok=195, es3 ok=195); cert idmap fix holds on EVERY node (es1's 4 consumers "
        "kibana/wazuh/fleet/elastalert keys 0600 owner 166536 + live idmap uids=@166536-1000-1 + "
        "in-namespace read OK, EACCES=0; es2/es3 ES key 0600/166536 + INNS_ES_READ_OK via UserNS, "
        "idmap legitimately absent by design); mlockall=true all 3 nodes, 0 OOM at es1's 14 GiB.\n"
        "teardown     : PASS on clean cwd (es2/es3 wiped clean; es1 re-wipe from ~ fully clean). "
        "FAIL on dirty cwd ~/LME — unquoted `systemctl stop lme*` glob expands to dir names, "
        "service stop defeated, stack SELF-RESURRECTED (3 containers + 9 units persisted at +35s) "
        "= the operator's exact concern REPRODUCED; remedied by re-wipe from clean cwd. Residual "
        "gaps: /etc/lme vault never removed; file-driver secrets (llm-keys, pgvector) survive. "
        "(This teardown FAIL is real and intentionally preserved below.)\n"
        "source       : %s\n"
        "NOTE: the \"Status: IN PROGRESS (durable-first)\" line in the summary below is the "
        "author's original skeleton marker written before evidence landed; it is SUPERSEDED by "
        "this completion header and by the VERDICT section. Full evidence verbatim follows.\n"
        "%s\n\n"
        % (AGENT_ID, ROW_ID, STARTED, FINISHED, OUTPUT_MD, "=" * 78)
    )
    text = header + md
    with open(OUT_TXT, "w", encoding="utf-8") as f:
        f.write(text)

    hnotice = {
        "type": "notice", "seq": 1, "agentId": AGENT_ID, "level": "info",
        "message": ("task-agent:3node-cluster — genuine transcript agent-%s (%s → %s)"
                    % (AGENT_ID, STARTED, FINISHED)),
    }
    tx_events, _ = P.transcript_to_events(TRANSCRIPT, AGENT_ID, cap_start=2)
    if not tx_events:
        raise SystemExit("transcript produced 0 events — aborting")
    events = [hnotice] + tx_events
    path, n = P.install_journal(EVENTS_DIR, ROW_ID, events)

    from collections import Counter
    tc = Counter(e.get("type") for e in events)
    seqs = [e["seq"] for e in events]
    print("out_txt=%s len=%d" % (OUT_TXT, len(text)))
    print("journal=%s events=%d contiguous=%s types=%s"
          % (path, n, seqs == list(range(1, n + 1)), dict(tc)))

if __name__ == "__main__":
    main()
