#!/usr/bin/env python3
"""Writes ONLY the raw-output text for row 30 to a plain session-scratchpad
temp file. No DB write, no events/audit-dir write. Used to feed a transparent
inline `UPDATE ... SET output=CAST(readfile(...) AS TEXT)`."""
OUTPUT_MD = "/home/tristan/gitters/_ocr_vms/cluster-3node-validation.md"
OUT_TXT = "/tmp/claude-1000/-home-tristan-gitters-LME/6539b11f-6582-4ca9-899d-8a9e286bccad/scratchpad/out30.txt"
AGENT_ID = "a0d13148540b65321"
ROW_ID = 30
STARTED = "2026-09-16T23:32:57.970Z"
FINISHED = "2026-09-17T00:24:36.376Z"

with open(OUTPUT_MD, "r", encoding="utf-8", errors="replace") as f:
    md = f.read()
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
print("wrote %s len=%d" % (OUT_TXT, len(text)))
