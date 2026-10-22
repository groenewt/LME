#!/usr/bin/env bash
# One-shot probe: confirm opencode+openai/gpt-5.6-sol runs headless AND the tailscale MCP loads with auth.
set -a; . "$HOME/.temp.sh" 2>/dev/null; set +a
cd /home/tristan/gitters/LME || exit 3
echo "=== PROBE START $(date -u +%H:%M:%SZ) ==="
echo "TS_API_TOKEN present: $([ -n "$TS_API_TOKEN" ] && echo yes || echo NO)"
timeout 240 /home/tristan/.opencode/bin/opencode run -m openai/gpt-5.6-sol --dir /home/tristan/gitters/LME \
"PROBE — do exactly two things then stop, terse: (1) list the exact tool names of your available tailscale MCP tools; (2) make ONE read-only tailscale MCP call (list tailnet machines) and paste the raw result. Change nothing else." 2>&1
echo "=== PROBE_EXIT=$? $(date -u +%H:%M:%SZ) ==="
