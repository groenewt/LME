#!/usr/bin/env bash
# HOLD-window closure proof for the armed tailscale SVC leg on graph.
# Run WHILE the --stage deploy HOLD keeps the stack up (before --stage teardown).
# Orchestrator-only live observation (read-only on the tailnet). No mutation.
set -u
SS=(-o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=15)
TS=tail6c2eb6.ts.net
SVCS=(lme-kibana lme-dashboard lme-log-analyzer lme-litellm)
OUT=/tmp/claude-1000/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/scratchpad/hold-proof-evidence.txt
{
  echo "############ HOLD PROOF $(date -u +%Y%m%dT%H%M%SZ) ############"
  echo "===== [1] graph Self.CapMap RAW keys (distinguish dead-VIP from wrong-key-shape) ====="
  ssh "${SS[@]}" root@graph 'tailscale status --json 2>/dev/null | grep -oE "\"services/[^\"]*\"|\"tag:[^\"]*\"" | sort -u'
  echo "===== [2] graph tailscale serve status (advertised svc:lme-* + co-tenant intact) ====="
  ssh "${SS[@]}" root@graph 'tailscale serve status 2>/dev/null'
  echo "===== [2b] graph serve status --json (VIP + DNS names) ====="
  ssh "${SS[@]}" root@graph 'tailscale serve status --json 2>/dev/null' | head -80
  echo "===== [3] per-svc CapMap presence assertion (armed key = services/<name>) ====="
  for s in "${SVCS[@]}"; do
    r=$(ssh "${SS[@]}" root@graph "tailscale status --json 2>/dev/null | grep -c \"services/$s\"")
    echo "  services/$s  present=$r  ($([ "$r" -ge 1 ] && echo LIVE || echo DEAD))"
  done
  echo "===== [4] REACHABILITY from trixie (tag:personal -> dst svc:lme-*; no -k tests cert SAN) ====="
  echo "--- trixie reachability to each svc VIP MagicDNS name ---"
  for s in "${SVCS[@]}"; do
    dns="$s.$TS"
    echo "  [$dns]"
    echo -n "    tailscale ping: "; ssh "${SS[@]}" root@trixie "tailscale ping --timeout=3s --c=1 $dns 2>&1 | head -1" 2>/dev/null || echo "(ping unavailable)"
    echo -n "    https no -k (cert SAN valid?): "; ssh "${SS[@]}" root@trixie "curl -sS --max-time 12 -o /dev/null -w '%{http_code}' https://$dns/ 2>&1 | tail -1" 2>/dev/null || echo "(fail)"
    echo -n "    https -k (reachability isolated): "; ssh "${SS[@]}" root@trixie "curl -sSk --max-time 12 -o /dev/null -w '%{http_code}' https://$dns/ 2>&1 | tail -1" 2>/dev/null || echo "(fail)"
  done
  echo "===== [5] graph accept-routes (should be TRUE now: egress leg set it; teardown reverts to baseline false) ====="
  ssh "${SS[@]}" root@graph 'tailscale debug prefs 2>/dev/null | grep -iE "RouteAll"'
  echo "############ END HOLD PROOF ############"
} 2>&1 | tee "$OUT"
echo "SAVED: $OUT"
