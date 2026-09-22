#!/usr/bin/env bash
# Operator access capture: web UI URLs (tailnet VIP + loopback) + secrets.
# Run during the --stage deploy HOLD (stack live on graph). Read-only.
set -u
SS=(-o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=15)
OUT=/tmp/claude-1000/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/scratchpad/operator-access.txt
{
  echo "############ OPERATOR ACCESS $(date -u +%Y%m%dT%H%M%SZ) ############"
  echo "===== [A] Authoritative VIP URLs (from serve status --json: DNS + port) ====="
  ssh "${SS[@]}" root@graph 'tailscale serve status --json 2>/dev/null' \
    | grep -iE "\"(Web|TCP|Service|Handlers|Proxy|127.0.0.1|https)" | head -60
  echo ""
  echo "===== [B] podman secret inventory (names only) ====="
  ssh "${SS[@]}" root@graph 'sudo -i podman secret ls 2>/dev/null'
  echo ""
  echo "===== [C] Core UI creds via extract_secrets.sh -p (elastic/kibana_system/wazuh/pgvector) ====="
  # extract_secrets.sh must be sourced; locate the installed or deployed copy.
  ssh "${SS[@]}" root@graph 'for d in /opt/lme /root/LME-gate; do if [ -f "$d/scripts/extract_secrets.sh" ]; then echo "# sourcing $d/scripts/extract_secrets.sh -p"; ( cd "$d" && bash -lc ". scripts/extract_secrets.sh -p" ) 2>&1 | grep -iE "^Exported (elastic|kibana|wazuh|pgvector)|^elastic|password"; break; fi; done'
  echo ""
  echo "===== [D] AI web-UI keys (file-driver; extract_secrets.sh skips these) ====="
  for s in litellm_master_key webui_api_key; do
    echo -n "  $s = "
    ssh "${SS[@]}" root@graph "sudo -i podman secret inspect --showsecret $s --format '{{.SecretData}}' 2>/dev/null || echo '(not present)'"
    echo ""
  done
  echo "############ END OPERATOR ACCESS ############"
} 2>&1 | tee "$OUT"
echo "SAVED: $OUT"
