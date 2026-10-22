#!/usr/bin/env bash
# REVERT the tailnet ACL to the pre-wave-12 snapshot (undoes the 4 svc:lme-* additions).
# Force-revert to known-good: no If-Match (deliberately overwrites whatever is live).
set -euo pipefail
set -a; . ~/.temp.sh; set +a
SCR="$(cd "$(dirname "$0")" && pwd)"
: "${TS_API_TOKEN:?TS_API_TOKEN not set}"
curl -sS -X POST \
  -H "Authorization: Bearer $TS_API_TOKEN" \
  -H "Content-Type: application/hujson" \
  --data-binary @"$SCR/tailnet-acl.live.hujson" \
  "https://api.tailscale.com/api/v2/tailnet/-/acl"
echo "  ^ reverted to tailnet-acl.live.hujson"
