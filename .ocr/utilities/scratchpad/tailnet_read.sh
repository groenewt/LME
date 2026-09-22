#!/usr/bin/env bash
# Read-only tailnet-side svc/VIP surface from silmaril's own status json.
# Usage: tailnet_read.sh <label>
lbl="${1:-read}"
echo "===== TAILNET READ [$lbl] $(date -u +%FT%TZ) ====="
tailscale status --json 2>/dev/null | python3 -c '
import json,sys
d=json.load(sys.stdin)
cm=d.get("Self",{}).get("CapMap",{}) or {}
sh=cm.get("service-host")
print("service-host cap:", json.dumps(sh) if sh is not None else "(absent)")
svc_caps=sorted(k for k in cm if k.startswith("services/"))
print("services/* caps present:", svc_caps if svc_caps else "(none)")
for k in svc_caps:
    print("   ", k, "=>", json.dumps(cm[k]))
# any peer advertising a service?
peers_with=[]
for name,p in (d.get("Peer",{}) or {}).items():
    for kk in p:
        if "service" in kk.lower() or "vip" in kk.lower():
            peers_with.append((p.get("HostName"),kk,p[kk]))
print("peer service/vip fields:", peers_with if peers_with else "(none)")
'
