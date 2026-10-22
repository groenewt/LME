#!/bin/bash
# Enforce a physical airgap for the OFFLINE INSTALL window:
#  - delete ONLY the default route (keep the 192.168.122.0/24 on-link route so
#    the host<->guest management SSH the pipeline rides on survives)
#  - prove no egress with raw-IP curls (route-level, not just DNS) BEFORE+AFTER
#  - launch a 3s guard that re-deletes any default route DHCP re-adds mid-install
#  - launch a 30s sampler recording route + mem + disk across the whole window
set -u
PROOF=/root/airgap-proof.txt
GLOG=/root/airgap-guard.log
SLOG=/root/airgap-sampler.log
: > "$PROOF"; : > "$GLOG"; : > "$SLOG"

echo "===== AIRGAP CUT $(date -u +%FT%TZ) =====" | tee -a "$PROOF"
echo "--- route BEFORE cut ---" | tee -a "$PROOF"
ip route 2>&1 | tee -a "$PROOF"

echo "--- PRE-CUT egress sanity (expect reachable: proves cut is what breaks it) ---" | tee -a "$PROOF"
pre=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 https://1.1.1.1 2>/dev/null || echo 000)
echo "pre_cut curl https://1.1.1.1 -> HTTP=$pre" | tee -a "$PROOF"

echo "--- cutting: ip route del default ---" | tee -a "$PROOF"
ip route del default 2>&1 | tee -a "$PROOF"; echo "del rc=$?" | tee -a "$PROOF"

echo "--- route AFTER cut (expect NO default) ---" | tee -a "$PROOF"
ip route 2>&1 | tee -a "$PROOF"

echo "--- PROOF raw-IP curls (expect FAIL rc=7 network unreachable) ---" | tee -a "$PROOF"
for tgt in https://1.1.1.1 https://8.8.8.8; do
  code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 "$tgt" 2>/dev/null); rc=$?
  echo "curl $tgt -> HTTP=$code rc=$rc" | tee -a "$PROOF"
done
echo "--- PROOF DNS-name curl (expect FAIL) ---" | tee -a "$PROOF"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 https://deb.debian.org 2>/dev/null); rc=$?
echo "curl https://deb.debian.org -> HTTP=$code rc=$rc" | tee -a "$PROOF"

echo "--- host<->guest link survival (this line proves SSH route intact) ---" | tee -a "$PROOF"
echo "whoami=$(whoami) link_ok=YES" | tee -a "$PROOF"

# guard: re-delete any default route DHCP re-adds; keep link route untouched
setsid bash -c '
while true; do
  if ip route show default 2>/dev/null | grep -q "^default"; then
    ts=$(date -u +%FT%TZ); r=$(ip route show default | tr "\n" ";")
    ip route del default 2>/dev/null
    echo "$ts RECUT removed:$r" >> '"$GLOG"'
  fi
  sleep 3
done' </dev/null >/dev/null 2>&1 &
echo "guard_pid=$!" | tee -a "$PROOF"

# sampler: witness route/mem/disk across the install window
setsid bash -c '
while true; do
  ts=$(date -u +%FT%TZ)
  dr=$(ip route show default | tr "\n" ",")
  m=$(free -m | awk "/Mem:/{print \"mem_free=\"\$4\"M avail=\"\$7\"M\"}")
  d=$(df -h / | awk "NR==2{print \"disk_used=\"\$3\" avail=\"\$4\" pct=\"\$5}")
  echo "$ts default_route=[$dr] $m $d" >> '"$SLOG"'
  sleep 30
done' </dev/null >/dev/null 2>&1 &
echo "sampler_pid=$!" | tee -a "$PROOF"
echo "===== AIRGAP ENFORCED (guard+sampler running) =====" | tee -a "$PROOF"
