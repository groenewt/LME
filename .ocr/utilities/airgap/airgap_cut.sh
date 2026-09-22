#!/bin/bash
# Cut the DEFAULT route (keep the 192.168.122.0/24 LINK route so host<->guest SSH survives),
# start a 5s guard that re-deletes any reappearing default route (DHCP renewal defense),
# and record raw-IP + DNS egress proofs.
set -u
LOG=/home/vmuser/airgap
echo "=== PRE-CUT route ===" | tee $LOG-proof.txt
ip route | tee -a $LOG-proof.txt
sudo ip route del default 2>&1 | tee -a $LOG-proof.txt; echo "route-del rc=$?" | tee -a $LOG-proof.txt
# guard loop
cat > /home/vmuser/airgap-guard.sh <<'GEOF'
#!/bin/bash
: > /home/vmuser/airgap-guard.log
while true; do
  if ip route | grep -q '^default'; then
    ts=$(date -u +%FT%TZ); ip route del default 2>/dev/null && echo "$ts RE-CUT default route" >> /home/vmuser/airgap-guard.log
  fi
  sleep 5
done
GEOF
chmod +x /home/vmuser/airgap-guard.sh
setsid bash -c 'nohup /home/vmuser/airgap-guard.sh >/dev/null 2>&1 < /dev/null &'
sleep 2
echo "=== POST-CUT route ===" | tee -a $LOG-proof.txt
ip route | tee -a $LOG-proof.txt
echo "=== egress proofs (expect failure) ===" | tee -a $LOG-proof.txt
for tgt in https://1.1.1.1 https://8.8.8.8 https://cloud.debian.org; do
  code=$(curl --max-time 6 -sk -o /dev/null -w '%{http_code}' "$tgt" 2>/dev/null); rc=$?
  echo "curl $tgt -> HTTP=$code rc=$rc" | tee -a $LOG-proof.txt
done
echo "guard pid: $(pgrep -f airgap-guard.sh | head -1)" | tee -a $LOG-proof.txt
