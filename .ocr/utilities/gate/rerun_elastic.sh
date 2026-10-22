#!/usr/bin/env bash
# Wave-6 re-validation: online --tailscale --elastic-services --no-llm on graph.
# Real pipeline only (deploy_gate rsyncs whole tree -> target install.sh). The
# deploy stage HOLDS (no teardown) so the roster can be asserted BY NAME while up.
set -uo pipefail
cd /home/tristan/gitters/LME
SC=/tmp/claude-1000/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/scratchpad
LOG="$SC/graph-ts-elastic-rerun.log"
IP=100.73.170.86
: > "$LOG"
echo "RERUN LAUNCH $(date -u +%FT%TZ)  HEAD=$(git rev-parse --short HEAD)" | tee -a "$LOG"
testing/e2e/deploy_gate.sh --host graph --ip "$IP" --graphroot /data/lme-storage \
  --flags "--tailscale --elastic-services --no-llm" --label graph-ts-elastic-rerun --stage deploy >> "$LOG" 2>&1
RC=$?
echo "DEPLOY_EXIT_RC=$RC" | tee -a "$LOG"
echo "===== ROSTER ASSERTION (stack held, deploy stage does not teardown) =====" | tee -a "$LOG"
ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new root@"$IP" '
  echo "running_count=$(podman ps -q | wc -l)  (EXPECT 10)"
  echo "--- names+status (EXPECT: 5 core + 5 elastic):"; podman ps --format "{{.Names}} {{.Status}}" | sort
  echo "--- heartbeat present+HEALTHY (was crash-looping pre-fix):"; podman ps --format "{{.Names}} {{.Status}}" | grep heartbeat || echo "HEARTBEAT ABSENT (REGRESSION)"
  echo "--- fleet-distribution ABSENT expected online:"; (podman ps --format "{{.Names}}" | grep -q fleet-distribution && echo "PRESENT (unexpected online)" || echo "ABSENT (expected)")
  echo "--- any failed lme units:"; systemctl --failed --plain --no-pager | grep -i lme || echo "(none failed - good)"
' >> "$LOG" 2>&1
echo "ROSTER_DONE $(date -u +%FT%TZ)" | tee -a "$LOG"
