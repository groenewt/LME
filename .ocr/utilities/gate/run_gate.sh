#!/usr/bin/env bash
SP=/tmp/claude-1000/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/scratchpad
export LOGDIR="$SP/gatelogs"
cd /home/tristan/gitters/LME
echo "START $(date -u +%FT%TZ)" > "$SP/gate_status.txt"
bash testing/e2e/deploy_gate.sh \
  --host 192.168.122.157 \
  --ssh-key /home/tristan/gitters/_ocr_vms/id_ed25519 \
  --remote-dir /home/vmuser/LME \
  --flags "--offline" \
  --label legC-airgapped-close \
  --stage all > "$SP/gate_console.log" 2>&1
rc=$?
echo "GATE_RC=$rc DONE $(date -u +%FT%TZ)" >> "$SP/gate_status.txt"
