#!/usr/bin/env bash
# RUN 2: same as-specified command, now with a single-node cluster.yml present.
# Empirically tests BLOCKER 2 (does the cluster path drop the -e heap 2g override?).
set -o pipefail
SCRATCH="/tmp/claude-1000/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/scratchpad"
LOG="$SCRATCH/trixie-cluster-a2b2-run2.log"
GATE="/home/tristan/gitters/LME/testing/e2e/deploy_gate.sh"

EV='{"lme_service_overrides":{"elasticsearch":{"environment":{"node.name":"lme-elasticsearch","discovery.seed_hosts":"127.0.0.1:9300","cluster.initial_master_nodes":"lme-elasticsearch","network.publish_host":"127.0.0.1"},"resources":{"heap":"2g"}}}}'

echo "=== RUN2 START $(date -Is) ===" | tee "$LOG"
"$GATE" \
  --host trixie --ip 100.127.117.27 \
  --flags "--cluster --no-llm" \
  --extra-vars "$EV" \
  --label trixie-cluster-a2b2 --stage all 2>&1 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
echo "=== RUN2 END $(date -Is) overall_rc=$rc ===" | tee -a "$LOG"
exit "$rc"
