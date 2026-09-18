#!/usr/bin/env bash
# ============================================================================
# LME E2E DEPLOY-GATE PIPELINE  (versioned gate harness)
# ----------------------------------------------------------------------------
# One leg of the seal gate = setup -> deploy -> teardown for ONE profile on ONE
# target, driven as a REAL pipeline: rsync the whole tree -> the tree's OWN
# scripts/wipe_lme.sh / install.sh -> health probe -> the tree's OWN wipe_lme.sh.
# NEVER ad-hoc per-file invocations. Any stage that cannot complete => the leg
# FAILS (nonzero exit), and the gate rule is: a stage that can't = FAIL.
#
# This harness runs on the CONTROLLER (e.g. the machine you invoke it from) and
# only ever touches the target through rsync + ssh; the target executes only the
# tree's own entrypoints. It is versioned here so the pipeline is reproducible,
# not a throwaway.
#
# Transport: plain `ssh -o BatchMode` to a MagicDNS name is intercepted by
# tailscale on :22 and authenticates by tailnet identity (no keys,
# non-interactive, root). rsync rides that same ssh.
#
# Usage:
#   testing/e2e/deploy_gate.sh --host graph --ip 192.168.68.73 \
#       --graphroot /data/lme-storage --flags "--elastic-services" \
#       --label graph-some --stage all
#
# Stages (--stage): all | rsync | wipe | install | health | deploy | teardown
#   wipe            = rsync + pre-install teardown+self-verify (cheapest smoke:
#                     validates transport + exec + a CLEAN host).
#   deploy          = rsync -> wipe -> install -> health, HOLD before teardown.
#   all             = rsync -> wipe -> install -> health -> teardown (full leg).
# Override LOGDIR / SRC / REMOTE_DIR via the environment.
# ----------------------------------------------------------------------------
set -uo pipefail

# ---- defaults --------------------------------------------------------------
# SRC defaults to the repo root discovered from this script's location
# (testing/e2e/deploy_gate.sh -> repo root two levels up), so the harness is
# portable regardless of where the checkout lives.
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SRC:-$(cd "$_SELF_DIR/../.." && pwd)}"
REMOTE_DIR="${REMOTE_DIR:-/root/LME-gate}"     # tree lands here on the target
HOST=""; IP=""; GRAPHROOT=""; FLAGS=""; LABEL=""; STAGE="all"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=15)
LOGDIR="${LOGDIR:-/tmp/lme-gate-logs}"

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2;;
    --ip) IP="$2"; shift 2;;
    --graphroot) GRAPHROOT="$2"; shift 2;;
    --flags) FLAGS="$2"; shift 2;;
    --label) LABEL="$2"; shift 2;;
    --stage) STAGE="$2"; shift 2;;
    --src) SRC="$2"; shift 2;;
    --remote-dir) REMOTE_DIR="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done
[ -n "$HOST" ] || { echo "FATAL: --host required" >&2; exit 2; }
LABEL="${LABEL:-$HOST}"
mkdir -p "$LOGDIR"
LOG="$LOGDIR/${LABEL}.log"
SSH=(ssh "${SSH_OPTS[@]}" "root@${HOST}")

say() { echo "[$(date -u +%FT%TZ)] [$LABEL] $*" | tee -a "$LOG"; }
run_remote() { "${SSH[@]}" "$@" 2>&1 | tee -a "$LOG"; return "${PIPESTATUS[0]}"; }

# ---- stage: rsync ----------------------------------------------------------
do_rsync() {
  say "RSYNC $SRC/ -> root@${HOST}:${REMOTE_DIR}/"
  "${SSH[@]}" "mkdir -p '$REMOTE_DIR'" 2>&1 | tee -a "$LOG"
  # Keep manifests/, ansible/inventory/, filter_plugins/ (ESSENTIAL to render).
  # Drop dev-only tooling + VM images + the env file (install.sh auto-creates it).
  rsync -e "ssh ${SSH_OPTS[*]}" -a --delete \
    --exclude='.git/' --exclude='scratchpad/' --exclude='_ocr_wt/' \
    --exclude='.ocr/' --exclude='.cursor/' --exclude='.opencode/' \
    --exclude='node_modules/' --exclude='__pycache__/' --exclude='*.pyc' \
    --exclude='*.qcow2' --exclude='*.iso' --exclude='*.img' \
    --exclude='config/lme-environment.env' \
    "$SRC/" "root@${HOST}:${REMOTE_DIR}/" 2>&1 | tee -a "$LOG"
  local rc="${PIPESTATUS[0]}"
  say "RSYNC rc=$rc"; return "$rc"
}

# ---- stage: wipe (pre teardown + self-verify; cheapest smoke) ---------------
do_wipe() {
  say "WIPE (teardown + self-verify clean) via tree's own scripts/wipe_lme.sh"
  run_remote "cd '$REMOTE_DIR' && bash scripts/wipe_lme.sh"
  local rc=$?
  say "WIPE rc=$rc  (0 => host verified CLEAN)"; return "$rc"
}

# ---- stage: install --------------------------------------------------------
do_install() {
  local g=""; [ -n "$GRAPHROOT" ] && g="-g '$GRAPHROOT'"
  local i=""; [ -n "$IP" ] && i="-i '$IP'"
  say "INSTALL via tree's own install.sh  flags=[$FLAGS] ip=[$IP] graphroot=[$GRAPHROOT]"
  run_remote "cd '$REMOTE_DIR' && NON_INTERACTIVE=true AUTO_CREATE_ENV=true ./install.sh $i $g $FLAGS"
  local rc=$?
  say "INSTALL rc=$rc"; return "$rc"
}

# ---- stage: health probe ---------------------------------------------------
do_health() {
  say "HEALTH probe"
  run_remote '
    set -o pipefail
    echo "== lme.service ==";        systemctl is-active lme.service || true
    echo "== running lme units ==";  systemctl list-units --plain --no-legend "lme*" --state=running | awk "{print \$1}" || true
    echo "== podman ps ==";          sudo -i podman ps --format "{{.Names}} {{.Status}}" || true
    echo "== ES :9200 TLS (expect 401 or 200) ==";
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 20 https://127.0.0.1:9200 || echo 000)
    echo "  ES http_code=$code"
    echo "== Kibana :5601 (expect 200/302/401) ==";
    kb=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 20 https://127.0.0.1:5601 || curl -s -o /dev/null -w "%{http_code}" --max-time 20 http://127.0.0.1:5601 || echo 000)
    echo "  Kibana http_code=$kb"
    # ES up (TLS handshake + auth challenge) is the pass gate; 000 => down.
    [ "$code" = "401" ] || [ "$code" = "200" ]
  '
  local rc=$?
  say "HEALTH rc=$rc  (0 => ES up behind TLS)"; return "$rc"
}

# ---- stage: teardown (final) ----------------------------------------------
do_teardown() {
  say "TEARDOWN (final) via tree's own scripts/wipe_lme.sh"
  run_remote "cd '$REMOTE_DIR' && bash scripts/wipe_lme.sh"
  local rc=$?
  say "TEARDOWN rc=$rc  (0 => host verified CLEAN)"; return "$rc"
}

# ---- driver ----------------------------------------------------------------
say "=== LEG START stage=$STAGE host=$HOST label=$LABEL ==="
rc=0
case "$STAGE" in
  rsync)    do_rsync; rc=$?;;
  wipe)     do_rsync && do_wipe; rc=$?;;
  install)  do_install; rc=$?;;
  health)   do_health; rc=$?;;
  teardown) do_teardown; rc=$?;;
  deploy)   # setup -> deploy -> health, HOLD before teardown (first-leg inspect)
    do_rsync   || { rc=$?; say "LEG FAIL at rsync";   exit $rc; }
    do_wipe    || { rc=$?; say "LEG FAIL at pre-wipe"; exit $rc; }
    do_install || { rc=$?; say "LEG FAIL at install"; exit $rc; }
    do_health  || { rc=$?; say "LEG FAIL at health";  exit $rc; }
    say "DEPLOY+HEALTH OK — stack HELD up for inspection (run --stage teardown to finish)"
    ;;
  all)
    do_rsync    || { rc=$?; say "LEG FAIL at rsync";    exit $rc; }
    do_wipe     || { rc=$?; say "LEG FAIL at pre-wipe"; exit $rc; }
    do_install  || { rc=$?; say "LEG FAIL at install";  do_teardown || true; exit $rc; }
    do_health   || { rc=$?; say "LEG FAIL at health";   do_teardown || true; exit $rc; }
    do_teardown || { rc=$?; say "LEG FAIL at teardown"; exit $rc; }
    ;;
  *) echo "unknown --stage $STAGE" >&2; exit 2;;
esac
say "=== LEG END stage=$STAGE rc=$rc ==="
exit "$rc"
