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
#
# --strict : make an install that RESCUED any task (PLAY RECAP rescued>0) FAIL
#            instead of only WARN.
#
# HEALTH is a REAL gate (see do_health). Its pass contract, all on the target:
#   * no `lme*` systemd unit in the `failed` state;
#   * >= EXPECT_MIN running containers (default 11 for default+llm; auto-lowered
#     for --no-llm/--offline, raised for --elastic-services; override with env
#     LME_GATE_MIN_CONTAINERS);
#   * EXPOSURE: every host-published port that should be loopback-only
#     (9200/5601/443/8220, plus llm 5432/8081/8502/8501/4000) is bound to
#     127.0.0.1/::1 and NOT LAN-open. Ports intentionally opened to the LAN
#     (expose_lan opt-in) are listed in env LME_GATE_LAN_OK="8502 5601 ...".
#   * SERVICE: ES :9200 -> 401/200, Kibana :5601 -> 200/302/401, and (llm)
#     dashboard /livez :8502 -> 200, log-analyzer :8501 reachable.
#   * AUTH: dashboard /api/health :8502 with NO key -> 401/403 (webui auth
#     enforced). Log-analyzer (streamlit) gates in-app at HTTP 200, so its auth
#     is not asserted at the HTTP layer here.
# Any check that cannot run (e.g. `ss` missing) is a FAIL, not a skip.
# ----------------------------------------------------------------------------
set -uo pipefail

# ---- defaults --------------------------------------------------------------
# SRC defaults to the repo root discovered from this script's location
# (testing/e2e/deploy_gate.sh -> repo root two levels up), so the harness is
# portable regardless of where the checkout lives.
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SRC:-$(cd "$_SELF_DIR/../.." && pwd)}"
REMOTE_DIR="${REMOTE_DIR:-/root/LME-gate}"     # tree lands here on the target
HOST=""; IP=""; GRAPHROOT=""; FLAGS=""; LABEL=""; STAGE="all"; STRICT=0
# Raw ansible extra-vars (JSON/k=v) forwarded verbatim to the target's install.sh
# --extra-vars, which appends it as a last-winning -e. Carries per-deploy values
# with no dedicated flag (e.g. multinode fleet_advertise_host / lme_service_overrides).
EXTRA_VARS=""
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=15)
LOGDIR="${LOGDIR:-/tmp/lme-gate-logs}"

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2;;
    --ip) IP="$2"; shift 2;;
    --graphroot) GRAPHROOT="$2"; shift 2;;
    --flags) FLAGS="$2"; shift 2;;
    --extra-vars) EXTRA_VARS="$2"; shift 2;;
    --label) LABEL="$2"; shift 2;;
    --stage) STAGE="$2"; shift 2;;
    --ssh-key) SSH_OPTS+=(-i "$2"); shift 2;;
    --src) SRC="$2"; shift 2;;
    --remote-dir) REMOTE_DIR="$2"; shift 2;;
    --strict) STRICT=1; shift;;
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
  # rsync must exist on BOTH ends -- it spawns a remote rsync over ssh. Stock
  # Debian-13 cloud images ship WITHOUT rsync (noble preinstalls it), so ensure
  # it on the target before the transfer. Idempotent: no-op where present. On an
  # AIRGAPPED target apt-get cannot reach a mirror -> nonzero rc -> this stage
  # FAILS loudly (airgapped images must pre-bake rsync); we never mask it.
  "${SSH[@]}" "command -v rsync >/dev/null 2>&1 || { apt-get update && apt-get install -y rsync; }" 2>&1 | tee -a "$LOG"
  local ensure_rc="${PIPESTATUS[0]}"
  if [ "$ensure_rc" -ne 0 ]; then say "RSYNC ensure-rsync-on-target FAILED rc=$ensure_rc"; return "$ensure_rc"; fi
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
  # Extra-vars ride through as a single-quoted argv element: the remote sh strips
  # the outer quotes and install.sh's --extra-vars receives the JSON as one arg.
  # (JSON must be single-quote-free -- it is, being all double-quoted.)
  local ev=""; [ -n "$EXTRA_VARS" ] && ev="--extra-vars '$EXTRA_VARS'"
  say "INSTALL via tree's own install.sh  flags=[$FLAGS] ip=[$IP] graphroot=[$GRAPHROOT] extra_vars=[$EXTRA_VARS]"
  # Capture THIS invocation's output to its own file (LOGDIR persists across
  # runs, so grepping the shared $LOG would match a prior leg's `rescued=`).
  local ilog="$LOGDIR/${LABEL}.install.$(date -u +%s).log"
  "${SSH[@]}" "cd '$REMOTE_DIR' && NON_INTERACTIVE=true AUTO_CREATE_ENV=true ./install.sh $i $g $FLAGS $ev" \
    2>&1 | tee -a "$LOG" | tee "$ilog"
  local rc="${PIPESTATUS[0]}"
  # RESCUE surfacing: Ansible PLAY RECAP emits `rescued=N` per host; a rescued
  # task means a rescue block masked a failure (the live graph run hit
  # rescued=2 that the gate never surfaced). Sum across recap lines.
  local rescued
  rescued=$(grep -oE 'rescued=[0-9]+' "$ilog" 2>/dev/null | grep -oE '[0-9]+' \
            | awk '{s+=$1} END{print s+0}')
  rescued="${rescued:-0}"
  if [ "$rescued" -gt 0 ]; then
    say "INSTALL WARN: rescued=$rescued task(s) recovered via an Ansible rescue block (PLAY RECAP)"
    if [ "$STRICT" = 1 ] && [ "$rc" = 0 ]; then
      say "INSTALL: --strict set and rescued>0 => treating install as FAIL"
      rc=1
    fi
  fi
  say "INSTALL rc=$rc (rescued=$rescued)"; return "$rc"
}

# ---- stage: health probe ---------------------------------------------------
do_health() {
  say "HEALTH probe (deep gate)"

  # ---- controller-side: derive the expected sets from the install flags ------
  # The LLM stack (group: llm in manifests/global.yml -> pgvector/llama-cpp/
  # litellm/log-analyzer/dashboard/embeddings) is present UNLESS --no-llm or
  # --offline. --elastic-services adds the apm/heartbeat/metric/file/logstash
  # pack. Guard the llm-only probes so the graph/trixie (default+llm) and any
  # reduced invocation both stay valid — same shape, different expected set.
  local llm_on=1
  case " $FLAGS " in *" --no-llm "*|*" --offline "*) llm_on=0;; esac
  local elastic_on=0
  case " $FLAGS " in *" --elastic-services "*) elastic_on=1;; esac

  # Loopback-only set: every host-published port that must NOT face the LAN
  # unless expose_lan opted it in (LME_GATE_LAN_OK). Core always; llm when on.
  local loopback_ports="9200 5601 443 8220"
  [ "$llm_on" = 1 ] && loopback_ports="$loopback_ports 5432 8081 8502 8501 4000"

  # Expected running-container floor. Default 11 (default+llm). Auto-adjust for
  # the reduced/expanded packs; an operator override always wins.
  local expect_min
  if [ -n "${LME_GATE_MIN_CONTAINERS:-}" ]; then
    expect_min="$LME_GATE_MIN_CONTAINERS"
  else
    if [ "$llm_on" = 1 ]; then expect_min=11; else expect_min=6; fi
    [ "$elastic_on" = 1 ] && expect_min=$((expect_min + 5))
  fi
  local lan_ok="${LME_GATE_LAN_OK:-}"

  say "HEALTH expects: containers>=$expect_min llm_on=$llm_on loopback=[$loopback_ports] lan_ok=[$lan_ok]"

  # ---- the remote payload ----------------------------------------------------
  # Quoted heredoc: single quotes are legal inside (unlike the old '...' arg
  # form) and the payload is independently `bash -n`-checkable. Values are
  # injected as env on the `bash -s` line, NOT interpolated here.
  local HEALTH_SH
  read -r -d '' HEALTH_SH <<'REMOTE_EOF' || true
set -o pipefail
fail=0
loopback_ok() { case "$1" in 127.0.0.1|::1|'[::1]') return 0;; *) return 1;; esac; }

echo "== lme.service =="
systemctl is-active lme.service || true

echo "== failed lme units (must be empty) =="
failed=$(systemctl list-units --plain --no-legend 'lme*' --state=failed 2>/dev/null | awk '{print $1}')
if [ -n "$failed" ]; then
  echo "  FAIL: lme units in failed state: $(echo $failed)"; fail=1
else
  echo "  ok: no failed lme units"
fi

echo "== running containers (expect >= $EXPECT_MIN) =="
running=$(sudo -i podman ps --format '{{.Names}}' 2>/dev/null | sed '/^$/d' | wc -l)
echo "  running=$running"
if [ "$running" -lt "$EXPECT_MIN" ]; then
  echo "  FAIL: only $running running container(s), expected >= $EXPECT_MIN"; fail=1
else
  echo "  ok: $running >= $EXPECT_MIN"
fi

echo "== exposure: loopback-only binds ($LOOPBACK_PORTS) =="
if ! command -v ss >/dev/null 2>&1; then
  echo "  FAIL: ss unavailable — cannot assert exposure"; fail=1
else
  # port<space>addr per listening socket (addr = local addr with the port
  # stripped): 0.0.0.0:9200->'9200 0.0.0.0', [::]:5601->'5601 [::]', *:5432->'5432 *'.
  listen_tbl=$(ss -ltnH 2>/dev/null | awk '{a=$4; p=a; sub(/:[0-9]+$/,"",a); sub(/.*:/,"",p); print p" "a}')
  # A live host always has listeners (sshd at minimum). Empty => the probe
  # broke (e.g. `ss` too old for -H), NOT a closed host: fail, don't pass green.
  if [ -z "$listen_tbl" ]; then
    echo "  FAIL: no listening sockets parsed from ss — cannot assert exposure"; fail=1
  fi
  for p in $LOOPBACK_PORTS; do
    case " $LAN_OK " in *" $p "*) echo "  port $p: LAN opt-in (expose_lan) — skip"; continue;; esac
    addrs=$(printf '%s\n' "$listen_tbl" | awk -v pp="$p" '$1==pp {print $2}')
    if [ -z "$addrs" ]; then
      echo "  port $p: not listening (service down or not in this profile)"
      continue
    fi
    bad=""
    for a in $addrs; do loopback_ok "$a" || bad="$bad $a"; done
    if [ -n "$bad" ]; then
      echo "  FAIL: port $p LAN-open on$bad — expected 127.0.0.1 (bind-inversion/expose_lan?)"; fail=1
    else
      echo "  ok: port $p loopback-only [$(echo $addrs)]"
    fi
  done
fi

echo "== service: ES :9200 (expect 401/200) =="
code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 https://127.0.0.1:9200 || echo 000)
echo "  ES http_code=$code"
case "$code" in 401|200) echo "  ok";; *) echo "  FAIL: ES not up behind TLS"; fail=1;; esac

echo "== service: Kibana :5601 (expect 200/302/401) =="
kb=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 https://127.0.0.1:5601 || echo 000)
echo "  Kibana http_code=$kb"
case "$kb" in 200|302|401) echo "  ok";; *) echo "  FAIL: Kibana not up"; fail=1;; esac

if [ "$LLM_ON" = 1 ]; then
  echo "== service: dashboard /livez :8502 (expect 200; unauthenticated liveness) =="
  dl=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 https://127.0.0.1:8502/livez || echo 000)
  echo "  dashboard /livez http_code=$dl"
  case "$dl" in 200) echo "  ok";; *) echo "  FAIL: dashboard /livez not reachable on loopback"; fail=1;; esac

  echo "== auth: dashboard /api/health with NO key (expect 401/403) =="
  da=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 https://127.0.0.1:8502/api/health || echo 000)
  echo "  dashboard /api/health (unauth) http_code=$da"
  case "$da" in 401|403) echo "  ok: webui auth enforced";;
    *) echo "  FAIL: /api/* served unauthenticated ($da) — webui-auth not enforced"; fail=1;; esac

  echo "== service: log-analyzer :8501 reachable (streamlit gates in-app at 200) =="
  la=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 https://127.0.0.1:8501 || echo 000)
  echo "  log-analyzer http_code=$la"
  case "$la" in 200|302|401|403) echo "  ok";; *) echo "  FAIL: log-analyzer unreachable"; fail=1;; esac
fi

echo "== HEALTH result: fail=$fail =="
exit "$fail"
REMOTE_EOF

  run_remote "EXPECT_MIN='$expect_min' LLM_ON='$llm_on' LOOPBACK_PORTS='$loopback_ports' LAN_OK='$lan_ok' bash -s" <<<"$HEALTH_SH"
  local rc=$?
  say "HEALTH rc=$rc  (0 => all gate checks passed)"; return "$rc"
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
