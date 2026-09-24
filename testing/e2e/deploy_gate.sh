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
# Stages (--stage): all | rsync | wipe | install | health | vip-probe | telemetry | deploy | teardown
#   wipe            = rsync + pre-install teardown+self-verify (cheapest smoke:
#                     validates transport + exec + a CLEAN host).
#   vip-probe       = A1 consumer-node VIP reachability. Applicability comes from
#                     the selected route contract; optional selected routes may be
#                     SKIPPED, and required selected routes must execute and pass.
#                     Also runs after health in the health/deploy/all stages.
#   deploy          = rsync -> wipe -> install -> health -> vip-probe, HOLD before teardown.
#   all             = rsync -> wipe -> install -> health -> vip-probe -> evidence
#                     retention -> teardown. It does not claim collection/readback.
#   telemetry       = fails until collection acceptance consumes the canonical
#                     resolved configuration; quarantined verification cannot pass it.
# Override LOGDIR / SRC / REMOTE_DIR via the environment.
#
# --strict : make an install that RESCUED any task (PLAY RECAP rescued>0) FAIL
#            instead of only WARN.
#
# HEALTH is a REAL gate (see do_health). Its pass contract, all on the target:
#   * no `lme*` systemd unit in the `failed` state;
#   * exact manifest-derived persistent container names under their declared
#     runtime owners, plus separately verified completed initialization jobs;
#   * the legacy EXPECT_MIN arithmetic remains as a compatibility floor, but an
#     unrelated same-count container set cannot satisfy the exact roster;
#   * EXPOSURE (DENY-BY-DEFAULT, over TCP *and* UDP): the checked set is the
#     COMPLETE list of host-published ports, DERIVED from the manifests (the union
#     of manifests/global.yml's canonical `ports:` table, manifests/services/*.yml
#     publish_ports, and manifests/profiles/*.yml overlays) -- NOT a hand-kept
#     subset. So NO service port is silently unchecked: wazuh 1514/1515/55000, the
#     udp syslog 514, fleet-distribution 8080, apm 8200, logstash 5044/8085 and the
#     ES transport 9300 are all covered now. EVERY such port must bind
#     127.0.0.1/::1; ANY non-loopback (0.0.0.0/LAN) bind on ANY of them, TCP OR UDP,
#     FAILS the gate. The only accepted non-loopback binds are:
#       - expose_lan operator opt-in, env LME_GATE_LAN_OK="8502 5601 ...";
#       - a port the ACTIVE manifest PROFILE deliberately opens (bind:0.0.0.0 in
#         manifests/profiles/<profile>.yml), derived ONLY when the profile is
#         explicitly named (--profile NAME or -e lme_profile=NAME) so a misfired
#         inference can never silently unlock a LAN bind (cluster->9300,
#         multinode->8220/9200; default/offline/tailscale open none);
#       - when the tailscale ingress leg is on for this run (--tailscale / --profile
#         tailscale / -e tailscale_serve_ingress=true), the ports it fronts
#         (8200/4000/5044) may ALSO bind this node's own tailnet IP (CGNAT
#         100.64.0.0/10 or ULA fd7a:115c:a1e0::/48) BY DESIGN. Override that fronted
#         set with env LME_GATE_TAILNET_OK="4000 ...".
#     A real 0.0.0.0/LAN bind still FAILS even on a tailnet-fronted port. Each
#     allowed non-loopback port logs WHICH rule admitted it (expose_lan / profile /
#     tailnet-ingress).
#   * SERVICE: ES :9200 -> 401/200, Kibana :5601 -> 200/302/401, and (llm)
#     dashboard /livez :8502 -> 200, log-analyzer :8501 reachable.
#   * AUTH: dashboard /api/health :8502 with NO key -> 401/403 (webui auth
#     enforced). Log-analyzer (streamlit) gates in-app at HTTP 200, so its auth
#     is not asserted at the HTTP layer here.
# Any check that cannot run (e.g. `ss` missing, the manifest port-set failing to
# derive, or ss returning no TCP listeners) is a FAIL, not a skip.
# ----------------------------------------------------------------------------
# ---- defaults --------------------------------------------------------------
# SRC defaults to the repo root discovered from this script's location
# (testing/e2e/deploy_gate.sh -> repo root two levels up), so the harness is
# portable regardless of where the checkout lives.
_SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SRC:-$(cd "$_SELF_DIR/../.." && pwd)}"
REMOTE_DIR="${REMOTE_DIR:-/root/LME-gate}"     # tree lands here on the target
HOST=""; IP=""; GRAPHROOT=""; FLAGS=""; LABEL=""; STAGE="all"; STRICT=0; SSH_KEY=""
# Raw ansible extra-vars (JSON/k=v) forwarded verbatim to the target's install.sh
# --extra-vars. In the SINGLE-NODE install path install.sh appends it as a
# last-winning -e (install.sh:832/834). In --cluster mode it is currently DROPPED:
# the cluster Phase-1 (site.yml, install.sh:1006) and Phase-2 (elasticsearch.yml,
# install.sh:1020) invocations do NOT forward EXTRA_VARS_ARGS, so a -e passed
# alongside --cluster is INERT until that asymmetry is fixed -- size a cluster node
# via its ansible/inventory/host_vars/es*.yml instead. Carries per-deploy values
# with no dedicated flag (e.g. multinode fleet_advertise_host / lme_service_overrides).
EXTRA_VARS=""
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=15)
LOGDIR="${LOGDIR:-/tmp/lme-gate-logs}"
LOG="${LOG:-}"
RESULTS="${RESULTS:-}"
SSH=()

require_arg_value() {
  local opt="$1" value="${2-}"
  if [ -z "$value" ] || [[ "$value" == --* ]]; then
    echo "FATAL: $opt requires a non-empty value" >&2
    return 2
  fi
}

parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --host|--ip|--graphroot|--flags|--extra-vars|--label|--stage|--ssh-key|--src|--remote-dir)
        require_arg_value "$1" "${2-}" || return $?
        case "$1" in
          --host) HOST="$2";;
          --ip) IP="$2";;
          --graphroot) GRAPHROOT="$2";;
          --flags) FLAGS="$2";;
          --extra-vars) EXTRA_VARS="$2";;
          --label) LABEL="$2";;
          --stage) STAGE="$2";;
          --ssh-key) SSH_KEY="$2"; SSH_OPTS+=(-i "$2");;   # target: translated by the contract; SSH_OPTS: probe host only
          --src) SRC="$2";;
          --remote-dir) REMOTE_DIR="$2";;
        esac
        shift 2
        ;;
      --strict) STRICT=1; shift;;
      *) echo "unknown arg: $1" >&2; return 2;;
    esac
  done
}

init_gate_run() {
  case "$STAGE" in
    all|rsync|wipe|install|health|vip-probe|telemetry|deploy|teardown) ;;
    *) echo "unknown --stage $STAGE" >&2; return 2;;
  esac
  if [ "$STAGE" != telemetry ] && [ -z "$HOST" ]; then
    echo "FATAL: --host required" >&2
    return 2
  fi
  LABEL="${LABEL:-${HOST:-lab}}"
  mkdir -p "$LOGDIR"
  LOG="${LOG:-$LOGDIR/${LABEL}.log}"
  RESULTS="${RESULTS:-$LOGDIR/${LABEL}.gate-results.jsonl}"
  case "$STAGE" in
    telemetry|vip-probe) ;;
    *) resolve_target_contract || return $?;;
  esac
}

say() {
  local line
  line="[$(date -u +%FT%TZ)] [${LABEL:-gate}] $*"
  if [ -n "${LOG:-}" ]; then printf '%s\n' "$line" | tee -a "$LOG"; else printf '%s\n' "$line"; fi
}

json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"; s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

# Machine-readable result contract. Required/applicable/executed are independent;
# a skipped or inapplicable check never appears as PASS.
emit_gate_result() {
  local check="$1" required="$2" applicable="$3" executed="$4" status="$5" evidence="$6" reason="$7"
  local line
  line=$(printf 'GATE_RESULT {"check":"%s","required":%s,"applicable":%s,"executed":%s,"status":"%s","evidence":"%s","reason":"%s"}' \
    "$(json_escape "$check")" "$required" "$applicable" "$executed" \
    "$(json_escape "$status")" "$(json_escape "$evidence")" "$(json_escape "$reason")")
  printf '%s\n' "$line"
  [ -z "${LOG:-}" ] || printf '%s\n' "$line" >>"$LOG"
  [ -z "${RESULTS:-}" ] || printf '%s\n' "${line#GATE_RESULT }" >>"$RESULTS"
}

run_remote() { "${SSH[@]}" "$@" 2>&1 | tee -a "$LOG"; return "${PIPESTATUS[0]}"; }

# ---- target contract + stage rsync (declared: testing/e2e/transfer/transfer.decl.yml) -------------------
# Residual debt: this is hand-written bash. It only STARTS the declared entry playbooks through the route's
# GENERATED seed launcher (controller.bootstrap.seed_launcher: <bundle>/<bundle.launcher_file>, a bundle member with
# the seed's custody), which execs the bundle seed's `run` (it binds the managed generation; resolve_harness.yml
# refuses any other) with exactly the declared seed_launch environment. This gate builds no environment and never
# names the seed; it reads the entry playbooks' declared outputs. Required inputs, no default, no derived fallback:
#   LME_CONTROLLER_LAUNCHER the bundle's generated launcher, by its ABSOLUTE path (seed_launcher.caller_argv)
#   LME_CONTROLLER_ROOT     the seed's owned toolchain root
#   LME_TRANSFER_INVENTORY  inventory (the target alias + root/owner host vars)
#   LME_TRANSFER_STATE_DIR  owned 0700 controller state dir; outputs gate.<label>.{contract.json,ssh-argv,machine-id,transfer.json}
#   LME_SSH_AUTH_MODE       the ONE ssh auth mode of this run (route ssh_auth.modes; the launcher's run mode
#                           parameter); the inventory's lme_ssh_auth_mode must equal it (a conflict refuses before any effect).
# Launcher call (positional, caller_argv): <launcher> run <root> <ssh auth mode> <ansible-playbook words...>; every
# word is one quoted argument ("$@" preserved), so spaces and empty words keep their boundaries.
gate_seed_run() {
  local pb="$1" v; shift
  for v in LME_CONTROLLER_LAUNCHER LME_CONTROLLER_ROOT LME_TRANSFER_INVENTORY LME_TRANSFER_STATE_DIR LME_SSH_AUTH_MODE; do
    if [ -z "${!v:-}" ]; then
      say "FATAL: $v is required (no default)"
      emit_gate_result transfer-input true true false FAIL none "TRANSFER_INPUT_MISSING: $v"
      return 2
    fi
  done
  case "$LME_CONTROLLER_LAUNCHER" in
    /*) : ;;
    *)
      say "FATAL: LME_CONTROLLER_LAUNCHER must be an absolute path (no command lookup)"
      emit_gate_result transfer-input true true false FAIL none "TRANSFER_INPUT_NOT_ABSOLUTE: LME_CONTROLLER_LAUNCHER"
      return 2
      ;;
  esac
  "$LME_CONTROLLER_LAUNCHER" run "$LME_CONTROLLER_ROOT" "$LME_SSH_AUTH_MODE" -i "$LME_TRANSFER_INVENTORY" "$_SELF_DIR/transfer/$pb" \
    -e "lme_transfer_target=$HOST" -e "lme_transfer_ssh_key=$SSH_KEY" -e "lme_transfer_state_dir=$LME_TRANSFER_STATE_DIR" \
    -e "lme_transfer_label=$LABEL" -e "lme_transfer_remote_dir=$REMOTE_DIR" "$@" 2>&1 | tee -a "$LOG"
  return "${PIPESTATUS[0]}"
}

# Every target stage uses ONLY this ssh argv (rendered from the one contract) and the recorded endpoint identity.
resolve_target_contract() {
  local out="$LME_TRANSFER_STATE_DIR/gate.$LABEL" rc
  gate_seed_run resolve_target.yml; rc=$?
  if [ "$rc" -ne 0 ] || ! mapfile -t SSH < "$out.ssh-argv" || ! IFS= read -r TARGET_IDENTITY < "$out.machine-id"; then
    emit_gate_result target-contract true true true FAIL "$LOG" "TARGET_CONTRACT_REFUSED: rc=$rc (see $out.contract.json and the log)"
    return 1
  fi
  emit_gate_result target-contract true true true PASS "$out.contract.json" ""
}

assert_target_identity() {
  local id
  id=$("${SSH[@]}" cat /etc/machine-id 2>>"$LOG") || id=""
  if [ -z "${TARGET_IDENTITY:-}" ] || [ "$id" != "$TARGET_IDENTITY" ]; then
    emit_gate_result target-identity true true true FAIL "$LOG" "TARGET_IDENTITY_MISMATCH: read '$id', contract '${TARGET_IDENTITY:-}'"
    return 1
  fi
}

do_rsync() {
  local receipt="$LME_TRANSFER_STATE_DIR/gate.$LABEL.transfer.json" rc
  say "TRANSFER (managed_archive, committed edition) $SRC -> contract ${SSH[*]: -1}:$REMOTE_DIR"
  rm -f -- "$receipt"
  gate_seed_run transfer.yml -e "lme_transfer_src=$SRC"; rc=$?
  if [ "$rc" -ne 0 ]; then
    emit_gate_result transfer true true true FAIL "$LOG" "TRANSFER_REFUSED: rc=$rc"; return 1
  fi
  if [ ! -s "$receipt" ]; then
    emit_gate_result transfer true true true FAIL "$LOG" "TRANSFER_NO_RECEIPT: rc=0 without $receipt"; return 1
  fi
  emit_gate_result transfer true true true PASS "$receipt" ""
}

# ---- stage: wipe (pre teardown + self-verify; cheapest smoke) ---------------
refuse_physical_silmaril_wipe() {
  if [ "${HOST%%.*}" = silmaril ]; then
    say "WIPE FAIL: blanket wipe forbidden on physical silmaril; target an exact recorded guest resource instead"
    emit_gate_result cleanup true true false BLOCKED none physical_silmaril_blanket_wipe_forbidden
    return 1
  fi
}

do_wipe() {
  refuse_physical_silmaril_wipe || return $?
  assert_target_identity || return $?
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
  assert_target_identity || return $?
  say "INSTALL via tree's own install.sh  flags=[$FLAGS] ip=[$IP] graphroot=[$GRAPHROOT] extra_vars=[$EXTRA_VARS]"
  # Capture THIS invocation's output to its own file (LOGDIR persists across
  # runs, so grepping the shared $LOG would match a prior leg's `rescued=`).
  local ilog
  ilog="$LOGDIR/${LABEL}.install.$(date -u +%s).log"
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

# ---- manifest-derived exposure sets (controller-side) ----------------------
# The exposure gate is DENY-BY-DEFAULT over the COMPLETE set of host-published
# ports. That set is NOT hand-maintained here: it is derived from the manifests so
# a port added to a service manifest is checked automatically (no blind spot).
# derive_published_ports() unions every port-mapping (`{host: N ...}`) across the
# canonical global table, the per-service manifests, AND the profile overlays --
# reading all three (not just global.yml) keeps "no service port silently unchecked"
# true even if the canonical table ever drifts from a service manifest. `protocol:
# udp` entries (e.g. wazuh syslog 514) are included by number; the udp listener table
# catches the bind. Emits unique host port NUMBERS, one per line.
# PRIMARY = a real PyYAML walk (this runs CONTROLLER-side, where python3+PyYAML is
# present -- the same convention wipe_lme.sh uses), so it is FORMAT-AGNOSTIC: a
# publish_ports entry written flow-style (`{host: N, ...}`) or block-style (`- host:`
# on its own line) is collected identically. FALLBACK (no python3/PyYAML on the
# controller) = the flow-style grep, valid for today's flow-style manifests. A python
# parse that errors or yields nothing degrades to the fallback rather than a partial.
derive_published_ports() {
  local root="$SRC/manifests" out=""
  [ -d "$root" ] || return 1
  if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1; then
    if out=$(python3 - "$root" 2>/dev/null <<'PY'
import glob, os, sys
try:
    import yaml
except Exception:
    sys.exit(3)
root = sys.argv[1]
ports = set()
def add(h):
    if isinstance(h, bool):
        return
    if isinstance(h, int):
        ports.add(h)
    elif isinstance(h, str) and h.strip().isdigit():
        ports.add(int(h.strip()))
def walk(n):
    if isinstance(n, dict):
        if 'host' in n:
            add(n['host'])
        for v in n.values():
            walk(v)
    elif isinstance(n, list):
        for v in n:
            walk(v)
files = []
gp = os.path.join(root, 'global.yml')
if os.path.isfile(gp):
    files.append(gp)
files += sorted(glob.glob(os.path.join(root, 'services', '*.yml')))
files += sorted(glob.glob(os.path.join(root, 'profiles', '*.yml')))
for f in files:
    try:
        with open(f) as fh:
            walk(yaml.safe_load(fh))
    except Exception:
        sys.exit(3)   # malformed manifest -> abort -> caller falls back
for p in sorted(ports):
    print(p)
PY
    ) && [ -n "$out" ]; then
      printf '%s\n' "$out"
      return
    fi
  fi
  # FALLBACK: flow-style grep across all three sources.
  {
    [ -f "$root/global.yml" ] && grep -hE '\{[[:space:]]*host:' "$root/global.yml"
    grep -rhE '\{[[:space:]]*host:' "$root/services/" 2>/dev/null
    grep -rhE '\{[[:space:]]*host:' "$root/profiles/" 2>/dev/null
  } | grep -oE 'host:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | sort -un
}

# explicit_profile(): the manifest profile install.sh will actually RENDER for this
# run, resolved in the SAME precedence install.sh + ansible produce (so the gate's
# accepted-LAN set matches the real render). Precedence, highest first:
#   1. lme_profile forwarded through --extra-vars (JSON or k=v). SINGLE-NODE path only:
#      install.sh injects lme_profile=<EFFECTIVE_PROFILE> into its own --extra-vars FIRST
#      then appends the operator's -e (install.sh:832/834), and ansible's LAST -e for a
#      key wins -- so a forwarded lme_profile overrides install's mode-derived profile.
#      NOTE: in --cluster mode install.sh DROPS the operator -e (Phase-1/2 at :1006/:1020
#      omit EXTRA_VARS_ARGS), so a forwarded lme_profile is ignored there and the profile
#      is purely --cluster-derived (branch 3) -- which is what this gate predicts anyway.
#   2. `--profile NAME` in the flags (-> LME_PROFILE -> EFFECTIVE_PROFILE, install.sh:147/710).
#   3. derived from the mode flags exactly as install.sh:711-716 (compute_effective_flags):
#      --cluster -> cluster, --offline -> offline. (default/tailscale open no LAN port,
#      so an empty result is correct for them; tailscale ingress is handled separately.)
# Deriving from the mode flags is FAIL-SAFE: the gate forwards these IDENTICAL flags to
# install.sh, so profile_lan_ports() reads the very manifest install.sh renders. A profile
# opens a LAN port ONLY via an explicit bind:0.0.0.0 entry, so a derivation can only ADMIT
# a port the profile genuinely binds wide, never invent an allowance; and a mismatch can at
# worst false-FAIL (narrower than rendered) -- the exposure check FAILs only on an actual
# 0.0.0.0 bind, so it can never false-PASS. Without derivation a bare `--cluster` gate leg
# would false-FAIL its own transport port (9300); this derivation removes that gate-side
# false-FAIL. (A leg that actually COMPLETES a cluster seal additionally needs an
# operator-supplied ansible/inventory/cluster.yml and a master roomy enough for the
# profile-default heap -- or the install.sh cluster -e-drop above fixed; those are
# install.sh/fleet limits surfaced as review findings, not gate limits.)
explicit_profile() {
  local p=""
  p=$(printf '%s' "$EXTRA_VARS" \
      | grep -oE '"?lme_profile"?[[:space:]]*[=:][[:space:]]*"?[a-z0-9_-]+' \
      | grep -oE '[a-z0-9_-]+$' | head -1)
  if [ -z "$p" ]; then
    case " $FLAGS " in
      *" --profile "*) p="${FLAGS##*--profile }"; p="${p%% *}";;
      *" --profile="*) p="${FLAGS##*--profile=}"; p="${p%% *}";;
    esac
  fi
  if [ -z "$p" ]; then
    case " $FLAGS " in
      *" --cluster "*) p="cluster";;
      *" --offline "*|*" -o "*) p="offline";;
    esac
  fi
  printf '%s' "$p"
}

# profile_lan_ports(): the host ports the named profile deliberately opens to the
# LAN. A profile opens a port ONLY by re-declaring a publish_ports entry with
# bind:0.0.0.0 (default posture is loopback), so we pull exactly those host ports.
# Format-agnostic PyYAML walk (a port dict with bind==0.0.0.0), grep fallback. An
# EMPTY result is VALID (default/offline/tailscale open nothing), so a SUCCESSFUL
# python parse is authoritative even when empty; only a parse error/absence falls back.
profile_lan_ports() {
  local prof="$1" pf="$SRC/manifests/profiles/${1}.yml" out=""
  [ -n "$prof" ] && [ -f "$pf" ] || return 0
  if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1; then
    if out=$(python3 - "$pf" 2>/dev/null <<'PY'
import sys
try:
    import yaml
except Exception:
    sys.exit(3)
ports = set()
def add(h):
    if isinstance(h, bool):
        return
    if isinstance(h, int):
        ports.add(h)
    elif isinstance(h, str) and h.strip().isdigit():
        ports.add(int(h.strip()))
def walk(n):
    if isinstance(n, dict):
        if 'host' in n and str(n.get('bind')) == '0.0.0.0':
            add(n['host'])
        for v in n.values():
            walk(v)
    elif isinstance(n, list):
        for v in n:
            walk(v)
try:
    with open(sys.argv[1]) as fh:
        walk(yaml.safe_load(fh))
except Exception:
    sys.exit(3)
for p in sorted(ports):
    print(p)
PY
    ); then
      printf '%s\n' "$out" | grep -v '^[[:space:]]*$' || true
      return
    fi
  fi
  # FALLBACK: flow-style grep.
  grep -E '\{[[:space:]]*host:.*bind:[[:space:]]*0\.0\.0\.0' "$pf" \
    | grep -oE 'host:[[:space:]]*[0-9]+' | grep -oE '[0-9]+' | sort -un
}

# effective_pack_flags(): echo "<install_llm> <install_elastic_services> <offline_mode>"
# (each 0/1) EXACTLY as do_health derives them from FLAGS, AFTER the --offline
# adjustment (offline forces elastic off, and llm off unless --llm). This is the same
# roster install.sh renders, so a manifest enable-filter keyed on these three matches
# the real deploy. Used by the VIP-probe stage (do_health computes them inline).
effective_pack_flags() {
  local llm_on=1 elastic_on=0 offline_on=0
  case " $FLAGS " in *" --no-llm "*) llm_on=0;; esac
  case " $FLAGS " in *" --elastic-services "*) elastic_on=1;; esac
  case " $FLAGS " in *" --offline "*|*" -o "*) offline_on=1;; esac
  if [ "$offline_on" = 1 ]; then
    elastic_on=0
    case " $FLAGS " in *" --llm "*) : ;; *) llm_on=0;; esac
  fi
  printf '%s %s %s\n' "$llm_on" "$elastic_on" "$offline_on"
}

# derive_tailnet_ingress_ports(): the ENABLED host ports the tailscale ingress leg
# (ansible/roles/podman/tasks/tailscale_ingress.yml) fronts THIS run -- each service's
# `tailnet_ingress:`-marked publish_ports entry, but ONLY when that service is enabled
# under the effective pack flags, mirroring the leg's own `enabled_when |
# is_enabled(lme_enable_flags)` gate. This REPLACES the literal `8200 4000 5044`.
# Emits unique host port NUMBERS, one per line (mode-agnostic: the exposure allowance
# is port-based). FAIL-CLOSED, deliberately with NO grep fallback (this runs
# CONTROLLER-side where python3+PyYAML is present, and a security allow-set must never
# be built from a degraded parse): a missing manifests tree, a parse error, an unknown
# enabled_when flag, or a malformed `tailnet_ingress` value (not https/raw-tcp) all
# return non-zero so the caller refuses to run a blind exposure gate rather than
# silently pass an empty allow-set. An EMPTY result from a SUCCESSFUL parse is
# LEGITIMATE (e.g. --tailscale --no-llm fronts nothing) and returns 0.
# Args: <install_llm 0|1> <install_elastic_services 0|1> <offline_mode 0|1>
derive_tailnet_ingress_ports() {
  local root="$SRC/manifests"
  [ -d "$root/services" ] || return 1
  command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1 || return 1
  python3 - "$root/services" "$1" "$2" "$3" <<'PY'
import glob, os, sys
try:
    import yaml
except Exception:
    sys.exit(3)
svc_dir = sys.argv[1]
flags = {'install_llm': sys.argv[2] == '1',
         'install_elastic_services': sys.argv[3] == '1',
         'offline_mode': sys.argv[4] == '1'}
KNOWN = {'install_llm', 'install_elastic_services', 'offline_mode'}
VALID_MODES = {'https', 'raw-tcp'}
def is_enabled(ew):
    # Mirror filter_plugins/lme_manifests.py:is_enabled -- AND over flags, 'always'
    # is a no-op, an unknown token is a typo -> fail closed (non-zero) rather than
    # silently evaluate False.
    if not ew:
        return True
    for f in ew:
        if f != 'always' and f not in KNOWN:
            sys.exit(4)
    for f in ew:
        if f == 'always':
            continue
        if not flags.get(f, False):
            return False
    return True
ports = set()
for path in sorted(glob.glob(os.path.join(svc_dir, "*.yml"))):
    try:
        with open(path) as fh:
            doc = yaml.safe_load(fh)
    except Exception:
        sys.exit(3)   # malformed manifest -> fail closed
    if not isinstance(doc, dict):
        continue
    marked = []
    for p in doc.get("publish_ports") or []:
        if not isinstance(p, dict) or p.get("tailnet_ingress") is None:
            continue
        if p.get("tailnet_ingress") not in VALID_MODES:
            sys.exit(5)   # malformed marker value -> fail closed
        try:
            marked.append(int(str(p.get("host")).strip()))
        except Exception:
            sys.exit(5)
    if not marked:
        continue
    if not is_enabled(doc.get("enabled_when") or ['always']):
        continue
    ports.update(marked)
for p in sorted(ports):
    print(p)
PY
}

# derive_vip_endpoints(): one consumer-probe endpoint per ENABLED opt-in VIP service,
# mirroring the VIP publisher (tailscale_service.yml). A service opts in with a
# top-level `tailnet_service:` key; among its loopback (bind 127.0.0.1), non-UDP
# publish_ports the fronted entry is the `tailnet_serve: true`-marked one, else the
# LOWEST host port (subagent A's _ts_pick); port = that entry's host, scheme = its
# `serve` key (default https). Enable-filtered by the effective pack flags so a
# disabled VIP is not probed (a false-fail). Emits `<tailnet_service>:<port>:<scheme>`
# per line. FAIL-CLOSED (non-zero) on a missing tree / parse error / unknown
# enabled_when flag; an empty result from a clean parse is valid (no opted-in VIPs).
# Args: <install_llm 0|1> <install_elastic_services 0|1> <offline_mode 0|1>
derive_vip_endpoints() {
  local root="$SRC/manifests"
  [ -d "$root/services" ] || return 1
  command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1 || return 1
  python3 - "$root/services" "$1" "$2" "$3" <<'PY'
import glob, os, sys
try:
    import yaml
except Exception:
    sys.exit(3)
svc_dir = sys.argv[1]
flags = {'install_llm': sys.argv[2] == '1',
         'install_elastic_services': sys.argv[3] == '1',
         'offline_mode': sys.argv[4] == '1'}
KNOWN = {'install_llm', 'install_elastic_services', 'offline_mode'}
def is_enabled(ew):
    if not ew:
        return True
    for f in ew:
        if f != 'always' and f not in KNOWN:
            sys.exit(4)
    for f in ew:
        if f == 'always':
            continue
        if not flags.get(f, False):
            return False
    return True
def hostnum(p):
    try:
        return int(str(p.get("host")).strip())
    except Exception:
        return None
out = []
for path in sorted(glob.glob(os.path.join(svc_dir, "*.yml"))):
    try:
        with open(path) as fh:
            doc = yaml.safe_load(fh)
    except Exception:
        sys.exit(3)
    if not isinstance(doc, dict):
        continue
    name = doc.get("tailnet_service")
    if not name:
        continue
    if not is_enabled(doc.get("enabled_when") or ['always']):
        continue
    loop = [p for p in (doc.get("publish_ports") or [])
            if isinstance(p, dict) and p.get("bind") == "127.0.0.1"
            and p.get("protocol") != "udp" and hostnum(p) is not None]
    if not loop:
        continue
    marked = [p for p in loop if p.get("tailnet_serve")]
    pick = marked[0] if marked else sorted(loop, key=hostnum)[0]
    scheme = pick.get("serve") or "https"
    out.append("%s:%s:%s" % (str(name), hostnum(pick), str(scheme)))
for line in out:
    print(line)
PY
}

# derive_host_scoped_min(): the GAP-3 host-scoped container floor -- the number of
# LONG-RUNNING podman containers THIS host SHOULD run, derived PURELY from DECLARED
# INTENT (manifest kinds ∧ effective pack flags ∧ the host's `lme_host_services`
# roster), NEVER by counting rendered `.container` units or `podman ps` on the target.
# That anti-tautology is the whole point: if the floor were "whatever the renderer
# produced", a SHORT render -- exactly the GAP-3 render-miss bug class -- would become
# invisible and the gate self-confirming. Here the gate encodes what the host SHOULD
# have INDEPENDENTLY, so a render that drops a scoped-in unit FAILS the floor check.
# Mirrors the ansible render decision EXACTLY -- a service is a counted container iff:
#     kind == container                 (targets/networks/volumes/path_services are not
#                                        `podman ps` containers -- e.g. trixie's `lme`
#                                        target + `network` count 0, matching do_health)
#     AND is_enabled(enabled_when, flags)   (the SAME is_enabled the renderer applies)
#     AND behavior.type != oneshot       (setup-certs/setup-accts run then EXIT -> never
#                                        in `podman ps`; the remote counts RUNNING only)
#     AND (no ConditionPathExists=/opt/lme/OFFLINE_MODE OR offline_mode on)
#                                        (fleet-distribution starts ONLY offline: the +1)
#     AND (roster empty/undefined OR id in roster)          (GAP-3 host scoping)
# Roster source = the SAME ansible/inventory/host_vars/<host>.yml the renderer reads.
# CONTRACT (must stay in lockstep with the Jinja host-scope clause + is_enabled):
#   * host_vars ABSENT, or present with NO `lme_host_services`, or `[]`
#       -> print NOTHING, exit 0  => caller keeps the full-host pack floor. GAP-3
#          HAZARD-1 empty-safe: undefined/[] == full stack, byte-identical to pre-GAP-3.
#   * a NON-EMPTY roster -> print the scoped integer (may be 0), exit 0.
#   * host_vars UNPARSABLE, roster MALFORMED (not a string list), a roster id naming NO
#     manifest service (GAP-3 4e typo class -- a scoped-out id silently lowers the floor
#     to match a short render), an unknown enabled_when flag, or a broken/absent
#     manifest tree -> exit NON-ZERO (fail CLOSED): the caller refuses a blind floor.
# Args: <host_vars_path> <install_llm 0|1> <install_elastic_services 0|1> <offline_mode 0|1>
derive_host_scoped_min() {
  local hv="$1" root="$SRC/manifests"
  [ -d "$root/services" ] || return 1
  # No-python graceful degrade (mirrors derive_published_ports' fallback philosophy in
  # this file): if this host_vars declares NO `lme_host_services` key at all, there is no
  # roster to resolve -> print nothing, succeed -> the caller keeps the full-host floor
  # WITHOUT touching python3, so a controller lacking python3 stays byte-identical on
  # every un-rostered host (incl. the es*.yml cluster-sizing files). Only a host that
  # ACTUALLY declares a roster falls through to the python parse -- and fails CLOSED
  # there if python is absent, since a scoped floor cannot be honestly derived without
  # it. The grep tests KEY PRESENCE only: comment lines (`# lme_host_services ...`) start
  # with `#` so the anchored regex skips them, and the python pass owns the value
  # decision -- a rare false-positive here costs only one harmless python re-check (which
  # then finds no roster), never a wrong floor.
  if ! grep -qE '^[[:space:]]*lme_host_services[[:space:]]*:' "$hv" 2>/dev/null; then
    return 0
  fi
  command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1 || return 1
  python3 - "$hv" "$root/services" "$2" "$3" "$4" <<'PY'
import glob, os, sys
try:
    import yaml
except Exception:
    sys.exit(3)
hv_path, svc_dir = sys.argv[1], sys.argv[2]
flags = {'install_llm': sys.argv[3] == '1',
         'install_elastic_services': sys.argv[4] == '1',
         'offline_mode': sys.argv[5] == '1'}
KNOWN = {'install_llm', 'install_elastic_services', 'offline_mode'}
# --- roster from host_vars (the SAME declaration the ansible renderer reads) --------
try:
    with open(hv_path) as fh:
        hv = yaml.safe_load(fh)
except Exception:
    sys.exit(3)                     # host_vars exists but unparsable -> fail closed
if hv is None:
    hv = {}
if not isinstance(hv, dict):
    sys.exit(3)
roster = hv.get('lme_host_services', None)
if roster is None or roster == []:
    sys.exit(0)                     # undefined/empty -> print nothing -> full-host floor
if not isinstance(roster, list) or not all(isinstance(x, str) for x in roster):
    sys.exit(5)                     # malformed roster -> fail closed
def is_enabled(ew):
    # Mirror filter_plugins/lme_manifests.py:is_enabled -- AND over flags; 'always' is a
    # no-op; an unknown token is a typo -> fail closed (never silently evaluate False).
    # Validate the WHOLE list before evaluating so an earlier unmet gate cannot mask a
    # later typo (identical two-pass shape to this file's other is_enabled mirrors).
    if not ew:
        return True
    for f in ew:
        if f != 'always' and f not in KNOWN:
            sys.exit(4)
    for f in ew:
        if f == 'always':
            continue
        if not flags.get(f, False):
            return False
    return True
services = {}
for path in sorted(glob.glob(os.path.join(svc_dir, "*.yml"))):
    try:
        with open(path) as fh:
            doc = yaml.safe_load(fh)
    except Exception:
        sys.exit(3)                 # malformed manifest -> fail closed
    if isinstance(doc, dict) and doc.get('id') is not None:
        services[str(doc['id'])] = doc
# GAP-3 4e typo class: every roster id MUST name a real manifest service (ANY kind, so
# infra ids like `lme`/`network` are valid), else a typo'd/absent id would silently
# lower the floor to match a short render. Fail closed -- do not certify off a guess.
unknown = [r for r in roster if r not in services]
if unknown:
    sys.exit(6)
roster_set = set(roster)
count = 0
for sid, doc in services.items():
    if doc.get('kind') != 'container':
        continue
    if not is_enabled(doc.get('enabled_when') or ['always']):
        continue
    if (doc.get('behavior') or {}).get('type') == 'oneshot':
        continue
    cpe = (doc.get('dependencies') or {}).get('condition_path_exists') or []
    if any('/opt/lme/OFFLINE_MODE' in str(x) for x in cpe) and not flags['offline_mode']:
        continue
    if sid not in roster_set:
        continue
    count += 1
print(count)
PY
}

# derive_host_runtime_rosters(): emit the exact expected runtime roster as
# `<class>\t<owner>\t<name>`. Persistent containers and completed initialization
# jobs are deliberately separate: a successful oneshot is never counted as a
# running container, while an unrelated running container cannot satisfy a
# missing expected service. `runtime_owner` is optional for legacy manifests and
# defaults to root; the lab resolved inventory supplies explicit owners for the
# new multi-owner topology and verifies them through the telemetry stage.
derive_host_runtime_rosters() {
  local hv="$1" root="$SRC/manifests"
  [ -d "$root/services" ] || return 1
  command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1 || return 1
  python3 - "$hv" "$root/services" "$2" "$3" "$4" <<'PY'
import glob, os, re, sys
import yaml

hv_path, svc_dir = sys.argv[1], sys.argv[2]
flags = {
    "install_llm": sys.argv[3] == "1",
    "install_elastic_services": sys.argv[4] == "1",
    "offline_mode": sys.argv[5] == "1",
}
known = set(flags)

try:
    with open(hv_path) as fh:
        host_vars = yaml.safe_load(fh) or {}
except FileNotFoundError:
    host_vars = {}
except Exception:
    sys.exit(3)
if not isinstance(host_vars, dict):
    sys.exit(3)
roster = host_vars.get("lme_host_services")
if roster in (None, []):
    roster = None
elif not isinstance(roster, list) or not all(isinstance(item, str) for item in roster):
    sys.exit(4)

def enabled(tokens):
    tokens = tokens or ["always"]
    if not isinstance(tokens, list) or any(not isinstance(token, str) for token in tokens):
        sys.exit(5)
    if any(token != "always" and token not in known for token in tokens):
        sys.exit(5)
    return all(token == "always" or flags[token] for token in tokens)

services = {}
for path in sorted(glob.glob(os.path.join(svc_dir, "*.yml"))):
    try:
        with open(path) as fh:
            doc = yaml.safe_load(fh)
    except Exception:
        sys.exit(3)
    if isinstance(doc, dict) and doc.get("id") is not None:
        services[str(doc["id"])] = doc
if roster is not None and any(item not in services for item in roster):
    sys.exit(6)

persistent, init_jobs = [], []
for sid, doc in services.items():
    if doc.get("kind") != "container" or not enabled(doc.get("enabled_when")):
        continue
    if roster is not None and sid not in roster:
        continue
    conditions = (doc.get("dependencies") or {}).get("condition_path_exists") or []
    if any("/opt/lme/OFFLINE_MODE" in str(item) for item in conditions) and not flags["offline_mode"]:
        continue
    owner = str(doc.get("runtime_owner") or "root")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]*", owner):
        sys.exit(7)
    name = str(doc.get("container_name") or doc.get("name") or "")
    if not name or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        sys.exit(7)
    if (doc.get("behavior") or {}).get("type") == "oneshot":
        init_jobs.append((owner, str(doc.get("name") or name) + ".service"))
    else:
        persistent.append((owner, name))

for owner, name in sorted(persistent):
    print("persistent\t%s\t%s" % (owner, name))
for owner, name in sorted(init_jobs):
    print("init\t%s\t%s" % (owner, name))
PY
}

# resolve_expect_min(): the expected running-container floor for THIS leg. Precedence:
#   1. LME_GATE_MIN_CONTAINERS  operator override (wins outright, unchanged).
#   2. host-scoped floor        when this host's host_vars declares lme_host_services
#                               (GAP-3): re-derived from declared intent, not the render.
#   3. full-host pack floor     otherwise -- the PRE-GAP-3 arithmetic kept VERBATIM, so
#                               every host without a roster (all of them today) is
#                               byte-identical. Long-running containers only (setup/
#                               oneshot units and volumes excluded):
#     core    = elasticsearch,kibana,fleet-server,wazuh-manager,elastalert2   (5)
#               + fleet-distribution, which starts ONLY in offline mode (its
#               ConditionPathExists=/opt/lme/OFFLINE_MODE) -> +1 IFF offline.
#     llm     = litellm,dashboard,log-analyzer,embeddings,llama-cpp,pgvector   (6)
#     elastic = apm-server,filebeat,logstash,metricbeat,heartbeat             (5)
#   Observed full-host: online+llm 5+6=11, online+elastic 5+5=10, offline core 6. The
#   host-scoped re-derivation (2) counts these SAME container-kind services filtered by
#   the roster, so a FULL roster reproduces the pack arithmetic exactly and a scoped
#   host (trixie roster -> log-analyzer+dashboard = 2) drops to its declared count.
# Echoes the integer on stdout (nothing else -- keep it log-free so callers can capture
# it); returns NON-ZERO (caller must FAIL) only when a DECLARED roster cannot be
# resolved. Args: <llm_on> <elastic_on> <offline_on>. Reads HOST and SRC from env.
resolve_expect_min() {
  local llm_on="$1" elastic_on="$2" offline_on="$3"
  if [ -n "${LME_GATE_MIN_CONTAINERS:-}" ]; then
    printf '%s\n' "$LME_GATE_MIN_CONTAINERS"; return 0
  fi
  local core_floor=5
  [ "$offline_on" = 1 ] && core_floor=6            # fleet-distribution: offline-only
  local full_floor
  if [ "$llm_on" = 1 ]; then full_floor=$((core_floor + 6))   # + llm pack
  else full_floor="$core_floor"; fi
  [ "$elastic_on" = 1 ] && full_floor=$((full_floor + 5))     # + elastic pack
  # GAP-3 host scoping: a host whose host_vars declares `lme_host_services` renders only
  # that subset, so the full floor FALSE-FAILS it. Re-derive from DECLARED INTENT; the
  # roster comes from the SAME host_vars file the renderer reads. Empty-safe (no file /
  # no roster / [] -> full floor) and fail-CLOSED (a declared-but-unresolvable roster ->
  # non-zero -> the caller refuses a blind floor). Short host name so an FQDN --host
  # (graph.tail...ts.net) still finds host_vars/graph.yml (mirrors the self-curl guard).
  local host_short="${HOST%%.*}"
  local hv="$SRC/ansible/inventory/host_vars/${host_short}.yml"
  if [ -f "$hv" ]; then
    local scoped
    if scoped="$(derive_host_scoped_min "$hv" "$llm_on" "$elastic_on" "$offline_on")"; then
      # non-empty stdout = a roster is declared (scoped integer, possibly 0);
      # empty stdout = no/empty roster -> keep the full-host floor.
      if [ -n "$scoped" ]; then printf '%s\n' "$scoped"; else printf '%s\n' "$full_floor"; fi
      return 0
    fi
    return 1   # declared roster could not be resolved -> caller FAILS closed
  fi
  printf '%s\n' "$full_floor"; return 0
}

# host_runs_service(): does THIS host's GAP-3 roster actually run <service_id>?
# Echoes 1 (host-local -> probe it) or 0 (scoped OUT -> skip). Reads the SAME
# ansible/inventory/host_vars/<host>.yml `lme_host_services` roster resolve_expect_min
# reads, and mirrors the render-side backward-compat rule (filter_plugins
# lme_manifests.py:_requires_partition -- a FALSY host_services roster == NO scoping
# == full host).
#
# ASYMMETRY vs derive_host_scoped_min (which fails CLOSED on an unresolvable roster):
# here a missing/broken roster is the LEGITIMATE full-host default, so it must never
# turn a probe OFF. DEFAULT-LOCAL (print 1) on: no host_vars file, no
# `lme_host_services` key, roster undefined/[]/unparsable/malformed, or python3/PyYAML
# absent. Prints 0 ONLY when a well-formed, non-empty roster EXISTS and does NOT
# contain <service_id>. The caller additionally CLAMPS any non-0 output to 1, so 0 is
# the only value that can ever skip a probe (fail-SAFE: a broken read keeps the probe
# ON, never silently off). Args: <host_vars_path> <service_id>
host_runs_service() {
  local hv="$1" sid="$2"
  # No host_vars file for this host -> full host -> service is local.
  [ -f "$hv" ] || { printf '1\n'; return 0; }
  # No roster KEY declared (presence only; the anchored regex skips `# ...` comment
  # lines) -> full host. Mirrors derive_host_scoped_min's no-python graceful-degrade.
  if ! grep -qE '^[[:space:]]*lme_host_services[[:space:]]*:' "$hv" 2>/dev/null; then
    printf '1\n'; return 0
  fi
  # A roster key is present; resolve membership honestly. Without python we cannot
  # parse the list -> DEFAULT-LOCAL (never scope a probe out on a guess). NB a
  # python-less controller that ACTUALLY declares a roster has already failed CLOSED
  # in resolve_expect_min (derive_host_scoped_min returns non-zero), so do_health never
  # reaches here in that case; this stays a defensive full-host default regardless.
  if ! { command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1; }; then
    printf '1\n'; return 0
  fi
  python3 - "$hv" "$sid" <<'PY'
import sys
try:
    import yaml
    with open(sys.argv[1]) as fh:
        hv = yaml.safe_load(fh)
except Exception:
    print(1); sys.exit(0)          # unparsable / no PyYAML -> full-host default (asymmetry)
if not isinstance(hv, dict):
    print(1); sys.exit(0)
roster = hv.get('lme_host_services', None)
if roster is None or roster == []:
    print(1); sys.exit(0)          # undefined/empty -> full host (pre-GAP-3 identity)
if not isinstance(roster, list) or not all(isinstance(x, str) for x in roster):
    print(1); sys.exit(0)          # malformed roster -> default local (do not scope OUT on junk)
print(1 if sys.argv[2] in roster else 0)
PY
}

# Shared by both remote payloads. curl writes `000` for %{http_code} before
# returning a transport failure, so appending `echo 000` produces the false-pass
# token `000000`. Preserve curl's return code and normalize output exactly once.
remote_http_helper() {
  cat <<'REMOTE_HTTP_EOF'
gate_http_code() {
  local code rc
  code=$(curl -sk -o /dev/null -w '%{http_code}' "$@")
  rc=$?
  if [ "$rc" -ne 0 ] || ! [[ "$code" =~ ^[0-9]{3}$ ]]; then
    printf '000'
    [ "$rc" -ne 0 ] && return "$rc"
    return 1
  fi
  printf '%s' "$code"
}
REMOTE_HTTP_EOF
}

health_remote_payload() {
  remote_http_helper
  cat <<'REMOTE_EOF'
set -o pipefail
fail=0
loopback_ok() { case "$1" in 127.0.0.1|::1|'[::1]') return 0;; *) return 1;; esac; }
tailnet_ok() {
  local a="${1#"["}"; a="${a%"]"}"
  case "$a" in
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0;;
    fd7a:115c:a1e0:*) return 0;;
    *) return 1;;
  esac
}

echo "== lme.service =="
systemctl is-active lme.service || true

echo "== failed lme units (must be empty) =="
failed=$(systemctl list-units --plain --no-legend 'lme*' --state=failed 2>/dev/null | awk '{print $1}')
if [ -n "$failed" ]; then
  echo "  FAIL: lme units in failed state: $(echo "$failed")"; fail=1
else
  echo "  ok: no failed lme units"
fi

echo "== exact owned persistent container roster =="
expected=$(printf '%s\n' $EXPECTED_PERSISTENT | sed '/^$/d' | sort -u)
owners=$(printf '%s\n' $EXPECTED_PERSISTENT | sed '/^$/d;s/:.*//' | sort -u)
[ -n "$owners" ] || owners=root
actual=""
for owner in $owners; do
  if [ "$owner" = root ]; then
    if ! names=$(sudo -i podman ps --format '{{.Names}}' 2>/dev/null); then
      echo "  FAIL: cannot enumerate persistent containers for owner=root"; fail=1; continue
    fi
  else
    if ! names=$(runuser -u "$owner" -- podman ps --format '{{.Names}}' 2>/dev/null); then
      echo "  FAIL: cannot enumerate persistent containers for owner=$owner"; fail=1; continue
    fi
  fi
  while IFS= read -r name; do
    [ -z "$name" ] || actual="${actual}${owner}:${name}"$'\n'
  done <<<"$names"
done
actual=$(printf '%s' "$actual" | sed '/^$/d' | sort -u)
missing=$(comm -23 <(printf '%s\n' "$expected") <(printf '%s\n' "$actual"))
unexpected=$(comm -13 <(printf '%s\n' "$expected") <(printf '%s\n' "$actual"))
if [ -n "$missing" ] || [ -n "$unexpected" ]; then
  echo "  FAIL: persistent container roster mismatch"
  [ -z "$missing" ] || echo "  missing=$(printf '%s' "$missing" | xargs)"
  [ -z "$unexpected" ] || echo "  unexpected=$(printf '%s' "$unexpected" | xargs)"
  fail=1
else
  echo "  ok: exact persistent roster=[$(printf '%s' "$actual" | xargs)]"
fi

echo "== initialization jobs (separate from persistent roster) =="
for entry in $EXPECTED_INIT_JOBS; do
  owner="${entry%%:*}"; unit="${entry#*:}"
  if [ "$owner" = root ]; then
    state=$(systemctl show "$unit" -p ActiveState -p SubState -p Result 2>/dev/null)
    state_rc=$?
  else
    state=$(runuser -u "$owner" -- systemctl --user show "$unit" -p ActiveState -p SubState -p Result 2>/dev/null)
    state_rc=$?
  fi
  if [ "$state_rc" -ne 0 ] || ! grep -qx 'ActiveState=active' <<<"$state" || \
     ! grep -qx 'SubState=exited' <<<"$state" || ! grep -qx 'Result=success' <<<"$state"; then
    echo "  FAIL: init job $entry not completed successfully"; fail=1
  else
    echo "  ok: init job $entry active/exited result=success"
  fi
done

echo "== running containers (compatibility floor >= $EXPECT_MIN) =="
running=$(printf '%s\n' "$actual" | sed '/^$/d' | wc -l)
echo "  running=$running"
if [ "$running" -lt "$EXPECT_MIN" ]; then
  echo "  FAIL: only $running expected persistent container(s), floor is $EXPECT_MIN"; fail=1
else
  echo "  ok: $running >= $EXPECT_MIN"
fi

echo "== exposure: loopback-only binds ($LOOPBACK_PORTS) =="
if ! command -v ss >/dev/null 2>&1; then
  echo "  FAIL: ss unavailable — cannot assert exposure"; fail=1
else
  listen_tbl=$( { ss -ltnH 2>/dev/null | awk -v pr=tcp '{a=$4; p=a; sub(/:[0-9]+$/,"",a); sub(/.*:/,"",p); print p" "a" "pr}'
                  ss -lunH 2>/dev/null | awk -v pr=udp '{a=$4; p=a; sub(/:[0-9]+$/,"",a); sub(/.*:/,"",p); print p" "a" "pr}'; } )
  if [ -z "$listen_tbl" ]; then
    echo "  FAIL: no listening sockets parsed from ss — cannot assert exposure"; fail=1
  elif ! printf '%s\n' "$listen_tbl" | awk '$3=="tcp"{f=1} END{exit f?0:1}'; then
    echo "  FAIL: no TCP listeners parsed from ss (sshd:22 expected) — exposure probe broken, refusing green"; fail=1
  fi
  for p in $LOOPBACK_PORTS; do
    case " $LAN_OK " in *" $p "*) echo "  port $p: LAN opt-in (expose_lan) — skip"; continue;; esac
    case " ${PROFILE_OPEN:-} " in *" $p "*) echo "  port $p: LAN opt-in (profile ${PROFILE_NAME:-?}) — skip"; continue;; esac
    addrs=$(printf '%s\n' "$listen_tbl" | awk -v pp="$p" '$1==pp {print $2}')
    if [ -z "$addrs" ]; then
      echo "  port $p: not listening (service down or not in this profile)"
      continue
    fi
    tailnet_port=0
    case " $TAILNET_PORTS " in *" $p "*) tailnet_port=1;; esac
    bad=""
    for a in $addrs; do
      loopback_ok "$a" && continue
      [ "$tailnet_port" = 1 ] && tailnet_ok "$a" && continue
      bad="$bad $a"
    done
    if [ -n "$bad" ]; then
      echo "  FAIL: port $p LAN-open on$bad — expected 127.0.0.1 (bind-inversion/expose_lan?)"; fail=1
    elif [ "$tailnet_port" = 1 ]; then
      echo "  ok: port $p loopback/tailnet-ingress [$(echo "$addrs")]"
    else
      echo "  ok: port $p loopback-only [$(echo "$addrs")]"
    fi
  done
fi

if [ "$ES_LOCAL" = 1 ]; then
  echo "== service: ES :9200 (expect 401/200) =="
  if ! code=$(gate_http_code --max-time 20 https://127.0.0.1:9200); then :; fi
  echo "  ES http_code=$code"
  case "$code" in 401|200) echo "  ok";; *) echo "  FAIL: ES not up behind TLS"; fail=1;; esac
else
  echo "== service: ES :9200 — SKIP (not host-local; consumer reaches it via tailnet VIP) =="
fi

if [ "$KIBANA_LOCAL" = 1 ]; then
  echo "== service: Kibana :5601 (expect 200/302/401) =="
  if ! kb=$(gate_http_code --max-time 20 https://127.0.0.1:5601); then :; fi
  echo "  Kibana http_code=$kb"
  case "$kb" in 200|302|401) echo "  ok";; *) echo "  FAIL: Kibana not up"; fail=1;; esac
else
  echo "== service: Kibana :5601 — SKIP (not host-local; consumer reaches it via tailnet VIP) =="
fi

if [ "$LLM_ON" = 1 ]; then
  if [ "$DASHBOARD_LOCAL" = 1 ]; then
    echo "== service: dashboard /livez :8502 (expect 200; unauthenticated liveness) =="
    if ! dl=$(gate_http_code --max-time 20 https://127.0.0.1:8502/livez); then :; fi
    echo "  dashboard /livez http_code=$dl"
    case "$dl" in 200) echo "  ok";; *) echo "  FAIL: dashboard /livez not reachable on loopback"; fail=1;; esac

    echo "== auth: dashboard /api/health with NO key (expect 401/403) =="
    if ! da=$(gate_http_code --max-time 20 https://127.0.0.1:8502/api/health); then :; fi
    echo "  dashboard /api/health (unauth) http_code=$da"
    case "$da" in 401|403) echo "  ok: webui auth enforced";;
      *) echo "  FAIL: /api/* served unauthenticated ($da) — webui-auth not enforced"; fail=1;; esac
  else
    echo "== service: dashboard :8502 — SKIP (not host-local; scoped out of this roster) =="
  fi
  if [ "$LOG_ANALYZER_LOCAL" = 1 ]; then
    echo "== service: log-analyzer :8501 reachable (streamlit gates in-app at 200) =="
    if ! la=$(gate_http_code --max-time 20 https://127.0.0.1:8501); then :; fi
    echo "  log-analyzer http_code=$la"
    case "$la" in 200|302|401|403) echo "  ok";; *) echo "  FAIL: log-analyzer unreachable"; fail=1;; esac
  else
    echo "== service: log-analyzer :8501 — SKIP (not host-local; scoped out of this roster) =="
  fi
fi

echo "== HEALTH result: fail=$fail =="
exit "$fail"
REMOTE_EOF
}

# ---- stage: health probe ---------------------------------------------------
do_health() {
  assert_target_identity || return $?
  say "HEALTH probe (deep gate)"

  # ---- controller-side: derive the expected sets from the install flags ------
  # The LLM stack (group: llm in manifests/global.yml -> pgvector/llama-cpp/
  # litellm/log-analyzer/dashboard/embeddings) is present UNLESS --no-llm, or
  # --offline WITHOUT --llm (a supported `--offline --llm` install KEEPS it -- see
  # the offline_on block below). --elastic-services adds the apm/heartbeat/metric/
  # file/logstash pack. Guard the llm-only probes so the graph/trixie (default+llm)
  # and any reduced invocation both stay valid — same shape, different expected set.
  local llm_on=1
  case " $FLAGS " in *" --no-llm "*) llm_on=0;; esac
  local elastic_on=0
  case " $FLAGS " in *" --elastic-services "*) elastic_on=1;; esac
  # --offline (== -o, install.sh:114) forces the ELASTIC pack OFF UNCONDITIONALLY
  # (install.sh:695 -- no offline bundle for it) but forces the LLM pack off ONLY
  # WHEN --llm is absent: install.sh:682 (compute_effective_flags) keeps the LLM
  # stack ON for a supported `--offline --llm` install. Mirror both exactly so an
  # `--offline --llm` leg counts its 6 LLM containers in the floor AND runs the LLM
  # probes (LLM_ON is set from llm_on on the run_remote line below). Match -o too:
  # a MISSED offline detection would mis-size the floor by a pack (fail-unsafe).
  # Bare `--offline` (every banked airgapped leg) has no --llm, so both packs go
  # off exactly as before -- a byte-identical outcome, no airgapped-leg regression.
  local offline_on=0
  case " $FLAGS " in *" --offline "*|*" -o "*) offline_on=1;; esac
  if [ "$offline_on" = 1 ]; then
    elastic_on=0
    case " $FLAGS " in *" --llm "*) : ;; *) llm_on=0;; esac
  fi

  # Loopback-only set = DENY-BY-DEFAULT over the COMPLETE set of host-published
  # ports, DERIVED from the manifests (see derive_published_ports) rather than the
  # old fixed 9-port literal, which left wazuh 1514/1515/55000, udp syslog 514,
  # fleet-distribution 8080, apm 8200, logstash 5044/8085 and ES transport 9300
  # UNCHECKED. Every port here must bind loopback UNLESS opted open (LME_GATE_LAN_OK
  # or a named profile's bind:0.0.0.0). Ports for services not installed in this
  # profile simply won't be listening (=> reported "not listening", never a FAIL).
  # A missing/unparsable manifest => FAIL, never a blind green (matches the doctrine
  # "a check that can't run = FAIL").
  local loopback_ports
  loopback_ports="$(derive_published_ports | xargs)"   # newline list -> trimmed single-spaced
  if [ -z "$loopback_ports" ]; then
    say "HEALTH FATAL: could not derive host-published port set from $SRC/manifests -- refusing to run a blind exposure gate"
    return 1
  fi

  # Expected running-container floor. An operator override (LME_GATE_MIN_CONTAINERS)
  # wins; otherwise the floor is the full-host pack arithmetic UNLESS this host declares
  # a GAP-3 `lme_host_services` roster in its host_vars, in which case it is re-derived
  # from DECLARED INTENT scoped to that roster (see resolve_expect_min / the anti-
  # tautology contract on derive_host_scoped_min). A host_vars file that declares a
  # roster we cannot resolve => FAIL, never a blind green (same doctrine as the exposure
  # gate above -- "a check that can't run = FAIL").
  local expect_min
  if ! expect_min="$(resolve_expect_min "$llm_on" "$elastic_on" "$offline_on")"; then
    say "HEALTH FATAL: $SRC/ansible/inventory/host_vars/${HOST%%.*}.yml declares an lme_host_services roster that could not be resolved (unparsable host_vars, malformed/typo'd roster, unknown enabled_when flag, broken manifest, or the controller cannot parse manifests -- python3/PyYAML) -- refusing to run a blind container-floor gate"
    return 1
  fi
  # Accepted non-loopback binds come from two DISTINCT, separately-labelled rules:
  #   * expose_lan operator opt-in       -> LME_GATE_LAN_OK  (env, unchanged)
  #   * a NAMED profile's bind:0.0.0.0   -> profile_open      (derived; cluster->9300,
  #     multinode->8220/9200). Kept SEPARATE from lan_ok so the remote log states
  #     WHICH rule admitted each allowed port. Empty unless a profile is explicitly
  #     named, so single-node/default deploys are byte-identical to before here.
  local lan_ok="${LME_GATE_LAN_OK:-}"
  local profile; profile="$(explicit_profile)"
  local profile_open; profile_open="$(profile_lan_ports "$profile" | xargs)"

  # ---- narrow tailnet-ingress exposure allowance -----------------------------
  # `tailscale serve --https=<port>` (ansible/roles/podman/tasks/tailscale_ingress.yml)
  # makes tailscaled bind THIS node's own tailnet IP for each fronted port BY
  # DESIGN (Leg A saw litellm:4000 on 100.73.170.86 + fd7a:115c:a1e0::...). That
  # is a tailnet-only exposure, NOT a LAN opening — but legitimate ONLY for the
  # ports the ingress leg fronts and ONLY when that leg is enabled for THIS run.
  # We pass the remote payload an allow-list (tailnet_ports); it is EMPTY unless
  # ingress is on, so when off the exposure check is byte-identical to a plain
  # deploy and a real 0.0.0.0/LAN bind on any port still FAILS.
  #
  # The fronted set is DERIVED from the manifests (was the literal `8200 4000 5044`):
  # each service's `tailnet_ingress:`-marked port, ENABLED under this run's pack flags
  # -- exactly the set tailscale_ingress.yml fronts (marker + enabled_when). So apm
  # 8200 / logstash 5044 count only with --elastic-services and litellm 4000 only with
  # the LLM stack, matching the real ingress leg instead of a fixed literal. Empty
  # unless ingress is on, so when off the exposure check is byte-identical to a plain
  # deploy and a real 0.0.0.0/LAN bind on any port still FAILS.
  local tailnet_ports=""
  local tailnet_on=0
  # Enabled for this run when the ingress leg is turned on: --tailscale (install.sh
  # sets tailscale_serve_ingress=true), --profile tailscale (profile sets it), or
  # an explicit tailscale_serve_ingress=true in the forwarded install extra-vars.
  # Match the profile name exactly (space-anchored) — install.sh validates it
  # against a fixed enum, so a prefix like `tailscale-x` must NOT trip this.
  case " $FLAGS " in *" --tailscale "*) tailnet_on=1;; esac
  case " $FLAGS " in *" --profile tailscale "*|*" --profile=tailscale "*) tailnet_on=1;; esac
  case "$EXTRA_VARS" in
    *'"tailscale_serve_ingress":true'*|*'"tailscale_serve_ingress": true'*|*'tailscale_serve_ingress=true'*) tailnet_on=1;;
  esac
  # Resolve the allow-set. The explicit operator override (LME_GATE_TAILNET_OK) is a
  # FULL escape hatch: it wins and enables the allowance WITHOUT parsing manifests
  # (mirrors LME_GATE_LAN_OK). Otherwise, ONLY when the ingress leg is on, derive the
  # enabled marked set from the manifests and FAIL CLOSED on any parse/marker failure
  # -- an empty set from a CLEAN parse is legitimate (nothing fronted this roster) and
  # is honoured; a broken parse must never silently pass an empty allow-list.
  if [ -n "${LME_GATE_TAILNET_OK:-}" ]; then
    tailnet_on=1; tailnet_ports="$LME_GATE_TAILNET_OK"
  elif [ "$tailnet_on" = 1 ]; then
    if tailnet_ports="$(derive_tailnet_ingress_ports "$llm_on" "$elastic_on" "$offline_on")"; then
      tailnet_ports="$(printf '%s' "$tailnet_ports" | xargs)"   # newline list -> trimmed single-spaced
    else
      say "HEALTH FATAL: could not derive the tailnet-ingress fronted port set from $SRC/manifests -- refusing to run a blind exposure gate"
      return 1
    fi
  fi
  # An empty tailnet_ports (ingress off, or a clean parse that fronts nothing this
  # roster) => the remote per-port allow clause never matches (inert), so a real
  # 0.0.0.0/LAN bind on any port still FAILS.

  # ---- ES/Kibana loopback-probe locality (GAP-5 cross-host consumer) ----------
  # The ES :9200 and Kibana :5601 curls in the remote payload below probe loopback
  # UNCONDITIONALLY. On a cross-host CONSUMER whose GAP-3 `lme_host_services` roster
  # EXCLUDES those services (they run on the PRODUCER; this host reaches them over a
  # tailnet VIP) there is no local listener, so an unconditional probe FALSE-FAILS an
  # otherwise-healthy leg. Gate each probe on whether THIS host actually runs the
  # service, read from the SAME host_vars roster resolve_expect_min uses (short host
  # name so an FQDN --host still resolves host_vars/<short>.yml). DEFAULT-LOCAL: no
  # host_vars / no roster / empty / unparsable -> 1 -> the probe runs exactly as today,
  # so every un-rostered leg (qemu-some, graph, airgapped, es*) is byte-identical. The
  # clamp makes 0 the ONLY value that can skip a probe: any empty/garbled read collapses
  # to 1 (fail-SAFE -- a broken locality read keeps the probe ON, never silently off).
  local probe_hv="$SRC/ansible/inventory/host_vars/${HOST%%.*}.yml"
  local es_local kibana_local dashboard_local log_analyzer_local
  es_local="$(host_runs_service "$probe_hv" elasticsearch)"
  kibana_local="$(host_runs_service "$probe_hv" kibana)"
  # The LLM-gated dashboard/log-analyzer probes below are host-facing UIs that can
  # ALSO be scoped out on a cross-host consumer roster (e.g. a log-analyzer-only
  # trixie leg drops dashboard). Gate each on the SAME roster + clamp so a roster
  # that excludes it skips its probe; DEFAULT-LOCAL (no host_vars / no roster / etc)
  # -> 1 -> byte-identical on every full-host leg.
  dashboard_local="$(host_runs_service "$probe_hv" dashboard)"
  log_analyzer_local="$(host_runs_service "$probe_hv" log-analyzer)"
  case "$es_local"           in 0) ;; *) es_local=1;;           esac
  case "$kibana_local"       in 0) ;; *) kibana_local=1;;       esac
  case "$dashboard_local"    in 0) ;; *) dashboard_local=1;;    esac
  case "$log_analyzer_local" in 0) ;; *) log_analyzer_local=1;; esac

  local runtime_rosters expected_persistent expected_init_jobs
  if ! runtime_rosters="$(derive_host_runtime_rosters "$probe_hv" "$llm_on" "$elastic_on" "$offline_on")"; then
    say "HEALTH FATAL: could not derive exact owned persistent/init rosters from manifests"
    emit_gate_result runtime_health true true false BLOCKED none runtime_roster_unresolvable
    return 1
  fi
  expected_persistent=$(printf '%s\n' "$runtime_rosters" | awk -F '\t' '$1=="persistent" {print $2 ":" $3}' | xargs)
  expected_init_jobs=$(printf '%s\n' "$runtime_rosters" | awk -F '\t' '$1=="init" {print $2 ":" $3}' | xargs)

  say "HEALTH expects: persistent=[$expected_persistent] init=[$expected_init_jobs] compatibility_floor=$expect_min llm_on=$llm_on profile=[${profile:-none}] loopback=[$loopback_ports] lan_ok=[$lan_ok] profile_open=[$profile_open] tailnet_ports=[$tailnet_ports] es_local=$es_local kibana_local=$kibana_local dashboard_local=$dashboard_local log_analyzer_local=$log_analyzer_local"

  # Sourceable so unit tests execute this exact payload with mocked commands.
  local HEALTH_SH
  HEALTH_SH="$(health_remote_payload)"

  run_remote "EXPECT_MIN='$expect_min' EXPECTED_PERSISTENT='$expected_persistent' EXPECTED_INIT_JOBS='$expected_init_jobs' LLM_ON='$llm_on' ES_LOCAL='$es_local' KIBANA_LOCAL='$kibana_local' DASHBOARD_LOCAL='$dashboard_local' LOG_ANALYZER_LOCAL='$log_analyzer_local' LOOPBACK_PORTS='$loopback_ports' LAN_OK='$lan_ok' PROFILE_OPEN='$profile_open' PROFILE_NAME='${profile:-}' TAILNET_PORTS='$tailnet_ports' bash -s" <<<"$HEALTH_SH"
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    emit_gate_result runtime_health true true true PASS "$LOG" runtime_readiness_verified
  else
    emit_gate_result runtime_health true true true FAIL "$LOG" runtime_readiness_failed
  fi
  emit_gate_result collection false false false NOT_APPLICABLE none legacy_health_does_not_evaluate_collection
  say "HEALTH rc=$rc (runtime readiness only; collection/readback not evaluated)"; return "$rc"
}

# ---- stage: vip-probe (A1 consumer-node VIP reachability; post-health) --------
# The CapMap liveness assert in tailscale_service.yml proves a VIP was ALLOCATED and
# APPROVED, NOT that a consumer can actually REACH it end-to-end. This stage closes
# that A1 gap: it curls each manifest-declared VIP endpoint FROM A SECOND inventory
# host (never a self-curl on the advertiser -- a node's own VIP is expected-unreachable).
#
# Applicability is resolved independently from these two control inputs:
#   LME_GATE_PROBE_FROM=<host>          the SECOND (consumer) inventory host to probe
#                                       FROM -- a tailnet node that is NOT --host.
#   LME_GATE_REQUIRE_VIP_REACHABLE=1    ARM enforcement -- THIS env knob IS the arming
#                                       mechanism (controller-side, SSH-threaded; there
#                                       is no ansible var for it): an unreachable VIP
#                                       becomes a typed FAIL instead of a WARN.
#   (optional) LME_GATE_TAILNET_DOMAIN  MagicDNS suffix, e.g. tail6c2eb6.ts.net; default
#                                       bare (the svc name resolves via the search domain).
#   (optional) LME_GATE_VIP_TIMEOUT     per-endpoint curl/connect timeout (default 15s).
# States for a selected VIP route:
#   neither set        -> SKIPPED, executed:false (optional, non-blocking)
#   probe-from only    -> executes; unreachable is recorded FAIL but non-blocking
#   require only       -> BLOCKED: required check cannot execute without a consumer
#   both set           -> executes; unreachable is a blocking FAIL
# With no selected VIP route the check is NOT_APPLICABLE; requiring it is invalid.
# Single-shot per endpoint (NO until/retries -- an until keyed on liveness hard-fails
# on retry-exhaustion, round-11 B1). Composable: probes whatever the manifests declare.
#
# ACCEPTANCE RULE (routing-only; do NOT overclaim -- W-1). A green result here proves
# the tailnet ROUTE is live: the VIP name resolved, the tailnet path carried the
# connection, and the backend answered (a raw-tcp connect, or ANY http_code). It does
# NOT prove GAP-2 end-to-end TLS closure. TLS closure is a SEPARATE, independent signal,
# proven ONLY by the consumer application's verify-full connection (trusted chain plus
# endpoint identity). The curl below is `-sk` (insecure) BY DESIGN, so it says nothing about chain
# validation -- a green vip-probe MUST NEVER be cited as evidence of TLS/CA closure. This
# is also why this stage builds NO `openssl s_client -verify_hostname` probe: a hostname-
# verifying administrator-shell probe could still pass outside the application runtime
# namespace. Routing here and application verify-full are non-substitutable signals.
normalize_bool() {
  case "$1" in
    1|true|TRUE|yes|on) printf '1\n';;
    0|false|FALSE|no|off|'') printf '0\n';;
    *) return 2;;
  esac
}

extra_var_value() {
  local key="$1"
  [ -n "$EXTRA_VARS" ] || return 1
  python3 - "$key" "$EXTRA_VARS" <<'PY'
import json, re, sys
key, raw = sys.argv[1:]
try:
    if raw.lstrip().startswith("{"):
        value = json.loads(raw)
        if not isinstance(value, dict) or key not in value:
            sys.exit(1)
        value = value[key]
        if isinstance(value, bool):
            print("true" if value else "false")
        else:
            print(str(value))
        sys.exit(0)
except Exception:
    sys.exit(2)
match = re.search(r"(?:^|\s)" + re.escape(key) + r"=([^\s]+)", raw)
if not match:
    sys.exit(1)
print(match.group(1))
PY
}

# Applicability comes from the selected route contract, not from whether a probe
# host happened to be supplied. Operator extra-vars are last-winning, matching
# install.sh, and invalid boolean values fail instead of silently disabling a check.
vip_route_selected() {
  local selected=0 profile value
  profile="$(explicit_profile)"
  if [ -n "$profile" ] && [ -f "$SRC/manifests/profiles/${profile}.yml" ]; then
    value=$(python3 - "$SRC/manifests/profiles/${profile}.yml" <<'PY'
import sys, yaml
try:
    with open(sys.argv[1]) as fh:
        doc = yaml.safe_load(fh) or {}
    value = (((doc.get("profile_overlay") or {}).get("vars") or {})
             .get("tailscale_serve_services"))
except Exception:
    sys.exit(2)
if value is None:
    sys.exit(1)
if not isinstance(value, bool):
    sys.exit(2)
print("1" if value else "0")
PY
    )
    case $? in 0) selected="$value";; 1) :;; *) return 2;; esac
  fi
  case " $FLAGS " in *" --tailscale "*) selected=1;; esac
  if value=$(extra_var_value tailscale_serve_services); then
    selected=$(normalize_bool "$value") || return 2
  else
    case $? in 1) :;; *) return 2;; esac
  fi
  printf '%s\n' "$selected"
}

vip_probe_remote_payload() {
  remote_http_helper
  cat <<'REMOTE_EOF'
set -o pipefail
fail=0
dead=""
for ep in $VIP_ENDPOINTS; do
  name="${ep%%:*}"; rest="${ep#*:}"; port="${rest%%:*}"; scheme="${rest##*:}"
  fqdn="$name"; [ -n "$DOMAIN" ] && fqdn="${name}.${DOMAIN}"
  case "$scheme" in
    tcp|raw-tcp)
      if timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/${fqdn}/${port}" 2>/dev/null; then
        echo "  ok: svc:$name $fqdn:$port (raw-tcp connect)"
      else
        echo "  UNREACHABLE: svc:$name $fqdn:$port (raw-tcp connect failed)"; dead="$dead svc:$name"
      fi
      ;;
    https)
      if ! code=$(gate_http_code --max-time "$TIMEOUT" "https://${fqdn}:${port}/" 2>/dev/null); then :; fi
      case "$code" in
        000) echo "  UNREACHABLE: svc:$name https://$fqdn:$port/ (no response -- DNS/route/TLS)"; dead="$dead svc:$name";;
        *) echo "  ok: svc:$name https://$fqdn:$port/ -> HTTP $code (VIP routes; backend answered)";;
      esac
      ;;
    *)
      echo "  INVALID: svc:$name unsupported scheme=$scheme"; dead="$dead svc:$name"
      ;;
  esac
done
if [ -n "$dead" ]; then
  echo "== VIP-PROBE: unreachable/invalid ->$dead =="
  exit 1
fi
echo "== VIP-PROBE: all derived VIP endpoints reachable =="
exit 0
REMOTE_EOF
}

validate_vip_endpoints() {
  local endpoints="$1" ep name port scheme extra seen=" "
  while IFS= read -r ep; do
    [ -n "$ep" ] || continue
    IFS=: read -r name port scheme extra <<<"$ep"
    [ -z "${extra:-}" ] || return 1
    [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9-]*$ ]] || return 1
    [[ "$port" =~ ^[1-9][0-9]*$ ]] || return 1
    [ "$port" -le 65535 ] || return 1
    case "$scheme" in https|tcp|raw-tcp) ;; *) return 1;; esac
    case "$seen" in *" $ep "*) return 1;; esac
    seen="$seen$ep "
  done <<<"$endpoints"
}

do_vip_probe() {
  local required route_selected from="${LME_GATE_PROBE_FROM:-}"
  if ! required=$(normalize_bool "${LME_GATE_REQUIRE_VIP_REACHABLE:-0}"); then
    say "VIP-PROBE FAIL: LME_GATE_REQUIRE_VIP_REACHABLE must be a strict boolean"
    emit_gate_result vip_reachability true false false FAIL none invalid_required_boolean
    return 2
  fi
  if ! route_selected=$(vip_route_selected); then
    say "VIP-PROBE FAIL: selected route contract has an invalid tailscale_serve_services value"
    emit_gate_result vip_reachability "$([ "$required" = 1 ] && printf true || printf false)" false false FAIL none invalid_route_boolean
    return 2
  fi

  local required_json=false
  [ "$required" = 1 ] && required_json=true
  if [ "$route_selected" = 0 ]; then
    if [ "$required" = 1 ]; then
      say "VIP-PROBE FAIL: reachability is required but no VIP route is selected"
      emit_gate_result vip_reachability true false false BLOCKED none required_vip_route_not_selected
      return 1
    fi
    say "VIP-PROBE NOT_APPLICABLE: resolved route contract does not select VIP services"
    emit_gate_result vip_reachability false false false NOT_APPLICABLE none vip_route_not_selected
    return 0
  fi

  local llm_on elastic_on offline_on endpoints endpoints_line
  read -r llm_on elastic_on offline_on < <(effective_pack_flags)
  if ! endpoints="$(derive_vip_endpoints "$llm_on" "$elastic_on" "$offline_on")"; then
    say "VIP-PROBE FAIL: could not derive the selected VIP endpoint set"
    emit_gate_result vip_reachability "$required_json" true false BLOCKED none endpoint_derivation_failed
    return 1
  fi
  endpoints="$(printf '%s\n' "$endpoints" | sed '/^[[:space:]]*$/d')"
  if [ -z "$endpoints" ]; then
    say "VIP-PROBE FAIL: selected VIP route derived zero endpoints"
    emit_gate_result vip_reachability "$required_json" true false BLOCKED none selected_route_has_no_endpoints
    return 1
  fi
  if ! validate_vip_endpoints "$endpoints"; then
    say "VIP-PROBE FAIL: derived endpoint does not satisfy name:port:https|tcp|raw-tcp contract"
    emit_gate_result vip_reachability "$required_json" true false FAIL none invalid_endpoint_contract
    return 2
  fi
  if [ -z "$from" ]; then
    if [ "$required" = 1 ]; then
      say "VIP-PROBE FAIL: required selected route has no consumer probe host"
      emit_gate_result vip_reachability true true false BLOCKED none probe_from_required
      return 1
    fi
    say "VIP-PROBE SKIPPED: selected route is optional and LME_GATE_PROBE_FROM is unset"
    emit_gate_result vip_reachability false true false SKIPPED none optional_probe_disabled
    return 0
  fi
  if [ "${from%%.*}" = "${HOST%%.*}" ]; then
    say "VIP-PROBE FAIL: probe source is the advertiser; self-VIP curl is invalid"
    emit_gate_result vip_reachability "$required_json" true false FAIL none self_probe_forbidden
    return 1
  fi

  local timeout="${LME_GATE_VIP_TIMEOUT:-15}" domain="${LME_GATE_TAILNET_DOMAIN:-}"
  if ! [[ "$timeout" =~ ^[1-9][0-9]*$ ]]; then
    say "VIP-PROBE FAIL: LME_GATE_VIP_TIMEOUT must be a positive integer"
    emit_gate_result vip_reachability "$required_json" true false FAIL none invalid_timeout
    return 2
  fi
  if [ -n "$domain" ] && ! [[ "$domain" =~ ^[A-Za-z0-9.-]+$ ]]; then
    say "VIP-PROBE FAIL: LME_GATE_TAILNET_DOMAIN contains invalid characters"
    emit_gate_result vip_reachability "$required_json" true false FAIL none invalid_tailnet_domain
    return 2
  fi
  endpoints_line="$(printf '%s\n' "$endpoints" | xargs)"
  say "VIP-PROBE applicable=true required=$required endpoints=[$endpoints_line] from=$from"
  local probe_sh rc
  probe_sh="$(vip_probe_remote_payload)"
  # shellcheck disable=SC2029 # validated values intentionally populate the remote env.
  ssh "${SSH_OPTS[@]}" "root@${from}" \
    "VIP_ENDPOINTS='$endpoints_line' DOMAIN='$domain' TIMEOUT='$timeout' bash -s" \
    <<<"$probe_sh" 2>&1 | tee -a "$LOG"
  rc="${PIPESTATUS[0]}"
  if [ "$rc" -eq 0 ]; then
    emit_gate_result vip_reachability "$required_json" true true PASS "$LOG" endpoints_reachable
    return 0
  fi
  emit_gate_result vip_reachability "$required_json" true true FAIL "$LOG" endpoint_unreachable
  if [ "$required" = 1 ]; then return 1; fi
  say "VIP-PROBE WARN: optional executed probe failed; aggregate gate remains non-blocking"
  return 0
}

# Manifest-driven source-to-destination verification extension. The verifier is
# implemented by the lab runner and consumes its pre-deployment resolved inventory;
# deploy_gate only supplies the stable invocation and refuses to synthesize success
# when the module, result artifact, or required arguments are absent.
do_telemetry() {
  say "TELEMETRY FAIL: collection acceptance is not yet integrated with the canonical resolved configuration"
  emit_gate_result telemetry_collection true true false FAIL none collection_engine_not_integrated
  return 2
}

# ---- stage: teardown (final) ----------------------------------------------
do_teardown() {
  refuse_physical_silmaril_wipe || return $?
  assert_target_identity || return $?
  say "TEARDOWN (final) via tree's own scripts/wipe_lme.sh"
  run_remote "cd '$REMOTE_DIR' && bash scripts/wipe_lme.sh"
  local rc=$?
  say "TEARDOWN rc=$rc  (0 => host verified CLEAN)"; return "$rc"
}

# ---- driver ----------------------------------------------------------------
retain_failed_state() {
  local stage="$1" rc="$2"
  say "LEG FAIL at $stage rc=$rc; failed state retained for inspection; evidence=$LOG results=$RESULTS"
  emit_gate_result cleanup false true false SKIPPED "$LOG" failed_state_retained
  return "$rc"
}

preserve_evidence_before_cleanup() {
  say "EVIDENCE retained before cleanup: log=$LOG results=$RESULTS"
  emit_gate_result evidence_retention true true true PASS "$LOG" evidence_persisted_before_cleanup
}

run_stage() {
  local stage="$1" rc=0
  case "$stage" in
    rsync) do_rsync || { rc=$?; retain_failed_state rsync "$rc"; return $?; };;
    wipe)
      do_rsync || { rc=$?; retain_failed_state rsync "$rc"; return $?; }
      do_wipe || { rc=$?; retain_failed_state wipe "$rc"; return $?; }
      ;;
    install) do_install || { rc=$?; retain_failed_state install "$rc"; return $?; };;
    health)
      do_health || { rc=$?; retain_failed_state health "$rc"; return $?; }
      do_vip_probe || { rc=$?; retain_failed_state vip-probe "$rc"; return $?; }
      ;;
    vip-probe) do_vip_probe || { rc=$?; retain_failed_state vip-probe "$rc"; return $?; };;
    telemetry) do_telemetry || { rc=$?; retain_failed_state telemetry "$rc"; return $?; };;
    teardown) preserve_evidence_before_cleanup && do_teardown;;
    deploy)
      do_rsync || { rc=$?; retain_failed_state rsync "$rc"; return $?; }
      do_wipe || { rc=$?; retain_failed_state pre-wipe "$rc"; return $?; }
      do_install || { rc=$?; retain_failed_state install "$rc"; return $?; }
      do_health || { rc=$?; retain_failed_state health "$rc"; return $?; }
      do_vip_probe || { rc=$?; retain_failed_state vip-probe "$rc"; return $?; }
      say "DEPLOY+HEALTH OK — stack HELD up for inspection; collection/readback requires --stage telemetry"
      ;;
    all)
      do_rsync || { rc=$?; retain_failed_state rsync "$rc"; return $?; }
      do_wipe || { rc=$?; retain_failed_state pre-wipe "$rc"; return $?; }
      do_install || { rc=$?; retain_failed_state install "$rc"; return $?; }
      do_health || { rc=$?; retain_failed_state health "$rc"; return $?; }
      do_vip_probe || { rc=$?; retain_failed_state vip-probe "$rc"; return $?; }
      preserve_evidence_before_cleanup || return $?
      do_teardown || { rc=$?; retain_failed_state teardown "$rc"; return $?; }
      ;;
    *) echo "unknown --stage $stage" >&2; return 2;;
  esac
}

main() {
  set -uo pipefail
  parse_args "$@" || return $?
  init_gate_run || return $?
  say "=== LEG START stage=$STAGE host=${HOST:-none} label=$LABEL ==="
  run_stage "$STAGE"
  local rc=$?
  say "=== LEG END stage=$STAGE rc=$rc ==="
  return "$rc"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
  exit $?
fi
