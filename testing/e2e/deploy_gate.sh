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
  # offline_resources/ holds the airgapped bundle (~21G, built ON the target by
  # scripts/prepare_offline.sh -- it needs network, so it CANNOT be rebuilt on an
  # airgapped box). The controller's source tree does NOT carry it, so without this
  # exclude `--delete` would wipe the on-target bundle and brick every subsequent
  # offline install. An --exclude also protects the target path from --delete, so
  # the bundle survives. Inert for networked targets (they have no such dir).
  rsync -e "ssh ${SSH_OPTS[*]}" -a --delete \
    --exclude='.git/' --exclude='scratchpad/' --exclude='_ocr_wt/' \
    --exclude='.ocr/' --exclude='.cursor/' --exclude='.opencode/' \
    --exclude='node_modules/' --exclude='__pycache__/' --exclude='*.pyc' \
    --exclude='*.qcow2' --exclude='*.iso' --exclude='*.img' \
    --exclude='offline_resources/' \
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

# explicit_profile(): the manifest profile IFF it was EXPLICITLY named for this run
# -- `--profile NAME` in the install flags, or an lme_profile forwarded verbatim
# through --extra-vars (JSON or k=v). Returns EMPTY otherwise. We deliberately do
# NOT infer a profile from the mode flags (--cluster/--offline) here: a profile's
# bind:0.0.0.0 entries widen the accepted-LAN set, so an inference that misfired
# would silently unlock a LAN allowance on the primary exposure evidence. An
# operator running cluster/multinode names the profile; default/offline/tailscale
# open nothing anyway, so the un-inferred path costs nothing.
explicit_profile() {
  local p=""
  case " $FLAGS " in
    *" --profile "*) p="${FLAGS##*--profile }"; p="${p%% *}";;
    *" --profile="*) p="${FLAGS##*--profile=}"; p="${p%% *}";;
  esac
  if [ -z "$p" ]; then
    p=$(printf '%s' "$EXTRA_VARS" \
        | grep -oE '"?lme_profile"?[[:space:]]*[=:][[:space:]]*"?[a-z]+' \
        | grep -oE '[a-z]+$' | head -1)
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
  case " $FLAGS " in *" --no-llm "*|*" --offline "*|*" -o "*) llm_on=0;; esac
  local elastic_on=0
  case " $FLAGS " in *" --elastic-services "*) elastic_on=1;; esac
  # --offline (== -o, install.sh:114) forces BOTH the llm and elastic packs OFF
  # (install.sh:276 llm, :695 elastic -- no offline bundle for either), so neither
  # pack's containers count toward the floor on an offline run even when the flags
  # are also present. Match -o too: here a MISSED offline detection would LOWER the
  # floor (fail-unsafe), unlike the llm_on match above where a miss raises it.
  local offline_on=0
  case " $FLAGS " in *" --offline "*|*" -o "*) offline_on=1;; esac
  [ "$offline_on" = 1 ] && { llm_on=0; elastic_on=0; }

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

  # Expected running-container floor, from the EFFECTIVE install flags. Long-running
  # containers only (setup/oneshot units and volumes excluded):
  #   core    = elasticsearch,kibana,fleet-server,wazuh-manager,elastalert2   (5)
  #             + fleet-distribution, which starts ONLY in offline mode
  #             (roles/fleet/tasks/main.yml:66 `when: offline_mode`) -- online
  #             agents pull the installer from Elastic direct -> +1 IFF offline.
  #   llm     = litellm,dashboard,log-analyzer,embeddings,llama-cpp,pgvector   (6)
  #   elastic = apm-server,filebeat,logstash,metricbeat,heartbeat             (5)
  # Observed: online+llm 5+6=11 (tailscale leg), online+elastic 5+5=10 (this leg's
  # 5-core roster observed directly), offline core 6 (airgapped leg). The online
  # core-only --no-llm floor (5) is DERIVED from that same 5-core roster, not
  # separately exercised. An operator override always wins.
  local expect_min
  if [ -n "${LME_GATE_MIN_CONTAINERS:-}" ]; then
    expect_min="$LME_GATE_MIN_CONTAINERS"
  else
    local core_floor=5
    [ "$offline_on" = 1 ] && core_floor=6            # fleet-distribution: offline-only
    if [ "$llm_on" = 1 ]; then expect_min=$((core_floor + 6))   # + llm pack
    else expect_min="$core_floor"; fi
    [ "$elastic_on" = 1 ] && expect_min=$((expect_min + 5))     # + elastic pack
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
  # Ports fronted by tailscale_ingress.yml: apm-server 8200, litellm 4000,
  # logstash-beats 5044 -- ALL THREE are in the checked set now that the loopback
  # set is the complete manifest-derived list (they were unchecked no-ops under the
  # old 9-port literal), so a tailnet-fronted bind on any of them is now actively
  # validated. Operator-overridable via env LME_GATE_TAILNET_OK (a port list), which
  # also turns the allowance on — an explicit escape hatch mirroring LME_GATE_LAN_OK.
  local tailnet_ports="8200 4000 5044"
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
  # Explicit operator override always wins and enables the allowance for its set.
  if [ -n "${LME_GATE_TAILNET_OK:-}" ]; then tailnet_on=1; tailnet_ports="$LME_GATE_TAILNET_OK"; fi
  # OFF => empty allow-list => the remote per-port clause never matches (inert).
  [ "$tailnet_on" = 1 ] || tailnet_ports=""

  say "HEALTH expects: containers>=$expect_min llm_on=$llm_on profile=[${profile:-none}] loopback=[$loopback_ports] lan_ok=[$lan_ok] profile_open=[$profile_open] tailnet_ports=[$tailnet_ports]"

  # ---- the remote payload ----------------------------------------------------
  # Quoted heredoc: single quotes are legal inside (unlike the old '...' arg
  # form) and the payload is independently `bash -n`-checkable. Values are
  # injected as env on the `bash -s` line, NOT interpolated here.
  local HEALTH_SH
  read -r -d '' HEALTH_SH <<'REMOTE_EOF' || true
set -o pipefail
fail=0
loopback_ok() { case "$1" in 127.0.0.1|::1|'[::1]') return 0;; *) return 1;; esac; }
# This node's OWN tailnet address: Tailscale CGNAT 100.64.0.0/10 (IPv4) or the
# global Tailscale ULA fd7a:115c:a1e0::/48 (IPv6). `ss` prints IPv6 bracketed and
# may zero-compress the 4th group (e.g. [fd7a:115c:a1e0::439:8d1a]); strip the
# brackets and prefix-match the fixed /48. A tailnet-fronted ingress port binds
# here BY DESIGN — accepted ONLY for the ports in $TAILNET_PORTS (see caller).
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
  # port<space>addr<space>proto per LISTENING socket, over BOTH tcp AND udp -- the
  # deny-by-default gate must see udp too (e.g. wazuh syslog 514, which the old
  # tcp-only probe was blind to). TWO single-proto calls (NOT one `ss -tuln`): with
  # a single proto the Local-Address column is $4 in both -- the exact parse that
  # produced the live 0.0.0.0 finding on graph -- so no new column assumption is
  # introduced (a dual-proto call shifts Local to $5, and a mis-parse would degrade
  # to a silent green, the very blindness we are closing). addr = local addr with
  # the port stripped: 0.0.0.0:9200->'9200 0.0.0.0 tcp', [::]:5601->'5601 [::] tcp',
  # *:5432->'5432 * tcp', udp 127.0.0.1:514->'514 127.0.0.1 udp'.
  listen_tbl=$( { ss -ltnH 2>/dev/null | awk -v pr=tcp '{a=$4; p=a; sub(/:[0-9]+$/,"",a); sub(/.*:/,"",p); print p" "a" "pr}'
                  ss -lunH 2>/dev/null | awk -v pr=udp '{a=$4; p=a; sub(/:[0-9]+$/,"",a); sub(/.*:/,"",p); print p" "a" "pr}'; } )
  # A live host always has listeners (sshd at minimum). Empty => the probe broke
  # (e.g. `ss` too old for -H), NOT a closed host: fail, don't pass green.
  if [ -z "$listen_tbl" ]; then
    echo "  FAIL: no listening sockets parsed from ss — cannot assert exposure"; fail=1
  # Complementary guard: a working probe on any live host ALWAYS sees >=1 tcp
  # listener (sshd:22). Zero tcp rows => the tcp leg of the probe silently broke
  # (only udp parsed); refuse to certify exposure off a half-blind table.
  elif ! printf '%s\n' "$listen_tbl" | awk '$3=="tcp"{f=1} END{exit f?0:1}'; then
    echo "  FAIL: no TCP listeners parsed from ss (sshd:22 expected) — exposure probe broken, refusing green"; fail=1
  fi
  for p in $LOOPBACK_PORTS; do
    # Two DISTINCT accepted-open rules, each self-identifying in the log so a
    # reviewer can tell WHICH rule admitted a non-loopback port: expose_lan operator
    # opt-in ($LAN_OK) vs a named profile's bind:0.0.0.0 ($PROFILE_OPEN).
    case " $LAN_OK " in *" $p "*) echo "  port $p: LAN opt-in (expose_lan) — skip"; continue;; esac
    case " ${PROFILE_OPEN:-} " in *" $p "*) echo "  port $p: LAN opt-in (profile ${PROFILE_NAME:-?}) — skip"; continue;; esac
    addrs=$(printf '%s\n' "$listen_tbl" | awk -v pp="$p" '$1==pp {print $2}')
    if [ -z "$addrs" ]; then
      echo "  port $p: not listening (service down or not in this profile)"
      continue
    fi
    # A bind on this node's tailnet IP is acceptable ONLY for a port the ingress
    # leg fronts this run ($TAILNET_PORTS; EMPTY when ingress is off => this clause
    # is inert and the check is byte-identical to a non-tailscale deploy).
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
      echo "  ok: port $p loopback/tailnet-ingress [$(echo $addrs)]"
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

  run_remote "EXPECT_MIN='$expect_min' LLM_ON='$llm_on' LOOPBACK_PORTS='$loopback_ports' LAN_OK='$lan_ok' PROFILE_OPEN='$profile_open' PROFILE_NAME='${profile:-}' TAILNET_PORTS='$tailnet_ports' bash -s" <<<"$HEALTH_SH"
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
