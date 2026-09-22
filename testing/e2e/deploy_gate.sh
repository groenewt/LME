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
# Stages (--stage): all | rsync | wipe | install | health | vip-probe | deploy | teardown
#   wipe            = rsync + pre-install teardown+self-verify (cheapest smoke:
#                     validates transport + exec + a CLEAN host).
#   vip-probe       = A1 consumer-node VIP reachability (post-health; DEFAULT OFF --
#                     no-op unless LME_GATE_PROBE_FROM / LME_GATE_REQUIRE_VIP_REACHABLE
#                     are set; see do_vip_probe). Also runs after health in the
#                     health / deploy / all stages (a no-op there when unarmed).
#   deploy          = rsync -> wipe -> install -> health -> vip-probe, HOLD before teardown.
#   all             = rsync -> wipe -> install -> health -> vip-probe -> teardown (full leg).
# Override LOGDIR / SRC / REMOTE_DIR via the environment.
#
# --strict : make an install that RESCUED any task (PLAY RECAP rescued>0) FAIL
#            instead of only WARN.
#
# HEALTH is a REAL gate (see do_health). Its pass contract, all on the target:
#   * no `lme*` systemd unit in the `failed` state;
#   * >= EXPECT_MIN running containers (default 11 for default+llm; lowered to the
#     5-core floor for online --no-llm and to 6 for bare --offline, but `--offline --llm`
#     KEEPS the LLM pack (floor 12); raised for --elastic-services; override with env
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

# ---- stage: health probe ---------------------------------------------------
do_health() {
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

# ---- stage: vip-probe (A1 consumer-node VIP reachability; post-health; DEFAULT OFF) --
# The CapMap liveness assert in tailscale_service.yml proves a VIP was ALLOCATED and
# APPROVED, NOT that a consumer can actually REACH it end-to-end. This stage closes
# that A1 gap: it curls each manifest-declared VIP endpoint FROM A SECOND inventory
# host (never a self-curl on the advertiser -- a node's own VIP is expected-unreachable).
#
# TWO INDEPENDENT KNOBS (both unset by default => this stage is a NO-OP and every
# existing invocation is byte-identical -- no existing caller passes either):
#   LME_GATE_PROBE_FROM=<host>          the SECOND (consumer) inventory host to probe
#                                       FROM -- a tailnet node that is NOT --host.
#   LME_GATE_REQUIRE_VIP_REACHABLE=1    ARM enforcement (mirrors the ansible var
#                                       tailscale_require_vip_reachable): an unreachable
#                                       VIP becomes a typed FAIL instead of a WARN.
#   (optional) LME_GATE_TAILNET_DOMAIN  MagicDNS suffix, e.g. tail6c2eb6.ts.net; default
#                                       bare (the svc name resolves via the search domain).
#   (optional) LME_GATE_VIP_TIMEOUT     per-endpoint curl/connect timeout (default 15s).
# States (mirrors the ansible var choosing fail-vs-warn, not whether the check exists):
#   neither set        -> no-op, rc 0                        (existing runs unchanged)
#   probe-from only    -> probe runs; unreachable = WARN, rc 0
#   require only       -> typed FAIL: a required probe with no consumer node cannot run
#   both set           -> probe runs; unreachable = typed FAIL
# Single-shot per endpoint (NO until/retries -- an until keyed on liveness hard-fails
# on retry-exhaustion, round-11 B1). Composable: probes whatever the manifests declare.
do_vip_probe() {
  local armed=0 from="${LME_GATE_PROBE_FROM:-}"
  case "${LME_GATE_REQUIRE_VIP_REACHABLE:-0}" in 1|true|TRUE|yes|on) armed=1;; esac
  # DEFAULT OFF: neither knob set => nothing to do, existing runs byte-identical
  # (return BEFORE any say/network so the log is unchanged too).
  if [ "$armed" = 0 ] && [ -z "$from" ]; then return 0; fi

  say "VIP-PROBE (consumer-node reachability; armed=$armed from=[${from:-none}])"
  # Armed but no consumer node => a required check that cannot run. Gate doctrine: a
  # check that can't run = FAIL. Self-curl is forbidden (self-VIP expected-unreachable),
  # so it can never substitute for a real second node.
  if [ -z "$from" ]; then
    say "VIP-PROBE FAIL: LME_GATE_REQUIRE_VIP_REACHABLE armed but LME_GATE_PROBE_FROM unset -- no consumer node to probe FROM (a self-curl on the advertiser is not a valid substitute)"
    return 1
  fi
  # Never self-curl: the probe-from node must NOT be the advertiser. Compare SHORT
  # names so `graph` and `graph.tail6c2eb6.ts.net` are recognised as the same node.
  local from_short="${from%%.*}" host_short="${HOST%%.*}"
  if [ "$from_short" = "$host_short" ]; then
    say "VIP-PROBE FAIL: LME_GATE_PROBE_FROM ($from) is the advertiser ($HOST) -- a self-VIP curl is expected-unreachable and cannot verify reachability; name a DIFFERENT inventory host"
    return 1
  fi

  # Effective pack flags (post-offline adjustment) so a disabled VIP is not probed.
  local llm_on elastic_on offline_on
  read -r llm_on elastic_on offline_on < <(effective_pack_flags)
  local endpoints
  if ! endpoints="$(derive_vip_endpoints "$llm_on" "$elastic_on" "$offline_on")"; then
    say "VIP-PROBE FAIL: could not derive the VIP endpoint set from $SRC/manifests"
    return 1
  fi
  endpoints="$(printf '%s' "$endpoints" | grep -v '^[[:space:]]*$' || true)"
  if [ -z "$endpoints" ]; then
    say "VIP-PROBE WARN: no enabled VIP endpoints derived from manifests -- nothing to probe for this roster"
    return 0
  fi
  local domain="${LME_GATE_TAILNET_DOMAIN:-}"
  local timeout="${LME_GATE_VIP_TIMEOUT:-15}"
  local endpoints_line; endpoints_line="$(printf '%s' "$endpoints" | xargs)"
  say "VIP-PROBE endpoints (svc:port:scheme)=[$endpoints_line] from=$from domain=[${domain:-magicdns}] timeout=${timeout}s armed=$armed"

  # Remote payload: runs ON the consumer node ($from). Values injected as env on the
  # `bash -s` line (NOT interpolated). Quoted heredoc => independently bash -n-checkable.
  local PROBE_SH
  read -r -d '' PROBE_SH <<'REMOTE_EOF' || true
set -o pipefail
fail=0
dead=""
for ep in $VIP_ENDPOINTS; do
  name="${ep%%:*}"; rest="${ep#*:}"; port="${rest%%:*}"; scheme="${rest##*:}"
  fqdn="$name"; [ -n "$DOMAIN" ] && fqdn="${name}.${DOMAIN}"
  case "$scheme" in
    tcp|raw-tcp)
      # raw-TLS passthrough VIP: a bare TCP connect (no HTTP verdict possible). A
      # connect proves the VIP routes to the backend listener.
      if timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/${fqdn}/${port}" 2>/dev/null; then
        echo "  ok: svc:$name $fqdn:$port (raw-tcp connect)"
      else
        echo "  UNREACHABLE: svc:$name $fqdn:$port (raw-tcp connect failed)"; dead="$dead svc:$name"
      fi
      ;;
    *)
      # https VIP: ANY HTTP response (even 401/403/5xx) proves the VIP name resolved,
      # the tailnet route is live and the backend answered. 000 => no response
      # (NXDOMAIN / no route / TLS handshake failure) => unreachable.
      code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" "https://${fqdn}:${port}/" 2>/dev/null || echo 000)
      case "$code" in
        000) echo "  UNREACHABLE: svc:$name https://$fqdn:$port/ (no response -- DNS/route/TLS)"; dead="$dead svc:$name";;
        *)   echo "  ok: svc:$name https://$fqdn:$port/ -> HTTP $code (VIP routes; backend answered)";;
      esac
      ;;
  esac
done
if [ -n "$dead" ]; then
  echo "== VIP-PROBE: unreachable ->$dead =="
  exit 1
fi
echo "== VIP-PROBE: all derived VIP endpoints reachable =="
exit 0
REMOTE_EOF

  # Probe FROM the consumer node (never the advertiser). Same BatchMode /
  # tailnet-intercepted ssh transport as the rest of the harness.
  ssh "${SSH_OPTS[@]}" "root@${from}" \
    "VIP_ENDPOINTS='$endpoints_line' DOMAIN='$domain' TIMEOUT='$timeout' bash -s" <<<"$PROBE_SH" 2>&1 | tee -a "$LOG"
  local rc="${PIPESTATUS[0]}"
  if [ "$rc" = 0 ]; then
    say "VIP-PROBE rc=0 (all derived VIP endpoints reachable from $from)"; return 0
  fi
  if [ "$armed" = 1 ]; then
    say "VIP-PROBE FAIL rc=$rc: one or more VIPs unreachable from $from (enforcement armed)"; return 1
  fi
  say "VIP-PROBE WARN rc=$rc: one or more VIPs unreachable from $from (enforcement OFF -> non-fatal warning)"; return 0
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
  health)   do_health && do_vip_probe; rc=$?;;   # probe is a no-op unless armed => unarmed --stage health is byte-identical
  vip-probe) do_vip_probe; rc=$?;;
  teardown) do_teardown; rc=$?;;
  deploy)   # setup -> deploy -> health -> (opt) vip-probe, HOLD before teardown
    do_rsync    || { rc=$?; say "LEG FAIL at rsync";     exit $rc; }
    do_wipe     || { rc=$?; say "LEG FAIL at pre-wipe";  exit $rc; }
    do_install  || { rc=$?; say "LEG FAIL at install";   exit $rc; }
    do_health   || { rc=$?; say "LEG FAIL at health";    exit $rc; }
    do_vip_probe || { rc=$?; say "LEG FAIL at vip-probe"; exit $rc; }
    say "DEPLOY+HEALTH OK — stack HELD up for inspection (run --stage teardown to finish)"
    ;;
  all)
    do_rsync     || { rc=$?; say "LEG FAIL at rsync";     exit $rc; }
    do_wipe      || { rc=$?; say "LEG FAIL at pre-wipe";  exit $rc; }
    do_install   || { rc=$?; say "LEG FAIL at install";   do_teardown || true; exit $rc; }
    do_health    || { rc=$?; say "LEG FAIL at health";    do_teardown || true; exit $rc; }
    do_vip_probe || { rc=$?; say "LEG FAIL at vip-probe"; do_teardown || true; exit $rc; }
    do_teardown  || { rc=$?; say "LEG FAIL at teardown";  exit $rc; }
    ;;
  *) echo "unknown --stage $STAGE" >&2; exit 2;;
esac
say "=== LEG END stage=$STAGE rc=$rc ==="
exit "$rc"
