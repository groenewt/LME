set -uo pipefail
# minimal ambient vars the sourced functions expect (NO ssh is reached in the tested states)
HOST="graph"; LABEL="dryrun"; LOG="/tmp/claude-1000/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/scratchpad/probe_states.log"; SRC="/home/tristan/gitters/LME"; FLAGS="--tailscale"
SSH_OPTS=(-o BatchMode=yes)
# Trip-wire: if control flow EVER reaches ssh in these states, fail loudly instead of dialing out.
ssh() { echo "!!! ssh WAS CALLED (should never happen in tested states): ssh $*"; return 99; }
source "/tmp/claude-1000/-home-tristan-gitters-LME/08a6f002-699c-4922-94af-1272948a7440/scratchpad/allfuncs.sh"
run_one() { # $1=label $2=env-assignments
  ( eval "$2"; do_vip_probe; echo "   -> rc=$?" )
}
echo "STATE 1 (neither knob)      [DEFAULT OFF -- must be silent no-op, rc 0]:"
( unset LME_GATE_PROBE_FROM LME_GATE_REQUIRE_VIP_REACHABLE; do_vip_probe; echo "   -> rc=$? (any line above this = LEAK; expect none)" )
echo "STATE 3 (require, no from)   [typed FAIL, pre-ssh]:"
( unset LME_GATE_PROBE_FROM; export LME_GATE_REQUIRE_VIP_REACHABLE=1; do_vip_probe; echo "   -> rc=$?" )
echo "SELF-CURL guard (from==host) [FAIL, pre-ssh]:"
( export LME_GATE_PROBE_FROM="graph.tail6c2eb6.ts.net" LME_GATE_REQUIRE_VIP_REACHABLE=1; do_vip_probe; echo "   -> rc=$?" )
