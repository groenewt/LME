set -uo pipefail
source "$1/gate_funcs.sh"   # $1 = scratchpad dir holding the extracted shipped funcs
SRC="$2"                    # $2 = tree root (contains manifests/)
for combo in "--tailscale" "--tailscale --elastic-services" "--tailscale --no-llm" "--offline --llm" "--offline"; do
  FLAGS="$combo"
  ef=$(effective_pack_flags); read -r llm el off <<<"$ef"
  ing=$(derive_tailnet_ingress_ports "$llm" "$el" "$off"); irc=$?
  vip=$(derive_vip_endpoints "$llm" "$el" "$off"); vrc=$?
  printf 'FLAGS=[%s] effective[llm el off]=[%s]\n' "$combo" "$ef"
  printf '   C.2 ingress-allow ports = [%s]  (rc=%s)\n' "$(echo $ing | xargs)" "$irc"
  printf '   C.3 vip endpoints       = [%s]  (rc=%s)\n' "$(echo $vip | xargs)" "$vrc"
done
