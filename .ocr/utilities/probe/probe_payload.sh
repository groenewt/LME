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
