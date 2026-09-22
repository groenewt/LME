set -u
ENVF=/root/LME-gate/config/lme-environment.env
echo "=== env file present? ==="; ls -la "$ENVF" 2>&1 | awk '{print $1,$5,$9}'
echo "=== elastic-ish var names (no values) ==="
grep -oiE '^[A-Za-z_]*elastic[A-Za-z_]*=|^[A-Za-z_]*password[A-Za-z_]*=' "$ENVF" 2>/dev/null | sort -u
# resolve elastic password
EP="$(grep -iE '^elastic_password=|^ELASTIC_PASSWORD=' "$ENVF" 2>/dev/null | head -1 | cut -d= -f2-)"
EP="${EP%\"}"; EP="${EP#\"}"; EP="${EP%\'}"; EP="${EP#\'}"
if [ -z "${EP:-}" ]; then
  for s in elastic elastic_password kibana_system; do
    v="$(podman secret inspect "$s" --showsecret 2>/dev/null | grep -oE '"SecretData":[^,]*' | cut -d'"' -f4)"
    [ -n "$v" ] && { EP="$v"; echo "cred from podman secret: $s"; break; }
  done
fi
echo "=== elastic cred length: ${#EP} ==="
echo "=== GET /api/fleet/agents (raw head) ==="
curl -sk -u "elastic:${EP}" "https://127.0.0.1:5601/api/fleet/agents?perPage=50&showInactive=true" -H "kbn-xsrf: true" --max-time 20 -o /tmp/kbfleet.json -w "http=%{http_code}\n" 2>&1
head -c 1200 /tmp/kbfleet.json 2>/dev/null; echo
echo "=== parsed summary ==="
python3 - <<'PY'
import json
try:
    d=json.load(open('/tmp/kbfleet.json'))
    items=d.get('items',d.get('list',[])) or []
    print('total=',d.get('total'),'returned=',len(items),'statusSummary=',d.get('statusSummary'))
    for a in items:
        print(' agent',str(a.get('id'))[:12],'status=',a.get('status'),'active=',a.get('active'),'last_checkin=',a.get('last_checkin'))
except Exception as e:
    print('parse-error:',e)
PY
rm -f /tmp/kbfleet.json 2>/dev/null
