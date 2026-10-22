set -u
EP="$(podman secret inspect elastic --showsecret 2>/dev/null | grep -oE '"SecretData":[^,]*' | cut -d'"' -f4)"
URL='https://127.0.0.1:5601/api/fleet/agents?page=1&perPage=20&kuery=status%3Aonline%20or%20(status%3Aerror%20or%20status%3Adegraded)%20or%20(status%3Aupdating%20or%20status%3Aunenrolling%20or%20status%3Aenrolling)%20or%20status%3Aoffline&showInactive=false&showUpgradeable=false&getStatusSummary=true&withMetrics=true'
curl -sk -u "elastic:${EP}" "$URL" -H 'kbn-xsrf: kibana' -H 'elastic-api-version: 2023-10-31' -H 'x-elastic-internal-origin: Kibana' --max-time 20 -o /tmp/kbss.json -w 'http=%{http_code}\n'
python3 - <<'PY'
import json
d=json.load(open('/tmp/kbss.json'))
print('total=',d.get('total'))
print('statusSummary=',d.get('statusSummary'))
print('CHECK-WOULD-PASS=', bool(d.get('total',0)>0 and (d.get('statusSummary') or {}).get('online',0)>0))
PY
rm -f /tmp/kbss.json
