AU="-sk -u $ES_USERNAME:$ES_PASSWORD"
for host in lme-kibana:5601 lme-kibana:443; do
  echo "== data views via $host =="
  curl $AU -H 'kbn-xsrf: true' "https://$host/api/data_views" -w '\nHTTP=%{http_code}\n' 2>&1 | tr ',' '\n' | grep -E '"title"|"name"|"id"|HTTP=|statusCode|error' | head -40
done
