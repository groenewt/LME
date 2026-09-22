B="https://$ES_HOST:$ES_PORT"
AU="-sk -u $ES_USERNAME:$ES_PASSWORD"
IDX="lme-seal-test-r5x9"
echo "== 1. WRITE doc (refresh=true) =="
curl $AU -H 'Content-Type: application/json' -XPOST "$B/$IDX/_doc/seal1?refresh=true" -d '{"seal":"ingest-e2e","ts":"2026-09-18T00:00:00Z","note":"controlled roundtrip probe"}' -w '\nHTTP=%{http_code}\n'
echo "== 2. SEARCH readback =="
curl $AU -H 'Content-Type: application/json' -XGET "$B/$IDX/_search" -d '{"query":{"match":{"seal":"ingest-e2e"}}}' -w '\nHTTP=%{http_code}\n' | tr ',' '\n' | grep -E '"total"|"value"|"hits"|"seal"|"note"|"_id"' | head -20
echo "== 3. DELETE test index (cleanup) =="
curl $AU -XDELETE "$B/$IDX" -w '\nHTTP=%{http_code}\n'
echo "== 4. CONFIRM gone =="
curl $AU "$B/_cat/indices/$IDX" -w '\nHTTP=%{http_code}\n'
