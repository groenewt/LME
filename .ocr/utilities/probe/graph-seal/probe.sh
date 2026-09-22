B="https://$ES_HOST:$ES_PORT"
AU="-sk -u $ES_USERNAME:$ES_PASSWORD"
echo "== HEALTH =="
curl $AU "$B/_cluster/health?pretty" | grep -E "status|number_of_nodes|unassigned|active_primary|active_shards|initializing|relocating"
echo "== DATA STREAMS logs-* (names+generation) =="
curl $AU "$B/_data_stream/logs-*" | tr ',' '\n' | grep -E '"name"|"generation"|"status"|"template"' | head -60
echo "== CAT logs-* indices =="
curl $AU "$B/_cat/indices/logs-*?v&h=index,docs.count,store.size,health,status" | head -40
echo "== CAT all indices docs>0 (non-system) =="
curl $AU "$B/_cat/indices?v&h=index,docs.count,store.size&s=docs.count:desc" | head -25
echo "== template count =="
curl $AU "$B/_cat/templates?h=name" | wc -l
echo "== ILM policies present =="
curl $AU "$B/_ilm/policy" | tr ',' '\n' | grep -c policy
