#!/bin/bash
fail=0
loopback_ok(){ case "$1" in 127.0.0.1|::1|'[::1]') return 0;; *) return 1;; esac; }
echo "== lme.service =="; systemctl is-active lme.service || true
echo "== failed lme units (must be empty) =="
failed=$(systemctl list-units --plain --no-legend 'lme*' --state=failed 2>/dev/null | awk '{print $1}')
[ -n "$failed" ] && { echo "  FAIL: failed lme units: $failed"; fail=1; } || echo "  ok: none failed"
echo "== running containers (expect >= 6) =="
running=$(sudo -i podman ps --format '{{.Names}}' 2>/dev/null | sed '/^$/d' | wc -l)
echo "  running=$running"; sudo -i podman ps --format '  {{.Names}} {{.Status}}' 2>/dev/null
[ "$running" -lt 6 ] && { echo "  FAIL: <6 running"; fail=1; } || echo "  ok"
echo "== exposure loopback-only (9200 5601 443 8220) =="
listen_tbl=$(ss -ltnH 2>/dev/null | awk '{a=$4;p=a;sub(/:[0-9]+$/,"",a);sub(/.*:/,"",p);print p" "a}')
[ -z "$listen_tbl" ] && { echo "  FAIL: no listeners parsed"; fail=1; }
for p in 9200 5601 443 8220; do
  addrs=$(printf '%s\n' "$listen_tbl" | awk -v pp="$p" '$1==pp{print $2}')
  [ -z "$addrs" ] && { echo "  port $p: not listening"; continue; }
  bad=""; for a in $addrs; do loopback_ok "$a" || bad="$bad $a"; done
  [ -n "$bad" ] && { echo "  FAIL: port $p LAN-open on$bad"; fail=1; } || echo "  ok: port $p loopback-only [$addrs]"
done
echo "== ES :9200 (expect 401/200) =="
code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 https://127.0.0.1:9200 || echo 000); echo "  ES=$code"
case "$code" in 401|200) echo "  ok";; *) echo "  FAIL"; fail=1;; esac
echo "== Kibana :5601 (expect 200/302/401) =="
kb=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 https://127.0.0.1:5601 || echo 000); echo "  Kibana=$kb"
case "$kb" in 200|302|401) echo "  ok";; *) echo "  FAIL"; fail=1;; esac
echo "== HEALTH result fail=$fail =="; exit $fail
