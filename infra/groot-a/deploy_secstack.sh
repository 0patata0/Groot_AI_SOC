#!/bin/bash
# Groot_A: Suricata(IDS on ens192) + ModSecurity CRS WAF(→ groot-web:80) 배치. 게이트형(리뷰 반영, 2026-09-26 실배치 검증). sudo bash 로 실행.
# 전제: 이미지 반입됨, ET 룰 ~/capstone/suricata/rules/*.rules, compose 파일 /home/groot_a/capstone/secstack/docker-compose.yml, /etc/hosts groot-web.
# 재실행 안전: 기존 스택이 떠 있으면 포트 점검을 건너뛰고 compose up 이 변경분만 재생성한다.
set -euo pipefail
BASE=/home/groot_a/capstone
SS=$BASE/secstack
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*"; exit 1; }

say "G0 preflight"
docker images --format '{{.Repository}}:{{.Tag}}' | grep -q '^jasonish/suricata:latest$' || die "suricata image missing"
docker images --format '{{.Repository}}:{{.Tag}}' | grep -q '^owasp/modsecurity-crs:nginx$' || die "modsecurity image missing"
[ -f $SS/docker-compose.yml ] || die "compose missing at $SS"
N=$(ls $BASE/suricata/rules/*.rules 2>/dev/null | wc -l); [ "$N" -gt 0 ] || die "ET rules not staged"
ip link show ens192 >/dev/null 2>&1 || die "ens192 missing"
getent hosts groot-web | grep -q 10.10.10.20 || die "groot-web unresolved"
timeout 5 bash -c 'exec 3<>/dev/tcp/groot-web/80' 2>/dev/null || die "groot-web:80 unreachable"
if [ -z "$(docker ps -q -f name='^waf$')" ] && ss -ltn | awk '{print $4}' | grep -qE ':(80|443)$'; then die "port 80/443 in use by a non-stack process"; fi
MU=$(docker inspect owasp/modsecurity-crs:nginx --format '{{.Config.User}}'); [ "$MU" = "nginx" ] || echo "note: modsec image user=$MU"
echo "ok: images, compose, $N rule files, ens192, groot-web:80, ports"

say "P1 build single ruleset -> $BASE/suricata/ruleset/suricata.rules"
mkdir -p $BASE/suricata/ruleset
cat $BASE/suricata/rules/*.rules > $BASE/suricata/ruleset/suricata.rules
RC=$(grep -cE '^(alert|drop|reject|pass) ' $BASE/suricata/ruleset/suricata.rules || true)
echo "rules: $RC ($(du -h $BASE/suricata/ruleset/suricata.rules | cut -f1))"
[ "$RC" -ge 50000 ] || die "ruleset looks incomplete ($RC)"
chmod 755 $BASE/suricata/ruleset; chmod 644 $BASE/suricata/ruleset/suricata.rules

say "P2 log dirs (modsec must be writable by uid 101)"
mkdir -p $SS/logs/suricata $SS/logs/modsec
chown 101:101 $SS/logs/modsec; chmod 755 $SS/logs/modsec
ls -ld $SS/logs/suricata $SS/logs/modsec

say "P3 compose up"
cd $SS && docker compose up -d 2>&1 | grep -E 'Creat|Start|Recreat|rror' | tail -8 || true
sleep 8
for c in suricata waf; do docker inspect -f '{{.Name}} {{.State.Status}} restarts={{.RestartCount}} exit={{.State.ExitCode}}' $c; done
for c in suricata waf; do
  [ "$(docker inspect -f '{{.State.Status}}' $c)" = "running" ] || { docker logs --tail 30 $c; die "$c not running"; }
  [ "$(docker inspect -f '{{.RestartCount}}' $c)" = "0" ] || { docker logs --tail 30 $c; die "$c restarted"; }
done
docker exec waf sh -c 'test -w /var/log/modsecurity' || die "waf cannot write /var/log/modsecurity"

say "P4 wait for Suricata engine (<=240s; 52k rules + Hyperscan compile)"
T=$(docker inspect -f '{{.State.StartedAt}}' suricata)
for i in $(seq 1 60); do docker logs --since "$T" suricata 2>&1 | grep -q 'Engine started' && break; sleep 4; done
docker logs --since "$T" suricata 2>&1 | grep -q 'Engine started' || { docker logs --tail 40 suricata; die "suricata did not start in 240s"; }
grep -E 'rules successfully loaded' $SS/logs/suricata/suricata.log | tail -1
if docker logs --since "$T" suricata 2>&1 | grep -qE '^(E:|Error:)'; then docker logs --since "$T" suricata 2>&1 | grep -E '^(E:|Error:)' | head -5; echo "(Error lines present — review)"; fi
echo -n "effective argv: "; docker inspect suricata --format '{{.Args}}'
ls -l $SS/logs/suricata/ 2>/dev/null | head -6 || true

say "V1 WAF -> groot-web (DVWA) through nginx/modsecurity (localhost is fine for WAF)"
curl -s -o /dev/null -w "http://localhost:80/               -> %{http_code} (302 -> /dvwa/login.php expected)\n" http://localhost:80/
curl -s -o /dev/null -w "http://localhost:80/dvwa/login.php -> %{http_code}\n" http://localhost:80/dvwa/login.php

say "V2 WAF detection (DetectionOnly: allowed but audited) — libinjection probe"
curl -s -o /dev/null -w "probe -> %{http_code}\n" "http://localhost:80/dvwa/login.php?username=admin%27%20OR%201%3D1--&password=x"
sleep 3
test -s $SS/logs/modsec/audit.log || die "audit.log missing/empty after probe"
echo "audit.log: $(wc -c < $SS/logs/modsec/audit.log) bytes; CRS rule ids in last record: $(tail -n1 $SS/logs/modsec/audit.log | grep -oE '"ruleId":"[0-9]{6}' | cut -d'"' -f4 | sort -u | tr '\n' ' ')"

say "V3 Suricata eve.json present (real IDS alert test must come from the far side of ens192, from the SAME VM segment — never via campus VPN)"
test -f $SS/logs/suricata/eve.json && echo "eve.json events: $(wc -l < $SS/logs/suricata/eve.json)" || echo "(eve.json not yet)"
echo "alerts so far: $(grep -c '"event_type":"alert"' $SS/logs/suricata/eve.json 2>/dev/null || echo 0)"
echo "  next: from B  curl -A 'sqlmap/1.0' http://192.168.16.71/dvwa/   -> eve.json sid 2008538 ; then agent_localfile.sh"
echo; echo "== SECSTACK_DONE =="
