#!/bin/bash
# Groot_A: 이름 기반 리버스 프록시(nginx) 배치 — 채팅(chat.groot.lab→B:8065) + 관리포털(wazuh.groot.lab→B:443). 게이트형. sudo bash 로 실행.
# 전제: nginx:1.27-alpine 반입됨, /home/groot_a/capstone/chatproxy/{docker-compose.yml,nginx.conf}, B:8065·B:443 도달 가능.
# A:443 은 chatproxy 전용. 자체서명 인증서 2종(chat.groot.lab / wazuh.groot.lab — 분리, 채팅 인증서 재신뢰 불필요) 생성.
# 재실행 안전: 인증서는 있으면 유지, nginx.conf 변경은 restart 로 반영(bind mount). nginx -t 실패 시 재시작 전에 중단.
set -euo pipefail
CD=/home/groot_a/capstone/chatproxy
EXT=192.168.16.230
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*"; exit 1; }

say "G0 preflight"
[ "$(id -u)" = 0 ] || die "run as root"
docker image inspect nginx:1.27-alpine >/dev/null 2>&1 || die "nginx image missing"
[ -f "$CD/docker-compose.yml" ] && [ -f "$CD/nginx.conf" ] || die "compose/nginx.conf missing at $CD"
timeout 5 bash -c 'exec 3<>/dev/tcp/10.10.10.10/8065' 2>/dev/null || die "B Mattermost 10.10.10.10:8065 unreachable"
timeout 5 bash -c 'exec 3<>/dev/tcp/10.10.10.10/443'  2>/dev/null || die "B Wazuh dashboard 10.10.10.10:443 unreachable"
if [ -z "$(docker ps -q -f name='^chatproxy$')" ] && ss -ltn | awk '{print $4}' | grep -qE ':443$'; then die "port 443 busy by a non-chatproxy process"; fi
echo "ok: image, compose, B:8065, B:443, port 443"

say "P1 self-signed certs (chat.groot.lab / wazuh.groot.lab — separate)"
mkdir -p "$CD/tls"
mkcert(){ # $1=name
  if [ ! -f "$CD/tls/$1.crt" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
      -keyout "$CD/tls/$1.key" -out "$CD/tls/$1.crt" \
      -subj "/CN=$1.groot.lab" -addext "subjectAltName=DNS:$1.groot.lab" >/dev/null 2>&1
    chmod 600 "$CD/tls/$1.key"; chmod 644 "$CD/tls/$1.crt"
    echo "  generated tls/$1.{crt,key}"
  else echo "  tls/$1.crt exists (kept)"; fi
  openssl x509 -in "$CD/tls/$1.crt" -noout -subject -ext subjectAltName | sed 's/^/    /'
}
mkcert chat; mkcert wazuh

say "P2 validate nginx config"
docker run --rm -v "$CD/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$CD/tls:/etc/nginx/tls:ro" nginx:1.27-alpine nginx -t 2>&1 | sed 's/^/  /' | grep -E 'syntax is ok|successful' || die "nginx -t failed"

say "P3 compose up (+ restart to apply nginx.conf edits — bind mount)"
cd "$CD" && docker compose up -d 2>&1 | grep -E 'Creat|Start|Recreat|rror' | tail -4 || true
docker compose restart chatproxy >/dev/null 2>&1 || true
sleep 3
[ "$(docker inspect -f '{{.State.Status}}' chatproxy 2>/dev/null)" = running ] || { docker logs --tail 20 chatproxy 2>&1; die "chatproxy not running"; }
[ "$(docker inspect -f '{{.RestartCount}}' chatproxy)" = 0 ] || { docker logs --tail 20 chatproxy; die "chatproxy restarting (config error?)"; }
echo -n "  container->B:8065: "; docker exec chatproxy wget -qO- -T5 http://10.10.10.10:8065/api/v4/system/ping 2>/dev/null | grep -q '"status":"OK"' && echo "reachable" || die "chatproxy container cannot reach 10.10.10.10:8065 (bridge egress/FORWARD)"

say "V1 chat.groot.lab (from A, --resolve to A ext IP)"
curl -sk --resolve chat.groot.lab:443:$EXT -o /dev/null -w "  https://chat.groot.lab/api/v4/system/ping -> %{http_code}\n" -m 8 https://chat.groot.lab/api/v4/system/ping
curl -sk --resolve chat.groot.lab:443:$EXT -o /dev/null -w "  https://chat.groot.lab/ (login) -> %{http_code}\n" -m 8 https://chat.groot.lab/
say "V2 chat websocket 101 (Origin=SiteURL)"
KEY=$(head -c16 /dev/urandom | base64)
curl -sk --resolve chat.groot.lab:443:$EXT -o /dev/null -w "  websocket -> %{http_code} (101 기대)\n" -m 8 \
  -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: $KEY" \
  -H "Origin: https://chat.groot.lab" https://chat.groot.lab/api/v4/websocket || true   # 101 후 본문 대기 타임아웃(exit 28)으로 set -e 종료 방지
say "V3 맨 IP/다른 Host 는 무응답(444)"
curl -sk -o /dev/null -w "  https://$EXT/ (맨 IP) -> %{http_code} (000/empty 기대)\n" -m 6 https://$EXT/ || echo "  맨 IP: 연결 종료(기대대로)"

say "V4 wazuh.groot.lab (from A — 출발지가 allowlist 면 302→/app/login, 아니면 403=allowlist 동작)"
H=$(mktemp)
code=$(curl -sk --resolve wazuh.groot.lab:443:$EXT -o /dev/null -D "$H" -w '%{http_code}' -m 10 https://wazuh.groot.lab/ || echo 000)
loc=$(grep -i '^location:' "$H" | tr -d '\r' | awk '{print $2}'); rm -f "$H"
echo "  https://wazuh.groot.lab/ -> $code ${loc:+(location: $loc)}"
case "$code" in
  302) echo "  ✅ 프록시→대시보드 정상(로그인 리다이렉트). allowlist 에 A 출발지 포함";;
  403) echo "  ℹ️ 403 = allowlist 가 A 자기 출발지(도커 헤어핀 172.x)를 거부 — 정책 동작 확인. 실사용 검증은 학과망 PC 에서";;
  *)   die "wazuh proxy unexpected $code";;
esac
if [ "$code" = 302 ]; then
  curl -sk --resolve wazuh.groot.lab:443:$EXT -o /dev/null -w "  https://wazuh.groot.lab/app/login -> %{http_code} (200 기대)\n" -m 10 https://wazuh.groot.lab/app/login
fi
say "V5 allowlist 가 로드된 설정에 존재하는지"
docker exec chatproxy nginx -T 2>/dev/null | grep -A12 'server_name wazuh.groot.lab' | grep -E 'allow|deny' | sed 's/^/  /'
echo; echo "== CHATPROXY_DONE =="
