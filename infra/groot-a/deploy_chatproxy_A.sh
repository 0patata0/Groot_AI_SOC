#!/bin/bash
# Groot_A: 채팅 리버스 프록시(nginx) 배치. 게이트형. sudo bash 로 실행.
# 전제: nginx:1.27-alpine 반입됨, /home/groot_a/capstone/chatproxy/{docker-compose.yml,nginx.conf}, B:8065(Mattermost) 도달 가능.
# A:443 은 비어 있어야 함(관리포털 DNAT 는 10443 으로 이동됨). 자체서명 인증서(chat.groot.lab) 생성.
set -euo pipefail
CD=/home/groot_a/capstone/chatproxy
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*"; exit 1; }

say "G0 preflight"
[ "$(id -u)" = 0 ] || die "run as root"
docker image inspect nginx:1.27-alpine >/dev/null 2>&1 || die "nginx image missing"
[ -f "$CD/docker-compose.yml" ] && [ -f "$CD/nginx.conf" ] || die "compose/nginx.conf missing at $CD"
timeout 5 bash -c 'exec 3<>/dev/tcp/10.10.10.10/8065' 2>/dev/null || die "B Mattermost 10.10.10.10:8065 unreachable"
# 443 이 이미 다른(non-chatproxy) 프로세스에 잡혀있지 않은지
if [ -z "$(docker ps -q -f name='^chatproxy$')" ] && ss -ltn | awk '{print $4}' | grep -qE ':443$'; then die "port 443 busy by a non-chatproxy process"; fi
echo "ok: image, compose, B:8065, port 443"

say "P1 self-signed cert (chat.groot.lab)"
mkdir -p "$CD/tls"
if [ ! -f "$CD/tls/chat.crt" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
    -keyout "$CD/tls/chat.key" -out "$CD/tls/chat.crt" \
    -subj "/CN=chat.groot.lab" -addext "subjectAltName=DNS:chat.groot.lab" >/dev/null 2>&1
  chmod 600 "$CD/tls/chat.key"; chmod 644 "$CD/tls/chat.crt"
  echo "  generated tls/chat.{crt,key}"
else echo "  cert exists (kept)"; fi
openssl x509 -in "$CD/tls/chat.crt" -noout -subject -ext subjectAltName | sed 's/^/  /'

say "P2 validate nginx config"
docker run --rm -v "$CD/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$CD/tls:/etc/nginx/tls:ro" nginx:1.27-alpine nginx -t 2>&1 | sed 's/^/  /' | grep -E 'syntax is ok|successful' || die "nginx -t failed"

say "P3 compose up (+ restart to apply any nginx.conf edit on re-run — bind mount)"
cd "$CD" && docker compose up -d 2>&1 | grep -E 'Creat|Start|Recreat|rror' | tail -4 || true
docker compose restart chatproxy >/dev/null 2>&1 || true
sleep 3
[ "$(docker inspect -f '{{.State.Status}}' chatproxy 2>/dev/null)" = running ] || { docker logs --tail 20 chatproxy 2>&1; die "chatproxy not running"; }
[ "$(docker inspect -f '{{.RestartCount}}' chatproxy)" = 0 ] || { docker logs --tail 20 chatproxy; die "chatproxy restarting (config error?)"; }
echo -n "  container->B:8065: "; docker exec chatproxy wget -qO- -T5 http://10.10.10.10:8065/api/v4/system/ping 2>/dev/null | grep -q '"status":"OK"' && echo "reachable" || die "chatproxy container cannot reach 10.10.10.10:8065 (bridge egress/FORWARD)"

say "V1 proxy serves chat.groot.lab (from A itself, --resolve to A ext IP)"
curl -sk --resolve chat.groot.lab:443:192.168.16.230 -o /dev/null -w "  https://chat.groot.lab/api/v4/system/ping -> %{http_code}\n" -m 8 https://chat.groot.lab/api/v4/system/ping
curl -sk --resolve chat.groot.lab:443:192.168.16.230 -o /dev/null -w "  https://chat.groot.lab/ (login) -> %{http_code}\n" -m 8 https://chat.groot.lab/
say "V2 websocket 101 (Origin=SiteURL)"
KEY=$(head -c16 /dev/urandom | base64)
curl -sk --resolve chat.groot.lab:443:192.168.16.230 -o /dev/null -w "  websocket -> %{http_code} (101 기대)\n" -m 8 \
  -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: $KEY" \
  -H "Origin: https://chat.groot.lab" https://chat.groot.lab/api/v4/websocket
say "V3 맨 IP/다른 Host 는 무응답(444)"
curl -sk -o /dev/null -w "  https://192.168.16.230/ (맨 IP) -> %{http_code} (000/empty 기대)\n" -m 6 https://192.168.16.230/ || echo "  맨 IP: 연결 종료(기대대로)"
echo; echo "== CHATPROXY_DONE =="
