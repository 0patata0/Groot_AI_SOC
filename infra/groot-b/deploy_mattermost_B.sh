#!/bin/bash
# Groot_B: 온프레미스 채팅(Mattermost) 배치 + 관리자·팀·채널·incoming webhook 자동 생성. 게이트형. root 로 실행.
# Wazuh 는 건드리지 않음(별도 compose/네트워크/포트). 결과로 A notifier 에 넣을 webhook URL 을 출력.
# 비밀: postgres pw 는 .env(0600), 관리자 pw 는 인자(ADMIN_PW) 또는 생성 후 1회 출력(→ CREDENTIALS.local.md). argv 노출 최소화 위해 stdin 주입 권장.
set -euo pipefail
CD=/home/groot_b/capstone/mattermost
IP=10.200.10.10; PORT=8065; API="http://$IP:$PORT/api/v4"
ADMIN_USER=${ADMIN_USER:-socadmin}; ADMIN_EMAIL=${ADMIN_EMAIL:-soc-admin@groot.local}
TEAM=${TEAM:-soc}; CHAN=${CHAN:-soc-alerts}
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*"; exit 1; }
jget(){ python3 -c 'import json,sys;d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
 d=d[int(k)] if isinstance(d,list) else d[k]
print(d)' "$1"; }

say "G0 preflight"
[ "$(id -u)" = 0 ] || die "run as root"
docker image inspect mattermost/mattermost-team-edition:11.11.1 >/dev/null 2>&1 || die "mattermost image missing"
docker image inspect postgres:16-alpine >/dev/null 2>&1 || die "postgres image missing"
[ -f "$CD/docker-compose.yml" ] || die "compose missing at $CD (stage mattermost-compose.yml first)"
command -v curl >/dev/null && command -v python3 >/dev/null || die "curl/python3 missing"
if ss -ltn | awk '{print $4}' | grep -q "$IP:$PORT\|0.0.0.0:$PORT"; then
  docker ps --format '{{.Names}}' | grep -qx mm-app || die "port $PORT busy by non-mm process"
fi
ADMIN_PW=${ADMIN_PW:-"Mm!$(openssl rand -hex 8)Aa9"}
echo "ok: images, compose, tools"

say "P1 secrets + volumes"
mkdir -p "$CD/volumes/postgres" "$CD/volumes/mm/config" "$CD/volumes/mm/data" "$CD/volumes/mm/logs" "$CD/volumes/mm/plugins" "$CD/volumes/mm/client-plugins"
chown -R 2000:2000 "$CD/volumes/mm"          # mattermost 컨테이너 uid 2000
if [ ! -f "$CD/.env" ]; then
  ( umask 077; { echo "POSTGRES_PASSWORD=Pg$(openssl rand -hex 12)"; echo "MM_SITEURL=http://localhost:18065"; } > "$CD/.env" )
  echo "  .env generated (POSTGRES_PASSWORD, MM_SITEURL=http://localhost:18065 for -L 18065 tunnel)"
else echo "  .env exists (kept)"; fi
chmod 600 "$CD/.env"

say "P2 compose up"
cd "$CD" && docker compose up -d 2>&1 | grep -E 'Creat|Start|Recreat|rror' | tail -6 || true
say "P3 wait for Mattermost API (<=180s)"
ok=0; for i in $(seq 1 60); do
  s=$(curl -s -m 5 "$API/system/ping" 2>/dev/null | jget status 2>/dev/null || true)
  [ "$s" = OK ] && { ok=1; break; }; sleep 3
done
[ "$ok" = 1 ] || { docker logs --tail 30 mm-app; die "Mattermost API not ready in 180s"; }
echo "  ping OK"

say "P4 admin/team/channel/webhook (idempotent-ish)"
export E="$ADMIN_EMAIL" U="$ADMIN_USER" P="$ADMIN_PW"
# 첫 사용자 = 시스템관리자(사용자 없을 때 무인증 생성 허용)
R=$(curl -s -m 15 -X POST "$API/users" -H 'Content-Type: application/json' \
    --data-binary @<(python3 -c 'import json,os;print(json.dumps({"email":os.environ["E"],"username":os.environ["U"],"password":os.environ["P"]}))' ) 2>/dev/null) || true
if echo "$R" | grep -q '"id"'; then echo "  admin created: $ADMIN_USER"; else echo "  admin create: $(echo "$R" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("message","(exists?)"))' 2>/dev/null || echo "?")"; fi
# 로그인 → 토큰(헤더)
TK=$(curl -s -m 15 -D - -o /dev/null -X POST "$API/users/login" -H 'Content-Type: application/json' \
     --data-binary @<(python3 -c 'import json,os;print(json.dumps({"login_id":os.environ["U"],"password":os.environ["P"]}))') | awk 'tolower($1)=="token:"{print $2}' | tr -d '\r')
[ -n "$TK" ] || die "admin login failed"
AB(){ curl -s -m 15 -H "Authorization: Bearer $TK" "$@"; }
# MM 오류응답도 "id"(오류코드)를 담으므로 status_code 있으면 실패로 간주하고 "" 반환
mmid(){ python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: print(""); sys.exit()
print("" if (not isinstance(d,dict) or d.get("status_code")) else d.get("id",""))'; }
# 팀
TID=$(AB "$API/teams/name/$TEAM" | mmid)
[ -n "$TID" ] || TID=$(AB -X POST "$API/teams" -H 'Content-Type: application/json' -d "{\"name\":\"$TEAM\",\"display_name\":\"SOC\",\"type\":\"O\"}" | mmid)
[ -n "$TID" ] || die "team create failed"; echo "  team $TEAM id=$TID"
# 채널
CID=$(AB "$API/teams/$TID/channels/name/$CHAN" | mmid)
[ -n "$CID" ] || CID=$(AB -X POST "$API/channels" -H 'Content-Type: application/json' -d "{\"team_id\":\"$TID\",\"name\":\"$CHAN\",\"display_name\":\"SOC Alerts\",\"type\":\"O\"}" | mmid)
[ -n "$CID" ] || die "channel create failed"; echo "  channel $CHAN id=$CID"
# incoming webhook (기존 있으면 재사용)
HID=$(AB "$API/hooks/incoming?per_page=200" | python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: d=[]
h=[x for x in d if isinstance(x,dict) and x.get("channel_id")==sys.argv[1]] if isinstance(d,list) else []
print(h[0]["id"] if h else "")' "$CID")
[ -n "$HID" ] || HID=$(AB -X POST "$API/hooks/incoming" -H 'Content-Type: application/json' -d "{\"channel_id\":\"$CID\",\"display_name\":\"soc-notifier\"}" | mmid)
[ -n "$HID" ] || die "incoming webhook create failed"
HOOK="http://$IP:$PORT/hooks/$HID"

say "V1 post a test message to the webhook"
curl -s -m 10 -o /dev/null -w "  webhook post -> %{http_code}\n" -X POST "$HOOK" -H 'Content-Type: application/json' -d '{"text":"[SOC] Mattermost 연동 테스트 — HITL 알림 채널 준비됨"}'
echo
echo "== MATTERMOST_DONE =="
echo "WEBHOOK_URL=$HOOK"
echo "ADMIN_USER=$ADMIN_USER"
echo "ADMIN_PW=$ADMIN_PW"
echo "SITEURL(browser via tunnel)=http://localhost:18065"
