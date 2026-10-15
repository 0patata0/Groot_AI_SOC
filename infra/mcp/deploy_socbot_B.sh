#!/bin/bash
# Groot_B: SOC 챗봇(soc_bot serve) 배치 + Mattermost 슬래시 명령 /soc 생성. 게이트형. root 로 실행.
# 읽기전용(mcp-ro)으로 Wazuh 조회 → 채팅에서 /soc 로 상호작용. 대응(차단)은 여기 없음(응답 MCP groot-resp 로 분리).
# 전제: /tmp/에 soc_bot.py 및 아래 MODULES, /etc/mcp/wazuh-ro.env, Mattermost 가동.
# 입력 env: MM_ADMIN_PW(=socadmin 비번), MM_WEBHOOK. 만료 카드 정리는 자동 활성화하지 않는다.
set -euo pipefail
MODULES=(soc_bot.py operations_approval.py soc_management_events.py approval_card_cleanup.py)
: "${MM_ADMIN_PW:?MM_ADMIN_PW unset}" "${MM_WEBHOOK:?MM_WEBHOOK unset (report 게시용 incoming webhook URL; 값은 CREDENTIALS.local.md)}"
MM=http://10.200.10.10:8065; API=$MM/api/v4
LISTEN=${LISTEN:-0.0.0.0:8090}                          # 봇 리슨(모든 IF). MM 컨테이너가 게이트웨이로 도달
SLASH_URL=${SLASH_URL:-http://172.19.0.1:8090}          # MM(컨테이너)→봇 콜백 주소 = mm-net 게이트웨이(호스트). ⚠️ MM 은 사설IP 아웃바운드를 기본 차단(SSRF)
# → mattermost-compose.yml 의 MM_SERVICESETTINGS_ALLOWEDUNTRUSTEDINTERNALCONNECTIONS 에 이 IP 가 있어야 함(172.19.0.1). EnableCommands=true 도 필요(compose 에 설정).
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*"; exit 1; }

say "G0 preflight"
[ "$(id -u)" = 0 ] || die "run as root"
# This older installer rewrites the entire env file. Once the dedicated rule
# broker has been enabled, rerunning it would erase RULE_BROKER_TOKEN,
# RULE_APPROVERS, and the Mattermost callback source restriction. Fail before
# any mutation; update the original soc-bot through the gated rule-broker
# installer or migrate the env with a reviewed procedure instead.
if [ -f /etc/socbot/soc_bot.env ] && grep -Eq '^(RULE_BROKER_TOKEN|SOC_APPROVAL_CARD_CLEANUP)=' /etc/socbot/soc_bot.env; then
  die "protected broker settings are present; deploy_socbot_B.sh would remove them. Use deploy_rule_broker_B.sh for broker updates"
fi
python3 -B - "${MODULES[@]}" <<'PY' || die 'soc-bot bundle missing, unsafe, or syntax-invalid'
import ast, os, pathlib, stat, sys
for name in sys.argv[1:]:
    path=pathlib.Path('/tmp')/name
    info=os.lstat(path)
    assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and not(stat.S_IMODE(info.st_mode)&0o022)
    ast.parse(path.read_text(encoding='utf-8'))
PY
[ -r /etc/mcp/wazuh-ro.env ] || die "/etc/mcp/wazuh-ro.env missing (read creds)"
curl -s -m5 "$MM/api/v4/system/ping" | grep -q '"status":"OK"' || die "Mattermost not reachable"
TK=$(curl -s -D - -o /dev/null -X POST "$API/users/login" -H 'Content-Type: application/json' --data-binary @<(printf '{"login_id":"socadmin","password":"%s"}' "$MM_ADMIN_PW") | awk 'tolower($1)=="token:"{print $2}' | tr -d '\r')
[ -n "$TK" ] || die "MM admin login failed"
echo "ok"

say "P1 user + install"
id socbot >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin -G mcp -c "capstone SOC bot" socbot
usermod -aG mcp socbot 2>/dev/null || true    # /etc/mcp/wazuh-ro.env(0640 root:mcp) 읽기용
install -d -o root -g socbot -m 0750 /opt/socbot
for module in "${MODULES[@]}"; do
  install -o root -g socbot -m 0750 "/tmp/$module" "/opt/socbot/$module"
done

say "P2 Mattermost 슬래시 명령 /soc (없으면 생성) + 토큰 확보"
TEAMID=$(curl -s -H "Authorization: Bearer $TK" "$API/teams/name/soc" | python3 -c 'import json,sys;d=json.load(sys.stdin);print("" if (not isinstance(d,dict) or d.get("status_code")) else d.get("id",""))')
[ -n "$TEAMID" ] || die "team soc not found"
STOKEN=$(curl -s -H "Authorization: Bearer $TK" "$API/commands?team_id=$TEAMID" | python3 -c 'import json,sys
d=json.load(sys.stdin); c=[x for x in d if isinstance(x,dict) and x.get("trigger")=="soc"] if isinstance(d,list) else []
print(c[0]["token"] if c else "")')
if [ -z "$STOKEN" ]; then
  R=$(curl -s -H "Authorization: Bearer $TK" -X POST "$API/commands" -H 'Content-Type: application/json' \
      -d "{\"team_id\":\"$TEAMID\",\"trigger\":\"soc\",\"method\":\"P\",\"url\":\"$SLASH_URL\",\"display_name\":\"SOC agent\",\"auto_complete\":true,\"auto_complete_desc\":\"alerts|agents|vulns|status|report\"}")
  STOKEN=$(echo "$R" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("token","")) if isinstance(d,dict) else print("")')
  [ -n "$STOKEN" ] || { echo "$R" | cut -c1-200; die "slash command create failed (EnableCommands? admin integrations?)"; }
  echo "  created /soc (token len ${#STOKEN})"
else echo "  /soc exists (token reused)"; fi

say "P3 env + systemd"
install -d -o root -g socbot -m 0750 /etc/socbot
umask 027
BROKER_TOKEN=${BROKER_TOKEN:-$(python3 -c "import secrets;print(secrets.token_hex(24))")}   # 응답 서버(A) hitl.env 의 RESP_BROKER_TOKEN 과 동일해야 함
READ_TOKEN=${READ_TOKEN:-$(python3 -c "import secrets;print(secrets.token_hex(24))")}       # Hermes 모니터 스크립트(SOC_READ_TOKEN)
APPROVERS=${APPROVERS:-}                                                                # 승인 버튼 허용 MM user id(쉼표). 빈값=누구나
cat > /etc/socbot/soc_bot.env <<EOF
# capstone SOC bot. 읽기 자격은 /etc/mcp/wazuh-ro.env(WAZUH_*) 재사용. 여기엔 웹훅/슬래시토큰/리슨 + Tier2 브로커 비밀.
MM_WEBHOOK=$MM_WEBHOOK
SLASH_TOKEN=$STOKEN
LISTEN=$LISTEN
BROKER_TOKEN=$BROKER_TOKEN
READ_TOKEN=$READ_TOKEN
APPROVERS=$APPROVERS
MM_ACTION_URL=$SLASH_URL
APPROVAL_TTL=900
EOF
echo "  broker/read tokens written to /etc/socbot/soc_bot.env (A 의 /etc/resp/hitl.env RESP_BROKER_TOKEN 에 같은 BROKER_TOKEN 을 넣을 것)"
chown root:socbot /etc/socbot/soc_bot.env; chmod 0640 /etc/socbot/soc_bot.env
umask 022
cat > /etc/systemd/system/soc-bot.service <<'EOF'
[Unit]
Description=capstone SOC chatbot (Mattermost /soc)
After=docker.service network-online.target
[Service]
User=socbot
Group=socbot
SupplementaryGroups=mcp
EnvironmentFile=/etc/mcp/wazuh-ro.env
EnvironmentFile=/etc/socbot/soc_bot.env
ExecStart=/usr/bin/python3 /opt/socbot/soc_bot.py serve
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable --now soc-bot >/dev/null; sleep 2
systemctl is-active soc-bot >/dev/null || { journalctl -u soc-bot --no-pager -n 15; die "soc-bot not active"; }
ss -ltn | grep -q "$LISTEN" && echo "  listening $LISTEN" || die "not listening on $LISTEN"

say "P4 주기 보고 타이머(soc-report) — REPORT_EVERY(기본 1h), REPORT_WINDOW(기본 60분). 경보 0이면 미게시(스팸 방지)"
REPORT_EVERY=${REPORT_EVERY:-1h}; REPORT_WINDOW=${REPORT_WINDOW:-60}
cat > /etc/systemd/system/soc-report.service <<EOF
[Unit]
Description=capstone SOC periodic incident report to Mattermost
After=docker.service network-online.target
[Service]
Type=oneshot
User=socbot
Group=socbot
SupplementaryGroups=mcp
EnvironmentFile=/etc/mcp/wazuh-ro.env
EnvironmentFile=/etc/socbot/soc_bot.env
ExecStart=/usr/bin/python3 /opt/socbot/soc_bot.py report $REPORT_WINDOW
EOF
cat > /etc/systemd/system/soc-report.timer <<EOF
[Unit]
Description=run SOC periodic report every $REPORT_EVERY
[Timer]
OnBootSec=5min
OnUnitActiveSec=$REPORT_EVERY
AccuracySec=30s
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload; systemctl enable --now soc-report.timer >/dev/null
systemctl list-timers soc-report.timer --no-pager --no-legend | awk '{print "  report timer:", $1, $2, $3, $4}'

say "P5 정기 상태요약 타이머(soc-summary) — 하루 2회, 이상 없어도 항상 게시(heartbeat)"
SUMMARY_HOURS=${SUMMARY_HOURS:-12}
SUMMARY_ONCAL=${SUMMARY_ONCAL:-"*-*-* 09,21:00:00 Asia/Seoul"}   # 호스트 타임존 변경과 무관하게 KST 09·21시
cat > /etc/systemd/system/soc-summary.service <<EOF
[Unit]
Description=capstone SOC periodic STATUS SUMMARY (always posts) to Mattermost
After=docker.service network-online.target
[Service]
Type=oneshot
User=socbot
Group=socbot
SupplementaryGroups=mcp
EnvironmentFile=/etc/mcp/wazuh-ro.env
EnvironmentFile=/etc/socbot/soc_bot.env
ExecStart=/usr/bin/python3 /opt/socbot/soc_bot.py summary $SUMMARY_HOURS
EOF
cat > /etc/systemd/system/soc-summary.timer <<EOF
[Unit]
Description=SOC status summary twice daily
[Timer]
OnCalendar=$SUMMARY_ONCAL
Persistent=true
AccuracySec=1min
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload; systemctl enable --now soc-summary.timer >/dev/null
systemctl list-timers soc-summary.timer --no-pager --no-legend | awk '{print "  summary timer next:", $1, $2, $3}'

say "V1 슬래시 명령 시뮬레이션(token 검증 + 응답)"
curl -s -m8 -X POST "http://$LISTEN" -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "token=$STOKEN" --data-urlencode "text=status" | python3 -c 'import json,sys;d=json.load(sys.stdin);print("  status ->",d.get("text","")[:100])'
curl -s -m8 -o /dev/null -w "  bad token -> HTTP %{http_code} (401 기대)\n" -X POST "http://$LISTEN" --data-urlencode "token=WRONG" --data-urlencode "text=status"
say "V2 MM 컨테이너에서 봇 도달(슬래시 콜백 경로)"
docker exec mm-app sh -c "wget -qO- --post-data='token=$STOKEN&text=agents' --header='Content-Type: application/x-www-form-urlencoded' http://$LISTEN 2>/dev/null" | python3 -c 'import json,sys;d=json.load(sys.stdin);print("  agents ->",d.get("text","")[:100])' || echo "  !! MM 컨테이너->봇 도달 실패(방화벽/바인드 확인)"
echo; echo "== SOCBOT_DONE =="
