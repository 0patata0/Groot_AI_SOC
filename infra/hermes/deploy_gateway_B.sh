#!/bin/bash
# Groot_B: Hermes 게이트웨이(상주 컨테이너) + Mattermost 어댑터 + 경보 감시 cron 배치. root 로 실행. 재실행 안전.
# 전제: deploy_hermes_B.sh prep/load 완료(/opt/hermes-data, 이미지), Mattermost 봇 계정 토큰 발급(팀장 계정 API), soc_bot 브로커 배치(READ_TOKEN).
# 입력 env: MM_HERMES_ENV=<MATTERMOST_* 줄이 든 파일>, SOC_READ_TOKEN=<soc_bot READ_TOKEN>  (둘 다 비밀 → repo 에 두지 않음)
set -euo pipefail
: "${MM_HERMES_ENV:?MM_HERMES_ENV unset}" "${SOC_READ_TOKEN:?SOC_READ_TOKEN unset}"
IMG=${IMG:-nousresearch/hermes-agent:v2026.9.24}; D=/opt/hermes-data; SRC=${SRC:-$(dirname "$0")}
U=$(id -u hermes); G=$(id -g hermes); RUN="docker run --rm -e HERMES_UID=$U -e HERMES_GID=$G -v $D:/opt/data $IMG"
F='s6-rc|cont-init|supervise|reconcile|preinit|stage2|Syncing|Done:|^$'
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*"; exit 1; }
[ "$(id -u)" = 0 ] || die root; docker image inspect "$IMG" >/dev/null || die "image missing"; [ -f "$MM_HERMES_ENV" ] || die "no $MM_HERMES_ENV"

say "P1 .env: MATTERMOST_* (URL/TOKEN/ALLOWED_USERS/HOME_CHANNEL/ALLOWED_CHANNELS/REQUIRE_MENTION/FREE_RESPONSE_CHANNELS/REPLY_MODE)"
touch "$D/.env"; sed -i '/^MATTERMOST_/d' "$D/.env"; grep -E '^MATTERMOST_' "$MM_HERMES_ENV" >> "$D/.env"; chown hermes:hermes "$D/.env"; chmod 600 "$D/.env"
grep -oE '^MATTERMOST_[A-Z_]+' "$D/.env" | tr '\n' ' '; echo

say "P2 config: resp 서버는 trust=full(승인은 서버측 브로커가 강제) + tool timeout 720s(> 브로커 대기 600s); tool_search off(MCP 툴 즉시 노출 — 검색 브리지 경유 시 qwen3.6 이 reasoning-only 로 멈추는 stall 실측)"
for kv in "mcp_servers.resp.trust full" "mcp_servers.resp.timeout 720" "tools.tool_search.enabled off"; do set -- $kv; $RUN config set "$1" "$2" 2>&1 | grep -vE "$F" | tail -1 | sed 's/^/  /'; done

say "P2b SOUL.md: 한국어 설명 + 식별자 원문 보존 + 추측 금지 규칙 (SOUL.groot.md 를 기본 페르소나 뒤에 덧붙임, 멱등)"
[ -f "$D/SOUL.md" ] || $RUN true >/dev/null 2>&1 || true
grep -q "Groot SOC 답변 규칙" "$D/SOUL.md" 2>/dev/null || cat "$SRC/SOUL.groot.md" >> "$D/SOUL.md"; chown hermes:hermes "$D/SOUL.md"; echo "  SOUL.md $(wc -c < "$D/SOUL.md") bytes"

say "P3 모니터 스크립트(읽기 토큰 포함, hermes 0700)"
install -d -o hermes -g hermes -m 0750 "$D/scripts"
{ echo '#!/bin/bash'; echo "export SOC_READ_TOKEN=$SOC_READ_TOKEN"; tail -n +2 "$SRC/scripts/recent_alerts.sh"; } > "$D/scripts/recent_alerts.sh"
chown hermes:hermes "$D/scripts/recent_alerts.sh"; chmod 700 "$D/scripts/recent_alerts.sh"
echo "  $($RUN bash -c 'bash /opt/data/scripts/recent_alerts.sh' 2>/dev/null | grep -vE "$F" | head -1)"

say "P4 게이트웨이 컨테이너(hermes) — 데이터 디렉터리당 하나만"
docker rm -f hermes >/dev/null 2>&1 || true
docker run -d --name hermes --restart unless-stopped -e HERMES_UID="$U" -e HERMES_GID="$G" -v "$D:/opt/data" "$IMG" gateway run >/dev/null
sleep 30; docker ps --filter name='^hermes$' --format '  {{.Names}} {{.Status}}'
grep -hE 'mattermost connected|WebSocket connected|Gateway running' "$D/logs/gateway.log" | tail -3 | sed 's/^/  /'
grep -q 'mattermost connected' "$D/logs/gateway.log" || die "mattermost not connected (MATTERMOST_TOKEN/URL?)"

say "P5 cron: soc-alert-watch (every 5m, monitor-script → 새 고심각 경보 때만 LLM, deliver mattermost=HOME_CHANNEL)"
if ! docker exec hermes hermes cron list 2>/dev/null | grep -q 'soc-alert-watch'; then
  docker exec hermes hermes cron create "every 5m" "$(cat "$SRC/soc_alert_watch.prompt")" --name soc-alert-watch --monitor-script recent_alerts.sh --deliver mattermost 2>&1 | grep -vE "$F" | grep -E 'Created|Name|Schedule|Monitor' | sed 's/^/  /'
else echo "  exists"; fi
docker exec hermes hermes cron list 2>&1 | grep -vE "$F" | grep -E '^\s+[0-9a-f]{12} |Next run|Deliver' | sed 's/^/  /'
echo; echo "== GATEWAY_DONE =="
