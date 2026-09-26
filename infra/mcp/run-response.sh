#!/bin/bash
# /opt/resp/run-response.sh — Groot_A에서 응답(차단) MCP 서버(stdio)를 실행하는 래퍼.
# 에이전트는 `ssh -T groot-resp` 로 실행 → A의 sshd(Match User resp ForceCommand) + authorized_keys(restrict,command=)가 이 래퍼만 실행.
# 배치: 소유 root:resp, 권한 0750. 정책 상한은 env(RESP_MAX_MINUTES 등)로 여기서만 조정. 비밀 없음(차단 능력은 resp 의 sudoers).
# 주의: stdin/stdout 은 MCP 프로토콜 채널 — 이 스크립트에서 stdout 출력 금지(진단은 stderr).
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
BIN=/opt/resp/response-mcp.py
[ -r "$BIN" ] || { echo "run-response: server missing: $BIN" >&2; exit 1; }
export RESP_AGENT_BLOCK=/usr/local/sbin/agent_block
# 알림 채널 설정(백엔드/엔드포인트/비밀). 있으면 source — 채널 교체는 이 파일만 수정.
HITL_ENV=${HITL_ENV:-/etc/resp/hitl.env}
if [ -r "$HITL_ENV" ]; then set -a; . "$HITL_ENV"; set +a; fi
export RESP_MAX_MINUTES="${RESP_MAX_MINUTES:-120}"
export RESP_DEFAULT_MINUTES="${RESP_DEFAULT_MINUTES:-10}"
export RESP_NOTIFY_BACKEND="${RESP_NOTIFY_BACKEND:-none}"
exec /usr/bin/python3 "$BIN"
