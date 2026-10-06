#!/bin/bash
# /opt/mcp/run-wazuh-ro.sh — Groot_B에서 읽기전용 Wazuh MCP 서버(stdio)를 실행하는 래퍼.
# 클라이언트(Claude Code / Hermes 등)는 `ssh -T groot-mcp` 를 MCP 명령으로 실행한다: sshd(Match User mcp ForceCommand)와
# authorized_keys(restrict,command=)가 이 래퍼만 실행시킨다. 원격 명령이 정확히 security-events 일 때만 보조 읽기 서버로 분기한다.
# 배치: 소유 root:mcp, 권한 0750. 비밀은 /etc/mcp/wazuh-ro.env (root:mcp 0640 — mcp 읽기만) 에만 두고 이 파일·repo에 넣지 않는다.
# 주의: stdin/stdout은 MCP 프로토콜 채널이다 — 이 스크립트에서 stdout에 아무것도 출력하지 말 것(진단은 stderr).
set -euo pipefail
# SSH 세션에서는 경로 오버라이드를 무시(환경변수로 다른 바이너리/파일을 지정하는 경로를 원천 차단)
if [ -n "${SSH_CONNECTION:-}" ]; then unset MCP_ENV_FILE MCP_BIN; fi
ENV_FILE=${MCP_ENV_FILE:-/etc/mcp/wazuh-ro.env}
BIN=${MCP_BIN:-/opt/mcp/mcp-server-wazuh}
[ -r "$ENV_FILE" ] || { echo "run-wazuh-ro: env file missing/unreadable: $ENV_FILE" >&2; exit 1; }
set -a; . "$ENV_FILE"; set +a
: "${WAZUH_API_USERNAME:?WAZUH_API_USERNAME unset}"; : "${WAZUH_API_PASSWORD:?WAZUH_API_PASSWORD unset}"
export RUST_LOG="${RUST_LOG:-info}"
# SSH_ORIGINAL_COMMAND 는 비교만 한다. 다른 명령이나 셸 메타문자는 실행하지 않고 기존 14툴 바이너리로 간다.
if [ "${SSH_ORIGINAL_COMMAND:-}" = security-events ]; then
  EVENTS=/opt/mcp/security-events-mcp.py
  [ -x "$EVENTS" ] || { echo "run-wazuh-ro: security-events server missing/not executable" >&2; exit 1; }
  exec /usr/bin/python3 "$EVENTS"
fi
[ -x "$BIN" ] || { echo "run-wazuh-ro: binary missing/not executable: $BIN" >&2; exit 1; }
exec "$BIN"
