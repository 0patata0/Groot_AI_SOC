#!/bin/bash
# Groot_B: 기존 mcp 계정/ForceCommand를 유지하며 보안 이벤트 읽기 MCP 서버를 추가한다.
# 사용: sudo bash deploy_security_events_B.sh /tmp/security-events-mcp.py /tmp/run-wazuh-ro.sh
# 두 입력 파일은 미리 검토해 B로 반입한다. 비밀 파일 수정, sshd/Hermes 재시작 없음.
set -euo pipefail

EVENTS_SRC=${1:-/tmp/security-events-mcp.py}
WRAP_SRC=${2:-/tmp/run-wazuh-ro.sh}
EVENTS=/opt/mcp/security-events-mcp.py
WRAP=/opt/mcp/run-wazuh-ro.sh
STAGE=
BACKUP=
MODIFIED=0
HAD_EVENTS=0

die() { echo "deploy_security_events_B: $*" >&2; exit 1; }
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  set +e
  if [ "$status" -ne 0 ] && [ "$MODIFIED" -eq 1 ]; then
    # 래퍼를 먼저 되돌려 새 서버 경로를 가리키지 않게 한다.
    restored=1
    cp -a "$BACKUP/run-wazuh-ro.sh" "$STAGE/run-wazuh-ro.restore" && mv -f "$STAGE/run-wazuh-ro.restore" "$WRAP" || restored=0
    if [ "$HAD_EVENTS" -eq 1 ]; then
      cp -a "$BACKUP/security-events-mcp.py" "$STAGE/security-events-mcp.restore" && mv -f "$STAGE/security-events-mcp.restore" "$EVENTS" || restored=0
    else
      rm -f "$EVENTS" || restored=0
    fi
    if [ "$restored" -eq 1 ]; then
      echo "deploy_security_events_B: 실패하여 기존 파일 복구 완료; 백업: $BACKUP" >&2
    else
      echo "deploy_security_events_B: 자동 복구 실패; $BACKUP 에서 수동 복구 필요" >&2
    fi
  fi
  [ -z "$STAGE" ] || rm -rf "$STAGE"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

[ "$(id -u)" -eq 0 ] || die "root로 실행해야 합니다"
[ -d /opt/mcp ] && id mcp >/dev/null 2>&1 && getent group mcp >/dev/null || die "기존 /opt/mcp 및 mcp 계정/그룹이 필요합니다"
[ -f "$WRAP" ] && [ ! -L "$WRAP" ] && [ -x /opt/mcp/mcp-server-wazuh ] || die "기존 Wazuh MCP 배치를 확인하세요"
[ -r /etc/mcp/wazuh-ro.env ] && [ -x /usr/bin/python3 ] && command -v runuser >/dev/null || die "기존 env, Python 또는 runuser가 없습니다"
for src in "$EVENTS_SRC" "$WRAP_SRC"; do
  [ -f "$src" ] && [ ! -L "$src" ] || die "일반 파일이 아닙니다: $src"
done

STAGE=$(mktemp -d /opt/mcp/.security-events-stage.XXXXXX)
install -o root -g mcp -m 0750 "$EVENTS_SRC" "$STAGE/security-events-mcp.py"
install -o root -g mcp -m 0750 "$WRAP_SRC" "$STAGE/run-wazuh-ro.sh"
bash -n "$STAGE/run-wazuh-ro.sh" || die "래퍼 구문 오류"
grep -Fq 'SSH_ORIGINAL_COMMAND:-}" = security-events' "$STAGE/run-wazuh-ro.sh" || die "래퍼에 security-events 분기가 없습니다"
grep -Fq 'exec "$BIN"' "$STAGE/run-wazuh-ro.sh" || die "래퍼에 기존 바이너리 경로가 없습니다"

# 자격증명이나 Indexer 호출 없이 구문·MCP initialize/tools/list를 확인한다.
check_tools() {
python3 -B - "$1" "$2" <<'PY'
import ast, json, subprocess, sys
path, mode = sys.argv[1:]
if mode == "direct":
    with open(path, encoding="utf-8") as source:
        ast.parse(source.read(), filename=path)
messages = [
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "deploy-preflight", "version": "1"}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
]
cmd = ["/usr/bin/python3", "-B", path] if mode == "direct" else ["runuser", "-u", "mcp", "--", "env", "-i", "PATH=/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE=1", "SSH_CONNECTION=local", "SSH_ORIGINAL_COMMAND=security-events", path]
p = subprocess.run(cmd, input="\n".join(map(json.dumps, messages)) + "\n", text=True, capture_output=True, timeout=10)
if p.returncode:
    raise SystemExit("MCP %s check exited with status %d" % (mode, p.returncode))
try:
    replies = [json.loads(line) for line in p.stdout.splitlines()]
    tools = next(reply["result"]["tools"] for reply in replies if reply.get("id") == 2)
    names = {tool["name"] for tool in tools}
except (ValueError, KeyError, StopIteration, TypeError) as exc:
    raise SystemExit("MCP %s protocol failed: %s" % (mode, type(exc).__name__))
if names != {"search_suricata_alerts", "search_modsecurity_alerts", "search_wazuh_alerts", "get_wazuh_sca_checks"}:
    raise SystemExit("MCP %s exposed unexpected tools" % mode)
print("MCP %s check: 4 read-only tools" % mode)
PY
}
check_tools "$STAGE/security-events-mcp.py" direct

BACKUP=$(mktemp -d /opt/mcp/.security-events-backup.XXXXXX)
cp -a "$WRAP" "$BACKUP/run-wazuh-ro.sh"
if [ -e "$EVENTS" ]; then
  [ -f "$EVENTS" ] && [ ! -L "$EVENTS" ] || die "기존 보안 이벤트 서버가 일반 파일이 아닙니다"
  cp -a "$EVENTS" "$BACKUP/security-events-mcp.py"
  HAD_EVENTS=1
fi

# 같은 파일시스템에서 각 rename을 원자적으로 수행한다. 새 서버를 먼저 설치해 래퍼가 없는 경로를 가리키지 않게 한다.
MODIFIED=1
mv -f "$STAGE/security-events-mcp.py" "$EVENTS"
mv -f "$STAGE/run-wazuh-ro.sh" "$WRAP"

# 실제 mcp 사용자와 래퍼 경유로도 도구 목록을 확인한다. Indexer 쿼리는 발생하지 않는다.
check_tools "$WRAP" wrapped

echo "배치 완료: $EVENTS, $WRAP (root:mcp 0750); 백업: $BACKUP"
echo "새 SSH 연결부터 적용됩니다. 서비스 재시작은 필요하지 않습니다."
