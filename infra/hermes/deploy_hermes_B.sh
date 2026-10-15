#!/bin/bash
# Groot_B: Hermes Agent(공식 Docker 이미지 nousresearch/hermes-agent, 오프라인 반입) 배치 + MCP 연결 검증. 게이트형. sudo bash 로 실행.
#   prep        : 호스트 사용자 hermes(격리) + 데이터 디렉터리 + 컨테이너용 SSH 키/설정 + config.yaml + B(mcp 계정) 키 등록 + 호스트에서 MCP 계약 테스트
#   load <tar>  : 반입한 이미지 tar(OCI layout) 를 docker load (태그 확인/보정)
#   test        : 컨테이너에서 MCP 연결 검증(LLM 불필요) — 계약 테스트 + chat -q 기동 후 agent.log 'MCP: registered …' 확인
# 자격증명 격리(A안): hermes 사용자는 mcp 그룹이 아님 → /etc/mcp/*.env 접근 불가. MCP 는 sshd ForceCommand 경계(mcp@B, resp@A)로만.
set -euo pipefail
# BEGIN managed-prestart legacy gate
case "${1:-}" in
  prep|test|all)
    if [[ -e /etc/capstone-hermes-guard || -L /etc/capstone-hermes-guard ||
          -e /var/lib/capstone-automation/hermes-guard || -L /var/lib/capstone-automation/hermes-guard ]]; then
      printf '%s\n' 'Legacy Hermes deployment blocked: managed guard state exists. Review the fixed root prestart path infra/automation/ansible/hermes-prestart-local-b.sh.' >&2
      exit 78
    fi
    ;;
esac
# END managed-prestart legacy gate
IMG=${IMG:-nousresearch/hermes-agent:v2026.9.24}
DATA=/opt/hermes-data          # 컨테이너의 /opt/data (HERMES_HOME)
HUSER=hermes
KEY=$DATA/home/.ssh/id_ed25519
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*"; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"

prep(){
  say "P1 host user '$HUSER' (system, nologin, NOT in group mcp) + $DATA"
  id "$HUSER" >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin "$HUSER"
  id -nG "$HUSER" | grep -qw mcp && die "$HUSER must not be in group mcp (credential isolation)"
  mkdir -p "$DATA/home/.ssh" "$DATA/logs"
  say "P2 container SSH key + ssh config (mcp-b / resp-a)"
  [ -f "$KEY" ] || ssh-keygen -q -t ed25519 -N "" -C "hermes-agent@groot-siem" -f "$KEY"
  cat > "$DATA/home/.ssh/config" <<CFG
# Hermes(컨테이너) → MCP 서버. 경로는 컨테이너 기준(/opt/data). sshd ForceCommand 경계 유지 — 자격증명은 서버 쪽에만.
Host mcp-b
    HostName 10.200.10.10
    User mcp
    IdentityFile /opt/data/home/.ssh/id_ed25519
    IdentitiesOnly yes
    BatchMode yes
    UserKnownHostsFile /opt/data/home/.ssh/known_hosts
    StrictHostKeyChecking accept-new
    ServerAliveInterval 30
Host resp-a
    HostName 10.200.10.1
    User resp
    IdentityFile /opt/data/home/.ssh/id_ed25519
    IdentitiesOnly yes
    BatchMode yes
    UserKnownHostsFile /opt/data/home/.ssh/known_hosts
    StrictHostKeyChecking accept-new
    ServerAliveInterval 30
CFG
  say "P3 config.yaml (mcp_servers: wazuh-ro=full / resp=untrusted → 쓰기 툴은 사람 승인)"
  [ -f "$DATA/config.yaml" ] && cp -a "$DATA/config.yaml" "$DATA/config.yaml.bak.$(date +%Y%m%d%H%M%S)"
  cat > "$DATA/config.yaml" <<YML
# Hermes Agent — Groot SOC (Groot_B, Docker). MCP 서버 2개를 stdio over SSH 로 등록. 실제 자격증명은 여기 없음.
mcp_servers:
  wazuh-ro:
    command: ssh
    args: ["-T", "-F", "/opt/data/home/.ssh/config", "mcp-b"]
    env:
      HOME: /opt/data/home
    connect_timeout: 60
    timeout: 180
    supports_parallel_tool_calls: false
    tools:
      resources: false
      prompts: false
    trust: full
  resp:
    command: ssh
    args: ["-T", "-F", "/opt/data/home/.ssh/config", "resp-a"]
    env:
      HOME: /opt/data/home
    connect_timeout: 60
    timeout: 180
    supports_parallel_tool_calls: false
    tools:
      resources: false
      prompts: false
    trust: untrusted
security:
  allow_lazy_installs: false
YML
  chown -R "$HUSER:$HUSER" "$DATA"; chmod 700 "$DATA/home/.ssh"; chmod 600 "$KEY" "$DATA/home/.ssh/config"; chmod 644 "$KEY.pub"
  say "P4 register pubkey on B (mcp account, same restrict,command prefix)"
  PUB=$(cat "$KEY.pub"); AK=/opt/mcp/.ssh/authorized_keys
  grep -qF "$PUB" "$AK" || printf 'restrict,command="/opt/mcp/run-wazuh-ro.sh" %s\n' "$PUB" >> "$AK"
  echo "  B: $(grep -c 'ssh-' "$AK") key(s) in $AK"
  echo "  A(resp) needs this line in /opt/resp/.ssh/authorized_keys:"
  echo "PUBKEY_LINE_FOR_A=restrict,command=\"/opt/resp/run-response.sh\" $PUB"
  say "P5 host-side MCP contract test as '$HUSER' (no container yet; proves key + sshd boundary)"
  install -m 644 -o "$HUSER" -g "$HUSER" "$(dirname "$0")/contract_test.py" "$DATA/contract_test.py" 2>/dev/null || cp /opt/mcp/contract_test.py "$DATA/contract_test.py"
  chown "$HUSER:$HUSER" "$DATA/contract_test.py"
  SSHOPTS="-T -i $KEY -o IdentitiesOnly=yes -o BatchMode=yes -o UserKnownHostsFile=$DATA/home/.ssh/known_hosts -o StrictHostKeyChecking=accept-new"
  runuser -u "$HUSER" -- python3 "$DATA/contract_test.py" --cmd "ssh $SSHOPTS mcp@10.200.10.10" 2>&1 | tail -6
  chown "$HUSER:$HUSER" "$DATA/home/.ssh/known_hosts" 2>/dev/null || true
  echo "PREP_DONE uid=$(id -u "$HUSER") gid=$(id -g "$HUSER")"
}

load(){
  TAR=${1:?tar path}; [ -f "$TAR" ] || die "no $TAR"
  say "L1 docker load $TAR ($(du -h "$TAR" | cut -f1))"
  OUT=$(docker load -i "$TAR" 2>&1); echo "$OUT" | tail -3
  if ! docker image inspect "$IMG" >/dev/null 2>&1; then
    ID=$(echo "$OUT" | grep -oE 'sha256:[0-9a-f]{64}' | tail -1); [ -n "$ID" ] || die "cannot find loaded image id"
    docker tag "$ID" "$IMG"; echo "  tagged $ID → $IMG"
  fi
  docker image inspect "$IMG" --format '  {{.RepoTags}} size={{.Size}} arch={{.Architecture}} created={{.Created}}'
}

test_mcp(){
  # 주의: 이미지 v2026.9.24 에는 mcp[cli](typer) 가 없어 `hermes mcp test` 가 안 됨(실측). 대신
  #  T1 컨테이너 안에서 stdlib 계약 테스트(컨테이너의 ssh·키·네트워크 검증) + T2 Hermes 본체 기동(chat -q; 모델 없어도
  #  MCP eager-connect 후 setup 안내에서 멈춤) → agent.log 의 "MCP: registered N tool(s) from M server(s)" 로 검증.
  id "$HUSER" >/dev/null 2>&1 || die "run prep first"
  docker image inspect "$IMG" >/dev/null 2>&1 || die "image missing; run load"
  UID_=$(id -u "$HUSER"); GID_=$(id -g "$HUSER")
  RUN="docker run --rm -e HERMES_UID=$UID_ -e HERMES_GID=$GID_ -v $DATA:/opt/data $IMG"
  say "T1 container-side contract tests (stdlib)"
  for s in "mcp-b get_wazuh_alert_summary" "resp-a list_blocks"; do set -- $s
    echo "  --- $1 ($2) ---"
    timeout 150 $RUN bash -c "python3 /opt/data/contract_test.py --cmd 'ssh -T -F /opt/data/home/.ssh/config $1' --tool $2 --args '{}' 2>&1 | grep -E 'RESULT|tools/call|tools/list'" 2>&1 \
      | grep -vE "s6-rc|cont-init|supervise|reconcile|preinit|stage2|Syncing|Done:" | sed 's/^/    /' || true
  done
  say "T2 Hermes own MCP client: chat -q (no model → stops at setup prompt after MCP registration) → agent.log"
  mkdir -p "$DATA/logs"; : > "$DATA/logs/agent.log"; chown "$HUSER:$HUSER" "$DATA/logs/agent.log"
  timeout 180 $RUN chat -q "mcp check" >/dev/null 2>&1 || true
  grep -h 'MCP' "$DATA/logs/agent.log" | sed 's/^/  /' | tail -4
  grep -q 'MCP: registered' "$DATA/logs/agent.log" && echo "HERMES_MCP_OK" || die "no MCP registration in agent.log (see $DATA/logs/mcp-stderr.log)"
}

case "${1:-}" in
  prep) prep;;
  load) load "${2:-}";;
  test) test_mcp;;
  all)  prep; load "${2:-}"; test_mcp;;
  *) echo "usage: $0 prep | load <tar> | test | all <tar>"; exit 1;;
esac
