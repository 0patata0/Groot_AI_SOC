#!/usr/bin/env bash
# One entry point for fresh three-host installation from approved offline artifacts.
set -euo pipefail
umask 077

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
MODE=apply
CONFIG=
BATCH=0
SSH_USER=ubuntu
SSH_PORT=22
SSH_IDENTITY=
SSH_KNOWN_HOSTS=${HOME}/.ssh/known_hosts
SECURITY_HOST=
SIEM_HOST=
SERVICE_HOST=
MONITOR_INTERFACE=auto
WEB_BACKEND_PORT=80
WAF_PORT=8080
LLM_BASE_URL=
LLM_MODEL=qwen3.6:35b
LOG_PROTECTED_IPS=
ADMIN_PROTECTED_CIDRS=
ADMIN_INPUT_SET=0
MANAGEMENT_ALLOWED_CIDRS=
DASHBOARD_ALLOWED_CIDRS=
DASHBOARD_DENIED_CIDRS=192.168.15.0/24
CHAT_ALLOWED_CIDRS=
CAPSTONE_ROOT=/opt/capstone
SURICATA_IMAGE=
WAF_IMAGE=
ET_RULES_FILE=
DVWA_IMAGE=
MARIADB_IMAGE=
LOG4SHELL_IMAGE=
LOG4SHELL_APP_JAR=
LOG4SHELL_HOSTNAME=
LAB_PUBLIC_ORIGIN=
LAB_HTTPS_PORT=443
LAB_ALLOWED_CIDRS=
LAB_PROXY_SUBNET=172.30.247.0/29
LAB_GATEWAY_PORT=18091
LAB_WHEEL_DIR=/opt/capstone-prereqs/wheels
LAB_MANIFEST=/opt/capstone-prereqs/cve_list.json
LAB_ADMIN_KEY_FILE=/opt/capstone-prereqs/lab-admin.key
LAB_SUDO_BUNDLE=/opt/capstone-prereqs/sudo
LAB_NONWEB_BUNDLE=/opt/capstone-prereqs/nonweb
LAB_TLS_CERT=/opt/capstone-prereqs/lab-tls.crt
LAB_TLS_KEY=/opt/capstone-prereqs/lab-tls.key
WORK=
RUN_ID=
REMOTE_STAGE=
STAGED_HOSTS=()

say() { printf '%s\n' "$*"; }
die() { printf 'deploy: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
Usage: ./deploy.sh [--check|--apply|--verify|--plan] [--config FILE] [--batch]

Without a config, asks for security, siem, service IPv4 addresses, in that order.
--check   Validate offline bundles and all three roles; never install packages.
--apply   Validate bundles, install offline prerequisites, then all three roles.
--verify  Check the existing deployment without applying it again.
--plan    Validate inputs and print the plan; no SSH or local staging.
--batch   Require all inputs in the configuration; never prompt.

SSH host keys, sudo access and reviewed offline bundles must be prepared first.
Packages and docker-save images in each server's artifacts.json are installed
without downloads. Lab wheels, catalog, sudo/nonweb bundles and TLS files stay on servers.
See deployment/bootstrap-guide.md and deployment/config.example.conf.
EOF
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --check|--apply|--verify|--plan) MODE=${1#--}; shift ;;
    --config) [[ $# -ge 2 ]] || die '--config needs a file'; CONFIG=$2; shift 2 ;;
    --batch) BATCH=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

# This is data, never sourced or evaluated as shell code.
if [[ -n $CONFIG ]]; then
  [[ -f $CONFIG && ! -L $CONFIG ]] || die 'configuration must be a regular file'
  while IFS= read -r line || [[ -n $line ]]; do
    [[ -z $line || $line == \#* ]] && continue
    [[ $line != *$'\r'* && $line == *=* ]] || die 'configuration requires KEY=value lines (LF)'
    key=${line%%=*}; value=${line#*=}
    case "$key" in
      SECURITY_HOST|SIEM_HOST|SERVICE_HOST|SSH_USER|SSH_PORT|SSH_IDENTITY|SSH_KNOWN_HOSTS|MONITOR_INTERFACE|WEB_BACKEND_PORT|WAF_PORT|LLM_BASE_URL|LLM_MODEL|LOG_PROTECTED_IPS|ADMIN_PROTECTED_CIDRS|MANAGEMENT_ALLOWED_CIDRS|DASHBOARD_ALLOWED_CIDRS|DASHBOARD_DENIED_CIDRS|CHAT_ALLOWED_CIDRS|SURICATA_IMAGE|WAF_IMAGE|ET_RULES_FILE|DVWA_IMAGE|MARIADB_IMAGE|LOG4SHELL_IMAGE|LOG4SHELL_APP_JAR|LOG4SHELL_HOSTNAME|LAB_PUBLIC_ORIGIN|LAB_HTTPS_PORT|LAB_ALLOWED_CIDRS|LAB_PROXY_SUBNET|LAB_GATEWAY_PORT|LAB_WHEEL_DIR|LAB_MANIFEST|LAB_SUDO_BUNDLE|LAB_NONWEB_BUNDLE|LAB_TLS_CERT|LAB_TLS_KEY)
        [[ $value != *$'\t'* ]] || die "tab in configuration: $key"
        printf -v "$key" '%s' "$value"
        if [[ $key == ADMIN_PROTECTED_CIDRS ]]; then ADMIN_INPUT_SET=1; fi
        ;;
      *) die "unsupported configuration key: $key" ;;
    esac
  done < "$CONFIG"
fi
prompt() {
  local name=$1 label=$2 value
  value=${!name}
  [[ -n $value ]] && return
  [[ $BATCH == 0 && -t 0 ]] || die "missing $name; use --config or an interactive terminal"
  printf '%s: ' "$label" >&2
  IFS= read -r value || die 'input cancelled'
  [[ -n $value ]] || die "$name cannot be empty"
  printf -v "$name" '%s' "$value"
}
prompt SECURITY_HOST 'security 서버 초기 IPv4 주소'
prompt SIEM_HOST 'siem 서버 초기 IPv4 주소'
prompt SERVICE_HOST 'service 서버 초기 IPv4 주소'
if [[ $BATCH == 0 && -t 0 && -z $CONFIG ]]; then
  printf '공통 SSH 사용자 [ubuntu]: ' >&2; IFS= read -r answer || die 'input cancelled'
  [[ -z $answer ]] || SSH_USER=$answer
  printf 'SSH 개인키 경로 [기존 ssh-agent/기본키 사용]: ' >&2; IFS= read -r SSH_IDENTITY || die 'input cancelled'
  printf 'security 감시 인터페이스 [auto]: ' >&2; IFS= read -r answer || die 'input cancelled'
  [[ -z $answer ]] || MONITOR_INTERFACE=$answer

fi
prompt LAB_PUBLIC_ORIGIN 'Log4Shell HTTPS 주소 (예: https://lab.example.org)'
prompt LAB_ALLOWED_CIDRS '실습 허용 내부망/VPN CIDR (쉼표로 구분)'
prompt LLM_BASE_URL 'Ollama/OpenAI 호환 API 주소 (예: http://192.0.2.40:11434/v1)'
if [[ $ADMIN_INPUT_SET == 0 && $BATCH == 0 && -t 0 ]]; then
  printf '차단 예외 관리자 IPv4 또는 CIDR 대역 (쉼표 구분, 없으면 Enter): ' >&2
  IFS= read -r ADMIN_PROTECTED_CIDRS || die 'input cancelled'
fi
ipv4() {
  local ip=$1 part
  [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  local old_ifs=$IFS; IFS=.
  for part in $ip; do
    [[ $part == 0 || $part != 0* ]] || { IFS=$old_ifs; return 1; }
    [[ ${#part} -le 3 && $part -le 255 ]] || { IFS=$old_ifs; return 1; }
  done
  IFS=$old_ifs
  [[ $ip != 0.* && $ip != 127.* && $ip != 255.255.255.255 ]]
}
hostname_valid() {
  local name=$1 label; local -a labels
  [[ $name =~ ^[a-z0-9.-]+$ ]] || return 1
  [[ ${#name} -le 253 && $name == *.* && $name != .* && $name != *. && $name != *..* ]] || return 1
  IFS=. read -r -a labels <<<"$name"
  for label in "${labels[@]}"; do [[ $label =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || return 1; done
  [[ ${labels[${#labels[@]}-1]} =~ [a-z] ]]
}
for host in "$SECURITY_HOST" "$SIEM_HOST" "$SERVICE_HOST"; do ipv4 "$host" || die 'server addresses must be usable IPv4 literals'; done
[[ $SECURITY_HOST != "$SIEM_HOST" && $SECURITY_HOST != "$SERVICE_HOST" && $SIEM_HOST != "$SERVICE_HOST" ]] || die 'three separate server addresses are required'
[[ $SSH_USER =~ ^[a-z_][a-z0-9_-]*$ && ${#SSH_USER} -le 32 ]] || die 'invalid SSH user'
for port in "$SSH_PORT" "$WEB_BACKEND_PORT" "$WAF_PORT" "$LAB_HTTPS_PORT" "$LAB_GATEWAY_PORT"; do
  [[ $port =~ ^[1-9][0-9]*$ && ${#port} -le 5 && $port -le 65535 ]] || die 'invalid TCP port'
done
[[ -z $LOG4SHELL_IMAGE && -z $LOG4SHELL_APP_JAR && -z $LOG4SHELL_HOSTNAME ]] || die 'legacy LOG4SHELL_* options are retired; use LAB_PUBLIC_ORIGIN and LAB_MANIFEST'
command -v python3 >/dev/null || die 'controller requires existing python3'
python3 -B "$HERE/deployment/validate_lab_site.py" "$LAB_PUBLIC_ORIGIN" "$LAB_HTTPS_PORT" "$LAB_ALLOWED_CIDRS" "$LAB_PROXY_SUBNET" || die 'invalid lab site settings'
[[ $LAB_GATEWAY_PORT != "$WEB_BACKEND_PORT" && $LAB_GATEWAY_PORT != 22 && $LAB_GATEWAY_PORT != 18090 && $LAB_GATEWAY_PORT != 18081 && $LAB_GATEWAY_PORT != 18082 && $LAB_GATEWAY_PORT != 18083 ]] || die 'lab gateway port conflict'
[[ $LAB_HTTPS_PORT != "$SSH_PORT" && $LAB_HTTPS_PORT != "$WAF_PORT" ]] || die 'lab HTTPS port conflict'
for key in LAB_WHEEL_DIR LAB_MANIFEST LAB_SUDO_BUNDLE LAB_NONWEB_BUNDLE LAB_TLS_CERT LAB_TLS_KEY; do
  value=${!key}
  [[ $value =~ ^/opt/[A-Za-z0-9._/-]+$ && $value != *..* && $value != *//* && $value != */ ]] || die "invalid server artifact path: $key"
done
[[ $MONITOR_INTERFACE == auto || $MONITOR_INTERFACE =~ ^[a-zA-Z0-9_.:-]+$ ]] || die 'invalid monitor interface'
[[ $LLM_MODEL =~ ^[a-zA-Z0-9_./:-]+$ ]] || die 'invalid model name'
[[ $LLM_BASE_URL =~ ^https?://[a-zA-Z0-9.-]+(:[0-9]+)?/v1/?$ ]] || die 'LLM_BASE_URL must be an HTTP(S) /v1 URL without credentials, query or fragment'
LOG_PROTECTED_IPS=$(python3 -B "$HERE/deployment/protected_hosts.py" "$SECURITY_HOST" "$SIEM_HOST" "$SERVICE_HOST" "$LLM_BASE_URL" "$LOG_PROTECTED_IPS") || die 'invalid protected addresses'
ADMIN_PROTECTED_CIDRS=$(python3 -B "$HERE/deployment/protected_hosts.py" --admin-cidrs "$ADMIN_PROTECTED_CIDRS") || die 'invalid administrator IP/network exemptions'
for key in MANAGEMENT_ALLOWED_CIDRS DASHBOARD_ALLOWED_CIDRS DASHBOARD_DENIED_CIDRS CHAT_ALLOWED_CIDRS; do
  value=${!key}
  value=$(python3 -B "$HERE/deployment/protected_hosts.py" --admin-cidrs "$value") || die "invalid access CIDRs: $key"
  printf -v "$key" '%s' "$value"
done
say "입력: security=$SECURITY_HOST, siem=$SIEM_HOST, service=$SERVICE_HOST"
say '순서: 반입물·패키지 → 역할 사전검사 → SIEM → 공통 키·등록 자격 → service → security → 승인·대응 → 로그 처리·상관분석 → SOC 대시보드 → 고정 읽기 진단 → 전체 검증'
say 'SOC 구성: 정확 후보 승인 MCP·제한된 대응·Vector 정제/회전/보존·관측 모니터·통합 대시보드'
if [[ -n $ADMIN_PROTECTED_CIDRS ]]; then
  say "관리자 IP 차단 예외: $ADMIN_PROTECTED_CIDRS"
else
  say '관리자 IP 차단 예외: 추가 지정 없음'
fi
say 'service 구성: 독립 DVWA/MariaDB + Lab Console + 웹 실습3개 + Redis/Samba/sudo 터미널3개 (sudo는 별도 rootless) + Wazuh agent'
say "Lab Console: $LAB_PUBLIC_ORIGIN/log4shell/ (DNS/hosts와 TLS 인증서는 사전 준비)"
say '패키지/이미지 인터넷 다운로드 없음. 기존 IP·라우팅·SSH 설정은 변경하지 않습니다.'
[[ $MODE != plan ]] || exit 0

for tool in ssh tar mktemp python3; do command -v "$tool" >/dev/null || die "controller missing $tool; see README"; done
[[ -f $SSH_KNOWN_HOSTS && ! -L $SSH_KNOWN_HOSTS ]] || die 'prepare a verified SSH known_hosts file first (README)'
[[ -z $SSH_IDENTITY || -f $SSH_IDENTITY ]] || die 'SSH identity file not found'
SSH_ARGS=(-p "$SSH_PORT" -o BatchMode=yes -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$SSH_KNOWN_HOSTS" -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=2)
if [[ -n $SSH_IDENTITY ]]; then SSH_ARGS+=(-i "$SSH_IDENTITY" -o IdentitiesOnly=yes); fi
ssh_run() { local host=$1; shift; ssh "${SSH_ARGS[@]}" "$SSH_USER@$host" "$@"; }
cleanup() {
  local rc=$? host
  trap - EXIT
  if [[ -n $REMOTE_STAGE ]]; then
    for host in ${STAGED_HOSTS[@]+"${STAGED_HOSTS[@]}"}; do
      ssh_run "$host" "sudo -n bash -c 'if [ -d $REMOTE_STAGE ] && [ ! -L $REMOTE_STAGE ]; then rm -rf -- $REMOTE_STAGE; fi'" >/dev/null 2>&1 || printf '원격 임시폴더 수동 정리 필요: %s:%s\n' "$host" "$REMOTE_STAGE" >&2
    done
  fi
  if [[ -n $WORK && -d $WORK ]]; then rm -rf -- "$WORK"; fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
WORK=$(mktemp -d "${TMPDIR:-/tmp}/capstone-deploy.XXXXXXXX")
RUN_ID=$(python3 -B -c 'import secrets; print(secrets.token_hex(12))')
REMOTE_STAGE=/var/tmp/capstone-bootstrap-$RUN_ID
mkdir "$WORK/bundle"
cat > "$WORK/bundle/site.env" <<EOF
# Generated data; values are shell-quoted by the controller below.
EOF
for key in SECURITY_HOST SIEM_HOST SERVICE_HOST SSH_PORT MONITOR_INTERFACE WEB_BACKEND_PORT WAF_PORT LLM_BASE_URL LLM_MODEL LOG_PROTECTED_IPS ADMIN_PROTECTED_CIDRS MANAGEMENT_ALLOWED_CIDRS DASHBOARD_ALLOWED_CIDRS DASHBOARD_DENIED_CIDRS CHAT_ALLOWED_CIDRS CAPSTONE_ROOT LAB_PUBLIC_ORIGIN LAB_HTTPS_PORT LAB_ALLOWED_CIDRS LAB_PROXY_SUBNET LAB_GATEWAY_PORT LAB_WHEEL_DIR LAB_MANIFEST LAB_ADMIN_KEY_FILE LAB_SUDO_BUNDLE LAB_NONWEB_BUNDLE LAB_TLS_CERT LAB_TLS_KEY; do
  value=${!key}
  printf 'export %s=%q\n' "$key" "$value" >> "$WORK/bundle/site.env"
done
for key in SURICATA_IMAGE WAF_IMAGE ET_RULES_FILE DVWA_IMAGE MARIADB_IMAGE; do
  value=${!key}
  [[ -z $value ]] || printf 'export %s=%q\n' "$key" "$value" >> "$WORK/bundle/site.env"
done
# Explicit source roots. Credentials, Git history, local configuration and datasets
# are never sent. Temporary files created by this script live only under WORK.
tar -C "$HERE" --exclude='*.local.*' --exclude='.env' --exclude='*CREDENTIAL*' --exclude='*credentials*' --exclude='*secrets*.env' --exclude='secrets' --exclude='*.key' --exclude='*.pem' --exclude='__pycache__' --exclude='*.pyc' --exclude='*.jar' --exclude='*.class' --exclude='.gradle' --exclude='infra/groot-c/log4shell-app/build' -cf "$WORK/bundle/source.tar" deployment infra new_rule
PAYLOAD_SHA=$(python3 -B - "$WORK/bundle/source.tar" <<'PY'
import hashlib,sys
with open(sys.argv[1],'rb') as f:
    h=hashlib.sha256()
    for b in iter(lambda:f.read(1048576),b''): h.update(b)
print(h.hexdigest())
PY
)
printf 'export CAPSTONE_RELEASE=%q\n' "$PAYLOAD_SHA" >> "$WORK/bundle/site.env"
tar -C "$WORK/bundle" -cf "$WORK/payload.tar" site.env source.tar

stage() {
  local host=$1
  # Root-owned, unpredictable, nonexisting path; extraction is never into / or $HOME.
  ssh_run "$host" "sudo -n bash -c 'umask 077; mkdir -- $REMOTE_STAGE'" || die "SSH/sudo prerequisite failed: $host"
  STAGED_HOSTS+=("$host")
  ssh_run "$host" "sudo -n tar --no-same-owner -xf - -C $REMOTE_STAGE" < "$WORK/payload.tar" || die "staging failed: $host"
  ssh_run "$host" "sudo -n bash -c 'set -eu; mkdir $REMOTE_STAGE/source; tar --no-same-owner -xf $REMOTE_STAGE/source.tar -C $REMOTE_STAGE/source; chmod -R go-rwx $REMOTE_STAGE'" || die "source extraction failed: $host"
}
remote_role() {
  local host=$1 role=$2 action=$3
  ssh_run "$host" "sudo -n bash $REMOTE_STAGE/source/deployment/remote.sh $REMOTE_STAGE $role $action"
}
for host in "$SECURITY_HOST" "$SIEM_HOST" "$SERVICE_HOST"; do stage "$host"; done
ids=()
for host in "$SECURITY_HOST" "$SIEM_HOST" "$SERVICE_HOST"; do
  identity=$(ssh_run "$host" 'cat /etc/machine-id') || die "cannot identify $host"
  [[ $identity =~ ^[0-9a-f]{32}$ ]] || die "invalid machine-id: $host"
  for previous in ${ids[@]+"${ids[@]}"}; do [[ $identity != "$previous" ]] || die 'two addresses resolve to the same server'; done
  ids+=("$identity")
done
if [[ $MODE == verify ]]; then
  remote_role "$SIEM_HOST" siem verify
  remote_role "$SERVICE_HOST" service verify
  remote_role "$SECURITY_HOST" security verify
  remote_role "$SECURITY_HOST" security soc-verify
  remote_role "$SECURITY_HOST" security log-verify
  remote_role "$SIEM_HOST" siem soc-verify
  remote_role "$SIEM_HOST" siem log-verify
  remote_role "$SIEM_HOST" siem dashboard-verify
  remote_role "$SECURITY_HOST" security diag-verify
  remote_role "$SERVICE_HOST" service diag-verify
  remote_role "$SIEM_HOST" siem diag-verify
  remote_role "$SIEM_HOST" siem tls-verify
  remote_role "$SERVICE_HOST" service host-verify
  remote_role "$SIEM_HOST" siem host-verify
  say '세 역할과 SOC 확장 검증 완료.'
  exit 0
fi
remote_prerequisites() {
  local host=$1 role=$2 action=$3
  ssh_run "$host" "sudo -n python3 -B $REMOTE_STAGE/source/deployment/prerequisites.py $action $role"
}
remote_prerequisites "$SECURITY_HOST" security check
remote_prerequisites "$SIEM_HOST" siem check
remote_prerequisites "$SERVICE_HOST" service check
ssh_run "$SIEM_HOST" "sudo -n python3 -B $REMOTE_STAGE/source/deployment/lab_key.py check"
if [[ $MODE == apply ]]; then
  remote_prerequisites "$SECURITY_HOST" security apply
  remote_prerequisites "$SIEM_HOST" siem apply
  remote_prerequisites "$SERVICE_HOST" service apply
fi
remote_role "$SECURITY_HOST" security check
remote_role "$SIEM_HOST" siem check
remote_role "$SERVICE_HOST" service check
remote_role "$SECURITY_HOST" security soc-check
remote_role "$SIEM_HOST" siem soc-check
remote_role "$SIEM_HOST" siem dashboard-check
remote_role "$SECURITY_HOST" security diag-check
remote_role "$SIEM_HOST" siem diag-check
remote_role "$SERVICE_HOST" service diag-check
remote_role "$SERVICE_HOST" service host-check
remote_role "$SIEM_HOST" siem host-check
say '세 서버 사전검사 통과.'
[[ $MODE != check ]] || exit 0

remote_role "$SIEM_HOST" siem apply
remote_role "$SIEM_HOST" siem verify
transfer_enrollment() {
  local host=$1
  # TLS CA + enrollment credential pass directly through pipes. Neither
  # the credential nor a private key is put on the controller disk or in argv.
  ssh_run "$SIEM_HOST" "sudo -n bash -c 'set -eu; cd /opt/capstone; test -f exports/wazuh-enrollment-ca.pem; test -f secrets/enrollment.pass; tar -cf - exports/wazuh-enrollment-ca.pem secrets/enrollment.pass'" |
    ssh_run "$host" "sudo -n bash $REMOTE_STAGE/source/deployment/receive-enrollment.sh" || die "enrollment transfer failed: $host"
}
transfer_enrollment "$SERVICE_HOST"
transfer_enrollment "$SECURITY_HOST"
# The existing SIEM admin credential is streamed through SSH directly to C.
# No secret appears in arguments, controller files, terminal output or Git.
ssh_run "$SIEM_HOST" "sudo -n python3 -B $REMOTE_STAGE/source/deployment/lab_key.py export" |
  ssh_run "$SERVICE_HOST" "sudo -n python3 -B $REMOTE_STAGE/source/deployment/lab_key.py receive" || die 'common lab key transfer failed'
remote_role "$SERVICE_HOST" service apply
remote_role "$SERVICE_HOST" service verify
remote_role "$SECURITY_HOST" security apply
remote_role "$SECURITY_HOST" security verify
# Only the public SIEM CA crosses SSH. No CA private key leaves the SIEM.
remote_role "$SIEM_HOST" siem tls-install
remote_role "$SIEM_HOST" siem tls-export |
  remote_role "$SECURITY_HOST" security tls-trust || die 'internal TLS CA transfer failed'
remote_role "$SIEM_HOST" siem soc-prepare
# Dedicated response credentials pass directly between root-owned endpoints.
# stdout for these phases is exclusively the bounded transfer protocol.
remote_role "$SIEM_HOST" siem soc-export |
  remote_role "$SECURITY_HOST" security soc-receive || die 'SOC credential transfer failed'
# This result is public host-key/agent/container identity only. Retain it in
# this invocation's private scratch directory while finishing the log gates.
remote_role "$SECURITY_HOST" security soc-apply > "$WORK/security-soc.json"
remote_role "$SECURITY_HOST" security log-activate
remote_role "$SIEM_HOST" siem log-monitor
remote_role "$SIEM_HOST" siem dashboard-apply
# The LLM management timer starts after its evidence sources are configured.
remote_role "$SIEM_HOST" siem soc-activate < "$WORK/security-soc.json"
# A separate read-only key can fetch only each host's root-published snapshot.
# It is never authorized for a shell, sudo, Docker or a caller-selected journal.
remote_role "$SIEM_HOST" siem diag-prepare
remote_role "$SIEM_HOST" siem diag-export |
  remote_role "$SECURITY_HOST" security diag-apply > "$WORK/security-diagnostics.json" || die 'security diagnostic reader setup failed'
remote_role "$SIEM_HOST" siem diag-export |
  remote_role "$SERVICE_HOST" service diag-apply > "$WORK/service-diagnostics.json" || die 'service diagnostic reader setup failed'
python3 - "$WORK/security-diagnostics.json" "$WORK/service-diagnostics.json" <<'PY' |
import json, pathlib, sys
values=[]
for name in sys.argv[1:]:
    raw=pathlib.Path(name).read_bytes()
    if len(raw)>16384: raise SystemExit('diagnostic host identity too large')
    values.append(json.loads(raw))
print(json.dumps(values,sort_keys=True,separators=(',',':')))
PY
  remote_role "$SIEM_HOST" siem diag-activate || die 'diagnostic transport activation failed'
# Host management and the old default Docker bridge must not bypass the
# dedicated lab guards. Preserve the authenticated controller's SSH source.
remote_role "$SERVICE_HOST" service host-apply
remote_role "$SIEM_HOST" siem host-apply
remote_role "$SERVICE_HOST" service host-verify
remote_role "$SIEM_HOST" siem host-verify
remote_role "$SECURITY_HOST" security verify
remote_role "$SECURITY_HOST" security soc-verify
remote_role "$SECURITY_HOST" security log-verify
remote_role "$SIEM_HOST" siem verify
remote_role "$SIEM_HOST" siem soc-verify
remote_role "$SIEM_HOST" siem log-verify
remote_role "$SIEM_HOST" siem dashboard-verify
remote_role "$SECURITY_HOST" security diag-verify
remote_role "$SERVICE_HOST" service diag-verify
remote_role "$SIEM_HOST" siem diag-verify
remote_role "$SIEM_HOST" siem tls-verify
say "구축 완료. WAF: http://$SECURITY_HOST:$WAF_PORT / SIEM: https://$SIEM_HOST / Mattermost: https://$SIEM_HOST:8444"
say "Lab Console: $LAB_PUBLIC_ORIGIN/log4shell/"
say "DVWA 독립 진입점: http://$SECURITY_HOST:$WAF_PORT/dvwa/"
say '인증 정보는 서버의 root 전용 경로에 보관합니다. 결과와 지원 범위는 README를 확인하세요.'
