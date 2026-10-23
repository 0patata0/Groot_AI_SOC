#!/usr/bin/env bash
# Portable, fresh-host IDS/WAF/agent core. No package installation or downloads.
# Existing managed raw/Vector deployments must use their own upgrade procedure.
# Base phase; deploy.sh subsequently installs the bounded SOC response extension.
# No adoption of existing raw state or network NAT/routing. The base nft table
# is additive and ACCEPT-only, not a perimeter firewall.
set -euo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C.UTF-8 TZ="${TZ:-Asia/Seoul}" PYTHONDONTWRITEBYTECODE=1
unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH COMPOSE_FILE COMPOSE_PROJECT_NAME COMPOSE_PROFILES
export DOCKER_HOST=unix:///var/run/docker.sock

die() { printf 'security: %s\n' "$*" >&2; exit 1; }
usage() { printf 'usage: bash security.sh check|apply|verify\n' >&2; exit 64; }
[[ $# == 1 ]] || usage
MODE=$1
[[ $MODE == check || $MODE == apply || $MODE == verify ]] || usage
[[ $EUID == 0 ]] || die 'root is required'

: "${CAPSTONE_SOURCE:?uploaded repository path is required}"
: "${SECURITY_HOST:?IPv4 is required}"
: "${SIEM_HOST:?IPv4 is required}"
: "${SERVICE_HOST:?IPv4 is required}"
: "${MONITOR_INTERFACE:?capture interface is required}"
CAPSTONE_ROOT=${CAPSTONE_ROOT:-/opt/capstone}
WEB_BACKEND_PORT=${WEB_BACKEND_PORT:-80}
WAF_PORT=${WAF_PORT:-8080}
ET_RULES_FILE=${ET_RULES_FILE:-/opt/capstone-prereqs/suricata.rules}
WAZUH_CA_FILE=${WAZUH_CA_FILE:-/opt/capstone-prereqs/wazuh-root-ca.pem}
WAZUH_ENROLLMENT_PASS_FILE=${WAZUH_ENROLLMENT_PASS_FILE:-/opt/capstone-prereqs/wazuh-enrollment.pass}
SURICATA_IMAGE=${SURICATA_IMAGE:-jasonish/suricata:8.0.6}
WAF_IMAGE=${WAF_IMAGE:-owasp/modsecurity-crs:nginx}
: "${LAB_PUBLIC_ORIGIN:?explicit HTTPS lab origin is required}"
: "${LAB_ALLOWED_CIDRS:?explicit private client/VPN CIDRs are required}"
LAB_HTTPS_PORT=${LAB_HTTPS_PORT:-443}
LAB_PROXY_SUBNET=${LAB_PROXY_SUBNET:-172.30.247.0/29}
LAB_GATEWAY_PORT=${LAB_GATEWAY_PORT:-18091}
LAB_TLS_CERT=${LAB_TLS_CERT:-/opt/capstone-prereqs/lab-tls.crt}
LAB_TLS_KEY=${LAB_TLS_KEY:-/opt/capstone-prereqs/lab-tls.key}
ROLE_DIR=$CAPSTONE_ROOT/security
COMPOSE=$ROLE_DIR/compose.json
STATE=$ROLE_DIR/deployment.json
CONF=/var/ossec/etc/ossec.conf
NFT_UNIT=capstone-portable-firewall.service
WAF_NAME=capstone-security-waf
SURI_NAME=capstone-security-suricata
EDGE_NAME=capstone-security-lab-edge
TEST_NAME=capstone-security-rulecheck
TEST_CID=''
export CAPSTONE_ROOT CAPSTONE_SOURCE SECURITY_HOST SIEM_HOST SERVICE_HOST MONITOR_INTERFACE
export WEB_BACKEND_PORT WAF_PORT ET_RULES_FILE WAZUH_CA_FILE WAZUH_ENROLLMENT_PASS_FILE ROLE_DIR
export LAB_PUBLIC_ORIGIN LAB_ALLOWED_CIDRS LAB_HTTPS_PORT LAB_PROXY_SUBNET LAB_GATEWAY_PORT LAB_TLS_CERT LAB_TLS_KEY
lab_security() { python3 -B "$CAPSTONE_SOURCE/deployment/offline_security.py" "$1"; }
log_pipeline() { python3 -B "$CAPSTONE_SOURCE/deployment/log_pipeline.py" "$1" security; }

bounded() { timeout --signal=TERM --kill-after=5s "$@"; }
hash() { local x; x=$(sha256sum -- "$1") || return 1; printf '%s' "${x%% *}"; }
safe_file() {
    python3 - "$1" "${2:-67108864}" <<'PY'
import os, pathlib, re, stat, sys
p=pathlib.Path(sys.argv[1]); limit=int(sys.argv[2])
assert p.is_absolute() and '..' not in p.parts
source=pathlib.Path(os.environ['CAPSTONE_SOURCE'])
staged=bool(re.fullmatch(r'/var/tmp/capstone-bootstrap-[0-9a-f]{24}/source',str(source))) and p.is_relative_to(source)
if staged:
    stage=source.parent; s=stage.lstat()
    assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700
for parent in reversed(p.parents):
    s=parent.lstat()
    anchor=staged and parent==pathlib.Path('/var/tmp') and stat.S_IMODE(s.st_mode)==0o1777
    assert stat.S_ISDIR(s.st_mode) and s.st_uid==0 and (anchor or not (s.st_mode & 0o022)), 'unsafe parent'
s=p.lstat()
assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and not (s.st_mode & 0o022)
assert 0<s.st_size<=limit, 'file size outside limit'
PY
}
compose() { bounded 300s docker compose --project-name capstone-security --file "$COMPOSE" "$@"; }
cleanup_native_test() {
    [[ -n $TEST_CID ]] || return 0
    local identity running
    identity=$(bounded 10s docker inspect --format '{{.Id}}:{{index .Config.Labels "io.capstone.portable.rulecheck"}}' "$TEST_CID") || return 1
    [[ $identity == "$TEST_CID:$PROFILE" ]] || return 1
    running=$(bounded 10s docker inspect --format '{{.State.Running}}' "$TEST_CID") || return 1
    if [[ $running == true ]]; then
        # Only this private, network-less syntax-test container is eligible.
        bounded 15s docker kill --signal KILL "$TEST_CID" >/dev/null || return 1
    fi
    bounded 15s docker rm "$TEST_CID" >/dev/null || return 1
    TEST_CID=''
}

preflight() {
    local cmd name names
    for cmd in python3 docker jq nft ip ss curl openssl sha256sum timeout systemctl stat install flock getent sync; do
        command -v "$cmd" >/dev/null || die "manually install prerequisite: $cmd"
    done
    python3 - <<'PY'
import ipaddress, os, pathlib, platform, re
release={k:v.strip('"') for k,v in (line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)}
assert release.get('ID')=='ubuntu' and release.get('VERSION_ID')=='24.04'
assert platform.machine()=='x86_64'
hosts=[ipaddress.IPv4Address(os.environ[k]) for k in ('SECURITY_HOST','SIEM_HOST','SERVICE_HOST')]
assert len(set(hosts))==3 and all(not (h.is_multicast or h.is_unspecified or h.is_loopback) for h in hosts)
for k in ('CAPSTONE_ROOT','CAPSTONE_SOURCE','ET_RULES_FILE','WAZUH_CA_FILE','WAZUH_ENROLLMENT_PASS_FILE'):
    v=os.environ[k]
    assert re.fullmatch(r'/[A-Za-z0-9._/-]+',v) and '..' not in pathlib.PurePosixPath(v).parts and v!='/'
assert os.environ['CAPSTONE_ROOT'].startswith('/opt/')
assert re.fullmatch(r'[A-Za-z0-9_.:-]{1,32}',os.environ['MONITOR_INTERFACE'])
assert os.environ['TZ']=='Asia/Seoul'
for k in ('WEB_BACKEND_PORT','WAF_PORT'):
    v=os.environ[k]; assert v.isascii() and v.isdecimal() and 1<=int(v)<=65535
assert int(os.environ['WAF_PORT']) not in (22,1514,1515)
PY
    [[ -d /run/systemd/system ]] || die 'systemd host required'
    [[ -x /usr/sbin/nft ]] || die 'expected Ubuntu nft binary missing'
    bounded 15s docker info --format '{{.OSType}}' | grep -qx linux || die 'local Linux Docker unavailable'
    bounded 10s docker compose version >/dev/null || die 'manually install Docker Compose plugin'
    if [[ $MONITOR_INTERFACE == auto ]]; then
        MONITOR_INTERFACE=$(ip -j route get "$SIEM_HOST" | jq -er 'if length==1 then .[0].dev else error("route ambiguity") end') || die 'cannot choose capture interface; set MONITOR_INTERFACE'
        [[ $MONITOR_INTERFACE =~ ^[A-Za-z0-9_.:-]{1,32}$ && $MONITOR_INTERFACE != lo ]] || die 'invalid capture interface from route'
        export MONITOR_INTERFACE
    fi
    ip link show dev "$MONITOR_INTERFACE" >/dev/null || die 'capture interface not found'
    ip -j address show | jq -e --arg ip "$SECURITY_HOST" '[.[].addr_info[]? | select(.family=="inet" and .local==$ip)]|length>0' >/dev/null || die 'SECURITY_HOST is not assigned on this host'
    ip -j route get "$SERVICE_HOST" | jq -e --arg ip "$SECURITY_HOST" 'length==1 and (.[0].prefsrc // .[0].src)==$ip' >/dev/null || die 'backend route source differs from SECURITY_HOST; fix routing before deployment'
    for name in /opt/suricata /home/groot_a/capstone/secstack; do
        [[ ! -e $name && ! -L $name ]] || die 'existing legacy/managed security deployment; refuse overwrite'
    done
    for name in /var/lib/capstone-raw-operations /var/lib/capstone-raw-migration; do
        if [[ -e $name || -L $name ]]; then
            # These namespaces are also produced by the new extension. Their
            # own full receipt/pins are checked below; never adopt legacy state.
            [[ -f $STATE && ! -L $STATE && -f $ROLE_DIR/log-pipeline/receipt.json && ! -L $ROLE_DIR/log-pipeline/receipt.json && ! -L $name ]] ||
                die 'unowned raw pipeline exists; refuse overwrite'
        fi
    done
    names=$(bounded 15s docker ps -a --format '{{.Names}}') || die 'container inventory failed'
    if grep -Eqi 'groot|^(waf|suricata|chatproxy)$|^single-node-wazuh' <<< "$names"; then
        die 'legacy or another role container exists'
    fi
    for name in "$CAPSTONE_ROOT" "$ROLE_DIR"; do
        [[ ! -L $name ]] || die 'deployment path is a symlink'
        if [[ -e $name ]]; then
            [[ -d $name && $(stat -c %u "$name") == 0 ]] || die 'unsafe deployment directory'
            (( (8#$(stat -c %a "$name") & 0022)==0 )) || die 'writable deployment directory'
        fi
    done
    safe_file "$CAPSTONE_SOURCE/deployment/offline_security.py" 2097152
    safe_file "$CAPSTONE_SOURCE/deployment/validate_lab_site.py" 1048576
    for name in nginx-log4shell-server.conf waf-log4shell-server.conf REQUEST-900-CAPSTONE-LABS.conf; do
        safe_file "$CAPSTONE_SOURCE/infra/groot-c/offline-labs/$name" 2097152
    done
    safe_file "$CAPSTONE_SOURCE/new_rule/GROOT_A_WAF.conf" 2097152
    safe_file "$CAPSTONE_SOURCE/new_rule/GROOT_A_local.rules" 2097152
    safe_file "$ET_RULES_FILE" 100000000
    CA_SHA=pending-bootstrap
    if [[ -e $WAZUH_CA_FILE || -L $WAZUH_CA_FILE ]]; then
        safe_file "$WAZUH_CA_FILE" 1048576
        bounded 5s openssl x509 -in "$WAZUH_CA_FILE" -noout -checkend 86400 >/dev/null || die 'invalid public enrollment CA'
        CA_SHA=$(hash "$WAZUH_CA_FILE")
    else
        [[ $MODE == check && ! -e $STATE ]] || die 'SIEM enrollment CA bootstrap missing'
    fi
    if [[ -e $WAZUH_ENROLLMENT_PASS_FILE || -L $WAZUH_ENROLLMENT_PASS_FILE ]]; then
        safe_file "$WAZUH_ENROLLMENT_PASS_FILE" 4096
        [[ $(stat -c %a "$WAZUH_ENROLLMENT_PASS_FILE") == 600 ]] || die 'enrollment secret must be root0600'
    else
        [[ $MODE == check && ! -e $STATE ]] || die 'SIEM enrollment password bootstrap missing'
    fi
    [[ -x /var/ossec/bin/wazuh-agentd && -x /var/ossec/bin/wazuh-logcollector && -f $CONF && ! -L $CONF ]] ||
        die 'manually install Wazuh agent 4.14.8 first'
    bounded 10s /var/ossec/bin/wazuh-control info 2>/dev/null | grep -q '4.14.8' || die 'Wazuh agent 4.14.8 required'
    getent group wazuh >/dev/null || die 'Wazuh agent package group missing'
    SURI_ID=$(bounded 15s docker image inspect --format '{{.Id}}' "$SURICATA_IMAGE") || die 'Suricata image must be preloaded manually'
    WAF_ID=$(bounded 15s docker image inspect --format '{{.Id}}' "$WAF_IMAGE") || die 'WAF image must be preloaded manually'
    [[ $SURI_ID =~ ^sha256:[0-9a-f]{64}$ && $WAF_ID =~ ^sha256:[0-9a-f]{64}$ ]] || die 'invalid local image identity'
    for name in "$SURI_ID" "$WAF_ID"; do
        [[ $(bounded 10s docker image inspect --format '{{.Os}}:{{.Architecture}}' "$name") == linux:amd64 ]] || die 'preloaded images must be native Linux amd64'
    done
    export SURI_ID WAF_ID
    LAB_PROFILE=$(lab_security profile) || die 'TLS/private-network/lab source preflight failed'
    [[ $LAB_PROFILE =~ ^[a-f0-9]{64}$ ]] || die 'invalid lab profile'
    SECURITY_SCRIPT_SHA=$(hash "${BASH_SOURCE[0]}")
    LOG_SOURCE_SHA=$(log_pipeline fingerprint | jq -er '.source_sha256') || die 'log source fingerprint failed'
    LOG_INSTALLER_SHA=$(hash "$CAPSTONE_SOURCE/deployment/log_pipeline.py")
    export LAB_PROFILE SECURITY_SCRIPT_SHA LOG_SOURCE_SHA LOG_INSTALLER_SHA
    ET_SHA=$(hash "$ET_RULES_FILE"); LOCAL_SHA=$(hash "$CAPSTONE_SOURCE/new_rule/GROOT_A_local.rules")
    WAF_SHA=$(hash "$CAPSTONE_SOURCE/new_rule/GROOT_A_WAF.conf")
    export ET_SHA LOCAL_SHA WAF_SHA CA_SHA
    PROFILE=$(python3 - <<'PY'
import hashlib,json,os
keys=('CAPSTONE_ROOT','SECURITY_HOST','SIEM_HOST','SERVICE_HOST','MONITOR_INTERFACE','WEB_BACKEND_PORT','WAF_PORT','SURI_ID','WAF_ID','ET_SHA','LOCAL_SHA','WAF_SHA','CA_SHA','LAB_PROFILE','SECURITY_SCRIPT_SHA','LOG_SOURCE_SHA','LOG_INSTALLER_SHA','LOG_PROTECTED_IPS','ADMIN_PROTECTED_CIDRS','TZ')
print(hashlib.sha256(json.dumps({k:os.environ[k] for k in keys},sort_keys=True,separators=(',',':')).encode()).hexdigest())
PY
)
    export PROFILE
    log_pipeline check >/dev/null || die 'log pipeline prerequisites/profile rejected'
    if [[ -e $STATE ]]; then
        safe_file "$STATE" 16384
        jq -e --arg p "$PROFILE" --arg mode "$MODE" '.schema_version==2 and .profile_sha256==$p and (.status=="complete" or ($mode=="verify" and .status=="incomplete"))' "$STATE" >/dev/null ||
            die 'partial/different-profile deployment: inspect required; automatic retry forbidden'
        return
    fi
    [[ ! -e $ROLE_DIR ]] || die 'partial role directory exists; inspect required'
    [[ ! -s /var/ossec/etc/client.keys ]] || die 'agent already registered; fresh-host deployment only'
    [[ ! -L /var/ossec/etc/client.keys ]] || die 'agent key path is a symlink'
    for name in /var/ossec/etc/capstone-manager-ca.pem /var/ossec/etc/capstone-enrollment.pass; do
        [[ ! -e $name && ! -L $name ]] || die 'existing enrollment destination'
    done
    if grep -q 'capstone' "$CONF"; then die 'existing capstone agent configuration'; fi
    for name in "$WAF_NAME" "$SURI_NAME" "$EDGE_NAME" "$TEST_NAME" capstone-security-edgecheck capstone-security-wafcheck; do
        ! bounded 10s docker container inspect "$name" >/dev/null 2>&1 || die 'unowned portable container exists'
    done
    ! bounded 10s docker network inspect capstone-security_waf >/dev/null 2>&1 || die 'unowned portable network exists'
    ! bounded 10s docker volume inspect capstone-security_suricata-lib >/dev/null 2>&1 || die 'unowned portable volume exists'
    ! nft list table inet capstone_portable >/dev/null 2>&1 || die 'existing unowned nft table'
    [[ ! -e /etc/systemd/system/$NFT_UNIT && ! -L /etc/systemd/system/$NFT_UNIT ]] || die 'existing unowned firewall service'
    ss -H -ltn | awk '{print $4}' | grep -Eq ":${WAF_PORT}$" && die 'requested WAF port is occupied'
    return 0
}

verify_role() {
    [[ -f $COMPOSE && -f $ROLE_DIR/manifest.json ]] || die 'role files missing'
    python3 - "$ROLE_DIR" <<'PY'
import hashlib,json,os,pathlib,stat,sys
r=pathlib.Path(sys.argv[1]); m=json.loads((r/'manifest.json').read_text())
assert set(m)=={'schema_version','profile_sha256','local_rules','site_specific_sids_excluded','files'}
assert m['schema_version']==2 and m['local_rules']==11 and m['site_specific_sids_excluded']==[1000000,2034802,2034806]
assert m['profile_sha256']==os.environ['PROFILE']
assert set(m['files'])=={'compose.json','config/GROOT_A_WAF.conf','config/wazuh-root-ca.pem','config/firewall.nft','rules/suricata.rules','rules/local.rules','rules/all.rules','config/lab-edge.conf','config/lab-waf.conf','config/lab-policy.conf','tls/lab.crt','tls/lab.key'}
for name,sha in m['files'].items():
    p=r/name; s=p.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==(101 if name=='tls/lab.key' else 0) and not(s.st_mode&0o022)
    if name=='tls/lab.key': assert s.st_gid==101 and stat.S_IMODE(s.st_mode)==0o400
    assert hashlib.sha256(p.read_bytes()).hexdigest()==sha, 'managed file changed'
PY
    local name cid image expected running health
    for name in "$WAF_NAME" "$SURI_NAME" "$EDGE_NAME"; do
        cid=$(bounded 10s docker inspect --format '{{.Id}}' "$name") || die 'managed container missing'
        [[ $(jq -er --arg n "$name" '.container_ids[$n]' "$STATE") == "$cid" ]] || die 'managed full container ID changed'
        image=$(bounded 10s docker inspect --format '{{.Image}}' "$cid")
        expected=$SURI_ID; [[ $name != "$SURI_NAME" ]] && expected=$WAF_ID
        [[ $image == "$expected" ]] || die 'managed image changed'
        bounded 10s docker inspect --format '{{json .Config.Labels}}' "$cid" |
            jq -e --arg p "$PROFILE" '."io.capstone.portable.profile"==$p and ."io.capstone.portable.role"=="security"' >/dev/null || die 'container ownership changed'
        running=$(bounded 10s docker inspect --format '{{.State.Running}}:{{.RestartCount}}' "$cid")
        [[ $running == true:0 ]] || die 'container is not running cleanly'
    done
    log_pipeline verify-base >/dev/null || die 'log producer mounts/command/config changed'
    bounded 10s docker inspect --format '{{json .HostConfig.PortBindings}}' "$WAF_NAME" |
        jq -e --arg ip "$SECURITY_HOST" --arg port "$WAF_PORT" '.=={"8080/tcp":[{"HostIp":$ip,"HostPort":$port}]}' >/dev/null || die 'WAF published address changed'
    bounded 15s docker exec "$WAF_NAME" nginx -t >/dev/null 2>&1 || die 'nginx validation failed'
    health=$(bounded 10s docker inspect --format '{{with index .State "Health"}}{{.Status}}{{else}}absent{{end}}' "$WAF_NAME")
    [[ $health == healthy ]] || die 'WAF image healthcheck must be healthy'
    bounded 10s docker exec "$WAF_NAME" sh -c 'test "$(id -u)" = 101 && test -w /var/log/modsecurity' || die 'WAF writer permission mismatch'
    lab_security verify || die 'TLS edge/proxy network verification failed'
    local engine_log
    engine_log=$(bounded 10s docker logs --tail 500 "$SURI_NAME" 2>&1) || die 'Suricata logs unavailable'
    grep -q 'Engine started' <<< "$engine_log" || die 'Suricata engine startup not observed'
    local http
    http=$(bounded 15s curl --noproxy '*' --connect-timeout 5 --max-time 10 -s -o /dev/null -w '%{http_code}' "http://$SECURITY_HOST:$WAF_PORT/") || die 'WAF request failed'
    [[ $http =~ ^[23][0-9][0-9]$ ]] || die 'WAF/backend did not return 2xx/3xx'
    systemctl is-active --quiet wazuh-agent || die 'Wazuh agent inactive'
    grep -qx "status='connected'" /var/ossec/var/run/wazuh-agentd.state || die 'Wazuh agent not connected'
    [[ -s /var/ossec/etc/client.keys ]] || die 'Wazuh enrollment incomplete'
    python3 - <<'PY'
import grp,hashlib,os,pathlib,stat,xml.etree.ElementTree as E
root=E.fromstring('<configuration>'+pathlib.Path('/var/ossec/etc/ossec.conf').read_text()+'</configuration>')
clients=root.findall('./ossec_config/client');assert len(clients)==1
c=clients[0];servers=c.findall('server');assert len(servers)==1
assert {x.tag:x.text for x in servers[0]}=={'address':os.environ['SIEM_HOST'],'port':'1514','protocol':'tcp'}
mode=c.findtext('disable-active-response');assert mode in ('yes','no')
if mode=='no':
    # Enabling Native AR is accepted only if the full bounded management
    # extension verifies. A hand-edited XML switch is never sufficient.
    import subprocess
    result=subprocess.run(['python3','-B',str(pathlib.Path(os.environ['CAPSTONE_SOURCE'])/'deployment/soc_management.py'),
                           'verify','--role','security'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
    assert result.returncode==0,'SOC active-response contract not verified'
en=c.find('enrollment');assert en is not None
assert en.findtext('agent_name')=='capstone-security' and en.findtext('manager_address')==os.environ['SIEM_HOST'] and en.findtext('enabled')=='yes'
assert en.findtext('server_ca_path')=='/var/ossec/etc/capstone-manager-ca.pem'
assert en.findtext('authorization_pass_path')=='/var/ossec/etc/capstone-enrollment.pass'
for rel,source in [('logs/suricata/eve.json','suricata'),('logs/modsecurity/audit.log','modsecurity')]:
    matches=[f for f in root.findall('./ossec_config/localfile') if f.findtext('location')==os.environ['ROLE_DIR']+'/'+rel]
    assert len(matches)==1;f=matches[0]
    assert f.findtext('log_format')=='json' and f.findtext('only-future-events')=='no'
    assert f.find('only-future-events').attrib=={'max-size':'2GB'} and f.find('max-size') is None
    assert [(x.attrib,x.text) for x in f.findall('label')]==[({'key':'capstone.source'},source)]
for name in ('capstone-manager-ca.pem','capstone-enrollment.pass'):
    p=pathlib.Path('/var/ossec/etc')/name;s=p.lstat()
    assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==grp.getgrnam('wazuh').gr_gid and stat.S_IMODE(s.st_mode)==0o640 and s.st_nlink==1
assert hashlib.sha256(pathlib.Path('/var/ossec/etc/capstone-manager-ca.pem').read_bytes()).hexdigest()==os.environ['CA_SHA']
PY
    nft -j list table inet capstone_portable | jq -e --arg a "$SECURITY_HOST" --arg b "$SIEM_HOST" --arg c "$SERVICE_HOST" '
      [.nftables[]|.chain? // empty] as $chains | [.nftables[]|.set? // empty] as $sets |
      ($chains|length)==1 and $chains[0].name=="input" and $chains[0].policy=="accept" and
      ($sets|length)==1 and $sets[0].name=="protected_v4" and ($sets[0].elem|sort)==([$a,$b,$c]|sort) and
      ([.nftables[]|.rule? // empty]|length)==2 and
      ([.nftables[]|.rule?.expr[]? | select(has("drop") or has("reject") or has("jump") or has("goto"))]|length)==0
    ' >/dev/null || die 'additive nft table differs'
    systemctl is-enabled --quiet "$NFT_UNIT" || die 'nft persistence unit not enabled'
    printf '{"role":"security","status":"verified","scope":"base_role","waf_mode":"DetectionOnly","lab_waf_mode":"enforce_or_signed_session_exempt","suricata_mode":"IDS","agent":"capstone-security","lab_waf_enforcement_installed":true,"extensions_verified_separately":true}\n'
}

apply_role() {
    if [[ -f $STATE ]]; then verify_role; return; fi
    # Check dependencies before creating the exclusive role/attempt directory.
    bounded 8s bash -c 'exec 3<>"/dev/tcp/$1/1514"' security-check "$SIEM_HOST" || die 'SIEM data listener unavailable'
    bounded 12s openssl s_client -connect "$SIEM_HOST:1515" -CAfile "$WAZUH_CA_FILE" -verify_ip "$SIEM_HOST" -verify_return_error </dev/null >/dev/null 2>&1 || die 'SIEM enrollment TLS identity verification failed'
    bounded 8s bash -c 'exec 3<>"/dev/tcp/$1/$2"' backend-check "$SERVICE_HOST" "$WEB_BACKEND_PORT" || die 'web backend listener unavailable'
    bounded 8s bash -c 'exec 3<>"/dev/tcp/$1/$2"' lab-gateway-check "$SERVICE_HOST" "$LAB_GATEWAY_PORT" || die 'private lab gateway unavailable'
    [[ -d $CAPSTONE_ROOT ]] || install -d -o root -g root -m 0755 "$CAPSTONE_ROOT"
    mkdir "$ROLE_DIR" || die 'role directory appeared; refuse retry'
    chmod 0755 "$ROLE_DIR"
    printf '{"schema_version":2,"status":"incomplete","profile_sha256":"%s"}\n' "$PROFILE" >"$STATE"
    sync -f "$STATE"; sync -f "$ROLE_DIR"
    trap 'printf "security: apply incomplete; inspect %s; no automatic retry or cleanup\n" "$ROLE_DIR" >&2' ERR
    trap 'cleanup_native_test || printf "security: private native test cleanup incomplete; inspect recorded CID\n" >&2' EXIT
    install -d -o root -g root -m 0755 "$ROLE_DIR/config" "$ROLE_DIR/rules" "$ROLE_DIR/logs" "$ROLE_DIR/logs/suricata"
    install -d -o 101 -g 101 -m 0755 "$ROLE_DIR/logs/modsecurity"
    install -d -o root -g root -m 0700 "$ROLE_DIR/backup"
    install -o root -g root -m 0444 "$CAPSTONE_SOURCE/new_rule/GROOT_A_WAF.conf" "$ROLE_DIR/config/GROOT_A_WAF.conf"
    install -o root -g root -m 0444 "$ET_RULES_FILE" "$ROLE_DIR/rules/suricata.rules"
    install -o root -g root -m 0444 "$WAZUH_CA_FILE" "$ROLE_DIR/config/wazuh-root-ca.pem"
    python3 - <<'PY'
import hashlib,json,os,pathlib,re
r=pathlib.Path(os.environ['ROLE_DIR']); source=pathlib.Path(os.environ['CAPSTONE_SOURCE'])
raw=(source/'new_rule/GROOT_A_local.rules').read_text()
assert hashlib.sha256(raw.encode()).hexdigest()==os.environ['LOCAL_SHA']
for name,expected in [('config/GROOT_A_WAF.conf','WAF_SHA'),('rules/suricata.rules','ET_SHA'),('config/wazuh-root-ca.pem','CA_SHA')]:
    assert hashlib.sha256((r/name).read_bytes()).hexdigest()==os.environ[expected], 'prerequisite changed during copy'
# Only this reviewed local file is parsed, not the ET feed. The site-specific
# Ollama marker and its two ET overrides are excluded on a different network.
logical=[]; pending=''
for line in raw.splitlines():
    if not pending and (not line.strip() or line.lstrip().startswith('#')):continue
    pending+=line[:-1] if line.endswith('\\') else line
    if not line.endswith('\\'):
        logical.append(pending); pending=''
assert not pending
kept=[]; skipped=[]
for line in logical:
    ids=re.findall(r'\bsid\s*:\s*(\d+)\s*;',line); assert len(ids)==1
    sid=int(ids[0])
    if sid in (1000000,2034802,2034806):skipped.append(sid);continue
    assert 1000001<=sid<=1000099 and line.startswith('alert ')
    # With no marker producer the negative flowbit is always true; removing it
    # avoids an undefined-flowbit warning and preserves the detection predicate.
    line=line.replace('flowbits:isnotset,groot_llm_api;','')
    kept.append(line)
assert len(kept)==11 and sorted(skipped)==[1000000,2034802,2034806]
local=('\n'.join(kept)+'\n').encode(); (r/'rules/local.rules').write_bytes(local)
et=(r/'rules/suricata.rules').read_bytes(); assert b'\0' not in et and et.strip()
active_et=b'\n'.join(line for line in et.splitlines() if not line.lstrip().startswith(b'#'))
assert not re.search(rb'\bsid\s*:\s*10000[0-9]{2}\s*;',active_et), 'ET prerequisite contains reserved local SID'
(r/'rules/all.rules').write_bytes(et+(b'' if et.endswith(b'\n') else b'\n')+local)
home='['+','.join(os.environ[k]+'/32' for k in ('SECURITY_HOST','SIEM_HOST','SERVICE_HOST'))+']'
labels={'io.capstone.portable.role':'security','io.capstone.portable.profile':os.environ['PROFILE']}
compose={'services':{
 'waf':{'image':os.environ['WAF_ID'],'container_name':'capstone-security-waf','restart':'always','labels':labels,
 'environment':{'TZ':'Asia/Seoul','BACKEND':'http://'+os.environ['SERVICE_HOST']+':'+os.environ['WEB_BACKEND_PORT'],'SERVER_NAME':'capstone-service','PORT':'8080','SSL_PORT':'8443','NGINX_X_FORWARDED_PORT':os.environ['WAF_PORT'],'BLOCKING_PARANOIA':'1','MODSEC_RULE_ENGINE':'DetectionOnly','MODSEC_AUDIT_ENGINE':'RelevantOnly','MODSEC_AUDIT_LOG_FORMAT':'JSON','MODSEC_AUDIT_LOG_TYPE':'Serial','MODSEC_AUDIT_LOG':'/var/log/modsecurity/audit.log'},
 'ports':[os.environ['SECURITY_HOST']+':'+os.environ['WAF_PORT']+':8080'],'volumes':[str(r/'logs/modsecurity')+':/var/log/modsecurity',str(r/'config/GROOT_A_WAF.conf')+':/etc/modsecurity.d/owasp-crs/rules/REQUEST-948-GROOT_A_WAF.conf:ro'],'networks':['waf'],'logging':{'driver':'json-file','options':{'max-size':'10m','max-file':'3'}}},
 'suricata':{'image':os.environ['SURI_ID'],'container_name':'capstone-security-suricata','restart':'always','labels':labels,'network_mode':'host','cap_add':['NET_ADMIN','NET_RAW','SYS_NICE'],
 'command':['-i',os.environ['MONITOR_INTERFACE'],'-S','/rules/all.rules','--set','vars.address-groups.HOME_NET='+home,'--set','stats.interval=60','--set','unix-command.enabled=yes'],
 'environment':{'TZ':'Asia/Seoul'},'volumes':[str(r/'rules')+':/rules:ro',str(r/'logs/suricata')+':/var/log/suricata','suricata-lib:/var/lib/suricata'],'logging':{'driver':'json-file','options':{'max-size':'10m','max-file':'3'}}}},
 'networks':{'waf':{'driver':'bridge'}},'volumes':{'suricata-lib':{}}}
(r/'compose.json').write_text(json.dumps(compose,sort_keys=True,indent=2)+'\n')
addresses=','.join(os.environ[k] for k in ('SECURITY_HOST','SIEM_HOST','SERVICE_HOST'))
(r/'config/firewall.nft').write_text('table inet capstone_portable {\n set protected_v4 { type ipv4_addr; elements = { '+addresses+' }; }\n chain input { type filter hook input priority -5; policy accept; ct state established,related accept; tcp dport 22 accept; }\n}\n')
for p in (r/'rules/local.rules',r/'rules/all.rules',r/'compose.json',r/'config/firewall.nft'):p.chmod(0o444)
manifest={'schema_version':2,'profile_sha256':os.environ['PROFILE'],'local_rules':11,'site_specific_sids_excluded':sorted(skipped),'files':{str(p.relative_to(r)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [r/'compose.json',*sorted((r/'config').iterdir()),*sorted((r/'rules').iterdir())]}}
(r/'manifest.json').write_text(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n')
for p in [r/'manifest.json',r/'compose.json',*list((r/'config').iterdir()),*list((r/'rules').iterdir())]:
    with p.open('rb') as f:os.fsync(f.fileno())
PY
    lab_security render || die 'lab TLS/WAF rendering failed; partial role retained'
    log_pipeline prepare || die 'log producers preparation failed; partial role retained'
    compose config --quiet || die 'generated Compose rejected'
    nft -c -f "$ROLE_DIR/config/firewall.nft" || die 'additive nft syntax rejected'
    # Native -T uses only a private tmpfs log directory, never an operational log.
    TEST_CID=$(bounded 30s docker create --pull never --name "$TEST_NAME" --label "io.capstone.portable.rulecheck=$PROFILE" --network none --read-only \
        --tmpfs /tmp --tmpfs /etc/suricata --tmpfs /var/log/suricata --tmpfs /var/run \
        --mount "type=bind,source=$ROLE_DIR/rules,target=/rules,readonly" \
        "$SURI_ID" -T -c /etc/suricata/suricata.yaml -S /rules/all.rules -l /var/log/suricata) || die 'private syntax-test creation failed; inspect before retry'
    [[ $TEST_CID =~ ^[0-9a-f]{64}$ ]] || die 'private syntax-test identity invalid'
    printf '%s\n' "$TEST_CID" >"$ROLE_DIR/native-test.cid"; sync -f "$ROLE_DIR/native-test.cid"
    bounded 240s docker start --attach "$TEST_CID" >"$ROLE_DIR/suricata-config-test.log" 2>&1 || die 'Suricata native rule test failed (private log retained)'
    [[ $(bounded 10s docker inspect --format '{{.State.Running}}:{{.State.ExitCode}}' "$TEST_CID") == false:0 ]] || die 'native rule test did not exit successfully'
    cleanup_native_test || die 'private syntax-test cleanup failed'
    lab_security native || die 'private lab Nginx configuration check failed; private log retained'
    nft -f "$ROLE_DIR/config/firewall.nft"
    cat >"/etc/systemd/system/$NFT_UNIT" <<EOF
[Unit]
Description=Capstone additive ACCEPT-only management safeguards
Before=docker.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '/usr/sbin/nft list table inet capstone_portable >/dev/null 2>&1 || /usr/sbin/nft -f $ROLE_DIR/config/firewall.nft'
[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "/etc/systemd/system/$NFT_UNIT"
    bounded 30s systemctl daemon-reload
    bounded 30s systemctl enable --now "$NFT_UNIT" >/dev/null
    compose up -d --pull never --no-build
    python3 - <<'PYIDS'
import json,os,pathlib,re,subprocess,tempfile
p=pathlib.Path(os.environ['ROLE_DIR'])/'deployment.json'; value=json.loads(p.read_text()); identities={}
for name in ('capstone-security-waf','capstone-security-suricata','capstone-security-lab-edge'):
    item=json.loads(subprocess.check_output(['docker','--host','unix:///var/run/docker.sock','inspect',name],timeout=15))[0]
    assert re.fullmatch('[a-f0-9]{64}',item['Id']) and item['Config']['Labels'].get('io.capstone.portable.profile')==os.environ['PROFILE']
    identities[name]=item['Id']
value['container_ids']=identities
fd,name=tempfile.mkstemp(prefix='.identities-',dir=p.parent)
with os.fdopen(fd,'w') as f:json.dump(value,f,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
os.replace(name,p)
PYIDS
    local ready=0 i
    for i in $(seq 1 60); do
        if bounded 10s docker logs --tail 500 "$SURI_NAME" 2>&1 | grep 'Engine started' >/dev/null &&
           [[ $(bounded 10s docker inspect --format '{{with index .State "Health"}}{{.Status}}{{end}}' "$WAF_NAME") == healthy ]]; then ready=1; break; fi
        sleep 4
    done
    [[ $ready == 1 ]] || die 'engine startup deadline exceeded'
    # Only an unregistered package installation is configured. Preserve all
    # package defaults outside client/raw inputs; never copy another agent key.
    cp -p -- "$CONF" "$ROLE_DIR/backup/ossec.conf.before"
    bounded 60s systemctl stop wazuh-agent
    [[ ! -s /var/ossec/etc/client.keys && ! -L /var/ossec/etc/client.keys ]] || die 'agent registered during apply; inspect required'
    [[ ! -e /var/ossec/etc/capstone-manager-ca.pem && ! -L /var/ossec/etc/capstone-manager-ca.pem && ! -e /var/ossec/etc/capstone-enrollment.pass && ! -L /var/ossec/etc/capstone-enrollment.pass ]] || die 'enrollment destination appeared'
    install -o root -g wazuh -m 0640 "$WAZUH_CA_FILE" /var/ossec/etc/capstone-manager-ca.pem
    install -o root -g wazuh -m 0640 "$WAZUH_ENROLLMENT_PASS_FILE" /var/ossec/etc/capstone-enrollment.pass
    sync -f /var/ossec/etc/capstone-manager-ca.pem; sync -f /var/ossec/etc/capstone-enrollment.pass; sync -f /var/ossec/etc
    python3 - <<'PY'
import os,pathlib,re,tempfile,xml.etree.ElementTree as E
p=pathlib.Path('/var/ossec/etc/ossec.conf'); raw=p.read_text(); s=p.stat()
assert '<!DOCTYPE' not in raw and '<?xml' not in raw
root=E.fromstring('<configuration>'+raw+'</configuration>')
blocks=root.findall('ossec_config'); assert blocks
clients=[x for b in blocks for x in b.findall('client')]; assert len(clients)==1
c=clients[0]
for e in list(c):
    if e.tag in ('server','enrollment'):c.remove(e)
server=E.SubElement(c,'server')
for k,v in [('address',os.environ['SIEM_HOST']),('port','1514'),('protocol','tcp')]:E.SubElement(server,k).text=v
en=E.SubElement(c,'enrollment')
for k,v in [('enabled','yes'),('manager_address',os.environ['SIEM_HOST']),('port','1515'),('agent_name','capstone-security'),('server_ca_path','/var/ossec/etc/capstone-manager-ca.pem'),('authorization_pass_path','/var/ossec/etc/capstone-enrollment.pass'),('delay_after_enrollment','5')]:E.SubElement(en,k).text=v
disabled=c.find('disable-active-response')
if disabled is None:disabled=E.SubElement(c,'disable-active-response')
disabled.text='yes'
added=E.Element('ossec_config')
for relative,source in [('logs/suricata/eve.json','suricata'),('logs/modsecurity/audit.log','modsecurity')]:
    f=E.SubElement(added,'localfile')
    for k,v in [('log_format','json'),('location',os.environ['ROLE_DIR']+'/'+relative)]:E.SubElement(f,k).text=v
    E.SubElement(f,'only-future-events',{'max-size':'2GB'}).text='no'
    E.SubElement(f,'label',{'key':'capstone.source'}).text=source
# Preserve unrelated package XML bytes: Wazuh's parser does not implement
# every XML entity transformation performed by a general XML serializer.
c.tail=None
body,count=re.subn(r'<client>.*?</client>',lambda _:E.tostring(c,encoding='unicode'),raw,flags=re.S)
assert count==1
body=body.rstrip()+'\n'+E.tostring(added,encoding='unicode')+'\n'
E.fromstring('<configuration>'+body+'</configuration>')
fd,name=tempfile.mkstemp(prefix='.capstone-',dir=p.parent)
with os.fdopen(fd,'w') as f:
    f.write(body); f.flush(); os.fchmod(f.fileno(),s.st_mode&0o777); os.fchown(f.fileno(),s.st_uid,s.st_gid);os.fsync(f.fileno())
os.replace(name,p)
fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
PY
    if ! bounded 20s /var/ossec/bin/wazuh-agentd -t >"$ROLE_DIR/agent-config-test.log" 2>&1 ||
       ! bounded 20s /var/ossec/bin/wazuh-logcollector -t >>"$ROLE_DIR/agent-config-test.log" 2>&1; then
        cp -p -- "$ROLE_DIR/backup/ossec.conf.before" "$CONF"
        die 'agent configuration rejected; original restored, agent left stopped'
    fi
    bounded 90s systemctl enable --now wazuh-agent >/dev/null
    ready=0
    for i in $(seq 1 36); do
        if grep -qx "status='connected'" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null; then ready=1; break; fi
        sleep 5
    done
    [[ $ready == 1 ]] || die 'agent enrollment/connection deadline exceeded'
    verify_role
    python3 - <<'PY'
import json,os,pathlib,tempfile
r=pathlib.Path(os.environ['ROLE_DIR']);fd,name=tempfile.mkstemp(prefix='.complete-',dir=r)
with os.fdopen(fd,'w') as f:
    json.dump({'schema_version':2,'status':'complete','profile_sha256':os.environ['PROFILE'],'agent':'capstone-security','package_installations':0,'network_downloads':0,'lab_waf_enforcement_installed':True,'automatic_ip_blocking_installed':False,'vector_installed':False,'container_ids':json.loads((r/'deployment.json').read_text())['container_ids']},f,sort_keys=True,separators=(',',':'));f.write('\n');f.flush();os.fsync(f.fileno())
os.replace(name,r/'deployment.json');fd=os.open(r,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
PY
    trap - ERR EXIT
}

preflight
case "$MODE" in
    check) printf '{"role":"security","status":"prerequisites_ready","mutations":0,"package_installations":0}\n' ;;
    apply) apply_role ;;
    verify) [[ -f $STATE ]] || die 'deployment not present'; verify_role ;;
esac
