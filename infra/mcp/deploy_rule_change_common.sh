#!/bin/bash
# Root-only installer for the separate approval-gated rule-change MCP on A/B.
# Staged inputs: rule_change_mcp.py, rule_change_executor.py, run-rule-change.sh.
# Inputs: RULE_PUBKEY (dedicated Hermes SSH public key) and a root-owned
# RULE_BROKER_TOKEN_FILE. The HMAC key is never placed in argv or sent on wire.
# This script never modifies WAF, Suricata, Wazuh rules or their Compose files.
set -euo pipefail
umask 077

ROLE=${1:-}; MODE=${2:-apply}
[[ $ROLE == a || $ROLE == b ]] || { echo 'usage: deploy_rule_change_{A,B}.sh [--check]' >&2; exit 2; }
[[ $MODE == apply || $MODE == --check ]] || { echo 'only --check is accepted' >&2; exit 2; }
[[ $# -le 2 ]] || { echo 'unexpected arguments' >&2; exit 2; }
[[ $(id -u) == 0 ]] || { echo 'run as root' >&2; exit 1; }

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
SRC=${RULE_CHANGE_SOURCE_DIR:-$HERE}
MCP_SRC=$SRC/rule_change_mcp.py
EXEC_SRC=$SRC/rule_change_executor.py
WRAP_SRC=$SRC/run-rule-change.sh
MCP_DST=/opt/rule-change/rule_change_mcp.py
EXEC_DST=/usr/local/sbin/rule-change-executor
WRAP_DST=/opt/rule-change/run-rule-change.sh
CONFIG=/etc/rule-change/config.json
TOKEN_DST=/etc/rule-change/broker.token
AK=/opt/rule-change/.ssh/authorized_keys
SUDOERS=/etc/sudoers.d/capstone-rule-change
SSHD=/etc/ssh/sshd_config.d/62-capstone-rule-change.conf
SERVICE=/etc/systemd/system/rule-change-worker.service
TIMER=/etc/systemd/system/rule-change-worker.timer
STATE=/var/lib/rule-change
BROKER_URL=http://10.200.10.10:8090
[[ $ROLE == b ]] && BROKER_URL=http://127.0.0.1:8090
BACKUP=; MODIFIED=0; HAD_TIMER_ACTIVE=0; HAD_TIMER_ENABLED=0; CREATED_USER=0
MANAGED=("$MCP_DST" "$EXEC_DST" "$WRAP_DST" "$CONFIG" "$TOKEN_DST" "$AK" "$SUDOERS" "$SSHD" "$SERVICE" "$TIMER")
die(){ echo "rule-change deploy: $*" >&2; exit 1; }

for bin in python3 docker sshd ssh-keygen visudo systemctl stat runuser; do command -v "$bin" >/dev/null || die "missing command: $bin"; done
for src in "$MCP_SRC" "$EXEC_SRC" "$WRAP_SRC" "$SRC/rule_readonly_install.py"; do
  [[ -f $src && ! -L $src ]] || die "staged source is absent or a symlink: $src"
done
python3 - "$SRC" "$MCP_SRC" "$EXEC_SRC" "$WRAP_SRC" "$SRC/rule_readonly_install.py" <<'PY' || die 'staged code directory/files must be root-owned and not group/world-writable'
import os, stat, sys
directory,*files=sys.argv[1:]
for path in (directory,*files):
    info=os.lstat(path)
    assert info.st_uid==0 and not (stat.S_IMODE(info.st_mode)&0o022), path
assert stat.S_ISDIR(os.lstat(directory).st_mode)
for path in files: assert stat.S_ISREG(os.lstat(path).st_mode)
PY
python3 - "$MCP_SRC" "$EXEC_SRC" "$SRC/rule_readonly_install.py" <<'PY' || die 'Python syntax failed'
import ast, pathlib, sys
for path in sys.argv[1:]:
    ast.parse(pathlib.Path(path).read_text(encoding='utf-8'), filename=path)
PY
bash -n "$WRAP_SRC" || die 'wrapper syntax failed'
grep -Fq 'exec /usr/bin/python3 /opt/rule-change/rule_change_mcp.py' "$WRAP_SRC" || die 'unexpected wrapper entrypoint'

[[ -n ${RULE_PUBKEY:-} && $RULE_PUBKEY != *$'\n'* && $RULE_PUBKEY != *$'\r'* ]] || die 'RULE_PUBKEY must be one public-key line'
[[ $RULE_PUBKEY =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+(\ [^[:cntrl:]]*)?$ ]] || die 'RULE_PUBKEY must be a single Ed25519 key'
ssh-keygen -l -f <(printf '%s\n' "$RULE_PUBKEY") >/dev/null 2>&1 || die 'invalid public key'
KEY_BODY=$(awk '{print $2}' <<<"$RULE_PUBKEY")
[[ -z ${RULE_BROKER_TOKEN:-} ]] || die 'pass the rule key via RULE_BROKER_TOKEN_FILE, not an environment variable'
[[ -n ${RULE_BROKER_TOKEN_FILE:-} && -f $RULE_BROKER_TOKEN_FILE && ! -L $RULE_BROKER_TOKEN_FILE ]] || die 'RULE_BROKER_TOKEN_FILE must be a regular file'
[[ $(stat -c %u "$RULE_BROKER_TOKEN_FILE") == 0 && $(stat -c %a "$RULE_BROKER_TOKEN_FILE") == 600 ]] || die 'broker token source must be root:root 0600'
python3 - "$RULE_BROKER_TOKEN_FILE" <<'PY' || die 'broker token parent directory must be root-controlled'
import os, pathlib, stat, sys
parent=pathlib.Path(sys.argv[1]).parent
info=os.lstat(parent)
assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not(stat.S_IMODE(info.st_mode)&0o022)
PY
python3 - "$RULE_BROKER_TOKEN_FILE" <<'PY' || die 'broker token format/length invalid'
import pathlib, re, sys
assert re.fullmatch(r'[A-Za-z0-9_-]{32,128}',pathlib.Path(sys.argv[1]).read_text().strip())
PY

# Never transmit the shared rule key over HTTP. The installed root executor's
# --broker-check performs a nonce-bound HMAC request AND authenticates the
# response before the worker timer is enabled. A failed check rolls back.

if [[ $ROLE == a ]]; then
  python3 - <<'PY' || die 'A live target, mount, or process gate failed'
import json, os, subprocess, sys
def inspect(name):
    d=json.loads(subprocess.check_output(['docker','inspect',name]))[0]
    assert d['State']['Running'], name+' not running'
    return d
def mount(d, source, dest, writable):
    matches=[m for m in d['Mounts'] if m['Source']==source and m['Destination']==dest]
    assert len(matches)==1 and bool(matches[0]['RW'])==writable, (d['Name'], dest)
def regular(path, limit):
    assert os.path.isfile(path) and not os.path.islink(path), path
    assert 0<os.path.getsize(path)<=limit, path
waf=inspect('waf'); sur=inspect('suricata')
wp='/home/groot_a/capstone/secstack/conf/GROOT_A_WAF.conf'
sd='/home/groot_a/capstone/suricata/ruleset'
mount(waf, wp, '/etc/modsecurity.d/owasp-crs/rules/REQUEST-948-GROOT_A_WAF.conf', False)
mount(sur, sd, '/rules', False)
assert 'MODSEC_RULE_ENGINE=DetectionOnly' in waf['Config']['Env']
args=sur.get('Args') or sur.get('Config',{}).get('Cmd') or []
assert any(a=='-S' for a in args) and '/rules/all.rules' in args
assert '-i' in args and 'ens192' in args
regular(wp, 2_000_000)
for f, cap in [('GROOT_A_local.rules',2_000_000), ('suricata.rules',100_000_000), ('all.rules',100_000_000)]:
    regular(os.path.join(sd,f),cap)
PY
else
  python3 - <<'PY' || die 'B live target, mount, or process gate failed'
import ipaddress, json, os, pathlib, subprocess
d=json.loads(subprocess.check_output(['docker','inspect','single-node-wazuh.manager-1']))[0]
assert d['State']['Running']
source='/var/lib/docker/volumes/single-node_wazuh_etc/_data'
matches=[m for m in d['Mounts'] if m['Source']==source and m['Destination']=='/var/ossec/etc']
assert len(matches)==1 and matches[0]['RW']
p=source+'/rules/local_rules.xml'
assert os.path.isfile(p) and not os.path.islink(p) and 0<os.path.getsize(p)<=2_000_000
mm=json.loads(subprocess.check_output(['docker','inspect','mm-app']))[0]
assert mm['State']['Running']
ip=mm['NetworkSettings']['Networks']['mattermost_mm-net']['IPAddress']
assert ipaddress.ip_address(ip).version==4
env=pathlib.Path('/etc/socbot/soc_bot.env')
assert env.is_file() and not env.is_symlink()
values={}
for line in env.read_text().splitlines():
    if '=' not in line or line.lstrip().startswith('#'): continue
    key,value=line.split('=',1)
    values[key.strip()]=value.strip().strip('"').strip("'")
assert values.get('RULE_MM_SOURCE_CIDRS')==ip+'/32', 'Mattermost callback CIDR must match live mm-app /32'
PY
fi

if [[ $MODE == --check ]]; then
  if [[ -x $EXEC_DST && -r $CONFIG ]]; then
    "$EXEC_DST" --check >/dev/null || die 'installed helper --check failed'
    "$EXEC_DST" --broker-check >/dev/null || die 'installed helper HMAC broker check failed'
    echo "rule-change $ROLE: local and HMAC broker preflight PASS; no local files/services changed"
  else
    echo "rule-change $ROLE: local preflight PASS; broker HMAC check runs after installation and before timer activation"
  fi
  exit 0
fi

[[ -e /etc/ssh/sshrc ]] && die '/etc/ssh/sshrc could corrupt MCP stdio'
for p in /opt/rule-change /opt/rule-change/.ssh /etc/rule-change "$STATE" "${MANAGED[@]}"; do
  [[ ! -L $p ]] || die "managed path is a symlink: $p"
done
CFG=$(sshd -T -C "user=rulechg,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22") || die 'sshd preflight failed'
grep -qx 'pubkeyauthentication yes' <<<"$CFG" || die 'sshd public key authentication disabled'
grep -qx 'usepam yes' <<<"$CFG" || die 'sshd UsePAM required for locked-password account'
grep -q '^authorizedkeysfile .*\.ssh/authorized_keys' <<<"$CFG" || die 'sshd AuthorizedKeysFile mismatch'
if [[ -e $AK ]]; then
  [[ -f $AK && ! -L $AK ]] || die 'existing authorized_keys is not a regular file'
  if grep -vE '^restrict,command="/opt/rule-change/run-rule-change.sh" ssh-ed25519 [A-Za-z0-9+/=]+( [^[:cntrl:]]*)?$' "$AK" | grep -q .; then
    die 'existing authorized_keys contains an unrestricted or unexpected line'
  fi
fi
if id rulechg >/dev/null 2>&1; then
  [[ $(id -nG rulechg) == rulechg ]] || die 'rulechg belongs to another group'
  [[ $(getent passwd rulechg | cut -d: -f6) == /opt/rule-change ]] || die 'existing rulechg home mismatch'
fi

BACKUP=$(mktemp -d /var/backups/rule-change-deploy.XXXXXX)
for i in "${!MANAGED[@]}"; do
  p=${MANAGED[$i]}
  if [[ -e $p ]]; then cp -a -- "$p" "$BACKUP/$i"; else : > "$BACKUP/$i.absent"; fi
done
if systemctl is-active --quiet rule-change-worker.timer; then HAD_TIMER_ACTIVE=1; fi
if systemctl is-enabled --quiet rule-change-worker.timer; then HAD_TIMER_ENABLED=1; fi

restore(){
  local i p
  set +e
  systemctl disable --now rule-change-worker.timer >/dev/null 2>&1
  systemctl stop rule-change-worker.service >/dev/null 2>&1
  for i in "${!MANAGED[@]}"; do
    p=${MANAGED[$i]}
    if [[ -f $BACKUP/$i.absent ]]; then rm -f -- "$p"; else rm -f -- "$p"; cp -a -- "$BACKUP/$i" "$p"; fi
  done
  systemctl daemon-reload >/dev/null 2>&1
  sshd -t && systemctl reload ssh >/dev/null 2>&1
  if [[ $HAD_TIMER_ENABLED == 1 ]]; then systemctl enable rule-change-worker.timer >/dev/null 2>&1; fi
  if [[ $HAD_TIMER_ACTIVE == 1 ]]; then systemctl start rule-change-worker.timer >/dev/null 2>&1; fi
  if [[ $CREATED_USER == 1 ]]; then userdel rulechg >/dev/null 2>&1 || true; fi
  echo "rule-change $ROLE: installation failed; managed files restored from $BACKUP" >&2
}
cleanup(){
  local status=$?
  trap - EXIT
  if [[ $status != 0 && $MODIFIED == 1 ]]; then restore; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
MODIFIED=1
systemctl stop rule-change-worker.timer >/dev/null 2>&1 || true
systemctl stop rule-change-worker.service >/dev/null 2>&1 || true

if ! id rulechg >/dev/null 2>&1; then
  useradd -r -U -M -d /opt/rule-change -s /bin/bash -c 'approved rule-change MCP' rulechg
  CREATED_USER=1
fi
usermod -p '*' rulechg
install -d -o root -g rulechg -m 0750 /opt/rule-change /opt/rule-change/.ssh
install -d -o root -g root -m 0700 /etc/rule-change "$STATE"
[[ -n ${RULE_READONLY_PUBKEY:-} && $RULE_READONLY_PUBKEY != "$RULE_PUBKEY" ]] || die 'independent RULE_READONLY_PUBKEY required'
install -o root -g rulechg -m 0644 "$MCP_SRC" "$MCP_DST"
install -o root -g rulechg -m 0750 "$WRAP_SRC" "$WRAP_DST"
install -o root -g root -m 0750 "$EXEC_SRC" "$EXEC_DST"
if [[ ! -e $TOKEN_DST || ! $RULE_BROKER_TOKEN_FILE -ef $TOKEN_DST ]]; then
  install -o root -g root -m 0600 "$RULE_BROKER_TOKEN_FILE" "$TOKEN_DST"
fi
chown root:root "$TOKEN_DST"; chmod 0600 "$TOKEN_DST"
python3 - "$ROLE" "$BROKER_URL" "$CONFIG" <<'PY'
import json, sys
role, url, dest=sys.argv[1:]
with open(dest,'w',encoding='utf-8') as f:
    json.dump({'host':role,'broker_url':url,'broker_token_file':'/etc/rule-change/broker.token'},f)
    f.write('\n')
PY
chown root:root "$CONFIG"; chmod 0600 "$CONFIG"

printf 'restrict,command="%s" %s\n' "$WRAP_DST" "$RULE_PUBKEY" > "$AK"
chown root:rulechg "$AK"; chmod 0640 "$AK"
cat > "$SUDOERS" <<'EOF'
# Only the exact no-argument executor call is available from the MCP account.
Defaults:rulechg env_reset
Defaults:rulechg !setenv
rulechg ALL=(root) NOPASSWD: /usr/local/sbin/rule-change-executor ""
EOF
chmod 0440 "$SUDOERS"
visudo -cf "$SUDOERS" >/dev/null || die 'sudoers invalid'
cat > "$SSHD" <<'EOF'
Match User rulechg
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PubkeyAuthentication yes
    ForceCommand /opt/rule-change/run-rule-change.sh
    PermitTTY no
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitUserRC no
Match all
EOF
chmod 0644 "$SSHD"
sshd -t || die 'sshd configuration invalid'
systemctl reload ssh || die 'sshd reload failed'
CFG=$(sshd -T -C "user=rulechg,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22")
for expected in 'forcecommand /opt/rule-change/run-rule-change.sh' 'permittty no' 'allowtcpforwarding no' 'passwordauthentication no' 'kbdinteractiveauthentication no'; do
  grep -qx "$expected" <<<"$CFG" || die "sshd effective restriction missing: $expected"
done

cat > "$SERVICE" <<'EOF'
[Unit]
Description=Apply only specifically approved local security rule proposals
After=network-online.target docker.service
Wants=network-online.target
[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/local/sbin/rule-change-executor --once
NoNewPrivileges=yes
PrivateTmp=yes
UMask=0077
EOF
cat > "$TIMER" <<'EOF'
[Unit]
Description=Poll approved local security rule proposals
[Timer]
OnBootSec=30s
OnUnitActiveSec=10s
AccuracySec=1s
Unit=rule-change-worker.service
[Install]
WantedBy=timers.target
EOF
chmod 0644 "$SERVICE" "$TIMER"
python3 - "$SRC/rule_readonly_install.py" "$ROLE" "$RULE_READONLY_PUBKEY" <<'PYREAD' || die 'read-only account provisioning failed'
import pathlib, sys
namespace={"__name__":"capstone_rule_readonly_install"}
exec(compile(pathlib.Path(sys.argv[1]).read_bytes(),sys.argv[1],"exec"),namespace)
namespace["install"](sys.argv[2],sys.argv[3])
PYREAD
systemctl reload ssh || die 'sshd readonly reload failed'
systemctl daemon-reload
"$EXEC_DST" --check >/dev/null || die 'root executor --check failed'
"$EXEC_DST" --broker-check >/dev/null || die 'root executor HMAC broker check failed'

# Protocol smoke test is read-only: initialize and tools/list only.
python3 - "$WRAP_DST" "$ROLE" <<'PY' || die 'unprivileged MCP protocol smoke test failed'
import json, subprocess, sys
msgs=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'installer','version':'1'}}},
      {'jsonrpc':'2.0','method':'notifications/initialized'},
      {'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}}]
p=subprocess.run(['runuser','-u','rulechg','--',sys.argv[1]],input='\n'.join(map(json.dumps,msgs))+'\n',text=True,capture_output=True,timeout=10)
assert p.returncode==0 and not p.stderr, 'MCP wrapper failed'
rows=[json.loads(line) for line in p.stdout.splitlines()]
tools=next(row['result']['tools'] for row in rows if row.get('id')==2)
assert {t['name'] for t in tools}==({'propose_rule_edit','propose_rule_change','propose_service_action'} | ({'temporarily_contain_ip'} if sys.argv[2]=='a' else set()))
PY
systemctl enable --now rule-change-worker.timer >/dev/null || die 'worker timer failed'
systemctl is-active --quiet rule-change-worker.timer || die 'worker timer not active'
MODIFIED=0
echo "rule-change $ROLE: installed; dedicated SSH/user/sudo and worker active; backup $BACKUP"
echo 'No security rule content was modified by this installer. Register Hermes only after both A/B pass SSH contract tests.'
