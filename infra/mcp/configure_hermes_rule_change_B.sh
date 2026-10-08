#!/bin/bash
# Run on Groot_B only AFTER both A/B rule-change servers and broker pass tests.
# --prepare-key creates only the dedicated client key and prints its public key.
# --check is read-only. Default apply registers two MCP entries and the managed
# SOUL policy, with rollback of Hermes files on any failed contract/parse check.
set -euo pipefail
umask 077
MODE=${1:---apply}
[[ $MODE == --prepare-key || $MODE == --check || $MODE == --apply ]] || { echo 'usage: configure_hermes_rule_change_B.sh [--prepare-key|--check|--apply]' >&2; exit 2; }
[[ $# -le 1 && $(id -u) == 0 ]] || { echo 'run as root with one optional mode' >&2; exit 1; }
DATA=/opt/hermes-data
SSH_DIR=$DATA/home/.ssh
KEY=$SSH_DIR/rule_change_ed25519
SSH_CFG=$SSH_DIR/config
YAML=$DATA/config.yaml
SOUL=$DATA/SOUL.md
SOUL_SRC=${RULE_SOUL_SRC:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../hermes" && pwd -P)/SOUL.groot.md}
START='<!-- rule-change-policy:start -->'
END='<!-- rule-change-policy:end -->'
BACKUP=; MODIFIED=0
die(){ echo "Hermes rule-change setup: $*" >&2; exit 1; }
for bin in python3 docker ssh-keygen stat; do command -v "$bin" >/dev/null || die "missing command: $bin"; done
id hermes >/dev/null 2>&1 || die 'hermes OS user missing'
[[ -d $SSH_DIR && ! -L $SSH_DIR ]] || die 'Hermes SSH directory missing/symlink'
[[ -f $YAML && ! -L $YAML && -f $SSH_CFG && ! -L $SSH_CFG ]] || die 'Hermes config or SSH config missing/symlink'
[[ -f $SOUL && ! -L $SOUL && -f $SOUL_SRC && ! -L $SOUL_SRC ]] || die 'SOUL file missing/symlink'
python3 - "$SOUL_SRC" <<'PY' || die 'SOUL source and parent directory must be root-controlled'
import os, pathlib, stat, sys
path=pathlib.Path(sys.argv[1])
for item,kind in ((path,stat.S_ISREG),(path.parent,stat.S_ISDIR)):
    info=os.lstat(item)
    assert kind(info.st_mode) and info.st_uid==0 and not(stat.S_IMODE(info.st_mode)&0o022)
PY
python3 - "$SOUL_SRC" <<'PY' || die 'SOUL source must contain one complete marked policy block'
import pathlib, sys
s=pathlib.Path(sys.argv[1]).read_text()
assert s.count('<!-- rule-change-policy:start -->')==1
assert s.count('<!-- rule-change-policy:end -->')==1
assert s.index('<!-- rule-change-policy:start -->')<s.index('<!-- rule-change-policy:end -->')
PY

if [[ $MODE == --prepare-key ]]; then
  [[ ! -e $KEY && ! -e $KEY.pub ]] || die 'key already exists; do not rotate implicitly'
  ssh-keygen -q -t ed25519 -N '' -C 'hermes-rule-change@groot-siem' -f "$KEY"
  chown hermes:hermes "$KEY" "$KEY.pub"; chmod 0600 "$KEY"; chmod 0644 "$KEY.pub"
  echo 'Dedicated rule-change public key (register on both A and B with deploy scripts):'
  cat "$KEY.pub"
  exit 0
fi
[[ -f $KEY && ! -L $KEY && -f $KEY.pub && ! -L $KEY.pub ]] || die 'dedicated key absent; run --prepare-key first'
[[ $(stat -c %a "$KEY") == 600 ]] || die 'private key mode must be 0600'
[[ $(stat -c %u "$KEY") == $(id -u hermes) ]] || die 'private key owner mismatch'
ACTUAL=$(ssh-keygen -y -f "$KEY") || die 'private key invalid'
[[ $(awk '{print $1,$2}' <<<"$ACTUAL") == $(awk '{print $1,$2}' "$KEY.pub") ]] || die 'public/private key mismatch'
[[ $(id -nG hermes) != *mcp* && $(id -nG hermes) != *rulechg* && $(id -nG hermes) != *docker* ]] || die 'hermes OS user has a privileged server group'
docker inspect hermes --format '{{.State.Running}}' | grep -qx true || die 'Hermes container not running'
for host in 10.200.10.1 10.200.10.10; do
  ssh-keygen -F "$host" -f "$SSH_DIR/known_hosts" >/dev/null 2>&1 || die "known_hosts lacks $host"
done

if [[ $MODE == --check ]]; then
  python3 - "$SSH_CFG" "$YAML" "$SOUL" "$SOUL_SRC" <<'PY' || die 'Hermes managed entries missing or drifted'
import pathlib, sys
ssh,yaml,soul,source=[pathlib.Path(p).read_text() for p in sys.argv[1:]]
assert ssh.count('# rule-change-hosts:start')==ssh.count('# rule-change-hosts:end')==1
assert yaml.count('  # rule-change-mcp:start')==yaml.count('  # rule-change-mcp:end')==1
assert soul.count('<!-- rule-change-policy:start -->')==soul.count('<!-- rule-change-policy:end -->')==1
ssh_block=ssh[ssh.index('# rule-change-hosts:start'):ssh.index('# rule-change-hosts:end')]
yaml_block=yaml[yaml.index('  # rule-change-mcp:start'):yaml.index('  # rule-change-mcp:end')]
assert 'Host rule-a\n    HostName 10.200.10.1\n    User rulechg' in ssh_block
assert 'Host rule-b\n    HostName 10.200.10.10\n    User rulechg' in ssh_block
assert ssh_block.count('IdentityFile /opt/data/home/.ssh/rule_change_ed25519')==2
assert '  rule-a:\n    command: ssh' in yaml_block and '  rule-b:\n    command: ssh' in yaml_block
assert yaml_block.count('    trust: full')==2
start='<!-- rule-change-policy:start -->'; end='<!-- rule-change-policy:end -->'
extract=lambda s:s[s.index(start):s.index(end)+len(end)]
assert extract(soul)==extract(source)
PY
  docker exec hermes hermes config get mcp_servers.rule-a.command >/dev/null 2>&1 || die 'Hermes YAML parse failed (rule-a)'
  docker exec hermes hermes config get mcp_servers.rule-b.command >/dev/null 2>&1 || die 'Hermes YAML parse failed (rule-b)'
  echo 'Hermes rule-change: read-only configuration check PASS; no files or services changed'
  exit 0
fi

BACKUP=$(mktemp -d /var/backups/rule-change-hermes.XXXXXX)
cp -a "$SSH_CFG" "$BACKUP/ssh-config"
cp -a "$YAML" "$BACKUP/config.yaml"
cp -a "$SOUL" "$BACKUP/SOUL.md"
rollback(){
  set +e
  cp -a "$BACKUP/ssh-config" "$SSH_CFG"
  cp -a "$BACKUP/config.yaml" "$YAML"
  cp -a "$BACKUP/SOUL.md" "$SOUL"
  docker restart hermes >/dev/null 2>&1
  echo "Hermes rule-change: setup failed; files restored from $BACKUP" >&2
}
cleanup(){
  status=$?
  trap - EXIT
  if [[ $status != 0 && $MODIFIED == 1 ]]; then rollback; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
MODIFIED=1

# Replace only our marked blocks. Other Hermes config, SSH aliases and persona
# are preserved. Atomic rename is safe here because /opt/hermes-data is a
# directory mount, not a single-file bind mount.
python3 - "$SSH_CFG" "$YAML" "$SOUL" "$SOUL_SRC" <<'PY'
import os, pathlib, re, sys, tempfile
ssh_path,yaml_path,soul_path,src_path=map(pathlib.Path,sys.argv[1:])
def managed(text,start,end,block):
    if text.count(start)!=text.count(end) or text.count(start)>1:
        raise ValueError('broken managed block markers')
    if start in text:
        a=text.index(start); b=text.index(end,a)+len(end)
        text=text[:a]+text[b:]
    return text,block
def replace(path,content):
    st=path.stat(); fd,tmp=tempfile.mkstemp(prefix='.rule-change-config-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            f.write(content); f.flush(); os.fsync(f.fileno())
        os.chown(tmp,st.st_uid,st.st_gid); os.chmod(tmp,st.st_mode & 0o777)
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
ssh=ssh_path.read_text()
ssh,block=managed(ssh,'# rule-change-hosts:start','# rule-change-hosts:end', '''# rule-change-hosts:start
Host rule-a
    HostName 10.200.10.1
    User rulechg
    IdentityFile /opt/data/home/.ssh/rule_change_ed25519
    IdentitiesOnly yes
    BatchMode yes
    UserKnownHostsFile /opt/data/home/.ssh/known_hosts
    StrictHostKeyChecking yes
    ServerAliveInterval 30
Host rule-b
    HostName 10.200.10.10
    User rulechg
    IdentityFile /opt/data/home/.ssh/rule_change_ed25519
    IdentitiesOnly yes
    BatchMode yes
    UserKnownHostsFile /opt/data/home/.ssh/known_hosts
    StrictHostKeyChecking yes
    ServerAliveInterval 30
# rule-change-hosts:end''')
if re.search(r'(?m)^Host\s+rule-[ab]\s*$',ssh): raise ValueError('unmanaged rule SSH host alias exists')
replace(ssh_path,ssh.rstrip()+'\n\n'+block+'\n')
yaml=yaml_path.read_text()
yaml,block=managed(yaml,'  # rule-change-mcp:start','  # rule-change-mcp:end', '''  # rule-change-mcp:start
  rule-a:
    command: ssh
    args: ["-T", "-F", "/opt/data/home/.ssh/config", "rule-a"]
    env: {HOME: /opt/data/home}
    connect_timeout: 60
    timeout: 240
    supports_parallel_tool_calls: false
    trust: full
  rule-b:
    command: ssh
    args: ["-T", "-F", "/opt/data/home/.ssh/config", "rule-b"]
    env: {HOME: /opt/data/home}
    connect_timeout: 60
    timeout: 240
    supports_parallel_tool_calls: false
    trust: full
  # rule-change-mcp:end''')
if re.search(r'(?m)^  rule-[ab]:\s*$',yaml): raise ValueError('unmanaged rule MCP entry exists')
matches=list(re.finditer(r'(?m)^mcp_servers:\s*$',yaml))
if len(matches)!=1: raise ValueError('expected exactly one mcp_servers mapping')
at=matches[0].end()
replace(yaml_path,yaml[:at]+'\n'+block+yaml[at:])
src=src_path.read_text(); start='<!-- rule-change-policy:start -->'; end='<!-- rule-change-policy:end -->'
policy=src[src.index(start):src.index(end)+len(end)]
soul=soul_path.read_text(); soul,_=managed(soul,start,end,policy)
replace(soul_path,soul.rstrip()+'\n\n'+policy+'\n')
PY

# Calls from inside the existing container prove key, host-key verification,
# SSH forced command, sudo policy, and read-only target retrieval on each host.
for pair in 'rule-a a:modsecurity-custom' 'rule-b b:wazuh-local-rules'; do
  read -r alias target <<<"$pair"
  docker exec -i -u "$(id -u hermes):$(id -g hermes)" -e HOME=/opt/data/home hermes \
    python3 - "$alias" "$target" <<'PY' >/dev/null || die "$alias read-only SSH/MCP contract failed"
import json, subprocess, sys
alias,target=sys.argv[1:]
messages=[
 {'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-06-18','capabilities':{},'clientInfo':{'name':'deployment-check','version':'1'}}},
 {'jsonrpc':'2.0','method':'notifications/initialized'},
 {'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}},
 {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'get_rule_change_target','arguments':{'target':target}}},
]
proc=subprocess.run(['ssh','-T','-F','/opt/data/home/.ssh/config',alias],input='\n'.join(map(json.dumps,messages))+'\n',text=True,capture_output=True,timeout=90)
assert proc.returncode==0
responses={row['id']:row for row in (json.loads(line) for line in proc.stdout.splitlines()) if 'id' in row}
assert responses[1]['result']['serverInfo']['name']=='capstone-rule-change-mcp'
names={tool['name'] for tool in responses[2]['result']['tools']}
assert names=={'get_rule_change_target','propose_rule_change','get_rule_change_status'}
assert not responses[3]['result'].get('isError')
PY
done
docker exec hermes hermes config get mcp_servers.rule-a.command >/dev/null 2>&1 || die 'Hermes YAML parse failed (rule-a)'
docker exec hermes hermes config get mcp_servers.rule-b.command >/dev/null 2>&1 || die 'Hermes YAML parse failed (rule-b)'
docker restart hermes >/dev/null || die 'Hermes restart failed'
sleep 10
docker inspect hermes --format '{{.State.Running}}' | grep -qx true || die 'Hermes not running after restart'
LIST=$(docker exec hermes hermes mcp list 2>&1) || die 'Hermes MCP list failed after restart'
grep -q 'rule-a' <<<"$LIST" && grep -q 'rule-b' <<<"$LIST" || die 'rule MCP servers missing from Hermes list'
MODIFIED=0
echo "Hermes rule-change: two MCP servers and SOUL policy registered; backup $BACKUP"
