#!/bin/bash
# Add the dedicated rule-approval endpoints to the existing B soc-bot service.
# Existing IP-block broker values and other soc-bot environment lines are kept.
# Inputs: explicit RULE_APPROVERS (Mattermost user IDs) and a root-owned
# RULE_BROKER_TOKEN_FILE. The key is never passed in argv or an HTTP header.
# --check is read-only.
set -euo pipefail
umask 077
MODE=${1:-apply}
[[ $MODE == apply || $MODE == --check ]] || { echo 'usage: deploy_rule_broker_B.sh [--check]' >&2; exit 2; }
[[ $# -le 1 && $(id -u) == 0 ]] || { echo 'run as root with one optional mode' >&2; exit 1; }
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
SRC=${RULE_SOCBOT_SRC:-$HERE/soc_bot.py}
DST=/opt/socbot/soc_bot.py
ENV=/etc/socbot/soc_bot.env
BROKER=http://127.0.0.1:8090
BACKUP=; MODIFIED=0
die(){ echo "rule broker deploy: $*" >&2; exit 1; }
for bin in python3 docker curl systemctl stat; do command -v "$bin" >/dev/null || die "missing command: $bin"; done
[[ -f $SRC && ! -L $SRC && -f $DST && ! -L $DST && -f $ENV && ! -L $ENV ]] || die 'staged/live soc-bot or env missing/symlink'
python3 - "$SRC" <<'PY' || die 'staged soc_bot.py and its directory must be root-controlled'
import os, pathlib, stat, sys
path=pathlib.Path(sys.argv[1])
for item,kind in ((path,stat.S_ISREG),(path.parent,stat.S_ISDIR)):
    info=os.lstat(item)
    assert kind(info.st_mode) and info.st_uid==0 and not(stat.S_IMODE(info.st_mode)&0o022)
PY
id socbot >/dev/null 2>&1 || die 'socbot account missing'
systemctl is-active --quiet soc-bot || die 'existing soc-bot service is not active'
python3 - "$SRC" <<'PY' || die 'staged soc_bot.py syntax or rule endpoints invalid'
import ast, pathlib, sys
s=pathlib.Path(sys.argv[1]).read_text(encoding='utf-8')
ast.parse(s)
assert 'RULE_BROKER_TOKEN' in s and '/rule-changes' in s and '/rule-actions' in s
PY

[[ -n ${RULE_APPROVERS:-} ]] || die 'RULE_APPROVERS is required; never inherit an empty/default approver list'
[[ $RULE_APPROVERS =~ ^[A-Za-z0-9]{26}(,[A-Za-z0-9]{26})*$ ]] || die 'RULE_APPROVERS must be a comma-separated list of Mattermost user IDs'
[[ -z ${RULE_BROKER_TOKEN:-} ]] || die 'pass the rule key via RULE_BROKER_TOKEN_FILE, not an environment variable'
[[ -n ${RULE_BROKER_TOKEN_FILE:-} && -f $RULE_BROKER_TOKEN_FILE && ! -L $RULE_BROKER_TOKEN_FILE ]] || die 'RULE_BROKER_TOKEN_FILE must be a regular file'
[[ $(stat -c %u "$RULE_BROKER_TOKEN_FILE") == 0 && $(stat -c %a "$RULE_BROKER_TOKEN_FILE") == 600 ]] || die 'token source must be root:root 0600'
python3 - "$RULE_BROKER_TOKEN_FILE" <<'PY' || die 'token source parent directory must be root-controlled'
import os, pathlib, stat, sys
info=os.lstat(pathlib.Path(sys.argv[1]).parent)
assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not(stat.S_IMODE(info.st_mode)&0o022)
PY
python3 - "$RULE_BROKER_TOKEN_FILE" <<'PY' || die 'rule token format/length invalid'
import pathlib, re, sys
token=pathlib.Path(sys.argv[1]).read_text().strip()
assert re.fullmatch(r'[A-Za-z0-9_-]{32,128}',token)
PY

MM_IP=$(python3 - <<'PY'
import ipaddress, json, subprocess
d=json.loads(subprocess.check_output(['docker','inspect','mm-app']))[0]
assert d['State']['Running']
net=d['NetworkSettings']['Networks']['mattermost_mm-net']
ip=ipaddress.ip_address(net['IPAddress'])
assert ip.version==4 and ip in ipaddress.ip_network('172.19.0.0/16')
assert net['Gateway']=='172.19.0.1'
print(ip)
PY
) || die 'Mattermost container/network gate failed'
CIDR=$MM_IP/32

# Probe the dedicated endpoint with a nonce-bound HMAC request and verify the
# HMAC on the response. The shared key is read from the local root-controlled
# soc-bot env file; it never appears in an HTTP header or command argument.
hmac_probe(){
python3 - "$ENV" <<'PY'
import hashlib, hmac, json, pathlib, secrets, sys, time, urllib.request
values={}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if '=' not in line or line.lstrip().startswith('#'): continue
    k,v=line.split('=',1); values[k.strip()]=v.strip().strip('"').strip("'")
key=values['RULE_BROKER_TOKEN'].encode()
path='/rule-changes/health'; ts=str(int(time.time())); nonce=secrets.token_hex(16)
empty_hash=hashlib.sha256(b'').hexdigest()
request_bytes=('v1\nGET\n'+path+'\n'+ts+'\n'+nonce+'\n'+empty_hash).encode()
signature=hmac.new(key,request_bytes,hashlib.sha256).hexdigest()
req=urllib.request.Request('http://127.0.0.1:8090'+path,headers={
    'X-Rule-Timestamp':ts,'X-Rule-Nonce':nonce,'X-Rule-Signature':signature},method='GET')
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(req,timeout=8) as response:
    body=response.read(4096)
    assert response.status==200 and len(body)<4096
    response_bytes=('v1\n'+nonce+'\n'+str(response.status)+'\n'+hashlib.sha256(body).hexdigest()).encode()
    expected=hmac.new(key,response_bytes,hashlib.sha256).hexdigest()
    received=response.headers.get('X-Rule-Response-Signature','')
    assert hmac.compare_digest(received,expected), 'broker response HMAC mismatch'
PY
}

# Parse only the simple KEY=VALUE lines managed by deploy_socbot_B.sh. Never
# source the file as shell code, and never print credentials or tokens.
OLD_TOKEN=$(python3 - "$ENV" "$RULE_BROKER_TOKEN_FILE" <<'PY'
import pathlib,sys
values={}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if '=' not in line or line.lstrip().startswith('#'): continue
    k,v=line.split('=',1); values[k.strip()]=v.strip().strip('"').strip("'")
for key in ('BROKER_TOKEN','APPROVERS','MM_WEBHOOK','MM_ACTION_URL'):
    assert values.get(key), key+' is empty'
new_token=pathlib.Path(sys.argv[2]).read_text().strip()
assert values['BROKER_TOKEN']!=new_token, 'rule broker token must differ from response broker token'
print(values['BROKER_TOKEN'])
PY
) || die 'existing broker env invalid or rule token is reused'

if [[ $MODE == --check ]]; then
  python3 - "$ENV" "$RULE_BROKER_TOKEN_FILE" "$RULE_APPROVERS" "$CIDR" <<'PY' || die 'installed rule broker settings differ from requested values'
import pathlib,sys
values={}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if '=' not in line or line.lstrip().startswith('#'): continue
    k,v=line.split('=',1); values[k.strip()]=v.strip().strip('"').strip("'")
expected=(pathlib.Path(sys.argv[2]).read_text().strip(),sys.argv[3],sys.argv[4])
assert (values.get('RULE_BROKER_TOKEN'),values.get('RULE_APPROVERS'),values.get('RULE_MM_SOURCE_CIDRS'))==expected
PY
  hmac_probe || die 'rule broker HMAC request/response readiness failed'
  echo 'rule broker B: authenticated configuration check PASS; no files or services changed'
  exit 0
fi

BACKUP=$(mktemp -d /var/backups/rule-broker-deploy.XXXXXX)
cp -a "$DST" "$BACKUP/soc_bot.py"
cp -a "$ENV" "$BACKUP/soc_bot.env"
rollback(){
  set +e
  cp -a "$BACKUP/soc_bot.py" "$DST"
  cp -a "$BACKUP/soc_bot.env" "$ENV"
  systemctl restart soc-bot >/dev/null 2>&1
  echo "rule broker B: installation failed; code/env restored from $BACKUP" >&2
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
install -o root -g socbot -m 0750 "$SRC" "$DST"
python3 - "$ENV" "$RULE_BROKER_TOKEN_FILE" "$RULE_APPROVERS" "$CIDR" <<'PY'
import os, pathlib, sys, tempfile
dest=pathlib.Path(sys.argv[1]); token=pathlib.Path(sys.argv[2]).read_text().strip(); approvers,cidr=sys.argv[3:]
st=dest.stat()
lines=[]
for line in dest.read_text().splitlines():
    if line.startswith(('RULE_BROKER_TOKEN=','RULE_APPROVERS=','RULE_MM_SOURCE_CIDRS=')): continue
    lines.append(line)
lines += ['RULE_BROKER_TOKEN='+token, 'RULE_APPROVERS='+approvers, 'RULE_MM_SOURCE_CIDRS='+cidr]
fd,tmp=tempfile.mkstemp(prefix='.socbot-rule-env-',dir=dest.parent)
try:
    with os.fdopen(fd,'w') as f:
        f.write('\n'.join(lines)+'\n'); f.flush(); os.fsync(f.fileno())
    os.chown(tmp,st.st_uid,st.st_gid); os.chmod(tmp,0o640)
    os.replace(tmp,dest)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
PY
systemctl restart soc-bot || die 'soc-bot restart failed'
systemctl is-active --quiet soc-bot || die 'soc-bot not active'
hmac_probe || die 'new rule broker HMAC request/response readiness failed'
CODE=$(curl -sS --max-time 8 -o /dev/null -w '%{http_code}' -H @<(printf 'X-Broker-Token: %s\n' "$OLD_TOKEN") \
  "$BROKER/pending") || die 'original IP-block broker not reachable'
[[ $CODE == 200 ]] || die "original IP-block broker regressed (HTTP $CODE)"
MODIFIED=0
echo "rule broker B: deployed with MM callback source $CIDR; original block broker still answers; backup $BACKUP"
echo 'Re-run --check after any mm-app recreation; update /32 with this installer if the container IP changes.'
