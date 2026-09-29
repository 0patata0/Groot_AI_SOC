#!/bin/bash
# Groot_B: 읽기전용 Wazuh MCP 서버(stdio) 배치 — 게이트형(적대적 리뷰 5관점 반영, 2026-09-26).
# 원칙(A안): 자격증명은 B의 /etc/mcp/wazuh-ro.env 에만. 전용 사용자 mcp + sshd Match/ForceCommand + authorized_keys restrict
#            → 클라이언트 키로는 MCP 서버만 실행 가능(셸·포워딩·PTY 불가).
# 실행(비밀은 argv·디스크에 두지 않고 stdin 으로 root 셸에 주입):
#   printf "MCP_API_PW='..'\nMCP_IDX_PW='..'\nAPI_ADMIN_PW='..'\nIDX_ADMIN_PW='..'\nMCP_PUBKEY='ssh-ed25519 AAAA.. c'\n" \
#     | sudo -k -S -p '' bash -c 'set -a; . /dev/stdin; set +a; exec bash /tmp/deploy_mcp_B.sh'   (sudo 비번은 첫 줄)
# 입력(env):
#   MCP_API_PW / MCP_IDX_PW   mcp-ro 계정 비밀번호(8~64자, 대·소·숫·기호; ' " \ 공백 금지)
#   API_ADMIN_PW / IDX_ADMIN_PW   관리자 비밀번호(API_ADMIN_USER 기본 wazuh-wui, IDX_ADMIN_USER 기본 admin)
#   MCP_PUBKEY                클라이언트 공개키 한 줄
#   MCP_BIN_SRC / MCP_WRAP_SRC / MCP_TEST_SRC   반입 파일(기본 /tmp/mcp-server-wazuh-linux-amd64, /tmp/run-wazuh-ro.sh, /tmp/contract_test.py)
# 재실행: 기존 계정이 있으면 "주어진 비밀번호 == 라이브 비밀번호"를 먼저 확인하고(불일치면 중단), 파일/키/sshd는 멱등. env 파일은 검증 뒤 원자적 교체.
set -euo pipefail
: "${MCP_API_PW:?MCP_API_PW unset}" "${MCP_IDX_PW:?MCP_IDX_PW unset}" "${API_ADMIN_PW:?API_ADMIN_PW unset}" "${IDX_ADMIN_PW:?IDX_ADMIN_PW unset}" "${MCP_PUBKEY:?MCP_PUBKEY unset}"
API_ADMIN_USER=${API_ADMIN_USER:-wazuh-wui}; IDX_ADMIN_USER=${IDX_ADMIN_USER:-admin}
SRC=${MCP_BIN_SRC:-/tmp/mcp-server-wazuh-linux-amd64}
SHA=${MCP_BIN_SHA256:-8a18cb44007d4834ee77ae8975355f404c49bda8c0d686e534994e3514134834}
WRAP_SRC=${MCP_WRAP_SRC:-/tmp/run-wazuh-ro.sh}; TEST_SRC=${MCP_TEST_SRC:-/tmp/contract_test.py}
API=https://127.0.0.1:55000; IDX=https://127.0.0.1:9200
COMPOSE_DIR=${COMPOSE_DIR:-/home/groot_b/capstone/wazuh/single-node}
IUSERS=$COMPOSE_DIR/config/wazuh_indexer/internal_users.yml
IDXC=${IDXC:-single-node-wazuh.indexer-1}
WRAP=/opt/mcp/run-wazuh-ro.sh; ENVF=/etc/mcp/wazuh-ro.env; AK=/opt/mcp/.ssh/authorized_keys
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*"; exit 1; }
# 자격증명은 argv 가 아니라 fd 로 (ps 노출 방지): basic auth → curl -K, bearer → -H @file
cu(){ local u=$1 p=$2; shift 2; curl -sk --max-time 20 -K <(printf 'user = "%s:%s"\n' "$u" "$p") "$@"; }
cb(){ curl -sk --max-time 20 -H @<(printf 'Authorization: Bearer %s\n' "$TK") "$@"; }
cr(){ curl -sk --max-time 20 -H @<(printf 'Authorization: Bearer %s\n' "$TKRO") "$@"; }
jget(){ python3 -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit(1)
for k in sys.argv[1].split("."):
    try: d = d[int(k)] if isinstance(d,list) else d[k]
    except Exception: sys.exit(1)
print(d)' "$1"; }
redact(){ sed -E 's/("?password"?[[:space:]]*[:=][[:space:]]*)"[^"]*"/\1"<redacted>"/g' | cut -c1-300; }
JWT='^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$'

say "G0 preflight"
[ "$(id -u)" = 0 ] || die "run as root"
[ -f "$SRC" ] || die "binary missing: $SRC"
echo "$SHA  $SRC" | sha256sum -c - >/dev/null || die "binary sha256 mismatch (expected reviewed v0.3.0 build)"
[ -f "$WRAP_SRC" ] || die "wrapper missing: $WRAP_SRC"; grep -q 'exec "\$BIN"' "$WRAP_SRC" || die "wrapper does not exec the binary"
[ -f "$TEST_SRC" ] || die "contract_test.py missing: $TEST_SRC"
for v in MCP_API_PW MCP_IDX_PW API_ADMIN_PW IDX_ADMIN_PW; do p=${!v}; [[ $p != *[\'\"\\[:space:]]* ]] || die "$v must not contain quotes, backslash or whitespace"; done
for v in MCP_API_PW MCP_IDX_PW; do
  p=${!v}; [ ${#p} -ge 8 ] && [ ${#p} -le 64 ] || die "$v length must be 8..64"
  [[ $p =~ [a-z] && $p =~ [A-Z] && $p =~ [0-9] && $p =~ [^A-Za-z0-9] ]] || die "$v must contain upper, lower, digit, symbol"
done
MCP_PUBKEY=$(printf '%s' "$MCP_PUBKEY" | tr -d '\r\n')
[[ $MCP_PUBKEY =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256)\ [A-Za-z0-9+/=]+(\ [^[:cntrl:]]*)?$ ]] || die "MCP_PUBKEY does not look like a single public key line"
ssh-keygen -l -f <(printf '%s\n' "$MCP_PUBKEY") >/dev/null 2>&1 || die "MCP_PUBKEY not parseable by ssh-keygen"
KEYBODY=$(awk '{print $2}' <<<"$MCP_PUBKEY")
TK=$(cu "$API_ADMIN_USER" "$API_ADMIN_PW" -X POST "$API/security/user/authenticate?raw=true"); [[ $TK =~ $JWT ]] || die "API admin auth failed ($API_ADMIN_USER)"
R=$(cu "$IDX_ADMIN_USER" "$IDX_ADMIN_PW" "$IDX/_cluster/health") && grep -q '"status"' <<<"$R" || die "indexer admin auth/health failed"
RID=$(cb "$API/security/roles" | python3 -c 'import json,sys; print(next((r["id"] for r in json.load(sys.stdin)["data"]["affected_items"] if r["name"]=="readonly"), ""))'); [ -n "$RID" ] || die "readonly role not found"
R=$(cu "$IDX_ADMIN_USER" "$IDX_ADMIN_PW" "$IDX/_plugins/_security/api/rolesmapping/readall") && python3 -c 'import json,sys; d=json.load(sys.stdin); assert "readall" in d["readall"]["backend_roles"], d' <<<"$R" 2>/dev/null || die "rolesmapping readall (backend_role readall) missing — cannot map via backend_roles"
CFG=$(sshd -T -C user=mcp,host=10.200.10.10,addr=10.200.10.10,laddr=10.200.10.10,lport=22) || die "sshd -T failed"
grep -qx 'pubkeyauthentication yes' <<<"$CFG" || die "sshd: PubkeyAuthentication must be yes"
grep -qx 'usepam yes' <<<"$CFG" || die "sshd: UsePAM must be yes"
grep -q '^authorizedkeysfile .*\.ssh/authorized_keys' <<<"$CFG" || die "sshd: AuthorizedKeysFile lacks .ssh/authorized_keys"
if grep -iqE '^(allowusers|allowgroups|denyusers|denygroups) ' <<<"$CFG"; then die "sshd Allow/Deny lists present — add mcp explicitly first"; fi
[ ! -e /etc/ssh/sshrc ] || die "/etc/ssh/sshrc exists: its stdout would pollute the MCP stdio channel"
[ -f "$IUSERS" ] || die "internal_users.yml not found at $IUSERS"
docker ps --format '{{.Names}}' | grep -qx "$IDXC" || die "indexer container $IDXC not running"
command -v python3 >/dev/null || die "python3 missing"; command -v runuser >/dev/null || die "runuser missing"
echo "ok: binary sha256, wrapper, test, passwords, pubkey($(ssh-keygen -l -f <(printf '%s\n' "$MCP_PUBKEY") | cut -d' ' -f2)), API admin, indexer admin, readonly role id=$RID, readall mapping, sshd"

say "P1 user mcp (system, no password hash, home /opt/mcp root-owned)"
id mcp >/dev/null 2>&1 || useradd -r -M -d /opt/mcp -s /bin/bash -c "capstone MCP server" mcp
usermod -p '*' mcp
install -d -o root -g mcp -m 0750 /opt/mcp /opt/mcp/.ssh
id mcp

say "P2 binary + wrapper + contract test (root:mcp 0750)"
install -o root -g mcp -m 0750 "$SRC" /opt/mcp/mcp-server-wazuh
install -o root -g mcp -m 0750 "$WRAP_SRC" "$WRAP"
install -o root -g mcp -m 0750 "$TEST_SRC" /opt/mcp/contract_test.py
ls -l /opt/mcp | sed 's/^/  /'

say "P3 Wazuh API user mcp-ro (role readonly)"
UID_RO=$(cb "$API/security/users" | python3 -c 'import json,sys; u=[x for x in json.load(sys.stdin)["data"]["affected_items"] if x["username"]=="mcp-ro"]; print(u[0]["id"] if u else "")')
if [ -z "$UID_RO" ]; then
  R=$(cb -X POST "$API/security/users" -H 'Content-Type: application/json' --data-binary @<(printf '{"username":"mcp-ro","password":"%s"}' "$MCP_API_PW"))
  UID_RO=$(jget data.affected_items.0.id <<<"$R" || true); [ -n "$UID_RO" ] || { redact <<<"$R"; die "API user create failed"; }
  echo "created mcp-ro id=$UID_RO"
else
  C=$(cu mcp-ro "$MCP_API_PW" -o /dev/null -w '%{http_code}' -X POST "$API/security/user/authenticate?raw=true")
  if [ "$C" = 200 ]; then echo "mcp-ro exists id=$UID_RO, password verified"
  elif [ "${MCP_ROTATE:-0}" = 1 ]; then
    R=$(cb -X PUT "$API/security/users/$UID_RO" -H 'Content-Type: application/json' --data-binary @<(printf '{"password":"%s"}' "$MCP_API_PW"))
    [ "$(jget data.total_affected_items <<<"$R" || true)" = 1 ] || { redact <<<"$R"; die "API password rotate failed"; }
    echo "mcp-ro exists id=$UID_RO, password ROTATED"
  else die "mcp-ro exists (id=$UID_RO) but MCP_API_PW != live password. Re-run with MCP_ROTATE=1 to set the new one, or pass the current one"; fi
fi
has_role(){ cb "$API/security/users?user_ids=$UID_RO" | python3 -c 'import json,sys; u=json.load(sys.stdin)["data"]["affected_items"][0]; sys.exit(0 if int(sys.argv[1]) in u["roles"] else 1)' "$RID"; }
has_role || { cb -X POST "$API/security/users/$UID_RO/roles?role_ids=$RID" >/dev/null; has_role || die "role bind failed"; }
cb "$API/security/users?user_ids=$UID_RO" | python3 -c 'import json,sys; u=json.load(sys.stdin)["data"]["affected_items"][0]; print("  user",u["username"],"id",u["id"],"roles",u["roles"],"allow_run_as",u["allow_run_as"])'

say "P4 indexer user mcp-ro (backend_role readall -> role readall via default rolesmapping)"
C=$(cu "$IDX_ADMIN_USER" "$IDX_ADMIN_PW" -o /dev/null -w '%{http_code}' "$IDX/_plugins/_security/api/internalusers/mcp-ro")
ROTATED_IDX=0
if [ "$C" = 200 ]; then
  C2=$(cu mcp-ro "$MCP_IDX_PW" -o /dev/null -w '%{http_code}' "$IDX/_plugins/_security/authinfo")
  if [ "$C2" = 200 ]; then echo "indexer mcp-ro exists, password verified"
  elif [ "${MCP_ROTATE:-0}" = 1 ]; then
    R=$(cu "$IDX_ADMIN_USER" "$IDX_ADMIN_PW" -X PUT "$IDX/_plugins/_security/api/internalusers/mcp-ro" -H 'Content-Type: application/json' --data-binary @<(printf '{"password":"%s","backend_roles":["readall"],"description":"capstone MCP read-only"}' "$MCP_IDX_PW"))
    grep -qE '"status" ?: ?"(CREATED|OK)"' <<<"$R" || { redact <<<"$R"; die "indexer password rotate failed"; }
    ROTATED_IDX=1; echo "indexer mcp-ro exists, password ROTATED"
  else die "indexer mcp-ro exists but MCP_IDX_PW != live password. Re-run with MCP_ROTATE=1, or pass the current one"; fi
else
  R=$(cu "$IDX_ADMIN_USER" "$IDX_ADMIN_PW" -X PUT "$IDX/_plugins/_security/api/internalusers/mcp-ro" -H 'Content-Type: application/json' --data-binary @<(printf '{"password":"%s","backend_roles":["readall"],"description":"capstone MCP read-only"}' "$MCP_IDX_PW"))
  grep -qE '"status" ?: ?"(CREATED|OK)"' <<<"$R" || { redact <<<"$R"; die "indexer user create failed"; }
  echo "created indexer mcp-ro"
fi

say "P5 internal_users.yml sync (securityadmin -t internalusers replaces the whole doc from this file)"
if [ "$ROTATED_IDX" = 1 ] && grep -qE '^mcp-ro:' "$IUSERS"; then
  install -o root -g root -m 0600 "$IUSERS" "$IUSERS.bak.$(date +%Y%m%d%H%M%S)"
  python3 - "$IUSERS" <<'PY'
import re, sys
p = sys.argv[1]; out = []; skip = False
for l in open(p).read().split("\n"):
    if re.match(r'^mcp-ro:\s*$', l): skip = True; continue
    if skip and (l.startswith((' ', '\t')) or l.strip() == ''): continue
    skip = False; out.append(l)
open(p, 'w').write("\n".join(out).rstrip("\n") + "\n")   # 같은 inode 유지(단일 파일 bind mount)
PY
  echo "internal_users.yml: old mcp-ro entry removed (rotation)"
fi
if ! grep -qE '^mcp-ro:' "$IUSERS"; then
  HERR=$(mktemp)
  H=$(printf '%s\n' "$MCP_IDX_PW" | docker exec -i -e JAVA_HOME=/usr/share/wazuh-indexer/jdk -e OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk "$IDXC" bash -c 'IFS= read -r HPW && export HPW && bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -env HPW' 2>"$HERR" | tail -n1)
  [[ $H == \$2* ]] || { cat "$HERR" >&2; rm -f "$HERR"; die "hash.sh failed"; }; rm -f "$HERR"
  install -o root -g root -m 0600 "$IUSERS" "$IUSERS.bak.$(date +%Y%m%d%H%M%S)"
  printf '\nmcp-ro:\n  hash: "%s"\n  reserved: false\n  backend_roles:\n  - "readall"\n  description: "capstone MCP read-only. Created live via REST %s; keep this entry in sync (rotate: hash.sh -> here -> securityadmin -t internalusers)"\n' "$H" "$(date -u +%F)" >> "$IUSERS"
  echo "internal_users.yml: mcp-ro appended (hash only)"
else echo "internal_users.yml already has mcp-ro"; fi
LIVE=$(cu "$IDX_ADMIN_USER" "$IDX_ADMIN_PW" "$IDX/_plugins/_security/api/internalusers" | python3 -c 'import json,sys; print("\n".join(json.load(sys.stdin)))')
for u in $LIVE; do grep -qE "^$u:" "$IUSERS" || echo "  WARN: live indexer user '$u' not in internal_users.yml (securityadmin -t internalusers would delete it)"; done

say "P6 sshd Match User mcp (server-side force) + authorized_keys restrict (root:mcp 0640 — mcp cannot rewrite it)"
cat > /etc/ssh/sshd_config.d/60-capstone-mcp.conf <<'EOF'
# capstone: MCP 전용 계정 mcp — 키 인증만, 래퍼만 실행, PTY/포워딩 금지. authorized_keys 의 restrict,command= 과 이중 강제.
Match User mcp
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PubkeyAuthentication yes
    ForceCommand /opt/mcp/run-wazuh-ro.sh
    PermitTTY no
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitUserRC no
Match all
EOF
sshd -t || die "sshd config invalid after Match block"
systemctl reload ssh
LINE="restrict,command=\"$WRAP\" $MCP_PUBKEY"
touch "$AK"; grep -qF -- "$KEYBODY" "$AK" || printf '%s\n' "$LINE" >> "$AK"
chown root:mcp "$AK"; chmod 0640 "$AK"
if grep -vqE "^restrict,command=\"$WRAP\" " "$AK"; then die "unrestricted line in $AK"; fi
sshd -T -C user=mcp,host=10.200.10.10,addr=10.200.10.10,laddr=10.200.10.10,lport=22 | grep -E '^(forcecommand|permittty|allowtcpforwarding|passwordauthentication) ' | sed 's/^/  effective: /'
cut -c1-80 "$AK" | sed 's/^/  /'

say "V1 mcp-ro is read-only on the API (every endpoint the MCP tools use must be 200, writes 403)"
TKRO=$(cu mcp-ro "$MCP_API_PW" -X POST "$API/security/user/authenticate?raw=true"); [[ $TKRO =~ $JWT ]] || die "mcp-ro API auth failed"
FAIL=0
# (/vulnerability/{id} API는 4.8+에서 제거됨(404) — 취약점은 인덱서 wazuh-states-vulnerabilities-* 로, readall 이 커버)
for ep in 'agents?limit=1' 'manager/logs?limit=1' 'manager/logs/summary' 'manager/stats/weekly' 'manager/stats/remoted' 'rules?limit=1' 'agents/001/stats/logcollector' 'syscollector/001/ports?limit=1' 'syscollector/001/processes?limit=1'; do
  C=$(cr -o /dev/null -w '%{http_code}' "$API/$ep"); printf '  GET /%-36s -> %s\n' "$ep" "$C"; [ "$C" = 403 ] && FAIL=1
done
[ $FAIL = 0 ] || die "readonly role lacks an action used by an MCP tool (403 above)"
NEG=$(mktemp)
C=$(cr -o "$NEG" -w '%{http_code}' -X POST "$API/security/users" -H 'Content-Type: application/json' -d '{"username":"zz-should-fail","password":"Zz1!zzzzzz"}'); [ "$C" = 403 ] || { cut -c1-200 "$NEG"; die "mcp-ro POST /security/users -> $C (expected 403)"; }
echo "  POST /security/users -> 403 (resourceless write denied)"
# 리소스 기반 쓰기: Wazuh RBAC은 허용 리소스가 0개면 403 대신 200 + affected 0 ("not sent to any agent")로 응답 — 둘 다 '효과 없음'이면 통과
C=$(cr -o "$NEG" -w '%{http_code}' -X PUT "$API/agents/restart")
if [ "$C" = 403 ]; then echo "  PUT /agents/restart -> 403"
elif [ "$C" = 200 ] && [ "$(jget data.total_affected_items <"$NEG" || true)" = 0 ]; then echo "  PUT /agents/restart -> 200 with 0 agents affected (RBAC filtered all agents; nothing restarted)"
else cut -c1-200 "$NEG"; die "mcp-ro PUT /agents/restart -> $C with effect (expected denial)"; fi
rm -f "$NEG"

say "V2 mcp-ro is read-only on the indexer"
N=""; for i in 1 2 3 4 5; do R=$(cu mcp-ro "$MCP_IDX_PW" "$IDX/wazuh-alerts-*/_count"); N=$(jget count <<<"$R") && break; sleep 2; done
[ -n "$N" ] || { redact <<<"$R"; die "mcp-ro _count wazuh-alerts-* failed"; }; echo "  wazuh-alerts-* count: $N"
C=$(cu mcp-ro "$MCP_IDX_PW" -o /dev/null -w '%{http_code}' "$IDX/wazuh-alerts-*/_search?size=1"); [ "$C" = 200 ] || die "mcp-ro _search -> $C"
R=$(cu mcp-ro "$MCP_IDX_PW" "$IDX/_plugins/_security/authinfo"); python3 -c 'import json,sys; d=json.load(sys.stdin); assert "readall" in d["roles"], d["roles"]; print("  authinfo roles:", d["roles"], "backend:", d.get("backend_roles"))' <<<"$R" || die "mcp-ro not mapped to readall"
C=$(cu mcp-ro "$MCP_IDX_PW" -o /dev/null -w '%{http_code}' -X PUT "$IDX/zz-should-fail"); [ "$C" = 403 ] || die "mcp-ro PUT index -> $C (expected 403)"
C=$(cu mcp-ro "$MCP_IDX_PW" -o /dev/null -w '%{http_code}' "$IDX/_plugins/_security/api/internalusers"); [ "$C" = 403 ] || die "mcp-ro security API -> $C (expected 403)"
C=$(cu mcp-ro "$MCP_IDX_PW" -o /dev/null -w '%{http_code}' "$IDX/"); echo "  writes/security 403; GET / -> $C (403 expected with readall; informational)"

say "P7 env file $ENVF (root:mcp 0640, atomic replace — only after the accounts are proven)"
install -d -o root -g mcp -m 0750 /etc/mcp
( umask 027; cat > "$ENVF.new" <<EOF
# capstone read-only Wazuh MCP server env — generated $(date -u +%FT%TZ). Accounts: mcp-ro (API role readonly / indexer backend_role readall)
WAZUH_API_HOST=127.0.0.1
WAZUH_API_PORT=55000
WAZUH_API_USERNAME=mcp-ro
WAZUH_API_PASSWORD='$MCP_API_PW'
WAZUH_INDEXER_HOST=127.0.0.1
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USERNAME=mcp-ro
WAZUH_INDEXER_PASSWORD='$MCP_IDX_PW'
WAZUH_VERIFY_SSL=false
RUST_LOG=info
EOF
)
chown root:mcp "$ENVF.new"; chmod 0640 "$ENVF.new"; mv -f "$ENVF.new" "$ENVF"
ls -l "$ENVF" | sed 's/^/  /'

say "V3 contract as user mcp via the wrapper (initialize -> initialized -> tools/list -> tools/call; proves API + indexer creds; stdout must be pure JSON)"
# get_wazuh_agents 는 status 가 필수(v0.3.0 스키마 required=[status]); alert_summary 는 인덱서 경로, agents 는 API 경로 → 두 자격증명 모두 실증
for spec in 'get_wazuh_agents {"status":"active"}' 'get_wazuh_alert_summary {"limit":3}'; do
  set -- $spec
  python3 /opt/mcp/contract_test.py --cmd "env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/opt/mcp runuser -u mcp -- $WRAP" --tool "$1" --args "$2" --timeout 60 || die "contract test failed for $1"
done
echo; echo "== MCP_DEPLOY_DONE =="
