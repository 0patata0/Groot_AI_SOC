#!/bin/bash
# Groot_A: 응답(차단) MCP 서버 배치 — 게이트형(리뷰 반영). root 로 실행(stdin 으로 비밀 주입 불필요; 자격증명 없음).
# 전제: /tmp/resp/ 에 response-mcp.py, run-response.sh 반입. capstone_fw(agent_block) 이미 적용됨. RESP_PUBKEY=클라이언트 공개키 한 줄.
# 원칙: 전용 사용자 resp(비번 없음) + sshd Match ForceCommand + authorized_keys restrict → 그 키로는 응답 서버만 실행.
#       resp sudoers = agent_block add/del/list 만(flush·기타 금지). 서버는 자격증명 없음(차단 능력은 sudoers 로 좁혀진 명령).
set -euo pipefail
: "${RESP_PUBKEY:?RESP_PUBKEY unset (client public key line)}"
SRC=${RESP_SRC:-/tmp/resp}
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*"; exit 1; }
DONE=0
cleanup(){ [ "$DONE" = 1 ] && return 0; echo "!! deploy incomplete — rolling back partial grant (sudoers, sshd drop-in, resp key)";
  rm -f /etc/sudoers.d/capstone-resp /etc/ssh/sshd_config.d/61-capstone-resp.conf /opt/resp/.ssh/authorized_keys
  systemctl reload ssh 2>/dev/null || true; }
trap cleanup EXIT

say "G0 preflight"
[ "$(id -u)" = 0 ] || die "run as root"
for f in response-mcp.py notifier.py run-response.sh agent_block_reaper.sh; do [ -f "$SRC/$f" ] || die "$SRC/$f missing"; done
python3 -m py_compile "$SRC/response-mcp.py" "$SRC/notifier.py" || die "python syntax"
bash -n "$SRC/run-response.sh" && bash -n "$SRC/agent_block_reaper.sh" || die "script syntax"
[ -x /usr/local/sbin/agent_block ] || die "agent_block not installed (run fw_phase2 first)"
nft list set inet capstone_fw agent_block >/dev/null 2>&1 || die "capstone_fw not loaded"
RESP_PUBKEY=$(printf '%s' "$RESP_PUBKEY" | tr -d '\r\n')
[[ $RESP_PUBKEY =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256)\ [A-Za-z0-9+/=]+(\ [^[:cntrl:]]*)?$ ]] || die "RESP_PUBKEY not a single public key line"
ssh-keygen -l -f <(printf '%s\n' "$RESP_PUBKEY") >/dev/null 2>&1 || die "RESP_PUBKEY not parseable"
KEYBODY=$(awk '{print $2}' <<<"$RESP_PUBKEY")
CFG=$(sshd -T -C user=resp,host=192.168.16.230,addr=192.168.16.230,laddr=192.168.16.230,lport=22) || die "sshd -T failed"
grep -qx 'usepam yes' <<<"$CFG" || die "sshd UsePAM must be yes (locked-password pubkey login)"
grep -qx 'pubkeyauthentication yes' <<<"$CFG" || die "sshd PubkeyAuthentication must be yes"
grep -q '^authorizedkeysfile .*\.ssh/authorized_keys' <<<"$CFG" || die "sshd AuthorizedKeysFile lacks .ssh/authorized_keys"
grep -iqE '^(allowusers|allowgroups|denyusers|denygroups) ' <<<"$CFG" && die "sshd Allow/Deny lists present — add resp explicitly first" || true
[ ! -e /etc/ssh/sshrc ] || die "/etc/ssh/sshrc exists: its stdout would pollute the MCP stdio channel"
echo "ok: syntax, agent_block, pubkey $(ssh-keygen -l -f <(printf '%s\n' "$RESP_PUBKEY") | cut -d' ' -f2), sshd"

say "P1 user resp (system, no password, home /opt/resp root-owned)"
id resp >/dev/null 2>&1 || useradd -r -M -d /opt/resp -s /bin/bash -c "capstone response MCP" resp
usermod -p '*' resp
install -d -o root -g resp -m 0750 /opt/resp /opt/resp/.ssh
id resp

say "P2 server + wrapper (root:resp 0750)"
install -o root -g resp -m 0750 "$SRC/response-mcp.py" /opt/resp/response-mcp.py
install -o root -g resp -m 0750 "$SRC/notifier.py" /opt/resp/notifier.py
install -o root -g resp -m 0750 "$SRC/run-response.sh" /opt/resp/run-response.sh
# 알림 채널 설정(기본 none). 채널 교체 = 이 파일만 수정(엔드포인트/백엔드). 비밀 포함 가능 → root:resp 0640.
install -d -o root -g resp -m 0750 /etc/resp
[ -f /etc/resp/hitl.env ] || { printf '# capstone 응답 알림 채널. 교체는 여기만. 승인(HITL)은 MCP elicitation 별개.\nRESP_NOTIFY_BACKEND=none\n' > /etc/resp/hitl.env; chown root:resp /etc/resp/hitl.env; chmod 0640 /etc/resp/hitl.env; }
ls -l /opt/resp /etc/resp/hitl.env | sed 's/^/  /'

say "P3 sudoers: resp may run ONLY agent_block add/del/list (no flush)"
cat > /etc/sudoers.d/capstone-resp <<'EOF'
# capstone: 응답 MCP 서버(resp)가 A 방화벽 차단 CLI 만 무암호로 실행. flush·기타 명령은 불가(최소권한).
resp ALL=(root) NOPASSWD: /usr/local/sbin/agent_block add *, /usr/local/sbin/agent_block del *, /usr/local/sbin/agent_block list
EOF
chmod 0440 /etc/sudoers.d/capstone-resp
visudo -cf /etc/sudoers.d/capstone-resp || { rm -f /etc/sudoers.d/capstone-resp; die "sudoers invalid (removed)"; }
echo "  sudoers ok"

say "P4 sshd Match User resp (ForceCommand) + authorized_keys restrict (root:resp 0640)"
cat > /etc/ssh/sshd_config.d/61-capstone-resp.conf <<'EOF'
Match User resp
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PubkeyAuthentication yes
    ForceCommand /opt/resp/run-response.sh
    PermitTTY no
    AllowTcpForwarding no
    AllowAgentForwarding no
    X11Forwarding no
    PermitUserRC no
Match all
EOF
sshd -t || { rm -f /etc/ssh/sshd_config.d/61-capstone-resp.conf; die "sshd config invalid (removed)"; }
systemctl reload ssh
AK=/opt/resp/.ssh/authorized_keys
LINE="restrict,command=\"/opt/resp/run-response.sh\" $RESP_PUBKEY"
touch "$AK"; grep -qF -- "$KEYBODY" "$AK" || printf '%s\n' "$LINE" >> "$AK"
chown root:resp "$AK"; chmod 0640 "$AK"
grep -vqE "^restrict,command=\"/opt/resp/run-response.sh\" " "$AK" && die "unrestricted line in $AK" || true
cut -c1-70 "$AK" | sed 's/^/  /'

say "P5 TTL-expiry reaper (auto-unblock 감사: action=expire → Wazuh) via systemd timer"
install -o root -g root -m 0755 "$SRC/agent_block_reaper.sh" /usr/local/sbin/agent_block_reaper.sh
cat > /etc/systemd/system/capstone-block-reaper.service <<'EOF'
[Unit]
Description=capstone: log expired agent_block entries (auto-unblock audit)
After=capstone-nat.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/agent_block_reaper.sh
EOF
cat > /etc/systemd/system/capstone-block-reaper.timer <<'EOF'
[Unit]
Description=capstone: run agent_block reaper every 60s
[Timer]
OnBootSec=90
OnUnitActiveSec=60
AccuracySec=5s
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload; systemctl enable --now capstone-block-reaper.timer >/dev/null
systemctl list-timers capstone-block-reaper.timer --no-pager --no-legend | awk '{print "  reaper timer:", $1, $2, $3, $4}'

say "V1 sudoers works: resp can add/del but NOT flush"
sudo -u resp sudo -n /usr/local/sbin/agent_block list >/dev/null 2>&1 && echo "  resp -> agent_block list ok" || die "resp cannot run agent_block list"
if sudo -u resp sudo -n /usr/local/sbin/agent_block flush >/dev/null 2>&1; then die "resp was allowed to flush (sudoers too broad!)"; else echo "  resp -> agent_block flush refused (good)"; fi

say "V2 MCP contract via the wrapper as resp (initialize/tools/list/tools/call list_blocks)"
[ -f "$SRC/contract_test.py" ] || echo "  (contract_test.py not staged; V2 does inline JSON-RPC)"
python3 - <<'PY'
import json, subprocess, sys
p = subprocess.Popen(["runuser","-u","resp","--","/opt/resp/run-response.sh"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
def send(o): p.stdin.write(json.dumps(o)+"\n"); p.stdin.flush()
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"deploy","version":"0"}}})
r=json.loads(p.stdout.readline()); assert r["result"]["serverInfo"]["name"]=="capstone-response-mcp", r; print("  initialize ok:", r["result"]["serverInfo"])
send({"jsonrpc":"2.0","method":"notifications/initialized"})
send({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
r=json.loads(p.stdout.readline()); names=[t["name"] for t in r["result"]["tools"]]; assert set(names)=={"block_ip","unblock_ip","list_blocks"}, names; print("  tools:", names)
send({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_blocks","arguments":{}}})
r=json.loads(p.stdout.readline()); assert r["result"]["isError"] is False, r; print("  list_blocks:", r["result"]["content"][0]["text"][:60])
send({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"block_ip","arguments":{"ip":"10.200.10.10","minutes":5,"reason":"deploy-selftest-protected"}}})
r=json.loads(p.stdout.readline()); assert r["result"]["isError"] is True and "rejected" in r["result"]["content"][0]["text"], r; print("  block protected -> rejected (good):", r["result"]["content"][0]["text"][:70])
p.stdin.close(); p.wait(timeout=10); print("  PASS")
PY
echo; echo "== V2 note: runuser proves server+policy+sudoers. The real ssh forced-command path is proven by the Mac-side 'ssh -T groot-resp' contract test that follows (deploy cannot, without the client private key). =="
DONE=1
echo; echo "== RESPONSE_DEPLOY_DONE =="
