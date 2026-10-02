#!/bin/bash
# fw_apply_v2.sh — FW v2(빡빡한 룰) 게이트형 적용 + 데드맨 롤백. **초안 — 미적용.** sudo bash 로 실행.
# 전제: /tmp/fw-v2/ 에 capstone-fw.nft, capstone-nat.sh, 99-capstone-fw.conf, fw_confirm_v2.sh 반입.
# 사용: sudo bash fw_apply_v2.sh [--enforce-output]   (기본은 output 섀도 모드)
#
# 잠금 방지(지속적 롤백) — v1 fw_phase2.sh 패턴 + v2 범위 확장:
#   - capstone-fw.nft 는 .pending 으로만 설치·적용 → 확인 전엔 부팅 시 v2 FW 가 켜지지 않는다.
#   - 데드맨(capstone-fw-deadman)이 DEADMAN 초 안에 확인되지 않으면: inet capstone_fw 삭제, .pending 철회,
#     FORWARD 정책 ACCEPT 복원 + CAPSTONE-FWD 제거, capstone-nat.sh 를 v1 백업으로 되돌려 재실행, v2 sysctl 제거 후 sysctl --system.
#   - 외부에서 검증(아래 V 목록) 후:  sudo fw_confirm_v2.sh   (타이머 해제 + .pending 확정 + 백업 정리)
#   잠겼으면 기다리면 원복된다. 콘솔(ESXi)로도 fw_confirm_v2.sh / 롤백 명령 실행 가능.
set -euo pipefail
SRC=${FW_SRC:-/tmp/fw-v2}; DEADMAN=${DEADMAN:-300}
PEND=/etc/nftables.d/capstone-fw.nft.pending
NAT=/usr/local/sbin/capstone-nat.sh; NATBAK=/usr/local/sbin/capstone-nat.sh.bak-v1
SYS=/etc/sysctl.d/99-capstone-fw.conf
ENFORCE_OUT=0; [ "${1:-}" = "--enforce-output" ] && ENFORCE_OUT=1
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*"; exit 1; }
trap 'echo "!! aborted at line $LINENO — if the dead-man is armed it rolls back in ${DEADMAN}s"' ERR

say "G0 preflight"
[ "$(id -u)" = 0 ] || die "run as root"
for f in capstone-fw.nft capstone-nat.sh 99-capstone-fw.conf fw_confirm_v2.sh; do [ -f "$SRC/$f" ] || die "$SRC/$f missing"; done
txncheck(){ local t; t=$(mktemp); { echo "table inet capstone_fw"; echo "delete table inet capstone_fw"; echo "include \"$1\""; } > "$t"; nft -c -f "$t"; local rc=$?; rm -f "$t"; return $rc; }   # bare-file nft -c hits EEXIST vs live interval sets
txncheck "$SRC/capstone-fw.nft" || die "capstone-fw.nft does not parse (as delete+include transaction)"
bash -n "$SRC/capstone-nat.sh" && bash -n "$SRC/fw_confirm_v2.sh" || die "script syntax"
systemctl is-active docker >/dev/null || die "docker not active"
ip -br addr show ens160 | grep -q ' 10\.200\.10\.1/' || die "ens160 is not 10.200.10.1"   # (v1 fw_phase2.sh 는 아직 10\.10\.10\.1 정규식 — 버그)
ip -br addr show ens192 >/dev/null || die "ens192 missing"
command -v systemd-run >/dev/null && command -v logger >/dev/null && command -v python3 >/dev/null || die "systemd-run/logger/python3 missing"
# 잠금 가드: 지금 접속한 출발지가 mgmt_src 에 있어야 한다(ens192 SSH 가 출발지 제한되므로)
# F2: sudo 는 SSH_CLIENT 를 지운다 → utmp(who -m)에서 로그인 피어 IP 복구. 그래도 불명이면 콘솔 확인 아니면 중단(묵시 통과 금지)
src=${SSH_CLIENT:-${SUDO_SSH_CLIENT:-}}; src=${src%% *}
[ -n "$src" ] || src=$(who -m 2>/dev/null | grep -oE '\(([0-9]{1,3}\.){3}[0-9]{1,3}\)' | tr -d '()' | head -1)
[ -n "$src" ] || src=$(who 2>/dev/null | grep -oE '\(([0-9]{1,3}\.){3}[0-9]{1,3}\)' | tr -d '()' | head -1)
if [ -z "$src" ]; then
  if [ -t 0 ]; then read -r -p "  원격 피어를 못 찾음(콘솔?). 잠금 안 되는 걸 확인했으면 YES 입력: " _a; [ "$_a" = YES ] || die "출발지 미확인 — 중단"
  else die "출발지 산출 불가(sudo 가 SSH_CLIENT 제거, who -m 비어있음). 'sudo -E bash $0' 로 재실행(SSH_CLIENT 보존) 또는 콘솔에서 실행"; fi
else
  python3 - "$src" "$SRC/capstone-fw.nft" <<'PY' || die "operator source $src is NOT in mgmt_src — you would lock yourself out. Add it to mgmt_src first."
import sys,re,ipaddress
ip=ipaddress.ip_address(sys.argv[1]); txt=open(sys.argv[2]).read()
m=re.search(r'set mgmt_src \{.*?elements = \{(.*?)\}', txt, re.S); elems=re.findall(r'[0-9.]+(?:/[0-9]+)?', m.group(1))
ok=any(ip in ipaddress.ip_network(e, strict=False) for e in elems)
# 내부망(ens160) 출발이면 mgmt_src 와 무관하게 허용됨
ok = ok or ip in ipaddress.ip_network('10.200.10.0/24')
sys.exit(0 if ok else 1)
PY
  echo "  operator session from $src: in mgmt_src (or internal) — ok"
fi
echo "ok"

say "P1 install (fw as .pending; nat v2 with v1 backup; sysctl v2)"
install -d -o root -g root -m 0755 /etc/nftables.d /var/lib/capstone
# output 모드 변환: 기본 섀도(파일 그대로). --enforce-output 이면 policy drop + FW_DROP_OUT + 최종 drop
if [ "$ENFORCE_OUT" = 1 ]; then
  sed -e 's/policy accept; # OUT_MODE/policy drop; # OUT_MODE/' \
      -e 's/FW_SHADOW_OUT /FW_DROP_OUT /' \
      -e 's|# OUT_DROP (inserted by --enforce-output):  counter drop|counter drop comment "OUT enforce"|' \
      "$SRC/capstone-fw.nft" > "$PEND"
  txncheck "$PEND" || die "enforce-output transform does not parse"
  echo "  output chain: ENFORCE (policy drop)"
else
  install -o root -g root -m 0644 "$SRC/capstone-fw.nft" "$PEND"; echo "  output chain: SHADOW (log only)"
fi
# F4: 현재 NAT 가 v1(마커 없음)일 때만 백업 → 재실행(이미 v2) 시 v1 백업을 v2 로 덮지 않음. 백업은 pristine 로 보존.
if [ ! -f "$NATBAK" ] && ! grep -q CAPSTONE_NAT_V2 "$NAT" 2>/dev/null; then cp -p "$NAT" "$NATBAK"; fi
[ -f "$NATBAK" ] || echo "  (주의: v1 백업 없음 — 롤백은 git 의 v1 로)"
install -o root -g root -m 0755 "$SRC/capstone-nat.sh" "$NAT"
install -o root -g root -m 0755 "$SRC/fw_confirm_v2.sh" /usr/local/sbin/fw_confirm_v2.sh
install -o root -g root -m 0644 "$SRC/99-capstone-fw.conf" "$SYS"
systemctl mask nftables.service >/dev/null 2>&1 || true
ls -l "$PEND" "$NAT" "$NATBAK" "$SYS" | sed 's/^/  /'

say "P2 arm dead-man (${DEADMAN}s): full v2 rollback unless confirmed"
systemctl stop capstone-fw-deadman.timer capstone-fw-deadman.service >/dev/null 2>&1 || true
systemctl reset-failed capstone-fw-deadman.timer capstone-fw-deadman.service >/dev/null 2>&1 || true
ROLLBACK="nft delete table inet capstone_fw; rm -f $PEND; iptables -P FORWARD ACCEPT; iptables -D DOCKER-USER -j CAPSTONE-FWD 2>/dev/null; iptables -F CAPSTONE-FWD 2>/dev/null; iptables -X CAPSTONE-FWD 2>/dev/null; cp -f $NATBAK $NAT; $NAT >/dev/null 2>&1; rm -f $SYS; [ -f /run/capstone-fw-sysctl.restore ] && sysctl -p /run/capstone-fw-sysctl.restore >/dev/null 2>&1; sysctl --system >/dev/null 2>&1; logger -t capstone-fw 'DEADMAN fired: v2 rolled back (fw table removed, FORWARD ACCEPT, nat v1 restored, sysctl runtime restored from snapshot)'"
systemd-run --on-active="$DEADMAN" --timer-property=AccuracySec=1s --unit=capstone-fw-deadman --description="rollback FW v2 if not confirmed" /bin/sh -c "$ROLLBACK" \
  || die "systemd-run failed"
systemctl list-timers capstone-fw-deadman.timer --no-pager --no-legend | grep -q capstone-fw-deadman || die "dead-man not armed"
echo "  armed: $(systemctl list-timers capstone-fw-deadman.timer --no-pager --no-legend | awk '{print $1, $2, $3, $4}')"
trap 'echo; echo "== dead-man armed (${DEADMAN}s). Verify from OUTSIDE (V list), then: sudo fw_confirm_v2.sh"' EXIT

say "P3 apply: sysctl v2, then capstone-nat.sh v2 with FW_FILE=$PEND (atomic fw load; FORWARD DROP; CAPSTONE-FWD rebuilt)"
# F5: 바꿀 키의 현재 런타임 값을 스냅샷 → 데드맨이 이 파일로 복원(파일 rm+--system 만으론 런타임 미복구)
: > /run/capstone-fw-sysctl.restore
for _k in net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv4.conf.ens192.rp_filter net.ipv4.conf.ens160.rp_filter net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.secure_redirects net.ipv4.conf.all.accept_source_route net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians net.ipv4.tcp_syncookies net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.icmp_ignore_bogus_error_responses net.ipv6.conf.ens192.disable_ipv6 net.ipv6.conf.ens160.disable_ipv6 net.ipv6.conf.all.forwarding; do
  echo "$_k = $(sysctl -n $_k 2>/dev/null)" >> /run/capstone-fw-sysctl.restore 2>/dev/null
done
sysctl --system >/dev/null; sysctl -n net.ipv4.conf.all.rp_filter net.ipv4.conf.all.send_redirects net.ipv6.conf.ens192.disable_ipv6 | paste -sd' ' | sed 's/^/  rp_filter send_redirects v6off(ens192): /'
FW_FILE="$PEND" "$NAT" | sed 's/^/  /'
nft list table inet capstone_fw >/dev/null || die "capstone_fw not loaded"
echo "  FORWARD: $(iptables -S FORWARD | head -1)"; echo "  CAPSTONE-FWD rules: $(iptables -S CAPSTONE-FWD | grep -c '^-A')"

say "V0 local checks (informational)"
curl -s -m 5 -o /dev/null -w "  WAF via lo http://127.0.0.1/ -> %{http_code}\n" http://127.0.0.1/ || echo "  WAF via lo FAILED"
ping -c1 -W2 10.200.10.10 >/dev/null 2>&1 && echo "  ping B ok" || echo "  ping B FAILED"
ping -c1 -W2 192.168.16.131 >/dev/null 2>&1 && echo "  ping campus NTP ok" || echo "  ping NTP FAILED"
chronyc -n tracking 2>/dev/null | grep -E 'Reference ID' | sed 's/^/  /' || true
grep -q "status='connected'" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null && echo "  wazuh agent connected" || echo "  wazuh agent NOT connected"
curl -s -m 5 -o /dev/null -w "  A->B broker http://10.200.10.10:8090/pending -> %{http_code} (401 expected)\n" http://10.200.10.10:8090/pending || echo "  broker FAILED"
echo "  shadow/drop log (last 5):"; journalctl -k --no-pager -n 300 2>/dev/null | grep -E 'FW_SHADOW_OUT|FW_DROP_FWD|SPOOF|FW_SSH_RATE' | tail -5 | sed 's/^/    /' || true

cat <<'V'

== V1 verify from OUTSIDE before confirming (all must pass) ==
  [ ] SSH to A from VPN / dept LAN (mgmt_src) works; from a non-mgmt source (e.g. 192.168.16.x) is refused
  [ ] https://chat.grootlab.duckdns.org 200 + websocket 101 ; https://wazuh.grootlab.duckdns.org 302->login
  [ ] http://dvwa.grootlab.duckdns.org 302 (WAF -> C)
  [ ] from VM segment: https://192.168.16.230:10443 reaches dashboard ; from VPN it must not (campus FW anyway)
  [ ] Hermes@B: `hermes chat -q` still registers 17 MCP tools (B->A resp SSH over ens160)
  [ ] A: journalctl -k | grep FW_SHADOW_OUT — review; nothing legitimate should appear (if it does, add an output allow BEFORE --enforce-output)
  [ ] scenario_log4shell_route.sh on -> Kali reaches 192.168.16.230:8080 ; off -> unreachable ; 10.200.10.20:8080 via routing from the segment: UNREACHABLE (P1 proof)
  [ ] (after B/C temp NIC removal) B reaches DGX 211.170.162.110:11434 ; C cannot reach arbitrary external hosts
Then:  sudo fw_confirm_v2.sh
== FW_V2_APPLIED (pending) ==
V
