#!/bin/bash
# Groot_A: Phase 2 호스트 방화벽(input 기본 차단) + agent_block 배치 — 게이트형, 데드맨 타이머 포함(리뷰 반영 2026-09-27). sudo bash 로 실행.
# 전제: /tmp/fw/ 에 capstone-fw.nft, agent_block, capstone-nat.sh, fw_confirm.sh 반입.
# 잠금 방지(지속적 롤백):
#   - 규칙 파일은 /etc/nftables.d/capstone-fw.nft.pending 으로만 설치하고 그 경로로 적용한다 → 확인 전엔 부팅 시 아무것도 켜지지 않는다.
#   - 데드맨 타이머(capstone-fw-deadman)가 DEADMAN 초 안에 확인되지 않으면 커널 테이블 삭제 + .pending 제거(부팅 파일도 없음).
#   - 외부에서 SSH/대시보드/WAF/NTP/MCP 점프를 확인한 뒤:  sudo fw_confirm.sh   (타이머 해제 + .pending → capstone-fw.nft 확정)
#   잠겼으면 기다리면 원복된다(NAT/포워딩 capstone_gw/capstone_fwd 는 건드리지 않음).
set -euo pipefail
SRC=${FW_SRC:-/tmp/fw}; DEADMAN=${DEADMAN:-300}
PEND=/etc/nftables.d/capstone-fw.nft.pending
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*"; exit 1; }
trap 'echo "!! aborted at line $LINENO — if the dead-man is armed it will roll back in ${DEADMAN}s (or run: nft delete table inet capstone_fw; rm -f $PEND)"' ERR

say "G0 preflight"
[ "$(id -u)" = 0 ] || die "run as root"
for f in capstone-fw.nft agent_block capstone-nat.sh fw_confirm.sh; do [ -f "$SRC/$f" ] || die "$SRC/$f missing"; done
nft -c -f "$SRC/capstone-fw.nft" || die "capstone-fw.nft does not parse"
bash -n "$SRC/agent_block" && bash -n "$SRC/capstone-nat.sh" && bash -n "$SRC/fw_confirm.sh" || die "script syntax"
systemctl is-active docker >/dev/null || die "docker not active"
nft list table ip capstone_gw >/dev/null 2>&1 && nft list table ip capstone_fwd >/dev/null 2>&1 || die "capstone_gw/capstone_fwd tables missing (run capstone-nat first)"
ip -br addr show ens160 | grep -q '10\.10\.10\.1/' || die "ens160 is not 10.10.10.1"; ip -br addr show ens192 >/dev/null || die "ens192 missing"
command -v systemd-run >/dev/null && command -v logger >/dev/null && command -v flock >/dev/null || die "systemd-run/logger/flock missing"
src=${SSH_CLIENT:-${SUDO_SSH_CLIENT:-unknown}}; echo "  operator session from: ${src%% *} (ens192 tcp/22 stays allowed; never_block guards mgmt sources)"
echo "ok"

say "P1 install (rules as .pending; nftables.service masked — /etc/nftables.conf would flush Docker+NAT)"
install -d -o root -g root -m 0755 /etc/nftables.d /var/lib/capstone
install -o root -g root -m 0644 "$SRC/capstone-fw.nft" "$PEND"
install -o root -g root -m 0755 "$SRC/agent_block" /usr/local/sbin/agent_block
install -o root -g root -m 0755 "$SRC/capstone-nat.sh" /usr/local/sbin/capstone-nat.sh
install -o root -g root -m 0755 "$SRC/fw_confirm.sh" /usr/local/sbin/fw_confirm.sh
systemctl mask nftables.service >/dev/null 2>&1 || true; echo "  nftables.service: $(systemctl is-enabled nftables.service 2>&1)"
ls -l "$PEND" /usr/local/sbin/agent_block /usr/local/sbin/capstone-nat.sh /usr/local/sbin/fw_confirm.sh | sed 's/^/  /'

say "P2 arm dead-man timer (${DEADMAN}s): removes inet capstone_fw AND $PEND unless confirmed"
systemctl stop capstone-fw-deadman.timer capstone-fw-deadman.service >/dev/null 2>&1 || true
systemctl reset-failed capstone-fw-deadman.timer capstone-fw-deadman.service >/dev/null 2>&1 || true
systemd-run --on-active="$DEADMAN" --timer-property=AccuracySec=1s --unit=capstone-fw-deadman --description="rollback capstone_fw if not confirmed" \
  /bin/sh -c "nft delete table inet capstone_fw; rm -f $PEND; logger -t capstone-fw 'DEADMAN fired: inet capstone_fw removed and pending file withdrawn'" \
  || die "systemd-run failed (systemctl status capstone-fw-deadman.timer)"
systemctl list-timers capstone-fw-deadman.timer --no-pager --no-legend | grep -q capstone-fw-deadman || die "dead-man timer not armed"
echo "  armed: $(systemctl list-timers capstone-fw-deadman.timer --no-pager --no-legend | awk '{print $1, $2, $3, $4}')"
trap 'echo; echo "== dead-man armed (${DEADMAN}s). Verify from OUTSIDE, then: sudo fw_confirm.sh   (must run before it fires)"' EXIT

say "P3 apply via capstone-nat.sh with FW_FILE=$PEND (atomic load; NAT/forward re-applied idempotently)"
FW_FILE="$PEND" /usr/local/sbin/capstone-nat.sh | sed 's/^/  /'
nft list table inet capstone_fw >/dev/null || die "table not loaded"
nft list chain inet capstone_fw input | grep -E 'policy|dport 22|dport 123' | sed 's/^/  /' || true

say "V1 local checks (informational — none may abort the run)"
curl -s -m 5 -o /dev/null -w "  WAF via lo http://127.0.0.1/ -> %{http_code}\n" http://127.0.0.1/ || echo "  WAF via lo: FAILED"
ping -c 1 -W 2 10.10.10.10 >/dev/null 2>&1 && echo "  ping B (internal) ok" || echo "  ping B FAILED"
ping -c 1 -W 2 192.168.16.129 >/dev/null 2>&1 && echo "  ping campus GW ok" || echo "  ping GW FAILED"
chronyc -n tracking 2>/dev/null | grep -E 'Reference ID' | sed 's/^/  /' || echo "  chrony tracking unavailable"
grep -q "status='connected'" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null && echo "  wazuh agent connected" || echo "  wazuh agent NOT connected"
echo "  agent_block self-test (expected non-zero exits below are NOT failures):"
trap - ERR; set +e
/usr/local/sbin/agent_block add 203.0.113.7 30s selftest | sed 's/^/    /'
/usr/local/sbin/agent_block list | grep -q '^203\.0\.113\.7 ' && echo "    list ok" || echo "    !! add/list FAILED"
for bad in 10.10.10.10 192.168.16.129 172.18.0.2 192.168.16.71; do /usr/local/sbin/agent_block add $bad 5m >/dev/null 2>&1; echo "    protected $bad -> exit $? (expect 3)"; done
/usr/local/sbin/agent_block add 010.10.10.10 5m >/dev/null 2>&1; echo "    leading-zero ip -> exit $? (expect 2)"
/usr/local/sbin/agent_block add 203.0.113.8 99999s >/dev/null 2>&1; echo "    ttl 99999s -> exit $? (expect 2)"
/usr/local/sbin/agent_block del 203.0.113.7 - selftest | sed 's/^/    /'
grep -c . /var/lib/capstone/agent_block.state | sed 's/^/    state file lines: /'
journalctl -t agent_block --no-pager -n 3 -o cat | sed 's/^/    journal: /'
set -e
echo; echo "== FW_PHASE2_APPLIED (pending) =="