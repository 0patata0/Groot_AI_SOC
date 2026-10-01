#!/bin/bash
# fw_confirm_v2.sh — fw_apply_v2.sh 적용 후 외부 검증(V1 목록)을 마쳤을 때 실행. sudo 로.
# 데드맨 해제 + .pending → capstone-fw.nft 확정 + v1 nat 백업 정리. **초안 — 미적용.**
set -euo pipefail
PEND=/etc/nftables.d/capstone-fw.nft.pending; FINAL=/etc/nftables.d/capstone-fw.nft; NATBAK=/usr/local/sbin/capstone-nat.sh.bak-v1
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
nft list table inet capstone_fw >/dev/null 2>&1 || { echo "!! inet capstone_fw not loaded (dead-man fired?) — nothing confirmed"; exit 1; }
[ "$(iptables -S FORWARD | head -1)" = "-P FORWARD DROP" ] || { echo "!! FORWARD policy is not DROP (dead-man fired?) — nothing confirmed"; exit 1; }
systemctl stop capstone-fw-deadman.timer capstone-fw-deadman.service >/dev/null 2>&1 || true
if [ -f "$PEND" ]; then mv -f "$PEND" "$FINAL"; fi
[ -f "$FINAL" ] || { echo "!! $FINAL missing"; exit 1; }
rm -f "$NATBAK"
logger -t capstone-fw "confirmed v2: inet capstone_fw + FORWARD DROP/CAPSTONE-FWD + sysctl v2 active and enabled at boot"
echo "confirmed v2: dead-man disarmed; boot file $(ls -l "$FINAL" | awk '{print $NF, $5"B"}'); FORWARD $(iptables -S FORWARD | head -1 | awk '{print $3}')"
