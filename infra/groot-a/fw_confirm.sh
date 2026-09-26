#!/bin/bash
# fw_confirm.sh — fw_phase2.sh 적용 후 외부 검증(SSH·대시보드·WAF·NTP·MCP 점프)을 마쳤을 때 실행. sudo 로.
# 데드맨 타이머 해제 + .pending → /etc/nftables.d/capstone-fw.nft 확정(부팅 시 capstone-nat.sh 가 로드).
set -euo pipefail
PEND=/etc/nftables.d/capstone-fw.nft.pending; FINAL=/etc/nftables.d/capstone-fw.nft
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
nft list table inet capstone_fw >/dev/null 2>&1 || { echo "!! inet capstone_fw is not loaded (dead-man already fired?) — nothing confirmed"; exit 1; }
systemctl stop capstone-fw-deadman.timer capstone-fw-deadman.service >/dev/null 2>&1 || true
if [ -f "$PEND" ]; then mv -f "$PEND" "$FINAL"; fi
[ -f "$FINAL" ] || { echo "!! $FINAL missing"; exit 1; }
logger -t capstone-fw "confirmed: inet capstone_fw active and enabled at boot ($FINAL)"
echo "confirmed: dead-man disarmed; boot file $(ls -l "$FINAL" | awk '{print $NF, $5"B"}')"
