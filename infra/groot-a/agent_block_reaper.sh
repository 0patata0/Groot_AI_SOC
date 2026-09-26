#!/bin/bash
# agent_block_reaper.sh — TTL 만료된 차단을 감사 로그로 남긴다. systemd 타이머(capstone-block-reaper)가 주기 실행.
# nft agent_block 셋은 flags timeout 이라 커널이 자동 만료시키지만, 그 순간엔 로그가 없다(SIEM 은 차단 시작만 알고 종료를 모름).
# 이 리퍼가 상태파일(agent_block add 가 기록)과 라이브 셋을 비교해 사라진 항목을 'action=expire' 로 logger → journald → Wazuh.
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
ST=/var/lib/capstone/agent_block.state; LK=/var/lib/capstone/agent_block.lock
T="inet capstone_fw"; S=agent_block
[ -f "$ST" ] || exit 0
nft list set $T $S >/dev/null 2>&1 || exit 0
exec 9>"$LK"; flock -w 5 9 || exit 0
tmp="$ST.tmp"; : > "$tmp"
while read -r ip exp; do
  [ -n "$ip" ] && [ -n "$exp" ] || continue
  if nft get element $T $S "{ $ip }" >/dev/null 2>&1; then
    printf '%s %s\n' "$ip" "$exp" >> "$tmp"          # 아직 차단 중 → 유지
  else
    logger -t agent_block -p auth.notice -- "action=expire ip=$ip result=ok reason=timeout by=timeout" || true
  fi
done < "$ST"
mv -f "$tmp" "$ST"
