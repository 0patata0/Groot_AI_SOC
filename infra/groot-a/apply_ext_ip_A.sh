#!/bin/bash
# Groot_A 외부(ens192) IP 변경 도우미. root 로 실행. 런북: infra/groot-a/ext_ip_change.md
#   check NEW           : 새 IP 가 비어 있는지(arping) + 보조주소로 붙여 게이트웨이(.129)·NTP(.131) 응답 확인 (기본경로·본 주소 불변)
#   apply NEW [OLD]     : netplan 주소 교체(마스크·게이트웨이 유지) + never_block(OLD→NEW) + Suricata HOME_NET + 스크립트 문구 + 적용.
#                         되돌림 타이머 없음(옛 IP 로 복귀는 금지). 이 세션은 끊기므로 새 IP 로 재접속해서 verify.
#   verify NEW          : 주소·경로·never_block·HOME_NET·컨테이너 상태 출력
#   secondary-off NEW   : check 가 남긴 보조주소 제거
set -euo pipefail
GW=192.168.16.129; NTP=192.168.16.131; NP=/etc/netplan/50-cloud-init.yaml; FW=/etc/nftables.d/capstone-fw.nft
SC=/home/groot_a/capstone/secstack/docker-compose.yml; CP=/home/groot_a/capstone/chatproxy/deploy_chatproxy_A.sh
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "root"
cmd=${1:-}; NEW=${2:-}; OLD=${3:-$(ip -4 -o addr show ens192 | awk '{print $4}' | cut -d/ -f1 | head -1)}
MASK=$(grep -oE '"192\.168\.16\.[0-9]+/[0-9]+"' "$NP" | head -1 | grep -oE '/[0-9]+' | tr -d /); MASK=${MASK:-25}
[[ -z "$NEW" || "$NEW" =~ ^192\.168\.16\.[0-9]+$ ]] || die "NEW must be 192.168.16.x"
case "$cmd" in
  check)
    [ -n "$NEW" ] || die "usage: $0 check NEW"
    say "C1 새 IP 사용 여부 (arping)"; if arping -c 2 -w 3 -I ens192 "$NEW" 2>/dev/null | grep -q 'bytes from'; then die "$NEW already in use on the segment"; else echo "  free"; fi
    say "C2 보조주소로 붙여 응답 확인 (본 주소·경로 불변)"; ip addr add "$NEW/$MASK" dev ens192 2>/dev/null || true
    for t in $GW $NTP; do printf "  ping -I %s -> %s: " "$NEW" "$t"; ping -I "$NEW" -c 2 -W 2 "$t" >/dev/null 2>&1 && echo OK || echo "무응답(캠퍼스 측 미등록/다른 대역 가능성)"; done
    printf "  arp %s: " "$GW"; ip neigh show "$GW" | awk '{print $5, $NF}'
    echo "  → 학과망 PC 에서 'nc -G 4 -z $NEW 22' 로 도달도 확인. 끝나면 '$0 secondary-off $NEW'";;
  secondary-off) ip addr del "$NEW/$MASK" dev ens192 2>/dev/null && echo "removed $NEW/$MASK" || echo "(not present)";;
  apply)
    [ -n "$NEW" ] && [ -n "$OLD" ] || die "usage: $0 apply NEW [OLD]"; [ "$NEW" != "$OLD" ] || die "NEW == OLD"
    TS=$(date +%Y%m%d-%H%M%S)
    say "A1 netplan $OLD/$MASK -> $NEW/$MASK (gw $GW 유지)"; cp -a "$NP" "$NP.bak-$TS"; sed -i "s#\"$OLD/$MASK\"#\"$NEW/$MASK\"#" "$NP"; grep -q "\"$NEW/$MASK\"" "$NP" || die "netplan edit failed"; netplan generate
    say "A2 never_block $OLD -> $NEW (파일+런타임)"; cp -a "$FW" "$FW.bak-$TS"; sed -i "s/\b$OLD\b/$NEW/g" "$FW"; nft -c -f "$FW"
    nft add element inet capstone_fw never_block { "$NEW" }; nft delete element inet capstone_fw never_block { "$OLD" } 2>/dev/null || true
    say "A3 Suricata HOME_NET"; cp -a "$SC" "$SC.bak-$TS"; sed -i "s/$OLD/$NEW/g" "$SC"; (cd "$(dirname "$SC")" && docker compose up -d suricata >/dev/null 2>&1); echo "  $(docker inspect suricata --format '{{join .Args " "}}' | grep -oE 'HOME_NET=[^ ]+')"
    say "A4 스크립트 문구"; for f in "$CP" /usr/local/sbin/capstone-nat.sh /usr/local/sbin/scenario_log4shell_route.sh; do [ -f "$f" ] && sed -i "s/$OLD/$NEW/g" "$f" && echo "  $f"; done
    ip addr del "$NEW/$MASK" dev ens192 2>/dev/null || true
    say "A5 적용 (2초 뒤 netplan apply — 이 세션 끊김. 복귀 타이머 없음)"; systemd-run --quiet --unit="netplan-switch-$TS" --on-active=2 bash -c "netplan apply"; echo "  scheduled";;
  verify)
    say "V"; ip -br a | grep ens192; ip route show default; echo "never_block: $(nft list set inet capstone_fw never_block | tr -d '\n' | grep -oE '192\.168\.16\.[0-9]+' | tr '\n' ' ')"
    echo "HOME_NET: $(docker inspect suricata --format '{{join .Args " "}}' | grep -oE 'HOME_NET=[^ ]+')"; docker ps --format '{{.Names}}={{.Status}}' | tr '\n' ' '; echo
    printf "gw %s ping: " "$GW"; ping -c2 -W2 "$GW" >/dev/null 2>&1 && echo OK || echo FAIL;;
  *) echo "usage: $0 {check NEW | secondary-off NEW | apply NEW [OLD] | verify}"; exit 1;;
esac
