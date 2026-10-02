#!/bin/bash
# 시나리오 전용: Log4Shell 랩(C)을 A 경유로 노출/회수. 평상시 OFF(재부팅에도 안 남음 — 런타임 테이블).
#
# 배경: 평상시 랩은 C 내부 전용(10.200.10.20:8080 바인딩) — 캠퍼스/VPN 직접 도달 불가.
#       시나리오 때만 이 스크립트로 A 경유 경로를 열어 Suricata(ens192 af-packet)로 검사되게 한다.
#
# ON  = A:ens192:8080 -> C 10.200.10.20:8080 DNAT + DOCKER-USER forward(NEW) 허용 + 회신 SNAT.
#       공격 경로: Kali(캠퍼스) -> http://192.168.16.230:8080/  ->  A(Suricata 검사)  ->  C 랩.
#       Suricata 는 ens192 에서 inbound 패킷(JNDI/LDAP 페이로드)을 그대로 캡처 → 탐지.
# OFF = 위 규칙 제거 → 랩은 다시 C 내부(10.200.10.20:8080) 전용.
#
# 주의:
#  - 별도 nft 테이블 `capstone_scenario` 사용(capstone_fw/capstone_fwd 를 건드리지 않음). 멱등.
#  - 런타임 전용: /etc/nftables.d 에 안 넣고 capstone-nat.service 도 로드 안 함 → 재부팅하면 자동 OFF(의도).
#  - VPN 은 A 로 8080 이 안 열림(22/80/443 만 통과, 실측) → 이 경로는 **캠퍼스(Kali) 세그먼트에서만** 유효.
#  - 공격성 트래픽은 캠퍼스 VPN 경유 금지(캠퍼스 FW 차단). Kali 는 캠퍼스 직결에서 실행.
#  - 회신 SNAT 는 여기 postrouting(ct status dnat masquerade)이 담당하므로 capstone_fwd 유무와 무관하게 자립.
set -e

EXT_IF="ens192"          # A 외부(캠퍼스) NIC
INT_IF="ens160"          # A 내부망 NIC
LAB_IP="10.200.10.20"     # C 내부 IP
LAB_PORT="8080"          # C 랩 포트
EXT_PORT="8080"          # A 외부 노출 포트 (host 8080 은 미사용 — WAF 는 host 80/8443)
TBL="capstone_scenario"

usage(){ echo "usage: $0 {on|off|status}"; exit 1; }
[ "$(id -u)" = "0" ] || { echo "root 필요: sudo $0 $*" >&2; exit 1; }
[ $# -ge 1 ] || usage

# F6: 관측용 egress 대상(C 아웃바운드 JNDI 콜백/유출을 Suricata 가 ens192 에서 보게). v2 FORWARD DROP 에서 필수.
OBS_SEG="192.168.16.0/25"   # 공격자(Kali)가 있는 VM 세그먼트
du_add(){  # inbound(DNAT 경로) + outbound(관측) DOCKER-USER NEW 허용. FORWARD DROP(v2) 아래서도 동작하게 맨 위 삽입.
  iptables -L DOCKER-USER -n >/dev/null 2>&1 || { echo "WARN: DOCKER-USER 없음 (docker 미기동?) — forward 허용 건너뜀" >&2; return 0; }
  iptables -C DOCKER-USER -d "$LAB_IP" -i "$EXT_IF" -o "$INT_IF" -p tcp --dport "$LAB_PORT" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null \
    || iptables -I DOCKER-USER -d "$LAB_IP" -i "$EXT_IF" -o "$INT_IF" -p tcp --dport "$LAB_PORT" -m conntrack --ctstate NEW -j ACCEPT
  # C -> 공격자 세그먼트 아웃바운드(콜백/유출) 관측 허용 — 없으면 v2 FORWARD DROP 이 유출 leg 를 끊어 Suricata 가 못 봄
  iptables -C DOCKER-USER -s "$LAB_IP" -i "$INT_IF" -o "$EXT_IF" -d "$OBS_SEG" -j ACCEPT 2>/dev/null \
    || iptables -I DOCKER-USER -s "$LAB_IP" -i "$INT_IF" -o "$EXT_IF" -d "$OBS_SEG" -j ACCEPT
}
du_del(){
  iptables -L DOCKER-USER -n >/dev/null 2>&1 || return 0
  while iptables -C DOCKER-USER -d "$LAB_IP" -i "$EXT_IF" -o "$INT_IF" -p tcp --dport "$LAB_PORT" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null; do
    iptables -D DOCKER-USER -d "$LAB_IP" -i "$EXT_IF" -o "$INT_IF" -p tcp --dport "$LAB_PORT" -m conntrack --ctstate NEW -j ACCEPT
  done
  while iptables -C DOCKER-USER -s "$LAB_IP" -i "$INT_IF" -o "$EXT_IF" -d "$OBS_SEG" -j ACCEPT 2>/dev/null; do
    iptables -D DOCKER-USER -s "$LAB_IP" -i "$INT_IF" -o "$EXT_IF" -d "$OBS_SEG" -j ACCEPT
  done
}

case "$1" in
  on)
    nft delete table ip "$TBL" 2>/dev/null || true
    nft -f - <<NFT
table ip $TBL {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    iifname "$EXT_IF" tcp dport $EXT_PORT dnat to $LAB_IP:$LAB_PORT   # scenario: Log4Shell lab via A
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "$INT_IF" ct status dnat masquerade                      # DNAT 회신이 A 로 돌아오게
  }
}
NFT
    du_add
    logger -t scenario-log4shell -p auth.notice -- "action=route-on ext=$EXT_IF:$EXT_PORT dst=$LAB_IP:$LAB_PORT by=$(id -un)" || true
    echo "ON: 캠퍼스에서 http://192.168.16.230:$EXT_PORT/  ->  (Suricata 검사)  ->  $LAB_IP:$LAB_PORT"
    echo "    (VPN 은 A:8080 불통 — 캠퍼스/Kali 세그먼트에서만. 시나리오 종료 후 반드시 '$0 off')"
    ;;
  off)
    nft delete table ip "$TBL" 2>/dev/null || true
    du_del
    logger -t scenario-log4shell -p auth.notice -- "action=route-off by=$(id -un)" || true
    echo "OFF: Log4Shell 랩 A 경유 회수 — 랩은 C 내부($LAB_IP:$LAB_PORT) 전용으로 복귀"
    ;;
  status)
    echo "== nft table ip $TBL =="
    nft list table ip "$TBL" 2>/dev/null || echo "(없음 = OFF)"
    echo "== DOCKER-USER (scenario 규칙) =="
    iptables -S DOCKER-USER 2>/dev/null | grep -- "-d $LAB_IP" | grep -- "--dport $LAB_PORT" || echo "(없음)"
    ;;
  *) usage;;
esac
