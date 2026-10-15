#!/bin/bash
# Groot_A NAT 게이트웨이 + forward 정책 v2 (빡빡한 룰 초안, 2026-10-01). **초안 — 아직 미적용.** 멱등(idempotent).
# CAPSTONE_NAT_V2  (F4: apply 가 이 마커로 v1/v2 구분해 v1 원본만 백업)
# capstone-nat.service 가 docker.service 이후 실행. 수동 재적용도 안전.
#
# v1 대비 변경(보안룰_취합.md 0-B):
#  P1  FORWARD 정책 DROP(Docker 본래 상태 복원) — 비허용 라우팅 forward(예: Kali→10.200.10.x) 차단
#  P2  내부→외부 egress 는 EGRESS_ALLOW 허용목록만(B→DGX, DNS). B/C 가 임시 NIC 로 직접 나가는 동안은 효력 없음, NIC 제거 후 강제됨
#  P8  컨테이너 east-west: WAF→C:80, chatproxy→B:8065/443 만. 컨테이너→외부/내부 그 외 drop
#  P9  forward drop 은 "FW_DROP_FWD " 로그(제한) → Wazuh 측면이동 신호
#  P11 관리 DNAT(10443→B:443) 출발지를 VM 세그먼트로 제한
#  구조: DOCKER-USER 에 허용 룰을 흩뿌리지 않고 전용 체인 CAPSTONE-FWD 를 만들어 매 적용마다 flush+재구성(결정적). DOCKER-USER 는 jump 1줄만.
#        시나리오 토글(scenario_log4shell_route.sh)은 여전히 `-I DOCKER-USER ...`(맨 위 삽입) → jump 보다 먼저 매칭되어 호환.
#  v1 의 블랭킷 룰(-s 10.200.10.0/24 ... ACCEPT 등)은 발견 시 제거(이관).
set -e

EXT_IF="ens192"            # 외부(캠퍼스) NIC
INT_IF="ens160"            # 내부망 NIC
INT_NET="10.200.10.0/24"   # 내부망 (A=.1 GW, B=.10, C=.20)
B_IP="10.200.10.10"; C_IP="10.200.10.20"
MGMT_DNAT_SRC="192.168.16.0/25"      # P11: 관리 DNAT 를 허용할 출발지(VM 세그먼트 직결)
NFT_FILE="/etc/nftables.d/capstone-gw.nft"
FWD_FILE="/etc/nftables.d/capstone-fwd.nft"
FWD_CHAIN="CAPSTONE-FWD"

# 관리 페이지 포트포워딩: "<A 외부포트>:<내부IP>:<내부포트>:<설명>"
PORTFORWARDS=(
  "10443:${B_IP}:443:Wazuh dashboard (VM세그먼트 직결용 https://192.168.16.230:10443 ; 학과망/VPN 은 A:443 chatproxy)"
)
# P2: 내부→외부 egress 허용목록 "<dst>:<proto>:<port>" (B/C 가 A 를 기본경로로 쓰게 된 뒤 효력)
EGRESS_ALLOW=(
  "211.170.162.110:tcp:11434:DGX Ollama (Hermes@B)"
  "211.170.162.111:tcp:11434:DGX Ollama (Hermes@B)"
  "168.126.63.1:udp:53:DNS"
  "168.126.63.1:tcp:53:DNS tcp"
)
# 시나리오 관찰 모드(C 아웃바운드 JNDI 콜백·유출을 Suricata 로 보려면) — scenario_log4shell_route.sh 가 ON 일 때 다음을 -I DOCKER-USER 로 넣도록 수정 권장:
#   iptables -I DOCKER-USER -s $C_IP -i $INT_IF -o $EXT_IF -d 192.168.16.0/25 -j ACCEPT   (OFF 시 -D)
# P8: 컨테이너 east-west 허용 "<dst>:<proto>:<ports>" (브리지 br-* / docker0 → 내부망)
EASTWEST_ALLOW=(
  "${C_IP}:tcp:80:WAF -> DVWA"
  "${B_IP}:tcp:8065,443:chatproxy -> Mattermost / Wazuh dashboard backend"
)

# BEGIN LOG4SHELL_TLS_WAF_HELPERS
# Read-only discovery; an absent/stopped/ambiguous endpoint adds no allow rule.
# This block can be sourced alone for a reviewed one-rule insertion via F().
capstone_tls_ipv4(){
  local value=$1 octet; local -a octets
  [[ $value =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r -a octets <<<"$value"
  for octet in "${octets[@]}"; do
    [[ $octet == 0 || $octet =~ ^[1-9][0-9]{0,2}$ ]] && ((10#$octet<=255)) || return 1
  done
  ((10#${octets[0]}>0 && 10#${octets[0]}<224 && 10#${octets[0]}!=127))
}
capstone_tls_endpoint(){
  local container=$1 network=$2 endpoint running address network_id extra metadata found_id found_name driver bridge
  endpoint=$(docker inspect --type container --format '{{.State.Running}}|{{with index .NetworkSettings.Networks "'"$network"'"}}{{.IPAddress}}|{{.NetworkID}}{{end}}' "$container" 2>/dev/null) || return 1
  [[ $endpoint != *$'\n'* ]] || return 1
  IFS='|' read -r running address network_id extra <<<"$endpoint"
  [[ $running == true && $network_id =~ ^[a-f0-9]{64}$ && -z $extra ]] || return 1
  capstone_tls_ipv4 "$address" || return 1
  metadata=$(docker network inspect --format '{{.Id}}|{{.Name}}|{{.Driver}}|{{index .Options "com.docker.network.bridge.name"}}' "$network_id" 2>/dev/null) || return 1
  [[ $metadata != *$'\n'* ]] || return 1
  IFS='|' read -r found_id found_name driver bridge extra <<<"$metadata"
  [[ $found_id == "$network_id" && $found_name == "$network" && $driver == bridge && -z $extra ]] || return 1
  if [[ -z $bridge || $bridge == '<no value>' ]]; then bridge="br-${network_id:0:12}"; fi
  # '+' would be an iptables interface wildcard; only an exact Linux name is valid.
  [[ $bridge =~ ^[A-Za-z0-9_.:-]{1,15}$ && $bridge != . && $bridge != .. ]] || return 1
  printf '%s %s\n' "$address" "$bridge"
}
capstone_log4shell_tls_waf_forward(){
  local source destination source_ip source_bridge destination_ip destination_bridge
  if ! source=$(capstone_tls_endpoint chatproxy chatproxy_chat-net) || \
     ! destination=$(capstone_tls_endpoint waf secstack_waf-net); then
    echo 'WARN: Log4Shell TLS WAF endpoints unavailable; narrow forward rule omitted' >&2
    return 0
  fi
  read -r source_ip source_bridge <<<"$source"
  read -r destination_ip destination_bridge <<<"$destination"
  if [[ $source_ip == "$destination_ip" ]]; then
    echo 'WARN: Log4Shell TLS WAF endpoint addresses overlap; narrow forward rule omitted' >&2
    return 0
  fi
  F -s "$source_ip/32" -i "$source_bridge" -d "$destination_ip/32" -o "$destination_bridge" \
    -p tcp --dport 8080 -m conntrack --ctstate NEW --ctdir ORIGINAL \
    --ctorigdst 192.168.16.230 --ctorigdstport 80 \
    -m comment --comment capstone-log4shell-tls-waf -j ACCEPT
}
# END LOG4SHELL_TLS_WAF_HELPERS

# 1) IP forwarding (런타임). 영구화는 /etc/sysctl.d/99-capstone-nat.conf (+ v2: 99-capstone-fw.conf)
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# 2) 마스커레이드: 독립 nft 테이블. 멱등 위해 삭제 후 로드.
nft delete table ip capstone_gw 2>/dev/null || true
nft -f "$NFT_FILE"

# 3) 관리용 포트포워딩 DNAT (P11: 출발지 제한) + 회신 SNAT
{
  echo "# generated by capstone-nat.sh v2 — 관리 페이지 포트포워딩. 목록은 PORTFORWARDS, 출발지 제한 MGMT_DNAT_SRC."
  echo "table ip capstone_fwd {"
  echo "  chain prerouting {"
  echo "    type nat hook prerouting priority dstnat; policy accept;"
  for e in "${PORTFORWARDS[@]}"; do IFS=: read -r ep ip ipt desc <<<"$e"
    echo "    iifname \"$EXT_IF\" ip saddr $MGMT_DNAT_SRC tcp dport $ep dnat to $ip:$ipt   # $desc"
  done
  echo "  }"
  echo "  chain postrouting {"
  echo "    type nat hook postrouting priority srcnat; policy accept;"
  echo "    oifname \"$INT_IF\" ct status dnat masquerade   # DNAT 된 연결의 회신이 A 로 돌아오게"
  echo "  }"
  echo "}"
} > "$FWD_FILE"
nft delete table ip capstone_fwd 2>/dev/null || true
nft -f "$FWD_FILE"

# 4) forward 정책 — P1 default-deny + 전용 체인 허용목록
if iptables -L DOCKER-USER -n >/dev/null 2>&1; then
  iptables -P FORWARD DROP
  # v1 블랭킷/개별 룰 이관 제거(있으면)
  while iptables -C DOCKER-USER -s "$INT_NET" -i "$INT_IF" -o "$EXT_IF" -j ACCEPT 2>/dev/null; do iptables -D DOCKER-USER -s "$INT_NET" -i "$INT_IF" -o "$EXT_IF" -j ACCEPT; done
  while iptables -C DOCKER-USER -d "$INT_NET" -i "$EXT_IF" -o "$INT_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do iptables -D DOCKER-USER -d "$INT_NET" -i "$EXT_IF" -o "$INT_IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; done
  for e in "${PORTFORWARDS[@]}"; do IFS=: read -r ep ip ipt desc <<<"$e"
    while iptables -C DOCKER-USER -d "$ip" -i "$EXT_IF" -o "$INT_IF" -p tcp --dport "$ipt" -m conntrack --ctstate NEW -j ACCEPT 2>/dev/null; do iptables -D DOCKER-USER -d "$ip" -i "$EXT_IF" -o "$INT_IF" -p tcp --dport "$ipt" -m conntrack --ctstate NEW -j ACCEPT; done
  done
  # 전용 체인 재구성
  iptables -N "$FWD_CHAIN" 2>/dev/null || iptables -F "$FWD_CHAIN"
  iptables -C DOCKER-USER -j "$FWD_CHAIN" 2>/dev/null || iptables -A DOCKER-USER -j "$FWD_CHAIN"   # -A: 시나리오 토글의 -I 룰이 앞에 오도록
  F(){ iptables -A "$FWD_CHAIN" "$@"; }
  F -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  F -m conntrack --ctstate INVALID -j DROP
  # ext -> int : 관리 DNAT 경로만, 출발지 제한
  for e in "${PORTFORWARDS[@]}"; do IFS=: read -r ep ip ipt desc <<<"$e"
    F -s "$MGMT_DNAT_SRC" -d "$ip" -i "$EXT_IF" -o "$INT_IF" -p tcp --dport "$ipt" -m conntrack --ctstate NEW -j ACCEPT
  done
  # ext -> 컨테이너 : Docker 가 publish 한 포트만 DNAT 되므로 NEW 는 곧 공개 서비스(WAF 80/8443, chatproxy 443)
  F -i "$EXT_IF" -o 'br-+' -m conntrack --ctstate NEW -j ACCEPT
  F -i "$EXT_IF" -o docker0 -m conntrack --ctstate NEW -j ACCEPT
  # int -> ext : P2 허용목록 (+ ICMP 진단)
  for e in "${EGRESS_ALLOW[@]}"; do IFS=: read -r dst proto port desc <<<"$e"
    F -s "$INT_NET" -i "$INT_IF" -o "$EXT_IF" -d "$dst" -p "$proto" --dport "$port" -m conntrack --ctstate NEW -j ACCEPT
  done
  F -s "$INT_NET" -i "$INT_IF" -o "$EXT_IF" -p icmp -j ACCEPT
  # 컨테이너 -> int : P8 east-west 허용목록
  for e in "${EASTWEST_ALLOW[@]}"; do IFS=: read -r dst proto ports desc <<<"$e"
    F -i 'br-+' -o "$INT_IF" -d "$dst" -p "$proto" -m multiport --dports "$ports" -m conntrack --ctstate NEW -j ACCEPT
  done
  # TLS proxy -> existing public WAF DNAT only; never a general bridge-to-bridge allow.
  capstone_log4shell_tls_waf_forward
  # 그 외(컨테이너→외부, 내부→컨테이너, 비허용 ext→int, 내부→비허용 외부) : 로그 후 drop (P9)
  F -m limit --limit 5/min --limit-burst 10 -j LOG --log-prefix "FW_DROP_FWD " --log-level notice
  F -j DROP
else
  echo "WARN: DOCKER-USER 체인 없음 (docker 미기동?) — forward 정책 건너뜀" >&2
fi

# 5) 호스트 방화벽 + agent_block — v1 과 동일한 원자 교체(차단 목록 커널/상태파일 복원). FW_FILE 은 적용 스크립트가 .pending 으로 지정 가능.
FW_FILE=${FW_FILE:-/etc/nftables.d/capstone-fw.nft}
STATE=/var/lib/capstone/agent_block.state
if [ -f "$FW_FILE" ]; then
  # ⚠ 바(bare) 파일을 `nft -c -f "$FW_FILE"` 로 검사하면 라이브 셋과 겹치는 interval 원소에서 EEXIST 로 실패한다(v1 함정).
  #   실제 적용 형태(테이블 delete + include 한 트랜잭션)로 검사한다 — 아래 nft -c -f "$TMP".
  TMP=$(mktemp)
  { echo "table inet capstone_fw"; echo "delete table inet capstone_fw"; echo "include \"$FW_FILE\""; } > "$TMP"
  SRC=none
  if nft list set inet capstone_fw agent_block >/dev/null 2>&1; then
    if nft -j list set inet capstone_fw agent_block | python3 -c '
import json, sys
d = json.load(sys.stdin)
for o in d.get("nftables", []):
    for e in (o.get("set") or {}).get("elem", []):
        if isinstance(e, dict):
            r = int(float(e["elem"].get("expires", 0)))
            if r > 0: print("add element inet capstone_fw agent_block { %s timeout %ds }" % (e["elem"]["val"], r))
        else: print("add element inet capstone_fw agent_block { %s }" % e)' >> "$TMP"; then SRC=kernel
    else logger -t capstone-fw -p auth.warning "could not read current agent_block set; block list not carried over"; fi
  elif [ -s "$STATE" ]; then
    now=$(date +%s)
    while read -r bip bexp; do
      [ -n "$bip" ] && [ -n "$bexp" ] || continue; rem=$((bexp - now)); [ "$rem" -gt 0 ] || continue
      echo "add element inet capstone_fw agent_block { $bip timeout ${rem}s }" >> "$TMP"
    done < "$STATE"; SRC=statefile
  fi
  N=$(grep -c '^add element' "$TMP" || true)
  if ! nft -c -f "$TMP"; then rm -f "$TMP"; logger -t capstone-fw -p auth.err "capstone-fw.nft transaction failed check (previous table kept)"; exit 1; fi
  if ! nft -f "$TMP"; then rm -f "$TMP"; logger -t capstone-fw -p auth.err "capstone-fw.nft failed to load (previous table kept if any); host FW may be OFF"; exit 1; fi
  rm -f "$TMP"
  logger -t agent_block -p auth.notice -- "action=reload restored=$N source=$SRC result=ok by=capstone-nat" || true
  FW_STATE="on ($N blocked restored from $SRC)"
else
  FW_STATE="off (no $FW_FILE)"
fi

echo "capstone-nat v2 적용됨: masquerade $INT_NET -> $EXT_IF | FORWARD policy $(iptables -S FORWARD | head -1 | awk '{print $3}') | $FWD_CHAIN $(iptables -S $FWD_CHAIN 2>/dev/null | grep -c '^-A') rules | 포트포워딩 ${#PORTFORWARDS[@]}건(src $MGMT_DNAT_SRC) | egress allow ${#EGRESS_ALLOW[@]} | host FW $FW_STATE"
