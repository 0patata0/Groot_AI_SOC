#!/bin/bash
# Groot_A: Wazuh agent 4.14.8 오프라인 설치 + 매니저(groot-siem=10.10.10.10) 등록. 게이트형(리뷰 반영). sudo bash로 실행.
# 전제: /tmp/wazuh-agent_4.14.8-1_amd64.deb (인터넷 PC에서 packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/ 받아 전송, sha256 확인),
#       /etc/hosts에 groot-siem, 매니저 authd(1515, use_password=no) 기동. fresh 설치여야 배포변수(WAZUH_MANAGER 등)가 적용됨.
# 롤백: systemctl disable --now wazuh-agent; dpkg -P wazuh-agent; (B) manage_agents -r <id>  ※ agent_control -r 은 삭제가 아니라 rootcheck
set -euo pipefail
DEB=/tmp/wazuh-agent_4.14.8-1_amd64.deb
MGR=groot-siem
CONF=/var/ossec/etc/ossec.conf
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*"; exit 1; }

say "G0 preflight"
[ -f "$DEB" ] || die "deb missing"
dpkg -s wazuh-agent >/dev/null 2>&1 && die "already installed (non-fresh: deployment vars ignored) — purge first"
[ -e /var/ossec ] && die "/var/ossec exists (stale) — remove first"
rm -rf /tmp/wz-ctl; dpkg-deb -e "$DEB" /tmp/wz-ctl
grep -q 'register_configure_agent.sh' /tmp/wz-ctl/postinst || die "postinst lacks register_configure_agent.sh"
rm -rf /tmp/wz-ctl
getent hosts $MGR | grep -q '10.10.10.10' || die "$MGR unresolved"
# docker-proxy 뒤라 TCP connect는 가짜 PASS → authd TLS 인증서로 실서비스 확인
timeout 6 openssl s_client -connect $MGR:1515 </dev/null 2>/dev/null | grep -q 'BEGIN CERTIFICATE' || die "authd TLS on $MGR:1515 not answering"
timeout 4 bash -c "exec 3<>/dev/tcp/$MGR/1514" 2>/dev/null || die "$MGR:1514 unreachable"
echo "ok"

say "I1 install (deployment vars; fresh install)"
WAZUH_MANAGER="$MGR" WAZUH_AGENT_NAME="$(hostname)" ENROLLMENT_DELAY=5 DEBIAN_FRONTEND=noninteractive dpkg -i "$DEB" 2>&1 | tail -3

say "I2 config gates"
if grep -q '<address>MANAGER_IP</address>' "$CONF"; then echo "warn: vars not applied — fallback sed"; sed -i "s|<address>MANAGER_IP</address>|<address>$MGR</address>|" "$CONF"; fi
[ "$(grep -c '<address>' "$CONF")" = "1" ] || die "unexpected <address> count"
grep -q "<address>$MGR</address>" "$CONF" || die "manager address not set"
grep -q 'MANAGER_IP' "$CONF" && die "MANAGER_IP remains" || true
grep -n -A6 '<enrollment>' "$CONF" | head -9 || true
# 기본 active-response(firewall-drop=iptables INPUT/FORWARD)는 Docker/nft 설계와 충돌 → 에이전트에서 비활성. 응답은 MCP→nft agent_block 로만.
sed -i '/<active-response>/,/<\/active-response>/ s|<disabled>no</disabled>|<disabled>yes</disabled>|' "$CONF"

say "I3 enable + start"
systemctl daemon-reload; systemctl enable --now wazuh-agent; sleep 5
/var/ossec/bin/wazuh-control status
/var/ossec/bin/wazuh-control status | grep -v 'is running' && die "a wazuh daemon is not running" || true

say "V1 wait connected (<=120s; 등록 후 delay_after_enrollment 5s)"
for i in $(seq 1 24); do grep -q "^status='connected'" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null && break; sleep 5; done
grep -E "^(status|last_keepalive|last_ack)" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null || echo "(state file absent)"
grep -q "^status='connected'" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null || { tail -30 /var/ossec/logs/ossec.log; die "not connected after 120s"; }

say "V2 log evidence"
grep -E 'Requesting a key|Valid key received|Connected to the server' /var/ossec/logs/ossec.log | tail -4
grep -E 'Duplicate agent name|Unable to connect to enrollment|Invalid server address|Could not resolve|CRITICAL' /var/ossec/logs/ossec.log && die "enrollment error" || echo "no enrollment errors"

say "V3 NAT path untouched"
echo "masquerade: $(nft list table ip capstone_gw | grep -c masquerade)  DOCKER-USER ACCEPT: $(iptables -S DOCKER-USER | grep -c ACCEPT)"
rm -f "$DEB"; echo; echo "== AGENT_DONE =="
# 매니저 측 확인(B): docker exec <manager> /var/ossec/bin/agent_control -l  → 'Name: groot-sec, IP: any, Active' (첫 keepalive 후 Pending→Active)
