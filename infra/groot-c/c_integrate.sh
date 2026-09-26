#!/bin/bash
# Groot_C: SIEM/MCP 연동 보완 — 게이트형, 멱등. sudo bash 로 실행. (C 담당자 구축분은 건드리지 않고 두 가지만 추가)
#  1) /etc/hosts 내부 이름(groot-sec/groot-siem/groot-web) — A·B와 동일
#  2) apache mod_remoteip: A의 WAF(nginx → 10.10.10.1 로 SNAT) 뒤에 있으므로 X-Forwarded-For 에서 실제 클라이언트 IP 복원.
#     없으면 access.log/Wazuh 경보 srcip 가 전부 10.10.10.1(A) → 나중에 차단 대응이 A 자신을 막는다. (2026-09-26 실측: 31103/31105 경보 srcip=10.10.10.1)
#     자체 검증: C → A의 WAF(10.10.10.1:80) → C 로 요청을 보내 access.log 에 C 자신의 IP가 찍히는지 확인. %h 가 복원 IP를 안 쓰면 LogFormat 을 %a 로 교체.
set -euo pipefail
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*"; exit 1; }
TS=$(date +%Y%m%d%H%M%S)

say "G0 preflight"
[ "$(id -u)" = 0 ] || die "run as root"
systemctl is-active apache2 >/dev/null || die "apache2 not active"
ip -br addr show ens160 | grep -q '10\.10\.10\.20/' || die "ens160 is not 10.10.10.20"
timeout 5 bash -c 'exec 3<>/dev/tcp/10.10.10.1/80' 2>/dev/null || die "A WAF 10.10.10.1:80 unreachable"
apachectl -M 2>/dev/null | grep -q log_config || die "mod_log_config missing"
grep -q 'LogFormat.*combined' /etc/apache2/apache2.conf || die "combined LogFormat not found in apache2.conf"
echo "ok"

say "P1 /etc/hosts internal names"
cp -a /etc/hosts /etc/hosts.bak.$TS
for e in "10.10.10.1   groot-sec  groot-a" "10.10.10.10  groot-siem groot-b" "10.10.10.20  groot-web  groot-c"; do
  n=$(awk '{print $2}' <<<"$e"); grep -qE "^10\.10\.10\.[0-9]+\s+$n\b" /etc/hosts || echo "$e" >> /etc/hosts
done
getent hosts groot-siem | grep -q 10.10.10.10 || die "groot-siem does not resolve"
grep -E '^10\.10\.10' /etc/hosts | sed 's/^/  /'

say "P2 apache mod_remoteip (X-Forwarded-For from A's WAF only)"
a2enmod -q remoteip >/dev/null
cat > /etc/apache2/conf-available/capstone-remoteip.conf <<'EOF'
# capstone: A의 WAF(nginx) 뒤 — X-Forwarded-For 에서 실제 클라이언트 IP 복원 (10.10.10.1 = A 내부 IP, WAF 컨테이너가 SNAT 됨)
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy 10.10.10.1
EOF
a2enconf -q capstone-remoteip >/dev/null
apachectl configtest 2>&1 | grep -q 'Syntax OK' || { apachectl configtest; die "apache configtest failed"; }
systemctl reload apache2; sleep 1

selftest(){ # C -> A WAF -> C ; access.log 마지막 줄의 첫 필드가 C 자신(10.10.10.20)이면 성공
  local m="capstone-remoteip-selftest-$1"
  curl -s -o /dev/null -m 8 -A "$m" "http://10.10.10.1/dvwa/login.php?x=$m" || true; sleep 1
  L=$(grep -F "$m" /var/log/apache2/access.log | tail -n1); echo "  access.log: ${L:0:110}"
  [[ $L == 10.10.10.20\ * ]]
}
say "V1 self-test with %h"
if selftest h; then echo "  OK: %h already logs the restored client IP"
else
  say "P3 fallback: combined LogFormat %h -> %a (useragent IP)"
  cp -a /etc/apache2/apache2.conf /etc/apache2/apache2.conf.bak.$TS
  sed -i -E 's/^(LogFormat ")%h( .*combined)$/\1%a\2/' /etc/apache2/apache2.conf
  grep -E '^LogFormat.*combined' /etc/apache2/apache2.conf | sed 's/^/  /'
  apachectl configtest 2>&1 | grep -q 'Syntax OK' || { cp -a /etc/apache2/apache2.conf.bak.$TS /etc/apache2/apache2.conf; die "configtest failed after LogFormat change (restored)"; }
  systemctl reload apache2; sleep 1
  selftest a || die "self-test still shows the proxy IP — check RemoteIPInternalProxy / X-Forwarded-For"
  echo "  OK with %a"
fi

say "V2 direct (non-proxied) request still logs the real peer"
curl -s -o /dev/null -m 5 -A capstone-direct-selftest http://127.0.0.1/dvwa/login.php || true; sleep 1
grep -F capstone-direct-selftest /var/log/apache2/access.log | tail -n1 | cut -c1-90 | sed 's/^/  /'

say "V3 time sync"
timedatectl show -p NTPSynchronized -p NTP -p TimeUSec | sed 's/^/  /'
echo; echo "== C_INTEGRATE_DONE =="
