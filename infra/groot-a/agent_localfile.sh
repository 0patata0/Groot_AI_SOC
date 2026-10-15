#!/bin/bash
# Groot_A: Wazuh 에이전트에 보안스택 로그 수집 추가 (Suricata eve.json, ModSecurity audit.log — 둘 다 1줄=1 JSON).
# 게이트형. sudo bash 로 실행. 재실행 안전(이미 등록돼 있으면 종료). 비밀 없음.
set -euo pipefail
C=/var/ossec/etc/ossec.conf
SS=/home/groot_a/capstone/secstack
EVE=$SS/logs/suricata/eve.json
AUD=$SS/logs/modsec/audit.log
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*"; exit 1; }

say "G0 preflight"
[ -f $C ] || die "ossec.conf missing"
[ -s $EVE ] || die "eve.json missing/empty (secstack not running?)"
[ -f $AUD ] || die "audit.log missing"
[ -r $EVE ] && [ -r $AUD ] || die "log files not readable by root?"
systemctl is-active wazuh-agent >/dev/null || die "wazuh-agent not active"
grep -q "status='connected'" /var/ossec/var/run/wazuh-agentd.state || die "agent not connected to manager"
if grep -q "$EVE" $C; then echo "already configured — nothing to do"; exit 0; fi
echo "ok: agent connected, logs present"

say "P1 backup"
B=$C.bak.$(date +%Y%m%d%H%M%S); cp -a $C $B; echo "backup: $B"

say "P2 append localfile block (separate <ossec_config> block; Wazuh merges multiple blocks)"
cat >> $C <<EOF

<!-- capstone secstack: Suricata IDS + ModSecurity WAF (JSON, 1 event/line) — added $(date -u +%F) -->
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>$EVE</location>
    <!-- Engine counters remain in eve.json; native JSON decoder has a bounded field count. -->
    <!-- Keep stats in native reader: Wazuh 4.14.8 ignore can desynchronize hash/offset. Manager rule 86600 handles stats at level 0. -->
    <label key="capstone.source">suricata</label>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>$AUD</location>
    <label key="capstone.source">modsecurity</label>
  </localfile>
</ossec_config>
EOF
tail -14 $C

say "P3 restart agent"
systemctl restart wazuh-agent
sleep 6
systemctl is-active wazuh-agent >/dev/null || { tail -20 /var/ossec/logs/ossec.log; cp -a $B $C; die "agent failed with new config — restored backup"; }

say "V1 logcollector picked up both files"
sleep 4
grep -E "Analyzing file|ERROR|CRITICAL" /var/ossec/logs/ossec.log | tail -6
grep -q "Analyzing file: '$EVE'" /var/ossec/logs/ossec.log || die "eve.json not picked up"
grep -q "Analyzing file: '$AUD'" /var/ossec/logs/ossec.log || die "audit.log not picked up"

say "V2 agent reconnected"
for i in $(seq 1 24); do grep -q "status='connected'" /var/ossec/var/run/wazuh-agentd.state 2>/dev/null && break; sleep 5; done
grep -E "^status" /var/ossec/var/run/wazuh-agentd.state
grep -q "status='connected'" /var/ossec/var/run/wazuh-agentd.state || die "agent not reconnected"
echo; echo "== AGENT_LOCALFILE_DONE =="
