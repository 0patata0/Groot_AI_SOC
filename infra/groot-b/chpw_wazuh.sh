#!/bin/bash
# chpw_wazuh.sh — Wazuh single-node(docker) 비밀번호 통일: indexer admin, dashboard kibanaserver, API wazuh-wui
# 사용:  NEWPW='<새비번>' NEWHASH='<bcrypt>' OLD_IDX_PW='<현재 admin 비번>' OLD_KIB_PW='<현재 kibanaserver 비번>' OLD_API_PW='<현재 wazuh-wui 비번>' \
#        sudo -E bash chpw_wazuh.sh
#   - NEWHASH: docker exec <indexer> bash -c 'export JAVA_HOME=/usr/share/wazuh-indexer/jdk; bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "<새비번>"'
#   - NEWPW는 API 정책(8~64자, 대·소문자·숫자·기호) 필수. 미충족 시 매니저 컨테이너가 기동 실패한다.
# 원칙: 단일파일 bind mount(internal_users.yml, wazuh.yml)는 같은 inode에 덮어쓰기(cat >), 게이트 통과 전 컨테이너 재생성 금지, 실패 시 자동 롤백.
# 비밀은 이 파일에 두지 말 것(환경변수로만). 이 스크립트는 데모계정 4개(kibanaro/logstash/readall/snapshotrestore)를 삭제한다.
set -euo pipefail
: "${NEWPW:?NEWPW 필요}"; : "${NEWHASH:?NEWHASH 필요}"
OLD_IDX_PW="${OLD_IDX_PW:-SecretPassword}"; OLD_KIB_PW="${OLD_KIB_PW:-kibanaserver}"; OLD_API_PW="${OLD_API_PW:-MyS3cr37P450r.*-}"
SN="${SN:-/home/groot_b/capstone/wazuh/single-node}"
IDX=single-node-wazuh.indexer-1; MGR=single-node-wazuh.manager-1; DSH=single-node-wazuh.dashboard-1
TS=$(date +%Y%m%d-%H%M%S)
CERTS=/usr/share/wazuh-indexer/config/certs
SA="export JAVA_HOME=/usr/share/wazuh-indexer/jdk; bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -icl -nhnv -p 9200 -cacert $CERTS/root-ca.pem -cert $CERTS/admin.pem -key $CERTS/admin-key.pem"
IU_C=/usr/share/wazuh-indexer/config/opensearch-security/internal_users.yml
HASHKEY=${NEWHASH: -20}   # 해시 끝 20자로 grep (특수문자 회피)
cd "$SN"
say(){ echo; echo "== $* =="; }
die(){ echo "!! ABORT: $*"; exit 1; }

say "P0 containers Up?"; docker compose ps --format '{{.Name}} {{.Status}}' | grep -q "$IDX.*Up" || die "indexer not Up"; echo ok

say "P1 backups (files + live security index -> secbak-$TS)"
cp -p docker-compose.yml "docker-compose.yml.bak-$TS"
cp -p config/wazuh_indexer/internal_users.yml "config/wazuh_indexer/internal_users.yml.bak-$TS"
cp -p config/wazuh_dashboard/wazuh.yml "config/wazuh_dashboard/wazuh.yml.bak-$TS"
docker exec $IDX bash -c "rm -rf /tmp/secbak; $SA -backup /tmp/secbak" | tail -2
docker cp $IDX:/tmp/secbak "./secbak-$TS"; echo "ok ($(ls ./secbak-$TS | wc -l) files)"

say "P2 opensearch_dashboards.yml must not hardcode creds"
if grep -nE '^opensearch\.(username|password)' config/wazuh_dashboard/opensearch_dashboards.yml; then die "yml overrides keystore"; fi; echo ok

say "P3 record inodes"
INO_IU=$(stat -c %i config/wazuh_indexer/internal_users.yml); INO_WY=$(stat -c %i config/wazuh_dashboard/wazuh.yml); echo "$INO_IU $INO_WY"

rollback(){ echo "!! rolling back files + live security index (containers untouched)"
  cp -p "docker-compose.yml.bak-$TS" docker-compose.yml
  cat "config/wazuh_indexer/internal_users.yml.bak-$TS" > config/wazuh_indexer/internal_users.yml
  cat "config/wazuh_dashboard/wazuh.yml.bak-$TS" > config/wazuh_dashboard/wazuh.yml
  docker exec $IDX bash -c "$SA -cd /tmp/secbak" | tail -2; }

say "M1 internal_users.yml IN PLACE (admin+kibanaserver new hash, demo users removed)"
cat > /tmp/iu.new <<'EOF'
---
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "__HASH__"
  reserved: true
  backend_roles:
  - "admin"
  description: "Admin user"

kibanaserver:
  hash: "__HASH__"
  reserved: true
  description: "Dashboard server user"
EOF
sed "s|__HASH__|$NEWHASH|g" /tmp/iu.new > /tmp/iu.new2
cat /tmp/iu.new2 > config/wazuh_indexer/internal_users.yml; rm -f /tmp/iu.new /tmp/iu.new2
[ "$(stat -c %i config/wazuh_indexer/internal_users.yml)" = "$INO_IU" ] || { rollback; die "inode changed"; }
C=$(docker exec $IDX grep -cF "$HASHKEY" $IU_C || true); [ "$C" = "2" ] || { rollback; die "container sees $C new hashes"; }
D=$(docker exec $IDX grep -cE '^(kibanaro|logstash|readall|snapshotrestore):' $IU_C || true); [ "$D" = "0" ] || { rollback; die "demo users visible"; }
echo "ok (container: 2 hashes, 0 demo)"

say "M2 wazuh.yml IN PLACE (dashboard->API password)"
sed "s|password: \".*\"|password: \"$NEWPW\"|" config/wazuh_dashboard/wazuh.yml > /tmp/wy.new
cat /tmp/wy.new > config/wazuh_dashboard/wazuh.yml; rm -f /tmp/wy.new
[ "$(stat -c %i config/wazuh_dashboard/wazuh.yml)" = "$INO_WY" ] || { rollback; die "wazuh.yml inode changed"; }
grep -qF "password: \"$NEWPW\"" config/wazuh_dashboard/wazuh.yml || { rollback; die "wazuh.yml not updated"; }; echo ok

say "M3 docker-compose.yml env"
sed -i -e "s|INDEXER_PASSWORD=.*|INDEXER_PASSWORD=$NEWPW|" -e "s|DASHBOARD_PASSWORD=.*|DASHBOARD_PASSWORD=$NEWPW|" -e "s|API_PASSWORD=.*|API_PASSWORD=$NEWPW|" docker-compose.yml
N=$(docker compose config 2>/dev/null | grep -cF "$NEWPW" || true); [ "$N" = "5" ] || { rollback; die "compose has $N pw lines (expected 5)"; }; echo "ok (5)"

say "M4 apply ONLY internalusers to the running indexer"
docker exec $IDX bash -c "$SA -f $IU_C -t internalusers" | tail -2

say "M5 GATE: new creds 200 / old creds 401"
h_new=$(curl -sk -o /dev/null -w '%{http_code}' -u "admin:$NEWPW" https://localhost:9200/_cluster/health)
k_new=$(curl -sk -o /dev/null -w '%{http_code}' -u "kibanaserver:$NEWPW" https://localhost:9200/_plugins/_security/authinfo)
h_old=$(curl -sk -o /dev/null -w '%{http_code}' -u "admin:$OLD_IDX_PW" https://localhost:9200/_cluster/health)
k_old=$(curl -sk -o /dev/null -w '%{http_code}' -u "kibanaserver:$OLD_KIB_PW" https://localhost:9200/_plugins/_security/authinfo)
echo "admin new=$h_new old=$h_old | kibanaserver new=$k_new old=$k_old"
{ [ "$h_new" = 200 ] && [ "$k_new" = 200 ] && [ "$h_old" = 401 ] && [ "$k_old" = 401 ]; } || { rollback; die "gate failed; rolled back"; }
echo "gate ok"

say "M6 recreate manager+dashboard"; docker compose up -d 2>&1 | grep -E 'Recreat|Start' | tail -4
say "M7 wait 75s"; sleep 75; docker compose ps --format '{{.Name}}  {{.Status}}'
docker compose ps --format '{{.Status}}' | grep -qi restart && die "a container is Restarting" || true

say "V1 manager"; docker logs --since 4m $MGR 2>&1 | grep -qi 'error configuring the API user' && die "API user error" || echo "no API-user error"
docker exec $MGR filebeat test output 2>&1 | grep -E 'talk to server|dial up'
say "V2 API"; t_new=$(curl -sk -o /dev/null -w '%{http_code}' -u "wazuh-wui:$NEWPW" -X POST https://localhost:55000/security/user/authenticate)
t_old=$(curl -sk -o /dev/null -w '%{http_code}' -u "wazuh-wui:$OLD_API_PW" -X POST https://localhost:55000/security/user/authenticate)
echo "api new=$t_new old=$t_old"; { [ "$t_new" = 200 ] && [ "$t_old" = 401 ]; } || die "API check failed"
say "V3 dashboard login"; l_new=$(curl -sk -o /dev/null -w '%{http_code}' -X POST https://localhost:443/auth/login -H 'osd-xsrf: true' -H 'Content-Type: application/json' -d "{\"username\":\"admin\",\"password\":\"$NEWPW\"}")
l_old=$(curl -sk -o /dev/null -w '%{http_code}' -X POST https://localhost:443/auth/login -H 'osd-xsrf: true' -H 'Content-Type: application/json' -d "{\"username\":\"admin\",\"password\":\"$OLD_IDX_PW\"}")
echo "login new=$l_new old=$l_old"
say "V4 demo users (expect 401)"; for u in kibanaro:kibanaro logstash:logstash readall:readall snapshotrestore:snapshotrestore; do printf '%s -> ' "$u"; curl -sk -o /dev/null -w '%{http_code}\n' -u "$u" https://localhost:9200/_plugins/_security/authinfo; done
say "V5 cluster"; curl -sk -u "admin:$NEWPW" https://localhost:9200/_cluster/health | grep -o '"status":"[a-z]*"'
echo; echo "== CHPW_DONE =="
