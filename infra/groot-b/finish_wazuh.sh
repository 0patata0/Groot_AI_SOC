#!/bin/bash
# Groot_B: Wazuh single-node 오프라인 기동 — 인증서 생성(openssl) + docker compose up
# 전제: images 로드됨, ~/capstone/wazuh/single-node 전개됨, vm.max_map_count=262144, /tmp/wazuh-certs-tool.sh 존재
# 실행: sudo bash finish_wazuh.sh
set -e
SN=/home/groot_b/capstone/wazuh/single-node
CG=/tmp/certgen
[ -f /tmp/wazuh-certs-tool.sh ] || { echo "ERROR: /tmp/wazuh-certs-tool.sh 없음"; exit 1; }

rm -rf "$CG"; mkdir -p "$CG"
cp /tmp/wazuh-certs-tool.sh "$CG/"
cp "$SN/config/certs.yml" "$CG/config.yml"      # 툴은 자기 옆의 config.yml을 읽는다
cd "$CG"
echo "== generating certs (openssl, no network) =="
bash wazuh-certs-tool.sh -A

DST="$SN/config/wazuh_indexer_ssl_certs"
mkdir -p "$DST"
cp -f "$CG"/wazuh-certificates/* "$DST/"
cp -f "$DST/root-ca.pem" "$DST/root-ca-manager.pem"   # manager 마운트용 사본
# ⚠️ 컨테이너 내부 비root 유저(wazuh-indexer 등)가 읽어야 하므로 644. 640이면 인덱서 크래시.
chmod 644 "$DST"/*
chown -R root:root "$DST"

echo "== certs =="; ls -1 "$DST"
echo "== compose up =="
cd "$SN" && docker compose up -d
sleep 20
docker compose ps
echo "== FINISH_DONE =="
