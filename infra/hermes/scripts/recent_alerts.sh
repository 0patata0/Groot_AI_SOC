#!/bin/bash
# Hermes cron --monitor-script (컨테이너 안 /opt/data/scripts/recent_alerts.sh 로 배치, hermes 소유 0700).
# 매 틱마다 실행되어 "최신 고심각도 경보 지문"을 출력한다. 출력 바이트가 이전과 같으면 Hermes 는 LLM 을 돌리지 않고,
# 달라지면(새 경보) 프롬프트에 MONITOR CHANGE DETECTED 차이를 넣어 조사를 시작한다. 자격증명 없음: soc_bot 의 읽기 토큰만.
# env: SOC_READ_TOKEN(필수), SOC_BOT_URL(기본 http://10.200.10.10:8090), MIN_LEVEL(기본 10), WINDOW_MIN(기본 60)
set -u
: "${SOC_READ_TOKEN:?SOC_READ_TOKEN unset}"
U="${SOC_BOT_URL:-http://10.200.10.10:8090}/recent?minutes=${WINDOW_MIN:-60}&level=${MIN_LEVEL:-10}"
out=$(curl -s -m 10 -H "X-Read-Token: $SOC_READ_TOKEN" "$U") || { echo "monitor: soc_bot unreachable"; exit 0; }
# 안정적 바이트: 키 정렬 JSON 으로 재직렬화 (타임스탬프는 절대값이라 새 경보가 있을 때만 바뀜)
python3 - <<'PY' "$out"
import json, sys
try:
    d = json.loads(sys.argv[1])
except Exception:
    print("monitor: bad response"); sys.exit(0)
if "error" in d:
    print("monitor: error %s" % d["error"]); sys.exit(0)
rows = d.get("latest", [])
if not rows:
    print("no high-severity alerts (level>=10) in window"); sys.exit(0)
for r in rows:
    print("%s | rule %s lv%s | agent %s | src %s | %s" % (r.get("ts"), r.get("id"), r.get("level"), r.get("agent"), r.get("srcip"), r.get("desc")))
PY
