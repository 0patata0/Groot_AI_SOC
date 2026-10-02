# GROOT_A IPS Phase-A 변경셋 — 무중단 탐지/로깅/자산 (2026-10-02, 검증 반영)

> 대상 Groot_A `groot-sec` / Suricata 8.0.6 (Docker). **차단 전환 없음**(여전히 passive `-i ens192`).
> 목적: 탐지 정확도·교차도구 상관·로그 신호 품질만 향상. 전부 라이브 무중단(출력/앱계층 설정 변경은 **짧은 컨테이너 재시작** 필요).
> 근거 문서 `GROOT_A_IPS_SURICATA_개선점(검증).md` Phase A: IPS-09/11/12/13/14/15/16/17/18/19.
> 모든 `--set`/파일은 **throwaway 컨테이너에서 실측 검증**(§7). 적용은 사용자 승인/점검 창에서.

## 1. compose `--set` 추가 (선언형, yaml 미편집 — **검증됨**)

`docker-compose.yml`의 `suricata.command`(및 `deploy_secstack.sh`) 끝에 아래를 추가. 현재:
```
suricata -i ens192 -S /rules/suricata.rules \
  --set vars.address-groups.HOME_NET=[10.200.10.0/24,192.168.16.230/32] \
  --set stats.interval=60
```
→ Phase-A 적용 후:
```
suricata -i ens192 -S /rules/suricata.rules \
  --set vars.address-groups.HOME_NET=[10.200.10.0/24,192.168.16.230/32] \
  --set stats.interval=60 \
  --set outputs.1.eve-log.community-id=true \        # IPS-13 교차도구(Zeek/WAF) 플로우 상관
  --set outputs.1.eve-log.community-id-seed=0 \       #        Zeek 기본 seed 정렬
  --set app-layer.protocols.tls.ja3-fingerprints=true \  # IPS-12 암호 플로우 지문(TLS는 복호화 못 하므로 메타로 활용)
  --set app-layer.protocols.tls.ja4-fingerprints=true \  #        ja4 동반
  --set threshold-file=/etc/suricata/threshold.in        # IPS-11 관리자 SSH 스캔 노이즈 억제
```
- **주의 — 인덱스 `outputs.1`**: 현재 라이브 yaml에서 `outputs` 리스트의 **[1]=eve-log**임을 실측 확인(0=fast,1=eve-log,2=tls-store,…). outputs 순서를 바꾸면 인덱스 재확인.
- **반영 방식**: 위 플래그는 **출력/앱계층 설정**이라 `suricatasc -c reload-rules`로는 안 먹고 **컨테이너 재시작** 필요. passive라 재시작 중 짧은 탐지 공백만 있음(통과 트래픽 영향 없음).

## 2. threshold.in (IPS-11) — `new_rule/GROOT_A_suricata_threshold.in`
- 반입: `/etc/suricata/threshold.in`(= compose `--set threshold-file=` 가 가리키는 경로, rw 볼륨 `/etc/suricata`).
- 내용 핵심: `suppress gen_id 1, sig_id 2001219, track by_src, ip 192.168.10.0/24` — 검증된 관리자망(192.168.10.0/24)의 ET SCAN SSH(2001219)만 억제, 그 외 출처는 유지(절대 전역 억제 금지).
- **threshold-file 은 reload 가능**: 편집 후 `docker exec suricata suricatasc -c reload-rules`로 즉시 반영(재시작 불필요). 단 compose `--set threshold-file` 자체를 처음 추가할 때는 재시작 1회.

## 3. 이미 켜져 있음 — 확인만 (변경 불필요, 실측)
- **IPS-18 alert.metadata**: eve alert에 `metadata`(ET의 mitre/severity) **기본 방출됨**(샘플 alert 2건에서 확인). 변경 없음.
- **IPS-12b TLS extended**: eve-log `tls: extended: yes` **이미 on**. 변경 없음.
- **IPS (http extended)**: `http: extended: yes` 이미 on.

## 4. 선택 yaml 편집 (리스트형이라 `--set` 부적합 — /etc/suricata 볼륨 편집 + 재시작)
- **IPS-17 eve 신호 분리(권장도 중):** 단일 eve.json에 `flow`/`stats`가 실경보를 희석. 2안:
  - (간단) Wazuh가 읽는 eve 타입에서 `- flow`/`- stats` 제거하고, `- anomaly:`는 `types: [applayer]`로 제한해 ARP/unknown-ethertype L2 노이즈(IPS-19) 차단.
  - (권장) eve-log 인스턴스 2개: Wazuh용(alert/http/tls/dns/fileinfo/ssh) + 비전송 로컬 파일(flow/stats/anomaly). flow를 **삭제하지 말고** 비전송 파일로 보존.
  - 반영: yaml 편집 → 컨테이너 재시작 → Wazuh agent localfile 경로 정합 확인.
- **IPS-19 L2 노이즈(선택):** ens192 비-IP 21.7%(ARP/unknown-ethertype). ARP 스푸핑 시나리오가 필요 없으면 af-packet `bpf-filter: "ip or ip6"`로 제거, 필요하면 eve `- arp` 출력 추가. 커널드롭 0이라 비긴급.

## 5. 컨테이너/수명주기/자산
- **IPS-14 버전 고정:** compose `image: jasonish/suricata:latest` → `jasonish/suricata:8.0.6`(가능하면 `@sha256:<digest>`). ET Open 버전도 suricata-update로 기록·고정. "8.0.6 랩" 재현성 확보.
- **IPS-16 리로드 vs 재시작 런북:** 룰/threshold만 바뀌면 `suricatasc -c reload-rules`(무중단), 실행플래그/`--set`/yaml 변경은 `docker compose up -d`(재시작 ~12초, 비피크). `deploy_secstack.sh`에 분기 문서화 + healthcheck 추가.
- **IPS-09 HOME_NET 단일 진실원:** 보호망 정의를 `secstack/.env` 한 곳에서 compose `--set HOME_NET`·nftables 스코프·WAF `BACKEND`이 참조. 유효 on-wire HOME_NET=192.168.16.230/32(ens192)이고 10.200.10.0/24 절반은 ens160 감시(IPS-01, Phase B/C) 전까진 aspirational임을 주석.
- **IPS-15 HTTP_PORTS(게이트):** 현재 `80` 유지. ens160 감시(IPS-01)가 들어올 때 DMZ 포트집합으로 확장(같은 `--set`으로 병합). 지금은 변경 없음.

## 6. 적용 순서 & 검증 명령
```bash
# 1) threshold.in 반입
sudo install -m0644 GROOT_A_suricata_threshold.in \
  /home/groot_a/capstone/secstack/.../etc-suricata/threshold.in   # /etc/suricata 볼륨 실제 경로
# 2) compose suricata.command 에 §1 --set 플래그 추가 후
cd /home/groot_a/capstone/secstack && docker compose up -d suricata   # 재시작(출력설정 반영)
# 3) 검증 (eve 필드 생성 확인)
docker exec suricata suricatasc -c reload-rules                       # threshold 재적용(무중단)
tail -n200 .../logs/suricata/eve.json | grep -o '"community_id":"[^"]*"' | head   # community_id 생성?
tail -n200 .../logs/suricata/eve.json | grep -oE '"ja3"|"ja4"' | sort -u          # TLS 지문 생성?
# 4) 억제 확인: 관리자망(192.168.10.x)발 2001219 가 alerts 에서 사라지는지 (비관리자 출처는 유지)
```
- 롤백: compose 이전본으로 `docker compose up -d suricata`(백업 존재), threshold.in 비우고 reload.

## 7. 검증 기록 (2026-10-02, throwaway 컨테이너 / 라이브·호스트 무영향)
| 항목 | 방법 | 결과 |
|---|---|---|
| `--set` 수용 | `suricata -T` (전 플래그) | 설정 로드 성공(에러 없음) |
| IPS-13 community-id | `outputs.1.eve-log.community-id=true` + http pcap | eve에 `community_id`(예 `1:Y/bgEYdp7JAn66TrxONwD3WGubc=`) **8건** |
| IPS-12 ja3/ja4 | `app-layer.protocols.tls.ja{3,4}-fingerprints=true` + 라이브 WAF TLS pcap | tls 이벤트에 **ja3=yes, ja4=yes**(TLS 1.3) |
| IPS-11 threshold | 테스트 룰 9999001 + `suppress by_src 127.0.0.1` | 억제 전 2건 → 후 **0건** |
| IPS-18 metadata | 공격 pcap alert | alert에 `metadata` **기본 포함**(2건) |
- 미검증(문서화만): IPS-17 eve 분리 효과(운영 판단), IPS-19 BPF, IPS-14 digest 고정은 운영 반영 항목.
