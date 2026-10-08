# 2026_capstone_Groot_B — SIEM(Wazuh) + MCP Server

> **현황(2026-10-06 기록 및 이번 SSH 재확인):** B의 `ens192` vNIC는 제거됐고 `ens160=10.200.10.10`의 기본 경로가 A(`10.200.10.1`)를 지난다. Wazuh 에이전트 000/001/002는 Active다. B의 `local_decoder.xml`·`local_rules.xml`에는 신규 신호 전용 항목이 없지만, IPS 로컬 SID가 기존 Suricata 룰로 분류되는지는 미확인이다. 공격 프로브 발화도 미검증이다. [기존 기록](../../대화기록/2026-10-06.md)

> **2026-10-08 관리 SSH 직접 재확인:** Wazuh 000/001/002는 계속 Active이고 경보 파일이 갱신 중이다. Hermes의 3개 MCP 서버가 enabled, SOC 봇·보고/요약 타이머가 active다. B 브로커 토큰·허용 승인자 목록은 비어 있지 않다. 로컬 룰 파일은 저장소와 해시가 같고 디코더는 주석의 옛 예시 IP 한 줄만 다르다. 신규 FW 접두어·WAF 100200대 분류는 여전히 없다. [오늘 기록](../../대화기록/2026-10-08.md)

> **같은 날 약 12:58 KST 후속 배포:** B `soc-bot`에 별도 룰 승인 API를 배포하고 `rulechg` SSH 강제 명령·root helper·`rule-change-worker.timer`를 설치했다(active/enabled). Hermes에는 기존 3개 MCP 서버를 유지하면서 `rule-a`·`rule-b`를 추가했다. A/B↔브로커 HMAC 통신과 로컬 룰 대상 읽기 조회가 통과했고, Wazuh 운영 룰 해시는 배포 전후 동일하다. 실제 Mattermost 승인 버튼→룰 적용·복구 E2E는 아직 검증하지 않았다. [배포 절차](../mcp/rule-change-deploy.md)

## Wazuh 4.14.8 single-node — 오프라인 기동 (2026-09-26 완료 ✅)
공식 **wazuh-docker `v4.14.8` single-node** 구성을 쓰되, 이 망은 **웹 egress 차단**이라 온라인 절차를 그대로 못 쓴다. 아래는 실제로 동작한 오프라인 절차.

### 사전 준비 (완료)
- 이미지 3종 오프라인 반입·`docker load`: `wazuh/wazuh-manager|indexer|dashboard:4.14.8`
- 공식 `single-node/` 디렉터리(compose + config) → `~/capstone/wazuh/single-node`
- 인덱서 필수: `vm.max_map_count=262144` (`/etc/sysctl.d/99-wazuh.conf`)

### 인증서 — ⚠️ 공식 생성기 컨테이너는 오프라인 불가
`generate-indexer-certs.yml`의 `wazuh-certs-generator`는 **실행 중 `packages.wazuh.com`에서 certs-tool을 내려받기** 때문에 이 망에선 멈춘다.
→ 대신 **`wazuh-certs-tool.sh`(4.14, 순수 openssl·네트워크 미사용 — 코드리뷰 완료)**를 인터넷 되는 곳에서 받아 B에 넣고 직접 실행한다. `finish_wazuh.sh`가 이걸 수행한다.

### 기동 절차
```bash
# (인터넷 PC) https://packages.wazuh.com/4.14/wazuh-certs-tool.sh 받아서 B:/tmp/ 로, finish_wazuh.sh도 B:/tmp/
sudo bash /tmp/finish_wazuh.sh
#  → certs.yml을 config.yml로 복사 → certs-tool -A → 인증서를 config/wazuh_indexer_ssl_certs/에 배치
#    (+ root-ca-manager.pem 사본) → chmod 644 → docker compose up -d → ps
```
- ⚠️ **인증서 권한은 반드시 644.** `640 root:root`로 두면 컨테이너 내부 비root 유저(wazuh-indexer)가 `root-ca.pem`을 못 읽어 보안 플러그인 로드 실패 → 인덱서 크래시 루프 → 대시보드 연쇄 재시작. (1차 기동 실패 원인)
- 접속: Dashboard `:443`, Server API `:55000`, Indexer `:9200`, Agent `:1514`. **현재 B 주소는 내부망 `10.200.10.10`만** — 옛 임시외부 `192.168.16.231`(ens192)은 제거 완료. 운영자는 A 경유 SSH ProxyJump(`ssh groot-b-int`); A:10443→B:443 DNAT 룰은 확인됐지만 허용 소스가 `192.168.16.0/25`여서 Kali의 실제 도달성은 미검증이다. 저장소 `fw-v2/capstone-nat.sh`는 A:443 chatproxy 경로도 설명하지만 이번 SSH 점검에서 해당 응답 경로는 구분하지 않았다. 2026-09-26 검증: A 경유로 22/443/1514/55000 도달, 대시보드 로그인 200.
- 리소스: 인덱서 힙 `-Xms1g -Xmx1g`(compose 기본). B RAM 여유 커서 필요 시 상향.

### 검증 결과 (2026-09-26)
- 3컨테이너 안정 Up / 인덱서 `_cluster/health` **green** (22 shards) / Dashboard **302** / API `POST /security/user/authenticate` **JWT 발급** / `wazuh-states-*`, `wazuh-monitoring-*` 인덱스 자동 생성(매니저↔인덱서 연동 OK)

### 계정 — 기본값 교체 완료 (2026-09-26)
`admin`(indexer) · `kibanaserver`(dashboard 서비스) · `wazuh-wui`(API) 세 계정을 **팀 공용 비밀번호로 통일**(값은 `CREDENTIALS.local.md`, 커밋 금지). 데모 계정 4개(kibanaro/logstash/readall/snapshotrestore, 공개 기본비번)는 **삭제**. 롤백 아티팩트: `secbak-<ts>/`(라이브 보안인덱스 덤프) + `*.bak-<ts>`.
- API 비번 정책: 8~64자 + 대·소문자·숫자·기호 필수 (`framework/wazuh/security.py` 정규식). 미충족 시 `create_user.py` 실패 → **매니저 컨테이너가 종료**되므로 반드시 준수.
- 절차는 `chpw_wazuh.sh` (NEWPW/NEWHASH 환경변수로 실행, 게이트형·실패 시 자동 롤백). 해시 생성: `docker exec <indexer> bash -c 'export JAVA_HOME=/usr/share/wazuh-indexer/jdk; bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p "<pw>"'`.
- ⚠️ 이 배포에서 검증된 함정 3가지 (4명 독립 리뷰 + 실컨테이너 확인):
  1. `internal_users.yml`·`config/wazuh_dashboard/wazuh.yml`은 **단일파일 bind mount** → `sed -i`/에디터 저장은 inode를 바꿔 **실행 중 컨테이너가 옛 파일을 계속 봄**(securityadmin이 옛 해시를 "성공" 재적용하는 무증상 실패). 반드시 `cat new > file`로 같은 inode에 덮어쓰고, 컨테이너 안에서 `grep`으로 새 값 확인 후 진행.
  2. 대시보드의 API 비번은 **env(`API_PASSWORD`)로 안 바뀜** — `/wazuh_app_config.sh`가 마커 `1513629884013`이 있으면 건너뜀. `config/wazuh_dashboard/wazuh.yml`의 `password:`를 직접 수정해야 함(아니면 UI만 401, curl 검증은 통과하는 무증상 실패).
  3. `securityadmin -cd`는 **보안설정 전부를 덮어써** UI/REST로 만든 사용자·롤을 지움 → `-f <internal_users.yml> -t internalusers`로 내부사용자만 적용하고, 먼저 `-backup`으로 라이브 상태를 덤프.
- 순서: 파일 편집(compose·wazuh.yml·internal_users) → securityadmin(-f) → **새 비번 200/옛 비번 401 게이트** → `docker compose up -d`(env 변경분 재생성; `restart`는 env를 안 읽음) → filebeat test·API 토큰·대시보드 실제 로그인·데모계정 401 검증.

## MCP Server (자격증명 보유 — A안)
- 읽기 서버: `gbrigandi/mcp-server-wazuh`(MIT, 읽기전용, 코드리뷰 완료 @969f36f)를 2026-09-26 B `/opt/mcp/`에 오프라인 배포했다. Wazuh API :55000 + Indexer :9200에 **읽기전용 계정**으로 접속하며 자격증명은 B `/etc/mcp/wazuh-ro.env`에 둔다. 읽기 14툴 계약 테스트와 Hermes 컨테이너 연결을 9/28까지 검증했다.
- 응답 서버는 A의 별도 MCP/Policy Engine이며 `block_ip`/`unblock_ip`/`list_blocks`→nftables `agent_block` 경로가 9/28 승인→차단 E2E까지 검증됐다. `isolate_host`는 후속 목표다. Hermes는 B의 별도 계정·컨테이너에서 실행하고 MCP 자격증명은 갖지 않는다.
- 승인형 로컬 룰 변경은 기존 읽기 MCP 권한을 올리지 않고 B 승인 브로커와 A/B의 별도 `rulechg` 계정·root helper로 처리한다. B에서는 Wazuh `local_rules.xml`만 변경 대상으로 허용한다. 10/08 HMAC health·대상 읽기 조회는 통과했으며 실제 승인→적용은 미검증이다.
- 참고 데이터: CISA KEV `~/capstone/kev/kev.json` (`kev-data.md`).

## 검증 체크리스트
- [x] Dashboard 접속, Server API/Indexer 응답 (2026-09-26)
- [x] Groot_A/C Agent 등록·Active (manager `10.200.10.10:1514`, 2026-10-06 기록)
- [ ] 신규 FW 프리픽스·WAF GROOT 룰·IPS 로컬 SID의 기존 디코더/룰 분류 여부 확인 → 빠진 항목만 추가 → VM 세그먼트 공격 프로브로 경보 실발화 검증
- [ ] Vulnerability Detection에서 Groot_C의 CVE-2021-3156 매핑 확인
- [x] MCP 읽기 14툴 호출 성공, Hermes 프로세스에 MCP 자격증명 없음 확인(2026-09-28 기록). 이번 SSH에서는 이 계약 테스트를 재실행하지 않았다.
- [x] 승인형 룰 변경 브로커·A/B 변경기와 Hermes `rule-a`·`rule-b` 배포, HMAC·읽기 조회 확인(2026-10-08). 운영 룰 해시는 그대로.
- [ ] 지정 승인자의 Mattermost 버튼 클릭→Wazuh 로컬 룰 적용·복구 E2E 검증.
