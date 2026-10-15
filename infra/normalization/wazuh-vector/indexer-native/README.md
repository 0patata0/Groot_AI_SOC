# 2026-10-14 — actions 없는 native monitor 구현·운영 관찰

## 현재 운영본 — 시간창 v2 (2026-10-14 19:38 KST)

기존 monitor `-HYdN6EBERDGWPLCrWpE`를 같은 ID/권한/enabled/주기/actions0으로 v2 갱신했다. 현재 관리는 [window-v2/OPERATIONS.md](window-v2/OPERATIONS.md)의 v1/v2 고정 registry helper를 사용한다. 아래 v1 원본·명령·60초 고정 검색창은 이전 시점의 이력이며 v1 helper는 v2 state를 거절한다.

최근300초 후보와360초 processing 창에서 정확한60초 sliding·마이크로초 경계·고유 identity를 검사한다. [계약](window-v2/README.md) · [native41사례/4단계](window-v2/native-validation-2026-10-14.json) · [응답guard66](window-v2/guard-validation-2026-10-14.json) · [운영배포/관찰](window-v2/deployment-2026-10-14.json). 조건부지연완화이며 장기장애 복구/영속중복제거/외부통지는 추가하지 않았다.

[monitor.json](monitor.json)은 기존 OpenSearch 2.19.6/Alerting 2.19.6.0용 **기본 비활성화(`enabled=false`) 배포 원본**이다. 2026-10-14 06:21 KST에 동일 원본으로 생성한 운영 monitor 한 개를 활성화했고, 아래의 두 주기 관찰과 별도 수동 조회를 완료했다. 입력은 전용 evidence의 `agent.id=001`, 정확한 location, `indexer-observation-v1` marker, source별 Wazuh leaf `100261/100262`로 한정한다. 원래 raw/ready 규칙과 별도의 경로이며, Wazuh leaf level 3과 Indexer trigger severity `5`는 서로 다른 척도다. 두 trigger 모두 `actions=[]`라 채팅·메일·차단 작업을 수행하지 않는다. 새 역할·계정·패키지·매핑을 요구하지 않는다.

## 06:21~06:25 KST 운영 연결 완료

[운영 결과 JSON](monitor-deployment-2026-10-14.json)에 생성·복구·활성화·반복 무변경과 증거 SHA를 기록했다. 정확한 이름의 monitor는 **1개**, ID는 `-HYdN6EBERDGWPLCrWpE`이며 최종 `enabled=true`, 두 trigger `actions=[]`다. 후보 query/Painless는 앞서 native 시험을 통과한 SHA 그대로다.

- scheduler의 실제 실행 시각 **06:22:25.196, 06:23:25.196 KST**를 각각 관찰했다. 두 시점 `running_on_time=true`, 해당 monitor 내부 alert는 0건이었다. scheduler 시각만으로 검색 성공이나 원격 수신 ACK를 주장하지 않는다.
- 그 뒤 **별도로 실행한 수동 dryrun**은 54/54 shard 성공, 적격 문서 1건·서비스 1개, match=false/unavailable=false였다. timeout·조기 종료·입력/trigger 오류·action은 0이었다. 이것을 두 실제 주기의 상세 검색 응답이라고 기록하지 않는다.
- 06:25 재실행은 `changed=false`였고 root state 바이트도 그대로였다. 실제 장비 간 조건의 운영 발화는 관찰하지 않았다. 장비 간/고유 5개/한도 초과의 판정 근거는 앞서 분리한 native 합성 시험이며, 운영 자료 1건만으로 그 시나리오 전체가 재현됐다고 보지 않는다.

첫 적용에서는 설정 인덱스 미존재 404 wrapper 차이와 GET의 stdin 상속을 보완했다. 첫 활성화는 서버에서 성공했지만 플러그인이 `schema_version`을 0→8로 바꾸어 엄격한 해시 검사에서 중단됐다. **정확한 같은 ID를 CAS로 비활성화한 뒤** 원인을 조사했다. 현재 본문의 schema만 8→0으로 돌렸을 때 최초 config SHA가 정확히 재현됐고, 공식 [UPDATE 코드](https://github.com/opensearch-project/alerting/blob/2.19.6.0/alerting/src/main/kotlin/org/opensearch/alerting/transport/TransportIndexMonitorAction.kt#L687)와 일치했다. 이 전이 하나만 좁게 허용하고 다른 모든 config 값의 동일성을 유지하도록 보완한 후 재활성화했다. 실패·복구 증거도 보존했다.

B의 영구 증거는 `/opt/capstone-automation/project/evidence/indexer-20261014/`에 있고, 실제 최종 source 5개와 manifest는 그 아래 `monitor-source/`에 있다. source 디렉터리는 root 0700, source/증거/state 파일은 root 0600이다. 최종 helper SHA는 `0318e0ab4231b32de9624466b19bb07c6324ae6277311d5bf528460a774d6f80`이다. 새 계정·권한·알림 목적지·차단을 추가하거나 기존 Wazuh 이벤트 매핑을 변경하지 않았다. 플러그인 자체의 설정·경보 인덱스 초기화는 native API의 내부 동작 범위다.

## 후보의 정확한 판정

- `observation_match`: 한 sensor와 서비스 방향에서 **동일 source의 서로 다른 stable key가 5개 이상**, 또는 Suricata와 nftables가 각각 하나 이상일 때 참이다. 상이한 두 source 관측이 같은 패킷이라는 뜻은 아니다. 서비스 키는 source port를 포함하지 않는 기존 `directional-service-v1` 계약을 따른다.
- `observation_unavailable`: 시간·응답 완결성·집계 한도를 검증하지 못하면 참이다. 정상 빈 검색은 match=false/unavailable=false이지만, 이것이 A→Wazuh→Filebeat 수집 정상이나 이벤트 유실 0을 증명하지는 않는다.
- 사건 시각은 keyword를 native Painless로 parse하여 **평가 periodEnd의 최근 60초**에 제한한다. 추가로 Wazuh 처리 `timestamp`는 검색 현재 시각의 최근 120초다. trigger에서는 `new Date().getTime()`과 `ctx.periodEnd.toEpochMilli()`를 비교해 **평가 종료 시각이 현재보다 15초 넘게 늦거나 5초 넘게 미래면 보류**한다. 시간 계산 해상도는 밀리초다. B 설치본에서 이 두 API를 사용하는 native probe는 성공했으며, 이 후보 전체의 native 검증은 아래 후속 결과를 따른다.
- 검색은 `size=0`, `_source=false`, timeout 10초, `terminate_after=10001`, 실제 `terms` 집계다. 판정은 **총 문서 ≤10,000, 성공 shard ≤64, 서비스 ≤100**, exact total `eq`, timeout·부분 실패·조기 종료 없음, 서비스 bucket 누락 없음에 한정한다. `terminate_after`는 shard별 한도이며 전체 CPU/읽기 문서 수를 10,000으로 제한하는 기능이 아니다. trigger의 shard 한도도 이미 수행한 검색 비용을 소급 제한하지 않는다.
- 서비스는 101개까지, source는 3개까지 받아 한도/예상 밖 source를 식별한다. stable key는 source별 실제 bucket 5개만으로 `>=5`를 증명한다. source key의 `sum_other_doc_count>0`은 여섯 번째 이후 키가 생략됐다는 뜻일 수 있어 정상이다. 전체 고유 수를 근사 `cardinality`로 판단하거나 5보다 큰 정확한 개수로 보고하지 않는다.
- 필수 필드에 distinct docvalue가 1개인지 검사하지만 원본 JSON scalar 여부는 증명하지 않는다. keyword 배열 `["x","x"]`는 중복 제거 후 docvalue 1개일 수 있다. 실제 JSON 타입·빈 quality 배열 검증은 root 관리 Vector 분기와 검증한 Wazuh evidence leaf가 담당한다. 품질 배열의 Indexer 표현을 가정한 `exists` 부정 조건은 넣지 않았다.

두 trigger의 검증 함수는 동일하며 [match](monitor-match.painless)와 [unavailable](monitor-unavailable.painless) 소스, [query](monitor-query.painless) 소스를 JSON 본문에 그대로 넣었다. 오프라인 [정책·파일 결속 검사](../tests/test_indexer_monitor_contract.py) **7개가 통과**했다. 이것은 Painless 실행·성능·종단 수신 검증이 아니다. 각 trigger가 시간을 별도로 읽으므로 허용 지연 경계를 통과하는 순간에는 두 상태를 원자적 한 쌍으로 해석하지 않는다.

## 05:45~05:47 KST 설치본 native 검증 완료

[실측 결과 JSON](monitor-validation-2026-10-14.json)에 production query 컴파일, 격리 query **38개**, 동일 production 검증 함수의 합성 context 실행 **23개**를 구분해 기록했다. 운영 검색 dryrun은 **54/54 shard 성공, hits 0, 두 trigger false, 오류·action 0**이었다. 임시 index에서는 index 대상만 치환한 동일 monitor 본문으로 고유 2/5/6개, 재전송 20행, 장비 간/다른 서비스, stale/future, 잘못된 출처·키·tuple·보호주소 제외를 통과했다. 100서비스·10,000문서는 허용하고 101서비스·10,001문서는 보류했다.

첫 시험은 fixture index의 자동 날짜 감지를 끄지 않아 합성 5건이 모두 제외되어 즉시 중단했다. 후보 monitor는 수정하지 않고 fixture에 `date_detection=false`를 명시한 뒤 재실행했으며, `event_time_kst`/destination_port/rule.id의 keyword와 timestamp의 date를 field_caps로 확인했다. 첫 실패 원인의 옛 mapping 자체는 삭제 전에 조회하지 않았으므로 직접 확인한 사실과 이 진단을 구분한다. 실패 index와 재시험 index 모두 삭제 acknowledged/HEAD 404를 확인했다.

실제 검색 시험은 임시 **1 shard**에서 수행했다. 64/65 shard, timeout·실패 shard·조기 종료·잘못된 합계·오래된 periodEnd의 거절은 원본 검증 함수에 합성 context를 전달해 실제 Painless로 실행한 증거다. 운영 shard 장애를 만들거나 scheduler를 과거로 재실행한 시험이 아니다. 시간 경계는 실행 중 clock read 간격 때문에 경계 안팎 **100ms 여유**를 두고 검증했다. 동일 값을 반복한 keyword 배열은 한 docvalue로 수용된다는 한계도 실제 확인했다.

100/101서비스 및 10,000/10,001문서 전후, 생성 전의 **9회 부하 점검 모두 write active/queue=0, search queue=0**이었다. 이는 표본 시점의 상태이며 전체 시험 중 생산 부하가 전혀 없었다는 보장은 아니다. 저장된 운영 monitor·생산 경보 문서·알림 action은 추가하지 않았다. 검증 후보 monitor SHA-256은 `f0262be494e605edcb22fb32f71f4854014dd4f671b035803886a5b1036bafd1`이다.

## 분리된 운영자 배포 실행기

[deploy-monitor-b.py](deploy-monitor-b.py)는 B의 기존 Python 표준 라이브러리·Docker·컨테이너 내부 curl/관리자 인증서만 사용하는 **일회성 root 운영자 명령**이다. 상시서비스나 MCP 도구가 아니며 LLM 권한에 추가하지 않는다. machine-id, 고정 monitor 이름, 동봉한 `monitor.json`의 위 SHA-256을 검사하고 임의 API 경로·후보 JSON·컨테이너를 인자로 받지 않는다. 인증서 본문과 검색 원문은 출력·반출하지 않는다.

운영자는 실제 evidence leaf level 3의 색인·`no_full_log`·SOC 비통지 확인 뒤 아래 명령을 **각각 별도 단계로** 실행한다. 실제 저장·활성화·검증은 앞 절의 완료 결과를 따른다. 아래 명령은 단계별 운영 절차이며 활성화 단계를 무조건 반복 적용한다는 뜻이 아니다.

```sh
python3 -B deploy-monitor-b.py inspect
python3 -B deploy-monitor-b.py create-disabled
# disabled readback와 evidence 색인 확인 후 별도 조율한 단계에서만 실행
python3 -B deploy-monitor-b.py enable
python3 -B deploy-monitor-b.py observe
# 동일 설정의 검증된 운영 monitor만 비활성화하는 복구 명령
python3 -B deploy-monitor-b.py disable
```

- `inspect`/`observe`는 state 파일이나 monitor를 바꾸지 않는다. 생성 전후 정확한 이름 일치 여부를 확인한다. 이름 검색이 100건을 넘거나 응답이 부분적이면 보류한다. API가 이름의 원자적 유일성을 보장하지 않으므로 다른 관리자와의 동시 생성까지 전역 lock으로 보장하지는 않는다. 정확한 이름이 이미 있으나 이 실행기가 소유한 state가 없으면 자동 채택·덮어쓰기를 거절한다.
- `create-disabled`는 root 전용 `/var/lib/capstone-automation/indexer-observation/`에 생성 의도를 먼저 fsync한다. POST가 반환한 ID·`_seq_no`·`_primary_term`과 **서버가 기본값을 정규화한 monitor 본문 전체 해시**를 독립 GET과 대조한다. 처음 POST와 같은 revision이라는 사실로 정규화 결과를 고정하며, query·스크립트·params·집계를 후보와 다시 대조하고, 설치 버전의 알려진 JSON 기본값만 좁게 정규화한다. 알 수 없는 필드와 다른 집계 종류는 거절한다. 첫 생성 응답을 잃으면 재생성하지 않고 pending 상태로 남긴다. 설치본의 설정 인덱스 미존재 404는 Alerting 예외로 감싸져 있어, 내부 `IndexNotFoundException`과 정확한 `.opendistro-alerting-config` 문자열이 일치하는 경우만 빈 이름 검색으로 수용한다. 알려진 ID는 readback 실패 전에도 기록한다.
- `enable`/`disable`은 마지막으로 검증한 ID·본문 해시·CAS revision이 그대로일 때만 실행한다. query·사용자·서버 기본값을 포함한 설정을 그대로 보내고 enabled와 API lifecycle 시각만 바뀌도록 검증한다. 설치본의 첫 UPDATE가 `schema_version=0`을 `8`로 바꾸는 동작만 예외로 허용하며, 이 값을 다시 0으로 돌린 나머지 전체 config 해시가 이전 값과 정확히 같아야 한다. 다른 schema 전이·권한·query·action 변경은 거절한다. 두 trigger의 severity `5`와 `actions=[]`를 다시 확인한다. 서버 응답과 독립 GET이 다르거나 CAS가 실패하면 자동 재시도하지 않는다. **활성화 요청의 응답 유실은 실제 enabled 여부가 불확실할 수 있으므로**, `inspect`로 관측 상태를 확인하고 운영자가 해당 ID를 조사해야 한다. pending 파일을 지워 새 monitor를 만드는 복구는 금지한다.
- `observe`는 해당 ID의 scheduler `last_execution_time`과 `running_on_time`만 반환한다. 활성화 후 서로 다른 두 실행 시각을 관찰하되, 이 지표만으로 검색 성공·알림 delivery·사건 종결을 증명하지 않는다. 실제 query 응답의 guard 상태·내부 ERROR/관찰 경보와 함께 확인한다. 1분 주기, 15초 지연 보류, actions 없음이라는 계약을 유지한다.

[배포 상태 전이 fixture](../tests/test_indexer_monitor_deployment.py) **23개**와 기존 정책 검사 **7개**, 합계 **30개가 통과**했다. 이는 mock API의 의도 저장·중복 거절·응답 유실·CAS·GET 대조 검사다. 실제 생성/활성화 API와 서버 기본값 직렬화 확인은 앞 절의 운영 증거로 별도 기록한다. 공식 [Alerting API](https://docs.opensearch.org/2.19/observing-your-data/alerting/api/)의 revision 조건을 사용한다. 설치본과 같은 tag의 [RestIndexMonitorAction](https://github.com/opensearch-project/alerting/blob/2.19.6.0/alerting/src/main/kotlin/org/opensearch/alerting/resthandler/RestIndexMonitorAction.kt#L148)에서 저장 기본 refresh가 `IMMEDIATE`임을 확인했다.

## 검증·운영 적용 이력

1. **완료:** 기존 evidence 검색을 입력으로 하는 disabled inline dryrun에서 후보 전체의 native compile과 결과 형식을 확인했다. 이 API에는 monitor 본문 자체를 보내며 `{"monitor": ...}`로 감싸지 않는다. 기존 운영 monitor의 저장/활성화 API를 호출하지 않는다.
2. **완료:** [격리 시험 명세](monitor-native-tests.json)의 run-id 전용 임시 index 한 개에 합성 메타데이터만 넣어 순차 검증했다. timestamp만 date, query에서 쓰는 필드는 keyword로 명시한다. **index 대상만 정확 임시 이름으로 바꾼 동일 query/trigger**로 중복 2/고유 5·6/교차 source/다른 서비스/과거·미래·누락·오형식·보호주소/100·101 서비스/10,000·10,001 문서를 검증한다. 운영 evidence 파일·wazuh-alerts index에는 시험 문서를 쓰지 않는다.
3. **완료:** 실제 장애를 만들지 않고, 동일 production 검증 함수에 합성 response context를 주는 별도 native trigger 시험으로 timeout·shard·조기 종료·숫자/구조 오류·오래된 periodEnd를 확인했다. 이는 검증 함수 시험이며 실제 shard 실패 복구나 실제 지연 스케줄 재현으로 기록하지 않는다. production 후보에는 test hook을 추가하지 않는다.
4. **완료:** 임시 index를 삭제했고 실제 evidence leaf의 level 3·`no_full_log`·같은 식별자 색인과 기존 SOC 최소 등급 5의 비통지를 별도 evidence 배포에서 확인했다. 운영 monitor 저장·활성화와 두 scheduler 시각 관찰은 앞 절과 같다. 실제 장비 간 발화·외부 통지·차단 승격은 이번 완료 범위에 포함하지 않는다.

inline dryrun도 완전한 읽기 전용 API는 아니다. 공식 runner는 dryrun 분기 전에 alert/history index 초기화를 수행할 수 있으며 마지막 alert 저장만 생략한다. 저장 monitor는 query-level이라 서비스마다 독립 사건을 만들지 않는다. false 판정은 기존 ACTIVE를 COMPLETED로 바꿀 수 있으므로 **공격 종결 증거로 해석하지 않는다**. 실행 오류는 플러그인의 ERROR 경보가 될 수 있고 actions 없는 상태에서도 내부 경보 메타데이터는 생길 수 있다. 지연 색인·창 밖 재전송·이전 boot·전역 정확히 한 번·통지 cooldown·영속 수신 ACK는 이 계약에 포함되지 않는다.

## 설치 버전과 대조한 근거

- [OpenSearch 2.19.6 Painless Date 허용 목록](https://github.com/opensearch-project/OpenSearch/blob/2.19.6/modules/lang-painless/src/main/resources/org/opensearch/painless/spi/java.util.txt#L607): 인자 없는 Date 생성자와 getTime 허용. Instant.now는 해당 Instant 허용 목록에 없다.
- [Alerting 2.19.6.0 trigger context](https://github.com/opensearch-project/alerting/blob/2.19.6.0/alerting/src/main/kotlin/org/opensearch/alerting/script/TriggerExecutionContext.kt): periodEnd는 Instant다.
- [TriggerService](https://github.com/opensearch-project/alerting/blob/2.19.6.0/alerting/src/main/kotlin/org/opensearch/alerting/TriggerService.kt), [AlertService](https://github.com/opensearch-project/alerting/blob/2.19.6.0/alerting/src/main/kotlin/org/opensearch/alerting/AlertService.kt), [QueryLevelMonitorRunner](https://github.com/opensearch-project/alerting/blob/2.19.6.0/alerting/src/main/kotlin/org/opensearch/alerting/QueryLevelMonitorRunner.kt): 오류/COMPLETED 상태와 dryrun의 저장 경계.
- [Lucene SortedSetDocValues](https://lucene.apache.org/core/9_12_1/core/org/apache/lucene/index/SortedSetDocValues.html): 문서 내부 값의 중복 제거. [OpenSearch keyword mapper](https://github.com/opensearch-project/OpenSearch/blob/2.19.6/server/src/main/java/org/opensearch/index/mapper/KeywordFieldMapper.java)는 이 타입을 사용한다.
- [Alerting 보안](https://docs.opensearch.org/2.19/observing-your-data/alerting/security/): 생성/수정자 권한으로 실행하며 별도 monitor/alert metadata는 원 index의 DLS/FLS와 보호 경계가 다를 수 있다. 고정 관리자 관리와 최소 집계 응답을 유지한다.

아래는 이 후보 작성 이전의 읽기 검증과 당시 운영 상태를 보존한 기록이다. 아래 `미구현/미배포` 문장은 해당 검증 시점을 가리킨다.

---

# 기존 Indexer 상관분석 경로 — 2026-10-14 읽기 검증

**새 도구나 Python 상시서비스 없이, 기존 Indexer가 최종 조회 시점의 사건 시각과 고유 사건 집합을 검사할 수 있다.** 다만 운영 정제 입력은 아직 `no_log`라 색인되지 않는다. 아래 최소 전환을 거쳐야 장비 간 상관에 쓸 수 있다. 이번에는 검색만 실행했으며 규칙·매핑·인덱스·monitor·알림을 만들거나 변경하지 않았다. [실측 JSON](validation-2026-10-14.json)은 원문·주소별 상세를 포함하지 않는다.

## 설치 상태와 현재 자료

- B의 실제 OpenSearch node는 **2.19.6**, Alerting과 Job Scheduler는 **2.19.6.0**이다. 루트 API의 `7.10.2` 표기는 호환 표기이므로 실제 node 버전과 구별한다.
- 관리자 인증서는 이미 Indexer 컨테이너에 마운트되어 있었다. 인증서 내용을 출력·반출하지 않고 컨테이너 내부 curl의 읽기 조회에만 사용했다. 기존 제한 계정은 `_search`와 `_field_caps`를 허용하지만 node metadata/monitor 검색은 403이다. 권한은 바꾸지 않았다.
- 관리자 monitor 검색은 404와 `.opendistro-alerting-config` 미존재를 반환했다. 플러그인 미설치가 아니라 저장된 monitor 설정 인덱스가 아직 없는 상태다.
- 첫 24시간 조회는 전체 2,817건, raw Suricata 57건, raw WAF 5건, 정제 2건이었다. 후속 조회에서 Suricata는 58건으로 증가했으며 모두 원천 시각·flow ID·서비스 방향 필드를 가졌다. 이 중 27건은 보호주소 `.110/.111` 관련이었다. 두 정제 문서는 이전의 별도 canary이고 운영 ready 자료가 아니다.
- `data.timestamp`는 date, 정제 `event_time_kst`와 stable key는 keyword, `full_log`는 text다. 기존 nftables 낮은 등급 원시 관측은 기본 색인 임계 미만이라, 해당 조회에서는 nftables 상관 재료가 없었다.

## 실제 실행한 native 조회

기존 canary 두 문서만 골라 Painless의 `ZonedDateTime.parse`로 keyword 사건 시각을 읽고 exact `terms`로 집계했다. 두 문서 모두 처리되었고, 현재 시각의 최근 120초 조건으로 바꾸면 **0건**이었다. 이전에 붙인 `fresh` 값을 그대로 믿지 않고 최종 조회에서 오래된 사건을 제외할 수 있음을 확인했다. 매핑 변경은 필요하지 않았다.

raw Suricata에서는 agent `001`, 정확한 EVE location, `source=suricata`, `event_type=alert`, date형 원천 시각을 묶고 출발지·목적지 양쪽의 `211.170.162.110/111`을 제외했다. 24시간 진단 조회는 31문서·2서비스였고, 한 서비스의 29문서에는 서로 다른 `full_log` 내용이 5개 이상 있었다. 다른 2문서 중 하나에는 `full_log`가 없었다. 같은 검색을 최근 120초로 제한하면 **0건**이었다. 54개 shard가 모두 성공하고 timeout은 없었다.

[raw-suricata-60s.json](raw-suricata-60s.json)은 같은 조회를 최근 60초로 좁힌 읽기 전용 후보다. 24시간 결과가 60초 임계 충족을 뜻하지 않는다. 이 후보의 사건 동일성은 **색인된 `full_log` 문자열 전체의 동일성**이다. 같은 문자열을 다시 넣으면 같은 bucket이고, 서로 다른 원문 내용만 별도 bucket이다. `flow_id`는 흐름 ID이며 Wazuh `id`는 재처리마다 달라질 수 있어 고유 사건 ID로 쓰지 않는다. 서로 다른 JSON 렌더링까지 같은 사건이라고 판단하는 의미상의 정규화는 이 후보가 제공하지 않는다.

raw 후보는 즉시 자동 monitor로 배포하지 않는다. source 문자열 집계 비용, 원문이 내부 검색 응답의 bucket key가 되는 점, `full_log` 누락 때문에 정제 stable key 경로가 더 적합하다. 원문 응답은 B root 전용 임시파일에서만 처리 후 삭제했고 사용자 출력·저장 증거는 건수뿐이다. composite 응답의 `after_key`는 마지막 짧은 페이지에도 있었으므로, 이것만으로 추가 자료가 있다고 단정하거나 완료를 선언하지 않는다. 자동화 전에는 고정 시각창·최대 페이지/그룹 수·마지막 빈 페이지 또는 동등한 완결 조건이 필요하다.

## 최소 운영 전환안

1. 기존 ready와 `100200` 이하 shadow `no_log`는 유지한다. 적격 Suricata/nftables 자료만 별도의 root 관리 evidence 경로로 내보내고, 그 정확한 location 전용 **독립 leaf level 3 + `no_full_log` + `no_email_alert`**로 색인한다. 현재 no_log 부모만 level 3으로 바꾸면 빈도·장비 간 shadow 자식이 최종 매칭된 행은 여전히 사라질 수 있으므로 그 방식은 사용하지 않는다. 새 출력 경로의 용량·회전·Wazuh 재개 경계도 기존 저장 관리에 포함해야 한다. 원래 raw 경보와 차단은 그대로 둔다.
2. evidence에는 sensor/source/schema/pipeline, 방향 tuple, event_time, stable64 key, 품질·보호주소 판정을 유지한다. 정확 agent와 location을 조회에 다시 요구한다. `.110/.111`은 출발지와 목적지 모두 제외한다. 이는 현재 상관 정책의 보호주소이며, 차단 helper의 더 넓은 관리망·세션 보호 정책을 대체하지 않는다.
3. 조회마다 현재 시각에 사건 시각을 다시 비교한다. 현재 keyword 매핑은 검증된 Painless parse로 시작할 수 있다. 검색 대상·시간·문서 수를 제한하고, 향후 충분한 자료량에서는 신규 전용 date 필드/매핑의 효과를 별도 검토한다. 기존 keyword 필드를 제자리에서 date로 바꾸지 않는다.
4. 첫 자동화는 **actions 없는 native monitor 관찰**이다. 검색 증거와 적격 건수·과거 재전송 제외를 먼저 확인하고, 실제 경보·채팅 승격은 별도 단계다. Indexer monitor alert는 Wazuh manager rule alert와 다른 저장·전달 경로이므로 SOC bot이 자동으로 읽는다고 가정하지 않는다.

다음 운영 단계의 정확한 변경 대상은 아래처럼 한정한다. **아래 경로와 ID는 후보이며 이번에 생성·예약을 운영에 반영한 것은 아니다.**

| 대상 | 다음 단계의 최소 변경 |
|---|---|
| `vector/vector.toml` | 기존 correlation 출력 중 적격 Suricata/nftables만 별도 native filter→file sink. 원래 ready 경로는 유지 |
| `/var/log/capstone-vector/evidence/normalized.jsonl` | root 관리 전용 evidence 파일. 자동 block/chat 입력으로 직접 연결하지 않음 |
| Vector maintenance/logrotate + Ansible vector role | evidence 권한·디렉터리·크기/보존·논리 EOF 확인을 기존 출력 관리와 함께 검사 |
| `wazuh-vector/apply-a.yml`의 전용 localfile 관리 | 정확 evidence 경로 1개를 JSON 입력으로 추가하고 기존 raw/ready 수집 유지 |
| `capstone_vector_rules.xml` 후보 ID `100260` | 정확 location/schema/pipeline/sensor를 확인하는 level 1/no_log evidence 전용 기초 |
| 후보 ID `100261`, `100262` | 각각 적격 Suricata와 nftables의 독립 leaf level 3, `no_full_log`, `no_email_alert`; 100210/211 shadow와 location으로 분리 |
| B 기존 Indexer | evidence 읽기 검증 후에만 actions 없는 monitor 설정. 현재 매핑 변경 불필요; 기존 제한 계정에 임의 관리자 권한 추가 금지 |

[evidence-60s.template.json](evidence-60s.template.json)은 자격증명·원문·monitor 생성 요청이 없는 재사용 가능한 `_search` 본문이다. `lower=upper=0` 기본값으로는 승인 가능한 시간창이 없다. 호출자는 마지막 script params의 `upper=T`, `lower=T-60000`을 같은 평가시각의 epoch ms 정수로 채우고, `_search?allow_partial_search_results=false`로 조회한다. 날짜 parse 동작 자체는 실제 canary에서 검증했으나 **새 evidence location/전체 template의 운영 자료 시험은 미실시**다. 향후 monitor에서는 실제 평가 시각을 직접 사용하는 동등한 조건을 확인하고, 과거 `period_end` 재실행이 현재 사건처럼 통과하지 않도록 추가 현재시각 범위와 비교한다.

반드시 통과할 후속 시험은 다음과 같다.

- 전용 leaf의 정확 location·agent·schema·source·보호주소·품질·포트·프로토콜 거절, 원래 43개 Wazuh 시나리오와 raw 룰 SHA 보존.
- `A,A,A,A,B`는 unique 2, `A,B,C,D,E`는 5, 서로 다른 source의 같은 서비스만 교차 조건 충족. 중복 문서의 별도 Indexer ID에도 stable key 집합은 불변.
- 예전 fresh 표기 재전송, 미래 시각, 날짜 parse 실패, key 누락/배열/형식 오류는 제외. 과거 자료 재생은 별도 조회에서만 보임.
- 100/101개 서비스, 10,000/10,001건 등 운영에서 정한 한도의 경계와 응답 크기 초과, shard 실패, timeout은 판정 보류. 예시 template은 최대 101개 서비스·각 5개 key만 반환한다. 호출/trigger는 `hits.total.relation=eq`, 총 문서 ≤10,000, 서비스 ≤100, `sum_other_doc_count=0`, failed shard 0, timeout false를 모두 확인해야 한다. 한도 값은 성능 측정 후 고정하며 이 문서 수를 측정된 처리능력으로 해석하지 않는다.
- 정제 사건→evidence 파일→Wazuh leaf→Indexer의 같은 event ID/내용 필드, 로그 회전·재시작·큐 지연 후 수신과 용량 정책, 신규 level 3이 SOC 최소 등급 5 채팅으로 전달되지 않는지 검증.
- 마지막으로 actions 없는 monitor에서 연속 임계 유지·복귀·다시 충족·프로세스 재시작을 관찰한다. 이 단계는 통지 정확히 한 번 검증이 아니다.

## 유한 범위의 정확한 판정 계약

- 예시 정책은 평가 시각 T의 **최근 60초** `[T-60s,T]`에 동일 sensor/서비스 방향의 stable key가 5개 이상일 때다. upstream 120초 신선도 조건은 이 최종 60초 조건을 대체하지 않는다. 1분 평가라면 모든 가능한 연속 60초창을 검사한다는 약속은 하지 않으며, 지연 허용창과 평가 주기는 관찰 후 고정한다. 과거 재생 자료는 별도 집계하고 실시간 승격에 섞지 않는다.
- 개수는 근사 `cardinality`가 아니라 실제 stable key `terms` bucket을 쓴다. `size=5`에서 서로 다른 실제 key 5개가 있으면 `>=5` 임계를 증명한다. 5보다 큰 정확한 전체 개수는 주장하지 않는다. 문서 중복이 같은 key bucket의 doc_count만 늘려도 임계는 증가하지 않는다.
- 서비스 그룹은 최대 100개 등 명시적 한도를 두고 101개 검출 또는 누락·pagination 미완료 시 자동 결정을 보류한다. HTTP 실패, timeout, 실패 shard, 누락된 필수 필드, 잘못된 날짜, 무효 stable key, 보호주소는 정상 판정으로 통과시키지 않는다. `allow_partial_search_results=false`와 응답 검사를 함께 사용한다.
- 장비 간 판정은 같은 서비스 방향에 실제 Suricata와 nftables source bucket이 각각 존재할 때만 가능하다. 서로 다른 두 source 관측이 같은 패킷이라는 보장은 하지 않는다. 현재 정제 자료가 색인되지 않아 이 조건의 운영 검증은 아직 남았다.
- bucket별 active alert의 지속 상태와 `NEW` 전용 action은 반복 통지를 줄일 수 있다. action throttle 15분은 **통지 빈도 제한**이며 사건 중복 제거·전역 정확히 한 번 보장이 아니다. 정상 복귀 후 새 alert, monitor 재생성, 장애·재시작 경계는 관찰 시험에 포함한다. 현재는 action이 없고 cooldown을 운영 설정하지 않았다.

## 근거

- [OpenSearch 2.19 Alerting API](https://docs.opensearch.org/2.19/observing-your-data/alerting/api/): monitor 종류, 저장 API, action throttle.
- [Per query/bucket monitors](https://docs.opensearch.org/2.19/observing-your-data/alerting/per-query-bucket-monitors/): 주기·`period_end` 기반 범위와 query/bucket 단위.
- [Triggers](https://docs.opensearch.org/2.19/observing-your-data/alerting/triggers/): query 결과 스크립트, NEW/DEDUPED/COMPLETED 상태. monitor 생성자의 권한과 출력 내용 범위를 별도로 관리해야 한다.
- [Terms](https://docs.opensearch.org/2.19/aggregations/bucket/terms/): 실제 고유값 bucket과 상위 bucket 누락/문서 수 오차.
- [Cardinality](https://docs.opensearch.org/2.19/aggregations/metric/cardinality/): 고유값 수의 근사 집계이므로 위 정확 임계 계약에는 쓰지 않는다.

플러그인 설치·기존 자료량·매핑·스크립트 실행 수치는 위 공식 문서에서 추정한 값이 아니라 2026-10-14 B의 읽기 실측이다. monitor lifecycle과 evidence 운영 전달은 아직 배포·시험하지 않았다.
