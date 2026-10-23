# 보안 이벤트 정규화 — Vector 운영 경로와 이전 검증

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../STATUS.md) · [실행 계획](../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

> 2026-10-15 05:00 최신: WAF 새CID6c72d5a5…·호스트bind·로그인계·양가드를 검증했다. 원본상태는 Suricata gen1/rev6·WAF gen4/rev13, Vector2627991·Wazuh1909632 실행이다. 원본/출력점검timer를5분주기의0·1·3분으로분산해자연실행exit0를모두확인했다. Hermes단계와마지막인증서감시까지완료했으며관리범위·LLM권한은확대하지않았다. [현재WAF실측·정리](../groot-a/imperva-exception/recreation-validation-2026-10-15.json). 아래는 각 시점의 이력이다.

## 2026-10-15 02:15 KST 최신 상태 — 3단계 운영 검증·타이머 활성화 완료

**02:15:39 KST 원본 회전 운영 전환과 자동 실행 확인을 완료했다.** Suricata·WAF 원본 타이머 두 개의 첫 실행은 회전 불필요(`not_due`)로 정상 완료됐고, 출력 유지관리의 정상 daily 실행에서는 ready·evidence·telemetry 세 파일을 회전했다. 빈 quarantine은 유지했다. 이어 유지관리 타이머만 다시 활성화해 첫 실행 `not_due`·추가 회전 0회를 확인했다. 세 타이머 모두 enabled/waiting이다.

최종 Vector는 **PID 2406117 / Invocation `12314ddc66e14e0083b08db2e51fc831`**로 정상 실행 중이며 Wazuh logcollector **1909632**, WAF master **2377669**·healthy와 원천 state **Suricata gen1/revision5, WAF gen3/revision11 active**는 유지됐다. pending 부재, 양 시작 가드와 수집·저장 상태 검사를 통과했다. 원본과 native checkpoint를 수동 수정하지 않았다. [운영 결과와 한계](vector/raw-operations/README.md) · [검증 메타데이터](vector/raw-operations/resume-validation-2026-10-14.json).

최종 소스·증거의 영구 보관과 임시물 정리를 완료했다(아래 정리 후속 기록). **4단계는 구현 준비 중이며 운영 전환은 아직 없다.** 인증서 관리는 마지막 순서다. 실제 호스트 재부팅, 새 CID의 WAF 재생성, 이번 구간의 새 적격 보안 사건 ACK는 검증하지 않았다. EVE·audit만 copytruncate에서 제외했고 Suricata 부가 로그와 WAF 보조 access의 기존 정책은 유지한다. 아래 기록은 각 시점의 이력이며 최신 상태는 이 항목을 따른다.

**02:19:46 KST 정리 후속:** A의 작업 자료 515파일·4,621,609B와 격리 시험 자료 8파일·98,071B를 보관한 뒤 stage3·시험 fixture·미사용 v1 recovery guard를 제거했다. migration 시작 가드는 유지했고 정리 전후 운영 상태 불변·서비스 신호 0회를 확인했다. Mac의 해당 임시 트리 650파일·55디렉터리·5,318,295B와 B 조회 임시파일 2개도 제거했으며 영구 증거는 유지했다. **이 문구는 267파일·2,077,701B 소스 스냅샷 이후에 추가한 기록**으로 그 스냅샷에 포함된 문서 바이트와 구분한다. **02:20:55 KST 최종 점검도 완료했다.** 두 migration guard는 ready이며 storage 정상·Vector active·recovery=no·collection=[]·binding 검증 및 상태 코드 없음, 세 타이머 enabled/active/waiting을 확인했다.

## 이전 시점 기록 — 2026-10-15 최신 운영 상태 — 원본 회전 적용, timer 활성화 대기

A에 원본 회전 controller와 WAF v2를 실제 반영하고 초기 migration seq18·reader 인계를 마쳤다. 두 원천의 실제 회전 결과는 **Suricata gen1 / revision 5 active**, **WAF gen3 / revision 11 active**다. **01:48:58 KST WAF의 같은 CID 재시작 1회**도 정상 종료·복귀를 통과했다. 새 master PID는 **2377669**, UID101·healthy이며, Vector **2368467**와 Wazuh logcollector **1909632** 및 두 raw state는 유지됐다. [운영 전환·검증과 한계](vector/raw-operations/README.md) · [현재 WAF v2 계약](vector/waf-producer-v2/README.md).

원본 `eve.json`과 `audit.log`만 legacy copytruncate에서 제외했다. Suricata `fast.log`·`stats.log`·`suricata.log`와 WAF `capstone-access.log`는 기존 copytruncate를 유지한다. WAF v2 정제는 감사 행의 context를 사용하며 access는 보조 원본이다. **원본·출력 회전 timer는 아직 disabled이며 활성화 사전 검사 2회, enable 0회**다. 따라서 자동 운영까지 완료했다고 표시하지 않는다.

실제 호스트 재부팅은 **0회**, 이번 관찰 구간의 자연 적격 보안 사건 ACK 표본도 **0건**이다. 로컬 처리 위치를 manager/Indexer 수신 확인으로 확대하지 않는다. 4단계 Hermes 운영 변경은 미착수이며 읽기 전용 사전 확인만 했고, 인증서 관리는 마지막 순서다. 아래 미배포·copytruncate 유지·후속 예정 문구는 각각의 과거 기준이며 현재 상태는 이 항목을 우선한다.

### 2026-10-14 당시 마감 기록

**2026-10-14 23:03:49 KST 마감 기준:** 사용자 요청에 따라 현재 작업 범위에서 마감한다. A 라이브 확인에서 이전 부트 자동 보존은 **10,323건·4,362,173B**(complete 6 / ready 3 / blocked 0)이며, Wazuh 원본 두 입력에는 `only-future-events=no`, `max-size=2GB`가 적용돼 있다. 관련 서비스는 정상이다.

원본 회전 controller와 WAF v2는 **미배포**이며 기존 copytruncate·WAF v1을 유지한다. 3단계 운영 전환·영속 복구는 미완료이고, 미완성 cutover CLI는 exit 78로 실행을 차단한다. 4~6단계는 착수하지 않았으며 인증서 관리는 마지막 순서다. 재개 조건은 [원본 회전·복구 현황](vector/raw-operations/README.md)을 따른다. 아래 내용은 이전 시점의 기록이다.

## 2026-10-14 19:38 KST 후속 — Indexer 시간 경계 보완 반영

Imperva/언어가드 기존로그 점검을마치고, 같은Indexer모니터를300초후보·정확60초sliding v2로갱신했다. native검색41개·lifecycle4단계·응답guard66개를통과했으며ID/권한/actions0·서비스/기존Wazuh룰은유지한다. 현재관리명령/검증/복구는 [v2운영안내](wazuh-vector/indexer-native/window-v2/OPERATIONS.md)를따른다. 자연스캔·최근Hermes사용표본은없어효과관찰대기다. 다음은WAF두reader회전격리→인증서관리이고장기지연/영속복구/정확히1회는별도다. 아래내용은각시점의기록이다.

## 운영 분석기 1/1 적용·실제 20회 종단 검증 완료 (2026-10-14 18:56 KST)

B의 `analysisd.event_threads=1`, `analysisd.rule_matching_threads=1`을 18:48:55 KST에 적용하고 **같은 manager 컨테이너를 한 번 재시작**했다. 기존 native 규칙 104개를 적용 전후 각각 통과했으며, 18:49:04의 새 analysisd PID는 `2132985`, 전체 스레드는 44개다. 다른 컨테이너와 보호 해시는 유지됐다. canary 없는 60.000186초 운영 관찰에서 수신 60건(약 1 EPS), drop 증가 0, queue 최대 표본 0, 단일 코어 대비 CPU 약 0.0333%를 확인했다. [적용·관찰 증거](wazuh-vector/correlation-fix/deployment-resume-2026-10-14.json).

사용자 명시 승인 후 실제 A agent001→B manager→Indexer의 **20회 × 13행(260행)** 시험을 18:56:08 KST에 완료했다. 동일 20개 run ID를 각각 한 번만 입력해 **manager 40건/Indexer 40건**, `100293` 20건·`100294` 20건, level 3·negative 경보 0건을 확인했다. 57/57 shard·strict CA/호스트명·각 run 및 전체 canonical tuple이 일치했으며 첫 조회 회차 11.3초, 입력 재시도 0회였다. A 원래 52행 접두 구간·inode·보호 설정과 B 옵션·룰·CID·SOC 안전 조건을 보존했다. 이 결과는 승인된 20회 시험의 성공이며 일반 트래픽의 장기 무손실 보장은 아니다. 기존 격리 1/1은 경보 4,000/4,000을 생성했지만 500 EPS 부하에서 queue 최대 표본 24%·최대 archive 관측 지연 약 10.04초가 있어 지속 처리량 보장은 아니다. [격리 부하와 한계](wazuh-vector/correlation-fix/LOAD-VALIDATION.md). 아래의 미배포·반입 대기 설명은 이전 시점 기록이다.


**2026-10-14 18:18 KST 후속:** 검증기 고정ID 가정을 수정해47개 합성 및 기존 회차 대조를 통과했다. 각30,000행 격리 부하에서 worker1/1은 상관4,000건 전부 생성했고 자동설정은1,362건이었다(양쪽 입력drop0). 1/1은500EPS 시험 중queue최대표본24%·최대관측지연10.04초가 있어 지속처리량 보장과 구분한다. 운영 두옵션 변경안은 준비했지만 배포 검증94파일의B 반입이 자동 승인 검토에서 거절되어 사용자 전송 승인 대기다. 운영옵션/규칙/서비스 변경과 실제001 새burst는 아직 없다. [보완·검증·남은 적용](wazuh-vector/correlation-fix/README.md). 아래는 이전 기록이다.

**2026-10-14 13:12 KST 상관 누락 조사:** 격리한 실제 Wazuh의 사전 logtest 없는 자동 설정 20회에서 100293 누락 8회·100294 누락 7회를 재현했다(중복 2회). 1/1 작업자 대조 20회는 정상이며, 40회×13행의 archives 원문과 최종 판정/alerts를 전수 대조했다. 병렬 판정의 순서 경쟁이 유력하지만 agent 000 직접 큐 시험이므로 과거 운영 001의 세부 원인 확정·운영 누락률·완전 해결로 확대하지 않는다. 검증기의 반복 경보 eventID0005 고정 가정도 별도 문제로 확인했다. 다음은 그 검증기 보완과 판정 병렬도 후보의 부하 검증이며, 운영 설정·규칙·서비스는 유지했다. [근거·실측·후속](wazuh-vector/correlation-diagnosis/README.md). 아래는 이전 기록이다.

## 현재 상태 — 보존 자료 전수 판정·현재 경로 확인 (2026-10-14 12:00 KST)

보존한 이전 boot 두 배치1,481건·621,820bytes의 SHA와 선택 조건을 A/B에서 독립 대조했다. 실제 Vector 분기에서 **현재 nft 선택 조건의 후보0건·비대상1,481건·정제 보안 이벤트0건**이며 운영 Wazuh 재주입과 Indexer 쓰기는 없다. 실제 분석/색인할 사건ID가 없으므로 이를 색인 누락이나 1,481건 색인 성공으로 표현하지 않는다. 이 판정은 해당 선택 조건의 범위이며 모든 kernel 로그의 안전성을 판단하지 않는다.

별도 합성14건은 정제 성공9·예상 실패3·비대상2로 검증했고, 성공9건은 모두 historical/replay 및 `correlation_eligible=false`다. [A 정제·재생 판정](vector/history-replay/README.md) · [검증 수치](vector/history-replay/validation-2026-10-14.json).

현재 전달 경로는 별도 합성 canary로 확인했다. native Wazuh8개 순서 시험을 마쳤고, canary13행을 6행/7행 사이 3초 간격으로 보낸 회차는 manager2건·Indexer2건의 정확한 사건ID·규칙100293/100294, strict TLS·57/57 shard·timeout 없음을 확인했다. 앞선 연속13행 회차는 manager1/Indexer1로 일치했지만 예상2건에는 미달했고 원인은 미확정이다. 간격을 둔 성공1회는 원격 영속 ACK·순서·무손실 보장이 아니다. [B 검증·제한](wazuh-vector/history-replay-b/README.md) · [검증 수치](wazuh-vector/history-replay-b/validation-2026-10-14.json).

**12:22 KST Suricata 후속 검증 완료:** 지연 공개 회전에서 Vector/Wazuh 각각6건·중복0, 연속2회전·정상재시작을 확인했다. 단순 rename 대조군은 늦은 기록·중간 세대2건 누락을 재현했다. 운영 copytruncate는 유지하며 다음은 WAF별 두 reader 검증과 세대 순서 영속 저장·강제 종료/재부팅 복구·초기 checkpoint 이전이다. [회전 결과](vector/raw-rotation/README.md). 아래의 격리 정제 예정 문구는 이번 결과로 후속 완료됐고, 이전 시점의 결과와 한계는 그대로 보존한다.

**2026-10-14 10:57 KST 후속 완료:** 이전boot 후속481건을 회수해 두배치1,481건/621,820bytes의 A→B 직접 전송·B 파일보관·A 수신증 저장을 검증했다. native 합성144개·실제 합성 응답유실 재시도 및 실제배치 해시/고유cursor를 확인했고 서비스는 유지됐다. Wazuh/Indexer ACK·전체무손실·운영 재주입을 뜻하지 않는다. 다음은 격리 정제와 Suricata→WAF raw 회전 검증이다. [실측과 운영 경계](vector/history-transfer/README.md). 아래 내용은 이전 기록이다.

**2026-10-14 06:09 KST 추가 적용:** [별도 evidence 분기](vector/EVIDENCE.md)와 Wazuh100260~100262를 운영에 연결했다. Vector110/jq18/reader9 및 Wazuh배포전후104개 검증을 통과했고, 자연 Suricata1건의 A→manager→Indexer 일치를 확인했다. 네 출력의 회전에서 두 reader의 EOF/해시·archive·수집 재개를 확인했다. 기존 no_log 상관은 유지하며 [Indexer 관측 모니터](wazuh-vector/indexer-native/README.md)와 [이전 boot 보존 결과](vector/history/README.md)는 별도 상태를 따른다. 원격 영속 ACK나 raw copytruncate 해결로 확대하지 않는다.

**2026-10-14 최신 후속:** WAF 최소 access/배포 ID producer와 Vector의 중복 키·독립 시각·요청 결합 정제를 운영에 연결했다. [WAF 계약](vector/WAF.md), [통합 검증](vector/pipeline-validation-2026-10-14.json), [출력 회전/보존](vector/STORAGE.md), [실제 Wazuh 상관/Indexer 검증](wazuh-vector/CORRELATION.md)을 참조한다. native 변환89개·Wazuh43개 시나리오 통과. 운영 공격 상관은 no_log이며 영속 중복 제거·전원장애 보장·raw copytruncate 해결로 확대 해석하지 않는다. 아래 첫 Vector 전환의 WAF 전체 격리 설명은 후속 전 상태다.

**2026-10-14 후속 적용:** 사용자 승인으로 A에 **Vector 0.59.0**을 설치하고 Suricata·nftables의 별도 공통 JSONL/KST 출력을 활성화했다. [운영 설정·22개 native 검사·한계](vector/README.md), [Ansible 배포·멱등성](../automation/ansible/README.md)를 참조한다. WAF는 모든 레코드를 격리하며 패키지 경로의 WAF 정제는 미완료다. 기존 raw Wazuh 입력·보안 룰·copytruncate를 유지한다.

Vector 출력은 별도 `schema_version=vector-1` 계약이다. 파일 sink 및 Wazuh 수집을 아래 Python 후보의 원문/위치 원자 저장·영속 수신증·재생 멱등성과 동일한 보장으로 표현하지 않는다. 이전 Python 후보의 실행 코드와 전용 테스트는 2026-10-14 사용자 정리 요청에 따라 삭제했으며 검증 기록만 보존한다. 운영 상시 실행기는 Vector다. 새 Wazuh 입력의 경계는 [연결 설정](wazuh-vector/)에서 관리한다. 출력 보존/회전·이전 부팅 journal·파일 재생 중복 및 신규 상관 룰/색인 종단 확인은 후속이다. 아래 내용은 각 시점의 이력이다.

**2026-10-14 정리:** Vector 운영 경로로 전환한 뒤 사용자 요청에 따라 이 문서에 나오는 이전 Python 구현 21개, 전용 테스트 16개와 합성 예제를 삭제했다. 아래 API·CLI·테스트 명령과 미배포/후속 계획은 각 검증 시점의 기록이며 현재 실행 지침이 아니다. 검증 결과와 JSON 증거는 보존했다. [삭제 목록·범위](RETIRED-2026-10-14.md), [현재 Vector 운영](vector/README.md), [현재 Wazuh 연결](wazuh-vector/)을 참조한다.

**2026-10-14 후속 검토 — 패키지 비교 우선:** 사용자 요청에 따라 추가 Python 구현·운영 연결에 앞서 Wazuh 기본 기능, Vector, Fluent Bit, Logstash, syslog-ng/rsyslog를 비교했다. 현재 추천 검증 후보는 Vector의 공통 필드 정제→별도 JSONL→기존 Wazuh agent→manager 경로이며 아직 선정·설치·실측하지 않았다. 이 경로의 파일 쓰기/전송 성공을 기존 SQLite 영속 수신증 또는 Wazuh 분석 완료와 동일시하지 않는다. 당시에는 기존 코드를 특수 입력·시각 근거·증거 보존 요구와의 비교 기준으로 보존하기로 했으나, 이후 사용자 정리 요청으로 실행 코드와 전용 테스트를 삭제했다. [기능별 대체 범위·공식 근거](../../대화기록/2026-10-14.md#python-자체-구현과-패키지대체-비교). 아래는 변경 전 검증 이력이다.

**2026-10-14 00:43 KST — 전달·수신 확인과 격리 재처리 분리 검증 완료.** A→B 임시 inbox에 실제 journal3건·격리 Suricata1건을 보내고, 첫 응답 유실 뒤 재전송까지 총5회 통신에서 B의 유일4행·일치 수신증4개를 확인했다. WAF 보관 원문4건은 독립 시간 근거로 재처리하여 KST를 복구했고 원래 격리 판정·원문·사건ID·체크포인트를 보존했다. 전체285회귀 통과. `durable_inbox`는 B 저장 확인이며 Wazuh 분석/색인 확인은 아니다. 기존 Wazuh 입력과 copytruncate는 유지하며 다음은 Wazuh 전달·신규 상관/시간창·재전송 및 기존 입력의 이중 집계 검증이다. [전달 계약·실측](DELIVERY.md) · [검증 집계](delivery-validation-2026-10-14.json). 아래 날짜·시각별 기록은 당시 결과다.

**최신 23:47 KST — 회전 후속 검증:** root manifest의 세대 순서·닫힘 증거를 수집기에 연결하고227회귀를 통과했다. 같은 설치 바이너리의 별도 시험에서 Suricata2건·WAF9건(시각 미대조로 격리)을 원문 그대로 보존했고 재오픈 추가0건을 확인했다. WAF USR1/같은 경로 HUP의 실패, 새 경로 HUP의 성공과 이전 요청 지연 기록을 실제 확인했다. 운영 정책은 유지하며 다음은 출력/수신확인·기존 Wazuh 경로 이전 검증이다. [회전 결과·한계](ROTATION.md). 아래 시간별 기록은 당시 결과다.

**2026-10-13 22:57 KST 현재: 3단계 수집기 후보 구현·분리 검증을 완료했다. 전체188회귀, A 실제 Suricata29/WAF4/nft130건 정제와 일반 kernel2건 보존, 저장소 재오픈 추가0건을 확인했다. 운영 회전 정책은 copytruncate로 남아 있으며 배출/격리 재처리·Wazuh 연결은 미배포다.** [수집기 계약과 다음 작업](COLLECTOR.md) · [실제 검증 집계](collector-validation-2026-10-13.json). Python 표준 라이브러리만 사용하며 추가 패키지는 설치하지 않았다. 아래 1·2단계/사전검증 기록은 당시 결과로 보존한다.

수집기 후보는 `collector.py`, `collector_file_reader.py`, `collector_journal_reader.py`, `collector_store.py`, `collector_waf_evidence.py`로 구성한다. 라이브 `journalctl`이 동일 레코드의 키 순서를 바꾸는 문제를 확인해 선택 필드의 canonical JSON을 저장/비교하도록 수정했다. 파일 입력의 raw는 실제 입력 bytes이고 journal raw는 선택 필드의 재직렬화 결과이므로 구분한다. 원문·체크포인트·용량 카운터를 같은 SQLite 트랜잭션에 저장하며, 읽기 위치를 먼저 전진시키지 않는다.


`normalize_events.py` (2026-10-14 삭제)는 서로 다른 원천의 관측 필드를 작은 공통 JSON으로 옮긴다. `examples.jsonl` (2026-10-14 삭제)은 Suricata·ModSecurity·nftables 합성 입력 3건이며 실제 공격이나 운영 경보가 아니다. `test_normalize_events.py` (2026-10-14 삭제)는 시각·식별자·주소 방향·동작 구분·민감 본문 제외·불량 입력 처리를 확인한다.




## 순차 보완 2단계 — 근거에 따른 KST 변환 (10/13 22:09 KST)

A 호스트는 KST, 현재 WAF 컨테이너의 `/etc/localtime`은 UTC였다. 과거 네 건은 **출발지 IP·HTTP 메서드·URI·상태 코드·wall time이 일치하는 Nginx 접근 로그를 각1건씩** 찾았다. 접근 로그의 명시적 `+0000`과 Docker 외부 UTC 기록이 각각0.052/0.551/0.200/0.741초 이내로 일치했다. 현재 컨테이너 설정이나 응답 `Date` 헤더만으로 과거 시각을 결정하지 않았다.

| 원문 시각(2026-10-12, UTC 근거 확인) | KST 정제 결과(2026-10-13) |
|---|---|
| 18:00:36 | 03:00:36+09:00 |
| 18:00:56 | 03:00:56+09:00 |
| 18:04:43 | 03:04:43+09:00 |
| 18:04:45 | 03:04:45+09:00 |

해당 감사 레코드의 producer는 ModSecurity v3.0.16이다. 같은 버전 공식 구현의 JSON `time_stamp`는 `ascTime()`을 사용하고, 이 함수는 `localtime_r` 후 `%c`로 작성하며 명시적 offset을 붙이지 않는다. 이번 실제 문자열의 시간대를 별도 근거로 확인해야 했던 이유다. [JSON 작성 소스](https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3.0.16/src/transaction.cc) · [시각 포맷 함수](https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3.0.16/src/utils/string.h).

어댑터에 선택 인자 `time_context=None`를 추가했다. 신뢰할 수 있는 검증기/수집기만 다음 세 필드를 전달하며, **로그 본문이나 HTTP 헤더에서 이 context를 가져오지 않는다.**

| time_context 필드 | 계약 |
|---|---|
| `source_utc_offset` | 검증된 고정 offset. `+00:00` 등 `±HH:MM`, 최대23:59. `-00:00`은 허용하지 않음 |
| `evidence_ref` | 보관한 근거의 참조. 기존 ASCII locator 규칙·1~160자 |
| `raw_bytes_sha256` | LF/CRLF까지 포함한 이번 원문 bytes의 SHA-256. 다른 레코드면 거절 |

무offset이지만 유효한 원천 시각에만 검증된 offset을 붙여 KST로 변환한다. 명시적 offset이 있는 원천은 유효한 context보다 우선한다. 형식/해시가 잘못된 context는 원천 시각 상태와 관계없이 호출을 거절한다. context가 없거나 원천 시각 자체가 누락/오류라면 기존 상태를 유지하고 관측 시각으로 대체하지 않는다. 고정 offset 적용 후 실행 호스트 시간대와 독립적으로 변환한다. [Python datetime의 시간대 변환](https://docs.python.org/3.11/library/datetime.html#datetime.datetime.astimezone).

보정된 출력에는 `time_status=source_with_verified_timezone`, `source_utc_offset`, `time_policy_version=waf-time-v1`, `time_evidence_ref`를 남긴다. 원천 시간대 누락 플래그는 `source_timezone_supplied`로 바꾸어 외부 근거가 사용됐음을 표시한다. **원문/event 객체·`raw_sha256`·`raw_bytes_sha256`·`event_id`는 바꾸지 않는다.** 기존 ID에 포함된 `modsecurity-audit-v1`도 유지했다. 보정 메타데이터까지32KiB출력한도에 포함한다.

`verify_waf_time_evidence.py` (원천 대조 검증기; 2026-10-14 삭제)는 위 날짜/네 레코드를 대상으로 하는 제한된 읽기 전용 검사다. 현재 일치 근거를 다시 확인한 뒤 원문 SHA에 결속한 context를 만들고 보정 결과·ID/원문 불변을 검사한다. **실시간 수집기나 미래 모든 WAF 로그에 UTC를 부여하는 설정이 아니다.** 레코드별 시간 근거는 [직접 검증 결과](waf-time-validation-2026-10-13.json)에 보관했다. 원문 요청 값은 출력하지 않았다.

시간대 회귀15개를 추가해 기존79개 포함 **94개 테스트가 통과**했다. 날짜/윤일/분수초/극단 offset·실행호스트 TZ3종·명시시각 우선·위조 본문 context 무시·원문과 사건ID 불변·크기 경계를 확인했다. 실제4건의 보정도 통과했고 A 원문파일·WAF컨테이너ID/시작시각·compose/agent/logrotate설정해시가 전후동일했다. 서버에 프로그램을 설치하거나 설정·시각·기존 Wazuh 경보를 바꾸지 않았다.

근거가 없는 다른 과거/미래 레코드는 계속 `timezone_missing`으로 남긴다. 미래 레코드에 대한 근거 생성·검증 실패 격리·회전/체크포인트/재전송은 다음 수집기 단계다. 새 시간 상태/메타데이터의 실제 agent→Wazuh→Indexer 및 상관 룰 검증도 후속 범위이며, 이전 디코딩10건 검증을 새 필드 검증으로 간주하지 않는다.

## 순차 보완 1단계 — WAF 중복 헤더 (10/13 21:47 KST)

사용자 요청에 따라 이번 단계는 WAF 입력 처리만 보완했다. `waf_input_adapter.py` (2026-10-14 삭제)의 `normalize_waf_record(raw, sensor=..., record_id=..., observed_at=...)`를 새 수집 어댑터 API로 준비했다. 위 21:27의 strict 원문 거절 결과는 당시 검증이며, 기존 공통 CLI/파서는 계속 같은 중복 키를 거절한다. 수집기 배포나 전체 JSON 파서의 허용 범위 변경은 하지 않았다.

원문 JSON을 키-값 쌍의 트리로 읽고 전체 깊이·UTF-8·숫자와 중복 키를 확인한다. **정확히 `transaction.response.headers.Server`에서 문자열 값이 반복되는 경우만 허용**한다. 검사 후 응답 헤더 영역을 정제 입력에서 제외하고 기존 변환 모듈을 호출한다. IP·시각·규칙 ID·요청 헤더·다른 경로의 중복은 계속 거절한다. Python 표준 `object_pairs_hook`로 쌍을 보존할 수 있으며 기본 파서의 마지막 값 덮어쓰기에 의존하지 않는다. [Python JSON 문서](https://docs.python.org/3/library/json.html#json.JSONDecoder).

반환값은 기존 `capstone_norm` 구조에 다음 정보를 더한다. 모든 부가 필드를 넣은 뒤 32KiB 상한을 다시 검사한다.

| 필드 | 어댑터 계약 |
|---|---|
| `input_adapter` | `modsecurity-audit-v1` |
| `raw_bytes_sha256` / `raw_bytes_length` | 전달받은 **원문 바이트 전체**의 SHA-256/길이. LF/CRLF·공백도 포함 |
| `raw_sha256` | 응답 헤더를 제외한 이벤트의 canonical JSON 해시. 원문 바이트 해시와 구별 |
| `event_id` | `[어댑터 버전, sensor, "modsecurity", record_id, raw_bytes_sha256]`의 canonical JSON 해시. 관측 시각 제외 |
| `quality_flags` 추가값 | 중복을 수용했다면 `duplicate_response_server_header` |

어댑터의 `event_id` 계산은 **중복이 없는 WAF 이벤트에도 적용**되며 코어 단독 호출의 ID와 다르다. 응답 헤더만 다른 원문을 같은 사건 ID로 합치지 않도록 원문 해시에 결속했다. 같은 원문 bytes·위치·센서의 재전송에서는 ID가 유지된다. 새 수집기는 이 입력 경로를 한 가지로 고정해야 하며 ID 생성 자체가 중복 전달 방지나 원문 보관을 제공하지는 않는다.

신규 어댑터 회귀17개를 추가했고 기존62개를 포함한 **전체79개 테스트가 통과**했다. 잘못된 경로/중복 키, 원문·ID 보존, 민감 값 제외, 입력1MiB/출력32KiB 경계를 확인했다.

21:47 A에서 기존 audit 8,432바이트·4개 레코드를 메모리로만 처리해 **4/4 수용**, 원문 bytes 해시 일치, `DetectionOnly/observed`와 각 규칙 수 보존을 확인했다. 로그 원문·파일 메타데이터·WAF 컨테이너 ID/시작시각·agent/logrotate 설정은 전후 동일했다. 원문 요청 내용을 Mac으로 가져오지 않았다. [직접 검증 결과](waf-adapter-validation-2026-10-13.json).

**1단계 당시에는 시간대를 보정하지 않았다.** 이후 위 2단계에서 이 네 건의 근거를 확보하고 KST 변환을 검증했다. context 없이 호출하면 기존 누락 상태가 유지된다. 수집기·새 상관 룰·운영 연결은 미배포다.

## 위치와 데이터 흐름

후속 운영 설계는 **A의 원천 로그에서 기존 수집 경로와 병렬로 분기**하는 방식이다. 이미 만들어진 B의 Wazuh 경보를 다시 정상화해 Wazuh로 되돌리는 구조가 아니다.

```text
Groot_A 원천
  Suricata EVE alert / ModSecurity JSON audit / kernel journal
            │
            ├── 기존 수집 경로 ──> Groot_B Wazuh 기존 디코더·룰
            │                              │
            │                              └── 기존 경보·인덱스 ──> 읽기 MCP ──> LLM
            │
            └── [후보 구현·미배포] 원천 수집기·안정적인 레코드 위치·체크포인트
                              │
                              ├── 비공개 SQLite: 입력·위치·정제·격리 원자 저장
                              └── 배출 검사 → A outbox → B inbox (분리 검증 완료·상시 미배포)
                                            │
                                            └── [후속 검증] 단일 정규화 입력
                                                 → B JSON 디코더
                                                 → 공통 필드 기반 상관 분석
```

기존 보안 이벤트 MCP의 필드 정리는 이미 수집·인덱싱된 경보를 **조회할 때** 응답 형식을 맞추는 기능이다. Wazuh 분석 엔진에 들어가기 전의 공통 필드를 만들거나 기존 룰의 집계 키를 바꾸는 정규화가 아니다. 여기서 준비하는 모듈과 위치·효과가 다르다.

원본은 기존 경로와 별도 보존 정책으로 유지한다. 정규화 출력은 필요한 필드만 남기므로 원문 복원이나 증거 보관을 대신하지 못한다. `normalize_events.py` CLI는 입력을 읽어 stdout으로 변환 결과를 출력한다. 새 `collector.py` CLI는 유한한 한 배치를 비공개 스풀에 저장한다. 두 경로 모두 원천 파일을 수정하거나 수집 데몬을 등록하지 않는다.

## 오프라인 사용

저장소 루트에서 다음 중 하나로 합성 예제를 변환한다. 출력은 터미널에만 표시되며 수집 서버로 전송하지 않는다.

```sh
python3 -B infra/normalization/normalize_events.py --input infra/normalization/examples.jsonl
```

```sh
python3 -B infra/normalization/normalize_events.py < infra/normalization/examples.jsonl
```

```sh
python3 -B -m unittest discover -s infra/normalization -p 'test_*.py' -v
```

`-B`는 Python 바이트코드 캐시 생성을 막는다. CLI는 UTF-8 JSONL 한 줄을 한 레코드로 읽고 성공한 레코드마다 JSON 한 줄을 출력한다. 실패한 줄은 원문 없이 `line N: 고정_오류_코드`를 stderr에 기록하고 다음 줄을 계속 처리한다. 종료 코드는 모두 성공하면 `0`, 한 줄 이상 거절되면 `1`, 입출력 오류면 `2`다. **종료 코드가 1이어도 stdout에는 성공한 일부 레코드가 있을 수 있다.** 이 부분 성공을 전체 파일의 성공으로 간주하지 않는다. 빈 줄도 올바른 JSON 레코드가 아니므로 거절된다.

## 입력 계약

최상위 객체는 다음 **다섯 필드만** 가진다. 원천 로그 한 줄을 그대로 넣는 대신 후속 수집기가 이 envelope를 만들어야 한다.

| 필드 | 이전 Python 구현 당시 계약 |
|---|---|
| `source` | `suricata`, `modsecurity`, `nftables` 중 하나 |
| `sensor` | 신뢰할 수 있는 수집기가 부여할 원천 식별자. 1~80자 |
| `record_id` | 같은 원천 레코드를 재처리할 때 유지할 위치 식별자. 1~160자 |
| `observed_at` | 수집기가 관측한 시각. 명시적 `Z` 또는 UTC offset을 가진 ISO 형식 문자열 |
| `event` | 아래 원천별 형태의 JSON 객체 |

`sensor`와 `record_id`는 영문 대소문자·숫자·`_ . : / @ + -`만 허용한다. 예제의 `eve:demo:1` 같은 값은 합성 위치이며 실제 inode·offset·journal cursor 설계가 완료됐다는 뜻이 아니다. 공격자가 보낸 헤더나 로그 본문에서 이 식별자를 받아서는 안 된다.

| 원천 | 허용하는 이벤트와 필수 구조 | 주요 제한 |
|---|---|---|
| Suricata | `event_type="alert"`, `alert.signature_id` | `stats`·`flow`·`http`·`dns` 단독 이벤트는 현재 지원하지 않음 |
| ModSecurity | `transaction`, 비어 있지 않은 `transaction.messages`, 각 항목의 `details.ruleId` | JSON audit 형태만 지원. native audit 텍스트나 빈 메시지 트랜잭션은 현재 지원하지 않음 |
| nftables | `_TRANSPORT="kernel"`, 단일 행 `MESSAGE` | 알려진 접두어로 시작하고 `IN/OUT/SRC/DST/PROTO`가 있어야 함. 알려진 접두어 중복·해당 키 중복은 거절 |

nftables의 알려진 접두어는 `AGENT_BLOCK`, `FW_DROP_IN`, `FW_DROP_OUT`, `FW_DROP_FWD`, `FW_SHADOW_OUT`, `FW_SSH_RATE`, `SPOOF`다. `IN=`·`OUT=`의 빈 값은 허용하지만 키 자체는 필요하다. `_TRANSPORT`라는 JSON 문자열만으로 원천 신뢰가 확보되지는 않는다. 실제 journal에서 kernel 레코드를 읽고 cursor·boot 식별자와 함께 검증하는 수집기가 필요하다.

## 출력 스키마와 필드 매핑

출력 최상위는 `{"capstone_norm": {...}}` 하나이며 스키마 버전은 문자열 `"1"`이다. 원천 데이터가 없거나 유효하지 않은 선택 필드는 생략한다. 공통 주소 자리에 `unknown`, 빈 문자열, `0.0.0.0` 같은 대체 집계 키를 만들지 않는다.

| 출력 필드 | 의미·타입 |
|---|---|
| `schema_version`, `source`, `sensor`, `record_id` | 버전과 원천·위치 식별자 |
| `raw_sha256`, `event_id` | 아래에 설명한 canonical JSON 기반 SHA-256 문자열 |
| `observed_at_kst` | 수집 관측 시각을 같은 절대 시각의 `+09:00`으로 변환 |
| `event_time_kst`, `time_status` | 원천 이벤트 시각이 해석될 때만 시각 출력. 코어 상태는 `source/missing/invalid/timezone_missing`; WAF 근거 보정은 `source_with_verified_timezone` |
| `source_ip`, `destination_ip` | 해당 원천 레코드가 관측한 출발지·목적지 IP |
| `source_port`, `destination_port`, `protocol` | 유효한 포트 정수·프로토콜 문자열. 알려진 번호(6/17 등)는 tcp/udp 등 이름으로 통일. 원천에 없으면 추정하지 않음 |
| `flow_source_ip`, `flow_destination_ip`, `flow_source_port`, `flow_destination_port` | Suricata의 `flow` 객체에 있는 별도 관측값. 최상위 주소를 덮어쓰지 않음 |
| `rule_ids` | 모든 원천에서 문자열 배열. 예: `["2034806"]`, `["942100"]`, `["FW_DROP_IN"]` |
| `native_severity_scale`, `native_severity_value` | 원천 심각도 척도와 문자열 배열. 예: Suricata `["1"]`, WAF `["2", "CRITICAL"]` |
| `action`, `direction` | 아래 동작 해석. `direction`은 현재 항상 `unknown` |
| `http_method`, `http_status`, `engine_mode` | 유효한 HTTP 메서드·상태 코드·WAF 엔진 모드가 있을 때만 출력 |
| `ingress_interface`, `egress_interface` | nft 기록의 유효한 비어 있지 않은 `IN/OUT` |
| `protected_asset` | 관측 주소 중 DGX 두 주소가 포함되는지 나타내는 boolean |
| `quality_flags` | 누락·유효성 문제를 나타내는 고정 문자열 배열 |

| 공통 필드 | Suricata | ModSecurity | nft kernel journal |
|---|---|---|---|
| `source_ip` / `destination_ip` | `src_ip` / `dest_ip` | `transaction.client_ip` / `host_ip` | `MESSAGE`의 `SRC` / `DST` |
| 포트 | `src_port` / `dest_port` | `client_port` / `host_port` | `SPT` / `DPT` |
| 이벤트 시각 | `timestamp` | `transaction.time_stamp` | `__REALTIME_TIMESTAMP`의 epoch microseconds |
| 규칙 | `alert.signature_id`를 문자열 배열로 변환 | 각 `messages[].details.ruleId`를 문자열로 변환·중복 제거 | 알려진 접두어의 문자열 배열 |
| 원천 심각도 | `alert.severity`의 문자열 배열, 척도 `suricata_1_3` | severity 문자열 배열, 척도 `modsecurity_0_7_or_native_label` | 생성하지 않음 |
| 동작 | `alert.action`의 `allowed/blocked`, 미확정이면 `observed` | 항상 `observed` | drop 접두어는 `logged_drop`, shadow는 `would_drop`, 나머지는 `observed` |

`rule_ids`와 `native_severity_value`는 원천 간 숫자/문자열 혼합으로 Indexer 필드 타입이 충돌하지 않도록 모두 문자열 배열로 통일한다. 원래 JSON 타입은 정규화 필드에서 복원하지 않고 `record_id`로 연결한 원본에서 확인한다. 원천 심각도 척도는 따로 유지하며 Wazuh level이나 하나의 공통 위험도 숫자로 환산하지 않는다. `rule_ids`와 WAF 심각도 목록은 각각 중복 제거된 목록으로, 두 배열의 같은 위치가 반드시 한 규칙의 쌍을 뜻하지 않는다. 개별 규칙별 판단에는 보존된 원문을 다시 확인한다.

### 시간·파싱 품질

명시적인 offset이 있는 ISO 시각과 지원하는 ModSecurity 시각 형식을 KST로 변환하며 마이크로초 여섯 자리를 출력한다. 코어에서 원천 시각이 없거나 잘못됐거나 시간대가 없으면 `event_time_kst`를 생략하고 `time_status`·`quality_flags`에 남긴다. 이를 `observed_at_kst`로 몰래 대체하지 않는다. WAF 어댑터는 위2단계의 원문별 외부근거가 있을 때만 시간대를 보완하고 별도상태를 출력한다. 미래 시각도 형식이 유효하면 해석하며, 지연·미래·시계 오차 허용 범위는 아직 구현하지 않은 수집 정책이다.

CLI는 줄당 최대 1 MiB, 이벤트 canonical JSON 최대 1 MiB, JSON 중첩 깊이 최대 64를 검사한다. 정제 출력은 프로젝트 한도 32 KiB이며 초과 시 레코드 전체를 거절한다. Wazuh 공식 한도와 동일하다는 뜻은 아니다. 잘못된 offset(예: `+09:60`)은 허용하지 않는다. UTF-8 오류·중복 JSON 키·NaN/Infinity·잘못된 envelope·미지원 이벤트는 거절한다. 일부 주소·포트·심각도·시각 오류는 해당 필드를 생략하거나 품질 플래그로 남기므로 **변환 성공이 곧 상관 분석에 적합하다는 뜻은 아니다.** 후속 룰은 필요한 필드와 품질 조건을 명시해야 한다. 이 모듈의 크기 한도를 Wazuh 실제 수집·디코더 한도로 간주하지 않는다.

요청·응답 body, 헤더, URI, 패킷, 시그니처/메시지 자유 텍스트는 출력에 복사하지 않는다. 불필요한 비밀 값과 조작 가능한 본문의 재전달을 줄이는 선택이며 원본에서 해당 내용을 지우는 기능은 아니다.

### 원본 해시·중복 식별의 경계

`raw_sha256`은 이름과 달리 **원문 파일 바이트의 해시가 아니다.** 파싱한 `event`를 키 정렬·일정한 구분자·UTF-8로 직렬화한 canonical JSON의 SHA-256이다. 원래 공백, 키 순서, escape 표기, 개행 등의 정확한 보존을 입증하지 못하며 별도의 표준 canonicalization 규격을 구현한 것도 아니다.

`event_id`는 `[sensor, source, record_id, event]`를 같은 방식으로 직렬화한 해시다. `observed_at`을 제외하므로 동일 원천 레코드의 재전송은 같은 ID가 되고, 내용이 같아도 `record_id`가 다른 두 관측은 별개 ID가 된다. 이 성질은 수집기가 레코드 식별자를 안정적으로 유지할 때만 성립한다. **현재 모듈은 ID를 생성할 뿐 중복 제거·재전송 상태 저장을 하지 않는다.** 원문 추적은 새 수집기 스풀에서 별도로 관리한다. 파일 bytes와 journal 선택 필드 canonical bytes의 해시 범위는 [수집기 계약](COLLECTOR.md)을 따른다.

## 해석 시 유지할 경계

- **관측 출발지 ≠ 공격자.** 응답 패킷의 출발지가 서버라고 해서 서버를 공격자로 바꾸지 않는다. `source_ip`를 임의의 `attacker_ip`로 재명명하지 않으며 NAT 전 주소·B/C의 원래 프로세스·역방향 연결을 추정하지 않는다. 공통 IP 값만으로 서로 다른 센서·NAT 위치의 동일 주체를 확정할 수 없다.
- **DGX 표식 ≠ 허용목록·오탐 판정.** `protected_asset=true`는 관측 endpoint 또는 flow 주소가 정확히 `211.170.162.110/.111`인 경우의 참고 표식이다. 포트·방향과 관계없이 두 주소를 표시하지만 레코드는 유지한다. 정상·악성을 결정하거나 경보를 숨기거나 실제 nft/Suricata 예외를 바꾸지 않는다.
- **WAF HTTP 403 ≠ WAF 차단 확인.** `DetectionOnly`와 403을 함께 보존하면서 `action=observed`로 둔다. 애플리케이션 응답과 WAF 조치를 구별할 추가 근거 없이 차단으로 바꾸지 않는다. HTTP audit만으로 TCP·TLS·NAT 관계도 새로 채우지 않는다.
- **nft shadow ≠ 실제 drop.** `FW_SHADOW_OUT`은 `would_drop`이고 drop 계열 접두어의 `logged_drop`과 다르다. `AGENT_BLOCK`·`SPOOF`는 현재 `observed`다. 10/13 라이브에서 `SPOOF/AGENT_BLOCK/FW_DROP_IN` 뒤 다음 룰이 drop이고 shadow 뒤에는 drop이 없음을 확인했다. 모듈은 기존 보수적 계약을 유지하며 `observed`가 실제 허용을 뜻하지 않는다. 배포 시점의 고정 룰 프로필에 결속한 동작 의미 정렬은 후속 수집 설계 사항이다.

## Wazuh 후속 연계 설계 — 이전 Python 구현 당시 미배포

공통 필드는 JSON decoder가 추출하는 dynamic field를 사용한다. 예를 들어 룰 엔진의 필드명은 **`capstone_norm.source_ip`**이며, 경보 인덱스에서 보이는 `data.capstone_norm.source_ip`와 구별해 시험한다. 출력 배열은 스칼라 목록으로 유지하고 배열의 객체를 만들지 않았다. 10/13 설치 Wazuh 4.14.8의 `wazuh-logtest`에서 동적 필드·boolean·배열·주소 누락·32KiB 출력을 포함한 10건을 대조해 모든 필드 일치를 확인했다. 실제 agent 전달·Indexer 매핑·신규 상관 룰은 아직 미검증이다. [Wazuh JSON decoder 공식 문서](https://documentation.wazuh.com/current/user-manual/ruleset/decoders/json-decoder.html).

초기 연계는 정규화 레코드 **한 건을 한 번만 넣는 단일 입력 경로**를 정하고, 공통 형식 판별용 **기초 level 1 + `<options>no_log</options>`**부터 격리 시험하는 설계다. 후속 빈도 집계에는 검증된 dynamic field의 `same_field`를 검토한다. level 0은 과거 일치 집계용으로 유지되지 않는다는 공식 제약을 고려한 선택이며, `no_log`는 그 경보를 기록하지 않는 옵션이지 수집·분석 비용을 없애는 설정이 아니다. 실제 룰 엔진 동작을 시험하기 전 배포하지 않는다. [Wazuh 룰 문법: if_matched_sid·same_field·options](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html).

이 폴더에는 운영 룰 XML, 새 룰 ID, 빈도 임계값, 수집 설정이 없다. 기존 원본 경보는 유지하고 정규화 기초 입력을 별도 경보로 중복 발행하지 않는 방향이다. 향후 상관 룰은 정규화 경로만 집계하고 원본·정규화 사본을 같은 카운터에 함께 넣지 않도록 분리해야 한다. `event_id` 필드만 추가한다고 Wazuh가 자동 중복 제거하는 것은 아니므로 전달 측 중복 제거와 재시작·재전송 시험도 필요하다.

병렬 분기는 추가 입력을 만들므로 **분석 처리량·큐·디스크 부하가 증가할 수 있다.** `no_log`의 경보 출력 억제를 큐 부하 개선으로 설명하지 않는다. JSON의 `event_time_kst`를 넣는 것만으로 Wazuh `frequency/timeframe` 집계가 그 시각을 기준으로 처리되도록 바뀌지 않는다. 실제 엔진의 수신·처리 및 집계 동작, 지연 도착·미래 시각·서로 다른 agent 범위는 별도로 검증한다. **과거 로그를 운영 입력에 재주입하지 않는다.** 재현 시험은 격리한 logtest/검증 환경에서 수행한다.

## 실제 수집 전 남은 작업 (3단계 후보 검증 후 갱신)

1. **원천 운영 회전:** writer별 회전/이전 inode 닫힘과 선택 manifest 수집기 연동의 분리 시험은 통과했다. live copytruncate는 그대로이며 기존 Wazuh 경로의 잔여 읽기·중복 방지와 운영 회전 제어 계층·재시작 복구가 남았다. manifest 없는 CLI는 회전 확인 지점에서 계속 멈춘다. JSONL 부분 행은 처리하지만 여러 줄의 단일 JSON 객체는 지원하지 않는다.
2. **시간 근거·격리 재처리:** 원래 판정과 원문을 보존하는 명시적 WAF 재처리를 구현·검증했다. 근거가 없는/모호한/한도를 넘은 건은 계속 격리하며 대량 트래픽의 근거 확보와 원문 보존 기간을 검증한다. 고정 nft 룰 프로필에 따른 동작 의미 정렬도 별도다.
3. **배출·전달·복구:** source gate→영속 outbox→B inbox→수신증을 구현·검증했다. 활성 파일은 봉인/EOF 검증까지 보류하여 실시간 전달 지연 상한은 보장하지 않는다. Wazuh 전송/분석 수신 확인·자동 정리·유실 커서 복구·예약 재시도는 남았고 용량이 차면 중단한다. inbox 중복 방지를 Wazuh까지 정확히1회 전달하는 보장으로 확대하지 않는다.
4. **운영 부하:** 최대 용량·프로세스 강제 종료·일부 파일 장애는 합성 시험했고 실제 제한 표본도 통과했다. 장기 입력률, 디스크 부족/전원 장애, 원천 보존 기간 초과와 지연 지표를 운영 조건에서 확인해야 한다.
5. **Wazuh 격리 검증:** 기존 설치 엔진의 JSON decode·동적 필드는 사전 시험을 통과했다. 신규 기초 level1/no_log·상관 룰·과거 재생/이중 집계 방지·실제 agent/Indexer 전달·시간창/빈도/큐 부하와 기존 경보 회귀는 후속이다. 새 시간 근거 메타데이터가 포함된 운영 전달을 검증했다고 간주하지 않는다.

현재 완료 범위는 전체285회귀, 제한된 A 표본의 별도 스풀 저장/재오픈과 B inbox 전달·수신 확인, WAF4건의 명시적 재처리, 이전 B Wazuh JSON 필드 디코딩이다. 수집기·전달기·새 상관 룰·운영 입력은 상시 배포하지 않았다. [수집기 계약](COLLECTOR.md) · [최신 전달 검증](delivery-validation-2026-10-14.json).
