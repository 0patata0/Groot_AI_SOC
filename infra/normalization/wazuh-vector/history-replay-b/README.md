# 보존 history의 분석 대상 판정과 B 색인 확인

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

**2026-10-14 18:56 KST 후속 완료:** B의 상관 디코딩/판정 작업자를 각각1개로 적용하고 같은 manager를1회 재시작했다. 기존104규칙 전후 검사와 실제001 경로20회·260행 단일 입력에서 manager40/Indexer40·100293/100294각20·strict TLS/57shard/사건정보 일치·부정대조0을 확인했다. 규칙 내용은 유지했다. 적용 후60초 자연입력60건에서drop증가0/queue표본0이며, 격리500EPS의queue24%·최대지연10.04초 한계는 남는다. 장기 무손실·지속500EPS 보장은 별도다. [적용·종단 검증](../correlation-fix/deployment-resume-2026-10-14.json). 아래는 이전 시점 기록이다.

**2026-10-14 18:18 KST 후속:** 검증기 고정ID 가정을 수정해47개 합성 및 기존 회차 대조를 통과했다. 각30,000행 격리 부하에서 worker1/1은 상관4,000건 전부 생성했고 자동설정은1,362건이었다(양쪽 입력drop0). 1/1은500EPS 시험 중queue최대표본24%·최대관측지연10.04초가 있어 지속처리량 보장과 구분한다. 운영 두옵션 변경안은 준비했지만 배포 검증94파일의B 반입이 자동 승인 검토에서 거절되어 사용자 전송 승인 대기다. 운영옵션/규칙/서비스 변경과 실제001 새burst는 아직 없다. [보완·검증·남은 적용](../correlation-fix/README.md). 아래는 이전 기록이다.

**2026-10-14 13:12 KST 상관 누락 조사:** 격리한 실제 Wazuh의 사전 logtest 없는 자동 설정 20회에서 100293 누락 8회·100294 누락 7회를 재현했다(중복 2회). 1/1 작업자 대조 20회는 정상이며, 40회×13행의 archives 원문과 최종 판정/alerts를 전수 대조했다. 병렬 판정의 순서 경쟁이 유력하지만 agent 000 직접 큐 시험이므로 과거 운영 001의 세부 원인 확정·운영 누락률·완전 해결로 확대하지 않는다. 검증기의 반복 경보 eventID0005 고정 가정도 별도 문제로 확인했다. 다음은 그 검증기 보완과 판정 병렬도 후보의 부하 검증이며, 운영 설정·규칙·서비스는 유지했다. [근거·실측·후속](../correlation-diagnosis/README.md). 아래는 이전 기록이다.

2026-10-14 작업. 기존 도구와 권한만 사용하며 원문·journal cursor는 Mac으로 반출하지 않는다. B 파일 보관 수신증, 격리 분석 결과, 실제 Indexer 문서는 서로 다른 증거다. 이 폴더의 스크립트는 운영 입력·규칙·색인에 쓰지 않는다.

## 1,481건의 현재 판정

A에 보존하고 B로 전달한 두 배치는 1,000건과 481건이다. B `preflight-b.sh`가 11:50:32 KST에 각 원본 payload/manifest SHA와 root0400 보관 상태를 대조했고, MESSAGE 문자열 1,481건 중 현재 nft selector에 맞는 행은 **0건**이었다. A 담당의 기존 Vector 0.59.0 분리 실행에서도 실제 정제 출력은 0건이었다.

따라서 이번 nft 정제 파이프라인의 Wazuh 분석·정제 색인 기대값은 0건이다. 없는 정제 event ID를 만들거나, 일반 kernel 자료에 nft source를 붙이거나, 과거 자료를 `fresh`로 바꾸지 않는다. **현재 selector의 비대상**이라는 판정이며 모든 kernel 로그의 보안·장애 의미가 없다는 내용 검증은 아니다. 원본 두 배치는 계속 보존한다.

현재 운영 ready는 `100200` level 1/`no_log`이고, evidence leaf `100261/100262`는 `fresh` 및 `correlation_eligible=true` 등을 요구한다. 향후 실제 과거 nft 후보가 생기면 A의 원천/정제 SHA와 stable event ID를 결속해 분리 보관하고, 기존 시각·`historical`·`replay` 판정을 유지한다. 해당 행을 기존 운영 수집 파일에 넣는 방식으로 분석하지 않는다.

## 격리 분석과 실제 저장의 구별

Wazuh의 [logtest 도구](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html)는 analysisd의 sandbox에서 decoder와 rule을 시험한다. [세션별 사건 이력](https://documentation.wazuh.com/current/development/wazuh-logtest.html)이 독립이므로 후보를 시험할 수 있지만 그 출력은 운영 alert 생성·Indexer 저장 ACK가 아니다.

향후 정제 후보가 있을 때는 정확한 ready location으로 logtest에 넣고 decoder/rule/level을 전수 대조한다. 과거 자료는 실시간 상관 재료가 되지 않아야 한다. `-U`는 한 행 시험에 적합하며 여러 행은 Phase 1 처리 건수와 rule ID 순서를 별도로 확인한다. logtest에 인쇄되는 전체 사건은 B root 전용 임시 파일에서만 처리한다.

실제 Indexer 존재를 확인할 때는 안정적인 event ID의 [정확한 terms 조회](https://docs.opensearch.org/2.19/query-dsl/term/terms/)를 사용한다. 원천 시각이 오래됐다고 최근 처리시각 범위로 잘라 조회하지 않는다. 요청·응답은 유한 크기로 제한하고, `allow_partial_search_results=false`, timeout 없음, 실패 shard 0, 정확한 전체 건수와 반환 ID 집합을 확인한다. 중복 문서도 별도 계수한다. 조회 결과 0은 현재 보관 인덱스의 일치 문서 부재이며, 과거 raw 수신 유실이나 원천 journal 전체의 완전성을 증명하지 않는다. 실제 후보가 0인 이번 배치에는 존재하지 않는 ID 집합의 조회를 성공 시험으로 세지 않는다.

## 별도의 합성 전송 경로 확인

부모 작업자가 승인된 기존 canary 전용 파일에만 합성 13행을 추가한다. 이 행은 보존한 1,481건과 관련 없는 검증 자료다. 원시 로그, ready, evidence 파일에는 넣지 않는다. 시행 전 B 실제 설정에서 Active Response/integration 각각 0, canary leaf level 3·`no_email_alert`·`no_full_log`, SOC report/summary 최소 level 5·monitor 기본 10을 확인했다. 새 계정·권한·패키지는 추가하지 않았다.

- `preflight-b.sh`: 고정 B 배치 SHA/대상 건수, manager 설정과 현재 SOC Python 소스 AST의 최소 등급을 읽는다. Python은 기존 표준 라이브러리를 한 번 호출할 뿐 상시 서비스를 추가하지 않는다.
- `verify-retained-canary-b.sh [32자리 run_id]`: 생략 시 과거 성공 run을 조회한다. 기존 Indexer 컨테이너의 CA와 관리자 클라이언트 인증서를 내부에서 사용하고 **인증서·hostname 검증을 유지**한다. 정확한 run의 모든 검색 결과가 2건, 규칙 `100293/100294`, level 3, agent `001`, canary location, 알려진 두 event ID인지 검사한다. manager는 현재 `alerts.json` 마지막 10,000행·16MiB 이내에서 같은 증거를 찾는다. 과거 자료가 이 범위에 없으면 실패하며 이를 과거 분석 자체의 실패로 단정하지 않는다. 쓰기는 수행하지 않는다.
- `native-canary-b.sh`: 기존 네 합성 fixture의 writer 변환을 재현한 뒤, 13행 연속·각 scenario·cross 역순·순서 변경을 서로 다른 logtest 세션에서 분석한다. 운영 입력으로 재발행하지 않는다.

### 11:51 이후 새 run에서 확인된 불일치

새 run `5f54ed9eb8c9fdd4586cfb97fd4f6cdd`의 A 입력은 부모가 13행·11,528bytes를 추가했다. 후속 A 대조에서 fixture 변환과 정확히 같고 시나리오 건수 5/2/5/1, 파일 EOF까지 읽은 것을 확인했다. EOF는 원격 ACK가 아니다.

B 엄격 조회는 **manager 1건 / Indexer 1건**, 규칙 `100293`, event ID 끝 `0005`를 확인했다. 검색은 57/57 shard 성공, timeout 없음, total relation `eq`였다. 따라서 발견된 경보의 색인 전달은 일치했지만 기대한 cross-source `100294`는 manager 단계부터 확인되지 않았다. 전체 2건 종단 성공으로 기록하지 않는다.

11:56:43 KST의 8개 native 순서 시험에서는 13행 연속도 `100293+100294`를 만들었고 cross 2행 단독도 `100294`를 만들었다. cross-first와 duplicate-first도 같은 두 leaf가 나왔다. 반대 순서 N→S에서는 `100292,100291`만 나왔으며 단방향 cross 조건에 부합한다. 규칙·컨테이너는 변경하지 않았다. fixture 조합 오류는 재현되지 않았고, 실제 전달/처리 순서 차이는 추가 확인 대상이다. 이 결과만으로 패킷 유실이나 analysisd 순서 역전을 확정하지 않는다.

새 시험은 부모가 순서를 조율한다. 추가 입력 전에 run ID를 새로 정하고 기존 부정 사례와 합성 출처를 유지한다. 처리 간격만으로 수신 ACK나 엄격한 순서를 보장한다고 설명하지 않는다.

### 12:00:39 KST 간격을 둔 새 run 성공

부모는 새 run `96803cd646c5fb8e85833f2cb859b267`에서 기존 합성 13행을 앞 6행·뒤 7행으로 나누고 사이에 3초를 두었다. B strict 조회는 manager 2건과 Indexer 2건, `100293/100294` level 3 및 정확한 두 event ID를 확인했다. 57/57 shard 성공, timeout 없음, total relation `eq`였다. 기존 CA·hostname 검증을 유지했고 규칙 파일·manager/indexer 컨테이너 ID는 불변이었다.

직전 12:00:20 aggregate 상태에서 analysisd `events_dropped=0`, remoted `discarded_count=0`, `dequeued_after_close=0`, 확인한 queue usage는 0이었다. 사건별 ACK가 아닌 조회 시점의 집계 수치다. 3초 간격의 성공은 이번 합성 경로의 관찰 결과이며, 앞선 실패 원인이 순서 역전임을 확정하거나 임의 부하에서 엄격한 순서·무손실을 보장하지 않는다.

정확한 시각·숫자·소스 SHA와 실패 기록은 [validation-2026-10-14.json](validation-2026-10-14.json)에 함께 남긴다. 과거 1,481건은 정제 후보 0건으로 판정했고, 현재 송수신 경로는 별도의 합성 사건으로 검사했다.

## 일괄 시험 불일치의 남은 조사

운영 shadow 규칙은100230/100231 양방향이지만 시험100294는 Suricata 선행→nft 후행 한 방향이다. Wazuh4.14.8의 [decode·rule worker 구성](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/analysisd.c#L1001-L1008), [규칙 판정 후 사건 상태 등록](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/analysisd.c#L2055-L2065), [기존 사건 목록 검색](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/eventinfo.c#L91-L122)을 보면 파일의 행 순서와 선행 상태 등록 완료 순서가 달라질 가능성이 있다. 이는 공식 소스에 따른 가설이며 이번 실제 행별 수신·처리 순서를 측정한 원인 확정이 아니다.

후속 검증은 격리 manager에서 실제 worker 구성과 decode/rule worker 각1개인 구성을 비교하고, 새 run별 burst·역순·간격 입력의 수신 건수와 경보 건수를 따로 세는 방식이 적절하다. 운영 thread를 임의로 줄이지 않는다. 기존 개별 evidence의 Indexer 사건시각 집계는 Wazuh 선행 상태 의존과 구분하며, 역방향 시험 규칙 추가만으로 동시 처리 경계를 해결했다고 주장하지 않는다.
