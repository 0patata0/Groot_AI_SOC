# infra — Docker 기반 배포 (B-1)

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 현재 구성은 A/B/C 역할 분리·MCP6서버·HTTP3/터미널3·단일 deploy.sh(service schema9)다.6CVE 공격·탐지 시험은 사용자 지시로 보류하고 LLM 진단/알림 실패 보완과 문서 정리를 우선한다. 실제 검증 범위와 새 서버 설치 제외를 함께 확인한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

> 2026-10-15: 채팅 인증서 만료 감시를 A(매일09:00KST)에, 전용 XML 디코더·규칙100300~100305를 B에 적용·검증했다. 만료일2027-01-06 15:02:33KST, 갱신은 수동이다. [현재 구성·갱신 절차](groot-a/certificate-monitor/README.md). 아래 기록은 해당 시점의 이력이다.

## 2026-10-15 02:15 KST 최신 상태 — 3단계 운영 검증·타이머 활성화 완료

**02:15:39 KST 원본 회전 운영 전환과 자동 실행 확인을 완료했다.** Suricata·WAF 원본 타이머 두 개의 첫 실행은 회전 불필요(`not_due`)로 정상 완료됐고, 출력 유지관리의 정상 daily 실행에서는 ready·evidence·telemetry 세 파일을 회전했다. 빈 quarantine은 유지했다. 이어 유지관리 타이머만 다시 활성화해 첫 실행 `not_due`·추가 회전 0회를 확인했다. 세 타이머 모두 enabled/waiting이다.

최종 Vector는 **PID 2406117 / Invocation `12314ddc66e14e0083b08db2e51fc831`**로 정상 실행 중이며 Wazuh logcollector **1909632**, WAF master **2377669**·healthy와 원천 state **Suricata gen1/revision5, WAF gen3/revision11 active**는 유지됐다. pending 부재, 양 시작 가드와 수집·저장 상태 검사를 통과했다. 원본과 native checkpoint를 수동 수정하지 않았다. [운영 결과와 한계](normalization/vector/raw-operations/README.md) · [검증 메타데이터](normalization/vector/raw-operations/resume-validation-2026-10-14.json).

최종 소스·증거의 영구 보관과 임시물 정리를 완료했다(아래 정리 후속 기록). **4단계는 구현 준비 중이며 운영 전환은 아직 없다.** 인증서 관리는 마지막 순서다. 실제 호스트 재부팅, 새 CID의 WAF 재생성, 이번 구간의 새 적격 보안 사건 ACK는 검증하지 않았다. EVE·audit만 copytruncate에서 제외했고 Suricata 부가 로그와 WAF 보조 access의 기존 정책은 유지한다. 아래 기록은 각 시점의 이력이며 최신 상태는 이 항목을 따른다.

**02:19:46 KST 정리 후속:** A의 작업 자료 515파일·4,621,609B와 격리 시험 자료 8파일·98,071B를 보관한 뒤 stage3·시험 fixture·미사용 v1 recovery guard를 제거했다. migration 시작 가드는 유지했고 정리 전후 운영 상태 불변·서비스 신호 0회를 확인했다. Mac의 해당 임시 트리 650파일·55디렉터리·5,318,295B와 B 조회 임시파일 2개도 제거했으며 영구 증거는 유지했다. **이 문구는 267파일·2,077,701B 소스 스냅샷 이후에 추가한 기록**으로 그 스냅샷에 포함된 문서 바이트와 구분한다. **02:20:55 KST 최종 점검도 완료했다.** 두 migration guard는 ready이며 storage 정상·Vector active·recovery=no·collection=[]·binding 검증 및 상태 코드 없음, 세 타이머 enabled/active/waiting을 확인했다.

## 이전 시점 기록 — 2026-10-15 최신 운영 상태 — 원본 회전 적용, timer 활성화 대기

A에 원본 회전 controller와 WAF v2를 실제 반영하고 초기 migration seq18·reader 인계를 마쳤다. 두 원천의 실제 회전 결과는 **Suricata gen1 / revision 5 active**, **WAF gen3 / revision 11 active**다. **01:48:58 KST WAF의 같은 CID 재시작 1회**도 정상 종료·복귀를 통과했다. 새 master PID는 **2377669**, UID101·healthy이며, Vector **2368467**와 Wazuh logcollector **1909632** 및 두 raw state는 유지됐다. [운영 전환·검증과 한계](normalization/vector/raw-operations/README.md) · [현재 WAF v2 계약](normalization/vector/waf-producer-v2/README.md).

원본 `eve.json`과 `audit.log`만 legacy copytruncate에서 제외했다. Suricata `fast.log`·`stats.log`·`suricata.log`와 WAF `capstone-access.log`는 기존 copytruncate를 유지한다. WAF v2 정제는 감사 행의 context를 사용하며 access는 보조 원본이다. **원본·출력 회전 timer는 아직 disabled이며 활성화 사전 검사 2회, enable 0회**다. 따라서 자동 운영까지 완료했다고 표시하지 않는다.

실제 호스트 재부팅은 **0회**, 이번 관찰 구간의 자연 적격 보안 사건 ACK 표본도 **0건**이다. 로컬 처리 위치를 manager/Indexer 수신 확인으로 확대하지 않는다. 4단계 Hermes 운영 변경은 미착수이며 읽기 전용 사전 확인만 했고, 인증서 관리는 마지막 순서다. 아래 미배포·copytruncate 유지·후속 예정 문구는 각각의 과거 기준이며 현재 상태는 이 항목을 우선한다.

### 2026-10-14 당시 마감 기록

**2026-10-14 23:03:49 KST 마감 기준:** 사용자 요청에 따라 현재 작업 범위에서 마감한다. A 라이브 확인에서 이전 부트 자동 보존은 **10,323건·4,362,173B**(complete 6 / ready 3 / blocked 0)이며, Wazuh 원본 두 입력에는 `only-future-events=no`, `max-size=2GB`가 적용돼 있다. 관련 서비스는 정상이다.

원본 회전 controller와 WAF v2는 **미배포**이며 기존 copytruncate·WAF v1을 유지한다. 3단계 운영 전환·영속 복구는 미완료이고, 미완성 cutover CLI는 exit 78로 실행을 차단한다. 4~6단계는 착수하지 않았으며 인증서 관리는 마지막 순서다. 재개 조건은 [원본 회전·복구 현황](normalization/vector/raw-operations/README.md)을 따른다. 아래 내용은 이전 시점의 기록이다.

## 2026-10-14 19:38 KST 후속 — Indexer 시간 경계 보완 반영

Imperva/언어가드 기존로그 점검을마치고, 같은Indexer모니터를300초후보·정확60초sliding v2로갱신했다. native검색41개·lifecycle4단계·응답guard66개를통과했으며ID/권한/actions0·서비스/기존Wazuh룰은유지한다. 현재관리명령/검증/복구는 [v2운영안내](normalization/wazuh-vector/indexer-native/window-v2/OPERATIONS.md)를따른다. 자연스캔·최근Hermes사용표본은없어효과관찰대기다. 다음은WAF두reader회전격리→인증서관리이고장기지연/영속복구/정확히1회는별도다. 아래내용은각시점의기록이다.

## 운영 분석기 1/1 적용·실제 20회 종단 검증 완료 (2026-10-14 18:56 KST)

B의 `analysisd.event_threads=1`, `analysisd.rule_matching_threads=1`을 18:48:55 KST에 적용하고 **같은 manager 컨테이너를 한 번 재시작**했다. 기존 native 규칙 104개를 적용 전후 각각 통과했으며, 18:49:04의 새 analysisd PID는 `2132985`, 전체 스레드는 44개다. 다른 컨테이너와 보호 해시는 유지됐다. canary 없는 60.000186초 운영 관찰에서 수신 60건(약 1 EPS), drop 증가 0, queue 최대 표본 0, 단일 코어 대비 CPU 약 0.0333%를 확인했다. [적용·관찰 증거](normalization/wazuh-vector/correlation-fix/deployment-resume-2026-10-14.json).

사용자 명시 승인 후 실제 A agent001→B manager→Indexer의 **20회 × 13행(260행)** 시험을 18:56:08 KST에 완료했다. 동일 20개 run ID를 각각 한 번만 입력해 **manager 40건/Indexer 40건**, `100293` 20건·`100294` 20건, level 3·negative 경보 0건을 확인했다. 57/57 shard·strict CA/호스트명·각 run 및 전체 canonical tuple이 일치했으며 첫 조회 회차 11.3초, 입력 재시도 0회였다. A 원래 52행 접두 구간·inode·보호 설정과 B 옵션·룰·CID·SOC 안전 조건을 보존했다. 이 결과는 승인된 20회 시험의 성공이며 일반 트래픽의 장기 무손실 보장은 아니다. 기존 격리 1/1은 경보 4,000/4,000을 생성했지만 500 EPS 부하에서 queue 최대 표본 24%·최대 archive 관측 지연 약 10.04초가 있어 지속 처리량 보장은 아니다. [격리 부하와 한계](normalization/wazuh-vector/correlation-fix/LOAD-VALIDATION.md). 아래의 미배포·반입 대기 설명은 이전 시점 기록이다.


**2026-10-14 18:18 KST 후속:** 검증기 고정ID 가정을 수정해47개 합성 및 기존 회차 대조를 통과했다. 각30,000행 격리 부하에서 worker1/1은 상관4,000건 전부 생성했고 자동설정은1,362건이었다(양쪽 입력drop0). 1/1은500EPS 시험 중queue최대표본24%·최대관측지연10.04초가 있어 지속처리량 보장과 구분한다. 운영 두옵션 변경안은 준비했지만 배포 검증94파일의B 반입이 자동 승인 검토에서 거절되어 사용자 전송 승인 대기다. 운영옵션/규칙/서비스 변경과 실제001 새burst는 아직 없다. [보완·검증·남은 적용](normalization/wazuh-vector/correlation-fix/README.md). 아래는 이전 기록이다.

**2026-10-14 13:12 KST 상관 누락 조사:** 격리한 실제 Wazuh의 사전 logtest 없는 자동 설정 20회에서 100293 누락 8회·100294 누락 7회를 재현했다(중복 2회). 1/1 작업자 대조 20회는 정상이며, 40회×13행의 archives 원문과 최종 판정/alerts를 전수 대조했다. 병렬 판정의 순서 경쟁이 유력하지만 agent 000 직접 큐 시험이므로 과거 운영 001의 세부 원인 확정·운영 누락률·완전 해결로 확대하지 않는다. 검증기의 반복 경보 eventID0005 고정 가정도 별도 문제로 확인했다. 다음은 그 검증기 보완과 판정 병렬도 후보의 부하 검증이며, 운영 설정·규칙·서비스는 유지했다. [근거·실측·후속](normalization/wazuh-vector/correlation-diagnosis/README.md). 아래는 이전 기록이다.

**2026-10-14 12:00 KST 검증:** A/B 보존 이전 boot 1,481건을 전수 대조했고 현재 nft 정제 후보는 0건이었다. 실제 보안 정제·색인 대상도 0건이며 운영 재주입은 하지 않았다. 별도 합성 대조14건 및 Wazuh native 순서8종을 검증했다. 새 간격 시험에서는 manager2건·Indexer2건의 정확 ID와57/57shard 성공을 확인했다. 앞선 일괄 시험의 manager1건/Indexer1건은 기대값 미달로 보존하며 누락 원인은 미확정이다. [검증 범위와 결과](normalization/vector/history-replay/README.md). 후속 Suricata 격리 시험은 지연 공개 방식에서 Vector/Wazuh 각각6건·중복0, 연속2회전·정상재시작을 통과했다. 단순 rename 대조군은2건 누락을 재현했다. 운영 copytruncate는 유지하며 다음은 WAF별 검증과 운영 전환/영속 복구 조건 확인이다. [회전 결과](normalization/vector/raw-rotation/README.md). 아래는 이전 시점 기록이다.

**2026-10-14 10:57 KST 후속 완료:** 이전boot 후속481건을 회수해 두배치1,481건/621,820bytes의 A→B 직접 전송·B 파일보관·A 수신증 저장을 검증했다. native 합성144개·실제 합성 응답유실 재시도 및 실제배치 해시/고유cursor를 확인했고 서비스는 유지됐다. Wazuh/Indexer ACK·전체무손실·운영 재주입을 뜻하지 않는다. 다음은 격리 정제와 Suricata→WAF raw 회전 검증이다. [실측과 운영 경계](normalization/vector/history-transfer/README.md). 아래 내용은 이전 기록이다.

**10/14 06:09 후속:** 실습망 Imperva `.9`의 정상 점검 두 형태에만 [좁은 WAF 예외](groot-a/imperva-exception/README.md)를 적용했다. 별도 Vector evidence와 Wazuh100260~100262를 연결해 자연 Suricata1건의 manager/Indexer 일치를 확인했고, 두 reader의 실제 출력 회전도 성공했다. [입력·보존 결과](normalization/vector/EVIDENCE.md)와 [관측 모니터 상태](normalization/wazuh-vector/indexer-native/README.md)를 따른다. 아래 기록은 각각 이전 시점이다.

**10/14 04:54 후속:** Suricata의 고정 형식 stats만 Wazuh 전송에서 제외해 JSON 필드 초과 오류를 해결했고, 약 29분간 재발 0건을 확인했다. Vector의 숫자 기반 수집 감시·원문 포함 진단 제한·Wazuh 100246~100251을 적용하고 실제 출력 회전과 재적용 changed=0을 확인했다. 공격 상관은 no_log를 유지한다. 기존 Indexer 후속 후보와 Hermes 복구·시작 전 준비는 [현재 상태](../STATUS.md)와 [다음 순서](../PLAN.md)를 따른다.

**10/14 후속 1~4번 적용:** WAF 최소 access/배포 ID와 Vector 결합 정제를 추가했고 통합 native89개 검사를 통과했다. [출력 보관](normalization/vector/STORAGE.md)은 실제 회전·보관 해시로 검증했다. [Wazuh 상관](normalization/wazuh-vector/CORRELATION.md)은 no_log 관찰 상태이며 전용 canary의 manager→Indexer 2건을 확인했다. [Hermes 자동화](automation/ansible/hermes-guard.md)는 Ansible·재생성 감지 timer·metadata 관찰로 이관했다. 5번 추가 도구 도입은 보류하며, 아래 첫 도구 전환 내용은 후속 전 상태다.

**10/14 도구 전환 적용:** A의 [Vector 0.59.0](normalization/vector/README.md)이 Suricata·nftables 별도 정제/KST 출력을 담당한다(WAF는 격리, 정제 미완료). A/B의 운영자 전용 [Ansible 2.21.5](automation/ansible/README.md)로 고정 파일 배포·검증·복구를 관리한다. 기존 승인 MCP/sudo 보호는 유지하고 실제 제한 계정 및 175개 회귀로 확인했다. B Hermes의 한자·일본어 검사는 외부 [regex 패키지](hermes/korean-output-guard.md)로 교체해 회귀51개·설치본12개가 통과했다. LLM의 패키지 설치·컨테이너 구성 권한은 추가하지 않았다. 현재 적용 범위·남은 작업은 [STATUS](../STATUS.md)와 [PLAN](../PLAN.md)을 따른다. 아래 기록은 당시 상태다.

**10/14 00:43 후속:** A→B 별도 inbox4건·응답 유실 포함5회 전송/중복0·수신증4개, WAF 보관 원문4건의 명시적 시간 근거 재처리·원래 판정/ID/원문 보존을 검증했다. 전체285회귀 통과. 운영 Wazuh 입력/copytruncate는 유지하며 다음은 Wazuh 전달·상관/시간창·기존 입력 이중 집계 검증이다. 담당자와 주차 배정은 유지한다. [전달 결과](normalization/DELIVERY.md).

**23:47 회전 후속:** 실제 설치본의 별도 프로세스에서 Suricata 재열기와 WAF 새 감사 경로 전환·이전 요청 지연 기록을 확인했다. root manifest 순차 수집 연결, 전체227회귀·시험 원문11건 보존·재오픈 추가0. 운영 copytruncate는 유지하며 다음은 출력/전달·수신 확인과 기존 Wazuh 경로 이전 검증이다. 시험 자원은 제거했고 담당자·주차 배정은 유지한다. [회전 결과](normalization/ROTATION.md).

> **22:57 수집기 후보 검증:** 전체188회귀·A 임시 저장소 Suricata29/WAF4/nft130 정제·일반 kernel2 보존·재오픈 추가0건. 운영 설정/서비스 불변, 임시 원문/DB 삭제. 다음은 현재 copytruncate를 대체할 엔진별 회전·닫힘 확인 검증이며 Wazuh 운영 연결은 계속 보류한다. [수집기 안내](normalization/COLLECTOR.md).
> **10/13 추가 작업:** 20:51 Hermes 한국어 전송 가드를 최종 배포하고 회귀42개·설치본10개 검증과 Mattermost 재연결을 완료했다. [검사·복구·재적용 안내](hermes/korean-output-guard.md). 상관분석용 [JSONL 정제 모듈](normalization/README.md)은 변환49+검증기13=62회귀·실제 원천 Suricata29/nft200건·설치 Wazuh 디코딩10건 검증을 통과했다. WAF 중복 헤더·무offset 시각 및 수집기/상관 룰 후속 검증 때문에 운영 연결은 보류한다. [21:27 검증 결과](normalization/VALIDATION-2026-10-13.md).
> **21:47 순차 보완:** WAF 입력 어댑터로 중복 Server 헤더 표본4건을 모두 수용했다. 원문·설정은 그대로이며 다음은 시간대 확인 단계다. [1단계 안내](normalization/README.md).
> **22:09 순차 보완:** WAF4건을 Nginx/Docker UTC와 대조해 KST로 변환했고 전체94회귀가 통과했다. 원문/ID/실행상태는 유지했다. 다음은 수집기 구현이며 운영 연결은 미배포다. [시간대 검증](normalization/waf-time-validation-2026-10-13.json).




> **10/13 19:50~19:54 최신 반영:** 기존 `.110` 예외를 유지하면서 `.111`을 추가한 Suricata 부분편집 제안은 실제 diff 게시→관리자 승인→worker 적용을 완료했다. Suricata는 19:50:28 KST에 시작해 19:50:41.988에 룰을 로드했고, 19:51 `applied`·19:54 승인 소비/결과 게시·로드 성공 52,497건·failed/skipped 0을 확인했다. A nft `never_block`의 DGX 두 `/32`는 라이브·영구 반영됐고, Hermes endpoint는 `http://211.170.162.111:11434/v1`로 전환했다(19:51:45 KST 확인). 모델 `qwen3.6:35b`·MCP timeout 420초·대화 DB·`.env`·SOUL·cron은 유지했다. Mattermost WebSocket 재연결·모델 API HTTP 200과 한국어 응답·실제 UID 경유 rule-a/rule-b 각 8개 도구 및 세 룰 대상 조회는 검증했으며, 전환 후 체감 속도와 실제 채팅 왕복은 아직 별도로 측정하지 않았다. 아래의 이전 미검증·대기 기록은 각 당시 상태다. [B 전환·백업](groot-b/README.md) · [실제 부분편집 적용](mcp/rule-change-deploy.md) · [룰 요약](../룰_요약.md).

> **10/13 최신 범위 결정:** 프로젝트 SSL VPN 원격접속과 모바일 푸시는 사용자 요청으로 추후 발전과제에 이관했다. 현재 완료 범위에서 제외하며 추가 조사·구축·시험은 재개 요청 후 진행한다. VPN은 미구축·중첩 접속 호환성 미검증이고 학과의 폐쇄 정책으로 비호환이 예상된다는 것은 사용자 판단이다. Android·iOS 로그인·채팅은 기존 사용자 확인상 성공했지만 푸시는 false·미복구다. 기존 DNS·푸시·A 전달 설정과 목적지 DNS 갱신 타이머는 유지하고 채팅 인증서 갱신 관리도 계속한다. 이번 결정은 문서상 범위 조정이며 새 라이브 점검·배포는 없다. 아래 진행 중·후속 기록은 당시 이력으로 보존한다. [발전과제](../PLAN.md#추후-발전과제-2026-10-13-사용자-결정).

> **10/13 14:29 승인형 운영 추가 배포:** 큰 룰 diff 자동 분할/단일 승인, 고정 서비스 작업, 증거 기반 임시 10분 차단과 유지 60분 결정을 지원한다. 패키지·컨테이너 구성 변경은 제외했다. 신규 도구 읽기·정책 캐시를 검증했으며 실제 신규 승인 실행 E2E는 후속 관찰 대상이다. [운영 범위·한계](mcp/approved-operations.md).

각 ESXi VM(Groot_A/B/C)의 Docker Compose·설정·운영 문서. 아래 배포 순서는 최초 구축 이력이다. 현재 단계와 사양은 [PLAN.md](../PLAN.md), 호스트별 절차는 [A](groot-a/README.md)·[B](groot-b/README.md)·[C](groot-c/C_구축_표준설정.md) 문서를 참조한다.

시각 자료: [현재 배포 네트워크 토폴로지](diagrams/current-network-topology-2026-10-08.png) · [버스형 토폴로지 개념도](diagrams/bus-topology-concept-2026-10-08.png). 버스형 그림은 실제 물리 배선이 아니라 내부망을 설명하기 위한 재배치다.

## 현재 상태 (2026-10-08 라이브 확인·배포 기록 기준)
- B/C의 `ens192` vNIC는 제거됐고 기본 경로는 A(`10.200.10.1`)를 지난다. 외부망 주소 `.231`/`.232`는 과거 설치 주소다.
- A의 FW v2는 적용·확정됐다(`FORWARD=DROP`, `CAPSTONE-FWD` 14룰). WAF의 GROOT 커스텀 룰 마운트·`DetectionOnly`·`nginx -t` 통과와 Suricata의 ET+로컬 `all.rules`·Phase-A 수동 탐지 설정을 SSH로 재확인했다.
- B의 Wazuh 에이전트 000/001/002는 Active다. 신규 FW 접두어·WAF 100200대 전용 분류는 없지만, 보안 이벤트 읽기 조회에서 Suricata 로컬 SID `1000010`→Wazuh `100110`, ModSecurity CRS `920350`→Wazuh `100101`을 확인했다. 나머지 로컬 룰 분류와 시나리오별 공격 트래픽 실발화는 미검증이다. WAF `On`·IPS 인라인 차단 전환은 별도 작업이다.
- B Hermes에는 `wazuh-ro`·`security-events`·`resp`·`rule-a`·`rule-b` 총 5개 MCP 서버가 등록됐다. 10/08 약 12:58 KST 승인 브로커·A/B 룰 변경기·worker를 배포해 HMAC 통신·읽기 조회를 확인했다. 운영 룰 해시는 그대로이며 실제 Mattermost 승인 버튼→룰 적용·복구 E2E는 미검증이다. [MCP 운영 문서](mcp/README.md).
- 채팅 `https://chat.grootlab.duckdns.org`에는 10/08 Let's Encrypt 인증서를 배포했고 A와 Mac의 HTTPS 검증을 통과했다(만료 2027-01-06 15:02 KST). 자동 갱신은 없으므로 2026-12 초 재발급·A 재배포를 준비한다. 사용자 보고상 관리자가 모바일 GlobalProtect 지원을 거절해 모바일 VPN은 검증 경로에서 제외했다. A에 도달하는 학교 내부 Wi-Fi의 Mattermost 앱 로그인은 미검증이다. [인증서 운영 기록](dns/README.md).
- A/B/C 호스트는 `Asia/Seoul`(KST)·NTP 동기화 상태이며, 10/08 재확인했다. B 상태 요약은 09·21 KST다. 일부 컨테이너·원본 로그는 UTC로 표시될 수 있다.
- A의 n8n은 10/08 SSH 점검에서 컨테이너·이미지·서비스·프로세스·일반 설치 경로·5678 수신 흔적이 없어 현재 배포·가동된 근거가 없다. 자동화는 B Hermes·SOC 봇·systemd 타이머가 담당한다.
- A의 Log4Shell 시나리오 경로 토글은 현재 OFF다. 저장소 스크립트에는 `OBS_SEG` 관찰 룰이 있지만 A에 설치된 스크립트에는 없어 재배포·경로 검증이 필요하다.
- 저장소의 [groot-a/docker-compose.yml](groot-a/docker-compose.yml)은 초기 배포 템플릿으로, 위 라이브 WAF 룰 마운트와 Suricata `all.rules`·Phase-A 옵션이 반영되지 않았다. A에 재배포하기 전 라이브 Compose와 대조해야 한다. [10월 6일 기존 기록](../대화기록/2026-10-06.md)과 이번 SSH 재확인 내용을 구분한다.

**2026-10-13 모바일 후속:** 위 10/08 기록 이후 사용자가 Android·iOS 모두 인증서 인식·로그인·채팅 성공을 확인했다. 알림 미수신은 남아 있으며 사용자는 프로젝트 서버의 모바일 푸시 복구를 추가 확인 없이 진행하도록 승인했다. A의 목적지 제한 정책과 B 푸시 설정 작업이 진행 중이고 실제 알림 수신은 아직 검증하지 않았다. 최신 적용 상태·상위 경로 확인 사항은 [B 운영 문서](groot-b/README.md#모바일-푸시--dns-복구외부-https-경로-미확보-2026-10-13)를 따른다.

**11:41:34 KST B 직접 확인:** TPNS HTTPS 주소와 `generic_no_channel`을 미리 반영하고 조회로 확인했으나 `SendPushNotifications=false`는 유지했다. Mattermost는 재시작 없이 healthy였으며 푸시 활성화·실제 수신 완료가 아니다.

**2026-10-13 최종 후속:** 모바일 푸시는 사용자 요청으로 서버 측 준비 상태에서 마무리했고 외부 경로 미확보·비활성·수신 미복구로 보류한다. 이후 승인된 Suricata 커스텀 오탐 예외를 12:32 실제 엔진에 반영해 52,495룰·실패/skip 0을 확인했다. 기존 hot reload 성공 오판 때문에 이번 활성화는 관리 SSH 재시작으로 마무리했고, 결함 수정 helper는 40개 테스트·독립 리뷰 후 12:43 A에 배포했다. 수정본의 무인 적용·실패 복구 E2E는 남아 있다. 실제 LLM 응답 4건에서 대상 네 SID는 0건이나 별도 ET Log4j 두 SID의 경보가 남았다. [최신 상태](../STATUS.md)·[상세 기록](../대화기록/2026-10-13.md)을 따른다.

**13:24 후속 정정:** 남았던 ET 두 SID도 별도 분석·17개 PCAP 검증·지정 승인 후 13:18 자동 적용했다. ET 원본을 보존하는 좁은 local override이며, 수정 worker의 승인→재시작→실제 엔진 확인 경로가 검증됐다. 로드 카운터 52,497·실패/skip 0, 이후 실제 LLM HTTP 200 2건·경보 0건이다. 실제 실패 복구 시험·장기 관찰은 남았다. Wazuh 40704 lv5의 원천인 fwupd 메타데이터 갱신 실패도 조사해 사용자 지시로 A/B `fwupd-refresh.timer`만 중지/비활성화했다. APT·보안 서비스·40704 룰은 유지한다.

```
infra/
├── groot-a/   # 보안장비: nftables(FW, 호스트) + Suricata(IPS) + ModSecurity(WAF)
├── groot-b/   # SIEM+MCP: Wazuh(공식 docker) + MCP Server
└── groot-c/   # 웹서버: DVWA 베어메탈 + CVE 실험 컨테이너 연동
```

## 배포 순서 (요약)
1. 네트워크·게이트웨이(Groot_A 호스트 nftables) → [PLAN.md](../PLAN.md) 1단계와 [A 운영 문서](groot-a/README.md)
2. `groot-a`: nftables 적용 후 `docker compose up -d` (Suricata·WAF)
3. `groot-c`: [C 표준 설정](groot-c/C_구축_표준설정.md)에 따라 베어메탈 DVWA와 Log4Shell 랩 컨테이너 구성·검증. 이전 DVWA/DB/CVE 통합 Compose 초안은 현 배포와 달라 제거했다.
4. `groot-b`: Wazuh 공식 single-node 배포 후 MCP Server, Agent를 A·C에 설치

## 공통 주의 (구축 시 확정 = TODO)
- 이미지 태그는 최신 확인 후 **고정(pin)** 한다(재현성).
- IP(2세그먼트): 내부망 `10.200.10.0/24` — Groot_A=`.1`(NAT GW)·Groot_B=`.10`·Groot_C=`.20`(ens160). A의 외부 `ens192`는 `192.168.16.230/25`(직결 `192.168.16.128/25`, GW `.129`)다. B/C의 옛 외부 주소 `.231`/`.232`는 제거됐다. A의 10443 DNAT 허용 소스와 저장소 `OBS_SEG`는 별도 `192.168.16.0/25`로 설정돼 있어 Kali 주소·라우팅 확인이 필요하다. 외부/DMZ/관리 3세그먼트 분리는 미채택.
- 자격증명·비밀번호는 `.env`로 분리하고 git에 커밋하지 않는다(`.gitignore`).
- 격리 실험 환경 전용. 외부에 노출 금지.
