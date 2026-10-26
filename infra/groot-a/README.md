# Groot_A (groot-sec) — 보안 게이트웨이 구성 요약

> **2026-10-26 접근 정책:** 실습 웹은 모든 출발지 허용, 학과망 `211.170.162.0/24`는 차단 예외·A SSH·Wazuh HTTPS 허용으로 증분 반영했다. 새 포트·B/C 직접 관리 노출은 추가하지 않았다. [검증·재현·잔여](../../STATUS.md).

> 2026-10-24 보완: 오프라인 host 패치, 기존 Java/관리망 격리, root 승인 진입점과 검증 TLS8444/8445를 적용했다. A 필수 컨테이너는 always로 재부팅 복구하며 실습/백업의 중지 상태는 보존한다. 상세 포트·권한·새 설치/기존 이관과 검증 범위는 [설치 안내](../../deployment/bootstrap-guide.md) 및 [STATUS](../../STATUS.md)를 따른다. LLM 추가 검증은 진행 중이다.

> **2026-10-24 직접 재확인:** Suricata는 `-S /rules/all.rules`로 ET+로컬 합본을 읽고 있다. 호스트 합본=ET+로컬 바이트·컨테이너 해시 일치, socket 통계52,497 loaded/failed0/skipped0을 확인했다. 로컬 파일 정의14개(자체12+ET override2)와 엔진 전체 카운터는 범위가 다르며 개별 룰 발화 E2E를 의미하지 않는다. `-S` 자체가 커스텀 비활성이라는 채팅 답변은 잘못됐다. 새 설치기도 같은 all.rules 경로이며 아래9/26 초기 템플릿을 운영에 재적용하지 않는다. [현재 상태](../../STATUS.md) · [공식 -S 의미](https://docs.suricata.io/en/suricata-8.0.2/command-line-options.html).

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../STATUS.md) · [실행 계획](../../PLAN.md).
> A는 외부/내부 관문이며 Suricata는 passive IDS다. DVWA의 DetectionOnly와 실습 HTTP 경로의 WAF 차단/요청별 예외를 구분한다. 이번 TLS 조회의 세 HTTPS 이름 만료는2027-01-13 13:25:12 KST이며 과거 인증서 값은 이력이다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

## Wazuh 시연용 VPN 한시 허용 — 2026-10-19 22:55 KST 검증

`https://wazuh.grootlab.duckdns.org/`의 VPN192.168.15/24 접근을 **2026-10-20 23:59 KST**까지 허용했다. 기존 공인 `chatduck.crt/key` 참조·요청별 UTC 종료 guard·자동 close timer를 적용했고 실제 VPN 로그인/green·조기 종료403·재개·다른웹 정상까지 확인했다. chatproxy 컨테이너와 기존 파일 inode를 유지한 reload이며 B·C 설정 변경은 없다. 저장소의 [chatproxy.nginx.conf](chatproxy.nginx.conf)는 원본 SHA2790ab83… 기준 파일이고 현재 라이브는 [한시 생성기·종료 도구](wazuh-demo-access/README.md)를 반영한 SHAfbee3603…다. [실측 증거](wazuh-demo-access/deployment-validation-20261019.json). 아래VPN거부 설명은 기존 정책 이력이며 예정 종료 후 다시 적용된다.

> 2026-10-15 14:33:38 KST 인증서 후속: 채팅·Log4Shell DuckDNS 이름이 공유하는 `*.grootlab.duckdns.org` Let's Encrypt 인증서를 A `chatduck.crt/key`에 적용하고 Nginx를 한 번 재로드했다. 만료는 **2027-01-13 13:25:12 KST**다. Mac의 시스템 CA 검증에서 채팅 ping200과 Log4Shell HTTPS 경로 최종200을 확인했다. 기본 Log4Shell 주소는 HTTP80으로 유지하고 HTTPS443은 선택 접근이다. 채팅 인증서 감시기는 동일 `chatduck.crt`의 만료를 읽고 수동 실행 exit0을 확인했지만 Log4Shell SNI는 주기 검사하지 않는다. 자동 갱신은 없으며 다음 재발급은 2026년 12월 중순에 준비한다.

> 2026-10-15: 채팅 인증서 만료 감시를 A(매일09:00KST)에, 전용 XML 디코더·규칙100300~100305를 B에 적용·검증했다. 만료일2027-01-06 15:02:33KST, 갱신은 수동이다. [현재 구성·갱신 절차](certificate-monitor/README.md). 아래 기록은 해당 시점의 이력이다.

## 2026-10-15 02:15 KST 최신 상태 — 3단계 운영 검증·타이머 활성화 완료

**02:15:39 KST 원본 회전 운영 전환과 자동 실행 확인을 완료했다.** Suricata·WAF 원본 타이머 두 개의 첫 실행은 회전 불필요(`not_due`)로 정상 완료됐고, 출력 유지관리의 정상 daily 실행에서는 ready·evidence·telemetry 세 파일을 회전했다. 빈 quarantine은 유지했다. 이어 유지관리 타이머만 다시 활성화해 첫 실행 `not_due`·추가 회전 0회를 확인했다. 세 타이머 모두 enabled/waiting이다.

최종 Vector는 **PID 2406117 / Invocation `12314ddc66e14e0083b08db2e51fc831`**로 정상 실행 중이며 Wazuh logcollector **1909632**, WAF master **2377669**·healthy와 원천 state **Suricata gen1/revision5, WAF gen3/revision11 active**는 유지됐다. pending 부재, 양 시작 가드와 수집·저장 상태 검사를 통과했다. 원본과 native checkpoint를 수동 수정하지 않았다. [운영 결과와 한계](../normalization/vector/raw-operations/README.md) · [검증 메타데이터](../normalization/vector/raw-operations/resume-validation-2026-10-14.json).

최종 소스·증거의 영구 보관과 임시물 정리를 완료했다(아래 정리 후속 기록). **4단계는 구현 준비 중이며 운영 전환은 아직 없다.** 인증서 관리는 마지막 순서다. 실제 호스트 재부팅, 새 CID의 WAF 재생성, 이번 구간의 새 적격 보안 사건 ACK는 검증하지 않았다. EVE·audit만 copytruncate에서 제외했고 Suricata 부가 로그와 WAF 보조 access의 기존 정책은 유지한다. 아래 기록은 각 시점의 이력이며 최신 상태는 이 항목을 따른다.

**02:19:46 KST 정리 후속:** A의 작업 자료 515파일·4,621,609B와 격리 시험 자료 8파일·98,071B를 보관한 뒤 stage3·시험 fixture·미사용 v1 recovery guard를 제거했다. migration 시작 가드는 유지했고 정리 전후 운영 상태 불변·서비스 신호 0회를 확인했다. Mac의 해당 임시 트리 650파일·55디렉터리·5,318,295B와 B 조회 임시파일 2개도 제거했으며 영구 증거는 유지했다. **이 문구는 267파일·2,077,701B 소스 스냅샷 이후에 추가한 기록**으로 그 스냅샷에 포함된 문서 바이트와 구분한다. **02:20:55 KST 최종 점검도 완료했다.** 두 migration guard는 ready이며 storage 정상·Vector active·recovery=no·collection=[]·binding 검증 및 상태 코드 없음, 세 타이머 enabled/active/waiting을 확인했다.

## 이전 시점 기록 — 2026-10-15 최신 운영 상태 — 원본 회전 적용, timer 활성화 대기

A에 원본 회전 controller와 WAF v2를 실제 반영하고 초기 migration seq18·reader 인계를 마쳤다. 두 원천의 실제 회전 결과는 **Suricata gen1 / revision 5 active**, **WAF gen3 / revision 11 active**다. **01:48:58 KST WAF의 같은 CID 재시작 1회**도 정상 종료·복귀를 통과했다. 새 master PID는 **2377669**, UID101·healthy이며, Vector **2368467**와 Wazuh logcollector **1909632** 및 두 raw state는 유지됐다. [운영 전환·검증과 한계](../normalization/vector/raw-operations/README.md) · [현재 WAF v2 계약](../normalization/vector/waf-producer-v2/README.md).

원본 `eve.json`과 `audit.log`만 legacy copytruncate에서 제외했다. Suricata `fast.log`·`stats.log`·`suricata.log`와 WAF `capstone-access.log`는 기존 copytruncate를 유지한다. WAF v2 정제는 감사 행의 context를 사용하며 access는 보조 원본이다. **원본·출력 회전 timer는 아직 disabled이며 활성화 사전 검사 2회, enable 0회**다. 따라서 자동 운영까지 완료했다고 표시하지 않는다.

실제 호스트 재부팅은 **0회**, 이번 관찰 구간의 자연 적격 보안 사건 ACK 표본도 **0건**이다. 로컬 처리 위치를 manager/Indexer 수신 확인으로 확대하지 않는다. 4단계 Hermes 운영 변경은 미착수이며 읽기 전용 사전 확인만 했고, 인증서 관리는 마지막 순서다. 아래 미배포·copytruncate 유지·후속 예정 문구는 각각의 과거 기준이며 현재 상태는 이 항목을 우선한다.

### 2026-10-14 당시 마감 기록

**2026-10-14 23:03:49 KST 마감 기준:** 사용자 요청에 따라 현재 작업 범위에서 마감한다. A 라이브 확인에서 이전 부트 자동 보존은 **10,323건·4,362,173B**(complete 6 / ready 3 / blocked 0)이며, Wazuh 원본 두 입력에는 `only-future-events=no`, `max-size=2GB`가 적용돼 있다. 관련 서비스는 정상이다.

원본 회전 controller와 WAF v2는 **미배포**이며 기존 copytruncate·WAF v1을 유지한다. 3단계 운영 전환·영속 복구는 미완료이고, 미완성 cutover CLI는 exit 78로 실행을 차단한다. 4~6단계는 착수하지 않았으며 인증서 관리는 마지막 순서다. 재개 조건은 [원본 회전·복구 현황](../normalization/vector/raw-operations/README.md)을 따른다. 아래 내용은 이전 시점의 기록이다.

## 운영 분석기 1/1 적용·실제 20회 종단 검증 완료 (2026-10-14 18:56 KST)

B는 18:48:55 KST에 디코딩·룰 판정 worker를 1/1로 적용하고 같은 manager 컨테이너만 한 번 재시작했다. 적용 전후 native 규칙 104개와 새 analysisd 44스레드, canary 없는 60초의 수신 60건·drop 증가 0·queue 표본 0을 확인했다. [B 적용·관찰 증거](../normalization/wazuh-vector/correlation-fix/deployment-resume-2026-10-14.json).

사용자 명시 승인 후 A의 실제 agent001 경로에 동일 20개 run ID × 13행, 총 260행을 각각 한 번만 입력했고 **18:56:08 KST에 manager 40건/Indexer 40건**을 확인했다. `100293` 20건·`100294` 20건, level 3·negative 경보 0건이며 57/57 shard·strict CA/호스트명·각 run/전체 canonical tuple이 일치했다. 첫 조회 회차 11.3초, 입력 재시도 0회다. A의 원래 52행 접두 구간·inode·보호 설정과 B 옵션·룰·CID·SOC 안전 조건을 보존했다. 승인된 20회 시험은 완료했으며 일반 트래픽의 장기 무손실을 보증하지 않는다. 격리 1/1의 4,000/4,000 성공과 500 EPS에서의 queue 24%·최대 관측 지연 약 10.04초 한계는 [별도 결과](../normalization/wazuh-vector/correlation-fix/LOAD-VALIDATION.md)로 구분한다. 아래 내용은 이전 시점의 기록이다.


**2026-10-14 12:00 KST 검증:** A/B 보존 이전 boot 1,481건을 전수 대조했고 현재 nft 정제 후보는 0건이었다. 실제 보안 정제·색인 대상도 0건이며 운영 재주입은 하지 않았다. 별도 합성 대조14건 및 Wazuh native 순서8종을 검증했다. 새 간격 시험에서는 manager2건·Indexer2건의 정확 ID와57/57shard 성공을 확인했다. 앞선 일괄 시험의 manager1건/Indexer1건은 기대값 미달로 보존하며 누락 원인은 미확정이다. [검증 범위와 결과](../normalization/vector/history-replay/README.md). 후속 Suricata 격리 시험은 지연 공개 방식에서 Vector/Wazuh 각각6건·중복0, 연속2회전·정상재시작을 통과했다. 단순 rename 대조군은2건 누락을 재현했다. 운영 copytruncate는 유지하며 다음은 WAF별 검증과 운영 전환/영속 복구 조건 확인이다. [회전 결과](../normalization/vector/raw-rotation/README.md). 아래는 이전 시점 기록이다.

**2026-10-14 10:57 KST 후속 완료:** 이전boot 후속481건을 회수해 두배치1,481건/621,820bytes의 A→B 직접 전송·B 파일보관·A 수신증 저장을 검증했다. native 합성144개·실제 합성 응답유실 재시도 및 실제배치 해시/고유cursor를 확인했고 서비스는 유지됐다. Wazuh/Indexer ACK·전체무손실·운영 재주입을 뜻하지 않는다. 다음은 격리 정제와 Suricata→WAF raw 회전 검증이다. [실측과 운영 경계](../normalization/vector/history-transfer/README.md). 아래 내용은 이전 기록이다.

**10/14 06:09 KST evidence 연결:** 기존 localfile10개를 보존하고 별도 evidence 입력을 추가했다. Vector110/jq18/reader9 통과, Vector+storage 두 playbook의 최종 누적 적용 changed5/재적용0. 네 출력·두 Wazuh reader의 실제 회전108초, archive 해시와 수집 재개를 확인했다. 기존 raw 회전은 유지한다. [운영 결과·용량·ACK 경계](../normalization/vector/EVIDENCE.md).

**10/14 05:49~05:50 KST Imperva 점검 오탐 예외 적용:** `211.170.162.9 → 172.18.0.2:8080`의 `GET /` 가운데 CL/TE가 없는 두 관측 형태만 early ModSecurity ID `10020/10021`로 분리했다. HTTP/1.0·Host 없음은920280만, HTTP/1.1·Host `192.168.16.230`은920350만 transaction에서 제외한다. `.9` 전체 허용이나949110/XSS 비활성화가 아니다. 분리 native21개 전후 비교·42요청을 통과한 뒤 같은 WAF master를 reload했고 healthy·loaded862·DetectionOnly·container ID/시작 시각을 유지했다. 정상 loopback HEAD는302, Vector·Wazuh agent·보관/승인 timer는 active였으며 다음 자연 스캔은 아직 미관측이다. [정확한 범위·배포·시험 한계](imperva-exception/README.md).

현재 예외는 기존 컨테이너 writable layer에 있고, 실제 A compose에는 `/etc/capstone-waf/REQUEST-900-CAPSTONE-SCANNER.conf` 파일 하나의 read-only bind를 추가했다. **실제 새 mount와 재생성 검증은 다음 통제된 재생성에서 확인한다.** 저장소 [docker-compose.yml](docker-compose.yml)은 초기 템플릿이므로 그대로 재적용하지 않는다. 주소가 `.2`에서 달라지면 이 예외는 적용되지 않아 기존 탐지가 유지된다.

**10/14 04:54 추가 적용:** Suricata raw의 고정 형식 stats만 native ignore로 전송에서 제외하고 원본 stats/alert는 유지했다. Vector 숫자 telemetry·원문 포함 진단 target 제한·출력 파일 3개의 회전 연결을 완료했다. native 97개/jq 16개 검사, 반복 적용 changed=0, 실제 회전 89.452초, 보관 SHA, 새 heartbeat, agent·보안 엔진·권한 유지를 확인했다. [필터](../normalization/wazuh-vector/stats-filter/README.md) · [수집 경계](../normalization/vector/collection/README.md).

**10/14 후속 적용:** WAF 기존 컨테이너에 최소 access JSON·고정 배포 ID producer를 추가하고 정상 HEAD 요청의 허용12필드·현재 binding을 확인했다. 기존 Nginx master·룰/DetectionOnly는 유지한다. Vector는 audit/access를 결속해 KST로 정제하며 native89개 검사를 통과했다. 출력에는 논리reader/SHA 확인 회전·보존·5분 용량 timer를 적용했다. 원천 copytruncate는 유지하고, 원격 영속 수신증으로 표현하지 않는다. [WAF 계약](../normalization/vector/WAF.md) · [보관](../normalization/vector/STORAGE.md). 아래 첫 적용 설명은 당시 기록이다.

**10/14 적용:** Vector0.59.0의 `capstone-vector.service`를 추가해 Suricata·nftables 공통 JSONL/KST를 `/var/log/capstone-vector/ready/normalized.jsonl`에 출력한다. WAF는 별도 격리로 남겼다. 기존 Wazuh raw 입력8개를 보존하고 정제 localfile1개를 추가했으며 실제 읽기 FD·수집 시작을 확인했다. 운영자 전용 Ansible2.21.5 환경은 `/opt/capstone-automation/venv`이며 LLM sudo/MCP 권한은 그대로다. 01:49 Vector/Wazuh agent/승인 timer active, 기존 helper/sudoers SHA 일치. [Vector](../normalization/vector/README.md) · [Wazuh 입력](../normalization/wazuh-vector/README.md) · [Ansible](../automation/ansible/README.md).

> **10/13 14:29 승인형 운영 추가 배포:** 큰 룰 diff 자동 분할/단일 승인, 고정 서비스 작업, 증거 기반 임시 10분 차단과 유지 60분 결정을 지원한다. 패키지·컨테이너 구성 변경은 제외했다. 신규 도구 읽기·정책 캐시를 검증했으며 실제 신규 승인 실행 E2E는 후속 관찰 대상이다. [운영 범위·한계](../mcp/approved-operations.md).

A = 외부(ens192 192.168.16.230, 캠퍼스 세그먼트) ↔ 내부(ens160 10.200.10.1) 관문. NAT·포워딩·호스트 방화벽·차단 셋·IDS·WAF·NTP 서버·Wazuh 에이전트가 여기 있다.

**프로젝트 망 정의(10/13 사용자 명확화):** 외부는 학과 실습망, 내부는 이미 구성된 `10.200.10.0/24` 서버망과 Docker 가상 NIC·네트워크 영역이다. Docker 가상 NIC 전체가 같은 IP 대역이라는 뜻은 아니다. 새 가상 스위치 구축을 전제로 하지 않는다. 학과망 관리자 단말→프로젝트 SSL VPN→기존 내부 서비스라는 원격근무 모의가 가능하며, 실제 인터넷/학교 상위 방화벽 접속 문제와 구별한다. VPN은 가능성 검토 단계이고 구축을 진행한 것은 아니다.

> **2026-10-13 13:43~13:45 KST WAF 읽기 전용 재확인:** 사용자에게 제시된 LLM 보고를 실제 설정과 대조했다. `/home/groot_a/capstone/secstack/conf/GROOT_A_WAF.conf`는 v1.0.0·22,652바이트·418줄이며 `SecRuleEngine DetectionOnly`는 보고된 99줄이 아닌 **59줄**이다. 저장소·호스트·컨테이너의 SHA-256은 모두 `62c855cf8e927ff57beb11d92daaa7936bbbdc2b035c029535d0da59cce2eebf`다. 기반 설정과 컨테이너 환경도 DetectionOnly이며 포함되는 설정에 활성 `On`·`ctl:ruleEngine`은 없었다. WAF healthy·`nginx -T` 성공·loaded 860, 컨테이너 시작 시각 10/05 19:18:45 KST 유지. 활성 커스텀 ID는 10개이며 `10010`은 주석 예제다. Section 0/ExceptionTable·XSS-002/-003·LFI-003은 없고 RCE도 저장소의 기존 `bash/sh/dash/zsh/ksh` 등과 동일하다. 정확한 확장 후보 diff는 확보하지 못했다. 현재 상태와 저장소의 두 버전이 DetectionOnly라는 사실만으로 서버의 모든 과거 `On` 전환 이력 부재를 단정하지 않는다. 전체 후보 파일은 128KiB까지 허용되고 8KiB 제한은 설명을 포함한 승인 카드 전체 diff에 적용된다. 실제 초과 시 변경 단위를 나누되 각 단계에서 전체 후보 제출·별도 승인·적용 확인 후 다음 기준 SHA를 다시 조회한다. 원래 확장 묶음의 실제 8KiB 초과 여부는 미확인이다. 이번에는 룰·모드·제안·서비스를 변경하지 않았다. [제안 경계](../mcp/rule-change-deploy.md).

> **2026-10-06 기록 및 10/08 SSH 재확인:** FW v2 적용·확정(`FORWARD=DROP`, `CAPSTONE-FWD` 14룰), WAF GROOT 룰 마운트·healthy·`nginx -t` 통과(`DetectionOnly`), Suricata `-i ens192 -S /rules/all.rules` 및 Phase-A(passive). 신규 FW 접두어·WAF 100200대 전용 분류는 없으나 읽기 조회에서 Suricata 로컬 SID `1000010`→Wazuh `100110`, ModSecurity CRS `920350`→Wazuh `100101`을 확인했다. 나머지 로컬 룰 분류와 시나리오별 공격 프로브 발화는 미검증이다. WAF `On`·IPS 인라인 전환은 남아 있다. [기존 확인 기록](../../대화기록/2026-10-06.md)

> **2026-10-08 관리 SSH 직접 재확인:** WAF 커스텀 ID 10개·Suricata 로컬 SID 11개의 라이브 파일 해시가 저장소와 각각 일치한다. WAF는 여전히 `DetectionOnly`, Suricata는 passive이고 인라인 queue 룰은 0개다. FW `FORWARD DROP`·14룰, nft input DROP·output ACCEPT이며 현재 임시 IP 차단은 0건이다. A 브로커 URL·토큰이 설정됐고 A→B 인증된 `GET /pending` HTTP 200이었다(승인→차단 E2E 미시험). [오늘 기록](../../대화기록/2026-10-08.md)

> **같은 날 약 12:58 KST 후속 배포:** A에 별도 `rulechg` SSH 강제 명령·root 소유 고정 대상 helper·`rule-change-worker.timer`를 배포했다(active/enabled). B 승인 브로커와의 HMAC 통신 및 WAF·Suricata 로컬 룰 **읽기 조회**가 통과했다. 두 운영 룰 해시는 배포 전후 동일하다. 실제 Mattermost 승인 버튼→룰 적용·복구 E2E는 아직 검증하지 않았다. [배포 절차](../mcp/rule-change-deploy.md)

> **시간·자동화 구성:** A/B/C 호스트는 `Asia/Seoul`(KST)이며 10/08 NTP 동기화를 재확인했다. 같은 날 A의 n8n은 컨테이너·이미지·서비스·프로세스·일반 설치 경로·5678 수신 흔적이 없어 배포·가동된 근거가 없었다. 자동화는 B의 Hermes·SOC 봇·systemd 타이머가 담당한다.

Log4Shell 경로는 이번 SSH 점검에서 **토글 OFF**(A:8080 NAT·DOCKER-USER 시나리오 룰 없음)였다. 저장소의 `scenario_log4shell_route.sh`에는 C→`OBS_SEG` 관찰 룰이 있으나 A에 설치된 `/usr/local/sbin/scenario_log4shell_route.sh`에는 없다. A `ens192`는 `192.168.16.230/25`(직결 `192.168.16.128/25`)인데, 라이브 10443 DNAT/CAPSTONE-FWD 출발지 제한과 저장소 `OBS_SEG`는 `192.168.16.0/25`다. Kali 주소·왕복 경로를 확인하고 설치본을 동기화한 뒤 시나리오를 검증해야 한다.

| 구성 | 파일(repo → A) | 요점 |
|---|---|---|
| NAT + 포트포워딩 + 호스트 FW 로더 | `fw-v2/capstone-nat.sh` → `/usr/local/sbin/capstone-nat.sh`, `capstone-nat.service`, `99-capstone-nat.conf` | 부팅 시(docker 이후) 실행. `capstone_gw` NAT·대시보드 10443→B:443 DNAT·`CAPSTONE-FWD` 허용목록, `FORWARD=DROP`, nft FW 로드 + 차단목록 복원. 루트의 `capstone-nat.sh`는 이전 버전 소스. |
| 호스트 방화벽 + 차단 | `fw-v2/capstone-fw.nft` → `/etc/nftables.d/capstone-fw.nft` | `inet capstone_fw`: 기존 input/`agent_block` 보호에 anti-spoof(`SPOOF`), `mgmt_src` SSH 레이트리밋(`FW_SSH_RATE`), output 체인 추가. 루트의 `capstone-fw.nft`는 이전 버전 소스. |
| 차단 인터페이스 | `agent_block` → `/usr/local/sbin/agent_block` | `add <ip> [ttl] [reason]` / `del` / `list` / `flush`. exit 0 ok · 2 invalid · 3 rejected(보호 대상·활성 SSH 출발지) · 4 nft 실패. 상태 `/var/lib/capstone/agent_block.state`(재부팅 복원). 전 동작 syslog(tag agent_block)→Wazuh |
| FW v2 적용 이력·향후 재적용 | `fw-v2/fw_apply_v2.sh`, `fw-v2/fw_confirm_v2.sh` | 300초 데드맨 아래 적용·외부 검증 후 확정했고, 10월 6일 타이머 0을 확인. `fw_phase2.sh`/`fw_confirm.sh`는 이전 단계 스크립트. |
| IDS + WAF | `docker-compose.yml`, `deploy_secstack.sh`, `suricata-rules.md`, `../../new_rule/` | WAF는 GROOT 룰을 로드한 DetectionOnly. **10/13 13:18** Suricata 8.0.6 passive, 자체 로컬 SID 12개+ET 두 SID override를 반영했다. 로드 카운터 52,497(높은 rev로 대체한 2개 정의 포함)·실패/skip 0. 승인형 worker가 기존 컨테이너를 재시작해 실제 반영을 확인했다. ET 원본 불변·local `cabbac45…`·합본 `ea160e90…`. 로그 `~/capstone/secstack/logs/`. **저장소 Compose는 초기 템플릿**이므로 라이브 대조 없이 재배포하지 않는다. |
| Wazuh 에이전트 | `install_agent.sh`, `agent_localfile.sh`, `logrotate-capstone-secstack` | ID 001 groot-sec. eve.json·audit.log·journald(커널 nft 로그, agent_block 감사) 수집 |
| NTP 서버 | `ntp_server.sh` | chrony ← 캠퍼스 192.168.16.131, B/C 에 10.200.10.1:123 서비스(`bindaddress`) |
| 응답(차단) MCP 서버 | `../mcp/{response-mcp.py, run-response.sh, deploy_response_A.sh}`, `agent_block_reaper.sh` | 사용자 `resp` + sshd ForceCommand + sudoers(agent_block add/del/list). 에이전트가 `ssh -T groot-resp` 로 block_ip/unblock_ip/list_blocks 호출 → `agent_block`. TTL 만료 리퍼(타이머 `capstone-block-reaper`) → Wazuh 100131. 이번 SSH 점검에서 A의 `/etc/resp/hitl.env`에 브로커 URL·토큰이 설정된 것은 확인했으나 승인 후 차단 종단 간 동작은 재시험하지 않았다. |
| 승인형 로컬 룰 변경 MCP | `../mcp/{rule_change_mcp.py,rule_change_executor.py,deploy_rule_change_A.sh}` | 별도 rulechg·root helper·10초 worker. 12:43 재시작·실제 로드 검증 보완 뒤, 13:16 두 ET override의 정확한 파생본·고정 marker 검증을 추가한 helper `81597b11…`를 배포했다. 13:18 지정 승인부터 worker 재시작·엔진 검증·결과 게시까지 자동 적용 E2E를 확인했다. 실제 운영 실패 복구 E2E는 남아 있다. |
| B 모바일 푸시 목적지 제한 | `capstone-push-egress.py`, `.service`, `.timer`, `capstone-push-egress-nat.conf` | 10/13 11:49 KST 배포. `DOCKER-USER`의 정확한 B→외부 TCP443 jump와 `CAPSTONE-PUSH`만 관리. 기존 NAT 로더 파일은 변경하지 않고 서비스 drop-in만 추가. 아래 운영 절차 참조. |

**fwupd 예약 정리(10/13 13:16):** Wazuh 40704·레벨 5는 A의 `fwupd-refresh.service` 메타데이터 갱신 실패였다. 제한망에서 LVFS HTTPS 시간 초과, 현재 VM의 updatable 장치 0을 확인하고 사용자 지시로 `fwupd-refresh.timer`만 disabled/inactive 처리했다. 해당 실패 표시를 초기화했으나 과거 경보는 보존했다. fwupd 데몬·패키지·APT·보안 서비스는 유지한다. 상태/설정 해시 백업은 `/var/backups/fwupd-refresh-timer-20261013.55af9vmn`, 복구는 `systemctl enable --now fwupd-refresh.timer`다. 이 타이머는 펌웨어를 설치하지 않고 업데이트 목록을 갱신한다.

## B 모바일 푸시용 제한적 외부 연결 정책

**2026-10-13 11:49:12 KST 라이브 배포 완료:** `DOCKER-USER` 맨 앞의 jump 1개가 `10.200.10.10/32`, `ens160`→`ens192`, TCP 목적지 443인 패킷만 `CAPSTONE-PUSH`로 보낸다. 공식 TPNS 이름 `push-test.mattermost.com`의 공인 IPv4만 최대 16개 허용하며, 당시 실측은 목적지 3개 ACCEPT + 최종 DROP 1개였다. `CAPSTONE-FWD`의 기존 ESTABLISHED 허용보다 먼저 검사하므로 기한이 지난 B의 기존 연결도 outbound 패킷은 통과하지 못한다. DGX 11434·DNS 등 다른 기존 허용은 변경하지 않는다.

| 저장소 파일 | A 설치 경로 |
|---|---|
| `capstone-push-egress.py` | `/usr/local/sbin/capstone-push-egress.py` |
| `capstone-push-egress.service` | `/etc/systemd/system/capstone-push-egress.service` |
| `capstone-push-egress.timer` | `/etc/systemd/system/capstone-push-egress.timer` |
| `capstone-push-egress-nat.conf` | `/etc/systemd/system/capstone-nat.service.d/20-push-egress.conf` |

타이머는 5분마다 DNS를 갱신하고 마지막 성공으로부터 최대 1시간만 허용한다. DNS 실패는 기존 `xt_time --datestop`을 연장하지 않으며, 초기 조회 실패는 DROP-only로 닫는다. updater가 중단돼도 UTC 기한을 커널이 검사한다. `capstone-nat.service`의 `ExecStartPost` drop-in이 부팅·서비스 재실행 뒤 helper를 호출하며, **`/usr/local/sbin/capstone-nat.sh` 자체는 수정하지 않았다.** 독립 jump는 기존 로더가 `CAPSTONE-FWD`를 재구성해도 남는다. 갱신은 `iptables-restore --noflush` 한 transaction에서 전용 체인만 명시적으로 비우고 채운다.

배포 백업: `/var/backups/mattermost-push-egress-20261013.o73oufbn`. helper SHA-256: `083d56822e71dc773c308cd470f90036f46690e2c4adcc01ed95f341d434de16`. 라이브 `--check`, 최초 적용, 재적용, systemd 서비스 실행·read-back을 통과했고 타이머 active/enabled·`ExecMainStatus=0`을 확인했다. 다른 filter 규칙과 기존 로더 해시는 배포 전후 동일했다. 당시 기한은 `03:49:11 UTC` = `12:49:11 KST`였으며 이후 정상 갱신 때 이동한다. **이 결과는 A 정책 배포 검증이며 B→TPNS HTTPS 도달이나 실제 모바일 푸시 수신 성공을 뜻하지 않는다.**

**11:49:31 KST 후속 실측:** B의 실제 `mm-app` 네트워크 namespace에서 실행한 푸시 준비 도구 `--check`는 TPNS IPv4 3개 모두 TCP timeout이었다. A `ens160`에서 B의 SYN을 목적지별 5회 수신했고, `ens192`에서 NAT된 SYN을 각각 5회 송신했으나 외부 회신은 0건이었다. `CAPSTONE-PUSH` ACCEPT 카운터도 각 목적지에서 5패킷/300바이트 증가했다. **B→A 로컬 허용 정책 통과는 검증됐지만 상위 경로는 아직 확보되지 않았다.** Mattermost의 `SendPushNotifications=false`를 유지하며 실제 모바일 푸시 수신은 복구되지 않은 상태다.

**11:56:53 KST 자동 갱신 확인:** active/enabled 타이머의 마지막 실행은 `11:54:12 KST`였고, 같은 시각 시작한 서비스의 `Result=success`·`ExecMainStatus=0`을 확인했다. 목적지 3개 규칙의 `datestop`이 모두 `03:54:11 UTC` = `12:54:11 KST`로 이동해 실제 타이머 갱신도 검증했다. 이는 위 외부 연결 timeout 상태를 해소한 결과는 아니다.

운영 확인은 `sudo /usr/bin/python3 -B /usr/local/sbin/capstone-push-egress.py --check`, `systemctl list-timers capstone-push-egress.timer`, `journalctl -u capstone-push-egress.service`, `sudo iptables -S CAPSTONE-PUSH`로 한다. `--check`는 정책을 수정하지 않는다. IP 허용은 같은 CDN IP를 공유하는 다른 HTTPS 호스트나 B 내부 프로세스를 구별하지 못하므로 Mattermost의 TLS 호스트명 검증은 계속 필요하다. 회신 경로는 기존 정책을 따르고 conntrack 세션을 삭제하지 않는다.

이 추가 정책만 제거하려면 A에서 아래 순서로 실행한다. 전체 FW/NAT 재적용이나 전체 ruleset 복원은 하지 않는다. helper는 예상과 다른 전용 규칙·참조를 발견하면 덮어쓰지 않고 중단하며, 적용 후 read-back 실패가 자동 복구를 의미하지는 않으므로 실제 상태를 재확인한다.

```bash
sudo systemctl disable --now capstone-push-egress.timer
sudo systemctl stop capstone-push-egress.service
sudo rm -f /etc/systemd/system/capstone-nat.service.d/20-push-egress.conf
sudo systemctl daemon-reload
sudo /usr/bin/python3 -B /usr/local/sbin/capstone-push-egress.py --remove
sudo iptables -S DOCKER-USER
sudo iptables -S CAPSTONE-FWD
```

제거는 전용 jump와 `CAPSTONE-PUSH`만 대상으로 하며 기존 conntrack 엔트리는 그대로 둔다. 제거 후 기존 `DOCKER-USER`→`CAPSTONE-FWD` jump와 원래 정책이 남았는지 확인한다.

## DuckDNS 채팅 공인 인증서 설치

**2026-10-08 라이브 적용:** `chat.grootlab.duckdns.org` 단일 이름 Let's Encrypt 인증서를 설치했다(만료 2027-01-06 15:02 KST). 배포 스크립트의 SNI·CA 검증 Mattermost ping과 Mac `curl` HTTP 200/인증서 검증을 통과했다. Mac·A의 임시 발급/전송 파일은 삭제했다. Mac ACME 상태도 삭제했으므로 자동 갱신은 없고, 2026-12 초 임시 환경에서 재발급·A 재배포를 준비한다. 사용자 보고에 따르면 학교 관리자가 관리 범위 확대를 이유로 모바일 GlobalProtect 지원을 거절했고 휴대폰 VPN 로그인도 실패했다. 모바일 VPN은 검증 경로에서 제외하며, A에 도달하는 학교 내부 Wi-Fi의 Mattermost 앱 로그인은 미검증이다. [발급·운영 이력](../dns/README.md).

**2026-10-13 후속 확인:** 사용자가 Android·iOS 모두 인증서 인식·로그인·채팅 성공을 확인해 위 모바일 미검증 상태를 갱신했다. 남은 문제는 모바일 알림이며 인증서 재발급은 조치 대상이 아니다. 사용자는 프로젝트 서버의 푸시 복구를 추가 확인 없이 진행하도록 승인했다. 이후 11:49:12 KST A의 B→TPNS 한정 정책을 위와 같이 배포했으며 실제 수신 완료를 뜻하지 않는다. 최신 적용 상태와 상위 경로 확인 사항은 [B 운영 문서](../groot-b/README.md#모바일-푸시--dns-복구외부-https-경로-미확보-2026-10-13)를 따른다.

**2026-10-15 와일드카드 발급·A 적용:** 기존 10/08 인증서는 채팅 이름만 포함해 Log4Shell HTTPS에는 재사용할 수 없었다. Mac에서 DuckDNS DNS-01로 `*.grootlab.duckdns.org` 한 이름을 새로 발급했고 채팅·Log4Shell 호스트명, 신뢰 체인, 개인키 일치를 확인했다. A의 공용 `chatduck.crt/key`에 배포하고 `chatproxy`의 Log4Shell 서버 블록도 같은 파일을 참조한다. Mac 시스템 CA 검증으로 채팅 `/api/v4/system/ping` 200과 Log4Shell HTTPS `/dvwa/login.php`→`/log4shell/` 최종 200을 확인했다. 배포 전 인증서는 `/var/backups/capstone-log4shell-tls/20261015T143336+0900`에 보존했다. 컨테이너 재생성·최종 Docker 네트워크 구성 변경 없이 Nginx 재로드 한 번으로 적용했으며 기존 게이트웨이와 다른 `CAPSTONE-FWD` 규칙은 유지했다. 내부 `*.groot.lab`과 Wazuh의 별도 인증서는 이 인증서의 적용 대상이 아니다. 기존 10/08 발급 기록은 당시 이력으로 유지한다.

ACME·DuckDNS HTTPS에 도달할 수 있는 장치에서 DNS-01 방식으로 **`*.grootlab.duckdns.org` 한 이름**의 인증서를 발급한다. A는 발급에 필요한 외부 HTTPS에 도달하지 못하므로, 발급된 `fullchain.pem`과 암호 없는 `privkey.pem`을 A에 안전하게 복사한 뒤 다음 명령을 A에서 실행한다. 개인키와 DuckDNS 토큰은 저장소에 넣지 않는다. Mac에는 발급 도구·계정 상태를 영구 설치하지 않고 임시 전용 디렉터리를 배포 후 정리한다.

```bash
sudo bash deploy_chatduck_cert_A.sh --check-only /root/certs/fullchain.pem /root/certs/privkey.pem
sudo bash deploy_chatduck_cert_A.sh /root/certs/fullchain.pem /root/certs/privkey.pem
```

`deploy_chatduck_cert_A.sh`는 채팅 호스트명 SAN·남은 유효기간·키 일치·신뢰 체인을 검증하고, 기존 `chatduck.crt/key`를 권한 제한 백업한 뒤 두 파일을 교체한다. 이어서 `nginx -t`, 재로드, 실제 채팅 SNI 인증서와 CA 검증 Mattermost ping을 확인하며, 실패하면 기존 파일을 복원하고 다시 재로드한다. **Log4Shell 이름과 HTTPS 응답은 이 스크립트의 자동 검증 범위가 아니므로 별도 확인**한다. `chat.groot.lab`·Wazuh 인증서 및 대시보드 허용목록은 건드리지 않는다. 갱신된 인증서도 같은 절차로 다시 배포해야 한다.

스크립트의 체인 검증은 **A 호스트의 신뢰 저장소 기준**이다. 새 휴대폰의 접속 확인이나 인증서 갱신 후 검증은 A `192.168.16.230`에 도달하는 학교 내부 Wi-Fi에서 브라우저로 `https://chat.grootlab.duckdns.org/api/v4/system/ping`을 확인한 뒤 Mattermost 앱에 같은 채팅 서버 주소로 로그인하는 순서다. 기존 Android·iOS 성공은 위 10/13 사용자 확인을 따르며, 휴대폰 GlobalProtect 로그인 실패의 기술적 원인은 채팅 인증서 결과와 구분한다.

## 자주 쓰는 명령 (A에서, sudo)
```
agent_block add 203.0.113.7 10m alert:1790431732.31   # 차단(사유는 감사용)
agent_block list ; agent_block del 203.0.113.7
nft list table inet capstone_fw                        # 현재 방화벽
journalctl -k -g 'AGENT_BLOCK|FW_DROP_IN|SPOOF|FW_SSH_RATE|FW_DROP_FWD|FW_SHADOW_OUT' -n 20  # 경계/FW v2 로그
systemctl restart capstone-nat                         # NAT/포워딩/FW 전부 재적용(차단목록 보존)
systemctl list-timers capstone-block-reaper.timer      # TTL 만료 감사 리퍼(60s)
```
응답 MCP 서버는 에이전트가 `ssh -T groot-resp` 로 호출(운영자가 직접 쓸 일은 없음; 수동 차단은 위 `agent_block`).

## 절대 하지 말 것
- `nft flush ruleset`, `nft -f /etc/nftables.conf`, `systemctl unmask/start nftables` — Docker·NAT·FW 전부 날아감(`nftables.service`는 mask 되어 있음).
- `never_block`(내부망·Docker·lo·A·GW·ESXi·NTP·DNS·관리 VPN 대역·구 B/C 외부 IP)을 라이브 접속 경로 검증 없이 좁히기. raw 훅이라 기존 SSH 세션도 즉시 끊길 수 있다.
- 캠퍼스 VPN 경유로 공격 트래픽 보내기(캠퍼스 FW가 쌍 차단).

## 프로젝트 SSL VPN 검토 — 미구축

학과 실습망을 외부 역할로 사용하는 기존 망에 VPN 진입 기능을 추가하는 시나리오다. 학과망에 직접 연결한 관리자 단말은 프로젝트 VPN 하나를, 재택 단말은 학교 GlobalProtect 위에 프로젝트 VPN을 중첩하는 구성을 검토할 수 있다. 중첩 구조는 가능하지만 현재 단말/학교 정책의 동시 연결 지원은 미확인이다. A `192.168.16.230`의 접속 경로는 학교 VPN을 유지하고 두 번째 VPN은 `10.200.10.0/24` 등 필요한 내부 목적지만 처리해야 한다. 실제 포트 도달성·기존 443 점유·주소풀/라우팅/DNS 충돌을 구축 전에 검증한다. 이번 상담에서는 설치나 설정 변경을 하지 않았다. [질문·공식 근거·제약 기록](../../대화기록/2026-10-13.md).

**2026-10-13 후속 결정 — 추후 발전과제로 보류:** 사용자는 학과망의 폐쇄적 정책 때문에 이중 SSL VPN이 호환되지 않을 가능성을 들어 프로젝트 SSL VPN 원격접속 시나리오를 현재 완료 범위에서 제외했다. 이는 사용자 판단에 따른 보류이며 실제 비호환을 확인한 결과는 아니다. VPN은 미구축, GlobalProtect와의 동시 연결은 미검증 상태로 남긴다. 모바일 푸시 복구도 같은 날 추후 발전과제로 분류했다. Android·iOS의 로그인·채팅 성공은 앞서 사용자가 확인했으나 푸시는 미복구이며 `SendPushNotifications=false`를 유지한다. 이번 결정으로 기존 A/B 설정·타이머는 변경하지 않고 추가 구축·활성화·수신 검증을 보류한다. 상위 방화벽 정책은 프로젝트에서 직접 변경할 수 없다.

## 포트 정리 (ens192 기준)
22 SSH(허용된 관리 출발지·MCP 점프) · 80 WAF→DVWA/Log4Shell UI(이름 기반) · **443 chatproxy→채팅/대시보드/선택 Log4Shell HTTPS**(이름 기반) · 8443 WAF TLS · 10443→B:443 대시보드 DNAT **룰 존재**(허용 소스 `192.168.16.0/25`; Kali에서의 실제 도달성 미검증). 9/28 채팅·대시보드 이름 기반 응답, 10/08 채팅 인증서 배포 후 HTTPS ping, 10/15 공용 인증서로 채팅·Log4Shell HTTPS를 검증했다. Wazuh 대시보드는 학과망·VM세그먼트 허용, VPN 403 정책을 유지한다. 공격성 트래픽은 캠퍼스 VPN 경유 금지.
