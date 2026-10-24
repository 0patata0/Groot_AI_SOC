# 2026_capstone_Groot_B — SIEM(Wazuh) + MCP Server

> **2026-10-25 06:23 KST Ollama 병행 시험 적용:** 같은 B host venv에 Ollama SDK+mcp-use 실행부를 설치했다. 모델은 Hermes와 같은 DGX qwen3.6:35b. `ollama` 봇의 `soc-ollama` 채널/DM을 활성화하고 기존 soc-agent는 이력/ID를 유지해 `soc-hermes`로 이름을 바꿨다. 읽기26도구·별도 비특권 gateway만 추가하며 기존 관리/승인은 Hermes가 담당한다. 18회 SDK 비교에서 후보가 빠른 표본을 얻었으나 실제 채팅 게시시간/전체 기능 동등성·완전한 정확도는 미검증이다. [사용·설치·복구](../ollama-trial/README.md) · [결과/한계/Git 상태](../../STATUS.md).


> **2026-10-25 05:22~05:25 KST 실행 의존성·왕복 확인:** 기존 Hermes 컨테이너(Python3.13.5/MCP2.0.0/httpx0.28.1)의 라이브러리만으로 native Ollama→MCP 읽기→최종 답변2건을 통과했다. B 기본 Python3.12.3 환경에는 같은 라이브러리가 없어 별도 배포가 필요하다. 선택 루트5의 전이 의존41개 조건 충족·격리 regex2026.9.29 확인은 새 실행부 전체 lock/배포 검증과 다르다. mcp-use Python1.7.1은 MCP<2를 요구하므로 운영 환경을 낮추지 않고 격리해야 한다. 운영8SHA/CID/PID 불변·설치/재시작0. [STATUS](../../STATUS.md) · [대체 후보와 필요 연결](../mcp/README.md).

> **2026-10-25 05:14 KST 추가 자원 확인:** DGX 추론을 유지하는 별도 Ollama 클라이언트/실행부 시험 공간은 충분하다고 판단한다. 가용RAM11.74GiB·가용디스크100.05GiB·swap0,4vCPU의3초표본busy0.25~2.76%. /·/opt·Docker는 같은 파일시스템이므로 디스크 여유를 중복 합산하지 않는다. Hermes314.3MiB·운영8SHA/CID/PID불변. 설치/다운로드/신규 동시 부하 시험은 하지 않았다. [STATUS](../../STATUS.md).

> **후속 정정:** 사용자 검토안은 B의 Ollama 클라이언트를 DGX Ollama에 연결하고 추론은 DGX에 두는 구성이다. 아래 RAM/GPU 실측은 사실이지만 이 원격 연결안의 제약으로 적용하지 않는다. 현행 유지 권고는 채팅·MCP 실행·기억·승인/관리 기능 이관이 미검증이라는 범위이며 속도 우열은 별도 비교 대상이다. [STATUS](../../STATUS.md).

> **2026-10-25 05:00 KST 역할·자원 확인:** B는 4 vCPU/RAM15.62GiB(가용11.77GiB)·swap사용0이며 계산용 GPU는 노출되지 않았다(VMware vmwgfx). Wazuh3종·Mattermost·PostgreSQL·Hermes 6컨테이너 실행, Hermes 유휴1표본314.2MiB/CPU0.16%. 현행35B 파일21.07GiB와 공존 서비스 때문에 B에서 동일 모델 추론을 맡기는 전환은 권장하지 않는다. B Hermes가 SOC/MCP·채팅을 관리하고 DGX Ollama가 추론하는 구성을 유지한다. 초기 프로세스 root와 실제 Hermes UID995를 구분하며 운영권한 변경은 없다. 전체 비교·근거·미검증 범위는 [STATUS](../../STATUS.md).

> 2026-10-24 보완: 오프라인 host 패치, 기존 Java/관리망 격리, root 승인 진입점과 검증 TLS8444/8445를 적용했다. A 필수 컨테이너는 always로 재부팅 복구하며 실습/백업의 중지 상태는 보존한다. 상세 포트·권한·새 설치/기존 이관과 검증 범위는 [설치 안내](../../deployment/bootstrap-guide.md) 및 [STATUS](../../STATUS.md)를 따른다. LLM 추가 검증은 진행 중이다.

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../STATUS.md) · [실행 계획](../../PLAN.md).
> 현재 B는 Wazuh4.14.8·Mattermost/PostgreSQL·Hermes·승인 브로커와 MCP6서버를 운영한다. 이번 읽기 점검에서 운영6컨테이너와 Wazuh000/001/002 Active를 확인했다. 고정 도구 목록과 실제 LLM 선택·대응 성공은 별개다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

## 통합 SOC 대시보드 생성 — 2026-10-19

[Groot SOC | 통합 탐지 현황](https://wazuh.grootlab.duckdns.org/app/dashboards#/view/groot-soc-20261019-dashboard): WAF·Suricata·Wazuh 기타 알림의 14패널, 최근 7일·30초 자동 갱신. 새 객체 15개와 기존 인덱스 패턴 참조를 API·브라우저로 검증했다. [소스·복원·적용 검증](soc-dashboard/README.md). 이번 확인에서 전역 시간대는 Browser 기본값이며 Mac 브라우저에서 KST로 표시된다. 아래 10/13 KST 고정 기록은 당시 이력으로 보존한다.

> 2026-10-15: 채팅 인증서 만료 감시를 A(매일09:00KST)에, 전용 XML 디코더·규칙100300~100305를 B에 적용·검증했다. 만료일2027-01-06 15:02:33KST, 갱신은 수동이다. [현재 구성·갱신 절차](../groot-a/certificate-monitor/README.md). 아래 기록은 해당 시점의 이력이다.

## 2026-10-14 19:38 KST 후속 — Indexer 시간 경계 보완 반영

Imperva/언어가드 기존로그 점검을마치고, 같은Indexer모니터를300초후보·정확60초sliding v2로갱신했다. native검색41개·lifecycle4단계·응답guard66개를통과했으며ID/권한/actions0·서비스/기존Wazuh룰은유지한다. 현재관리명령/검증/복구는 [v2운영안내](../normalization/wazuh-vector/indexer-native/window-v2/OPERATIONS.md)를따른다. 자연스캔·최근Hermes사용표본은없어효과관찰대기다. 다음은WAF두reader회전격리→인증서관리이고장기지연/영속복구/정확히1회는별도다. 아래내용은각시점의기록이다.

## 운영 분석기 1/1 적용·실제 20회 종단 검증 완료 (2026-10-14 18:56 KST)

B의 `analysisd.event_threads=1`, `analysisd.rule_matching_threads=1`을 18:48:55 KST에 적용하고 **같은 manager 컨테이너를 한 번 재시작**했다. 기존 native 규칙 104개를 적용 전후 각각 통과했으며, 18:49:04의 새 analysisd PID는 `2132985`, 전체 스레드는 44개다. 다른 컨테이너와 보호 해시는 유지됐다. canary 없는 60.000186초 운영 관찰에서 수신 60건(약 1 EPS), drop 증가 0, queue 최대 표본 0, 단일 코어 대비 CPU 약 0.0333%를 확인했다. [적용·관찰 증거](../normalization/wazuh-vector/correlation-fix/deployment-resume-2026-10-14.json).

사용자 명시 승인 후 실제 A agent001→B manager→Indexer의 **20회 × 13행(260행)** 시험을 18:56:08 KST에 완료했다. 동일 20개 run ID를 각각 한 번만 입력해 **manager 40건/Indexer 40건**, `100293` 20건·`100294` 20건, level 3·negative 경보 0건을 확인했다. 57/57 shard·strict CA/호스트명·각 run 및 전체 canonical tuple이 일치했으며 첫 조회 회차 11.3초, 입력 재시도 0회였다. A 원래 52행 접두 구간·inode·보호 설정과 B 옵션·룰·CID·SOC 안전 조건을 보존했다. 이 결과는 승인된 20회 시험의 성공이며 일반 트래픽의 장기 무손실 보장은 아니다. 기존 격리 1/1은 경보 4,000/4,000을 생성했지만 500 EPS 부하에서 queue 최대 표본 24%·최대 archive 관측 지연 약 10.04초가 있어 지속 처리량 보장은 아니다. [격리 부하와 한계](../normalization/wazuh-vector/correlation-fix/LOAD-VALIDATION.md). 아래의 미배포·반입 대기 설명은 이전 시점 기록이다.


**2026-10-14 18:18 KST 후속:** 검증기 고정ID 가정을 수정해47개 합성 및 기존 회차 대조를 통과했다. 각30,000행 격리 부하에서 worker1/1은 상관4,000건 전부 생성했고 자동설정은1,362건이었다(양쪽 입력drop0). 1/1은500EPS 시험 중queue최대표본24%·최대관측지연10.04초가 있어 지속처리량 보장과 구분한다. 운영 두옵션 변경안은 준비했지만 배포 검증94파일의B 반입이 자동 승인 검토에서 거절되어 사용자 전송 승인 대기다. 운영옵션/규칙/서비스 변경과 실제001 새burst는 아직 없다. [보완·검증·남은 적용](../normalization/wazuh-vector/correlation-fix/README.md). 아래는 이전 기록이다.

**2026-10-14 13:12 KST 상관 누락 조사:** 격리한 실제 Wazuh의 사전 logtest 없는 자동 설정 20회에서 100293 누락 8회·100294 누락 7회를 재현했다(중복 2회). 1/1 작업자 대조 20회는 정상이며, 40회×13행의 archives 원문과 최종 판정/alerts를 전수 대조했다. 병렬 판정의 순서 경쟁이 유력하지만 agent 000 직접 큐 시험이므로 과거 운영 001의 세부 원인 확정·운영 누락률·완전 해결로 확대하지 않는다. 검증기의 반복 경보 eventID0005 고정 가정도 별도 문제로 확인했다. 다음은 그 검증기 보완과 판정 병렬도 후보의 부하 검증이며, 운영 설정·규칙·서비스는 유지했다. [근거·실측·후속](../normalization/wazuh-vector/correlation-diagnosis/README.md). 아래는 이전 기록이다.

**2026-10-14 12:00 KST 검증:** A/B 보존 이전 boot 1,481건을 전수 대조했고 현재 nft 정제 후보는 0건이었다. 실제 보안 정제·색인 대상도 0건이며 운영 재주입은 하지 않았다. 별도 합성 대조14건 및 Wazuh native 순서8종을 검증했다. 새 간격 시험에서는 manager2건·Indexer2건의 정확 ID와57/57shard 성공을 확인했다. 앞선 일괄 시험의 manager1건/Indexer1건은 기대값 미달로 보존하며 누락 원인은 미확정이다. [검증 범위와 결과](../normalization/wazuh-vector/history-replay-b/README.md). 후속 Suricata 격리 시험은 지연 공개 방식에서 Vector/Wazuh 각각6건·중복0, 연속2회전·정상재시작을 통과했다. 단순 rename 대조군은2건 누락을 재현했다. 운영 copytruncate는 유지하며 다음은 WAF별 검증과 운영 전환/영속 복구 조건 확인이다. [회전 결과](../normalization/vector/raw-rotation/README.md). 아래는 이전 시점 기록이다.

**2026-10-14 10:57 KST 후속 완료:** 이전boot 후속481건을 회수해 두배치1,481건/621,820bytes의 A→B 직접 전송·B 파일보관·A 수신증 저장을 검증했다. native 합성144개·실제 합성 응답유실 재시도 및 실제배치 해시/고유cursor를 확인했고 서비스는 유지됐다. Wazuh/Indexer ACK·전체무손실·운영 재주입을 뜻하지 않는다. 다음은 격리 정제와 Suricata→WAF raw 회전 검증이다. [실측과 운영 경계](../normalization/vector/history-transfer/README.md). 아래 내용은 이전 기록이다.

**10/14 06:23 KST 관측 모니터 활성:** 기존 Indexer에 `capstone-evidence-observation-v1` 한 개를 저장·활성화하고 실제 주기2회 정상·내부alert0을 확인했다. 별도 수동 query는54/54shard·1건·두trigger false·오류0이었다. 두trigger 모두actions가 없고 권한/계정/매핑은 추가하지 않았다. 첫활성화의schema_version변경은동일ID비활성복구후좁은검사보완으로처리했다. [배포·관측·한계](../normalization/wazuh-vector/indexer-native/README.md).

**10/14 06:09 KST evidence 연결:** 별도 XML에100260~100262를 추가하고 배포 전후104개 native 시나리오를 통과했다. manager는 기존 컨테이너에서05:52:37 KST에 재시작했고 local_rules는 보존했다. 자연 Suricata1건이100261 level3으로 manager/Indexer에 기록됐으며 A 사건ID·시각·고유 키가 같다. no_full_log/no_email_alert이며 nft는logged_drop만 허용한다. [배포 결과](../normalization/wazuh-vector/evidence-deployment-2026-10-14.json) · [별도 관측 모니터 상태](../normalization/wazuh-vector/indexer-native/README.md).

**10/14 04:54 추가 적용:** 수집 health 규칙 100246~100251(level 3/ignore 900초)을 추가하고 native 51개 검사·재적용 changed=0·기존 local_rules 유지를 확인했다. A 통계 필터 적용 이후 약 29분간 decoder 오류는 0건이며, B의 기본 한도 256개는 유지했다. manager는 health 적용 시 04:38:55에 재시작했다. Hermes 운영 ID/시작 시각과 timer/observer는 그대로이며, native 복구 16개·cold 복원 13개 등을 별도로 검증했다. [health](../normalization/wazuh-vector/collection-health-validation-2026-10-14.json) · [Hermes 준비](../automation/ansible/hermes-prestart-plan.md).

**10/14 후속 적용:** 정제 전용 규칙의 실제 agent 출처 접두사를 수정하고 native43개 시나리오·canary13행→manager2건→Indexer2건·동일event ID를 확인했다. 공격 상관은 no_log이며 기존 local_rules/승인권한은 보존한다. Hermes는 재시작 없이 Ansible 배포·고정 이미지 재생성 감지 timer·metadata 관찰 서비스를 적용했고 최종 재실행changed0이다. 자연 cron에 따른 DB/예약 상태 갱신을 보존했다. 시작 전 가드 적용·실제재생성/강제롤백·장기 혼입률은 미검증이다. [상관 검증](../normalization/wazuh-vector/CORRELATION.md) · [자동화](../automation/ansible/hermes-guard.md). 아래는 후속 전 기록이다.

**10/14 적용:** Vector 정제 입력용 Wazuh 규칙100200(level1/no_log)을 별도 XML에 추가했다. 기존 local_rules SHA는 동일하며 실제 엔진 양성2/음성4 검사·manager 정상 기동·재적용변경0을 확인했다. 신규 상관분석과 Indexer 종단 확인은 후속이다. 운영자 전용 Ansible2.21.5를 격리 설치했다. Hermes 문자 검사는 `regex==2026.9.29` 외부 Unicode 엔진으로 교체해51회귀/설치본12개·Mattermost/.111/MCP5/DB 정상 확인을 마쳤다. 인용/전송 정책의 Python 연동은 유지하고 컨테이너 재생성 시 엔진·가드 재적용이 필요하다. [Wazuh 연결](../normalization/wazuh-vector/README.md) · [언어 검사](../hermes/korean-output-guard.md).

> **10/13 한국어 혼입 보완:** B Hermes에 한국어 전송 검사를 적용했다. 일반/수정/첨부 설명/예약 보고를 검사하며 기존 승인 권한과 `.111` 모델 연결은 유지한다. 20:51:04 재시작·20:51:15 Mattermost 연결·20:52 실제 교정/전송 검증을 완료했다. 범위·한계·백업은 [검사 운영 문서](../hermes/korean-output-guard.md)를 따른다. 컨테이너 재생성 시 코드 재적용이 필요하다.


## 2026-10-13 19:51~19:54 KST 최신 반영 — Hermes DGX `.111` 전환

Hermes의 모델 endpoint를 기존 `.110`에서 **`http://211.170.162.111:11434/v1`**로 변경했다. 같은 Hermes 컨테이너를 **19:51:42.745 KST**에 재시작했고 **19:51:45 KST** resolver에서 `.111`·`qwen3.6:35b`를 확인했다. rule MCP timeout 420초, 대화 DB, `.env`, SOUL, cron은 유지했다. 같은 모델 태그를 유지했지만 노드별 모델 패키징·Ollama 버전은 다르며, 파라미터 합계가 더 작은 모델로 교체한 것은 아니다. 세부 비교는 [현재 상태](../../STATUS.md)와 [실측 자료](../hermes/benchmarks/README.md)를 따른다.

변경 전 백업은 `/var/backups/hermes-dgx111-20261013._j_oz3ky`에 보존했다. 실배치 `/opt/hermes-data/config.yaml`의 SHA-256은 다음과 같다.

| 시점 | SHA-256 |
|---|---|
| 전환 전 `.110` | `1aba095168ec6224a97f172b7a831d9556b472979e1ae986f90e34e185349aa0` |
| 전환 후 `.111` | `c03f7adc96e248562f81be107ee31a275ee17abffdb46ba3fd9cc70fbedf25e7` |

전환에 앞서 A nft `never_block`에 DGX 두 `/32`를 라이브·영구 반영했고, 기존 `.110`을 유지하면서 `.111`을 추가하는 Suricata 부분편집 제안은 실제 카드 승인 후 **19:50 KST worker가 적용**했다. Suricata는 **19:50:28 KST 시작·19:50:41.988 KST 룰 로드**, 19:51 후속 조회에서 `applied`를 확인했다. 19:54 재검증에서 승인 소비·결과 게시 성공과 로드 성공 52,497건·failed/skipped 0을 확인했다. [FW 보호 범위](../groot-a/fw-v2/README.md) · [부분편집 승인·적용](../mcp/rule-change-deploy.md).

**전환 후 연결 검증:** 19:51:54 KST Mattermost WebSocket 재연결과 19:53 KST `.111` 모델 API의 HTTP 200·한국어 응답을 확인했다. 실제 Hermes UID로 rule-a/rule-b 각 8개 도구와 세 룰 대상 조회도 재확인했다. 전환 후 체감 응답 속도와 실제 채팅 왕복은 아직 별도로 측정하지 않았으며, 아래의 과거 기록은 당시 확인 범위로 보존한다.

> **10/13 14:29 승인형 운영 추가 배포:** 큰 룰 diff 자동 분할/단일 승인, 고정 서비스 작업, 증거 기반 임시 10분 차단과 유지 60분 결정을 지원한다. 패키지·컨테이너 구성 변경은 제외했다. 신규 도구 읽기·정책 캐시를 검증했으며 실제 신규 승인 실행 E2E는 후속 관찰 대상이다. [운영 범위·한계](../mcp/approved-operations.md).

> **현황(2026-10-06 기록 및 10/08 SSH 재확인):** B의 `ens192` vNIC는 제거됐고 `ens160=10.200.10.10`의 기본 경로가 A(`10.200.10.1`)를 지난다. Wazuh 에이전트 000/001/002는 Active다. 신규 FW 접두어·WAF 100200대 전용 분류는 없으나 보안 이벤트 읽기 조회에서 Suricata 로컬 SID `1000010`→Wazuh `100110`과 ModSecurity CRS `920350`→Wazuh `100101`을 확인했다. 나머지 로컬 룰 분류와 시나리오별 공격 프로브 발화는 미검증이다. [기존 기록](../../대화기록/2026-10-06.md)

> **2026-10-08 11:53~11:59 KST 관리 SSH 직접 재확인:** Wazuh 000/001/002는 계속 Active이고 경보 파일이 갱신 중이다. 당시 Hermes의 기존 3개 MCP 서버가 enabled였고, SOC 봇·보고/요약 타이머가 active였다. B 브로커 토큰·허용 승인자 목록은 비어 있지 않다. 로컬 룰 파일은 저장소와 해시가 같고 디코더는 주석의 옛 예시 IP 한 줄만 다르다. 신규 FW 접두어·WAF 100200대 분류는 여전히 없다. [오늘 기록](../../대화기록/2026-10-08.md)

> **같은 날 약 12:58 KST 후속 배포:** B `soc-bot`에 별도 룰 승인 API를 배포하고 `rulechg` SSH 강제 명령·root helper·`rule-change-worker.timer`를 설치했다(active/enabled). Hermes에는 기존 3개 MCP 서버를 유지하면서 `rule-a`·`rule-b`를 추가했다. A/B↔브로커 HMAC 통신과 로컬 룰 대상 읽기 조회가 통과했고, Wazuh 운영 룰 해시는 배포 전후 동일하다. 실제 Mattermost 승인 버튼→룰 적용·복구 E2E는 아직 검증하지 않았다. [배포 절차](../mcp/rule-change-deploy.md)

> **채팅·시간(10/08 당시 기록):** Mattermost는 B `10.200.10.10:8065`에서 동작하고 A:443 chatproxy로 접근한다. 대표 이름 `https://chat.grootlab.duckdns.org`의 Let's Encrypt 인증서는 10/08 A에 배포됐다. 학교 내부 Wi-Fi의 모바일 앱 로그인은 미검증이며, 관리자 지원 거절(사용자 보고)로 모바일 VPN 경로는 제외한다. B 호스트는 KST·NTP 동기화, Mattermost는 `TZ=Asia/Seoul`, 상태 요약은 09·21 KST다. 일부 컨테이너·원본 로그의 UTC 표시는 별개다. 모바일 앱의 후속 사용자 확인은 아래 10/13 갱신을 따른다.

**호스트 예약 작업 후속(13:16:27 KST):** 사용자 지시로 B의 `fwupd-refresh.timer`만 disabled/inactive 처리하고 해당 refresh 서비스의 failed 표시를 정리했다. LVFS DNS는 정상이지만 TCP443 시간 초과, VMware VM의 updatable 장치 0이었다. 기존 fwupd 데몬·패키지·APT·Wazuh 40704·경보 이력과 주요 서비스/컨테이너의 시작 시각은 유지했다. 백업 `/var/backups/fwupd-refresh-timer-20261013.6bxd7830`, 복구 `systemctl enable --now fwupd-refresh.timer`. 이 조치는 펌웨어 목록 갱신을 중지한 것으로, 모바일 푸시나 펌웨어 설치 기능을 변경한 것이 아니다.

## 모바일 푸시 — DNS 복구·외부 HTTPS 경로 미확보 (2026-10-13)

**10/13 사용자 요청으로 이번 작업 마무리:** 모바일 로그인·채팅은 정상이며, A/B 준비 설정과 `SendPushNotifications=false`를 유지한 채 추가 활성화·수신 검증은 보류한다. 푸시 복구 완료를 뜻하지 않으며 이번 마무리로 서버 설정이나 실행 중인 타이머를 변경하지 않았다. 외부 통신 가능한 허용 경로를 확보한 뒤 사용자가 재개를 요청하면 연결 검사→푸시 활성화→실제 Android·iOS 수신 검증 순서로 진행한다.

**2026-10-13 후속 결정 — 추후 발전과제로 분류:** 사용자는 모바일 푸시 알림 복구와 프로젝트 SSL VPN 원격접속 시나리오를 모두 현재 완료 범위에서 제외하고 추후 발전과제로 남기기로 했다. Android·iOS 로그인·채팅 성공은 앞선 사용자 확인이며, 푸시 미복구·`SendPushNotifications=false` 상태와 구별한다. 기존 A/B 준비 설정·타이머를 유지하고 추가 활성화·수신 검증은 진행하지 않는다. 상위 정책은 직접 변경할 수 없으며 허용된 외부 경로가 확보되고 사용자가 재개를 요청하면 검토한다. SSL VPN은 미구축이며, 학과망의 폐쇄적 정책에 따른 이중 접속 비호환 가능성은 사용자 판단이고 현재 환경에서 실측한 결과는 아니다.

**최신 상태(11:49:31 KST 실측·후속 사용자 정정 반영):** 사용자가 추가 확인 없이 진행하도록 승인한 범위는 프로젝트 서버의 모바일 푸시 복구이며, **상위 방화벽은 우리가 변경할 수 없는 영역**이라고 후속 정정했다. B의 DNS와 TPNS 주소·알림 내용 설정, A의 B→TPNS 한정 전달 정책은 반영한 상태로 유지한다. **현재 푸시 URL은 공란이 아니며 `SendPushNotifications=false`만 유지한다.** 실제 B 컨테이너에서 A를 거쳐 SYN이 외부로 나가는 것까지 확인했지만 회신이 없다. 학교에서 허용하는 기존 외부 프록시·중계 경로가 있는지 확인이 필요하며 푸시 활성화·휴대폰 실제 수신은 미완료다. Android·iOS의 인증서 인식·로그인·채팅 성공은 사용자 확인 결과다.

**10/13 초기 점검:** 모바일의 알림 불가 안내를 조사했다. Mac에서 채팅 HTTPS는 HTTP 200·TLS 검증 0이고 A `nginx -t`도 통과했다. B Mattermost 11.11.1의 실제 `mmctl --local config get` 결과는 `EmailSettings.SendPushNotifications=false`, `PushNotificationServer=""`였다. 로그에서 `Post "/api/v1/send_push": unsupported protocol scheme ""` 오류가 반복됐다. 이 서버 측 실패는 인증서 재발급으로 해결되지 않는다. 당시에는 휴대폰 로그인·오류 원문·실제 수신을 별도 확인할 필요가 있었다.

- **복구 완료:** B Netplan에는 DNS 설정이 없고 resolved에도 upstream이 없었다. 기존 A 정책에서 허용한 `168.126.63.1`의 직접 DNS 응답을 확인한 뒤 [resolved-capstone.conf](resolved-capstone.conf)를 `/etc/systemd/resolved.conf.d/60-capstone-dns.conf`로 설치하고 `systemd-resolved`만 재시작했다. 10:56 KST 호스트 이름 해석 성공·라우팅 불변, 10:58 Mattermost 네트워크의 `127.0.0.11` DNS 응답 성공·mm-app healthy·backend ping 200을 확인했다. 이전 부재 상태와 라우트 기록은 `/var/backups/mattermost-dns-20261013.3oxvy4cb/manifest.json`에 있다. 복구 취소는 해당 drop-in만 제거하고 resolved를 재시작하는 방식이다.
- **초기 로컬 경로(11:28 이전):** 당시 A `CAPSTONE-FWD`는 B→DGX:11434·허용 DNS·ICMP만 허용하고 B의 외부 HTTPS를 허용하지 않았다. B `10.200.10.10/32`에서 TPNS 목적지 TCP 443만 허용하는 정책이 필요했으며, 이 시점에는 방화벽 미변경이었다. 아래 11:49 배포로 해당 로컬 전달 제약을 해소했다.
- **남은 상위 경로:** A 자체의 IPv4 output은 accept이나 `push-test.mattermost.com`의 세 A 레코드 모두 TCP 443 연결이 시간 초과됐다. 같은 시각 Mac에서는 HTTPS 200·TLS 검증 성공이었다. B의 트래픽도 A에서 NAT되어 나가며 11:49 실측에서 A 외부 송신·회신 없음이 확인됐다. 정확한 차단 장비·정책은 미확인이다. 서비스 주소는 바뀔 수 있어 현재 IP 세 개를 영구 주소로 간주하지 않는다.
- **설정 도구:** [configure_mattermost_push_B.py](configure_mattermost_push_B.py)의 기본 `--check`는 설정·컨테이너 DNS/TLS 연결을 검사한다. 모든 DNS A 주소를 실제 mm-app CA 번들로 검사하도록 보완했고 모의 장애·구문 검증을 통과했다. 아래 11:41에 URL·내용 설정은 사전 반영했지만 실제 활성화용 `--apply`와 수신 검증은 아직 수행하지 않았다. 연결 실패 상태에서 푸시를 켜지 않는다.
- **11:05 KST 읽기 점검:** 위 스크립트의 기본 `--check` 실행에서 컨테이너 내장 DNS는 정상이었으나 HTTPS 연결은 `TimeoutError`였으며, 푸시 활성화나 Mattermost 재시작은 수행하지 않았다.

**10/13 후속 사용자 확인·11:25~11:28 KST 라이브 점검:**

- **사용자 확인:** Android와 iOS 모두 인증서를 정상 인식하고 Mattermost 로그인·채팅에 성공했다. 남은 증상은 알림 미수신과 “알림을 받을 수 없다”는 경고다. 위 10/08·초기 점검의 모바일 로그인 미확인 상태를 이 확인으로 갱신하며, 이 증상 때문에 채팅 인증서를 재발급할 필요는 없다. 실제 휴대폰 화면을 관리 SSH로 확인한 결과는 아니다.
- **B 직접 확인(11:25):** `SendPushNotifications=false`, `PushNotificationServer=""`, `PushNotificationContents=full`이며 SiteURL은 대표 채팅 HTTPS 주소와 일치했다. Mattermost는 healthy였다. 최근 30분의 빈 URL·push proxy 관련 오류는 16건, 해당 집계의 TLS 오류는 0건이었다. Mattermost 11.11.1은 푸시 비활성일 때 모바일 푸시 검사에 `false`를 반환하므로 당시 설정은 사용자 경고를 설명한다. [공식 서버 구현](https://github.com/mattermost/mattermost/blob/v11.11.1/server/channels/app/notification_push.go#L755).
- **A·Mac 직접 비교(11:25):** A에서 당시 `push-test.mattermost.com`의 3개 A 레코드 각각으로 향한 TCP 443 연결이 모두 `TimeoutError`였다. Mac은 같은 세 IP를 각각 지정한 `curl --resolve`에서 모두 HTTP 200·TLS 검증 0이었다. TPNS 루트의 HTTP 200은 기본 HTTPS 도달성 확인이며 휴대폰 알림 배달 성공을 뜻하지 않는다.
- **A 패킷·경로 직접 확인(11:28):** `ens192` 캡처에서 각 목적지로 SYN 6회가 나갔고 회신은 0건이었다. 경로는 A `192.168.16.230` → 게이트웨이 `192.168.16.129`였고 IPv4 nftables output 정책은 accept, 관측한 보조 규칙은 로깅이었다. 상위망이나 목적지 측 응답 경로 문제를 의심할 근거이며, 정확히 어느 장비·정책에서 막히는지는 아직 확인하지 못했다.

**11:41~11:49 KST 사전 설정·A 전달 정책 배포 및 검증:**

- **B 11:41:34 직접 적용·조회:** `PushNotificationServer`를 공란에서 `https://push-test.mattermost.com`으로, `PushNotificationContents`를 `full`에서 `generic_no_channel`로 바꿨고 `SendPushNotifications=false`는 유지했다. `mmctl`로 세 값이 일치함을 확인했다. 변경 전 값은 `/var/backups/mattermost-push-stage-20261013.cirnowp3/selected-settings.json`에 보관했다. Mattermost는 healthy이고 시작 시각이 그대로여서 재시작하지 않았다.
- **A 11:49:12 직접 배포:** `/usr/local/sbin/capstone-push-egress.py`, 대응 service·timer, `/etc/systemd/system/capstone-nat.service.d/20-push-egress.conf`를 배포했다. `DOCKER-USER` 맨 앞에서 출발지 B `10.200.10.10/32`, `ens160`→`ens192`, TCP 443만 `CAPSTONE-PUSH`로 보낸다. 전용 체인은 TPNS의 동적 IPv4 목적지별 허용 뒤 DROP으로 끝나며 C·전체 인터넷에 대한 허용은 추가하지 않았다. [정책 소스](../groot-a/capstone-push-egress.py).
- **A 갱신·복구 경계:** 타이머는 5분마다 DNS를 갱신한다. 기존 주소의 유효기간은 최대 1시간이며 DNS 실패 시 커널의 UTC 만료 시각을 연장하지 않는다. NAT 로더 원본·다른 filter 규칙·NAT 규칙은 변경하지 않았다. A 헬퍼의 `--check`, `--apply`, 반복 적용, 서비스 실행을 검증했고 타이머는 active/enabled다. 배포 백업은 `/var/backups/mattermost-push-egress-20261013.o73oufbn`이다.
- **11:49:31 실제 B 컨테이너 경로 검증:** 실제 CA 번들을 사용하는 검사에서 DNS 3개 주소는 정상이었으나 세 주소의 TCP 443 연결은 모두 시간 초과됐다. 동시 A 캡처에서 각 목적지로 B `.10`의 SYN 5개가 들어오고 A `.230`으로 변환된 SYN 5개가 외부로 나갔으며 회신은 0건이었다. 새 허용 규칙 카운터도 목적지별 5씩 증가했다. **A 로컬 전달 정책은 동작하며 남은 실패 지점은 A 외부 송신 이후 경로다.** 상위 장비 로그를 보지 않아 정확한 원인은 확정하지 않았다.

**후속 사용자 정정 — 상위 방화벽은 직접 변경 대상에서 제외:** 앞서 “모든 서버 담당자”라는 답변을 상위 장비 관리까지 포함하는 것으로 해석해 관리 접속 정보를 확인하려 했으나, 사용자가 상위 방화벽은 우리가 건드릴 수 없는 부분이라고 명확히 했다. 관리 범위는 프로젝트 서버로 한정한다. 상위 방화벽의 관리 주소·자격증명을 받아 직접 접속하거나 정책을 변경하는 계획은 철회했다. 외부 메시지는 발송하지 않았다.

**사용자 추가 설명과 실측 범위:** 사용자 설명에 따르면 프로젝트 VM은 상위 방화벽 뒤의 내부망 전용 환경에 있으며 외부 통신은 선택적으로 허용된다. 라이브에서 직접 확인한 범위는 B→DGX API HTTP 200·DNS 정상, TPNS TCP 443의 외부 송신 후 회신 없음까지다. 학교 방화벽의 개별 규칙을 직접 열람한 결과는 아니다. 이 외부 통신 제약은 프로젝트 안의 인증서 재발급이나 추가 TLS 설정으로 해결할 수 없다. 기존에 허용된 푸시 도달 경로가 확인되지 않은 현재 구성에서는 공식 모바일 푸시 미복구·`SendPushNotifications=false` 상태를 유지하며, 이 설명 반영으로 기존 A/B 설정을 추가 변경하지 않았다.

남은 확인 대상은 **학교에서 허용하는 기존 outbound 프록시 또는 중계 경로의 존재와 사용 조건**이다. 허용된 경로가 제공되면 실제 B 컨테이너에서 그 경로의 도달성·TLS·푸시 전달 가능 여부를 먼저 검증하고 필요한 제한 설정을 검토한다. 현재는 그런 경로가 확인되지 않았으며 새 중계를 구축하거나 성공을 보장하는 단계가 아니다. 허용된 외부 경로가 없고 상위 정책 변경도 불가능하다면 현재 망에서는 공식 iOS·Android 앱의 백그라운드 푸시를 복구할 수 없다. 임의 터널이나 Mac 상주 프록시는 설치하지 않는다. 채팅 서비스의 공개 인터넷 인바운드 개방도 이 문제의 해결 조건이 아니다.

Mattermost의 [기업 프록시·DMZ 중계 안내](https://docs.mattermost.com/developers/contribute/more-info/mobile/push-notifications/corporate-proxy)는 HPNS를 전제로 한 경로를 설명한다. 현재 무료 TPNS에 허용된 기존 경로를 적용할 수 있는지는 별도 검토·실측해야 한다. [자체 MPNS 운영](https://docs.mattermost.com/deployment-guide/mobile/host-your-own-push-proxy-service)도 APNs/FCM 외부 통신과 자체 앱 서명·푸시 인증 구성이 필요하므로, 자체 MPNS 설치만으로 현재 망의 외부 통신 제약이 해소되지는 않는다.

허용된 외부 경로가 확인되면 기존 직접 연결용 검사·설정 도구를 해당 경로에 그대로 사용할 수 있는지부터 검토한다. 실제 B의 연결 검증을 통과한 뒤에만 `SendPushNotifications=true` 적용과 휴대폰 수신 검증을 진행한다. 도구는 목표 설정이면 변경 없이 검증만 하며, 이미 다른 값으로 푸시가 켜져 있으면 자동 변경을 중단한다. 실제 변경 시 `/var/backups/mattermost-push-*/selected-settings.json`에 세 값을 제한 권한으로 저장한다. 실패 시 비활성화부터 복구를 시도하지만 **앱이 재기동하지 못해 mmctl API도 사용 불가능하면 자동 복구는 보장되지 않으므로 운영자가 보호된 백업을 이용해야 한다.** 설정 변경 중에는 다른 관리자와 동시 편집하지 않는다. 현재 검증은 B 사전 설정·A 전달 정책·실제 B 발신 경로까지이며 푸시 활성화·롤백·휴대폰 수신을 서버에서 시험한 결과는 아니다.

공식 무료 TPNS는 비상업 self-hosted와 App Store/Google Play 공식 앱을 지원하지만 SLA가 없다. **알림 내용 설명 정정:** 앞서 `generic_no_channel`이 본문·채널명을 모두 제외한다고 요약했으나, 정확히는 본문을 제외한 일반 알림이며 11.11.1 구현상 DM 채널 정보·발신자명·식별자 등 전달용 메타데이터가 남을 수 있다. 완전한 익명 알림이나 ID-only 모드와 같지 않다. 현재 내용 설정은 `generic_no_channel`이지만 푸시 활성화는 계속 `false`다. 푸시 자체와 채팅 접속은 별도 경로다. 채팅 상세 조회·답변·승인에는 계속 A 사설 주소에 접근 가능한 내부망이 필요하다. [TPNS 공식 설명](https://docs.mattermost.com/administration-guide/configure/push-notification-server-configuration-settings#test-push-notifications-service-tpns) · [11.11.1 알림 내용 구현](https://github.com/mattermost/mattermost/blob/v11.11.1/server/channels/app/notification_push.go#L814).

`/api/v4/system/ping?device_id=...`는 실제 테스트 푸시를 실행하므로 읽기 점검에 사용하지 않았다. 경로·서버 설정을 마친 뒤 휴대폰 OS 알림 권한과 앱 알림 조건을 확인하고 실제 수신을 시험한다. 현재 **모바일 푸시 복구 완료가 아니다**.

## 시간대 운영 — 대시보드 KST 고정·원본 UTC 보존 (2026-10-13)

**11:08 KST 라이브 점검:** A/B/C 호스트는 모두 `Asia/Seoul`, `NTP=yes`, `NTPSynchronized=yes`였다. B/C는 A를 NTP 서버로 사용하며 관측 오프셋은 각각 약 `-8 µs`·`-12 µs`였다. 호스트 시계 동기화와 대시보드 표시 시간대는 별도 설정이다.

**11:15:23 KST 대시보드 적용·확인:** B의 `/home/groot_b/capstone/wazuh/single-node/config/wazuh_dashboard/opensearch_dashboards.yml`에 다음 설정을 추가해 브라우저 시간대에 맡기던 `Browser` 대신 `Asia/Seoul`로 고정했다.

```yaml
uiSettings.overrides.dateFormat:tz: Asia/Seoul
```

- 단일 파일 bind mount의 inode를 유지하는 방식으로 저장하고 **Wazuh dashboard만 재시작**했다. 설정 조회 `GET /api/opensearch-dashboards/settings`에서 `settings["dateFormat:tz"]`의 `isOverridden=true`, `userValue="Asia/Seoul"`을 확인했고 대시보드 상태는 `green`이었다. 이미 열려 있는 브라우저는 **페이지를 새로고침**해야 한다. [공식 시간대 설정 정의](https://github.com/opensearch-project/OpenSearch-Dashboards/blob/2.19.6/src/core/server/ui_settings/settings/date_formats.ts#L71).
- 변경 전 설정은 `/var/backups/wazuh-dashboard-kst-20261013.s5skh0b2/opensearch_dashboards.yml`에 보관했다. SHA-256은 변경 전 `3c25160c3e71d399cb1227b0de73f27bb8322f5b2740a89ea48e5fa4241ee8db`, 변경 후 `00251479be0841fee49bd01a594d2eb6e2a1be71cf78ed6b9651f566af424136`이다. 복구가 필요하면 백업을 동일 inode에 덮어쓰고 dashboard만 재시작한 뒤 설정 API와 상태를 다시 확인한다.
- **원본 이벤트 timestamp·인덱스·UTC 로그는 임의로 수정하지 않았다.** 실측 원본 `2026-10-13T02:05:20.124+0000`은 KST `2026-10-13T11:05:20.124+09:00`과 같은 순간이다. 화면의 날짜 필드 표시와 원본 JSON·`full_log` 안의 시각 문자열은 다르게 보일 수 있으므로 `Z`·`+0000`·`+09:00` 같은 시간대 표기를 함께 비교한다.

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
- 접속: Dashboard `:443`, Server API `:55000`, Indexer `:9200`, Agent `:1514`. **현재 B 주소는 내부망 `10.200.10.10`만** — 옛 임시외부 `192.168.16.231`(ens192)은 제거 완료. 운영자는 A 경유 SSH ProxyJump(`ssh groot-b-int`). 대시보드 대표 경로는 A:443 chatproxy→B:443이며 `https://wazuh.grootlab.duckdns.org`로 학과망·VM세그먼트에서 접근한다(VPN 403 정책). 9/28 이름 기반 대시보드 로그인 200을 확인했다. A:10443→B:443 DNAT 룰도 있지만 허용 소스가 `192.168.16.0/25`여서 Kali의 실제 도달성은 미검증이다.
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
- 보안 이벤트 읽기 서버: 같은 `mcp` 계정의 `security-events` 강제 명령 분기로 Suricata·ModSecurity 경보 2툴을 제공한다. 이미 Wazuh에 인덱싱된 이벤트만 조회하며, 10/06 계약 테스트·기존 14툴 회귀 및 Hermes LLM의 두 새 도구 호출을 확인했다.
- 응답 서버는 A의 별도 MCP/Policy Engine이며 `block_ip`/`unblock_ip`/`list_blocks`→nftables `agent_block` 경로가 9/28 승인→차단 E2E까지 검증됐다. `isolate_host`는 후속 목표다. Hermes는 B의 별도 계정·컨테이너에서 실행하고 MCP 자격증명은 갖지 않는다.
- 승인형 로컬 룰 변경은 기존 읽기 MCP 권한을 올리지 않고 B 승인 브로커와 A/B의 별도 `rulechg` 계정·root helper로 처리한다. B에서는 Wazuh `local_rules.xml`만 변경 대상으로 허용한다. 10/08 HMAC health·대상 읽기 조회는 통과했으며 실제 승인→적용은 미검증이다.
- 참고 데이터: CISA KEV `~/capstone/kev/kev.json` (`kev-data.md`).

## 검증 체크리스트
- [x] Dashboard 접속, Server API/Indexer 응답 (2026-09-26)
- [x] Groot_A/C Agent 등록·Active (manager `10.200.10.10:1514`, 2026-10-06 기록)
- [ ] 신규 FW 프리픽스·WAF GROOT 룰·나머지 IPS 로컬 SID의 디코더/룰 분류 여부 확인 → 빠진 항목만 추가 → VM 세그먼트 공격 프로브로 경보 실발화 검증. SID `1000010`→Wazuh `100110` 조회는 완료.
- [ ] Vulnerability Detection에서 Groot_C의 CVE-2021-3156 매핑 확인
- [x] MCP 읽기 14툴 호출 성공, Hermes 프로세스에 MCP 자격증명 없음 확인(2026-09-28 기록). 이번 SSH에서는 이 계약 테스트를 재실행하지 않았다.
- [x] 승인형 룰 변경 브로커·A/B 변경기와 Hermes `rule-a`·`rule-b` 배포, HMAC·읽기 조회 확인(2026-10-08). 운영 룰 해시는 그대로.
- [ ] 지정 승인자의 Mattermost 버튼 클릭→Wazuh 로컬 룰 적용·복구 E2E 검증.
