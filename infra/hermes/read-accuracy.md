# 조회 정확성: 연결 상태와 WAF 설정 모드

2026-11-04 KST. 공통계약1.5.21/query1.19.16·기존35B를 유지하며 B의 Native/SDK/관리 gate와 SDK 실행기를 보완했다. 실제 MCP 선택은 모델이 수행하며 응답 값은 이번 호출의 SHA 결속 자료에서만 구성한다. [현황](../../STATUS.md) · [이전 조회 지연 개선](lookup-latency.md).

| 문제 | 보완·검증 |
|---|---|
| 한국어 ‘연결 끊긴’ 필터가 전체 상태로 넓어짐 | Wazuh의 active/disconnected/pending/never_connected를 구별. 제외·복수 상태·모호함·과거/원인/변경을 별도 처리. 실패/빈 조건을 전체나0건으로 바꾸지 않음 |
| WAF 설정/시작값/정책 혼동 | configured_engine_mode·startup_engine_mode·helper 정책을 분리. 고정DetectionOnly 유지 문구 제거. 설정 파일 관측을 worker 메모리 적재/실제 차단으로 단정하는 문구 거절 |
| WAF 단문에 실제 조회 누락 | 좁은 현재모드 요청만 읽기 계획에 연결. 실제 get_service_action_target(a:waf)·응답 SHA/observation 해시·대상 검증 후 표 구성. 과거/원인/사건/여러 장비/변경은 이 계획으로 축소하지 않음 |
| SDK 서비스 조회가 IDS로 고정됨 | 실행기의 기존 a:suricata 단일 고정을 요청 계획의 검증된 대상과 일치시킴. 실제 WAF/IDS 스키마 양쪽 회귀 검사 |
| 같은 시각 반복 출력 | 동일 KST 표시만 중복 제거, 원문 facts/offset 보존 |

## 실제 새 채팅

모두 공동 채널의 새 root이며 쓰기/보호 호출0이다. 질문 수가 적고 부하·캐시를 통제한 평균 시험이 아니다.

| 질문/담당 | 실제 호출·결과 | 채팅 게시까지 |
|---|---|---:|
| 연결 끊긴 에이전트만/Ollama | 실제 에이전트 목록1회·disconnected 범위0개, 다른 상태 미조회 명시 |10.824초|
| 같은 뜻 직접 Hermes | 실제 목록4회·요청 범위0개. 다른 상태도 조회했으므로 ‘미조회’ 경고를 붙이지 않음 |27.670초|
| 현재 WAF 모드/Hermes | 실제 a:waf1회·On/시작값DetectionOnly/후순위 설정을 표로 분리 |26.314초|
| ModSecurity 엔진 모드/Ollama 최종 | 실제 a:waf1회·동일 표·적재/실제차단 별도검증 명시 |9.874초|

중간 WAF 시험은52.393초 뒤 설정값은 맞으나 적재 단정으로 불합격했다. 단정 거절 뒤에는 MCP0/partial, 다음 SDK 후보는 IDS 고정과 충돌하여 미완료였다. 이 실패를 성공 표본에 합치지 않았다. 실행기 수정 후 위 최종 실제 조회가 성공했다.

최종 서버격리 관리222/SDK195/Native390/review59/설치37=903PASS·skip0. 설치37은 소스/렌더 계약이며 새 OS 설치가 아니다. 구문/범위/오류/해시변조·한국어 상태·WAF 현재/시작값·권한 경계를 검사했다. 원문 증거는 로컬 전용으로 보존한다.

## 배포·설치·복구

B18:44 최초13대상 적용 후 중간 후보를 검수하고19:09 SDK 실행기까지 총16대상으로 동기화했다. 보호config/SOUL8SHA·broker원PID·양WS/worker를 확인하고19:11:31확정·타이머 해제·확정 후 recovery no-op을 확인했다. 기존 Native 컨테이너는 후보 반영 과정에서 총3회, 기존 SDK/review worker는 총4회씩 재시작했다. 새 모델/패키지/포트·보안정책·일반 권한 위임 변경0이다.

`/var/lib/capstone-read-accuracy/20261104-r1/deployment`에 원본/후보·모든 중간SHA·manifest·독립 복구/확정을 보존한다. 초기15분 원복 타이머는 실제 답변의 오류를 발견한 뒤 새15분 타이머를 먼저 등록해 교체했다. 복구는 중간SHA를 허용하되 외부 drift를 거절하며 busy 작업을 중단하지 않는다. 실제 수동 원복·새 공격/사건 종결은 미시험이다.

신규 설치는 기존 `deploy.sh`→SIEM plugin의 read_contract/chat_harness/grounding/query 복사와 SDK runtime/harness 복사를 사용한다. 추가 바이너리/설정 키가 없어 기존 소스 묶음과 오프라인 목록을 유지한다. 실제 신규 설치는 실행하지 않았다.

한국어 상태 의미의 원출처: [Wazuh agent life cycle](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/agent-life-cycle.html), [connection](https://documentation.wazuh.com/current/user-manual/agent/agent-management/agent-connection.html), [API use cases](https://documentation.wazuh.com/current/user-manual/api/use-cases.html).2026-11-04공식 문서 확인. 로컬 timeout 설정은 별도이며 문서 예시를 현재 설정으로 간주하지 않는다.


<!-- service-query-20261118 -->

현재 상태만 묻는 짧은 요청과 호스트만 답하는 후속 요청을 같은 공통 계약으로 처리한다. 현재 조회에는 필요한 실제 읽기만 사용하고 요청하지 않은 journal을 추가하지 않는다. 모호한 대상은 확인하며 과거 수치·판단·승인을 새 근거로 이어받지 않는다. 운영10소스·영수증1개와 새8요청/6읽기를 확인했다. 기존 단일 deploy.sh의 복사·영수증 경로를 유지하며 새 패키지·포트·키·일반 권한은 없다. [동작·재현·한계](service-query-contract.md) · [실제 검증](query-completion/service-catalog.validation.json).
<!-- /service-query-20261118 -->


<!-- service-cause-candidate-20261119 -->

복합 원인 조사에는 별도 실패가 남아 있다. SDK 필수 조회 연결 후보는3반례와 회귀833검사·Linux 공식38/설치37검사를 통과했지만 실제 격리 실행에서 최종 보고가 수용되지 않았다. 후보 검증과 운영 적용을 구분하며 해당 후보를 배포하지 않는다. [원인·수행·미완료](service-query-contract.md) · [실제 실패·후보 검증](../validation/service-query/cause-completion.validation.json).
<!-- /service-cause-candidate-20261119 -->


<!-- service-provenance-summary-in-archive -->


<!-- native-identity-parity-20261119 -->

서비스 이름을 실제 구성요소와 구분하는 공통 조회 계약을 Hermes·Ollama·공동 관리 경로에 연결했다. 등록된 논리 서비스의 unit이 LoadState=not-found이면 같은 호스트의 서비스·컨테이너 목록을 확인한다. 목록 조회가 끝나도 구성요소가 확인되지 않으면 unresolved_service_lookup과 needs_review 또는 partial을 유지한다. 명시적인 unit 조회와 실제 loaded 서비스의 현재 상태 조회는 이 구분을 따른다.

[검증·적용·한계](../validation/service-query/identity-parity.validation.json) · [설치 원본 23파일 기준 패치](../validation/service-query/identity-parity.patch).
<!-- /native-identity-parity-20261119 -->
