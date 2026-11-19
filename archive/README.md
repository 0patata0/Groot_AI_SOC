# 과거 기록과 복원 안내

<!-- coordinator-private-pid1-20261119 -->
11/19 [격리 PID1 기반 검증](../infra/validation/journal-composition/private-pid1.validation.json)의 실제3systemd·기본 Native의 C 카탈로그·독립 타이머·초기 실패와 정리를 [현황 이력](STATUS_HISTORY.md#coordinator-private-pid1-20261119), [계획 이력](PLAN_HISTORY.md#coordinator-private-pid1-20261119), [진단 이력](DIAGNOSTIC_HISTORY.md#coordinator-private-pid1-20261119)에 연결했다. 전체 root 실행기·Lifecycle·SSH/Docker·소스/캐시 전역 복구와 실제 호스트 재부팅은 남는다.
<!-- /coordinator-private-pid1-20261119 -->

<!-- bootstrap-clock-gate-20261118 -->
<a id="bootstrap-clock-gate-20261118"></a>

로컬 prerequisites25·remote5·기존 controller48의78검사를 통과했다. 기존 설치 순서를 바꾸지 않았고 가짜 SSH의 순서 검증은 실제 서버 설치 증거로 쓰지 않는다. 실제 읽기에서는 같은 검사 소스를 메모리에서 실행했다. A/B/C가 통과하고 관리자231이 미동기로 거절됐다. 기존 운영 설치기를 실행하거나 운영 소스를 교체하지 않았으며 패키지 설치·서비스 재시작·새 네트워크 요청·모델 호출·채팅·공격·학습은0이다.

[시각 사전조건·검증 범위](../deployment/clock-readiness.validation.json)
<!-- /bootstrap-clock-gate-20261118 -->

<!-- chat-access-readiness-20261118 -->
<a id="chat-access-readiness-20261118"></a>

관리자231에서 채팅의 공개 이름으로443/TLS1.3 연결과 /api/v4/system/ping의200·OK를 확인했다. CA·호스트명 검증을 통과했고 제공 인증서 지문은 A의 저장 관측과 같았다. 다만 이름이192.168.16.230으로 해석됐으므로 관리자 LAN 경로의 결과다. 외부 인터넷·다른 VPN 경로·로그인·봇 대화의 성공으로 확대하지 않는다. 실제 정상 HTTP 요청은1개이며 자격 증명을 보내지 않았다.

정확 변경안390a0f43은 관리자231의 /etc/systemd/timesyncd.conf.d/90-capstone-campus.conf 파일1개와 기존 timesyncd의1회 재시작만 포함한다. 학내131을 지정하고5분 내 확인하지 못하면 추가한 설정만 원복한다. NTP 보정으로 시계가 약47초 앞으로 이동할 수 있으며 원복 시 시계를 강제로 과거로 돌리지 않는다. 관리자에게 정확 승인을 요청했으며 실제 설정·시각 변경과 운영 NTP 서비스 재시작은 아직 수행하지 않았다.

[관리자 경로·시각·정확 변경안 원장](../infra/groot-a/certificate-monitor/access-readiness-20261118.json)
<!-- /chat-access-readiness-20261118 -->

<!-- certificate-rules-native-20261118 -->
<a id="certificate-rules-native-20261118"></a>

초기 설치기 연결의 로컬190검사와 Linux 합성52조건·두 역할의 유닛 구문 검사는 기존 근거로 보존한다. 후속으로 B의 기존 Wazuh4.14.8 이미지에서12규칙을 격리 적재하고112사례를 모두 통과했다. 새 검증기의 로컬 경계 검사4개와 기존 인증서 검사15개도 통과했다. 운영 매니저의 컨테이너·시작 시각·설정8파일 지문은 전후 같았다. 새 Ubuntu 전체 설치·운영 룰 적용·실제 경보 전달·독립 재구현은 미수행이다.

[검증 원장](../deployment/certificate-monitor.validation.json)
<!-- /certificate-rules-native-20261118 -->

<!-- certificate-bootstrap-20261118 -->
단일 deploy.sh에 신규 A의 실습용 TLS와 B의 내부 채팅 TLS 감시를 연결했다. 기존 감시기에서 검증한 코어를 재사용하고 공개 인증서 경로·고정 엔드포인트·호스트 machine-id를 각각 결속한다. 실습 도메인과 채팅 도메인은 서로 다른 센서 이름·Wazuh 규칙으로 연결한다. 기존 운영 A의 두 파일과 타이머·인증서는 바꾸지 않았다.
<!-- /certificate-bootstrap-20261118 -->

[초기 설치 연결](DEPLOYMENT_HISTORY.md#certificate-bootstrap-20261118) · [검사와 한계](DIAGNOSTIC_HISTORY.md#certificate-bootstrap-20261118)

<!-- presentation-and-plain-toc-20261118 -->
[표 없는 목차·발표 동기화](DESIGN_ALTERNATIVES.md#presentation-and-plain-toc-20261118)와 [출력 검수](DIAGNOSTIC_HISTORY.md#presentation-and-plain-toc-20261118)를 기록했다. 11월18일 후속 결과와5장 논문 좌표를 연결한20쪽 발표·편집 표/차트·메모의 갱신은 유형별 presentation-and-plain-toc-20261118 이력을 참조한다. 실제 리허설과 발표는 별도다.
<!-- /presentation-and-plain-toc-20261118 -->

사용자 지정 [다섯 장 목차](DESIGN_ALTERNATIVES.md#thesis-five-chapter-20261118)와 [내용·출력 검증](DIAGNOSTIC_HISTORY.md#thesis-five-chapter-20261118)을 유형별 이력에 연결했다. 기존6장 조건은 후속 지시로 대체됐으며 전체98쪽/본문1~92쪽·151색인과 고정 결과 원장의 범위를 구분한다.

<!-- chat-alignment:history -->

[복합 조사 후보](../infra/validation/management-latency/README.md)의 실제 2채팅·동일 자료 재검사·실제 MCP 격리 실패·10파일 미승격을 유형별 이력에 추가했다. 앞선 13파일 운영 확정·새 8단순 채팅과 구분하며 원문·실패·복구 근거를 보존한다.

관리정책 고정 조회와 A4/B2/C2 파일 후보의 관측·실패·정정도 유형별 이력에 추가했다. Mac87/Linux87·생략0과 구문 검사는 운영 적용·엔진 로드·전역 MCP/승인/복구 완료와 구분한다.

현재 요약은 [STATUS](../STATUS.md), 활성 작업은 [PLAN](../PLAN.md)을 따른다. [실행기의 정리·현재 설치 검증](../infra/validation/journal-composition/COORDINATOR.md)과 [관리대역 전역 요구사항](../infra/mcp/management-policy.md)을 유형별 이력에 기록했다. 소스와 구조/격리 검사, 실제 운영 인수는 구분하며 이전 미완료 문구는 당시 관측으로 보존한다.

A의 운영 Native NAT와 다른 미커밋 통합 대안을 구분해 기록했다. 복수 대역·영구 로더25검사/격리9조건은 미배포 개발 근거이며 전체 보안장비 whitelist의 운영 완료가 아니다.

관리대역의 공통 registry·14적용면·34검사는 소스 계약의 검증 이력으로 남긴다. 장비별 실제 whitelist 반영과 전역 MCP의 운영 완료는 아직 아니다.

[전체 수집 자원 시험](../infra/validation/journal-composition/RESOURCES.md)의 호스트별1회 관측·운영 미적용과 문서 갱신 후 윤문 규칙을 현황·계획·진단 이력에 남겼다. 유한 한도 확정과 초기 설치 동기화는 남아 있다.

<!-- service-error-coverage:start -->
[오류 원문·조사 검증](../infra/validation/service-error-coverage/README.md) — query152/common96 미적용5소스 후보로 errors0 뒤 같은 범위 원문 조회·형식 정정을 보완했습니다. Mac1239(기존6생략)/Hermes1322·신규49·공식Harness²36구성/상시 증가0·643복원을 확인했습니다. 최종SDK4응답21.028~43.559초이나 데이터 손실·DNS 영향 추정이 남아 미승격입니다. 총14실행/5문자열·29읽기/47모델완료는 개발 소비이며 운영/실제 채팅·독립 점수가 아닙니다. 정본/설치 query137·학습 모델/권한·기존 정확 승인안 유지.
<!-- service-error-coverage:end -->

최근 [진단 시각·등록 대상의 실제 검증](../infra/validation/diagnostic-read-boundaries/README.md)과 미승격·fixture 정정·typed 실행 근거 잔여를 아래5유형에 보존했다. 643소스 복원·회귀·실제MCP·모델 내용과 운영 로드/채팅을 구분한다.

최근 [실제 journal MCP·모델4요청](../infra/validation/host-journal-model/README.md)의 실제조회/의미오류/검사오탐·대상확인·소수초경계·소비원장·미적용과정리근거를아래5유형으로보존했다. backend일치·회귀·모델완수·실제채팅을구분한다.

최근 [OS 실제 비교4요청](../infra/validation/read-target-live/README.md)의 실패·가드레일검출·집계로그필수계획공백·20:52라이브/자체정리를5유형이력에추가했다. 회귀840과실제완수/운영적용은구분하며후보는미채택이다.

최근 [OS 대상·범위 후보](../infra/validation/read-target-binding/README.md)의4소스/840회귀·과거응답 검출·미적용과 논문56쪽 매뉴얼 상세화/전수 검수·43쪽 복구본을 아래5개 유형별 이력에 보존했다. 날짜별 실행 관측은 이력에 두고 논문 본문은 목적·방법·이유·확인·복구 중심으로 정리했다.

최근 [짧은 조회 후보](../infra/validation/read-intent-scope/README.md)의 공통3소스·801검사·실제3빈표본/12~16초와 미적용·잔여 OS/조사 의미 범위를 유형별 이력에 보존했다.

최근 [읽기 시도 결속 후속](../infra/validation/read-attempt-binding/README.md)의6소스/785검사·실제6요청과 대상명 OS 실패·짧은DNS 범위·부재/활성 과장의 미채택 사유를 유형별 이력에 보존했다. 명시 도구 검사 성공을 모든 자연어/운영 성공으로 확대하지 않는다.

최근 [공통 주장 결속 검증](../infra/validation/claim-modality/README.md)의 공통4소스·585로컬 집계/기존 Hermes264·실제9요청과 미채택 사유를 유형별 원장에 남겼다. 부정/계획 오탐과 무호출 도구 실패 서술을 구분하며 기존 두 승인 계획·운영/설치/권한은 불변이다.

현재 상태는 [STATUS](../STATUS.md), 현재 계획은 [PLAN](../PLAN.md)을 확인합니다. 이 디렉터리의 과거 버전·정책·시험 결과를 현재 운영 상태로 해석하지 않습니다.

현재 요약 정리 전의 STATUS·PLAN 상세는 각 통합 원장에 `source-dfc3e2a-status`·`source-dfc3e2a-plan`으로 보존했다. 정확히 같은 절만 기존 본문으로 참조하고, 원본 SHA와 Git 복구 위치를 함께 남겼다.

최근 [평가범위정정](../finetuning/EVALUATION_SCOPE.md)은기존test176의소비128·workflow0을확인하고비교준비기의사용이력감사를추가했다.새독립관제평가·운영변경으로표시하지않는다.

직전 [이력 전송 읽기 감사](../infra/normalization/vector/history-auto-transfer/AUDIT.md)의14완료·420일치·실패43보존검토·같은420배치80회시간측정/1024추정을추가했다. 운영변경0이며정확적용승인은계속대기다.

직전 [관리 상태 정확 적용 준비](../infra/validation/control-status/application/README.md)의19파일·현재 프로필 gate·시작 관측·37운영자 검사·영수증 불일치 정정·격리 원복과 미적용 범위를 유형별 이력에 추가했다. 직전 현재 요약은 Git32a6545에서 복원한다. 구조·회귀·API와 실제 적용/타이머/채팅을 구분한다.

## 유형별 통합 이력

| 찾는 내용 | 통합 문서 | 합친 기존 문서 |
|---|---|---:|
| 작업 결과·상태·실패·정정 | [현황 이력](STATUS_HISTORY.md) | 83개 |
| 실행 순서·보류·후속 과제 | [계획 이력](PLAN_HISTORY.md) | 51개 |
| 설치 안내·검증·웹 정책 변경 | [설치 이력](DEPLOYMENT_HISTORY.md) | 6개 |
| 배치·교차 검토 등 설계 대안 | [설계 대안](DESIGN_ALTERNATIVES.md) | 3개 |
| 서비스 진단·응답 시험 | [진단 이력](DIAGNOSTIC_HISTORY.md) | 2개 |

각 문서는 최신 Git 기록 순으로 탐색하며, 원문 제목과 당시 시각은 본문에 보존합니다. 펼치기 안에서 당시 기록을 읽을 수 있습니다. 같은 H2 절의 내용이 바이트 단위로 동일하거나 링크 정리 후 본문이 동일한 경우에만 하나의 본문으로 연결했습니다. 같은 제목이라도 수치·상태·결정·실패가 다르면 별도 보존합니다. 이는 의미가 비슷하다는 이유로 과거 결과를 합산하거나 지운 정리가 아닙니다.

11/8 정리로145개 문서를5개로 통합하고, 전체 파일은151개에서12개로 줄였습니다.1,257절 중 정확히 반복된248절을 참조로 대체했습니다. 원문 전체와 모든 절의 보존 여부를 확인했으며, 링크 목적지만 통합 위치에 맞췄습니다. [원본 SHA·이동 원장](CONSOLIDATION.json).

## 별도로 유지한 기록

| 기록 | 분리한 이유 |
|---|---|
| [하네스 정리 전](chat-harness-before-cleanup-20261104.md) | 공통 출력·역할·시험의 별도 변경 기록 |
| [관리 접속 변경 전](TEAM_ACCESS-20261103-before-admin.md) | 과거 접속 정책의 증거. 현재 접속 방법으로 사용하지 않음 |
| [진단 검증 수치](diagnostic-navigation-common41-20261107.validation.json) | 당시 기계 판독 원장·해시 보존 |
| [저장소 정리·복원](REPOSITORY_CLEANUP.md) · [11/1 원장](REPOSITORY_CLEANUP_20261101.json) | 이전 자료 정리의 복구 경로 |

k3s(B-2)는 보류한 대안입니다. 현행 진입점은 단일 `deploy.sh`와 Compose(B-1) 구성입니다. 2026-10-06에 사용자가 삭제한 B-1 원본 구축순서를 참조한 대안 문서만으로 신규 설치를 완결할 수 없습니다.

## 원문 복원

통합 전 원본은 Git 커밋 `dbbe7ef1838fa87d8de7f340bb7e02be9e292266`에 있습니다. 원장의 정확한 `path`를 선택해 새 파일로 추출하고 `sha256`을 비교합니다. Git 이력은 다시 쓰지 않았습니다.

```bash
git show dbbe7ef1838fa87d8de7f340bb7e02be9e292266:archive/STATUS-before-evidence-guardrails-20261108.md > /private/tmp/groot-old-status.md
shasum -a 256 /private/tmp/groot-old-status.md
```

기존 파일을 덮어쓰지 않는 새 목적지를 사용합니다. 이후 이력은 위 유형별 문서에 날짜·근거를 추가하며 `before-*` 전체 복사본을 계속 만들지 않습니다. 상세 대화와 로컬 검증 원문은 기존처럼 `대화기록/`에만 보관합니다. 데이터셋 압축과 가중치는 이 문서 정리의 대상이 아닙니다.

현재 매뉴얼 전달본은66쪽이다. 운영 시작·FW 전체 조회·사건·카드/원복·하네스 사본·학습 인수 절차와128목차/캡션을 검수하고 직전60쪽18파일 복구본은 로컬에 보존했다. 이전56·60쪽 기록은 당시 사실로 유지한다. 유형별 이력과 현재 STATUS를 따른다.

[앱 선언 오류/색인 정책 후보](../infra/validation/application-error-filter/README.md)의 실제 누락·4행 메모리 대조·381검사·미적용과 초기 실패/정정을 유형별 이력에 보존했다. 현황은 STATUS를 따른다.

서비스/호스트 journal 통합 후보의 설계·실패·검증·미적용 범위는 유형별 이력과 [통합 원장](../infra/validation/journal-composition/README.md)을 함께 확인합니다.


소스40대상 초안·캐시 복구 모듈의 격리 검증과 A/B 수집 잘림·영수증 불일치·미배포 범위는 유형별5이력과 [후속 원장](../infra/validation/journal-composition/README.md)에 보존합니다. 운영 승인/적용 완료와 구분합니다.


수집 오버레이의 실제 A/B 잘림 보완·과거4ID/격리 캐시 인수·초기 실패/최종 회귀·미배포 범위는 유형별5이력과 [수집 원장](../infra/validation/journal-composition/collection-validation.json)을 따릅니다. 이전 캐시 준비와 기본 통합 기록은 당시 사실로 보존합니다.

자동 관리의 입력 중복·보고 의존성 누락·중단 복구와 Malvex 선택적 참고는 [현황 이력](STATUS_HISTORY.md)·[진단 이력](DIAGNOSTIC_HISTORY.md)·[설계 대안](DESIGN_ALTERNATIVES.md)에 기록했다. 현재 적용 범위와 미완료는 [검증 문서](../infra/validation/management-latency/README.md)를 따른다.


논문 구조 재편의 결과·계획·설계·검증은 STATUS_HISTORY·PLAN_HISTORY·DESIGN_ALTERNATIVES·DIAGNOSTIC_HISTORY의 `thesis-structure-20261117` 항목에 기록했다. 실제 배포 변경은 없어 DEPLOYMENT_HISTORY의 새 적용 이력은 추가하지 않았다.


논문 전체 소스의 오프라인 복원 보강은 유형별 이력의 `thesis-reproduction-kit-20261117` 항목을 참조한다. 설치·운영 변경은 없어 새 배포 이력은 추가하지 않았다.


논문 로그 정제 구현의 보완은 유형별 `thesis-log-pipeline-20261117` 이력을 참조한다. 설치·운영 설정 변경은 없어 새 배포 이력은 추가하지 않았다.


논문 실행 예제의 실제 plan 확인·CIDR 정정은 유형별 `thesis-command-check-20261117` 이력을 참조한다. 운영 소스·설정 변경이나 배포는 없었다.


논문 구조 재현 명령의 Git/Framework 입력과 실제 실행은 유형별 `thesis-harness-reproduction-20261117` 이력을 참조한다. 운영 배포는 없었다.


논문 후속6대화의 측정 정의·원문 대조·결과와 한계는 유형별 `thesis-live-results-20261117` 이력을 참조한다. 기존 발표 초안의 현행화 미완료도 구분했다.


11/17 근거를 반영한20쪽 최종발표 초안·편집 표/차트·PDF·발표자 메모의 현행화는 유형별 `presentation-refresh-20261117` 이력을 참조한다. 실제 리허설과 최종 발표는 별도다.


최근 [동반 조회·주장 검증](../infra/validation/management-latency/companion.validation.json)의 실제 2/3/3읽기와 자동 완료 오답, 공통 필드 검사 보완·13파일 후보 미적용을 유형별 원장에 남겼다. 구조/회귀 통과와 실제 판단 품질을 구분한다.


[구조화 판단 검증](../infra/validation/management-latency/evidence-judgment.validation.json)의 실제 3읽기와 47.493/67.984/46.940초의 소요 시간, 오답 거절과 미완료 조사를 유형별 원장에 남겼다. 16사본 후보는 기본값 꺼짐·운영 미적용이다.


[후속 조회 검증](../infra/validation/management-latency/evidence-followup.validation.json)에 5실제 시험의 추가 조회·비교표·KST 범위와 실패를 기록했다. 마지막 48.320초도 미확인 표현 오류가 남아 품질 미통과이며 16사본 후보는 운영 미적용이다.


[목록·가용성 검증](../infra/validation/management-latency/capability-grounding.validation.json)의 5실제 시험과 정정 실패를 유형별 원장에 기록했다. 마지막 짧은 요청의 사실 범위는 확인했으나 확장 조사의 실제 접근·대상 조회는 미완료이며 운영에 적용하지 않았다.


[웹 근거 조회 검증](../infra/validation/management-latency/web-evidence-scope.validation.json)의 실제4시험과 두 정정 원인을 유형별 원장에 기록했다. 웹 추가 읽기 누락은 보완했으나 경로 공백·짧은 판단문의 범위 표현·운영 연결은 미완료다.


[관측 목록과 미확인 범위](../infra/validation/management-latency/report-scope.validation.json)에 실제5시험·보관 원문3건 재표시·Native 결속 준비를 구분했다. Native 실행 연결·정확 운영 적용·새 채팅은 미완료다.


[Native 공통 보고 연결 후보](../infra/validation/management-latency/native-compact-execution.validation.json)는 소스 연결·설치 사본14경계 검증과 실제 Native/채팅·운영의 미검증 상태를 구분한다.


FW MCP의 전송·페이지 수용·원문 SHA 명세와 실제 로컬 재현·입력형 검증 공백은 유형별 `thesis-mcp-contract-20261117` 이력을 참조한다. 운영 수정과 새 독립 재구현은 별도다.

<a id="thesis-outline-correction-20261118"></a>
논문 목차 재수정의 결과·완료 범위·구조 선택·출력 검수는 [상태 이력](STATUS_HISTORY.md#thesis-outline-correction-20261118)·[계획 이력](PLAN_HISTORY.md#thesis-outline-correction-20261118)·[설계 이력](DESIGN_ALTERNATIVES.md#thesis-outline-correction-20261118)·[검증 이력](DIAGNOSTIC_HISTORY.md#thesis-outline-correction-20261118)에 보존했다. 운영 배포 변경은 없어 새 배포 이력을 추가하지 않았다.


[Native 첫 조회·실제 실행 보완](../infra/validation/management-latency/native-initial-e2e.validation.json)은 격리 모델/MCP 실행과 운영 미적용·실제 채팅 미검증, 중간 실패를 구분한다.


[Native 첫 선택 작은 정정](../infra/validation/management-latency/native-selection-repair.validation.json)은 자연2질문·선택 오류의 제어된 재현·운영 미적용과 실제 채팅 미검증을 구분한다.


[읽기 경로의 실제 승격 시험](../infra/validation/management-latency/read-activation.validation.json)은 설치 사본 회귀와 일반 Hermes 채팅 실패, 원복 후 검증을 구분한다.

<a id="thesis-page-one-20261118"></a>
국문 초록 삭제와 서론1쪽 시작의 결과·계획·구역 설계·검수는 [상태](STATUS_HISTORY.md#thesis-page-one-20261118)·[계획](PLAN_HISTORY.md#thesis-page-one-20261118)·[설계](DESIGN_ALTERNATIVES.md#thesis-page-one-20261118)·[진단](DIAGNOSTIC_HISTORY.md#thesis-page-one-20261118) 이력에 연결했다. 운영 배포 변경은 없다.


## 2026-11-18 일반 게이트웨이 읽기 연결 확정

일반 Hermes 채팅의 첫 조회·보고를 공통 읽기 검증 경로에 연결해 운영 적용을 확정했다. 새 채팅4건은 복합 조회 Hermes47.132초·Ollama46.925초, IDS14.873초·systemd12.190초였다. 어제의 KST 달력 구간과 현재 차단 목록을 구분했으며 실제8읽기·보호 작업0건이다. Mac/Linux302·206·39, Linux Harness²38·설치37과 운영50소스 검사를 통과했다. 변경/영수증31파일과 보호38파일을 대조했다. MCP45도구·모델·권한은 유지했다. 긴 기본 보고와 Native 내부 제어 문구 노출, 브라우저 표 확인은 남았다. 일반 정확도·30/60초 달성으로 확대하지 않는다. 공격·새 학습 중단을 유지한다.

31파일 적용은11:13:58, 확정은11:27:12 KST이며15분 원복 타이머를 해제했다. 앞선 운영 시험의 실패·원복은 과거 기록으로 보존한다. 실제 gte/lte 경계 확인에 따라 전날 종료를23:59:59.999999 KST로 정정했다. 준비 마지막 진단의 종료1은 PREPARED 기록 이후 타이머 경합이었고 독립 SHA/게이트 대조 후 적용했다. 임시5경로/1367파일/71021931B를 정리하고 실제 복구본은 보존했다. [검증 원장](../infra/validation/management-latency/native-gateway.validation.json).

<a id="thesis-cover-20261118"></a>
표지 문구2개 삭제와 기존 팀원3명의 표기·생성기/출력 검수는 [상태](STATUS_HISTORY.md#thesis-cover-20261118)·[계획](PLAN_HISTORY.md#thesis-cover-20261118)·[설계](DESIGN_ALTERNATIVES.md#thesis-cover-20261118)·[검증](DIAGNOSTIC_HISTORY.md#thesis-cover-20261118) 이력에 보존했다.

<!-- response-rpc-input-20261118 -->
## 응답 MCP tools/call 입력형 보완 후보 — 2026-11-18

로컬81·Linux격리24·원복5조건을 확인한 개발 후보이며 운영 적용은 정확 승인 대기다. [현황](STATUS_HISTORY.md#response-rpc-input-20261118) · [계획](PLAN_HISTORY.md#response-rpc-input-20261118) · [적용 준비](DEPLOYMENT_HISTORY.md#response-rpc-input-20261118) · [선택 근거](DESIGN_ALTERNATIVES.md#response-rpc-input-20261118) · [실패·검사](DIAGNOSTIC_HISTORY.md#response-rpc-input-20261118)
<!-- /response-rpc-input-20261118 -->


## 2026-11-18 보고 표시 보완 확정·공통 날짜 공백

읽기 보고의 기본 요약·명시적 상세와 제어 문구 비공개 처리를 운영20파일에 적용·확정했다. 새 채팅4건에서 표시·원문 투영이 일치했고 실제12읽기·보호0건이다. 요약은Hermes36.345초/1731자·Ollama45.829초/1869자였다. Mac/Linux311·215·39·27, Linux Harness²38·설치37과 운영50소스를 확인했다. 단, ‘개별 내역까지’의 ‘까지’를 시간 조건으로 읽어 상세2건은 어제 대신 최근24시간을 조회했다. 표시4건 통과를 요청 기간4건 정확으로 확대하지 않는다. 기존 공통 날짜 함수 보완이 우선이다. MCP45도구·모델·권한과 공격·학습 중단은 유지한다.

적용12:25:40/확정12:40:22 KST, 보호51·같은컨테이너/계획재시작1·독립원복타이머해제. 실제요약/상세4표시를확인했지만상세질문2개의요청기간은실패했다. 실제MCP인자와변경전후동일한날짜함수로원인을확인했다. 원복으로표시개선을없애기보다기존기간오류를공통층에서보완한다. 시험용5경로/2623파일/101361917B 정리, 운영/복구/프레임워크/스킬보존. [원장](../infra/validation/management-latency/report-display.validation.json).


## 2026-11-18 공통 날짜 수정 확정·추가 자연어 실패 보존

공통 날짜 함수가 내역·행·장비의 ‘까지·부터·사이’를 시간 조건으로 오해하던 문제를 수정했다. 하네스 두 사본과 SDK 영수증을 운영 3파일로 적용·확정했고 보호 68파일을 대조했다. 새 채팅 6건 중 이전 상세 질문 2건과 명시한 09~10시 질문 2건은 실제 요청 기간이 맞았다. 다만 ‘경보’를 생략한 출발지 비교 질문 2건은 요청한 센서를 조회하지 못했다. Ollama 상세 답변은 ‘증거가 아닙니다’라는 올바른 한계 문장을 오탐해 정정 2회 뒤 미완료 보고를 냈다. 실제 읽기 17회·보호 작업 0회이며 기간 수정 성공과 전체 답변 성공을 구분한다. Mac/Linux 315·219·39·27, Linux Harness² 38·설치 37과 운영 50소스를 확인했다. MCP 45도구·모델·권한과 앞선 표시 보완은 유지한다. 다음 보완은 암시적 사건 조회와 근거 부정문 검증이다.

13:23:49 적용·13:29:47 KST 확정, 독립 원복 타이머 해제·복구본 보존. 실제6질문/17읽기 중 상세2·명시 시간2의 구간은 맞았고 경보 생략2건은 요청 센서 미조회다. SDK 상세의 증거 부정문 오탐·정정2회/모델20.708초와 SDK 암시적 질문12모델/157.426초를 다음 공통 하네스 보완 근거로 보존한다. 시험용2경로656파일 정리·결과7개 반출/SHA 확인. [검증 원장](../infra/validation/management-latency/calendar-scope.validation.json).


## 2026-11-18 암시적 센서 조회 확정·목록 형용사 오탐 보존

경보·로그라는 명사를 생략한 센서 관측 질문을 공통 조사 경로에 연결하고 나열된 결과의 근거 부정·조건을 해석하는 검사를 보완했다. 운영12소스+SDK영수증1을 적용·확정하고 보호58파일을 대조했다. 새6채팅은 모두 WAF·IDS와 어제 구간을 실제 조회했다. 모델 보고 수용3건과 보수적 미완료3건을 구분한다. 남은 공통 문제는 목록의 활성 주소를 기능 활성 주장으로 오인하는 가드다. Ollama 같은 짧은 질문은157.426→42.846초·모델12→2회, 상세는69.574→46.030초·4→2회였다. 단회 비교이며 일반 SLO가 아니다. Mac/Linux325·228·39·27과 공식 구조38·설치37·설치기 게이트5, 운영50소스를 확인했다. MCP45도구·모델·권한·상시 지시량은 유지한다. 이전 Native167.380초 실패 후보는 원복했고 새 입구 회귀를 추가했다.

14:56:00 적용·15:06:17 KST 확정. 새6질문/18읽기 모두 대상·기간 일치·보호0, 수용3/미완료3. Native 짧은68.475·상세66.737초와 SDK 인과63.074초의 동일 가드 오탐을 다음 보완으로 남긴다. 앞선 후보의 실제 실패·원복과 새 입구 회귀, 긴 문자열 처리 실패를 보존한다. 시험6경로2638파일 정리·결과28개 반출/SHA 확인. [검증 원장](../infra/validation/management-latency/observation-intent.validation.json).


## 2026-11-18 현재 목록/기능 상태 구분 확정

현재 차단 목록의 활성 주소를 차단 기능 활성 설정으로 오인하던 공통 가드를 수정했다. 검증된 최신 목록의 명시적0건·건수도 대조하고 직접 부정된 기능 상태는 별도 근거를 요구한다. 운영 하네스2사본+SDK영수증1을 확정·보호69파일을 확인했다. 새6채팅/18읽기에서 대상·기간6일치, 모델보고 수용5건이다. 첫 적용에서 이전 실패3문장은 Hermes짧은68.475→35.847초·상세66.737→45.966초, SDK인과63.074→44.141초로 수용됐다. Native짧은 표본은 줄었고 상세·SDK인과 표본은 같았다. 단회 결과이며 일반 SLO·전문가 정확도 점수로 확대하지 않는다. 실제 거절12초안 재검사·Mac/Linux333·295·39·27과 Linux공식38·설치37을 통과했다. MCP45도구·모델·권한·승인·기존스킬·상시지시량은 유지한다.

첫 적용15:38:18 KST·첫 확정15:46:01 뒤 목록 명사 후보를 추가 적용·실제 재시험·보호69파일을 확인해 확정했다. 실제 거절12초안 재검사·원래함수3실패/직전후보1실패·오류0을 보존한다. 격리 의존 파일 준비 실패2회와 실제 추가1파일을 통한 복구도 기록했다. 실제 새6질문과 단회 응답시간은 전반적 정확도·일반 SLO와 구분한다. [검증 원장](../infra/validation/management-latency/membership-grounding.validation.json).


## 2026-11-18 HTTP 평서 부정·간접 의문 공통 보완 확정

공통 어법/HTTP 인과 검사는 증거가 아니다·차단했는지·의미하는지는 추가 검증 필요라는 올바른 한계를 거절했다. 이를 보완했다. 계약3사본·하네스2사본·SDK영수증1을 운영6파일로 확정하고 보호66파일을 대조했다. 새3채팅/9읽기의 대상·기간이 일치했고 모델 보고는3건 수용됐다. 실제거절3초안 재생과 Mac/Linux336·298·39·27, Linux공식38·설치37을 통과했다. MCP45도구·모델·권한·승인·TTL·스킬·상시 지시량은 유지한다. 제한된 검증이며 일반 정확도/SLO는 별도다.

계약3·하네스2·SDK영수증1을 관리자231 경유로 적용·실제 재시험·확정했다. 이전68.769초/4단계 실패와 실제3초안·기존함수 새3검사중2실패/오류0을 보존한다. 단회 검증·표본·사건 미확인과 일반 정확도/SLO를 구분한다. [검증 원장](../infra/validation/management-latency/http-modality.validation.json).


## 2026-11-18 인증서 관측 수정 확정·출력 대상 오류 확인

관리자231 경유로 승인된 감시 실행파일·service2개를 적용하고17:13:01 KST에 확정했다. 실제 oneshot은exit0/verified이며 인증서 지문이 일치한다. 기존 MCP의 현재 상태와 실제 journal4표본에서도 확인했다. 5분 독립 원복은 해제하고 원본·정확 후보·제어기는 보존했다. 프록시·인증서·개인키·매일09:00 타이머·MCP/모델은 유지한다. 새 채팅1건은 올바른 인증서 조회 뒤 불필요한 Wazuh 에이전트 조회가 추가되고 최종 표의 대상이 바뀌어 실패로 기록했다. 초기 설치 이식·공개443·내일 예약 실행은 별도 미완료다.

적용 전 전체 cm_main/check는 기존10.3972초/tls_timeout·후보0.472초/verified였다. Linux root26·적용/원복14검사와 실제 독립 타이머의 격리 파일2개 복구를 통과했다. 단일deploy.sh의 lab TLS와 채팅 TLS 이식은 미완료다. [검증·실패·복구](../infra/groot-a/certificate-monitor/readiness.validation.json).


<!-- service-query-20261118 -->

현재 상태만 묻는 짧은 요청과 호스트만 답하는 후속 요청을 같은 공통 계약으로 처리한다. 현재 조회에는 필요한 실제 읽기만 사용하고 요청하지 않은 journal을 추가하지 않는다. 모호한 대상은 확인하며 과거 수치·판단·승인을 새 근거로 이어받지 않는다. 운영10소스·영수증1개와 새8요청/6읽기를 확인했다. 기존 단일 deploy.sh의 복사·영수증 경로를 유지하며 새 패키지·포트·키·일반 권한은 없다. [동작·재현·한계](../infra/hermes/service-query-contract.md) · [실제 검증](../infra/hermes/query-completion/service-catalog.validation.json).
<!-- /service-query-20261118 -->


<!-- service-cause-candidate-20261119 -->

복합 원인 조사에는 별도 실패가 남아 있다. SDK 필수 조회 연결 후보는3반례와 회귀833검사·Linux 공식38/설치37검사를 통과했지만 실제 격리 실행에서 최종 보고가 수용되지 않았다. 후보 검증과 운영 적용을 구분하며 해당 후보를 배포하지 않는다. [원인·수행·미완료](../infra/hermes/service-query-contract.md) · [실제 실패·후보 검증](../infra/validation/service-query/cause-completion.validation.json).
<!-- /service-cause-candidate-20261119 -->


<!-- service-report-provenance-candidate-20261119 -->

이번 서비스 보고 후보는 실제 품질 검증을 통과하지 못해 운영에 적용하지 않았다. 서비스 현재 조회의 기존 확정 결과는 유지한다. 원인·이력 조사는 현재 수집본과 실제 journal을 함께 읽으며 자동 선택한 최근 구간을 초기 확인 범위로 표시한다. 보고에서 근거를 넘는 문장을 제외하더라도 원래 판단·검토 상태와 조회 범위 안내를 유지한다. 모델·MCP·권한·보호 주소·승인·차단 TTL은 이번 보완의 변경 대상이 아니다. [검증·미적용·남은 문제](../infra/validation/service-query/report-provenance.validation.json) · [공통 동작](../infra/hermes/service-query-contract.md).
<!-- /service-report-provenance-candidate-20261119 -->

## 2026-11-19 인증서 감시의 자연 예약 실행 확인

<!-- certificate-scheduled-followup-20261119 -->
11/19 09:00 KST의 자연 예약 실행과 exit0/verified를 확인했고 기존 MCP2읽기·journal4표본을 대조했다. 다음 예약은11/20 09:00 KST이며 수동 실행·운영 변경은0이다. 한 차례의 예약 관측으로 외부 인터넷 경로·장기 안정성·새 OS 전체 설치·독립 재구현까지 검증한 것은 아니다.

[예약 관측·MCP 대조·한계](../infra/groot-a/certificate-monitor/readiness.validation.json)
<!-- /certificate-scheduled-followup-20261119 -->


<!-- service-claim-types-candidate-20261119 -->

서비스 조사와 최종 보고의 지침을 기존 공통 스킬 안에서 분리했다. 최종 보고에 같은 조사 지침을 모두 반복해서 넣지 않으며 원문과 조회 근거는 유지한다. 자동 시작 설정의 한국어 설명도 실제 UnitFileState와 대조하고 일부 표본을 매 실행의 결과로 확대하는 문장을 검사한다. 지침을 분리한 첫 실제 추론은 78.191초가 걸렸다. 읽기 3회·모델 호출 5회였으며 자동 시작 설정과 기능 정상 판단에 오류가 남았다. 후속 속성 검사 후보의 실제 추론과 운영 적용은 아직 수행하지 않았다. 기존 운영 소스와 승인 경계는 유지한다. [候補・検証・未適用](../infra/validation/service-query/claim-types.validation.json)
<!-- /service-claim-types-candidate-20261119 -->

<!-- panel-wording-followup-20261119 -->
판넬 METHOD를 구현 목적에서 구성·처리 흐름으로 이어지도록 다듬고 CONCLUSION은 연구의 구현 성과로 시작하도록 바꾸어 설명3줄을 보강했다. 기존 시험 수치·검증 한계와 ABSTRACT·이미지·표를 보존한다. 판넬 자료는 계속 로컬/Git 제외다.

[수정 이력](STATUS_HISTORY.md#panel-wording-followup-20261119) · [사용할 원고](PLAN_HISTORY.md#panel-wording-followup-20261119) · [검수 이력](DIAGNOSTIC_HISTORY.md#panel-wording-followup-20261119)
<!-- /panel-wording-followup-20261119 -->
