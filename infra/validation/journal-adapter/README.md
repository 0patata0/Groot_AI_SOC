# 등록 journal native 조회 어댑터

<!-- journal-composition:start -->
[통합 후보 검증](../journal-composition/README.md) — 서비스/호스트 journal/앱 오류34소스와 공통 소비자·스킬을 합쳤습니다. 서버1,453회귀·실제4ID/호스트42행을 확인했고, 현재 Native/운영 DB·봇에는 미적용입니다. 정확 소스·캐시 복구안/승인·로드·새 채팅이 남습니다.
<!-- journal-composition:end -->

<!-- diagnostic-read-boundaries:start -->
진단 경계 후속은 [검증 원장](../diagnostic-read-boundaries/README.md)에 정리했다. 내부µs·등록 대상 확인·명확한 상대 기간과 원인 괄호 반례를 보완했고 실제SDK3요청/4읽기·모델완료6·wire2성공/3거절을 확인했다. not-found/default Result의 미검출 해석 오류가 남아 미승격이며 현재 정본·초기 설치·운영/권한/모델은 바꾸지 않았다. 구조/회귀·실제 의미·새 채팅을 구분한다.
<!-- diagnostic-read-boundaries:end -->

후속 [실제 MCP·모델4요청](../host-journal-model/README.md)은 B의5읽기·12모델완료를 확인했으나 의미 오류·검사 오탐·대상 확인/시각 경계가 남았다. 운영 미적용·실제채팅0이며 아래 당시 관측을 성공으로 덮어쓰지 않는다.

후속 [집계 host journal](../host-journal/README.md)과 [파일별 비용 보완](../host-journal-cost/README.md)은 별도 미승인 수정이다. 파일별후보의실제24h A/B/C 응답은CLI전체병합과일치했다. 기존정확9코드적용계획은불변이며 이후속후보를포함하거나승인한것이아니다. 아래등록unit8건·부모21논리시험과후속78요청은대상/분모가다르다. 실제모델/MCP/새채팅은남는다.

후속 [정확 운영 적용안](application/README.md)은33개 고유 회귀를 Mac/A/B/C에서 각각 통과했고 실제 바이트9적용/9원복·18중간 cold load·3PREPARED/원본6개를 준비했다. 운영 source/service/timer·실제MCP/새채팅은 아직 미적용·미수행이다. 아래166검사·8건은 앞선 어댑터 구현 검증이며 합쳐 독립 정확도로 세지 않는다.

**공통 어댑터 구현과 166개 회귀, A/B/C의 실제 로그 격리 검증 8건을 완료했다. 운영 파일·서비스에는 아직 반영하지 않았다.** [원장](validation.json) · [이전 비용 실험](../journal-native/README.md) · [현재 상태](../../../STATUS.md).

## 직접 확인한 결과

같은 요청 구간을 유지하고 운영 reader와 같은 root/group·AF_UNIX·NoNewPrivileges·cap_dac_read_search·128MiB/8tasks 환경의 별도 임시 unit에서 실행했다. 후보의 표준 응답은 현재 설치된 구버전 validator도 모두 통과했다.

| 요청 | 새 어댑터 | 실제 관측과 한계 |
|---|---|---|
| A rule-worker 24시간 오류 후보 | 15.137초, 반환 표본 0 | 앞선 CLI 후보는 개별12초 시간 초과. 전체 오류 부재나 정상 판정은 아님 |
| B rule-worker 같은 24시간 | 7.400초, 표본 0 | 앞선 CLI 후보13.500초와 별도 실행. 캐시·부하 통제 비교는 아님 |
| C apache 같은 24시간 | 0.335초, 표본 0 | 앞선 CLI 후보0.305초. 모든 대상의 속도 향상을 주장하지 않음 |
| A 기존 1µs 구간 | 0.217초, 1행 | 기존 cursor SHA 일치, CLI와 행·has_more 일치 |
| A/B/C 같은24시간 전체 우선순위 tail | 0.300/0.271/0.265초 | 5/5/3행, debug를 오류 조회 조건으로 잘라내지 않음 |
| B management 과거6시간 오류 | 5.790초, 6행 | CLI와 모든 정규화 행·메시지/커서 해시·has_more 일치 |

기준24시간은 `2026-11-14T03:24:10.795222+09:00`부터다. 실제 요청·관측 시각·SHA는 원장을 따른다. 모든 응답은 전체 건수 null·보존 검증 false를 유지했다. 각1회이며 운영 부하/캐시를 통제하지 않았다. 실제 MCP·모델·Mattermost 요청0으로 채팅60초 목표나 p95·독립 관제 정확도를 입증하지 않는다. 앞선11.946초는 요약 프로토타입이고 이번15.137초는 표준 응답·접근검사를 포함한 별도 실행이다.

## 공통 구현과 권한

- [journal 공통 모듈](../../mcp/diagnostic_journal.py)의 source_row·마스킹·커서 충돌·finish·행 validator를 CLI 회귀 경로와 native 작업자가 함께 사용한다. [core](../../mcp/system_diagnostics.py)는 고정 child의 stderr와 취소·시간/바이트 한도를 감독한다.
- [private native 작업자](../../mcp/diagnostic_journal_native.py)는 등록된25개 service와 해당 호스트, 기존 요청 필드만 받는다. 임의 명령·파일·unit·패턴·셸·환경 선택 인자는 없다. root 소유·비쓰기 디렉터리와4개 코드 파일을 검사하고 일반 MCP 도구로 노출하지 않는다.
- python-systemd v235의 저수준 `_previous`로 실제 EOF와 빈 필드/읽기 실패를 구별한다. systemd255의 자체 unit·PID1/UNIT·root/OBJECT·coredump 필터, 정수µs·우선순위·고정 오류 literal 선택을 보존한다. 원문은 지시나 승인으로 취급하지 않는다.
- MESSAGE는 native에서 필터링하고 공통 마스킹 뒤 파이프로 보낸다. systemd JSON의 큰 필드 null·이진 byte 배열·다중 필드 표현을 맞추며 단순 메시지 절단으로 비밀 값을 노출하지 않는다. 마스킹은 best effort이고 비밀 비노출을 보증하지 않는다.
- 최대2개 child와2개 스레드·부모로5tasks, 구간 최대6시간/전체24시간, 개별12초·전체20초를 유지한다. 선행 작업은 취소·회수하며 요청 실패를 빈 성공으로 바꾸지 않는다. child 패킷64KiB·최종60,000B, 기존 전체1/2MiB 이하를 유지한다. 잘린 패킷의 정렬 경계보다 오래된 행을 대신 올리지 않는다.
- 전후 고정 journalctl zero-row 접근검사·child stderr 거절·native 중간 오류 전파를 적용했다. 이는 모든 journal 파일의 보존·완전성 인증은 아니며 기존 보존 미확인 표시를 없애지 않는다.

## 검사·설치·미완료

회귀는 native28·journal33·core43·history24·inventory15·설치23=166, 생략0이다. 바이너리/다중/대형 MESSAGE·정밀 경계·커서 충돌·접근 경고·중간 실패·패킷 잘림·동시2개·조기 종료/상대 작업 취소·실제 child 종료를 검사했다. 실제8건은 별도 표에 기록했으며 새 독립 정확도 시험이 아니다. 격리 시험 후 core의 docstring만 정정했고 실행 AST 일치를 확인했다.

단일 [설치기](../../../deployment/soc_diagnostics.py)는 새 helper를 기존 소스 묶음·설치/검증 영수증에 포함하고 systemd255·Python binding235/API 사전검사를 추가했다. A/B/C 모두 기존 `python3-systemd 235-1build4`·`libsystemd0/systemd 255.4-1ubuntu8.18`이 있어 설치0이다. 새 서버에는 [오프라인 목록](../../../deployment/setup-packages-artifacts.md)의 deb·의존성과 무결성 확인이 필요하다. 온라인 fallback은 없다. 설치 계약과 실제 새 OS 전체 설치는 구분한다.

초기 리팩터링의 unit 지역변수 누락, 설치 검사 mock 누락, 런처의 ROOT 치환 누락은 수정·재검사했다. ROOT 오류는 세 호스트 모두 mkdir/시험 unit 시작 전에 발생했다. 운영 장애나 모델 오답으로 집계하지 않는다. review-agent 원본 미발견으로 수동 결함 검토를 했으며 Semgrep 미수행, 하네스 변경이 없어 공식 Harness²는 이번에 실행하지 않았다.

서버 임시21파일286,019B/3폴더·Mac 임시15파일772,643B를 근거 보존 후 제거하고 부재를 확인했다. A/B/C 운영3source·unit·reader PID/시작ticks 불변·active를06:59 KST에 확인했다. 설치된 journal8336과 기존19파일 승인 대기 계획은 유지한다. 가중치/데이터·복구본·G_Harness2·원래 다른9작업은 보존한다.

다음은 별도 정확 적용/원복 계획·백업·관리자 승인이다. 기존19파일 트랜잭션의 whitelist나 승인 범위를 늘리지 않는다. 승인 후 운영 reader 재시작·실제 비특권 MCP·새 실제 채팅·확정이 필요하다. 현재 격리 통과를 운영 완료로 표시하지 않는다.
