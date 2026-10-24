# Groot_AI_SOC

> **2026-10-24 실제 채팅·Memory 정리:** 틀린 현재형 메모3항목과 활성 사본42개를 정정하고 실제 구동 경로를 읽기 근거로 제공했다. 실채팅의 목록22.206초·표0.140초는 정확했고 IDS의 기존 구동 경로 오답도 정정됐다. 다만 재질문126.243초·시각/표본/도구 인자 오류가 남아 자연어 전체 통과로 표시하지 않는다. [현재 상태](STATUS.md) · [실측/한계](infra/hermes/natural-chat-memory-validation-20261024.json).

> **2026-10-24 조회 경로 통합:** 룰/서비스/승인 상태 조회4종은 읽기 전용 `rule-a/b`, 변경 제안은 `rule-write-a/b`로 제공한다. 독립 계정·키와 root 경계로 중복 제공을 없앴고 기존 조회 이름을 보존했다. 논리 MCP8개/도구35개이며 추가 VM은 없다. 실제 조회·권한 거절·859회귀를 확인했다. 상세 적용/한계는 [STATUS](STATUS.md), 사용 경계는 [MCP 안내](infra/mcp/README.md)를 따른다.

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](STATUS.md) · [실행 계획](PLAN.md).
> 현재 구성은 A/B/C 역할 분리·MCP8논리 서버·HTTP3/터미널3·단일 deploy.sh(service schema9)다.6CVE 공격·탐지 시험은 사용자 지시로 보류하고 LLM 진단/알림 실패 보완과 문서 정리를 우선한다. 실제 검증 범위와 새 서버 설치 제외를 함께 확인한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

> 2026-10-24: 서버 패키지는 공식 검증한 deb를 오프라인 반입해 설치한다. Mac 작업용 바이너리는 반입·검증 직후 삭제한다. 세 서버 보안 업데이트의 설치/무결성 확인은 끝났으며 새 커널 부팅·보안/LLM 나머지 검증은 [STATUS](STATUS.md)를 따른다.

> 보완 적용: host sudo/커널147·기존 Java/관리망 격리·root 승인 진입점·검증 TLS8444/8445를 운영에 반영했다. A 필수 컨테이너의 재부팅 정책은 always이며 실습/백업 중지는 유지한다. 후속 LLM 진단·알림에서는 룰 표 제목 오탐·상태 표지 누락·종료 종류/종료값 혼동과 보고 전송 실패 처리를 추가 보완했다. 실제 SOC Alerts의 검증 알림2건은 저장 본문·API 재조회·WebSocket 수신을 확인했다. 실패·복구 이력과 새 설치 시험 제외는 [STATUS](STATUS.md)를 따른다.

> **일반 채팅 조회 보완:** 실제 대화의0도구/잘못된 룰 개수·IDS 비활성 주장을 확인해 현재 룰·장비 표·활성 전제 후속과 A/B 대상 구분을 보완했다. 파일 정의·요약·엔진 적재를 구분하며 읽기 전용 MCP와 승인형 룰 관리 MCP의 역할을 함께 유지한다. 배포·실제 모델 표본과 남은 한계는 [STATUS](STATUS.md), 동작은 [조회 플러그인 안내](infra/hermes/query-completion/README.md)를 따른다.

> **조회/조사 역할:** 단순 목록은 읽기로 제한하고, 장애 조사는 도구 결과 뒤 기존 승인형 변경안 준비를 보존한다. 실제 적용에는 기존 승인 경계를 유지한다.

> **룰 목록·표 속도 후속:** 1.3.1을 운영에 반영했다. 최종 native SDK의 현재 조회는28.229초/실제3읽기, 검증된 앞선 결과의 장비 표 재정리는0.072초/추가 모델·MCP0이었고 반환/저장 본문이 일치했다. 표의 근거 시점을 명시하며 실제 새 채팅 화면·일반 정확도/SLA와 구분한다. [최신 상태](STATUS.md).

## 현재 사용·검증 범위 — 2026-10-24

- **보안·LLM 보완:** 점검에서 확인한 호스트 패치·실습/관리망 격리·승인 실행 경계·내부 관리 TLS를 적용했다. LLM은 제한된 재조회와 근거 범위 검사를 적용하고 실제5질문을 재시험했다. 조회 성공과 모델 자체 해석·일반 정확도를 구분한다. [최신 결과와 한계](STATUS.md)를 먼저 확인한다. CVE 악용 시험은 보류 상태다.
- **접속:** [Lab Console](https://log4shell.grootlab.duckdns.org/log4shell/)에 HTTP3개(Log4Shell·Apache2.4.49/2.4.50)와 터미널3개(Redis·Samba·sudo)를 제공한다. DVWA는 기존 독립 주소다. 이번 허용 클라이언트의 HTTPS 목록·상태 조회는200/6항목·이미지6개였으며 실습을 새로 시작하거나 공격을 보내지 않았다.
- **관제:** A의 WAF·Suricata·Vector, B의 운영6컨테이너·승인 브로커, C의 API·터미널·guard와 Wazuh000/001/002 연결을 읽기 확인했다. MCP는6서버이며 고정 진단은25대상이다. oneshot의 정상 `inactive/dead`와 미사용 실습의 중지는 장애나 초기화 대상으로 취급하지 않는다.
- **진단 보완:** 사건 관리 경로에서 요청별 도구 제한·제한된 모델 재조회·근거 없는 보고의 검토 필요 처리를 적용했다. 도구/인자는 모델이 선택한다. 모델·전역 설정·승인 권한을 유지하며 확인한 DGX/Qwen 사건 관리와 지원하는 일반 채팅 룰 조회의 읽기 선택 단계에 요청별 reasoning_effort=medium을 적용한다. 완전히 검증된 파일 목록/표는 추가 모델 호출 없이 기존 native 저장/전송으로 전달한다. 완료·불완료 보고는 영속 큐에서 재전송하며 조사·조치를 다시 실행하지 않는다. 실제 자연어 조회·코드 결속 검증 수치와 한계는 [STATUS](STATUS.md)를 따른다.
- **진행 순서:**6CVE 재현·탐지 연결은 사용자 지시로 우선 보류한다. 진단/알림과 문서 최신화를 먼저 마감하고 시연 경로·실제 사건 대응·반복 평가를 후속으로 남긴다. 새3VM 전체 설치 시험 제외, 프로젝트 VPN·모바일 푸시 보류는 유지한다.
- **문서 읽기:** 아래 schema6/7/8·4/5항목·이전 접속·타이머·PID 설명은 날짜별 이력이다. 현재 신규 설치 소스는 service schema9이며 진입점은 `deploy.sh` 하나다. 초기 설치·기존 운영 최소 이관·실제 공격 E2E를 구분한다.

## 날짜별 구현·운영 이력

2026-10-24 후속 검증: Samba 만료·sudo daemon 정리·기존3호스트 재부팅/복구와 실제 SDK 조회를 확인했다. 자연어 모델의 도구 선택 실패와 A 첫 자동 기동 실패/복구는 [최신 현황](STATUS.md)에 구분해 기록했다. 새3VM 전체 설치와 실제 공격·대응 E2E는 완료 범위에 포함하지 않는다.

> 최신 완료·검증·남은 작업·Git 반영 상태는 [STATUS.md](STATUS.md)를 기준으로 확인한다. 작업 단위가 끝나면 관련 파일·현황을 갱신하고 검증 후 커밋·푸시까지 자동으로 진행한다([작업 규칙](AGENTS.md#작업-단위-완료-시-자동-커밋푸시)). 2026-10-23 일시정지 구간 재검증은 운영267/267 통과, 회귀240개 통과·환경상1개 생략이며 실제 SDK 재조회도 통과했다.

## 읽기 전용 시스템 진단 운영 연결 완료 (2026-10-23)

A/B/C의 고정25개 systemd 대상에 root 수집기·권한을 제한한 snapshot reader·단일 `get_system_diagnostics` MCP를 연결했다. 일반 sudo·Docker·임의 shell/journal 권한은 추가하지 않는다. 기존 B는 원본 해시·유휴/승인/lease 검사와 복구 백업을 거쳐 최소 이관했으며, 단일 `deploy.sh`의 새 서버 설치 경로도 같은 소스 계약을 사용한다. 운영 서버에는 초기 설치기 전체를 실행하지 않았다.

설치된 MCP SDK2.0.0의 표준 `_meta` 호환성과 journal grep의 정상적인 일치 없음 처리를 보완했다. core33·진단 설치기18·controller37·SIEM40 회귀와 실제 UID995 SDK의6개 MCP initialize/list, 잘못된 인자·쓰기 도구 거절을 확인했다. 최종 A/B/C4개 대상 조회에서 A/B 오류 표본0과 C의 과거 `publication_failed` 분류를 확인했다. C terminal 오류103개 중 보존50개로 잘림이 있으므로 전체 로그 건수나 정확한 원인 분석으로 해석하지 않는다. 원문 MESSAGE·환경·명령·HTTP 본문은 반환하지 않는다.

[실제 SDK·운영 증거](infra/mcp/system-diagnostics-validation-20261023.json) · [설치·후속 핀 증거](deployment/diagnostics-journal-fix-validation-20261023.json) · [추가 검증 계획](infra/추가검증_계획_2026-10-23.md). 새3VM 전체 설치·실제 취약점 공격/탐지/대응 E2E·재부팅·장시간 터미널 만료는 이번 완료 범위와 구분한다.

## 파비콘 재발 후속 완료 (2026-10-23)

기본 `/favicon.ico`·Apple 아이콘 요청이 이미지로 연결되도록 프록시를 보완하고, 메인/터미널은 새 이름의 로컬 ICO를 정적으로 선언한다. 공통 테마 스크립트는 이미 맞는 아이콘을 제거하지 않는다. 실제 HTTPS의 상태·MIME·자산 SHA가 일치했고 설치기 반입/검증 목록도 갱신했다. Safari에 남은 오리 아이콘은 사용자 승인 후 아이콘 캐시만 백업·재생성하여 같은 주소의 서버 선화 표시를 확인했으며 사용자도 확인했다. 방문 기록·쿠키·암호는 변경하지 않았다. [검증 증거](infra/groot-c/offline-labs/favicon-validation-20261023.json).

## sudo 웹 터미널 운영 반영 완료 — 2026-10-23

마지막 sudo 항목은 기존에 `ready` 상태만 표시하고 웹 실행·접속은 제공하지 않았다. **HTTP3개 + 웹 터미널3개, 총6항목**의 소스를 C에 반영하고 실제 HTTPS 터미널을 검증했다. sudo도 같은 [Lab Console](https://log4shell.grootlab.duckdns.org/log4shell/)에서 **실습 환경 시작 → 환경 열기**를 사용하고, 이미지 준비 완료6개를 확인했다.

sudo는 기존 별도 rootless 런타임과 이미지·반입 bundle을 유지한다. 호스트 전용 계정 UID1991, 컨테이너 시작 UID1000, user namespace 안의 setuid 실습 조건을 유지하며 호스트 sudo나 일반 Docker 권한을 제공하지 않는다. sudo 터미널은 전체1개만 허용하고 **연결 종료·입력 유휴5분·전체30분·터미널 서비스 종료 시 해당 sudo 컨테이너 전체를 중지**한다. 다시 연결하려면 콘솔에서 환경을 시작해야 한다. Redis/Samba의 세션 종료와 실습 중지 구분은 그대로다.

단일 `deploy.sh`의 service **schema9**에 이 연결을 반영했다. 아래 schema8·터미널2종의 완료 기록과 [기존 검증 JSON](infra/groot-c/nonweb-labs/validation-20261023.json)은 sudo 웹 연결 전 이력으로 보존하며 새3종의 운영 완료 증거로 사용하지 않는다. DVWA는 독립 주소를 유지하고 새 VM3대 전체 설치·실제 취약점 악용/방어 E2E는 별도 검증이다.


검증은 native 콘솔97개·nonweb121개, 설치기 service50개·controller35개와 Node2종이다. 실제 HTTPS에서 sudo UID1000·패키지1.8.31-1ubuntu1·터미널 크기 변경·Ctrl+C·단일 연결·연결 종료 시 전체 중지·활성 세션 중지·새 CID 재시작을 확인했다. 기존 rootful 컨테이너는 적용 전후 동일했다. 새로고침한 Safari에서 이미지6개·sudo 항목과 시작 버튼은 확인했고, 사용자 브라우저 조작과 겹쳐 sudo 터미널 명령의 시각 검수는 별도로 완료 처리하지 않았다. [sudo 운영 증거](infra/groot-c/nonweb-labs/sudo-web-validation-20261023.json).

## Redis·Samba 확장 완료 당시 구성·schema8 — 2026-10-23

[Lab Console](https://log4shell.grootlab.duckdns.org/log4shell/)의 운영 카탈로그는 **HTTP 실습3개 + sudo CLI1개 + Redis/Samba 웹 터미널2개**다. Redis **CVE-2022-0543**(Ubuntu `5:5.0.7-2`)와 Samba **CVE-2017-8594**(4.6.3)는 같은 콘솔에서 **실습환경 시작 → 환경 열기**를 선택해 브라우저 터미널을 여는 흐름을 추가했다. sudo는 기존 별도 rootless CLI를 유지하고, DVWA는 원래 독립 주소에 그대로 둔다.

터미널은 선택한 격리 컨테이너의 고정 비권한 계정에만 연결한다. 같은 실습의 세션은 컨테이너·계정을 공유하며 사용자별 OS 격리는 아니다. 실습 중지는 해당 Redis/Samba 컨테이너와 휘발성 데이터를 정리한다. WAF 차단 예외 키는 기존 HTTP3개 실습용이며 터미널 권한을 부여하지 않는다. 콘솔과 실습 페이지에는 공통 차콜/웜화이트 테마와 서버 선화 파비콘을 사용하고 외부 CDN 없이 로컬 터미널 자산을 제공한다.

C에 두 이미지와 전용 런타임·터미널 API를 반영했다. native 콘솔94개·런타임/daemon67개·이미지 준비22개 회귀를 통과했고, 실제 HTTPS에서 비권한 셸·서비스 응답·Ctrl+C·다른 세션 보존·시작/중지와 호스트 방향 연결 차단을 확인했다. 새로고침한 Safari에서는 서버 파비콘과 Redis 터미널의 UID10001·PONG을 확인했다. [운영 검증 근거](infra/groot-c/nonweb-labs/validation-20261023.json).

단일 `deploy.sh`의 service **schema8**에6항목 카탈로그·터미널 자산·고정 nonweb bootstrap을 연결했다. `LAB_NONWEB_BUNDLE`의 검증된 Redis/Samba 이미지 묶음을 반입하며 초기 설치 완료만으로 두 실습을 자동 시작하지 않는다. **새 VM3대 전체 설치 시험은 사용자 요청으로 계속 보류**하며 실제 취약점 악용·탐지/LLM 대응 E2E·재부팅은 검증하지 않았다. [설치 순서](deployment/bootstrap-guide.md) · [터미널과 격리 범위](infra/groot-c/offline-labs/README.md).

## 콘솔 개편·단일 초기 설치기 — 2026-10-23 확장 전 기록

> 아래4항목·schema7·HTTP35개·native66개 결과는 Redis/Samba 확장 전 검증 이력이다. 현재 운영 구성과 검증 범위는 위 항목을 따른다.

메인에 수평 메뉴·큰 제목·서버 선화·실습 현황 띠를 적용했다. 메인과 Java·Apache 두 하위 실습 화면은 같은 차콜·웜그레이/웜화이트 팔레트를 공유한다. 외부 CDN 없이 동작하며 DVWA는 기존 독립 화면을 유지한다. 최신 서버 자산 SHA 일치와 공개 HTTP35개 검사를 통과했다. 선택한 HTTPS origin의 Secure 쿠키 회귀를 포함한 C native66개도 통과했다.

새3서버 초기 설정은 `bash deploy.sh --apply --batch --config deployment/site.local.conf` 하나로 시작한다. 승인된 로컬 deb·이미지 반입, SIEM→공통 키 전달→콘솔/웹3종·sudo→TLS/WAF 구성을 내부 helper로 연결했다. [준비물·실행 순서](deployment/bootstrap-guide.md). **새 VM3대 전체 적용은 아직 미실행**이며 운영 웹 검증과 구분한다.

## 실습 페이지 테마·DVWA 범위 정정 — 2026-10-23 적용 완료

Log4Shell HTTPS 주소의 **콘솔·Java·Apache 두 버전** HTML에 상단 단일 테마 버튼을 제공한다. 현재 모드인 `다크` 또는 `화이트`와 같은 16px 크기의 달·해 아이콘을 표시하고, 고정된 아이콘 자리·가운데 정렬한 글자 슬롯과 약180ms 색상 전환을 사용한다. `prefers-reduced-motion`을 존중하며 외부 CDN 없이 같은 사이트의 `localStorage`에 선택을 보존한다. 최신 자산의 서버 SHA 일치와 새로고침한 Safari에서 고정 아이콘·글자 가운데 정렬·양방향 전환을 확인했다. Java·Apache 두 버전의 테마 동작도 확인했다.

사용자는 **DVWA를 원래 독립 주소에서 그대로 유지**하도록 범위를 정정했다. 앞서 같은 Log4Shell 사이트에 연결한 것은 요청 범위를 잘못 확대한 작업이었다. 정정 당시 카탈로그는 **Java·Apache 두 버전·sudo 총4항목**, 웹 실습은 관리형3개였다. 추가했던 DVWA 프록시·카탈로그 연결·전용 예외 쿠키·테마 처리만 제거했으며, 원래 DVWA 앱·DB·독립 접속 경로는 유지했다. 10/22의 5항목 배포·검증 자료는 당시 이력으로 보존한다.

## 오프라인 실습 관리 웹 — 2026-10-22 배포·10/23 범위 정정 완료

기존 Log4Shell 주소를 **[Lab Console](https://log4shell.grootlab.duckdns.org/log4shell/)**로 전환했다. 로컬 `cve_list.json`과 준비된 Docker 이미지만 사용하며, **Log4Shell·Apache httpd 2.4.49/2.4.50** 3개는 관리형 웹 실습으로 실행·중지한다. **sudo CVE-2021-3156**은 웹 실행 없는 별도 rootless CLI 항목으로, rootless 런타임·무해한 환경 검증·정식 상태 발행 검증을 완료했다. 실제 권한 상승·호스트 탐지 시나리오는 검증하지 않았다. 키 없이 목록과 웹 실습을 사용할 수 있다. 선택 입력하는 차단 예외 키는 기존 Wazuh Dashboard 관리자 암호와 같으며, 일회용 HMAC 서명을 검증한 10분 세션 동안 해당 실습의 WAF 탐지는 기록하되 차단을 유예한다. [접속 방법·전체 소스·오프라인 설치/반입·복구](infra/groot-c/offline-labs/README.md).

FastAPI·고정 기능 broker·격리망을 C에 설치하고 기존 A/C 프록시를 전환했다. 기존 Java 컨테이너는 복구용으로 유지했다. 아래 10/19의 공개 Java 화면과 초기 구축 설명은 당시 이력이며, 새 관리 웹은 아래 단일 `deploy.sh`에서 내부 설치기를 자동 호출한다.

정정 후 C native 회귀 **64개**와 최종 HTTP **35개** 검사를 통과했다. 당시4항목·기존 DVWA 독립 주소200/테마 미주입·제거한 DVWA 경로404·실행/중지409, 기본 HMAC 세션·Apache 두 버전의 합성 차단/예외/복원·sudo 준비 상태를 확인했다.

10/22 당시 다중 실습 backend **64개**·공개 HTTPS **31개**·DVWA 예외 경계 **15개**, 합성 검사9건의 WAF→Wazuh alerts→Indexer 전달을 확인했다. 이 결과는 정정 전 구성의 이력이며 정정 후4항목의 최종 검증 결과로 대신하지 않는다. 실제 취약점 공격·탐지·차단 E2E는 수행하지 않았다. [공식 규칙 후보27개](infra/groot-c/offline-labs/rule-source-candidates.json)는 조사 자료이며 운영에 반영하지 않았다. 이 단계의 단일 초기 설치 경로는 service schema7로4항목 콘솔·웹이미지3개·별도sudo 환경까지 구성했다. 현재 schema8 확장은 위 항목을 따른다. 새 VM3대 실제 적용 검증은 아직 미실행이다.

## 통합 SOC 대시보드 — 2026-10-19 생성 완료

학과 VPN에서 **[Groot SOC | 통합 탐지 현황](https://wazuh.grootlab.duckdns.org/app/dashboards#/view/groot-soc-20261019-dashboard)**을 연다. WAF·Suricata·Wazuh 기타 알림의 수치·추이·주요 탐지·출발지·최근 알림을 14개 패널로 표시한다. 기본 최근 7일, 30초 자동 갱신이며 실제 브라우저 표시와 API 재조회를 검증했다. [집계 의미·복원 파일·적용 근거](infra/groot-b/soc-dashboard/README.md). VPN 임시 접근 종료 시각은 아래와 같으며 저장된 대시보드는 유지한다.

2026 capstone project — nftables, Suricata, ModSecurity, Wazuh, Mattermost, Hermes 기반 실습 SOC.

현재 운영 이력은 [STATUS.md](STATUS.md), 진행 계획은 [PLAN.md](PLAN.md)에 있습니다. 날짜별 대화·작업 기록은 로컬 전용 `대화기록/`에 보관하며 Git에는 포함하지 않습니다. 이 문서의 새 환경 구축과 기존 운영 서버의 변경 이력을 구분합니다.

운영 목표는 **LLM을 SOC 관리 주체로 두는 것**입니다. 사건 조사·대응 판단·구체 변경안·승인 요청·결과 확인을 LLM이 맡고, 관리자는 보호된 변경을 승인하거나 거부합니다. 제한된 helper/worker는 허용 범위와 증거를 검증하고 실행합니다. 긴급 임시 선차단도 LLM 판단을 거칩니다. 2026-10-15 관리 경로 전환의 실제 적용·검증 범위는 STATUS의 해당 이력을 따릅니다. 2026-10-23 초기 설치기에는 승인형 운영 경로를 연결했으며, 소스·격리 회귀 검증과 새 VM 전체 설치 검증은 구분합니다. 새 VM 설치 시험은 아직 수행하지 않았습니다.

## 시연용 Wazuh VPN 접속 — 2026-10-20 23:59 KST까지

학과 VPN 연결 후 **[Wazuh Dashboard](https://wazuh.grootlab.duckdns.org/)**에 기존 계정으로 로그인한다. 10/19 22:55 KST 실제 VPN 인증서·로그인·대시보드 상태green과 종료 서비스의403을 검증했다. VPN 임시 허용은 **10/20 23:59:00 KST** 자동 종료되며 기존 학과망 접근은 유지한다. [적용 범위·자동 종료·검증 근거](infra/groot-a/wazuh-demo-access/README.md).

## Log4Shell Java 웹·초기 자동 빌드 — 2026-10-19 완료

기존 C 앱의 JAR·실행 환경을 직접 확인한 기록에서 Spring Boot **2.6.1**, Log4j API/Core 각각 **2.14.1**, Java **8u181**을 확인했습니다. 새 [Spring Boot 실습 웹](infra/groot-c/log4shell-app/README.md)은 화면과 로깅 API를 직접 제공하며, `/log4shell/`에서 입력한 요청 파라미터 또는 헤더를 변경 없이 기록합니다. API는 상태 조회로 받은 CSRF 토큰·쿠키를 사용하는 `POST /log4shell/api/log`이며 이전 앱의 `GET /` 계약과 다릅니다.

당시 초기 설치기는 service **schema6**로 Java JAR을 자동 빌드하거나 준비 JAR을 사용했습니다. 후속 schema7에서 검증된 이미지와 통합 콘솔로 전환했고, 현재 소스는 Redis/Samba까지 연결한 schema8입니다. 이 항목은10/19 이력입니다. 기존 운영 C의 Java 웹 교체·정상 요청 검증은19:57 KST 완료했고, 컨테이너 재생성 자동화의 후속 결과는 [STATUS](STATUS.md)에 별도로 기록합니다. 무해한 요청의 응답·로그 확인, 새 VM 구축, 실제 공격·콜백·탐지 E2E는 서로 다른 검증 범위입니다. [이전 PHP 웹의 검증 이력](infra/groot-c/log4shell-ui/README.md)은 당시 결과로 보존합니다.

## 룰 개수·ID 조회 근거 반영 — 2026-10-16 21:00 KST

A/B 조회 실행기에 같은 파일 바이트·SHA로 계산한 집계를 추가하고, **21:00:20 KST** Hermes1.1·일반/관리 정책·현재 참조53개에 반영했습니다. 순수 커스텀 룰 목록·개수 요청은 LLM이 실제 조회한 응답의 원문·SHA와 집계가 일치해야 확정 목록으로 표시합니다. 확인된 **대상 파일 정의는 WAF10개, Suricata14개(로컬12+ET2), Wazuh19개(level0 포함)**입니다. 예비 ID·주석·체인 후속 조건을 별도 규칙으로 세지 않으며 실제 엔진 적재 수나 전체 CRS/ET 개수를 뜻하지 않습니다.

실제 모델 native 시험57.38초·API3회·읽기3회에서 정확한 개수·ID·저장 답변 일치를 확인했고,999개 오류 합성 시험과 플러그인150개 회귀도 통과했습니다. 기존 Hermes 컨테이너만 한 번 재시작한 뒤 **21:02:22 KST** 새 버전 등록·53개 정책 참조·DB·Mattermost/API 연결·heartbeat·timer를 확인했습니다. config·env·cron·다른 DB 내용과 승인 권한을 유지하고 새 패키지·보안 엔진 재시작은 없었습니다. **실제 Mattermost 새 게시·화면 E2E는 수행하지 않았습니다.** 복합 분석·사용자 지정 형식은 이 목록 처리 범위 밖이며 모든 답변의 정확도나 응답 시간을 보장하지 않습니다. [운영 범위](infra/hermes/query-completion/README.md) · [검증 근거](infra/hermes/rule-inventory-validation-20261016.json).

## 조회 실행 보완 적용·답변 정확도 개선 진행 중 — 2026-10-16

> 아래는 20:34의 1단계 당시 기록입니다. 이후 파일 정의 개수·ID 집계는 위21:00 후속에 반영했습니다.

조회를 약속한 뒤 도구 없이 끝나는 응답을 보완하는 1단계를 **20:34:01 KST** 운영 Hermes에 적용했습니다. 현재 세션 정책 참조 53개와 일반·관리용 SOUL을 갱신하고 같은 컨테이너를 한 번 재시작했으며, 20:34:41 Mattermost/API 연결·timer·실제 플러그인 등록을 확인했습니다. 기존 native 파일 8개, `.env`·cron·다른 DB 내용은 보존하고 config에는 플러그인만 추가했습니다. 최초 YAML 사전 검사 실패는 운영 변경 전에 중단했습니다.

최종 native 시험 2건에서 각각 실제 읽기 조회 3건과 최종 답변을 확인했고, 별도 미실행 경로는 조회 실패를 정직하게 안내했습니다. **규칙 개수·예비 규칙·상태 설명의 정확도는 아직 해결 중이며, 사용자 요청에 따라 2단계를 진행하고 있습니다.** 조회 실행 성공을 정확도나 응답 시간 보장으로 해석하지 않습니다. [동작·복구 범위](infra/hermes/query-completion/README.md) · [검증 근거](infra/hermes/rule-query-execution-validation-20261016.json) · [초기 설치기 반영](deployment/README.md).

## 채팅 답변 서식 — 2026-10-16 변경

SOC 채팅 답변은 **요약 → 확인 내역 → 조치 및 다음 단계** 순서를 유지하면서, 확인 내역을 표 대신 `- **대상명**: 상태 — 근거` 목록으로 작성합니다. 승인 안내는 대상·변경 전·변경 후·예상 영향·검증·승인 상태의 여섯 항목을 각각 한 줄에 씁니다. 표는 Markdown 문서·파일 본문이나 사용자가 명시적으로 표를 요청한 경우에만 사용하며, 파일을 제공하는 채팅 안내도 목록으로 씁니다. 승인 카드와 원문 로그·diff는 바꾸지 않습니다.

2026-10-16 19:13:42 KST에 현재 세션52개와 자동 관리용 SOUL에 반영했습니다. 초기 설치기는 같은 서식4개 지침만 복사하며 기존 읽기 전용 역할·MCP2개 권한을 유지합니다. SIEM 회귀31개·정책 갱신 회귀11개와 실제 모델의 합성 상태/승인 사례2개를 통과했습니다. 채팅 게시나 클라이언트 화면 렌더링 시험은 수행하지 않았으며 모든 출력의 서식·정확도를 보장하지 않습니다. [서식·문맥 안내](infra/hermes/mattermost-context/README.md) · [검증 근거](infra/hermes/chat-format-validation-20261016.json).

> 다음은 2026-10-15 최초 표 서식의 당시 기록입니다. 현재 채팅 서식은 위 목록 정책을 따릅니다.

SOC의 조사·상태 답변은 **요약 → 확인 내역 → 조치 및 다음 단계** 순서와 간결한 근거 표를 기본 서식으로 사용합니다. 초기 설치기도 같은 서식4개 지침만 [운영 정책](infra/hermes/SOUL.groot.md)에서 가져오며, 기존 읽기 전용 역할과 MCP2개의 권한은 유지합니다. 원문 구획 검사와 소스 해시 검증이 실패하면 설치를 중단합니다. 라이브 서식은2026-10-15 18:23:59에 반영했고 모델 표본을 확인했으나 모든 답변의 기계적 서식 강제나 정확도 보장은 아닙니다. [채널·스레드 문맥 안내](infra/hermes/mattermost-context/README.md).

## Bash 하나로 초기 설치

SSH·서버 주소·승인된 오프라인 반입물을 준비하고 저장소 루트에서 실행합니다.

```bash
cp deployment/config.example.conf deployment/site.local.conf
# 실제 서버 주소·SSH 경로·HTTPS 이름·허용 내부망·LLM 주소를 편집
bash deploy.sh --apply --batch --config deployment/site.local.conf
```

이 진입점 하나가 **반입물 검사 → 로컬 패키지/이미지 설치 → 역할 사전검사 → SIEM → 공통 키 전달 → service → security → 승인·대응/로그 처리/대시보드 → 전체 검증**을 호출합니다. 패키지·이미지는 인터넷에서 자동 다운로드하지 않고 서버에 반입한 파일만 사용합니다. 전체 저장소가 필요하며 내부 helper를 사용자가 따로 실행하지 않습니다. 향후 서버 변경 시 설치기·반입 목록·설정 예제·검증도 같은 작업에서 갱신합니다.

| 역할 | 초기 구성 |
|---|---|
| SIEM | Wazuh·Indexer·Dashboard, Mattermost/PostgreSQL, Hermes 읽기·승인 MCP, 승인 브로커·관리 경로, 상관관측·통합 SOC 대시보드 |
| service | 독립 DVWA/MariaDB, schema8 Lab Console·제한된 broker·nft guard, HTTP 실습3개·sudo CLI1개·Redis/Samba 터미널2개, 상태 발행·agent |
| security | Suricata·DVWA WAF, Log4Shell TLS·실습 WAF, agent, Vector 정제·회전·보존, 승인 worker·제한된 nft 대응 |

`--plan`은 네트워크 접근 없이 입력만 검증합니다. `--check`는 읽기 검사이며 빈 서버의 미설치 패키지를 보고할 수 있습니다. 기본 `--apply`가 로컬 deb와 이미지 archive까지 설치합니다. `--verify`는 기존 동일 구성만 검사합니다. 기존 운영 서버나 구형 service schema6/7을 자동 덮어쓰지 않습니다.

| 준비·실행 문서 | 내용 |
|---|---|
| [단일 설치 전체 가이드](deployment/bootstrap-guide.md) | 정확한 순서, artifact manifest, 자동 설치 범위, 출력·실패 시 동작 |
| [설정 예제](deployment/config.example.conf) | 서버·HTTPS·허용 CIDR·서버 내 파일 경로 |
| [VM·네트워크·SSH 준비](deployment/setup-network-ssh.md) | 고정 주소·라우팅·키 검증·sudo |
| [패키지·이미지 반입 자료](deployment/setup-packages-artifacts.md) | 외부 Linux 준비 환경에서 공식 패키지·이미지 확보 |
| [Hermes 이미지 준비](deployment/hermes-image.md) | 기반 이미지·가드·의존성·빌드 |
| [실습 소스·이미지](infra/groot-c/offline-labs/README.md) |6항목 카탈로그·3개 웹이미지·Redis/Samba 터미널·차단 예외·테마·독립 DVWA |
| [sudo 초기 준비](infra/groot-c/offline-labs/nonweb/sudo/runtime/BOOTSTRAP.md) | 고정 rootless bundle·서명 검증·초기 구성 |
| [Redis/Samba 준비](infra/groot-c/nonweb-labs/README.md) | 별도 이미지 bundle·고정 런타임·웹 터미널·격리 계약 |

초기 성공 주소는 `LAB_PUBLIC_ORIGIN/log4shell/`, 독립 DVWA는 `http://SECURITY_HOST:WAF_PORT/dvwa/`, Wazuh는 `https://SIEM_HOST`, Mattermost는 `http://SIEM_HOST:8065`입니다. SIEM `admin` 암호를 Lab Console 차단 예외 키로 직접 연결하며, 원문은 SSH 파이프로 service에 전달합니다. 인증자료는 서버 root 전용 경로에 두며 Git·Mac 임시파일·로그에 기록하지 않습니다.

## 검증 범위와 운영 이식

셸 구문·가짜 SSH 전송 순서·오프라인 반입 검증·service schema8·6항목/터미널 자산 결속·TLS/WAF 설정·installer 실패 경로·sudo와 nonweb 고정 권한 계약을 회귀 검사합니다. 운영 서버에서 확인한 웹/HMAC/WAF canary/sudo 환경 결과와 새 초기 설치 시험은 구분합니다. **새 Ubuntu VM3대 전체 설치는 아직 미실행**입니다. 구현·격리 회귀를 실제 새 서버 설치 성공으로 표시하지 않습니다.

2026-10-23 설치기 소스에 승인형 쓰기 MCP·브로커·worker·제한된 nft 대응/Native AR, Vector 정제·원본 세대 회전·출력 유지관리·이전 부트 로컬 보관, Indexer 상관관측과 통합 SOC 대시보드를 연결합니다. **실제 새 VM 설치 시험은 사용자 요청으로 제외**했습니다. 위의10/16 읽기 MCP2개 설명은 기본 SIEM 단계의 이력이며, 이번 확장 단계가 승인·대응 경로를 추가합니다. 상세 계약과 검증 한계는 [초기 설치 가이드](deployment/bootstrap-guide.md)를 따릅니다.

다음 범위는 이번 설치기 통합에 포함하지 않습니다.

- 운영망 FORWARD/NAT 정책과 기존 운영 계정·승인 DB·수동 변경 이력 이관
- A→B 이전 로그 전송, 긴 장애 구간 무손실 회수·일반 백업
- DGX/Imperva 고정 주소 예외·정기 보고·실제 CVE 공격과 탐지/대응 E2E
- DNS/공개 인증서 발급·채팅 HTTPS·모바일 푸시·SSL VPN 자체 구축·모델 학습

Suricata는 기본 수동 탐지 모드이며 nft 대응은 LLM 조사·판단과 제한된 실행 경로를 거칩니다. LLM에 일반 sudo/Docker·패키지 설치 권한을 주지 않습니다. 이전 PHP·Java 직접 구동 설명은 각각의 README와 검증 이력에 보존합니다.
