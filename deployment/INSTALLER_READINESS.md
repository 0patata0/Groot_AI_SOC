# 초기 설치·통합 패키지 준비 상태

현재 query1.19.108/common1.5.56·진단MCP1.2.7·routing1.1.6은 서비스 이력/현재 관제 지표를 구분하고, 단문 대기열 조회가 불필요한 조사로 확대되던 경로를 통일한다.1,345고유PASS/skip0·B21SHA/보호8·양봇 연결/독립원복을 확인했다.108 새 단문은 **Hermes17.272초/Ollama17.074초**, 각1실제조회로 지표표를 완료했다. 재시도에서도 현재 대기열 대상 범위를 유지한다. 일부 채팅 지표의 미확인은 표시하고 원인을 확인 중이다. **일반 원인·복합 조사에서 정확한60초 목표는 미완료**다. 모델·권한·승인·FW/TTL·패키지 변경0, 새OS 전체설치·평균/p95 미시험. [변경·실측·복구](../infra/hermes/pipeline-navigation.md).

11/6 [복합 사건 읽기 연결](../infra/hermes/incident-bundle.md): query1.19.74/common1.5.33·security-events1.3.0/진단1.2.2를 함께 반영했다. `incident_evidence.py`와 기존 SIEM/SDK/관리 소스 복사·백업/원복을 사용하며 내부 MCP 검증은7읽기다. 원본 근거/인용/권한 검사를 유지하고 모델 표시만 무손실 압축한다. 고유1,215검사·운영17파일/보호7SHA 확인. 추가 deb/wheel/image·포트·키·입력 설정0. 최종30초/실제 새OS 설치는 미완료다. 아래 날짜별 기록은 당시 범위다.

11/6 [과거 서비스 오류 조회](../infra/mcp/journal-history.md): 단일 deploy.sh의 진단 소스 묶음에 diagnostic_history.py를 추가하고 초기24시간 분할 수집을 연결했다. 기존 timer/reader/MCP·Python 표준 SQLite 사용, 새 패키지·포트·키·권한0. A/B/C 증분 운영과 고유123검사·실제 SDK11호출 확인, A 일부 구간 공백·최종30초·새OS 전체설치 미완료는 구분한다.

11/4 웹 읽기 연계: 기존 단일deploy.sh→service diag-apply 내부 설치와 SIEM 복사 경로에 `web_access_deploy.py`·`web_evidence.py`·`read-web-evidence.py`·`web_evidence_client.py`를 연결했다. 별도 계정/SSH 강제 명령·publisher/timer 계약6과 진단18·관리38 검사를 통과했다. 기존 운영 증분 적용/MCP 조회는 [별도 근거](../infra/mcp/web-evidence.md)이며 새 OS 전체 설치 증거가 아니다.

2026-11-05 KST. 단일 `deploy.sh` 기반은 구현했으나 완성된 일괄 배포 제품으로 표시하지 않는다. 실제 새3VM 설치는 사용자 조건으로 실행하지 않았다. [현황](../STATUS.md) · [운영](OPERATIONS.md) · [공식 지침 부분 대조](SECURITY_GUIDELINES.md) · [이전 점검](../archive/deployment-INSTALLER_READINESS-before-read-accuracy-ncsc-20261104.md).

| 항목 | 확인한 범위 | 남은 범위 |
|---|---|---|
| 단일 진입점 | root deploy.sh→역할·SOC·진단·선택 봇·오프라인 반입 | 전체 새 서버 설치 미시험 |
| 웹 정책 | On·UI/API 포함 WAF·관리 CIDR+HMAC 소스 연결 | role 검증의 lab_waf_mode 구 설명 문자열 잔여·실제 새 환경 경로 검증 |
| 공동 채널 | remote.sh에 siem review-chat-install/verify 두 작업만 추가. 역할3×작업명4=12조건으로 허용/거부 검사 | 실제 신규 review 설치는 미실행 |
| 컨트롤러 | 누락된 security host-check/verify fixture3을 실제 실행 순서로 정정. 가짜SSH46PASS | 가짜SSH는 실제 remote dispatcher/VM 설치·복구 증거 아님. 별도 NAT/Ansible 후보는 이번 검증·게시 범위 밖 |
| 공통 하네스 | read_contract/chat_harness/grounding/query·SDK runtime/harness와 출력 SKILL이 기존 복사/묶음 경로 사용. 사건/검증실패에도 단일soc-output재사용·내부 실행별 읽기 metadata·불변 포함gate와root참조SHA결속. 설치계약38PASS | 새 OS 실행 시험 없음·패키지/포트/키 추가0 |
| 사건 종결 검사 | Native/SDK가 공통의 명시적 판단·자산별 사건 시각 조회/인용 최소 검사 사용. SDK 구조화 선택 묶음/오류 피드백도 기존 소스 복사 경로로 설치. 관리247/설치38·전체951PASS, 실제 오류 출력 거절·미해결 유지 재생 | SDK 보호 쓰기/혼합 요청 전체 동등성·실제 영향/종결·새 보고 시각/의미·신규 설치 미완료. Native 읽기 인자의 실제 스키마 검사/실제-32602 응답 구분도 같은 common/query/SDK 경로에 포함·서버961PASS. 기존 고정Native/SDK의jsonschema/MCP 의존성을 사용하며 새 패키지/포트/키0, 오프라인 반입은 기존 소스 갱신만 필요. [범위](../infra/hermes/incident-closure-minimum.md) |
| 두 봇 프로필 | trial/chat/review 옵션·제한된 권한 모드 | 기본enable0/read-only와 현행 운영 두 봇 프로필을 구분. 완성된 제품 프로필 필요 |
| WAF 원문 대응 | configure_waf_evidence 소스 포함 | 초기 producer/raw/pin/enrollment 자동 연결 미확인 |
| 오프라인 | 역할별 deb/image SHA·버전 검사·로컬 설치 | wheel/TLS/runtime/catalog 등 포함 최종 통합 반입물·하위 의존성/서명 대장 미완성 |
| 운영 지침 | 현행 가이드의 WAF 우회/검사 면제 문구 정정·운영 절차와 공식 지침 대조 연결 | 로그 장기보존/용량·백업복원·시간동기화·전 경로/사건 종결·기관별 책임/주기 확인 |

이번 설치기 변경은 소스 허용목록과 회귀검사뿐이며 운영 서버에 초기 설치/적용/재시작을 하지 않았다. 같은 기간 B 봇의 증분 보완·재시작과 혼동하지 않는다. 새 의존성·deb/wheel/image·공개 포트·자격 키는 추가하지 않는다. 기존 반입 소스만 갱신한다.

11/5 [공통 업무 스킬](../infra/hermes/workflow-skills.md) 보완: soc-output과 조회/사건/변경/복구4개 절차를 같은 canonical 원본으로 배포한다. 기존 단일deploy.sh의 SIEM23파일·SDK source_files·관리 source_bundle에 로더/flat 별칭을 연결하고 네 SKILL의 파일명 충돌을 검사했다. 설치 계약39·SIEM역할40PASS, 전체 서버1,091PASS/skip0. 기존 고정 의존성만 사용해 새 deb/wheel/image·키/포트는 없다. 운영은 A2/B30파일 증분 반영·확정했으며 새 OS 전체 설치는 실행하지 않았다. 권한/역할/정확 승인 강제는 SOUL와 서버 코드에 유지한다. 실제 조사 시간초과·새 UI/자동 자기개선 연결 등 남은 범위는 위 검증에 구분한다.

11/5 사건 실패 표·DNS 근거 보완: 기존 output_contract/관리 source_bundle·security-events·조사 SKILL·rule-change-executor 복사 경로에 같은 소스가 포함된다. 공통1.5.29/query1.19.24/events1.2.1·최종 서버1,081PASS/skip0(설치39포함), 새 패키지/키/포트0이다. `<rule><group>` 분류 표지의 정상 문법 허용은 기존 구조·정확 승인 강제를 유지한다. 오전 Wazuh 일반 정보성 후보는 만료/미적용이었다. 후속 [지정 흐름 후보](../infra/validation/dns-noise/README.md)는21조건·정확 승인/운영SHA 확인 뒤 canonical 초기 룰과 동기화했다. 기존 B relay 고정 경로의 휴대 가능한 자동 설치는 이번 수정의 검증 범위 밖이며 별도 공백으로 유지한다. 증분 배포와 새 OS 전체 설치·전체 오프라인 묶음 검증을 구분한다.

11/5 [필수 사건 조회 범위](../infra/hermes/required-sensor-scope.md): 공통1.5.30/query1.19.25의 정확 읽기 안내·MCP 전 검사·실제 같은 읽기만 오류 해소를 기존 공통 gate/source_bundle 복사 경로로 연결했다. 설치39를 포함한 서버995PASS/skip0·B11파일 증분 확정, 새 패키지/권한/포트/키0이다. canonical 코드의 helper/Trace와 root의 포함 gate·reference를 같은 단위로 갱신한다. 실제 사건 판단/종결·새 OS 전체 설치는 별도다.

11/5 [과거 웹 조회 보완](../infra/mcp/web-history.md): 기존 단일deploy.sh/diag-apply/SIEM source복사 경로로 schema2 정제 이력 publisher·reader를 연결했다. 원본 읽기8MiB·최근10k는 유지하고 검색을 시간/서비스 필터 뒤 최대50행으로 제한한다. 이력은32MiB/128k행·최대8세대/TTL회전·기존 그룹읽기만 허용한다. 새 패키지/이미지/포트/키/일반권한0·고유85검사/실제MCP·C3/B2확정, 새 OS 전체 설치는 별도 미실행이다.

## FW·IPv4 경로의 현재 범위

NAT 유지보수 helper와 canonical 로더/unit, fresh prerequisites의 IPv4-only 설정/검증·확정이 단일 deploy.sh에 연결됐다. IPv4 복구 경계9검사·기존 오프라인 준비18검사, 실제 legacy A/B/C 증분 검증을 통과했다. 새3VM 전체 설치·OS재부팅·운영 수동 복구는 미시험이다. [실측·복구](../infra/mcp/fw-consolidation.md).

기존 offline_security source 복사 경로에 HTTP Wazuh 고정별칭308·웹 제한 설정을 동기화했다. 기존 두 bot renderer/승인 모듈 복사도 새 사유/조건 표를 설치한다. 설치 렌더16·프록시 경계2·해당서버104검사와 운영 증분 확인이며 새3VM 전체설치/일반 관리DNS자동발급은 미검증이다.

11/6 query1.19.62의 [고정 등록 규격·웹 파일 무손실 표현·보고 검사](../infra/hermes/review-payload.md)는 기존 source복사·immutable gate렌더에 포함된다. 자동검토 root flag는 내부 전달값이며 새 사용자 설정키·오프라인 패키지/이미지/포트0. 설치계약41PASS·root 원본SHA 결속/64KiB 인자 상한·증분 배포9파일/보호7 확인. 신규3VM 전체 설치·자연 발생 자동 스케줄·실제 공격 E2E는 이번에 실행하지 않았다.

root생성 요청별 내부 CAPSTONE_REVIEW_CONTEXT_JSON은 canonical controller와 gate가 함께 처리한다. 사용자설정·공통키·오프라인 반입목록 추가0이다. 실제 새 서버 전체 설치 미시험은 유지한다.

정정 피드백/종결 검사는 기존 source 복사·controller 설치 렌더에 포함된다. 실제 영향 미확인+resolved 거절을 Native/host에서 검사하며 새 패키지·설정·오프라인 반입 항목은 없다.

11/6 [예약 조사 잠금 충돌](../infra/hermes/controller-contention.md)은 기존 canonical controller/source_bundle와 immutable gate 렌더 경로에 반영된다. 실제 Busy만 --once deferred/exit0, 명시적 재조사와 일반 오류는 실패 유지. 설치 렌더42PASS·B controller1파일 증분 확인이며 새 설정/키/포트/오프라인 반입 항목0. 새 OS 전체 설치는 미실행이다.
