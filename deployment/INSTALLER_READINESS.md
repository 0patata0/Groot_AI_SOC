# 초기 설치·통합 패키지 준비 상태

11/4 웹 읽기 연계: 기존 단일deploy.sh→service diag-apply 내부 설치와 SIEM 복사 경로에 `web_access_deploy.py`·`web_evidence.py`·`read-web-evidence.py`·`web_evidence_client.py`를 연결했다. 별도 계정/SSH 강제 명령·publisher/timer 계약6과 진단18·관리38 검사를 통과했다. 기존 운영 증분 적용/MCP 조회는 [별도 근거](../infra/mcp/web-evidence.md)이며 새 OS 전체 설치 증거가 아니다.

2026-11-04 KST. 단일 `deploy.sh` 기반은 구현했으나 완성된 일괄 배포 제품으로 표시하지 않는다. 실제 새3VM 설치는 사용자 조건으로 실행하지 않았다. [현황](../STATUS.md) · [운영](OPERATIONS.md) · [공식 지침 부분 대조](SECURITY_GUIDELINES.md) · [이전 점검](../archive/deployment-INSTALLER_READINESS-before-read-accuracy-ncsc-20261104.md).

| 항목 | 확인한 범위 | 남은 범위 |
|---|---|---|
| 단일 진입점 | root deploy.sh→역할·SOC·진단·선택 봇·오프라인 반입 | 전체 새 서버 설치 미시험 |
| 웹 정책 | On·UI/API 포함 WAF·관리 CIDR+HMAC 소스 연결 | role 검증의 lab_waf_mode 구 설명 문자열 잔여·실제 새 환경 경로 검증 |
| 공동 채널 | remote.sh에 siem review-chat-install/verify 두 작업만 추가. 역할3×작업명4=12조건으로 허용/거부 검사 | 실제 신규 review 설치는 미실행 |
| 컨트롤러 | 누락된 security host-check/verify fixture3을 실제 실행 순서로 정정. 가짜SSH46PASS | 가짜SSH는 실제 remote dispatcher/VM 설치·복구 증거 아님. 별도 NAT/Ansible 후보는 이번 검증·게시 범위 밖 |
| 공통 하네스 | read_contract/chat_harness/grounding/query·SDK runtime/harness와 출력 SKILL이 기존 복사/묶음 경로 사용. 사건/검증실패에도 단일soc-output재사용·내부 실행별 읽기 metadata·불변 포함gate와root참조SHA결속. 설치계약38PASS | 새 OS 실행 시험 없음·패키지/포트/키 추가0 |
| 사건 종결 검사 | Native/SDK가 공통의 명시적 판단·자산별 사건 시각 조회/인용 최소 검사 사용. SDK 구조화 선택 묶음/오류 피드백도 기존 소스 복사 경로로 설치. 관리247/설치38·전체951PASS, 실제 오류 출력 거절·미해결 유지 재생 | SDK 보호 쓰기/혼합 요청 전체 동등성·실제 영향/종결·Native 인자 오류·신규 설치 미완료. 새 패키지/포트/키0이며 오프라인 반입은 기존 소스 갱신만 필요. [범위](../infra/hermes/incident-closure-minimum.md) |
| 두 봇 프로필 | trial/chat/review 옵션·제한된 권한 모드 | 기본enable0/read-only와 현행 운영 두 봇 프로필을 구분. 완성된 제품 프로필 필요 |
| WAF 원문 대응 | configure_waf_evidence 소스 포함 | 초기 producer/raw/pin/enrollment 자동 연결 미확인 |
| 오프라인 | 역할별 deb/image SHA·버전 검사·로컬 설치 | wheel/TLS/runtime/catalog 등 포함 최종 통합 반입물·하위 의존성/서명 대장 미완성 |
| 운영 지침 | 현행 가이드의 WAF 우회/검사 면제 문구 정정·운영 절차와 공식 지침 대조 연결 | 로그 장기보존/용량·백업복원·시간동기화·전 경로/사건 종결·기관별 책임/주기 확인 |

이번 설치기 변경은 소스 허용목록과 회귀검사뿐이며 운영 서버에 초기 설치/적용/재시작을 하지 않았다. 같은 기간 B 봇의 증분 보완·재시작과 혼동하지 않는다. 새 의존성·deb/wheel/image·공개 포트·자격 키는 추가하지 않는다. 기존 반입 소스만 갱신한다.
