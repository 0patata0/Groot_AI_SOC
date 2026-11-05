# 구축·운영 가이드

웹 백엔드 읽기는 기존 service diag-apply가 `web_access_deploy.py`를 내부 호출하고 SIEM 역할이 보조소스2개를 설치한다. C 전용 강제 reader/정제 publisher를 추가하며 새 패키지·공개 포트·private key 반출은 없다. [고정 범위·한계·실제 검증·복구](../infra/mcp/web-evidence.md). 새 서버 전체 설치 시험은 미실행이다.

2026-11-04 KST. 신규 설치의 사용자 진입점은 루트 `deploy.sh` 하나다. 운영 중인 A/B/C는 초기 설치기로 덮어쓰지 않는다. 현재 구축·운영의 전 항목 정합과 전체 새 서버 설치를 완료한 상태는 아니다.

| 목적 | 기준 문서 |
|---|---|
| 현재 구현/실제 운영/미검증 | [STATUS](../STATUS.md) · [PLAN](../PLAN.md) |
| 신규 환경 준비·단일 설치 흐름 | [bootstrap](bootstrap-guide.md) · [입력 설정](configuration-guide.md) |
| 네트워크·SSH·관리 경로 | [준비](setup-network-ssh.md) · [현재 관리 정책](../infra/groot-a/management-access.md) |
| 오프라인 패키지·이미지/무결성 | [반입 목록](setup-packages-artifacts.md) · [설치 준비도/공백](INSTALLER_READINESS.md) |
| 설치 후 확인·문제 진단 | [검증](verify-troubleshoot.md) |
| 일상 관제·승인·대응·복구·보고 | [운영 절차](OPERATIONS.md) · [LLM 관리 경계](SOC_MANAGEMENT.md) |
| 공식 기준과의 부분 대조 | [NCSC 기본지침·국정원 AI/공급망 지침](SECURITY_GUIDELINES.md) |
| 공통 출력·단순 조회 속도/근거 | [출력 스킬](../infra/hermes/skills/soc-output/SKILL.md) · [조회 지연](../infra/hermes/lookup-latency.md) · [읽기 정확성](../infra/hermes/read-accuracy.md) |

UI/API를 포함한 WAF 경로는 On을 기준으로 한다. 공개 열람 허용과 실행·중지·터미널 제어 권한을 구분하며, 제어에는 관리자 CIDR과 HMAC 인증이 모두 필요하다. 과거 차단 검사 면제 세션 설명은 현행 사용법이 아니다.

단순 조회는 기본 Ollama 담당, 복합 사건/변경은 Hermes 우선이며 직접 태그를 존중한다. 모델·MCP·승인·서비스 동작과 실제 공격 E2E는 각각 검증한다. 새 서버 전체 설치는 사용자 조건으로 실행하지 않았다. 오프라인 전체 패키지·WAF 증거 초기등록·기관별 보존/복구 등 미완료는 준비도/현황에 남긴다.

이전 날짜별 설치 확장 설명과 시험 수치는 [과거 기록](../archive/deployment-README-before-ncsc-20261104.md)에 보존한다. 과거 모델/API 주소·버전·권한·검사 면제·시험 성공 문구를 현재 환경에 그대로 적용하지 않는다.

사건/자동조사/검증실패 보고도 기존 `soc-output/SKILL.md` 하나를 재사용한다. 공통1.5.22/query1.19.17의 내부 필수 읽기 metadata는 신뢰된 controller가 실행별로 전달하며 사용자 설정·셸 권한을 추가하지 않는다. 기존 소스 복사·오프라인 묶음 경로와 설치계약37검사를 유지한다. [운영 반영·실제 화면·잔여](../infra/hermes/incident-followup.md).

관리 CLI의 실제 진입점은 불변 포함코드다. 초기 설치는 렌더링 gate를 root 참조파일로 함께 기록하고 실행 전에 두SHA를 대조한다. 운영 증분 갱신은 파일 복사본뿐 아니라 실제 포함코드도 동기화·검증한다. [11/4 실제 원인·보완](../infra/hermes/management-gate-binding.md). 새 패키지·입력키·새서버설치 추가0이다.

후속 root 제어기 보완은 대상별 상태 API/ID, 임시차단과 유지 승인 의미, 대응 사건 종결 전의 최소 영향 조회·인용 검사를 포함한다. 관리247/설치38/review59=344검사와 두 실제 출력 재생으로 확인했다. 실제 백엔드 진단/앱 영향·SDK 일반채팅의 같은 종결 검사와 전 업무 완료는 미검증이다. 기존 source bundle을 갱신하며 새 패키지·실제 초기 설치를 추가하지 않는다. [실제 실패·검증·복구](../infra/hermes/incident-impact.md).

11/5 [공통 업무 스킬](../infra/hermes/workflow-skills.md) 보완: soc-output과 조회/사건/변경/복구4개 절차를 같은 canonical 원본으로 배포한다. 기존 단일deploy.sh의 SIEM23파일·SDK source_files·관리 source_bundle에 로더/flat 별칭을 연결하고 네 SKILL의 파일명 충돌을 검사했다. 설치 계약39·SIEM역할40PASS, 전체 서버1,091PASS/skip0. 기존 고정 의존성만 사용해 새 deb/wheel/image·키/포트는 없다. 운영은 A2/B30파일 증분 반영·확정했으며 새 OS 전체 설치는 실행하지 않았다. 권한/역할/정확 승인 강제는 SOUL와 서버 코드에 유지한다. 실제 조사 시간초과·새 UI/자동 자기개선 연결 등 남은 범위는 위 검증에 구분한다.
