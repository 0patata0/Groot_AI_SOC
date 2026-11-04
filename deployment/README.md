# 구축·운영 가이드

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
