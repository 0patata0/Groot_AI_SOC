# 구축·운영 가이드

[정확 적용·복구 후보](../infra/validation/control-status/application/README.md)는 현재 프로필로 내장 gate와19파일·영수증·유휴 확인·15분 원복을 준비했다. 설치 회귀46과 격리 원복은 통과했지만 정본·초기 설치 입력은 유지한다. 운영 적용은 정확 승인 후이며 실제 콜드 재시작/새 채팅·새 OS 전체 설치는 아직 미수행이다. 단일 deploy.sh 진입점도 유지한다.

11/8 [제한된 journal 원문 조회](../infra/mcp/journal-excerpts.md)를 A/B/C 운영에 적용했다. 진단MCP1.3.0·common71/query122, Linux1,544회귀검사·비특권 실제MCP11호출(정상9/인자거절2)·독립복구 확정. 초기 deploy.sh는 같은 소스와 고정 service를 설치하며 새 패키지/TCP/일반 sudo·Docker 권한0이다. **실제 새 OS 전체 설치와 일반 복합 판단 정확성은 미완료**다. 최신 채팅/모델/운영 결과는 [STATUS](../STATUS.md)를 따른다.

11/7: SSH·실습 관리 주소, Wazuh 웹 관리 주소, 자동 차단 보호 주소를 별도로 입력한다. 관리자 SSH의 특정 횟수 경보만 예외 처리하고 다른 공격/인증 로그를 유지한다. [정책과 정기보고의 적용 전후 구분](../infra/validation/admin-ssh/README.md).

11/6 당시 query1.19.75는 [관측 범위 검사](../infra/hermes/observation-scope.md)를 두 봇과 관리 게이트에 동기화했다. 프로세스 상태와 서비스 기능 정상, 로그 연속성 미검증과 실패를 구분한다. 고유1,112검사·B9파일/보호7SHA 확인. 기존 소스 복사·내장 게이트 경로를 사용하며 추가 패키지/포트/키는 없다. 최종30초·새 OS 전체 설치는 미완료다. 아래74 기록은 당시 범위다.

11/6 [복합 사건 읽기 연결](../infra/hermes/incident-bundle.md): query1.19.74/common1.5.33·security-events1.3.0/진단1.2.2를 함께 반영했다. `incident_evidence.py`와 기존 SIEM/SDK/관리 소스 복사·백업/원복을 사용하며 내부 MCP 검증은7읽기다. 원본 근거/인용/권한 검사를 유지하고 모델 표시만 무손실 압축한다. 고유1,215검사·운영17파일/보호7SHA 확인. 추가 deb/wheel/image·포트·키·입력 설정0. 최종30초/실제 새OS 설치는 미완료다. 아래 날짜별 기록은 당시 범위다.

11/6 [과거 서비스 오류 조회](../infra/mcp/journal-history.md): 단일 deploy.sh의 진단 소스 묶음에 diagnostic_history.py를 추가하고 초기24시간 분할 수집을 연결했다. 기존 timer/reader/MCP·Python 표준 SQLite 사용, 새 패키지·포트·키·권한0. A/B/C 증분 운영과 고유123검사·실제 SDK11호출 확인, A 일부 구간 공백·최종30초·새OS 전체설치 미완료는 구분한다.

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

이전 날짜별 설치 확장 설명과 시험 수치는 [과거 기록](../archive/DEPLOYMENT_HISTORY.md#source-252038d31234088c)에 보존한다. 과거 모델/API 주소·버전·권한·검사 면제·시험 성공 문구를 현재 환경에 그대로 적용하지 않는다.

사건/자동조사/검증실패 보고도 기존 `soc-output/SKILL.md` 하나를 재사용한다. 공통1.5.22/query1.19.17의 내부 필수 읽기 metadata는 신뢰된 controller가 실행별로 전달하며 사용자 설정·셸 권한을 추가하지 않는다. 기존 소스 복사·오프라인 묶음 경로와 설치계약37검사를 유지한다. [운영 반영·실제 화면·잔여](../infra/hermes/incident-followup.md).

관리 CLI의 실제 진입점은 불변 포함코드다. 초기 설치는 렌더링 gate를 root 참조파일로 함께 기록하고 실행 전에 두SHA를 대조한다. 운영 증분 갱신은 파일 복사본뿐 아니라 실제 포함코드도 동기화·검증한다. [11/4 실제 원인·보완](../infra/hermes/management-gate-binding.md). 새 패키지·입력키·새서버설치 추가0이다.

후속 root 제어기 보완은 대상별 상태 API/ID, 임시차단과 유지 승인 의미, 대응 사건 종결 전의 최소 영향 조회·인용 검사를 포함한다. 관리247/설치38/review59=344검사와 두 실제 출력 재생으로 확인했다. 실제 백엔드 진단/앱 영향·SDK 일반채팅의 같은 종결 검사와 전 업무 완료는 미검증이다. 기존 source bundle을 갱신하며 새 패키지·실제 초기 설치를 추가하지 않는다. [실제 실패·검증·복구](../infra/hermes/incident-impact.md).

11/5 [공통 업무 스킬](../infra/hermes/workflow-skills.md) 보완: soc-output과 조회/사건/변경/복구4개 절차를 같은 canonical 원본으로 배포한다. 기존 단일deploy.sh의 SIEM23파일·SDK source_files·관리 source_bundle에 로더/flat 별칭을 연결하고 네 SKILL의 파일명 충돌을 검사했다. 설치 계약39·SIEM역할40PASS, 전체 서버1,091PASS/skip0. 기존 고정 의존성만 사용해 새 deb/wheel/image·키/포트는 없다. 운영은 A2/B30파일 증분 반영·확정했으며 새 OS 전체 설치는 실행하지 않았다. 권한/역할/정확 승인 강제는 SOUL와 서버 코드에 유지한다. 실제 조사 시간초과·새 UI/자동 자기개선 연결 등 남은 범위는 위 검증에 구분한다.

11/5 [과거 웹 조회 보완](../infra/mcp/web-history.md): 기존 단일deploy.sh/diag-apply/SIEM source복사 경로로 schema2 정제 이력 publisher·reader를 연결했다. 원본 읽기8MiB·최근10k는 유지하고 검색을 시간/서비스 필터 뒤 최대50행으로 제한한다. 이력은32MiB/128k행·최대8세대/TTL회전·기존 그룹읽기만 허용한다. 새 패키지/이미지/포트/키/일반권한0·고유85검사/실제MCP·C3/B2확정, 새 OS 전체 설치는 별도 미실행이다.

## 공동 채널 읽기 감사 후보의 초기 설치 범위

[읽기 감사 보존](../infra/validation/native-read-audit/README.md)은 기존 `review_chat.SOURCES`의 작업자·전달기2파일만 바꾼 미적용 후보다. 초기 `deploy.sh`의4소스 묶음·오프라인 의존성/포트/권한 범위는 그대로이며, 같은4파일만 둔 Linux 격리 import를 통과했다. 기존 운영 변경은 신규 설치기를 재실행하지 않고 정확 후보 승인·영수증/백업·독립 원복·유휴 재시작·실제 새 채팅을 따로 검증한다. 실제 새 OS 전체 설치는 하지 않았다.

## 과거 범위 연결 후보의 설치 제외

[125검사 연결 후보](../infra/validation/peer-source-context/README.md)는 모델 의미 개선을 입증하지 못해 보류했다. 테스트한 전달기/정책/조사 스킬과 전용 검사는 복원 가능한 패치로만 보존하고, canonical·`deploy.sh` 입력은61733a1 기준으로 복구했다. 초기4소스/공통 스킬 복사 경로·오프라인 의존성은 그대로다. 새 OS 설치·운영 적용/재시작은 없다.
