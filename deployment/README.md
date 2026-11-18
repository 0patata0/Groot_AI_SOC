# 구축·운영 가이드

<!-- certificate-bootstrap-20261118 -->
<a id="certificate-bootstrap-20261118"></a>

단일 deploy.sh에 신규 A의 실습용 TLS와 B의 내부 채팅 TLS 감시를 연결했다. 기존 감시기에서 검증한 코어를 재사용하고 공개 인증서 경로·고정 엔드포인트·호스트 machine-id를 각각 결속한다. 실습 도메인과 채팅 도메인은 서로 다른 센서 이름·Wazuh 규칙으로 연결한다. 기존 운영 A의 두 파일과 타이머·인증서는 바꾸지 않았다.

초기 설치기 연결의 로컬190검사와 Linux 합성52조건·두 역할의 유닛 구문 검사는 기존 근거로 보존한다. 후속으로 B의 기존 Wazuh4.14.8 이미지에서12규칙을 격리 적재하고112사례를 모두 통과했다. 새 검증기의 로컬 경계 검사4개와 기존 인증서 검사15개도 통과했다. 운영 매니저의 컨테이너·시작 시각·설정8파일 지문은 전후 같았다. 새 Ubuntu 전체 설치·운영 룰 적용·실제 경보 전달·독립 재구현은 미수행이다.
<!-- /certificate-bootstrap-20261118 -->

<!-- certificate-rules-native-20261118 -->
<a id="certificate-rules-native-20261118"></a>

기존51사례를 각 역할에 적용하고 센서·도메인 교차, 프로그램명·수집 위치 접미 조건, 메시지 hostname 차이를 추가해112사례를 구성했다. 기대 규칙이 있는54사례는 실제 규칙 ID와 위험도를 대조했고 나머지58사례는12규칙에 매칭되지 않음을 확인했다. 정상·30/14/7일·만료와 TLS 실패를 조합했으며 만료는 A100304/B100310·위험도10을 유지한다. unknown+verified는 원본의 상태 형식 대조이며 실제 정상 관측으로 집계하지 않는다.

재검증에는 기존 고정 이미지와 Linux root의 빈0700 작업 경로, 운영 매니저의 전체 컨테이너 ID가 필요하다. 실행기는 생성한12규칙과 원본 decoder를 읽기 전용으로 연결하고 매 사례마다 새 logtest 세션을 사용한다. 실제 엔진의 규칙 ID·위험도·decoder와 잘못된 입력의 거절을 확인한다. 종료 시 전체 CID·이미지·작업 표식·입력 경로를 대조한 뒤 자기 컨테이너만 제거한다. Docker 목록 조회 성공과 CID 부재를 함께 확인하고 운영 지문도 다시 읽는다.
<!-- /certificate-rules-native-20261118 -->

```bash
# Linux B, root; replace FULL_MANAGER_CID with the exact existing manager ID.
install -d -m 0700 /var/tmp/capstone-cert-rules-check
python3 -B deployment/tests/run_certificate_rules_native.py --workdir /var/tmp/capstone-cert-rules-check --manager FULL_MANAGER_CID
```


[복합 조사 검증](../infra/validation/management-latency/README.md). 공통 어법/HTTP 인과 검사는 증거가 아니다·차단했는지·의미하는지는 추가 검증 필요라는 올바른 한계를 거절했다. 이를 보완했다. 계약3사본·하네스2사본·SDK영수증1을 운영6파일로 확정하고 보호66파일을 대조했다. 새3채팅/9읽기의 대상·기간이 일치했고 모델 보고는3건 수용됐다. 실제거절3초안 재생과 Mac/Linux336·298·39·27, Linux공식38·설치37을 통과했다. MCP45도구·모델·권한·승인·TTL·스킬·상시 지시량은 유지한다. 제한된 검증이며 일반 정확도/SLO는 별도다. [HTTP 어법·새 채팅 검증](../infra/validation/management-latency/http-modality.validation.json).

초기 설치 소스는 [수집기 한도·이력 후보](../infra/validation/journal-composition/LIMITS.md)에 맞췄다. deploy.sh가 고정 역할의 수집·초기 이력을 순서대로 실행하고 실제 로드 한도나 이력 완전성이 맞지 않으면 타이머·reader 활성화로 넘어가지 않는다. 새 OS 전체 설치와 기존 운영의 조정 배포는 아직 검증하지 않았다.

<!-- journal-composition:start -->
[조정 실행기](../infra/validation/journal-composition/COORDINATOR.md)에 정리·현재 설치 검증을 연결했다. 15모듈·50소스·39제어 문서, 동일 소스 Mac252·Linux252/생략0·공식78→80구성/추가2/수정14/상시 증가0은 격리 근거다. root namespace5조건도 실제 서비스 인수가 아니다. 운영 소스/서비스 변경0이며 실제 systemd·독립 복구·정확 승인·MCP/두 봇 채팅이 남았다. 관리정책의 고정 조회·파일 후보를 A/B/C 실제8설정에서 확인했다. 같은 소스 Mac87·Linux87/생략0과 A의 nft/Bash/nginx 구문 검사는 개발 근거다. 실제 엔진 로드·신뢰된 출처/경로·14면 전체 연결·전역 MCP/정확 카드/독립 원복·초기 설치·두 봇 검증은 남았다.
<!-- journal-composition:end -->



로컬 매뉴얼형 논문은 설치 plan/check/apply/verify의 입력·위치·통과 기준과 실패 시 부분 설치 확인을 보강했다. 동일66쪽 MD/PDF/DOCX 문서 검수이며 운영 시작·정확 카드/원복·후임 인수 절차도 연결했다. 신규 OS 전체 설치나 운영 변경은 수행하지 않았다. [현재 상태](../STATUS.md)를 따른다.


<!-- service-error-coverage:start -->
[원문·조사 후보](../infra/validation/service-error-coverage/README.md)는 미적용 patch/재현기다. 정본·설치기를 승격하지 않았으며 실제 새 OS 설치·운영 로드/새 채팅은 미수행이다. 후보의 추가 읽기는 기존 등록 함수/대상/기간/한도 안에서 이루어지고 권한/승인/보호/TTL을 확대하지 않는다. 기존19/journal9 적용안은 별개로 보존한다.
<!-- service-error-coverage:end -->

<!-- diagnostic-read-boundaries:start -->
진단 경계 후속은 [검증 원장](../infra/validation/diagnostic-read-boundaries/README.md)에 정리했다. 내부µs·등록 대상 확인·명확한 상대 기간과 원인 괄호 반례를 보완했고 실제SDK3요청/4읽기·모델완료6·wire2성공/3거절을 확인했다. not-found/default Result의 미검출 해석 오류가 남아 미승격이며 현재 정본·초기 설치·운영/권한/모델은 바꾸지 않았다. 구조/회귀·실제 의미·새 채팅을 구분한다.
<!-- diagnostic-read-boundaries:end -->

[실제 journal 후보 검증](../infra/validation/host-journal-model/README.md). 후보의B MCP/SDK통합을별도임시경로에서검증했다. 운영입력·단일deploy.sh·OS/그룹/SSH/config·두정확승인계획은바꾸지않았다. backend읽기와모델보고정확도는별도이며의미오류/시각경계를고친정확새후보·실제로딩/채팅·새OS전체설치가남는다. 아래는 각 과거 단위의 관측이다.

[읽기 시도6소스 개발 후보](../infra/validation/read-attempt-binding/README.md)는 실제 OS/DNS 근거 오류가 남아 미채택이며 단일 deploy.sh 정본/설치 입력을 변경하지 않았다. query143·controller 내장 gate의 향후 같은 SHA 재렌더와 정확 적용/복구·새 채팅 검증은 별도다. 기존19/journal9 정확 계획도 불변이다.

[주장 결속 개발 후보](../infra/validation/claim-modality/README.md)는 실제 DNS 근거 오류가 남아 미채택이며 단일 deploy.sh의 정본/설치 입력에 넣지 않았다. 기존19파일·journal9코드의 정확 적용 계획도 불변이다. 개발 패치 재구성을 운영 설치/새 OS 검증으로 사용하지 않는다.

[native journal 후보](../infra/validation/journal-adapter/README.md)에서 사용하는 단일 deploy.sh/helper, systemd255/binding235 API와 오프라인 의존 목록은 유지한다. 별도 [정확9코드 운영 적용안](../infra/validation/journal-adapter/application/README.md)은 회귀33회·복제 원복9회·중간 load18회를 거쳤다. A/B/C의 PREPARED 상태와 원본6개도 준비했다. 기존 운영 서버의 승인형 증분 작업이며 초기 설치기를 재실행하지 않는다. 실제 운영 적용과 원복 timer, 새 채팅과 새 OS 전체 설치는 아직 수행하지 않았다. 아래 날짜별 설명은 당시 범위다.

[정확 적용·복구 후보](../infra/validation/control-status/application/README.md)는 현재 프로필로 내장 gate와19파일·영수증·유휴 확인·15분 원복을 준비했다. 설치 회귀46과 격리 원복은 통과했지만 정본·초기 설치 입력은 유지한다. 운영 적용은 정확 승인 후이며 실제 콜드 재시작/새 채팅·새 OS 전체 설치는 아직 미수행이다. 단일 deploy.sh 진입점도 유지한다.

11/8 [제한된 journal 원문 조회](../infra/mcp/journal-excerpts.md)를 A/B/C 운영에 적용했다. 진단MCP1.3.0·common71/query122, Linux1,544회귀검사·비특권 실제MCP11호출(정상9/인자거절2)·독립복구 확정. 초기 deploy.sh는 같은 소스와 고정 service를 설치하며 새 패키지/TCP/일반 sudo·Docker 권한0이다. **실제 새 OS 전체 설치와 일반 복합 판단 정확성은 미완료**다. 최신 채팅/모델/운영 결과는 [STATUS](../STATUS.md)를 따른다.

11/7: SSH·실습 관리 주소, Wazuh 웹 관리 주소, 자동 차단 보호 주소를 별도로 입력한다. 관리자 SSH의 특정 횟수 경보만 예외 처리하고 다른 공격/인증 로그를 유지한다. [정책과 정기보고의 적용 전후 구분](../infra/validation/admin-ssh/README.md).

11/6 당시 query1.19.75는 [관측 범위 검사](../infra/hermes/observation-scope.md)를 두 봇과 관리 게이트에 동기화했다. 프로세스 상태와 서비스 기능 정상, 로그 연속성 미검증과 실패를 구분한다. 고유1,112검사·B9파일/보호7SHA 확인. 기존 소스 복사·내장 게이트 경로를 사용하며 추가 패키지/포트/키는 없다. 최종30초·새 OS 전체 설치는 미완료다. 아래74 기록은 당시 범위다.

11/6 [복합 사건 읽기 연결](../infra/hermes/incident-bundle.md): query1.19.74/common1.5.33·security-events1.3.0/진단1.2.2를 함께 반영했다. `incident_evidence.py`와 기존 SIEM/SDK/관리 소스 복사·백업/원복을 사용하며 내부 MCP 검증은7읽기다. 원본 근거/인용/권한 검사를 유지하고 모델 표시만 무손실 압축한다. 고유1,215검사·운영17파일/보호7SHA 확인. 추가 deb/wheel/image·포트·키·입력 설정0. 최종30초/실제 새OS 설치는 미완료다. 아래 날짜별 기록은 당시 범위다.

11/6 [과거 서비스 오류 조회](../infra/mcp/journal-history.md): 단일 deploy.sh의 진단 소스 묶음에 diagnostic_history.py를 추가하고 초기24시간 분할 수집을 연결했다. 기존 timer/reader/MCP·Python 표준 SQLite 사용, 새 패키지·포트·키·권한0. A/B/C 증분 운영과 고유123검사·실제 SDK11호출 확인, A 일부 구간 공백·최종30초·새OS 전체설치 미완료는 구분한다.

웹 백엔드 읽기는 기존 service diag-apply가 `web_access_deploy.py`를 내부 호출하고 SIEM 역할이 보조소스2개를 설치한다. C 전용 강제 reader/정제 publisher를 추가하며 새 패키지·공개 포트·private key 반출은 없다. [고정 범위·한계·실제 검증·복구](../infra/mcp/web-evidence.md). 새 서버 전체 설치 시험은 미실행이다.

2026-11-04 KST. 신규 설치의 사용자 진입점은 루트 `deploy.sh` 하나다. 운영 중인 A/B/C는 초기 설치기로 덮어쓰지 않는다. 구축·운영의 모든 항목이 일치하는지 확인하는 작업과 새 서버 전체 설치는 아직 완료하지 않았다.

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

단순 조회는 기본적으로 Ollama가 담당하고 복합 사건/변경은 Hermes가 우선 맡는다. 사용자가 직접 태그한 봇을 존중한다. 모델·MCP·승인·서비스 동작과 실제 공격 E2E는 각각 검증한다. 새 서버 전체 설치는 사용자 조건으로 실행하지 않았다. 오프라인 전체 패키지·WAF 증거 초기등록·기관별 보존/복구 등 미완료는 준비도/현황에 남긴다.

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


[짧은 조회3소스 후속](../infra/validation/read-intent-scope/README.md)은 공통 표현·DNS 주제 표본을 격리 보완했다. 로컬801집계795pass/6의존성skip·기존Hermes801/skip0,실제후보3요청/MCP3·모델3/12~16초·표 반환을 확인했다. 모두 빈 표본·Native 실대화/채팅 미수행·통제 전후 비교 아님이다. OS 대상명 허위 실패/current 대체·조사0건/SID 활성 오류는 남았으며 정본·초기설치/운영/권한/예산과 기존 두 정확 승인 계획은 불변이다.

## 관리 IP·대역의 공통 검증

[공통 정책 계약](../infra/mcp/management-policy.md)의 registry·14적용면·34검사를 작성했다. 목록과 전체 후보/읽기 확인을 검사하는 순수 함수이며 초기 설치나 운영 반영을 수행하지 않는다. 장비 어댑터·전역 MCP/카드/원복과 `deploy.sh`의 단일 정책 연결이 남았다. 기존 관리/차단/대시보드 입력을 자동으로 통합한 상태는 아니다. 추가 deb/wheel과 Mac 패키지 설치는0이다.

A의 실제 Native NAT 소스를 기준으로 복수 관리대역 변경과 영구 로더 후보를 추가했다. Native18·로더7검사와 Linux 격리9조건을 통과했다. 기존 미커밋 NAT 통합 대안은 보존했으며 운영 설치·초기 설치기 연결은 아직이다. 추가 패키지·모델 호출·운영 주소 변경은0이다. [범위](../infra/mcp/management-policy.md).

<!-- response-rpc-input-20261118 -->
## 응답 MCP tools/call 입력형 보완 후보 — 2026-11-18

초기 설치 진입점 deploy.sh는 기존 soc_management와 soc_runtime.render를 통해 같은 정본 소스를 설치한다. 실제 렌더 사본의 stdio 입력 검사도 통과했다. 갱신한 소스와 회귀 파일을 오프라인 소스 묶음에 포함하며 새 패키지·이미지·포트·키·설정 값은 없다. 운영 서버를 초기 설치기로 덮어쓰지 않는다. 새 OS 전체 설치 검증은 미수행이다.

관리자231 경유 조회에서 A의 /opt/capstone-soc/response-mcp.py는 기존1.2.0 소스와 같은 SHA임을 확인했다. 후보1.2.1의 SHA는 f911e8d9274686589c51145d52386c452ce0616085dd09b795c121d835758bc2다. 적용 대상은 이 파일 하나이며 정확 후보 승인을 기다린다. 변경 전 해시·root:root/0600·보호 파일을 대조하고 백업과5분 독립 원복 타이머를 준비한 뒤 교체한다. 운영 적용·기존 봇 연결의 재로드·새 실제 채팅 검증은 미수행이다.

[응답 MCP 검증 원장](../infra/mcp/response-rpc.validation.json)
<!-- /response-rpc-input-20261118 -->


<!-- certificate-readiness:20261118 -->

## 인증서 관측 실패 수정과 남은 출력 오류

관리자231 경유로 승인된 감시 실행파일·service2개를 적용하고17:13:01 KST에 확정했다. 실제 oneshot은exit0/verified이며 인증서 지문이 일치한다. 기존 MCP의 현재 상태와 실제 journal4표본에서도 확인했다. 5분 독립 원복은 해제하고 원본·정확 후보·제어기는 보존했다. 프록시·인증서·개인키·매일09:00 타이머·MCP/모델은 유지한다. 새 채팅1건은 올바른 인증서 조회 뒤 불필요한 Wazuh 에이전트 조회가 추가되고 최종 표의 대상이 바뀌어 실패로 기록했다. 초기 설치 이식·공개443·내일 예약 실행은 별도 미완료다. [검증·미완료 범위](../infra/groot-a/certificate-monitor/readiness.validation.json).
<!-- /certificate-readiness:20261118 -->
