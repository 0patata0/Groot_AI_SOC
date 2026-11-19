# 초기 설치·통합 패키지 준비 상태

<!-- bootstrap-clock-gate-20261118 -->
<a id="bootstrap-clock-gate-20261118"></a>

단일deploy.sh의 사전검사에서 호스트 시간대가Asia/Seoul이고 NTP=yes·NTPSynchronized=yes인지 확인한다. 세 호스트의 준비 검사와 각 호스트의 패키지 적용 단계에서 같은 조건을 읽으며 역할별 실행·검증·내보내기 전에도 다시 확인한다. 누락·중복·다른 시간대·NTP 비활성·미동기·조회 실패는 준비 완료로 통과시키지 않는다. 시간·시간대·NTP 설정을 바꾸거나 서비스를 재시작하지 않는다.

로컬 prerequisites25·remote5·기존 controller48의78검사를 통과했다. 기존 설치 순서를 바꾸지 않았고 가짜 SSH의 순서 검증은 실제 서버 설치 증거로 쓰지 않는다. 실제 읽기에서는 같은 검사 소스를 메모리에서 실행했다. A/B/C가 통과하고 관리자231이 미동기로 거절됐다. 기존 운영 설치기를 실행하거나 운영 소스를 교체하지 않았으며 패키지 설치·서비스 재시작·새 네트워크 요청·모델 호출·채팅·공격·학습은0이다.

이 검사는 OS가 보고하는 시간 상태의 사전조건이다. 설정한 시간 원본의 신뢰성·절대UTC 정확도·호스트 사이의 오차·장기 동기화까지 측정한 결과가 아니다. 이후 상태가 바뀌면 다음 단계에서 중단될 수 있으며 이미 끝난 작업을 자동으로 되돌리지 않는다. 부분 설치는 기존 영수증과 실제 상태를 확인해 처리한다.

[시각 사전조건·검증 범위](clock-readiness.validation.json)
<!-- /bootstrap-clock-gate-20261118 -->

<!-- chat-access-readiness-20261118 -->
<a id="chat-access-readiness-20261118"></a>

기존 운영 감시기 두 파일의17:13 확정과 신규 설치기의 소스 연결·격리 Wazuh112검증은 완료한 범위다. 11/19 09:00 KST의 자연 예약 실행과 exit0/verified를 확인했고 기존 MCP2읽기·journal4표본을 대조했다. 다음 예약은11/20 09:00 KST이며 수동 실행·운영 변경은0이다. 한 차례의 예약 관측으로 외부 인터넷 경로·장기 안정성·새 OS 전체 설치·독립 재구현까지 검증한 것은 아니다. 신규3호스트 전체 OS 설치와 독립 재구현도 미수행이다.

관리자 호스트는 NTP=yes·NTPSynchronized=no였고 조회 컴퓨터보다46.486~47.051초 늦었다. 같은 방식으로 읽은 A의 상대 차이는-0.033~0.864초 범위였으며 NTP 동기화 상태는yes였다. 이 범위는 각 SSH 조회의 왕복 시간을 포함한 관측 한계다. 원래 원격 시각과 조회 컴퓨터의 수신 시각을 함께 보존하며 과거 원문 시각을 고쳐 쓰지 않는다.

정확 변경안390a0f43은 관리자231의 /etc/systemd/timesyncd.conf.d/90-capstone-campus.conf 파일1개와 기존 timesyncd의1회 재시작만 포함한다. 학내131을 지정하고5분 내 확인하지 못하면 추가한 설정만 원복한다. NTP 보정으로 시계가 약47초 앞으로 이동할 수 있으며 원복 시 시계를 강제로 과거로 돌리지 않는다. 관리자에게 정확 승인을 요청했으며 실제 설정·시각 변경과 운영 NTP 서비스 재시작은 아직 수행하지 않았다.

[관리자 경로·시각·정확 변경안 원장](../infra/groot-a/certificate-monitor/access-readiness-20261118.json)
<!-- /chat-access-readiness-20261118 -->

<!-- certificate-bootstrap-20261118 -->
<a id="certificate-bootstrap-20261118"></a>

초기 설치의 check는 입력·소스·호스트와 기존 설치 충돌을 검사한다. install은 기존 A lab-edge와 B 내부 TLS가 준비된 뒤, 관리 타이머와 진단 수집을 시작하기 전에 실행한다. 첫 실제 감시 결과가 verified여야 설치 영수증을 남기고 매일09:00 KST 타이머를 켠다. 부분 설치와 영수증·파일 변동은 자동으로 덮어쓰지 않고 중단한다.

초기 설치기 연결의 로컬190검사와 Linux 합성52조건·두 역할의 유닛 구문 검사는 기존 근거로 보존한다. 후속으로 B의 기존 Wazuh4.14.8 이미지에서12규칙을 격리 적재하고112사례를 모두 통과했다. 새 검증기의 로컬 경계 검사4개와 기존 인증서 검사15개도 통과했다. 운영 매니저의 컨테이너·시작 시각·설정8파일 지문은 전후 같았다. 새 Ubuntu 전체 설치·운영 룰 적용·실제 경보 전달·독립 재구현은 미수행이다.

추가 deb·wheel·이미지·포트·사용자 설정 키는 없다. 기존 LAB_PUBLIC_ORIGIN/LAB_HTTPS_PORT/LAB_PROXY_SUBNET과 LAB_TLS_CERT/LAB_TLS_KEY 입력, B 내부 TLS의 별도 인증서를 사용한다. 단일 설치기의 기존 소스 묶음에 새 어댑터·검사와 고정 템플릿을 포함한다. 기존 운영 서버의 증분 수정과 새 서버 초기 설치를 구분한다.
<!-- /certificate-bootstrap-20261118 -->

<!-- certificate-rules-native-20261118 -->
<a id="certificate-rules-native-20261118"></a>

시험은 기존 Linux amd64 이미지의 analysisd와 wazuh-db를 별도 컨테이너에서 실행했다. 이미지 다운로드 없이 network none·권한 제한·읽기 전용 입력5개·자원 제한을 사용했다. 기본 internal_options와 CDB6목록은 이미지 안의 공개 기본 파일에서 복원하고 시험 내부에서만 쓰기 권한을 부여했다. 운영 설정·데이터·키·소켓은 시험 컨테이너에 연결하지 않았다. 개인키 읽기·운영 재시작·새 공격·학습·모델 호출·채팅은0이다.

첫 전체 실행은44사례 통과 후85초 제한으로 끝났다. 그때까지 규칙 불일치는 없었고 시험 컨테이너와 파일을 제거했다. 제한을360초로 정정한 뒤 PID·시작 tick·boot ID와 실제 컨테이너를 추적했고 같은112사례를213.596초에 완료했다. 두 실행의 공통44사례를 중복 합산하지 않는다. 최종 엔진 시작의 오류·경고는0이며 시험 컨테이너와129파일251412바이트의 작업 경로를 제거하고 부재를 확인했다.
<!-- /certificate-rules-native-20261118 -->


[진단 설치 보완](../infra/validation/journal-composition/LIMITS.md): 수집/초기 이력에 MemoryMax256MiB·High192MiB·스왑0·Tasks64·FD1,024를 적용하는 후보와 고정 backfill unit을 준비했다. systemd 실제 로드 값·4개 unit 영수증·부분 수집 CLI1을 검사한다. Mac1,427/기존6생략·격리 Linux1,510/생략0과 실제 제한 실행은 새 OS 전체 설치의 증거가 아니다.

[native journal 후보](../infra/validation/journal-adapter/README.md)에서 사용하는 단일 deploy.sh/helper, systemd255/binding235 API와 오프라인 의존 목록은 유지한다. 별도 [정확9코드 운영 적용안](../infra/validation/journal-adapter/application/README.md)은 회귀33회·복제 원복9회·중간 load18회를 거쳤다. A/B/C의 PREPARED 상태와 원본6개도 준비했다. 기존 운영 서버의 승인형 증분 작업이며 초기 설치기를 재실행하지 않는다. 실제 운영 적용과 원복 timer, 새 채팅과 새 OS 전체 설치는 아직 수행하지 않았다. 아래 날짜별 설명은 당시 범위다.

2026-11-08: 현재 단일deploy.sh에는 host_inventory.py·진단MCP1.4.0·공통 조회/출력 스킬·비특권 읽기 검증(36개)이 연결됐습니다. 고정 root collector만 AF_NETLINK를 추가로 허용하며 신규 패키지/공개 포트/키는 없습니다. 운영 증분 검증과 새 OS 전체 설치는 구분합니다. [범위·검증](../infra/mcp/host-inventory.md).

11/8 [제한된 journal 원문 조회](../infra/mcp/journal-excerpts.md)를 A/B/C 운영에 적용했다. 진단MCP1.3.0·common71/query122, Linux1,544회귀검사·비특권 실제MCP11호출(정상9/인자거절2)·독립복구 확정. 초기 deploy.sh는 같은 소스와 고정 service를 설치하며 새 패키지/TCP/일반 sudo·Docker 권한0이다. **실제 새 OS 전체 설치와 일반 복합 판단 정확성은 미완료**다. 최신 채팅/모델/운영 결과는 [STATUS](../STATUS.md)를 따른다.

11/7 관리자 정책: 단일deploy.sh에서SSH/실습관리·Wazuh웹·차단보호CIDR을별도로입력하고명시빈값을존중한다. 관리SSH22의SID2001219만예외생성·초기입력/정책74검사,정기보고정책전후분리30검사/운영dry확인을마쳤다. 초기보고변경이력은빈목록·추가패키지/포트0·새OS전체설치0. [검증·실제적용범위](../infra/validation/admin-ssh/README.md).

11/7 단문 검증 당시 query1.19.118/common1.5.62·routing1.1.6/진단MCP1.2.8이다. 짧은 FW 정책·상관 룰 첫N개·임시차단 질문의 실제 근거 연결과 Native 인자 제한을 보완했다. Linux1,390검사/skip0·최종 양봇6채팅10.337~20.621초/각1읽기·쓰기0·대상/원문/표본문 일치·16:02독립원복 확정. 학습본 포함3군 SDK는 각30/30이나 개발 회귀이며 독립 정확도나 학습 우위가 아니다. 운영 원본35B를 유지한다. [변경·실패·복구](../infra/hermes/short-read-evidence.md).

11/6 [복합 사건 읽기 연결](../infra/hermes/incident-bundle.md): query1.19.74/common1.5.33·security-events1.3.0/진단1.2.2를 함께 반영했다. `incident_evidence.py`와 기존 SIEM/SDK/관리 소스 복사·백업/원복을 사용하며 내부 MCP 검증은7읽기다. 원본 근거/인용/권한 검사를 유지하고 모델 표시만 무손실 압축한다. 고유1,215검사·운영17파일/보호7SHA 확인. 추가 deb/wheel/image·포트·키·입력 설정0. 최종30초/실제 새OS 설치는 미완료다. 아래 날짜별 기록은 당시 범위다.

11/6 [과거 서비스 오류 조회](../infra/mcp/journal-history.md): 단일 deploy.sh의 진단 소스 묶음에 diagnostic_history.py를 추가하고 초기24시간 분할 수집을 연결했다. 기존 timer/reader/MCP·Python 표준 SQLite 사용, 새 패키지·포트·키·권한0. A/B/C 증분 운영과 고유123검사·실제 SDK11호출 확인, A 일부 구간 공백·최종30초·새OS 전체설치 미완료는 구분한다.

11/4 웹 읽기 연계: 기존 단일deploy.sh→service diag-apply 내부 설치와 SIEM 복사 경로에 `web_access_deploy.py`·`web_evidence.py`·`read-web-evidence.py`·`web_evidence_client.py`를 연결했다. 별도 계정/SSH 강제 명령·publisher/timer 계약6과 진단18·관리38 검사를 통과했다. 기존 운영 증분 적용/MCP 조회는 [별도 근거](../infra/mcp/web-evidence.md)이며 새 OS 전체 설치 증거가 아니다.

2026-11-05 KST. 단일 `deploy.sh` 기반은 구현했으나 완성된 일괄 배포 제품으로 표시하지 않는다. 실제 새3VM 설치는 사용자 조건으로 실행하지 않았다. [현황](../STATUS.md) · [운영](OPERATIONS.md) · [공식 지침 부분 대조](SECURITY_GUIDELINES.md) · [이전 점검](../archive/DEPLOYMENT_HISTORY.md#source-ef7424bbadcff1f6).

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


## 인증서 감시기의 설치 이식 공백

기존 A용 TLS 감시기 후보는 전체 check 격리 비교·native26·원복14·독립 타이머의 격리 파일2개 복구까지 확인했다. 수동 변경 제어기는 기존 두 파일의 정확 복구용이며 초기 설치기의 추가 진입점이 아니다. 운영 두 파일은 정확 승인 후17:13:01 KST에 확정했고 실제 exit0/verified·MCP/journal을 확인했다. 새 채팅의 최종 대상 오류는 별도다. deploy.sh의 lab TLS와 채팅 TLS는 도메인·포트·파일 경로/모드가 다르므로 고정 machine-id·경로·B 규칙을 명시적으로 이식해야 한다. 기존 운영 감시기 두 파일의17:13 확정과 신규 설치기의 소스 연결·격리 Wazuh112검증은 완료한 범위다. 11/19 09:00 KST의 자연 예약 실행과 exit0/verified를 확인했고 기존 MCP2읽기·journal4표본을 대조했다. 다음 예약은11/20 09:00 KST이며 수동 실행·운영 변경은0이다. 한 차례의 예약 관측으로 외부 인터넷 경로·장기 안정성·새 OS 전체 설치·독립 재구현까지 검증한 것은 아니다. 신규3호스트 전체 OS 설치와 독립 재구현도 미수행이다. [검증과 수동 복구](../infra/groot-a/certificate-monitor/README.md).


<!-- service-query-20261118 -->

현재 상태만 묻는 짧은 요청과 호스트만 답하는 후속 요청을 같은 공통 계약으로 처리한다. 현재 조회에는 필요한 실제 읽기만 사용하고 요청하지 않은 journal을 추가하지 않는다. 모호한 대상은 확인하며 과거 수치·판단·승인을 새 근거로 이어받지 않는다. 운영10소스·영수증1개와 새8요청/6읽기를 확인했다. 기존 단일 deploy.sh의 복사·영수증 경로를 유지하며 새 패키지·포트·키·일반 권한은 없다. [동작·재현·한계](../infra/hermes/service-query-contract.md) · [실제 검증](../infra/hermes/query-completion/service-catalog.validation.json).
<!-- /service-query-20261118 -->


<!-- service-cause-candidate-20261119 -->

복합 원인 조사에는 별도 실패가 남아 있다. SDK 필수 조회 연결 후보는3반례와 회귀833검사·Linux 공식38/설치37검사를 통과했지만 실제 격리 실행에서 최종 보고가 수용되지 않았다. 후보 검증과 운영 적용을 구분하며 해당 후보를 배포하지 않는다. [원인·수행·미완료](../infra/hermes/service-query-contract.md) · [실제 실패·후보 검증](../infra/validation/service-query/cause-completion.validation.json).
<!-- /service-cause-candidate-20261119 -->


<!-- service-provenance-summary-in-archive -->


<!-- native-identity-boundary-20261119 -->

Hermes·공동 관리 경로의 최종 완료 경계에서 추가 공백을 확인했다. 서비스·컨테이너 목록을 모두 읽으면 pending은 비지만 논리 서비스의 실체가 확인됐다는 뜻은 아니다. 기존 chat_diagnostic_state는 이 미확인 상태를 최종 incomplete에 남기지 않았다. 이 때문에 짧은 요청에서 service_history_plan이 없을 때도 완료 방어가 유지되도록 정본에 4줄을 추가했다.

이번 변경은 정본과 집중검사에만 반영했다. 운영 파일·서비스·권한·모델을 바꾸지 않았고 새 모델 호출·MCP 도구 실행·채팅 게시·공격·학습도 하지 않았다. E17의 실제 SDK 단회 22.172초·partial 결과는 별도 근거로 유지한다. Native 전체 설치 사본 연결·SHA pin·영수증·복구·실제 채팅과 Vector의 실제 수집 경로 확인은 남아 있다. 15:50 KST 전에 기록·게시를 마치고 새 작업은 시작하지 않는다.

[Native 완료 경계 검증·미적용](../infra/validation/service-query/native-identity.validation.json) · [E17 SDK 실제 관측](../infra/validation/service-query/service-identity.validation.json) · [전체 경과](../archive/DIAGNOSTIC_HISTORY.md#native-identity-boundary-20261119).
<!-- /native-identity-boundary-20261119 -->
