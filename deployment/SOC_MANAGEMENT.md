# 초기 설치의 승인형 SOC 관리 확장

## 현재 설치·운영 기준 — 2026-11-04

관리 제어기는 실제 허용 대상에 따라 룰·서비스·임시차단의 상태 API와 ID를 구분한다. 차단/변경 대응이 연결된 센서 사건 또는 remediated 판정은 종결 전에 사건 구간의 자산별 Wazuh 경보 실제 읽기와 인용을 최소 검사한다. 정상 DNS 등 조치 없는 분류에 외부 목적지의 agent를 꾸며 요구하지 않는다. 이 검사는 위험 해소의 의미적 정확성을 대신하지 않으며 표본0·403·만료는 침해 부재 증거가 아니다.

기존 canonical controller 복사/렌더·설치38검사에 연결되며 새 패키지·키·포트·설정 입력은 없다. [실제 오류·재생·운영 범위](../infra/hermes/incident-impact.md) · [현황](../STATUS.md). 아래 날짜별 고정3-flow 설명은 과거 이력이며 현재 WAF/IDS 대체 근거·600/3600/60초 정책은 현행 운영 문서와 소스를 따른다. 실제 신규 설치0이다.

> **2026-11-02 보고 근거 보완:** 공용 grounding·query-completion 1.19.5와 자동 관리 controller를 기존 소스 묶음으로 설치한다. 실제 성공 호출에 없는 인용, 짧은 KST 시각 오표기, 서비스 재적용과 WAF 모드 변경의 혼동을 정정 대상으로 삼는다. 기존 초기 설치 경로가 두 봇의 원본/SHA 핀과 embedded gate를 함께 생성한다. 추가 패키지·포트·이미지·승인 권한은 없다. 운영 반영 범위와 새 모델 재시험 결과는 [STATUS](../STATUS.md)를 따른다.

> **2026-10-31 관제 보고 보완:** query-completion 1.15.4과 동일 공용 grounding 소스/SHA 핀을 두 봇·자동 조사에 함께 반영합니다. 센서 룰과 Wazuh 상관 규칙, 반환 건수와 신뢰 경계 필드의 혼동을 실제 응답과 대조해 LLM 정정을 요청합니다. 기존 단일 설치 경로·의존성과 승인/도구 권한을 유지합니다. [동작·검증 범위](../infra/hermes/event-report-grounding.md).

## 자동 조사 정책 동기화 — 2026-10-31

자동 조사용 `soc_alert_watch.prompt`의 공인 IP 전용·사설 실습망 일괄 제외 문구를 현재 집행 정책과 맞췄다. 공인 또는 RFC1918 출발지를 조사하며, 실제 차단은 명시적 `never_block`·관리/필수 서비스 주소 보호와 최근 5분의 독립적인 양방향 severity 1 TCP 흐름 3개, 현재 ingress 조건을 모두 검증해야 한다. 사설 주소 자체를 무해성이나 차단 적격성의 근거로 삼지 않는다.

자동 조사 wrapper에서는 `resp.block_ip/unblock_ip`를 제공하지 않는다. 별도 대화형 봇의 승인 요청 기능과 혼동해 자동 조사에서 없는 도구를 권하지 않는다. 임시 차단 거절을 우회하지 않고 필요한 조사·지원되는 변경안 준비를 LLM이 주도하며, 미지원 대응은 미완료로 보고한다. `verify` 모드는 계속 읽기 전용이다.

루트 `deploy.sh`의 기존 `source_bundle` → `prepare-siem` 복사 경로가 이 프롬프트를 그대로 설치한다. 설치 묶음의 실제 프롬프트와 렌더링된 집행기/도구 gate를 대조하는 회귀를 추가했다. 패키지·이미지·포트·설정 키·오프라인 반입 의존성은 추가되지 않는다. 기존 B에는 root 복구본을 남기고 프롬프트만 원자 교체했으며, 초기 설치기를 실행하거나 서비스를 재시작하지 않았다. 다음 자동 조사부터 읽는다. 검증 범위와 실제 사건 재조사 결과는 [STATUS](../STATUS.md)를 따른다. 새 서버 전체 설치나 실제 공격 차단 E2E 성공을 뜻하지 않는다.

### 센서 사건 종결 조건

실제 WAF/IDS 경보를 찾은 것은 조회 성공이며 사건 해결은 아니다. 센서 사건에서 resolved를 내려면 LLM이 `INCIDENT_DISPOSITION` 한 줄에 assessment(benign/remediated), 사건별 basis, 이번 실행에서 성공한 실제 센서 조회를 포함하는 evidence_tools를 명시해야 한다. 누락·형식 오류·중복 키·미해결 판단·조회 근거 부족은 needs_review로 남긴다. 승인 대기가 있으면 기존 waiting_approval 처리가 우선하며 verify의 읽기 전용 범위도 유지한다. 제어용 줄은 채널 보고에서 숨기고 원 응답/trace는 보존한다.

이 검사는 모델 판단의 의미적 진실성을 보증하지 않는다. 실제 재시험에서는 monitor 후 needs_review로 정정되었으나 Wazuh 상관 규칙과 native 센서 룰의 혼동 등 답변 품질 문제가 남았다. 초기 설치는 동일 controller 원본을 렌더링한다. 기존 B는 활성 embedded gate를 그대로 두고 관련 함수만 AST/CAS 대조 후 교체했다. 서비스 재시작·권한 추가는 없으며 새 서버 전체 설치와 실제 공격 대응 E2E는 별도다.

> **2026-11-04 기준:** [운영 절차](OPERATIONS.md) · [공식 지침 부분 대조](SECURITY_GUIDELINES.md) · [현재 구현/운영/미검증](../STATUS.md). 기본/확장/운영 MCP 프로필은 구분하며 과거 도구 수를 현행 전 업무 권한으로 간주하지 않는다. 신규3VM 실제 설치는 미실시다.

## 2026-10-24 관리 gate 보완

후속 읽기 보안 점검에서 기존 A의 응답 계정은 하위 차단 helper를 직접 sudo 실행할 수 있는 이전 구조임을 확인했다. 아래 새 설치기의 root 승인 wrapper/직접 helper sudo 금지 계약과 구분하며, 초기 설치기를 기존 서버에 실행하지 않고 원본·의존성·복구를 확인한 별도 최소 이관이 필요하다. 이번에는 점검만 했고 실제 우회·차단·sudoers 변경은 하지 않았다. [판정과 후속](../STATUS.md).

초기 설치기는 같은 `soc_management_run.py` 원본을 root 소유 controller의 `-I -B -c` 인수로 결속한다. 요청 builder는 native 도구 재구성과 `extra_body`가 있어도 mode별 도구 목록·강제 선택을 다시 검사한다. 실제 MCP 호출 완료가0이면 완료/SILENT를 미확인·needs_review로 표시한다. Controller는 needs_review의 SILENT도 고정 검토 안내로 전달한다. 진단 시각은 `observed_at_kst`, 오류 수는 반환 표본과 전체 건수 미확인을 구분한다.

이 소스 계약을 기존 B에 별도 최소 이관한 결과는 [STATUS](../STATUS.md)를 따른다. 아래 신규 설치 모듈 전체를 기존 운영 서버에서 실행한 것은 아니며 새3VM 전체 설치 시험도 하지 않았다. 추가 패키지·이미지·포트·일반 실행 권한은 없다.

2026-10-23 코드 통합. 실제 새 VM 설치와 운영 서버 적용은 수행하지 않았다.
사용자 진입점은 루트 `deploy.sh`이며 아래 단계는 그 내부 호출 계약이다.

| 내부 단계 | 호스트 | 역할 |
|---|---|---|
| `check --role siem\|security` | B/A | 소스·도구·미관리 계정/파일/포트 충돌의 읽기 전용 사전 검사 |
| `prepare-siem` | B | 실제 등록 A agent ID, Mattermost 관리자 ID·컨테이너 /32 확인; 별도 HMAC/응답 토큰·SSH키 생성; 브로커 준비 |
| `export-siem` → `receive-security` | B→A | 컨트롤러의 인증된 SSH stdin 파이프로만 공유 비밀 전달; stdout을 터미널·로그·파일에 복사하지 않음 |
| `apply-security` | A | 제한된 forced-command MCP/worker, Native AR 등록 어댑터, TTL nft set 설치; 공개 SSH host key·완료 영수증 반환 |
| 로그 활성화·SIEM 모니터·대시보드 | A/B | 이 단계 뒤 관리 loop 활성화. A AR 설정 변경 뒤 로그 source pin을 확정 |
| `activate-siem` | B | A 공개 결과를 stdin으로 검증; 엄격 SSH host key pin, MCP 5개, 정확 agent/rule AR 설정, 동일 CID 재시작 후 인증 API 준비 검사·도구 목록 검사·관리 timer 활성화 |
| `verify --role siem\|security` | B/A | 소스/설치 파일 SHA, 고정 full CID, 인증 브로커, unit 상태, 실제 nft 보호 요소·drop 순서, AR 설정 검증 |

공통 환경은 기존 `CAPSTONE_SOURCE`, `/opt/capstone` 고정 `CAPSTONE_ROOT`, 세 서버 IPv4,
`MONITOR_INTERFACE`, `SSH_PORT`, `WAF_PORT`, `LLM_BASE_URL`, `LOG_PROTECTED_IPS`다.
`ADMIN_PROTECTED_CIDRS`는 선택적 canonical IPv4 CIDR 목록이며 빈 값은 추가 보호 0개다.
주소를 대역 내 개별 IP로 펼치지 않고 `never_block`·containment 검사에 합친다.
이 예외는 IP 차단에만 적용한다. 탐지 로그를 버리거나 WAF 요청 검사를 면제하지 않는다.

추가 Python 패키지나 이미지가 필요하지 않다. 기존 Hermes 이미지의 MCP/CLI/한국어 guard와
Ubuntu의 Python·OpenSSH·sudo·systemd·shadow·iproute2·Docker를 사용하며 A에는 nftables가 필요하다.
패키지 설치·이미지 pull·일반 shell·Docker 권한을 LLM에 제공하지 않는다.

## 권한과 재현 경계

- 기존 승인·후보·증거 검증 엔진은 원본을 수정하지 않고 설치 시 고정 상수만 AST로 바인딩한다.
  승인 target은 A WAF/Suricata 로컬 룰과 B `capstone_portable_rules.xml`이다.
  허용 서비스 작업은 A WAF·Suricata, B Wazuh manager·dashboard뿐이다. 새 TLS edge를 옛 chatproxy로 대체하지 않는다.
- `rulechg`와 `resp`는 고정 stdio forced command와 **인수 없는 root helper 하나**만 sudo로 호출한다.
  `resp`에 `agent_block add *` 같은 직접 권한을 주지 않는다. 승인 자격은 root 파일에만 있다.
- B Wazuh 룰은 실제 live 파일과 재시작 시 복사되는 source를 같은 후보·백업에 결속한다.
  source는 bind inode를 보존하고, native analysisd 검사 실패 시 두 파일을 복원한다.
- Native AR는 고정 agent/rule/location 사건을 등록할 뿐 차단하지 않는다.
  LLM 조사·MCP 호출 후 세 개 이상의 독립적 양방향 흐름, 최근 증거, 실제 source pins와 보호주소를 확인한다.
  임시 TTL 600초, 승인 유지 3600초, 미응답 만료·소유권·재연장 금지는 기존 엔진을 유지한다.
- 관리 loop의 도구 gate는 root 소유 controller에 고정해 `python -I -B -c`로 전달한다.
  사용자 쓰기 가능한 Hermes data 경로의 실행 파일을 root controller가 신뢰하지 않는다.
  관리 CLI 홈에는 gateway 전용 플러그인을 활성화하지 않으며, 한국어 guard와 MCP 제한은 별도로 유지한다.
- `/var/lib/capstone-soc/{siem,security}.json`은 설치 영수증이다. 완료된 반복 호출은 검증만 수행한다.
  중간 intent만 남은 실패는 자동 삭제·자동 재시도를 하지 않는다. root 비공개 백업과 intent를 보존하고 검토 후 복구한다.
  기존 운영 설치나 미관리 계정·컨테이너를 이 모듈로 이관하지 않는다.

## 검증 범위와 남은 한계

신규 synthetic 회귀는 상수 변환·정확 승인 유지·full CID·도구 권한·관리자 CIDR·nft 변조 거부·
multi-root AR·재실행 무변경·Wazuh live/source 교체와 복원을 검사한다.
기존 MCP/containment 및 Hermes 관리 회귀도 별도로 실행한다.
이는 실제 신규 3서버 설치, Mattermost 실제 승인 클릭, 공격 E2E, 장애·서비스 재시작 E2E를 증명하지 않는다.

임시 차단 대상 destination은 설치의 세 서버 주소로 고정한다. 별도 NAT/public alias는 자동 추정하지 않는다.
현재 IP 차단 검사는 인터페이스·gateway·DNS·활성 SSH 연결도 보호한다.
kernel TTL은 브로커 장애와 무관하게 만료하며, 재부팅 뒤 임시 차단을 자동 재생성하지 않는다.
과거 로그 일괄 전송, 일반 백업/복구, 장기 장애 backfill, 모델 판단 정확도 평가는 별도 과제다.
승인으로 룰 원문이 바뀐 뒤 초기 역할의 원본 SHA 검증과 운영 변경 영수증을 조정하는 일반 업데이트 기능도 별도다.

## 2026-11-04 실제 포함 gate와 참조 결속

운영 CLI는 `python -I -B -c`의 불변 포함 코드를 실행한다. `run.py` 복사본만 갱신한 것으로 실행 코드 갱신을 판단하지 않는다. 신규 설치는 동일 렌더링 gate를 `/opt/capstone-management/soc_management_run.py`에도 root750으로 기록하고 기존 managed-files 원장에 포함한다. controller는 포함코드 SHA가 root참조와 다르면 자식 실행 전에 거절한다. 기존 운영 증분에서도 포함코드·참조·plugin/SDK 핀과 실제 MCP 구간을 함께 확인한다.

현재 임시차단은 독립3흐름이 아닌 적격 ingress1흐름 또는 검증한WAF 거부 거래를 사용하는11/2이후 정책이다. 지정IDS Native 예외·원래600초·유지승인3600초·해제/만료후60초와 새근거 조건을 유지한다. 위날짜별3흐름설명은과거기록이다. [현재정책](../infra/mcp/approved-operations.md) · [실제 배포/927검사/잔여](../infra/hermes/management-gate-binding.md). 새패키지/포트/일반권한·실제새3VM설치 추가0이다.

## 자동 후속 상태와 고정 실행 인자 (2026-11-05)

모든 verify는 operator_review 여부와 관계없이 실제 연결된 owned/shared 제안의 현재 상태를 필수 읽기로 전달한다. 룰은 proposal_id, 서비스/차단은 request_id이며 등록 스키마 안의 정확 ID를 모델이 선택한다. 실제 센서/영향/판단·승인 경계를 대체하지 않는다. 초기 설치 렌더의 고정 `-I -B -c`는 SHA256 결속 zlib/base64 인자이며 원문 root참조와 재생성 결과가 정확히 일치해야 한다. 원본2MiB·실행 인자65,535B 상한을 실행 전에 검사한다. 이는 Linux 단일 인자 한도 초과를 막고 writable home 실행으로 우회하지 않는다. [원인·운영·935검사·한계](../infra/hermes/shared-status-verification.md).
