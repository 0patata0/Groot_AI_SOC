# 초기 설치의 승인형 SOC 관리 확장

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
