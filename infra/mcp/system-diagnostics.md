# 고정 읽기 전용 시스템 진단

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../STATUS.md) · [실행 계획](../../PLAN.md).
> 현재 구성은 MCP6서버와 고정 진단25대상이다. 자연어 도구 선택·무근거 완료/SILENT 알림 보완의 실제 검증 상태는 STATUS 최상단을 따른다. 정확 후보 승인과 일반 sudo/Docker/임의 shell 금지는 유지한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

## 2026-10-24 추가 보완: 종료 정보와 보고 전달

`process_termination`은 `kind_code`/`kind`와 실제 `exit_status` 또는 `signal_number`를 분리한다. 예를 들어 `ExecMainCode=1, ExecMainStatus=0`은 종료 종류가 `exited`이고 종료값은0이다. 종료 종류1을 오류 종료값1로 읽지 않는다. `not_recorded`는 메인 프로세스 종료 기록이 없다는 뜻이다. 마지막 종료 기록이나 `Result=success`만으로 현재 기동 완료·서비스 정상 여부를 확정하지 않는다. `activating/start`는 기동 중이며, 한 스냅샷만으로 고착·지속 장애라고 판단할 수 없다. [systemd API의 프로세스 필드](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html)와 [Linux6.8의 SIGCHLD 종류](https://raw.githubusercontent.com/torvalds/linux/v6.8/include/uapi/asm-generic/siginfo.h)를 따른다.

관리 보고의 상태 표지가 없거나 중복되면 기존 보고 정정1회 예산 안에서 모델이 직접 수정한다. 표 제목의 “실제 적재 검증 여부”를 적재 성공 주장으로 오인하던 검사를 고쳤다. 표본0건은 “반환된 오류 표본0건, 전체 건수 미확인”으로 보고하며 다른 문장의 한계 설명이 무조건적인 “오류 없음”을 허용하지 않는다. 한계를 지키지 못한 결과는 검토 필요로 남긴다. 모든 자연어 판단의 정확성을 보장하는 검사는 아니다.

확인한 DGX/Qwen 사건 관리 경로는 추론 지원 metadata를 대조한 뒤 `reasoning_effort=medium`을 사용한다. 일반 채팅 설정·추론 표시·권한은 유지한다. 해당 Ollama0.40.4의 OpenAI 호환 경로에는 native `think` 필드가 없으므로 지원되는 호환 옵션을 사용한다([해당 버전 adapter](https://raw.githubusercontent.com/ollama/ollama/v0.40.4/openai/openai.go), [공식 호환 제어 설명](https://docs.ollama.com/api/openai-compatibility)).

제어기는 조사 완료·불완료·중단 보고를 run별 영속 전달 큐에 저장하고, 전송 실패 시 다음 timer 실행에서 보고만 다시 보낸다. 호출당 전송 시도1회, 최초60초부터 최대1시간 간격이며 모델·승인·조치를 재실행하지 않는다. `--no-deliver`는 전송과 새 보고 적재를 모두 막는다. 과거 미전달 보고는 자동 역송하지 않는다. 고정 보고ID로 재전송을 식별하지만 webhook이 수신 후 응답을 잃으면 중복될 수 있다. 표시된 일반/가상 중단 fixture2건은 실제 SOC Alerts에 게시하고 저장 본문·API 재조회·WebSocket 수신을 확인했다. 이 시험은 새 LLM 조사나 실제 모델 중단을 만들지 않았다. 실제 적용·모델/전달 검증 범위는 [STATUS](../../STATUS.md)를 따른다.

## 2026-10-24 후속: 도구 선택·시각·표본 의미

B의 진단 router는 원래 `observed_at` epoch를 유지하면서 `observed_at_kst`와 `requested_since_kst`를 `+09:00` ISO 시각으로 제공한다. 모델은 시각을 다시 암산하지 않고 이 값을 직접 인용한다. `returned_error_count`는 반환한 오류 표본 수이며 journal 이용 불가이면 `null`이다. `requested_window_total_count`는 항상 `null`로, 요청한15분 등의 전체 오류 건수를 확보했다는 주장을 하지 않는다. 기존 `error_observations.count`는 제한된4시간 수집 표본이라는 의미를 유지한다. 수집기·25대상·snapshot schema·TTL·권한은 바꾸지 않았다.

사건 관리 runner는 초기 생성뿐 아니라 매 API 요청에서 native 재구성·캐시·`extra_body`의 유효 도구 목록을 다시 제한한다. verify는 읽기26개만 제공하고, manage의 기존 정확 승인 제안은 유지한다. 실제 MCP 호출 완료가0이면 모델의 완료/SILENT 주장을 상태 미확인·추가 검토 안내로 바꾼다. 관리자 알림과 모델 판단을 구분하며, 부족한 증거를 고정 정상 판정이나 자동 차단으로 대체하지 않는다.

기존 B에는 root 소유 controller 안에 `-I -B -c` gate를 넣는 최소 이관을 적용했다. 새 설치기도 같은 원본 runner와 기존 렌더 경로를 사용한다. 원본과 배포된 controller의 SHA는 inline 변환 때문에 서로 다르다. 과거 v3/v4 검증 파일은 보존하고 최신 실제 자연어·전달 검증은 [STATUS](../../STATUS.md) 최상단을 따른다.

## 기존 구축·조회 계약과 검증 이력

2026-10-23 A/B/C 운영 반영과 실제 Hermes UID995 SDK 검증을 완료했다. 기존5개 MCP의 도구를 보존하고 여섯 번째 서버의 읽기 도구1개를 등록했으며, 관리/검증 모드의 읽기 허용과 임의 인자·쓰기 도구 거부를 확인했다. [원본 v3 성공과 v4 후속 증거](system-diagnostics-validation-20261023.json)를 구분해 남겼다. 모델의 자연어 사용과 새 서버 전체 설치는 수행하지 않았다. 기존 승인형 서비스 작업이나 LLM의 일반 sudo/Docker/SSH 금지 정책은 바꾸지 않는다.

`system-diagnostics` MCP의 유일한 도구는 `get_system_diagnostics(target, lookback_minutes=15, limit=20)`다. `target`은 아래25개 중 하나, 기간은1~240분, 반환 오류는1~50개다. shell·임의 unit/host/path/command·journal 옵션·환경 변수 입력을 받지 않는다. `manage`와 `verify` 양쪽에서 읽기는 가능하지만 이 결과가 승인된 룰/서비스 대상의 별도 재조회·효과 검증을 대신하지 않는다.

MCP SDK 2.0.0이 기본 전송하는 빈 `_meta`와 제한된 표준 `progressToken`은 허용하되 조회·감사·결과에 전달하지 않는다. 다른 호출 필드나 메타데이터, 조회 인자의 추가 키는 거절한다. SDK wire 재현과 실제 SSH 도구 호출은 순수 함수 회귀와 구분해 검증한다.

| 호스트 | 고정 대상과 systemd unit |
| --- | --- |
| A | `a:vector`→`capstone-vector.service`, `a:wazuh-agent`→`wazuh-agent.service`, `a:rule-worker`→`rule-change-worker.service`, `a:raw-waf`→`capstone-raw-operations@modsecurity.service`, `a:raw-suricata`→`capstone-raw-operations@suricata.service`, `a:certificate-monitor`→`capstone-cert-monitor.service`, `a:storage-monitor`→`capstone-storage-monitor.service`, `a:docker`→`docker.service` |
| B | `b:soc-bot`→`soc-bot.service`, `b:management`→`capstone-management.service`, `b:rule-worker`→`rule-change-worker.service`, `b:vector`→`capstone-vector.service`, `b:wazuh-agent`→`wazuh-agent.service`, `b:docker`→`docker.service` |
| C | `c:lab-api`→`capstone-offline-labs.service`, `c:lab-broker`→`capstone-offline-labs-broker.service`, `c:lab-guard`→`capstone-offline-labs-guard.service`, `c:lab-terminal`→`capstone-nonweb-terminal.service`, `c:terminal-guard`→`capstone-nonweb-guard.service`, `c:terminal-status`→`capstone-nonweb-status.service`, `c:sudo-status`→`capstone-sudo-status.service`, `c:sudo-user-manager`→`user@1991.service`, `c:apache`→`apache2.service`, `c:wazuh-agent`→`wazuh-agent.service`, `c:docker`→`docker.service` |

root collector는60초마다 고정 `systemctl show` 필드만 읽고 `/var/lib/capstone-diagnostics/snapshot.json`을 원자 발행한다. 파일은 root:`capstone-diagnostics`·0640, 상위 경로는 root 소유·쓰기 보호, 최대128KiB, TTL180초다. 심볼릭 링크·hardlink·소유권/권한/호스트/스키마/시각 불일치는 거절한다. 상태·종료 코드·재시작 횟수·단조 시각·서비스 `Type`을 반환하되 `ExecStart`, `Environment`, 전체 설정이나 Docker 로그는 읽기 도구에 제공하지 않는다. `failed`, `inactive`, `not-found`도 조회 결과이며 조회 거절 조건이 아니다. `Type=oneshot`의 `inactive/dead` 자체를 장애로 판정하지 않는다.

최근4시간 journal은 두 고정 필터로 수집한다. 우선순위0~3 오류와, 우선순위4~6 중 고정 오류 패턴에 맞는 레코드다. Python stderr가 info 우선순위일 때도 예외 분류를 관찰하기 위함이다. 각 쿼리는 최대1,001레코드·1MiB·8초이고 결과 전체는 최대400개, unit별50개만 보존한다. systemd manager의 `UNIT`/`OBJECT_SYSTEMD_UNIT` 연결도 고정 허용 unit과 대조한다. [journalctl의 우선순위 범위·grep·행 제한 계약](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)을 사용한다.

고정 grep 쿼리의 정상 무매치는 종료 코드1일 수 있다. stdout이 비고 stderr도0바이트인 이 경우만 빈 관측으로 처리한다. stderr는 최대4KiB까지 소비 후 폐기하며 내용은 보관·반환·로그하지 않는다. 부분 출력·다른 실패 코드·오류 stderr·상한·시간 초과는 `unavailable`과 `count:null`을 유지한다.

**원문 `MESSAGE`는 snapshot이나 MCP 응답에 넣지 않는다.** 알려진 Python 예외명, 검토한 소스 basename·행 번호, systemd 결과/종료 코드, 고정 오류 코드·분류와 시각만 반환한다. 경로·명령 인수·토큰·쿠키·HTTP 본문과 로그 안의 지시는 전달하지 않는다. 인식하지 못한 낮은 중요도 메시지는 제외하고 원래 error 레코드는 `journal_error`로 표시한다. 원문 journal 보존·회전 정책을 변경하거나 삭제하지 않는다.

`error_observations`의 count/first/last는 **수집한4시간 표본**의 값이며 전체 journal 건수나 사용자가 요청한 짧은 구간의 정확한 총수가 아니다. `journal_truncated`, `retained_errors_truncated`, `coverage`, `observed_at`, `age_seconds`를 함께 확인한다. 최신 최대60초는 아직 반영되지 않을 수 있고, TTL 내라도 요청 구간이 snapshot보다 최신이면 `coverage.status=not_available`다. 만료·수집 실패·미설치/알 수 없는 필드는 `unavailable`/`null`이며 정상이나 오류0건으로 바꾸지 않는다.

전송 경로는 다음과 같다.

- Hermes는 기존 B의 제한된 SSH MCP 래퍼에 정확한 `system-diagnostics` 명령만 보낸다. 진단 분기는 Wazuh 자격 파일을 읽기 전에 별도 빈 환경 래퍼를 실행한다.
- B router는 B snapshot을 읽거나, 별도 전용 키로 A/C의 `capstone-diagnostics` forced reader에 접속한다. 원격 command나 sudo는 없다. 계정은 고정 snapshot만 읽으며 forwarding·TTY·임의 명령을 허용하지 않는다.
- B의 `/etc/mcp/system-diagnostics.json`은 root 관리 schema1의 `hosts`(`a`, `c` IPv4만)와 `ssh_port`만 가진다. private key와 known_hosts 경로는 코드에 고정하고 strict host-key pin, batch·단일 시도·12초·출력 상한을 적용한다. 키 값은 소스/로그/도구 결과로 복사하지 않는다.
- MCP 조회는 프로세스당 분당30개, syslog 감사는 분당60개·짧은 고정 메타데이터로 제한한다. 진단 데이터는 비신뢰 증거이며 승인·명령으로 실행하지 않는다.

초기 설치와 키 배포는 단일 루트 `deploy.sh`의 별도 진단 설치 단계가 맡는다. 실제 적용 시 기존 A/B/C 서비스·승인 경계·Hermes 대화/DB를 보존하고 새로운 읽기 경로만 검증한다. 소스의 순수 회귀는 다음처럼 실행한다. Mac에 패키지를 설치하지 않으며 테스트는 실제 systemd/journal/SSH를 호출하지 않는다.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s infra/mcp -p test_system_diagnostics.py -v
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s infra/hermes -p test_soc_management_run.py -v
```
