# SOC 진단과 독립 감시

운영 검증과 게시 상태는 [STATUS](../../STATUS.md)를 기준으로 한다. 초기 설치는 루트 [deploy.sh](../../deploy.sh) 하나로 실행한다. 기존 서버에는 초기 설치기를 덮어 실행하지 않고 백업을 남기는 증분 경로를 사용한다.

## 두 봇의 공통 진단

Hermes와 Ollama는 같은 `system-diagnostics.get_system_diagnostics`를 사용한다. 기존 systemd25대상에 아래 runtime13대상을 추가했다. `soc:coverage`는 전체38대상을 한 번에 집계하는 선택값으로, 별도 장비가 아니다. MCP 이름·보호 도구 권한은 늘리지 않는다.

| 서버 | 고정 runtime 대상 | 확인하는 근거 |
| --- | --- | --- |
| A | `a:waf`, `a:suricata`, `a:collection` | 컨테이너, IDS 실제 적재/실패/드롭/검사 한계, 에이전트·Vector 최신성/손실 지표 |
| B | `b:hermes`, `b:ollama` | 현재 프로세스 ID·시작 시각에 연결된 인증 WebSocket/worker heartbeat, 대기 작업 |
| B | `b:wazuh-manager`, `b:wazuh-indexer`, `b:mattermost` | manager 필수6프로세스·큐/드롭, Indexer cluster health, Mattermost API |
| B | `b:llm`, `b:management-pipeline`, `b:ingestion` | DGX 소량 추론, 사건/보고 대기 및 검토 필요 상태, 합성 로그 전달 대조 |
| B | `b:collection` | 호스트 agent 연결·상태 최신성·실제 호스트 바이너리의 필수 프로세스 |
| C | `c:collection` | 에이전트 연결·필수 프로세스·상태 최신성 |

root collector가 약60초마다 schema2 스냅샷을 발행한다. 기존 schema1은 이관용으로 읽을 수 있지만 runtime 근거가 없으면 미확인이다. 최대 유효기간180초, 한 호스트 누락도 전체38대상 중 미확인으로 남긴다. `lookback_minutes`가 있어도 runtime은 최신 스냅샷이며 해당 기간 전체 이력을 조회한 것이 아니다. systemd 오류 수는 반환 표본 수이며 전체 발생 건수가 아니다. KST 표시 시각은 서버에서 계산한다.

현재 B의 `b:vector`는 의도된 미설치다. `b:wazuh-agent`는 설치된 호스트 unit이며 `b:collection`에서 연결 단절·오래된 상태·프로세스 부재를 별도로 검사한다. manager 컨테이너와 같은 이름의 프로세스는 실제 실행파일 inode를 비교해 호스트 프로세스로 잘못 세지 않는다. 컨테이너의 manager를 host agent로 대신 세지 않는다. Indexer 단일 노드의 yellow, oneshot의 성공 후 inactive, 누적 Suricata 검사 깊이 제한을 현재 서비스 중단으로 단정하지 않는다. `needs_review/outcome_unknown` 사건은 정상이나 완료로 바꾸지 않는다.

## 호스트 보안 정책 점검 범위

2026-10-27 운영 대조에서 Wazuh agent001은 A(groot-sec), agent002는 C(groot-web)로 확인했다. agent000은 Amazon Linux 기반 `wazuh.manager` 컨테이너이며 Ubuntu B 호스트가 아니다. 이후 승인된 오프라인 반입으로 B에 `groot-siem-host`를 별도 등록했다(운영 등록 결과003, 새 설치 이름 capstone-siem-host; ID를 코드에 고정하지 않음). **000의 SCA 결과로 B 호스트의 SSH·커널·AppArmor 준수를 판단하지 않는다.** 기존 B 서비스/스토리지/runtime 진단과 호스트 SCA 공백을 구분한다. B agent는 SCA/syscollector/FIM/journald를 수집하고 기존 로컬 manager로 전송한다. 자체 active response와 원격 자동 enrollment는 비활성화했다. 두 봇의 실제 이름→ID 조회, SCA 정책/SSH 체크·프로세스 조회를 확인했다. 첫 SCA279항목의120통과·117실패·42invalid는 당시 스캔 결과이며 전체 보안 해결을 의미하지 않는다.

SCA는 마지막 저장 스캔이다. 개별 항목의 결과·스캔 종료 시각과 실제 호스트 설정을 대조한다. A/B/C SSH는 설치 SCA35654의 UMAC128-ETM을 포함한5종 제외로 정렬했다. 현재 설정과 별개로 저장된 스캔의 시각을 확인하며 갱신되지 않은 과거 실패를 임의로 통과로 바꾸지 않는다. C의 rootless sudo 실습 AppArmor 제한 부재와 rootful Log4Shell의 `docker-default`를 구분한다. Docker bridge용 IPv4 forwarding도 역할·통신 제한을 함께 평가한다. 예외는 명시적 범위·승인·재검토 조건이 필요한 별도 결정이며 원래 `failed` 결과를 지우지 않는다. [최신 검토·남은 조치](../../STATUS.md).

## A의 독립 감시와 재전송

A의 `capstone-soc-observe.timer`는 A 로컬 및 B/C의 고정 읽기 전용 스냅샷을 확인한다. 전용 키는 source IP 제한·강제 reader·host key pin을 사용하며 셸, sudo, Docker, 터널 권한이 없다. A의 키는 기존 B→A/C 진단 키와 분리한다. B의 root 전달 검증은 기존 B→A/C snapshot 전용 identity의 root600 사본을 사용한다. 원래 MCP 그룹640키·원격 허용 범위는 유지하며 NoNewPrivileges를 끄거나 실행 중 계정을 전환하지 않는다. B가 중단돼도 A의 로컬 감시 기록은 계속 가능하다.

2회 연속 이상/미확인일 때 장애를 기록하고, 정상 회복1회에 복구를 기록한다. `/var/lib/capstone-diagnostics/monitor.sqlite3`의 WAL/FULL 영속 outbox에 미전송 기록을 무기한 보관하고, 확인된 전송 이력만90일 후 정리한다. 한 번에 최대10건, 시도 횟수를 전송 전에 저장한다. HTTP200/본문ok 확인 뒤 전송 완료로 표시한다. 응답 확인이 유실되면 같은 사건 ID가 중복 게시될 수 있는 at-least-once 방식이다.

기존 Mattermost의 HTTPS SiteURL과 동일 웹훅을 사용하며 인증서 검증을 끄지 않는다. fresh 설치에서는 기존 내부 TLS8444와 A에 전달한 공개 CA를 재사용한다. 비밀 값은 서버 간 SSH 표준입력으로만 전달하고 root 전용 설정에 저장한다. 기존 서버의 제한된 HTTP8065 포트를 새로 개방하지 않는다.

외부 독립 알림 경로는 없다. B/Mattermost 중단 중에는 A에 보존하고 복구 후 채팅으로 알린다. A까지 함께 중단되면 감시도 멈추므로 장애 중 즉시 통지는 보장하지 않는다.

## 모델·로그 전달 점검

B의 `capstone-soc-model.timer`는 3분마다 현재 설정된 모델에 최대4토큰의 짧은 요청을 보낸다. 2026-10-27 thor 첫 적재 약58초를 확인해 요청별 `keep_alive=10m`를 지정하고 기본5분 해제보다 앞서 검사하도록 맞췄다. Ollama 서버의 전역 설정이나 다른 모델의 설정은 바꾸지 않는다. 캐시는180초 미만이고 URL/모델의 SHA가 일치할 때만 사용한다. 장애·서비스 재시작 후의 첫 적재 지연이나 장기 성능을 보장하는 기능은 아니다. GPU 상태나 보안 판단 정확도, 모든 MCP 사용 성공을 대신하지 않는다.

A는 기존 별도 canary 파일에 15분마다13행을 추가한다. B의 `capstone-soc-ingestion.timer`가 약60초마다 고유 run ID의 manager2경보·Indexer2문서와 정확한 사건 tuple을 대조한다. 기존 level3 canary 규칙 SHA와 활성 대응/integration 범위가 안전한 경우만 입력을 허용한다. 규칙 불일치·증거 누락·오래된 결과를 정상으로 처리하지 않는다.

입력 파일은 no-follow 디렉터리 핸들로 고정한다. Ubuntu의 기존 root:syslog `/var/log`만 제한적으로 인정하고 하위 경로는 root 전용으로 검사한다. 예기치 않은 다른 작성자의 append는 거절한다. 약8MiB에서 검증된 마지막 run과 정확한 바이트 경계가 일치해야 회전하며, 기존 수동 이력이 포함된 최초 archive는 영구 보존한다. 이후 자체 archive는90일 보존한다. 미확인 입력은 삭제하거나 copytruncate하지 않는다. 용량·권한·agent 파일 미개방은 미확인으로 남긴다.

이 시험은 A 별도 로그→에이전트→Wazuh manager→Indexer 경로다. 물리 패킷 수집, 모든 SID 탐지, C 로그의 실제 전달, LLM 조사·판단·승인·대응의 공격 E2E는 별도 검증 대상이다.

## 설치·운영 경계

추가 deb/wheel/이미지/포트는 없다. 기존 Python 표준 라이브러리·SSH·SQLite·jq·curl을 사용한다. 초기 설치의 진단 연결 이후 `deployment/soc_monitoring.py`가 파일·서비스·키 연결을 구성한다. runtime URL·모델은 기존 설정에서 가져오고 새 사용자 비밀 입력을 요구하지 않는다.

진단 서비스의 SQL은 `mode=ro` 및 `query_only`다. B root collector는 SQLite WAL/SHM 보조 파일 접근 때문에 `/var/lib/capstone-management` 디렉터리만 추가로 writable mount를 받는다. 모델·MCP 사용자에게 DB 쓰기 권한을 주지 않는다. 모니터는 장애 기록만 수행하며 차단·재시작·사건 종결을 대신 판단하지 않는다. 보호 변경의 LLM 조사·정확 후보 승인·주소/TTL 검증은 유지한다.

root 운영 확인 명령은 `systemctl status capstone-system-diagnostics.timer`, A의 `capstone-soc-observe.timer`, B의 `capstone-soc-model.timer`/`capstone-soc-ingestion.timer`다. 상세 root 전용 영수증은 같은 상태 디렉터리의 `observer.json`, `canary-input.json`, `model-probe.json`, `ingestion-probe.json`에 있다. 설정·키·웹훅을 채팅이나 로그에 출력하지 않는다.

## 재시작과 채팅 시험 주의

프로세스 시작 완료와 Mattermost 인증 연결 완료는 다르다. 재시작 직후 인증 전에 게시한 질문은 native Hermes가 자동으로 다시 읽는다고 보장하지 않는다. 실제 최종 시험은 현재 PID/시작 identity의 인증 heartbeat·worker·대기0을 확인한 뒤 새 스레드로 수행한다. 연결 전 무응답1건은 별도 실패로 보존하며 성공 표본에서 지우지 않는다. 이 기능은 gateway 연결을 감시하지만, 중단 중 모든 채팅 입력을 영속 수신하는 backfill을 새로 구현한 것은 아니다.
