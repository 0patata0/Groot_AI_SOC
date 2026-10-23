# 초기 설치 로그 정제·회전·관측 모듈

`log_pipeline.py`는 기존 `infra/normalization/`의 운영 계약을 새 3 VM의 주소·머신 ID·고정 컨테이너에 결속하는 관리자용 설치 모듈이다. 진입점은 루트 `deploy.sh`이며, 기존 운영 서버를 자동으로 인수하거나 과거 일회성 배포 스크립트를 실행하지 않는다. LLM에 일반 sudo, Docker, 패키지 설치 또는 임의 명령 권한을 추가하지 않는다.

2026-10-23에 소스 렌더링·권한·실패·재실행 계약의 로컬 격리 회귀를 수행했다. **이 어댑터로 새 3 VM을 실제 설치하거나 호스트를 재부팅한 검증은 하지 않았다.** 기존 운영 검증 기록과 이 설치기의 검증 결과는 별개다.

## 반입 조건

- A: 사전 검증한 Vector **0.59.0** Debian 패키지, jq, logrotate, coreutils, util-linux, systemd, Bash, Python 3.12 및 기본 보안 역할의 Docker·Wazuh agent 패키지. Vector는 `/usr/bin/vector` 또는 `/usr/local/bin/vector`의 root 소유 정규 실행 파일이어야 한다. logrotate는 `/usr/sbin/logrotate`를 사용한다.
- B: 기본 SIEM 역할의 Wazuh **4.14.8**/Indexer **2.19.6** 고정 이미지와 생성된 TLS CA·관리자 클라이언트 인증서. 기존 관리자 암호를 읽거나 새 암호를 전송하지 않는다. API 호출은 CA/호스트 검증을 켜고 고정 B 주소의 9200 포트만 사용한다.
- A Suricata는 고정 이미지의 native `--build-info`에서 **8.0.6**을 확인한다. WAF producer와 규칙은 기본 역할이 검증한 이미지에 readonly bind로 추가된다.
- source bundle은 `deployment/log_pipeline.py`, 명시한 정제·회전·history 소스, Wazuh 규칙·관측 JSON과 native logtest 4개 및 참조된 합성 fixture를 포함한다. 모든 소스의 SHA-256과 설치기 자체 SHA를 receipt에 결속한다. 다운로드나 패키지 설치는 이 모듈의 기능이 아니다.

주소는 `SECURITY_HOST`, `SIEM_HOST`, `SERVICE_HOST`의 서로 다른 IPv4다. `LOG_PROTECTED_IPS`는 쉼표로 구분한 인프라 보호 주소이며 세 호스트를 포함한다. 기존 `protected_asset`와 evidence/관측 진입 조건에 사용한다. **`ADMIN_PROTECTED_CIDRS`는 별도 차단 예외 정책이므로 이 모듈의 로그 정제·탐지·관측 필터에 넣지 않는다.** 관리자 주소의 원본 감사 이벤트를 지우거나 보이지 않게 만드는 기능이 아니다.

## 컨트롤러 순서

모든 명령은 `CAPSTONE_SOURCE`와 위 주소 환경변수를 받는다. `ROLE_DIR`는 A `/opt/capstone/security`, B `/opt/capstone/siem`만 허용한다. 설치 identity는 공개 주소·보호 주소·소스·현재 머신 ID로 만든다. 부모 Bash의 일시적인 `PROFILE` 환경변수는 identity 입력이 아니다.

| 명령 | 동작 |
| --- | --- |
| `fingerprint security` | 로컬 소스 SHA 집계. 서비스·파일 생성 없음 |
| `check security\|siem` | Linux root·도구·새 설치 경로 또는 관리 receipt/파일 확인. 기동·컴파일·컨테이너 생성 없음 |
| `prepare security` | 기본 A compose 렌더 후, writer 기동 전에 실행. 고정 이미지에서 **기동하지 않은** 임시 컨테이너로 Suricata 기본 YAML만 읽고 제거. readonly 구성 bind·gen0·alias를 만들고 기본 manifest의 compose SHA 갱신 |
| `prepare siem` | B core compose 생성 후 manager 기동 전에 규칙 bind와 분석 worker 순서를 설정. 호출자는 변경한 core compose를 다시 읽어 후속 compose 생성에 사용 |
| `verify-base security` | 준비 파일과 실제 writer의 전체 mount·image·command·entrypoint·환경변수를 비교. 알 수 없는 추가 mount도 거절. 최종 정제 활성화는 요구하지 않음 |
| `activate siem` | manager 기동 후 버전·규칙 syntax·실제 복사 SHA와 native 합성 logtest를 확인. 아직 monitor 미완료 |
| `activate security` | agent 등록과 **SOC의 마지막 ossec.conf 변경 이후**에 실행. 기존 raw localfile/AR 설정을 보존하고 정제 localfile을 추가한 후 최종 XML SHA에 원본 gate를 결속. reader·timer 기동 및 첫 checkpoint 검사 |
| `monitor siem` | A agent 등록 이후, 현재 `capstone-security`의 유일한 Active agent ID를 조회해 관측 모니터 생성. disabled 생성→readback→revision CAS 활성화→재검증 |
| `verify security\|siem` | 최종 receipt·파일·runtime identity·reader gate 또는 monitor의 실제 상태 확인. 중간 상태는 완료로 인정하지 않음 |

B native logtest는 기존 entry 9개, correlation 24개, health 30개, evidence 53개를 합성 입력으로 검사한다. fixture는 `wazuh-logtest`의 stdin에만 주고 실제 수집 파일·journal·alert queue에는 쓰지 않는다. 따라서 이 결과는 전송·색인 E2E의 증거가 아니다. 실제 실행 시 각 묶음의 PASS 줄 수와 출력 SHA를 receipt에 저장하며, 요약 PASS 줄은 시나리오 수에 포함하지 않는다.

## 원본과 출력 운영 계약

- writer log 부모는 정확 `/opt/capstone/security/logs/suricata`의 998:998/0755와 `.../modsecurity`의 101:101/0755만 제한 허용한다. 각 `capstone-managed`는 root:root/0711이고 상태·설치 소스는 root 소유다. 다른 사용자 소유 부모나 symlink는 거절한다.
- 원본은 `generation-0000000000.jsonl`부터 시작한다. Suricata는 generation·고정 reader alias `eve.json`·writer alias `active.jsonl`의 3개 hardlink, WAF는 generation·reader alias `audit.log`의 2개 hardlink를 정확히 검사한다. WAF audit-path는 root:root/0444다.
- Suricata YAML은 readonly이며 EVE 출력만 `capstone-managed/active.jsonl`로 옮긴다. WAF는 템플릿만 readonly bind하고 이미지가 생성하는 override 목적지는 덮어막지 않는다. 실행 중 WAF full CID와 producer/config SHA를 함께 결속한다.
- 준비 시 첫 gen0가 0바이트임을 device/inode와 함께 기록한다. writer가 먼저 기록해 첫 reader 기동 시 파일이 비어 있지 않아도, **최대 600초의 첫 시작 grant** 안에서만 그 동일 gen0를 `read_from=beginning`으로 읽을 수 있다. 실제 native checkpoint가 생긴 것을 확인하면 grant를 봉인한다. 이후 비어 있지 않은 파일에 checkpoint가 없거나 손상되면 거절한다. checkpoint를 만들어 넣거나 수신 ACK를 가장하지 않는다.
- 원본 회전은 기존 두 reader/정확 writer identity gate와 영속 state/history를 사용한다. 원본 세대를 자동 삭제하지 않으며, writer 재생성으로 full CID가 바뀌면 자동 인수하지 않는다. 허용된 동일 CID 재시작과 새로운 컨테이너 인수는 다른 작업이다.
- 정제 출력은 기존 maintenance의 정지·reader 확인·재개 계약으로 회전한다. ready/quarantine/evidence/telemetry에 일일 또는 64 MiB, 48회·14일 보존 설정을 적용한다. 용량·collection 오류·buffer pressure·raw line 크기 관측 timer도 포함한다. 이 숫자는 손실 없는 처리량이나 저장 공간 보장을 뜻하지 않는다.
- 보조 `fast.log`, `stats.log`, `suricata.log`, `capstone-access.log`만 별도 일일 timer에서 기존 14회/500 MiB copytruncate 정책을 사용한다. EVE, audit, generation 파일과 wildcard는 이 정책에 포함하지 않는다. 보조 copytruncate의 기록 공백 가능성은 남는다.
- 이전 boot의 journal은 기존 bounded history-auto가 A 로컬의 root 전용 store에 보존한다. 자동 운영 재주입은 하지 않는다. **A→B history-auto-transfer SSH 반입·수신·보관 모듈은 이 어댑터에 포함하지 않았다.**

설정은 `/etc/capstone-vector`, 정제 출력은 `/var/log/capstone-vector`, 원본 state는 `/var/lib/capstone-raw-operations`, 로컬 journal 보존은 `/var/lib/capstone-vector-history-auto`다. 설치 receipt는 각 역할의 `log-pipeline/receipt.json`에 root:root/0600으로 저장한다. Vector config/env/line-binding의 정확 0600 계약과 private state를 보존한다. Docker 호출은 실행 파일 경로뿐 아니라 `unix:///var/run/docker.sock`을 명시한다.

## 실패·재실행과 검증 한계

완료된 동일 프로파일에 대한 변경 단계 재호출은 검증만 한다. `prepared`/`rules_active`는 check에서 관리 중간 상태로 확인할 수 있으나 최종 verify 성공은 아니다. create/activate/monitor 요청 결과가 불확실하거나 파일·주소·머신 ID·소스 SHA가 바뀌면 자동 재시도·adoption을 하지 않는다. 해당 intent receipt와 운영 상태를 관리자가 대조한 뒤 별도 복구해야 한다. 중간 실패는 이미 성공한 앞선 역할을 자동으로 되돌리지 않는다.

관측 모니터는 `actions=[]`, 1분 주기다. OpenSearch가 저장 시 추가하는 알려진 기본값만 canonical 비교에서 허용하고 검색 timeout·부분 shard·중복 이름·예상하지 않은 404는 거절한다. 사건 판단·승인·차단을 이 모니터의 고정 분기로 대체하지 않는다.

로컬 검증은 `python3 -B deployment/test_log_pipeline.py`로 실행한다. 실제 새 VM의 native 설치, 실제 호스트 재부팅, 새 보안 사건의 manager/Indexer 종단 수신, 장기 장애·대량 backlog 복구, 일반 백업/재해복구, 실제 공격 및 LLM 승인 전체 E2E는 이 모듈의 로컬 회귀로 입증되지 않는다. Vector의 로컬 acknowledgement나 Wazuh cursor를 원격 영속 수신증으로 표현하지 않는다.
