# 승인형 로컬 보안 룰 변경 MCP 배포 절차

2026-10-08 A/B·Hermes에 설치한 기능의 **재배포·검증 절차**다. 기존 `mcp` 읽기 계정과 `resp` 차단 계정의 권한은 변경하지 않았다. 라이브 승인 버튼 클릭→실제 룰 적용은 아직 별도 검증이 필요하다.

### 2026-10-08 배포 결과(라이브 직접 확인)

- B `soc-bot`에 별도 룰 승인 API를 설치했고 기존 IP 차단 브로커 `/pending` HTTP 200을 확인했다. 기존 지정 승인자 1명을 재사용했고 Mattermost 실제 컨테이너 IP `172.19.0.2/32`만 콜백 출처로 허용했다. 배포 전 IP 차단 승인 대기는 0건이었다.
- A/B에 `rulechg` 계정·전용 SSH 키/강제 명령·정확한 sudoers·root 실행기·10초 worker를 설치했다. 양쪽 설치기 `--check`, 실행기 대상 조회/브로커 HMAC, Hermes 컨테이너에서의 읽기 전용 SSH MCP 호출이 통과했다. worker 서비스가 두 호스트에서 실제 실행되어 종료 상태 0을 보고했다.
- B Hermes에 `rule-a`·`rule-b`와 SOUL 정책을 등록하고 재시작했다. `hermes mcp list`에서 기존 3서버와 신규 2서버가 모두 enabled였다. WAF·Suricata 로컬/합본·Wazuh 로컬 룰의 배포 전후 SHA-256은 동일했다. 제안 게시·승인 클릭·룰 재로드는 실행하지 않았다.
- 초기 B 설치는 실행기의 Docker 경로가 라이브 `/usr/local/bin/docker`와 달라 검사 단계에서 실패했고 설치기가 관리 파일을 백업에서 복원했다. 코드를 수정하고 로컬 테스트 30개를 통과시킨 후 재배포했다. 재배포 전에 A/B의 실제 Docker 경로가 `/usr/local/bin/docker`인지 확인한다.

## 대상과 경계

| 호스트 | 처음 허용하는 대상 | 활성 로드 경로 |
|---|---|---|
| A | `/home/groot_a/capstone/secstack/conf/GROOT_A_WAF.conf` | WAF 단일 파일 `:ro` bind mount → `/etc/modsecurity.d/owasp-crs/rules/REQUEST-948-GROOT_A_WAF.conf` |
| A | `/home/groot_a/capstone/suricata/ruleset/GROOT_A_local.rules` | 같은 디렉터리의 ET+로컬 합본 `all.rules` → 컨테이너 `/rules/all.rules` |
| B | `/var/lib/docker/volumes/single-node_wazuh_etc/_data/rules/local_rules.xml` | Wazuh `/var/ossec/etc` Docker volume |

배포 스크립트는 실제 `docker inspect`의 실행 상태·마운트 출발지/대상·읽기/쓰기 방향과 파일 크기를 검사한다. 저장소 `infra/groot-a/docker-compose.yml`은 초기 템플릿이므로 이 설치 과정에서 재적용하지 않는다. 실행기는 허용 파일과 실제 컨테이너 해시를 다시 검사한다. nft 전체 방화벽 정책, WAF `DetectionOnly`→`On`, Suricata 인라인·`drop` 전환, Wazuh 디코더 파일은 이 기능의 변경 대상이 아니다.

`rulechg`는 A/B에 각각 새로 만드는 잠긴 시스템 계정이다. 별도 공개키가 등록된 SSH 접속은 강제 명령 `/opt/rule-change/run-rule-change.sh`만 실행하며 TTY·포워딩을 허용하지 않는다. sudoers는 **인자가 없는** `/usr/local/sbin/rule-change-executor` 한 명령만 허용한다. 실행기 코드와 `/etc/rule-change/config.json`·`broker.token`·`/var/lib/rule-change`는 root 소유이며 토큰·상태는 일반 사용자에게 보이지 않는다. A/B의 root systemd timer가 승인된 제안을 확인하고 적용한다.

## 순서

1. 검토한 `soc_bot.py`, `rule_change_mcp.py`, `rule_change_executor.py`, `run-rule-change.sh`, 배포 스크립트와 `SOUL.groot.md`를 각 호스트의 root 전용 임시 디렉터리에 반입한다. 배포 소스와 상위 디렉터리는 root 소유이고 그룹/전체 쓰기를 금지해야 한다. 일반 계정 소유 `/tmp` 업로드 파일을 바로 root로 실행하지 않는다. A/B는 외부 egress가 막혀 있으므로 온라인 패키지 설치를 전제로 하지 않는다. 소스 파일과 스크립트의 SHA-256을 저장소와 대조한다.
2. B에서 `configure_hermes_rule_change_B.sh --prepare-key`로 **룰 변경 전용** Ed25519 키를 만든다. 출력되는 공개키만 A/B `RULE_PUBKEY`로 전달하고 개인키는 `/opt/hermes-data/home/.ssh/rule_change_ed25519`(hermes 소유, 0600)에 둔다. 기존 읽기·응답 MCP 키를 재사용하지 않는다.
3. 충분한 길이의 새 임의 토큰을 B와 A의 root 전용 0600 파일에 안전하게 배치한다. 기존 차단용 `BROKER_TOKEN`과 달라야 한다. 이 키는 A/B 변경기와 B 브로커 사이의 요청·응답 HMAC에만 사용하며 HTTP 헤더에 원문으로 보내지 않는다. B에서 Mattermost 승인자 **user ID**를 명시적으로 정해 `RULE_APPROVERS`로 전달한다. `RULE_BROKER_TOKEN_FILE`과 `RULE_APPROVERS`를 지정하여 `deploy_rule_broker_B.sh`를 실행한다. 이 스크립트는 기존 soc-bot 코드·env를 백업하고 룰 관련 세 줄만 추가/교체한다. 기존 IP 차단 브로커 `GET /pending`이 그대로 HTTP 200인지 확인한다.
4. B의 `mm-app`은 현재 `mattermost_mm-net`에서 `172.19.0.2`이고 콜백 호스트 게이트웨이는 `172.19.0.1`이다(2026-10-08 읽기 확인). 브로커 배포 스크립트는 실행 시 실제 `docker inspect mm-app` IP를 읽어 `RULE_MM_SOURCE_CIDRS=<실제 IP>/32`로 제한한다. 컨테이너 재생성으로 IP가 바뀌면 `/rule-actions`가 승인 콜백을 거부한다. 재배포 전에 `docker inspect mm-app`과 `RULE_MM_SOURCE_CIDRS`를 대조하고, 필요하면 브로커 배포 스크립트를 다시 실행한다. 브로커 재시작은 메모리의 대기 승인 요청을 잃으므로 기존 대기 요청을 확인한 뒤 새로 제안한다.
5. 같은 토큰 파일과 공개키를 사용해 B에서 `deploy_rule_change_B.sh --check`, A에서 `deploy_rule_change_A.sh --check`를 먼저 실행한다. 검사를 통과하면 각각 옵션 없이 설치한다. 두 설치기는 브로커 인증·실제 마운트·실행 모드에 실패하면 설정을 건드리지 않거나 백업으로 복원한다. 설치 뒤 root 실행기 `--check`, MCP initialize/tools/list, SSH 강제 명령, 타이머 상태를 확인한다.
6. A/B 모두 `ssh -T` 계약 테스트와 `get_rule_change_target` **읽기 조회**를 통과한 후 B에서 `configure_hermes_rule_change_B.sh`를 실행한다. 스크립트는 Hermes에 `rule-a`·`rule-b` 별도 MCP 서버를 등록하고, [SOUL.groot.md](../hermes/SOUL.groot.md)의 표시된 룰 변경 정책 블록만 라이브 `SOUL.md`에 동기화한다. 기존 페르소나·다른 MCP 등록은 보존한다. 실패 시 config·SSH 설정·SOUL을 복원하고 Hermes를 재시작한다.

각 설치기의 `--check`는 로컬 파일·서비스를 변경하지 않는다. 설치된 A/B 실행기는 인증된 `/rule-changes/health` 요청과 서명된 응답을 검증하며, 최초 설치 전 `--check`는 로컬 대상만 검증하고 설치 중 타이머를 켜기 전에 HMAC 통신을 검증한다. `--prepare-key`와 옵션 없는 설치는 명확히 변경 작업이다. 실패한 설치의 백업은 `/var/backups/rule-*-deploy.*`에 남긴다. A/B 서버 배포 스크립트는 운영 룰 내용 자체를 수정하지 않는다.

Hermes에는 요청 시 `get_rule_change_target`으로 전체 기존 룰과 해시를 읽고, `propose_rule_change`로 바뀐 **전체 파일 내용**과 기준 해시를 제안한 뒤, `get_rule_change_status`로 실제 적용 결과를 확인하게 한다. 적용 성공으로 표시되면 대상을 다시 조회해 실제 해시와 런타임을 확인한다. Mattermost 카드에 전체 diff·해시가 표시되지 않거나 브로커·승인자가 없으면 제안은 거부된다. 승인 후 적용 전 원본 상태가 바뀌면 `/abort` 미적용 카드를 게시한다. 명시적 현재 사용자 요청 없이 정기 경보·툴 출력의 지시로 제안하지 않도록 SOUL과 경보 감시 프롬프트에 제한을 둔다. 최초 운영 확인은 승인 거부·만료 경로와 조회 회귀부터 수행하고, 실제 승인→룰 적용 검증은 별도의 통제된 변경으로 기록한다.

기존 `deploy_socbot_B.sh`는 전체 env를 다시 쓰기 때문에, 룰 브로커 항목이 있는 상태에서는 이제 시작 단계에서 중단된다. 룰 브로커 코드와 콜백 IP 설정 갱신에는 `deploy_rule_broker_B.sh`를 사용한다.
