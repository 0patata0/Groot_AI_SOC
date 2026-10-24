# 단일 Bash 초기 설치

> **2026-10-25 선택적 시험 분기:** `OLLAMA_TRIAL_ENABLE=1`과 `OLLAMA_TRIAL_BUNDLE`을 지정하면 B의 반입물을 사전검사하고 SOC/진단 구성 뒤 host venv의 Ollama 기반 읽기 실행부를 설치·검증한다. 모델은 DGX에 유지한다. `OLLAMA_TRIAL_CHAT_ENABLE=1`을 함께 지정하면 ollama 봇과 비공개 soc-ollama 채널·host gateway 서비스도 추가하며 기존 Hermes 채널 ID를 유지해 soc-hermes로 이름 변경한다. 두 옵션 기본값0이며 기존 운영 서버에는 전체 bootstrap을 재실행하지 않는다. [추가 반입·권한·복구](../infra/ollama-trial/README.md), [실제 검증 범위](../STATUS.md).


<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 사용자 진입점은 루트 deploy.sh 하나이고 service schema9·HTTP3/터미널3·MCP6서버/고정 진단을 연결한다. 새3VM 전체 설치 시험은 사용자 제외 범위를 유지하며 기존 운영 서버를 초기 설치기로 덮어쓰지 않는다. 이번 운영 보완은 별도 최소 이관이다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

새 Ubuntu 24.04 amd64 서버 3대의 진입점은 저장소 루트의 `deploy.sh` 하나다. 서버 주소, SSH 접근, 관리자 승인된 오프라인 반입 파일을 준비한 후 다음 한 번으로 패키지·이미지 준비와 역할 설치·검증을 실행한다.

```bash
bash deploy.sh --apply --batch --config deployment/site.local.conf
```

`deployment/config.example.conf`를 로컬 전용 `site.local.conf`에 복사하고 실제 주소·HTTPS 이름·허용 내부망을 입력한다. 비밀번호를 이 파일에 넣지 않는다. 전체 저장소가 필요하며 `deploy.sh`만 따로 복사해서 실행하는 방식은 아니다. 내부 Python/Bash helper는 진입점이 자동으로 호출한다. Mac에는 패키지를 설치하지 않는다.

## 2026-10-24 보안 경계와 오프라인 준비

패키지 다운로드는 외부 준비 환경에서만 수행한다. 대상 서버에는 서명/해시를 검증한 deb와 의존성을 반입하고, 설치기는 전용 임시 캐시·빈 저장소 목록·`--no-download --no-remove`로 설치한다. Mac에는 패키지를 설치하지 않으며 반입/해시 확인 후 작업용 deb를 삭제한다. [반입 목록과 버전 기준](setup-packages-artifacts.md)을 함께 준비한다. host sudo 최소 `.4`, SIEM nginx 최소 `1.24.0-2ubuntu7.18`을 검사한다.

SIEM 기본 구성 뒤 전용 비권한 nginx가 **8444→같은 호스트 Mattermost8065**, **8445→loopback 승인8090** TLS를 제공한다. 기존 SIEM CA로 전용 DNS/IP 인증서를 만들며 CA 개인키는 SIEM에만 남긴다. 공개 CA만 SSH 파이프로 security의 운영체제 신뢰 저장소에 전달한 후 SOC 연결을 시작한다. SIEM의 일반 nginx 기본80 서비스는 masked로 유지한다. 최종 `--verify`에는 TLS와 호스트 격리가 포함된다. 기존 운영 A의 채팅/대시보드 프록시도 CA·이름 검증을 사용한다.

`MANAGEMENT_ALLOWED_CIDRS`는 SSH 원천, `DASHBOARD_ALLOWED_CIDRS`는443, `CHAT_ALLOWED_CIDRS`는8444 클라이언트를 지정한다. 대시보드의 `DASHBOARD_DENIED_CIDRS`(기본 VPN192.168.15.0/24)는 허용 목록보다 먼저 적용한다. 웹 허용 값이 비면 직접 클라이언트 접근을 열지 않고 security 프록시/필수 내부 통신만 허용한다. 인증된 설치 SSH 원천은 자동으로 보존한다. `ADMIN_PROTECTED_CIDRS`는 IP 차단 예외이며 SSH/웹 권한으로 확대하지 않는다. 새 공개 CA를 사용자 단말에 신뢰시키는 절차는 서버 간 CA 전달과 별개다.

SIEM은 서비스 C에서 agent1514/1515만 받고, Indexer9200/API55000/기존HTTP관리포트는 물리 서비스망에 개방하지 않는다. C의 기존 Docker 기본 bridge는 스스로 관리 영역 연결을 시작할 수 없으며 security에서 들어온 허용 서비스 응답만 허용한다. dedicated 실습 guard와 Docker 체인은 유지하고 별도 inet 테이블만 관리한다. 기존 Java의 임의 외부/JNDI 연결을 다시 여는 시나리오는 별도 승인·격리 설계가 필요하며 현재 CVE 재현 보류를 해제한 것이 아니다.

`resp`는 인자 없는 root MCP 진입점만 sudo 실행한다. root 전용 설정과 승인 검증을 거친 private helper만 실행하며 하위 차단 helper의 직접 sudo는 허용하지 않는다. 승인 일회성 소비·보호 주소·소유권·TTL을 유지하고 LLM에 일반 sudo/Docker·패키지 권한을 주지 않는다.

A의 필수 WAF·Suricata와 TLS 프록시는 재부팅 때 복구되도록 `restart: always`를 사용한다. 운영 중 `docker stop`은 멈추지만 daemon/호스트 재시작 시 돌아온다. 장기 중지는 관리자가 해당 정확한 CID의 재시작 정책을 `no`로 지정한 뒤 중지한다. 실습/백업의 기존 중지 정책은 유지한다. [Docker 공식 정책](https://docs.docker.com/engine/containers/start-containers-automatically/)을 따른다. 현재 기존 서버의147 부팅·최초 실패/복구·후속 통과와 새3VM 전체 설치 미실행은 [STATUS](../STATUS.md)에서 구분한다.

## 실행 순서와 범위

관리 controller와 gate, 진단 MCP는 같은 원본 소스에서 렌더한다. 초기 사건 DB는 run별 `report_outbox`를 함께 만들며, 기존 운영 서버의 최소 이관은 원본 SHA·유휴 상태·root 복구/DB 백업을 먼저 확인하고 빈 전달 테이블만 추가한다. 과거 사건·대화나 미전달 보고를 초기화·자동 재전송하지 않는다. 전송 실패·모델 불완료 알림과 `--no-deliver` 의미는 [진단·보고 계약](../infra/mcp/system-diagnostics.md)을 따른다. 추가 패키지·포트·자격은 필요하지 않다.

1. 입력과 검증된 SSH host key를 확인하고 서버 3대의 machine-id가 서로 다른지 확인한다.
2. 각 서버의 `/opt/capstone-prereqs/artifacts.json`과 모든 파일 해시를 검사한다. 하나라도 다르면 패키지 설치 전에 중단한다.
3. 승인된 로컬 `.deb`를 `apt-get --no-download --no-remove`로 설치하고 Docker save archive를 `docker load`한다. 지정하지 않은 추가 패키지, 다운그레이드, 기존 이미지 태그 충돌을 거절한다. SIEM의 `vm.max_map_count`가 부족한 경우 전용 설정 파일로 최소262144를 적용한다.
4. 준비된 상태에서 security·siem·service 역할을 모두 사전검사한다. 역할 충돌, 포트 충돌, 자료 누락이 있으면 서비스 설치 전에 중단한다. 이 단계의 실패 시 앞 단계에서 설치한 패키지는 유지한다.
5. SIEM을 설치·검증하고 등록 CA·암호를 두 agent 서버로 전달한다. Wazuh Dashboard의 `admin` 암호(`siem.json`의 `indexer_password`)는 SSH 파이프로 service의 root0600 파일에 직접 전달한다. Mac 파일·명령 인수·로그에는 저장하지 않는다.
6. service에 독립 DVWA/MariaDB, FastAPI 콘솔·제한된 Docker broker·nft guard, 전용 Nginx gateway, 별도 sudo rootless 환경과 Redis·Samba·sudo 웹 터미널 서비스, Wazuh agent를 구성한다. 콘솔 계정 생성과 sudo 준비 다음에 별도 nonweb bundle을 검증·반입한다.
7. security에 Suricata·기존 DVWA WAF와 별도 Log4Shell TLS 진입점을 구성한다. 관리·예외 키 인증은 콘솔에 직접 연결하고, 고정된3개 실습 경로만 WAF를 지난다. 일반 요청은 규칙에 걸릴 때 차단하며 유효한 예외 세션은 감사 로그를 유지한다.
8. SIEM의 비권한 내부 TLS8444/8445를 설치하고 공개 CA만 security에 전달·신뢰시킨 뒤 SOC를 구성한다. SIEM이 생성한 Mattermost 관리자 ID를 승인자로 고정하고 승인 브로커·정확 후보 worker·규칙 MCP·제한된 응답 MCP·Native AR 사건 전달을 구성한다. 전용 토큰은 B→A SSH 파이프로 전달하며, 승인자 암호를 MCP에 배포하지 않는다. 관리용 SSH는 고정 명령과 검증된 host key만 사용한다.
9. Vector0.59.0 정제·원본 세대 회전·출력 유지관리·이전 부트 로컬 보관을 구성하고, 실제 등록 agent ID에 결속한 Indexer 상관관측 모니터를 추가한다. 관측 모니터의 `actions`는 비어 있으며 자체 차단을 실행하지 않는다.
10. 통합 SOC 대시보드의 14개 패널을 구성한다. 기존 saved object와 내용이 충돌하면 덮어쓰지 않고 중단한다. 없는 객체만 생성하고 전체 내용을 재조회한다. 그 뒤 Hermes 관리 경로를 활성화한다.
11. 세 호스트에 고정 읽기 진단 수집기를 설치한다. root 수집기가60초마다 systemd 상태와 분류한 오류 메타데이터만 게시하고, B의 비권한 MCP는 로컬 snapshot 또는 A/C의 강제 snapshot reader를 읽는다. 새 전용 키의 공개키만 A/C로 전달하고, 기존 관리자·대응용 키는 재사용하지 않는다. SSH host key는 기존에 검증한 배포 SSH 경로로 받아 별도 known_hosts에 고정한다.
12. service/siem의 별도 host guard를 적용하고 인증된 SSH 원천을 보존한다. 기본 역할과 SOC 확장의 파일·이미지·컨테이너·서비스·승인 경계, 세 호스트 진단 snapshot·MCP 호출, 내부 TLS와 host guard를 최종 검증한다. 임시 전송 폴더를 정리한다. 실패 시 부분 설치 상태와 서버의 복구 자료를 남기고 임의 덮어쓰기·전체 삭제를 하지 않는다. 대시보드의 아직 완료되지 않은 동일 내용 생성만 제한적으로 재개할 수 있고, 다른 확장 부분 설치는 검토 없이 재시도하지 않는다.

카탈로그는 웹 실습3개와 Redis·Samba·sudo 터미널3개로 총6개다. 준비된 로컬 이미지만 사용하며 사용자가 콘솔에서 시작한 뒤 웹 화면 또는 같은 사이트의 터미널을 연다. 웹3개와 Redis/Samba는 초기 설치 중 시작하지 않는다. sudo 초기 bootstrap은 패키지·격리 검증을 위해 한 번 기동하며, 이후 중지 상태도 정상 설치로 검증한다. 터미널은 고정된 해당 실습 컨테이너에만 연결하며 호스트 셸·임의 Docker API·LLM 권한을 추가하지 않는다. sudo는 별도 UID1991 rootless 런타임을 유지하고 중앙 터미널의 고정 어댑터로만 연결한다. sudo 터미널은 전체 사용자 중 한 연결만 허용하며 연결 종료·입력 유휴/수명 만료 때 해당 sudo 컨테이너 전체를 중지한다. Redis/Samba 세션과 다른 실습은 중지하지 않는다. DVWA는 `http://SECURITY_HOST:WAF_PORT/dvwa/`, 콘솔·실습 페이지는 `LAB_PUBLIC_ORIGIN/log4shell/` 아래다. DVWA를 Log4Shell 메뉴에 다시 추가하지 않는다.

`--plan`은 로컬 입력만 확인한다. `--check`는 반입물과 역할 조건을 검사하되 패키지·이미지·서비스를 설치하지 않으므로, 아직 패키지가 없는 빈 서버에서는 누락을 보고할 수 있다. `--verify`는 이미 관리 중인 동일 구성의 검증만 수행한다. 기존 운영 GROOT 서버를 신규 설치 대상으로 인수하지 않는다.

읽기 진단은 `get_system_diagnostics` 하나만 추가한다. 대상은 소스에 고정한 A/B/C 서비스 ID이며 경로·호스트·unit명·명령을 호출자가 지정할 수 없다. 수집한 snapshot은 `/var/lib/capstone-diagnostics/snapshot.json`의 root 소유0640 파일이고 TTL은180초다. 오류 조회의 최대4시간은 상한이 있는 수집 표본이며, 원본 journal 본문·환경변수·명령행·비밀값은 MCP 응답에 넣지 않는다. 누락되거나 중지된 unit도 관찰 결과로 표시하고, 자료 만료나 검증 실패를 정상으로 간주하지 않는다. 신규 설치는 전용 계정·unit·키·receipt를 자동 구성한다. 기존 운영 서버의 이 진단 확장만 추가하는 작업은 별도 원본 SHA 확인·복구 백업·변경 검증 경로를 사용하며 전체 초기 설치기를 다시 실행하지 않는다.

A/C의 진단 SSH 계정은 공개키 인증과 고정 `read-snapshot` 실행만 허용한다. wrapper는 원격 명령·추가 인수를 거절하고 빈 환경으로 reader를 실행한다. 설치기는 `sshd -t`와 계정별 effective 정책을 확인하며, 전역 `PermitUserEnvironment no`·`UsePAM yes`가 충족되지 않으면 SSH를 reload하지 않고 중단한다. 전역 전용 지시문을 `Match` 안에 넣거나 기존 전역 인증 정책을 자동 변경하지 않는다.

## 폐쇄망 반입물

모든 자료는 해당 서버의 `/opt/capstone-prereqs` 아래 root 소유·그룹/기타 쓰기 금지 경로에 둔다. 자격 JSON·TLS 개인키·공통 예외 키는0600이다. manifest의 해시는 **관리자가 승인한 파일의 동일성**을 검증한다. 그 자체가 공급자 서명 검증을 대신하지 않는다. 외부 준비 서버에서 공식 출처·저장소 서명·버전·라이선스를 검토하고 반입 대장을 보존한다.

`artifacts.json`은 다음 형식이다. 예시는 구조 설명이며 `REVIEWED_*` 자리에 실제 검증값을 입력해야 한다. 역할마다 파일이 다르다. 배열이 비어 있으면 이미 설치된 패키지·이미지를 사용하며 역할별 버전 검증은 그대로 실행한다.

```json
{
  "schema": 1,
  "role": "service",
  "packages": [
    {"file":"example_1.0_amd64.deb", "sha256":"REVIEWED_64_HEX",
     "package":"example", "version":"1.0", "architecture":"amd64"}
  ],
  "images": [
    {"file":"java-lab.tar", "sha256":"REVIEWED_64_HEX",
     "tag":"groot-labs/log4shell:2.14.1", "image_id":"sha256:REVIEWED_64_HEX"}
  ]
}
```

파일은 manifest 옆의 평면 파일명이며 하위 경로·symlink·중복 항목을 받지 않는다. 패키지 전이 의존성도 전부 반입한다. `dpkg-deb -f FILE Package Version Architecture`, `sha256sum FILE`, `docker image inspect --format '{{.Id}}' TAG`로 확인한 값을 입력한다. 대상 서버에서 `apt update`, `pip install`, `docker pull`을 실행하지 않는다.

온라인 Linux 준비 서버의 이미지 반출 예:

```bash
# 먼저 공식/검토된 원본으로 이미지 준비 및 native amd64 확인을 완료한다.
docker image inspect --format '{{.Id}} {{.Os}} {{.Architecture}}' groot-labs/log4shell:2.14.1
docker save --output java-lab.tar groot-labs/log4shell:2.14.1
sha256sum java-lab.tar
# 오프라인 호스트의 artifacts.json에 태그·정확한 image ID·archive SHA를 기록한다.
# deploy.sh --apply가 아래와 동일한 로컬 load를 자동 수행한다.
# docker load --input /opt/capstone-prereqs/java-lab.tar
```

필수 준비 범위:

| 서버 | 패키지·이미지 외 자료 |
|---|---|
| 공통 | Ubuntu24.04 amd64·systemd·Python3.12·SSH/sudo 및 검증된 host keys. Docker Engine/CLI/Compose·관리 명령은 로컬 deb로 설치 가능 |
| SIEM | 기존 [SIEM 준비 목록](setup-packages-artifacts.md)의 Wazuh 원본 tree, `siem.json`, Python bcrypt, Wazuh/Mattermost/PostgreSQL/Hermes 이미지와 관련 소스 |
| service | Wazuh agent4.14.8, Docker29.8.1/CLI, uidmap·libsubid4·dbus-user-session·AppArmor·nftables·gpgv; DVWA/MariaDB/WAF 이미지; 아래6항목 카탈로그와3개 관리형 웹이미지; 전체 lock wheel 디렉터리; 고정 sudo bundle 및 Redis·Samba nonweb bundle |
| security | Wazuh agent4.14.8, Vector0.59.0 로컬 deb와 전이 의존성, Suricata8.0.6/WAF 이미지, jq·logrotate·util-linux·nftables, 검증한 ET Open 룰, 지정 DNS 이름의 TLS 인증서·개인키, 접속 허용 내부망/VPN CIDR |

콘솔 wheel은 [prepare-python.sh](../infra/groot-c/offline-labs/scripts/prepare-python.sh)의 Ubuntu/Python3.12 amd64용 전체 목록과 해시를 사용한다. 카탈로그는 [cve_list.json](../infra/groot-c/offline-labs/cve_list.json), 웹이미지 반출입은 [offline-labs README](../infra/groot-c/offline-labs/README.md)를 따른다. sudo는 [고정 rootless bootstrap](../infra/groot-c/offline-labs/nonweb/sudo/runtime/BOOTSTRAP.md)의 별도 서명 증빙까지 필요하다. sudo의 준비 JSON만 보고 서명 검증을 생략하지 않는다.

Redis·Samba 자료는 `LAB_NONWEB_BUNDLE`(기본 `/opt/capstone-prereqs/nonweb`)에 둔다. [nonweb 준비 안내](../infra/groot-c/nonweb-labs/README.md)의 `manifest.json`, `provenance.json`, `redis-image.tar`, `samba-image.tar` 정확4개와 이미지·archive 해시를 검증한다. 이 자료는 웹이미지 반출입 목록과 분리하며, 신규 `--check`는 계정·컨테이너·서비스를 생성하지 않는다. `--apply`는 `/opt/capstone-nonweb-labs` 관리 소스와 고정 root Unix socket 서비스를 구성하고 두 실습 컨테이너는 시작하지 않는다. 완료된 동일 구성의 재실행은 검증만 하고, 부분 설치·출처 충돌은 임의 인수하지 않는다.

service schema는 **9**다. `LOG4SHELL_IMAGE`, `LOG4SHELL_APP_JAR`, `LOG4SHELL_HOSTNAME`의 구형 직접 Java Compose 옵션을 거절한다. 현재 콘솔은 검증·반입된 이미지 ID로 실행한다. 기존 JAR 빌드 도구는 이미지 준비 용도로 보존한다. 구형 schema6·7·8 설치는 명시적인 별도 이관이 필요하며 새 설치기로 덮어쓰지 않는다. source profile과 완료 receipt는 `terminal_api.py`, 재귀적인 static 파일·로컬 xterm 자산·favicon, sudo 및 nonweb 관리 코드를 함께 검증한다.

## 검증과 운영 변경 원칙

셸 구문·컨트롤러 가상 SSH 순서·입력/반입물 위변조·역할 생성물·초기 설치 실패/재실행·고정 권한 계약을 자동 시험한다. 기존 운영 서버의 웹·HMAC·WAF canary·sudo 환경 검증과 **새 VM3대 전체 설치 검증**은 별개다. 새 설치 경로의 실제 VM 전체 적용은 아직 실행하지 않았다. 신규 VM에서 `--apply`와 허용 클라이언트 HTTPS 접속까지 통과한 이후에만 실제 설치 검증 완료로 기록한다.

SOC 연결의 설치 코드는 포함하되, 이 변경의 새 VM 설치 시험은 사용자 요청으로 제외했다. 구문·격리 회귀 통과와 실제 서비스 기동·공격 E2E 성공을 구분한다. 최초 빈 인덱스에는 최소 필드 메타데이터를 사용하므로 대시보드 생성 성공만으로 실제 탐지 데이터나 화면 렌더링까지 검증했다고 표시하지 않는다.

내부 단계·권한·부분 실패와 재실행 계약은 [SOC 관리 확장](SOC_MANAGEMENT.md)과 [로그 처리 모듈](log-pipeline.md)에 기록했다. 이번 소스와 로컬 검증 결과는 [SOC 설치기 검증 기록](soc-bootstrap-validation-20261023.json)으로 구분해 보존한다.

`LOG_PROTECTED_IPS`는 추가 보호 IPv4의 쉼표 목록이다. 세 서버와 IP로 지정한 LLM은 자동 합집합으로 포함한다. LLM을 호스트명으로 지정하면 그 서버의 승인된 실제 IP를 명시해야 하며 설치 중 DNS로 추정하지 않는다. 관리·VPN 인프라 주소도 이 목록에 포함한다. 기존 대응 정책의 비공개/예약 주소 보호를 유지하므로 내부 실습 출발지의 실제 IP 차단 허용 범위를 이 설치기가 임의로 넓히지 않는다.

관리자 차단 예외는 별도 선택 항목 `ADMIN_PROTECTED_CIDRS`다. 대화형 초기 설정에서 다음처럼 묻고, 값이 없으면 Enter로 넘어간다. 설정 파일에 빈 `ADMIN_PROTECTED_CIDRS=`를 적거나 batch 모드에서 생략해도 추가 예외 없이 진행한다.

```text
차단 예외 관리자 IPv4 또는 CIDR 대역 (쉼표 구분, 없으면 Enter): 192.168.10.25,192.168.15.0/24
관리자 IP 차단 예외: 192.168.10.25/32,192.168.15.0/24
```

단일 IP는 `/32`로, 호스트 비트가 있는 대역은 실제 네트워크 주소로 정리하고 중복·포함 범위를 합친다. 값은 서버 프로필과 nft `never_block`에 저장하고, LLM 임시 차단·관리자 승인형 IP 차단의 실행 전에도 검사한다. 관리자 대역의 탐지·원본 로그 수집은 계속 수행한다. 이 항목은 HTTPS 접속 허용망 `LAB_ALLOWED_CIDRS`나 WAF 요청 검사 예외 세션과 별개다.

운영망 FORWARD/NAT/VPN/DNS 자체, 공개 인증서 발급·채팅 HTTPS, 기존 SOC의 수동 이력·기존 승인 DB, A→B 이전 로그 전송, 긴 장애 구간의 무손실 회수·일반 백업·실제 공격 E2E는 별도 범위다. Suricata는 수동 탐지 모드를 유지하고 제한된 별도 nft 대응 경로를 사용한다. LLM에 일반 sudo/Docker·패키지 설치 권한을 부여하지 않는다.

앞으로 서버 변경을 수행하면 같은 작업에서 `deploy.sh`의 역할/helper·반입 목록·설정 예제·검증을 갱신한다. 운영 서버 재설정과 신규 설치는 구분한다. 상시 서버 감시나 소스 자동 작성 데몬은 추가하지 않는다.
