# 패키지·이미지·배포 자료 준비

> **2026-10-25 선택 반입물 추가:** Ollama 시험 옵션을 켤 때만 `/opt/capstone-prereqs/ollama-trial`에 deb3개·Linux CPython3.12 wheel70개와 정확한 [별도 manifest](../infra/ollama-trial/offline-manifest.json)를 준비한다. python3.12-venv3.12.3-1ubuntu0.17 / pip-whl24.0+dfsg-1ubuntu1.3 / setuptools-whl68.1.2-2ubuntu1.2 및 [전체 Python lock](../infra/ollama-trial/requirements.lock)을 사용한다. 이 묶음은 기존 평면 artifacts.json 목록과 구분하며 자체 설치기가 해시/추가 파일을 검증한다. [준비·적용·정리](../infra/ollama-trial/README.md). 채팅 옵션은 이 wheel 묶음에 포함된 httpx/websockets를 사용하므로 별도 바이너리가 더 필요하지 않다. 기본 설치에는 추가하지 않는다.


> **2026-10-24 응답 지연 보완:** query-completion 1.5.1의 `__init__.py`·`plugin.yaml`과 기존 공용 `grounding.py`를 소스 번들로 반입한다. 기존 deploy.sh의 확장 소스 해시 검증을 사용하며 deb/wheel/이미지 추가와 Mac 설치는 없다. 운영은 플러그인2파일 최소 교체로 반영하고 기존 공용 코드·모델·설정·승인 경계를 유지했다. [현황](../STATUS.md).

> **2026-10-24 Memory 갱신:** 추가 오프라인 바이너리는 없다. 변경된 SOUL·rule_change_executor.py·service_action_executor.py는 기존 SOC 소스 번들이 함께 반입/검증한다. 운영 Memory snapshot은 root가 현재 서버 사실을 확인해 작성하고 원본·DB 백업 후 적용하는 유지보수 자료다. 신규 VM의 이미 확인된 상태로 배포하지 않는다. [현황](../STATUS.md).

> **2026-10-24 조회 통합 반입:** 추가 deb/wheel/이미지/포트는 없다. 소스 반입에는 `infra/mcp/rule_readonly_install.py`와 변경된 공통 MCP/실행기·관리 정책/설정이 포함된다. 루트 deploy.sh의 SOC 소스 번들이 함께 해시를 검증하고, 서버에서 독립 읽기 키를 생성해 공개키만 기존 비공개 설치 스트림으로 A에 전달한다. 개인키를 Mac으로 반입하지 않는다. 기존 운영에 초기 설치기 전체를 다시 실행하지 않는다. [권한 경계](../infra/mcp/README.md).


2026-10-24 기존 서버는 외부 APT 다운로드를 사용할 수 없다. 외부 접속이 되는 준비 환경에서 공식 Ubuntu `InRelease` 서명과 `Packages`의 SHA256/크기/배포판/아키텍처를 검증하고 필요한 `.deb`와 의존성을 반입한다. Mac을 사용할 때는 기존 도구로 작업별 임시 경로에만 다운로드하고, 서버 반입·해시 확인을 마친 바이너리는 즉시 삭제한다. Mac 패키지 설치·프로젝트 내 deb/wheel/캐시 보관은 하지 않는다. 작업 종료 시 이번 helper·임시 파일도 제거하며 소스·검증 기록과 서버의 운영 복구 백업은 보존한다.

호스트 최소 기준은 sudo `1.9.15p5-3ubuntu5.24.04.4`이며 SIEM의 내부 TLS에는 nginx `1.24.0-2ubuntu7.18` 이상과 전이 의존성을 반입한다. 취약한 rootless sudo 실습 bundle과 호스트 패키지는 별개다. 설치기는 검증한 파일을 전용 임시 APT 캐시에 공식 파일명(epoch는 `%3a`)으로 배치한 뒤 빈 저장소 목록과 `--no-download --no-remove`로 설치하며 성공·실패 모두 캐시를 지운다. 임의 이름의 로컬 deb에 `--no-download`만 붙이면 실제 APT에서 경로 오류가 날 수 있어 이 단계가 필요하다. 온라인 `apt-get update/install`, 미검증 다운로드나 의존성 자동 반입으로 대체하지 않는다.

호스트 sudo는 `1.9.15p5-3ubuntu5.24.04.4` 이상을 준비한다(2026-10-24 보안 기준). Ubuntu 공식 서명/Packages SHA 검증을 마친 반입물 또는 그 이상의 설치 패키지가 필요하며, 초기 설치기는 이전 호스트 버전/반입물을 거절한다. rootless sudo 실습의 별도 고정 취약 bundle은 호스트 패키지와 구분해 유지한다.

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 사용자 진입점은 루트 deploy.sh 하나이고 service schema9·HTTP3/터미널3·MCP6서버/고정 진단을 연결한다. 새3VM 전체 설치 시험은 사용자 제외 범위를 유지하며 기존 운영 서버를 초기 설치기로 덮어쓰지 않는다. 이번 운영 보완은 별도 최소 이관이다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

현재 기본 설치 경로는 [단일 Bash 초기 설치](bootstrap-guide.md)다. `deploy.sh --apply`가 각 서버의 승인된 `artifacts.json`에 따라 로컬 deb와 Docker archive를 설치한다. 아래 온라인 명령은 **외부 Linux 준비 환경에서 반입 자료를 만들거나 관리자가 사전에 설치할 때의 참고 절차**이며 폐쇄망 설치기가 실행하는 다운로드 명령이 아니다. Mac에는 패키지·JDK·Docker Desktop·가상환경을 설치하지 않는다.

Log4Shell은 schema7부터 현재 콘솔과 검증된3개 웹이미지를 사용하며, schema8에서 Redis·Samba 터미널2종을 추가했고, 현재 schema9는 sudo까지 웹 터미널로 연결한6항목(웹3·터미널3) 카탈로그다. 아래 구형 Java 직접Compose/JAR 자동 빌드 설명은 과거 schema6 준비 절차이며 신규 기본 경로가 아니다. 기존 빌드 도구는 Java 이미지 준비에 사용할 수 있다. sudo 고정 rootless bundle·별도 Redis/Samba nonweb bundle·wheel·TLS 자료도 새 가이드에 따라 반입한다. sudo 웹 터미널 연결에는 기존 sudo 이미지·서명 bundle을 그대로 사용하고 중앙 nonweb 소스의 고정 어댑터를 함께 반입한다. 추가 패키지·이미지나 새 설정 키는 없다.

2026-10-23 SOC 확장에는 security 서버의 **Vector0.59.0과 Suricata8.0.6**이 필요하다. Vector 공식 Linux amd64 deb 및 전이 의존성의 출처·서명을 외부 Linux 준비 환경에서 검토하고, 해당 파일의 실제 Package/Version/Architecture/SHA를 security `artifacts.json`의 `packages`에 넣는다. 배포 revision을 추정해 기록하지 않는다. 기존 공통 준비 목록의 jq·logrotate·coreutils·util-linux·nftables·OpenSSH·systemd도 필요하다. 새 SOC helper와 대시보드 import는 Python 표준 라이브러리이며 별도 wheel을 요구하지 않는다. 준비 파일이 없으면 사전검사에서 중단하고 온라인 설치로 대체하지 않는다. 이 확장의 새 VM 설치 시험은 제외했다.

다음 순서로 진행한다. SSH·고정 주소·라우팅을 먼저 준비하고, 이 문서의 자료 준비를 마친 뒤 `deploy.sh --check`를 실행한다. 예시의 `192.0.2.x`는 실제 배포 주소로 변경한다. 각 코드 블록의 실행 위치를 확인하고 **명령이 실패하면 다음 단계로 넘어가지 않는다.** 운영 중인 서버의 패키지나 agent 등록 정보를 삭제해서 신규 조건에 맞추지 않는다.

| 실행 위치 | 준비할 내용 |
|---|---|
| 세 대상 서버 모두 | 공통 명령, Docker Engine·Compose, 시간대 |
| security·service | 미등록 Wazuh agent 4.14.8 |
| security | Suricata·WAF 이미지, 검증한 ET/Open 룰 |
| service | DVWA·MariaDB·고정 digest Java 이미지, Apache proxy/proxy_http와 DVWA mysqli 확인. 새 앱 JAR은 기본 자동 빌드, 준비 JAR 지정도 가능 |
| siem | bcrypt·커널 설정, Wazuh·Mattermost·PostgreSQL 이미지, Wazuh 원본, 읽기 MCP, 준비된 Hermes 이미지, `siem.json` |

이 문서 작성 시 공식 설치 문서·공개 릴리스 메타데이터와 저장소 스크립트를 대조했다. 실제 패키지 설치, 바이너리 다운로드, 이미지 빌드 및 새 VM 구축은 수행하지 않았다. 아래에 명시한 SHA는 확인한 공개 배포 자료의 값이며 운영 비밀 값이 아니다.

## 1. 세 서버 공통 패키지 준비

OS·아키텍처 조회는 각 대상 서버에서 수행한다. 아래 `apt-get update/install`은 같은 Ubuntu24.04 amd64의 **외부 Linux 준비 환경에서만** 실행하는 준비 예시다. 운영 서버에서는 실행하지 않고 검증한 deb/의존성을 `artifacts.json`과 함께 반입해 `deploy.sh`의 오프라인 경로로 설치한다. Ubuntu 24.04의 코드명은 `noble`, Debian 패키지 아키텍처는 `amd64`여야 한다.

```bash
set -euo pipefail
. /etc/os-release
test "$ID" = ubuntu
test "$VERSION_ID" = 24.04
test "$(dpkg --print-architecture)" = amd64
test "$(uname -m)" = x86_64

sudo apt-get update
sudo apt-get install -y openssh-server openssh-client sudo ca-certificates \
  curl gnupg openssl jq python3 python3-venv \
  coreutils findutils gawk grep sed util-linux iproute2 procps tar gzip \
  rsync logrotate nftables iptables
sudo systemctl enable --now ssh
sudo timedatectl set-timezone Asia/Seoul
timedatectl status
```

`getent`·`useradd`·`runuser`·`flock` 등의 Ubuntu 기본 관리 명령도 필요하다. 설치기는 누락된 명령을 감지하면 중단한다. 시간대 변경과 시간 동기화는 별개다. `timedatectl`의 동기화 상태가 정상인지 확인하고, 폐쇄망이면 허용된 내부 NTP를 사용한다. 이 명령은 기존 방화벽 정책을 초기화하거나 SSH 접근을 일괄 개방하지 않는다.

Wazuh 원본을 가져오는 외부 Linux 준비 환경에만 `git`이 필요하다. 원본을 반입하는 SIEM에 Git은 필수 조건이 아니다. 아래 설치도 준비 환경용이다.

```bash
sudo apt-get install -y git
```

## 2. Docker 공식 apt 저장소와 Engine·Compose

대상 서버에서는 기존 Docker·containerd 상태만 조회한다. 저장소 등록·curl·APT 다운로드/설치 명령은 외부 Linux 준비 환경용이며, 대상에는 검증한 Docker deb/전이 의존성을 반입한다. 기존 Docker·containerd가 운영 중이면 이 신규 구축 절차를 중지한다. 아래 조회 결과에 기존 컨테이너용 패키지가 나오면 무조건 제거하지 말고 새 VM인지 확인한다.

```bash
dpkg-query -W -f='${Package} ${Version}\n' \
  docker.io docker-compose docker-compose-v2 docker-doc docker-buildx \
  podman-docker containerd runc 2>/dev/null || true
```

외부 Linux 준비 환경에 공식 apt 서명 키와 저장소를 등록한다. 설치된 운영 서버에 이 다운로드 경로를 추가하지 않는다. `/etc/apt/keyrings/docker.asc` 또는 `docker.sources`가 이미 있으면 내용을 비교하고 기존 파일을 덮어쓰지 않는다. 아래 `test`는 중복 준비를 의도적으로 거절한다. [Docker의 Ubuntu 설치 문서](https://docs.docker.com/engine/install/ubuntu/)를 기준으로 작성했다.

```bash
set -euo pipefail
test ! -e /etc/apt/keyrings/docker.asc
test ! -e /etc/apt/sources.list.d/docker.sources
sudo install -d -m 0755 /etc/apt/keyrings
sudo curl --fail --show-error --silent --location \
  https://download.docker.com/linux/ubuntu/gpg \
  --output /etc/apt/keyrings/docker.asc
sudo chmod 0644 /etc/apt/keyrings/docker.asc

sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<'EOF'
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: noble
Components: stable
Architectures: amd64
Signed-By: /etc/apt/keyrings/docker.asc
EOF
sudo apt-get update
apt-cache madison docker-ce
```

표시된 `docker-ce` 버전 중 검토한 **전체 버전 문자열**을 입력한다. Engine·CLI는 같은 버전으로 설치하고, 나머지 패키지의 실제 설치 버전도 기록한다. 이 문서는 변동하는 최신 Docker 버전 번호를 고정값처럼 제시하지 않는다.

```bash
read -r -p '설치할 docker-ce 전체 버전: ' docker_version
test -n "$docker_version"
apt-cache madison docker-ce | awk '{print $3}' | grep -Fx -- "$docker_version"
sudo apt-get install -y "docker-ce=$docker_version" "docker-ce-cli=$docker_version" \
  containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker info --format '{{.OSType}}'
sudo docker compose version
dpkg-query -W -f='${Package}\t${Version}\n' \
  docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
unset docker_version
```

정상 결과는 Docker OS `linux`와 Compose plugin 버전이다. `docker info`가 실패하면 서비스 로그·디스크·권한부터 확인한다. 배포 계정 또는 LLM 계정을 `docker` 그룹에 추가할 필요는 없다. 배포는 준비된 관리자 `sudo`를 사용하고 Hermes는 일반 Docker 권한을 받지 않는다.

폐쇄망에서는 공식 저장소를 사용할 수 있는 **동일 Ubuntu 24.04 amd64 준비 환경**에서 Docker와 전이 의존성의 `.deb`를 확보한다. [Docker의 수동 패키지 설치 절차](https://docs.docker.com/engine/install/ubuntu/#install-from-a-package)처럼 `containerd.io`, `docker-ce`, `docker-ce-cli`, `docker-buildx-plugin`, `docker-compose-plugin`을 함께 반입한다. APT의 서명 검증을 우회하거나 누락 의존성을 `--force`로 무시하지 않는다. 반입 전후 SHA-256을 대조하고 대상 서버에서 `sudo apt-get --no-download install /절대경로/*.deb`로 로컬 파일만 설치한다. 설치 실패 시 필요한 의존성을 준비 환경에서 추가 확보한다.

Docker 게시 포트는 일반 host INPUT/UFW 규칙과 경로가 다를 수 있다. 접근 제한은 [네트워크 준비 절차](setup-network-ssh.md)와 실제 패킷 경로를 대조한다. 이 프로젝트의 기본 nft 테이블은 접근 차단 정책 전체를 제공하지 않는다.

## 3. security·service의 Wazuh agent 4.14.8

SIEM에는 이 agent를 설치하지 않는다. security와 service에서 기존 등록 여부를 먼저 확인한다. 다음 조건이 실패하면 기존 agent를 삭제하거나 `client.keys`를 비워서 진행하지 않는다.

```bash
set -euo pipefail
test ! -e /var/ossec
sudo install -d -m 0755 /etc/apt/keyrings
test ! -e /etc/apt/keyrings/wazuh.asc
test ! -e /etc/apt/sources.list.d/wazuh.list
sudo curl --fail --show-error --silent --location \
  https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  --output /etc/apt/keyrings/wazuh.asc
sudo chmod 0644 /etc/apt/keyrings/wazuh.asc
printf '%s\n' \
  'deb [arch=amd64 signed-by=/etc/apt/keyrings/wazuh.asc] https://packages.wazuh.com/4.x/apt/ stable main' \
  | sudo tee /etc/apt/sources.list.d/wazuh.list >/dev/null
sudo apt-get update
apt-cache madison wazuh-agent

wazuh_version=$(apt-cache madison wazuh-agent | awk '$3 ~ /^4\.14\.8-/ {print $3; exit}')
test -n "$wazuh_version"
printf '선택한 Wazuh agent 버전: %s\n' "$wazuh_version"
sudo env -u WAZUH_MANAGER -u WAZUH_REGISTRATION_SERVER \
  -u WAZUH_REGISTRATION_PASSWORD -u WAZUH_AGENT_NAME -u WAZUH_AGENT_GROUP \
  apt-get install -y "wazuh-agent=$wazuh_version"
sudo systemctl disable --now wazuh-agent
sudo apt-mark hold wazuh-agent
test "$(dpkg-query -W -f='${Version}' wazuh-agent)" = "$wazuh_version"
sudo test ! -s /var/ossec/etc/client.keys
sudo /var/ossec/bin/wazuh-control info
unset wazuh_version
```

공식 문서는 등록 변수 없이 설치하면 미등록 agent를 준비할 수 있다고 설명한다. 여기서는 manager 주소와 등록 암호를 아직 지정하지 않는다. 실제 `deploy.sh`가 SIEM 구성 후 새 CA·등록 암호·agent 이름을 넣고 등록한다. agent는 **중지하되 mask하지 않는다.** mask 상태이면 배포 시 시작할 수 없다. 패키지 hold는 manager 4.14.8과의 버전 불일치를 방지하기 위한 것이며, 이후 보안 업데이트는 검토 후 manager와 함께 계획한다. [Wazuh Linux agent 설치·업데이트 관리](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html)

`4.14.8-*`가 저장소에 없으면 다른 최신 버전을 대신 설치하지 않는다. 공식 패키지 목록에서 4.14.8 amd64와 배포자의 checksum을 확보하거나 검증한 내부 패키지 저장소를 사용한다. `apt-cache`의 revision을 확인하므로 문서에서 확인하지 않은 `-1` 등의 revision을 가정하지 않는다.

## 4. SIEM의 bcrypt와 커널 설정

```bash
set -euo pipefail
sudo apt-get install -y python3-bcrypt
python3 -B -c 'import bcrypt; print("bcrypt import OK")'
if [ "$(sysctl -n vm.max_map_count)" -lt 262144 ]; then
  sudo test ! -e /etc/sysctl.d/99-capstone-wazuh.conf
  sudo test ! -L /etc/sysctl.d/99-capstone-wazuh.conf
  printf '%s\n' 'vm.max_map_count=262144' \
    | sudo tee /etc/sysctl.d/99-capstone-wazuh.conf >/dev/null
  sudo sysctl -p /etc/sysctl.d/99-capstone-wazuh.conf
fi
test "$(sysctl -n vm.max_map_count)" -ge 262144
```

`99-capstone-wazuh.conf`가 이미 있으면 기존 값을 먼저 검토한다. 다른 sysctl 파일이 더 큰 값을 요구하면 낮추지 않고 그 설정을 유지한다. `bcrypt`는 새 Indexer 암호 해시를 만들 때 사용한다. [Wazuh Docker 요구사항](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)에 맞춰 커널 값을 준비하며, 이 단계에서 Compose를 기동하지 않는다.

## 5. 역할별 이미지 수동 확보와 확인

먼저 각 대상 서버에서 사전 자료·증거 경로를 만든다. `/opt/capstone-prereqs`는 root 소유이고 symlink가 아니어야 한다. 기존 자료를 덮어쓰지 않는다.

```bash
sudo install -d -o root -g root -m 0700 /opt/capstone-prereqs
sudo install -d -o root -g root -m 0700 /opt/capstone-prereqs/evidence
sudo stat -c '%U:%G %a %n' /opt/capstone-prereqs
```

아래 다운로드 명령은 해당 역할의 반입물을 만드는 외부 Linux 준비 환경에서 실행하고, 대상 서버에는 `docker save` 산출물을 반입한다. Mac에 Docker·준비 도구를 설치하지 않는다. 태그를 받은 뒤 **같은 작업 도중 다시 pull하지 않는다.** `latest`·`nginx`·`10` 같은 태그는 시간이 지나면 바뀐다. 최초 준비의 image ID와 RepoDigest를 기록하고, 이후 동일 바이트를 복원하려면 검증한 digest 또는 저장한 image archive를 사용한다. 역할 스크립트는 최초 로컬 ID를 기록하고 변경 시 재검증을 거절한다.

```bash
# security에서만
sudo docker pull --platform linux/amd64 jasonish/suricata:latest
sudo docker pull --platform linux/amd64 owasp/modsecurity-crs:nginx

# service에서만
sudo docker pull --platform linux/amd64 ghcr.io/digininja/dvwa:latest
sudo docker pull --platform linux/amd64 mariadb:10
sudo docker pull --platform linux/amd64 ghcr.io/christophetd/log4shell-vulnerable-app@sha256:6f88430688108e512f7405ac3c73d47f5c370780b94182854ea2cddc6bd59929

# siem에서만
sudo docker pull --platform linux/amd64 wazuh/wazuh-manager:4.14.8
sudo docker pull --platform linux/amd64 wazuh/wazuh-indexer:4.14.8
sudo docker pull --platform linux/amd64 wazuh/wazuh-dashboard:4.14.8
sudo docker pull --platform linux/amd64 postgres:16-alpine
sudo docker pull --platform linux/amd64 mattermost/mattermost-team-edition:11.11.1
```

이미지 이름은 역할 스크립트와 [Suricata 이미지 배포자](https://github.com/jasonish/docker-suricata), [CRS 컨테이너](https://github.com/coreruleset/modsecurity-crs-docker), [DVWA 공식 Compose](https://github.com/digininja/DVWA/blob/master/compose.yml)에 대조한다. SIEM의 다섯 이미지 참조는 현재 스크립트의 고정 계약이다. Hermes는 아래 별도 절차로 준비한다.

각 서버에서 역할 값을 지정해 필요한 이미지의 OS·아키텍처를 검사하고 비밀이 없는 메타데이터만 저장한다. 아래 service 목록은 온라인 준비의 기본 digest를 사용한다. 오프라인 반입 후 `LOG4SHELL_IMAGE`를 로컬 image ID로 재정의했다면 목록의 마지막 Log4Shell 참조도 같은 검토된 `sha256:…` 값으로 바꾼다.

```bash
set -euo pipefail
read -r -p '현재 서버 역할(security/siem/service): ' image_role
case "$image_role" in
  security) images=(jasonish/suricata:latest owasp/modsecurity-crs:nginx) ;;
  service) images=(ghcr.io/digininja/dvwa:latest mariadb:10 \
    ghcr.io/christophetd/log4shell-vulnerable-app@sha256:6f88430688108e512f7405ac3c73d47f5c370780b94182854ea2cddc6bd59929) ;;
  siem) images=(wazuh/wazuh-manager:4.14.8 wazuh/wazuh-indexer:4.14.8 \
    wazuh/wazuh-dashboard:4.14.8 postgres:16-alpine \
    mattermost/mattermost-team-edition:11.11.1) ;;
  *) exit 1 ;;
esac
for ref in "${images[@]}"; do
  test "$(sudo docker image inspect --format '{{.Os}}/{{.Architecture}}' "$ref")" = linux/amd64
done
sudo docker image inspect "${images[@]}" \
  | jq '[.[] | {Id, RepoTags, RepoDigests, Os, Architecture}]' \
  | sudo tee /opt/capstone-prereqs/evidence/images.json >/dev/null
sudo chmod 0600 /opt/capstone-prereqs/evidence/images.json
unset image_role ref images
```

컨테이너의 `docker inspect` 전체 출력에는 환경변수 비밀 값이 포함될 수 있으므로 운영 증거 수집에 통째로 사용하지 않는다. 위 명령은 **이미지**의 지정 필드만 기록한다.

### service의 Spring Boot Log4Shell 준비

위 공식 digest 이미지는 검토된 **Java 빌드·실행 환경**으로 유지한다. 기본 설정 `LOG4SHELL_APP_JAR=` 또는 키 생략은 자동 빌드다. controller가 [새 앱 소스](../infra/groot-c/log4shell-app/README.md)와 빌드 도구를 service 서버에 전달하고, service 적용 단계에서 로컬 이미지의 JDK와 기존 Boot JAR의 라이브러리·loader를 사용해 새 앱을 컴파일·패키징한다. Gradle·JDK의 호스트 설치나 네트워크 의존성 다운로드는 필요하지 않다. 기존 이미지 앱 자체를 실행하지 않으며, 검증한 새 JAR을 `/app/spring-boot-application.jar`에 읽기 전용으로 마운트한다.

`--check`는 소스·빌더 지문과 필수 파일, 로컬 이미지 존재 등 사전 조건만 검사한다. 이미지 안에서 실제 컴파일하는 단계는 SIEM 구성 이후 service `--apply`에 있다. 빌드 실패 시 후속 service/security 설치를 중단하지만 완료된 SIEM을 지우지 않는다. 기존 `LOG4SHELL_IMAGE`를 다른 고정 이미지로 바꾸면 자동 빌드에 필요한 `javac 1.8.0_181`·Boot2.6.1·Log4j2.14.1 라이브러리도 있어야 한다. 새 VM 3대 전체 설치 성공은 로컬 회귀나 기존 C 단독 검증과 별도로 확인해야 한다.

**선택: 사전에 빌드한 JAR 사용.** 기존 JDK·Gradle이 있는 승인된 Linux 준비 서버에서 앱 README의 Java 대상 버전과 고정 의존성으로 `bootJar`를 만들 수 있다. 소스 commit·JAR SHA·실제 Log4j API/core 버전·빌드 도구 버전을 기록하고, 작업용 빌드 산출물·의존성 캐시는 검증·반입 후 정리한다. 검토한 JAR을 service의 작업용 임시 경로로 전달하고 기록한 SHA와 대조한 뒤 아래처럼 배치한다. 아래 경로는 실제 서버 경로로 바꾸며 기존 파일을 임의로 덮어쓰지 않는다. 이 절차는 기본 자동 모드에서는 필요 없다.

```bash
# service 서버: 파일 출처와 반입 SHA를 먼저 대조한 뒤 수행
set -euo pipefail
test ! -e /opt/capstone-prereqs/log4shell-app.jar
sudo install -o root -g root -m 0644 /검증한-JAR-절대경로 /opt/capstone-prereqs/log4shell-app.jar
sudo sha256sum /opt/capstone-prereqs/log4shell-app.jar
```

이 방식을 선택했을 때만 관리 컴퓨터의 `deployment/site.local.conf`에 `LOG4SHELL_APP_JAR=/opt/capstone-prereqs/log4shell-app.jar` 또는 준비한 다른 `/opt/…jar` 절대 경로를 지정한다. 파일은 service 서버의 root 소유·그룹/기타 쓰기 금지 일반 파일이어야 한다. 자동·준비 JAR 모드 모두 ZIP 내부의 새 `MainController`·앱 main class·정적 `index.html/app.js/app.css`, Spring Boot launcher, Log4j API/core 각각의 `2.14.1` 라이브러리 이름·내부 Maven metadata·필수 클래스를 확인한다. 이 정적 검사는 클래스의 모든 동작이나 취약점 악용 성공을 입증하지 않는다. schema6에 빌드 모드·소스/빌더 지문과 결과 JAR 해시를 보존하고 복사 전후·재검증에 대조한다.

DVWA 이미지는 여전히 자체 PHP와 mysqli를 사용하지만 Log4Shell 중계용 PHP8.1/curl/session 조건은 제거됐다. Apache의 `mod_proxy.so`·`mod_proxy_http.so`를 갖춰야 한다. **service 또는 Linux 준비 서버**에서 이미 반입한 이미지만 사용해 확인한다.

```bash
set -euo pipefail
dvwa_id=$(sudo docker image inspect --format '{{.Id}}' ghcr.io/digininja/dvwa:latest)
sudo docker run --rm --pull never --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges --entrypoint sh "$dvwa_id" \
  -c 'test -r /usr/lib/apache2/modules/mod_proxy.so && test -r /usr/lib/apache2/modules/mod_proxy_http.so && php -m | grep -qx mysqli'
unset dvwa_id
```

실패하면 Linux 준비 환경에서 검토된 DVWA 이미지를 준비한다. 설치기가 실행 중 apt/pip/pull/build로 보충하지 않는다. service 역할은 같은 격리 검사를 첫 apply 전에 수행한다.

새 앱은 `internal: true`인 `lab` Docker 네트워크에만 연결하고 호스트 포트는 게시하지 않는다. `SERVER_ADDRESS=0.0.0.0`, `SERVER_PORT=8080`, context path `/log4shell`, `LOGGING_CONFIG=classpath:log4j2-spring.xml`, nonroot·읽기 전용 루트·리소스 제한을 고정한다. Compose가 Java entrypoint·JAR 인자·작업 디렉터리 `/app`도 명시하므로 이미지의 기본 명령을 실행하지 않는다. JAR의 long bind는 읽기 전용이며 `create_host_path: false`이므로 재생성 시 소스 JAR이 누락되면 중단한다. Apache가 기존 웹 포트의 `/log4shell/`를 내부 앱에 그대로 전달하므로 외부8080이나 PHP 웹 파일·세션 상태 경로를 만들지 않는다. 설치 검증은 실제 런타임 API/core `2.14.1`과 무해한 파라미터 로깅만 확인한다. 공격 재현·LDAP 콜백·탐지 E2E는 별도 실험이다.

### 오프라인 이미지 반입

인터넷이 가능한 Linux 준비 서버에서 필요한 역할 이미지를 pull하고 위와 같은 metadata를 보존한다. 다음 예시는 security 두 이미지이며 SIEM·service는 해당 목록으로 바꾼다. [Docker save](https://docs.docker.com/reference/cli/docker/image/save/)와 [Docker load](https://docs.docker.com/reference/cli/docker/image/load/)는 컨테이너 볼륨·운영 데이터를 옮기는 명령이 아니다.

```bash
# Linux 준비 서버
set -euo pipefail
umask 077
image_work=$(mktemp -d /var/tmp/capstone-images.XXXXXXXX)
sudo docker image save jasonish/suricata:latest owasp/modsecurity-crs:nginx \
  > "$image_work/security-images.tar"
sha256sum "$image_work/security-images.tar"
```

출력한 SHA-256을 대상 운영자가 신뢰할 수 있는 별도 기록으로 전달한다. 확인한 SSH host key를 사용하는 직접 `scp` 또는 승인된 내부 반입 경로로 파일을 옮긴다. Mac을 중간 저장소로 사용할 필요는 없다. 대상에서는 새 임시폴더를 만들고 파일을 넣은 뒤, 신뢰한 기록의 SHA와 먼저 비교한다.

```bash
# security 대상 서버: archive를 아래 임시폴더에 반입한 다음 계속
set -euo pipefail
umask 077
image_in=$(mktemp -d /var/tmp/capstone-image-in.XXXXXXXX)
printf '반입할 대상 임시폴더: %s\n' "$image_in"
# 아래 설명의 scp로 security-images.tar를 이 폴더에 반입한 뒤 계속한다.
read -r -p '별도로 확인한 security-images.tar SHA-256: ' expected_archive_sha
[[ $expected_archive_sha =~ ^[0-9a-f]{64}$ ]]
printf '%s  %s\n' "$expected_archive_sha" "$image_in/security-images.tar" | sha256sum -c -
sudo docker image load --input "$image_in/security-images.tar"
sudo docker image inspect jasonish/suricata:latest owasp/modsecurity-crs:nginx \
  | jq '[.[] | {Id, RepoTags, RepoDigests, Os, Architecture}]'
```

준비 서버의 별도 터미널에서 다음과 같이 전송한다. `target_dir`에는 위에서 출력된 정확한 경로를 입력한다. 비밀 값이 없는 경로이며 SSH 사용자·주소는 실제 값으로 바꾼다. 키 준비와 host key 대조는 [SSH 준비 절차](setup-network-ssh.md)를 먼저 마친 상태여야 한다.

```bash
# Linux 준비 서버: 앞서 image_work를 만든 같은 셸
read -r -p '대상에서 출력한 반입 임시폴더: ' target_dir
[[ $target_dir =~ ^/var/tmp/capstone-image-in\.[A-Za-z0-9]{8}$ ]]
scp -o BatchMode=yes -o StrictHostKeyChecking=yes \
  "$image_work/security-images.tar" "ubuntu@192.0.2.10:$target_dir/"
unset target_dir
```

load 후의 image ID와 `linux/amd64`가 준비 서버 기록과 같아야 한다. archive의 자체 계산 SHA만 일치하는 것은 배포자의 출처 인증을 대신하지 않는다. 준비 서버에서 원본 출처를 확인하고, 반입 양쪽에서 바이트 동일성을 추가로 확인하는 것이다. 성공 증거 보존 후 양쪽의 이번 archive와 임시폴더를 마지막 정리 절차로 삭제한다. 사용 중인 Docker 이미지·볼륨·기존 cache를 `prune`하지 않는다.

Log4Shell을 오프라인 반입하면 Docker `save/load` 후 원래 `RepoDigests` 참조가 복원되지 않을 수 있다. 이 경우 준비 서버에서 **공식 digest로 받은 image ID를 기록**하고 archive 전송용 로컬 태그를 붙여 보존한다. 이 태그는 `save/load`의 식별 용도이며 `LOG4SHELL_IMAGE` 입력에는 사용할 수 없다.

```bash
# Linux 준비 서버: 위 공식 digest 이미지가 이미 준비된 상태
set -euo pipefail
umask 077
lab_ref=ghcr.io/christophetd/log4shell-vulnerable-app@sha256:6f88430688108e512f7405ac3c73d47f5c370780b94182854ea2cddc6bd59929
lab_id=$(sudo docker image inspect --format '{{.Id}}' "$lab_ref")
test -z "$(sudo docker image ls --quiet capstone-log4shell:reviewed-20261015)"
sudo docker image tag "$lab_id" capstone-log4shell:reviewed-20261015
lab_work=$(mktemp -d /var/tmp/capstone-lab-image.XXXXXXXX)
sudo docker image save capstone-log4shell:reviewed-20261015 > "$lab_work/log4shell-image.tar"
printf 'reviewed image ID: %s\n' "$lab_id"
sha256sum "$lab_work/log4shell-image.tar"
```

앞의 검증된 SSH 전송·archive SHA 대조 순서로 service에 전달하고 `docker image load --input 실제반입경로/log4shell-image.tar`를 수동 실행한다. 이어서 다음 조회의 image ID가 준비 서버에서 별도 기록한 값과 같은지 확인한다.

```bash
# service 대상 서버
set -euo pipefail
read -r -p '준비 서버에서 별도로 확인한 Log4Shell image ID(sha256:...): ' expected_lab_id
[[ $expected_lab_id =~ ^sha256:[0-9a-f]{64}$ ]]
lab_loaded_id=$(sudo docker image inspect --format '{{.Id}}' capstone-log4shell:reviewed-20261015)
test "$lab_loaded_id" = "$expected_lab_id"
test "$(sudo docker image inspect --format '{{.Os}}/{{.Architecture}}' "$lab_loaded_id")" = linux/amd64
printf 'LOG4SHELL_IMAGE=%s\n' "$lab_loaded_id"
unset expected_lab_id lab_loaded_id
```

동일성을 확인한 뒤 출력된 `LOG4SHELL_IMAGE=sha256:…` 한 줄을 관리 컴퓨터의 `deployment/site.local.conf`에 넣는다. 설치기가 허용하는 참조는 repository digest 또는 로컬 image ID뿐이며 태그 입력은 `log4shell_digest_or_image_id_required`로 거절한다. 기본 digest 참조가 존재하는 경우에는 재정의가 필요 없다. 설치기는 실제 로컬 image ID를 저장한다. archive 검증·반입 후 양쪽 작업 폴더의 이번 archive를 삭제하고, 준비 서버의 `lab_work`도 아래 정리 기준에 맞춰 제거한다. 운영 이미지와 metadata 증거는 보존한다.

## 6. security용 ET/Open 룰 생성·검증

이 예시는 **인터넷 연결이 가능한 security 또는 Linux 준비 서버**에서, 배포에 사용할 것과 동일한 Suricata image ID로 수행한다. 호스트에 `suricata-update`나 Python 패키지를 추가 설치하지 않고 준비된 이미지 안의 updater를 수동 사용한다. [Suricata 룰 관리 문서](https://docs.suricata.io/en/suricata-8.0.6/rule-management/suricata-update.html)와 [updater 옵션](https://suricata-update.readthedocs.io/en/1.3.3/update.html)을 기준으로 한다. `--no-reload`는 현재 엔진의 룰 reload를 막으며, 구문 검사를 생략하는 옵션은 사용하지 않는다.

```bash
set -euo pipefail
umask 077
et_work=$(mktemp -d /var/tmp/capstone-et.XXXXXXXX)
mkdir "$et_work/config" "$et_work/data" "$et_work/output" "$et_work/logs"
suri_id=$(sudo docker image inspect --format '{{.Id}}' jasonish/suricata:latest)
test "$(sudo docker image inspect --format '{{.Os}}/{{.Architecture}}' "$suri_id")" = linux/amd64

# 이미지의 기본 설정만 새 빈 임시폴더로 초기화한다. 트래픽 캡처는 하지 않는다.
sudo docker run --rm --pull=never --network=none \
  --mount "type=bind,src=$et_work/config,dst=/etc/suricata" \
  --mount "type=bind,src=$et_work/data,dst=/var/lib/suricata" \
  --mount "type=bind,src=$et_work/logs,dst=/var/log/suricata" \
  "$suri_id" -V | tee "$et_work/engine-version.txt"
printf '{}\n' > "$et_work/output/update.yaml"
touch "$et_work/output/empty.conf"

# 외부 통신은 공개 ET/Open 룰 다운로드에만 필요하다.
# 운영 .env·로그·설정·등록 키는 어떤 mount에도 넣지 않는다.
sudo docker run --rm --pull=never --user 0:0 --entrypoint suricata-update \
  --env PYTHONDONTWRITEBYTECODE=1 \
  --mount "type=bind,src=$et_work/config,dst=/etc/suricata,readonly" \
  --mount "type=bind,src=$et_work/data,dst=/var/lib/suricata" \
  --mount "type=bind,src=$et_work/output,dst=/prepared" \
  --mount "type=bind,src=$et_work/logs,dst=/var/log/suricata" \
  "$suri_id" --config /prepared/update.yaml --data-dir /var/lib/suricata \
  --suricata-conf /etc/suricata/suricata.yaml --output /prepared \
  --disable-conf /prepared/empty.conf --enable-conf /prepared/empty.conf \
  --modify-conf /prepared/empty.conf --drop-conf /prepared/empty.conf \
  --etopen --no-reload 2>&1 | tee "$et_work/update.log"
sudo test -s "$et_work/output/suricata.rules"
```

빈 data/config와 명시한 빈 필터를 사용하므로 기존 운영 예외를 가져오지 않는다. 이미지에 updater가 없거나 옵션이 맞지 않으면 중단하고 해당 image의 버전을 검토한다. 빌드나 런타임 설치로 즉석 보충하지 않는다. ET 출력은 받는 날짜와 엔진 버전에 따라 달라지므로 임의의 고정 checksum을 문서에 기재하지 않는다.

동일 image ID로 오프라인 구문 검사를 한 번 더 하고, 예약 SID 충돌·빈 파일·바이너리 혼입을 확인한다.

```bash
sudo docker run --rm --pull=never --network=none --read-only \
  --tmpfs /tmp --tmpfs /etc/suricata --tmpfs /var/log/suricata --tmpfs /var/run \
  --mount "type=bind,src=$et_work/output,dst=/rules,readonly" \
  "$suri_id" -T -c /etc/suricata/suricata.yaml -S /rules/suricata.rules \
  -l /var/log/suricata 2>&1 | tee "$et_work/native-test.log"
sudo python3 -B - "$et_work/output/suricata.rules" <<'PY'
import pathlib,re,sys
p=pathlib.Path(sys.argv[1]); b=p.read_bytes()
assert 0<len(b)<=100000000 and b'\0' not in b
b.decode('utf-8')
active=b'\n'.join(x for x in b.splitlines() if not x.lstrip().startswith(b'#'))
assert re.search(rb'\bsid\s*:\s*[0-9]+\s*;',active)
assert not re.search(rb'\bsid\s*:\s*10000[0-9]{2}\s*;',active)
print('ET input and reserved SID checks passed')
PY
sudo sha256sum "$et_work/output/suricata.rules"
```

security에서 직접 준비했다면 다음처럼 최종 입력으로 반입한다. 별도 준비 서버라면 `suricata.rules`와 비밀 없는 검증 기록만 SSH로 전송하고 security에서 SHA 대조 후 같은 `install` 명령을 수행한다. 준비용 Suricata 이미지 ID와 security의 ID도 같아야 한다. Wazuh CA·등록 암호는 이 단계에서 복사하지 않는다.

```bash
sudo test ! -e /opt/capstone-prereqs/suricata.rules
sudo install -o root -g root -m 0644 "$et_work/output/suricata.rules" \
  /opt/capstone-prereqs/suricata.rules
sudo install -o root -g root -m 0600 "$et_work/engine-version.txt" \
  /opt/capstone-prereqs/evidence/et-engine-version.txt
sudo install -o root -g root -m 0600 "$et_work/update.log" \
  /opt/capstone-prereqs/evidence/et-update.log
sudo install -o root -g root -m 0600 "$et_work/native-test.log" \
  /opt/capstone-prereqs/evidence/et-native-test.log
sudo sha256sum /opt/capstone-prereqs/suricata.rules \
  | sudo tee /opt/capstone-prereqs/evidence/et-input.sha256 >/dev/null
sudo chmod 0600 /opt/capstone-prereqs/evidence/et-input.sha256
```

배포기는 ET 파일을 그대로 보존하고 프로젝트 일반 탐지 규칙 11개를 따로 합친다. 합본에도 native `-T`를 수행한다. 여기서 만든 ET 파일에 기존 DGX/Imperva 주소의 예외를 덧붙이지 않는다.

## 7. SIEM용 Wazuh single-node 원본

SIEM 또는 Linux 준비 서버에서 Git을 준비한 뒤 수행한다. 공개 태그 `v4.14.8`을 확인한 commit은 **`5f5951b795578cb0844f4601b66df890860c20f3`**다. [공식 v4.14.8 원본](https://github.com/wazuh/wazuh-docker/tree/v4.14.8/single-node)을 가져오며 기존 운영 디렉터리를 복제하지 않는다.

```bash
set -euo pipefail
umask 077
wazuh_work=$(mktemp -d /var/tmp/capstone-wazuh-src.XXXXXXXX)
git clone --depth 1 --branch v4.14.8 \
  https://github.com/wazuh/wazuh-docker.git "$wazuh_work/repository"
test "$(git -C "$wazuh_work/repository" rev-parse HEAD)" = \
  5f5951b795578cb0844f4601b66df890860c20f3
test -f "$wazuh_work/repository/single-node/docker-compose.yml"
test -z "$(find "$wazuh_work/repository/single-node" -type l -print -quit)"

# SIEM에서 수행하는 반입 단계. 별도 준비 서버라면 single-node만 먼저 전송한다.
sudo test ! -e /opt/capstone-prereqs/wazuh-docker/single-node
sudo install -d -o root -g root -m 0700 /opt/capstone-prereqs/wazuh-docker
sudo cp -R "$wazuh_work/repository/single-node" /opt/capstone-prereqs/wazuh-docker/
sudo chown -R root:root /opt/capstone-prereqs/wazuh-docker
sudo find /opt/capstone-prereqs/wazuh-docker -type d -exec chmod 0755 {} +
sudo find /opt/capstone-prereqs/wazuh-docker -type f -exec chmod 0644 {} +
printf '%s\n' 'v4.14.8 5f5951b795578cb0844f4601b66df890860c20f3' \
  | sudo tee /opt/capstone-prereqs/evidence/wazuh-source.txt >/dev/null
sudo chmod 0600 /opt/capstone-prereqs/evidence/wazuh-source.txt
```

`.git`은 `single-node` 바깥이므로 최종 경로에 들어가지 않는다. **공식 Compose를 직접 먼저 기동하거나 공식 cert generator를 별도로 실행하지 않는다.** 프로젝트 설치기가 원본을 복사한 뒤 새 CA, SIEM IP SAN 인증서, 암호, 등록 구성을 생성한다. 태그의 commit이 달라지면 위 검사에서 멈추고 원인을 확인한다. 확인 값을 현재 값으로 자동 치환하지 않는다.

원본에는 공개 기본 설정만 포함한다. 상위 `/opt/capstone-prereqs`는 `0700`으로 유지하고, 그 안의 공개 Wazuh 원본만 디렉터리 `0755`·파일 `0644`로 준비한다. 설치기가 파일 권한을 보존해 컨테이너에 개별 마운트하므로, 이 YAML까지 `0600`으로 바꾸면 비root Indexer/Dashboard가 읽지 못할 수 있다. 실제 비밀 입력 `siem.json`과 생성된 비밀 파일의 별도 권한은 그대로 유지한다.

## 8. SIEM용 읽기 MCP 바이너리

권장 준비 경로는 검증한 공식 릴리스 바이너리다. [gbrigandi/mcp-server-wazuh v0.3.0 릴리스](https://github.com/gbrigandi/mcp-server-wazuh/releases/tag/v0.3.0)와 [GitHub 공개 자산 메타데이터](https://api.github.com/repos/gbrigandi/mcp-server-wazuh/releases/tags/v0.3.0)에서 다음 값을 확인했다.

| 항목 | 확인값 |
|---|---|
| 소스 commit | `969f36fb833c5404055a668dc27b97f0ea3cc755` |
| Linux amd64 자산 | `mcp-server-wazuh-linux-amd64` |
| 크기 | `15933592` bytes |
| 자산 SHA-256 | `8a18cb44007d4834ee77ae8975355f404c49bda8c0d686e534994e3514134834` |

이 값은 공식 GitHub 자산 메타데이터와의 대조용이다. 별도 서명 검증을 수행했다는 의미는 아니다. 현재 SIEM 설치기는 SHA·ELF 형식을 검사하지만 바이너리의 CPU·런타임 호환성을 완전히 분석하지 않으므로 아래 amd64·실행 검사를 함께 한다.

### 8-1. 릴리스 다운로드·대조·반입

Linux 준비 서버 또는 인터넷이 허용된 SIEM에서만 실행한다. `file`·`readelf`를 위해 `file binutils`를 수동 준비한다. 바이너리의 해시를 확인하기 전에 실행하지 않는다.

```bash
sudo apt-get install -y file binutils
set -euo pipefail
umask 077
mcp_work=$(mktemp -d /var/tmp/capstone-mcp.XXXXXXXX)
mcp_expected=8a18cb44007d4834ee77ae8975355f404c49bda8c0d686e534994e3514134834
curl --fail --show-error --silent --location --proto '=https' --tlsv1.2 \
  https://github.com/gbrigandi/mcp-server-wazuh/releases/download/v0.3.0/mcp-server-wazuh-linux-amd64 \
  --output "$mcp_work/mcp-server-wazuh"
test "$(stat -c %s "$mcp_work/mcp-server-wazuh")" = 15933592
printf '%s  %s\n' "$mcp_expected" "$mcp_work/mcp-server-wazuh" | sha256sum -c -
file "$mcp_work/mcp-server-wazuh"
readelf -h "$mcp_work/mcp-server-wazuh"
chmod 0700 "$mcp_work/mcp-server-wazuh"
timeout 10 "$mcp_work/mcp-server-wazuh" --help
printf '%s\n' "$mcp_expected" > "$mcp_work/mcp-server-wazuh.sha256"
```

ELF header는 64-bit, little endian, x86-64여야 한다. `--help`는 CLI 실행 가능 여부만 검사하며 실제 Wazuh에 접속하거나 자격증명을 요구하지 않는다. 바이너리와 한 줄 checksum 파일만 SIEM으로 보낸다. 별도 준비 서버를 사용했다면 SIEM에서 해시·ELF·`--help` 검사를 다시 수행한다.

```bash
# SIEM에서: mcp_work는 검증한 두 파일이 있는 SIEM 로컬 임시폴더
sudo test ! -e /opt/capstone-prereqs/mcp/mcp-server-wazuh
sudo install -d -o root -g root -m 0700 /opt/capstone-prereqs/mcp
sudo install -o root -g root -m 0755 "$mcp_work/mcp-server-wazuh" \
  /opt/capstone-prereqs/mcp/mcp-server-wazuh
sudo install -o root -g root -m 0644 "$mcp_work/mcp-server-wazuh.sha256" \
  /opt/capstone-prereqs/mcp/mcp-server-wazuh.sha256
sudo python3 -B - <<'PY'
import hashlib,pathlib,re
d=pathlib.Path('/opt/capstone-prereqs/mcp')
p=(d/'mcp-server-wazuh.sha256').read_text().strip()
b=(d/'mcp-server-wazuh').read_bytes()
assert re.fullmatch('[0-9a-f]{64}',p)
assert hashlib.sha256(b).hexdigest()==p
assert b[:4]==b'\x7fELF' and b[4:6]==b'\x02\x01'
assert int.from_bytes(b[18:20],'little')==62
print('MCP SHA-256 and Linux amd64 ELF checks passed')
PY
```

**`.sha256`에는 파일명을 붙이지 않는다.** 일반적인 `sha256sum file > file.sha256` 출력은 이 설치기의 입력 형식과 다르다. 소문자 64자리 SHA와 개행만 저장한다. MCP용 `.env`, 운영 API 암호, 기존 SSH 키는 반입하지 않는다. 설치기가 새 읽기 전용 Wazuh/Indexer 계정과 제한된 SSH 실행 경로를 구성한다.

### 8-2. 소스 빌드가 필요한 경우

공식 바이너리를 사용할 수 없거나 별도 소스 검토 정책이 있을 때만 이 경로를 선택한다. v0.3.0 소스에는 **Cargo.lock이 없고**, [upstream 릴리스 workflow](https://github.com/gbrigandi/mcp-server-wazuh/blob/969f36fb833c5404055a668dc27b97f0ea3cc755/.github/workflows/release.yml)는 Rust stable과 `x86_64-unknown-linux-musl`을 사용한다. 따라서 같은 소스 commit이어도 오늘 다시 빌드한 결과가 위 릴리스 SHA와 같다고 보장할 수 없다. 새 dependency lock·도구 버전·빌드 결과를 함께 검토하고 보존해야 한다.

별도 **일회용 Linux amd64 준비 VM**에서 수동으로 Git, C 빌드 도구, musl, Perl, pkg-config, CA를 설치한다. Rust는 [공식 설치 안내](https://www.rust-lang.org/tools/install)를 확인해 준비한다. 아래는 Rustup과 Cargo 다운로드까지 전용 임시폴더 안에 두는 예시다. 받은 Rustup 셸을 검토한 다음 운영자가 실행한다. Mac에서는 실행하지 않는다.

```bash
sudo apt-get install -y git build-essential musl-tools perl pkg-config \
  libssl-dev ca-certificates curl file binutils less
set -euo pipefail
umask 077
mcp_build=$(mktemp -d /var/tmp/capstone-mcp-build.XXXXXXXX)
export RUSTUP_HOME="$mcp_build/rustup"
export CARGO_HOME="$mcp_build/cargo"
export CARGO_TARGET_DIR="$mcp_build/target"
mkdir "$mcp_build/tmp"
curl --fail --show-error --silent --location https://sh.rustup.rs \
  --output "$mcp_build/rustup-init.sh"
less "$mcp_build/rustup-init.sh"
env TMPDIR="$mcp_build/tmp" sh "$mcp_build/rustup-init.sh" \
  -y --no-modify-path --profile minimal --default-toolchain stable
"$CARGO_HOME/bin/rustup" target add x86_64-unknown-linux-musl

git clone https://github.com/gbrigandi/mcp-server-wazuh.git "$mcp_build/source"
git -C "$mcp_build/source" checkout --detach 969f36fb833c5404055a668dc27b97f0ea3cc755
test "$(git -C "$mcp_build/source" rev-parse HEAD)" = \
  969f36fb833c5404055a668dc27b97f0ea3cc755
"$CARGO_HOME/bin/rustc" --version --verbose > "$mcp_build/rust-version.txt"
"$CARGO_HOME/bin/cargo" --version > "$mcp_build/cargo-version.txt"
env PATH="$CARGO_HOME/bin:$PATH" "$CARGO_HOME/bin/cargo" generate-lockfile \
  --manifest-path "$mcp_build/source/Cargo.toml"
env PATH="$CARGO_HOME/bin:$PATH" "$CARGO_HOME/bin/cargo" fetch --locked --target x86_64-unknown-linux-musl \
  --manifest-path "$mcp_build/source/Cargo.toml"
```

여기서 `Cargo.toml`·새 `Cargo.lock`·dependency 출처를 검토한다. 공개 소스와 의존성만 준비 서버로 가져오고 Wazuh·SIEM 운영 자료를 외부 빌드에 제공하지 않는다. 확인 후 lockfile 변경과 추가 다운로드를 금지하는 `--frozen`으로 빌드한다. 빌드 중 Rust compiler가 필요로 하는 subprocess의 경로도 지정한다.

```bash
env PATH="$CARGO_HOME/bin:$PATH" "$CARGO_HOME/bin/cargo" build --release --frozen \
  --target x86_64-unknown-linux-musl --manifest-path "$mcp_build/source/Cargo.toml" \
  2>&1 | tee "$mcp_build/build.log"
mcp_built="$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/mcp-server-wazuh"
test -x "$mcp_built"
file "$mcp_built"
readelf -h "$mcp_built"
timeout 10 "$mcp_built" --help
sha256sum "$mcp_built"
```

stdlib/dependency 최소 Rust 버전 문제나 빌드 실패가 나면 Cargo 파일의 버전 제약을 임의로 완화하지 않는다. toolchain·dependency 조합을 별도로 검토한다. upstream 시험도 검토한 모의 서비스·격리 환경에서 수행하고, 실제 Wazuh 호출 시험은 배포 후 새 읽기 계정으로 수행한다. `--help` 성공만으로 MCP 도구의 정상 동작을 보장하지 않는다.

검토한 소스 빌드 결과를 사용한다면 위 8-1의 반입 단계에서 **직접 빌드한 실제 SHA**를 pin으로 쓰고, 공식 릴리스 checksum으로 표시하지 않는다. `Cargo.lock`, toolchain 버전, source commit, 결과 SHA, 시험 결과를 SIEM의 root 전용 evidence에 보존한다. 바이너리/lock을 확보한 후 준비 VM의 전용 Rustup·Cargo cache·build tree를 정리한다. 실제 MCP `initialize`·`tools/list` 검증은 설치기의 SIEM 검증 단계에서도 수행한다.

## 9. Hermes와 SIEM 초기 입력

일반 채팅 1.4는 query-completion의 `__init__.py`·`plugin.yaml`과 공용 `infra/hermes/soc_management_run.py`를 `grounding.py`로 함께 반입한다. 세 파일은 단일 deploy.sh가 설치하며 공용 코드 SHA와 native 핀을 검사한다. 별도 패키지 다운로드는 없다. 일반/관리 프로필의 `timezone: Asia/Seoul`, KST 정책과 승인 카드 표시도 같은 소스 묶음을 사용한다.

[Hermes 이미지 수동 준비](hermes-image.md)를 완료하고 결과 image ID를 `siem.json`의 `hermes_image`에 기록한다. 기존 운영 Hermes의 `.env`, 대화 데이터, SSH 키, Docker volume은 이식하지 않는다. 준비된 이미지에는 Python 3.13, MCP SDK, 검토된 한국어 출력 가드·regex가 있어야 하며, 첫 기동 전 검사를 통과해야 한다.

`/opt/capstone-prereqs/siem.json`의 필드와 암호 조건은 [루트 README의 siem 사전 자료](../README.md#siem)를 따른다. 파일은 **root:root 0600**, 정확한 JSON 스키마여야 한다. shell history에 암호를 쓰는 `echo '암호'` 방식 대신 SIEM에서 `sudoedit`으로 입력한다. 전체 JSON을 로그에 출력하지 않고 문법만 확인한다.

```bash
sudo python3 -B - <<'PY'
import json,pathlib,stat
p=pathlib.Path('/opt/capstone-prereqs/siem.json')
s=p.lstat()
assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_gid==0
assert stat.S_IMODE(s.st_mode)==0o600
assert isinstance(json.loads(p.read_text()),dict)
print('SIEM JSON syntax and ownership/mode passed')
PY
```

구체 필드·암호 강도·이미지 존재 등은 `deploy.sh --check`가 추가 검사한다. 이 문법 검사만으로 전체 입력이 승인되는 것은 아니다.

## 10. 준비 완료 확인과 임시파일 정리

아래 항목이 만족되면 관리 컴퓨터의 저장소 루트에서 `bash deploy.sh --check`를 실행한다. 실제 설치를 시작하는 명령은 `--apply`다.

| 확인 항목 | 통과 기준 |
|---|---|
| OS·시간 | 서로 다른 Ubuntu 24.04 amd64 세 서버, Asia/Seoul, 시간 동기화 |
| 패키지 | Docker/Compose 정상, 공통 명령 존재, SIEM bcrypt·sysctl 통과 |
| agent | security·service 4.14.8, 중지·미등록, mask 없음 |
| 이미지 | 역할별 이미지가 로컬에 존재하고 linux/amd64, ID 증거 보존 |
| service Spring 앱 | Java 로컬 이미지 참조와 전달할 소스·빌더, Apache proxy/proxy_http·DVWA mysqli 확인. JAR override일 때는 준비 파일 출처·SHA·내부 계약도 확인 |
| ET | security의 `suricata.rules`, root 소유·0644, SHA·엔진 시험 증거 |
| Wazuh 입력 | SIEM의 공식 v4.14.8 single-node 원본, root 소유, symlink 없음 |
| MCP | SIEM의 검증된 ELF와 hash-only `.sha256`, 출처·SHA·아키텍처 확인 |
| Hermes·JSON | 준비 이미지의 pin, root:root 0600 `siem.json` |

고정 읽기 진단 확장은 저장소의 `infra/mcp/system_diagnostics.py`, `system-diagnostics-mcp.py`, `read-system-diagnostics.py`, `run-system-diagnostics.sh`와 `deployment/soc_diagnostics.py`를 같은 오프라인 소스로 반입한다. Python 표준 라이브러리와 기존 systemd/journalctl·OpenSSH·util-linux 도구를 사용하며 새 pip/CDN/컨테이너 이미지 반입은 없다. 배포 시 새 진단 전용 Ed25519 키를 B에서 생성하고 공개키만 전달한다. 개인키와 서버의 실제 snapshot은 Git이나 관리자 컴퓨터의 반입 묶음에 넣지 않는다.

운영 입력(`/opt/capstone-prereqs`), 증거, 실행에 필요한 이미지와 패키지는 보존한다. 검증이 끝난 **이번 작업의** download archive·source clone·Rustup/Cargo cache·일회용 build context만 제거한다. 예를 들어 ET 준비 폴더는 다음처럼 삭제 대상을 제한한다. 각 작업의 변수에 실제 경로가 남아 있을 때만 실행한다.

```bash
set -euo pipefail
[[ $et_work =~ ^/var/tmp/capstone-et\.[A-Za-z0-9]{8}$ ]]
test -d "$et_work" && test ! -L "$et_work"
sudo rm -rf -- "$et_work"
test ! -e "$et_work"
unset et_work suri_id
```

같은 방식으로 `image_work`의 `capstone-images.*`, `image_in`의 `capstone-image-in.*`, `lab_work`의 `capstone-lab-image.*`, `wazuh_work`의 `capstone-wazuh-src.*`, `mcp_work`의 `capstone-mcp.*`, `mcp_build`의 `capstone-mcp-build.*` 각각을 확인해 제거한다. source build 환경변수 `RUSTUP_HOME`, `CARGO_HOME`, `CARGO_TARGET_DIR`는 정리 후 `unset`한다. 소스 빌드에만 쓴 별도 VM이면 운영 자료를 반입하지 않은 상태에서 VM 자체 폐기도 가능하다. 기존 사용자 cache·다른 Docker 이미지·공용 APT cache를 일괄 삭제하지 않는다.

이 경로를 따르면 Mac에는 서버 패키지 반입물이 생성되지 않는다. 배포 소스·설정·문서·작업 기록은 정리 대상이 아니다. 최종 기록에는 설치 버전, image ID/digest, ET/MCP SHA, 공개 출처, 검사 결과와 임시폴더 제거 결과를 남기고 암호·토큰·키는 남기지 않는다.
