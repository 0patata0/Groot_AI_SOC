# Groot_AI_SOC

2026 capstone project — nftables, Suricata, ModSecurity, Wazuh, Mattermost, Hermes 기반 실습 SOC.

현재 운영 이력은 [STATUS.md](STATUS.md), 진행 계획은 [PLAN.md](PLAN.md)에 있습니다. 날짜별 대화·작업 기록은 로컬 전용 `대화기록/`에 보관하며 Git에는 포함하지 않습니다. 이 문서의 새 환경 구축과 기존 운영 서버의 변경 이력을 구분합니다.

## 처음 구축할 때 읽는 순서

아래 상세 문서는 **어느 컴퓨터에서 실행하는지, 입력값, 실행 명령, 기대 결과, 실패 시 돌아갈 단계**를 함께 설명합니다. 실제 주소·NIC·게이트웨이·DNS는 관리자가 할당받은 값으로 바꿉니다. 문서의 예시 명령을 이번 작업에서 서버에 실행한 것은 아닙니다.

| 순서 | 상세 문서 | 내용 |
|---|---|---|
| 1 | [VM·네트워크·SSH 준비](deployment/setup-network-ssh.md) | VM 식별, 고정 IP, 경로·포트·미러링, 계정·공개키·host key, SSH 포트, sudo 설정·회수 |
| 2 | [패키지·배포 자료 준비](deployment/setup-packages-artifacts.md) | Docker 저장소/설치, Wazuh agent 고정 버전, 이미지 반입, ET 규칙, MCP 바이너리·해시 |
| 3 | [Hermes 이미지 준비](deployment/hermes-image.md) | 기반 이미지 확인, 한국어 가드·의존성, 수동 빌드와 정리 |
| 4 | [환경값 입력·설치 실행](deployment/configuration-guide.md) | 설정 키 전체 설명, LLM 연결, SIEM 계정 JSON, plan/check/apply/verify와 성공 기준 |
| 5 | [초기 접속·검증·장애 대응](deployment/verify-troubleshoot.md) | 최초 로그인, 사설 CA, 서비스/agent/MCP 확인, 오류별 진단, 부분 실패 처리 |

아래 내용은 같은 절차의 요약입니다. 실행 명령을 한 번에 모두 붙여넣지 말고 상세 문서의 실행 위치와 성공 조건을 확인하며 순서대로 진행합니다. 최초 설치 후 사용할 소스 버전과 로컬 설정을 보존합니다.

## 단일 셸로 세 서버 구축

관리 컴퓨터에서 `bash deploy.sh`를 한 번 실행하고 **security → siem → service 초기 IPv4 주소**를 입력합니다. 같은 SSH 계정·포트를 세 서버에서 사용하며, 셸이 SSH로 자료를 전달하고 역할별 구성을 적용합니다. IPv4/라우팅/SSH 설정 자체는 바꾸지 않습니다.

| 역할 | 구성 |
|---|---|
| security | Suricata 수동 IDS, ModSecurity DetectionOnly WAF, GROOT 규칙, Wazuh agent, 별도 nft 기본 허용 테이블 |
| siem | Wazuh manager/indexer/dashboard, Mattermost/PostgreSQL, Hermes, 읽기 전용 MCP |
| service | DVWA/MariaDB, 내부 Log4Shell 앱·실습 웹 UI, security 서버만 허용하는 웹 접근 설정, Wazuh agent |

**패키지·이미지·SSH 준비는 아래 절차로 먼저 수동 완료해야 합니다.** 배포 셸은 apt/pip/npm 설치나 이미지 pull/build를 실행하지 않습니다. 패키지·이미지·입력 자료의 정적 사전검사를 세 서버 모두 통과해야 서비스 구성을 시작합니다. 런타임 검사와 서비스 연결 검증은 해당 단계에서 추가 수행합니다.

입력 순서와 실제 설치 순서는 다릅니다. 실행은 `전체 사전검사 → siem → 등록 CA/암호 전달 → service → security → 검증`입니다. 인증 정보는 서버의 root 전용 파일에 보존하고, 관리 컴퓨터에 등록 암호를 저장하거나 터미널에 출력하지 않습니다.

## 1. 서버와 네트워크 수동 준비

- 서로 다른 **Ubuntu 24.04 LTS amd64 VM 세 대**, systemd, 고정 IPv4 주소를 준비합니다. 기존 프로젝트가 동작 중인 서버에 덮어쓰는 설치기는 아닙니다.
- 관리 컴퓨터에서 세 서버로 SSH가 가능해야 합니다. security와 service는 siem의 TCP 1514/1515에, security는 service의 웹 포트(기본80)에 연결할 수 있어야 합니다.
- 관리자는 siem의 HTTPS443·Mattermost8065, security의 WAF8080에 접근합니다. SIEM의 DB/indexer/API 내부 포트를 인터넷에 노출하지 않습니다.
- 외부 LLM/Ollama는 별도로 준비합니다. 기본 설정은 별도 API 키를 요구하지 않는 내부 OpenAI 호환 `/v1` API이며 siem에서 접근 가능해야 합니다. 모델 다운로드·학습·DGX 구축은 이 셸의 작업이 아닙니다.
- Suricata는 security의 지정 NIC를 관측합니다. 다른 VM의 트래픽도 관측하려면 가상 스위치 미러링이나 security를 경유하는 라우팅을 관리자가 먼저 구성합니다.
- WAF/IDS는 탐지 모드입니다. nft 구성은 기존 방화벽을 지우지 않는 ACCEPT-only 테이블이며, 기존 운영망의 FORWARD 차단·NAT 정책을 그대로 이식하지 않습니다.
- DVWA와 Log4Shell은 실습용 취약 애플리케이션입니다. 웹 요청은 security를 거쳐 받으며 DB와 Log4Shell 앱 포트를 호스트에 게시하지 않습니다. Log4Shell 실습 UI는 기존 WAF 주소의 `/log4shell/`에서 정상 헤더·헤더 누락 요청을 비교합니다. 별도의 외부8080 포트를 열지 않습니다.

권장 초기 자원은 SIEM 4 vCPU/8GiB RAM 이상과 충분한 로그 디스크입니다. 실제 보존기간·수집량에 따라 늘립니다. Wazuh의 Docker 요구조건은 [공식 문서](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html)를 함께 확인합니다.

## 2. SSH와 sudo 수동 준비

세 서버의 콘솔에서 아래 패키지를 설치하고 SSH를 활성화합니다. 다음 명령은 **운영자가 직접 실행하는 사전 준비 명령**입니다.

```bash
sudo apt-get update
sudo apt-get install -y openssh-server sudo
sudo systemctl enable --now ssh
sudo timedatectl set-timezone Asia/Seoul
```

세 서버에 동일한 배포용 계정(기본 `ubuntu`)을 준비하고 관리 컴퓨터의 공개키를 각 계정의 `~/.ssh/authorized_keys`에 등록합니다. 디렉터리 권한은700, 파일은600으로 설정합니다. 개인키를 서버나 저장소에 복사하지 않습니다. 외부의 관리용 SSH 접근은 관리 컴퓨터 주소로 제한합니다. SIEM에는 Hermes 컨테이너에서 호스트 자신의 SSH 포트로 접속하는 읽기 MCP 경로도 별도로 허용해야 합니다. 실제 출발지와 정책은 [네트워크·SSH 상세 절차](deployment/setup-network-ssh.md)를 따릅니다.

자동 설치는 root 작업이 필요하므로 해당 계정에서 `sudo -n`이 가능해야 합니다. 관리자가 `sudo visudo -f /etc/sudoers.d/capstone-bootstrap`로 배포용 계정의 **일시적인 관리자 권한**을 준비합니다. 예를 들어 계정명이 `ubuntu`라면:

```sudoers
ubuntu ALL=(root) NOPASSWD: ALL
```

이는 설치 관리자용 권한입니다. Hermes/LLM 계정에 부여하지 않습니다. 구축·확인 후 필요하지 않으면 관리자가 이 배포용 항목을 제거합니다. 이후 `--verify`를 SSH로 실행할 때도 root 조회 권한이 필요합니다.

SSH host key는 반드시 별도 경로로 확인합니다. 서버 콘솔의 다음 출력과 관리 컴퓨터가 받은 공개키 fingerprint를 대조한 뒤 `known_hosts`에 등록합니다.

```bash
# 각 서버 콘솔
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub

# 관리 컴퓨터: 예시 주소를 실제 주소로 변경
ssh-keyscan -t ed25519 192.0.2.10 > /tmp/security-hostkey
ssh-keygen -lf /tmp/security-hostkey
# 콘솔 값과 일치하는 경우에만 등록
cat /tmp/security-hostkey >> ~/.ssh/known_hosts
rm /tmp/security-hostkey
ssh -o BatchMode=yes -o StrictHostKeyChecking=yes ubuntu@192.0.2.10 'sudo -n true'
```

siem/service도 동일하게 준비합니다. 설치기는 `StrictHostKeyChecking=yes`를 사용하므로 host key가 없거나 바뀌면 중단합니다. 비밀번호 대화형 인증이나 host key 검사 우회는 하지 않습니다.

## 3. 패키지 수동 설치

관리 컴퓨터에는 Bash 3.2 이상, OpenSSH client, tar, Python3가 필요합니다. 이미 준비된 Linux 관리 서버나 기존 도구가 있는 Mac에서 실행할 수 있습니다. 이 작업을 위해 Mac에 추가 패키지를 설치할 필요는 없습니다. 관리 컴퓨터의 전송 임시폴더는 종료 시 제거합니다.

세 대상 Ubuntu 서버에 다음 도구를 수동 설치합니다.

```bash
sudo apt-get install -y ca-certificates curl openssl jq python3 python3-venv \
  coreutils findutils gawk grep sed util-linux iproute2 procps tar gzip \
  rsync logrotate nftables iptables
```

Docker Engine과 Compose plugin은 [Docker의 Ubuntu 설치 절차](https://docs.docker.com/engine/install/ubuntu/)에 따라 각 서버에 수동 설치합니다. 공식 apt 저장소 등록 후 설치하는 패키지는 다음과 같습니다.

```bash
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker info
sudo docker compose version
```

security/service에는 **Wazuh agent 4.14.8**을 [공식 Linux agent 설치 절차](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-linux.html)에 따라 미리 설치합니다. 아직 manager에 등록하지 않은 새 설치여야 합니다. 기존 agent 키나 등록된 agent를 지워서 맞추지 않습니다. 설치 후 최초 배포 전에는 agent를 중지해 둡니다.

```bash
sudo systemctl stop wazuh-agent
```

siem에는 비밀번호 해시 생성용 `python3-bcrypt`도 수동 설치하고, Wazuh indexer용 `vm.max_map_count`를 262144 이상으로 준비합니다. 기존에 더 높은 값이 있으면 유지합니다. [SIEM 패키지·커널 설정 상세 명령](deployment/setup-packages-artifacts.md)을 따릅니다.

역할별 이미지·공식 배포 자료·Python 의존성의 정확한 준비 목록은 아래 역할별 절차를 따릅니다. 다운로드할 수 없는 내부망에서는 인터넷이 가능한 준비 환경에서 검증한 이미지/자료를 가져와 `docker load` 등으로 수동 반입합니다. 실행 중 다운로드로 보충하지 않습니다.

## 4. 역할별 사전 자료

역할별 스크립트의 `check`는 OS 패키지, 로컬 이미지, 새 환경 여부와 입력 자료를 검사합니다. 기본 경로는 `/opt/capstone-prereqs`이며 root 소유로 준비합니다.

```bash
sudo install -d -m 0700 /opt/capstone-prereqs
```

### security

다음 이미지를 **security 서버에서 수동으로** 받거나 반입합니다. 실행기는 설치 시 실제 로컬 이미지 ID를 저장하며 재검증 때 비교합니다. 다른 검토된 이미지 참조는 로컬 설정의 `SURICATA_IMAGE`·`WAF_IMAGE`로 지정할 수 있습니다.

```bash
sudo docker pull jasonish/suricata:latest
sudo docker pull owasp/modsecurity-crs:nginx
```

Suricata와 호환되는 **검토된 ET 룰 파일**을 `/opt/capstone-prereqs/suricata.rules`에 root 소유·0644로 반입합니다. [suricata-update 공식 절차](https://docs.suricata.io/en/latest/rule-management/suricata-update.html)를 이용해 별도 준비 서버에서 생성할 수 있습니다. 다른 서버의 운영 규칙·예외·자격증명을 통째로 복사하지 않습니다. ET 파일은 원문을 보존하고 프로젝트의 일반 탐지 규칙11개를 별도로 합칩니다. 기존 DGX 주소 전용 flowbit·ET 예외는 신규 환경에 넣지 않습니다.

감시 NIC가 여러 개라면 `MONITOR_INTERFACE`를 명시합니다. `auto`는 SIEM으로 향하는 인터페이스를 선택합니다. service 방향 출발지 주소도 입력한 security 주소와 일치해야 합니다. Wazuh 등록 CA와 암호는 SIEM 구성 후 자동 전달하므로 미리 만들 필요가 없습니다.

### service

[DVWA 공식 Compose](https://github.com/digininja/DVWA/blob/master/compose.yml)와 [Log4Shell 앱 공식 README](https://github.com/christophetd/log4shell-vulnerable-app/blob/main/README.md)의 이미지를 **service 또는 Linux 준비 서버에서 수동으로** 준비합니다.

```bash
sudo docker pull ghcr.io/digininja/dvwa:latest
sudo docker pull mariadb:10
sudo docker pull --platform linux/amd64 ghcr.io/christophetd/log4shell-vulnerable-app@sha256:6f88430688108e512f7405ac3c73d47f5c370780b94182854ea2cddc6bd59929
```

초기 DB와 관리자 암호는 서버에서 새로 생성합니다. DVWA의 기본 취약 수준은 `impossible`이며 실습 시 운영자가 변경합니다. Log4Shell UI는 DVWA 이미지의 기존 Apache/PHP에 읽기 전용으로 마운트합니다. PHP8.1 이상과 curl/session 확장이 필요하며 설치기가 누락 확장이나 패키지를 설치하지 않습니다. 수동 확인·오프라인 반입·`LOG4SHELL_IMAGE` 설정은 [자료 준비](deployment/setup-packages-artifacts.md)를 따릅니다.

신규 환경의 UI 주소는 `http://SECURITY_HOST:WAF_PORT/log4shell/`입니다(기본 WAF 포트8080). UI는 별도 `internal: true` Docker lab 네트워크의 고정 대상 `log4shell:8080`만 호출합니다. 정상 헤더는 대상 HTTP200, 필수 헤더 누락은 대상 HTTP400을 비교하고 브라우저 최근20개 기록을 KST로 표시합니다. 직접 공격·LDAP 콜백·탐지 E2E는 별도 실습이며 기본 설치에서 실행하지 않습니다. 기존 운영망 UI의 `http://192.168.16.230/log4shell/` 주소와 혼용하지 않습니다.

### siem

```bash
sudo docker pull wazuh/wazuh-manager:4.14.8
sudo docker pull wazuh/wazuh-indexer:4.14.8
sudo docker pull wazuh/wazuh-dashboard:4.14.8
sudo docker pull postgres:16-alpine
sudo docker pull mattermost/mattermost-team-edition:11.11.1
```

[공식 wazuh-docker](https://github.com/wazuh/wazuh-docker/tree/v4.14.8/single-node)의 **v4.14.8 single-node 원본**을 `/opt/capstone-prereqs/wazuh-docker/single-node`에 수동 반입합니다. Git이 있는 준비용 Linux에서 해당 태그를 내려받아 `.git`을 제외한 자료만 전달해도 됩니다. 대상 경로는 root 소유, 그룹/다른 사용자 쓰기 금지이며 symlink를 허용하지 않습니다. 기존 서버의 데이터 볼륨이나 생성된 비밀을 포함하지 않습니다. 공식 Compose는 실행기의 입력 자료이며, 직접 `docker compose up`으로 먼저 실행하지 않습니다.

```bash
# git이 이미 준비된 Linux에서 수동으로 실행하는 예시
set -euo pipefail
umask 077
work_dir=$(mktemp -d)
git clone --depth 1 --branch v4.14.8 https://github.com/wazuh/wazuh-docker.git "$work_dir/wazuh-docker"
test "$(git -C "$work_dir/wazuh-docker" rev-parse HEAD)" = 5f5951b795578cb0844f4601b66df890860c20f3
sudo test ! -e /opt/capstone-prereqs/wazuh-docker/single-node
sudo install -d -m 0700 /opt/capstone-prereqs/wazuh-docker
sudo cp -R "$work_dir/wazuh-docker/single-node" /opt/capstone-prereqs/wazuh-docker/
sudo chown -R root:root /opt/capstone-prereqs/wazuh-docker
sudo find /opt/capstone-prereqs/wazuh-docker -type d -exec chmod 0755 {} +
sudo find /opt/capstone-prereqs/wazuh-docker -type f -exec chmod 0644 {} +
rm -rf -- "$work_dir"
```

상위 `/opt/capstone-prereqs`는 `0700`으로 유지합니다. 공개 Wazuh 원본의 `0644` 파일 권한은 컨테이너 내부 프로세스가 개별 마운트된 설정을 읽기 위해 필요합니다. 실제 암호가 들어가는 `siem.json`은 아래와 같이 `0600`으로 관리합니다.

Hermes는 [수동 이미지 준비 절차](deployment/hermes-image.md)에 따라 Linux에서 먼저 준비합니다. Python3.13, MCP SDK, 프로젝트 한국어 가드와 검증된 `regex`가 포함된 이미지여야 하며, 그 **로컬 `sha256:…` 이미지 ID 또는 registry digest**를 아래 JSON에 넣습니다. 실행기는 자체 다운로드나 누락 의존성 설치를 하지 않습니다.

읽기 MCP는 [gbrigandi/mcp-server-wazuh](https://github.com/gbrigandi/mcp-server-wazuh)의 검토된 v0.3.0/커밋 `969f36f` 계열 Linux amd64 바이너리를 별도 Linux에서 준비합니다. 출처·릴리스 checksum 또는 검토한 소스 빌드 결과를 대조한 뒤 다음 두 파일을 반입합니다. 자동 설치기는 첫 파일이 ELF이며 둘째 파일의 SHA-256과 같은지 검사합니다. 자체 계산한 해시만으로 원본 출처까지 검증되는 것은 아닙니다.

- `/opt/capstone-prereqs/mcp/mcp-server-wazuh`: root 소유 실행 파일
- `/opt/capstone-prereqs/mcp/mcp-server-wazuh.sha256`: 검증한 SHA-256 소문자64자리만 한 줄

마지막으로 `sudoedit /opt/capstone-prereqs/siem.json`으로 다음 형식의 파일을 만들고 `sudo chmod 600 /opt/capstone-prereqs/siem.json`을 실행합니다. 예시 암호는 모두 **서로 다른 새 암호**로 바꿉니다. 이 파일은 서버에만 두고 Git에 넣지 않습니다. API 암호는 대·소문자/숫자/기호를 섞고, 각 암호 길이는 UTF-8 기준16~72바이트로 준비합니다.

```json
{
  "schema_version": 1,
  "wazuh_api_username": "wazuh-wui",
  "wazuh_api_password": "CHANGE_ME_NEW_API_PASSWORD",
  "indexer_username": "admin",
  "indexer_password": "CHANGE_ME_NEW_INDEXER_PASSWORD",
  "mattermost_admin_username": "socadmin",
  "mattermost_admin_email": "operator@example.org",
  "mattermost_admin_password": "CHANGE_ME_NEW_CHAT_PASSWORD",
  "postgres_password": "CHANGE_ME_NEW_DATABASE_PASSWORD",
  "hermes_image": "sha256:REPLACE_WITH_PREPARED_LOCAL_IMAGE_ID"
}
```

설치기는 원본 자료를 보존하고 `/opt/capstone/siem`에 복사한 뒤 비밀번호 설정, 새 사설 CA와 입력 SIEM IP SAN 인증서, Wazuh 등록 암호, Mattermost 관리자·팀·채널·봇, 읽기 전용 계정/MCP와 Hermes 연결을 구성합니다. **공인 HTTPS 인증서는 발급하지 않습니다.** Dashboard는 새 사설 CA를 신뢰해야 하며, Mattermost는 내부망 HTTP8065 기본 구성입니다. 공개 인증서·HTTPS 역방향 프록시·모바일 푸시는 별도 설정합니다.

SIEM의 SSH는 Hermes 전용 키에 읽기 MCP만 허용하는 계정/ForceCommand를 추가하고 구문 검사 후 reload합니다. 기존 관리 계정이나 SSH 포트는 변경하지 않습니다. 현재 설치기는 `AllowUsers/AllowGroups/DenyUsers/DenyGroups`가 있는 SIEM 구성을 거절합니다. 허용 목록에 계정만 추가해도 이 검사는 통과하지 않습니다. 해당 정책을 유지해야 하는 환경은 설치기의 별도 지원·검증이 필요하며, 검사를 통과하려고 기존 운영 SSH 정책을 제거하지 않습니다.

## 5. 실행

프로젝트 전체를 관리 컴퓨터에 내려받고 저장소 루트에서 실행합니다.

```bash
bash deploy.sh
```

주소를 security, siem, service 순으로 입력한 뒤 SSH 사용자, 개인키 경로(기존 agent/default key 사용 시 빈칸), 감시 NIC, LLM API 주소를 입력합니다. 사전 준비가 모두 통과해야 서비스 설치가 시작됩니다.

반복 실행할 환경은 비밀 값이 없는 로컬 설정으로 저장할 수 있습니다. `~`, `$HOME`, 셸 치환, 따옴표를 해석하지 않는 단순 `KEY=value` 형식입니다. 경로는 절대 경로를 사용합니다.

```bash
cp deployment/config.example.conf deployment/site.local.conf
# 실제 주소, SSH 경로, LLM 주소를 편집
bash deploy.sh --plan --batch --config deployment/site.local.conf
bash deploy.sh --check --batch --config deployment/site.local.conf
bash deploy.sh --apply --batch --config deployment/site.local.conf
bash deploy.sh --verify --batch --config deployment/site.local.conf
```

`--plan`은 로컬 입력 검사만 수행하고 SSH 연결을 하지 않습니다. `--check`는 원격 임시폴더에서 읽기 사전검사를 하고 정리합니다. `--apply`는 설치·시작·검증, `--verify`는 기존 구성 확인입니다.

같은 프로필의 완료된 역할은 검증 경로로 처리하며, 중간 실패 흔적이나 다른 설정·기존 서비스가 발견되면 자동 덮어쓰기하지 않습니다. Log4Shell·UI를 포함한 service 상태는 schema2이며 이전 schema1의 자동 이관은 지원하지 않습니다. 실패한 역할의 상태와 서버 내 제한된 로그를 검토한 뒤 재개합니다. 자동 롤백을 명목으로 기존 컨테이너·볼륨·agent 키를 삭제하지 않습니다.

## 검증 범위와 운영 이식

로컬 controller 회귀는 실제 셸을 가짜 SSH 전송에 연결해 실행합니다.

```bash
python3 -B deployment/tests/test_controller.py
bash deployment/roles/siem-test.sh
bash deployment/roles/service-test.sh
```

새 Ubuntu VM 세 대에서 실제 구축 완료를 확인하기 전에는 해당 결과를 운영 검증으로 표시하지 않습니다. 이번 자동 구성 범위는 위 표의 **새 환경 기본 SOC**입니다. 실제 컨테이너 기동, Wazuh 에이전트 등록, DVWA 초기 DB 생성, Log4Shell 앱·UI, Mattermost/Hermes 연결은 새 Ubuntu VM에서 추가 검증해야 합니다. 적용 중에는 native 엔진 구문검사와 서비스 검증이 실패하면 후속 단계를 중단합니다. `--check`는 전체 기능 E2E 시험이 아니며, Hermes 이미지 import 검사는 apply 시작 시 격리된 로컬 컨테이너에서 수행합니다.

다음 운영 기능은 소스가 저장소에 있지만 이 셸에서 자동 이식하지 않습니다.

- 승인형 쓰기 MCP·브로커·worker, nft 선차단/Native AR, 운영망 FORWARD/NAT 정책
- Vector 정제·원본 세대 회전·백업 이관·보존/용량 감시·Indexer 상관분석의 운영 정책
- 기존 DGX/Imperva 고정 주소 예외, 정기 보고·인증서 감시, Log4Shell 직접 공격·LDAP 콜백·탐지 E2E 시나리오
- 공개 인증서·채팅 HTTPS·모바일 푸시·SSL VPN, 모델 학습/업로드

Docker 자체 JSON 로그에는 역할별 제한이 있지만 Suricata/WAF 원본의 장기 회전·보존은 별도 설정해야 합니다. 새 환경에는 읽기 MCP 두 개만 연결되며 LLM에 일반 sudo나 Docker 권한을 주지 않습니다. 이 새 환경 설치기로 기존 운영 서버를 업그레이드하지 않습니다. 기존 C의 Apache/PHP UI 추가 배포는 [별도 운영 절차](infra/groot-c/log4shell-ui/README.md)와 작업 기록으로 구분합니다.
