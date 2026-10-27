# 새 환경의 네트워크·SSH 준비

## 세 호스트 공통 SSH MAC 정책 — 2026-10-27

루트 `deploy.sh`의 security·siem·service 역할은 `deployment/ssh_macs.py`의 check/install/verify를 호출한다. `/etc/ssh/sshd_config.d/01-capstone-macs.conf`에 아래 정책을 배치하고 소스 SHA와 실제 유효 설정을 검증한다. 정확히 일치하는 종전 A의4종 제외 파일만 백업 후5종 제외로 이행한다. 다른 기존 파일·더 엄격한 정책·MAC 외 옵션 변경은 거절한다.

```text
MACs -hmac-sha1,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com
```

SHA1/UMAC64 계열4종과 설치된 Ubuntu SCA35654가 금지하는 UMAC128-ETM을 제외한다. 이 범위는 모든 SSH/CIS 항목의 통과를 뜻하지 않는다. 기존 계정·키·비밀번호 인증·허용 IP는 별도 정책이다.

후보 배치 후 전체 구문·유효 옵션을 확인하고 `ssh.service`를 reload한다. 실패하면 이번 추가 파일을 제거하거나 정확한 종전 파일의 내용·권한을 복원한다. 원본과 메타데이터는 `/var/backups/capstone-ssh-macs-*`에 root 전용으로 보존한다. 기존 세션을 유지하면서 별도 신규 관리 연결과 실제 봇/MCP 클라이언트를 검증한다. 배포 helper의 reload 성공만으로 신규 접속까지 검증했다고 표시하지 않는다. 운영 서버에는 초기 설치기를 재실행하지 않고 승인된 설정만 증분 적용한다.

저장된 SCA 스캔과 현재 유효 설정은 다르다. 적용 후 스캔 시각과 개별 체크를 다시 조회해야 하며 과거 실패 기록을 지우지 않는다. 실제 운영 결과는 [STATUS](../STATUS.md)를 따른다.

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 사용자 진입점은 루트 deploy.sh 하나이고 service schema9·HTTP3/터미널3·MCP6서버/고정 진단을 연결한다. 새3VM 전체 설치 시험은 사용자 제외 범위를 유지하며 기존 운영 서버를 초기 설치기로 덮어쓰지 않는다. 이번 운영 보완은 별도 최소 이관이다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

[README로 돌아가기](../README.md). 이 문서는 `deploy.sh` 실행 **전**에 운영자가 세 Ubuntu VM을 준비하는 절차입니다. 명령의 실행 위치를 구분하며, 실제 설치는 이 저장소의 스크립트와 함께 검증해야 합니다. 문서 작성 과정에서 서버 설정을 변경한 것은 아닙니다.

## 1. 주소·NIC·VM부터 확정

다음 주소는 문서용 예시입니다. 실제 학과망 주소, 게이트웨이, VLAN, DNS, 인터페이스명으로 모두 교체합니다. `192.0.2.0/24`, `198.51.100.0/24`를 실제 인터넷 주소로 사용하지 않습니다.

| 항목 | 예시 | 운영자가 기록할 내용 |
|---|---|---|
| security | `192.0.2.10/24` | SSH/WAF에 사용할 고정 IP, 관리 NIC, 감시 NIC |
| siem | `192.0.2.20/24` | SSH/Dashboard/Mattermost에 사용할 고정 IP |
| service | `192.0.2.30/24` | SSH/DVWA backend에 사용할 고정 IP |
| 관리 컴퓨터 | `192.0.2.50` | 서버에서 관측하는 SSH 출발지 IP; VPN/NAT 뒤라면 변환 후 주소 |
| LLM API | `http://192.0.2.40:11434/v1` | SIEM에서 도달하는 OpenAI 호환 주소와 실제 모델명 |
| 게이트웨이 | `192.0.2.1` | 다른 대역으로 갈 때만 필요한 실제 라우터 |
| 공통 SSH | `capdeploy`, TCP `22` | 세 서버에서 같은 계정명·포트 사용 |

세 VM은 **Ubuntu 24.04 LTS amd64, systemd**가 필요합니다. VM 복제로 생성했다면 하이퍼바이저의 복제·일반화 절차로 MAC, machine-id, SSH host key가 각각 고유한지 확인합니다. 기존 운영 VM의 식별자나 agent 등록 키를 지워 신규 VM처럼 만드는 방식으로 진행하지 않습니다.

**실행 위치: 각 서버의 하이퍼바이저 콘솔.** 아래 명령은 조회만 합니다.

```bash
cat /etc/os-release
uname -m
cat /etc/machine-id
hostnamectl
ip -br link
ip -br -4 address
ip -4 route
df -h / /var/lib
free -h
```

기대 결과는 `VERSION_ID="24.04"`, `x86_64`, 서로 다른 machine-id와 IP입니다. 관리 NIC의 MAC을 하이퍼바이저 vNIC와 대조합니다. 세 주소가 같은 VM으로 연결되면 배포 사전검사에서 중단합니다. 저장공간은 이미지·볼륨·로그를 함께 고려하고, SIEM은 README의 초기 자원 기준에서 수집량에 맞게 늘립니다.

하이퍼바이저에서는 각 VM의 관리 vNIC를 의도한 가상 스위치/포트그룹에 연결합니다. VLAN 태깅 주체가 하이퍼바이저인지 게스트 OS인지 확인해 중복 태깅을 피합니다. 제품·버전·가상 스위치 이름은 설치 환경에 따라 다르므로 특정 ESXi 메뉴나 포트그룹명을 전제로 하지 않습니다.

## 2. 고정 IPv4 설정

**실행 위치: 각 서버 콘솔.** 원격 SSH 연결만으로 주소를 바꾸지 않습니다. 현재 Netplan 파일을 먼저 읽고, 해당 NIC를 이미 정의한 파일을 편집합니다. 같은 NIC 정의를 새 YAML에 중복 추가하지 않습니다.

```bash
sudo netplan get
sudo ls -l /etc/netplan
sudo install -d -m 0700 /root/capstone-bootstrap-backups
sudo cp -a /etc/netplan "/root/capstone-bootstrap-backups/netplan-$(date +%Y%m%dT%H%M%S)"
```

출력에서 확인한 파일을 `sudoedit /etc/netplan/실제파일명.yaml`로 편집합니다. 아래는 **systemd-networkd를 사용하는 신규 VM의 단일 관리 NIC** 예시입니다. `enp1s0`는 `ip -br link`에서 확인한 이름으로 교체하고, siem/service에서는 주소를 각각 `.20/24`, `.30/24`로 바꿉니다. NetworkManager가 관리하는 VM에 renderer만 강제로 바꾸지 않습니다.

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp1s0:
      dhcp4: false
      addresses:
        - 192.0.2.10/24
      routes:
        - to: default
          via: 192.0.2.1
      nameservers:
        addresses:
          - 198.51.100.53
```

예시 DNS도 실제 조직 DNS로 교체합니다. 외부 연결이 없는 동일 서브넷만 사용할 때는 불필요한 `routes`/`nameservers` 항목을 생략할 수 있습니다. 다른 NIC에 이미 기본 경로가 있으면 두 번째 기본 경로를 무조건 추가하지 않습니다. cloud-init이 네트워크 파일을 생성하는 이미지라면 상위 네트워크 설정도 함께 수정해야 재부팅 후 유지됩니다. [Netplan 정적 주소 설정](https://netplan.readthedocs.io/en/stable/examples/)을 참고합니다.

편집한 **실제 파일 경로**의 소유자와 모드를 `root:root`, `0600`으로 맞춘 후 적용합니다.

```bash
sudo chown root:root /etc/netplan/실제파일명.yaml
sudo chmod 0600 /etc/netplan/실제파일명.yaml
sudo netplan generate
sudo netplan try --timeout 120
```

`generate`는 오류 없이 끝나야 합니다. `try` 동안 별도 관리 단말에서 새 주소로 접속 가능한지 확인하고 콘솔에서 확정합니다. 실패하면 확정하지 말고 콘솔에서 주소·게이트웨이·YAML을 수정합니다. 자동 복귀 후에도 실제 주소/경로와 파일이 원하는 상태인지 확인합니다. 특히 가상 인터페이스는 복귀가 완전하지 않을 수 있으므로 백업과 콘솔을 유지합니다. [Netplan try의 복귀 동작·제약](https://netplan.readthedocs.io/en/stable/netplan-try/)에 설명돼 있습니다.

```bash
ip -br -4 address
ip -4 route
resolvectl status
```

주소가 계획과 같고 재부팅 후에도 유지돼야 다음 단계로 진행합니다. DNS가 필요한 패키지 저장소나 LLM 호스트명을 쓴다면 그 이름이 조직 DNS에서 조회되는지도 확인합니다.

## 3. 경로와 허용 포트

기본 배치는 세 서버를 직접 통신 가능한 실습망에 두고, 사용자는 security의 WAF로 웹 요청을 보냅니다. WAF가 service로 새 연결을 만들기 때문에 **security를 모든 VM의 기본 게이트웨이로 지정할 필요는 없습니다**.

```text
관리 컴퓨터 ── SSH ──┬─ security
                    ├─ siem
                    └─ service
실습 클라이언트 ── WAF:8080@security ── HTTP:80@service
                                         ├─ DVWA
                                         └─ Apache /log4shell/ proxy ── private lab ── Spring Boot:8080/log4shell/
security / service ── Wazuh:1514,1515@siem
관리자 ── Dashboard:443 / Mattermost:8065@siem
Hermes@siem ── LLM:11434 또는 지정 포트
Hermes 컨테이너@siem ── siem 자신의 SSH 포트 ── 읽기 MCP
```

Log4Shell 앱의8080은 service 내부 Docker `lab` 네트워크에서만 사용합니다. 해당 네트워크는 `internal: true`이며 앱의 호스트 포트는 게시하지 않습니다. 기존 WAF 포트의 `/log4shell/`로 UI를 이용하므로 새 외부8080 허용이나 DNAT 토글이 필요하지 않습니다. Apache→Spring Boot 내부 통신은 security 감시 NIC를 지나지 않으며, 화면·로깅 API 정상 응답은 공격 탐지 검증과 구분합니다. 화면과 API는 같은 Java 앱이 제공하고 PHP 중계 웹은 사용하지 않습니다.

Log4Shell에 별도 HTTP 이름을 쓰려면 `LOG4SHELL_HOSTNAME`을 설정하기 전에 관리자가 DNS 또는 클라이언트 hosts에 해당 이름→`SECURITY_HOST`를 준비합니다. 예를 들어 문서용 주소라면 `192.0.2.10 log4shell.example.org`이며 실제 환경의 할당 주소로 바꿉니다. 설치기는 DNS/hosts를 수정하지 않습니다. 접속은 `http://호스트명:WAF_PORT/`이고 포트80만 생략합니다. 이름을 준비하지 않았으면 설정을 비워 두고 기존 IP `/log4shell/` 경로를 사용합니다. 인증서·HTTPS·별도 앱 포트 개방은 이 선택값으로 추가되지 않습니다.

다음은 **접근 정책을 작성할 때의 허용 관계**입니다. 현재 설치기가 방화벽에 이 표를 자동 반영하는 것은 아닙니다.

| 출발지 → 목적지 | TCP 포트 | 용도·범위 |
|---|---|---|
| 관리 컴퓨터 → 세 서버 | 공통 `SSH_PORT` | 키 기반 배포·조회 |
| security/service → siem | `1514`, `1515` | agent 로그·TLS 등록 |
| security → service | `WEB_BACKEND_PORT` 기본 `80` | DVWA·Log4Shell UI의 WAF backend; 일반 클라이언트 직접 접근은 허용하지 않음 |
| 승인된 실습 클라이언트 → security | `WAF_PORT` 기본 `8080` | WAF를 통한 실습 HTTP |
| 관리자 → siem | `443`, `8065` | Dashboard·Mattermost |
| siem/Hermes → 외부 LLM | API URL의 포트 | 모델 추론 |
| siem 내부 서비스/읽기 MCP → siem | `55000`, `9200` | Wazuh API·Indexer; 일반 사용자망에 개방하지 않음 |
| Hermes 컨테이너 → siem | 공통 `SSH_PORT` | 강제 명령 계정의 읽기 MCP |

SIEM의 컨테이너 게시 포트는 입력한 SIEM IP에 바인딩됩니다. **IP 바인딩만으로 출발지 접근 제어가 되지는 않습니다.** 하이퍼바이저/라우터 ACL 또는 Docker에 맞춘 호스트 정책으로 표의 출발지를 제한합니다. PostgreSQL/MariaDB 포트는 호스트에 게시하지 않습니다. 패키지 반입 단계의 DNS/HTTPS·시간 동기화는 조직 정책에 따라 별도로 허용합니다.

UFW의 일반 INPUT 규칙만으로 Docker 게시 포트가 보호된다고 판단하지 않습니다. Docker는 컨테이너 패킷을 별도 NAT/forward 경로로 처리하므로 실제 firewall backend와 컨테이너 경로에 맞춰 정책을 작성해야 합니다. 기존 nft/iptables 규칙을 flush하거나 Docker의 firewall 관리를 끄는 절차는 이 설치기에 없습니다. [Docker 방화벽 동작](https://docs.docker.com/engine/network/packet-filtering-firewalls/)을 기준으로 검토합니다.

security의 `capstone_portable` nft 테이블은 **ACCEPT-only 기본 테이블**입니다. 외부 차단, NAT, FORWARD 통제 또는 위 출발지 제한을 대신하지 않습니다. 기존 다른 테이블의 DROP을 우회하지도 않습니다. 그 테이블에 보이는 TCP22 accept를 이유로 다른 SSH 포트가 열렸다고 판단하지 않습니다.

**실행 위치: security.** 아래 예시의 목적지를 실제 주소로 교체합니다.

```bash
ip -4 route get 192.0.2.20
ip -4 route get 192.0.2.30
```

service 방향 결과의 `src`는 입력할 `SECURITY_HOST`여야 합니다. 다중 NIC 환경에서 다른 source가 선택되면 설치기가 중단합니다. 현재 설치기는 SSH 주소와 WAF backend 출발지 주소를 따로 입력받지 않으므로 이 조건을 만족하는 주소·라우팅을 설계합니다. 경로를 억지로 바꾸거나 service의 허용 범위를 전체망으로 넓혀 통과시키지 않습니다.

다른 서브넷이 필요한 경우 운영자가 실제 라우터를 정하고 양방향 반환 경로를 준비합니다. 아래는 **해당 경로가 필요한 경우에만** 기존 Netplan NIC의 `routes`에 넣는 예시입니다.

```yaml
routes:
  - to: 198.51.100.0/24
    via: 192.0.2.1
```

이미 있는 기본 경로와 병합하고 `netplan generate`/`try`로 검증합니다. security를 라우터로 사용하는 설계는 IP forwarding·반환 경로·FORWARD 정책·필요한 NAT를 별도로 완성해야 하며, 기본 설치기를 실행했다고 구성되지 않습니다.

## 4. Suricata가 볼 트래픽 준비

`MONITOR_INTERFACE=auto`는 **security에서 SIEM으로 가는 NIC**를 선택합니다. 이 값이 다른 VM의 패킷을 복사해 주는 것은 아닙니다. 보통 스위치에서 같은 포트그룹에 있다는 사실만으로 다른 VM 간 유니캐스트가 전달되지는 않습니다.

1. 하이퍼바이저에서 관측할 VM/포트/VLAN과 트래픽 방향을 정합니다. 요청·응답을 모두 분석하려면 양방향을 미러링합니다.
2. 지원되는 포트 미러링/SPAN 기능의 목적지로 security의 **전용 감시 vNIC**를 지정합니다. 관리 vNIC와 구분하고, 원본 포트로 되돌아가는 루프를 만들지 않습니다.
3. 해당 제품이 요구하는 promiscuous/수신 정책을 감시 포트에만 적용합니다. promiscuous 허용만으로 미러링이 완성됐다고 판단하지 않습니다.
4. security에서 `ip -br link`와 MAC을 대조하고 실제 감시 NIC를 `deployment/site.local.conf`의 `MONITOR_INTERFACE`로 지정합니다.

감시 전용 NIC는 관리 주소·기본 경로 없이 운용할 수 있습니다. 기존 networkd Netplan의 `ethernets`에 다음과 같은 항목을 넣되, `enp2s0`는 실제 감시 NIC로 교체합니다.

```yaml
enp2s0:
  dhcp4: false
  dhcp6: false
  accept-ra: false
  link-local: []
  optional: true
```

Netplan 적용 후 `ip link show dev 실제감시NIC`에서 UP 상태를 확인합니다. DOWN이면 콘솔에서 `sudo ip link set dev 실제감시NIC up`으로 시험한 뒤 네트워크 관리자의 영구 설정도 확인합니다. 이 명령 한 번만으로 재부팅 후 상태를 보장하지 않습니다.

이 배포는 Suricata `-i NIC` 수동 IDS 방식이며 NFQUEUE나 AF_PACKET의 IPS bridge를 만들지 않습니다. [Suricata 캡처 인터페이스 옵션](https://docs.suricata.io/en/latest/command-line-options.html)을 참고합니다. 구축 후 승인된 클라이언트에서 정상 웹 요청을 보내 Suricata 인터페이스 RX/통계와 WAF 접근 로그가 증가하는지 대조합니다. 단순 SSH 트래픽만 보이는 경우 감시 경로를 다시 확인합니다.

## 5. 배포 계정과 SSH 공개키

**실행 위치: 세 서버 콘솔의 기존 관리자 계정.** 다음은 신규 배포 계정 `capdeploy`를 쓰는 예시입니다. 기존 `ubuntu` 계정을 쓸 때는 홈·그룹·권한을 확인하고 계정 생성 단계만 생략합니다. 배포 계정을 Docker 그룹에 추가할 필요는 없습니다.

```bash
sudo apt-get update
sudo apt-get install -y openssh-server sudo
sudo systemctl enable --now ssh
sudo timedatectl set-timezone Asia/Seoul
getent passwd capdeploy
```

`getent`에 계정이 없을 때만 다음을 실행합니다.

```bash
sudo adduser --disabled-password --gecos '' capdeploy
sudo install -d -m 0700 -o capdeploy -g capdeploy /home/capdeploy/.ssh
sudo -u capdeploy touch /home/capdeploy/.ssh/authorized_keys
sudo chmod 0600 /home/capdeploy/.ssh/authorized_keys
```

**실행 위치: 관리 컴퓨터.** 기존 승인된 SSH 키를 우선 사용합니다. `.pub` 파일 내용만 확인해 각 서버 콘솔로 전달합니다. 개인키를 서버·Git·채팅에 복사하지 않습니다.

```bash
ssh-keygen -lf "$HOME/.ssh/id_ed25519.pub"
cat "$HOME/.ssh/id_ed25519.pub"
```

기존 키가 없다면 운영자가 사용할 영구 키를 다음처럼 생성할 수 있습니다. 기존 파일이 있으면 덮어쓰지 않습니다. 이는 운영용 인증 자료이며 작업 종료 때 삭제할 패키지 임시파일과 다릅니다.

```bash
ssh-keygen -t ed25519 -a 64 -f "$HOME/.ssh/capstone_deploy"
ssh-add -t 1h "$HOME/.ssh/capstone_deploy"
```

키에 passphrase를 설정하고, 대화형 입력을 받지 않는 배포를 실행하기 전에 기존 ssh-agent에 unlock합니다. agent가 준비되지 않았다면 운영체제의 기존 SSH agent 환경을 먼저 준비합니다. Mac에 별도 키 관리 패키지를 설치하지 않습니다.

**실행 위치: 각 서버 콘솔.** `sudoedit`으로 공개키 한 줄을 추가합니다. 다른 키는 보존합니다.

```bash
sudoedit /home/capdeploy/.ssh/authorized_keys
sudo chown capdeploy:capdeploy /home/capdeploy/.ssh/authorized_keys
sudo chmod 0600 /home/capdeploy/.ssh/authorized_keys
sudo chmod go-w /home/capdeploy
sudo ssh-keygen -lf /home/capdeploy/.ssh/authorized_keys
sudo /usr/sbin/sshd -t
sudo /usr/sbin/sshd -T | awk '$1=="pubkeyauthentication" || $1=="usepam" || $1=="authorizedkeysfile"'
```

공개키 fingerprint가 관리 컴퓨터와 같고 `sshd -t`가 성공해야 합니다. SIEM은 `pubkeyauthentication yes`, `usepam yes`가 필요합니다. SSH 설정을 편집했다면 `sshd -t` 성공 후 `sudo systemctl reload ssh`로 반영합니다. 기존 인증 정책을 일괄 덮어쓰지 않습니다. [Ubuntu OpenSSH 설정·키 인증](https://documentation.ubuntu.com/server/how-to/security/openssh-server/)에 기본 동작이 설명돼 있습니다.

SIEM에 `AllowUsers/AllowGroups/DenyUsers/DenyGroups`가 적용돼 있으면 현재 설치기는 `manual_sshd_allowlist_review_required`로 멈춥니다. 새 `capstone-mcp` 계정을 만드는 절차와 충돌하기 때문입니다. 관리자가 해당 정책을 검토해야 하며 **기존 제한을 지우거나 계정을 추가하는 것만으로 현 검사에 통과한다고 안내하지 않습니다**. 이런 정책을 반드시 유지해야 하는 환경은 설치기 검사·정책 지원을 먼저 보완해야 합니다.

## 6. 22번 외 SSH 포트를 쓸 때

기본22를 유지하면 이 절을 건너뜁니다. 설치기는 세 서버가 **같은 SSH 포트**를 사용할 때만 지원하며, 대화형 질문에는 포트 입력이 없으므로 로컬 설정 파일에 `SSH_PORT=2222`처럼 명시합니다. 각 서버의 방화벽/ACL에 새 포트를 먼저 허용하고 콘솔을 유지합니다.

**실행 위치: 각 서버 콘솔.** 실제 적용 중인 포트 설정을 조회합니다.

```bash
sudo /usr/sbin/sshd -T | awk '$1=="port" || $1=="listenaddress"'
sudo systemctl cat ssh.socket
sudo systemctl is-active ssh.socket
```

기존 SSH 설정을 아래처럼 root 전용 경로에 백업합니다. host 개인키도 포함되므로 이 백업을 외부에 공유하지 않습니다.

```bash
sudo install -d -m 0700 /root/capstone-bootstrap-backups
sudo cp -a /etc/ssh "/root/capstone-bootstrap-backups/ssh-$(date +%Y%m%dT%H%M%S)"
```

`sudoedit /etc/ssh/sshd_config.d/10-capstone-port.conf`로 `Port 2222`를 넣습니다. 기존 다른 파일의 `Port`와 `ListenAddress`도 함께 검토합니다. `Port`는 복수 지정이 가능하므로 `.conf` 하나를 추가했다고 기존 포트가 닫혔다고 간주하지 않습니다.

```bash
sudo /usr/sbin/sshd -t
sudo /usr/sbin/sshd -T | awk '$1=="port" || $1=="listenaddress"'
```

Ubuntu24.04는 socket activation을 사용할 수 있고 systemd generator가 SSH 포트를 반영합니다. [Ubuntu의 socket activation 설명](https://discourse.ubuntu.com/t/sshd-now-uses-socket-based-activation-ubuntu-22-10-and-later/30189)을 참고해 실제 활성 방식에 맞는 다음 **한 분기**를 실행합니다.

```bash
# ssh.socket이 active인 경우: 서버 콘솔에서 실행
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket ssh.service
```

```bash
# ssh.socket이 비활성이고 ssh.service가 직접 수신하는 경우
sudo systemctl restart ssh.service
```

```bash
sudo ss -lntp
sudo systemctl status ssh.service --no-pager
```

목표 포트가 실제 LISTEN인지 확인합니다. 관리 컴퓨터에서 새 포트로 로그인 성공 후에만 기존 포트를 정책상 제거합니다. 실패하면 콘솔에서 SSH/소켓 설정을 복구하고 실제 리스너·상위 ACL을 조사합니다. `/usr/lib/systemd/system`의 배포판 unit을 직접 편집하지 않습니다.

## 7. Host key를 검증한 뒤 등록

**실행 위치: 각 서버의 신뢰할 수 있는 콘솔.** IP·역할과 함께 다음 fingerprint를 대조할 준비를 합니다.

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

**실행 위치: 관리 컴퓨터의 Bash.** 아래는 security 한 대의 예시이며 siem/service도 각각 반복합니다. 임시 파일에는 공개 host key만 저장합니다.

```bash
SERVER_IP=192.0.2.10
SERVER_SSH_PORT=22
hostkey_work=$(mktemp -d "${TMPDIR:-/tmp}/capstone-hostkey.XXXXXXXX")
ssh-keyscan -T 5 -p "$SERVER_SSH_PORT" -t ed25519 "$SERVER_IP" > "$hostkey_work/hostkey"
ssh-keygen -lf "$hostkey_work/hostkey"
```

**여기서 멈추고 콘솔 fingerprint와 사람이 대조합니다.** 일치하지 않거나 스캔이 비어 있으면 등록하지 않습니다. VM·IP·NAT·포트가 맞는지 조사하고 임시폴더만 삭제합니다. `ssh-keyscan`은 신뢰 검증 도구가 아니므로 성공 종료만으로 수락하지 않습니다.

일치하는 경우에만 등록합니다. 아래는 기존 `known_hosts`에 추가하는 예시입니다.

```bash
install -d -m 0700 "$HOME/.ssh"
touch "$HOME/.ssh/known_hosts"
chmod 0600 "$HOME/.ssh/known_hosts"
cat "$hostkey_work/hostkey" >> "$HOME/.ssh/known_hosts"
rm -f -- "$hostkey_work/hostkey"
rmdir -- "$hostkey_work"
unset hostkey_work
```

22번 외 포트는 자동으로 `[IP]:포트` 형식이 기록됩니다. 기존 항목과 충돌하면 VM 재설치 등 정당한 변경인지 콘솔에서 다시 확인합니다. 검증 전에 `ssh-keygen -R`로 기존 신뢰 기록을 지우거나 `StrictHostKeyChecking=no`로 우회하지 않습니다.

## 8. 설치 중에만 쓰는 sudo 준비와 접속 검증

**실행 위치: 각 서버 콘솔의 관리자.** 설치기는 컨테이너·계정·루트 소유 파일을 구성하므로 배포 계정의 비대화형 root 권한이 필요합니다. 이 권한은 Hermes/LLM 계정과 별개입니다.

```bash
sudo visudo -f /etc/sudoers.d/capstone-bootstrap
```

파일이 이미 있으면 내용을 확인하고 해당 배포의 정책인지 먼저 대조합니다. 신규 파일의 예시는 다음과 같습니다.

```sudoers
capdeploy ALL=(root) NOPASSWD: ALL
```

```bash
sudo chown root:root /etc/sudoers.d/capstone-bootstrap
sudo chmod 0440 /etc/sudoers.d/capstone-bootstrap
sudo visudo -cf /etc/sudoers
```

**실행 위치: 관리 컴퓨터.** 세 서버 각각에서 다음이 비밀번호 질문 없이 성공해야 합니다. 키 경로·계정·IP·포트를 교체합니다.

```bash
ssh -p 22 -i "$HOME/.ssh/capstone_deploy" \
  -o IdentitiesOnly=yes -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$HOME/.ssh/known_hosts" \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no \
  capdeploy@192.0.2.10 'set -e; id -un; sudo -n id -u; cat /etc/machine-id'
```

기대 출력은 `capdeploy`, `0`, 해당 VM의 machine-id입니다. 접속 실패 시 서버 콘솔에서 `sudo journalctl -u ssh.service --since '-10 min' --no-pager`를 확인합니다. 로그를 공유할 때 불필요한 사용자·주소 등은 가립니다.

| 증상 | 확인할 곳 |
|---|---|
| timeout/refused | 고정 주소, 경로·반환 경로, 서버 `ss -lntp`, 호스트/상위 ACL, SSH 포트 |
| host key verification failed | 위 콘솔 대조·known_hosts 경로·비표준 포트 기록 |
| permission denied (publickey) | 공개키 일치, 홈/.ssh/authorized_keys 소유자·권한, 계정·키 경로, agent unlock |
| sudo: a password is required | sudoers의 정확한 계정명, 파일0440/root 소유, `visudo -cf` 결과 |
| SIEM 구성 후 Hermes SSH만 실패 | SIEM 자신의 입력 IP/SSH 포트 경로, Hermes Docker 네트워크→호스트 INPUT 허용, `capstone-mcp` 강제 명령 설정 |

SIEM의 읽기 MCP는 컨테이너에서 호스트 자신의 SSH 포트에 접속하므로, SSH를 관리 컴퓨터 주소 하나에만 허용한 호스트 정책은 이를 막을 수 있습니다. 배포 후 실제 Hermes Docker 네트워크와 출발지 주소를 확인하여 그 경로도 허용합니다. 임의의 전체 Docker 대역이나 모든 외부 주소를 허용하지 않습니다.

## 9. 로컬 설정으로 옮기고 사전검사

**실행 위치: 관리 컴퓨터의 저장소 루트.** `deployment/site.local.conf`는 비밀 값 없이 실제 경로와 주소만 적으며 Git에서 제외됩니다.

```bash
set -e
umask 077
test ! -e deployment/site.local.conf
test ! -L deployment/site.local.conf
cp deployment/config.example.conf deployment/site.local.conf
chmod 0600 deployment/site.local.conf
```

파일이 이미 있으면 위 복사 절차는 중단됩니다. 기존 설정을 확인하고 편집하며 덮어쓰지 않습니다. 편집기로 세 주소, `SSH_USER=capdeploy`, 공통 포트, 개인키 절대 경로, known_hosts 절대 경로, 감시 NIC, LLM 주소·모델을 반영합니다. Mac의 키 경로 예시는 `/Users/운영자/.ssh/capstone_deploy`입니다. 설정 파일은 `$HOME`, `~`, 따옴표, 명령 치환을 확장하지 않습니다.

```bash
bash deploy.sh --plan --batch --config deployment/site.local.conf
bash deploy.sh --check --batch --config deployment/site.local.conf
```

`--plan`은 입력 형식만, `--check`는 SSH·OS·수동 자료 준비를 검사합니다. 패키지/이미지 자료가 아직 없으면 다음 README 절차를 완료한 뒤 다시 실행합니다. `--check` 성공이 미러링·전체 서비스·LLM 응답의 종단 간 검증은 아닙니다.

## 10. 구축·검증 후 임시 관리자 권한 회수

`--apply`와 `--verify`가 끝난 뒤 **다른 관리자/콘솔 접근을 확보한 상태에서** 이번에 추가한 sudoers 파일만 제거합니다. 서비스 계정·agent 키·컨테이너·운영 데이터는 정리 대상이 아닙니다.

```bash
# 각 서버 콘솔의 별도 관리자 계정에서 실행
sudo rm -- /etc/sudoers.d/capstone-bootstrap
sudo visudo -cf /etc/sudoers
```

관리 컴퓨터에서 `ssh ... 'sudo -n id -u'`가 거절되는지 확인합니다. 계속 성공하면 기존 sudo 그룹/다른 sudoers에서 권한을 받는지 관리자가 확인합니다. 기존 정책을 임의로 삭제하지 않습니다. 배포 전용 공개키도 더 이상 쓰지 않으면 해당 키 한 줄만 `authorized_keys`에서 제거합니다.

이후 `deploy.sh --verify`도 root 조회 권한을 요구하므로, 권한을 회수한 상태에서는 해당 명령이 중단되는 것이 정상입니다. 정기 관리에 필요하면 승인된 관리 계정으로 검증하거나 설치 작업 때만 임시 권한을 다시 준비합니다. 서버 복구용 Netplan/SSH 백업과 운영용 키는 보존하고, 이번 host-key 수집용 임시폴더가 남지 않았는지 확인합니다.
