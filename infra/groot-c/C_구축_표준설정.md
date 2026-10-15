# Groot_C 구축 표준설정 (A·B와 맞추기 위한 핸드오프)

> 목적: A·B에서 이미 표준화한 설정을 C도 동일하게 맞추기 위한 문서.
> 다루지 않는 것: 각자 로컬 PC의 접속 편의(예: `~/.ssh/config`, `/etc/hosts` 별칭)는 개인 설정이라 제외.
> 최초 구축 확인일: 2026-09-25 기준 (A·B 실동작 확인 완료). 아래 설치 단계의 외부 NIC·DNS·직접 접속 설명은 그 시점의 이력이다.
> **현황(2026-10-06 기록 및 이번 SSH 재확인):** C의 `ens192` vNIC는 제거됐고 `ens160=10.200.10.20`의 기본 경로는 A(`10.200.10.1`)다. netplan에는 DNS 서버를 넣지 않았고 내부 이름은 `/etc/hosts`를 쓴다. Apache·Wazuh 에이전트 002는 Active, DVWA는 302, `log4shell-lab`은 `10.200.10.20:8080`에서 가동 중이며 NTP 동기화도 확인됐다. [기존 기록](../../대화기록/2026-10-06.md)

> **2026-10-08 관리 SSH 직접 재확인:** 내부 NIC만 사용하고 A 경유 기본 경로·KST/NTP 동기화가 유지된다. Apache·Docker·Wazuh agent active, DVWA 로그인 HTTP 200, B 매니저 1514/tcp 연결 ESTAB이다. `log4shell-lab`은 내부 주소 8080에서 HTTP 400으로 응답했으며 취약점 기능 재현까지 확인한 것은 아니다. [오늘 기록](../../대화기록/2026-10-08.md)


> **2026-10-15 13:20 KST UI 적용·직접 확인:** 기존 Apache/PHP에 `/log4shell/` 요청 실습 화면을 추가했다. 접속은 **http://192.168.16.230/log4shell/** 이며 정상 헤더200·헤더누락400, 응답·KST·브라우저 최근20개를 확인할 수 있다. 실제 HTTP9검사와 브라우저 두 요청을 통과했고 C Apache/Docker/Wazuh active·DVWA200·기존 내부8080 컨테이너와 A 경로가 유지된다. 새 패키지·컨테이너·서비스 재시작·방화벽 변경은 없다. 신규 환경용 루트 설치기는 별도 Docker internal lab 구성으로 같은 UI를 제공하며, 새 VM 실제 구축과 공격 탐지 E2E는 미실행이다. [사용·회수 안내](log4shell-ui/README.md) · [검증 기록](log4shell-ui/deployment-validation-20261015.json).

---

## 0. ⚠️ 가장 먼저 알아야 할 환경 제약 — 이 망은 웹이 막혀 있다

이 VM망(임시 외부 `192.168.16.0/24`)은 **나가는 웹 트래픽(TCP 80/443)이 전면 차단**되어 있다.
- `ping 8.8.8.8`(ICMP)·DNS(UDP 53)는 되지만, **`apt update`/`apt install`/`docker pull`은 전부 타임아웃**으로 실패한다.
- 목적지 무관(naver·github·docker hub·국내미러 전부 차단) = **포트 기준 차단**.
- 실제로 나가는 outbound 포트는 6개뿐: `123, 587, 853, 873, 990, 1194`. (80/443/22/11434 전부 차단)

**결론: C의 모든 패키지·컨테이너 이미지는 "오프라인 반입"으로 설치해야 한다.** (아래 4·5절 방식 그대로)
- 인터넷 되는 PC에서 파일을 받아 `scp`로 VM에 넣고 로컬 설치.
- 근본 해결(온라인 pull)은 관리자에게 (a) 443 허용 또는 (b) HTTP(S) 프록시 주소를 받아야 함 → 받기 전까진 오프라인.

---

## 1. VM 기본 정보 (C)

| 항목 | 값 |
|---|---|
| VM 이름 | `2026_capstone_Groot_C` |
| OS | Ubuntu Server **24.04.5** LTS (live server, amd64) |
| 사용자명 | `groot_c` |
| 호스트명 | `groot-web` (역할 기반 — sec/siem/web 규칙) |
| 비밀번호 | 팀 공용 규칙 (`CREDENTIALS.local.md` 참조, 격리랩 전용) |
| 역할 | 웹 취약/서비스 서버 — **DVWA(베어메탈, 이미 설치됨) + CVE 랩(컨테이너)** = 하이브리드 |
| SSH | 설치 단계에서 **openssh-server 포함 설치** |

- 호스트명 영구 적용 확인: `hostnamectl` → `Static hostname: groot-web`.

---

## 2. 네트워크 (A·B와 동일 규칙)

### 2-1. NIC 역할 (설치 당시 어댑터 2개; 현재 `ens160`만)
| NIC | 역할 | C의 주소 |
|---|---|---|
| `ens160` | **내부망** (10.200.10.0/24) — 프로젝트 상시 사용 | `10.200.10.20/24` |
| `ens192` | **옛 임시 외부망** (192.168.16.0/24) — 설치 당시 사용, 현재 제거 완료 | 옛 주소 `192.168.16.232/24` |

- 임시외부 게이트웨이: `192.168.16.129` (정상 GW MAC = `f4:cf:e2:4c:8f:7e`)
- 설치 당시 DNS: `168.126.63.1` (KT). 현재 C netplan에는 DNS 서버가 없다.
- 내부 IP 배정: A=10.200.10.1(현재 게이트웨이) / B=10.200.10.10 / **C=10.200.10.20**
- 설치 당시 임시외부 IP는 이후 재배정돼 C의 마지막 외부 IP가 `.232`였고, 현재는 제거됐다.

### 2-2. netplan — 설치/구축 단계 (인터넷 필요할 때)
```yaml
# /etc/netplan/00-installer-config.yaml  (권한 600)
network:
  version: 2
  ethernets:
    ens160:                      # 내부망 (기본 라우트 없음, 주소만)
      addresses: [10.200.10.20/24]
    ens192:                      # 임시 외부망 (기본 라우트 + DNS는 여기만)
      addresses: [192.168.16.232/24]
      routes:
        - to: default
          via: 192.168.16.129
      nameservers:
        addresses: [168.126.63.1]
```
설치 당시 적용: `sudo netplan apply` (아래 NIC 변경 이력 참고). 현재 운영 설정은 다음 절을 따른다.

### 2-3. netplan — 현재 운영 단계
- `ens192`는 A만 남고 B·C에서는 제거 완료. C의 기본 게이트웨이는 A(NAT) `10.200.10.1`이다. 2026-10-02 라이브 기록상 C netplan에는 DNS 항목이 없다.
```yaml
network:
  version: 2
  ethernets:
    ens160:
      addresses: [10.200.10.20/24]
      routes:
        - to: default
          via: 10.200.10.1        # A(Groot_A) NAT 게이트웨이
```

### 2-3-1. 내부 이름 해석 `/etc/hosts` (A·B·C 적용 완료)
서비스·에이전트 설정이 임시 NIC와 무관하게 내부 IP 이름을 쓰도록 세 VM 모두에 추가:
```
# capstone internal (10.200.10.0/24, VLAN40)
10.200.10.1   groot-sec  groot-a
10.200.10.10  groot-siem groot-b
10.200.10.20  groot-web  groot-c
```
- 확인: `getent hosts groot-siem` → `10.200.10.10`. (자기 자신 이름은 Ubuntu 기본 `127.0.1.1` 항목이 먼저 잡혀도 무방)
- 이후 C의 Wazuh 에이전트는 매니저를 **`groot-siem`(10.200.10.10:1514)** 으로 지정.
- 운영자 접속(최종): 외부에서 C 직접 접속 없음. Mac에서 `ssh groot-c-int`(A 경유 점프). DVWA 는 브라우저로 `http://dvwa.groot.lab`(A WAF 경유). (구 루프백 터널 `localhost:18080` 은 2026-09-28 제거 — 운영자 루프백 사용 불가)

### 2-4. ⚠️ 네트워크 변경 시 주의 (A·B에서 실제로 겪음)
- 설치 당시 NIC/포트그룹 변경에서는 콜드부트가 필요했던 사례가 있었다. 다만 2026-10-02 B/C `ens192` 물리 제거는 ESXi 핫언플러그로 완료됐고 게스트에서 NIC가 사라진 것을 확인했다.
- IP 충돌 주의: 같은 대역에 이미 그 IP를 쓰는 호스트가 있으면 GW MAC 오학습·`ENOBUFS`·ping 100% 손실 발생. (B가 .231에서 충돌 → .233으로 해결한 이력)
- 진단 팁: `ip neigh show <gw>` 로 GW MAC이 `f4:cf:e2:4c:8f:7e`인지 확인.

---

## 3. Docker 오프라인 설치 (버전 고정 — A·B와 동일)

이 절의 외부 IP로 직접 `scp`하는 명령은 **설치 당시 기록**이다. 현재 C의 외부 NIC는 제거돼 그 주소로 전송할 수 없으며, 필요 시 A 경유 내부 IP 접속 경로를 사용한다.

**고정 버전**: Docker Engine **29.8.1**, Docker Compose 플러그인 **v5.5.1**. (C도 이 버전으로 맞춘다)

### 3-1. 인터넷 되는 PC에서 파일 3개 준비
```bash
# ① Docker static 바이너리 번들 (dockerd·containerd·runc·CLI 일체)
curl -fSL https://download.docker.com/linux/static/stable/x86_64/docker-29.8.1.tgz -o docker-29.8.1.tgz
# ② Compose 플러그인 (정적 바이너리)
curl -fSL https://github.com/docker/compose/releases/download/v5.5.1/docker-compose-linux-x86_64 -o docker-compose-linux-x86_64
# ③ 검증용 hello-world 이미지 tar (인터넷 PC에 docker 있으면 이게 제일 쉬움)
docker pull --platform linux/amd64 hello-world && docker save hello-world:latest -o hello-world.tar
#   (인터넷 PC에 docker가 없으면 registry API로 조립해야 함 — 필요하면 A/B 담당에게 hello-world.tar 요청)
```
→ 세 파일을 C로 전송: `scp docker-29.8.1.tgz docker-compose-linux-x86_64 hello-world.tar groot_c@192.168.16.232:/tmp/`

### 3-2. C에서 설치 (아래 스크립트를 `/tmp/install_docker.sh`로 저장 후 `sudo bash`)
```bash
#!/bin/bash
set -e
cd /tmp
# 1) static 바이너리 배치
tar xzf /tmp/docker-29.8.1.tgz
install -m 0755 /tmp/docker/* /usr/local/bin/
# 2) compose 플러그인
install -d -m 0755 /usr/local/lib/docker/cli-plugins
install -m 0755 /tmp/docker-compose-linux-x86_64 /usr/local/lib/docker/cli-plugins/docker-compose
# 3) 커널 모듈
modprobe overlay || true; modprobe br_netfilter || true
printf 'overlay\nbr_netfilter\n' > /etc/modules-load.d/docker.conf
# 4) docker 그룹 + 사용자 (C는 groot_c)
groupadd -f docker
usermod -aG docker groot_c
# 5) systemd 유닛 (정적 설치용 최소 유닛 — dockerd가 내장 containerd 자동 기동)
cat > /etc/systemd/system/docker.service <<'UNIT'
[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/dockerd
ExecReload=/bin/kill -s HUP $MAINPID
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
TasksMax=infinity
Delegate=yes
KillMode=process
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
# 6) 기동
systemctl daemon-reload
systemctl enable --now docker
# 7) 검증
systemctl is-active docker
docker --version
docker compose version
docker load -i /tmp/hello-world.tar
docker run --rm hello-world | head -4
# 8) 정리
rm -rf /tmp/docker /tmp/docker-*.tgz /tmp/docker-compose-linux-x86_64 /tmp/hello-world.tar
```

### 3-3. 설치 전 사전 확인 (A·B에서 통과한 항목 — C도 동일해야 함)
```bash
which iptables nft            # /usr/sbin/iptables, /usr/sbin/nft 있어야 함
for m in overlay br_netfilter bridge; do modinfo -F filename $m; done   # 3개 모두 존재
uname -m                      # x86_64
df -h /                       # 여유 공간 충분
```
- 기대 결과: `Docker version 29.8.1`, `Docker Compose version v5.5.1`, `Hello from Docker!` 출력.
- 설치 후 `groot_c`가 sudo 없이 `docker` 쓰려면 **한 번 재로그인**(docker 그룹 반영).

---

## 4. net-tools (선택 — 편의)

아래 외부 IP `scp` 명령도 설치 당시 기록이다. 현재는 A 경유 내부 IP 경로를 사용한다.
- `ifconfig/netstat/route/arp` 쓰려면 설치. **오프라인**이라 deb 직접 반입:
```bash
# 인터넷 PC에서
curl -fSL http://archive.ubuntu.com/ubuntu/pool/main/n/net-tools/net-tools_2.10-0.1ubuntu4.4_amd64.deb -o net-tools.deb
scp net-tools.deb groot_c@192.168.16.232:/tmp/
# C에서 (의존성은 libc6뿐 — 이미 있음)
sudo dpkg -i /tmp/net-tools.deb && rm /tmp/net-tools.deb
```

---

## 5. C 진행자 완료 체크리스트
- [x] VM 이름 `2026_capstone_Groot_C`, OS Ubuntu 24.04.5, user `groot_c`, host `groot-web`
- [x] SSH(openssh) 접속 됨 (옛 직접 경로 `192.168.16.232`는 종료; 현재 A 경유 내부 IP로 접속)
- [x] netplan: ens160=10.200.10.20, default via A(10.200.10.1), DNS 설정 없음; ens192 vNIC 제거(2026-10-02~06 기록)
- [x] 설치 당시 NIC 변경은 콜드부트로 적용·GW MAC/충돌을 확인. 이후 B/C 외부 NIC는 핫언플러그로 제거(2026-10-02 기록)
- [x] Docker **29.8.1** 설치 (2026-09-26 확인)
- [x] (선택) net-tools 설치
- [x] DVWA: **베어메탈로 이미 설치·구동 중** (재설치·컨테이너화 X — 그대로 유지). `/dvwa/` 200
- [x] CVE 랩 컨테이너: `log4shell-lab`(`log4shell-vulnerable-app:latest`, :8080) 가동 중
- [x] Wazuh 에이전트 4.14.8 → `10.200.10.10:1514`(내부망) **ID 002 groot-web Active**, apache access/error 수집(`apache` 포맷), journald, SCA/rootcheck
- [ ] 시나리오 전: DVWA 기본 보안레벨이 `impossible`(config.inc.php) → 공격 시나리오용 `low`로(환경변수 `DEFAULT_SECURITY_LEVEL` 또는 설정 파일)

## 7. 연동 확인·보완 (2026-09-26, A/B 담당이 C에 적용 — `infra/groot-c/c_integrate.sh`)
확인된 것(변경 없음): 에이전트 002 Active·인벤토리(764 패키지, 포트)·취약점 상태 2,422건이 B에 인덱싱, MCP 툴에서 C 조회 성공, B 웹 룰(31101 4xx / 31103 SQLi / 31105 XSS)이 C의 access.log로 실제 발생.

적용한 것 2가지(백업 `/etc/hosts.bak.*`):
1. `/etc/hosts` 내부 이름 추가: `10.200.10.1 groot-sec groot-a` / `10.200.10.10 groot-siem groot-b` / `10.200.10.20 groot-web groot-c` (A·B와 동일).
2. **apache `mod_remoteip`** (`/etc/apache2/conf-available/capstone-remoteip.conf`: `RemoteIPHeader X-Forwarded-For`, `RemoteIPInternalProxy 10.200.10.1`). 이유: 공격 트래픽은 A의 WAF(nginx)를 거쳐 오고 WAF 컨테이너는 A의 내부 IP(10.200.10.1)로 SNAT되므로, 이게 없으면 **access.log·Wazuh 경보의 srcip가 전부 10.200.10.1(A)** — 나중에 자동 차단이 A 자신을 막는 사고가 됨(실측). 적용 후 실제 클라이언트 IP(예: 192.168.16.231)로 기록·경보됨을 확인. 직접 접속(127.0.0.1 등)은 그대로 실제 피어.
3. 시계(최종, 사용자 결정): **A ← 캠퍼스 시간 서버 192.168.16.131(chrony), C ← A(10.200.10.1, systemd-timesyncd)**. 외부 NTP는 캠퍼스가 UDP 123을 차단해 불가. C에는 `/etc/systemd/timesyncd.conf.d/capstone.conf`(NTP=10.200.10.1)가 있고 VMware Tools timesync는 **꺼 둠**(두 소스 충돌 방지). 적용 스크립트 `infra/ntp_client.sh`. **C에서 Tools timesync를 다시 켜거나 다른 NTP를 넣지 말 것.** 확인: `timedatectl timesync-status` → Server 10.200.10.1, Packet count ≥ 1. (ens192 제거 후에도 내부망 경로라 그대로 동작)

참고: C 에이전트의 active-response는 기본값(enabled)인데 매니저에 트리거가 없어 동작하지 않음. 설계상 대응은 MCP→A nftables로 하므로 그대로 둠(필요 시 A처럼 disabled로).

---

## 6. 보안 주의 (팀 공통)
- VM 공용 비번(값은 `CREDENTIALS.local.md`)은 약한 랩 전용 값 = **격리 랩 전용**. 공개 저장소 push 전 강한 비번으로 교체. 문서·스크립트에 비번 리터럴을 쓰지 않는다.
- 자격증명(Wazuh API 등)은 `.env`/MCP Server 환경변수로만. 평문 커밋 금지. (비번·IP 등 민감정보는 `CREDENTIALS.local.md` = gitignore)
- 현재 C netplan에는 DNS 서버가 없고, 내부 호스트명은 `/etc/hosts`를 쓴다. 위 KT DNS 설명은 설치 당시 설정 이력이다.
