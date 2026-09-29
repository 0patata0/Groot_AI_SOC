# 로컬 apt 레포 패키지 목록 — Agentic SOC (noble/amd64)

> 대상: Ubuntu **24.04(noble) / amd64**. 내부망 임시 apt 레포에 미리 담을 후보를 역할별로 정리.
> 용도: 인터넷 되는 곳에서 `apt-get install --download-only <목록>`(또는 `debmirror`/`apt-mirror` 필터)로 받아 `dpkg-scanpackages` 색인 → 내부망 HTTP 서빙 → B/C(및 A) `ubuntu.sources` 지정.
> **의존성은 apt 가 자동으로 끌어옴** → 아래는 최상위 패키지만.
>
> 등급: **[필수]** 역할에 직접 · **[권장]** 방어/운영 유용 · **[선택]** 상황따라 · **[주의]** 이중용도/공격표면↑(필요 호스트에만) · **[확인]** noble 존재 여부 빌드 시 확인.
> 실측(2026-09-29): 아래 "이미 설치됨"은 A·C 에 있어 **to-download 목록에서 제외**. 표의 패키지는 전부 현재 **미설치**.

---

## 0. 원칙 (먼저)
- **egress 차단**: 도구는 오프라인 동작하되 **시그니처·룰·피드는 오프라인 반입** 필요(ClamAV 시그니처, YARA 룰, Trivy DB). 외부 whois/위협인텔은 도달 제한.
- **자격증명 격리**: 에이전트에 직접 주지 말고 **서버(A 응답 MCP / B 읽기 MCP) 툴로 감싸** 노출. 파괴적·고위험 동작은 **Tier 2 사람 승인**. 자동은 되돌릴 수 있는 것만.
- **공격표면 최소화**: [주의] 도구는 게이트웨이(A)에 블랭킷 설치 금지, 필요한 호스트에만.
- **공격 도구는 여기 없음**: 침투/공격 툴(nmap 제외)은 Kali(공격 담당) 몫. 이 레포는 A/B/C **방어·조사용**.
- **IPS/WAF는 컨테이너**: Suricata·ModSecurity 는 apt 아님(Docker 이미지, §외부). 네이티브 전환 시에만 `suricata` 등 추가.

## 이미 설치됨 → 레포엔 선택(재설치·신규호스트용, to-download에선 제외)
`nftables` `iptables` `chrony` `openssh-server` `ca-certificates` `gnupg` `curl` `wget` `net-tools` `tcpdump` `jq` `rsync` `python3` `unattended-upgrades` `needrestart`

---

## 1. 대응·차단 강화 (block_ip 실효성)
| 패키지 | 역할 | 등급 |
|---|---|---|
| `conntrack` | 차단 시 **기존 세션 강제 종료**(nft drop 누수 방지) | [필수급] |
| `ipset` | 대량 IP 블록리스트 | [선택] |
| `fail2ban` | 반복 공격 IP 호스트층 자동 차단 | [권장] |
| `auditd` `audispd-plugins` | 커널 감사(실행·인증·파일) → Wazuh 탐지·조사 근거 | [권장] |

## 2. 침해 조사·헌팅
| 패키지 | 역할 | 등급 |
|---|---|---|
| `yara` | 로컬 룰 IOC 매칭(멀웨어 헌팅) | [권장] 룰 반입 |
| `clamav` `clamav-daemon` `clamav-freshclam` | 오프라인 AV | [권장] 시그니처 반입 |
| `tshark` `tcpflow` `ngrep` | pcap/스트림 분석(현재 tcpdump만) | [권장] |
| `tcpreplay` | pcap 재생(탐지 룰 검증) | [선택] |

## 3. DFIR·포렌식 (사고 대응·증거)
| 패키지 | 역할 | 등급 |
|---|---|---|
| `testdisk` | 파티션/파일 복구(photorec 포함) | [선택] |
| `dcfldd` `ewf-tools` | 포렌식 이미징·EWF 처리 | [선택] |
| `hashdeep` `ssdeep` | 재귀 해시·퍼지 해시(알려진/유사 파일 매칭) | [권장] |
| `libimage-exiftool-perl` | 파일 메타데이터 추출 | [선택] |
| `foremost` `binwalk` `bulk-extractor` | 파일 카빙·특징 추출 | [선택] |
| `sleuthkit` | 디스크 포렌식(fls/icat 등) | [선택] |

## 4. 정적·멀웨어 분석
| 패키지 | 역할 | 등급 |
|---|---|---|
| `radare2` | 리버싱·바이너리 분석 | [선택] |
| `pev` | PE 파일 분석 | [선택] |
| `upx-ucl` | 패킹 바이너리 언패킹 | [선택] |
| `binutils` `file` | objdump·파일 식별(대개 base) | [선택] |

## 5. 네트워크 보안 모니터링(NSM)·탐지 보강
| 패키지 | 역할 | 등급 |
|---|---|---|
| `arpwatch` | ARP 변화 감시(내부망 ARP 스푸핑 탐지) | [권장] |
| `p0f` | 수동 OS 핑거프린팅 | [선택] |
| `iptraf-ng` `vnstat` | 실시간 트래픽·통계 | [선택] |
| `python3-scapy` | 패킷 크래프팅/분석(탐지 툴 작성) | [주의] 이중용도 |

## 6. 무결성·하드닝·감사
| 패키지 | 역할 | 등급 |
|---|---|---|
| `debsums` | 설치 패키지 파일 변조 체크섬 검증 | [권장] |
| `lynis` | 보안 감사·하드닝 권고 | [권장] |
| `rkhunter` `chkrootkit` | 루트킷 점검 | [선택] |
| `aide` `aide-common` | 파일 무결성(Wazuh FIM 일부 중복) | [선택] |
| `apparmor-utils` `apparmor-profiles-extra` | AppArmor(응용 격리·allowlisting) | [선택] |
| `openscap-scanner` | SCAP 취약·컴플라이언스 스캔 | [선택] |
| `acct` | 프로세스 계정(사후 추적) | [선택] |
| `libpam-pwquality` `libpam-google-authenticator` | 암호정책·SSH 2FA(예방) | [선택] |
| `acl` | 세분 파일권한 | [선택] |
| `usbguard` | USB 장치 제어(물리 접근 시) | [선택] |
| `age` | 파일 암호화(증거·비밀 보관) | [확인] |

## 7. 예방·패치 운영 (핵심 2개는 이미 설치)
| 패키지 | 역할 | 등급 |
|---|---|---|
| `apt-listchanges` `debsecan` `apticron` | 변경점·취약점 요약·알림 | [선택] |

## 8. 평가·데이터 분석 (3단계 MTTI/MTTR 실측·그래프)
| 패키지 | 역할 | 등급 |
|---|---|---|
| `python3-pandas` `python3-numpy` | 지표 집계·통계 | [권장] |
| `python3-matplotlib` `gnuplot` | 결과 그래프 | [권장] |
| `hyperfine` | 명령 지연·처리량 벤치(tok/s·응답시간 측정) | [권장] noble 확인됨 |
| `datamash` `csvkit` | CLI 통계·CSV 처리 | [선택] |

## 9. 로그·스크립트 라이브러리 (서버·MCP 확장)
| 패키지 | 역할 | 등급 |
|---|---|---|
| `python3-yaml` `python3-requests` `python3-dateutil` | 설정·내부 HTTP·시각 | [권장] |
| `python3-jinja2` | 리포트 템플릿 | [선택] |
| `moreutils` `ripgrep` `sqlite3` | 로그 파이프(ts)·고속 검색·경량 DB | [선택] |

## 10. 네트워크 진단·자산 점검
| 패키지 | 역할 | 등급 |
|---|---|---|
| `dnsutils` | dig/nslookup | [권장] |
| `mtr-tiny` `iftop` `nload` `ethtool` | 경로·대역·NIC | [선택] |
| `socat` `netcat-openbsd` | 소켓 테스트·응급 통신 | [선택] |
| `bridge-utils` | 브리지 관리 | [선택] |
| `whois` | 등록정보(egress 차단으로 제한적) | [선택] |
| `nmap` | 내부 자산·포트 점검(방어측) | [주의] 지정 호스트만 |

## 11. 컨테이너·이미지 운영
| 패키지 | 역할 | 등급 |
|---|---|---|
| `skopeo` | **데몬 없이 이미지 반입·검사·복사**(커스텀 puller 대체) | [권장] |
| `docker.io` `containerd` `docker-compose-v2` | apt 기반 Docker(정적 대신 쓸 경우) | [선택] 현재 정적 |
| `podman` `buildah` | 데몬리스 대안 | [선택] |

## 12. 시스템 운영·관측
| 패키지 | 역할 | 등급 |
|---|---|---|
| `vim` `tmux` `less` `tree` `lsof` | 편집·세션·탐색 | [선택] |
| `htop` `atop` `iotop` `nmon` `sysstat` | 자원·성능 모니터 | [선택] |
| `git` | 설정·스크립트 버전관리 | [선택] |
| `strace` `ncdu` `unzip` | 추적·디스크·압축 | [선택] |
| `borgbackup` (또는 `restic`) | 설정·증거 백업(중복제거) | [선택] |

## 13. 빌드/개발 (필요할 때만)
| 패키지 | 역할 | 등급 |
|---|---|---|
| `build-essential` `python3-dev` `python3-venv` `python3-pip` `pkg-config` `libssl-dev` | 소스 빌드·확장·격리 파이썬 | [주의] A(게이트웨이) 지양, 빌드 전용 호스트에 |

---

## 부록 A. 다운로드용 평문 목록 (등급별, 이미 설치분 제외)

### 코어 (방어 실효성 + 조사·평가 기본) — 우선 반입
```
conntrack ipset fail2ban auditd audispd-plugins dnsutils
yara clamav clamav-daemon clamav-freshclam tshark tcpflow ngrep tcpreplay
hashdeep ssdeep debsums lynis rkhunter chkrootkit
python3-yaml python3-requests python3-dateutil skopeo
python3-pandas python3-numpy python3-matplotlib hyperfine
arpwatch apparmor-utils
```

### 선택 (포렌식·하드닝·운영·진단)
```
testdisk dcfldd ewf-tools libimage-exiftool-perl foremost binwalk bulk-extractor sleuthkit
radare2 pev upx-ucl p0f iptraf-ng vnstat
aide aide-common apparmor-profiles-extra openscap-scanner acct acl usbguard age
libpam-pwquality libpam-google-authenticator apt-listchanges debsecan apticron
python3-jinja2 moreutils ripgrep sqlite3 datamash csvkit gnuplot
mtr-tiny iftop nload ethtool socat netcat-openbsd bridge-utils whois
vim tmux less tree lsof htop atop iotop nmon sysstat git strace ncdu unzip borgbackup
```

### 주의 (이중용도/공격표면 — 필요한 호스트에만)
```
nmap python3-scapy docker.io containerd docker-compose-v2 podman buildah
build-essential python3-dev python3-venv python3-pip pkg-config libssl-dev
```

## 부록 B. apt 밖 — 외부 반입(레포 대상 아님)
- **컨테이너 취약점 스캔**: `trivy`(GitHub .deb/바이너리), `grype`·`syft`(SBOM, 바이너리), `dive`(이미지 레이어). Trivy DB 는 오프라인 반입.
- **NSM(고급)**: `zeek`(Ubuntu 기본 저장소에 없음 — Zeek OBS 저장소. noble 엔 `zeek-aux`·`zkg`만). 현재는 Suricata 컨테이너로 커버.
- **메모리/타임라인 포렌식**: `volatility3`, `plaso`(log2timeline) — pip 설치(apt 아님).
- **Docker Engine/Compose**: 현재 정적 바이너리 v29.8.1(`/usr/local/bin`).
- **Wazuh 에이전트**: `wazuh-agent` 4.14.8 `.deb`(Wazuh 저장소).
- **보안 스택 이미지(tar)**: `jasonish/suricata:latest`(IPS), `owasp/modsecurity-crs:nginx`(WAF), `nginx:1.27-alpine`. + Suricata ET Open 룰셋.
- **오프라인 데이터**: ClamAV 시그니처, YARA 룰, Trivy DB, (반입됨) CISA KEV.
