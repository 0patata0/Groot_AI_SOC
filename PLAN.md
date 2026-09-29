# Agentic SOC 구축 실행 계획 (ESXi 온프레미스)

제안서: [suggestion.md](suggestion.md) · 검토메모: [suggestion_review.md](suggestion_review.md) · 시뮬레이션: [simulation_report.md](simulation_report.md)
변경 배경: `plan_changed.md`로 인프라를 AWS에서 ESXi 온프레미스로 전환. 이전 AWS 계획 백업: `대화기록/PLAN_aws_backup_2026-09-22.md`

이 문서는 실행 순서·체크리스트·진행 로그를 관리한다. 작업마다 체크박스와 진행 로그를 갱신한다.

---

> **한 장 요약은 [STATUS.md](STATUS.md)** (라이브 헬스·접속 치트시트·다음 할 일).

## 현재 상태 (2026-09-27)

- 인프라 구축 진행 중(순차). VM 3대(Ubuntu 24.04.5) 생성 완료.
- **A**: Docker(오프라인)·**NAT 게이트웨이 완료**·**Wazuh Agent(001 Active)**·**Suricata IDS + ModSecurity WAF 배치·검증 완료(2026-09-26)** → eve.json/audit.log가 Wazuh로 흐름.
- **B**: **Wazuh 4.14.8 스택 기동 완료**(비번 통일) + A 보안스택용 로컬 룰(`infra/groot-b/local_rules.xml`) 적용·경보 인덱싱 검증 완료.
- ⚠️ 운영 제약(2026-09-26 실제 발생): **공격성 테스트 트래픽을 캠퍼스 VPN 경유로 보내면 캠퍼스 FW가 (VPN IP↔A) 쌍을 차단**해 A 관리접속이 끊김. IDS/WAF 테스트는 반드시 Kali/B/C 등 **VM 세그먼트 안**에서. A 복구 경로: `ssh -J groot-b groot_a@10.200.10.1`.
- **C**: OS·네트워크·DVWA(베어메탈)·**Docker+log4shell-lab 완료**, **Wazuh Agent 002 Active**·취약점 2,422건 인덱싱. Log4Shell 랩은 **C 내부 전용 격리**(시나리오 때만 A 경유 토글).
- **MCP**: 읽기 서버(B, `ssh -T groot-mcp`) + **응답 서버(A, `ssh -T groot-resp`, block_ip→agent_block) 배치·계약 테스트 완료(2026-09-27)**. 클라이언트 설정은 각 한 줄(런타임 불가지론). 런타임(Claude Code vs Hermes) 결정은 보류.
- 제약: 이 망 outbound 웹(80/443)·DGX(11434) 전면 차단 → 모든 반입 오프라인. DGX 연결 보류(관리자 permit 대기).
- 주요 결정 확정: LLM=DGX Spark(A-1)/보류 시 로컬 Ollama, 오케스트레이션=Docker Compose(B-1), 보안장비=nftables/Suricata/ModSecurity+CRS, Wazuh=4.14.8.

---

## 1. 아키텍처 (ESXi 호스트)

ESXi 호스트 위에 VM 3대 + 공격자 노트북. 컨테이너로 각 역할 구현.

```
        [ 공격자 노트북 : Kali ]
                  │  (공격 트래픽)
                  ▼
  ┌───────────────────────────────────────────────────┐
  │                 ESXi 호스트                         │
  │                                                    │
  │  ┌──────────────────────────┐                      │
  │  │ 2026_capstone_Groot_A          │  ← 네트워크 관문/검사 │
  │  │  보안장비 (Docker)         │                      │
  │  │  ├─ FW  (nftables/OPNsense)│                     │
  │  │  ├─ IPS (Suricata inline)  │                     │
  │  │  └─ WAF (ModSecurity+CRS)  │                     │
  │  └────────────┬─────────────┘                      │
  │               ▼ (검사 통과 트래픽)                   │
  │  ┌──────────────────────────┐                      │
  │  │ 2026_capstone_Groot_C          │  ← 메인 웹서버        │
  │  │  ├─ DVWA (Docker)          │  (웹공격 대상)        │
  │  │  ├─ CVE 취약 컨테이너       │  (Log4Shell 등)      │
  │  │  └─ Wazuh Agent            │                      │
  │  └────────────┬─────────────┘                      │
  │               │ 로그/이벤트                          │
  │               ▼                                     │
  │  ┌──────────────────────────┐                      │
  │  │ 2026_capstone_Groot_B          │  ← 관제/두뇌 인터페이스│
  │  │  ├─ Wazuh (Mgr+Indexer+Dash)│                    │
  │  │  └─ MCP Server (자격증명 보유)│                   │
  │  └────────────┬─────────────┘                      │
  └───────────────┼────────────────────────────────────┘
                  │ MCP 호출 (자격증명 없는 Agent가 조회/대응)
                  ▼
      [ LLM Agent 실행 위치 — 아래 옵션 참조 ]
        vLLM(Qwen) + Agent Runtime + Policy Engine
```

트래픽 흐름: Kali → Groot_A(FW→WAF→IPS 검사) → Groot_C(DVWA/CVE). 로그는 전부 Groot_B의 Wazuh로 집중. LLM Agent는 Groot_B의 MCP Server를 통해 조사·대응.

네트워크 세그먼트(ESXi 포트그룹으로 분리 권장):
- 외부/공격자 세그먼트 (Kali ↔ Groot_A)
- DMZ 세그먼트 (Groot_A ↔ Groot_C)
- 관리 세그먼트 (Groot_B Wazuh/MCP, Agent)

### 온프레미스 전환의 이점 (AWS 대비)
- **Port Scan이 실제로 탐지된다.** AWS Security Group이 패킷을 관문에서 버리던 문제가 사라져 IPS가 스캔을 관측.
- **경보 소스가 풍부해진다.** FW 로그 + IPS(Suricata) 경보 + WAF(ModSecurity) 로그 → Agent 상관분석 재료 증가.
- **네트워크 복잡성·비용 제거.** SSH 역방향 터널, AWS SSM, 팔로알토 우회, 클라우드 비용 전부 불필요.
- **재현성.** 전체를 한 호스트에서 스냅샷·복제 가능.

---

## 1.5 사양표 (B-1 Docker Compose)

실제 ESXi 호스트: KTNF SR285K2-V5, Xeon Gold 5215 20 논리CPU(약 10물리/20스레드), RAM 256 GB, NIC 4개, 관리망 192.168.16.130(GW .129). **다른 서버와 공유하므로 보수적으로 배분.** C=vCPU.

이 호스트에는 Groot_A/B/C만 올린다(DGX Spark는 ARM 외부장비, Kali는 노트북 → 호스트 자원 미사용).

| VM | 역할 | 목표(이 프로젝트) | NIC(세그먼트) |
|---|---|---|---|
| Groot_A | 보안장비(FW/IPS/WAF) | **2C / 6G / 60G** | EXT, DMZ, MGMT |
| Groot_B | SIEM + MCP | **4C / 16G / 150G** | MGMT |
| Groot_C | 웹서버(DVWA/DB/CVE) | **2C / 6G / 60G** | DMZ, MGMT |
| 우리 몫 합계 | | **8C / 28G / 270G** | 호스트 CPU의 ~40%, RAM의 ~11% |
| 남는 여유 | 다른 서버용 | 약 12C / 228G | |

배분 원칙:
- RAM은 256G로 남아돌아 병목인 Groot_B(Wazuh Indexer)에 16G를 넉넉히 준다(RAM으로 병목 해소). CPU는 공유 자원이라 8 vCPU로 보수적.
- 인터넷 경로: 관리 NIC 하나를 호스트 실제망(192.168.16.0/24, GW .129)에 연결해 패키지·NGC·NVD/KEV 접근 확보.
- 확인 필요: 데이터스토어 여유 ≥ 300G (이미지에 디스크 용량 미표시).
- 외부 고정: DGX Spark(GB10, 128G 통합, 30B BF16 여유), Kali 노트북(2C/4G).
- 주요 SW: Groot_A(nftables/Suricata/ModSecurity+nginx/Wazuh Agent), Groot_B(Wazuh Mgr·Indexer·Dash/MCP Server), Groot_C(DVWA/DB/CVE/Wazuh Agent).
- k3s(B-2) 사양은 archive/PLAN_2.md 1.5 참조(보류안).

## 2. 옵션 결정 (근거)

### 옵션 A. LLM Agent 실행 위치

| | A-1. DGX Spark 유지 (권장) | A-2. ESXi GPU 패스스루 |
|---|---|---|
| 구성 | DGX Spark에서 vLLM+Agent+Policy 실행, ESXi 관리 세그먼트로 Groot_B(MCP) 접속 | ESXi 호스트 GPU를 VM 하나에 패스스루하여 vLLM 실행 |
| 장점 | 제안서 "DGX Spark 기반" 정체성 유지, 128GB로 30B 여유, 관제망과 물리 분리 | 전 구성이 한 호스트에 모임, 관리 단순 |
| 단점 | DGX Spark ↔ ESXi 네트워크 연결 필요 | 제안서 전제(DGX Spark)와 어긋남, ESXi 호스트에 충분한 GPU 필요, 패스스루 설정 |
| 공통 | 어느 쪽이든 MCP Server는 Groot_B(별도 머신)에 두어 자격증명 격리(A안) 유지. Agent 프로세스에는 자격증명 없음 | |

→ **결정: A-1 (DGX Spark).** 과제 정체성과 자격증명 격리에 가장 잘 맞음. A-2는 DGX Spark 사용 불가 시 대안.

### 옵션 B. 컨테이너 오케스트레이션

| | B-1. Docker Compose (권장) | B-2. Kubernetes (k3s) |
|---|---|---|
| 구성 | VM별 `docker-compose.yml` | 경량 K8s(k3s)로 파드 배포 |
| 장점 | 구축·디버깅 빠름, 캡스톤 규모에 적합, Wazuh/Suricata 공식 compose 예제 풍부 | 오케스트레이션 학습 효과, 선언적 배포 |
| 단점 | 다중 노드 오케스트레이션 학습은 약함 | 구축 복잡도·시간 증가, Suricata inline·Wazuh의 K8s 네트워킹이 까다로움 |

→ **결정: B-1 (Docker Compose).** 보안장비 inline 검사와 Wazuh 안정성 때문에 Compose가 안전. k3s는 대안.

---

## 3. 확정 결정 (유지 항목)

| 항목 | 결정 | 비고 |
|---|---|---|
| 모델 | Qwen3-30B-A3B-Instruct-2507 (MoE) 1차 / 32B 비교 | 대역폭상 MoE 우위 |
| 추론 서버 | vLLM (NGC 컨테이너 우선) | GB10/aarch64 |
| MCP 역할 | 자격증명 격리 보안 경계 (A안). MCP Server는 Groot_B, Agent는 자격증명 없음 | 온프레미스 분리로 경계 더 명확 |
| Alert 전달 | Indexer 폴링 (전 구간 내부망이라 웹훅도 가능) | |
| 공격 시나리오 | DVWA(웹공격) + CVE 컨테이너(Log4Shell 등) 병행 | KEV 등재 CVE |
| 대응 | 자동은 되돌릴 수 있는 동작만, 고위험은 사람 승인 | Policy Engine + HITL(⚠️Slack 불가, 443 차단 — 터미널/온프레미스 채팅으로 대체 예정) |
| Fine-tuning | 확장 목표 (LoRA/QLoRA) | 없어도 완결 |

확정: LLM=DGX Spark(A-1), 오케스트레이션=Docker Compose(B-1).

보안장비(Groot_A) 제품 확정
| 역할 | 제품 | 비고 |
|---|---|---|
| FW | nftables (게이트웨이 netfilter) | Response Tool이 drop 규칙 조작. 대안 OPNsense |
| IPS | Suricata (inline, NFQUEUE) + ET Open 룰 | eve.json → Wazuh |
| WAF | ModSecurity v3 + OWASP CRS (nginx 리버스 프록시) | DVWA 앞단, 감사로그 → Wazuh |

트래픽 순서: Kali → Groot_A(FW → IPS → WAF) → Groot_C.

---

## 0단계. 사전 준비 (1주)

- [x] ESXi 호스트 사양 확인 (CPU/RAM/디스크, GPU 유무 → 옵션 A-2 가능 여부) — 사양표 1.5, GPU 없음 → A-1 유지
- [x] VM 3대 생성: 2026_capstone_Groot_A / _B / _C (**Ubuntu Server 24.04.5 LTS**, GUI 없이 동일 버전 통일), Kali는 노트북 호스트 — user groot_a/b/c, host groot-sec/siem/web
- [ ] ESXi 포트그룹으로 3개 세그먼트(외부/DMZ/관리) 구성, Groot_A를 게이트웨이로 — **부분**: 현재 내부망(10.10.10)+임시외부(192.168.16) 2세그먼트, A NAT 게이트웨이 완료. 3세그먼트 분리는 미완
- [ ] (확정 A-1) DGX Spark ↔ ESXi 관리 세그먼트 연결 확인 — **보류**: VM·운영자 VPN 모두 11434 차단 확인, 관리자 라우팅/permit 대기
- [x] (확정 B-1) 각 VM에 Docker/Compose 설치 — **A·B 완료**(오프라인 static Docker 29.8.1 + Compose v5.5.1, hello-world 검증). C는 별도 담당 대기
- [ ] LLM 실행처에서 vLLM으로 Qwen3-30B-A3B 실행, tool calling·tok/s 실측 → 모델 확정 — 보류(DGX 접근 대기; 대안 B 로컬 Ollama)
- [x] (확정) 보안장비 이미지 준비: nftables(FW), Suricata inline(IPS, ET Open), ModSecurity+OWASP CRS(WAF, 공식 이미지) — A에 `jasonish/suricata:latest`·`owasp/modsecurity-crs:nginx`, B에 Wazuh 4.14.8 오프라인 반입 완료. nftables 네이티브
- [x] 저장소 디렉터리 구조 생성 — infra/groot-a·b·c 등

디렉터리 구조 (초안)
```
capstone_project/
├── PLAN.md, suggestion.md, ...
├── infra/
│   ├── groot-a/   # FW/IPS/WAF compose 또는 k8s manifest
│   ├── groot-b/   # Wazuh + MCP Server compose
│   └── groot-c/   # DVWA + CVE 컨테이너 compose
├── mcp-server/    # MCP Server (Groot_B 배포). 자격증명 보유, Agent와 분리
├── agent/         # Agent Runtime + Policy Engine (LLM 실행처 배포). 자격증명 없음
├── scenarios/     # 공격 스크립트, ground truth
└── eval/          # 평가 스크립트, 결과
```

---

## 1단계. 인프라 구축 (2~3주)

목표: 공격 시나리오 실행 시 Wazuh에 FW/IPS/WAF/서버 경보가 뜬다.

### 1-1. 2026_capstone_Groot_A (보안장비)
- [x] 게이트웨이 역할 설정 (외부↔DMZ 라우팅, IP 포워딩) — NAT masquerade(10.200.10.0/24→ens192) + DOCKER-USER forward + ip_forward 영구화, `capstone-nat.service`, B 경유 검증 완료
- [x] FW: nftables 규칙(기본 차단+웹 허용). Response Tool이 규칙을 조작할 인터페이스 마련 — **완료(2026-09-27)**: NAT(`capstone_gw`) + 관리 포트포워딩(`capstone_fwd`: **웹서비스 DVWA만 기본 IP 노출(80)**, 관리포털은 특정포트 **A:10443→B:443**(캠퍼스 `https://192.168.16.230:10443`), **443 비움**, VPN 관리는 SSH 터널, WAF TLS 8443) + **Phase 2 호스트 방화벽 `inet capstone_fw`**(`capstone-fw.nft`: input 기본 drop, 허용=lo/established/ICMP/내부 NTP/SSH; 캠퍼스 L2 잡음 무로그 drop; 출발지별 미터 로그 `FW_DROP_IN`) + **`agent_block`**(raw prerouting drop 셋 + `never_block` 잠금가드 + CLI `/usr/local/sbin/agent_block add|del|list|flush`, TTL 10s~24h, 상태파일로 재부팅 복원, 모든 동작 syslog→Wazuh). 외부→내부 forward 는 Docker FORWARD(drop)+DOCKER-USER 선별 허용. 데드맨 타이머+`.pending` 방식으로 잠금 없이 적용(`fw_phase2.sh`/`fw_confirm.sh`), `nftables.service` mask. **실측**: B 외부IP 90s 차단→A 경유 전면 차단·내부 무영향·해제·복원, B 경보 100121/100122/100125. 인라인 IPS(NFQUEUE) 전환은 미정
- [x] IPS: Suricata — **1단계 IDS(passive, ens192) 배치 완료(2026-09-26)**: 8.0.6, ET Open 52,483룰 `-S` 배타 로드, `HOME_NET=[10.200.10.0/24,192.168.16.230/32]`(기본값이면 공격자 대역이 내부로 잡혀 경보 0), `stats.interval=60`, Hyperscan 캐시 볼륨. B에서 `curl -A sqlmap/1.0` → **sid 2008538 경보 실측**. inline(NFQUEUE) 전환은 Phase2. `infra/groot-a/docker-compose.yml`·`deploy_secstack.sh`(리뷰 반영 게이트형). **ET Open 룰셋 오프라인 반입·리뷰 완료**(`~/capstone/suricata/rules`, md5검증, lua 0 · `suricata-rules.md`)
- [x] WAF: ModSecurity v3 + OWASP CRS 4.29 — **배치 완료(2026-09-26)**: nginx 리버스 프록시 :80/:443 → `groot-web:80`(DVWA, 경로 `/dvwa/`), DetectionOnly(차단 전환은 `MODSEC_RULE_ENGINE=On`), JSON 감사로그 `logs/modsec/audit.log`(uid 101 소유 필수). 실 클라이언트 IP 기록 확인, CRS 913100/942100/949110 실측
- [x] Wazuh Agent 설치 — **완료(2026-09-26)**: 4.14.8 오프라인 dpkg(배포변수 WAZUH_MANAGER=groot-siem), authd 자동등록 → 매니저 **ID 001 groot-sec Active**. 기본 active-response는 비활성(응답은 MCP→nft `agent_block` 로만). 스크립트 `infra/groot-a/install_agent.sh`. **IPS/WAF 로그 전송 완료**: `agent_localfile.sh`(eve.json·audit.log json localfile, label capstone.source) → B 도착 검증. 로그 회전 `logrotate-capstone-secstack`(daily/500M/14, copytruncate). FW(nft) 로그는 Phase2 차단정책과 함께

### 1-2. 2026_capstone_Groot_B (Wazuh + MCP)
- [x] Wazuh all-in-one 설치 (Manager+Indexer+Dashboard) — **기동 완료(2026-09-26)**: 4.14.8 single-node compose, 인증서는 오프라인 `wazuh-certs-tool.sh`(openssl)로 생성. 인덱서 green·대시보드 302·API 토큰 OK. 절차 `infra/groot-b/README.md` (⚠️ 인증서 권한 644 필수). **기본 비번 교체 완료**(3계정 통일, 데모계정 삭제, 값은 CREDENTIALS.local.md)
- [x] Groot_A/C의 Agent 등록, Dashboard에서 Active 확인 — **완료**: 001 groot-sec(A)·002 groot-web(C) 모두 Active(2026-09-26, 2026-09-27 재확인). 매니저 000 포함 3대
- [x] Suricata eve / ModSecurity 감사로그 수집 룰 확인, MITRE 태그 확인 — **완료(2026-09-26)**: Suricata는 내장 86601(lv3) 위에 severity별 100110(lv9)/100111(lv6)+버스트 100112, ModSecurity는 내장 룰 없음 → JSON 필드 기반 100100~100103(CRS 히트 lv7, 임계 초과 lv10, 버스트 lv12), MITRE T1190/T1595. `infra/groot-b/local_rules.xml`(wazuh-logtest·`analysisd -t` 검증 후 적용). B에서 A로 프로브 → **alerts.json·인덱서(`rule.groups:capstone`) 5건 실측**
- [x] Vulnerability Detection 활성화 (OS 패키지 CVE 매핑 확인) — **완료**: C(002) 취약점 상태 2,422건 인덱싱, 대시보드 Vulnerability Inventory 확인, `/soc vulns` 조회
- [x] MCP Server 배치 (자격증명은 여기에만). LLM 실행처에서 접근 확인 — **읽기 서버 배치·검증 완료(2026-09-26)**: `mcp-server-wazuh` v0.3.0(sha256 검증) `/opt/mcp/`, 전용 사용자 `mcp` + sshd ForceCommand + authorized_keys restrict, 읽기전용 계정 `mcp-ro`(API readonly / 인덱서 readall, 쓰기 403 실증), 자격증명은 B `/etc/mcp/wazuh-ro.env`에만. Mac에서 `ssh -T groot-mcp`(A 점프 전용 키)로 **계약 테스트 PASS**(initialize·14 tools·get_wazuh_alert_summary 실경보 반환). `infra/mcp/deploy_mcp_B.sh`(적대적 리뷰 5관점 반영), `contract_test.py`. 차단(block_ip)은 소형 응답서버로 별도

### 1-3. 2026_capstone_Groot_C (메인서버)
- [x] DVWA 실행 (웹공격 대상) — **베어메탈로 설치·구동 중**(별도 담당). 하이브리드: DVWA 베어메탈 유지, 재현성은 ESXi 스냅샷+DVWA Reset
- [x] CVE 취약 컨테이너 실행: Log4Shell(CVE-2021-44228) 취약 앱 — **C 담당자 완료 확인(2026-09-26)**: Docker 29.8.1 + `log4shell-lab`(:8080) 가동. 권한상승용 취약 패키지(sudo Baron Samedit)는 VM OS 수준에 구성(대기)
- [x] Wazuh Agent 설치, 웹로그·FIM·Syscollector·인증로그 수집 — **담당자 완료 + 연동 보완(2026-09-26)**: 에이전트 4.14.8 → 매니저 10.200.10.10 내부망, **ID 002 groot-web Active**, apache access/error(`apache` 포맷)·journald 수집, 인벤토리(764패키지·포트)·취약점 상태 2,422건 인덱싱, SCA/rootcheck 동작. 웹 룰 실측(31101/31103/31105). **보완**: `c_integrate.sh` — 내부 호스트명 + **apache mod_remoteip**(WAF의 X-Forwarded-For 복원; 이전엔 C 경보 srcip가 전부 A=10.200.10.1이라 차단 대응이 A를 막을 위험) → srcip 실제 클라이언트로 확인. 시계(최종): 캠퍼스가 외부 NTP(UDP 123) 차단 → **A ← 192.168.16.131(캠퍼스 시간 서버, chrony 오프라인 반입) ; B/C ← A(10.200.10.1, timesyncd)** 체인. `infra/groot-a/ntp_server.sh`, `infra/ntp_client.sh`. 남은 것: DVWA 기본 보안레벨 impossible → 시나리오 시 low(담당자 협의)

### 1-4. 공격자 (Kali)
- [ ] 노트북에 Kali, ESXi 외부 세그먼트에 연결
- [ ] nmap/nikto/sqlmap/hydra, Log4Shell PoC + 악성 LDAP(marshalsec) 준비

### 1-5. 경보 검증
- [~] 시나리오 1~3 실행 → IPS/WAF/Wazuh 경보 발생 확인, rule id 기록(`scenarios/alerts.md`) — **시나리오·탐지 검증 문서 완비(2026-09-27)**: `scenarios/`(README·scenario-1 웹, scenario-2 Log4Shell, scenario-3 privesc, alerts 매트릭스, references). 공격 생성 절차는 공개 표준(OWASP WSTG, Wazuh PoC, 앱 README, ET/CRS) 링크로 인용, 우리 룰 id에 매핑. **실행은 선행조건 해결 후**: DVWA level low(C 담당), Log4Shell 경로 **결정됨**(A 경유 토글 `scenario_log4shell_route.sh`, 평상시 랩은 C 내부 격리), sudo 취약 버전 확인, Kali 세그먼트 직결
- [x] FW 자동 차단(nftables) 동작 확인 → Baseline 대응 — `agent_block`/`inet capstone_fw` 완료·실차단 검증(1-1 참조). 대응 룰 100121/100126~100129

---

## 2단계. MCP Tool + AI Agent (3~4주)

목표: 경보 발생 시 Agent가 자동 조사하고 판단·대응 제안을 산출.

### 2-1. MCP Server (Groot_B)
설계 원칙(A안): MCP Server는 Agent와 별도 머신(Groot_B)에서 실행, 자격증명(Wazuh API, FW/IPS 접근, Slack)은 여기에만.
**클라이언트 불가지론(pluggable agent)**: 서버는 어떤 AI가 붙는지 모르게 설계 — 에이전트 런타임/LLM 교체는 클라이언트 설정 1블록만 변경(전송 계약: 1차 stdio over SSH → 확장 HTTP). 설계·템플릿·계약테스트: `infra/mcp/README.md`. 읽기 서버는 기성 `gbrigandi/mcp-server-wazuh` v0.3.0(리뷰 완료), 응답 서버는 소형 커스텀(별도 자격증명).
- [x] Wazuh Tool: `search_alerts`, `get_alert`, `get_agent_status`, `get_vulnerabilities` — **읽기 MCP 서버 14툴로 커버**(계약테스트 PASS) + SOC 챗봇 `/soc alerts|agents|vulns`로 실사용
- [ ] CVE Tool: `cve_lookup` → NVD + CISA KEV — **CISA KEV 오프라인 반입·리뷰 완료**(B `~/capstone/kev`, 1,726건, CC0, 시나리오 CVE 포함 · `infra/groot-b/kev-data.md`). NVD 상세는 보완 예정
- [ ] Server Tool: 프로세스/포트/FIM/인증 (Wazuh API, 내부망이라 SSH 읽기전용도 가능)
- [ ] Network Tool: `search_suricata`(IPS), WAF 로그 조회, FW 로그 조회 (AWS Flow Logs 대체)
- [x] Response Tool `block_ip`/`unblock_ip`/`list_blocks` — **완료(2026-09-27)**: 응답 MCP 서버(A, 파이썬 stdlib stdio, `infra/mcp/response-mcp.py`), 전용 사용자 `resp`(sshd ForceCommand + authorized_keys restrict) + sudoers(agent_block add/del/list 만, flush 금지) → nft `agent_block`. 정책 엔진(TTL 상한 RESP_MAX_MINUTES=120, reason 필수·정규화, IP 검증, flush 미노출). TTL 만료 리퍼(systemd 타이머)로 auto-unblock 감사(action=expire→B 100131). 자격증명 격리 유지(에이전트=키만, 차단 능력=A sudoers). Mac `ssh -T groot-resp` 계약 테스트 PASS: block→100121, 거부(보호IP)→100123, unblock→100122, 만료→100131. 적대적 리뷰 3관점 반영. `deploy_response_A.sh`(데드맨 롤백 트랩). — [ ] `isolate_host`·`notify`(Slack)는 추후
- [ ] `cve_lookup` 등 조사 툴 확장(읽기 서버 14툴 + KEV)
- [ ] 각 Tool 단독 테스트

### 2-2. Agent Runtime = Hermes Agent (Nous Research) — **⏸ 보류 (2026-09-26)**
> **검토 중인 대안**: DGX Spark(현재 망에서 도달 불가)를 쓰지 않고 **Claude(Claude Code)를 MCP 클라이언트로 직접 연결**. Claude Code는 MCP 서버를 stdio로 실행하므로 명령을 `ssh groot-b-int <B의 MCP 래퍼>`로 두면 서버는 B에서 실행되고 자격증명은 B에만 존재 → **A안(에이전트 프로세스 무자격증명) 유지, HTTP 빌드 불필요**. 확정 시 이 절의 Hermes 항목은 "대안 런타임"으로 강등. 아래 Hermes 계획은 보존.

직접 구현이 아니라 Hermes Agent를 사용(교수 지정). MCP 네이티브 지원이라 2-1 MCP Server를 그대로 붙인다.
- [x] Hermes 설치, `~/.hermes/config.yaml`의 `mcp_servers`에 우리 MCP Server 등록(stdio/HTTP) — **2026-09-28 완료**: 설치 위치=B(MCP 서버가 있는 VM; Mac 은 콘솔), 방식=공식 Docker 이미지 `nousresearch/hermes-agent:v2026.9.24`(amd64 968MB) 오프라인 반입(`infra/tools/pull_image.py`, 레지스트리 API·sha256 검증·OCI layout). `infra/hermes/deploy_hermes_B.sh prep` 완료: 격리 사용자 `hermes`(mcp 그룹 아님) + `/opt/hermes-data`(=/opt/data) + 컨테이너용 SSH 키/config + `config.yaml`(wazuh-ro=full, resp=untrusted) + B(mcp)·A(resp) authorized_keys 에 `restrict,command=` 등록. **호스트측 계약 테스트 PASS(읽기 14툴·응답 list_blocks)**. 이미지 반입·load 후 **컨테이너 안 계약 테스트 PASS(읽기·응답) + Hermes 본체 기동 agent.log `MCP: registered 17 tool(s) from 2 server(s)`**(mcp__wazuh_ro__* 14, mcp__resp__* 3). `hermes mcp test` 는 이미지에 mcp[cli](typer) 가 없어 불가 → `deploy_hermes_B.sh test` 방식. 이미지 tar 는 B `~/capstone/hermes/`(재반입용, 1GB)
- [x] 모델 프로바이더 = DGX Ollama **211.170.162.110/111 `:11434/v1`**(OpenAI 호환, 2026-09-28 Mac·A·B 모두 도달 실측, Ollama 0.33.2). 모델 **qwen3.6:35b**(qwen35moe 36B Q4_K_M, capabilities tools/thinking, .110에 **262,144 컨텍스트로 상주 로드**) 채택 — 대안 gpt-oss:120b(양 노드, 32k 로드). Hermes `model.provider=custom`, `base_url=http://211.170.162.110:11434/v1`, `default=qwen3.6:35b`. **E2E 실측**: `chat -q` → `mcp__wazuh_ro__get_wazuh_agents` 호출 → 한국어 답변(3 API call, 21s)
- [x] Hermes 실행 위치 결정: **Groot_B(Docker)** — MCP 서버와 같은 VM(2026-09-28, 사용자 결정 "에이전트는 MCP 서버가 있는 곳에"). MCP 도달성 확보. LLM 도달성은 미해결(B egress 없음, DGX 11434 불통) → 후보: B 로컬 llama.cpp(오프라인 소형 모델) / DGX permit 후 OpenAI 호환 / A 경유 프록시
- [x] Alert 트리거 — **완료(2026-09-28)**: Hermes 게이트웨이(B 상주 컨테이너) cron `soc-alert-watch`(every 5m) + `--monitor-script`(soc_bot `/recent` 지문) → 새 level≥10 경보 때만 LLM 조사 → `soc-alerts` 보고(`[SILENT]` 로 침묵). 프롬프트 `infra/hermes/soc_alert_watch.prompt`, 배치 `deploy_gateway_B.sh`
- [ ] 시스템 프롬프트/지침: Tool 결과는 데이터로만, 출력 형식(판단 JSON)
- [x] Agent(Hermes)·LLM 프로세스에 자격증명 없음 확인 — 컨테이너 데이터에는 SSH 키 1개뿐(`/opt/data/home/.ssh`), 호스트 사용자 hermes 는 mcp 그룹 아님(`/etc/mcp/*.env` 0640 root:mcp 접근 불가), MCP 는 sshd ForceCommand 래퍼로만(2026-09-28 실측)
- [ ] 조사 trajectory 저장 (평가·파인튜닝 재사용)
- [ ] **평가 통제**: Hermes 크로스세션 메모리·자기개선 스킬 때문에 회차가 독립적이지 않음 → 측정 회차마다 메모리/스킬 리셋(또는 학습효과를 별도 지표로 분리)

### 2-3. Policy Engine (MCP Server의 Response Tool 안)
- [~] 결정적 자동/승인/거부 판정을 Response Tool에서 수행 — **1차 완료(2026-09-27)**: 응답 서버 `response-mcp.py`가 TTL 상한·reason 필수·IP 검증·보호대상(A `never_block`)·활성 SSH 출발지 거부·flush 미노출을 강제. 고위험 동작 사람 승인(elicitation→Slack)은 런타임 결정 후.
- [ ] 정책표(suggestion.md 10장) YAML화
- [ ] 결정적 자동/승인/거부 판정을 Response Tool에서 수행, 보호 IP·allowlist
- [x] 고위험 동작 사람 승인 — **Tier 2 완료(2026-09-28)**: 응답 서버 `block_ip` → soc_bot 브로커 → Mattermost [승인][거부] 버튼 → 승인 시만 실행(fail-closed, 600s). 무인(cron) 실행에서도 동작. E2E 실측(채팅 요청→승인→차단→회신). (이전 계획 메모:) 고위험 동작은 MCP elicitation → 사람 승인. ⚠️ **Slack 무효(2026-09-27 실측: 아웃바운드 443 전면 차단)** — 외부 SaaS 도달 불가(587/853만 열림). **채널을 교체 용이하게 구현 완료(2026-09-27)**: 승인=MCP elicitation(서버가 채널 모름, 런타임이 표시) + 알림=`notifier.py` 백엔드 추상화(`/etc/resp/hitl.env` 의 `RESP_NOTIFY_BACKEND`+엔드포인트 1블록으로 none|http|email|slack 교체, 재시작 불필요, 코드 불변). http(내부 Mattermost/웹훅)로 스왑·수신 검증. **알림 채널 Tier 1 배치 완료(2026-09-27)**: 온프레미스 **Mattermost**(B, TE 11.11.1+PG16 오프라인 반입) → 채널 `soc-alerts`, A `/etc/resp/hitl.env`=http 연동, block/unblock→채널 게시 검증. 브라우저 `ssh -N groot-mm`→http://localhost:18065. 설계·상태 `infra/mcp/hitl-chat.md`. 남은 것: Tier 2(채팅 내 승인 버튼) — 런타임 결정 후(Hermes면 내장 PR #29373)
- [ ] Response dry-run 해제

### 2-4. 통합 테스트
- [ ] 시나리오 1~4 실행, Agent 조사 완결 확인
- [ ] 시나리오 5(프롬프트 인젝션) — Agent가 로그 지시 안 따름 + 자격증명 격리로 유출·오작동 불가 확인

---

## 3단계. 평가 (2주)
- [ ] 시나리오별 ground truth 정의 (공격여부·단계·침해·적절대응)
- [ ] 시나리오 0(정상) 포함, 자동 실행 스크립트, 각 10회 이상 반복
- [ ] **Hermes 상태 리셋으로 회차 독립성 확보** (학습 off + 회차마다 초기화). 절차: `infra/hermes/eval_reset.md`
- [ ] Baseline(Wazuh 룰+FW/IPS 자동차단+사람 수동 조사) vs Agentic SOC 측정
- [ ] 지표: MTTI, MTTR, Triage/Correlation/Compromise 정확도, 대응 적절성, 인젝션 방어, Tool 효율, 추론비용
- [ ] (보조) 학습 on + 반복으로 Hermes 자기개선 효과(학습 곡선) 별도 측정
- [ ] 결과표·그래프, 실패사례 분석

---

## 4단계. Fine-tuning (확장) / 5단계. 문서화
- [ ] trajectory 선별 → teacher 초안 → 사람 검수 → Qwen 채팅템플릿 변환 → LoRA/QLoRA
- [ ] 최종 보고서, 아키텍처 다이어그램, 시연, README

---

## 리스크와 대응
| 리스크 | 대응 |
|---|---|
| ESXi 리소스 부족 (VM 3대+GPU) | VM 사양 조정, LLM은 DGX Spark(A-1)로 분리 |
| GPU 패스스루 실패(A-2) | A-1(DGX Spark)로 전환 |
| Suricata inline/WAF 프록시 구성 난이도 | 우선 passive(IDS)로 시작 후 inline 전환 |
| DGX Spark 속도 부족 | 모델 축소, Tool 응답 요약 |
| K8s 구축 지연(B-2) | Docker Compose로 회귀 |
| 일정 초과 | Fine-tuning 제외해도 완결되게 설계 |

---

## 진행 로그
최신 항목을 위에 둔다. (세부 이력은 `대화기록/YYYY-MM-DD.md`)

### 2026-09-27 (HITL 채팅 · SOC 챗봇/자동 보고 · Log4Shell 노출 하드닝)
- **HITL 알림 채널(Tier 1)**: 온프레미스 Mattermost(B, TE 11.11.1+PG16 오프라인) + A `/etc/resp/hitl.env`=http 연동, block/unblock→채널 게시 검증. 캠퍼스·VPN 공통 접속 위해 **A:443 nginx 리버스 프록시**(`https://chat.groot.lab`, 웹소켓 101, 데스크톱 앱 동일 URL). 대시보드는 보안상 VPN 직접노출 안 함.
- **SOC 챗봇 + 자동 보고**: 채팅 슬래시 `/soc`(alerts/agents/vulns/status/report, 읽기전용 mcp-ro) + 에이전트 인시던트 보고서 게시 + **주기 보고**(B `soc-report.timer` 매시, 경보 0이면 스킵) + **정기 상태 요약 heartbeat**(B `soc-summary.timer` 하루 2회, 이상 없어도 게시). `infra/mcp/soc_bot.py`.
- **Log4Shell 노출 하드닝**: C 컨테이너 `0.0.0.0:8080`→`10.200.10.20:8080` 내부 전용 바인딩(외부·VPN 직접 차단, Mac·A·B 3방향 실측). 시나리오용 A 경유 토글 `infra/groot-a/scenario_log4shell_route.sh`(A:8080→C DNAT+SNAT+forward, 런타임 전용=재부팅 자동 OFF, 캠퍼스/Kali만) 설치·on/off 검증, 평상시 OFF.
- 다음: 에이전트 런타임 결정(→ NL 대화·`/soc block`·Tier 2 승인 버튼), 시나리오 실제 실행(DVWA low), 네트워크 최종화(B/C ens192 제거), 공개 전 비번 교체.

### 2026-09-27 (A 방화벽 2단계 + agent_block · 관리 포트포워딩 · 시계 체인 · C 연동)
- **A 호스트 방화벽 Phase 2 + `agent_block` 완료**: `inet capstone_fw`(input 기본 drop + raw prerouting 차단 셋 + never_block 잠금가드 + 로그 미터), CLI `agent_block`(검증·TTL 상한·활성 SSH 출발지 거부·원자적 갱신·상태파일·감사로그), `capstone-nat.sh`가 부팅 시 원자적 로드·차단목록 복원. 적대적 리뷰 4관점(잠금·Docker 공존·CLI 오용·SIEM 도착) 반영, 데드맨+`.pending`으로 무잠금 적용 후 외부 검증·확정. B에 디코더(`local_decoder.xml`)+룰 100120~100130(차단/해제/거부/flush/reload/데드맨/드롭 버스트). 실차단 테스트 통과.
- 관리 포트포워딩: `https://192.168.16.230/` → Wazuh 대시보드(VPN은 A로 22/80/443만 통과 → 443 사용, WAF TLS 8443으로). 시계: A(chrony)←192.168.16.131, B/C(timesyncd)←A. C: mod_remoteip(실 srcip)·hosts·연동 확인.
- (3) 시나리오·탐지 검증 문서 완비, (4) 응답 MCP 서버 배치·검증 완료(2026-09-27). 다음: (2) B/C ens192 제거·기본라우트 A(콜드부트, C 담당자 협의) → 시나리오 실제 실행(DVWA low) → 에이전트 런타임 결정(Claude Code면 읽기 `groot-mcp`+응답 `groot-resp` 두 블록 등록).

### 2026-09-26 세션3 (② A 보안스택 배치 · Wazuh 파이프라인 완성)
- A에 Suricata 8.0.6 IDS(ens192, ET Open 52,483룰, HOME_NET 교정) + ModSecurity v3/CRS 4.29 WAF(→ groot-web `/dvwa/`, DetectionOnly) 배치. 배치 전 적대적 검증 5건(`:ro`+chown 크래시, HOME_NET 무매치, uid 101, localhost 검증 불가, 재실행 포트 게이트) 실물 확인 후 반영. `infra/groot-a/deploy_secstack.sh`.
- Wazuh 파이프라인: A `agent_localfile.sh`(eve.json·audit.log) → B `local_rules.xml`(Suricata severity 100110/100111/100112, ModSecurity 100100~100103) → B에서 A로 프로브 → alerts.json·인덱서 `rule.groups:capstone` 5건 실측. 튜닝 `stats.interval=60`, logrotate.
- ⚠️ 사고: Mac(VPN)에서 sqlmap UA 프로브 직후 **캠퍼스 FW가 (VPN IP↔A) 쌍 차단**(A ens192 tcpdump 0패킷). A 작업은 `ssh -J groot-b groot_a@10.200.10.1`로 완료. **공격 테스트는 VM 세그먼트에서만** 규칙화. 세션 종료 시 미해제.
- 다음: ③ MCP 읽기 서버(B). 런타임(Claude/Hermes) 결정 보류 유지.

### 2026-09-26 (A·B 이미지 반입 · MCP 선정)
- A/B/C 상태 점검. C는 DVWA가 이미 베어메탈로 설치됨 → **하이브리드 확정**(DVWA 베어메탈 유지 + CVE만 컨테이너).
- **A·B 컨테이너 이미지 오프라인 반입**: A=`jasonish/suricata:latest`·`owasp/modsecurity-crs:nginx`, B=Wazuh manager/indexer/dashboard **4.14.8**. (crane 없이 registry API로 amd64 추출→`docker load`, Mac 로컬 삭제)
- **MCP 서버**: 기성 `gbrigandi/mcp-server-wazuh`(MIT) 선정, 설치 없이 **코드리뷰 완료**(LOW RISK, @969f36f 핀, 읽기전용). 차단(block_ip)은 소형 응답서버로 별도(최소권한 2분리).
- 제약 확인: 이 망 outbound 웹(80/443)·11434 전면차단 → 반입은 전부 오프라인. 열린 포트 123/587/853/873/990/1194만.
- **룰/데이터 반입(리뷰-후-반입)**: ET Open 룰셋(A, 52,483룰, md5검증·lua 0), CISA KEV(B, 1,726건·CC0·시나리오 CVE 포함). 각각 `infra/groot-a/suricata-rules.md`, `infra/groot-b/kev-data.md`. ⚠️ scp는 sftp모드 실패 → **`scp -O`(legacy)**로 전송해야 함(이 환경 특성).

### 2026-09-25 (A NAT 게이트웨이)
- Groot_A NAT 게이트웨이 구성: nft masquerade + DOCKER-USER forward + ip_forward 영구화, `capstone-nat.service`. B 경유 인터넷 왕복 검증. 산출물 `infra/groot-a/`.

### 2026-09-24 (오프라인 Docker · 네트워크)
- 웹 egress 차단 발견 → A·B에 Docker(static 29.8.1 + Compose v5.5.1) 오프라인 설치, net-tools 오프라인. C 핸드오프 문서 `infra/groot-c/C_구축_표준설정.md`.
- VM 네트워크 확정: A .230/10.200.10.1, B .233/10.200.10.10, C .234/10.200.10.20, DNS 168.126.63.1(KT), NIC 변경은 콜드부트(init 0).

### 2026-09-23 (OS/git)
- VM OS Ubuntu Server 24.04.5 확정, git 로컬 저장소 초기화(원격 미연결).

### 2026-09-22 (인프라 전환)
- AWS → ESXi 온프레미스 전환 반영. VM 3대(Groot A/B/C) + Kali 노트북. FW/IPS/WAF 보안장비 계층 신설
- 사용자 결정: 시나리오는 DVWA+CVE 병행. LLM 위치(DGX Spark vs ESXi GPU)와 오케스트레이션(Docker vs K8s)은 두 안 모두 계획에 포함해 검토 대기
- MCP Server를 Groot_B로 분리 → 자격증명 격리(A안)가 물리적으로 더 명확해짐
- 온프레미스 이점: Port Scan 실탐 가능, FW/IPS/WAF로 경보 소스 증가, 네트워크 복잡성·비용 제거
- 기존 AWS 계획은 `대화기록/PLAN_aws_backup_2026-09-22.md`로 백업

(이전 로그는 백업 파일 참조)
