# Agentic SOC 구축 실행 계획 (ESXi 온프레미스)

제안서: [suggestion.md](suggestion.md) · 검토메모: [suggestion_review.md](suggestion_review.md) · 시뮬레이션: [simulation_report.md](simulation_report.md)
변경 배경: `plan_changed.md`로 인프라를 AWS에서 ESXi 온프레미스로 전환. 이전 AWS 계획 백업: `대화기록/PLAN_aws_backup_2026-09-22.md`

이 문서는 실행 순서·체크리스트·진행 로그를 관리한다. 작업마다 체크박스와 진행 로그를 갱신한다.

---

## 현재 상태 (2026-09-22)

- 설계·계획 단계. 아키텍처를 ESXi 온프레미스로 전환.
- 주요 결정 확정: LLM=DGX Spark(A-1), 오케스트레이션=Docker Compose(B-1), 보안장비=nftables(FW)/Suricata(IPS)/ModSecurity+CRS(WAF). 두 안 비교는 아래 2장에 근거로 유지.

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
  │  │ capstone_Groot_A          │  ← 네트워크 관문/검사 │
  │  │  보안장비 (Docker)         │                      │
  │  │  ├─ FW  (nftables/OPNsense)│                     │
  │  │  ├─ IPS (Suricata inline)  │                     │
  │  │  └─ WAF (ModSecurity+CRS)  │                     │
  │  └────────────┬─────────────┘                      │
  │               ▼ (검사 통과 트래픽)                   │
  │  ┌──────────────────────────┐                      │
  │  │ capstone_Groot_C          │  ← 메인 웹서버        │
  │  │  ├─ DVWA (Docker)          │  (웹공격 대상)        │
  │  │  ├─ CVE 취약 컨테이너       │  (Log4Shell 등)      │
  │  │  └─ Wazuh Agent            │                      │
  │  └────────────┬─────────────┘                      │
  │               │ 로그/이벤트                          │
  │               ▼                                     │
  │  ┌──────────────────────────┐                      │
  │  │ capstone_Groot_B          │  ← 관제/두뇌 인터페이스│
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
- k3s(B-2) 사양은 PLAN_2.md 1.5 참조.

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
| 대응 | 자동은 되돌릴 수 있는 동작만, 고위험은 사람 승인 | Policy Engine + Slack |
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

- [ ] ESXi 호스트 사양 확인 (CPU/RAM/디스크, GPU 유무 → 옵션 A-2 가능 여부)
- [ ] VM 3대 생성: capstone_Groot_A / _B / _C (Ubuntu 22.04 기준), Kali는 노트북 호스트
- [ ] ESXi 포트그룹으로 3개 세그먼트(외부/DMZ/관리) 구성, Groot_A를 게이트웨이로
- [ ] (확정 A-1) DGX Spark ↔ ESXi 관리 세그먼트 연결 확인
- [ ] (확정 B-1) 각 VM에 Docker/Compose 설치
- [ ] LLM 실행처에서 vLLM으로 Qwen3-30B-A3B 실행, tool calling·tok/s 실측 → 모델 확정
- [ ] (확정) 보안장비 이미지 준비: nftables(FW), Suricata inline(IPS, ET Open), ModSecurity+OWASP CRS(WAF, 공식 이미지)
- [ ] 저장소 디렉터리 구조 생성

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

### 1-1. capstone_Groot_A (보안장비)
- [ ] 게이트웨이 역할 설정 (외부↔DMZ 라우팅, IP 포워딩)
- [ ] FW: nftables 규칙(기본 차단+웹 허용) 또는 OPNsense. Response Tool이 규칙을 조작할 인터페이스 마련
- [ ] IPS: Suricata inline(NFQUEUE)으로 배치, ET Open 룰, eve.json 생성
- [ ] WAF: ModSecurity + OWASP CRS를 리버스 프록시로 Groot_C 앞단에 배치
- [ ] Wazuh Agent 설치, FW/IPS/WAF 로그를 Wazuh로 전송

### 1-2. capstone_Groot_B (Wazuh + MCP)
- [ ] Wazuh all-in-one 설치 (Manager+Indexer+Dashboard)
- [ ] Groot_A/C의 Agent 등록, Dashboard에서 Active 확인
- [ ] Suricata eve / ModSecurity 감사로그 수집 룰 확인, MITRE 태그 확인
- [ ] Vulnerability Detection 활성화 (OS 패키지 CVE 매핑 확인)
- [ ] MCP Server 배치 (자격증명은 여기에만). LLM 실행처에서 접근 확인

### 1-3. capstone_Groot_C (메인서버)
- [ ] DVWA 컨테이너 실행 (웹공격 대상)
- [ ] CVE 취약 컨테이너 실행: Log4Shell(CVE-2021-44228) 취약 앱. 권한상승용 취약 패키지(예: sudo Baron Samedit)는 VM OS 수준에 구성
- [ ] Wazuh Agent 설치, 웹로그·FIM·Syscollector·인증로그 수집

### 1-4. 공격자 (Kali)
- [ ] 노트북에 Kali, ESXi 외부 세그먼트에 연결
- [ ] nmap/nikto/sqlmap/hydra, Log4Shell PoC + 악성 LDAP(marshalsec) 준비

### 1-5. 경보 검증
- [ ] 시나리오 1~3 실행 → IPS/WAF/Wazuh 경보 발생 확인, rule id 기록(`scenarios/alerts.md`)
- [ ] FW 자동 차단(Active Response 또는 nftables) 동작 확인 → Baseline 대응으로 사용

---

## 2단계. MCP Tool + AI Agent (3~4주)

목표: 경보 발생 시 Agent가 자동 조사하고 판단·대응 제안을 산출.

### 2-1. MCP Server (Groot_B)
설계 원칙(A안): MCP Server는 Agent와 별도 머신(Groot_B)에서 실행, 자격증명(Wazuh API, FW/IPS 접근, Slack)은 여기에만.
- [ ] Wazuh Tool: `search_alerts`, `get_alert`, `get_agent_status`, `get_vulnerabilities`
- [ ] CVE Tool: `cve_lookup` → NVD + CISA KEV
- [ ] Server Tool: 프로세스/포트/FIM/인증 (Wazuh API, 내부망이라 SSH 읽기전용도 가능)
- [ ] Network Tool: `search_suricata`(IPS), WAF 로그 조회, FW 로그 조회 (AWS Flow Logs 대체)
- [ ] Response Tool(초기 dry-run): `block_ip`(FW/Groot_A 규칙 또는 Wazuh Active Response), `isolate_host`(FW 규칙/세그먼트 격리), `notify`(Slack)
- [ ] 각 Tool 단독 테스트

### 2-2. Agent Runtime (LLM 실행처)
- [ ] Alert 폴러: Indexer에서 지정 level 이상 신규 경보 조회 → 조사 큐
- [ ] 시스템 프롬프트(역할, 조사절차, Tool 결과는 데이터로만, 출력 형식)
- [ ] 조사 루프: Alert→LLM→tool_call→결과→반복→최종 판단(JSON), 호출/시간 상한
- [ ] Agent 프로세스에 자격증명 없음 확인
- [ ] 조사 trajectory 저장 (평가·파인튜닝 재사용)

### 2-3. Policy Engine (LLM 실행처, Agent와 함께)
- [ ] 정책표(suggestion.md 10장) YAML화
- [ ] 자동/승인/거부 판정, 보호 IP·allowlist
- [ ] Slack 승인 (Socket Mode)
- [ ] Response dry-run 해제

### 2-4. 통합 테스트
- [ ] 시나리오 1~4 실행, Agent 조사 완결 확인
- [ ] 시나리오 5(프롬프트 인젝션) — Agent가 로그 지시 안 따름 + 자격증명 격리로 유출·오작동 불가 확인

---

## 3단계. 평가 (2주)
- [ ] 시나리오별 ground truth 정의 (공격여부·단계·침해·적절대응)
- [ ] 시나리오 0(정상) 포함, 자동 실행 스크립트, 각 10회 이상 반복
- [ ] Baseline(Wazuh 룰+FW/IPS 자동차단+사람 수동 조사) vs Agentic SOC 측정
- [ ] 지표: MTTI, MTTR, Triage/Correlation/Compromise 정확도, 대응 적절성, 인젝션 방어, Tool 효율, 추론비용
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
최신 항목을 위에 둔다.

### 2026-09-22 (인프라 전환)
- `plan_changed.md` 반영: AWS → ESXi 온프레미스. VM 3대(Groot A/B/C) + Kali 노트북. FW/IPS/WAF 보안장비 계층 신설
- 사용자 결정: 시나리오는 DVWA+CVE 병행. LLM 위치(DGX Spark vs ESXi GPU)와 오케스트레이션(Docker vs K8s)은 두 안 모두 계획에 포함해 검토 대기
- MCP Server를 Groot_B로 분리 → 자격증명 격리(A안)가 물리적으로 더 명확해짐
- 온프레미스 이점: Port Scan 실탐 가능, FW/IPS/WAF로 경보 소스 증가, 네트워크 복잡성·비용 제거
- 기존 AWS 계획은 `대화기록/PLAN_aws_backup_2026-09-22.md`로 백업

(이전 로그는 백업 파일 참조)
