# Agentic SOC 구축 실행 계획 (ESXi 온프레미스)

제안서: [suggestion.md](suggestion.md) · 검토메모: [suggestion_review.md](suggestion_review.md) · 시뮬레이션: [simulation_report.md](simulation_report.md)
변경 배경: `plan_changed.md`로 인프라를 AWS에서 ESXi 온프레미스로 전환. 이전 AWS 계획 백업: `대화기록/PLAN_aws_backup_2026-09-22.md`

이 문서는 실행 순서·체크리스트·진행 로그를 관리한다. 작업마다 체크박스와 진행 로그를 갱신한다.

---

> **한 장 요약은 [STATUS.md](STATUS.md)** (라이브 헬스·접속 치트시트·다음 할 일).

## 현재 상태 (2026-10-06 인프라 SSH 재점검·2026-10-08 룰 변경 MCP 배포 기준)

- A/B/C를 2026-10-06 05:05~05:07 UTC(14:05~14:07 KST)에 SSH로 읽기 전용 재점검했다. 10/6 선행 배치 세부 내용은 [같은 날 작업 기록](대화기록/2026-10-06.md) 참조. 공격 프로브·차단 전환은 이번에 실행하지 않았다.
- VM 3대(Ubuntu 24.04.5)와 NAT 게이트웨이, Wazuh·MCP·Hermes·Mattermost 경로가 구축됐다. B/C의 임시 외부 NIC `ens192`는 제거됐고 기본 경로는 A다.
- **A**: FW v2 적용(`FORWARD=DROP`, `CAPSTONE-FWD` 14룰, nft `SPOOF`/`FW_SSH_RATE`/output 체인). WAF healthy·`nginx -t` 통과·`REQUEST-948-GROOT_A_WAF.conf` 마운트(DetectionOnly), Suricata ET+local 합본·Phase-A(`-i ens192`, passive), eve.json 갱신을 SSH로 확인했다. 선행 10/6 기록에 `community_id` 275건이 있다. 신규 공격 경보 실발화는 미확인.
- **B**: Wazuh 000/001/002 Active, manager·indexer·dashboard·Mattermost·Hermes Up, DGX API 200을 SSH로 확인했다. **라이브 `local_decoder.xml`/`local_rules.xml`에 신규 FW 프리픽스·WAF 100200+ 룰이 없다.** IPS local SID의 분류는 미확인.
- ⚠️ 운영 제약(2026-09-26 실제 발생): **공격성 테스트 트래픽을 캠퍼스 VPN 경유로 보내면 캠퍼스 FW가 (VPN IP↔A) 쌍을 차단**해 A 관리접속이 끊김. IDS/WAF 테스트는 반드시 Kali/B/C 등 **VM 세그먼트 안**에서. A 복구 경로: `ssh -J groot-b groot_a@10.200.10.1`.
- **C**: `ens192` 제거·기본 경로 A, Apache·Wazuh Agent active, DVWA 302, `log4shell-lab` 가동(`10.200.10.20:8080` 내부 바인딩), NTP 동기화를 SSH로 확인했다. 취약점 2,422건 인덱싱은 이전 기록의 수치다.
- **MCP·Agent**: 읽기 서버(B)와 응답 서버(A) 배치·계약 테스트 완료. 런타임은 Hermes(B)로 결정·배치했고 DGX 추론, 경보 조사, Tier 2 승인→차단 경로를 2026-09-28에 E2E 검증했다.
- **승인형 룰 변경(2026-10-08 약 12:58 KST)**: B 승인 브로커와 A/B 전용 `rulechg`·worker timer를 배포하고 Hermes에 `rule-a`·`rule-b`를 추가했다. HMAC 통신 및 WAF·Suricata·Wazuh 로컬 룰 대상의 읽기 조회를 확인했고 운영 룰 해시는 그대로다. 실제 Mattermost 승인→룰 적용 E2E는 아직 검증하지 않았다.
- 제약: 일반 웹(80/443) 반출 제한으로 이미지·패키지는 오프라인 반입. DGX `:11434` 연결은 확보됐다.
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
  │  │  ├─ FW  (nftables)         │                     │
  │  │  ├─ IPS (Suricata passive) │                     │
  │  │  └─ WAF (ModSecurity+CRS)  │                     │
  │  └────────────┬─────────────┘                      │
  │               ▼ (검사 통과 트래픽)                   │
  │  ┌──────────────────────────┐                      │
  │  │ 2026_capstone_Groot_C          │  ← 메인 웹서버        │
  │  │  ├─ DVWA (베어메탈)        │  (웹공격 대상)        │
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
      [ DGX Spark — LLM 추론 전용 ]
        Ollama · qwen3.6:35b (OpenAI 호환 /v1, 256k ctx)
   ↳ 실제 배포: Agent Runtime(Hermes)은 Groot_B 상주(MCP와 같은 세그먼트),
      Policy Engine 은 응답 MCP(Groot_A) 안. DGX 는 추론만 담당.
```

트래픽 흐름: Kali → Groot_A의 FW·WAF → Groot_C(DVWA/CVE). Suricata는 A 외부 인터페이스에서 passive로 관찰한다. WAF는 DetectionOnly다. 로그는 Groot_B의 Wazuh로 집중하고, Hermes(B)는 MCP를 통해 조사·대응한다.

네트워크 세그먼트(실제 구성 = 2세그먼트, 2026-09-29 확정):
- A 외부 NIC의 **실측 직결망은 `192.168.16.128/25`**(`192.168.16.230/25`, GW `.129`). A의 10443 DNAT 출발지 허용목록은 별도 `192.168.16.0/25`이며, Kali 주소·라우팅은 아직 확인되지 않았다. Kali→A 경로를 검증하기 전 두 대역을 같은 직결 세그먼트로 취급하지 않는다.
- 내부망 세그먼트 `10.200.10.0/24` (Groot_A ↔ Groot_B/Groot_C — Wazuh/MCP/Hermes)
- B/C는 2026-10-02에 외부 NIC `ens192` 물리 제거를 완료했고, 10/6 SSH 재점검에서 NIC 부재와 기본 경로 A를 재확인했다.
- 외부/DMZ/관리 3세그먼트 분리는 캠퍼스망 제약·구축 범위상 미채택

### 온프레미스 전환의 이점 (AWS 대비)
- **Port Scan이 실제로 탐지된다.** AWS Security Group이 패킷을 관문에서 버리던 문제가 사라져 IPS가 스캔을 관측.
- **경보 소스가 풍부해진다.** FW 로그 + IPS(Suricata) 경보 + WAF(ModSecurity) 로그 → Agent 상관분석 재료 증가.
- **네트워크 복잡성·비용 제거.** SSH 역방향 터널, AWS SSM, 팔로알토 우회, 클라우드 비용 전부 불필요.
- **재현성.** 전체를 한 호스트에서 스냅샷·복제 가능.

---

## 1.5 사양표 (B-1 Docker Compose)

실제 ESXi 호스트: KTNF SR285K2-V5, Xeon Gold 5215 20 논리CPU(약 10물리/20스레드), RAM 256 GB, NIC 4개, 관리망 192.168.16.130(GW .129). **다른 서버와 공유하므로 보수적으로 배분.** C=vCPU.

이 호스트에는 Groot_A/B/C만 올린다(DGX Spark는 ARM 외부장비, Kali는 노트북 → 호스트 자원 미사용).

| VM | 역할 | 목표(이 프로젝트) | 운용 NIC(10/6 기록) |
|---|---|---|---|
| Groot_A | 보안장비(FW/IPS/WAF) | **2C / 6G / 60G** | 외부 `ens192`·내부 `ens160` |
| Groot_B | SIEM + MCP | **4C / 16G / 150G** | 내부 `ens160` |
| Groot_C | 웹서버(DVWA/DB/CVE) | **2C / 6G / 60G** | 내부 `ens160` |
| 우리 몫 합계 | | **8C / 28G / 270G** | 호스트 CPU의 ~40%, RAM의 ~11% |
| 남는 여유 | 다른 서버용 | 약 12C / 228G | |

배분 원칙:
- RAM은 256G로 남아돌아 병목인 Groot_B(Wazuh Indexer)에 16G를 넉넉히 준다(RAM으로 병목 해소). CPU는 공유 자원이라 8 vCPU로 보수적.
- 네트워크 경로: A가 외부망과 내부망 사이의 관문이며 B/C의 기본 경로는 A다. 일반 웹 반출은 제한돼 패키지·이미지는 오프라인 반입했다.
- 확인 필요: 데이터스토어 여유 ≥ 300G (이미지에 디스크 용량 미표시).
- 외부 고정: DGX Spark(GB10, 128G 통합, 30B BF16 여유), Kali 노트북(2C/4G).
- 주요 SW: Groot_A(nftables/Suricata/ModSecurity+nginx/Wazuh Agent), Groot_B(Wazuh Mgr·Indexer·Dash/MCP Server), Groot_C(DVWA/DB/CVE/Wazuh Agent).
- k3s(B-2) 사양은 archive/PLAN_2.md 1.5 참조(보류안).

## 2. 옵션 결정 (근거)

### 옵션 A. LLM Agent 실행 위치

| | A-1. DGX Spark 유지 (권장) | A-2. ESXi GPU 패스스루 |
|---|---|---|
| 구성 | DGX Spark에서 **Ollama** 추론(`qwen3.6:35b`), Agent Runtime(Hermes)은 Groot_B 상주(MCP와 같은 세그먼트), Policy Engine은 응답 MCP(Groot_A) 안 | ESXi 호스트 GPU를 VM 하나에 패스스루하여 추론 실행 |
| 장점 | 제안서 "DGX Spark 기반" 정체성 유지, 128GB로 30B 여유, 관제망과 물리 분리 | 전 구성이 한 호스트에 모임, 관리 단순 |
| 단점 | DGX Spark ↔ ESXi 네트워크 연결 필요 | 제안서 전제(DGX Spark)와 어긋남, ESXi 호스트에 충분한 GPU 필요, 패스스루 설정 |
| 공통 | 읽기 MCP는 Groot_B, 응답 MCP는 Groot_A에 두어 자격증명 격리(A안) 유지. Agent 프로세스에는 자격증명 없음 | |

→ **결정: A-1 (DGX Spark).** 과제 정체성과 자격증명 격리에 가장 잘 맞음. A-2는 DGX Spark 사용 불가 시 대안.

### 옵션 B. 컨테이너 오케스트레이션

| | B-1. Docker Compose (권장) | B-2. Kubernetes (k3s) |
|---|---|---|
| 구성 | A 보안 스택·B Wazuh는 Docker Compose, C는 DVWA 베어메탈+Log4Shell 랩 컨테이너 | 경량 K8s(k3s)로 파드 배포 |
| 장점 | 구축·디버깅 빠름, 캡스톤 규모에 적합, Wazuh/Suricata 공식 compose 예제 풍부 | 오케스트레이션 학습 효과, 선언적 배포 |
| 단점 | 다중 노드 오케스트레이션 학습은 약함 | 구축 복잡도·시간 증가, Suricata inline·Wazuh의 K8s 네트워킹이 까다로움 |

→ **결정: B-1 (Docker Compose).** 보안장비 inline 검사와 Wazuh 안정성 때문에 Compose가 안전. k3s는 대안.

---

## 3. 확정 결정 (유지 항목)

| 항목 | 결정 | 비고 |
|---|---|---|
| 모델 | **`qwen3.6:35b`** (채택) | tool calling·thinking 지원, DGX Ollama `.110`에 256k ctx 상주. 초기 계획 Qwen3-30B-A3B(MoE)/32B 비교에서 실제 상주 모델로 확정 |
| 추론 서버 | **Ollama** (:11434, OpenAI 호환 `/v1`) — DGX Spark 211.170.162.110/.111 두 엔드포인트 | Qwen3 tool calling·thinking 지원, `qwen3.6:35b` 채택(.110에 256k ctx 상주). vLLM은 대안 |
| MCP 역할 | 자격증명 격리 보안 경계 (A안). 읽기 MCP는 Groot_B, 응답 MCP는 Groot_A, Agent는 자격증명 없음 | 온프레미스 분리로 경계 더 명확 |
| Alert 전달 | Indexer 폴링 (전 구간 내부망이라 웹훅도 가능) | |
| 공격 시나리오 | DVWA(웹공격) + CVE 컨테이너(Log4Shell 등) 병행 | KEV 등재 CVE |
| 대응 | 자동은 되돌릴 수 있는 동작만, 고위험은 사람 승인 | Policy Engine + HITL(⚠️Slack 불가, 443 차단 — 온프레미스 Mattermost 로 대체 완료, Tier 2 승인) |
| Fine-tuning | 확장 목표 (LoRA/QLoRA) | 없어도 완결 |

확정: LLM=DGX Spark(A-1), 오케스트레이션=Docker Compose(B-1).

보안장비(Groot_A) 제품 확정
| 역할 | 제품 | 비고 |
|---|---|---|
| FW | nftables (게이트웨이 netfilter) | Response Tool이 drop 규칙 조작. 대안 OPNsense |
| IPS | Suricata passive + ET Open·local 룰(인라인 NFQUEUE 전환 예정) | eve.json → Wazuh |
| WAF | ModSecurity v3 + OWASP CRS + 신규 룰(nginx 리버스 프록시) | DetectionOnly 유지, 감사로그 → Wazuh |

트래픽 경로: Kali → Groot_A의 FW·WAF → Groot_C. Suricata는 현재 passive 관찰 중이다.

---

## 0단계. 사전 준비 (1주)

- [x] ESXi 호스트 사양 확인 (CPU/RAM/디스크, GPU 유무 → 옵션 A-2 가능 여부) — 사양표 1.5, GPU 없음 → A-1 유지
- [x] VM 3대 생성: 2026_capstone_Groot_A / _B / _C (**Ubuntu Server 24.04.5 LTS**, GUI 없이 동일 버전 통일), Kali는 노트북 호스트 — user groot_a/b/c, host groot-sec/siem/web
- [x] ESXi 포트그룹 세그먼트 구성 — **2세그먼트로 확정(2026-09-29)**: 내부망(10.200.10.0/24) + A 외부 직결망(`192.168.16.128/25`, 10/6 SSH 재확인), Groot_A가 NAT 게이트웨이. A의 10443 허용 출발지 `192.168.16.0/25`는 직결망과 다르며 Kali 경로 확인이 남았다. 캠퍼스망 제약·구축 범위상 외부/DMZ/관리 3세그먼트 분리는 하지 않기로 결정.
- [x] (확정 B-1) 각 VM에 Docker/Compose 설치 — A·B 오프라인 설치·검증, C Docker와 `log4shell-lab` 가동(2026-09-26 담당자 확인)
- [x] (확정) 보안장비 이미지 준비: nftables(FW), Suricata passive IDS(ET Open+local, 인라인 IPS는 후속 전환), ModSecurity+OWASP CRS(WAF, 공식 이미지) — A에 `jasonish/suricata:latest`·`owasp/modsecurity-crs:nginx`, B에 Wazuh 4.14.8 오프라인 반입 완료. nftables 네이티브
- [x] 저장소 디렉터리 구조 생성 — infra/groot-a·b·c 등

현재 배포 파일 구조와 A/B/C 역할은 [infra/README.md](infra/README.md)를 따른다. 초기 구상에는 C의 DVWA/DB/CVE 통합 Compose가 있었으나, 실제 C는 DVWA 베어메탈과 Log4Shell 랩 컨테이너로 구성됐다.

---

## 1단계. 인프라 구축 (2~3주)

목표: 공격 시나리오 실행 시 Wazuh에 FW/IPS/WAF/서버 경보가 뜬다.

### 1-1. 2026_capstone_Groot_A (보안장비)
- [x] 게이트웨이 역할 설정 (외부↔DMZ 라우팅, IP 포워딩) — NAT masquerade(10.200.10.0/24→ens192) + DOCKER-USER forward + ip_forward 영구화, `capstone-nat.service`, B 경유 검증 완료
- [x] FW: nftables 게이트웨이·`agent_block` — 2026-09-27 NAT·호스트 input 기본 차단·관리 DNAT·응답 CLI와 실차단 검증 완료. **2026-10-06 기록상 FW v2 적용·확정**: `FORWARD=DROP`, `CAPSTONE-FWD` 14룰, `capstone_fw` v2(SPOOF·SSH rate·output 체인), 데드맨 타이머 0. 대시보드 DNAT와 A→B:443·A→C:80 경로 보존. 10/1의 FORWARD=ACCEPT 감사 결과는 이 적용으로 해소됨. 신규 FW 로그의 B 분류·실발화는 미확인.
- [x] IPS: Suricata — 2026-09-26 passive IDS/ET Open 배치와 기존 sid 2008538 경보 실측 완료. **2026-10-06 기록상** `-S /rules/all.rules`(ET+local) 및 Phase-A(community-id·ja3/ja4·threshold) 적용, eve `community_id` 275건 확인. **local SID 1000xxx의 공격 발화는 미검증**, NFQUEUE 인라인 전환은 후속 게이트.
- [x] WAF: ModSecurity v3 + OWASP CRS 4.29 — 2026-09-26 기본 배치·기존 CRS 경보 실측 완료. **2026-10-06 재집계 기준** `REQUEST-948-GROOT_A_WAF.conf`의 활성 고유 ID 10개(`SecRule` 지시자 12줄) 로드·`nginx -t` 통과, 리버스프록시 정상. 기존 11개 기록은 오집계이며 `id:10010`은 주석 처리돼 활성 룰이 아니다. **DetectionOnly 유지**; 신규 `GROOT_A/*` 룰의 audit→Wazuh 실발화 및 `On` 전환은 후속 검증.
- [x] Wazuh Agent 설치 — **완료(2026-09-26)**: 4.14.8 오프라인 dpkg(배포변수 WAZUH_MANAGER=groot-siem), authd 자동등록 → 매니저 **ID 001 groot-sec Active**. 기본 active-response는 비활성(응답은 MCP→nft `agent_block` 로만). 스크립트 `infra/groot-a/install_agent.sh`. **기존 IPS/WAF 로그 전송 완료**: `agent_localfile.sh`(eve.json·audit.log json localfile, label capstone.source) → B 도착 검증. 로그 회전 `logrotate-capstone-secstack`(daily/500M/14, copytruncate). FW Phase 2 로그는 B 기존 룰로 수집됐고, FW v2 신규 접두사 분류와 실발화는 미검증.

### 1-2. 2026_capstone_Groot_B (Wazuh + MCP)
- [x] Wazuh all-in-one 설치 (Manager+Indexer+Dashboard) — **기동 완료(2026-09-26)**: 4.14.8 single-node compose, 인증서는 오프라인 `wazuh-certs-tool.sh`(openssl)로 생성. 인덱서 green·대시보드 302·API 토큰 OK. 절차 `infra/groot-b/README.md` (⚠️ 인증서 권한 644 필수). **기본 비번 교체 완료**(3계정 통일, 데모계정 삭제, 값은 CREDENTIALS.local.md)
- [x] Groot_A/C의 Agent 등록, Dashboard에서 Active 확인 — **완료**: 001 groot-sec(A)·002 groot-web(C) 모두 Active(2026-09-26, 2026-09-27 재확인). 매니저 000 포함 3대
- [x] Suricata eve / ModSecurity 감사로그 수집 룰 확인, MITRE 태그 확인 — **완료(2026-09-26)**: Suricata는 내장 86601(lv3) 위에 severity별 100110(lv9)/100111(lv6)+버스트 100112, ModSecurity는 내장 룰 없음 → JSON 필드 기반 100100~100103(CRS 히트 lv7, 임계 초과 lv10, 버스트 lv12), MITRE T1190/T1595. `infra/groot-b/local_rules.xml`(wazuh-logtest·`analysisd -t` 검증 후 적용). B에서 A로 프로브 → **alerts.json·인덱서(`rule.groups:capstone`) 5건 실측**
- [ ] **신규 신호 Wazuh 디코더·룰 보완**: 10/6 SSH 점검에서 B 라이브 `local_decoder.xml`/`local_rules.xml`에 FW `SPOOF`/`FW_SSH_RATE`/`FW_DROP_FWD`/`FW_SHADOW_OUT`와 WAF `GROOT_A/*` 100200–299용 항목이 없음을 확인했다. 추가 후 대시보드 분류를 검증한다. IPS local SID 1000xxx 분류는 별도 확인.
- [x] Vulnerability Detection 활성화 (OS 패키지 CVE 매핑 확인) — **완료**: C(002) 취약점 상태 2,422건 인덱싱, 대시보드 Vulnerability Inventory 확인, `/soc vulns` 조회
- [x] 읽기 MCP Server 배치(B의 읽기 자격증명 격리), LLM 실행처에서 접근 확인 — **읽기 서버 배치·검증 완료(2026-09-26)**: `mcp-server-wazuh` v0.3.0(sha256 검증) `/opt/mcp/`, 전용 사용자 `mcp` + sshd ForceCommand + authorized_keys restrict, 읽기전용 계정 `mcp-ro`(API readonly / 인덱서 readall, 쓰기 403 실증), 자격증명은 B `/etc/mcp/wazuh-ro.env`에만. Mac에서 `ssh -T groot-mcp`(A 점프 전용 키)로 **계약 테스트 PASS**(initialize·14 tools·get_wazuh_alert_summary 실경보 반환). `infra/mcp/deploy_mcp_B.sh`(적대적 리뷰 5관점 반영), `contract_test.py`. 차단 권한·승인 브로커 설정은 A의 별도 응답 MCP 경계에 있다.

### 1-3. 2026_capstone_Groot_C (메인서버)
- [x] DVWA 실행 (웹공격 대상) — **베어메탈로 설치·구동 중**(별도 담당). 하이브리드: DVWA 베어메탈 유지, 재현성은 ESXi 스냅샷+DVWA Reset
- [x] CVE 취약 컨테이너 실행: Log4Shell(CVE-2021-44228) 취약 앱 — **C 담당자 완료 확인(2026-09-26)**: Docker 29.8.1 + `log4shell-lab`(:8080) 가동. 권한상승용 취약 패키지(sudo Baron Samedit)는 VM OS 수준에 구성(대기)
- [x] Wazuh Agent 설치, 웹로그·FIM·Syscollector·인증로그 수집 — **담당자 완료 + 연동 보완(2026-09-26)**: 에이전트 4.14.8 → 매니저 10.200.10.10 내부망, **ID 002 groot-web Active**, apache access/error(`apache` 포맷)·journald 수집, 인벤토리(764패키지·포트)·취약점 상태 2,422건 인덱싱, SCA/rootcheck 동작. 웹 룰 실측(31101/31103/31105). **보완**: `c_integrate.sh` — 내부 호스트명 + **apache mod_remoteip**(WAF의 X-Forwarded-For 복원; 이전엔 C 경보 srcip가 전부 A=10.200.10.1이라 차단 대응이 A를 막을 위험) → srcip 실제 클라이언트로 확인. 시계(최종): 캠퍼스가 외부 NTP(UDP 123) 차단 → **A ← 192.168.16.131(캠퍼스 시간 서버, chrony 오프라인 반입) ; B/C ← A(10.200.10.1, timesyncd)** 체인. `infra/groot-a/ntp_server.sh`, `infra/ntp_client.sh`. 남은 것: DVWA 기본 보안레벨 impossible → 시나리오 시 low(담당자 협의)

### 1-4. 공격자 (Kali)
- [ ] 노트북에 Kali, ESXi 외부 세그먼트에 연결
- [ ] nmap/nikto/sqlmap/hydra, Log4Shell PoC + 악성 LDAP(marshalsec) 준비

### 1-5. 경보 검증
- [~] 시나리오 1~3 실행 → IPS/WAF/Wazuh 경보 발생 확인, rule id 기록(`scenarios/alerts.md`) — **시나리오·탐지 검증 문서 완비(2026-09-27), 실행은 미완료**. 선행조건: DVWA level low(C 담당), A Log4Shell 토글 설치본의 `OBS_SEG` 동기화와 경로 확인, C sudo 패키지의 CVE 취약성 확인(현재 1.8.31 버전 문자열만 관측), Kali 주소·라우팅 확인과 VPN을 통하지 않는 실습 경로.
- [ ] **신규 룰 실발화 확인**: VM 세그먼트에서 공격 프로브를 실행해 WAF audit·IPS eve·FW 로그→B Wazuh alerts 경로를 실측한다(캠퍼스 VPN 경유 금지).
- [ ] **앱 계층 차단 전환**: WAF `On`·Suricata NFQUEUE 인라인 drop은 현재 미적용. 탐지 실측 후 별도 게이트에서 전환·검증한다. 시나리오 `OBS_SEG`는 저장소 스크립트에 있으나 A 설치본에는 없으며, 허용 목적지 `192.168.16.0/25`가 실제 Kali 대역인지 확인한 뒤 배포한다.
- [x] FW 자동 차단(nftables) 동작 확인 → Baseline 대응 — `agent_block`/`inet capstone_fw` 완료·실차단 검증(1-1 참조). 대응 룰 100121/100126~100129

---

## 2단계. MCP Tool + AI Agent (3~4주)

목표: 경보 발생 시 Agent가 자동 조사하고 판단·대응 제안을 산출.

### 2-1. MCP Server (읽기 Groot_B, 응답 Groot_A, 승인형 로컬 룰 변경 A/B)
설계 원칙(A안): Hermes는 B의 격리 컨테이너에서, 읽기 MCP는 B의 별도 계정·프로세스에서, 응답 MCP·Policy Engine은 A의 별도 계정·프로세스에서 실행한다. 승인형 로컬 룰 변경 MCP는 A/B의 또 다른 전용 계정·root helper와 B의 브로커에 둔다. Wazuh 읽기 자격증명은 B의 MCP 환경에, 차단 권한과 승인 브로커 설정은 A의 응답 경계에 두며 Hermes에는 주지 않는다.
**클라이언트 불가지론(pluggable agent)**: 서버는 어떤 AI가 붙는지 모르게 설계 — 에이전트 런타임/LLM 교체는 클라이언트 설정 1블록만 변경(전송 계약: 1차 stdio over SSH → 확장 HTTP). 설계·템플릿·계약테스트: `infra/mcp/README.md`. 읽기 서버는 기성 `gbrigandi/mcp-server-wazuh` v0.3.0(리뷰 완료), 응답 서버는 소형 커스텀(별도 자격증명).
- [x] Wazuh Tool: `search_alerts`, `get_alert`, `get_agent_status`, `get_vulnerabilities` — **읽기 MCP 서버 14툴로 커버**(계약테스트 PASS) + SOC 챗봇 `/soc alerts|agents|vulns`로 실사용
- [ ] CVE Tool: `cve_lookup` → NVD + CISA KEV — **CISA KEV 오프라인 반입·리뷰 완료**(B `~/capstone/kev`, 1,726건, CC0, 시나리오 CVE 포함 · `infra/groot-b/kev-data.md`). NVD 상세는 보완 예정
- [x] Server Tool: 프로세스/포트/FIM/인증 — **읽기 MCP 서버로 커버**(계약테스트 PASS): 프로세스·포트는 `get_wazuh_agent_processes`/`get_wazuh_agent_ports`, FIM·인증 이벤트는 Wazuh 알림·매니저 로그 조회(`get_wazuh_alert_summary`/`search_wazuh_manager_logs`)로 확인. 경보 조사 프롬프트에서 실사용
- [x] Network Tool: IPS(Suricata)·WAF·FW 로그 조회 — 기존 세 소스의 Wazuh 집중 로그를 읽기 MCP로 조회 가능. **2026-10-06 SSH 점검에서 B 신규 FW·WAF 디코더/룰 부재 확인**; 추가 후 MCP 조회 결과를 검증한다. IPS local SID 분류는 미확인.
- [x] Response Tool `block_ip`/`unblock_ip`/`list_blocks` — **완료(2026-09-27)**: 응답 MCP 서버(A, 파이썬 stdlib stdio, `infra/mcp/response-mcp.py`), 전용 사용자 `resp`(sshd ForceCommand + authorized_keys restrict) + sudoers(agent_block add/del/list 만, flush 금지) → nft `agent_block`. 정책 엔진(TTL 상한 RESP_MAX_MINUTES=120, reason 필수·정규화, IP 검증, flush 미노출). TTL 만료 리퍼(systemd 타이머)로 auto-unblock 감사(action=expire→B 100131). 자격증명 격리 유지(에이전트=키만, 차단 능력=A sudoers). Mac `ssh -T groot-resp` 계약 테스트 PASS: block→100121, 거부(보호IP)→100123, unblock→100122, 만료→100131. 적대적 리뷰 3관점 반영. `deploy_response_A.sh`(데드맨 롤백 트랩). — [ ] `isolate_host`·`notify`(Mattermost)는 추후
- [~] 승인형 규칙 변경 MCP — **2026-10-08 저장소 구현·오프라인 검증·라이브 배포 및 읽기/인증 점검 완료**: 기존 읽기 MCP는 유지하고 A(WAF·Suricata)와 B(Wazuh)에 별도 전용 계정·고정 대상 변경기를 배포했다. 현재 전문·해시 조회 → 원본 해시가 맞는 전체 후보 제안 → Mattermost 전체 diff/해시 카드 → 지정 승인자 클릭 → 일회성 승인 소비 → 적용 전 재검사·백업·엔진 검사·재로드/재시작·읽기 해시 확인·실패 복구 흐름이다. A↔B 승인 API는 평문 토큰을 보내지 않고 일회성 nonce·양방향 HMAC 서명을 검사한다. B 브로커·A/B `rulechg`/worker timer가 동작하고 Hermes에 `rule-a`·`rule-b`가 등록됐다. HMAC 통신·세 대상 읽기 조회를 통과했으며 운영 룰 해시는 배포 전후 동일하다. **실제 Mattermost 승인 버튼 클릭→룰 적용·복구 E2E는 별도 검증 작업으로 남았다.** nft 전체 정책과 WAF/IPS 차단 모드 전환은 범위 밖이다. 세부 범위와 한계는 `infra/mcp/README.md` 참조.
- [ ] `cve_lookup` 등 조사 툴 확장(읽기 서버 14툴 + KEV)
- [x] 각 Tool 단독 테스트 — **계약테스트 PASS**: 읽기 14툴·응답 3툴(`block_ip`/`unblock_ip`/`list_blocks`) 초기화·호출 검증(`infra/mcp/contract_test.py`), 컨테이너 안 재검증(2026-09-28)

### 2-2. Agent Runtime = Hermes Agent (Nous Research) — **채택·배치 완료 (2026-09-28)**
> **해소(2026-09-28)**: Hermes Agent 를 `Groot_B` 에 컨테이너로 배치 완료(공식 이미지 오프라인 반입) → DGX Ollama(`211.170.162.110/.111`) 연결·MCP 17툴 등록·경보 트리거·Tier 2 승인까지 E2E 실측(아래 항목 참조). 초기엔 DGX 도달 불가로 Claude Code 직결을 대안으로 검토했으나 DGX 엔드포인트가 열려 불필요해졌다.

직접 구현이 아니라 Hermes Agent를 사용(교수 지정). MCP 네이티브 지원이라 2-1 MCP Server를 그대로 붙인다.
- [x] Hermes 설치, `~/.hermes/config.yaml`의 `mcp_servers`에 우리 MCP Server 등록(stdio/HTTP) — **2026-09-28 완료**: 설치 위치=B(MCP 서버가 있는 VM; Mac 은 콘솔), 방식=공식 Docker 이미지 `nousresearch/hermes-agent:v2026.9.24`(amd64 968MB) 오프라인 반입(`infra/tools/pull_image.py`, 레지스트리 API·sha256 검증·OCI layout). `infra/hermes/deploy_hermes_B.sh prep` 완료: 격리 사용자 `hermes`(mcp 그룹 아님) + `/opt/hermes-data`(=/opt/data) + 컨테이너용 SSH 키/config + `config.yaml`(wazuh-ro=full, resp=untrusted) + B(mcp)·A(resp) authorized_keys 에 `restrict,command=` 등록. **호스트측 계약 테스트 PASS(읽기 14툴·응답 list_blocks)**. 이미지 반입·load 후 **컨테이너 안 계약 테스트 PASS(읽기·응답) + Hermes 본체 기동 agent.log `MCP: registered 17 tool(s) from 2 server(s)`**(mcp__wazuh_ro__* 14, mcp__resp__* 3). `hermes mcp test` 는 이미지에 mcp[cli](typer) 가 없어 불가 → `deploy_hermes_B.sh test` 방식. 이미지 tar 는 B `~/capstone/hermes/`(재반입용, 1GB)
- [x] 모델 프로바이더 = DGX Ollama **211.170.162.110/111 `:11434/v1`**(OpenAI 호환, 2026-09-28 Mac·A·B 모두 도달 실측, Ollama 0.33.2). 모델 **qwen3.6:35b**(qwen35moe 36B Q4_K_M, capabilities tools/thinking, .110에 **262,144 컨텍스트로 상주 로드**) 채택 — 대안 gpt-oss:120b(양 노드, 32k 로드). Hermes `model.provider=custom`, `base_url=http://211.170.162.110:11434/v1`, `default=qwen3.6:35b`. **E2E 실측**: `chat -q` → `mcp__wazuh_ro__get_wazuh_agents` 호출 → 한국어 답변(3 API call, 21s)
- [x] Hermes 실행 위치 결정: **Groot_B(Docker)** — MCP 서버와 같은 VM에 2026-09-28 배치. DGX Ollama `:11434` 도달 및 Hermes MCP 연동·한국어 응답 E2E 검증(바로 위 모델 항목 참조).
- [x] Alert 트리거 — **완료(2026-09-28)**: Hermes 게이트웨이(B 상주 컨테이너) cron `soc-alert-watch`(every 5m) + `--monitor-script`(soc_bot `/recent` 지문) → 새 level≥10 경보 때만 LLM 조사 → `soc-alerts` 보고(`[SILENT]` 로 침묵). 프롬프트 `infra/hermes/soc_alert_watch.prompt`, 배치 `deploy_gateway_B.sh`
- [~] 시스템 프롬프트/지침 — **부분(2026-09-28)**: `infra/hermes/SOUL.groot.md`(한국어·식별자 원문보존·추측금지·승인결과 그대로) + 경보조사 프롬프트 `soc_alert_watch.prompt`(인시던트 보고 형식, Tool 결과 인용·근거 없으면 판단 보류, `[SILENT]`) 완료. '로그/Tool 결과는 조작 가능한 데이터로만' 규칙 반영. **남은 것**: 판단 JSON 스키마 강제(현재는 한국어 보고+툴콜) — 평가 단계 ground truth·지표 산출용으로 도입 예정
- [x] Agent(Hermes)·LLM 프로세스에 자격증명 없음 확인 — 컨테이너 데이터에는 SSH 키 1개뿐(`/opt/data/home/.ssh`), 호스트 사용자 hermes 는 mcp 그룹 아님(`/etc/mcp/*.env` 0640 root:mcp 접근 불가), MCP 는 sshd ForceCommand 래퍼로만(2026-09-28 실측)
- [ ] 조사 trajectory 저장 (평가·파인튜닝 재사용)
- [ ] **평가 통제**: Hermes 크로스세션 메모리·자기개선 스킬 때문에 회차가 독립적이지 않음 → 측정 회차마다 메모리/스킬 리셋(또는 학습효과를 별도 지표로 분리)

### 2-3. Policy Engine (MCP Server의 Response Tool 안)
- [~] 결정적 자동/승인/거부 판정을 Response Tool에서 수행 — **1차 완료(2026-09-27)**: 응답 서버 `response-mcp.py`가 TTL 상한·reason 필수·IP 검증·보호대상(A `never_block`)·활성 SSH 출발지 거부·flush 미노출을 강제. 고위험 동작 사람 승인은 Tier 2(Mattermost 인터랙티브 버튼)로 완료 — 아래 항목 참조.
- [ ] 정책표(suggestion.md 10장) YAML화
- [ ] 결정적 자동/승인/거부 판정을 Response Tool에서 수행, 보호 IP·allowlist
- [x] 고위험 동작 사람 승인 경로 — **Tier 2 E2E 검증(2026-09-28)**: 응답 서버 `block_ip` → soc_bot 브로커 → Mattermost [승인][거부] 버튼 → 승인 시 실행. 무인(cron)에서도 채팅 요청→승인→차단→회신을 실측했다. **2026-10-08 코드 재확인:** 브로커 미설정이면 `block_ip`는 즉시 실행하며 `APPROVERS` 미설정이면 승인자를 제한하지 않는다. 전체 설정에 대해 fail-closed라고 볼 수 없고, 오늘은 라이브 승인 설정·동작을 재시험하지 않았다.
- [x] Response 실차단 게이트 검증 — 2026-09-28 승인→차단 E2E를 실측했다. 새 WAF·IPS·FW v2 경보에서 시작하는 자동/승인 경로는 신규 분류 룰과 시나리오 경보 실발화 후 별도로 검증한다.

### 2-4. 통합 테스트
- [ ] 시나리오 1~4 실행, Agent 조사 완결 확인
- [ ] 시나리오 5(프롬프트 인젝션) — Agent가 로그 지시 안 따름 + 자격증명 격리로 유출·오작동 불가 확인

---

## 3단계. 평가 (2주)
- [ ] 시나리오별 ground truth 정의 (공격여부·단계·침해·적절대응)
- [ ] 시나리오 0(정상) 포함, 자동 실행 스크립트, 각 10회 이상 반복
- [ ] **Hermes 상태 리셋으로 회차 독립성 확보** (학습 off + 회차마다 초기화). 절차: `infra/hermes/eval_reset.md`
- [ ] Baseline(Wazuh 룰+FW/IPS 자동차단+사람 수동 조사) vs Agentic SOC 측정 — 비교군의 WAF·IPS 모드를 동일하게 통제한다. 2026-10-06 기준 WAF DetectionOnly·IPS passive이므로 자체 차단 효과를 측정하려면 별도 인라인 전환·실측이 필요하다.
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
| Suricata inline/WAF 차단 전환 | 현재 passive/DetectionOnly. 신규 로그 분류·실발화 검증 뒤 별도 차단 게이트에서 전환 |
| DGX Spark 속도 부족 | 모델 축소, Tool 응답 요약 |
| K8s 구축 지연(B-2) | Docker Compose로 회귀 |
| 일정 초과 | Fine-tuning 제외해도 완결되게 설계 |

---

## 진행 로그
최신 항목을 위에 둔다. (세부 이력은 `대화기록/YYYY-MM-DD.md`)

### 2026-10-08 (약 12:58 KST, 승인형 룰 변경 MCP 배포)
- B 승인 브로커와 A/B `rulechg` 전용 SSH 강제 명령·root helper·worker timer를 배포했다. Hermes에 `rule-a`·`rule-b`를 추가하고 기존 읽기·응답 MCP 서버를 유지했다.
- HMAC health와 WAF·Suricata·Wazuh 로컬 룰 대상의 읽기 조회가 통과했다. A/B worker timer는 active/enabled이며 운영 룰 파일 해시는 배포 전후 동일하다. 실제 Mattermost 승인 버튼→룰 적용·복구 E2E는 아직 실행하지 않았다. [작업 기록](대화기록/2026-10-08.md)

### 2026-10-06 (05:05~05:07 UTC SSH 읽기 전용 재점검)
- A의 FW v2 `FORWARD=DROP`·CAPSTONE-FWD 14룰, WAF 룰 마운트·DetectionOnly, Suricata 합본 룰·Phase-A passive 및 eve 갱신을 재확인했다. B/C의 `ens192` 부재·A 기본 경로, B 스택/에이전트 3대·DGX API 200, C DVWA·랩·Agent·NTP 정상도 확인했다.
- **새 확인 사항**: B 라이브 `local_decoder.xml`/`local_rules.xml`에 신규 FW 프리픽스와 WAF 100200+ 룰이 없다. 추가 배포 뒤 공격 프로브로 실제 발화 확인이 필요하다. IPS local SID의 분류는 아직 확인되지 않았다.

### 2026-10-06 (세션 1: 이전 배치 적용 상태 확인)
- 세션 1 실측 기록상 FW v2 `FORWARD=DROP` 확정, WAF SecRule 11개 DetectionOnly 로드, IPS ET+local/Phase-A passive 적용, B/C `ens192` 제거·기본 경로 A 유지.
- 이 시점에는 신규 FW·WAF·IPS 룰의 B 분류와 공격 시 실제 발화가 미확인이었다. 같은 날 위 SSH 재점검에서 FW·WAF 신규 디코더/룰 부재를 확인했다. WAF `On`·IPS 인라인 drop 및 Log4Shell egress 관찰용 `OBS_SEG`는 후속 작업.
- 같은 날 세션 2에서 탐지 모드로 현재 에이전트 조사·`agent_block` 평가를 진행할 수 있으나, 최종 차단 성능 주장에는 별도 전환 검증이 필요하다고 정리했다.

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
