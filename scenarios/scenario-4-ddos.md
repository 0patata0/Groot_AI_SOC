# 시나리오 4 — 볼류메트릭 DDoS (2호스트 ICMP+SYN 플러드, A 게이트웨이)

<!-- current-project-context:2026-11-10 -->
> **현행 기준 — 2026-11-10:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 이 시나리오는 2026-11-10 19:31~19:34 KST에 **실제 1회 실행**했다. 아래 "실측 결과"는 그 1회 관측이며 평균·반복·완료를 뜻하지 않는다. 원시 증거는 로컬 전용 `대화기록/검증/2026-11-10-ddos-inspect/`에 보존한다.
<!-- /current-project-context -->

목표: 승인된 Kali 공격 호스트 2대에서 사전 캡처한 DDoS 트래픽을 A(게이트웨이)로 **재생(tcpreplay)**하고, FW·IDS·SIEM이 이 볼류메트릭 공격을 보는지 확인한다. 공격 트래픽 생성 방법은 이 문서가 직접 쓰지 않으며, 재생본은 공개 DDoS 트레이스를 랩 IP로 재매핑한 것이다.

- 대상: **A `192.168.16.230`** (TCP SYN은 `:80` = WAF/nginx 정문). ICMP는 L3로 A에만 도달(DVWA까지 가지 않음).
- 출발지: **Kali `192.168.16.232`, `192.168.16.233`** (승인된 공격 호스트, 세그먼트 직결).
- 선행조건: WAF On·Suricata passive(인라인 아님). 공격은 Kali에서 직접 송신, 운영 설정 변경은 관리자231 경유.
- 재생 도구: `dual_replay_worker.py`(233 서버·232 클라이언트 배리어 동기화 후 GO) → 각 호스트 `tcpreplay --intf1=eth0 --loop=1 --multiplier=1`.

## 공격 구성 (재생본)

| 항목 | 232 | 233 | 합계 |
|---|---|---|---|
| 패킷 | 94,889 | 94,889 | 189,778 |
| ICMP echo | 92,764 | 92,764 | 185,528 |
| TCP SYN → :80 | 2,125 | 2,125 | 4,250 |
| 평균 속도 | 0.33Mbps·562pps | 0.33Mbps·549pps | ~0.5Mbps·~1,138pps |
| 송신 시간 | 168s | 170s | — |

원본: `ddostrace.20070804_134936.pcap`(공개 트레이스) → src를 Kali 232/233, dst를 A 230, SYN dport 80으로 재매핑. 대역폭이 작아(≈0.5Mbps) 자원 고갈형이 아니라 **탐지 서명 시험용**이다.

## 기대 탐지·대응 (정답표)

| 단계 | 능력 | 대상 | 기대 탐지 | 기대 대응 |
|---|---|---|---|---|
| 4.1 ICMP 플러드 | 다중 호스트 ICMP echo 홍수 | A 230 | Suricata 로컬 **ICMP 플러드 threshold 룰**(by_dst rate) → Wazuh 상관 | 플러드 소스 `agent_block` |
| 4.2 SYN 플러드 | TCP SYN 홍수 → :80 | A 230:80 | A 호스트 FW의 비정상 상태 drop + Suricata 로컬 **SYN 플러드 threshold 룰** → Wazuh | FW drop(상시) + 소스 `agent_block` |
| 4.3 상관·인지 | 다중 소스 동시 플러드 | A 230 | SIEM이 FW drop + IDS 플러드를 상관해 **DDoS 사건**으로 집계, LLM 관제가 인지 | 사건 보고·차단 승인 |

## 실측 결과 — 2026-11-10 19:31~19:34 KST (실제 1회)

| 방어 계층 | 기대 | **실제 관측** | 판정 |
|---|---|---|---|
| **nftables (A)** | SYN 플러드 drop | `ct state invalid` drop **9 → 7,194 패킷** | ✅ 부분 차단(SYN/비정상 상태). ICMP echo는 기존 "health ping accept" 룰로 통과 |
| **Suricata IDS (A)** | ICMP/SYN 플러드 경보 | eve.json +1.1MB(flow 2,356 기록 정상)이나 **플러드 경보 0건**. 최근 alert는 평시 DuckDNS DNS뿐 | ❌ **미탐**(볼류메트릭/threshold 룰 부재) |
| **Wazuh SIEM (B)** | DDoS 사건 집계 | 플러드·DDoS 경보 **0건**(카나리·sudo 이벤트만) | ❌ **미탐**(IDS 미발화·FW drop 미전달) |
| **LLM 관제** | 사건 인지 | 받을 IDS/SIEM 경보 없음 | ❌ 자동 인지 불가 |
| **서비스 영향** | — | A·B·관리호스트 응답 유지, 다운 없음 | 영향 없음(대역폭 작음) |

## 탐지 공백과 보완 (후속, 승인형)

현재 SOC는 이 DDoS를 **방화벽에서만 부분 차단**하고 **IDS·SIEM은 전혀 보지 못한다** → LLM 관제의 자동 인지 불가. 보완:

1. **Suricata 로컬 플러드 threshold 룰** 추가(허용 SID 1000000–1000099): ICMP echo rate(by_dst), SYN rate(by_dst). → 재생 시 발화해야 함.
2. **nftables 무효상태 drop 로그를 Wazuh로 전달**해 FW 차단량을 SIEM에서 상관.
3. 룰 추가 후 **재재생 → Suricata 탐지 → Wazuh 상관 → LLM 인지**까지 E2E 확인.

## 주의
- 승인된 캡스톤 랩 전용. 대상은 A 230, 출발지는 Kali 232/233뿐. 외부 대상·캠퍼스 VPN 출발 금지.
- 재생본은 유한(각 ~170초)·자동 종료이며 자원 고갈을 유도하지 않는다. 룰 추가·운영 반영은 관리자231 경유 승인 절차를 따른다.
- 이 결과는 1회 관측이다. `alerts.md`의 미검증 표시와 [현황](../STATUS.md)을 함께 본다.
