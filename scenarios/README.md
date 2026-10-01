# 공격 시나리오 · 탐지 검증 패키지 (Groot 캡스톤 SOC)

이 폴더는 **블루팀 탐지 검증(detection validation)** 문서다. 각 시나리오는 "공격 단계 → 우리 인프라에서 떠야 하는 탐지(Suricata sid / ModSecurity·CRS 룰 / Wazuh 룰 id) → 대응(agent_block)"을 짝지어, 팀이 Kali에서 실행하고 Wazuh에서 실제로 보이는지 체크리스트로 확인하도록 만든다.

**공격 트래픽을 어떻게 만드는지(how-to)는 이 문서가 직접 쓰지 않는다.** 대신 공개된 권위 있는 표준 문서(OWASP WSTG, Wazuh 공식 PoC 가이드, 취약 앱의 공식 README, Emerging Threats/CRS 룰)를 `references.md`에 링크로 정리하고, 팀은 그 절차를 따른다. 이 문서는 그 결과로 **우리 SOC가 무엇을 봐야 하는지**를 정의한다.

## 승인·범위 (Rules of Engagement)
- **승인된 캡스톤 실습 환경 전용.** 대상은 우리가 구축한 격리 랩 호스트뿐: Groot_A(192.168.16.230), Groot_C DVWA(A 경유 `http://192.168.16.230/` → `/dvwa/`), Groot_C Log4Shell 랩(`log4shell-vulnerable-app`, C:8080). 그 외 어떤 시스템도 대상 아님.
- **Kali는 캠퍼스 VM 세그먼트(192.168.16.0/24)에 직접 연결.** 캠퍼스 VPN(GlobalProtect) 경유로 공격 트래픽을 보내면 캠퍼스 방화벽이 (VPN클라↔대상) 쌍을 차단해 관리 접속까지 끊긴다(2026-09-26 실측). → [[campus-vpn-no-attack-traffic]]
- **재현성**: 시나리오 전후로 ESXi 스냅샷 + DVWA "Create/Reset Database". 파괴적 단계(권한상승 등)는 스냅샷 복원으로 원복.
- **관측 시간대**: 실행 시각(UTC)을 기록해 Wazuh 필터 `timestamp` 범위와 맞춘다. A/B/C 시계는 동기화됨(A←캠퍼스 NTP, B/C←A).

## 실행 전 반드시 해결할 선행조건 (팀 확인 필요)
1. **DVWA 보안 레벨**: 현재 `impossible`(config `DEFAULT_SECURITY_LEVEL`). 웹 공격 시나리오(1) 전에 **`low`**로 낮춰야 SQLi/XSS가 성립. C 담당자와 협의.
2. **WAF 모드**: 현재 `DetectionOnly`(경보만, 차단 안 함). 시나리오 1의 "차단" 기대치는 **① A 호스트 방화벽 `agent_block`(대응)** 또는 **② WAF를 `MODSEC_RULE_ENGINE=On`으로 전환**했을 때 달라진다. 각 단계에 "관찰 단계 기대치 / 차단 전환 시 기대치"를 구분해 둠.
3. **Log4Shell 경로(중요)**: C:8080 랩 앱은 **A의 WAF/Suricata를 거치지 않는다**(A는 80/443/8443만 published, 8080은 아님). Kali가 `192.168.16.232:8080`로 직접 치면 A의 어떤 보안장비도 보지 못한다. 시나리오 2가 인라인 탐지되려면 (a) A에 8080 DNAT+WAF 경로를 추가하거나, (b) ens192 제거 후 C가 A 경유로만 도달되게 한 뒤 실행해야 한다. 미결정 시 시나리오 2는 **엔드포인트(Wazuh agent 002) 탐지 + 취약점 탐지 상관**만 검증. → 아키텍처 결정 항목.
4. **권한상승(시나리오 3)**: Baron Samedit(CVE-2021-3156)는 취약 sudo 버전이 있어야 성립. **먼저 C의 `sudo --version`을 확인**하고, 24.04 기본이 패치본이면 취약 버전을 별도 스테이징하거나 이 시나리오를 "탐지 룰만 준비" 상태로 둔다.

## 시나리오 색인
| # | 파일 | 주제 | 주 탐지 계층 |
|---|---|---|---|
| 1 | [scenario-1-recon-web.md](scenario-1-recon-web.md) | 외부 정찰 + 웹 공격(정찰·스캐너·SQLi·XSS·인증 무차별) | 호스트 FW / Suricata / WAF / Wazuh 웹 |
| 2 | [scenario-2-log4shell.md](scenario-2-log4shell.md) | CVE-2021-44228 Log4Shell (C:8080 랩) | 네트워크(조건부) / 엔드포인트 / 취약점 탐지 |
| 3 | [scenario-3-privesc.md](scenario-3-privesc.md) | 침투 후 권한상승 (CVE-2021-3156 Baron Samedit) | 엔드포인트(auditd/rootcheck/SCA) |
| — | [alerts.md](alerts.md) | 전체 탐지·대응 매트릭스(실행 중 체크) | — |
| — | [references.md](references.md) | 트래픽 생성용 공개 권위 레퍼런스(OWASP/Wazuh/앱 README/룰) | — |

## 평가 정답표
- [ground-truth.md](ground-truth.md) / [ground-truth.json](ground-truth.json): 시나리오 단계 ↔ ATT&CK 기법 + 기대 탐지(rule id) + 정답 판단(verdict/attack_chain/대응). 3단계 채점 기준.

## Wazuh에서 검증하는 법 (공통)
- 대시보드 → Threat Hunting / Discover, 인덱스 `wazuh-alerts-*`.
- 유용한 필터: `rule.groups: capstone`(우리 로컬 룰), `agent.name: groot-web`(C), `agent.name: groot-sec`(A), `rule.id: 100121`(차단 대응), `data.srcip: <Kali IP>`.
- 취약점: 대시보드 Vulnerability Detection → Inventory/Events (agent 002).
- 우리 로컬 룰 요약: 100102 WAF 임계초과, 100103 WAF 버스트, 100111 Suricata medium, 100121 agent_block 차단, 100126/100127 차단 IP 계속 타격, 100128/100129 호스트 FW inbound drop/스캔. 내장: 31103 SQLi, 31105 XSS, 31101 4xx, 5710/5712 SSH 무차별.

*이 문서군은 팀이 소유한 격리 실습 인프라의 방어 검증용이다.*
