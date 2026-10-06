# 공격 시나리오 · 탐지 검증 패키지 (Groot 캡스톤 SOC)

이 폴더는 **블루팀 탐지 검증(detection validation)** 문서다. 각 시나리오는 "공격 단계 → 우리 인프라에서 떠야 하는 탐지(Suricata sid / ModSecurity·CRS 룰 / Wazuh 룰 id) → 대응(agent_block)"을 짝지어, 팀이 Kali에서 실행하고 Wazuh에서 실제로 보이는지 체크리스트로 확인하도록 만든다.

> **현황(2026-10-06 라이브 점검):** A의 FW v2는 `FORWARD=DROP`으로 적용·확정됐다. WAF GROOT 룰은 `DetectionOnly`, Suricata ET+로컬 룰과 Phase-A는 passive로 로드됐다. B/C의 외부 `ens192`는 제거됐다. B의 Wazuh 인덱스에는 Suricata 로컬 SID `1000010`→`100110` 및 ModSecurity CRS `920350`→`100101` 경보가 관측됐지만, 이번 점검에서 시나리오 공격 트래픽은 새로 실행하지 않았다. GROOT WAF 커스텀 ID `10100`대 및 다른 신규 룰의 발화는 미검증이다. A의 Log4Shell 경로 토글은 OFF이며 설치된 스크립트에는 저장소의 `OBS_SEG` 코드가 없다. [작업 기록](../대화기록/2026-10-06.md)

**공격 트래픽을 어떻게 만드는지(how-to)는 이 문서가 직접 쓰지 않는다.** 대신 공개된 권위 있는 표준 문서(OWASP WSTG, Wazuh 공식 PoC 가이드, 취약 앱의 공식 README, Emerging Threats/CRS 룰)를 `references.md`에 링크로 정리하고, 팀은 그 절차를 따른다. 이 문서는 그 결과로 **우리 SOC가 무엇을 봐야 하는지**를 정의한다.

## 승인·범위 (Rules of Engagement)
- **승인된 캡스톤 실습 환경 전용.** 대상은 우리가 구축한 격리 랩 호스트뿐: Groot_A(192.168.16.230), Groot_C DVWA(A 경유 `http://192.168.16.230/` → `/dvwa/`), Groot_C Log4Shell 랩(A의 시나리오 경로 토글을 켠 동안만 A:8080→C:8080). B/C의 과거 외부 IP로 직접 접근하는 경로는 제거됐다. 그 외 어떤 시스템도 대상 아님.
- **Kali는 설계상 캠퍼스 VM 외부 세그먼트 `192.168.16.0/25`에 직접 연결한다.** A의 `ens192`는 `192.168.16.230/25`(직결 `192.168.16.128/25`)지만 10443 DNAT 허용 소스와 저장소 `OBS_SEG`는 `192.168.16.0/25`로 설정돼 있다. Kali의 실제 주소·라우팅은 아직 미확인이다. 공격 전에 출발지와 A까지의 왕복 경로를 확인한다. 캠퍼스 VPN(GlobalProtect) 경유 공격 트래픽은 캠퍼스 방화벽이 연결 쌍을 차단해 관리 접속까지 끊긴다(2026-09-26 실측). → [[campus-vpn-no-attack-traffic]]
- **재현성**: 시나리오 전후로 ESXi 스냅샷 + DVWA "Create/Reset Database". 파괴적 단계(권한상승 등)는 스냅샷 복원으로 원복.
- **관측 시간대**: 실행·탐지·대응 시각을 날짜와 `+09:00` 오프셋이 포함된 KST로 기록한다. Wazuh `timestamp`는 절대 시각이므로 대시보드 표시 시간대를 확인하고 같은 순간에 해당하는 범위로 필터한다. A/B/C 호스트는 2026-10-06부터 `Asia/Seoul`이며 NTP 동기화됨(A←캠퍼스 NTP, B/C←A). Mattermost 컨테이너는 KST로 재배포했고, 다른 컨테이너 내부 표시는 UTC일 수 있다.

## 실행 전 반드시 해결할 선행조건 (팀 확인 필요)
1. **DVWA 보안 레벨**: 현재 `impossible`(config `DEFAULT_SECURITY_LEVEL`). 웹 공격 시나리오(1) 전에 **`low`**로 낮춰야 SQLi/XSS가 성립. C 담당자와 협의.
2. **WAF·IPS 모드**: 현재 WAF `DetectionOnly`, Suricata passive이므로 룰 매치만으로 첫 요청·패킷을 막지 않는다. `agent_block`에 따른 A 호스트 FW 차단은 별도 대응이다. WAF `On`·IPS 인라인/drop 효과는 추후 전환 후 별도 실험으로 검증한다.
3. **Log4Shell 경로(중요)**: C의 `ens192`는 제거됐고 랩 앱은 내부 IP `10.200.10.20:8080`에서 가동 중이다. A의 경로 토글은 현재 OFF이며 설치본에는 저장소의 `OBS_SEG` 관찰 룰이 없다. 스크립트를 동기화하고 A:8080 토글 경로를 검증한 뒤 Kali 요청·Suricata 탐지를 시험한다. 이 경로는 WAF를 통과하지 않는다. [시나리오 2](scenario-2-log4shell.md)
4. **권한상승(시나리오 3)**: C에서 `sudo --version` 1.8.31을 관측했다. 이 문자열만으로 CVE-2021-3156 취약 여부를 확정하지 않는다. 패키지 빌드·패치 상태를 확인한 뒤 실험 범위를 정한다.

## 시나리오 색인
| # | 파일 | 주제 | 주 탐지 계층 |
|---|---|---|---|
| 1 | [scenario-1-recon-web.md](scenario-1-recon-web.md) | 외부 정찰 + 웹 공격(정찰·스캐너·SQLi·XSS·인증 무차별) | 호스트 FW / Suricata / WAF / Wazuh 웹 |
| 2 | [scenario-2-log4shell.md](scenario-2-log4shell.md) | CVE-2021-44228 Log4Shell (A:8080 토글→C:8080 랩) | 네트워크(토글 시) / 엔드포인트 / 컨테이너 JAR 확인·조건부 취약점 인벤토리 |
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
- B의 `local_decoder.xml`·`local_rules.xml`에는 신규 FW `SPOOF`/`FW_SSH_RATE`/`FW_DROP_FWD`/`FW_SHADOW_OUT`, WAF `GROOT_A/*`, IPS 로컬 SID 1000xxx를 위한 전용 항목이 없다. **SID `1000010`은 기존 Suricata 룰 `100110`으로 분류됨을 확인**했고, 나머지 신규 ID는 `alerts.json`·대시보드와 대조해 빠진 분류만 추가한다. [alerts.md](alerts.md)의 Verified는 해당 시나리오에서 공격·탐지·대응을 실제 확인한 뒤 표시한다.

*이 문서군은 팀이 소유한 격리 실습 인프라의 방어 검증용이다.*
