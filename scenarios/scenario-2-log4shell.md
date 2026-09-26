# 시나리오 2 — Log4Shell (CVE-2021-44228, C:8080 랩)

목표: 우리가 C에 띄운 `log4shell-vulnerable-app`(Log4j 2.14.1)을 대상으로, 취약점의 관측 흔적(네트워크·엔드포인트·취약점 탐지)이 SOC에 남는지 확인한다. **exploit 체인은 이 저장소에 두지 않는다** — 랩 앱의 [공식 README](https://github.com/christophetd/log4shell-vulnerable-app/blob/main/README.md) 절차와 `references.md`의 CVE/PoC 문서를 격리 랩에서 그대로 따른다.

- 대상 앱: `log4shell-vulnerable-app`(C:8080). 문서화된 주입 지점 = 앱이 로깅하는 요청 헤더/필드(README 참조)에 JNDI 조회 문자열.
- CVE-2021-44228 (CISA KEV). Log4j JNDI lookup을 통한 RCE 클래스.

## ⚠️ 선행조건 — 경로 결정 (README §선행조건 3)
C:8080은 **A의 WAF/Suricata를 거치지 않는다**(A는 8080 미publish). 세 가지 중 택1:
- **(A) 인라인 검증**: A에 8080 DNAT(+가능하면 WAF 경유) 경로를 추가 → Kali가 `192.168.16.230:<port>`로 치면 Suricata/WAF가 관측. (capstone-nat.sh PORTFORWARDS에 추가하거나 WAF 백엔드 확장)
- **(B) ens192 제거 후**: C가 A 경유로만 도달 → 자연히 인라인.
- **(C) 미결정 시(현 상태)**: Kali가 `192.168.16.234:8080` 직접 → **네트워크 탐지는 없음**, 엔드포인트(agent 002)와 취약점 탐지만 검증.

| 단계 | 능력(레퍼런스) | 기대 탐지 | 기대 대응 |
|---|---|---|---|
| 2.1 취약점 존재 | Wazuh Vulnerability Detection PoC | 대시보드 Vulnerability → Inventory에 agent 002의 Log4j/CVE-2021-44228 (Syscollector `<interval>` 주기) | 패치/격리 권고 |
| 2.2 JNDI 주입 시도 (경로 A/B일 때) | 랩 앱 README 트리거 | Suricata ET JNDI/LDAP 룰(`ET EXPLOIT Apache log4j RCE` 계열), WAF CRS(있으면), Wazuh 네트워크 상관 | `agent_block add <KALI_IP>` |
| 2.3 콜백/2차 요청 | README의 LDAP/HTTP 콜백 | A egress는 차단망(대부분 실패) — Suricata가 outbound JNDI/LDAP 흔적, Wazuh | egress 차단이 이미 완화. 소스 차단 |
| 2.4 엔드포인트 흔적 | Wazuh auditd/프로세스 | agent 002에서 java의 비정상 자식 프로세스/네트워크(auditd 연동 시) | 대응·격리 |

## 검증 포인트
- 2.1은 경로 결정과 무관하게 **지금 검증 가능**: 대시보드에서 agent 002의 Log4j 관련 CVE가 Inventory에 있는지.
- 2.2~2.3은 경로 A/B 확정 후. Suricata eve.json에서 `event_type:alert`의 signature에 log4j/JNDI 포함 여부, `data.srcip:<KALI_IP>`.
- 우리 망은 outbound 80/443 차단 → 실제 2차 페이로드 회수는 대부분 실패(의도된 방어). "시도 탐지"에 초점.

## 주의
- 랩 앱은 의도적 취약. 반드시 스냅샷 후 실행, 종료 시 컨테이너 재기동/스냅샷 복원.
- README가 인용하는 [LunaSec 권고문](https://www.lunasec.io/docs/blog/log4j-zero-day/) 배경 숙지.
