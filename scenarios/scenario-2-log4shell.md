# 시나리오 2 — Log4Shell (CVE-2021-44228, C:8080 랩)

목표: 우리가 C에 띄운 `log4shell-vulnerable-app`(Log4j 2.14.1)을 대상으로, 취약점의 관측 흔적(네트워크·엔드포인트·취약점 탐지)이 SOC에 남는지 확인한다. **exploit 체인은 이 저장소에 두지 않는다** — 랩 앱의 [공식 README](https://github.com/christophetd/log4shell-vulnerable-app/blob/main/README.md) 절차와 `references.md`의 CVE/PoC 문서를 격리 랩에서 그대로 따른다.

- 대상 앱: `log4shell-vulnerable-app`(C:8080). 문서화된 주입 지점 = 앱이 로깅하는 요청 헤더/필드(README 참조)에 JNDI 조회 문자열.
- CVE-2021-44228 (CISA KEV). Log4j JNDI lookup을 통한 RCE 클래스.

## 선행조건 — 경로 (2026-09-27 확정: 노출은 C 내부로 좁힘, 시나리오 때 A 경유)
**평상시 랩은 C 내부 전용**(컨테이너가 `10.10.10.20:8080` 에만 바인딩 — 캠퍼스/VPN 직접 도달 불가, 실측). 즉 구 (C)안 `192.168.16.234:8080` 직접 경로는 **이제 닫혀 있다**. 시나리오 때만 A 경유 경로를 연다:
- **(A) 인라인 검증 — 채택/준비됨**: A 토글 스크립트로 8080 DNAT 경로를 ON → Kali(캠퍼스)가 `http://192.168.16.230:8080/` 로 치면 **Suricata(ens192 af-packet)가 그대로 검사**. 종료 후 OFF 로 회수.
  ```bash
  # A(게이트웨이)에서 — 시나리오 시작:
  sudo /usr/local/sbin/scenario_log4shell_route.sh on      # A:8080 -> C 10.10.10.20:8080 (+회신 SNAT, forward 허용)
  sudo /usr/local/sbin/scenario_log4shell_route.sh status  # 활성 규칙 확인
  # ... Kali(캠퍼스 직결)에서 http://192.168.16.230:8080/ 로 시나리오 수행 ...
  # 시나리오 종료:
  sudo /usr/local/sbin/scenario_log4shell_route.sh off     # 경로 회수 → 랩은 다시 C 내부 전용
  ```
  - 런타임 전용 nft 테이블(`capstone_scenario`) — **재부팅하면 자동 OFF**(의도). capstone_fw/capstone_fwd 는 건드리지 않음.
  - VPN 은 A 로 8080 이 안 열림(22/80/443 만) → **캠퍼스/Kali 세그먼트에서만** 유효. 공격성 트래픽 VPN 경유 금지(캠퍼스 FW 차단).
  - 소스 스크립트: `infra/groot-a/scenario_log4shell_route.sh`.
  - (선택) WAF(ModSecurity/CRS) 인라인도 필요하면 WAF 백엔드를 log4shell 로 확장 — 현재는 Suricata IDS 경로만. CRS 4.x 에 log4j 룰 포함.
- **(B) ens192 제거 후**: C 기본라우트가 A 로 바뀌면 A 경유가 상시 인라인 → 토글 불필요(다른 작업자 세팅 대기 중).

| 단계 | 능력(레퍼런스) | 기대 탐지 | 기대 대응 |
|---|---|---|---|
| 2.1 취약점 존재 | Wazuh Vulnerability Detection PoC | 대시보드 Vulnerability → Inventory에 agent 002의 Log4j/CVE-2021-44228 (Syscollector `<interval>` 주기) | 패치/격리 권고 |
| 2.2 JNDI 주입 시도 (경로 A ON, Kali→192.168.16.230:8080) | 랩 앱 README 트리거 | Suricata ET JNDI/LDAP 룰(`ET EXPLOIT Apache log4j RCE` 계열), WAF CRS(백엔드 확장 시), Wazuh 네트워크 상관 | `agent_block add <KALI_IP>` |
| 2.3 콜백/2차 요청 | README의 LDAP/HTTP 콜백 | A egress는 차단망(대부분 실패) — Suricata가 outbound JNDI/LDAP 흔적, Wazuh | egress 차단이 이미 완화. 소스 차단 |
| 2.4 엔드포인트 흔적 | Wazuh auditd/프로세스 | agent 002에서 java의 비정상 자식 프로세스/네트워크(auditd 연동 시) | 대응·격리 |

## 검증 포인트
- 2.1은 경로 결정과 무관하게 **지금 검증 가능**: 대시보드에서 agent 002의 Log4j 관련 CVE가 Inventory에 있는지.
- 2.2~2.3은 경로 A/B 확정 후. Suricata eve.json에서 `event_type:alert`의 signature에 log4j/JNDI 포함 여부, `data.srcip:<KALI_IP>`.
- 우리 망은 outbound 80/443 차단 → 실제 2차 페이로드 회수는 대부분 실패(의도된 방어). "시도 탐지"에 초점.

## 주의
- 랩 앱은 의도적 취약. 반드시 스냅샷 후 실행, 종료 시 컨테이너 재기동/스냅샷 복원.
- README가 인용하는 [LunaSec 권고문](https://www.lunasec.io/docs/blog/log4j-zero-day/) 배경 숙지.
