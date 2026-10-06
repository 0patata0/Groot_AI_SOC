# 시나리오 2 — Log4Shell (CVE-2021-44228, C:8080 랩)

목표: C의 `log4shell-vulnerable-app`(기존 설계상 Log4j 2.14.1, 실제 JAR 버전 미확인)을 대상으로, 취약점의 관측 흔적(네트워크·엔드포인트)을 SOC에서 확인하고 실제 컨테이너의 JAR 버전을 별도 증거로 남긴다. **exploit 체인은 이 저장소에 두지 않는다** — 랩 앱의 [공식 README](https://github.com/christophetd/log4shell-vulnerable-app/blob/main/README.md) 절차와 `references.md`의 CVE/PoC 문서를 격리 랩에서 그대로 따른다.

- 대상 앱: `log4shell-vulnerable-app`(C:8080). 문서화된 주입 지점 = 앱이 로깅하는 요청 헤더/필드(README 참조)에 JNDI 조회 문자열.
- CVE-2021-44228 (CISA KEV). Log4j JNDI lookup을 통한 RCE 클래스.

## 선행조건 — 경로 (2026-10-06 기록 기준)
**평상시 랩은 C 내부 전용**(`log4shell-lab`이 `10.200.10.20:8080`에서 가동 중임을 이번 SSH 점검에서 확인). B/C의 외부 `ens192`는 제거됐으므로, 옛 C `192.168.16.232:8080` 직접 경로는 없다. 시나리오 때만 A 경유 경로를 연다. A의 FW v2는 `FORWARD=DROP`으로 적용·확정됐고 WAF는 `DetectionOnly`, Suricata는 passive다. 이 상태에서 아래 "인라인"은 **A를 통한 관측 경로**를 뜻하며 IPS 실차단을 뜻하지 않는다. [10월 6일 기존 기록](../대화기록/2026-10-06.md)
- **A 경유 관측 경로**: A 토글 스크립트로 8080 DNAT 경로를 ON → Kali(캠퍼스)가 `http://192.168.16.230:8080/` 로 치면 Suricata(ens192)의 수동 탐지 대상이 된다. 종료 후 OFF 로 회수. 이번 SSH 점검에서 토글은 OFF(A:8080 NAT·DOCKER-USER 시나리오 룰 없음)였으며, ON 상태에서의 경로·공격 실발화는 검증하지 않았다.
  ```bash
  # A(게이트웨이)에서 — 시나리오 시작:
  sudo /usr/local/sbin/scenario_log4shell_route.sh on      # A:8080 -> C 10.200.10.20:8080 (+회신 SNAT, forward 허용)
  sudo /usr/local/sbin/scenario_log4shell_route.sh status  # 활성 규칙 확인
  # ... Kali(캠퍼스 직결)에서 http://192.168.16.230:8080/ 로 시나리오 수행 ...
  # 시나리오 종료:
  sudo /usr/local/sbin/scenario_log4shell_route.sh off     # 경로 회수 → 랩은 다시 C 내부 전용
  ```
  - 런타임 전용 nft 테이블(`capstone_scenario`) — **재부팅하면 자동 OFF**(의도). capstone_fw/capstone_fwd 는 건드리지 않음.
  - VPN 은 A 로 8080 이 안 열림(22/80/443 만) → **캠퍼스/Kali 세그먼트에서만** 유효. 공격성 트래픽 VPN 경유 금지(캠퍼스 FW 차단).
  - 소스 스크립트: `infra/groot-a/scenario_log4shell_route.sh`.
  - 저장소의 현 토글에는 C→`192.168.16.0/25`(`OBS_SEG`) 아웃바운드 관측 허용/회수 룰이 들어 있다. **A에 설치된 토글에는 이 코드가 없는 것을 이번 SSH 점검에서 확인했다.** A `ens192` 직결망은 별도 `192.168.16.128/25`이므로 Kali의 실제 IP·라우팅을 확인하고 설치본 동기화, ON/OFF 및 왕복 경로를 검증한다.
  - WAF(ModSecurity/CRS)는 이 8080 경로를 통과하지 않는다. WAF 관측을 별도로 평가하려면 경로 설계와 검증이 추가로 필요하다.

| 단계 | 능력(레퍼런스) | 기대 탐지 | 기대 대응 |
|---|---|---|---|
| 2.1 취약점 존재 | C 컨테이너의 JAR/이미지 증거 확인 | 실제 Log4j JAR 버전과 CVE 매핑을 별도 증거로 기록. Wazuh agent 002의 Vulnerability Inventory에 보이면 함께 기록하되, 컨테이너 내부 JAR이 패키지 인벤토리에 안 잡힐 수 있음 | 패치/격리 권고 |
| 2.2 JNDI 주입 시도 (경로 A ON, Kali→192.168.16.230:8080) | 랩 앱 README 트리거 | Suricata ET/로컬 JNDI 룰 발화 기대, Wazuh 네트워크 상관은 미검증. 현재 WAF 경로는 아님 | `agent_block add <KALI_IP>` (별도 대응) |
| 2.3 콜백/2차 요청 | README의 LDAP/HTTP 콜백 | C→VM 세그먼트 `OBS_SEG` 경로가 라이브에서 허용되면 Suricata outbound JNDI/LDAP 흔적 기대. 그 외 외부 egress는 FW 정책에 좌우됨 | 발화 확인 뒤 소스 차단 판단 |
| 2.4 엔드포인트 흔적 | Wazuh auditd/프로세스 | agent 002에서 java의 비정상 자식 프로세스/네트워크(auditd 연동 시) | 대응·격리 |

## 검증 포인트
- 2.1은 A 경로 토글과 무관하게 컨테이너 내부 JAR/이미지 증거로 확인한다. Wazuh agent 002의 Vulnerability Inventory에서 CVE-2021-44228이 보이는지도 확인하되, **표시되지 않아도 JAR의 부재나 안전성을 뜻하지 않는다.** 실제 JAR 버전은 이번 점검에서 확인하지 않았다.
- 2.2~2.3은 Kali 주소·왕복 라우팅, A 토글의 ON 상태·`OBS_SEG` 룰·A→C 경로를 확인한 뒤 실행한다. Suricata eve.json의 `event_type:alert`·signature/log4j/JNDI와 Wazuh `alerts.json`·`data.srcip:<KALI_IP>`를 같은 시간창에서 대조한다. 신규 룰 실발화는 아직 검증되지 않았다.
- 외부 80/443 egress 제한과 `FORWARD=DROP` 아래서 2차 연결의 성공·실패는 목적지/허용룰에 따라 달라진다. 기대 결과와 실제 패킷·경보를 따로 기록한다.

## 주의
- 랩 앱은 의도적 취약. 반드시 스냅샷 후 실행, 종료 시 컨테이너 재기동/스냅샷 복원.
- README가 인용하는 [LunaSec 권고문](https://www.lunasec.io/docs/blog/log4j-zero-day/) 배경 숙지.
