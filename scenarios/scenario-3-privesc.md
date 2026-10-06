# 시나리오 3 — 권한상승 (CVE-2021-3156 Baron Samedit, C 호스트)

목표: 침투 후 로컬 권한상승 시도가 C 엔드포인트(Wazuh agent 002)에 탐지되는지 확인한다. 이 시나리오는 **네트워크가 아니라 엔드포인트 텔레메트리**(auditd/rootcheck/SCA/취약점) 검증이다. exploit 코드는 저장소에 두지 않는다 — `references.md`의 Qualys 권고문/CVE만 인용한다.

- CVE-2021-3156 (Baron Samedit): sudo heap 오버플로우 → 로컬 root. CISA KEV.

## ⚠️ 선행조건 (README §선행조건 4) — 반드시 먼저
1. **C의 `sudo --version`은 이번 SSH 점검에서 1.8.31로 관측했다.** 버전 문자열만으로 CVE-2021-3156 취약 여부를 확정할 수 없다. 설치 패키지 빌드·패치 이력과 Wazuh 취약점 인벤토리를 확인한 뒤 실험 가능 여부를 판단한다.
2. 취약성이 확인되지 않으면: (a) 취약 sudo를 격리 랩에 별도 스테이징(오프라인 deb, 스냅샷 필수), 또는 (b) 이 시나리오를 **"탐지 룰만 준비"** 상태로 두고 취약점 탐지(3.1)만 검증.

| 단계 | 능력(레퍼런스) | 기대 탐지 | 기대 대응 |
|---|---|---|---|
| 3.1 취약점 존재 | Wazuh Vulnerability Detection | 취약 sudo 스테이징 시 대시보드 Inventory에 CVE-2021-3156 (agent 002) | 패치 권고 |
| 3.2 exploit 실행 | Qualys 권고문 PoC(격리 랩) | auditd 연동 시 비정상 sudo 호출/충돌·exec 체인 → Wazuh syscheck/auditd 룰; 셸 획득 시 `Successful sudo`/새 root 세션 | 호스트 격리, 소스 세션 추적 |
| 3.3 지속성/흔적 | 파일 변경(FIM), rootcheck | Wazuh FIM(`syscheck`), rootcheck 이상 | 대응 |

## 검증 포인트
- 3.1은 실제 설치 패키지의 CVE 상태를 확인한 뒤 검증한다. 현재 확인된 것은 `sudo --version` 문자열뿐이다.
- 3.2 탐지를 위해 **C에 auditd + Wazuh 연동**이 필요할 수 있음(현재 agent 002는 apache/journald/SCA/rootcheck 수집). auditd 규칙 추가 여부를 먼저 결정 → [references.md] Wazuh system-calls monitoring.
- 대응은 네트워크 차단이 아니라 **호스트 격리/스냅샷 복원**이 주. agent_block은 외부 유입 소스에만 유효.

## 주의
- 파괴적 단계. 반드시 스냅샷 후 실행, 종료 시 복원. 취약 sudo는 실습 후 원복(패치본으로).
