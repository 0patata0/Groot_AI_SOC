# CISA KEV 데이터 — 반입 기록

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../STATUS.md) · [실행 계획](../../PLAN.md).
> 현재 B는 Wazuh4.14.8·Mattermost/PostgreSQL·Hermes·승인 브로커와 MCP6서버를 운영한다. 이번 읽기 점검에서 운영6컨테이너와 Wazuh000/001/002 Active를 확인했다. 고정 도구 목록과 실제 LLM 선택·대응 성공은 별개다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

CVE 우선순위(실제 익스플로잇된 취약점) 판단용 **CISA Known Exploited Vulnerabilities** 카탈로그. MCP CVE 툴/취약점 판단의 오프라인 기준 데이터.

## 출처 / 버전 / 라이선스
- 소스: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  - 스키마: `.../known_exploited_vulnerabilities_schema.json`
  - 라이선스: `.../licenses/kev/license.txt` = **CC0 1.0 (퍼블릭도메인)**
- 반입일: 2026-09-26, catalogVersion **2026.09.25**, **1,726건**

## 리뷰 결과 (반입 전)
- 순수 JSON 데이터(실행코드 없음), CC0 → LOW RISK
- 우리 시나리오 CVE 포함 확인: **CVE-2021-44228**(Log4Shell, ransomware=Known), **CVE-2021-3156**(Baron Samedit)
- 필드: cveID, vendorProject, product, vulnerabilityName, dateAdded, requiredAction, dueDate, knownRansomwareCampaignUse, cwes 등

## 스테이징 위치 (Groot_B)
- `~/capstone/kev/kev.json`, `~/capstone/kev/kev_license.txt`
- MCP CVE 툴/응답 로직에서 read-only 참조.

## 갱신 / 보완
- KEV는 수시 갱신 → 인터넷 되는 곳에서 재다운로드 후 scp `-O` 교체.
- 상세 CVE(설명/CVSS/영향버전)는 KEV에 없음 → 필요 시 **NVD** 타깃 레코드(우리 시나리오 CVE 위주)를 별도 오프라인 반입해 보완(직접 채우기).
