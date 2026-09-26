# CISA KEV 데이터 — 반입 기록

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
