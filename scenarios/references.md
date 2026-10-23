# 트래픽 생성용 공개 권위 레퍼런스

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 6개 CVE 재현·탐지 연결(작업3번)은 사용자 지시로 보류한다. 현재 실습은 HTTP3개와 Redis/Samba/sudo 터미널3개이며 DVWA는 독립 경로다. 아래 정답·룰 ID·공격 경로는 기대값/과거 계획으로 보존하며 실행 완료를 뜻하지 않는다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

각 공격 유형을 "어떻게 만드는지"는 아래 표준 문서를 따른다(이 저장소가 공격 절차를 자체 작성하지 않는 이유 = 공개된 canon을 쓰는 것이 재현성·정확성·검증가능성에서 낫다). 각 레퍼런스가 **우리 어떤 탐지에 대응되는지**를 오른쪽에 적었다. 실행자는 링크의 절차를 랩 대상(192.168.16.230 / DVWA `/dvwa/` / C:8080)에만 적용한다.

## 웹 애플리케이션 테스트 (시나리오 1)
| 레퍼런스 | 내용 | 우리 탐지 매핑 |
|---|---|---|
| [OWASP WSTG v4.2 — Testing for SQL Injection (WSTG-INPV-05)](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html) | SQLi 테스트 표준 절차·페이로드 클래스 | CRS 942100(libinjection), Wazuh 31103, 로컬 100102 |
| [OWASP WSTG — Testing for Reflected XSS (WSTG-INPV-01)](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection_Testing/) | 반사형 XSS 테스트 | CRS 941xxx, Wazuh 31105 |
| [OWASP WSTG — Information Gathering (WSTG-INFO)](https://owasp.org/www-project-web-security-testing-guide/) | 정찰·핑거프린팅 방법론 | 호스트 FW drop 100128/100129 |
| [OWASP WSTG — Testing for Weak Lockout (WSTG-ATHN-03)](https://owasp.org/www-project-web-security-testing-guide/) | 인증 무차별·잠금 정책 테스트 | 웹 로그인 무차별 → WAF/웹 로그, SSH는 5710/5712 |
| [Wazuh PoC — Detecting an SQL injection attack](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-web-attack-sql-injection.html) | Apache access.log에서 SQLi 탐지. 시도=**31103**, 성공(HTTP 200)=**31106** | 우리 C는 Apache→agent 002. 동일 룰 적용 |
| [Wazuh PoC — Detecting a Shellshock attack](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-web-attack-shellshock.html) | 웹 로그 기반 Shellshock 탐지(보너스 웹 시나리오) | Wazuh 웹 룰 |
| [Nmap 공식 문서 — 포트/서비스 스캔](https://nmap.org/book/man-port-scanning-techniques.html) | 정찰 스캔 기법(표준 플래그) | A 호스트 FW inbound drop → 100128, 버스트 100129 |
| [Nikto](https://github.com/sullo/nikto) | 웹 서버 스캐너(스캐너 UA) | CRS 913100(scanner UA), Suricata ET 스캐너 룰 |
| [sqlmap](https://github.com/sqlmapproject/sqlmap) | 자동 SQLi 도구(기본 UA `sqlmap/…`) | **Suricata ET sid 2008538**, CRS 942100, Wazuh 31103/100102 |
| [hydra (thc-hydra)](https://github.com/vanhauser-thc/thc-hydra) | 로그인 무차별. Wazuh PoC가 SSH/RDP 무차별 도구로 사용 | SSH→5710/5712/5551; DVWA 로그인→WAF/웹 로그 |

## Log4Shell (시나리오 2, CVE-2021-44228)
| 레퍼런스 | 내용 | 우리 탐지 매핑 |
|---|---|---|
| [christophetd/log4shell-vulnerable-app — 공식 README](https://github.com/christophetd/log4shell-vulnerable-app/blob/main/README.md) | 우리가 C에 띄운 바로 그 랩 앱. 재현 절차(악성 LDAP 서버 + JNDI 트리거를 헤더에 주입)와 "sandbox VM에서만" 경고를 문서화 | 네트워크(조건부, 선행조건 3), 엔드포인트 agent 002 |
| [LunaSec — Log4Shell 원 권고문](https://www.lunasec.io/docs/blog/log4j-zero-day/) | 취약점 원리·영향(README가 인용하는 원문) | 배경 |
| [NVD CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) / [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CVE 상세·KEV 등재 | Wazuh Vulnerability Detection 상관 |
| [Wazuh PoC — Vulnerability detection](https://documentation.wazuh.com/current/proof-of-concept-guide/poc-vulnerability-detection.html) | Syscollector `<interval>`로 스캔, 대시보드 Inventory/Events | agent 002 취약점(2,422건) 상관 |

> ⚠️ 시나리오 2는 **인라인 exploit 체인을 이 저장소에 두지 않는다.** 랩 앱 README의 문서화된 트리거(그 앱이 로깅하는 주입 지점)와 위 CVE/PoC 레퍼런스만 인용한다. 실제 콜백/LDAP 구성은 실행자가 README 절차를 격리 랩에서 따른다.

## 권한상승 (시나리오 3, CVE-2021-3156 Baron Samedit)
| 레퍼런스 | 내용 | 우리 탐지 매핑 |
|---|---|---|
| [Qualys 원 권고문 — Baron Samedit](https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt) | 취약 sudo 버전 범위·원리 | 선행조건 4(버전 확인) |
| [NVD CVE-2021-3156](https://nvd.nist.gov/vuln/detail/CVE-2021-3156) / CISA KEV | CVE 상세·KEV | Wazuh Vulnerability Detection |
| [Wazuh — auditd/명령 실행 모니터링](https://documentation.wazuh.com/current/user-manual/capabilities/system-calls-monitoring/index.html) | auditd 연동으로 exec/권한상승 흔적 수집 | agent 002 auditd 룰 |
| [Wazuh — Rootcheck / SCA](https://documentation.wazuh.com/current/user-manual/capabilities/policy-monitoring/index.html) | 정책·루트킷·설정 이상 | agent 002 rootcheck/SCA |

## 룰셋 근거(우리 탐지의 출처)
| 레퍼런스 | 내용 |
|---|---|
| [Emerging Threats Open 룰셋](https://rules.emergingthreats.net/open/suricata/rules/) | A Suricata가 로드한 ET Open(52,483룰). sid 2008538 = ET SCAN Sqlmap 등 |
| [OWASP CRS 규칙 문서](https://coreruleset.org/docs/) | WAF가 쓰는 CRS 4.29: 913100(스캐너), 942100(SQLi), 941xxx(XSS), 949110(임계) |
| [Wazuh Ruleset (내장 룰)](https://github.com/wazuh/wazuh/tree/main/ruleset/rules) | 31101/31103/31105/31106(웹), 5710/5712(SSH 무차별), 0475-suricata_rules.xml |

## Sources
- [Wazuh Proof of Concept guide](https://documentation.wazuh.com/current/proof-of-concept-guide/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [christophetd/log4shell-vulnerable-app](https://github.com/christophetd/log4shell-vulnerable-app)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
