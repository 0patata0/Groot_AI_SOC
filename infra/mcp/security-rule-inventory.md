# 전체 규칙·상관 조건 조회와 도구 비교

2026-10-31 KST 기준. 구현·운영 검증·Git 상태는 [STATUS](../../STATUS.md)를 기준으로 한다.

`get_security_rules`는 기본/내장 규칙과 프로젝트 규칙을 함께 조회한다. 기존 `get_rule_change_target`은 승인할 커스텀 파일의 전문·기준 SHA 조회로 유지한다. 읽기 도구 확장이 기본 규칙 편집 권한, 임의 경로·명령 실행 권한을 추가하지 않는다.

## 공식 도구와 직접 파서 비교

| 대상·방법 | 실제 확인한 범위 | 판단 |
| --- | --- | --- |
| Wazuh 공식 `/rules` API | 기본4,512+커스텀59=4,571 정의, 설정상 enabled4,569/disabled2. ID5712의 frequency8/timeframe120/if_matched_sid5710/same_source_ip 반환 | 직접 XML 문법을 재구현하는 대신 공식 API를 사용한다. 실제 경보 발생 여부는 별도 사건 조회로 확인한다 |
| 설치된 Wazuh MCP `get_wazuh_rules_summary` | 실제 기본 반환300개. ID/level/description/groups/file/status 등의 문자열 요약. ID5712의 상관 조건은 출력에서 빠짐. offset 인자 없음 | 기존 요약 기능은 있지만 전체/상관 조건 조회의 완료 근거로 쓰지 않는다 |
| Suricata `suricatasc` 8.0.6 | ruleset-stats: loaded52,497/failed0/skipped0. ruleset-failed-rules 비어 있음. reload-time 조회 성공 | 엔진 통계는 공식 소켓 기능을 사용한다. 현재 command-list는 성공한 전체 SID 정의를 열거하지 않음 |
| 설치된 `suricata-update` 1.3.8 파서 | 합본71,988행 정의 중 주석 해제52,497, 고유52,495. 현재 자료에서 파싱 경고0. 시험 문자열 `msg:"a; b"`는 msg 필드를 잘못 분리 | 공식 도구도 문법 검증기나 무누락 보장이 아니다. 상세 원문 보존·부분/실패 검사 없이 교체하지 않는다 |
| 직접 IDS 파서 | 주석 해제 ET52,483+local14=52,497 정의. ET 재정의2개를 합치지 않고 별도 표시. 실제 엔진 통계와 원문을 함께 제공 | 현재 상세 조회에 유지. 파싱 실패는 빈 목록으로 바꾸지 않고 실패 처리. 주석 처리된 비활성 정의19,491개는 현재 선택 정의 수에서 제외 |
| WAF 직접 파서 | 실제 nginx entrypoint/Include 경로, 기본640+프로젝트15=655 ID 정의, chain 하위 조건과 제외·수정 지시 보존 | 고정 읽기 경로에서 유지. 요청별 조건·동적 제외를 실제 활성 개수로 환산하지 않음 |
| OWASP CRS `secrules_parsing` | 공개 프로젝트 문서 확인. Python/textX 기반이며 README가 미완성 parser model이라고 명시 | 운영 설치·현재 WAF 파일 벤치마크 미실시. 바로 대체하지 않음 |

**시간은 같은 작업끼리만 비교한다.** 서버 내부 직접 측정에서 Wazuh 전체 API GET 3회는1.082/1.043/1.039초(auth0.205초 별도), 기존 MCP 요약300개는1.151초였다. 범위가 달라 속도 우열 점수로 환산하지 않는다. 새 Wazuh 수집기는 변경 중 읽기 방지를 위해 전체 API를 두 번 대조하며 약2.50초였다. WAF 후보 수집0.40초, IDS 후보 수집+엔진 통계7.23초, 공식 Suricata 통계 단독0.086초, 공식 파서 합본3.82초는 서로 다른 작업이다. 모델 처리·SSH 왕복·Mattermost 전송 시간은 포함하지 않는다. 반복 부하·P95 벤치마크가 아니다.

도구와 Python은 양자택일이 아니다. MCP는 LLM이 호출하는 인터페이스이고, 공식 Wazuh API도 내부적으로 Wazuh의 Python 규칙 해석 코드를 사용한다. 선택 기준은 언어보다 원자료 해석의 정확성·누락 탐지·실제 런타임 확인 범위·권한 경계다.

## 호출과 범위

| 요청 | MCP 인자 예 |
| --- | --- |
| `WAF 룰` | `{"target":"a:waf"}` |
| `IDS 기본 룰` | `{"target":"a:suricata","origin":"builtin"}` |
| `Wazuh ID 5712 조건 보여줘` | `{"target":"b:wazuh","view":"details","rule_id":"5712"}` |
| `Wazuh 상관분석 룰 조건 조회` | `{"target":"b:wazuh","view":"details","correlation_only":true}` |
| 전체 상세 다음 페이지 | `view=details`, 최대limit100, 이전 `next_offset`와 같은 `snapshot_id` |

기본 summary의 counts는 수집한 전체 정의의 집계이며 `rules`는 최대20개 표본이다. details도 기본20개이며 전체 상세 목록은 마지막 페이지까지 필요하다. `source_file_count`는 전체 수집 파일 수, `files`는 반환한 규칙의 출처 파일이다. 현재 파일/컨테이너 세대가 달라지면 페이지를 섞지 않고 다시 조회한다. 모델 도구 예산 안에 모든 페이지를 못 가져오면 전체 완료로 보고하지 않는다.

Wazuh `details`·원 API 정의·의존 ID/그룹 참조 존재를 반환한다. 시간/횟수·이전 이벤트 조건221개와 단순 if_sid/if_group/if_level 의존4,031개를 구분한다. 합계4,252를 모두 시간 기반 상관 규칙으로 부르지 않는다. API enabled는 설정상 선택 여부이며 엔진 메모리의 개별 룰이나 탐지 성공 증명은 아니다. IDS도 현재 디스크 합본과 엔진 전역 통계를 구분한다. 표기 시각은 KST이며 원본 승인 해시는 별도 변경 도구에만 사용한다.

## 설치·권한·복구

루트 `deploy.sh`의 기존 SOC 설치 경로가 `security_rule_inventory.py`를 `/opt/rule-change/`에 설치한다. 새 패키지·포트·컨테이너가 없다. 오프라인 반입은 기존 소스 번들에 해당 모듈을 포함하는 것으로 충분하다. 초기 설치 프로파일은 기존 `/opt/capstone/siem/capstone-mcp/credentials.json`의 capstone-ro·고정 SIEM 주소·CA 검증을 사용한다. 기존 운영 B는 `/etc/mcp/wazuh-ro.env`의 mcp-ro·기존 loopback/TLS 설정을 그대로 사용한다. 자격을 새로 복제하거나 관리 계정을 사용하지 않는다. MCP 사용자 인자로 URL·자격·파일 경로를 받을 수 없다.

운영 반영은 초기 설치기를 재실행하지 않고 원본 메타데이터/해시 대조·root 백업 후 변경 부분만 반영한다. 두 봇/자동조사 읽기 allowlist·공통 하네스·오프라인 소스도 맞춘다. 복구 시 같은 배포 manifest의 파일/소유자/권한을 복원하고 새 모듈만 제거하며, 봇 재시작 후 기존 목록·조회가 돌아오는지 확인한다. 승인형 쓰기 정책은 수정하지 않는다. 실제 복구 실행·보호 변경 E2E·새 서버 전체 설치 시험은 별도 검증이다.

## 1차 출처

- [Wazuh 4.14 공식 규칙 API 구현](https://github.com/wazuh/wazuh/blob/v4.14.0/framework/wazuh/rule.py), [공식 XML/상세 필드 해석](https://github.com/wazuh/wazuh/blob/v4.14.0/framework/wazuh/core/rule.py), [상관 규칙 문법](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html).
- [설치 MCP의 개발자 저장소](https://github.com/gbrigandi/mcp-server-wazuh). Wazuh 회사의 공식 MCP 제품으로 표시하지 않는다.
- [Suricata 8.0.6 Unix socket 공식 문서](https://docs.suricata.io/en/suricata-8.0.6/unix-socket.html), [OISF suricata-update parser 소스](https://github.com/OISF/suricata-update/blob/master/suricata/update/rule.py). 문서 검토와 운영 설치1.3.8 시험은 구분한다.
- [OWASP CRS 규칙 파서](https://github.com/coreruleset/secrules_parsing), [ModSecurity 자체 규칙 API 소스](https://github.com/owasp-modsecurity/ModSecurity/blob/v3/master/src/rules_set.cc). 라이브러리 함수가 기존 nginx에서 호출 가능한 전체 룰 MCP라는 뜻은 아니다.
