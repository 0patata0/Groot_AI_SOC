> 18:13 후속: 신규 읽기 전용 chat_lookup_prompt도 기존 canonical controller/worker 소스 복사를 사용한다. 새로운 패키지·이미지·포트·복사 경로0, 설치/렌더37검사 통과·실제 신규 설치0. [운영 검증](../infra/hermes/lookup-latency.md).

> 11/4 후속 하네스 동기화: 출력 스킬 `infra/hermes/skills/soc-output/SKILL.md`와 공통 `output_contract.py`, 관리용 `chat_markdown.py`를 기존 source bundle/역할 설치·SDK 복사 목록에 연결했다. 소스 기반 설치계약37·SIEM 서식40 검사를 통과했다. 새 패키지/이미지/포트는 없으며 기존 Python과 소스만 필요하다. 실제 새 서버 설치는 실행하지 않았다. 아래 최초 점검의 ‘설치 코드 수정0’은 당시 범위이며 현재 소스 복사 갱신과 구분한다. 원격 허용목록·전체 오프라인 묶음 등 기존 잔여를 해결한 것은 아니다. [운영 적용·재현·한계](../infra/hermes/harness-cleanup.md).

# 초기 설치·통합 패키지 준비 상태

2026-11-04 읽기 점검. **최신 웹 정책의 소스 연결은 확인했지만, 현재 상태를 완성된 일괄 배포 제품으로 표시하지 않는다.** 사용자가 실제 설치는 지금 하지 말고 확인만 하도록 지시했으므로 서버 접속/설치/재시작·코드 수정은 수행하지 않았다. [운영 상태](../STATUS.md) · [웹 정책](../infra/validation/web-policy/README.md).

| 항목 | 코드에서 확인한 상태 | 판정 |
|---|---|---|
| 사용자 진입점 | 루트deploy.sh가 security/siem/service, 오프라인 패키지·이미지 적재, 키 연계·진단·봇 단계를 순차 호출 | 기반 구현 |
| 최신 WAF/관리 인증 | 신규 WAF On·UI/API 포함4프록시·DetectionOnly 예외 제거·C 관리자 CIDR+HMAC 제어. remote site.env가 MANAGEMENT_ALLOWED_CIDRS를 export하고 bootstrap이 이를 기록 | 소스 연결 확인, 새 서버 운영 미시험 |
| 두 봇/공동 채널 | Ollama/runtime/chat/review 옵션 존재. 기본은3개 enable=0·read-only | 현행 두 봇 동등 권한 구성을 자동으로 선택하는 제품 프로필은 별도 필요 |
| 공동 검토 채널 | deploy.sh는siem review-chat-install/verify를 호출하지만 remote.sh 최초 허용 목록에는 없음. 뒤쪽 dispatcher 존재 여부와 무관하게 선행 gate가64로 거부 | 실제 코드 경로 차단, 미수정 |
| WAF 근거 기반 IP 대응 | configure_waf_evidence.py는 SOC source bundle과 설치 경로에 포함. 초기 실행 순서에서 실제 enrollment 호출을 찾지 못함 | 자동 준비 완료로 표시하지 않음. producer/raw/pin 전제의 명시적 설치·검증 필요 |
| 오프라인 일괄 반입 | artifacts.json 기반 deb/image SHA·버전 검사와 오프라인 설치 지원. wheel/실습 이미지·카탈로그·TLS/별도 runtime 묶음은 각 서버 /opt/capstone-prereqs에 사전 준비 | 전체 의존성을 포함해 한 번 반입하는 최종 배포 패키지는 아직 아님 |
| 설치 검증 | Bash 구문 통과. 가짜SSH 컨트롤러46개 중43통과·3실패 | 실패3개는 신규 A host-check/host-verify를 기대 목록에 누락한 fixture 불일치. 실제 VM 설치 결과가 아님 |
| 실제 초기 설치 | 신규 Ubuntu24.04 amd643대 전체 설치 | 사용자 조건으로 미실시 |

허용 목록 재현은 remote.sh의 인자 검사 부분만 로컬에서 실행했다. review2작업은64, 대조용 trial-chat-install/verify와 diag-check는0이다. root 확인·site.env·SSH·패키지·서비스 동작은 실행하지 않았다. 가짜SSH 시험의43개 통과는 원격 dispatcher 실행이나 새 서버 제품 검증의 대체가 아니다.

배포 단위의 목표는 검수한 source·역할별 오프라인 의존성·SHA/버전/출처 목록·설정 입력·설치 후 판정·실패/복구 기록을 함께 제공하고, 사용자는 실제 주소·관리자·추론 API를 설정한 뒤 deploy.sh 하나로 설치하는 것이다. 자격/개인키·운영 데이터·가중치를 소스 패키지나 Git에 섞지 않는다. 이번에는 패키지를 새로 제작하거나 운영 소스/설정·기본 옵션을 변경하지 않았다.

다음 구현 때는 먼저 review 허용 목록과 회귀 기대값·WAF 증거 초기 준비를 정리한 뒤, 전체 오프라인 묶음과 동일한 설치/검증 프로필을 연결한다. 새3VM 실제 설치는 사용자가 가능하다고 할 때까지 실행하지 않는다. 웹 실제 공격 E2E·C 승인형 MCP·LLM 전 관제 업무의 기존 잔여 과제도 계속 유지한다.

점검 결과3개 문서는 `32d6222cace694647ec7967df09d7a15aa7040b2`로 게시하고 2026-11-04T12:07:29.303399+09:00 원격main 일치를 확인했다. 이 게시 확인 문구는 후속 문서 커밋으로 보존한다. 코드 문제는 미수정 상태이며 실제 설치는 실행하지 않았다.
