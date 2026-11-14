# LLM 운영설정 공통화 — 단일 소스 지도와 공통 원칙 (작업 #6)

이 문서는 SOC 봇의 LLM 운영설정(SOC 스킬·공통 스크립트·시스템 프롬프트)이 **하나의 리포 소스에서 공통화**되어 있음을 고정 기록하고, 장비·surface별 **정당한 차이**와 **공통 운영 원칙**, 그리고 공통성을 유지·강제하는 경로를 정리한다. 변경 원칙: **공통 요소를 먼저 바꾸고, surface별 차이는 그 위에 얹는다.** 특정 질문·특정 surface만 통과하는 예외를 쌓지 않는다.

> 현행 기준은 [STATUS.md](../../STATUS.md)를 따른다. 아래 소스 지도는 리포에서 확인한 배포 소싱 기준이며, 라이브 실제 바이트 일치는 Harness² 교차본 점검과 별개 증거다.

## 1. 공통 단일 소스 (`infra/hermes/`)

리포의 **단일 소스는 `infra/hermes/`** 하나다. surface는 배포 시 이 소스를 가져가며, **파일명·경로만 surface마다 다르다**(내용 분기 없음).

| 공통 소스(리포) | 종류 | native (A plugin) | sdk (Ollama-trial) | management |
|---|---|---|---|---|
| `infra/hermes/skills/soc-output/SKILL.md` | 스킬(출력계약) | `.../groot-query-completion/SKILL.md` | `/opt/capstone-ollama-trial/SKILL.md` | `/opt/capstone-management/SKILL.md` |
| `infra/hermes/skills/soc-{query,investigate,change,recover}/SKILL.md` | 스킬(워크플로) | `.../groot-query-completion/skill-soc-*.md` | `/opt/capstone-ollama-trial/skill-soc-*.md` | `/opt/capstone-management/skill-soc-*.md` |
| `infra/hermes/SOUL.groot.md` | 시스템 프롬프트 | `/opt/hermes-data/SOUL.md` | `/opt/capstone-ollama-trial/soc_policy.md` | `/opt/hermes-data/management/SOUL.md` |
| `infra/hermes/{chat_markdown,output_contract,workflow_contract}.py` | 공통 스크립트 | 동일 이름 | 동일 이름 | 동일 이름 |
| `infra/hermes/{chat_contract,read_contract}.py` 등 | surface 공유 스크립트 | 사용 | `ollama_trial.py`가 `hermes/`에서 소싱 | 해당 없음 |

- **검증(리포)**: sdk는 `deployment/ollama_trial.py`가 `hermes/skills/*/SKILL.md`·`hermes/SOUL.groot.md`·공통 스크립트를 `source.parent/'hermes/...'`에서 가져온다. management는 `deployment/soc_management.py`가 `infra/hermes/skills/soc-*/SKILL.md`·`SOUL.groot.md`·공통 스크립트를 번들에 넣는다. 둘 다 **자기 surface용 별도 스킬/프롬프트 소스를 두지 않는다.**
- **미완전 추적**: native(A의 `groot-query-completion` Hermes 플러그인)의 스킬·SOUL 빌드 경로는 리포에서 전체를 추적하지 못했다(플러그인 번들/이미지 경유로 추정). Harness²는 native를 포함한 3 surface를 같은 논리 스킬의 복사본으로 교차 점검한다.

## 2. 공통 운영 원칙 (모든 SOC 스킬이 공유)

아래는 5개 스킬이 공통으로 따르는 불변 원칙이다. 스킬마다 문구가 다를 수 있으나 **원칙은 하나**이며, 새 스킬·개선도 이를 먼저 적용한다.

1. **권한 미부여**: 스킬 문구는 도구 권한·승인·보호 정책을 바꾸지 않는다. 담당 역할·실행 권한은 **SOUL과 현재 도구 카탈로그**를 따른다.
2. **공통 출력 재사용**: 조회·사건·승인안·교차검토 결과는 `soc-output`(`SOC_OUTPUT_CONTRACT_V1`)의 표·근거 형식을 재사용한다. 비슷한 출력을 위해 스킬을 복제하지 않는다.
3. **단계 구분**: 제출≠승인≠소비≠적용≠엔진 반영≠실제 효과. 경보 매칭/HTTP403/차단 만료≠침해 성공·위험 해소·종결. 프로세스 active·재시작 성공≠기능 정상·무손실.
4. **근거·미확인 보존**: 실패·0건·부분·미지원을 정상·권한거부로 바꾸지 않는다. 미확인은 미확인으로 둔다. 가상의 로그/행을 만들지 않는다.
5. **상태 비승계**: 이전 봇 수치·정상 주장·승인·과거 카드를 새 관측·현재 승인으로 재사용하지 않는다. 후속 질문은 같은 사용자·확인된 대화 범위의 대상·조건만 이어받고 명시된 새 대상이 있으면 전환한다.
6. **표기 공통**: 설명은 한국어, 시각은 확인된 KST(+09:00), 용량은 공통 렌더러 규칙. 이미 제공된 KST·남은시간을 재변환/암산하지 않는다.
7. **내부 제어 줄**: `INCIDENT_DISPOSITION`·`MANAGEMENT_STATUS` 등 실행기 제어 줄은 지정 구문·별도 줄로만 쓰고 일반 답변 본문/표에 노출하지 않는다. 이 표식은 승인·실행 권한이 아니다.

스킬별 고유 책임(= surface가 아니라 **역할**별 차이): `soc-query`(조회·후속·페이지), `soc-investigate`(원인·상관·영향·종결 판단, 교차 검토 단계 전용 `## 교차 검토 대조` 절 포함), `soc-change`(변경안·승인·적용·원복), `soc-recover`(장애 진단·복구), `soc-output`(공통 출력 계약).

## 3. 공통성 유지·강제 경로

- **탐지**: Harness² `cross_copy` 점검이 3 surface의 같은 스킬 복사본 해시를 비교해 `drift`를 보고한다([infra/validation/harness2](../validation/harness2/README.md)). 공통 스크립트·SOUL도 각 component 경로 해시로 점검한다.
- **조치(거버넌스)**: 라이브 핫에디트로 생긴 드리프트는 작업 #5 승인 카드로 처리한다 — 읽기 `get_harness_check_status`, 점검 요청 `request_harness_check`, **드리프트 재동기화** `request_harness_skill_resync`(정본 surface 바이트로 1회 덮어쓰기, 해시결속), 비결정 항목은 `acknowledge_harness_finding`([승인형 운영 작업](../mcp/approved-operations.md)).
- **회귀(리포)**: [`test_common_operational_settings.py`](test_common_operational_settings.py)가 단일 소스 배선과 공통 불변식(스킬 frontmatter·공통 출력 재사용·버전 마커·배포 소싱)을 점검한다.

**실제 노출 경계 확인:** 관리자231 경유로 Hermes 컨테이너의 고정 `rule-b`/`rule-write-b` 연결에서 위 거버넌스4개 `tools/list`와 스키마 SHA를 확인했고, `get_harness_check_status` 읽기1회는 정기 구조 점검 `passed`를 반환했다. 반면 SDK의 `infra/ollama-trial/policy.py`는 서버 목록에서4개를 인식하되 `READ_TOOLS`/`PROTECTED_TOOLS`에는 넣지 않아 현재45개 목록에 노출하지 않는다. 설치된 서버 도구와 두 봇의 실행 허용 목록은 같지 않다. 이 진단은 자연어 선택·카드 클릭·1회 실행·재동기화 검증을 대신하지 않는다. SDK 통합은 정확한 권한 후보 검토·승인 후 별도로 진행하며 이번에는 정책을 바꾸지 않았다. [노출·실제 읽기 근거](../validation/peer-semantics/validation-r3.json).

## 4. 범위·한계

- 스킬·프롬프트 **내용 변경은 운영 변경**이다. Harness² 구조 검증과 거버넌스 배포·실제 채팅 검증을 거친다. 이 문서·테스트는 **소스 공통화의 명시·강제**이며 라이브 바이트 일치나 런타임 로드를 증명하지 않는다.
- 리포 소스 공통화는 사실상 완료 상태다. 남은 공백은 native 빌드 경로의 완전 추적과, 라이브 드리프트의 실제 재동기화 E2E 검증(작업 #5 배포 전제).
