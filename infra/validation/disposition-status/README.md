# 판단·상태 모순 검사를 정정 단계로 + 코드 블록 진단 후보

2026-11-13 KST. **수정·회귀·구조 점검까지이며 운영 B에는 적용하지 않았다.** 적용은 사용자 승인 뒤 관리자231 경유로 [`apply_b.py`](apply_b.py)를 1회 실행한다. [현황](../../../STATUS.md) · [작은 원장](validation.json) · [직전 수정: 제어 줄 서식](../control-format/README.md).

## 문제와 정정 (11/13 23:48 Hermes 조사, 2차 초안 전문을 실제 검사로 재생)

23:55 보고에서는 "판단 unresolved + 상태 resolved 모순을 컨트롤러가 실행 후 거절해 대체 문구가 됐다"고 했다. **이 설명은 틀렸다.** 2차 초안 전문을 실제 검사 함수에 넣어 보니 사실은 다음과 같았다.

| 사실 | 근거 |
|---|---|
| 대체 문구를 만든 곳 | 컨트롤러가 아니라 실행기의 최종 검사(`guarded_result`)다. 상태 줄이 무효이거나 근거 검사 위반이 남으면 `factual_review_report`로 바꾼다 |
| 실제 원인 ① | 보고서 전체를 코드 블록(```` ```text … ``` ````)으로 감싸, `MANAGEMENT_STATUS` 줄 뒤에 닫는 ```` ``` ````이 남았다. 그래서 상태 줄이 무효가 됐다 |
| 실제 원인 ② | 조회하지 않은 Suricata를 근거처럼 언급했다("Suricata severity-1/2 등이 탐지되지 않았습니다", `unobserved_event_source:suricata`) |
| 모순 자체 | 판단 `unresolved` + 상태 `resolved` 모순도 실제로 있었다. 이 규칙은 컨트롤러의 **센서 사건 조사 판정**(`sensor_disposition_error`, `sensor_requirements`가 있을 때)에만 있다. 그 판정도 상태만 `needs_review`로 바꾸고 본문은 그대로 둔다. 공동 채널 조사처럼 센서 요건이 없는 경로에서는 다른 검사만 통과하면 **모순된 제어 줄이 그대로 통과**한다 |

## 수정 (규칙은 컨트롤러와 같게, 위치만 정정 단계로)

| 위치 | 변경 |
|---|---|
| 관리 실행기 `disposition_status_conflict` | 상태가 `resolved`인데 판단 줄의 assessment가 `unresolved`면 모순으로 본다. 판단 줄이 있는 보고서만 검사한다(조회형 답변에는 판단 줄이 없다). 컨트롤러 규칙과 같은 기준이다 |
| 정정 훅 | 위 모순을 `unresolved_disposition_marked_resolved`로 정정 단계에 넣고, 새 조회 없는 직접 정정 대상(`LITERAL_REPAIR_ISSUES`)에 등록했다. 진단은 "두 값은 같은 판단이어야 한다. 미해결이면 resolved를 쓰지 말고, assessment를 바꾸려면 실제 근거가 있어야 한다"이다. 판단을 종결 쪽으로 유도하지 않는다 |
| 최종 검사 | 바꾸지 않았다(대체 문구 전환 조건 불변). 자동 사건 보고에서 마지막까지 모순이 남는 경우는 기존처럼 컨트롤러가 `needs_review`로 처리한다 |
| 상태 줄 진단 | 상태 줄 뒤에 코드 블록 닫는 표시가 있으면 "보고서나 제어 줄을 코드 블록으로 감싸지 말라"고 말한다 |
| `soc-investigate` 스킬 | 제어 줄 문장에 두 원칙을 더했다. 보고서 전체나 제어 줄을 코드 블록으로 감싸지 않는다. assessment가 unresolved이면 MANAGEMENT_STATUS를 resolved로 쓰지 않는다 |
| query-completion | 실행기 SHA 고정값 |

**실제 초안 재생**: 23:48 2차 초안은 그대로 두면 "코드 블록 닫는 표시" 진단과 Suricata 문장 진단을 받는다. 코드 블록만 벗기면 모순 검사가 잡는다. 정정을 거치면서 세 원인이 모두 차례로 진단된다.

## 검증

| 항목 | 결과 |
|---|---|
| 새 회귀(`test_report_repair_diagnosis.py`의 `DispositionStatusConflict` 5건) | `unresolved`+`resolved`만 모순(monitor·needs_review·benign/remediated+resolved·판단 줄 없음은 아님)·직접 정정 대상 등록, 코드 블록 진단, 실제 정정 훅에서 모순 진단·근거 요구 문구, 일관된 보고서는 이 정정 없음, 스킬 문장 두 원칙. 수정 전 실행기로는 동작 시험 3건 실패(나머지 2건은 기존 동작·스킬 문장 확인이라 기준본에서도 통과) |
| 관련 시험 | `test_report_repair_diagnosis` 15/15. `test_soc_management_evidence` 등 묶음의 실패 1건(`test_model_can_repair_missing_status_once_without_another_forced_read`)은 HEAD 기준본에서도 같은 기존 실패다 |
| 관련 묶음(현재본 대 HEAD 기준본) | Hermes 1,278(신규 5)·query-completion 408·Ollama 374·MCP 708·설치기 343. 새 실패 0. 차이 3건은 무관하다(다른 작업의 미커밋 핀, 기준본에서만 오류인 MCP 시험 1건(실행마다 결과가 달라지는 유형), 다른 작업의 미추적 방화벽 NAT 시험) |
| 공식 Harness² core(`6868817`) | 25구성, 스킬 5, 하위 에이전트 0, 상시 문구 변화 0, 변경 3구성요소. 보고서는 Git 제외 `G_Harness2/runs/2026-11-13-disposition-status-235809/` |
| 적용 스크립트 격리 시험 | 적용(사본 9곳·내장본·영수증, 다른 영수증 항목 보존), 원복(11파일), 거절 4종 |
| 운영 전제(B, 23:58 읽기 전용) | 사본 9곳·내장본·Ollama 영수증 3항목이 기준값과 같다 |

| 파일 | 기준(운영) | 후보 | 사본 |
|---|---|---|---|
| `soc_management_run.py` | `b32ea4c6…` | `f6556563…` | 4 + 컨트롤러 내장본 |
| `query-completion/__init__.py` | `576736f4…` | `53b54682…` | 2 |
| `skills/soc-investigate/SKILL.md` | `eeb28a8d…` | `3345bcc9…` | 3 |

**남은 것(이번 범위 밖)**: Hermes 조사 초안에 "peer(Ollama) 검토 결과" 같은 교차 검토 형식의 문단이 섞였다(23:48 1·2차). 교차 검토는 내부 식별자(`e3` 등)를 노출하고 시점 차이만으로 모두 미확인 처리했다. 별도 과제다.

## 적용 방법(승인 후, 미실행)

`apply_b.py <실행기> <플러그인 __init__> <SKILL.md>`를 B root로 1회 실행한다(직전 배포와 같은 절차). 적용 뒤 같은 질문으로 실제 채팅을 확인한다. 확인 항목은 두 가지다. 코드 블록·모순이 생기면 진단이 짚는지, 보고서가 대체 문구 없이 게시되는지다.
