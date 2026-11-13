# 조회 범위 일치 후보 (독립 조회와 근거는 질문 범위와 같아야 한다)

2026-11-13 KST. **수정·회귀·구조 점검까지이며 운영 B에는 적용하지 않았다.** 적용은 사용자 승인 뒤 관리자231 경유로 [`apply_b.py`](apply_b.py)를 1회 실행한다. [현황](../../../STATUS.md) · [작은 원장](validation.json) · [직전 수정: 교차 검토 요청 조건](../peer-query-scope/README.md).

## 문제 (11/13 22:22 공동 채널, B 기록)

| 관측 | 내용 |
|---|---|
| 교차 검토 거짓 이견 ① | 검토자가 자기 조회의 `returned_count: 0`을 "전체 구간 0건"으로 읽고 Hermes의 "전체 건수 미확인"을 반박했다(`indexed_window_total_count: null`) |
| 교차 검토 거짓 이견 ② | 검토자 자신의 Wazuh 조회에 질문에 없던 `program_name='systemd'` 필터가 붙었고, 그 0건으로 Hermes의 필터 없는 표본 10건을 반박했다 |
| Hermes 실패 | 질문에 없는 `get_firewall_rules`를 호출하면서 이전 페이지에서 받은 적 없는 `snapshot`(`d41d8cd9…`, 빈 문자열의 MD5)을 넣었다. MCP가 `FileNotFoundError`로 거절했고, 답변 전체가 "도구 조회 실패로 판단 미완료"가 됐다 |

공통 원인은 하나다. 첫 조회의 선택적 인자(필터·페이지 토큰)가 질문에 근거하지 않아도 열려 있었고, 교차 검토도 질문보다 좁거나 의미가 다른 근거로 이견을 만들 수 있었다. 확인해 보니 Hermes 첫 조회 공통 함수(`initial_event_filter_schema`)는 IP·규칙 ID·에이전트 ID만 제한하고 `program_name`과 방화벽 페이지 토큰은 제한하지 않았다(22:30 보고의 "Hermes는 이미 막혀 있다"는 이 필드에 대해 틀렸다). Ollama 교차 검토의 독립 조회는 이 함수를 쓰지 않았다. 하네스가 `systemd`를 넣은 것은 아니다(로컬 확인). 스키마 설명의 "예: systemd"를 보고 모델이 붙였다.

## 수정 (공통 원칙 → 적용 지점)

**원칙: 첫 조회는 질문보다 좁을 수 없다. 교차 검토의 일치·이견 근거도 질문 범위 안의 관측이어야 한다.**

| 위치 | 변경 |
|---|---|
| 공통 첫 조회 함수 `initial_event_filter_schema` (`soc_management_run.py`, 두 봇 공용) | `program_name`은 명시 라벨(`program_name`·`program`·`프로그램`)이 있거나 질문이 `systemd`·서비스 실패를 말할 때만 그 값으로 허용한다. 그 밖에는 선택지에서 뺀다. 첫 방화벽 조회는 `snapshot`을 빼고 `offset`을 0으로 묶는다(새 실시간 조회, Ollama의 기존 첫 페이지 규칙과 같음). 컨트롤러가 필수로 정한 인자는 건드리지 않는다 |
| Ollama 런타임 `question_scope_schema` (`runtime.py`) | 교차 검토(`peer`)의 독립 조회 도구 스키마에 같은 공통 함수를 적용한다. Ollama 단독 채팅은 바꾸지 않는다(결과를 보고 필터를 좁히는 후속 조회를 유지) |
| 공동 채널 작업자 (`review_channel_worker.py`) | 교차 검토 단계에서만 `question_scope_reads`를 런타임에 넘긴다. 근거 바인딩에 규칙 두 개를 추가했다. ① 근거 호출의 `applied_filters` 값이 질문에 없으면, 그 근거로 한 일치·이견을 `peer_filter_scope_mismatch`로 거절한다(참조 목록에 `filters_outside_question`으로 표시해 모델도 본다). ② 반환 표본 수(`returned_count`·`returned_items`)가 0인 근거로 한 이견을 `peer_zero_sample_dissent`로 거절한다. 두 코드 모두 정정 1회 경로에 넣었다. 미확인과 0이 아닌 표본은 그대로 쓸 수 있다 |
| query-completion 고정값 | 실행기 SHA 고정값을 새 실행기로 맞췄다 |

**의도한 한계**
- "sshd 로그" 같은 질문도 라벨이 없으면 첫 조회에서 `program_name` 필터를 쓰지 않는다. 더 넓게 조회할 뿐 좁아지지 않는다.
- 반환 0건으로는 "상대가 본 경보가 실제로는 없다"는 이견도 낼 수 없다. 색인 지연, 조회 한도, 시점 차이 때문에 0건은 부재의 증거가 아니다. 이는 MCP 결과의 `evidence_scope_ko` 문구와 같은 원칙이다.
- Hermes가 질문 밖 도구(이번에는 방화벽)를 고르는 것 자체는 막지 않는다. 이번 수정으로 그 조회가 지어낸 인자로 실패하지는 않는다.

## 검증

| 항목 | 결과 |
|---|---|
| 새 회귀 | Hermes `test_query_scope.py` 5건(질문 밖 `program_name` 제거·명시/systemd 허용·필수 인자 불변·첫 방화벽 조회는 새 조회와 `offset` 0·다른 도구 불변). `test_review_channel.py` 3건(질문 밖 필터 근거 거절·질문의 필터 허용, 0건 이견 거절·일치/미확인/0이 아닌 표본 허용, 교차 검토만 범위 플래그 전달). Ollama `test_runtime.py` 2건(교차 검토 스키마 축소, 단독 채팅 불변) |
| 의도한 기존 시험 기대값 변경 | 21:55 사례 시험 픽스처에 질문 문장을 넣었다(필터가 질문 안에 있어야 요청 조건 검사만 확인됨). Ollama 교차 검토 요청 비교 시험에 `question_scope_reads: True`를 추가했다 |
| 기존 방화벽 첫 페이지 시험 | 처음 후보는 `offset`을 아예 빼서 Ollama 시험 1건(`test_first_fw_page_cannot_invent_snapshot_or_future_offset`)이 실패했다. `offset`을 0으로 묶도록 고쳐 통과했다 |
| 관련 묶음(현재본 대 HEAD 기준본, 최종본) | Hermes 1,261(신규 8)·query-completion 408·Ollama 370(신규 2)·MCP 708·설치기 343. 새 실패 0. 차이 2건은 무관하다(다른 작업의 미커밋 핀, 다른 작업의 미추적 방화벽 NAT 시험) |
| 공식 Harness² core(`6868817`) | 25구성, 하위 에이전트 0, 상시 문구 변화 0, 변경 4파일(`evidence_gate`·`native_query`·`sdk_runtime`·`channel_worker`). 보고서는 Git 제외 `G_Harness2/runs/2026-11-13-query-scope-223915/`(최종본, `-223722`는 첫 후보) |
| 적용 스크립트 격리 시험(Mac 임시 공간) | 적용(사본 8곳·내장본·영수증 2종), 원복(11개 파일 복원), 거절 5종(대기열 사용 중·사본 불일치·내장본 불일치·Ollama 영수증 불일치·공동 채널 영수증 불일치 시 변경 없음). 최종 SHA로 재시험 통과 |
| 운영 전제(B, 22:39 읽기 전용) | 사본 8곳·내장본·Ollama 영수증 3항목·공동 채널 영수증 작업자 항목이 모두 기준값과 같다 |

| 파일 | 기준(운영) | 후보 |
|---|---|---|
| `soc_management_run.py` (사본 4 + 컨트롤러 내장본) | `cf6124ad…` | `bc19115d…` |
| `query-completion/__init__.py` (사본 2) | `accf2b07…` | `3847d9c8…` |
| `ollama-trial/runtime.py` | `1e7aefa6…` | `026a2cf9…` |
| `review_channel_worker.py` | `47811503…` | `f4f426c7…` |

## 적용 방법(승인 후, 미실행)

`apply_b.py <실행기> <플러그인 __init__> <런타임> <작업자>`를 B root로 1회 실행한다. 상대 시각 배포와 같은 절차다. 두 대기열이 비어 있을 때만 컨트롤러 잠금 아래 사본 8곳·내장본·영수증 2종을 교체하고, 45분 원복 타이머를 건다. Ollama 대기열이 비어 있으면 Ollama 봇만 재시작한다. 적용 뒤에는 22:22와 같은 질문으로 공동 채널 실제 채팅을 확인한다. 확인 항목은 세 가지다. 교차 검토의 독립 조회에 질문 밖 필터가 없어야 하고, 0건·범위 불일치 이견이 게시되지 않아야 하며, Hermes 첫 조회 선택에 `snapshot`이 없어야 한다. 모델 출력은 매번 달라 같은 상황이 재현되지 않을 수 있으며, 그 경우 회귀로만 확인된 부분을 구분해 기록한다.
