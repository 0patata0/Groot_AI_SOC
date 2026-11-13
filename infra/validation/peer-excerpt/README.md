# 교차 검토: 표시용 발췌의 생략 수를 조회 누락으로 오해하지 않기 후보

2026-11-14 KST. **수정·회귀·구조 점검까지이며 운영 B에는 적용하지 않았다.** 적용은 사용자 승인 뒤 관리자231 경유로 [`apply_b.py`](apply_b.py)를 1회 실행한다. [현황](../../../STATUS.md) · [작은 원장](validation.json) · [직전 수정: 조회 한도](../peer-limit/README.md) · [공통 스킬](../../hermes/workflow-skills.md).

## 문제 (11/14 01:38 공동 채널 Ollama 교차 검토)

검토자는 Wazuh를 `limit 10`으로 읽어 10건을 받았다. 그런데 미확인 주장에 "제한 10건에 도달(scan_capped true)해 **7건이 생략**되었습니다", "누락된 7건의 경보에 공격 징후가 있을 수 있어"라고 썼다.

| 확인 | 내용 |
|---|---|
| 7의 정체 | 공동 채널 작업자(`compact_peer_result`)는 검토 입력을 줄일 때 배열을 `{returned_items: 실제 길이, sample: 앞쪽 3개, omitted_items: 나머지 수}`로 바꾼다. 10건 중 3건을 보여 주고 7건을 표시에서 뺐다는 뜻이다. **조회에서 빠진 경보가 아니다** |
| 이름 | `omitted_items`는 이 작업자만 만드는 값이다(MCP 결과에는 없다). "생략"이라는 이름이 데이터 누락처럼 읽힌다 |
| 안내문 | 검토자 안내는 "omitted_items·truncated를 확인하세요"라고만 해서, 이 값이 데이터 손실 신호인 것처럼 보이게 했다 |
| **01:35 내 설명의 오류(정정)** | 01:35 수정에서 스킬 문장과 정정 문구가 `omitted_items`를 한도에 닿은 조회의 건수 4종에 넣고 "검토자가 정한 한도와 같은 값"이라고 설명했다. 이것은 틀렸다. `omitted_items`는 한도와 무관한 표시용 생략 수다. 검토자의 "한도 10에 도달(scan_capped true)해 7건이 생략"은 바로 이 잘못된 연결을 따른 것이다. 그래서 내 문장이 오해를 키웠을 가능성이 있다 |

## 수정 (형식 설명은 코드, 원칙은 스킬)

| 층 | 위치 | 변경 |
|---|---|---|
| 입력 형식(코드) | `compact_peer_result` | 이름을 뜻대로 바꿨다. `omitted_items` → `not_shown_in_excerpt`, `omitted_characters` → `not_shown_characters`, 깊이 제한 표시 `omitted` → `not_shown`. 실제 반환 건수는 계속 `returned_items`다 |
| 안내문(코드) | 교차 검토 합성 지시 | "omitted_items·truncated를 확인하세요"를 발췌 형식 설명으로 바꿨다. `not_shown_*`는 이 표시에서만 뺀 양이며 조회에서 빠진 경보·데이터가 아니다. 도구 결과 자체의 `truncated`는 원문 그대로 읽는다 |
| 강제 경계(코드) | `bind_peer_references` | 근거가 `not_shown_*`이면 일치·이견을 새 코드 `peer_display_excerpt_scope`로 거절한다(한도와 무관). 미확인은 허용한다 |
| 01:35 정정(코드·스킬) | `PEER_LIMIT_BOUND_KEYS`, 정정 문구, `## 교차 검토 대조` | `omitted_items`를 한도 관련 목록과 문장에서 뺐다. 스킬에는 "검토 입력의 not_shown_in_excerpt 같은 값은 표시용 발췌에서 뺀 수이며 조회에서 빠진 경보가 아닙니다"를 더했다 |

실행기·검사기·하네스는 바꾸지 않았다. 원래 도구 영수증도 바뀌지 않는다(검토 입력의 표시만 바뀐다).

**한계**: 01:38의 오해는 **미확인 주장의 본문**에 나왔다. 미확인 본문은 결정적으로 검사하지 않는다. 그래서 이번 강제 경계가 그 문장을 직접 막지는 않는다. 효과는 이름·안내문·스킬 원칙이 모델의 읽기를 바로잡는지에 달려 있다.

## 검증

| 항목 | 결과 |
|---|---|
| 새 회귀(`test_review_channel.py`) | 10건 반환·3건 표시일 때 `returned_items` 10, `not_shown_in_excerpt` 7, 긴 문자열 `not_shown_characters` 200, 압축 결과에 `omitted`라는 글자가 없음. 한도 도달·미도달 모두 `not_shown_*` 근거의 일치·이견은 `peer_display_excerpt_scope`로 거절되고 미확인은 허용됨. `omitted_items`는 한도 목록에 없음. 스킬 절에 원칙 문장이 있고 `omitted_items`는 없음. **HEAD 코드로는 실패**(`not_shown_in_excerpt` 없음) |
| 기존 시험 갱신 | 압축 시험의 키 이름, 01:35 한도 시험의 경로 목록(`omitted_items` 제외), 교차 검토 프롬프트 시험에 형식 설명 포함·`omitted_items` 미포함 단언 추가 |
| 관련 시험 | `test_review_channel`·`test_workflow_contract` 97건 통과 |
| 관련 묶음(현재본 대 HEAD 기준본) | Hermes 1,294(신규 1)·query-completion 408·Ollama 374·MCP 708·설치기 343. 새 실패 0. 차이는 무관하다(기준본에서만: 다른 작업의 미커밋 핀 1건, 실행마다 결과가 달라지는 MCP 시험 2건 / 현재본에서만: 다른 작업의 미추적 방화벽 NAT 시험 1건) |
| 공식 Harness² core(`6868817`) | 25구성, 스킬 5, 하위 에이전트 0, 상시 문구 변화 0, 변경 2구성요소(`channel_worker`·`skills/soc-investigate`). 보고서는 Git 제외 `G_Harness2/runs/2026-11-14-peer-excerpt-014459/` |
| 적용 스크립트 격리 시험(Mac 임시 공간) | 적용(작업자 1·스킬 3·두 영수증 항목, 다른 항목 보존), 원복(6파일), 거절 4종 |
| 운영 전제(B 01:45 읽기 전용) | 작업자 `923db594…`·스킬 사본 3곳 `125ed453…`, 두 영수증 항목이 기준값과 같고 배포 폴더 이름이 비어 있다 |

| 파일 | 기준(운영) | 후보 | 사본 |
|---|---|---|---|
| `review_channel_worker.py` | `923db594…` | `da7e3a3d…` | 1 + 공동 채널 영수증 |
| `skills/soc-investigate/SKILL.md` | `125ed453…` | `50825f27…` | 3 + Ollama 영수증 항목 |

## 적용 방법(승인 후, 미실행)

`apply_b.py <review_channel_worker.py> <SKILL.md>`를 B root로 1회 실행한다. 직전 배포와 같은 절차다(컨트롤러 잠금, 두 대기열이 빈 상태, 45분 원복 타이머, Ollama 대기열이 비면 Ollama 봇만 재시작). 적용 뒤 같은 질문으로 실제 채팅을 확인한다. 확인 항목은 하나다. 교차 검토가 "N건이 생략/누락" 같은 표현을 쓰지 않는지다.
