# Ollama MCP 도구 목록 계약 수정 후보 (공동 채널 교차 검토 `ValueError`)

2026-11-13 KST. **원인 확인·수정·회귀·구조 점검까지이며 운영 B에는 적용하지 않았다.** 적용은 사용자 승인 뒤 관리자231 경유로 [`apply_b.py`](apply_b.py)를 1회 실행한다. [현황](../../../STATUS.md) · [작은 원장](validation.json) · [발견 기록: 상대 시각 구간](../relative-window/README.md).

## 증상

공동 채널(`soc-review-agent`)의 Ollama 교차 검토가 오늘 4회(17:23, 20:17, 20:44, 21:27) 모두 같은 문구로 끝났다. "조회·판단 실행이 중단되어 … 오류 유형: ValueError", "독립 조회 근거가 부족해 상대 답변 검증을 완료하지 못했습니다." 대기열 결과에는 모델 호출 0, 도구 호출 0, 약 7초가 남아 있다. 작업 상태는 `done`이지만 결과는 `partial`이다. 20:42 배포 기록에 "교차 검토 정상"으로 적은 것은 이 차이를 놓친 오기였다(정정 완료).

## 원인 (B 라이브 확인)

| 확인 | 결과 |
|---|---|
| 21:43 재현 추적(B, `soc-ollama`, 21:27 실패 작업의 실제 요청을 작업자에 다시 입력, 쓰기·모델 호출 없음) | 첫 `ValueError`는 `policy.filter_catalog`의 `server_tool_contract_changed`다. 경로는 `runtime.run` → MCP 연결 후 도구 목록 → `filter_catalog('rule-b', …)` |
| 21:44 전체 서버 도구 목록 대조(목록 조회만) | `rule-b`에 `get_harness_check_status`가 추가로 있다. `rule-write-b`에 `request_harness_check`·`request_harness_skill_resync`·`acknowledge_harness_finding`이 추가로 있다. 나머지 6개 서버는 정책과 같다 |
| 배경 | 작업 #5(채팅 Harness² 점검 승인 카드)의 B 전용 도구 4개가 11/13 00:34 배포(T2)로 B의 규칙 MCP에 추가됐다. Ollama 정책은 MCP가 광고하는 도구 집합이 고정 목록과 **정확히 같아야** 진행한다(목록 변화 시 차단). 이 고정 목록은 갱신되지 않았다 |

**영향 범위**: 00:34 이후 `rule-b`나 `rule-write-b`에 연결하는 모든 Ollama 실행이 모델 호출 전에 멈춘다. 공동 채널 교차 검토는 도구 범위를 미리 정하지 않아 모든 읽기 서버에 연결하므로 전부 실패했다. Ollama 단독 봇은 `hermes-parity` 모드라서 범위가 정해지지 않은 조사형 질문에서 같은 실패가 난다. 단순 목록 조회(예: "최근 30분 Wazuh 경보 보여줘", 21:29)는 `security-events` 서버만 연결해서 정상이었다. Hermes는 이 정책을 쓰지 않는다.

## 수정 (공통 요소: 서버 목록 계약과 사용 권한 분리)

[`infra/ollama-trial/policy.py`](../../ollama-trial/policy.py)

- `CATALOG_TOOLS`: 각 MCP 서버가 광고하는 **정확한 도구 집합**이다. 기존 사용 목록(`PARITY_TOOLS`)에 B 전용 Harness² 도구 4개(`HARNESS_GOVERNANCE_B`)를 더했다. `filter_catalog`의 정확 일치 검사는 이 계약으로 한다. 그 밖의 추가, 누락, A 서버에 B 전용 도구가 보이는 경우는 계속 차단한다.
- 사용 권한(`READ_TOOLS`, `PARITY_TOOLS`)은 바꾸지 않았다. 4개 도구는 어떤 Ollama 모드에서도 노출되지 않고 이름 변환(`alias`)도 거부된다. Harness² 점검 승인 카드는 Hermes 관리 경로의 기능이므로 Ollama 권한을 넓히지 않는다.
- 연결 풀 적격성, 도구 수(읽기 36), 쓰기 서버 접근 규칙은 그대로다.

**재발 방지**: [`test_policy.py`](../../ollama-trial/test_policy.py)의 `CatalogContract`가 MCP 원본과 계약을 직접 비교한다. 원본은 `rule_change_mcp.tool_list`(rule-a/b, rule-write-a/b의 호스트별 목록)와 `security-events` 서버의 `tools/list` 응답이다. MCP에 도구가 추가되면 운영 채팅보다 이 시험이 먼저 실패한다.

## 검증

| 항목 | 결과 |
|---|---|
| 새 회귀 `CatalogContract` 5건 | 현재본 5/5 통과. 수정 전 정책으로는 5/5 실패(원본 대조 4개 서버·보안 이벤트, 운영 목록 수용, 그 밖의 목록 변화 차단) |
| `test_policy.py` 전체 | 17/17 |
| 관련 묶음(현재본 대 HEAD 기준본) | Ollama 368(신규 5)·query-completion 408 모두 통과. Hermes 1,250·MCP 708은 기준본과 같은 기존 실패이고, 설치기는 343(기준 332)이다. 새 실패 0. 차이 2건은 무관하다. Hermes 1건은 기준본에서만 실패하는 다른 작업의 미커밋 핀이고, 설치기 1건은 다른 작업의 미추적 방화벽 NAT 시험(`deployment/tests/test_firewall_nat.py`, 11/03 파일)이다 |
| 공식 Harness² core(`6868817`) | 25구성, 하위 에이전트 0, 상시 문구 변화 0, 변경 1파일(`sdk_authority` = `policy.py`). 보고서는 Git 제외 `G_Harness2/runs/2026-11-13-catalog-contract-214758/` |
| 적용 스크립트 격리 시험(Mac 임시 공간) | 적용(정책·영수증 교체, 표식·백업·원복 스크립트 생성), 원복(두 파일 복원), 거절 3종(대기열 사용 중·운영 기준 불일치·후보 변경 시 변경 없음) |
| 운영 전제(B, 21:44) | `/opt/capstone-ollama-trial/policy.py`와 영수증 `sources.policy.py`가 리포 HEAD와 같다(`7716bdd3…`) |

| 파일 | 기준(운영·HEAD) | 후보 |
|---|---|---|
| `infra/ollama-trial/policy.py` → `/opt/capstone-ollama-trial/policy.py` | `7716bdd3…` | `832d8c69…` |
| 영수증 `/etc/capstone-ollama-trial/receipt.json`의 `sources.policy.py` | `7716bdd3…` | `832d8c69…` |

B의 설치 원본 사본 `/opt/capstone-prereqs/ollama-trial/source/infra/ollama-trial/policy.py`는 10/31 판(`c3701c92…`)으로, 이번 일과 별개로 이미 운영본보다 오래됐다. 이 후보는 그 사본을 바꾸지 않는다. 새 서버 설치는 리포의 `deployment/ollama_trial.py`가 리포 `policy.py`를 쓰므로 수정이 반영된다.

## 적용 방법(승인 후, 미실행)

`apply_b.py <policy.py>`를 B root로 1회 실행한다. 두 채팅 대기열이 비어 있을 때만 정책 파일과 영수증 항목을 교체하고, 백업과 45분 원복 타이머를 건다. Ollama 대기열이 비어 있으면 Ollama 봇만 재시작한다. 공동 채널 교차 검토는 작업마다 새 프로세스라 재시작이 필요 없다. 적용 뒤에는 공동 채널 조사 질문의 Ollama 교차 검토가 실제 독립 조회와 대조를 마치는지, Ollama 단독 채널의 조사형 질문이 모델 호출까지 가는지 확인하고 확정한다.
