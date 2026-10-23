# 2026-10-15 — 추론 설정과 실제 도구 호출 비교

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 현재 구성은 MCP6서버와 고정 진단25대상이다. 자연어 도구 선택·무근거 완료/SILENT 알림 보완의 실제 검증 상태는 STATUS 최상단을 따른다. 정확 후보 승인과 일반 sudo/Docker/임의 shell 금지는 유지한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

10:06:02 KST B의 운영 모델 `qwen3.6:35b`에만 `agent.reasoning_overrides`의 `none`을 적용했다. `.111` endpoint·모델·MCP 권한·승인·한국어 가드는 유지했다. config SHA는 `89ec0f90…`에서 `00722d3c…`로 바뀌었고 UID995:GID986/0640을 보존했다. 원본은 B `/var/backups/capstone-hermes-reasoning-20261015`에 있다. 기존 Hermes PID2248019/CID/StartedAt을 유지했으며 재시작0이다. 설치된 gateway 로더와 provider가 `enabled=false` → `reasoning_effort=none`으로 해석함을 실제 UID에서 확인했다.

## 새 동일 입력 대조

[집계](comparison.json). Ollama0.32.4, 모델 digest `096fdbd02fe620fc10cbeb6537e080f8041aece851e5d696aed024d4f70f2e47`, 35.5B/Q4_K_M이다. 동일 prompt/tools/temperature0/seed42/max_tokens2048에서 추론 값만 medium/none으로 바꿨다. 원래 promptfoo 평가에는 medium 명시가 없었으므로 이것을 이전 평가의 완전 재현이라고 부르지 않는다.

| 읽기 사례 | medium | none |
|---|---|---|
| A WAF | 22.247초, 2048토큰 length, 추론7966자, 호출0 | 0.693초, 29토큰, 추론0, 정확 native 호출1 |
| B Wazuh manager | 22.746초, 2048토큰 length, 추론7702자, 호출0 | 0.721초, 31토큰, 추론0, 정확 native 호출1 |

원본 API 응답의 단일 문서/선택/assistant, `finish_reason=tool_calls`, ID·type·정확 함수·JSON 인수를 검사했다. JSON 텍스트나 코드펜스는 native 호출로 인정하지 않는다. 이 네 건은 반환 도구를 실행하지 않았다. [runner](run-case.sh)의 curl 모의 경계12개가 Mac과 B에서 통과했다.

최초 medium 한 건은 HTTP200/23.053309초였으나 jq 구문 오류로 분류 실패했고 초기 EXIT 처리로 raw가 삭제됐다. 결과 성공으로 사용하지 않는다. 그 소스·timing은 별도 실패 경로에 보존했고, 집계기 수정·경계 검사 뒤 위 새 대조를 수행했다.

## 한국어 품질과 합성 부분 편집

기존 여섯 품질 문항·채점기를 유지한 실제 none 비교는 **6/6, 0.963~1.752초, completion45~118토큰**이었다. 여섯 사례의 성공이며 일반 SOC 분석 정확성이나 장기 혼입률을 보증하지 않는다.

최초 followup01은 일반 config.reasoning_effort를 넣었지만 고정 promptfoo provider가 Qwen 모델명에서 이를 생략했다. 6/6·13.753~19.642초 결과를 none 검증으로 쓰지 않는다. followup02는 공식 `passthrough: {reasoning_effort: none}`를 사용했다. [고정 provider 구현](https://raw.githubusercontent.com/promptfoo/promptfoo/0.124.1/src/providers/openai/chat.ts)의 모델명 분기와 passthrough 병합을 근거로 구분한다. 기존 showThinking=false는 추론 표시 제어다.

[합성 쓰기 요청](synthetic-write-request.json)은 실제 부분 편집 스키마와 `mcp__rule_a__propose_rule_edit` 이름을 사용했다. 2.182초·165토큰으로 native 호출1을 반환했다. 초기 정확 인수 fixture는 모델이 줄바꿈 없는 더 짧은 유일 기준 문자열을 선택해 실패했다. 원래 판정은 [배포 집계](deployment.json)에 남겼다. 설치된 변경기 SHA `d937c7de…`의 `_validated_edits`/`_edit_candidate` 순수 함수로 같은 응답을 대조하니 목표 파일·SHA·target·사유가 모두 일치했다. 의미 검증은 통과지만 실제 승인 요청·MCP 쓰기·룰 변경은0이다.

## 실제 Hermes와 읽기 MCP 통합

[일회 검증기](verify-hermes-readonly.py)는 기존 Hermes/MCP 패키지를 재사용하는 운영자 시험이다. 새 서비스나 운영 코드 패치가 아니다. 컨테이너 UID995:986에서 별도 `/tmp/capstone-readonly-20261015` home/work를 사용했고 기존 대화·.env·DB를 복제하지 않았다. 허용한 모델 노출 도구는 정확 `mcp__rule_a__get_service_action_target` 하나이며 dispatch와 SDK 양쪽에서 `a:waf` 읽기1회만 허용했다.

실제 결과는 초기화5.979초·대화6.135초·전체12.254초, 모델 API2회·MCP wire1회·dispatch1회(0.418초), running 상태 및 응답 완료였다. 종료/연결 정리도 완료했다. 실제 설치된 regex2026.9.29 검사에서 최종문450자에 Han/Kana0·한글 존재를 확인했다. 운영 Mattermost 발송은0이다. 순수 모델 API 시간은 별도 계측하지 않아 null이며 대화시간에서 MCP시간을 뺀 값을 모델시간이라고 부르지 않는다.

이는 좁은 통합 시험이다. 전체 운영 도구 목록·긴 대화·실제 승인 대기·Mattermost 전달 지연까지 개선됐다고 확대하지 않는다. 이후 자연 요청의 언어·읽기/쓰기 지연을 관찰한다. 세션별 `/reasoning` override는 모델별 기본값보다 우선하며 이번에 지우지 않았다.

[Ollama 설치 버전의 none 변환](https://github.com/ollama/ollama/blob/v0.32.4/openai/openai.go) · [Hermes 설정 우선순위](https://hermes-agent.nousresearch.com/docs/user-guide/configuration). 설정 파일만 바꾸며 학습·모델 교체·sudo/Docker 권한 확대는 없다.

## 증거 보존과 정리

10:10:14 KST B `/var/backups/capstone-hermes-reasoning-20261015`에 92파일/1,211,170B를 해시 대조해 보존했다. manifest SHA는 `c66cb6251b6015950a05035d139450a57d7ea9272c7ff7898de8ac5248f29f94`다. 임시 평가 stage와 격리 Hermes 작업 경로를 제거했다. 집계 완료한 medium 원문 두 건도 제거했으며 SHA와 판정 메타데이터는 보존했다. 앞선 평가 metadata의 raw_retained 표기는 후행 cleanup 영수증으로 정정된다. Mac 새 패키지 설치는0이다.
