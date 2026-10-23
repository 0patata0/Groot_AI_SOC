# 2026-10-15 KST promptfoo 실측

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../../STATUS.md) · [실행 계획](../../../../../PLAN.md).
> 현재 구성은 MCP6서버와 고정 진단25대상이다. 자연어 도구 선택·무근거 완료/SILENT 알림 보완의 실제 검증 상태는 STATUS 최상단을 따른다. 정확 후보 승인과 일반 sudo/Docker/임의 shell 금지는 유지한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

부모 운영자가 B의 Node22.22.0/promptfoo0.124.1 설치와 native config2개·순수36회귀 성공 후 `.111`의 `qwen3.6:35b`를 직접 평가했다. 다음은 서버 결과에서 원문을 제외해 추출한 집계다. 모델 응답·추론·개별 보안 원문은 이 문서에 옮기지 않았다.

| 평가 | 출력 상한 | 통과 | API 왕복 시간 | 관측 결과 |
| --- | ---: | ---: | --- | --- |
| 품질6개 | 2048토큰 | 6/6 | 13.820~22.325초 | 정답·두 키 JSON·한국어 표면 조건 통과 |
| 도구 최초2개 | 2048토큰 | 0/2 | 22.501초 / 22.832초 | 두 건 모두 `finish_reason=length`, 채점 대상 빈 출력 |
| 도구 추가 비교2개 | 8192토큰 | 0/2 | 84.053초 / 60.281초 | 첫 건 length·빈 출력, 둘째 stop·코드 블록 응답 |

집계 원본: [품질](quality-2048.json), [도구2048](tools-2048.json), [도구8192](tools-8192.json). 최초 실패와 추가 비교 실패를 모두 보존했다. 자동 재시도는 없고, 운영자의 8192토큰 비교 한 번 이후 추가 평가·모델 튜닝은 하지 않았다. 120초 latency 조건 안에서 반환됐어도 응답 형식/도구 선택 조건을 실패하면 통과가 아니다.

도구 사례는 `read_a_waf`와 `read_b_wazuh-manager`다. 두 사례 모두 정확한 함수 `get_service_action_target` 하나와 각각 `{"target":"a:waf"}`, `{"target":"b:wazuh-manager"}`를 요구한다. 8192 비교의 첫 사례는 completion8192토큰·빈 출력이었다. 둘째는 completion5599토큰·157문자·코드 울타리 포함이며, 함수명과 기대 target 문자열 및 JSON 객체 하나가 있었다는 **분류 메타데이터만** 확인했다. 전체 출력은 JSON이 아니어서 기존 채점 기준으로 실패다. 문자열이 보였다는 사실을 native 도구 호출 성공으로 바꾸지 않는다.

현재 prompt는 도구 호출을 ‘제안’하도록 요청하고 `tool_choice=auto`를 사용한다. 채점기는 호출 배열을 담은 JSON 텍스트도 허용한다. 따라서 이번 범위는 합성 도구 선택·형식 평가이며 native API 호출 필드의 별도 인증은 아니다. promptfoo provider는 응답의 content/호출/reasoning 필드에 따라 채점 출력을 구성하므로, 그 출력만으로 원본 `message.tool_calls`의 존재 여부를 모두 단정하지 않는다. `showThinking=false` 또한 reasoning 표시 억제이며 모델 추론 비활성화 근거가 아니다. [고정0.124.1 provider 소스](https://github.com/promptfoo/promptfoo/blob/0.124.1/src/providers/openai/chat.ts#L947-L980).

실제 도구 실행·MCP 호출·모델 grader·채팅 발송은0이다. callback/exec provider가 없으며 Hermes의 운영 설정·가드·권한도 바꾸지 않았다. 품질6/6은 이 여섯 사례의 성공이지 일반 SOC 정확성 또는 프로덕션 한국어 품질 보증이 아니다. API 왕복 시간은 TTFT·실제 도구 처리·승인 대기·사용자 전송 시간을 포함한 Hermes 전체 latency가 아니다.

[모델 관측](model-observation.json)의 digest는 품질 실행 중과 최종 도구 평가 후 동일했다. 품질 시작 전 digest pin은 관측하지 않았다. 현재 도구 실패 원인의 내부 추론/프로토콜 수준 구분과 엄격한 native 호출 평가는 후속 범위로 남기며, 통과를 위해 기존 실패 기록이나 `grade.cjs`를 수정하지 않는다.
