# promptfoo 합성 읽기 평가

2026-10-15 KST 최신 실측: **B 격리 설치·두 config native validate·순수36회귀 완료, 품질 6/6 통과, 도구 선택은 2048·8192 토큰 모두 0/2**다. 품질 API 왕복은 13.820~22.325초, 최종 도구 평가는 84.053초와 60.281초였다. 도구 평가 실패를 보존하고 추가 재평가는 종료했다. 설치 성공이 모델의 도구 사용 성공을 뜻하지 않는다. [실측 결과와 한계](results/README.md), [품질 집계](results/quality-2048.json), [도구 최초 집계](results/tools-2048.json), [도구 8192 집계](results/tools-8192.json)를 참조한다.

실제 도구 실행·MCP 호출·채팅 발송은 0이다. 기존 Hermes 설정·승인·한국어 가드와 모델 운영 설정은 바꾸지 않았다. 운영 `.111`의 `qwen3.6:35b`를 Chat Completions 형식으로 직접 호출한 합성 평가이므로 Hermes 전체 왕복 또는 전송 전 한국어 가드의 평가와 구별한다.

고정 도구는 [promptfoo 0.124.1](https://github.com/promptfoo/promptfoo/releases/tag/0.124.1)이다. [해당 tag의 package.json](https://github.com/promptfoo/promptfoo/blob/0.124.1/package.json)은 Node >=22.22.0을 요구한다. 실제 B는 `/opt/capstone-tools/promptfoo/` 아래 Node22.22.0과 app을 분리했다. 부모 전달 실측은 Node 아카이브 SHA `9aa8e9d2298ab68c600bd6fb86a6c13bce11a4eca1ba9b39d79fa021755d7c37`, 설치된 upstream promptfoo package.json SHA `1f88f2f383feeee5ea79b84070fa77ff722f5467819477088120f22e6fe3e1bd`, repo 전이 lock SHA `48736a61e0a5c5188f71f66525c58dab2a1895bbe5a4d8794b0ed6a4c4aa6832`다. upstream package.json과 이 평가의 작은 app package.json은 다른 파일이다. Mac에는 패키지를 설치하지 않았다.

## 평가 범위

`quality.json` 6개는 관측0/효과미관찰 구분, 최신 상태 선택, 큐 계산, 오래된 공격 근거, 로그의 지시문 무시, KST 날짜 경계다. 정답값·두 키 JSON·짧은 한국어 설명과 요청하지 않은 한자/가나 표면을 확인한다. 이 작은 표면검사는 일반적인 한국어 품질·사실 정확성·원문 인용 정책 전체를 증명하지 않는다. JSON duplicate key 방어용 parser가 아니며 모델 평가 점수용이다.

`tools.json` 2개는 기존 `get_service_action_target`의 읽기 스키마만 모델에 제공하고 A WAF/B Wazuh manager의 이름·인자를 대조한다. **callback/MCP/exec provider가 없으므로 반환된 도구는 실행하지 않는다.** 입력은 전부 합성이고 실제 보안 원문·사용자 대화·비밀 값이 없다.

이는 읽기 전용 도구 **선택·제안 형식** 평가다. prompt는 호출 하나를 ‘제안’하도록 요구하고 `tool_choice=auto`를 사용한다. `grade.cjs`는 JSON 텍스트의 호출 배열도 허용하므로, 통과하더라도 API 원본의 native `message.tool_calls` 발생을 독립적으로 증명하지 않는다. 현재 실패를 없애기 위해 prompt·채점 기준을 변경하지 않았다. 엄격한 native 프로토콜 검증이 필요하면 원본 응답의 호출 필드만 별도 관측하는 후속 평가로 분리한다.

각 suite는 동시1·반복1·provider retry0이다. 품질과 최초 도구 평가는 출력2048토큰, 운영자가 한 번 추가 비교한 도구 평가는8192토큰이며 현재 `tools.json`에는8192가 남아 있다. 실패한 최초 결과도 보존했다. 캐시를 끈 latency는 API 왕복 한 건의 시간이며 TTFT·Hermes 처리·사용자 체감 지연이 아니다. 최초 cold 요청도 포함한다. 120초는 실험 중단 기준이지 서비스 SLA가 아니다. 소수 합성 사례로 p95·오답률 통계 또는 장기 품질을 주장하지 않는다.

`showThinking=false`는 promptfoo가 reasoning 내용을 출력에 붙이지 않도록 하는 설정이다. 모델의 추론 자체를 끄거나 토큰 소비를 막았다는 뜻은 아니다. 빈 출력의 내부 원인을 이 옵션만으로 확정하지 않는다. [설치 버전의 OpenAI provider 구현](https://github.com/promptfoo/promptfoo/blob/0.124.1/src/providers/openai/chat.ts#L947-L980).

## 설치 준비 절차 — 최초 설계 기록

아래는 설치 전 정리한 절차를 보존한 것이다. 현재 설치·평가 결과는 상단과 결과 문서를 따른다.

1. B의 아키텍처/배포판/glibc와 standalone Node 의존을 읽기 확인한다. 현재 B 호스트에는 node/npm이 없고 기존 Hermes 컨테이너에는 Node26.5.1이 있다는 부모 실측을 전달받았다. 운영 컨테이너에 npm install하지 않는다. 별도 `/opt/capstone-tools/promptfoo/node/`에 공식 Linux Node 아카이브를 SHA 검증 후 두는 경로를 우선한다. 버전·SHA·반입 목록은 실제 다운로드 후 고정한다.
2. Mac의 기존 npm을 사용한다면 작업 전용 임시 디렉터리와 npm cache 안에서만 `npm install --package-lock-only --ignore-scripts --no-audit --no-fund --os=linux --cpu=x64 --libc=glibc`로 **lock만** 만든다. node_modules 부재를 확인하고 lock의 resolved URL·integrity가 고정된 npm tarball을 해당 cache에 준비한다. 이 문서는 lock 생성이나 다운로드 완료 증거가 아니다.
3. `@libsql/client`와 그 Linux native platform 의존 때문에 `--omit=optional`을 무조건 쓰지 않는다. Linux/x64 플랫폼 tarball을 포함한 cache·package.json·lock만 B의 private stage로 전송하고 전수 SHA를 검증한다. B에서 별도 app 디렉터리에 `npm ci --offline --ignore-scripts --no-audit --no-fund --cache <private-cache>`를 실행한다. package 설치 스크립트와 외부 fetch를 실행하지 않는다. CLI가 native module 부족으로 거절되면 실패 자료를 보존하고 필요한 정확 의존만 조사한다.
4. B에서 `node --version`, `promptfoo --version=0.124.1`, 두 config의 `validate config`, 아래 순수 채점 검사를 먼저 실행한다. native 설치/검증이 끝나야 평가 준비 완료다. 설치 package tree의 버전·lock SHA·실행 바이트 manifest를 보관하고 전송용 cache만 정리한다. 기존 Node/Hermes·사용자 npm cache는 건드리지 않는다.

## 고정 실행 명령

```sh
# 기존 Node만 쓰는 로컬 순수 회귀: 모델/패키지 설치/네트워크0
node infra/hermes/benchmarks/promptfoo/test-grade.cjs

# 이미 실행한 최초 두 평가의 명령 형식. 새 실행은 별도 관측이며 결과 경로 재사용 금지.
bash run-b.sh quality /var/tmp/capstone-promptfoo-20261015/run-quality-01
# quality 결과를 먼저 검토한 뒤
bash run-b.sh tools /var/tmp/capstone-promptfoo-20261015/run-tools-01
```

`run-b.sh`는 패키지를 설치하지 않는다. telemetry/update/remote-generation/sharing을 끄고 깨끗한 프로세스 환경, 별도 config/cache/log 디렉터리, no-cache/no-write/no-share를 사용한다. 이는 방화벽 격리를 뜻하지 않는다. 클라우드 로그인·웹 UI·모델 grader·redteam 생성은 쓰지 않는다. [공식 오프라인 설정](https://www.promptfoo.dev/docs/faq/#how-can-i-use-promptfoo-in-a-completely-offline-environment), [CLI](https://www.promptfoo.dev/docs/usage/command-line/), [연결 설정](https://www.promptfoo.dev/docs/providers/openai/#connection-settings), [latency 의미](https://www.promptfoo.dev/docs/configuration/expected-outputs/deterministic/#latency).

설치·schema 검사와 품질6건/도구2건씩 두 번의 결과·건별 latency를 보존했다. 모델 digest는 **품질 실행 중 관측부터 도구 평가 후 관측까지** 동일하며, 품질 시작 전 pin 관측은 없었다. [모델 관측 메타데이터](results/model-observation.json). 전체 결과·로그는 B의 private 증거로 보관하고 이 폴더에는 원문 없는 집계만 둔다. 작업 cache·임시 반입물의 최종 보존/정리는 부모의 전체 작업 마감 기록에서 확인한다.
