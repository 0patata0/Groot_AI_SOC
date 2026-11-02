# 단문 진단·도구 스키마·근거 검증 보완

2026-11-03 공통 하네스 `soc-chat-contract:1.5.14`를 Hermes와 Ollama 운영 경로에 반영했다. 두 봇의 운영 모델은 기존 `qwen3.6:35b`다. 학습본은 별도 후보로 보존하며 이번에는 가중치를 바꾸지 않았다. [현재 현황](../../STATUS.md) · [작은 검증 원장](diagnostic-harness-20261103.json).

| 문제 | 변경 | 확인 |
|---|---|---|
| `벡터 살아있어?`처럼 짧은 표현이 일반 질문으로 처리됨 | 알려진 서비스·호스트와 `살아있어`, `돌아가`, `돌고 있어`, `켜져` 등의 조회 의도를 연결. 실제 MCP enum의 대상만 제시 | 동일한 4개 질문에서 실제 대상 조회 2/4 → 4/4. 개념·번역·쓰기 요청과 기존 IDS 엔진 적재 조회 경로는 유지 |
| 변환 모델에서 전체 도구 목록을 보내면 HTTP 500 | 인자가 없는 Wazuh 도구 3개의 객체 스키마에 `properties: {}`를 명시 | 읽기 도구 32개와 이름을 그대로 유지. HF 미학습본·학습본 모두 기존 형태의 500을 재현하고 수정 후 해당 도구/전체 목록 요청은 200 |
| 실제 조회 없이 정상이라고 답하거나 오래된 성공을 재사용 | 정상·실행 중 주장에도 근거 검사. 도구 서버·대상·반환 SHA·최신 조회 결과를 결속하고 최신 실패가 이전 성공을 무효화 | 무조회·무관한 조회·다른 대상·실패·손상된 SHA·잘못된 서버·정상 주장 뒤의 별도 미확인 문구를 회귀 검사 |

분류기는 질문의 범위만 좁힌다. 도구 선택과 호출은 LLM이 수행하며, 사건 판단이나 변경 승인을 대신하지 않는다. 모호하거나 미지원인 대상의 상태를 임의로 정상으로 만들지 않는다. 등록 서비스에 대한 관측 검사를 보완한 것이며 모든 자연어의 의미를 완벽하게 판별한다는 보증은 아니다.

## 스키마 오류의 재현과 처리

실제 SDK 요청에서 다음 세 도구는 파라미터가 `{"type":"object"}`뿐이었다.

- `mcp__wazuh_ro__get_wazuh_cluster_health`
- `mcp__wazuh_ro__get_wazuh_remoted_stats`
- `mcp__wazuh_ro__get_wazuh_weekly_stats`

이 생략형은 MCP의 유효한 JSON Schema다. 설치된 Thor Ollama 0.40.2의 변환 모델 경로에서는 `JSON schema error at #: properties must be an object`가 재현됐다. 같은 요청에 빈 속성 객체를 명시하면 오류가 사라졌다. 내부에서 누락 값이 null 등으로 바뀌는 정확한 지점은 직접 계측하지 않았다. [공식 llama.cpp 검사](https://github.com/ggml-org/llama.cpp/blob/master/common/json-schema.cpp)와 [Ollama API의 도구 형식](https://github.com/ollama/ollama/blob/main/docs/api.md)을 참고했으며, 최신 문서를 설치 버전의 동작 증거로 대신하지 않고 실제 버전에서 별도 재현했다.

정규화는 공통 `chat_contract.normalized_schema()`를 사용한다. 기존 속성·required·명시적 제약과 호스트 제한은 보존한다. 모델에 새 인자나 도구를 추가하지 않으며 실제 호출은 기존 입력 검증과 MCP 권한 검사를 통과해야 한다. 문제 도구를 숨겨 관제 범위를 줄이는 방법은 사용하지 않았다.

## 검증 범위

| 구분 | 결과 | 의미 |
|---|---|---|
| 로컬 회귀 | Ollama 171 PASS, Hermes 380개 중 378 PASS/환경 2 skip | 신규 진단·스키마 검사 8개 포함 |
| 설치 경로 | 설치 계약 1 PASS, 독립 source bundle import 1 PASS | 기존 루트 `deploy.sh`의 소스 복사 경로에서 동작 |
| 스테이징 비교 | 같은 4개 질문 모두 실제 대상 조회 1회씩 성공. 중앙값 34.75 → 10.54초 | 기존 완료 표시 4건 중 2건은 실제 조회가 없었음. 채팅 게시 제외·작은 순차 표본 |
| 실제 추론 서버 | 2개 변환 모델 × 수정 전/후 단일 도구/후 전체 목록, 총 6조건 확인 | 스키마 수락 검사이며 의미 정확도나 MCP 실행 점수는 아님 |
| 최종 운영 소스 | Ollama 실행기 5건(원본 3·학습본 2), Hermes native 2건, 총 7건 정확한 대상의 실제 진단 MCP 1회씩 성공 | 새 독립 문맥, 보호 호출·채팅 게시 0 |
| 운영 상태 | 소스 4사본 SHA 일치, 두 봇 인증 heartbeat/worker 정상, 설정·모델·SOUL SHA 유지 | Hermes 1회 재시작, Ollama·review 소비자 각각 1회 stop/start |

Hermes gateway의 INFO alias 설치 문구는 관측하지 못했다. 시작 로그의 등록 거절·source pin 오류는 없었고, 재기동·파일 SHA·인증 heartbeat와 동일 운영 소스를 사용하는 별도 native 세션의 실제 MCP 호출을 확인했다. 06:58 보완 단위에서는 새 Mattermost 게시/UI 왕복을 시험하지 않았고 이후 실제 채널8건은 아래 후속 결과로 확인했다. 보호 쓰기·승인·공격 E2E, 장기 안정성 및 새 OS 전체 설치는 미시험이다. 이전 모델 비교 점수와 이번 하네스 보완 검증은 별도로 유지한다.

## 실제 채널 후속 검사 — 2026-11-03 07:30~07:35 KST

운영35B를 유지한 두 전용 채널에 새 짧은 질문6건과 같은 스레드의 `FW` 답변2건을 게시해8/8 기대 처리를 확인했다. 진단4건/전체 FW 조회2건은 각각 정확한 MCP1회, 대상 없는 룰 질문2건은 조회 없이 장비를 확인했다. native DB의 원글/세션/호출/결과와 Ollama durable job/report/reply를 실제 게시 글과 대조했다. 진행 표시6건·KST·범위·반환 SHA·봇 혼선0도 확인했다. FW는 기본 정책·NAT·Docker·커스텀을 포함한99규칙을 조회하고 요약/생략 범위를 명시했다.

게시 API 성공 후 최종 글 관측은 Hermes15.37~16.43초/Ollama3.39~7.70초(실조회 각3건)였다. 약1초 폴링·공유 자원·작은 순차 표본이며 모델 품질이나 전체 메신저 속도의 우위로 환산하지 않는다. 코드·설정·모델·서비스 재시작0, 기존 source/config/SOUL SHA와 heartbeat를 확인했다. 보호 쓰기·승인 시험은 하지 않았다. 실제 API 게시/갱신/응답은 검증했으나 브라우저 제어의 kernel assets 오류로 화면 표 렌더링은 시각 확인하지 못했다. [8건 원장·제한](diagnostic-chat-check-20261103.json).

## 설치·운영 반영과 복구

초기 설치 진입점은 루트 `deploy.sh` 하나다. 기존 Ollama source bundle은 공통 `harness.py`와 `chat_contract.py`를 복사하고, SIEM 설치는 Hermes 플러그인에 같은 파일을 `chat_harness.py`와 `chat_contract.py`로 배치한다. 새 패키지·이미지·키·설정 키·MCP·공개 수신 포트는 없다. 이번 운영 반영은 정확한 이전 SHA를 대조한 4파일 증분 교체였으며 초기 설치기로 운영 서버를 덮어쓰지 않았다.

B의 복구·증분 소스와 manifest는 root 전용 `/var/lib/capstone-harness-updates/20261103-r1`에 보존했다. 기존 소유권과 모드를 유지했고, 실행 중인 durable chat/review 작업이 없는 것을 확인한 뒤 반영했다. 12분 독립 복구 타이머는 배포 전에 만들고 7건 검증·연결 확인 후 해제했다. 실제 운영 원복은 실행하지 않았다.

승인된 root 운영자는 다음 명령으로 해당 변경만 복구할 수 있다.

```sh
python3 -B /var/lib/capstone-harness-updates/20261103-r1/rollback.py --manual
```

복구기는 현재 파일이 이번 배포 SHA일 때만 이전 파일을 복구한다. 다른 변경이 있으면 덮어쓰지 않고 `rollback-result.json`에 보존한 drift를 기록한다. 이를 LLM의 일반 sudo/Docker 도구로 위임하지 않는다. 복구 시 봇 소비자를 재기동하므로 운영자가 진행 중인 작업을 먼저 확인해야 한다.

시험용 모델 daemon·SSH forward·watchdog·격리 폴더는 종료/제거했고, 검증 근거와 소스는 root 전용 복구 경로에 남겼다. 모델 가중치·기존 복구본·학습 입력을 삭제하지 않았으며 Mac에는 패키지나 가중치를 다운로드하지 않았다.
