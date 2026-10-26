# B 호스트의 Ollama 기반 SOC 비교 실행부

> **10/26 카탈로그:** 읽기 전용은6서버28도구, Hermes 동등 권한은8서버37도구(보호9). SCA 조회를 두 봇에 공통 제공하며 새 listener·패키지는 없다. 초기 설치의 resp 연결은 읽기 모드에서 `list_blocks`만 노출하며 보호 동작은 계속 거절한다. [배포/검증](../../STATUS.md).

> **공동 채널:** `soc-review-agent`에서 @ollama 직접 요청과 양방향 검증을 지원한다. 직접 요청은 기존 동등 권한, 자동 조회/검증은 읽기 전용이다. 검증용 resp 혼합 카탈로그에서는 list_blocks만 노출한다. [사용법](../hermes/chat-channels.md) · [운영 검증](../../STATUS.md).

> **2026-10-26 채널/발신자 구분:** 공개 soc-ollama와 -ollama 채널, -agent 채널의 @ollama 멘션 및 기존 허용 DM을 지원한다. 두 봇 공통 접미사 동기화60초, 보고 발신자 soc-report 분리를 적용했다. [채널 규칙](../hermes/chat-channels.md) · [검증·미완료](../../STATUS.md).

> **2026-10-26:** 공통 계약1.4.0과37대상 진단 집계를 사용한다. 인증 WebSocket/worker·대기열 heartbeat와 조회 누락 검사를 추가했다. 첫 실채팅 시험에서 `soc:coverage` 선택 누락을 찾아 수정했으며 [검증 결과](../../STATUS.md)와 [독립 감시 범위](../mcp/monitoring.md)를 따른다.

> **2026-10-25 현행 공통 계약1.3.0:** 같은35B 모델의 읽기 선택에 장비별 항목·필터·한도를 함께 검증하고 여러 ID·제외 조건·이름 검색·규칙 개수 비교를 보완했다. 진단 미등록 대상은 실제 조회 없이 미지원으로 표시하며 다른 서비스를 대신 조회하지 않는다. 실제 반복 수치·보류 질문 평가·미완료 범위와 Git 상태는 [STATUS](../../STATUS.md), native 차이는 [공통 기준](../hermes/chat-harness.md)을 따른다.

> **당시 기록 — 2026-10-25 계약1.2.2:** 명확한 조회는 첫 단계부터 같은35B 모델의 JSON 선택을 검증한다. 다장비/복합 요구·진단 누락, 임의 필터·시간 기준 인자·반복, 정책 추측을 보완하고 대용량 감사 자료의 원문 SHA/집계/시간 정보를 보존한다.

> **2026-10-25 조회 수정:** 공통 부정문·특수 KST·장비 식별·누락 검사와 대용량 취약점 집계를 반영했다. 성공한 조회를 반복하지 않도록 범위를 좁히고, 미확인은 그대로 보고한다. 수집기 시간대 오류는 절대시각 미확인 처리로 제한하며 [공통 계약·한계](../hermes/chat-harness.md)와 [실측](../../STATUS.md)을 따른다.

> **당시 기록 — 2026-10-25 19:33 확장 조회 시험:** 신규6유형에서 핵심 완료0/6이며 많은 질문에서 실제 도구를 호출하지 않았다. 수집 통계는 C002 대신003을 선택했고 공통 열거 부정문 오분류로 최종 조회 결과도 유실됐다. 문구를 단순화한 에이전트 대조도0조회였다. 직접 MCP 조회는 가능하므로 도구 미설치와 에이전트의 실행/보고 실패를 구분한다. 이번은 설정 고정 시험이며 수정 배포하지 않았다. [상세·검증 한계](../../STATUS.md).

> **2026-10-25 공통 하네스 고정 24응답 재시험:** Ollama 읽기92.63/쓰기77.61, 가중83.62점(각1회)이다. 전체 진단7/25·18미조회, 다장비 WAF/IDS 주석 위치 불일치, 실패 후 성공 상태와 정책 거절 답변의 검사 오탐이 남았다. 기존 후보/상태를 검증한 추가 승인·적용·원복은 Codex의 개입이 있으며 모델 자율 점수에 합산하지 않는다. 운영 하네스·모델·권한 변경 없이 시험했고 상세/완료 상태는 [STATUS](../../STATUS.md)를 따른다.

> **2026-10-25 하네스 정렬:** 일반 채팅은 Hermes와 같은 `chat_contract.py`/공개 SOC 정책을 읽으며 추론off·temperature0·top_p0.95·출력2048을 적용한다. 같은 읽기 범위/근거 렌더러와 변경안 제출 근거 표를 공유하고, 일부 실패/미처리는 `partial`로 기록한다. native 재시도·세션/Memory·예산 카운터는 별도다. [공통 기준·배치 파일·한계](../hermes/chat-harness.md) · [라이브 검증](../../STATUS.md).

> **2026-10-25 쓰기 비교 결과:** 같은 모델/36도구에서6유형씩 시험했다. Ollama는 단일 WAF/IDS/Wazuh 정확 후보를 만들었지만3장비 진행상태 누락·복합 요청의 원복안 누락·원복 SHA 안내 오류가 남았다. 명시 부분 편집 안내·별도 원복 지시 후 정상 승인으로 WAF1행 적용/정확 원복 완료. 기존 controller 자동관리 이관은 하지 않는다. [비교·후속](../../STATUS.md).

> **2026-10-25 봇 식별:** `ollama`에는 공식 라마 아이콘, 기존 `hermes`에는 공식 앱 아이콘을 적용했다. 초기 채팅 설치도 동봉 자산을 사용한다. 모델/권한/실행부 설정과 별개이며 [현재 검증 상태](../../STATUS.md)를 따른다.


모델 추론은 기존 DGX Ollama에 두고, B에 `mcp-use 1.7.1` + `langchain-ollama 1.1.0` + 공식 Ollama Python SDK `0.6.3`을 별도 Python 3.12 venv로 설치한다. 이 구성은 **Ollama 클라이언트를 사용하는 에이전트 실행부**다. B에 Ollama 추론 daemon/CLI·모델 가중치를 설치하는 구성은 아니다. 실제 비교 결과와 현재 Git/검증 상태는 [STATUS](../../STATUS.md)를 따른다.

`B soc-ollama → DGX /api/chat → B의 MCP 호출 → DGX 최종 답변` 순서로 실행한다. host 프로세스여서 추가 Docker NIC가 없고 기존 Hermes와 직렬로 연결하지 않는다. 기존 자동 사건 관리 controller는 Hermes가 계속 맡는다. 별도 `ollama` 봇은 전용 채널/DM에서 조사와 승인형 변경안 준비를 수행할 수 있으며, 두 실행부가 같은 보호 MCP·승인 broker를 사용한다. 자동 사건 소비자를 추가해 같은 사건을 중복 처리하지 않는다. 두 라이브러리 환경의 MCP 버전(시험1.30/운영2.0)은 서로 섞지 않는다.

## 권한과 범위

- `soc-ollama`: nologin·자체 그룹만, sudo/Docker 권한 없음. 코드는 root 소유이며 계정이 수정할 수 없다. venv는 패키지 분리이며 OS sandbox는 아니다.
- 기본 설치 `read-only`는 5서버·26읽기다. 사용자가 허용한 현재 라이브 설정 `hermes-parity`는 **8서버·36도구(읽기27·보호9)**이며 Hermes와 이름/JSON Schema SHA가 전부 같다. 조회4종은 rule-a/b, 제안은 rule-write-a/b, 기존 차단/해제·목록은 resp가 담당한다.
- parity 모드는 Hermes가 사용하는 rulechg/resp의 제한된 SSH 키를 root 소유·전용 그룹 읽기로 연결한다. B 읽기 MCP에는 별도 강제 명령 키를 사용한다. host key 검증·포워딩 금지·기존 서버 강제 명령을 유지하며 일반 관리자 키/쉘/sudo/Docker 권한은 주지 않는다.
- 보호9개도 기존 정확 후보 승인·증거·보호 주소·임시 TTL 검사를 통과해야 한다. 모델이 승인하거나 서버 검증을 우회할 수 없다. 보호 호출 시작을 먼저 SQLite에 기록하고, 실행 중 재시작되면 결과 미확인으로 전달하며 자동 재실행하지 않는다. 같은 요청 내 동일 보호 인자도 중복 실행하지 않는다.
- 모델 호출 기본12회(허용1~16), 도구 기본32회(허용1~40). graph의 middleware 단계 예산은 별도로 `8×모델한도+16`이며 모델/도구 한도를 늘리지 않는다. 근거 정정 최대2회도 같은 총 예산을 쓴다. 읽기 MCP90초·보호720초, parity 첫 대화900초·정정180초·gateway1110초 상한이다. 이는 응답 목표 시간이 아닌 실패 상한이며 승인 대기를 포함한다.
- 모델 추론 off, temperature0, top_p0.95, 출력2048토큰. 외부 telemetry/tracing은 비활성화한다. 도구 호출은 직렬화하며 실제 실패와 미확인을 정상/0건으로 바꾸지 않는다.
- [harness.py](harness.py)는 Hermes의 canonical query-completion·soc_management_run 소스를 그대로 사용해 파일 SHA/집계·KST·근거 위반을 검사한다. 설치 시 `query_grounding.py`/`grounding.py`와 공통 `read_contract.py`/정책 소스를 복사하고 receipt SHA를 검증한다. 기본 규칙 범위3장비·IDS=A·시간/표본 범위를 안내하고, 부족한 조회/근거 오류를 최대2회 정정한 뒤 검증된 집계 또는 미확인 보고를 출력한다. 구형 Wazuh 텍스트 시각은 모델 전달 전에 KST 표시로 변환하되 원본/해시는 감사 기록에 보존한다.
- native 도구 호출이 멈추면 같은 모델의 JSON Schema 출력으로 허용된 **읽기** 도구/인자를 최대2회 선택하게 하고, 실제 MCP 스키마와 남은 예산을 검사한 뒤 호출한다. 도구를 고정 분기로 대신 호출하거나 보호 도구/승인을 생성하지 않는다. 선택도 실패하면 미확인으로 보고한다. [Ollama 공식 structured outputs](https://docs.ollama.com/capabilities/structured-outputs)와 설치된 ChatOllama 구현을 대조했다.
- IDS 단순 조회는 실제 running·health·현재 룰 경로·바이트 결합·SID 미확인을 함께 표시한다. 이벤트/진단은 실제 요청 구간·반환 표본·수집 상태를 그대로 렌더링한다. 전역 journal 전체/등록되지 않은 서비스/절대 시간 구간을 조회했다고 주장하지 않는다. 사건 위험·조치 판단을 고정 코드로 대신하지 않는다.
- 동일 사용자·동일 스레드의 완전한 실제 조회 근거만 표 재서식에 재사용한다. 단순 룰 목록은 모델이 선택해 호출한 파일을 SHA로 검증한 뒤 바로 렌더링하여 큰 원문을 다시 모델에 설명시키지 않는다. 새 스레드나 '현재/다시 조회' 요청에는 캐시를 사용하지 않는다. 과거 봇 문장/처리시간 footer는 사실 근거가 아니다. 과거 Memory 전체, 자동 사건 controller, 모든 운영 기능의 동등성은 아직 이관하지 않았다.

## 오프라인 반입과 초기 설치

신규 설치의 유일한 진입점은 루트 [deploy.sh](../../deploy.sh)다. [설정 예제](../../deployment/config.example.conf)의 `OLLAMA_TRIAL_ENABLE=1`, `OLLAMA_TRIAL_BUNDLE=/opt/capstone-prereqs/ollama-trial`을 지정한다. 기본값0이면 실행하지 않는다. Hermes와 같은 권한을 원하는 설치에는 `OLLAMA_TRIAL_ACCESS_MODE=hermes-parity`를 명시한다(기본 `read-only`). `--check`는 B 반입물을 검증하고 `--apply`는 SOC/진단 연결 뒤 내부 설치기를 호출한다. `--verify`는 실제 읽기 목록 발견까지 검사하며 모델 생성/채팅 게시를 수행하지 않는다. `OLLAMA_TRIAL_CHAT_ENABLE=1`을 함께 지정하면 봇/채널과 비특권 systemd gateway도 설치한다. 기본값0이며 기존 Hermes 채널 ID를 유지해 soc-hermes로 이름을 맞춘다. 새 3VM 전체 설치 시험은 별도 미검증이다.

반입 파일은 [offline-manifest.json](offline-manifest.json)의 정확한 파일명·버전·출처·크기·SHA-256을 사용한다. Linux CPython3.12 x86_64 wheel70개와 아래 deb3개다. B의 기존 Python 버전과 deb 의존성을 먼저 대조해야 하며 다른 Ubuntu/Python으로 그대로 확장하지 않는다.

| deb | 반입 버전 |
| --- | --- |
| python3.12-venv | 3.12.3-1ubuntu0.17 |
| python3-pip-whl | 24.0+dfsg-1ubuntu1.3 |
| python3-setuptools-whl | 68.1.2-2ubuntu1.2 |

```text
/opt/capstone-prereqs/ollama-trial/
  offline-manifest.json
  debs/       # 정확한 manifest의 deb3개
  wheels/     # 정확한 manifest의 wheel70개
```

root 소유·그룹/기타 쓰기 금지로 반입한다. 설치기는 추가 파일·symlink·해시 불일치를 거절한다. `dpkg -i`와 `pip --no-index --require-hashes --no-compile`만 사용하며 서버에서 다운로드하지 않는다. [requirements.lock](requirements.lock)은 전체 전이 의존성을 고정한다. manifest 동일성 검사는 공식 공급자 확인을 대신하지 않는다. 공식 Ubuntu 패키지 정보 및 PyPI 버전별 파일 해시와 대조한 출처를 manifest에 기록했다.

기존 운영 B에는 전체 초기 설치기를 실행하지 않고 관리자가 동일 [내부 구현](../../deployment/ollama_trial.py)의 제한된 증분 설치를 사용했다. 설치 receipt가 있으면 재설치하지 않고 검증하며 접근 모드 변경은 아래 증분 upgrade로 수행한다. 부분 설치는 자동 덮어쓰지 않고 검토를 요구한다. 운영 B의 bundle에는 재현·복구용 `source/`도 보존한다. Mac에는 패키지를 설치하지 않으며 반입·검증 후 이번 다운로드/임시 생성물만 삭제한다.

## 실행

관리자가 B에서 호출한다. wrapper가 비특권 계정으로 낮춘 뒤 실행하며 JSON 결과는 stdout, 라이브러리 로그는 stderr에 기록한다. 질문을 보낸다고 Mattermost에 게시되지는 않는다.

```bash
sudo /usr/local/sbin/capstone-ollama-trial <<'JSON'
{"question":"현재 IDS 상태를 실제 조회하고 개별 SID 적재 확인 여부를 구분해줘.","tools":["mcp__rule_a__get_service_action_target","mcp__rule_b__get_service_action_target"]}
JSON
```

`tools`를 생략하면 root 설정의 권한(현재 parity36개) 안에서 단순 룰/IDS/이벤트/전체 서비스 진단을 해당 읽기 도구로 좁힌다. 변경안 요청에는 기존 보호 도구를 유지하며 분류기가 도구를 대신 호출하거나 사건 조치를 결정하지 않는다. 초기 SDK 비교에는 두 실행부에 동일한5개만 노출했으며 현재 채팅과 조건이 다르다. `{"discover_only":true}`는 모델/보호 호출 없이 선택 모드의 이름/스키마를 확인한다. `calls`에 실제 인자·결과·소요시간, `model_calls`에 생성시간/토큰과 Ollama native 메타데이터, `final_response`에 최종 답변이 나온다. 상세 결과에는 운영 데이터가 있으므로 로컬 전용 검증 기록으로 보관한다.

## 비교 방법과 한계

[hermes_benchmark.py](hermes_benchmark.py)는 기존 Hermes 이미지의 SDK를 새 임시 HERMES_HOME에서 사용한다. 현재 라이브 UID995·DGX 주소·모델에 맞춘 운영자 시험 어댑터이며 범용 실행 진입점이 아니다. 일반 채널 gateway와 운영 Memory/플러그인/DB를 사용하지 않는다. 두 실행부에 같은 한국어 시스템 지시·질문·5개 읽기 도구·모델·출력/추론 옵션을 적용하고 매회 새 대화로 시험한다. 실행 순서를 교대하며 모델 unload나 DGX 설정 변경을 하지 않는다.

시간 계산·IDS 상태·장비별 파일 룰 집계를 각각 반복하고, 생성 완료 여부와 별개로 인자·실제 조회값·KST·파일/엔진 구분을 검토한다. 모델 cold-load 예비 시험과 계측 코드 실패는 별도 기록한다. 프로그램 시작/연결을 포함한 전체 시간과 준비된 대화 처리 시간을 구분한다. Hermes는 전체 API 단계(스트림 소비 포함), 후보는 LangChain 완료 callback과 native duration을 기록한다. 내부 시간 범위가 완전히 같지는 않으므로 전체/대화 wall time을 비교 기준으로 사용한다.

이 결과는 **두 읽기 SDK 구성의 비교**이며 현재 운영 채팅 최종 게시 시간, 다중 사용자 부하, 동일 전체 기능의 우열을 뜻하지 않는다. 이후 채팅 하네스·권한 동등화와 새 스레드 실측을 추가했다. 보호 승인/TTL의 실제 성공 E2E, 자동 관리 controller·Memory 전체 동등성은 여전히 별도 미검증이다. 최신 결과는 STATUS를 따른다.

## Mattermost에서 직접 시험

현재 봇 이름은 `ollama`, 채널은 [soc-ollama](https://chat.grootlab.duckdns.org/soc/channels/soc-ollama)다. 기존 `soc-agent`는 ID·이력을 유지한 [soc-hermes](https://chat.grootlab.duckdns.org/soc/channels/soc-hermes)로 변경했다. 새 채널은 기존 관리자와 Ollama 봇만 참여하는 비공개 채널이며 Hermes는 참여하지 않는다. 멘션 없이 질문하고 같은 스레드에서 후속 질문을 이어간다. `ollama`와의 DM도 사용할 수 있다. 현재 관리자 ID만 허용하며 다른 봇·시스템 글·이전 글·다른 채널 요청은 실행하지 않는다.

`capstone-ollama-chat.service`가 같은 host venv의 [chat.py](chat.py)를 soc-ollama 계정으로 실행한다. 기존 B Mattermost의 호스트 바인딩 주소8065에 HTTP/WebSocket으로 연결하며 새 수신 포트/NIC는 없다. 설치기는 관리자 자격을 보내기 전에 주소가 이 호스트에 할당된 IP인지 검사한다. 봇 토큰은 root 소유0640 설정에서만 읽으며 모델/로그/Git에 전달하지 않는다. 시스템 관리자 역할이나 전체 채널 게시 권한을 주지 않는다. ProtectSystem=strict·NoNewPrivileges·전용 상태 경로 쓰기와1GiB 메모리/128task 제한을 적용한다.

새 요청에는 같은 스레드의 처리 중 답변 하나를 만들고 완료 결과로 갱신한다. 답변 하단에 KST·처리시간을 표시한다. 스레드 또는 DM의 최근10개/8,000자 내 문맥만 사용하고 현재 상태는 다시 조회하도록 지시한다. 새 채널 스레드는 이전 스레드와 섞지 않는다. 현재36도구 권한에서 단순 읽기는 필요한 도구/대상으로 좁히므로 위의5도구 SDK 비교 수치와 실제 채팅 시간이 같다고 단정하지 않는다. 새 스레드 실제 시험은 API 최종게시시각과 WebSocket 수신·실제 MCP 결과를 대조한다.

중복 이벤트는 SQLite로 제거하고 모델 완료 결과를 저장한 뒤 전달을 재시도한다. WebSocket 재연결 시 소속 채널/DM의 최근60글을 확인한다. 장시간 단절로60글을 넘는 이력과 신규 DM 재발견의 모든 경우를 보장하지 않는다. POST 응답이 불명확하면 스레드의 원본 요청 ID를 대조하며 무조건 재게시하지 않는다. 불명확한 요청은 로그 확인 후 새로 질문할 수 있다. 그룹 DM·첨부/이미지 분석·메시지 수정에 따른 자동 재생성·전체 세션 이관은 범위 밖이다.

연결 검사 `chat.py --check`는 봇 신원·채널·WebSocket hello만 확인하며 게시/모델 요청0이다. 실제 게시 왕복은 사용자가 허용한 socadmin 질문으로 별도 확인했으며 결과는 STATUS에 기록한다. [공식 봇 계정](https://docs.mattermost.com/developers/integrate/reference/bot-accounts) · [WebSocket API](https://docs.mattermost.com/api/reference/mattermost-api).

## 기존 서버 증분 갱신

운영 중인 전체 초기 설치기를 다시 실행하지 않는다. root 소유 소스에 이번 버전과 canonical Hermes 두 파일을 함께 반입한 뒤, 진행 중인 새 봇 요청이 없는 시점에 실행한다.

```bash
sudo python3 -I -B /opt/capstone-prereqs/ollama-trial/source/deployment/ollama_trial.py upgrade \
  --source-root /opt/capstone-prereqs/ollama-trial/source \
  --hermes-home /opt/hermes-data --access-mode hermes-parity
```

설치기는 기존 root 소스/설정·소유권 정보를 `/var/backups/capstone-ollama-*`에 보관하고 새 gateway만 멈춰 갱신·36도구 발견·pip check 후 다시 시작한다. 검증 실패 시 이전 소스/설정/소유권을 복원하고 이번에 생성한 파일만 제거한다. 기존 Hermes 서비스·관리 설정을 변경하지 않는다. 이번 하네스 갱신에는 추가 wheel/deb가 필요 없으며 기존 manifest/lock을 유지한다. 운영 복구 bundle의 source와 receipt도 같이 맞춘다.

## 중지·복구

CLI 자체는 상주하지 않는다. 채팅을 켠 경우 관리자가 `systemctl disable --now capstone-ollama-chat.service`로 새 요청 처리를 중지할 수 있다. 기존 Hermes는 계속 사용한다. 봇 제거 시 정확한 chat receipt의 토큰을 폐기하고 해당 봇만 비활성화한다. 채널/대화 이력을 임의 삭제하지 않는다. 채널 이름을 복구하려면 같은 기존 채널 ID의 이름만 soc-agent로 변경한다. unit·chat 설정/소스를 제거한 뒤 daemon-reload하며 전용 SQLite 기록은 보존/제거 여부를 따로 결정한다. 완전 제거 시 관리자는 실행 중인 시험이 없음을 확인하고 receipt의 `registered_public_key`와 정확히 일치하는 **이번 키 한 줄만** B MCP authorized_keys에서 제거한다. `authorized_keys.before` 전체 복원으로 이후 정상 키를 덮어쓰면 안 된다.

이후 시험 wrapper, `/opt/capstone-ollama-trial`, `/etc/capstone-ollama-trial`, 전용 STATE/계정과 선택적 복구 bundle을 해당 경로만 검토하여 정리한다. 기존 ruleview 키 등록·Hermes·MCP 서비스는 삭제하지 않는다. deb3개는 다른 프로그램이 사용할 수 있으므로 자동 제거하지 않는다. 제거 절차의 실제 실행은 아직 검증하지 않았다.

## 검증

```bash
python3 -B -m unittest discover -s infra/ollama-trial -p 'test_*.py'
python3 -B -m unittest discover -s deployment/tests -p 'test_controller.py'
```

정책/반입물/JSON 출력 검사와 배포 분기 검사는 실제 신규 서버 설치를 대신하지 않는다. 실제 운영 설치·MCP 호출·자연어 비교·보류 범위를 [STATUS](../../STATUS.md)에 구분한다.
