# MCP 계층 — 에이전트/LLM 교체가 쉬운 구조 (pluggable agent)

> **2026-10-25 06:23 KST Ollama 병행 시험 적용:** 같은 B host venv에 Ollama SDK+mcp-use 실행부를 설치했다. 모델은 Hermes와 같은 DGX qwen3.6:35b. `ollama` 봇의 `soc-ollama` 채널/DM을 활성화하고 기존 soc-agent는 이력/ID를 유지해 `soc-hermes`로 이름을 바꿨다. 읽기26도구·별도 비특권 gateway만 추가하며 기존 관리/승인은 Hermes가 담당한다. 18회 SDK 비교에서 후보가 빠른 표본을 얻었으나 실제 채팅 게시시간/전체 기능 동등성·완전한 정확도는 미검증이다. [사용·설치·복구](../ollama-trial/README.md) · [결과/한계/Git 상태](../../STATUS.md).


## 2026-10-25 Ollama 실제 왕복·기존 코드 재사용 후보

DGX Ollama native `/api/chat`→모델의 도구 선택→SSH MCP 실행→결과를 받은 최종 답변까지 읽기2건을 확인했다. 기존8서버/36도구 스키마는 불변이고 고유 alias36개를 검증했다. 실제 모델에 제시한 도구는 Suricata 서비스 조회와 시간 계산2종뿐이다. 앞선 표준 SDK 연결 시험에서 진전한 범위이며, 전체36도구 선택·보호 변경·Mattermost·세션/관리 작업을 새 실행부로 대체한 결과는 아니다. 이번 코드는 임시 검증용으로 정리했고 운영에 설치하지 않았다. 실측·의존성·미검증 항목은 [STATUS](../../STATUS.md)를 기준으로 한다.

### 어디까지 기존 제품으로 줄일 수 있는가

다음은 **문서/공개 소스 검토에 따른 후보**다. 라이브에서 해당 프레임워크를 설치·실행하거나 속도를 비교한 것은 아니다. MCP 서버는 기능을 제공하고, MCP 클라이언트/에이전트 프레임워크는 연결·선택·실행 루프를 맡는다. 양쪽을 구분해 선택한다.

| 후보 | 대체할 수 있는 코드 | 현재 환경의 적용 조건·판단 |
| --- | --- | --- |
| mcp-use Python + ChatOllama | MCP 연결/발견·도구 변환·모델 호출과 도구 실행 반복 | 우선 비교 후보. stdio command/args로 기존 SSH 연결을 구성할 수 있다는 문서상 근거가 있다. ChatOllama는 Ollama SDK로 native 채팅을 호출한다. Python1.7.1 선언은 MCP>=1.24,<2이므로 현재 운영 MCP2와 별도 환경 필요; 통신 호환은 별도 시험 |
| mcp-use TypeScript v2 | native Ollama `/api/chat`·MCP 실행 루프 | Python 의존성 충돌을 피할 대안. 확인한 소스의 Ollama provider가 native API를 호출한다. Node 런타임/패키지 고정과 기존 Python 관리·출력 검사 연결은 추가 필요 |
| 공식 Knowledge Graph Memory MCP | 사실·관계·관측의 영속 저장/검색/삭제 | 선택 도입 후보. 로컬 JSONL 기억이며 대화 스레드/재시작 복원·출처/유효기간 판정·현재 상태 재조회는 별도. 추가 도구/왕복이 생기므로 속도 개선 목적으로 무조건 추가하지 않음 |
| fast-agent | 다중 MCP 연결·에이전트 실행 | stdio 지원. 문서의 Ollama 연결은 generic OpenAI-compatible `/v1`이므로 native API 비교 후보와 구분. 현재 SOC 승인/관리·채팅 이관은 별도 |
| MCPHost (mark3labs) | 도구 발견/필터·실행 루프·비대화형 실행, Go 바이너리 반입 | 저장소 archived=true를 확인해 새 운영 도입 우선 제외. main632cc196의 Ollama 생성 경로는 `/v1`이며 사전 적재/fallback 로직도 있음. 이름에 Ollama 지원이 있어도 native 생성 경로라는 뜻은 아님 |
| Mattermost 공식 MCP / Agents | 메시지 조회·검색·게시 API 도구 | 현재 Team11.11.1에 즉시 호환이라고 확정하지 않음. 최신 Agents 일반 요구 v12+, MCP endpoint 절 v11.2+를 구분하고 실제 플러그인 버전을 고정해야 함. 문서상 외부 MCP/상태 변경 도구의 Enterprise 이상 조건과 Streamable HTTP/OAuth 또는 PAT 검토 필요 |
| 커뮤니티 mattermost-mcp-host | Mattermost WebSocket 수신·스레드 문맥·MCP 연결의 참고 구현 | 확인한 main64731f2의 주 실행부가 AzureChatOpenAI를 직접 생성함. 별도 ollama-mcp-server 디렉터리가 있어도 주 에이전트의 DGX Ollama 호환을 뜻하지 않음. 수정 없는 대체품으로 채택하지 않음 |

공식 근거: [mcp-use Python LLM](https://docs.mcp-use.com/python/agent/llm-integration) · [stdio 설정](https://docs.mcp-use.com/python/client/client-configuration) · [Python 의존성 선언](https://github.com/mcp-use/mcp-use/blob/f877f789e7b4979e62e5cbe221bfb29ebb86d1bd/libraries/python/pyproject.toml) · [ChatOllama 구현](https://github.com/langchain-ai/langchain/blob/master/libs/partners/ollama/langchain_ollama/chat_models.py) · [TypeScript provider](https://github.com/mcp-use/mcp-use/blob/f877f789e7b4979e62e5cbe221bfb29ebb86d1bd/libraries/typescript/packages/agent/src/llm/providers/ollama/index.ts) · [Memory MCP](https://github.com/modelcontextprotocol/servers/blob/main/src/memory/README.md) · [fast-agent provider](https://fast-agent.ai/models/providers/additional/) · [fast-agent stdio](https://fast-agent.ai/mcp/client-servers/) · [MCPHost 상태](https://github.com/mark3labs/mcphost) / [provider 소스](https://github.com/mark3labs/mcphost/blob/632cc196002275d42dbf93ad3f1241ff853deb80/internal/models/providers.go) · [Mattermost 공식 조건](https://docs.mattermost.com/administration-guide/configure/agents-admin-guide) · [커뮤니티 host 실제 LLM](https://github.com/jagan-shanmugam/mattermost-mcp-host/blob/64731f22558b9ccfd7f965b2e0269f2e0e60b97f/src/mattermost_mcp_host/agent/llm_agent.py).

### 추가로 필요한 환경과 유지할 프로젝트 코드

**별도 환경의 위치:** 같은 B 서버 안의 별도 컨테이너 또는 Python 가상환경을 의미한다. 다른 물리 서버/VM을 마련할 필요는 없다. 기존 Hermes의 패키지와 시험 실행부의 패키지·설정·기억 경로를 분리하고, 모델 추론은 두 환경 모두 DGX Ollama를 이용한다. 기존 MCP 서버도 재사용한다. venv는 패키지 분리이며 OS 권한 격리를 대신하지 않으므로 SSH 키·도구/승인 제한은 별도로 적용한다. 아직 어느 방식도 새로 설치하지 않았다.

- 기존 SOC 조회/제안36도구를 위해 새로운 범용 MCP 서버를 추가할 필요는 없다. 현재의 `calculate_time`도 재사용한다. 서버/계정별 키·known_hosts·ForceCommand·도구 이름/target enum·타임아웃·관리 allowlist를 새 클라이언트에 정확히 연결해야 한다.
- 기존 컨테이너의 MCP/httpx/aiohttp/PyYAML/jsonschema 및 전이41패키지 조건 충족을 확인했다. regex2026.9.29는 별도 CPython3.13 경로에 있다. 독립 Python3.12 환경을 택하면 venv 및 그 ABI의 wheel을 따로 준비한다. 이 목록은 완성된 오프라인 lock이 아니다. REST 직결에는 Ollama CLI/SDK/로컬 추론 daemon이 필수는 아니지만 ChatOllama를 택하면 langchain-ollama와 Ollama SDK 등의 전이 의존성이 추가된다.
- Memory MCP를 택하면 Node/npm 패키지와 지정 데이터 경로를 준비한다. 컨테이너에는 Node/npm이 있지만 호스트 PATH에는 없었다. 기존 Hermes Memory를 자동 공유하거나 대체하지 않는다. 공식 예시의 온라인 npx/pip/go install을 폐쇄망 서버에서 그대로 실행하지 않고 버전·출처·해시·전체 의존성을 고정해 오프라인 반입한다. 기존 운영 가상환경을 다운그레이드하지 않는다.
- `soc_management_controller.py`는 Hermes CLI/stream-json/세션 복원을 호출하고 `soc_management_run.py`는 AIAgent·도구·출력 hook을 사용한다. 프레임워크를 도입해도 관리 사건→새 실행부→구조화 결과/영속 보고 연결이 필요하다. Mattermost MCP의 조회/게시 도구만으로 채팅 이벤트 수신·스레드 격리·재시도까지 자동 구현되는 것은 아니다. 공식 Mattermost standalone stdio 실행은 문서상 개발용이며 운영 권장 경로는 plugin embedded/HTTP다.
- LLM의 조사/변경안 준비를 유지하고 정확 후보 승인·보호 주소·TTL·worker·KST/근거/한국어 검사를 이어야 한다. 일반 MCP 승인 확인창을 기존 승인 브로커의 동등 구현으로 보지 않는다. 범용 shell/파일/Docker 도구·프레임워크 code execution·외부 텔레메트리/추적·무제한 반복을 기본으로 추가하지 않고, 필요한 기존 도구만 제한하고 요청 예산을 고정한다.

추후 별도 실행부를 도입한다면 먼저 읽기 전용으로 이름 충돌7종/36스키마·프로토콜·오류/제한을 시험하고, 같은 모델·문맥·도구 노출·추론 정책·캐시 조건에서 정확도/질문→게시 시간을 반복 비교한다. 별도 Memory와 관리 사건 소비 경로를 사용해 이중 게시/이중 적용을 막는다. 실제 설치 시 루트 deploy.sh·설정 예제·오프라인 목록·검증/복구를 함께 갱신한다. 이번에는 설치·새 서비스/포트·승인 생성·채팅 게시·운영 교체가 없다.

> **원격 연결안 정정:** B Ollama 클라이언트→DGX Ollama는 가능하며 B의 모델용 자원 부족으로 배제하지 않는다. 기존 MCP 서버와 승인 계층을 재사용할 수 있지만 MCP 도구 실행/결과 전달·채팅/기억·관리 흐름을 맡는 실행부가 필요하다. 현 Hermes보다 빠른지는 동등 기능 비교 전에는 확정하지 않는다. [STATUS](../../STATUS.md).

> **2026-10-25 서버 적합성 후속:** B의 4 vCPU/15.62GiB·계산 GPU 미노출과 현재35B 파일21.07GiB를 확인해 **B Hermes + DGX Ollama 유지**를 권고한다. 기존 MCP는 호환 클라이언트로 재사용 가능하지만 Ollama 설치만으로 Mattermost·기억·정확 승인·LLM 관리 실행이 자동 이관되지는 않는다. 이 프로젝트의 승인/TTL 통제는 외부 MCP·브로커·worker와 함께 보존해야 한다. 별도 실행부의 동등 기능/속도 비교는 미실행이다. [비교 결과](../../STATUS.md).

## 2026-10-25 에이전트 교체 시 호환 경계

운영의일반/관리8MCP는모두SSH stdio다. 기존컨테이너의Python환경에서Hermes에이전트없이표준MCP SDK로36도구발견과Suricata상태·KST계산2읽기를확인했다. 서버를재사용할근거이며Ollama자체나신규에이전트의전체운영호환시험은아니다.

| 항목 | 교체 시 요구 |
| --- | --- |
| 연결 | MCP initialize/list_tools/call_tool,SSH subprocess/stdin/stdout,기존UID·키·known_hosts·ForceCommand·시간제한 |
| 도구 매핑 | A/B에같은bare이름7종존재.서버별이름/target enum을보존하고자동으로한쪽에합치지않음 |
| 권한 | ruleview조회/rulechg제안·resp권한분리,관리gate의직접차단제외,승인/보호주소/TTL·worker검증유지 |
| 결과 | 호출ID/오류/타임아웃·KST파생값·원본해시/관측범위·최종저장/알림의동일성 |
| SOC 실행 | LLM조사·판단·변경안작성주도,정확승인후적용확인·영속사건큐/실패보고보존 |

Ollama의function calling은도구선택을출력하지만현재MCP접속/실행과Mattermost·관리/승인흐름은클라이언트측이이어받아야한다. [Ollama 도구 호출](https://docs.ollama.com/capabilities/tool-calling) · [MCP 클라이언트](https://modelcontextprotocol.io/docs/2026-07-28/develop/build-client). 현재서버에Ollama를설치하는배치안이라도이실행부의설계·검증이추가로필요하다. 최신실측/미실행범위는 [STATUS](../../STATUS.md).

> **2026-10-25 KST 조회 표현:** A/B의 공통 룰 MCP 읽기 응답에 `time_display`(KST·경과값)를 추가했다. 해시 대상 `observation`·원본 내용·승인 SHA는 그대로다. 기존 진단 MCP의 순수 `calculate_time`은 서버 조회/정상 판정 증거와 분리한다. [시간 계산 계약](system-diagnostics.md) · [운영 검증](../../STATUS.md).

> **2026-10-24 KST/진단 후속:** 승인 카드의 시작/만료 시각은 KST로 표시하며 원본 계획·해시는 그대로 유지한다. 진단 범위 오류는 허용 수치를 반환하고 실제mcp계정의 거절/정정 조회를 확인했다. 최신 배포·검증은 [STATUS](../../STATUS.md).

> **2026-10-24 현재 구동 근거 보완:** `get_rule_change_target(a:suricata-local)`의 runtime은 기존 검증을 통과한 rule_source_path(`/rules/all.rules`), 정확 ET+local 결합 여부/SHA·관측 epoch를 반환한다. `get_service_action_target(a:suricata)`도 동일 canonical reader의 rule_source_evidence를 사용하며 승인용 observation/base_state_sha256은 유지한다. 컨테이너 ID 불일치/읽기 실패는 미확인으로 남긴다. per-SID 적재 미검증 플래그는 계속 false다. 새 도구/권한/포트는 없다. [실제 재시험과 남은 오류](../../STATUS.md) · [검증](../hermes/natural-chat-memory-validation-20261024.json).

## 현행 조회·변경 기능 소유 — 2026-10-25

같은 조회는 읽기 전용 경로에서만 제공한다. 실제 파일 읽기/집계 구현은 공통 root helper를 재사용하지만 SSH 계정·개인키·sudo 인자·MCP 목록·실행 허용은 분리한다.

| 경로 | 계정 / 기능 |
| --- | --- |
| rule-a / rule-b | 독립 키의 ruleview. get_rule_change_target, get_rule_change_status, get_service_action_target, get_operation_status만 제공 |
| rule-write-a / rule-write-b | 기존 rulechg. propose_rule_edit, propose_rule_change, propose_service_action. A만 temporarily_contain_ip 추가 |
| wazuh-ro | 기존14개 Wazuh API 조회. 전체 룰 요약은 로컬 파일 목록과 다른 범위 |
| security-events / system-diagnostics | 정제 이벤트2종 / 고정 systemd 진단과 순수 시간 계산2종. 승인 상태 SHA를 얻는 실시간 서비스 조회와 구별 |
| resp | 기존 list_blocks 및 승인형 block_ip/unblock_ip. 관리 gate는 직접 block/unblock 제외 |

총8논리 MCP/36도구이며 서버 VM을 추가하지 않는다. 기존6개 중 혼합 rule-a/b를 조회/제안 경로로 나눴다. 같은 호스트의 조회/제안 목록은 서로 겹치지 않고 target enum도 자기 장비만 포함한다. B에 미지원 임시 차단을 안내하지 않는다. 조회 요청을 변경 서버로 보내거나 읽기 경로에 제안을 위조하면 거부한다. ruleview sudo는 `rule-change-executor --read-only`만 허용하고 해당 모드는 모든 변경/worker/사건 등록을 거부한다. 파일/SHA 조회·모든 판단 없는 집계는 이전 명칭을 유지하므로 실제 도구 근거 검증과 이전 조회의 표 재정리 연결을 보존한다.

LLM은 먼저 읽기 도구로 증거·정확 SHA/현재 상태를 얻고 필요하면 같은 장비의 rule-write 경로로 구체 승인안을 준비한다. 조사 후 별도 재지시를 기다리지 않는다. 정확 후보 승인·지정 worker, 긴급 차단의 LLM 조사·증거/보호 주소·TTL을 유지하며 일반 sudo/Docker/패키지 설치 권한은 제공하지 않는다. 원인 분석 이후 기존 변경안 준비 도구 보존과 단순 조회 제한은 query1.3.1을 그대로 사용한다.

신규 설치는 루트 deploy.sh가 독립 키 생성/전달과 양쪽 읽기 계정·공통 helper·정책·normal/management 설정을 연결한다. 내부 rule_readonly_install.py는 사용자 진입점이 아니다. 새 오프라인 패키지·이미지·포트가 없으며 기존 서버에는 초기 설치기를 재실행하지 않는다. 운영 이관은 root 백업·유휴 확인·현재 정책 참조 동기화 뒤 같은 Hermes CID를 재기동했다. 영수증은 작업 JSON 폴더 밖 `/var/lib/capstone-mcp-unify`에 보관한다.

859회귀·실제8서버 SDK/35스키마·파일3/서비스2 읽기·교차 경계7거절·root경계6거절과 worker 후속 성공을 확인했다. 파일 정의10/14/19는 전체 엔진 활성 룰 수를 뜻하지 않는다. 이번 모델 새 응답·실제 채팅/공격/승인/차단E2E·새 VM 전체 설치 시험은 별도다. [검증](role-consolidation-validation-20261024.json) · [최신 현황](../../STATUS.md). 아래 배포 이력은 당시의 범위다.

> LLM 진단·알림 추가 보완: 종료 종류/실제 종료값 구분, 상태 표지의 모델 정정, 룰 표 제목 오탐 수정과 run별 영속 보고 재전송을 적용했다. 확인한 DGX/Qwen 사건 관리 요청은 지원되는 reasoning_effort=medium을 사용한다. 일반 채팅 설정과 승인/도구 권한은 유지한다. 실제 SOC Alerts의 표시된 fixture2건은 설치된 전달 큐/함수와 기존 webhook을 거쳐 저장·API 재조회·WebSocket 수신을 확인했다. 실제 검증·한계는 [STATUS](../../STATUS.md) 최상단을 따른다.

> 이전 보완 이력(2026-10-24 08:13 기준): 오프라인 host 패치, 기존 Java/관리망 격리, root 승인 진입점과 검증 TLS8444/8445를 적용했다. A 필수 컨테이너는 always로 재부팅 복구하며 실습/백업의 중지 상태는 보존한다. LLM 최종5질문은 맞는 도구12읽기를 완료했고 해석 불일치/상태 표지 누락2건은 검토 필요로 남겼다. 상세 포트·권한·새 설치/기존 이관과 검증 범위는 [설치 안내](../../deployment/bootstrap-guide.md) 및 [STATUS](../../STATUS.md)를 따른다.

## 조회와 승인형 변경 MCP의 역할

`rule_a/rule_b`는 고정 룰 파일 원문·SHA·실행 대상 상태를 조회하고 정확 후보 변경의 승인을 요청한다. 같은 파일의 변경 기준과 조회 근거를 함께 제공한다. `wazuh_ro`는 에이전트/클러스터·경보/룰 요약 등을, `security_events`는 정제된 IDS/WAF 이벤트를, `system_diagnostics`는 고정 대상 진단을 읽는다. Wazuh의 룰 요약은 세 장비 로컬 파일 원문·해시나 엔진 개별 적재 증명과 같지 않다. `resp`의 차단 목록 읽기와 보호된 대응도 별도 범위다. 이 논리 MCP6개를 각각 별도VM으로 세지 않는다.

단순 조회가 룰 관리 MCP의 getter를 사용한다고 다른 읽기 MCP가 불필요해지는 것은 아니다. 모델에는 요청에 필요한 읽기 목록을 좁혀 제시하되, 서버의 쓰기 거절·정확 승인·증거/TTL 검증은 별도로 유지한다. 현재 일반 채팅 보완의 범위·미완료는 [STATUS](../../STATUS.md)와 [조회 플러그인](../hermes/query-completion/README.md)을 따른다. 이 설명은 MCP 제거/통합이나 새 권한 위임을 뜻하지 않는다.

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../STATUS.md) · [실행 계획](../../PLAN.md).
> 현재 구성은 MCP6서버와 고정 진단25대상이다. 자연어 도구 선택·무근거 완료/SILENT 알림 보완의 실제 검증 상태는 STATUS 최상단을 따른다. 정확 후보 승인과 일반 sudo/Docker/임의 shell 금지는 유지한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

## 2026-10-24 08:13 보완 당시 이력

사건 관리의 읽기0·실제 인자 거절·알려진 근거 불일치에는 각1회 제한된 재시도를 사용한다. 현재 원본 요청과 KST를 재명시하고 모델이 기존26개 읽기 중 필요한 도구/인자를 선택한다. 해당 Ollama 경로의 재조회1회만 기본 thinking 정책을 사용하며 전역 설정/권한/기존12턴·180초·210초 한도는 유지한다. 성공한 읽기만 관측으로 세고 무관한 조회로 경보 값을 채우지 못하게 한다. 남은 범위 불일치는 실제 수량·시간·SHA와 needs_review로 보고하며 모든 모델 문장의 정확성을 보장하지 않는다. 상태 표지는 언어변환 전 모델 결론을 유지하고 누락은 검토 필요다.

진단은 요청 끝/시작·관측시각·오류 표본/전체 건수 미확인을 구분한다. 이벤트는 동일 절대UTC 양끝으로 색인 경보를 조회하며 KST 요청 구간·반환 표본·전체unknown을 반환한다. 진단/이벤트 limit은50 이하다. 룰 정의의 runtime_load_verified=false는 실제 엔진 적재 미확인이다. resp는 root 전용 설정의 고정 MCP만 sudo 실행하며 하위 helper 직접 실행을 거절한다. A의 승인 전송은 검증된 HTTPS8445, B의 같은 호스트 브로커는 loopback8090이다. 최종 SDK6서버/7읽기와 봇API/WebSocket을 확인했고 관리 timer를 원래대로 복원했다. 공격·보호쓰기 E2E는 미실행이다.

## 2026-10-24 보완 전 실제 조회·점검 이력

후속 보안·LLM 점검에서는 UID995의6서버 initialize/list와 이벤트2종 직접 조회가 성공했으나, 같은 읽기26도구를 제공한 자연어 이벤트 요청2건은 호출0회였다. 진단/룰/agent·차단목록 요청3건에서는 실제7회 조회했다. 룰의 `runtime_load_verified=false`를 확인 완료로 뒤집는 답변 등 해석 오류도 있어 SDK 연결·모델 선택·답변 정확도를 각각 구분한다. A의 기존 응답 계정과 신규 설치기의 root 승인 wrapper 차이 역시 별도 최소 이관 과제이며 이번 점검에서 sudoers나 운영 권한을 변경하지 않았다. 상세 결과는 [STATUS](../../STATUS.md) 최상단을 따른다.

Hermes UID995의 SDK로6서버 initialize/list를 다시 확인했다. 서버가 제공한 도구는 Wazuh14·security-events2·resp3·rule-a8·rule-b8·system-diagnostics1이며, 관리 CLI에 실제 제공하는 도구와 구분한다. verify는 읽기26개, manage는 기존 승인 제안 등 허용 목록만 제공하고 legacy resp 쓰기를 직접 노출하지 않는다. constructor 이후 재구성된 도구도 매 요청에서 다시 제한한다.

세 고정 룰 대상의 현재 파일 정의는 WAF10·Suricata14(로컬12/ET override2)·Wazuh19(level0 포함)개였다. 이 값은 해당 파일 바이트/SHA의 정의 수이며 전체 CRS/ET/Wazuh·엔진 적재 수나 실제 발화 수가 아니다. 고정 진단은KST 시각·반환 표본 수·요청 구간 전체 건수 미확인을 구분한다. 실제 자연어3건/진단7조회·SILENT 검증 안내1건의 근거와 남은 해석 한계는 [STATUS](../../STATUS.md)를 따른다.

## 2026-10-23 고정 시스템 진단 — A/B/C 배포·실제 SDK 검증 완료

`system-diagnostics`의 읽기 도구1개 `get_system_diagnostics`를 추가했다. A/B/C의 허용된 systemd 대상25개에서 상태·`Type`·종료 코드·재시작 횟수와 최대4시간의 분류된 오류 표본을 읽는다. root collector의60초 주기·TTL180초 snapshot을 읽고 원문 journal·환경·명령·HTTP 본문은 반환하지 않는다. 미설치·중지·실패한 unit도 조회하며, 조회 실패/잘림/범위 한계를 정상이나 오류0으로 바꾸지 않는다. 기존 승인형 변경·LLM 관리 주체와 일반 sudo/Docker 금지 정책을 유지한다. [범위·전송·검증 계약](system-diagnostics.md).

기존 B는21:21:05 KST에 동일 Hermes CID·컨테이너 설정을 보존한 채 여섯 번째 MCP 등록을 마쳤다. 실제 UID995 SDK에서 기존5개 MCP의 도구 이름 해시 보존, 새 도구의 A/B/C 읽기, 잘못된 인자와 쓰기 도구 거부, 관리/검증 모드의 읽기 허용을 확인했다. SDK의 빈 `_meta` 호환성과 journal grep의 정상 무매치 종료코드1을 고친 후 추가 컨테이너 재시작 없이 A/B의 관측0건과 C의 과거 분류 오류 보존을 다시 확인했다. 이0건은 제한된 수집 표본이며 전체 journal이나 서비스 정상의 보증이 아니다. 모델 요청·채팅 게시와 새 서버 전체 설치는 수행하지 않았다. [v3 역사·v4 후속·검증 한계](system-diagnostics-validation-20261023.json).

## 2026-10-16 룰 파일 정의 집계 — 조회 근거 배포

`get_rule_change_target`에 현재 원문과 **같은 바이트·SHA-256**에서 계산한 `rule_inventory`를 추가했다. A는 **20:50:55 KST**, B는 **20:53:09 KST**에 배포했다. 라이브 대상 파일에서 WAF **10개**(SecRule 조건문 12개·체인 후속 조건 2개), Suricata **14개**(로컬 SID 12개·ET override 2개, noalert 마커 포함), Wazuh **19개**(level 0 기반 룰 1개 포함)를 확인했다. [배포·검증 근거](../hermes/rule-inventory-validation-20261016.json).

`schema_version:1`, `scope:target_file_definitions`이며 `declared_count`는 중복 포함 선언 수, `unique_id_count`는 고유 ID 수다. `ids`·`duplicate_ids`와 실제 인접 ID만 묶은 `contiguous_id_groups`, 종류별 `details`를 제공한다. 주석의 예약 ID·인용 문자열·체인 후속 조건을 별도 룰로 세지 않는다. 미지원 구문이면 `status:unavailable`·개수 `null`로 부분 집계를 폐기하고 원문 조회는 유지한다. 이 정보는 **대상 파일의 정의 집계**이며, CRS/ET 전체 개수나 실제 엔진 적재·경보 발생 여부를 뜻하지 않는다(`runtime_load_verified:false`).

실행기 SHA는 A `156b88d0ac60c85df96ce05961b911cd5bc28ddb65b0df3656134e8a17015c6c`, B `22d91b33a7196d869cb3bb3425c05809775d55ab937d6c0c01876f53e401fba1`이다. B는 기존 버전에 집계 함수와 조회 필드만 이식하여 나머지 전체 모듈 AST를 보존했으므로 A와 해시가 다르다. 저장소 회귀 91개와 B 후보 회귀 81개가 통과했다. 보안 엔진 재시작·새 패키지 설치·룰 변경은 없으며 읽기 대상과 승인·쓰기 권한은 유지한다. 백업은 A `/var/backups/capstone-rule-inventory/20261016/205053`, B `/var/backups/capstone-rule-inventory/20261016/205308`이다.

**만료 승인 카드 정리 배포(2026-10-15 19:02 KST 검증):** 새로 추적한 미응답 만료 요청만 본문·버튼을 정리하고 `만료된 승인 요청` 표시를 남긴다. 원글 DELETE 없이 댓글·승인/거부·소비/결과·감사기록과 기존 webhook 카드는 보존한다. 첫 실제 응답의 빈 첨부 `null` 정규화 문제를 수정한 뒤90개 회귀와 실제5초 worker의 만료 후2.368초1회 정리·보호 카드 불변을 확인했다. 이번 정리 시험은 실제 관리자 승인·룰 API 호출0이며 별도 승인→적용 E2E가 아니다. 고정 완료 시간도 보장하지 않는다. [운영·배포·복구·검증 범위](approval-card-cleanup.md).

**Wazuh 상태 판정(2026-10-15):** 프로세스 `running`과 API 준비 상태를 별도로 확인한다. 잔존 `.restart` 때문에 프로세스가 정상이어도 API1017·인증500이 발생할 수 있다. 복구 후에는 인증·manager 상태의 필수 데몬 값·agents·실제 MCP 조회를 확인하며 상태 파일을 자동으로 무조건 삭제하지 않는다. 단일 manager의 cluster disabled는 조회 권한 부족이 아니다. [실제 원인·복구·잔여 과제](wazuh-api-health-20261015.md).

**영속 사건 큐 배포 요건(2026-10-15 후속):** `soc-bot.service`의 `ProtectSystem=strict`를 유지하면서 `/var/lib/socbot`만 쓰기 가능해야 한다. 전체 흐름 시험에서 파일 소유권이 맞아도 서비스의 파일시스템 제한으로 사건 등록이503으로 실패하는 문제를 확인했다. 해당 디렉터리의 `socbot:socbot`·0700과 SQLite 파일0600을 유지하고 [전용 drop-in 예시](soc-bot-management-state.conf.example)를 `/etc/systemd/system/soc-bot.service.d/management-state.conf`에 적용했다. 진행 중 승인0건 확인 후 daemon-reload·브로커 재시작을 수행했으며 실제 합성 사건의 등록과 큐 수신을 확인했다. 다른 경로의 쓰기 권한, LLM 도구 권한, 승인 조건은 확대하지 않는다.

원칙: **MCP 서버는 표준 클라이언트와 에이전트 구현을 분리한다.** 호환 MCP 클라이언트와 도구 이름·스키마·결과 어댑터가 있으면 서버의 도구·자격·권한·정책을 보존해 재사용할 수 있다. 에이전트의 채팅·Memory·검사·승인/관리 실행부까지 설정 한 블록으로 자동 이관된다는 뜻은 아니다. Ollama의 모델 API에도 별도 MCP 클라이언트/실행 루프가 필요하다.

**2026-10-13 19:54 후속 완료:** `.111` Suricata 예외를 새 `propose_rule_edit`로 제출해 실제 전체 diff 게시·관리자 카드 승인·worker 적용·엔진 검증·결과 게시까지 확인했다. Hermes는 `.111`의 `qwen3.6:35b`로 전환했고 기존 MCP 권한·대화 이력을 유지했다. 아래 19:14의 부분 편집 적용 미검증 표시는 당시 상태다. 이번 작은 단일 카드 검증을 큰 diff 분할 카드·별도 서비스 작업·임시 선차단의 실제 실행 검증으로 확대하지 않는다. [최종 상태·증거](../../STATUS.md).

## 2026-10-13 후속 구현 — 부분편집 제안, 라이브 배포 완료

**19:10~19:14 KST A/B 배포·실제 MCP 계약 검증 완료.** Hermes 실제 UID에서 버전 0.3.0·각 8개 도구, 세 대상 읽기와 존재하지 않는 문맥의 편집 거절을 확인했다. 승인 상태와 룰/관련 파일 해시는 불변이며 worker·Mattermost 연결은 정상이다. SOUL·cron 및 현재 36세션 정책 캐시를 이력 보존 조건으로 갱신했다. 전체 MCP 172개·정책 6개 테스트를 통과했다. 새 부분 편집의 실제 전체 diff 게시 → 승인 → 적용 E2E는 다음 필요한 변경에서 확인한다. 아래 14:25~14:29의 7개 도구 기록은 당시 사실로 보존한다.

| 새 도구 | 입력 | 동작 |
|---|---|---|
| `propose_rule_edit` | `target`, `base_sha256`, `edits: [{old_text, new_text}]`, `reason` | 현재 원문과 SHA를 검사하고 작은 치환으로 전체 후보를 서버에서 구성한 뒤 기존 검증·전체 diff·단일 승인 경로로 전달 |

- 작은 룰 추가·수정·삭제에는 **`propose_rule_edit`를 우선 사용**한다. `get_rule_change_target`에서 얻은 현재 SHA-256과 필요한 문맥만 복사하며, 바뀌지 않는 전체 파일을 모델이 다시 생성하지 않는다. 호스트·고정 대상·sudo 실행기 경계는 기존과 같다.
- `old_text`는 비어 있지 않은 리터럴 문자열이며 **같은 원문에서 정확히 한 번** 나타나야 한다. 공백·개행을 정규화하거나 정규식으로 찾지 않는다. 삽입은 고유한 기존 문맥을 새 내용과 함께 치환하고, 삭제는 `new_text`를 빈 문자열로 둔다.
- 편집은 **1~16개**, 모든 `old_text`와 `new_text`의 UTF-8 합계는 **64KiB 이하**다. 모든 위치는 편집 전 원문에서 찾고 범위가 서로 겹치면 거절한다. 앞 편집의 결과를 다음 편집의 입력으로 사용하는 순차 치환이 아니다. 서버가 원문 바이트를 보존해 구성한 전체 후보는 비어 있지 않은 **128KiB 이하** 파일이어야 한다.
- 기준 SHA 불일치, 문맥 누락·중복·겹침 또는 한도 오류가 나면 원문을 재조회하고 해당 부분을 바로잡는다. **오류를 피하려고 자동으로 `propose_rule_change`의 전체 파일 재작성이나 임의 명령으로 전환하지 않는다.** 기존 전체 후보 API는 의도적으로 파일 대부분을 다시 작성해야 하는 요청의 호환 경로로 유지한다.
- 서버에서 만든 전체 후보는 기존 대상별 사전검증과 **전체 diff 최대 512KiB·분할 검토 후 최종 승인 한 번**을 그대로 거친다. 원본·후보·diff 해시 결속, 지정 승인자, 만료, 일회성 승인 소비, 적용 전 원본 재검사도 유지한다. 부분편집은 승인 없는 변경 권한을 추가하지 않는다.
- Mattermost에는 **전체 diff와 승인 카드**를 게시한다. 새 도구의 모델 응답은 게시 확인 뒤 제안 ID·상태·원본/후보/제안/diff 해시·크기·편집 수·사전검증·런타임·만료 등 메타데이터로 제한하고, 후보 전문과 diff 전문을 다시 전달하지 않는다. 기존 `propose_rule_change`의 응답 형식은 유지한다. 이후 `get_rule_change_status`와 대상 재조회로 승인·실제 반영을 확인한다.

모의 시험에서는 같은 22,652바이트 합성 파일의 주석 추가를 짧은 치환으로 반환받아 마지막 LF를 포함한 전체 후보를 2/2 정확하게 재구성했다. 실제 MCP·승인·룰 적용은 호출하지 않았으며, 긴 추론과 운영 전체 처리 시간은 별도로 봐야 한다. [측정 결과와 한계](../hermes/benchmarks/README.md#부분편집-비교) · [새 버전 배포 확인 절차](rule-change-deploy.md).

## 2026-10-13 추가 구현 — 대형 변경·고정 운영 작업·응답 승인 보강

**상태: A/B 라이브 배포와 Hermes 읽기 계약 검증 완료(2026-10-13 14:25~14:29 KST).** 새 대형 승인 카드의 실제 클릭, 승인 후 서비스 작업, 증거 기반 선차단의 라이브 E2E는 아직 수행하지 않았다. 아래 날짜별 라이브 기록은 당시 상태를 보존한다. 특히 기존 8KiB 거부·응답 MCP의 승인 누락 경로 설명은 이번 수정 전 운영 코드에 관한 기록이다. [배포 기록](rule-change-deploy.md) · [오늘 작업 증거](../../대화기록/2026-10-13.md).

- **전체 후보는 128KiB, 전체 검토 diff는 512KiB:** `candidate_content`에는 교체할 전체 파일을 제출한다. 8KiB를 넘는 변경은 브로커가 원문·들여쓰기 표시 각각 8KiB 이하인 검토 메시지로 자동 분할한 뒤 **최종 승인 카드 한 개**를 게시한다. 부분 번호·총수·원문 byte 범위·부분/전체 diff SHA-256·제안 SHA-256으로 전체 변경에 결속한다. 모든 게시가 성공해야 `pending`이 되며, 일부 실패·만료·게시 시간 초과는 승인할 수 없다. 각 검토·승인 카드의 본문은 12,000자/UTF-8 바이트 이하로 제한하고 결과 표시 여유를 둔다. 작은 변경은 기존 단일 카드를 유지한다.
- **`rule-a`·`rule-b` 각각 7개 도구의 실제 목록 확인:** 아래 목록은 공통 스키마이며 root 실행기가 호스트·대상·허용 작업을 다시 제한한다. `rule-b`에서 A 대상이나 임시 IP 차단을 실행할 수 없다.

| 도구 | 범위 |
|---|---|
| `get_rule_change_target` | 고정 로컬 룰 전문·기준 해시 조회 |
| `propose_rule_change` | 전체 후보 파일의 단일 승인 요청 |
| `get_rule_change_status` | 룰 승인·적용·복구 상태 조회 |
| `get_service_action_target` | 허용 서비스의 현재 상태·가능 작업 조회 |
| `propose_service_action` | 조회한 상태에 결속한 고정 restart/reload의 사전 승인 요청 |
| `temporarily_contain_ip` | A에서 검증한 최근 공격 증거가 조건을 충족하는 외부 IPv4의 최대 10분 임시 차단 |
| `get_operation_status` | 서비스 작업·임시 차단의 승인·실행·검증·만료 상태 조회 |

서비스 작업은 A `waf`·`chatproxy`의 reload/restart, A `suricata`와 B `wazuh-manager`·`wazuh-dashboard`의 restart만 허용한다. 승인 카드에서 변경 전 상태, 예상 변경 후 상태, 영향, 사유와 해시를 검토하고 지정 승인 뒤 한 번만 실행한다. 패키지 설치·컨테이너 생성/구성 변경·임의 셸 명령은 지원하지 않는다. 임시 차단은 서버 증거·보호 주소·활성 SSH 검사 뒤 선행하며, 이후 **60분 유지 / 해제 요청**을 받는다. 무응답·장애 시 원래 10분 커널 TTL이 상한이다. 해제 요청은 다음 worker에서 처리하므로 진행 중인 룰·서비스 작업에 따라 지연될 수 있다. 세부 기준·복구 절차는 [승인형 운영 작업](approved-operations.md)에 둔다.

기존 `resp`의 `block_ip`·`unblock_ip`도 모두 명시적 승인과 `/consume`의 일회성 소비를 요구하도록 수정했다. 브로커 URL/토큰·승인자·허용 콜백 출처 누락 시 실행하지 않는다. 소비는 요청 ID·action·IP·기간에 결속하며, 공개 nonce 조회 `/nonce/<id>`는 제거했다. 신규 룰/운영 API의 양방향 HMAC과 기존 IP 대응 API의 토큰 방식은 구분한다. [채팅 승인 흐름](hitl-chat.md).

로컬 154개 테스트에서 UTF-8 분할 재조합·512KiB 경계·4MiB HTTP 상한·게시 실패/만료·승인 결속·일회성 소비·서비스/임시 차단 모의 실행·기존 읽기 회귀를 검증했다. 라이브에서는 B 14:25:56, A 14:26:15 KST 배포 후 실제 Hermes UID 995로 각 rule MCP 7개 도구, 고정 서비스 5개 상태 조회, 기존 resp 3개 도구와 차단 목록 조회에 성공했다. 14:29 확인에서 Hermes 실행·Mattermost 연결과 현재 34개 대화 캐시의 정책/해시·DB 무결성이 정상이다. A의 보호 DGX 주소 제안은 거부됐고 룰·nft 상태·대상 서비스 컨테이너 시작 시각은 유지됐다. 배포 과정에서 재시작한 것은 soc-bot과 Hermes뿐이다. 실제 신규 승인 클릭·서비스 실행·선차단 E2E는 이 읽기 검증과 별도로 남는다.

```
[LLM API]         Claude API | OpenAI | Ollama(Qwen)      <- 런타임 provider 설정
      ^
[에이전트 런타임]   Claude Code | Claude Desktop | Hermes | 커스텀   <- MCP 클라이언트 설정
      ^   MCP 표준 (stdio | HTTP streamable)
[MCP 읽기 @B]      wazuh-ro 14툴 + security-events 2툴 -> Wazuh API/Indexer
[MCP IP 대응 @A]   resp 3툴 -> nft agent_block
[MCP 룰 변경 @A/B] rule-a / rule-b -> B 승인 브로커 -> 지정 승인 -> 고정 로컬 룰 적용
      ^
[데이터/대상]       Wazuh @B, nftables·WAF·Suricata @A, Wazuh 로컬 룰 @B
```

2026-10-08 약 12:58 KST 배포 후 Hermes에 위 5개 MCP 서버가 enabled임을 확인했다. 룰 변경 경로는 HMAC 통신·현재 룰 읽기 조회까지 검증했고, 실제 Mattermost 승인 버튼→룰 적용·복구 E2E는 아직 미검증이다.

**2026-10-13 추가 확인:** Hermes 실행 UID에서 rule-a Suricata·rule-b Wazuh 조회에 성공했다. 일반 sudo/Docker 권한 없이 이 MCP로 고정 로컬 룰의 변경 제안·검증·승인 후 적용을 요청할 수 있다. 권한·큐 상태의 근거를 구분하도록 SOUL 관리 블록을 배포하고 Hermes를 재시작한 뒤 5개 MCP enabled를 확인했다. LLM API 오탐 예외는 오프라인 12개 사례와 전체 ET+후보 구문 검사를 통과했고 제안 `b17074c82fe506065789849596292050`의 Mattermost 카드가 게시됐다. 10:29 KST 당시 `pending`·운영 룰 미변경을 확인했고 만료 시각은 10:37:21 KST였다. **10:51:34 KST 후속 확인에서는 A 제안 JSON 상태 `expired`·라이브 원본 SHA `4422a0c1…` 유지로 승인 만료·미적용을 확인했다. 새 제안은 게시하지 않았다.** 실제 승인→적용·reload 검증은 현재 룰 조회와 새 카드 지정 승인 뒤에 진행할 작업으로 남는다. [오늘 기록](../../대화기록/2026-10-13.md) · [운영 절차](rule-change-deploy.md).

**12:32~12:44 KST 후속 정정:** 위 만료·미적용 설명은 10:51 당시 기록이다. 새 제안 `7676bcb16b819d23f949f126a9e16c7d`의 지정 승인·파일 교체 뒤 hot reload 성공 오판을 발견했고, 운영자 재시작으로 승인된 52,495룰의 실제 로드를 확인했다. 12:43:13 A helper 수정본 배포와 사전·브로커·런타임 조회 검사가 통과했다. 이후 실사용 HTTP 200 4건·새 흐름 3개에서 대상 커스텀 4종 경보는 0건이지만 ET `2034806`·`2034802`가 각각 2건 남았다. ET 원인 분석·별도 후보 검증·승인, 수정 helper의 자동 적용·실제 실패 복구 E2E와 장기 관찰은 [상세 기록](rule-change-deploy.md)을 따른다.

**13:00~13:17 KST ET 후속:** 직전 24시간의 ET `2034806/2034802` 각 3건은 모두 A `.230`→DGX `.110:11434`이며 같은 흐름에 정상 LLM API POST·200·SSE 기록이 있었다. 본문/`tx_id`가 없어 정확한 문자열 원인은 미확정이다. 두 ET 원본의 조건을 보존하고 고정 flowbit 예외·rev +1만 허용하는 A helper `81597b11…`를 13:16:15에 배포했다. 실행기 30개 테스트·독립 검토, 전체 ET 기반 검사와 HMAC 검사가 통과했고 런타임은 그대로였다. 17개 사례·197패킷 검증을 통과한 후보 제안 `90ff6d8cf37547f7451c81e0caf1cd73`을 13:17:13 게시했다. 게시 당시 지정 승인 대기·미적용이었으며, 만료 예정 13:27:13 전에 승인이 접수됐다.

**13:18 자동 적용·13:20:50 KST 확인:** 같은 제안이 `applied`·결과 카드 게시 성공으로 종료됐고 **운영자 재시작 없이 수정 helper의 자동 적용 E2E를 확인했다.** 실제 룰 로드 시각 13:18:09.056041 KST, 로드 성공 52,497건·failed/skipped 0·passive 유지, 로컬 SHA `cabbac45…`·합본 `ea160e90…`·ET 원본 불변을 검증했다. 로드 건수에는 대체 정의 2개가 포함되며 고유 SID는 52,495개, 로컬 파일은 로컬 SID 12개+ET override 2개다. 13:20 초기 조회에는 새 LLM 요청이 없었으나 **13:24:45 후속 조회에서는 새 LLM HTTP 200 응답 2건·전체 경보 0건**을 확인했다. 이 표본의 ET 2종·커스텀 4종 경보는 모두 0건이며, HTTP 2건을 고유 흐름 2개로 해석하지 않는다. 실제 실패 복구 E2E와 장기 관찰은 남는다. [해시·배포·예외 범위](rule-change-deploy.md).

## 경보 시각 표시 — KST 배포(2026-10-13 11:17:40 KST)

`soc_bot.py`의 보고서 시각과 `/recent`의 보조 필드 `ts_kst`는 원본에 명시된 시간대·offset을 기준으로 같은 절대 시각을 KST로 표시한다. `/recent`의 `ts`는 원본 문자열을 그대로 유지하며 원본 로그·Indexer 저장값·검색 조건은 변경하지 않았다. 0이 아닌 초 미만 값은 6자리 마이크로초로 보존하고, 정수초 시각은 기존 초 단위 형식을 유지한다. 시간대 없는 시각은 UTC로 가정하지 않고 `시간대 확인 필요`로 표시한다.

Hermes 모니터는 `ts_kst`를 우선 표시하고 해당 필드가 없으면 `ts`를 사용한다. 같은 응답은 같은 바이트를 출력하며 같은 초 안의 서로 다른 소수부도 구별한다. SOUL과 기존 `soc-alert-watch` 작업 프롬프트에는 보고 시각의 `Asia/Seoul` 변환·`KST`/`+09:00` 표시, 시간대 추정 금지, 원본 로그 인용 시 시각·offset 보존 지침을 반영했다. 기존 모니터 토큰과 나머지 프롬프트는 보존했다.

라이브 백업은 `/var/backups/soc-hermes-kst-20261013.4v9nt2ci`이며, 배포한 `/opt/socbot/soc_bot.py` SHA-256은 `310699930164c0e62b4eeebcecf628b3b6a26a52dbd88e802fe4a7fad07e75ea`이다. 실행 중 Hermes 작업과 IP 차단·룰 승인 대기가 없음을 확인한 뒤 soc-bot과 Hermes를 재시작했다. 재시작 후 브로커 요청·응답 HMAC 검증, Hermes 실행·OOM 없음·새 gateway 상태를 확인했다.

검증: 실제 `/recent` 5건에서 원본 시각과 KST 변환이 일치했다(예: `2026-10-13T02:15:24.221+0000` → `2026-10-13 11:15:24.221000 KST`). 점검 시 level≥10 경보가 0건이어서 모니터 출력은 배포 전후 동일했다. 로컬 17개 테스트에서 offset 변환, 시간대 없는 시각 처리, 원본 보존, `.124`/`.125` 구별과 변환 전후 epoch 동등성을 확인했고 셸·내장 Python 문법 검사도 통과했다. **실제 LLM이 생성한 자연어 보고서의 KST 표시는 아직 검증하지 않았다.**

## 교체 지점
| 바꾸고 싶은 것 | 어디를 고치나 | 서버 변경 |
|---|---|---|
| LLM API | 에이전트 런타임의 provider 설정(모델/엔드포인트/키) | 없음 |
| 에이전트 런타임 | 그 런타임의 MCP 클라이언트 설정(명령 또는 URL) | 없음 |
| 전송(stdio↔HTTP) | 서버 기동 방식(플래그/서비스) | 툴·자격증명 동일 |
| **알림 채널**(HITL notify) | A `/etc/resp/hitl.env` 의 `RESP_NOTIFY_BACKEND` + 엔드포인트 1블록 | 없음(코드·정책 불변) |
| **승인 창구**(HITL approve) | **Tier 2 구현: 응답 MCP→soc_bot 브로커(`RESP_BROKER_URL`)→Mattermost [승인]/[거부] 버튼**. 현재 `block_ip`는 브로커가 설정된 경우 거부·만료·오류 시 미실행하지만, 미설정 시 즉시 실행하는 경로가 있다(아래 현행 제약 참조). 원 설계는 MCP elicitation | 없음(브로커 URL 1블록, 서버 코드는 채널을 모름) |

## 전송 계약
- **stdio over SSH** — 운영 중인 기본 읽기 서버는 `ssh -T groot-mcp`(원격 명령 인자 없음), 보안 이벤트 읽기 서버는 `ssh -T groot-mcp security-events`. B의 sshd `Match User mcp` ForceCommand + authorized_keys `restrict,command=`가 두 경우 모두 래퍼 `/opt/mcp/run-wazuh-ro.sh`를 강제한다. 래퍼는 `SSH_ORIGINAL_COMMAND`가 정확히 `security-events`일 때만 2툴 보조 서버로 분기하고, 다른 명령은 기존 Wazuh 14툴 서버로 보낸다. 서버 프로세스는 **B에서** 뜨고, 읽기 자격증명은 B의 `/etc/mcp/wazuh-ro.env`에만 → 클라이언트 호스트(Mac 등)에 자격증명 없음(A안). 클라이언트 키(`~/.ssh/groot_mcp_ed25519`)는 A에서는 B:22 점프 전용(`restrict,permitopen`), B에서는 mcp 계정 래퍼 전용.
- **확장: HTTP(streamable)** `http://10.200.10.10:8080/mcp` + `Authorization: Bearer <token>` — 프로세스를 못 띄우는 원격/커스텀 API 클라이언트용. `mcp-server-wazuh`를 `--features http`로 빌드해 B에 systemd 서비스로 상주(전용 사용자, `127.0.0.1` 또는 내부 IP 바인드). 같은 코드·같은 툴.
- 기존 Wazuh 서버의 stdio/HTTP 전송은 **툴 목록·자격증명·권한이 동일**하다. 보안 이벤트 보조 서버는 현재 stdio 경로만 준비했다.

## 서버 측(B) 배치 원칙
- 바이너리: `gbrigandi/mcp-server-wazuh` v0.3.0 (리뷰 커밋 969f36f와 동일, sha256 `8a18cb44…`, 읽기전용 14툴). `/opt/mcp/mcp-server-wazuh` (root:mcp 0750)
- 래퍼 `/opt/mcp/run-wazuh-ro.sh` (root:mcp 0750): env 파일을 읽고 기본 요청은 `/opt/mcp/mcp-server-wazuh`, 정확한 `security-events` 요청은 `/opt/mcp/security-events-mcp.py`를 실행한다. env 파일은 **root:mcp 0640(mcp 읽기만, 수정 불가)**, 내용은 **읽기전용 계정 `mcp-ro`**(Wazuh API role `readonly` / 인덱서 backend_role `readall`)뿐. 비밀은 repo·CREDENTIALS 파일에도 두지 않음(B의 env 파일이 유일, 분실 시 관리자가 재설정).
- 전용 사용자 `mcp`(시스템 계정, 비밀번호 없음) + sshd `Match User mcp`(ForceCommand·PermitTTY no·포워딩 금지·비밀번호 인증 금지) + authorized_keys `restrict,command=` 이중 강제. authorized_keys는 root:mcp 0640 이라 mcp 계정 자신도 제한을 풀 수 없음.
- 배치 스크립트 `deploy_mcp_B.sh`(게이트형, 비밀은 stdin 주입): 계정 생성 → `internal_users.yml` 동기화(securityadmin 재적용 대비) → sshd → **읽기전용 실증**(툴이 쓰는 API 엔드포인트 전부 200, 쓰기 403; 인덱서 read 200·write 403) → env 원자적 교체 → **계약 테스트를 mcp 사용자로 실행**(tools/call 로 실제 자격증명 검증).
- 응답 서버(차단)는 **별도 프로세스·별도 자격증명**(A의 nft `agent_block` 제어) + Policy Engine 내장. 읽기 서버와 분리 = 최소권한.

## 클라이언트 설정 템플릿 (비밀 없음)
**Claude Code** (프로젝트 `.mcp.json` 또는 `claude mcp add`):
```json
{ "mcpServers": { "wazuh-ro": { "type": "stdio", "command": "ssh", "args": ["-T", "groot-mcp"] } } }
```
(`claude-code.mcp.json.example`는 기존 Wazuh 서버 설정. 보안 이벤트 서버는 같은 SSH 설정에 원격 명령 인자 `security-events`를 추가한다.)
**Hermes** (B 의 Docker 컨테이너, `/opt/hermes-data/config.yaml` = 컨테이너 `/opt/data/config.yaml`; 아래는 [전체 템플릿](../hermes/config.example.yaml)의 SSH 연결 부분 요약):
```yaml
mcp_servers:
  wazuh-ro:
    command: ssh
    args: ["-T", "-F", "/opt/data/home/.ssh/config", "mcp-b"]   # Host mcp-b = mcp@10.200.10.10, 키·known_hosts 는 /opt/data/home/.ssh
    env: { HOME: /opt/data/home }
    trust: full
  security-events:
    command: ssh
    args: ["-T", "-F", "/opt/data/home/.ssh/config", "mcp-b", "security-events"]
    env: { HOME: /opt/data/home }
    trust: full
  resp:
    command: ssh
    args: ["-T", "-F", "/opt/data/home/.ssh/config", "resp-a"]  # Host resp-a = resp@10.200.10.1
    env: { HOME: /opt/data/home }
    trust: full         # 새 구현: block/unblock 모두 서버 승인+1회 consume; 라이브 배포 상태는 상단 참조
    # HTTP 전환 시: url: "http://10.200.10.10:8080/mcp", headers: {Authorization: "Bearer ${env:SOC_MCP_TOKEN}"}
  rule-a:
    command: ssh
    args: ["-T", "-F", "/opt/data/home/.ssh/config", "rule-a"]
    env: { HOME: /opt/data/home }
    trust: full         # 지정 승인 강제는 별도 브로커·root 실행기
  rule-b:
    command: ssh
    args: ["-T", "-F", "/opt/data/home/.ssh/config", "rule-b"]
    env: { HOME: /opt/data/home }
    trust: full
```
기존 `17 tool(s) from 2 server(s)`는 2026-09-28 실측이다. 2026-10-06 라이브 `/opt/hermes-data/config.yaml`에 `security-events`를 추가하고 Hermes 컨테이너를 재시작했다. `docker exec hermes hermes mcp list`에서 `wazuh-ro`·`security-events`·`resp`가 모두 enabled임을 확인했다. `hermes chat -q` LLM 대화에서 새 `search_suricata_alerts`·`search_modsecurity_alerts` 도구가 각각 실제 호출되어 결과를 반환했다. 전체 도구 수는 별도로 계수하지 않았다. 검증 경로: `infra/hermes/deploy_hermes_B.sh test` — 컨테이너 안 계약 테스트 + `chat -q` 기동 후 agent.log 확인. 컨테이너 키는 B `/opt/mcp/.ssh/authorized_keys`·A `/opt/resp/.ssh/authorized_keys` 에 Mac 키와 같은 `restrict,command=` 접두로 등록됨(2026-09-28).
어느 클라이언트든 그 호스트에 `~/.ssh/config`의 `groot-mcp` 블록(키·ProxyJump·BatchMode)과 키 파일만 있으면 된다. 다른 호스트에서 쓰려면 그 호스트용 키를 만들어 B `/opt/mcp/.ssh/authorized_keys`(같은 `restrict,command=` 접두)와 A `~groot_a/.ssh/authorized_keys`(점프 전용 접두)에 추가.
**커스텀/원격(HTTP)** — Python `mcp` SDK: `streamablehttp_client("http://10.200.10.10:8080/mcp", headers={"Authorization": "Bearer ..."})` → `list_tools()` / `call_tool("get_wazuh_alert_summary", {...})`.

## AI와 무관한 검증(서버 계약 테스트)
어떤 AI를 붙이기 전에 표준 클라이언트로 서버를 먼저 검증한다: `contract_test.py`(표준 라이브러리만, 오프라인) — `python3 infra/mcp/contract_test.py --cmd "ssh -T groot-mcp" --tool get_wazuh_alert_summary --args '{"limit":3}'` → initialize/tools/list/tools/call + stdout 순수성 검사. (`npx @modelcontextprotocol/inspector`나 Python `mcp` SDK도 동일하게 쓸 수 있다.) 통과하면 "서버는 검증됨"이고, 이후 런타임 교체는 클라이언트 설정만 바꿔 같은 호출을 재현하면 된다. B에도 `/opt/mcp/contract_test.py`가 있어 서버 로컬에서 `runuser -u mcp`로 재검증 가능.

## 보안 이벤트 읽기 서버 — B 배치·원격 조회 검증 완료(2026-10-06)
`security-events-mcp.py`는 기존 Wazuh 인덱서의 `wazuh-alerts-*`에 **이미 적재된** 이벤트만 조회한다. 원본 Suricata EVE·ModSecurity 감사 로그나 장비 설정을 직접 읽지 않는다. 응답은 KST 시각과 제한된 메타데이터만 포함하고, HTTP 헤더·요청 본문·원본 로그는 반환하지 않는다.

| 도구 | 조회 범위 |
|---|---|
| `search_suricata_alerts` | 최근 Suricata 알림. 시간·건수와 출발지 IP·SID 필터 |
| `search_modsecurity_alerts` | 최근 ModSecurity 알림. 시간·건수와 출발지 IP·WAF 룰 ID 필터 |

두 도구 모두 기본 최근 60분/10건, 최대 24시간/50건이며, `mcp-ro`의 기존 인덱서 읽기 권한만 사용한다. 실제 조회 결과는 Wazuh 수집·인덱싱 상태에 좌우된다. B에는 `deploy_security_events_B.sh`로 설치했다. 이 스크립트는 로컬 MCP 목록 사전 검사, 기존 파일 백업, 원자적 파일 교체, `mcp` 사용자 경유 목록 검증을 수행하며 서비스 재시작 없이 새 SSH 연결부터 적용한다. `python3 infra/mcp/contract_test.py --cmd "ssh -T groot-mcp security-events" --tool search_suricata_alerts --args '{"limit":3}'` 형식의 원격 계약 테스트로 2툴 목록과 두 실제 조회를 확인했다. Suricata 로컬 SID `1000010`은 Wazuh `100110`, ModSecurity CRS `920350`은 Wazuh `100101` 경보로 반환됐다. WAF는 당시 `DetectionOnly`이며, GROOT 커스텀 WAF ID `10100`대의 발화와 별도 공격 시나리오는 검증하지 않았다. 기본 `ssh -T groot-mcp`의 기존 14툴도 회귀 테스트를 통과했다. Hermes LLM에서도 두 새 도구의 실제 호출이 각각 성공했다.

WAF 규칙 ID 필터는 최근 후보 경보 최대 250건을 검사한다. 해당 범위를 넘어선 일치는 누락될 수 있으며 응답의 `scan_capped`로 범위 절단 여부를 확인한다. 규칙 ID는 구조화된 ModSecurity 메시지 또는 유효한 JSON 직렬화에서만 추출하고, 자유 형식 로그 문자열은 규칙 ID 근거로 사용하지 않는다.

## 응답(차단) 서버 — 구현됨 (Groot_A, 2026-09-27)
읽기 서버와 **분리된 소형 커스텀 서버**(최소권한). 차단 능력이 A에 있으니 A에 co-locate(2차 SSH hop 불필요).
- 파일: `response-mcp.py`(파이썬 stdlib stdio MCP, 의존성 0) → `/opt/resp/`, 래퍼 `run-response.sh`, 배치 `deploy_response_A.sh`(게이트·롤백 트랩), 만료 리퍼 `../groot-a/agent_block_reaper.sh`.
- 툴: `block_ip(ip, minutes≤120, reason)` / `unblock_ip(ip, reason)` / `list_blocks()` → nft `agent_block`(A Phase2 FW). 정책 엔진: TTL 상한·reason 필수/정규화·IP 검증·보호대상(never_block)·활성 SSH 출발지 거부·flush 미노출.
- 자격증명 격리(A안): 에이전트는 SSH 키만. 차단 능력 = A의 `resp` 계정 sudoers(`agent_block add/del/list` 만). sshd `Match User resp` ForceCommand + authorized_keys restrict.
- 클라이언트(불가지론): `{"command":"ssh","args":["-T","groot-resp"]}` 한 블록. 읽기(`groot-mcp`)와 별개 키(`groot_resp_ed25519`).
- 감사: 모든 add/del/거부 → syslog(agent_block) → Wazuh 100120~100123, reload 100125, **TTL 만료 100131**(리퍼). 차단 시작↔종료가 SIEM 타임라인에 남음.
- 계약 테스트: `python3 infra/mcp/contract_test.py --cmd "ssh -T groot-resp" --tool list_blocks --args '{}'`.

## 승인형 규칙 변경 MCP — A/B·Hermes 라이브 배포 (2026-10-08)
11:46 KST의 라이브 MCP 목록에는 B의 읽기 16툴과 A의 IP 차단 응답 3툴만 있었다. 이후 별도 승인형 변경 경계를 구현하고 같은 날 A/B와 Hermes에 배포했다. 배포 후 `hermes mcp list`에서 기존 `wazuh-ro`·`security-events`·`resp`와 신규 `rule-a`·`rule-b` 5서버가 모두 enabled였다. A/B의 읽기 전용 `get_rule_change_target`, 브로커 요청·응답 HMAC, SSH 강제 명령, 10초 worker 실제 실행 성공을 확인했다. **Mattermost 승인 버튼 클릭→운영 룰 적용·재로드 E2E는 아직 수행하지 않았다.**

**2026-10-13 후속:** 오전 제안 `b17074c82fe506065789849596292050`은 만료·미적용이었다. 12:25:04 KST 새 제안 `7676bcb16b819d23f949f126a9e16c7d`의 지정 승인 뒤 worker가 Suricata 파일을 교체했고, 로컬 룰은 `98146db1…`, ET+로컬 합본은 `2b3fcd03…`로 확인했다(ET 불변). 그러나 초기 `applied`는 **실제 런타임 로드 증거가 아니었다**. `-S` 기동에서는 hot reload가 `NOK`였는데 `suricatasc`의 종료 코드 0 때문에 기존 helper가 성공으로 오판했다. 승인 소비·백업·정확한 후보를 재확인하고 운영자가 기존 컨테이너를 재시작한 뒤 12:32:35.865415 KST 로드 시각, 52,495룰·failed/skipped 0·running true·OOM false·passive 유지를 확인했다. 재시작 요청부터 확인까지 17.89초는 실제 탐지 공백 측정치가 아니다. [상세 경위·백업](rule-change-deploy.md).

**12:43:13 KST A helper 수정 배포:** 실행기 SHA `10cae221…`를 root:root·0750으로 원자 교체했다. 향후 승인된 Suricata 변경은 기존 컨테이너 재시작과 실제 룰 통계·로드 시각 검사로 반영 여부를 확인하며, 승인 카드에 짧은 탐지 중단을 알린다. `suricatasc` JSON `NOK`도 실패로 처리한다. `--check`·`--broker-check`, 새 파서의 실제 52,495룰·failed/skipped 0·12:32 로드 조회가 통과했다. 배포 중 운영 룰·컨테이너 ID/StartedAt은 불변이며 추가 재시작은 없었다. 백업은 `/var/backups/rule-change-runtime-20261013.j7mzevn2`이고 실행기·브로커 40개 테스트와 독립 검토가 통과했다. B 실행기는 이번에 재배포하지 않았다. 수정본의 자동 적용·실제 실패 복구 E2E는 아직 미검증이다.

**12:44:26 KST 실사용 표본:** 재적재 후 새 LLM 흐름 3개·HTTP 200 4건에서 대상 커스텀 SID `1000032/33/70/71`은 0건이었다. 같은 A→DGX `.110:11434`에서 ET SID `2034806`(Log4j RCE obfuscation outbound)·`2034802`(lower TCP bypass outbound)는 각각 2건 남았다. LLM 전달 문자열에 반응했을 가능성은 본문 미열람 상태의 추정이며 전체 오탐 해소로 보고하지 않는다. ET는 이번 승인 범위 밖으로 그대로 유지했고 별도 원인 분석·좁은 후보 검증·승인과 장기 재발 관찰이 남는다.

- 대상은 A의 `GROOT_A_WAF.conf`·`GROOT_A_local.rules`와 B의 Wazuh `local_rules.xml` 세 로컬 룰 파일로 고정했다. `get_rule_change_target`이 현재 전문·SHA-256·컨테이너 상태를 조회하고, `propose_rule_change`가 조회 시점 해시와 전체 후보 파일을 받아 diff·영향·검증 상태를 보여주고 Mattermost 승인을 요청한다. `get_rule_change_status`로 거부·만료·적용·복구 결과를 확인한다. 임의 경로·셸 명령·nft 정책·WAF 차단 모드·Suricata 인라인/drop 전환은 노출하지 않는다.
- **10/13 13:16 A 변경 경계 보완:** Suricata 로컬 SID `1000000..1000099` 외에는 ET `2034806/2034802` 두 SID만 현재 ET 원본 바이트를 보존한 override로 허용한다. 차이는 고정 `flowbits:isnotset,groot_llm_api`와 rev +1뿐이며 ET 파일은 쓰지 않는다. 마커 주소·포트·방향·옵션을 고정하고 다른 flowbit 작성자를 금지한다. 제안·승인 소비 전·파일 교체 직전에 현재 ET와 대조하며, 원본 변경·다른 SID·탐지 조건 완화·pass/drop은 거절한다. 기존 대상·브로커·Mattermost 지정 승인 흐름을 유지하므로 일반 sudo/Docker 권한이 필요하지 않다. 두 ET 예외의 실제 자동 적용은 위 13:18~13:20 기록을 따른다.
- `rule_change_mcp.py`는 전용 SSH 사용자로 실행하고, root 소유 `rule_change_executor.py`의 **인자 없는 고정 sudo 명령**만 호출한다. 읽기 MCP의 권한은 올리지 않는다. 실행기는 호스트/대상 허용목록, 컨테이너 마운트·원본 해시, WAF DetectionOnly·Suricata passive 상태를 검사한다. 승인 전 Suricata 후보는 임시 결합 파일로 `suricata -T`를 시험하며, WAF/Wazuh는 구조 검사 후 승인된 적용 단계에서 엔진 구문 검사를 수행한다. 임시 Suricata 검증 파일은 활성 `all.rules`를 교체하지 않고 검사 후 삭제한다.
- `soc_bot.py`의 **별도 룰 승인 API**는 전용 토큰·명시적 승인자·Mattermost 콜백 출처를 필수로 한다. 카드에는 변경 전/후 SHA-256과 전체 diff·영향·사유·만료 시각을 표시하며, 표시 한도를 넘으면 제안을 거부한다. 승인된 정확한 변경안 digest를 1회 소비하고, 실행 직전 원본·ET/결합 룰 상태를 다시 비교한다. 변경 백업, WAF 단일 파일 bind inode 보존, Suricata 결합 룰 재작성, Wazuh manager 재시작, 엔진 검사·읽기 해시·프로세스 상태 검사, 실패 시 복구와 결과 카드 게시를 구현했다. 브로커 장애·설정 누락·거부·만료·해시 불일치는 적용하지 않는다.
- 배치 순서(실행 완료): B의 브로커 코드/전용 토큰·기존 지정 승인자 1명·Mattermost 실제 출처 `/32` 설정 → A/B의 `deploy_rule_change_{A,B}.sh`로 전용 사용자·SSH 강제 명령·sudoers·root 전용 상태/백업·10초 worker 설치 → 전용 키로 SSH 계약 테스트 → B Hermes 설정과 SOUL의 룰 변경 지침 등록. 운영 WAF·Suricata·Wazuh 파일의 배포 전후 SHA-256은 동일했다. 재배포 전에는 라이브 경로·마운트·모드와 승인 대기 건을 다시 확인한다.
- 실제 실행 순서와 점검 명령은 [rule-change-deploy.md](rule-change-deploy.md)에 정리했다. A↔B 승인 API는 HTTP 위에 일회성 nonce와 요청·응답 HMAC을 적용해 승인 위조를 막는다. HTTP 본문 내용의 기밀성은 제공하지 않으므로 후보 룰에 비밀 값을 넣지 않는다.
- **남은 검증/한계:** 10/13 13:18에는 수정 helper의 지정 승인→파일 교체→재시작→실제 로드 검사→결과 카드까지 자동 적용 E2E를 확인했다. 실제 실패 복구 E2E와 새 LLM 통신의 장기 오탐 관찰은 남는다. 브로커는 승인 상태를 메모리에 두므로 재시작하면 대기/승인 건은 소실되어 적용이 중단된다. 승인 소비 뒤 브로커가 재시작되면 실행기 로컬 결과는 남아도 Mattermost 결과 카드가 누락될 수 있다. 승인 후 적용 전 원본·마운트 드리프트로 중단되면 변경기는 `/abort`로 승인권을 폐기하고 실제 읽기 해시와 미적용 사유 카드를 게시한다. 브로커 장애로 카드 게시가 실패하면 로컬 상태에 미적용 결과가 남고, 같은 보고를 제한 횟수만 재시도한다. Hermes가 실제 사람 발화를 했는지는 MCP가 독립적으로 인증하지 못하므로 SOUL/자동 경보 프롬프트에서 자발적 제안을 금지하고, 서버에서는 지정 승인자의 버튼 클릭을 최종 강제한다.
- 기존 IP 차단은 별도 `resp` MCP가 담당하며 기존 경로의 미설정 시 즉시 실행 제약은 이번 룰 변경 구현과 별개로 남아 있다. Wazuh API의 [`rules:update` 권한](https://documentation.wazuh.com/current/user-manual/api/rbac/reference.html)은 파일 단위로 좁히기 어렵기에 새 경계는 고정 파일 helper를 쓴다.

### 알림/승인 채널도 교체 용이(엔드포인트만)
읽기·응답 서버와 같은 원칙을 HITL 에도 적용 — **두 층으로 분리**:
- **승인(approve)** = **Tier 2 경로 E2E 검증(2026-09-28)**: 응답 MCP `request_approval()` 이 soc_bot 브로커(`RESP_BROKER_URL`)를 폴링, 브로커가 Mattermost 에 [승인]/[거부] 카드를 띄운다. 브로커 설정 시 승인 결과만 `block_ip`를 실행하고 거부/만료/오류는 미실행한다. 다만 브로커 미설정 시 즉시 실행하는 현행 코드 경로가 있어 전체 설정에 대해 fail-closed라고 할 수 없다. *어디에* 띄울지는 브로커/런타임이 정한다. 상세 [hitl-chat.md](hitl-chat.md).
- **알림(notify/감사 푸시)** = `notifier.py`(stdlib) 백엔드 추상화. `/etc/resp/hitl.env` 의 `RESP_NOTIFY_BACKEND`(none|http|email|slack) + 엔드포인트만 바꾸면 채널 교체(코드·정책·서버 불변). run-response.sh 가 세션마다 이 파일을 source → **재시작 없이** 다음 연결부터 반영. 예시 `hitl.env.example`.
  - `http`: 내부 Mattermost/Rocket.Chat incoming webhook 또는 사내 웹훅(내부망) — 권장. **채팅 채널 상세 설계(양방향 웹훅·인터랙티브 승인)는 [hitl-chat.md](hitl-chat.md)**.
  - `email`: 이 망은 아웃바운드 587 열림.
  - `slack`: ⚠️ 아웃바운드 443 전면 차단(2026-09-27 실측)이라 이 망에선 불가. 나중에 443 열리면 backend 만 slack 으로.
  - best-effort: 알림 실패는 stderr 로그만, block/unblock 결과(툴 응답)에 영향 없음. stdout(프로토콜) 불침범.
- 검증(2026-09-27): `hitl.env` 를 http 로 바꾸고 내부 sink 로 block/unblock 알림 수신 확인 → 다시 none 으로 복원. 기본은 none(알림 off, 기존 동작 동일).

## 상태
- 2026-09-27: 기존 Wazuh 읽기 서버(B, `groot-mcp`)와 응답 서버(A, `groot-resp`) 배치·계약 테스트 완료.
- 2026-09-28: Hermes에서 기존 17툴/2서버 등록 실측.
- 2026-10-06: 보안 이벤트 2툴 서버를 B에 배치하고 원격 목록·Suricata·ModSecurity 조회 및 기존 14툴 회귀 계약 테스트 통과. Hermes 세 번째 서버 enabled 및 LLM의 새 도구 2개 실제 호출 확인.
- 2026-10-08: A/B 관리 SSH로 실제 구성 재확인. A 응답 MCP의 브로커 URL·토큰, B의 브로커 토큰·허용 승인자 목록은 비어 있지 않다(값 비출력). A에서 해당 토큰으로 B `GET /pending`을 호출해 HTTP 200·대기 0건을 확인했다. Hermes의 `wazuh-ro`·`security-events`·`resp` 3서버가 enabled이고 규칙 변경 MCP는 없다. 승인 카드→클릭→차단은 이번 점검에서 실행하지 않았다. 미설정 시 즉시 실행하는 코드 경로는 여전히 남아 있다.
- **2026-10-08 후속 정정:** 바로 위 항목은 **11:53~11:59 KST 배포 전 점검**의 기록이다. 약 12:58 KST B 룰 승인 브로커·A/B 변경기/worker·Hermes `rule-a`·`rule-b`를 배포해 총 5서버 enabled, HMAC 통신·읽기 조회를 확인했다. 운영 룰 해시는 그대로이고 실제 룰 승인·적용 E2E는 미검증이다. 기존 IP 차단 경로의 설정 누락 시 즉시 실행 제약은 남아 있다.
- **2026-10-13 후속:** 새 지정 승인으로 LLM API 연결의 선택 SID 4종 예외 파일을 적용했다. 초기 reload 성공 오판을 발견해 운영자가 기존 컨테이너를 재시작했고 12:32 런타임 52,495룰·실패 0을 확인했다. 12:43:13 A helper 수정본을 배포해 사전·브로커·런타임 조회 검사를 통과했으며 추가 재시작은 없었다. 12:44 실사용 새 흐름 3개에서 대상 4종 경보는 0건이나 ET `2034806`·`2034802` 각 2건은 남았다. 두 ET SID 분석·별도 검증/승인, 수정 helper 자동 적용·실제 실패 복구 E2E와 장기 관찰은 남은 작업이다.
- **2026-10-13 13:18~13:24 후속:** 두 ET SID의 좁은 예외가 새 지정 승인 후 자동 적용됐다. 로컬 `cabbac45…`·합본 `ea160e90…`·ET 불변, 실제 로드 52,497건(고유 SID 52,495개)·failed/skipped 0을 확인했다. 13:24 후속 조회의 새 LLM HTTP 200 응답 2건에서 경보는 0건이다. 수정 helper의 자동 적용 E2E와 이 실사용 표본은 확인됐으며, 실제 실패 복구 E2E·장기 재발 관찰은 남는다.
