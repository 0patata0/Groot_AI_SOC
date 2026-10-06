# MCP 계층 — 에이전트/LLM 교체가 쉬운 구조 (pluggable agent)

원칙: **MCP 서버는 클라이언트 불가지론(client-agnostic)**. 어떤 AI(에이전트 런타임·LLM API)가 붙는지는 서버가 모른다. "무엇을 붙일지"는 **클라이언트 설정 한 블록**에만 존재한다. 따라서 에이전트/LLM을 바꿔도 서버(툴·자격증명·권한·정책)는 그대로다.

```
[LLM API]         Claude API | OpenAI | Ollama(Qwen)      <- 런타임 provider 설정
      ^
[에이전트 런타임]   Claude Code | Claude Desktop | Hermes | 커스텀   <- MCP 클라이언트 설정
      ^   MCP 표준 (stdio | HTTP streamable)
[MCP 서버 @Groot_B]  Wazuh 읽기 14툴 + 보안 이벤트 읽기 2툴; 응답 서버는 A에서 block_ip -> nft agent_block
      ^
[Wazuh API/Indexer @B, nftables @A]
```

## 교체 지점
| 바꾸고 싶은 것 | 어디를 고치나 | 서버 변경 |
|---|---|---|
| LLM API | 에이전트 런타임의 provider 설정(모델/엔드포인트/키) | 없음 |
| 에이전트 런타임 | 그 런타임의 MCP 클라이언트 설정(명령 또는 URL) | 없음 |
| 전송(stdio↔HTTP) | 서버 기동 방식(플래그/서비스) | 툴·자격증명 동일 |
| **알림 채널**(HITL notify) | A `/etc/resp/hitl.env` 의 `RESP_NOTIFY_BACKEND` + 엔드포인트 1블록 | 없음(코드·정책 불변) |
| **승인 창구**(HITL approve) | **Tier 2 구현: 응답 MCP→soc_bot 브로커(`RESP_BROKER_URL`)→Mattermost [승인]/[거부] 버튼**(승인 시만 실행, fail-closed). 원 설계는 MCP elicitation | 없음(브로커 URL 1블록, 서버 코드는 채널을 모름) |

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
**Hermes** (B 의 Docker 컨테이너, `/opt/hermes-data/config.yaml` = 컨테이너 `/opt/data/config.yaml`; 아래는 `infra/hermes/config.example.yaml` 템플릿):
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
    trust: full         # 라이브는 응답 MCP의 승인 브로커가 쓰기 툴 승인을 강제
    # HTTP 전환 시: url: "http://10.200.10.10:8080/mcp", headers: {Authorization: "Bearer ${env:SOC_MCP_TOKEN}"}
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

### 알림/승인 채널도 교체 용이(엔드포인트만)
읽기·응답 서버와 같은 원칙을 HITL 에도 적용 — **두 층으로 분리**:
- **승인(approve)** = **Tier 2 완료(2026-09-28)**: 응답 MCP `request_approval()` 이 soc_bot 브로커(`RESP_BROKER_URL`)를 폴링, 브로커가 Mattermost 에 [승인]/[거부] 카드를 띄우고 승인 시에만 `block_ip` 실행(거부/만료=미실행, fail-closed). *어디에* 띄울지는 브로커/런타임이 정하므로 서버 코드는 채널을 모름(원 설계 MCP elicitation 원칙 유지). 상세 [hitl-chat.md](hitl-chat.md).
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
