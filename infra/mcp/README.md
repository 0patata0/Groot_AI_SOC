# MCP 계층 — 에이전트/LLM 교체가 쉬운 구조 (pluggable agent)

원칙: **MCP 서버는 클라이언트 불가지론(client-agnostic)**. 어떤 AI(에이전트 런타임·LLM API)가 붙는지는 서버가 모른다. "무엇을 붙일지"는 **클라이언트 설정 한 블록**에만 존재한다. 따라서 에이전트/LLM을 바꿔도 서버(툴·자격증명·권한·정책)는 그대로다.

```
[LLM API]         Claude API | OpenAI | Ollama(Qwen)      <- 런타임 provider 설정
      ^
[에이전트 런타임]   Claude Code | Claude Desktop | Hermes | 커스텀   <- MCP 클라이언트 설정
      ^   MCP 표준 (stdio | HTTP streamable)
[MCP 서버 @Groot_B]  읽기 서버(wazuh) + 응답 서버(block_ip -> A nft agent_block)   <- 자격증명은 여기만
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
| **승인 창구**(HITL approve) | MCP elicitation — 런타임/클라이언트가 표시(터미널·온프레미스 채팅 등) | 없음(서버는 채널을 모름) |

## 전송 계약
- **1차(지금): stdio over SSH** — 클라이언트가 `ssh -T groot-mcp`를 MCP 명령으로 실행(원격 명령 인자 없음: B의 sshd `Match User mcp` ForceCommand + authorized_keys `restrict,command=`가 래퍼 `/opt/mcp/run-wazuh-ro.sh`를 강제). 서버 프로세스는 **B에서** 뜨고, Wazuh 자격증명은 B의 `/etc/mcp/wazuh-ro.env`에만 → 클라이언트 호스트(Mac 등)에 자격증명 없음(A안). Claude Code·Claude Desktop·Hermes 모두 지원. 빌드 불필요(릴리스 바이너리 stdio 전용). 클라이언트 키(`~/.ssh/groot_mcp_ed25519`)는 A에서는 B:22 점프 전용(`restrict,permitopen`), B에서는 mcp 계정 래퍼 전용.
- **확장: HTTP(streamable)** `http://10.200.10.10:8080/mcp` + `Authorization: Bearer <token>` — 프로세스를 못 띄우는 원격/커스텀 API 클라이언트용. `mcp-server-wazuh`를 `--features http`로 빌드해 B에 systemd 서비스로 상주(전용 사용자, `127.0.0.1` 또는 내부 IP 바인드). 같은 코드·같은 툴.
- 어느 쪽이든 **툴 목록·자격증명·권한은 동일** → 클라이언트 교체 비용 = 설정 1블록.

## 서버 측(B) 배치 원칙
- 바이너리: `gbrigandi/mcp-server-wazuh` v0.3.0 (리뷰 커밋 969f36f와 동일, sha256 `8a18cb44…`, 읽기전용 14툴). `/opt/mcp/mcp-server-wazuh` (root:mcp 0750)
- 래퍼 `/opt/mcp/run-wazuh-ro.sh` (root:mcp 0750): `set -a; . /etc/mcp/wazuh-ro.env; set +a; exec /opt/mcp/mcp-server-wazuh` — env 파일은 **root:mcp 0640(mcp 읽기만, 수정 불가)**, 내용은 **읽기전용 계정 `mcp-ro`**(Wazuh API role `readonly` / 인덱서 backend_role `readall`)뿐. 비밀은 repo·CREDENTIALS 파일에도 두지 않음(B의 env 파일이 유일, 분실 시 관리자가 재설정).
- 전용 사용자 `mcp`(시스템 계정, 비밀번호 없음) + sshd `Match User mcp`(ForceCommand·PermitTTY no·포워딩 금지·비밀번호 인증 금지) + authorized_keys `restrict,command=` 이중 강제. authorized_keys는 root:mcp 0640 이라 mcp 계정 자신도 제한을 풀 수 없음.
- 배치 스크립트 `deploy_mcp_B.sh`(게이트형, 비밀은 stdin 주입): 계정 생성 → `internal_users.yml` 동기화(securityadmin 재적용 대비) → sshd → **읽기전용 실증**(툴이 쓰는 API 엔드포인트 전부 200, 쓰기 403; 인덱서 read 200·write 403) → env 원자적 교체 → **계약 테스트를 mcp 사용자로 실행**(tools/call 로 실제 자격증명 검증).
- 응답 서버(차단)는 **별도 프로세스·별도 자격증명**(A의 nft `agent_block` 제어) + Policy Engine 내장. 읽기 서버와 분리 = 최소권한.

## 클라이언트 설정 템플릿 (비밀 없음)
**Claude Code** (프로젝트 `.mcp.json` 또는 `claude mcp add`):
```json
{ "mcpServers": { "wazuh-ro": { "type": "stdio", "command": "ssh", "args": ["-T", "groot-mcp"] } } }
```
(`claude-code.mcp.json.example` 참고. 원격 명령 인자는 두지 않는다 — 어차피 ForceCommand가 무시한다.)
**Hermes** (B 의 Docker 컨테이너, `/opt/hermes-data/config.yaml` = 컨테이너 `/opt/data/config.yaml`; 실배치본 `infra/hermes/config.example.yaml`):
```yaml
mcp_servers:
  wazuh-ro:
    command: ssh
    args: ["-T", "-F", "/opt/data/home/.ssh/config", "mcp-b"]   # Host mcp-b = mcp@10.200.10.10, 키·known_hosts 는 /opt/data/home/.ssh
    env: { HOME: /opt/data/home }
    trust: full
  resp:
    command: ssh
    args: ["-T", "-F", "/opt/data/home/.ssh/config", "resp-a"]  # Host resp-a = resp@10.200.10.1
    env: { HOME: /opt/data/home }
    trust: untrusted    # 쓰기 툴은 사람 승인
    # HTTP 전환 시: url: "http://10.200.10.10:8080/mcp", headers: {Authorization: "Bearer ${env:SOC_MCP_TOKEN}"}
```
검증(LLM 불필요): `infra/hermes/deploy_hermes_B.sh test` — 컨테이너 안 계약 테스트 + `chat -q` 기동 후 agent.log 의 `MCP: registered 17 tool(s) from 2 server(s)`(2026-09-28 실측). 이미지 v2026.9.24 에는 mcp[cli](typer) 가 없어 `hermes mcp test` 는 안 됨. 컨테이너 키는 B `/opt/mcp/.ssh/authorized_keys`·A `/opt/resp/.ssh/authorized_keys` 에 Mac 키와 같은 `restrict,command=` 접두로 등록됨(2026-09-28).
어느 클라이언트든 그 호스트에 `~/.ssh/config`의 `groot-mcp` 블록(키·ProxyJump·BatchMode)과 키 파일만 있으면 된다. 다른 호스트에서 쓰려면 그 호스트용 키를 만들어 B `/opt/mcp/.ssh/authorized_keys`(같은 `restrict,command=` 접두)와 A `~groot_a/.ssh/authorized_keys`(점프 전용 접두)에 추가.
**커스텀/원격(HTTP)** — Python `mcp` SDK: `streamablehttp_client("http://10.200.10.10:8080/mcp", headers={"Authorization": "Bearer ..."})` → `list_tools()` / `call_tool("get_wazuh_alert_summary", {...})`.

## AI와 무관한 검증(서버 계약 테스트)
어떤 AI를 붙이기 전에 표준 클라이언트로 서버를 먼저 검증한다: `contract_test.py`(표준 라이브러리만, 오프라인) — `python3 infra/mcp/contract_test.py --cmd "ssh -T groot-mcp" --tool get_wazuh_alert_summary --args '{"limit":3}'` → initialize/tools/list/tools/call + stdout 순수성 검사. (`npx @modelcontextprotocol/inspector`나 Python `mcp` SDK도 동일하게 쓸 수 있다.) 통과하면 "서버는 검증됨"이고, 이후 런타임 교체는 클라이언트 설정만 바꿔 같은 호출을 재현하면 된다. B에도 `/opt/mcp/contract_test.py`가 있어 서버 로컬에서 `runuser -u mcp`로 재검증 가능.

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
- **승인(approve)** = MCP **elicitation**. 서버는 "사람 승인 필요"만 요청하고, *어디에* 띄울지는 런타임/클라이언트가 정함 → 서버는 채널을 모름(가장 강한 분리). 터미널(Claude Code)·온프레미스 채팅 등 무엇이든.
- **알림(notify/감사 푸시)** = `notifier.py`(stdlib) 백엔드 추상화. `/etc/resp/hitl.env` 의 `RESP_NOTIFY_BACKEND`(none|http|email|slack) + 엔드포인트만 바꾸면 채널 교체(코드·정책·서버 불변). run-response.sh 가 세션마다 이 파일을 source → **재시작 없이** 다음 연결부터 반영. 예시 `hitl.env.example`.
  - `http`: 내부 Mattermost/Rocket.Chat incoming webhook 또는 사내 웹훅(내부망) — 권장. **채팅 채널 상세 설계(양방향 웹훅·인터랙티브 승인)는 [hitl-chat.md](hitl-chat.md)**.
  - `email`: 이 망은 아웃바운드 587 열림.
  - `slack`: ⚠️ 아웃바운드 443 전면 차단(2026-09-27 실측)이라 이 망에선 불가. 나중에 443 열리면 backend 만 slack 으로.
  - best-effort: 알림 실패는 stderr 로그만, block/unblock 결과(툴 응답)에 영향 없음. stdout(프로토콜) 불침범.
- 검증(2026-09-27): `hitl.env` 를 http 로 바꾸고 내부 sink 로 block/unblock 알림 수신 확인 → 다시 none 으로 복원. 기본은 none(알림 off, 기존 동작 동일).

## 상태 (2026-09-27)
- 읽기 서버(B, `groot-mcp`) + 응답 서버(A, `groot-resp`) **둘 다 배치·계약 테스트 완료**.
- 에이전트 런타임 선택: **보류**(Hermes vs Claude Code vs 기타). 결정 후 두 블록(`groot-mcp` 읽기 + `groot-resp` 응답)만 클라이언트에 등록하면 됨 — 서버는 그대로.
