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

## 승인형 규칙 변경 MCP — 저장소 구현, 라이브 미배포 (2026-10-08)
2026-10-08 11:46 KST 라이브 MCP 목록에는 B의 읽기 16툴과 A의 IP 차단 응답 3툴만 있었다. 이후 **저장소에** 별도 승인형 변경 경계를 구현했다. 아래는 코드·오프라인 테스트 상태이며, 서버 배치·Hermes 등록·실제 승인 클릭·운영 룰 변경을 완료했다는 뜻이 아니다.

- 대상은 A의 `GROOT_A_WAF.conf`·`GROOT_A_local.rules`와 B의 Wazuh `local_rules.xml` 세 로컬 룰 파일로 고정했다. `get_rule_change_target`이 현재 전문·SHA-256·컨테이너 상태를 조회하고, `propose_rule_change`가 조회 시점 해시와 전체 후보 파일을 받아 diff·영향·검증 상태를 보여주고 Mattermost 승인을 요청한다. `get_rule_change_status`로 거부·만료·적용·복구 결과를 확인한다. 임의 경로·셸 명령·nft 정책·WAF 차단 모드·Suricata 인라인/drop 전환은 노출하지 않는다.
- `rule_change_mcp.py`는 전용 SSH 사용자로 실행하고, root 소유 `rule_change_executor.py`의 **인자 없는 고정 sudo 명령**만 호출한다. 읽기 MCP의 권한은 올리지 않는다. 실행기는 호스트/대상 허용목록, 컨테이너 마운트·원본 해시, WAF DetectionOnly·Suricata passive 상태를 검사한다. 승인 전 Suricata 후보는 임시 결합 파일로 `suricata -T`를 시험하며, WAF/Wazuh는 구조 검사 후 승인된 적용 단계에서 엔진 구문 검사를 수행한다. 임시 Suricata 검증 파일은 활성 `all.rules`를 교체하지 않고 검사 후 삭제한다.
- `soc_bot.py`의 **별도 룰 승인 API**는 전용 토큰·명시적 승인자·Mattermost 콜백 출처를 필수로 한다. 카드에는 변경 전/후 SHA-256과 전체 diff·영향·사유·만료 시각을 표시하며, 표시 한도를 넘으면 제안을 거부한다. 승인된 정확한 변경안 digest를 1회 소비하고, 실행 직전 원본·ET/결합 룰 상태를 다시 비교한다. 변경 백업, WAF 단일 파일 bind inode 보존, Suricata 결합 룰 재작성, Wazuh manager 재시작, 엔진 검사·읽기 해시·프로세스 상태 검사, 실패 시 복구와 결과 카드 게시를 구현했다. 브로커 장애·설정 누락·거부·만료·해시 불일치는 적용하지 않는다.
- 배치 순서: B의 브로커 코드/전용 토큰·승인자·Mattermost 출처 설정 → A/B의 `deploy_rule_change_{A,B}.sh`로 전용 사용자·SSH 강제 명령·sudoers·root 전용 상태/백업·10초 worker 설치 → 전용 키로 SSH 계약 테스트 → B Hermes 설정과 SOUL의 룰 변경 지침 등록. 배치 스크립트와 구체적 명령은 이 절과 스크립트 주석을 함께 검토한다. 배포 전 세 장비의 라이브 경로·마운트·모드를 다시 확인한다.
- 실제 실행 순서와 점검 명령은 [rule-change-deploy.md](rule-change-deploy.md)에 정리했다. A↔B 승인 API는 HTTP 위에 일회성 nonce와 요청·응답 HMAC을 적용해 승인 위조를 막는다. HTTP 본문 내용의 기밀성은 제공하지 않으므로 후보 룰에 비밀 값을 넣지 않는다.
- **남은 검증/한계:** 오프라인 테스트는 라이브 버튼 클릭·룰 적용을 대신하지 않는다. 브로커는 승인 상태를 메모리에 두므로 재시작하면 대기/승인 건은 소실되어 적용이 중단된다. 승인 소비 뒤 브로커가 재시작되면 실행기 로컬 결과는 남아도 Mattermost 결과 카드가 누락될 수 있다. 승인 후 적용 전 원본·마운트 드리프트로 중단되면 변경기는 `/abort`로 승인권을 폐기하고 실제 읽기 해시와 미적용 사유 카드를 게시한다. 브로커 장애로 카드 게시가 실패하면 로컬 상태에 미적용 결과가 남고, 같은 보고를 제한 횟수만 재시도한다. Hermes가 실제 사람 발화를 했는지는 MCP가 독립적으로 인증하지 못하므로 SOUL/자동 경보 프롬프트에서 자발적 제안을 금지하고, 서버에서는 지정 승인자의 버튼 클릭을 최종 강제한다.
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
