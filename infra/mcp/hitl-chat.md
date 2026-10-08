# HITL 채팅 채널 설계 — 온프레미스 Mattermost (오프라인, 양방향 웹훅)

Slack은 이 망에서 불가(아웃바운드 443 차단, 2026-09-27 실측). 대신 **자체 호스팅 채팅**을 내부망에 두면 Slack과 같은 UX를 인터넷 0으로 재현한다. 자체 호스팅이라 웹훅이 **양방향**으로 동작한다:
- **나가는 방향(알림)** = incoming webhook: 우리 서비스 → Mattermost 채널.
- **들어오는 방향(승인/명령)** = interactive message buttons / outgoing webhook / slash command: 운영자 클릭 → 우리 내부 엔드포인트.

둘 다 목적지가 내부 IP라 캠퍼스 방화벽/443 egress와 무관하다.

## 왜 Mattermost
- 자체 호스팅(Docker), incoming/outgoing webhook + **interactive message buttons**(승인/거부) + slash command + bot API 지원. air-gapped 배포 문서 존재.
- **Hermes 에이전트에 Mattermost 인터랙티브 승인 버튼이 이미 구현**(NousResearch/hermes-agent PR #29373, issue #27587) → 런타임=Hermes면 승인 창구가 사실상 내장.
- 대안: Rocket.Chat(유사). 초경량이 필요하면 채팅 없이 "승인 인박스" 웹페이지도 가능하지만 사용자가 채팅 형태를 원함.
- ⚠️ 무료판의 **모바일 푸시**는 Mattermost 호스티드 프록시(인터넷) 필요 → 우리는 안 씀. **웹/데스크톱 클라이언트는 완전 오프라인 동작**. 2026-10-08 DuckDNS 채팅 이름에 Let's Encrypt 인증서를 적용해 Mac의 HTTPS 검증을 통과했다. 사용자의 휴대폰 GlobalProtect 로그인은 실패했고 원인은 미확인이다. 현재는 A에 도달하는 학교 내부 Wi-Fi에서 실제 Mattermost 앱 로그인을 시험해야 한다. 앱 접속과 푸시 알림은 별개다.

## 구성 요소
- **Mattermost 서버 + PostgreSQL** (Docker, 오프라인 이미지 반입 — 기존 방식과 동일). 배치 후보: **Groot_B**(디스크 145G 여유) 또는 소형 전용 VM. 내부망 전용(10.200.10.x), 접근은 대시보드처럼 A 점프(`ssh -L`).
- **알림**: 이미 완성 — `notifier.py` http 백엔드가 Mattermost incoming webhook URL로 POST. `/etc/resp/hitl.env` 에 `RESP_NOTIFY_BACKEND=http` + `RESP_NOTIFY_URL=<webhook>` 한 블록.
- **승인 브로커**(Tier 2에서 추가): 내부 소형 HTTP 리스너(B). Mattermost 버튼 클릭의 action 콜백을 받아 (a) 클릭 사용자 검증(허용 승인자 목록), (b) request-id 별 결정(승인/거부) 저장. 응답 MCP 서버는 고위험 동작 시 request-id 생성→버튼 메시지 게시→브로커 결정 대기→진행/중단.

## 두 단계로 나눠 도입
**Tier 1 — 알림 피드(지금 바로, 저비용)**
- Mattermost 세우고 채널 하나 + incoming webhook 생성 → `hitl.env` http 로 스왑.
- 모든 SOC 이벤트(경보, 자동/정책 차단, 거부, 리로드)가 채팅에 흐른다. 승인은 런타임(터미널/Hermes)에서.
- 이미 만든 것으로 대부분 커버. 남는 작업 = Mattermost 배치 + 웹훅 URL 등록.

**Tier 2 — 채팅 내 인터랙티브 승인(Slack급)**
- 고위험 동작에 [승인][거부] 버튼. 클릭 → 브로커 → 결정.
- 런타임=**Hermes**면 내장 기능 활용(브로커 대부분 불필요). 런타임=**Claude Code**면 (a) 터미널 elicitation 그대로 쓰거나 (b) ~50줄 브로커 추가.

## 승인 흐름 (Tier 2)
```
Agent(고위험 판단) → 응답 MCP 서버: request-id 생성
  → Mattermost incoming webhook 로 "X 차단 승인?" + [승인][거부] 버튼 게시
운영자 클릭 → Mattermost → (outgoing/action) → 승인 브로커(B, 내부 HTTP)
  → 승인자 검증 + request-id 결정 저장
응답 서버: 결정 폴링/수신 → 승인이면 agent_block, 거부면 중단 → 결과를 채널에 회신
```
모든 화살표가 내부망(10.200.10.x) — 인터넷 불필요.

## 교체 용이성(기존 원칙 유지)
- 알림 대상 교체 = `hitl.env` 의 URL 한 줄(Mattermost↔Rocket.Chat↔사내웹훅↔이메일).
- 승인 창구 교체 = 런타임의 HITL 설정(터미널↔Mattermost) — 서버는 채널을 모름(elicitation).
- Slack이 나중에 열리면(443 허용) backend=slack 한 줄로.

## 참고
- Mattermost interactive messages: https://developers.mattermost.com/integrate/plugins/interactive-messages/
- Incoming webhooks: https://docs.mattermost.com/integrations-guide/incoming-webhooks
- Outgoing webhooks: https://docs.mattermost.com/integrations-guide/outgoing-webhooks.html
- 컨테이너 배포: https://docs.mattermost.com/deployment-guide/server/deploy-containers
- Hermes 인터랙티브 승인: NousResearch/hermes-agent PR #29373 / issue #27587

## 상태 (2026-09-27 갱신)
- **Tier 1 배치 완료(B)**: Mattermost TE 11.11.1 + PostgreSQL 16(오프라인 반입), 팀 `soc`/채널 `soc-alerts`, incoming webhook 생성, A `/etc/resp/hitl.env`=http 연동. **실 검증**: `ssh -T groot-resp` block/unblock → `soc-alerts` 채널 게시 확인. 브라우저 `ssh -N groot-mm`→http://localhost:18065(로그인 200). 배치: `infra/groot-b/{mattermost-compose.yml, deploy_mattermost_B.sh}`. 계정/웹훅/비번은 CREDENTIALS.local.md.
### SOC 챗봇/에이전트 상호작용 (2026-09-27)
- **에이전트 보고**: `soc_bot.py report [분]` → 최근 경보를 조사(인덱서 mcp-ro)해 **인시던트 보고서(첨부)** 를 채널에 게시(SOC-Agent 명의). 규칙 트리거 후 실측 게시.
- **대화형 챗봇**: Mattermost 슬래시 명령 **`/soc`** → B의 `soc-bot` 서비스(soc_bot.py serve, systemd, socbot 사용자). `/soc alerts [분] | agents | vulns [id] | status | report [분] | help`. 읽기전용(mcp-ro), 토큰 검증. block 등 대응은 응답 MCP(groot-resp)로 분리 유지.
  - 도달 경로: MM(컨테이너)→봇 콜백은 mm-net 게이트웨이 `http://172.19.0.1:8090`, 봇은 0.0.0.0:8090. **MM SSRF 보호** 때문에 `MM_SERVICESETTINGS_ALLOWEDUNTRUSTEDINTERNALCONNECTIONS` 에 172.19.0.1 필요(compose에 설정). `EnableCommands=true`.
  - 배치: `infra/mcp/{soc_bot.py, deploy_socbot_B.sh, soc_bot.env.example}`. 실측: `/soc status|alerts|agents|vulns` 응답 확인.
  - NL(자연어) 대화는 LLM 런타임(Claude/Hermes) 연결 후. 지금은 명령형 봇(오프라인 동작).
- **주기 인시던트 보고**: B `soc-report.timer`(systemd, 기본 hourly / window 60분) → `soc_bot.py report` → 채널 게시. **경보 0이면 게시 안 함**(스팸 방지). 수동 `/soc report [분]`.
- **정기 상태 요약(heartbeat)**: B `soc-summary.timer`(하루 2회, `OnCalendar=*-*-* 09,21:00:00 Asia/Seoul`, Persistent) → `soc_bot.py summary 12` → **이상 없어도 항상 게시**(🟢 이상없음 / 🟡 관찰 / 🔴 주의; 에이전트 active·최근 12h 경보·상위규칙·취약점). 수동 `/soc summary [시간]`. 주기/시각은 타이머 유닛에서 조정(SUMMARY_ONCAL/SUMMARY_HOURS). 2026-10-06 A/B/C 호스트 KST·NTP 동기화를 확인했고 B `soc-bot`은 최근 경보 시각을 KST로 표시한다. Mattermost 컨테이너는 `TZ=Asia/Seoul` 재생성 후 healthy를 확인했다. 다른 컨테이너 내부 시계 표시는 UTC일 수 있다.

- **이후 진행**: 2026-09-28 Hermes의 MCP 2서버 17툴 등록, NL 대화 및 Tier 2 승인 브로커의 차단 E2E를 검증했다(아래 절). 라이브 응답 MCP는 `trust: full`이며 서버측 브로커가 고위험 `block_ip` 승인과 거부/만료 시 미실행을 강제한다. `/soc block` 슬래시 명령은 별도 범위다.
- 포트: **A:443 nginx 리버스 프록시(chatproxy) → B:8065**. 내부 바인드 10.200.10.10:8065. 모바일 푸시(인터넷 필요)는 미사용이고 모바일 앱 로그인은 실기기 미검증.

### VPN·캠퍼스 클린 접속 — A:443 이름 기반 리버스 프록시 (2026-09-27 확정)
Mattermost 웹소켓은 **Origin == SiteURL** 일 때만 수락(그 외 403, 실측). 사용자 제약(루프백 사용 불가)으로 클라이언트 터널은 배제 → **A:443 nginx 리버스 프록시**로 해결:
- `https://chat.groot.lab`(443) → A nginx(chatproxy) → B:8065. SiteURL/AllowCorsFrom = `https://chat.groot.lab` → Origin 일치 → **웹소켓 101(VPN·캠퍼스 모두 실측)**.
- `/etc/hosts` 는 어디서나 `192.168.16.230 chat.groot.lab` 동일(루프백/터널 불필요). 데스크톱 앱 서버도 `https://chat.groot.lab` 하나. 자체서명 인증서 1회 신뢰.
- 맨 IP(`https://192.168.16.230/`)·다른 Host 는 444(무응답). 구성 `infra/groot-a/chatproxy*`(nginx:1.27-alpine 오프라인). 구 A:8065 DNAT·터널(groot-mm/groot-chat) 제거.
- ⚠️ MM 은 plain http(8065) 유지(ConnectionSecurity 빈값), nginx 가 TLS 종단 + `X-Forwarded-Proto https`. compose env 변경은 `docker compose up -d --force-recreate` 로 적용(up 만으론 재생성 안 됨 — 실측 함정).

### 관리포털(Wazuh 대시보드)도 같은 프록시에 (2026-09-28)
- 학과망(192.168.12.x)에서 A:10443 이 캠퍼스 FW 에 막히고(22/80/443 만 통과, VPN 과 동일 정책 실측) 운영자가 루프백 터널을 못 쓰는 제약 → **chatproxy 에 `wazuh.groot.lab` 서버블록 추가**: `https://wazuh.groot.lab` → B:443(HTTPS 백엔드, `proxy_ssl_verify off`). 인증서는 `tls/wazuh.*` 로 분리(채팅 인증서·데스크톱 앱 재신뢰 불필요).
- **출발지 allowlist**(nginx `allow/deny`): 학과망 192.168.10.0/24(2026-09-29 추가 — 학과망 PC 가 이 대역으로도 배정됨, 403 실측 후 반영) · 192.168.12.0/24 · VM세그먼트 192.168.16.0/24 · 내부망 10.200.10.0/24 만 허용, 그 외(VPN 192.168.15.0/24·외부 211.x) 403 → "대시보드는 VPN 으로 접근되면 안 됨" 결정 유지. A 는 클라이언트 IP 를 NAT 없이 그대로 본다(실측).
- 실측(학과망 PC): `/`→302 `/app/login`, `/app/login`→200(Wazuh/OpenSearch), 채팅 회귀 200, 맨 IP 444. 배치: `infra/groot-a/{chatproxy.nginx.conf, deploy_chatproxy_A.sh}`(V4/V5 검증 추가; V2 웹소켓 curl 의 `set -e` 조기종료 버그 수정).
- 미검증: VPN 출발지 403 은 VPN 이 끊긴 상태라 실측 못 함 → VPN 재연결 시 `https://wazuh.groot.lab` 가 403 인지 확인할 것.

### 팀원 무설정 접속 이름 추가 (2026-09-28)
- `https://chat.grootlab.duckdns.org`(DuckDNS 공개 DNS → 192.168.16.230) 를 chatproxy 에 별도 블록/인증서로 추가. Mattermost `SiteURL` 은 이 이름(대표, 링크 생성용), `AllowCorsFrom` 은 `https://chat.groot.lab https://chat.grootlab.duckdns.org` → **두 Origin 모두 웹소켓 101 실측**(기존 hosts 사용자·데스크톱 앱 무영향). `docker compose up -d --force-recreate mattermost` 로 앱만 재생성(33s healthy).

### LLM 연결 완료 — Hermes ↔ DGX Spark (2026-09-28)
- DGX Ollama 새 주소 211.170.162.110/.111:11434 가 VM 에서 도달(이전 .100/.101 은 불통이었음). Hermes(B)를 `custom` 프로바이더 `http://211.170.162.110:11434/v1`, 모델 `qwen3.6:35b`(256k ctx 상주) 로 설정 → **MCP 툴 호출 포함 E2E 응답 확인**. 이제 NL 에이전트·경보 트리거·Tier 2(응답툴 승인, `trust: untrusted`) 구현이 가능.

### Tier 2 완성 — 채팅 승인 버튼 + Hermes 게이트웨이/경보 트리거 (2026-09-28)
- **Hermes 게이트웨이**: B 상주 컨테이너 `hermes`(`gateway run`, `/opt/hermes-data`). Mattermost 플러그인(env `MATTERMOST_URL/TOKEN/ALLOWED_USERS/HOME_CHANNEL/ALLOWED_CHANNELS/REQUIRE_MENTION/FREE_RESPONSE_CHANNELS`)이 봇 `@hermes`로 웹소켓 연결. 채널: `soc-agent`(멘션 없이 자연어 대화), `soc-alerts`(보고·승인, `@hermes` 멘션 시만 응답). 실측: 상태 질문에 MCP 툴로 조회해 한국어 답변.
- **경보 트리거(cron `soc-alert-watch`)**: 5분마다 `--monitor-script recent_alerts.sh`(soc_bot `GET /recent` 지문: 최근 60분 level≥10 최신 5건)를 돌려 **바뀔 때만** LLM 조사 실행 → `soc-alerts`(HOME_CHANNEL)에 인시던트 보고, 내부 잡음이면 `[SILENT]`. 프롬프트 `infra/hermes/soc_alert_watch.prompt`. 배치 `infra/hermes/deploy_gateway_B.sh`.
- **승인 브로커(soc_bot, B:8090)**: 응답 서버(A)의 `block_ip` → `POST /approval`(X-Broker-Token) → soc_bot 이 웹훅으로 [승인][거부] 버튼 카드 게시(콜백 `http://172.19.0.1:8090/actions`, 요청별 nonce) → 운영자 클릭 → `APPROVERS` 검사·결정 저장·카드 갱신 → A 가 `GET /decision/<id>` 폴링(최대 600s) → 승인 시 `agent_block`, 거부/만료/오류는 미실행. 이 승인 경로는 2026-09-28 무인 실행(cron)에서도 검증했다. Hermes 쪽 `resp` 는 `trust: full`, `timeout: 720`(승인은 서버측). `list_blocks` 는 `readOnlyHint` 로 승인 불필요.
- **2026-10-08 코드 재확인·후속 배포:** `RESP_BROKER_URL` 또는 토큰이 비면 `block_ip`가 승인 없이 실행되고, `APPROVERS`가 비면 승인자를 제한하지 않는다. `unblock_ip`에도 승인 단계가 없다. 별도 룰 변경 기능은 전용 토큰·명시적 승인자·콜백 출처·제안 해시 결속·일회성 소비를 강제하고 A↔B 승인 API에 nonce와 양방향 HMAC을 사용한다. 약 12:58 KST B 브로커·A/B 전용 변경기/worker·Hermes의 `rule-a`·`rule-b`를 배포해 HMAC·읽기 대상 조회를 확인했다. 운영 룰 해시는 그대로이며 **실제 Mattermost 승인→룰 적용 E2E는 미검증**이다. 룰 변경 기능은 기존 IP 차단 경로의 제약을 해결하지 않는다.
- **E2E 실측**: `soc-agent`에 "203.0.113.9 를 1분간 차단" → Hermes `block_ip` → 카드 게시(3s) → 승인 → A 차단(TTL 60s) → Hermes 회신 "BLOCKED … (approved by socadmin)". 브로커 단위 검증: 권한 없는 사용자 거부·중복 클릭 방지·잘못된 nonce 거부.
- 주의: Mattermost 는 API 로 게시물을 돌려줄 때 버튼 콜백 컨텍스트를 제거하므로 자동 테스트는 브로커의 `/pending`·`/nonce`(브로커 토큰) 로 클릭을 시뮬레이션한다. soc_bot 8090 은 A(10.200.10.10)·MM 컨테이너(172.19.0.1) 양쪽에서 닿아야 하므로 0.0.0.0 바인드 유지(토큰 인증).
- 비밀 위치: 봇 토큰 B `/opt/hermes-data/.env`, 브로커/읽기 토큰 B `/etc/socbot/soc_bot.env` + A `/etc/resp/hitl.env`. 문서에 값 없음.

### 답변 품질 조정 (2026-09-28 저녁)
- **증상**: 자연어 질문에 Hermes 가 툴을 부르지 않고 추론만 하다 멈추거나(agent.log `Reasoning-only clean stop`) 가짜 결과(`<status>` 태그, 존재하지 않는 경보)를 내놓음. DGX 에 직접 물으면 12/12 툴 호출 정상 → Hermes 의 **tool_search 브리지(MCP 툴을 검색→설명→호출 3단계로 숨김)** 와 큰 시스템 프롬프트가 원인.
- **조치**: `tools.tool_search.enabled: off`(툴 스키마 24→54개 즉시 노출) + `SOUL.md` 에 "한국어 설명 / 툴명·IP·규칙id·에러원문·경로·명령은 원문 백틱 / 툴 결과에 없는 원인 추측 금지 / 승인 결과 그대로 보고" 규칙(`infra/hermes/SOUL.groot.md`) + cron 프롬프트 동일 규칙. 재검증: 상태 요약·차단목록+경보 설명 모두 실제 툴 호출, 한국어+식별자 원문, 없는 필드는 "포함되지 않음"으로 정직 보고.
- 알려진 한계: 읽기 서버의 `get_wazuh_alert_summary` 는 rule.id 를 안 돌려줌(서버 형식) → 규칙 id 가 필요하면 `search_wazuh_manager_logs`/인덱서 조회 툴 보강 검토.

### 보안 이벤트 전용 읽기 MCP·KST 적용 (2026-10-06)
- B에 `security-events-mcp.py`를 배치했다. `ssh -T groot-mcp security-events`의 2툴 목록과 `search_suricata_alerts`·`search_modsecurity_alerts`의 실제 인덱서 조회가 계약 테스트를 통과했다. 기존 `ssh -T groot-mcp`의 14툴도 회귀 검증했다. 새 도구는 이미 인덱싱된 Wazuh 경보의 제한된 필드만 KST 시각으로 반환하며, Suricata EVE·ModSecurity 감사 원본이나 장비 설정은 읽지 않는다.
- 읽기 전용 결과에서 Suricata 로컬 SID `1000010`→Wazuh `100110`, ModSecurity CRS `920350`→Wazuh `100101`을 확인했다. WAF는 `DetectionOnly`다. GROOT 커스텀 WAF ID `10100`대의 발화와 시나리오별 공격 재현은 아직 확인하지 않았다.
- Hermes 실설정에서 보안 이벤트 서버를 세 번째 MCP 서버로 등록하고 컨테이너 재시작 후 `hermes mcp list`의 3서버 enabled를 확인했다. `hermes chat -q` LLM 대화에서도 `mcp__security_events__search_suricata_alerts`(최근 60분, SID `1000010`→Wazuh `100110`)와 `mcp__security_events__search_modsecurity_alerts`(최근 24시간, CRS `920350`→Wazuh `100101`)를 각각 실제 호출했다. 서버 계약 테스트와 LLM 호출 검증을 모두 통과했다.
