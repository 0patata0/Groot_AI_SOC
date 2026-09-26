# HITL 채팅 채널 설계 — 온프레미스 Mattermost (오프라인, 양방향 웹훅)

Slack은 이 망에서 불가(아웃바운드 443 차단, 2026-09-27 실측). 대신 **자체 호스팅 채팅**을 내부망에 두면 Slack과 같은 UX를 인터넷 0으로 재현한다. 자체 호스팅이라 웹훅이 **양방향**으로 동작한다:
- **나가는 방향(알림)** = incoming webhook: 우리 서비스 → Mattermost 채널.
- **들어오는 방향(승인/명령)** = interactive message buttons / outgoing webhook / slash command: 운영자 클릭 → 우리 내부 엔드포인트.

둘 다 목적지가 내부 IP라 캠퍼스 방화벽/443 egress와 무관하다.

## 왜 Mattermost
- 자체 호스팅(Docker), incoming/outgoing webhook + **interactive message buttons**(승인/거부) + slash command + bot API 지원. air-gapped 배포 문서 존재.
- **Hermes 에이전트에 Mattermost 인터랙티브 승인 버튼이 이미 구현**(NousResearch/hermes-agent PR #29373, issue #27587) → 런타임=Hermes면 승인 창구가 사실상 내장.
- 대안: Rocket.Chat(유사). 초경량이 필요하면 채팅 없이 "승인 인박스" 웹페이지도 가능하지만 사용자가 채팅 형태를 원함.
- ⚠️ 무료판의 **모바일 푸시**는 Mattermost 호스티드 프록시(인터넷) 필요 → 우리는 안 씀. **웹/데스크톱 클라이언트는 완전 오프라인 동작**.

## 구성 요소
- **Mattermost 서버 + PostgreSQL** (Docker, 오프라인 이미지 반입 — 기존 방식과 동일). 배치 후보: **Groot_B**(디스크 145G 여유) 또는 소형 전용 VM. 내부망 전용(10.10.10.x), 접근은 대시보드처럼 A 점프(`ssh -L`).
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
모든 화살표가 내부망(10.10.10.x) — 인터넷 불필요.

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
- **정기 상태 요약(heartbeat)**: B `soc-summary.timer`(하루 2회, `OnCalendar=*-*-* 00,12:00:00` UTC = 09/21 KST, Persistent) → `soc_bot.py summary 12` → **이상 없어도 항상 게시**(🟢 이상없음 / 🟡 관찰 / 🔴 주의; 에이전트 active·최근 12h 경보·상위규칙·취약점). 수동 `/soc summary [시간]`. 주기/시각은 타이머 유닛에서 조정(SUMMARY_ONCAL/SUMMARY_HOURS).

- **남은 것**: Tier 2(채팅 내 [승인][거부] 버튼 + 승인 브로커), NL 에이전트(LLM 연결), `/soc block`(응답 MCP 연동) — 런타임 결정 후. Hermes면 인터랙티브 승인 내장(PR #29373).
- 포트: **A:443 nginx 리버스 프록시(chatproxy) → B:8065**. 내부 바인드 10.10.10.10:8065. 모바일 푸시(인터넷 필요) 미사용 — 웹/데스크톱만.

### VPN·캠퍼스 클린 접속 — A:443 이름 기반 리버스 프록시 (2026-09-27 확정)
Mattermost 웹소켓은 **Origin == SiteURL** 일 때만 수락(그 외 403, 실측). 사용자 제약(루프백 사용 불가)으로 클라이언트 터널은 배제 → **A:443 nginx 리버스 프록시**로 해결:
- `https://chat.groot.lab`(443) → A nginx(chatproxy) → B:8065. SiteURL/AllowCorsFrom = `https://chat.groot.lab` → Origin 일치 → **웹소켓 101(VPN·캠퍼스 모두 실측)**.
- `/etc/hosts` 는 어디서나 `192.168.16.230 chat.groot.lab` 동일(루프백/터널 불필요). 데스크톱 앱 서버도 `https://chat.groot.lab` 하나. 자체서명 인증서 1회 신뢰.
- 맨 IP(`https://192.168.16.230/`)·다른 Host 는 444(무응답). 구성 `infra/groot-a/chatproxy*`(nginx:1.27-alpine 오프라인). 구 A:8065 DNAT·터널(groot-mm/groot-chat) 제거.
- ⚠️ MM 은 plain http(8065) 유지(ConnectionSecurity 빈값), nginx 가 TLS 종단 + `X-Forwarded-Proto https`. compose env 변경은 `docker compose up -d --force-recreate` 로 적용(up 만으론 재생성 안 됨 — 실측 함정).
