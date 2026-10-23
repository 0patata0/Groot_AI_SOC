# HITL 채팅 채널 설계 — 온프레미스 Mattermost (오프라인, 양방향 웹훅)

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../STATUS.md) · [실행 계획](../../PLAN.md).
> 현재 구성은 MCP6서버와 고정 진단25대상이다. 자연어 도구 선택·무근거 완료/SILENT 알림 보완의 실제 검증 상태는 STATUS 최상단을 따른다. 정확 후보 승인과 일반 sudo/Docker/임의 shell 금지는 유지한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

## 현재 채널·문맥 동작 (2026-10-15 18:11 KST)

Hermes의 기존 관리자 허용 목록과 멘션 조건을 유지하면서 고정 채널 허용 목록을 비웠다. 명시한 한 팀의 공개 채널에는 봇 자신을 startup hook에서 가입시키고 300초마다 동기화한다. 현재 공개 채널4개 가입을 확인했으며, 비공개 채널은 봇 초대가 필요하다. home 채널·자유 응답 채널 설정은 유지한다. 채널 제한 해제는 모든 사용자의 관리 권한 부여가 아니다.

허용된 관리자가 보고의 댓글에서 멘션하면 `pre_gateway_dispatch` plugin이 현재 글의 사용자·채널·스레드를 API로 대조하고 원 보고와 앞선 댓글 최대25개를 읽는다. 일반 채널의 새 글에는 같은 채널의 앞선 최상위 글 최대20개만 제공한다. 카드 본문·표시 필드는 읽지만 버튼 action/integration/callback 메타데이터는 제외한다. 원래 메시지·채널·스레드와 native 답변 라우팅은 바꾸지 않는다.

읽은 이력은 신뢰하지 않는 참고 인용이며 승인으로 취급하지 않는다. native `@file` 확장 이후 `reply_to_text`로 붙이고, 봇·내부 사건·비허용 사용자·명령은 제외한다. 조회는 전체9초·문맥12,000자·원글6,000자까지이며 조회 실패와 생략을 모델에 전달한다. 원글 전체를 항상 읽거나 자연어 답변의 정확도를 보장하는 기능은 아니다. 실제 변경은 기존 브로커의 정확 후보·관리자 결정·일회 소비 검증을 계속 거친다.

18:11:02 기존 Hermes 컨테이너 stop/start 후18:11:17 연결을 확인했다. 실제 HTTP 조회를 사용하는 시험용 gateway/hook fixture에서 웹훅 자동 보고756자·카드1,483자·채널 글3개를 확인했고 문맥33·동기화20·native7·SIEM 설치기24검사를 통과했다. 후속 실제 세션 DB에서18:14:25·18:15:59 사용자 요청2건 모두 문맥 표지·`status:ok`·`same_thread`·원글/세션 일치를 확인했다. **native hook의 실제 대화 적용은 확인했지만 모델 답변 내용의 정확도는 미평가**다. pinned adapter·`run_turn.py`는 변경하지 않았다. 설치기 운영 파일5개는 반영했지만 신규 VM 실제 설치는 별도다. [설치 위치·설정·복구](../hermes/mattermost-context/README.md).

**19:02 KST 후속:** 새로 추적한 미응답 만료 카드의 본문·버튼 정리를 배포하고 실제 API 검증을 완료했다. 원글 DELETE 없이 `만료된 승인 요청` 표시를 남기며 댓글·승인/거부·소비/결과·감사기록과 기존 webhook 카드는 보존한다. 최초 빈 첨부 `null` 응답의 읽기 검증 실패를 수정한 뒤, 실제5초 worker의 만료 후2.368초1회 정리·보호 카드 불변·댓글 유지·추가 PUT0을 확인했다. 이번 시험에는 실제 관리자 승인·룰 API 호출이 없었으므로 승인→적용 E2E와 구별한다. [정리 기능·설정·한계](approval-card-cleanup.md).

아래 과거 기록의 채널 제한·승인 검증 범위·모바일 푸시·인증서 상태는 당시 기록이다. 현재 LLM 관리 주체와 실제 승인 시험 범위는 [최신 현황](../../STATUS.md)을 따른다.

> **2026-10-13 19:54 후속 완료:** DGX `.111` 예외의 부분 편집 제안은 실제 관리자 카드 승인→worker 적용→엔진 로드 검증→결과 게시까지 완료했다. Hermes의 `.111` 전환 후 Mattermost/WebSocket 재연결도 확인했다. 아래 부분 편집 미검증 표시는 이전 상태다. 큰 diff 분할 카드·별도 서비스 작업·임시 선차단의 실제 실행 검증은 여전히 별도다. [최종 기록](../../대화기록/2026-10-13.md).

> **19:14 KST 후속:** 작은 룰 변경은 새 `propose_rule_edit`로 변경 문맥만 제출하며 서버가 전체 후보를 구성한다. A/B 각 8개 도구·실제 조회/잘못된 편집 거절을 검증했다. 전체 diff·최종 승인 1회는 동일하고 새 도구는 모델에 짧은 게시 확인/제안 정보만 돌려준다. 새 부분 편집 승인 → 적용 E2E는 실사용 후속으로 남긴다. 아래 7개 도구 설명은 14:29 당시 기록이다.

> **2026-10-13 14:25~14:29 KST 라이브 배포·읽기 검증 완료:** 큰 룰 diff, 고정 서비스 작업, 임시 공격 IP 차단, 기존 차단/해제 승인을 아래처럼 보강했다. A/B 배포 후 Hermes의 실제 UID에서 도구 목록·상태 조회를 확인했다. 새 승인 버튼의 실제 클릭·서비스 실행·선차단 E2E는 아직 수행하지 않았다. [배포 문서](rule-change-deploy.md) · [오늘 작업 증거](../../대화기록/2026-10-13.md). 아래 9/28·10/08 기록은 당시 동작을 보존한다.

### 이번 추가 버전의 채팅 승인

- **룰 수정:** 전체 후보 파일은 128KiB, 영향·사유를 포함한 전체 diff는 512KiB까지 허용한다. 8KiB를 넘는 내용은 번호가 붙은 검토 메시지 여러 개로 표시하고, 마지막 **승인/거부 카드 한 개**에서 변경 전체를 결정한다. 각 부분의 요청 ID·전체/부분 해시·byte 범위를 확인한다. 모든 메시지 게시가 성공해야 승인 가능하며 일부 게시 실패·만료·시간 초과는 실행되지 않는다. 검토 부분은 승인 단위를 나눈 것이 아니다.
- **고정 서비스 작업:** A WAF·chatproxy의 reload/restart, A Suricata 및 B Wazuh manager/dashboard의 restart를 사전 승인한다. 카드에 변경 전 실측 요약·예상 변경 후 상태·영향·사유·관찰/작업 계획/고정 정책 해시를 표시한다. 승인 후 현재 기준이 유지되는지 확인하고 한 번 실행한 뒤 실제 관찰 결과를 보고한다. 패키지 설치·컨테이너 생성/구성 변경·임의 명령은 노출하지 않는다.
- **증거 기반 임시 차단:** A가 최근 Suricata 공격 증거와 보호 주소·활성 SSH 조건을 검사한 외부 IPv4만 최대 10분 먼저 차단하고 **60분 유지 / 해제 요청** 카드를 게시한다. 무응답·장애 시 원래 10분 커널 TTL이 상한이다. 해제 요청은 다음 worker에서 처리하며 기존 룰·서비스 작업 때문에 지연될 수 있다. 반복 요청으로 기한을 늘리지 않는다. 이 예외 정책과 별개로 일반 `resp.block_ip`·`unblock_ip`는 모두 사전 승인을 요구한다.

`rule-a`·`rule-b`의 새 공통 스키마는 각각 7개 도구다: 기존 룰 조회/제안/상태 3개와 서비스 조회/제안, 임시 차단, 운영 작업 상태 조회 4개. 실제 host/target/action 제한은 root helper가 강제하며 `rule-b`에서 임시 차단을 실행할 수 없다. [7개 도구와 대상](README.md) · [운영 작업 상세](approved-operations.md).

룰은 `/rule-changes`·`/rule-actions`, 서비스·임시 차단은 `/operations`·`/operation-actions`로 분리한다. 새 운영 API는 기존 룰 전용 HMAC 자격을 사용하지만 서비스/차단 종류·계획 digest·요청 ID·nonce를 별도로 결속한다. 지정 승인자 user ID와 실제 Mattermost TCP peer를 검사하고 한 번만 소비한다. 동일 요청 ID로 다른 계획을 제출하거나 서로 다른 승인 종류의 callback을 재사용할 수 없다. 결과 보고는 실제 실행 후 관찰 해시를 사용하며 작업 계획 해시와 같다고 가정하지 않는다.

기존 IP 대응 `/approval`·`/actions`도 `action=block|unblock`을 카드·상태·소비 요청에 결속하도록 수정했다. URL/토큰·`APPROVERS`·허용 callback 출처 누락 시 실행하지 않고, `/consume`에서 요청 ID·action·IP·기간을 대조해 승인 한 번만 소비한다. `/nonce/<id>`는 제거했다. 예전 기록의 nonce 조회·가상 승인 클릭 시험은 새 버전에서 사용할 수 없다. 기존 IP 대응은 토큰 방식이며 신규 룰/운영 API의 양방향 HMAC과 전송 보호 수준이 같다고 설명하지 않는다.

브로커 승인 상태는 메모리에 있다. 배포 전 `/pending` 및 인증된 health의 활성 legacy/rule/operation 건수를 확인하고, 승인·실행·결과 보고 중인 요청을 임의로 잃지 않도록 처리한다. 로컬 154개 테스트가 통과했다. 라이브 B 14:25:56·A 14:26:15 배포 후 14:29에 Hermes 실행·Mattermost 연결, 실제 UID 995의 rule MCP 각 7개 도구·고정 서비스 5개 조회·resp 3개 도구/차단 목록, 현재 34개 대화 캐시의 정책/해시·DB 무결성을 확인했다. 룰·nft·대상 서비스 컨테이너 시작 시각은 유지됐으며, 배포 시 재시작한 것은 soc-bot과 Hermes뿐이다. **새 대형 카드의 실제 승인 클릭·서비스 실행·임시 선차단 E2E는 읽기 검증과 별도로 남는다.**

> **현재 운영 기준(2026-10-08 확인 기록):** Mattermost·Hermes·`soc-bot`은 B에 배포돼 있고, 채팅은 A:443 chatproxy→B:8065로 접근한다. 대표 주소는 `https://chat.grootlab.duckdns.org`다. 같은 날 Let's Encrypt 인증서를 A에 배포해 HTTPS 검증을 통과했다(만료 2027-01-06 15:02 KST). 자동 갱신은 없으며 2026-12 초 재발급·A 재배포를 준비한다. 모바일은 관리자 GlobalProtect 지원 거절(사용자 보고)에 따라 A에 도달하는 학교 내부 Wi-Fi에서 시험하며 앱 로그인은 미검증이다.
>
> Hermes에는 읽기 `wazuh-ro`·`security-events`, IP 대응 `resp`, 승인형 로컬 룰 변경 `rule-a`·`rule-b` 총 5개 MCP 서버가 연결됐다. 기존 IP 차단의 승인 E2E는 9/28 검증했고, 10/08 신규 룰 변경 기능은 배포·HMAC·읽기 조회까지 확인했다. 실제 Mattermost 승인→룰 적용·복구 E2E는 미검증이다. 현재 승인 처리는 B의 별도 `soc-bot` 브로커가 맡는다.

> **2026-10-13 모바일 후속:** 사용자가 Android·iOS 모두 인증서 인식·로그인·채팅 성공을 확인했다. 아래 “모바일 푸시 미사용/우리는 안 씀”은 초기 설계 결정이며 현재는 **모바일 푸시 복구 요청으로 변경**됐다. 사용자는 프로젝트 서버의 해당 복구를 추가 확인 없이 진행하도록 승인했다. A 정책·B 설정 작업은 진행 중이고 실제 알림 수신은 미완료다. 최신 적용 상태·상위 경로 확인 사항은 [B 운영 문서](../groot-b/README.md#모바일-푸시--dns-복구외부-https-경로-미확보-2026-10-13)를 따른다.
>
> **11:41:34 KST B 직접 확인:** TPNS HTTPS 주소·`generic_no_channel` 설정을 반영했으며 푸시는 `SendPushNotifications=false`로 유지했다. Mattermost 재시작은 없었고 healthy였다. 외부 경로 검증 후 활성화와 휴대폰 수신 검증이 남았다.

아래 초기 설계와 날짜별 구축 기록은 당시 판단을 보존한다. '배치 후보', '남는 작업', '지금은 명령형 봇', '모바일 푸시 미사용', 예전 터널 경로는 현재 운영 안내가 아니며 위 요약과 후속 배포 기록을 우선한다.

Slack은 이 망에서 불가(아웃바운드 443 차단, 2026-09-27 실측). 대신 **자체 호스팅 채팅**을 내부망에 두면 Slack과 같은 UX를 인터넷 0으로 재현한다. 자체 호스팅이라 웹훅이 **양방향**으로 동작한다:
- **나가는 방향(알림)** = incoming webhook: 우리 서비스 → Mattermost 채널.
- **들어오는 방향(승인/명령)** = interactive message buttons / outgoing webhook / slash command: 운영자 클릭 → 우리 내부 엔드포인트.

둘 다 목적지가 내부 IP라 캠퍼스 방화벽/443 egress와 무관하다.

## 왜 Mattermost
- 자체 호스팅(Docker), incoming/outgoing webhook + **interactive message buttons**(승인/거부) + slash command + bot API 지원. air-gapped 배포 문서 존재.
- **Hermes 에이전트에 Mattermost 인터랙티브 승인 버튼이 이미 구현**(NousResearch/hermes-agent PR #29373, issue #27587) → 런타임=Hermes면 승인 창구가 사실상 내장.
- 대안: Rocket.Chat(유사). 초경량이 필요하면 채팅 없이 "승인 인박스" 웹페이지도 가능하지만 사용자가 채팅 형태를 원함.
- **초기 설계·10/08 당시 기록:** ⚠️ 무료판의 **모바일 푸시**는 Mattermost 호스티드 프록시(인터넷) 필요 → 우리는 안 씀. **웹/데스크톱 클라이언트는 완전 오프라인 동작**. 2026-10-08 DuckDNS 채팅 이름에 Let's Encrypt 인증서를 적용해 Mac의 HTTPS 검증을 통과했다. 사용자 보고에 따르면 학교 관리자가 관리 범위 확대를 이유로 모바일 GlobalProtect 지원을 거절했고 휴대폰 VPN 로그인도 실패했다. 현재는 A에 도달하는 학교 내부 Wi-Fi에서 실제 Mattermost 앱 로그인을 시험해야 한다. 앱 접속과 푸시 알림은 별개다.

## 초기 설계의 구성 요소
- **Mattermost 서버 + PostgreSQL** (Docker, 오프라인 이미지 반입 — 기존 방식과 동일). 배치 후보: **Groot_B**(디스크 145G 여유) 또는 소형 전용 VM. 내부망 전용(10.200.10.x), 접근은 대시보드처럼 A 점프(`ssh -L`).
- **알림**: 이미 완성 — `notifier.py` http 백엔드가 Mattermost incoming webhook URL로 POST. `/etc/resp/hitl.env` 에 `RESP_NOTIFY_BACKEND=http` + `RESP_NOTIFY_URL=<webhook>` 한 블록.
- **승인 브로커**(Tier 2에서 추가): 내부 소형 HTTP 리스너(B). Mattermost 버튼 클릭의 action 콜백을 받아 (a) 클릭 사용자 검증(허용 승인자 목록), (b) request-id 별 결정(승인/거부) 저장. 응답 MCP 서버는 고위험 동작 시 request-id 생성→버튼 메시지 게시→브로커 결정 대기→진행/중단.

## 초기 도입 계획
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

## 초기 교체 설계
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

**2026-10-13 정정:** 위 미사용·미검증은 당시 상태다. Android·iOS 로그인·채팅 성공을 사용자가 확인했고, 푸시는 현재 복구 작업 대상이다. 실제 수신 검증은 남아 있다.

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

### 기록 정정·현재 경계 (2026-10-08 문서 점검)
- 위 9/28 주의 문단의 `A(10.200.10.10)` 표기는 B 주소를 잘못 적은 것이다. 10/08 SSH 확인 기준 A는 `10.200.10.1`, B는 `10.200.10.10`이다. Mattermost 컨테이너는 `172.19.0.2`, 콜백이 향하는 B Docker 게이트웨이는 `172.19.0.1`로 구분한다. 신규 룰 승인 콜백은 실제 컨테이너 주소 `172.19.0.2/32`만 허용하며 컨테이너 재생성 뒤 IP가 바뀌면 재설정이 필요하다. [배포 기록·절차](rule-change-deploy.md).
- 9/28 기존 IP 차단 승인 성공은 모든 쓰기 작업이 항상 승인을 거친다는 의미가 아니다. 현 코드의 `block_ip`는 브로커 URL·토큰이 없으면 즉시 실행하고 `unblock_ip`는 승인 없이 실행한다. 10/08 오전에는 실제 브로커 설정이 존재함을 확인했다. 새 `rule-a`·`rule-b` 경계는 전용 토큰·명시적 승인자·정확한 제안 해시를 강제하며 설정 누락·거부·만료 시 적용하지 않는다.

### 한국어 응답 혼입 보완 (2026-10-13 13:49~13:50 KST)
- 최근 응답에서 한자·가나 혼입을 확인해 SOUL과 `soc-alert-watch`에 동일 `korean-output-policy` 블록을 배포했다. 자연스러운 한글 설명·전송 전 문장 재작성, 로그/코드/식별자 원문 보존, 명시적 외국어 요청 및 고정 JSON/`[SILENT]` 예외를 함께 규정한다. 문자를 일괄 삭제하는 필터나 모델 학습·샘플링 변경은 하지 않았다.
- 설치된 Hermes 0.21.5는 기존 대화의 DB 시스템 프롬프트를 재사용한다. 유휴 agent·활성 lease 0 확인 후 Hermes만 정지하고 최신 SOUL·cron·state DB를 백업했다. 현재 `gateway_routing`과 `sessions.json`이 일치하는 Mattermost 34개 세션에 새 관리 블록만 추가했다. 새 SHA/blob을 삽입하고 해당 세션의 prompt 참조 두 칼럼만 갱신했으며 옛 blob은 보존했다. 메시지/도구 이력·라우팅·세션의 나머지 필드는 전후 해시가 같았다. 재기동으로 메모리 캐시를 비웠다.
- 기존 cron은 업무 지침·일정·전송 대상 등 다른 필드를 유지하고 새 언어 블록을 추가했다. 저장소에는 있으나 라이브에서 빠져 있던 무인 작업의 `propose_rule_change` 금지 문장도 반영했다. 기존 페르소나·룰 승인 정책·모델·환경·모니터 스크립트는 유지했다.
- 백업: B `/var/backups/hermes-korean-20261013.bg_iwt7m`(root 0700, SOUL/jobs/state DB/manifest 0600). 라이브 SOUL SHA `125909a3214e8c6a9de4ca89d619a766ffd906bfb8b71a35b9d9b3802581d5c9`, cron prompt SHA `bab48293995a640f077a0b09add28c0321e74632d1787b15cca3c782f4a33ee2`, 언어 블록 SHA `6c3cc1cedea9beaffd67f2a0ef49b2b3cb194f866c4fbe35d3d0b8a0c555e3b5`. 복구 시 유휴·정지를 확인하고 SOUL/cron의 해당 블록 및 대상 캐시 참조만 되돌린다. **운영 재개 후 과거 DB 전체를 덮어쓰면 새 대화가 사라질 수 있으므로 금지**한다. 전체 DB 백업은 배포 직후 정지 상태의 실패 복구 및 감사용이다.
- 검증: 13:50:56 현재 34개 캐시에 정책 1회·SHA 일치, 실제 `load_soul_md`가 정책을 잘림 없이 로드, DB integrity ok·cron 5분 enabled·5 MCP enabled·Mattermost connected·soc-bot active. 다른 컨테이너 시작 시각은 그대로다. DGX API 합성 입력의 후보 4건은 한국어 설명/혼입 이력 정리/원문 보존/명시적 번역 조건을 통과했다. 실제 채팅으로 시험 메시지를 게시한 결과나 장기 오류율 측정은 아니다.
- 재배포 주의: `deploy_gateway_B.sh`는 기존 SOUL 제목·기존 cron이 있으면 내용 갱신을 건너뛴다. 해당 스크립트 전체 재실행 대신 관리 블록과 기존 작업의 prompt만 동기화하고 현재 대화의 저장 지침까지 확인해야 한다. [Hermes SOUL 공식 설명](https://hermes-agent.nousresearch.com/docs/guides/use-soul-with-hermes)과 설치 소스의 실제 캐시 동작을 함께 확인했다.
