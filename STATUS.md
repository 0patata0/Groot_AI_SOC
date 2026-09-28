# 인프라 현황 스냅샷 — 2026-09-27 17:24 UTC

> Agentic SOC 캡스톤. 상세 계획·체크리스트는 [PLAN.md](PLAN.md), 날짜별 작업로그는 [대화기록/](대화기록/), 자격증명은 `CREDENTIALS.local.md`(git 미커밋).
> 이 파일은 "지금 살아있는 상태"의 한 장 요약이다.

## 라이브 헬스 (방금 점검)
| 호스트 | 역할 | 상태 |
|---|---|---|
| **Groot_A** `groot-sec` 192.168.16.230 / 10.10.10.1 | FW/IPS/WAF 게이트웨이 + NTP + 응답 MCP | ✅ waf(healthy)·suricata(running), wazuh-agent active, nft(capstone_gw/fwd/fw), capstone-nat·chrony·리퍼 타이머 active, nftables.service **masked**, 차단 0건 |
| **Groot_B** `groot-siem` 10.10.10.10 | Wazuh SIEM + 읽기 MCP + 채팅 | ✅ manager·indexer·dashboard Up, **에이전트 3대 Active**, 읽기 서버 `/opt/mcp`, **Mattermost+PostgreSQL(mm-app/mm-postgres) Up** — HITL 알림 채널 |
| **Groot_C** `groot-web` 10.10.10.20 | DVWA + CVE 랩 | ✅ apache active, DVWA 200, `log4shell-lab` 컨테이너(**C 내부 전용 바인딩** `10.10.10.20:8080` — 캠퍼스/VPN 직접 도달 차단), wazuh-agent active |
| 관리포털(Wazuh) | **A:443 이름 프록시**(chatproxy)→B:443 (+A:10443 DNAT 유지) | ✅ **`https://wazuh.groot.lab`** 학과망·VM세그먼트 OK(로그인 200 실측 2026-09-28). 출발지 allowlist — **VPN(192.168.15.0/24)·외부는 403**(대시보드 VPN 비노출 결정 유지). 학과망(192.168.12.x)은 10443 이 캠퍼스 FW 에 막힘(실측) → 이 경로가 유일. 팀원 무설정 별칭 **`https://wazuh.grootlab.duckdns.org`**(동일 allowlist). 맨 IP 443=444 |
| 채팅(Mattermost) | A:443 nginx 리버스 프록시(chatproxy)→B:8065 | ✅ **`https://chat.groot.lab`**(hosts) + **`https://chat.grootlab.duckdns.org`**(팀원 무설정, DuckDNS) — 둘 다 웹소켓 101 실측(AllowCorsFrom 두 Origin). SiteURL=DuckDNS 이름(대표). 맨 IP 443은 444 |
| SOC 챗봇 | B `soc-bot`(systemd) + MM 슬래시 `/soc` | ✅ `/soc status\|alerts\|agents\|vulns\|report`. 읽기전용(mcp-ro), 대응은 groot-resp 분리. NL은 LLM 연결 후 |
| 에이전트 런타임(Hermes) | B Docker `nousresearch/hermes-agent:v2026.9.24`(오프라인 반입, 격리 사용자 hermes) | ✅ **Hermes 가 MCP 2서버 17툴 등록 확인**(agent.log; 읽기 14 + 응답 3, 컨테이너 안 계약 테스트 PASS). 자격증명 격리 유지(SSH 키 1개, ForceCommand 경계). **LLM 미연결**(B egress 없음 → 로컬 llama.cpp/DGX permit/A 프록시 중 택1) |
| 주기 인시던트 보고 | B `soc-report.timer`(hourly) | ✅ 매시 인시던트 보고서 자동 게시. 경보 0이면 미게시(스팸 방지) |
| 정기 상태 요약 | B `soc-summary.timer`(하루 2회, 00·12 UTC=09·21 KST) | ✅ **이상 없어도 항상** 상태 요약 게시(🟢/🟡/🔴, 에이전트·경보·취약점). `/soc summary [h]` 수동 |
| DVWA(웹 서비스) | A:80 WAF→C | ✅ `http://192.168.16.230/`(302) IP 접근 + **URL `http://dvwa.groot.lab/`**(WAF Host 서빙 검증; 클라이언트 hosts 적용 후) |
| Log4Shell 랩 경로 | 평상시 C 내부 전용 / 시나리오 때 A 경유 | ⚙️ 토글 `sudo scenario_log4shell_route.sh on\|off\|status`(A). ON=`http://192.168.16.230:8080/`→Suricata 검사→C(캠퍼스/Kali만, VPN 불통). 런타임 전용(재부팅=자동 OFF). 소스 `infra/groot-a/scenario_log4shell_route.sh` |

## 완료된 것
- **네트워크/게이트웨이**: A NAT(masquerade) + 관리 포트포워딩(A:443→B 대시보드, WAF TLS 8443). VPN은 A로 22/80/443만 통과.
- **A 보안장비**: Suricata 8.0.6 IDS(ET Open 52,483룰) + ModSecurity/CRS 4.29 WAF(DetectionOnly). 로그→Wazuh.
- **B Wazuh 4.14.8**: 스택 기동, 비번 통일, 로컬 룰(Suricata/WAF/agent_block/호스트FW), 취약점 탐지(C 2,422 CVE).
- **에이전트**: A(001)·C(002) Active, 로그·인벤토리·취약점 수집.
- **시계**: A(chrony)←캠퍼스 192.168.16.131, B/C(timesyncd)←A. 외부 NTP·VMware Tools timesync 미사용.
- **A 호스트 방화벽 Phase 2 + agent_block**: input 기본 drop, raw prerouting 차단 셋 + never_block 잠금가드, CLI, 데드맨 적용, 실차단 검증. B 룰 100120~100131.
- **MCP 읽기 서버**(B, `ssh -T groot-mcp`): 14 툴, 읽기전용 계정 mcp-ro, 계약 테스트 PASS.
- **MCP 응답 서버**(A, `ssh -T groot-resp`): block_ip/unblock_ip/list_blocks → agent_block, 정책 엔진, TTL 만료 리퍼, 계약 테스트 PASS(차단 100121 / 거부 100123 / 해제 100122 / 만료 100131).
- **문서**: `scenarios/`(탐지 검증 매트릭스 + 공개 표준 레퍼런스), infra README(A/B/C/MCP).

## 접속 치트시트 (Mac, ssh config 등록됨)
- SIEM 대시보드: **`https://wazuh.groot.lab`**(A:443 프록시; 학과망·VM세그먼트만, VPN·외부 403). VM세그먼트 직결이면 `https://192.168.16.230:10443` 도 가능. (admin, 비번 CREDENTIALS)
- 셸: `ssh groot-a` / `ssh groot-b-int` / `ssh groot-c-int`.
- **팀원 무설정 접속(2026-09-28, 공개 DNS=DuckDNS `grootlab.duckdns.org`→192.168.16.230)**: hosts·ssh config 없이 `https://chat.grootlab.duckdns.org` · `https://wazuh.grootlab.duckdns.org`(VPN 403) · `http://dvwa.grootlab.duckdns.org`. SSH 는 `ssh -J groot_a@192.168.16.230 groot_b@10.10.10.10` 한 줄(C 는 10.10.10.20). 안내문 `팀접속안내.md`. **DuckDNS 등록 완료·학과망에서 이름만으로 실측 OK**(해석 4개, 채팅 200/101, 대시보드 302→로그인 200, DVWA 302, 인증서 SNI 일치; 2026-09-28).
- 내부 이름(클라이언트 /etc/hosts 에 `192.168.16.230 dvwa.groot.lab wazuh.groot.lab chat.groot.lab` 1줄):
  - 캠퍼스·VPN 공통: `http://dvwa.groot.lab/` · `https://chat.groot.lab/`(데스크톱 앱 동일 URL)
  - 대시보드: `https://wazuh.groot.lab/` (학과망·VM세그먼트만, VPN 403 — 보안상 VPN 비노출 유지). 자체서명 인증서 1회 신뢰(채팅 인증서와 별개)
- 읽기 MCP: `ssh -T groot-mcp` · 응답 MCP: `ssh -T groot-resp` (에이전트 런타임이 이 두 줄만 등록하면 됨).
- 수동 차단(A): `sudo agent_block add <ip> [ttl] [reason]` / `list` / `del <ip>`.

## 보류 / 다음
- **보류(2)**: B/C 임시 NIC(ens192) 제거 + 기본라우트 A로 전환(콜드부트) — **다른 작업자 세팅 중**. 완료 시 never_block의 .233/.234, ssh `groot-mcp-direct` 정리.
- **다음 후보**:
  1. 에이전트 런타임: **Hermes(B Docker) ↔ MCP 연결 검증 완료(2026-09-28)** → 남은 것은 LLM 연결(B 로컬 llama.cpp / DGX permit / A 경유 프록시 중 택1). 연결되면 NL 대화·`/soc block`·승인(untrusted 서버 툴) 활성화.
  2. 시나리오 실제 실행(선행조건: DVWA `low`, ~~Log4Shell 경로~~ → **결정됨**(A 경유 토글 준비, `scenario_log4shell_route.sh`), C sudo 버전, Kali 세그먼트 직결).
  3. 응답툴 확장(`isolate_host`·`notify`) + 고위험 동작 사람 승인.
- **HITL 채널**: Slack/Discord 등 클라우드 채팅 전부 불가(아웃바운드 443 차단, 실측). → **온프레미스 Mattermost를 B에 배치(Tier 1 완료, 2026-09-27)**: 브라우저 `ssh -N groot-mm`→http://localhost:18065, SOC 경보가 `soc-alerts` 채널에 실시간(응답 서버 block/unblock→채널 게시 검증). 승인=MCP elicitation(런타임), 알림 채널 교체는 `/etc/resp/hitl.env` 1블록. 남은 것: Tier 2(채팅 내 승인 버튼) — 런타임 결정 후(Hermes면 내장).
- **주의**: 공격성 테스트 트래픽은 캠퍼스 VPN 경유 금지(캠퍼스 FW가 차단). `never_block`에 관리 VPN 대역(192.168.15.0/24) 포함 — VPN 대역 바뀌면 갱신.

## 커밋 상태
- 로컬 변경만(미커밋). 원격(GitHub) 미연결. 추적 파일에 비밀 없음(비밀은 CREDENTIALS.local.md=gitignore, B의 env, Mac ssh 키에만).
