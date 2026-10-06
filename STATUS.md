# 인프라 현황 스냅샷 — 2026-10-06 SSH 점검 기준

> Agentic SOC 캡스톤. 상세 계획·체크리스트는 [PLAN.md](PLAN.md), 날짜별 작업로그는 [대화기록/](대화기록/), 자격증명은 `CREDENTIALS.local.md`(git 미커밋).
> A/B/C는 2026-10-06 05:05~05:07 UTC(14:05~14:07 KST)에 SSH로 읽기 전용 재점검했다. 기능별 과거 실측은 각 행의 날짜와 [작업 기록](대화기록/2026-10-06.md)을 참조한다. 공격 프로브·차단 전환은 이번에 실행하지 않았다.
> **시간대 변경(2026-10-06 15:59 KST, 라이브 확인):** A/B/C 호스트를 `Asia/Seoul`(KST, UTC+09:00)로 통일했고 NTP 동기화를 확인했다. B의 `soc-summary.timer`는 `09,21:00 Asia/Seoul`로 설정했고 다음 실행은 21:00 KST다. B `soc-bot`은 최근 경보 시각을 KST로 표시하며, Mattermost 컨테이너는 `TZ=Asia/Seoul`로 재생성 후 healthy를 확인했다. 다른 컨테이너의 내부 시간대는 UTC일 수 있으며, Wazuh 원본 타임스탬프와 표시 시간대는 구분한다.
> **내부망은 2026-09-29 부터 `10.200.10.0/24`(A .1 / B .10 / C .20)** — 캠퍼스 코어가 쓰는 10.10.10.0/24 와의 중복을 없앴다(런북 `infra/internal_net_change.md`).
> **외부 주소 확인 주의:** 이번 SSH에서 A `ens192=192.168.16.230/25`, 직결 라우트 `192.168.16.128/25`, 기본 게이트웨이 `.129`를 확인했다. 라이브 A:10443 DNAT와 `CAPSTONE-FWD`의 허용 출발지 `192.168.16.0/25`는 **다른 대역**이다. Kali 주소·라우팅이 미확인이므로 이 허용목록이 의도대로 작동하는지는 시나리오 전에 검증해야 한다.

## 라이브 헬스 (A/B/C 호스트는 2026-10-06 SSH 재점검)
| 호스트 | 역할 | 상태 |
|---|---|---|
| **Groot_A** `groot-sec` 192.168.16.230 / 10.200.10.1 | FW/IPS/WAF 게이트웨이 + NTP + 응답 MCP | ✅ SSH 재점검: **FORWARD=DROP**, `CAPSTONE-FWD` 14룰, nft v2(`SPOOF`/`FW_SSH_RATE`/output). WAF healthy·`nginx -t` 통과·`REQUEST-948-GROOT_A_WAF.conf` 마운트·**DetectionOnly**. Suricata `-i ens192 -S /rules/all.rules`+Phase-A 설정, eve.json 갱신 중. 이후 B의 Wazuh 인덱스에서 로컬 SID `1000010` 경보 관측(시나리오별 공격 재현은 미실시) |
| **Groot_B** `groot-siem` 10.200.10.10 | Wazuh SIEM + 읽기 MCP + 채팅 | ✅ SSH 재점검: `ens192` 없음·기본 경로 A, Wazuh 000/001/002 Active, manager·indexer·dashboard·Mattermost·Hermes Up, DGX API 200. **라이브 `local_decoder.xml`/`local_rules.xml`에 신규 FW 프리픽스와 WAF 100200+ 룰이 없음**. 읽기 전용 조회로 Suricata SID `1000010`→Wazuh `100110`, ModSecurity CRS `920350`→Wazuh `100101` 경보 관측. GROOT WAF 커스텀 ID `10100`대의 실제 발화는 미확인 |
| **Groot_C** `groot-web` 10.200.10.20 | DVWA + CVE 랩 | ✅ SSH 재점검: `ens192` 없음·기본 경로 A, Apache·Wazuh Agent active, DVWA 302, `log4shell-lab` 가동(`10.200.10.20:8080` 내부 바인딩), NTP 동기화 |
| 관리포털(Wazuh) | **A:443 이름 프록시**(chatproxy)→B:443 (+A:10443 DNAT 유지) | ✅ **`https://wazuh.groot.lab`** 학과망·VM세그먼트 OK(로그인 200 실측 2026-09-28). 출발지 allowlist(학과망 **192.168.10.0/24·192.168.12.0/24**·VM세그먼트·내부망) — **VPN(192.168.15.0/24)·외부는 403**(대시보드 VPN 비노출 결정 유지). 2026-09-29 학과망이 192.168.10.x 로 배정되어 403 → allowlist 에 추가·chatproxy 재시작으로 해결. 학과망(192.168.12.x)은 10443 이 캠퍼스 FW 에 막힘(실측) → 이 경로가 유일. 팀원 무설정 별칭 **`https://wazuh.grootlab.duckdns.org`**(동일 allowlist). 맨 IP 443=444 |
| 채팅(Mattermost) | A:443 nginx 리버스 프록시(chatproxy)→B:8065 | ✅ **`https://chat.groot.lab`**(hosts) + **`https://chat.grootlab.duckdns.org`**(팀원 무설정, DuckDNS) — 둘 다 웹소켓 101 실측(AllowCorsFrom 두 Origin). SiteURL=DuckDNS 이름(대표). 맨 IP 443은 444 |
| SOC 챗봇 | B `soc-bot`(systemd) + MM 슬래시 `/soc` | ✅ `/soc status\|alerts\|agents\|vulns\|report`는 읽기전용(mcp-ro). 자연어 대화는 별도 `@hermes` 게이트웨이, 대응은 groot-resp 분리 |
| 에이전트 런타임(Hermes) | B 상주 컨테이너 `hermes`(gateway) + DGX qwen3.6:35b(256k) + Mattermost 봇 `@hermes` | ✅ **채팅 NL 대화(`soc-agent`)·경보 트리거 cron(5분, 변화 시만 조사→`soc-alerts` 보고)·Tier 2 승인([승인][거부] 버튼→A 차단) 전부 E2E 실측(2026-09-28)**. 자격증명 격리 유지. 배치 `infra/hermes/deploy_gateway_B.sh`, 브로커 `infra/mcp/soc_bot.py` |
| 주기 인시던트 보고 | B `soc-report.timer`(hourly) | ✅ 매시 인시던트 보고서 자동 게시. 경보 0이면 미게시(스팸 방지) |
| 정기 상태 요약 | B `soc-summary.timer`(하루 2회, 09·21 KST) | ✅ **이상 없어도 항상** 상태 요약 게시(🟢/🟡/🔴, 에이전트·경보·취약점). `/soc summary [h]` 수동 |
| DVWA(웹 서비스) | A:80 WAF→C | ✅ `http://192.168.16.230/`(302) IP 접근 + **URL `http://dvwa.groot.lab/`**(WAF Host 서빙 검증; 클라이언트 hosts 적용 후) |
| Log4Shell 랩 경로 | 평상시 C 내부 전용 / 시나리오 때 A 경유 | ⚙️ **10/6 라이브 토글 OFF**(A:8080 시나리오 NAT/DOCKER-USER 룰 없음). `sudo scenario_log4shell_route.sh on\|off\|status`(A)로 전환하는 설계. 저장소 스크립트의 `OBS_SEG` 관찰 룰은 A 설치본에 없으므로 재배포·경로 검증이 선행돼야 한다. |

## 완료된 것
- **네트워크/게이트웨이**: A NAT(masquerade) + 이름 기반 A:443 프록시(대시보드·채팅), A:10443→B:443 DNAT, WAF TLS 8443. VPN은 A로 22/80/443만 통과.
- **A 보안장비**: FW v2의 FORWARD 기본 차단, WAF 신규 룰 마운트(DetectionOnly), Suricata ET+local 합본·Phase-A(passive) 적용을 SSH 재확인. B에 인덱싱된 Suricata 로컬 SID `1000010` 경보 1종과 CRS `920350` 경보 1종을 읽기 전용 조회로 확인했다. 다른 신규 룰 및 시나리오별 발화는 미검증이다.
- **B Wazuh 4.14.8**: 스택 기동, 비번 통일, 로컬 룰(Suricata/WAF/agent_block/호스트FW), 취약점 탐지(C 2,422 CVE).
- **에이전트**: A(001)·C(002) Active, 로그·인벤토리·취약점 수집. B/C는 `ens192` 물리 제거·기본 경로 A 전환 완료.
- **시계**: A/B/C 호스트 `Asia/Seoul`(KST), NTP 동기화 확인(2026-10-06 15:59 KST). A(chrony)←캠퍼스 192.168.16.131, B/C(timesyncd)←A. 외부 NTP·VMware Tools timesync 미사용.
- **A 호스트 방화벽 Phase 2 + agent_block**: input 기본 drop, raw prerouting 차단 셋 + never_block 잠금가드, CLI, 데드맨 적용, 실차단 검증. B 룰 100120~100131.
- **MCP 읽기 서버**(B, `ssh -T groot-mcp`): 기존 Wazuh 14툴 계약 테스트 PASS. 별도 `ssh -T groot-mcp security-events` 보안 이벤트 2툴을 B에 배치하고 Suricata·ModSecurity 조회 계약 테스트 PASS. 둘 다 읽기전용 `mcp-ro` 인덱서 권한을 사용한다. Hermes 실설정에 세 번째 서버를 추가해 재시작했고 `hermes mcp list`에서 3서버 enabled를 확인했다. Hermes LLM 대화의 두 새 도구 호출도 PASS(SID `1000010`, CRS `920350`).
- **MCP 응답 서버**(A, `ssh -T groot-resp`): block_ip/unblock_ip/list_blocks → agent_block, 정책 엔진, TTL 만료 리퍼, 계약 테스트 PASS(차단 100121 / 거부 100123 / 해제 100122 / 만료 100131).
- **문서**: `scenarios/`(탐지 검증 매트릭스 + 공개 표준 레퍼런스), infra README(A/B/C/MCP).

## 접속 치트시트 (Mac, ssh config 등록됨)
- SIEM 대시보드: **`https://wazuh.groot.lab`**(A:443 프록시; 학과망·VM세그먼트만, VPN·외부 403). VM세그먼트 직결이면 `https://192.168.16.230:10443` 도 가능. (admin, 비번 CREDENTIALS)
- 셸: `ssh groot-a` / `ssh groot-b-int` / `ssh groot-c-int`.
- **팀원 무설정 접속(2026-09-28, 공개 DNS=DuckDNS `grootlab.duckdns.org`→192.168.16.230)**: hosts·ssh config 없이 `https://chat.grootlab.duckdns.org` · `https://wazuh.grootlab.duckdns.org`(VPN 403) · `http://dvwa.grootlab.duckdns.org`. SSH 는 `ssh -J groot_a@grootlab.duckdns.org groot_b@10.200.10.10` 한 줄(C 는 10.200.10.20; 이름 기반이라 A IP 변경과 무관). 안내문 `팀접속안내.md`. **DuckDNS 등록 완료·학과망에서 이름만으로 실측 OK**(해석 4개, 채팅 200/101, 대시보드 302→로그인 200, DVWA 302, 인증서 SNI 일치; 2026-09-28).
- 내부 이름(클라이언트 /etc/hosts 에 `192.168.16.230 dvwa.groot.lab wazuh.groot.lab chat.groot.lab` 1줄):
  - 캠퍼스·VPN 공통: `http://dvwa.groot.lab/` · `https://chat.groot.lab/`(데스크톱 앱 동일 URL)
  - 대시보드: `https://wazuh.groot.lab/` (학과망·VM세그먼트만, VPN 403 — 보안상 VPN 비노출 유지). 자체서명 인증서 1회 신뢰(채팅 인증서와 별개)
- 읽기 MCP: 기존 Wazuh `ssh -T groot-mcp`, Suricata·ModSecurity 경보 `ssh -T groot-mcp security-events` · 응답 MCP: `ssh -T groot-resp`. Hermes 3서버 enabled 및 새 읽기 도구 2개의 LLM 호출 확인.
- 수동 차단(A): `sudo agent_block add <ip> [ttl] [reason]` / `list` / `del <ip>`.

## 보류 / 다음
- **다음 작업·검증**: B 라이브 룰 파일에 없는 신규 FW(`SPOOF`/`FW_SSH_RATE`/`FW_DROP_FWD`/`FW_SHADOW_OUT`)·WAF(`GROOT_A/*` 100200–299) 디코더·룰을 추가하고 IPS local SID 1000xxx의 나머지 분류도 확인. SID `1000010`→Wazuh `100110`은 이미 관측했다. 이어 VM 세그먼트 공격 프로브로 WAF audit·IPS eve·FW 로그→Wazuh alerts 실발화를 시나리오별로 검증.
- **별도 전환**: WAF `On`과 IPS 인라인 drop은 아직 적용하지 않았다. 탐지 검증 후 차단 게이트와 평가 범위를 결정. Log4Shell egress 관찰용 `OBS_SEG` 룰은 저장소에만 있고 A 설치본에는 없다.
- **다음 후보**:
  1. 에이전트: **경보 트리거·Tier 2 승인·채팅 게이트웨이까지 완료(2026-09-28)** → 다음은 시나리오 실측(사용자 직접), 평가(MTTI/MTTR), 승인자 목록에 팀원 추가.
  2. 시나리오 실제 실행(선행조건: DVWA `low`, A Log4Shell 토글 설치본 동기화·경로 검증, C sudo CVE 취약성 검증, Kali VM 세그먼트 직결). C의 `sudo --version`은 10/6에 **1.8.31**로 관측했으나 버전만으로 CVE-2021-3156 취약 여부를 확정하지 않는다.
  3. 응답툴 확장(`isolate_host`·`notify`), 팀원 승인자 목록 구성. 고위험 차단의 Tier 2 승인 경로는 9/28 검증 완료.
- **HITL 채널**: 온프레미스 Mattermost(B)와 Tier 2 [승인][거부] 버튼의 차단 E2E를 2026-09-28에 검증했다. 이번 SSH에서는 A의 브로커 URL·토큰 환경 변수 설정만 값 출력 없이 확인했고, 승인→차단 E2E는 재시험하지 않았다.
- **주의**: 공격성 테스트 트래픽은 캠퍼스 VPN 경유 금지(캠퍼스 FW가 차단). `never_block`에 관리 VPN 대역(192.168.15.0/24) 포함 — VPN 대역 바뀌면 갱신.

## 저장소 동기화 주의
- 10/6 라이브 적용 사실은 작업 기록에 있으나 저장소의 일부 배포 설정은 적용 전 상태일 수 있다. 배포 재실행 전 라이브와 비교해야 한다.
- 추적 문서 `로그_파이프라인.md`에서 발견한 평문 자격증명은 현재 작업 파일에서 제거하고 gitignored `CREDENTIALS.local.md` 참조로 바꿨다. 과거 Git 이력·이전 도구 출력에는 노출 흔적이 남아 있어 자격증명 교체와 이력 처리 범위를 별도로 결정해야 한다. 값은 문서에 옮기지 않는다.
