# 인프라 현황 스냅샷 — 2026-10-08 SSH 재점검·룰 변경 MCP·채팅 인증서 배포 기준

> Agentic SOC 캡스톤. 상세 계획·체크리스트는 [PLAN.md](PLAN.md), 날짜별 작업로그는 [대화기록/](대화기록/), 자격증명은 `CREDENTIALS.local.md`(git 미커밋).
> A/B/C는 2026-10-08 11:53~11:59 KST에 관리 SSH로 읽기 전용 재점검했다. 이어 약 12:58 KST B 승인 브로커, A/B 룰 변경 MCP·worker, Hermes 등록을 배포·검증했다. 세부 근거는 [작업 기록](대화기록/2026-10-08.md)에, 이전 기능별 E2E 실측은 해당 날짜 기록에 구분했다. 공격 프로브·차단 전환·실제 Mattermost 승인→룰 적용 E2E는 실행하지 않았다.
> **시간대 변경(2026-10-06 15:59 KST, 라이브 확인):** A/B/C 호스트를 `Asia/Seoul`(KST, UTC+09:00)로 통일했고 NTP 동기화를 확인했다. B의 `soc-summary.timer`는 당시 `09,21:00 Asia/Seoul`로 설정했고 다음 실행이 같은 날 21:00 KST임을 확인했다. B `soc-bot`은 최근 경보 시각을 KST로 표시하며, Mattermost 컨테이너는 `TZ=Asia/Seoul`로 재생성 후 healthy를 확인했다. 다른 컨테이너의 내부 시간대는 UTC일 수 있으며, Wazuh 원본 타임스탬프와 표시 시간대는 구분한다. 10/08 세 호스트의 KST·NTP 동기화는 재확인했다.
> **내부망은 2026-09-29 부터 `10.200.10.0/24`(A .1 / B .10 / C .20)** — 캠퍼스 코어가 쓰는 10.10.10.0/24 와의 중복을 없앴다(런북 `infra/internal_net_change.md`).
> **외부 주소 확인 주의:** 10/08 SSH에서 A `ens192=192.168.16.230/25`, 직결 라우트 `192.168.16.128/25`, 기본 게이트웨이 `.129`를 재확인했다. 10/06에 확인한 A:10443 DNAT·`CAPSTONE-FWD`의 허용 출발지 `192.168.16.0/25`는 **다른 대역**이다. Kali 주소·라우팅이 미확인이므로 이 허용목록이 의도대로 작동하는지는 시나리오 전에 검증해야 한다.
> **채팅 인증서(2026-10-08 약 16:02 KST, 라이브 배포):** `chat.grootlab.duckdns.org`에 Let's Encrypt 인증서를 적용했다. 만료 2027-01-06 15:02 KST. A 배포 스크립트의 SNI·CA 검증 ping과 Mac의 `curl` HTTP 200/TLS 검증 결과 0을 확인했다. 실제 모바일 앱의 학교 Wi-Fi·VPN 로그인은 미검증이고 갱신은 미자동화다. [운영 기록](infra/dns/README.md).

## 라이브 헬스 (A/B/C 호스트는 2026-10-08 SSH 재점검)
| 호스트 | 역할 | 상태 |
|---|---|---|
| **Groot_A** `groot-sec` 192.168.16.230 / 10.200.10.1 | FW/IPS/WAF 게이트웨이 + NTP + 응답·룰 변경 MCP | ✅ 10/08: **FORWARD=DROP**, `CAPSTONE-FWD` 14룰, nft input DROP·output ACCEPT, 임시 차단 목록 비어 있음. WAF healthy·`nginx -t` 통과·커스텀 ID 10개·**DetectionOnly**. Suricata `-i ens192 -S /rules/all.rules`·로컬 SID 11개, 인라인 queue 0개, eve.json 갱신. WAF/Suricata 운영 룰 해시는 배포 전후 동일. A `rulechg`·worker timer active/enabled, HMAC 통신·읽기 전용 대상 조회 통과. 기존 차단 브로커 `GET /pending` HTTP 200 확인 |
| **Groot_B** `groot-siem` 10.200.10.10 | Wazuh SIEM + 읽기·룰 변경 MCP + 채팅 | ✅ 10/08: `ens192` 없음·기본 경로 A, Wazuh 000/001/002 Active, manager·indexer·dashboard·Mattermost·Hermes Up, `soc-bot`·보고/요약 타이머 active. 11:53~11:59 KST에는 Hermes 기존 3서버 enabled였고, 약 12:58 배포 뒤 `rule-a`·`rule-b`가 추가됐다. B `rulechg`·worker timer active/enabled, 승인 브로커 HMAC·읽기 전용 대상 조회 통과. Wazuh 운영 룰 해시는 배포 전후 동일. **신규 FW 접두어·WAF 100200+ 분류는 여전히 없음**. 디코더 차이는 주석 예시 IP 한 줄뿐 |
| **Groot_C** `groot-web` 10.200.10.20 | DVWA + CVE 랩 | ✅ 10/08: `ens192` 없음·기본 경로 A, Apache·Wazuh Agent·Docker active, DVWA 로그인 HTTP 200, `log4shell-lab` 실행 중(`10.200.10.20:8080` 내부 바인딩·HTTP 응답 확인), A NTP 동기화. C→B Wazuh 1514/tcp 연결 ESTAB; 랩 기능 전체 재현 시험은 하지 않음 |
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
- **승인형 룰 변경 MCP**(A/B, 2026-10-08 약 12:58 KST): B 브로커에 별도 룰 승인 API를 배포하고 A/B에 `rulechg` 강제 명령·root helper·worker timer를 설치했다. Hermes에 `rule-a`·`rule-b`를 추가하면서 기존 읽기·응답 MCP 서버를 유지했다. HMAC health와 세 로컬 룰 대상의 읽기 조회가 통과했고 운영 룰 해시는 배포 전후 동일했다. 실제 Mattermost 버튼 승인→룰 적용은 아직 검증하지 않았다.
- **문서**: `scenarios/`(탐지 검증 매트릭스 + 공개 표준 레퍼런스), infra README(A/B/C/MCP).

## 접속 치트시트 (Mac, ssh config 등록됨)
- SIEM 대시보드: **`https://wazuh.groot.lab`**(A:443 프록시; 학과망·VM세그먼트만, VPN·외부 403). VM세그먼트 직결이면 `https://192.168.16.230:10443` 도 가능. (admin, 비번 CREDENTIALS)
- 셸: `ssh groot-a` / `ssh groot-b-int` / `ssh groot-c-int`.
- **팀원 무설정 접속(2026-09-28, 공개 DNS=DuckDNS `grootlab.duckdns.org`→192.168.16.230)**: hosts·ssh config 없이 `https://chat.grootlab.duckdns.org` · `https://wazuh.grootlab.duckdns.org`(VPN 403) · `http://dvwa.grootlab.duckdns.org`. SSH 는 `ssh -J groot_a@grootlab.duckdns.org groot_b@10.200.10.10` 한 줄(C 는 10.200.10.20; 이름 기반이라 A IP 변경과 무관). 안내문 `팀접속안내.md`. **DuckDNS 등록 완료·학과망에서 이름만으로 실측 OK**(해석 4개, 채팅 200/101, 대시보드 302→로그인 200, DVWA 302, 당시 인증서 SNI 일치; 2026-09-28). 채팅 DuckDNS 이름은 10/08 공인 인증서로 전환했다.
- 내부 이름(클라이언트 /etc/hosts 에 `192.168.16.230 dvwa.groot.lab wazuh.groot.lab chat.groot.lab` 1줄):
  - 캠퍼스·VPN 공통: `http://dvwa.groot.lab/` · `https://chat.groot.lab/`(데스크톱 앱 동일 URL)
  - 대시보드: `https://wazuh.groot.lab/` (학과망·VM세그먼트만, VPN 403 — 보안상 VPN 비노출 유지). 자체서명 인증서 1회 신뢰(채팅 인증서와 별개)
- 읽기 MCP: 기존 Wazuh `ssh -T groot-mcp`, Suricata·ModSecurity 경보 `ssh -T groot-mcp security-events` · 응답 MCP: `ssh -T groot-resp`. 10/06 읽기 도구 2개의 LLM 호출을 확인했다. 10/08 룰 변경 전용 `rule-a`·`rule-b`를 추가해 Hermes에 총 5개 서버를 등록했고, 룰 대상의 읽기 조회를 확인했다.
- 수동 차단(A): `sudo agent_block add <ip> [ttl] [reason]` / `list` / `del <ip>`.

## 보류 / 다음
- **채팅 인증서 후속:** A 사설 IP에 도달하는 학교 Wi-Fi에서 `https://chat.grootlab.duckdns.org`로 Mattermost 모바일 앱 로그인을 검증한다. 사용자 보고에 따르면 학교 관리자는 관리 범위 확대를 이유로 모바일 GlobalProtect 지원을 거절했고, 사용자 휴대폰의 VPN 로그인도 실패했다. 기술적 실패 원인은 미확인이나 운영상 모바일 VPN 경로는 계획에서 제외한다. 이 실패는 채팅 인증서 시험 결과가 아니다. 만료 2027-01-06 전에 재발급·A 재배포한다(2026-12 초 준비 권장). Mac 임시 ACME 상태는 삭제했으므로 무인 갱신은 없다.
- **다음 작업·검증**: B 라이브 룰 파일에 없는 신규 FW(`SPOOF`/`FW_SSH_RATE`/`FW_DROP_FWD`/`FW_SHADOW_OUT`)·WAF(`GROOT_A/*` 100200–299) 디코더·룰을 추가하고 IPS local SID 1000xxx의 나머지 분류도 확인. SID `1000010`→Wazuh `100110`은 이미 관측했다. 이어 VM 세그먼트 공격 프로브로 WAF audit·IPS eve·FW 로그→Wazuh alerts 실발화를 시나리오별로 검증.
- **별도 전환**: WAF `On`과 IPS 인라인 drop은 아직 적용하지 않았다. 탐지 검증 후 차단 게이트와 평가 범위를 결정. Log4Shell egress 관찰용 `OBS_SEG` 룰은 저장소에만 있고 A 설치본에는 없다.
- **승인형 규칙 변경 MCP 후속 검증**: 11:46 KST에는 라이브 MCP 목록에 읽기 16툴·IP 차단 응답 3툴만 있었으나, 약 12:58 KST A/B 변경기·worker·Hermes 연결 배포를 완료했다. A의 WAF·Suricata와 B의 Wazuh **로컬 룰**만 조회·제안 대상으로 허용한다. 서버 간 승인 API는 nonce·양방향 HMAC을 사용하고, 지정 승인자가 Mattermost의 변경 전후 diff·해시 카드를 승인한 정확한 제안만 1회 적용하도록 구현했다. HMAC·읽기 조회를 확인하고 기존 읽기·응답 서버를 유지했지만 **실제 승인 버튼 클릭→룰 변경·복구 E2E는 미검증**이다. 운영 룰 해시는 배포 전후 동일하다. 기존 IP 차단 브로커의 설정 누락 시 즉시 실행 제약은 별개로 남아 있다. 상세 `infra/mcp/README.md`.
- **다음 후보**:
  1. 에이전트: **경보 트리거·Tier 2 승인·채팅 게이트웨이까지 완료(2026-09-28)** → 다음은 시나리오 실측(사용자 직접), 평가(MTTI/MTTR), 승인자 목록의 실제 팀원 구성·권한 검증.
  2. 시나리오 실제 실행(선행조건: DVWA `low`, A Log4Shell 토글 설치본 동기화·경로 검증, C sudo CVE 취약성 검증, Kali VM 세그먼트 직결). C의 `sudo --version`은 10/6에 **1.8.31**로 관측했으나 버전만으로 CVE-2021-3156 취약 여부를 확정하지 않는다.
  3. 응답툴 확장(`isolate_host`·`notify`), 지정 승인자 계정의 실제 버튼 권한 검증. 고위험 차단의 Tier 2 승인 경로는 9/28 검증 완료.
- **HITL 채널**: 온프레미스 Mattermost(B)와 Tier 2 [승인][거부] 버튼의 차단 E2E는 2026-09-28 실측이다. 2026-10-08 라이브 SSH에서 A의 브로커 URL·토큰, B의 브로커 토큰·허용 승인자 목록이 비어 있지 않음을 값 출력 없이 확인했다. A→B `GET /pending`은 HTTP 200(대기 0건)이었다. 오늘 승인 카드→클릭→차단 E2E는 재시험하지 않았다.
- **주의**: 공격성 테스트 트래픽은 캠퍼스 VPN 경유 금지(캠퍼스 FW가 차단). `never_block`에 관리 VPN 대역(192.168.15.0/24) 포함 — VPN 대역 바뀌면 갱신.

## 저장소 동기화 주의
- 10/6 라이브 적용 사실은 작업 기록에 있으나 저장소의 일부 배포 설정은 적용 전 상태일 수 있다. 배포 재실행 전 라이브와 비교해야 한다.
- 추적 문서 `로그_파이프라인.md`에서 발견한 평문 자격증명은 현재 작업 파일에서 제거하고 gitignored `CREDENTIALS.local.md` 참조로 바꿨다. 과거 Git 이력·이전 도구 출력에는 노출 흔적이 남아 있어 자격증명 교체와 이력 처리 범위를 별도로 결정해야 한다. 값은 문서에 옮기지 않는다.
