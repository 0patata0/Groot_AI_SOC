# Groot_A (groot-sec) — 보안 게이트웨이 구성 요약

A = 외부(ens192 192.168.16.230, 캠퍼스 세그먼트) ↔ 내부(ens160 10.200.10.1) 관문. NAT·포워딩·호스트 방화벽·차단 셋·IDS·WAF·NTP 서버·Wazuh 에이전트가 여기 있다.

> **2026-10-06 기록 및 10/08 SSH 재확인:** FW v2 적용·확정(`FORWARD=DROP`, `CAPSTONE-FWD` 14룰), WAF GROOT 룰 마운트·healthy·`nginx -t` 통과(`DetectionOnly`), Suricata `-i ens192 -S /rules/all.rules` 및 Phase-A(passive). 신규 FW 접두어·WAF 100200대 전용 분류는 없으나 읽기 조회에서 Suricata 로컬 SID `1000010`→Wazuh `100110`, ModSecurity CRS `920350`→Wazuh `100101`을 확인했다. 나머지 로컬 룰 분류와 시나리오별 공격 프로브 발화는 미검증이다. WAF `On`·IPS 인라인 전환은 남아 있다. [기존 확인 기록](../../대화기록/2026-10-06.md)

> **2026-10-08 관리 SSH 직접 재확인:** WAF 커스텀 ID 10개·Suricata 로컬 SID 11개의 라이브 파일 해시가 저장소와 각각 일치한다. WAF는 여전히 `DetectionOnly`, Suricata는 passive이고 인라인 queue 룰은 0개다. FW `FORWARD DROP`·14룰, nft input DROP·output ACCEPT이며 현재 임시 IP 차단은 0건이다. A 브로커 URL·토큰이 설정됐고 A→B 인증된 `GET /pending` HTTP 200이었다(승인→차단 E2E 미시험). [오늘 기록](../../대화기록/2026-10-08.md)

> **같은 날 약 12:58 KST 후속 배포:** A에 별도 `rulechg` SSH 강제 명령·root 소유 고정 대상 helper·`rule-change-worker.timer`를 배포했다(active/enabled). B 승인 브로커와의 HMAC 통신 및 WAF·Suricata 로컬 룰 **읽기 조회**가 통과했다. 두 운영 룰 해시는 배포 전후 동일하다. 실제 Mattermost 승인 버튼→룰 적용·복구 E2E는 아직 검증하지 않았다. [배포 절차](../mcp/rule-change-deploy.md)

> **시간·자동화 구성:** A/B/C 호스트는 `Asia/Seoul`(KST)이며 10/08 NTP 동기화를 재확인했다. 같은 날 A의 n8n은 컨테이너·이미지·서비스·프로세스·일반 설치 경로·5678 수신 흔적이 없어 배포·가동된 근거가 없었다. 자동화는 B의 Hermes·SOC 봇·systemd 타이머가 담당한다.

Log4Shell 경로는 이번 SSH 점검에서 **토글 OFF**(A:8080 NAT·DOCKER-USER 시나리오 룰 없음)였다. 저장소의 `scenario_log4shell_route.sh`에는 C→`OBS_SEG` 관찰 룰이 있으나 A에 설치된 `/usr/local/sbin/scenario_log4shell_route.sh`에는 없다. A `ens192`는 `192.168.16.230/25`(직결 `192.168.16.128/25`)인데, 라이브 10443 DNAT/CAPSTONE-FWD 출발지 제한과 저장소 `OBS_SEG`는 `192.168.16.0/25`다. Kali 주소·왕복 경로를 확인하고 설치본을 동기화한 뒤 시나리오를 검증해야 한다.

| 구성 | 파일(repo → A) | 요점 |
|---|---|---|
| NAT + 포트포워딩 + 호스트 FW 로더 | `fw-v2/capstone-nat.sh` → `/usr/local/sbin/capstone-nat.sh`, `capstone-nat.service`, `99-capstone-nat.conf` | 부팅 시(docker 이후) 실행. `capstone_gw` NAT·대시보드 10443→B:443 DNAT·`CAPSTONE-FWD` 허용목록, `FORWARD=DROP`, nft FW 로드 + 차단목록 복원. 루트의 `capstone-nat.sh`는 이전 버전 소스. |
| 호스트 방화벽 + 차단 | `fw-v2/capstone-fw.nft` → `/etc/nftables.d/capstone-fw.nft` | `inet capstone_fw`: 기존 input/`agent_block` 보호에 anti-spoof(`SPOOF`), `mgmt_src` SSH 레이트리밋(`FW_SSH_RATE`), output 체인 추가. 루트의 `capstone-fw.nft`는 이전 버전 소스. |
| 차단 인터페이스 | `agent_block` → `/usr/local/sbin/agent_block` | `add <ip> [ttl] [reason]` / `del` / `list` / `flush`. exit 0 ok · 2 invalid · 3 rejected(보호 대상·활성 SSH 출발지) · 4 nft 실패. 상태 `/var/lib/capstone/agent_block.state`(재부팅 복원). 전 동작 syslog(tag agent_block)→Wazuh |
| FW v2 적용 이력·향후 재적용 | `fw-v2/fw_apply_v2.sh`, `fw-v2/fw_confirm_v2.sh` | 300초 데드맨 아래 적용·외부 검증 후 확정했고, 10월 6일 타이머 0을 확인. `fw_phase2.sh`/`fw_confirm.sh`는 이전 단계 스크립트. |
| IDS + WAF | `docker-compose.yml`, `deploy_secstack.sh`, `suricata-rules.md`, `../../new_rule/` | 라이브 WAF는 GROOT 룰을 로드한 `DetectionOnly`, Suricata 8.0.6은 ET+로컬 `all.rules`(47,694,450바이트, 로컬 SID 11줄)·Phase-A(community-id, JA3/JA4, threshold 파일 존재) 수동 탐지. 로그 `~/capstone/secstack/logs/`. **저장소 Compose는 초기 템플릿**이므로 라이브 설정을 대조하기 전 재배포 금지. |
| Wazuh 에이전트 | `install_agent.sh`, `agent_localfile.sh`, `logrotate-capstone-secstack` | ID 001 groot-sec. eve.json·audit.log·journald(커널 nft 로그, agent_block 감사) 수집 |
| NTP 서버 | `ntp_server.sh` | chrony ← 캠퍼스 192.168.16.131, B/C 에 10.200.10.1:123 서비스(`bindaddress`) |
| 응답(차단) MCP 서버 | `../mcp/{response-mcp.py, run-response.sh, deploy_response_A.sh}`, `agent_block_reaper.sh` | 사용자 `resp` + sshd ForceCommand + sudoers(agent_block add/del/list). 에이전트가 `ssh -T groot-resp` 로 block_ip/unblock_ip/list_blocks 호출 → `agent_block`. TTL 만료 리퍼(타이머 `capstone-block-reaper`) → Wazuh 100131. 이번 SSH 점검에서 A의 `/etc/resp/hitl.env`에 브로커 URL·토큰이 설정된 것은 확인했으나 승인 후 차단 종단 간 동작은 재시험하지 않았다. |
| 승인형 로컬 룰 변경 MCP | `../mcp/{rule_change_mcp.py,rule_change_executor.py,deploy_rule_change_A.sh}` | `rulechg` 전용 계정·SSH 강제 명령과 root helper로 WAF·Suricata 로컬 룰만 처리한다. B 브로커가 승인한 제안을 10초 worker가 확인한다. HMAC·읽기 조회 통과, 실제 승인→룰 적용 E2E는 미검증. |

## DuckDNS 채팅 공인 인증서 설치

**2026-10-08 라이브 적용:** `chat.grootlab.duckdns.org` 단일 이름 Let's Encrypt 인증서를 설치했다(만료 2027-01-06 15:02 KST). 배포 스크립트의 SNI·CA 검증 Mattermost ping과 Mac `curl` HTTP 200/인증서 검증을 통과했다. Mac·A의 임시 발급/전송 파일은 삭제했다. Mac ACME 상태도 삭제했으므로 자동 갱신은 없고, 2026-12 초 임시 환경에서 재발급·A 재배포를 준비한다. 사용자 보고에 따르면 학교 관리자가 관리 범위 확대를 이유로 모바일 GlobalProtect 지원을 거절했고 휴대폰 VPN 로그인도 실패했다. 모바일 VPN은 검증 경로에서 제외하며, A에 도달하는 학교 내부 Wi-Fi의 Mattermost 앱 로그인은 미검증이다. [발급·운영 이력](../dns/README.md).

ACME·DuckDNS HTTPS에 도달할 수 있는 장치에서 DNS-01 방식으로 `chat.grootlab.duckdns.org` 또는 `*.grootlab.duckdns.org` 인증서를 발급한다. A는 발급에 필요한 외부 HTTPS에 도달하지 못하므로, 발급된 `fullchain.pem`과 암호 없는 `privkey.pem`을 A에 안전하게 복사한 뒤 다음 명령을 A에서 실행한다. 개인키와 DuckDNS 토큰은 저장소에 넣지 않는다.

```bash
sudo bash deploy_chatduck_cert_A.sh --check-only /root/certs/fullchain.pem /root/certs/privkey.pem
sudo bash deploy_chatduck_cert_A.sh /root/certs/fullchain.pem /root/certs/privkey.pem
```

`deploy_chatduck_cert_A.sh`는 호스트명 SAN·남은 유효기간·키 일치·신뢰 체인을 검증하고, 기존 `chatduck.crt/key`를 권한 제한 백업한 뒤 두 파일을 교체한다. 이어서 `nginx -t`, 재로드, 실제 SNI 인증서와 CA 검증을 사용하는 Mattermost ping을 확인하며, 실패하면 기존 파일을 복원하고 다시 재로드한다. `chat.groot.lab`·Wazuh 인증서 및 대시보드 허용목록은 건드리지 않는다. 갱신된 인증서도 같은 절차로 다시 배포해야 한다.

스크립트의 체인 검증은 **A 호스트의 신뢰 저장소 기준**이다. 실제 휴대폰 검증은 A `192.168.16.230`에 도달하는 학교 내부 Wi-Fi에서 브라우저로 `https://chat.grootlab.duckdns.org/api/v4/system/ping`을 확인한 뒤 Mattermost 앱에 같은 채팅 서버 주소로 로그인하는 순서다. 휴대폰 GlobalProtect 로그인 실패의 기술적 원인은 미확인이며 채팅 인증서 검증 결과와 구분한다.

## 자주 쓰는 명령 (A에서, sudo)
```
agent_block add 203.0.113.7 10m alert:1790431732.31   # 차단(사유는 감사용)
agent_block list ; agent_block del 203.0.113.7
nft list table inet capstone_fw                        # 현재 방화벽
journalctl -k -g 'AGENT_BLOCK|FW_DROP_IN|SPOOF|FW_SSH_RATE|FW_DROP_FWD|FW_SHADOW_OUT' -n 20  # 경계/FW v2 로그
systemctl restart capstone-nat                         # NAT/포워딩/FW 전부 재적용(차단목록 보존)
systemctl list-timers capstone-block-reaper.timer      # TTL 만료 감사 리퍼(60s)
```
응답 MCP 서버는 에이전트가 `ssh -T groot-resp` 로 호출(운영자가 직접 쓸 일은 없음; 수동 차단은 위 `agent_block`).

## 절대 하지 말 것
- `nft flush ruleset`, `nft -f /etc/nftables.conf`, `systemctl unmask/start nftables` — Docker·NAT·FW 전부 날아감(`nftables.service`는 mask 되어 있음).
- `never_block`(내부망·Docker·lo·A·GW·ESXi·NTP·DNS·관리 VPN 대역·구 B/C 외부 IP)을 라이브 접속 경로 검증 없이 좁히기. raw 훅이라 기존 SSH 세션도 즉시 끊길 수 있다.
- 캠퍼스 VPN 경유로 공격 트래픽 보내기(캠퍼스 FW가 쌍 차단).

## 포트 정리 (ens192 기준)
22 SSH(허용된 관리 출발지·MCP 점프) · 80 WAF→DVWA · **443 chatproxy→B 채팅/대시보드**(이름 기반) · 8443 WAF TLS · 10443→B:443 대시보드 DNAT **룰 존재**(허용 소스 `192.168.16.0/25`; Kali에서의 실제 도달성 미검증). 9/28 채팅·대시보드 이름 기반 응답과 10/08 채팅 인증서 배포 후 HTTPS ping을 검증했다. Wazuh 대시보드는 학과망·VM세그먼트 허용, VPN 403 정책을 유지한다. 공격성 트래픽은 캠퍼스 VPN 경유 금지.
