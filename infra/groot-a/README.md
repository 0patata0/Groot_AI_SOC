# Groot_A (groot-sec) — 보안 게이트웨이 구성 요약 (2026-09-27 기준)

A = 외부(ens192 192.168.16.230, 캠퍼스 세그먼트) ↔ 내부(ens160 10.200.10.1) 관문. NAT·포워딩·호스트 방화벽·차단 셋·IDS·WAF·NTP 서버·Wazuh 에이전트가 여기 있다.

| 구성 | 파일(repo → A) | 요점 |
|---|---|---|
| NAT + 포트포워딩 + 호스트 FW 로더 | `capstone-nat.sh` → `/usr/local/sbin/`, `capstone-nat.service`, `99-capstone-nat.conf` | 부팅 시(docker 이후) 실행. ①masquerade `capstone_gw` ②DOCKER-USER forward 허용 ③`PORTFORWARDS` 목록 → `capstone_fwd`(DNAT+회신 SNAT) ④`capstone-fw.nft` 원자적 로드 + 차단목록 복원 |
| 호스트 방화벽 + 차단 | `capstone-fw.nft` → `/etc/nftables.d/capstone-fw.nft` | `inet capstone_fw`: input 기본 drop(허용 lo/established/ICMP/내부 NTP/SSH), 캠퍼스 L2 잡음 무로그 drop, `FW_DROP_IN` 미터 로그; raw prerouting `agent_block` 셋 drop + `never_block` 잠금가드 + `AGENT_BLOCK` 로그 |
| 차단 인터페이스 | `agent_block` → `/usr/local/sbin/agent_block` | `add <ip> [ttl] [reason]` / `del` / `list` / `flush`. exit 0 ok · 2 invalid · 3 rejected(보호 대상·활성 SSH 출발지) · 4 nft 실패. 상태 `/var/lib/capstone/agent_block.state`(재부팅 복원). 전 동작 syslog(tag agent_block)→Wazuh |
| FW 배치 절차 | `fw_phase2.sh`, `fw_confirm.sh` | 규칙을 `.pending`으로 적용 + 데드맨 타이머(300s) → 외부에서 SSH/대시보드/WAF/NTP/MCP 검증 → `sudo fw_confirm.sh`(확정). 미확인 시 자동 원복(부팅 파일도 없음) |
| IDS + WAF | `docker-compose.yml`, `deploy_secstack.sh`, `suricata-rules.md` | Suricata 8.0.6 IDS(ens192, ET Open, HOME_NET 교정) + ModSecurity CRS(80→C DVWA, TLS 8443). 로그 `~/capstone/secstack/logs/` |
| Wazuh 에이전트 | `install_agent.sh`, `agent_localfile.sh`, `logrotate-capstone-secstack` | ID 001 groot-sec. eve.json·audit.log·journald(커널 nft 로그, agent_block 감사) 수집 |
| NTP 서버 | `ntp_server.sh` | chrony ← 캠퍼스 192.168.16.131, B/C 에 10.200.10.1:123 서비스(`bindaddress`) |
| 응답(차단) MCP 서버 | `../mcp/{response-mcp.py, run-response.sh, deploy_response_A.sh}`, `agent_block_reaper.sh` | 사용자 `resp` + sshd ForceCommand + sudoers(agent_block add/del/list). 에이전트가 `ssh -T groot-resp` 로 block_ip/unblock_ip/list_blocks 호출 → `agent_block`. TTL 만료 리퍼(타이머 `capstone-block-reaper`) → Wazuh 100131 |

## 자주 쓰는 명령 (A에서, sudo)
```
agent_block add 203.0.113.7 10m alert:1790431732.31   # 차단(사유는 감사용)
agent_block list ; agent_block del 203.0.113.7
nft list table inet capstone_fw                        # 현재 방화벽
journalctl -k -g 'AGENT_BLOCK|FW_DROP_IN' -n 20        # 드롭 로그
systemctl restart capstone-nat                         # NAT/포워딩/FW 전부 재적용(차단목록 보존)
systemctl list-timers capstone-block-reaper.timer      # TTL 만료 감사 리퍼(60s)
```
응답 MCP 서버는 에이전트가 `ssh -T groot-resp` 로 호출(운영자가 직접 쓸 일은 없음; 수동 차단은 위 `agent_block`).

## 절대 하지 말 것
- `nft flush ruleset`, `nft -f /etc/nftables.conf`, `systemctl unmask/start nftables` — Docker·NAT·FW 전부 날아감(`nftables.service`는 mask 되어 있음).
- `never_block`(내부망·Docker·lo·A·GW·ESXi·NTP·DNS·관리 VPN 대역·B/C 임시외부)을 좁히기. 잠금 방지의 전부다. raw 훅이라 기존 SSH 세션도 즉시 끊긴다.
- 캠퍼스 VPN 경유로 공격 트래픽 보내기(캠퍼스 FW가 쌍 차단).

## 포트 정리 (ens192 기준)
22 SSH(관리·MCP 점프) · 80 WAF→DVWA · 443 → B 대시보드(DNAT) · 8443 WAF TLS(캠퍼스 세그먼트만) · 그 외 drop(로그). VPN에서는 22/80/443만 도달.
