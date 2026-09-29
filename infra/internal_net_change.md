# 내부망 대역 변경 런북 — 10.10.10.0/24 → 10.200.10.0/24 (2026-09-29 적용 완료)

> 작성 2026-09-29. 배경: 학과 코어 라우터가 10.10.10.0/24 를 사용(traceroute 실측: 10.10.10.13 → 10.10.10.1)해 우리 내부망과 겹친다.
> 내부 포트그룹은 격리돼 있어 지금 당장 통신 장애는 없지만, A 의 `never_block`(내부망 보호)·Suricata `HOME_NET`·에이전트 프롬프트의 "내부 소음" 판정이
> 전부 `10.10.10.0/24` 를 "우리 것"으로 취급한다 → 캠퍼스 쪽 10.10.10.x 장비가 A 외부면에 나타나면 **차단 불가·내부 소음으로 오판**된다.
> 겹치지 않는 대역으로 바꾸면 "내부 = 우리 VM" 정의가 명확해진다. **상태: 실행 완료(2026-09-29, 10.200.10.0/24 적용·E2E 검증)** — 아래 목록은 실제 적용된 변경과 일치. 각 호스트 원본은 `*.bak-intnet-<시각>` 으로 보존.

## 대역 선택
| 후보 | 판단 |
|---|---|
| **10.200.10.0/24** (권장) | 호스트 번호 유지(A=.1, B=.10, C=.20) → 치환이 기계적. 캠퍼스 실측 대역(192.168.10/12/15/16.x, 10.10.10.x)·DGX(211.170.162.x)·Docker 브리지(172.17~19.x)와 무관. Mac 라우팅표에 별도 경로 없음(기본경로만) |
| 192.168.200.0/24 | 캠퍼스가 192.168.x 를 여러 개 쓰므로 미래 충돌 가능성이 상대적으로 높음 |
| 172.30.x.x | Docker compose 가 172.16.0.0/12 안에서 브리지를 순차 할당 → 언젠가 충돌 |

IT 에 "10.200.10.0/24 를 캠퍼스에서 쓰는지" 한 줄 확인하면 더 좋다(필수는 아님 — 내부 포트그룹은 격리).

## 사전 조건 (안전장치)
- **B/C 임시 NIC(.233/.234) 제거 전에 실행** — 변경 중 세 VM 모두 외부 NIC 로 직접 SSH 가능(학과망에서 .233/.234:22 open 실측) → 내부망을 건드려도 잠금 위험 0. NIC 제거 후엔 B/C 가 A 경유(내부망)로만 닿아 위험이 커진다.
- A 외부 IP 재변경(09-29)과는 독립(ens192 는 손대지 않음). 다만 같은 시간에 두 변경을 섞지 않는다.
- C 는 담당자 VM → netplan/ossec/apache/컨테이너 변경을 사전 공지.
- Wazuh 에이전트는 IP `any` 로 등록돼 있어(client.keys 001/002) 재등록 불필요.

## 변경 목록 (실측 인벤토리, 백업 파일 제외)
### A (groot-sec)
| 항목 | 내용 | 반영 |
|---|---|---|
| `/etc/netplan/50-cloud-init.yaml` | ens160 `10.10.10.1/24` | `netplan apply` |
| `/etc/hosts` | 3 줄(groot-sec/siem/web) | 즉시 |
| `/etc/chrony/chrony.conf` | `bindaddress 10.10.10.1`, `allow 10.10.10.0/24` | chrony 재시작 |
| `/etc/nftables.d/capstone-gw.nft` | `ip saddr 10.10.10.0/24 … masquerade` | nft 재적용 |
| `/etc/nftables.d/capstone-fwd.nft` | `dport 10443 dnat to 10.10.10.10:443` | nft 재적용 |
| `/etc/nftables.d/capstone-fw.nft` | `never_block` 셋 원소 `10.10.10.0/24` | nft 재적용(런타임 셋도 갱신) |
| `/usr/local/sbin/capstone-nat.sh` | `INT_NET`, 포워딩 표(10443→B) | 재실행 |
| `/usr/local/sbin/scenario_log4shell_route.sh` | DNAT 대상 `10.10.10.20:8080` | 파일만(OFF 상태) |
| `secstack/docker-compose.yml` | `extra_hosts groot-web:10.10.10.20`, Suricata `--set vars.address-groups.HOME_NET=[10.10.10.0/24,192.168.16.230/32]` | `compose up -d`(waf·suricata 재생성, ~20초 단절) |
| `chatproxy/nginx.conf` | upstream `10.10.10.10:8065`, `10.10.10.10:443` (8곳) | `compose restart chatproxy`(bind mount) |
| `/etc/resp/hitl.env` | `RESP_NOTIFY_URL`(B 웹훅), `RESP_BROKER_URL` | 파일만(응답 MCP 는 세션마다 새로 읽음) |
| `/home/groot_a/.ssh/authorized_keys` | 팀 점프키 `permitopen="10.10.10.10:22"` | 즉시 |
| Wazuh 에이전트 | `<address>groot-siem</address>`(이름) → hosts 만 바꾸면 됨 | wazuh-agent 재시작 |

### B (groot-siem)
| 항목 | 내용 | 반영 |
|---|---|---|
| `/etc/netplan/50-cloud-init.yaml` | ens160 `10.10.10.10/24` | `netplan apply` |
| `/etc/hosts` | 3 줄 | 즉시 |
| `/etc/systemd/timesyncd.conf.d/capstone.conf` | `NTP=10.10.10.1`, `FallbackNTP` | timesyncd 재시작 |
| `mattermost/docker-compose.yml` + `.env` | publish `10.10.10.10:8065:8065`, `MM_ALLOWED_INTERNAL=… 10.10.10.10 …` | `compose up -d`(채팅 ~10초 단절) |
| `/etc/socbot/soc_bot.env` | `MM_WEBHOOK=http://10.10.10.10:8065/hooks/…` | soc-bot 재시작 |
| `/opt/hermes-data/.env` | `MATTERMOST_URL=http://10.10.10.10:8065` | hermes 컨테이너 재시작 |
| `/opt/hermes-data/home/.ssh/config` | `mcp-b` HostName `10.10.10.10`, `resp-a` HostName `10.10.10.1` | hermes 재시작 |
| `/opt/hermes-data/scripts/recent_alerts.sh` | `SOC_BOT_URL` 기본값 | 즉시 |
| `/opt/hermes-data/cron/jobs.json` | soc-alert-watch 프롬프트의 "내부 소음" 대역 `10.10.10.0/24` | jobs.json 편집 후 hermes 재시작(또는 cron 재생성) |
| Wazuh 매니저/대시보드/인덱서 | 0.0.0.0 바인딩, 에이전트 IP any | 변경 없음 |

### C (groot-web) — 담당자 공지 후
| 항목 | 내용 | 반영 |
|---|---|---|
| `/etc/netplan/50-cloud-init.yaml` | ens160 `10.10.10.20/24` | `netplan apply` |
| `/etc/hosts` | 3 줄 | 즉시 |
| `/etc/systemd/timesyncd.conf.d/capstone.conf` | `NTP=10.10.10.1` | timesyncd 재시작 |
| `/etc/apache2/conf-available/capstone-remoteip.conf` | `RemoteIPInternalProxy 10.10.10.1` | apache reload |
| `/var/ossec/etc/ossec.conf` | `<address>10.10.10.10</address>`, `<manager_address>` | wazuh-agent 재시작 |
| `log4shell-lab` 컨테이너 | `-p 10.10.10.20:8080:8080` | 컨테이너 재생성(같은 이미지·restart 정책) |

### Mac / 저장소
- `~/.ssh/config`: `groot-b-int`·`groot-c-int`·`groot-mcp` HostName 3곳(사용자 승인 후).
- `팀접속안내.md`(`ssh -J … groot_b@10.10.10.10`), STATUS.md, PLAN.md, infra/*/README, 배치 스크립트 원본(`chatproxy.nginx.conf`, `capstone-nat.sh`, `fw_phase2.sh`, `scenario_log4shell_route.sh`, `ntp_server.sh`, `ntp_client.sh`, `c_integrate.sh`, `deploy_hermes_B.sh`, `deploy_chatproxy_A.sh`, `deploy_mcp_B.sh`, `hitl.env.example`, `config.example.yaml`, `recent_alerts.sh`, `soc_alert_watch.prompt`, `scenarios/scenario-2-log4shell.md`). 대화기록/과거 로그는 그대로 둔다(역사).

## 실행 순서 (예상 30~40분, 단절: 채팅 ~10초·WAF/IDS ~20초·Hermes ~1분)
1. 세 VM 에 외부 NIC 로 각각 SSH 세션 확보(A .230, B .233, C .234). ESXi 스냅샷 권장(선택).
2. **netplan 을 A→B→C 순으로 새 주소로 적용**(내부 링크만 바뀜). `ping` A↔B↔C 새 주소 확인.
3. A: hosts·chrony·nft 3파일 + `capstone-nat.sh` 재실행·`never_block` 런타임 갱신 → secstack `compose up -d` → chatproxy 재시작 → hitl.env·authorized_keys·scenario 스크립트 → wazuh-agent 재시작.
4. B: hosts·timesyncd → mattermost `compose up -d` → soc-bot 재시작 → hermes(.env/ssh config/recent_alerts/jobs.json) 재시작.
5. C: hosts·timesyncd·apache reload·ossec.conf·wazuh-agent 재시작·log4shell-lab 재생성.
6. 검증: Wazuh 에이전트 3대 Active / `https://wazuh.grootlab.duckdns.org` 302→200 / chat 200·ws 101 / DVWA 302(WAF→C) / `chronyc clients` 에 B·C / soc_bot 웹훅 게시 / Hermes `chat -q` 로 MCP 17 툴 등록 / block_ip 승인 카드 1회 / `sudo agent_block list`.
7. Mac ssh config·저장소 문서·스크립트 원본 갱신 → 커밋. 메모리(캠퍼스 정책·Hermes 레이아웃) 갱신.

## 롤백
각 호스트 netplan/설정 파일은 `*.bak-<시각>` 으로 남기고, 실패 시 역순으로 되돌린다. 외부 NIC 경로가 살아 있으므로 언제든 접근 가능.
