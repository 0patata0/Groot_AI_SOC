# FW v2 초안 — Groot_A "빡빡한 룰" (2026-10-01)

> **상태: 초안, 미적용.** 라이브 A 는 v1 그대로. 담당자 IPS/WAF 룰과 취합(`보안룰_취합.md`)한 뒤 일괄 반영.
> 검증: nft 문법은 A 에서 `nft -c`(체크 전용, 적용 없음)로 섀도/강제 두 변형 모두 통과(트랜잭션 형태). 스크립트는 `bash -n` 통과. **동작 검증은 적용 시 데드맨 아래서.**

## 파일
| 파일 | 역할 | 배포 경로(적용 시) |
|---|---|---|
| `capstone-fw.nft` | 호스트 FW v2(`inet capstone_fw`): 안티스푸핑, mgmt_src SSH 제한+레이트리밋, IPv6 drop, never_block 축소, **output 체인(섀도 기본)** | `/etc/nftables.d/capstone-fw.nft`(확정 전 `.pending`) |
| `capstone-nat.sh` | NAT + **FORWARD DROP + 전용 체인 `CAPSTONE-FWD`**(ext→int DNAT만, egress 허용목록, east-west, drop 로그), DNAT 출발지 제한, v1 블랭킷 룰 이관 제거, agent_block 보존 원자 로드 | `/usr/local/sbin/capstone-nat.sh`(v1 은 `.bak-v1`) |
| `99-capstone-fw.conf` | sysctl: rp_filter strict, redirects off, martians log, syncookies, ens192/ens160 IPv6 off | `/etc/sysctl.d/99-capstone-fw.conf` |
| `fw_apply_v2.sh` | 게이트형 적용: 사전점검(**접속 출발지가 mgmt_src 인지 자동 검사**) → `.pending` 설치 → 데드맨(기본 300s, **v2 전체 롤백**) → 적용 → 로컬 점검 → 외부 검증 목록 출력. `--enforce-output` 로 output 강제 | 실행만 |
| `fw_confirm_v2.sh` | 외부 검증 후 확정: 데드맨 해제, `.pending`→확정, v1 백업 정리 | `/usr/local/sbin/fw_confirm_v2.sh` |

## v1 → v2 변경 매핑 (`보안룰_취합.md` 0-B)
| P | 내용 | 어디서 |
|---|---|---|
| P1 | FORWARD 정책 DROP, 비허용 forward 차단 | `capstone-nat.sh` §4 |
| P2 | 내부→외부 egress 허용목록(`EGRESS_ALLOW`: DGX .110/.111:11434, DNS) — **B/C 임시 NIC 제거 후 효력** | `capstone-nat.sh` |
| P3 | A 자신 output 체인 — **섀도(로그만)** 기본, `--enforce-output` 으로 강제 | `capstone-fw.nft` output |
| P4 | ens192 SSH 출발지 `mgmt_src`(VPN·학과망 2개·ESXi) + 신규연결 6/min(버스트 10) 레이트리밋(`FW_SSH_RATE`) | `capstone-fw.nft` input |
| P5 | 안티스푸핑: ens192 에서 내부/루프백/0.0.0.0/8/멀티캐스트/자기IP 출발지 drop, ens160 에서 비내부 drop(`SPOOF` 로그) + sysctl rp_filter=1·send_redirects=0·log_martians=1 | `capstone-fw.nft` prerouting_block, sysctl |
| P7 | IPv6 input/output drop + ens192/ens160 disable_ipv6 | nft, sysctl |
| P8 | 컨테이너 east-west: WAF→C:80, chatproxy→B:8065/443 만(`EASTWEST_ALLOW`) | `capstone-nat.sh` |
| P9 | forward drop 로그 `FW_DROP_FWD `(5/min) → Wazuh 측면이동 신호. output 섀도 `FW_SHADOW_OUT ` | nat, nft |
| P11 | 10443 DNAT 출발지 `192.168.16.0/25` 만 | `capstone-nat.sh` §3 |
| P12 | never_block 172.16.0.0/12 → 172.17/18/19.0.0/16, 관리 대역(학과망 2개) 추가 | `capstone-fw.nft` |
| — | v1 `fw_phase2.sh` 사전점검 정규식 버그(`10\.10\.10\.1`) 수정본 반영 | `fw_apply_v2.sh` G0 |

**미반영(별도 결정)**: P6(Docker 공개포트 외부 IP 바인딩 — compose 파일 변경 사항), P10(`conntrack` 설치 + agent_block 세션 종료 — 패키지 반입 후).

## 적용 절차 (취합 시)
1. 반입: 이 폴더를 A `/tmp/fw-v2/` 로.
2. **`mgmt_src` 에 지금 접속 출발지 포함 확인**(VPN 192.168.15.x / 학과망 192.168.10.x·12.x). 현장 PC(192.168.16.x)에서 하려면 셋에 추가.
3. `sudo bash /tmp/fw-v2/fw_apply_v2.sh` → 데드맨 300s 안에 외부 검증(V1 목록) → `sudo fw_confirm_v2.sh`.
4. output 은 섀도로 1~2일 운용: `journalctl -k | grep FW_SHADOW_OUT` 검토 → 정당한 트래픽이면 output 체인에 allow 추가 → `fw_apply_v2.sh --enforce-output` 로 재적용(동일 데드맨 절차).
5. B/C 임시 NIC 제거 후: egress 허용목록(`EGRESS_ALLOW`) 효력 확인 — B→DGX OK, C→임의 외부 불통.

## 롤백
- 데드맨 발화 또는 수동: `nft delete table inet capstone_fw; rm -f /etc/nftables.d/capstone-fw.nft.pending; iptables -P FORWARD ACCEPT; iptables -D DOCKER-USER -j CAPSTONE-FWD; iptables -F CAPSTONE-FWD; iptables -X CAPSTONE-FWD; cp /usr/local/sbin/capstone-nat.sh.bak-v1 /usr/local/sbin/capstone-nat.sh; capstone-nat.sh; rm /etc/sysctl.d/99-capstone-fw.conf; sysctl --system`
- 확정 후 되돌리려면 v1 파일(`infra/groot-a/capstone-fw.nft`, `capstone-nat.sh`)을 같은 데드맨 절차로 재적용.

## 호환성·주의
- **시나리오 토글** `scenario_log4shell_route.sh`: `-I DOCKER-USER` 로 맨 위에 넣으므로 `CAPSTONE-FWD` jump(`-A`)보다 먼저 매칭 → ON/OFF 그대로 동작. **C 아웃바운드 관찰(JNDI 콜백·유출)을 Suricata 로 보려면** ON 시 `iptables -I DOCKER-USER -s 10.200.10.20 -i ens160 -o ens192 -d 192.168.16.0/25 -j ACCEPT`(OFF 시 `-D`)를 토글에 추가해야 함(NIC 제거 후 필수).
- **agent_block**: 그대로. 재적용 시 커널/상태파일에서 차단 목록 복원(v1 동일).
- **Hermes@B → resp@A**: ens160 tcp/22 허용 유지. **A→B 브로커/웹훅/wazuh**: output 허용. **ProxyJump**: output 허용.
- **chatproxy/WAF 인바운드**: ext→br NEW 허용. **내부→A 공개서비스(80/443)** 는 drop(필요 시 `CAPSTONE-FWD` 에 추가).
- **사전검사 함정**: 바(bare) 파일 `nft -c -f` 는 라이브 interval 셋과 겹치면 EEXIST → v2 는 delete+include 트랜잭션으로 검사(실측 확인).
- 로그 접두사 신설(`SPOOF`, `FW_SSH_RATE`, `FW_DROP_FWD`, `FW_SHADOW_OUT`/`FW_DROP_OUT`): B Wazuh 로컬 룰 추가 필요(기존 `FW_DROP_IN`/`AGENT_BLOCK` 룰 100120~ 참고).
