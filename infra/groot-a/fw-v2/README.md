# FW v2 — Groot_A "빡빡한 룰" (2026-10-01 설계, 2026-10-06 상태 갱신)

> **상태(2026-10-06 이번 세션 SSH 재점검): FW v2 적용·확정.** A의 `FORWARD=DROP`, `CAPSTONE-FWD` 14룰, nft v2 체인(`SPOOF`·`FW_SSH_RATE`·output)을 05:05~05:07 UTC에 재확인했다. 앞선 [세션 1 기록](../../../대화기록/2026-10-06.md)에는 데드맨 타이머 0, 대시보드 DNAT·A→B/C 경로 확인도 있다. **라이브 파일과 이 저장소 사본의 동일성은 대조하지 않았다.**
> A의 실측 외부 주소는 `192.168.16.230/25`(직결망 `192.168.16.128/25`, GW `.129`)인데, 라이브 10443 DNAT/`CAPSTONE-FWD`의 출발지 허용목록은 별도 `192.168.16.0/25`다. 이 값은 아래 P11의 설계와 같지만 Kali IP·라우팅이 미확인이라 의도한 실습 출발지를 허용하는지 판단할 수 없다. 시나리오 `OBS_SEG` 목적지도 동일한 `0/25`이므로 실제 경로를 확인한 뒤 재배포한다.
>
> 아래 파일 설명·절차·롤백은 2026-10-01~02의 설계 및 적용 준비 기록이다. 당시 `nft -c`(트랜잭션 형태)와 `bash -n`을 통과했다. 이번 SSH 재점검과 룰 수 재집계에서 WAF DetectionOnly/활성 커스텀 고유 ID 10개(기존 11개 기록은 오집계; `id:10010`은 주석 처리)와 IPS 합본(local SID 11개)·Phase-A passive를 확인했다. WAF `On`·IPS 인라인/drop 전환은 미완료다. B manager의 로컬 디코더·룰 파일에는 신규 FW 접두사·WAF 100200+ 분류가 **없다**. IPS local SID 분류는 별도 확인이 필요하며, 모두 공격 실발화 검증이 남았다. A의 브로커 URL·토큰 환경 변수는 설정돼 있고 일반 Tier 2 승인→차단 E2E는 9/28에 검증됐지만 이번 SSH에서 재시험하지 않았다.

## 파일
| 파일 | 역할 | 배포 경로(적용 시) |
|---|---|---|
| `capstone-fw.nft` | 호스트 FW v2(`inet capstone_fw`): 안티스푸핑, mgmt_src SSH 제한+레이트리밋, IPv6 drop, never_block 축소, **output 체인(섀도 기본)** | `/etc/nftables.d/capstone-fw.nft`(확정 전 `.pending`) |
| `capstone-nat.sh` | NAT + **FORWARD DROP + 전용 체인 `CAPSTONE-FWD`**(ext→int DNAT만, egress 허용목록, east-west, drop 로그), DNAT 출발지 제한, v1 블랭킷 룰 이관 제거, agent_block 보존 원자 로드 | `/usr/local/sbin/capstone-nat.sh`(v1 은 `.bak-v1`) |
| `99-capstone-fw.conf` | sysctl: rp_filter strict, redirects off, martians log, syncookies, ens192/ens160 IPv6 off | `/etc/sysctl.d/99-capstone-fw.conf` |
| `fw_apply_v2.sh` | 게이트형 적용: 사전점검(**접속 출발지가 mgmt_src 인지 자동 검사**) → `.pending` 설치 → 데드맨(기본 300s, **v2 전체 롤백**) → 적용 → 로컬 점검 → 외부 검증 목록 출력. `--enforce-output` 로 output 강제 | 실행만 |
| `fw_confirm_v2.sh` | 외부 검증 후 확정: 데드맨 해제, `.pending`→확정, v1 NAT 백업 보존 | `/usr/local/sbin/fw_confirm_v2.sh` |

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

## 2026-10-02 당시 적용 절차 (완료된 배치의 기록)
1. 반입: 이 폴더를 A `/tmp/fw-v2/` 로.
2. **`mgmt_src` 에 지금 접속 출발지 포함 확인**(VPN 192.168.15.x / 학과망 192.168.10.x·12.x). 현장 PC(192.168.16.x)에서 하려면 셋에 추가.
3. `sudo bash /tmp/fw-v2/fw_apply_v2.sh` → 데드맨 300s 안에 외부 검증(V1 목록) → `sudo fw_confirm_v2.sh`.
4. output 은 섀도로 1~2일 운용: `journalctl -k | grep FW_SHADOW_OUT` 검토 → 정당한 트래픽이면 output 체인에 allow 추가 → `fw_apply_v2.sh --enforce-output` 로 재적용(동일 데드맨 절차).
5. B/C 임시 NIC 제거 후: egress 허용목록(`EGRESS_ALLOW`) 효력 확인 — B→DGX OK, C→임의 외부 불통.

## 2026-10-02 당시 롤백 메모
- 아래 명령은 당시 초안의 수동 롤백 절차다. **확정된 라이브 v2에 그대로 실행할 절차로 취급하지 않는다.** 재변경 시 현장 백업·라이브 파일·데드맨 상태를 먼저 확인한다.
- 데드맨 발화 또는 수동: `nft delete table inet capstone_fw; rm -f /etc/nftables.d/capstone-fw.nft.pending; iptables -P FORWARD ACCEPT; iptables -D DOCKER-USER -j CAPSTONE-FWD; iptables -F CAPSTONE-FWD; iptables -X CAPSTONE-FWD; cp /usr/local/sbin/capstone-nat.sh.bak-v1 /usr/local/sbin/capstone-nat.sh; capstone-nat.sh; rm /etc/sysctl.d/99-capstone-fw.conf; sysctl --system`
- 확정 후 되돌리려면 v1 파일(`infra/groot-a/capstone-fw.nft`, `capstone-nat.sh`)을 같은 데드맨 절차로 재적용.

## 호환성·주의
- **시나리오 토글** `scenario_log4shell_route.sh`: 저장소 사본(`infra/groot-a/scenario_log4shell_route.sh`)은 OBS_SEG를 ON 시 `-I DOCKER-USER`로 `CAPSTONE-FWD` jump 앞에 넣고 OFF 시 제거한다. **2026-10-06 A 설치본(`/usr/local/sbin/scenario_log4shell_route.sh`)에는 OBS_SEG 구현이 없다.** 8080 NAT/DOCKER-USER 룰도 없어 토글은 OFF다. 저장소 사본을 라이브에 재배포한 뒤 ON/OFF와 C 아웃바운드 관찰 경로를 검증해야 한다.
- **agent_block**: 그대로. 재적용 시 커널/상태파일에서 차단 목록 복원(v1 동일).
- **Hermes@B → resp@A**: ens160 tcp/22 허용 유지. **A→B 브로커/웹훅/wazuh**: output 허용. **ProxyJump**: output 허용.
- **chatproxy/WAF 인바운드**: ext→br NEW 허용. **내부→A 공개서비스(80/443)** 는 drop(필요 시 `CAPSTONE-FWD` 에 추가).
- **사전검사 함정**: 바(bare) 파일 `nft -c -f` 는 라이브 interval 셋과 겹치면 EEXIST → v2 는 delete+include 트랜잭션으로 검사(실측 확인).
- 로그 접두사 신설(`SPOOF`, `FW_SSH_RATE`, `FW_DROP_FWD`, `FW_SHADOW_OUT`/`FW_DROP_OUT`): 이번 SSH 재점검에서 B manager `local_decoder.xml`·`local_rules.xml`에 신규 분류가 **없음**을 확인했다. 추가 후 VM 세그먼트 공격 프로브로 `alerts.json`까지 검증해야 한다(기존 `FW_DROP_IN`/`AGENT_BLOCK` 룰 100120~ 참고).
