# A SPOOF 로그 소음(DHCP 브로드캐스트) 축소 후보

2026-11-13 KST. **후보와 검사 전용 `nft -c` 확인까지이며 A 방화벽에는 미적용**이다. 방화벽은 보호 변경이라 사용자 승인 후 관리자231 경유로 `apply_a.py`를 1회 실행한다. [현황](../../../STATUS.md) · [작은 원장](validation.json) · [A 방화벽 v2](../../groot-a/fw-v2/README.md) · [history-auto 영향](../../normalization/vector/history-auto/README.md).

## 사실(라이브 A 읽기전용, 15:35~15:38)

| 항목 | 값 |
|---|---|
| 현재 부팅 SPOOF 커널 로그 | 9,278건(약 26시간, 약 8,600건/일). **전부** `ens192` SRC `0.0.0.0`:68 → DST `255.255.255.255`:67 UDP, 즉 **DHCP DISCOVER 브로드캐스트**이고 출발 MAC은 1개(기기 1대) |
| 이전 부팅(10/24~11/11) 표본 6만 건 | 59,999건이 같은 DHCP 브로드캐스트, 1건은 0.0.0.0→224.0.0.1 IGMP |
| 원인 | A 안티스푸핑(P5) 목록 `spoof_src_ext`에 `0.0.0.0/8`이 있다. RFC 2131 DHCP 클라이언트는 주소를 받기 전 정상적으로 출발지 0.0.0.0을 쓴다. 출발지별 미터(6/분)가 단일 출발지 0.0.0.0을 계속 허용해 하루 약 8,600건이 "SPOOF"로 남았다 |
| 영향 | 커널 journal 소음, history-auto 보존소의 약 80%가 이 기록(폴더 상한 도달의 원인). Wazuh는 SPOOF 전용 규칙이 없어 기본 4100(level 0)만 매칭되므로 경보 영향은 없다 |
| 라이브 파일 | `/etc/nftables.d/capstone-fw.nft` = 리포 `infra/groot-a/fw-v2/capstone-fw.nft`(`f820c798…`) |

A는 ens192에서 DHCP 서버를 운영하지 않으므로 이 패킷은 지금처럼 drop하는 것이 맞다. 바꾸는 것은 **로그만**이다.

## 후보

`prerouting_block`의 ens192 SPOOF 로그 규칙 바로 앞에 한 줄을 추가한다([후보 파일](capstone-fw.candidate.nft), `da3dd852…`).

```
iifname "ens192" ip saddr 0.0.0.0 ip daddr 255.255.255.255 udp sport 68 udp dport 67 counter drop comment "DHCP client broadcast from 0.0.0.0 (RFC 2131); A serves no DHCP on ens192 - never logged"
```

- 출발지는 정확히 0.0.0.0이다(`/8` 아님). 목적지는 제한 브로드캐스트, 포트는 클라이언트 68→서버 67, 외부 NIC만 대상이다. 그 밖의 위장 출발지(내부망·루프백·자기 주소·멀티캐스트·0.0.0.0의 다른 목적지/포트)와 ens160 비내부 출발지는 **계속 SPOOF로 기록·drop**한다. 기존 ens160 169.254 link-local "never logged" 규칙과 같은 방식이다.
- 카운터를 남겨 drop 수는 계속 볼 수 있다.
- 드물게 보인 0.0.0.0 IGMP 질의(이전 부팅 6만 건 중 1건)는 범위를 좁게 유지하려고 포함하지 않았다.

## 검증

| 항목 | 결과 |
|---|---|
| 테스트(`deployment/tests/test_groot_a_spoof_dhcp.py`) | 5/5: 규칙 1개가 SPOOF 로그 바로 앞, drop·로그·accept 없음, 정확한 패턴만 매칭, 나머지 파일은 동일, 남은 SPOOF 로그 2개 유지, 적용 스크립트의 SHA·규칙 일치, 라이브는 테이블 재적재 없이 규칙 1개 삽입 |
| A `nft -c`(검사 전용) | 후보 전체 파일을 부팅·재적용 때와 같은 트랜잭션(테이블 삭제+include)으로 검사해 rc 0. 단일 규칙 삽입(handle 14 앞)도 rc 0. 라이브 규칙 수 13개 그대로 |
| 기존 방화벽 관리 ACL 테스트 | 통과 |

## 적용 방법(승인 후)

`apply_a.py <후보 경로>`를 root로 1회 실행한다.

1. 사전조건: 라이브 파일 SHA가 `f820c798…`이고, SPOOF 로그 규칙이 유일하며, DHCP 규칙이 아직 없고, 후보 파일 `nft -c`가 통과해야 한다. 하나라도 어긋나면 무변경으로 거부한다.
2. 라이브: SPOOF 로그 규칙(handle) 앞에 규칙 1개를 `nft insert`한다. **테이블을 다시 읽지 않으므로 임시 차단(agent_block) 원소는 그대로다.**
3. 영구: 원본을 백업(`/var/backups/capstone-fw-dhcp-noise-<시각>`)하고 후보 파일로 교체한 뒤 `nft -c`로 다시 확인한다. 실패하면 삽입한 규칙을 지우고 파일을 되돌린다.
4. 확인: 새 규칙 카운터가 늘고 이후 SPOOF 로그가 사라지는지(journal), 나머지 규칙이 그대로인지 본다. 리포 `infra/groot-a/fw-v2/capstone-fw.nft`도 적용본으로 동기화한다.
