# 방화벽 통합 관리 검토 — 2026-11-03

사용자 요청은 INPUT·OUTPUT·FORWARD·NAT·MANGLE을 한곳에서 관리하고 미사용 테이블과 중복 처리를 정리하는 것이다. 아래는 A의 실제 스냅샷을 분석한 **변경 전 검토**다. 커널 규칙·MCP·봇 출력·부팅 경로는 아직 바꾸지 않았다. [현재 상태](../../STATUS.md) · [작은 검증 원장](fw-consolidation-review-20261103.json).

## 실제 구조와 사용 증거

12:09 KST에 8테이블·99규칙·9집합을 읽었고, **13:05:48 KST A SSH 인증·sudo 읽기 재조회에서도 같은 구성**을 확인했다. 카운터·handle·만료 시간 제외 구조가 일치하며 정책은 변경하지 않았다. 5테이블은 Docker/iptables 호환 계층, 2테이블은 프로젝트 NAT, 1테이블은 프로젝트 호스트 방화벽이다. Docker 테이블 안의 `CAPSTONE-*` 사용자 체인은 프로젝트가 관리하므로 테이블 소유자와 규칙 소유자도 구분한다.

| 테이블 | 규칙 수 | 주요 체인 | 용도·정리 판단 |
|---|---:|---|---|
| `ip nat` | 8 | PREROUTING·OUTPUT·POSTROUTING·DOCKER | Docker 포트 DNAT·송신 NAT. 실제 사용 확인, 유지 |
| `ip filter` | 42 | FORWARD·DOCKER-*·CAPSTONE-FWD·CAPSTONE-PUSH | Docker/프로젝트 전달 정책. 소유 체인 구분해 정리 |
| `ip6 nat` | 2 | PREROUTING·OUTPUT·DOCKER | Docker IPv6 NAT. 미사용/자동 재생성 여부 확인 후 정리 |
| `ip6 filter` | 5 | FORWARD·DOCKER-* | Docker IPv6 전달 정책. 미사용/자동 재생성 여부 확인 후 정리 |
| `ip raw` | 3 | PREROUTING | Docker 초기 필터. 실제 참조·동작 보존 필요 |
| `ip capstone_gw` | 1 | postrouting | 내부망 외부 통신 masquerade. 프로젝트 NAT 통합 후보 |
| `ip capstone_fwd` | 2 | prerouting·postrouting | 관리10443 DNAT와 응답 NAT. 통합/해당 경로 폐지 검토 |
| `inet capstone_fw` | 36 | prerouting_block·input·output | 호스트 방화벽·초기 차단·9집합. 프로젝트 정책 통합 대상 |

총8테이블·30체인·99규칙·9집합이며 A 호스트 네트워크 네임스페이스 범위다. PREROUTING은 독립 테이블 이름이 아니라 위 여러 테이블에서 사용하는 체인/hook이다. 재조회는 A에 한정하며 B/Thor 접속·시험 프로세스/결과 복구를 확인한 것은 아니다.

| 기능 | 규칙 수 | 설명 |
|---|---:|---|
| INPUT | 14 | A 호스트 수신 |
| OUTPUT | 14 | A 호스트 송신 |
| FORWARD | 47 | Docker 및 프로젝트 전달 정책 |
| NAT | 13 | Docker NAT와 프로젝트 NAT3규칙 |
| 초기 PREROUTING | 11 | Docker raw 및 프로젝트 선차단 |
| MANGLE | 0 | 이번 스냅샷에서 마킹/헤더 수정 규칙은 확인되지 않음 |

분류기는 모든 규칙을 한 번씩 계산하고 실제 hook 경로·원래 table/chain/handle·소유 추정을 함께 남긴다. 여러 hook에서 호출되는 체인도 중복 집계하지 않는다. 빈 체인·0카운터·미연결 객체를 자동으로 미사용으로 판정하지 않는다.

12:09~12:14 사이 Docker443 DNAT 카운터는16, NAT PREROUTING은43, 컨테이너 SNAT는79 증가했다. 따라서 NAT는 실제 사용 중이다. 독립 프로젝트 NAT 규칙은 카운터가 없고 기존 conntrack CLI/proc도 없어, 10443 관리 경로의 최근 사용까지 확인했다고 표시하지 않는다. NAT 카운터는 전체 애플리케이션 성공이나 세션별 패킷 수를 의미하지 않는다.

## 통합 후보와 경계

프로젝트 `ip capstone_gw`·`ip capstone_fwd`의 NAT3규칙을 기존 `inet capstone_fw`의 `nat_prerouting`·`nat_postrouting` 두 체인으로 이관하는 후보를 생성했다. 기존 IPv4 동작을 보존하도록 `nfproto ipv4`를 명시하고 DNAT의 주소 계열도 지정한다. 기존 호스트 filter/차단 체인이나 `agent_block` 집합을 다시 만들지 않는다. Docker 소유 테이블은 삭제하지 않는다.

INPUT/OUTPUT/FORWARD는 처리 경로이며 NAT는 체인 유형, MANGLE은 마킹·헤더 수정 등의 처리 목적이다. nftables에서는 필요한 hook/type/priority를 명시해 구성할 수 있다. 단순한 표시 정리를 위해 빈 MANGLE 체인을 만들 필요는 없다. [공식 hook 설명](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks) · [체인·우선순위](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains) · [inet NAT](https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_%28NAT%29).

현재 스냅샷에는 iptables 호환 `xt` 표현이 있다. Docker 생성 규칙을 임의 이관하거나 방화벽 백엔드를 전환하는 계획은 아니다. Docker 네트워크와 프로젝트 정책을 하나의 관리 관점에서 조회하되, 각 규칙의 소유 주체를 유지한다. [Docker iptables 통합](https://docs.docker.com/engine/network/firewall-iptables/) · [Docker nftables 소유 경계](https://docs.docker.com/engine/network/firewall-nftables/).

## 생성·검사

`fw_policy_layout.py`는 표준 라이브러리만 쓰는 오프라인 도구다. 네트워크 접속·shell·커널 쓰기를 수행하지 않으며 설치기나 운영 MCP에 아직 연결하지 않았다.

```sh
python3 -B infra/mcp/fw_policy_layout.py snapshot.json
python3 -B infra/mcp/fw_policy_layout.py snapshot.json --merge-candidate
python3 -B -m unittest discover -s infra/mcp -p test_fw_policy_layout.py
```

`snapshot.json`은 `nft -j -a -n list ruleset`의 JSON이다. 원문은 로컬 검증 기록에 보존한다. 잘못된 hook·규칙 추가·집합 추가·중복 체인·기존 대상 체인이 있으면 NAT 후보 생성을 거절한다. 검사는6PASS이며 실제99규칙의 분류 합계도 일치했다. 13:11 실제 A에서 생성한 트랜잭션의 `nft --check --json -f -` 검사도0으로 통과했다. 이 단계는 커널 정책을 적용하지 않는다.

13:14 기존 도구만 사용해 A에 격리 네트워크 네임스페이스3개를 만들고 [검증 실행기](validate_nat_isolated.py)로 기존3 NAT규칙 → 통합안 → 기존구성 원복을 실제 적용했다. 각 단계에서10443 DNAT/응답 masquerade, 내부망 송신 masquerade, 허용범위 밖 출발지의10443 미전달을 확인해3단계×3조건을 통과했다. 시험 프로세스/네임스페이스/임시 veth를 제거하고 호스트 정책 구조 불변도 확인했다. **Docker/호스트 filter/차단 집합·TTL을 포함한 운영 전체 통신·원복 검증은 아니다.**

## 적용 전 남은 작업

1. A는13:05 읽기 재접속에 성공했다. B/Thor의 기존 시험 프로세스·결과부터 재확인하고 새 관리자 IP·왕복/복구 경로를 확인한다. 사용자는211.170.162.85의 관리자/경유지 지정을 취소했고 새 IP를 전달할 예정이다. 기존 캠퍼스 허용 정책은 아직 변경하지 않았다.
2. A/B/C의 관리 listener·프록시 실제 사용자 IP·MCP 전용 키/고정 명령·필수 수집 경로를 대조한다. DVWA·Log4Shell 공개 웹과 관리 접속을 구분한다.
3. NAT 문법 검사와 격리3단계×3조건의 동등동작/원복은 통과했다. 실제 Docker/호스트 filter/차단 집합·TTL과 함께 동작하는 순서/통신·운영 원복은 별도로 검증한다.
4. 기존 `capstone-nat.sh`의 지속 설정·부팅 unit·legacy 참조를 함께 정리하고 루트 `deploy.sh` 설치 경로를 동기화한다. 새 서버 설치와 기존 운영 서버 증분 변경을 구분한다.
5. 정확한 이전 바이트·SHA/CAS·독립 복구 타이머와 임시차단 TTL 보존을 준비한다. 비교 중인 모델의 실제 조회 대상은 비교 완료 전에 바꾸지 않는다.
6. 적용 후 관리 SSH/대시보드·공개 웹·내부/외부 통신·MCP·차단/승인/만료·재생성 경로를 확인한 뒤 운영 반영을 확정한다.

## 추가 정리 범위: IPv6와 PREROUTING

사용자는 미사용 IPv6 테이블도 제거하도록 요청했다. 현재 A 스냅샷에는 Docker 소유 `ip6 nat`(2규칙)·`ip6 filter`(5규칙)가 있고, 확인된 IPv6 카운터는0이다. 이것만으로 미사용을 입증하지 않는다. 13:08 실조회에서 전역/ULA주소와default route가없고링크로컬/loopback만있으며,현재established0·Docker네트워크5개모두EnableIPv6false를확인했다. 그러나커널IPv6는활성이고sshd의[::]:22 및docker-proxy의[::]:80/443/8443 수신이있으며daemon관련명시설정은없다. 따라서대표관측구간의의존성을확인하고IPv4전용공개포트/SSH정책과Docker재생성경로를함께검토한다. 미사용이입증되면 해당테이블과생성원인을함께정리하고재시작/부팅재생성·관리/웹통신·복구를검증한다. 이번실제삭제는0이다.

PREROUTING은표시용테이블이아니라패킷처리hook이다. 현재Docker외부포트DNAT와프로젝트10443DNAT,DNAT이전임시선차단에사용한다. INPUT만으로이동하면전달패킷을놓칠수있다. 선차단은INPUT/FORWARD공통체인으로재설계할수있지만보호주소·기존연결차단·TTL·Docker순서를재검증해야한다. 10443이불필요하다고확인되면그DNAT경로를정리할수있으며,이것이DockerDNAT의PREROUTING제거를뜻하지않는다.
