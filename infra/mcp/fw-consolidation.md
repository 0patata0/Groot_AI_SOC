# 방화벽 통합 관리 검토 — 2026-11-03

사용자 요청은 INPUT·OUTPUT·FORWARD·NAT·MANGLE을 한곳에서 관리하고 미사용 테이블과 중복 처리를 정리하는 것이다. 아래는 A의 실제 스냅샷을 분석한 **변경 전 검토**다. 커널 규칙·MCP·봇 출력·부팅 경로는 아직 바꾸지 않았다. [현재 상태](../../STATUS.md) · [작은 검증 원장](fw-consolidation-review-20261103.json).

## 실제 구조와 사용 증거

12:09 KST에 8테이블·99규칙·9집합을 읽었다. 5테이블은 Docker/iptables 호환 계층, 2테이블은 프로젝트 NAT, 1테이블은 프로젝트 호스트 방화벽이다. Docker 테이블 안의 `CAPSTONE-*` 사용자 체인은 프로젝트가 관리하므로 테이블 소유자와 규칙 소유자도 구분한다.

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

`snapshot.json`은 `nft -j -a -n list ruleset`의 JSON이다. 원문은 로컬 검증 기록에 보존한다. 잘못된 hook·규칙 추가·집합 추가·중복 체인·기존 대상 체인이 있으면 NAT 후보 생성을 거절한다. 검사는6PASS이며 실제99규칙의 분류 합계도 일치했다. 이 검사가 nft 문법 검사나 실제 트래픽 검증을 대신하지 않는다.

## 적용 전 남은 작업

1. 관리망 연결을 복구하고 새 관리자 IP·왕복/복구 경로를 확인한다. 사용자는211.170.162.85의 관리자/경유지 지정을 취소했고 새 IP를 전달할 예정이다. 기존 캠퍼스 허용 정책은 아직 변경하지 않았다.
2. A/B/C의 관리 listener·프록시 실제 사용자 IP·MCP 전용 키/고정 명령·필수 수집 경로를 대조한다. DVWA·Log4Shell 공개 웹과 관리 접속을 구분한다.
3. 실제 커널/nft 버전과 Docker 호환 규칙의 전체 의미를 확인하고, 격리 네트워크 네임스페이스에서 NAT 우선순위/응답 경로를 검증한다. `nft --check`와 실제 통신 검증을 구분한다.
4. 기존 `capstone-nat.sh`의 지속 설정·부팅 unit·legacy 참조를 함께 정리하고 루트 `deploy.sh` 설치 경로를 동기화한다. 새 서버 설치와 기존 운영 서버 증분 변경을 구분한다.
5. 정확한 이전 바이트·SHA/CAS·독립 복구 타이머와 임시차단 TTL 보존을 준비한다. 비교 중인 모델의 실제 조회 대상은 비교 완료 전에 바꾸지 않는다.
6. 적용 후 관리 SSH/대시보드·공개 웹·내부/외부 통신·MCP·차단/승인/만료·재생성 경로를 확인한 뒤 운영 반영을 확정한다.
