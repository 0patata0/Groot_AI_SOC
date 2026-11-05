# 방화벽 정리·IPv4 전용 운용

2026-11-05 19:20 KST 운영 확인. [현재 현황](../../STATUS.md) · [검증 원장](fw-consolidation-validation-20261105.json) · [변경 전 검토](fw-consolidation-review-20261103.md).

| 호스트 | 테이블 전→후 | 체인 전→후 | IPv6 주소·경로·수신·전용 테이블 |
|---|---:|---:|---|
| A | 8→4 | 30→17 | 모두0 |
| B | 6→4 | 24→14 | 모두0 |
| C | 8→6 | 28→18 | 모두0 |

A의 프로젝트 NAT3규칙을 기존 `ip nat` PREROUTING/POSTROUTING에 iptables-native 방식으로 이관하고 `ip capstone_gw`·`ip capstone_fwd`를 제거했다. NAT의 출발지/포트/주소 조건은 유지했다. A는 `ip nat`, `ip filter`, `ip raw`, `inet capstone_fw`를 사용한다. `inet`는 IPv4도 처리하는 계열이며 IPv6 전용 테이블이 아니다. `capstone_fw`의 입력·출력·초기 차단과 예외/차단 집합, Docker의 자동 전달 체인은 유지한다. 사용자 추가 지시에 따라 `capstone_fw`를 다른 테이블로 통합하는 변경은 중단했다.

Docker 자동 테이블에 호스트 FW를 직접 합치는 격리 시험에서는 `iptables -S`가 incompatible 오류를 내고 `iptables-save`도 규칙을 내보내지 못했다. 운영 병합/이름 변경은0이다. 단순 set 한 개를 넣는 시험과 전체 호스트 정책을 넣는 시험은 결과가 달랐다. 초회 fixture의 INPUT 체인 누락 및 IPv4 계열에서 nfproto 사용 오류는 실패 이력으로 보존했고, 수정한 격리 시험에서 호환 문제를 확인했다.

## 실제 적용과 검증

| 항목 | 확인 |
|---|---|
| NAT 격리 | 기존→통합→원복→부팅 시 NAT 없음의4단계×3통신 조건 통과. 원래 호스트 방화벽/집합 handle 유지·시험 TTL57→55→52→50초, namespace/veth 정리 |
| A 운영 NAT | 18:53 적용·18:57 확정. 관리자231의10443→B443 HTTP200, Kali232의10443 연결 실패 |
| IPv6 영구 설정 | all/default/현재 인터페이스 disable_ipv6=1, Docker ipv6/ip6tables/userland-proxy=false·live-restore=true, SSH IPv4, A chrony -4, C Apache IPv4 |
| 컨테이너 | C→B→A 순서 적용. Docker daemon만 재시작하고 모든 기존 컨테이너 ID/PID/StartedAt·중지 상태 동일 |
| 실제 웹 | 19:11 Kali232: DVWA 로그인200, Log4Shell HTTP308/HTTPS200, 비파괴 SQLi1건 WAF403.233 새 송신0 |
| MCP | 실제 Hermes 컨테이너→resp-a 강제 MCP: 전체4테이블·17체인·102규칙·9집합, complete=true |
| 관리/예외 | 새 SSH 세션 A/B/C 재접속, A 호스트 정책 구조 동일·agent_block handle7/never_block4/mgmt_src5·관리자231/32 원소 동일 |
| 상태 | A/B/C failed unit0, IPv6 수신0. 재적용은 already_applied이며 컨테이너 재생성0 |
| 소스 검사 | IPv4 복구/드리프트/실패 경계9검사, 오프라인 준비18검사 및 Bash 구문 검사 통과 |

A의 규칙 수는103→102이다. Docker의 userland proxy 비활성화로 필요한 IPv4 NAT 규칙이 늘어 총 규칙 수가 테이블/체인 수만큼 감소하지 않는다. 테이블 수 감소를 보안·지연 향상 근거로 삼지 않는다. 운영 당시 agent_block은 비어 있었으므로 실제 활성 차단의 TTL 이동 시험을 했다고 표시하지 않는다. 격리 TTL 보존과 WAF403은 전체 LLM 판단·FW차단·카드·만료 E2E를 대체하지 않는다.

## 설치·유지보수·복구

진입점은 루트 `deploy.sh`다. 기존 A의 NAT 유지보수는 `--firewall-nat`→[basic_nat.py](../../deployment/basic_nat.py), 호스트 IPv4 전용 유지보수는 `--ipv4-only`→[ipv4_only.py](../../deployment/ipv4_only.py)를 사용한다. 두 경로는 관리자 root 유지보수용이며 LLM 일반 sudo 권한을 추가하지 않는다.

기존 운영 호스트를 초기 설치기로 덮지 않았다. 새 설치는 오프라인 prerequisites가 Docker 준비 후 역할 적용 전에 IPv4 전용 설정을 수행하고 검증/확정한다. canonical v2 로더는 NAT helper를 부팅에 호출한다. 기존 동작에 필요한 Docker PREROUTING/DOCKER-USER는 삭제하지 않는다. 이미 실행 중인 컨테이너의 IPv6 network가 활성화돼 있으면 자동 이관을 거절한다.

복구 원본은 A `/var/lib/capstone-basic-nat/migration-1793872427652357256`, IPv4 설정은 각 호스트 `/var/lib/capstone-ipv4-only/run-*`에 보존했다.15분 독립 타이머를 두고 운영 확인 후 확정/타이머 해제·확정 후 recovery no-op을 확인했다. root 수동 복구는 각각 `rollback --manual`에 정확한 복구 디렉터리를 지정하며, 다른 운영자의 후속 파일 변경이 있으면 덮어쓰지 않고 거절한다. 운영 수동 원복·실제 OS 재부팅·새3VM 전체 설치는 미시험이다. 확인된 구성으로부터의 재생성 방지와 실제 재부팅 검증을 구분한다.

새 deb/wheel/image 설치0, Mac 설치0이다. 사용한 Docker29.8.1/Compose5.5.1 및 기존 nft/iptables/OpenSSH/systemd/Python을 기준으로 검증했다. [Docker live restore](https://docs.docker.com/engine/daemon/live-restore/)는 bridge/graph-driver 등 옵션 변경 시 재연결을 보장하지 않으므로, 이번에는 그 옵션을 변경하지 않고 실제 컨테이너 상태를 대조했다.
