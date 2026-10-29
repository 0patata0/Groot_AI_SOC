# 전체 방화벽 읽기 MCP

`resp.get_firewall_rules`는 A 호스트 커널의 **전체 nftables 실행 규칙**을 읽는다. 기존 응답 MCP에 추가하므로 서버·포트·SSH 키·sudo 권한을 새로 만들지 않는다. Hermes와 Ollama는 동일한 도구와 공통 근거 검사를 사용한다. 현재 배포·실측 범위는 [STATUS](../../STATUS.md)를 따른다.

## 사용

- `fw 룰 보여줘`, `방화벽 보여줘`, `FW 기본 정책과 체인 보여줘`: 전체를 조회한 뒤 모든 체인의 기본 정책·hook·우선순위·규칙 수를 요약한다.
- `FW 전체 규칙 상세`: 개별 규칙의 handle·조건·동작을 채팅 표시 페이지별로 보여준다(최대16규칙/조건6,000자). `FW 전체 규칙 상세 2페이지`처럼 이어 볼 수 있다. 표시 페이지와 MCP 캡처 페이지는 별개다. 긴 단일 조건·집합 원문은 표시 생략을 명시하며 MCP 원문은 모든 조건·counter·원소를 보존한다.
- FW는 WAF·IDS와 별개다. `list_blocks`는 봇의 임시 차단 집합만 읽으며 전체 정책·NAT의 대체가 아니다. nft handle도 WAF rule ID나 Suricata SID가 아니다.
- 사용자 질문을 받으면 모델이 실제 읽기 도구와 인자를 선택한다. 공통 하네스는 범위를 좁히고 실제 응답을 검증·표시하며 도구를 미리 실행하거나 변경을 승인하지 않는다.

MCP `tools/call` 예:

```json
{"name":"get_firewall_rules","arguments":{}}
```

응답 텍스트는 JSON이다. `observed_at_kst`, `target=a:firewall`, 원시 조회 SHA-256, 종류별 `counts`, `objects`, `snapshot`, `offset`, `next_offset`, `total_objects`, `complete`를 반환한다. `objects`에는 native nft JSON의 table/chain/rule/set/map/element 등을 빠짐없이 보존한다. 규칙 0개·조회 실패·표시 요약을 구분한다.

## 범위·페이지

- 고정 명령은 `/usr/sbin/nft -j -a -n list ruleset` 하나다. 모든 family/table, 기본 정책과 일반 체인, 허용/차단/NAT/Docker 규칙, 집합을 포함한다. DNS 역조회를 하지 않는다. [공식 nft 매뉴얼](https://www.netfilter.org/projects/nftables/manpage.html).
- A 호스트 네트워크 네임스페이스만 대상이다. B/C와 다른 컨테이너 네임스페이스, legacy iptables는 포함하지 않는다. `/proc/net/ip{,6}_tables_names`에서 legacy 테이블이 발견되면 별도 경고하며 legacy가 조회됐다고 표시하지 않는다.
- `limit` 기본/최대200개, 페이지 객체 JSON 예산48,000바이트, 전체 캡처2MiB, nft 실행10초 제한이다. 명령·경로·필터 등 임의 인자는 거절한다.
- `next_offset`이 있으면 같은 `snapshot`과 해당 `offset`으로 계속 읽는다. 5분 동안 root 전용 `/run/capstone-fw-read`에 보관하므로 SSH/MCP 연결이 바뀌어도 같은 시점을 읽는다. 최대8개 스냅샷을 보관하며 다음 조회에서 만료/초과 파일을 정리한다. 재부팅 시 사라진다.
- 만료·너무 큰 단일 객체·타임아웃·권한·잘못된 JSON은 `isError=true`다. 일부 페이지만 읽었거나 종류별 총계가 맞지 않으면 봇은 전체 조회 완료로 표시하지 않는다. 정적 규칙 존재가 연결 성공·공격 탐지·차단 효과 검증을 뜻하지 않는다.

## 배포·복구

초기 설치 진입점은 루트 `deploy.sh`다. `deployment/soc_management.py`가 canonical `response-mcp.py`를 기존 root 진입점에 설치하고 4도구 계약을 검사한다. SIEM 설치 경로는 공통 정책/grounding/하네스를 복사한다. 기존의 nftables/Python/OpenSSH만 사용하며 신규 deb·wheel·이미지·설정 키는 없다. 과거 `deploy_response_A.sh`의 비특권 legacy 배치는 전체 FW 조회의 지원 경로가 아니므로 NFT 일반 sudo 권한을 덧붙이지 않는다.

운영 서버는 초기 설치기로 덮어쓰지 않는다. A의 MCP 소스와 B의 두 봇 공통 파일·설치 영수증·관리 gate를 백업하고 증분 반영한다. 이번 복구점은 A/B 각각 `/var/backups/capstone-fw-read-20261029`다. 복구 시 두 호스트의 대응 소스·영수증을 함께 되돌리고 봇/공동 채널 서비스를 재시작한다. 기존 파일 소유권·권한을 유지한다. 공동채널 실행기는 root controller의 `-c` 내장 관리 gate를 실행하므로, 별도 `management-code/run.py`만 바꿔서는 반영되지 않는다. 증분 반영에서도 controller의 내장 코드를 canonical `soc_management_run.py`와 동기화하고 실제 `command_for` 결과의 읽기 허용 목록을 검증한다. 이번 내장 코드 복구점은 `controller-inline/`이다. FW 정책 파일이나 커널 규칙은 복구 대상이 아니다.

`readOnlyHint`는 클라이언트 힌트다. 실제 경계는 root 소유 forced entrypoint, 고정 argv, 엄격한 인자 검사, 비공개 스냅샷 경로이며 범용 shell·Docker·nft 쓰기 권한을 봇에 주지 않는다. 기존 block/unblock 승인·보호 주소·TTL 검사는 그대로 적용된다. [MCP 공식 annotation 설명](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/).
