# 전체 방화벽 읽기 MCP

**11/4 표시 페이지 보완:** 같은 사용자/스레드의 `다음 페이지`·`이전 페이지`·`2페이지`는 검증된 동일 조회 원문으로 재구성하고 새 조회가 아님을 표시한다. 새 대화는 대상 확인부터 수행한다. 전체 조회와 표시 페이지·Native 메시지 분할은 구분한다. [실채팅 검증/한계](../hermes/chat-table-chunks.md).

`resp.get_firewall_rules`는 A 호스트 커널의 **전체 nftables 실행 규칙**을 읽는다. 기존 응답 MCP에 추가하므로 서버·포트·SSH 키·sudo 권한을 새로 만들지 않는다. Hermes와 Ollama는 동일한 도구와 공통 근거 검사를 사용한다. 현재 배포·실측 범위는 [STATUS](../../STATUS.md)를 따른다.

## 사용

- `fw 룰 보여줘`, `방화벽 보여줘`, `FW 기본 정책과 체인 보여줘`: 전체를 조회한 뒤 모든 체인의 기본 정책·hook·우선순위·규칙 수를 요약한다.
- `FW input만 보여줘`, `FW output 룰`, `FW CAPSTONE-FWD 체인 룰`: 전체 MCP 페이지를 검증한 뒤 요청 hook/정확한 체인과 jump/goto·집합/맵을 통한 참조만 표시한다. 체인 이름의 대소문자를 유지하며 다른 체인으로 대체하지 않는다. INPUT 선택은 PREROUTING 등을 포함한 전체 접근 허용 판정이 아니다. [11/4 적용·검증](../hermes/firewall-scope.md).
- 같은 사용자·스레드의 `각각 표로 보여줘`, `룰 조회해줘`, `2페이지`는 이전 FW 선택 범위를 이어받는다. `output만`은 새 선택으로 바꾸며 `FW 전체 룰`은 전체 범위로 되돌린다. 새 대화나 다른 주제·쓰기/승인 이력에서 대상을 추정하지 않는다.
- 실채팅의 연속 재정리→짧은 범위 변경은1.5.18에서 보완했다. 대상 없는 별도 root의 `output만`은 한 번 확인한다. 실제10조건과 Hermes 긴 표 분할 미완료는 [최신 검증](../hermes/firewall-chat.md)을 따른다.
- `FW 룰 50개씩 끝까지 조회해줘`: 모델이 선택하는 첫·후속 MCP 호출에 같은 `limit=50`을 요구한다. 모호하지 않은 `N개씩`의1~200 범위만 적용하며, 바이트 상한 때문에 한 페이지가N개보다 적을 수 있다. `50개만`이라는 전체 개수 제한과 구분한다.
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

## 2026-10-30 페이지 크기 보완과 운영 확인

두 봇의 실제 채팅12건(수정 전8·후4)을 검사했다. 전체145객체·98규칙/14기본정책과 실제 게시 본문을 대조했으며, FW와 WAF/IDS를 혼동하지 않았다. 기존의 연속 페이지/합계 검사는 앞 페이지 누락을 이미 거부했다. 보완한 것은 Ollama가 명시한 `50개씩`을 후속 호출에서200으로 바꾸던 문제다. 같은 공통 하네스가 매 선택에서 `limit`의 enum/필수 여부를 유지하며 도구 호출을 미리 실행하지 않는다. 수정 후 양쪽 모두50/50/45 및73/72객체로 끝까지 조회했다. 전체 보안관제·승인/쓰기 검증 결과로 확대하지 않는다.

이번 B 증분 복구점은 `/var/backups/capstone-fw-pages-20261030-204505`다. root 전용 `manifest.json`은 Ollama `harness.py`, Hermes `chat_harness.py`, 운영 복구용 source의 `harness.py`·회귀 파일, Ollama 설치 영수증의 이전 파일·해시·소유권·모드와 적용 전 부재를 기록한다. 두 봇에 진행 중인 요청이 없는지 확인하고 중지한 뒤, manifest의 원래 파일·모드·소유권을 함께 복원한다. 적용 전 부재인 파일은 이번에 추가한 해당 파일만 제거한다. 이후 기존 봇을 시작해 영수증/소스 SHA와 인증된 웹소켓·실제 조회를 확인한다. 이번에는 백업 해시와 적용 후 상태를 검증했으며, 성공 배포 뒤 실제 롤백을 실행하지는 않았다.

설치 진입점 `deploy.sh`의 기존 SIEM/Ollama 소스 복사 경로가 이 canonical 하네스를 사용한다. 새 서비스·포트·키·이미지·패키지는 없으며 오프라인 반입 시 갱신된 프로젝트 소스를 사용한다. 운영 서버는 전체 초기 설치기로 덮어쓰지 않았다. 상세 시간·표본 한계와 남은 승인 상태 검증은 [STATUS](../../STATUS.md)를 따른다.

## 2026-11-03 통합 관리 검토

사용자는 INPUT/OUTPUT/FORWARD/NAT/MANGLE 기준의 통합 관리와 미사용 테이블 정리를 요청했다. A현재99규칙을 빠짐없이 분류하는 오프라인 분석기와 프로젝트NAT3규칙 이관 후보를 만들었다. 기존 get_firewall_rules 응답/권한/운영 커널·봇 표시는 아직 바꾸지 않았다. 단순 테이블 수 감소를 보안·성능 향상으로 표시하지 않는다. [검토·검사·미완료](fw-consolidation.md).

## 현재 테이블과 실제 읽기

11/5 NAT/IPv4 적용 후 실제 Hermes→resp-a는4테이블·17체인·102규칙·9집합을 complete=true로 읽었다. capstone_fw는 유지하며 IPv6 전용 테이블은0이다. 위11/3의99규칙/미적용은 당시 기록이다. [현재 구조·검증·복구](fw-consolidation.md).

기본 FW 질문도 IP 임시차단·남은시간·거부조건·예외 의미를 같은 완전 스냅샷에서 표시한다. xt 미해석·앞선 허용/체인·예외와실제패킷판정을구분한다. [반영·실측·한계](containment-display.md).


<a id="thesis-mcp-contract-20261117"></a>
## 2026-11-17 고정 소스의 로컬 stdio 입력형 관측

기준은 고정 커밋 `4fcbbf4bf2ca89f8bea0b1bd69b67545e2b6f9c3`의 `response-mcp.py`이며 작업본 바이트도 같았다. 기존 서버5·공통 하네스9검사는 실패/생략0이고 별도 fixture stdio에서17요청/알림1개를 대조했다.

기존 함수 단위 입력 검사와 실제 JSON-RPC 래퍼의 기본값 처리 사이에서 공백을 확인했다.5종의 비객체 falsey 입력은 handle에서 {}가 되어 새 fixture 조회로 이어졌다. 실제 nft·원격 연결·승인/차단은0이다. 재현기는 종료1과 공백 원장을 남기며 종료2의 소스 불일치/미완료와 구분한다. 이 결과를 운영 취약성이나 승인 우회의 입증으로 사용하지 않는다.

[고정 서버 구현](https://github.com/0patata0/Groot_AI_SOC/blob/4fcbbf4bf2ca89f8bea0b1bd69b67545e2b6f9c3/infra/mcp/response-mcp.py) · [기존 서버 검사](test_firewall_read.py) · [기존 공통 하네스 검사](../ollama-trial/test_firewall_harness.py). nft 바이트·캐시 위치·파일 UID를 시험용으로 대체했으므로 실제 커널·root 소유권·운영 서버 동작은 확인하지 않았다.

<!-- response-rpc-input-20261118 -->
<a id="response-rpc-input-20261118"></a>
## 응답 MCP tools/call 입력형 보완 후보 — 2026-11-18

응답 MCP의 tools/call에서 params·arguments의 자료형과 도구 이름을 도구 실행 전에 검사하도록 수정했다. 인자를 생략하면 빈 객체를 사용하고, null·배열·불리언·숫자·문자열을 객체로 바꾸지 않는다. 잘못된 입력은 -32602 오류로 반환한다. 네 도구의 목록·스키마와 승인·TTL·보호 주소·고정 helper는 유지한다.

로컬81개 검사와 Linux 격리24개 검사를 통과했다. 로컬 검사는 RPC7·FW조회5·공통하네스9·root진입점6·설치47·승인7개다. Linux에서는 nobody 계정으로 실제 stdio6·FW조회5·승인7·진입점6개를 실행했다. 원복은 원본 유지·정확 후보 복원·다른 세대 보존·확정 후보 보존·심볼릭 링크 거절의5조건을 별도 격리 환경에서 확인했다.

수정 전 소스는 같은 RPC 검사에서 실패했고 수정본은7개를 모두 통과했다. 기존 시험 초안의 child 인자 개수와 문자열 이름 분류 오류를 먼저 바로잡았다. Linux 첫 실행에서는 시험이 호스트의 /proc/net/ip_tables_names를 읽어 PermissionError가 발생했다. 해당 시험만 명시적 procfs 데이터로 대체해5개를 다시 통과했으며 운영 소스의 권한 검사를 완화하지 않았다.

관리자231 경유 조회에서 A의 /opt/capstone-soc/response-mcp.py는 기존1.2.0 소스와 같은 SHA임을 확인했다. 후보1.2.1의 SHA는 f911e8d9274686589c51145d52386c452ce0616085dd09b795c121d835758bc2다. 적용 대상은 이 파일 하나이며 정확 후보 승인을 기다린다. 변경 전 해시·root:root/0600·보호 파일을 대조하고 백업과5분 독립 원복 타이머를 준비한 뒤 교체한다. 운영 적용·기존 봇 연결의 재로드·새 실제 채팅 검증은 미수행이다.

초기 설치 진입점 deploy.sh는 기존 soc_management와 soc_runtime.render를 통해 같은 정본 소스를 설치한다. 실제 렌더 사본의 stdio 입력 검사도 통과했다. 갱신한 소스와 회귀 파일을 오프라인 소스 묶음에 포함하며 새 패키지·이미지·포트·키·설정 값은 없다. 운영 서버를 초기 설치기로 덮어쓰지 않는다. 새 OS 전체 설치 검증은 미수행이다.

논문의 고정4fcbbf4 재현 소스와 당시 입력형 실패 기록은 보존한다. 이번1.2.1은 후속 개발 후보이므로 고정 소스의 실패를 성공으로 바꾸지 않는다. 논문 본문·MD·DOCX·PDF와95쪽/본문1~89쪽·143색인은 그대로 유지하고 현재 작성 현황에 후보와 운영 미적용 범위를 별도로 기록한다.

응답 서버의 handle 밖 코드는 AST가 같고 네 도구의 실제 목록·스키마도 기존 설치본과 같다. 결함 우선 수동 검토와 실제 stdio·설치 렌더·승인 회귀를 수행했다. review-agent 스킬은 설치본을 찾지 못했고 Semgrep은 실행하지 않았다. 하네스·스킬·모델·MCP 스키마는 바꾸지 않았으며 이번 단위에서 공식 Harness²를 새로 실행한 것으로 표시하지 않는다. 실제 nft 커널·root 캐시 소유권과 봇 채팅의 검증은 이 격리 시험에 포함하지 않는다.

```bash
python3 -B infra/mcp/test_response_rpc.py
python3 -B infra/mcp/test_firewall_read.py
python3 -B infra/mcp/test_response_approval.py
python3 -B deployment/tests/test_response_entrypoint.py
python3 -B deployment/tests/test_soc_management.py
```

[검증 원장](response-rpc.validation.json) · [회귀 검사](test_response_rpc.py) · [MCP 2025-06-18 도구 오류 규격](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)
<!-- /response-rpc-input-20261118 -->
