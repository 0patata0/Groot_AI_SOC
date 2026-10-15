# 승인형 로컬 보안 룰 변경 MCP 배포 절차

## 2026-10-13 19:50~19:54 KST — 실제 부분편집 승인·적용 및 DGX 전환 완료

아래 19:40에 게시한 제안 `d466dc53aef84540443266a3a6db786b`는 **실제 Mattermost 카드 승인을 받은 뒤 19:50 KST worker가 적용**했다. Suricata 시작 시각은 **19:50:28 KST**, 실제 룰 로드 시각은 **19:50:41.988 KST**이며, **19:51 후속 조회에서 `applied`**를 확인했다. 19:54 재검증에서 `approval_consumed=true`·`result_posted=true`, 로드 성공 52,497건·failed/skipped 0을 확인했다. 19:50:28은 적용 완료 시각이 아니라 컨테이너 시작 시각이다. 기존 `.110` 예외를 유지하면서 마커 목적지를 정확한 `[211.170.162.110,211.170.162.111]`·rev 2로 확장했다. 적용된 로컬 룰 SHA-256은 `82f41d…`, ET+로컬 합본은 `8669…`이고 ET 원본은 불변이다. 실제 `propose_rule_edit`의 **전체 diff 게시→관리자 승인→worker 적용·런타임 검증→결과 게시** 경로를 이번에 확인했다. 아래의 승인 대기·만료 예정 시각은 게시 당시 기록이며 최종 상태는 `applied`다.

출발지 A·TCP 목적지 11434·서버 방향·연결 상태·무알림 마커·단일 flowbit 작성자 경계와 기존 6개 SID 예외 범위는 유지했다. A nft의 두 DGX `/32` 차단 방지는 19:30에 별도로 라이브·영구 반영했다. 이어 Hermes의 endpoint를 `.111`로 바꾸고 같은 컨테이너를 **19:51:42.745 KST**에 재시작했으며, **19:51:45 KST** resolver에서 `.111`·모델 `qwen3.6:35b`를 확인했다. MCP timeout 420초·대화 DB·`.env`·SOUL·cron은 그대로다. [B 설정 해시·백업](../groot-b/README.md) · [FW 보호 범위](../groot-a/fw-v2/README.md).

**후속 연결·도구 검증:** Mattermost WebSocket은 19:51:54 KST에 재연결됐고, 19:53 KST `.111` 모델 API의 HTTP 200·한국어 응답을 확인했다. 실제 Hermes UID 경유 rule-a/rule-b 각 8개 도구와 세 룰 대상 조회도 재확인했다. 전환 후 체감 응답 속도·실제 채팅 왕복과 실제 실패 복구 E2E까지 검증한 것으로 해석하지 않는다.

## 2026-10-13 19:40 KST — DGX 두 주소 지원·부분편집 승인 대기

A/B helper를 `d937c7…`로 갱신했다. ET 예외의 고정 마커는 기존 **`.110`·rev 1** 또는 정확한 **`[211.170.162.110,211.170.162.111]`·rev 2** 두 프로필만 허용한다. A 출발지·TCP 11434·방향·연결 상태·`noalert`·단일 flowbit 작성자와 기존 ET 원문 보존·관리자 승인 경계는 유지한다. 기존 `.110` 예외를 유지하면서 `.111`을 추가하기 위한 변경이다.

전체 ET+후보 구문 검사(`-T`)와 **27/27 사례 검증 두 회**를 통과한 뒤 실제 `propose_rule_edit`로 제안 **`d466dc53aef84540443266a3a6db786b`**를 생성했다. 전체 diff와 Mattermost 승인 카드 게시에 성공했으며, 이 기록 시점에는 **승인 대기**다. 만료 예정은 **19:50:28 KST**다. 유효한 부분편집 제안·검토 게시까지 확인했으며, 지정 승인→운영 적용 E2E 완료로 기록하지 않는다.

현재 라이브 Suricata 마커는 `.110`·rev 1이고 운영 모델 endpoint도 `.110`이다. `.111` 전환은 준비 단계이며, 승인 뒤 룰 적용·실제 런타임 확인과 연계해 진행한다. 별도로 nft `never_block`의 두 DGX `/32` 보호는 [19:30 반영 기록](../groot-a/fw-v2/README.md)을 따른다. 아래 19:14 및 이전 기록은 덮어쓰지 않고 당시 상태로 보존한다.

## 2026-10-13 후속 부분편집 버전 — 라이브 배포·계약 검증 완료

**19:10~19:14 KST A/B 배포 완료.** helper `4b015b96…`·frontend `2926ee95…`, 실제 Hermes UID에서 버전 0.3.0·각 8개 도구를 확인했다. 세 대상 조회·존재하지 않는 문맥의 편집 거절·전후 승인 수 0·룰/관련 파일 해시 불변을 검증했다. 현재 36세션 정책 캐시·SOUL·cron 갱신, 이력/다른 DB 보존·integrity·로더 무잘림·Mattermost 재연결을 확인했다. MCP 172개 + 정책 6개 테스트 통과. **실제 부분 편집 승인 카드 게시 → 지정 승인 → 운영 적용 E2E는 아직 수행하지 않았다.** 아래 14:25~14:29 기록은 이전 7개 도구 버전의 배포 사실이다. [해시·백업·실행 결과](../../대화기록/2026-10-13.md).

이번 갱신은 기존 설치 스크립트 전체를 재실행하지 않았다. 그 스크립트의 도구 3개·timeout 240 가정은 현재 운영과 다르므로 현행 시스템의 업데이트 명령으로 그대로 사용하지 않는다. 코드 2개만 root 전용 백업 → 유휴/잠금 → 원자 교체 → 불변성 검사로 반영했고, [정책 갱신기](../hermes/update_rule_edit_policy_B.py)는 Hermes 정지 상태에서 dry-run 후 실행했다. 정책 갱신기 자체는 컨테이너를 중지/시작하지 않는다. 재시작 후에는 새 대화 보존을 위해 과거 DB 전체 복원을 하지 않는다.

### 입력·후보 구성·승인 계약

`propose_rule_edit(target, base_sha256, edits, reason)`의 `edits`에는 `{old_text, new_text}` 객체를 1~16개 전달한다. 모든 old/new 텍스트의 UTF-8 합계는 64KiB 이하이며 `old_text`는 비어 있지 않아야 한다. 실행기는 고정 대상과 현재 원본 SHA-256을 확인한 다음, 잠금 안에서 원본 바이트를 기준으로 치환 위치를 결정한다. 각 `old_text`가 원문에 정확히 한 번 있어야 하고 편집 범위는 서로 겹칠 수 없다. 겹쳐 나타나는 동일 문자열도 중복으로 거절하며, 편집 순서에 따라 앞선 결과를 다시 치환하지 않는다. 공백·줄바꿈을 자동 보정하지 않는다.

삽입은 고유한 기존 문맥을 `old_text`로 잡고 `new_text`에 그 문맥과 추가할 내용을 넣는다. 삭제는 `new_text`를 빈 문자열로 둔다. 동일한 old/new, 원본과 동일한 최종 후보, 빈 후보, 최종 후보 128KiB 초과는 거절한다. 이 경로도 기존 WAF·Suricata·Wazuh 대상별 검증과 실행 모드 제한을 그대로 적용한다.

서버가 전체 후보를 구성한 뒤 기존 `/rule-changes` 프로토콜로 원본/후보 SHA·전체 diff SHA·제안 digest·만료를 결속한다. **전체 diff는 최대 512KiB이며, Mattermost에서 필요에 따라 검토 메시지로 분할한 뒤 최종 승인 한 번을 받는다.** 후보 내용을 모델이 적게 출력한다는 이유로 관리자에게 보여줄 변경 검토를 줄이지 않는다. 지정 승인·일회성 소비·적용 전 원본 재확인·고정 실행·검증·복구 경로는 유지한다.

새 도구는 전체 검토 게시가 확인된 뒤 제안 ID·`pending` 상태·원본/후보/제안/diff 해시·후보/diff 크기·편집 수·사전검증·런타임·만료·게시 위치를 반환한다. **후보 전문과 diff 전문은 새 도구 응답에 넣지 않는다.** 서버 상태에는 완전한 후보와 승인 payload를 보존하며 Mattermost에는 전체 diff가 게시된다. 기존 `propose_rule_change`의 전체 후보 입력·diff 포함 응답은 호환성을 위해 유지한다.

### 새 버전 배포 때 추가로 확인할 사항

1. 기존 절차대로 활성 승인·실행·결과 보고 작업과 현재 소스/룰 해시를 확인하고 백업한다. A/B의 `rule_change_mcp.py`와 `rule_change_executor.py`가 같은 부분편집 계약을 구현하는지 대조한다. 이 기능을 위해 패키지·컨테이너 구성을 새로 만들지 않는다.
2. 배포 뒤 구문·helper·HMAC·worker 검사와 함께 실제 Hermes 실행 사용자 경유 `tools/list`에서 `rule-a`·`rule-b` 각각 **8개 도구**, `propose_rule_edit`의 네 입력 필드와 host guard를 확인한다. `get_rule_change_target` 읽기 조회와 편집 한도 안내, 기존 전체 후보·서비스·응답 도구의 회귀를 점검한다. 이 단계는 읽기 계약 확인이며 실제 승인 게시·룰 적용의 증거가 아니다.
3. Hermes SOUL의 관리 정책을 부분편집 우선 지침으로 맞춘다. 기존 대화가 정책을 캐시했다면 대화 내용·도구 이력은 보존하면서 관리 정책과 해시만 동기화하고 검증한다. 정책·코드·도구 스키마가 서로 다른 상태로 변경 요청을 재개하지 않는다.
4. 배포 시각·소스 해시·백업 위치·실제 도구 수·읽기 결과·룰 해시/서비스 상태를 후속 기록으로 남긴다. 부분편집의 실제 Mattermost 전체 diff 게시→지정 승인→파일 적용·런타임 검증은 별도의 통제된 실제 변경에서 확인한다. 모의 모델 출력이나 로컬 후보 재구성을 이 E2E 성공으로 대체하지 않는다.

### 부분편집 버전의 사용 순서

사용자가 현재 대화에서 명시적으로 룰 수정을 요청하면 `get_rule_change_target`으로 원문과 기준 SHA를 읽는다. 작은 추가·수정·삭제에는 `propose_rule_edit`를 우선 사용하고, 승인 대기 상태와 검토 위치를 안내한 뒤 `get_rule_change_status`로 실제 적용 결과를 확인한다. 적용 성공 뒤에도 대상을 다시 조회해 후보 해시와 런타임을 대조한다.

기준 SHA 불일치·문맥 누락/중복·편집 겹침·한도 오류가 나면 최신 파일을 다시 읽고 필요한 부분만 고친다. **오류가 났다는 이유로 `propose_rule_change` 전체 재작성이나 임의 sudo/Docker 명령으로 자동 우회하지 않는다.** 전체 후보 API는 의도적으로 파일 대부분을 다시 작성해야 하는 변경에만 사용한다. 아래 기존 절차의 전체 파일 제출 설명은 그 호환 경로에 해당한다. 부분편집 API가 아직 배포되지 않은 호스트에서는 새 도구 사용 가능 여부를 먼저 확인하며, 미지원 사실을 작은 수정의 자동 전체 재작성 근거로 삼지 않는다.

같은 합성 파일을 사용한 모델 API 시험에서 부분편집은 2/2 정확한 후보 재구성을 확인했지만 실제 MCP를 호출하지 않았다. 출력 룰 텍스트 감소와 전체 응답 시간 개선은 같은 비율이 아니며 긴 추론도 남았다. [실측 조건·원본 응답·한계](../hermes/benchmarks/README.md#부분편집-비교)를 따른다.

## 2026-10-13 추가 버전 — 라이브 배포·읽기 계약 검증 완료

이번 추가 버전은 **전체 후보 128KiB / 전체 diff 512KiB / 분할 검토 후 최종 승인 1회**를 지원한다. 아래 13:43~13:45의 8KiB 거부·논리적 변경 분할 안내는 수정 전 운영 코드의 기록이다. 새 구현에서는 전체 후보 한 건을 제출하면 브로커가 표시만 분할한다. 각 부분에 요청 ID·번호/총수·원문 UTF-8 byte 범위·부분/전체 해시를 넣고, 원문과 들여쓰기 표시 각각 8KiB 이하·본문 12,000자/바이트 이하로 유지한다. 모든 검토 메시지와 마지막 승인 카드 게시 후에만 `posting`→`pending`으로 전환한다. 부분 게시 실패·기한 만료·게시 시간 초과는 승인 불가이며, 같은 제안 digest를 한 번만 소비한다.

`/rule-changes` HTTP 본문은 JSON escaping을 포함해 최대 4MiB다. 브로커 게시 제한은 90초이며 이미 시작한 웹훅의 최대 15초를 고려해 실행기의 생성 요청은 120초까지 기다린다. MCP helper 호출·Hermes 도구 제한도 배포 구성과 함께 확인한다. 이번 버전의 `rule-a`·`rule-b` 공통 도구 목록은 각 7개이며 [도구별 범위](README.md#2026-10-13-추가-구현--대형-변경고정-운영-작업응답-승인-보강)를 따른다. 고정 서비스 사전 승인과 증거 기반 임시 IP 차단은 룰 파일 승인과 분리된 `/operations` 프로토콜이다. 허용 서비스·보호 주소·10분 임시 기한·60분 유지·해제 요청 지연은 [승인형 운영 작업](approved-operations.md)을 따른다. 패키지 설치·컨테이너 생성/구성 변경은 대상이 아니다.

추가 버전의 배포 시 아래를 기존 절차에 함께 적용한다.

1. 소스·현재 해시·백업과 실행 중 작업을 확인한다. 기존 토큰 인증 `/pending`, HMAC 인증 `/rule-changes/health`·`/operations/health`에서 활성 legacy/rule/operation 작업 수를 확인한다. `pending`뿐 아니라 `approved`·`consumed`·`reporting`·결과 보고 재시도도 고려한다. 신규 `/operations/health`는 이전 코드에서 없을 수 있으므로 404를 정상 0건으로 해석하지 않는다.
2. B 브로커의 `soc_bot.py`와 **같은 디렉터리의 `operations_approval.py`를 함께** 배포한다. A/B helper는 `service_action_executor.py`·`incident_containment.py`와 고정 실행 정책을 포함한 배포 묶음을 검증한다. 기존 룰·컨테이너 구성·패키지는 이 코드 배포에서 변경하지 않는다. 기존 `response-mcp.py`도 차단·해제 승인 보강본으로 맞춘다.
3. 브로커는 승인 상태를 메모리에 보관하므로 재시작 전 활성 작업을 끝내거나 안전하게 중단한 상태인지 확인한다. 임시 차단의 원래 10분 기한은 nftables TTL로 독립 보장하지만, 브로커 재시작으로 아직 소비하지 않은 유지 승인이나 결과 카드가 사라질 수 있다. 진행 중 승인 소비 상태를 새로 만들거나 승인 클릭을 흉내 내어 복구하지 않는다.
4. 재배포 후 각 호스트에서 구문 검사·HMAC health·root helper 검사·읽기 조회·7개 도구 목록과 host guard·worker 상태를 확인한다. 기존 IP 대응은 지정 `APPROVERS`와 허용 Mattermost TCP peer가 필수이고 `/consume`은 요청 ID·action·IP·기간 일치 시 1회만 허용한다. `/nonce/<id>`는 제거됐으므로 HTTP nonce 조회로 승인 시험을 하지 않는다.
5. 실제 서버 파일 해시·서비스 상태·승인 대기·검증 결과와 백업/복구 위치를 후속 기록에 남긴다. 큰 diff의 실제 카드 게시·지정 운영자 승인·적용은 통제된 실제 변경 요청에서 확인한다. 로컬 모의 검증을 라이브 E2E 성공으로 기록하지 않는다.

### 이번 추가 버전의 라이브 확인(14:25~14:29 KST)

- **B 배포 14:25:56:** 브로커·운영 승인 모듈·B helper와 정책/캐시를 반영했다. 백업은 `/var/backups/approved-operations-B-20261013.i32lcaf9`다.
- **A 배포 14:26:15:** A helper·고정 운영 모듈·응답 MCP를 반영했다. 백업은 `/var/backups/approved-operations-A-20261013.9jfki4zt`다. 보호 대상 DGX 주소의 임시 차단 요청은 root 검증에서 거부됐으며 실제 차단은 발생하지 않았다.
- **14:29 최종 확인:** Hermes 실행·Mattermost 연결, 현재 34개 대화 캐시의 관리 정책/해시와 SQLite 무결성을 확인했다. 실제 Hermes UID 995에서 `rule-a`·`rule-b` 각각 7개 도구 목록, 고정 서비스 5개 상태 조회, 기존 `resp` 3개 도구와 차단 목록 조회가 성공했다.
- **변경 범위:** 룰·nft 상태와 대상 서비스 컨테이너 `StartedAt`은 배포 전후 동일했다. 배포 시 soc-bot을 재시작하고 Hermes를 정지/기동했으며 WAF·Suricata·chatproxy·Wazuh 서비스의 작업 버튼은 실행하지 않았다. 로컬 테스트 154개가 통과했다.
- **남은 검증:** 새 대형 카드의 실제 운영자 승인, 승인 후 서비스 작업·검증, 실제 공격 증거에 따른 임시 선차단·유지/해제는 라이브 E2E 미검증이다. 읽기 조회·보호 대상 거절 검증을 실제 승인 실행 성공으로 해석하지 않는다. [오늘 작업 증거](../../대화기록/2026-10-13.md).

다음 절의 10/08 및 10/13 13:18 기록은 각각 당시 버전의 배포 사실로 보존한다.

## 이전 라이브 배포·검증 기록

2026-10-08 A/B·Hermes에 설치한 기능의 **재배포·검증 절차**다. 기존 `mcp` 읽기 계정과 `resp` 차단 계정의 권한은 변경하지 않았다. 10/13 첫 적용의 Suricata hot reload 성공 오판은 운영자 재시작으로 반영을 완료하고 helper를 수정했다. **13:18 두 ET 예외는 수정 helper가 지정 승인→파일 교체→재시작→실제 로드 검사→결과 카드까지 자동 처리한 E2E를 확인했다.** 실제 실패 복구 E2E와 새 LLM 통신의 장기 오탐 관찰은 남는다.

### 2026-10-13 오탐 조치 준비(라이브 조회·후보 오프라인 검증)

- 10:23 KST Hermes 실제 UID 995에서 `rule-a`의 `a:suricata-local`, `rule-b`의 `b:wazuh-local-rules`를 `get_rule_change_target`으로 조회했다. 일반 sudo/docker 권한이 없다는 점은 이 고정 대상 변경 경로를 사용할 수 없다는 뜻이 아니다. 10:16 KST A 승인 상태는 0건이고 worker가 정상 동작했다.
- 원천 EVE의 SID `1000032/33/70/71` 67건은 A `192.168.16.230 → 211.170.162.110:11434`의 19개 흐름에 있었고, 같은 흐름 HTTP 기록 24개를 찾았으며, 조회한 최근 5개 표본에서 `POST /v1/chat/completions`·200을 확인했다. 현재 Suricata·Wazuh·A agent 큐/드롭 지표는 0이었다. 사용자 보고의 과거 포화 원인은 미확정이다.
- [로컬 후보](../../new_rule/GROOT_A_local.rules)는 무알림 flowbit SID `1000000`과 해당 4종의 rev 2 예외다. 다른 클라이언트·포트·`.111`·DGX 시작 연결, ET·URI/헤더·스캐너 룰은 예외가 아니다. 실제 Suricata 8.0.6의 원본/후보 오프라인 PCAP 검증(12개 사례, 142패킷)이 통과했다. 이는 운영 룰 적용·reload 검증을 대신하지 않는다.
- **승인 카드 게시 완료·라이브 미적용:** 현재 라이브 SHA-256 `4422a0c110baa6d57c542313b517b8f5aba86123bdec02c502e69ee68514d09f`, 후보 SHA-256 `98146db160e1c2544f7d98a2d26d699cc5c869a087102f3380bb3bfb863a2c6b`. 10:27경 rule-a의 전체 ET+후보 `Suricata -T` 통과 후 `propose_rule_change`로 전체 diff와 해시를 게시했다. 제안 `b17074c82fe506065789849596292050`은 당시 pending, 만료 10:37:21 KST다. 지정 승인 뒤에만 worker가 적용하며, 승인 후에는 상태·파일 재조회뿐 아니라 실제 Suricata reload 완료와 신규 경보·큐 지표를 확인한다.
- **SOUL 정책 배포(10:26 KST):** 권한 단정 전 MCP 조회, 이벤트/설명 및 큐 용량/사용량 구별, 승인 우회 금지와 미지원 작업 보고 지침을 관리 블록에 추가했다. 실행 agent 0을 새로 확인한 뒤 다른 페르소나를 보존해 라이브 반영·Hermes 재시작·5개 MCP enabled를 확인했다. 백업 `/var/backups/hermes-policy-20261013.h9viljuc/SOUL.md`, 라이브 전체 SOUL SHA-256 `f7dab7648d9774e11fa5c5268231ad79737ebd661c16c560302f10411fb67e2e`. 일반 sudo·Docker 소켓·임의 SSH 권한 추가, 큐 삭제는 하지 않았다.

**10:29:11 KST 재확인:** `get_rule_change_status`의 제안 상태와 `approval_status`가 모두 `pending`이고 라이브 원본 해시 `4422a0c1…`도 유지됐다.

**당시 상태 — 10:51:34 KST:** A의 제안 `b17074c82fe506065789849596292050` JSON 상태 `expired`와 라이브 원본 SHA-256 `4422a0c110baa6d57c542313b517b8f5aba86123bdec02c502e69ee68514d09f` 유지를 확인했다. 당시 후보는 승인 만료·미적용이며 새 제안은 게시하지 않았다. 만료한 카드를 재사용하지 않고 아래 새 제안으로 재개했다.

### 2026-10-13 새 지정 승인·파일 교체와 런타임 반영(12:25~12:32)

- **새 제안:** 12:25:04 KST `7676bcb16b819d23f949f126a9e16c7d`를 게시했다. 지정 승인 후 worker가 파일을 교체했고 12:27 조회에서 `applied`를 확인했다. 현재 로컬 SHA-256은 `98146db160e1c2544f7d98a2d26d699cc5c869a087102f3380bb3bfb863a2c6b`, 합본은 `2b3fcd03a259db8017c0006e2a8e1ff33581532a4c24edf57911805ad3ce17c0`이며 ET 원본(`f11a97da…`)은 불변이다.
- **초기 성공 판정의 한계·결함:** 12:29 런타임 통계는 기존 52,494룰과 10/10의 로드 시각이었다. `-S /rules/all.rules`로 기동한 Suricata 8.0.6은 live reload를 지원하지 않으며, 12:32:20.358 KST 재시작 전 `reload-rules`의 `NOK` 응답을 직접 확인했다. 기존 helper는 `suricatasc`의 종료 코드 0을 성공으로 간주했으므로 `applied`·파일 해시만으로 새 룰이 실행 중이라고 판정할 수 없었다.
- **운영자 후속 반영:** 승인 소비 상태 `true`, 원본 두 백업과 승인된 후보·ET·합본 해시를 다시 확인한 뒤 같은 ID의 기존 Suricata 컨테이너를 재시작했다. `StartedAt=12:32:22.439 KST`, `ruleset-reload-time=12:32:35.865415 KST`, `rules_loaded=52,495`, failed/skipped 0, running true·OOM false·passive 유지로 런타임 반영을 확인했다. 재시작 요청부터 검증까지 17.89초이며 실제 탐지 공백을 별도로 계측한 수치는 아니다.
- **복구 자료:** `/var/lib/rule-change/7676bcb16b819d23f949f126a9e16c7d.primary.bak`와 `.all.bak`는 root 소유·0600이다. 원본 로컬 SHA 접두어는 `4422a0c1…`, 원본 합본은 `84239…`다. 운영 룰은 승인된 정확한 후보와 일치한다.
- **12:32 당시 남은 검증:** helper의 reload 판정 결함 수정·배포는 당시 준비 중이었다. 이번 결과는 승인→파일 교체 후 운영자 재시작으로 런타임을 확인한 것이며, 수정 helper의 자동 적용·실패 복구 E2E를 검증한 결과는 아니다. 실제 오탐 재발 감소의 장기 관찰도 남아 있다.

승인 검토 시 NAT 범위를 함께 본다. 센서에서 A `.230`으로 변환된 모든 DGX `.110:11434` TCP 연결의 4개 SID가 제외되며 B/C·API 경로·실행 프로세스를 인증하지 않는다. “다른 클라이언트”는 센서에서 다른 출발지 IP로 보이는 경우다.

### 2026-10-13 A 실행기 수정 배포(12:43:13 KST)

- `/usr/local/sbin/rule-change-executor`를 SHA-256 `10cae22154e884ec0645d954fe67fae0d233d3c2f98268235963ac3e5ef23e85`, root:root·0750으로 배포했다. 적용 lock 안에서 제안들이 종료 상태임과 기존 실행기 SHA·승인 후 운영 룰 해시를 확인한 뒤 원자적으로 교체했다. 이전 실행기와 manifest는 `/var/backups/rule-change-runtime-20261013.j7mzevn2`에 보존했다(디렉터리 0700, 파일 0600).
- **새 적용 정책:** `-S` 기동 Suricata는 승인된 파일 교체·구문 검사 후 기존 컨테이너를 재시작한다. 컨테이너 ID·새 시작 시각·passive 모드와 런타임 룰 수(0 초과), failed/skipped 0, 새 룰 로드 시각의 일관성을 확인한다. `suricatasc` JSON의 `return: OK`와 응답 구조를 검사하며, `NOK`/비정상 응답을 종료 코드 0만으로 성공 처리하지 않는다. 원본 복구 때도 동일한 재시작·런타임 검증 경로를 사용한다. 승인 카드의 영향 설명에는 재시작과 잠깐의 탐지 중단을 명시한다.
- **배포 확인:** 실행기의 `--check`·`--broker-check`가 통과했고, 새 JSON 파서로 라이브 `rules_loaded=52,495`, failed/skipped 0과 12:32:35 로드 시각을 읽었다. 운영 룰 SHA·Suricata 컨테이너 ID/StartedAt은 배포 전후 불변이며 추가 재시작은 하지 않았다. worker는 라이브 `Type=oneshot`, `TimeoutStartUSec=infinity`를 확인했다. 실행기 23개+브로커 17개=40개 테스트와 독립 검토가 통과했다.
- **범위·남은 검증:** 이번 실행기 배포는 A만 수행했다. B Wazuh 실행기는 별도 재배포하지 않았다. 새 실행기를 통한 자동 룰 적용·실제 실패 복구 E2E는 아직 미검증이며, 실사용 표본 결과는 아래 후속 확인과 같다.

### 2026-10-13 재적재 후 실사용 표본·남은 ET 경보(12:44:26 KST)

- 재적재 이후 EVE 조회 구간을 확인했고 새 LLM 흐름 3개·HTTP 200 4건에서 대상 커스텀 SID `1000032/33/70/71` 경보는 0건이었다. 같은 A→DGX `.110:11434`에서 ET SID `2034806` 2건·`2034802` 2건은 남아 있어 전체 경보 0건 또는 전체 오탐 해소로 보고하지 않는다.
- 정적 ET 룰 직접 조회상 각각 Log4j RCE obfuscation outbound·lower TCP bypass outbound 탐지다. LLM 전달 본문 문자열에 반응했을 가능성은 있지만 본문 미열람으로 원인은 추정이다. ET는 승인된 4개 커스텀 SID 예외 범위 밖이므로 수정하지 않았다. 두 ET SID의 별도 원인 분석·좁은 후보 검증·승인과 장기 재발 관찰이 남는다.
- 12:43:44 A `kernel_drops=0`, `alert_queue_overflow=0`; 12:43:57 B 모든 큐 usage와 events_dropped 0, remoted queue size/discard 0을 확인했다. 배포 후 worker는 12:43:37 success/exit 0, timer active/enabled였고 B 주요 서비스는 기존 시작 시각을 유지하며 실행 중이었다. 현재 표본은 사용자 보고의 과거 큐 포화 원인을 확정하지 않는다.

### 2026-10-13 ET Log4j 재분석·후보 검증·지정 승인·자동 적용(13:00~13:24)

- **라이브 근거(13:00:47 KST):** 직전 24시간 EVE 두 파일을 조회해 ET `2034806/2034802` 각각 3건을 확인했다. 모두 A `192.168.16.230 → 211.170.162.110:11434`이고 같은 흐름에 `POST /v1/chat/completions`·HTTP 200·`text/event-stream` 기록이 있다. 경보에 본문·`tx_id`가 없어 정확한 JSON 매칭 문자열은 확정하지 않는다. WAF 미탐지만으로 암호화 여부를 판정하거나, NAT 주소를 원래 프로세스 또는 DGX의 스캔 주체로 해석하지 않는다.
- **후보 설계:** 현재 ET 두 규칙의 바이트를 로컬 파일에 복사하고 SID 앞 `flowbits:isnotset,groot_llm_api`와 rev 2→3만 바꾼다. ET 원본 파일은 유지하고 같은 SID의 높은 revision이 선택되는 Suricata 동작을 사용한다. `all.rules=ET+local` 계약, 기존 대상 `a:suricata-local`과 지정 승인 경계를 유지한다. 단순 IP `suppress`·전체 흐름 `pass`·`drop`은 사용하지 않는다. `-S`는 hot reload를 제한하지만 현재 helper의 합본 교체·재시작 경로를 막지 않는다.
- **예외 범위:** 기존 무알림 SID `1000000`이 표시하는 A NAT `.230`→DGX `.110:11434` 연결에만 두 ET 예외를 둔다. 동일 NAT 뒤 B/C·다른 프로세스·다른 API 경로도 포함될 수 있으므로 URI/프로세스별 인증 예외가 아니다. 다른 IP/포트·DGX 시작 연결과 로컬 URI/헤더·스캐너 탐지는 유지한다.
- **검증:** 실제 Suricata 8.0.6의 원본/후보 PCAP 17개 사례·197패킷과 전체 ET+후보 `-T`가 통과했다. A helper는 두 ET SID의 현재 원본·고정 guard·rev +1을 바이트 단위로 대조하며, 마커 헤더/옵션 불변·동일 flowbit의 단일 작성자·실제 옵션 단위 SID 검사를 강제한다. 들여쓰기로 엔진이 무시할 수 있는 마커도 거절한다. 제안 사전검사·승인 소비 전·파일 교체 직전에 재검증한다. 실행기 30개 테스트와 독립 검토가 통과했다.
- **helper 배포(13:16:15 KST):** A `/usr/local/sbin/rule-change-executor` SHA-256 `81597b1115f2e4708379ea1f21c7d965ed0d26453f95a509b6e94532e317841f`, root:root·0750. lock 안에서 실제 전체 ET 기반 후보 검사·현재 해시를 확인하고 원자 교체했다. 이전 실행기·manifest는 `/var/backups/rule-change-et-20261013.6flbbemz`에 백업했다. `--check`·브로커 HMAC 검사를 통과했고 룰 해시·Suricata 런타임은 그대로였다. B 실행기/브로커 재배포나 일반 sudo/Docker 권한 확대는 하지 않았다.
- **제안 게시(13:17:13 KST):** `90ff6d8cf37547f7451c81e0caf1cd73`, 당시 지정 승인 대기, 만료 예정 13:27:13 KST. staged 전체 ET+후보 `-T`와 5,172바이트 diff 게시를 확인했다. 로컬 기준 SHA는 `98146db160e1c2544f7d98a2d26d699cc5c869a087102f3380bb3bfb863a2c6b`, 합본 기준은 `2b3fcd03a259db8017c0006e2a8e1ff33581532a4c24edf57911805ad3ce17c0`다. 게시 시점에는 미적용이었으며 이후 만료 전에 승인이 접수됐다.

| 후보 구성 | SHA-256 |
|---|---|
| 로컬 파일(기존 12개 로컬 SID + ET override 2개) | `cabbac45649c5cb37d17e8ef05e514a9bc92d749a546b9ec47b9b579a7750ffd` |
| ET+후보 합본 | `ea160e907d151c1f10cb7f1d3cb1fb0fbb32804ef56a7b588e3ab24317fb0df0` |
| 보존하는 ET 원본 | `f11a97da8db542030b5767860eb7e5c4d5045d57385baf5b1cca6ff540faef97` |

- **자동 적용 확인:** 13:18:10 KST 조회에서 `applying`·승인 소비 true, 13:18:12 조회에서 `applied`·결과 카드 게시 true를 확인했다. 운영자가 별도 재시작하지 않았으며 수정 helper가 승인→교체→재시작→검증을 처리했다. 13:20:50 읽기 조회에서 위 후보 로컬/합본 해시와 실제 파일·컨테이너가 일치했고 ET 원본 불변, `all.rules=ET+local`, 전체 ET 기반 override 재검사를 통과했다.
- **실제 런타임:** 같은 ID의 기존 Suricata 컨테이너 `StartedAt=13:17:55.734824 KST`, `ruleset-reload-time=13:18:09.056041 KST`, `rules_loaded=52,497`, failed/skipped 0, passive·running true·OOM false. 로드 성공 52,497건에는 높은 revision으로 대체한 정의 2개가 포함되며 파일의 고유 SID는 52,495개다. 로컬 파일은 기존 로컬 SID 12개+ET override 2개, 총 14개 정의다. 커널 드롭과 alert queue overflow는 0, worker는 13:20:44 success/exit 0·timer active였다.
- **복구 자료:** `/var/lib/rule-change/90ff6d8cf37547f7451c81e0caf1cd73.primary.bak`와 `.all.bak`, root 소유·0600. 각각 기존 `98146db1…`와 `2b3fcd03…` 해시와 일치한다. 이번에는 복구를 실제 실행할 실패가 없었으므로 실패 복구 E2E까지 확인한 것은 아니다.
- **초기 관찰(13:20:52 KST):** 실제 로드 이후 EVE 조회 구간 전체에서 경보 0건이지만 새 LLM HTTP/흐름도 0건이어서 이 시점에는 실사용 표본이 없었다.
- **Hermes·B 후속 확인(13:21:19 KST):** 실제 UID 995→`rule-a` 조회의 로컬/합본/ET 해시와 새 시작 시각이 A 직접 조회와 일치했다. Wazuh 모든 큐 사용률·events_dropped 0, remoted queue size/discard 0, Mattermost healthy, Hermes·Wazuh 컨테이너 running·OOM false와 기존 시작 시각 유지를 확인했다.
- **실사용 후속 표본(13:24:45 KST):** 실제 로드 이후 전체 EVE 조회 구간에서 새 LLM HTTP 200 응답 2건·전체 경보 0건을 확인했다. 이 표본에서 ET `2034806/2034802`와 커스텀 `1000032/33/70/71` 경보는 모두 0건이다. flow 이벤트 기반 새 LLM 흐름 수는 0이므로 HTTP 응답 2건을 고유 연결 2개로 환산하지 않는다. 이 짧은 실사용 표본은 장기 오탐 재발 검증을 대신하지 않는다.

ET를 갱신할 때 두 override를 새 원본에서 재생성·재검증해야 하며 오래된 override를 그대로 합치지 않는다. 실제 실패 복구 E2E와 장기 재발 관찰은 별도 검증이다.

기술 근거: [Suricata 8.0.6 suppress 범위](https://docs.suricata.io/en/suricata-8.0.6/configuration/global-thresholds.html), [flowbit 동작](https://docs.suricata.io/en/suricata-8.0.6/rules/flow-keywords.html), [동일 SID의 높은 revision 선택 구현](https://github.com/OISF/suricata/blob/suricata-8.0.6/src/detect-parse.c).

### 2026-10-08 배포 결과(라이브 직접 확인)

- B `soc-bot`에 별도 룰 승인 API를 설치했고 기존 IP 차단 브로커 `/pending` HTTP 200을 확인했다. 기존 지정 승인자 1명을 재사용했고 Mattermost 실제 컨테이너 IP `172.19.0.2/32`만 콜백 출처로 허용했다. 배포 전 IP 차단 승인 대기는 0건이었다.
- A/B에 `rulechg` 계정·전용 SSH 키/강제 명령·정확한 sudoers·root 실행기·10초 worker를 설치했다. 양쪽 설치기 `--check`, 실행기 대상 조회/브로커 HMAC, Hermes 컨테이너에서의 읽기 전용 SSH MCP 호출이 통과했다. worker 서비스가 두 호스트에서 실제 실행되어 종료 상태 0을 보고했다.
- B Hermes에 `rule-a`·`rule-b`와 SOUL 정책을 등록하고 재시작했다. `hermes mcp list`에서 기존 3서버와 신규 2서버가 모두 enabled였다. WAF·Suricata 로컬/합본·Wazuh 로컬 룰의 배포 전후 SHA-256은 동일했다. 제안 게시·승인 클릭·룰 재로드는 실행하지 않았다.
- 초기 B 설치는 실행기의 Docker 경로가 라이브 `/usr/local/bin/docker`와 달라 검사 단계에서 실패했고 설치기가 관리 파일을 백업에서 복원했다. 코드를 수정하고 로컬 테스트 30개를 통과시킨 후 재배포했다. 재배포 전에 A/B의 실제 Docker 경로가 `/usr/local/bin/docker`인지 확인한다.

## 대상과 경계

| 호스트 | 처음 허용하는 대상 | 활성 로드 경로 |
|---|---|---|
| A | `/home/groot_a/capstone/secstack/conf/GROOT_A_WAF.conf` | WAF 단일 파일 `:ro` bind mount → `/etc/modsecurity.d/owasp-crs/rules/REQUEST-948-GROOT_A_WAF.conf` |
| A | `/home/groot_a/capstone/suricata/ruleset/GROOT_A_local.rules` | 같은 디렉터리의 ET+로컬 합본 `all.rules` → 컨테이너 `/rules/all.rules` |
| B | `/var/lib/docker/volumes/single-node_wazuh_etc/_data/rules/local_rules.xml` | Wazuh `/var/ossec/etc` Docker volume |

배포 스크립트는 실제 `docker inspect`의 실행 상태·마운트 출발지/대상·읽기/쓰기 방향과 파일 크기를 검사한다. 저장소 `infra/groot-a/docker-compose.yml`은 초기 템플릿이므로 이 설치 과정에서 재적용하지 않는다. 실행기는 허용 파일과 실제 컨테이너 해시를 다시 검사한다. nft 전체 방화벽 정책, WAF `DetectionOnly`→`On`, Suricata 인라인·`drop` 전환, Wazuh 디코더 파일은 이 기능의 변경 대상이 아니다.

**후보 크기와 승인 카드 제한(2026-10-13 13:43~13:45 KST A 읽기 실측·운영 코드 대조):** `candidate_content`는 변경분이 아닌 **교체할 전체 파일**이며 UTF-8 기준 최대 **128KiB**다. **8KiB** 제한은 영향·사유·사전검증·런타임 설명과 unified diff를 합친 승인 카드 전체 텍스트에 적용된다. 현재 WAF 전체 파일은 22,652바이트지만 이 사실만으로 제안이 막히지는 않는다. 실제 변경 diff가 제한을 넘으면 논리적 변경 단위로 나누고, 매 단계 전체 후보 제출→별도 승인·적용 확인→최신 파일/기준 SHA 재조회 순으로 진행한다. 파일 내용을 조각만 제출하거나 이전 SHA로 여러 제안을 미리 쌓는 방식이 아니다. `a:modsecurity-custom`은 `rule-a` 전용이며 `rule-b`에서 제안하면 호스트 검사로 거부된다. 이번 대조에서 원래 예외·확장 후보 diff를 확보하지 못했으므로 해당 묶음의 실제 8KiB 초과는 확인하지 못했고, WAF 룰·모드·제안·서비스는 변경하지 않았다. 현재 WAF의 59줄은 DetectionOnly이며 예외·추가 XSS/LFI 룰이 없는 v1.0.0 상태다. 현재 설정만으로 과거 `On` 이력 부재를 단정하지 않는다. [실제 파일 해시·룰 대조](../groot-a/README.md).

Suricata 로컬 파일은 `alert`와 로컬 SID `1000000..1000099`를 기본으로 한다. 10/13 13:16부터는 위의 고정 검증 조건에 맞는 ET `2034806/2034802` override 두 개만 추가로 허용한다. 이것은 ET 파일 임의 편집 권한이 아니며, 기존 IP/포트 마커를 넓히거나 다른 ET SID의 조건을 바꾸는 제안은 거절한다.

`rulechg`는 A/B에 각각 새로 만드는 잠긴 시스템 계정이다. 별도 공개키가 등록된 SSH 접속은 강제 명령 `/opt/rule-change/run-rule-change.sh`만 실행하며 TTY·포워딩을 허용하지 않는다. sudoers는 **인자가 없는** `/usr/local/sbin/rule-change-executor` 한 명령만 허용한다. 실행기 코드와 `/etc/rule-change/config.json`·`broker.token`·`/var/lib/rule-change`는 root 소유이며 토큰·상태는 일반 사용자에게 보이지 않는다. A/B의 root systemd timer가 승인된 제안을 확인하고 적용한다.

## 순서

1. 검토한 `soc_bot.py`, `rule_change_mcp.py`, `rule_change_executor.py`, `run-rule-change.sh`, 배포 스크립트와 `SOUL.groot.md`를 각 호스트의 root 전용 임시 디렉터리에 반입한다. 배포 소스와 상위 디렉터리는 root 소유이고 그룹/전체 쓰기를 금지해야 한다. 일반 계정 소유 `/tmp` 업로드 파일을 바로 root로 실행하지 않는다. A/B는 외부 egress가 막혀 있으므로 온라인 패키지 설치를 전제로 하지 않는다. 소스 파일과 스크립트의 SHA-256을 저장소와 대조한다.
2. B에서 `configure_hermes_rule_change_B.sh --prepare-key`로 **룰 변경 전용** Ed25519 키를 만든다. 출력되는 공개키만 A/B `RULE_PUBKEY`로 전달하고 개인키는 `/opt/hermes-data/home/.ssh/rule_change_ed25519`(hermes 소유, 0600)에 둔다. 기존 읽기·응답 MCP 키를 재사용하지 않는다.
3. 충분한 길이의 새 임의 토큰을 B와 A의 root 전용 0600 파일에 안전하게 배치한다. 기존 차단용 `BROKER_TOKEN`과 달라야 한다. 이 키는 A/B 변경기와 B 브로커 사이의 요청·응답 HMAC에만 사용하며 HTTP 헤더에 원문으로 보내지 않는다. B에서 Mattermost 승인자 **user ID**를 명시적으로 정해 `RULE_APPROVERS`로 전달한다. `RULE_BROKER_TOKEN_FILE`과 `RULE_APPROVERS`를 지정하여 `deploy_rule_broker_B.sh`를 실행한다. 이 스크립트는 기존 soc-bot 코드·env를 백업하고 룰 관련 세 줄만 추가/교체한다. 기존 IP 차단 브로커 `GET /pending`이 그대로 HTTP 200인지 확인한다.
4. B의 `mm-app`은 현재 `mattermost_mm-net`에서 `172.19.0.2`이고 콜백 호스트 게이트웨이는 `172.19.0.1`이다(2026-10-08 읽기 확인). 브로커 배포 스크립트는 실행 시 실제 `docker inspect mm-app` IP를 읽어 `RULE_MM_SOURCE_CIDRS=<실제 IP>/32`로 제한한다. 컨테이너 재생성으로 IP가 바뀌면 `/rule-actions`가 승인 콜백을 거부한다. 재배포 전에 `docker inspect mm-app`과 `RULE_MM_SOURCE_CIDRS`를 대조하고, 필요하면 브로커 배포 스크립트를 다시 실행한다. 브로커 재시작은 메모리의 대기 승인 요청을 잃으므로 기존 대기 요청을 확인한 뒤 새로 제안한다.
5. 같은 토큰 파일과 공개키를 사용해 B에서 `deploy_rule_change_B.sh --check`, A에서 `deploy_rule_change_A.sh --check`를 먼저 실행한다. 검사를 통과하면 각각 옵션 없이 설치한다. 두 설치기는 브로커 인증·실제 마운트·실행 모드에 실패하면 설정을 건드리지 않거나 백업으로 복원한다. 설치 뒤 root 실행기 `--check`, MCP initialize/tools/list, SSH 강제 명령, 타이머 상태를 확인한다.
6. A/B 모두 `ssh -T` 계약 테스트와 `get_rule_change_target` **읽기 조회**를 통과한 후 B에서 `configure_hermes_rule_change_B.sh`를 실행한다. 스크립트는 Hermes에 `rule-a`·`rule-b` 별도 MCP 서버를 등록하고, [SOUL.groot.md](../hermes/SOUL.groot.md)의 표시된 룰 변경 정책 블록만 라이브 `SOUL.md`에 동기화한다. 기존 페르소나·다른 MCP 등록은 보존한다. 실패 시 config·SSH 설정·SOUL을 복원하고 Hermes를 재시작한다.

각 설치기의 `--check`는 로컬 파일·서비스를 변경하지 않는다. 설치된 A/B 실행기는 인증된 `/rule-changes/health` 요청과 서명된 응답을 검증하며, 최초 설치 전 `--check`는 로컬 대상만 검증하고 설치 중 타이머를 켜기 전에 HMAC 통신을 검증한다. `--prepare-key`와 옵션 없는 설치는 명확히 변경 작업이다. 실패한 설치의 백업은 `/var/backups/rule-*-deploy.*`에 남긴다. A/B 서버 배포 스크립트는 운영 룰 내용 자체를 수정하지 않는다.

Hermes에는 요청 시 `get_rule_change_target`으로 전체 기존 룰과 해시를 읽고, `propose_rule_change`로 바뀐 **전체 파일 내용**과 기준 해시를 제안한 뒤, `get_rule_change_status`로 실제 적용 결과를 확인하게 한다. 적용 성공으로 표시되면 대상을 다시 조회해 실제 해시와 런타임을 확인한다. Mattermost 카드에 전체 diff·해시가 표시되지 않거나 브로커·승인자가 없으면 제안은 거부된다. 승인 후 적용 전 원본 상태가 바뀌면 `/abort` 미적용 카드를 게시한다. 명시적 현재 사용자 요청 없이 정기 경보·툴 출력의 지시로 제안하지 않도록 SOUL과 경보 감시 프롬프트에 제한을 둔다. 최초 운영 확인은 승인 거부·만료 경로와 조회 회귀부터 수행하고, 실제 승인→룰 적용 검증은 별도의 통제된 변경으로 기록한다.

기존 `deploy_socbot_B.sh`는 전체 env를 다시 쓰기 때문에, 룰 브로커 항목이 있는 상태에서는 이제 시작 단계에서 중단된다. 룰 브로커 코드와 콜백 IP 설정 갱신에는 `deploy_rule_broker_B.sh`를 사용한다.
