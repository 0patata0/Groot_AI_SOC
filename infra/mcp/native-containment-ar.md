# Native Wazuh 사건 → LLM 판단 → 제한된 Containment

> **2026-10-31 자동 조사 후속:** A의 RFC1918 집행 정책과 두 봇의 공통 정책은 갱신되어 있었으나 자동 조사 프롬프트에 공인 전용 설명이 남아 있음을 운영에서 확인했다. 이 프롬프트도 현재 정책으로 교체했다. 자동 조사에 없는 `resp.block_ip/unblock_ip`와 대화형 승인 경로도 구분했다. 보호주소·증거·TTL·관리자 승인 범위와 실제 nft 규칙은 변경하지 않았다. [초기 설치 동기화](../../deployment/SOC_MANAGEMENT.md) · [운영 검증·미완료](../../STATUS.md).

> 2026-10-29 정정: 아래 과거 공인 전용·사설 전체 제외 설명은 현재 정책이 아니다. LLM 조사 후 공인/RFC1918 출발지를 동일 증거 기준으로 검증하며 live never_block·관리·필수 서버 보호는 유지한다. Native AR은 계속 사건 등록만 수행한다. [현재 정책](approved-operations.md)을 기준으로 한다.

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../STATUS.md) · [실행 계획](../../PLAN.md).
> 현재 구성은 MCP6서버와 고정 진단25대상이다. 자연어 도구 선택·무근거 완료/SILENT 알림 보완의 실제 검증 상태는 STATUS 최상단을 따른다. 정확 후보 승인과 일반 sudo/Docker/임의 shell 금지는 유지한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

## 현재 운영: LLM 판단 선행 구조 배포 완료 (2026-10-15 14:08 KST)

Native AR의 역할을 **사건 등록**으로 변경하여 운영에 반영했다. 사건의 대응 필요성과 도구 선택은 LLM이 판단하고, 관리자는 보호된 변경의 승인·거부를 결정한다. helper/worker는 고정 정책 검증과 실행을 담당한다. 긴급 임시 차단도 LLM 호출을 먼저 거치며, 모델 지연·장애 때 Native AR가 대신 직접 차단하는 경로는 없다.

```text
A Wazuh agent001 / rule100110
  → Native AR: 고정 사건 필드 검사 → submit-incident
  → B HMAC 사건 등록 / 영속 outbox
  → B 사건 제어기 → 기존 Hermes 세션에서 LLM 조사·판단
  → 필요할 때 rule-a MCP temporarily_contain_ip
  → 서버 원본 증거·보호 주소 검사 → 600초 임시 차단
  → 기존 관리자 유지/해제 승인 → 고정 worker
  → 승인·실행 결과 outbox → 같은 사건의 LLM 읽기 전용 검증
```

### 이번 배포에서 직접 확인한 사실

| 시각(KST) | 적용·확인 |
|---|---|
| 13:59:57 | B `soc_bot.py`/operations에 HMAC 사건 등록, SQLite 승인 전이 outbox, level9 이상 최근5분·최대500건 경보 조회를 적용했다. soc-bot 재시작 후 인증된 사건·경보 조회를 확인했다. |
| 14:00:47 | A adapter와 root executor를 교체했다. adapter는 `submit-incident`만 보내고 직접 root `contain-ip`는 거절한다. 제한 MCP 계정의 호출만 기존 containment 경계로 전달하며 이번 배포의 nft 호출·A 서비스 재시작은0이다. |
| 14:01:24 / 14:01:35 | Hermes 정책 갱신 후 같은 컨테이너를 재시작하고 채팅 재연결을 확인했다. 기존 최근5개 경보 감시 cron을 비활성화하여 새 사건 처리와 중복 실행하지 않는다. |
| 14:08 | B `capstone-management.timer` 활성화 후 실제 실행 exit0를 확인했다. 사건 큐와 실제 MCP 제안 ID를 영속 보존하고 승인 결과에 따라 같은 세션을 읽기 전용으로 재개한다. |

현재 native 플랫폼 toolset은 `mcp-resp`, `mcp-rule-a`, `mcp-rule-b`, `mcp-security-events`, `mcp-wazuh-ro`의 정확5개다. 자동 관리 wrapper는 읽기/관리 모드를 코드에서 구분하고 일반 셸·설치·컨테이너 구성 도구를 허용하지 않는다. 기존 동기 승인 대기 `resp.block_ip/unblock_ip`는 자동 관리 실행에서 제외하고 `list_blocks`만 사용한다. [제어기](../hermes/soc_management_controller.py) · [Hermes 실행 경계](../hermes/soc_management_run.py) · [사건 outbox](soc_management_events.py).

### 유지하는 실행 제한과 검증 범위

사건 등록은 A의 직접 root 경로만 허용하고 `SUDO_USER`가 있으면 거절한다. 실제 `contain-ip`는 `SUDO_USER=rulechg`인 제한 MCP 경로만 허용하며 `requested_by=hermes-mcp`로 구분한다. 이 귀속 값만으로 LLM의 판단을 증명하지 않으며 제어기의 실제 모델·도구 호출 이력을 함께 확인한다. 조사 입력에는 보호 IPv4도 들어올 수 있지만, 차단 시에는 기존 보호 주소 정책이 그대로 적용된다.

독립적인 양방향 TCP severity1 flow3개, 최근5분 원본 증거,600초 임시 TTL, 자동 연장 금지,3600초 유지 또는 해제 승인, HMAC/nonce/일회 소비를 유지한다. 큐 수신증은 차단·사건 해결 성공을 뜻하지 않는다. 승인 후 룰 적용 검증은 제안 ID·정확한 대상·예상/실제 SHA·실행 상태를 확인하며 서비스·차단도 실제 상태를 재조회한다. 결과가 불명확한 모델 실행은 자동 쓰기 재실행 없이 검토 상태로 남긴다.

오프라인 회귀 **284개**(제어기33·wrapper25·사건 outbox21·정책7·사건등록10·adapter38·executor53·containment36·MCP10·브로커25·operations12·legacy7·resp7)가 통과했다. 실제 `.111` 모델의 읽기 전용 호출과 같은 세션 재개2회는 **26.469초·17.533초**, 쓰기 요청·Mattermost 전송0으로 확인했다. **실제 적격 경보→LLM 판단→차단→관리자 승인→검증/만료 전체 시험은 아직 미실시**이며 이 읽기 시간을 긴급 대응 성능으로 제시하지 않는다.

경보 `_index/_id`와 Native 사건 ID를 영속 보존하고60초 단위로 묶되, 진행 중 동일 agent/rule/IP 사건에는 최대5분 안에서 합류한다. 최근5분 조회의 공백·500건 초과와 최근40건 문맥 제한은 명시한다. 검색 시간창을 넘는 과거 사건의 자동 회수, 전체 수집 경로의 무손실, 회전 전후5분 원본 증거의 완전성을 보장하지 않는다. managed reader의 현재 generation 한계도 아래 이전 검증과 같다.

아래 후보·오전 설치 설명은 **변경 전 이력**이다. 그 안의 직접 `contain-ip`, 외부 IPv4만 조사 입력으로 받는 설명, 당시 helper/adapter SHA를 현재 동작이나 현재 파일 해시로 사용하지 않는다. 현재 동작은 위14:08 확인을 기준으로 한다.

## 이전 후보 기록: LLM 판단 선행 전환 — 배포 전 로컬 검증 (2026-10-15)

현재 저장소의 adapter는 `contain-ip`를 보내지 않는다. native `add`의 고정 agent001·rule100110/level9·EVE 경로·severity1·명시 시간대와 최근5분 검사를 통과하면 정확7필드 사건을 고정 root helper의 `submit-incident`로 전달한다. helper는 HMAC으로 `POST /management/incidents`에 등록하고 검증한 `queued/event_key/seq` 수신증만 반환한다. 이 경로는 룰 engine·ContainmentService·승인 소비·nft를 실행하지 않으며 새 MCP 도구로도 노출하지 않는다.

사건의 `event_id`는 유효한 Wazuh `alert.id`를 보존한다. ID가 없을 때는 명시된 사건 필드와 정규화한 `flow_id`의 canonical JSON SHA-256으로 만든다. 동일 사건의 재전달은 같은 ID를 사용하며 메시지 본문·원문 명령은 포함하지 않는다. private/관리/DGX 등 보호 IPv4도 **조사 입력**으로 수용한다. 해당 주소의 실제 차단 금지는 기존 containment 정책에서 그대로 강제한다.

등록은 A의 직접 root 실행만 허용하고 `SUDO_USER`가 있는 경로는 거절한다. 반대로 기존 `contain-ip` helper는 `SUDO_USER=rulechg`인 제한 MCP 호출만 허용하고 `requested_by=hermes-mcp`로 기록한다. 기존 Native AR의 직접 root `contain-ip`는 거절한다. 이는 호출 경로의 구분이며, 실제 LLM 판단·도구 호출 이력은 제어기 검증으로 별도 확인해야 한다. root 자체를 비신뢰 주체와 격리한다는 의미는 아니다.

LLM이 사건을 조사·판단한 뒤 필요할 때 기존 `temporarily_contain_ip`를 호출한다. 서버의 독립3-flow·보호 주소·600초 TTL·유지/해제 카드 승인·일회 소비는 유지한다. 큐 등록은 차단이나 사건 해결 성공을 뜻하지 않으며 등록 실패·timeout 때 직접 차단으로 우회하지 않는다. 서버 적용·실제 큐 등록→LLM 판단→차단·후속 승인 E2E는 아직 미실행이다. 아래 내용은 **변경 전 10월15일 오전의 설치·확인 이력**이며 새 후보가 운영에 반영됐다는 뜻이 아니다.

로컬 검증은 사건등록10개·adapter/managed reader38개·룰 executor53개·기존 containment36개·MCP10개, 총147개를 통과했다. native envelope→등록 helper→모의 큐에서 중복 ID의 같은 수신증과 engine/명령 실행0, private 입력 수용, 만료·잘못된 입력 거절, 직접 root 차단 거절·제한 MCP 귀속을 확인했다. 실제 HTTP·nft·채팅·서버 변경 없이 수행한 회귀이며 라이브 검증과 구분한다.

**2026-10-15 설치·설정 활성화 완료, 실제 차단 E2E는 미시험**이다. A 새3파일 설치 후 Linux native69개와 실제 managed current generation 4,015건의 읽기를 확인했다. B는 agent001/rule100110에 한정한 연결의 native 설정3개 통과 후08:31:30 KST 같은CID 재시작·ready를 확인했다. A는08:47 KST CP 정합성 수정과 함께 `<disabled>no</disabled>`를 적용하고 agent를 한 번만 stop/start했으며,08:49:07 후조건에서 활성화·guard PASS·checkpoint 직접 수정0을 확인했다.

[Wazuh stateless AR](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)의 `add` 알림을 기존 `/usr/local/sbin/rule-change-executor` stdin `contain-ip` 요청으로만 변환한다. 별도 승인 플랫폼은 없고 기존 root helper SHA `d937c7def4d2938d7655e445cb5cf9cd7858837aebebaf4278feae5fb69965a2`도 그대로다. **적격 운영 경보에 의한 실제 차단·자동 만료·유지/해제 승인 카드 end-to-end는 실행하지 않았다.** 설치·활성화를 그 시험 성공으로 확대하지 않는다.

## 고정 범위

`native-containment-ar.xml`의 manager 연결은 command `capstone-containment`, `timeout_allowed=no`, `defined-agent` 001, rule100110 하나다. `level`·`rules_group`를 추가하면 Wazuh가 조건을 OR로 해석해 범위가 넓어지므로 쓰지 않는다. [공식 설정 의미](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html)

A adapter도 native envelope/add·agent001·rule100110/level9·정확 Suricata eve 위치·5분 이내 명시 시간대·외부 IPv4를 검사한다. `data.src_ip`는 재검증을 시작할 힌트다. 경보 한 건만으로 차단을 허용하지 않는다. DGX/사설·예약·관리 주소 보호 및 최근5분의 독립적인 양방향 TCP severity1 공격 flow3개는 **기존 `incident_containment.validated_evidence`·live backend가 다시 판단**한다. 기존 600초 임시 TTL, 자동 만료, 반복 연장 금지, HMAC/nonce/일회소비를 사용한 3600초 유지 또는 해제 승인을 그대로 사용한다. 기존 승인 카드 발송은 실제 적격 사건에서만 기존 흐름대로 발생하며, 이번 합성 검증에서는 메시지·nft·HTTP 호출이 없다.

AR에는 Wazuh timeout/delete/repeated_offenders를 추가하지 않는다. 커널 TTL·소유 태그와 기존 root worker가 해제를 관리한다. adapter는 shell/sudo/임의 명령·경로·token을 받지 않고 고정 helper만 실행한다. helper 실패·360초 timeout·중단은 결과 불명/거절로 남기며 자동 재호출하지 않는다. stdout에는 고정 상태와 helper 종료 코드만 남고 원문·IP·승인 내용은 내보내지 않는다. 설치 Wazuh의 실제 적격 경보 envelope부터 adapter와 기존 차단 정책까지의 연결은 미시험으로 남긴다.

## Managed 원천 보완

이전 reader는 `.1`/현재 파일의 nlink1만 허용해 managed generation/active/eve **3개** hardlink 구조를 거절했다. 설치된 `managed_suricata_evidence.py`는 다음 조건에서만 현재 generation을 읽는다. 실제 읽기4,015건·6,498,609B·nlink3를 확인했으며 이전 세대나 공격 적격성 전체를 검증했다는 뜻은 아니다.

- 고정 A machine/현재 boot, root0600 canonical 단일 state, schema1·정확 active/pending=null/proof=null 계약.
- root0711 managed 디렉터리, 정확 generation basename/dev/inode, 세 경로의 regular/nofollow/UID998:GID998/0644/nlink3 일치. 남은 publish 임시 링크는 거절.
- 실제 Vector config/env 및 Wazuh config SHA가 root state pins와 일치. 원래 config 메타도 전후 동일해야 한다.
- 기존 Vector 공통 lock에 nonblocking shared lock을 잡고 상태·설정을 전후 대조. 다른 회전 작업이 lock을 잡았거나 상태가 pending이면 보류.
- pre-stat EOF 기준 마지막16MiB, 최대32768행/행256KiB/검사5초. 같은 고정 범위를 두 번 읽어 일치 확인; 이후 append는 허용하지만 잘린 첫 행·미완료 마지막 행은 제외. 잘못된/중복키 JSON은 공격 증거에 포함하지 않는다.

`incident_containment.py`의 접점만 보완한다. managed root가 어떤 형태로든 존재하면 root 고정 extension의 검증한 바이트를 불러오며 오류 시 legacy로 우회하지 않는다. managed root 없는 기존 환경의 reader는 그대로다. **현재 세대만** 읽으므로 회전 직후 이전 세대에 걸친5분 전체성이나 완전 탐지·원격 ACK를 주장하지 않는다. 부족하면 기존 3-flow 기준에서 거절한다. runtime coordinator/state/checkpoint는 수정하지 않는다.

## 수행한 설치·활성화 순서

1. 부모 운영자가 기존 incident 원본 SHA `e22114ad94d2a11294bf329174f5eb8e9879bdb5c8d053025889624f9e42152f` 및 실제 root:root0750/nlink1을 확인·백업했다. 새 reader `/opt/rule-change/managed_suricata_evidence.py` root:root0400, adapter `/var/ossec/active-response/bin/capstone-containment` root:root0750를 source SHA와 결속해 설치했고 incident는 원래0750으로 한 접점만 CAS했다. 기존 helper/sudoers/broker는 그대로다.
2. A 기존 Linux Python에서 **신규33+기존Containment36=69개 PASS**와 실제 root 경로·managed3link 읽기를 확인했다. 시험의 모델·nft·채팅 호출은0이다. 모의 flow3개가 기존정책을 통과하는 것과 실제 운영 차단은 구별한다.
3. B manager에 정확 command/AR 두 블록만 추가하여 native 설정3개, 같은CID bounded restart 및 필수5프로세스·agent001 active를 확인했다. 이 시점에는 아직 A disabled=yes였고 이후 A 단계와 구분한다.
4. A CP 정합성 수정과 충돌하지 않도록 한 번의 통제된 config CAS/agent restart에서 stats-ignore 제거와 AR disabled=no만 결합했다. 아래 readiness 영수증 SHA와 설치3파일을 재대조했고, 이후 후조건은 `active_response_config_enabled=true`, `native_stop_calls=1`, `native_start_calls=1`, `checkpoint_rewritten=false`였다. 실패 시 권한을 우회하거나 설정을 추정해 재시도하지 않는다.

설치된3파일 SHA는 incident `ab51cfeb5416a278f20c3cd569ed582c5a6f239e91b480a2ed89e1c06cba980c`, managed reader `06d36cdbf61de5ed08e8e6c3cc829a7d01648e10f04f5c6253818ea89be3d4df`, adapter `d7b603e542b68e8290c37e9214427a56a181c5cee15daee3d2cd5a7ca8e8989e`다. 보호 IP·독립3-flow 기준·600초 TTL·기존 유지/해제 승인 정책은 변경하지 않았다.

readiness 파일은 `/var/lib/capstone-automation/native-containment/ready.json`(root400, 부모root700, regular/nlink1)이며 정확9키다. 단일 canonical sorted JSON+LF로 fsync 후 게시한다.

```json
{"agent_id":"001","automatic_test_containment_executed":false,"installed_sha256":{"/opt/rule-change/incident_containment.py":"<64hex>","/opt/rule-change/managed_suricata_evidence.py":"<64hex>","/var/ossec/active-response/bin/capstone-containment":"<64hex>"},"machine_id":"096e90b6243e438aa8a7b392be754732","manager_configuration_verified":true,"native_tests_passed":true,"policy":"capstone-native-containment-ready-v1","rule_id":"100110","schema_version":1}
```

실제 readiness SHA는 `83b05b8080ae1d9cd34a951032db3970aded81fc1b606a4e05744ccce8b9a35f`다. 이 파일 자체는 A 활성화나 공격 차단의 증거가 아니라 설치와 B 설정 준비의 근거다. A 활성화는 별도 CP controller 후조건으로 확인했다. 원본 metadata는 부모 evidence의 `ar-install-a.json`(SHA7608292f…), `ar-ready-b-v2.json`(24d4cc73…), `cp-final.json`(558add2c…)에 보존돼 있다. 실제 적격 자연 공격/차단·만료·유지·해제 end-to-end와 카드 발송 시험은 별도로 남는다.
