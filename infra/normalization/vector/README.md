# Vector 기반 정제 경로

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../STATUS.md) · [실행 계획](../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

## 2026-10-15 02:15 KST 최신 상태 — 3단계 운영 검증·타이머 활성화 완료

**02:15:39 KST 원본 회전 운영 전환과 자동 실행 확인을 완료했다.** Suricata·WAF 원본 타이머 두 개의 첫 실행은 회전 불필요(`not_due`)로 정상 완료됐고, 출력 유지관리의 정상 daily 실행에서는 ready·evidence·telemetry 세 파일을 회전했다. 빈 quarantine은 유지했다. 이어 유지관리 타이머만 다시 활성화해 첫 실행 `not_due`·추가 회전 0회를 확인했다. 세 타이머 모두 enabled/waiting이다.

최종 Vector는 **PID 2406117 / Invocation `12314ddc66e14e0083b08db2e51fc831`**로 정상 실행 중이며 Wazuh logcollector **1909632**, WAF master **2377669**·healthy와 원천 state **Suricata gen1/revision5, WAF gen3/revision11 active**는 유지됐다. pending 부재, 양 시작 가드와 수집·저장 상태 검사를 통과했다. 원본과 native checkpoint를 수동 수정하지 않았다. [운영 결과와 한계](raw-operations/README.md) · [검증 메타데이터](raw-operations/resume-validation-2026-10-14.json).

최종 소스·증거의 영구 보관과 임시물 정리를 완료했다(아래 정리 후속 기록). **4단계는 구현 준비 중이며 운영 전환은 아직 없다.** 인증서 관리는 마지막 순서다. 실제 호스트 재부팅, 새 CID의 WAF 재생성, 이번 구간의 새 적격 보안 사건 ACK는 검증하지 않았다. EVE·audit만 copytruncate에서 제외했고 Suricata 부가 로그와 WAF 보조 access의 기존 정책은 유지한다. 아래 기록은 각 시점의 이력이며 최신 상태는 이 항목을 따른다.

**02:19:46 KST 정리 후속:** A의 작업 자료 515파일·4,621,609B와 격리 시험 자료 8파일·98,071B를 보관한 뒤 stage3·시험 fixture·미사용 v1 recovery guard를 제거했다. migration 시작 가드는 유지했고 정리 전후 운영 상태 불변·서비스 신호 0회를 확인했다. Mac의 해당 임시 트리 650파일·55디렉터리·5,318,295B와 B 조회 임시파일 2개도 제거했으며 영구 증거는 유지했다. **이 문구는 267파일·2,077,701B 소스 스냅샷 이후에 추가한 기록**으로 그 스냅샷에 포함된 문서 바이트와 구분한다. **02:20:55 KST 최종 점검도 완료했다.** 두 migration guard는 ready이며 storage 정상·Vector active·recovery=no·collection=[]·binding 검증 및 상태 코드 없음, 세 타이머 enabled/active/waiting을 확인했다.

## 이전 시점 기록 — 2026-10-15 최신 운영 상태 — 원본 회전 적용, timer 활성화 대기

A에 원본 회전 controller와 WAF v2를 실제 반영하고 초기 migration seq18·reader 인계를 마쳤다. 두 원천의 실제 회전 결과는 **Suricata gen1 / revision 5 active**, **WAF gen3 / revision 11 active**다. **01:48:58 KST WAF의 같은 CID 재시작 1회**도 정상 종료·복귀를 통과했다. 새 master PID는 **2377669**, UID101·healthy이며, Vector **2368467**와 Wazuh logcollector **1909632** 및 두 raw state는 유지됐다. [운영 전환·검증과 한계](raw-operations/README.md) · [현재 WAF v2 계약](waf-producer-v2/README.md).

원본 `eve.json`과 `audit.log`만 legacy copytruncate에서 제외했다. Suricata `fast.log`·`stats.log`·`suricata.log`와 WAF `capstone-access.log`는 기존 copytruncate를 유지한다. WAF v2 정제는 감사 행의 context를 사용하며 access는 보조 원본이다. **원본·출력 회전 timer는 아직 disabled이며 활성화 사전 검사 2회, enable 0회**다. 따라서 자동 운영까지 완료했다고 표시하지 않는다.

실제 호스트 재부팅은 **0회**, 이번 관찰 구간의 자연 적격 보안 사건 ACK 표본도 **0건**이다. 로컬 처리 위치를 manager/Indexer 수신 확인으로 확대하지 않는다. 4단계 Hermes 운영 변경은 미착수이며 읽기 전용 사전 확인만 했고, 인증서 관리는 마지막 순서다. 아래 미배포·copytruncate 유지·후속 예정 문구는 각각의 과거 기준이며 현재 상태는 이 항목을 우선한다.

## 운영 분석기 1/1 적용·실제 20회 종단 검증 완료 (2026-10-14 18:56 KST)

B의 `analysisd.event_threads=1`, `analysisd.rule_matching_threads=1`을 18:48:55 KST에 적용하고 **같은 manager 컨테이너를 한 번 재시작**했다. 기존 native 규칙 104개를 적용 전후 각각 통과했으며, 18:49:04의 새 analysisd PID는 `2132985`, 전체 스레드는 44개다. 다른 컨테이너와 보호 해시는 유지됐다. canary 없는 60.000186초 운영 관찰에서 수신 60건(약 1 EPS), drop 증가 0, queue 최대 표본 0, 단일 코어 대비 CPU 약 0.0333%를 확인했다. [적용·관찰 증거](../wazuh-vector/correlation-fix/deployment-resume-2026-10-14.json).

사용자 명시 승인 후 실제 A agent001→B manager→Indexer의 **20회 × 13행(260행)** 시험을 18:56:08 KST에 완료했다. 동일 20개 run ID를 각각 한 번만 입력해 **manager 40건/Indexer 40건**, `100293` 20건·`100294` 20건, level 3·negative 경보 0건을 확인했다. 57/57 shard·strict CA/호스트명·각 run 및 전체 canonical tuple이 일치했으며 첫 조회 회차 11.3초, 입력 재시도 0회였다. A 원래 52행 접두 구간·inode·보호 설정과 B 옵션·룰·CID·SOC 안전 조건을 보존했다. 이 결과는 승인된 20회 시험의 성공이며 일반 트래픽의 장기 무손실 보장은 아니다. 기존 격리 1/1은 경보 4,000/4,000을 생성했지만 500 EPS 부하에서 queue 최대 표본 24%·최대 archive 관측 지연 약 10.04초가 있어 지속 처리량 보장은 아니다. [격리 부하와 한계](../wazuh-vector/correlation-fix/LOAD-VALIDATION.md). 이번 적용은 B 분석기 worker 두 옵션이며 Vector 정제·입력·보존 정책의 변경으로 해석하지 않는다. 아래의 미배포·반입 대기 설명은 이전 시점 기록이다.


**2026-10-14 12:00 KST 검증:** A/B 보존 이전 boot 1,481건을 전수 대조했고 현재 nft 정제 후보는 0건이었다. 실제 보안 정제·색인 대상도 0건이며 운영 재주입은 하지 않았다. 별도 합성 대조14건 및 Wazuh native 순서8종을 검증했다. 새 간격 시험에서는 manager2건·Indexer2건의 정확 ID와57/57shard 성공을 확인했다. 앞선 일괄 시험의 manager1건/Indexer1건은 기대값 미달로 보존하며 누락 원인은 미확정이다. [검증 범위와 결과](history-replay/README.md). 후속 Suricata 격리 시험은 지연 공개 방식에서 Vector/Wazuh 각각6건·중복0, 연속2회전·정상재시작을 통과했다. 단순 rename 대조군은2건 누락을 재현했다. 운영 copytruncate는 유지하며 다음은 WAF별 검증과 운영 전환/영속 복구 조건 확인이다. [회전 결과](raw-rotation/README.md). 아래는 이전 시점 기록이다.

**2026-10-14 10:57 KST 후속 완료:** 이전boot 후속481건을 회수해 두배치1,481건/621,820bytes의 A→B 직접 전송·B 파일보관·A 수신증 저장을 검증했다. native 합성144개·실제 합성 응답유실 재시도 및 실제배치 해시/고유cursor를 확인했고 서비스는 유지됐다. Wazuh/Indexer ACK·전체무손실·운영 재주입을 뜻하지 않는다. 다음은 격리 정제와 Suricata→WAF raw 회전 검증이다. [실측과 운영 경계](history-transfer/README.md). 아래 내용은 이전 기록이다.

**06:09 KST 현재 기준:** 기존 ready/no_log 경로를 유지하면서 적격 Suricata·nft 이벤트의 별도 `evidence/normalized.jsonl` 분기를 운영 적용했다. native110개(main49+WAF61)·jq18개·분리 reader9개가 통과했다. Vector와 storage를 한 번에 실행한 Ansible의 **최종 누적** recap은 첫 적용 `ok68 changed5`, 재적용 `ok67 changed0`이며 중간 recap과 합산하지 않는다. 실제 두 reader 회전과 Suricata1건의 A→Indexer 식별자 대조까지 확인했다. 범위와 한계는 [evidence 계약·검증](EVIDENCE.md)에 기록했다.

**04:49 KST 수집 상태 보완 적용:** 숫자 telemetry·PID/Invocation/180초 신선도 검사와 Wazuh 상태 규칙을 연결하고 원문이 포함될 수 있는 file-source 진단 출력을 제한했다. native97개/jq16개·재적용changed0·기존raw/agent/권한 보존을 확인했다. EOF 과대행 counter 누락 등 남은 한계는 [수집 경계와 실측](collection/README.md)에 기록했다.

이 디렉터리는 **Vector 0.59.0 + VRL**로 Suricata·nftables와 독립 시각 근거가 확인된 WAF를 정제하는 구성이다. 기존 Python 수집기·SQLite 전달기를 실행하지 않는다. 기존 Wazuh 원시 로그 입력은 유지하며, 운영 설치·활성화 결과는 상위 작업 기록에서 별도로 확인한다. 이 문서의 설정 존재가 운영 배포 완료를 뜻하지 않는다.

```text
Suricata EVE ── alert 선택·VRL ────────────┐
kernel journal ── prefix·transport·VRL ────┤
WAF v2 audit context ── 결속·시각검증 ────┤
                                         ↓
             KST·방향별 서비스 키·신선도 메타데이터
                         ├─ ready → A agent → B no_log 상관 규칙
                         └─ 적격 Suricata/nft → evidence → A agent
                                                → B 관찰 규칙 → Indexer
오류·시각근거 없음·짝 불일치 → root 전용 quarantine
수집·버퍼 숫자 metric → root 전용 telemetry → 운영 상태 검사
별도 root canary → level3 시험 경보 → Indexer 종단 확인
```

## 파일과 운영 경로

| 저장소 파일 | 원격 경로/역할 |
|---|---|
| `vector.toml` | 초기 v1 구성 이력. 현재 설치 파일은 `raw-operations/vector-v2.toml`을 검증한 `/etc/capstone-vector/vector.toml`이며 [전환 기록](raw-operations/INITIAL-MIGRATION.md)을 따른다. |
| `transforms/*.vrl` | 기존 공통 변환의 `/etc/capstone-vector/transforms/` 경로. 현재 v2에는 `waf-producer-v2/audit-context.vrl`을 `waf_audit_context.vrl`로 추가한다. |
| `vector.env.example` | 검증한 값만 `/etc/capstone-vector/vector.env`에 배포 |
| `capstone-vector.service` | `capstone-vector.service`, 바이너리 `/usr/local/bin/vector` |
| `tests.toml` + `tests-correlation.toml` + `tests-collection.toml` + `tests-evidence.toml` | 실제 바이너리의 main 회귀49개(기존/공통28+수집9+evidence12); 운영 입력을 읽지 않음 |
| `tests-waf.toml` | 별도 합성 topology로 실행하는 WAF 회귀61개 |
| `waf-producer/` | 초기 v1 audit/access 결합 배포 이력. 현재 운영 재적용 경로가 아니다. |
| `waf-producer-v2/` + `raw-operations/` | 현재 감사 context 정제·세대 회전·시작 가드와 운영자 전용 전환/복구. 기존 v1 playbook은 managed state가 있으면 쓰기 전에 거절한다. |

상태·disk buffer는 `/var/lib/capstone-vector`, 출력은 `/var/log/capstone-vector/{ready,evidence,quarantine,telemetry}`에 둔다. 출력 디렉터리는 root0700, 파일은 root0600이다. 서비스는 root 소유 원시 로그와 journal을 읽기 위해 root로 실행하되, systemd에서 전체 파일시스템을 읽기 전용으로 만들고 두 전용 디렉터리만 쓰도록 제한한다. 설정·환경 파일은 관리자만 변경할 수 있어야 한다. 환경 변수에는 검증한 경로·센서 ID·WAF 배포 결속 값이 들어가며 비밀은 없다. Vector 0.57.0 이후 환경 보간은 명시적 opt-in이 필요하므로 서비스에 이를 설정했다. 외부 입력·LLM이 이 환경 파일을 바꾸는 경로는 없다.

상위 운영자 배포 절차가 제공하는 A의 경로는 `vector.env.example`에 기록했다. 원격 config의 상대 VRL 경로 때문에 검증과 실행의 작업 디렉터리는 `/etc/capstone-vector` 또는 시험 복사본 루트여야 한다. 설정과 data 디렉터리 및 component ID를 바꾸면 체크포인트 결속이 달라질 수 있으므로 일반적인 재시작으로 취급하지 않는다.

## 정제 계약

- 정제 출력은 허용 목록으로 새 객체를 생성한다. 원시 `.message`, HTTP 본문·헤더·URL, journal cursor는 Wazuh 정제 경로로 보내지 않는다. `capstone_norm.schema_version="vector-1"`, `pipeline="vector"`로 기존 Python `schema_version="1"`과 구분한다.
- Suricata는 `event_type=alert`, 숫자 SID, severity 1~3, 명시적 시간대가 있는 시각만 통과한다. KST 변환 뒤에도 원본 action `allowed/blocked`를 보존한다. HTTP 403을 임의로 차단으로 바꾸지 않는다. 비 alert는 정상적인 선택 제외다.
- nft는 실제 journald source의 `_TRANSPORT=kernel`과 알려진 prefix를 함께 요구한다. 선택 필드 중복, 다중 행, 재등장하는 prefix, cursor/시각 부재는 격리한다. `FW_SHADOW_OUT`은 `would_drop`이고 실제 차단으로 세지 않는다. 첫 기동은 현재부터 시작하고 이후 체크포인트를 사용한다. A의 systemd 255에서는 Vector가 all-boots follow를 거절하므로 **현재 부트만 수집**한다. 초기에는 이전 부트 회수가 미구현이었으나 현재 [history-auto](history-auto/README.md)가 보존 중인 이전 부트를 유한 배치로 별도 저장한다. 이는 운영 재주입·B 자동 전송·과거 전체 journal 무손실 복구가 아니며 원본 journal과 기존 Wazuh 경로를 보존한다.
- 잘못된 IP·port는 상관 키에서 제거하고 품질 플래그를 넣는다. `unknown` 같은 대체 IP를 만들지 않는다. 실제 source/destination과 Suricata flow tuple을 구분한다. `.110/.111` 보호 주소는 `protected_asset=true` 메타데이터이며 차단·탐지 예외를 수행하지 않는다.
- event/observed 시각은 KST 문자열이며 offset 없는 Suricata 시각을 UTC/KST로 추정하지 않는다. nft는 journal의 마이크로초 epoch를 사용한다. Wazuh frequency/timeframe은 별도 설정 없이 이 문자열 기준 event-time 분석이 되지 않는다.
- 실패한 remap은 `drop_on_error=true`, `reroute_dropped=true`로 격리한다. 실패한 원문이 정상 출력으로 우회하지 않는다. 격리 파일에는 원문이 포함될 수 있으므로 root 전용으로 유지하고 Wazuh localfile에 등록하지 않는다.

## WAF와 공통 상관 메타데이터

**아래 단락은 초기 v1 결합 계약이다. 현재 운영은 [WAF v2](waf-producer-v2/README.md)의 감사 행 context·독립 시각 검증을 사용하며 audit/access 메모리 결합을 사용하지 않는다.**

WAF는 native JSON 구문 검사 뒤 제한된 중복 키 감시를 거친다. 정확한 `transaction.response.headers.Server` 문자열 중복만 허용하고 이 헤더는 출력에서 제외한다. 다른 중복은 격리한다. audit와 nginx 최소 access가 생성 request ID·배포 ID·주소/포트 등으로 정확히 연결되고 access의 명시 offset/epoch와 audit 시각이 일치해야 ready로 보낸다. 이전 배포·늦은 짝·짝 누락은 추정하지 않는다. [WAF 계약과 검증](WAF.md)을 따른다.

공통 `correlation.vrl`은 관측 시각에서 이벤트 시각을 뺀 값이 -5초~120초일 때 `fresh`, 그보다 오래되면 `historical`, 앞서면 `future`로 구분한다. 유효한 센서/방향별 IP/목적지 port/TCP·UDP, 품질 플래그 없음, 보호 자산 아님을 만족해야 `correlation_eligible=true`다. 키는 센서·source IP·destination IP·destination port·protocol의 SHA-256이며 양방향 세션을 임의로 같은 키로 묶지 않는다.

nft는 cursor 기반 event ID, 다른 입력은 센서·소스·message SHA를 `correlation_dedupe_key`로 제공한다. 키 제공은 영속 중복 제거가 아니다. Wazuh의 `different_field`는 전체 고유 집계가 아니므로 실제 반복/장비 간 상관은 **no_log 관찰 모드**로 둔다. WAF는 no_log base 수용이며 장비 간 상관의 승격 대상이 아니다. [실제 transport prefix와 Indexer 검증](../wazuh-vector/README.md)을 참조한다.

evidence 분기는 `fresh`, `correlation_eligible=true`, `protected_asset=false`, 빈 품질 flags인 Suricata/nft만 선택하고 그 사본에만 `evidence_lane=indexer-observation-v1`을 붙인다. ready 객체는 그대로다. B nft 관찰 규칙은 추가로 `action=logged_drop`을 요구하므로 `SPOOF/observed`가 evidence에 있어도 해당 색인 경보에서 제외된다. 이 차이를 차단 판정으로 임의 승격하지 않는다.

## 재시작·회전·ACK의 범위

Vector 패키지를 도입해도 Python의 sealed-generation, 원시 원자 보관, 서명 없는 SHA 영수증 `durable_inbox` 계약이 그대로 생기지 않는다.

| 항목 | 이 구성의 의미 |
|---|---|
| file 체크포인트 | Vector data 디렉터리의 device/inode 기준 위치. archive 폐쇄 FD·전체 SHA 증명을 검증하지 않음 |
| 첫 file 기동 | `read_from=beginning`: 현재 파일을 backfill. 이미 체크포인트가 있으면 이어 읽음 |
| 새 회전 파일 | 발견 시 처음부터 읽음. `end`로 바꾸면 발견 전 기록된 새 파일 앞부분을 건너뛸 수 있어 사용하지 않음 |
| 원시 회전 | 초기에는 copytruncate를 유지했다. 현재 EVE·audit는 [세대별 writer 종료·두 reader gate](raw-operations/README.md)를 거쳐 별칭을 전환하고 원본을 보존한다. fast/stats/suricata/access 로그는 legacy copytruncate다. timer 활성화와 실제 호스트 재부팅 검증은 상단 상태를 따른다. |
| Suricata ID | UUID 기반 **관측 ID**. disk buffer 안의 재시도에서는 값이 유지되지만 원천 재수집에는 새 ID가 생길 수 있음 |
| nft ID | 센서+cursor 기반 ID. 이 구성에는 영속 중복 제거 테이블이 없으므로 같은 ID 재수신 자체가 차단되지는 않음 |
| message SHA | Vector가 제공한 message 범위. 파일 개행 바이트·전체 원시 파일·binary journal 증명이 아님 |
| disk buffer | ready·quarantine·evidence에 각각 268,435,488 B, 독립3개 설정 합805,306,464 B(약768MiB). full 때 block이며 evidence 지연이 공통 source/ready에도 전파될 수 있음. telemetry는 별도 memory buffer. ACK는 Wazuh 분석 완료 확인이 아님 |
| file sink ACK | OS write 성공 수준. 공식 구현은 fsync 완료를 기다리지 않으므로 전원 장애 시 영속성 보장이 아님 |
| 출력 보존 | ready·evidence·quarantine·telemetry 네 출력 파일을 native logrotate로 회전·압축·보존. ready/evidence 두 로컬 reader의 논리 위치·SHA1을 확인하고 Vector만 일시 정지. 원격 ACK 기반 purge는 아님 |

`max_line_bytes=1 MiB`를 넘는 원시 행은 Vector file source가 버릴 수 있으며 remap 격리에도 도달하지 않는다. 원본 파일은 변경하지 않지만 이는 기존 Python의 정지·원문 보존 체크포인트 정책과 다르다. 입력 누락·source 오류·buffer 사용량·출력 디스크 잔량을 별도 감시해야 한다. 출력 회전·보존·용량 감시는 [STORAGE.md](STORAGE.md)에 기록했다. Vector에는 MemoryHigh384M/MemoryMax512M을 적용하지만 처리량이나 고유 WAF 그룹 수 상한을 보장하는 값은 아니다. 메모리 `dedupe`로 서로 다른 정상 동일내용 이벤트를 합치지 않는다.

## Wazuh 연결과 승격 조건

아래 번호는 최초 연결·승격 시 사용한 순서다. 현재 적용·실측 여부는 이 문서 상단과 [Wazuh 운영 기록](../wazuh-vector/README.md)을 따른다.

1. Vector의 unit test와 실제 소량 원본 샘플 시험에서 정상 필드·KST·격리·원문 비전송을 대조한다. source 파일의 oversize, 회전, 체크포인트 재시작은 unit test가 검증하지 못하므로 별도 실측한다.
2. A의 기존 Wazuh agent에는 **ready와 evidence**를 별도 JSON localfile로 등록했다. quarantine·telemetry는 이 정제 입력에 등록하지 않는다. 최초 evidence는 빈 파일에 reader가 연결된 것을 확인한 뒤 writer를 시작했다. 두 경로 모두 manager의 JSON decoder와 rule 엔진을 거치며 indexer 직송이 아니다.
3. manager에는 `pipeline=vector`, `schema_version=vector-1`인 전용 낮은 레벨 base를 두고 일반 raw 경보와 같은 빈도 카운터에 섞지 않는다. rule ID는 기존 전체 룰셋과 충돌 검사한 뒤 정한다. 처음에는 상관 경보 없이 decode/ingestion만 확인한다.
4. 최초 backfill 완료·agent 전달·중복 조건·processing-time window를 검증한 후 전용 상관 규칙을 활성화한다. 과거 이벤트가 짧은 시간에 몰리는 동안 frequency 경보를 켜지 않는다. `.110/.111` 보호 및 관리자 승인 정책은 기존 제한된 쓰기 MCP/worker에서 유지하며 Vector는 이를 수정하지 않는다.
5. 출력 회전·재처리·전달 실패 재시도에서 중복/누락 허용 범위를 검증하기 전에는 원시 입력을 제거하지 않는다.

Linux 시험 디렉터리에서 수행할 정적/변환 검증 예시:

```sh
export CAPSTONE_SENSOR=groot-sec
export SURICATA_EVE_PATH=/verified/input/eve.json
export WAF_AUDIT_PATH=/verified/input/audit.log
# 추가 WAF_* 값은 검증한 root 배포 manifest로 설정한다(WAF.md 참조).
export VECTOR_DANGEROUSLY_ALLOW_ENV_VAR_INTERPOLATION=true
export INVOCATION_ID=cccccccccccccccccccccccccccccccc # 분리 검증용; 운영은 systemd가 제공
/path/to/vector-0.59.0 validate --no-environment vector.toml
/path/to/vector-0.59.0 test vector.toml tests.toml tests-correlation.toml tests-collection.toml tests-evidence.toml
```

위 main49개와 별도로 WAF61개는 [WAF 문서](WAF.md)의 합성 환경으로 `tests-waf.toml`만 실행한다. `test`는 변환에 고정 fixture를 넣는 시험이므로 실제 원천 reader·journal 권한·Wazuh 전송 확인과 다르다. Mac에는 패키지를 설치하지 않는다. 서비스 설치와 활성화는 상위 고정 Ansible 배포 및 운영 검증 절차가 담당한다.

## 공식 근거

- [Vector file source](https://vector.dev/docs/reference/configuration/sources/file/): 체크포인트·읽기 시작 위치·행 제한·회전 한계.
- [Vector journald source](https://vector.dev/docs/reference/configuration/sources/journald/): kernel match·cursor·부트 범위.
- [Vector 0.59.0 journald 구현](https://github.com/vectordotdev/vector/blob/v0.59.0/src/sources/journald.rs#L346-L350): systemd 250~257에서 all-boots 설정 거절.
- [Vector file sink](https://vector.dev/docs/reference/configuration/sinks/file/): 출력 ACK가 fsync를 보장하지 않는 범위.
- [Vector 환경 변수](https://vector.dev/docs/reference/environment_variables/): 보간 opt-in과 신뢰된 배포 값 요구.
- [Vector remap](https://vector.dev/docs/reference/configuration/transforms/remap/) 및 [native unit tests](https://vector.dev/docs/reference/configuration/unit-tests/).
- [Wazuh JSON 파일 수집](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/monitoring-log-files.html): agent localfile → manager 연결.
