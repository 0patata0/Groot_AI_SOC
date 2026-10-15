# Vector 정제 이벤트의 Wazuh 상관 검증

## 2026-10-14 19:38 KST 후속 — Indexer 시간 경계 보완 반영

Imperva/언어가드 기존로그 점검을마치고, 같은Indexer모니터를300초후보·정확60초sliding v2로갱신했다. native검색41개·lifecycle4단계·응답guard66개를통과했으며ID/권한/actions0·서비스/기존Wazuh룰은유지한다. 현재관리명령/검증/복구는 [v2운영안내](indexer-native/window-v2/OPERATIONS.md)를따른다. 자연스캔·최근Hermes사용표본은없어효과관찰대기다. 다음은WAF두reader회전격리→인증서관리이고장기지연/영속복구/정확히1회는별도다. 아래내용은각시점의기록이다.

## 운영 분석기 1/1 적용·실제 20회 종단 검증 완료 (2026-10-14 18:56 KST)

B의 `analysisd.event_threads=1`, `analysisd.rule_matching_threads=1`을 18:48:55 KST에 적용하고 **같은 manager 컨테이너를 한 번 재시작**했다. 기존 native 규칙 104개를 적용 전후 각각 통과했으며, 18:49:04의 새 analysisd PID는 `2132985`, 전체 스레드는 44개다. 다른 컨테이너와 보호 해시는 유지됐다. canary 없는 60.000186초 운영 관찰에서 수신 60건(약 1 EPS), drop 증가 0, queue 최대 표본 0, 단일 코어 대비 CPU 약 0.0333%를 확인했다. [적용·관찰 증거](correlation-fix/deployment-resume-2026-10-14.json).

사용자 명시 승인 후 실제 A agent001→B manager→Indexer의 **20회 × 13행(260행)** 시험을 18:56:08 KST에 완료했다. 동일 20개 run ID를 각각 한 번만 입력해 **manager 40건/Indexer 40건**, `100293` 20건·`100294` 20건, level 3·negative 경보 0건을 확인했다. 57/57 shard·strict CA/호스트명·각 run 및 전체 canonical tuple이 일치했으며 첫 조회 회차 11.3초, 입력 재시도 0회였다. A 원래 52행 접두 구간·inode·보호 설정과 B 옵션·룰·CID·SOC 안전 조건을 보존했다. 이 결과는 승인된 20회 시험의 성공이며 일반 트래픽의 장기 무손실 보장은 아니다. 기존 격리 1/1은 경보 4,000/4,000을 생성했지만 500 EPS 부하에서 queue 최대 표본 24%·최대 archive 관측 지연 약 10.04초가 있어 지속 처리량 보장은 아니다. [격리 부하와 한계](correlation-fix/LOAD-VALIDATION.md). 기존 실공격 상관의 `no_log`, 별도 evidence 및 actions 없는 Indexer monitor 정책은 유지한다. 아래의 미배포·반입 대기 설명은 이전 시점 기록이다.


**2026-10-14 18:18 KST 후속:** 검증기 고정ID 가정을 수정해47개 합성 및 기존 회차 대조를 통과했다. 각30,000행 격리 부하에서 worker1/1은 상관4,000건 전부 생성했고 자동설정은1,362건이었다(양쪽 입력drop0). 1/1은500EPS 시험 중queue최대표본24%·최대관측지연10.04초가 있어 지속처리량 보장과 구분한다. 운영 두옵션 변경안은 준비했지만 배포 검증94파일의B 반입이 자동 승인 검토에서 거절되어 사용자 전송 승인 대기다. 운영옵션/규칙/서비스 변경과 실제001 새burst는 아직 없다. [보완·검증·남은 적용](correlation-fix/README.md). 아래는 이전 기록이다.

**2026-10-14 13:12 KST 상관 누락 조사:** 격리한 실제 Wazuh의 사전 logtest 없는 자동 설정 20회에서 100293 누락 8회·100294 누락 7회를 재현했다(중복 2회). 1/1 작업자 대조 20회는 정상이며, 40회×13행의 archives 원문과 최종 판정/alerts를 전수 대조했다. 병렬 판정의 순서 경쟁이 유력하지만 agent 000 직접 큐 시험이므로 과거 운영 001의 세부 원인 확정·운영 누락률·완전 해결로 확대하지 않는다. 검증기의 반복 경보 eventID0005 고정 가정도 별도 문제로 확인했다. 다음은 그 검증기 보완과 판정 병렬도 후보의 부하 검증이며, 운영 설정·규칙·서비스는 유지했다. [근거·실측·후속](correlation-diagnosis/README.md). 아래는 이전 기록이다.

**2026-10-14 12:00 KST 추가 검증:** 새 합성13행 일괄 입력은 manager1건/Indexer1건으로 기대2건에 미달했다. 같은 자료의 격리 분석8종은 통과했고, 첫6행과 후행7행 사이3초를 둔 새 시험은 manager2건/Indexer2건·정확ID·57/57shard 성공을 확인했다. 원인 미확정인 첫 실패도 보존한다. writer의 간격은 진단용이며 분석 ACK가 아니다. `tests/verify-canary-b.sh`는 이제 CA·호스트명, 전체 shard, 정확 건수·agent·location·ID를 검사하는 단일 읽기 조회기에 연결한다. 기존 인증서 검증 우회·부분 검색 성공 판정은 사용하지 않는다. 최근 시험은 색인 지연 후 같은 run을 다시 조회할 수 있으나, 새 입력을 자동 생성하지 않는다. [결과와 한계](history-replay-b/README.md).

**2026-10-14 06:09 KST 추가 적용:** 아래 Wazuh no_log 상관은 그대로 유지하며 별도 evidence 경로와100260~100262를 추가했다. 자연 Suricata1건의 manager/Indexer 종단 일치를 확인했고 두 reader 회전도 성공했다. `SPOOF/observed`는 nft leaf의 `logged_drop` 조건 때문에 제외한다. [운영 배포 결과](evidence-deployment-2026-10-14.json), [입력·보존 경계](../vector/EVIDENCE.md), [Indexer 관측 모니터](indexer-native/README.md)를 따른다. 아래 마지막 절의 monitor/evidence 미적용 설명은 후보 검토 당시 이력이다.

2026-10-14 KST에 A/B에 적용하고 합성 canary의 manager·Indexer 종단 검증을 완료했다. **운영 입력의 신규 상관 규칙은 모두 `no_log`이며 기존 원시 경보·차단 규칙과 합치지 않는다.** 실제 확인 수치와 실패 후 정정은 [후속 검증 JSON](correlation-validation-2026-10-14.json)에 기록한다.

## 입력 계약과 범위

기존 기초 규칙 `100200`은 JSON decoder, `pipeline=vector`, `schema_version=vector-1`, `source=suricata|nftables|modsecurity`, `(groot-sec) any->/var/log/capstone-vector/ready/normalized.jsonl`의 정확한 규칙 location을 요구한다. 새 `100201`은 `groot-sec` 센서, TCP/UDP, 정상 64자리 상관 키, `correlation_eligible=true`, `correlation_time_class=fresh`, `protected_asset=false`를 추가로 요구한다. 원문 Suricata/커널 로그에는 이 전용 필드와 location이 없으므로 기존 `local_rules.xml` 경로에서 처리한다. WAF는 기초 `100200`에서 수용하지만 반복·장비 간 상관 분기에는 포함하지 않는다.

Vector가 추가하는 필드:

| 필드 | 계약 |
|---|---|
| `correlation_time_class` | 원천 시각과 정제 관측 시각의 차이가 -5~120초면 `fresh`, 오래되면 `historical`, 미래면 `future` |
| `correlation_eligible` | fresh이고 주소·포트·TCP/UDP가 유효하며 품질 플래그가 없고 보호 자산이 아닐 때 true |
| `correlation_key` | `[sensor, source_ip, destination_ip, destination_port, protocol]`의 JSON SHA-256. 패킷 방향을 그대로 구분하며 응답 방향을 요청 방향으로 추정하지 않음 |
| `correlation_dedupe_key` | Suricata는 센서·원천·message SHA에서, nftables는 journal cursor의 기존 event ID에서 파생 |

패킷 방향과 동일 서비스 tuple의 일치는 공격 인과관계나 사용자의 동일성을 증명하지 않는다. NAT 전후 주소가 다르면 이 규칙은 묶지 않는다. 양 장비 로그가 같은 A agent에서 들어오는 현재 배치를 대상으로 하며 `global_frequency`를 켜지 않는다.

## 규칙

| ID | 동작 | 기록 정책 |
|---|---|---|
| 100200 | 기존 정제 입력 기초 | level 1, no_log |
| 100201 | fresh·품질·보호 자산·상관 키 경계 | level 1, no_log |
| 100210 / 100211 | Suricata 관측 / nftables logged_drop | level 1, no_log |
| 100220 / 100221 | 동일 방향·서비스의 같은 원천 반복, 5회/60초 후보 | level 2, no_log |
| 100230 / 100231 | 같은 tuple의 Suricata→nftables / 역순, 60초 후보 | level 2, no_log |
| 100290 / 100291 / 100292 | 독립 합성 canary 기초 및 원천 분기 | level 1, no_log |
| 100293 / 100294 | 합성 canary 반복 / 장비 간 상관 | level 3, no_email_alert, no_full_log |
| 100240 | native 저장 관리 program/location 기초 및 성공 상태 | level 0, no_log |
| 100241 | 저장 여유 공간 부족 | level 3, ignore 900초 |
| 100242~100245 | 공간 임계·Vector 중지·회전 실패·읽기 위치 확인 실패 | level 5, ignore 900초 |

실제 설치본의 빈도·분기 결과는 `tests/test-correlation-manager.sh`의 순서별 ID 검증으로 확정한다. `fixtures/correlation/`에는 문서용 IP만 들어 있다. 각 시나리오는 새 logtest 세션에서 실행하므로 시나리오 간 카운터를 공유하지 않는다.

저장 상태 규칙은 정제 공격 상관과 별개다. A에 이미 있는 journald 수집기가 native syslog 형식으로 전달하는 `program_name=capstone-vector-storage`, `location=(groot-sec) any->journald`, 정확한 `status=...` 메시지만 검사한다. 정상 성공 상태는 기록하지 않고 실제 상태 이상만 색인 가능한 등급으로 기록한다. 같은 규칙의 반복은 15분간 제한하며, 원격 수신 실패에 대한 알림 보장은 별도다. `tests/test-health-manager.sh`는 10개 합성 logtest만 실행하며 실제 `logger`/journal/alert queue에 경고를 주입하지 않는다.

## 실제 transport location 정정

첫 종단 시도에서 열린 canary 파일에 합성 13행을 추가했으나 manager·Indexer는 0건이었다. agent는 연결 상태이고 native checkpoint도 파일 끝과 일치했다. 원인은 직접 logtest에만 맞춘 `^/path$` 조건이었다. Wazuh 4.14.8은 등록 agent에서 받은 사건의 규칙 검사 location을 `(groot-sec) any->/path`로 보존한다. JSON alert의 location은 경로만 보여 이 차이를 최초 기초 검증에서 놓쳤다.

현재 규칙과 native fixture는 **`(groot-sec) any->` 고정 prefix와 정확한 파일 경로**를 요구한다. 다른 등록 agent와 prefix 없는 로컬 입력은 거절하며, canary 경로는 운영 기초의 허용 범위에 포함하지 않는다. 등록 이름·주소 바인딩이 바뀌면 검토 후 규칙도 함께 갱신해야 한다. Wazuh 자체 XML 파서는 `&gt;`를 정규식용 `>`로 풀지 않으므로 텍스트에 유효한 literal `->`를 사용한다. entity로 작성한 첫 수정은 native 검사에서 실패하여 Ansible이 원래 전용 파일로 rollback하고 필수 서비스를 복구했다.

## 시간과 중복의 한계

Wazuh 4.14.8의 `timeframe`은 `current_time - generate_time`으로 검사한다. JSON `event_time_kst`를 event-time window로 사용하지 않는다. 따라서 원천 시각이 오래되어도 `fresh`라는 필드를 잘못 붙인 입력은 상관될 수 있다. `processing-time-only` 시나리오는 이 한계를 숨기지 않고 확인한다. `historical`/`future`는 전용 기초까지 남고 상관 재료에서 제외된다. **Vector 정제 이후의 큐·전송 지연이나 fresh 행의 재전송까지 이 분류만으로 재평가하지 못한다.**

`different_field`는 현재 이벤트의 값과 이전 값들을 비교하는 기능이다. 이전 이벤트들끼리 모두 다른지 확인하는 고유 집계가 아니다. 같은 ID를 다섯 번 보낸 경우는 제외되지만, A를 네 번 보낸 뒤 B를 보내면 반복 후보가 발생할 수 있다. `duplicate-history-limitation`은 그 차이를 검증한다. Suricata 원문 재수집 시 새로운 관측 UUID가 만들어지는 점을 보완하려고 별도 안정 키를 사용하지만, 이것만으로 전달의 exactly-once를 보장하지 않는다. 이 한계 때문에 운영 상관 결과는 계속 `no_log`로 유지한다.

## 별도 합성 canary와 종단 확인

시험 입력은 `/var/log/capstone-vector/canary/normalized.jsonl`의 root 관리 전용 파일이다. 이 위치는 운영 `100200`의 허용 범위에 추가하지 않는다. 독립 `100290`에서 JSON/pipeline/schema/source 외에 `sensor=capstone-canary`, `kind=correlation-e2e`, 32자리 hex run ID, `192.0.2.40 → 198.51.100.20:8443/tcp`, fresh와 상관 키를 모두 요구한다. 운영 ready/원시 로그에는 합성 행을 쓰지 않는다. 주기 생성기·LLM 실행 도구·네트워크 공격·알림 전송 기능은 추가하지 않는다.

실행 전 실제 알림 통합·Active Response 조건을 확인한다. 승인된 시험에서만 별도 localfile을 연결하고, 파일이 열린 후 합성 행을 쓴다. manager alert의 canary rule ID와 run ID, indexer 문서의 같은 값을 대조해야 종단 성공으로 기록한다. 단순 agent FD, logtest 매칭, 파일 쓰기 성공은 indexer 반영을 대신하지 않는다. 시험 결과에는 합성 ID·건수·시각만 남기고 자격증명과 운영 로그 원문은 출력하지 않는다.

고정 A 플레이북이 canary 디렉터리 `root:root 0700`과 파일 `0600`을 절단 없이 준비하고 기존 agent 입력 블록에 추가한다. 임의 실행은 제공하지 않으며 운영자가 기존 경계를 확인한 후만 다음 수동 시험을 사용한다. 같은 run ID의 재사용과 파일 10MiB 초과는 거절한다. 테스트 데이터는 자동 삭제하지 않는다.

```sh
# A: 새로운 32자리 hex run ID를 정한 후 합성 13행만 추가한다.
/bin/bash tests/write-canary-a.sh <run-id>
# B: 같은 run ID의 manager 2건과 indexer 2건 및 사건 ID 일치를 읽기 전용으로 확인한다.
/bin/bash tests/verify-canary-b.sh <run-id>
```

2026-10-14 읽기 전용 확인에서 B는 `log_alert_level=3`, `email_alert_level=12`, Active Response·integration 설정 0개였으며, 실제 SOC bot의 기본 조회/집계 최소 등급은 5, monitor 기본값은 10이었다. 이는 해당 시점의 확인이며 수동 시험 전 재확인할 조건이다. 합성 canary는 level 3이며 자동 차단 또는 실제 채팅 전송을 요청하지 않는다.

## 라이브 검증 결과

- B 설치본 Wazuh 4.14.8에서 base 9개, 상관 24개 시나리오/76행, health 10개를 적용 전후 통과했다. ModSecurity의 정상 정제 입력은 100200/no_log로 수용하며 공격 상관 분기를 추가하지 않았다.
- 새 run `1507d4e26aa74ca590aae9ea9c4f187d`의 합성 13행에서 100293·100294가 각 1건씩, 모두 level 3으로 manager와 Indexer에 기록됐다. 같은 event ID가 양쪽에 남았다. 동일 ID 반복 5행과 과거 1행은 추가 경보를 만들지 않았다.
- 첫 run `4c42cf8b95214c2896efe153d254616f`은 잘못된 location 경계 때문에 0건이었다. 시험을 성공으로 간주하거나 같은 run을 재주입하지 않았다.
- A의 세 번째 apply와 B의 최종 재적용은 모두 `changed=0`이었고 agent PID/start 및 manager ID/StartedAt이 유지됐다. A의 두 번째 apply는 후보 사본만 한 번 갱신했으며 운영 변경·재시작은 없었다.
- A의 raw localfile 8개, B의 기존 local_rules.xml, 두 서버의 승인 helper·sudoers·worker 파일과 권한을 유지했다. 수동 시험용 root 전용 입력만 추가했다.
- 실제 공격·고레벨 시험 경보·채팅·차단 요청은 만들지 않았다. 저장 상태 10개 시험은 logtest에서만 실행했으므로 실제 health 경보의 종단 전달까지 증명한 것은 아니다.
- 운영 상관은 계속 no_log이므로 이 시험은 운영 공격 상관 경보의 활성화, 원시 패킷→Vector 변환의 종단 보장, exactly-once 전달 또는 event-time 처리 보장이 아니다.

## 공식 근거

- [Wazuh 규칙 문법](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html): frequency, same_field/different_field, no_log와 level 0의 제약.
- [4.14.8 eventinfo.c](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/eventinfo.c): 처리 시각 창, 동적 필드 비교, 같은 agent 범위.
- [4.14.8 analysisd.c](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/analysisd.c): no_log와 별도로 Active Response 실행 분기가 존재하므로 로그 비기록만으로 차단 불가를 가정하지 않음.
- [4.14.8 logcollector.c](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/logcollector.c): 새 wildcard 파일도 저장 위치가 없으면 EOF부터 시작할 수 있어 일반 파일 회전과 별도 검증해야 함.

- [4.14.8 remoted/secure.c](https://github.com/wazuh/wazuh/blob/v4.14.8/src/remoted/secure.c#L863-L885): agent ID·등록 이름·등록 주소를 transport location에 넣음.
- [4.14.8 cleanevent.c](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/cleanevent.c#L502-L549): ID를 분리한 뒤 이름·주소 prefix를 규칙 검사 location에 보존.

## 2026-10-14 후속: 경보 승격 조건의 native 재검증

[분리된 native 기능 검증](native-promotion-audit/README.md)에서 Vector 0.59.0 VRL8개·stdin8개를 통과했다. dedupe는 캐시 안의 중복을 제거하고 reduce는 batch 안의 전체 고유값을 세지만, 퇴출·재시작·batch 경계 뒤 재집계까지 막지 못했다. 현재 시각 gate는 그 지점까지 늦어진 행을 제외하지만 이후 agent/Wazuh 대기 지연을 재평가하지 못한다. 이 결과로 운영 상관을 승격하지 않으며 기존 no_log와 raw 경보를 유지한다. 새 Python 서비스·수집 경로·monitor·채팅 게시·차단을 추가하지 않았다.

이후 [기존 Indexer의 읽기 검증](indexer-native/README.md)에서 OpenSearch 2.19.6/Alerting 2.19.6.0, keyword 사건 시각의 최종 조회시각 재평가, exact terms 고유값 집계가 동작함을 확인했다. 기존 canary 2건은 현재 120초 범위에서 0건으로 제외됐다. raw Suricata는 보호주소를 제외한 24시간 진단 31문서에서 내용별 집계가 가능했지만 원문 누락과 비용 때문에 운영 권장 경로로 선택하지 않았다. 운영 no_log를 일괄 해제하지 않고 별도 evidence location과 100260대 leaf level 3, stable key·짧은 event-time 조회, actions 없는 native monitor 관찰로 이어가는 최소 후보를 문서화했다. 실제 evidence 입력·monitor·매핑·경보는 변경하지 않았다.
