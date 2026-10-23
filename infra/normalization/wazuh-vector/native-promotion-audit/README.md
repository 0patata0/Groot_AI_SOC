# 상관 경보 승격 전 native 기능 검증 — 2026-10-14

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

**운영 승격을 하지 않는다.** 기존 Vector 0.59.0으로 현재 시각 재평가, `dedupe`, `reduce.flat_unique`를 분리 검증했다. 한 배치의 고유 집계는 가능하지만 캐시 퇴출·프로세스 재시작·배치 경계 이후까지의 고유성과 Wazuh 도착 시점의 신선도를 함께 보장하지 못했다. 기존 Wazuh 43개 시나리오와 합성13행→manager2건→Indexer2건 결과는 [기존 검증](../CORRELATION.md)에 있으며 이번에는 운영 입력·규칙·경보를 변경하지 않았다.

## 실제 설치본에서 확인한 결과

| 합성 시험 | 결과 | 의미 |
|---|---|---|
| 현재 시각 재평가 VRL 8개 | 모두 통과 | 과거·미래 시각, 보호 자산, 품질 오류, 부적합 입력을 그대로 승인하지 않음 |
| stable-key dedupe: A,A,A,A,B | 2개 출력 | 캐시에 남아 있는 동일 사건의 재전송 제거 |
| cache 2개: A,B,C,A | 4개 출력 | 퇴출된 A는 다시 통과함 |
| 별도 프로세스 두 번에 A | 각각 1개 출력 | 캐시는 프로세스 재시작 후 보존되지 않음 |
| event_time=2000년, fresh=true | 0개 출력 | 재평가 지점까지 이미 지연된 행은 제외 가능 |
| 같은 key, 다른 원천 | 2개 출력 | Suricata와 nftables의 서로 다른 관측을 합치지 않음 |
| reduce: A,A,A,A,B | unique=2 | 단일 batch 안의 전체 고유값 집계 가능 |
| reduce: A,B,C,A | unique=3 | 단일 batch에서는 LRU 퇴출 문제와 무관 |
| max_events=5, A~E를 두 번 입력 | unique=5인 summary 2개 | batch flush 뒤 같은 집합을 다시 집계함 |

총 **VRL 8개 + 실제 stdin 8개**를 통과했다. cache 2와 batch 5는 작은 입력으로 경계 동작을 재현하기 위한 시험 값이며 운영 추천값이 아니다. 두 설정 모두 합성 stdin만 읽고 stdout으로만 출력한다. 실제 file/journal/agent/manager/Indexer 입력은 읽거나 쓰지 않는다.

## 승격 전에 남는 조건

1. 동일 원천 사건의 안정 ID와 상관 시간창을 기준으로, 재전송·캐시 퇴출·재시작·batch flush 후에도 이미 센 사건을 다시 세지 않는 계약이 필요하다. 현재 `dedupe`의 캐시 확대나 TTL만으로 이를 증명하지 못했다. `reduce.flat_unique`는 batch 내부의 정확한 집합이며 영속 전체 집합이 아니다.
2. 최종 경보 결정 지점에서 event_time을 현재 시각과 다시 비교해야 한다. 이 후보 `freshness.vrl` 뒤에서 파일·agent queue·전송이 지연되면 이전의 true 필드는 자동으로 만료되지 않는다. Wazuh `timeframe`/`time`은 수신 처리시각을 사용하므로 기존 XML의 등급만 높여 해결할 수 없다.
3. 상태 유실·한도 초과·재시작 때는 정상으로 추정하여 경보를 승격하지 않는 복구/보류 조건과 검증이 필요하다. 누락을 피하려고 같은 입력을 다시 세는 동작과, 중복을 피하려고 입력을 버리는 동작의 차이를 명시해야 한다.
4. 위 조건을 만족한 이후에만 기존 raw 경보와 중복, 보호 대상 제외, 정상 장기 입력, 실제 채팅 전달 범위를 별도로 확인한다. 이번에는 no_log 해제·고레벨 합성 경보·채팅 게시·차단 요청을 하지 않았다.

새 Python 상시서비스, 새 Indexer 수집 경로 또는 monitor를 추가하지 않았다. 그런 경로는 이번 native 검증의 완료 조건으로 간주하지 않으며 별도 설계 범위다.

## 재현

설치된 서버에서 이 폴더만 별도 임시 경로에 복사하고 실행한다. Mac에 Vector를 설치하지 않는다.

```sh
/bin/bash run-audit.sh
```

`run-audit.sh`는 설치 버전을 확인하고 `/var/tmp/capstone-correlation-audit.*` 하나를 만든 뒤 종료 시 제거한다. Vector의 임시 data_dir를 고정하고 각 프로세스에 15초 제한을 둔다. 서비스 설치·재시작, 운영 설정 include, 네트워크 sink를 제공하지 않는다. `freshness.vrl`은 신선도 경계를 실증하는 후보이며 기존 정제의 전체 schema/원천 검증을 대신하는 배포용 검증기가 아니다.

## 근거

- [Vector dedupe](https://vector.dev/docs/reference/configuration/transforms/dedupe/): 최근 사건의 메모리 LRU 캐시와 시간 만료 설정. 실제 0.59.0 퇴출·재시작 동작은 위 stdin 시험으로 확인했다.
- [Vector reduce](https://vector.dev/docs/reference/configuration/transforms/reduce/): `flat_unique`, `max_events`, 만료·주기 flush의 범위. 고유 집합은 현재 group의 batch 단위다.
- [Wazuh 규칙 문법](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html): `different_field`와 서버 시각 조건.
- [Wazuh 4.14.8 eventinfo.c](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/eventinfo.c#L124-L145): `timeframe`을 현재 처리 시각과 사건의 생성 시각 차이로 검사.
