# Indexer 사건 시각 60초창 후보 v2

## 현재 상태 — 운영 반영 완료 (2026-10-14 19:40 KST)

같은 운영 모니터에 v2를 반영했고 ID·권한·활성 상태·주기를 보존했다. native 검색41개/수명주기4단계/guard66개 및 변경 후 정기실행2회·실제57shard 검색을 확인했다. [배포 증거](deployment-2026-10-14.json)와 [현재 관리·복구 절차](OPERATIONS.md)를 사용한다. Python은 일회성 생성·시험·운영 관리용이며 상관 판정은 native Painless가 담당한다. 아래는 후보를 작성·동결한 시점의 계약과 검증 준비 기록이다.

이 폴더는 기존 `capstone-evidence-observation-v1` 모니터를 갱신하기 위한 **기본 비활성 후보**다. 상위 v1 파일과 현재 운영 모니터는 이 후보 생성 작업에서 변경하지 않았다. 이름·trigger ID·1분 주기·`actions: []`·agent/location/producer marker/장비별 leaf·보호주소 제외 조건은 보존한다. Python은 후보 생성과 합성 시험 자료 생성에만 사용하며 상시 상관 엔진이나 새 서비스를 추가하지 않는다.

후보 [monitor.json](monitor.json) SHA-256은 `acc8ac9649cc8b974872a30cf4bcc8f2e52adf0caf56ed197e8b95066d657c7f`다. 작성 단계에서는 오프라인 계약 검사 **9개**만 통과했다. [41개 native 시험 자료 목록](fixture-manifest.json)은 기대값이며 실제 OpenSearch 실행 결과가 아니다. Painless 컴파일·실제 여러 shard·10,000건 경계·부하·scheduler lifecycle 검증과 운영 CAS 갱신은 별도 절차다.

## 사건 창과 중복의 의미

검색 후보는 평가 시각 `T=period_end`의 사건 시각 **[T−300초,T]**, 처리 시각 `timestamp`의 **[실제 조회 now−360초,now+5초]**다. 최근 300초에 5건이 있다는 이유만으로 일치시키지 않는다. 같은 `correlation_key` 서비스의 사건을 시각순으로 정렬하고, **어떤 연속 60초 구간 안에서** 아래 중 하나가 성립할 때 관찰 일치다.

- 같은 source의 고유 `(source, correlation_dedupe_key)`가 5개 이상이다.
- Suricata와 nftables 관측이 각각 하나 이상이다. 두 장비가 같은 패킷을 관측했다는 주장은 아니다.

동일 `(source,key)`·동일 사건 시각·동일 서비스 재전송은 한 사건으로 센다. 같은 `(source,key)`의 시각 또는 서비스가 다르면 어느 하나를 선택하지 않고 전체 결과를 `identity_conflict`로 보류한다. 다른 source의 같은 key는 별도 identity다. 이벤트 ID/원문을 재작성하지 않고, query에서 기존 64hex event/message/key 필드와 출처 조건을 유지한다.

사건 시각은 정수 **마이크로초**로 계산한다. 59.999999초와 정확히 60.000000초는 포함하고 60.000001초는 제외한다. 밀리초 절삭은 사용하지 않는다. `Instant.nano % 1000 != 0`인 나노초 입력은 정확히 표현할 수 없는 입력으로 query에서 제외하며 map도 다시 거절한다. 이는 입력 정밀도 계약이며 자동 반올림이 아니다. 처리 시각 date와 `period_end`의 밀리초 해상도는 사건 간 거리 계산의 마이크로초 해상도와 구분한다.

300초는 **60초 사건 폭 + 최대 120초 사건→색인 지연 + 최대 120초 성공 평가 간격**을 가정한 조건부 보존 범위다. 마지막 사건을 `L`이라 하면 모든 사건이 `L+120초`까지 색인되고 이후 120초 안에 성공 평가할 때, 최초 사건 `L−60초`까지 후보 범위에 남는다. 이 지연·간격 조건을 이번 코드가 보장하거나 SLA로 측정한 것은 아니다. 장기 장애 후 회복, 120초를 넘는 색인 지연, 원천 유실·upstream fresh 제외, 시계 오류까지 복구하는 기능은 없다. 처리 시각 창은 선행 사건의 조기 색인과 평가 지연 여유를 남기기 위해 별도로 360초다.

## native 집계와 실패 경계

OpenSearch [`scripted_metric`](https://docs.opensearch.org/2.19/aggregations/metric/scripted-metric/)의 init/map/combine/reduce를 사용한다. map은 사건 시각·source·stable key·서비스 key만 저장한다. combine은 shard별 자료를 전달하고, reduce는 shard를 합쳐 identity 충돌과 한도를 확인한 뒤 서비스별 정렬·sliding window를 수행한다. 정렬 뒤 순회는 선형이며 모든 사건 쌍을 비교하지 않는다.

- shard별 map/combine은 최대 10,000문서·100서비스를 보관한다. reduce도 총 10,000문서·100서비스를 넘으면 판정하지 않는다. 10,001번째 문서 및 101번째 서비스는 정상 빈 결과와 구별된다.
- 동일 key 재전송도 검색 문서 수 한도에 포함된다. 고유 사건이 하나여도 10,001문서면 보류한다. 서비스 key 형식 검사는 처음 본 서비스에만 반복하여, 10,000행에 대해 동일 64자리 검사를 불필요하게 반복하지 않는다. 실제 Painless 실행 한도·속도는 native 검증 대상이다.
- 성공 shard 최대 64, exact hits total `eq`, timeout/부분 shard 실패/조기 종료 없음, 집계 documents와 hits total 일치를 모두 요구한다. empty/null shard는 빈 입력으로 취급하되 최종 합계가 맞아야 한다.
- 기존 `size=0`, `_source=false`, 10초 검색 timeout과 shard별 `terminate_after=10001`을 유지한다. 검색 필터가 제외한 무효 입력은 집계에 들어오지 않는다. 집계에 들어온 자료의 충돌·잘못된 중간 상태·한도 초과는 `valid=false`다.
- shard별 한도와 reduce 이후 전체 한도는 **전역 사전 메모리/CPU 한도가 아니다**. 최대 64개 shard가 각각 제한 안의 중간 자료를 만들어 전송할 수 있고, 검색 자체와 집계 전송 비용은 먼저 발생한다. 10,000을 실측 처리량이나 장기 무누락 보장으로 읽지 않는다.

최종 응답 `aggregations.observation.value`는 12개 필드만 반환한다. `policy`, `precision`, `valid`, 고정 `reason`, `match`와 `documents`, `unique_events`, `duplicate_documents`, `services`, `matched_services`, `repeat_services`, `cross_source_services`다. 원문·시각 목록·서비스/사건 key 목록은 반환하지 않는다. 무효 결과는 `valid=false`, `match=false`, 건수 `-1`이며 정상 empty의 `valid=true`, 건수 `0`과 다르다. trigger 공통 검증은 같은 소스를 내장하고 무효·stale 평가·합계 불일치를 `observation_unavailable`로 처리한다.

필수 docvalue가 하나인지는 확인하지만 원래 JSON scalar 타입을 증명하지 않는다. 같은 값이 반복된 keyword 배열은 한 docvalue로 보일 수 있다. 원본 타입·빈 quality 배열은 기존 root 관리 Vector 분기와 정확 Wazuh evidence leaf를 신뢰하는 경계를 그대로 유지한다. producer 계약 밖의 입력을 이 후보가 임의로 신뢰하는 것은 아니다.

## alert episode와 관찰 범위

기존 query-level 두 trigger ID를 유지한다. 같은 trigger가 계속 true인 동안에는 하나의 active episode가 유지되고, false가 되면 완료되며, 이후 true가 되면 새 episode가 생기는 native lifecycle을 따른다. 300초 겹침 조회로 같은 사건이 연속 평가에 포함될 수 있다. 이 구조는 서비스별 영구 dedup/cooldown 또는 전역 exactly-once가 아니다. 한 서비스의 일치가 계속되는 동안 다른 서비스가 새로 일치해도 같은 query trigger의 active episode에 포함될 수 있다. action은 비어 있어 채팅·차단·외부 통지를 수행하지 않는다. [OpenSearch query/bucket monitor 구분](https://docs.opensearch.org/2.19/observing-your-data/alerting/per-query-bucket-monitors/).

## 재현과 시험

Mac의 기존 Python만 사용하며 설치·bytecode 생성 없이 실행한다.

```sh
python3 -B build.py --check
python3 -B test_contract.py
# 검토한 .painless를 수정했을 때 이 폴더의 생성물만 다시 작성
python3 -B build.py --write
```

`build.py`는 상위 v1 monitor의 고정 SHA를 먼저 확인한다. 시간 범위·scripted_metric·두 condition source 외의 query/provenance/trigger 설정이 바뀌지 않는지를 오프라인 검사한다. 작은 합성 사례는 구현의 sorted sliding과 다른 endpoint 열거 oracle로 기대값을 대조한다. [오프라인 검증 메타데이터](offline-validation.json)를 참고한다.

`fixtures.py.cases(period_end_ms)`는 한 번에 한 case를 생성하는 generator다. 각 결과는 `name`, `documents`, `expected`(최종 metric의 비교할 필드), 선택적 `query_excluded`다. 문서에는 테스트 주소·합성 hash와 Wazuh 형태의 필드만 있으며 원문은 없다. 실제 native 시험은 별도 테스트 index에만 입력하고 candidate의 index 이름과 실행 시각 치환만 바꾼다. date detection을 끄고 `timestamp`는 date, 정제 동적 필드는 keyword로 고정해 생산 매핑과 대조해야 한다. 각 case 전에 격리 index를 비우고 refresh하여 직전 자료가 섞이지 않게 한다.

native 필수 범위는 다음과 같다.

- 41개 자료의 정확 결과: 240초에 퍼진 5건의 비일치, 과거에 완성된 60초 구간, 지연된 장비 간 동반 사건, 도착 순서 역전, µs 경계, identity 충돌, 출처·보호주소·미래/과거 입력 제외, 100/101서비스와 10,000/10,001문서.
- 실제 여러 shard에서 동일 사건 중복·identity 충돌·source가 나뉘어도 전역 결과가 같음. empty index/null shard가 정상 empty이고 shard 순서에 의존하지 않음.
- 동일 trigger 공통 validator의 합성 context로 failed/부분/65shards, stale/future periodEnd, 잘못된 total·metric/count·valid/overflow를 보류함.
- 반복 true→false→다시 true에서 native query-level episode의 상태 전이. 저장/실행은 운영자 승인된 별도 비활성 테스트 모니터만 사용하고 actions는 계속 비움.

시험이 통과하기 전 이 후보를 운영 모니터로 활성화하지 않는다. 실제 갱신은 기존 모니터 ID·본문·revision을 확인한 CAS 단계여야 하며 같은 이름의 모니터를 추가 생성하지 않는다. 이번 폴더에 자동 배포·루프·서비스·LLM 권한을 넣지 않았다.
