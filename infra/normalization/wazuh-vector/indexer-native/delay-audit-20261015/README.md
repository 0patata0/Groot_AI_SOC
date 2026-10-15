# Indexer 지연·평가 공백·중복의 제한 시험

2026-10-15 10:36:09 KST 기준 **B native 시험 PASS(322.292초)**. 로컬11개·AST 및 독립 읽기 검토 뒤 전용 합성 index/disabled monitor에서 시간 경계12개, lifecycle5단계, 실제130초 검색 가시성 지연과180초 평가 공백을 확인했다. [실제 결과](validation-2026-10-15.json)에 각 판정·전후 identity·정리 결과를 보존했다. 기존 운영 v2, Vector, Wazuh 룰과 임계5는 변경하지 않았다. Python은 한 번 종료하는 관리자 시험기이고 상시 상관 엔진이 아니다. 패키지 설치·운영 서비스 재시작은 없었다.

현재 [v2](../window-v2/README.md)는 사건 시각300초, Wazuh 처리 시각360초 후보에서 실제60초 구간을 검사한다. 300초는 사건 폭60초 + 최대 색인 지연120초 + 최대 성공 평가 간격120초라는 조건부다. Vector는 정제 시점에서 이미120초보다 오래된 원천을 historical로 분류해 evidence에 보내지 않는다. 따라서 query 범위만 늘리는 것으로 긴 원천 수집 장애를 복구하지 못한다.

이 시험은 다음 세 범위를 구분한다.

| 범위 | 방법 | 입증하지 않는 것 |
| --- | --- | --- |
| native 시간 경계12개 | 전용2shard index에 합성 시각120/300/1800초 자료 입력, 기존 Painless 실행 | 1800초 실제 장애·대기, 원천→정제 경로 |
| 저장 경보 lifecycle5단계 | 같은 사건 재전송, private receipt에서 새 client 객체로 읽기, identity 충돌로 unavailable, 원래 사건 재등장 | Python/Indexer 프로세스 재시작, host 재부팅, 영구 사건 중복 제거 |
| 선택 `--timed` | 전용 index만 자동 refresh를 끄고130초 비가시성 확인→명시 refresh, 이후 이 시험의 평가를180초 쉬고 재실행 | 운영 Indexer 장애, 생산 monitor scheduler 중단·복구 |

세 독립 서비스마다 고유5건이 양성이고 고유4건과 `A,A,A,A,B`는 음성이다. 같은 사건을 다른 Indexer 문서ID로 다시 넣어도 한 검색의 고유 사건은 늘지 않는다. `event_time_kst`와 `timestamp`를 독립 대조한다. **`timestamp`는 manager 처리 시각이며 Indexer ingest 시각이 아니다.** 실제 검색 가시성은 `_bulk` 접수 뒤 두 `_search`의0건과130초 이후 명시 `_refresh`/15건으로 별도 측정한다.

저장 monitor의 동일 사건은 연속 true 동안 같은 active ID를 유지한다. identity 충돌에서 match=false/unavailable=true가 된 뒤 원래 사건이 다시 유효해지면 새 match episode가 생기는 현재 동작을 검사한다. 이를 영구 중복 방지 성공으로 기록하지 않는다. `fresh_client_readback`은 영속 보관한 소유권 메타데이터로 객체를 새로 구성하는 검사일 뿐, 실제 프로세스 재시작은0이다.

`--timed`의 합성 사건은 최초시점−60초부터 최초시점까지다. 130초 가시성 보류 후에는15건·서비스3개가 일치한다. 이어180초 동안 이 시험의 평가를 쉬면 사건 모두300초창 밖으로 빠져 **보관 문서는15개인데 검색 결과는 valid empty**다. unavailable=false도 예상값이다. 이는 현재 unavailable trigger가 모든 수집/색인 공백을 감시하는 것은 아니라는 제한을 드러낸다. 종료 시각을 과거로 속이거나 production trigger의 stale guard를 풀지 않는다.

## 재사용·안전 범위

고정 SHA의 [기존 native helper](../window-v2/native-verify-b.py)를 바이트 검증 후 메모리 사본으로 import한다. 그 사본의 변경은 세 문자열뿐이다: 소유 index의 `_bulk?refresh=false`/`_refresh` 두 경로 추가, HTTP/process timeout을 유한 실행 예산에 맞춘 값으로 전달. 인증서·CA·호스트명 검증·`curl --disable`·고정 Indexer CID·응답 크기·mutation intent·불확실 응답 재시도 금지·UUID 확인 후 삭제/404 검증은 기존 코드를 재사용한다. 기존 파일은 수정하지 않는다.

- 고정 B machine ID/root, 실행자가 전달한 exact Indexer CID와 현재 named container가 일치해야 첫 mutation에 진입한다. CID/image/PID/StartedAt/RestartCount를 전후 대조한다. Env/로그/운영 문서는 조회하지 않는다.
- 새 index는 `capstone-test-indexer-delay-20261015-<uuid>`이며2shard/replica0다. 저장 monitor는 해당 index만 읽고 disabled/actions[]다. Alerting의 내부 경보 메타데이터는 생기지만 외부 통지·자동 대응은 없다.
- 입력 최대30행(일반 사례), lifecycle의 충돌 포함 최대31행, timed15행이다. 데이터는 문서용 주소·합성 hash이며 보안 원문이 없다. 채점은 원문 없이 count·metric·trigger·경보ID/state로 한다.
- 공개 CLI는 임의 API/대상 index/지연 길이를 받지 않는다. 과거 소스·현재 fixture를 SHA로 확인한 후 실행하며 결과 경로는 exclusive다. 작업410초, 정리 최대55초·전체470초 안의 요청 예산이며 실행자는 외부480초 상한을 둔다. 요청 최대HTTP10초/process12초다. 30초 이하 간격으로 진행 JSON을 출력한다. 시간 초과·부분 응답은 실패로 보존하고 자동 mutation 재호출을 하지 않는다.
- 정리는 고정 owned monitor/UUID의 index만 삭제한다. 응답 불명확·정리 실패면 성공 처리하지 않고 증거를 남긴다. 본 시험이 운영 서비스/PID를 바꾸는 명령은 없다. root의 별도 전후 보호 파일/서비스 확인을 대신하지 않는다.

## 검토 후 실행 형태

source는 이 폴더4파일과 인접 `window-v2/{native-verify-b.py,fixtures.py,monitor.json}` 3파일, 합계7파일이다. 원래 상대 배치를 유지해 root 소유·쓰기 보호로 반입한다. 출력 부모 `/var/tmp/capstone-delay-audit-20261015`만 root:root0700으로 미리 준비하고 새로운 run 경로를 사용한다. 부모가 최종 source manifest를 고정한 뒤 아래 명령으로 실행한다. 최초 로컬 시험은 helper 치환문맥이 두 곳에 걸쳐 안전 거절됐으며, 정확한 `indexpaths` 문맥으로 좁힌 뒤11개 모두 통과했다.

```sh
# 로컬: 기존 Python만, 네트워크/운영 접근/bytecode 생성0
python3 -B infra/normalization/wazuh-vector/indexer-native/delay-audit-20261015/test_contract.py

# B: 검토된 source와 fresh 실제 CID/fixture SHA를 운영자가 고정한다.
/usr/bin/timeout --kill-after=5s 480s /usr/bin/python3 -B \
  /ROOT_REVIEWED_SOURCE/delay-audit-20261015/run-native-b.py \
  --output /var/tmp/capstone-delay-audit-20261015/run-01 \
  --indexer-cid '<정확한64hex>' --fixtures-sha256 '<동결64hex>' --timed
```

입력 원문·last-native-response·mutation ledger는 B root 전용 결과 경로에 보존하고 Mac에는 메타데이터만 반입한다. 새 client readback·130초 가시성·180초 평가 공백 한 회차를 장기부하·1800초 장애·실제 재시작의 근거로 확대하지 않는다. 생산 monitor lookback 확대, historical 재주입, 영속 dedupe/ACK 추가는 이번 변경 대상이 아니다.

## 2026-10-15 실제 결과

10:30:46.731~10:36:09.022 KST, `--timed`를 포함한 한 회차가 322.292초에 통과했다. 시간 경계12개와 저장 경보 lifecycle5단계가 모두 예상값과 일치했다. 고유5건×서비스3개는 양성, 고유4건 및 `A,A,A,A,B`는 음성이었다. 같은 사건의 문서 재전송은 고유 사건을 늘리지 않았지만, unavailable 이후 같은 사건 재등장은 새 episode를 만들었다. 이는 검색 내 중복 제거와 episode 유지의 실증이며 영구 사건 중복 방지 실증이 아니다.

전용 index의 실제 비가시성은130.357초였다. refresh 후15건·repeat 서비스3개가 일치했고, 이어180.243초 동안 이 시험의 평가만 쉬자 보관 문서15건이 그대로 있어도 사건300초 창 밖이 되어 `valid=true`, match=false, unavailable=false가 됐다. 두 평가 모두2/2 shard 성공·실패0이었다. **1800초 사례는 timestamp를 지정한 native 경계 시험이며 실제1800초 장애를 발생시킨 결과가 아니다.** 원천 정제의120초 historical 분류와 Indexer query의300초 사건 창도 서로 다른 단계다.

strict TLS 검증, 동결 helper/fixture 불변, Indexer CID/image/PID/StartedAt/RestartCount 전후 일치를 확인했다. uncertain mutation은0, 정리 실패는0이며 소유 시험 monitor와 index의 삭제/404 검증을 마쳤다. 운영 입력 쓰기·서비스 재시작·생산 monitor 중단·실제 client/Indexer 프로세스 재시작은0이다. [별도10분 부하 시험](load/README.md)은 이 지연 시험과 구분한다.

10:48:24 KST [후속 보존·정리](preservation-2026-10-15.json)를 확인했다. 서버 증거는 `/var/backups/capstone-delay-audit-20261015/native-runs/{run-01,load-01}`에 남겼고 manifest364파일 SHA `014070dd61f4b807a47cd9c9f522514d571f679c78dabeb68f2579c977039aec`를 대조했다. 사적 실행용 복사본/queue 등과 작업 stage를 제거했으며 운영 파일 삭제는 없었다. 실행 당시 source README는 원형으로 보존하고 최신 결과 문서는 후속 snapshot으로 구분한다.
