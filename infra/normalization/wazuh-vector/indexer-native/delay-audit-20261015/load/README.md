# 50 EPS · 600초 사적 analysisd 부하 관측

2026-10-15 10:47:43 KST 기준 **B 실제 시험 PASS, 전체642.808초**. 검토와 B 계약16개 통과 후 `EXECUTION_REVIEWED=True`로 활성화한 source `3ca9499f6e4635995843be8db28fd9afdd58c8e370aa065495771d4a5dac72f8`를 실행했다. [실제 결과](validation-2026-10-15.json)는 600초 부하·30,000개 exact archive·4,000개 leaf·drop0·최종 queue0·사적 자식 정리와 운영 전후 불변을 기록한다. 사적 agent000의 한 회차이며 전체 수집 파이프라인/Indexer/agent001/장기 재시작 검증은 아니다.

운영 소스/서비스/원천/체크포인트를 바꾸지 않고 B의 설치 binary·규칙·decoder를 복사한 사적 analysisd 하나에 합성 30,000행을 보냈다. 기존 60초 시험과 구분하여 `analysisd.event_threads=1`, `analysisd.rule_matching_threads=1`, `analysisd.decoder_order_size=1024`를 확인했다. 준비 전/복사 후/종료 후 이 값과 운영 PID·시작시각·queue inode·고정 보호 파일 SHA를 대조했다.

`run-native-b.py`는 기존 [부하 runner](../../../correlation-fix/run-load-b.py)와 [격리 helper](../../../correlation-diagnosis/run-isolated-b.py)의 SHA를 먼저 검증해 메모리에서만 조정한다. 기존 파일은 그대로 보존한다. helper의 mount/network namespace·사적 root·FD/운영 socket 분리 검사와 binary 자원 제한을 재사용한다. 사적 agent `000`이며 WDB/remote/execd/AR를 시작하지 않는다. 운영 logtest session도 호출하지 않는다.

조정은 부하 runner의 EPS/기간, 진행 출력 두 곳(30초), microburst 표기(15행/300ms)와 격리 helper의 읽기 전용 Docker 호출 timeout(8초), 직접 자식 등록 직후 PID 관측뿐이다. 생성 중 보류한 TERM/ALRM/INT는 자식 pre-exec에서 해제한다. 관측은 `waitid(WNOWAIT)`로 자식을 회수하지 않아, 종료 시 PID/start ticks/session/process group을 확인하고 해당 사적 group만 TERM→필요시 KILL→회수할 수 있다. 일반적인 정상 실행에서는 foreground analysisd 하나다. 주 PID만 zombie이고 자식이 남는 경계도 별도 Linux 합성 시험에 포함한다.

## 판정

- 2,000개 독립 그룹 × 15행: repeat 5, cross 2, 동일 key repeat 5, historical negative 3. 양성 leaf는 그룹마다 `100293` 1개와 `100294` 1개, 총 4,000개여야 한다. 잘못된 scenario의 leaf·중복 archive/alert·누락·다른 rule은 실패다.
- 전송 성공을 처리 확인으로 세지 않는다. 30,000행 각각의 archive `full_log` 바이트/그룹/event ID/agent/location을 전수 대조하고 archive leaf와 alert identity의 전체 집합도 일치해야 한다. archive와 alert EOF가 10초 이상 안정되어야 한다.
- 마지막 native state의 received/decoded/processed는 각각 30,000, dropped는 0, 마지막 queue 표본은 모두 0, state age는 8초 이하여야 한다. `events_processed`만으로 최종 규칙/쓰기 성공을 주장하지 않는다. archive/alert 전수 대조가 주 근거다.
- 1초 표본과 실제 native state 갱신(5초)의 max queue/메모리/CPU, 전송→archive 관측 latency, 송신 일정 지연을 보존한다. 0 queue 표본은 표본 사이까지 항상 0이었다는 보장이 아니다. native state counter의 시작/끝/delta와 실제 고유 갱신 수를 함께 남긴다.
- 입력 timestamp는 합성 fixture 생성시각으로 고정된다. 이 시험은 native Wazuh 상관 처리의 수신시각 창을 검사하며, Vector의 event-time freshness·agent001 전송·Indexer/ACK·최대 stats 필드 JSON 처리량을 검증하지 않는다. 현재 1024 옵션으로 같은 canonical workload를 처리하는 시험이다.

10분 1회 성공을 장기 안정성·긴 장애 복구·재시작 영속 중복 방지로 확대하지 않는다. 실제 서비스/호스트 재시작은 없다. 같은 서버의 다른 부하 시험과 겹치지 않게 순차 실행한다.

## 고정 반입과 실행

새 3파일과 다음 6파일을 repo 상대 경로 그대로 root 소유/쓰기 보호 상태로 반입한다. source SHA는 `PINS`에 고정되어 있고 helper는 hash 확인 전에 실행되지 않는다.

```text
wazuh-vector/indexer-native/delay-audit-20261015/load/{run-native-b.py,test_contract.py,README.md}
wazuh-vector/correlation-fix/run-load-b.py
wazuh-vector/correlation-diagnosis/run-isolated-b.py
wazuh-vector/fixtures/correlation/{canary-repeat,canary-cross,canary-repeat-duplicate,canary-historical}.jsonl
```

검토 승인 후 공개 실행 차단만 해제한 최종 SHA를 고정했다. B의 실제 현재 full manager CID를 넘겼다. 출력 경로는 고정 parent 아래 새 `load-*` 한 곳만 허용하며 기존 경로 재사용은 거절한다. 아래 외부 timeout은 실제 실행한 값이다.

```bash
python3 -B /ROOT_SOURCE/wazuh-vector/indexer-native/delay-audit-20261015/load/test_contract.py
timeout --kill-after=40s 700s python3 -B \
  /ROOT_SOURCE/wazuh-vector/indexer-native/delay-audit-20261015/load/run-native-b.py \
  --output /var/tmp/capstone-delay-audit-20261015/load-01 \
  --manager-cid FULL_CURRENT_64_HEX_CID
```

내부 업무 deadline은 675초이며 이후 자식 정리(최대 13초)와 bounded 읽기 postflight를 수행한다. 초안은 외부705초+kill15초였으나 실제 실행은700초+kill40초를 사용했다. 따라서 실제 외부 강제 종료 상한은740초(12분20초)이며, 이번 실행은 그 전에642.808초로 끝났다. 커널의 중단 불가능 I/O까지 정리 완료를 보장하는 표현은 쓰지 않는다. 강제 외부 종료·자식 정리/보호파일 검증 실패는 성공이 아니며, 보존된 `partial-result.json`과 PID 정보를 보고 사람이 확인한다. 불확실 실행을 자동 재시도하지 않는다.

초기 여유 메모리 ≥4GiB/디스크 ≥2GiB/CPU affinity 4개, 실행 중 여유 메모리 ≥2GiB/디스크 ≥512MiB를 요구한다. 이 조건이 맞지 않으면 시작/지속하지 않는다. private native CPU 240초, address space 4GiB, 개별 파일 128MiB, archive incremental reader 120MiB 상한도 그대로 유지한다.

`result.json`은 root 전용 서버 증거이며 status/전수 판정/자식 회수/운영 전후 비교를 함께 확인해야 한다. stdout은 시작/30초 진행/최종 상태·건수만이며 합성 원문과 native 로그는 서버에 남긴다. 운영 파일의 SHA 전후 비교는 명시한 보호 범위에 한정된다. 모든 운영 체크포인트의 SHA를 조사했다는 뜻이 아니다.

## 계약 및 실제 검증

2026-10-15 Mac에서 계약 시험 16개 중 13개 PASS, Linux 전용 자식 정리 3개 skip이었다. 이후 운영자가 B에서16개 전부 PASS(0.334초)를 확인했다. 고정 source drift 거절, 1/1/1024·중복 옵션 거절, 전송만 성공/leaf 누락/drop/state stale 거절, 그룹/음성 입력 구성, 중복 archive·negative leaf 거절을 검사했다. Linux 3개는 정상 leader+child, zombie leader+child, 처음 start ticks 조회 실패 후 등록된 직접 자식의 PPID/PGID/SID를 재확인한 정리이다.

실제 부하 결과는 다음과 같다. 600초 송신 창은15행/300ms이며 마지막 송신은599.700658초, archive 전수 관측 완료는599.999223초였다. 이후 안정 drain10.0초를 포함한 부하 함수 시간은610.033초, 준비/정리 포함 전체는642.808초였다.

| 실제 측정 | 결과 |
| --- | --- |
| 송신 / 원문·identity 전수 일치 archive | 30,000 / 30,000 |
| archive 및 alert leaf | 각각100293=2,000, 100294=2,000 |
| 그룹별 leaf 불일치 / 처리 오류 | 0 / 0 |
| native received / decoded / processed / dropped | 30,000 / 30,000 / 30,000 / 0 |
| 마지막 및 최대 표본 queue usage | 모두0, 연속 무대기 보장은 아님 |
| 고유 native state 갱신 / 관측 표본 | 122 / 609 |
| 마지막 state age | 5.056초 |
| 전송→archive 관측 latency p50 / p95 / p99 / max | 11.101 / 304.988 / 305.595 / 355.351ms |
| 사적 process CPU / 최대 RSS / thread | 21.62초 / 250,060KiB / 44 |
| 최대 송신 일정 지연 | 2.724ms |

전후 운영 identity·명시 보호 파일·옵션 대조가 일치했고, 사적 직접 자식 회수와 살아 있는 해당 process group 구성원0을 확인했다. `cleanup.exit_code=1`은 전수 부하 판정 뒤 `stop_owned`의 TERM 종료·회수 단계에 기록된 native 자식 종료 코드다. `load.errors=[]`, `load_verification_completed=true`인 부하 처리 판정과 구분한다. [종료 로그 확인](termination-2026-10-15.json)에서 private stderr와 ossec.log의 동일 SHA 및10:47:43 KST `INFO (1225): SIGNAL15 … Exit Cleaning`을 확인했으며, 해당 종료 코드를 exit0으로 바꾸지 않고 보존했다.

패키지 설치·운영 입력/체크포인트 쓰기·운영 서비스 재시작·운영 logtest 호출은0이다. 10:48:24 KST [후속 보존·정리](../preservation-2026-10-15.json)에서 사적 자식 정리와 잔여 stage FD 없음, stage 제거를 확인했다. `/var/backups/capstone-delay-audit-20261015/native-runs/load-01`에 logs/state/etc/ruleset/input을 남기고 사적 bin/lib/queue/stats/tmp는 제거했다. 운영 파일 삭제는 없었다. 전체 manifest364파일을 SHA 대조했고, native 보존344경로·235,048,513B는 hardlink별 경로를 합산한 수치로 물리 디스크 사용량이 아니다. 실행 당시 source README는 원형 보존하며 이 최신 문서는 후속 snapshot으로 구분한다.
