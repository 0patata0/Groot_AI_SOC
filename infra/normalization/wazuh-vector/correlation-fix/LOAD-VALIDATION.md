# 분석기 1/1 후보의 격리 부하 검증

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

2026-10-14 18:17:32 KST 완료. B에 설치된 Wazuh 4.14.8의 독립 복사본에서 **1/1 설정은 2,000그룹의 기대 상관 경보 4,000개를 모두 생성했다.** 같은 30,000행을 받은 자동 설정은 1,362개만 생성했다. 양쪽 모두 입력·디코딩·처리·원문 보관 30,000개, native drop 0이었다. 입력 유실과 판정 누락을 구분하는 시험이며 운영 설정을 변경한 결과는 아니다.

1/1은 500 EPS를 60초 동안 받은 뒤 약 10초를 더 사용해 backlog를 비웠다. 상한 부하에서 지연 없이 지속 처리한다고 해석하면 안 된다. 실제 변경 전 운영의 별도 60초 표본은 평균 1.2333 EPS, 5초 표본 최대 2.8000 EPS였다. 그 표본 역시 장기 최대 수신량을 보증하지 않는다.

## 결과

| 항목 | 디코딩/룰 판정 1/1 | 자동/자동 |
|---|---:|---:|
| 같은 합성 입력 / exact archives | 30,000 / 30,000 | 30,000 / 30,000 |
| 그룹 수 / 기대 경보 | 2,000 / 4,000 | 2,000 / 4,000 |
| 반복 `100293` 실제 / 기대 | 2,000 / 2,000 | 1,052 / 2,000 |
| 교차 `100294` 실제 / 기대 | 2,000 / 2,000 | 310 / 2,000 |
| 하나 이상 누락된 그룹 | 0 | 1,899 |
| 두 종류가 모두 누락된 그룹 | 0 | 739 |
| 추가 발화 그룹 | 0 | 0 |
| 실제 송신 EPS¹ | 500.242 | 500.218 |
| 마지막 archive 관측: 시작 후 | 70.010초 | 60.006초 |
| 송신→archive 관측 p50 / p99 | 2.796 / 9.644초 | 0.017 / 0.043초 |
| 송신→archive 관측 최댓값 | 10.039초 | 0.056초 |
| sampled rule queue 최대² | 0.24 | 0.00 |
| 분석기 CPU 누계 | 63.40초 | 120.17초 |
| 분석기 최대 RSS | 141,728 KiB | 111,360 KiB |

¹ 첫 burst를 시작점에 보내고 마지막을 59.97초에 보내므로 송신 완료 시간으로 나눈 값은 500보다 조금 크다. 60초 창 평균은 둘 다 정확히 500 EPS다. 최대 schedule lag는 각각 4.658ms와 15.298ms였다.

² native queue 사용률은 5초마다 갱신되는 순간값을 1초마다 읽은 표본이다. 0.00은 표본 사이 적체나 worker in-flight가 없었다는 뜻이 아니다. 1/1의 0.24는 `rule_matching_queue_usage`이며 나머지 sampled queue는 0.00이었다.

각 arm은 `events_received=total_events_decoded=events_processed=30000`, `events_dropped=0`, 최종 sampled queue 0, 최신 state를 확인했다. archives에서 판정한 leaf의 전달 순번/룰별 개수와 alerts가 정확히 일치하고, 모든 행을 읽은 상태를 10초 이상 연속 유지했다. 1/1은 2,000그룹 각각 두 leaf가 한 번씩 발생했고 negative에서 발화하지 않았다. 자동 설정의 반복 누락은 948그룹, 교차 누락은 1,690그룹이다. 전체 합계만 비교해 누락과 중복이 상쇄되지 않도록 그룹별 원장을 별도로 보존했다.

## 시험 계약과 한계

`run-load-b.py`는 종료형 표준 라이브러리 Python 시험기다. 과거 `correlation-diagnosis/run-isolated-b.py`의 최종 SHA `605f5296…`를 확인한 뒤 복사·namespace/chroot 기동·직접 자식 종료 함수만 import한다. 과거 진단 소스와 기록은 수정하지 않았다. 새 수집 서비스·패키지·컨테이너·계정·키·권한을 추가하지 않았다.

- 두 arm은 동일 canonical 입력 바이트를 사용했다. 그룹마다 새 run ID/상관 key와 고유 event/dedupe ID를 만들었고, 중복 negative의 5행은 같은 논리 ID를 유지했다. 기존 13행 그룹에 historical negative 2행을 더해 15행 × 2,000그룹으로 구성했다. 30ms마다 15행 burst를 보내 평균 500 EPS를 만들었으므로 과거 13행 단발 시험과 같은 부하라고 표현하지 않는다.
- 1/1을 먼저, 자동을 다음에 각각 새 private 프로세스로 실행했다. 한 번에 분석기 하나였고 logtest는 호출하지 않았다. 고정 순서는 시간·캐시 효과를 제거하는 무작위 실험이 아니다. 각 조건의 60초 한 회차 결과이며 장기 실패 확률이나 지속 처리 한계를 추정하지 않는다.
- native 분석기와 전체 기존 룰/디코더는 서버 안의 root 전용 prefix에 복사했다. 별도 mount/network namespace, private chroot·큐·로그와 최소 passwd/group만 사용했다. 운영 DB/socket·외부 네트워크와 연결하지 않았다. agent `000`, WDB 없음, root daemon UID 조건이므로 운영 agent `001`의 remoted/labels/Indexer 경로와 동등하지 않다.
- `send()` 성공은 커널 접수이며 분석 ACK가 아니다. 30,000개 archives의 전달 identity와 canonical 원문 전체를 전수 대조했다. archives 순서는 판정/기록 완료 순서이지 입력 수신 또는 상관 이력 등록의 총순서가 아니다.
- 지연은 송신 완료부터 driver가 해당 archive 행을 읽을 때까지의 단조 시계 차이다. native writer flush·polling을 포함한 관측 상한이며 실제 사건 발생 시각 지연이나 Indexer ACK가 아니다.
- `.state`의 수신/디코딩/처리/drop은 같은 PID 내 누계다. `events_processed`는 룰 판정 전 증가하므로 완료 ACK가 아니며, `.state`에는 archives 누계가 없다. 따라서 전수 원문과 alerts 결속이 주된 drain 근거다. [Wazuh 4.14.8 state.c](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/state.c), [analysisd.c](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/analysisd.c).

운영 PID/starttick·CID·root/queue inode·바이너리/설정/규칙 SHA와 호스트 passwd/group의 해시·권한은 전후 일치했다. 시험 자식은 모두 종료했다. 이 runner snapshot은 `local_internal_options.conf` SHA를 포함하지 않는다. 부모의 별도 18:18:24 KST postload 확인에서 local 옵션 `73252a6f…`, 기본 internal 옵션·ossec·룰·바이너리·라이브러리 SHA와 manager/analysisd PID·시작 tick·50스레드가 모두 유지됐으며 운영 drop 0·sampled queue 0이었다. 이 시험기가 운영 thread를 변경하거나 manager를 재시작하지는 않았다.

## 첫 시도와 보완

[첫 시도](initial-attempt-2026-10-14.json)는 `load-2841acb66e93`, source `c801ca17…`다. native 기동·격리 검증 후 송신 전에 reader가 native 로그의 hardlink 수 2를 거절했다. 요약 함수가 그 최초 오류를 `native_state_samples_missing`으로 덮은 문제도 있었다. 사후 private 파일 메타데이터에서 current/dated 로그가 symlink가 아닌 hardlink 2개이고, send receipt 파일이 생성되지 않았음을 확인했다. 송신 0, 자식 정리·운영 불변을 확인한 실패 이력을 남겼다.

최종 보완은 정규파일을 유지하면서 같은 private 로그 디렉터리 안에 동일 dev/inode인 두 이름이 정확히 존재할 때만 native hardlink를 허용한다. 외부 hardlink·symlink·inode 교체·축소·120MiB 초과는 거절한다. 최초 오류를 보존하며, 최종 통계가 없거나 불일치하면 성공 처리하지 않는다. 로컬 계약 회귀 10개가 통과한 `69b7bd1a…`로 두 arm을 완료했다.

## 증거와 보관

- [전체 메타데이터](load-validation-2026-10-14.json): source SHA, input SHA, 그룹별 불일치, state/CPU/메모리 표본, 검증 결과. 원문·private stderr는 제외한 projection이며 서버 원본 result SHA를 포함한다.
- [요약](summary-2026-10-14.json): 두 arm 비교와 범위 제한.
- 서버 완료 trial: `/var/tmp/capstone-correlation-fix-20261014/load-894341808f15/`. `runner-source.py`, `historical-helper-source.py`, `synthetic-input.jsonl`, 각 arm의 send receipts·load-result·native logs·FD inventory와 최종 result를 보관해야 한다. 첫 실패 trial도 별도로 보존한다.
- 실행 소스 SHA256: `69b7bd1aaa8bc5224da32978422b21b7ef8d20830dd35c0a43236206c965bc63`.
- 로컬 전체 메타데이터 SHA256: `9f206cf517a2cbf948f14b1f0e63bd769f11e77f63b2411bce0b5a1e180894b1`.

합성 입력·native archives 원문은 B 서버에서만 보관한다. Mac에는 검증 소스와 숫자/해시 메타데이터만 반입했다. 운영 적용은 기존 Ansible 절차 및 실제 `001` burst E2E 결과로 판단한다.

**18:25 KST 보관·정리 후속:** 위 trial 경로는 실행 당시의 위치다. 필요한 증거를 같은 B 서버의 `/opt/capstone-automation/project/evidence/correlation-fix-20261014/` 아래 같은 상대 경로로 보관하고 SHA를 대조한 뒤 task stage를 삭제했다. 복제 바이너리·룰셋 전체는 임시물로 정리했고 동결 실행 소스·합성입력·송신/수신/판정 자료와 최초 실패는 남겼다. A/B 사후 운영 불변도 확인했다. 배포 검증 파일 반입은 자동 승인 검토에 막혀 대기 중이며 운영 설정을 변경하지 않았다. [보관·정리 및 미완료 항목](finalization-2026-10-14.json).

```sh
/usr/bin/python3 -B -m unittest discover \
  -s infra/normalization/wazuh-vector/correlation-fix \
  -p 'test_load_contract.py' -v
```
