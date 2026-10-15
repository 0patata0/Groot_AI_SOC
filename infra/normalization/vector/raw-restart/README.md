# Wazuh 원본 입력의 재시작 경계 시험

2026-10-14 22:00 KST 결과: **A의 설치된 Wazuh로 두 설정·각 5개 경계를 실행했고, 운영 불변과 private 프로세스·경로 정리를 확인했다.** [실측 메타데이터](native-validation-2026-10-14.json)에 결과와 원격 원본 결과 SHA를 보존했다. 이 격리 시험은 운영 설정·원본·체크포인트·서비스를 변경하지 않았다.

| 경계 | 기본 `yes` | `no / 2GB` |
|---|---|---|
| 최초 등록의 기존 1·2행 | 두 행 모두 건너뜀 | 두 행 모두 건너뜀 |
| 정상 종료 중 추가한 4·5행 | 두 행 모두 건너뜀 | 두 행 모두 수신 |
| 오래된 native 저장 위치에서 강제 종료 후 추가한 9·10행 | 두 행 모두 건너뜀 | 두 행 모두 수신, 이미 수신했던 7·8행은 각각 한 번 재수신 |
| 새 inode·동일 길이·다른 내용의 12·13행 | 두 행 모두 건너뜀 | 두 행 모두 수신 |
| 새 inode·완전히 동일한 내용의 12·13·14행 | 세 행 모두 건너뜀 | 세 행 모두 건너뜀 |

두 설정 모두 강제 종료 직전 저장 위치가 메모리 수신보다 뒤처졌고, SIGKILL 전후 checkpoint SHA가 같았다. 모든 수신은 합성 원문과 정확히 대조했으며, 실제 운영 logcollector PID는 불변이었다. `no / 2GB`는 기존 저장 위치가 있는 파일의 중단 중 추가분 복구를 개선하지만, 최초 등록과 동일 prefix 세대 구분은 해결하지 않으며 재수신도 발생한다. 따라서 운영 회전에는 별도 generation 상태·prefix 충돌 거절·reader 시작 보호가 필요하다.

`run-probe-a.py`는 A의 설치된 Wazuh logcollector와 라이브러리를 전용 디렉터리에 복사해 실행하는 종료형 시험 도구다. 상시 Python 수집기가 아니다. `wazuh-isolated.sh`는 기존 격리 시험과 같은 mount/network namespace 방식을 사용한다. private namespace에서 `/`를 `rprivate`로 바꾼 뒤 `/var/ossec`를 private prefix에 bind하고, 별도 Unix datagram queue로 합성 JSON만 받는다. 실제 agent/manager 전송은 없다.

두 설정을 같은 순서로 비교한다.

- `default`: `only-future-events`를 생략한 기본값 대조군.
- `recover`: `<only-future-events max-size="2GB">no</only-future-events>` 후보.

| 경계 | 입력과 관측 |
|---|---|
| 최초 등록 | 저장 위치 없는 파일의 기존 1·2행, 시작 후 새 표식 3행 |
| 정상 종료 중 추가 | native SIGTERM 종료로 저장한 위치 뒤에 4·5행을 쓰고 재기동, 표식 6행 |
| 강제 종료 | 정상 저장 위치 6행 뒤 7·8행의 queue 수신을 확인하고 private 프로세스를 SIGSTOP, 저장 위치를 읽은 뒤 SIGKILL; 중단 중 9·10행 추가, 재기동 후 표식 11행 |
| 같은 길이의 다른 세대 | 기존 위치 파일은 그대로 두고 alias를 다른 inode·같은 byte 길이·다른 SHA의 12·13행 파일로 교체, 재기동 후 표식 14행 |
| 완전히 같은 바이트의 다른 세대 | 이전 세대를 byte 단위로 복사한 새 inode에 alias를 교체, 같은 12·13·14행이 다시 읽히는지 관측하고 새 표식 15행 |

기존 행을 건너뛰거나 중복 처리해도 관측값을 숨기지 않는다. `status=completed_observations`는 시험이 끝나고 운영 불변·private 정리가 확인됐다는 뜻이며, 복구가 모든 경계에서 성공했다는 뜻이 아니다. 각 case의 `offline_missing`, `received_counts`, `prior_case_replays`, `within_case_repeats`를 해석해야 한다. 강제 종료의 `stale_checkpoint_established=false`이면 그 실행은 오래된 저장 위치 복구를 재현하지 못한 것이다. 완전히 동일한 세대의 논리 ID 재사용은 의도한 negative 대조다.

공식 4.14.8 소스에서 저장 위치가 없으면 EOF를 선택하고, 위치가 있으면 해당 길이의 SHA-1 비교와 `diff_max_size`로 재시작 위치를 결정한다. 따라서 새 inode만으로 독립 세대 복구가 보장되지는 않는다. 원본을 0으로 덮거나 checkpoint를 수정하는 보정은 없다. [Wazuh logcollector 재시작 위치 코드](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/logcollector.c#L2576-L2622)

정상 종료는 SIGTERM을 실제 전달하고 강제 종료 없이 native 반환 코드 1 및 저장된 path/offset/전체 SHA-1이 EOF와 맞는 경우로 제한한다. 파일 저장에는 정상 종료의 `atexit` 경로가 있으나, 이번 시험은 OS 재부팅·정전·디스크 오류 내구성을 증명하지 않는다. [native 파일 저장 코드](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/logcollector.c#L2407-L2427), [SIGTERM 종료 코드](https://github.com/wazuh/wazuh/blob/v4.14.8/src/shared/sig_op.c#L44-L69)

수신 oracle은 생성한 compact ASCII JSON과 native queue의 body 바이트를 정확히 비교한다. 단순 JSON 의미 비교로 바이트 차이를 숨기지 않는다. JSONL의 줄바꿈은 native JSON reader가 제거하고 cJSON으로 다시 직렬화하므로, 원본 JSONL 전체와 queue frame 전체가 동일하다고 주장하지 않는다. [native JSON reader](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/read_json.c#L42-L112)

## 실행 계약

부모 작업자의 소스 검토·실행 신호 이후 A root에서만 실행한다. 먼저 다음 parent를 root:root 0700으로 준비하고, 미존재하는 고유 `run-*` 하위 경로를 지정한다.

```sh
/usr/bin/python3 -B /검토된/경로/raw-restart/run-probe-a.py \
  --output /var/tmp/capstone-sequential-20261014/step3/raw-restart/run-01
```

- Machine ID를 A에 고정한다. 운영 `wazuh-agent`·Vector active 여부, logcollector PID/start ticks, 운영 queue/root inode와 설정·바이너리 해시를 전후 비교한다.
- 강제 종료는 exact child PID/start ticks/pidfd와 private exe/cwd/mount/network/queue 확인 뒤에만 한다. 최초 helper 준비 실패의 정리는 unreaped direct child의 전용 process group만 대상으로 한다.
- 한 프로파일에 reader 하나만 실행한다. 입력 파일은 각각 4KiB 미만, 수신은 프로파일별 최대 200개, 개별 준비 명령 45초, reader 준비 12초, 정상 종료 15초, 본 시험 360초 상한이다. 부모의 외부 상한은 finally 정리 시간을 포함해 450초 이상으로 둔다.
- `result.json`·`runtime.json`과 단계별 checkpoint 복사본·생성한 세대 원본·private 로그·수신 SHA metadata·실행 소스를 A의 결과 디렉터리에 남긴다. stdout은 메타데이터만 출력한다. 운영 원문은 읽지 않으며 Mac으로 옮기지 않는다.
- 모든 private child 종료 및 증거 보존을 확인한 뒤 `/var/tmp/capstone-raw-restart.*`를 삭제한다. 정리·보존 실패 시 경로를 남기고 실패로 보고한다. 운영 입력에 대한 Wazuh 분석 완료, Indexer 색인 ACK, 무손실 또는 정확히 한 번 처리를 보장하는 시험은 아니다.

로컬 검증은 기존 Python/Bash만 사용하며 설치가 필요 없다.

```sh
/usr/bin/python3 -B infra/normalization/vector/raw-restart/test_contract.py
/bin/bash -n infra/normalization/vector/raw-restart/wazuh-isolated.sh
```
