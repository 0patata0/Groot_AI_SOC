# 이전 boot kernel 자료의 수동 보존

**2026-10-14 10:57 KST 후속 완료:** 이전boot 후속481건을 회수해 두배치1,481건/621,820bytes의 A→B 직접 전송·B 파일보관·A 수신증 저장을 검증했다. native 합성144개·실제 합성 응답유실 재시도 및 실제배치 해시/고유cursor를 확인했고 서비스는 유지됐다. Wazuh/Indexer ACK·전체무손실·운영 재주입을 뜻하지 않는다. 다음은 격리 정제와 Suricata→WAF raw 회전 검증이다. [실측과 운영 경계](../history-transfer/README.md). 아래 내용은 이전 기록이다.

**후속 결과 — 2026-10-14 10:43 KST:** 검증된 첫 배치 뒤의 481건/203,010bytes를 별도 child로 보존했다. 부모 원문·manifest 두 SHA는 불변이고, 고정 boot/kernel/cutoff 범위에서 다음 행이 없는 `source_range_exhausted=true`를 확인했다. 두 배치의 합계는 1,481건/621,820bytes이며 과거 journal vacuum·미확인 ACK 경계까지 복구했다는 뜻은 아니다. B 전송이나 재주입은 이 회수에서 실행하지 않았다. [실제 후속 결과](continuation-deployment-2026-10-14.json).

**2026-10-14 06:25:06~06:25:07 KST, A에서 실제 이전 boot 한 배치의 수동 보존을 완료했다.** 고정 boot `b807aba1a92547ffb0c429771628b521`·종료 epoch_us `1791926099107280`에서 가장 오래된 **1,000건/418,810bytes**를 root 전용 경로에 남겼다. SHA256은 `4f3fd39e4bd0e63eca07e00e5dac4515f59b473a401c97e84ed206d568f1128d`이며 정확한 경계 cursor 재조회, 파일별 fsync·원자 rename, root0700/0400·단일 link 및 저장 후 SHA 대조를 통과했다. [실제 보존 결과](deployment-2026-10-14.json).

첫 배치 당시에는 다음 행이 있어 **`source_range_exhausted=false`였으며 첫 배치만으로 이전 boot 전체 회수가 아니었다.** 원래 미수집 ACK 경계도 알려져 있지 않다. 이 history 모듈은 B 전달·원격 수신증·Vector 재주입을 수행하지 않는다. 첫 보존에서 Vector/wazuh-agent의 PID·InvocationID·ActiveState는 전후 동일했고 체크포인트·서비스·원본 journal 변경 명령을 실행하지 않았다. 원문과 cursor는 A에만 남겼다. 첫 배치 실제 보존은 1회였으며 동일 배치 재실행은 합성 시험에서만 확인했다.

기존 A 도구만 사용하는 종료형 Bash/journalctl/jq/coreutils 작업이며 상시 수집기·timer·새 패키지는 없다. [기존 읽기 probe](../collection/probe-journal-history.sh)의 boot/cursor/epoch/kernel 필드를 유지하되, 최근 1,000건을 삭제하던 probe와 달리 지정 범위의 **가장 오래된 최대 1,000건**을 A에서 보존한다. [실행 전 읽기 확인](readonly-2026-10-14.json)과 [합성 25개 검증](validation.json)은 각 시점의 자료이며, 실행 소스 5개 SHA는 실제 보존 전에도 일치했다.

후속 회수는 [검증된 부모 배치 뒤의 수동 회수](CONTINUATION.md)에 별도로 구현했다. 부모 ID·기대 payload SHA·기대 manifest SHA를 고정하고 경계를 다시 확인하는 방식이다. 10:39 KST A 분리 실행본에서 기존25개+후속24개 합성을 통과한 뒤 10:43 KST 실제 후속 한 배치만 실행했다. 기존 첫 배치와 v1 실행 소스는 그대로 유지한다.

운영자 진입점은 [`export-previous-boot.sh`](export-previous-boot.sh)다. A machine-id, root, 현재 boot와 다른 명시적 boot ID, 현재보다 늦지 않은 명시적 종료 epoch(마이크로초)를 요구한다. 출력 위치는 `/var/lib/capstone-vector-history`로 고정되어 있다. 일반 명령·경로·패키지·컨테이너 구성 권한을 LLM/MCP에 추가하지 않는다. source 파일과 디렉터리의 root 소유·쓰기 권한을 검사하며, 기존 저장 디렉터리의 권한을 임의로 바꾸지 않는다.

## 보존 및 완료 판정

- `journalctl --boot=고정ID --until=@고정초.마이크로초 _TRANSPORT=kernel --output=json --all --lines=+1000`으로 가장 오래된 배치를 선택한다. MESSAGE와 cursor·realtime·monotonic·boot·transport 원문은 A root 전용 파일에만 남는다.
- `/proc/uptime` 기준 15초를 **추출·cursor 재조회·JSON 검증이 공유**한다. 각 생산자에 `timeout`을 적용하고 종료 신호 뒤 0.2초의 강제 종료 여유를 예산 안에서 뺀다. SHA·manifest 작성·`sync FILE`·rename은 내구성 마무리 단계여서 이 15초 예산 밖이며, 느린 디스크에서 전체 명령이 더 오래 걸릴 수 있다. 절대 15초 안에 모든 fsync까지 끝난다고 보장하지 않는다.
- 본문과 경계 검증 원문 파일을 합쳐 최대 32MiB다. 경계를 넘는 다음 1byte의 **존재 여부만 숫자**로 세며 그 byte를 기록하지 않는다. cap 뒤 producer가 정상 종료했더라도 초과로 판정한다. producer/consumer exit를 따로 기록하고 124(timeout), 137(kill/timeout), 141(SIGPIPE), 다른 실패를 완료로 취급하지 않는다.
- 한 물리 행에 한 JSON 객체, 마지막 LF, 지정 boot/kernel, bounded cursor, epoch와 종료 범위, 중복 cursor 및 monotonic 역순을 검사한다. 빈 범위는 보관 만료와 진짜 0건을 확정할 근거가 부족하므로 `empty_range_unproven` 부분 보존이다.
- 처음 cursor를 지정해 한 행을 재조회하고 **정확한 같은 cursor**인지 확인한다. 마지막 cursor를 지정해 최대 두 행을 재조회하고 첫 행이 정확한 마지막 cursor인지 확인한다. 두 번째 행이 있으면 `source_range_exhausted=false`, 없으면 `true`다. journalctl의 가까운 cursor 대체 탐색을 정확한 재조회 성공으로 오인하지 않는다.
- `complete_batch`는 선택된 배치를 검증·동기화해 보존했다는 뜻이다. `source_range_exhausted=true`도 **고정 boot/종료 시각/kernel 범위의 관측 끝**만 의미한다. 원래 ACK 시작점은 모르며, 추출 도중 중간 journal 파일이 vacuum된 구간의 무손실 증명이 아니다. 두 끝 cursor가 살아 있다고 중간 자료가 모두 남아 있었다고 단정하지 않는다.

manifest에는 고정 선택 조건, 첫/끝 cursor·epoch, 검증한 건수(미검증이면 null), 물리 LF 수, 원문 bytes/SHA256, producer/consumer 결과, 범위 끝 여부가 남는다. 원문 포함 `kernel.jsonl`과 manifest는 root 소유·0400, 완료 디렉터리는 0700이다. 첫/끝 cursor를 포함한 자세한 manifest는 A에만 둔다. stdout에는 건수·크기·SHA·고정 상태값만 출력한다.

## 재실행과 실패

배치 ID는 정책 버전·boot·종료 시각·최대 건수·바이트 한도의 SHA다. root 전용 flock 아래 `partial-<ID>.<attempt>/`에 쓴다. 정상 완료 때 원문과 manifest 및 디렉터리를 `sync FILE`한 뒤 같은 filesystem의 `batch-<ID>/`로 원자 rename하고 부모를 다시 동기화한다. GNU `sync FILE`은 해당 파일이나 디렉터리 FD에 fsync를 수행한다. filesystem 전체를 동기화하는 `sync -f`는 사용하지 않는다.

완료 이름이 이미 있으면 권한·SHA·크기·ID를 대조하고 다시 동기화한 뒤 재사용하며 journal을 다시 읽거나 덮어쓰지 않는다. 다른 내용이면 거절한다. 부분 보존 재시도는 새 attempt를 만들고 과거 partial을 자동 삭제하지 않는다. 시작할 때 최소 최대 capture량+8MiB 여유를 요구한다. 자동 정리·압축·ACK·원본 삭제는 없다.

검증 실패는 exit 2와 `partial` manifest를 남긴다. 예상하지 못한 I/O·동기화 오류나 프로세스 강제 종료는 nonzero 또는 미완료 디렉터리로 남을 수 있다. **partial 디렉터리 안의 manifest만 보고 완료로 채택하지 않는다.** rename 직후 디렉터리 동기화 실패도 호출 성공으로 보고하지 않으며, 다음 명시적 재실행에서 기존 최종 파일을 검증하고 다시 동기화해야 한다. 전원 장애·실제 디스크 오류의 내구성을 합성 fixture만으로 입증하지 않았다.

## 실행 경계와 검증

관리자가 root 소유 후보를 검토한 뒤 `bash export-previous-boot.sh <32자리_이전_boot_ID> <고정_종료_epoch_us>`를 명시적으로 실행하는 방식이다. 자동으로 가장 최근 boot를 선택하지 않으며 현재 Vector data/checkpoint, 운영 ready, Wazuh 입력, 원본 journal, 보안 서비스는 바꾸지 않는다. **B 전송·Vector 재주입·상관 등록은 이번 작업에 없다.** 원문을 Mac으로 반출하지 않는다.

[`test-native.sh`](test-native.sh)는 A의 기존 Bash/jq/coreutils에서 가짜 journalctl만 실행한다. 합성 입력을 자기 임시 디렉터리에 만들고 시험 뒤 제거한다. root 전용 함수 계약과 실제 stdout pipe/timeout/32MiB cap/atomic rename/reuse를 검증한다. 운영 wrapper를 호출하거나 실제 journal을 읽지 않는다. 결과·실행 소스 SHA·도구 버전은 [`validation.json`](validation.json)에 남긴다.

공식 근거: [systemd v255 journalctl 문서 원본](https://github.com/systemd/systemd/blob/v255/man/journalctl.xml)에서 `--lines=+N`은 가장 오래된 N개, `--cursor`는 지정 위치에서 시작하며 cursor는 opaque 값이다. [GNU coreutils 9.4 sync 구현](https://github.com/coreutils/coreutils/blob/v9.4/src/sync.c)과 [timeout 구현](https://github.com/coreutils/coreutils/blob/v9.4/src/timeout.c)의 파일 동기화·종료 상태 계약을 사용한다.
