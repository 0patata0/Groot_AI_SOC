# 고정 A/B 저장공간 감시와 보존 검토 목록

> **09:32 KST 후속:** A/B timer 실제09:02 자연실행exit0와 B전용로그2행1014B/nativeCP EOF·SHA일치를확인했다. B service·SOC수신은더이상대기항목이아니다. A09:32는18%/여유47,604,580,352B·raw28,891,127B·backup27,084,621B/ok다. 보존기한검토목록과자동삭제미구성은유지한다. 아래08:50~08:52는당시표본이다.

2026-10-15 A/B 설치·고정 경로 `check`와 양쪽 Linux private fixture 각30개 PASS를 확인했다. 추가 패키지 없이 Bash, jq, GNU find/du/df/stat/timeout, flock, logger, systemd를 사용한다. 로컬 임계값·형식 시험16개와 systemd unit/calendar 해석도 통과했다. A는 08:52:22 KST 실제 oneshot이 exit0으로 완료됐고, 저장 상태와 journal JSON이 동일했다. timer enabled/active 및 다음 예정 시각09:02 KST도 확인했다. B의 실제 service/timer와 SOC 수신, 예정된 자연 tick은 후속 확인 대상이다. 원문·체크포인트·보관본을 삭제하거나 서비스를 중지하지 않는다.

A 08:50:39 관측은 사용률20%·여유46,845,345,792B·managed raw28,107,392B·backup14,313,406B·history6,518,123B다. B 08:50:58은 사용률27%·여유108,564,328,448B·backup6,539,836B·history1,251,272B다. [실제 설치/확인 metadata](deployment-validation-2026-10-15.json)는 부모 실행 출력과 source SHA를 결속하며, 이 용량 표본을 장기 보장으로 해석하지 않는다.

## 범위와 실행

`monitor.sh run|check`만 받으며 root와 고정 machine-id로 A/B를 판별한다. 임의 경로·명령·호스트·임계값 인수는 없다. `run`은 root0600의 최근 상태/검토 목록을 atomic rename+fsync로 갱신하고 `capstone-storage` 태그로 JSON 한 건을 journal에 쓴다. `check`는 같은 관측 JSON만 출력한다. 두 모드 모두 own state 아래 임시 작업 폴더와 lock을 사용하며 끝나면 자신의 scratch만 제거한다.

| 대상 | 고정 관측 범위 |
|---|---|
| A raw | `logs/suricata/capstone-managed`, `logs/modsec/capstone-managed`의 합계(앞 경로 `/home/groot_a/capstone/secstack/`) |
| A history | `/var/lib/capstone-vector-history-auto/store`, `/var/lib/capstone-vector-history` |
| B history | `/var/lib/capstone-history-receipts` |
| 두 호스트 backup | `/var/backups/capstone-*`의 직접 하위 디렉터리만, 최대 64개 |
| disk | 위 고정 경로들이 있는 filesystem의 최소 여유 bytes/최대 사용률 |

A는 기존 `vector.lock`을 shared/nonblocking으로 잡아 세대 선택을 보호한다. 회전/관리자 작업과 경합하면 기다리거나 서비스를 조작하지 않고 unavailable을 낸다. 원문 파일은 stat/du로만 조사하며 내용을 읽지 않는다. raw state JSON은 current/pending 번호를 판단할 만큼만 읽는다. CP·자격증명·환경 파일·DB는 열지 않는다.

각 트리는 최대 100,000 entry, 한 filesystem만 읽는다. symlink, FIFO/socket 등 비정규 entry, 읽기 실패, state 형식 오류, 디렉터리 교체는 해당 계측을 null로 만든다. backup 이름이 prefix와 일치해도 symlink/일반파일이면 무시하여 0으로 만드는 대신 unavailable이다. worker는 30초(TERM 후 2초 KILL), wrapper는 40초, unit은 45초 상한이다. 시간 초과/잘못된 worker 결과는 성공한 0B 관측이 아니다. 디스크·status 쓰기 자체가 실패하면 unit 실패로 남으며 journal 성공까지 보장하지 않는다.

`du -xsb`는 apparent bytes다. 같은 트리 안 hardlink 중복은 GNU du가 제외하지만 서로 다른 고정 root 사이의 hardlink는 각각 합산될 수 있다. 실제 쓰기는 계속되므로 측정은 관측 구간의 용량 표본이지 원자적 filesystem 스냅샷이나 최대 증가량 보장이 아니다. entry 개수/시간 한도를 넘으면 범위를 임의로 생략해 healthy로 표시하지 않는다.

## 고정 판정과 JSON 계약

18개 flat key만 방출한다. 계측 실패 값은 null이며 `scan_status=unavailable`이다.

```
schema_version policy machine_id host observed_at_utc status reason scan_status
used_percent available_bytes raw_bytes backup_bytes history_bytes
raw_archive_review_due_count backup_review_due_count retention_days
automatic_deletion checkpoint_changed
```

`policy=capstone-storage-retention-v1`, schema_version=1, host=a/b, UTC 시각은 초 단위 Z다. 마지막 두 boolean은 항상 false다. numeric 값은 비음수 정수 또는 null이다. retention_days는 A30/B90이다.

- critical: disk 사용률 ≥90%, 여유 <2GiB, raw 합계 ≥5GiB, backup 합계 ≥2GiB 중 하나.
- warning: 사용률 ≥80%, raw ≥4GiB, backup ≥1GiB 중 하나이며 critical/unavailable이 아님.
- unavailable: 하나 이상 계측 불명확하며 알려진 critical 조건이 없음.
- ok: 전부 관측했고 임계값 미만.

알려진 critical은 다른 항목의 unknown보다 우선한다. warning과 unknown이 함께면 unavailable이다. reason은 각각 `capacity_critical`, `capacity_warning`, `scan_unavailable`, `healthy`다. history_bytes는 가시화하며 임의의 새 history 경고 한도는 추가하지 않았다.

B 담당의 예정 규칙 매핑은 100310 정상 level0/no_log, 100311 warning level5, 100312 critical level10, 100313 unavailable level5다. 기존 SOC 수집 경로를 사용하며 새 메시지 채널·자동 차단 권한은 없다. 이 디렉터리는 B 규칙/decoder를 설치하지 않는다. 태그/고정 route와 JSON을 검증하는 규칙의 native 시험은 별도 필수다.

## 보존 정책과 남은 범위

A raw의 30일 경과 파일 중 root:root0400/nlink1이고 current/pending 번호가 아닌 generation만 검토 목록에 넣는다. 이는 **archive/delete 승인이나 reader drain·writer FD0·B 수신증 증명은 아니다**. count 이름을 `raw_archive_review_due_count`로 제한했고 inventory에도 archive_authorized/delete_authorized=false를 쓴다. 목록은 최대 32행, 전수 count는 별도 유지한다. 이 조사만으로 원문을 옮기거나 지우지 않는다.

backup은 root 디렉터리 mtime가 A30일/B90일을 넘으면 검토 count에 넣는다. 디렉터리 mtime는 완료 시각/최근 내부 파일 수정 시각의 증명이 아니다. runtime/guard/migration receipt가 참조하는 backup은 항상 보호하며 현재는 모든 capstone backup을 삭제 금지로 취급한다. B history/receipts도 용량만 계측한다. B90일 archive 검토 후 실제 삭제/자동 보존수명 집행은 별도 승인된 reference·receipt 검증 설계가 남는다. systemd-tmpfiles의 단순 age-delete를 raw/backup에 연결하지 않는다.

## 설치 및 검증 계약

운영자는 소스 SHA와 기존 호스트 상태를 확인한 뒤 기존 배포 도구로 다음 고정 파일만 반입한다. installer/SSH는 이 후보에 포함하지 않는다.

- `/usr/local/lib/capstone-storage-monitor`: root:root0755. `monitor.sh` 0500, `monitor-lib.sh`/`policy.jq` 0400, 각 nlink1. wrapper에 lib/policy SHA가 고정된다.
- `/var/lib/capstone-storage-monitor`: root:root0700. `.lock`, `status.json`, `inventory.json`은 root0600. 다른 저장 경로의 권한은 바꾸지 않는다.
- unit 두 개는 `/etc/systemd/system/` root0644. `systemd-analyze verify`와 calendar 해석을 native로 먼저 확인한다.

`test-native.sh --policy-only`는 순수 jq 시험16개다. Linux root에서 `test-native.sh`는 새 `/var/tmp/capstone-storage-native.*`만 사용해 총30개를 시험한다. 실제 GNU du/df, symlink/없음, 세대 검토 제외, worker timeout/오염, status fsync/rename을 확인한다. publisher 시험만 world-writable `/var/tmp` 위 조상 대신 자신의 root0700 fixture까지 trust boundary를 제한하는 stub을 사용한다. 운영 상태·원문·서비스는 접근하지 않는다.

native 시험 후 A/B에서 `monitor.sh check`의 정확 18키와 live 경로/용량을 대조하고 B 규칙을 연결한다. 첫 `systemctl start capstone-storage-monitor.service`와 journal 1건, 상태 파일 root0600, 기존 보호 SHA/CP 불변을 확인한 뒤 timer를 활성화한다. timer는 KST 매시 02/17/32/47분, Persistent=false다. 기존 raw(0/1분대)와 output(3분대) 회전 일정은 바꾸지 않는다. 이후 자연 tick은 별도로 관찰한다.
