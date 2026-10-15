# EOF 과대행의 제한된 바이트 검사

**21:20 KST 운영 확인 완료:** A에 검사 파일4개와 기존 maintenance 연결을 반영했고 재적용 changed0·Vector PID/InvocationID 불변을 확인했다. 21:19:26 기존 systemd oneshot의 정상 실행에서 root0600 상태 파일 저장·세 원천 안정·과대행0·5분 timer active를 확인했다. 이 실행은 수동 시작이며 자연 timer 주기 실측은 별도다. B에는100252/100253 두level3 상태 규칙만 추가했고 baseline104·후보116·동일manager1회재시작후116개를 통과했다. A의 기존 보호59파일과 reader/엔진은 같고 B의1/1·44threads·나머지5컨테이너·승인 경계도 유지됐다. drop0/queue0은 한 시점 표본이다. 소스·증거 보관/정리는 후속 마감으로 기록한다. [운영 적용과 상태](deployment-2026-10-14.json), [합성34·통합12 검증](validation-2026-10-14.json).

이 후보는 Vector의 EOF 과대행 숫자 counter 누락을 보완하는 주기적 관측이다. GNU coreutils의 `dd`, `tr`, `wc`, `stat`, `timeout`과 기존 jq를 사용한다. 새 Python 수집기·패키지·서비스·Vector 설정 변경은 없다. 원시 로그를 수정·재주입하거나 기존 checkpoint를 갱신하지 않는다.

**최신 검증(2026-10-14 21:06 KST경): A의 최종 native 합성 34개 모두 PASS.** 원천 크기 경계·비ASCII 바이트·큰 파일 EOF·소유권/경로 거절·timeout·append/truncate/regrow/rename·pipefail·predicate 음성을 포함했다. 실행 전후 library SHA `028ac32906a2a7964d46c01a81f42f23e975b25bc6b99593ef97c4bb3676b447`와 test SHA `a68d83c790bf5064ec6eb25f6cc4b34a088ad933a0e42025d1bf89850190c16d`가 같았다. 이는 private fixture의 결과이며 운영 maintenance 연결·경보 배포 완료와 구분한다. 런타임 세 파일은 이 시점 이후 변경하지 않았다.

초기 관측 이력: Bash 구문검사 후 부모가 2026-10-14 21:01 KST에 초기 스냅샷으로 A의 GNU coreutils 9.4/jq 1.7 호환성과 합성 세 경계를 확인했다. 그 초기판의 실제 원천 관측은 Suricata 17,814,378B/max8,903B, 감사 10,072B/max2,188B, 접근 810B/max405B로 모두 전체 범위가 안정됐고 초과 관측은 없었다. 이 값은 해당 시점의 관측이며 최종 소스의 운영 연결 완료를 뜻하지 않는다.

## 정확히 측정하는 범위

열기 전 파일 크기를 `size`로 고정하고 `[max(0,size-33554432), size)` 범위를 읽는다. GNU `dd`가 검증한 regular FD에서 바이트 단위로 이동한 뒤 정해진 count까지만 읽으므로 새 append를 계속 따라가지 않는다. 파일 끝이 LF로 끝나는 경우와 LF 없는 마지막 행 모두 포함한다.

```sh
dd bs=65536 skip="$start" count="$count" iflag=skip_bytes,count_bytes status=none |
  LC_ALL=C tr -c '\n' '.' |
  LC_ALL=C wc -c -L
```

`wc -L`만 원문에 적용하면 탭·CR·문자 표시 폭 때문에 바이트 길이와 다를 수 있다. 먼저 LF를 제외한 **각 바이트**를 ASCII 점 하나로 치환하므로 NUL·UTF-8·탭·CR도 한 바이트씩 계산된다. 한 번의 `wc -c -L`로 검사한 바이트 수와 LF를 제외한 최대 행 길이를 얻는다. 변환 결과는 pipe 안에서만 이동하며 파일·stdout에 원문이나 치환 행을 저장하지 않는다. [GNU coreutils 9.4 매뉴얼 원문](https://github.com/coreutils/coreutils/blob/v9.4/doc/coreutils.texi), [9.4 wc의 EOF 잔여 길이 처리](https://github.com/coreutils/coreutils/blob/v9.4/src/wc.c#L567-L620)

구간의 첫 행은 앞부분이 잘린 조각일 수 있다. 그 조각만 1,048,576B를 넘으면 초과 관측이지만, 초과하지 않아도 원래 전체 행의 정상 여부는 알 수 없다. 큰 파일에서 구간 이전에만 존재하는 과대행은 이 검사로 검출하지 않는다. `full_file_scan=false`를 전체 정상으로 바꾸어 해석하면 안 된다.

## 일관성과 실패 판정

- 실행자 root, 절대경로 형태, 모든 상위 디렉터리와 파일의 symlink 부재, regular file, 지정 UID/GID/mode, nlink1을 확인한다. 실원천의 기존 상위 소유자·권한은 변경하지 않는다.
- 열기 전 경로 stat, 열린 FD stat, 실제 읽기 이후 FD·현재 경로 stat, 상위 디렉터리 신원을 대조한다. inode·size·mtime·ctime 등이 바뀌면 `inconclusive`다. 이 대조는 정기 관측의 변경 검출이며 적대적 root에 대한 원자 snapshot이나 파일 시스템 불변 증명은 아니다.
- 파일 하나의 **stat/open/scan/post 검사 전체**를 GNU timeout 5초 + 강제 종료 유예 1초로 제한한다. 타입 검사 뒤 FIFO로 바뀌어 open이 대기해도 무한 대기를 허용하지 않는다. 세 파일의 최대 읽기는 96MiB다. 통합 호출자는 전체 30초 제한과 최대 16KiB 메타데이터 수신 제한도 적용한다.
- 소스 읽기에 따른 atime 변화는 가능하다. atime은 읽기의 정상 부작용이므로 안정성 비교 대상에서 제외한다. 원문·파일 권한·mtime을 변경하지 않는다.

결과의 `observed_positive`는 읽힌 스트림에서 1MiB 초과 길이가 관측됐다는 뜻이다. 이후 파일 변경이나 읽기 오류가 확인돼도 이 관측값은 지우지 않는다. 다만 확정 `verdict`는 `inconclusive`로 두고 `collection_raw_line_oversize_seen`와 `collection_raw_line_scan_unavailable`을 함께 낼 수 있다. timeout으로 결과 자체를 얻지 못하면 정상이나 무초과로 추정하지 않는다.

`within_scanned_range`는 안정된 해당 범위에서만 초과를 관측하지 않았다는 뜻이다. `complete_snapshot_range=true`와 실제 읽은 byte count를 함께 요구하며, `full_file_scan`은 시작 offset이 0일 때만 true다. 모니터 주기 사이에 생성·회전·삭제된 자료, 모든 역사 파일, Vector가 이미 버린 원문의 복구까지 보장하지 않는다.

## 파일과 호출 계약

| 저장소 파일 | 운영 설치 후보 | 역할 |
|---|---|---|
| `line-length-lib.sh` | `/etc/capstone-vector/line-length-lib.sh`, root:root 0644 | 제한된 native 검사 및 fixture용 함수 |
| `scan-raw-lines.sh` | `/usr/local/sbin/capstone-vector-raw-lines`, root:root 0755 | A machine ID/root/고정 세 원천만 허용 |
| `raw-line-status.jq` | `/etc/capstone-vector/raw-line-status.jq`, root:root 0644 | 메타데이터 검증 후 고정 상태 배열 |
| `test-native.sh` | task 임시 경로에서만 실행 | private 합성 원천과 결정론적 실패 대조 |

운영 CLI는 `capstone-vector-raw-lines check` 한 가지다. 임의 경로·코드·예산 인수를 받지 않는다. 고정 원천은 `/home/groot_a/capstone/secstack/logs/` 아래 `suricata/eve.json`(998:998/0644), `modsec/audit.log`(101:101/0644), `modsec/capstone-access.log`(101:101/0640)다. 런타임 Vector 설정·환경 SHA 결속과 logger/스냅샷 저장은 상위 maintenance 통합에서 수행하며 이 도구는 환경 파일을 source/eval하지 않는다.

정상 형식 JSON을 만들었으면 결과가 inconclusive여도 exit0이다. 실행 환경·인수·의존 파일 오류는 nonzero이며 호출자는 unavailable로 처리해야 한다. `raw-line-status.jq`는 scanner envelope **하나**를 stdin으로 받아 고정 상태 코드의 배열만 출력한다. 여러 JSON 문서·중복 source·잘못된 수치·상태 위조는 unavailable이다. 잘린 JSON의 jq nonzero, 빈 출력, 전체 시간 초과 역시 통합자가 unavailable로 처리한다. 외부 `.statuses` 값은 신뢰하지 않고 행 메타데이터로 다시 산출한다.

합성 함수 API는 `ll_scan PATH UID GID MODE LIMIT_BYTES BUDGET_BYTES TIMEOUT_SECONDS`다. 이 함수는 운영 CLI의 권한 경계로 공개하지 않는다. 테스트는 현재 task의 root0700 `/var/tmp/capstone-sequential-20261014/step2/` 아래에서만 private fixture를 만들고 정리한다. mode는 stat 표현인 `600` 등으로 전달한다. 정상 임계값은 1,048,576B, 최대 예산은 33,554,432B다.

## 최종 native 시험 후보

실제 1MiB 직전/정확/초과 행의 LF·EOF 양쪽, NUL·탭·UTF-8·CR의 정확 byte count, 큰 파일 끝의 초과 행·첫 조각 초과·구간 앞쪽에만 있는 초과 행, UID/mode 불일치, 파일/상위 symlink, FIFO, 누락 파일을 검사한다. 별도 private 코드 사본의 고정 지연과 실패 pipe로 실제 timeout/pipefail 처리도 확인한다.

append, truncate, 같은 크기로 regrow, rename 교체는 테스트 전용 stat 경계에서 합성 파일만 변경해 결정론적으로 검증한다. 이 테스트 instrumentation은 배포 파일에 넣지 않는다. predicate는 positive+inconclusive의 이중 상태, 잘못된 행 개수·source·수치·추가 필드·복수 JSON 문서도 거절해야 한다. 실제 원천이나 고정 live CLI는 합성 test가 호출하지 않는다.

**21:27 KST 후속 확인:** 배포 후 타이머가 21:24:31에 자연 실행돼 21:24:32 정상 종료했다. root0600 상태 파일의 binding 일치·3원천 안정·상태 코드 없음이 확인됐다. 수동 실행 검증에 더해 정기 실행도 확인한 것이며 전수 무손실 보장은 아니다. A149/B107개 검증 파일을 영구 증거 경로에 SHA 대조해 보존했고 프로젝트 소스 동기화·작업 파일 정리를 마감 중이다.
