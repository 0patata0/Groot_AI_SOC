# 봉인 raw 보관·복원 검증과 수명주기 정책

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 기존 서버의 운영 자동화와 새 서버 초기 설치는 구분한다. 지정 범위의 C1/B1/A2 재부팅 복구는10/24 검증 이력이 있으며 최초 실패·수동 복구도 보존한다. 현재6실습·MCP6서버를 기준으로 읽고 과거 후보/PID/시험 결과를 새 실측으로 해석하지 않는다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

**2026-10-15 봉인본 5개의 A 압축·private 복원과 B 보관·private 복원 검증을 완료했다.** 순수 정책 합성 51개와 Linux native A/B 각 16개도 통과했다. 원본 21,157,373B를 gzip 1,556,116B로 보관했고, 운영자 SSH 연결 사이 메모리 중계로 B에 manifest/gzip 10파일을 전달했다. B 고정 machine ID에서 5개 모두 manifest·gzip SHA/크기 및 복원 원문 SHA/크기를 대조했다. 근거는 [실측 metadata](live-archive-2026-10-15.json), [검증 기록](validation-2026-10-15.json)이다.

A에서는 공유 vector lock, 정확한 container writer의 writable FD0, state SHA 및 원본 identity를 전후 확인했다는 부모 실행 결과를 반영했다. 이 문서 담당자는 로컬 catalog·B receipt 5쌍의 고유 manifest SHA, 원문/압축 합계, 각 원문 SHA/크기와 수신 시각을 독립 대조했다. 마지막 B 복원 확인 시각은 10:19:17 KST다. 원본 삭제0, 기존 kernel history sender 변경0, Mac raw 파일 저장0이다. A에 B 영수증을 보존하는 후속 확인은 부모가 진행 중이며 이 시점에 완료를 주장하지 않는다.

**일반 백업 이관·자동 실행 주기·삭제 executor는 여전히 미구현**이다. 이번 5개는 원본을 유지하는 보존 복사만 수행했다. `first_verified_at_epoch`부터 30일 및 엄격한 전체 소비/참조 proof 조건을 충족한 삭제 대상으로 확인하지 않았으므로 삭제0이다. 복사 시각인 `copy_verified_at_epoch`를 엄격한 삭제 검증의 최초 시각으로 승격하지 않는다.

부모가 10:08:52 KST A에서 관측해 전달한 봉인본은 Suricata gen0 21,143,722B와 WAF gen0 10,072B/gen1·2·3 각 1,193B, 합계 5개다. 모두 root:root0400/nlink1이다. 현재 Suricata active rev7/gen1, WAF active rev14/gen4와 구별한다. 이 정보는 **부모의 실측 전달**이며 이 후보 작성 과정에서는 SSH나 운영 파일 읽기를 수행하지 않았다.

## 재사용 도구와 보존 경계

- 기존 Bash/jq/GNU coreutils/gzip/timeout/flock를 쓴다. 단일 raw 파일은 `gzip -n`과 별도 canonical manifest 두 파일이면 충분하다. 원격 tar pathname 추출이 필요하지 않다.
- 운반에는 기존 rsync/SSH 또는 운영자가 승인된 두 SSH 연결 사이로 중계하는 스트림을 사용한다. 원문을 Mac 디스크에 저장하지 않는다. 압축 전달 성공을 복원 성공으로 취급하지 않는다.
- 기존 history forced sender는 `/var/lib/capstone-vector-history-auto/store`의 kernel 배치만 허용한다. 이 키·sudo·gate를 raw archive에도 되는 것으로 간주하거나 조용히 확대하지 않는다. 이번 한시 운영자 전송은 그 경로와 독립이다.
- B의 보관·복원 영수증은 raw 파일 보관 증거다. Wazuh 분석·Indexer 색인·보안 경보 전달 ACK가 아니다. A/B 원본 CP를 읽어 고치거나 offset을 복구하지 않는다.
- `/var/backups/capstone-*` 전반, history job/head/parent payload, receipt, raw state history 및 migration/stop/HUP intent는 삭제 대상이 아니다. 관련 기능이 이를 참조하는지 완전히 증명하지 못하면 계속 보호한다.

## 원본 유지 복사와 삭제 검토

`archive_copy_eligible`은 root:root0400/nlink1, 정확한 dev/inode/bytes/SHA256·SHA1, 읽기 전후 안정, 공유 vector lock, 해당 inode를 쓰는 writer FD가 0이라는 관측만 요구한다. 일반 회전 이력이 없거나 source pins가 특수 rebind로 바뀌어도 원본 유지 복사는 가능하다. 허용된 링크 수는 운영 범위를 좁히기 위해 **정확히 1**이다.

`deletion_review_ready`는 위 조건에 다음을 추가한다.

1. SHA로 결속한 `old_closed → readers_drained → publish_pending → active` 및 현재까지 연속된 일반 전이. `old_closed`의 inode/bytes/SHA256, 두 reader의 EOF offset, Wazuh 전체 SHA1을 실제 봉인본과 대조한다.
2. 양 엔진 현재 active, candidate를 가리키는 current/pending·reader alias·writer pointer가 없음, vector-stop/writer-reopen/output-resume/migration 작업의 미완료 참조 없음. source pins를 바꾸는 특수 전이는 이 후보가 일반 전이로 승인하지 않는다.
3. 최초로 위 사실을 검증한 immutable 영수증의 `first_verified_at_epoch`부터 2,592,000초 경과. 다음 실행에서 기존 영수증을 그대로 사용한다. 원문 mtime, 백업 디렉터리 mtime, 같은 영수증을 다시 읽은 시각으로 최초 시각을 바꾸지 않는다. 관측 시각이 최초 시각보다 이전이면 보류한다.
4. A 압축본의 private 복원 SHA/bytes, B에서 보관된 동일 manifest/gzip SHA/bytes 및 **B private 복원** SHA/bytes가 일치함.

검토가 준비돼도 출력은 `delete_authorized:false`, `automatic_deletion:false`다. 현재 도구에는 원본 삭제 경로가 없다. 실제 삭제 구현은 fresh 공유 lock·참조/FD·inode/SHA 재대조와 보존 영수증의 신뢰 경계를 별도 검토해야 한다. 수명 도래 후보가 없으면 자동 삭제 0이 정상 결과다. B90일도 검토 주기이며 B payload/receipt 자동 삭제가 아니다.

## 기존 상태를 입력으로 만드는 방법

순수 `evaluate.sh SNAPSHOT.json`은 **오프라인 정책 검사**다. JSON에 적힌 true가 실제 관측인지 인증하지 않으므로 항상 `observation_authenticated:false`를 반환한다. 운영 수집기는 부모의 고정 경로·root 권한·lock·runtime pin 검사를 별도로 수행해야 한다.

고정 입력 원천은 다음과 같다.

| 원천 | 사용 필드·검사 |
|---|---|
| `/var/lib/capstone-raw-operations/{suricata,modsecurity}/state.json` | 기존 `state.jq`의 전체 exact schema. root0600/nlink1/canonical/SHA·전후 동일, 양 엔진 active |
| 같은 디렉터리의 `history/<revision>-<sha256>.json` | root0400/nlink1/canonical, 파일명 revision/SHA와 내용 일치. 필요한 구간 전수; 최대 1024개 |
| `.../logs/{suricata,modsec}/capstone-managed/generation-%010d.jsonl` | 봉인본 root0400/nlink1, 실제 dev/ino/bytes/SHA256·SHA1·전후 identity |
| `.../logs/suricata/eve.json`, `.../logs/modsec/audit.log` | 두 alias의 실제 dev/ino가 해당 current와 동일하고 후보와 다름 |
| Suricata `capstone-managed/active.jsonl`, WAF `audit-path.conf` | writer target이 해당 current. WAF pointer는 exact root0444 내용/SHA·단일 고정 generation 경로 검사 |
| `/var/lib/capstone-raw-operations/vector-stop-intent.json` | lstat 기준 부재. dangling symlink도 부재가 아님 |
| 각 engine `writer-reopen-intent.json` | 같은 부재 계약. 현재·보존된 intent가 요구하는 state 파일은 지우지 않음 |
| `/var/lib/capstone-vector-maintenance/resume.pending` 및 초기/rebind ledger | pending/진행 중 전환이면 삭제 검토 보류. 원본 유지 복사는 별도 안정 관측으로 판단 |

정책은 기존 [state.jq](../../../normalization/vector/raw-operations/state.jq)의 SHA `3db6baef5c679521bdc257cbe1aca66fd6884714f734a1778ca27b249e40a775`를 확인하고 그대로 구조 검증에 재사용한다. 운영 파일이나 그 스키마를 수정하지 않는다. state CAS는 이전 state를 history에 저장하지만 active는 proof를 비우므로 현재 state 한 개만으로 과거 소비를 판정할 수 없다.

snapshot exact 키는 `policy.jq`의 `input_shape`다. `current`는 양 engine의 `{sha256,state}`, `chain`은 해당 engine의 동일 wrapper 배열이다. 정상 chain의 처음 네 항목은 closed/drained/publish/active이고 마지막 항목은 현재 state와 SHA까지 같아야 한다. history가 부족하거나 특수 rebind를 해석할 수 없으면 `chain:[]`로 남겨 복사만 검토한다. 잘못된 history를 정상으로 메우거나 proof를 새로 만들지 않는다.

`capture`의 complete/stable/shared_lock_held/host_pins_match/raw_guards_passed/intents_absent/writer_fd_zero/references_clear는 **수집기가 실제 확인한 사실**이어야 한다. 정책은 state와 영수증의 canonical JSON+LF SHA를 직접 재계산하고 최대 4MiB metadata만 읽는다. raw 내용은 이 snapshot에 넣지 않는다.

## 압축·B private 복원 함수

`bundle-lib.sh`는 Linux/root 라이브러리다. 직접 실행은 exit78로 거절한다. 라이브러리를 source하기 전 고정 SHA·root 소유를 검증하고, 운영자가 아래 순서를 고정한 한시 wrapper에서만 호출한다. runtime/service를 새로 배포하는 도구가 아니다.

1. A에서 기존 `/var/lib/capstone-automation/ansible/vector.lock`을 공유로 얻고, fixed native writer gate가 해당 dev/ino에 writable FD0임을 확인한다. `capture`를 완료하고 source metadata를 private root0400 canonical 파일로 고정한다. `source` exact 키는 `lc_source_meta`와 같다.
2. root0700 `/var/backups/capstone-raw-retention/{archives,work}` 또는 검토된 private native fixture 아래에서 `lc_pack SOURCE SOURCE_METADATA NEW_BUNDLE WORK_PARENT`를 호출한다. SOURCE는 고정 두 raw 디렉터리의 generation 파일만 가능하다. NEW_BUNDLE은 아직 없는 1회성 디렉터리다.
3. 함수는 source FD를 연 뒤 identity를 재대조하고, SHA256/SHA1을 확인한 후 gzip을 만든다. 압축 후 source/metadata를 다시 확인하고 bundle 두 파일을 fsync한다. private 복원이 정확히 맞아야 `capstone-sealed-raw-archive-v1` 결과가 나온다. source는 수정하지 않는다.
4. B 신규 root0700 incoming 디렉터리에 `manifest.json`, `payload.jsonl.gz` 두 파일만 전송해 root0400/nlink1로 보존한다. `--delete`, `--remove-source-files`, `--inplace`, 기존 경로 덮어쓰기는 사용하지 않는다. 전송 성공 후에도 원본 A bundle은 유지한다.
5. B의 고정 machine ID에서 `lc_b_receipt BUNDLE WORK_PARENT`를 호출한다. manifest exact schema·압축 SHA/크기·private 복원 SHA/크기, 두 파일의 전후 identity와 fsync를 확인한다. 반환한 `capstone-sealed-raw-receipt-v1` JSON을 **호출자가** 신규 root0400 영수증으로 create-exclusive·fsync·SHA 확인 후 게시한다. 이 라이브러리 stdout 자체를 게시된 영수증으로 간주하지 않는다.
6. A에서 실제 B 영수증 SHA와 내용을 신뢰된 연결로 확인해 보존한다. 삭제 검토용 최초 영수증은 엄격 proof가 준비된 경우에만 별도로 생성하며, 원본이 이미 있으면 exact 재사용한다. 일부 생성 후 실패한 디렉터리/영수증은 자동 덮어쓰기·재생성하지 않고 inspect 대상으로 남긴다.

`lc_verify_bundle BUNDLE WORK_PARENT`는 A/B 공통 복원 검증 함수다. gzip에는 추출 pathname이 없고, 선언 bytes + 최대 한 block의 출력 제한·CPU120초·wall120초로 복원한다. 한 파일은 최대 2GiB, 압축본은 최대 2GiB+8MiB다. 시간/CRC/크기/SHA 실패는 성공한 복원이 아니다. 전체 wrapper의 시간 예산은 root 실행 단계에서 별도 고정한다.

## 일반 백업과 자동 검토의 후속 최소 경계

일반 백업은 참조 중이어도 **원본 유지 보존**은 가능하다. 단순 `tar` 성공으로 정적 snapshot을 증명하지 않는다. 고정 allowlist 디렉터리의 타입/metadata/전수 파일 SHA를 복사 전후 대조하고, private snapshot을 만들고 같은 목록으로 압축·B private 복원을 검증해야 한다. symlink·mount·불안정/미완료 파일은 보류하며 private key/credential이 있는 범위는 별도 보안 정책 없이 복사하지 않는다. 이번 raw 라이브러리는 임의 백업 디렉터리 인수를 받지 않는다.

기간 후 자동 실행을 추가할 때도 **검토 worker**가 먼저다. root immutable first 영수증을 읽어 시각을 보존하고, 최신 상태·참조·B 복원 증거로 위 정책을 다시 계산해 bounded status만 기록한다. 신규 전송 계정, 주기 worker, 삭제 executor, B90일 삭제는 아직 구현·설치하지 않았다. first 영수증과 원래 state history를 자동 정리하는 경로도 없다.

## 검증

- 로컬: `bash test-policy.sh` → 51개 PASS. 현재/기록 분리, EOF/연속 전이, 특수 pin 변경 거절, first 시각 보존·역행, 복사/삭제 분리, remote digest/bytes 결속, duplicate/extra JSON, state/receipt SHA를 검사한다.
- Linux root: `bash test-bundle-native.sh` → **A/B 각 16개 PASS**. 고유 `/var/tmp/capstone-lifecycle-native.*`의 synthetic raw에만 gzip·private 복원·변조/링크/모드/기존 bundle 거절·조건부 fsync 실패를 시험했고 fixture를 정리했다. native fixture 자체는 운영 원문, Docker/systemd, SSH를 호출하지 않는다. 검증 source는 library `c7094e67…`, fixture `e884a28b…`다.
- 최초 A/B 시험은 12개 통과 뒤 `bundle_unsafe_mode`의 시험용 bundle 이름에 금지된 밑줄이 있어 거절됐다. 당시 결과는 보존했으며, fixture 이름만 하이픈으로 바꾸고 보관 root를 기존 용량 감시에 포함되는 `/var/backups/capstone-raw-retention`로 확정한 후 위 16개를 재검증했다. 최초 실패를 실제 source 복사/복원 실패로 기록하지 않는다.
- `bundle-lib.sh`의 source/devino 관측은 전체 호스트 FD 전수 무참조 증명이 아니다. live writer gate와 fresh 수집 책임은 호출자에게 남는다. 테스트의 schema true를 실제 관측으로 승격하지 않는다.

## 10:21 KST 후속 확인

B의 원격 영수증5개를 A root0400 파일로 보존했고 양쪽 SHA가 일치했다. A/B 압축본을 각각 다시 복원해5개씩 통과했다. 기존 작업 인벤토리 일반파일이 `/var/backups` 최상위에 있어 용량 감시의 디렉터리 계약을 거절하던 문제도 확인했다. 해당 A34,367B/B1,719,512B 파일을 기존 `capstone-tools-followup-20261015-final` 폴더로 옮기고 내용SHA·inode를 보존했다. 이후 감시 `ok/complete`, A18%·backup31,043,922B/B26%·backup23,607,238B다. 이 후행 확인으로 앞선 B영수증 A보존 대기 표기를 정정한다.
