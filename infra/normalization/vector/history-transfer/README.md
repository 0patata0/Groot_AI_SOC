# 닫힌 history 배치의 B 파일 보관 수신기

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

**11:02 KST 마감:** 소스는 A/B `/opt/capstone-automation/project/infra/normalization/vector/history-transfer/`에 보관했고, 실제 두 배치의 재검증을 해당 보관본으로 통과했다. 증거는 `project/evidence/history-20261014/`, 변경 전 소스는 `/var/backups/capstone-history-source-20261014/`다. 작업용 source staging·합성자료·사용자 upload·Mac 임시97파일은 제거했다. 운영 A/B 원본·수신증과 B root incoming은 보존한다. [정리 집계](cleanup-2026-10-14.json).

**실측:** 후속 회수까지 포함한 native 합성144개가 통과했다(export25/continuation24/receiver41/promotion33/ACK21). 실제 A→B 합성3건/666bytes에서 첫 B 응답을 버린 후 같은 수신증·유일 배치1개를 확인하고 A의 반복 저장도 검증했다. 실제1,000건+481건도 두 SHA/fsync/원자 저장 후 첫 수신증을 유지했다. A/B에서 합계1,481개 cursor가 유일하고 원본manifest는 계속 remote_receipt=false인 최초 기록을 보존한다. 이후 수신 사실은 별도 receipt가 증명한다. [실측 JSON](deployment-2026-10-14.json).

운영 경로는 `send-batch.sh`(A 원본→B 기존 groot_b 전용 임시경로), `promote-upload.sh`(B root 제한 복사), `receive-batch.sh`(B 보관), `acknowledge-receipt.sh`(A 별도 수신증)의 순서다. 세 입력은 batch ID·payload SHA·manifest SHA다. A 수신증은 `/var/lib/capstone-vector-history/receipts/<ID>/`의 root0400 파일2개이며, B 원본과 수신증은 아래 batches 경로다.

송신은 이 작업에서 검증한 B ED25519 키를 고정하고 기존 관리자 인증을 사용한다. 현재 작업의 인증 supervisor는 비밀을 sealed memfd에 일시 전달했으며 새 키·계정·권한을 설치하지 않았다. `CAPSTONE_AUTH_FD_PATH`는 비밀값이 아닌 root 메모리 FD 경로다. 사용자 업로드 경로는 `/var/tmp/capstone-history-upload-20261014/<ID>/<payloadSHA>-<manifestSHA>/`로 고정된 일회성 운영 경로이며 정리 후에는 없다. 향후 재전송은 관리자가 이 경로/인증 사전조건을 다시 준비해야 한다. 상시 데몬·자동 재시도·LLM 호출 권한은 없다. 비밀 일반파일/argv/env/log 생성은 없지만 메모리 swap까지 배제한 보장은 아니다.

부분 입력·변조·용량 부족·동기화/rename 실패·응답 유실은 격리 시험에서 확인했다. 실제 운영 디스크를 채우거나 전원을 끄거나 네트워크를 끊지는 않았다. B 파일 저장 확인을 Wazuh/Indexer ACK로 사용하거나 A 원본 삭제의 자동 근거로 삼지 않는다. 운영 raw 회전과 보존 배치의 Vector 격리 재생은 다음 단계다.

2026-10-14 작성. **10:55~10:57 KST 실제 두 배치1,481건·621,820bytes의 B 보관과 A 수신증 저장까지 완료했다.** 별도 데몬·패키지·Wazuh 입력·LLM 실행 권한을 추가하지 않는다. 기존 Bash, jq, GNU coreutils와 flock을 사용한다. A의 원본 배치는 지우거나 manifest를 수정하지 않는다.

## 고정 호출과 경로

운영자용 진입점은 `receive-batch.sh <batch_id> <expected_payload_sha256> <expected_manifest_sha256>`이다. 세 값 모두 소문자64자리 hex만 허용한다. 임의 경로·명령·실패 주입 인자는 없다. B의 고정 machine-id와 root 실행, root 소유·일반 사용자 쓰기 불가 source를 확인한 뒤 깨끗한 환경의 별도 Bash worker를 호출한다. 기존 `../history/validate-records.jq`를 SHA256 `2470fab15dfde40540d60a3e47f4de8a6f5520f46acb231d1067895c770ffaa9`로 고정해 함께 배포해야 한다.

저장 루트는 `/var/lib/capstone-history-receipts`다.

| 상대 경로 | 의미 |
|---|---|
| `incoming/<batch_id>/<payload_sha>-<manifest_sha>/` | root가 승격한 입력 `kernel.jsonl`, `manifest.json` 두 파일만 허용 |
| `partial/<batch_id>.<attempt>/` | 수신기가 별도로 만든 제한된 크기의 스냅샷과 미완료 작업 |
| `batches/<batch_id>/` | 완료 이름. payload·A manifest·B receipt·receipt SHA의 네 파일 |
| `.lock` | root0600 전역 flock. root 승격 작업도 이 lock과 조율 |

디렉터리는 root0700, 입력 파일은 root0400 또는0600이며 symlink·hardlink·비정규 파일을 거절한다. 완료 파일은 root0400이다. 기존 디렉터리·파일의 잘못된 권한을 자동 완화하지 않는다. source/receiver machine-id는 고정 운영 결속이며 journal 원문에서 발급한 서명이나 실제 `_MACHINE_ID` 검증으로 해석하지 않는다.

A→B rsync 인증과 일반 운영자 upload 디렉터리에서 root incoming으로 승격하는 절차는 부모 운영 절차가 담당한다. **사용자가 쓸 수 있는 upload 경로를 수신기 입력으로 직접 연결하지 않는다.** root 승격이 lock을 해제한 뒤 수신기를 호출한다. 잠금을 잡은 채 호출하면 재진입을 허용하지 않고 거절한다.

## 검증과 저장 순서

1. A에서 확정한 payload SHA와 **원본 manifest 바이트 SHA**를 인자로 받는다. 배치 ID는 SHA를 대신하지 않는다.
2. root incoming을 별도의 private partial로 제한 복사한다. GNU `dd`의 `nofollow`, `nonblock`, byte count를 사용하고 원본 dev/inode/크기/시각/권한을 전후 대조한다. 입력과 snapshot의 기대 SHA도 대조한다. payload 최대32MiB, manifest 최대64KiB다.
3. 허용 정책은 `previous-kernel-batch-v1`, `previous-kernel-continuation-v1`뿐이다. 정책·boot·cutoff·한도·후속 정책의 parent3개 SHA로 ID를 재계산한다. 완성 manifest의 범위·타입·건수·원문 크기·SHA를 검사한다. manifest의 중복 scalar 경로도 거절한다.
4. payload의 각 물리 행이 JSON이고 마지막 LF가 있으며 지정 boot/kernel/cutoff·중복 없는 cursor·monotonic 순서·최대1,000건을 만족해야 한다. 기존 jq 검증 결과 전체를 `record_metadata`와 대조한다. `source_range_exhausted=false`는 유효한 완료 배치다. 후속 정책의 `continuation_boundary_verified=true`는 **A producer의 선언**이며 B가 parent 원문이나 journal을 다시 조회했다는 뜻이 아니다.
5. 최초 receipt와 그 SHA를 만든다. 네 파일을0400으로 고정한 후 각각 fsync하고 partial 디렉터리·부모도 동기화한다. 같은 filesystem의 완료 이름으로 덮어쓰기 없이 원자 rename한다. `mv -n`의 종료0만 믿지 않고 partial 부재·최종 inode 일치를 확인한다.
6. rename 후 파일들과 완료 디렉터리, 양쪽 부모 디렉터리 동기화가 모두 성공해야 stdout으로 결과를 반환한다. 디렉터리가 새로 생성됐을 때도 부모를 동기화한다. 실패하면 성공 응답을 하지 않는다.

검증에는 제한된 parser 실행시간과 메모리를 사용한다. fsync의 전체 소요시간까지 짧은 고정시간으로 보장하지 않는다. 최소 여유 공간은32MiB+8MiB이며 whole-store quota는 없다. 기존 incoming·partial·완료 배치의 총량 제한이나 자동 삭제는 별도 운영 과제다.

## 재시도와 영수증 경계

완료 이름이 있으면 payload·manifest·receipt·receipt SHA·권한을 다시 검증하고 파일·디렉터리를 다시 동기화한다. **같은 ID에 다른 payload SHA 또는 manifest SHA는 충돌**이다. 응답 유실이나 마지막 디렉터리 fsync 실패 후 같은 기대값으로 재호출하면 검증된 최초 receipt를 반환한다. 오래된 incoming이 사라졌어도 기존 완료본 자체를 검증할 수 있다.

receipt에는 `stage=remote_file_preserved`, source/receiver machine-id, 고정 store ID, batch ID, 두 기대 SHA, bytes, records, policy, 최초 KST 수신시각이 들어간다. 원문·cursor는 없다. stdout은 이 필드와 `receipt_sha256`, `reused`만 출력한다. 저장 receipt의 최초 바이트·시각은 재시도에 바뀌지 않는다. `reused`는 응답별 값이다.

**`receipt_sha256`는 stdout 전체의 해시가 아니다.** A는 응답에서 `receipt_sha256`와 `reused`를 제거한 뒤 `jq -cS`가 출력하는 **LF 포함 canonical JSON 바이트**의 SHA를 대조한다. SHA는 인증 서명이 아니며 고정 SSH host key와 기존 인증된 운영자 경로에 의존한다. A receipt는 원본 source manifest와 별도의 파일로 동기화·원자 저장해야 한다.

최종 디렉터리가 보인다는 사실만으로 성공 처리하면 안 된다. rename 직후 중단되거나 fsync가 실패했을 수 있으므로 수신기의 재검증·재동기화 후 성공 응답이 필요하다. 이 수신점은 **B 파일 보관**이며 Wazuh 분석·Indexer 저장 ACK가 아니다. producer cursor 조회, 전체 이전 boot 복구, 전원 장애에서의 실제 내구성까지 독립 검증했다는 의미도 아니다.

## 분리 합성 시험

`test-native.sh`는 Linux의 자기 임시 디렉터리에 합성 payload만 만든다. 운영 machine-id 진입점이나 운영 store는 호출하지 않는다. private library의 sync/rename hook은 fixture worker 안에서만 바꾸며 운영 API나 환경 변수에 노출하지 않는다. 시험 종료 시 자기 합성 임시 디렉터리만 정리한다.

시험은 v1/v2, 재사용·최초 receipt 유지, ID/두 SHA 충돌, metadata 변조, 미완성/잘린 입력, symlink/hardlink/FIFO, 크기·타입·정책 제한, rename 전후 fsync 실패, `mv -n` no-op, 응답 유실, 저장본 손상과 원문 없는 고정 오류 출력을 포함한다. 실패 주입 시험 통과는 실제 전원 차단이나 디스크 장치 장애 검증과 구분한다. 2026-10-14 B의 기존 Bash 5.2.21, jq 1.7, GNU coreutils 9.4에서 native 41/41 PASS를 확인했다. `nice -n 10`과 외부 180초 제한을 적용했고 시험 임시 디렉터리 잔여는 0이었다. 실제 history 원문·운영 store·공개 수신 진입점은 사용하지 않았다. 정확한 소스 SHA와 검증 경계는 [receiver-validation-2026-10-14.json](receiver-validation-2026-10-14.json)에 기록했다.
