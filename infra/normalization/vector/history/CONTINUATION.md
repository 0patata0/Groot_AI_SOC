# 검증된 부모 배치 뒤의 수동 회수

**2026-10-14 10:43:04~10:43:05 KST, A에서 실제 후속 한 배치 481건/203,010bytes 보존을 완료했다.** 부모 두 SHA와 원문은 그대로이며 child의 `source_range_exhausted=true`를 확인했다. 이는 고정 boot/kernel/cutoff 범위의 관측 끝이며 원래 boot 전체 무손실이나 ACK 경계 복구를 뜻하지 않는다. child ID `bf58e25ad123f6d84c54b66ced22e186750c2328f67d59439b1bccb4c47fae68`, payload SHA `5e96e0e71bb8c67bf5e751c5d71fca467d26058440229503fe45c8036e70fe58`, manifest SHA `18c79f4f8473da11bd7edf5e6f472e22aeb4d43c5fb2dcc5e08117ea87f4e697`다. [실제 후속 결과](continuation-deployment-2026-10-14.json).

Vector/wazuh-agent의 PID·InvocationID·ActiveState는 전후 동일했고 원문/cursor는 A root 경로에만 남겼다. 추가 배치 loop·B 전송·운영 재주입·체크포인트·서비스·원본 삭제는 실행하지 않았다. 두 보존 파일의 합계는 1,481건/621,820bytes다.

앞서 10:39:24~10:39:47 KST A의 SHA 고정 분리 실행본에서 기존25개+후속24개 native 합성 시험을 모두 통과했다. 기존 첫 배치·v1 실행 소스5개는 변경하지 않았다. 첫 배치의 실제 보존 결과는 [기존 실측 JSON](deployment-2026-10-14.json), 합성 결과와 실행 SHA는 [후속 검증 JSON](continuation-validation-2026-10-14.json)에 분리해 남겼다.

고정 A 운영자 진입점은 `bash continue-previous-boot.sh <parent_batch_id> <expected_payload_sha256> <expected_manifest_sha256>`다. 인수는 각각 소문자 64hex이며 cursor·파일 경로·실행 명령을 받지 않는다. 경로는 `/var/lib/capstone-vector-history/batch-<ID>`로 고정되고 root/machine-id와 권한 검사를 유지한다. 부모가 현재 boot이거나 고정 종료 시각이 미래이면 거절한다. LLM/MCP 또는 sudoers에 이 진입점을 추가하지 않는다.

부모 원문과 manifest의 **두 기대 SHA**를 호출자가 고정한다. 원문 bytes/SHA·JSONL 메타데이터·첫/끝 cursor·boot/cutoff·정책별 batch ID도 다시 계산한다. 기대 manifest SHA까지 고정하므로 추가키·공백만 바뀌어도 거절한다. 부모가 이미 `source_range_exhausted=true`라면 추가 회수를 만들지 않는다. 원본 부모나 이전 완료 이름을 덮어쓰지 않는다.

## 경계 판정

1. 부모 끝 cursor로 `--cursor`/`--lines=+2`를 조회한다. 첫 행은 정확한 부모 끝 cursor이고 다음 행이 하나 있어야 한다. 가까운 다른 cursor나 예상 밖 EOF면 부분 보존으로 중단한다.
2. 같은 고정 boot/cutoff에서 `--after-cursor`/`--lines=+1000`을 실행한다. child 첫 행은 1번에서 확인한 다음 cursor와 같아야 하며 부모 끝과 달라야 한다. parent/child monotonic 시각은 비감소여야 한다.
3. child 끝 cursor로 최대 두 행을 재조회한다. 정확한 첫 행을 확인한 뒤 다음 행 존재 여부로 child의 `source_range_exhausted`를 판정한다.
4. 부모 끝 cursor를 다시 한 행 재조회하고 부모 payload/manifest SHA를 재검사한다. 회수 사이 경계가 사라지거나 부모 파일이 바뀌면 완료 처리하지 않는다.

15초 공유 capture/JSON 검증 예산과 새 원문 총32MiB, child 최대1,000건, timeout/SIGPIPE/잘린 JSON/LF 거절은 기존 함수를 재사용한다. 기존 부모 검증에 읽는 보존 파일 자체는 새 capture 바이트에 더하지 않는다. 최종 SHA·파일/디렉터리 fsync·원자 rename은 이 시간 예산 밖이다. 실패한 새 원문은 `partial-*` 시도별로 남기며 부분 상태에서 EOF를 주장하지 않는다. 강제 종료·디스크 오류와 중간 journal vacuum의 무손실은 보장하지 않는다.

같은 부모 기대값으로 재실행하면 같은 child ID를 찾는다. 완료 child의 권한·SHA·JSONL 메타데이터·부모 결속을 검증하고 동기화한 뒤 재사용하며 journal을 재조회하지 않는다. B 수신기와 달리 호출 인수에 child의 외부 기대 SHA는 없으므로 A root 소유 보존 디렉터리와 잠금을 신뢰한다. 부모의 모든 조상 원문을 재귀 검증하는 기능은 없다.

## B 수신기와 공유하는 식별 계약

v1 정책은 `previous-kernel-batch-v1`, 후속 정책은 `previous-kernel-continuation-v1`이다. 각각 아래 항목을 **순서대로 UTF-8 문자열 한 행+LF**로 연결하여 SHA256을 계산한다. 임의 JSON 직렬화의 SHA가 아니다.

| 정책 | 순서대로 해시할 항목 |
|---|---|
| 기존 v1 | policy, boot_id, until_epoch_us, `1000`, `33554432` |
| 후속 | policy, parent.batch_id, parent.payload_sha256, parent.manifest_sha256, boot_id, until_epoch_us, `1000`, `33554432` |

완료 manifest의 기존 필드는 동일하다. 후속에서 추가·변경되는 부분은 다음과 같다.

```json
{
  "policy": "previous-kernel-continuation-v1",
  "selection": {"order": "after_verified_parent_cursor"},
  "parent": {
    "batch_id": "64lowerhex",
    "payload_sha256": "64lowerhex",
    "manifest_sha256": "64lowerhex"
  },
  "continuation_boundary_verified": true,
  "continuation_phase": "verified"
}
```

`parent`는 위 3개 키만 허용한다. 완료 조건은 `status=complete_batch`, `reason=verified`, `records_verified=true`, `producer_exit=consumer_exit=0`, `source_range_exhausted` boolean, 기존 `record_metadata`의 count/첫끝cursor/첫끝realtime/첫끝monotonic 일치다. 부모와 child는 같은 boot/cutoff다. 원래 ACK 시작점을 알 수 없다는 표시는 유지한다.

B가 자기 사본의 payload/manifest 기대 SHA와 ID·JSONL 메타데이터를 대조하는 것은 독립 파일 수신 검증이다. A에서 실제 journal 경계를 재조회했다는 `continuation_boundary_verified`는 A의 실행 증거이며, B가 직접 journal을 검사했다는 뜻이 아니다. B에 모든 조상 파일이 있다는 조건이나 Wazuh 분석·색인 ACK를 이 manifest가 보장하지 않는다.

[`test-continuation-native.sh`](test-continuation-native.sh)는 실제 journal 대신 합성 cursor 순서 자료를 사용하는 종료형 테스트다. 정상 child와 다음 child/EOF, 동일 호출 재사용, 원본 부모 불변, nearest 대체, 중간 경계 소실, 첫 행 누락/중복, JSON/LF 오류, timeout, cap와 partial 보존, 부모 payload/manifest/ID 변조의 24개를 통과했다. 기존 25개도 같은 복사본에서 다시 통과했다. 시험 전후 소스 SHA가 같고 자기 합성 자료 디렉터리는 0개로 정리됐다. 첫 실행은 후보 디렉터리의 0700 확인에서 시험 전에 중단됐으며, 본인 소유 staging만 0700으로 고정한 뒤 실행했다. 실제 journal·운영 wrapper·서비스·체크포인트는 사용하거나 바꾸지 않았다.
