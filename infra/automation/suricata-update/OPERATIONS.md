# 고정 오프라인 후보의 운영 절차

이 절차는 기존 이미지에 포함된 Suricata Update 1.3.8을 **현재 활성 규칙의 후보 생성·검증 도구**로 사용한다. 기존 승인 worker와 `all.rules == ET 원본 + local`의 바이트 합본 계약은 유지한다. 새 ET 다운로드, 주기 업데이트, flowbit 의존 규칙의 자동 활성화, 전체 후보의 운영 게시, reload/restart는 연결하지 않는다. MCP·LLM 실행 권한도 추가하지 않는다.

**2026-10-16 후속:** 조회용 파일 정의 집계를 추가한 현재 A 실행기와 저장소 `compare_rules.py`의 pin은 `156b88d0ac60c85df96ce05961b911cd5bc28ddb65b0df3656134e8a17015c6c`다. 아래 10/15 설치 소스·검증 증거 및 `d937c7…` pin은 당시 스냅샷으로 보존한다. 새 시험은 검토된 최신 비교 소스와 정확히 일치하는 실행기 사본·재확인한 입력을 **새 root 전용 source 디렉터리**에 준비한 뒤 수행한다. 설치 스냅샷의 pin만 바꾸거나 과거 통과 결과를 재사용하지 않는다. 이번 갱신에서는 updater·native 시험을 재실행하지 않았다. [갱신 근거와 범위](../../hermes/rule-inventory-validation-20261016.json).

2026-10-15 v6에서는 원본/후보 활성 규칙52,495개가 같고 추가·제거·변경0, 예외SID2034802/2034806 검증이 통과했다. 이어 격리 native `-T`에서52,495 loaded/failed0/skipped0을 확인했다. [후보 결과](native-candidate-validation-2026-10-15.json)와 [구문 결과](native-syntax-validation-2026-10-15.json)를 함께 읽는다. 후보 생성 결과의 `native_syntax_verified:false`는 생성 당시 상태이며 나중 결과를 덮어쓰지 않는다. PCAP replay와 운영 규칙 변경은 이번에 수행하지 않았다.

## 영구 보관 위치

2026-10-15 아래 경로의 영구 반입·보관과 고정 staging17개 정리를 완료했다. [후행 배포 기록](deployment-validation-2026-10-15.json)의 archive 영수증을 기준으로 확인한다. 서버에는 이 후행 문서 수정 전10파일 스냅샷이 설치돼 있고 그 바이트/SHA는 유지한다. 전체 작업 임시 경로 정리는 별도다.

| 경로 | 내용과 권한 |
|---|---|
| `/opt/capstone-automation/project/infra/automation/suricata-update` | 검토된 candidate/compare/pins, native 검증기, 순수시험, 문서·결과. root 소유, 일반 사용자 쓰기 금지. Python 실행 소스와 manifest는 root0400/nlink1로 보관 |
| `/var/backups/capstone-suricata-update-20261015` | root0700. 원본별 metadata·후보·로그·검증 결과·보관 manifest. 보관 파일 root0400, 원문은 A에 유지 |

새 daemon/unit/timer를 설치하지 않는다. `/usr/bin/suricata-update`, 설치된 Python 모듈, Suricata 실행 파일과 승인 worker도 바꾸지 않는다. `verify-native-a.py`는 이번 v6 job/PID에 고정된 일회성 증거용 도구이며 다음 후보를 자동 검증하는 범용 CLI가 아니다.

## 후보 생성 한 번의 경계

1. 관리자는 고정 A machine-id, manifest의 정확 CID/image, 현재 PID/StartedAt, `/rules`의 RO mount, source/worker/규칙 SHA를 확인한다. 기존 rule-change lock을 먼저, Vector lock을 다음에 잡는다. 기존 배포 도구와 root 권한으로만 수행한다.
2. root 전용 새 source 디렉터리에 `candidate.py`, `compare_rules.py`, `native-pins-2026-10-15.json`, 승인 worker의 해시 고정 사본을 전달한다. 전달 후 SHA·소유·쓰기 권한을 확인한다. 컨테이너 source 경로와 고유16자리 lowercase hex attempt는 관리자가 고정하며 외부 요청 인수로 받지 않는다.
3. 정확 CID의 root에서 기존 Python으로 아래 argv를 한 번 실행한다. 외부 Docker 호출은 TERM300초/KILL10초 등 유한 상한을 둔다. 내부 updater는120초와 private PGID 정리 경계를 갖는다. 시간 초과를 성공이나 재실행 승인으로 해석하지 않는다.

   ```sh
   /usr/bin/python3 -B /tmp/OPERATOR_SOURCE/candidate.py \
     /tmp/OPERATOR_SOURCE/native-pins-2026-10-15.json \
     /tmp/OPERATOR_SOURCE/rule_change_executor.py 2026101500000001
   ```

   `OPERATOR_SOURCE`와 예시 attempt를 그대로 재사용하지 않는다. 기존 job 디렉터리가 있으면 새 입력으로 덮어쓰지 않고 거절한다. 실제 v6 job은 `/tmp/capstone-suricata-update-20261015-0819000000000004`다.
4. rc0만 보지 않고 `status=candidate_compared_native_test_pending`, `protected_files_unchanged=true`, 원본/후보52,495, 추가·제거·변경0, `local_overrides_verified=true`, 예상 output 하나와 SHA를 모두 확인한다. 불일치하면 같은 attempt를 재송신하지 않는다. 차이를 보존하고 별도 검토한다.
5. 운영자 사후검사에서 CID/image/PID/StartedAt, 원본 규칙·config·worker SHA가 유지돼야 한다. 생성 결과는 영구 증거에 보관하고 운영 `/rules/all.rules`에는 복사하지 않는다.

기존 ET의 비활성 행을 원문 그대로 updater에 넣으면1.3.8의 flowbit 해결기가 추가 규칙을 활성화할 수 있다. 실제 v5에서292개가 추가되어 거절됐다. v6은 원본3개를 보존하고 설치본 SHA 고정 native parser로 현재 활성 행만 파생 입력으로 만든 뒤, 다시 원본 전체 활성 집합과 전수 대조한다. resolver를 수정하거나 차이를 무시하지 않는다. 규칙/image/worker가 바뀌면 현재 고정값은 거절하도록 유지하고 새 검토로 pins를 갱신한다.

## 격리 구문 시험과 게시 승인

실제 v6 후보는35,666,630B, SHA `0da12c9990b80e346f18cb7c370960010bc5fccc8a740dc2d1892c3664afb436`다. `verify-native-a.py`는 기존 shadow helper SHA `6dcf1556f89c8882a422cf92a3c8caa90bbdcdf71b809d0224587fe45b17db15`만 사용한다. 이 검증기가 직접 rule-change→Vector lock을 잡으므로 같은 잠금을 바깥에서 다시 잡지 않는다.

Suricata `-T`도 출력 초기화를 하므로 live YAML에 `-l`만 추가해 실행하지 않는다. 검증기는 별도 mount/network/PID namespace에서 운영 루트를 RO로 만들고 로그/run/tmp만 private RW로 가린다. 후보는 `/rules/all.rules`에 RO bind한다. exact loaded/failed/skipped, 운영 source·raw inode 불변과 private tree 제거까지 확인해야 구문 성공이다. 고정 helper/source 전달 및 native 결과 경로는 [README](README.md#native-검증과-승인-경계)를 따른다.

후보의 **실제 운영 게시 방식 변경**은 이번 도입 범위에 없다. 이를 나중에 제안한다면 기존27개 PCAP 회귀, 규칙 차이와 ET 예외, 실제 운영 합본 byte 계약, 승인 worker 권한을 별도로 검토해야 한다. parsed map 동일성과 `-T` 성공만으로 모든 트래픽의 동작 동등성을 주장하지 않는다.

## 보관과 staging 정리

관리자는 다음 자료를 영구 경로에 복사하고 각 파일 bytes/SHA, source/attempt 관계를 manifest로 기록한다. 파일과 부모 디렉터리를 fsync한 뒤 원본/보관본 SHA를 다시 대조한다. 원문 규칙과 native 로그는 서버 밖에 출력하지 않는다.

- 최종 source/pins/worker 사본 또는 같은 SHA의 영구 보관 참조, 원본 ET/local/all3개의 SHA와 보존 위치. 동일 원문을 실패 attempt마다 중복 보관할 필요는 없다.
- v6 파생 입력 정보, `projection.json`, `argv.json`, `update.yaml`, `comparison.json`, `result.json`, version/update 로그. 최종 후보는 `gzip -n` 등 기존 도구로 압축 보관할 수 있으며 **압축 파일 SHA와 해제된35,666,630B/원본 SHA를 함께 검증**한다.
- v2–v5 실패별 sourceSHA·result/log/pins/comparison/argv 중 실제 생성된 자료. 없는 파일을 성공처럼 채우지 않는다. v5의292개 추가SID와 dependency metadata를 별도 보존한다. 실패 디렉터리의 동일 fullET 복제본은 전수 보존 대상이 아니다.
- 격리 native source/helper SHA, 결과JSON, 로그SHA·원본 로그, cleanup/운영 불변 증거. 실패 이력과 뒤의 성공 증거를 구분한다.

영구 보존 대조가 완료된 후에만 관리자가 이번 작업의 정확 staging/job 경로를 재조회해 정리한다. inventory가 바뀌거나 사용 중인 process/mount/FD가 있으면 보류한다. 운영 rules, raw, CP, 승인 worker, 기존 guard가 참조하는 backup은 이 정리 대상이 아니다. 이 디렉터리의 후보 도구는 영구 보관본이나 운영 입력을 자동 삭제하지 않는다.
