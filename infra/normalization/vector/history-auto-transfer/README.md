# 이전 부트 배치의 B 자동 보관

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

> **15분 자연 주기 확인:** 09:33:15~09:33:22 KST, Invocationc9e8e4e93b5b4ba593138707ef77bdc1, exit0/new0/reused18/13,741건. 첫활성화실행에이어실제다음주기를확인했다.

**2026-10-15 09:17 KST 운영 확인:** B 전용키 생성(09:14), A 읽기 전용 sender 설치(09:14:52), B 수신기 설치(09:15:09)를 마쳤다. 09:16:58 첫 전송에서 **18배치·13,741건·payload 5,799,184B**의 영수증 18개를 새로 검증했고, 09:17:29 재실행은 신규0·재사용18이었다. B 실제 저장 영수증과 기존 수동2배치의 SHA가 유지됐고, A18배치 아래207파일의 SHA·크기·inode 스냅샷도 전후 일치했다. private key는 B 밖으로 반출하지 않았고, 임의 SSH 명령 `false`는 rc65로 거절됐다.

타이머는 enabled/active이며 실행 종료 후15분 주기다. 활성화 직후 **09:17:57→09:18:04 첫 자동 실행 exit0**을 확인했다(Invocation `0d8a7084178e4696bb8753bd85942a57`, 신규0·재사용18·13,741건). 다음15분 자연 실행은09:33:04+AccuracySec30s 예정으로 아직 관측 대기이며, 최종 서버 증거의 영구 보관·정리도 진행 중이다. [검증 메타데이터](validation-2026-10-15.json), [A/B 설치 도구와 순서](deploy/README.md)를 참고한다.

배포 전 B 기존 Linux/rsync의 격리 runtime **33개**, 설치 helper **20개**가 통과했다. 실제 rsync의 두 SSH argv는 네트워크 없는 recorder로 먼저 확인했으며, 실제 SSH·최초 보존·재사용은 위 운영 결과로 별도 검증했다. runtime/installer 소스는 native 통과본에서 변경하지 않았다.

기존 수동 수신기와 A 자동 추출기는 수정하지 않았다. 배포 전 실측 A 저장소5,885,459B·B 수동2배치 저장소1,251,272B는 metadata를 포함한 저장소 수치이며, 위 전송 payload 합계와 구분한다.

운영자 일회성 검증에서 두 사전 오류도 보존했다. A 배치의 부가 metadata까지 포함한 파일 수를36개로 잘못 예상했다가 실제207개로 정정했고 원본 변경은 없었다. 첫 임의 SSH 명령 시험은 `-n`이 없어 원격 shell script의 stdin을 소비해 pull0으로 끝났고, `-n`을 넣은 다음 호출에서 위 최초 전송을 완료했다. 이 보완은 일회성 검증 스크립트에만 적용했고 runtime/installer는 그대로다.

## 경계

B root가 A의 완료 `batch-<64hex>` manifest만 먼저 조회하고, 배치별로 정확 `kernel.jsonl`과 `manifest.json`을 회수한다. SHA·정책별 batch ID·크기·행 수·기록 metadata는 [기존 수신기](../history-transfer/README.md)가 다시 검사한다. 같은 ID의 다른 manifest/payload는 거절하고 같은 바이트의 재시도에는 최초 canonical receipt를 재사용한다. 두 정책 `previous-kernel-batch-v1`, `previous-kernel-continuation-v1`만 허용한다.

성공 경계는 **B의 `remote_file_preserved`**다. A 원본·job·journal checkpoint를 수정하거나 삭제하지 않는다. A `remote_receipt=false` 원본도 유지하며 A 자동 ACK, Wazuh 분석·Indexer 색인·보안 전달 ACK, 원래 journal 전 범위 회수 완료를 주장하지 않는다. 실행 중 새로 완성된 배치는 다음 주기의 조회 대상이다. 배치 간 parent ancestry 전체를 B에서 다시 실행 검증하는 기능은 기존 수신기 범위에 없다.

A는 기존 distro `rrsync 3.2.7`의 고정 `-ro` 제한만 공개한다. 이 버전은 `-ro`에서 remove/delete와 서버 log-file을 금지하고 제한 디렉터리 밖 경로·copy-links·protect-args를 거절한다. [고정 버전 공식 소스](https://raw.githubusercontent.com/RsyncProject/rsync/v3.2.7/support/rrsync)를 기준으로 검토했다. 새 SSH 서비스 계정의 셸은 `/bin/dash`이며 로그인 profile/bashrc를 실행 경로로 추가하지 않는다. 이 키와 sudo 권한은 LLM/MCP/Hermes에 제공하지 않는다.

B rsync에는 삭제 옵션 자체를 넣지 않는다. 실제 3.2.7은 `--no-delete`를 지원하지 않아 첫 무네트워크 argv probe가 거절됐으므로 해당 옵션을 제거했다. A `-ro`의 delete/remove 거절은 별도 유지한다. native fixture의 두 실제 argv recorder case는 소켓을 열지 않고 설치된 rsync의 옵션·호출 형식을 검사한다.

## 설치 계약 — 위 시각에 설치 완료

| 호스트 | 원본 | 설치 경로·소유권 |
|---|---|---|
| A | `export-a.sh` | `/usr/local/libexec/capstone-history-export`, root:root0500 |
| A | `ssh-gate-a.sh` | `/usr/local/libexec/capstone-history-ssh-gate`, root:root0755 |
| B | `run-b.sh` | `/usr/local/sbin/capstone-history-auto-transfer`, root:root0500 |
| B | `worker-b.sh`, `transfer-lib.sh`, `ssh-b.sh`, `runtime.sha256` | `/usr/local/lib/capstone-history-auto-transfer/`, 부모 root0755·파일 root0400 |
| B | service/timer | `/etc/systemd/system/`, root:root0644 |

B에는 기존 receiver 5개를 현재 정확 SHA/권한으로 유지한다. `transfer-lib.sh`가 설치된 `/opt/capstone-automation/project/infra/normalization/vector/history-transfer`와 `../history/validate-records.jq`를 고정 확인한다. receiver 파일 SHA가 달라지면 자동 허용하지 않는다.

1. A `capstone-hist`가 없음을 확인하고 UID 중복 없는 시스템 계정, 잠긴 암호, `/bin/dash`, root 소유의 변경 불가 home을 만든다. 홈 `/var/lib/capstone-history-export`와 `.ssh`는 root0755, `authorized_keys`는 root0644로 공개키 읽기만 허용한다. 기존 계정이 있으면 재사용하지 말고 그 상태를 먼저 검토한다. shell/profile·사용자 sudo·그룹 권한을 추가하지 않는다.
2. B `/etc/capstone-history-transfer` root0700에서 `ssh-keygen -q -t ed25519 -N '' -f /etc/capstone-history-transfer/id_ed25519`를 **한 번만** 실행한다. private key root0600, 공개키만 A에 전달한다. 기존 키는 덮어쓰지 않는다. 비밀 키를 Mac으로 복사하지 않는다.
3. A 공개키의 옵션은 `from="10.200.10.10",restrict,command="/usr/local/libexec/capstone-history-ssh-gate"`로 고정한다. gate는 SSH 원래 명령 하나를 sudo helper에 전달하고 helper는 sender 명령·문자·길이·store·기존 rrsync/rsync SHA를 검사한다. sudoers는 `capstone-hist ALL=(root) NOPASSWD: NOSETENV: sha256:<fixed_exporter_SHA> /usr/local/libexec/capstone-history-export *` 한 항목만 허용하고 `visudo -cf` 검증 후 설치한다. wildcard는 단일 인수의 rsync 명령문을 위한 것이며 helper가 인수 수 1개와 read-only 문법을 다시 강제한다. sudoers에 다른 명령이나 환경 보존 예외를 추가하지 않는다.
4. 이미 신뢰하는 운영 접속으로 A의 ed25519 **공개 host key**를 받아 B `known_hosts` root0600에 `capstone-history-source-a ssh-ed25519 <public key>` 한 줄로 저장한다. 미검증 `ssh-keyscan` 결과를 그대로 신뢰하지 않는다. 연결 주소는 `10.200.10.1`, 계정은 `capstone-hist`, host alias·키 종류·strict checking은 고정이다.
5. B `/var/lib/capstone-history-auto-transfer`와 `work/` root0700, `.lock` root0600/0B를 새로 만든다. 기존 `/var/lib/capstone-history-receipts` root0700와 `.lock` root0600/0B를 확인한다. 부모 디렉터리와 설치 소스는 symlink·비root 쓰기를 허용하지 않는다. 생성한 파일/디렉터리와 부모를 fsync한다.
6. Linux 합성 시험 및 실제 SSH 명령 allow/deny 시험 후 `capstone-history-auto-transfer run`을 수동 1회 실행한다. stdout metadata, B 실제 canonical receipt, A 원본/job/CP 불변을 확인한 뒤 timer를 enable한다. 첫 성공만으로 다음 자연 주기까지 확인했다고 쓰지 않는다.

실제 A store `/var/lib/capstone-vector-history-auto/store` root0700, `.lock` root0600을 shared/nonblocking으로 읽는다. 잠금 중 최대 60초 sender만 실행하고 원본 파일을 쓰지 않는다. B 별도 전송 lock은 작업 전체, 기존 receipt lock은 incoming 공개/수신기 commit을 보호한다. 파일 `ssh-b.sh`는 root0400이며 rsync `-e '/bin/bash <fixed path>'`로 실행하므로 실행 비트를 추가하지 않는다.

## 상한·실패·재시도

- 완료 배치 조회 최대256개, A inventory 최대4096개 항목/1GiB, 파일 최대32MiB·manifest64KiB, 기존 receiver 최대1000행을 유지한다.
- B receipt+작업 저장소 합계와 예약 복사량을 합쳐 논리적 1GiB를 넘으면 중단한다. 디렉터리 항목8192개, 최소 여유40MiB에 이번 복사 예약량을 더해 검사한다. 이는 전용 워크플로의 용량 검사이며 filesystem quota나 별도 root 수동 쓰기까지 차단하는 기능은 아니다.
- rsync당65초, A sender60초, 네트워크 유휴30초·SSH connect5초, 전체600초+강제정리10초, unit620초, 메모리512MiB. 재접속/전송 재시도 loop는 없다. timer는 부팅3분 후, 실행 종료15분 후다.
- 자동 삭제 대상은 **해당 성공 호출이 만든 B transient incoming과 작업 디렉터리**뿐이다. 최초 수신기의 원자 commit+fsync 영수증 이후만 제거한다. 기존/manual incoming, B 완료 배치/영수증, A 파일은 삭제하지 않는다.
- 실패 작업은 B root0700 `work/run-*`에 남고 고정 phase/exit metadata만 출력한다. 자동 정리하거나 partial을 완료로 취급하지 않는다. 반복 실패가 저장소 상한에 닿으면 운영자 확인까지 중단된다. 다음 timer의 같은 ID 재조회는 기존 수신기의 멱등 검증을 사용한다.
- `status.json`과 `latest-batches.jsonl`은 최근 성공 snapshot이다. 실패 때 이전 성공 파일이 남을 수 있으므로 현재 unit result/관측 시각을 함께 본다. 최신 성공과 과거 실패를 섞어 전송 성공으로 판단하지 않는다. 원문·cursor·SSH 오류 원문은 stdout에 내보내지 않는다.

## 시험과 완료 조건

`test-native.sh`는 Linux root의 별도 `/var/tmp/capstone-history-pull-test.*`만 사용한다. SHA가 고정된 기존 receiver fixture 생성 함수를 재사용하고 private 복사본의 machine/store/source 경로만 바꾼다. 실제 SSH/계정/키/운영 store 호출은 없다. manifest 거절, 같은 ID 충돌, 첫 commit와 stable receipt 재사용, 수신 후 transient 정리, 용량 거절, raw 출력 차단을 검사한다. 함수의 조건문 호출에서도 검사 실패가 명시 전파되도록 A gate를 시험한다.

native33+20 이후 실제 SSH를 거친 초기18배치 보존·A 원본 불변·재실행 `new_receipts=0`·최초 저장 영수증 SHA 불변·타이머 첫 자동 실행까지 완료했다. 호출별 catalog는 `reused`가 false→true로 바뀌므로 첫/두 번째 catalog 전체 SHA가 다르며, 이 차이를 저장 canonical receipt 변경으로 해석하지 않는다. 남은 확인은 이후15분 자연 주기 및 최종 증거 영구 보관·정리다. 이 결과도 A 자동 ACK나 Wazuh/Indexer 전달 ACK를 뜻하지 않는다.
