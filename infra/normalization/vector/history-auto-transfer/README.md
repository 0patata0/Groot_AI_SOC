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

- 완료 배치 조회 최대1024개, A inventory 최대16,384개 항목/1GiB(**2026-11-13 19:31 적용: A 보존소와 동기화, 이전 256개·4096개**), 파일 최대32MiB·manifest64KiB, 기존 receiver 최대1000행을 유지한다.
- B receipt+작업 저장소 합계와 예약 복사량을 합쳐 논리적 1GiB를 넘으면 중단한다. 디렉터리 항목16,384개(작업 폴더 정리 4,096개, 11/13 적용 전 8192·2048), 최소 여유40MiB에 이번 복사 예약량을 더해 검사한다. 이는 전용 워크플로의 용량 검사이며 filesystem quota나 별도 root 수동 쓰기까지 차단하는 기능은 아니다.
- rsync당65초, A sender60초, 네트워크 유휴30초·SSH connect5초, 전체600초+강제정리10초, unit620초, 메모리512MiB. 재접속/전송 재시도 loop는 없다. timer는 부팅3분 후, 실행 종료15분 후다.
- 자동 삭제 대상은 **해당 성공 호출이 만든 B transient incoming과 작업 디렉터리**뿐이다. 최초 수신기의 원자 commit+fsync 영수증 이후만 제거한다. 기존/manual incoming, B 완료 배치/영수증, A 파일은 삭제하지 않는다.
- 실패 작업은 B root0700 `work/run-*`에 남고 고정 phase/exit metadata만 출력한다. 자동 정리하거나 partial을 완료로 취급하지 않는다. 반복 실패가 저장소 상한에 닿으면 운영자 확인까지 중단된다. 다음 timer의 같은 ID 재조회는 기존 수신기의 멱등 검증을 사용한다.
- `status.json`과 `latest-batches.jsonl`은 최근 성공 snapshot이다. 실패 때 이전 성공 파일이 남을 수 있으므로 현재 unit result/관측 시각을 함께 본다. 최신 성공과 과거 실패를 섞어 전송 성공으로 판단하지 않는다. 원문·cursor·SSH 오류 원문은 stdout에 내보내지 않는다.

## 시험과 완료 조건

`test-native.sh`는 Linux root의 별도 `/var/tmp/capstone-history-pull-test.*`만 사용한다. SHA가 고정된 기존 receiver fixture 생성 함수를 재사용하고 private 복사본의 machine/store/source 경로만 바꾼다. 실제 SSH/계정/키/운영 store 호출은 없다. manifest 거절, 같은 ID 충돌, 첫 commit와 stable receipt 재사용, 수신 후 transient 정리, 용량 거절, raw 출력 차단을 검사한다. 함수의 조건문 호출에서도 검사 실패가 명시 전파되도록 A gate를 시험한다.

native33+20 이후 실제 SSH를 거친 초기18배치 보존·A 원본 불변·재실행 `new_receipts=0`·최초 저장 영수증 SHA 불변·타이머 첫 자동 실행까지 완료했다. 호출별 catalog는 `reused`가 false→true로 바뀌므로 첫/두 번째 catalog 전체 SHA가 다르며, 이 차이를 저장 canonical receipt 변경으로 해석하지 않는다. 남은 확인은 이후15분 자연 주기 및 최종 증거 영구 보관·정리다. 이 결과도 A 자동 ACK나 Wazuh/Indexer 전달 ACK를 뜻하지 않는다.

## 2026-11-13 전송 상한 동기화 — 19:31 A·B 적용, 전송 재개

**적용 결과(사용자 승인 "history 전송 상한 적용해줘", 관리자231 경유)**: 19:31:16에 A 관문을 `fd1e7769…`로 바꾸고 sudoers digest도 같은 값으로 바꿨다(전체 `visudo` 통과, 백업 `/var/backups/capstone-history-transfer-capsync-20261113T193116`). 19:31:28에는 B 전송 잠금 아래 3개 파일을 교체했다(runtime 검사 통과, 백업 `…-20261113T193128`). 바로 시작한 수동 전송은 19:31:28~19:34:45(3분 17초)에 성공했다. A 배치 338개를 확인했고, 그중 82개를 새로 받고 256개는 기존 영수증을 재사용했다. B 보존 기록은 331,820건·178 MB이고 유닛 결과는 success다. 이후 A·B 실패 유닛은 0이다. 실패 시도 작업 폴더 40개는 그대로 남아 있으며 정리는 별도 검토 대상이다. **자연 주기 확인**: 19:49:48~19:51:54 실행이 success였다(342배치, 신규 4·재사용 338, 335,820건).

### 후보 작성 기록

**무엇이 멈췄나(라이브 읽기전용, 17:30~17:38)**: 같은 날 09:37·15:55에 A history-auto 보존소의 상한을 올렸다(폴더 256→1024, 항목 4,096→16,384). 이 전송 경로의 상한은 그대로였다. 09:41에 A 배치가 257개가 됐고, **09:44부터** A 관문(`export-a.sh`, 배치 ≤256)이 목록 요청을 거부했다. 이후 B 실행은 매번 `manifest_pull`에서 rsync 종료 12(deferred)로 끝나 failed 유닛이 됐다. 17:38 관측값은 A 배치 316개·항목 4,384개·168 MB, B 영수증 258개(5항목씩)·1,558항목·135 MB였다. 마지막 성공은 09:29(256개 재사용, 91초)였고, 실패한 시도의 작업 폴더 33개가 남아 있다(정책상 자동 삭제 없음). A 원본과 B 영수증은 삭제·손실되지 않았다.

**후보**: 상한만 바꾸고 동작·바이트·시간 제한·재시도 없음은 그대로 둔다.

| 위치 | 현재 | 후보 | 근거 |
|---|---|---|---|
| `export-a.sh` A 관문 | 항목 ≤4,096·배치 ≤256 | 항목 ≤16,384·배치 ≤1,024 | A 보존소 `AUTO_MAX_STORE_ENTRIES`·`AUTO_MAX_BATCH_DIRS`와 같음(같은 `find` 행 계산) |
| `worker-b.sh` B 목록 | 배치 ≤256 | 배치 ≤1,024 | A와 같음 |
| `transfer-lib.sh` `hat_capacity` | 항목 ≤8,192 | 항목 ≤16,384 | 영수증 1024×5 + 1024배치 목록 2,048 + 남은 실패 시도 |
| `transfer-lib.sh` `hat_cleanup_work` | 작업 폴더 ≤2,048 | ≤4,096 | 1024배치 목록만 약 2,052항목이라 정리 단계에서 다시 멈출 자리였다 |

`runtime.sha256`(`9a62534a4e2d3202…`)과 `deploy/source-pins.sha256`을 갱신했다. A sudoers는 관문 SHA로 고정돼 있어 적용 때 같은 digest 한 줄만 바꾼다. B 1 GiB 논리 용량은 그대로 둔다(1024배치 추정 약 540 MB). 600초 실행 제한도 그대로 둔다(기존 배치 재확인 약 0.35초/배치 → 1024개 약 360초). 한 번에 새 배치가 많아 시간을 넘기면 그 실행은 보류되지만, 완료된 영수증은 남아 다음 실행이 이어서 처리한다.

**검증**

| 항목 | 결과 |
|---|---|
| B 격리 합성 시험(`/var/tmp` 임시, 운영 경로·SSH 미사용, 종료 후 삭제) | 전송 **38/38**(기존 33 + 신규 5: `coupled_limits`, `export_batch_cap`, `export_row_cap`, `b_entry_cap`, `work_cleanup_cap`), 설치기 20/20 |
| 사고 재현 | 오늘 오전 상태(전송 원본은 기준본, A 보존소 상한만 1024/16,384)에 새 시험을 돌리면 `coupled_limits`에서 실패한다. 같은 일이 다시 생기면 시험이 잡는다 |
| 로컬 `test_apply_cap_sync.py` | 4/4: 적용 스크립트의 기준·후보 SHA, runtime·source 고정값, 런타임 원본은 상한 숫자만 바뀜 |

| 파일 | SHA256 |
|---|---|
| `export-a.sh` | `fd1e7769f8da6828da31aac101fc29a3ea343a2ff1c57301b27f09483f80355e` (운영 `dc4fc243…`) |
| `worker-b.sh` | `6781b8fd74546f36e1b8bad3ddbcddb7055c5e7a5625acb914dd885d1c5304b5` (운영 `7e783365…`) |
| `transfer-lib.sh` | `52dbb82b0cb31ce8fc2e29257b56c43b46ead47afbb9c02a6b2e4385eff251d4` (운영 `012411c7…`) |

**적용 순서(승인 후, 관리자231 경유)**: (1) A `apply-cap-sync-a.py <export-a.sh>`. 관문과 sudoers digest를 함께 바꾸고 `visudo`로 검사하며, 실패하면 둘 다 되돌린다. (2) B `apply-cap-sync-b.py <worker> <lib> <runtime>`. 전송 잠금 아래 3개 파일을 교체하고 runtime을 확인한다. (3) B 전송 유닛을 수동 1회 실행하고 `status.json`(발견 배치 316개 이상, 신규 약 58개)과 영수증 수를 확인한 뒤 failed 상태를 해제한다. 어느 쪽을 먼저 적용해도 중간 실행은 보류만 되고 데이터에 영향이 없다. 남은 실패 시도 폴더 33개의 정리는 별도 검토 대상이다.

## 2026-11-14 00:08 관측 — 마무리 단계 게시 상한 초과(B 읽기전용 진단 · 00:25 수정 후보 시험 완료, 운영 미적용)

[작은 원장](validation-2026-11-14.json) · [적용 스크립트](apply-publish-cap-b.py)

**무엇이 멈췄나(라이브 읽기전용)**: 11/13 23:54:05 실행이 `finalize`에서 exit 65(deferred)로 끝났고 유닛은 failed다. 23:36 성공 실행이 게시한 `latest-batches.jsonl`은 386배치 × 약 680바이트 = **262,370바이트**였다. 다음 실행의 `hat_publish`는 기존 게시 파일이 `hat_file … 600 262144`, 즉 **256 KiB 이하**인지 먼저 확인한다. 그래서 이후 실행은 모두 같은 지점에서 실패한다. 다음 주기(00:09:06~00:11:29) 실행도 같은 `finalize` exit 65로 실패해 이를 확인했다(남은 작업 폴더 42개). 다른 마무리 검사는 통과 조건이었다(rsync 고정값 일치, 항목 3,274/16,384, 바이트 215 MB/1 GiB, 여유 102 GB).

**원인 계열**: 19:31 상한 동기화는 배치 상한을 256에서 1024로 올렸지만, 게시 파일 상한은 그대로였다. 1024배치에 영수증 최대 4,096바이트를 곱하면 4 MiB까지 필요하다. 오전 사고와 같은 "한쪽 상한만 바뀐" 유형이다. `coupled_limits` 시험도 이 값은 다루지 않는다.

**데이터 영향**: 실패한 실행도 마무리 전에 배치 수신과 영수증 확정을 끝낸다. 23:54 실행은 390배치 모두 확정했고 그중 4개가 신규였다. 갱신되지 않는 것은 최신 목록과 `status.json`(23:36에 멈춤), 그리고 유닛 상태다. A 원본과 B 영수증의 손실은 없다.

**기한**: 실패한 실행마다 작업 폴더(약 785항목)가 정책상 남는다. 이 속도면 약 16회 뒤, 대략 11/14 04:30~05:00에 `hat_capacity`의 항목 상한(16,384)에 닿는다. 그 뒤에는 시작 단계에서 멈춰 새 배치 수신도 중단된다. A 원본은 A 보존소에 남는다.

**수정 후보(00:20 작성·시험 완료, 운영 미적용·승인 대기)**: 상한 하나만 고쳤다. 동작·용량·시간 제한·재시도 없음·삭제 없음은 그대로다.

| 위치 | 기준(운영) | 후보 | 근거 |
|---|---|---|---|
| `transfer-lib.sh` `HAT_PUBLISH_MAX`(새 상수) | — | 4,194,304 | 작업자 배치 상한 1024 × 영수증 상한 4,096바이트(`hat_receipt`) |
| `hat_publish` 기존 게시 파일 상한 | 262,144 고정 | `HAT_PUBLISH_MAX` | 23:36 목록 262,370바이트가 다음 실행을 막았다 |
| `hat_publish` 새 파일 크기 확인 | 없음 | 일반 파일·심볼릭 아님·`HAT_PUBLISH_MAX` 이하 | 다음 실행이 거절할 목록은 애초에 게시하지 않는다 |
| `test-native.sh` `coupled_limits` | 배치·항목·정리 상한 | + 게시 상한 ≥ 배치 상한 × 영수증 상한 | 이번 같은 한쪽 변경을 시험이 잡는다 |
| `test-native.sh` 새 시험 2건 | — | `publish_incident_catalog`(262,370바이트 기존 목록 통과), `publish_cap`(상한 정확히 통과, 새 파일·기존 파일 1바이트 초과 거절·원본 유지) | |
| `runtime.sha256`·`deploy/source-pins.sha256` | `9a62534a…` 등 | `abdd7d67…`(runtime), 라이브러리 `0ed5bbe6…`, 시험 `d3bcd3f7…` | 설치기 고정값 동기화 |

**검증**

| 항목 | 결과 |
|---|---|
| B 격리 합성 시험(`/var/tmp` 임시, 운영 경로·SSH 미사용, 종료 후 삭제 확인) | 전송 **40/40**(기존 38 + 신규 2), 설치기 20/20 |
| 사고 재현 | 새 시험을 운영 중인 기준 라이브러리(`52dbb82b…`)에 돌리면 `coupled_limits`에서 실패한다 |
| 적용 스크립트 격리 시험(B `/var/tmp`, 경로만 바꾼 사본) | 적용(2파일 교체·`runtime.sha256` 통과·0400·백업에 원본), 재실행 거절, 후보 불일치 거절, 작업자 불일치 거절, 적용 중 고정값 검사 실패 시 2파일 원복, 전송 잠금 사용 중 거절. 거절 경우 모두 원본 유지 |
| 로컬 고정값 시험 | `test_apply_publish_cap.py` 4/4(기준·후보·작업자 SHA, 라이브러리 변경 줄이 게시 상한 3줄뿐, 상한 연동), `test_apply_cap_sync.py` 4/4(19:31 적용분은 자기 커밋 `3f30d52`를 기준으로 고정하도록 갱신) |
| 운영 전제(B 00:19 읽기전용) | 설치본 `transfer-lib.sh` `52dbb82b…`·`runtime.sha256` `9a62534a…`·`worker-b.sh` `6781b8fd…`·`ssh-b.sh` `7ea52f7d…`, 모두 root:root 0400 nlink 1. 전송 잠금 파일 있음, 유닛 failed |

처음 적용 스크립트 시험에서는 원복 경로 시험이 앞 시험과 같은 초에 백업 폴더 이름이 겹쳐 백업 단계에서 멈췄다(원본 변경 없음). 백업 폴더를 매번 고유 이름(`mkdtemp`, 0700)으로 만들도록 고친 뒤 원복까지 확인했다.

**적용 순서(승인 후, 관리자231 경유, B만)**: (1) B root로 `apply-publish-cap-b.py <transfer-lib.sh> <runtime.sha256>`를 1회 실행한다. 전송 잠금을 잡은 뒤, 설치본 2개와 작업자가 기준값일 때만 교체하고 `runtime.sha256`을 확인한다. 실패하면 원복한다. (2) 전송 유닛을 수동으로 1회 실행한다. 확인할 것은 세 가지다. `status.json`이 새 관측 시각에 발견 배치 391개 이상인지, `latest-batches.jsonl`이 새로 게시됐는지, 유닛 결과가 success인지다. (3) 다음 자연 주기도 success인지 확인한다. A는 바꾸지 않는다. 남은 실패 시도 폴더 42개(오전 사고 39개, 10/24 1개, 23:54·00:11 2개)의 정리는 별도 검토 대상이다. 적용 뒤에는 실패 폴더가 더 늘지 않는다.

**남은 위험(이번 범위 밖)**: 실행마다 모든 배치 영수증을 다시 검증한다. 390배치에 약 2분 23초(00:09:06~00:11:29)가 걸렸다. 이 비율이면 1024배치에서 약 6분 15초로, 실행 제한 600초 안이지만 여유가 크지 않다. 배치가 늘면 다시 측정한다.
