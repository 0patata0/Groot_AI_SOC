# 이전 boot kernel journal의 유한 자동 보존

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

**2026-10-14: native 합성 33개와 Ansible syntax/check를 통과한 최종판을 A에 설치했고, 22:06:55 KST부터 타이머를 활성화했다.** 최종 9파일/51,061B의 library SHA `2604d5c6f9a7044f58d2c8c66995bf696d5bbdee69f49c9e48984556d1636ddf`, test SHA `b5b6c10c40f534e27451c789202d6c456f3b03c6be01a5bf6028e4f8e1cb7cba`에 대응하는 합성 실행은 exit0/33 PASS/0 FAIL이다. 실제 journal·운영 wrapper·서비스는 합성 시험에서 호출하지 않았으며, 이후 별도 운영 설치와 실제 회수를 수행했다. [검증 이력](validation-2026-10-14.json), [운영 적용](deployment-2026-10-14.json), [최종 실행 소스](native-payload-manifest.json).

22:34:59 KST 후속 조회에서 이전 boot 9개 중 고정 cutoff 범위 완료3·대기6·보류0·진행중0, 누적5,876건/2,495,151bytes였다. 타이머의 마지막 자연 실행은22:32:21 KST, service 결과 success/0이었다. 이는 그 시점의 job 요약이며 원래 발생했던 모든 journal이나 원격 분석·색인 완료를 뜻하지 않는다.

23:03:49 KST 마감 조회는 10,323건/4,362,173bytes·완료6/대기3/보류0/진행중0이다. 설치된 타이머는 계속 활성 상태로 유지하며 이번 작업 마감으로 중지하지 않았다. 전체 과거 로그 복구나 B 전송 완료라는 뜻은 아니다.

23:10:22 KST 임시 정리 후 재확인에서는 10,806건/4,566,236bytes·완료7/대기2/보류0이었다. 타이머와 기존 서비스는 정상이며 보존 증거는 `/opt/capstone-automation/project/evidence/sequential-20261014/step3`로 옮겨 해시를 대조했다.

최초 9파일/48,931B 판의 30 PASS는 [이전 실행 소스](native-payload-v1-manifest.json)로 따로 보존했다. 이후 완료 배치 재발견 시 파일·디렉터리 재fsync를 job 커밋보다 먼저 요구하고, 조건문으로 호출한 Bash 검증 함수의 중요 실패를 명시적으로 반환하도록 보강했다. 최종 33개는 이 두 보강과 실패·재개 대조를 포함해 다시 실행한 결과다.

이 단계는 A에 **현재 남아 있는** 이전 boot의 kernel journal을 파일로 보존한다. 기존 [첫 배치](../history/README.md)와 [후속 배치](../history/CONTINUATION.md)의 셸·jq 구현을 그대로 사용하고, systemd oneshot 한 번에 최대 한 배치만 처리한다. 상시 Python 수집기·새 패키지·SSH 자격정보·LLM 실행 권한을 추가하지 않는다.

## 현재 운영 자료와의 관계

수동 보존했던 1,481건은 `/var/lib/capstone-vector-history`에, B의 파일 수신증은 [기존 수신 경로](../history-transfer/README.md)에 그대로 남긴다. 이 후보는 그 자료를 자동 job으로 임의 채택하지 않는다. `/var/lib/capstone-vector-history-auto/store`에 최초 발견 시각을 cutoff로 고정한 별도 체인을 만들므로 같은 원문이 중복 보관될 수 있다. **운영 ready·Wazuh·Indexer로 재주입하지 않으므로 이 보존 때문에 SOC 경보가 중복 발생하지 않는다.**

기존 B 수신증·수동 전송 도구는 변경하지 않는다. 그 도구의 고정 입력은 수동 보관소이므로 **새 자동 store는 아직 B 무인 전송에 연결하지 않았다.** 자동 store의 검증된 배치를 기존 수신 계약으로 넘기는 절차는 별도 후속 단계다. B 파일 보관 수신증은 Wazuh 분석이나 Indexer 색인의 확인증이 아니다.

## 실행·상태 계약

고정 root 전용 CLI는 `/usr/local/sbin/capstone-vector-history-auto run|inspect`다. A machine ID와 Linux를 확인하고 임의 경로·boot·cursor·예산 인수를 받지 않는다. 환경을 비운 뒤 검증한 런타임을 실행한다. `inspect`는 영속 job 상태의 요약이며 보관 원문의 전수 무결성 검사나 journal 재조회가 아니다.

| 항목 | 고정 범위 |
|---|---|
| 런타임 | `/usr/local/lib/capstone-vector-history-auto`, root:root 0700 |
| 재사용 원본 | 런타임의 `history/` 아래 기존 5파일, 바이트/SHA 그대로 |
| 영속 목록 | `/var/lib/capstone-vector-history-auto/jobs/<boot32>.json`, root:root 0600 |
| 자동 보관소 | 같은 root의 `store/`, root:root 0700 |
| 완료 자료 | 기존 정책대로 `batch-<id>/kernel.jsonl`, `manifest.json` 각 0400 |
| 동시 실행 | 자동 root의 `.lock` flock + 기존 history store lock |
| 회차 예산 | 전체 timeout 90초 + 종료 유예 3초; systemd 100초/stop 5초, control-group 종료 |
| 한 배치 | 최대 1,000건·검증 재조회 포함 32MiB·capture/validate 15초 |
| boot 목록 | 최대 64개·64KiB·5초; 초과/누락/중복/형식 실패는 명시 보류 |
| 영속 job | 최대 64개; 완료/보류 job도 포함하며 자동 삭제 없음 |
| 자동 store | 논리 크기 1GiB, 새 회수 전 40MiB 여유 예약; batch+partial 최대 256개 |
| 파일/메타 제한 | store 최대 4,096 entries, store 밖 깊이2 메타 최대 256 entries |
| 주기 | 부팅 2분 후, 이후 oneshot 비활성화 시점부터 5분 간격 |

이미 부팅 후 2분이 지난 서버에서 timer를 처음 활성화하면 `OnBootSec=2min`이 즉시 만료되어 첫 회수가 시작될 수 있다. 따라서 `history_auto_enable=true`는 설치만 하는 플래그가 아니라 실제 유한 회수의 시작을 포함한다. [systemd v255의 timer 공식 설명](https://github.com/systemd/systemd/blob/v255/man/systemd.timer.xml#L151-L155)

32MiB/15초는 기존 exporter의 capture·validation 한도다. hash/fsync/final rename까지 15초라는 뜻이 아니며, 전체 실행의 별도 90초 제한이 있다. 종료 처리·디스크 응답 지연까지 절대 시간 안에 완결되거나 정전 시 모든 하드웨어가 내구성을 제공한다는 보장은 아니다. systemd가 그룹 전체를 종료하고 다음 실행이 남은 상태를 검증한다.

store는 이 자동화만 쓰는 root 전용 영역이다. 다른 운영자가 직접 쓰거나 quota를 우회하지 않는 것이 상한의 전제다. 논리 크기에는 부분 파일과 검증 보조 파일도 포함한다. 압축·thin provisioning·파일 시스템 메타데이터를 포함한 물리 디스크 예약의 보장은 아니다. 기존 exporter의 최소 여유 공간 검사도 유지한다.

## 재시작과 보류

1. retained boot 목록을 제한된 크기로 읽고 현재 boot를 제외한다. 새 job의 boot/cutoff/정책을 root 파일에 먼저 원자 저장하고 파일·디렉터리를 fsync한다. 목록을 잘라서 정상으로 처리하지 않는다.
2. job을 결정적인 boot 문자열 순서로 선택한다. 한 회차에 한 개만 진행하므로 큰 boot가 먼저 끝날 때까지 뒤 job은 기다릴 수 있다.
3. 저장된 head의 manifest SHA, 원문 SHA·크기·행 metadata를 다시 검증한다. 다음 결정적 batch ID와 inflight 상태를 먼저 저장한 뒤 기존 exporter를 호출한다.
4. 완료 파일 rename 후 job 갱신 전에 중단되면 다음 실행은 같은 ID의 완료 자료를 재검증·fsync하고 job을 한 번만 진전시킨다. journal 원문을 다시 읽어 새 중복 배치를 만들지 않는다.
5. 완료 자료 없이 partial이 남으면 `blocked`로 기록하고 자동 재시도하지 않는다. cursor 누락·nearest 대체·boot vacuum·잘린 JSON·empty 범위·capture 실패도 완료로 보지 않는다. 원문·partial·manifest는 삭제하지 않는다.
6. inflight만 있고 완료/partial이 없는 시작 전 중단은 같은 ID로 재시도한다. 시도는 배치당 3회까지다. store lock 경합도 저장된 시도 횟수에 들어가며 한도 후 운영자 확인이 필요하다.

현재 boot ID는 회차 시작, job 쓰기 전, rename 직전, capture 뒤에 대조한다. 달라지면 job 결과 커밋을 거절한다. exporter가 이미 보존한 완료 파일은 삭제하지 않고 다음 회차에 재검증한다. 이를 위해 남은 inflight 상태가 정상 복구 경로에 포함된다.

완료 자료나 저장된 head가 변조·손상되면 자동으로 덮어쓰거나 다른 경계로 진행하지 않는다. blocked 해제·부분 파일 삭제·cutoff 변경·과거 job 재작성 CLI는 이번 후보에 없다. 운영자가 원인과 보존 자료를 검토한 뒤 후속 변경으로 처리해야 한다. 중단 때 남은 메타 임시 파일도 상한에 포함돼, 반복 실패로 무한히 쌓이는 것을 허용하지 않는다.

## `complete`의 한계

`complete`는 **고정 cutoff 이하에서 현재 보존된 해당 boot의 kernel journal 범위를 끝까지 읽고 경계를 검증했다**는 뜻이다. 원래 발생한 전체 사건, 이미 vacuum된 중간 기록, Vector가 과거에 확인한 정확한 ACK 경계를 복구했다는 뜻은 아니다. 양 끝 cursor 생존 확인으로 중간 vacuum 유실 0을 증명하지 않는다.

cutoff는 최초 발견 시점의 현재 realtime이다. 과거 boot에서 시계가 앞으로 잘못 이동한 이력이 있으면 cutoff보다 큰 event timestamp는 제외될 수 있다. 사람이 읽는 boot 목록의 시간 문자열을 추정 파싱해 전체 완료로 확대하지 않는다. 현재 cutoff 범위를 넘는 자료까지 포함한 전체 boot 복구는 별도 검토 사항이다.

`raw_payload_exported:false`는 원문·cursor를 **프로세스 stdout/외부 응답으로 내보내지 않는다**는 뜻이다. 서버 안에는 의도적으로 원문 파일을 보존한다. 로그/표준출력은 정책·상태·이유·boot ID·건수·바이트 수만 포함한다. 최초 cutoff와 source 원문 조회가 atime을 변경할 수 있으며 원천 내용·journal 설정·현재 Vector checkpoint는 변경하지 않는다.

## 설치와 검증

`install-a.yml`은 기존 localhost Ansible controller로 실행한 운영자 전용 설치기다. root/A 식별자, 고정 경로 소유권·권한, 배포 원문 SHA를 확인한다. 알 수 없는 기존 런타임 파일을 자동 업그레이드하지 않는다. 기존 history source 5개는 복사만 하며 원본 파일을 수정하지 않는다. 런타임의 `runtime.sha256` 8항목과 안전한 root 소유 경로를 CLI가 실행 때마다 검증한다. 이 manifest는 root 관리 경계이며 별도 전자서명은 아니다.

기본값은 타이머 활성화 없음이다. 부모의 검토·native 시험 뒤에만 `history_auto_enable=true`로 설치·활성화한다. 새 timer만 시작하며 Vector/Wazuh/Suricata/WAF를 재시작하지 않는다. 설치 실패 시 일부 새 파일이 남을 수 있으나 native parser/installed inspect 통과 전 timer를 켜지 않는다. 운영 복구는 새 timer를 중지·비활성화하고 root 보관 자료를 그대로 두는 방식이며 기존 raw/대화/설정 복원을 수행하지 않는다.

```sh
# A의 기존 operator controller용 재현 명령.
ansible-playbook -i ../../../automation/ansible/inventory/local-a.ini install-a.yml --syntax-check
ansible-playbook -i ../../../automation/ansible/inventory/local-a.ini install-a.yml --check
# 이번에는 enable=false로 설치/inspect/실제 수동 회수 후 timer를 별도로 활성화했다.
# 아래는 신규 설치 때 설치와 활성화를 함께 하는 옵션이다.
ansible-playbook -i ../../../automation/ansible/inventory/local-a.ini install-a.yml -e history_auto_enable=true
```

합성 시험은 형제 `history/`의 5개 의존 파일과 `history-auto/{auto-worker.sh,auto-lib.sh,state.jq,test-native.sh}`를 함께 반입해 `bash history-auto/test-native.sh`로 실행한다. 실제 journalctl·운영 wrapper·systemctl을 호출하지 않는다. 실제 EOF 후속 배치, 부팅 변경 뒤 완료 자료 재사용, timeout 중단 후 partial 보존, cursor 누락/nearest, 빈 원천/손상 JSON, 목록의 과대·중복·현재 boot 누락, 동시 실행, 용량·partial 상한, head 손상·unsafe state를 검사한다. 완료 자료의 재fsync 실패 시 head가 그대로인지와 재시도 복구, payload·JSON 의미가 같은 manifest 공백 변조의 SHA 거절도 포함한다. private fixture만 만들고 정리하며 원문은 stdout에 출력하지 않는다.
