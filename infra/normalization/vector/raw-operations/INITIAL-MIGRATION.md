# 초기 원본 회전 전환 후보

> **2026-10-31 후속:** 두 엔진의 회전 작업이 서로의 Vector 재개를 막던 경로를 보완했다. 이미 신호가 전달되고 old writer closed/new writer open이 실제 검증된 전환만, reader 소유권 검사 전에 봉인·기록한다. 설치 coordinator SHA `9f9ad7996bc0bec3b6b35d00b0f6c7776b346d24c39aef8b7e74ebdd65049592`. 원본/CP 수동 수정·재신호·가드 우회 없이 04:01 KST 두 엔진 active·예약 회전 종료0·reader 가드 통과를 확인했다. 아래 10/14·10/15 해시는 당시 이력이다. [복구와 검증](peer-recovery-2026-10-31.md).

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

## 2026-10-15 02:15 KST 최신 상태 — 3단계 운영 검증·자동 실행 확인 완료

**02:15:39 KST 원본 회전 운영 전환과 세 타이머 활성화를 완료했다.** Suricata와 WAF raw 타이머는 첫 실행 `completed/local_rotation_or_not_due`를 확인했고, 해당 원천은 크기·기간 임계치 미만이라 새 회전 없이 기존 state를 유지했다. 출력 maintenance의 정상 daily 실행은 ready·evidence·telemetry 세 파일을 회전하고 빈 quarantine은 유지했다. 이어 maintenance만 재활성화한 첫 실행은 `not_due`로 끝나 추가 회전 0회였다. 세 타이머는 enabled/waiting이다.

최종 Vector는 **PID2406117 / Invocation `12314ddc66e14e0083b08db2e51fc831`**다. Wazuh logcollector1909632, 같은 CID의 WAF master2377669·UID101·healthy, Suricata gen1/revision5·WAF gen3/revision11 active, runtime·설정·ledger·barrier는 유지됐다. pending0, 양 reader 시작 가드와 maintenance health 검사를 통과했으며 원문·native checkpoint를 수동 수정하지 않았다. [현재 운영 계약](README.md) · [실측 메타데이터](resume-validation-2026-10-14.json).

출력 회전은 기존 inode archive와 활성화 전 EOF까지의 접두 SHA, 새 alias 및 고정 Invocation의 시작·완료 이벤트로 대조했다. 중간 `rotated_current_reader_ready`의 unit/Invocation 필드는 실제 journal에 없었으므로 같은 boot·UID0·태그·실행시간의 보조 관측으로만 기록했다. 검증기 거절과 systemd inactive 메타데이터 초기화에 따른 사전 거절도 보존했으며, 원래 타이머 전체를 재실행하거나 force를 추가하지 않았다. 사후 영수증은 초기 백업의 `timer-activation-postcheck/result.json`, 원래 실행과 실패는 `timer-activation/`에 있다.

이로써 이번 3단계 운영 적용·수동 회전·같은 CID WAF 재시작·타이머 첫 실행 검증은 완료했다. 최종 소스·증거 영구 보관과 임시물 정리를 완료했다(아래 정리 후속 기록). **4단계는 구현 준비 중이며 운영 전환은 없다.** 인증서 관리는 마지막 순서다. 호스트 재부팅과 새 CID WAF 재생성의 지속성은 아직 검증하지 않았고 이번 구간의 적격 보안 사건 ACK 표본도 없다. 로컬 처리 위치와 출력 접두 보존을 원격 수신증·전체 무손실로 확대하지 않는다. 아래 기록은 각 당시 상태로 보존한다.

**02:19:46 KST 정리 후속:** A의 작업 자료 515파일·4,621,609B와 격리 시험 자료 8파일·98,071B를 보관한 뒤 stage3·시험 fixture·미사용 v1 recovery guard를 제거했다. migration 시작 가드는 유지했고 정리 전후 운영 상태 불변·서비스 신호 0회를 확인했다. Mac의 해당 임시 트리 650파일·55디렉터리·5,318,295B와 B 조회 임시파일 2개도 제거했으며 영구 증거는 유지했다. **이 문구는 267파일·2,077,701B 소스 스냅샷 이후에 추가한 기록**으로 그 스냅샷에 포함된 문서 바이트와 구분한다. **02:20:55 KST 최종 점검도 완료했다.** 두 migration guard는 ready이며 storage 정상·Vector active·recovery=no·collection=[]·binding 검증 및 상태 코드 없음, 세 타이머 enabled/active/waiting을 확인했다.

## 이전 시점 기록 — 2026-10-15 최신 적용 상태: reader 인계·수동 회전 완료분과 남은 경계

초기 ledger seq18 `guards_installed`와 세 번째 resume의 후조건 검증을 마쳤다. 이후 실제 회전으로 Suricata **gen1 / revision 5 active**, WAF **gen3 / revision 11 active**를 확인했다. WAF resume4 완료 시 Vector PID 2316372와 기존 Wazuh가 실행 중이었고, 후속 출력 회전이 끝난 01:31:13에는 Vector PID 2368467과 같은 Wazuh의 실행을 확인했다. 원문·native checkpoint를 수동 수정하지 않았으며, 중간 실패·보류·제한 복구 증거와 최초 plan·before·source는 모두 보존한다. [재개 검증 메타데이터](resume-validation-2026-10-14.json).

현재 canonical runtime `/usr/local/lib/capstone-raw-operations/coordinator.sh`에는 [coordinator-writer-intent-fix.sh](coordinator-writer-intent-fix.sh), SHA `4b741931945035d1a99d953998cf2543c35d406a647ccaffcb6deb8158ee39c0`가 설치돼 있다. 신규 28개·기존 30/24개 native 회귀와 소스 검사 2개를 묶은 상위 시험 5개가 72.430초에 통과했고, 첫 실행의 fixture 오류 두 건도 남겼다. 01:19:54 CAS 설치 전후 두 reader guard가 통과했으며 설치 자체의 서비스 신호는 0회였다. 00:44:30의 UID 보완 `2f8fdfc4…`와 이후 재열기 보완 소스는 이전 단계의 근거이며 현재 설치 바이트와 구분한다.

실제 WAF gen3 회전에서는 force가 기록한 영속 signal intent를 재개해 첫 resume의 **추가 HUP 0회**로 old writer 종료를 확인했다. `old_closed / revision 8`, 다음 세대 0바이트 상태에서는 Vector PID 2212780을 유지하며 보류했다. 무해한 POST 1회(HTTP 405, 감사 행 1,193바이트, messages 0개) 후 새 alias 공개·native checkpoint 대기·자동 reader 기동을 거쳐 resume4에서 active로 마쳤다. gen2 전환 때 exact audit pathname의 checkpoint 항목이 일시 누락됐다가 자연 복구된 관찰도 보존한다. 내부 실행 순서가 정확히 무엇이었는지는 확정하지 않았으며, 이를 동일 크기 파일의 결함으로 단정하지 않는다.

기존 출력 유지보수 force는 1회 92.979초, exit0으로 완료했고 pending 부재·양 guard 통과를 확인했다. 이후 pending 생성과 Vector stop 전에 migration barrier/runtime guard를 검사하는 [maintenance 보호본](../capstone-vector-maintenance-raw-guard.sh), SHA `2334ba3697cd98a445a5ab83dfa4ba044775868e9ed7a2be9e8ed0cceef0a921`을 native 36개 통과 후 01:26:44 CAS 반영했다. 전후 guard PASS, 다른 runtime·설정·state·unit 불변, 설치 신호 0회이며 원본 `8413fb43…`은 `/var/backups/capstone-raw-operations-initial-20261014/maintenance-raw-guard-fix`에 보존했다. 새 보호본의 실제 `prepare` guard를 거친 출력 force도 **01:31:13, 127.617초, exit0**으로 1회 완료했다. Vector PID 2368467 / Invocation `335851e515254887946d926a6676e6e8`이 active이며 기존 Wazuh, raw state는 유지됐다. output pending·raw stop-intent는 없고 양 guard PASS·maintenance check exit0이었다. 앞선 별도 사전 검사는 Suricata cursor 불안정으로 거절됐으며 stop·회전은 모두 0회였다. 해당 보류 기록과 성공 증거를 구분하며, 성공 자료는 같은 초기 백업의 `operating-output-rotation-guarded-attempt2`에 보존했다. guard 거절 시 pending 생성·Vector stop 전에 멈추지만 전체 300초 예산 내 최악 조건 완료를 보장하지 않는다.

WAF 시작 시 v2 override를 구판으로 되돌리던 template/intermediate 두 파일은 **01:40:23 CAS 반영**을 마쳤다. 01:37:08의 private native envsubst/copy 검사(source `4ffef980…`)는 운영 source 불변·private 디렉터리 정리를 확인했고, CAS 계획은 SHA `0a81a7d0ac59458e4b32f96f80c1fe8ebf03f3330151a4c54b235aec71c823a1`로 고정했다. `/etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template`을 먼저, `/etc/nginx/modsecurity.d/modsecurity-override.conf`를 다음으로 현재 target과 같은 SHA `814a4af8c52a66e1ee0eed072b0e5dbac9340240cad8ae6118ec7a5e902ea8cb`로 바꿨다. 실행 중 target·producer·runtime·state·raw 신원·PID 불변, 서비스 신호 0회이며 원본과 결과는 초기 백업의 `waf-coldstart-override-fix`에 보존한다.

**01:48:58 같은 CID의 WAF 실제 재시작 1회가 통과했다.** SIGQUIT 정상 종료 뒤 master PID 647700→2377669, 같은 CID/image·mounts, UID101·healthy를 확인했다. raw state 5/11과 reader PID 2368467/1909632는 유지됐고 강제 kill은 없었다. 결과는 초기 백업의 `waf-coldstart-validation/result.json`, SHA `9f2e2811e04da112c3155557a0f261ec25cb0b2886813c4d56e600bed226e1ee`에 보존한다. 분리 native 검사와 실제 전체 시작 결과를 각각 기록한다. **3단계 전체 완료와 자동 회전 활성화는 아직 보류한다.** 원본·출력 회전 timer는 disabled, 실제 호스트 재부팅은 0회다. 새 컨테이너 재생성 지속성도 별도 검증 범위다. 00:45 KST 이후 A의 153건은 모두 `nftables:observed`이며 보안 leaf 적격 사건은 0건이었다. B manager/Indexer 같은 범위 exact 조회 0건, Indexer 57/57 shard 성공과 queue/drop 0을 확인했으므로 이번 구간에는 보안 사건의 원격 ACK를 검증할 대상이 없었다. 무해한 WAF probe 역시 보안 경보 ACK 대상으로 세지 않는다. 아래 기록은 당시의 실패·후보·검증 상태를 그대로 보존한다.

출력 timer의 두 번째 사전 검사는 **enable 0회** 상태에서 정상 daily 회전 대상으로 판정돼 보류됐다. 실제 원인은 앞선 관리자 force가 시험 helper의 `TZ=UTC`를 물려받아 logrotate 상태 시각에 `2026-10-14 16:29`를 기록한 반면, 운영 timer는 KST `2026-10-15 01:54`를 기준으로 판단한 차이다. 당시 ready/evidence/telemetry가 대상이고 빈 quarantine은 대상이 아니었다. 운영 코드나 상태 파일을 보정하지 않고, 정상 timer의 첫 회전을 허용한 뒤 결과를 검증하는 후보를 준비한다.

관리자가 수동 유지보수를 실행할 때도 timer와 같은 시간대를 명시한다.

```sh
/usr/bin/env TZ=Asia/Seoul /usr/local/sbin/capstone-vector-maintenance run
```

`check`나 별도 승인된 `force`도 같은 `TZ=Asia/Seoul` 환경을 사용한다. `force`는 주기 도래와 무관하게 회전을 요청하므로 일반 실행을 대신하지 않는다. 과거 UTC 시험 기록은 덮어쓰지 않는다.

## 2026-10-15 자정 유지보수 경합과 제한 복구 후보

부모의 실제 조회에서 기존 출력 유지보수 timer가 00:01:39 실행돼 Vector를 중지·출력 파일을 회전했고, 00:03:41 재시작은 초기 migration의 blocked guard가 거절했다. `resume.pending`과 기존 출력 회전본은 남았고 raw 파일·native checkpoint는 덮어쓰지 않았다. 초기 전환의 단계별 lock만으로는 단계 사이에 들어오는 기존 timer를 막지 못했다. 이 조정 누락은 별도 복구 대상으로 기록한다. 부모는 Vector의 자동 재시도를 명시 중지하고, 기존 enabled 상태를 보존한 뒤 유지보수 timer를 disabled/inactive로 두었다. Wazuh와 raw writer는 계속 실행 중이며, raw3개의 Vector CP는 읽기 대조에서 유효했다. 현재 ready/evidence는 새 inode의 0바이트 파일이고 이전 파일은 서버에 보존됐다.

`pending\n`은 출력 회전 재개 표식일 뿐 checkpoint 백업이 아니다. 복구는 현재 native CP와 실제 inode를 검증하고 v1 Vector를 한 번 시작하는 방식이며, 과거 CP·원문을 복원본으로 덮어쓰지 않는다. 제한된 `v1-recovery-guard.sh`는 고정 plan/seq6 ledger/source/boot·짧은 유효기간·v1 설정·raw3 CP·Wazuh output EOF·timer disabled/inactive를 확인한다. 빈 output은 실제 해당 inode FD가 정확히 한 개이고 position=0인 경우에만 허용한다. guard는 직접 시작·삭제·checkpoint 변경을 하지 않는다. 부모의 일회성 controller가 실제 시작 증거를 수집하고 원래 blocked drop-in으로 되돌린 뒤 pending을 보존·정리한다. 기존 maintenance `run`은 복구 뒤 새 logrotate까지 실행하므로 이 제한 복구에 그대로 재사용하지 않는다.

새 cutover의 `accept-v1-recovery PLAN_SHA RECEIPT_SHA`는 이번 정확한 seq6 ledger SHA `78f9261b6347ef43622428ad041e9bffb841c4c6d99804406052c8831b873343`와 원래 source SHA `9a17d6fac16240dbd98039253b806b5e115e2569e7f8ea0e38c472b61c956b83`만 예외적으로 읽는다. 원본 plan/before/source/ledger 이력을 보존한 채 새 source SHA와 root 전용 receipt 참조를 다음 ledger revision에 추가한다. phase와 이미 armed된 Suricata signal은 그대로다. 이후 비교에서는 검증된 새 Vector Invocation/PID만 원래 baseline 위에 덧씌우고 Wazuh·설정·CID 조건은 유지한다. 일반 mutation은 timer가 disabled/inactive이며 maintenance 실행 프로세스가 없을 때만 허용한다. migration 완료 후에만 기존 timer enabled 상태를 복구한다.

Receipt는 고정 백업 아래 `v1-recovery-receipt.json` root/0400 canonical JSON이고, `recovery-evidence/{authority.json,prestart.json,pending.before,timer-before.json,v1-recovery-guard.sh}`의 정확한 SHA와 내용을 대조한다. prestart의 실제 pass·authority·plan·ledger·boot·guard·barrier 결속, raw3와 output2 증거, timer의 이전 enabled/active 및 disabled/inactive 보존을 검사한다. 승인 기록은 root 운영자가 검증·생성한 복구 증거이며 암호학적 원격 수신증이나 전역 exactly-once 보장이 아니다. 이 절차는 임의 다른 장애·부트·ledger를 자동 승인하지 않는다.

Suricata entrypoint 분리 fixture는 부모가 기존 컨테이너에서 00:04 native 6개 모두 통과시켰다. 실제 패치는 새 maintenance 표식 검사에서 거절되어 아직 적용하지 않았다. 아래 entrypoint 보완 기록은 이 최신 상황과 함께 읽는다. 복구 확장 후보는 부모가 A에서 native 45개 모두 통과시켰다(0.548초). private Linux root 파일시스템 7개가 포함되며, cutover SHA는 `9109d81e28674a2329a7fb4ecafef7df8fd12511b2afdd81b6d73238af0f6266`, 테스트 SHA는 `9decbf5e105406907c0fd1b707c20becd1419d80ca27170e19e1ac0b14b31334`다. 이 합성 검증은 실제 Vector 복구·entrypoint 패치 성공의 증거가 아니며 두 운영 결과는 별도로 기록한다.

## 2026-10-15 Suricata 초기 재시작 후 발견한 보완

실제 초기 전환 중 Suricata의 같은 컨테이너 재시작 한 번은 완료됐으나, 후조건에서 관리 디렉터리의 소유권이 root에서 `998:998`로 바뀌어 단계가 거절됐다. 당시 ledger는 `legacy_excluded`의 `apply-suricata` intent, `signal_armed=true`로 남았다. 추가 재시작은 하지 않는다. 부모의 실제 읽기 조회에서는 `eve.json`, gen0, active가 같은 dev/inode와 3개 hardlink를 유지했고, 원문 파일은 writer `998:998/0644` 상태였다.

원인은 `/docker-entrypoint.sh`의 `fix_perms`가 로그 트리를 재귀 chown하는 기존 동작이다. 이 동작은 이전 compose 주석에도 기록돼 있었지만 초기 전환 설계에서 누락됐다. 디렉터리만 root로 되돌리면 다음 재시작 때 반복되고, 향후 봉인된 root/0400 파일까지 writer 소유가 될 수 있어 별도 보완이 필요하다.

`suricata-entrypoint-original.sh`는 실제 SHA `49a6e84e7bd4aab2187483e7556e96e9e1dba641c3d6fda09c253a329279aef1`의 원문이다. `suricata-entrypoint-managed.sh` 후보 SHA는 `eb6820266481f699306eb5730b9fd4b9276f37705450ff5cefe2eb9e3aaa9d47`이며 로그 chown 한 문장만 바꿨다. `capstone-managed` 전체와 `eve.json`을 모두 prune한다. reader alias 역시 봉인 inode의 hardlink일 수 있기 때문이다. 나머지는 native find와 `chown --no-dereference`로 처리하며 config/lib/run의 기존 chown과 전체 시작 순서는 바이트 그대로 유지한다. find의 chown 실행 실패는 원래 `set -e`에 nonzero로 전파된다.

별도 native fixture는 기존 Suricata 컨테이너의 GNU find 4.8.0·suricata UID 998을 사용한다. 검증 대상 `fix_perms` 함수만 추출하고 네 운영 경로를 전부 private task 디렉터리로 치환한다. 계정 변경 분기는 빈 PGID/PUID로 비활성화하며 전체 entrypoint나 Suricata를 실행하지 않는다. 원본의 소유권 손상 재현, 후보의 봉인/reader hardlink/active 보존, 일반 로그 chown, symlink target 보존, 반복 실행 및 오류 전파를 검사한다. 현재 소스·Bash 검사 2개가 로컬 통과했고 native 4개는 부모 실행 대기다.

보완 배포는 기존 plan/ledger/runtime/compose를 변경하지 않는 별도 관리자 작업이다. 원본·후보와 현재 plan/ledger/CID를 연결한 보완 증거를 보존하고, entrypoint의 exact SHA·root/0755 CAS를 확인한 뒤 같은 gen0와 hardlink 3개를 재검증한다. 관리 디렉터리만 root/0711로 복원한 후 기존 armed 단계의 후조건 경로로 재개한다. **같은 컨테이너의 향후 재시작에 적용되는 수정이며, 실제 호스트 재부팅 시험이나 새 CID/컨테이너 재생성 지속성을 검증한 것은 아니다.** 새 컨테이너는 별도의 사전 인계 검토가 필요하다.

## 2026-10-14 재개: 실제 prepare·최종 합성 검증 완료

사용자 재개 지시에 따라 초기 전환 후보를 보완했다. **운영 전환은 아직 완료하지 않았다.** 최종 native 합성 검증 후 고정 관리자 CLI를 활성화했으며, 실제 단계 실행은 부모 작업이 현재 계획 SHA를 대조해 순차 수행한다. 동일 컨테이너의 초기 전환과 재시작 경계를 대상으로 한다. 새 컨테이너 생성·CID 교체·이미지 재생성 지속성은 후속 단계이며 이번 코드가 자동으로 승인하지 않는다.

부모 작업이 A에서 최종 `deploy-raw-operations-a.py` SHA `6dcf1556f89c8882a422cf92a3c8caa90bbdcdf71b809d0224587fe45b17db15`로 실제 `prepare`를 실행했다. 설치된 WAF와 Suricata의 설정 검사 두 건이 성공했고, `operating_mutations=false`로 완료했다. 준비 계획 SHA는 `39ec7c6829888a3394217b98b5fbea05c89c0fc94e480ccd309fe72af7c9f40f`, 백업은 `/var/backups/capstone-raw-operations-initial-20261014`다. 준비기·계획에 포함된 runtime source는 이후 고정한다.

앞선 실패 두 건은 덮어쓰지 않았다. 첫 시도는 다른 mount namespace의 `/proc/PID/root`를 bind하는 과정에서 의도한 컨테이너 루트가 선택되지 않아 거절됐다. 두 번째는 겹쳐진 `/proc` mount의 숨겨진 `rw`와 새 `ro` 결과를 한 문자열로 검사해서 거절됐다. 최종본은 정확한 컨테이너 root/mount view 진입 직후 새 mount/network/PID namespace를 만들고, 새 procfs를 먼저 설치한다. 실제 열린 `/`와 `/proc` FD의 `mnt_id`를 해당 Bash의 mountinfo 한 행에 결속해 RO를 확인한다. 이후 후보 파일과 지정된 private log/run/cache/tmp만 쓰기 가능하게 둔다. native 실패 자료·설정 후보는 서버에 보존한다. `private_tmp_preserved`는 제거 완료가 확인되지 않았다는 뜻이며, 정리가 일부 진행된 실패에서 원형 전체 보존을 의미하지 않는다. engine별 결과와 전체 prepare의 host 보호 설정 대조는 별도 증거다.

초기 전환 후보의 안전 계약은 다음과 같다.

1. 원본·후보·plan·same CID/image·현재 boot를 대조한 뒤 영속 migration ledger를 만든다. legacy copytruncate가 두 raw alias를 더 이상 포함하지 않게 하는 단계가 writer 전환보다 앞선다.
2. root 전용 blocked marker를 먼저 저장하고, 두 reader의 같은 `90-capstone-raw-start.conf`에 임시 시작 guard를 적용·실효 확인한다. 이후 설정 일부만 게시된 상태에서 중단돼도 reader 시작은 거절된다.
3. Suricata 재시작·WAF HUP·Vector stop마다 실제 명령 전에 영속 signal intent를 기록한다. 응답을 잃은 재개는 실제 후조건을 검증하며, 불확실한 신호를 자동 재발송하지 않는다.
4. WAF v1 gen0의 writable FD가 없어지고 audit·access 두 원천의 native EOF를 확인한 뒤 v1 reduce TTL보다 긴 3초를 기다린다. 완료 행과 gen1의 실제 공통 prefix 차이를 검사하고 Vector를 정상 중지한다. gen1이 비어 있거나 prefix가 구분되지 않으면 원문을 보존한 채 대기한다.
5. 두 초기 state와 실제 중지 Invocation에 연결된 marker를 최초 intent에 고정한다. 중간 실패 후에는 그 바이트를 그대로 재사용한다. runtime/config/state의 일부만 게시된 경우도 원본 또는 고정 후보만 허용하고, 다른 내용은 보존·거절한다. 체크포인트를 직접 수정하지 않는다.
6. 최종 runtime·state·source pin 및 두 native guard가 통과한 뒤에만 marker를 released로 바꾼다. released 임시 guard 역시 고정 최종 guard로 위임한다. 그 다음 같은 drop-in 파일을 최종 guard로 교체하고 daemon-reload한다. release 또는 첫 drop-in 교체 직후 중단돼도 같은 intent에 결속된 증거로 재개한다. 정상 guard를 통과해 자동 재시작한 active reader도 검증하며, 이 단계가 별도 start 명령을 보내지는 않는다.
7. 이후 관리자 고정 `resume modsecurity`로 alias 공개·native 새 checkpoint 확인을 마친 뒤에만 timer 활성화를 검토한다. 이 후보의 install-guards 성공만으로 raw 전환·원격 분석·색인을 완료했다고 보지 않는다.

A의 root 전용 task 경로에서 첫 native 32개가 모두 통과했고, CLI 활성화 뒤 최종 34개도 모두 통과했다(0.480초). 실제 private 파일시스템 fixture 7개가 포함됐으며 시험 디렉터리 정리를 확인했다. 최종 cutover SHA는 `2edba40717cb2482b0e286b2ed89298bbbc2da3a2153ab068b10ab9381776d44`, 테스트 SHA는 `4a8ceeeb393d58db377c190919bf20f1f4744190252d8a35d067dc989ac8aa22`다. 두 실행본 사이에서 단계 함수는 바뀌지 않았고, CLI 차단 해제·dependency 실패 표시와 최초 inspect/invalid argument/dependency 실행 차단 회귀만 추가됐다. phase fixture는 실제 단계 함수를 호출하되 Docker/systemd/gate를 대체한 모의 시험이다. partial runtime/config/state 게시, stop 성공 뒤 ledger 실패, release 직후·첫 drop-in 교체 직후 실패, released 뒤 active reader 재개, 바뀐 release 거절을 구분한다. 별도의 Linux fixture는 실제 private 파일에서 hardlink/atomic rename/fsync 실패·재시도/충돌·symlink 거절을 검증한다. 이를 실제 daemon 장애나 호스트 재부팅 시험으로 해석하지 않는다.

최초 실제 `inspect`는 성공했고 ledger를 만들지 않았다. 이어 `install-barrier`의 ledger 준비 단계에서 scanner 권한이 초안의 `0700`과 달라 거절됐다. 실제 root:root `0755`와 기존 `vector-storage-a.yml`의 `0755`가 일치하므로 baseline 검사·후보 교체·release 재검사의 세 곳만 `0755` 유지로 바로잡았다. 당시 ledger·barrier·drop-in은 아직 없었고, 먼저 저장된 후보 source만 별도 보존한다. 보완 cutover SHA는 `9a17d6fac16240dbd98039253b806b5e115e2569e7f8ea0e38c472b61c956b83`, 테스트 SHA는 `1f364a631db7c39e2e61b36266abb4da0b3b8edbbea550828fd54acb658bdf19`다. 준비기·plan·runtime은 변경하지 않았다. 권한 회귀를 포함한 36개 중 로컬 29개 통과, Linux 전용 7개는 보완본의 서버 재검증 대기다.

`inspect`는 과거 boot의 증거도 읽으며, 최초 호출은 ledger를 생성하지 않는다. 누락·변조된 preparation 모듈은 코드 실행 전에 거절하고, 잘못된 CLI 인수는 호스트나 운영 단계에 접근하기 전에 거절한다. migration 도중 호스트가 재부팅되면 mutation은 새 boot를 자동 승인하지 않고 거절한다. 관리자가 증거를 재검증하는 별도 복구 절차가 필요하며, **재부팅 후 초기 migration 자동 복구 완료를 주장하지 않는다.** 정상 운영 runtime의 boot guard·기존 컨테이너 재시작 계약과 구분한다.

원문·checkpoint를 복원본으로 덮어쓰거나 삭제하지 않는다. 원문 Mac 반출, 새 패키지·venv 설치, 새 SSH 권한, LLM의 배포 권한 확대는 없다. 아래는 당시 중단 사실을 보존한 과거 기록이며, 현재 검증 상태는 위의 재개 기록을 따른다.

## 이전 중단 기록


2026-10-14 사용자 요청에 따라 현재 진행분을 보존하고 신규 전환 작업을 중단했다. **운영 원본 회전 전환은 미배포**이며 기존 copytruncate 설정과 v1 Vector 파이프라인을 이 후보로 바꾸지 않았다.

`deploy-raw-operations-a.py`는 `check`와 `prepare`만 구현한다. 고정 A 호스트·원본 설정 SHA/권한·컨테이너 CID/image·reader 상태를 대조하고, 서버 전용 백업과 별도 mount/network/PID namespace의 읽기 전용 설정 검사 후보를 만든다. 로컬 합성 11개와 A의 실제 읽기 전용 `check`가 통과했다. 실제 `prepare`, private native nginx/Suricata 검사 및 초기 전환은 **아직 실행하지 않았다**. 따라서 private 검사 코드의 Linux 동작 성공을 주장하지 않는다. 실제 check는 당시 동결 coordinator 7e526ea 계열을 사용했으며 이후 stop-intent 보강본의 prepare 결과와 구분한다.

`cutover-raw-operations-a.py`는 미완성 검토 초안이다. 파일 실행 시 준비 모듈을 불러오기 전에 고정 오류 `initial_cutover_draft_disabled`와 종료 코드 78을 반환한다. 함수 내부 `main()`도 차단돼 있다. 초안에 남은 단계 함수는 지원되는 운영 API가 아니며 직접 가져와 실행해서는 안 된다. AST 구문 확인과 실행 차단 확인만 수행했으며 원격 설치·운영 호출은 없다.

재개 시 필요한 순서는 다음과 같다.

1. 새 source manifest와 현재 운영 원본을 다시 대조하고, root가 작성한 unit/drop-in 및 최신 stop-intent runtime을 함께 동결한다. 기존 prepare 시점의 SHA를 현재 상태로 간주하지 않는다.
2. 실행 중 writer가 v1/v2 세대를 섞지 않도록 초기 상태와 서비스 시작 차단을 확정한다. WAF gen0의 늦은 writer 종료·두 reader EOF·완결 행·gen1의 실제 공통 prefix 차이를 확인해야 한다. gen1이 비어 있으면 보류하며 guard를 우회하지 않는다.
3. 실제 중지 전 영속 intent와 rev0 publish_pending state/marker 연결을 검토한다. Vector stop 후 crash, 여러 설정 설치 중 중단, state 일부만 생성된 상태, native 시작과 외부 운영자 변경의 경합을 합성 시험으로 검증한다. 현재 초안의 부분 함수 구현을 완료 검증으로 해석하지 않는다.
4. 원본·checkpoint는 복원본으로 덮어쓰지 않고, 불확실한 restart/HUP는 자동 재시도하지 않는 재개/복구 절차를 완성한다. CLI import 전 source 신원 검증과 단계별 CAS·로그 상한도 최종 검토한다.
5. 실제 prepare의 private native 설정 검사, systemd unit 검증 및 수동 전환을 순차 수행한 뒤에만 timer 활성화를 검토한다. 기존 v1 재배포 도구가 새 manifest/scanner를 덮어쓰지 못하는 경계도 확인한다.

WAF v2 access는 이전 보조 파일 경로를 유지하므로 v1 reader가 살아 있는 짧은 전환 기간에는 v2 access가 v1 parser에서 격리될 수 있다. 기존 v1 audit을 v2로 재해석하지 않는 문제와 별도이며, 원본 access는 보존해야 한다. 로컬 EOF/설정 검사/서비스 시작은 manager 분석·Indexer 수신증 또는 전원 장애 시 정확히 한 번 처리를 보증하지 않는다.

Mac 패키지 설치·신규 venv·개인 임시 폴더 생성은 없었다. 이 작업에서 변경한 후보 파일과 검사 스크립트는 저장소에 남기고, 공용 임시 자료의 최종 정리는 부모 작업에서 처리한다.

## 2026-10-15 후속: 복구 완료와 WAF native 검사 UID 보완 후보

앞의 보류 기록 이후 부모의 실제 운영 결과로 Vector v1 복구와 receipt 수용(seq7)이 완료됐다. Suricata entrypoint 보완은 00:30:18 적용됐고 추가 재시작 없이 기존 armed 단계의 후조건을 통과해 seq8로 진행했다. 초기 WAF 전환은 seq9 `apply-waf-writer`, `signal_armed=false`에서 native 검사 오류로 멈췄다. 여기까지의 오류는 WAF HUP 전이므로 이 기록 시점에는 새 신호를 보내지 않았다. 이 결과는 부모가 전달한 운영 증거이며, 아래 합성 시험으로 대신 입증한 것이 아니다.

부모의 실제 조회에서 WAF master와 nginx 계정은 `101:101`, `/tmp`는 root/1777, 기존 `/tmp/nginx.pid`는 `101:101/0644`, `fs.protected_regular=2`였다. root로 실행한 `nginx -t`는 구문 검사 뒤 기존 PID 파일을 열 때 EACCES로 실패했고, 같은 컨테이너에서 `--user 101:101`로 실행한 검사는 exit0이었다. 증거는 고정 초기 백업의 `waf-native-owner-check/native-nginx-101.log`에 보존된다. Linux의 [protected_regular 설명](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-regular)은 sticky 디렉터리에서 다른 사용자가 소유한 기존 regular 파일의 O_CREAT 열기를 제한한다. 참고한 [Nginx 1.28.0 source](https://github.com/nginx/nginx/blob/release-1.28.0/src/core/ngx_cycle.c#L955-L990)에도 설정 검사 시 PID 파일을 create-or-open으로 여는 경로가 있다. 이 소스 버전을 설치된 정확한 Nginx 버전이라고 주장하지 않으며, 이번 UID 선택의 직접 근거는 실제 master 소유권과 두 native 검사 결과다.

자동 회전의 기존 coordinator에도 같은 root native 검사가 있어, 별도 `coordinator-native-user-fix.sh` 후보를 준비했다. 원본 SHA `95f86e2db4115b929193fa9fac5c81fd4ad5cc98afc65ed3cad42dd7c950063e`를 보존하고, `ro_switch_writer`의 `nginx -t` 한 명령만 `--user 101:101`로 바꿨다. 후보 SHA는 `2f8fdfc42c14ad7b7abd8643644a76005b415ce0f1f06cebbe6e2fc9233e3914`다. 설정 파일 SHA를 읽는 별도 root exec, CID·writer 신원 검사, HUP, 봉인, checkpoint·state·stop-intent 로직은 바이트 그대로다. sysctl이나 PID 파일 권한을 바꾸지 않고, LLM 권한을 늘리지 않는다.

`test-coordinator-native-user-fix.py`는 원본 SHA와 정확한 한 곳 변경·Bash 구문을 검사한다. Linux/root에서는 실제 후보 함수를 불러와 native 검사 UID/검사 실패·timeout/신원 변경 시 신호 금지/HUP timeout 재시도 금지/Suricata의 nginx 미호출/root SHA 조회를 검증한다. Docker·systemd는 실행하지 않는다. 각 Docker 명령은 정확한 인수만 받는 모의 함수로 제한하고, 실제 봉인·원문 접근 전에 writer gate가 멈춘다. 기존 dispatcher/guard 30개와 stop-intent 24개도 수정 없이 별도 private bundle의 후보 coordinator로 다시 실행한다. 현재 로컬 검사는 2개 통과, Linux 의존 10개는 미실행이며 실제 A 결과는 후속 기록으로 구분한다.

배포는 초기 plan의 runtime SHA 결속을 유지해야 한다. `apply-readers`와 `install-guards.release_proof`는 원본 coordinator SHA를 검사하므로 이 단계 전에 후보로 바꾸면 정상적으로 거절된다. 초기 `publish_pending` 재개는 writer switch를 다시 호출하지 않는다. 원래 초기 전환과 guard release·두 source의 active 상태 확인을 마친 뒤, 자동 회전 timer 활성화 전에 같은 shared lock 아래 별도 root 관리자 보완으로 원본/후보 SHA와 root/0400/nlink1을 대조해 원자 교체·fsync하고 증거를 남긴다. state의 source pin과 released marker는 coordinator 내용 SHA를 직접 포함하지 않지만, 이것이 임의 교체 허용이라는 뜻은 아니다. 기존 plan/before/runtime 원본을 그대로 보존하고 실제 설치 SHA를 별도 보완 기록에 결속한다. 이후 frozen `install-guards` 재실행은 원본 SHA와 달라 거절될 수 있으므로 무작정 재사용하지 않는다. 이 후보는 같은 CID의 현재 운영 계약만 대상으로 하며 새 컨테이너 인계는 별도 단계다.
