# 원본 로그 회전과 재시작 복구

> **2026-10-31 후속:** 두 엔진의 회전 작업이 서로의 Vector 재개를 막던 경로를 보완했다. 이미 신호가 전달되고 old writer closed/new writer open이 실제 검증된 전환만, reader 소유권 검사 전에 봉인·기록한다. 설치 coordinator SHA `9f9ad7996bc0bec3b6b35d00b0f6c7776b346d24c39aef8b7e74ebdd65049592`. 원본/CP 수동 수정·재신호·가드 우회 없이 04:01 KST 두 엔진 active·예약 회전 종료0·reader 가드 통과를 확인했다. 아래 10/14·10/15 해시는 당시 이력이다. [복구와 검증](peer-recovery-2026-10-31.md).

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

> 2026-10-15 05:00 최신: WAF 새CID6c72d5a5…·호스트bind·로그인계·양가드를 검증했다. 원본상태는 Suricata gen1/rev6·WAF gen4/rev13, Vector2627991·Wazuh1909632 실행이다. 원본/출력점검timer를5분주기의0·1·3분으로분산해자연실행exit0를모두확인했다. Hermes단계와마지막인증서감시까지완료했으며관리범위·LLM권한은확대하지않았다. [현재WAF실측·정리](../../../groot-a/imperva-exception/recreation-validation-2026-10-15.json). 아래는 각 시점의 이력이다.

## 2026-10-15 02:15 KST 최신 상태 — 3단계 운영 검증·자동 실행 확인 완료

**02:15:39 KST 원본 회전 운영 전환과 세 타이머 활성화를 완료했다.** Suricata와 WAF raw 타이머는 첫 실행 `completed/local_rotation_or_not_due`를 확인했고, 해당 원천은 크기·기간 임계치 미만이라 새 회전 없이 기존 state를 유지했다. 출력 maintenance의 정상 daily 실행은 ready·evidence·telemetry 세 파일을 회전하고 빈 quarantine은 유지했다. 이어 maintenance만 재활성화한 첫 실행은 `not_due`로 끝나 추가 회전 0회였다. 세 타이머는 enabled/waiting이다.

최종 Vector는 **PID2406117 / Invocation `12314ddc66e14e0083b08db2e51fc831`**다. Wazuh logcollector1909632, 같은 CID의 WAF master2377669·UID101·healthy, Suricata gen1/revision5·WAF gen3/revision11 active, runtime·설정·ledger·barrier는 유지됐다. pending0, 양 reader 시작 가드와 maintenance health 검사를 통과했으며 원문·native checkpoint를 수동 수정하지 않았다. [초기 전환·복구 이력](INITIAL-MIGRATION.md) · [실측 메타데이터](resume-validation-2026-10-14.json).

출력 회전은 기존 inode archive와 활성화 전 EOF까지의 접두 SHA, 새 alias 및 고정 Invocation의 시작·완료 이벤트로 대조했다. 중간 `rotated_current_reader_ready`의 unit/Invocation 필드는 실제 journal에 없었으므로 같은 boot·UID0·태그·실행시간의 보조 관측으로만 기록했다. 검증기 거절과 systemd inactive 메타데이터 초기화에 따른 사전 거절도 보존했으며, 원래 타이머 전체를 재실행하거나 force를 추가하지 않았다. 사후 영수증은 초기 백업의 `timer-activation-postcheck/result.json`, 원래 실행과 실패는 `timer-activation/`에 있다.

이로써 이번 3단계 운영 적용·수동 회전·같은 CID WAF 재시작·타이머 첫 실행 검증은 완료했다. 최종 소스·증거 영구 보관과 임시물 정리를 완료했다(아래 정리 후속 기록). **4단계는 구현 준비 중이며 운영 전환은 없다.** 인증서 관리는 마지막 순서다. 호스트 재부팅과 새 CID WAF 재생성의 지속성은 아직 검증하지 않았고 이번 구간의 적격 보안 사건 ACK 표본도 없다. 로컬 처리 위치와 출력 접두 보존을 원격 수신증·전체 무손실로 확대하지 않는다. 아래 기록은 각 당시 상태로 보존한다.

**02:19:46 KST 정리 후속:** A의 작업 자료 515파일·4,621,609B와 격리 시험 자료 8파일·98,071B를 보관한 뒤 stage3·시험 fixture·미사용 v1 recovery guard를 제거했다. migration 시작 가드는 유지했고 정리 전후 운영 상태 불변·서비스 신호 0회를 확인했다. Mac의 해당 임시 트리 650파일·55디렉터리·5,318,295B와 B 조회 임시파일 2개도 제거했으며 영구 증거는 유지했다. **이 문구는 267파일·2,077,701B 소스 스냅샷 이후에 추가한 기록**으로 그 스냅샷에 포함된 문서 바이트와 구분한다. **02:20:55 KST 최종 점검도 완료했다.** 두 migration guard는 ready이며 storage 정상·Vector active·recovery=no·collection=[]·binding 검증 및 상태 코드 없음, 세 타이머 enabled/active/waiting을 확인했다.

## 이전 시점 기록 — 2026-10-15 최신 상태: 수동 회전·시작 입력 보완 완료, 실제 재시작 완료, timer 활성화 대기

초기 migration seq18 `guards_installed`와 reader 인계를 마쳤다. 실제 원본 회전은 Suricata **gen1 / revision 5 active**, WAF **gen3 / revision 11 active**까지 확인했다. WAF의 마지막 resume4 후 양 reader의 실행을 확인했다. 이후 출력 회전까지 마친 01:31:13의 Vector PID는 2368467이며 기존 Wazuh는 유지됐다. 초기 전환·중간 보류·제한 복구 기록은 [INITIAL-MIGRATION.md](INITIAL-MIGRATION.md), 실측 메타데이터는 [재개 검증 기록](resume-validation-2026-10-14.json)에 보존한다.

현재 설치된 `/usr/local/lib/capstone-raw-operations/coordinator.sh`는 [coordinator-writer-intent-fix.sh](coordinator-writer-intent-fix.sh), SHA `4b741931945035d1a99d953998cf2543c35d406a647ccaffcb6deb8158ee39c0`와 같다. 신규 28개와 기존 30·24개 native 회귀, 소스 검사 2개를 묶은 상위 시험 5개가 72.430초에 통과했다. 첫 실행의 fixture 오류 두 건도 보존했다. 01:19:54 CAS 교체 전후 두 reader guard가 통과했고, 설치 자체의 서비스 신호는 0회였다. 이전 `coordinator.sh`, UID 보완본 `coordinator-native-user-fix.sh`, 재열기 보완본 `coordinator-writer-reopen-fix.sh`는 당시 소스와 근거로 남긴다.

실제 WAF gen3 회전은 신호 intent를 영속 저장한 뒤, 첫 resume에서 **추가 HUP 없이** old writer 종료를 확인해 `old_closed / revision 8`로 진행했다. 다음 세대가 0바이트인 동안에는 Vector PID 2212780을 유지하며 공개를 보류했다. 무해한 POST 1회가 HTTP 405·1,193바이트 감사 행을 만든 뒤 alias 공개와 새 native checkpoint 확인을 거쳐 active로 완료했다. 중간 checkpoint 확인 대기는 원문이나 checkpoint를 수동 수정하지 않고 재검증했다. 이 요청의 ModSecurity messages는 0개로, 보안 경보 전달 시험이 아니다.

기존 출력 유지보수의 수동 force 1회는 92.979초, exit0으로 완료했고 pending 부재와 양 guard 통과를 확인했다. 이후 [출력 유지보수 보호본](../capstone-vector-maintenance-raw-guard.sh), SHA `2334ba3697cd98a445a5ab83dfa4ba044775868e9ed7a2be9e8ed0cceef0a921`이 native 36개를 통과해 **01:26:44 CAS 반영**됐다. 이 보완은 pending 생성과 Vector stop 전에 released migration barrier와 raw runtime guard를 검사한다. 교체 전후 양 guard가 통과했고 다른 runtime·설정·state·unit은 같으며 설치 신호는 0회다. 원본 `8413fb43…`은 보존했다. 새 보호본이 설치된 실제 `prepare`의 guard를 사용한 출력 force 1회도 **01:31:13, 127.617초, exit0**으로 완료했다. Vector PID 2368467 / Invocation `335851e515254887946d926a6676e6e8`의 active 상태, 기존 Wazuh 유지, output pending·raw stop-intent 부재, raw state 불변, 양 guard PASS와 maintenance check exit0을 확인했다. 앞선 별도 사전 검사는 Suricata cursor가 안정되지 않아 stop 0회·회전 0회로 거절됐으며 실패 기록을 보존했다. 실제 성공 증거는 초기 백업의 `operating-output-rotation-guarded-attempt2`에 있다. 300초 전체 제한 안에서 모든 최악 조건의 완료를 보장하지 않는다.

WAF 시작 시 구판 템플릿이 v2 override를 덮는 경계는 private native 검사 후 두 입력 파일을 수정했다. 01:37:08 검증은 운영 source 불변과 private 디렉터리 정리를 확인했고, CAS 계획 SHA `0a81a7d0ac59458e4b32f96f80c1fe8ebf03f3330151a4c54b235aec71c823a1`에 고정했다. 01:40:23에 `/etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template`과 `/etc/nginx/modsecurity.d/modsecurity-override.conf`만 현재 운영 target과 같은 SHA `814a4af8c52a66e1ee0eed072b0e5dbac9340240cad8ae6118ec7a5e902ea8cb`로 CAS 반영했다. 실행 중 target·producer·runtime·state·raw inode·PID는 유지됐고 서비스 신호는 0회다. 근거는 초기 백업의 `waf-coldstart-override-fix`에 보존한다.

**01:48:58 같은 CID의 WAF 실제 재시작 1회도 통과했다.** SIGQUIT 정상 종료 후 master PID가 647700에서 2377669로 바뀌었고, 같은 CID/image·mounts, UID101·healthy, raw state 5/11과 reader PID 2368467/1909632 불변을 확인했다. 강제 kill은 없었다. 결과 SHA는 `9f2e2811e04da112c3155557a0f261ec25cb0b2886813c4d56e600bed226e1ee`이며 초기 백업의 `waf-coldstart-validation/result.json`에 보존한다. **3단계 전체는 아직 완료하지 않았으며 timer 활성화가 남아 있다.** 원본·출력 회전 timer는 disabled이며 실제 호스트 재부팅은 0회다. 다른 시작 조건·새 CID 재생성 지속성과 장애 후 전달 완료를 현재 결과로 대신 보증하지 않는다.

00:45 KST 이후 A evidence 두 파일에서 확인한 153건은 모두 `nftables:observed`로, 현재 B 보안 leaf의 적격 조건에 해당하는 사건은 0건이었다. 같은 범위의 B manager/Indexer exact 조회도 0건이고 Indexer 57/57 shard 성공, queue 표본과 drop은 0이었다. 따라서 **이번 관찰 구간의 보안 사건 ACK는 검증 대상이 없어 확인하지 못했다.** 로컬 native 처리 위치, 과거 종단 검증, 이번 구간의 수신·색인 근거를 분리한다. 아래는 당시 후보와 검증 기록이며 현재 상태는 이 항목을 따른다.

출력 timer의 두 번째 사전 검사는 **enable 0회** 상태에서 정상 daily 회전 대상으로 판정돼 보류됐다. 실제 원인은 앞선 관리자 force가 시험 helper의 `TZ=UTC`를 물려받아 logrotate 상태 시각에 `2026-10-14 16:29`를 기록한 반면, 운영 timer는 KST `2026-10-15 01:54`를 기준으로 판단한 차이다. 당시 ready/evidence/telemetry가 대상이고 빈 quarantine은 대상이 아니었다. 운영 코드나 상태 파일을 보정하지 않고, 정상 timer의 첫 회전을 허용한 뒤 결과를 검증하는 후보를 준비한다.

관리자가 수동 유지보수를 실행할 때도 timer와 같은 시간대를 명시한다.

```sh
/usr/bin/env TZ=Asia/Seoul /usr/local/sbin/capstone-vector-maintenance run
```

`check`나 별도 승인된 `force`도 같은 `TZ=Asia/Seoul` 환경을 사용한다. `force`는 주기 도래와 무관하게 회전을 요청하므로 일반 실행을 대신하지 않는다. 과거 UTC 시험 기록은 덮어쓰지 않는다.

## 2026-10-14 당시 마감 기록

2026-10-14 사용자 요청으로 **3단계를 부분 적용 상태에서 마감하고 나머지는 보류**했다. 이 폴더의 회전 controller·guard는 검증 중 후보이며 운영 회전은 아직 기존 copytruncate다. 이전 부트 자동 보존기는 [별도 설치 기록](../history-auto/README.md)을 따른다.

## 확인한 동작

- 설치 Wazuh 4.14.8의 기본 future-only는 중지 중 기록을 건너뛰었다. `only-future-events=no`, `max-size=2GB`는 같은 파일의 정상 재시작과 오래된 checkpoint에서 미처리 부분을 읽었다.
- 강제 종료 시험에서는 checkpoint 저장 전 이미 처리한 두 행이 다시 전달됐다. 새 inode에 이전과 같은 바이트가 있으면 새 세대 앞부분을 건너뛰었다. 처음 등록된 파일도 저장 위치가 없으면 기존 바이트를 건너뛰었다. 따라서 옵션 변경만으로 모든 회전·재시작 문제를 해결했다고 보지 않는다.
- Wazuh 저장 해시는 offset까지의 **전체 prefix SHA1**이다. 4KiB prefix만 비교하지 않는다. Vector는 device/inode와 offset, Wazuh는 pathname·offset·해시를 각각 검사한다.
- WAF v2의 UID 101 실제 writer·두 세대·늦은 요청 세 건은 Vector audit/access 각 3건, Wazuh audit 3건으로 일치했다. 별도 실제 audit→VRL 재생도 ready 3·누락/중복/격리 0이었다. v2는 요청 context 생성 시각이며 access 완료 시각으로 표시하지 않는다.

## 운영 전환 후보의 범위

기존 reader pathname과 Vector source ID를 유지하고 writer 경로를 분리한다. 원본을 담은 inode는 hardlink로 보존하며, 이전 writer 종료·완결 행·두 reader 처리 위치를 대조한 뒤에만 다음 세대를 공개한다. 같은 prefix 때문에 Wazuh가 세대를 구분하지 못하는 경우와 확인 불가 상태는 보류한다. checkpoint의 offset을 임의 수정하거나 기존 원본을 자동 삭제하지 않는다.

`state-lib.sh`는 root 전용 세대 상태와 이전 revision을 보존한다. `checkpoint-gates.sh`는 설치 제품의 저장 위치와 원본을 읽기 전용으로 대조한다. `writer-gates.sh`는 정확한 컨테이너의 PID·시작 시점·namespace·FD를 대조한다. 이들은 Bash/jq/coreutils와 기존 서비스·엔진을 연결하는 제한된 운영 도구다. Python 파일은 일회성 배포·검증에만 사용하며 상시 수집기를 추가하지 않는다.

`deploy-reader-policy-a.py check|apply`는 고정 A 호스트의 raw 입력 두 곳만 복원 옵션으로 바꾸는 일회성 관리자 도구다. 공용 배포 잠금·원본 SHA/metadata 비교·native 문법 검사·서버 백업·agent 재연결·원본 접두 구간 불변을 확인한다. 적용 실패 시 다른 변경과 충돌하지 않는 경우에만 원본으로 복귀한다. LLM/MCP에 일반 sudo 또는 Docker 권한을 추가하지 않는다.

로컬 원본 보존, reader 처리 위치, manager 분석 결과, Indexer 수신 결과는 각각 다른 근거다. 이 단계의 회전 gate는 manager/Indexer 수신증이나 전원 장애 시 정확히 한 번 처리를 보증하지 않는다.

## 검증 상태와 남은 경계

[검증 기록](validation-2026-10-14.json)의 native 결과는 writer20·행 길이59·체크포인트53·상태 저장34·감시 통합39개다. 회전 조정기30개는 서비스 동작을 대체한 단계 시험과 private 하드링크 시험이므로 운영 전체 회전과 구분한다. 실제 checkpoint 네 조합도 읽기 전용으로 통과했다. 임시 systemd service는 시작 전 실패 후30.02초 자동 재시도와 관리자 stop 후35초 정지 유지를 확인했으며 실제 호스트 재부팅은 수행하지 않았다.

최신 조정기에서 dispatch30개와 stop-intent24개를 통과했다. 첫24개 실행은 시험 fixture의 Bash 변수 경계 오류로 중단됐고, fixture만 고친 최종판으로 재검증했다. 실제 fsync와 사설 자식 SIGKILL을 포함하지만 systemd/Docker 호출과 checkpoint는 대체한 합성 검증이다.

초기 전환 설치기는 합성11개와 실제 읽기 전용 check만 통과했다. prepare·운영 cutover는 실행하지 않았으며 미완성 cutover CLI는 import 전과 main 모두 exit78로 차단했다. 시작 전 영속 차단, v1 EOF/flush와 실제 stop 의도에서 state/marker로 인계, 부분 설정 설치 중단 복구, v1 storage playbook의 감시기 덮어쓰기 방지가 재개 조건이다. [재개 지점](INITIAL-MIGRATION.md), [마감 증거](finalization-2026-10-14.json).

용량 후보의 5GiB 상한은 엔진별 관리 디렉터리 기준이며 전체 합산 상한이 아니다. 여유 공간 2GiB는 공통 파일시스템 기준이다. 원본을 자동 삭제하지 않으므로 용량 부족 시 회전을 보류하는 것이 디스크 사용량의 절대 상한을 보장하지 않는다. 정지 intent가 없는 서비스는 자동 기동하지 않지만, 이미 회전 작업이 intent를 기록한 매우 짧은 구간의 동시 수동 stop 원인은 최종 systemd 상태만으로 구별할 수 없다.

1MiB/LF 검사는 Vector 입력 한도와 불완전 EOF 확인이다. Wazuh JSON reader는 별도의 버퍼 한도, NUL·JSON object 검사와 ignore 조건을 가지므로 저장 offset이 EOF라는 사실만으로 모든 행의 송신·분석 성공을 증명하지 않는다. 원문 보존과 원격 수신증을 계속 분리한다. [Wazuh 4.14.8 JSON reader](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/read_json.c#L34-L112)
