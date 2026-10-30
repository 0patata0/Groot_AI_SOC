# WAF v2 producer의 분리 native 검증

> 2026-10-31 회전 coordinator의 상호 대기 보완은 [현재 복구 기록](../raw-operations/peer-recovery-2026-10-31.md)을 따른다. 아래 10/14 해시는 당시 배포 이력이다.

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

## 2026-10-15 02:15 KST 최신 상태 — 3단계 운영 검증·자동 실행 확인 완료

**02:15:39 KST 원본 회전 운영 전환과 세 타이머 활성화를 완료했다.** Suricata와 WAF raw 타이머는 첫 실행 `completed/local_rotation_or_not_due`를 확인했고, 해당 원천은 크기·기간 임계치 미만이라 새 회전 없이 기존 state를 유지했다. 출력 maintenance의 정상 daily 실행은 ready·evidence·telemetry 세 파일을 회전하고 빈 quarantine은 유지했다. 이어 maintenance만 재활성화한 첫 실행은 `not_due`로 끝나 추가 회전 0회였다. 세 타이머는 enabled/waiting이다.

최종 Vector는 **PID2406117 / Invocation `12314ddc66e14e0083b08db2e51fc831`**다. Wazuh logcollector1909632, 같은 CID의 WAF master2377669·UID101·healthy, Suricata gen1/revision5·WAF gen3/revision11 active, runtime·설정·ledger·barrier는 유지됐다. pending0, 양 reader 시작 가드와 maintenance health 검사를 통과했으며 원문·native checkpoint를 수동 수정하지 않았다. [원본 회전 운영 계약](../raw-operations/README.md) · [실측 메타데이터](../raw-operations/resume-validation-2026-10-14.json).

출력 회전은 기존 inode archive와 활성화 전 EOF까지의 접두 SHA, 새 alias 및 고정 Invocation의 시작·완료 이벤트로 대조했다. 중간 `rotated_current_reader_ready`의 unit/Invocation 필드는 실제 journal에 없었으므로 같은 boot·UID0·태그·실행시간의 보조 관측으로만 기록했다. 검증기 거절과 systemd inactive 메타데이터 초기화에 따른 사전 거절도 보존했으며, 원래 타이머 전체를 재실행하거나 force를 추가하지 않았다. 사후 영수증은 초기 백업의 `timer-activation-postcheck/result.json`, 원래 실행과 실패는 `timer-activation/`에 있다.

이로써 이번 3단계 운영 적용·수동 회전·같은 CID WAF 재시작·타이머 첫 실행 검증은 완료했다. 최종 소스·증거 영구 보관과 임시물 정리를 완료했다(아래 정리 후속 기록). **4단계는 구현 준비 중이며 운영 전환은 없다.** 인증서 관리는 마지막 순서다. 호스트 재부팅과 새 CID WAF 재생성의 지속성은 아직 검증하지 않았고 이번 구간의 적격 보안 사건 ACK 표본도 없다. 로컬 처리 위치와 출력 접두 보존을 원격 수신증·전체 무손실로 확대하지 않는다. 아래 기록은 각 당시 상태로 보존한다.

**02:19:46 KST 정리 후속:** A의 작업 자료 515파일·4,621,609B와 격리 시험 자료 8파일·98,071B를 보관한 뒤 stage3·시험 fixture·미사용 v1 recovery guard를 제거했다. migration 시작 가드는 유지했고 정리 전후 운영 상태 불변·서비스 신호 0회를 확인했다. Mac의 해당 임시 트리 650파일·55디렉터리·5,318,295B와 B 조회 임시파일 2개도 제거했으며 영구 증거는 유지했다. **이 문구는 267파일·2,077,701B 소스 스냅샷 이후에 추가한 기록**으로 그 스냅샷에 포함된 문서 바이트와 구분한다. **02:20:55 KST 최종 점검도 완료했다.** 두 migration guard는 ready이며 storage 정상·Vector active·recovery=no·collection=[]·binding 검증 및 상태 코드 없음, 세 타이머 enabled/active/waiting을 확인했다.

## 이전 시점 기록 — 2026-10-15 최신 상태: v2 운영 회전·템플릿 보완 완료, 실제 재시작 완료, timer 활성화 대기

초기 v1→v2 전환의 migration seq18과 reader 인계를 마쳤고, 실제 WAF 원본 회전은 **gen3 / revision 11 active**까지 확인했다. 마지막 resume4 후 reader 실행을 확인했으며, 후속 출력 회전이 완료된 01:31:13의 Vector PID는 2368467이고 기존 Wazuh는 유지됐다. 현재 v2는 감사 행에 담긴 context 생성 시각으로 정제하며, v1 audit/access의 메모리 결합을 사용하지 않는다. access 원본은 보조 로그로 보존한다. [운영 전환 기록](../raw-operations/INITIAL-MIGRATION.md), [실측 메타데이터](../raw-operations/resume-validation-2026-10-14.json).

현재 회전 runtime은 [coordinator-writer-intent-fix.sh](../raw-operations/coordinator-writer-intent-fix.sh), SHA `4b741931945035d1a99d953998cf2543c35d406a647ccaffcb6deb8158ee39c0`다. 신규 28개·기존 30/24개 native 회귀와 소스 검사 2개를 묶은 상위 시험 5개를 통과한 뒤 01:19:54 CAS 설치됐고, 양 reader guard 전후 PASS·설치 신호 0회를 확인했다. nginx native 검사 UID를 실제 master의 101:101로 맞춘 이전 보완도 유지한다. gen3 회전 재개에서는 **추가 HUP 없이** old writer 종료를 확인했으며, 다음 세대가 비어 있는 동안에는 실행 중 Vector를 유지했다. 무해한 POST 1회가 HTTP 405·1,193바이트 감사 행을 만든 뒤 새 alias와 native checkpoint를 확인해 active로 마쳤다.

이 요청의 ModSecurity messages는 0개이며 보안 경보 ACK 시험이 아니다. 00:45 KST 이후 A evidence의 153건도 모두 `nftables:observed`로 현재 B 보안 leaf 적격 사건은 0건이었다. B exact 조회 0건·Indexer 57/57 shard 성공·queue/drop 0을 확인했지만, 이번 구간은 적격 사건이 없어 보안 분석·색인 ACK를 검증하지 못했다. 로컬 reader 처리 위치와 과거 종단 검증을 이번 수신증으로 대신하지 않는다.

WAF 시작 시 구판 템플릿이 v2 override를 덮는 경계는 private native envsubst/copy 검사 후 두 입력 파일을 수정했다. 01:37:08 검사에서 운영 source 불변·private 디렉터리 정리를 확인했고, CAS 계획 SHA는 `0a81a7d0ac59458e4b32f96f80c1fe8ebf03f3330151a4c54b235aec71c823a1`이다. **01:40:23**, template `/etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template`과 intermediate `/etc/nginx/modsecurity.d/modsecurity-override.conf`를 현재 target과 같은 SHA `814a4af8c52a66e1ee0eed072b0e5dbac9340240cad8ae6118ec7a5e902ea8cb`로 CAS 반영했다. 실행 중 target·producer·runtime·state·raw 신원·PID는 같고 서비스 신호는 0회였다. 원본·검사·반영 증거는 초기 백업의 `waf-coldstart-override-fix`에 보존한다.

**01:48:58 같은 CID의 WAF 실제 재시작 1회도 통과했다.** master PID는 647700→2377669로 바뀌었고 같은 CID/image·mounts, UID101·healthy, raw state 5/11과 reader PID 2368467/1909632 불변을 확인했다. SIGQUIT 정상 종료이며 강제 kill은 없었다. 실제 결과 SHA `9f2e2811e04da112c3155557a0f261ec25cb0b2886813c4d56e600bed226e1ee`는 초기 백업의 `waf-coldstart-validation/result.json`에 보존한다. 분리 envsubst/copy 검사와 실제 전체 시작 결과를 구분한다. **3단계 전체는 아직 미완료이며 timer 활성화가 남아 있다.** 원본·출력 회전 timer는 disabled, 실제 호스트 재부팅은 0회다. 이번 같은 CID의 정상 시작 검증과 새 컨테이너 재생성 지속성은 구분한다. 출력 유지보수 보호본 `2334ba36…`은 native 36개 통과 후 01:26:44 반영됐다. 해당 코드의 실제 `prepare` guard를 사용한 force 1회는 01:31:13에 127.617초·exit0으로 완료했으며, output pending·raw stop-intent 부재, raw state 불변, 양 guard PASS·maintenance check exit0을 확인했다. 앞선 별도 사전 검사에서는 Suricata cursor가 안정되지 않아 stop·회전 0회로 거절됐고 그 기록도 보존했다. 아래 분리 native 결과와 당시 운영 대기 표기는 과거 기록으로 보존한다.

출력 timer의 두 번째 사전 검사는 아직 enable 0회인 상태에서 daily 회전 대상으로 판정돼 보류됐다. 앞선 관리자 force는 시험 helper의 UTC 환경에서 실행돼 logrotate 상태 시각을 `2026-10-14 16:29`로 남겼고, 운영 timer는 KST `2026-10-15 01:54`를 기준으로 판단했다. 이는 raw 상태 손상과 구분하며, 상태 파일이나 운영 코드는 수정하지 않는다. 수동 유지보수도 `/usr/bin/env TZ=Asia/Seoul /usr/local/sbin/capstone-vector-maintenance run`처럼 KST를 명시한다. 정상 timer 첫 회전을 검증하는 후보는 준비 중이다.

## 2026-10-14 분리 native 검증 기록

**2026-10-14 native 검증 완료, 운영 전환은 대기 중이다.** 실제 UID/GID101 writer로 smoke1건과 두 세대 rotate3건을 실행해 Vector audit/access·Wazuh audit의 ID/원문 또는 native cJSON SHA가 모두 일치했다. 구 worker의 늦은 기록과 종료된 FD, private 프로세스·경로 정리를 확인했다. `audit-context.vrl` 합성25개와 실제 감사 원문3건 재생도 ready3·누락/중복/격리0으로 통과했다. 이어 전체 Vector v2 후보 구성의 native `validate --no-environment`도 exit0이었다. [실측 메타데이터](native-validation-2026-10-14.json).

이 시험은 실제 운영 producer·Vector·Wazuh 설정이나 서비스를 변경하지 않았다. 새 상시 수집기나 패키지가 아니라 기존 설치 바이너리를 실행하는 일회성 시험 도구다. 실제 원문 VRL 재생은 회전 중 실시간 운영 처리·원격 수신증 검증과 구분한다.

## 변경하는 형식과 검증 범위

감사 로그의 `transaction.unique_id`를 다음 형식으로 생성한다.

```text
v2:<binding 64hex>:<nginx request_id 32hex>:<nginx msec>:<nginx time_iso8601>
```

서버가 생성한 변수만 사용한다. 현재 10자리 epoch 초·밀리초 세 자리·25자리 offset ISO라면 전체 길이는 141byte다. 시험은 이 숫자만 보고 통과하지 않고 전체 정규식, HTTP 응답의 request ID, msec의 epoch ms와 ISO 초가 가리키는 시각, audit의 offset 없는 context 시각을 함께 대조한다. ISO는 초 정밀도이므로 ms 차이는 0..999ms이며 audit context와는 최대 2초 범위만 허용한다. 이 2초는 별도 시험 oracle이며 운영 VRL 정책을 바꾸지 않는다.

검증한 정제 계약은 `time_status=trusted_context_creation`, `time_basis=nginx_modsecurity_context_creation`이다. 요청 context 생성 시각을 보존하며 요청 완료·응답·access log 기록 시각으로 표시하지 않는다. 원문 producer 계약 통과 뒤 실제 감사 원문에 VRL을 별도로 적용해 확인했다.

`stable-format.conf`는 binding·형식을 정의하고 세대마다 그대로 재사용한다. `generation-paths.conf`와 `modsecurity.conf`에는 해당 세대 access/audit 경로를 넣는다. 시험의 `config_sha256`은 **정확한 stable format 설정 바이트**의 SHA이며 경로 설정 SHA와 분리한다. 동일 binding으로 경로만 바꾸어도 v2 감사 행 자체에 요청 context의 명시 시각이 남는지 확인한다. 최소 access 원문은 reader 대조에만 사용하며 v2 감사의 시간 근거로 대신 사용하지 않는다.

- `--mode smoke`: UID/GID 101의 private nginx master·worker, 정상 요청 1건, 실제 Vector audit/access와 private Wazuh audit queue의 정확 수신·SHA를 검사한다.
- `--mode rotate`: 첫 정상 요청, 이전 worker가 수락한 부분 POST, 새 세대 정상 요청의 총 3건을 2세대(2/1)에서 검사한다. 새 pathname+HUP 후에도 옛 요청의 소켓과 audit/access FD가 유지되는지 확인하고, 3초 이상 완료를 늦춰 v2 시각이 완료 시각이 아닌 앞선 context 시각인지 대조한다. old writer FD 0·정확 reader 수신·Wazuh 논리 EOF/SHA를 확인한 뒤 인접 세대를 공개한다.

Vector는 원문 행에서 LF만 제외한 SHA, Wazuh는 설치된 cJSON의 `PrintUnformatted` 재직렬화 SHA를 비교한다. 같은 binding의 여러 세대는 request ID 집합으로 구분하여 앞 세대 행을 다음 세대의 성공으로 재사용하지 않는다. Vector 종료 코드 0과 Wazuh의 SIGTERM 종료 코드 1·최종 file_status 일치를 그대로 요구한다. Wazuh fixture는 `only-future-events=no`, `max-size=2GB`를 사용한다. 이 결과를 현재 운영 raw 입력의 기본 future-only 동작과 혼동하지 않는다.

## 재사용·격리·보관

기존 [WAF 회전 probe](../waf-rotation/run-probe-a.py)를 SHA `ae12559a4641e596c647bc009a7f0d68906e2890d8201d18fca75537e324f7fe`에 고정해 읽은 바이트로 import/subclass한다. 이전 소스는 수정하지 않는다. namespace, exact PID/start tick/pidfd, CID·설정·운영 prefix 전후 대조, timeout의 TERM→finally→제한된 emergency cleanup을 재사용한다.

새 net namespace에는 loopback만 있고 기존 WAF 컨테이너의 mount/root 및 설치 nginx/ModSecurity 바이너리만 사용한다. 새 컨테이너나 운영 프로세스 신호는 없다. private writer의 실제 UID/GID를 `/proc`에서 101로 대조한다. 최상위 writer 디렉터리와 generation 설정 디렉터리는 root 0711, 설정은 root 0444이며, UID 101에 필요한 로그 파일 0600·임시/실행 디렉터리 0700만 쓰기를 허용한다. 다른 사용자에게 설정 쓰기 권한을 주지 않는다. Wazuh는 root 전용 private state·queue와 별도 mount/net namespace를 사용하며 manager에 연결하지 않는다.

`nsenter --setgid`의 supplementary group 제거와 `--setuid`를 사용하고 실제 프로세스의 네 UID/GID 값 및 supplementary groups를 다시 검사한다. [util-linux nsenter 설명](https://man7.org/linux/man-pages/man1/nsenter.1.html). 설치본의 실제 실행 가능 여부는 native smoke에서 확인한다.

원격 결과는 `/var/tmp/capstone-sequential-20261014/step3/producer-v2/run-<고유값>`에 남긴다. 각 출력 경로는 최초 1회만 사용할 수 있다. `smoke` 전체 child 대기는 240초, `rotate`는 480초이며 timeout 시 45초의 정리 유예와 마지막 정확 대상 정리가 별도다. 명령/reader별 기존 제한도 유지한다.

`evidence/`에 세대별 audit/access 원문·stable/path/ModSecurity/nginx 설정·manifest를 root 0400으로 보존한다. manifest는 각 세대의 원래 reader/writer 경로, SHA, expected request ID를 포함한다. 결과에는 request 시작·수락·해제·완료 시각과 v2 시간 대조 metadata를 남긴다. 원문은 A에만 남으며 stdout은 상태·건수·시간/해시 대조 결과·증거 경로만 출력한다. 실패 증거도 지우지 않고 별도 경로에서 다음 시험을 수행한다.

## 실행 전 확인과 남는 경계

부모 운영자가 소스 SHA·호스트·기존 컨테이너를 확인한 뒤 실행한다. 후보에는 기존 frozen probe와 새 helper가 함께 있어야 한다. Mac 설치·서버 패키지 설치는 필요 없다. `test-probe-offline.py`는 형식·시간 거절과 같은 binding의 세대별 reader 판정만 검사하며 실제 nginx 지원을 증명하지 않는다.

```sh
/usr/bin/python3 -B test-probe-offline.py
```

native 성공 전에는 실제 v2 unique ID 길이·UID101 writer 재열기·3건 수신 성공을 주장하지 않는다. 이후 native 성공해도 운영 경로 이전, 영속 rotation state, crash/reboot 복구, 운영 raw future-only checkpoint 정책, v2 VRL의 실제 원문 적용, 원격 ACK는 각각 별도 검증 범위다. 실시간 audit/access 결합 성공을 이 raw reader 시험으로 주장하지 않는다.
