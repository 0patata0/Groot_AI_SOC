# Vector 출력 보관과 장애 확인

## 2026-10-15 02:15 KST 최신 상태 — 정상 daily 회전과 타이머 활성화 완료

**02:15:39 KST 세 타이머의 활성화·첫 실행 검증을 완료했다.** Suricata·WAF raw 타이머의 첫 실행은 `not_due`였고, 출력 유지관리의 정상 daily 실행은 ready·evidence·telemetry 세 파일을 rename/create했다. 빈 quarantine은 회전하지 않았다. 기존 inode의 archive와 활성화 전 EOF까지의 SHA-256 접두 구간을 대조했으며 새 출력 alias를 확인했다. 이는 해당 접두 구간의 보존 증거이고 이후 추가 바이트 전체의 원격 ACK를 뜻하지 않는다.

정상 회전 후 Vector는 **PID2406117 / Invocation `12314ddc66e14e0083b08db2e51fc831`**로 재개했다. 이후 maintenance 타이머만 다시 활성화해 첫 실행 `not_due`, 추가 회전 0회와 동일 Vector를 확인했다. raw 두 타이머는 그대로 유지했고 최종 세 타이머 모두 enabled/waiting이다. Wazuh1909632·WAF2377669·raw state5/11 active·보호 설정은 같으며 pending0, 양 시작 가드와 maintenance check가 통과했다.

첫 검증기는 중간 logger 행의 unit/Invocation 메타데이터 누락을 거절해 maintenance만 일시 중지했다. 사후 검증에서는 저장된 실행 증거와 같은 Invocation의 시작·완료 두 이벤트를 필수로 대조하고, 중간 tag-only 행은 시간상 보조 관측으로 구분했다. systemd가 종료된 oneshot 메타데이터를 초기화한 경우도 정확한 초기화 사전과 저장된 실행 증거를 함께 검사했다. 원래 실패 기록은 유지했다. 최종 증거는 초기 백업의 `timer-activation/` 및 `timer-activation-postcheck/`, [검증 메타데이터](raw-operations/resume-validation-2026-10-14.json)에 연결한다.

운영 runtime·logrotate 상태·시간대를 이 과정에서 직접 수정하지 않았고 추가 force도 없었다. 수동 실행은 아래와 같이 `TZ=Asia/Seoul`을 명시한다. 최종 소스·증거 보관과 임시물 정리를 완료했다(아래 정리 후속 기록). 4단계는 구현 준비 중이고 운영 전환은 없으며 인증서는 마지막이다. 호스트 재부팅·새 WAF CID·새 적격 보안 사건 ACK는 미검증이다. 아래는 당시 상태와 검사 결과를 보존한 기록이다.

**02:19:46 KST 정리 후속:** A의 작업 자료 515파일·4,621,609B와 격리 시험 자료 8파일·98,071B를 보관한 뒤 stage3·시험 fixture·미사용 v1 recovery guard를 제거했다. migration 시작 가드는 유지했고 정리 전후 운영 상태 불변·서비스 신호 0회를 확인했다. Mac의 해당 임시 트리 650파일·55디렉터리·5,318,295B와 B 조회 임시파일 2개도 제거했으며 영구 증거는 유지했다. **이 문구는 267파일·2,077,701B 소스 스냅샷 이후에 추가한 기록**으로 그 스냅샷에 포함된 문서 바이트와 구분한다. **02:20:55 KST 최종 점검도 완료했다.** 두 migration guard는 ready이며 storage 정상·Vector active·recovery=no·collection=[]·binding 검증 및 상태 코드 없음, 세 타이머 enabled/active/waiting을 확인했다.

## 이전 시점 기록 — 2026-10-15 현재 상태 — raw 시작 가드 반영, timer 활성화 대기

현재 `/usr/local/sbin/capstone-vector-maintenance`는 [capstone-vector-maintenance-raw-guard.sh](capstone-vector-maintenance-raw-guard.sh), SHA `2334ba3697cd98a445a5ab83dfa4ba044775868e9ed7a2be9e8ed0cceef0a921`의 설치본이다. 01:26:44 KST CAS 반영 후 실제 `prepare` 경로의 가드를 사용한 출력 force 1회가 **01:31:13, 127.617초, exit0**으로 끝났다. 원본 `capstone-vector-maintenance.sh`는 이전 소스로 보존하며 그대로 재배포하지 않는다.

새 `prepare`는 공유 잠금을 보유한 부모 호출 아래에서 **pending 생성·Vector stop 전에** migration barrier가 released인지와 고정 raw runtime의 읽기 가드를 확인한다. 남은 신호 intent·불완전 state·불명확 checkpoint·timeout·출력 불일치는 pending 생성 0/stop 0으로 보류한다. 기존 ready/evidence 두 reader의 EOF·prefix SHA 확인과 빈 파일의 고유 FD/offset0 조건은 유지한다. 전체 서비스 제한은 300초이며 모든 단계의 최악 시간을 합해도 완료된다는 보장은 아니다.

EVE와 audit는 별도 [원본 세대 회전](raw-operations/README.md)으로 전환해 copytruncate에서 제외했다. Suricata fast/stats/suricata.log와 WAF access는 기존 copytruncate다. 정제 ready·evidence·quarantine·telemetry 네 출력은 이 문서의 rename/create 회전을 계속 사용한다. WAF v2는 access 결합에 의존하지 않으며 access 원본은 보조 보관 대상이다.

**01:48:58 KST 같은 CID의 WAF 실제 재시작도 통과**했고, master2377669·healthy, Vector2368467/Wazuh1909632, Suricata gen1/revision5·WAF gen3/revision11 active가 유지됐다. 현재 원본·출력 회전 timer는 **disabled**, 활성화 사전 검사 **2회/enable 0회**다. 실제 호스트 재부팅은 0회이고 이번 관찰 구간의 자연 적격 보안 사건 ACK 표본도 0건이다. [전환·재시작 근거](raw-operations/resume-validation-2026-10-14.json).

두 번째 timer 사전 검사의 daily 회전 판정은 앞선 수동 force가 시험 helper의 `TZ=UTC`로 logrotate 상태에 `2026-10-14 16:29`를 기록한 반면, 운영 timer는 KST `2026-10-15 01:54`를 기준으로 판단한 차이다. ready/evidence/telemetry가 대상이고 빈 quarantine은 제외됐다. 과거 기록이나 상태 파일을 고쳐 판단을 맞추지 않으며 정상 timer 첫 실행의 결과 확인은 아직 대기다.

관리자의 수동 실행도 운영 timer와 같은 시간대를 명시한다. `check`는 상태 확인, `run`은 정상 주기 판단이고 `force`는 별도로 조율한 실제 강제 회전에서만 사용한다.

```sh
/usr/bin/env TZ=Asia/Seoul /usr/local/sbin/capstone-vector-maintenance check
/usr/bin/env TZ=Asia/Seoul /usr/local/sbin/capstone-vector-maintenance run
# 별도로 조율한 강제 회전에서만 실행
/usr/bin/env TZ=Asia/Seoul /usr/local/sbin/capstone-vector-maintenance force
```

기존 v1 `vector-storage-a.yml`은 managed raw/migration barrier가 있으면 변경 전에 거절한다. 현재 보완은 [관리자 전용 전환·복구 절차](raw-operations/INITIAL-MIGRATION.md)를 따른다. 4단계 운영 변경은 미착수(읽기 사전 확인만), 인증서 관리는 마지막 순서다. 아래 내용은 각 이전 시점의 기록이며 당시 copytruncate 유지·timer active 표현을 현재 상태와 구분한다.

**2026-10-14 21:20 KST 2단계 운영 적용 완료:** 기존 5분 maintenance에 원천 세 파일의 EOF 포함 마지막 최대 32MiB씩을 읽는 native 바이트 검사를 연결했다. 사전 scanner 합성 34개와 private mount namespace의 실제 maintenance `check` 12개가 통과했다(통합 7.491초). 이 격리 시험에서 후보/운영 설정 SHA·기존 raw-state·운영 원천 inode/prefix 불변, logger 호출 0, namespace/fixture 정리를 확인했다. 이후 B는 21:16:46 기존 104개·후보 116개·재시작 후 116개 검증을 통과해 두 규칙만 추가하고 같은 manager CID를 한 번 재시작했다. A는 21:18:20 검사기·binding 새 파일 네 개와 maintenance 갱신을 적용했으며 반복 `changed=0`, Vector PID/실행 식별자 불변을 확인했다. [수집 감시의 최신 계약](collection/README.md), [검사기 상세](collection/line-length/README.md).

21:19:26 기존 oneshot의 **수동 실행**은 exit 0이었고 root 0600 `raw-lines.json`에 세 원천의 안정된 전체 스냅샷(`full_file_scan=true`, `statuses=[]`)을 저장했다. 당시 파일은 모두 32MiB 이내였으며 최대 행은 Suricata 8,903byte·audit 2,188byte·access 405byte였다. timer는 active/waiting이고 자연 주기에서 새 코드가 실행됐는지는 아직 확인하지 않았다. 21:20 A의 기존 보호 파일 59개와 프로세스 식별자, B의 기존 설정·승인 경계 및 나머지 다섯 컨테이너가 유지됐다. B analysisd는 44 threads·decode/rule matching 1/1·단일 표본 dropped 0/queue 사용률 0이었다. 소스·증거 영구 보관과 임시물 정리는 이 기록 시점에 진행 중이다.

운영 `check`는 `raw_lines=<JSON>`만 추가 출력하며 상태 파일이나 logger를 쓰지 않는다. `run/force`는 기존 배포/유지보수 잠금 안에서 `/var/lib/capstone-vector-maintenance/raw-lines.json`을 root 0600으로 원자 저장하고, 초과 관측/검사 불가 두 고정 상태만 기존 health logger에 전달한다. Wazuh 100252/100253은 level 3·ignore 900초·no email이다. `/etc/capstone-vector/raw-line-binding.json`이 검토된 `vector.toml`·`vector.env` SHA를 고정하며, 배포 전 또는 검사 전후 불일치는 검사 불가로 처리한다. 출력 회전의 네 파일·두 reader EOF/SHA gate·원천 raw copytruncate·Vector checkpoint와 서비스 재시작 정책은 그대로 유지했다.

각 원천은 최대 32MiB·5초(종료 유예 1초), 전체 scanner 호출은 30초(종료 유예 2초)이며 기존 maintenance service 제한 300초 안에서 실행한다. 원문은 출력하거나 새 보존 파일에 복사하지 않는다. `within_scanned_range`는 조사한 안정된 구간에 대한 관측일 뿐이며, 검사 사이 사라진 행·범위 밖의 행·copytruncate gap·원격 ACK·복구를 보장하지 않는다. 이 최신 블록 아래의 배포/시험 수치는 각 이전 시점의 이력이다.

**2026-10-14 12:22 KST 원천 Suricata 추가 검증:** 별도 offline writer와 실제 Vector/Wazuh private reader에서 지연 공개 회전은 각각6건·중복0, 연속2회전·정상재시작을 통과했다. 단순 rename 대조군에서는 늦은 옛파일 기록/중간 세대2건을 놓쳤다. 운영 copytruncate·기존 출력 회전기는 유지하며 이번 결과는 격리 검증이다. 강제 종료·재부팅·초기 checkpoint 이전·운영 Vector 완료 근거·WAF별 확인 후 운영 전환해야 한다. [실측·시도 이력·한계](raw-rotation/README.md).

2026-10-14 A에 native logrotate·systemd timer를 적용했다. **현재 ready·evidence·quarantine·숫자 telemetry의 네 출력**을 대상으로 하며 원시 Suricata/WAF 회전 정책은 바꾸지 않는다. 구현은 `capstone-vector-maintenance.sh`, `logrotate.conf`, `capstone-vector-maintenance.{service,timer}`와 운영자용 `vector-storage-a.yml`이다.

**06:09 KST 확장:** evidence 독립 출력과 두 Wazuh reader의 EOF·SHA 검사를 적용했다. native110개·jq18개·분리 reader9개 통과 후 Vector/storage의 최종 **누적** Ansible recap은 첫 `ok68 changed5`, 재적용 `ok67 changed0`이었다. 중간 Vector recap을 별도로 더하지 않는다. 실제 두 파일 회전 결과는 아래 후속 기록과 [evidence 검증](EVIDENCE.md)을 따른다.

**04:49 KST 확장:** private telemetry 파일도 같은 회전에 포함하고 현재 Invocation heartbeat·수집 오류/손실 신호·버퍼 압력 상태를5분마다 확인한다. 자세한 판정과 탐지 불가 범위는 [수집 경계](collection/README.md)를 따른다. raw 원본과 checkpoint는 유지한다.

## 회전 순서

아래는 10/14 최초 출력 회전 순서이며 현재는 위 raw 시작 가드가 pending 생성·stop 전에 추가된다. 5분 주기는 활성화 후의 정책으로, 현재 활성화 여부는 상단 기록을 따른다.

5분마다 용량과 서비스 상태를 확인하고 logrotate가 daily 또는 maxsize 64MiB 조건을 판단한다. 실제 회전 때만 Vector를 멈추고 다음 순서를 따른다.

1. Wazuh agent는 계속 동작한다. ready와 evidence **각각** 현재 inode를 연 reader가 정확히 하나이고 FD offset이 파일 크기와 같아야 한다.
2. 파일 쓰기가 멈춘 상태에서 비어 있지 않은 두 파일은 **각각** Wazuh가 저장한 논리 offset이 전체 크기와 같고 native prefix SHA1이 파일 전체 SHA1과 일치해야 한다. 커널 FD 위치는 libc 선읽기를 포함하므로 단독 증거로 쓰지 않는다. 빈 파일도 고유 reader·FD offset0을 확인한다.
3. logrotate가 네 출력을 rename/create로 회전해 새 root:root0600 파일을 만든다(빈 파일은 `notifempty`에 따라 제외). Wazuh가 새 ready/evidence를 모두 연 뒤 Vector를 재개한다. 출력 파일은 copytruncate하지 않는다.
4. 중단된 회전은 root 전용 `resume.pending`을 남긴다. 다음 실행이 reader를 다시 확인한 뒤 재개한다. 대기 실패 시 파일을 지우거나 처리 위치를 강제 변경하지 않는다.

단계별 reader 대기는 90초, systemd 전체 제한은 300초다. 실제 A의 Wazuh 파일 상태 저장 간격 64초를 고려했다. 배포와 같은 flock을 사용하며 정상 잠금 충돌(exit75)은 systemd 실패 경보를 만들지 않고 다음 주기에 재시도한다. raw 엔진·Wazuh agent는 회전 때문에 멈추지 않는다. Vector가 멈춘 사이 수집이 지연되면 공통 메타데이터가 120초보다 오래된 이벤트를 신규 상관에서 제외한다.

## 보존과 감시

- `rotate 48`, `maxage 14`, 압축 및 한 회전 지연 압축을 사용한다. **14일 전체 보존을 보장하는 조건이 아니다.** 64MiB 크기 회전이 잦으면 48개 제한이 먼저 적용되며, maxage는 회전 시 검사한다. 5분 검사 사이 파일이 64MiB를 초과할 수 있다.
- 가용 5GiB 미만 또는 사용률 80% 이상은 `disk_space_low`, 2GiB 미만 또는 90% 이상은 `disk_space_critical`을 journald에 기록한다.
- `vector_not_active`, `reader_not_at_current_eof`, `rotation_failed_pending_recovery`도 `capstone-vector-storage` 프로그램명으로 기록한다. Wazuh 전용 상태 규칙은 [연결 문서](../wazuh-vector/README.md)를 따른다.
- 용량 경보가 logrotate 보존 정책 밖의 데이터·Vector 버퍼를 자동 삭제하지 않는다. 자동 원시 로그 삭제나 서비스를 강제 정지하는 용량 대응은 구현하지 않았다.
- ready·quarantine·evidence는 각각268,435,488byte의 독립 disk buffer를 사용하며 설정 합계는805,306,464byte(약768MiB)다. 파일·archive·버퍼 메타데이터 용량은 별도다. 세 buffer의 full 정책은 block이므로 evidence 병목이 공통 source와 ready에도 영향을 줄 수 있다. telemetry는 별도 memory buffer이며 위 disk 합계에 포함하지 않는다.

## 직접 검증

02:51:11 KST 통제된 실제 회전을 수행했다. Vector 정지부터 reader 확인·재개까지 85초였다. 493,119bytes 보관본의 SHA-256이 닫힌 writer 파일과 같았고, 새 inode로 전환한 뒤 Vector·agent·timer가 active였다. 회전 뒤 Vector `NRestarts=0`, recovery marker 없음, 사용률18%·가용 약47.8GB를 확인했다. 이는 의도한 stop/start이 없었다는 뜻이 아니라 자동 실패 재시작이 없었다는 뜻이다.

부모 없는 prepare 호출은 exit77, 배포 lock을 보유한 실행은 exit75로 거절됐다. 이 거절 시험 전후 Vector PID·InvocationID가 같고 pending marker도 없었다. logrotate --debug, bash 구문, systemd unit 검사를 통과했으며 동일 Ansible 재실행은 changed0이다. B의 상태 규칙은 합성 native logtest로 검증하며 실제 운영에 장애 경보를 주입하지 않는다.

**06:06:21~06:08:09 후속 실측:** evidence를 포함한 force 회전1회가108초에 완료됐다. ready638,200byte와 evidence47,324byte archive의 inode·크기·전체 SHA256이 writer 정지 후 기록한 값과 같았다. 두 새 파일에 Wazuh FD가 각각 정확히 하나·offset0이었고 logcollector PID는 유지됐다. Vector는 새 Invocation으로 정상 재개, NRestarts0, pending 부재와 설정 해시 불변을 확인했다. 06:09:10 새 Invocation heartbeat와 evidence metric, `collection=[]`, `recovery=no`도 확인했다. 이 결과는 로컬 두 reader 회전 시험이며 원격 ACK나 전원 장애 내구성 검증은 아니다.

## 확인하지 못한 보장

다음 문단은 최초 출력 회전 당시의 경계다. 후속으로 EVE·audit의 raw 회전과 [이전 부트 유한 자동 보존](history-auto/README.md)을 적용했지만, 이들이 원격 ACK·전체 무손실·전원 장애 후 정확히 한 번 처리를 보장하지는 않는다.

로컬 reader 처리 위치는 manager/Indexer 수신증이 아니다. Wazuh 내부 queue 무폐기·네트워크 장애 시 최종 전달·전원 장애 시 fsync 영속성을 이 회전기가 보장하지 않는다. 기존 raw copytruncate, Vector의 이전 부트 journal 미회수, file source의 1MiB 초과 행 제외, 재전송의 영속 중복 제거도 별도 문제다. 실패/지연이 있으면 기존 raw 입력과 원본을 보존하고 신규 상관 경보를 승격하지 않는다.

근거: [logrotate 보존·회전 동작](https://man7.org/linux/man-pages/man8/logrotate.8.html), [설치 버전 Wazuh의 논리 offset 저장](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/logcollector.c), [Vector file sink ACK 범위](https://vector.dev/docs/reference/configuration/sinks/file/).

**21:27 KST 후속 확인:** 배포 후 타이머가 21:24:31에 자연 실행돼 21:24:32 정상 종료했다. root0600 상태 파일의 binding 일치·3원천 안정·상태 코드 없음이 확인됐다. 수동 실행 검증에 더해 정기 실행도 확인한 것이며 전수 무손실 보장은 아니다. A149/B107개 검증 파일을 영구 증거 경로에 SHA 대조해 보존했고 프로젝트 소스 동기화·작업 파일 정리를 마감 중이다.
