# Suricata Wazuh checkpoint 불일치 조사

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../../STATUS.md) · [실행 계획](../../../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

> **2026-10-15 운영 반영 완료:** stats-ignore 제거와 제한 AR 활성화, agent stop/start각1회 및 timer/guard복원을마쳤다. 이후 native통계필드한도 문제는 B1024설정으로보완했다. 자연stats2행·CP27표본 불일치0, Boverflow0/agent001Active 확인. 원문/CP수동수정0. 재현62파일은 `/var/backups/capstone-suricata-stats-ignore-20261015/native-checkpoint-comparison.tgz`로보존·검증후전용임시경로제거했다. 아래사전분석과구분한다.

2026-10-15 KST 조사 기록이다. 이 폴더는 원인 조사·종료형 격리 시험과 검토 중인 고정 A 일회성 수정 후보를 포함한다. 현재 운영 적용은 하지 않았다. 운영 checkpoint와 guard를 수정하는 경로는 없으며 새 패키지·상주 Python·운영 원문 반출도 없다.

## 직접 관측과 소스 해석

아래 라이브 사실은 부모 운영자가 A에서 읽기 검사한 결과를 전달한 것이다. 이 문서 작성자는 SSH를 실행하지 않았다.

| 관측 | 값 |
| --- | --- |
| 04:41 KST saved offset | `3399532` (LF 경계) |
| 당시 stored SHA1 | `246c1541a8e1a2ae0d3827f0cec408d956356671` |
| 같은 offset의 실제 prefix SHA1 | `047ed148133c1e9d2a9ab8c09f8d6d092b4bfc40` |
| 바로 다음 stats 행 | 8,858 B, 종료 offset `3408390` |
| 위 stats 행까지의 prefix SHA1 | **당시 stored SHA1과 정확히 동일** |
| 후속 정상 관측 | offset `3422150`, stored/prefix 모두 `2b9dd707005b799fd87507a0b2f005619ba76e23` |
| 원문 구조 검사 | NUL 0, LF 종료, JSON 2,202행 유효, 최대행 8,872 B |

실제 Suricata localfile에는 다음 PCRE2 ignore가 존재했다. 원문 로그 값은 포함하지 않는다.

```text
^\{"timestamp":"[0-9T:.+-]+","event_type":"stats","stats":\{
```

Wazuh 4.14.8 [`read_json.c`](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/read_json.c#L29-L148)는 LF 행을 hash context에 먼저 반영한다. 이후 ignore/restrict에 걸리면 `continue`하여 맨 아래 `current_position` 갱신을 건너뛴다. 함수 끝에서는 앞서 진행한 hash context와 마지막 정상 행의 offset을 함께 저장한다. [`w_update_file_status`](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/logcollector.c#L2347-L2367)는 두 값을 다시 정합화하지 않는다. **이번 stored hash가 다음 ignored stats 행 끝과 일치한 사실은 이 경로와 직접 부합한다.** 격리 바이너리 재현 전에는 실제 호출 순서까지 관측했다고 표현하지 않는다.

이는 JSON 파일이 잘렸거나 raw bytes가 바뀌어야만 발생하는 현상이 아니다. 당시 stat/CP가 안정됐어도 저장된 hash/offset 쌍 자체가 불일치할 수 있다. NUL/과대행 경로도 소스상 별개 가능성이지만 이번 검사 범위에서는 NUL 0과 최대행 8,872 B로 배제된다. native 첫 `fgets` 한도는 `65536-256-1=65279` B다. [고정 버전 상수](https://github.com/wazuh/wazuh/blob/v4.14.8/src/headers/defs.h#L23-L50)

`w_get_hash_context`는 기존 context를 복사하며, 이후 정상 행 처리가 끝나면 offset도 따라갈 수 있다. 디스크 checkpoint는 파일 검사 주기에 저장된다. 반면 재시작 시 불일치한 hash를 받으면 native 자체는 offset0부터 읽는 경로가 있다. 그러므로 **불일치 중 restart로 해결하거나 CP를 수동 교정하지 않는다.** [context/재시작 경로](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/logcollector.c#L2576-L2686), [주기 저장](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/logcollector.c#L860-L866)

기존 `cg_wazuh_cold`의 `same_inode_prefix_changed` 보류는 유지한다. 이 경계는 임의 파일 변조와 위 native 상태를 구별하지 않으므로, 원인이 설명됐다는 이유만으로 PASS로 바꾸지 않는다. logical EOF도 전달·분석·색인 완료 증거가 아니다.

## 격리 native 비교 후보

[`run-isolated-a.py`](run-isolated-a.py)는 기존 설치 Wazuh 바이너리와 라이브러리를 private 복사하고 기존 검증된 mount/network 격리·private Unix queue·PID/start/pidfd 자식 정리 코드를 재사용한다. 운영 `ossec.conf`나 checkpoint를 입력으로 사용하지 않는다. private vcheck/loop만 1초로 설정하며 hash/offset은 native가 작성한 것만 읽는다.

1. `default` 프로필은 실제와 같은 stats ignore를 둔다. 정상 합성 JSON→stats JSON→정상 JSON을 순차 append하여 stats 미송신, offset 정체/hash 진행 관측 여부, 다음 정상 행 뒤 회복을 기록한다.
2. `recover` 프로필은 ignore가 없다. 같은 stats가 private queue에 정확히 1회 도착하고 hash/offset이 EOF와 일치해야 한다. 이는 B manager 규칙의 `no_log` 여부를 시험하지 않는다.

최대 180초 alarm, private 파일 크기·자식 회수·운영 설정/PID 전후 대조를 둔다. mismatch는 짧은 관측 구간에 놓칠 수 있으므로 `completed_observations`와 `mismatch_observed`를 별도로 보고한다. 재현하지 못한 실행을 원인 확정 PASS로 해석하지 않는다. 합성 원문·private checkpoint는 A evidence에만 보존하며 stdout은 메타데이터뿐이다.

의존 소스는 원래 파일을 변경하지 않고 같은 private dependency 디렉터리에 복사한다. 실행 전 SHA를 검증한 바이트만 import한다.

| 파일 | SHA-256 |
| --- | --- |
| [`../../raw-restart/run-probe-a.py`](../../raw-restart/run-probe-a.py) | `4886142c41408978438cdee641ba50c2e6eb27fee119e743802a176fd5d9ea83` |
| [`../../raw-restart/wazuh-isolated.sh`](../../raw-restart/wazuh-isolated.sh) | `a9001ac1fb2755dcb94409817d44038665fbfb0c508469e0a428747cef6593cd` |

```sh
# 부모 운영자가 검토한 root private source/dependency 경로만 사용한다.
# output parent는 root0700, run-01은 없어야 한다.
python3 -B /ABS/checkpoint-diagnosis/run-isolated-a.py \
  --reuse /ABS/private-reuse \
  --output /var/tmp/capstone-checkpoint-diagnosis-20261015/run-01
```

**A native 결과:** 부모 운영자의 첫 실행에서 ignore의 mismatch/old-offset·hash-ahead를 실제 관측했고 ignore 없는 프로필은 일치했다. 첫 비교의 `only-future-events` 설정이 달랐으므로 이를 두 프로필 모두 `no/max-size=2GB`로 맞춰 다시 실행했다. 두 번째 native에서도 **ignore 있음은 불일치 재현, ignore 없음은 불일치 없음**, 자식 종료·임시 정리·운영 설정/PID 불변을 확인했다. 결과는 [native-validation-2026-10-15.json](native-validation-2026-10-15.json)에 부모가 보관했다. 이 두 번째 결과가 동일 옵션 대조 근거다.

## 최소 운영 수정안 — 아직 적용하지 않음

native 비교가 확인되면 Suricata localfile의 위 **정확한 ignore 한 항목만 제거**하는 방안이 가장 작다. stats를 생략하려면 reader offset/hash를 건드리지 않는 B 분석 규칙 단계에서 처리한다. 실제 stats 형태의 native logtest가 level0/no_log인지 먼저 검사하며, 기본 규칙이 그러할 것이라고 추정해 배포하지 않는다. 발생률·manager 처리 증가도 실제 수치로 확인한다.

**후속 부모 실측:** B의 정확한 stats JSON native logtest는 기본 decoder `json`, 규칙 `86600/level0`로 분류됐다. 처음 셸 인용이 깨져 잘못 전달된 시험은 무효로 남기고, 정확한 base64 입력으로 재검증한 결과다. 따라서 이번 stats 수정에 별도 B 규칙 추가는 필요하지 않다. level0 분류 시험을 자연 운영 경보·색인의 종단 확인으로 확대하지 않는다.

**추가 승인 범위:** 부모는 A의 기존 active-response `disabled=yes`를 `no`로 바꾸는 작업도 같은 config CAS와 재시작 1회에 묶도록 지시했다. [`fix-stats-ignore-a.py`](fix-stats-ignore-a.py)는 두 정확한 항목만 바꾸고 ca_store/ca_verification·다른 설정은 보존한다. CP 원인 수정과 AR 활성화는 별도 변경으로 plan에 기록한다. AR adapter·기존 helper의 검증·배포 영수증이 있어야 apply를 허용하며, 현재 공개 apply는 차단 상태다. [`test-fix-stats-ignore.py`](test-fix-stats-ignore.py)의 로컬 18개는 정확한 두 치환·부정 입력·순수 state 후보·private 실제 CAS/rename 뒤 실패를 검사했고 서버 실행은 하지 않았다.

`/var/ossec/etc/ossec.conf`는 양 engine state의 `source_pins.wazuh_config_sha256`에 고정돼 있다. 정상 `raw_state_cas`는 source pin 변경을 거절하므로 기존 state-lib를 완화하지 않는다. 아래는 별도 관리 작업의 필요한 조건이며 이 폴더가 구현·실행한 변경 절차는 아니다.

1. shared rule-change/vector lock을 취득하고 raw 두 engine이 `active`, pending/stop·writer intent가 없음을 새로 확인한다. raw 두 timer와 출력 maintenance timer의 원래 상태를 기록해 일시 정지한다. 필요하면 재부팅 중 경합도 막는 일시 disable을 영속 기록한다.
2. 원본 config, 양 state의 exact SHA·메타데이터와 runtime/guard pin을 보존한다. 후보는 config의 한 ignore만 제거하고 양 state에서 `revision+1`과 `wazuh_config_sha256`만 바뀌어야 한다. generation/inode/phase/proof/다른 pin은 그대로이며 `state.jq` 검사를 통과해야 한다.
3. 같은 불일치가 남아 있으면 자연적인 정상 행 후 `cg_wazuh_cold`가 PASS할 때까지 기다린다. 운영 JSON을 인위적으로 append하거나 checkpoint를 고치지 않는다. 읽기 검사와 정지 사이 재발할 수 있으므로 **정지 후에도 저장 CP의 prefix 정합성을 재검사**한다. 실패하면 다음 단계·재시작을 자동 진행하지 않고 기록한다.
4. config와 두 state의 부분 게시 중 reader 자동 시작을 막는 고정 임시 systemd 시작 barrier를 확인한다. runtime guard 자체는 유지한다. native 후보 config 검사 후 root 전용 durable intent, 원본 history 보관, 3파일 정확 before→after prefix CAS·fsync로 변경한다. 도중 실패 시 재시작/임의 rollback 없이 정확히 바뀐 파일을 조사한다.
5. 변경된 config와 양 state가 모두 결속되고 기존 양 runtime guard가 통과한 뒤 barrier를 제거·daemon-reload하고 허가된 Wazuh 재시작 1회를 수행한다. start 결과가 불명확하면 재발송하지 않는다. Vector/writer는 유지하며 Wazuh 새 PID·서비스·CP prefix와 이후 자연 stats 두 주기를 확인한다. 마지막에 기록한 timer 상태를 복원한다.

계속 쓰이는 active 원본과 별도 reader의 작업이므로 순차 검사만으로 모든 순간의 변경을 막지는 못한다. 특히 정지 직전/직후 CP가 다시 불일치하면 무조건 시작 허용 대신 안전하게 보류하는 절차가 필요하다. 구체 적용 controller는 부모 운영자가 새 라이브 pin과 native 결과를 검토한 뒤 결정한다.

## 후속 일회성 controller 후보

앞 절의 설계를 [`fix-stats-ignore-a.py`](fix-stats-ignore-a.py)로 구현했다. 공개 `apply`는 검토 차단 상태다. 로컬 회귀는 기존 18개에 AR 준비 수신증의 exact schema·typed flags·고정 agent/rule·설치 파일 집합/해시·명시 SHA 누락 거절 7개, 실제 디렉터리 권한 계약과 CAS 중 parent 변경 거절 4개를 추가하여 **29개 PASS**다. 이는 Linux 서비스나 실제 config 적용 시험의 대체가 아니다.

부모 실측에서 `/var/ossec/etc`는 symlink 없는 `110:110/0770`, 그 부모 `/var/ossec`는 `0:110/0750`이다. 이 설치 계약 때문에 controller는 `/var/ossec/etc` 한 경로만 정확 `110:110/0770`을 허용하고 다른 모든 조상의 root/no022 검사를 유지한다. CAS의 파일 읽기·임시파일·rename·fsync·readback은 고정한 parent FD를 기준으로 하며 디렉터리 dev/inode/UID/GID/mode가 바뀌면 거절한다. shared lock과 정확 before SHA는 이 작업들의 협력 경합을 막는 조건이며 Wazuh group 자체를 별도 보안 경계로 바꾸는 조치는 아니다.

`prepare`는 root private `/var/backups/capstone-suricata-stats-ignore-20261015`에 before/after 3파일과 native config 검사 로그, exact source SHA가 결속된 plan을 생성한다. config에서는 stats ignore 제거와 기존 AR disabled=no 두 변경만 허용하며 state에서는 양쪽 revision+1/새 config SHA만 바꾼다. 최종 controller 바이트와 plan이 결속되므로 공개 차단 해제 등 source 변경 전에 만든 plan은 이후 source로 적용할 수 없다.

`apply --plan-sha256 <64hex> --ar-ready-sha256 <64hex>`는 고정 `/var/lib/capstone-automation/native-containment/ready.json` root0400/parent0700의 정확 9키와 agent001/rule100110, native 시험·B 설정 확인, 실제 설치된 reader/helper/adapter 세 파일의 정확 SHA·소유·mode를 검사한다. 실제 containment가 실행됐다는 영수증은 받지 않는다. 준비 영수증 자체를 이 controller가 발행하지 않는다. 계약은 [`native-containment-ar.md`](../../../../mcp/native-containment-ar.md)를 따른다.

고정 shared lock 아래 timer 3개를 일시 disable하고, 양 reader의 임시 drop-in에 `ExecStartPre=/usr/bin/false`와 `Restart=no`를 둔다. Wazuh stop 1회 뒤에도 기존 양 guard가 통과해야 3파일 CAS를 진행한다. 각 state의 원본은 native history 이름으로 fsync 보관한다. 모든 CAS와 AR 재검증 후 false만 제거하고 Restart=no를 유지한 채 Wazuh start 1회를 요청한다. 성공 확인 후 임시 drop-in을 제거하고 기존 Restart 정책·timer enable 상태를 복원한다. timeout·부분 게시 실패는 durable intent와 완료/결과불명 경로를 남기고 자동 rollback·명령 재발송 없이 중단한다. 이때 timer 또는 시작 차단이 남을 수 있으므로 실패 증거를 먼저 조사해야 한다.

`verify --plan-sha256 <64hex>`는 설치 3파일/state schema·AR 영수증·새 Wazuh 프로세스와 Invocation·기존 Vector PID/Invocation·양 native guard를 다시 읽는다. 이후 자연 stats 두 주기의 CP 정합성, 실제 AR 종단 및 timer 정기 실행 여부는 별도 운영 관측이며 이 후보의 성공 JSON만으로 완료라고 하지 않는다.

**실제 prepare 거절 후 정정:** 부모의 A prepare는 원본 SHA가 그대로인 상태에서 `exact_stats_ignore_missing`으로 멈췄다. 실제 XML은 `type="PCRE2"`인데 초기 후보가 `type="pcre2"`를 전제한 오류였다. 정확 대문자만 허용하도록 두 검사 지점을 고쳤고 소문자 거절 회귀를 추가해 로컬 **30개 PASS**다. 편집 중 공개 apply는 다시 차단했다. 당시 private BASE는 만들어졌으나 config 후보 생성 전이므로 운영 3파일·서비스 변경은 없었다. 실패 디렉터리는 실제 목록을 대조한 뒤 별도 고정 실패 경로로 보존하고, 최종 소스 검토·활성화 후 같은 BASE에 새 plan을 준비한다. 이전 plan/source의 덮어쓰기나 적용 재시도 기능을 추가하지 않는다.
