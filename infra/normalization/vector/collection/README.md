# 수집·보존 경계와 검토용 개선안

## 2026-10-14 21:20 KST 2단계 — EOF 과대 행 감시 운영 적용·수동 실행 확인

**사전 검증 뒤 A/B 운영 적용을 완료했다.** B는 21:16:46 기존 104개·후보 116개·같은 manager 컨테이너 재시작 뒤 116개 native 검증을 통과했고, level 3 상태 규칙 100252/100253만 추가했다. manager는 같은 CID로 한 번 재시작했으며 나머지 다섯 컨테이너는 유지됐다. A는 21:18:20 검사기 세 파일과 SHA binding 한 파일을 설치하고 maintenance를 갱신했다. 반복 적용은 `changed=0`이었고 Vector PID/실행 식별자는 같았다. 새 패키지 설치나 운영 합성 입력은 없었다.

21:19:26 기존 oneshot을 **수동으로 한 번 실행**해 exit 0과 root 0600 상태 저장을 확인했다. 세 원천 모두 당시 파일 전체가 32MiB 이내였고 `file_stable=true`, `full_file_scan=true`, `statuses=[]`였다. Suricata 18,058,977byte/최대 행 8,903byte, WAF audit 10,072byte/2,188byte, WAF access 810byte/405byte를 검사했다. 이는 해당 시점의 안정된 스냅샷 관측이며 과거 전체 로그의 무손실 판정이 아니다. timer는 active/waiting이지만 **새 감시 코드가 자연 타이머 주기로 실행됐는지는 아직 확인하지 않았다.**

21:20 사후 대조에서 A의 기존 보호 파일 59개(호스트 8·컨테이너 51), 컨테이너·서비스·Vector/Wazuh reader 식별자가 유지됐다. B는 analysisd 44 threads, decode/rule matching 1/1, 관측 시점 dropped 0·각 queue 사용률 0이었고 승인 경계와 기존 규칙·설정이 유지됐다. 이 단일 표본을 지속적인 queue 비움이나 무손실 보장으로 해석하지 않는다. 소스·증거의 영구 보관과 작업 임시물 정리는 이 기록 시점에 진행 중이다.

기존 숫자 telemetry에서 누락될 수 있는 EOF 과대 행을 보완하기 위해 **고정 원천 세 파일의 제한된 마지막 구간**을 검사하는 후보를 추가했다. 새 패키지나 상시 Python 수집기 없이 기존 Bash·GNU coreutils·jq를 사용한다. native scanner 합성 34개와 실제 maintenance `check`를 연결한 격리 시험 12개가 모두 통과했다. 후자는 7.491초였으며 후보/운영 설정 SHA, 원래 raw-state 파일, 운영 원천 inode·기존 prefix가 유지됐다. private namespace·fixture 정리가 완료됐고, private logger stub의 호출은 0이었다. 이는 다른 운영 프로세스의 로그까지 없었다는 주장이 아니다. [scanner 계약과 검증 범위](line-length/README.md).

검사 범위는 각 파일을 열기 전 고정한 크기 `S`의 `[max(0, S−32MiB), S)`이며 세 파일 합계는 최대 96MiB다. LF를 제외한 바이트를 같은 길이의 ASCII로 치환한 뒤 `wc -c -L`로 검사하므로 NUL·UTF-8·탭·CR도 바이트 단위로 센다. **1MiB를 초과한 행**이 대상이고, WAF VRL의 별도 128KiB 제한과 혼동하지 않는다. 마지막 LF 없는 행도 포함하지만 구간 앞의 행 조각과 검사 범위 밖은 전수 검사로 표시하지 않는다. 소스마다 timeout 5초·종료 유예 1초, maintenance의 전체 scanner 호출에는 timeout 30초·종료 유예 2초를 둔다. 읽는 동안 파일·경로 상태가 바뀌거나 입력을 확정하지 못하면 `inconclusive`다. 변경 중 초과 사실까지 관찰했으면 초과와 검사 불가 상태를 함께 남긴다.

| 운영 상태 코드 | 의미 | Wazuh 규칙 |
|---|---|---|
| `collection_raw_line_oversize_seen` | 검사한 구간에서 한 행 또는 행 조각이 source 상한을 초과했다. 처리 손실이나 전체 초과 건수를 확정하지 않는다. | 100252, level 3 |
| `collection_raw_line_scan_unavailable` | 변경·timeout·권한·설정 결속·응답 오류 등으로 이번 검사를 확정하지 못했다. | 100253, level 3 |

두 규칙은 기존 health 경로의 `ignore=900`, `no_email_alert`를 사용한다. `check`는 `raw_lines=<JSON>`을 출력하며 logger나 영속 상태를 갱신하지 않는다. `run/force`는 기존 공용 잠금 안에서 고정 코드만 logger로 보내고 `/var/lib/capstone-vector-maintenance/raw-lines.json`을 root 0600으로 원자 저장한다. 결과는 KST 시각·허용된 숫자/상태 필드뿐이며 원문·경로·자유로운 오류 본문을 출력하지 않는다. 현재 Vector 설정과 환경 파일은 검토된 SHA에 고정하고 `/etc/capstone-vector/raw-line-binding.json`에 결속한다. 배포 전과 검사 전후 SHA가 달라지면 정상으로 승인하지 않는다. 파일 경로나 상한을 바꾼 뒤 단순히 현재 SHA로 다시 승인하지 않도록 배포 핀의 재검토가 필요하다.

통합 시험 12개는 정상 세 원천, 1MiB+1 EOF, binding 누락·변조·복수 JSON, config/env drift, helper 실패, 빈/복수/과대 응답, 원문 표식이 섞인 metadata를 다뤘다. 원문 표식은 check 출력에 없었다. 각 사례에서 실제 설정 경로와 원천 파일에는 private mount namespace의 합성/후보 파일만 읽기 전용으로 연결했다. 이 사전 시험 당시에는 A 설치 대기·B 확장 검증 진행 중이었으며, 이후 적용 결과는 위 최신 기록을 따른다. 격리 시험 자체는 기존 Vector·Wazuh·원천 회전·checkpoint를 바꾸지 않았다.

이 검사는 **주기적 관측**이다. 두 검사 사이 사라진 초과 행, 마지막 32MiB 밖의 행, copytruncate 유실은 놓칠 수 있다. `within_scanned_range`는 해당 안정된 구간에서만 초과가 관측되지 않았다는 뜻이다. 자동 격리·복구·원문 재주입·전체 무손실·원격 ACK를 제공하지 않으며 Vector 자체의 EOF counter 문제도 수정하지 않는다. 아래 기록은 이전 단계 당시의 결과다.

**04:49 KST 후속 적용 완료:** 아래의 초기 미연결 표시는 분리 조사 시점이다. 통합 후보 native97개·jq16개를 통과한 뒤 A에 숫자 telemetry와 원문 포함 file-source 진단 target 제한을 적용했다. Vector 첫changed4·storage changed2, 양쪽 반복changed0·PID/InvocationID불변을 확인했다. 현재 Invocation heartbeat·KST·허용필드·root0600·maintenance `collection=[]`를 확인했고 기존 agent/보안 컨테이너/승인 경계를 보존했다. [실측 JSON](validation-2026-10-14.json).

운영 경로는 `/var/log/capstone-vector/telemetry/health.jsonl`이며 기존48회/maxage14/64MiB 회전에 포함한다. 60초 숫자 표본과180초 freshness, PID+systemd InvocationID로 현재 실행을 구분한다. 누적 counter>0은 해당 실행의 관측 신호이며 사건별 손실 수신증이 아니다. `reached_eof=true/false` series를 분리 보존한다. 5분 maintenance가 제한된 status만 journald에 쓰고 Wazuh100246~100251(level3/ignore900초)이 기록한다. 원문 telemetry 자체를 Wazuh 입력으로 추가하지 않는다.

`VECTOR_LOG=info,vector::internal_events::file::source=off`는 과대행 원문이 포함되던 정확 target의 진단을 제한한다. 같은 target의 다른 파일 진단도 보이지 않으므로 숫자 감시를 함께 사용한다. EOF의 과대행 counter 누락은 계속 남는다. 내부 metric0·`collection=[]`를 전체 무손실 증거로 해석하지 않는다. **전체 고유 상관·이전boot 자동회수·raw copytruncate 전환·장기 부하/전원 장애는 미완료**다.


2026-10-14 A의 Vector 0.59.0으로 읽기 전용 조사와 분리 시험을 수행했다. **숫자 telemetry·file source 로깅 정책·기존 maintenance 연결 후보까지 작성했으며 아직 운영 적용하지 않았다.** 원시 파일, 기존 Vector data/checkpoint, 보안 엔진, Wazuh 입력, 운영 logrotate를 변경하지 않았다. 새 패키지·상시 Python 코드도 추가하지 않았다.

## 우선 처리할 범위

| 순서 | 기존 도구로 가능한 작업 | 조건과 남는 한계 |
|---|---|---|
| 1 | Vector 숫자 내부 메트릭의 별도 기록·상태 감시 | source 오류·일부 누락·buffer 증가를 관측한다. 아래 EOF 과대 행 누락까지 탐지하지는 못한다. root 전용 보존·stale·InvocationID별 기준을 후보에 연결했다. 운영 적용/실측은 대기 중이다. |
| 2 | 이전 부팅 journal의 지정 boot별 종료형 추출 | journalctl로 제한된 표본을 읽고 별도 검증할 수 있다. 현재 source의 checkpoint를 건드리거나 운영 ready에 자동 주입하지 않는다. |
| 3 | 낮은 부하에서 source 회전·재시작 경계 시험 | 이미 확인한 WAF pair SIGKILL 및 출력 rename 회전을 반복하지 않는다. raw 회전 방식 변경은 writer·Wazuh reader 전환 계획을 먼저 완성한다. |
| 4 | 소량 정상 쌍부터 단계적으로 WAF 처리량 측정 | 합성 파일만 사용하고 운영 WAF 요청/경보는 만들지 않는다. 파일 총32MiB·한 Vector·2분·nice/timeout 범위 안에서 실시한다. 현재 결과는 처리량 보장이 아니다. |

## 실제 과대 행 동작

`probe-file-boundaries.sh`는 root 임시 디렉터리에 합성 파일 약4.19MiB를 만들고 한 Vector만 실행한다. 실행 한도80초, 종료·오류 시 임시 입력/data/출력을 정리한다. 운영 파일을 읽거나 쓰지 않는다.

| 입력 | 실제 결과 |
|---|---|
| 1,048,575byte + newline | 완전한 한 행으로 출력 |
| 1,048,576byte + newline | 완전한 한 행으로 출력 |
| 1,048,577byte + newline, 다음 정상 행이 이미 존재 | 초과 행 제외, 뒤 정상 행 정상 출력, reading_line_from_file error counter 1 |
| EOF에 1,048,577byte 행을 별도 추가 | 초과 행 제외, error counter 증가 없음 |
| 그 뒤 정상 행 추가 | 정상 행 출력, 누락된 error counter는 여전히 증가하지 않음 |

두 번 같은 결과를 확인했다. 최종 시험 peak RSS는45,832KiB였다. 파일 source 구현이 `raw_line: Some`을 반환한 경우에만 해당 읽기에서의 discarded 목록을 emit하기 때문에 EOF에 끝난 과대 행은 숫자 오류 관측에서도 누락된다. 따라서 **error counter가 0이라는 이유로 과대 행 손실이 없다고 판정하면 안 된다.** 운영 상한1MiB를 무한히 키워 해결하지 않는다. 유효 WAF는 별도로 VRL의128KiB 상한을 적용하며, source 상한을 넘은 행은 remap quarantine에 도달하지 않는다.

추가로 실제 오류 stdout에서 `truncated_bytes` 필드를 확인했다. source ERROR에는 원문 앞부분이 포함될 수 있으므로 `internal_logs`나 서비스 stdout 전체를 새로운 Wazuh 입력으로 등록하지 않는다. 현재 서비스 stdout은 journald로 연결되어 있다. 분리 시험에서 아래 정확한 EnvFilter로 해당 source의 문자 로그를 직렬화 전에 차단하고 error counter 1은 유지함을 확인했다. EOF 오류 누락은 이 로깅 변경과 별개다.

원본 파일 자체는 수정되지 않는다. 다만 이후 기존 보존 정책으로 원본이 없어지면 수동 복구도 불가능하다. 완전한 초과 행 보존·중단형 checkpoint 처리는 Vector 설정 하나로 보장할 수 없다. producer 크기 상한이 입증되거나 별도 보존 검사·upstream 수정이 마련되기 전에는 이 범위를 완료로 표시하지 않는다.

## 통합된 숫자 telemetry 후보

`vector.toml`의 internal_metrics → 허용 metric/component 선택 → metric_to_log → 허용 숫자·label만 새 객체 생성 → 전용 file sink 순서다. hostname, file path, 원문, 자유로운 reason 문자열은 출력에서 제외한다. source의 oversize drop은 `intentional=true`이므로 intentional=false만 감시하지 않는다. `reached_eof=true/false` series를 분리해 unread 값이 0인 다른 series에 덮이지 않게 한다.

- 60초 간격, source4개·기존 sink2개 및 global uptime만 선택한다. source 자체 ACK를 보장하지 않는 내부 관측값이다.
- 실행 epoch는 systemd `INVOCATION_ID`32hex, native PID, metric timestamp를 함께 기록한다. KST 문자열과 Unix 초를 같이 보관한다.
- 출력은 `/var/log/capstone-vector/telemetry/health.jsonl` 고정 경로다. root0700 디렉터리·서비스 umask077로 새 파일0600, 기존 파일의 root 소유·단일 link·0600을 Ansible에서 확인한다.
- memory buffer128건/drop_newest를 사용한다. 새256MiB disk buffer를 만들거나 보안 입력을 telemetry 때문에 붙잡지 않는다. telemetry 자체는 best effort다.
- 기존 출력 회전에 세 번째 파일로 포함한다. 같은 Vector pause/Wazuh ready reader drain/rename/restart 절차, daily 또는64MiB 조건,48개·14일 정책을 사용한다. 5분 maintenance 주기의 사후 판단이므로64MiB는 엄격한 순간 최대치가 아니다. raw copytruncate는 바꾸지 않는다.

서비스 후보에 `VECTOR_LOG=info,vector::internal_events::file::source=off`를 넣는다. Vector0.59에서 실제 과대 행 오류의 정확한 tracing target을 확인했다. 이 target의 문자 진단 전체가 사라지므로 숫자 오류·누락 신호·heartbeat를 함께 관측한다. systemd의 MESSAGE 필터만 쓰면 journald의48KiB 줄 분할 뒤 원문 후속 조각이 남을 수 있어 사용하지 않는다.

분리 비교 시험에서 raw `truncated_bytes` 로그는 없어졌고 error counter는1로 유지됐다. 합성 marker는 stdout/stderr에서0건이었다. 실제 internal metric 형태 시험에서도8개 metadata,2개 heartbeat, source error max1, buffer gauge2개, Invocation·숫자epoch·KST 결속을 확인했다. 실제 source 원문을 실험 입력으로 사용하지 않았다.

### 기존 maintenance에 연결한 판정

`collection-health.jq`는 최대 마지막1MiB만 읽고 양 끝의 잘렸을 수 있는 행은 버린다. 짧은 파일에서도 첫 행 하나를 버리므로180초 시작 유예와 주기적 heartbeat를 사용한다. 완전한 중간 행의 JSON/스키마/허용 label 오류는 invalid다. 현재 MainPID·InvocationID·시작시각에 맞는 표본만 판단하고 미래5초 초과 표본은 invalid다. heartbeat180초 초과는 stale이다. 조회 중 서비스 재시작 등으로 epoch가 바뀌면 다음 maintenance에서 다시 판단한다.

| 상태 코드 | 의미 |
|---|---|
| `collection_telemetry_missing` | 시작180초 뒤에도 현재 실행 heartbeat 없음 |
| `collection_telemetry_stale` | 현재 실행 heartbeat가180초보다 오래됨 |
| `collection_telemetry_invalid` | 완전행 형식/메타데이터 또는 실행정보를 확인할 수 없음 |
| `collection_error_seen` | 현재 실행의 가장 최근 error counter 중 하나가0보다 큼 |
| `collection_loss_signal_seen` | drop 또는 unread/unknown unwatch counter가0보다 큼. 정확한 실제 손실 건수 확정이 아님 |
| `collection_buffer_pressure` | normalized/quarantine disk buffer의 최근 size가268435488byte의75% 이상 |

counter delta를 영속 저장하지 않는다. 한번 오류가 난 실행은 누적치가 남아 같은 상태가 반복될 수 있다. 기존5분 maintenance가 고정 코드만 logger로 보내며 Wazuh 측 level3/ignore900/noemail로 빈도를 줄인다. `check`는 출력만 하며 logger를 호출하지 않는다. 기존 서비스 비활성·디스크 임계치 level5 경보는 유지한다. EOF에서 사라진 과대 행·silent copytruncate gap은 이 상태값으로 판별할 수 없다. 정상 heartbeat도 무손실 증명이 아니다.

### 검증과 적용 경계

후보 native 검사는 main19+correlation9+collection8와 별도 WAF61이다. jq 회귀는 heartbeat·epoch/PID·미래/잘못된 JSON·오류/손실/buffer·양끝조각·EOF series 양순서/잘못된 EOF label의16개다. systemd unit, logrotate debug, bash 및 두 Ansible playbook 문법도 검사한다. 검증수치와 운영 적용 여부는 `validation-2026-10-14.json`에 구분해 남긴다.

고정 운영자 wrapper `infra/automation/ansible/run-vector-local-a.sh`는 `vector-shadow-a.yml vector-storage-a.yml`을 같은 Vector lock 아래 순서대로 실행한다. 후보 Vector unit/config가 바뀌어 한번 재시작하며 그 후 maintenance·logrotate를 설치한다. 새 template·Ansible role/검사파일은 `infra/automation/ansible/`, 설정·VRL·tests·jq·maintenance는 `infra/normalization/vector/` 상대 구조를 유지해야 한다. 변경 없는 두 번째 apply는 서비스 재시작 없이 changed0이어야 한다. 배포는 부모 검토 뒤에 진행한다.

## 이전 부팅 journal

A의 systemd255에서는 Vector0.59가 `current_boot_only=false`를 명시적으로 거절한다. `extra_args`나 버전 응답 wrapper로 이를 우회하지 않는다. package/systemd 업그레이드 없이 가능한 방법은 종료형 journalctl로 특정 boot의 보관 데이터를 읽는 것이다.

`probe-journal-history.sh`는 list-boots에서 이전 boot ID를 고정하고 `_TRANSPORT=kernel` 최근1,000건만 조회한다. 명령별15초·출력32MiB 상한이 있으며, 원문은 A root 임시 파일에만 두었다가 삭제한다. 라이브 보관 boot10개, 이전 boot 표본1,000건/421,375byte, cursor·epoch·transport 및 선택 boot 결속1,000건 일치를 확인했다. 이 제한된 표본의 nft prefix는0건이었다. 이전 boot 전체에 nft가 없다는 뜻은 아니다. 운영 재주입은 수행하지 않았다.

실제 회수 경로를 추가하려면 먼저 다음 조건이 필요하다.

1. 재부팅 전 마지막 ACK cursor와 보관 journal의 연결 증거. 현재 source가 새 boot cursor로 진행한 후에는 옛 미수집 경계를 추정할 수 없다.
2. 고정 boot/cursor/시각 범위·원본 선택 필드·SHA·총건수와 완료/중단 상태를 가진 별도 불변 export.
3. kernel transport와 cursor는 보존하면서 replay 입력임을 명시. 최근 reboot여도 신규 `fresh` 상관에 자동 합류시키지 않음.
4. 동일 cursor 재주입의 중복 범위와 수신 판정. event ID가 같다는 것만으로 Wazuh 영속 중복 제거가 되지 않음.
5. 운영 ready와 분리된 표본 정제 검증 후 필요한 범위만 명시적 회수. 현재1,000건 조사를 전체 backlog 회수로 표시하지 않음.

## raw copytruncate 전환 설계

현재 device/inode fingerprint와 활성 경로만 수집한다. 원본이 잘린 뒤 기존 read offset보다 빨리 다시 커지면 크기 감소를 관측하지 못하고 앞부분이 빠질 수 있다. copy와truncate 사이 writer가 기록한 부분은 복사본에도 없을 수 있다. 패키지의 일반적인 copytruncate 지원을 이 간격의 무손실 보장으로 해석하지 않는다.

공식 권고인 첫 회전 파일 include·delaycompress도 현재 설정에 곧바로 추가하지 않는다. device/inode 방식에서 복사본은 다른 파일로 보이므로 이미 읽은 이벤트 재수집이 생길 수 있다. checksum fingerprint로 바꾸면 기존 checkpoint 의미가 달라지고 동일 prefix·충돌·첫 행이 같은 세대의 구별 문제가 생긴다. WAF의 정확한 source path 결속도 archive 경로를 자동으로 받아들이지 않는다.

rename/reopen으로 바꾸려면 Suricata lazy reopen 확인, ModSecurity 이전 writer FD 종료와 신규 FD 확인, Wazuh old reader가 논리 EOF에 도달한 증거, Vector의 이전 세대 읽기 완료를 함께 처리해야 한다. 이전 구현 조사와 출력 회전 성공 증거를 재사용한다. 보안 캡처를 멈추거나 기존 raw reader를 급히 전환하는 변경은 이번 시험에서 하지 않았다.

다음의 작은 분리 시험은 가능하다. 합성 번호 행100개를 읽은 test Vector만 잠시 멈춘 뒤 copy/truncate/더큰재작성, 재개 후 보존 archive와 읽힌 번호를 비교한다. 별도 fresh data_dir에서 checksum+archive 후보를 대조하되 중복까지 함께 계산한다. 이 시험이 성공해도 운영 writer·Wazuh old FD 문제는 별도로 남는다. 본 기록 시점에는 이 raw 회전 시험·운영 변경을 실행하지 않았다.

## 공식 근거

- [Vector file source](https://vector.dev/docs/reference/configuration/sources/file/): max_line_bytes, fingerprint, checkpoint와 회전 권고.
- [Vector0.59 file server](https://github.com/vectordotdev/vector/blob/v0.59.0/lib/file-source/src/file_server.rs#L274-L285): 정상 raw_line 분기 안의 oversize telemetry emit.
- [Vector0.59 file 오류](https://github.com/vectordotdev/vector/blob/v0.59.0/src/internal_events/file.rs#L527-L554): truncated_bytes·오류 counter·intentional drop.
- [systemd255 journald](https://github.com/systemd/systemd/blob/v255/man/journald.conf.xml): stdout LineMax 분할과 MESSAGE 필터 단독 사용의 한계.
- [Vector0.59 internal_metrics](https://github.com/vectordotdev/vector/blob/v0.59.0/src/sources/internal_metrics.rs): 숫자 metric 및 선택 PID tag.
- [Vector0.59 journald](https://github.com/vectordotdev/vector/blob/v0.59.0/src/sources/journald.rs#L346-L350), [systemd255 journalctl](https://github.com/systemd/systemd/blob/v255/man/journalctl.xml): all-boots follow 제한과 지정 boot 조회.

**21:27 KST 후속 확인:** 배포 후 타이머가 21:24:31에 자연 실행돼 21:24:32 정상 종료했다. root0600 상태 파일의 binding 일치·3원천 안정·상태 코드 없음이 확인됐다. 수동 실행 검증에 더해 정기 실행도 확인한 것이며 전수 무손실 보장은 아니다. A149/B107개 검증 파일을 영구 증거 경로에 SHA 대조해 보존했고 프로젝트 소스 동기화·작업 파일 정리를 마감 중이다.
