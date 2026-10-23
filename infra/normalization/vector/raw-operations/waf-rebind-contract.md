# 새 WAF CID의 raw 세대·binding 재결속 계약

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

2026-10-15 작성. **설계·소스 대조 문서이며 새 CID 전환 구현·실행 증거가 아니다.** 이 문서 작성 중 코드, 서비스, 컨테이너, checkpoint, 원문은 변경하지 않았다. 현재 운영의 같은 CID 재시작 검증과 앞으로 수행할 새 CID 전환을 구분한다. 실행은 고정 A의 root 운영자용 Ansible/Bash/jq 작업으로 제한하고 LLM/MCP 권한이나 상시 Python 수집기를 추가하지 않는다.

결론은 새 CID마다 새 binding과 새 audit 세대를 사용하고, 구 binding의 봉인 EOF를 구 Vector 환경에서 처리한 다음 새 환경을 공개하는 것이다. 기존 일반 회전 CAS는 `source_pins` 변경을 거절하므로 그대로 호출하여 재결속할 수 없다. WAF env SHA는 Suricata state에도 들어 있으므로 **WAF state 하나만 바꾸는 전환은 불완전하다.** 여러 파일의 원자 교체를 하나의 원자 transaction이라고 부르지 않는다. 시작 차단 아래 각 파일의 정확 CAS와 영속 intent로 부분 적용을 구별해야 한다.

## 1. 기준 증거와 현재 제한

읽은 자료는 부모가 조회한 `readiness-v6-output.json`이다. 관측 시각은 **2026-10-15 03:20:05.281415 KST**, 파일 SHA-256은 `c225a902ffb30d0bb73384bc0f5a0ef4f5d9865ff0554da9ded198c97f47caec`이다. 작업 당시 위치는 `/private/tmp/capstone-waf-persistence-20261015.s8rt0u01/readiness-v6-output.json`이며 영구 증거 위치는 부모의 보관 기록을 따른다. `issues=[]`와 전후 metadata 안정은 읽기 조사 결과다. 자료 자체의 `readiness_authorized=false`를 운영 실행 승인으로 바꾸어 해석하지 않는다.

| 대상 | 이 관측의 사실 |
|---|---|
| A machine ID | `096e90b6243e438aa8a7b392be754732` |
| boot ID | `bfafc2dda0fe42ada088e7fe6c576486` |
| WAF CID | `02fb9ec3db38b01ccc49b61c7ca57d41e745d691cf0acd97a8b9978b16e1f41e` |
| WAF image | `sha256:411cc97544ec0af886d3bc2a230564c2d28f08a800152617507476cda6ae9650` |
| WAF 실행 | healthy/running, PID `2377669`, start ticks `142492178`, UID/GID `101:101`, restart `unless-stopped`, stop signal `SIGQUIT` |
| WAF raw | active, revision `11`, generation `3`, device/inode `64512:1441998`, 1,193 B, `101:101/0644`, alias 포함 링크 2 |
| WAF state SHA | `94979ce10fea83d6a6bd758c79425e8d2b4caae5cc844be3ca55e0aa2a40dee0` |
| Suricata raw | active, revision `5`, generation `1`, device/inode `64512:1441999`, 2,220,514 B, `998:998/0644`, 링크 3 |
| Suricata state SHA | `40ceeb4a479b3dccbf7b546b4bbf8d85271fd0fbee7f4167b1df7b809162b204` |
| reader | Vector PID `2406117`, invocation `12314ddc66e14e0083b08db2e51fc831`; Wazuh active, 실제 logcollector PID `1909632`, ticks `141224139` |
| 자동 작업 | raw 두 timer와 output maintenance timer 모두 enabled/active/waiting |
| 잔여 intent | 두 writer-reopen intent, Vector stop intent, output `resume.pending` 없음 |

현재 WAF의 실제 bind는 로그 디렉터리 RW와 GROOT 룰 RO 두 개다. compose의 Imperva RO bind 문구는 존재하지만 현재 컨테이너의 실제 mount에는 없다. 따라서 compose 원문만으로 새 CID의 설정 영속성을 확인할 수 없다. 현재 image/Cmd/Env/포트/network/정책을 복제하는 별도 배포 계약과 새 CID의 실제 Mounts를 대조해야 한다. Env 값과 raw는 서버 root private 증거에만 남긴다.

현재 네트워크의 WAF 주소는 `172.18.0.2`, `secstack_waf-net`의 유일한 해당 주소 소유자다. Imperva 좁은 예외는 그 주소에 결속돼 있다. 새 CID가 다른 주소를 받았을 때 예외 범위를 넓히거나 이전 준비 결과를 재사용하지 않는다. 주소 보존·이름 교체·포트 인계는 새 컨테이너 배포자의 별도 명시 검사다.

모든 위 수치·SHA는 후속 전환의 고정 입력 후보일 뿐이다. timer가 활성인 현재 상태에서 얻은 오래된 revision을 그대로 적용하지 않고 작업 lock 취득 뒤 최신 상태와 다시 대조한다.

## 2. 실제 재사용 소스와 API

현재 설치 `/usr/local/lib/capstone-raw-operations/coordinator.sh`의 소스는 [coordinator-writer-intent-fix.sh](coordinator-writer-intent-fix.sh)이다. 같은 디렉터리의 역사적 `coordinator.sh`와 혼동하지 않는다.

| repo 소스 | 대조한 SHA-256 |
|---|---|
| `coordinator-writer-intent-fix.sh` | `4b741931945035d1a99d953998cf2543c35d406a647ccaffcb6deb8158ee39c0` |
| `state-lib.sh` | `d754d17726310a56c77e5d37c41f0ae3883881dfbc91bfa20b7ef916fe428f3a` |
| `state.jq` | `3db6baef5c679521bdc257cbe1aca66fd6884714f734a1778ca27b249e40a775` |
| `checkpoint-gates.sh` | `92acb7ce322d109bc7e70c32bb42a17cf5cddd1b7f5b6d7f23871e89cbaa4af6` |
| `checkpoint-gates.jq` | `ebc3022b44dae2a79845e35b5b26439d369162715644a720ce35257a1e22d8e6` |
| `writer-gates.sh` | `c8a4f766c8cff125115f4d6413b746309004d608fdc1db370ec4dfe456cb1667` |
| `guard.sh` | `7f78865f4be32dbd647b46f15c4d5118471ef5eca607e6f966aa4579b9b3037e` |
| `migration-start-guard.sh` | `b848a6e20b368e2568bf05c1ac91dc4c9c4c043771fb83a916e38d2b540d2bf4` |

| 함수·명령 | 정확한 계약과 재사용 범위 |
|---|---|
| `raw_state_read_twice ROOT ENGINE` | root `0700` 트리, state root `0600`/nlink1, canonical JSON+LF, metadata·내용·SHA 재대조. `{state,sha256,file_identity,start_authorized:false}` 반환. |
| `jq -e -f state.jq STATE` | 구조 검사. 실제 writer/reader, 현재 CID, SHA 값의 진실성이나 시작 권한을 증명하지 않는다. |
| `raw_state_init ROOT ENGINE CANDIDATE` | state 미존재, revision0/active/generation0 전용. 기존 state 재결속에 사용 금지. |
| `raw_state_cas ROOT ENGINE OLD_SHA CANDIDATE` | 공용 lock 아래 revision+1/인접 phase/동일 source_pins. 이전 state root0400 보관·재fsync 후 다음 state rename·dir sync. **새 CID/env pin 변경과 active→active 갱신은 거절한다.** |
| `writer_identity waf` | literal 이름 `waf`의 현재 running PID/namespace/ticks 관측. `identity` 객체를 추출하여 다음 gate에 전달한다. 다른 이름의 새 후보나 stopped old CID에는 이 API를 그대로 쓸 수 없다. |
| `writer_gate waf IDENTITY_JSON DEV INO` | 정확 현재 컨테이너의 전체 process membership/FD 전후 검사. rc0+`closed`는 writable FD0, rc10+`open`은 FD>0, rc75는 판정 불가. 미래 reopen/호스트의 다른 writer까지 배제하지 않는다. |
| `cg_vector_eof CP_DIR SOURCE DEV INO BYTES` | native v1 dev_inode의 정확 1개 항목과 offset==봉인 bytes. `checkpoints.new.json`이 있으면 우선 검사하며 손상 시 stable 파일로 대체하지 않는다. |
| `cg_vector_current CP_DIR SOURCE DEV INO` | 정확 current 항목, offset≤size. 정확 0개 항목만 `vector_checkpoint_match_missing`; 중복·손상과 구분한다. |
| `cg_wazuh_eof CP LOGICAL SOURCE DEV INO BYTES` | logical path 정확 1개, offset==bytes, 실제 저장 offset 전량의 SHA1 대조. `min(offset,4096)` 검사가 아니다. |
| `cg_wazuh_cold CP LOGICAL NEW_SOURCE OLD_DEV OLD_INO` | 기존 path CP를 새 파일에 적용했을 때의 cold 시작 판정. 동일 inode면 유효 prefix 이어읽기, 다른 inode의 같은 prefix면 거절. old offset보다 짧은 파일도 읽은 전체 prefix와 별도 common-byte 검사가 필요하다. |
| `cg_sealed_lines SOURCE DEV INO BYTES 1048576` | 봉인 전량 최대 512 MiB, GNU dd/tr/wc로 byte 길이·최종 LF 검사. empty는 허용, 1 MiB 초과 행·잘린 마지막 행은 거절. |
| `ro_prefix_distinct [OLD_BYTES]` | coordinator 내부 환경을 명시 설정한 뒤 old/new의 실제 공통 길이만 `cmp`한다. old empty는 허용, new empty 또는 동일 공통 prefix는 보류. |
| `ro_validate`, `ro_guard_one`, `ro_guard_all` | 모든 source pin/alias/권한/현재 writer/CP와 intent를 재검증한다. old CID가 사라진 상태를 자동으로 새 CID에 결속하지 않는다. |
| `ro_stop_vector`, `ro_owned_pause`, `ro_start_vector` | boot·실제 invocation/start_usec·state/current/pending/pins에 결속된 중지 intent를 사용한다. 임의 inactive를 자신이 중지한 것으로 채택하지 않는다. |
| `ro_publish` | publish_pending에서 prefix 재확인→alias hardlink 원자 교체→guard와 Vector 시작→새 native CP 및 실제 Wazuh FD→active CAS. 새 CID용 bootstrap이 검증된 뒤 재사용 가능. |

checkpoint gate는 공개 호출 하나마다 30초(+강제 종료 유예 2초), writer gate는 14초(+1초), reader guard는 110초(+2초) 상한이다. 여러 호출의 합산 시간이 그 단일 상한을 갖는 것은 아니다. checkpoint/source 전후 변경은 성공으로 숨기지 않고 보류한다. raw source의 정확 링크 수·UID/권한은 coordinator가 추가 대조한다.

다음은 **읽기 전용 검사 예시**다. root/source SHA/권한 검증을 먼저 수행하고 Linux A에서만 실행한다. 이 문서에서는 실행하지 않았다.

```bash
lib=/usr/local/lib/capstone-raw-operations
state=/var/lib/capstone-raw-operations
source "$lib/state-lib.sh"
raw_state_read_twice "$state" suricata
raw_state_read_twice "$state" modsecurity
/usr/local/sbin/capstone-raw-operations check modsecurity
/bin/bash "$lib/guard.sh" vector
/bin/bash "$lib/guard.sh" wazuh
```

`run`, `resume`, `force`는 읽기 명령이 아니다. 특히 `force`로 새 CID rebind를 시도하지 않는다. 전환 controller가 공용 lock을 이미 보유한 동안 lock을 다시 잡는 공개 `resume` 명령을 중첩 호출하지 않는다.

## 3. 변경해야 하는 고정 객체

| 경로 | 새 CID 전환의 허용 변경 |
|---|---|
| `/etc/capstone-vector/vector.env` | 정확 1개씩 존재하는 `WAF_INSTANCE_ID`, `WAF_CONFIG_SHA256`, `WAF_DEPLOYMENT_BINDING`의 값만 변경. CR/NUL/중복/비정상 framing 거절, 나머지 바이트 보존. shell `source`/`eval`로 env 원문을 실행하지 않는다. |
| `/etc/capstone-vector/waf-binding.json` | schema `waf-producer-deployment-2`/version2 유지, `instance_id`, `configuration_sha256`, `deployment_binding`만 새 고정 값으로. machine/name/audit/access/time 정책과 나머지 정확 키를 보존한다. |
| `/etc/capstone-vector/raw-line-binding.json` | `schema_version:1`, `policy:periodic-snapshot-tail-v1`과 Vector config SHA 유지, `vector_env_sha256`만 새 env SHA로. |
| `/var/lib/capstone-raw-operations/suricata/state.json` | current·CID·engine pins·active phase·proof 유지. **env SHA만 변경**, revision+1. |
| `/var/lib/capstone-raw-operations/modsecurity/state.json` | old current를 보존하고 fresh generation을 pending으로 추가한 publish_pending bootstrap. CID/producer/env pin만 승인된 값으로 바꾸고 실제 old_closed/readers_drained/publish_guard proof를 결속한다. |
| 컨테이너 `/etc/nginx/conf.d/zz-capstone-evidence.conf` | 새 binding을 두 위치(access JSON와 `modsecurity_transaction_id`)에만 정확 교체. `$request_id/$msec/$time_iso8601`는 literal로 보존. **최종 생성 바이트**의 SHA가 WAF_CONFIG_SHA256이다. |
| override template/intermediate/target | 기존 include 계약 및 SHA `814a4af8…`를 새 컨테이너 첫 시작 전에 모두 재현하고 native 검증. target만 바꾸면 cold start에 구 template가 덮을 수 있다. |
| 로그 `/home/groot_a/capstone/secstack/logs/modsec/capstone-managed/audit-path.conf` | `SecAuditLog /var/log/modsecurity/capstone-managed/generation-NNNNNNNNNN.jsonl` 한 줄+LF, root0444/nlink1. 새 세대 pointer SHA를 pending.writer_config_sha256에 사용. |

`vector.toml` SHA `6602dcefef13b0b9f31310b8f3afe77b66b20795517135911ee38056968e93d8`, VRL, Wazuh 설정, 기존 checkpoint, Suricata writer 설정은 변경 대상이 아니다. 새 producer에 binding 문자열이 들어가므로 그 SHA는 기존 `1e4c37a9…`와 달라진다. 기존 binding `3ae6308b…`를 새 CID에 재사용하지 않는다. 새 binding은 CSPRNG로 한 번 생성·고정 저장한 64hex로 하고 재시도 시 다시 만들지 않는다.

현재 baseline이면 old generation3 다음은 generation4다. 최신 current가 바뀌었으면 `current.number+1`을 다시 계획하고 기존 intent의 generation을 임의로 바꾸지 않는다. 기존 inode에 새 binding 행을 append하지 않는다. v2 VRL은 env binding과 audit unique_id binding이 다르면 `waf_audit_producer_binding`으로 거절한다. event ID는 sensor/source/**instance/binding**/request_id에 결속되므로 구 원문을 새 env로 재해석하는 것은 동일 사건 처리로 간주할 수 없다. 근거는 [audit-context.vrl](../waf-producer-v2/audit-context.vrl)과 [v2 producer](zz-capstone-evidence-v2.conf)다.

## 4. 운영자 전용 최소 진행 순서

아래는 구현 시 지켜야 할 순서다. 현재 저장소에 이 전체 rebind를 실행하는 승인된 공개 명령은 없다. 기존 초기 v1→v2 `deploy/cutover`는 날짜·원본 SHA·CID·초기 state 부재를 전제로 하므로 재실행하지 않는다.

1. **새 계획 고정.** boot, old CID/image/PID/ticks/StartedAt/name, 실제 mounts/network/주소, raw 두 state·writer/reader·config/env/binding·runtime SHA를 fresh 조회한다. root private 새 attempt 디렉터리를 create-exclusive로 만들고 old 파일 바이트/metadata와 새 후보 바이트를 각각 보관·fsync한다. Docker Env는 불필요한 다른 컨테이너분을 수집하지 않고 출력하지 않는다. native config와 실제 설치 source 계약을 확인한 stopped/never-started 새 후보를 준비하되 첫 start 전에 아래 보호가 완성되어야 한다.
2. **경합과 재부팅 시작 차단.** 세 timer의 기존 enabled/active 상태·unit SHA를 기록하고 잠시 disable/stop한다. maintenance service 및 두 raw service가 실행 중이지 않고 pending/모든 intent가 없음을 확인한다. `/var/lib/capstone-automation/ansible/vector.lock`을 root0600/nlink1·안전한 조상 확인 후 `flock -n`으로 취득한다. 기존 released migration marker와 `90-capstone-raw-start.conf`는 변경하지 않는다. 양 unit의 `/etc/systemd/system/{capstone-vector,wazuh-agent}.service.d/99-capstone-waf-rebind-block.conf`에 정확 `[Service]\nExecStartPre=/usr/bin/false\n` 바이트를 root0644로 create-exclusive 게시·fsync한 뒤 daemon-reload한다. 실제 ExecStartPre에 기존 runtime guard와 `/usr/bin/false`가 정확 1개 추가됐고 NeedDaemonReload=no인지 대조한다. **기존 marker만 blocked로 바꾸는 방법은 사용하지 않는다.** 별도 전환 ledger가 차단 단계와 소유권을 기록하며 drop-in은 이미 실행 중인 프로세스를 stop하지 않는다.
3. **old writer를 명시적으로 종료.** 정확 CID·PID/ticks·name·부트의 durable stop intent를 먼저 fsync하고 기존 컨테이너를 보존한 채 한 번만 정상 종료한다. timeout/결과 불명은 자동 신호 재전송 없이 inspect한다. 새 컨테이너 첫 start 전에 old Running=false/Pid0/Restarting=false와 old process/namespace 종료를 확인한다. old와 new를 같은 writer 경로에 동시에 실행하지 않는다. 이 stopped-old 검증은 현재 `writer_gate`가 지원하지 않으므로 controller의 별도 정확 대상 검사로 구현·검증해야 한다.
4. **구 binding의 최종 EOF 처리.** old generation의 최종 size/devino/SHA·마지막 LF와 실제 old writer 종료를 고정한다. old root0400 봉인, managed root0711 보존, 링크 수는 generation+현재 audit alias=2로 확인한다. 구 Vector env와 구 alias를 유지한 채 Wazuh/Vector native EOF까지 기다린다. Suricata는 계속 원문을 보존하며 이 구간에도 source 설정을 바꾸지 않는다. Vector를 멈추기 전 실제 invocation/start_usec/boot·old/new state 증거에 결속한 별도 operator stop intent를 fsync한다. clean inactive 확인 후 마지막 Vector EOF를 다시 검사한다. WAF v2는 access join/2초 TTL이 없으므로 access EOF를 audit timestamp 근거로 대체하거나 불필요한 v1 join 대기를 끌어오지 않는다.
5. **새 세대와 새 writer.** 새 generation 파일을 create-exclusive, UID101/GID101/0644로 만들고 root0711 managed 안에 보존한다. pointer를 새 세대로 정확 CAS하고, never-started 후보의 template→intermediate→target/producer/두 rule bind·UID·이미지·network 계약을 재검사한다. exact name을 `waf`로 인계한 뒤 durable first-start intent 아래 한 번 시작한다. 새 writer identity와 old inode FD0/new inode FD>0을 검사한다. 실제 요청이 없으면 새 파일은 0B일 수 있으므로 old가 nonempty일 때 공통 prefix 구분이 될 때까지 보류한다. 필요하면 별도 승인된 localhost 정상 수집 검증 1회로 행을 만들며 공격/채팅/모델 호출로 대신하지 않는다.
6. **새 rebind 후보 고정.** old 원문·EOF·새 writer·새 prefix를 대조한 뒤 WAF `publish_pending`/current old/pending new의 완전한 후보와 Suricata active env-pin-only 후보, env 및 두 binding JSON을 **최초 한 번** 만들어 fsync한다. 재개 때 CP 전체 파일 SHA가 다른 원천의 정상 진행으로 바뀌어도 bootstrap을 다시 생성하지 않는다. 저장한 당시 SHA는 증거로 보존하고 재개 판정은 해당 native path의 offset/prefix/identity 의미를 다시 확인한다.
7. **차단 구간 안의 정확 CAS.** 다음 절의 한정 rebind transaction으로 env/두 binding/두 state를 공개한다. Vector는 계속 자신의 stop intent로 중지되어 있어야 한다. source pin이 섞인 중간 상태에서는 reader start, raw timer, maintenance를 허용하지 않는다. 기존 runtime stop intent를 썼다면 old source_pins가 달라져 그대로 재사용할 수 없으므로 원래 증거를 보존하고 실제 중지 ownership을 새 bootstrap state에 인계한 별도 receipt/marker가 필요하다. 이전 중지 사실 없이 marker만 생성하여 ownership을 꾸미지 않는다.
8. **일반 회전으로 인계.** blocked를 유지한 채 frozen old EOF·실제 Vector 중지·새 prefix를 재검사하고, alias를 old inode에서 new inode로 정확 CAS/fsync한다. 그 다음 최종 source/state와 양 runtime guard를 직접 검증해 별도 전환 ledger에 handoff proof를 영속화한다. **새 env 적용 뒤 alias가 old인 채 release하지 않는다.** 기존 guard의 alias=old 분기는 offset≤size이며 EOF를 요구하지 않으므로, 예상 밖 reader 자동 시작에 의존할 수 없다. 정확한 자신 소유의 두 `99-capstone-waf-rebind-block.conf`만 CAS 확인 후 제거·부모 fsync하고 daemon-reload하여 기존 runtime guard가 그대로 유효한지 확인한다. 기존 migration marker는 변경하지 않는다. 새 bootstrap과 실제 stop 소유권이 결속된 뒤 기존 `resume`은 alias=new 경로의 `ro_publish`에서 시작/CP/FD 검사를 이어갈 수 있다. 새 Vector CP와 Wazuh의 새 prefix CP 및 새 inode FD까지 확인해야 active로 승격한다. Wazuh native CP의 path 행이 일시 누락되면 기다려 재조회하고 직접 CP를 채우거나 missing을 pass로 바꾸지 않는다.
9. **최종 공개.** active state와 최종 이름/CID·이미지/설정·reader/원문 보존을 확인한 뒤 자신 소유의 99 차단 drop-in 제거와 기존 90 runtime guard 불변을 확인한다. 옛 migration/source/CP 증거는 유지한다. 자신이 중지한 timer만 원래 enabled/active 상태로 복원하고 실제 다음 수행 결과를 확인한다. 두 timer를 끈 상태를 완료로 표시하지 않는다.

새 writer 종료/이름/first-start의 전체 Docker 복제·복귀 절차는 별도 fixed-target Ansible에 속한다. 이 raw rebind 문서는 새 컨테이너를 생성하거나 기존 컨테이너를 제거하는 범용 도구를 허가하지 않는다. 새 binding 행이 생긴 뒤 old 환경으로 되돌릴 때에도 새 세대의 처리·보존 계획이 필요하며 checkpoint를 옛 사본으로 되돌리지 않는다.

## 5. checkpoint·publication 명령 연결

아래 변수는 임의 사용자 인수가 아니라 root가 고정한 검증된 plan에서 읽는 값이다. `old_bytes`는 writer 종료 후 고정한 크기다. 각 stdout은 root private JSON으로만 보관하고 원문을 출력하지 않는다. rc0와 JSON `verdict=pass`, 정확 identity를 함께 검사한다.

```bash
source /usr/local/lib/capstone-raw-operations/checkpoint-gates.sh
cp_dir=/var/lib/capstone-vector/waf_audit
wazuh_cp=/var/ossec/queue/logcollector/file_status.json
alias=/home/groot_a/capstone/secstack/logs/modsec/audit.log

cg_sealed_lines "$old_path" "$old_dev" "$old_ino" "$old_bytes" 1048576
cg_wazuh_eof "$wazuh_cp" "$alias" "$old_path" "$old_dev" "$old_ino" "$old_bytes"
cg_vector_eof "$cp_dir" "$old_path" "$old_dev" "$old_ino" "$old_bytes"
cg_wazuh_cold "$wazuh_cp" "$alias" "$new_path" "$old_dev" "$old_ino"

# alias 변경·새 reader 시작 뒤의 확인. EOF가 아닌 유효한 새 offset 증거다.
cg_vector_current "$cp_dir" "$new_path" "$new_dev" "$new_ino"
cg_wazuh_cold "$wazuh_cp" "$alias" "$new_path" "$new_dev" "$new_ino"
```

새 prefix 판정은 위 cold gate만으로 끝내지 않는다. `ro_prefix_distinct`처럼 `min(old_offset,new_size)` 바이트를 실제 비교하고 `cmp` rc1만 구분 성공으로 인정한다. rc0(같음)·rc2(오류)는 보류다. old offset0일 때만 empty 새 세대 시작을 허용할 수 있다. old_offset SHA1은 전체 offset 길이를 사용하므로 단순히 더 짧아 SHA1이 다른 파일을 안전하다고 판정하지 않는다.

새 writer가 literal `waf`로 실행된 뒤에는 다음 API를 그대로 사용할 수 있다. `writer_gate`의 rc10은 오류가 아니라 열린 writer 상태이지만, rc/JSON identity·target·process 합계까지 대조해야 한다. 실행 shell의 errexit로 rc10을 잃지 않도록 명시 캡처한다.

```bash
source /usr/local/lib/capstone-raw-operations/writer-gates.sh
observed=$(writer_identity waf) || exit 75
identity=$(printf '%s\n' "$observed" | jq -ce '.identity') || exit 75
writer_gate waf "$identity" "$old_dev" "$old_ino"   # rc0/closed 요구
rc=0
proof=$(writer_gate waf "$identity" "$new_dev" "$new_ino") || rc=$?
[[ $rc == 10 ]] || exit 75                             # open 증거 별도 JSON 검사
```

현재 `ro_writer_pair`는 old/new 관측 사이 동일한 process membership도 확인한다. 단독 gate 두 번을 호출하는 controller도 그 비교를 생략하지 않는다. 새 CID·최종 image/name/mounts/producer SHA를 사전/사후 다시 확인해야 하며 위 함수만으로 container 설정 전체가 검증되는 것은 아니다.

## 6. source-pins 변경의 단 한 번 CAS와 중단 판정

최소 새 구현은 **고정 A와 승인된 old/new CID 한 쌍을 위한 operator-only rebind 단계**다. 일반 `_rs_transition`을 완화하거나 임의 old/new pin 인수를 공개하지 않는다. Bash/jq/coreutils의 파일 검증·fsync·rename과 Ansible builtin을 사용하면 충분하다. source 전체 SHA 고정, clean env, no symlink/정규 파일/UID·GID·mode·nlink/크기 제한, 공용 lock, canonical JSON+LF 조건은 기존 lib와 같아야 한다.

제안 신규 plan/ledger/원본·후보 보관은 기존 stage3 ledger와 분리한 고정 `/var/backups/capstone-waf-recreation-20261015/rebind/`다. plan은 `plan.json`, 영속 CAS intent는 `intent.json`이며 기존 attempt를 덮지 않는다. **현재 미구현·미생성 경로**다. root0700 부모/root0600 ledger, 완료 receipt·보관 사본 root0400, 파일과 각 부모를 fsync한다. plan에는 양 state old/new SHA, env/두 manifest old/new SHA, old/new CID/image/identity, 부트, raw generation/devino/최종 old bytes·SHA, runtime SHA, native proof SHA, 원래 timer/drop-in/reader ownership을 기록한다.

한정 transition은 다음 둘뿐이다. 숫자는 fresh baseline이 여전히 위 관측과 같을 때만 해당한다.

- Suricata `active/rev5 → active/rev6`: env pin과 revision만 바뀌고 나머지 JSON 값 동일.
- WAF `active/rev11 → publish_pending/rev12`: current gen3 그대로, pending gen4, 승인된 CID/producer/env pin과 실제 세 proof 추가. 일반 회전 API로 가짜 중간 revision을 만들지 않는다. 새 WAF state의 `.proof.old_closed.writer_pid/start_ticks`는 구 writer의 실제 종료 증거를 뜻하고 새 PID로 덮지 않는다. 이후 `publish_pending → active`는 기존 `raw_state_cas`의 인접 transition으로 rev13에 진행 가능하다.

두 state는 각각 **old SHA일 때 정확 한 번** 교체한다. 새 SHA면 이전 게시 결과로 검증·재fsync만 하고 다시 revision을 올리지 않는다. 그 밖의 SHA는 충돌이다. 이전 state를 기존 `history/<revision>-<oldSHA>.json` 규칙으로 보존하고 내용·권한·file/dir sync를 확인한 뒤 임시 next를 fsync→현재 exact SHA/identity 재검사→rename→부모 sync→readback한다. 기존 lib의 history 용량·staging 한도도 유지한다. Ansible `copy` 성공만으로 이 의미상의 CAS·다중 파일 transaction을 대체하지 않는다.

여러 객체의 순서는 ledger에 고정한다(예: env → WAF manifest → raw-line binding → Suri state → WAF state). 각 rename 전 `attempted` intent, 후 readback receipt를 남긴다. rename 후 dir sync 실패면 **결과 불명**이지 무변경이 아니다. 재개는 모든 경로를 먼저 조사해 각각 old/new 둘 중 하나인지, 적용된 집합이 계획 순서의 정확 prefix인지 검증한 뒤 남은 파일만 게시한다. 이미 존재하는 후보·history·receipt를 조용히 덮어쓰지 않는다.

| 중단 지점 | 허용되는 다음 처리 |
|---|---|
| arm 전 | 원래 상태 재확인. 기존 결과가 있으면 새 attempt로 덮지 않고 먼저 판정. |
| timer/drop-in/barrier 일부 반영 | 실제 unit/99 차단 drop-in SHA와 원래 enabled 상태를 대조해 차단을 완성. writer 신호 전송 금지. |
| stop/start 신호 intent 존재, 결과 불명 | 정확 CID/PID/start·Docker state/event를 읽어 진단. 신호 자동 재전송 금지. |
| old stopped, 구 EOF 미완료 | 구 env/alias와 원문 유지. 부족한 native offset은 기다림 또는 명시 수동 복구. new env 공개 금지. |
| 새 writer 실행, 새 파일 empty/동일 prefix | 새 원문 보존·별칭은 old 유지. 정상 검증 행을 별도 조율하며 CP 수정 금지. |
| 일부 env/manifest/state 게시 | blocked와 timer pause 유지. frozen 후보 old/new SHA 및 적용 prefix를 먼저 전수 검사. guard 통과 전 reader 시작 금지. |
| 모든 파일 게시, release 전 | blocked 아래 EOF/실제 중지/prefix 재검증→alias new CAS/fsync→양 guard 순서. 원래 bootstrap proof 바이트는 그대로 사용. |
| release 뒤 start 응답 불명 | active인 새 실제 invocation이면 guard/CP/FD를 확인해 완료 판정. 다시 start하지 않는다. inactive이면 자신의 정확 stop intent일 때만 기존 bounded start 경로를 사용. |
| alias 새 inode, native CP 미저장 | publish_pending 유지·재조회. CP 파일 복원/합성/직접 수정 금지. |
| 부트 변경 | blocked 유지, inspect만 허용. old PID/ticks/신호 ownership을 새 부트에 자동 재결속하지 않음. |

현재 raw coordinator는 새 rebind ledger를 알지 못한다. 따라서 새 ledger 파일 하나를 만드는 것만으로 `run/resume/force`가 막힌다고 주장할 수 없다. timer disable과 공용 lock을 사용하고 전환 중 직접 coordinator 호출을 금지한다. 프로세스 종료로 lock이 풀린 뒤에도 자동 실행을 막는 timer·reader barrier를 유지하고, 재개는 rebind controller의 exact 상태 검사로만 한다.

## 7. 구현 전에 필요한 최소 검증

1. **구조/거절 합성:** 기존 `raw_state_cas`의 pin 변경 거절 보존, 승인된 두 한정 transition만 허용, 다른 CID/boot/이미지/임의 추가 키·numeric SHA·중복 JSON·root 권한/링크/ancestor 이상 거절.
2. **CAS 중단:** 각 파일의 rename 전·후/fsync 실패, 두 state 사이 중단, newSHA 재발견, history fsync 실패, source 변경·부트 변경에서 재신호/재revision 0과 시작 차단 확인.
3. **두 binding·두 inode:** 실제 설치 Vector/VRL을 private 입력으로 실행하여 old env의 old 행, new env의 new 행만 정제되고 교차 binding은 정확 producer-binding 이유로 격리되는지 확인. 원문/키 전체 Mac 반출 0. 이 재생 검증은 운영 실시간 인계나 B ACK가 아니다.
4. **native CP 경계:** old 최종 EOF/LF/행 상한·pending JSON 우선·동일/빈/짧은 prefix·새 native CP 잠시 missing·Wazuh path row 일시 누락을 시험. 이때도 raw/CP를 운영 경로에 합성하지 않는다.
5. **시작 차단/재개:** 99 차단 drop-in 설치 후 실제 unit 시작 거절, 제거 직후 자동 재시도와 controller의 동일 시작 중복 방지, 한쪽 state만 게시된 경우 거절, raw timer/maintenance의 소유한 pause·최종 복원 확인.
6. **새 컨테이너 실증:** 실제 새 CID의 첫 시작 전 전체 파일·mount·UID·template 출력·producer hash 검증, old 정상 종료·raw 보존, 새 writer open, 최종 두 reader guard/CP/FD 확인. 현재 같은 CID 재시작 PASS를 이 항목의 성공으로 대체하지 않는다.

이 문서의 로컬 EOF·FD·guard는 수집 경계 증거다. Wazuh manager 수신, 분석 성공, Indexer 색인, 원격 ACK, 전체 과거 원문 무손실, host 재부팅 완료를 증명하지 않는다. raw generation 삭제·checkpoint rewind·원문 자동 재주입은 이 계약에 포함하지 않는다.

## 8. metadata helper 후보의 실제 인터페이스

[waf-rebind-metadata.sh](waf-rebind-metadata.sh)와 [test-waf-rebind-metadata-native.sh](test-waf-rebind-metadata-native.sh)를 후속 후보로 작성했다. 최초 Linux/root private fixture 32개는 부모 실행 결과 31 PASS/1 FAIL이었다. `prepare_success`는 마지막 LF가 만든 빈 행을 jq가 null 키로 해석해 실패했다. 실패 source/helper `9ed45a28…` 및 원격 로그 SHA `2fc00bd62b8a8225d4daf044b86ceeacfd7108a2d81f53bd9f05d0fff95648f3`는 보존한다. 빈 행 키에만 `// ""`를 적용하고 실제 변환 함수를 분리했으며, 파일 CAS 로직은 바꾸지 않았다. 주석·빈 행·마지막 LF의 정확한 바이트 보존 회귀 두 개를 추가했다. 수정 함수의 Mac jq 검사 2개와 부모의 A Linux 관련 `prepare` 선택시험 6개는 PASS다(로그 SHA `c40cffed095613aaac3553aa0f6350c9c2394b82f36f73d050c14deeb880ca54`). 그 뒤 `wr_main`만 고정 CLI로 연결했으며 준비·CAS 함수의 바이트 불변을 대조했다. **helper 운영 실행은 아직 하지 않았다.**

현재 fixture는 전체 34개이며 인수 `prepare`는 관련 6개, `env`는 순수 변환 2개를 선택한다. 인수 없음 또는 `all`은 전체 시험이다. fixture는 실제 metadata 파일/권한/해시/CAS/history/재개를 검사하되 live precondition과 native EOF 결과는 명시 stub한다. Docker, systemd, 운영 CP·raw 접근은 하지 않으므로 실제 FD9·effective ExecStartPre·서비스 상태·원천 EOF의 운영 호환 증거를 대신하지 않는다.

검토 후 연결한 고정 CLI는 `prepare|inspect|apply` 한 인수다. 설치 후보 경로는 `/usr/local/lib/capstone-raw-operations/waf-rebind-metadata.sh`이며 외부 wrapper가 보유한 FD9를 상속해야 한다. root0400/nlink1 자기 파일과 안전한 조상을 검사한 후 clean environment 자식에서 전체 실행을 300초, TERM 후 KILL 유예 2초로 제한한다. 시간 초과는 부분 intent·파일을 보존하고 inspect를 요구하며 자동 재시도/rollback하지 않는다. helper는 FD9와 실제 lock 경로의 devino/UID/mode/nlink를 대조하고 **같은 FD에 `flock -n`을 취득**한다. 원래부터 잠겨 있었다는 사실을 `flock` 성공만으로 주장하지 않는다. Ansible subprocess가 FD를 닫을 수 있으므로 lifecycle playbook 안에서 상속을 가정하지 않고 부모 고정 wrapper 단계에서 직접 helper를 호출한다.

입력은 고정 `/var/backups/capstone-waf-recreation-20261015/rebind/` root0700 안의 다음 세 root0400/nlink1 파일이다. JSON은 canonical compact sorted+LF, 중복 키·여러 문서·초과 크기·symlink를 거절한다.

- `descriptor.json`: exact keys `schema_version`, `policy`, `machine_id`, `boot_id`, `authority`, `expected_before_sha256`. version1/policy `capstone-waf-rebind-metadata-v1`. expected map은 순서와 무관하게 정확 `vector.env`, `raw-line-binding.json`, `waf-binding.json`, `suricata-state.json`, `modsecurity-state.json`의 before SHA다.
- `stop-proof.json`: exact keys `schema_version`, `policy`, `boot_id`, `old_cid`, `new_cid`, `old_state_sha256`, `invocation_id`, `start_usec`, `stop_armed`, `stopped_clean`, `before_status`, `after_status`. policy `capstone-waf-rebind-vector-stop-v1`. before/after status는 `ActiveState`, `SubState`, `InvocationID`, `MainPID`, `Result`, `ExecMainStatus`, `ExecMainStartTimestampMonotonic`의 7개 문자열이다. before active/running/PID>0, after clean inactive/dead/PID0 및 동일 시작 시각·동일/빈 invocation을 요구한다. 실제 중지 신호 intent 원문은 orchestration ledger가 별도로 보관한다.
- `new-producer.conf`: 새 binding 두 곳을 구 binding으로 되돌린 바이트 SHA가 before manifest의 producer SHA와 같아야 한다. 다른 변경을 허용하지 않는다. 실제 새 컨테이너 producer SHA와도 대조한다.

`authority`의 정확 필드는 아래와 같다. 상세 type/range 검사는 helper의 `wr_plan`에 있다.

| 키 | 값 |
|---|---|
| `old_container` | `cid,image,pid,start_ticks`(ticks는 문자열) |
| `new_container` | `image,started_at,identity`; identity는 writer gate의 `cid,pid,start_ticks,mount_ns,pid_ns,uid,gid` 객체 |
| `new_binding`, `new_producer_sha256` | 각각 64hex |
| `wazuh` | `invocation_id,pid,start_ticks` |
| `runtime_sha256` | coordinator.sh, guard.sh, state-lib.sh, state.jq, checkpoint-gates.sh, checkpoint-gates.jq, writer-gates.sh의 정확 7개 map |
| `barrier_sha256` | 정확 99 drop-in 바이트의 SHA |
| `unit_execstartpre_sha256` | `{vector,wazuh}`; `systemctl show UNIT --value -p ExecStartPre` 출력+LF의 SHA |
| `stop_proof_sha256` | 위 stop-proof.json SHA |

`prepare`는 다섯 live 파일을 expected SHA·metadata 전후 대조하여 `before/`에 보관하고, 실제 old EOF/new prefix 결과로 `after/`와 `plan.json`을 만든다. plan은 descriptor의 `expected_before_sha256` 대신 순서 있는 `files:[{name,before_sha256,after_sha256},…]`를 갖는다. 이미 before/after/plan 등이 있으면 부분 준비 증거를 보존하고 재생성을 거절한다. 성공 출력은 `status=prepared`, `operating_files_changed=0`이다. 이 함수의 native 읽기는 후보 생성용이며 생성물을 운영에 게시하지 않는다.

`apply`는 모든 조건을 다시 읽고 영속 `intent.json`을 먼저 생성한다. 상태는 `{schema_version,policy,plan_sha256,prefix,attempted,complete}`다. 파일 게시 전 attempted를 기록하고 게시 후 root0400 `receipts/<index>-<name>.json`을 저장한다. 기존 intent prefix와 실제 after prefix의 차이는 정확히 마지막 attempted 한 파일이 이미 게시된 경우만 수용한다. 재fsync와 receipt 검사 후 남은 파일을 진행하며 rollback하지 않는다. 완료 `result.json`은 `status=metadata_applied`, `files=5`, 정확 plan SHA 및 `alias_published=false`, `reader_start_authorized=false`, `signals_sent=0`, `raw_written=false`, `checkpoint_written=false`다. alias·runtime stop-intent 인계·99 차단 해제·Vector 시작은 이 성공 결과를 엄격히 검증한 별도 orchestration 단계다.

`inspect`는 plan·파일 prefix·intent 구조를 읽고 `live_preconditions_checked=false`, `reader_start_authorized=false`로 반환한다. 이것을 실행 권한이나 이후 alias 공개의 새 증거로 사용하지 않는다. `prepare/apply`는 현재 old alias와 runtime stop-intent 부재를 요구하므로, 정상 alias 인계 이후에 다시 실행하는 도구가 아니다.

실제 precondition은 고정 A/root/boot·검증된 runtime SHA·공용 FD9 lock, 세 timer disabled/inactive·관련 oneshot 비실행, 정확 99 drop-in 및 effective ExecStartPre/NeedDaemonReload, 실제 소유한 Vector 중지·Wazuh PID/ticks, retained old CID stopped·새 literal `waf` CID/image/identity, old root0400 봉인·new101:101/0644/nlink1·old alias/devino, writer FD old0/newopen, native old EOF와 실제 공통 prefix다. 최종 적용 전후에는 full gate, 각 파일 CAS 전후에는 빠른 현재 조건을 반복한다. 부분 게시 중 runtime reader guard가 실패하는 것을 정상으로 숨기지 않고 시작 차단을 유지한다.
