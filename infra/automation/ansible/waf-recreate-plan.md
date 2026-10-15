# WAF 재생성 지속성: 고정 A 한 대의 최소 전환 계획

2026-10-15 작성. **계획이며 새 CID 생성·기동·운영 적용의 완료 기록이 아니다.** 기존 Ansible, Docker CLI, Bash/jq/coreutils, 설치된 native writer/checkpoint/시작 가드를 재사용한다. 새 패키지·상시 수집기·네트워크 재생성·LLM/MCP 권한 추가는 포함하지 않는다. 원문과 Docker 전체 설정은 A의 root 전용 증거에만 보관한다.

## 확인한 기준과 작업 분리

부모가 A에서 조회한 `readiness-v6-output.json`(03:20:05 KST, SHA `c225a902ffb30d0bb73384bc0f5a0ef4f5d9865ff0554da9ded198c97f47caec`), `profile-output.json`, `network-version-output.jsonl`을 읽었다. 다음은 해당 관측의 사실이며, 변이 직전에 잠금 아래 다시 확인한다.

| 항목 | 기준 |
|---|---|
| machine ID | `096e90b6243e438aa8a7b392be754732` |
| 기존 WAF CID | `02fb9ec3db38b01ccc49b61c7ca57d41e745d691cf0acd97a8b9978b16e1f41e` |
| image ID | `sha256:411cc97544ec0af886d3bc2a230564c2d28f08a800152617507476cda6ae9650` |
| 실행 | PID2377669, UID/GID101, healthy/running, SIGQUIT, restart `unless-stopped` |
| 기존 네트워크 | `secstack_waf-net`, ID `aaadd71ccea72ed484e217ace846752bcaf465412116f3806de5b14834138654`, bridge/default IPAM, `172.18.0.0/16`, gateway `.1` |
| 기존 WAF 주소 | `172.18.0.2`, 현재 해당 주소의 유일한 소유자, endpoint IPAMConfig는 null |
| Docker | A Engine29.8.1/API1.56 |
| 원본 상태 | Suricata active gen1/revision5, WAF active gen3/revision11; pending/stop/reopen intent 없음 |
| reader | Vector2406117, Wazuh logcollector1909632; Wazuh unit MainPID0은 정상인 별도 daemon 구조 |
| 자동 작업 | raw 두 timer와 output maintenance timer enabled/active/waiting |

서버 기준 증거는 `/var/backups/capstone-waf-recreation-20261015/`의 `before-inspect.json`, `before-compose.yml`, `rendered-compose.json`, `image-inspect.json`이다. 이 원본을 후속 결과로 덮어쓰지 않는다. 기존 실제 bind는 로그 RW와 GROOT948 RO 두 개뿐이다. Imperva RO는 live compose에만 있으며 producer와 시작 template은 writable layer에만 있다. 같은 CID의 01:48:58 정상 재시작 성공은 새 CID 지속성 검증을 대신하지 않는다.

작업을 두 부분으로 나눈다.

1. **영구 원본 준비:** 별도 `waf-persistence-prepare-a.yml`에서 기존 producer/template 바이트를 root 호스트 파일로 보존하고 live compose에 두 RO mount만 추가한다. 기존 binding/CID/PID/원본/state는 유지한다. 이것만으로 실행 중 mount가 바뀌거나 재생성이 완료되지는 않는다.
2. **새 CID 전환:** 본 계획에 따라 정확한 WAF 하나만 교체하고 새 binding·audit 세대·두 raw state의 공통 env pin을 인계한다. source/metadata CAS는 [재결속 계약](../../normalization/vector/raw-operations/waf-rebind-contract.md)의 별도 고정 helper가 담당한다. 일반 회전기의 허용 범위를 넓히지 않는다.

## 고정 설정과 최소 허용 차이

live compose `/home/groot_a/capstone/secstack/docker-compose.yml`의 기준 SHA는 `5f41d56c42f00d625b2ec3bec3f355f9599e8a38fa824f9baa193bcce2dd5d60`이다. prepare 완료 뒤에는 그 단계가 발행한 실제 새 SHA를 입력으로 사용한다. 저장소의 초기 compose나 `deploy_secstack.sh`를 다시 실행하지 않는다.

새 컨테이너는 기존 image ID로 `--pull=never` 생성한다. entrypoint/Cmd/Healthcheck/User는 실제 image 기본값과 기존 값이 같다는 profile을 재검사하고, 기존 env11·포트80/8443·extra_hosts·보안 기본값·기존 로그/GROOT mount를 보존한다. Env 값은 출력하지 않고 서버 내 exact 비교한다. 허용 차이는 다음으로 제한한다.

- 새 CID/Hostname/생성시각 및 tag 대신 동일 immutable image ID 지정.
- Imperva·producer·override **template** RO bind 세 개가 기존 두 mount에 추가되어 실제 mount가 다섯 개가 됨.
- 같은 기존 네트워크의 endpoint에 명시 IP `172.18.0.2` 지정.
- 후보의 restart policy만 `no`. 인계 완료 뒤 exact 새 CID에 `unless-stopped` 갱신 한 번.
- 관리 label의 명시된 차이. 기존 Compose config-hash를 새 구성의 해시처럼 복사하지 않는다. 거짓으로 남을 Compose 관리 label은 정해진 목록으로 제거하고 고정 plan/역할 label을 붙이며, 나머지 label은 별도 exact 정책으로 대조한다. 이후 무검증 `compose up`으로 다시 덮어쓰지 않는다.

추가 bind의 container 목적지는 다음과 같다. host source 두 경로/SHA는 prepare 결과와 다시 대조한다. 임의 경로 인수는 허용하지 않는다.

| 원본 | container 목적지 | 계약 |
|---|---|---|
| `/etc/capstone-waf/REQUEST-900-CAPSTONE-SCANNER.conf` | `/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-CAPSTONE-SCANNER.conf` | root0444, SHA `d95e75f39d082053543b04de10d538154da4ce8b25e9333014b3b2d858b65f8d` 그대로 |
| `/etc/capstone-waf/zz-capstone-evidence-v2.conf` | `/etc/nginx/conf.d/zz-capstone-evidence.conf` | root0444, 새 binding 두 위치만 변경한 후보 SHA를 고정 |
| `/etc/capstone-waf/modsecurity-override-v2.conf.template` | `/etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template` | root0444, SHA `814a4af8c52a66e1ee0eed072b0e5dbac9340240cad8ae6118ec7a5e902ea8cb` |

native entrypoint가 생성하는 `/etc/nginx/modsecurity.d/modsecurity-override.conf`와 `/etc/modsecurity.d/modsecurity-override.conf`는 RO mount하지 않는다. 첫 기동 후 두 생성물이 template과 같은 검증된 내용인지 확인한다. managed directory root0711, 새 audit 파일101:101/0644와 고정 path-conf root0444 계약도 다시 확인한다.

## `.2` 보존의 사전 조건

Docker 일반 CLI 문구만으로 자동 할당 subnet의 지원 여부를 판단하지 않는다. 확인한 A29.8.1의 `validateEndpointSettings`는 user-defined network 여부와 실제 `IpamInfo()` pool 안의 주소인지 검사한다. 명시 subnet이 없을 때의 금지 검사는 제거돼 있다. 따라서 현재 기존 네트워크를 재생성할 필요는 없다. [Moby29.8.1 실제 검사](https://github.com/moby/moby/blob/docker-v29.8.1/daemon/container_operations.go#L494-L592). 이 변경의 공식 설명도 자동 할당 pool에 지정 IP를 허용한다고 명시한다. [Moby PR51577](https://github.com/moby/moby/pull/51577).

old stop **이전**에 exact image와 후보 이름으로 `docker create --network secstack_waf-net --ip 172.18.0.2 ...`를 한 번 수행해 daemon 설정 검증·stopped/never-started·IPAMConfig·전체 허용 diff를 확인한다. 생성은 프로세스를 시작하지 않는다. 다만 생성 성공은 start 시 endpoint/IP/포트 할당 성공을 보증하지 않는다. [Docker create](https://docs.docker.com/reference/cli/docker/container/create/).

담당 경계는 `waf-recreate-candidate-a.yml`이 정지 후보 `waf-prestart-20261015` 생성과 profile 대조, `waf-recreate-cutover-a.yml`이 실제 인계 순서다. 기존 보존명은 `waf-before-20261015`, network alias는 `waf`, 관리 label은 `capstone.waf.recreation=20261015`로 고정한다. 후보 결과의 새 CID를 얻은 뒤 binding을 발급·고정하고, **첫 start 전에만** producer host 파일을 기존 SHA에서 새 SHA로 CAS한다. created 후보에 기존 producer inode가 mount됐다고 가정하지 않고 실제 first-start readback으로 최종 새 SHA를 확인한다.

old가 완전히 정지한 뒤 기존 endpoint의 `.2` 점유가 해제됐는지 확인하고 새 후보를 시작한다. 첫 start 후 실제 IP가 정확 `.2`, 기존 network ID, 유일 소유자임을 확인한다. 예상과 다르면 예외를 subnet으로 넓히지 않고 전환을 보류한다. 기존 endpoint가 남았다는 이유로 `network disconnect --force`나 네트워크 삭제를 자동 추가하지 않는다.

## 고정 운영 순서

각 Docker 변이는 **고정 대상·인수·전 상태·intent fsync → 정확 한 번 호출 → actual inspect → 결과 fsync**로 수행한다. timeout·응답 유실·잔여 intent는 자동 재호출하지 않는다. Ansible `until`/rescue로 create/stop/rename/start를 반복하지 않고 읽기 재조회만 반복한다. 전체 작업에 shell `eval`이나 env 실행을 사용하지 않는다.

| 단계 | 수행과 완료 조건 |
|---|---|
| 0. 계획·후보 준비 | fresh host/boot/CID/image/profile·보호 SHA·원본 state를 고정한다. 새 64hex binding과 producer 후보를 한 번 생성해 fsync한다. 기존 producer 두 binding 위치만 바뀌고 나머지 바이트가 동일해야 한다. private native nginx/template 검사와 좁은 Imperva 회귀를 마친다. stopped 후보 create/readback은 여기서 완료 가능하다. |
| 1. 동시 작업·시작 차단 | 기존 timer 상태를 보관하고 raw2+maintenance timer를 일시 disabled/inactive로 만든다. 실행 중 oneshot 종료와 모든 pending/intent 부재를 확인한다. `rule-change/.lock` 다음 `vector.lock` 순으로 취득한다. 두 reader에 고정 `99-capstone-waf-rebind-block.conf`(`[Service]`와 `ExecStartPre=/usr/bin/false`만, root0644)를 create-exclusive로 추가하고 daemon-reload한다. effective ExecStartPre에 기존 guard와 false 정확1개, NeedDaemonReload=no를 확인한다. **기존 migration marker와90번 drop-in은 변경하지 않는다.** 실행 중 reader는 계속 동작한다. |
| 2. old WAF 정상 종료 | exact old CID/PID/ticks/StartedAt와 모든 nginx member PID/ticks를 보관·재대조한 뒤 `docker stop --signal SIGQUIT --timeout -1` 한 번. CLI만70초로 제한하고, timeout 때 daemon에 stop/kill을 재전송하지 않는다. old container는 삭제하지 않는다. Running=false/Pid0/Restarting=false, old PID/namespace 종료, endpoint 해제를 확인한다. 강제 kill 또는 불확실 종료는 별도 실패 상태로 남긴다. |
| 3. 구 binding EOF·Vector 중지 | old generation3을 최종 inode/size/hash/LF와 old process 종료로 봉인한다. 구 alias와 구 env 상태에서 Wazuh/Vector EOF를 최대125초 읽기 대기로 검증한다. EOF 보류 때는 실제 stop intent를 만들지 않으므로 봉인 결과를 재확인하고 이 읽기 단계를 다시 시도할 수 있다. 실제 Vector Invocation/start_usec에 결속한 영속 stop intent 후 정상 중지하고 native 저장 CP의 EOF를 다시 확인한다. v2 audit 단독이므로 access join drain을 새로 만들지 않는다. Suricata writer는 계속 기록한다. |
| 4. 새 writer 경계 | 고정 generation4를 새 inode로 create-exclusive하고 audit-path.conf를 CAS한다. old 이름을 보관명으로, 후보를 literal `waf`로 각각 한 번 rename한다. first-start intent 후 후보 start 한 번. healthy/UID101/actual mount5/IP `.2`/모든 config SHA를 확인한다. old stopped 증거와 별도로 새 `writer_identity waf` 및 새 writer의 old inode FD0/new inode FD>0을 확인한다. |
| 5. 검증된 source 재결속 | old EOF+새 prefix 구분이 확인된 뒤 env/binding2개/두 raw state/실제 stop ownership 인계 후보를 한 번 고정한다. 기존 state/history를 보존하며 특수 CAS한다. WAF current gen3→pending gen4/publish_pending, 새 CID/producer/env pin; Suricata는 env pin과 revision만 바뀐다. Vector 설정·VRL·Wazuh 설정·checkpoint는 유지한다. |
| 6. alias 공개와 차단 해제 | 차단 유지 중 old EOF/새 prefix를 재검사하고 old alias→새 generation hardlink를 정확 CAS·fsync한다. final state/source/alias와 양 runtime guard가 통과해야 별도 전환 ledger에 해제 근거를 게시한다. 정확한99번 drop-in 두 개만 제거하고 daemon-reload/effective 기존 guard를 확인한다. 기존 migration marker는 그대로다. 차단 해제 전에 새 env로 구 alias를 다시 읽는 구간을 만들지 않는다. |
| 7. native resume·완료 | 새 state에 실제 stop ownership이 결속된 것을 확인하고 기존 `resume modsecurity`로 Vector 시작과 새 native CP를 확인한다. Vector current CP와 Wazuh 새 prefix/current inode FD가 확인된 뒤에만 active가 된다. 초기 기준 그대로라면 WAF revision12→13, Suricata5→6이다. 보류되면 publish_pending을 유지하고 CP를 만들거나 고치지 않는다. |
| 8. 정책·자동 작업 복귀 | 양 guard/health/source/예외/.2/새 state를 대조한 뒤 exact 새 CID의 restart policy를 `unless-stopped`로 한 번 바꾼다. cutover `complete` 영수증은 `native_handoff_complete_timers_paused`이며 세 timer를 활성화하지 않는다. 별도의 검토된 관리자 절차로 timer를 원래 상태에 맞춰 순차 복귀시키고 첫 실행/실제 due 여부·pending0·reader를 확인한다. maintenance는 `TZ=Asia/Seoul`을 사용한다. old container와 모든 원본 세대·증거는 보존한다. |

새 generation이 0B이면 Wazuh의 동일 prefix 오인을 배제할 근거가 부족할 수 있다. 실제 자연 행을 기다리거나 별도 승인된 정상 localhost 요청 1회만 사용한다. 해당 요청이 messages0이면 수집/시간/CP 검증일 뿐 보안 경보·Indexer ACK 성공으로 보고하지 않는다.

`writer_gate`는 현재 이름 `waf`의 **running** 컨테이너를 요구한다. stopped old에 호출해 실패했다고 writer가 남아 있다고 단정하지 않고, old 종료 증거와 new writer의 old FD0을 구분한다. binding은 새 CID마다 바꾸므로 old raw를 새 env로 재해석하지 않는다.

## 재사용할 실제 명령과 새 구현의 경계

다음은 검토된 고정 경로의 함수/API다. 실행 전 설치 소스 SHA와 소유/권한을 대조한다. 인수는 위 plan/봉인 증거에서만 가져온다.

```bash
source /usr/local/lib/capstone-raw-operations/checkpoint-gates.sh
source /usr/local/lib/capstone-raw-operations/writer-gates.sh

cg_vector_eof /var/lib/capstone-vector/waf_audit "$OLD_SOURCE" "$OLD_DEV" "$OLD_INO" "$OLD_BYTES"
cg_wazuh_eof /var/ossec/queue/logcollector/file_status.json \
  /home/groot_a/capstone/secstack/logs/modsec/audit.log \
  "$OLD_SOURCE" "$OLD_DEV" "$OLD_INO" "$OLD_BYTES"
cg_sealed_lines "$OLD_SOURCE" "$OLD_DEV" "$OLD_INO" "$OLD_BYTES" 1048576
cg_wazuh_cold /var/ossec/queue/logcollector/file_status.json \
  /home/groot_a/capstone/secstack/logs/modsec/audit.log \
  "$NEW_SOURCE" "$OLD_DEV" "$OLD_INO"

/bin/bash /usr/local/lib/capstone-raw-operations/guard.sh vector
/bin/bash /usr/local/lib/capstone-raw-operations/guard.sh wazuh
/usr/local/sbin/capstone-raw-operations check modsecurity
/usr/bin/env TZ=Asia/Seoul /usr/local/sbin/capstone-vector-maintenance check
```

함수의 scratch 파일 외 원문/CP에는 쓰지 않는다. Wazuh는 해당 path의 저장 offset 전체 prefix SHA1을 대조한다. CP 전체 파일 SHA는 다른 입력 때문에 달라질 수 있어 각 관측 증거로 남기고, 다른 SHA라는 이유만으로 CP를 복원하지 않는다. missing/partial/잘못된 CP와 동일 prefix 새 inode는 보류한다. cold 판정과 함께 coordinator의 실제 공통 길이 prefix 구분도 요구한다.

`/usr/local/sbin/capstone-raw-operations resume modsecurity`는 **변이 명령**이며 내부에서 vector.lock을 잡는다. 외부가 같은 lock을 잡은 채 중첩 호출하지 않는다. final 후보와 receipt를 fsync한 뒤 timer/시작 차단 계약에 맞춰 외부 vector lock을 풀고 단일 resume을 호출하거나, 검토된 같은 프로세스 인계 방식 하나만 선택한다. checkpoint는 수정하지 않는다.

새 코드는 고정 A/WAF용 Ansible 단계와 필요한 작은 영속 CAS/receipt helper에 한정한다. 일반 `raw_state_cas`는 source_pins 변경을 거절하므로 우회 옵션을 추가하지 않는다. [state-lib.sh](../../normalization/vector/raw-operations/state-lib.sh), [실제 coordinator 소스](../../normalization/vector/raw-operations/coordinator-writer-intent-fix.sh), [새 CID 재결속 계약](../../normalization/vector/raw-operations/waf-rebind-contract.md)을 재사용한다. 기존 v1 Vector role/storage의 migration 거절 가드와 초기 migration ledger/plan은 유지한다.

## 구현 후보의 좁은 실행 계약

`waf-recreate-cutover-local-a.sh`가 공유 잠금을 소유하고, `waf-recreate-cutover-a.yml`은 기존 Ansible로 고정 lifecycle 명령만 실행한다. 공개 play pin은 native 검증 전 `REVIEW_PENDING`으로 차단했고, 최종 후보에서는 검증한 play SHA에 고정했다. 이는 실제 전환 완료를 의미하지 않는다. `preflight`는 원본/후보 CID와 전체 created profile, 경로·권한·소스 SHA·state5/11·timer·양 guard를 읽기만 하며 `initialize`나 old stop을 대신 실행하지 않는다.

단계는 `initialize → barrier → stop-old → drain-stop → prepare-new → retain-old → name-new → start-new → prepare-metadata → apply-metadata → publish → unblock → resume → complete`다. `prepare-metadata`/`apply-metadata`는 고정 FD9를 유지하는 wrapper에서 native Bash helper를 직접 호출하고, 일반 lifecycle은 Ansible에서 처리한다. `resume`만 native coordinator의 기존 재개 상태 머신에 한정해 최대8회의 명시 호출을 허용한다. 재호출마다 결과를 별도로 기록하며 Docker stop/rename/start 재전송은 허용하지 않는다.

응답이 불확실한 lifecycle의 `verify-*`는 해당 intent와 실제 완료 상태만 재조회한다. 성공한 Docker 명령을 다시 실행하지 않는다. post-action 영수증은 정확한 기존 바이트만 재사용할 수 있다. 새 전환/다른 Invocation/다른 boot로 간주되는 값은 기존 증거를 덮지 않고 거절한다. 자동 rollback이나 범용 재부팅 복구는 구현 범위가 아니다.

실측 Docker29.8.1/API1.56 및 `OomKillDisable=false`, cgroup2 조건을 start 전후 확인한다. created→started에서 `OomKillDisable=false`가 `null`이 되는 한 필드와 실측8개 HostConfig의 `null`/빈 배열만 정규화한다. 두 profile의 전체 키 집합과 나머지 값은 동일해야 한다. 이 예외는 실제 A daemon의 기본값 직렬화에 한정되며 값이 있는 배열·누락 키·새 보안/리소스 설정을 허용하지 않는다.

## 실패와 재개 범위

| 경계 | 허용하는 처리 |
|---|---|
| old stop 전 | old 계속 운영. 생성한 stopped 후보/호스트 후보/intent를 보존하고 실패 원인만 수정한다. 살아 있는 기존 WAF를 지우거나 재생성하지 않는다. |
| old 정지 후, 새 writer 시작 전 | 새 후보가 확실히 stopped임을 확인한 뒤 old 이름·pointer·권한·기존 source/시작 조건을 exact CAS 복구할 수 있는지 검사한다. 모든 조건이 맞을 때만 old 정상 start를 별도 intent로 수행한다. old gen 봉인 해제는 이 경계에 한정하고 기록한다. |
| 새 writer 시작 후, reader 인계 전 | 새 원문과 binding을 보존한다. old와 new 동시 실행 금지. 새 종료가 입증되지 않으면 old를 시작하지 않는다. 새 원문이 생긴 뒤에는 단순 원본 파일 복사로 rollback하지 않고 전진 재개 또는 별도 복구 계획을 택한다. |
| metadata 일부 CAS/alias 공개/release 후 | blocker와 intent를 보존하고 exact 현재 상태를 읽어 남은 단계를 구별한다. 이미 처리한 CP/원문/state를 이전 백업으로 덮지 않는다. 일반 rescue의 old start/재create는 금지한다. |
| daemon 응답 유실/다른 root 변경/재부팅 | 자동 재호출 없이 inspect-only. 정확 CID·phase·boot·파일 원본/후보 SHA가 확정되지 않으면 blocked 및 timer 보류를 유지한다. 재부팅 전체 복구 성공은 이 작업의 완료 조건으로 주장하지 않는다. |

IP가 `.2`가 아니면 Imperva 예외는 적용되지 않아 원래 탐지가 유지되는 설계다. 이를 이유로 목적지 조건을 제거하거나 새 주소를 임의 채택하지 않는다. source `211.170.162.9`, destination `172.18.0.2:8080`, 정확 GET `/`와 기존 protocol/Host/framing 조건 및 제외 ID920280/920350은 불변이다. [기존 예외 계약](../../groot-a/imperva-exception/README.md).

## 구현 전·후의 필수 검증

- 변이 없이 고정 Docker argv/profile diff·image/Env/ports/security·label 허용 목록·세 신규 RO bind·`.2` 설정을 검증한다. create 응답 유실, stop/rename/start 불확실 결과에 변이 재전송0을 시험한다.
- 합성 state/실제 private 파일에서 old EOF 미달, 동일 prefix, 빈 새 세대, CP row 누락, source pin 일부 갱신, 두 state 중 한 개만 게시, alias 게시 후 중단, release 전 자동 reader start 차단을 시험한다. 이전 phase를 성공으로 축약하지 않는다.
- native entrypoint/template/producer/Imperva 경로를 실제 UID101과 RO mount 조건으로 검증한다. 예외의 두 정상 조건과 기존 조건 이탈·공격 대조는 별도 격리 native fixture에서 검증하고 운영 공격 요청은 만들지 않는다.
- 실제 전환 후 새 CID 한 개만 running, old stopped 보존, image동일·IP `.2`·UID101·healthy·mount5·RestartCount·새 binding을 대조한다. 원래 GROOT/Imperva/rules·다른 컨테이너·Suricata writer·Wazuh PID/설정은 유지되어야 한다.
- old 세대 봉인 hash, 새 audit context, Vector/Wazuh current CP 및 alias/FD, 양 raw state active, pending/intent0, 양 guard·maintenance check, 최종 restart policy와 세 timer의 첫 실행을 각각 기록한다. 필요하면 설치된 source/doc/metadata를 A/B 영구 증거에 보관한다.

범위는 **한 번의 통제된 새 CID 전환과 설정 지속성**이다. 자연 Imperva 스캔의 효과, 장기 무손실, Wazuh 모든 행 송신, 전역 exactly-once, 원격 영속 ACK, host 재부팅은 별도 근거가 필요하다. 파일 보존·native CP·manager/Indexer 수신을 같은 성공으로 묶지 않는다.

## 2026-10-15 후보 검증 기록

부모가 A에서 실행한 검증 결과를 전달받았다. 고정 후보 create는1회였으며 첫 profile 검사는 Docker의8개 HostConfig empty 기본값 직렬화 차이로 거절됐다. 새 고정 CID의 postcreate-only 검사로 이를 확인했고, 해당 후조건35태스크는 failed0이었다. 추가 create/start/stop은0이며 기존 WAF PID2377669는 유지됐다. 새 CID는 `6c72d5a5b8229fc3b6e010c9d046d97ac5c13437cae045c72a330fe0d6d82f81`로 고정했다. 첫 거절 이력과 기존 snapshot은 보존했다.

cutover의 root-private native22개는 실제 파일 생성/CAS·fsync 실패·rename 불확실·EOF 보류 후 재시도·armed stop 재전송 거절·Invocation 변경·stop-proof 게시 후 완료 영수증 복구를 통과했다. 시험에서는 서비스/운영 raw/checkpoint/Docker를 호출하지 않았으며 native gate는 mock이다. 별도 실제 `wrc_unit` parser8개와 실제 profile jq34개, 합계42개 순수 검증도 통과했다. 이 결과가 실제 lifecycle나 네트워크 인계를 대신하지 않는다.

native22 검증 wrapper SHA는 `50faf6c8ae2e01c4dabe0a1c2361b040ee73b7e6814a90a5cfcb6c7c48fb40b3`이다. 최종 후보 `6e31ccc907d69fb7dd53d1a3e0acc47f8c760f966a01ebc7e7018078418b4d8f`는 변이 함수의 바이트를 유지하고, 읽기 preflight에 Mounts 순서 정규화·설치 helper/entrypoint/maintenance/producer 핀·새 generation 부재 확인을 추가한 뒤 공개 play 핀을 연결했다. play SHA는 `433925fb6fdf069bb9387bd98f53eb11ec0b3d389b5231984cb32a809861cd55`이며38태스크/embedded Bash24구문 검사가 통과했다. 실제 native Ansible 최종 구문·read-only preflight와 이후 전환 결과는 별도로 기록해야 한다.

후속 v4에서 순수42개는 다시 통과했으나 Ansible 구문 검사 전에 `LC_ALL=C`가 UTF-8 요구에 맞지 않아 실행을 거절했다. 운영 변경은0이었다. 부모가 확인한 원인에 따라 public entrypoint의 locale만 `C.UTF-8`로 바꾼 후보 SHA는 `dfcec89a025fd80ca261130cb47f2af5ac86d82c63822eaf7f0df1d8a858053f`다. 변이 함수·play·pins는 그대로이며 v4 실패 증거를 보존한다. 실제 구문·preflight는 이 보완본으로 재확인한다.

실제 전환에서는 initialize/barrier와 old WAF의 SIGQUIT 정상 stop이 완료됐다. 다음 drain-stop의 EOF·의도 저장 뒤, Vector stop을 보내기 전 검증이 거절됐다. 원인은 `wrc_unit`가 키 순서를 정규화하지 않아 저장 JSON이 `wrc_json`의 canonical 바이트 조건과 달랐던 것이다. 부모의 읽기 진단에서 Vector는 기존 PID2406117/Invocation `12314ddc66e14e0083b08db2e51fc831` 그대로 active였고 새 후보는 never-started였다. 기존42개 시험은 JSON 의미만 비교했고 native22개는 미리 정렬된 unit stub을 사용해 이 공백을 놓쳤다.

수정은 `wrc_unit`의 jq에 `-S` 한 옵션을 더한 것뿐이며 source SHA는 `5a68aa0ecc28babe6fa066db816177545e7c4aea44572c56962c90dab42a153e`다. 성공 unit3개에 canonical 바이트 정확 비교를 추가한42개는 이전본에서3실패/수정본에서42통과했다. native fixture에도 실제 unit parser→drain-stop 저장→dispatch guard 연결1개를 추가했다(총23개, Linux 결과는 후속 기록). 저장 원본 SHA `3c35c71c…`와 기존 intent SHA `167eb8aa…`를 고정한 별도 일회 completion script는 원문을 root0400으로 먼저 보존하고 의미가 같은 canonical 파일만 CAS한 뒤, 같은 active Invocation과 기존 guard를 재확인해 **첫 Vector stop1회**와 기존 post만 이어가도록 준비했다. old WAF stop 재전송·새 container start·checkpoint 수정은 포함하지 않는다. 완료 여부는 실제 실행 영수증으로 따로 판정한다.

부모의 v7 실행에서 수정본 canonical42개가 native 통과했고, 일회 completion script로 실제 첫 Vector stop과 기존 post가 성공했다(`stop-proof` SHA 접두8175cc, phase 영수증 접두2f48c76). old WAF stop은 재전송하지 않았다. 이 시점부터 새 producer 준비·rename·first-start가 진행 중이며, source는 동결 상태다. 새로 추가한 통합23번째 fixture는 가용성 복구 전 실행을 확대하지 않고 후보 증거로 보관한다. 최종 인계 성공은 아직 이 기록으로 주장하지 않는다.
