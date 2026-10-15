# Hermes 시작 전 가드 적용 후보 계획

**2026-10-15 후속:** 이 문서의 아래 본문은 10월 14일 설계 기록이다. 이후 고정 B의 실제 후보 첫 시작·시험 실패·기존 컨테이너 복귀를 완료했으며, [현재 구현·운영 결과](roles/hermes_prestart/README.md)와 [검증 기록](hermes-prestart-validation-2026-10-15.json)을 우선한다. 원래 계획과 실패 이력은 덮어쓰지 않는다.

**2026-10-14 04:39 KST 읽기 조사에 기반한 준비 자료다. 운영 전환 playbook·role·wrapper는 구현하거나 적용하지 않았다.** 이번 범위는 계획, 순수 계약 helper와 합성 검증까지다. 기존 `hermes_guard` role를 변경하지 않는다. 새 컨테이너 create/start, 기존 컨테이너 stop/rename과 실제 장애 유발은 수행하지 않았다. [생성 옵션 관측](hermes-prestart-inspect-2026-10-14.json), [원본·wheel 분리 복원 결과](hermes-cold-readiness-2026-10-14.json)를 근거로 별도 운영 단계에서 결정한다.

## 이번에 사용할 수 있는 부분

[hermes_prestart_contract.py](../../hermes/hermes_prestart_contract.py)는 전달받은 Docker inspect 메타데이터만 검사하는 표준 라이브러리 helper다. Docker 실행·파일 읽기/쓰기·네트워크·배포 CLI가 없으며, LLM/MCP에 공개하지 않았다.

- `validate_baseline(info)`는 관측한 고정 컨테이너·이미지·실행 옵션·bind·네트워크 범위를 검사한다.
- `validate_created(baseline, candidate, ...)`는 시작 이력이 없는 후보의 Config·HostConfig·Mounts 동등성을 검사한다. 환경 변수는 순서가 달라도 같은 값이어야 하며 중복 키·줄바꿈은 거절한다.
- `recovery_decision(old, new, ...)`는 후보 정지·보호 파일·DB 상태를 확인한 메타데이터에 한해서 복귀 의도 또는 수동 확인을 반환한다. DB 과거 사본 복원은 허용하지 않는다. 반환값 자체는 작업 승인이나 실행 명령이 아니다.

[합성 회귀](../../hermes/test_hermes_prestart_contract.py) **9개 통과**: 생성 옵션 차이, 잘못된 bind·환경·이미지, 알 수 없는 비기본 옵션, bool/int 혼동, 비정상 수치, 이미 시작된 후보, 불확실한 후보 정지, 보호 상태 불일치, 이름 충돌과 DB 복원 금지를 확인했다. 비밀 값은 합성 문자열만 사용했다. 재현 명령은 프로젝트 루트에서 `/usr/bin/python3 -B -m unittest discover -s infra/hermes -p 'test_hermes_prestart_contract.py' -v`다.

helper는 실제 증거를 수집하지 않으며 호출자가 제공한 inspect를 신뢰한다. 운영 사용 전에는 배포 lock 아래에서 신선한 전체 inspect, 이름에 대한 전체 Docker namespace 결속, 보호 파일·DB 검사 결과를 확보해야 한다. 검사 직후 상태가 바뀌는 경쟁 조건이나 controller 종료를 이 helper만으로 해결할 수 없다. 아래 전환·복귀 절차는 다음 작업의 설계이며 아직 실행 가능한 자동화가 아니다.

## 최소 안전 계약

- 관리자 root 전용이며 LLM/MCP/sudoers에 공개하지 않는다. 새 Galaxy collection·패키지·이미지 다운로드가 없다. 기존 Ansible builtin과 Docker CLI, 기존 uv/고정 wheel만 사용한다.
- 기존 `hermes` full ID, 고정 image ID `sha256:2fd023ef…27ea283`, 원본/가드 SHA, root artifact SHA, `/opt/hermes-data:/opt/data` bind를 확인한다. 일반적인 컨테이너 복제기가 아니다. 지원하지 않는 생성 옵션 또는 새 변경은 거절한다.
- 새 컨테이너는 **시작하지 않은 상태**에서 원본 source SHA를 읽고, core·adapter·run_turn와 고정 regex target을 복사해 다시 읽어 검증한다. 첫 gateway가 실행되기 전에 가드 파일이 완성돼 있어야 한다. 현재 timer의 사후 패치를 기다리지 않는다.
- 기존 데이터 bind는 계속 같은 디렉터리를 사용한다. 두 gateway가 이 디렉터리를 동시에 사용하지 않는다. 기존 컨테이너는 삭제하지 않고 이름을 바꿔 복귀용으로 보존한다.
- 동일 guard 배포 lock을 전체 단계 동안 유지한다. timer의 lock 경합은 기존 exit75 유예 경계를 사용한다. 다른 관리자가 바꾼 이름/파일을 덮어쓰거나 정체가 다른 컨테이너를 중지하지 않는다.
- 실제 상태 변경 직전에 이미지·컨테이너·source·설정·유휴/lease와 이름 결속을 다시 검사한다. 실패를 알면서 다음 단계로 진행하거나 보호 설정을 자동 수정하지 않는다.

## 관측한 생성 옵션과 복제 범위

| 항목 | 관측값·처리 |
|---|---|
| 이미지 | 표시 tag는 `nousresearch/hermes-agent:v2026.9.24`; create에는 확인한 full image ID만 사용 |
| 프로세스 | image entrypoint `/opt/hermes/docker/entrypoint-dispatch.sh`, command `gateway run`, user root, cwd `/opt/hermes` |
| 환경 | image 기본12개+HERMES_UID/GID=995/986, 총14개; 중복 key·줄바꿈0. 값은 서버 root0600 env 파일/no_log로만 다룸 |
| 저장 | `/opt/hermes-data:/opt/data` bind 하나, RW/rprivate; image 선언 volume도 `/opt/data` |
| 네트워크 | 기본 `bridge` 하나, 고정 IP·alias·link·driver option·노출/게시 port 없음 |
| 수명 | restart=`unless-stopped`, AutoRemove=false, stop signal/timeout 별도 지정 없음 |
| 실행 경계 | runc, private IPC/cgroup namespace, shm64MiB; privileged=false, readonly rootfs=false |
| 추가 옵션 | capability/device/DNS/extra-host/tmpfs/ulimit/sysctl 추가 없음, CPU·메모리 제한은 기본값, json-file 로그/추가 로그옵션 없음 |
| 메타데이터 | Compose labels 없음, image revision label만 있음. 기존 hostname은 기존 ID 앞12자리 |

create 직후 Config와 HostConfig를 운영 inspect 기준으로 다시 비교한다. Environment는 중복 없는 key/value의 동등성을 검사하고, root env 파일의 파싱 결과가 달라졌다면 시작하지 않는다. 나머지 Config 값은 같은 이미지의 기본값을 그대로 계승했는지 확인한다. HostConfig는 다루는 옵션만 일부 검사하지 않고 전체를 비교하여 예상 밖 차이를 거절한다.

새 container ID/생성 시각, 자동 hostname(new ID 앞12자리), 자동 할당 bridge IP/endpoint ID, Config.Image의 tag→고정 ID 표현만 의도한 차이로 허용한다. 네트워크 이름·IPAM/alias 여부·실제 image ID와 bind는 같아야 한다. 현재 관측에는 정확 재현을 막는 특수 옵션이 없지만, 실제 create 뒤의 비교가 통과하기 전에는 재현 완료로 선언하지 않는다.

## 다음 단계 파일안 — 아직 작성하지 않음

| 파일 | 책임 |
|---|---|
| `hermes-prestart-b.yml` | 고정 이미지/해시·기존 컨테이너 ID/관리자 기대값을 가진 root 전용 playbook |
| `hermes-prestart-local-b.sh` | 고정 B machine-id·root·기존 guard flock·private stage/receipt 경계 |
| `roles/hermes_prestart/tasks/main.yml` | 읽기 사전 검사, 지원 옵션 검증, 단계 간 CAS와 분기 |
| `roles/hermes_prestart/tasks/prepare.yml` | env 파일, stopped 후보 create, 원본 SHA 확인, 순수 patch/cold target 준비·복사·검증 |
| `roles/hermes_prestart/tasks/cutover.yml` | 유휴/이름 재검사, old stop·보존 snapshot, old/new rename, 최초 start·검증 |
| `roles/hermes_prestart/tasks/rollback.yml` | 확인한 new만 stop, old 이름 복원·검증 후 start; 기존 DB를 덮어쓰지 않음 |
| read-only checker | inspect 비교·정지 파일 metadata/DB quick_check·MCP initialize/tools-list만 집계. 임의 shell·도구 실행 인수는 받지 않음 |

향후 명령 실행과 상태 변경은 native Ansible task로 구현한다. 기존 순수 패처, `hermes_guard_checks.py`, 가짜 HTTP11 검증기를 재사용할 계획이다. 기존 `infra/mcp/contract_test.py`는 항상 `tools/call`까지 수행하므로 이 작업의 연결 확인기로 그대로 사용하지 않는다. 별도 연결 검사에는 모델·MCP tool call·채팅 게시를 넣지 않는다.

## 준비 단계 — 기존 서비스 유지

1. 고정 B/컨테이너/image/source/wheel 검사와 full inspect 사본을 root private stage에 보존한다. env 값과 inspect 원문은 stdout·채팅·저장소로 보내지 않는다.
2. 고정 source 후보와 cold package를 private 임시 경로에서 만들고 이미 검증한 목표 SHA·네이티브 엔진 버전·ABI를 확인한다. 운영 `/opt/hermes`와 regex target은 수정하지 않는다.
3. 고유한 candidate 이름으로 Docker create만 수행한다. Docker metadata/image/생성 옵션·Mounts 동등성 확인 뒤, 아직 시작하지 않은 후보의 원본 소스2개를 읽어 accepted SHA를 확인한다.
4. 검증한 패치2개·core·regex 전체 target을 stopped 후보에 복사한다. 다시 꺼내 SHA/패키지 파일 manifest/소유자·권한을 비교한다. 서비스 UID는 읽을 수 있고 수정할 수 없어야 한다.
5. 실패 시 기존 컨테이너는 그대로 둔다. 자신이 만든 ID와 아직 한 번도 시작하지 않았다는 상태를 증명할 때만 후보를 정리한다. 이름이 바뀌거나 실행 흔적이 있으면 임의 삭제하지 않고 중단한다.

기존 설치본으로 만든 cold target은 같은 image/CPython/ABI에서의 사전 검증이다. stopped 후보에서는 `docker exec`를 실행할 수 없으므로 첫 실행 전 byte/manifest 대조와 첫 실행 후 실제 import를 구분한다. 첫 실행 전 파일이 완성되더라도 새 런타임 import 실패까지 미리 없앴다고 주장하지 않는다.

## 전환·검증·복귀

1. 기존 gateway의 heartbeat/agent/work/lease와 config/.env/SOUL/source를 다시 확인한다. 데이터 snapshot은 old stop 후 취한다. 기존 요청이 있으면 시작하지 않는다.
2. old를 정상 stop하고 Running=false를 확인한 뒤 설정·cron·DB/WAL/SHM의 바이트/소유권/권한을 root 백업에 기록한다. old는 retained 이름으로 남기고 new를 `hermes`로 바꾼다. 전환 과정의 old/new ID와 이름은 매번 대조한다.
3. new의 첫 start 뒤 실제 설치본 가짜 HTTP11, 새 heartbeat, config/.env/SOUL 보존, DB readonly quick_check, MCP5개의 initialize/tools-list만 확인한다. 일반 사용자/cron의 자연 실행 기록을 DB 손상이나 임의 변경으로 오인해 되돌리지 않는다.
4. 정상일 때 재적용 timer의 확인된 새 ID를 기록한다. retained old는 이 작업에서 삭제하지 않는다. 운영자 확인 뒤 보관/제거는 별도 결정이다.
5. 실패하면 확인한 new를 stop하고 정지 확인 후에만 old 이름과 실행을 복구한다. 새 gateway가 DB에 쓴 정상 기록은 유지한다. old/new 동시 실행은 금지한다.
6. new 정지를 확인할 수 없거나 보호 설정 변경·DB 손상·이름 충돌을 발견하면 자동 old start도 거절한다. 이 경우 정상 복귀를 단정하지 않고 수동 확인을 요구한다. 다른 관리자의 파일을 과거 사본으로 덮어쓰지 않는다.

상태 receipt는 root 전용 파일로 단계·old/new ID·허용 해시를 기록한다. Ansible이 살아 있는 일반 오류는 native block/rescue가 처리하지만 controller 강제 종료·전원 장애는 자동 복구를 보장하지 않는다. pending receipt가 남으면 새 apply를 자동 반복하지 않고 실제 Docker 이름/실행 상태와 데이터 상태를 확인한다.

## 예상 영향과 남은 한계

후보 준비 동안 기존 gateway는 계속 동작한다. 중단 구간은 old stop부터 new의 연결/검증 완료까지이며, **대략 1–3분은 운영 계획상 예산일 뿐 실측이나 상한 보장이 아니다.** 실패 복귀 때 추가 stop/start·확인 시간이 필요하다. 실제 stage별 timeout과 중단 허용 시간을 후보 검토에서 확정해야 한다.

현재 idle/lease 조회는 새 요청 유입을 잠그는 drain 기능이 아니다. 조회 직후 기존 cron이나 사용자 요청이 시작될 수 있으므로 짧은 중단·응답 지연 가능성을 없앴다고 말할 수 없다. 운영 전환 시점은 별도 조율한다. 이 계획의 목적은 **새 gateway의 첫 실행 전에 가드 파일을 설치**하는 것이며, 무중단 서비스 전환이나 모든 대화의 무손실 처리를 증명하는 것은 아니다.

기존 `deploy_gateway_B.sh`는 env/config/cron 편집, `docker rm -f`, 즉시 `docker run`이 포함돼 이 절차를 대체하지 못한다. 현재 서비스 재생성에 그대로 재실행하지 않는다.

## 2026-10-15 실제 첫 시작·복귀 완료 후속

B root 전용 release `/opt/capstone-automation/releases/hermes-prestart-20261015-f93793c125bf`로 stopped 후보에 가드 3파일과 regex를 먼저 설치·17파일 readback한 뒤 실제 첫 시작을 수행했다. 첫 시작과 복귀 후 각각 UID 995 가짜 HTTP 11개·MCP 5개 initialize/tools-list·새 heartbeat·DB 검사를 통과했다. 정상 readiness 뒤 고정 시험 실패를 발생시켜 실제 fallback을 확인했으며 최종 상태는 `rolled-back/revision22`다.

원래 CID `6c2ed13aea89…`는 PID2248019로 운영 중이고 후보 `47aa31c88f9d…`는 정지 보존한다. 각각 start 1회·종료 코드 0을 관측했고 강제 종료·DB/WAL 과거 복원·두 번째 cutover는 없었다. 원래 plan SHA `116e2493…ee37d`와 보호 설정은 유지했다. helper Linux native 64개와 Ansible 구문 검사를 통과했으며 상세 해시와 최종 receipt는 위 현재 문서에 기록한다.

실제 구현은 위 과거 파일안의 `rollback.yml` 대신 [fallback.yml](roles/hermes_prestart/tasks/fallback.yml)을 사용한다. 고정 root 운영자 절차이며 임의 Docker 생성을 가로채는 공통 admission 장치는 아니다. 불확실 intent·임의 crash·부팅 변경은 자동 재시도하지 않는다. LLM/MCP 권한을 확대하지 않았고 이 실증은 실제 호스트 재부팅이나 무중단·모든 대화 무손실을 보장하지 않는다.

구형 우회 실행 경로도 후속 보완했다. B에서 발견한 `/home/groot_b/capstone/hermes/deploy_hermes_B.sh`를 SHA `6065fa7f…649460`으로 CAS 적용하고 기존 UID/GID1000·0664를 보존했다. 같은 바이트의 root0400 검증 사본에서 `prep/test/all`이 exit78로 거절됐으며 native41개·syntax와 Ansible `ok28/changed5/failed0`을 확인했다. 운영 PID2248019와 적용 후 원본 SHA는 유지됐다. `deploy_gateway_B.sh`는 저장소의 향후 복사본에 같은 차단을 두었고 실제 B 사본 배포로 간주하지 않는다. 직접 Docker 명령을 통제하는 범용 장치가 아니라 해당 소스 스크립트의 관리 상태 검사다.
