# 고정 B Hermes 첫 시작 전 설치와 실제 복귀

## 2026-10-23 진단 MCP 호환 계약 — 소스 검증

기존 정확한5개 MCP 또는 그 집합에 `system-diagnostics` 하나만 추가한 정확한6개를 읽기 사전 점검에서 허용한다. 새 서버는 `get_system_diagnostics` 도구1개와 이름 목록 SHA까지 고정한다. 임의 서버·추가 도구·다른 SSH 명령은 거절하며 `initialize`/`tools/list`만 호출한다. 현재 일반 `hermes-prestart-b.yml`의 source/probe SHA를 동기화했고, 아래10/15의 postcreate/postinstall 전용 playbook·증거는 당시 고정 컨테이너 이력으로 보존한다. 이 소스 검증은 새 lifecycle 실행이나 운영 전환 완료를 뜻하지 않는다.

## 2026-10-15 최신 결과 — 4단계 실제 시험 완료

고정 B 운영자 경로에서 **시작 전 가드 설치 → 후보의 실제 첫 시작·readiness → 고정 시험 실패 → 원래 컨테이너의 실제 복귀**를 완료했다. 최종 ledger는 `rolled-back`, revision 22이며 원래 plan SHA `116e24939a67657e83ebc3900740182ed491db41d42fcb9fc68e9a52f83ee37d`는 유지됐다. 기존 CID `6c2ed13aea89404463061ea2032084bdd159ae784aff4e7bd9eea7406ba9b30b`가 PID `2248019`로 운영 중이고, 시험 후보 CID `47aa31c88f9d93adb0aa28a00b40b125df6ebd1b235605ee5274661509e21342`는 `exited` 상태로 보존한다. 두 번째 cutover나 후보 삭제는 하지 않았다.

후보와 복귀한 기존 컨테이너 각각에서 실제 UID 995의 가짜 HTTP 전송 경로 11개, MCP 5개 initialize/tools-list, 해당 시작 이후의 새 heartbeat, DB 검사·보호 설정 확인이 통과했다. Docker 관측상 각각 start 1회·정상 종료 `die=0`이며 강제 종료는 없었다. DB/WAL을 과거 사본으로 되돌리지 않았고 tools/call·모델·채팅 호출도 0회다. 최종 guard readback SHA는 `eff330d8e97cab34ad8f489be69f4f57c9076786ffa0fbd3c055249ad7e0ac5e`, 최종 receipt SHA는 `38458901be81b3a3f02f6378ddedea3f43e6186fbdb2659747b6cf52180689f4`다.

실행 release는 B `/opt/capstone-automation/releases/hermes-prestart-20261015-f93793c125bf`이고, 동일 helper의 Linux root 합성 64개(0.766초)와 native Ansible 구문 검사를 통과했다. [검증·실행 기록](../../hermes-prestart-validation-2026-10-15.json)에 실패한 준비 단계와 후속 성공을 함께 남긴다. 읽기 전용 idle/DB 검사는 제한적으로 재시도하지만 arm/finish/Docker 변경은 자동 재시도하지 않는다.

이 결과는 **고정 호스트·이미지·CID·plan을 검토한 root 운영자 경로**의 실증이다. 임의 Docker 생성에 적용되는 공통 시작 차단 장치나 모든 crash 뒤 자동 복구가 아니다. LLM/MCP 권한은 확대하지 않았으며, 다음 새 CID 전환에는 새 관측과 운영자 검토가 필요하다. 아래 초기 준비·실패 기록은 당시 기준으로 보존한다.

**구형 스크립트 차단 후속도 B에 적용했다.** 실제 발견된 사본 `/home/groot_b/capstone/hermes/deploy_hermes_B.sh`의 SHA를 `b689…`에서 `6065fa7fd7d4e896a9d2da5e22f44746970fc80dc4cd2aed8992ae0f40649460`으로 교체하고 기존 UID/GID1000·0664를 유지했다. 같은 바이트의 root0400 사본에서 `prep`·`test`·`all`이 모두 변경 전에 exit78로 거절됐으며, 거절 시험 전후 운영 파일 SHA와 PID2248019는 유지됐다. native41개·구문 검사 및 Ansible `ok28/changed5/failed0`을 통과했다. 저장소의 `deploy_gateway_B.sh`에도 차단을 추가했으나 이번 B에서는 해당 운영 사본을 찾지 못해 향후 복사본 보호와 구분한다. 이는 관리 상태가 있을 때 **두 소스 스크립트의 실행을 거절하는 장치**이며 직접 Docker 호출까지 막는 공통 admission 제어가 아니다. 이 후속에서 컨테이너 변경은 없었다.

## 준비 및 보완 이력

2026-10-15 후보이며 운영 전환은 아직 실행하지 않았다. B의 기존 Ansible syntax 검사와 Linux root 합성 49개가 2026-10-15 02:34경 통과한 뒤 운영자 wrapper의 임시 실행 차단만 해제했다. 실제 stopped 후보의 Docker 옵션 대조, UID 995 native 11개 시험 및 실제 복귀 관측은 아직 남아 있다. 이 후보를 LLM/MCP 실행 권한에 추가하지 않는다.

후속 첫 `prepare`는 create/ledger 생성 전 MCP 사전 검사에서 중단됐다. 실제 SDK 2.0.0의 5개 initialize는 응답했으나, 검사기가 Python 속성 대신 wire alias `serverInfo`를 사용해 `AttributeError`가 발생했다. `server_info`와 `next_cursor` 두 속성명만 [공식 v2.0.0 모델](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/src/mcp-types/mcp_types/_types.py)에 맞췄다. snake_case 결과 처리와 페이지가 남은 응답 거절·context 종료를 회귀 검사하며, 기존 CID/PID 불변·ledger 미생성인 실패 증거는 보존한다. 실제 수정본 재검증과 lifecycle 실행 결과는 별도로 기록한다.

수정 후 로컬 회귀 50개가 0.272초에 통과했다. 별도 B 실제 UID 995 읽기 진단도 MCP 5개 initialize/tools-list, 도구 수 14/2/3/8/8, 페이지 없음·이름 중복 없음으로 통과했으며 기존 CID/PID는 유지됐다. tools/call·모델·채팅 호출은 0회다. 이 진단은 실제 후보 생성·첫 시작·복귀의 완료 증거가 아니다.

후속 `prepare`는 정지 후보 1개를 생성한 뒤 Docker CLI 기본값 차이로 후조건에서 거절됐다. 실측은 후보의 `AttachStdout/AttachStderr=true/true`, `OomKillDisable=false`와 기존의 `false/false/null` 차이이며, stdin·TTY·마운트·네트워크는 같았다. [Docker CLI](https://github.com/docker/cli/blob/v28.5.1/cli/command/container/opts.go)와 [Moby 기본값](https://github.com/moby/moby/blob/v28.5.1/daemon/daemon_unix.go)에 맞춰 **명시적인 후보 CID 비교 경로에서만** 정확한 세 값·타입을 확인한 뒤 기존 표현으로 변환한다. 나머지 전체 비교와 기존 CID의 원래 profile/plan digest는 유지한다. 일부 조합·숫자 대체·OOM 비활성화·stdin/TTY·기존 CID 변경 거절 및 기존 create intent의 후조건만 완료하는 회귀를 포함한 56개가 로컬에서 통과했다. 생성 명령은 재실행하지 않으며, 실제 후조건 재판정은 원래 plan/ledger·생성 CID를 결속한 별도 운영자 절차로 진행한다.

추가 B 실측은 Docker 29.8.1, OOM-disable 지원 false, cgroup v2다. [실제 버전의 시작 검사](https://github.com/moby/moby/blob/docker-v29.8.1/daemon/start.go)와 [지원 여부 검사](https://github.com/moby/moby/blob/docker-v29.8.1/daemon/daemon_unix.go)는 후보 첫 시작 때 OOM 값을 false에서 null로 바꿀 수 있으므로, 생성 상태는 false만, 명시적인 첫 시작 후 단계는 실제 StartedAt·running/exited 증거와 null만 허용한다. 각 단계의 Docker info 두 필드를 다시 읽고 exact false/`"2"`를 확인해 단계 증거 해시에 포함한다. 원래 plan은 바꾸지 않는다. 이 전이·지원값 변경 거절까지 포함한 최신 로컬 59개가 통과했으며 실제 첫 시작 완료를 뜻하지 않는다.

같은 후보의 create 후조건 재판정과 파일 설치 후 readback에서는 기존 uv의 `site-packages/.lock` 때문에 예상 16개와 실제 17개가 달라 거절됐다. 이 파일만 빈 바이트·root:root·0644·정규 파일·단일 링크로 허용하고 전체 해시에 포함한다. RECORD의 정확한 13개 경로에는 `.lock`을 허용하지 않는다. 로컬 64개 중 63개가 통과했으며 root 소유자 회귀 1개는 B native 실행용으로 남겼다. 기존 설치 파일을 다시 복사하지 않는 후조건 재판정은 별도 운영자 절차다.

대상은 B machine-id `1e143067c98a44ffba6eaa925dc038d7`, 기존 Hermes CID `6c2ed13aea89404463061ea2032084bdd159ae784aff4e7bd9eea7406ba9b30b`, image `sha256:2fd023efbb8d3d2b0ce1a73d028b07370cff34f567cfe0e999553e8c327ea283` 하나뿐이다. 기존 source/patcher/guard policy와 config·경보·MCP 허용 설정은 바꾸지 않는다. Python helper는 검증과 root 전용 원자 기록을 담당하며 Docker/서비스/네트워크 호출이 없다. Docker 상태 변경은 native Ansible `command.argv`만 실행한다. 새 이미지 pull, 패키지 설치, 컨테이너 삭제, DB/WAL 과거 사본 복원은 없다.

운영자 진입점은 `hermes-prestart-local-b.sh PHASE TOKEN12HEX`다. 기존 재적용 작업과 같은 `/var/lib/capstone-automation/hermes-guard/apply.lock`을 전체 실행 동안 유지한다. 5분 재적용 타이머가 이 lock을 얻지 못하면 변경하지 않는다. 별도 admission lock은 없으므로 idle/lease 확인 후 정지 사이에 새 사용자 요청이 도착하는 경합까지 제거한다고 주장하지 않는다. 관리자는 이 짧은 중단 구간을 별도로 조율해야 한다.

| 단계 | 실제 동작 및 증거 |
|---|---|
| `syntax` | native Ansible 파싱만 한다. |
| `inspect` | 이미 존재하는 transaction의 메타데이터만 읽는다. 최초 ledger/디렉터리를 만들지 않는다. |
| `prepare` | private 원본 inspect/환경·data hash를 저장 → create intent fsync → fixed image의 stopped candidate 생성 → 전체 Config/HostConfig/Mounts/네트워크 동등성 확인 → 실제 image의 accepted source 2개를 patch → core/기설치 isolated regex 복사 → 17개 파일·RECORD·wheel payload readback. 후보는 시작하지 않는다. |
| `cutover` | fresh idle/lease → stop intent → 원본 stop → 현재 DB 7파일 snapshot → 원본 retained rename → 후보 hermes rename → stopped snapshot 불변·가드 readback 확인 → start intent → 첫 start → 새 PID/StartedAt 이후의 새 heartbeat·UID 995 fakeHTTP 11개·MCP 5개 initialize/tools-list(도구 호출 0)·DB quick_check·설정 불변 → 실제 활성 CID만 watcher 기록. |
| `exercise` | 위와 같이 정상 패치 후보를 실제 첫 시작하고 readiness를 먼저 통과시킨 뒤, 고정된 시험 실패를 기록하여 아래 fallback을 실행한다. 정상 firststart 증거가 없는 prepare 실패를 복귀 시험으로 계산하지 않는다. |
| `fallback` | 확실한 firststart 후 실패 상태에서만 후보 stop intent → 후보의 정지/이름 확인 → candidate 이름으로 보존 → 원본 이름 복원 → 현재 DB 불변·후보 정지 재확인 → 원본 start intent → 새 PID/StartedAt/heartbeat·UID native 시험·DB 확인. 후보를 자동으로 다시 시작하지 않는다. |

각 mutating command는 영속 `intent` 뒤 한 번만 호출한다. timeout, 결과 불명, stop/rename 도중 중단이면 intent를 남기고 자동 재발송하지 않는다. 첫 start가 실제로 발생했다가 확실히 `exited`인 상태는 후보를 명시적으로 stop해 Docker 재시작을 억제한 뒤 fallback을 지원한다. create/install 실패는 원본을 그대로 둔다. stop-old/rename/start의 불확실 중간 상태나 부팅 변경은 자동 복구 대상이 아니며, 현재 Docker 상태·private evidence를 운영자가 검토해야 한다. 이것을 임의 crash 이후 무인 자동 복구 완료로 표현하지 않는다.

`/var/backups/hermes-prestart-TOKEN`은 root0700, plan/ledger/env/단계 evidence는 root0600이다. full inspect와 원래 환경은 이 서버 전용 경로에만 남기고 Ansible `no_log`로 처리한다. stdout은 CID/단계/해시/고정 오류만 반환한다. plan과 과거 revision/evidence는 덮어쓰지 않으며 현재 ledger만 정확 SHA CAS 후 파일·부모 fsync로 전진한다. 원문 대화·토큰·환경 값을 Mac으로 반출하지 않는다. SQLite는 운영 DB에 connect하지 않는다. 원본 DB+WAL을 private temp에 복사하고 WAL을 포함한 quick_check/lease 조회를 수행하며 원본 7파일 전후 해시·소유자·권한이 같아야 한다. SQLite가 만드는 SHM은 이 private temp에만 생긴다. DB는 정지 직후 현재 사본의 해시를 비교할 뿐 백업으로 되돌리지 않는다. 시작 이후 자연 DB/WAL 갱신은 허용하고 config.yaml/.env/SOUL의 바이트는 계속 고정한다.

이번 운영 목표는 `exercise` 한 번으로 정상 후보의 firststart와 고정 실패 후 실제 fallback을 증명하고 원래 old CID를 최종 운영 상태로 유지하는 것이다. 새 후보는 정지 상태로 보존하며 두 번째 cutover를 하지 않는다. 추후 실제 새 CID 전환은 새 관측·고정 plan·운영자 검토가 필요하다. 본 후보는 보존한 옛 컨테이너나 증거를 자동 삭제하지 않으며 실제 host reboot 검증을 대체하지 않는다.

로컬 시험:

```sh
/usr/bin/python3 -B -m unittest discover -s infra/hermes -p 'test_hermes_prestart*.py'
bash -n infra/automation/ansible/hermes-prestart-local-b.sh
```

현재 49개(기존 metadata 계약 9개 + 새 transaction/orchestration 40개)가 Mac과 B Linux root에서 통과했다. B native 실행은 0.599초였고 기존 Ansible syntax exit 0, 기존 CID/PID/StartedAt/Image 불변을 확인했다. synthetic Docker metadata와 private 임시 파일만 사용했으며 실제 Docker/Ansible lifecycle, 서버 패키지/서비스, 채팅/모델 호출은 아직 실행하지 않았다. 원래 검사본은 `/opt/capstone-automation/releases/hermes-prestart-20261015-f3e6773e49ad`, 로그는 작업 경로 `step4/native-1`에 보존했다. 이후 wrapper의 실행 차단 제거와 해당 회귀 기대값만 변경하며 실제 운영 결과는 별도로 기록한다.

기존 old 컨테이너에서 5개 MCP 연결과 source/regex 부모 root·쓰기보호를 create 전에 먼저 검사한다. SSH `StrictHostKeyChecking=yes`, `UpdateHostKeys=no`, `ControlMaster=no`, `ControlPath=none`으로 기존 키 검증·known_hosts 보존을 유지한다. 후보와 복귀한 원본의 tool-name digest를 동일 baseline과 비교한다. 이 MCP 검사는 서버 도구 목록만 읽으며 tools/call·LLM·채팅 게시를 하지 않는다.
