# Hermes 복구 절차의 분리 검증

이 검증은 운영 Hermes를 중지·재시작·재생성하거나 실제 채팅을 보내지 않고, 운영 Ansible의 **판단과 `block/rescue` 흐름**을 임시 합성 파일로 검사한다. Docker 동작은 시험 대역이므로 실제 엔진의 복구 성공이나 새 컨테이너의 정상 시작을 증명하지 않는다.

## 실행 범위

[`tests/hermes_guard_fixture.py`](tests/hermes_guard_fixture.py)는 현재 `roles/hermes_guard/tasks/main.yml`에서 이미지·소스·직전 유휴·컨테이너 이름 결속 검사와 배포/복구 block을 직접 읽는다. 원본 task의 assert·when·register·loop·rescue는 실제 Ansible이 평가한다. Docker/helper 명령만 임시 fixture 경로의 시험 대역으로 바꾸며 heartbeat 재시도 간격은 시험에서만 0초로 줄인다. 원본 운영 task와 helper의 SHA-256을 결과에 남긴다.

시험의 모든 컨테이너 파일은 임시 디렉터리 아래의 평범한 파일이다. SQLite도 같은 디렉터리에 새로 만든 합성 DB다. `hermes_guard_checks.py`의 실제 snapshot·idle 함수가 이 자료를 읽는다. 원본 코드의 고정 파일 해시 변수에는 합성 파일의 해시를 주입하므로 운영 이미지/소스의 진위를 새로 검사하는 시험으로 해석하지 않는다. 운영 이미지/소스 거절 식의 분기와 실행 순서를 검사한다.

안전 경계는 다음과 같다.

- 실제 Docker·systemd·네트워크·패키지 명령을 호출하지 않는다. Ansible의 native 모듈은 command/copy/stat/assert/set_fact/fail만 허용한다.
- native copy/stat 대상은 알려진 stage 파일 template 4개로 한정한다. 명령 대역은 동일 fixture ID와 통합 파일 3개만 다루며 절대경로·`..`·심볼릭 링크를 통한 경계 이탈을 거절한다.
- task 이름·명령 형식·허용 모듈이 바뀌면 자동 추정하지 않고 시험을 중단한다. 새로운 운영 경로를 검토한 뒤 시험도 함께 갱신한다.
- 결과는 시나리오명·판정·합성 lifecycle 횟수·변경된 합성 파일명과 코드 해시만 출력한다. 실제 설정·원문·대화·비밀은 입력받지 않는다.
- 실행이 정상 종료하면 전체 합성 파일/DB와 Ansible 임시 파일을 삭제한다. 시험 프로세스 강제 종료 시 잔여 임시 파일 정리는 별도 운영자 작업이다.

## 재실행

Mac에는 패키지를 설치하지 않는다. 경계 회귀와 계획 작성만 stdlib Python으로 수행할 수 있다.

```sh
python3 -B -m unittest discover -s infra/automation/ansible/tests -p 'test_hermes_guard_fixture.py' -v
python3 -B infra/automation/ansible/tests/hermes_guard_fixture.py prepare
```

B에 이미 준비된 `/opt/capstone-automation/venv/bin/ansible-playbook`으로만 native 실행한다. 프로젝트의 상대 디렉터리를 유지한 비공개 시험 사본에서 실행한다. 이 명령은 운영 재적용 wrapper를 호출하지 않는다.

```sh
python3 -B infra/automation/ansible/tests/hermes_guard_fixture.py run
```

## 시나리오와 의미

| 분리 시나리오 | 확인할 결과 |
|---|---|
| 정상 후보·core 없는 원본 | 후보 3파일 일치, 합성 stop/start 각 1회, 보호 파일 불변 |
| 알 수 없는 이미지/소스·직전 소스 변경·busy·이름 결속 변경 | 합성 stop/start/후보 쓰기 모두 0 |
| 부분 복사 실패·설치 읽기 해시 불일치 | 원본 파일 복구, 보호 파일 불변, 실패 결과를 숨기지 않음 |
| 시작 전 DB 변경 | 원본 코드 복구 뒤에도 정지 유지; 바뀐 DB를 과거 사본으로 덮어쓰지 않음 |
| 시작 후 runtime 실패·core 없는 원본의 실패 | 원본 통합 재시작; 원래 없었던 core는 미사용 상태에서 제거 |
| 시작 후 정상 DB 증가와 runtime 실패 | 원본 코드를 복구하되 새 DB 기록 보존 |
| 시작 후 config 변경·원본 복구 해시 불일치 | 재시작 거절, 정지 상태 유지 |
| 최초 stop 명령 실패 | 보존 snapshot이 없으므로 추정 재시작 거절 |

시험의 예상 실패는 Ansible exit 2여도 보호 경계가 맞으면 통과로 분류하므로, native 종료 코드와 시나리오 판정을 함께 기록한다.

## 2026-10-14 분리 시험 결과

B의 기존 native Ansible에서 **16개 시나리오가 모두 통과**했다. Mac와 B의 stdlib 경계 회귀는 각각 7개 통과다. 먼저 정상/부분 복사 실패 2개로 실행 경로를 확인했고, 독립 읽기 검토에서 권고한 native 파일 대상의 정확 allowlist를 반영한 뒤 전체를 실행했다. 운영 role와 helper의 소스는 바꾸지 않았다. [시나리오별 종료 코드·소스 해시·관측 메타데이터](hermes-recovery-validation-2026-10-14.json)를 보존한다.

04:25 KST 읽기 관측에서 기존 Hermes의 전체 ID·이미지·01:37:16 KST 시작 시각을 확인했다. 컨테이너는 running/OOM false, 재적용 timer는 active/waiting, metadata observer는 active/running이었다. 03:55–04:25 KST의 observer verdict 4종은 모두 0건이며 다른 journal 행도 0건이다. 응답 분모가 없으므로 0% 혼입률이라는 뜻은 아니다. 실제 채팅·모델 호출, 운영 배포/재시작/재생성은 이번에 수행하지 않았다.

## 아직 남는 운영 검증

1. 실제 재생성된 동일 이미지에서 고정 wheel을 복원하고 adapter/run_turn을 적용하는 경로는 이 시험 범위가 아니다. 새 이미지·다른 ABI를 허용하는 기능도 추가하지 않는다.
2. 실제 Docker stop/cp/start 실패, 기존 gateway 시작·Mattermost 재연결, 실제 새 컨테이너의 timer 감지는 별도 운영 조율 후 검증해야 한다. 그 전에는 운영 컨테이너를 유지한다.
3. Ansible/controller 강제 종료·호스트 전원 장애와 중간 상태 재개는 아직 검증하지 않았다. 현재 native rescue는 Ansible이 실패를 처리할 수 있을 때만 실행된다.
4. timer는 재생성 후 탐지와 유휴 대기가 있으므로 가드가 새 프로세스의 첫 응답보다 먼저 적용됨을 보장하지 않는다. 실제 시험에는 사용자 요청과 예약 작업이 실행될 수 있는 구간, 정지 시점의 DB/설정 백업, 원래 컨테이너·고정 이미지로 돌아갈 절차를 먼저 구체화해야 한다.

이 시험을 LLM에 패키지 설치·컨테이너 생성·임의 Ansible 실행 권한을 제공하는 경로로 연결하지 않는다. 운영 절차는 [고정 재적용 문서](hermes-guard.md)를 따른다.

## 재생성 준비 확인과 분리 cold 복원 — 04:34 KST 후속

읽기 점검에서 고정 이미지 `sha256:2fd023ef…27ea283`와 기존 컨테이너를 확인했다. 선언된 bind는 `/opt/hermes-data:/opt/data` 하나이며 `HERMES_HOME=/opt/data`다. `docker diff` 258경로는 guard 패키지23, Hermes 코드/상위 디렉터리8, `/etc`5, `/run`218, `/tmp`3, 루트1로 집계됐다. Hermes의 변경된 일반 코드 파일은 core·adapter·run_turn 세 개다. venv 변경은 보이지 않았다. `/etc` 계정 파일과 `/run`은 시작 시 계정 조정·프로세스 상태로 추정하며, 별도 `/tmp` 일반 파일1개는 원문을 열지 않아 업무상 필요 여부를 아직 확정하지 않았다. bind 밖의 변경을 모두 불필요하다고 판단한 것은 아니다.

현재 컨테이너에는 Compose labels가 없어서 Compose 파일 경로를 확인할 수 없다. 저장소의 `deploy_gateway_B.sh`는 직접 `docker run`을 사용한다. **이 과거 스크립트를 현재 서비스 재생성에 재실행하지 않는다.** `.env`·config·SOUL·cron을 수정하고 기존 컨테이너를 `rm -f`한 뒤 새 gateway를 즉시 시작하므로, 현재 데이터 보존과 시작 전 가드 적용 조건을 만족하지 않는다.

최초 root 백업 `/var/backups/hermes-korean-guard-cooj_d_2/original/`의 두 원본 SHA가 패처의 accepted SHA와 일치했다. [`hermes_guard_cold.py`](tests/hermes_guard_cold.py)로 이 두 파일만 임시 호스트 디렉터리에 복사해 순수 후보 생성·compile을 실행했고 현재 배포 목표 SHA 두 개를 다시 얻었다. 이어 기존 컨테이너의 `/tmp/capstone-guard-cold.*`에 원본 wheel을 반입해 새 임시 target으로 설치했다. `uv --no-config --offline`, `--no-deps --no-index --require-hashes --no-cache`, 전용 `HOME/TMPDIR/UV_CACHE_DIR`와 `UV_NO_CACHE=1`을 사용했다. cache 디렉터리가 만들어지지 않았음을 확인했다.

실제 UID995가 cold target의 `regex._regex` 확장을 읽었고, 고정 버전과 경로·한자/가나 양성8개·한국어/기호 음성5개 검사가 통과했다. 고정 운영 target을 우회해 production guard를 import한 것은 아니다. 운영 코드3개·regex tree·config/.env/SOUL의 해시와 컨테이너 ID/이미지/StartedAt가 전후 같았으며 호스트/컨테이너의 임시 target은 제거했다. 모델·MCP·채팅 호출은 0이다. [원본/후보/wheel 해시와 실제 결과](hermes-cold-readiness-2026-10-14.json)를 참조한다.

실제 재생성 전에는 다음 **시작 전 검사 절차를 별도로 구현·검토**해야 한다. 현재 timer나 running 컨테이너용 playbook만으로 충족했다고 볼 수 없다.

1. 현재 full inspect에 근거한 고정 image ID·entrypoint/cmd·UID/GID·bind·환경·네트워크·재시작 정책을 보존하는 운영자 전용 생성 명세를 준비한다. 이미지 tag 최신값을 당겨오지 않는다. 실제 생성은 별도 조율한다.
2. 새 컨테이너는 **created/stopped 상태**로 만들고, 먼저 그 안의 원본 adapter/run_turn SHA를 확인한다. 복원본과 이미지 내 원본의 일치는 그때 직접 재확인해야 한다. 검토한 core·패치2개·regex 전체 target을 시작 전에 복사하고 다시 읽어 SHA/파일 권한을 대조한다. `docker create`는 시작하지 않으며 `docker cp`는 정지된 컨테이너도 지원한다. [Docker create](https://docs.docker.com/reference/cli/docker/container/create/), [Docker cp](https://docs.docker.com/reference/cli/docker/container/cp/).
3. 검사 실패 시 새 gateway를 시작하지 않고 기존 컨테이너를 유지한다. 시작 직전 old/new ID 결속, 유휴/lease, 설정·DB의 일관된 정지 시점 백업과 복귀 방법을 확인한다. 같은 `/opt/data`에 두 gateway를 동시에 실행하지 않는다.
4. 이전 컨테이너를 바로 삭제하지 않고 복귀 가능한 상태로 남긴다. 새 gateway가 정상 DB 기록을 만든 뒤에는 옛 DB 바이트를 무조건 덮어쓰지 않는다. 시작 후 native import/연결·보호 설정·실행 상태를 확인하고 timer의 새 ID를 등록한다.

이 절차의 후보 복사와 첫 시작은 아직 수행하지 않았다. 5분 timer의 사후 적용을 기다리는 방식으로 첫 응답의 무가드 공백을 없앴다고 주장하지 않는다.
