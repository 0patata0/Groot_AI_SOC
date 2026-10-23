# Hermes 한국어 출력 검사

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../STATUS.md) · [실행 계획](../../PLAN.md).
> 현재 구성은 MCP6서버와 고정 진단25대상이다. 자연어 도구 선택·무근거 완료/SILENT 알림 보완의 실제 검증 상태는 STATUS 최상단을 따른다. 정확 후보 승인과 일반 sudo/Docker/임의 shell 금지는 유지한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

## 2026-10-15 최신 후속 — 첫 시작 전 설치와 실제 복귀 검증

[고정 B 운영자 prestart 경로](../automation/ansible/roles/hermes_prestart/README.md)에서 새 후보가 처음 실행되기 전에 가드 3파일·격리 regex를 설치하고 17개 파일을 다시 읽어 확인했다. 실제 후보 첫 시작·readiness를 통과한 뒤 고정 시험 실패를 주어 원래 컨테이너로 복귀했으며, 최종 `rolled-back/revision22`다. 원래 CID `6c2ed13aea89…`는 PID2248019로 운영 중이고 후보 `47aa31c88f9d…`는 정지 보존한다. 두 번째 전환이나 컨테이너 삭제는 하지 않았다.

후보와 복귀한 원본 각각 실제 UID995의 가짜 HTTP 11개, MCP5 initialize/tools-list, 새 heartbeat·DB 검사·보호 설정 확인을 통과했다. helper native64개 및 Ansible 구문 검사도 통과했으며 실행 release는 `/opt/capstone-automation/releases/hermes-prestart-20261015-f93793c125bf`다. [검증 기록](../automation/ansible/hermes-prestart-validation-2026-10-15.json)에 준비 단계 실패와 후속 성공을 함께 보존한다. 최종 readback SHA는 `eff330d8e97cab34ad8f489be69f4f57c9076786ffa0fbd3c055249ad7e0ac5e`, receipt SHA는 `38458901be81b3a3f02f6378ddedea3f43e6186fbdb2659747b6cf52180689f4`다. DB/WAL 과거 복원·강제 종료·tools/call·모델·채팅 호출은 없었다.

이는 고정 이미지·CID·plan을 검토한 root 경로에서 첫 실행 전 적용과 확인된 실패 후 복귀를 검증한 결과다. 일반 Docker 생성 전체에 적용되는 시작 차단이나 불확실 crash의 자동 재시도를 보장하지 않는다. 기존 timer의 탐지·유휴 대기 한계도 별도이며 LLM/MCP 권한은 확대하지 않았다. 아래의 과거 미실행·한계 문구는 해당 검증 당시의 기록으로 읽는다.

2026-10-13 사용자가 제공한 실제 답변의 `각 대상에 대해以下步骤이 필요합니다:` 혼입을 대상으로 작성했다. 기존 SOUL·cron의 한국어 지침만으로는 생성 결과를 강제할 수 없어 **Mattermost 전송 전 코드 검사**를 추가한다. 모델을 학습하거나 MCP 도구를 다시 실행하는 기능이 아니다. 실제 배포·검증 시각은 이 문서 아래와 [당일 기록](../../대화기록/2026-10-13.md)을 따른다.

**2026-10-15 구형 배포 경로 후속:** B의 실제 `deploy_hermes_B.sh` 사본을 SHA `6065fa7f…649460`으로 보완해 관리 상태가 있으면 `prep/test/all`을 변경 전에 exit78로 거절한다. 같은 바이트의 root0400 사본으로 확인했고 native41개·syntax·Ansible `ok28/changed5/failed0`을 통과했다. 기존 파일 UID/GID1000·0664, 적용 후 SHA와 운영 PID2248019를 유지했으며 컨테이너 변경은 없었다. 저장소 `deploy_gateway_B.sh`의 차단은 향후 복사본 보호이고 이번 B 운영 사본 배포는 아니다. 이는 해당 스크립트 경로의 보호이며 임의 Docker 명령이나 LLM 권한 전체를 통제하는 공통 시작 장치는 아니다.

## 처리 방식

문자 검출은 외부 [`regex` 패키지](https://pypi.org/project/regex/2026.9.29/)의 컴파일된 Unicode 속성 엔진을 사용한다. 직접 관리하던 코드 포인트 범위표는 제거했다. `Script=Han/Hiragana/Katakana`와 가나 공통 문자 중 Letter/Mark를 검사하므로 확장 한자·장음·반각 탁점도 패키지의 Unicode 데이터에 따라 처리한다. 한글·영문 식별자·공통 문장부호·emoji는 이 검사만으로 혼입으로 판정하지 않는다. 미할당 코드 포인트를 임의로 한자로 간주하지 않는다. 따라서 기존 넓은 범위표와 문자 단위 결과가 완전히 같지는 않다.

교정 여부, 검증된 인용 보존, 현재 요청의 외국어 출력 예외, 최종 전송 차단은 프로젝트 정책 연결 코드로 유지한다. 패키지는 문자 검사 엔진이며 한국어 문법·의미·번역 정확도 검사기는 아니다. Python 전체를 제거하거나, 단순히 표준 `re`에 새 이름만 붙인 변경으로 설명하지 않는다. [패키지의 Unicode 속성·집합 연산 지원](https://github.com/mrabarnett/mrab-regex)은 직접 범위표를 유지할 필요를 줄여준다.

1. 정상 한국어·영문 기술 식별자만 있는 응답은 그대로 통과하며 추가 API를 호출하지 않는다.
2. 제보된 위 문장은 `각 대상에 대해 다음 절차가 필요합니다:`로 정확히 치환한다.
3. 다른 설명의 한자·가나 혼입은 해당 조각만 한 번 번역한다. 기존 한국어, 숫자, 주소, 상태, 명령·식별자 등 나머지 문자는 서버 안에서 보존한다. 교정 API에는 외국어 조각 목록만 보내고, JSON 번역 배열을 받은 뒤 서버가 원래 위치에 끼워 넣는다. 보호 토큰을 모델이 다시 생성하게 하지 않는다. 원문 구조와 한국어 대체 부분을 검증한 뒤 복원한다.
4. 교정 실패·12초 초과·잘못된 토큰·여전한 혼입에는 **해당 줄만** `[응답의 일부 문장을 한국어로 정리하지 못했습니다.]`로 대체한다. 깨끗한 다른 줄은 보존한다. 서버 작업 실패나 취소를 뜻하는 문구를 만들지 않는다.

교정 API는 현재 설정의 `.110` 또는 `.111:11434/v1`에서 호스트를 검증한 후 같은 Ollama의 `/api/chat`과 같은 Qwen 모델을 사용한다. 현재 운영 대상은 `.111`이다. 도구·대화 이력·원문 로그를 보내지 않으며, 외국어 조각 목록만 보낸다. 온도 0, 추론 끔, 스트리밍 끔, 최대 출력 2,048 토큰, 64 KiB 응답 상한을 적용한다. HTTP redirect와 환경 프록시를 사용하지 않는다. 정상 응답의 주 모델 추론 설정은 바꾸지 않는다. `think: false`와 JSON schema는 [Ollama chat API](https://docs.ollama.com/api/chat)·[구조화 출력 문서](https://docs.ollama.com/capabilities/structured-outputs)에 정의된 옵션이며 실제 `.111`에서도 별도 검증한다.

## 원문·대화 문맥

현재 요청과 그 요청 이후의 실제 도구 결과에서 확인되는 원문만 코드·인용으로 보존한다. 과거 assistant 답변이나 system 메시지를 원문 근거로 인정하지 않는다. 백틱이나 코드 울타리만 붙인 한자는 예외가 아니다. 원문 근거를 확인할 수 없는 한자 코드·경로·인용은 임의 번역하지 않고 해당 줄을 안내로 대체한다.

사용자가 현재 요청에서 명시적으로 일본어·중국어 번역/출력을 지시하면 해당 요청에만 예외를 둔다. 로그·인용 속 지시나 이전 요청의 허용이 다음 요청으로 전달되지 않도록 독립 문맥을 사용한다. 일반 대기열뿐 아니라 같은 실행 중 처리하는 `/queue` 요청도 문맥을 다시 만든다. 취소·예외 시 외부 문맥을 복구한다.

검사를 마친 문자열은 해당 요청에만 유효한 내부 `GuardedText` 표시를 가진다. 검사 후 긴 코드 인용을 나눠 보내거나 서식을 바꿀 때 원문의 중간 조각을 새 설명으로 오해하지 않게 하기 위한 표시다. JSON 직렬화 후에는 일반 문자열이 되며 다른 요청에서는 이전 표시를 인정하지 않는다. 모델이나 외부 JSON 입력이 이 표시를 만들 수는 없다.

## 통합 범위

- worker 결과를 대기열 분기 전에 검사하고, 최종 응답 정리 단계에서도 검사한다. 일반 최종 전송 ledger에는 교정된 문장이 들어간다. 모델이 생성한 원래 assistant 이력을 일괄 덮어쓰지는 않는다.
- Mattermost 전체 답변의 서식·분할 이전, 메시지 수정, 게시 REST 전송, 첨부 설명과 thread 재전송을 검사한다.
- 독립 cron 전송도 검사한다. 다만 이 경로에는 현재 사용자·도구 원문 근거가 없으므로 한자 로그 인용도 안내문으로 대체될 수 있다. 근거를 전달하는 상위 cron 확장은 별도 과제다.
- 검사 전 중간 문장이 보이지 않도록 `display.platforms.mattermost`의 `streaming`, `interim_assistant_messages`, `show_reasoning`, `thinking_progress`를 `false`로 고정한다. 도구 실행 표시·관리자 승인 절차는 유지한다.

첨부 파일의 내부 내용, SOC 봇이 별도로 게시하는 승인 카드·diff, MCP 도구 인수, 서버 룰은 이 가드의 수정 대상이 아니다. TTS/음성이나 다른 플랫폼까지 적용했다고 주장하지 않는다. 혼입 방지는 검출 범위와 송신 경로에 대한 제어이며 모델의 모든 문장이 문법·사실 면에서 정확함을 보장하지 않는다. 외국어 조각 주변의 기존 한국어 조사는 그대로 남아 어색할 수 있다.

## 파일·검증·재적용

- [검사 모듈](korean_output_guard.py) · [오프라인 정책 회귀](test_korean_output_guard.py) · [실제 외부 엔진 회귀](test_korean_output_guard_engine.py)
- [고정 의존성](korean-output-guard-requirements.txt): CPython 3.13 Linux x86_64 wheel 하나의 버전·SHA-256을 고정한다. 다른 플랫폼·소스 빌드를 자동 허용하지 않는다.
- [버전 고정 소스 패처](patch_korean_output_guard.py): 확인한 `adapter.py`와 `gateway/run_turn.py`의 원본/정확한 패치 SHA만 허용한다. 다른 upstream에는 자동 적용하지 않는다.
- [B native Ansible 배포](../automation/ansible/hermes-guard.md): 검토한 이미지/소스·실제 UID 외부 엔진·유휴/heartbeat/lease를 확인한 뒤 Ansible이 백업·복사·중지·시작·rescue를 관리한다. 이미 같은 코드면 Hermes를 재시작하지 않는다. DB/설정·MCP 권한·승인 상태는 편집하지 않는다. 구 Python 배포기는 native 이관 후 삭제했다.
- [설치본 전송 경로 검증기](verify_korean_output_guard_runtime.py): 실제 설치 adapter를 가짜 HTTP로 실행한다. 채팅 게시·파일 업로드는 하지 않는다. `--model`은 합성 혼입 문장의 DGX 교정 API 호출만 추가한다.

패키지가 준비된 서버 격리 환경에서 회귀 검증한다. 맥에는 패키지를 설치하지 않는다.

```sh
python3 -B -m unittest discover -s infra/hermes -p 'test_korean_output_guard*.py' -v
```

B에서 재적용할 때 검토한 모듈과 패처를 담은 root 전용 bundle 디렉터리를 전달한다. 패키지는 검증한 wheel을 서버로 반입하고, 기존 컨테이너의 `/opt/capstone-guard-runtime/regex-2026.9.29/lib/python3.13/site-packages`에 운영자가 따로 준비한다. 전역 Hermes 의존성을 업그레이드하지 않는 격리 target이며 전체 Hermes 프로젝트를 새 환경에 복제하지 않는다. 디렉터리는 root 소유, 서비스 UID 읽기 가능, 서비스 UID 쓰기 불가로 유지한다. 설치에는 `uv --no-config pip install --python /opt/hermes/.venv/bin/python --target <고정 target> --no-deps --no-index --find-links <검토한 wheel 디렉터리> --only-binary=:all: --require-hashes --no-cache --link-mode=copy -r <고정 lock>`를 사용한다. `--no-config`는 이번 target 설치에서 Hermes `pyproject.toml`의 별도 의존성 제약을 읽지 않게 하는 옵션이며 기존 프로젝트 파일을 변경하지 않는다. 현재 운영 재적용은 위 native Ansible wrapper의 `check`/`apply`를 사용한다. Ansible은 외부 엔진 target이 없는 경우에만 원본 wheel의 같은 pin으로 복원한다. 과거 Python 배포기의 `--bundle`/`--apply` 경로는 이관 후 제거했다. 실행 전 실제 배포 대상 코드 버전과 유휴 상태를 확인한다.

가드는 고정 경로를 잠깐 import 검색 경로에 추가하며 `.pth` 파일을 실행하지 않는다. 정확한 패키지 버전, 컴파일된 `_regex` 확장, 고정 경로에서 읽은 엔진을 확인한다. 패키지가 없거나 버전·실행 위치가 다르면 이전 범위표로 조용히 돌아가지 않고 import를 실패시킨다. 배포기는 이 검사를 서비스 중지 전에 수행한다. Hermes가 이미 다른 `regex` 버전을 먼저 import한 경우에도 강제로 교체하지 않으며, 실제 gateway import 순서 검증이 필요하다.

설치 위치는 `/opt/hermes/capstone_korean_output_guard.py`와 기존 이미지 내부의 adapter/run_turn 두 파일이며, 외부 엔진은 `/opt/capstone-guard-runtime/regex-2026.9.29` 아래에 있다. 현재 컨테이너를 재시작해도 유지되지만 **컨테이너를 삭제·재생성하거나 이미지를 교체하면 외부 엔진 설치와 가드 통합을 모두 재적용해야 한다.** 아래 native 재적용 timer는 검토한 이미지/소스에 한해 이를 복원하며 탐지·유휴 대기 구간이 있다. 기존 컨테이너 구성 자체를 바꾸지 않은 선택에 따른 제약이다. 새 Python ABI/아키텍처에서는 wheel lock부터 재검토하고, Hermes 소스 해시가 다르면 소스 경로와 패처도 재검토해야 한다.

## 배포 결과

### 2026-10-14 native Ansible 재적용 운영 이관

[고정 Ansible 재적용 절차](../automation/ansible/hermes-guard.md)를 추가했다. core 정책은 유지하고 백업·복사·중지·시작·rescue 복구를 native task로 분리한다. `hermes_guard_checks.py`는 설정/DB/유휴 상태의 읽기 검사만, 기존 SHA 패처의 CLI는 후보 파일 생성만 담당한다. 기존 배포 Python은 새 timer에서 호출하지 않는다.

후보는 B 기존 controller에서 syntax와 `--check`를 통과한 뒤 운영에 적용했다. metadata observer는 02:57:21 KST 시작했고 timer/observer는 active/enabled다. 코드가 이미 같아 Hermes 재시작은 없었으며, 최종 반복 적용은 03:06:22 KST `changed=0`이었다. lock 경합은 75만 정상 유예로 분리했다. 설정/.env/SOUL/컨테이너 시작 시각은 유지됐고, 그 사이 cron 세션과 runtime 기록이 자연 증가한 것은 출처·시각으로 확인해 보존했다. 실제 UID 전송 검증 11개와 MCP 5개 initialize/tools-list가 통과했다.

timer 방식에는 재생성 후 탐지·유휴 대기 구간이 있고 부팅 전 강제 적용을 보장하지 않는다. 새 컨테이너 생성·image/entrypoint 변경과 장애 유발 rollback은 수행하지 않았다. 03:10:49 KST까지 짧은 metadata 관찰 4종 건수는 각각 0이지만 전체 응답 분모가 없으므로 혼입률로 계산하지 않는다. 상세 시각·한계는 위 절차와 검증 요약을 따른다. 현재 실행 경로에서 빠진 구 Python 배포기는 삭제하고, 순수 패처와 읽기/런타임 검증은 유지했다.

### 2026-10-14 외부 엔진 사전 검증

B 기존 Hermes 컨테이너의 CPython 3.13.5/x86_64에서 고정 wheel SHA를 확인하고 **regex 2026.9.29 한 개만** 격리 target에 설치했다. 기존 Hermes 환경에는 regex가 없었다. 첫 uv 시도는 프로젝트의 `pynacl` 제약과 `--require-hashes`가 충돌해 설치 전 중단됐다. 기존 제약 파일은 그대로 두고 `--no-config`를 추가한 재시도로 고정 패키지 설치를 완료했다.

- 실제 서비스 UID 995/GID 986에서 **회귀 51개 통과(0.206초)**. 기존 42개 정책/transport와 신규 9개 외부 엔진 회귀를 합한 결과다.
- 실제 gateway/base와 후보 모듈, 설치된 Mattermost adapter/run_turn import 성공. metadata는 `regex / 2026.9.29 / regex._regex / isolated_runtime`으로 확인했다.
- 후보를 메모리에 연결한 **가짜 HTTP 전송 경로 11개 통과**: 일반 전송, 수정, 첨부 설명, 직접 API, 긴 원문 인용 분할, thread 재시도, 이전 요청 예외 폐기, 교정 실패 차단, 독립 cron, 대기열 문맥 갱신, 패키지 엔진 검사. 실제 채팅 게시·파일 업로드 0건이며 이번 검사에서는 모델 API를 호출하지 않았다.
- 이후 실제 `.111` 모델의 합성 조각 교정을 포함한 `--model` 검사에서 **12개 모두 통과**했다. 한국어 교정과 기존 IP·`pending` 보존을 확인했으며 실제 채팅 게시·파일 업로드는 여전히 0건이다. 주 모델 설정은 바꾸지 않았다.
- 새 배포기 읽기 사전 확인도 통과했다. 최초 두 번은 heartbeat가 45초 기준보다 오래돼 변경 전에 중단됐고, 상태 파일을 수정하거나 기준을 완화하지 않은 채 실제 갱신(age 0.397초) 직후 재검사해 성공했다. 유휴/활성 lease, 패키지 import와 기존 소스 SHA를 확인했으며 설정 before/after SHA는 동일했다.
- 후보 core SHA: `a6b977d2c670ded98f61639a480702ed06d4a866b705e7d10705a056b974895c`.
- 이 사전 검증 시점의 운영 core는 아래 이전 SHA `5e8ac56d…47fc85` 그대로였다. **이 항목은 운영 코드 교체·재시작 완료 보고가 아니다.** 검사 후 컨테이너 임시 후보·wheel 사본은 제거했으며, 격리 설치 패키지는 다음 적용 단계용으로 유지했다. 맥에는 패키지를 설치하지 않았다.

### 2026-10-14 외부 엔진 운영 적용

**01:37:18 KST 적용 완료, 01:40:48 KST 최종 연결 확인 완료.** 새 heartbeat(age 0.517초), 유휴/활성 lease 조건을 그대로 확인한 뒤 기존 배포기로 적용했다. 컨테이너 `6c2ed13aea89`를 재생성하지 않고 Hermes만 01:37:16.547에 재시작했다. 다른 worker나 보안 서비스를 재시작하지 않았다.

- root 전용 변경 전 백업: B `/var/backups/hermes-korean-guard-x8nzjth6`. 이 백업은 이전 자체 범위표 가드를 복구하는 기준이며 완전 제거용 최초 백업과 구분한다.
- 운영 core SHA: `a6b977d2c670ded98f61639a480702ed06d4a866b705e7d10705a056b974895c`. 기존 adapter/run_turn SHA는 아래 10/13 값 그대로다.
- 설정 SHA는 전후 모두 `89ec0f90c2e421e67eed90bfc631eced42167efff1e0160cdeea91464b819d96`. `.111`·`qwen3.6:35b`, MCP 설정 5개/활성 설정 5개를 유지했다. 각 MCP의 실제 도구 호출을 새로 수행한 검증은 아니다.
- 대화 DB `quick_check=ok`, sessions 99개/messages 1,021개가 전후 동일했다. 배포기가 DB를 편집하지 않았고, 최종 gateway running/활성 agent 0/활성 작업 없음/OOM false를 확인했다.
- 설치된 운영 모듈을 실제 UID로 읽어 외부 엔진 provenance와 **12개 전송/모델 검사 모두 통과**했다. 실제 채팅 게시·파일 업로드는 0건이다.
- Mattermost 상태가 이번 재시작 이후인 `2026-10-13T16:37:27.885849+00:00`에 `connected`로 갱신됐다. 인증된 WebSocket 연결 문구는 `/opt/hermes-data/logs/gateway.log`에서 확인했다. `docker logs`만 검사한 최초 확인에서는 파일 로그를 찾지 못했으며 연결 실패로 단정하지 않고 상태/시각을 추가 대조했다.
- 컨테이너 임시 검증 파일은 정리했다. `/opt/capstone-guard-runtime/regex-2026.9.29`는 운영 의존성이므로 유지한다. 실제 사용자 채팅의 종단 간 왕복, 장기 혼입률, 강제 장애를 동반한 롤백 시험은 이번 검증 범위에 포함하지 않는다.

### 2026-10-13 이전 버전 운영 결과

아래 결과는 직접 범위표를 사용하던 이전 버전의 관측이다. 외부 엔진의 운영 적용 결과로 간주하지 않는다.

**2026-10-13 20:51 KST 최종 배포 완료, 20:52 검증 완료.** 기존 Hermes 컨테이너를 20:51:04.311에 재시작했고 20:51:15 Mattermost/WebSocket 연결·20:51:17 gateway running을 확인했다. 실제 `.111`·`qwen3.6:35b`, MCP 5개와 기존 timeout, 활성 agent/lease 0, OOM false, DB quick_check ok다.

- 로컬 한국어 회귀 **42개 통과**, 설치본 실제 UID에서 가짜 HTTP 전송과 실제 DGX 교정을 합친 **10개 검증 통과**. 실제 채팅 게시·파일 업로드는 0건이다. 사용자 채팅의 전체 왕복이나 장기 혼입률을 측정한 결과는 아니다.
- 최종 배포 전 합성 문장 2건은 정확히 교정됐고 0.909/0.536초였다. 이는 교정 전용 API 표본이며 정상 채팅의 응답 속도 보장이 아니다. 정상 답변은 교정 API를 호출하지 않는다.
- core SHA: `5e8ac56d71c8ab5dd925ea4737e9a6b0de0a2ebb7e5a3ec4f0ad35296847fc85`
- adapter SHA: `1bbe71e24cf7fd212f38b13cb421bb5b05c841ea4d70a061d6dcb57253e6c47b`
- run_turn SHA: `d4dae0f3194f7b7d435aac2eb37d4697822612cd6955911d86bb61400ad2871a`
- config SHA: `89ec0f90c2e421e67eed90bfc631eced42167efff1e0160cdeea91464b819d96`

최초 변경 전 백업은 B `/var/backups/hermes-korean-guard-cooj_d_2`이며 최종 교정 transport 변경 직전 백업은 `/var/backups/hermes-korean-guard-wxo6y5tx`다. 뒤 백업에는 1차 가드가 들어 있으므로 **완전 제거용 원본은 앞 백업**을 사용한다. 백업에는 설정 비밀 값이 포함될 수 있어 root 전용으로 유지하며 채팅·저장소에 복사하지 않는다. 기존 대화 DB는 배포기가 편집하지 않았다.

1차 OpenAI 호환 교정 호출은 12초 제한에 걸려 안전 안내를 반환했다. 이를 실제 API 시험에서 발견해 최종본은 native 추론 끔·JSON 배열 방식으로 교체했다. 이 실패를 지우지 않고 당일 기록에 남겼다. 실제 복구 장애를 유발한 롤백 시험이나 이후 사용자 실사용 장기 관찰까지 완료한 것은 아니다.
