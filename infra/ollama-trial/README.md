# B 호스트의 Ollama 기반 읽기 시험 실행부

모델 추론은 기존 DGX Ollama에 두고, B에 `mcp-use 1.7.1` + `langchain-ollama 1.1.0` + 공식 Ollama Python SDK `0.6.3`을 별도 Python 3.12 venv로 설치한다. 이 구성은 **Ollama 클라이언트를 사용하는 에이전트 실행부**다. B에 Ollama 추론 daemon/CLI·모델 가중치를 설치하는 구성은 아니다. 실제 비교 결과와 현재 Git/검증 상태는 [STATUS](../../STATUS.md)를 따른다.

`B soc-ollama → DGX /api/chat → B의 MCP 호출 → DGX 최종 답변` 순서로 실행한다. host 프로세스여서 추가 Docker NIC가 없고 기존 Hermes와 직렬로 연결하지 않는다. 기존 운영 채팅·기억·사건 관리·승인 경로는 계속 Hermes가 맡는다. 별도 `ollama` 봇은 읽기 시험 채널/DM만 담당한다. 두 라이브러리 환경의 MCP 버전(시험1.30/운영2.0)은 서로 섞지 않는다.

## 권한과 범위

- `soc-ollama`: nologin·자체 그룹만, sudo/Docker 권한 없음. 코드는 root 소유이며 계정이 수정할 수 없다. venv는 패키지 분리이며 OS sandbox는 아니다.
- rule-a/b 각4개, security-events2개, system-diagnostics2개, wazuh-ro14개: **5서버·26읽기 도구**를 제공한다. write 서버와 응답 서버는 키/목록에서 제외한다. 기존 resp의 읽기1개도 해당 키에 보호 도구가 함께 있어 제외했다.
- ruleview의 기존 읽기 전용 키를 복사하고, B MCP에는 새 강제 명령 SSH 키를 등록한다. host key 검증·포워딩 금지를 유지한다. 일반 관리자/대응 키를 복사하지 않는다.
- MCP 도구 이름을 서버별로 구분하고 원본 JSON Schema·대상 A/B·호출 예산을 검사한다. 도구 실패를 정상으로 바꾸지 않는다. 실제 보호 호출/채팅 게시 기능은 없다.
- 기본 모델 단계5회(허용1~6), 도구8회(허용1~12), 도구90초·대화180초 제한. 모델 추론 off, temperature0, top_p0.95, 출력2048토큰. 외부 telemetry/tracing은 비활성화한다.
- 자동 사건 소비·정확 승인·기존 Memory/근거 검사 이관은 포함하지 않는다. 별도 채팅 gateway는 처리 상태를 SQLite에 기록하고 Mattermost의 최근 대화를 문맥으로 사용한다. 명시적 ISO 시각은 KST로 표시하지만 프롬프트/시각 변환만으로 사실 정확성을 보장하지 않는다.

## 오프라인 반입과 초기 설치

신규 설치의 유일한 진입점은 루트 [deploy.sh](../../deploy.sh)다. [설정 예제](../../deployment/config.example.conf)의 `OLLAMA_TRIAL_ENABLE=1`, `OLLAMA_TRIAL_BUNDLE=/opt/capstone-prereqs/ollama-trial`을 지정한다. 기본값0이면 실행하지 않는다. `--check`는 B 반입물을 검증하고 `--apply`는 SOC/진단 연결 뒤 내부 설치기를 호출한다. `--verify`는 실제 읽기 목록 발견까지 검사하며 모델 생성/채팅 게시를 수행하지 않는다. `OLLAMA_TRIAL_CHAT_ENABLE=1`을 함께 지정하면 봇/채널과 비특권 systemd gateway도 설치한다. 기본값0이며 기존 Hermes 채널 ID를 유지해 soc-hermes로 이름을 맞춘다. 새 3VM 전체 설치 시험은 별도 미검증이다.

반입 파일은 [offline-manifest.json](offline-manifest.json)의 정확한 파일명·버전·출처·크기·SHA-256을 사용한다. Linux CPython3.12 x86_64 wheel70개와 아래 deb3개다. B의 기존 Python 버전과 deb 의존성을 먼저 대조해야 하며 다른 Ubuntu/Python으로 그대로 확장하지 않는다.

| deb | 반입 버전 |
| --- | --- |
| python3.12-venv | 3.12.3-1ubuntu0.17 |
| python3-pip-whl | 24.0+dfsg-1ubuntu1.3 |
| python3-setuptools-whl | 68.1.2-2ubuntu1.2 |

```text
/opt/capstone-prereqs/ollama-trial/
  offline-manifest.json
  debs/       # 정확한 manifest의 deb3개
  wheels/     # 정확한 manifest의 wheel70개
```

root 소유·그룹/기타 쓰기 금지로 반입한다. 설치기는 추가 파일·symlink·해시 불일치를 거절한다. `dpkg -i`와 `pip --no-index --require-hashes --no-compile`만 사용하며 서버에서 다운로드하지 않는다. [requirements.lock](requirements.lock)은 전체 전이 의존성을 고정한다. manifest 동일성 검사는 공식 공급자 확인을 대신하지 않는다. 공식 Ubuntu 패키지 정보 및 PyPI 버전별 파일 해시와 대조한 출처를 manifest에 기록했다.

기존 운영 B에는 전체 초기 설치기를 실행하지 않고 관리자가 동일 [내부 구현](../../deployment/ollama_trial.py)의 제한된 증분 설치를 사용했다. 설치 receipt가 있으면 재설치하지 않고 검증한다. 부분 설치는 자동 덮어쓰지 않고 검토를 요구한다. 운영 B의 bundle에는 재현·복구용 `source/`도 보존한다. Mac에는 패키지를 설치하지 않으며 반입·검증 후 이번 다운로드/임시 생성물만 삭제한다.

## 실행

관리자가 B에서 호출한다. wrapper가 비특권 계정으로 낮춘 뒤 실행하며 JSON 결과는 stdout, 라이브러리 로그는 stderr에 기록한다. 질문을 보낸다고 Mattermost에 게시되지는 않는다.

```bash
sudo /usr/local/sbin/capstone-ollama-trial <<'JSON'
{"question":"현재 IDS 상태를 실제 조회하고 개별 SID 적재 확인 여부를 구분해줘.","tools":["mcp__rule_a__get_service_action_target","mcp__rule_b__get_service_action_target"]}
JSON
```

`tools`를 생략하면26개 읽기를 노출한다. 비교 시험에서는 두 실행부에 동일한5개를 노출했다. `{"discover_only":true}`는 모델을 호출하지 않고5서버26도구의 이름/스키마를 확인한다. `calls`에 실제 인자·결과·소요시간, `model_calls`에 생성시간/토큰과 Ollama native 메타데이터, `final_response`에 최종 답변이 나온다. 상세 결과에는 운영 데이터가 있으므로 로컬 전용 검증 기록으로 보관한다.

## 비교 방법과 한계

[hermes_benchmark.py](hermes_benchmark.py)는 기존 Hermes 이미지의 SDK를 새 임시 HERMES_HOME에서 사용한다. 현재 라이브 UID995·DGX 주소·모델에 맞춘 운영자 시험 어댑터이며 범용 실행 진입점이 아니다. 일반 채널 gateway와 운영 Memory/플러그인/DB를 사용하지 않는다. 두 실행부에 같은 한국어 시스템 지시·질문·5개 읽기 도구·모델·출력/추론 옵션을 적용하고 매회 새 대화로 시험한다. 실행 순서를 교대하며 모델 unload나 DGX 설정 변경을 하지 않는다.

시간 계산·IDS 상태·장비별 파일 룰 집계를 각각 반복하고, 생성 완료 여부와 별개로 인자·실제 조회값·KST·파일/엔진 구분을 검토한다. 모델 cold-load 예비 시험과 계측 코드 실패는 별도 기록한다. 프로그램 시작/연결을 포함한 전체 시간과 준비된 대화 처리 시간을 구분한다. Hermes는 전체 API 단계(스트림 소비 포함), 후보는 LangChain 완료 callback과 native duration을 기록한다. 내부 시간 범위가 완전히 같지는 않으므로 전체/대화 wall time을 비교 기준으로 사용한다.

이 결과는 **두 읽기 SDK 구성의 비교**이며 현재 운영 채팅 최종 게시 시간, 다중 사용자 부하, 동일 전체 기능의 우열을 뜻하지 않는다. 보호 변경/정확 승인·TTL, 관리 controller, Memory 유효성, KST/근거 검사, Mattermost 게시·재시도·영속 세션의 동등성은 후속 과제다.

## Mattermost에서 직접 시험

현재 봇 이름은 `ollama`, 채널은 [soc-ollama](https://chat.grootlab.duckdns.org/soc/channels/soc-ollama)다. 기존 `soc-agent`는 ID·이력을 유지한 [soc-hermes](https://chat.grootlab.duckdns.org/soc/channels/soc-hermes)로 변경했다. 새 채널은 기존 관리자와 Ollama 봇만 참여하는 비공개 채널이며 Hermes는 참여하지 않는다. 멘션 없이 질문하고 같은 스레드에서 후속 질문을 이어간다. `ollama`와의 DM도 사용할 수 있다. 현재 관리자 ID만 허용하며 다른 봇·시스템 글·이전 글·다른 채널 요청은 실행하지 않는다.

`capstone-ollama-chat.service`가 같은 host venv의 [chat.py](chat.py)를 soc-ollama 계정으로 실행한다. 기존 B Mattermost의 호스트 바인딩 주소8065에 HTTP/WebSocket으로 연결하며 새 수신 포트/NIC는 없다. 설치기는 관리자 자격을 보내기 전에 주소가 이 호스트에 할당된 IP인지 검사한다. 봇 토큰은 root 소유0640 설정에서만 읽으며 모델/로그/Git에 전달하지 않는다. 시스템 관리자 역할이나 전체 채널 게시 권한을 주지 않는다. ProtectSystem=strict·NoNewPrivileges·전용 상태 경로 쓰기와1GiB 메모리/128task 제한을 적용한다.

새 요청에는 같은 스레드의 처리 중 답변 하나를 만들고 완료 결과로 갱신한다. 답변 하단에 KST·처리시간을 표시한다. 스레드 또는 DM의 최근10개/8,000자 내 문맥만 사용하고 현재 상태는 다시 조회하도록 지시한다. 새 채널 스레드는 이전 스레드와 섞지 않는다. 전체26읽기를 노출하므로 아래5도구 SDK 비교 수치와 실제 채팅 시간이 같다고 단정하지 않는다.

중복 이벤트는 SQLite로 제거하고 모델 완료 결과를 저장한 뒤 전달을 재시도한다. WebSocket 재연결 시 소속 채널/DM의 최근60글을 확인한다. 장시간 단절로60글을 넘는 이력과 신규 DM 재발견의 모든 경우를 보장하지 않는다. POST 응답이 불명확하면 스레드의 원본 요청 ID를 대조하며 무조건 재게시하지 않는다. 불명확한 요청은 로그 확인 후 새로 질문할 수 있다. 그룹 DM·첨부/이미지 분석·메시지 수정에 따른 자동 재생성·전체 세션 이관은 범위 밖이다.

연결 검사 `chat.py --check`는 봇 신원·채널·WebSocket hello만 확인하며 게시/모델 요청0이다. 실제 게시 왕복은 사용자 직접 질문으로 별도 확인한다. [공식 봇 계정](https://docs.mattermost.com/developers/integrate/reference/bot-accounts) · [WebSocket API](https://docs.mattermost.com/api/reference/mattermost-api).

## 중지·복구

CLI 자체는 상주하지 않는다. 채팅을 켠 경우 관리자가 `systemctl disable --now capstone-ollama-chat.service`로 새 요청 처리를 중지할 수 있다. 기존 Hermes는 계속 사용한다. 봇 제거 시 정확한 chat receipt의 토큰을 폐기하고 해당 봇만 비활성화한다. 채널/대화 이력을 임의 삭제하지 않는다. 채널 이름을 복구하려면 같은 기존 채널 ID의 이름만 soc-agent로 변경한다. unit·chat 설정/소스를 제거한 뒤 daemon-reload하며 전용 SQLite 기록은 보존/제거 여부를 따로 결정한다. 완전 제거 시 관리자는 실행 중인 시험이 없음을 확인하고 receipt의 `registered_public_key`와 정확히 일치하는 **이번 키 한 줄만** B MCP authorized_keys에서 제거한다. `authorized_keys.before` 전체 복원으로 이후 정상 키를 덮어쓰면 안 된다.

이후 시험 wrapper, `/opt/capstone-ollama-trial`, `/etc/capstone-ollama-trial`, 전용 STATE/계정과 선택적 복구 bundle을 해당 경로만 검토하여 정리한다. 기존 ruleview 키 등록·Hermes·MCP 서비스는 삭제하지 않는다. deb3개는 다른 프로그램이 사용할 수 있으므로 자동 제거하지 않는다. 제거 절차의 실제 실행은 아직 검증하지 않았다.

## 검증

```bash
python3 -B -m unittest discover -s infra/ollama-trial -p 'test_*.py'
python3 -B -m unittest discover -s deployment/tests -p 'test_controller.py'
```

정책/반입물/JSON 출력 검사와 배포 분기 검사는 실제 신규 서버 설치를 대신하지 않는다. 실제 운영 설치·MCP 호출·자연어 비교·보류 범위를 [STATUS](../../STATUS.md)에 구분한다.
