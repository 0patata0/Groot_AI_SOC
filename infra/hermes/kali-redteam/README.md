# Kali 레드팀 Hermes

Kali232·233에 Hermes Agent `v0.23.2`를 사용자 계정으로 설치하고 지정한 DGX111의40B 모델을 `qwen3.8-40b-heretic:hermes-64k` 태그로 연결한다. 공격·시나리오 시험은 중단 상태다. 설치 완료나 모델 응답 확인은 시험 재개를 뜻하지 않는다. 역할과 조사·재현·피드백 방법은 [SOUL.md](SOUL.md)에 둔다.

고정 원본은 [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent/tree/ae2a81ccc00e9b7c06301523e5bb09608397149c)의 `ae2a81ccc00e9b7c06301523e5bb09608397149c`다. [반입 목록](offline-inputs.json)은 Linux x86_64용 wheel102개와 도구 아카이브8개의 URL·버전·크기·SHA256, 원본 archive와 lock3개의 SHA를 포함한다. 모델 가중치·자격 파일·운영 봇 설정을 묶음에 넣지 않는다.

## 오프라인 반입

송신 컴퓨터에서는 기존 Git·curl·Python만 사용한다. 패키지를 설치하거나 Linux 바이너리를 실행하지 않는다. 작업별 임시 폴더에 공식 소스와 반입 파일을 준비한다. 아래 `SOURCE`는 고정 commit의 깨끗한 공식 체크아웃이고 `TASK`는 작업별 임시 폴더다.

```bash
./deploy.sh --kali-hermes --prepare-bundle \
  --source "$SOURCE" --artifacts "$TASK/artifacts" \
  --output "$TASK/bundle.tar" --download
```

이 명령은 고정 목록의 파일만 내려받아 SHA와 크기를 검증하고 `git archive`로 만든 원본을 대조한다. 이미 검수한 반입 파일이 있으면 `--download`를 생략한다. 출력의 bundle SHA256을 전송 후 다시 대조한다. 묶음과 설치기 `deployment/kali_hermes.py`는 호스트 키를 고정한 기존 SSH 경로로 각 Kali의 작업 폴더에 전달한다. HTTP 프록시나 터널로 Kali의 인터넷 다운로드를 대신하지 않는다.

Kali에 프로젝트 소스를 함께 반입했다면 루트 설치 진입점은 다음과 같다. `BUNDLE`과 `SHA256`은 전달한 묶음의 경로와 실제 해시다.

```bash
./deploy.sh --kali-hermes --install \
  --offline-bundle "$BUNDLE" --sha256 "$SHA256"
```

이번처럼 설치기와 검수된 묶음만 전달하는 경우에도 같은 Python 모듈을 실행한다. 일반 계정·Kali Linux·x86_64를 확인하며 sudo, apt, 인터넷 fallback을 사용하지 않는다. 기존 설치·런처가 있으면 덮어쓰지 않는다.

```bash
python3 -B kali_hermes.py --install \
  --offline-bundle "$BUNDLE" --sha256 "$SHA256"
```

설치기는 입력 archive의 경로·중복·링크·크기와 모든 파일 SHA를 검사한다. 공식 PM의 wheelhouse 설치와 native assembler를 사용하고 Python 의존성은 `--offline --no-index --only-binary`로 설치한다. 공식 `all` extra를 선택하며 음성·메신저 등 모든 선택 기능을 설치한 것으로 표시하지 않는다. TUI·웹 UI frontend는 빌드하지 않는다.

## 모델과 역할 설정

`API_BASE`는 지정한 DGX의 OpenAI 호환 `/v1` 주소다. API 모델 목록에 있는 이름만 설정한다. 실제 `/api/show`의 기본 `num_ctx`는32768이고 GGUF의 최대값은262144다. Hermes가 요구하는 최소64000을 충족하도록 클라이언트의 context와 Ollama 요청값은65536으로 지정한다. OpenAI 호환 API가 요청의 context 옵션을 반영하지 않는 것을 실제 `/api/ps`에서 확인했다. [Ollama 공식 절차](https://docs.ollama.com/api/openai-compatibility#setting-the-local-context-size)에 따라 같은40B 가중치에 `num_ctx=65536`을 지정한 전용 태그를 추가한다. 응답 후 `/api/ps`의 실제 창 크기를 별도로 대조한다. 기존 모델의 태그·가중치·전역 설정은 보존한다.

관리자231에서 다음 명령으로 서버 측 태그를 준비한다. 원본 digest가 달라졌거나 이미 있는 태그의 가중치·설정이 다르면 덮어쓰지 않는다. 새 태그는 원본의 가중치 blob·template·system·모델 메타데이터와 다른 파라미터를 보존하며 출처 표시는 원본 모델 이름으로 바뀐다. 반입·양자화·가중치 다운로드와 서비스 재시작은 하지 않는다.

```bash
./deploy.sh --kali-hermes --ensure-model-context \
  --api-base-url "$API_BASE" \
  --source-model qwen3.8-40b-heretic:latest \
  --source-digest ed6fa9293f89e68614dff3c83e85934ef50efd7903a71cdc38b24dc45bbb0813 \
  --model qwen3.8-40b-heretic:hermes-64k --context-length 65536
```

다음은 각 Kali에서 실행한다.

```bash
./deploy.sh --kali-hermes --list-models --api-base-url "$API_BASE"
./deploy.sh --kali-hermes --configure \
  --api-base-url "$API_BASE" --model qwen3.8-40b-heretic:hermes-64k \
  --context-length 65536 --soul-template infra/hermes/kali-redteam/SOUL.md \
  --agent-id redteam-kali232 --kali-address 192.168.16.232
./deploy.sh --kali-hermes --verify
```

233에서는 식별자와 주소의 마지막 값을 함께233으로 바꾼다. 설정 전 config와 SOUL은 사용자 데이터 폴더의 `backups/capstone-redteam-*`에 보관한다. Hermes가 읽는 공식 파일명은 대문자 `~/.hermes/SOUL.md`다. 실제 템플릿의 두 자리표시자를 호스트별로 치환하고 원문 전체 로드를 확인한다. 동적 패키지 설치는 `security.allow_lazy_installs=false`로 둔다. SOUL 문구는 도구 권한이나 승인 정책을 대신하지 않는다.

## 설치 결과와 복구

| 위치 | 용도 |
| --- | --- |
| `~/.local/bin/hermes` | CLI 런처 |
| `~/.local/share/capstone-hermes/v0.23.2/` | source·Python·venv·PM runtime·도구와 manifest |
| 같은 폴더의 `offline-inputs.json`·`capstone-install.json` | 반입 파일과 설치 영수증 |
| 같은 폴더의 `uv-cache/` | 설치된 PM이 오프라인에서 사용할 운영 캐시 |
| `~/.hermes/config.yaml`·`SOUL.md` | 모델 설정·레드팀 역할 |
| `~/.hermes/redteam/reports/` | 프로젝트 원장에 합칠 분석·시험 보고서 |

설치 실패 시 성공 영수증이나 런처를 만들지 않는다. 실패 원인과 프로세스 종료를 확인한 뒤 이번 작업이 만든 부분 설치만 구별해 복구한다. 사용자 데이터와 운영 runtime·필요한 오프라인 캐시를 임시 반입 파일과 함께 지우지 않는다. 모델·역할 설정은 해당 변경 전 백업으로 복구할 수 있다. 기존 설치가 없었던 호스트의 설치 제거는 사용자 데이터 보존 범위를 정한 별도 작업으로 처리한다.

최종 검증 뒤 송신 컴퓨터의 작업별 다운로드·공식 소스 체크아웃·압축파일과 Kali의 반입 staging을 정리한다. 고정 목록·SHA·출처·설치 영수증은 남긴다. 설치·CLI·SOUL 로드·모델 응답과 실제 공격·탐지·대응 E2E는 각각 기록한다. [검증 결과](validation.json)를 현재 상태의 근거로 사용한다.
