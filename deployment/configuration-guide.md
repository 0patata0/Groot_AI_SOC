# 환경 값 입력과 단일 셸 실행

이 문서는 새 Ubuntu 24.04 amd64 서버 세 대의 사전 준비를 마친 뒤 수행한다. 명령마다 실행 위치를 표시했다. `192.0.2.0/24`는 문서용 예시이며 실제 할당 주소로 바꾼다. 기존 운영 A/B/C의 주소·비밀번호·등록 키를 복사하지 않는다.

먼저 [네트워크·SSH 준비](setup-network-ssh.md), [패키지·자료 준비](setup-packages-artifacts.md), [Hermes 이미지 준비](hermes-image.md)를 완료한다. 실제 입력 파일은 두 개다.

| 파일 | 작성 위치 | 내용 | 권한·보관 |
|---|---|---|---|
| `deployment/site.local.conf` | 관리 컴퓨터의 저장소 | 세 서버 주소, SSH, NIC, LLM, 포트 | 0600 권장, Git 제외 |
| `/opt/capstone-prereqs/siem.json` | siem 서버 | 초기 계정·암호, 준비한 Hermes 이미지 ID | root:root 0600, 서버에만 보관 |

`deploy.sh`는 전자를 읽고, siem 역할은 후자를 서버에서 직접 읽는다. SIEM 암호를 관리 컴퓨터 설정이나 명령 인수에 넣지 않는다.

## 1. 입력값 확정

다음 표를 먼저 채운다. 같은 서버에 여러 역할을 지정할 수 없다.

| 항목 | 예시 | 확인 방법 |
|---|---|---|
| security 주소 | `192.0.2.10` | 해당 서버 `ip -br -4 address` |
| siem 주소 | `192.0.2.20` | 해당 서버 `ip -br -4 address` |
| service 주소 | `192.0.2.30` | 해당 서버 `ip -br -4 address` |
| 공통 SSH 사용자·포트 | `capdeploy`, `22` | 세 서버 키 인증과 `sudo -n true` 성공 |
| security 감시 NIC | `ens192` 또는 `auto` | `ip -br link`, 미러링/경유 경로 확인 |
| LLM API | `http://192.0.2.40:11434/v1` | siem에서 아래 모델 목록 조회 |
| 모델 이름 | `qwen3.6:35b` | API가 반환한 정확한 모델 ID |
| backend/WAF 포트 | `80` / `8080` | 각 호스트에서 사용 가능한 포트 |

설치기가 입력받는 주소는 이미 서버 NIC에 할당된 주소다. 설치기는 OS IP·게이트웨이·DNS·SSH 포트를 변경하지 않는다. `MONITOR_INTERFACE=auto`는 SIEM으로 가는 경로의 NIC를 선택하므로 미러 전용 NIC를 쓰면 직접 지정한다. security→service의 출발지 주소는 `SECURITY_HOST`와 일치해야 한다.

### LLM 연결 확인 — siem 서버

이미 준비된 내부 LLM 서버를 사용한다. 이 절차는 모델 다운로드·학습·DGX 재설치를 하지 않는다. 아래 요청은 모델 목록 조회이며 응답 생성을 요청하지 않는다. [Ollama 공식 호환 API](https://docs.ollama.com/api/openai-compatibility)에 `/v1/models`가 정의돼 있다.

```bash
set -euo pipefail
llm_base_url=http://192.0.2.40:11434/v1
llm_model=qwen3.6:35b
curl --noproxy '*' --fail --silent --show-error \
  --connect-timeout 5 --max-time 20 "${llm_base_url%/}/models" |
  jq -er --arg model "$llm_model" '.data[] | select(.id == $model) | .id'
```

지정한 모델 ID가 한 줄로 나와야 한다. 연결 실패는 라우팅·리스너·접근 허용을 확인하고, 모델이 없으면 LLM 담당 환경에서 준비한다. 이름만 비슷한 다른 모델로 자동 대체하지 않는다. 현재 설치기는 별도 API 키를 요구하지 않는 내부 엔드포인트용이며 URL 안의 계정·토큰·쿼리를 거절한다. HTTPS라면 siem 및 Hermes 이미지에서 신뢰할 수 있는 인증서가 필요하다. `curl -k`로 우회하지 않는다.

## 2. 관리 컴퓨터 설정 작성

실행 위치: **프로젝트 저장소 루트, Bash**. 이미 있는 설정은 덮어쓰지 않는다.

```bash
set -euo pipefail
umask 077
test -f deploy.sh
test ! -e deployment/site.local.conf
cp deployment/config.example.conf deployment/site.local.conf
chmod 600 deployment/site.local.conf
```

텍스트 편집기로 `deployment/site.local.conf`를 수정한다. 기본 예시는 다음과 같다.

```ini
SECURITY_HOST=192.0.2.10
SIEM_HOST=192.0.2.20
SERVICE_HOST=192.0.2.30
SSH_USER=capdeploy
SSH_PORT=22
SSH_IDENTITY=/home/operator/.ssh/capstone_deploy
SSH_KNOWN_HOSTS=/home/operator/.ssh/known_hosts
MONITOR_INTERFACE=auto
WEB_BACKEND_PORT=80
WAF_PORT=8080
LLM_BASE_URL=http://192.0.2.40:11434/v1
LLM_MODEL=qwen3.6:35b
```

위 `/home/operator`는 예시다. Mac의 기존 키를 사용하는 경우 실제 `/Users/사용자명/...` 절대 경로를 넣는다. 키 파일을 새로 서버에 반입하는 것이 아니라 관리 컴퓨터가 기존 개인키로 인증한다.

| 키 | 의미·제약 |
|---|---|
| `SECURITY_HOST`, `SIEM_HOST`, `SERVICE_HOST` | 서로 다른 IPv4 리터럴. 호스트명·CIDR·SSH 사용자 접두사 금지 |
| `SSH_USER`, `SSH_PORT` | 세 서버 공통 값. 사용자 기본 `ubuntu`, 포트 기본22. 비기본 포트는 siem 내부 읽기 MCP SSH에도 반영 |
| `SSH_IDENTITY` | 개인키 절대 경로. 빈 값이면 기존 ssh-agent/기본 키 사용. 암호화 키는 미리 ssh-agent에 등록 |
| `SSH_KNOWN_HOSTS` | 콘솔 fingerprint와 대조한 키 파일의 절대 경로. 새 host key 자동 수락 없음 |
| `MONITOR_INTERFACE` | security의 감시 NIC 또는 `auto` |
| `WEB_BACKEND_PORT` | service의 DVWA·`/log4shell/` UI 게시 포트, 기본80. 22/1514/1515 예약 포트 금지 |
| `WAF_PORT` | security의 WAF 게시 포트, 기본8080 |
| `LLM_BASE_URL` | `http://호스트:포트/v1` 또는 신뢰된 HTTPS. API 키·쿼리 금지 |
| `LLM_MODEL` | 모델 API에서 확인한 정확한 ID. 대화형 기본값은 `qwen3.6:35b` |
| `SURICATA_IMAGE`, `WAF_IMAGE` | 생략 가능. 각각 `jasonish/suricata:latest`, `owasp/modsecurity-crs:nginx` 로컬 이미지 |
| `ET_RULES_FILE` | 생략 가능. security의 `/opt/capstone-prereqs/suricata.rules` 기본 |
| `DVWA_IMAGE`, `MARIADB_IMAGE` | 생략 가능. 각각 `ghcr.io/digininja/dvwa:latest`, `mariadb:10` 로컬 이미지 |
| `LOG4SHELL_IMAGE` | 생략하면 공식 고정 digest 이미지 사용. `registry/image@sha256:64자리` 또는 검토한 로컬 `sha256:64자리` image ID만 허용하며 태그는 거절. [수동 자료 준비](setup-packages-artifacts.md)를 따르며 실행 중 pull/build 없음 |

설정은 `KEY=value` 데이터다. `export`, 따옴표, 줄 끝 주석, `~`, `$HOME`, `$(...)`를 쓰지 않는다. 줄 맨 앞 `#`는 주석이며 LF 줄바꿈을 사용한다. 알 수 없는 키는 거절한다. `source deployment/site.local.conf`로 실행할 필요가 없다. Wazuh/Mattermost/PostgreSQL 버전과 `/opt/capstone` 경로는 이번 설치기에서 고정돼 있다.

## 3. SIEM 초기 계정 작성 — siem 서버 콘솔

먼저 [Hermes 수동 빌드](hermes-image.md)를 완료하고 실제 로컬 image ID를 확인한다. 이 ID는 비밀이 아니다.

```bash
set -euo pipefail
umask 077
sudo docker image inspect --format '{{.Id}}' capstone-hermes:guarded-20261015
sudo install -d -o root -g root -m 0700 /opt/capstone-prereqs
sudo test ! -e /opt/capstone-prereqs/siem.json
sudoedit /opt/capstone-prereqs/siem.json
```

파일이 이미 있으면 마지막 두 명령으로 초기화하지 말고 기존 준비 파일인지 먼저 확인한다. 편집기에 아래 JSON을 넣고 네 암호와 관리자 이메일, Hermes image ID를 바꾼다. 실제 암호를 채팅·셸 명령줄·Git에 복사하지 않는다.

```json
{
  "schema_version": 1,
  "wazuh_api_username": "wazuh-wui",
  "wazuh_api_password": "CHANGE_ME_NEW_API_PASSWORD",
  "indexer_username": "admin",
  "indexer_password": "CHANGE_ME_NEW_INDEXER_PASSWORD",
  "mattermost_admin_username": "socadmin",
  "mattermost_admin_email": "operator@example.org",
  "mattermost_admin_password": "CHANGE_ME_NEW_CHAT_PASSWORD",
  "postgres_password": "CHANGE_ME_NEW_DATABASE_PASSWORD",
  "hermes_image": "sha256:REPLACE_WITH_PREPARED_LOCAL_IMAGE_ID"
}
```

| 항목 | 설정 기준 |
|---|---|
| `schema_version` | 숫자1 |
| `wazuh_api_username` | 3~32자, 영문자로 시작. 영문/숫자/`.`/`_`/`-` 허용. 예시 `wazuh-wui` |
| `indexer_username` | `admin` 고정. Dashboard 로그인에도 사용 |
| `mattermost_admin_username` | 3~32자, 영문 소문자로 시작. 소문자/숫자/`.`/`_`/`-` 허용 |
| `mattermost_admin_email` | 운영자가 관리하는 이메일 형식. 이 설정만으로 SMTP가 구성되는 것은 아님 |
| 네 `*_password` | 각각 새 값, UTF-8 기준16~72바이트. `CHANGE_ME`와 제어문자 금지 |
| Wazuh API 암호 추가 조건 | 영문 대문자·소문자·숫자·특수문자 모두 포함 |
| `hermes_image` | 준비한 로컬 `sha256:64자리` 또는 검증된 `registry/image@sha256:64자리`. 태그만 지정 불가 |

JSON 특수문자 `"`와 `\`는 올바르게 이스케이프해야 한다. 아래 검사는 파일 내용을 출력하지 않는다.

```bash
set -euo pipefail
sudo chown root:root /opt/capstone-prereqs/siem.json
sudo chmod 600 /opt/capstone-prereqs/siem.json
sudo jq -e 'type == "object" and .schema_version == 1' \
  /opt/capstone-prereqs/siem.json >/dev/null
sudo stat -c '%U:%G %a %n' /opt/capstone-prereqs/siem.json
```

마지막 출력은 `root:root 600`이어야 한다. 위 `jq`는 JSON 구문·최상위 버전만 검사하며 필수 키·암호 조건·이미지 존재 여부는 다음 `--check`에서 검사한다. 추가 키와 중복 키도 설치기가 거절한다.

## 4. 계획과 전체 사전검사 — 관리 컴퓨터

저장소 전체를 동일 버전으로 사용한다. `deploy.sh`만 따로 복사하면 역할 파일과 규칙이 없어 실행할 수 없다.

```bash
bash deploy.sh --plan --batch --config deployment/site.local.conf
```

주소와 적용 순서가 의도와 같은지 확인한다. 이 단계는 SSH를 호출하지 않는다. 다음으로 세 호스트의 SSH·도구·입력 자료를 확인한다.

```bash
bash deploy.sh --check --batch --config deployment/site.local.conf
```

성공 기준은 종료 코드0과 `세 서버 사전검사 통과.`다. 초기 CA/등록 암호는 SIEM 설치 후 전달되므로 fresh security/service 검사에서 아직 없어도 된다. 패키지·이미지·주소·권한·등록된 기존 agent 문제는 해당 사전 준비로 돌아가 수정한다. 체크를 통과해도 실제 DB/API 초기화·Hermes 연결을 검증한 것은 아니다.

`--check`도 파일을 전송하기 위한 root 임시폴더를 원격에 만든 뒤 정리한다. 기존 설치가 있으면 상태/API 조회와 읽기 MCP 검증도 수행할 수 있다. 서비스 설치·채팅 게시·모델 추론은 요청하지 않는다.

## 5. 구성 적용 — 관리 컴퓨터

```bash
bash deploy.sh --apply --batch --config deployment/site.local.conf
```

실제 단계는 아래와 같다. 하나가 실패하면 후속 역할은 실행하지 않는다.

| 순서 | 수행 내용 | 결과 |
|---|---|---|
| 1 | 세 호스트 전체 사전검사, 서로 다른 machine-id 확인 | 역할 혼용·준비 누락 거절 |
| 2 | SIEM 준비 이미지 격리 검사, 새 CA/계정·Wazuh/Mattermost/MCP/Hermes 구성 | SIEM 서비스·읽기 MCP 검증 |
| 3 | SIEM의 등록 CA·암호를 SSH 파이프로 service/security에 전달 | 관리 컴퓨터에 암호 파일 저장 없음 |
| 4 | service의 DB/DVWA 초기화, 내부 Log4Shell·UI 구성, 웹 접근 제한, Wazuh 등록 | backend·UI·내부 lab·agent 검증 |
| 5 | security의 WAF/IDS 규칙·탐지 모드·별도 nft 테이블·Wazuh 등록 | 엔진·웹·agent 검증 |
| 6 | SIEM 최종 검증 | 구축 완료 주소 출력 |

자동 생성물은 `/opt/capstone/{siem,service,security}`와 소스 보존용 `/opt/capstone/releases/…`에 있다. 전달받은 CA/등록 파일은 각 서버 `/opt/capstone-prereqs/`에 남는다. 정상 설치의 필요한 운영 자료이므로 임시파일처럼 지우지 않는다. 임시 전송 폴더는 `/var/tmp/capstone-bootstrap-…`이며 설치기가 종료 시 정리한다.

Log4Shell UI 접속 주소는 `http://SECURITY_HOST:WAF_PORT/log4shell/`이며 기본 예시는 `http://192.0.2.10:8080/log4shell/`다. DVWA Apache/PHP에 읽기 전용 UI 파일을 추가하고 private lab 네트워크의 `http://log4shell:8080/`만 요청한다. Log4Shell 앱은 호스트 포트를 게시하지 않으므로 service:8080이나 새 방화벽 허용 규칙을 만들지 않는다. 기존 운영망 `http://192.168.16.230/log4shell/`은 기존 A:80 경로이며 신규 환경의 WAF 기본8080과 구분한다.

UI는 정상 헤더 HTTP200·헤더 누락 HTTP400, 응답 시간·본문, 최근20개 브라우저 기록의 KST 표시를 제공한다. 기본 구성은 직접 공격이나 LDAP 콜백을 실행하지 않으며, UI 응답 성공이 WAF/Suricata/Wazuh 탐지 E2E 성공을 뜻하지 않는다. 자세한 정상 동작 시험은 [검증 절차](verify-troubleshoot.md)를 따른다.

### 대화형 실행

기본 SSH22·기본 포트·기본 모델을 사용할 때는 다음 한 명령으로 실행할 수 있다.

```bash
bash deploy.sh
```

질문 순서는 **security 주소 → siem 주소 → service 주소 → 공통 SSH 사용자 → 개인키 경로 → 감시 NIC → LLM API 주소**다. SSH 포트·모델·웹 포트는 대화형 질문에 없으므로 다른 값을 쓰려면 앞의 설정 파일 방식을 사용한다. 대화형 명령도 사전검사 후 실제 구성을 적용한다.

## 6. 재검증과 운영 인계

```bash
bash deploy.sh --verify --batch --config deployment/site.local.conf
```

성공 기준은 종료 코드0과 `세 역할 검증 완료.`다. 최초 로그인, 서비스별 확인, 모델 응답 시험, 장애 진단은 [검증·장애 대응](verify-troubleshoot.md)을 따른다. 설치기가 검사한 범위와 실제 보안 경보 전달·모델 응답 시험을 각각 기록한다.

검증 중에는 처음 쓴 이미지 ID·규칙·입력·스크립트가 유지돼야 한다. image pull, 소스 업데이트, 입력 변경 뒤에는 같은 설치를 그대로 재검증하지 못할 수 있다. `changed_inputs`·`profile_changed`·부분 설치 오류를 없애려고 manifest/receipt나 DB 볼륨을 지우지 않는다. 소스 커밋·로컬 설정·준비 자료를 보존하고 의도한 변경을 별도 이관 작업으로 처리한다.

Log4Shell·UI를 포함한 service의 `input.json`과 `manifest.json`은 **schema2**다. 기존 DVWA/DB만 구성했던 service의 schema1을 자동 업그레이드하지 않으며 재실행하면 입력/manifest 불일치로 거절한다. 기존 service는 데이터·계정·agent 등록을 보존하는 별도 이관이 필요하다. 이 service 상태 버전과 SIEM 준비 파일 `siem.json`의 `schema_version: 1`은 서로 다른 형식이므로 혼동해 수정하지 않는다.

사전검사 실패는 원인을 고친 뒤 재실행할 수 있다. 적용 시작 후 실패했다면 [부분 실패 처리](verify-troubleshoot.md)의 상태 확인부터 수행한다. 새 VM 세 대에서 실제 설치가 성공했다는 검증은 이 문서 작성 시 아직 하지 않았다.
