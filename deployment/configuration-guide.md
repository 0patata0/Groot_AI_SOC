# 환경 값 입력과 단일 셸 실행

새 Ubuntu 24.04 amd64 서버 3대의 진입점은 저장소 루트의 `deploy.sh` 하나다. 현재 service 상태는 **schema7**, security 상태는 **schema2**다. 기존 운영 A/B/C를 새 설치 대상으로 인수하지 않는다. **새 VM 3대에서 전체 `--apply`를 실제 실행한 검증은 아직 하지 않았다.**

[네트워크·SSH 준비](setup-network-ssh.md), [오프라인 반입·설치 흐름](bootstrap-guide.md), [Hermes 이미지 준비](hermes-image.md)를 먼저 확인한다. 예시 `192.0.2.0/24`는 문서용이며 실제 할당 주소로 바꾼다. 설치기는 IP·라우팅·DNS·SSH를 자동 변경하지 않는다.

| 입력 | 위치 | 내용·권한 |
|---|---|---|
| `deployment/site.local.conf` | 관리 컴퓨터 저장소 | 주소·SSH·LLM·`LAB_*` 설정. 로컬 전용0600 권장, 비밀번호 금지 |
| `/opt/capstone-prereqs/artifacts.json` 및 명시된 파일 | 서버마다 | 역할별 승인된 `.deb`·Docker save archive의 버전·SHA·ID. root 소유, group/world 쓰기 금지 |
| `/opt/capstone-prereqs/siem.json` | SIEM | 초기 계정·암호·Hermes image ID. root:root0600 |
| wheel 디렉터리·카탈로그·sudo bundle | service | 아래 `LAB_WHEEL_DIR`, `LAB_MANIFEST`, `LAB_SUDO_BUNDLE` |
| TLS 인증서·개인키 | security | `LAB_PUBLIC_ORIGIN` 이름과 맞는 인증서. 개인키 root:root0600 |

반입 manifest의 해시는 관리자가 승인한 파일의 동일성을 확인한다. 공급자 서명 검증은 별도 준비 단계의 책임이며, sudo bundle은 자체 고정 pin·서명 체인을 추가 검사한다. Mac에 패키지를 설치하지 않으며 controller는 반입 바이너리를 자동 다운로드하지 않는다.

## 1. 입력값 확정

| 항목 | 예시 | 확인 방법 |
|---|---|---|
| security / siem / service | `192.0.2.10` / `.20` / `.30` | 서로 다른 VM·machine-id와 NIC 주소 |
| 공통 SSH 사용자·포트 | `capdeploy`, `22` | host key 대조, 키 인증과 `sudo -n true` |
| security 감시 NIC | `ens192` 또는 `auto` | 미러링/경유 경로. auto는 SIEM 방향 NIC 선택 |
| LLM API·모델 | `http://192.0.2.40:11434/v1`, `qwen3.6:35b` | SIEM에서 실제 모델 목록 조회 |
| 추가 보호 IP | `LOG_PROTECTED_IPS=192.0.2.50,192.0.2.60` | 관리·VPN 등 차단에서 제외할 IPv4. 세 서버·literal LLM은 자동 포함, hostname LLM은 IP 명시 필수 |
| 관리자 IP/대역 차단 예외(선택) | `ADMIN_PROTECTED_CIDRS=192.168.10.25,192.168.15.0/24` | 초기 prompt에서 Enter 또는 빈 설정이면 추가 예외 없음. IP는 /32, 대역은 네트워크 주소로 정규화 |
| DVWA backend / WAF 포트 | `80` / `8080` | 해당 서버에서 포트가 비어 있는지 |
| Lab HTTPS origin | `https://lab.example.org` | DNS/hosts→security, 인증서 SAN·유효기간·클라이언트 신뢰 |
| Lab 허용 CIDR | `192.168.10.0/24` | 실제 실습 클라이언트 내부망/VPN 출발지 |
| Lab 프록시 subnet | `172.30.247.0/29` | 호스트 route·Docker network·허용 CIDR과 겹치지 않는 사설 /29 |

security→service의 실제 출발지 주소는 `SECURITY_HOST`와 일치해야 한다. HTTPS 포트를 바꾸면 origin의 포트도 같게 지정한다. 인증서 발급·DNS/hosts 구성은 사전 작업이며, 설치기가 준비된 인증서를 검증·배치한다.

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

저장소 루트에서 기존 파일을 덮어쓰지 않고 예제를 복사한다.

```bash
umask 077
test ! -e deployment/site.local.conf
cp deployment/config.example.conf deployment/site.local.conf
chmod 600 deployment/site.local.conf
```

텍스트 편집기에서 실제 값으로 바꾼다. 다음 경로 중 SSH 키·known_hosts만 관리 컴퓨터의 경로이며, `LAB_*` 반입 경로는 대상 서버의 경로다.

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
LAB_PUBLIC_ORIGIN=https://lab.example.org
LAB_HTTPS_PORT=443
LAB_ALLOWED_CIDRS=192.168.10.0/24
LAB_PROXY_SUBNET=172.30.247.0/29
LAB_GATEWAY_PORT=18091
LAB_WHEEL_DIR=/opt/capstone-prereqs/wheels
LAB_MANIFEST=/opt/capstone-prereqs/cve_list.json
LAB_SUDO_BUNDLE=/opt/capstone-prereqs/sudo
LAB_TLS_CERT=/opt/capstone-prereqs/lab-tls.crt
LAB_TLS_KEY=/opt/capstone-prereqs/lab-tls.key
LLM_BASE_URL=http://192.0.2.40:11434/v1
LLM_MODEL=qwen3.6:35b
```

| 설정 | 의미·제약 |
|---|---|
| `SECURITY_HOST`, `SIEM_HOST`, `SERVICE_HOST` | 서로 다른 사용 가능한 IPv4 리터럴. 호스트명·CIDR 금지 |
| `SSH_USER`, `SSH_PORT` | 세 서버 공통. 기본 ubuntu/22. 비기본 SSH 포트는 내부 읽기 MCP에도 반영 |
| `SSH_IDENTITY`, `SSH_KNOWN_HOSTS` | 관리 컴퓨터의 실제 경로. 빈 identity는 기존 ssh-agent/기본키 사용. host key 자동 수락 없음 |
| `MONITOR_INTERFACE` | security 감시 NIC 또는 auto |
| `WEB_BACKEND_PORT`, `WAF_PORT` | 독립 DVWA의 service/backend와 security/WAF 포트. Lab HTTPS와 별개 |
| `LAB_PUBLIC_ORIGIN`, `LAB_HTTPS_PORT` | 필수 HTTPS DNS origin과 같은 포트. path·사용자정보·query 금지. 기본443은 origin에 생략 |
| `LAB_ALLOWED_CIDRS` | 쉼표로 구분한 1~32개 고유 RFC1918 IPv4 CIDR. `0.0.0.0/0` 불가 |
| `LAB_PROXY_SUBNET` | security 전용 프록시의 사설 /29. 호스트 route·기존 Docker·클라이언트 CIDR과 충돌 금지 |
| `LAB_GATEWAY_PORT` | service 내부 gateway 포트, 기본18091. security와 service loopback만 허용하며 사용자 공개 주소가 아님 |
| `LAB_WHEEL_DIR` | service의 Python3.12 amd64용 전체 고정 wheel 목록. 설치기는 인터넷 대신 이 입력으로 콘솔 환경 준비 |
| `LAB_MANIFEST` | service의 고정 4항목 카탈로그. Java/Apache2개는 정확한 로컬 image ID, sudo는 local-cli 상태 항목 |
| `LAB_SUDO_BUNDLE` | service의 [고정 sudo bundle](../infra/groot-c/offline-labs/nonweb/sudo/runtime/BOOTSTRAP.md). 10파일+manifest와 서명 증빙 필수 |
| `LAB_TLS_CERT`, `LAB_TLS_KEY` | security의 준비된 인증서/개인키. `/opt/…` 절대 경로. 실제 hostname·키 일치·유효기간 검증 |
| `LLM_BASE_URL`, `LLM_MODEL` | 내부 `/v1` API와 실제 모델 ID. URL 안의 자격·query 금지 |
| `SURICATA_IMAGE`, `WAF_IMAGE`, `DVWA_IMAGE`, `MARIADB_IMAGE` | 선택 로컬 이미지 참조. 반입된 ID·플랫폼·역할 계약을 검사하며 pull하지 않음 |
| `ET_RULES_FILE` | 선택 security 룰 경로. 기본 `/opt/capstone-prereqs/suricata.rules` |

`LAB_ADMIN_KEY_FILE`은 controller의 고정 전달 경로이며 설정 파일의 입력 키가 아니다. `LAB_ADMIN_KEY`나 비밀번호 값도 넣지 않는다. 구형 `LOG4SHELL_IMAGE`, `LOG4SHELL_APP_JAR`, `LOG4SHELL_HOSTNAME`은 더 이상 쓰지 않으며 값이 있으면 거절한다. schema7은 준비된 관리형 이미지로 실행하고 초기 설치 중 Java JAR를 빌드·마운트하지 않는다.

설정은 LF의 `KEY=value` 데이터다. `export`, 따옴표, 줄 끝 주석, 변수 확장, `~`, 명령 치환을 넣지 않는다. 맨 앞 `#`만 주석이며 알 수 없는 키는 거절한다. 파일을 shell `source`로 실행하지 않는다. 설정 파일에 정의한 경로를 controller가 서버로 업로드하는 것은 아니다.

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
| `indexer_username` | `admin` 고정. Dashboard 로그인과 실습 차단 예외 키의 공통 계정 |
| `mattermost_admin_username` | 3~32자, 영문 소문자로 시작. 소문자/숫자/`.`/`_`/`-` 허용 |
| `mattermost_admin_email` | 운영자가 관리하는 이메일 형식. 이 설정만으로 SMTP가 구성되는 것은 아님 |
| 네 `*_password` | 각각 새 값, UTF-8 기준16~72바이트. `CHANGE_ME`와 제어문자 금지 |
| Indexer 암호 추가 조건 | Lab 예외 키와 공통 사용하므로 8자 이상. 원문을 로컬 설정 파일에 넣지 않음 |
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

## 4. 계획·사전검사·적용

저장소 전체와 로컬 설정을 함께 사용한다. `deploy.sh`만 복사해서 실행할 수 없다.

```bash
bash deploy.sh --plan --batch --config deployment/site.local.conf
bash deploy.sh --check --batch --config deployment/site.local.conf
# 준비가 끝난 새 환경에 실제 적용
bash deploy.sh --apply --batch --config deployment/site.local.conf
```

| 모드 | 동작·성공 범위 |
|---|---|
| `--plan` | 로컬 입력·주소·순서 출력, SSH 없음 |
| `--check` | 세 서버 반입물과 역할 사전조건 검사. 패키지·이미지·서비스 설치 없음. 빈 서버의 누락 도구는 실패할 수 있음 |
| `--apply` | 아래 단계별 설치와 검증. 실패 시 다음 단계 중단, 앞 단계의 변경을 자동 롤백하지 않음 |
| `--verify` | 완료된 동일 프로필의 파일·이미지·서비스·API·권한 경계를 재검증. 설치나 컨테이너 재생성 없음 |

`--check` 성공은 종료 코드0과 `세 서버 사전검사 통과.`다. SSH 전송을 위한 root 임시폴더는 만들고 종료 시 정리한다. 역할에 따라 격리된 일회성 이미지 구문검사나 기존 서비스 읽기 검증을 할 수 있지만 실습 공격·채팅·모델 추론은 수행하지 않는다.

적용 순서는 다음과 같다.

1. 세 호스트의 SSH·machine-id와 각 `artifacts.json`/SHA를 모두 검사한다.
2. 각 서버의 승인된 로컬 deb를 `apt-get --no-download --no-remove`로 설치하고 이미지 archive를 load한다. 목록 외 패키지·다운그레이드·기존 다른 이미지 태그를 거절한다. 그 다음 세 역할의 사전검사를 수행한다.
3. SIEM을 구성·검증한 뒤 등록 CA·암호를 security/service로 SSH 파이프 전달한다.
4. Dashboard `admin`의 `indexer_password`를 service의 `/opt/capstone-prereqs/lab-admin.key` root:root0600에 직접 전달한다. Mac 디스크·명령 인수·로그에 저장하지 않는다.
5. service에 콘솔·broker·nft guard와 별도 sudo rootless 환경을 설치하고, 독립 DVWA/MariaDB·gateway·Wazuh agent를 구성·검증한다.
6. security에 Suricata IDS·DVWA WAF와 별도 Lab TLS 진입점/실습 WAF 정책을 설치·검증한다. SIEM을 다시 검증하고 주소를 출력한다.

운영 파일은 `/opt/capstone/{siem,service,security}`, 소스는 `/opt/capstone/releases/<SHA>`에 보존한다. 콘솔은 `/opt/capstone-offline-labs`, 상태는 `/var/lib/capstone-offline-labs`, sudo 설치 상태는 `/var/lib/capstone-sudo-bootstrap`를 사용한다. 반입된 CA·자격·TLS·운영 복구 archive를 작업 임시파일과 혼동해 지우지 않는다.

### 접속과 공통 예외 키

- DVWA는 기존 독립 경로 `http://SECURITY_HOST:WAF_PORT/dvwa/`다. Lab Console 카탈로그에 넣지 않는다.
- 콘솔은 `LAB_PUBLIC_ORIGIN/log4shell/`, Java는 `/log4shell/labs/CVE-2021-44228/`, Apache 실습은 동일 origin의 해당 CVE 경로다.
- 정상 무키 요청과 웹 실습 실행·중지는 허용된다. WAF 규칙에 걸린 요청을 차단하며, 키가 없다는 이유만으로 모든 요청을 차단하지 않는다.
- 선택 예외 키는 Dashboard `admin` 암호와 같다. 브라우저가 30초·1회용 challenge를 HMAC 서명해 보내며 원문·고정 키 해시를 보내지 않는다. 성공 시 별도 HttpOnly 세션 쿠키가600초 유지된다. 같은 브라우저 탭 사이에 공유되며 키 자체가 쿠키에 들어가는 것은 아니다.
- 관리·인증 API는 Lab WAF를 우회하고 고정된 실제 실습 경로만 WAF를 지난다. 예외는 해당 WAF 차단에만 적용되며 Suricata·기존 IP 차단·보호 주소·LLM 승인/TTL 정책을 해제하지 않는다.
- sudo는 관리자 전용 CLI 환경의 상태만 표시한다. `ready`도 환경/패키지 검증이며 실제 권한상승·host auditd 시나리오 성공을 뜻하지 않는다.

기본 설치는 웹 실습3개 이미지만 준비하며 자동 기동하지 않는다. 콘솔에서 선택해 실행한 뒤 같은 HTTPS 링크로 접속한다. SSH 포트포워딩은 일반 접속의 필수 절차가 아니다. 추가 CVE는 이미지·카탈로그뿐 아니라 제한된 same-origin 라우트 계약도 별도로 준비해야 한다.

### 대화형 실행

```bash
bash deploy.sh
```

설정 파일 없이 터미널에서 실행할 때 질문 순서는 **security 주소 → siem 주소 → service 주소 → 공통 SSH 사용자 → 개인키 경로 → 감시 NIC → Lab HTTPS origin → 허용 내부망/VPN CIDR → LLM API 주소**다. 기본 동작은 실제 `--apply`다. SSH/HTTPS 포트·모델·인증서/번들 경로 등 질문에 없는 값을 바꾸려면 설정 파일을 쓴다. 대화형 실행도 사전 반입물·인증서·자격 JSON을 요구한다.

## 5. 재검증과 운영 인계

```bash
bash deploy.sh --verify --batch --config deployment/site.local.conf
```

종료 코드0과 `세 역할 검증 완료.`를 확인한 뒤 [검증·장애 대응](verify-troubleshoot.md)에 따라 허용 클라이언트 HTTPS·로그인·정상 웹 요청과 관리자 봇 질의를 별도로 확인한다. server TLS probe의403은 클라이언트 ACL에 의한 결과일 수 있어 외부 허용 클라이언트 검증을 대신하지 않는다.

완료된 동일 프로필의 `--apply`는 재검증만 수행한다. service schema1~6, security schema1, 기존 수동 설치를 숫자만 바꿔 이관하지 않는다. SIEM 준비 `siem.json`의 `schema_version: 1`은 별도 입력 형식이므로 바꾸지 않는다. 이미지·룰·주소·키·소스 변경은 별도 검토가 필요하며 `changed_inputs`, 부분 설치, 파일 해시 오류를 없애려고 manifest·receipt·DB 볼륨을 삭제하지 않는다.

현재 확인한 코드/모의 회귀 및 기존 C sudo 번들의 실제 정적 서명 검증은 **새 VM 3대 전체 설치 성공과 별개**다. 새 환경의 `--apply`, `--verify`, 허용 클라이언트 접속을 실제 수행한 뒤 해당 범위만 인수 기록에 남긴다.
