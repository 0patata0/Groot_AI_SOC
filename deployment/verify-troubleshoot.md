# 설치 후 접속·검증·장애 진단

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 사용자 진입점은 루트 deploy.sh 하나이고 service schema9·HTTP3/터미널3·MCP6서버/고정 진단을 연결한다. 새3VM 전체 설치 시험은 사용자 제외 범위를 유지하며 기존 운영 서버를 초기 설치기로 덮어쓰지 않는다. 이번 운영 보완은 별도 최소 이관이다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

이 문서는 [README](../README.md)의 단일 설치기로 **새 환경**을 구성한 뒤 사용하는 절차입니다. 경로와 성공 판정은 `deploy.sh`와 `deployment/roles/{security,siem,service}.sh`의 구현을 기준으로 작성했습니다. 기존 운영 서버의 이름·계정·경로와 혼용하지 않습니다. **새 Ubuntu VM 세 대에서의 실제 통합 구축 검증은 아직 수행하지 않았습니다.** 아래 명령은 운영자가 해당 환경에서 실행할 검증 절차이며, 이미 확인된 라이브 결과를 뜻하지 않습니다.

예시 주소 `192.0.2.10`은 security, `.20`은 siem, `.30`은 service입니다. 실제 배포 때 입력한 주소·포트로 바꿉니다. 서버 명령은 명시된 서버의 SSH 터미널에서 실행하고, 관리 컴퓨터 명령은 저장소 루트에서 실행합니다. 로그·설정에는 자격증명이 포함될 수 있으므로 전체 파일을 채팅이나 Git에 붙이지 않습니다.

## 1. 완료 여부부터 확인

관리 컴퓨터에서 설치 때 사용한 소스와 로컬 설정으로 실행합니다.

```bash
bash deploy.sh --verify --batch --config deployment/site.local.conf
```

성공 조건은 명령 종료 코드 `0`과 마지막 `세 역할 검증 완료.`입니다. 단순히 컨테이너가 만들어졌거나 `--check`가 통과한 것은 설치 완료가 아닙니다. `--verify`도 SSH 임시 전송 폴더를 만들고 정리하지만 서비스 설정을 재적용하지 않습니다.

| 확인 단계 | 확인하는 범위 | 확인하지 않는 범위 |
|---|---|---|
| `--plan` | 로컬 입력값, 주소·형식 검사 | SSH, 서버 패키지, 서비스 상태 |
| `--check` | 세 서버 artifacts manifest·해시와 역할별 도구·이미지·TLS·wheel·sudo bundle 조건. 일회성 격리 이미지 검사 가능 | 패키지 설치·이미지 load·신규 서비스 구성·전체 연결 |
| `--apply`의 최종 성공 | 세 서버 반입물 검사→오프라인 패키지/이미지 설치→역할 사전검사→SIEM→공통 키/등록 자격 전달→service→security 및 아래 검증 | 외부 브라우저 접근, 공격 시나리오, LLM 답변의 정확성·지연 |
| `--verify` | SIEM API/TLS·Indexer·Mattermost·읽기 MCP·Hermes, service schema9의 DB/콘솔/broker/gateway/sudo·Redis/Samba 터미널 서비스·agent, security schema2의 TLS/WAF/IDS·agent·nft 상태 | 신규 모델 요청, 채팅 메시지 전송, 실제 공격 탐지·운영 보존 정책 |

SIEM 검증은 MCP 두 개의 도구 목록과 `get_wazuh_agents` 읽기 호출, Mattermost 봇 인증, 60초 이내 Hermes heartbeat를 확인합니다. `model_requests_sent: 0`, `chat_messages_sent: 0`, `write_approval_configured: false`는 초기 설치 범위에 맞는 결과입니다. service는 독립 DVWA/DB, 6항목 카탈로그·고정 웹이미지3개·터미널3개, 별도 rootless sudo와 agent를 검사합니다. security는 `waf_mode: DetectionOnly`(DVWA), `lab_waf_mode: enforce_or_signed_session_exempt`(실습), `suricata_mode: IDS`를 구분합니다. 자동 IP 차단·Vector 설치는 포함하지 않습니다.

`--check`는 패키지를 설치하지 않으므로 빈 서버에서 도구 누락으로 실패할 수 있습니다. `--apply`는 먼저 승인된 로컬 deb·이미지를 설치한 뒤 역할 검사를 합니다. 이때 역할 사전검사가 실패해도 앞서 설치한 OS 패키지는 자동 롤백되지 않습니다.

## 2. 최초 로그인

| 서비스 | 접속 주소 | 최초 계정·암호의 출처 |
|---|---|---|
| Wazuh Dashboard | `https://192.0.2.20/` | 사용자 `admin`; SIEM의 `/opt/capstone-prereqs/siem.json` 중 `indexer_password` |
| Mattermost | `http://192.0.2.20:8065/` | 같은 JSON의 `mattermost_admin_username` / `mattermost_admin_password` |
| DVWA, 독립 WAF 경유 | `http://192.0.2.10:8080/dvwa/` | 사용자 `admin`; service의 `/opt/capstone/service/credentials/admin-password` |
| Lab Console | `https://lab.example.org/log4shell/` | 무키 실습 가능. 선택 차단 예외 키는 Dashboard `admin` 암호와 같음 |
| Java 실습 | `https://lab.example.org/log4shell/labs/CVE-2021-44228/` | 콘솔에서 실행 후 같은 HTTPS 경로 사용. CSRF 세션은 앱이 별도로 관리 |
| Hermes | 별도 웹 로그인 없음 | Mattermost의 `capstone` 팀 → `soc` 채널에서 봇 멘션 |

Dashboard 로그인 암호는 Wazuh API용 `wazuh_api_password`와 다릅니다. `kibanaserver`는 Dashboard의 내부 연결용 계정이므로 관리자 로그인에 사용하지 않습니다. 계정 역할은 [Wazuh 공식 암호 관리 문서](https://documentation.wazuh.com/current/user-manual/user-administration/password-management.html)를 참고합니다.

Dashboard에 로그인한 뒤 에이전트 목록에서 `capstone-security`, `capstone-service`의 연결 상태를 확인합니다. 새 환경에서 탐지 경보가 아직 없거나 보안 이벤트 조회가 빈 결과를 반환하는 것은 가능한 상태입니다. 독립 DVWA WAF는 `RelevantOnly`로 기록하므로 정상 로그인 페이지 GET마다 WAF 경보가 생기는 것은 아닙니다. 실습 WAF의 검사/감사 경로와 구분합니다. 에이전트 연결, 로그 파일 생성, 경보 생성, 색인 표시를 각각 구분하며 실제 탐지 시나리오 시험은 별도 수행합니다.

### 필요한 암호 한 개만 확인

아래 명령은 **해당 서버에서 관리자가 직접 실행**합니다. 암호를 한 번 터미널에 표시하므로 화면 공유·터미널 녹화·`script`/`tee` 기록을 사용하지 않는 개인 세션에서 조회합니다. 셸 명령에는 암호 값 자체를 넣지 않으며, 출력은 대화기록·보고서에 복사하지 않습니다.

```bash
# SIEM: 먼저 사용자 이름만 확인
sudo python3 -B -c 'import json; d=json.load(open("/opt/capstone-prereqs/siem.json")); print(d["mattermost_admin_username"])'

# SIEM: Dashboard 암호 한 개
sudo python3 -B -c 'import json; print(json.load(open("/opt/capstone-prereqs/siem.json"))["indexer_password"])'

# SIEM: Mattermost 암호 한 개
sudo python3 -B -c 'import json; print(json.load(open("/opt/capstone-prereqs/siem.json"))["mattermost_admin_password"])'

# service: DVWA 관리자 암호 한 개
sudo cat /opt/capstone/service/credentials/admin-password
```

`siem.json`, `app-credentials.json`, `.env`, Compose의 환경변수 전체를 출력하지 않습니다. 봇 토큰·등록 암호·SSH 개인키는 최초 웹 로그인에 필요하지 않습니다. 사전 파일의 암호 문자열만 고치면 실행 중인 계정 암호가 바뀌는 것은 아니며, 설치 프로필 비교도 실패합니다. 암호 변경은 연결 계정과 애플리케이션을 함께 변경하는 별도 운영 작업으로 처리합니다.

### Dashboard 사설 CA 신뢰

설치기는 자체 사설 CA와 **입력한 SIEM IP가 SAN에 포함된 인증서**를 만듭니다. `https://192.0.2.20/`처럼 설치한 IP로 접속합니다. 나중에 임의 DNS 이름을 붙여 접속하면 CA를 신뢰해도 이름 불일치가 발생할 수 있습니다.

1. SIEM 콘솔에서 공개 CA fingerprint를 확인합니다.

   ```bash
   sudo openssl x509 -in /opt/capstone/exports/wazuh-enrollment-ca.pem \
     -noout -subject -fingerprint -sha256
   ```

2. 관리 컴퓨터에서 이미 host key를 검증한 SSH를 통해 **공개 CA만** 임시 폴더로 받습니다. SSH 포트·키가 기본값이 아니라면 설치 때와 동일한 옵션을 추가합니다.

   ```bash
   ca_work=$(mktemp -d)
   ssh -o BatchMode=yes -o StrictHostKeyChecking=yes capdeploy@192.0.2.20 \
     'sudo -n cat /opt/capstone/exports/wazuh-enrollment-ca.pem' > "$ca_work/capstone-root-ca.crt"
   openssl x509 -in "$ca_work/capstone-root-ca.crt" -noout -subject -fingerprint -sha256
   ```

3. 별도로 확인한 콘솔 fingerprint와 완전히 같은지 대조합니다. 일치한 CA만 관리자 브라우저/OS의 신뢰 저장소로 가져옵니다. Mac은 키체인 접근에서 인증서를 가져와 SSL 신뢰를 설정할 수 있습니다. UI는 OS 버전에 따라 다르므로 [Apple 공식 안내](https://support.apple.com/guide/keychain-access/change-the-trust-settings-of-a-certificate-kyca11871/mac)를 따릅니다. 브라우저가 자체 인증서 저장소를 사용하면 해당 저장소에도 정책에 맞게 등록합니다.
4. 브라우저를 다시 열어 Dashboard의 인증서 오류가 사라지는지 확인한 뒤 다운로드 파일을 지웁니다.

   ```bash
   rm -- "$ca_work/capstone-root-ca.crt"
   rmdir -- "$ca_work"
   unset ca_work
   ```

CA 신뢰 등록은 관리자가 선택한 클라이언트의 의도적인 설정이며 패키지 설치가 아닙니다. 이 문서 작업에서 Mac 신뢰 저장소를 변경한 것은 아닙니다. `/opt/capstone/siem/tls/root-ca-key.pem`을 비롯한 개인키는 외부로 복사하지 않습니다. 원인 확인을 위해 `curl -k`나 브라우저 인증서 검사 해제를 상시 설정하지 않습니다.

### Mattermost와 Hermes 첫 사용

Mattermost 관리자 계정은 설치 중 생성됩니다. 최초 화면에서 새 계정을 다시 만들지 말고 기존 사용자 로그인을 선택합니다. 팀 URL은 `http://192.0.2.20:8065/capstone/channels/soc`입니다. 팀은 `Capstone SOC`, 채널 표시명은 `SOC`, 봇 이름은 `capstone-assistant`입니다.

관리자가 직접 다음과 같이 한 번 요청하여 **모델 응답까지** 별도로 시험합니다.

```text
@capstone-assistant 현재 연결된 Wazuh 에이전트 이름과 상태만 확인해줘. 비밀값과 로그 본문은 제외해줘.
```

이 시험은 LLM 요청과 채팅 기록을 실제로 생성합니다. 정상 기준은 같은 스레드의 한국어 답변, 실제 조회한 결과/조회 한계의 표시, 비밀값 비노출입니다. 초기 구성은 **설치 관리자 한 명 + 지정 SOC 채널 + 멘션**만 허용합니다. 다른 사용자·다른 채널·멘션 없는 메시지에 답하지 않는 것은 초기 정책상 정상입니다. 사용자 추가나 정책 변경은 별도 검토가 필요합니다.

현재 연결된 MCP는 Wazuh 조회와 Suricata/ModSecurity 경보 조회 두 개입니다. 룰 수정·sudo·Docker 조작·승인 카드·정기 보고는 이 설치기에 포함되지 않습니다. Mattermost의 HTTP 접속 성공은 공인 인증서/모바일 푸시 구성이 끝났다는 의미도 아닙니다.

### DVWA 첫 사용

WAF 주소로 로그인하고 기본 보안 수준이 `impossible`인지 확인합니다. 설치기가 DB와 계정을 이미 초기화하므로 `Setup / Reset DB`를 다시 실행하지 않습니다. 일반 관리 컴퓨터에서 `http://192.0.2.30/`에 직접 접근하면 Apache ACL의 `403`이 기대값입니다. 실제 네트워크 방화벽이 먼저 제한하는 환경에서는 연결 자체가 제한될 수도 있습니다. 실습을 위해 보안 수준을 낮추는 것은 별도 실습 작업이며 초기 구축 확인에 필요하지 않습니다.

### Lab Console·Java·선택 예외 키 첫 사용

**허용된 내부망/VPN 클라이언트 브라우저**에서 `LAB_PUBLIC_ORIGIN/log4shell/`를 엽니다. 예시는 `https://lab.example.org/log4shell/`입니다. DNS/hosts는 security를 가리키고 인증서가 해당 이름과 일치해야 합니다. 옛 `LOG4SHELL_HOSTNAME`·HTTP 직접 Java 경로는 신규 설정이 아닙니다.

1. 키 없이 카탈로그6개와 상태가 보이는지 확인합니다. 웹3개·터미널3개는 `not_deployed` 또는 `stopped`여도 설치 상태로 정상일 수 있습니다. 이미지 존재와 `deployment_allowed=true`를 확인합니다. sudo도 실습 환경 시작 → 환경 열기로 연결하며, 기존 UID1991 rootless 환경과 고정 컨테이너 UID1000을 사용합니다. sudo 터미널은 전체 사용자 중 한 연결만 허용하고 연결 종료·유휴/수명 만료 때 해당 sudo 컨테이너 전체를 중지합니다.
2. Java 항목을 선택해 실행합니다. 이는 관리자 또는 사용자가 요청한 **실제 컨테이너 기동**입니다. `running`을 확인하고 화면의 같은 HTTPS 링크를 엽니다. 로컬 포트18081을 클라이언트 컴퓨터의 localhost로 오해하지 않으며 SSH 터널이 필수는 아닙니다.
3. Java·Log4j API/core2.14.1 표시를 확인하고 `capstone-spring-verification` 같은 무해한 메시지 한 건을 기록합니다. HTTP200·요청 ID·시각을 확인하되 CSRF 값·쿠키를 작업 기록에 복사하지 않습니다. Apache 두 버전은 각각 CVE-2021-41773/42013의 같은 origin 링크와 버전·정상 공개 파일만 확인합니다.
4. 필요한 경우 `차단 예외 키 (선택)`에 Wazuh Dashboard `admin` 암호를 직접 입력합니다. 브라우저 WebCrypto가 30초·1회용 challenge에 HMAC 서명하며, 키 원문이나 고정 키 해시를 서버에 보내지 않습니다. 검증 후 입력/참조를 비우지만 완전한 메모리 삭제를 보장하는 기능은 아닙니다.
5. 예외 적용 후 `관리자 실습 · 탐지만 기록`, 만료 시각을 확인합니다. 별도 HttpOnly 쿠키는600초 유효하며 같은 브라우저 탭 사이에 공유됩니다. `예외 해제` 후 일반 모드로 돌아오는지 확인합니다. 키·proof·쿠키를 개발자 도구나 로그에서 복사하지 않습니다.
6. DVWA를 기존 독립 주소로 다시 열어 로그인 페이지가 유지되는지 확인합니다. DVWA는 콘솔 카탈로그와 예외 세션 적용 대상이 아닙니다.

일반 모드는 정상 요청을 허용하고 보안 규칙에 걸릴 때 WAF에서 차단합니다. 콘솔 관리·인증 경로는 실습 WAF를 지나지 않고, 고정된 실제 실습3개 경로만 WAF를 통과합니다. 선택 예외는 해당 WAF 검사 정책만 바꾸며 Suricata·기존 L4/IP 차단·보호 주소·LLM 승인/TTL 정책을 해제하지 않습니다. 기존 IP 차단으로 접속이 끊긴 상태는 키 입력으로 복구할 수 없습니다.

위 정상 요청은 앱 처리와 브라우저 연결의 근거입니다. 실제 취약점 공격·LDAP 콜백·Wazuh 상관/색인 E2E 성공을 의미하지 않습니다. WAF canary 차단/예외 시험과 보안 로그 수신 시험은 승인된 별도 검증으로 기록합니다. 신규 서버의 WAF raw 로그, Wazuh manager 수신, indexer 색인, Dashboard 표시도 각각 확인해야 합니다.

## 3. 서버별 읽기 검증

아래 명령은 설정을 변경하지 않습니다. HTTP GET은 정상 접근 로그를 남길 수 있습니다. 성공 기준과 함께 확인하고, 값 하나만 정상이라고 전체 경로가 정상이라고 판단하지 않습니다.

### 공통: 시간·용량·컨테이너

세 서버에서 각각 실행합니다.

```bash
timedatectl show -p Timezone -p NTPSynchronized
date --iso-8601=seconds
df -h / /opt
sudo docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
```

호스트 시간대는 `Asia/Seoul`, `date` offset은 `+09:00`이 기준입니다. NTP 동기화가 `no`이면 시간 서버 접근과 호스트 시간 설정을 먼저 점검합니다. 컨테이너 `TZ` 또는 UI 표시와 원본 이벤트 timestamp는 구분합니다. 원본의 `Z`/`+00:00`은 UTC 표기이며 그 자체가 잘못된 시각은 아닙니다. Dashboard의 사용자 표시 시간대를 Asia/Seoul 또는 KST인 브라우저 시간으로 맞추고, 동일 이벤트를 UTC+9로 대조합니다.

### SIEM 서버

```bash
sudo docker compose --project-name capstone-siem \
  --project-directory /opt/capstone/siem -f /opt/capstone/siem/compose.json ps
sudo jq '{role,status,readonly_mcp_servers,write_approval_configured}' \
  /opt/capstone/siem/deployment.json
sudo jq '{role,status,containers,readonly_mcp_servers}' /opt/capstone/siem/verified.json
sudo docker exec capstone-wazuh-manager /var/ossec/bin/agent_control -l
sudo sshd -t
sudo systemctl is-active ssh
```

6개 컨테이너가 실행되어야 합니다: `capstone-wazuh-manager`, `capstone-wazuh-indexer`, `capstone-wazuh-dashboard`, `capstone-postgres`, `capstone-mattermost`, `capstone-hermes`. 완료 receipt의 `status`는 `applied`, 최종 검증 파일은 `verified`입니다. `applied`만 있고 최종 검증이 실패한 경우는 전체 완료로 보지 않습니다. agent 목록에는 `capstone-security`, `capstone-service`가 연결 상태로 나타나야 합니다.

아래 TLS 요청은 SIEM 서버에서 실행합니다. 인증서 검증과 웹 응답만 확인하며 관리자 암호를 사용하지 않습니다.

```bash
SIEM_HOST=192.0.2.20
sudo curl --noproxy '*' --cacert /opt/capstone/siem/tls/root-ca.pem \
  --connect-timeout 5 --max-time 15 -sS -o /dev/null -w 'dashboard HTTP %{http_code}\n' \
  "https://$SIEM_HOST/"
curl --noproxy '*' --connect-timeout 5 --max-time 15 -fsS \
  "http://$SIEM_HOST:8065/api/v4/system/ping" | jq '{status}'
```

Dashboard의 정상 UI 응답/로그인 이동과 Mattermost의 `status: OK`를 확인합니다. 이 두 검사만으로 Wazuh API 인증이나 LLM 연결까지 확인되지는 않습니다. 상세 애플리케이션 검증은 최상위 `--verify`를 사용합니다.

### service 서버

```bash
sudo docker compose --project-name capstone-service \
  --project-directory /opt/capstone/service -f /opt/capstone/service/compose.json ps
sudo jq '{role,state,schema}' /opt/capstone/service/manifest.json
sudo cat /opt/capstone/service/phase
sudo docker inspect --format '{{json .HostConfig.PortBindings}}' capstone-service-db
sudo docker network inspect --format '{{.Internal}}' capstone-service_private
sudo systemctl is-active capstone-offline-labs capstone-offline-labs-broker capstone-offline-labs-guard wazuh-agent
sudo sed -n "/^status=/p" /var/ossec/var/run/wazuh-agentd.state
sudo docker exec capstone-service-dvwa apachectl -t
```

`capstone-service-dvwa`와 `capstone-service-db`는 healthy, `capstone-service-gateway`는 running이어야 합니다. manifest는 `schema:9`, state와 phase는 complete입니다. DB 호스트 포트는 `{}` 또는 null, private 네트워크는 true, agent는 active/connected가 기준입니다. gateway는 service/loopback의 지정18091에 바인딩하며 security 출발지만 허용합니다. 웹 실습 컨테이너는 Compose에 직접 포함되지 않고 제한된 broker가 고정 image ID로 관리합니다.

같은 서버에서 익명 상태 조회와 sudo의 **중지 상태도 허용하는 설치·격리 검사**를 확인할 수 있습니다. 실제 설정이 다른 gateway 포트이면 바꿉니다.

```bash
curl --noproxy '*' --connect-timeout 5 --max-time 10 -fsS \
  http://127.0.0.1:18091/_offline-labs/api/status | jq '{deployment_allowed,safety_error,labs}'
sudo systemctl is-active user@1991.service capstone-sudo-status.timer
sudo jq '{schema,checked_at,expires_at,labs}' /var/lib/capstone-offline-labs/nonweb-status.json
sudo /usr/bin/python3 -IB /opt/capstone-nonweb-labs/sudo_terminal.py check
```

위 `check`는 기동/중지하지 않고 정상 중지 상태를 허용합니다. 실행 중 패키지의 고정 버전을 다시 확인하려면 기존 관리자 CLI `lab.py verify`를 사용하며, 이 명령은 중지 상태에서 실패하는 것이 정상입니다. sudo는 별도 UID1991 rootless daemon·network none·hostroot와 다른 UID/GID mapping·builtin seccomp2·최소 capability·자원 제한을 확인합니다. 환경 검증은 `environment_only`, `attack_tested=false`, `host_scenario_verified=false`이며 실제 권한상승이나 원래 host auditd 시나리오 성공이 아닙니다. 전용 컨테이너는 AppArmor 컨테이너 프로필 격리가 없고, 호스트 전역 AppArmor는 유지합니다. 기존 publisher는 root가 읽기 재검증한300초 receipt를60초마다 갱신하며 정지/오류/만료를 ready로 표시하지 않습니다. 콘솔의 sudo 실행·중지 상태는 중앙 터미널 어댑터에서 별도로 검증합니다.

전체 역할의 최종 검증은 controller `--verify`로 수행합니다. 정지된 웹 실습을 강제로 기동하거나 JAR 해시를 조회하는 구형 schema6 시험은 사용하지 않습니다. Java 이미지/카탈로그를 바꾸거나 관리 컨테이너를 수동 재생성하면 고정 계약/receipt 검사에 걸릴 수 있으므로 웹 broker와 명시된 운영 절차를 따릅니다. sudo의 `stop→up`은 승인된 고정 CLI 계약상 새 CID가 되며, 이 동작도 검증 명령과 구분합니다.

### security 서버

```bash
sudo docker compose --project-name capstone-security \
  --file /opt/capstone/security/compose.json ps
sudo jq '{schema_version,status,agent,lab_waf_enforcement_installed,automatic_ip_blocking_installed,vector_installed}' \
  /opt/capstone/security/deployment.json
sudo docker exec capstone-security-waf nginx -t
sudo nft list table inet capstone_portable
sudo systemctl is-enabled capstone-portable-firewall.service
sudo systemctl is-active wazuh-agent
sudo sed -n "/^status=/p" /var/ossec/var/run/wazuh-agentd.state
sudo grep -E '^SecRuleEngine[[:space:]]' /opt/capstone/security/config/GROOT_A_WAF.conf
sudo docker inspect --format '{{json .Config.Cmd}}' capstone-security-suricata
```

security manifest/deployment는 `schema_version:2`, 완료 상태여야 합니다. `capstone-security-waf`는 healthy, `capstone-security-suricata`와 `capstone-security-lab-edge`는 running이어야 합니다. Suricata 이미지에는 Docker healthcheck가 없을 수 있으므로 표에 `healthy`가 없다는 이유만으로 실패로 보지 않습니다. 최상위 검증은 엔진 시작 로그·고정 이미지·마운트·agent 상태를 추가 확인합니다. 기본 DVWA WAF는 DetectionOnly이며, 별도 Lab Host/경로 정책은 일반 enforce 또는 유효한 서명 세션 exempt입니다. 기본 설정의 SecRuleEngine 한 줄만 보고 Lab 차단이 꺼졌다고 판단하지 않습니다. Suricata는 지정 NIC의 IDS 캡처와 `/rules/all.rules` 사용이 기준입니다. nft `capstone_portable`은 허용 테이블이며 차단 엔진이나 전체 방화벽 정책의 정상 판정을 대신하지 않습니다.

security에서 service의 정상 웹 페이지에 접근해 실제 출발지/라우팅/ACL을 확인합니다.

```bash
SECURITY_HOST=192.0.2.10
SERVICE_HOST=192.0.2.30
ip route get "$SERVICE_HOST"
curl --noproxy '*' --interface "$SECURITY_HOST" --connect-timeout 5 --max-time 10 \
  -sS -o /dev/null -w 'backend HTTP %{http_code}\n' "http://$SERVICE_HOST:80/dvwa/login.php"
curl --noproxy '*' --connect-timeout 5 --max-time 10 \
  -sS -o /dev/null -w 'WAF HTTP %{http_code}\n' "http://$SECURITY_HOST:8080/dvwa/login.php"
```

포트는 변경한 설정에 맞춥니다. 정상 DVWA 로그인 페이지는 HTTP `200`이 기준입니다. backend가 `403`이면 service가 실제로 보는 접속 IP와 입력한 security 주소가 다른지 먼저 확인합니다. `X-Forwarded-For`만 바꾸어 우회하지 않습니다. WAF가 정상 요청을 통과시킨다는 사실과 Suricata가 미러링 트래픽을 받는다는 사실도 별도로 확인해야 합니다.


### 허용 클라이언트의 HTTPS 확인

승인된 내부망/VPN 클라이언트에서 DNS·인증서 신뢰를 준비하고 읽기 요청을 수행합니다. `curl -k`를 사용하지 않습니다.

```bash
LAB_PUBLIC_ORIGIN=https://lab.example.org
curl --noproxy '*' --connect-timeout 5 --max-time 15 -fsS \
  "$LAB_PUBLIC_ORIGIN/log4shell/api/list" | jq 'map(.cve_id)'
curl --noproxy '*' --connect-timeout 5 --max-time 15 -fsS \
  "$LAB_PUBLIC_ORIGIN/log4shell/api/session" | jq '{mode,expires_at}'
```

카탈로그6개와 새 클라이언트의 `mode:enforce`, `expires_at:null`이 정상 기준입니다. 유효한 예외 쿠키가 있는 브라우저는 exempt일 수 있으며 위 curl은 브라우저 쿠키를 공유하지 않습니다. security 자체의 `--verify` TLS probe는 Docker SNAT/클라이언트 ACL로200 또는403을 허용하고 `allowed_client_e2e_verified:false`를 출력합니다. 따라서 서버 검사 성공과 허용 클라이언트200을 별도 확인합니다.403을 없애려고 전체 CIDR 허용·프록시 신뢰 범위를 확대하지 않습니다.

## 4. 파일·로그·완료 기록 위치

| 위치 | 의미와 취급 |
|---|---|
| `/opt/capstone/releases/<SHA-256>/` | 설치 때 보존한 프로젝트 소스. 실행 중 제거하지 않음 |
| `/opt/capstone/role` | 원격 실행기가 기록한 서버 역할 |
| `/opt/capstone/siem/deployment.json`, `verified.json` | SIEM 적용/최종 검증 receipt. 전체 자격증명 파일과 구분 |
| `/opt/capstone/siem/actions/*.intent.json` | SIEM 변경 직전 작업 의도. intent가 있다고 해당 작업 성공이 보장되는 것은 아님 |
| `/opt/capstone/siem/failure-*.json` | 실패 단계·고정 사유 코드. 민감값 제외 요약 |
| `/opt/capstone/siem/diagnostic-*.log`, `api-failure-*.body` | 실패한 명령·HTTP 진단. 자격증명/응답 본문 가능성이 있어 root 전용으로 검토 |
| `/opt/capstone/siem/capstone-hermes/logs/gateway.log` | Hermes gateway 연결·도구 진단. 사용자 메시지 등 포함 가능 |
| `/opt/capstone/siem/capstone-hermes/gateway_state.json` | heartbeat. 현재 `running`, 최근 60초 이내 갱신 여부 확인 |
| `/opt/capstone/security/deployment.json`, `manifest.json` | security 완료 상태·파일 해시 |
| `/opt/capstone/security/{suricata-config-test,agent-config-test}.log` | native 구문검사 기록 |
| `/opt/capstone/security/logs/suricata/eve.json` | Suricata 원본 JSON 이벤트 |
| `/opt/capstone/security/logs/modsecurity/audit.log` | WAF 원본 감사 로그. 요청 본문·개인정보 포함 가능 |
| `/opt/capstone/security/backup/ossec.conf.before` | 최초 agent 설정 백업 |
| `/opt/capstone/service/{phase,manifest.json}` | service 마지막 phase 및 완료 manifest |
| `/opt/capstone/service/evidence/*.log` | Compose·Apache·DB 초기화·agent 구문검사/시작 진단 |
| `/opt/capstone/service/evidence/sudo-install.json`, `sudo-install.log` | 별도 rootless 초기 설치 결과/비공개 실패 진단 |
| `/var/lib/capstone-offline-labs/install-state.json` | 콘솔 설치 stage·고정 파일·환경 receipt |
| `/var/lib/capstone-offline-labs/nonweb-status.json` | root 발행 sudo 상태·시각·만료. 환경 검증 상태이며 공격 성공 기록 아님 |
| `/var/lib/capstone-sudo-bootstrap/manifest.json` | sudo 초기 helper의 preparing/complete/verification_failed 상태 |
| `/var/lib/capstone-sudo-bootstrap/recovery/` | sudo 운영 복구 archive·SHA. 임시파일이 아님 |
| `/opt/capstone/security/config/lab-{edge,waf,policy}.conf`, `tls/` | schema2 HTTPS 진입점/실습 정책과 운영 TLS. 개인키 공유 금지 |
| `/opt/capstone/service/evidence/ossec.conf.before` | service의 최초 agent 설정 백업 |
| `/opt/capstone/service/logs/{access,error}.log` | DVWA Apache 로그 |
| `/var/ossec/logs/ossec.log` | security/service의 Wazuh agent 진단 |
| `/var/ossec/logs/ossec.log` **(manager 컨테이너 내부)** | Wazuh manager 진단. 호스트 agent 경로와 구분 |

`docker logs`, `journalctl`, 위 원본 파일은 관리자 개인 터미널에서 필요한 시간·행만 확인합니다. 예를 들어 SIEM의 `sudo docker logs --since 10m --tail 100 capstone-wazuh-manager`는 조회 명령이지만 출력이 항상 비밀 없는 요약이라는 보장은 없습니다. 전체 `docker inspect`나 `docker compose config`는 환경변수/암호를 표시할 수 있으므로 공유용 진단으로 사용하지 않습니다. Compose 구문만 확인할 때는 `config --quiet`를 씁니다.

소스 번들과 SSH 작업용 `/var/tmp/capstone-bootstrap-<24자리 hex>`는 실행 종료 시 정리됩니다. `/opt/capstone/releases`, 완료 기록, 운영 비밀, DB 볼륨은 임시 파일이 아니므로 지우지 않습니다.

## 5. 증상별 진단과 다음 조치

| 증상·사유 코드 | 먼저 확인할 것 | 다음 조치 |
|---|---|---|
| `Host key verification failed` | 콘솔 fingerprint, `SSH_KNOWN_HOSTS`, 비기본 포트의 `[IP]:port` 항목 | 콘솔로 새 키의 정당성을 확인한 뒤 해당 항목만 갱신. 검사 우회 금지 |
| `Permission denied (publickey)` | `SSH_USER`·`SSH_IDENTITY`, 올바른 공개키, 홈/`.ssh` 소유자·권한 | 사전 SSH 등록 절차 수정. 비밀번호 인증을 설치기에서 대신 활성화하지 않음 |
| `sudo: a password is required` | 동일 계정의 `sudo -n true`, 배포용 sudoers 구문 | 콘솔에서 설치 관리자 권한 준비. LLM 계정에 sudo 권한 추가하지 않음 |
| `two addresses resolve to the same server` | 세 IP가 같은 VM을 가리키는지, 복제 VM의 machine-id | 실제로 구분된 VM인지 콘솔 점검. 운영 중 machine-id를 임의 변경해 검사를 우회하지 않음 |
| `missing package command` / `manual_package_missing_*` | README 수동 목록, Ubuntu/amd64 버전, PATH | 승인된 로컬 deb/전이 의존성을 artifacts.json에 준비. 새 환경 --apply가 오프라인 설치하며 Mac에는 설치하지 않음 |
| `Docker daemon unavailable` / `compose_plugin_required` | `systemctl is-active docker`, `docker compose version` | Docker 서비스·plugin 수동 준비 수정. 기존 daemon 데이터 삭제 금지 |
| `preloaded_*_image_required` / `image_architecture_not_linux_amd64` | 로컬 이미지 존재·참조·OS/Architecture | 검토된 amd64 save archive·ID·SHA를 artifacts.json에 준비. --apply는 로컬 load만 하며 pull하지 않음 |
| `artifact checksum mismatch` / `APT selected an unlisted package/removal` | 역할별 artifacts.json·원본 SHA·누락 전이 의존성 | 서명 검토한 준비 서버의 bundle을 수정. 대상 인터넷 다운로드·강제 의존성 무시 금지 |
| `schema9_requires_prebuilt_manifest_images_not_legacy_jar_options` | 구형 LOG4SHELL_* 값 잔존 | 새 LAB_* 설정·고정 카탈로그/이미지 사용. 기존 schema6·7·8 환경은 별도 이관 |
| `nonweb_runtime_preflight_failed` | Redis/Samba bundle·관리 소스·고정 런타임 조건 미충족 | `LAB_NONWEB_BUNDLE`의 정확4파일·SHA와 helper의 정제된 오류 코드 확인. check는 계정 생성 전에도 가능 |
| `nonweb_runtime_install_failed_private_evidence_preserved` | 별도 nonweb 설치 중 실패 | service/evidence/nonweb-install.json과 별도 root receipt를 확인하고 부분 설치를 수동 검토. 재실행으로 덮어쓰지 않음 |
| `offline_lab_preflight_failed` / `offline_lab_prerequisites_invalid` | wheel 전체 목록·해시, 6항목 카탈로그, 고정 웹3이미지·터미널3개, nft/systemd 조건 | 오류 원인을 확인하고 정확한 반입물을 복구. latest 대체·guard 생략 금지 |
| `lab_common_key_precondition_failed` / 공통 키 전달 실패 | SIEM admin 암호 입력 계약·SSH pipe·service 키 root0600·기존 다른 키 | 원문을 로그에 출력하지 않고 연결 정책/권한을 점검. 기존 키를 덮어써 암호 회전하지 않음 |
| TLS/site preflight 실패 | origin/port·SAN·키 일치·유효기간·허용 CIDR·/29 충돌 | DNS·인증서·네트워크 계획 수정. 웹 공개를 의도한 경우에만 `LAB_ALLOWED_CIDRS=all` 지정. `-k`로 TLS 검사를 우회하지 않음 |
| 콘솔404/502 또는 실습503 | HTTPS→edge→gateway→콘솔, 실습 실행 상태·고정 경로 | 관리 API와 실제 WAF 실습 경로를 분리 확인. Java를 DVWA Apache의 직접 JAR 프록시로 복원하지 않음 |
| 예외 인증401/429 | 입력 키·30초 challenge 만료/재사용·발급 제한·HTTPS/WebCrypto·시각 | 새 challenge로 재입력 또는 제한 시간 후 재시도. raw키/Bearer/고정해시 프로토콜은 거절되는 것이 정상 |
| `deployment_allowed:false` | `safety_error`, nft guard·network 계약 | 배포가 차단된 원인을 복구. 상태 조회·관리 중지는 별도 가능하며 LLM에 일반 Docker 권한 추가 금지 |
| sudo `needs_setup` / `sudo_runtime_install_failed_private_evidence_preserved` | UID1991/subid 충돌, OS 전제, 고정 bundle, manifest phase, rootless/publisher receipt TTL | 부분 상태를 보존하고 전용 helper 근거로 복구. host sudo 변경·전역 userns/AppArmor 완화 금지 |
| `prepared_image_validation` 실패 | [Hermes 이미지 준비](hermes-image.md)의 기반 이미지, MCP SDK, regex 버전·가드 해시 | Linux에서 이미지를 올바르게 준비하고 검증. 이 단계가 root 상태 생성 전 실패했는지도 확인 |
| `existing_*`, `deployment_incomplete`, `partial/different-profile` | 이전 완료/부분 설치 기록, VM이 기존 운영 서버인지 | 현재 상태 보존 후 수동 복구 계획. 디렉터리·receipt·볼륨·agent 키 삭제로 fresh 조건 만들지 않음 |
| `*_port_*used*` / `backend_port_in_use` | `sudo ss -lntup`의 해당 포트 소유 프로세스 | 기존 서비스 용도를 확인한 뒤 주소/설치 대상 계획 수정. 프로세스 강제 종료 금지 |
| `unsafe_*`, `*_permissions_*`, `secret_file_requires_root_0600_*` | 파일 경로 symlink 여부, `sudo stat` 소유자·권한 | 필요한 파일 하나의 소유자/모드만 검토해 수정. `/opt` 전체 재귀 chmod 금지 |
| agent TLS/등록 시간 초과 | SIEM TCP1515의 도달성, CA·IP SAN·인증서 기간, 양쪽 시간 | 아래 등록 TLS 진단 실행. 1514와 1515를 각각 확인하고 원인 해결. `client.keys`나 등록 암호 삭제 금지 |
| agent `disconnected` | SIEM TCP1514 경로, manager 실행 상태, agent의 최근 제한된 진단 | 경로/서비스 복구 후 같은 agent의 연결 회복 확인. 중복 신규 등록 시도하지 않음 |
| Dashboard 인증서 오류 | 인증서 체인·IP SAN·현재 시각·클라이언트 CA 신뢰 | 공개 CA 신뢰와 접속 IP 수정. 임의 인증서 재발급은 기존 등록/프로필 영향 검토 후 수행 |
| Dashboard/API 인증 실패 | Dashboard admin과 API 계정의 구분, 초기 파일과 실제 계정 불일치 | 정확한 계정부터 확인. 초기 JSON만 변경하거나 기본 암호를 시도하지 않음 |
| `health_timeout_core` / Indexer 시작 실패 | SIEM 메모리·디스크·vm.max_map_count, 제한된 indexer 로그 | 자원·커널 설정·권한 등 구체적 원인 해결. 초기화/볼륨 제거로 재시도하지 않음 |
| WAF `502`, backend 연결 실패 | security→service IP/포트/라우트, DVWA·DB health | 백엔드 연결부터 복구한 뒤 WAF 경유 GET 재검증 |
| WAF 경유 DVWA `403` | service Apache가 보는 실제 TCP peer, security 출발지·NAT | 주소/라우팅을 의도한 구조에 맞춤. ACL을 전체 허용으로 바꾸어 통과시키지 않음 |
| Suricata 실행되나 이벤트가 없음 | 감시 NIC, link/패킷 카운터, 가상 스위치 미러링, 트래픽 경로 | 정상 요청이 해당 NIC에 도달하는지부터 확인. 경보 0개만으로 장애/정상 판정하지 않음 |
| Mattermost 접속되나 봇 무응답 | 관리자 계정인지, SOC 채널인지, 멘션 여부, gateway heartbeat | 허용 정책과 WebSocket 연결을 먼저 확인한 뒤 모델/MCP 순서로 분리 진단 |
| Hermes LLM 오류·느림 | `LLM_BASE_URL`의 `/v1`, 실제 모델명, SIEM에서 LLM 경로/지연 | API 모델 목록·서비스 상태를 읽기 조회. 모델 학습·다운로드나 서버 변경을 설치 재실행으로 해결하지 않음 |
| MCP SSH/인증 실패 | `sshd -t`, 전용 키/known_hosts 경로·권한, `capstone-mcp` 정책, API CA | `--verify`의 MCP 단계와 고정 오류 코드를 근거로 복구. ForceCommand/host key/CA 검증 해제 금지 |
| `container_replacement_requires_review` / `managed_file_changed` | 설치 후 수동 재생성·이미지/파일 변경 여부 | 변경 이유와 새 상태를 검토하는 운영 이관 작업 필요. receipt를 현재 값으로 수동 덮어써 우회하지 않음 |
| 모바일 푸시 경고 | HTTP 기본 구성, 공개 HTTPS/푸시·네트워크 준비 여부 | 신규 기본 설치의 범위 밖. 서버 로그인과 푸시 연결을 구분하여 별도 구축 |

등록 TLS는 **security 또는 service**에서 다음과 같이 확인합니다. 표준 출력에는 인증서·연결 정보가 보일 수 있지만 등록 암호나 개인키를 전달하지 않습니다.

```bash
SIEM_HOST=192.0.2.20
sudo timeout 12s openssl s_client -connect "$SIEM_HOST:1515" \
  -CAfile /opt/capstone-prereqs/wazuh-root-ca.pem \
  -verify_ip "$SIEM_HOST" -verify_return_error -no_ign_eof </dev/null
```

`Verification: OK` 또는 `Verify return code: 0 (ok)`는 CA·서버 신원 검증 근거입니다. 단순 TCP 연결, 인증서 검증 성공, 등록 암호 인증 성공, TCP1514 agent 연결 성공은 서로 다른 단계입니다. `timeout`만으로 TLS 신뢰 실패라고 단정하지 말고, TLS 성공 메시지와 agent/manager 진단을 함께 대조합니다.

LLM의 모델 목록 확인은 **SIEM**에서 실제 설정 주소로 실행합니다. 답변 생성 요청은 하지 않습니다.

```bash
LLM_BASE_URL=http://192.0.2.40:11434/v1
curl --noproxy '*' --connect-timeout 5 --max-time 15 -fsS "$LLM_BASE_URL/models" | jq -r '.data[]?.id'
```

목록에 설치 설정의 `LLM_MODEL`이 있어야 합니다. 목록 조회 성공만으로 채팅 응답·도구 호출 성공을 보장하지 않으며, 이후 관리자의 한 번의 채팅 시험으로 구분해 확인합니다. 이 설치기는 별도 API 키가 없는 내부 OpenAI 호환 API를 전제로 합니다.

## 6. 실패 후 안전한 재개

1. 실패한 명령의 종료 코드·시각·역할·고정 사유만 기록합니다. 배포가 멈췄더라도 먼저 성공한 SIEM/service가 계속 실행 중일 수 있습니다. 후속 단계가 자동 실행되지 않았다는 사실과 앞 단계가 롤백되었다는 주장을 구분합니다.
2. 위 경로의 receipt/phase/intent와 현재 컨테이너·볼륨 존재 여부를 읽기 확인합니다. 원본 로그가 필요하면 서버 root 전용 상태로 보존하고 공유본에는 필요한 오류 메타데이터만 남깁니다.
3. **적용 전 사전조건 실패**는 패키지/이미지/SSH 준비를 수정하고 `--check`부터 다시 실행할 수 있습니다. **일부 적용 후 실패**는 마지막 phase와 실제 성공 범위를 확인한 뒤 수동 복구 계획을 작성합니다. 자동 설치기는 부분 상태를 무조건 이어서 수행하지 않습니다.
4. 외부 네트워크·시간·용량 원인 등만 해결했다면 먼저 `--verify`로 현재 상태를 확인합니다. 완료된 같은 프로필을 `--apply`하는 경우에도 검증 경로를 사용합니다. 다른 주소·모델·이미지·소스 버전으로 바뀌면 단순 재실행을 업그레이드로 취급하지 않습니다.
5. DB 초기화, agent 재등록, 컨테이너 재생성, 계정 재발급이 필요하면 영향·보존할 데이터·복구 경로를 정한 별도 작업으로 진행합니다. `docker compose down -v`, `docker system prune`, `/opt/capstone` 삭제, `client.keys` 삭제, 완료 receipt 수정을 일반 복구 절차로 사용하지 않습니다.
6. 배포용 sudoers 정리는 모든 검증이 끝난 뒤 합니다. 이후 `--verify`는 root 조회를 사용하므로 그 권한까지 제거했다면 관리자 콘솔 또는 다시 준비한 배포 계정으로 수행해야 합니다. Hermes에는 설치용 관리자 권한을 이전하지 않습니다.

## 7. 로컬 코드 검사와 실제 서버 시험을 구분

관리 컴퓨터의 기존 Python/Bash만 사용하여 다음 회귀 검사를 실행할 수 있습니다. 패키지 설치·Docker 기동·실서버 접속은 하지 않습니다.

```bash
python3 -B deployment/tests/test_controller.py
python3 -B deployment/tests/test_prerequisites.py
python3 -B deployment/tests/test_lab_key.py
python3 -B deployment/tests/test_offline_security.py
python3 -B deployment/tests/test_soc_diagnostics.py
python3 -B deployment/test_offline_service.py
bash deployment/roles/siem-test.sh
bash deployment/roles/service-test.sh
python3 -B -m unittest discover -s infra/groot-c/offline-labs/nonweb/sudo/runtime -p test_bootstrap.py
```

이 검사는 controller의 가짜 SSH 순서, 반입물·키 프로토콜, SIEM/service/security 설정 생성, sudo bootstrap의 실패·권한 계약을 확인합니다. 통과 결과는 새 VM의 설치 성공, 실제 인증/DB 동작, 패킷 탐지, 모바일 알림 성공을 대신하지 않습니다. 신규 환경의 최종 인수 기록에는 사용 소스 commit, 대상 역할, 수동 준비 버전/이미지 ID, `--verify` 결과, 브라우저 로그인, 정상 웹 요청, 관리자의 봇 질의 결과와 미검증 항목을 나누어 남깁니다. 비밀값은 기록하지 않습니다.

읽기 진단은 `deploy.sh --verify`에서 각 호스트의 collector timer·소스 SHA·snapshot 소유권/크기/TTL을 확인하고, B의 비권한 읽기 계정으로 A/C 고정 reader의 SSH 연결과 host key를 대조합니다. 이어 Hermes의 실제 SSH MCP 경로에서 도구 목록과 bounded read 한 건을 검사합니다. 새 모델 추론이나 채팅 메시지는 보내지 않습니다. stale/unavailable은 관측 실패이며 서비스 정상 판정으로 대체하지 않습니다. 정상 수집 간격60초·허용 나이180초·최대4시간 오류 표본과 truncation 플래그를 함께 읽어야 합니다. 오류0건은 전체 원본 로그에 오류가 없었다는 증거가 아닙니다.

고정 journal grep 조회에 일치 항목이 없으면 종료 코드1과 빈 stdout·stderr를 정상적인 빈 관측으로 처리합니다. 이 경우에만 오류 수가0입니다. stderr·권한 오류·다른 조회 실패·시간 또는 출력 상한 초과는 `unavailable`과 `count=null`을 유지하며, 일반 명령의 종료 코드1을 성공으로 바꾸지 않습니다.

`diagnostic_ssh_effective_policy_mismatch`이면 A/C에서 고정 진단 계정의 effective `sshd -T -C` 정책을 관리자가 확인합니다. 전역 `PermitUserEnvironment no`·`UsePAM yes`, 공개키 전용 인증, forwarding/TTY 금지와 고정 `read-snapshot` ForceCommand가 필요합니다. 초기 설치기는 이 조건을 만족시키기 위해 기존 전역 SSH 파일을 덮어쓰지 않습니다. `sshd -t`가 실패한 부분 설치도 원본 SHA와 신규 namespace·복구 백업을 검토한 별도 이관 없이 재실행하지 않습니다.
