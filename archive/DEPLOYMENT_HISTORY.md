# 설치·웹 정책 이력

이 문서는 과거 기록입니다. 현재 상태는 [STATUS](../STATUS.md), 실행 계획은 [PLAN](../PLAN.md)을 따릅니다. 같은 내용을 반복한 부분은 하나의 본문으로 연결했습니다. 서로 다른 날짜·판단·실패·정정은 합쳐 단정하지 않습니다. [정리·복원 안내](README.md).

| 원문 마지막 Git 기록(KST) | 보존한 문서 |
|---|---|
| 2026-11-04T19:18:25+09:00 | [deployment-verify-troubleshoot-before-ncsc-20261104.md](#source-7a802540e249541b) |
| 2026-11-04T19:18:25+09:00 | [deployment-configuration-guide-before-ncsc-20261104.md](#source-5f5f782f6b670953) |
| 2026-11-04T19:18:25+09:00 | [deployment-bootstrap-guide-before-ncsc-20261104.md](#source-6da49272bde6c9e3) |
| 2026-11-04T19:18:25+09:00 | [deployment-README-before-ncsc-20261104.md](#source-252038d31234088c) |
| 2026-11-04T19:18:25+09:00 | [deployment-INSTALLER_READINESS-before-read-accuracy-ncsc-20261104.md](#source-ef7424bbadcff1f6) |
| 2026-11-04T12:00:02+09:00 | [README-offline-labs-20261104-before-enforce.md](#source-429cb0b9c8ff56ec) |

<a id="source-7a802540e249541b"></a>

## deployment-verify-troubleshoot-before-ncsc-20261104.md

<details>
<summary>당시 기록 펼치기 · 2026-11-04T19:18:25+09:00</summary>

<a id="source-7a802540e249541b-h0"></a>
<a id="record-d939ca7d5fe043b61c37130825086b2728769ba7b0f5166a4d6f681d283cc28d"></a>

# 설치 후 접속·검증·장애 진단



<a id="source-7a802540e249541b-h1"></a>
<a id="record-f0f97c0787b1d6a087b47c921611e20b4e9a7a24633052bf3b5deeb0bcf6ae93"></a>

## B 호스트 수집과 manager 컨테이너 구분

새 설치 `deploy.sh`는 `capstone-siem-host`를 별도 등록한다. 운영 이름은 `groot-siem-host`이며 ID는 등록/조회 결과에서 확인하고 고정000/003으로 가정하지 않는다. Wazuh agent000의 Amazon Linux 결과는 manager 컨테이너이고 B Ubuntu24.04 호스트 결과가 아니다.

- 호스트에서 `systemctl is-active wazuh-agent`와 `/var/ossec/var/run/wazuh-agentd.state`의 connected·최근 갱신을 확인한다. `/var/lib/capstone-siem-host-agent/receipt.json`에는 비밀 없는 ID·설정 SHA·등록 KST가 있다. client.keys는 출력하지 않는다.
- 두 봇의 `get_wazuh_agents`에서 이름·ID·OS를 확인하고 `get_wazuh_sca_checks`로 정책 목록→정확 policy/check·스캔 시각을 조회한다. `b:wazuh-agent`는 호스트 unit, `b:wazuh-manager`는 컨테이너다.
- syscollector 패키지/OS/프로세스, journald/FIM/SCA 수집이 각각 도착했는지 확인한다. 단순 active나 전체 SCA 점수만으로 모든 탐지·대응 E2E를 통과했다고 표시하지 않는다.
- 운영 검증에서는 B 점검용 SSH 접속4건의 journald 메시지/PID와 agent003의 경보 ID/원문, 인덱서 저장 내용을 대조했다. A/C는 수집기 순차 재시작 후 새 SCA의 SSH MAC35654 통과를 확인했다. 전체 raw 로그 보관은 비활성화 상태이며 이 검증은 모든 로그 무누락·FIM 이벤트·공격 대응 시험을 대신하지 않는다. [시점별 결과](../STATUS.md).
- 부분 설치 실패의 pending/원본 config는 보존한다. 다른 agent 키를 삭제하거나 등록 파일을 비워 재시도하지 않는다. 실패 시 새 host agent만 중지되며 manager/다른 agent는 재시작하지 않는다.


<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 사용자 진입점은 루트 deploy.sh 하나이고 service schema9·HTTP3/터미널3·MCP6서버/고정 진단을 연결한다. 새3VM 전체 설치 시험은 사용자 제외 범위를 유지하며 기존 운영 서버를 초기 설치기로 덮어쓰지 않는다. 이번 운영 보완은 별도 최소 이관이다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

이 문서는 [README](../README.md)의 단일 설치기로 **새 환경**을 구성한 뒤 사용하는 절차입니다. 경로와 성공 판정은 `deploy.sh`와 `deployment/roles/{security,siem,service}.sh`의 구현을 기준으로 작성했습니다. 기존 운영 서버의 이름·계정·경로와 혼용하지 않습니다. **새 Ubuntu VM 세 대에서의 실제 통합 구축 검증은 아직 수행하지 않았습니다.** 아래 명령은 운영자가 해당 환경에서 실행할 검증 절차이며, 이미 확인된 라이브 결과를 뜻하지 않습니다.

예시 주소 `192.0.2.10`은 security, `.20`은 siem, `.30`은 service입니다. 실제 배포 때 입력한 주소·포트로 바꿉니다. 서버 명령은 명시된 서버의 SSH 터미널에서 실행하고, 관리 컴퓨터 명령은 저장소 루트에서 실행합니다. 로그·설정에는 자격증명이 포함될 수 있으므로 전체 파일을 채팅이나 Git에 붙이지 않습니다.



<a id="source-7a802540e249541b-h2"></a>
<a id="record-a5ac56f8611f7a225580fdd19d05597f33623b5f62766c97127d87cbea08d2c1"></a>

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



<a id="source-7a802540e249541b-h3"></a>
<a id="source-7a802540e249541b-h4"></a>
<a id="source-7a802540e249541b-h5"></a>
<a id="source-7a802540e249541b-h6"></a>
<a id="source-7a802540e249541b-h7"></a>
<a id="source-7a802540e249541b-h8"></a>
<a id="record-e749be6cd4fab76e0f973dc6260d88135708846bb3294f6456aa589f83bea142"></a>

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



<a id="source-7a802540e249541b-h10"></a>
<a id="source-7a802540e249541b-h11"></a>
<a id="source-7a802540e249541b-h12"></a>
<a id="source-7a802540e249541b-h13"></a>
<a id="source-7a802540e249541b-h14"></a>
<a id="source-7a802540e249541b-h9"></a>
<a id="record-2103e8114b2c1795c81dda6b640dd9998cff817f95a61185bf64556f15eca9bf"></a>

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



<a id="source-7a802540e249541b-h15"></a>
<a id="record-65fe6a349455c8cb9ec64fd240f16fa76b1e8cde5f7c2fa693121da8e8b8f307"></a>

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



<a id="source-7a802540e249541b-h16"></a>
<a id="record-8df1654671cecea3847b5f82b551f3011c99e9888f27538d70a545dfe14b479f"></a>

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



<a id="source-7a802540e249541b-h17"></a>
<a id="record-916cb650960268a5235eaee56c8cb23f0f60d83c9b397dccf091b038e16fcc60"></a>

## 6. 실패 후 안전한 재개

1. 실패한 명령의 종료 코드·시각·역할·고정 사유만 기록합니다. 배포가 멈췄더라도 먼저 성공한 SIEM/service가 계속 실행 중일 수 있습니다. 후속 단계가 자동 실행되지 않았다는 사실과 앞 단계가 롤백되었다는 주장을 구분합니다.
2. 위 경로의 receipt/phase/intent와 현재 컨테이너·볼륨 존재 여부를 읽기 확인합니다. 원본 로그가 필요하면 서버 root 전용 상태로 보존하고 공유본에는 필요한 오류 메타데이터만 남깁니다.
3. **적용 전 사전조건 실패**는 패키지/이미지/SSH 준비를 수정하고 `--check`부터 다시 실행할 수 있습니다. **일부 적용 후 실패**는 마지막 phase와 실제 성공 범위를 확인한 뒤 수동 복구 계획을 작성합니다. 자동 설치기는 부분 상태를 무조건 이어서 수행하지 않습니다.
4. 외부 네트워크·시간·용량 원인 등만 해결했다면 먼저 `--verify`로 현재 상태를 확인합니다. 완료된 같은 프로필을 `--apply`하는 경우에도 검증 경로를 사용합니다. 다른 주소·모델·이미지·소스 버전으로 바뀌면 단순 재실행을 업그레이드로 취급하지 않습니다.
5. DB 초기화, agent 재등록, 컨테이너 재생성, 계정 재발급이 필요하면 영향·보존할 데이터·복구 경로를 정한 별도 작업으로 진행합니다. `docker compose down -v`, `docker system prune`, `/opt/capstone` 삭제, `client.keys` 삭제, 완료 receipt 수정을 일반 복구 절차로 사용하지 않습니다.
6. 배포용 sudoers 정리는 모든 검증이 끝난 뒤 합니다. 이후 `--verify`는 root 조회를 사용하므로 그 권한까지 제거했다면 관리자 콘솔 또는 다시 준비한 배포 계정으로 수행해야 합니다. Hermes에는 설치용 관리자 권한을 이전하지 않습니다.



<a id="source-7a802540e249541b-h18"></a>
<a id="record-dd2998d054cb0531067dadc72f39a268eb0fb0530be43c995fe796d0766f8698"></a>

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


</details>

<a id="source-5f5f782f6b670953"></a>

## deployment-configuration-guide-before-ncsc-20261104.md

<details>
<summary>당시 기록 펼치기 · 2026-11-04T19:18:25+09:00</summary>

<a id="source-5f5f782f6b670953-h0"></a>
<a id="record-58e21fc994ba3b4d40f4c23c734fee4e2ca20938febd1904369e352830576ba1"></a>

# 환경 값 입력과 단일 셸 실행

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 사용자 진입점은 루트 deploy.sh 하나이고 service schema9·HTTP3/터미널3·MCP8논리 서버/35도구·고정 진단을 연결한다. 새3VM 전체 설치 시험은 사용자 제외 범위를 유지하며 기존 운영 서버를 초기 설치기로 덮어쓰지 않는다. 이번 운영 보완은 별도 최소 이관이다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

새 Ubuntu 24.04 amd64 서버 3대의 진입점은 저장소 루트의 `deploy.sh` 하나다. 현재 service 상태는 **schema9**, security 상태는 **schema2**다. 기존 운영 A/B/C를 새 설치 대상으로 인수하지 않는다. **새 VM 3대에서 전체 `--apply`를 실제 실행한 검증은 아직 하지 않았다.**

[네트워크·SSH 준비](setup-network-ssh.md), [오프라인 반입·설치 흐름](bootstrap-guide.md), [Hermes 이미지 준비](hermes-image.md)를 먼저 확인한다. 예시 `192.0.2.0/24`는 문서용이며 실제 할당 주소로 바꾼다. 설치기는 IP·라우팅·DNS·SSH를 자동 변경하지 않는다.

| 입력 | 위치 | 내용·권한 |
|---|---|---|
| `deployment/site.local.conf` | 관리 컴퓨터 저장소 | 주소·SSH·LLM·`LAB_*` 설정. 로컬 전용0600 권장, 비밀번호 금지 |
| `/opt/capstone-prereqs/artifacts.json` 및 명시된 파일 | 서버마다 | 역할별 승인된 `.deb`·Docker save archive의 버전·SHA·ID. root 소유, group/world 쓰기 금지 |
| `/opt/capstone-prereqs/siem.json` | SIEM | 초기 계정·암호·Hermes image ID. root:root0600 |
| wheel 디렉터리·카탈로그·sudo/nonweb bundle | service | 아래 `LAB_WHEEL_DIR`, `LAB_MANIFEST`, `LAB_SUDO_BUNDLE`, `LAB_NONWEB_BUNDLE` |
| TLS 인증서·개인키 | security | `LAB_PUBLIC_ORIGIN` 이름과 맞는 인증서. 개인키 root:root0600 |

반입 manifest의 해시는 관리자가 승인한 파일의 동일성을 확인한다. 공급자 서명 검증은 별도 준비 단계의 책임이며, sudo bundle은 자체 고정 pin·서명 체인을 추가 검사한다. Mac에 패키지를 설치하지 않으며 controller는 반입 바이너리를 자동 다운로드하지 않는다.



<a id="source-5f5f782f6b670953-h1"></a>
<a id="source-5f5f782f6b670953-h2"></a>
<a id="record-b26110006e3397f6a3e0eea4775c632b3cdff0851cd5ef4aec9055941116a853"></a>

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



<a id="source-5f5f782f6b670953-h3"></a>
<a id="record-2a0f0db61061b35e8142637d448457b64121a858c0caea46645151194fff79dc"></a>

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
LAB_NONWEB_BUNDLE=/opt/capstone-prereqs/nonweb
LAB_TLS_CERT=/opt/capstone-prereqs/lab-tls.crt
LAB_TLS_KEY=/opt/capstone-prereqs/lab-tls.key
LLM_BASE_URL=http://192.0.2.40:11434/v1
LLM_MODEL=qwen3.6:35b
```

`MANAGEMENT_ALLOWED_CIDRS`는 신규 C 콘솔의 `OFFLINE_LABS_ADMIN_CIDRS`에도 기록된다. 공개 웹 열람과 관리자 제어를 분리하며, 인증해도 WAF On이다. 현재 운영의 관리자 주소는192.168.16.231/32다. [검증·복구](../infra/validation/web-policy/README.md).

| 설정 | 의미·제약 |
|---|---|
| `SECURITY_HOST`, `SIEM_HOST`, `SERVICE_HOST` | 서로 다른 사용 가능한 IPv4 리터럴. 호스트명·CIDR 금지 |
| `SSH_USER`, `SSH_PORT` | 세 서버 공통. 기본 ubuntu/22. 비기본 SSH 포트는 내부 읽기 MCP에도 반영 |
| `SSH_IDENTITY`, `SSH_KNOWN_HOSTS` | 관리 컴퓨터의 실제 경로. 빈 identity는 기존 ssh-agent/기본키 사용. host key 자동 수락 없음 |
| `MONITOR_INTERFACE` | security 감시 NIC 또는 auto |
| `WEB_BACKEND_PORT`, `WAF_PORT` | 독립 DVWA의 service/backend와 security/WAF 포트. Lab HTTPS와 별개 |
| `LAB_PUBLIC_ORIGIN`, `LAB_HTTPS_PORT` | 필수 HTTPS DNS origin과 같은 포트. path·사용자정보·query 금지. 기본443은 origin에 생략 |
| `LAB_ALLOWED_CIDRS` | 쉼표로 구분한 1~32개 고유 RFC1918 IPv4 CIDR, 또는 모든 출발지의 실습 웹 접근을 명시하는 단독 값 `all`. `all`과 CIDR 혼합·`0.0.0.0/0`은 거절. SSH·Wazuh·MCP 접근 정책과 별개 |
| `LAB_PROXY_SUBNET` | security 전용 프록시의 사설 /29. 호스트 route·기존 Docker·클라이언트 CIDR과 충돌 금지 |
| `LAB_GATEWAY_PORT` | service 내부 gateway 포트, 기본18091. security와 service loopback만 허용하며 사용자 공개 주소가 아님 |
| `LAB_WHEEL_DIR` | service의 Python3.12 amd64용 전체 고정 wheel 목록. 설치기는 인터넷 대신 이 입력으로 콘솔 환경 준비 |
| `LAB_MANIFEST` | service의 고정 6항목 카탈로그. Java/Apache2개는 정확한 로컬 image ID, Redis/Samba/sudo는 고정 managed-terminal3개; sudo는 별도 rootless 런타임 |
| `LAB_SUDO_BUNDLE` | service의 [고정 sudo bundle](../infra/groot-c/offline-labs/nonweb/sudo/runtime/BOOTSTRAP.md). 10파일+manifest와 서명 증빙 필수 |
| `LAB_NONWEB_BUNDLE` | service의 [Redis/Samba bundle](../infra/groot-c/nonweb-labs/README.md). manifest·provenance 및 이미지 archive2개, 기본 `/opt/capstone-prereqs/nonweb`. 콘솔 계정 생성 이후 별도 helper가 설치하며 두 실습은 미시작 상태로 둠 |
| `LAB_TLS_CERT`, `LAB_TLS_KEY` | security의 준비된 인증서/개인키. `/opt/…` 절대 경로. 실제 hostname·키 일치·유효기간 검증 |
| `LLM_BASE_URL`, `LLM_MODEL` | 내부 `/v1` API와 실제 모델 ID. URL 안의 자격·query 금지 |
| `SURICATA_IMAGE`, `WAF_IMAGE`, `DVWA_IMAGE`, `MARIADB_IMAGE` | 선택 로컬 이미지 참조. 반입된 ID·플랫폼·역할 계약을 검사하며 pull하지 않음 |
| `ET_RULES_FILE` | 선택 security 룰 경로. 기본 `/opt/capstone-prereqs/suricata.rules` |

읽기 전용 시스템 진단에는 별도 비밀번호 입력이 없다. 설치기가 `SECURITY_HOST`·`SIEM_HOST`·`SERVICE_HOST`와 `SSH_PORT`를 새 진단 전용 SSH 경로에도 결속한다. B에서 생성한 새 키는 A/C의 고정 snapshot reader만 호출하며 관리자 SSH 키·WAF 예외 키·Wazuh 자격증명을 공유하지 않는다. collector는 root로 고정 상태와 오류 분류 메타데이터만 수집하고, MCP 계정에는 root·sudo·Docker·원본 journal 읽기 권한을 주지 않는다. 기존 서버는 새 진단 namespace가 없는지 확인한 뒤 확장 부분만 별도 배포한다.

`LAB_ADMIN_KEY_FILE`은 controller의 고정 전달 경로이며 설정 파일의 입력 키가 아니다. `LAB_ADMIN_KEY`나 비밀번호 값도 넣지 않는다. 구형 `LOG4SHELL_IMAGE`, `LOG4SHELL_APP_JAR`, `LOG4SHELL_HOSTNAME`은 더 이상 쓰지 않으며 값이 있으면 거절한다. schema9은 준비된 관리형 이미지로 실행하고 초기 설치 중 Java JAR를 빌드·마운트하지 않는다. 기존 schema6·7·8 서비스는 자동으로 인수하지 않는다.

설정은 LF의 `KEY=value` 데이터다. `export`, 따옴표, 줄 끝 주석, 변수 확장, `~`, 명령 치환을 넣지 않는다. 맨 앞 `#`만 주석이며 알 수 없는 키는 거절한다. 파일을 shell `source`로 실행하지 않는다. 설정 파일에 정의한 경로를 controller가 서버로 업로드하는 것은 아니다.



<a id="source-5f5f782f6b670953-h4"></a>
<a id="record-b009208600dc7df2200e02b8992b9860f521f22be739c79795a6a38854a0e3f4"></a>

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



<a id="source-5f5f782f6b670953-h5"></a>
<a id="source-5f5f782f6b670953-h6"></a>
<a id="source-5f5f782f6b670953-h7"></a>
<a id="record-cf053a82586e3cc30932a63487e62342259d3fc706feda4dd63d334656ef1448"></a>

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
- sudo도 콘솔에서 시작한 뒤 같은 사이트의 웹 터미널로 연다. 별도 UID1991 rootless 런타임·컨테이너 UID1000을 유지하며 웹/LLM에 일반 Docker나 호스트 sudo 권한을 주지 않는다. sudo는 전체 사용자 중 한 터미널만 허용하고 연결 종료·유휴/수명 만료 때 해당 컨테이너 전체를 중지한다. 환경/패키지 검증은 실제 권한상승·host auditd 시나리오 성공을 뜻하지 않는다.

기본 설치는 웹 실습3개 이미지만 준비하며 자동 기동하지 않는다. 콘솔에서 선택해 실행한 뒤 같은 HTTPS 링크로 접속한다. SSH 포트포워딩은 일반 접속의 필수 절차가 아니다. 추가 CVE는 이미지·카탈로그뿐 아니라 제한된 same-origin 라우트 계약도 별도로 준비해야 한다.

### 대화형 실행

```bash
bash deploy.sh
```

설정 파일 없이 터미널에서 실행할 때 질문 순서는 **security 주소 → siem 주소 → service 주소 → 공통 SSH 사용자 → 개인키 경로 → 감시 NIC → Lab HTTPS origin → 허용 내부망/VPN CIDR → LLM API 주소**다. 기본 동작은 실제 `--apply`다. SSH/HTTPS 포트·모델·인증서/번들 경로 등 질문에 없는 값을 바꾸려면 설정 파일을 쓴다. 대화형 실행도 사전 반입물·인증서·자격 JSON을 요구한다.



<a id="source-5f5f782f6b670953-h8"></a>
<a id="record-6922fc3b789d75c1210008b4a8fc2457739b5aef85d75e07a5103d78b3c96cc3"></a>

## 5. 재검증과 운영 인계

```bash
bash deploy.sh --verify --batch --config deployment/site.local.conf
```

종료 코드0과 `세 역할 검증 완료.`를 확인한 뒤 [검증·장애 대응](verify-troubleshoot.md)에 따라 허용 클라이언트 HTTPS·로그인·정상 웹 요청과 관리자 봇 질의를 별도로 확인한다. server TLS probe의403은 클라이언트 ACL에 의한 결과일 수 있어 외부 허용 클라이언트 검증을 대신하지 않는다.

완료된 동일 프로필의 `--apply`는 재검증만 수행한다. service schema1~6, security schema1, 기존 수동 설치를 숫자만 바꿔 이관하지 않는다. SIEM 준비 `siem.json`의 `schema_version: 1`은 별도 입력 형식이므로 바꾸지 않는다. 이미지·룰·주소·키·소스 변경은 별도 검토가 필요하며 `changed_inputs`, 부분 설치, 파일 해시 오류를 없애려고 manifest·receipt·DB 볼륨을 삭제하지 않는다.

현재 확인한 코드/모의 회귀 및 기존 C sudo 번들의 실제 정적 서명 검증은 **새 VM 3대 전체 설치 성공과 별개**다. 새 환경의 `--apply`, `--verify`, 허용 클라이언트 접속을 실제 수행한 뒤 해당 범위만 인수 기록에 남긴다.


</details>

<a id="source-6da49272bde6c9e3"></a>

## deployment-bootstrap-guide-before-ncsc-20261104.md

<details>
<summary>당시 기록 펼치기 · 2026-11-04T19:18:25+09:00</summary>

<a id="source-6da49272bde6c9e3-h0"></a>
<a id="record-a5edb1fb42eb9084fa00c0da6e56136df0aaf5bd23305f04446a0adb7139556e"></a>

# 단일 Bash 초기 설치

> **2026-11-04 현행 웹 제어:** 공개 열람은 `LAB_ALLOWED_CIDRS`, 실습 실행·중지·터미널은 `MANAGEMENT_ALLOWED_CIDRS`에서 설치한 관리자 CIDR과 HMAC 인증이 모두 필요하다. UI/API 포함4개 경로는 WAF On을 유지하며 이전 검사 예외는 제거했다. 기존 운영은 [증분 유지보수/복구](../infra/validation/web-policy/README.md)를 따른다. 아래 날짜별 예외 설명은 과거 이력이다.

> 2026-10-29 차단 예외: RFC1918 전체는 기본 보호하지 않는다. `LOG_PROTECTED_IPS`의 정확한 필수 주소와 `ADMIN_PROTECTED_CIDRS`의 명시적 관리 범위를 보호한다. 예제의 관리자 `211.170.162.85`는 기존 승인된 campus /24에도 포함된다. SSH 허용은 `MANAGEMENT_ALLOWED_CIDRS`, Wazuh HTTPS는 `DASHBOARD_ALLOWED_CIDRS`로 별도 설정한다. 운영 서버 전체 재설치는 하지 않는다.

> **2026-10-26 학과망 관리 예제:** 현장 `211.170.162.0/24` 정책은 `ADMIN_PROTECTED_CIDRS`, `MANAGEMENT_ALLOWED_CIDRS`, `DASHBOARD_ALLOWED_CIDRS`에 각각 명시한다. 세 값은 차단 예외·SSH·Wazuh라는 서로 다른 권한이다. 새 환경에서는 실제 관리 대역으로 교체하며 기존 A의 증분 설정을 초기 설치기로 덮어쓰지 않는다. 추가 패키지·오프라인 바이너리는 없다.

> **2026-10-26 실습 웹 공개 설정:** `LAB_ALLOWED_CIDRS=all`은 실습 HTTPS의 모든 출발지를 허용한다. 기존 CIDR 목록 방식과 사설 /29 프록시 충돌 검사는 유지하며 입력을 생략해 자동 공개하지 않는다. 콘솔의 기존 목록·시작/중지·터미널 경로도 이 웹 접근 범위에 포함된다. WAF 예외 키·세션, SSH·Wazuh·MCP의 별도 정책은 그대로다. 추가 패키지/이미지는 없고 기존 소스 반입 목록에 포함된 `validate_lab_site.py`, `offline_security.py`, `nginx-log4shell-server.conf`로 재현한다. 새 서버 전체 설치 검증과 기존 A의 ACL 증분 적용은 구분한다.

> **2026-10-26 감시 단계:** 기존 진단 및 선택 Ollama 구성 뒤 `monitor-configure/prepare/authorize/trust/activate/verify` 내부 단계를 루트 deploy.sh가 호출한다. A→B/C 전용 snapshot 키·기존 HTTPS SiteURL/CA·웹훅 스트림을 연결한다. 새3VM 전체 설치 성공 여부는 운영 증분 검증과 구분해 [STATUS](../STATUS.md)에 기록한다. [감시 상세](../infra/mcp/monitoring.md).

> **2026-10-25 선택적 시험 분기:** `OLLAMA_TRIAL_ENABLE=1`과 `OLLAMA_TRIAL_BUNDLE`을 지정하면 B의 반입물을 사전검사하고 SOC/진단 구성 뒤 host venv의 Ollama 기반 읽기 실행부를 설치·검증한다. 모델은 DGX에 유지한다. `OLLAMA_TRIAL_CHAT_ENABLE=1`을 함께 지정하면 ollama 봇과 비공개 soc-ollama 채널·host gateway 서비스도 추가하며 기존 Hermes 채널 ID를 유지해 soc-hermes로 이름 변경한다. 두 옵션 기본값0이며 기존 운영 서버에는 전체 bootstrap을 재실행하지 않는다. [추가 반입·권한·복구](../infra/ollama-trial/README.md), [실제 검증 범위](../STATUS.md).


<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 사용자 진입점은 루트 deploy.sh 하나이고 service schema9·HTTP3/터미널3·MCP6서버/고정 진단을 연결한다. 새3VM 전체 설치 시험은 사용자 제외 범위를 유지하며 기존 운영 서버를 초기 설치기로 덮어쓰지 않는다. 이번 운영 보완은 별도 최소 이관이다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

새 Ubuntu 24.04 amd64 서버 3대의 진입점은 저장소 루트의 `deploy.sh` 하나다. 서버 주소, SSH 접근, 관리자 승인된 오프라인 반입 파일을 준비한 후 다음 한 번으로 패키지·이미지 준비와 역할 설치·검증을 실행한다.

```bash
bash deploy.sh --apply --batch --config deployment/site.local.conf
```

`deployment/config.example.conf`를 로컬 전용 `site.local.conf`에 복사하고 실제 주소·HTTPS 이름·허용 내부망을 입력한다. 비밀번호를 이 파일에 넣지 않는다. 전체 저장소가 필요하며 `deploy.sh`만 따로 복사해서 실행하는 방식은 아니다. 내부 Python/Bash helper는 진입점이 자동으로 호출한다. Mac에는 패키지를 설치하지 않는다.



<a id="source-6da49272bde6c9e3-h1"></a>
<a id="record-29430b68b17142f387e3a5021481188521507ecdd9f43943746b2777dc4c8d09"></a>

## 2026-10-24 보안 경계와 오프라인 준비

패키지 다운로드는 외부 준비 환경에서만 수행한다. 대상 서버에는 서명/해시를 검증한 deb와 의존성을 반입하고, 설치기는 전용 임시 캐시·빈 저장소 목록·`--no-download --no-remove`로 설치한다. Mac에는 패키지를 설치하지 않으며 반입/해시 확인 후 작업용 deb를 삭제한다. [반입 목록과 버전 기준](setup-packages-artifacts.md)을 함께 준비한다. host sudo 최소 `.4`, SIEM nginx 최소 `1.24.0-2ubuntu7.18`을 검사한다.

SIEM 기본 구성 뒤 전용 비권한 nginx가 **8444→같은 호스트 Mattermost8065**, **8445→loopback 승인8090** TLS를 제공한다. 기존 SIEM CA로 전용 DNS/IP 인증서를 만들며 CA 개인키는 SIEM에만 남긴다. 공개 CA만 SSH 파이프로 security의 운영체제 신뢰 저장소에 전달한 후 SOC 연결을 시작한다. SIEM의 일반 nginx 기본80 서비스는 masked로 유지한다. 최종 `--verify`에는 TLS와 호스트 격리가 포함된다. 기존 운영 A의 채팅/대시보드 프록시도 CA·이름 검증을 사용한다.

`MANAGEMENT_ALLOWED_CIDRS`는 SSH 원천, `DASHBOARD_ALLOWED_CIDRS`는443, `CHAT_ALLOWED_CIDRS`는8444 클라이언트를 지정한다. 대시보드의 `DASHBOARD_DENIED_CIDRS`(기본 VPN192.168.15.0/24)는 허용 목록보다 먼저 적용한다. 웹 허용 값이 비면 직접 클라이언트 접근을 열지 않고 security 프록시/필수 내부 통신만 허용한다. 인증된 설치 SSH 원천은 자동으로 보존한다. `ADMIN_PROTECTED_CIDRS`는 IP 차단 예외이며 SSH/웹 권한으로 확대하지 않는다. 새 공개 CA를 사용자 단말에 신뢰시키는 절차는 서버 간 CA 전달과 별개다.

SIEM은 서비스 C에서 agent1514/1515만 받고, Indexer9200/API55000/기존HTTP관리포트는 물리 서비스망에 개방하지 않는다. C의 기존 Docker 기본 bridge는 스스로 관리 영역 연결을 시작할 수 없으며 security에서 들어온 허용 서비스 응답만 허용한다. dedicated 실습 guard와 Docker 체인은 유지하고 별도 inet 테이블만 관리한다. 기존 Java의 임의 외부/JNDI 연결을 다시 여는 시나리오는 별도 승인·격리 설계가 필요하며 현재 CVE 재현 보류를 해제한 것이 아니다.

`resp`는 인자 없는 root MCP 진입점만 sudo 실행한다. root 전용 설정과 승인 검증을 거친 private helper만 실행하며 하위 차단 helper의 직접 sudo는 허용하지 않는다. 승인 일회성 소비·보호 주소·소유권·TTL을 유지하고 LLM에 일반 sudo/Docker·패키지 권한을 주지 않는다.

A의 필수 WAF·Suricata와 TLS 프록시는 재부팅 때 복구되도록 `restart: always`를 사용한다. 운영 중 `docker stop`은 멈추지만 daemon/호스트 재시작 시 돌아온다. 장기 중지는 관리자가 해당 정확한 CID의 재시작 정책을 `no`로 지정한 뒤 중지한다. 실습/백업의 기존 중지 정책은 유지한다. [Docker 공식 정책](https://docs.docker.com/engine/containers/start-containers-automatically/)을 따른다. 현재 기존 서버의147 부팅·최초 실패/복구·후속 통과와 새3VM 전체 설치 미실행은 [STATUS](../STATUS.md)에서 구분한다.



<a id="source-6da49272bde6c9e3-h2"></a>
<a id="record-0f5f69d5e15cf137ab69ee19485db85da206a08aa34f10b47df7e4d90bf62e90"></a>

## 실행 순서와 범위

관리 controller와 gate, 진단 MCP는 같은 원본 소스에서 렌더한다. 초기 사건 DB는 run별 `report_outbox`를 함께 만들며, 기존 운영 서버의 최소 이관은 원본 SHA·유휴 상태·root 복구/DB 백업을 먼저 확인하고 빈 전달 테이블만 추가한다. 과거 사건·대화나 미전달 보고를 초기화·자동 재전송하지 않는다. 전송 실패·모델 불완료 알림과 `--no-deliver` 의미는 [진단·보고 계약](../infra/mcp/system-diagnostics.md)을 따른다. 추가 패키지·포트·자격은 필요하지 않다.

1. 입력과 검증된 SSH host key를 확인하고 서버 3대의 machine-id가 서로 다른지 확인한다.
2. 각 서버의 `/opt/capstone-prereqs/artifacts.json`과 모든 파일 해시를 검사한다. 하나라도 다르면 패키지 설치 전에 중단한다.
3. 승인된 로컬 `.deb`를 `apt-get --no-download --no-remove`로 설치하고 Docker save archive를 `docker load`한다. 지정하지 않은 추가 패키지, 다운그레이드, 기존 이미지 태그 충돌을 거절한다. SIEM의 `vm.max_map_count`가 부족한 경우 전용 설정 파일로 최소262144를 적용한다.
4. 준비된 상태에서 security·siem·service 역할을 모두 사전검사한다. 역할 충돌, 포트 충돌, 자료 누락이 있으면 서비스 설치 전에 중단한다. 이 단계의 실패 시 앞 단계에서 설치한 패키지는 유지한다.
5. SIEM을 설치·검증하고 등록 CA·암호를 두 agent 서버로 전달한다. Wazuh Dashboard의 `admin` 암호(`siem.json`의 `indexer_password`)는 SSH 파이프로 service의 root0600 파일에 직접 전달한다. Mac 파일·명령 인수·로그에는 저장하지 않는다.
6. service에 독립 DVWA/MariaDB, FastAPI 콘솔·제한된 Docker broker·nft guard, 전용 Nginx gateway, 별도 sudo rootless 환경과 Redis·Samba·sudo 웹 터미널 서비스, Wazuh agent를 구성한다. 콘솔 계정 생성과 sudo 준비 다음에 별도 nonweb bundle을 검증·반입한다.
7. security에 Suricata·기존 DVWA WAF와 별도 Log4Shell TLS 진입점을 구성한다. 관리·예외 키 인증은 콘솔에 직접 연결하고, 고정된3개 실습 경로만 WAF를 지난다. 일반 요청은 규칙에 걸릴 때 차단하며 유효한 예외 세션은 감사 로그를 유지한다.
8. SIEM의 비권한 내부 TLS8444/8445를 설치하고 공개 CA만 security에 전달·신뢰시킨 뒤 SOC를 구성한다. SIEM이 생성한 Mattermost 관리자 ID를 승인자로 고정하고 승인 브로커·정확 후보 worker·규칙 MCP·제한된 응답 MCP·Native AR 사건 전달을 구성한다. 전용 토큰은 B→A SSH 파이프로 전달하며, 승인자 암호를 MCP에 배포하지 않는다. 관리용 SSH는 고정 명령과 검증된 host key만 사용한다.
9. Vector0.59.0 정제·원본 세대 회전·출력 유지관리·이전 부트 로컬 보관을 구성하고, 실제 등록 agent ID에 결속한 Indexer 상관관측 모니터를 추가한다. 관측 모니터의 `actions`는 비어 있으며 자체 차단을 실행하지 않는다.
10. 통합 SOC 대시보드의 14개 패널을 구성한다. 기존 saved object와 내용이 충돌하면 덮어쓰지 않고 중단한다. 없는 객체만 생성하고 전체 내용을 재조회한다. 그 뒤 Hermes 관리 경로를 활성화한다.
11. 세 호스트에 고정 읽기 진단 수집기를 설치한다. root 수집기가60초마다 systemd 상태와 분류한 오류 메타데이터만 게시하고, B의 비권한 MCP는 로컬 snapshot 또는 A/C의 강제 snapshot reader를 읽는다. 새 전용 키의 공개키만 A/C로 전달하고, 기존 관리자·대응용 키는 재사용하지 않는다. SSH host key는 기존에 검증한 배포 SSH 경로로 받아 별도 known_hosts에 고정한다.
12. service/siem의 별도 host guard를 적용하고 인증된 SSH 원천을 보존한다. 기본 역할과 SOC 확장의 파일·이미지·컨테이너·서비스·승인 경계, 세 호스트 진단 snapshot·MCP 호출, 내부 TLS와 host guard를 최종 검증한다. 임시 전송 폴더를 정리한다. 실패 시 부분 설치 상태와 서버의 복구 자료를 남기고 임의 덮어쓰기·전체 삭제를 하지 않는다. 대시보드의 아직 완료되지 않은 동일 내용 생성만 제한적으로 재개할 수 있고, 다른 확장 부분 설치는 검토 없이 재시도하지 않는다.

카탈로그는 웹 실습3개와 Redis·Samba·sudo 터미널3개로 총6개다. 준비된 로컬 이미지만 사용하며 사용자가 콘솔에서 시작한 뒤 웹 화면 또는 같은 사이트의 터미널을 연다. 웹3개와 Redis/Samba는 초기 설치 중 시작하지 않는다. sudo 초기 bootstrap은 패키지·격리 검증을 위해 한 번 기동하며, 이후 중지 상태도 정상 설치로 검증한다. 터미널은 고정된 해당 실습 컨테이너에만 연결하며 호스트 셸·임의 Docker API·LLM 권한을 추가하지 않는다. sudo는 별도 UID1991 rootless 런타임을 유지하고 중앙 터미널의 고정 어댑터로만 연결한다. sudo 터미널은 전체 사용자 중 한 연결만 허용하며 연결 종료·입력 유휴/수명 만료 때 해당 sudo 컨테이너 전체를 중지한다. Redis/Samba 세션과 다른 실습은 중지하지 않는다. DVWA는 `http://SECURITY_HOST:WAF_PORT/dvwa/`, 콘솔·실습 페이지는 `LAB_PUBLIC_ORIGIN/log4shell/` 아래다. DVWA를 Log4Shell 메뉴에 다시 추가하지 않는다.

`--plan`은 로컬 입력만 확인한다. `--check`는 반입물과 역할 조건을 검사하되 패키지·이미지·서비스를 설치하지 않으므로, 아직 패키지가 없는 빈 서버에서는 누락을 보고할 수 있다. `--verify`는 이미 관리 중인 동일 구성의 검증만 수행한다. 기존 운영 GROOT 서버를 신규 설치 대상으로 인수하지 않는다.

읽기 진단은 `get_system_diagnostics` 하나만 추가한다. 대상은 소스에 고정한 A/B/C 서비스 ID이며 경로·호스트·unit명·명령을 호출자가 지정할 수 없다. 수집한 snapshot은 `/var/lib/capstone-diagnostics/snapshot.json`의 root 소유0640 파일이고 TTL은180초다. 오류 조회의 최대4시간은 상한이 있는 수집 표본이며, 원본 journal 본문·환경변수·명령행·비밀값은 MCP 응답에 넣지 않는다. 누락되거나 중지된 unit도 관찰 결과로 표시하고, 자료 만료나 검증 실패를 정상으로 간주하지 않는다. 신규 설치는 전용 계정·unit·키·receipt를 자동 구성한다. 기존 운영 서버의 이 진단 확장만 추가하는 작업은 별도 원본 SHA 확인·복구 백업·변경 검증 경로를 사용하며 전체 초기 설치기를 다시 실행하지 않는다.

A/C의 진단 SSH 계정은 공개키 인증과 고정 `read-snapshot` 실행만 허용한다. wrapper는 원격 명령·추가 인수를 거절하고 빈 환경으로 reader를 실행한다. 설치기는 `sshd -t`와 계정별 effective 정책을 확인하며, 전역 `PermitUserEnvironment no`·`UsePAM yes`가 충족되지 않으면 SSH를 reload하지 않고 중단한다. 전역 전용 지시문을 `Match` 안에 넣거나 기존 전역 인증 정책을 자동 변경하지 않는다.



<a id="source-6da49272bde6c9e3-h3"></a>
<a id="record-8b9d0d3b5e80dc0e0a1866b388ae98ec786be54bf19c3eab3bf7da4a3ee18443"></a>

## 폐쇄망 반입물

모든 자료는 해당 서버의 `/opt/capstone-prereqs` 아래 root 소유·그룹/기타 쓰기 금지 경로에 둔다. 자격 JSON·TLS 개인키·공통 예외 키는0600이다. manifest의 해시는 **관리자가 승인한 파일의 동일성**을 검증한다. 그 자체가 공급자 서명 검증을 대신하지 않는다. 외부 준비 서버에서 공식 출처·저장소 서명·버전·라이선스를 검토하고 반입 대장을 보존한다.

`artifacts.json`은 다음 형식이다. 예시는 구조 설명이며 `REVIEWED_*` 자리에 실제 검증값을 입력해야 한다. 역할마다 파일이 다르다. 배열이 비어 있으면 이미 설치된 패키지·이미지를 사용하며 역할별 버전 검증은 그대로 실행한다.

```json
{
  "schema": 1,
  "role": "service",
  "packages": [
    {"file":"example_1.0_amd64.deb", "sha256":"REVIEWED_64_HEX",
     "package":"example", "version":"1.0", "architecture":"amd64"}
  ],
  "images": [
    {"file":"java-lab.tar", "sha256":"REVIEWED_64_HEX",
     "tag":"groot-labs/log4shell:2.14.1", "image_id":"sha256:REVIEWED_64_HEX"}
  ]
}
```

파일은 manifest 옆의 평면 파일명이며 하위 경로·symlink·중복 항목을 받지 않는다. 패키지 전이 의존성도 전부 반입한다. `dpkg-deb -f FILE Package Version Architecture`, `sha256sum FILE`, `docker image inspect --format '{{.Id}}' TAG`로 확인한 값을 입력한다. 대상 서버에서 `apt update`, `pip install`, `docker pull`을 실행하지 않는다.

온라인 Linux 준비 서버의 이미지 반출 예:

```bash
# 먼저 공식/검토된 원본으로 이미지 준비 및 native amd64 확인을 완료한다.
docker image inspect --format '{{.Id}} {{.Os}} {{.Architecture}}' groot-labs/log4shell:2.14.1
docker save --output java-lab.tar groot-labs/log4shell:2.14.1
sha256sum java-lab.tar
# 오프라인 호스트의 artifacts.json에 태그·정확한 image ID·archive SHA를 기록한다.
# deploy.sh --apply가 아래와 동일한 로컬 load를 자동 수행한다.
# docker load --input /opt/capstone-prereqs/java-lab.tar
```

필수 준비 범위:

| 서버 | 패키지·이미지 외 자료 |
|---|---|
| 공통 | Ubuntu24.04 amd64·systemd·Python3.12·SSH/sudo 및 검증된 host keys. Docker Engine/CLI/Compose·관리 명령은 로컬 deb로 설치 가능 |
| SIEM | 기존 [SIEM 준비 목록](setup-packages-artifacts.md)의 Wazuh 원본 tree, `siem.json`, Python bcrypt, Wazuh/Mattermost/PostgreSQL/Hermes 이미지와 관련 소스 |
| service | Wazuh agent4.14.8, Docker29.8.1/CLI, uidmap·libsubid4·dbus-user-session·AppArmor·nftables·gpgv; DVWA/MariaDB/WAF 이미지; 아래6항목 카탈로그와3개 관리형 웹이미지; 전체 lock wheel 디렉터리; 고정 sudo bundle 및 Redis·Samba nonweb bundle |
| security | Wazuh agent4.14.8, Vector0.59.0 로컬 deb와 전이 의존성, Suricata8.0.6/WAF 이미지, jq·logrotate·util-linux·nftables, 검증한 ET Open 룰, 지정 DNS 이름의 TLS 인증서·개인키, 접속 허용 내부망/VPN CIDR |

콘솔 wheel은 [prepare-python.sh](../infra/groot-c/offline-labs/scripts/prepare-python.sh)의 Ubuntu/Python3.12 amd64용 전체 목록과 해시를 사용한다. 카탈로그는 [cve_list.json](../infra/groot-c/offline-labs/cve_list.json), 웹이미지 반출입은 [offline-labs README](../infra/groot-c/offline-labs/README.md)를 따른다. sudo는 [고정 rootless bootstrap](../infra/groot-c/offline-labs/nonweb/sudo/runtime/BOOTSTRAP.md)의 별도 서명 증빙까지 필요하다. sudo의 준비 JSON만 보고 서명 검증을 생략하지 않는다.

Redis·Samba 자료는 `LAB_NONWEB_BUNDLE`(기본 `/opt/capstone-prereqs/nonweb`)에 둔다. [nonweb 준비 안내](../infra/groot-c/nonweb-labs/README.md)의 `manifest.json`, `provenance.json`, `redis-image.tar`, `samba-image.tar` 정확4개와 이미지·archive 해시를 검증한다. 이 자료는 웹이미지 반출입 목록과 분리하며, 신규 `--check`는 계정·컨테이너·서비스를 생성하지 않는다. `--apply`는 `/opt/capstone-nonweb-labs` 관리 소스와 고정 root Unix socket 서비스를 구성하고 두 실습 컨테이너는 시작하지 않는다. 완료된 동일 구성의 재실행은 검증만 하고, 부분 설치·출처 충돌은 임의 인수하지 않는다.

service schema는 **9**다. `LOG4SHELL_IMAGE`, `LOG4SHELL_APP_JAR`, `LOG4SHELL_HOSTNAME`의 구형 직접 Java Compose 옵션을 거절한다. 현재 콘솔은 검증·반입된 이미지 ID로 실행한다. 기존 JAR 빌드 도구는 이미지 준비 용도로 보존한다. 구형 schema6·7·8 설치는 명시적인 별도 이관이 필요하며 새 설치기로 덮어쓰지 않는다. source profile과 완료 receipt는 `terminal_api.py`, 재귀적인 static 파일·로컬 xterm 자산·favicon, sudo 및 nonweb 관리 코드를 함께 검증한다.



<a id="source-6da49272bde6c9e3-h4"></a>
<a id="record-2ae2d726266b3d6d94fca0dff4a9f01136b500a2fb9b25de500a75bc58906871"></a>

## 검증과 운영 변경 원칙

셸 구문·컨트롤러 가상 SSH 순서·입력/반입물 위변조·역할 생성물·초기 설치 실패/재실행·고정 권한 계약을 자동 시험한다. 기존 운영 서버의 웹·HMAC·WAF canary·sudo 환경 검증과 **새 VM3대 전체 설치 검증**은 별개다. 새 설치 경로의 실제 VM 전체 적용은 아직 실행하지 않았다. 신규 VM에서 `--apply`와 허용 클라이언트 HTTPS 접속까지 통과한 이후에만 실제 설치 검증 완료로 기록한다.

SOC 연결의 설치 코드는 포함하되, 이 변경의 새 VM 설치 시험은 사용자 요청으로 제외했다. 구문·격리 회귀 통과와 실제 서비스 기동·공격 E2E 성공을 구분한다. 최초 빈 인덱스에는 최소 필드 메타데이터를 사용하므로 대시보드 생성 성공만으로 실제 탐지 데이터나 화면 렌더링까지 검증했다고 표시하지 않는다.

내부 단계·권한·부분 실패와 재실행 계약은 [SOC 관리 확장](SOC_MANAGEMENT.md)과 [로그 처리 모듈](log-pipeline.md)에 기록했다. 이번 소스와 로컬 검증 결과는 [SOC 설치기 검증 기록](soc-bootstrap-validation-20261023.json)으로 구분해 보존한다.

`LOG_PROTECTED_IPS`는 추가 보호 IPv4의 쉼표 목록이다. 세 서버와 IP로 지정한 LLM은 자동 합집합으로 포함한다. LLM을 호스트명으로 지정하면 그 서버의 승인된 실제 IP를 명시해야 하며 설치 중 DNS로 추정하지 않는다. 관리·VPN 인프라 주소도 이 목록에 포함한다. 기존 대응 정책의 비공개/예약 주소 보호를 유지하므로 내부 실습 출발지의 실제 IP 차단 허용 범위를 이 설치기가 임의로 넓히지 않는다.

관리자 차단 예외는 별도 선택 항목 `ADMIN_PROTECTED_CIDRS`다. 대화형 초기 설정에서 다음처럼 묻고, 값이 없으면 Enter로 넘어간다. 설정 파일에 빈 `ADMIN_PROTECTED_CIDRS=`를 적거나 batch 모드에서 생략해도 추가 예외 없이 진행한다.

```text
차단 예외 관리자 IPv4 또는 CIDR 대역 (쉼표 구분, 없으면 Enter): 192.168.10.25,192.168.15.0/24
관리자 IP 차단 예외: 192.168.10.25/32,192.168.15.0/24
```

단일 IP는 `/32`로, 호스트 비트가 있는 대역은 실제 네트워크 주소로 정리하고 중복·포함 범위를 합친다. 값은 서버 프로필과 nft `never_block`에 저장하고, LLM 임시 차단·관리자 승인형 IP 차단의 실행 전에도 검사한다. 관리자 대역의 탐지·원본 로그 수집은 계속 수행한다. 이 항목은 HTTPS 접속 허용망 `LAB_ALLOWED_CIDRS`나 WAF 요청 검사 예외 세션과 별개다.

운영망 FORWARD/NAT/VPN/DNS 자체, 공개 인증서 발급·채팅 HTTPS, 기존 SOC의 수동 이력·기존 승인 DB, A→B 이전 로그 전송, 긴 장애 구간의 무손실 회수·일반 백업·실제 공격 E2E는 별도 범위다. Suricata는 수동 탐지 모드를 유지하고 제한된 별도 nft 대응 경로를 사용한다. LLM에 일반 sudo/Docker·패키지 설치 권한을 부여하지 않는다.

앞으로 서버 변경을 수행하면 같은 작업에서 `deploy.sh`의 역할/helper·반입 목록·설정 예제·검증을 갱신한다. 운영 서버 재설정과 신규 설치는 구분한다. 상시 서버 감시나 소스 자동 작성 데몬은 추가하지 않는다.



<a id="source-6da49272bde6c9e3-h5"></a>
<a id="record-4fd4f9b20eb9d1f3ba5d3a4108b70774c7c251d2e238846ec238f264a69beb57"></a>

## 채널 참여와 자동 보고 발신자 (2026-10-26)

초기 Hermes 채널은 soc-hermes, 보고 채널은 soc-alerts-agent다. SOC 설치는 non-admin soc-report 봇과 그 봇 소유의 채널 고정 웹훅을 생성하며, 관리자 계정과 발행자를 분리한다. Ollama 채팅 선택 시 공개 soc-ollama와 공용 보고채널 멘션을 연결한다. 두 봇의 자동 참여는 채널 표시 이름 끝의 -agent/-hermes/-ollama 기준이다. 공통 동기화 소스와 deployment/report_publisher.py는 기존 소스 묶음에 포함된다. 추가 deb/wheel/이미지/포트는 없다. 실제 새 VM 전체 설치 검증은 이번 라이브 증분 검증과 별개다. [사용·현재 완료 범위](../infra/hermes/chat-channels.md).




<a id="source-6da49272bde6c9e3-h6"></a>
<a id="record-eedc495533c57eac0cc731c09d074812ebb32325089ce995eb7f3de4edd4e446"></a>

## 선택적 공동 채널

두 봇의 직접 요청·상호 검증 채널을 함께 설치하려면 기존 `OLLAMA_TRIAL_ENABLE=1`, `OLLAMA_TRIAL_CHAT_ENABLE=1`과 `SOC_REVIEW_CHAT_ENABLE=1`을 설정한다. 단일 진입점 `deploy.sh`가 Ollama 채팅 확인 뒤 `deployment/review_chat.py`를 호출한다. 새 서버 설치 옵션이며 운영 서버에는 초기 설치를 다시 실행하지 않는다.

반입 소스에 `infra/hermes/review_channel.py`, `review_channel_policy.py`, `review_channel_worker.py`와 `deployment/review_chat.py`를 포함한다. 기존 공통 `read_contract.py`·query 근거 모듈·Ollama SDK를 재사용하며 추가 deb/wheel/이미지/수신 포트는 없다. 전용 systemd 서비스·root 대기열을 만들고, Ollama 모델 작업은 기존 비특권 계정으로 실행한다. Hermes는 고정 UID의 기존 관리 gate를 사용한다. 봇 토큰은 분배기만 읽고 모델에 전달하지 않는다. 기존 보안 룰·관리자 승인 경계는 유지한다.

서비스/파일 SHA와 현재 PID의 heartbeat 검사는 새 서버 전체 설치 시험을 대신하지 않는다. 실제 완료 범위는 [STATUS](../STATUS.md), 채널 사용은 [채널 안내](../infra/hermes/chat-channels.md)를 따른다.

2026-10-26 관리 제어기 보완은 기존 `deployment/soc_runtime.py`의 canonical 제어기/gate 렌더링과 `deployment/review_chat.py`의 실행부 반입 경로를 사용한다. 새 패키지·이미지·포트는 추가하지 않는다. 관리 제어기와 공동채널 worker를 함께 맞추며, 시간 계산 도구를 감사 대상으로 허용하되 실제 서버 관측으로 인정하지 않는다.


</details>

<a id="source-252038d31234088c"></a>

## deployment-README-before-ncsc-20261104.md

<details>
<summary>당시 기록 펼치기 · 2026-11-04T19:18:25+09:00</summary>

<a id="source-252038d31234088c-h0"></a>
<a id="record-810260cf195a4a75570f7e97f2b2b1d872af0842e88a8c601c86f37c3e80f79a"></a>

# 초기 설치기의 Hermes 확장

11/3 조기 해제 재차단 보완은 기존 root `deploy.sh` SOC source bundle의 `incident_containment.py`·`soc_agent_block.py`·`soc_alert_watch.prompt`를 갱신한다. 확인된 해제+60초/자연 기한+60초와 종료 이후 새 공격 근거를 적용하고 WAF 사건에 Native IDS를 추가 요구하지 않는다. 운영에는 재시작 없는 SHA 대조 증분 반영이며 새 서버 전체 설치 시험과 구분한다. 추가 오프라인 바이너리·키·포트·MCP 권한은 없다. [원인·검증·복구](../infra/mcp/containment-reblock.md).

11/3 역할 배정1.1.0은 기존 루트 `deploy.sh`의 공동 채널 source 묶음(review_channel.py/review_channel_policy.py)과 Ollama·review 채널 안내에 반영한다. 추가 deb/wheel/이미지/포트/설정 키/권한은0이며 기존 SOUL·운영35B·endpoint를 유지한다. 운영은 idle/CAS 복구본을 둔 증분 적용이고 새 서버 전체 설치는 별도 미검증이다. [사용·설치·복구](../infra/hermes/agent-deployment.md).

11/3 공통 계약1.5.14는 기존 루트 `deploy.sh`의 Ollama source bundle과 SIEM Hermes 플러그인 복사 경로에 반영한다. canonical `infra/ollama-trial/harness.py`·`infra/hermes/chat_contract.py`가 두 봇에 배치된다. 운영은 SHA를 대조한4파일 증분 적용으로 검증했으며 새 서버 전체 설치는 미실시다. 추가 패키지·이미지·설정 키·MCP·공개 포트는 없다. [단문진단·스키마·근거 검사와 복구](../infra/hermes/diagnostic-harness.md).

11/2 WAF 원본 임시차단 보완은 기존 SOC source bundle에 `managed_waf_evidence.py`·공통 reader·운영자 전용 `configure_waf_evidence.py`와 최신 자동 조사 prompt를 포함한다. 추가 오프라인 바이너리·포트·키는 없다. 검증된 managed 원본·producer v2·전용 프록시와 root SHA manifest가 필요하며, 코드 설치만으로 이 전제까지 완료됐다고 표시하지 않는다. [구성·복구·새 서버 미검증 범위](../infra/mcp/waf-containment.md).

> **2026-10-31 카드 조사·진행 표시:** `deploy.sh`의 SIEM 설치 경로에 `progress.py`와 Mattermost 진행/cleanup 설정을 포함한다. security-events4읽기 도구와 SDK 기본32/parity41도구 계약을 동기화한다. 기존 패키지·포트·키를 사용하며, 운영 증분 반영과 새 서버 전체 설치 시험은 구분한다. [동작·복구](../infra/hermes/card-investigation-progress.md) · [현재 상태](../STATUS.md).




<a id="source-252038d31234088c-h1"></a>
<a id="record-88c6f03b65536d93de22f99872bc0a3321b52d0a445504afb7e571ff46c91cbd"></a>

## 2026-10-31 단문·systemd 호스트 작업 소스

`deploy.sh`의 기존 진단/관리/Hermes/Ollama 설치 경로에 공통 단문 계약1.5.7·query1.17.0, 현재 failed 집계3대상, A Vector·A/B Wazuh host-agent 승인형 restart를 함께 반입한다. SOC renderer는 systemd 프로필을 컨테이너 ID 바인딩에서 제외하고 관리 gate/controller의 대상 목록을 동기화한다. SOUL·source pin·어댑터·context 소스도 함께 배치한다. 기존 키·계정·포트·deb/wheel/image 목록은 유지하며 **추가 오프라인 바이너리0**, 갱신 소스가 반입 대상이다. 운영은 root 백업 후 증분 적용이며 새3VM 전체 설치 시험은 미실시. [사용/복구/검증 구분](../infra/mcp/host-service-actions.md) · [현황](../STATUS.md).

> **2026-10-31 사건 판단 정정:** 기존 `deploy.sh` 소스 경로로 query-completion1.15.7/chat-contract1.5.2와 두 봇 공통 하네스를 설치합니다. B 운영 파일과 오프라인 source cache를 동기화했으며 새 패키지·포트·설정 키는 없습니다. 운영 증분 반영과 새 서버 전체 설치 검증은 구분합니다. [동작·복구·검증](../infra/hermes/incident-judgment-repair.md).

> **2026-10-29 FW 읽기:** root `deploy.sh`의 기존 SOC/두 봇 소스 경로에 전체 FW 조회를 포함했다. 응답 MCP 4도구 계약과 공통 38도구 허용 목록을 사용한다. 신규 설정 키·포트·패키지는 없다. [설치·오프라인·복구 범위](../infra/mcp/firewall-read.md) · [검증](../STATUS.md).

> **2026-10-27 선택 추론 터널:** root `deploy.sh`에 `LLM_TUNNEL_CONFIG`를 추가했다. 기존 OpenSSH/Python/systemd로 B 전용 주소에서 외부 추론 서버의 loopback API에 연결하며 별도 모델·패키지 다운로드나 키 위임을 하지 않는다. [준비·권한·검증·복구](inference-transport.md)와 [실제 운영 상태](../STATUS.md)를 구분한다.

> **2026-10-27 B 호스트 agent:** `deploy.sh`의 SIEM 역할도 검증된 미등록 Wazuh4.14.8-1 deb를 요구한다. manager 준비 후 `siem_host_agent.py`로 별도 host agent 등록·연결을 검증하고 초기 소스 프로필에 포함한다. 응답 서식은 정책 블록 안의 정확한5항목만 추출해 앞쪽 조회 범위 지침이 추가돼도 초기 설치가 실패하지 않는다. 기존 서버에는 초기 설치기를 재실행하지 않는다. 두 봇의 host/manager 구분과 공통38대상 진단을 함께 배포한다. [반입](setup-packages-artifacts.md#오프라인-b-호스트-패키지와-검증) · [검증](verify-troubleshoot.md#b-호스트-수집과-manager-컨테이너-구분).

> **2026-10-27 Ollama 연결 수명:** `deploy.sh`의 기존 Ollama 설치/upgrade 소스 목록에 `infra/ollama-trial/read_pool.py`를 포함한다. 오프라인 반입은 기존 source archive만 갱신하며 deb/wheel/이미지 추가는 없다. `OLLAMA_TRIAL_CHAT_ENABLE=1`의 일반 채팅은 순수 읽기 연결을 최대300초 유휴 유지한다. SSH 설정·키 교체 시 gateway 재시작이 필요하다. 설치 계약/운영 증분 배포와 새3VM 전체설치 미실행 범위는 [STATUS](../STATUS.md)를 따른다.

> **2026-10-27 공통 SSH MAC:** root `deploy.sh`의 security·siem·service 역할에5종 제외·정확한 구4종 정책 이행·충돌 거절·백업/원복·검증을 연결한다. 기존 OpenSSH/Python3/systemd를 사용하며 추가 패키지는 없다. 소스 archive에 `deployment/ssh_macs.py`와 세 역할을 함께 포함한다. 운영 적용은 별도 증분 경로이며 새3VM 전체 설치 검증과 구분한다. [정책·복구](setup-network-ssh.md#세-호스트-공통-ssh-mac-정책--2026-10-27) · [현재 검증 상태](../STATUS.md).

> **10/26 조사 필드 반입:** security-events canonical 소스의 제한된 DNS/HTTP 조사 문맥을 기존 root deploy.sh SIEM 경로가 반입한다. 기존 서버는 해당1파일만 백업 후 증분 적용하며 재시작·새키·포트·deb/wheel/이미지 추가0이다. 기존 내부 MCP 배포기의 도구 목록 검사도 현행3개로 맞췄다. 새3VM 전체설치 검증과 [운영 증분/검증](../STATUS.md)은 구분한다.

> **10/26 22:53 감사 전송 보완:** 기존 소스 반입의 관리 controller/run과 H/O 공통 grounding·핀을 함께 갱신한다. security-events 감사128KiB/사건 식별500건 상한 및 초과 거절, 운영자 사유 전달이 deploy.sh 기존 렌더링에 반영된다. 추가 패키지/이미지/포트0이며 운영 증분과 새3VM전체설치를 구분한다. [검증·Git](../STATUS.md).

> **10/26 사건 종결 검증:** 기존 deploy.sh→SOC 관리 controller 렌더링 경로가 대상 서버별 읽기 도구·후속 변경 참조·SCA 개별 점검 제목과 센서 사건의 출처/출발지/시각/상관 규칙 ID 근거 검증을 함께 반영한다. SCA 특정 인자 오류의 실제 재조회 확인을 포함한 관리139/설치30 검사를 통과했고 운영은 root controller만 증분 교체했다. 추가 패키지·이미지·포트·키0이며 새3VM 전체 설치는 미실행이다. [STATUS](../STATUS.md).

> **10/26 저장소 계측 소스:** 기존 소스 묶음의 `infra/automation/storage-retention/{monitor.sh,monitor-lib.sh,test-native.sh,README.md}`를 함께 갱신한다. lib SHA pin·256개 상한/실패 분류를 기존 고정 A/B 운영 설치에 증분 반영했다. 새 deb/wheel/이미지·포트·키 변경0이며 기존 오프라인 목록을 유지한다. 이 고정 호스트 모듈의 새 서버 bootstrap/전체 설치 검증은 미완료다. [설치 계약](../infra/automation/storage-retention/README.md) · [실측/잔여](../STATUS.md).

> **10/26 사건 조회 소스:** 기존 반입 소스의 `infra/mcp/security-events-mcp.py`, 관리 controller/gate, query-completion 근거핀, Ollama 정책/설치기를 함께 반영한다. SCA는 기존 API 계정의 읽기 권한을 재사용하며 추가 deb/wheel/이미지는0이다. 기본 read-only 설치에도 resp 조회 연결을 포함해 실행부 계약(6서버/28읽기)에 맞춘다. 운영 증분과 새 서버 전체 설치 검증은 [STATUS](../STATUS.md)에서 구분한다.

> **2026-10-26 독립 감시:** 루트 deploy.sh의 진단 연결 이후 A/B/C runtime 수집·A outbox/B 모델·수집 검사와 키 연결을 자동 구성한다. 별도 설치 진입점·패키지·이미지·포트는 추가하지 않는다. [구성·키·제한](../infra/mcp/monitoring.md) · [운영 검증](../STATUS.md).

> **2026-10-25 새 질문 보완 소스1.10.0 / 계약1.3.0:** 장비별 요청 결합·복수 ID·제외/검색 조건·진단 지원 범위 검사는 루트 deploy.sh의 기존 SIEM/Ollama 소스 매핑으로 함께 배치한다. 운영 서버는 root 백업 후 증분 교체하고 실제 Mattermost WebSocket 인증 복귀를 확인했다. 새 deb/wheel/이미지/포트·설정 예제·키/권한 계약 변경은 없어 기존 오프라인 바이너리 목록을 유지하고 갱신 소스를 반입한다. 실제 새3VM 전체 설치는 미실행이다. [검사·운영 검증·한계](../STATUS.md).

> **당시 기록 — 2026-10-25 반복 개선 소스1.9.2:** 루트 deploy.sh의 기존 SIEM/Ollama 설치 경로가 공통 read_contract·harness·계약1.2.2 및 Ollama chat 감사 저장 보완을 함께 배치한다. 기존 오프라인 manifest 바이너리를 유지하고 갱신 소스 전체를 반입한다. 추가 deb/wheel/이미지/포트0이며 설정 예제·키/권한 계약 변경도 없다. 운영은 백업 후 증분 upgrade로 반영했고 실제 새3VM 전체 설치는 미실행이다. [구현·검증 구분](../STATUS.md).

> **2026-10-25 공통 채팅 소스:** 초기 SIEM 설치에 query 플러그인8파일(문맥/훅과 합계13)을 배치한다. Ollama도 같은 정책/근거 소스를 사용하며 읽기90초·보호720초 설정을 연계한다. 추가 패키지·이미지·포트는 없다. 기존 운영은 증분 반영만 수행했고 새3VM 전체 설치는 미검증이다. [전체 파일과 native 차이](../infra/hermes/chat-harness.md) · [현황](../STATUS.md).

> **2026-10-25 봇 프로필:** 초기 Hermes 봇과 선택적 Ollama 봇 생성 시 [동봉 아이콘](bot-icons/sources.json)을 지정한다. `deploy.sh` 소스 archive에 PNG·출처/SHA·라이선스와 `bot_profiles.py`를 포함하므로 서버 외부 다운로드와 추가 패키지는 없다. 운영 기존 계정은 별도 최소 API 갱신으로 적용했으며 새3VM 전체 설치 시험과 구분한다.


> **2026-10-25 Ollama 하네스·동등 권한 재시험 완료:** 같은 DGX qwen3.6:35b와 8서버·36도구(읽기27·보호9)로 실제 채팅을 비교했다. 새 스레드 룰/표 약10초·IDS14.9초·로그14.9초·25대상 진단50.1초, 검증된 같은 스레드 표 재정리0.063초였다. 조회 근거·KST·대상/범위 오류를 보완했으며 전체 진단 지연과 Hermes의 일부 조회 누락은 후속이다. 기존 정확 승인/TTL 경계와 Hermes 자동 관리 controller는 유지한다. 전체 자연어 정확도·보호 실행 E2E·새3VM 설치 완료를 뜻하지 않는다. [결과·한계·Git 상태](../STATUS.md).


> **2026-10-25 설치 동기화:** 루트 `deploy.sh`의 기존 source bundle에 IDS 대상 제한·KST 저장용 플러그인/공용 gate/SOUL과 A/B 룰 MCP의 `time_display`, B 진단 MCP의 `calculate_time`을 포함한다. 진단 설치 probe는 SDK의 `is_error`/`isError` 차이를 처리하고 실제 두 도구·KST 날짜 경계·10분 계산을 검증한다. 추가 deb/wheel/이미지나 오프라인 반입 항목은 없으며 기존 목록을 유지한다. 운영은 별도 최소 교체로 반영했고 새 서버 전체 설치 시험은 미실행이다.

> **2026-10-25 설치 계약:** deploy.sh는 Hermes `timezone: Asia/Seoul`, query-completion 1.6.0의3파일(공용 grounding 포함), 동일 관리 gate·KST 정책·승인 카드·정확한 진단 범위 오류를 반입한다. 현재 조회의 API 문맥 축소와 첫 읽기/간결한 상태 설명 안내를 포함하며 소스 변경은 기존 배포 해시 계약에 반영된다. 추가 패키지 없음. 운영 최소 변경과 새 서버 전체 설치 시험은 구분하며 [STATUS](../STATUS.md)를 따른다.

> **2026-10-24 Memory/읽기 근거 보완:** 초기 deploy.sh가 사용하는 SOUL에 메모보다 현재 관측을 우선하는 원칙을 추가했고 동일 rule/service getter가 현재 명령·결합 파일의 검증 근거를 제공한다. 운영은 root 검토 Memory와 활성 참조만 최소 갱신했으며 신규 서버에 날짜가 고정된 운영 Memory를 심지 않는다. 추가 deb/이미지/포트0,865회귀 통과·새3VM 설치 미실행. 실제 자연어 재질문의 남은 오류/지연은 [STATUS](../STATUS.md)에 구분한다.

> **2026-10-24 현행:** root deploy.sh는 독립 읽기 키·ruleview 계정과 rule-write-a/b를 자동 연결한다. 룰 조회/변경은 서로 다른 경로이며 기존 읽기 도구 이름을 유지한다. 전체 설치 후 논리 MCP8개/35도구다. 새로운 deb/이미지/포트는 없다.47 SOC 렌더/정책 검사와40 SIEM 검사를 통과했으며 새3VM 전체 설치 검증은 제외한다. [현황](../STATUS.md) · [권한 경계](../infra/mcp/README.md).

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 사용자 진입점은 루트 deploy.sh 하나이고 service schema9·HTTP3/터미널3·MCP8논리 서버/고정 진단을 연결한다. 새3VM 전체 설치 시험은 사용자 제외 범위를 유지하며 기존 운영 서버를 초기 설치기로 덮어쓰지 않는다. 이번 운영 보완은 별도 최소 이관이다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

단일 설치 스크립트와 오프라인 반입 준비는 [초기 설치 가이드](bootstrap-guide.md)를 따른다. `deploy.sh --apply`는 승인된 로컬 deb와 Docker save archive를 설치한다. 이미지·패키지를 인터넷에서 다운로드하거나 Mac에 도구를 설치하지 않는다. Hermes 이미지는 [이미지 준비 절차](hermes-image.md)에 따라 외부 Linux 준비 환경에서 먼저 만든다.

2026-10-23부터 기본 SIEM의 읽기 MCP2개 구성 뒤에 승인 브로커·규칙 MCP2개·제한된 응답 MCP·LLM 관리 경로를 연결한다. 설치 검증은 모델 요청·시험 채팅을 발신하지 않지만 마지막에 활성화되는 관리 타이머는 실제 운영 사건을 조사하고 필요한 승인 요청을 수행한다. Vector 정제·보존·상관관측과 통합 SOC 대시보드 설치도 같은 진입점에 포함한다. 아래 조회 플러그인 설명과10/16 실측은 보존하며, 새 VM3대 설치 시험은 사용자 요청으로 제외한다.



<a id="source-252038d31234088c-h2"></a>
<a id="record-470ea158180d6fafe0e652a2c489b8b0db151d407c116b9c25ae021657483408"></a>

## 2026-10-24 일반 채팅 조회 보완

조회 플러그인 소스는1.3.1이며, 첫 요청의 읽기 목록 제한·A/B 대상 enum 축소·일반 현재 룰/표의 해시 연결 집계·부분 조회의 한 번 보완·완전히 검증된 직전 조회의 표 재정리와 근거 시점 표시를 포함한다. 적용·검증 상태와 시간 표본은 [STATUS](../STATUS.md)를 따른다. 실제 도구/인자는 모델이 선택하고 승인형 쓰기·LLM 관리 역할은 유지한다. 아래1.1의 명시적 표 제외와 기본 추론 설명은 당시 기록이며 새 동작은 [플러그인 안내](../infra/hermes/query-completion/README.md)를 따른다.

SIEM 설치기의 조회 플러그인2파일 매핑과 소스 SHA 프로필이 새 바이트를 자동 포함하고 기존6개와 API실행 단계1개를 더한7 native pin을 검사한다. 새 의존성/이미지/포트가 없어 패키지·오프라인 바이너리 추가는 없다. 인증서 pure fixture는 root chown을 실제 실행하는 대신 요구하는5개 `(0,1000)` 소유권 인자를 검사해 Mac에서도 실행된다. 새3VM 전체 설치 검증과 기존 운영 최소 반영은 구분한다.

완전한 파일 집계/검증된 직전 표 재정리는 provider 없이 기존 native 정규화·저장으로 넘긴다. 이 로컬 표시의 단계 수를 실제 모델 호출 수로 세지 않으며, 이름/레벨·원인/분석·원문/변경은 기존 경로다. 현재 조회의 실제 도구 선택·승인 경계를 유지하고 API실행 함수/loop alias까지6alias를 등록·해제한다. 실제 표본/적용과 새VM 제외는 STATUS를 따른다.

장애 조사는 첫 읽기 뒤 원래 승인형 변경안 준비 도구를 보존하며 단순 목록/표의 읽기 제한과 구분한다. 현재 query177+SIEM40 검사는217개이고 실제 새3VM 설치·승인형 변경 E2E를 대신하지 않는다.



<a id="source-252038d31234088c-h3"></a>
<a id="record-4c70482317c88262555ccb6b1e998c5d8fbb37539a4efb6a4a4137413a5fce17"></a>

## 포함 파일과 권한

SIEM 설치기는 기존 Mattermost 문맥 플러그인·공개 채널 동기화 훅 5개 파일에 [조회 응답 보완 플러그인](../infra/hermes/query-completion/__init__.py)의 `__init__.py`, `plugin.yaml`, `alignment.py`, `grounding.py`, `chat_harness.py`, `chat_contract.py`, `soc_policy.md`, `read_contract.py`를 더해 총13개 파일을 배치한다. `plugins.enabled`에는 `groot-mattermost-context`, `groot-query-completion`을 지정한다. 모든 파일은 신규 Hermes 서비스 계정 소유, 파일 `0600`·디렉터리 `0700`이며, 소스 SHA는 배포 프로필에 포함된다. 설치 후 소스가 달라지면 같은 설치의 재검증에서 프로필 불일치로 거절한다.

기본 SIEM 단계의 도구는 Wazuh·security-events 읽기 MCP2개다. 이후 별도 SOC 확장 단계가 정확 후보 승인 도구와 운영 SOUL을 설치한다. 조회 플러그인 자체가 쓰기 권한이나 승인 우회 경로를 추가하지는 않는다.



<a id="source-252038d31234088c-h4"></a>
<a id="record-c9228ec7a3c7e9783b654e77b38b6152e4525dd5603a9ae287cc914736811b88"></a>

## 조회 응답 보완과 버전 검사

새 플러그인은 Mattermost의 한국어 읽기 요청에서 현재 턴의 실제 도구 호출 없이 “조회 중” 같은 진행 약속으로 끝나는 답변을 제한적으로 처리한다. 명시적인 현재 커스텀·로컬 룰 조회에 대해서는 근거 없는 조회 완료·현재 적용 상태 주장도 좁게 검사한다. 이 추가 검사는 개념 설명, 과거 결과 요약, 제공한 내용 분석, 인용, 정직한 실패 안내와 질문을 구분한다. 여유 실행 횟수와 알려진 읽기 도구가 있으면 기존 Hermes 루프에 한 번 더 답변을 요청한다. `chat_completions`의 다음 요청 한 번에만 현재 노출된 읽기 도구 집합과 `tool_choice=required`를 제공하며, 도구·인자는 LLM이 선택한다. 재차 도구 호출 없이 끝나면 완료를 주장하더라도 현재 상태를 확인하지 못했다는 문구로 종료한다. 변경 요청과 승인·거부는 이 보완 대상이 아니다. 모든 표현의 감지, 응답 정확도, 조회 성공이나 일정 시간 내 완료를 보장하지 않는다.

`1.1.0`에는 단순한 현재 커스텀·로컬 룰 목록·개수에 한해 파일 집계 표시를 보완하는 2단계를 구현했고 로컬 회귀와 native 집계 경로 검증을 마쳤다. 현재 턴의 실제 도구 호출 ID, 대상 파일 본문과 집계의 SHA-256이 일치하는 `rule_inventory`만 사용한다. native 외부 자료 포장은 호출 도구 이름과 고정 형식이 정확히 일치할 때만 한 겹 해석한다. 정의 수·고유 ID를 표시하고, 부분 실패는 0개로 채우지 않으며 엔진 적재·탐지·차단 성공을 주장하지 않는다. 분석·원문·변경·과거 자료, 서비스·상태·로그·경보가 섞인 요청과 명시적 표/JSON/CSV 출력 요청은 원래 모델 경로를 유지한다. 순수 집계에서 알려진 다른 읽기를 함께 했더라도 파일 집계 근거는 정확한 대상 읽기 결과에서만 받는다. 자세한 범위는 [플러그인 안내](../infra/hermes/query-completion/README.md)를 따른다. 기존 운영 서버에는 2026-10-16 21:00:20 KST 반영했고 21:02:22 KST 실제 프로세스 연결·등록 등 배포 후 검증이 통과했다. 이 반영을 새 VM 초기 설치 시험으로 해석하지 않는다.

집계 표시에는 `rule_a/rule_b.get_rule_change_target`의 집계 결과가 필요하다. 기본 읽기 MCP2개 단계만으로는 이 집계 경로가 준비되지 않으며, SOC 확장의 규칙 MCP 구성이 끝나야 사용할 수 있다. LLM이 노출된 도구를 선택하는 구조와 승인 권한은 유지한다.

`tool_choice=required`를 전달했다는 사실은 실행 보장이 아니다. 2026-10-16 확인한 [Ollama 공식 호환 문서](https://github.com/ollama/ollama/blob/main/docs/api/openai-compatibility.mdx)는 `tools`는 지원, `tool_choice`는 미지원으로 표시한다. 실제 읽기 도구 스키마 8개와 `required`를 전달해도 도구 호출 없이 `finish_reason=stop`으로 끝난 평가 사례가 있다. 따라서 재시도 뒤 실제 도구 호출을 확인하고 0회면 조회 미실행 안내로 끝내는 `FALLBACK` 검사가 최종 확인 단계다. [검증 근거](../infra/hermes/rule-query-execution-validation-20261016.json)에서 요청 옵션과 실제 실행 결과를 구분한다.

추가 보완은 provider `custom`, 모델 `qwen3.6:35b`, API 주소 `http://211.170.162.111:11434/v1`가 모두 맞고 실제 요청의 모델도 일치하는 경로에 한정한다. 보완 재시도 요청 한 번에서만 최상위와 `extra_body`의 `think`, `reasoning_effort`, `reasoning`을 제거하여, 검증된 이 모델의 기본 thinking 동작을 사용한다. 현재 전역 reasoning 비활성 설정을 변경하지 않으며, 이후 요청은 기존 비활성 설정으로 돌아간다. 다른 모델·서버는 원래 설정을 따르고, 새 환경의 다른 주소로 예외가 자동 확대되지 않는다.

앞서 시험한 `extra_body.think=true` 단독 추가는 유효한 활성화 방법이 아니었다. 해당 실제 요청에는 `reasoning_effort=none`이 남아 있었으며, [Ollama v0.40.4의 OpenAI 호환 변환 코드](https://github.com/ollama/ollama/blob/v0.40.4/openai/openai.go)는 `reasoning.effort`, 그다음 `reasoning_effort`로 추론 설정을 결정한다. 이전 실패 결과는 검증 JSON에 남기고 현재 동작 설명은 위의 한 요청 옵션 제거 방식으로 정정한다.

이 선택의 근거인 같은 모델·문제 이력의 native thinking 활성 비교 평가에서는 49.444초 동안 실제 읽기 조회 3건과 최종 답변이 완료됐다. 다만 답변은 표를 사용했고 DetectionOnly 상태를 차단 상태처럼 설명하는 등 정확도 검사를 통과하지 못했다. 해당 결과는 조회 실행 성공과 답변 정확도 실패로 구분하며, 보완 요청 한 번에 모델 기본 thinking을 사용하는 최종 플러그인의 운영 배포 성공과도 구분한다. 추가 추론과 재시도 때문에 지연이 늘 수 있으며, 이 표본 시간은 응답 시간 보장이 아니다.

이 구현은 공개 완료 훅이 아니라 검토한 Hermes 내부 함수의 실행 중 참조를 감싸므로 정확한 소스 버전에 고정한다. 설치기는 플러그인 원문의 `SOURCE_SHA256` 상수를 실행 없이 파싱하고 다음 6개 원본 파일의 SHA를 준비 이미지와 대조한다.

- `agent/turn_final_response.py`
- `agent/conversation_loop.py`
- `agent/turn_context.py`
- `agent/message_metadata.py`
- `agent/turn_api_request.py`
- `agent/chat_completion_helpers.py`

SHA 값은 플러그인 한 곳에서 관리한다. `PluginContext.on_unload` 등 기존 native API도 검사하며, 누락·불일치 시 신규 서비스·계정·배포 상태를 만들기 전에 중단한다. 이미지 검사는 `apply` 초기에 네트워크·호스트 마운트 없는 읽기 전용 임시 컨테이너에서 수행한다. `check`는 소스 상수와 준비 자료의 정적 검사까지만 수행하며 이미지 실행 검사는 아직 남아 있음을 표시한다. 버전을 바꿀 때는 핀을 임의로 지우지 말고 내부 루프와 회귀 시험을 다시 검토한다.

운영 중 해제는 `plugins.enabled`에서 해당 플러그인만 제외하고 idle 확인 후 같은 Hermes 컨테이너를 재시작하는 방식으로 수행한다. `on_unload`는 모듈 함수 참조를 원복하지만, 이미 agent 인스턴스에 예약된 1회 API 요청 builder까지 즉시 제거하지는 않는다. 그 참조는 다음 호출에서 해제되므로 hot unload만으로 즉시 완전 해제됐다고 판단하지 않는다. 이전 대화 DB는 복원하지 않는다.



<a id="source-252038d31234088c-h5"></a>
<a id="record-609ee6b15de2998c2ffc517342c1878b07b5c779620242c295dba541007217d6"></a>

## 검증 범위

로컬 회귀 시험은 `bash deployment/roles/siem-test.sh`로 실행한다. 파일 복사·권한·기존 도구 범위 보존, 7개 파일의 프로필 포함, 6개 소스 핀 각각의 누락·변조 거절, unload API 및 설치 전 검사 순서를 가짜 이미지·파일 응답으로 확인한다. 실제 Docker·서버·모델·Mattermost 호출은 없다.

2단계 파일 집계와 응답 경계는 `python3 -B infra/mcp/test_rule_inventory.py`, `python3 -B infra/hermes/query-completion/test_inventory_render.py`로 별도 검사한다. 이 검사는 로컬 소스·가짜 native 저장 경로를 사용하며 운영 서버 변경이나 실제 모델·채팅 호출을 하지 않는다.

현재 집계 렌더링 회귀 65개와 기존 조회 보완 85개가 통과했다. 별도 실제 native 모델 평가는 57.38초·API 3회·실제 읽기 3건으로 정확한 WAF 10/Suricata 14/Wazuh 19개와 ID 목록, 반환·저장 본문 일치를 확인했다. 잘못된 999개 답변을 공급한 합성 응답 시험도 12.046초·native 반복 2회·실제 읽기 3건으로 통과했다. 초기 두 시험의 보호 포장 미인식 실패는 검증 이력에 남긴다. 이 평가와 초기 설치기의 새 VM 구축·사용자 채팅 전달·운영 배포는 별도 범위다.

새 VM에서 초기 설치를 실행한 시험은 아직 하지 않았다. 기본 SIEM 단계의 완료 검사는 컨테이너 실행과 읽기 MCP 연결을 확인하고, 후속 SOC 확장은 승인·대응을 포함한 MCP 5개의 도구 목록을 검사한다. 이것만으로 새 플러그인의 실제 등록과 대화 동작까지 입증하지는 않는다. 실제 배포에서는 `agent.log`의 `capstone.query_completion` 등록 기록과 `aliases_installed=True`를 기동 시각 이후 기록인지 대조해야 한다. 기존 서버 배포의 첫 검사는 Docker 로그만 조회해 실패했고, 실제 등록 INFO가 남는 `agent.log`를 확인해 통과했다. 등록 기록은 해당 프로세스에 보완 함수가 연결됐다는 근거이며, 실제 조회 완료·결과 정확도·채팅 전달까지 검증한 근거는 아니다.


</details>

<a id="source-ef7424bbadcff1f6"></a>

## deployment-INSTALLER_READINESS-before-read-accuracy-ncsc-20261104.md

<details>
<summary>당시 기록 펼치기 · 2026-11-04T19:18:25+09:00</summary>

<a id="source-ef7424bbadcff1f6-h0"></a>
<a id="record-18a55f58cb5bcdad6da9dab67bee3875099443238f04272144550bd32b77ce10"></a>

> 18:13 후속: 신규 읽기 전용 chat_lookup_prompt도 기존 canonical controller/worker 소스 복사를 사용한다. 새로운 패키지·이미지·포트·복사 경로0, 설치/렌더37검사 통과·실제 신규 설치0. [운영 검증](../infra/hermes/lookup-latency.md).

> 11/4 후속 하네스 동기화: 출력 스킬 `infra/hermes/skills/soc-output/SKILL.md`와 공통 `output_contract.py`, 관리용 `chat_markdown.py`를 기존 source bundle/역할 설치·SDK 복사 목록에 연결했다. 소스 기반 설치계약37·SIEM 서식40 검사를 통과했다. 새 패키지/이미지/포트는 없으며 기존 Python과 소스만 필요하다. 실제 새 서버 설치는 실행하지 않았다. 아래 최초 점검의 ‘설치 코드 수정0’은 당시 범위이며 현재 소스 복사 갱신과 구분한다. 원격 허용목록·전체 오프라인 묶음 등 기존 잔여를 해결한 것은 아니다. [운영 적용·재현·한계](../infra/hermes/harness-cleanup.md).

# 초기 설치·통합 패키지 준비 상태

2026-11-04 읽기 점검. **최신 웹 정책의 소스 연결은 확인했지만, 현재 상태를 완성된 일괄 배포 제품으로 표시하지 않는다.** 사용자가 실제 설치는 지금 하지 말고 확인만 하도록 지시했으므로 서버 접속/설치/재시작·코드 수정은 수행하지 않았다. [운영 상태](../STATUS.md) · [웹 정책](../infra/validation/web-policy/README.md).

| 항목 | 코드에서 확인한 상태 | 판정 |
|---|---|---|
| 사용자 진입점 | 루트deploy.sh가 security/siem/service, 오프라인 패키지·이미지 적재, 키 연계·진단·봇 단계를 순차 호출 | 기반 구현 |
| 최신 WAF/관리 인증 | 신규 WAF On·UI/API 포함4프록시·DetectionOnly 예외 제거·C 관리자 CIDR+HMAC 제어. remote site.env가 MANAGEMENT_ALLOWED_CIDRS를 export하고 bootstrap이 이를 기록 | 소스 연결 확인, 새 서버 운영 미시험 |
| 두 봇/공동 채널 | Ollama/runtime/chat/review 옵션 존재. 기본은3개 enable=0·read-only | 현행 두 봇 동등 권한 구성을 자동으로 선택하는 제품 프로필은 별도 필요 |
| 공동 검토 채널 | deploy.sh는siem review-chat-install/verify를 호출하지만 remote.sh 최초 허용 목록에는 없음. 뒤쪽 dispatcher 존재 여부와 무관하게 선행 gate가64로 거부 | 실제 코드 경로 차단, 미수정 |
| WAF 근거 기반 IP 대응 | configure_waf_evidence.py는 SOC source bundle과 설치 경로에 포함. 초기 실행 순서에서 실제 enrollment 호출을 찾지 못함 | 자동 준비 완료로 표시하지 않음. producer/raw/pin 전제의 명시적 설치·검증 필요 |
| 오프라인 일괄 반입 | artifacts.json 기반 deb/image SHA·버전 검사와 오프라인 설치 지원. wheel/실습 이미지·카탈로그·TLS/별도 runtime 묶음은 각 서버 /opt/capstone-prereqs에 사전 준비 | 전체 의존성을 포함해 한 번 반입하는 최종 배포 패키지는 아직 아님 |
| 설치 검증 | Bash 구문 통과. 가짜SSH 컨트롤러46개 중43통과·3실패 | 실패3개는 신규 A host-check/host-verify를 기대 목록에 누락한 fixture 불일치. 실제 VM 설치 결과가 아님 |
| 실제 초기 설치 | 신규 Ubuntu24.04 amd643대 전체 설치 | 사용자 조건으로 미실시 |

허용 목록 재현은 remote.sh의 인자 검사 부분만 로컬에서 실행했다. review2작업은64, 대조용 trial-chat-install/verify와 diag-check는0이다. root 확인·site.env·SSH·패키지·서비스 동작은 실행하지 않았다. 가짜SSH 시험의43개 통과는 원격 dispatcher 실행이나 새 서버 제품 검증의 대체가 아니다.

배포 단위의 목표는 검수한 source·역할별 오프라인 의존성·SHA/버전/출처 목록·설정 입력·설치 후 판정·실패/복구 기록을 함께 제공하고, 사용자는 실제 주소·관리자·추론 API를 설정한 뒤 deploy.sh 하나로 설치하는 것이다. 자격/개인키·운영 데이터·가중치를 소스 패키지나 Git에 섞지 않는다. 이번에는 패키지를 새로 제작하거나 운영 소스/설정·기본 옵션을 변경하지 않았다.

다음 구현 때는 먼저 review 허용 목록과 회귀 기대값·WAF 증거 초기 준비를 정리한 뒤, 전체 오프라인 묶음과 동일한 설치/검증 프로필을 연결한다. 새3VM 실제 설치는 사용자가 가능하다고 할 때까지 실행하지 않는다. 웹 실제 공격 E2E·C 승인형 MCP·LLM 전 관제 업무의 기존 잔여 과제도 계속 유지한다.

점검 결과3개 문서는 `32d6222cace694647ec7967df09d7a15aa7040b2`로 게시하고 2026-11-04T12:07:29.303399+09:00 원격main 일치를 확인했다. 이 게시 확인 문구는 후속 문서 커밋으로 보존한다. 코드 문제는 미수정 상태이며 실제 설치는 실행하지 않았다.


</details>

<a id="source-429cb0b9c8ff56ec"></a>

## README-offline-labs-20261104-before-enforce.md

<details>
<summary>당시 기록 펼치기 · 2026-11-04T12:00:02+09:00</summary>

<a id="source-429cb0b9c8ff56ec-h0"></a>
<a id="source-429cb0b9c8ff56ec-h1"></a>
<a id="record-e8c43a84daa2bd140fb7154b0ad53d2dc8b43814da61c21c1e7c52ecb6cc2542"></a>

# 과거 문서 보존: infra/groot-c/offline-labs/README.md

2026-11-04 갱신 전 원문이다. 상대 링크는 원래 경로 기준이며 현재 정책은 [현재 README](../infra/groot-c/offline-labs/README.md)를 따른다.

# GROOT Lab Console



<a id="source-429cb0b9c8ff56ec-h2"></a>
<a id="record-876066f9c0ce8e797748dc876300e5e5e307b9d2afd34f0fd28c8f4790143bf0"></a>

## 웹 접근 정책 변경 — 2026-10-26

사용자가 DVWA·Log4Shell 웹을 모든 출발지에 허용하도록 결정했다. A의 Log4Shell 서버 블록에서 기존 IP 허용 목록을 `allow all`로 바꾸고 같은 컨테이너를 reload했다. `211.170.162.107`의 기존 접근 거부를 확인했으며 상위망 라우팅·방화벽 도달성과 사이트 자체 허용은 별개다. 도메인은 여전히 사설 A 주소로 해석된다. 세부 운영 응답·새 출발지 재시험 결과는 [STATUS](../../../STATUS.md)에 기록한다.

콘솔의 기존 목록·시작/중지·터미널 기능도 같은 웹 접근 정책을 따른다. WAF 예외 키·10분 세션·프록시 신뢰 경계와 실습 격리는 그대로이며, Wazuh·SSH·MCP 공개를 뜻하지 않는다. 초기 설치는 `LAB_ALLOWED_CIDRS=all`로 명시하며 CIDR 목록을 입력하면 기존 제한을 적용한다. 추가 반입 패키지·이미지는 없다. 아래 접근 제한 설명은 당시 이력이다.

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../STATUS.md) · [실행 계획](../../../PLAN.md).
> 현재 콘솔은 HTTP3개(Log4Shell/Apache2종)와 터미널3개(Redis/Samba/sudo), 총6항목이다. sudo는 별도 rootless의 UID1000·전역 단일 세션이며 종료 시 전체 중지한다. DVWA는 독립 유지한다. 환경 준비와 CVE 악용 성공을 구분하고 공격 재현은 보류한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->



<a id="source-429cb0b9c8ff56ec-h3"></a>
<a id="record-bf3b54f6418c5de8e4d2c7bb24b92e025e959743cb87c1e47ed4a571a6dd392e"></a>

## 파비콘 재발 후속 완료 (2026-10-23)

메인과 터미널은 로컬 `lab-console-icon.ico`를 정적으로 선언하고 공통 테마는 올바른 아이콘을 그대로 유지한다. 루트 favicon·Apple 아이콘 경로도 이미지로 연결한다. 실제 HTTPS MIME·SHA 및 Safari 아이콘 캐시 백업·재생성 후 같은 주소의 서버 선화 표시와 사용자 확인을 완료했다. 설치기 반입·검증 목록을 함께 갱신했다. [최종 아이콘 증거](favicon-validation-20261023.json).



<a id="source-429cb0b9c8ff56ec-h4"></a>
<a id="record-77d41ff5b9aecd2829ad02162f33ef97815bd1efabf0ee156db963102152d541"></a>

## sudo 웹 터미널 연결 — 운영 반영·HTTPS 검증 완료 (2026-10-23)

sudo CVE-2021-3156은 기존에 `local-cli`의 준비 상태만 표시해 웹 시작·열기가 비활성화돼 있었다. 새 소스는 이를 `managed-terminal`로 연결하며 **HTTP3개 + 웹 터미널3개, 총6항목**을 사용한다. sudo도 **실습 환경 시작 → 환경 열기**로 `/log4shell/terminal/CVE-2021-3156/`에 접속한다. 별도 rootless 저장소의 준비 이미지도 확인해 모든 입력이 준비됐으면 이미지 수는6개다. C 운영 적용과 실제 HTTPS 접속·입출력·종료 검증을 완료했다.

기존 sudo 이미지·반입 bundle·고정 런타임은 그대로 유지하고 중앙 `sudo_terminal.py` adapter를 통해 연결한다. 호스트 UID1991의 전용 rootless 계정과 컨테이너 UID1000을 사용하며 호스트 sudo·일반 Docker 옵션·임의 host shell을 받지 않는다. 기존 user namespace 안의 setuid 실습 조건을 유지하므로 HTTP/Redis/Samba의 no-new-privileges 계약을 그대로 복사하지 않는다. [중앙 관리 계약](../nonweb-labs/README.md)이 현재 웹 연결 정책이며 `nonweb/sudo/README.md`의 웹 미제공 설명은 원래 CLI 런타임 구축 당시 이력이다. 그 CLI 소스와 pin은 이번에 바꾸지 않는다.

sudo 터미널은 서버 전체1개만 연결한다. **연결 종료·입력 유휴5분·전체30분·터미널 서비스 종료는 sudo 컨테이너 전체 중지**로 처리하고, 재연결은 환경을 자동 시작하지 않는다. 브라우저 탭 종료의 keepalive 전달은 보장되지 않으므로 서버의 시간 제한 정리를 함께 사용한다. 종료 결과를 확인하지 못하면 UI는 중지 완료라고 표시하지 않는다. Redis/Samba의 세션 종료는 환경을 유지하며, 전체 정리는 콘솔 중지로 수행하는 기존 정책을 유지한다.

단일 `deploy.sh`는 service schema9로 이 경로를 반입·검증하도록 연결했다. 아래 schema8·터미널2종의 운영 완료와 [기존 통합 JSON](../nonweb-labs/validation-20261023.json)은 당시 이력이며 sudo 웹터미널 검증을 대신하지 않는다. 실제 취약점 악용/방어 E2E와 새 VM3대 전체 설치 시험은 별도다.


검증은 native 콘솔97개·nonweb121개, 설치기 service50개·controller35개와 Node2종이다. 실제 HTTPS에서 sudo UID1000·패키지1.8.31-1ubuntu1·터미널 크기 변경·Ctrl+C·단일 연결·연결 종료 시 전체 중지·활성 세션 중지·새 CID 재시작을 확인했다. 기존 rootful 컨테이너는 적용 전후 동일했다. 새로고침한 Safari에서 이미지6개·sudo 항목과 시작 버튼은 확인했고, 사용자 브라우저 조작과 겹쳐 sudo 터미널 명령의 시각 검수는 별도로 완료 처리하지 않았다. [sudo 운영 증거](../nonweb-labs/sudo-web-validation-20261023.json).



<a id="source-429cb0b9c8ff56ec-h5"></a>
<a id="record-481df8f849b44cc3311fd4b3d84a42375604c74b7a69021539ca6bb5696fea44"></a>

## Redis·Samba 웹 터미널 확장 — sudo 웹 연결 전 완료 이력 (2026-10-23)

현재 운영 `cve_list.json`은 **6항목**이다. 기존 HTTP3개와 sudo CLI에 Redis **CVE-2022-0543**(Ubuntu `5:5.0.7-2`), Samba **CVE-2017-7494**(4.6.3)의 `managed-terminal` 유형을 추가했다. 두 항목은 같은 HTTPS 콘솔에서 **실습환경 시작 → 환경 열기**를 선택해 `/log4shell/terminal/<CVE ID>/`의 가상 터미널에 접속하도록 구현했다. sudo의 웹 실행·셸은 제공하지 않으며 DVWA는 원래 독립 주소를 유지한다.

FastAPI는 peer credential을 확인하는 전용 Unix daemon을 거쳐, root 런타임이 검증한 full 컨테이너 ID의 고정 UID/GID10001:10001 세션을 연다. 임의 호스트 명령·이미지·mount·Docker 옵션은 받지 않는다. Redis/Samba 서비스는 컨테이너 loopback에서만 제공하고 host port를 게시하지 않는다. 따라서 HTTP 실습3개의 WAF 검사·예외 모드와 터미널 안의 Redis/SMB 프로토콜은 같은 검사 경로가 아니며, WAF 키를 터미널 권한으로 사용하지 않는다.

터미널의 입력 유휴 한도는5분, 전체 수명은30분, 출력 버퍼는256KiB다. 같은 lab의 세션은 컨테이너·UID10001·파일시스템을 공유하므로 **사용자별 OS 격리가 아니다**. 탭을 닫으면 해당 OS 세션(SID)의 검증된 UID10001 프로세스 정리를 시도하며, 새 OS 세션으로 분리한 자식까지 포함한 실습 전체 정리는 해당 lab의 **중지**로 컨테이너를 제거한다. 이는 기존 HTTP3개의 정지·재시작 계약과 구분한다.

C의 이미지 빌드·런타임·콘솔 반영을 완료했다. native 콘솔94개(HTTP API14개 포함), 런타임40개·터미널 daemon27개, 이미지 준비22개 회귀를 통과했다. 초기 런타임33개·daemon25개는 보완 전 결과다. 실제 HTTPS에서 서비스 응답·비권한 셸·시작을 확인하고, 터미널 helper만 보완한 최종 이미지로 Ctrl+C·다른 세션 보존·중지·중지 후 접속 거부를 재확인했다. 또한 호스트에서 도달 가능한 listener가 컨테이너에서 차단되는 것을 실측했다. host port 없음·internal network·Docker socket 없음·읽기 전용 rootfs·리소스 제한도 확인했다. 새로고침한 Safari에서 서버 파비콘, Redis의 UID10001·PONG, 최종 Samba의 UID10001·Version4.6.3·SMB3 공유 목록과 다크/화이트 테마·연결 종료·콘솔 중지를 확인했다.

[통합 운영 검증](../nonweb-labs/validation-20261023.json)과 [최종 TTY·이미지 증거](../nonweb-labs/terminal-tty-validation-20261023.json)에 실제 ID·SHA·검증 범위를 기록한다. 설치와 격리 조건은 [비웹 런타임 관리 계약](../nonweb-labs/README.md)을 따른다. 단일 `deploy.sh`의 service schema8은6항목·로컬 터미널 자산·`LAB_NONWEB_BUNDLE`을 반입하고 두 컨테이너를 자동 시작하지 않는다. **아래4항목·HTTP35개·native66개는 Redis/Samba 확장 전 검증 기록**이다. 새 VM3대 전체 설치 시험은 사용자 요청으로 보류하며 실제 취약점 악용/방어 E2E·재부팅·30분 전체 세션 수명 실측은 미검증이다.



<a id="source-429cb0b9c8ff56ec-h6"></a>
<a id="record-279b300f345fb255dafef1ac9c3eca6d348c95994f34305b63587d96cf8fe4bc"></a>

## Redis·Samba 확장 전 운영 검증 기록

확장 전 UI는 수평 메뉴·큰 제목·서버 선화의 Lab Console이며 연결된 Java·Apache 두 버전과 공통 차콜/웜화이트 색상을 사용한다. DVWA는 독립 화면을 유지한다. 전체3서버 초기 설정은 루트 [deploy.sh 단일 진입점](../../../deployment/bootstrap-guide.md)이 로컬 반입·역할 설치·내부 helper를 연결한다. 당시 HTTPS35개·C native66개를 통과했으며 아래64개 검증은 변경 전 단계다. 새 VM3대 전체 apply는 아직 미실행이다.

기존 Log4Shell 웹 주소에서 사용하는 오프라인 CVE 실습 관리 화면이다. [관리 화면](https://log4shell.grootlab.duckdns.org/log4shell/)의 목록 조회·실행·중지는 **키 없이** 사용할 수 있다. 선택적인 차단 예외 키는 해당 브라우저의 WAF 검사 모드를 10분 동안 바꾸는 용도다. 확장 전 검증한 카탈로그는 **4항목**이다. Log4Shell과 Apache httpd 2.4.49·2.4.50은 로컬 이미지로 관리한다. DVWA는 목록과 같은 HTTPS 실습 경로에서 제외하고 원래 독립 주소로 유지한다. sudo는 별도 rootless CLI 환경이며 웹에서 실행하지 않는다. sudo rootless 런타임의 무해한 환경 검증과 정식 상태 발행 검증을 완료했다. 실제 권한 상승·호스트 탐지 성공을 뜻하지 않는다.



<a id="source-429cb0b9c8ff56ec-h7"></a>
<a id="record-2b9d34bf0d8b5122470a53fbe1ce8cac32c4b528c1f704b1fc51705d92ec7a74"></a>

## 현재 범위 정정·공통 테마 — 적용 완료 (2026-10-23)

사용자가 DVWA를 원래 독립 주소에서 그대로 유지하도록 명시했다. 앞서 추가한 DVWA 통합은 요청 범위를 잘못 확대한 것으로, Log4Shell 사이트의 프록시·카탈로그 연결·전용 예외 쿠키·테마 처리만 제거했다. 원래 DVWA 앱·DB·독립 접속 설정은 유지했다. 10/22의5항목 검증 자료는 당시 이력으로 보존하며 정정 후 최종 통합 검증을 대신하지 않는다.

콘솔과 고정 웹3항목(Java·Apache 2.4.49·Apache 2.4.50)의 HTML 페이지 상단에 현재 모드인 **`다크` 또는 `화이트` 한 단어와16px 달·해 아이콘**을 표시하는 단일 버튼을 제공한다. 고정96px 버튼에서16px 아이콘 열과 글자 슬롯을 분리하고 각 슬롯 중심에 정렬한다. A TLS 프록시가 공통 로컬 `static/theme.js`·`static/theme.css`를 HTML에 넣으며 외부 CDN·폰트·테마 API는 없다. 전환 효과는180ms이고 reduced-motion 설정에서는 끈다. 최신 자산의 서버 SHA 일치, 새로고침한 Safari의 고정 아이콘·글자 가운데 정렬·양방향 전환, Java·Apache 두 버전의 테마 동작을 확인했다. sudo는 같은 콘솔에서 전용 웹 터미널 화면으로 연결한다.

선택은 같은 출처 localStorage의 `groot-lab.theme.v1`에 저장하고 다른 탭에 반영한다. 저장된 선택이 없으면 콘솔·Java·Apache 모두 다크 화면에서 시작한다. 저장소 접근이 차단돼도 현재 페이지의 전환은 동작한다. 버튼은 표시 설정만 바꾸며 키·쿠키·폼 입력을 읽거나 요청하지 않는다.

Java와 Apache 두 버전은 메인과 같은 최대1344px 외곽 프레임, 직선 테두리, 타이포그래피와 버튼을 사용한다. 헤더의 `Lab Console` 링크로 메인에 돌아갈 수 있고, Java의 요청·응답 패널과 Apache의 버전·안내 패널은 각 실습 기능에 맞춰 유지한다. 작은 화면에서는 탐색과 패널을 세로로 배치한다. 이 모양은 공통 `theme.js/css`에서 적용하므로 Java JAR·실습 이미지를 다시 만들 필요가 없다. 단일 초기 설치기도 두 파일을 필수 소스로 반입·복사하고 실제 제공 파일을 대조하므로 동일한 디자인을 설치한다. JSON·일반 텍스트 실습 자료의 응답 형식은 바꾸지 않는다.



<a id="source-429cb0b9c8ff56ec-h8"></a>
<a id="record-23d4ec04e181d9235ba9dca5f01e338260c7931977b7a6bbdbc16ffff1b0093c"></a>

## 사용 방법

관리 화면은 학과 내부망·기존 VPN에서 HTTPS로 접근한다. HTTP 주소는 HTTPS로 이동한다. 아래는 현재6항목 기준 사용법이며 Redis/Samba의 운영 검증 범위는 맨 위 절을 따른다.

1. 관리 화면에서 항목을 선택한다. 목록·상태 조회와 HTTP3개/터미널3개 실습의 시작·중지에는 키가 필요하지 않다. sudo도 콘솔에서 시작한 뒤 환경을 연다.
2. Java·Apache 두 버전은 **실습 실행 → 실습 열기**를 선택한다. 같은 HTTPS 사이트의 `/log4shell/labs/<항목 ID>/`에서 열리며 SSH 터널은 필요하지 않다.
3. Redis·Samba는 **실습 환경 시작 → 환경 열기**를 선택한다. 실행 중이고 격리가 확인되면 `/log4shell/terminal/<항목 ID>/`의 터미널이 열린다. 터미널의 **재연결**은 실행 중인 환경에 새 세션을 연결하고, **연결 종료**는 해당 세션만 종료한다. 환경 전체 중지는 콘솔의 **중지**를 사용한다.
4. HTTP3개 실습은 정상 요청을 허용하고 WAF 보안 규칙에 탐지된 요청을 차단한다. 탐지만 기록하려면 **차단 예외 키 (선택)**에 **Wazuh Dashboard `admin` 계정의 비밀번호와 같은 키**를 입력하고 **예외 적용**을 누른다. Redis/SMB 프로토콜과 터미널 권한에는 이 예외가 적용되지 않는다. 키를 Git, URL, 명령행 인수, 채팅, 브라우저 저장소에 넣지 않는다.
5. HTTP 실습의 예외 상태는 `관리자 실습 · 탐지만 기록`, 일반 상태는 `일반 실습 · 차단 적용`으로 표시한다. 예외 해제 또는 600초 만료 후 일반 정책으로 돌아간다. 사용을 마치면 직접 시작한 실습도 중지한다. sudo의 실행·중지는 웹에서 제공하지 않으며 DVWA는 이 관리 화면의 대상이 아니다.

공통 키는 C의 root 관리 파일에 별도로 동기화한 값으로 검증한다. 이 화면이 Wazuh 계정으로 로그인하거나 Wazuh API에 비밀번호를 전달하는 것은 아니며 SSO도 아니다. 키 적용 여부는 실습 실행·중지 권한이나 Docker 실행 범위를 늘리지 않는다.

브라우저는 WebCrypto로 **일회용 서명**을 만들며 키 원문과 재사용 가능한 고정 SHA-256 해시를 서버에 보내지 않는다. 검증 순서는 다음과 같다.

- 서버에서 유효기간 **30초**, **한 번만 사용 가능한** challenge를 받는다. challenge는 접속 IP·Host에 연결된다.
- 브라우저에서 `HMAC-SHA-256(key=SHA-256(UTF-8(입력 키)), message=UTF-8(challenge.message))`를 계산한다. 입력의 앞뒤 공백도 그대로 사용한다.
- 서버에는 `challenge_id`와 해당 요청의 64자리 hex `proof`만 보낸다. 서버는 자체 보관한 키로 같은 값을 계산해 비교한다. 해시를 디코딩하거나 원래 비밀번호를 복원하는 방식이 아니다.
- 오류·만료 후에는 키를 다시 입력해 **새 challenge**로 시도한다. 이미 전송한 서명을 자동 재전송하지 않는다. 키 문자열 참조를 줄이고 소유한 바이트 버퍼를 정리하지만 JavaScript·브라우저 메모리의 완전한 삭제를 보장하지 않는다.

성공하면 키 자체가 아닌 서명된 `groot_lab_mode` 세션 쿠키를 발급한다. 공개 HTTPS에서는 `Secure`, `HttpOnly`, `SameSite=Strict`를 적용하며 클라이언트 IP와 **600초** 만료에 묶인다. 페이지 새로고침으로 해제되지 않고 **같은 브라우저의 다른 탭에도 공유**된다. UI는 서버의 만료 시각·남은 시간을 표시하고 10초마다 상태·정책을 재확인한다. GET 조회는 만료 시간을 연장하지 않는다. **예외 해제**는 쿠키를 지우며, IP가 바뀌면 기존 세션은 유효하지 않다. 보안 연결이나 WebCrypto가 없는 브라우저에서도 무키 실습은 가능하지만 예외 키 입력은 비활성화된다.

실행 중인 같은 CVE를 다시 시작해도 중복 컨테이너를 만들지 않는다. 중지 후 동작은 유형별로 다르다.

| 유형 | 콘솔의 중지 | 다시 시작 |
|---|---|---|
| HTTP3개(Java·Apache 두 버전) | 컨테이너를 정지하고 보존한다. | 동일한 관리 컨테이너를 다시 시작한다. |
| Redis·Samba 터미널2개 | 해당 실습의 모든 터미널 연결을 정리하고 컨테이너를 정지·제거한다. tmpfs의 실습 데이터도 사라진다. | 고정 이미지로 새 컨테이너를 만든다. |
| sudo 터미널1개 | 연결 종료·만료와 콘솔 중지 시 rootless 실습 컨테이너 전체를 중지한다. | 콘솔에서 실습 환경을 다시 시작한다. 일반 호스트 셸은 제공하지 않는다. |

Redis/Samba 터미널의 **연결 종료**는 실습 환경 전체 중지가 아니다. 같은 실습을 공유하는 다른 세션까지 정리하려면 콘솔에서 해당 실습을 중지한다. sudo는 연결 종료·만료 시 컨테이너 전체를 중지하는 별도 계약이다. Docker의 `running`과 무해한 서비스 준비 검사는 실제 취약점 재현·방어 탐지 성공을 의미하지 않는다. 사용자가 중지한 실습은 재부팅 후 임의로 시작하지 않고 필요할 때 다시 시작한다.



<a id="source-429cb0b9c8ff56ec-h9"></a>
<a id="record-1b6d29d2735e29dd9f20f466c87e318299c133998a6b501843932ce9cb9bf5d0"></a>

## 구성과 경계

```text
관리 화면·API (WAF 미경유)
  브라우저 /log4shell/ → A HTTPS 프록시
  → C Apache /_offline-labs/ (A·loopback만 허용)
  → 127.0.0.1:18090 FastAPI (capstone-labs 비권한 계정)
  → Unix socket (peer UID/GID 검사)
  → root 고정 기능 broker → 로컬 Docker Engine

웹 실습 요청 (WAF 경유, 고정3개 경로)
  브라우저 /log4shell/labs/<등록된 웹 항목 ID>/ → A HTTPS 프록시
  → 내부 세션 검사 → WAF 전용 Host·고정 경로
  → C Apache 내부 경로 (A·loopback만 허용)
  → 관리형: 127.0.0.1:18081(Java) / :18082(httpd 2.4.49) / :18083(httpd 2.4.50)

Redis·Samba 터미널 (WAF 미경유, 고정2개 항목)
  브라우저 /log4shell/terminal/<등록된 터미널 항목 ID>/
  → 같은 출처 /log4shell/api/terminal/{open,poll,input,resize,close}
  → C FastAPI → 전용 Unix daemon → 검증한 컨테이너의 UID/GID10001:10001
  → 컨테이너 loopback의 Redis/SMB 서비스 (호스트 게시 포트 없음)

sudo 터미널 (WAF 미경유, 고정1개 항목)
  브라우저 /log4shell/terminal/CVE-2021-3156/ → 같은 출처 terminal API
  → 전용 daemon → sudo 중앙 adapter → 원래 rootless 런타임
  → 검증한 컨테이너 UID/GID1000:1000 (호스트 전용 계정 UID1991)
  → 단일 세션, 연결 종료·만료 시 해당 실습 컨테이너 전체 중지
```

**관리·터미널 API는 WAF를 경유하지 않고 HTTP3개 실습 요청은 WAF를 경유한다.** 키 검증의 challenge·proof 및 예외 세션 쿠키는 관리 경로에서 처리한다. A는 내부 세션 검사 결과로 검사 모드를 정하고 클라이언트가 보낸 제어 헤더를 덮어쓴다. HTTP 실습 요청과 함께 검사 모드·요청 식별자·클라이언트 주소를 전달하며, 쿠키는 해당 경로의 허용 목록만 남긴다. Java는 기존 CSRF 쿠키만 허용하고 httpd에는 쿠키를 전달하지 않는다. 키·proof·예외 세션 쿠키는 WAF에 전달하지 않는다. 세션 검사 서비스에 연결할 수 없으면 임의로 예외를 허용하지 않는다.

WAF의 기존 전역 `DetectionOnly`·CRS·감사 설정은 유지하고, 전용 Host의 허용된3개 실습 경로에만 일반 모드 `On` 또는 예외 모드 `DetectionOnly`를 적용한다. 새 규칙·vhost 파일의 배포와 재생성 제약은 아래 운영 절을 따른다. DVWA의 원래 독립 경로와 이전 `log4shell-lab` 컨테이너는 보존한다. 이전 Java 컨테이너는 별도 관리기가 계속 소유하며 새 웹의 중지 버튼 대상이 아니다.

이 예외는 **해당 웹 요청의 WAF 즉시 차단**에만 적용된다. Suricata는 트래픽을 관측하는 기존 passive 탐지 경로를 유지하며, 탐지 이후 기존 IP 차단·보호 주소 검사·LLM 조사와 판단·관리자 승인·TTL 계약을 바꾸지 않는다. **이미 적용된 L4/IP 차단은 이 키로 해제할 수 없다.** 예외 세션이 모든 네트워크 보호 정책을 우회하거나 공격 성공을 보장하지 않는다.

- FastAPI에는 Docker socket·docker 그룹·sudo 권한이 없다. broker는 `status`, `deploy`, `stop`과 등록된 항목 ID만 받는다. HTTP3개는 기존 broker가 관리하고 `managed-terminal`3개는 고정 ID를 전용 daemon으로 전달하며 sudo는 중앙 adapter에서 원래 rootless 런타임을 호출한다. 아래 HTTP Docker 실행·격리 계약과 Redis/Samba의 [별도 런타임 계약](../nonweb-labs/README.md)을 구분한다. sudo도 고정 웹 터미널로 연결하되 SOC/Hermes LLM에 Docker 권한을 위임하지 않는다.
- 서버 시작 때 로컬 JSON을 읽고 검증한다. 등록되지 않은 ID, 추가 실행 옵션, 잘못된 JSON, 중복 CVE·호스트 포트를 거부한다. 매니페스트 변경은 두 서비스 재시작 후 반영한다.
- Docker 태그가 가리키는 로컬 이미지 ID를 고정 SHA와 대조한다. `--pull=never`, 명령 인수 배열, 로컬 Unix Docker 소켓만 사용한다. 이미지 누락 시 오류를 반환하며 다운로드로 대체하지 않는다.
- HTTP3개 실행은 UID/GID 65532, 읽기 전용 rootfs, `/tmp` tmpfs, capability 전체 제거, no-new-privileges, CPU 1개·메모리 512MiB·PID 128·로그 회전으로 제한한다. 이미지에 선언된 `VOLUME`도 거부한다. 임의 mount·환경변수·command·Docker exec API는 없다. Redis/Samba의 서비스 사용자·리소스·격리망은 별도 고정 계약을 따르며 브라우저 터미널은 두 컨테이너 안의 UID/GID10001:10001에만 연결한다.
- HTTP3개는 전용 bridge `br-offline-labs`의 nftables 입력·전달 규칙과 ICC 차단, 컨테이너 DNS loopback 설정을 검사한다. 새 컨테이너의 호스트/다른 네트워크 방향 연결을 막는다. 단순 loopback 포트 게시만으로 외부 송신이 막힌다고 가정하지 않는다.
- HTTP3개는 Docker 29의 `--internal` 게시 포트 제한을 피하기 위해 일반 전용 bridge와 별도 nft 격리를 사용한다. 호스트와 실습 앱 사이의 응답은 허용한다. Redis/Samba는 포트를 게시하지 않고 각각의 internal bridge와 별도 nft 격리를 사용한다.
- root 전용 receipt의 전체 컨테이너 ID·이미지·명령·환경·리소스·포트·네트워크·라벨을 검증한다. 이름이 같은 미관리 컨테이너를 가져오거나 삭제하지 않는다. 생성 후 receipt 저장이 실패하면 자동 인수하지 않고 관리자 검토 대상으로 남긴다.
- HTTP guard 오류 때 해당 HTTP 실습의 새 배포는 막되, 검증된 관리 컨테이너의 상태 조회·중지는 유지한다. 터미널3개는 유형별 고정 런타임/adapter의 격리 검사로 시작·접속을 결정한다. 실행 중인 컨테이너의 격리 장치를 root가 별도로 제거하는 행위까지 자동 복구하는 감시기는 아니다.
- API는 허용된 Host·Origin/Fetch Metadata·JSON 타입·4KiB 본문 제한을 사용하며 CORS를 열지 않는다. 모든 브라우저 요청은 같은 출처 쿠키를 사용하고 `Authorization` 헤더는 보내지 않는다. 예외 검증 API는 이 헤더가 있는 요청을 거부한다. UI·CSS·JS·폰트는 외부 CDN을 사용하지 않고 Swagger/ReDoc 외부 자산도 비활성화했다.



<a id="source-429cb0b9c8ff56ec-h10"></a>
<a id="record-97cf5bc5e8be9cb9e106a8068100546d7d65f39e4758eb95cfff95c2725e3160"></a>

## 파일

| 파일 | 용도 |
|---|---|
| `app.py`, `static/` | 무키 실습 API와 순수 CSS/JS UI·WebCrypto 서명 |
| `static/theme.js`, `static/theme.css` | 콘솔·Java·Apache HTML의 공통 다크/화이트 버튼·로컬 테마 자산 |
| `static/favicon.svg` | 같은 사이트에서 제공하는 모노크롬 서버 선화 파비콘 |
| `terminal_api.py`, `static/terminal.html`, `static/terminal.js`, `static/terminal.css` | 같은 출처 터미널 API·화면·세션 연결 |
| `static/terminal-vendor/` | 고정 xterm.js·fit addon, 라이선스·출처·SHA |
| `challenge.py`, `practice_mode.py` | 30초 일회용 HMAC challenge·600초 IP 바인딩 세션 |
| `cve_list.json`, `manifest.py` | 정적 카탈로그·엄격한 검증 |
| `broker.py`, `guard.py` | 고정 Docker 실행·소유권 검사·전용망 차단 |
| `Log4Shell.Dockerfile` | 기존 로컬 이미지와 검증된 Java JAR를 새 로컬 이미지로 구성 |
| `images/httpd/` | 공식 httpd 2.4.49·2.4.50 기반의 오프라인 빌드·정적 fixture |
| `nonweb/sudo/` | 별도 rootless sudo 환경 준비·무해한 버전/격리 확인 |
| `../nonweb-labs/` | Redis/Samba 고정 런타임·별도 이미지 번들·터미널 daemon |
| `rule-source-candidates.json` | 공식 규칙 후보 27개, 조사 자료이며 자동 설치 입력이 아님 |
| `requirements.lock`, `wheel-inventory.json` | Linux amd64·Python 3.12 의존성 버전·PyPI URL·SHA |
| `scripts/prepare-python.sh` | 연결된 준비 PC에서 wheel 다운로드·해시 확인만 수행 |
| `scripts/unpack_wheels.py` | 폐쇄망 서버에서 검증한 wheel을 전용 vendor 경로에 설치 |
| `scripts/export-images.sh`, `scripts/import-images.sh` | 관리자용 `docker save`/`load`·해시/ID 검사 |
| `scripts/install.sh` | 오프라인 최초 설치·systemd 서비스 구성 |
| `apache-proxy.conf`, `nginx-log4shell-server.conf` | 관리 경로 분리·같은 HTTPS 실습 주소·내부 세션 검사 |
| `waf-log4shell-server.conf`, `REQUEST-900-CAPSTONE-LABS.conf` | WAF의 고정 웹 경로·요청별 검사 모드 |
| `scripts/apply-waf.py`, `waf-logrotate.conf` | root 전용 WAF 추가 파일 적용·전용 모드 로그 회전 |
| `test_app.py`, `test_broker.py`, `test_practice_mode.py`, `test_lab_types.py` | HMAC·세션·입력·소유권·배포 제한 회귀 |



<a id="source-429cb0b9c8ff56ec-h11"></a>
<a id="record-0626b6a60eaf57df2626247fcc4b804c242aa3535afc7d516abbe410015b905d"></a>

## 매니페스트 형식과 확장

`cve_list.json`은 JSON 배열이며 `/api/list`는 시작 때 읽고 검증한 원래 값을 그대로 반환한다. `type`을 생략한 기존 Log4Shell 항목은 `managed-http`로 취급한다.

| 항목 | 유형 | 실행·접속 범위 |
|---|---|---|
| CVE-2021-44228 | `managed-http` | Log4j 2.14.1, loopback 18081, 웹 실행·중지 |
| CVE-2021-41773 | `managed-http` | Apache httpd 2.4.49, loopback 18082, 웹 실행·중지 |
| CVE-2021-42013 | `managed-http` | Apache httpd 2.4.50, loopback 18083, 웹 실행·중지 |
| CVE-2022-0543 | `managed-terminal` | Redis Ubuntu 5:5.0.7-2, 고정 내부 서비스·웹 터미널 소스 구현, 운영 검증 별도 |
| CVE-2017-7494 | `managed-terminal` | Samba 4.6.3, 고정 내부 서비스·웹 터미널 소스 구현, 운영 검증 별도 |
| CVE-2021-3156 | `managed-terminal` | 별도 rootless sudo 환경을 중앙 adapter로 연결, 웹 시작·터미널 열기·중지, 전체1세션 |

`managed-terminal`은 HTTP 앱용 image/port/path 값을 받아 임의 실행하지 않는다. Redis/Samba 고정2개와 sudo 중앙 adapter1개만 연결하며 이미지는 각각의 root 관리 번들·설치 config에서만 읽는다. 기존 이미지 export 스크립트의 HTTP3개와 Redis/Samba의 전용2개 archive 번들은 분리한다. 소스 필드가 존재하거나 이미지가 준비됐다는 이유만으로 실행 중·공격 재현 완료로 표시하지 않는다.

다음은 `managed-http` 항목의 형식이다. 이 유형의 `image_id`는 필수 고정 검증 필드다.

```json
{
  "cve_id": "CVE-2021-44228",
  "software": "Apache Log4j / Spring Boot Lab",
  "vulnerable_version": "2.14.1",
  "image_tag": "groot-labs/log4shell:2.14.1",
  "image_id": "sha256:6534536682a48754c4ffd98f8d7fadec20180b15dae361c14e0a672f57e73d36",
  "host_port": 18081,
  "container_port": 8080,
  "description": "Java 문자열 로깅 실습",
  "path": "/log4shell/"
}
```

최대 32개 항목을 지원하며 `managed-http`는 CVE당 TCP 포트 1개를 사용한다. `host_port`는 1024–65535, `container_port`는 1–65535이며 호스트 포트는 서로 달라야 한다. `path`는 컨테이너 앱의 경로이며 실행 명령으로 해석하지 않는다. 같은 출처 링크는 HTTP3항목의 고정 실습 경로와 terminal3항목의 고정 터미널 경로를 지원한다. `local-cli`·`managed-terminal` 항목에는 HTTP용 Docker 이미지·포트·경로 필드를 받지 않는다. 유효한 입력이어도 18090 등 이미 사용 중인 호스트 포트는 Docker 시작 시 충돌 오류로 남는다.

`local-cli`는 root 소유 `0600` 파일 `/var/lib/capstone-offline-labs/nonweb-status.json`의 고정 schema·소유권·유효기간(최대 600초)을 읽기만 한다. 파일이 없거나 잘못됐거나 만료되면 `needs_setup`으로 표시한다. `ready`도 `verification: environment_only`이며 `attack_tested`·`host_scenario_verified`는 항상 false다. 비권한 CLI는 이 root 파일을 작성하지 않는다.

httpd 두 이미지는 정적 공개 fixture만 제공하고 CGI/CGID·ScriptAlias·ExecCGI를 사용하지 않는다. CGI 명령 실행 재현을 제공하거나 검증했다는 의미가 아니다. 관리 API의 `Origin: null` 거부·CORS 차단을 유지한다.

추가할 HTTP 이미지는 해당 실행 계약(비root·읽기 전용·tmpfs만 쓰기)에 맞게 준비하고 정상 기동을 먼저 검증한다. DB·다중 포트·추가 볼륨·root 기동이 필요한 임의 공개 이미지를 JSON에만 넣으면 모두 실행되는 구조는 아니다. terminal 유형도 Redis/Samba 고정2개와 sudo adapter1개만 연결한다. 계약을 확장할 때는 broker·회귀·격리를 함께 검토한다. CVE 번호와 실제 취약 버전/구성의 대응도 관리자가 확인해야 한다.

새 CVE를 목록에 추가하는 것만으로 같은 HTTPS 주소의 웹 경로가 생기지는 않는다. A TLS 프록시·WAF·C Apache의 고정 경로, 쿠키/리다이렉트 처리, UI의 지원 링크를 별도로 준비하고 검증해야 한다. 준비되지 않은 CVE의 웹 접속 링크는 비활성화한다.

기존 실행 중 HTTP 항목의 이미지·포트를 임의 변경하면 receipt 대조에서 충돌로 거절된다. 해당 컨테이너를 멈추고 서버 백업·데이터 보존·명시적 교체를 검토한 후 새 계약으로 갱신한다. 웹에서는 임의 컨테이너 삭제·초기화·이미지 업로드를 제공하지 않는다. Redis/Samba의 고정 **중지** 동작에 포함된 자기 컨테이너 제거는 앞의 유형별 계약을 따른다.



<a id="source-429cb0b9c8ff56ec-h12"></a>
<a id="record-517fea725359d7816728d34aa4d215bdc09452aa8ab73fab464cc18453b62cdd"></a>

## 오프라인 준비와 최초 설치

전제는 Ubuntu 24.04 amd64, Python 3.12, Docker Engine 28 이상, systemd, nftables, 기존 SSH 관리 경로다. 설치 스크립트는 OS 패키지를 내려받지 않는다. 다른 CPU/Python 버전은 맞는 wheel과 잠금 파일을 별도로 준비한다. Mac에는 서버 패키지를 설치하지 않는다.

1. 연결된 준비 환경에서 검토한 이미지를 확보하고 실제 로컬 이미지 ID를 카탈로그와 대조한다. Log4Shell은 기존 이미지·JAR, httpd 두 항목은 [공식 이미지와 오프라인 빌드 절차](images/httpd/README.md)를 사용한다. 기반 이미지가 로컬에 있는지 먼저 확인하고 `--network=none --pull=false`로 빌드한다. 이미지 ID를 임의로 대체하거나 태그만 신뢰하지 않는다.

```sh
# 소스 디렉터리에서 실행. 이미지 export는 준비된 Linux Docker 호스트에서 수행한다.
cd infra/groot-c/offline-labs
bash scripts/export-images.sh cve_list.json /new/offline-images
# 기존 Python 3.12/pip을 갖춘 준비 환경: 설치 없이 wheel 다운로드·해시 대조
bash scripts/prepare-python.sh /new/offline-wheels
```

현재 export는 `managed-http` **3개 이미지만** 저장하고 전체6항목 카탈로그를 함께 복사한다. Redis/Samba의2개 이미지는 `LAB_NONWEB_BUNDLE`로 지정하는 [별도 번들](../nonweb-labs/README.md)에 담는다. sudo rootless 이미지·도구도 HTTP 묶음에 포함되지 않으며 [별도 준비 절차](nonweb/sudo/README.md)를 따른다. 독립 DVWA는 이 실습 이미지 export/import의 대상이 아니다.

2. 승인된 매체로 소스·카탈로그·이미지 묶음·wheel을 옮긴다. `SHA256SUMS`도 별도로 신뢰할 수 있는 이관 기록과 대조한다. 파일 해시만으로 공급자의 신원을 증명하지 않는다.

```sh
# 폐쇄망 Linux 서버: 해시·기존 태그 충돌·load 후 이미지 ID 검사, pull 없음
sudo bash scripts/import-images.sh /approved/offline-images
```

import는 이미지만 적재한다. 동봉 카탈로그를 운영 경로에 자동 설치하거나 앱을 시작하지 않는다. 신규 설치는 검토한 카탈로그를 아래 설치 소스에 두고, 기존 서버의 카탈로그 갱신은 `/etc/capstone-offline-labs/cve_list.json`을 root 통제로 교체한 뒤 두 서비스를 재시작하는 별도 절차다.

3. 사용자 진입점은 루트 `deploy.sh` 하나다. 현재 service schema9는 HTTP3/터미널3의6항목 카탈로그를 검증하고, 콘솔 설치·sudo 준비 다음에 `LAB_NONWEB_BUNDLE`의 고정 nonweb bootstrap을 호출한다. 터미널 자산과 관리 소스도 설치 지문에 포함한다. 아래 CLI는 그중 콘솔 내부 설치기만 실행하며 Redis/Samba 런타임 전체 설치를 대신하지 않는다. 별도 사전 점검이나 격리 검증이 필요하면 사용할 수 있다. 이미 설치된 `/opt`·`/etc`·계정·unit·broker 상태·전용 네트워크가 있으면 거절하며, 운영 서버 갱신이나 자동 삭제용으로 사용하지 않는다.

```sh
# 첫 설치 사전 검사: 파일/계정/네트워크/컨테이너 생성, 다운로드 없음
sudo bash scripts/install.sh --check \
  --manifest /approved/offline-images/cve_list.json \
  --origin https://lab.example.org /approved/offline-wheels

# 실제 최초 설치: 값 대신 root:root 0600 키 파일의 경로만 전달
sudo bash scripts/install.sh --apply \
  --manifest /approved/offline-images/cve_list.json \
  --origin https://lab.example.org \
  --admin-key-file /approved/private/common-admin-key /approved/offline-wheels
```

`--origin`을 생략하면 `http://127.0.0.1:18090`와 `http://localhost:18090`만 허용한다. 기존 운영 도메인을 기본값으로 복제하지 않는다. 공개 HTTPS origin은 경로·인증정보 없이 명시해야 하며, root가 설정한 HTTPS 호스트에만 Secure 모드 쿠키를 발급한다. 외부 입력의 `X-Forwarded-Proto`는 이 판단에 사용하지 않는다. 예전 `install.sh WHEEL_DIRECTORY` 호출은 loopback 전용 `--apply`로 호환한다.

검사는 Ubuntu24.04/amd64·Python3.12·rootful Docker28 이상과 필요한 기존 도구, 소스 전체의 symlink, strict catalog, HTTP3개 이미지의 정확한 로컬 ID/플랫폼, 이미 점유된 포트와 Docker publish, 계정·unit·nft·전용 bridge 충돌을 확인한다. wheel은 고정 inventory의 크기/SHA와 ZIP 내부 경로·중복·파일 유형·CRC까지 쓰기 전에 검사한다. `--check`는 로컬 Unix Docker 소켓과 읽기 명령 및 nft 구문 dry run만 사용하며 이미지 적재, 앱 실행, OS 패키지 설치를 하지 않는다.

키는 **선택적인 WAF 차단 예외용이며 콘솔 로그인 조건이 아니다.** `--check`는 키 파일 없이도 가능하다. standalone `--apply`에서 키 파일을 생략하면 무작위 파일을 생성하고 경로만 안내한다. 공통 Wazuh 키를 사용할 경우 전체 초기 설정기가 root 비공개 파일로 전달하며, standalone 설치기는 Wazuh 비밀번호를 조회하거나 변경하지 않는다. 키 원문을 명령행·출력·로그에 넣지 않는다. 입력 파일은 root 소유의 쓰기 제한 경로 아래 `root:root 0600`, 설치 파일은 `root:capstone-labs 0640`이다.

콘솔 설치기는 테마·파비콘·터미널 화면·로컬 vendor를 포함한 `static/` 전체와 검증한 wheel 내용을 복사하고 전용 guard·broker·loopback FastAPI 서비스를 구성한다. 컨테이너 실습을 자동 실행하지 않는다. `/api/list`, broker `/api/status`, 격리 규칙과 서비스 활성 상태를 확인한 뒤 완료로 기록한다. `/var/lib/capstone-offline-labs/install-state.json`은 root0600이며 단계·완료 여부·설치 파일의 SHA/권한을 보존한다. 실패 시 `failed_partial`과 마지막 단계를 남기고 후속 변경을 중단한다. 생성된 계정·파일·네트워크를 임의 삭제하지 않으므로, 원인을 검토하고 해당 부분 설치를 처리한 뒤 다시 진행한다. 기존 설치의 반복 검증은 전체 초기 설정기의 관리 receipt·runtime 검사 경로를 사용한다.

```sh
# loopback 관리 UI/API만 점검하는 기존 SSH 터널 예시
ssh -N -L 18090:127.0.0.1:18090 groot-c-int
# 로컬 브라우저: http://127.0.0.1:18090/
```

이 콘솔 내부 설치기는 A/C 공개 프록시·TLS/WAF 구성, Redis/Samba 런타임·전용 daemon·이미지 반입을 대신하지 않는다. 전체 초기 설정기가 해당 역할을 별도로 담당한다. 신규 환경의 주소·인증서·SSH 별칭은 설정 파일에서 검토하며, 제공 standalone 프록시 예시는 현재 A/C 주소에 대한 자료다. 기존 C에는 이미 콘솔이 설치되어 있으므로 이 최초 설치기를 다시 실행하지 않는다.

과거 sudo `local-cli`는 상태 조회만 제공했다. 현재는 rootless 준비 상태와 중앙 adapter를 검사해 `managed-terminal` 시작·열기·중지를 제공한다. rootless 도구·이미지·계정·상태 발행기는 [독립 설치 경로](nonweb/sudo/README.md)에서 준비하며, 이 설치기는 `nonweb/`를 복사하거나 과거 설치 기록 스크립트를 실행하지 않는다. DVWA는 원래 독립 서비스로 유지하며 이 콘솔 범위에 포함하지 않는다. 전체 초기 설정의 구현·fixture 검증과 실제 새3VM 전체 설치 검증은 구분한다.



<a id="source-429cb0b9c8ff56ec-h13"></a>
<a id="record-d03ed5da277e07f7dec062a99e8116f81eeac3698581dbac4c0ba6b34d0acd59"></a>

## API

공개 URL에는 `/log4shell` 접두사가 붙고 loopback 직접 접속에서는 `/api/...`다. 목록·상태·실행·중지는 키가 필요하지 않지만 기존 내부망·허용 Host/Origin 경계는 유지된다. 키나 고정 해시를 `Authorization` 또는 요청 본문으로 전달하지 않는다. WebCrypto 서명을 만드는 UI를 사용하며 비밀 값을 명령행에 넣는 예시는 제공하지 않는다.

| 요청 | 입력·결과 |
|---|---|
| `GET /api/list` | 매니페스트 JSON 배열 그대로, 무키 |
| `GET /api/status` | `labs` 배열, `deployment_allowed`, `safety_error`, 확인 시각, 무키 |
| `POST /api/deploy` | 등록된 HTTP/terminal 항목의 `cve_id` → 고정 환경 시작 또는 이미 실행 중인 동일 컨테이너, 무키 |
| `POST /api/stop` | 같은 입력 → HTTP3개는 정지·보존, Redis/Samba는 세션 정리·컨테이너 제거, sudo는 전체 컨테이너 중지, 무키 |
| `GET /api/challenge` | `challenge_id`(32hex), ASCII `message`, `expires_at`, `algorithm: HMAC-SHA-256`, `key_derivation: SHA-256`; 30초·1회용 |
| `POST /api/session` | `{"challenge_id":"…","proof":"…"}`만 허용 → `mode: exempt`, `expires_at` 및 600초 HttpOnly 세션 쿠키 |
| `GET /api/session` | 쿠키 상태 `{mode: enforce 또는 exempt, expires_at: epoch 또는 null}`, 무키 |
| `DELETE /api/session` | 빈 JSON 객체 `{}` → 쿠키 해제, `{mode: enforce, expires_at: null}` |
| `POST /api/terminal/open` | 고정 terminal 항목의 `cve_id`·`rows`·`cols` → 메모리에만 보관하는 세션 ID |
| `POST /api/terminal/poll` | 세션 ID·`cursor` → 최대10초 대기 후 base64 출력·다음 cursor·종료 상태 |
| `POST /api/terminal/input` | 세션 ID·base64 입력, 요청당 원본 최대2048바이트 |
| `POST /api/terminal/resize` | 세션 ID·`rows`(2–100)·`cols`(20–300) |
| `POST /api/terminal/close` | 세션 ID → 해당 연결 종료, 실습 컨테이너는 유지 |

터미널 API는 등록된 같은 출처 `Origin`을 요구하고 세션을 Host·클라이언트 IP에 결속한다. 세션 ID는 JSON 본문으로만 전달하며 URL·브라우저 저장소에 남기지 않는다. 출력은 HTML로 삽입하지 않고 터미널 바이트로 처리한다. 출력으로 인한 클립보드 변경과 자동 링크 기능은 비활성화한다. 별도의 호스트 셸·임의 이미지·Docker 옵션을 받는 API는 없다.

내부 `/api/gateway-session`은 A 프록시의 세션 확인용이며 공개 경로에서는 404로 막는다. `X-Lab-Gateway: 1`과 프록시가 고정한 정확한 등록 항목 `X-Lab-ID`를 요구한다. 공개 프록시는 웹3항목만 연결한다. Java 앱의 CSRF 토큰·쿠키 검증은 그대로 유지한다.

현재 카탈로그의 `local-cli` 실행·중지는 `local_cli_managed_separately`로409를 반환한다. 이미지 미준비·소유권 충돌·격리 검사 실패도 409, 잘못된/만료된/replay된 HMAC 검증은 입력 반사 없는 401, 다른 Origin은 403이다. 예외 검증에서 추가 필드나 `Authorization`을 보내도 거부한다. challenge 발급 한도는 429와 `Retry-After: 30`으로 안내한다. 일반 실행 API의 허용하지 않은 필드/타입은 422, 실행 서비스 연결 실패는 503이다. API 응답은 `no-store`로 처리한다. 원본 Docker stderr는 웹 응답에 노출하지 않으며 키·고정 해시·proof를 웹 오류 응답이나 콘솔 로그에 출력하지 않는다.



<a id="source-429cb0b9c8ff56ec-h14"></a>
<a id="record-8b96c84b5517992c1040e0421dc24e4e9550c3f539fc9e3a521dd523e7c9bcd0"></a>

## 운영·복구

```sh
sudo systemctl status capstone-offline-labs capstone-offline-labs-broker capstone-offline-labs-guard
sudo python3 -B /opt/capstone-offline-labs/guard.py check
sudo journalctl -u capstone-offline-labs -u capstone-offline-labs-broker --since today
# manifest를 root 통제 파일로 검토·변경한 다음 적용
sudo systemctl restart capstone-offline-labs-broker capstone-offline-labs
```

공통 키를 바꿀 때는 Wazuh Dashboard `admin` 비밀번호와 C의 `/etc/capstone-offline-labs/admin-token`을 root 관리 절차로 동기화한다. 파일 소유권 `root:capstone-labs`·모드 `0640`을 유지하고 FastAPI를 재시작한다. Wazuh 비밀번호를 변경해도 C의 파일이 자동 갱신되지는 않는다. 키가 바뀌면 이전 키로 서명한 예외 세션은 유효하지 않다. 실행 중인 실습 컨테이너는 그대로이며 개별 사용자 계정·SSO 기능은 제공하지 않는다.

WAF 추가 파일은 기존 컨테이너의 **writable layer**에 설치한다. 컨테이너 재시작·동일 컨테이너를 유지한 호스트 재부팅에는 남지만 **full recreate에는 남지 않는다.** 승인된 전체 재생성 뒤에는 새 컨테이너를 검토하고, A의 root가 `scripts/apply-waf.py`에 `--container-id`(전체 ID)와 `--image-id`(고정 SHA)를 전달해 두 파일을 다시 적용한 후 실습 TLS 경로를 활성화해야 한다. 이미 같은 바이트의 파일이 있으면 재확인하지만 다른 내용이 있으면 덮어쓰지 않고 거절한다. 기존 배포 버전의 갱신에는 변경 전 SHA·백업·복구를 갖춘 별도 절차가 필요하다. 이 도구는 LLM/MCP에 Docker 권한을 위임하는 도구가 아니다.

추가 대상은 `/etc/nginx/conf.d/zz-capstone-labs.conf`와 `/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-CAPSTONE-LABS.conf`다. 검토한 원본은 A의 `/etc/capstone-offline-labs-waf/`에 보관한다. 적용기는 기존 컨테이너·이미지·mount를 바꾸지 않고 `nginx -t`와 reload를 수행하며, 다음 기존 고정 파일의 SHA가 유지되는지 검사한다.

- `/etc/nginx/conf.d/zz-capstone-evidence.conf`
- `/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-CAPSTONE-SCANNER.conf`
- `/etc/modsecurity.d/modsecurity.conf`

전용 모드 로그에는 요청 식별자·클라이언트 주소·검사 모드·상태를 기록하며 키·proof·예외 쿠키를 기록하지 않는다. `waf-logrotate.conf`는 이 추가 로그용이며 기존 감사·access·raw generation 회전 계약을 대체하지 않는다.

현재 원래 경로 백업은 A/C `/var/backups/capstone-offline-labs/20261022/`에 있다. v1 이전 경로 원복은 **기존 nginx.conf·log4shell-java.conf의 내용**을 원래 파일에 복원하고 각각 문법 검사/reload하는 절차다. 후속 WAF 전용 경로까지 적용한 뒤 원복할 때는 먼저 새 TLS 실습 경로를 비활성화하고, 이번에 추가한 WAF 두 파일도 소유권·현재 SHA를 확인한 후 별도로 복구한다. v1 백업만으로 후속 변경 전체를 되돌렸다고 판단하지 않는다. A nginx.conf는 Docker 단일 파일 bind mount이므로 inode를 보존해 내용을 쓴다. 전체 디렉터리·기존 Java 컨테이너·DB를 덮어쓰거나 삭제하지 않는다. 새 실습을 중지한 뒤 관리 웹/broker 서비스만 비활성화할 수 있고, nft guard는 실습 컨테이너가 남아 있는 동안 유지한다.

최초 Log4Shell 운영 이미지 아카이브: `/var/lib/capstone-offline-labs/images/log4shell-2.14.1.tar`. 이 파일은 요청한 로컬 이미지 저장소이므로 정리 대상 임시 다운로드와 구분해 보존한다. 실행 소스는 `/opt/capstone-offline-labs`, root manifest·키는 `/etc/capstone-offline-labs`, receipt는 `/var/lib/capstone-offline-labs/runtime.json`이다.



<a id="source-429cb0b9c8ff56ec-h15"></a>
<a id="record-bb8be234c3139ca5497f448e235c44c154dbe97b76dc1a70fa7a98966ce397bf"></a>

## 검증 범위

**2026-10-23 확장 전 범위 정정 기록:** 당시 카탈로그는4항목·웹3경로였으며 DVWA는 원래 독립 서비스로 유지한다. 정정 후 C native 회귀64개·최종 HTTP35개를 통과했다. 카탈로그4개·기존 DVWA 독립 주소200/테마 미주입, 제거한 DVWA3경로404·실행/중지unknown_cve409, 기본 HMAC 정상·DVWA 전용 쿠키 미발급, Apache 두 버전의 무해 canary403→200→403·sudo ready를 확인했다. 최신 자산의 서버 SHA와 새로고침한 Safari에서의 표시·양방향 전환도 대조했다. 아래5항목·DVWA 통합 검증과 기존 JSON은 당시 이력으로 보존하며, 현재 구성의 검증 완료 주장으로 사용하지 않는다.

**다중 실습 후속 당시 이력 (2026-10-22):** 5항목 카탈로그·유형 경계의 backend 회귀 **64개**, 공개 HTTPS **31개**와 DVWA 예외 경계 **15개** 검사를 통과했다. 이는 API·고정 라우팅·무해한 정상/정책 요청 검증이며 실제 취약점 공격·탐지·차단 E2E 결과가 아니다. DVWA는 HTTP 세션과 Safari에서 기본 실습 계정 로그인·Welcome·Security 페이지를 확인했고 보안 수준 `impossible`을 변경하지 않았다. DVWA sandbox의 전용 예외 cookie만으로 WAF 통과, 다른 실습·관리 API에서 무효, 양 cookie 해제 후 차단 복원을 HTTPS로 검증했다. 새 실습의 합성 검사9건은 WAF→Wazuh alerts→Indexer까지 같은 transaction으로 대조했다. sudo의 10/23 후속 환경 검증은 native26회귀·7단계 무해 실행으로 완료했다. 정식 publisher의 ready→중지 시 needs_setup→새 컨테이너 실행 시 ready도 실제3단계 확인했고, enabled/active인 60초 timer가 root:root0600·TTL300초 상태 파일을 갱신한다. 실제 권한 상승·호스트 탐지 E2E는 미실행이다.

[공식 규칙 후보 27개](rule-source-candidates.json)는 CRS 7·ET Open 10·Wazuh 10개의 **조사 자료**다. 운영 규칙 변경·자동 설치·실제 엔진 발화 검증은 하지 않았다. 고정 버전·설치된 ID/rev·제외 조건 대조와 별도 승인·격리 검증이 필요하다.

**기존 v1 검증 기록:** 2026-10-22 C에 오프라인 콘솔을 설치하고 A/C 프록시를 reload했다. 당시 FastAPI·broker native 회귀 25개, bearer 인증 API·시작/중지/재시작·중복 실행 동일 ID, Java 8u181·Log4j2.14.1 버전200, 외부 HTTPS·HTTP308·위조 TLS hint 무효·내부 관리 경로403·DVWA200을 확인했다. 브라우저에서는 로그인 전 다크 UI를 확인했고 인증 후 동작은 API와 모의 DOM/API 회귀로 확인했다. 이 기록은 이전 bearer·SSH 터널 접속 방식의 결과이며 최종 HMAC·WAF 경로 검증 결과로 해석하지 않는다. 해당 시점의 네트워크 차단·컨테이너 상태·SHA 증거는 `deployment-validation-20261022.json`에 남긴다.

**후속 HMAC·같은 HTTPS 경로 검증:** 2026-10-22 다음 결과를 직접 확인했다. 기존 v1 기록과 구분한다.

- C 서버 native 회귀 **43개 통과**. 프론트는 Node 문법 검사 및 실제 WebCrypto/독립 HMAC 대조를 포함한 모의 DOM/API 회귀를 통과했다.
- 실제 HTTPS 기본 **18개**, 경로 보완 후 **37개 검사 통과**: 익명 정상 요청 200, 익명 canary 403, HMAC 인증 200, 예외 세션의 canary GET·POST 200, 예외 해제 후 403, 서명 재사용 401, 원문 키를 보내는 이전 프로토콜 401을 확인했다.
- 무키 Docker 실행의 중복 요청·중지·재시작 **6개 검사 통과**. 기존 관리 컨테이너의 동일 ID를 유지했다.
- Safari에서 무키 콘솔, 같은 HTTPS Java 실습 링크, 실제 무해한 문자열 로깅 200을 확인했다.
- WAF raw 감사 로그 **5건**에서 일반 모드 403 **3건**, 예외 모드 200 **2건**, 0보다 큰 클라이언트 포트를 확인했다. 검사한 로그에는 `Authorization`, 예외 세션 쿠키, `proof`가 없었다.

**Wazuh manager 수신:** 같은 요청 marker 5건을 B의 Wazuh manager `alerts.json`에서도 확인했다. `agent.id=001`, `rule.id=100101`, `rule.level=7`이며 HTTP 403 3건·200 2건으로 WAF 감사 기록과 대응한다. 같은 5건이 `wazuh-alerts-4.x-2026.10.22`에 색인된 것도 CA·호스트명 검증 HTTPS 조회로 확인했다. Dashboard 화면의 시각 검증과는 구분한다.

raw 수집 경로에서 앞서 `publish_pending` / `reader_restart_guard_failed` 상태가 관측되었고, 이후 reader guard가 `ready`로 자연 회복한 것을 확인했다. 21:51 기존 timer의 자연 진행으로 ModSecurity raw는 active/rev44/gen10, Suricata는 active/rev42/gen8이며 Vector·Wazuh 실행과 새 세대 checkpoint 도달을 확인했다. 설정·체크포인트를 수동 조정하지 않았다.

독립 검토에서 Nginx의 정규화 경로와 ModSecurity 원본 URI의 차이로 이중 슬래시·dot segment 경로에 기본 차단이 빠지는 것을 무해 canary로 확인했다. 전용 Host와 Nginx의 단일 실습 proxy location으로 범위를 제한하고 룰의 중복 원본 URI 조건을 제거했다. 이중 슬래시·dot segment·퍼센트 인코딩 6개 경로 각각에서 기본403/예외200/해제403을 최종 확인했다. 기존 WAF producer·scanner·engine 고정 SHA와 컨테이너 시작 시각은 유지했다.

전용 WAF 규칙의 `X-Groot-Lab-Check: mode-check-v1`은 일반/예외 모드의 차이를 확인하는 무해한 합성 canary다. canary의 차단·통과·감사 기록 확인을 실제 공격 탐지나 취약점 재현 성공으로 보지 않는다. 실제 공격·콜백·탐지·차단 E2E, 호스트 재부팅, 새 VM 전체 설치, 추가로 등록할 앱의 호환성은 별도 검증 범위다. 실습 컨테이너의 오프라인 고립은 기존 서버 전체가 물리적으로 완전히 단절됐다는 주장과 구분한다.

참고한 공식 계약: [FastAPI 정적 파일](https://fastapi.tiangolo.com/tutorial/static-files/), [Uvicorn 실행](https://fastapi.tiangolo.com/deployment/manually/), [Docker 포트 게시](https://docs.docker.com/engine/network/port-publishing/), [Docker 보안](https://docs.docker.com/engine/security/). Python 배포 출처·버전·파일별 SHA는 `wheel-inventory.json`에 보존한다.


</details>

## 2026-11-08 23:18 KST — 공개 진단 코드 표시

A/B/C `/opt/capstone-diagnostics/diagnostic_journal.py` 각1파일을 `ddf0cc0c0a62180683aef1b5c796b193a8628ba1d278a6269f28e3c25fd48bd4`에서 `8336e073a249f9a31d4ea5fd90d506f126aada2bf93ec0dcfa47fc135383c1cc`로 변경했다. 기존 비밀 마스킹 우선순위를 유지하고 공개 사유85종 및 숫자 종료값/짧은 상태명을 보존한다. reader 재시작3회·봇/수집기 재시작0, 독립15분 원복 준비→A23:18:26/B23:18:35/C23:18:42 확정·noop·타이머 해제. 복구본은 각 서버 `/var/lib/capstone-diagnostics/journal-redaction-20261108`; 과거 설치 영수증은 덮어쓰지 않고 증분 원장 추가. 원본은 위 SHA와 직전 Git `0ceb3686bfe334548af7e908becd5058a75a67dd`에서 복구 가능하다. [실제 MCP·채팅·한계](../infra/mcp/journal-excerpts.md). 복합108 하네스 후보는 운영 미적용이다.

## 2026-11-13 17:06~17:26 KST — 사건 조사 인용 안내 위치 후보 적용 후 원복 (B, 관리자231 경유)

사용자 승인("인용 안내 후보 적용해줘")에 따라 적용했다. 컨트롤러 잠금 아래(0.05초) 8개 파일을 원자 교체했다. 실행 사본 4곳은 `96876e4e`→`d6de30da`, 플러그인 2곳은 `28ef2a73`→`7bb48edb`로 바꿨고, 컨트롤러 내장 실행기 상수(`178c8dbb`→`a3218877`)와 Ollama 영수증도 갱신했다. 백업과 45분 원복 타이머는 `/var/lib/capstone-service-grounding/20261113-citation-prefix/`에 있다. 컨트롤러 자체 내장본 검증과 틱 정상을 확인했다. 공동 채널 실제 조사에서 판단 호출 3번의 캐시 재사용(7.8/3.5/1.1초)을 확인했다. 그러나 메모가 처음 들어간 호출에서 과거에 없던 깨진 출력이 나와 17:26:19에 원복했다(8개 기준 SHA 복귀, 타이머 정지, 틱·내장본 검증 정상). Hermes 컨테이너와 봇은 재시작하지 않았다. [후보·결과](../infra/validation/citation-prefix/README.md).

## 2026-11-13 19:31 KST — history-auto A→B 전송 상한 동기화 (A·B, 관리자231 경유)

사용자 승인("history 전송 상한 적용해줘")에 따라 적용했다. A(19:31:16)에서는 관문을 `dc4fc243`→`fd1e7769`로 바꾸고, sudoers digest 한 줄을 같은 값으로 바꿨다(후보·전체 `visudo` 통과). B(19:31:28)에서는 전송 잠금 아래 `worker-b.sh`·`transfer-lib.sh`·`runtime.sha256`을 교체하고 runtime 검사를 통과했다. 원본은 각 호스트의 `/var/backups/capstone-history-transfer-capsync-*`에 있다. 수동 전송 1회(3분 17초)에서 338배치를 확인했다(신규 82). 09:44부터 이어진 B 실패가 해소됐고 A·B 실패 유닛은 0이다. 원인은 같은 날 A 보존소 상한만 올린 변경(DIAGNOSTIC_HISTORY 참고)이다. [적용 기록](../infra/normalization/vector/history-auto-transfer/README.md).

## 2026-11-13 20:14~20:18 KST — 사건 조사 인용 안내 위치 재적용·확정 (B, 관리자231 경유)

실제 생성 A/B 평가(30회, 오류 A 4·B 2, 깨진 출력 0/0) 뒤 사용자 승인("인용 안내 후보 재적용해줘")에 따라 재적용했다. 같은 8개 파일을 교체했고(컨트롤러 `a3218877`, 실행 사본 `d6de30da`, 플러그인 `7bb48edb`), 백업과 원복 스크립트는 `/var/lib/capstone-service-grounding/20261113-citation-prefix-r2/`에 있다. 내장본 자체 검증과 틱 정상을 확인했다. 공동 채널 실제 조사 1건이 정상 완료(깨진 출력·도구 오류 0)된 것을 보고 20:18:57에 확정하고 원복 타이머를 해제했다. Hermes 컨테이너와 봇은 재시작하지 않았다. [기록](../infra/validation/citation-prefix/README.md#재적용과-확정-2026-11-13-20142018-사용자-승인-인용-안내-후보-재적용해줘).

## 2026-11-13 20:42 KST — 조회 끝 시각 미래 오류 수정 적용 (B, 관리자231 경유)

사용자 승인("조회 끝 시각 수정 적용해줘")에 따라 적용했다. 공동 채널 작업자 `review_channel_worker.py`(`bba9a951`→`9973fbf1`)와 공통 계약 `chat_contract.py` 3곳(`4ef328b6`→`2cae4b65`)을 교체했고, Ollama 영수증을 갱신했다. 대기열이 비어 있어 `capstone-ollama-chat`만 재시작했다. 백업은 `/var/backups/capstone-time-correction-20261113T204212`에 있다. 실제 채팅에서 정상 경로(조회 오류 0, 실제 보고서 게시, 교차 검토 정상)를 확인했다. 수정 경로(미래 시각 거절, 정정된 거부의 실패 미판정)는 회귀 시험으로 확인했다. [기록](../infra/validation/time-correction/README.md).

## 2026-11-13 21:22 KST — 상대 시각 구간("최근 N분") 고정 적용 (B, 관리자231 경유)

사용자 승인("상대 시각 구간 적용해줘")에 따라 적용했다. 사본 11곳을 교체했다(관리 실행기 `d6de30da`→`cf6124ad` ×4, query-completion `7bb48edb`→`accf2b07` ×2, 공통 계약 `2cae4b65`→`43fdbb1f` ×3, Ollama 하네스 `5cbdb9fc`→`5d79bb9d` ×2). 컨트롤러 내장본(`a3218877`→`6ecc3fd0`)과 Ollama 영수증도 갱신했다. 원복 타이머 45분을 건 상태에서 Ollama 봇만 재시작했다. 사후 점검은 오류 0이었다. 실제 채팅에서 Hermes 조사(첫 조회 `lookback_minutes: 30`)와 Ollama 단순 목록(30분 1회 조회)을 확인하고 21:30:38에 확정했다. 표식·백업은 `/var/lib/capstone-service-grounding/20261113-relative-window`에 있다. 같은 채팅의 Ollama 교차 검토 `ValueError`는 적용 전부터 있던 결함이라 별도로 남겼다. 20:42 '조회 끝 시각' 적용 기록의 "교차 검토 정상"도 같은 이유로 정정했다. [기록](../infra/validation/relative-window/README.md).

## 2026-11-13 21:51 KST — Ollama 도구 목록 계약 수정 적용 (B, 관리자231 경유)

사용자 승인("교차 검토 수정 적용해줘")에 따라 적용했다. `/opt/capstone-ollama-trial/policy.py`와 영수증 `sources.policy.py`를 `7716bdd3`→`832d8c69`로 바꿨다. 두 대기열이 비어 있을 때 적용했고 45분 원복 타이머를 걸었으며, Ollama 봇만 재시작했다. 사후 점검에서 8개 서버가 모두 통과했고, Harness² 도구 노출은 0이었다. 실제 채팅에서 공동 채널 교차 검토(모델 3회·독립 읽기 3회·대조 게시)와 Ollama 단독 조사형 질문(MCP 8개 연결·모델 3회)을 확인하고 21:59:51에 확정했다. 표식·백업은 `/var/lib/capstone-service-grounding/20261113-catalog-contract`에 있다. 새로 드러난 교차 검토 품질 문제(거짓 이견 1건, 범위 밖 읽기)와 단독 판단 미완료는 별도로 남겼다. [기록](../infra/validation/catalog-contract/README.md).

## 2026-11-13 22:22 KST — 교차 검토 요청 조건 근거 거절 적용 (B, 관리자231 경유)

사용자 승인("거짓 이견 수정 적용해줘")에 따라 공동 채널 작업자 `review_channel_worker.py`를 `9973fbf1`→`47811503`으로 바꿨다. 공동 채널 설치기 영수증의 작업자 항목은 20:42 배포가 남긴 `bba9a951`에서 새 SHA로 고쳤다. 서비스는 재시작하지 않았다(작업마다 새 프로세스). 설치기 영수증 5항목이 모두 일치한다. 실제 채팅에서 교차 검토는 정상 완료됐지만, 새 검사는 발동하지 않았다. 대신 다른 종류의 거짓 이견 2건(표본/전체 혼동, 질문에 없는 필터로 좁힌 조회와 비교)과 Hermes의 범위 밖 방화벽 조회 실패가 드러났다. 22:27:18 확정. 표식·백업은 `/var/lib/capstone-service-grounding/20261113-peer-query-scope`에 있다. [기록](../infra/validation/peer-query-scope/README.md).

## 2026-11-13 22:46 KST — 조회 범위 일치 적용 (B, 관리자231 경유)

사용자 승인("조회 범위 수정 적용해줘")에 따라 적용했다. 컨트롤러 잠금 아래 사본 8곳을 교체했다(관리 실행기 `cf6124ad`→`bc19115d` ×4, query-completion `accf2b07`→`3847d9c8` ×2, Ollama 런타임 `1e7aefa6`→`026a2cf9`, 공동 채널 작업자 `47811503`→`f4f426c7`). 컨트롤러 내장본, Ollama 영수증 3항목, 공동 채널 영수증도 갱신했다. Ollama 봇만 재시작했다. 사후 점검은 정상이었다. 같은 질문의 실제 채팅에서는 이전 상황이 재현되지 않아 새 규칙이 발동하지 않았다. 22:51:35에 확정했다. 표식·백업은 `/var/lib/capstone-service-grounding/20261113-query-scope`에 있다. 같은 채팅에서 Hermes의 질문 밖 클러스터 노드 조회 실패(잘못된 `node_type`)와 교차 검토의 범위 밖 조회·과장된 일치가 드러나, 조사형 질문의 첫 조회 도구 범위 제한을 다음 후보로 남겼다. [기록](../infra/validation/query-scope/README.md).

## 2026-11-13 23:11 KST — 조사 첫 조회 도구 범위 + 교차 검토 원칙 스킬 통합 적용 (B, 관리자231 경유)

사용자 승인("조사 도구 범위 적용해줘")에 따라 적용했다. 컨트롤러 잠금 아래 사본 16곳을 교체했다. 대상은 관리 실행기 `bc19115d`→`6b605668` ×4, query-completion `3847d9c8`→`fb935f63` ×2, 하네스 `5d79bb9d`→`dba169a1` ×2, Ollama 런타임 `026a2cf9`→`75a8ffe1`, 공동 채널 작업자 `f4f426c7`→`2c4b46f8`, `workflow_contract.py` `d7884003`→`de984aca` ×3, `skill-soc-investigate.md` `f3306812`→`24fc9e24` ×3이다. 컨트롤러 내장본, Ollama 영수증 6항목, 공동 채널 영수증도 갱신하고 Ollama 봇만 재시작했다. 실제 채팅에서 Hermes 첫 선택과 Ollama 교차 검토가 모두 질문이 지정한 두 경보만 조회했다(오류 0). 23:16:05에 확정했다. 사용자 지시("되도록 스킬로 묶어 관리")를 반영해, 교차 검토 판단 원칙은 공동 채널 작업자 코드에서 `soc-investigate`의 교차 검토 단계 전용 절로 옮겼다. [기록](../infra/validation/investigation-scope/README.md).

## 2026-11-13 23:34 KST — 보고서 정정 진단·0건 숫자 경계·제어 줄 순서 적용 (B, 관리자231 경유)

사용자 승인("보고서 근거 검사 수정 적용해줘")에 따라 적용했다. 컨트롤러 잠금 아래 사본 11곳을 교체했다. 대상은 관리 실행기 `6b605668`→`76bd1e09` ×4, query-completion `fb935f63`→`18a04801` ×2, 하네스 `dba169a1`→`7b427f36` ×2, `skill-soc-investigate.md` `24fc9e24`→`acab349c` ×3이다. 컨트롤러 내장본과 Ollama 영수증 4항목도 갱신하고 Ollama 봇만 재시작했다. 실제 채팅에서 진단 전달과 제어 줄 순서 정정, 교차 검토의 0건 이견 거절이 실제로 동작했다. 다만 모델이 제어 줄을 백틱으로 감싸 보고서는 여전히 대체 문구로 끝났다(다음 후보). 23:40:04에 확정했다. [기록](../infra/validation/report-repair/README.md).

## 2026-11-13 23:47 KST — 제어 줄 서식 진단 보강 적용 (B, 관리자231 경유)

사용자 승인("제어 줄 서식 수정 적용해줘")에 따라 적용했다. 컨트롤러 잠금 아래 사본 9곳을 교체했다. 대상은 관리 실행기 `76bd1e09`→`b32ea4c6` ×4, query-completion `18a04801`→`576736f4` ×2, `skill-soc-investigate.md` `acab349c`→`eeb28a8d` ×3이다. 컨트롤러 내장본과 Ollama 영수증 3항목도 갱신하고 Ollama 봇만 재시작했다. 실제 채팅에서 제어 줄 서식은 해결됐고, 정정 진단과 순서 정정도 동작했다. 남은 실패는 판단 `unresolved`와 상태 `resolved`의 모순으로, 이 규칙을 컨트롤러가 실행 후에만 검사해 생긴다(다음 후보). 23:53:06에 확정했다. [기록](../infra/validation/control-format/README.md).

## 2026-11-14 00:00 KST — 판단·상태 모순 정정 단계 검사·코드 블록 진단 적용 (B, 관리자231 경유)

사용자 승인("판단·상태 모순 수정 적용해줘")에 따라 적용했다. 컨트롤러 잠금 아래 사본 9곳을 교체했다. 대상은 관리 실행기 `b32ea4c6`→`f6556563` ×4, query-completion `576736f4`→`53b54682` ×2, `skill-soc-investigate.md` `eeb28a8d`→`3345bcc9` ×3이다. 컨트롤러 내장본과 Ollama 영수증 3항목도 갱신했고, Ollama 봇만 재시작했다. 사후 점검은 정상이었다. 실제 채팅의 두 초안은 제어 줄 순서와 서식이 맞았고 코드 블록이 없었으며, 판단과 상태도 일관됐다. 그래서 새 검사는 발동하지 않았다(회귀로만 확인). 보고서는 검사기 오탐으로 대체 문구가 됐다. `sensor_rule_ids`의 "ids"를 IDS 언급으로 읽은 것이며, 다음 후보로 넘겼다. 00:07:53에 확정했다. [기록](../infra/validation/disposition-status/README.md).

## 2026-11-14 00:29 KST — history-auto 전송 게시 상한 수정 적용 (B, 관리자231 경유)

사용자 승인("이력 전송 게시 상한 적용해줘")에 따라 B에만 적용했다. 11/13 23:54부터 전송이 매 실행 `finalize`에서 exit 65로 멈췄다. 원인은 게시 목록(262,370바이트)이 고정 256 KiB 상한을 넘은 것이고, 19:31 배치 상한 동기화에서 이 상한이 빠졌다. 00:26:31 타이머 실행이 끝나기를 기다린 뒤 00:29:13에 전송 잠금 아래 `transfer-lib.sh` `52dbb82b`→`0ed5bbe6`, `runtime.sha256` `9a62534a`→`abdd7d67`을 교체했다. 작업자와 A는 바꾸지 않았다. 수동 실행(00:29:13~00:31:36)이 success였고, 397배치 중 신규 1·재사용 396이었다. 게시 목록은 269,848바이트다. 자연 주기(00:46:36~00:49:02)도 이 목록을 받아들여 success였다(400배치·신규 3). [기록](../infra/normalization/vector/history-auto-transfer/README.md).

## 2026-11-14 01:01 KST — 센서 약어 경계 검사기 수정 적용 (B, 관리자231 경유)

사용자 승인("IDS 검사기 수정 적용해줘")에 따라 적용했다. 컨트롤러 잠금 아래 사본 6곳을 교체했다. 대상은 관리 실행기 `f6556563`→`ee848f91` ×4, query-completion `53b54682`→`fab84467` ×2이다. 컨트롤러 내장본과 Ollama 영수증 2항목도 갱신했고, Ollama 봇만 재시작했다. 사후 점검은 정상이었다. 실제 채팅 초안은 필드명을 쓰지 않아 오탐 방지 경로가 발동하지 않았다. 2차 초안은 조회하지 않은 IDS를 실제로 언급해 올바르게 거절됐다. 01:05:57에 확정했다. [기록](../infra/validation/ids-boundary/README.md).

## 2026-11-14 01:19 KST — 표본 0건 주장의 문장 단위 판정·진단 인용 일치 적용 (B, 관리자231 경유)

사용자 승인("0건 검사 수정 적용해줘")에 따라 적용했다. 컨트롤러 잠금 아래 사본 6곳을 교체했다. 대상은 관리 실행기 `ee848f91`→`88896285` ×4, query-completion `fab84467`→`ce1ba937` ×2이다. 컨트롤러 내장본과 Ollama 영수증 2항목도 갱신했고, Ollama 봇만 재시작했다. 사후 점검은 정상이었다. 실제 채팅에서 새 연결형 어미 검사와 문장 단위 인용이 동작했고, 2차 초안이 위반 0으로 통과해 오늘 같은 질문에서 처음으로 Hermes 보고서가 대체 문구 없이 게시됐다. 01:23:27에 확정했다. [기록](../infra/validation/zero-sentences/README.md).

## 2026-11-14 01:35 KST — 교차 검토 조회 한도 이견 수정 적용 (B, 관리자231 경유)

사용자 승인("교차 검토 한도 수정 적용해줘")에 따라 적용했다. 컨트롤러 잠금 아래 공동 채널 작업자 `2c4b46f8`→`923db594` ×1, `skill-soc-investigate.md` `3345bcc9`→`125ed453` ×3을 교체하고, Ollama 영수증 스킬 항목과 공동 채널 영수증 작업자 항목을 갱신했다. Ollama 봇만 재시작했다. 사후 점검에서 운영 작업자 사본으로 한도 도달 건수 이견 거절과 한도 미도달 허용을 확인했다. 실제 채팅의 교차 검토는 건수 이견을 내지 않았지만, 새 규칙은 발동하지 않았다(검토자가 스스로 미확인 선택). Hermes는 두 번 연속 정상 게시됐다. 01:40:04에 확정했다. [기록](../infra/validation/peer-limit/README.md).

