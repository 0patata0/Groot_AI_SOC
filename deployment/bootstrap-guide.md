# 단일 Bash 초기 설치

새 Ubuntu 24.04 amd64 서버 3대의 진입점은 저장소 루트의 `deploy.sh` 하나다. 서버 주소, SSH 접근, 관리자 승인된 오프라인 반입 파일을 준비한 후 다음 한 번으로 패키지·이미지 준비와 역할 설치·검증을 실행한다.

```bash
bash deploy.sh --apply --batch --config deployment/site.local.conf
```

`deployment/config.example.conf`를 로컬 전용 `site.local.conf`에 복사하고 실제 주소·HTTPS 이름·허용 내부망을 입력한다. 비밀번호를 이 파일에 넣지 않는다. 전체 저장소가 필요하며 `deploy.sh`만 따로 복사해서 실행하는 방식은 아니다. 내부 Python/Bash helper는 진입점이 자동으로 호출한다. Mac에는 패키지를 설치하지 않는다.

## 실행 순서와 범위

1. 입력과 검증된 SSH host key를 확인하고 서버 3대의 machine-id가 서로 다른지 확인한다.
2. 각 서버의 `/opt/capstone-prereqs/artifacts.json`과 모든 파일 해시를 검사한다. 하나라도 다르면 패키지 설치 전에 중단한다.
3. 승인된 로컬 `.deb`를 `apt-get --no-download --no-remove`로 설치하고 Docker save archive를 `docker load`한다. 지정하지 않은 추가 패키지, 다운그레이드, 기존 이미지 태그 충돌을 거절한다. SIEM의 `vm.max_map_count`가 부족한 경우 전용 설정 파일로 최소262144를 적용한다.
4. 준비된 상태에서 security·siem·service 역할을 모두 사전검사한다. 역할 충돌, 포트 충돌, 자료 누락이 있으면 서비스 설치 전에 중단한다. 이 단계의 실패 시 앞 단계에서 설치한 패키지는 유지한다.
5. SIEM을 설치·검증하고 등록 CA·암호를 두 agent 서버로 전달한다. Wazuh Dashboard의 `admin` 암호(`siem.json`의 `indexer_password`)는 SSH 파이프로 service의 root0600 파일에 직접 전달한다. Mac 파일·명령 인수·로그에는 저장하지 않는다.
6. service에 독립 DVWA/MariaDB, FastAPI 콘솔·제한된 Docker broker·nft guard, 전용 Nginx gateway, 별도 sudo rootless 환경, Wazuh agent를 구성한다.
7. security에 Suricata·기존 DVWA WAF와 별도 Log4Shell TLS 진입점을 구성한다. 관리·예외 키 인증은 콘솔에 직접 연결하고, 고정된3개 실습 경로만 WAF를 지난다. 일반 요청은 규칙에 걸릴 때 차단하며 유효한 예외 세션은 감사 로그를 유지한다.
8. 설치 결과와 파일·이미지·컨테이너·서비스 상태를 검증한다. 임시 전송 폴더를 정리한다. 실패 시 부분 설치 상태와 서버의 복구 자료를 남기고 임의 덮어쓰기·전체 삭제·자동 재시도를 하지 않는다.

웹 실습3개는 로컬 이미지가 준비된 상태로 등록하고 사용자가 콘솔에서 실행한다. sudo는 웹에서 실행할 수 없으며 관리자 전용 CLI와 상태 발행기를 사용한다. DVWA는 `http://SECURITY_HOST:WAF_PORT/dvwa/`, 콘솔·Java·Apache 두 버전은 `LAB_PUBLIC_ORIGIN/log4shell/` 아래다. DVWA를 Log4Shell 메뉴에 다시 추가하지 않는다.

`--plan`은 로컬 입력만 확인한다. `--check`는 반입물과 역할 조건을 검사하되 패키지·이미지·서비스를 설치하지 않으므로, 아직 패키지가 없는 빈 서버에서는 누락을 보고할 수 있다. `--verify`는 이미 관리 중인 동일 구성의 검증만 수행한다. 기존 운영 GROOT 서버를 신규 설치 대상으로 인수하지 않는다.

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
| service | Wazuh agent4.14.8, Docker29.8.1/CLI, uidmap·libsubid4·dbus-user-session·AppArmor·nftables·gpgv; DVWA/MariaDB/WAF 이미지; 아래4항목 카탈로그와3개 관리형 이미지; 전체 lock wheel 디렉터리; 고정 sudo bundle |
| security | Wazuh agent4.14.8, Suricata/WAF 이미지, 검증한 ET Open 룰, 지정 DNS 이름의 TLS 인증서·개인키, 접속 허용 내부망/VPN CIDR |

콘솔 wheel은 [prepare-python.sh](../infra/groot-c/offline-labs/scripts/prepare-python.sh)의 Ubuntu/Python3.12 amd64용 전체 목록과 해시를 사용한다. 카탈로그는 [cve_list.json](../infra/groot-c/offline-labs/cve_list.json), 웹이미지 반출입은 [offline-labs README](../infra/groot-c/offline-labs/README.md)를 따른다. sudo는 [고정 rootless bootstrap](../infra/groot-c/offline-labs/nonweb/sudo/runtime/BOOTSTRAP.md)의 별도 서명 증빙까지 필요하다. sudo의 준비 JSON만 보고 서명 검증을 생략하지 않는다.

`LOG4SHELL_IMAGE`, `LOG4SHELL_APP_JAR`, `LOG4SHELL_HOSTNAME`의 구형 직접 Java Compose 옵션은 schema7에서 거절한다. 현재 콘솔은 검증·반입된 이미지 ID로 실행한다. 기존 JAR 빌드 도구는 이미지 준비 용도로 보존한다. 구형 schema6을 새로운 구성으로 조용히 덮어쓰지 않는다.

## 검증과 운영 변경 원칙

셸 구문·컨트롤러 가상 SSH 순서·입력/반입물 위변조·역할 생성물·초기 설치 실패/재실행·고정 권한 계약을 자동 시험한다. 기존 운영 서버의 웹·HMAC·WAF canary·sudo 환경 검증과 **새 VM3대 전체 설치 검증**은 별개다. 새 설치 경로의 실제 VM 전체 적용은 아직 실행하지 않았다. 신규 VM에서 `--apply`와 허용 클라이언트 HTTPS 접속까지 통과한 이후에만 실제 설치 검증 완료로 기록한다.

이 초기 설치기는 현재 저장소의 역할별 지원 범위를 따른다. 운영망 NAT/VPN/DNS 자체를 구축하거나, 기존 SOC의 모든 수동 이력을 자동 이관하거나, LLM에 일반 sudo/Docker·패키지 설치 권한을 부여하지 않는다. Suricata 수집은 기존 역할의 수동 탐지 모드이며 관리자의 승인 브로커·자동 차단 체계는 해당 구성의 별도 지원 범위를 확인한다.

앞으로 서버 변경을 수행하면 같은 작업에서 `deploy.sh`의 역할/helper·반입 목록·설정 예제·검증을 갱신한다. 운영 서버 재설정과 신규 설치는 구분한다. 상시 서버 감시나 소스 자동 작성 데몬은 추가하지 않는다.
