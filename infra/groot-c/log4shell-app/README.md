# Log4Shell Java 실습 웹

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../STATUS.md) · [실행 계획](../../../PLAN.md).
> 현재 콘솔은 HTTP3개(Log4Shell/Apache2종)와 터미널3개(Redis/Samba/sudo), 총6항목이다. sudo는 별도 rootless의 UID1000·전역 단일 세션이며 종료 시 전체 중지한다. DVWA는 독립 유지한다. 환경 준비와 CVE 악용 성공을 구분하고 공격 재현은 보류한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

> **2026-10-22 변경:** 공개 `/log4shell/` 주소는 [오프라인 실습 관리 웹](../offline-labs/README.md)으로 전환했다. 이 Java 앱과 검증된 기존 JAR는 첫 CVE 항목에 포함하며 새 실습은 C의 `127.0.0.1:18081`에 실행하며 같은 HTTPS 사이트의 `/log4shell/labs/CVE-2021-44228/`에서 WAF를 거쳐 접속한다. 키 없이 실습할 수 있고 선택적인 WAF 차단 예외 키·일회용 서명은 관리 웹에서 처리한다. 기존 `log4shell-lab` 컨테이너는 복구용으로 보존했다. 아래 10/19 공개 라우팅·설치 기록과 현재 관리 웹을 구분한다.

Spring Boot가 입력 화면과 API를 직접 제공한다. 브라우저에서 `message` 요청 파라미터 또는 `X-Api-Version` 헤더를 선택해 원문을 `logger.info(raw)`에 전달한다. 기존 PHP 중계 웹을 교체하는 소스이며 공격 페이로드·콜백 서버·명령 실행 기능은 포함하지 않는다.

## 소스와 실행

- `build.gradle`: Spring Boot 2.6.1, Java 8 호환, `log4j-api`·`log4j-core` 2.14.1 명시/강제 고정.
- `src/main/java/.../MainController.java`: 실제 HTTP 헤더 또는 `message`를 수정 없이 기록한다. 서버가 받기 전 URL/form 디코딩과 HTTP 헤더 규격은 적용된다.
- `src/main/java/.../LabCsrf.java`: 브라우저 요청의 CSRF 검사만 담당한다. 로그 문자열을 필터링하거나 로그인·권한을 제공하지 않는다.
- `src/main/resources/static/`: 화면·CSS·JavaScript. 응답 원문은 `textContent`로 표시하고 브라우저 저장소에 보관하지 않는다.
- `src/main/resources/log4j2-spring.xml`: KST 시각·요청 ID·입력 경로·원문을 콘솔에 출력한다.

준비된 개발용 Linux 환경에서 Gradle 7.3.1과 호환 JDK를 사용해 `gradle --no-daemon bootJar`로 빌드한다. Mac에 빌드 도구를 설치하는 절차가 아니다. 결과는 `build/libs/spring-boot-application.jar`다.

```sh
java -jar build/libs/spring-boot-application.jar
```

기본 주소는 `http://127.0.0.1:8080/log4shell/`다. 바인딩과 포트는 `SERVER_ADDRESS`, `SERVER_PORT`로 지정할 수 있다. 의도적으로 취약한 버전을 포함하므로 내부 실습 환경에 한정한다.

## API 계약

- `GET /log4shell/api/status`: 실행 중인 Log4j API/Core·Java 버전, KST 시각, CSRF 토큰을 반환한다.
- `POST /log4shell/api/log`: form의 `source=parameter&message=...` 또는 `source=header&headerName=X-Api-Version`과 실제 헤더 값을 기록한다. 직접 API 호출은 `headerName=User-Agent`도 지원한다. 브라우저 UI는 사용자가 설정 가능한 `X-Api-Version`을 사용한다.
- POST에는 status 응답의 쿠키와 `X-Lab-CSRF-Token` 헤더가 필요하다. HTTP/HTTPS 쿠키명은 분리하며 HttpOnly·SameSite=Strict, HTTPS Secure를 적용한다. 서명 키는 프로세스 메모리에만 있고 재시작 후 토큰을 다시 받아야 한다.
- 응답은 원문·요청 ID·INFO·KST 시각을 담는다. HTTP 성공은 로깅 호출 완료를 뜻하며 패킷 발생·공격 성공·Wazuh 경보를 보증하지 않는다.

입력 문자열은 검사·trim·이스케이프 없이 로깅한다. CSRF와 source/header 선택 검사는 이 문자열 처리와 별개다. 브라우저는 헤더 값의 앞뒤 공백을 정리하거나 줄바꿈·일부 문자를 거부할 수 있으므로, 원문과 줄바꿈 비교에는 message를 사용한다. 악성 예제 문자열은 제공하지 않는다.

## 최초 실습 서버 교체 경로 — 2026-10-19 19:57 당시

현재 주소를 유지하는 구조는 `A WAF → C Apache /log4shell/ → C 내부 Java 앱 /log4shell/`이다. 선택 HTTPS는 기존 A chatproxy를 거친다. `apache-proxy.conf`는 기존 C용 고정 upstream이며 Apache `proxy`·`proxy_http` 모듈을 사용한다. 일반 forward proxy는 열지 않는다.

최초 교체에서는 기존 컨테이너의 이미지·포트·네트워크를 재구성하지 않고 JAR와 명시적인 바인딩 설정만 교체했다. 현재 재생성 방식은 아래 영속 Compose 관리 절을 따른다. `existing-container.properties`는 해당 컨테이너의 `/application.properties`로 사용하는 운영 전용 설정이다. 외부로 새 8080을 공개하는 설정이 아니며 기존 `10.200.10.20:8080` 바인딩을 유지한다.

기존 JAR의 검증된 라이브러리와 Spring loader를 재사용하는 오프라인 도구는 다음과 같다. 기존 서버 JDK로 Java 8 클래스를 컴파일한 뒤 사용한다. 의존성 다운로드·새 패키지 설치가 없고, 원본 파일은 덮어쓰지 않는다.

```sh
python3 -B tools/build_from_existing.py inspect ORIGINAL.jar NEW_DEPENDENCY_DIR
# 기존 서버 JDK 8: -encoding UTF-8 -source 1.8 -target 1.8,
# NEW_DEPENDENCY_DIR/lib/* 를 classpath로 Java 소스를 새 classes 디렉터리에 컴파일
python3 -B tools/build_from_existing.py package ORIGINAL.jar CLASSES_DIR src/main/resources NEW.jar
```

도구는 Boot2.6.1과 Log4j2.14.1 내부 메타데이터, 전체 라이브러리 SHA, loader 보존을 확인한다. 이것은 Gradle 의존성 해석 시험과 별개인 기존 운영 JAR 기반 빌드 경로다. 신규 3서버 설치기는 기본적으로 service 서버의 준비된 이미지 안에 있는 JDK·기존 JAR의 라이브러리를 사용해 소스를 자동 빌드한 뒤 읽기 전용 마운트한다. 준비한 새 JAR을 직접 쓰려면 `LOG4SHELL_APP_JAR`에 service 서버의 `/opt/…jar` 경로를 지정한다. [초기 설치 안내](../../../deployment/configuration-guide.md)의 자동/준비 JAR 모드와 기존 운영 컨테이너 관리 절차를 구분한다.

이전 PHP 소스·운영 디렉터리는 교체 시 복구 백업에 보존하고 활성 웹 경로에서 제거한다. 과거 [PHP 검증 기록](../log4shell-ui/README.md)은 당시 결과로 남긴다. `/log4shell/api.php`는 새 API가 아니다.

별도 A:8080 공격 시나리오 토글은 이번 웹 교체에 포함하지 않는다. 내부 Java 로깅 요청을 A 외부 NIC의 Suricata 관측으로 간주하지 않는다. 실제 공격·콜백·차단 E2E 시험은 별도다.

## 근거

- [기존 취약 앱의 빌드 구성](https://github.com/christophetd/log4shell-vulnerable-app/blob/main/build.gradle)
- [기존 앱의 Java 실행 환경](https://github.com/christophetd/log4shell-vulnerable-app/blob/main/Dockerfile)
- [Apache Log4j 보안 공지](https://logging.apache.org/security.html)

2026-10-19 19:57 KST 기존 서버 교체를 완료했다. [현황](../../../STATUS.md)과 [배포·검증 기록](deployment-validation-20261019.json)을 따른다. 실제 공격·콜백 E2E는 수행하지 않았다.

아래는 최초 교체 당시의 제한과 PHP 복구 경로다. 운영 복구본은 C `/var/backups/capstone-log4shell-java/20261019-replace-php`(root0700), 새 배포 JAR는 `/var/lib/capstone-log4shell-java/spring-boot-application.jar`에 있다. 같은 컨테이너의 쓰기 계층에서 JAR를 교체했으므로 원래 이미지로 컨테이너를 재생성하면 새 앱이 자동 복원되지 않는다. 재생성은 별도 검토하며 보존 JAR·외부 바인딩 설정을 명시적으로 적용해야 한다. 복구 시에는 컨테이너를 정지한 상태에서 이전 JAR와 설정을 복원하고, Apache 새 프록시를 해제한 뒤 백업의 기존 PHP 경로를 복원한다. 일반 운영 중 JAR를 덮어쓰지 않는다.

## 2026-10-19 후속 — 기존 C의 영속 Compose 관리

위 19:57 기록은 최초 교체 당시 상태다. 후속 관리 소스는 [compose.yaml](compose.yaml)·[manage.sh](manage.sh)·[검증기](managed_contract.py)이며, **20:29 KST 기존 C에 적용하고 실제 재생성과 컨테이너 부재 후 기동을 모두 확인했다**. [후속 검증 근거](compose-validation-20261019.json)를 참고한다. 초기 3VM 설치기의 service 역할과 별도로 기존 C만 관리한다.

관리 루트는 `/opt/capstone-log4shell`(root0700), Compose project는 `capstone-log4shell`, service는 `app`, 컨테이너 이름은 `log4shell-lab`이다. JAR를 `artifacts/<SHA-256>.jar`에 보존하고 같은 파일을 읽기 전용 bind mount한다. 로컬 이미지 ID·JAR SHA·명시적인 내부 바인딩 주소와 관리 파일 해시를 root0600 `managed.env`·`manifest.json`에 저장한다. `create_host_path: false`와 사전 파일 검사를 함께 사용하여 누락된 JAR 대신 디렉터리를 만들지 않는다.

기존 기본 `bridge` 네트워크와 `unless-stopped` 재시작 정책을 사용한다. 컨테이너는 UID/GID65532, 읽기 전용 rootfs, capability 제거, `/tmp` tmpfs와 메모리·CPU·PID 제한으로 실행한다. 바인딩 기본값은 loopback이며 설치에는 실제 사설/loopback IPv4를 명시해야 한다. JAR 경로·Java 명령·`/log4shell` context·로그 설정을 Compose에 고정하고 이미지 pull/build는 하지 않는다. Apache·방화벽·A의 시나리오 토글은 이 관리기가 변경하지 않는다.

현재 C는 설치를 완료했으므로 아래 `install`을 다시 실행하지 않고 설치된 관리기의 `up`·`recreate`·`verify`를 사용한다. 최초 전환 복구본은 `/var/backups/capstone-log4shell-java/20261019-compose`에 보존했다. 기존 `log4shell-lab`이 남아 있으면 `install`은 소유 여부와 관계없이 거절한다. 기존 미관리 컨테이너의 보존·중지·이름 변경과 실패 시 복귀는 별도로 검토한 전환 절차에서 처리한다. 관리기가 임의로 가져오거나 삭제하지 않는다. 초기 설치 예시는 **C에서** 실행하며 실제 저장소 위치를 넣는다.

```sh
sudo env \
  LOG4SHELL_APP_JAR=/var/lib/capstone-log4shell-java/spring-boot-application.jar \
  LOG4SHELL_IMAGE=sha256:5f25b56ad55e388a0e20afd98627c91d4dc8d94b464d918fcfb2c1652d2ef14d \
  LOG4SHELL_BIND_ADDRESS=10.200.10.20 \
  LOG4SHELL_SOURCE_ROOT=/path/to/capstone_project \
  bash /path/to/capstone_project/infra/groot-c/log4shell-app/manage.sh install
sudo bash /opt/capstone-log4shell/manage.sh up
```

`LOG4SHELL_SOURCE_ROOT`는 최초 설치에 복사할 `deployment/validate_log4shell_jar.py`·`deployment/verify_log4shell_app.py`가 있는 저장소 루트다. 생략하면 관리 소스의 세 단계 위를 사용한다. 설치 후에는 관리기·Compose·검증기·JAR가 영속 루트에 모두 있으므로 원본 저장소나 최초 JAR 경로가 없어도 다음 명령을 실행할 수 있다.

```sh
sudo bash /opt/capstone-log4shell/manage.sh check
sudo bash /opt/capstone-log4shell/manage.sh status
sudo bash /opt/capstone-log4shell/manage.sh verify
sudo bash /opt/capstone-log4shell/manage.sh recreate
```

`check`는 소유권·파일 모드·해시·로컬 이미지와 존재하는 관리 컨테이너의 ID/project/마운트/포트/권한/env를 검사한다. `status`는 확인된 상태를 보여준다. `up`·`recreate`는 이 검사를 먼저 통과해야 하며, 고정 service만 `--no-deps --no-build --pull never`로 시작한다. `recreate`는 검증된 컨테이너를 새 ID로 만든다. 시작 후 최대 약90초 동안 준비를 확인하고, 실제 마운트 내부 JAR SHA와 런타임 버전·쿠키/CSRF를 거친 고정 무해 POST를 검증한다. 실패하면 실행 흔적을 지우거나 자동 롤백하지 않고 검토 대상으로 남긴다. 준비 확인 중 실패한 무해 요청은 반복될 수 있다.

컨테이너 생성 후 ID 영수증 저장 전에 관리기가 중단되면 일반 `up`은 새 ID를 자동으로 채택하지 않는다. 운영자가 현재 상태를 검토한 뒤 `sudo bash /opt/capstone-log4shell/manage.sh recover`로 명시적으로 복구한다. 이 명령은 파일·이미지·project 소유 목록·전체 컨테이너 계약·마운트 내부 SHA·실제 HTTP 검증을 모두 통과한 경우에만 `runtime.json`의 ID를 다시 기록한다. 설정이 다르거나 미관리 컨테이너이면 거절하며 컨테이너를 지우지 않는다. 영수증은 고유 임시 파일에 기록·fsync한 뒤 원자 교체하므로 이전 쓰기가 중단된 임시 파일 때문에 다음 복구가 막히지 않는다.

`/run/capstone-log4shell`의 root0700 디렉터리와 root0600 lock으로 동시 실행을 막는다. Docker는 `/var/run/docker.sock`에 명시적으로 연결하며 다른 CLI context를 따르지 않는다. 저장된 파일·원래 이미지·컨테이너 ID·라벨 또는 마운트가 달라지면 자동으로 승인하지 않는다. 같은 project의 다른 이름 컨테이너·추가 service·orphan도 실행 전에 거절한다. 이 경로는 현재 승인된 JAR의 재생성용이며 새 앱 버전으로의 업데이트·호스트 재부팅 복구·공격 E2E 검증을 대신하지 않는다.
