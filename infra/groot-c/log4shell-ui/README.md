# Log4Shell 실습 웹 화면

기존 C 서버의 Log4Shell 앱에 정상 요청 또는 필수 헤더가 빠진 요청을 보내고, 실제 HTTP 응답·처리 시간·최근 요청을 브라우저에서 확인한다. 기존 Apache/PHP를 사용하며 새 패키지·컨테이너·상시 Python 서비스는 설치하지 않는다.

## 사용

기존 실습망/VPN에서 **http://192.168.16.230/log4shell/** 로 접속한다. `dvwa.groot.lab` 이름 해석이 구성된 환경에서는 `http://dvwa.groot.lab/log4shell/`도 같은 경로다. 2026-10-15 기존 C에 적용했으며 실제 검증 범위는 아래 배포 기록을 따른다.

1. 화면의 API 연결 준비가 끝나면 `X-Api-Version` 값을 입력한다. 기본값 `1.0`을 그대로 사용해도 된다.
2. 정상 요청을 보내면 기존 앱의 `HTTP 200`과 `Hello, world!` 응답을 확인할 수 있다.
3. 헤더 누락 요청을 보내면 필수 헤더가 없어 앱이 `HTTP 400`을 반환한다. 화면의 전송 API 오류와 실습 앱의 400 응답은 구분해 표시한다.
4. 최근 요청은 이 브라우저의 저장소에 최대 20회 남는다. 내역 지우기는 이 화면의 브라우저 기록만 지우며 Apache·Log4j·보안장비 로그를 삭제하지 않는다.

최근 내역은 서버 전체 접속 로그나 Wazuh 경보 목록이 아니다. 최초 로딩의 ‘준비’는 UI API 연결 상태이고, 실제 랩 앱의 응답 상태는 요청을 보낸 뒤에 확인한다. 시각은 KST로 표시한다.

## 경로와 실습 범위

```text
브라우저 → A:80 WAF → C:80 Apache /log4shell/
                         └ PHP → C 10.200.10.20:8080 Log4Shell 앱
```

이 화면은 헤더와 응답을 관찰하는 기본 실습이다. 헤더 값은 영문·숫자·공백·점·밑줄·하이픈 1~64자로 제한한다. 임의 URL·헤더 이름·JNDI 문자열·셸 명령·Docker 명령을 전달하는 기능은 없다.

기존 **A:8080 → C:8080 시나리오 토글**과 별도의 경로다. 토글이나 nftables, WAF 엔진 모드, Suricata 모드를 바꾸지 않는다. A의 WAF는 UI의 요청을 보지만 C 내부의 PHP→Log4Shell 호출 자체는 A 외부 NIC의 Suricata를 지나지 않는다. HTTP 200 또는 400을 확인한 것만으로 Log4Shell 취약점 재현이나 보안 탐지 성공이 입증되는 것은 아니다. 실제 공격 시나리오는 [기존 실습 문서](../../../scenarios/scenario-2-log4shell.md)의 범위와 선행조건을 따른다.

## 구현과 제한

| 파일 | 역할 |
|---|---|
| `public/index.html`, `app.css`, `app.js` | 외부 CDN 없는 화면·브라우저 기록·응답 표시 |
| `public/api.php` | 세션/CSRF 검사, 입력 검증, 고정 목적지에 GET 요청 |
| `install.sh` | C의 기존 Apache/PHP 검사, 신규 경로 배포, 실패 시 웹 경로 회수 |
| `verify.py` | Python 표준 라이브러리로 실제 HTTP 계약 검사. 운영 서비스가 아닌 검증 도구 |

응답 본문은 HTML로 실행하지 않고 텍스트로 표시한다. CSRF 토큰과 세션 쿠키는 브라우저 최근 기록에 저장하지 않는다. API는 본문 2 KiB, 랩 응답 8 KiB, 연결 1.5초·전체 4초로 제한한다. 목적지는 코드의 고정 주소이며 프록시 환경변수나 HTTP 리다이렉트를 따르지 않는다. 세션별/전체 요청 사이를 최소 1초로 제한하고 전체 동시 요청은 하나로 제한한다.

PHP의 세션은 기존 시스템 세션 저장소를 사용한다. 전역 요청 제어 파일은 `/var/lib/capstone-log4shell-ui/request.lock`이다. 웹 파일은 root 소유·0644이고 웹 프로세스가 소스를 수정할 수 없게 둔다. 이 화면은 관리자 인증·권한 관리 시스템을 제공하지 않으며 기존 실습망 웹 접근 범위에서 무해한 두 종류의 요청만 중계한다.

## C 서버에 적용

다음 `install.sh`는 이미 Apache·PHP 8.1 이상과 curl/session 확장·Python3·Log4Shell 앱을 갖춘 현재 C 환경용 추가 구성이다. 신규 환경에서는 루트 [`deploy.sh`](../../../deploy.sh)의 service 역할이 격리된 Log4Shell 앱과 이 UI를 함께 구성하므로 이 보조 설치기를 따로 실행하지 않는다. 신규 환경의 API 목적지는 Docker 내부 `http://log4shell:8080/`으로 생성되며, 접속 주소는 `http://SECURITY_HOST:WAF_PORT/log4shell/`이다. [수동 패키지·이미지 준비](../../../deployment/setup-packages-artifacts.md)와 [설정 안내](../../../deployment/configuration-guide.md)를 먼저 따른다.

프로젝트의 이 디렉터리 전체를 C의 운영 소스 경로에 반입한 뒤 **C에서** 실행한다. Mac에 패키지를 설치할 필요가 없다.

```bash
sudo bash /home/groot_c/capstone/log4shell-ui/install.sh
```

설치기는 `/var/www/html/log4shell`이 이미 있으면 덮어쓰지 않고 중단한다. PHP lint·Apache configtest·기존 DVWA/Log4Shell 응답을 확인한 뒤 네 파일을 배포한다. 실제 HTTP 검증이 실패하면 추가한 웹 디렉터리를 백업 경로로 옮겨 회수한다. 기존 Apache 설정·DVWA 파일·컨테이너를 바꾸거나 재시작하지 않는다.

배포 영수증·소스 해시는 `/var/backups/capstone-log4shell-ui/<시각>/`에 보존한다. 추가 확인은 C에서 다음과 같이 수행한다.

```bash
python3 -B /home/groot_c/capstone/log4shell-ui/verify.py http://127.0.0.1/log4shell/
curl --fail --silent --show-error -o /dev/null http://127.0.0.1/dvwa/login.php
```

검증 도구는 정상·헤더 누락 요청과 입력/CSRF/메서드/연속 요청 제한을 확인한다. 셸 실행·JNDI 공격·콜백 서버를 사용하지 않으며 토큰·쿠키·응답 본문을 출력하지 않는다.

## 회수

화면을 닫으려면 C에서 `/var/www/html/log4shell` 디렉터리를 이번 배포 백업 폴더의 `disabled-public` 등 새로운 이름으로 옮긴다. 기존 파일과 겹치는 경로에 덮어쓰지 않는다. Apache 재시작은 필요 없다. 기존 Log4Shell 컨테이너와 DVWA는 계속 동작한다. 요청 제어 파일·원본 소스·검증 영수증은 보존한다.

## 확인 근거

- 2026-10-15 12:59 KST 직접 확인: C Apache/Docker/Wazuh active, PHP 8.3.6과 curl/session 확장, `log4shell-lab`의 내부 8080 바인딩, 정상 헤더 요청의 200 응답, DVWA 로그인 200.
- 13:01 KST A 직접 확인: WAF healthy·기존 C:80 프록시·DVWA 200, `capstone_scenario` 테이블 없음. 이후 기존 C에 UI를 배포했으며 기존 공격 시나리오 토글은 변경하지 않았다.
- 13:10 KST C 직접 배포: PHP lint·Apache configtest·실제 HTTP 9개·공개 파일 SHA 검사 통과, 정상200/헤더누락400·기존 DVWA200. [배포 검증 기록](deployment-validation-20261015.json)에 후속 확인을 보존한다. 신규 VM3대 실제 구축과 공격·탐지 E2E는 별도 미실행이다.
- [기본 앱 컨트롤러](https://github.com/christophetd/log4shell-vulnerable-app/blob/main/src/main/java/fr/christophetd/log4shell/vulnerableapp/MainController.java)
- [PHP 세션 쿠키 설정](https://www.php.net/manual/en/function.session-set-cookie-params.php), [PHP cURL 설정](https://www.php.net/manual/en/function.curl-setopt.php)
