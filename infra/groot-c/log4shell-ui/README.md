# Log4Shell 실습 웹 화면

기존 C 서버의 Log4Shell 앱에 정상 요청 또는 필수 헤더가 빠진 요청을 보내고, 실제 HTTP 응답·처리 시간·최근 요청을 브라우저에서 확인한다. 기존 Apache/PHP를 사용하며 새 패키지·컨테이너·상시 Python 서비스는 설치하지 않는다.

## 사용

기존 실습망/VPN의 대표 주소는 **http://log4shell.grootlab.duckdns.org/** 다. DVWA의 `http://dvwa.grootlab.duckdns.org/`와 같은 HTTP80 접근 경로를 사용하며, 루트는 `/log4shell/`로 이동한다. hosts 예비 이름은 `log4shell.groot.lab`이며 해당 이름을 유지한 채 `/log4shell/`로 이동한다. Log4Shell 이름에 잘못 붙은 `/dvwa/login.php` 등 UI 밖의 경로도 `/log4shell/`로 이동한다. 기존 `http://192.168.16.230/log4shell/` 경로도 유지한다. 처음 설치한 13:20 검증은 아래 기록의 IP 주소 기준이며, 이후 이름 기반 접속 검증은 최신 작업 기록과 구분한다.

**2026-10-15 14:33:38 KST 인증서 후속:** `*.grootlab.duckdns.org` 공용 Let's Encrypt 인증서를 A `chatproxy`에 적용했다(만료 **2027-01-13 13:25:12 KST**). `https://log4shell.grootlab.duckdns.org/`는 선택 경로이며 Mac의 시스템 CA 검증에서 잘못된 `/dvwa/login.php` 요청이 같은 HTTPS 이름의 `/log4shell/`로 이동해 최종 200을 반환했다. 이 화면의 기본 안내와 실습 검증은 위 HTTP 주소를 유지한다. 와일드카드는 `chat.grootlab.duckdns.org`와 Log4Shell 이름에 유효하지만 `log4shell.groot.lab` 같은 내부 별칭에는 유효하지 않다. 채팅 인증서 일일 감시는 공유 파일의 만료를 읽으나 Log4Shell SNI·경로를 정기 검사하지 않아 배포·갱신 때 별도로 확인한다.

1. 화면의 API 연결 준비가 끝나면 `X-Api-Version` 값을 입력한다. 기본값 `1.0`을 그대로 사용해도 된다.
2. 정상 요청을 보내면 기존 앱의 `HTTP 200`과 `Hello, world!` 응답을 확인할 수 있다.
3. 헤더 누락 요청을 보내면 필수 헤더가 없어 앱이 `HTTP 400`을 반환한다. 화면의 전송 API 오류와 실습 앱의 400 응답은 구분해 표시한다.
4. 최근 요청은 이 브라우저의 저장소에 최대 20회 남는다. 내역 지우기는 이 화면의 브라우저 기록만 지우며 Apache·Log4j·보안장비 로그를 삭제하지 않는다.

최근 내역은 서버 전체 접속 로그나 Wazuh 경보 목록이 아니다. 최초 로딩의 ‘준비’는 UI API 연결 상태이고, 실제 랩 앱의 응답 상태는 요청을 보낸 뒤에 확인한다. 시각은 KST로 표시한다.

## 경로와 실습 범위

```text
http://log4shell.grootlab.duckdns.org/ → A:80 WAF
    → C:80 Apache (이름 일치 시 /log4shell/로 이동)
                         └ PHP → C 10.200.10.20:8080 Log4Shell 앱
https://log4shell.grootlab.duckdns.org/ → A:443 chatproxy (선택)
    → A WAF → C:80 Apache → 같은 /log4shell/ 화면
```

이 화면은 헤더와 응답을 관찰하는 기본 실습이다. 헤더 값은 영문·숫자·공백·점·밑줄·하이픈 1~64자로 제한한다. 임의 URL·헤더 이름·JNDI 문자열·셸 명령·Docker 명령을 전달하는 기능은 없다.

기존 **A:8080 → C:8080 시나리오 토글**과 별도의 경로다. 토글이나 nftables, WAF 엔진 모드, Suricata 모드를 바꾸지 않는다. A의 WAF는 UI의 요청을 보지만 C 내부의 PHP→Log4Shell 호출 자체는 A 외부 NIC의 Suricata를 지나지 않는다. HTTP 200 또는 400을 확인한 것만으로 Log4Shell 취약점 재현이나 보안 탐지 성공이 입증되는 것은 아니다. 실제 공격 시나리오는 [기존 실습 문서](../../../scenarios/scenario-2-log4shell.md)의 범위와 선행조건을 따른다.

선택 HTTPS는 A:443에서 TLS를 종료하므로 A 외부 NIC의 Suricata가 들어오는 HTTP 본문을 평문으로 관측하는 공격 경로로 사용하지 않는다. 인증서 신뢰 여부와 Log4Shell 공격·탐지 성공은 별개다.

## 구현과 제한

| 파일 | 역할 |
|---|---|
| `public/index.html`, `app.css`, `app.js` | 외부 CDN 없는 화면·브라우저 기록·응답 표시 |
| `public/api.php` | 세션/CSRF 검사, 입력 검증, 고정 목적지에 GET 요청 |
| `install.sh` | C의 기존 Apache/PHP 검사, 신규 경로 배포, 실패 시 웹 경로 회수 |
| `log4shell-vhost.conf` | 현재 C의 HTTP 이름 기반 가상호스트. DVWA 기본 가상호스트를 유지하고 Log4Shell 이름만 선택 |
| `verify.py` | Python 표준 라이브러리로 실제 HTTP 계약 검사. 운영 서비스가 아닌 검증 도구 |

응답 본문은 HTML로 실행하지 않고 텍스트로 표시한다. CSRF 토큰과 세션 쿠키는 브라우저 최근 기록에 저장하지 않는다. API는 본문 2 KiB, 랩 응답 8 KiB, 연결 1.5초·전체 4초로 제한한다. 목적지는 코드의 고정 주소이며 프록시 환경변수나 HTTP 리다이렉트를 따르지 않는다. 세션별/전체 요청 사이를 최소 1초로 제한하고 전체 동시 요청은 하나로 제한한다.

PHP의 세션은 기존 시스템 세션 저장소를 사용한다. 전역 요청 제어 파일은 `/var/lib/capstone-log4shell-ui/request.lock`이다. 웹 파일은 root 소유·0644이고 웹 프로세스가 소스를 수정할 수 없게 둔다. 이 화면은 관리자 인증·권한 관리 시스템을 제공하지 않으며 기존 실습망 웹 접근 범위에서 무해한 두 종류의 요청만 중계한다.

**2026-10-15 HTTP 세션 오류 수정:** HTTPS 방문 뒤 HTTP에서 `연결 재확인 필요`와 API403이 반복되는 현상을 같은 Safari에서 재현했다. 같은 이름의 Secure 쿠키 때문에 HTTP 세션 쿠키를 저장하지 못하는 문제여서 HTTP는 `groot_log4shell_ui_http`, HTTPS는 `__Secure-groot_log4shell_ui_https`로 분리했다. 기존 쿠키를 삭제하지 않아도 새로고침하면 새 세션을 사용한다. 양쪽의 HttpOnly·SameSite=Strict·CSRF 검사와 HTTPS의 Secure를 유지한다.

HTTPS 프록시는 Log4Shell 경로에 `X-Groot-Lab-TLS: 1`을 고정 전달한다. WAF가 `X-Forwarded-Proto`를 내부 연결의 HTTP로 바꾸므로 별도 힌트를 사용한다. 이 힌트는 **더 엄격한 Secure 쿠키 선택에만** 사용하며 인증·접근 권한·신뢰 출발지 판정에 사용하지 않는다. 외부 HTTP에서 이 값을 위조해도 Secure 접두사/속성을 가진 쿠키만 요청할 수 있고 CSRF 검사는 생략되지 않는다. 일반 HTTP에서 Secure 쿠키를 저장하지 못하는 브라우저 규칙은 [Set-Cookie 문서](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie)에 따른다. 새 HTTPS 프록시를 구성할 때는 이 고정 헤더와 새 HTTPS 쿠키명도 함께 반영한다.

15:46 C PHP 교체·A Nginx reload 후 C의 API9검사와 초기 설치기30검사가 통과했다. 기존 쿠키가 남은 Safari의 HTTP 정상200/헤더 누락400, HTTPS 정상200, HTTPS 사용 후 기존 HTTP 탭의 정상200을 확인했다. 같은 쿠키 저장소로 HTTPS→HTTP→HTTPS→HTTP를 검사해 정상200·누락400·잘못된 CSRF403을 확인했다. 외부 WAF가403의 Content-Type을 text/html로 바꾸는 기존 한계는 별개로 남아 있으며 엄격한 외부9검사 전체 통과로 표현하지 않는다. [검증 기록](session-validation-20261015.json)을 참고한다.

## C 서버에 적용

다음 `install.sh`는 이미 Apache·PHP 8.1 이상과 curl/session 확장·Python3·Log4Shell 앱을 갖춘 현재 C 환경의 **최초 추가 설치용**이다. 신규 환경에서는 루트 [`deploy.sh`](../../../deploy.sh)의 service 역할이 격리된 Log4Shell 앱과 이 UI를 함께 구성하므로 이 보조 설치기를 따로 실행하지 않는다. 신규 환경의 API 목적지는 Docker 내부 `http://log4shell:8080/`으로 생성되며, 기본 접속 주소는 `http://SECURITY_HOST:WAF_PORT/log4shell/`이다. 선택 설정 `LOG4SHELL_HOSTNAME`을 입력하면 자신의 DNS 이름과 WAF 포트로도 접속한다. 운영 DuckDNS 이름은 신규 환경에 복제하지 않는다. [수동 패키지·이미지 준비](../../../deployment/setup-packages-artifacts.md)와 [설정 안내](../../../deployment/configuration-guide.md)를 먼저 따른다.

신규 범용 `deploy.sh`의 호스트명 설정은 **HTTP 이름 경로까지만** 구성한다. 공개 CA 인증서 발급, TLS 개인키 배포, A:443 `chatproxy` 설정과 HTTPS 검증은 기존 운영망에 맞춘 **별도 수동 작업**이며 범용 설치 완료에 포함되지 않는다.

프로젝트의 이 디렉터리 전체를 C의 운영 소스 경로에 반입한 뒤 **C에서** 실행한다. Mac에 패키지를 설치할 필요가 없다.

```bash
sudo bash /home/groot_c/capstone/log4shell-ui/install.sh
```

설치기는 `/var/www/html/log4shell` 또는 기존 Log4Shell 가상호스트가 있으면 덮어쓰지 않고 중단한다. PHP lint·Apache configtest·기존 DVWA/Log4Shell 응답을 확인한 뒤 네 파일과 `sites-available/log4shell.conf`를 배포한다. 기본 DVWA 설정을 유지하고 추가 가상호스트를 enable한 뒤 Apache를 한 번 reload한다. 대표·hosts 별칭의 루트·슬래시 없는 경로·잘못된 DVWA 경로302, 화면200과 실제 HTTP 검증에 실패하면 이번 가상호스트를 회수하고 기존 Apache 구성을 reload하며, 추가 웹 디렉터리도 백업 경로로 옮긴다. 컨테이너·패키지·방화벽은 변경하지 않는다.

이미 배포된 현재 C에는 이 최초 설치기를 다시 실행하지 않는다. 기존 공개 파일과 Apache 설정을 보존·대조한 별도 변경 절차로 가상호스트만 추가한다. `000-default.conf`가 첫 기본 가상호스트로 남아야 IP·DVWA 이름의 루트 동작이 유지된다. 이름은 A 주소를 가리키도록 DNS 또는 클라이언트 hosts에 사전 준비한다.

배포 영수증·소스 해시는 `/var/backups/capstone-log4shell-ui/<시각>/`에 보존한다. 추가 확인은 C에서 다음과 같이 수행한다.

```bash
python3 -B /home/groot_c/capstone/log4shell-ui/verify.py http://127.0.0.1/log4shell/
curl --fail --silent --show-error -o /dev/null http://127.0.0.1/dvwa/login.php
```

검증 도구는 정상·헤더 누락 요청과 입력/CSRF/메서드/연속 요청 제한을 확인한다. 셸 실행·JNDI 공격·콜백 서버를 사용하지 않으며 토큰·쿠키·응답 본문을 출력하지 않는다.

## 회수

화면을 닫으려면 C에서 `/var/www/html/log4shell` 디렉터리를 이번 배포 백업 폴더의 `disabled-public` 등 새로운 이름으로 옮긴다. 이름 기반 설정도 회수할 때는 이번 `sites-enabled/log4shell.conf`만 해제하고 configtest 후 Apache를 reload한다. 기본 DVWA 설정은 유지하며 기존 파일과 겹치는 경로에 덮어쓰지 않는다. 기존 Log4Shell 컨테이너와 DVWA는 계속 동작한다. 요청 제어 파일·원본 소스·검증 영수증은 보존한다.

## 확인 근거

- 2026-10-15 12:59 KST 직접 확인: C Apache/Docker/Wazuh active, PHP 8.3.6과 curl/session 확장, `log4shell-lab`의 내부 8080 바인딩, 정상 헤더 요청의 200 응답, DVWA 로그인 200.
- 13:01 KST A 직접 확인: WAF healthy·기존 C:80 프록시·DVWA 200, `capstone_scenario` 테이블 없음. 이후 기존 C에 UI를 배포했으며 기존 공격 시나리오 토글은 변경하지 않았다.
- 13:10 KST C 직접 배포: PHP lint·Apache configtest·실제 HTTP 9개·공개 파일 SHA 검사 통과, 정상200/헤더누락400·기존 DVWA200. [배포 검증 기록](deployment-validation-20261015.json)에 후속 확인을 보존한다. 신규 VM3대 실제 구축과 공격·탐지 E2E는 별도 미실행이다.
- 14:33:38 KST A 직접 적용: 채팅과 Log4Shell DuckDNS 이름이 동일 `chatduck.crt/key` 와일드카드 인증서를 사용하도록 설정하고 Nginx를 한 번 재로드했다. Mac 시스템 CA 검증으로 채팅 ping200, Log4Shell HTTPS의 `/dvwa/login.php`→`/log4shell/` 최종200을 확인했다. 기존 HTTP 대표 주소와 A/C의 공격 시나리오 토글은 유지한다. 채팅 인증서 감시기의 수동 실행은 exit0이지만 Log4Shell SNI는 정기 검사 대상이 아니다.
- [기본 앱 컨트롤러](https://github.com/christophetd/log4shell-vulnerable-app/blob/main/src/main/java/fr/christophetd/log4shell/vulnerableapp/MainController.java)
- [PHP 세션 쿠키 설정](https://www.php.net/manual/en/function.session-set-cookie-params.php), [PHP cURL 설정](https://www.php.net/manual/en/function.curl-setopt.php)
