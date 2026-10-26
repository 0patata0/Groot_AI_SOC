# GROOT Lab Console

## 웹 접근 정책 변경 — 2026-10-26

사용자가 DVWA·Log4Shell 웹을 모든 출발지에 허용하도록 결정했다. A의 Log4Shell 서버 블록에서 기존 IP 허용 목록을 `allow all`로 바꾸고 같은 컨테이너를 reload했다. `211.170.162.107`의 기존 접근 거부를 확인했으며 상위망 라우팅·방화벽 도달성과 사이트 자체 허용은 별개다. 도메인은 여전히 사설 A 주소로 해석된다. 세부 운영 응답·새 출발지 재시험 결과는 [STATUS](../../../STATUS.md)에 기록한다.

콘솔의 기존 목록·시작/중지·터미널 기능도 같은 웹 접근 정책을 따른다. WAF 예외 키·10분 세션·프록시 신뢰 경계와 실습 격리는 그대로이며, Wazuh·SSH·MCP 공개를 뜻하지 않는다. 초기 설치는 `LAB_ALLOWED_CIDRS=all`로 명시하며 CIDR 목록을 입력하면 기존 제한을 적용한다. 추가 반입 패키지·이미지는 없다. 아래 접근 제한 설명은 당시 이력이다.

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../STATUS.md) · [실행 계획](../../../PLAN.md).
> 현재 콘솔은 HTTP3개(Log4Shell/Apache2종)와 터미널3개(Redis/Samba/sudo), 총6항목이다. sudo는 별도 rootless의 UID1000·전역 단일 세션이며 종료 시 전체 중지한다. DVWA는 독립 유지한다. 환경 준비와 CVE 악용 성공을 구분하고 공격 재현은 보류한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

## 파비콘 재발 후속 완료 (2026-10-23)

메인과 터미널은 로컬 `lab-console-icon.ico`를 정적으로 선언하고 공통 테마는 올바른 아이콘을 그대로 유지한다. 루트 favicon·Apple 아이콘 경로도 이미지로 연결한다. 실제 HTTPS MIME·SHA 및 Safari 아이콘 캐시 백업·재생성 후 같은 주소의 서버 선화 표시와 사용자 확인을 완료했다. 설치기 반입·검증 목록을 함께 갱신했다. [최종 아이콘 증거](favicon-validation-20261023.json).

## sudo 웹 터미널 연결 — 운영 반영·HTTPS 검증 완료 (2026-10-23)

sudo CVE-2021-3156은 기존에 `local-cli`의 준비 상태만 표시해 웹 시작·열기가 비활성화돼 있었다. 새 소스는 이를 `managed-terminal`로 연결하며 **HTTP3개 + 웹 터미널3개, 총6항목**을 사용한다. sudo도 **실습 환경 시작 → 환경 열기**로 `/log4shell/terminal/CVE-2021-3156/`에 접속한다. 별도 rootless 저장소의 준비 이미지도 확인해 모든 입력이 준비됐으면 이미지 수는6개다. C 운영 적용과 실제 HTTPS 접속·입출력·종료 검증을 완료했다.

기존 sudo 이미지·반입 bundle·고정 런타임은 그대로 유지하고 중앙 `sudo_terminal.py` adapter를 통해 연결한다. 호스트 UID1991의 전용 rootless 계정과 컨테이너 UID1000을 사용하며 호스트 sudo·일반 Docker 옵션·임의 host shell을 받지 않는다. 기존 user namespace 안의 setuid 실습 조건을 유지하므로 HTTP/Redis/Samba의 no-new-privileges 계약을 그대로 복사하지 않는다. [중앙 관리 계약](../nonweb-labs/README.md)이 현재 웹 연결 정책이며 `nonweb/sudo/README.md`의 웹 미제공 설명은 원래 CLI 런타임 구축 당시 이력이다. 그 CLI 소스와 pin은 이번에 바꾸지 않는다.

sudo 터미널은 서버 전체1개만 연결한다. **연결 종료·입력 유휴5분·전체30분·터미널 서비스 종료는 sudo 컨테이너 전체 중지**로 처리하고, 재연결은 환경을 자동 시작하지 않는다. 브라우저 탭 종료의 keepalive 전달은 보장되지 않으므로 서버의 시간 제한 정리를 함께 사용한다. 종료 결과를 확인하지 못하면 UI는 중지 완료라고 표시하지 않는다. Redis/Samba의 세션 종료는 환경을 유지하며, 전체 정리는 콘솔 중지로 수행하는 기존 정책을 유지한다.

단일 `deploy.sh`는 service schema9로 이 경로를 반입·검증하도록 연결했다. 아래 schema8·터미널2종의 운영 완료와 [기존 통합 JSON](../nonweb-labs/validation-20261023.json)은 당시 이력이며 sudo 웹터미널 검증을 대신하지 않는다. 실제 취약점 악용/방어 E2E와 새 VM3대 전체 설치 시험은 별도다.


검증은 native 콘솔97개·nonweb121개, 설치기 service50개·controller35개와 Node2종이다. 실제 HTTPS에서 sudo UID1000·패키지1.8.31-1ubuntu1·터미널 크기 변경·Ctrl+C·단일 연결·연결 종료 시 전체 중지·활성 세션 중지·새 CID 재시작을 확인했다. 기존 rootful 컨테이너는 적용 전후 동일했다. 새로고침한 Safari에서 이미지6개·sudo 항목과 시작 버튼은 확인했고, 사용자 브라우저 조작과 겹쳐 sudo 터미널 명령의 시각 검수는 별도로 완료 처리하지 않았다. [sudo 운영 증거](../nonweb-labs/sudo-web-validation-20261023.json).

## Redis·Samba 웹 터미널 확장 — sudo 웹 연결 전 완료 이력 (2026-10-23)

현재 운영 `cve_list.json`은 **6항목**이다. 기존 HTTP3개와 sudo CLI에 Redis **CVE-2022-0543**(Ubuntu `5:5.0.7-2`), Samba **CVE-2017-7494**(4.6.3)의 `managed-terminal` 유형을 추가했다. 두 항목은 같은 HTTPS 콘솔에서 **실습환경 시작 → 환경 열기**를 선택해 `/log4shell/terminal/<CVE ID>/`의 가상 터미널에 접속하도록 구현했다. sudo의 웹 실행·셸은 제공하지 않으며 DVWA는 원래 독립 주소를 유지한다.

FastAPI는 peer credential을 확인하는 전용 Unix daemon을 거쳐, root 런타임이 검증한 full 컨테이너 ID의 고정 UID/GID10001:10001 세션을 연다. 임의 호스트 명령·이미지·mount·Docker 옵션은 받지 않는다. Redis/Samba 서비스는 컨테이너 loopback에서만 제공하고 host port를 게시하지 않는다. 따라서 HTTP 실습3개의 WAF 검사·예외 모드와 터미널 안의 Redis/SMB 프로토콜은 같은 검사 경로가 아니며, WAF 키를 터미널 권한으로 사용하지 않는다.

터미널의 입력 유휴 한도는5분, 전체 수명은30분, 출력 버퍼는256KiB다. 같은 lab의 세션은 컨테이너·UID10001·파일시스템을 공유하므로 **사용자별 OS 격리가 아니다**. 탭을 닫으면 해당 OS 세션(SID)의 검증된 UID10001 프로세스 정리를 시도하며, 새 OS 세션으로 분리한 자식까지 포함한 실습 전체 정리는 해당 lab의 **중지**로 컨테이너를 제거한다. 이는 기존 HTTP3개의 정지·재시작 계약과 구분한다.

C의 이미지 빌드·런타임·콘솔 반영을 완료했다. native 콘솔94개(HTTP API14개 포함), 런타임40개·터미널 daemon27개, 이미지 준비22개 회귀를 통과했다. 초기 런타임33개·daemon25개는 보완 전 결과다. 실제 HTTPS에서 서비스 응답·비권한 셸·시작을 확인하고, 터미널 helper만 보완한 최종 이미지로 Ctrl+C·다른 세션 보존·중지·중지 후 접속 거부를 재확인했다. 또한 호스트에서 도달 가능한 listener가 컨테이너에서 차단되는 것을 실측했다. host port 없음·internal network·Docker socket 없음·읽기 전용 rootfs·리소스 제한도 확인했다. 새로고침한 Safari에서 서버 파비콘, Redis의 UID10001·PONG, 최종 Samba의 UID10001·Version4.6.3·SMB3 공유 목록과 다크/화이트 테마·연결 종료·콘솔 중지를 확인했다.

[통합 운영 검증](../nonweb-labs/validation-20261023.json)과 [최종 TTY·이미지 증거](../nonweb-labs/terminal-tty-validation-20261023.json)에 실제 ID·SHA·검증 범위를 기록한다. 설치와 격리 조건은 [비웹 런타임 관리 계약](../nonweb-labs/README.md)을 따른다. 단일 `deploy.sh`의 service schema8은6항목·로컬 터미널 자산·`LAB_NONWEB_BUNDLE`을 반입하고 두 컨테이너를 자동 시작하지 않는다. **아래4항목·HTTP35개·native66개는 Redis/Samba 확장 전 검증 기록**이다. 새 VM3대 전체 설치 시험은 사용자 요청으로 보류하며 실제 취약점 악용/방어 E2E·재부팅·30분 전체 세션 수명 실측은 미검증이다.

## Redis·Samba 확장 전 운영 검증 기록

확장 전 UI는 수평 메뉴·큰 제목·서버 선화의 Lab Console이며 연결된 Java·Apache 두 버전과 공통 차콜/웜화이트 색상을 사용한다. DVWA는 독립 화면을 유지한다. 전체3서버 초기 설정은 루트 [deploy.sh 단일 진입점](../../../deployment/bootstrap-guide.md)이 로컬 반입·역할 설치·내부 helper를 연결한다. 당시 HTTPS35개·C native66개를 통과했으며 아래64개 검증은 변경 전 단계다. 새 VM3대 전체 apply는 아직 미실행이다.

기존 Log4Shell 웹 주소에서 사용하는 오프라인 CVE 실습 관리 화면이다. [관리 화면](https://log4shell.grootlab.duckdns.org/log4shell/)의 목록 조회·실행·중지는 **키 없이** 사용할 수 있다. 선택적인 차단 예외 키는 해당 브라우저의 WAF 검사 모드를 10분 동안 바꾸는 용도다. 확장 전 검증한 카탈로그는 **4항목**이다. Log4Shell과 Apache httpd 2.4.49·2.4.50은 로컬 이미지로 관리한다. DVWA는 목록과 같은 HTTPS 실습 경로에서 제외하고 원래 독립 주소로 유지한다. sudo는 별도 rootless CLI 환경이며 웹에서 실행하지 않는다. sudo rootless 런타임의 무해한 환경 검증과 정식 상태 발행 검증을 완료했다. 실제 권한 상승·호스트 탐지 성공을 뜻하지 않는다.

## 현재 범위 정정·공통 테마 — 적용 완료 (2026-10-23)

사용자가 DVWA를 원래 독립 주소에서 그대로 유지하도록 명시했다. 앞서 추가한 DVWA 통합은 요청 범위를 잘못 확대한 것으로, Log4Shell 사이트의 프록시·카탈로그 연결·전용 예외 쿠키·테마 처리만 제거했다. 원래 DVWA 앱·DB·독립 접속 설정은 유지했다. 10/22의5항목 검증 자료는 당시 이력으로 보존하며 정정 후 최종 통합 검증을 대신하지 않는다.

콘솔과 고정 웹3항목(Java·Apache 2.4.49·Apache 2.4.50)의 HTML 페이지 상단에 현재 모드인 **`다크` 또는 `화이트` 한 단어와16px 달·해 아이콘**을 표시하는 단일 버튼을 제공한다. 고정96px 버튼에서16px 아이콘 열과 글자 슬롯을 분리하고 각 슬롯 중심에 정렬한다. A TLS 프록시가 공통 로컬 `static/theme.js`·`static/theme.css`를 HTML에 넣으며 외부 CDN·폰트·테마 API는 없다. 전환 효과는180ms이고 reduced-motion 설정에서는 끈다. 최신 자산의 서버 SHA 일치, 새로고침한 Safari의 고정 아이콘·글자 가운데 정렬·양방향 전환, Java·Apache 두 버전의 테마 동작을 확인했다. sudo는 같은 콘솔에서 전용 웹 터미널 화면으로 연결한다.

선택은 같은 출처 localStorage의 `groot-lab.theme.v1`에 저장하고 다른 탭에 반영한다. 저장된 선택이 없으면 콘솔·Java·Apache 모두 다크 화면에서 시작한다. 저장소 접근이 차단돼도 현재 페이지의 전환은 동작한다. 버튼은 표시 설정만 바꾸며 키·쿠키·폼 입력을 읽거나 요청하지 않는다.

Java와 Apache 두 버전은 메인과 같은 최대1344px 외곽 프레임, 직선 테두리, 타이포그래피와 버튼을 사용한다. 헤더의 `Lab Console` 링크로 메인에 돌아갈 수 있고, Java의 요청·응답 패널과 Apache의 버전·안내 패널은 각 실습 기능에 맞춰 유지한다. 작은 화면에서는 탐색과 패널을 세로로 배치한다. 이 모양은 공통 `theme.js/css`에서 적용하므로 Java JAR·실습 이미지를 다시 만들 필요가 없다. 단일 초기 설치기도 두 파일을 필수 소스로 반입·복사하고 실제 제공 파일을 대조하므로 동일한 디자인을 설치한다. JSON·일반 텍스트 실습 자료의 응답 형식은 바꾸지 않는다.

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
