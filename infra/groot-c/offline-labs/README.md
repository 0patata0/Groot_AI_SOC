# GROOT Lab Console

현재 정책은 **2026-11-04 운영 반영** 기준이다. [상태·남은 과제](../../../STATUS.md) · [검증·배포·원복](../../validation/web-policy/README.md) · [갱신 전 이력](../../../archive/DEPLOYMENT_HISTORY.md#source-429cb0b9c8ff56ec).

[콘솔](https://log4shell.grootlab.duckdns.org/log4shell/)은 HTTP3개(Log4Shell·Apache2.4.49/2.4.50)와 터미널3개(Redis·Samba·sudo), 총6항목을 제공한다. DVWA는 기존 독립 주소를 유지한다. 목록·상태·실행 중인 웹은 공개 열람할 수 있고, **실행·중지·터미널 제어는 관리자 접속 주소와 인증이 모두 필요하다. 인증돼도 WAF 차단은 계속 적용된다.** 이전 차단 예외 모드/쿠키는 폐기했다.

## 사용 방법

1. 콘솔에서 항목과 현재 상태를 확인한다. 이미지 준비·컨테이너 가동·서비스 응답·공격 재현 성공은 서로 다른 상태다.
2. 제어가 필요하면 관리자 호스트192.168.16.231을 통해 접속하고 **관리자 인증 키**로 인증한다. 현재 키는 root가 C에 동기화한 공통 관리 키다. 키를 URL·명령행·채팅·Git·브라우저 저장소에 넣지 않는다.
3. 등록한 HTTP 항목을 시작하고 **실습 열기**로 `/log4shell/labs/<ID>/`를 연다. WAF는 정상 요청을 전달하고 탐지한 공격 요청을 차단한다. 인증은 검사 예외가 아니다.
4. 터미널 항목은 **실습 환경 시작 → 환경 열기**를 사용한다. 재연결은 새 환경을 자동 생성하지 않는다. Redis/Samba 연결 종료는 해당 세션만, sudo는 연결 종료/만료 시 컨테이너 전체를 중지한다.
5. 사용을 마치면 직접 시작한 실습을 중지하고 관리자 인증을 해제한다. IP 변경·600초 만료·키 변경 시 다시 인증한다. GET·새로고침은 세션 수명을 연장하지 않는다.

브라우저는30초 일회용 IP/Host 결속 challenge에 `HMAC-SHA-256(key=SHA-256(UTF-8(키)), message=UTF-8(challenge.message))`를 계산한다. 서버에는 challenge ID와 proof만 전달하며 키 원문·고정 해시는 보내지 않는다. 새 `groot_lab_admin` 쿠키는600초 IP 결속·Secure(HTTPS)·HttpOnly·SameSite=Strict다. 이전 `groot_lab_mode`와 서명 목적이 달라 옛 세션으로 제어할 수 없다. WebCrypto가 없으면 공개 열람만 가능하다. 개별 계정/SSO 기능은 아니다.

## 요청 경로와 권한

```text
브라우저 /log4shell/ (UI·API·터미널 HTTP·등록 HTTP3개)
  → A HTTPS 프록시 (실제 클라이언트 주소/ID·enforce 헤더 강제)
  → 기존 WAF (고정 proxy172.18.0.3만 신뢰, ModSecurity On)
  → C Apache의 A·loopback 전용 내부 경로
  → loopback FastAPI 또는 등록 웹 backend

FastAPI의 제어 요청
  → Origin/Host/본문 경계 + 관리자 CIDR + 새 HMAC 세션
  → peer UID/GID를 검증하는 고정 Unix broker/terminal daemon
  → 검증한 실습 컨테이너의 고정 동작
```

내부 쿠키 교환만 A의 `internal` subrequest로 C에 전달하며 공개 `/api/gateway-session`은404다. Java CSRF 쿠키만 해당 실습으로 전달하고 httpd에는 쿠키를 전달하지 않는다. 공개 UI·API는 WAF를 거친다. 실제 Redis/SMB 또는 터미널 내 프로토콜 자체를 HTTP WAF가 모두 검사하는 것은 아니며 각 전용 런타임의 격리가 필요하다.

WAF의10031 DetectionOnly 전환을 제거했다. On·공통 CRS와 탐지 메시지는 유지하고 관리 쿠키·proof·터미널 입력의 bulk HTTP 감사 사본은 제외한다. IP 차단·보호 주소·승인·TTL은 별도이며 관리자 인증 키로 IP 차단을 해제하지 않는다. 전용 mode 접근 로그에는 요청 ID·주소·시각·상태만 기록한다.

FastAPI에는 Docker socket·docker 그룹·sudo가 없다. root broker는 등록 ID의 status/deploy/stop만, terminal daemon은 고정 세션 기능만 수행한다. 임의 이미지·mount·환경·명령·호스트 셸 API는 없다. LLM의 변경은 별도의 승인형 MCP 범위를 따른다.

## 실습 격리와 수명

| 유형 | 실행/중지·격리 |
|---|---|
| HTTP3개 | UID/GID65532, read-only rootfs·tmpfs, cap-drop·no-new-privileges, CPU1·메모리512MiB·PID128. loopback18081/18082/18083, 전용 bridge/nft·ICC 차단. 중지는 정지·보존 |
| Redis·Samba | 포트 게시 없는 전용 internal bridge·nft, 컨테이너 UID10001. 중지는 세션 정리·컨테이너 제거. [별도 런타임](../nonweb-labs/README.md) |
| sudo | 전용 UID1991 rootless 런타임·컨테이너 UID1000. 전역 단일 세션, 종료/만료 시 전체 중지. 취약점 실습에 필요한 setuid 조건은 해당 런타임 계약으로 관리 |

이미지 ID·전체 컨테이너 ID·고정 설정·네트워크·receipt 소유권을 검사한다. 이름만 같은 미관리 컨테이너를 가져오거나 삭제하지 않는다. 이미지 누락 시 pull하지 않고, 격리 확인 실패 시 새 실행을 거부한다. 터미널 입력 유휴5분·전체30분·출력256KiB 제한이며 사용자별 OS 격리로 표시하지 않는다. 중지된 실습을 재부팅 뒤 임의로 시작하지 않는다.

## API

공개 경로에는 `/log4shell`, loopback 직접 경로에는 접두사가 없다.

| 경로 | 권한·결과 |
|---|---|
| GET `/api/list`, `/api/status` | 공개 열람. status는 isolation_verified·administrator_required·deployment_allowed를 구분 |
| GET `/api/session` | 항상 mode=enforce, admin_authenticated·admin_expires_at 반환 |
| GET `/api/challenge` | 관리자 CIDR에서만 일회용 challenge 발급 |
| POST `/api/session` | challenge_id/proof만 허용, 관리자 CIDR·1회 검증 뒤 새 세션. WAF 예외 없음 |
| DELETE `/api/session` | 빈 JSON 객체로 관리자 쿠키 삭제, enforce 유지 |
| POST `/api/deploy`, `/api/stop` | 관리자 CIDR+인증, 등록 cve_id만 허용 |
| `/api/terminal/*` | 관리자 CIDR+인증+명시한 같은 Origin+세션 소유권·고정 입력 경계 |
| `/api/gateway-session` | 공개404, 내부 고정 프록시 교환만 허용 |

401 인증 실패,403 출발지/Origin 거부,404 미등록 경로,409 격리/소유권/이미지 충돌,422 잘못된 고정 입력,429 challenge 한도,503 broker 미연결을 구분한다. 오류에 키/proof/원본 Docker stderr를 반사하지 않는다. Host·Origin/Fetch Metadata·JSON4KiB·헤더 크기 경계를 유지하고 외부 CDN·Swagger 자산을 쓰지 않는다.

## 설치·저장·복구

사용자 초기 진입점은 루트 [deploy.sh](../../../deploy.sh)다. service 역할은 검수된 catalog·wheel inventory·고정 이미지와 전체 static 자산을 반입하고 security 역할은4개 WAF 프록시 경로를 만든다. `MANAGEMENT_ALLOWED_CIDRS`를 C 관리자 CIDR로 기록한다. 공개 열람은 `LAB_ALLOWED_CIDRS=all`과 별개다. 기존 서버를 초기 설치기로 덮어쓰지 않는다. [오프라인 목록](../../../deployment/setup-packages-artifacts.md).

실행 소스 `/opt/capstone-offline-labs`, catalog/키 `/etc/capstone-offline-labs`, 상태/receipt `/var/lib/capstone-offline-labs`다. 키 파일은 root:capstone-labs0640이며 원문을 로그/출력하지 않는다. 공통 키를 회전하면 C 파일도 별도로 동기화하고 API를 재시작한다. Wazuh 계정 암호 변경만으로 자동 동기화되지 않는다.

이미지·rootless 저장소와 운영 receipt·복구본은 보존한다. 임시 반입물과 구분한다. guard·broker·API·터미널의 초기 설치/반복 검증, 실패 시 partial 기록·무단 재시도 금지, 고정 이미지 반입/manifest 검증은 기존 bootstrap을 따른다. 새 OS3대 전체 설치와 모든 CVE 악용/탐지 E2E는 미검증이다.

11/4 검증에서는 HTTP3개가 기존 중지 상태였다. UI200·환경 격리 확인을 HTTP3개 가동이나 취약점 재현 성공으로 표시하지 않는다. 상세 검증과 정확 복구 경로는 [웹 보안 기록](../../validation/web-policy/README.md)을 따른다.
