# Wazuh 시연용 VPN 접속 — 2026-10-20 23:59 KST 종료

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../STATUS.md) · [실행 계획](../../../PLAN.md).
> A는 외부/내부 관문이며 Suricata는 passive IDS다. DVWA의 DetectionOnly와 실습 HTTP 경로의 WAF 차단/요청별 예외를 구분한다. 이번 TLS 조회의 세 HTTPS 이름 만료는2027-01-13 13:25:12 KST이며 과거 인증서 값은 이력이다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

이 소스는 A의 기존 `wazuh.grootlab.duckdns.org:443` 서버 블록 한 곳에만 `192.168.15.0/24` VPN을 한시 허용하는 후보를 만들고, `apply.py`로 검토된 고정 구성을 한 번 적용한다. 기존 Wazuh 로그인은 유지하며 manager API·indexer·10443 포트, B 설정, legacy `wazuh.groot.lab`, 채팅·Log4Shell 서버 블록을 변경하지 않는다. 실제 적용·접속·종료 검증 결과는 바로 아래 기록을 따른다.

## 2026-10-19 22:52 적용·22:55 KST 최종 검증

기존 [Wazuh 주소](https://wazuh.grootlab.duckdns.org/)를 학과 VPN에서 기존 계정으로 접속할 수 있다. 임시 허용은 **2026-10-20 23:59:00 KST**에 종료되며 기존 학과망 허용은 유지한다. 일반 인터넷 공개나 별도 VPN 서버 설치는 하지 않았다.

- A의 같은 chatproxy를 reload했다. 컨테이너 ID·기동시각·Compose·인증서 파일은 유지했고 nginx.conf inode 1441919도 유지했다. 현재 설정 SHA는 `fbee3603f3e395ac46d78da9e97dc83a119f459cbfbc6d8cecf950bf364bbc01`이다. 저장소의 `../chatproxy.nginx.conf`는 변경 전 기준 파일이며 현재 설정은 여기에 `render.py`가 만든 한시 설정을 반영한 결과다.
- 실제 VPN에서 시스템 CA·호스트명 검증, 로그인 페이지200, 기존 계정 로그인200, 인증 후 `/app/wz-home`200, 상태 API200/green을 확인했다. 종료 서비스 수동 실행22:53 후 VPN403을 확인하고 승인된 기간 안에서 다시 열었다. 마지막 로그인·POST 로그아웃·로그인 화면 복귀까지 통과했다. 타이머는 enabled/active/waiting이며 다음 실행은 10/20 14:59UTC다.
- 오프라인9+7, 격리 실제 Nginx 문법 검사·guard12경계를 통과했다. 첫 격리 문법 검사는 임시 캐시 chown 권한 부족으로 실패했고 운영 변경 없이 정리 후 syntax 컨테이너에만 CHOWN을 추가해 통과했다. 운영 설정에도 실제 `nginx -t`를 수행했다.
- 채팅 ping200, Log4Shell HTTP/HTTPS 상태200·2.14.1, legacy Wazuh VPN403을 확인했다. B의3개 Wazuh 컨테이너 ID·기동시각과 Compose/dashboard설정3개 SHA, C Log4Shell ID·기동시각도 유지됐다.
- 종료 전 시작한 요청·이미 받은 화면의 강제 삭제는 하지 않는다. 미래의 예약 시각 자체는 아직 도래하지 않았으며, 실제 종료 서비스·403과 격리 Nginx의 종료 초 경계를 각각 검증한 것이다. 학과 현장 단말·일반 인터넷 접속·호스트 재부팅은 이번에 시험하지 않았다.

[배포·검증 증거](deployment-validation-20261019.json). 복구본은 A `/var/backups/capstone-wazuh-demo/20261019`(root0700)이며 소스·증거는 `/var/lib/capstone-wazuh-demo-access/source`에도 보존한다. 운영 timer·close·state·include와 복구본은 유지하고 작업 staging·검사 컨테이너는 정리한다. 새 패키지 설치·다운로드·인증서 개인키 복사는 없다.

`render.py`는 실측 원본 SHA `2790ab83df6c4e1b13ac00a277ea8158a16bb767c2c2b1e0a2c5f01b598b8424`만 받는다. 새 출력 디렉터리에 후보 `nginx.conf`, 활성·종료 include, `state.json`을 만든다. 입력 파일은 수정하지 않고 기존 출력 디렉터리도 덮어쓰지 않는다.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B infra/groot-a/wazuh-demo-access/render.py \
  infra/groot-a/chatproxy.nginx.conf /작업별/새출력폴더
PYTHONDONTWRITEBYTECODE=1 python3 -B infra/groot-a/wazuh-demo-access/test_window.py
```

대상 서버 블록의 인증서 참조만 기존 공인 wildcard `chatduck.crt/key`로 변경한다. `apply.py`는 `openssl x509 -checkhost wazuh.grootlab.duckdns.org`의 일치 출력, 시스템 CA를 통한 fullchain 검증, 종료 시각 이후까지의 유효기간을 확인한다. 개인키를 출력하거나 복사하지 않는다. 공인 인증서 경로와 시간 guard는 종료 후에도 남으며, 종료는 임시 VPN 허용만 회수한다.

## 요청마다 적용되는 종료 조건

`http` 범위에 `geo` 하나와 `map` 두 개를 추가한다. VPN 요청은 `$time_iso8601`이 아래 UTC 구간에 속할 때만 진행할 수 있다.

- `2026-10-19 00:00:00`부터 `23:59:59`까지.
- `2026-10-20 00:00:00`부터 `14:58:59`까지.
- UTC offset은 `+00:00`만 인정한다. 시각 형식·timezone이 바뀌면 VPN 요청을 거부한다.

`2026-10-20T14:59:00+00:00`부터 해당 VPN 요청은 대상 서버의 `if (...) { return 403; }`에서 차단한다. 타이머·reload가 실패해도 **이미 로드된 guard가 새 요청을 거부**한다. 다른 출발지는 원래 allow/deny 정책을 적용한다. 종료 전에 시작한 요청·이미 수신한 화면 내용을 소급하여 취소하는 기능은 아니다.

## A 설치 계약과 적용 순서

`apply.py`는 A에서 root가 명시적으로 실행하는 일회성 적용기다. SSH·패키지 설치·이미지 다운로드·인증서 발급을 하지 않는다. 원본 SHA·컨테이너 ID와 `render.py`, `close.py`, 두 unit의 검토된 SHA를 고정하므로, 다른 상태나 수정된 소스에 재사용하려면 재검토가 필요하다. 상태 디렉터리·종료 도구·unit·include·타이머 기록 또는 날짜 백업이 이미 있으면 덮어쓰지 않는다.

아래 예시는 이 디렉터리를 A의 root 소유 stage에 올린 뒤 **A의 root 셸에서** 실행한다. `demo_source`에는 `apply.py`, `render.py`, `close.py`, 두 unit과 검사 파일들이 직접 있어야 한다. 먼저 격리 검사를 통과시키고 명시적으로 `apply.py`를 호출한다.

```sh
demo_source=/var/tmp/wazuh-demo-stage/source
demo_docker=$(command -v docker)
demo_nsenter=$(command -v nsenter)
demo_image=$("$demo_docker" --host unix:///var/run/docker.sock inspect \
  --format '{{.Image}}' 2c6923e7a66ebf55ef28f866cda77a3000f3ed26f7937198927cd73d5cd85403)
python3 -B "$demo_source/native_check.py" \
  --render "$demo_source/render.py" \
  --baseline /home/groot_a/capstone/chatproxy/nginx.conf \
  --tls-dir /home/groot_a/capstone/chatproxy/tls \
  --image "$demo_image" --docker "$demo_docker" --nsenter "$demo_nsenter"

# 격리 검사 JSON의 passed=true 및 cleanup 결과를 확인한 뒤 적용한다.
python3 -B "$demo_source/apply.py" "$demo_source"
```

Docker가 `/usr/bin/docker`에 있다는 가정을 피하려고 검사기에는 실제 경로를 전달한다. `apply.py`와 설치되는 종료 도구도 고정 PATH에서 Docker를 찾고 로컬 Unix socket을 명시한다. 적용 성공 JSON의 `installed_reload_signalled`는 설정 검사와 reload 신호 전송을 뜻하며, `http_login_test`는 `pending`으로 남는다. 실제 VPN의 CA 검증·로그인·다른 서비스 점검은 이어서 별도로 수행한다.

| 파일 | 설치 위치·권한 |
|---|---|
| `close.py` | `/usr/local/sbin/capstone-wazuh-demo-close`, root:root 0500 |
| 출력 `state.json` | `/var/lib/capstone-wazuh-demo-access/state.json`, 부모 root0700·파일 root0600 |
| 출력 활성 include | `/home/groot_a/capstone/chatproxy/tls/wazuh-vpn-window.allow.conf`, root:root 0644 |
| `.service`·`.timer` | `/etc/systemd/system/`, root:root 0644 |
| 출력 `nginx.conf` | `/home/groot_a/capstone/chatproxy/nginx.conf`, 기존 inode 유지 |

1. 현재 원본 SHA·컨테이너 ID·두 bind mount와 컨테이너 `date -Iseconds`의 `+00:00` timezone을 확인한다. 원본·후보·활성/종료 include·소스·상태·기존 inode/권한은 `/var/backups/capstone-wazuh-demo/20261019`에 root0700 디렉터리·root0600 파일로 보존한다. 고정 ID는 `2c6923e7a66ebf55ef28f866cda77a3000f3ed26f7937198927cd73d5cd85403`이다. 다르면 재검토한다.
2. root 전용 상태·종료 스크립트·서비스·타이머를 먼저 설치한다. `systemd-analyze verify`와 `systemd-analyze calendar '2026-10-20 14:59:00 UTC'`로 검사한 뒤 timer를 enable/start하고 다음 실행 시각을 확인한다.
3. 활성 include를 설치하고 후보 설정을 기존 `tls` 디렉터리 마운트의 작업용 파일로 넣어 `nginx -t -c /etc/nginx/tls/후보파일`로 검사한다. 현재 실행 설정은 아직 그대로다.
4. 원본 SHA와 inode를 다시 확인한 뒤 후보를 기존 `nginx.conf` inode에 기록한다. 해당 설정은 단일 파일 bind mount이므로 파일 rename으로 교체하지 않는다. 컨테이너 안의 SHA·`nginx -t`를 확인하고 reload한다. 실패하면 임시 include를 닫고 timer를 중지·disable한 뒤 원본을 같은 inode로 복원하여 native 검사·reload한다. 복원 성공 시 이번에 만든 파일을 정리하고 백업 증거는 남긴다. 복원 실패 시에는 닫힌 include와 상태·종료 도구를 보존하고 실패 JSON으로 알린다.
5. 적용기는 임시 후보 파일을 제거하고 설정 SHA·timer 시각 등을 JSON과 백업에 기록한다. 적용자는 이어서 시스템 CA 검증을 켠 VPN 요청에서 대상 로그인 경로, legacy Wazuh 거부, 채팅 ping·Log4Shell 기존 동작을 확인한다. `systemctl start capstone-wazuh-demo-close.service`로 실제 조기 종료와 VPN 403을 검사할 수 있다. 자동 재개 기능은 없으며, 다시 허용하는 작업은 별도 판단·검증 대상으로 남긴다.

`close.py check`는 고정 상태·include의 현재 active/closed 값을 확인한다. 인자 없이 실행하거나 `close`를 지정하면 언제든 임시 허용을 조기 종료한다. `flock` 후 include를 원자적으로 빈 주석으로 바꾸고 fsync하며, 고정 로컬 Docker socket·컨테이너 ID·마운트를 확인한 뒤 `nginx -t`와 reload를 요청한다. 실패해도 활성 allow를 복구하지 않는다. `nginx -s reload` 성공 출력은 신호 전달 확인이며 브라우저 시험 결과로 표현하지 않는다.

타이머는 `OnCalendar=2026-10-20 14:59:00 UTC`, `Persistent=true`, `AccuracySec=1s`다. 종료 서비스가 실패하면 15초 후 재시도한다. 컨테이너가 재생성되면 ID가 달라 close의 reload는 거부하지만, include는 이미 닫히고 기존/새 설정의 요청별 UTC guard도 종료 시각 이후 VPN 요청을 거부한다. 종료 서비스와 timer는 성공 증거를 확인한 뒤 별도 관리 정리 대상으로 남긴다.

## 검증 범위

`test_window.py`의 오프라인 9개 회귀는 UTC 초 경계, 종료일 1,440분, timezone 변경 거부, 원본 불일치 거부, 다른 서버 블록 보존, 종료 파일의 멱등성과 상태 경로 변조 거부를 검사한다.

`native_check.py`는 운영 컨테이너의 기존 로컬 image ID로 포트 미게시·network none 임시 컨테이너만 만든다. 인증서 디렉터리는 읽기 전용으로 연결하고, 전체 후보의 include·인증서 경로만 격리 경로로 바꾸어 `nginx -t`를 수행한다. 문법 검사 컨테이너에만 자체 tmpfs 캐시 초기화용 `CHOWN` capability를 추가한다. guard 검사에서는 출발지·시각 입력 두 개만 fixture 헤더로 대체하며 실제 서버 시계를 바꾸지 않는다. 헤더를 통한 시험 입력은 운영 후보에는 들어가지 않는다.

guard의 12개 native HTTP 사례는 시작 전, 첫 초, 첫날 마지막 초, 종료일 13:59:59·14:00:00·14:58:59, 종료 초 14:59:00, 15:00:00, 다음 날, 다른 timezone, 잘못된 시각, VPN 외 출발지를 검사한다. 예상 응답은 허용 구간 204·거부 구간 403이다. 소유 label과 image ID가 일치하는 임시 컨테이너만 정리하고 잔존 여부를 결과에 포함한다.

`test_native_check.py`의 7개 회귀는 진단 출력 길이·제어문자 제한, 문법 검사 전용 `CHOWN`, fixture 경로 변경 범위, guard 입력 두 개만 변경, 12개 경계와 renderer 일치, 다른 컨테이너 삭제 거부, 소유 컨테이너 삭제 확인을 검사한다.

```sh
python3 -B infra/groot-a/wazuh-demo-access/test_window.py
python3 -B infra/groot-a/wazuh-demo-access/test_native_check.py
```

격리 parser·guard 검사 결과와 실제 VPN 로그인·조기 종료·예약된 timer 실행 결과는 따로 기록한다. 기존 TCP 연결의 후속 HTTP 요청도 요청별 guard를 평가하지만, 이미 진행 중인 요청이나 업그레이드된 연결을 강제 종료하는 기능은 아니다. 원본 접근 제한은 Wazuh 계정 인증을 대신하지 않는다.

근거: [Nginx 접근 규칙 순서](https://nginx.org/en/docs/http/ngx_http_access_module.html), [map](https://nginx.org/en/docs/http/ngx_http_map_module.html), [geo](https://nginx.org/en/docs/http/ngx_http_geo_module.html), [reload](https://nginx.org/en/docs/control.html), [systemd timer](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html).
