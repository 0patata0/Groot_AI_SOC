# Redis / Samba 오프라인 이미지 준비

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../STATUS.md) · [실행 계획](../../../PLAN.md).
> 현재 콘솔은 HTTP3개(Log4Shell/Apache2종)와 터미널3개(Redis/Samba/sudo), 총6항목이다. sudo는 별도 rootless의 UID1000·전역 단일 세션이며 종료 시 전체 중지한다. DVWA는 독립 유지한다. 환경 준비와 CVE 악용 성공을 구분하고 공격 재현은 보류한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

이 문서는 이미지의 출처 검증과 빌드·export를 다룬다. 컨테이너 격리, 최초 import, 웹 터미널은 [README.md](README.md)와 `bootstrap.py`의 별도 계약이다. Mac에 Docker·GPG·패키지를 설치하지 않는다. 네트워크가 가능한 준비 장비에서 입력만 내려받고, 승인된 Linux amd64 빌드 서버의 기존 Docker와 `gpgv`로 검증·빌드한다. 호스트 Redis/Samba/sudo 패키지는 변경하지 않는다.

## 버전과 CVE의 의미

| 실습 | 고정 입력 | 공식 근거와 검증 범위 |
|---|---|---|
| Redis | Ubuntu focal `redis-server`와 `redis-tools` **5:5.0.7-2** | [CVE-2022-0543](https://ubuntu.com/security/CVE-2022-0543)은 Lua 라이브러리를 연결한 배포판 패키징 문제다. 업스트림 버전 문자열 5.0.7만으로 판정하지 않는다. Ubuntu 수정판은 `5:5.0.7-2ubuntu0.1`이며 [USN-5316-1](https://ubuntu.com/security/notices/USN-5316-1)과 대조한다. |
| Samba | 서명된 업스트림 **4.6.3** 소스 | [CVE-2017-7494](https://www.samba.org/samba/security/CVE-2017-7494.html)의 수정판은 4.6.4다. 쓰기 가능한 공유와 named pipe가 관련 조건이며 `nt pipe support = no`는 공식 우회책이다. 이 설정은 `yes`이며 악성 공유 라이브러리나 공격 코드는 포함하지 않는다. |

이미지 검사는 버전·패키지·서비스 정상 동작을 확인한다. Redis PING/임시 SET·GET·DEL/단순 Lua 반환, Samba 임시 텍스트 파일 put/get/delete만 실행한다. 출력의 `attack_tested`는 항상 `false`다. 실제 취약점 악용이나 호스트 탈출을 검증했다는 뜻이 아니다. Samba의 `/share`에 적용되는 `noexec` 등 런타임 보호는 실제 악용 가능성에 영향을 줄 수 있다.

기반은 Linux amd64 Ubuntu 20.04의 `ubuntu@sha256:c664f8f86ed5a386b0a340d981b8f81714e21a8b9c73f658c4bea56aa179d54a`다. 임의 태그나 최신 이미지를 당겨오지 않는다. `sources.json`은 공식 URL, 실제 내려받은 파일의 크기·SHA256, Samba 서명키 fingerprint를 고정한다. Ubuntu 패키지는 각 반입 시 받은 서명된 InRelease → Packages.xz SHA256 → deb SHA256 연결로 검증하며, 그때 선택된 전체 의존성과 버전을 provenance에 보존한다. 따라서 날짜가 다른 재취득 결과가 비트 단위로 같다고 보장하지 않는다. 검증 후 export한 image archive가 재설치 입력이다.

## 준비 단계

네트워크가 가능한 장비의 작업 전용 임시 디렉터리에 받는다. `acquire` 성공은 다운로드와 해시 일치일 뿐, 서명 승인이 아니다.

```sh
python3 -B prepare.py acquire --output /작업전용임시경로/acquired
```

`assets`와 이 소스 폴더를 승인된 빌드 서버의 새 root 전용 디렉터리로 반입한다. 아래 경로는 예시이며 디렉터리가 이미 있으면 덮어쓰지 않는다. 업로드 archive의 SHA를 양쪽에서 대조하고 경로 탈출·심볼릭 링크 없는 안전 해제로 설치한다.

```sh
python3 -B /var/lib/nonweb-image-build/source/prepare.py prepare \
  --assets /var/lib/nonweb-image-build/assets \
  --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg \
  --keyring-sha256 '<독립적으로 확인한 Ubuntu archive keyring SHA256>' \
  --output /var/lib/nonweb-image-build/contexts
```

Ubuntu keyring 자체의 신뢰와 SHA는 운영자가 OS 설치/패키지 출처에서 확인해야 한다. 같은 미검증 반입 파일에서 계산한 SHA만 입력해 신뢰했다고 주장하지 않는다. `gpgv`는 설치된 기존 도구만 사용한다. Ubuntu 3개 InRelease 서명, 6개 압축 Packages의 signed SHA, 전체 deb, Samba 압축·해제 tar SHA와 서명을 모두 검증한 후에만 컨텍스트를 만든다. 과거 취약 패키지의 진위를 검증하는 경로이며 최신 보안 업데이트나 배포판 지원을 보장하는 경로가 아니다.

Samba 4.6.3은 2017년 배포 서명이므로 현재 공개키가 아니라 [공식 보관 키](https://download.samba.org/pub/samba/expired-gpg-keys/samba-pubkey_6F33915B6568B7EA.asc)를 사용한다. 공식 [2021년 키 전환 공지](https://lists.samba.org/archive/samba-technical/2021-February/136270.html)의 당시 fingerprint `52FBC0B86D954B0843324CDC6F33915B6568B7EA`와 결속한다. 만료된 역사적 키로 과거 tar 서명을 확인하는 의미이며 새 소프트웨어 서명 신뢰 정책을 완화하지 않는다. [Samba 배포 안내](https://www.samba.org/samba/download/)에 따라 서명 대상은 압축을 푼 tar다.

```sh
python3 -B /var/lib/nonweb-image-build/source/images.py build \
  --contexts /var/lib/nonweb-image-build/contexts \
  --output /var/lib/nonweb-image-build/build-result.json
python3 -B /var/lib/nonweb-image-build/source/images.py export \
  --result /var/lib/nonweb-image-build/build-result.json \
  --provenance /var/lib/nonweb-image-build/contexts/provenance.json \
  --output /opt/capstone-prereqs/nonweb
```

빌드는 Linux root, root 소유·group/world 쓰기 금지 경로, 기존 고정 기반 이미지가 필요하다. 시스템 Docker socket과 `/usr/local/bin/docker` 또는 `/usr/bin/docker`만 사용한다. 빌드 플러그인을 추가하지 않고 기존 classic builder를 명시한다. `--pull=false --network=none`, 로컬 deb에 `apt-get --no-download`, 서명 확인된 Samba 소스만 사용한다. `redis-build.log`와 `samba-build.log`는 결과 디렉터리에 root0600으로 남는다. 실패 시 기존 컨텍스트/증거를 보존하고 원인을 확인한다.

Export는 새 `/opt/...` root 전용 디렉터리에 `manifest.json`, `provenance.json`, `redis-image.tar`, `samba-image.tar`만 만든다. 태그 대신 전체 image ID로 저장해 기존 사용자 태그 덮어쓰기를 막는다. `bootstrap.read_bundle()`이 아카이브 SHA, 단일 이미지, OCI/config/layer/diff-id 연결, 태그 없음, 소유권을 다시 검증한다. Docker의 image ID가 OCI manifest ID인 경우와 config ID인 경우를 구분한다. Export는 runtime을 만들거나 image를 import하지 않는다. 설치기의 check/apply는 이 bundle을 사용하며 원본 archive와 provenance는 운영 복구용으로 보존한다.

## 이미지와 터미널 계약

- Redis 서비스는 UID/GID65534, 컨테이너 loopback6379에서 실행한다. Samba는 제한된 capability의 UID0 서비스이며 loopback1445와 guest 공유 `lab`을 사용한다. 외부 게시 포트는 없다.
- Samba의 [ncalrpc dir](https://www.samba.org/samba/docs/4.7/man-html/smb.conf.5.html#NCALRPCDIR)는 기존 `/run` tmpfs 안의 `/run/samba/ncalrpc`로 고정한다. 컴파일 기본 설정 경로 `/usr/local/samba/etc/smb.conf`는 `/etc/samba/smb.conf`를 가리키므로 터미널의 일반 `smbclient`도 같은 설정을 사용한다.
- `/share`는 익명 실습 참여자가 공유하는 휘발성 공간이다. 소유자는65534:65534, 루트 디렉터리 모드는01777이며 SMB 생성 파일은0666, 하위 디렉터리는0777로 강제한다. 이 설정은 guest NT ACL 검사와 업로드·다운로드를 위한 lab 내부 계약이며 `/share` 밖이나 호스트의 권한은 변경하지 않는다. Native 검사에서 실제 생성 모드와 텍스트 파일 put/get/cmp/delete를 확인한다.
- 두 이미지의 `/bin/sh`, `redis-cli` 또는 `smbclient`는 UID/GID10001 터미널 계정에서 실행 가능하다. `/tmp`가 작업·홈 경로다. 서비스용 writable tmpfs와 capability는 runtime 계약을 따른다.
- `/lab/terminal-session.sh`와 `terminal-close.sh`는 별도 64자리 소문자 hex process tag만 받는다. API token을 전달하지 않는다. Docker exec의 controlling TTY를 유지하고 worker의 PID=PGID=SID와 초기 foreground 상태를 확인하므로 대화형 셸의 job control과 Ctrl+C가 동작한다. 셸 시간 제한은 1,800초다.
- close는 고정 UID, receipt 소유권/링크/모드, worker PID 시작시각·PGID·SID와 정확한 명령행을 먼저 검증한다. 동일 SID의 UID10001 프로세스를 snapshot하고, 각 PID의 UID·SID·시작시각을 신호 직전에 다시 확인한 뒤 HUP/TERM을 보낸다. foreground/background job의 별도 PGID도 포함하며 다른 SID에 신호를 보내지 않는다.
- 같은 컨테이너의 세션들은 UID10001과 파일시스템을 공유한다. 세션 간 사용자 격리를 제공하지 않는다. 임의 `setsid`/daemonize로 해당 SID를 벗어난 자손의 전부 종료를 보장하지 않으며, 모든 실습 프로세스를 정리하는 경계는 해당 컨테이너 stop/reset이다.

작업 후 Mac 다운로드·임시 파일과 서버의 반입 archive/빌드 deb/컴파일 디렉터리는 운영 이미지 archive·최종 source/provenance/서명 결과·필요 로그와 구분해 정리한다. 기존 사용자 파일과 Docker 전역 캐시를 일괄 삭제하지 않는다. 단위 회귀는 `python3 -B test_images.py`로 실행하며, 이것을 실제 이미지 빌드·서비스·웹 터미널 E2E 완료와 구분한다.
