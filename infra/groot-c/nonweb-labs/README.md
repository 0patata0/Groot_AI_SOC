# 웹 터미널 중앙 관리·Redis/Samba 고정 런타임

## sudo 웹 터미널 중앙 연결 계약 (2026-10-23)

카탈로그는 **HTTP3개 + 웹 터미널3개, 총6항목**으로 연결한다. Redis/Samba는 아래 system Docker 고정 런타임을 사용하고 sudo CVE-2021-3156은 새 `sudo_terminal.py` adapter가 원래 별도 rootless 런타임을 호출한다. 같은 HTTPS 콘솔의 **실습 환경 시작 → 환경 열기**를 제공하고 service schema9 설치 경로에서 자동 연결한다. 실제 운영 적용·접속 검증 결과는 별도 증거와 STATUS에서 확인한다. 아래 `validation-20261023.json`과 TTY2종 증거는 Redis/Samba 완료 당시 이력이다.

중앙 bootstrap은 `sudo_terminal.py`를 포함한 관리 소스9개의 SHA를 결속한다. 기존8개 계약에서의 운영 변경은 별도 원본 백업과 명시적 pin 이관 후 검증하며 초기 설치기로 덮어쓰지 않는다. sudo adapter는 승인된 CLI 소스/config/image의 고정 pin을 확인하고 bootstrap receipt가 있으면 그 기록도 대조한다. receipt 이전의 수동 C 설치는 같은 정확한 승인 pin으로만 인정하며 임의 기존 컨테이너를 채택하지 않는다. 고정 고정 `capstone-sudo` 계정 UID1991과 그 계정의 rootless Docker socket만 사용한다. 셸은 검증된 full CID의 **컨테이너 UID/GID1000:1000**로 연다. 원래 sudo 이미지·package·오프라인 bundle은 바꾸지 않는다. user namespace 내부 setuid 실습을 위한 기존 no-new-privileges=false와 SETUID/SETGID 조건을 유지하며 이를 호스트 권한으로 확대하지 않는다. 호스트 root 매핑 없음·network none·host port/mount/device/socket 없음·read-only root·자원/기본 seccomp 계약을 기존 검사기로 다시 확인한다. browser나 LLM에 일반 Docker·호스트 shell·sudo 권한을 주지 않는다.

sudo는 서버 전체 **터미널1개**만 허용한다. 같은 프로세스가 컨테이너 내부에서 권한을 바꿀 수 있으므로 UID1000 프로세스만 죽이는 정리를 사용하지 않는다. **연결 종료·입력 유휴5분·전체30분 만료·터미널 서비스 종료 시 해당 full CID의 sudo 컨테이너 전체를 중지**한다. 대상 CID 비교와 중지를 같은 전용 operation lock으로 묶어 교체된 컨테이너를 중지하지 않는다. 중지 결과를 확인하지 못하면 성공을 반환하지 않고 새 sudo 연결을 보류한다. UI는 종료 실패를 중지 완료로 표시하지 않는다. 브라우저 pagehide keepalive 전달 실패에는 서버 시간 제한을 함께 사용하며, 다시 사용하려면 콘솔에서 환경을 시작한다. 재연결 요청이 환경을 자동 배포하지 않는다.

Redis/Samba는 기존 UID10001·SID/시작시각 기반 세션 정리를 유지하고 연결 종료만으로 컨테이너를 중지하지 않는다. 아래 고정 `lab.sh` 명령·internal bridge·nft·이미지2종 bundle 계약은 **Redis/Samba 전용**이다. 원래 sudo CLI 소스와 그 README는 운영 SHA 결속을 유지하기 위해 보존하며, 그곳의 웹 미제공 설명은 중앙 adapter 추가 전 이력으로 읽는다. DVWA 독립 운영과 HTTP WAF 예외의 범위는 그대로다. 실제 취약점 악용/호스트 탐지 E2E·신규3VM 설치·재부팅 완료를 이 구현 계약으로 주장하지 않는다.

## Redis·Samba 전용 계약과 이전 구현 검증 (2026-10-23)

기존 `lab.sh` 초안을 확장해 고정 Compose·오프라인 bootstrap·상태 publisher와 같은 HTTPS 사이트의 웹 터미널 연결 소스를 작성했다. Redis/Samba 확장 완료 당시 카탈로그는 HTTP3개·sudo CLI1개·터미널2개의 **6항목**이었다. 현재 sudo 연결 정책은 위 중앙 계약을 따른다. Redis/Samba는 **실습환경 시작 → 환경 열기** 순서로 `/log4shell/terminal/<CVE ID>/`에 접속하도록 구현했다. 당시 sudo는 별도 rootless CLI였고 DVWA는 독립 주소를 유지했다.

소스 작성 단계에서 로컬 런타임 회귀33개·터미널 daemon 회귀25개와 Bash 구문 검사가 통과했다. HTTP API 회귀14개는 Mac에 FastAPI가 없어 건너뛴 뒤, C의 기존 vendor 환경에서 후보 콘솔 전체94개 회귀에 포함해 통과했다. 이 시험은 가짜 RPC를 쓰는 API 경계 검사이며 실제 컨테이너·브라우저 터미널 동작 증거와 구분한다.

이 README는 설치 시 SHA로 결속하는 **관리 계약**이다. 실제 운영 검증 결과는 별도 `validation-20261023.json`과 저장소 [STATUS.md](../../../STATUS.md)에 기록한다. 그 기록에서 이미지 ID·archive SHA·적용 시각·무해한 서비스/터미널/네트워크 격리 검사·시작/중지/재시작·복구 범위를 확인한다. 설치 완료, 기존 C의 한정 확장 검증, 새 VM3대 전체 설치 시험, 실제 취약점 악용 E2E를 서로 대신하는 증거로 쓰지 않는다.

Redis **CVE-2022-0543**는 Ubuntu 패키지 `redis-server`/`redis-tools` **5:5.0.7-2**를 사용한다. upstream Redis 버전 문자열만으로 해당 패키지 취약점을 입증하지 않는다. Samba **CVE-2017-7494**는 upstream **4.6.3**을 사용한다. 실제 공격·취약점 악용 E2E는 이 설치기나 기본 검증에서 수행하지 않는다.

웹 콘솔의 시작/중지와 가상 터미널은 peer credential로 제한한 별도 Unix 서비스가 이 고정 런타임을 호출한다. 터미널은 검증된 컨테이너의 **UID/GID 10001:10001**로만 접속한다. 호스트 셸, 임의 Docker 인수·이미지·mount·경로를 받지 않는다. 원래 sudo rootless 실습과 다른 환경이며 호스트 sudo·sudoers를 수정하지 않는다.

터미널은 입력 없이 **5분**, 생성 후 최대 **30분**으로 제한한다. 출력 버퍼는 세션당 **256KiB**, 한 입력은 최대2KiB이며 오래된 출력이 제거되면 누락 여부를 표시한다. 같은 클라이언트의 동시 세션은2개, daemon 전체는8개까지다. 세션 제어 요청은 같은 출처와 서버가 결속한 소유자·비밀 세션 식별자를 확인한다. 이 식별자는 URL이나 접근 로그에 넣지 않는다.

같은 lab의 세션은 **동일 컨테이너·UID10001·파일시스템을 공유**한다. 브라우저 세션 소유권 검사는 사용자마다 별도 OS·프로세스·데이터 격리를 제공하는 기능이 아니다. 터미널은 Docker가 제공하는 controlling TTY를 유지해 대화형 명령과 Ctrl+C를 지원한다. 탭 종료·만료는 기록된 OS 세션(SID)에 속한 UID10001 프로세스의 PID·시작시각을 검증해 정리를 시도한다. 새 OS 세션으로 분리한 자식까지 포함한 최종 정리 경계는 해당 **실습환경 중지**이며, 이때 lab 컨테이너와 휘발성 데이터가 제거된다. 다른 lab이나 호스트 서비스는 중지 대상이 아니다.

## 오프라인 준비·설치

대상은 Ubuntu 24.04 amd64, Python 3.12+, 기존 system Docker 28+, Compose plugin, nftables, systemd다. `--check`는 콘솔 계정 생성 전에도 사전 조건을 검사하며, `--apply`에는 콘솔의 `capstone-labs` 계정이 먼저 준비돼 있어야 한다. 이 bootstrap은 pip/apt/pull/build/download를 실행하지 않는다. 이미지 제작·export는 별도 준비 단계다.

검토된 이미지를 full image ID로 export해 root 소유의 `/opt/capstone-prereqs/nonweb`에 준비한다. 다른 사용자에게 쓰기 가능한 부모, symlink, hardlink, 추가 파일은 허용하지 않는다.

- `manifest.json`: schema 1, profile `capstone-nonweb-v1`, `images`의 정확한 `redis`·`samba` 두 항목과 `provenance_sha256`.
- 이미지 항목: `image_id`, `archive` (`redis-image.tar` 또는 `samba-image.tar`), `archive_sha256`, `archive_size`, `software` (`Redis`/`Samba`), `version` (`5.0.7`/`4.6.3`), `start_sha256`, `verifier_sha256`.
- `provenance.json`: 이미지 제작 담당의 공개 출처·서명·패키지 버전·빌드 증거. manifest와 SHA가 같아야 한다.
- 두 이미지 tar: Docker save의 정확히 한 이미지, RepoTags 없음. 파일 SHA, config 또는 OCI manifest ID, config→layer diff ID를 검증하며 호스트에 tar를 풀지 않는다.

```sh
sudo python3 -IB /opt/capstone-source/infra/groot-c/nonweb-labs/bootstrap.py --check \
  --bundle /opt/capstone-prereqs/nonweb \
  --source-root /opt/capstone-source/infra/groot-c/nonweb-labs
sudo python3 -IB /opt/capstone-source/infra/groot-c/nonweb-labs/bootstrap.py --apply \
  --bundle /opt/capstone-prereqs/nonweb \
  --source-root /opt/capstone-source/infra/groot-c/nonweb-labs
sudo python3 -IB /opt/capstone-nonweb-labs/bootstrap.py --verify \
  --bundle /opt/capstone-prereqs/nonweb
```

`--source-root`는 저장소 루트가 아닌 이 폴더를 가리킨다. `--check`는 입력·기존 Docker·nft 충돌만 읽고 이미지 로드, 파일 생성, 컨테이너 생성, 서비스 시작을 하지 않는다. `--apply`는 source/config/receipt, 이미지 로드, guard·terminal·publisher unit을 설치하며 실습 컨테이너는 기본 미시작이다. 완료 후 같은 입력의 apply는 검증만 한다. 중간 실패는 root 전용 `bootstrap.json`의 `state=partial`/`phase`에 남고 추가 작업을 중단한다. 기존 사용자 상태·부분 컨테이너·이미지를 자동 삭제하거나 무시하지 않는다.

## 고정 실행과 상태

```sh
sudo bash /opt/capstone-nonweb-labs/lab.sh check redis
sudo bash /opt/capstone-nonweb-labs/lab.sh up redis
sudo bash /opt/capstone-nonweb-labs/lab.sh getcontainer redis
sudo bash /opt/capstone-nonweb-labs/lab.sh verify samba
sudo bash /opt/capstone-nonweb-labs/lab.sh status samba
sudo bash /opt/capstone-nonweb-labs/lab.sh stop redis
```

`up`은 시작 중인 동일 컨테이너를 재생성하지 않는다. `reset`은 운영자가 지정 실습만 재생성하고 휘발성 실습 파일을 지우는 명령이다. `logs`는 운영자용 최근 200줄이다. `stop`/`down`은 기록된 정확한 컨테이너만 정지·삭제하며 전용 network를 남긴다. 선택적인 과거 세 번째 image ID 인수는 설치된 ID와 같을 때만 허용한다.

모든 성공 결과는 JSON이며 `status=running|stopped|not_deployed`, full `container_id`, pinned `image_id`, `image_present`, `verified_at`, `exec_user=10001:10001`를 제공한다. `getcontainer`는 격리 계약과 무해한 서비스 검사까지 다시 통과해야 full ID를 반환한다. 실패는 고정 오류 코드이며 Docker stderr나 인증정보를 출력하지 않는다.

각 lab 영수증에 full CID를 보존한다. 같은 이름·라벨이라도 기록되지 않은 컨테이너는 채택·삭제하지 않는다. Compose 완료와 영수증 기록 사이에 중단된 경우 자동 복구로 채택하지 않으므로 운영자 확인이 필요하다. 이를 우회하려고 receipt를 임의 재작성하지 않는다.

## 격리와 검증 의미

실습마다 서로 다른 internal bridge와 ICC 비활성 설정을 쓴다. 공개 포트와 host bind mount는 없고 read-only root, no-new-privileges, cap drop, tmpfs, 메모리·CPU·PID·로그 제한을 확인한다. Redis 서비스는 65534, Samba 서비스는 필요한 네 capability만 가진 컨테이너 root다. Samba `/share`만 라이브러리 적재 실습 조건을 유지하기 위해 `noexec`를 지정하지 않는다. 이는 호스트 실행권한이 아니며 /share는 컨테이너 tmpfs다.

전용 nft `inet capstone_nonweb`은 `br-cap-redis`·`br-cap-samba`에서 호스트로 새 연결 및 양방향 forwarding을 차단한다. 다른 nft 테이블을 수정하지 않는다. guard가 없거나 순서·drop·우선순위가 다르면 새 시작과 터미널 연결은 거부하며 정지 기능은 남긴다. internal network만을 호스트 서비스 차단의 증거로 삼지 않는다.

이미지 `/lab/start.sh`, `/lab/verify.sh` SHA를 실제 컨테이너에서 확인한 뒤 `/lab/verify.sh`의 고정 JSON을 검사한다. 서비스는 컨테이너 내부 loopback만 이용한다(Redis `127.0.0.1:6379`, Samba `127.0.0.1:1445`, share `lab`). 터미널 예시는 `redis-cli -h 127.0.0.1 -p 6379 PING`, `smbclient //127.0.0.1/lab -p 1445 -N -c ls`이다.

상태 publisher는 60초마다 무해한 기능·격리 검사를 하고 `/var/lib/capstone-nonweb-labs/status.json`을 root:root0600, TTL300초로 갱신한다. sudo의 기존 상태 파일은 변경하지 않는다. `ready`는 **실습 환경 준비**이며 `verification=environment_only`, `attack_tested=false`다. 설치 완료·이미지 존재·실제 시작·공격 성공은 서로 구분한다. 이 운영 점검용 영수증에서 미시작은 `needs_setup`, 검사 실패는 `error`다. 웹 콘솔은 이 영수증을 읽는 대신 고정 status RPC로 현재 컨테이너·이미지·격리 설정을 조회하며, 터미널을 열 때 서비스 기능을 다시 검사한다.

코드·로컬 회귀와 기존 C의 한정 실측, 새 VM 전체 설치 검증은 각각 별도 증거로 기록한다. 이 문서만으로 실제 적용이나 새 3VM 설치 통과를 주장하지 않는다.
