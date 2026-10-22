# CVE-2021-3156 sudo 패키지·격리 환경 준비

이 디렉터리는 C 호스트의 sudo를 변경하지 않고 **별도 rootless Docker**에서 Ubuntu 20.04의 sudo `1.8.31-1ubuntu1` 패키지를 준비하고 확인한다. 공격 페이로드·exploit·웹 shell·임의 명령 실행 API는 포함하지 않는다. CLI의 유일한 컨테이너 내부 검사는 고정된 `/lab/check.sh`이며 `sudo --version`, `dpkg-query`, 파일 소유권/권한을 확인한다. 운영 `/var/run/docker.sock`, 기존 웹 broker, `nonweb-labs/lab.sh`, 전역 Docker 설정은 사용하거나 변경하지 않는다.

**현재 확인 범위(2026-10-22~23 KST, C 실측):** Ubuntu 24.04.5의 별도 계정 `capstone-sudo`(UID/GID 1991)에 Docker 29.8.1·RootlessKit 3.1.0 환경을 설치했다. Ubuntu/Docker 저장소 서명과 패키지 해시 검증, 오프라인 이미지 빌드·반입, Linux 네이티브 회귀 26개와 `check → up → verify → 실행 중 up → stop → 새 CID up → verify`가 통과했다. 매 `verify`에서 고정 `docker exec /lab/check.sh`를 새로 실행했다. rootless 컨테이너는 실행 상태로 유지한다. **권한 상승 공격과 원래 호스트 auditd→Wazuh 시나리오는 실행하지 않았다.** 웹의 `ready`도 패키지와 격리 환경 확인만 뜻한다.

호스트 sudo revision, 기존 시스템 Docker unit, 전역 user namespace/AppArmor sysctl은 설치 전후 동일했다. 초기 조사 때 rootless 도구가 없던 상태는 과거 기록이며 현재의 미준비 상태를 뜻하지 않는다.

## 출처와 버전 판단

- [Ubuntu CVE 상태](https://ubuntu.com/security/CVE-2021-3156)와 [USN-4705-1](https://ubuntu.com/security/notices/USN-4705-1)은 focal 수정 버전을 `1.8.31-1ubuntu1.2`로 명시한다. 준비 대상은 이전 revision인 `1.8.31-1ubuntu1`이다. `sudo --version`의 `1.8.31`만으로 패치 상태를 판정하지 않는다.
- [Ubuntu 공식 archive](https://archive.ubuntu.com/ubuntu/pool/main/s/sudo/)에 해당 amd64 deb와 대응 소스가 있다. `prepare.py`는 Ubuntu archive 서명, Packages 파일 해시/크기, 정확한 package/version/architecture/filename, deb SHA256/크기를 연결해 검증한다. 설치 후 전체 dpkg revision도 비교한다.
- [sudo 1.9.5p2 변경 이력](https://github.com/sudo-project/sudo/blob/SUDO_1_9_5p2/NEWS)과 [Qualys 원 연구](https://blog.qualys.com/vulnerabilities-threat-research/2021/01/26/cve-2021-3156-heap-based-buffer-overflow-in-sudo-baron-samedit)가 원인·수정 근거다. 이 코드는 취약 함수나 공격 성공을 실행 검증하지 않는다.
- `source.json`의 Ubuntu base는 Docker 공식 `library/ubuntu:20.04`의 linux/amd64 manifest로 고정했다. 초기 `source.json` 기록은 2026-10-22 registry metadata 조회 결과다. 이후 승인된 C 준비 단계에서 base·sudo 이미지의 실제 빌드와 반입을 수행했으며 이미지 아카이브의 OCI manifest→config→layer 해시와 rootless 저장소의 rootfs diff ID까지 대조했다. multiarch index와 config/image ID도 출처 기록에 별도로 남겼다.

## 준비 호스트에서 패키지 검증·이미지 빌드

다운로드는 네트워크가 허용된 준비 환경에서만 한다. Mac에는 도구·패키지를 설치하지 않는다. 필요한 기존 도구가 없는 Mac에서는 작업용 임시 디렉터리로 파일만 받아, `gpgv`와 신뢰한 Ubuntu archive keyring이 있는 승인된 Linux 준비 호스트로 옮긴다. `prepare.py`와 `lab.py`는 네트워크를 호출하지 않는다. `runtime/history/rootless-acquire.py`는 실제 반입에 사용한 네트워크 다운로드 코드의 과거 원본이며 자동 실행하거나 import하지 않는다.

준비할 공식 파일:

```text
https://archive.ubuntu.com/ubuntu/dists/focal/InRelease
https://archive.ubuntu.com/ubuntu/dists/focal/main/binary-amd64/Packages.xz
https://archive.ubuntu.com/ubuntu/pool/main/s/sudo/sudo_1.8.31-1ubuntu1_amd64.deb
```

`--keyring-sha256`는 이미 신뢰하는 Ubuntu 설치/배포 경로에서 별도로 확인한 archive keyring SHA256을 사용한다. 임의로 받은 keyring과 그 옆의 해시를 함께 믿으면 공급자 확인이 되지 않는다. 이 검사는 **과거 특정 패키지의 진위 확인**이며 최신 업데이트 목록임을 주장하지 않는다. 고정 release/suite와 패키지 revision을 요구하지만 역사 자료의 만료 시각을 현재 업데이트 저장소처럼 검사하지 않는다.

```sh
python3 -B prepare.py \
  --inrelease /approved/sudo-input/InRelease \
  --packages-xz /approved/sudo-input/Packages.xz \
  --deb /approved/sudo-input/sudo_1.8.31-1ubuntu1_amd64.deb \
  --keyring /usr/share/keyrings/ubuntu-archive-keyring.gpg \
  --keyring-sha256 <independently-verified-keyring-sha256> \
  --output /approved/new-sudo-build-context
```

검증에 실패하면 빌드 context를 만들지 않는다. 성공한 새 디렉터리에 `sudo.deb`, `preparation.json`, Dockerfile, 무해 검사기와 출처 기록만 복사한다. stdout의 `deb_sha256`, `preparation_sha256`을 보존한다. `gpgv`가 없거나 서명이 틀리면 중단하며 설치나 검증 우회를 하지 않는다.

이미지 준비 담당자는 고정 base를 확보하고 이미지 digest/config ID를 검증한다. 준비 Linux Docker 환경에서만 아래 빌드를 수행한다. base가 없으면 먼저 승인된 반입 절차를 완료한다. `--pull=false`만으로 누락 base 반입을 차단한다고 가정하지 않는다.

```sh
docker image inspect ubuntu@sha256:c664f8f86ed5a386b0a340d981b8f81714e21a8b9c73f658c4bea56aa179d54a
docker build --network=none --pull=false \
  --build-arg SUDO_DEB_SHA256=<verified-deb-sha256> \
  --build-arg PREPARATION_SHA256=<verified-preparation-json-sha256> \
  --tag groot-labs/sudo:1.8.31-1ubuntu1 /approved/new-sudo-build-context
```

Dockerfile은 deb·준비 증거 해시를 다시 검사한 다음 컨테이너 이미지 안에서만 `dpkg -i`를 수행한다. 의존 패키지가 없으면 실패하며 `apt`로 임의 보충하지 않는다. 이 경우 필요한 동일 배포판 의존 패키지를 별도 서명/해시 검토한 뒤 준비 절차를 확장해야 한다. 호스트에 이 deb를 설치하지 않는다. 빌드 결과 전체 image ID, 준비 증거, 이미지 아카이브 해시를 기록하고 실습 rootless daemon의 별도 이미지 저장소로 검증해 반입한다. 시스템 Docker의 이미지가 rootless 저장소에 자동 공유되지는 않는다.

## 별도 rootless 런타임 선행조건

이 CLI는 런타임을 설치하거나 계정·AppArmor·sysctl·systemd·subuid/subgid를 변경하지 않는다. 다른 환경에서 별도로 확인해야 할 최소 범위는 다음과 같다. 현재 C는 이 조건을 준비했으며 새로운 일반 VM에서의 자동 설치를 검증한 것은 아니다.

1. 전용 비관리 사용자와 서로 겹치지 않는 subordinate UID/GID 범위. 기존 `groot_c` 범위를 다른 계정에 재사용하지 않는다.
2. 현재 Docker 배포와 호환되는 rootless 구성요소(`dockerd-rootless.sh`, `rootlesskit`) 및 `uidmap`의 `newuidmap`/`newgidmap`. 선택한 rootless 네트워크 driver 도구와 사용자 systemd/DBus 의존성도 실제 설치 목록으로 확인한다. `dbus-user-session` 등이 없을 때만 승인된 서버 반입 범위에 포함한다.
3. Ubuntu 24.04의 user namespace 제한을 충족하는 **해당 rootlesskit 실행 파일의 AppArmor 허용 구성**. 시스템 전체의 AppArmor/user namespace 보호를 끄지 않는다.
4. user systemd 서비스 및 cgroup v2에서 CPU·memory·pids controller 위임. CLI는 Docker 선언뿐 아니라 실행 프로세스의 `cpu.max`, `memory.max`, `memory.swap.max`, `pids.max`도 읽어 확인한다. 실제 제한을 읽거나 확인할 수 없으면 준비 완료로 처리하지 않는다.

공식 근거: [rootless 선행조건](https://docs.docker.com/engine/security/rootless/), [자원 제한](https://docs.docker.com/engine/security/rootless/tips/#limiting-resources), [Ubuntu 24.04 및 rootless 제약](https://docs.docker.com/engine/security/rootless/troubleshoot/).

`no-new-privileges`는 setuid를 막으므로 이 **분리된** 런타임에서만 false를 요구한다. capability는 user namespace 내부 `SETUID`·`SETGID`만 허용하고 나머지를 제거한다. 컨테이너는 일반 사용자 UID 1000으로 시작하며 네트워크 none, 포트 없음, 호스트 bind/device/socket 없음, read-only rootfs, 제한된 tmpfs, CPU 0.5·메모리 256MiB·PID 64로 제한한다. host 초기 user namespace에서 읽은 모든 UID/GID 매핑 행에 host ID 0이 없어야 하며, 컨테이너 UID/GID 0의 매핑은 전용 계정 1991과 정확히 같아야 한다. 실제 Seccomp mode 2, CapBnd `0xc0`, 전체 CID와 정확히 일치하는 `docker-<CID>.scope` 및 자원 제한도 검사한다. 기존 웹 실습의 no-new-privileges와 broker 계약은 그대로 유지한다. [Linux의 no_new_privs 동작](https://docs.kernel.org/userspace-api/no_new_privs.html)

## 현재 C의 전용 설치와 한계

- `uidmap`·`libsubid4`: `1:4.13+dfsg1-4ubuntu3.2`. Docker 공식 `docker-ce-rootless-extras` `29.8.1`은 deb 전체를 설치하지 않고 검증된 실행 파일 3개만 `/opt/capstone-sudo-rootless/29.8.1/bin/`에 배치했다. rootless daemon은 기존 `/usr/local/bin/dockerd`를 사용한다.
- 계정은 비밀번호 잠금·`/usr/sbin/nologin`, 홈 `/var/lib/capstone-sudo-runtime` 0700, subuid/subgid `231072:65536`이다. SSH·일반 sudo·시스템 Docker 그룹 권한을 추가하지 않았다. rootless socket은 `/run/user/1991/docker.sock`, data root와 VFS 이미지 저장소는 전용 홈 아래다.
- rootless network driver와 port driver 모두 `none`, detached network namespace는 false다. slirp4netns나 추가 네트워크 도구를 설치하지 않았다. 전용 user unit `capstone-sudo-docker.service`와 `user@1991.service`의 CPU·memory·pids 위임을 사용한다.
- Ubuntu의 전역 제한을 유지하면서 정확한 rootlesskit 경로에만 `userns` 허용 프로필을 추가했다. 이 프로필 자체는 `unconfined`이며 별도 파일 접근 샌드박스가 아니다. **실습 컨테이너도 `apparmor=unconfined`이므로 컨테이너 AppArmor 프로필 격리는 없다.** rootless UID 분리·builtin seccomp·최소 capability·네트워크/자원 제한은 계속 적용한다.
- Docker 29.8.1 rootless의 AppArmor 관리 인터페이스 오인식을 막기 위해 **전용 `user@1991.service`의 mount namespace에서만** `InaccessiblePaths=/sys/kernel/security`를 적용했다. 해당 프로세스의 securityfs 접근을 줄이는 설정이며 호스트 AppArmor를 끄지 않는다. 실제 호스트 securityfs 접근, 전역 sysctl 및 시스템 Docker unit이 유지됨을 대조했다. [Docker 29.8.1에 포함된 HostSupports 조건](https://github.com/moby/moby/blob/docker-v29.8.1/vendor/github.com/containerd/containerd/v2/pkg/apparmor/apparmor_linux.go), [Docker rootless 제한](https://docs.docker.com/engine/security/rootless/troubleshoot/)

최종 설정 템플릿과 실제 사용 설치·검증 소스는 [`runtime/`](runtime/)에 보존한다. `history/`는 C 고정 경로·UID·과거 해시에 의존하는 일회성 실행 기록이므로 현재 서버에 재실행하지 않는다. 공식 다운로드 출처와 SHA는 `runtime/provenance.json`, 파일별 SHA는 `runtime/source-sha256.json`에 있다.

## 고정 CLI

관리자가 이미지 빌드/반입 증거를 확인한 다음 `config.example.json`의 모든 대체값을 실제 값으로 채워 `/etc/capstone-sudo-lab/config.json`에 `root:root`, 0644로 설치한다. 상위 디렉터리도 root 소유이며 group/world 쓰기를 금지한다. 예시의 UID 0과 대체 문자열은 의도적으로 거부된다. 실행 소스도 root가 검토한 경로에 두며 일반 실습 사용자가 수정하지 못하게 한다.

계정이 nologin이므로 관리자가 아래처럼 고정 CLI를 **전용 비root 계정으로** 실행한다. 예시는 기존 관리자 권한의 root 셸에서 실행하며 새 sudo 권한을 부여하는 설정이 아니다. 마지막 `verify`만 `check`, `up`, `status`, `stop` 중 하나로 바꿀 수 있다. CLI는 자신의 `/run/user/1991/docker.sock`만 사용하고 Docker context/DOCKER_HOST를 무시한다.

```sh
runuser -u capstone-sudo -- env -i \
  PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  HOME=/var/lib/capstone-sudo-runtime \
  XDG_RUNTIME_DIR=/run/user/1991 \
  DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1991/bus \
  LANG=C LC_ALL=C PYTHONDONTWRITEBYTECODE=1 \
  /usr/bin/python3 -B /opt/capstone-offline-labs/nonweb/sudo/lab.py verify
```

- `check`: 설정·이미지·런타임 선언만 확인. 컨테이너를 생성하지 않으며 `environment_ready=false`다.
- `up`: 없으면 고정 컨테이너를 생성한다. 실행 중이면 동일 CID를 유지한다. 정지된 관리 컨테이너는 full CID·receipt·전체 계약과 PID 0을 확인하고 이력을 남긴 뒤 `docker rm`(force 없음)으로 제거하여 고정 이미지에서 새로 만든다. 따라서 `stop → up`은 새 CID다. 실제 host `/proc`에서 전체 CID cgroup·PID·UID/GID mapping·자원 제한을 확인하고 무해 검사 실행. 검증 실패 시 해당 CID를 중지한다.
- `verify`: 실행 중 컨테이너의 같은 검증 수행. 성공 시에만 `environment_ready=true`, `verification=environment_only`다.
- `status`: 상태 조회만 하며 새 버전 검증으로 간주하지 않는다.
- `stop`: 검증된 소유권의 컨테이너만 중지. 자원 controller 위임 문제나 이미지 삭제 때문에 중지 자체가 막히지 않도록 해당 준비 검사는 생략한다. rootless·컨테이너 소유권/보호 설정 검사는 유지한다.

개인 관리 receipt는 passwd에 등록된 홈의 `.local/state/capstone-sudo-lab/runtime.json`이다. 이름이 같아도 receipt가 없는 컨테이너를 인수하지 않는다. receipt를 쓰기 전에 생성만 성공한 경우에도 중지 상태의 미관리 충돌로 남겨 검토하게 한다. 임의 삭제·초기화·shell·추가 command 인자 기능은 없다. `up`의 정지 컨테이너 교체만 허용하며 과거 CID·이미지·시각은 같은 state 디렉터리의 `retired-<CID>.json`에 남긴다. 삭제 실패나 중간 중단으로 이력/receipt가 어긋나면 임의 인수하지 않고 관리자의 검토를 요구한다. Docker stderr와 내부 `/proc` 내용은 외부 JSON에 노출하지 않는다.

## 웹의 읽기 전용 상태

CLI는 root 관리 웹 receipt를 직접 쓰지 않는다. root publisher가 검토한 CLI·고정 config로 `verify`를 실행한 결과와 전체 CID/이미지를 확인하고 다음 최소 schema로 변환한다. 다른 사용자가 생성한 임의 JSON이나 `status` 출력만으로 `ready`를 게시하면 안 된다.

```json
{
  "schema": 1,
  "checked_at": 1792670400,
  "expires_at": 1792670460,
  "labs": {"CVE-2021-3156": {"status": "needs_setup"}}
}
```

시각은 schema 설명용 예시다. 실제 `capstone-sudo-status.service`/`.timer`는 **60초마다 TTL 300초**의 receipt를 갱신한다. 2026-10-23 KST에 정식 unit의 `ready → CLI stop 후 needs_setup → 새 CID up 후 ready` 전환과 timer enabled/active를 실측했다. root publisher는 고정 verify만 전용 계정으로 실행하고 full CID/이미지를 다시 조회한 뒤 root의 초기 host `/proc`에서 UID/GID·seccomp·capability·cgroup을 재검증한다. 시작·중지·임의 명령 인자나 일반 Docker 권한을 웹/LLM에 제공하지 않는다.

출력은 root 소유 임시 파일에 받고 `runuser` **이후** 고정 `prlimit --fsize=131072:131072 --`로 파일 크기를 제한한다. 자식 soft/hard 한도 131072 bytes를 네이티브에서 확인했다. 새 receipt는 root:root 0600으로 fsync 후 원자 교체한다. 기존 receipt에 다른 CVE가 있으면 덮어쓰거나 TTL을 연장하지 않고 거절하므로 다중 publisher는 별도 집계 설계가 필요하다. 경로는 `/var/lib/capstone-offline-labs/nonweb-status.json`, root:root 0600, root 소유 상위 디렉터리, symlink/hardlink 금지다. rootless 미준비·확인 불가·중지 상태에서는 `needs_setup`, 유효한 환경 검증 성공 때만 `ready`, 검증 오류는 `error`로 나타낸다. 웹은 누락·만료를 미준비로 취급한다. 비웹 카탈로그는 `type=local-cli`이고 포트·웹 URL·실행 command를 받지 않는다.

`ready`여도 **취약 패키지와 격리 환경 확인**이라는 뜻이다. `attack_tested=false`, `host_scenario_verified=false`는 항상 유지한다. rootless 컨테이너 안에서 auditd를 설치하는 것만으로 호스트 kernel 감사 수집이 구성되지 않는다. audit 제어를 위해 host PID/user namespace·AUDIT_CONTROL·privileged 권한을 부여하지 않는다. C agent 002의 호스트 패키지 인벤토리도 이 컨테이너의 sudo를 호스트 sudo로 취급하지 않는다. 원래 호스트 권한 상승→auditd→Wazuh 시나리오는 별도 VM에서의 검증으로 남는다.

## 회귀 및 정리

```sh
python3 -B -m unittest discover -s infra/groot-c/offline-labs/nonweb/sudo -p 'test_*.py' -v
sh -n infra/groot-c/offline-labs/nonweb/sudo/check.sh
```

로컬 모의 회귀는 rootless/UID/cgroup/host mount·port 거절, 출처/이미지 불일치, 미관리 컨테이너 거부, up 검사 실패 시 정확 CID 중지, 패키지 서명 실패와 hash chain/버전 변조 거부를 확인한다. 실제 서명 검증·이미지 빌드·Linux rootless 실행·CVE 재현 성공의 증거를 대신하지 않는다. 초기 소스 작성 이후 공식 패키지를 Mac 작업별 임시 디렉터리로 내려받아 C에서 서명 검증·설치·빌드했다. Mac 전역 도구 설치는 하지 않았다. 모의 테스트 임시 디렉터리는 자동 제거한다. 작업용 다운로드·deb·반입 압축·build context는 최종 정리 대상이며, 운영 복구용 `/var/lib/capstone-offline-labs/offline-sudo-20261022/`의 이미지 tar·`images.json`·`SHA256SUMS`, rootless 배포 실행 파일·설정 및 작은 JSON 검증 증거는 보존한다.


현재 rootless 이미지 ID는 `sha256:90fd1384894d26e34c2364b0ff8fb8bdb92a3e9ebc3df5dee29a61b68bfcab2a`이며, 시스템 Docker의 OCI manifest ID `sha256:3a7816fe014c0a9e33b36b869dcd65b0e9662cb51f78271254b396502dd53ab7`와는 저장소 식별 형식이 다르다. 아카이브 안의 manifest→config 해시 연결을 검증해 같은 내용임을 확인했다. 최종 소스·설정 SHA와 공개 출처 및 작은 실행 증거는 `runtime/`에 보존하며, 이미지 tar나 deb 바이너리는 Git 소스에 넣지 않는다.


2026-10-23 C 정리 결과: 작업용 23파일(53,975,344 bytes)과 sudo assets/context·rootless artifacts 디렉터리 3개를 제거했다. `preparation.json`, 다운로드 출처 JSON과 실제 빌드 소스·로그는 작은 텍스트 증거로 보존했다. 운영 이미지 tar(28,681,728 bytes)의 SHA256 `db6a201143ad6372d24c91fed6e04f58206abad535941d39e6f5ad2ac79c5389`는 정리 전후 동일했고 runtime 계정·data·units·소스 및 유효한 ready receipt도 유지됐다. 상세 삭제 경로·해시는 [`runtime/cleanup-20261023.json`](runtime/cleanup-20261023.json)에 있다. 공유 서버 stage 디렉터리와 Mac 작업 임시 디렉터리의 최종 정리는 전체 작업 담당자가 별도로 수행한다.
