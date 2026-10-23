# 초기 설치용 sudo rootless bootstrap

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../../../STATUS.md) · [실행 계획](../../../../../../PLAN.md).
> 현재 콘솔은 HTTP3개(Log4Shell/Apache2종)와 터미널3개(Redis/Samba/sudo), 총6항목이다. sudo는 별도 rootless의 UID1000·전역 단일 세션이며 종료 시 전체 중지한다. DVWA는 독립 유지한다. 환경 준비와 CVE 악용 성공을 구분하고 공격 재현은 보류한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

`bootstrap.py`는 Ubuntu 24.04 amd64의 **새 전용 환경**에 고정 sudo 실습 프로파일을 설치한다. 기존 `history/` 스크립트를 실행하지 않는다. 현재 C의 수동 설치는 별도 완료 환경이며 이 helper의 관리 manifest가 없으므로 재적용을 거부한다. 코드·모의 회귀를 준비했으며 **이 helper로 새 VM 전체 설치를 실제 검증한 상태는 아니다.** 기존 C의 성공 증거를 새 설치기의 성공 증거로 바꾸어 해석하지 않는다.

```sh
python3 -B /opt/capstone/releases/<release>/infra/groot-c/offline-labs/nonweb/sudo/runtime/bootstrap.py \
  --check --bundle /opt/capstone-prereqs/sudo
# 초기 설치 controller가 관리자 권한으로 --apply, 이후 --verify를 호출한다.
```

- `--check`: root 소유 소스·번들, 서명과 고정 SHA, OCI 이미지, 호스트 전제조건과 경로·UID 충돌을 검사한다. signature/extras 검사용 임시 파일은 자동 제거한다. 계정·컨테이너·서비스·영속 설치 경로를 만들지 않는다. 성공은 `prerequisites_ready`, `environment_ready=false`다.
- `--apply`: 검사를 다시 통과한 뒤 전용 계정·rootless 구성·고정 CLI·publisher를 설치하고 실제 `up`/fresh `verify`와 root 재검증, timer/receipt 검증을 수행한다. 완료 manifest가 있으면 **verify만** 수행한다. 업그레이드·외부 설치 인수·부분 설치 재개 도구가 아니다.
- `--verify`: 관리 manifest·소스/설정 SHA·UID/GID·rootless/seccomp/cgroup·고정 버전 검사·publisher/timer·fresh receipt를 검사한다. 시작·중지·재설치하지 않는다.

표준 출력은 JSON 한 개다. 성공 rc0, 실패 rc1과 `status=needs_setup`, 고정 오류 코드를 반환한다. 원격 명령 stderr·자격 값은 출력하지 않는다. 중간 실패는 `/var/lib/capstone-sudo-bootstrap/manifest.json`의 `preparing` 또는 `verification_failed` 상태로 남겨 수동 검토하게 한다. 관리하지 않는 동명 계정·UID/GID·경로·unit을 제거하거나 인수하지 않는다.

## 선행 OS 패키지와 권한

초기 controller의 OS 패키지 단계가 `uidmap`, `libsubid4` **1:4.13+dfsg1-4ubuntu3.2**, `dbus-user-session`, gpgv·dpkg 도구, systemd, AppArmor 4 ABI, ip·nsenter·prlimit 등을 먼저 준비해야 한다. 이 helper는 apt/dpkg 설치를 실행하지 않는다. 기존 root 소유 Docker CLI와 dockerd 및 rootful daemon **29.8.1**을 요구한다. 실행 파일은 `/usr/local/bin` 또는 `/usr/bin`의 검증된 경로에서 선택한다. Python 3 stdlib만 사용한다.

systemd가 PID1이어야 하며 cgroup v2 CPU·memory·pids controller, 초기 host UID/GID namespace, `unprivileged_userns_clone=1`, `apparmor_restrict_unprivileged_userns=1`을 요구한다. 정확히 다음 전용 자원을 예약하며 충돌하면 재할당하지 않는다.

- 사용자/그룹 `capstone-sudo`, UID/GID 1991, 잠긴 비밀번호, nologin, 홈 `/var/lib/capstone-sudo-runtime` 0700.
- subuid/subgid `231072:65536`; 기존 다른 계정 범위와 겹치면 실패.
- `/opt/capstone-sudo-rootless/29.8.1/bin`, `/etc/capstone-sudo-lab`, `/opt/capstone-offline-labs/nonweb/sudo`.
- 전용 rootless user unit 및 UID1991의 delegate/securityfs drop-in, 해당 rootlesskit 경로의 AppArmor userns 프로필, `capstone-sudo-status.service/.timer`.

호스트 sudo revision·시스템 Docker 설정/컨테이너·전역 AppArmor/sysctl은 설치 전후 대조하고 변경하지 않는다. 시스템 Docker의 Compose/네트워크에는 sudo를 추가하지 않는다. 전용 rootless socket, VFS 저장소, network/port driver none, 비활성 detached netns를 사용한다. 실습 컨테이너는 별도 AppArmor 프로필 격리가 없으며 builtin seccomp·UID 분리·최소 capability·자원 제한을 계속 검증한다. securityfs 제한은 전용 user@1991 mount namespace에만 적용한다.

## `/opt/capstone-prereqs/sudo` 번들

디렉터리와 모든 상위 경로는 root 소유, group/world 쓰기 금지다. 파일은 root 소유 regular file, 단일 hardlink, symlink 금지다. 아래 파일 외의 항목은 거부한다.

| 이름 | 신뢰 기준 |
|---|---|
| `manifest.json` | 아래 exact schema와 파일 집합; 이 파일의 해시만으로 원본을 신뢰하지 않음 |
| `sudo-image.tar` | 승인된 운영 OCI save archive, SHA256 `db6a201143ad6372d24c91fed6e04f58206abad535941d39e6f5ad2ac79c5389`, 28,681,728 bytes |
| `preparation.json` | SHA256 `8c69d341e14798ec161d093031f0ae54473d7d089166c3eedba6bbda0ce042ff`, 973 bytes |
| `sudo.deb` | Ubuntu focal `1.8.31-1ubuntu1`, SHA256 `de4106cd19a5b9f8acac9e0ab5f40f218d3ac321cc58143e051baab064a5fb36` |
| `sudo.InRelease`, `sudo.Packages.xz` | 고정 preparation의 해시와 대조 후 Ubuntu 서명→Packages→정확 deb record 검증 |
| `ubuntu-archive-keyring.gpg` | 검토된 keyring SHA256 `80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31` |
| `docker.asc`, `docker.InRelease`, `docker.Packages.gz` | 고정 SHA 및 Docker 공개키 fingerprint `9DC858229FC7DD38854AE2D88D81803C0EBFCD88`, 저장소 서명→Packages 검증 |
| `docker-ce-rootless-extras_29.8.1-1~ubuntu.24.04~noble_amd64.deb` | SHA256 `02897501837b7ff4fec8248decdd5828b7d40d7f591021a91f29673e02d0f982`, 10,177,712 bytes |

```json
{
  "schema": 1,
  "profile": "ubuntu24.04-amd64-sudo-rootless-29.8.1-v1",
  "files": {
    "sudo-image.tar": {
      "sha256": "db6a201143ad6372d24c91fed6e04f58206abad535941d39e6f5ad2ac79c5389",
      "size": 28681728
    }
  }
}
```

위 JSON은 형태 설명용이다. 실제 `files`에는 표의 **manifest 자체를 제외한 10파일**이 모두 있어야 한다. 운영자에게 전달된 승인된 파일로만 전체 manifest를 만든다. 임의 파일로 새 해시를 계산해 manifest에 넣어도 소스의 검토된 pin과 달라 거부된다. 정확한 추가 SHA/크기는 `bootstrap.py`의 `PINS`, 기존 공개 출처는 `provenance.json`에 있다.

고정 archive는 저장소 소스에 포함하지 않는다. 2026-10-23에 C의 `/var/lib/capstone-offline-labs/offline-sudo-20261022/bootstrap-bundle`에 **10개 입력+manifest 전체**를 root0700 디렉터리/root0600 파일로 보존했다. 앞선 임시 반입물 정리 후, 아직 Mac 작업 temp에 남아 있던 원본 7개의 고정 SHA를 재확인하여 기존 운영 archive·preparation·keyring과 합쳤다. 이 위치는 재배포에 필요한 관리 운영 아티팩트이므로 임시 패키지 정리 대상에서 제외한다. 새 VM에는 관리자가 별도 승인된 반입 경로로 `/opt/capstone-prereqs/sudo`에 복사한다(하드링크·심볼릭링크 사용 금지).

위 보관처를 사용할 수 없다면 공식 출처 또는 검증된 오프라인 보관처에서 다시 반입하고 같은 고정 해시를 만족해야 한다. URL의 현재 내용이 바뀌었거나 이 고정 artifact를 확보할 수 없으면 설치를 중단한다. arbitrary tag/latest나 다른 이미지를 자동 선택하지 않는다.

이 서명 검사는 **검토된 과거 artifact의 진위**를 검사한다. 과거 InRelease를 현재 최신 업데이트 인덱스라고 주장하지 않으며, 일반 OS 패키지의 최신성/의존성 검증은 앞선 패키지 준비 단계의 책임이다. 이미지의 OCI manifest/config/layer 해시를 확인하고 rootless에 load한 뒤 실제 rootfs diff IDs를 대조한다. Docker extras는 deb 전체를 설치하지 않고 해시가 고정된 rootlesskit 3.1.0 및 shell helper 2개만 추출한다.

## 상태·복구·검증 범위

관리 manifest는 `/var/lib/capstone-sudo-bootstrap/manifest.json` root0600이다. 보호 상태 before snapshot, preparation·서명 결과·bundle manifest와 운영 복구용 `recovery/sudo-image.tar`/`SHA256SUMS`를 보존한다. 준비 bundle을 정리할 때 운영 복구 archive와 전용 runtime data를 삭제하지 않는다. 소스가 달라진 재적용은 자동 업그레이드하지 않고 `managed_source_changed`로 중단한다.

publisher는 고정 verify와 root 재검증만 수행한다. 웹/LLM에 일반 sudo·Docker 권한이나 임의 명령 API를 주지 않는다. `ready`는 취약 패키지와 격리 환경 확인이며 `attack_tested=false`, `host_scenario_verified=false`를 유지한다. host auditd→Wazuh 권한상승 시나리오를 완료했다고 표시하지 않는다.

```sh
python3 -B -m unittest discover \
  -s infra/groot-c/offline-labs/nonweb/sudo/runtime -p test_bootstrap.py
```

27개 모의 검사는 manifest/pin 변경, 소유권·hardlink·symlink, UID/subid 충돌, OCI 변조, umask077의 새 부모 권한, 외부/부분 설치 거부, check의 설치 미실행, 기존 완료 apply의 verify-only 동작, 완료 전 보호 상태 변동 및 최종 검증 실패를 확인한다.

별도로 C에서 번들의 `read_bundle`→Ubuntu/Docker gpgv 서명→Packages/deb→OCI 5개 layer/config→고정 extras 바이너리 3개 검증을 실제 수행했다. 증거는 [`bootstrap-bundle-verification-20261023.json`](bootstrap-bundle-verification-20261023.json)이며, 서버 원본은 복구 디렉터리의 `bootstrap-bundle-verification.json`, 사용 소스는 `bootstrap-verifier/`에 보존했다. 이 정적 검증은 기존 C 계정·runtime·컨테이너·host sudo·서비스를 변경하지 않았다. **새 VM의 `--apply`·패키지 설치·systemd·rootless 전체 실행을 대신하지 않는다.**
