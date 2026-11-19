# 소스·캐시·소비자 조정 실행기

<!-- coordinator-collection-reference-20261120 -->
<a id="coordinator-collection-reference-20261120"></a>
## 고정 root 진입점의 격리 통합과 수집 결과 보존

B의 기존 PID1·SSH·별도 Docker 기반을 확장해 A7/B36/C7의50소스와 합성 캐시를 실제 고정 경로에 배치했다. 운영 소스는 관리자231 경유로 읽은65경로의 SHA·메타데이터에 결속하며 B의 누락된 기준 소스는 B 안에서만 읽었다. 운영 설정·자격·대화 DB·원시 journal은 반입하지 않았다. 소비자·승인·계정·키·이미지와 캐시는 시험용이다.

부분 적용 시험은 같은 실행기 자식의 renameat/renameat2 종료를 ptrace로 관측했다. 두 승인 대상의 실제 after SHA와 applying/pending apply를 확인한 뒤 그 자식만 SIGKILL했다. 실행기·backend를 패치하지 않았으며 독립 복구 뒤 원본50소스/캐시와 원래 활성 소비자·동일 Docker CID/이미지를 대조했다. 이는 프로세스 유실 시험이며 전원 유실·호스트 재부팅 시험은 남아 있다.

기한 시험은 apply/verify 뒤 독립 원복을, 정상 시험은 A/C 뒤 B의 소스 확정과 재개를 확인했다. collection/MCP/Hermes/Ollama의 실제 인수 근거 없이 completion_prepare를 요청했다. 세 역할 모두 operator_acceptance_required로 거절됐다. 정리/current의 Native 성공과 실제 운영 인수는 별도 조건이다.

정상 종료한 oneshot이 systemd에서 정리되면서 ConditionResult=no·실행 시각0이 됐다. 수집 검증 실패는 이 현상과 연결됐다. 같은 _UnitReference로 실행 유닛의 RefUnit을 유지하자 세 번의 속성 조회에서 실행 시각·조건 결과가 유지됐고 해제 뒤 정리됐다. 조건 불충족 유닛은 참조 중에도 실행0/no였다. 후보 Native는 두 고정 수집 유닛만 참조하며 기존 조건·종료값·새 실행 시각 기준을 유지한다. 연결 실패나 중첩 획득 실패·본문/해제 예외에서도 연결을 닫고 임의 fallback을 하지 않는다. [systemd Manager의 RefUnit 계약](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html)을 따른다.

같은 운영 후보32소스로 Mac·Linux가 각각15군258검사·생략0을 통과했다. Linux는 별도 PID1의 UID/GID50123·보조 그룹0에서 실행했다. 수집 서비스 검사는22→28이며 별도 상태 관측8검사·AST6파일·부정 CLI3조건을 확인했다. 공식 Harness²의80구성 중2수정, 검증85→91과 정적44payload를 포함한135구성의 상시16,917자 증가0을 대조했다. 구조 통과는 실행·SOC 정확도·운영 인수를 뜻하지 않는다.

검증은 기존 Python·dbus-daemon·libsystemd를 사용했다. 외부 송신 없는 별도 namespace와1GiB·Tasks384·CPU100%를 유지하며 일반 경로는180초다. 비특권 Linux 회귀의 자식210초·관측220초·프로브250초와 bootstrap 전체300초를 구분한다. 기존90초 회귀 제한 실패와 원문 로그를 남기지 못한 한계도 보존했다. 시험 종료 뒤 빈 역할 cgroup·호스트 namespace 유지·52입력 SHA 동일과 자체 작업 폴더 제거를 확인한다. 관측이 running이면 같은 실행만 다시 읽고 새 실행으로 대체하지 않는다.

재현에는 고정42소스와 두 manifest, 검증 기반·full-input.json을 합한52입력이 필요하다. full-input은 schema/source_commit/live_metadata/known_before/after/after_provenance/backend_probe_sha256/scope를 포함한다. live_metadata는 각 고정 경로의 exists/SHA/bytes/uid/gid/mode이며 A/C 기준은 같은 SHA의 확보 소스, B 누락 기준은 B 내부의 고정 경로 읽기만 허용한다. after44파일은 지정 commit의 원본과 unit 생성기로 만들고 reader3·MCP launcher1·무결성 영수증2는 시험 안에서 정확한 전후 SHA에 결속해 생성한다. 자격/키/운영 설정을 입력에 섞지 않는다. 실제 반입 manifest·case별 해시와 결과 원문은 로컬 전용이다.

```sh
# 승인된 Linux B에서52입력이 있는 별도 작업 디렉터리의 검증기를 사용한다.
python3 -IB validate_full_native.py --start-owned --case bootstrap
python3 -IB validate_full_native.py --collect-owned /run/capstone-pid1-<출력된 고유값>
# partial / deadline / confirmed도 각각 고유 작업으로 실행하고 terminal 수집 뒤 정리한다.
```

backup75는 성공이나 자동 재시도 권한이 아니다. 잠금·현재 단계·durable intent와 같은 요청의 결과를 대조하는 계약은 남았다. 실제 호스트 재부팅·장기 복구·Native 정리/current·새 OS 설치·운영 payload 정확 승인·현재 소스/모델/MCP 스키마/권한 대조와 새 실제 MCP/두 봇 인수도 남아 있다. 아래252검사와 초기 backend 기록은 당시 근거로 보존한다.

[실행·출처·실패·제한 원장](private-full-native.validation.json)
<!-- /coordinator-collection-reference-20261120 -->

<!-- coordinator-private-backends-20261119 -->
<a id="coordinator-private-backends-20261119"></a>
## 실제 SSH·Docker backend 연결

11/19 기존 PID1 기반 검증기를 그대로 재사용해 A6/B17/C4의27유닛을 기본 Native로 읽었다. 유닛 이름과 실제 systemd 속성을 사용하지만 소비자 프로그램은 sleep·타이머의 합성 입력이다. 운영 서비스나50소스 전체를 실행한 결과로 표시하지 않는다.

시험 안에서 새 Ed25519 키와 고정 known_hosts를 만들었다. A→B/C와 B→A/C의4경로에서 실제 SSH 공개키 인증과 원격 UID50123·역할·machine-id 지문을 대조했다. B 클라이언트는 UID50124로 실행했다. A→B에 C의 호스트 키를 넣으면 거절되며 C에는 클라이언트 키를 두지 않는다. 운영 키를 복사하거나 StrictHostKeyChecking을 끄지 않았다. 이 응답은 시험용 신원 응답이며 운영 reader 프로토콜과 Context.peers 검증은 남는다.

B의 user namespace가 소유하는 별도 network namespace를 만들고 시험 전용 veth로 외부 연결이 없는 상위 시험 네트워크에 붙였다. Docker의 host PID/network 옵션은 이 B 역할 안의 공간만 공유한다. 운영 호스트의 PID·네트워크·Docker 소켓은 연결하지 않는다. /proc·/sys의 기존 마스크를 읽기 전용으로 보존하고 noexec인 이미지 저장소에서는 기존 BusyBox 실행 파일을 읽기 전용으로 연결해 사용한다.

실제 별도 Docker 데몬에 새 이미지를 반입해 만든 컨테이너에서 Native의 정지·재개를 확인했다. 정책 no·running=false·PID0에서 같은 CID/이미지의 새 PID·unless-stopped로 돌아왔다. 실제 로드된 메모리64MiB·pids16·비특권·NoNewPrivileges와 세 마운트의 읽기 전용 속성도 확인했다. 실제 Hermes 이미지와 격리 설정의 동등성을 검증한 것은 아니다.

최종12:19:01 KST 실행은 외부512MiB/Tasks256/CPU100%/최대75초 제한에서 메모리 최대94,498,816바이트·pids.peak67·OOM0이었다.9회 자체 시험의 유닛·작업/입력 폴더·cgroup 부재를12:20:45 KST에 별도로 읽었다. Mac에 패키지를 설치하거나 대형 운영 이미지를 반출하지 않았다.

검증기와 기존42소스·두 manifest, PID1 기반 검증기·probe를 같은 디렉터리에 둔다. 기존 도구가 있는 승인된 Linux 점검 호스트의 root가 명시적으로 실행한다.

```sh
python3 -IB infra/validation/journal-composition/validate_private_backends.py --run-owned-units
```

공식 Harness²는 기존 고정 후보를 복원한 뒤 새 소스3개를 검사한다.82→85구성·기존 수정0·상시16,917자 증가0이며 모델 품질 점수는 아니다.

```sh
python3 -B infra/validation/journal-composition/reproduce_limits.py --repo . --output /private/tmp/soc-private-backends
python3 -B infra/validation/journal-composition/check_private_backends_structure.py --repo . --restored-root /private/tmp/soc-private-backends/candidate --output /private/tmp/soc-private-backends/backends-harness2.json
```

고정 root 실행기·독립 Lifecycle.recover·실제50소스와 캐시·전역 복구·원래 소비자 재개·정리/current·실제 호스트 재부팅은 다음 통합 단계다. 정확 승인·운영 적용과 새 MCP/두 봇 인수도 계속 별도로 확인한다.

[검증 원장](private-backends.validation.json) · [실행 조건과 남은 작업](COORDINATOR.md#coordinator-private-backends-20261119).
<!-- /coordinator-private-backends-20261119 -->

소스와 캐시를 함께 전환하고 원래 소비자를 재개한 뒤 임시 장치를 정리하도록 연결했다. **격리 검증을 마친 후보이며 운영 서버에는 아직 적용하지 않았다.** 운영 유닛의 정지·재개·실제 부팅·독립 복구 검증과 전체 payload의 정확 승인, MCP·두 봇 새 채팅 인수가 남았다. [소스 고정](coordinator-manifest.json) · [검증 원장](coordinator-validation.json) · [현재 상태](../../../STATUS.md).

## 공통 계약과 고정 범위

B 읽기 MCP는 Hermes 컨테이너 밖 SSH 세션에서 실행된다. 컨테이너만 정지하면 이전 코드의 MCP가 남으므로 reader의 재접속과 고정 소비자도 함께 제어한다. 보안 엔진·로그 수집·스토리지 감시·차단 만료 작업은 정지 대상에 넣지 않았다.

| 구성 | 하는 일 | 경계 |
|---|---|---|
| 파일·reader·MCP 중계 | A7/B36/C7 합50소스의 전후 SHA/소유자/권한·불변 백업·조회/재접속 차단 | 기존 shell launcher 보존·임의 파일 덮어쓰기 불허 |
| 상태·보관·계획 | 호스트 잠금·단계/nonce·정확 plan/bundle·계정/기계/CID/보호 설정 결속 | 19보조 파일·39제어 문서·고정 root 진입점 |
| 서비스·보조 unit·프로세스 | 고정 unit/CID, 전용 읽기 계정의 SSH 자식만 종료·재확인 | 일반 SSH·보안 엔진·다른 계정은 대상 밖 |
| 캐시·원자 생성 | 메타데이터 DB의 원본/새 관측 보존·덮어쓰기 없는 생성 | 사건/대화/승인 DB·원시 journal 복구 아님 |
| 정리·현재 설치 | 인수 근거·전역 정리 결정/허가·임시 중계/제어 문서 제거·현재 실물 재확인 | root 운영자 전용. 모델/MCP에 승인·배포 권한을 추가하지 않음 |

Mac에 패키지를 추가하지 않았다. 관리자231을 경유하고 기존 A/B 읽기 인증 경로를 사용하며 새 키를 복사하지 않는다. 고정 복구 unit의 권한과 서비스 중단 범위도 최종 정확 승인에 포함해야 한다.

## 단계와 복구

| 단계 | 조건과 결과 |
|---|---|
| 준비·정지 | 원본/원래 unit/CID 기록→중계/상태/독립 복구 장치 준비→새 조회 차단·소비자 유휴/정지 확인 |
| 백업·적용 | 전 호스트의 소스·캐시·백업 근거 일치 후 핵심 소스 변경 |
| 검증·소스 확정 | 새 수집/로드 자원 제한·캐시 정책 확인. A·C 뒤 B를 마지막으로 소스 확정 |
| 재개 | 일치하는 새 전역 근거가 있어야 원래 활성 서비스만 재개 |
| 확정 전 원복 | 원본 소스/캐시 복구와 완료 기록 확인 후 기존 수집 재개 |
| 확정 후 원복 | 독자 원복 불허. 별도 정확 승인·새 전역 정지 근거·공통 원복 결정 필요 |
| 인수·정리 | 실제 collection/MCP/Hermes/Ollama 근거의 SHA와 운영자 인수 기록→전 호스트 정리 준비→공통 결정/허가→자체 임시 장치 정리 |
| 현재 설치 조회 | 고정 current pointer·실제 소스/권한·캐시 정책·원래 활성 서비스/CID·임시 제어 부재·초기 출처 보존 대조 |

`confirmed`는 소스 확정이다. 실제 MCP·두 봇 새 채팅·의미/누락 확인까지 완료했다는 뜻으로 쓰지 않는다. 인수 파일은 root 운영자의 진술이며 합성 시험 기록은 실제 근거를 대신하지 못한다. 일부만 확정되거나 연결이 단절된 상태에서는 분산 원자성을 보장하지 않는다.

준비만 한 원복과 완료 응답 유실을 처리할 때는 최초 시작 단계를 다시 읽는다. 정리 응답이 유실됐다는 이유로 이미 재개한 정상 서비스를 다시 정지하지 않는다. 캐시 복구 뒤 새 관측도 재시도로 덮지 않는다. 소스·보호 설정·다른 current pointer가 바뀌면 임시 제어를 제거하기 전에 거절한다. 부분 정리를 재시도할 때는 이미 제거한 자체 파일을 허용하되 다른 파일을 삭제하지 않는다.

## 현재 설치와 초기 출처

실제 읽기에서 A/C에는 초기 active 기록이 있고 B에는 prepared만 있었다. B는 prepared가 있을 때만 active 부재를 허용한다. 둘 다 없거나 A/C active가 없으면 거절한다. 기존 영수증과 현재 소스의 불일치를 과거부터 정상이었던 것처럼 고치지 않는다.

기존 서버의 조정 적용을 인수한 뒤 별도 root 전용 `current-release.json`과 `/var/lib/capstone-journal-release/current.json`으로 현재 상태를 확인한다. 첫 pointer의 생성과 다음 교체는 이전 SHA에 결속하며 응답이 유실돼도 같은 결과만 재사용한다. 원래 초기 설치 검증은 별도다. 새 pointer로 이전 설치 영수증을 소급 복구하거나 전체 새 OS 설치를 증명하지 않는다. 운영 서버에는 아직 이 pointer가 없다.

## 검증 범위

| 검사 | 결과 | 해석 |
|---|---|---|
| Mac | Python3.12.5·15프로필252통과·생략0 | 실제 파일/SQLite/자식 I/O. 서비스/Docker backend는 모의 |
| Linux | 같은32소스 SHA·Python3.13.5·252통과·생략0 | UID10001·네트워크 없음·읽기 전용·capability 제거·256MiB/Tasks64·OOM0 |
| root namespace | 고정 진입 성공·잘못된 plan/진입 경로/UID/helper 거절5조건 | 합성 계정/소스/캐시의 격리 컨테이너. 실제 systemd·SSH·독립 복구 아님 |
| 공식 Harness² | 고정68688175…·78→80구성·추가2·수정14·상시16,917자 증가0 | 구조·컴파일·편집 범위. 모델 품질 점수 아님 |
| 운영 대조 | 관리자 경유 초기 출처/룰 도구/관리정책 읽기 | 운영 소스/서비스 변경0·모델/채팅/공격/학습0 |

252는 독립 보안 사건 수가 아니며 캐시42에는 기존40검사가 포함된다. 기존 읽기/판정8파일과 동결 원장을 보존했다. 시험 컨테이너·작업 폴더는 정리했고 운영 CID/시작 시각/재시작 정책은 같았다. 정확히 소유를 확인한 익명 volume1개만 제거했다. 보관된 Docker 이벤트의 한계로 과거 시험 volume 전체의 부재는 인증하지 않는다.

초기 실패도 보존했다. 실제 Docker 경로는 `/usr/local/bin/docker`였고 재현기에서 Mac 그룹/flat 경로/`Path.chown`에 관한 가정을 고쳤다. namespace 시험은 이미지의 `/opt/data` volume과 작업 경로, 비어 있는 캐시 디렉터리 누락 때문에 처음 실패했다. 자체 bind를 명시하고 디렉터리를 보존해 수정했으며 보호 검사를 완화하지 않았다.


<!-- coordinator-private-pid1-20261119 -->
## 격리 PID1 검증 기반

11/19 B의 기존 Python3.12.3과 systemd255.4-1ubuntu8.18로 세 개의 실제 PID1을 실행했다. 각 역할은 별도 계정 파일·machine-id·설정·저장소와 UID/mount/PID/UTS/IPC/cgroup 공간을 갖는다. 네트워크는 전용 공간의 loopback만 공유하며 호스트 Docker 소켓·운영 설정·자격 파일은 연결하지 않는다. 새 패키지나 큰 캐시 이미지 반출 없이 기존 실행 파일을 읽기 전용으로 사용했다.

관리자가 전용 procfs와 제한된 장치를 준비한 뒤 user namespace로 권한을 낮춘다. 읽기 전용 마운트를 그대로 넘기고 systemd에 위임한 자체 cgroup 아래에서만 자식을 관리한다. 이 순서는 [systemd 컨테이너 인터페이스](https://systemd.io/CONTAINER_INTERFACE/), [cgroup 위임](https://systemd.io/CGROUP_DELEGATION/)과 [Linux mount namespace 제약](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)을 참고했다.

| 검사 | 관측과 한계 |
|---|---|
| 실제 PID1 | 격리 역할3개에서 systemd가PID1, 서로 다른 namespace와 machine-id 확인 |
| 서비스·타이머 | PrivateDevices·PrivateTmp·ProtectSystem 등 보호 설정의 실제 서비스 exit0, 별도PID의 타이머3개 실행 |
| 기본 Native | 경로/명령 변환이나 runner 주입 없이 각 환경의 동일한 C 수집 유닛4개와 로드 자원 값 확인 |
| 자원 | 외부 유닛512MiB/Tasks256/CPU100%/최대75초, 최신 메모리 최대59,170,816바이트·pids.peak54·OOM0 |
| 소스·구조 | 기존42소스 SHA불변, 공식 Harness²80→82구성/추가2/수정0/상시16,917자 증가0 |
| 정리 | 자체5회 시험 유닛·폴더·cgroup 부재를10:43:48 KST의 별도 읽기로 확인 |

이 검사는 전체 전환·복구 시험의 기반이다. 현재 세 역할에는 동일한 C 카탈로그의 합성 서비스만 배치했다. 운영 A/B/C의 전체 소스·캐시·소비자를 실행하거나 고정 root 진입점·Lifecycle.recover·SSH/Docker를 연결한 결과로 쓰지 않는다. 실제 호스트 재부팅·운영 적용·새 MCP/두 봇 인수도 남는다. [검증 원장](private-pid1.validation.json).

실행은 기존 도구가 있는 승인된 Linux 점검 호스트에서 root로 명시한다. 새 소프트웨어 설치나 운영 배포 명령은 포함하지 않는다. 검증기와 두 manifest 및 기존42소스를 같은 디렉터리에 보관한다.

```sh
python3 -IB infra/validation/journal-composition/validate_private_pid1.py --run-owned-units
```

공식 구조 검사는 기존 고정 후보를 저장소 밖에 복원한 뒤 실행한다. 출력 경로는 아직 없어야 한다.

```sh
python3 -B infra/validation/journal-composition/reproduce_limits.py --repo . --output /private/tmp/soc-private-pid1-base
python3 -B infra/validation/journal-composition/check_private_pid1_structure.py --repo . --restored-root /private/tmp/soc-private-pid1-base/candidate --output /private/tmp/soc-private-pid1-base/private-pid1-harness2.json
```

초기 user namespace 시험은 newuidmap 부재로 실패했다. 보조 도구 설치 대신 부모가 자체 자식의 ID매핑만 설정했다. 첫 PID1 시험은 부팅 실패 뒤 chroot 밖의 진단 경로에 쓰려 해 원인을 기록하지 못했고 다음 시험에서 procfs 마운트 거절을 확인했다. 실패 보고 경로와 관리자 초기화 순서를 고쳤으며 읽기 전용·권한 격리 조건은 유지했다. 시작 응답 유실과 관측 기한을 서비스 부재로 간주하지 않고 자체 유닛의 종료를 확인한 뒤 작업 폴더를 제거한다.
<!-- coordinator-private-pid1-publication-20261119 -->
| 격리 PID1 기반 검증 게시 | 확인 값 |
|---|---|
| 내용 커밋 | `5d8ce83730b8c27386ebf7a7d50d40e00ddc9aa7` |
| 실제 원격 main 일치 | `2026-11-19T10:56:13.982331+09:00` |
| 공개 범위 | 검증기2·원장1·문서10의13파일, 운영 runtime 변경0 |
| 실제 검증 | B 안의3PID1·보호 서비스·독립 타이머·기본 Native의 동일 C4유닛 |
| 자원·정리 | 메모리 최대59,170,816바이트·pids.peak54·OOM0, 10:43:48 KST 자체5회 부재 읽기 |
| 공식 구조 | Harness²80→82구성·추가2·기존 수정0·상시16,917자 증가0 |
| 게시 전 검사 | 추적2444·위험0·기존 합성/코드10·신규0·후보13SHA·윤문012 light0.01%/6/6/gate0 |
| 남은 범위 | root Lifecycle·SSH/Docker·전체 소스/캐시 복구·호스트 재부팅·정확 승인·운영 적용·MCP/두 봇 |
<!-- /coordinator-private-pid1-publication-20261119 -->
<!-- /coordinator-private-pid1-20261119 -->

## 재현과 운영 적용 조건

기존 Python과 보존한 공식 `G_Harness2/`를 사용한다. 저장소 밖에 아직 없는 출력 경로를 지정하고 구조 검사 뒤 같은 소스 SHA로 회귀를 실행한다.

```sh
python3 -B infra/validation/journal-composition/reproduce_limits.py --repo . --output /private/tmp/soc-coordinator-baseline
python3 -B infra/validation/journal-composition/check_coordinator_structure.py --repo . --restored-root /private/tmp/soc-coordinator-baseline/candidate --output /private/tmp/soc-coordinator-harness2.json
python3 -B infra/validation/journal-composition/run_coordinator_regressions.py --output /private/tmp/soc-coordinator-checks
```

구조 검사는 32소스의 SHA·기존8파일·복원한2,271파일 후보·프레임워크 버전을 확인한다. 회귀는 예상 수·종료 코드·생략·소스 불변·자체 작업 제거를 검사한다. 실제 운영 root 진입점이나 독립 원복을 실행하는 명령은 아니다.

다음은 실제 systemd·부팅·독립 복구·부분 실패를 검증하고 현재 소스/모델/MCP 스키마/권한을 대조하며 전체 payload를 동결해 정확 승인을 받는 단계다. 이후 관리자231을 경유한 적용과 새 수집·MCP·두 봇 새 채팅·확정/복구·정리/current를 확인한다. 기존 관리19/journal9 승인은 재사용하지 않는다. 관리대역 전역 변경은 [별도 공통 기능](../../mcp/management-policy.md)으로 구현해야 한다. 공격/학습 중단·새 OS 전체 설치·Suricata 인라인 IPS의 미검증 상태도 유지한다.
