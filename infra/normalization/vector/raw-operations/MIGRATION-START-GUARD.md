# 최초 전환 중 reader 시작 차단

현재 상태: 2026-10-14 A의 기존 도구로 Linux 합성 31개와 임시 systemd unit 시험을 통과했다. 초기 운영 전환에 연결하기 전 후보이며, 실제 Vector/Wazuh 서비스, 운영 marker 및 재부팅은 이번 시험 대상이 아니다.

`migration-start-guard.sh`는 초기 v1 → v2 전환 중 일부 설정이나 상태만 바뀐 채 reader가 다시 시작하는 것을 막는다. 회전 중 Vector를 잠시 중지했다는 runtime `vector-stop-intent.json`과 목적과 저장 위치가 다르다. 이 스크립트는 파일을 수정하거나 서비스를 시작하지 않는다.

## 고정 경로와 API

- 설치 파일: `/usr/local/lib/capstone-raw-migration/migration-start-guard.sh`
- marker: `/var/lib/capstone-raw-migration/start-barrier.json`
- 위임 대상: `/usr/local/lib/capstone-raw-operations/guard.sh`
- 인수: `vector`, `wazuh`, `inspect` 중 하나

marker 디렉터리는 root:root `0700`, 파일은 root:root `0600`, 일반 파일, 링크 수 1, 최대 4 KiB여야 한다. JSON은 키를 정렬한 한 줄과 마지막 LF만 허용한다. 키 중복, 여러 JSON 문서, 추가 키, symlink, 다른 소유자 및 쓰기 가능한 조상은 거절한다. 명령은 고정 A machine-id와 root/Linux를 확인한다.

`vector`와 `wazuh`는 blocked·marker 누락·검증 실패에서 75를 반환한다. released면 runtime guard의 SHA·보호 권한을 확인하고 marker를 다시 읽은 뒤 해당 역할을 runtime guard에 `exec`로 위임한다. runtime guard의 거절 코드도 그대로 전달한다. `inspect`는 유효한 blocked/released marker의 메타데이터만 반환하며 시작 권한을 부여하지 않는다. 잘못된 인수는 64다.

## installer가 지켜야 할 순서

1. 기존 설정과 reader InvocationID를 확인하고 migration ledger를 영속 저장한다.
2. 최초 blocked marker를 독점 생성하고 파일 및 부모 디렉터리를 fsync한다. marker가 없는 상태를 허용으로 해석하지 않는다.
3. 양 reader에 같은 이름의 임시 `90-capstone-raw-start.conf`를 설치한다. ExecStartPre는 `+/bin/bash /usr/local/lib/capstone-raw-migration/migration-start-guard.sh vector|wazuh`다. daemon-reload 후 실제 설정 반영과 기존 실행 InvocationID 불변을 확인한다.
4. 이 barrier가 양쪽에 반영된 다음에만 legacy logrotate 제외를 포함한 최초 설정·writer 변경을 시작한다. barrier가 기존 실행 프로세스를 중지하지는 않는다.
5. 구 v1 writer 종료·EOF·join 처리, 실제 reader 중지 소유 증거, 최종 v2 설정 및 양 engine state를 확인한다. runtime stop-intent는 실제 중지한 boot/Invocation/start 시각을 보존한다.
6. 공용 작업 lock 아래 양쪽 runtime guard를 직접 실행하여 모두 통과한 뒤 그 설정·상태 및 ledger SHA를 release proof에 기록한다. 원래 blocked marker에 대한 CAS로 released marker를 원자 교체하고 fsync한다.
7. 임시 drop-in을 같은 이름의 최종 runtime guard drop-in으로 CAS 교체하고 daemon-reload한다. 두 ExecStartPre를 누적하지 않는다. release 직후 중단돼 임시 drop-in이 남아도 매번 pinned runtime guard를 거친다.

released marker는 전환 증거로 남긴다. reader를 시작하려고 marker를 삭제하거나 상태를 임의로 고쳐서는 안 된다. blocked는 boot가 바뀌어도 거절하고, released는 매 시작 때 실제 runtime guard를 실행한다. arm/release 쓰기와 검증된 rollback은 installer 소유이며 이 파일의 공개 API가 아니다.

## marker 형식

최상위 키는 아래 여덟 개뿐이다. SHA는 소문자 64자리, boot 및 machine ID는 소문자 32자리 hex다.

```json
{
  "schema_version": 1,
  "policy": "capstone-raw-migration-start-v1",
  "machine_id": "096e90b6243e438aa8a7b392be754732",
  "phase": "blocked",
  "plan_sha256": "<64 hex>",
  "armed_boot_id": "<32 hex>",
  "armed_ledger_sha256": "<64 hex>",
  "release": null
}
```

released에서는 `release`가 아래 여섯 키를 가진 객체다. state SHA는 release 당시 증거이며, 이후 정상 회전으로 상태가 바뀌는 것을 이 marker가 막지 않는다. 이후 상태의 유효성은 매번 실행하는 runtime guard가 검증한다.

```json
{
  "boot_id": "<32 hex>",
  "ledger_sha256": "<64 hex>",
  "runtime_guard_sha256": "<64 hex>",
  "suricata_state_sha256": "<64 hex>",
  "modsecurity_state_sha256": "<64 hex>",
  "readers_verified": ["vector", "wazuh"]
}
```

## 검증 범위

`test-migration-start-guard-native.sh`는 private metadata로 31개 허용·거절 경계를 검사한다. 서비스나 운영 상태에 접근하지 않는다. `test-migration-start-retry-native.sh`는 고유 임시 unit 하나에서 실제 barrier 코드의 blocked 거절, 30초 후 재시도, 합성 released proof를 통한 fixture guard 위임, 수동 stop 이후 35초간 재시작하지 않음을 확인한다. 실제 raw guard, 운영 reader, 재부팅 및 전원 장애는 이 임시 unit 시험의 대상이 아니다.

이 barrier는 root가 기록한 release proof를 전제로 한다. root의 동시 임의 파일 교체를 배제하는 공용 작업 lock과 installer CAS가 필요하다. native checkpoint, WAF join 완료, B 보관 receipt 또는 Wazuh 분석·색인 수신확인을 이 marker로 대체하지 않는다.

### 2026-10-14 native 결과

- metadata 허용·거절 31개 통과. 운영 상태 접근 및 systemd/Docker 호출 없이 private fixture를 정리했다.
- 고유 임시 systemd unit에서 blocked 실패 1회 → 30.06초 뒤 자동 재시도 1회 → fixture normal guard 위임 1회 → 기동 성공 1회를 확인했다.
- 수동 중지 뒤 35초 동안 중지가 유지되고 전체 시작 시도는 2회로 유지됐다. 임시 unit의 프로세스 종료와 fixture 삭제를 확인했다. 실제 운영 unit은 호출하지 않았다.
- 실행 소스 SHA-256: guard `b848a6e20b368e2568bf05c1ac91dc4c9c4c043771fb83a916e38d2b540d2bf4`, metadata fixture `cb54e3b8f1e884a368d1c9d6c26509e4ae8a04154d0ef0ee973d9a91352d71d0`, systemd fixture `187436fbf1d2c23432891c068242c474d4b7107303bd8b0b1198df5ee9ac82bc`.

실행 로그는 A의 `/var/tmp/capstone-resume-20261014/step3/migration-barrier-native/{metadata.log,systemd.log}`에 생성됐다. 이 임시 경로의 최종 보관·정리는 부모 실행자의 마감 기록을 따른다. 합성 release proof 및 fixture guard를 사용했으므로 운영 raw guard, 실제 migration 중단 복구 또는 재부팅 성공의 증거로 확대하지 않는다.
