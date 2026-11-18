# 소스·캐시·소비자 조정 실행기

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

<!-- coordinator-native-systemd-20261119 -->
## 실제 systemd의 격리 시험

11/19 관리자231 경유 A/B/C의 실제27유닛을 후보 Native의 운영 모드로 읽었다. 생성자·고정 카탈로그·systemctl 속성 해석을 확인했으며 정지·시작 명령은 실행하지 않았다. B의 컨테이너도 선택한 상태 필드만 읽었다.

별도 시험은 관리자231의 기존 systemd255.4와 Python을 사용했다. 고유한 /run 시험 유닛과 C 합성 파일을 만들고 후보40소스·별도 캐시 의존2개 지문을 확인했다. 유닛 이름·파일 경로·그룹·ExecStart, runtime enable과 조회 속성을 명시적으로 변환했다. 시험 영수증을 쓰도록 합성 루트를 ReadWritePaths에 추가했다. 실제 서비스 관리자의 로드·자원 제한·시작 조건·타이머를 사용하지만 운영 진입점과 전체 Lifecycle 복구는 아직 검증하지 않았다.

| 확인 조건 | 실제 관측 |
|---|---|
| 수집기와 보조 유닛 로드 | 후보의 유한 자원 값과 상태 검사 통과 |
| 로드 값 변경 | 시험 watchdog의 MemoryMax를 바꾸자 실행 준비 거절 |
| 시작 차단 | collection 표식이 있는 시험 reader의 시작을 건너뛰고 PID0·시작 시각 불변 |
| 중단 뒤 독립 복구 | 시험 apply 프로세스가 파일2개 교체 후 종료23. 다른 PID의 타이머가 약9.42초 뒤 원본 복구·reader 차단 보존 |
| 재개 | 시작 전 활성 상태였던 시험 reader와 타이머만 재개 |
| 정리 | 자체 유닛·enable 링크·작업 폴더 제거와 별도 부재 읽기 통과 |

검증기는 Linux root와 명시적 --run-owned-units 옵션을 요구한다. 이번처럼 관리자 경유로 승인된 점검 호스트에 고정 소스와 두 manifest를 함께 전달해 실행한다. Mac 설치나 운영 A/B/C의 고정 유닛 변경은 필요하지 않다.

```sh
python3 -IB infra/validation/journal-composition/validate_owned_systemd.py --run-owned-units
```

처음에는 시험 기반 설정의 netlink drop-in 누락과 여러 경로의 변환 누락으로 거절됐다. 다음 시험은 여러 파일이 있는 drop-in 디렉터리를 일찍 지우려다 정리 오류로 종료됐다. 남은 자체39파일을 크기·SHA로 기록하고 제거한 뒤 정리 순서를 수정해6조건을 다시 확인했다. 후속 읽기 검사는 빈 list-unit-files가 종료1을 반환하는 경우를 반영했다. 원본 실행기와 고정 후보는 변경하지 않았다.

운영 root 진입점·Lifecycle.recover·실제 재부팅/SSH 단절·B Docker·캐시/전역 복구·정확 승인·운영 적용·새 MCP/봇 인수는 남는다. [검증 원장](native-systemd.validation.json)은 이 범위를 분리한다.
<!-- /coordinator-native-systemd-20261119 -->

## 재현과 운영 적용 조건

기존 Python과 보존한 공식 `G_Harness2/`를 사용한다. 저장소 밖에 아직 없는 출력 경로를 지정하고 구조 검사 뒤 같은 소스 SHA로 회귀를 실행한다.

```sh
python3 -B infra/validation/journal-composition/reproduce_limits.py --repo . --output /private/tmp/soc-coordinator-baseline
python3 -B infra/validation/journal-composition/check_coordinator_structure.py --repo . --restored-root /private/tmp/soc-coordinator-baseline/candidate --output /private/tmp/soc-coordinator-harness2.json
python3 -B infra/validation/journal-composition/run_coordinator_regressions.py --output /private/tmp/soc-coordinator-checks
```

구조 검사는 32소스의 SHA·기존8파일·복원한2,271파일 후보·프레임워크 버전을 확인한다. 회귀는 예상 수·종료 코드·생략·소스 불변·자체 작업 제거를 검사한다. 실제 운영 root 진입점이나 독립 원복을 실행하는 명령은 아니다.

다음은 실제 systemd·부팅·독립 복구·부분 실패를 검증하고 현재 소스/모델/MCP 스키마/권한을 대조하며 전체 payload를 동결해 정확 승인을 받는 단계다. 이후 관리자231을 경유한 적용과 새 수집·MCP·두 봇 새 채팅·확정/복구·정리/current를 확인한다. 기존 관리19/journal9 승인은 재사용하지 않는다. 관리대역 전역 변경은 [별도 공통 기능](../../mcp/management-policy.md)으로 구현해야 한다. 공격/학습 중단·새 OS 전체 설치·Suricata 인라인 IPS의 미검증 상태도 유지한다.
