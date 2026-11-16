# 전체 수집기 한도와 초기 이력 수집

전체 수집기와 초기24시간 이력 수집의 유한 자원 제한 후보를 검증했다. 실행 코드2개·시험3개의5소스 오버레이이며 운영에는 아직 적용하지 않았다. Mac1,427개 중 기존 의존성6개를 생략했고 기존 Hermes 이미지의 격리 Linux1,510개는 모두 통과했다. 공식 Harness²는40구성·5변경면·상시16,917자 증가0이다.

## 무엇을 바꿨는가

| 항목 | 후보의 동작 |
|---|---|
| 공통 한도 | MemoryHigh192MiB·MemoryMax256MiB·스왑0·TasksMax64·FD1,024 |
| 정기 수집 | capstone-system-diagnostics.service, 시작 제한85초·종료 대기5초·전체 프로세스 그룹 종료 |
| 초기 이력 | capstone-diagnostic-history-backfill.service, 고정 역할의24시간 수집·시작 제한150초·종료 대기5초·AF_UNIX만 허용 |
| 실행 전 | systemd가 실제 로드한 한도·형식·시간 제한을 대조하고 다르면 시작하지 않음 |
| 완료 조건 | 실패 구간이나 잘림이 있으면 부분 보고·캐시는 보존하되 CLI가1로 종료. timer·reader 활성화로 넘어가지 않음 |
| 설치 영수증 | 기존3개에 초기 이력 유닛을 더한4개 unit과 local source를 확인. 단일 사용자 진입점은 deploy.sh 유지 |

파일에 한도가 적혀 있는지만 확인해서는 덮어쓴 설정을 찾을 수 없다. 설치기는 daemon-reload 뒤 실제 로드 값을 읽고 정기 수집과 초기 이력을 순서대로 실행한다. 두 단계가 성공한 뒤 타이머와 reader를 활성화한다. 이미 설치된 서버에는 이 초기 설치기를 재실행하지 않는다.

## 실제 격리 실행

| 호스트 | 전체 수집 | 24시간 이력 | 수집 최고 메모리 | 수집 최고 태스크 |
|---|---:|---:|---:|---:|
| A | 6.921초 | 31.341초 | 49.34MiB | 43 |
| B | 8.024초 | 28.154초 | 56.71MiB | 54 |
| C | 4.578초 | 12.466초 | 50.00MiB | 46 |

세 서버 모두 일반 수집과 이력 수집의 OOM·태스크 한도 초과가0이었다. runtime4개 worker와 inventory5개 worker를 포함했고 두 풀은 순서대로 실행됐다. A/C와 B의 재시험은 runtime·inventory의 unavailable 항목이 없었다. 이력은0/7/0행, 잘림과 실패 구간0이었다. 이 수치는 고정 분류 범위의 결과이며 오류·공격 전체의 부재를 뜻하지 않는다.

B의 관리 DB는 읽기 전용으로 백업한 뒤 시험 유닛의 사설 마운트에 연결했다. 기존 B 유닛의 WAL/SHM 쓰기 경로를 유지하면서 운영 DB 행을 바꾸지 않으려는 시험 구성이다. 해당 관리 조회는 복사 시점의 자료이며 운영 DB를 그 이후 시각까지 직접 조회했다는 증거로 쓰지 않는다. Docker daemon·컨테이너 내부 exec·외부 API 서버의 자원은 수집기 cgroup 측정 밖이다.

B의 별도 음성 시험에서는 MemoryMax256MiB·스왑0에서 시험 자식이 OOM으로 종료됐고 태스크64에서 추가 thread가 거절됐다. 하드 한도를 분리 검증하려고 그 시험만 MemoryHigh를256MiB로 올렸다. 일반 수집과 이력 수집은192MiB를 사용했다. 시간 초과 시험은 시작 제한을2초로 줄였으며 SIGTERM을 무시하는 자식도 실행 중이 아님을 확인했다. 운영 설정의85/150초 제한을 실측한 것으로 표시하지 않는다.

## 실패와 정정

초기 Linux 전송은 manifest 파일명 속 ARCHIVE를 먼저 치환해 base64 해석 중 실패했다. 원격 시험 폴더와 유닛이 없음을 확인한 뒤, 문자열 literal과 config를 직접 대조하도록 고쳤다. 운영에는 쓰지 않았다.

스왑0 후보의 첫 전체 회귀는 자정 직후에 실패했다. 시험이 오늘01:10~01:20을 무조건 과거로 기대했지만 실제로는 미래였다. 시험 기준 시각을 고정하고 미래 거절·자정 전후 반례2개를 추가했다. 런타임의 미래 시각 거절은 유지했다. 첫 실패와 최종1,427/1,510 결과를 구분해 보존했다.

첫 B 수집 시험에서는 원래 유닛의 관리 DB 쓰기 예외를 제외했다. 이 조건에서 management-pipeline 한 곳이 unavailable이었다. 그 시험은 전체 경로 성공으로 세지 않았다. 첫 메모리 초과 시험도 약25초 뒤 실패했으며 결과 기록이 남지 않아 원인을 확정하지 않았다. 최종 음성 시험은 성공·실패와 자원 이벤트를 먼저 기록하도록 고쳤다.

## 재현과 적용 경계

```sh
python3 -B infra/validation/journal-composition/reproduce_limits.py --repo . --output /private/tmp/soc-collector-limits-replay
python3 -B infra/validation/journal-composition/run_limits_regressions.py --root /private/tmp/soc-collector-limits-replay/candidate --comparison /private/tmp/soc-collector-limits-replay/comparison-base --environment mac --output /private/tmp/soc-collector-limits-checks
```

공개 명령은 고정 소스·공식 구조·회귀를 재현한다. 실제 서버 프로브·DB 사본·커널 음성 시험의 실행기와 원문은 로컬 검증 기록에 보존했다. 현재 운영 파일을 바꾸거나 실제 채팅을 보내는 명령이 아니다.

초기 설치 소스와 생성 유닛은 함께 맞췄다. 추가 패키지·공개 포트·키·MCP 도구·일반 sudo/Docker 위임은0이다. 운영 적용에는 소스·캐시·소비자의 일관 정지, 백업·독립 원복·새 증거 기반 확정과 정확 승인이 더 필요하다. 기존40경로 초안은 새 unit까지 포함한 최종 승인안이 아니다. 새 OS 전체 설치·실제 MCP/양봇 새 채팅·독립 관제 정확도는 미검증이다.

[고정 입력](limits-manifest.json) · [수치·정리·한계](limits-validation.json) · [초기 설치 유닛](limits-units.json) · [수집 기반](README.md) · [현재 상태](../../../STATUS.md)
