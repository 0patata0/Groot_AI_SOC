# 호스트 시스템 journal의 전체 구간 검색 후보

<!-- diagnostic-read-boundaries:start -->
진단 경계 후속은 [검증 원장](../diagnostic-read-boundaries/README.md)에 정리했다. 내부µs·등록 대상 확인·명확한 상대 기간과 원인 괄호 반례를 보완했고 실제SDK3요청/4읽기·모델완료6·wire2성공/3거절을 확인했다. not-found/default Result의 미검출 해석 오류가 남아 미승격이며 현재 정본·초기 설치·운영/권한/모델은 바꾸지 않았다. 구조/회귀·실제 의미·새 채팅을 구분한다.
<!-- diagnostic-read-boundaries:end -->

후속 [실제 MCP·모델4요청](../host-journal-model/README.md)은 B의5읽기·12모델완료를 확인했으나 의미 오류·검사 오탐·대상 확인/시각 경계가 남았다. 운영 미적용·실제채팅0이며 아래 당시 관측을 성공으로 덮어쓰지 않는다.

호스트 전체 오류 로그의 24시간 검색이 시간 제한으로 끝나던 문제를 파일별 native 조회로 보완했다. **A·B·C 실제 격리 시험은 성공했으며 운영에는 아직 적용하지 않았다.** 부모 [집계 journal 후보](../host-journal/README.md)의 실패 기록을 보존하고 별도 후속 패치로 관리한다. 설치된 MCP·모델의 도구 선택·새 Mattermost 응답은 이번 검증 범위에 포함하지 않는다.

## 무엇을 왜 바꿨는가

| 확인한 문제 | 변경 | 유지한 조건 |
|---|---|---|
| B의 같은 24시간 검색이 worker 2개·1개 모두 20초 제한에 걸림 | native가 선택해 이미 연 모든 시스템 journal 파일을 개별 조회한 뒤 최신 표본 병합 | 전체 기간·고정 오류 필터·사용자 journal 제외 |
| 여러 파일을 넘나드는 native 이전 항목 탐색에서 반복 메타데이터 검사가 집중됨 | 원래 anchor를 열어 둔 채 동일 inode의 FD로 native Reader 복제 | 자체 journal 바이너리 파서·파일 시각 추정·일부 파일 제외 없음 |
| 설치 환경의 바인딩 기능 확인 필요 | 설치 사전검사에서 검토한 `Reader`의 `files` 인자 지원 확인 | python-systemd235/systemd255 고정·자동 다운로드/대체 구현 없음 |

1,000항목 이하의 진단에서 `fstat` 호출이 syscall 측정 시간의 약 97.8%였다. 이 수치는 좁은 prefix의 비용 진단이며 전체 로그 수나 전체 요청의 97.8%를 뜻하지 않는다. 우선 시험한 priority index 제거 후보는 실제 24시간 검색이 계속 실패해 채택하지 않았다. [실패 패치](rejected-scan-r1.patch)와 [검증 원장](validation.json)을 함께 보존한다.

## 실제 결과와 판정

세 서버 모두 같은 고정 24시간·`errors`·limit5 조건이다. 기존 CLI를 각각 24개의 1시간 요청으로 조회하고 합친 **전체 응답**과 대조했다.

| 서버 | 후보의 24시간 단일 요청 | 반환 행 | CLI 전체 구간 병합과 일치 | CLI 24개 요청 누적 시간 |
|---|---:|---:|---|---:|
| A | 5.500281초 | 5 | 일치 | 98.112070초 |
| B | 2.607778초 | 2 | 일치 | 45.661436초 |
| C | 1.937432초 | 1 | 일치 | 32.809291초 |

후보6요청(각6시간·24시간)과 별도 CLI72요청을 실행했다. 표의 CLI 누적 시간은 단일 조회 시간이나 채팅 응답 시간이 아니다. 캐시·부하·실행 순서를 통제하지 않아 일반 성능 우위·콜드 스타트 SLA로 환산하지 않는다. 세 응답의 `has_more=false`는 가용 journal의 고정 필터 표본 결과이며 로그 보존 완전성·무오류·침해 부재를 증명하지 않는다.

| 검사 | 결과 | 의미 |
|---|---|---|
| 공식 Harness² | 고정 `6868817518876de8fd170c6a8354daca273b6191`,33구성·5스킬·상시16,917자/증가0 | 실행 모듈2개만 구조 변화, 검사 파일1개 추가 변경 |
| Mac 회귀 | 1,054개 중1,048통과·기존 선택 의존6생략 | 이전 호스트 fixture19개는 새 Linux FD I/O만 모의. 실제 Linux 증거와 구분 |
| 기존 Hermes 회귀 | 1,137개 통과·생략0 | 실제 설치 Python 의존 환경의 별도 소스 사본. 서비스 교체 아님 |
| 새 경계 검사 | 16개 통과 | 전체 소스 포함·전역 최신 표본·충돌·회전/삭제·FD 안전성·기존 reader fallback·입력 거절 |
| 실제 모델·MCP·채팅 | 모두0 | 봇의 최종 정확도·전체 응답 지연 해결은 아직 미확인 |

## 안전 경계

- FD는 private worker 자신이 native `LOCAL_ONLY|SYSTEM_ONLY` anchor를 열어 얻은 값만 사용한다. MCP/worker 입력으로 경로·FD·명령·정규식을 지정할 수 없다.
- root 소유·일반 파일·단일 링크·쓰기 권한·journal 경로·inode 일치를 검사한다. 파일 수256초과는 거절하며 일부만 읽어 성공으로 표시하지 않는다. 원래 anchor와 모든 복제 reader를 종료한다.
- 읽는 동안 가용 inode 집합이 바뀌면 실패한다. 삭제·회전·vacuum을 0건이나 완전한 조회로 바꾸지 않는다. 애초 열린 journal FD가 있는 embedded 호출은 기존 제한된 reader를 유지한다.
- 마스킹·등록 unit·기간·반환·패킷·취소·요청 빈도·20초 조회/12초 child·128MiB/Tasks8·UID·권한·승인·TTL은 유지한다. 임의 코드 실행·새 OS 권한은 추가하지 않는다.
- 같은 시각의 항목이 잘리는 경우 기존 다중 파일 순서와 동일 부분집합까지 보장하지 않는다. 실제 세 구간의 전체 응답 일치와 일반 동시각 tie 동작은 구분한다.

## 로컬에서 복원하고 검사하는 방법

준비물은 이 저장소의 Git 이력, Python3, 고정된 공식 `G_Harness2/`이다. 패키지를 Mac에 설치하지 않는다. 명령은 운영 서버에 연결하지 않고 프로젝트 밖의 **새 경로**에 부모와 후보를 복원한다.

```sh
python3 -B infra/validation/host-journal-cost/reproduce.py \
  --repo /path/to/capstone_project --output /private/tmp/host-journal-cost-review
SOC_PARTITION_ROOT=/private/tmp/host-journal-cost-review/candidate \
SOC_PARTITION_BASE=/private/tmp/host-journal-cost-review/base \
  python3 -B infra/validation/host-journal-cost/test_partitions.py
SOC_HOST_JOURNAL_ROOT=/private/tmp/host-journal-cost-review/candidate \
SOC_FROZEN_HOST_TEST=/path/to/capstone_project/infra/validation/host-journal/test_host_journal.py \
  python3 -B infra/validation/host-journal-cost/test_host_compat.py
```

`manifest.json`의 부모4파일·34소스/측 SHA·허용 AST·패치·검사 해시를 확인한다. 실패하면 후보를 적용하지 않고 출력의 실패 위치를 확인한다. 이 패치는 미승인 부모 후보 위의 차분이며 운영 정본에 바로 적용하는 설치 절차가 아니다.

## 다음 단계와 복구

현재 canonical/초기 설치 입력과 운영 reader는 기존 상태다. 기존 관리 상태19파일·journal9코드 정확 계획을 이 후보에 재사용하지 않는다. 다음 단계는 같은 후보의 실제 모델 도구 선택과 실패 처리 검증→정확한 새 적용/복구안과 승인→관리자231 경유 최신 SHA·유휴 확인→독립 원복 타이머→적용/로드→양봇의 새 실제 채팅 확인→확정이다. 승인 거절·실패·불일치 시 운영 적용을 중단하고 준비한 원본으로 복구한다.

원격·Mac 시험 폴더는 결과/전체 SHA/프로세스 종료를 확인한 뒤 이번 작업의 자체 파일만 정리한다. 원래9변경·논문56쪽15개 산출물·기존 PREPARED 후보/백업·`G_Harness2/`·데이터/가중치는 보존한다. 세부 정리 영수증은 검증 원장의 후속 항목을 따른다. [공식 API 출처](SOURCES.md) · [현재 상태](../../../STATUS.md) · [계획](../../../PLAN.md).

원격 자체8폴더 1,418파일/20,573,462B·결과82파일을 전체SHA/종료 확인 후 보존·제거했고, Mac 자체3루트 12,289파일/180,961,159B와 생성 transport17개를 정리해 부재를 확인했다. 최소3수정소스·공개패치/복원기·원문·G_Harness2·자료/가중치·기존운영백업과논문15SHA/원래9변경은보존한다. Mac 새패키지설치0이다.

## 서비스 타입·실행 근거 후속

[후속 후보](../typed-service/README.md)는 같은 호스트의 실제 inventory·페이지와 실행 기본값 해석을 보완했다. SDK4요청/13읽기·모델완료10과 Mac1120/Hermes1203 회귀를 확인했으나 의미/요약 문제가 남아 미승격이다. 이 부모의 과거 결과·미적용 상태를 소급해서 성공으로 바꾸지 않는다.

## 사실 조회·미확인 후속

[후속 후보](../factual-service/README.md)는 단순 조회의 이름/기간·로그 조사·요약을 보완했다. 최종 Mac1149/Hermes1232·실제SDK4요청14.479~26.601초를 확인했으나 타입/관계 표현·인용 반례가 남아 미승격이다. 이 부모의 과거 관측/실패와 미적용 상태를 소급해 바꾸지 않는다.

## 서비스 출처·미확인 조회 후속

[후속8소스 후보](../service-provenance/README.md)는 미등록 unit을 실제 프로세스로 설명하거나 목록을 관련 구성요소로 추정하던 응답·인증 원문 인용 오탐을 보완했다. 사실 조회 확인 입력을 축소했고 실제SDK5실행/4문자열·12읽기/12모델완료, Mac1190(기존6생략)/Hermes1273·신규41을 확인했다. 같은 과거Docker 구간 all12행·HTTP500 4행 대 errors0을 확인해 원인 추가조회 누락을 남은P1로 기록했다. 이 부모의 과거 실패·해시·미적용 상태를 소급해 바꾸지 않으며 새 후보도 운영 미승격이다.
