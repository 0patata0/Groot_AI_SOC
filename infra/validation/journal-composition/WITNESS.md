# 조정 배포를 위한 상태 대조와 재개 판정

소스·캐시·봇이 서로 다른 버전으로 재개되는 일을 막으려고 읽기 전용 상태 대조를 준비했다. 후속 [조정 실행기](COORDINATOR.md)와 연결해 격리 검증을 마쳤지만 **운영 서버에는 아직 설치하지 않았다.** 기존8파일과 동결 원장의 바이트는 보존했다. [기존 검증 원장](witness-validation.json) · [소스 고정](witness-manifest.json) · [현재 상태](../../../STATUS.md).

## 구현한 기능

| 구성 | 하는 일 | 실행 경계 |
|---|---|---|
| `release_status.py` | A·C 각6개, B34개의 고정 경로에서 SHA256·소유자·권한, 캐시 정책, 배포 단계를 읽는다 | root 전용 임시 Unix 소켓. 파일·캐시·서비스를 바꾸지 않는다 |
| `reader_bridge.py` | 정확한 기존 forced reader를 내장해 일반 조회의 입력 바이트를 그대로 넘기고 `release_status` 조회만 중계한다 | 임시 운영자용 경로다. 새 MCP 도구·sudo·명령 실행 권한을 만들지 않는다 |
| `cohort_guard.py` | 세 서버의 새 관측이 같은 소스 계약·캐시 정책·배포 단계인지 검사해 허용 또는 보류를 판정한다 | 순수 판정 함수다. 서비스 시작·배포 승인·타이머 취소 기능은 없다 |
| `check_release_structure.py` | 이전 수집 후보를 해시대로 복원하고 추가8파일을 공식 Harness²로 검사한다 | 프로젝트 밖 새 작업 경로를 사용한다. 모델·운영 서버를 호출하지 않는다 |

46경로는 기존 소스·영수증40개와 수집·초기 이력 unit6개다. 후속 실제 조회에서 별도 Python reader3개와 B의 컨테이너 밖 읽기 MCP를 확인해 조정 범위를50소스로 잡았다. reader/MCP 차단·소비자 정지·원복·재개는 새 실행기에 연결했다. 정리·현재 설치 출처·실제 서비스 검증·전체 payload와 정확 승인은 남았으며 기존46경로 목록은 최종 승인안이 아니다.

## 읽기와 재개를 확인하는 방법

일반 snapshot·inventory·journal·history 요청은 내장한 기존 reader가 처리한다. 운영자 조회는 schema1, 고정 호스트, 32자리16진 배포 ID만 받는다. 경로·명령·후보 바이트·파일시스템 루트는 요청으로 선택할 수 없다. 기존 B→A/C 읽기 인증 경로를 사용할 수 있도록 중계를 준비했다. 현재 운영 reader를 교체한 것은 아니다.

상태 응답의 `source_contract_sha256`은 호스트·배포 ID·전체 경로의 전후 SHA256·UID·GID·mode를 묶는다. 재개 판정기는 이 계약과 각 파일의 실제 해시·권한 일치를 따로 검사한다. 같은 배포 ID만 붙인 다른 설정은 통과하지 못한다. 파일을 두 차례 대조하며 심볼릭 링크·하드 링크·쓰기 가능한 상위 경로·읽기 중 교체를 거절한다. FIFO는 비차단 열기로 거절해 읽기 대기에 갇히지 않게 했다.

캐시는 고정 메타데이터 DB만 읽는다. 다른 정책·잘못된 호스트·손상·sidecar·권한 불일치는 `unavailable`이다. 사건·대화·승인 DB와 원시 journal을 복구하지 않는다. 반환 내용에도 원문 메시지·커서·비밀 값은 넣지 않는다.

| 판정 목적 | 필요한 근거 |
|---|---|
| 후보 검증 | 세 서버 모두 후보 소스·새 캐시 정책·`verified` |
| A·C 확정 준비 | B는 `verified`, A·C는 `verified`·`confirming`·`confirmed` 중 하나 |
| B 최종 확정 준비 | A·C는 `confirmed`, B는 `verified` 또는 `confirming` |
| 후보 재개 | 세 서버 모두 후보 소스·새 캐시 정책·`confirmed` |
| 원본 재개 | 세 서버 모두 원본 소스·기존 캐시 정책·`rolled_back` |

모든 판정은 KST 관측15초 이내, 미래 허용2초 이내, 세 관측의 시차5초 이내를 요구한다. 누락·연결 실패·오래된 근거·일부 확정·서로 다른 정책은 재개 불허다. 격리 파일시스템의 응답도 운영 확정에 사용할 수 없다. 이 판정만으로 실행 중인 reader·MCP·봇이 새 코드를 로드했다고 인증하지 않는다.

## 검증과 재현

| 검증 | 결과 | 해석 범위 |
|---|---|---|
| Mac | 106개 중102통과·Linux 전용4개 생략 | 신규66개와 기존 캐시40개. 소스/프로토콜/복구 반례 |
| 기존 Hermes 이미지 | Linux·UID10001·네트워크 없음·106통과·생략0 | 실제 SEQPACKET/SO_PEERCRED의 정상·다른 UID·크기 초과·중복 키 검사 포함 |
| 공식 Harness² | 기존40→48구성·추가8·기존 변경0·상시16,917자 증가0 | 구조·컴파일·편집 범위 검사. 모델 품질 점수 아님 |
| 관리자 경유 A/B/C | 01:42~01:57 KST 전후 소스·유닛 SHA와 reader PID/시작값 일치 | 운영 Native 부재·수집기 MemoryMax infinity 유지. 새 배포 없음 |
| B 유휴 조회 | 01:47 KST 실행 중 채팅 작업·관리 실행·Hermes 활성 임대0 | 당시 관측이다. 실제 정지 직전에 다시 확인해야 한다 |

기존 수집 후보2,271파일의 SHA는 `0f625eaa82fc247b18446446d12fd170370d2586ed64f7ada172fbfa794bdd40`로 유지했다. 다음 구조 재현 명령은 아직 없는 출력 경로를 지정한다. G_Harness2와 기존 도구만 사용하며 Mac에 패키지를 추가하지 않는다.

```sh
python3 -B infra/validation/journal-composition/check_release_structure.py --repo . --output /private/tmp/soc-release-witness-check
python3 -B -m unittest discover -s infra/validation/journal-composition -p 'test_release_status.py'
python3 -B -m unittest discover -s infra/validation/journal-composition -p 'test_reader_bridge.py'
python3 -B -m unittest discover -s infra/validation/journal-composition -p 'test_release_ipc.py'
python3 -B -m unittest discover -s infra/validation/journal-composition -p 'test_cohort_guard.py'
python3 -B -m unittest discover -s infra/validation/journal-composition -p 'test_cache_transaction.py'
```

Linux에서 허용하지 않은 UID를 먼저 거절하면 커널은 오류 응답 대신 연결 reset 또는 broken pipe를 돌려줄 수 있다. 초기 시험 두 번은 JSON 응답만 기대해 실패했다. 거절 동작은 유지하고 허용된 연결의 오류를 숨기지 않도록 음성 시험만 고쳤다. A 목록 조회의 template unit 오류와 선택적 부재 경로를 잘못 거절한 첫 시험도 기록했다. 최종 구조 검사 후 소스를 동결하고 위 회귀를 다시 실행했다.

## 운영 적용 전에 남은 일

| 순서 | 완료 조건 |
|---|---|
| 1 | 수집기·reader·B 소비자의 일관 정지, 진행 작업 재확인, 부팅 뒤에도 유지되는 소비자 재개 차단 장치 |
| 2 | 소스·캐시·영수증의 불변 백업, 새 관측 보존, 호스트별 독립 원복 타이머와 연결 단절·재부팅·부분 확정 시험 |
| 3 | 이번 상태 대조·재개 판정을 실제 실행기에 연결하고 A·C 확정 뒤 B를 최종 확정하도록 검증 |
| 4 | 실제 소스·MCP 스키마·모델·권한 재대조, 전체 payload 동결, 정확한 관리자 승인 |
| 5 | 관리자231 경유 적용, 실제 새 수집·MCP·두 봇 새 채팅·로드/복구 검증 |

독립 서버의 확정과 네트워크 단절을 하나의 물리적 원자 작업으로 보장하지 않는다. 일부 서버만 확정된 상태에서는 자동 재개를 허용하지 않고 일관된 버전으로 복구하거나 다시 확정해야 한다. 실제로 B의 재개를 막는 장치는 후속 실행기에서 구현해야 한다.

이번 작업의 운영 소스·캐시 게시·서비스 재시작·모델 생성·채팅 게시·공격·학습은0이다. 임시 Linux 시험4폴더38파일과 시험 컨테이너는 정리했다. 영수증 원본·과거 정확 계획·복구본·논문66쪽 MD/PDF/DOCX는 보존한다. Semgrep과 새 OS 전체 설치는 수행하지 않았다.
