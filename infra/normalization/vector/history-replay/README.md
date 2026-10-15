# 이전 boot 자료의 격리 분류 확인

2026-10-14 11:54:49~11:54:50 KST, A에 보존된 **1,481건 / 621,820바이트**를 설치된 Vector 0.59.0으로 별도 실행해 확인했다. 현재 nft 접두사 선택 조건에 맞는 자료는 **0건**이며, 1,481건 모두 이 보안 정제 경로의 비대상이다. 실제 정제 실패도 0건이다. 이 결과는 전체 kernel 로그가 보안상 무해하다는 판정이나, 1,481건의 Wazuh 분석·Indexer 색인 완료를 뜻하지 않는다.

[검증 결과](validation-2026-10-14.json)에 원본 두 배치 및 실행 소스 SHA, 전수 계수, 경계 검증, 운영 상태 불변성과 초기 후보 시험 실패를 기록했다. 원문·커서는 Mac으로 가져오지 않았다.

| 구분 | 입력 | nft 후보 | 정제 성공 | 정제 거절 | 비대상 |
|---|---:|---:|---:|---:|---:|
| 실제 보존 자료 | 1,481 | 0 | 0 | 0 | 1,481 |
| 별도 합성 제어 | 14 | 12 | 9 | 3 | 2 |

합성 제어는 알려진 접두사 7종, 일반 kernel 메시지와 잘못된 접두사, 중복 SRC, kernel 이외 transport, 잘못된 시각, 유효하지 않은 IP, 보호 대상 주소를 다룬다. 예상 거절 3건은 중복 SRC·잘못된 transport·시각이다. 정제된 9건 모두 `historical`, `replay=true`, `correlation_eligible=false`이며 보호 대상 1건과 품질 플래그 1건도 보존했다. `observed` 2건 / `would_drop` 1건 / `logged_drop` 6건의 의미를 변경하지 않았다. 이 합성 자료는 운영 입력·경보와 섞이지 않는다.

## 사용한 경계

- [verify-a.sh](verify-a.sh)는 고정된 A machine ID와 root만 허용하며, 이미 보존된 두 배치 ID·payload SHA·manifest SHA에 결속된다. 임의 경로·boot·cursor를 인수로 받지 않는다. **이번 1,481건의 검증 전용**으로, 다른 데이터나 새 hash는 자동 수용하지 않는다.
- [기존 기록 검증기](../history/validate-records.jq)를 실행 번들에 같은 이름으로 포함하고 SHA를 검사한다. 각 배치의 첫/끝 cursor·시각·건수가 원래 manifest와 같고, 두 배치 전체 cursor가 고유하며 child의 부모 결속이 일치하는지 확인한다. 네 경계의 record/event ID는 별도 jq 인코딩+SHA 계산으로 대조했다. 전체 selector 결과의 ID 중복과 누락도 계수로 확인했다.
- 운영 nft selector 문자열과 [nftables.vrl](../transforms/nftables.vrl), [correlation.vrl](../transforms/correlation.vrl)의 SHA를 대조한 뒤 동일 VRL을 private 실행 경로에 복사한다. 해당 운영 설정을 편집하지 않는다.
- [run-isolated.sh](run-isolated.sh)는 private stdin 입력, private `data_dir`, private file sink만 갖는 [replay.toml](replay.toml)을 실행한다. journald/file 원천, 네트워크 sink, 운영 ready/evidence 출력, 운영 체크포인트를 사용하지 않는다. 검증은 최대 20초, 실행은 최대 30초와 종료 유예 3초를 둔다.
- 이번 자료의 모든 journal 필드가 문자열임을 먼저 검사한다. 이 범위에서 `MESSAGE`를 `message`로 옮기는 동작은 [Vector v0.59.0 journald 구현](https://github.com/vectordotdev/vector/blob/v0.59.0/src/sources/journald.rs#L862-L909)의 기존 namespace 동작과 같다. 원본에 `message`가 이미 있거나 숫자·배열 등 다른 형식이 있으면 거절한다. 실제 journald의 byte-array 변환까지 모사하는 범용 대체 구현이 아니다.
- 별도 표식 `replay_lane=previous-boot-analysis-v1`과 `correlation_eligible=false`를 적용한다. 원천 시각과 cursor 기반 ID는 유지하며 `evidence_lane=indexer-observation-v1`을 부여하지 않는다. 과거 자료를 현재 공격 상관분석에 재주입하지 않는다.
- A 보존 원문·manifest SHA와 `capstone-vector.service` PID/Invocation/active, `wazuh-agent.service` Invocation/active, 실제 `wazuh-logcollector` PID/start tick이 전후 동일했다. Wazuh unit의 정상 `MainPID=0`은 logcollector 확인으로 보완했다. 동작 중인 운영 체크포인트의 자연 진전까지 멈췄다는 의미는 아니다.

## 실행과 보관

관리자는 이 폴더의 네 소스와 `../history/validate-records.jq`를 root 소유 0700 실행 디렉터리에 모아 각 SHA를 검증한 뒤 `/bin/bash verify-a.sh`를 실행한다. 기존 A 도구만 사용하며 설치·서비스 변경·상시 daemon이나 timer가 없다. 내부 실행기는 고정 `/var/tmp/capstone-replay-20261014/history-replay-<임시이름>/{actual,synthetic}` 경로만 받는다.

원문 사본·커서 요약·private ID 목록·Vector 진단 로그는 A root 전용 임시 경로에만 남는다. 작업 종료 시 상위 작업자가 공용 staging과 함께 정리하며, 원래 `/var/lib/capstone-vector-history/batch-*` 보존 파일은 삭제하지 않는다. Mac에는 집계·해시·한계가 담긴 결과 JSON만 보관한다.

처음 두 후보 시험에서 각각 VRL 파일 경로의 환경변수 미확장, console 결과와 Vector 내부 stdout 로그 혼합을 발견했다. private 리터럴 경로를 렌더링하고 별도 private file sink를 사용하도록 고친 최종본으로 위 전수·합성 검증을 통과했다. 운영 Vector 설정을 고친 것은 아니다.

현재 결과는 보존 범위의 분류 검증까지다. 이전 boot에 대해 보존 전에 vacuum 등으로 유실된 로그가 전혀 없었다는 증명, 원래 미수신 경계의 복원, Wazuh 재주입, 과거자료 Indexer 저장을 수행하지 않았다. Wazuh/Indexer의 별도 native 제어 시험은 상위 작업에서 구분해 기록한다.

**12:28 KST 마감:** A/B 관련 소스·문서38개씩과 원문 없는 검증 metadata를 SHA 대조해 보관했고 작업용 A/B·Mac 임시 경로를 제거했다. 원래 보존 배치·수신증은 유지한다. [보관 위치·정리 수치·최종 운영 확인](finalization-2026-10-14.json).
