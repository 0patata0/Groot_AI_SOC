# journal native 운영 적용·원복 후보

<!-- journal-composition:start -->
[조정 실행기](../../journal-composition/COORDINATOR.md)에 정리·현재 설치 검증을 연결했다. 15모듈·50소스·39제어 문서, 동일 소스 Mac252·Linux252/생략0·공식78→80구성/추가2/수정14/상시 증가0은 격리 근거다. root namespace5조건도 실제 서비스 인수가 아니다. 운영 소스/서비스 변경0이며 실제 systemd·독립 복구·정확 승인·MCP/두 봇 채팅이 남았다. 관리대역 공통 계약은14적용면·34검사를 마쳤다. 전역 MCP·장비 어댑터·실제 적용/원복은 아직 연결하지 않았다.
<!-- journal-composition:end -->

**A/B/C의 정확 후보·원본 백업과 회귀·복제 경로 검증을 준비했다. 운영 적용과 원복 타이머 실행은 아직 하지 않았다.** [정확 계획](plan.json) · [검증 원장](validation.json) · [어댑터 구현](../README.md) · [현재 상태](../../../../STATUS.md).

승인에 결속할 전체 계획 SHA256:

`0f5cc45fbdb0a0ca1ec18cc0cc1428a4d982549a7ca7cbeab7095cabaa4c219e`

## 변경 범위

| 대상 | 현재 | 적용할 후보 |
|---|---|---|
| A/B/C system_diagnostics.py | e72f3fddfd82 | 5fd3b9802930 |
| A/B/C diagnostic_journal.py | 8336e073a249 | db0028225c8b |
| A/B/C diagnostic_journal_native.py | 없음 | cd0667698bd6 |

호스트별2개 교체·1개 추가, 총9개 코드 파일이다. 전체 SHA·UID/GID0·0644와 source 바이트, 호스트 머신ID 해시는 계획에 고정했다. 호스트별 보호 항목 합계53개(A15/B23/C15)는 history/runtime/inventory/강제 reader·기존 unit/수집기 netlink drop-in·초기 설치 영수증을 그대로 검사한다. 기존19파일 관리 상태 수정 계획은 별개이며 이번 적용 범위에 넣지 않는다.

최종 준비 경로는 각 서버의 `/var/lib/capstone-journal-native/12545722ac1fd845-{a,b,c}`다. root 전용0700에 후보·원본2개씩·계획·해시가 고정된 실행기를 보관했다. 초기 설치 영수증이나 모델·MCP 스키마/계정·보안장비 룰·차단 TTL·키·포트·상시 권한을 바꾸지 않는다. 단일 초기 설치기 deploy.sh를 운영 서버에 재실행하지 않는다.

## 적용·실패·확정 절차

1. 관리자231 경유로 현재 source/권한·머신ID·reader PID/시작ticks·unit/drop-in/기존 영수증을 다시 확인한다. 고정 dependency 사전검사에서 systemd255·Python binding235/API를 확인하며 온라인 설치로 대체하지 않는다. 차이가 있으면 적용을 멈추고 원인을 확인한다.
2. 사용자 승인 후 호스트별 apply를 systemd의 별도 Type=exec 서비스에 맡긴다. SSH 응답이 끊겨도 같은 unit/state를 관측하고, 관측 시간 초과만으로 재시작하지 않는다. [systemd255 실행 방식](https://www.freedesktop.org/software/systemd/man/255/systemd-run.html)은 서비스 매니저가 실행을 관리하는 방식이다.
3. 파일 교체 전에 해당 서버의15분 독립 원복 타이머를 설정하고 active 여부를 확인한다. 수집 타이머를 잠시 멈추고 이미 실행 중인 collector가 끝나기를 최대90초 기다린다. collector 프로세스는 강제로 중지하지 않는다. 그 뒤 journal reader만 정지한다. 일반 봇·추론·WAF/IDS/FW 서비스는 이 실행기의 조작 대상이 아니다.
4. **helper → core → journal** 순서로 파일별 원자 교체를 수행한다. 세 파일 전체가 하나의 원자적 트랜잭션은 아니며, 서비스 정지·각 단계의 구/신 라이브러리 호환·백업/원복으로 보완한다. 새 helper는 원자적인 create-if-absent를 사용한다. reader·수집 타이머를 시작하고 기존 비특권 계정의 고정 journal 요청까지 확인한 뒤 APPLIED로 기록한다.
5. 실제 비특권 MCP와 양봇의 새 채팅에서 현재 설치 후보의 읽기·근거·출력을 확인한다. 그 근거 파일 SHA와 해당 적용시각·호스트·현재 reader PID/시작ticks를 root 전용 validation-proof.json에 결속한다. 시험 fixture나 이전 보고서로 이 파일을 만들지 않는다. 증거 내용의 정확성은 운영자가 대조하며, 이 attestation의 구조 검사만으로 의미 정확도가 증명되지는 않는다.
6. 확정은 실제 파일·보호 항목·비특권 읽기를 재검사하고 최신5분 이내 MCP·채팅 근거가 모두 있어야 한다. COMMITTED 기록을 먼저 저장한 뒤 원복 타이머를 해제한다. 확정 뒤 원복 작업이 늦게 실행돼도 소스를 바꾸지 않는다. 미확정 만료/실패 시 구 journal → 구 core → 자기 후보 helper 제거로 원복한다. 외부 변경·잘못된 소유권·알 수 없는 파일을 덮어쓰지 않으며, 충돌은 수동 확인이 필요할 수 있다.

최대 apply 실행300초·원복 실행180초, 원복 예약900초다. [타이머 기준](https://www.freedesktop.org/software/systemd/man/255/systemd.timer.html)은 활성화 뒤의 monotonic 시간이다. 현재 방식은 Mac/SSH 연결과 독립적으로 실행하도록 구성했으며, 실제 호스트 재부팅·전원 차단 후 자동 복구를 시험하거나 보장한 것은 아니다. 중간 코드 조합을 cold load한 검사는 재부팅 시험과 다르다.

journal·진단 history·사건/채팅 queue DB·센서 로그를 과거 스냅샷으로 복구하는 API는 없다. 복제 시험에서는 교체 후 새로 쓴 SQLite fixture 사건이 파일 원복 뒤에도 남는지 확인했다. 기존 helper와 같은 바이트라는 이유로 다른 소유자의 파일을 지우지 않는다.

## 검증과 정정

| 검증 | 확인한 범위 |
|---|---|
| 고유 회귀33개 | Mac·Linux A/B/C에서 같은33개 각각 통과·skip0. 네 번 실행을132개 독립 사례로 세지 않음 |
| 실제 바이트 복제3역할 | 기존2코드+새helper9개 적용→9개 원복, 새 helper 부재 복구, 새 fixture DB 내용 보존 |
| 단계별 cold load | 역할별6개, 총18중간 조합 로드 통과. 모든 중간 조합에서 전체 서비스/질의를 실행한 시험은 아님 |
| 새 코드의 실제 journal 읽기 | 복제 경로에서 A 기존1µs1행·B과거 오류6행·C전체우선순위3행, 모두 기존 validator 통과 |
| 운영 대조 | 최종3준비 폴더 PREPARED·원본2개씩, 기존9소스 before 일치·보호53항목 일치·reader PID/ticks 유지 |
| 운영 미수행 | 실제9코드 교체·reader 재시작·원복 timer 발동·실제MCP·새채팅·새 OS 전체 설치 |

이번33개 적용기 검사는 [구현 단계](../README.md)의166개 어댑터/설치 검사와 별도다. 모델 판단·기관 독립 관제 정확도·채팅60초나 학습 우위를 증명하지 않는다. 복제 query 시간도 부하/캐시 비통제 표본이므로 성능 비교로 쓰지 않는다.

최초 준비는 기존 netlink drop-in과 timer의 MainPID 유무를 맞춰 대조했다. B의 기존 영수증 파일명에 있는 KST `+0900`을 범위 검사에서 거절한 것은 같은 고정 디렉터리 내의 파일명 허용과 root 메타데이터 검사로 정정했다. 그 뒤 실제 구/신 소스를 단계별 로드해 **새 journal/구 core의 root_file 바인딩 부재**를 재현했다. 잘못된 중간 조합은2파일 원복·새 fixture 보존을 확인했고 최종 순서와 반례 회귀를 보완했다. 모두 자기 복제/준비 경로이며 운영 장애나 모델 오답으로 집계하지 않는다.

review-agent 원본 미발견으로 수동 결함 우선 검토를 했다. Semgrep 미수행이며 하네스/스킬은 이번에 바꾸지 않아 공식 Harness² 실행을 주장하지 않는다. 이후 하네스 정리는 별도 공식 Harness² 절차를 따른다.

## 보관·정리

최종3개 PREPARED 폴더·원본 백업6개는 승인과 복구를 위해 보존한다. 폐기한 준비2세대와 시험13개 unit은 종료·source/상태·파일별 SHA를 대조한 뒤 자기 파일183개2,751,905B/19artifact 폴더를 제거했다. 최종 준비와 운영 reader·수집 설정은 그대로다. Mac 자기 임시67파일2,285,932B를 제거·부재 확인했고 최소재현10개와 운영자 source6개·원문·전체 계획은 로컬 기록에 보존했다. G_Harness2·사용자 환경·운영 복구본·데이터/가중치·논문43쪽 검수본과 원래 다른9작업은 유지한다.
