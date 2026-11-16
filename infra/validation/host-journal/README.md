# 호스트 시스템 journal 읽기·공통 계획 후보

<!-- journal-composition:start -->
[정본 동기화](../journal-composition/CANONICAL.md) — 검증 후보와 다른32파일을 맞추고 선택36파일 SHA·현재 정본1,427검사/기존6생략·공식40구성/22변경면/상시 증가0을 확인했습니다. 이전 Linux1,510은 동일 동결 바이트의 근거입니다. 운영에는 미적용이며 일관 정지·부팅 차단·독립 원복·정확 승인·실제 MCP/새 채팅은 남습니다.
<!-- journal-composition:end -->

<!-- diagnostic-read-boundaries:start -->
진단 경계 후속은 [검증 원장](../diagnostic-read-boundaries/README.md)에 정리했다. 내부µs·등록 대상 확인·명확한 상대 기간과 원인 괄호 반례를 보완했고 실제SDK3요청/4읽기·모델완료6·wire2성공/3거절을 확인했다. not-found/default Result의 미검출 해석 오류가 남아 미승격이며 현재 정본·초기 설치·운영/권한/모델은 바꾸지 않았다. 구조/회귀·실제 의미·새 채팅을 구분한다.
<!-- diagnostic-read-boundaries:end -->

후속 [실제 MCP·모델4요청](../host-journal-model/README.md)은 B의5읽기·12모델완료를 확인했으나 의미 오류·검사 오탐·대상 확인/시각 경계가 남았다. 운영 미적용·실제채팅0이며 아래 당시 관측을 성공으로 덮어쓰지 않는다.

후속 [파일별 native 비용 보완 후보](../host-journal-cost/README.md)는 동일24h errors A5.50/B2.61/C1.94초·CLI전체병합일치를 확인했다. 운영 미적용·실제모델/설치MCP/새채팅 미수행이다. 아래는 이 문서의 원래 관측이며 당시 실패를 덮어쓰지 않는다.

**최근 로그의 실제 읽기는 확인했지만 운영에는 적용하지 않았다.** [실제 모델 시험](../read-target-live/README.md)에서 드러난 집계 systemd 로그의 필수 읽기 공백을 보완하는 후보다. 고정 A·B·C 시스템 journal을 기존 `get_system_diagnostics`에 연결하고 공통 계획·근거 검사·표시·설치 사전검사를 함께 수정했다. 24시간 오류 검색은 native와 CLI 모두 시간 제한에 걸렸으며 해결된 것으로 표시하지 않는다.

## 범위와 사용 원리

| 요청 종류 | 대상·인자 | 반환 범위 |
|---|---|---|
| 현재 실패 서비스 | 기존 `a:systemd`·`b:systemd`·`c:systemd`, 시간 인자 없음 | 현재 수집 스냅샷의 failed unit 집계 |
| 호스트 시스템 로그 | 같은 고정 대상 + `view=journal` + KST 시작·종료 | 해당 호스트의 로컬 **시스템** journal 표본. 사용자 journal 제외 |
| 개별 서비스 로그 | 기존 등록 unit target + 같은 journal 인자 | 지정 서비스의 기존 읽기·응답 형태 유지 |
| 과거 정제 오류 색인 | 등록 unit target + 시작·종료, journal view 없음 | 기존 서비스 색인만 지원. 호스트 집계 target으로 대체 불가 |

호스트 journal은 `unit=null`, `journal_target_scope=host_system`으로 구별한다. 각 행의 실제 `source_units`·`source_transport`를 보존하며 필드가 없으면 그 사실을 표시한다. 앱이 남긴 UNIT 필드나 메시지는 실행 주체·원인·승인의 증거로 확대하지 않는다. 동일 메시지도 출처가 다르면 표에서 합치지 않는다.

스키마의 호스트 journal 메타데이터를 공통 계획이 검증한다. `B systemd 오류 로그 좀 봐줘`처럼 짧은 요청에도 최근15분의 실제 journal 읽기가 필수로 생긴다. A·C와 등록 별칭도 같은 규칙을 사용한다. 호스트가 불명확하면 선택을 추정하지 않는다. 현재 상태와 과거 로그를 함께 요청하면 별도 읽기로 유지한다. 과거 로그가 실행되지 않았거나 실패하면 현재 스냅샷으로 완료 처리하지 않는다.

원인 조사 기본24시간과 명시 구간은 계속 별도로 취급한다. 이 기본 구간은 사용자가 지정한 사건 시각이 아니다. **이번 시험에서 호스트 전체24시간 errors 검색은 실패했으므로 해당 요청의 완수·실전 가용성을 주장하지 않는다.** 최근 all 표본 조회 성공도 그 기간 전체 오류 검색을 대신하지 않는다.

## 제한과 권한

- 기존30일 내·최대24시간, 반환1~50행, 오류 후보/all 구분, 마스킹·바이트·시간·취소·UID·요청 빈도 제한을 유지한다. native aggregate는 `LOCAL_ONLY|SYSTEM_ONLY`, CLI 대조는 `--system`을 사용한다.
- 임의 unit·경로·명령·정규식·호스트를 입력받지 않는다. 도구 이름·OS 쓰기·승인·보호 주소·차단 TTL·모델·재시도 예산은 바꾸지 않는다. root gate 수정은 검증된 스키마의 동등한 모델 입력 투영뿐이다.
- 기존 관리 상태19파일과 journal9코드의 정확 승인 계획은 그대로다. 이 후속 후보는 두 계획에 자동 편입되거나 승인된 것으로 간주되지 않는다.

## 검증 결과

| 증거 | 결과 | 의미와 한계 |
|---|---|---|
| 공식 Harness² | 고정 `6868817518876de8fd170c6a8354daca273b6191`,33구성·5스킬·상시16,917자/증가0, 변경9구성 | 구조·범위 검사. 품질·속도·운영 성공 아님 |
| 코드·초기 설치 경로 | 운용 소스9개·기존 검사2개 수정. 설치 사전검사에 `SYSTEM_ONLY` 지원 확인 | 정확 source/AST·34소스씩 복원, 새 서버 전체 설치 미수행 |
| 공통 회귀 | Mac1,038 중1,032통과·OpenAI 의존6생략. 기존 Hermes1,121통과·생략0 | 실행 건수이며 독립 사례 수·정확도 아님. Mac 추가64개 부분검사는 서버의 전체147개 검사와 구분 |
| 새 경계 검사 | 19개 통과, 공개 재현 경로에서도19통과 | 고정 대상·사용자 journal 제외·호스트 일치·스키마 동등성·시간·마스킹·출처·변조·이전 unit 호환 |
| 실제 서버 읽기 | A/B/C 각 최근 errors·최근 all·등록 unit·인증 소켓 성공. 세 종류9회 native/CLI 응답 전체 일치 | 운영 reader와 별도의 제한된 임시 서비스. 실제 MCP·모델·Mattermost 호출0 |
| 긴 오류 구간 | 24h errors는 native3회·CLI3회 모두 시간 제한. 같은24h all tail3회는 반환 | 0건·정상·완전 검색으로 치환하지 않음. 전체21논리 시험 중15성공/6실패 |

실제 root 시험은 기존과 같은 NoNewPrivileges·CAP_DAC_READ_SEARCH·AF_UNIX·네트워크 격리·128MiB·TasksMax8 제한에서 수행했다. 최근 errors 표본0건은 그 범위의 반환 값이며 무오류를 입증하지 않는다. CLI와 native의 순차 실행·캐시·서버 부하를 통제하지 않았으므로 위 결과로 속도 우위를 계산하지 않는다. [검증 원장](validation.json)에 인자·응답 SHA·시간·실패·분모를 보존한다.

## 복원·재검사

운영 서버를 변경하지 않는 로컬 복원 명령이다. 기존 공식 `G_Harness2/`와 저장소 Git 이력이 필요하다. 새 패키지를 Mac에 설치하지 않는다.

```sh
python3 -B infra/validation/host-journal/reproduce.py \
  --repo /path/to/capstone_project --output /private/tmp/host-journal-review
SOC_HOST_JOURNAL_ROOT=/private/tmp/host-journal-review/candidate \
  python3 -B infra/validation/host-journal/test_host_journal.py
```

`manifest.json`은 미승인 R6 부모·추가 설치/검사 의존 소스·패치·후보·AST 해시를 고정한다. `candidate.patch`를 운영에 바로 적용하는 절차가 아니다. 기존9변경·논문56쪽·운영 승인 백업을 보존한다. 자체 임시7폴더725파일10,356,916바이트는 결과44파일·전체 SHA·프로세스 종료를 확인한 뒤 제거·부재 확인했다. 21:47 KST A/B/C reader 파일·프로필·PID와 B24소스/45허용schema·config/modeldigest·기존 봇/타이머는 불변이었다. Mac 자체 임시9,047파일133,737,924바이트와 생성 transport7개도 제거했다. 최소 후보11소스·공개 복원기·검증 원문과 framework·자료/가중치는 보존했다.

## 남은 완료 조건

긴 구간 errors의 읽기 비용·실패 후 좁은 실제 구간 조사·모델의 의미 해석을 보완해야 한다. 이후 공식 Harness² 재검사→후보 동결→회귀→새 실제 모델/읽기→정확 새 승인 계획→관리자 경유 적용·실제 로드→새 Mattermost 응답을 검증한다. 과거 모델4요청/7읽기/13완료는 이번0호출과 합산하지 않는다. [현재 상태](../../../STATUS.md)·[계획](../../../PLAN.md).
