# 호스트 journal의 실제 MCP·모델 검증

**실제 로그 읽기는 가능해졌으나 응답의 의미와 검사에 문제가 남아 운영 후보를 확정하지 않았다.** [파일별 native 후보](../host-journal-cost/README.md)를 현재 학습 모델·SDK에 연결해 새 요청4개를 각각 독립된 대화로 실행했다. 모두 내부 상태는 partial이며, 이를 곧바로 같은 종류의 실패4건이나 정확도 점수로 계산하지 않는다. 조회 완수·모델 주장·검사 거절·최종 답변을 나눠 평가했다.

## 범위와 실제 결과

| 새 요청 | 실제 MCP 읽기 | SDK 경과 | 확인한 결과·남은 문제 |
|---|---:|---:|---|
| B 서버 systemd 오류 로그 확인 | 1회 | 37.57초 | 15분 로그 후보7행을 실제 반환. 기동 Started3행까지 모두 실패로 설명한 모델 오류. 원인 미확인 문장에는 부재 검사 오탐도 발생 |
| B systemd 지난24시간 오류 로그 표 | 1회 | 71.63초 | 요청24시간 후보9행 반환. 과거 Exit Code 요약을 현재 종료 속성으로 거절. 서로 다른 unit을 재시작 루프 가능성으로 묶은 추론도 근거 부족 |
| B vector 로그와 현재 상태 | 3회 | 19.60초 | 현재 snapshot·해당 unit journal·수집 상태를 읽음. LoadState=not-found인데 inactive 서비스로 요약. 이 조회만으로 실제 Docker Vector의 상태·로그를 확인한 것은 아님 |
| 호스트 없이 systemd 오류 로그 확인 | 0회 | 39.70초 | 읽지 않은 A/B/C 실패0건을 생성한 초안3개는 거절됨. 최종에는 검증 불가 문구만 남아, 즉시 대상 확인 질문을 하는 요구에 미달 |

기록된 모델 완료는12회(요청별3·4·2·3), SDK의 실제 데이터 읽기는5회다. 모델을 쓰지 않은 별도 MCP smoke는 도구 호출2회 중1성공·소수초 인자1거절이며 SDK5회와 분리한다. 성공한 smoke는0.248초였고 채팅 응답 시간이 아니다. 보호 호출·채널 게시·운영 파일/설정/DB·기존 서비스 변경·새 학습·공격 시험은0이다. [검증 원장](validation.json)에 질문·인자·반환 SHA·시간·거절 이유·분모를 보존한다.

## 어떻게 시험했는가

1. 공개 부모 후보를 복원해34소스/측 SHA·허용 AST와 공식 Harness² 고정 버전을 다시 확인했다.33구성·5스킬·상시16,917자/증가0이다. 이 검사는 구조 확인이며 모델 정확도 증거가 아니다.
2. 관리자231 경유로 B의 설치 소스·45허용 schema·모델 digest·config와 기존 reader를 대조했다. 기존 에이전트→Thor 추론 경로와 학습 모델을 유지했다.
3. 별도 root 소유 시험 폴더에 동일 후보를 복제했다. SDK의 이 시험 프로세스에서만 system-diagnostics 전송을 SSH 대신 자체 stdio/Unix 연결로 바꿨다. 설치 config는 수정하지 않았다.
4. MCP는 기존 `mcp` UID·기존 journal 그룹·capability0으로 실행했다. 실제 journal은 기존 root/peer UID·rate·20초 조회/12초 child·128MiB/Tasks8 제한을 둔 별도 reader가 읽었다. 모델은 경로·FD·명령이나 권한을 지정할 수 없다.
5. 데이터 읽기 smoke를 통과한 뒤 네 SDK 요청을 실행하고 실제 호출·최종 답변·거절된 초안·API 완료 지표를 수집했다. 이전 요청의 답변이나 관측을 다음 대화로 주지 않았다.

이번 통합 대상은 B다. A·C의 실제 전체 구간 읽기 증거는 부모의 별도 backend 시험에 있다. 모든 호스트의 MCP 통합이나 Hermes gateway·Mattermost 왕복을 이 결과로 대신하지 않는다. 이 한 연결에서 SSH를 뺀 시험 경과를 운영 채팅 SLA나 모델 우위로 사용하지 않는다.

## 구분해서 보완할 공통 문제

| 문제 | 근거 | 필요한 보완 |
|---|---|---|
| 후보 건수와 실제 실패의 혼동 | 고정 오류 후보 필터에는 파일 이름 참조도 포함되므로 Started 행이 반환됨 | 반환 행·실패 이벤트·원인·현재 상태를 나누어 판단. 필터를 통과했다는 이유만으로 전부 오류로 단정하지 않음 |
| 원인 미확인 문장 거절 | 같은 초안을 로컬 재처리해 `sample_zero_presented_as_absence` 오탐 재현 | 문장의 주체와 괄호 속 예시를 공통으로 처리. 별도의 실제 부재 단정은 계속 거절 |
| 과거 로그와 현재 속성 혼동 | 과거 Exit Code 요약에 `diagnostic_current_exit_status_unverified` 발생 | 실제 근거에 결속된 로그 내용 보고와 현재 프로세스 상태 주장을 분리. 근거 없는 재시작 루프 추론도 별도 검토 |
| unit과 실제 서비스의 혼동 | not-found unit과 별개로 수집 프로세스는 관측됨 | 호스트·대상 종류·실제 unit/container를 구분하고 필요한 현재 대상 탐색을 이어감 |
| 대상 미지정의 지연·허위 조회 | 도구0회에서 A/B/C0건 초안3개 | 실제 호출 전에 공통 대상 해석으로 한 번 확인. 불명확한 호스트나 예전 수치를 추정하지 않음 |
| 소수초 시각 경계 | 같은 초의 과거 until 거절·30일보다0.25초 오래된 since 허용 | 정수초로 자른 현재 시각과 microsecond 입력의 경계를 통일. 유예 시간 추가로 미래/보존 제한을 약화하지 않음 |

시각 경계는 실제 smoke 거절과 별도 순수 clock 모의4조건(불일치2개)으로 확인했다. 수정한 생산 코드가 있는 것은 아니다. 모델 오류를 전부 검사 오탐으로 처리하거나, 검사만 꺼서 완료율을 높이지 않는다.

## 초기 실패·보존·다음 절차

시험용 root broker의 UID 전환과 SDK가 읽을 수 없는 운영자 파일의 해시 검사에서 준비 실패가 있었다. 이 단계에서는 모델 요청이 전송되지 않았음을 확인한 후, 권한을 늘리지 않고 기존 mcp 계정 직접 실행·운영자/SDK 검사 분리로 고쳤다. 초기 연결 실패를 보존했고, 모델은 데이터 읽기 smoke를 통과한 뒤에만 요청했다. 시험 unit의 RuntimeMax 변경 시도도 거절되어 원래 수명을 유지했고 모델 네 요청은 그 안에 끝났다. 과거 실패와 최종 실행의 소스 SHA를 [원장](source-manifest.json)에 구분한다.

시험 unit과 모델/MCP 프로세스의 종료를 확인했고 원문·전체 SHA를 보존했다. 임시 제거 결과는 검증 원장의 후속 영수증을 따른다. 원래9변경·논문56쪽15개 산출물·기존 PREPARED 후보/원본 백업·framework·자료/가중치는 보존한다.

원문을 가진 운영자는 부모 복원기로 새 로컬 경로에 후보를 만든 뒤 아래처럼 같은 입력의 거절과 시각 경계를 재현할 수 있다. 새 서버 조회·모델 호출·운영 변경은 하지 않는다. 원문 경로는 로컬 전용이며 새 외부 사용자에게 공개하지 않는다.

```sh
python3 -B infra/validation/host-journal-cost/reproduce.py \
  --repo /path/to/capstone_project --output /private/tmp/host-journal-model-review
python3 -B infra/validation/host-journal-model/replay.py \
  --candidate /private/tmp/host-journal-model-review/candidate \
  --evidence /private/collected/out/candidate/result.json
python3 -B infra/validation/host-journal-model/clock_replay.py \
  --candidate /private/tmp/host-journal-model-review/candidate
```

네 질문과 관측된 모델 답변은 [사용 원장](../../../finetuning/EVALUATION_USAGE.json)에 소비한 개발 자료로 기록했다. 답변에는 오류가 있으므로 정답·SFT 대상·새 독립 평가로 쓰지 않는다. 원장의 지문은 로컬 user/final-answer 관측 fixture이며 실제 전체 wire 정책·도구·문맥을 담은 입력 지문이 아니다. 기존 자료를 다시 채점한 결과나 단순 회귀와 합산하지 않는다.

다음은 위 공통 문제의 후보를 공식 Harness²→동결→반례/회귀→새 실제 읽기·모델 요청으로 검증하는 것이다. 이후 정확한 새 승인·복구안→관리자 경유 적용/로드→양봇의 새 실제 채팅을 확인한다. 기존 관리19파일·journal9코드 계획의 승인을 재사용하지 않는다. [현재 상태](../../../STATUS.md) · [계획](../../../PLAN.md).

자체 원격 시험 폴더의 일반 파일97개·소켓2개/2,217,104B는 결과38파일과 전체SHA·프로세스 종료 확인 후 제거했다. Mac 자체 임시5,560파일/82,712,402B와 생성 transport5개도 제거·부재를 확인했다. 원문·재현·framework/자료가중치·운영백업·논문15SHA·기존9변경은 보존했다.
