# 서비스 사실 조회의 미확인 상태와 원문 출처

**미등록 unit의 해석·관계 추정과 인용 오탐을 보완한 미적용 후보**다. 원인 조사의 추가 조회 누락이 남아 운영 승격하지 않는다. 부모 [사실 조회 후보](../factual-service/README.md)와 전체 선행 조합도 미적용이다. 설치본 query137과 후보 query149/common93을 구분한다.

## 목적과 동작

| 무엇을 바꿨나 | 어떻게 동작하나 | 이유 |
|---|---|---|
| 구성요소 식별 미확인 | 등록된 현재·기간 조회와 동일 호스트 목록 탐색이 끝난 단순 조회에 `unresolved_service_lookup` 형식 사용. 모델은 미확인 확인값만 반환하고 실제 관측은 하네스가 표시 | not-found의 inactive/dead를 실제 프로세스 상태로 해석하거나 목록을 관련 컨테이너로 묶지 않음 |
| 조회 완료와 사건 종결 | 식별 미확인은 needs_review, 식별 확인된 사실 조회만 observed. 미확인 형식에는 사건 종결값을 생성하지 않음 | 조회를 받았다는 사실이 정상 판정·사건 해결이 되는 것을 방지 |
| 원문 인용과 새 주장 | 검증된 diagnostic 영수증에서 결정적으로 만든 표의 정확한 원문 행만 의미 검사에서 구분. 덧붙이거나 변경한 주장, 임의 표는 계속 검사 | 로그가 주장한 문장을 봇의 새 주장으로 오인하지 않음. 원래 승인·인용 검사는 전체 답변에 유지 |
| 사실 확인용 모델 입력 | 기존 soc-query 스킬의 절을 재사용. 질문·범위·영수증 해시·식별 범위만 전달하고 원문은 감사·표시에 보존 | 긴 journal 전체를 다시 읽어 고정 조회 확인값을 생성하는 낭비 축소 |
| 조사와 권한 | 원인·영향·비교·추가 대상은 기존 조사 경로에서 전체 근거 유지. Native/SDK 모두 같은 공통 원칙 사용 | 모델 판단이나 승인·도구·보호 경계를 고정 정상 응답으로 대체하지 않음 |

실패·오래된 목록은 0개로 바꾸지 않는다. 목록 조회가 아직 남았거나 요청 밖의 추가 읽기가 섞이면 닫힌 미확인 조회로 끝내지 않는다. Native의 식별 자료는 모델 JSON 밖의 turn/nonce/영수증에 결속한다. SDK도 실행 문맥의 자료만 렌더러에 넘긴다. 스킬은 권한을 확대하지 않는다.

## 실제 응답과 남은 문제

같은 학습35B·hermes-parity·등록된 실제 MCP 읽기를 사용한 격리 SDK 시험이다. 부모1회/후보4회, 질문 문자열4개, SDK 읽기12회·기록 모델 완료12회다. 별도 protocol smoke2읽기·초기 운영 MCP2읽기는 이 분모에 합치지 않는다.

| 요청 | 부모148/92 | 후보149/93 | 내용 검토 |
|---|---:|---:|---|
| B systemd 최근9분 로그 | 27.460초 | 9.160초 | 반환50행·표시 한도와 실제 구간 표시. 사실 확인 합성 입력16,010→818토큰 |
| B Vector 현재·최근4분 로그 | 이번 대조 없음 | 15.890초 | unit not-found·실제 구성요소 미확인. 목록185 unit/7컨테이너는 관계 증거로 쓰지 않음·partial |
| B Docker 과거05:50~05:53 로그·현재 | 이번 대조 없음 | 9.242초 | 전체 표본12행에 실제 오류 포함·조회 완료 |
| B Docker 같은 과거 구간 오류 원인·현재 | 이번 대조 없음 | 18.970초 | 기본 errors 표본0 뒤 추가 조회 없이 미확인으로 끝남·partial |

시간은 실행기 전체 시간이며 Mattermost 도착시간이 아니다. 같은 질문 한 쌍도 시간·로그 내용·공유 GPU·캐시·순서가 통제되지 않았다. 부모는 미적용 후보이고 운영 기준선이 아니다. 실행 completed를 전체 품질 통과나 모델 우위로 해석하지 않는다.

| 남은 문제 | 실제 근거 | 다음 보완 |
|---|---|---|
| 오류 필터와 후속 조사 누락 | 같은 Docker 구간 all은12행·HTTP500 4행(priority6), errors는0행. 원인 요청은 errors 뒤 all을 추가 조회하지 않음 | 고정 오류 후보의 한계를 인식하고 같은 대상·기간·한도의 등록 원문으로 조사 확대. 필터/수집기 원인 별도 점검 |
| 부가 구간·장황한 표시 | 현재 속성의 기본15분 구간과 요청한 과거 로그 구간이 함께 표시. Vector 수집 지표도 표시 | 속성 관측 시각·나이와 요청 로그 범위를 분리하고 부가 필드를 축약 |
| 실제 운영 증거 | 실제 Native Hermes 추론·새 Mattermost 게시·정확 통합 적용/복구·독립 사건은 미수행 | 정확 후보 승인과 실제 로드 후 새 대화/운영 인수 검증 |

과거 Docker500은 실제 오류다. 현재 active/running이나 errors 반환0은 과거 오류 부재·현재 모든 기능 정상·복구 완료를 뜻하지 않는다. 호출자·근본 원인·지속 영향은 미확인이다. [출처와 한계](SOURCES.md).

## 준비와 재현

저장소 Git 이력, 기존 Python3/jsonschema, 보존된 고정 `G_Harness2/`가 필요하다. 새 패키지·네트워크·모델·서버 작업 없이 새 임시 경로에 복원한다. 기존 경로를 덮어쓰지 않는다.

```sh
python3 -B infra/validation/service-provenance/reproduce.py \
  --repo /path/to/capstone_project --output /private/tmp/new-provenance-replay
SOC_PROVENANCE_ROOT=/private/tmp/new-provenance-replay/candidate \
SOC_FACTUAL_TEST=/private/tmp/new-provenance-replay/parent-artifacts/test_factual_service.py \
SOC_TYPED_TEST=/private/tmp/new-provenance-replay/parent-artifacts/test_typed_service.py \
  python3 -B infra/validation/service-provenance/test_service_provenance.py
SOC_TYPED_ROOT=/private/tmp/new-provenance-replay/candidate \
SOC_TYPED_TEST=/private/tmp/new-provenance-replay/parent-artifacts/test_typed_service.py \
  python3 -B infra/validation/service-provenance/test_typed_compat.py
```

[동결 명세](manifest.json)·[8소스 패치](candidate.patch)·[입력 해시](source-manifest.json)·[검증 원장](validation.json)을 함께 사용한다. 643소스 전체 해시를 확인하며 현재 운영본에 이 패치를 바로 붙이지 않는다. 과거 typed36 시험은 정확한 원본 SHA를 검사한 뒤 모델 mock의 고정 스키마 응답 생성만 보완한다. 원본36 assertion은 바꾸지 않는다.

## 확인과 복구 경계

| 확인 종류 | 결과 | 대신할 수 없는 검증 |
|---|---|---|
| 공식 Harness² | pin6868817·35구성/5스킬/20scripts·8수정면·상시16,917자/증가0 | 실제 모델 판단·운영 품질 |
| Mac 회귀 | 21프로필1,190개 중1,184통과·기존 optional OpenAI6생략 | 서버 의존성·실제 응답 |
| 기존 Hermes 이미지 | UID10001·network connect금지·21프로필1,273개 전부 통과 | 실제 gateway/채팅 |
| 추가 반례·공개 재현 | 신규41·부모 호환36 통과,643소스 복원 | 새 독립 SOC 점수 |
| 라이브 재대조 | 14:43:17 KST 관리자231 경유 B32설치 SHA·모델/설정·reader927/startticks7043 불변, native 모듈 부재 | A/C 전체 재검증 |

실제 SDK 실행마다 같은45도구 카탈로그를 관측했다. 별도 초기 도구3스키마의14:05 KST 관측과 구분한다. Native 요청/렌더러 연결 반례는 mock을 이용한 검사이며 실제 Hermes 모델 호출이 아니다.

후보 미채택 상태여서 운영 원복은 실행하지 않았다. 기존 관리19/journal9 정확 승인안·백업은 불변이며 새 후보에 승인을 재사용하지 않는다. 원문/SHA를 보존한 뒤 자체2유닛 종료·5PID부재, 원격2폴더862일반파일/2socket·14,336,338B와 Mac21,483파일·324,233,173B·transport7개·중복 전송wrapper1개를 정리했다. 전역 프로세스 조사 주장은 하지 않는다. G_Harness2·논문15SHA·기존9작업·자료/가중치·복구본은 보존한다.

이번5응답은 [평가 사용 원장](../../../finetuning/EVALUATION_USAGE.json)의 개발 소비다. 정답/SFT·새 독립 평가로 재사용하지 않는다. 운영 적용/보호 dispatch/채널 게시/공격/새 학습/새 Mac 패키지0이다. 수동 결함 우선 검토이며 review-agent 실행이나 Semgrep 수행으로 표시하지 않는다.
