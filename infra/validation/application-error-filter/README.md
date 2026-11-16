# 앱 오류 필터와 보관 색인 검증

**운영 미적용 후보다.** 같은 Docker journal 구간에 원문12행과 앱의 `level=error`·HTTP500 기록4행이 있었으나, 설치된 오류 발췌와 보관 오류 색인은 모두0건이었다. 색인은 해당 구간을 스캔했다고 표시했다. 후보는 선언된 앱 오류 수준을 공통으로 분류하고, 다른 정책의 과거 스캔 표시를 새 정책의 완료 근거로 재사용하지 않는다.

| 구분 | 확인 결과 | 범위 |
|---|---|---|
| 실제 설치 경로 | metadata0·errors0·all12, 과거 스캔233구간 | 관리자231 경유 B의 등록 MCP3읽기와 같은 구간 직접 읽기 |
| 메모리 내 후보 | 정제4·현재 수집 재처리4·CLI4·Native4 | 실제 같은 원문, 코드만 메모리에서 교체. 설치/캐시 쓰기0 |
| 기존 캐시의 후보 읽기 | 기존 이벤트0, legacy-unversioned·partial | 읽기 전용. 새 정책으로 재스캔한 결과가 아님 |
| 개발 검사 | Mac381 중370통과/의존성11생략, Hermes381통과/생략0 | 8프로필·추가24검사. 독립 보안 사건 점수 아님 |
| 공식 Harness² | 고정37구성·8변경면·상시16917자/증가0 | 기존 시험 파일의 감사 표현 추가이며 런타임 구성요소 증설 아님 |
| 실제 적용 | 없음 | 기본 소스와 설치된 core/journal2파일이 달라 통합 대조 필요 |

## 공통 변경과 경계

5개 런타임/MCP 소스와 기존 시험3파일의 [패치](candidate.patch)를 고정했다. JSON·logfmt의 최상위 `level`·`severity`·`log.level` 문자열만 앱 선언 수준으로 읽는다. `error`·`fatal`·`panic`·`critical`·`alert`·`emergency`·`emerg`를 인식하며, 본문·중첩 객체의 표식·일반 HTTP500 문자열만으로 앱 오류를 만들지 않는다. 중복·충돌 필드와 형식/크기 한도 초과는 임의로 해석하지 않는다. 메시지16384문자·필드64개 한도다.

기존 journal 우선순위0..3의 일반 분류는 바꾸지 않아 과거 동일 커서의 기록을 재분류로 충돌시키지 않는다. 정보/경고 우선순위4..6에서 새로 인식한 선언은 `application_error`·`format`·`level`로만 정제한다. 이 값은 앱이 선언한 수준이며 공격·데이터 손실·원인·현재 영향·복구의 증거가 아니다. 기존 systemd/예외/고정 코드 후보의 의미는 보존한다.

공통 전처리 후보는 구조화 메시지 구분자까지 읽되 새 앱 경로는 파서로 확인한다. 정상 후보가 CLI tail을 채우면 `has_more`/부분 한계를 유지하며0건을 전체 부재로 만들지 않는다. Native는 정상 후보를 선택 행 한도 전에 제외한다. 원문·행/바이트/시간·대상·마스킹 한도는 유지한다. 임의 패턴·경로·명령 인자, 새 도구·포트·권한을 추가하지 않았고 실제3개 입력 스키마는 기준본·후보와 같다.

## 보관 정책과 복구

`source_filter_policy=application-severity-v1`으로 정책을 구분한다. 이전 정책/미기록 정책의 이벤트는 읽을 수 있지만 그 스캔 범위를 현 정책의 완료로 표시하지 않는다. 승인 적용 뒤 첫 정상 게시 트랜잭션은 기존 이벤트를 보존하고 이전 `windows` 표식만 무효화한다. 실제 다시 수집한 구간부터 새 정책의 스캔 범위를 쌓는다. 실패하면 표식 초기화와 이벤트 변경을 모두 롤백한다. 실제 운영 DB에 이 게시·재스캔을 수행하지 않았다.

운영 적용에는 파일·수집기·캐시의 같은 버전과 원본 DB 복구본이 필요하다. 이전 코드로의 원복 시 캐시도 호환되는 복구본을 사용해야 한다. 현재의 정확 승인 계획2개를 이 후보로 덮어쓰거나 승인됐다고 취급하지 않는다. [앞선 서비스 조사 후보](../service-error-coverage/README.md)·호스트 journal 보완과 통합한 뒤 새 정확 승인/원복안·실제 로드·MCP·두 봇 채팅 검증이 필요하다.

## 재현

Python3.12와 보존된 공식 `G_Harness2/`가 필요하다. 새 패키지·모델·자격 파일을 내려받지 않는다. 출력 경로는 저장소 밖의 아직 없는 경로로 고른다.

```sh
python3 -B infra/validation/application-error-filter/reproduce.py --repo . --output /private/tmp/soc-app-error-replay
SOC_APP_ERROR_ROOT=/private/tmp/soc-app-error-replay/candidate python3 -B infra/validation/application-error-filter/test_application_errors.py
python3 -B -m unittest discover -s /private/tmp/soc-app-error-replay/candidate/infra/mcp -p 'test_*diagnostic*.py'
```

재현기는 Git 기준 전체2258파일과 패치8파일 SHA를 검사하고 공식 구조 결과를 만든다. 모델·MCP·채팅·배포를 실행하지 않는다. Mac에 없는 OpenAI 타입 관련11개는 기존 Hermes 환경의 전체147소비자 검사에서 생략 없이 확인했다. 테스트 fixture의 임의 본문/마스킹/출력 한도는 명시 all 조회로 정정했고 기존 검증을 삭제하지 않았다. 초기 누락 입력·실패와 수정은 [검증 원장](validation.json)에 구분한다.

[소스와 근거](SOURCES.md) · [고정 입력](manifest.json) · [출처/무결성](source-manifest.json) · [검증 범위](validation.json)

실제 네 건은 이미 관측한 개발 사례이며 일반 탐지율·오탐률·새 학습 효과·Mattermost 응답 속도로 환산하지 않는다. 미반환8행의 정상 여부를 독립 정답으로 인증하지 않았다. LLM의 데이터 손실/DNS 영향 추정, 새로운 로그 형식, 실제 인수·승인/원복·독립 사건 평가는 여전히 별도다.
