# 서비스 종류와 실행 근거의 대조

**일부 개선을 실제 읽기와 모델로 확인한 미적용 후보다.** [부모 진단 경계 후보](../diagnostic-read-boundaries/README.md)도 미적용이며 현재 운영 소스로 설명하지 않는다. 논리 서비스와 unit의 차이, 실제 추가 읽기, 근거 없는 실행 해석을 보완했지만 새 답변에 의미·요약 문제가 남아 승격하지 않는다.

| 보완 | 확인한 결과 | 한계 |
|---|---|---|
| 기본 Result와 실행 | not-found·실행 시각0·not_recorded를 과거 성공/프로세스 정지로 해석한 이전 답변의 세 문장을 검출 | 알려진 실행 주장 경계이며 모든 언어·판단의 정확성 인증 아님 |
| 논리 서비스의 타입 | 같은 호스트의 loaded systemd·Docker 목록과 실제 next_offset을 모델이 선택해 읽음 | unit 미발견을 Docker/다른 호스트/첫 행으로 매핑하지 않음 |
| 직접 지정한 unit | `.service` 요청은 unit 조회1회, 다른 종류로 대체하지 않음 | 실제 실행·전체 기능을 확인했다는 뜻 아님 |
| Native·SDK·root 경로 | 공통 탐색 상태·실제 callable·스키마/권한 검사·실패/잘린 페이지·partial을 연결 | Native는 회귀로 확인했으며 새 실제 Hermes 추론/채팅은 미수행 |
| 안내 | 기존 soc-query/soc-investigate 절 재사용·공통 표에 unit 미발견과 목록 범위 표시 | 요약의 미확인0·과도한 파일 부재/원인 추정은 남음 |

## 실제 관측

관리자231 경유 B에서 05:18:24 KST 같은 스냅샷의 loaded service187개(100+87행)·Docker7개를 읽었고 Vector 항목은 없었다. `b:vector`는 등록된 `capstone-vector.service`의 not-found·실행 monotonic0·process not_recorded를 반환했다. 이 자료는 전체 설치 파일·모든 프로세스 부재의 증거가 아니다.

12:49 KST에 운영32소스·기존45도구 스키마 SHA·설정·학습 모델digest·reader927/ticks7043 불변을 다시 확인했다. 이 재대조는 아래 네 요청을 다시 실행한 것이 아니다. 정본/설치는 query1.19.137이고 새 query1.19.147/common1.5.91은 격리 후보뿐이다. 진단 MCP1.4.4는 부모와 같으며 운영에 새로 배포하지 않았다.

| 새로운 SDK 요청 | 실제 MCP 읽기 | 기록된 모델 완료 | 전체 worker 시간 | 결과 |
|---|---:|---:|---:|---|
| B Vector 현재 상태 | 4 | 3 | 20.303초 | 같은 호스트 목록187/7 조회·partial, 구성요소 식별 미확인 |
| B Vector 현재+최근5분 로그 | 6 | 4 | 28.916초 | 실제 journal과 목록 조회·partial |
| B capstone-vector.service 현재 | 1 | 1 | 13.875초 | unit 원값 조회 완료, 프로세스/사건 종결 아님 |
| B Docker 현재+최근5분 로그 | 2 | 2 | 26.407초 | loaded unit과 journal12행·partial |

실제 SDK13읽기/기록된 모델 완료10회와 별도 wire smoke2읽기·초기 운영 MCP7읽기를 구분한다. worker completed는 실행 완료이며 품질 통과가 아니다. 네 요청은05:52~05:54 KST 개발 관측이고 같은 모델·권한을 유지했다. 공유 GPU·캐시·순서·질문/로그를 통제한 전후 비교가 아니며 Mattermost 왕복·Hermes 실제 응답시간·일반 정확도로 사용하지 않는다.

## 남은 내용 오류

| 관측 | 남은 문제 | 다음 보완 |
|---|---|---|
| 논리 서비스 현재 표 | 본문과 partial은 식별 미확인을 밝히지만 요약은 미확인0으로 표시 | 조회 수신·unit 미발견·구성요소 식별을 요약에서도 구분 |
| Vector 이력 답변 | not-found를 물리적 파일 부재로 확대하고 재시작 필요를 적음 | 실제 확인 범위·변경 필요성의 근거를 분리 |
| Docker 이력 답변 | Canceled를 연결 끊김으로 설명하고 image resolve를 해상도로 번역 | 원문과 확인된 의미를 표시하고 미입증 원인을 추가 조회 |

Docker의 `status=500`은 전체 원문4행에 실제로 있다. 잘린 표시만 읽은 초기 private 검토가 이를 부재로 잘못 보았으며 원문 대조로 정정했다. HTTP500 자체를 환각으로 세지 않는다. 해당05:51:47 오류와 시험 시각이 가깝다는 이유로 원인을 시험에 귀속하거나 현재도 장애라고 단정하지 않는다.

## 검증과 보호 경계

Mac19프로필1,120개 중1,114통과/기존 optional OpenAI6생략·기존 Hermes 이미지 UID10001/네트워크 connect금지의1,203개 전부 통과했다. 신규36개와 공개 복원본의36개는 생략0이다. 초기 staging manifest가 자신을 입력 해시에 넣어 검사 실행 전에 거절됐고 자체 manifest를 정정했다. 실제 표현·부정/이중부정·Started 기록·불량 타입·페이지 변경·다른 호스트·명시 tool subset과 Native 스키마를 추가 검증했다. 회귀 수를 독립 SOC 사례 수로 세지 않는다.

공식 Harness² pin6868817의35구성/5스킬/20scripts·수정8면·상시16,917자/증가0과 전체643소스 복원을 확인했다. 구조 통과는 내용·운영 승인의 대체가 아니다. [동결 입력](manifest.json) · [패치](candidate.patch) · [실제 시험 입력66개+manifest](source-manifest.json) · [검증 원장](validation.json) · [공식 의미 근거](SOURCES.md).

권한·승인·보호 주소·TTL·기존20초/child12초·128MiB/Tasks8·입력 allowlist는 유지했다. 예약 inventory callable은 실제 policy-filtered 카탈로그의 기존 읽기이며 원 요청의 명시 tool subset은 확장하지 않는다. 보호 dispatch·운영 변경·채널 게시·공격·새 학습0이다. 기존19/journal9 정확 승인안은 보존하고 재사용하지 않는다.

원문210파일·전체SHA 보존 후 자체 시험 unit2개를 종료하고 worker/supervisor 부재를 확인했다. 원격 자체777+90일반파일/2socket·12,597,037B와 Mac 자체16,245파일/247,114,429B·임시 transport10개를 정리했다. G_Harness2·기존9작업·논문15SHA·자료/가중치·복구본은 유지한다. 원문과 논문·포트폴리오는 로컬 전용이며 네 관측은 [평가 사용 원장](../../../finetuning/EVALUATION_USAGE.json)에 개발 소비로만 기록한다. 정답·SFT·새 독립 평가가 아니다.

## 복원과 반례 실행

Git 이력·기존 Python3/jsonschema·보존한 고정 G_Harness2가 필요하다. 새 설치·네트워크·모델·서버 변경 없이 새 임시 경로에 복원한다.

```sh
python3 -B infra/validation/typed-service/reproduce.py \
  --repo /path/to/capstone_project --output /private/tmp/new-typed-replay
SOC_TYPED_ROOT=/private/tmp/new-typed-replay/candidate \
  python3 -B infra/validation/typed-service/test_typed_service.py
```

다음은 단순 상태/로그의 사실 조회 범위와 요약·원인 구분을 공통 계약에서 보완하는 일이다. 충분한 회귀·새 실제 응답을 확인한 뒤 부모를 포함한 정확 적용/복구 후보·승인→관리자 경유 로드→양봇 새 채팅 순서를 따른다. 현재 후보의 운영 적용을 요청하거나 완료로 표시하지 않는다.

## 사실 조회·미확인 후속

[후속 후보](../factual-service/README.md)는 단순 조회의 이름/기간·로그 조사·요약을 보완했다. 최종 Mac1149/Hermes1232·실제SDK4요청14.479~26.601초를 확인했으나 타입/관계 표현·인용 반례가 남아 미승격이다. 이 부모의 과거 관측/실패와 미적용 상태를 소급해 바꾸지 않는다.

## 서비스 출처·미확인 조회 후속

[후속8소스 후보](../service-provenance/README.md)는 미등록 unit을 실제 프로세스로 설명하거나 목록을 관련 구성요소로 추정하던 응답·인증 원문 인용 오탐을 보완했다. 사실 조회 확인 입력을 축소했고 실제SDK5실행/4문자열·12읽기/12모델완료, Mac1190(기존6생략)/Hermes1273·신규41을 확인했다. 같은 과거Docker 구간 all12행·HTTP500 4행 대 errors0을 확인해 원인 추가조회 누락을 남은P1로 기록했다. 이 부모의 과거 실패·해시·미적용 상태를 소급해 바꾸지 않으며 새 후보도 운영 미승격이다.
