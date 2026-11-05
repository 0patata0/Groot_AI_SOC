# 자동 검증의 요청별 읽기 선택

2026-11-05 당시 검증 기록. common1.5.32/query1.19.32/security-events1.2.2. 현재 운영 후속은 [복합 조사 지연](case-latency.md)을 따른다. [현황](../../STATUS.md) · [검증 원장](native-read-selection.validation.json) · [직전 IDS 영향 조사](ids-impact-report.md).

## 원인과 변경

기존 API의 짧은 무실행 시험에서 required/지정 tool_choice가 호출을 강제하지 못했다. 이번에는 설치된 Native 비스트리밍 helper와 OpenAI SDK를 mock HTTP로 통과시켜 required/tools와 response_format이 실제 body에 보존됨을 확인했다. 이 격리 결과를 모든 streaming 요청의 실제 패킷 캡처나 모든 미호출의 단일 원인 증명으로 확대하지 않는다.

자동 검증의 아직 미충족한 상태·센서·관측 경로 기반 읽기만 모델의 엄격한 JSON Schema 선택으로 전달한다. 마지막 Native request builder 이후의 읽기 범위를 사용하고 요청별 임의 nonce·현재 turn·등록 도구·정확 인자 스키마에 결속한다. 모델이 반환한 현재 API 응답만 해석하며 자유 문장·로그·과거 JSON은 실행 입력이 아니다. 응답/사용량/원문을 보존한 형식 어댑터 뒤에 원래 Native registry 검증·MCP 실행·실제 영수증 기록이 이어진다. 어댑터 자체의 MCP 호출은0이다.

| 경계 | 구현 |
|---|---|
| 허용 범위 | verify·현재 확인한35B/로컬 추론 터널·인증된 pending-read만. 일반 manage·쓰기/승인·추론 판단은 기존 경로 |
| 거절 | stale turn/nonce·알 수 없는/쓰기 도구·잘못된 인자·중복 키/호출·length/refusal·취소/redirect·등록 범위 변경 |
| Native 보존 | 원래 전송·회계·재시도·취소·registry dispatch·증거/승인/종결 검사.12turn/180·210초 한도 유지 |
| 설치 | 기존 단일deploy.sh source 복사·root gate 렌더/핀. 다른 SIEM 주소의11435 URI 치환·회귀 추가. 새 패키지/포트/키/일반권한0 |

## 검사와 실제 실행

고유983PASS/최종skip0=관리306+SDK219+Native391+설치41+표19+출력7. SDK 환경의OpenAI 부재로13개를 생략한 뒤 실제 Hermes 컨테이너에서 해당 선택 시험17개를 모두 실행했다. 반복된4개는 누적하지 않았다. 신규18검사는 요청/취소/승인 경계와 실제 SDK HTTP body·초기 설치 주소 치환을 포함한다. 설치 계약은 새 OS 전체 설치 성공이 아니다.

동일 모델의 새 무실행 probe는2.099초에 모델 JSON 선택1개를 정확히 반환했다. provider native tool_calls0·실제MCP0이며 이것만으로 실제 도구 사용이나 전체 성능 향상을 주장하지 않는다.

| 실제 IDS 재검토85ddc3c6 | 결과 |
|---|---|
| 모델 구조화 응답 |6응답에서7읽기 선택·실제 Native/MCP 실행. 센서2개 선택 배치1회 포함 |
| 필수 조사 |상태/센서3·실제 등록 후보/host/백엔드7읽기를 시작 후70.659초까지 완료 |
| 이후 추가 조사 |모델이 상태 재조회·에이전트·차단 목록·진단4개를 추가. 최종 조회132.031초 완료 |
| 총 결과 |11MCP/오류0/보호쓰기0,214.346초 시간초과·outcome_unknown. 실패 outbox sent |
| 남은 문제 |자료0건을 부재로 해석한 사실 정정1회(sample_zero_presented_as_absence), 저추론/2048토큰·34도구 상태에서 최종 정정 전 시간초과 |

현재 요청의 직접 조회 단계는 실제 확인했으나 전체 응답 지연/판단·종결은 해결되지 않았다. 같은 사건의 개발 재검토이고 시간 구간·도구 수·공유 GPU 부하가 달라 개선율/평균 우위를 계산하지 않는다. 다음은 최초 사실 판단과 정정 단계의 범위·도구 재선택·대기/생성을 분리하고, 독립 사건에서 최종 보고까지 확인하는 것이다. 침해 부재·프런트 목적지 결속·전체 요청 수는 새로 입증하지 않았다.

완료된 별도 operation의 추가 CLI 재검토는review_case_not_eligible로 거절됐다. 완료 상태·기존 결과를 그대로 두었고 새 모델 실행/강제 재개0이며 이를 모델 실패로 세지 않는다.

## 배포·복구·정리

B9파일15:28:12 적용·15:29:09 고유SHA/보호7SHA·gate참조/53,515B 인자·양WS/worker·4서비스 확인 후 확정했다. 최초 확인은 시작 직후 worker 미준비로 거절됐고 같은 프로세스의 준비 후 확정했다. Native/SDK/review 각1재시작·추론 서버/GPU/모델·FW/TTL/승인 변경0이다. 진행 중 모델은 관측 시간초과로 중단하지 않았다.

15분 독립 복구 타이머를 해제하고 confirmed_noop을 확인했다. 원본9개/manifest·복구기는 `/var/lib/capstone-native-read/20261105-r1/deployment/`에 보존한다. 정확한 수동 복구는 `python3 -B /var/lib/capstone-native-read/20261105-r1/deployment/rollback.py --manual`이며 이번 실제 실행은 미시험이다. 운영DB·승인·채팅·원문trace·가중치는 보존한다. 시험 source/로그는 SHA 대조와 로컬 복사 후 정리했으며 실제 크기·Mac 정리·Git 게시 결과는 원장/현황에 분리한다.

마감 정리: 서버 source438개/6585826B·시험기록9개/15776B와 Mac 자체26개/6129510B·임시 폴더/SSH소켓을 제거하고 경로 프로세스0을 확인했다. 도구 코드 감사 사본과 원SHA·검사 로그는 로컬 전용으로 보존했다. 기존 사용자 환경·캐시·publisher와 운영 복구본은 유지했다.
