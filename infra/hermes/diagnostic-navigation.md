# 서비스 현재·과거 조회와 응답 지연 — 2026-11-07

현재 query1.19.89/common1.5.44이다. 서비스 현재·과거 조회의 검증 오탐, 질문별 지침 누락, 교차검토의 상태 해석 검사를 보완했다. 실제 채팅 최종 시간·품질은 아래 실측과 구분한다. [현황](../../STATUS.md) · [수치 원장](diagnostic-navigation.validation.json) · [직전 기록](../../archive/diagnostic-navigation-common41-20261107.md).

## 수정한 원인

| 항목 | 문제와 수정 | 유지한 경계 |
|---|---|---|
| 과거/현재 종료값 | 과거 exit_code=1을 현재 exit_status=0과 비교해 정당한 과거 설명도 거절했다. target·unit·시각과 타입을 보존해 각 시점의 근거와 비교 | 잘못된 현재 값·다른 호스트/시각·미확인 과거 값은 거절. 실제87 이전 영수증으로 오탐 제거 재현 |
| 서비스 지침 전달 | 공통 지침 파일에만 있던 설명이 실제 .service 원인 질문의 안내에서는 빠졌다. 두 봇 초기 안내와 교차검토에 공통 SERVICE_STATE_GUIDANCE 연결 | 특정 호스트의 정답·현재 상태를 저장하지 않음. 실제 MCP 관측으로 판단 |
| 일회성 서비스 해석 | 성공한 oneshot의 inactive/dead를 지속 장애로 단정하거나 NRestarts=0으로 수동 재시작 이력을 추정하는 응답을 보완 | 프로세스 정상 종료를 전체 기능 정상·침해 부재·사건 종결로 확대하지 않음 |
| 교차검토 | 실제 인용이 있다는 것만으로 잘못된 상태 해석이 완료 처리되던 경로에 같은 진단 검증 적용 | 조회 권한·새 도구·승인 없음. 같은 근거로 제한된 정정 후 실패하면 partial |
| 실제 속성 대조 | ActiveState/SubState/Result/Type을 실제 현재·과거 속성과 비교. 시작 중을 정지·실패로 만들어 쓰는 오답 거절 | 실제 runtime completed 플래그와 의미 정확성을 별도 검증 |
| 공통 코드 | 순수 진단 검증을 공통 계약으로 이동, Native/SDK/peer 동일 기준 | gate64,110B, 기존65,536B 상한·필수 읽기·SHA/기간/신선도 검사 유지 |

oneshot은 지속 실행 프로세스 없이 종료할 수 있고 RemainAfterExit가 없으면 작업 후 dead 상태가 될 수 있다. 따라서 inactive/dead만으로 장애를 단정하지 않는다. [systemd 공식 설명](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml). 반환하지 않은 journal 원문을 ‘수집되지 않음’으로 바꾸지 않으며, 오류 종료값만으로 상세 원인을 만들지 않는다.

## 실제 Mattermost 시험

같은 서비스의 과거 실패·현재 상태를 새 root에서 질문하며 설정 변경은 금지했다. 날짜가 바뀌어 ‘오늘’ 대신 ‘어제’를 사용해11/6 오류를 조회했다. 첫 답변과 뒤따르는 교차검토는 별도 측정한다.

| query88/common43 실제 채팅 | 첫 최종 응답 | 품질 판정 |
|---|---:|---|
| Hermes 직접 요청 |64.370초|partial. oneshot 상태 오인, 정정 후 현재 성공 값을 과거 이력에 옮겨 적어 거절 |
| Ollama 직접 요청 |47.133초|런타임completed이나 품질 실패. 실제 activating/start를 inactive/dead로 설명하고 근거 없이 재시작 필요 판단 |
| Hermes 질문 뒤 Ollama 교차검토 |83.749초(worker)|상태 해석 검사2회 거절·partial |
| Ollama 질문 뒤 Hermes 교차검토 |215.168초(worker)|최종 조사 미완료·partial |

첫 응답과 peer 시간은 합산한 같은 지표가 아니다. Native 두 실제 MCP 영수증의 SHA·target/unit·11/6 구간·답변 완료 당시 신선도·쓰기0을 독립 확인했다. 이번 SDK47초 건은 영수증 캐시가 남아 실제 activating/start와 답변 불일치를 확인했다. **47초를 성공 실적으로 세지 않는다.** 입력26,130토큰의 첫 보고 모델35.294초 중 prefill24.384초였고, 두 진단 MCP의 합은0.145초였다. 단일 표본이므로 전체 병목 비율이나 평균으로 일반화하지 않는다.

최종 query89/common44는 literal ActiveState/SubState/Result/Type 주장과 실제 시점별 값도 대조한다. 위 SDK 오답을 운영 소스와 같은 실제 영수증으로 재검사해 diagnostic_property_value_mismatch 거절을 확인했다. query89의 새 채팅 최종 시간은 아직 측정하지 않았으며 이 재현을 새로운 채팅 성공으로 대체하지 않는다.

query86 당시 Hermes74.516초/Ollama66.520초는 둘 다partial이었다. 그 원인에는 모델의 과대 해석뿐 아니라 이번에 재현한 과거/현재 종료값 검사 오탐도 포함된다. query87 Hermes63.918초 역시 상태 오인으로부분보고였고, 뒤따른 Ollama peer67.472초는 인용 검사를 통과했으나 의미가 잘못되어 성공 통계에서 제외했다. 과거 원문·trace는 보존한다.

## 검증·배포·복구

- 고유1,232 PASS/skip0/중복0: Native471·서비스범위14·진단주장16·SDK250·query391·peer70·설치20. 다른 대상/시각의 종료값, 원문 명령 배제, 실제 초기 안내, 승인/권한 경계와 인용 검사를 포함한다.
- 00:38:00 관리자231→A→B 경유 최종7변경/18파일SHA, 보호8·SDK20sourceSHA, 정지 중DB/설정/cron 보존, 유휴 큐·lease 확인. 양봇WS/worker·3서비스active·Bfailed0 뒤15분 독립 원복 확정/no-op 확인.
- 현재 복구본 `/var/lib/capstone-service-semantics/20261107-gate89`, 중간87/88·직전86과 기존 운영DB/원문/trace/채팅도 보존. 실제 수동 원복 시험은 하지 않았다. 최초88적용은 heartbeat_stale로 변경 전 중단, 새 heartbeat로 재확인했다. 시작 직후 WS 준비 중 상태도 정상 연결 후 확정했다.
- 단일deploy.sh의 기존 canonical 복사·controller gate 렌더·review worker/SDK 설치 경로를 사용한다. 새 패키지·포트·키·모델·학습·FW·TTL·승인 변경0. 새OS 전체 설치·실제 공격/부하·UI 전수는 미실행이다.
- fixture 첫 갱신은 Docker 인자 길이 제한으로 변경 전 실패했고 stdin으로 전달해 해결했다. 이전 fixture 검사·반복 실행은 위 고유 수에 더하지 않는다. 초기 새 검사/peer mock 불일치도 수정 후 최종 통과했다.

공유GPU·캐시·질문별 근거량이 달라 각1회로 평균/p95·전체 조사 SLA를 주장하지 않는다. 상세 원인을 입증하지 못하면 그 한계를 답변에 남기며, 정확도·승인 검사를 생략해 시간을 맞추지 않는다.

최종 자체 서버 시험본 459파일 7,078,826B 제거/부재확인. Mac 작업 임시물 정리 및 Git 게시 영수증은 수치 원장에 구분한다. 다음은 실제 근거·현재 질문·판단 지침의 중복 입력과 재작성 비용을 줄이는 별도 후보를 검증하는 것이다.

Mac 자체 임시33파일 12,836,128B 제거/부재확인. 기존 사용자 파일·다른 작업 임시물은 변경하지 않았다.
