# 사건관리 실패·검토 필요 알림의 표 보완

2026-11-05 KST · 공통1.5.29/query1.19.24. [현황](../../STATUS.md) · [관련 검증](../validation/dns-noise/validation.json).

실제 soc-alerts-agent 최근 사건관리5게시물 중4개가 조사 실패/검토 필요의 줄글이었다. 정상 모델 보고는 표였지만 `incomplete_report`의 일반 오류와 SILENT 예외는 정책 스킬을 건너뛰어 고정 문장을 직접 만들었다. 표 정규화는 기존 줄글을 표로 바꾸지 않아 이 경로가 남았다.

공통 `output_contract.incident_failure`로 조사 상태·확인된 원인·실제 조치의 미확인·다음 확인을 같은3열 표로 만든다. 알 수 없는 예외 문자열은 출력하지 않고 고정 진단 식별자로 제한한다. 시간초과/도구 인자 오류/중단/보고 부재를 구별하며 실제 적용·차단·승인 성공을 만들지 않는다. 특수 영향 근거 부족 표는 유지한다. 제어기 생성 알림을 ‘아래는 LLM 응답’이라고 쓰던 안내도 정정했다. 조사·승인·재전송·사건 종결 로직은 그대로다.

| 검증 | 실제 범위 |
|---|---|
| 회귀 | 최종 서버1,081PASS/skip0:관리268·SDK219·Native391·설치39·review60·workflow4·output7·events26·executor67. 반복 합산0 |
| 실제 게시 | [형식 보완 게시물](https://chat.grootlab.duckdns.org/soc/pl/yioa5ni8i7r7pmyxn5ty5djwyo). 이전 terminal 조사 결과의 표시만 새로 게시, 새 조사/승인/차단0. MattermostAPI로 머리글/구분선+내용4행·코드블록 없음 확인 |
| 브라우저 | CUA kernel assets 오류로 상태 조회 자체가 실패. reset 뒤에도 같아 이번 UI 렌더 성공으로 주장하지 않음 |
| 운영 | B helper/보고6파일10:00:15확정. root controller의 해당2함수와 helper 검증1함수 외 AST 유지. 세 프로필 output_contract SHA 동일, gate참조/보호설정7SHA·WS/worker/4서비스 확인. 이 단위의 채팅 재시작0 |

공통 스킬의 지시와 실제 예외 경로를 함께 연결했다. 과거 줄글4건은 감사 이력으로 유지하고 새 표의 형식 보완 게시를 구분한다. 모든 정상 모델 보고·모든 카드·단일 초장문 행/UI 전수 통과나 실제 사건 종결을 주장하지 않는다.

## 조사 지연의 별도 결과

과거 timeout run18은5MCP 합계 약0.5초, 본문 출력 마지막82.916초 뒤211.604초 결과까지 조용한 구간이 있었다. 단순히210초 제한을 늘리지 않았다. 이미 수행한 읽기의 시각·표본·표지 같은 고정 근거 오류만 정정할 때 verify 모드의 다음 요청1회에 none/2048토큰을 쓰고 이후 원래 추론으로 복원하는 좁은 경로를 추가했다. 초기 위험 판단·필수 근거가 빠진 경우·보호 변경·다른 모델/서버에는 적용하지 않는다.6개 회귀 검사를 추가했다.

새 Native 재검토는129.206초·읽기5성공+입력 스키마 거절1·needs_review다. 필수 후속 시간 구간의 소수점 경계를 모델이 줄여 재시도 단계가 남았고 해당 literal 보정 프로필은 실제 실행되지 않았다. 따라서214.272→129.206초를 이 변경의 속도 향상으로 귀속하지 않는다. manager로그 필수인자 누락·정확 필수 구간/광고된 스키마 준수·실제 영향/종결과 오류 복구는 잔여다.

## 복구

B의 `/var/lib/capstone-investigation-latency/20261105-r1/deployment`, `/var/lib/capstone-dns-context/20261105-r1/deployment`, `/var/lib/capstone-report-helper/20261105-r1/deployment`에 원본·manifest·rollback을 보존한다. 각 독립15분 타이머를 확인 후 해제하고 confirmed no-op을 확인했다. report/helper 원복은 controller/rule-worker lock과 현재 룰 SHA를 확인한다. 새 그룹을 쓰는 Wazuh 후보가 적용된 뒤에는 원래 정책을 먼저 복원하지 않고 구 검증기로 되돌리지 않는다. 실제 수동 원복 시험0·운영DB/승인/대화/가중치 보존이다.
