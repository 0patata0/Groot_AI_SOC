# 변경 승인·실행 기록 조회

`get_rule_change_status(proposal_id=...)`는 제안의 **실행 기록**을 읽는다. 새 승인·변경 적용·원복·알림 재전송을 실행하지 않는다. 실제 현재 파일은 `get_rule_change_target(target=...)`로 따로 읽는다. 이 구분은 두 봇의 공통 조회 계약에도 적용된다.

| 필드 | 의미와 한계 |
| --- | --- |
| `status` | 실행기에 저장된 pending/prepared/applied/rolled_back/recovery_failed 등의 상태. 현재 서비스 건강 상태가 아니다. |
| `approval_status` / `approval_status_source` | pending/prepared는 서명 검증된 브로커 조회, 완료 기록은 저장된 승인 소모 또는 거부/만료 근거. `unavailable`은 승인 조회 실패이고 `unknown`은 근거 미기록이다. 실행 pending만으로 미승인이라 판단하지 않는다. |
| `approval_consumed` | 실행기에 저장된 일회 승인 소모 여부. 필드가 없는 과거 기록은 null이며 false로 채우지 않는다. 브로커 consumed와 로컬 prepared가 함께 있으면 상태 조정이 필요한 기록으로 보존한다. |
| `result_posted` / `result_delivery.status` | confirmed는 기존 브로커의 결과 게시 확인이다. 사용자 읽음·단말 표시·모바일 푸시 수신의 증명은 아니다. retry_pending은 결과 알림 재전송 대기이며 변경을 재실행하지 않는다. abort_confirmed/abort_pending/abort_report_error는 적용 전 중단 알림을 구분한다. |
| `before_sha256` / `after_sha256` | 제안의 원본/후보 해시. 후보는 아직 승인되지 않았을 수도 있다. |
| `recorded_result.readback_sha256` | 실행 결과 보고용으로 저장한 과거 읽기 해시. 현재 파일 해시가 아니다. |
| `current_file_checked` | 이 도구에서는 false. 현재 파일 비교가 요청되면 별도 읽기 결과의 실제 content/SHA를 검증한다. |
| `observed_at_kst` | 이번 기록 조회 시각이며 과거 적용 시각이 아니다. |

예: `WAF 변경 <실제 제안 ID> 승인됐어? 적용 여부와 결과 알림까지 확인해줘.`, `Wazuh 변경 <실제 제안 ID> 지금 상태도 확인해줘.` 짧은 승인·적용·원복 질문도 실제 ID와 장비가 식별되면 상태 조회로 분류한다. 호출은 모델이 선택하고, 제공한 ID·대상 범위만 선택 스키마에 남긴다. 실제 변경 명령·인용문·64자리 파일 해시를 조회 제안 ID로 바꾸지 않는다. 대상 또는 반환 ID가 맞지 않는 응답은 완료 근거가 되지 않는다.

현재 파일이 원본과 같아도 과거 `recovery_failed`가 성공으로 바뀌지는 않는다. 파일 복원과 당시 서비스 검증 실패는 함께 존재할 수 있다. 현재 container running만으로 내부 필수 프로세스·개별 룰 적재 정상까지 보장하지 않는다.

초기 설치 진입점은 루트 `deploy.sh`를 유지한다. 기존 소스 반입 경로의 `rule_change_executor.py`, 두 봇 공통 `read_contract.py`·`harness.py`가 변경 대상이며 새 패키지·설정 키·포트·권한은 없다. 기존 서버에는 읽기 메서드와 공통 조회 소스를 증분 배포한다. root 백업 manifest에 원본 경로·SHA·소유권·모드가 있고, 복구 시 이를 대조해 파일을 복원한 뒤 유휴 상태에서 봇 연결과 관리 timer를 확인한다. 설치기로 운영 서버 전체를 덮어쓰지 않는다.

2026-10-30 복구점은 A `/var/backups/capstone-change-status-20261030-211238`, B `/var/backups/capstone-change-status-20261030-211343`이다. B의 복구용 소스 묶음에는 앞서 운영에 적용됐지만 빠져 있던 Wazuh XML 주석 검사와 회귀 검사도 동기화했다. 자동 복구 분기는 준비했으며 이번 정상 배포에서 실패 복구를 강제로 실행하지 않았다. 실제 검증 범위·생략·Git 결과는 [STATUS.md](../../STATUS.md)를 따른다.
