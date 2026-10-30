# 서비스·임시차단 상태와 IDS 적재 통계 조회

서비스 재시작/재로드 및 임시차단의 요청 ID는 `get_operation_status(request_id=...)`로 읽는다. 룰 파일 제안 ID를 읽는 `get_rule_change_status`와 구분한다. WAF·IDS·채팅 프록시·임시차단은 A, Wazuh Manager·Dashboard는 B가 담당한다.

두 봇의 공통 조회 계약은 요청 ID와 대상이 명확하면 해당 읽기 도구와 인자만 모델에 제시한다. 모델이 도구를 선택·호출하며 하네스가 조사 판단이나 보호 작업을 자동 실행하지 않는다. `missing or ambiguous` 응답은 조회 실패다. 등록되지 않음·삭제·만료·다른 서버 제출 중 하나로 단정하거나 현재 차단이 없다고 바꾸지 않는다. 같은 실패를 무작정 재호출하거나 새 변경안을 제출하지 않는다.

예: `WAF 재시작 요청 <요청 ID> 처리됐어?`, `임시차단 요청 <요청 ID> 지금도 차단 중이야?`, `Wazuh Manager 재시작 요청 <요청 ID> 결과와 현재 상태 알려줘`. 현재 서비스가 요청되면 `get_service_action_target`을 별도로 읽고 observation의 해시를 검증한다. 현재 가동 중이라는 사실은 과거 재시작 요청의 승인·실행 성공을 입증하지 않는다.

| 임시차단의 실제 관측 | 의미 |
| --- | --- |
| `owned` | 이번 요청이 소유한 규칙이 현재 조회에서 확인됨 |
| `foreign` | 다른 소유의 규칙이 확인됨 |
| `absent` | 조회한 nft 집합에서 부재. 전체 방화벽·WAF의 허용을 뜻하지 않음 |
| `unavailable` | 실시간 차단 상태 조회 실패. 미차단이나 만료가 아님 |

과거 워크플로의 `owned_deadline`과 현재 조회의 `live_owned_deadline`·`live_remaining_seconds`를 구분하고 표시 시각은 KST로 변환한다. 과거 기한만으로 현재 차단 여부를 계산하지 않는다. 승인 상태가 없는 과거 기록은 미확인이며, 브로커 조회 불가는 승인 대기로 바꾸지 않는다.

## IDS 엔진 통계

`get_service_action_target(target="a:suricata")`는 기존 서비스 observation·파일 근거와 별도로 `rule_engine_evidence`를 반환한다. 고정된 Suricata 소켓 읽기 명령 `ruleset-reload-time` → `ruleset-stats` → `ruleset-reload-time` 및 전후 컨테이너 관측만 사용한다. 재적재·재시작은 실행하지 않는다.

| 필드 | 의미 |
| --- | --- |
| `status` | `observed` 또는 `unavailable` |
| `rules_loaded` / `rules_failed` / `rules_skipped` | 실제 단일 tenant(id=0) 엔진 카운터. 조회 실패를 숫자 0으로 채우지 않음 |
| `last_reload_kst` / `observed_at_kst` | 마지막 엔진 적재 시각 / 이번 통계 관측 시각 |
| `container_id` | 같은 조회의 서비스 observation에 연결된 컨테이너 |
| `per_sid_load_verified` / `current_file_load_verified` | 모두 false. 전체 카운터는 개별 SID나 현재 디스크 파일과 적재 세대의 일치 증명이 아님 |

읽기 도중 컨테이너 ID·시작 시각 또는 마지막 적재 시각이 달라지거나, 카운터/시각이 유효하지 않으면 `unavailable`로 남긴다. 로딩 실패가 실제 0인 관측과 통계를 읽지 못한 상태를 구분한다. 실제 엔진 적재 수 0도 유효한 관측이며 정상이라는 뜻이 아니다. 카운터는 승인용 observation/base_state_sha256에 섞지 않는다. 소스 변경으로 서비스 정책 해시는 바뀌므로 기존 승인의 정책 검증을 건너뛰지 않는다.

## 설치·복구·검증 범위

초기 진입점은 루트 `deploy.sh`다. 기존 `service_action_executor.py`, 공통 `read_contract.py`·`harness.py` 복사 경로를 사용한다. 추가 패키지·이미지·포트·설정 키·도구 권한은 없으며 오프라인 소스 묶음을 갱신한다. 운영 서버에는 증분 반영하고 초기 설치기로 전체를 덮어쓰지 않는다.

2026-10-30 A/B 복구점은 각 서버의 `/var/backups/capstone-operation-reads-20261030-214209`다. root 전용 manifest의 원본 SHA·소유권·모드를 대조해 복원한다. 원래 없던 소스 묶음 파일은 manifest의 null 원본 표시를 따른다. 봇이 유휴일 때 공통 소스를 함께 복원한 뒤 기존 봇 프로세스와 관리 timer·연결 상태를 확인한다. IDS/WAF를 재시작할 필요는 없다.

실제 관측·채팅 검증과 격리 실패 시험, 실제 보호 작업/원복 및 새 서버 전체 설치 여부는 [STATUS.md](../../STATUS.md)를 따른다. 존재하는 서비스·임시차단 요청의 운영 실행 기록이 없는 상태에서 누락 ID 시험을 성공한 보호 작업 시험으로 세지 않는다.
