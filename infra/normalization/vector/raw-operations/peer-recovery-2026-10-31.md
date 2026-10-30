# 2026-10-31 Vector 원본 회전 상호 대기 복구

A의 Vector 로그 정제가 실제로 멈춰 있었다. 03:46 KST 점검에서 마지막 정상 종료가 10/29 17:06:03 KST이고 출력 갱신도 중단됐음을 확인했다. Storage unavailable의 백업 JSON 유형 판정 오류와는 별개다. 사용자 보고의 Systemd 13건·Vector 비활성4건·회전실패3건은 경보 집계이며, 정확한 보고 구간과 13건 전체의 서비스 대응은 아직 확인하지 않았다. 이를 서로 다른 장애20개 또는 모두 같은 원인으로 세지 않는다.

## 원인과 수정

Suricata writer는 이미 새 원본 세대로 이동했지만 완료 intent가 남아 있었다. 동시에 WAF 회전이 공유 Vector 정지를 소유했다. Suricata는 다른 엔진의 정지 소유권 때문에 완료 기록을 정리하지 못했고, WAF는 남아 있는 Suricata intent 때문에 Vector 시작 가드에서 거절됐다.

`coordinator-writer-intent-fix.sh`는 reader 소유권 검사 전에 **기존 신호·정확한 writer identity·old closed/new open이 모두 검증된 전환만** 봉인하고 기록한다. 새 신호·alias 공개·reader 시작/정지·checkpoint 쓰기를 이 분기에서 수행하지 않는다. writer 미완료/두 파일 동시 open/identity 변경/기존 intent 부재는 각각 제한한다. 이후 기존 소유권·reader·원본 보존 가드는 유지한다.

A의 coordinator와 rebind 해시 핀2파일을 CAS·공유 잠금·root0400·원자 교체로 반영했다. 설치 진입점은 기존 `deploy.sh`이며 현재 candidate 매핑과 WAF cutover/rebind 핀을 함께 맞췄다. 기존10/14·10/15 동결 검증 기록과 일회성 진단 입력 해시는 당시 근거로 보존한다. B의 확인한 Vector source cache3경로는 없었고 추가 설치하지 않았다. 서비스/포트/패키지/보안 정책/LLM 권한은 추가하지 않았다.

## 실제 복구 확인

| KST | 확인 결과 |
| --- | --- |
| 03:52:30 | A2파일 반영. 배포 자체 서비스 신호0·원본/CP 덮어쓰기0 |
| 03:53:40 | Suricata 기존 writer 전환 완료 기록·intent 정리. 공유 정지 소유권 때문에 후속은 정상 보류 |
| 03:54:20 | WAF 기존 작업 재개로 Vector 시작. ready/evidence 출력 증가 |
| 03:59:23 | 03:58 예약 출력 회전 종료0·Vector 정상 재기동 |
| 04:00:14 | Suricata 예약 실행 종료0·active gen16/rev82 |
| 04:01:12 | WAF 예약 실행 종료0·active gen15/rev69 |
| 04:01:31 | Vector active, 실패 unit0, pending/intent0, 상태 점검 `recovery=no collection=[]`, 두 reader 가드 통과, 세 timer enabled/active |

ready/evidence 출력과 현재 invocation telemetry 갱신을 확인했다. B Indexer 03:59:23~04:00:37 KST에서 신규 Suricata 정제 evidence100261을5건 확인했고105 shard 성공·실패0·timeout false다. 같은 구간의100243/100244/40704는0건이다. 짧은 관측과 경보의 ignore 구간 때문에 0건 자체를 장기 무장애 보증으로 삼지 않는다.

첫 수동 재개는 예약 maintenance의 잠금으로 `coordinator_busy` 종료 후 별도로 재개했다. 이후 `new_reader_checkpoint_pending`, 활성 원본이 읽기 중 커진 `source_changed`, `reader_restart_guard_failed` 보류를 보존했으며 기존 예약 주기에서 성공했다. 결과 불명 타임아웃을 실패로 간주해 중복 실행하지 않았다. 과거 경보를 삭제하거나 정상으로 덮지 않았다.

04:03:31 KST 후속에서도 Vector PID1100883 유지·두 세대 active·pending0·telemetry 갱신·collection 상태 없음이며, 다음 예약 maintenance04:03:02 종료0을 확인했다.

## 검증과 복구

Linux에서 실제 private 파일/state·모의 서비스로 native33+30+24=87검사와 소스2검사를 통과했다(상위 wrapper5검사는 중복 집계하지 않음). Mac에서는 소스2통과·Linux 전용3생략, 초기 설치 계약39통과다. 격리 검사와 위 운영 성공을 구분한다. [원장·소스/증거 SHA](peer-recovery-validation-2026-10-31.json).

복구본은 A `/var/backups/capstone-vector-peer-recovery-20261031-035230`에 있다. 이전 코드2파일은 현행 SHA 확인·공유 잠금 하에서만 함께 복귀할 수 있다. 원복은 기존 상호 대기 결함을 다시 만들 수 있으므로 자동으로 수행하지 않는다. 백업된 state/intent/checkpoint는 증거이며 **진행된 운영 state나 native checkpoint를 옛 백업으로 덮어쓰지 않는다**. 이전 원본 Suricata gen15(95,605,150B)·WAF gen14(6,304B)를 root0400으로 보존했다.

중단 기간 전체 원본→정제→manager/Indexer 누락·중복 전수 대조, 실제 공격·LLM 승인·대응 E2E, 호스트 재부팅/새 서버 전체 설치는 미완료다. 운영 봇의 턴 시각/실패 인자 피드백 수정도 이 장애 대응으로 배포를 보류했으며 별도 작업이다.
