# 회전 점검 타이머 시각 분산

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../../STATUS.md) · [실행 계획](../../../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

2026-10-15 WAF 전환 후 세 타이머를 동시에 복원하자 같은 시각의 maintenance가 공유 잠금을 잡아 두 원본 점검이 두 차례 coordinator_busy로 보류됐다. 기존 5분 주기를 유지하면서 Suricata는 매시00/05/10…분, ModSecurity는01/06/11…분, 출력 maintenance는03/08/13…분에 실행한다(KST).

각 파일은 해당 `.timer.d/20-capstone-stagger.conf`에 설치하는 drop-in이다. `OnBootSec=` 빈 값은 기존 단조 시계와 달력 trigger 목록 전체를 비운다. 이후 정확히 하나의 달력식을 추가한다. 기존 Persistent=false를 유지한다. 서비스나 수집기를 재시작하지 않고 timer만 다시 시작한다.

긴 작업이나 관리자 잠금이 겹치면 기존 exit2 보류는 유지하며 다음 5분 주기에 다시 점검한다. 원본/체크포인트/회전 기준 변경은 없다. 초기 설정·실측과 이후 검증 결과는 [재생성 검증 기록](../../../../groot-a/imperva-exception/recreation-validation-2026-10-15.json)을 따른다.

[systemd255 timer 지침](https://raw.githubusercontent.com/systemd/systemd/v255/man/systemd.timer.xml)의 빈 timer옵션 초기화 및 AccuracySec 동작을 확인했고 실제 A systemd-analyze calendar가 5분 간격으로 해석했다.
