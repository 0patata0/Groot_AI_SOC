# Indexer 시간창 v2 운영 관리

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../../STATUS.md) · [실행 계획](../../../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

2026-10-14 19:38:41 KST에 기존 모니터를 v2로 갱신했고 같은 ID·권한·활성 상태·주기를 보존했다. 원본 백업과 독립 GET을 확인했다. 변경 후19:39:25/19:40:25 두 정기 실행은 on_time=true였고, 별도19:40:32 dryrun은57/57shard 성공·유효한empty·두trigger false·내부alert0이었다. 컨테이너/서비스/analysisd PID·보호hash는유지됐고drop0이다. [배포·관찰 증거](deployment-2026-10-14.json)를 참고한다. [판정 계약](README.md)과 [후보 원본](monitor.json)을 함께 확인한다. v1 원본과 helper는 이전 배포 이력으로 보존한다.

## 관리 명령

아래 명령은 B 관리자 전용이다. LLM/MCP에 새 실행 권한을 부여하지 않는다. 설치 경로는 `/opt/capstone-automation/project/infra/normalization/wazuh-vector/indexer-native/window-v2/`이다.

```sh
sudo python3 -B /opt/capstone-automation/project/infra/normalization/wazuh-vector/indexer-native/window-v2/manage-monitor-b.py inspect
sudo python3 -B /opt/capstone-automation/project/infra/normalization/wazuh-vector/indexer-native/window-v2/manage-monitor-b.py observe
```

`inspect`는 고정 v1/v2 SHA registry와 관리 state에 따라 정확한 후보를 선택해 ID·revision·전체 설정 해시·이름의 유일성을 검사한다. `observe`는 같은 검사 뒤 scheduler 상태를 읽는다. 실행 시각 갱신은 해당 검색의 성공이나 사건 수신증을 뜻하지 않는다.

## 적용과 복구

`upgrade`는 검증된 같은 monitor를 v2로 갱신한다. 같은 ID·enabled 상태·schedule·trigger ID·actions·user/권한·기타 메타데이터를 보존하고 입력 검색과 trigger condition만 교체한다. 공유 lock을 잡고 원본 GET/state를 root 전용 `/var/backups/capstone-indexer-window-*`에 fsync 보관한 다음, pending 수신증과 원래 revision에 결속한 CAS PUT을 한 번 수행한다. 응답과 독립 GET이 일치해야 v2 state를 원자 갱신한다. 같은 v2를 다시 요청하면 검증 후 변경 없이 종료한다.

```sh
# 격리 native 검증과 최신 상태 확인을 마친 관리자가 실행
sudo python3 -B /opt/capstone-automation/project/infra/normalization/wazuh-vector/indexer-native/window-v2/manage-monitor-b.py upgrade
```

복구가 필요하면 같은 helper의 `rollback`으로 현재 v2 revision·전체 설정을 검증한 뒤 고정 v1의 입력/condition만 CAS 복원한다. 현재 권한과 상태는 그대로 유지한다. `disable`은 정상 관리 상태의 동일 monitor를 비활성화한다. 과거 v1 helper는 v2 state를 거절하므로 현재 관리에는 위 경로를 사용한다.

```sh
sudo python3 -B /opt/capstone-automation/project/infra/normalization/wazuh-vector/indexer-native/window-v2/manage-monitor-b.py rollback
sudo python3 -B /opt/capstone-automation/project/infra/normalization/wazuh-vector/indexer-native/window-v2/manage-monitor-b.py disable
```

HTTP 응답 불명확·CAS 충돌·독립 GET 불일치면 자동 재시도나 이름을 근거로 한 monitor 채택을 하지 않는다. pending state와 backup의 원본/acknowledged-update/readback을 보존하고 정확한 ID를 읽어 원본·검증된 후보·제3의 변경 중 어느 상태인지 먼저 판별한다. 수동으로 pending을 지우거나 PUT을 반복하면 안 된다. 정상 관리 상태에서의 rollback은 로컬 mutation 시험으로 검증하며, 장애·전원 종료 중 실제 복구는 별도 시험이다.

OpenSearch 2.19의 update 경로는 true→true 갱신에서 서버의 기존 `enabled_time`을 보존한다. 관리 helper는 실제 응답에서도 그 값의 동일성을 검사한다. [공식 구현](https://raw.githubusercontent.com/opensearch-project/alerting/2.19/alerting/src/main/kotlin/org/opensearch/alerting/transport/TransportIndexMonitorAction.kt#L604-L612).

## 검증 경계

- [변경기 유한 시험](migration-tests-2026-10-14.json): 14개. 권한/시각/동작 변경, stale revision, 불명확 PUT, 변경된 readback, SHA 불일치 및 script 매개변수 정규화를 검사한다.
- [native 검색·수명주기 검증](native-validation-2026-10-14.json): 실제2shard 검색41개와 경보 수명주기4단계, schema8 동일설정 CAS를 통과했다. 전용 합성index·disabled/actions 없는 monitor만 사용했고 삭제 후404를 확인했다. 운영 Wazuh 입력은 추가하지 않았다.
- [native 응답 guard 검증](guard-validation-2026-10-14.json): 합성 context66개(정상10/거절56)를 정확한 원본 Painless로 대조했다. 실제 shard 장애를 일으킨 시험은 아니다.
- `true→true`는 같은 trigger의 active alert ID를 유지하고, false는 완료, 다음 true는 새 ID다. COMPLETED는 관찰 조건의 해제이며 공격 종결을 증명하지 않는다. 검색이 unavailable인 회차에도 match는 false여서 기존 match alert가 완료될 수 있다. 서비스별 사건 ID 영속 중복 제거·cooldown·정확히 한 번 전달은 제공하지 않는다.
- 검색 성공·두 주기 scheduler 관측·짧은 runtime 결과는 장기간 무손실, 지속 부하 용량, 모든 색인 지연의 보장이 아니다.

## 작업 마감

소스·문서42개를 B 프로젝트에 보관하고 증거A33/B114파일을 해시대조 보존했다. 두서버작업stage와Mac임시135파일을정리했고설치0·운영상태불변을확인했다. [전체 마감](finalization-2026-10-14.json) · [B 보존/정리](finalization-b-2026-10-14.json). 최종마감파일과이문구는42파일서버스냅샷후행기록이다.
