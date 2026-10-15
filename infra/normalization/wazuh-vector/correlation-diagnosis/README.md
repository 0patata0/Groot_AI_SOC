# 상관 경보 누락 진단

2026-10-14: 운영 manager를 변경하지 않고, B에 설치된 Wazuh 4.14.8 분석기·룰의 독립 복사본에서 상관 경보 누락을 재현했다. 모든 시험의 입력은 전용 합성 자료이며, 운영 큐·설정·룰·계정과 연결하지 않았다. `retrospective-b.json`은 과거 burst/paced 결과를 읽기 대조한 별도 증거다.

## 완료한 실측

[smoke-validation-2026-10-14.json](smoke-validation-2026-10-14.json)의 4차 smoke는 13개 원문 전달·보관과 경보 2개를 확인했다. 첫 시도는 호스트에 없는 `wazuh` 그룹 조회로 입력 전 종료됐다. 2·3차는 읽기 전용 `/dev/urandom` FD가 보수적 허용 목록에 없어 입력 전 종료됐다. 세 실패 모두 자식 정리와 운영 원본 불변을 확인한 뒤, 관측한 조건만 좁게 보완했다.

[matrix-validation-2026-10-14.json](matrix-validation-2026-10-14.json)은 각 스레드 조합에서 ID 재사용/고유화, S→N/N→S, burst/교차 앞 3초 간격/행별 100ms 간격을 한 번씩 대조한 48개 사례다. 같은 private 프로세스의 별도 logtest 세션에서 각 사례의 순차 기대 ID를 검사한 후 실제 큐에 전송했다.

| JSON 디코딩 / 룰 판정 설정 | 사례 | 반복 100293 누락 | S→N의 100294 누락 | N→S의 예상 밖 100294 |
|---|---:|---:|---:|---:|
| 자동 / 자동 | 12 | 1 | 0 | 0 |
| 1 / 자동 | 12 | 3 | 0 | 0 |
| 자동 / 1 | 12 | 0 | 0 | 0 |
| 1 / 1 | 12 | 0 | 0 | 0 |

48개 사례의 원문 624개가 모두 exact archives 검증을 통과했다. 기록된 최종 판정과 alerts는 모두 일치했고, 기대 경보 72개 중 실제 68개였다. 따라서 이 실행에서 확인한 4개 반복 경보 누락은 입력 수신 누락 또는 alerts writer 기록 지연과 구분된다. 자동 설정은 기존 4코어 환경에서 사용한 값이며 실제 전체 스레드는 50/47/47/44개였다. 위 수치는 이 유한 시험의 관측값으로, 장기 누락 확률이 아니다.

[native-only-validation-2026-10-14.json](native-only-validation-2026-10-14.json)은 13:10:32 KST에 완료했다. 새 private 프로세스에서 사전 logtest를 **한 번도 호출하지 않고** 자동/자동과 1/1을 각각 20회 비교했다. 모두 S→N burst이며 각 조합은 ID 재사용 10회와 고유 ID 10회다.

| JSON 디코딩 / 룰 판정 설정 | 사례 | 반복 100293 누락 | 교차 100294 누락 | 하나 이상 누락된 사례 | 실제 / 기대 경보 |
|---|---:|---:|---:|---:|---:|
| 자동 / 자동 | 20 | 8 | 7 | 13 | 25 / 40 |
| 1 / 1 | 20 | 0 | 0 | 0 | 40 / 40 |

자동 조합에서 두 종류가 모두 빠진 사례가 2개여서 8+7개 누락이 13개 사례에 발생했다. 재사용 ID 10회 중 6회, 고유 ID 10회 중 7회에서 불일치했다. 40개 사례의 원문 520개와 최종 alerts writer 대조가 모두 정상이며, 별도 프로세스의 1/1은 20회 모두 기대 경보 2개를 만들었다. 그러므로 이 환경의 병렬 조건에서 **실제 상관 판정 누락을 재현했으며, ID 재사용이나 logtest 선행 호출만으로 설명되는 문제는 아니다.**

집계와 범위 제한은 [summary-2026-10-14.json](summary-2026-10-14.json)에 기계 검증 가능한 형태로 보존했다. matrix와 native-only의 source SHA는 해당 서버 trial의 동결 사본과 결속된다. 성공 smoke 소스도 별도 보관했다. smoke 성공본은 `06334689…`, matrix는 `2771db06…`, native-only 및 최종 runner는 `605f5296…`이다. 앞선 실패 시도의 소스 SHA도 smoke 이력에 보존했다.

운영 archives가 비활성화된 과거 burst의 13개 전체 수신·처리 순서는 복원할 수 없다. 과거 `native-canary-b.sh`의 8개 검사는 Phase 1 건수를 자동 확인했지만 기대 룰 ID 목록은 자동으로 단정하지 않았다. smoke·matrix 진단기는 기대 ID를 명시적으로 비교했고 native-only는 사전 logtest를 생략했다.

## 격리와 실행 순서

1. 고정 B machine-id와 단일 manager의 CID/시작 시각, analysisd PID/시작 tick, `/var/ossec`·운영 큐 inode, 바이너리·설정·기존 룰 SHA를 기록한다.
2. root 전용 task 아래 새 prefix에 분석기, `libwazuhext.so`, 기존 룰·디코더·목록과 내부 옵션만 복사한다. 운영 `ossec.conf`에서는 상대 `ruleset` 참조만 가져오며, 나머지 운영 설정 본문, agent DB, client.keys, 큐 소켓, 인증 자료는 복사하지 않는다. 생성 설정에는 archives JSON, 레벨 3 alerts JSON, private logtest만 있다.
3. 새로운 mount/network namespace에서 mount propagation을 private으로 고정하고 복사한 분석기를 `-f -u root -g root -D <prefix>`로 실행한다. 호스트에 없는 그룹 조회를 충족하려고 rprivate 처리 뒤 private 최소 group/passwd만 해당 namespace의 `/etc/group`·`/etc/passwd`에 읽기 전용 bind한다. 호스트 원본의 inode·SHA·권한은 전후 대조한다. 별도 네트워크 연결, active response, integration, Indexer/filebeat가 없다. 전용 root UID는 시험 전제이며 운영 daemon UID와 같다고 주장하지 않는다. `/proc/<PID>/root`·cwd·namespace·열린 파일 및 운영 분석기 socket inode와 비공유를 확인한 뒤에만 private 큐에 입력한다. 허용되는 외부 character device는 `/dev/null`과 정확한 읽기 전용 `/dev/urandom`뿐이다.
4. 첫 실행은 agent `000`, 자동 스레드, 13개 입력 한 묶음만 수행한다. `000`은 labels DB 조회를 생략한다. 이 결과를 운영 agent `001`의 전체 전송 경로와 동등하다고 해석하지 않는다. native WDB는 기동하지 않았다. 빈 private WDB 경로에 대한 MITRE/통계 조회 재시도는 발생하지만 canary 룰은 MITRE를 사용하지 않는다. 운영 `001`/WDB/daemon UID와 다른 제한된 메커니즘 시험이다.
5. 성공 후 자동/자동, 디코딩 1·룰 자동, 디코딩 자동·룰 1, 1/1 조합을 비교했다. ID 재사용/고유 ID, S→N/N→S, burst/cross 앞 3초 간격/행별 100ms 간격을 각각 분리한다. 한 번에 분석기 하나만 실행한다. 운영 스레드 설정은 바꾸지 않는다.
6. 새 private 프로세스에서 native-only 40개 사례를 실행할 때는 `logtest_executed=false`, `logtest_rule_ids=null`로 기록한다. 이전 순차 기대값과 실제 archives/alerts를 비교하되 해당 사례가 logtest 검사를 받았다고 표기하지 않는다.
7. 직접 실행한 자식 PID·시작 tick만 종료했다. 전후 운영 신원·해시가 일치해야 한다. 시험 루트와 native 로그는 서버에 남겨 부모가 결과 보관 후 정리하며, Mac에는 집계·검증 메타데이터만 전달한다.

## 판정 계약

- 실제 송신은 JSON 뒤 NUL 1바이트를 포함한 private UNIX datagram 13개다. `send()` 성공은 커널 접수이며 분석 ACK가 아니다.
- 매 행에는 별도 `delivery_seq`가 있다. 중복 시나리오는 동일 논리 event/dedupe ID를 5회 유지한다. 전달 순번은 다르므로 전송 바이트가 완전히 동일한 재전송 시험은 아니다. 고유 ID arm은 run/scenario/source/logical sequence를 해시한다.
- smoke와 matrix는 같은 private 분석기의 logtest 세션에서 순차 기대 룰 ID 13개를 먼저 엄격 확인했다. native-only는 이 단계를 생략했다. private 큐 처리에서는 archives의 13개 전달 순번·원래 JSON 전체 일치와 alerts의 실제 룰별 개수를 따로 기록한다. 기대 경보 개수가 다르면 원인 조사 결과로 남기며 성공으로 바꾸지 않는다.
- S→N의 순차 기대값은 반복 `100293` 1건과 교차 `100294` 1건이다. N→S는 canary가 역방향 룰을 갖지 않으므로 반복 1건만 기대한다.
- archives는 룰 처리 후 별도 큐에 기록되므로, 그 순서를 최초 입력 수신 순서 또는 SID 이력 등록 순서로 단정하지 않는다. 본 시험은 remoted/agent/Indexer·알림 경로를 시험하지 않는다.

## 공식 4.14.8 소스 근거

- [analysisd.c](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/analysisd.c): `-D` 뒤 chdir/chroot, 입력·디코딩·룰 큐와 스레드, 판정 뒤 SID 이력 등록 및 archives 전달. 병렬 처리 가설의 근거이며 실제 누락 원인을 소스만으로 확정하지 않는다.
- [logtest.c](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/logtest.c): 세션별 event list와 mutex, 동기 디코딩/판정. 실제 병렬 큐와 다른 경로다.
- [labels.c](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/labels.c): agent `000`의 전역 labels와 다른 agent의 WDB 캐시 조회가 다르다.
- [os_net.c](https://github.com/wazuh/wazuh/blob/v4.14.8/src/os_net/os_net.c): native datagram의 NUL과 logtest stream의 little-endian 길이 프레임.
- [defs.h](https://github.com/wazuh/wazuh/blob/v4.14.8/src/headers/defs.h): private chroot 내부의 상대 queue/log 경로.

## 적용 판단과 남은 한계

운영 병렬 설정에서 발생한 과거 특정 canary의 모든 수신 기록이 없으므로, 그 한 건의 세부 실행 순서를 확정하지 않는다. 이번 독립 시험은 동일 설치 바이너리·룰에서 병렬 조건과 상관 판정 누락의 관련성을 확인했다. 원천 시각 기준 집계나 전체 서비스 부하에서의 처리 보장까지 확인한 결과는 아니다. 사전 logtest는 별도 세션 상태를 사용하지만, 프로세스 실행 이력·스케줄링 영향도 분리하려고 native-only 대조를 추가했다.

배포 후보는 디코딩과 룰 판정의 직렬화다. 이번 시험에서는 운영 설정을 변경하지 않았다. 운영 적용 전에는 실제 수신량과 큐 적체 여유, 처리 지연, manager 재시작·복구 조건을 별도 검토해야 한다. 행 사이 고정 지연은 진단 보조이며 처리 완료 ACK나 운영 무누락 보장이 아니다. 여러 원천의 실제 발생 시각 순서까지 보장하지 않는다.

독립 리뷰에서 기존 canary 검증기의 반복 경보 event ID를 `0005`로 고정한 조건도 한계로 확인했다. 동일 5개 이벤트가 병렬 처리되면 다른 전달 행에서 `100293`이 발화할 수 있다. smoke에서는 4번 행, matrix에서는 다른 행에서도 발화했다. 검증기는 올바른 run/scenario·허용된 5개 논리 이벤트·한 번의 반복 경보라는 조건으로 판단해야 한다. 이것은 경보 자체가 1개뿐이었던 과거 누락과 별개의 검증기 문제다.

새 패키지·계정·키·컨테이너·상시 서비스·MCP 권한은 추가하지 않았다. Mac에는 검증 코드와 메타데이터만 두었고 시험 중 native 로그는 서버의 private task에 보관했다. 모든 자식 종료와 운영 신원·해시 불변을 확인한 결과만 완료로 보관한다.

## 최종 보관·정리 (13:17 KST)

A/B의 `/opt/capstone-automation/project/`에 관련 소스·문서23개씩(731,286bytes)을 SHA 대조해 보관했다. 변경 전 소스는 `/var/backups/capstone-correlation-source-20261014/`, 읽기 확인·성공/실패 시험·동결 실행 소스·합성 native 원문 증거는 `project/evidence/correlation-20261014/`에 보존했다. A metadata 3개/B219개를 별도로 보관했다.

삭제 전 모든 보관 파일의 SHA/크기, 운영 불변 확인 결과와 시험 프로세스 부재를 대조했다. A 임시27파일(768,434bytes), B3,538파일(172,598,071bytes), Mac51파일(853,878bytes)을 삭제하고 경로 부재를 확인했다. 설치 패키지·새 컨테이너0이며, 기존 운영 자료·복구 백업은 유지했다. [마감 수치](finalization-2026-10-14.json). 이 문단과 마감 JSON은23파일 서버 소스 스냅샷 이후 작성됐다. 서버의 별도 preservation/cleanup JSON이 보관·정리 증거다.
