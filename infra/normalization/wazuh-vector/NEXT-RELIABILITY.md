# 남은 수집 신뢰성 작업: 최소 실행 순서

## 2026-10-14 19:38 KST 후속 — Indexer 시간 경계 보완 반영

Imperva/언어가드 기존로그 점검을마치고, 같은Indexer모니터를300초후보·정확60초sliding v2로갱신했다. native검색41개·lifecycle4단계·응답guard66개를통과했으며ID/권한/actions0·서비스/기존Wazuh룰은유지한다. 현재관리명령/검증/복구는 [v2운영안내](indexer-native/window-v2/OPERATIONS.md)를따른다. 자연스캔·최근Hermes사용표본은없어효과관찰대기다. 다음은WAF두reader회전격리→인증서관리이고장기지연/영속복구/정확히1회는별도다. 아래내용은각시점의기록이다.

## 운영 분석기 1/1 적용·실제 20회 종단 검증 완료 (2026-10-14 18:56 KST)

B의 `analysisd.event_threads=1`, `analysisd.rule_matching_threads=1`을 18:48:55 KST에 적용하고 **같은 manager 컨테이너를 한 번 재시작**했다. 기존 native 규칙 104개를 적용 전후 각각 통과했으며, 18:49:04의 새 analysisd PID는 `2132985`, 전체 스레드는 44개다. 다른 컨테이너와 보호 해시는 유지됐다. canary 없는 60.000186초 운영 관찰에서 수신 60건(약 1 EPS), drop 증가 0, queue 최대 표본 0, 단일 코어 대비 CPU 약 0.0333%를 확인했다. [적용·관찰 증거](correlation-fix/deployment-resume-2026-10-14.json).

사용자 명시 승인 후 실제 A agent001→B manager→Indexer의 **20회 × 13행(260행)** 시험을 18:56:08 KST에 완료했다. 동일 20개 run ID를 각각 한 번만 입력해 **manager 40건/Indexer 40건**, `100293` 20건·`100294` 20건, level 3·negative 경보 0건을 확인했다. 57/57 shard·strict CA/호스트명·각 run 및 전체 canonical tuple이 일치했으며 첫 조회 회차 11.3초, 입력 재시도 0회였다. A 원래 52행 접두 구간·inode·보호 설정과 B 옵션·룰·CID·SOC 안전 조건을 보존했다. 이 결과는 승인된 20회 시험의 성공이며 일반 트래픽의 장기 무손실 보장은 아니다. 기존 격리 1/1은 경보 4,000/4,000을 생성했지만 500 EPS 부하에서 queue 최대 표본 24%·최대 archive 관측 지연 약 10.04초가 있어 지속 처리량 보장은 아니다. [격리 부하와 한계](correlation-fix/LOAD-VALIDATION.md). 운영 raw copytruncate·WAF 두 reader 회전과 영속 복구의 남은 검증 범위는 그대로이며, worker 변경으로 수집 무손실·영속 ACK가 추가되는 것은 아니다. 아래의 미배포·반입 대기 설명은 이전 시점 기록이다.


**2026-10-14 18:18 KST 후속:** 검증기 고정ID 가정을 수정해47개 합성 및 기존 회차 대조를 통과했다. 각30,000행 격리 부하에서 worker1/1은 상관4,000건 전부 생성했고 자동설정은1,362건이었다(양쪽 입력drop0). 1/1은500EPS 시험 중queue최대표본24%·최대관측지연10.04초가 있어 지속처리량 보장과 구분한다. 운영 두옵션 변경안은 준비했지만 배포 검증94파일의B 반입이 자동 승인 검토에서 거절되어 사용자 전송 승인 대기다. 운영옵션/규칙/서비스 변경과 실제001 새burst는 아직 없다. [보완·검증·남은 적용](correlation-fix/README.md). 아래는 이전 기록이다.

**2026-10-14 13:12 KST 상관 누락 조사:** 격리한 실제 Wazuh의 사전 logtest 없는 자동 설정 20회에서 100293 누락 8회·100294 누락 7회를 재현했다(중복 2회). 1/1 작업자 대조 20회는 정상이며, 40회×13행의 archives 원문과 최종 판정/alerts를 전수 대조했다. 병렬 판정의 순서 경쟁이 유력하지만 agent 000 직접 큐 시험이므로 과거 운영 001의 세부 원인 확정·운영 누락률·완전 해결로 확대하지 않는다. 검증기의 반복 경보 eventID0005 고정 가정도 별도 문제로 확인했다. 다음은 그 검증기 보완과 판정 병렬도 후보의 부하 검증이며, 운영 설정·규칙·서비스는 유지했다. [근거·실측·후속](correlation-diagnosis/README.md). 아래는 이전 기록이다.

**2026-10-14 12:00 KST 검증:** A/B 보존 이전 boot 1,481건을 전수 대조했고 현재 nft 정제 후보는 0건이었다. 실제 보안 정제·색인 대상도 0건이며 운영 재주입은 하지 않았다. 별도 합성 대조14건 및 Wazuh native 순서8종을 검증했다. 새 간격 시험에서는 manager2건·Indexer2건의 정확 ID와57/57shard 성공을 확인했다. 앞선 일괄 시험의 manager1건/Indexer1건은 기대값 미달로 보존하며 누락 원인은 미확정이다. [검증 범위와 결과](history-replay-b/README.md). 후속 Suricata 격리 시험은 지연 공개 방식에서 Vector/Wazuh 각각6건·중복0, 연속2회전·정상재시작을 통과했다. 단순 rename 대조군은2건 누락을 재현했다. 운영 copytruncate는 유지하며 다음은 WAF별 검증과 운영 전환/영속 복구 조건 확인이다. [회전 결과](../vector/raw-rotation/README.md). 아래는 이전 시점 기록이다.

**2026-10-14 10:57 KST 후속 완료:** 이전boot 후속481건을 회수해 두배치1,481건/621,820bytes의 A→B 직접 전송·B 파일보관·A 수신증 저장을 검증했다. native 합성144개·실제 합성 응답유실 재시도 및 실제배치 해시/고유cursor를 확인했고 서비스는 유지됐다. Wazuh/Indexer ACK·전체무손실·운영 재주입을 뜻하지 않는다. 다음은 격리 정제와 Suricata→WAF raw 회전 검증이다. [실측과 운영 경계](../vector/history-transfer/README.md). 아래 내용은 이전 기록이다.

**06:25 KST 후속:** 이전boot `b807aba1…`의 고정 cutoff로 최대1,000건을 실제 보존했다. 결과는1,000건/418,810bytes·SHA 및 cursor 경계 확인·A서비스 PID/Invocation 불변이다. `source_range_exhausted=false`이며 다음배치 after-cursor, 별도 Vector 재생 정제, B 수신 절차는 아직 구현/실측하지 않았다. [실제 보존과 한계](../vector/history/README.md). 별도 evidence/관측 모니터는 [우선순위1 결과](indexer-native/README.md)로 적용됐으며 아래04:44의 미배포/monitor미생성 문구는 그 당시 계획이다.

2026-10-14 **04:44 KST A 읽기 확인**: raw Suricata/WAF는 `copytruncate`, 14회·500MiB 기준이다. Vector 0.59.0은 device/inode 방식의 활성 경로만 읽고 journal은 current boot/since-now다. persistent journal 디렉터리와 보관 boot 10개가 있다. agent buffer는 5,000건/EPS500이다. B Filebeat는 7.10.2이며 queue 별도 설정이 없다. A/B에는 rsync 3.2.7과 `--fsync`가 이미 있다. [메타데이터 증거](reliability-readonly-2026-10-14.json). 아래는 **미배포 실행안**이며 이번 조사는 원문·운영 파일·서비스를 변경하지 않았다.

| 순서 | 기존 도구의 최소 변경안 | 완료 판정과 안전한 중단 |
|---|---|---|
| **1. 이전 boot 자료를 먼저 보존** | `journalctl`의 고정 boot ID·종료 시각으로 종료형 export를 A root 전용 경로에 만든다. 먼저 1,000건/32MiB·15초의 기존 시험 범위부터 시작하고, cursor·boot·epoch·kernel transport를 유지한다. 별도 Vector stdin/file 시험에서 기존 nft VRL로 정제하되 `replay=true`, 실시간 상관 제외로 고정한다. | 원본 선택 범위·첫/끝 cursor·행수·바이트·SHA와 완료/부분 상태를 보관한다. cursor 재조회 실패·보존 만료·시간/용량 초과면 부분 회수로 표시한다. 현재 Vector checkpoint를 바꾸거나 운영 ready에 합치지 않는다. 기존 표본 1,000건에 nft가 0건이었다는 사실을 이전 boot 전체에 nft가 없다는 뜻으로 쓰지 않는다. |
| **2. 닫힌 배치의 B 보관을 확인** | 별도 데몬 없이 운영자용 Ansible/SSH·기존 rsync를 사용한다. A에서 고정한 소량 배치를 B의 임시 이름으로 전송→수신 SHA/크기 대조→수신 파일 fsync→같은 filesystem에서 최종 이름으로 원자 이동→디렉터리 동기화→고정 batch ID/SHA 결과를 A에 보관한다. 먼저 합성 배치로 수행한다. | A→B 직접 경로·고정 host key·제한된 계정/명령 권한을 먼저 확인한다. 새 권한을 자동 부여하지 않는다. 같은 ID/같은 SHA 재시도는 기존 파일 검증, 다른 SHA는 충돌 거절이다. 응답 유실·전송 중단·용량 부족·동기화 실패 시험을 통과해야 `remote_file_preserved`로 표시한다. SSH 종료0이나 rsync 전송 성공만으로 완료하지 않으며, `--delete`·`--remove-source-files`·원본 자동 삭제는 사용하지 않는다. **이 수신점은 B 파일 보관이며 Wazuh 분석·색인 ACK가 아니다.** |
| **3. raw 회전을 writer별로 분리** | 기존 한 묶음의 logrotate를 즉시 바꾸지 않는다. Suricata부터 실제 바이너리+합성 입력+격리 Vector/Wazuh reader로 rename/reopen 경계를 검증한다. 이전 writer가 닫히고 양 reader가 이전 세대를 소비한 뒤에만 새 세대를 고정 읽기 경로로 공개하는 세대별 경로/alias 후보를 비교한다. WAF는 그다음 별도 처리한다. | Suricata SIGHUP은 다음 쓰기에서 재열 수 있다. WAF는 USR1·같은 audit 경로 HUP이 실패했고 **새 audit 경로+HUP**만 이전 분리 시험을 통과했다. 늦은 요청이 옛 inode에 기록될 수 있다. old writer FD0, 마지막 marker·논리 EOF, 새 세대 첫 행, 연속 2회전·중단 재개·중복을 확인하기 전 운영 회전을 바꾸지 않는다. WAF audit/access 짝·배포 binding·고정 source path도 함께 유지해야 한다. |

**선택에서 제외할 단축안:** archive wildcard만 추가하면 inode 방식에서 복사본을 다시 읽을 수 있다. checksum fingerprint로 바꾸는 것만으로 기존 checkpoint를 안전하게 옮기지 못한다. Wazuh는 inode 변경 때 옛 reader를 닫으므로 단순 rename/HUP만으로 늦은 마지막 행의 소비를 보장하지 않는다. systemd255에서 Vector all-boots follow를 버전 위장이나 extra_args로 우회하지 않는다. 이전 boot의 정확한 미수집 시작점이 남아 있지 않으면 겹치는 구간을 명시적으로 회수하고 cursor 기반 ID로 대조한다.

**영속 수신의 남는 경계:** agent buffer 확대나 TCP 사용은 이벤트별 원격 commit receipt를 추가하지 않는다. 기존 `Vector → file → Wazuh` 경로의 일반 옵션만으로 이 구간 전체를 영속 확인으로 바꿀 수 없다. 추후 기존 Vector의 Elasticsearch sink→기존 Indexer를 별도 증거 저장 경로로 쓰는 대안은 있지만 Wazuh 분석을 경유하지 않으며, 전용 색인/쓰기 권한·부분 Bulk 실패·재시도·stable ID·수신 확인을 따로 시험해야 한다. 기본 partial-failure 재시도가 꺼져 있고 disk buffer의 동기화 전 구간도 있으므로 설정 추가만으로 해결 완료라고 쓰지 않는다. 이번에는 이 경로와 monitor를 만들지 않는다.

첫 구현 대상은 **종료형 journal export와 소량 배치 원격 보관 시험**이다. 기존 Ansible에 고정 대상 작업으로 넣고 일반 playbook·패키지·컨테이너 구성 권한을 LLM에 주지 않는다. 원문은 A/B에만 보관하고 Mac에는 건수·SHA만 남긴다. 이후 raw Suricata 회전, WAF 회전 순으로 진행하며 현재 원본 보존과 shadow 상관을 유지한다. EOF 과대 행의 telemetry 누락, source 보존 만료와 전원 장애까지 포함한 무손실 약속은 별도 검증 없이 하지 않는다.

근거: [기존 실제 writer 회전 시험](../ROTATION.md), [journal/과대 행 실측](../vector/collection/README.md), [Wazuh4.14.8 송신·메모리 buffer 경계](../DELIVERY.md), [systemd255 journalctl 소스 문서](https://github.com/systemd/systemd/blob/v255/man/journalctl.xml), [rsync `--fsync`](https://download.samba.org/pub/rsync/rsync.1), [Vector Elasticsearch sink의 ACK·ID·부분 실패 재시도](https://vector.dev/docs/reference/configuration/sinks/elasticsearch/). 이전 Python 구현은 삭제된 검증 이력이며 다시 운영 도입하는 계획이 아니다.
