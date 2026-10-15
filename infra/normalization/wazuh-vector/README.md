# Vector → Wazuh 기초 입력

## 2026-10-14 19:38 KST 후속 — Indexer 시간 경계 보완 반영

Imperva/언어가드 기존로그 점검을마치고, 같은Indexer모니터를300초후보·정확60초sliding v2로갱신했다. native검색41개·lifecycle4단계·응답guard66개를통과했으며ID/권한/actions0·서비스/기존Wazuh룰은유지한다. 현재관리명령/검증/복구는 [v2운영안내](indexer-native/window-v2/OPERATIONS.md)를따른다. 자연스캔·최근Hermes사용표본은없어효과관찰대기다. 다음은WAF두reader회전격리→인증서관리이고장기지연/영속복구/정확히1회는별도다. 아래내용은각시점의기록이다.

## 운영 분석기 1/1 적용·실제 20회 종단 검증 완료 (2026-10-14 18:56 KST)

B의 `analysisd.event_threads=1`, `analysisd.rule_matching_threads=1`을 18:48:55 KST에 적용하고 **같은 manager 컨테이너를 한 번 재시작**했다. 기존 native 규칙 104개를 적용 전후 각각 통과했으며, 18:49:04의 새 analysisd PID는 `2132985`, 전체 스레드는 44개다. 다른 컨테이너와 보호 해시는 유지됐다. canary 없는 60.000186초 운영 관찰에서 수신 60건(약 1 EPS), drop 증가 0, queue 최대 표본 0, 단일 코어 대비 CPU 약 0.0333%를 확인했다. [적용·관찰 증거](correlation-fix/deployment-resume-2026-10-14.json).

사용자 명시 승인 후 실제 A agent001→B manager→Indexer의 **20회 × 13행(260행)** 시험을 18:56:08 KST에 완료했다. 동일 20개 run ID를 각각 한 번만 입력해 **manager 40건/Indexer 40건**, `100293` 20건·`100294` 20건, level 3·negative 경보 0건을 확인했다. 57/57 shard·strict CA/호스트명·각 run 및 전체 canonical tuple이 일치했으며 첫 조회 회차 11.3초, 입력 재시도 0회였다. A 원래 52행 접두 구간·inode·보호 설정과 B 옵션·룰·CID·SOC 안전 조건을 보존했다. 이 결과는 승인된 20회 시험의 성공이며 일반 트래픽의 장기 무손실 보장은 아니다. 기존 격리 1/1은 경보 4,000/4,000을 생성했지만 500 EPS 부하에서 queue 최대 표본 24%·최대 archive 관측 지연 약 10.04초가 있어 지속 처리량 보장은 아니다. [격리 부하와 한계](correlation-fix/LOAD-VALIDATION.md). 아래의 미배포·반입 대기 설명은 이전 시점 기록이다.


**2026-10-14 18:18 KST 후속:** 검증기 고정ID 가정을 수정해47개 합성 및 기존 회차 대조를 통과했다. 각30,000행 격리 부하에서 worker1/1은 상관4,000건 전부 생성했고 자동설정은1,362건이었다(양쪽 입력drop0). 1/1은500EPS 시험 중queue최대표본24%·최대관측지연10.04초가 있어 지속처리량 보장과 구분한다. 운영 두옵션 변경안은 준비했지만 배포 검증94파일의B 반입이 자동 승인 검토에서 거절되어 사용자 전송 승인 대기다. 운영옵션/규칙/서비스 변경과 실제001 새burst는 아직 없다. [보완·검증·남은 적용](correlation-fix/README.md). 아래는 이전 기록이다.

**2026-10-14 13:12 KST 상관 누락 조사:** 격리한 실제 Wazuh의 사전 logtest 없는 자동 설정 20회에서 100293 누락 8회·100294 누락 7회를 재현했다(중복 2회). 1/1 작업자 대조 20회는 정상이며, 40회×13행의 archives 원문과 최종 판정/alerts를 전수 대조했다. 병렬 판정의 순서 경쟁이 유력하지만 agent 000 직접 큐 시험이므로 과거 운영 001의 세부 원인 확정·운영 누락률·완전 해결로 확대하지 않는다. 검증기의 반복 경보 eventID0005 고정 가정도 별도 문제로 확인했다. 다음은 그 검증기 보완과 판정 병렬도 후보의 부하 검증이며, 운영 설정·규칙·서비스는 유지했다. [근거·실측·후속](correlation-diagnosis/README.md). 아래는 이전 기록이다.

**2026-10-14 12:00 KST 검증:** A/B 보존 이전 boot 1,481건을 전수 대조했고 현재 nft 정제 후보는 0건이었다. 실제 보안 정제·색인 대상도 0건이며 운영 재주입은 하지 않았다. 별도 합성 대조14건 및 Wazuh native 순서8종을 검증했다. 새 간격 시험에서는 manager2건·Indexer2건의 정확 ID와57/57shard 성공을 확인했다. 앞선 일괄 시험의 manager1건/Indexer1건은 기대값 미달로 보존하며 누락 원인은 미확정이다. [검증 범위와 결과](history-replay-b/README.md). 후속 Suricata 격리 시험은 지연 공개 방식에서 Vector/Wazuh 각각6건·중복0, 연속2회전·정상재시작을 통과했다. 단순 rename 대조군은2건 누락을 재현했다. 운영 copytruncate는 유지하며 다음은 WAF별 검증과 운영 전환/영속 복구 조건 확인이다. [회전 결과](../vector/raw-rotation/README.md). 아래는 이전 시점 기록이다.

**2026-10-14 06:09 KST 운영 연결 완료:** 별도 evidence 입력과 `100260~100262`를 배포했다. B는 배포 전후 각각104개 native 시나리오를 통과했고, A의 기존 localfile10개와 관리 블록 밖 바이트를 보존했다. 자연 발생 Suricata1건에서 A 파일→manager→Indexer의 사건ID·시각·고유 키 일치를 확인했다. 두 reader의 실제 회전·보관 해시·수집 재개도 통과했다. 아래04:44의 evidence 미적용 설명은 이전 상태다. [배포 결과](evidence-deployment-2026-10-14.json) · [Vector evidence·회전 계약](../vector/EVIDENCE.md).

`100261`은 Suricata 허용 action, `100262`는 nft `logged_drop`만 level3/no_full_log/no_email_alert로 색인한다. evidence의 `SPOOF/observed`를 nft leaf에서 제외하는 것은 현재 정책이며 전송 실패로 보지 않는다. 기존 no_log 상관은 유지하고, [별도 Indexer monitor](indexer-native/README.md)의 상태는 그 문서에 기록한다. 이 입력 연결을 영속 수신증이나 자동 차단으로 표현하지 않는다.

**04:44 KST 후속 확인:** Suricata raw 통계의505필드 때문에 생긴 decoder 초과 오류를 [canonical stats 전송 필터](stats-filter/README.md)로 해결했다. 04:24 적용 뒤10분 이상 오류0건이며 엔진 원본 통계와 보안 이벤트는 유지한다. 수집 상태 규칙100246~100251을level3/ignore900초로 추가했고 총51 native 시나리오·동일 재적용changed0을 확인했다. [배포 증거](collection-health-validation-2026-10-14.json). 기존 실공격 상관은no_log다. [기존 Indexer를 이용한 후속 후보](indexer-native/README.md)는 조회 검증만 했고 monitor/evidence 운영 연결은 미적용이다.

**2026-10-14 후속 적용:** [상관·시간·중복·별도 canary 계약](CORRELATION.md)에 따라 운영 정제 이벤트의 `no_log` 상관과 native 저장 상태 규칙을 적용했다. 실제 agent transport location prefix를 보정한 뒤 합성 canary 13행에서 manager 경보 2건·Indexer 문서 2건과 동일 event ID를 확인했다. base는 Suricata/nftables/ModSecurity를 수용하지만 공격 상관은 Suricata/nftables만 shadow로 유지한다. 검증 수치는 [후속 증거](correlation-validation-2026-10-14.json)를 참조한다.

아래 최초 연결 기록은 당시 검증 범위다. 첫 native 시험은 transport prefix 없는 경로를 사용했으므로 실제 agent에서 규칙이 맞는다는 증거가 아니었다. 이 차이는 위 후속 종단 시험에서 발견·수정했다. 현재 `apply-b.yml`은 base 9개·상관 24개 시나리오(76행)·health 18개·evidence 53개, 총104개 시나리오를 배포 전후 검사하며, 기존 raw 규칙과 승인 경계는 보존한다.

## 최초 연결 기록

2026-10-14 KST에 A의 기존 Wazuh agent에 정제 JSONL 입력을 추가하고, B manager에 **규칙 100200 하나(level 1, `no_log`)**를 적용했다. 기존 원시 입력 8개와 `local_rules.xml`은 보존했다. 신규 상관 경보는 아직 활성화하지 않았다.

```text
A Vector → /var/log/capstone-vector/ready/normalized.jsonl
         → A의 기존 Wazuh agent → B의 기존 Wazuh manager
         → JSON decoder → 100200 / package_shadow / no_log
```

규칙은 `pipeline=vector`, `schema_version=vector-1`, source가 `suricata|nftables`이고 location이 정제 파일 경로인 경우만 매칭한다. 원시 이벤트와 같은 경보·빈도 카운터에 합치지 않는다. level 1은 후속 전용 상관 규칙에 사용할 수 있는 기초 상태이며, `no_log`는 현재 정제 경보를 기록하지 않도록 한다. **따라서 현재 결과는 indexer 검색·최종 수신 ACK·새 상관분석 완료를 뜻하지 않는다.** WAF는 Vector에서 격리 중이며 이 입력에 들어오지 않는다.

## 고정 운영자 배포

- `apply-b.yml`: 신규 `capstone_vector_rules.xml`만 atomic copy·백업 → 전체 `wazuh-analysisd -t` → 합성 native logtest 6개 → 변경 시 같은 manager 컨테이너 재시작 → ID·필수 프로세스·logtest 재확인. 실패 시 기존 전용 파일 복원 또는 처음 만든 파일만 제거한다. 기존 `local_rules.xml`은 수정하지 않는다.
- `apply-a.yml`: 현재 `ossec.conf` 복사본에 별도 `ossec_config` 블록을 붙여 native 검증한다. 설치 직전 live SHA·소유자·권한을 다시 확인한 뒤 백업·교체하며, 변경 때만 기존 agent를 재시작한다. 실패하면 백업으로 복원한다. 여러 `ossec_config` 블록을 하나로 재작성하지 않는다.
- `run-local.sh`는 root·고정 A/B machine-id·local connection을 요구한다. 자체 lock과 기존 승인 worker의 `/var/lib/rule-change/.lock`을 함께 잡아 배포를 직렬화한다. 새 MCP 도구나 LLM sudo 권한을 추가하지 않는다.
- A/B 모두 `/opt/capstone-automation/venv/bin/ansible-playbook`을 사용한다. 영구 프로젝트는 `/opt/capstone-automation/project/infra/normalization/wazuh-vector/`에 root 전용으로 보관한다. 이 폴더에는 패키지 설치·컨테이너 재생성·기존 보안 룰 수정 작업이 없다.

고정 호스트에서 운영자가 실행한다:

```sh
/bin/sh run-local.sh b syntax
/bin/sh run-local.sh b apply
/bin/sh run-local.sh a syntax
/bin/sh run-local.sh a apply
```

`check`는 Ansible 예상 변경 확인이며 설치 전 native rule 매칭을 대신하지 않는다. Wazuh 4.14.8의 `wazuh-logtest`에는 별도 후보 config를 지정하는 `-c` 옵션이 없으므로 새 XML의 전체 검증·logtest는 transaction 중 설치 후, manager 재시작 전에 수행한다. fixture는 문서용 주소만 포함하며 운영 로그에는 쓰지 않는다.

## 읽기 위치와 재시작의 한계

입력의 `only-future-events=no`, `max-size=2GB`는 Linux JSON 파일에도 적용된다. 그러나 저장된 위치가 없는 **첫 등록은 EOF에서 시작**한다. Vector가 이미 쓴 과거 ready 행을 자동으로 전부 재생하는 설정이 아니다. 기존 파일은 그대로 보존한다.

이후 저장된 prefix hash가 일치하고 미수집량이 제한 이하이면 저장 offset으로 돌아간다. prefix가 바뀌면 처음부터 읽을 수 있고, 미수집량이 한도를 넘으면 끝으로 이동할 수 있다. 체크포인트 저장은 정상 종료 등 실제 구현 조건의 영향을 받는다. 이것은 crash-safe exactly-once 또는 원격 분석 완료 보장이 아니다. 운영 입력의 안전한 회전·재처리·새 상관 규칙의 event-time/processing-time 검증은 후속 과제다.

## 검증 결과와 범위

자세한 수치는 [validation-2026-10-14.json](validation-2026-10-14.json)에 남겼다.

- A 전체 후보 native 검사, A/B Ansible syntax 검사 통과.
- B 정상 2개·잘못된 schema/pipeline/source/location 4개 native logtest 통과. 신규 규칙 한 개와 `no_log` 확인. 기존 `local_rules.xml` SHA 및 승인 helper/sudoers 관련 파일·권한 전후 동일.
- A 기존 raw localfile 8개 각각의 SHA 보존. 새 입력 한 개, logcollector의 해당 파일 FD 한 개와 시작 로그 확인. 원래 mode `0660`, uid 0/gid 110 보존.
- B 두 번째 apply `changed=0`, container ID/StartedAt 동일. A 두 번째는 운영 변경 없이 후보 파일만 한 번 갱신했고, 세 번째 apply `changed=0`; 두 번 모두 agent 프로세스 PID/start ticks 그대로였다.
- 관찰한 B alert 파일 1,861행에서 Vector/100200 경보는 0건이었다. 이는 검사한 파일 구간의 관찰값이며 영구적인 중복 부재 보장이 아니다.

초기 B 적용이 진행되는 동안 공유 worker lock 권고가 도착했다. 당시 기존 `local_rules.xml`과 승인 경계가 변하지 않았음을 확인했고, 이후 B 재적용과 첫 A 적용부터 공유 lock을 사용했다. 실패 복구 경로는 코드에 포함했으며 이번 운영에서 장애를 일부러 유발하는 rollback 시험은 하지 않았다. A의 실제 read FD와 manager의 동일 native 엔진 매칭은 확인했지만 개별 이벤트의 영속 원격 수신·indexer 반영은 검증하지 않았다.

공식 근거: [Wazuh localfile](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html), [4.14.8 일반 파일의 future 옵션 처리](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/logcollector.c#L984-L998), [저장 위치 복원 및 첫 EOF 처리](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/logcollector.c#L2576-L2623), [규칙 옵션과 level 0의 제약](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html).
