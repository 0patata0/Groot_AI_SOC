# Indexer 관찰용 적격 이벤트 분기

2026-10-14 KST 기준. Vector·수집·회전 계약과 아래에 명시한 실제 운영 검증 범위를 기록한다. 초기 후보 검증 기록에 운영 결과를 추가했으며, 원격 영속 수신 ACK나 전체 이벤트 무손실을 보장하는 구성은 아니다.

## 입력과 출력

기존 `correlation_metadata` 출력은 그대로 `ready/normalized.jsonl`로 보낸다. 새 분기는 다음 조건을 모두 만족한 이벤트만 `/var/log/capstone-vector/evidence/normalized.jsonl`에 기록한다.

- schema `vector-1`, pipeline `vector`, source `suricata` 또는 `nftables`
- `correlation_eligible == true`, `correlation_time_class == fresh`
- `protected_asset == false`, `quality_flags == []`

기존 정제기의 보호 대상 판정은 출발지·목적지 `.110/.111` 모두에 적용된다. source_port를 신규 필수조건으로 만들지 않는다. 기존 공통 상관분석 정책이 IP·목적지port·프로토콜·시간을 검증한 뒤 적격 여부를 결정한다. WAF, 과거/미래 이벤트, 보호 대상, 품질 오류 및 미적격 이벤트는 이 분기에 들어가지 않는다.

새 분기에서만 `capstone_norm.evidence_lane=indexer-observation-v1`을 추가한다. 기존 ready 객체는 수정하지 않는다. 원문 URI/body/header/message를 추가하지 않으며 필드가 이미 정제된 객체를 사용한다. 이 marker는 관찰 경로 구분이지 Indexer 영속 수신증이나 중복 제거 키가 아니다. `correlation_dedupe_key`가 같아도 Wazuh가 자동으로 영속 중복 제거한다고 가정하지 않는다. Vector 재전송·수집 재시작 이후 중복 가능성이 남는다.

Vector의 `correlation_eligible`과 B의 관찰 규칙은 조건 범위가 다르다. B의 nft 규칙 `100262`는 추가로 `action=logged_drop`을 요구한다. 따라서 `SPOOF`/`observed` 이벤트가 evidence에 기록되어도 해당 색인 경보가 생기지 않는 것이 현재 정책이다. 원시 방화벽 체인 동작을 추측해 이를 `logged_drop`으로 바꾸거나 B의 조건을 넓히지 않는다. Suricata 관찰 규칙 `100261`과 nft 관찰 규칙은 level3이며, 공격 판정·자동 차단을 추가하는 경로가 아니다.

## 저장과 상태 감시

디렉터리는 root:root0700, 파일은 root:root0600/단일 link다. symlink·비정상 기존 파일은 거절하며 최초 빈 파일만 `force=false`로 만든다. 기존 evidence 내용을 지우지 않는다.

독립 evidence disk buffer는268435488byte다. 기존 ready와 quarantine의 같은 크기 두 개를 합하면 설정 합805306464byte(약768MiB)가 된다. 활성/회전 출력 파일과 버퍼 메타데이터·할당 여유는 별도 용량이다. 신규 buffer도 `when_full=block`이므로 evidence 출력이 막히면 공통 원천과 ready 진행에도 지연이 전파될 수 있다. 부모 배포 절차에서 디스크 여유를 확인하고 telemetry가 evidence sink의 오류·drop·buffer size도 감시한다. 이 정책은 telemetry 자체의 memory128/drop_newest와 다르다.

## 네 파일 회전과 두 reader 증거

ready, evidence, quarantine, telemetry를 기존 고정 logrotate 그룹으로 관리한다. daily/64MiB 조건·48개/14일 보존·delaycompress·rename 방식은 유지한다. timer 간격 사이 추가 기록이 가능하므로64MiB를 엄격한 순간 최대치로 표현하지 않는다.

Vector를 중지한 뒤 ready와 evidence 각각에 다음 조건을 요구한다.

1. 현재 inode를 연 Wazuh logcollector FD가 정확히 하나이고 kernel FD offset이 현재 파일 크기와 같음.
2. 비어 있지 않은 파일은 Wazuh `file_status.json`에 해당 path가 정확히 하나이고 논리 offset이 크기와 같음.
3. 저장된 SHA1이 현재 파일 전체 SHA1과 같음.

둘 중 하나라도 늦거나 증거가 없으면90초 범위 안에서 재확인하고 회전을 진행하지 않는다. 실패 복구 pending marker는 기존 계약대로 남는다. 준비 시 evidence의 inode/size/SHA256도 기존 ready와 별도로 기록한다. 이는 로컬 logcollector 읽기 완료 증거이며 manager 분석 완료·Indexer 저장 완료·내부 queue 무손실을 보장하지 않는다.

A localfile을 연결하기 전에 evidence 파일을 생성해야 한다. 또한 새 maintenance가 활성화되기 전 두 파일의 localfile 등록과 읽기 FD를 확인해야 한다. 운영 전환은 부모가 파일 선생성→B 규칙→A localfile→Vector/maintenance의 순서를 조율한다. 기존 raw 입력과 no_log ready 입력을 유지한다.

## 검증 범위

`tests-evidence.toml`은 적격 Suricata/nft 두 파이프라인에서 marker가 evidence에만 생기는지와 WAF·historical·future·protected·ineligible·quality·schema/pipeline·잘못된 bool/보호필드10종 제외를 검사한다. collection native와 jq fixture는 evidence sink counter 및 buffer를 인식하는지 검사한다. 기존 native97개와 jq16개도 유지한다.

`collection/test-reader-gate.sh`는 임시 실제 파일/FD/SHA1과 합성 Wazuh checkpoint를 사용한다. 실제 함수의 ready/evidence 동시 성공, 각각의 논리 offset 지연, evidence SHA 불일치·중복 checkpoint·kernel offset 지연·다중/누락 FD 및 회복을 확인한다. 프로세스 탐색 결과와 고정 checkpoint 경로만 시험용으로 치환하며 운영 파일·Wazuh 상태·systemd·logger를 호출하지 않는다. 이 분리 시험을 운영 두 reader 회전 성공으로 보고하지 않는다.

raw copytruncate·과대 EOF 행 미탐지·이전 부팅 journal 회수는 이번 분기로 해결되지 않는다.

## 운영 적용과 확인

2026-10-14 05:58:51~06:01:27에 A에 적용했다. 사전에 B 규칙과 A localfile을 연결했고, 쓰기 시작 직전 evidence의 빈 root0600 파일에 Wazuh FD가 정확히 하나이며 offset0임을 재확인했다. 동결한208개 파일 SHA와 native110개·health18개·분리 reader9개 검증을 통과한 후보를 사용했다.

고정15개 관리 파일을 root 전용 위치에 백업하고 기존/후보 SHA만 허용하는 복구 절차를 준비했다. 한 Ansible 호출에서 Vector와 storage playbook을 차례로 실행했으며 recap은 **누적 통계**다. 첫 적용의 최종 합계는 `ok68 changed5`이고, 그중 Vector playbook 종료 시점은 `ok49 changed3`이었다. 재적용의 최종 합계는 `ok67 changed0`이었다(Vector 종료 시점 `ok48 changed0`). 두 recap을 별도 작업 합계처럼 더하지 않는다. 실패·rescue는 없었고, 두 번째 실행의 Vector PID와 Invocation도 같았다. 실제 실패 복구를 실행한 검증으로 표현하지 않는다. WAF·Imperva 예외·MCP·권한·agent 설정의 보호 대상 해시 및 WAF 컨테이너 identity는 전후 같았다.

06:01:58에는 evidence12건이 모두 적격·fresh·보호 대상 제외·품질 flags 없음·KST 조건을 만족했고, ready 표본517건에는 evidence marker가 없었다. 현재 Invocation의 heartbeat와 evidence sink 숫자 metric을 확인했으며 maintenance의 수집 상태는 빈 경고 목록이었다. 06:03:59에는 ready와 evidence 모두 Wazuh의 논리 offset·FD offset·SHA1이 파일 전체와 일치했다. Agent는 연결 상태였고 전송 buffer0, 최근10분 ERROR/WARNING0이었다. 이는 로컬 읽기·순간 상태 관찰이며 manager/indexer ACK가 아니다.

06:04:51 evidence31건은 `nftables/SPOOF/observed`30건과 `suricata/allowed`1건이었다. 전자의 B nft 관찰 경보0은 위 action 조건에 따른 결과다. 후자의 `100261` level3 경보는 B manager와 Indexer에서 실제 확인했으며, 06:06:06에 A evidence의 event_id·source·event_time·dedupe key가 해당 B 문서와 정확히 일치함을 대조했다. 원문 payload는 Mac으로 반출하지 않았다. Suricata1건의 종단 관찰을 모든 source의 영속 수신 보장으로 확대하지 않는다.

06:06:21~06:08:09에는 설치된 maintenance로 강제 회전1회를 실시했다. ready638,200byte와 evidence47,324byte archive의 inode·크기·전체 SHA256이 writer 중지 후 기록한 값과 일치했다. 두 새 파일은 root0600이었고 각각 현재 inode의 Wazuh FD가 정확히 하나·offset0이었다. Wazuh logcollector PID는 유지됐다. Vector는 새 PID/Invocation으로 정상 재개했고 자동 재시작 횟수0, pending marker 부재, 설정 해시 불변을 확인했다. 108초는 전체 시험 소요시간이며 매번 동일한 중지 시간을 보장하지 않는다. 이 시험은 두 로컬 reader 회전 성공이며 원격 ACK·무손실 보장이 아니다.

06:09:10에는 새 Invocation heartbeat1개와 evidence sink metric2개를 확인했다. 회전 뒤 새 evidence19건은 모두 적격/KST 조건을 만족했고 ready19건에는 marker가 없었다. maintenance는 `collection=[]`, `recovery=no`였으며 가용 공간은 약47.79GB였다. 이는 해당 시점의 표본이며 장기 최대 부하 검증은 아니다.

검증 메타데이터·Ansible 실행 로그·일회성 운영자 controller는 A의 `/opt/capstone-automation/project/evidence/indexer-20261014/`에 root 전용으로 보관한다. 백업은 `/var/backups/capstone-vector-evidence-20261014-t05607rd`이며 evidence 내용이나 Vector 버퍼를 복구 대상으로 지우지 않는다. 수치 요약은 [검증 JSON](evidence-validation-2026-10-14.json)을 따른다.
