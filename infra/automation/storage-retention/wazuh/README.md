# 저장공간 상태의 Wazuh 연결

> **2026-11-05 수정:** B의 1MiB 전달 로그가 1,048,268B에 도달해 다음 줄을 추가하지 못했고, 측정은 `ok`인데 ExecStartPost가 15분마다 실패했다. 현재 EOF·전체 SHA1 체크포인트 확인 뒤 원본 전체를 root0700 보관소에 SHA256/fsync 보존하고 새 root0600 로그를 배타 생성한다. Linux24조건과 실제 ProtectSystem의 별도 bind mount 경계1조건을 통과했다. 실제 B 전달 exit0·실패 unit0·수집 체크포인트 확인, 원문과 최초 실패/복구 기록은 보존한다. [작은 원장](rotation-validation-20261105.json).

> **2026-10-31 후속:** 반복100313의 원인은 B monitor의 정상 백업 파일 거절이었다. monitor만 수정했고 decoder/규칙/relay와18키 계약은 유지했다. 01:17 KST 새 `ok` 상태의 relay SHA와 수집기 EOF776,927B를 대조했으며 실제 상태의 native 판정100310/level0도 확인했다. 수정 이후100313은 01:17:46 KST 조회에서0건이다. 정상 level0은 no_log이므로 Indexer 경보 부재만으로 전달 성공을 판단하지 않았다. 과거 카드/경보는 보존한다. [운영 영수증](../deployment-validation-2026-10-31.json).

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 기존 서버의 운영 자동화와 새 서버 초기 설치는 구분한다. 지정 범위의 C1/B1/A2 재부팅 복구는10/24 검증 이력이 있으며 최초 실패·수동 복구도 보존한다. 현재6실습·MCP6서버를 기준으로 읽고 과거 후보/PID/시험 결과를 새 실측으로 해석하지 않는다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

2026-10-15 KST 검증 결과: 부모가 B에서 실행한 Linux relay 17개와 실제 Wazuh logtest 56개가 모두 통과했다. [상위 monitor](../README.md)의 canonical 18키 JSON을 전용 decoder `capstone_storage_json`으로 분류한다. 로컬 정적 fixture 56개·relay jq 7개·Bash 구문도 통과했다. 실제 localfile·relay 설치와 재시작 이후 수신 결과는 부모의 배포 기록에서 별도로 확인해야 한다.

후속 운영 관측(2026-10-15 09:02 KST): 부모가 A/B 자연 timer 실행의 exit0·상태 `ok`를 확인했다. B relay 파일은 1,014B/2행이고 Wazuh checkpoint가 EOF이며 prefix SHA와 일치했다. 이는 해당 로그의 native 읽기 위치와 자연 주기 동작 근거다. 정상 level0 상태의 Indexer 경보 생성이나 미래 전달 무손실을 의미하지 않는다. 상세 운영 원본·영수증은 부모의 server evidence에 보존한다.

최초 native config 검사는 `status`가 Wazuh 정적 필드이므로 `<field name="status">`로 사용할 수 없어 거절됐다. 부모가 신규 XML 두 파일만 제거했고 재시작은 없었다. 최종 규칙은 이미 canonical 전체 형식을 검증한 payload의 정확 `"status":"…","used_percent":` 구간을 `<match type="pcre2">`로 검사한다. 이 최소 수정본의 native 56개 통과이며, decoder·relay·상태 정책은 바꾸지 않았다. 규칙 SHA는 `7de1c160bca37eb5610acd89cb80016cbb9e2037e258b068c9633251b7a9bee8`, decoder SHA는 `8b6b4fe73713a341e07bea666068fee1f0b97517b32f72d6ba99b804659840b7`이다.

| 상태 | 규칙 | level | 동작 |
| --- | --- | --- | --- |
| ok | 100310 | 0 | no_log |
| warning | 100311 | 5 | no_email_alert/no_full_log |
| critical | 100312 | 10 | no_email_alert/no_full_log |
| unavailable | 100313 | 5 | no_email_alert/no_full_log |

용량 임계값은 monitor가 판정하고 규칙은 상태를 매핑한다. 알려진 critical+unknown은 level10이며 warning+unknown은 unavailable/level5다. 규칙은 고정 program `capstone-storage`, 아래 두 location, JSON의 정확 key·type·host/machine-id/retention_days 결속과 status/reason/scan_status 조합을 요구한다. 문자열로 위장한 boolean, 추가/중복 key, 복수 JSON, 뒤쪽 원문을 받지 않는다. canonical 형식과 tag/location은 서명이 아니며 독립적인 발신자 인증을 추가하지 않는다. 두 허용 route와 payload의 host 조합을 별도 암호학적으로 증명하지도 않는다.

`ignore` 억제 창은 두지 않는다. 같은 leaf를 A/B가 공유하므로 전역 ignore로 한 호스트 경보가 다른 호스트를 가리는 것을 피한다. 15분 관측마다 같은 상태 경보가 반복될 수 있으며 영구 중복 제거·exactly-once 전달·자동 삭제·Active Response·모델/채팅 호출은 없다. 새 규칙 그룹을 기존 자동 대응의 포괄 group selector에 연결하지 않아야 한다.

## 고정 수집 경로

- A: 기존 agent001의 `(groot-sec) any->journald`. A의 기존 수집 설정은 이 후보가 수정하지 않는다.
- B: 기존 manager 내부 `/var/ossec/logs/capstone-storage-b.log`, `log_format=syslog`. [manager-localfile.xml](manager-localfile.xml)은 **삽입용 fragment**이며 전체 ossec.conf가 아니다. `only-future-events=yes`이므로 과거 파일의 전량 소급 수신을 주장하지 않는다.

부모가 읽기로 확인한 B manager CID는 `45b85672e0fe16fd14616e608c99b683e2f651b049efcd71da2b45367b057806`이다. host journal/syslog mount는 없고 기존 named volume `/var/lib/docker/volumes/single-node_wazuh_logs/_data`가 `/var/ossec/logs`에 RW로 연결된다. 따라서 XML만 추가해 host journal이 수집된다고 판단하지 않는다. B relay가 **monitor 상태 파일**을 syslog 한 줄로 전달한다. host journal의 임의 과거 행을 재생하거나 Docker exec를 호출하는 relay가 아니다.

부모 실측에서 volume `_data`는 `999:999/0770`, 그 상위 Docker/volumes/volume 경로는 각각 root:root/0710·0701·0701이다. relay는 `_data` 한 경로만 정확 예외로 받고 나머지 조상은 root:root/no022를 요구한다. logcollector는 root이므로 새 목적 파일은 host root:root0600/nlink1로 미리 만든다. installer가 root 전용 `.relay.lock`도 생성해야 한다.

## B relay 설치 계약

| 대상 | 소스·메타데이터 |
| --- | --- |
| `/usr/local/lib/capstone-storage-monitor/relay-b.sh` | [relay-b.sh](relay-b.sh), root:root0500/nlink1 |
| 같은 디렉터리 `status-b.jq` | [status-b.jq](status-b.jq), root:root0400/nlink1; relay 내부 SHA pin |
| `/var/lib/capstone-storage-monitor/.relay.lock` | root:root0600/nlink1, 0B |
| `/var/lib/docker/volumes/single-node_wazuh_logs/_data/capstone-storage-b.log` | 새 root:root0600/nlink1, 최초 0B, **기존 파일이 있으면 덮어쓰지 않음** |
| `/etc/systemd/system/capstone-storage-monitor.service.d/20-manager-relay.conf` | [storage-relay-b.conf](storage-relay-b.conf), root:root0644; B만 |

drop-in은 ExecStartPost, 해당 기존 volume의 ReadWritePaths, TimeoutStartSec60s만 추가한다. monitor의 기존 SuccessExitStatus=2/75를 유지한다. exit2의 unknown 상태도 전달할 수 있어야 하며 busy75로 새 상태가 없을 때는 stale/최근 SHA 검사가 재전송을 제한한다. 실제 설치본에서 이 ExecStartPost 동작과 unit 분석을 확인한다. relay 자체는 10초 timeout+2초 KILL이며 monitor worker의 기존 40초 wrapper와 합쳐 unit60초 한도를 둔다. 상한 내 모든 성공을 보장한다는 의미는 아니다.

relay는 고정 B/root만 받고 별도 flock을 사용한다. 상태 파일 root0600/nlink1/최대4096B를 GNU dd nofollow/nonblock으로 private 복사해 전후 메타를 대조하고, 단일 canonical JSON·18키·B identity·현재 policy 계산·120초 이내 시각을 검증한다. 다른 monitor 경로·host·임계값 인수는 없다.

목적 log는 먼저 읽기 전용 FD로 열어 named inode·root0600/nlink1을 확인한다. Bash의 최초 read-open 자체가 O_NOFOLLOW를 제공하지 않으므로 전후 non-symlink/동일 inode 검사를 통과한 FD만 사용한다. **쓰기 목적지는 검증된 `/proc/self/fd/4` 하나**이며 manager-writable 파일 이름을 다시 열어 쓰지 않는다. prefix SHA·부모/파일 identity·정확 증가량을 후검사한다. 기존 로그 마지막 행이 미완성이면 append하지 않는다.

새 줄을 포함해 1MiB를 넘을 때에는, 파일 마지막 줄과 root0600/nlink1·고정 inode를 확인한 뒤 Wazuh 체크포인트의 정확 경로·EOF·전체 소비 파일 SHA1을 요구한다. 체크포인트가 늦거나 모호하거나 prefix 해시만 일치하면 회전하지 않는다. 별도 bind mount 간 rename을 가정하지 않고, 검증한 읽기 FD의 전체를 `/var/lib/capstone-storage-monitor/relay-archive-*/closed.log`로 복사·전체 SHA256 확인·fsync한 후에만 고정된 이전 이름을 unlink하고 새 root0600 파일을 배타 생성한다. 기존 내용은 삭제·truncate하지 않는다. 원래 inode는 새 로그로 승계하지 않으며 archive와 영수증을 보존한다. 보관소1024개 한도·자동 삭제 없음이며, 무한 보존이나 모든 장애에서 exactly-once를 보장하지 않는다. 보존 직후 crash/이름 변경/새 파일 생성 실패는 journal의 단계와 보관소로 수동 조정하며 성공 영수증으로 바꾸지 않는다. 성공한 status SHA는 root0600 `relay-last.sha256`에 fsync/rename 보관해 동일 관측 재전달을 막는다. append 뒤 receipt 저장 전 crash는 중복 가능성이 남고 원문을 rollback하지 않는다. 어떤 native 읽기/append/fsync/metadata 검사 실패도 전달 완료 receipt로 바꾸지 않는다.

## 검증·배포 순서

1. 기존 manager의 `/var/ossec/etc/{rules,decoders}`와 기본 ruleset 전체에서 ID100310~100313 및 decoder 이름 충돌을 확인한다. repo 검색 결과는 사용 없음이지만 **실제 설치본 확인을 대신하지 않는다**. 현재 manager CID·ossec.conf·기존 XML·AR selector와 보호 파일 SHA를 고정한다.
2. 소스 반입 SHA를 확인한 뒤 Linux root에서 아래 relay17개 private fixture를 실행한다. 테스트는 실제 GNU dd/stat/flock/fsync와 root/999 파일 메타를 사용한다. 유일한 trust-boundary stub은 root0700 fixture 위 `/var/tmp` 조상 검사뿐이며 운영 파일·service·Docker 접근은 없다. fixture는 자신의 임시 폴더만 종료 시 제거한다.
3. decoder/rules를 별도 파일로 설치한 뒤 manager restart 전에 native config 검사와 아래 logtest56개를 실행한다. XML location의 `any->journald`는 literal `>`여야 한다. `&gt;`로 변환하면 Wazuh OS_XML에서 다른 경로로 해석될 수 있어 원문 표현을 고정한다. 실패하면 이 신규 파일만 원래 상태로 복구하고 재시작하지 않는다.
4. B log/fragment/relay/drop-in 설치, native config·systemd 검증, 허가된 manager reload/restart를 부모가 수행한다. A/B 실제 monitor 실행 이후 각각 정확 route/host·상태·시각·값을 manager에서 확인한다. level0 정상은 alert 부재가 성공 근거가 아니므로 native logtest와 수신 관측을 구분한다. Indexer 문서는 별도 검증이다.

```sh
python3 -B /ABS/wazuh/test-storage-rules.py
bash /ABS/wazuh/test-relay-native.sh --policy-only
# Linux root/private fixture만 실행; 설치와 운영 입력은 하지 않음
bash /ABS/wazuh/test-relay-native.sh
# 승인된 native XML 설치가 선행되어야 함; fresh logtest 세션별 합성 입력
python3 -B /ABS/wazuh/test-storage-rules.py --native --manager FULL_64HEX_CID
```

공식 참고: [Wazuh localfile](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html), [규칙 구문·level/options](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html). 실제 native 경로·decoder 결과는 문서 해석과 별도로 검증해야 한다.

## 11/5 실제 실패와 복구 경계

첫 회전 후보는 체크포인트를4KiB prefix로 오해해 운영 guard가 거절했다. 설치본의 EOF 해시는 전체 SHA1임을 직접 대조하고 prefix-only 거절을 추가했다. 다음 후보는 ProtectSystem의 각 ReadWritePaths가 별도 bind mount여서 GNU mv가 copy/unlink로 바뀌는 경계를 놓쳤다. 보관소에 전체 내용/SHA는 남았으나 inode 후검사가 거절했고 원래 이름이 없어졌다. 해당 전체 보존을 확인해 새 로그 이름을 배타 생성, 전달을 복구했다. 이 실패를 성공한 회전으로 세지 않는다.

최종 후보는 copy/fsync 후 고정 이름만 unlink하도록 수정하고 실제 systemd 별도 bind mount의1MiB 합성 파일 전체 보존·새 관측 전달을 검증했다. 첫15분 복구 타이머는 확정 지연으로 원본 소스를 복구했으며, 다시 별도 r4 백업·타이머로 최종 소스를 적용하고 같은 실행 안에서 결과/SHA를 확인·확정했다. 과거 시험 transient unit2개의 실패 상태만 기록 보존 뒤 reset-failed했고, 과거 journal/DB/승인/백업은 지우지 않았다.

기존 랩 서비스의 소스·수동 설치 계약은 위 표를 따른다. portable 단일 `deploy.sh`의 신규 Wazuh 규칙 복사와 이 기존 고정 경로 relay 자동 구성은 별개다. 후자는 이번에 새 OS에서 검증하거나 신규 서비스로 확장하지 않았다. 새 패키지·키·포트·MCP 권한은 없고 기존 Python3/GNU 도구만 사용한다.
