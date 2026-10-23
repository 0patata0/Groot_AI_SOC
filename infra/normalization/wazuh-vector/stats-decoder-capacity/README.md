# Suricata 실제 stats와 manager JSON 필드 한도

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

2026-10-15 실제 적용 완료: B의 `analysisd.decoder_order_size=1024`를 반영했다. daemon control 재시작 과정에서 컨테이너 감독 정책에 의해 같은 CID가09:10:50 KST에 재시작됐고, init PID2315523/RestartCount1을 확인했다. 별도 수동 추가 재시작은 없었다. 필수5프로세스와 agent001 Active, 실제 표본 native504필드·86600/level0을 확인했다. 이는 아래 격리 시험과 구분되는 운영 적용 결과다.

09:11:54~09:14:04 KST 약130초의 실제 관측에서 A의 자연 stats2건·안정 CP 표본27개·offset/hash 불일치0·CP 수동 수정0, B의 새 JSON 필드 한도 오류0·agent001 Active를 확인했다. 다섯 프로세스 PID와 컨테이너 identity는 관측 중 동일했고 analysisd RSS는146,432→147,072KiB(+640KiB)였다. [배포·관측 JSON](deployment-validation-2026-10-15.json)은 직접 읽은 두 메타데이터 파일의 SHA를 포함한다. 이 짧은 관측에는 CPU/queue/drop 수치가 없으며 장기 무손실이나1024 설정의500EPS 성능을 증명하지 않는다. 격리 runner `e77dd4d9…`는 변경하지 않았다.

2026-10-15 A의 logcollector stats ignore를 제거한 뒤 native CP offset/hash 정합은 회복됐지만, B의 JSON decoder 기본256개 한도가 실제 통계를 다시 잘랐다. 기존 작은 합성 stats는 이 한도를 검증하지 않았다. 과거 [stats-filter 실측](../stats-filter/validation-2026-10-14.json)은 통계 최대504개+agent label1개를 기록했다. 이번 부모의 실제 표본은8,882B/재귀 scalar508leaf다. stats.detect.engines 배열1개를 native가 한 필드로 보존하므로 실제 decoder 입력은504필드, agent label 포함505필드다. 원문은 서버에만 있다. 원래 stats ignore를 되살리면 앞서 재현한 CP 결함이 돌아오므로 이번 후보는 **B analysisd 설정 한 항목**이다.

후보 값은 `analysisd.decoder_order_size=1024`다. [공식 옵션](https://documentation.wazuh.com/current/user-manual/reference/internal-options.html#analysisd)의 허용32..1024에 포함된다. [4.14.8 JSON decoder](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/decoders/plugins/json_decoder.c#L192-L205)는 동적 필드마다 이 한도를 검사한다. stats용 no_log 규칙만 추가해도 decode 단계의 한도 오류는 사라지지 않는다. 새 특수 decoder로 통계 전체를 생략하면 decoder 순서/필드 의미를 바꾸므로 현재는 검증된 전역 옵션의 제한된 조정을 우선한다.

## 운영 변경 전 native 비교

`verify-native-b.py`는 root가 정확 CID/image를 확인한 **기존 B manager 컨테이너** 안에서 실행하는 종료형 후보다. 실행 인수는 없다. parent가 고정 fixture를 `/tmp/capstone-stats-fixture-20261015.jsonl` root0400/nlink1로 전달해야 한다. SHA `74cde4f77b8dc1e5d3999ba2048e7f98180c0c5600f1c41ee8d9ee709e6d2f61`,8,882B, topkeys timestamp/event_type/stats,native504필드와 정확한 LF1개를 요구한다.

```sh
python3 -B /ROOT_REVIEWED_SOURCE/verify-native-b.py
```

새 `/tmp/capstone-stats-decoder-capacity-20261015`만 만들며 기존 경로가 있으면 거절한다. actual ruleset/decoders/lists/internal options를 private chroot 두 개에 복사하고 `<ruleset>`의 상대 경로만 포함하는 최소 config를 쓴다. queue/FTS·로그도 private다. 운영 DB·manager socket·agent config는 사용하지 않는다. 설치된 `wazuh-logtest-legacy -D <private> -c etc/ossec.conf -v`가 각 profile에서 한 번만 실행된다. 4.14.8 legacy에는 `-l`이 없고 location은 stdin이다.

- 256: 실제504필드와 label 포함505필드를 각각256개까지만 추출하고 초과 오류 합계497개를 재현해야 한다.
- 1024: 두 입력의504/505개 키를 원래 순서대로 모두 추출하고 초과 오류0, decoder=json, 최종86600/level0/경보 생성0이어야 한다.
- 실제 원문과 `capstone.source=suricata` label을 추가한 입력 모두 서버에 보존한다. stdout은 count/SHA/상태만 출력한다. 원문 native 로그는 stage 안에만 남긴다.
- 각 process45초, CPU40초/가상메모리2GiB/출력8MiB로 제한한다. unreaped child의 private PGID를 정리하고 wait한다. 전체 외부 실행도180초 등 유한 상한을 둔다.
- 실제 config/rule/decoder/list/binary/lib source metadata+SHA를 전후 대조한다. source 쓰기·manager 재시작·외부 통신은 없다. private stage는 검증/보존을 위해 남기며 parent가 보관 후 정리한다.

첫 native 시도는 scalar만 가정한 시험 도구가 배열을 거절해 stage/child 생성 전에 끝났다. 원문 배열을 고치지 않고, 공식 기본 array/null 처리와 일치하도록 오라클을 보완했다. 로컬 AST·실제 표본 타입 projection과 출력 parser 5개 시험은 통과했다. 최종 소스는 private chroot 루트의 권한을 umask와 무관하게 root:999/0750으로 명시하고 검사한다. 독립 읽기 검토에서 추가 실행 blocker는 없었으며 최종 SHA는 `e77dd4d9e179097ce35aba46006754164710f66a20ec84663694384050ed1510`다. 부모가 B에서 실행한 최종 native 비교는 통과했다. 256 arm은 두 입력을 각각256개로 잘라 초과 오류497개를 재현했고, 1024 arm은504/505개를 전수 추출하며 오류0이었다. 양쪽 최종86600/level0, source·운영 컨테이너 불변을 확인했다. 이 native 결과 자체는 격리 비교이며, 이후 실제 manager 옵션 적용·관측 결과는 최신 상단과 별도 deployment JSON에 기록한다. legacy는 단일 decoder의 추출/기본 규칙 판정을 검증하며 실제 agent001 라우팅·manager 병렬처리·Indexer 도착 증거는 아니다. `-t` 성공만으로 전량 필드 추출을 주장하지 않는다.

[공식 decoder 기본값](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html#json-array-structure)은 array이며 [4.14.8 plugin](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/decoders/plugins/json_decoder.c#L320-L325)은 배열 전체를 cJSON_Print 후 한 필드로 저장한다. 재귀 scalar count를 그대로 decoder field count로 해석하지 않는다.

## 최소 적용·사후 검증 계약

[analysisd](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/analysisd.c#L518)는 시작 시 한도를 읽는다. 기존 daemon의 [logtest 세션](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/logtest.c#L174-L176)은 이 값을 공유하므로 local options 파일만 바꾼 뒤 새 session을 열어도1024 검증을 대신하지 못한다. standalone [legacy](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/testrule.c#L138-L195)는 private chroot에서 설정을 새로 읽는다.

native 비교 통과 뒤 parent 배포는 다음으로 제한한다.

1. 기존 `local_internal_options.conf` 원문/SHA/권한과 고정 manager identity를 root backup에 보존한다. 현재 실측은root:9990640/380B이며 decoder_order override가 없다. event/rule threads1/1 등 나머지 바이트를 그대로 두고 한 줄만 추가한 후보를 만든다.
2. native config 검사와 설치 직전 fresh CAS 후 atomic 교체·fsync한다. 원래 UID/GID/mode를 유지한다. ossec.conf/rules/decoder/internal_options는 변경하지 않는다.
3. 같은 manager를 명시적으로 한 번 재시작하고 필수 process/agent001 연결·실제 옵션1024와 다른 보호 SHA를 확인한다. 요청 결과가 불명확하면 자동 재전송하지 않는다. 복구는 현재 파일이 정확한 후보일 때만 원본으로 되돌릴 수 있으며, 재시작 상태를 먼저 확인한다.
4. 실제 위치의 live logtest에서 전체 field count/86600level0을 재확인하고, 자연 stats가 최소2회 도착하는 동안 새 필드 한도 오류0·queue/drop·RSS/CPU를 관찰한다. synthetic/native 진단 오류 시각은 자연 오류 집계에서 분리한다. A config/CP를 다시 쓰지 않는다.

한도는 모든 분석 이벤트에 적용된다. [DynamicField](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/eventinfo.h#L19-L22)는 포인터2개이며64bit에서256→1024의 배열 증가는 event당 약12KiB다(문자열/기타 메모리 제외 계산). 기존256 설정의500EPS 시험을 새1024 설정의 성능 보장으로 재사용하지 않는다. 1024를 넘는 미래 입력까지 처리할 수 있다는 보장도 아니다.
