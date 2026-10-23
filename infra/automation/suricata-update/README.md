# Suricata Update: 현재 규칙의 오프라인 후보 생성

**2026-10-16 실행기 갱신 후 구분:** 룰 조회에 파일 정의 집계를 추가한 A 실행기 SHA는 `156b88d0ac60c85df96ce05961b911cd5bc28ddb65b0df3656134e8a17015c6c`다. 저장소의 `compare_rules.py`는 이 SHA를 고정한다. A에 설치한 **10/15 비교 도구·문서·결과 스냅샷과 기존 `d937c7…` pin은 그대로 보존**했다. 최신 실행기로 새 후보 시험을 진행하려면 검토된 최신 소스와 일치하는 실행기 사본·새로 확인한 manifest를 별도의 root 전용 source 디렉터리에 준비해야 한다. 과거 고정 시험을 새 실행기에서 통과한 결과로 재해석하거나 설치 스냅샷의 pin만 덮어쓰지 않는다. 이번에는 updater 재실행·룰 변경·자동 활성화·새 패키지 설치가 없다. 파일 정의 집계는 실제 적재 개수와 별개다. [이번 조회 근거 배포](../../mcp/README.md#2026-10-16-룰-파일-정의-집계--조회-근거-배포) · [검증 기록](../../hermes/rule-inventory-validation-20261016.json).

2026-10-15 후행 마감 기록: 검토된 소스·문서10파일을 `/opt/capstone-automation/project/infra/automation/suricata-update`에 설치하고, 증거를 `/var/backups/capstone-suricata-update-20261015`에 보존했다. archive 영수증 SHA는 `a4b053b79460b503fd1d0cd01db254215f9e8699bbbb0bf50a2fec8573cb6392`다. 최종 후보와 원본1벌의 gzip·해제 SHA, 실패 시도 metadata 및 자동 활성화됐던292개 규칙 metadata를 보존한 뒤 고정 staging17개를 정리했다. 운영 보호 파일 불변·규칙 변경0·서비스 신호0이다. [영구 반입 결과](deployment-validation-2026-10-15.json)를 참고한다.

서버의10파일은 **이 문단을 추가하기 전 스냅샷**이며 해당 SHA를 덮어쓰지 않았다. 아래 도입 이력과 시험 결과도 보존한다. 전체 Mac/서버 작업 임시 경로의 정리 완료를 뜻하지 않는다. 도구 사용 범위는 오프라인 후보 생성·검증이며 자동 feed/규칙 활성화나 승인 worker의 기존 byte 합본 방식은 변경하지 않았다.

2026-10-15 준비 상태: A의 기존 Suricata 8.0.6 이미지에 `/usr/bin/suricata-update` 1.3.8과 Python 3.9.25가 이미 들어 있다. 추가 설치, 새 ET 다운로드, 주기 업데이트, 운영 규칙 변경은 필요하지 않다. 08:14 부모의 읽기 전용 실측을 `native-pins-2026-10-15.json`에 고정했다. 로컬 순수 비교 시험 20개와 Python 구문 검사는 통과했다.

첫 v2 실행은 실행 파일 117,696,088B가 읽기 한도를 넘어 job 생성 전에 거절됐다. 고정 Suricata 실행 파일만 128MiB로 보완한 v3에서는 실제 updater가 **4.968초, exit0**으로 완료됐고 보호 파일은 불변이었다. 후속 전량 비교가 local 전용 parser로 ET 문법 일부를 거절했다. v4는 기존 parser를 local/ET 예외 검증에만 유지하고, 전량 비교에는 SHA 고정된 설치본 `suricata.update.rule`을 사용한다. v4도 updater 4.92초·exit0·보호 파일 불변을 확인했으나, 후속 자체 quote tokenizer가 `native_raw_unterminated`로 거절했다. v5는 이 tokenizer를 제거하고 설치본 `Rule.raw`의 바깥 공백만 제거한 문자열을 그대로 비교한다. v5는 활성 원본 52,495개와 후보 52,787개를 끝까지 비교하여 변경/제거0·추가292를 확인하고 거절했다. updater의 flowbit 의존성 자동 활성화였다. 원본 전체 snapshot을 보존하고 pinned native parser로 현재 활성 행만 별도 입력으로 만드는 v6에서는 **3.369초·exit0, 52,495개 동일, 추가/제거/변경0, 두 예외 검증·보호 파일 불변**을 확인했다. 이어 고정 A에서 격리 native 구문 시험도 **16.075초·exit0, 52,495 loaded/failed0/skipped0**으로 통과했다. Suricata 보호 파일·raw inode와 기존 프로세스는 불변이고 private tree는 제거됐다. 운영 규칙 반영·PCAP replay는 수행하지 않았다. 앞선 실패의 source·결과·로그·metadata 이력을 보존하며, 중복 fullET 사본은 보관 manifest에 따라 정리했다.

영구 소스·증거 경로, 제한된 수동 실행과 staging 정리는 [운영 절차](OPERATIONS.md)를 따른다.

## 사용하는 도구와 산출물

- `candidate.py`: 같은 고정 컨테이너 안에서 한 번 실행한다. 현재 ET/local/all과 updater의 `.py` 33개, 실행 파일·YAML의 39개 SHA를 전후 대조한다. 새 private 디렉터리의 cache/output만 사용한다.
- `compare_rules.py`: 기존 승인 worker의 SHA를 확인하고 AST에서 순수 parser/예외 검증 함수 4개만 local/ET 예외 검증에 재사용한다. 전량은 설치본 `rule.py` SHA를 별도로 확인해 native parser로 읽으며 활성 행의 parse 실패를 조용히 건너뛰지 않는다. worker의 실행·권한·승인 함수를 실행하지 않는다.
- `test_compare_rules.py`: 기존 local 규칙에 기반한 순수 합성 오라클 20개. 실제 ET 전량이나 native 엔진 시험을 대체하지 않는다.
- `verify-native-a.py`: 고정 v6 job 후보만 대상으로 기존 SHA 고정 shadow helper의 mount/net/PID 격리를 재사용하는 A 관리자 일회성 구문 검사다. root 전체를 RO로 만든 뒤 임시 로그/run/tmp를 RW로 가리고 후보만 `/rules/all.rules`에 RO bind한다. 엔진 -T exit0와 52,495 loaded/failed0/skipped0, 운영 핀·raw inode 불변, 임시 tree 제거를 모두 요구한다. 반복용 일반 입력 API나 승인 worker가 아니다.
- `native-pins-2026-10-15.json`: root가 실측한 고정 CID/image 및 파일 SHA. 배포 시 root:root 0400으로 두며, 다른 이미지/규칙에 재사용하려면 다시 검토한다.

현재 ET 47,684,589 bytes + local 13,546 bytes = all 47,698,135 bytes다. 기존 승인 worker의 `all.rules == suricata.rules + GROOT_A_local.rules` 바이트 계약을 유지한다. updater의 출력은 주석 제거·정렬·중복 SID 선택 때문에 이 합본과 다른 파일일 수 있다. 출력 전체를 운영 `/rules/all.rules`에 복사하는 기능은 없다.

## 고정 실행 절차

아래는 **10/15 당시 고정 입력과 pin의 재현 조건 기록**이다. 현재 저장소 소스의 pin은 위 10/16 기록을 따르며, 새 시험에는 해당 버전에 맞는 별도 승인 소스·실행기·입력 확인이 필요하다.

운영자는 A의 기존 rule-change 잠금 다음 Vector 공유 잠금을 잡고, 고정 CID `39ce628179fb39cac72fa59ccb562475a8f874a58eec401b6c6e187614bebd0d`, 이미지 `sha256:d4fd70f7955f1f9d5c8f54d0b91dd22e359bebce6fba5423d1182f33ae0d59ff`, 현재 PID/StartedAt, `/rules`의 RO mount를 먼저 확인한다. root/operator가 기존 권한으로 수행하며 MCP·LLM 실행 권한은 늘리지 않는다.

1. 승인된 소스 2개(`candidate.py`, `compare_rules.py`), manifest, 현재 `rule_change_executor.py` 사본을 같은 컨테이너의 새로운 root 전용 source 디렉터리에 전달하고 SHA를 확인한다. worker SHA는 `d937c7def4d2938d7655e445cb5cf9cd7858837aebebaf4278feae5fb69965a2`다. source·manifest의 변경 가능한 경로를 일반 사용자에게 주지 않는다.
2. 고정 CID로 root의 종료형 Python을 실행한다. 마지막 인수는 재사용하지 않는 16자리 소문자 hex다. 외부 wrapper 전체 상한은 300초 이상으로 설정하고, 정상/실패 결과와 private 로그를 먼저 보존한다.

   ```sh
   /usr/bin/python3 -B /tmp/OPERATOR_SOURCE/candidate.py \
     /tmp/OPERATOR_SOURCE/native-pins-2026-10-15.json \
     /tmp/OPERATOR_SOURCE/rule_change_executor.py 2026101500000001
   ```

   결과 디렉터리는 `/tmp/capstone-suricata-update-20261015-2026101500000001`이다. `OPERATOR_SOURCE`는 운영자가 준비한 고정 전달 경로이며 웹/MCP 인수가 아니다. 부모 wrapper는 정확 CID/image와 live PID/StartedAt 불변을 사후에도 대조한다.
3. 원본 ET/local/all 사본을 먼저 SHA 확인 후 보존한다. 설치본 native parser의 활성 행만 `et-active.rules`/`local-active.rules`에 투영하고 재parse 결과가 같은지 확인한다. ET 파생본을 신규 cache에 넣고 그 파일만 가리키는 `file://` URL과 `--offline --no-reload --no-test`를 사용한다. 기본 ET Open fallback, 기존 cache/source registry, 기본 update.yaml/enable/disable/drop/modify.conf 및 배포본 추가 규칙을 사용하지 않는다. `DATA_DIRECTORY`, proxy, PYTHONPATH 등 상속 환경을 제거한다. `update.yaml`은 실행마다 private 경로로 생성하며 산출물에 보존한다.
4. updater는 현재 활성 규칙의 private local/ET 파생본을 처리한다. 1.3.8에는 flowbit 자동 해결을 끄는 분기가 없으므로 비활성 원문 규칙을 이 단계 입력에 넣지 않는다. native resolver나 vendor source는 수정하지 않는다. 원본 대비 활성 집합을 바꾸려는 옵션이 아니다. 운영 YAML 자동 필터는 끄고 병합 결과만 조사한다. 실제 적용 중인 YAML을 기준으로 규칙을 자동 비활성화하거나 vendor feed를 바꾸는 절차가 아니다. 활성 `(gid,sid)`별 최고 revision의 native `Rule.raw.strip()` 문자열을 전수 비교하고, 추가·제거·변경을 하나라도 찾으면 거절한다. 두 ET SID 2034802/2034806만 승인된 중복을 허용하며, vendor 원문 대비 좁은 flowbit 추가와 rev+1도 기존 validator로 검사한다.
5. 성공 상태는 **`candidate_compared_native_test_pending`**이다. `native_syntax_verified`와 `native_replay_verified`는 false다. `result.json`, `comparison.json`, input 사본, output, 실행 argv/config/log를 A에 보존한다. 원문 규칙은 필요 없이 Mac에 출력하지 않는다. 실패도 같은 디렉터리에 남기며 다른 attempt로만 다시 실행한다.

## native 검증과 승인 경계

Suricata 8.0.6의 `-T`도 output 초기화를 먼저 수행한다. 따라서 `-l private`만 붙이고 live YAML을 그대로 넘기면 absolute EVE 경로 접근을 막지 못한다. 이 runner는 엔진의 `--build-info`/버전 조회를 제외하고 `-T`나 replay를 실행하지 않는다. 다음 native 단계는 기존 읽기 전용 mount namespace + private log/run 경로를 쓰는 검증 경로에서 수행해야 한다. 운영 EVE/CP 파일로 쓰기 가능한 테스트는 허용하지 않는다.

현재 도구는 후보 생성·구문 검증까지 사용한다. 출력으로 운영 합본 방식을 교체하려면 다음 승인 경계를 별도로 확인한다.

1. 실제 설정을 기반으로 격리한 엔진에서 전체 후보 `suricata -T -S <candidate>` 성공, failed/skipped 0과 source SHA 결속. 이번 v6에서는 완료했으며 다른 후보의 결과로 재사용하지 않는다.
2. 기존 `infra/mcp/validate_dgx_endpoint_transition.py`의 27개 PCAP 회귀를 재사용한다. 새 도구 출력에서 현재 local SID와 ET 예외를 추출한 후보 및 기존 합본 대조군을 사용한다. HTTP 요청을 보내거나 live sensor에 replay하지 않는다.
3. parsed 규칙 집합 동일성은 모든 트래픽에 대한 실행 동등성·장기 오탐률의 증명이 아니다. updater가 flowbit 의존성 때문에 규칙을 추가/변경하면 그 차이를 승인 없이 되돌리거나 무시하여 PASS시키지 않는다.
4. 현재 worker는 ET 원본을 고정한 local 변경만 승인한다. ET 업데이트 또는 updater 출력의 직접 채택은 이 권한에 포함되지 않는다. 이번에는 운영 byte-concat과 승인 경로를 변경하지 않는다. 향후 feed 갱신에는 ET/local/all 3개 SHA, 예외 재생성, native/PCAP 결과와 실제 변경 diff를 묶는 별도 검토가 필요하다.

아래는 완료한 v6 구문 시험의 재현 조건 기록이다. 해당 고정 job/source staging은 영구 보존 후 이미 정리했으므로 그대로 재실행하지 않는다. 새로운 시험은 새 검토와 고정 입력이 필요하다. 당시 운영자는 고정 A `/var/tmp/capstone-tools-followup-20261015/suricata-native-source` root0700에 `verify-native-a.py`와 기존 `deploy-raw-operations-a.py`(SHA `6dcf1556f89c8882a422cf92a3c8caa90bbdcdf71b809d0224587fe45b17db15`, root0400)를 둔다. `python3 -B …/verify-native-a.py`가 자체로 rule-change→Vector lock을 잡으므로 바깥에서 같은 잠금을 다시 잡지 않는다. 고정 job `0819000000000004`, 후보 SHA `0da12c9990b80e346f18cb7c370960010bc5fccc8a740dc2d1892c3664afb436`, 35,666,630 bytes만 검사한다. 결과/진단은 host `…/suricata-native-v6/`에 보존하고 container 임시 tree만 정리한다. PID나 원본 규칙이 바뀌면 실행을 거절한다. native helper의 초기 migration CLI는 호출하지 않는다.

## 근거

공식 문서는 지원 Suricata에 updater가 포함되므로 먼저 설치 여부를 확인하도록 안내한다. 1.3.8은 archive 경로 이탈 취약점 수정 버전이다. [Quickstart](https://suricata-update.readthedocs.io/en/latest/quickstart.html), [공식 보안 권고](https://github.com/OISF/suricata-update/security/advisories/GHSA-6v4p-4w5x-9fp2)

`--offline`은 기존 cache를 사용하고 `--local`은 로컬 규칙을 추가한다. private cache/config가 필요한 이유다. [공식 명령 문서](https://suricata-update.readthedocs.io/en/latest/update.html)

공식 source의 `Fetch.fetch`, `build_rule_map`, `resolve_flowbits`, `load_dist_rules`, `config.init`를 검토했다. 공개 master는 설계 근거이며 실제 실행은 설치본 33개 source SHA로 고정한다. [updater main.py](https://github.com/OISF/suricata-update/blob/master/suricata/update/main.py), [config.py](https://github.com/OISF/suricata-update/blob/master/suricata/update/config.py)

8.0.6 `suricata.c`의 `PreRunPostPrivsDropInit`에서 output 초기화 후 `RUNMODE_CONF_TEST`가 종료된다. [고정 버전 소스](https://github.com/OISF/suricata/blob/suricata-8.0.6/src/suricata.c#L2946-L2956)

1.3.8 `resolve_flowbits`는 활성 rule이 요구하는 흐름 상태를 설정하는 비활성 rule을 재귀 활성화하고 noalert로 바꾼다. 이 동작은 개별 경보를 추가하지 않아도 다른 규칙의 판정을 바꿀 수 있다. 자동 활성화를 승인한 것으로 취급하지 않으며 현재 v6에서는 그 입력 후보를 제외한다. [고정 1.3.8 소스](https://github.com/OISF/suricata-update/blob/1.3.8/suricata/update/main.py#L674-L699)
