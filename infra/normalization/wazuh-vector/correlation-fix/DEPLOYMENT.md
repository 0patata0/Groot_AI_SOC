# B의 상관 처리 작업자 설정 후보

이 후보는 기존 B Wazuh manager의 `local_internal_options.conf`에서 `analysisd.event_threads=1`, `analysisd.rule_matching_threads=1`만 적용한다. 패키지·컨테이너 구성·규칙 내용·MCP 승인 권한을 바꾸지 않는다. 관리자 전용 수동 작업이며 LLM 실행 대상으로 등록하지 않는다.

현재 B native syntax/check·옵션 합성 **11개**·건강 조건 합성 **10개**를 통과한 후보를 운영에 적용했다. **2026-10-14 18:48:55 KST** 같은 manager 컨테이너의 적용이 성공했고, 18:49:04 후속 상태와 이후 **60초 관찰을 완료**했다. 자연 입력60건·drop 증가0·queue 표본 최대0을 확인했다. 사용자 명시 승인 후 실제 **20회 burst/260행을 한 번만 입력했고18:56:08 manager40건/Indexer40건 종단 검증도 통과**했다. 이번 결과를 장기·모든 부하의 무손실 보장으로 해석하지 않는다. [최신 재개 결과](deployment-resume-2026-10-14.json) · [후보 검증 메타데이터](native-validation-2026-10-14.json).

최초 후보 작성 당시에는 로컬 구문 검사와 독립 읽기 검토만 마쳤다. 초기 94파일/141,064bytes 반입은 자동 승인 검토가 두 번 거절하여 원격 검증과 운영 적용을 중단했다. 이후 사용자의 같은 전송 재시도 지시를 받고 반입에 성공했다. 다른 경로나 도구로 우회하지 않았다.

## 파일과 사전 조건

- [apply-b.yml](apply-b.yml): 원본·컨테이너 CAS, 두 줄 후보, native 검사, 같은 컨테이너 재시작, 제한된 rollback.
- [run-b.sh](run-b.sh): 고정 B machine-id/root, private 경로, 기존 `wazuh-vector.lock` → `rule-change/.lock`, 기존 Ansible 2.21만 사용한다.
- [test-options-policy.py](test-options-policy.py): 실제 playbook의 순수 변환·검증 task 11개와 적용/복구 건강 조건 10개를 B의 기존 Ansible에서 검사한다. Docker/서비스/운영 파일 task는 선택하지 않는다. Mac에 실행 의존성을 설치하지 않는다.

읽기 전용 B 조회에서 controller 2.21.5와 기존 etc named volume을 확인했다. 옵션 경로는 `/var/lib/docker/volumes/single-node_wazuh_etc/_data/local_internal_options.conf`이며 당시 uid0/gid999/0640/nlink1/320bytes였다. B에는 별도 Vector 서비스용 `vector.lock`이 없으므로 실제 존재하는 위 두 lock을 사용한다.

playbook 옆 `preflight.json`은 root0600·일반 파일·링크 수1로 관리한다. 저장소에 운영 pin 파일을 넣지 않는다. 키는 아래 6개만 허용한다.

| 키 | 의미 |
| --- | --- |
| `generated_at_epoch` | 같은 B에서 새로 수집한 Unix 초. 실행 시 30분 이내 |
| `manager_id` | `single-node-wazuh.manager-1`의 전체 64자리 ID |
| `options_sha256` | 현재 `local_internal_options.conf` SHA-256 |
| `ossec_conf_sha256` | 현재 `ossec.conf` SHA-256 |
| `local_rules_sha256` | 현재 `rules/local_rules.xml` SHA-256 |
| `vector_rules_sha256` | 현재 `rules/capstone_vector_rules.xml` SHA-256 |

재적용에서도 pin을 실제 상태와 대조한다. 예전 원본 SHA를 새 파일에 맞추기 위해 임의로 덮어쓰는 절차가 아니다. 미지 파일/컨테이너/중복 옵션/CRLF·NUL·마지막 LF 누락은 적용 전에 거절한다. 대상 두 줄을 제거했을 때 원본과 후보의 나머지 바이트가 같은지도 검사한다.

## 승인 후 실행 순서

부모 디렉터리에 기존 `ansible.cfg`, `inventory.ini`, manager 테스트 4개와 그 fixture를 유지한 root 전용 번들이 필요하다. 고정 wrapper가 임의 Ansible 인자를 전달하지 않는다.

```sh
/bin/bash correlation-fix/run-b.sh syntax
/bin/bash correlation-fix/run-b.sh check
/opt/capstone-automation/venv/bin/python -B correlation-fix/test-options-policy.py
# 운영 적용은 검증 결과와 적용 시점을 조율한 뒤에만 수행한다.
/bin/bash correlation-fix/run-b.sh apply
```

`check`는 후보 텍스트·pin·읽기 메타데이터만 검사하며 native 프로세스나 재시작을 실행하지 않는다. `apply`는 기존 `analysisd -t`와 104개 native 규칙 시나리오를 확인한다. 변경이 필요하면 root 전용 `/var/backups/capstone-correlation-fix-*`에 원본과 후보를 보관하고, 보호 파일과 옵션·name→CID를 다시 확인한 후 옵션만 원자 교체한다. 후보 `-t` 뒤 같은 **전체 CID**를 한 번 재시작하고 건강·104개 시나리오·`-t`·보호 파일·최종 옵션 SHA를 재검증한다. 이미 1/1이면 검증만 수행하며 파일·백업 생성·재시작이 없다.

일반 실패 시 복구는 같은 name→CID, 원본 또는 후보 SHA, 원래 권한, 백업 SHA가 모두 맞을 때만 수행한다. 재시작 시도 전 실패면 옵션 원복만 하고, 재시작 시도 후 실패면 원래 옵션으로 같은 컨테이너를 다시 시작한다. 복구 후 건강·`-t`·원본 SHA/메타데이터를 확인한 뒤 배포 실패로 끝낸다. 규칙·DB·대화·수집 체크포인트를 되돌리지 않는다. 관리자 외부 변경, 전원 장애, Ansible 강제 종료, Docker 제어 응답 불확실성은 자동 rollback 보장에 포함되지 않는다. 이 경우 보관된 원본과 실제 상태를 먼저 대조한다.

## 판정 한계와 후속 관찰

Wazuh 4.14.8의 `analysisd -t`는 `rule_matching_threads`를 읽지만, `event_threads`를 읽는 실행 단계 전에 종료한다. 따라서 `-t` 통과를 실제 두 작업자 수의 증거로 삼지 않는다. 재시작 후 시작 로그/프로세스 메타데이터와 별도 native 1/1 시험 결과를 함께 확인한다. [공식 4.14.8 analysisd 소스](https://github.com/wazuh/wazuh/blob/v4.14.8/src/analysisd/analysisd.c).

1/1은 같은 JSON 처리 경로의 병렬 상관 경합을 줄이는 조치다. 처리량 감소·큐 지연/유실 위험은 관찰해야 하며 상위 수집 순서나 전송 성공을 보장하지 않는다. 실제 반복 canary의 manager/Indexer 결과, 같은 PID 내 state 누계 차이, 큐 사용량·drop, 기존 보안/승인 서비스와 모델 연결의 보존을 부모 작업에서 별도로 검증한다. 합성 logtest는 운영 수집 파일에 쓰지 않으며 차단이나 채팅을 발생시키는 시험으로 해석하지 않는다.

## 후속 native 후보 검증

최초 manifest는 그대로 보존하며, 실제 검증에서 발견한 두 문제만 보강한 [최종 manifest](deployment-payload-final-manifest.json)를 따로 남겼다. 최종 후보는 **94파일/143,365bytes**, playbook SHA는 `6263115c9be1db2d9a9fe0ef218fbabe4270c2b24eef4bc426e70c72cdb6c260`이다.

- 첫 native 시험은 YAML이 CR escape를 제어문자로 미리 해석해 정상 LF 파일도 거절했다. check는 변경 없이 실패했고, Jinja에 escape literal을 전달하도록 수정했다. 실패 로그·최초 소스 SHA를 보존했다.
- 수정본의 native syntax/check와 옵션 합성 **11개**가 통과했다. 부정 사례는 framing assert에서 중단되고 변환 단계로 넘어가지 않았다.
- 읽기 상태 조회에서 manager의 필수 네 프로세스가 정상이어도 optional 구성요소가 비실행이면 `wazuh-control status`가 **1**을 반환함을 확인했다. 적용/복구 건강 조건을 rc0 또는1과 필수 네 프로세스 running의 조합으로 제한했다. 두 실제 조건을 읽는 합성 **10개**에서 필수 프로세스 누락·not running·timeout124를 거절했다.
- 최종 native syntax/check·옵션11·health10이 모두 통과했다. check recap은 **ok15/changed0/failed0**이며 manager ID·StartedAt·운영 옵션 SHA는 불변이었다.
- native 변환으로 별도 root 임시 후보를 만들고 두 옵션 외 바이트 동일성을 확인했다. 원본 SHA는 `73252a6f47fff93d8ce62ca70a8f9196a216d5e09dc2228758fcf0b0ac77133f`, 후보 SHA는 `f77426cbe8f1b2a304593fb48c6c3b42355c03c42bf9c2e540786ee2473b2079`다.

이 후보 검증에서는 운영 apply·재시작·104개 실제 규칙 회귀를 실행하지 않았다. 해당 단계는 부모 배포 작업에서 같은 고정 playbook으로 수행하며 결과를 별도로 기록한다. 합성 health 검증을 실제 장애 유발 rollback 성공으로 해석하지 않는다.

## 운영 적용 기록 — 2026-10-14 18:48 KST

부모 배포 작업의 실측 결과를 전달받아 기록했다. 이 문서 갱신 과정에서는 추가 원격 호출이나 운영 변경을 수행하지 않았다.

- **18:48:55** 고정 playbook 적용은 exit0, **ok41/changed6/failed0/rescued0**으로 끝났다. 같은 컨테이너를 재시작했고 적용 전후 각각 104개 native 규칙 시나리오를 통과했다. 이번 성공 경로에서 rollback은 실행되지 않았다.
- `analysisd.event_threads=1`, `analysisd.rule_matching_threads=1`을 적용했다. 원본 옵션 SHA `73252a6f47fff93d8ce62ca70a8f9196a216d5e09dc2228758fcf0b0ac77133f`에서 검증된 후보 SHA `f77426cbe8f1b2a304593fb48c6c3b42355c03c42bf9c2e540786ee2473b2079`로 바뀌었다.
- 원본·후보·결과는 B root 전용 `/var/backups/capstone-correlation-fix-nsgyviqo/`의 `local_internal_options.conf.before`, `local_internal_options.conf.candidate`, `result.json`에 보관했다.
- **18:49:04** manager의 전체 CID는 유지됐으며 새 init PID는 **2132232**, analysisd PID는 **2132985**, analysisd 전체 스레드는 **44개**였다. 전체 스레드 수를 두 특정 작업자의 직접 계수와 혼동하지 않는다.
- 기존 running native 프로세스 **10종**의 종류가 같았고, 다른 컨테이너·서비스와 보호 파일 해시도 유지됐다. 이 시점의 drop은 **0**이었다. 이 한 번의 상태 조회는 장기 무손실 증거가 아니다.

## 후속 60초 관찰과 종단 시험 상태

부모 작업의 후속 관찰에서는 **60.000186초** 동안 received가 **60건** 증가했다(약1EPS). drop 증가 **0**, queue 표본 최대 **0**이었고, analysisd CPU는 한 코어 대비 비율 **0.000333332**, 약 **0.0333%**였다. 이 관찰에는 합성 canary가 포함되지 않았다. 낮은 부하에서 짧게 관찰한 결과이며 지속 처리량·장기 무손실을 증명하지 않는다.

별도로 준비한 **20회 burst/260행 운영 입력은 처음에0행에서 중단**됐다. 자동 승인 검토가 정확한260행 운영 입력에 대한 승인이 없다는 사유로 실행 전에 거절했다. 이후 사용자가 해당 범위를 명시 승인했고, 같은 입력을 한 번만 실행한 후속 결과는 아래에 기록한다. 이 입력은 위 자연 입력60초 관찰이 끝난 뒤의 별도 단계다.

## 실제 종단 검증 완료 — 2026-10-14 18:56:08 KST

부모 배포 작업의 최종 실측 결과를 전달받아 기록했다. 동일한20개 run의 **260행을1회 입력**했고, manager와 Indexer에서 각각 **40건**을 확인했다. 두 경로 모두 `100293`20건·`100294`20건, level3이며 negative0이었다. 각 run과 전체의 canonical tuple이 정확히 일치했고57/57shard 성공, CA 및 호스트명 TLS 검증을 통과했다.

전체 첫 읽기1회에서 기대값을 확인했으며 읽기에는11.3초가 걸렸다. **입력 재시도는0회**였다. 처음 거절된 호출에서 입력이 발생하지 않았고, 명시 승인 뒤 같은20개 run을 한 번만 보냈다는 경계를 유지한다.

시험 전후 A 보호 설정과 기존52행 prefix·파일inode, B 옵션·규칙·같은CID·SOC 안전 경계가 보존됐다. [최신 재개 결과](deployment-resume-2026-10-14.json)는 최초 중단 기록과 분리해 보관한다. 이번 시험에서 상관경보 누락이 재현되지 않았으며, 과거 누락의 세부 실행 순서를 소급 확정하거나 장기·다양한 부하의 무손실을 보장하지 않는다. 격리500EPS 시험에서 확인한 적체·배출 지연 한계도 계속 유효하다.
