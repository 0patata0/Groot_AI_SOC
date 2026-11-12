# A(센서) Wazuh 에이전트 버퍼 확대 후보

2026-11-13 KST. **후보·라이브 읽기전용 드라이런까지이며 운영에는 미적용**이다. 컨트롤러의 `APPLY_REVIEWED=False`라 apply는 막혀 있다. 사용자 승인 후 이 값을 바꿔 커밋하고, 그 소스로 `prepare`→`apply`→`verify`를 관리자231 경유로 실행한다. [rule 203 전체 경과](../../../../validation/rule203/README.md) · [작은 원장](validation.json) · [현황](../../../../../STATUS.md).

## 왜

| 날짜(KST) | A rule 203 | 버퍼 포화 지속(“가득 참” 2초 간격 경고 수 기준) | 그 구간의 A 경보 |
|---|---|---|---|
| 10/29 17:02~ | 47건 | 약 94초 | 283건(재접속 34분 뒤) |
| 11/2 14:42~ | 36+1건 | 약 74초 | **6,505건**, 분당 최대 3,840·초당 최대 303(실제 WAF·IDS 공격 시험) |
| 11/5 17:54~ | 23건 | 약 46초 | 167건(재접속 10분 뒤) |

A는 Suricata eve·ModSecurity·Vector 정규화 3개 경로를 수집하는 IDS/WAF 센서다. 버퍼는 패키지 기본값 **5000건·500건/초**다. 포화 구간에 들어온 이벤트(공격 시점 증거 포함)가 유실될 수 있다. rootcheck 결과는 19건뿐이라 B와 원인이 다르다. 10/29·11/5는 경보 수가 적어 level 0 이벤트나 재접속 뒤 몰린 로그로 추정한다(미확인). 11/5 이후에는 공격 시험이 중단돼 재발이 없다.

## 후보 값과 근거

`queue_size` 5000 → **100000**, `events_per_second` 500 → **1000**(둘 다 Wazuh 허용 최대값).

- A는 공격 증거를 모으는 센서라 유실보다 지연이 낫다. 가득 찼을 때 최대 약 100초 늦게 전달되지만 버리지 않는다.
- 최악의 메모리는 약 160MB다(10만 건 × eve 평균 1.6KB). A의 가용 메모리는 4.5GB였다.
- **한계**: 과거 입력 속도를 측정할 수 없어 충분한지는 다음 공격 시험에서만 확인할 수 있다. 원천 중복 수집(raw eve와 Vector 정규화 증거 경로)의 볼륨 축소는 구조 변경이라 이번 범위가 아니다.

## 변경 방법 — 10/15 적용된 컨트롤러 재사용

A의 `ossec.conf` SHA는 raw 상태 2개(`/var/lib/capstone-raw-operations/{suricata,modsecurity}/state.json`)의 `source_pins.wazuh_config_sha256`에 CAS로 고정돼 있다. 설정만 바꾸면 리더 가드가 Vector/Wazuh 읽기를 보류한다. 그래서 2026-10-15 실제 적용된 [`fix-stats-ignore-a.py`](../checkpoint-diagnosis/fix-stats-ignore-a.py)의 트랜잭션을 그대로 이식했다(`tune-buffer-a.py`). 잠금·CAS·유닛·가드·시작 차단 헬퍼가 원본과 같은지는 테스트로 고정했다.

1. 공유 잠금 2개를 잡는다. `prepare`는 런타임 9파일 SHA·설정 기준 SHA(`d65f9da4…`)·상태 2개(active·대기 없음·고정 SHA 일치)·리더 가드를 확인한다. 그다음 비공개 `/var/backups/capstone-agent-buffer-20261113`에 3파일 전/후와 `wazuh-agentd`·`wazuh-logcollector -t -c` 결과, 계획을 기록한다. 운영 변경은 없다.
2. `apply --plan-sha256`은 계획·컨트롤러 SHA 결속과 30분 이내를 확인한다. 이후 타이머 3개 일시 중지 → 시작 차단 drop-in → Wazuh 정지 1회 → 가드 → 3파일 CAS(상태는 revision+1·고정 SHA만 변경, 원본은 history에 보관) → 차단 해제 → Wazuh 시작 1회 → 검증 → 유닛 정책·타이머 복원 순서로 진행한다. Vector는 멈추지 않는다. 자동 재시도·자동 원복은 없다. 실패하면 단계·완료 경로·결과불명 경로를 기록하고 조사를 요구한다.
3. `verify`(읽기전용)는 새 설정·상태 SHA, `state.jq`, Vector 불변, Wazuh 새 기동, 라이브 버퍼 값, 에이전트 연결, 가드를 확인한다.

새 설치는 `deployment/log_pipeline.py`의 `agent_buffer()`가 같은 값을 적용한다(`activate security`의 `agent_configuration`). 두 경로의 값이 같은지는 테스트로 고정했다.

## 검증

| 항목 | 결과 |
|---|---|
| 컨트롤러 테스트(`test-tune-buffer-a.py`) | 16/16. 버퍼 두 값만 변경·주석/AR 보존, 이미 적용·다른 값·없음·중복·비활성·속성·CRLF/NUL 거부, 상태 revision+1·고정 SHA만 변경, 대기/다른 고정 SHA/엔진 불일치/비정규 거부, apply 차단(`APPLY_REVIEWED=False`), 실제 원자 교체·변경 감지·결과불명 기록, 상위 디렉터리 권한, **헬퍼가 10/15 적용본과 동일**, 새 설치 값 일치 |
| 원 컨트롤러 테스트 | 30/30(무회귀) |
| 설치기 `deployment/test_log_pipeline.py` | 40/40(버퍼 적용·멱등·거부 추가, 기존 AR/raw 보존 테스트 갱신) |
| A 라이브 읽기전용 드라이런(02:27) | 런타임 9파일 SHA 일치. 설정 diff **2줄**(5000→100000, 500→1000), 후보 SHA `e4f25140…`. 상태 후보 suricata rev 152→153·modsecurity 114→115 모두 `state.jq` 통과. 임시 사본 `wazuh-agentd`·`wazuh-logcollector -t -c` 0. 시작 차단 drop-in 없음, 서비스·타이머 정상, logcollector 1개, 가드 ready, 증거 디렉터리 없음, 라이브 설정 불변, 임시 사본 삭제 |

## 적용 시 유의

- 적용 중 Wazuh 에이전트를 1회 멈췄다 다시 시작하므로 수 초간 A 로그 전달이 멈춘다. 재시작 뒤 오프라인 구간 로그가 몰려 들어오는데, 확대된 버퍼가 받아낸다. 공격 시험이 없는 시간에 실행한다.
- 상태 파일이 5분 주기 타이머로 바뀔 수 있으므로 `prepare` 뒤 30분 안에 `apply`한다. 그사이 상태가 바뀌면 apply가 거부한다. 새로 prepare하려면 기존 증거 디렉터리를 조사·보존한 뒤 새 이름을 써야 한다.
- 버퍼 크기가 충분한지는 다음 공격 시험에서 rule 203 부재와 미전송 없음으로 확인한다(공격 시험은 중단 상태).
