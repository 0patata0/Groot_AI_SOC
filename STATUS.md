# 인프라 현황 — 2026-11-12 23:15 KST

전체 목표는 **LLM 실전 관제 운용·논문 완성·2026-12-01 발표**이며 미완료다. 정확성이 속도보다 우선이다. 최신 균형1,220건 학습본을 운영하면서 보완한다. 학습본 사용과 독립적인 정확도 우위는 구분한다. [활성 계획](PLAN.md) · [직전 상세 상태·실패 이력](archive/STATUS_HISTORY.md#source-a961b1d1c0e72743).

## 현재 작업: 채팅 Harness² 점검 거버넌스(#5) — Unit 1·2·3 후보 완료 (11/12 23:05, 로컬 구현·테스트)

작업 #5는 **채팅에서 Harness² 점검을 관리자 승인 카드로 요청·적용**하는 거버넌스 기능이다. 사용자 지정 범위 = **전체 경로 둘 다**: (a) 점검 요청→카드→승인→워커가 수동 점검 실행→결과 읽기, (b) 점검의 `review_drafts`(개선안)→카드→승인→워커가 개선 적용→검증. 안전민감(브로커 카드 종류·루트 워커·스킬/설정 변경)이라 **후보(코드+테스트)로 단위별 구현**하고 거버넌스 배포·실제 채팅 검증은 분리한다.

| Unit | 내용 | 상태 |
|---|---|---|
| **Unit 1: 읽기 도구(읽기전용, 저위험)** | 읽기전용 MCP에 `get_harness_check_status` 추가. 비루트 MCP(`capstone-mcp`/`ruleview`)는 harness2 reports(root 0700) 직접 불가 → 기존 **sudo 읽기전용 헬퍼** 경로 재사용: `rule_change_executor`에 읽기 연산 `harness-status` 추가(루트가 고정 경로 `server_audit.py --latest`를 격리 실행·소유권/모드·크기·형태 검증 후 중계; `ruleview`만, `rulechg` 거부). `server_audit.py`에 `--latest`(감사 미개시, `get_latest()` 요약) 추가. 도구 설명에 `automatic_adoption:false`·승인 필요·구조통과≠런타임정확 명시 | ✅ **후보 구현·로컬 테스트 완료(미배포)** |
| **Unit 2: 점검 요청 카드(중민감도)** | B 전용 쓰기 도구 `request_harness_check(reason)` → **비변경 operation 하위종류 `harness_check`** 브로커 카드(상위 종류·cleanup KINDS 불변) → 관리자 승인 → 워커가 `capstone-harness2-audit.service`를 **정확히 1회** 실행. 서비스 작업과 동일 durable exactly-once·중단 시 미재실행 규율(상태해시/preflight는 비변경이라 제거). 진행상황은 기존 `get_operation_status`로 추적 | ✅ **후보 구현·로컬 테스트 완료(미배포)** |
| **Unit 3: 개선 적용 카드(최고 민감도)** | 범위=**승인+결정론 재동기화**(사용자 선택). `review_drafts`는 설계상 자동적용 불가(`apply:False`)라 **임의 자동 적용 안 함**. 유일한 안전·결정론 변환인 **skill-drift 재동기화**만 적용: `request_harness_skill_resync`(B 쓰기)→`harness_review`(mode=resync) 카드→승인→워커가 **정본 surface 복사본의 정확한 바이트**로 드리프트 복사본을 1회 덮어쓰기(전/후 SHA CAS·백업·검증, 모델 생성 내용 0). 구조이상·중복의심은 `acknowledge_harness_finding`→카드→승인=**확인 기록만(파일 변경 0)**, 실제 수정은 기존 거버넌스 경로. `report_sha256`는 현재 점검 보고와 일치해야 함(공급출처 결속) | ✅ **후보 구현·로컬 테스트 완료(미배포)** |

- **회귀(로컬)**: Unit 1 — `test_rule_change_mcp`·`test_rule_change_executor`·`test_server_audit`. Unit 2·3 합산 — `test_operations_approval` **21**(harness_check/harness_review 카드·approve/consume/applied·잘못된 plan/target/mode 400), `test_service_action_executor` **37**(HarnessCheckService 7: 1회 실행·멱등·거부/중단/만료/실패; HarnessReviewService 7: 정본 바이트 재동기화·멱등·드리프트없음/보고불일치 거부·승인후 대상변경 abort·중단 미재실행·deny·acknowledge 무변경·host a 거부), `test_rule_change_executor` **73**(디스패치 host-b 가드·`_operation_services` host-b 2워커), `test_rule_change_mcp` **17**(쓰기도구 host b·인자거부·읽기MCP 미노출). `test_incident_containment` **46**·`test_approval_card_cleanup` **39** 회귀 통과. 권한·승인·보호 정책 **불변**: 재동기화는 기존 관리 파일 2개 사이의 해시결속 바이트 복사뿐이며 LLM 임의 패치·일반 sudo/Docker·컨테이너 재구성 위임 **없음**.
- **미완·배포 전제**: 거버넌스 배포(관리자231 경유)와 **실제 카드 클릭→워커 실행 E2E** 미검증. **재동기화 배포 전 반드시 라이브에서 확인**: ① 3 surface 스킬 파일 경로가 실제 런타임 로드 파일인지(소유자·모드), ② 덮어쓰기 후 봇이 재로드하는지(또는 재시작 필요), ③ 어느 surface가 정본인지는 관리자 판단. 후보는 server_audit 고정 경로맵을 권위로 사용. 구현/정적 통과와 실제 운영 검증을 구분한다.

[MCP 도구](infra/mcp/rule_change_mcp.py)·[실행기/워커](infra/mcp/rule_change_executor.py)·[운영 실행기 HarnessCheckService](infra/mcp/service_action_executor.py)·[승인 브로커](infra/mcp/operations_approval.py)·[감사 CLI](infra/validation/harness2/server_audit.py)·[프로토콜 문서](infra/mcp/approved-operations.md). 로컬 세션 기록은 Git 제외.

## 현재 작업: LLM 운영설정 공통화·SKILL.md 공통 정리(#6) (11/12 23:10, 리포 문서·테스트)

핵심 확인: **스킬·공통 스크립트·시스템 프롬프트는 이미 `infra/hermes/` 단일 소스**에서 sdk(`ollama_trial.py`)·management(`soc_management.py`)가 배포한다(배포 시 동일 바이트, 드리프트는 라이브 핫에디트에서만—#5가 처리). 즉 **물리적 공통화는 사실상 완료**였고, 남은 작업은 그 공통 모델을 **명시·강제**하는 것.

| 산출물 | 내용 | 상태 |
|---|---|---|
| `infra/hermes/OPERATIONAL_SETTINGS.md` | 단일 소스 지도(소스→surface 경로/파일명), 5개 스킬 공통 운영원칙 7가지(권한 미부여·soc-output 재사용·단계 구분·근거/미확인 보존·상태 비승계·KST/용량 공통·내부 제어 줄), 정당한 surface 차이, 유지·강제 경로(Harness² 드리프트 탐지 + #5 승인 카드) | ✅ 작성 |
| `infra/hermes/test_common_operational_settings.py` | 불변식 회귀 **5통과**: 단일 스킬 소스 트리·skill-soc-*.md 포크 없음, frontmatter 공식 창(≤600B)·name 일치, 워크플로 스킬의 soc-output 재사용·버전 마커, 공통 스크립트/SOUL 단일본, 두 배포기(ollama_trial·soc_management)가 hermes에서 소싱 | ✅ 통과 |

- **범위·한계**: 스킬·프롬프트 **내용 변경은 운영 변경**(Harness² 구조검증·거버넌스 배포·실제 채팅 검증 대상)이라 이번엔 변경하지 않았다. native(A `groot-query-completion` 플러그인)의 스킬·SOUL 빌드 경로는 리포에서 전체 추적 못함(문서에 사실대로 구분). 이 작업은 소스 공통화의 **명시·강제**이며 라이브 바이트 일치·런타임 로드를 증명하지 않는다.

## 현재 작업: 에이전트 큐/병목 원인 분석(#7) (11/12 23:07, 라이브 B 읽기전용 진단)

B(관리자231 경유) 읽기전용 관측으로 "큐 가득 참"의 **구조적 원인**을 규명했다. **지금 큐는 비어 있다**(due_backlog 0·실행 중 0·inbox 처리 완료) — 상시가 아니라 경보 급증(DDoS) 구간의 부하 현상이다.

| 원인 | 증거 | 성격 |
|---|---|---|
| **단일 추론 슬롯 직렬** | Thor Ollama 모델 인스턴스 1개(35B Q4KM·22GB VRAM), 컨트롤러 `once()` 틱당 케이스 1건·조사 최대 280s 블로킹. 처리량 ≈ 1케이스/~3분 | 구조적 |
| **분산 플러드 출발지별 케이스** | `batch_identity`는 (agent,rule,src_ip,분)만 묶음(의도적). 분산 DDoS는 출발지 다수→케이스 다수(배치 391키 각 1건). 단일 슬롯×다수=적체 | 설계상 |
| **경보 수집 절단** | `alerts?minutes=5&limit=500` 고정. 5분 창 500초과분 누락(`alert_truncation_at` 기록) | 보호 계약 |
| **sticky 커버리지 플래그** | 전원차단 유래 `alert_coverage_gap_since`·`alert_truncation_at`가 리셋 경로 없이 고착→매 틱 `alert_coverage_gap/truncated:true` 표시(신호 오염). 단 "과거 손실" 정직 경고 의미도 있음 | 모니터링 |

- 결과적으로 부하 시 케이스가 단일 슬롯 배수 속도를 초과→타임아웃→needs_review 199·outcome_unknown 152(66%). (앞서 outer 타임아웃 240→300 배포로 완료율은 개선, 처리량 상한은 그대로.)
- **유효 해결 옵션**: ①Thor 추론 병렬화(GPU/VRAM 운영 결정) ②플러드 상관 1케이스 집약(기능·#11/#8 중첩) ③절단 요약/한도 상향(브로커 계약 변경) ④커버리지 플래그 의미 명확화.
- **선택·구현(사용자 선택=④, 후보·미배포)**: 컨트롤러 `ingest_alerts`/`summary`에서 `alert_coverage_gap`·`alert_truncated`를 **"현재 커버리지 저하"**로 재정의 — 적시(폴 간격≤300s)+비절단 폴이 확인되면 "0"으로 복원. **과거 공백/절단 창은 `alert_coverage_gap_last_kst`·`alert_truncation_last_kst`(+감사 저널)에 보존**해 손실이 계속 보이게 함(0으로 정규화 안 함). 전원차단 이후 매 틱 리포트에 붙던 **가짜 커버리지 공백 캐비엇 제거**. 컨트롤러 회귀 **119 통과**, 해당 테스트 현재/과거 분리로 갱신. (evidence 1건 실패는 HEAD 동일 기존 문제·무관.) 운영 배포는 거버넌스(후보→관리자231 경유 리터럴패치)로 분리. ①②③은 미착수(옵션 보존). [진단 이력](archive/DIAGNOSTIC_HISTORY.md)·[라이브 원문](대화기록/검증/2026-11-12-queue-diag/)(로컬).

## 현재 작업: 전원복귀(콜드부트) 복구 — outer 타임아웃·Vector 로테이션 (11/12 21:16, 라이브 A/B/C)

어제 전 서버 전원차단 → 오늘 13:32 동시 재부팅. 복구 점검 결과:

| 서버 | 상태 |
|---|---|
| B(siem)·C(web) | ✅ 완전 복귀(실패0·Wazuh 에이전트 4개 Active·MM·Thor터널·양봇·컨트롤러·DVWA) |
| A(sec) | ✅ 방화벽·Suricata·WAF·Wazuh에이전트·containment 증거(active.jsonl 최신) 정상. ⚠️ Vector 정규화 로테이션만 미완 |

- **outer 타임아웃 수정(완료)**: 컨트롤러 command_for의 모델 스트림 **outer deadline 240→300s**(소스 c11ee53, deploy111 리터럴패치 라이브 eeae57da, 30분 원복 취소·확정). deploy110의 280s 서브프로세스 타임아웃을 240s outer가 먼저 잘라 무력화하던 걸 해소 → 모델 조사가 full 280s 창 사용. 실증: 18:36 조사 188s 완료. **이것이 "관제가 안 됨"의 직접 원인(모델 조사 240s 중단) 해결.**
- **Vector 정규화 파이프라인(복구 완료, 전부 원격)**: 전원차단으로 세대 로테이션이 `publish_pending`/`old_closed` 중단. 2단계 게이트를 원격으로 통과시켜 복구. ①reader 게이트: maintenance `reader_at_eof`의 `sha1sum(정규화파일)==logcollector 저장 해시` 불일치(복구 중 Vector 재시작이 파일 재기록으로 유발). file_status.json 백업 후 ready/evidence/canary 해시만 현재 sha1로 재동기화(offset 유지→**중복 유입 없음**)→reader 통과. ②telemetry 게이트: `collection_telemetry_invalid`(Vector <180s 가동이라 현재 invocation의 fresh telemetry 부재). maintenance 타이머 일시 정지→Vector 무중단 가동→+210s 자동 maintenance 1회→**전 게이트 통과**. 결과(21:32): resume.pending **해제**, Vector **active(up 423s·재시작0)**, phase **active**, 로테이션 정상, maintenance 타이머 재가동. 가드가 전 과정 손상 방지(stuck-but-safe).
- **영향 구분**: 탐지·피드·containment 증거·모델 조사는 Vector 무관하게 정상(핵심 SOC). Vector 정규화→B 인덱스도 이제 복구. 복구 과정의 반복 개입은 가드로 손상 없음.
- **콜드부트 자동화(구현·설치·enable 완료)**: `capstone-vector-coldboot-recovery.{sh,service}`(소스 a0b0962, A `/usr/local/sbin`·`/etc/systemd/system`, enabled=multi-user.target.wants). 부팅 1회: 중단 로테이션 감지(정상 시 no-op)→maintenance 타이머 일시 정지→Vector 가드 기동→(FD·offset이 EOF인데 저장 해시만 어긋난 정밀 조건에서만) logcollector 해시 재동기화(offset 유지=중복 유입 없음, file_status 백업)→fresh telemetry까지 바운드 대기→guarded maintenance finalize 1회→타이머 항상 복원(trap). force·raw-state 편집 없음. **실증: 정상 파이프라인에서 no-op(“healthy; no recovery needed”, success)·설치/enable 확인. 실제 중단-부팅 E2E는 prod 재부팅 불가로 미실증**(로직은 11/12 수동 복구 그대로).

[실측 원문](대화기록/검증/2026-11-10-ddos-inspect/)(로컬, a_*·b_* 다수). 구현/배포와 실제 운영 검증, 완료와 부분복구를 구분한다.

## 과거: 관제 병목 진단·수정 배포(deploy110) (11/12 18:06, 라이브 B)

사용자 보고 "관제가 안 된다 + 병목 + 서비스 오류". 라이브 B 진단: 컨트롤러는 16초 주기로 정상 전달하나 **사건 조사의 66%가 실패**(완료 176 vs needs_review 195 + outcome_unknown 149). 세 수정 후보를 **운영 배포·확정**했다.

| 항목 | 확인/조치 | 상태 |
|---|---|---|
| soc-summary.service 실패 | **부팅 레이스**(13:34 부팅 catch-up이 Mattermost 미기동 시 Connection refused). reset-failed로 정리, **실패 유닛 0개**, 21:00 정기 실행 정상 예정 | ✅ 조치 완료 |
| 병목1: 모델 조사 타임아웃 | 141건 outcome_unknown=`model_subprocess_timeout`(실측 avg 138·max 214초). 타임아웃 210→280s·run-budget 250 + systemd `TimeoutStartSec` 290→360 drop-in | ✅ 배포 |
| 병목2: tool_failure 오분류 | 121 run 중 31(26%)=컨테인먼트 거부. 컨테인먼트 시도 86건 중 63건(73%) 거부. 후보①(거부=정상 분류) + 프롬프트(호스트 로그 사건 차단 금지) | ✅ 배포 |
| 소스 커밋 | ①cdee8cc ②③edb53bc. 컨트롤러 회귀 **189 통과** | ✅ 커밋·푸시 |
| **운영 배포(deploy110)** | 라이브 컨트롤러는 **render 산출물**(462KB)이라 raw 복사 불가·프로필 미저장. **리터럴 패치**로 배포: `ast.unparse(HEAD) vs ast.unparse(baseline)` diff를 **문맥 앵커/부분문자열 7패치**로 변환, 라이브(21ca9abc)에서 전 앵커 유일성 검증(ALL_MATCH)→SHA 사전확인·py_compile·백업·원자적 교체·30분 원복 타이머. 라이브 `9c6f5565`. 내장 게이트(run.py 불변)·무결성 가드 영향 없음 | ✅ 확정 |
| 배포 후 검증 | 배포 후 run **6+건 전부 정상 종료·0 실패**(108 같은 기동 실패 없음), 마커 9개 적재 확인. 원복 타이머 취소·백업 보존 | ✅ 안정 |

**운영 검증 별도:** 컨트롤러 코드는 안정 적재·실행됐으나, 실제 효과(타임아웃·tool_failure 감소)는 새 모델 조사가 쌓여야 관측된다. 구현/배포 성공과 실제 관제 품질 향상은 구분한다. systemd drop-in은 라이브 override이며 유닛 렌더러(repo 외부)엔 미반영—차이 기록. [실측·배포 원문](대화기록/검증/2026-11-12-deploy110/)·[진단](대화기록/검증/2026-11-10-ddos-inspect/)(로컬).

## 과거: 컨트롤러 후보 ①(컨테인먼트 거부 분류)·대시보드 임시 개방 (11/12 17:00)

| 항목 | 확인한 상태 | 남은 일 |
|---|---|---|
| **후보 ①**: 자동 사건보고 오분류 수정 | ✅ **후보 구현·로컬 검증 완료(미배포)**. 지배 실패였던 `temporarily_contain_ip`의 **자격-거부**(호스트 로그 사건에 모델이 차단 시도→헬퍼가 "no verified recent attack flow…" 등으로 정당 거부)를 컨트롤러가 `model_tool_failure`로 오분류하던 문제. `containment_not_eligible()` 추가로 **자격-거부 8종만** 예상 결과로 처리(`self.tool_error` 미설정), 증거/방화벽 **인프라 오류는 그대로 tool_error 유지**. 신규 회귀 3종 통과·컨트롤러 119/119 통과(+63/+58줄, 삭제0) | **운영 배포는 거버넌스**(후보→회귀→관리자 경유 적용→실제 채팅 검증). 안전민감 코드라 사용자/관리자 승인 전 미배포 |
| 대시보드 VPN 임시 개방 | ✅ 사용자 승인(재시작)으로 **chat/Mattermost 수준(VPN 포함) 3시간 개방**. Mac(VPN)에서 `https://wazuh.grootlab.duckdns.org` → **302 `/app/login`**(개방 전 403). **19:58 KST reload 기반 자동 원복**(재시작 불필요). chat 200 유지(재시작 영향 없음) | 원복 후 기준 설정(게이트 유지)은 소스와 동일. 상시 개방 아님 |
| 지난 개방 실패 **진짜 원인** | ✅ 규명: chatproxy가 `nginx.conf`를 **단일 파일 bind-mount**로 읽는데 rename 교체로 마운트가 stale(11/4 inode 고정)돼 **reload로 설정 변경이 반영 안 됨**. ACL/시간창 문제가 아니었음. 해결=제자리 기록+임시 컨테이너 문법검증+**재시작**. [진단 이력](archive/DIAGNOSTIC_HISTORY.md) | 향후 chatproxy 설정 변경은 reload 아닌 재시작 필요 |

기존 실패 1건(`test_soc_management_evidence`의 grounding_wrapper 연속 테스트)은 **HEAD에서도 동일 실패**하는 기존 문제로 후보 ①과 무관하다. 구현 완료와 실제 운영 검증은 구분한다. [실측 원문](대화기록/검증/2026-11-10-ddos-inspect/)(로컬).

## 현재 작업: 룰-조회 신뢰성·자동 사건보고 공백 (11/10 21:00, 실제 Mattermost 검증)

사용자가 실제 Mattermost로 봇을 시험하며 두 공백을 보고: (1) DDoS 사건보고 자동 미게시, (2) 추가한 룰을 LLM이 조회 못 함("없다/오타/답 바뀜"). 실제 사용자 경로(`https://chat.grootlab.duckdns.org`, socadmin)로 재현·검증했다.

| 항목 | 확인한 상태 | 남은 일 |
|---|---|---|
| DDoS 탐지·상관 | ✅ 정상: 재생 때 Wazuh 룰 100112(level 12) 15회·100110(9) 19회·level≥10 47건 생성(라이브) | — |
| 자동 **사건보고** | ⚠️ **파이프라인 정상, 모델 실패**: 구 cron은 10/15 durable controller로 의도적 교체(정상). controller DB에 report_outbox **854건 전부 sent**, DDoS 경보 inbox **6150건** 적재, DDoS 시간대 case 3건 생성·전달. HOME_CHANNEL(`soc-alerts-agent`) 실제: 20:06 경보 62건→20:07/20:11 "**자동 조사 실패·확인 필요**"→20:13 경보 124건→20:13 "추가 검토 필요". 즉 **탐지·상관·적재·전달은 모두 동작**하고 **모델 조사가 타임아웃/도구실패(`model_subprocess_timeout`·`model_tool_failure`)로 불완전 보고만 전달**. (앞 "feeder 단절"은 조용한 틱 오해로 정정) | 모델 조사 신뢰성/지연(Thor 단일 슬롯 경합)이 핵심. Hermes 반복 재시작도 기여 (task #10→#3/#7/#8과 동일 뿌리) |
| 룰 그라운드트루스 | ✅ 1000090/1000091(A·69건 발화)·100111/100112(B)는 실재. `get_security_rules` 도구가 `matched_count:1`로 정확 반환(라이브 재현) | — |
| 룰-조회 봇 신뢰성 | ⚠️ **부분 해결**: 원인=모델이 bare 룰ID를 Suricata로 단정·타 네임스페이스 미조회·문맥의 다른 룰로 대체. `soc-query` 스킬에 네임스페이스 추론+특정ID `rule_id`조회+대체금지 규칙 추가, **라이브 3곳 배포**(`/opt/capstone-management`·`groot-query-completion`·`capstone-ollama-trial`, 소비자 재시작). 실제 채팅 재검증: bare `100112`→a:suricata+b:wazuh 모두 조회→Wazuh 정의 정확 반환(수정 전 "없음/오타"에서 개선) | 잔여: 출력이 영문 추론문 유출(soc-output 미적용)·반복 동일질문 "이미 답변" 문맥혼란·명시케이스 ID목록만 반환. 결정적 해결은 쿼리 하네스의 룰ID 사전 그라운딩(후보) |
| 진행표시 "스팸" | 정정: 봇 글 52개 중 51개 `delete_at`로 삭제돼 사용자 화면엔 진행표시 1개만 보임. 의도대로 동작 | 저우선 최적화: 생성+삭제 churn→edit-in-place |

배포 백업 `/var/lib/capstone-service-grounding/20261110-soc-query-skill{,-r2}`. 스킬 변경은 도구 권한·승인·보호 정책을 바꾸지 않는다. 구조·도구 정상과 모델 신뢰성 문제를 구분한다. [실측 원문](대화기록/검증/2026-11-10-ddos-inspect/)(로컬). 시나리오 탐지 결과는 [scenario-4](scenarios/scenario-4-ddos.md).

## 현재 작업: 실제 복합 답변 보완·서버 Harness² 정기 점검 연결

| 영역 | 확인한 상태 | 남은 일 |
|---|---|---|
| 운영 | 기존107(common1.5.83/query1.19.136/진단MCP1.4.1)·진단 코드 표시 보완·균형 학습본 유지 | 후보108 운영 적용0 |
| 공통 조회 처리 | 성공/실패 근거 분리, 시간 역전 사전 거절, 추가 읽기의 도구·인자 동시 선택 후보 | 동시 선택은 기본 비활성(`CAPSTONE_SERVICE_DIRECT_READS=0`); 실제 정확도·지연 미검증 |
| 수치·단위 | 시간 차이 주장을 같은 대상의 실제 두 시각과 계산 결과에 결속. 과거 실제 “15분” 오답 재생 검출 | 전체 수치·관계 판단의 정확성 보장 아님 |
| 공통 출력 | 고정 “60초 주기” 문구4곳을 실제 표시된 수집 시각 기준으로 통일 | 미배포 후보이며 운영 채팅 출력은 아직 바뀌지 않음 |
| Harness²·회귀 | R26 공식27구성·8편집표면·상시문자증가0·432파일 동결. 서버11프로필1,332회 PASS/skip0·종료 확인 | 중복 포함; 실제 모델·새 채팅·전체 설치 검증을 대신하지 않음 |
| 실패 이력 | R25 1,332회 중 기존 출력1실패를 보존하고 R26에서 수정 | 최신 실제 시험은 이전 R24 189.413초·시간 단위 오답으로 의미 실패 |
| 별도 수집 | A 오류 후보 검색8.363초 관측 | 기존8초 수집 제한 경계 보완 미적용 |
| 재개 지점 | 후보 보존·운영 미적용·새 실시험 미시작 | R26 소스/라이브 재대조→실제 복합 질문 정확도·속도→통과 후 운영/양봇 채팅 |

11/9 **01:43:48 KST** 관리자231 경유 확인:48manifest/보호6 차이0·양봇WS/worker 정상·두 대기열0·학습 모델 설정 유지. R25/R26 회귀는 모두 종료했다. 이번 보호 호출·새 모델 실행·채팅 게시·공격·학습·운영 배포0이다. 후보 소스는 아직 미커밋·미배포이며, 완료한 검증·상태 문서만 별도 게시한다. 공식 `G_Harness2`와 복구본·검증 원문을 보존한다. [실측·실패·후보 근거](infra/hermes/service-investigation.md).

R25/R26 서버 시험본은 종료·432소스/로그 SHA 대조 후 각449파일(총898) 제거했고, Mac의 해당 임시 실행10파일(12,736,970bytes)도 제거 확인했다. 소스·검증 원문·재생성 코드·공식 G_Harness2·기존 복구본은 보존했다.

11/9 20:56 사용자 목표 재활성화로 재개했다. 관리자231 접속 시간초과2회 후 사용자가 연결/전원을 확인했고20:59:01에48manifest/보호6 차이0·양봇/큐0를 실제 확인했다. 같은432파일 동결과 R26 회귀 결과를 대조한 R27 실제 B관리 시험은70.027초·3읽기/5모델·partial이다. 최종 경고3개 중 부정문/판단표 검사2개는 오탐이고, 제한 표본0을 하루 전체 오류 부재로 설명한1개는 실제 모델 오류다. 도구·인자 동시 선택은 추가 조회가 발생하지 않아 아직 실측하지 못했다.

11/10 사용자 확정: 목표는 12/1 최종 발표·발표 전 논문 완성·실전 운용 가능 상태. 채팅 점검 요청은 관리자 승인 카드 방식이며 후보108 마무리 후 구현한다. R28 동결 뒤 서버 회귀(11/9 21:22 시작)의 최종 결과와 R28 실제 모델 시험 결과는 기록되지 않았다(시험 폴더는 이후 제거됨).

사용자가 두 봇의 스스로 개선하는 기능과 B의 공식 Harness² 설치를 요청했다. 최초 요청 시만 실행 지시는 후속 자동 실행 요청으로 갱신됐으며 **매일03:00 KST 자동 점검 + 요청 시 수동 점검**으로 확정했다. 정기 점검/격리 개선안 작성과 관리자 카드 승인 후 운영 적용을 구분한다. **11/10 B 설치·03시 타이머 활성 완료(관리자231 경유).** 설치기 check/install/verify 통과(공식140파일·설정/영수증 SHA), 타이머 enabled/active·다음 11/11 03:00 KST. 1차 수동 실행은 수집 unit의 `User=root`+`NoNewPrivileges` 조합으로 runuser 전환 실패(`discovery_unavailable`→점검 incomplete). User=/Group=만 제거해 재설치했고 2차 실행에서 수집 observed(45도구·학습 모델·모델/도구/채팅/보호 호출0)·점검 완료(status findings). 원인은 코드 라우팅 스킬 4개가 always-on 문구에 없다는 공식 규칙으로, 점검 투영 불일치였다. workflow_contract MARKERS 기반 라우팅 색인을 추가해 재설치했고 17:39 수동 실행에서 세 표면 passed. 설치 전후 48manifest/보호6 차이0·양봇·큐0. 임시 반입본(/var/tmp) 제거. 봇 채팅 요청 연결·승인형 개선 경로는 미구현이다. [설치·실측](infra/validation/harness2/README.md#b-서버-정기-점검-설치). 기존5스킬 재사용/중복검토·근거·정확후보·회귀·승인·복구가 목표이고, 구조 점검 자체를 자동 품질 향상으로 주장하지 않는다.


## 현재 작업: 후보109 운영 확정·Hermes 네이티브/지연 보완 (11/10 19:58)

| 영역 | 확인한 상태 | 남은 일 |
|---|---|---|
| 운영 109 | 19:51 적용·19:58 확정(14변경, drift0, 원복 noop). R38 격리 4/4 판단 수락, 회귀 1,350 PASS. 실제: **Ollama 복합 판단 수락**(100초), Hermes 네이티브는 폴백(168초·동시 부하) | Hermes 네이티브 prune 미적용·Thor 단일 슬롯 지연 → 후보110 |
| 응답 지연 | 복합 질문 100~168초(Thor 단일 슬롯·첫 호출 약2.2만 토큰). 문맥65,536 적용 | 질문 유형별 도구 사전 선정·상태 점검 변경 → 후보110 |
| DDoS 탐지 | 11/10 재생: FW 부분 차단·IDS·SIEM 미탐 공백 확인. scenario-4 게시. 플러드 룰 작성·오프라인 검증 | 관리자 경유 운영자 적용·재재생 E2E(승인됨, 진행 예정) |

## 과거: 후보108 운영 확정·지연/큐 개선 (11/10 18:45)

| 영역 | 확인한 상태 | 남은 일 |
|---|---|---|
| 운영 108 | 사용자 승인으로 18:26 적용·18:43:05 확정(54 manifest 차이0, 원복 noop). 단순 조회 정상(Ollama 17.0초·Hermes 62.7초). 표 줄바꿈 결함·근거 없는 정상 단정 차단 | 복합 질문: Hermes 55초·Ollama 199초 모두 근거표만(판단 미완료). 격리 시험은 동시 선택 켬, 운영 기본은 끔 → 후보109 |
| 서버 상태 | A/B/C 실패 unit0·자원 여유·시간 동기·에이전트3 Active·로그/경보 최신·웹·채팅·Thor 모델 적재 정상(17:57~18:03 관측) | 장기 연속성·무손실은 별도 |
| 응답 지연 | 첫 모델 호출 입력 약2.2만 토큰 처리 약21초, Thor 단일 슬롯 대기·3분 상태 점검의 캐시 덮어쓰기. 18:45 Thor 문맥 65,536 적용, 병렬 슬롯은 모델 미지원으로 효과 없음(제거) | 상태 점검 방식 변경(승인 필요)·후보109 도구 사전 선정 |
| 에이전트 큐 | B 버퍼 20,000·1,000/s 적용(18:44, 설치기 동일 코드·영수증 재결속), 재시작 직후 일회성 포화 1회 | 22:25 rootcheck 때 효과 확인, A는 수집 가드 고정값과 함께 별도 |

[지연·큐 분석](infra/hermes/latency-and-queue-20261110.md) · [R29~R32 결과](infra/hermes/service-investigation.md)

## 최근 완료: B Harness² 정기 점검 설치 (11/10)

| 항목 | 결과 | 남은 일 |
|---|---|---|
| 설치 | `/opt/capstone-harness2`·`/etc`·`/var/lib/capstone-harness2`, 수집/점검 서비스+03시 타이머 | 03:00 첫 정기 실행 결과 확인 |
| 실제 실행 | 2차 수동: 수집16초 observed·45도구, 점검3초 findings → 원인(코드 라우팅 투영) 수정 후 3차 passed(세 표면·5스킬) | MARKERS 등록≠질문별 실제 선택 증명 |
| 수정 | 수집 unit `User=`/`Group=` 제거(NoNewPrivileges 유지), 점검 라우팅 색인·finding_kinds 추가, 테스트 갱신 | — |
| 회귀 | harness_maintenance37·server_audit27·server_context8·remote1·prerequisites18 PASS, `bash -n` | 새 서버 전체 설치 시험 미실행 |
| 공용 스킬 점검 | secret-scanner: 추적1,967파일 중 5건 모두 오탐(생성 코드·테스트 값). review-agent: 이번 unit 수정 결함 없음 | semgrep CLI 없음→미수행 |

## 최근 완료: 포스터 토폴로지 색상 변경 (11/10)

`topology/render_poster_1.py`에 라이트 테마를 추가하고 `토폴로지_상세_1`·`토폴로지_버스_1` SVG/PNG를 재생성했다. 배경은 처음에 sRGB(0.886, 0.931, 0.977)≈`#E2EDF9`로 바꿨다가 사용자 후속 요청으로 흰색으로 바꿨다. 상세형 vSwitch는 회색으로, 패널·카드·글자·의미색은 밝은 배경에 맞춰 조정했다. 상세형 NIC 라벨과 Security Group 점선이 겹치던 문제도 함께 분리했다. 기존 다크 팔레트는 코드에 보존했다. PNG는 SVG의 2배(Chrome headless, 설치0)이고 육안 검수만 했다. 포스터 PPTX 반영은 별도다. 게시: `79b7abd`(라이트 블루) → `74ce280`(흰 배경·회색 vSwitch), 각각 원격 main 일치 확인.

## 직전 완료: 연속 후속 질문·실제 journal 조회 보완

| 항목 | 확인된 상태 | 한계·다음 확인 |
|---|---|---|
| 담당 봇 유지 | 직접 지정한 봇을 같은 사용자/채널/스레드의15분 이내 연속 조회에 유지 | 새 대상·새 태그 우선, direct/승인/이전 수치는 계승하지 않음 |
| 실제 OS 로그 | 등록 unit/target의 짧은 로그 요청에 view=journal. 기간 생략은15분/50행 표본 | 임의 unit 권한 확대 없음. 현재 상태로 로그 완료를 대신하지 않음 |
| 운영 | common1.5.83·routing1.1.8, query1.19.136/진단MCP1.4.1·학습 모델/MCP45스키마 유지 | B12파일 적용,21:08:31 확정·48manifest/보호6·양worker/4active·큐0/failed0 |
| Harness²·회귀 | 공식 구조/차이 점검25구성·5편집 표면, 상시문자 변화0. 관련7프로필1,289회PASS/skip0 | 중복 포함, 전체저장소/독립정확도 아님. 초기 환경/범위 실패 보존 |
| 실제 채팅 | 양봇 상태→메모리→로그6건 통과·각새조회1회. 존재하지 않는 이름2건도 정확히 보고 | H17.773/17.379/35.619초, O23.216/19.107/15.886초·각1회·원문/게시 일치 |
| 출력 | 게시된 표 Markdown을 원문 기반 렌더러와 대조 | 이번 브라우저 제공자 부재로 화면 렌더링 재확인은 못함 |
| 복구·Git | 독립 원복 타이머 해제·확정noop, 서버 복구본/G_Harness2 보존. 공개 소스·문서 게시 완료 | 서버 시험917파일·Mac 임시 실행38파일 정리, 검증 원문·복구본 보존. Git 게시 영수증은 아래 구분 |

21:14:34 KST 마지막 관리자 경유 확인: 48파일 manifest·보호6 SHA 일치, 4서비스 active, 양봇 연결/worker 정상, 대기열0·실패 unit0, 모델 불변. 이후 상시 상태를 보장하는 기록은 아니다.

[변경·실측·실패·복구](infra/hermes/service-followups.md) · [수치](infra/hermes/service-followups.validation.json) · [전체 조회 범위](infra/mcp/host-inventory.md). 직전19시나리오의1실패는 당시 실패 이력으로 보존하며 이번 성공으로 덮어쓰지 않는다.

## 최근 완료: 진단 코드 표시 보완

23:18 A/B/C 각1파일 적용 확정, reader만3회 재시작·봇재시작0. 공개 진단 코드와 종료값이 비밀로 오인돼 가려지던 문제를 수정했다. 실제 MCP/새 양봇 채팅 각1조회에서 원문 SHA·인자·표본문과 렌더러 일치를 확인했다.23:19 B48manifest/보호6·양worker/WS·큐0·45도구·학습본 불변을 재확인했다. 복구본·G_Harness2 보존, 서버 임시 시험본 정리 완료. 실제 화면·복합 판단·전체 설치·수동 원복은 별도 미검증이다.

## 운영 및 완료 범위

| 영역 | 확인된 범위 | 남은 범위 |
|---|---|---|
| 모델 | DGX 균형1,220대화/610step 본학습·병합/양자화·Thor 반입 완료. 11:46 학습본 운영 전환 확정, 원본·복구 보존 | 독립176평가·복합 판단 오류·일반 정확도/학습 우위 미입증 |
| 조회·출력 | 무승인 읽기: loaded unit 상태/상세, Docker 목록/상세/stats/마스킹로그, CPU/메모리/프로세스/포트/네트워크/디스크, 등록 journal. 호스트별 표·용량 최대 소수점2자리+원값 | 임의 unit journal·전체 OS 임시관리 권한은 미구현 |
| 근거 가드레일 | 원문/SHA·시간/대상·현재/과거·부분/완료 경계, 근거 없는 정상/종결 거절. Native 실패 때 확보한 근거 보존 | 범용 할루시네이션 방지 보장 아님. Vector 복합 원인·영향·교차검토 잔여 |
| FW·웹 | IPv4/NAT 정리, HTTP Wazuh→HTTPS308, 웹 빈도/동시연결 제한, FW IP·조건/차단사유 표. WAF On·UI/API 경유·제어 관리자231+인증 | 전체 DDoS/egress/관리경로·장기 재부팅/복원은 별도 |
| 차단 | 지정 공격 룰 Native 선차단600초, 유지승인60분, 해제·만료 뒤60초 재차단 대기. 승인 카드 유지 | 모든 보호 변경·유지/해제·사건종결 E2E 미완료 |
| 혼합 시험 | Kali232에서 정상97 HTTP200·공격3 WAF403, WAF/백엔드/Wazuh 원문 대조 | WAF·IPS·FW 각각 최소30개 구별사례 미실행. 정상POST 빈도 경보 보완·오탐/미탐 구분 필요 |
| Suricata | 8.0.6/ens192 -i·NFQ지원 확인. 사용자 선별룰 직접drop 인라인 도입 확정 | 큐/인라인 운영 미적용. 격리·장애/원복·혼합E2E 필요 |
| DNS·수집·보존 | 지정230→168.126.63.1:53·정보성SID2만 예외. 광역DNS 면제 없음, storage/원문 경로 보완 | 수집 무손실·장기 연속성·전체 복구 미입증 |
| 문서 | archive 유형별 통합·datasets/finetuning 역할·원본1/정제본1 압축 정책, 로컬 포트폴리오MD | 논문46쪽·발표20쪽은 당시 초안. 최신 결과/공식 제출형식·리허설 잔여 |

## 다음 작업

사용자 목표 재활성화로 복합 원인/현재 영향의 실제 의미 검증과 서버 Harness² 자동 점검·요청형 개선 경로를 진행한다. 독립176평가, 승인형 임시OS관리·인라인IPS/장비별 혼합시험, 장기운용/설치검증, 논문·발표는 별도 남는다. 기존 공격 시험 중단은 별도 재개 지시 전 유지한다.

- 관리/조회는 Mac→관리자231→A→B/C, 공격은 승인된 Kali232/233만. 보호 주소·정확 후보·승인/TTL 유지.
- 수집/정제는 로컬, 학습DGX, 검증 가중치 적재/추론Thor. 이번 학습/공격 실행0.
- 자격·대화·검증 원문·가중치·데이터·논문/발표·포트폴리오 Git 제외. 현재 검증을 전체 관제 완성이나 무누락으로 확대하지 않는다.

## Git·작업 트리

R25/R26 검증·마감 공개4문서는 `5edbb5f9f68aff1f1b6ac64cb4e0754a7d16e86f`로 커밋·푸시했고 2026-11-09T01:47:09.058069+09:00 실원격 main 일치를 확인했다. 이 영수증의 후속 커밋·최종 원격 일치·작업 트리는 로컬 세션 기록에 남긴다. 미완료 후보 소스는 이 게시에 포함하지 않았다.

11/10 포스터 토폴로지 5파일(`topology/render_poster_1.py`, `토폴로지_상세_1`·`토폴로지_버스_1` SVG/PNG)은 이전 staged 초기본을 최신 색상으로 바꿔 `79b7abd`·`74ce280`으로 게시했고, 2026-11-10T17:18:54 KST 원격 main 일치를 확인했다. STATUS 갱신은 `021d238`, 이어서 PLAN·README·topology/README·유형별 이력·AGENTS(11/9·11/10 사용자 지시) 동기화를 별도 커밋으로 게시했다. 11/10 B Harness² 설치 소스·설치기 연결·문서는 `e21119435c02fe30b073abfa3c9acebc4fd37797`로 게시했고 2026-11-10T17:33:19 KST 원격 main 일치를 확인했다. Mac 임시 반입 폴더와 B `/var/tmp` 반입본은 제거했다(B 번들·공식 소스·G_Harness2는 보존). 점검 라우팅 투영 수정은 `160274e70081f592cb5201c7b58202007c3cf5fa`로 게시했고 2026-11-10T17:40:11 KST 원격 main 일치를 확인했다. B 번들의 `reports-backup-20261110/`에 수정 전 보고서 사본을 남겼다.

복합108 후보, 기존 Ansible/NAT/혼합시험 변경은 미완료 상태로 보존하며 문서 게시에 포함하지 않는다. 전체 작업 트리는 dirty이며 staged 변경은 없다. 자격·로컬 기록/검증·G_Harness2는 Git 제외다. 이전 게시 이력은 [통합 이력](archive/STATUS_HISTORY.md)과 로컬 세션 기록에서 확인한다.
