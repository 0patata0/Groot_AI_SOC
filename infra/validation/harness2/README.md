# Harness² 보완 점검

사용자 지속 지시에 따라 **이후 모든 하네스 정리에도 공식 Harness²를 사용한다.**
구조·편집 범위·변경 목록을 먼저 점검하고, 후보 동결→회귀→운영 대조·배포→새 실제 채팅 순서로 검증한다.

Harness²는 프로젝트 코드의 검토를 보완하는 로컬 도구다. 운영 변경, 승인 판단,
모델 교체를 자동 결정하지 않는다. 실제 추론은 기존 **B 에이전트 → Thor** 경로를
사용한다. 이 점검 도구에서 Thor API를 직접 호출하지 않는다.

공식 [google-research/harness2](https://github.com/google-research/harness2)의
`6868817518876de8fd170c6a8354daca273b6191` / 0.1.0 / Apache-2.0을
Git 제외 `G_Harness2/`에 보존한다. **11/8 후속 지시: 작업 후 자동 삭제하지 않고, 사용자가 명시적으로 삭제를 요청할 때만 제거한다.** 15:35 정리 직후 이 지시를 받아 같은 공식 커밋으로 복원했다. 별도 작업용 실행 스크립트와 서버 시험 복사본은 정리했다. 설치 확인용 결정론적 예제는 과거 2과제 성공이다.
이는 SOC 에이전트 성능 결과가 아니다.

[정리 범위·순서와 단절 후 인계](COMPONENTS.md)

## 실제 사용 범위

| 기능 | 적용 |
|---|---|
| 공식 `core.tree.validate` | 스킬 형식·참조·Python 구문·편집 표면 검사. 하위 에이전트 금지 |
| 공식 `core.tree.diff_summary` | 기준본과 수정 후보의 정확한 추가·삭제·변경 목록 |
| 프로젝트 검사기 `audit.py` | 운영 SHA와 같은 Git 기준본, 동일 테스트, 수정 가능한 8파일을 고정해 비교 |
| 모델 기반 자동 후보 생성·선택 | 사용하지 않음. 수정안은 Codex가 근거를 확인해 작성 |
| 운영 배포 | 별도 관리자231 경유 절차·원본 백업·원복 타이머·실제 검증으로 수행 |

프레임워크의 기본 실행 예제를 운영 권한으로 실행하지 않는다. 공식 선택 루틴은
기준 실행을 선택 후보에서 제외하므로, 그 선택 결과만으로 운영본보다 낫다고
판단할 수 없다. 이 작업은 직접 확인한 기준본 대조와 별도 승인 경계를 유지한다.

## 연결 중 확보하는 기준

1. 관리자231 경유로 B의 배포 파일·보호 파일 SHA, 실제 운영 모델, 서비스·봇
   연결·대기열 상태를 읽고 KST 시각을 남긴다.
2. 기존 비특권 `soc-ollama` 런타임으로 실제 MCP 목록과 입력 스키마를 읽는다.
   도구 실행·모델 추론·채팅 게시 없이 이름·스키마 SHA·설명을 보존한다.
3. 비밀 값·인증 환경·SSH 키를 프레임워크에 복사하지 않는다. 원본 조회 결과와
   내부 주소가 있는 자료는 로컬 `대화기록/검증/`에 보존한다.
4. 동일한 검증 소스를 B의 기존 Linux 실행환경에서도 격리 실행한다. 새 패키지나
   운영 설치기를 실행하지 않는다. 실제 배포 파일과 검증용 복사본을 구분한다.

## 연결이 끊긴 뒤

확보한 자료는 **해당 시각의 관측**이다. 로컬의 코드 정리·스키마 대조·회귀검사는
계속할 수 있지만 현재 서버 상태, 도구 연결 성공, 실제 답변 완료를 증명하지 않는다.
재접속 후 배포 대상 SHA·도구 스키마·모델·권한을 재확인한다. 차이가 있으면 자동으로
덮어쓰지 않고 차이를 검토하고 필요한 검사를 다시 수행한다.

`audit.py`는 고정한 Git 커밋과 로컬 스냅샷을 인자로 받는다. 실행 예:

```sh
PYTHONPATH=G_Harness2 python3 -B infra/validation/harness2/audit.py \
  --repo /path/to/project --base-ref FULL_GIT_COMMIT \
  --source-manifest /path/to/test-manifest.json \
  --snapshot /path/to/snapshot-public-fields.json \
  --catalog /path/to/catalog-public-fields.json \
  --output /path/to/project/G_Harness2/runs/NEW_RUN \
  --test-python /absolute/path/to/existing/python3
```

먼저 `--structure-only`로 구조·변경 범위를 점검하고 후보를 동결한 뒤 같은 소스 SHA로 회귀를 실행한다. 테스트 코드는 두 군에서 동일하며 수정 대상에 포함하지 않는다.

편집 표면의 스크립트 경로는 비교용 이름이며, 에이전트의 실제 설치 경로가 아니다.
`REPORT.json`에는 실제 프로젝트 경로·모든 소스 SHA·공통 테스트 SHA·실패 이름·검사
로그 SHA를 남긴다. 평가 질문·정답을 모델 학습에 넣지 않는다. 재현용 테스트 통과를
일반 정확도·실전 무누락으로 표현하지 않는다.

## 2026-11-08 13:18까지의 검증 이력

| 확인 | 결과 |
|---|---|
| 12:36 KST 운영 대조 | 기존 manifest·SDK drift 0, 두 봇 연결·작업자 정상, 큐0·실패서비스0 |
| MCP 실제 목록 | 44도구, 보호 작업9개. 모델/도구 실행0. 스키마는 별도 재조회와 SHA 일치 |
| 실행 패키지 | mcp-use1.7.1 / langchain-ollama1.1.0 / mcp1.30.0 |
| 동일 개발회귀79건 | 운영 기준 코드70통과·9실패 → 수정 후보79통과 |
| B Linux 회귀 | 출력 보완1,673회 통과 뒤 정리 후보13프로필1,691회 수행. 기존 mock1건 수정 후 peer88 재검사 통과. 중복 실행 포함, 독립 정확도 아님 |
| 배포 전 추가 대조 | 공동 채널의 Markdown 복사본 차이 검출로 첫 staging 거절. 운영 변경0 |
| 정리 후 구조 점검 | 25파일: SOUL·감사 색인·스킬5·모듈18, 하위 에이전트0. 편집8개/나머지 고정 |
| 정리 후 로컬 회귀 | 동일 코드 후보88검사 통과. 새 함수가 없는 기준본의 테스트 오류도 보존, 일반 성능 점수로 사용하지 않음 |
| 운영 후속 | 12:46 출력 보완 확정 뒤 새 채팅 H166.603초 partial/1조회·O28.423초 partial/0조회. 전체 정리 전 시험 실패로 보존 |
| 운영 확정 | 공통 경로13:06 적용·13:07 확정. 감사 이벤트의 Enabled/설정 On 구분 보완 후13:12 재확정. 44manifest·보호6·SDK20·review5 일치, 원복 타이머 해제 |
| 최종 변경 회귀 | Enabled 필드 보완 후 관련5프로필1,305회 통과. 위 전체 검사와 중복되며 별도 정확도 표본이 아님 |
| 새 Hermes 채팅 | 30.096초·완료·실제 MCP1조회·3행·쓰기0. KST 자정~요청 시각/개별 규칙·설명 원문 대조 |
| 새 Ollama 채팅 | 19.345초·완료·실제 MCP1조회·3행·쓰기0. 같은 질문을 별도 새 대화에서 검증 |
| 실제 Mattermost 화면 | 양쪽 모두 요청 구간 표1개·경보 표1개/3행이 실제 table/row/cell로 표시됨. 줄글·코드블록 아님 |
| 최종 운영 재확인 | 13:18 KST 배포/SDK 차이0·4서비스 active·양봇 연결/worker 정상·큐0·failed0. 최신 균형 학습본 유지 |
| 임시 자료 정리 | 13:18 KST G_Harness2 제거 확인. 7회 보고·기준본 대비 patch·소스/로그 SHA와 인계서는 로컬 검증 기록에 보존. 서버 격리 시험3복사본도 제거 |

실제 질문은 `오늘 WAF 차단 경보를 표로 보여줘`였다. 각 1회 개발 검증이므로 평균
응답 시간·복합 판단·독립 정확도·모든 장비의 완전성을 입증하지 않는다. 구간 전체
건수는 미확인으로 표시하고 반환된 3건만 대조했다. 실제 감사 이벤트가 `Enabled`인데
설정값 `On`을 기대해 partial로 남긴 중간 결과(H31.346초)도 실패 원문과 함께 보존했다.

13:18에는 임시 프레임워크·전용 환경·캐시를 제거했다. 이후 재준비했고 최신 보관 지시는 상단을 따른다. 현재 공식 core는 기존 Python에서 import를 확인했으며 전용 가상환경·추가 패키지는 설치하지 않았다. 공개 검사기와 프로젝트 소스는 보존한다.
기존 사용자 환경·서버 복구본·운영 DB·채팅·승인 원장은 삭제하지 않았다.

## 후속 정리 기준 — 2026-11-08 14시

장비명 없는 경보 조회에서 옛 표현이 다시 나와 같은 공식 커밋을 재준비했다. 로컬 기존 Python으로 core를 사용해 별도 패키지 설치는 없었다. 14:07 운영 SHA 대조→474파일 동결→25구성 검사→3편집파일 후보 정리→동일 반례/서버 회귀→운영 대조·적용→새 실제3채팅 순서로 진행했다. 14:10 실제 MCP44 schema SHA도 이전 관측과 일치했다.

기준본은 앞선 배포의 **미커밋 운영 스냅샷**이다. `audit.py`의 Git 기준본 제약을 속이지 않고 별도 로컬 감사 실행기에 동결본·SHA를 명시해 같은 공식 `tree.validate`/`diff_summary`로 검토했다. 감사용 workflow 색인은 실제 선택기를 설명하는 메타데이터이며 운영 프롬프트로 배포하지 않는다. 모델 기반 후보 생성·선택·서브에이전트·자동 채택은0이다.

회귀8프로필1,394회 통과와 실제 새채팅 18.429~20.494초/각1조회/정확한10·10·7행은 [별도 결과](../../hermes/event-listing-parity.md)에 남긴다. 구조 검사 통과만으로 성능·권한 안전성·독립 정확도 완료를 선언하지 않는다. 이후 하네스 정리도 이 순서를 유지하고 결과/patch/SHA를 보존한다. 프레임워크 삭제는 상단의 최신 사용자 지시를 따른다.

후속 임시 설치도 14:17 KST에 제거 확인했다. Mac 644파일과 B의 격리474파일을 정리하고 보고·변경 patch·원문 SHA·실채팅 검증은 로컬 증거에 보존했다. 운영 복구본은 유지한다.

## 공통 문맥 후속 점검 — 2026-11-08

공통 대상 해석→장비별 세부 조건 순서로 정리한다. 같은 사용자의 후속 질문은 대상 종류·호스트·이름·필터를 유지하고, 명시적인 새 주제는 이전 주제를 대체한다. 과거 응답 수치·승인을 새 근거로 사용하지 않는다. Docker/systemd·보안 룰과 두 Native/SDK 경로를 함께 검증한다.

공식 core.tree 검사는 이번 고정 편집 표면27구성/5스킬/19스크립트에서 수행했다. 이전30구성과 범위가 다르므로 이를3개 제거로 해석하지 않는다. 상시문자는 기준/후보16,802로 동일하다. Linux11프로필1,559회/skip0 통과. 운영 증분 배포에서 receipt manifest와 controller 내장 gate 사본 누락을 실제 채팅으로 발견해 보완했다. 이후 마감 검사는 소스 SHA뿐 아니라 **4개 gate 복사본·query SHA핀·controller의 verified_management_command 일치**도 확인한다. 초기 설치기의 render(run_source) 경로는 유지한다. 실제 채팅 결과와 미완료 범위는 [STATUS](../../../STATUS.md), [조회 검증](../../mcp/host-inventory.md)을 따른다.

## 후속107 — 2026-11-08 21:08

실제20:46 운영47SHA·MCP45스키마·모델 대조 후 공식 core로 구조25구성/5스킬/18스크립트·상시16848문자 불변을 확인했다. 다른 편집 색인인 과거27개와 삭제 수를 비교하지 않는다. 변경은 채널 담당계승/정책·공통 계약·SDK 연결·soc-query의5표면이다. 후보 재동결/관련1289검사→관리자 경유12파일 적용→새 실제8채팅 원문/게시 확인→21:08:31 확정 순서를 마쳤다. 실제 과거2오류와 최초 환경/범위 검사 실패는 [기록](../../hermes/service-followups.md)에 구분한다. G_Harness2/운영 복구본 보존, 모델 기반 자동 후보 생성·선택은 수행하지 않았다.

## B 서버 정기 점검 설치

**2026-11-10 기존 B에 설치·활성화 완료(관리자231 경유).** 공식 Harness² 0.1.0/`6868817`을 B에 고정 SHA로 보관하고, 매일 03:00 KST에 공통 SOC 스킬·스크립트의 구조 점검을 실행한다. 모델 호출·도구 실행·채팅 게시·소스 수정·자동 적용은 없다. 보고서의 개선안 초안은 `review_only`이며, 운영 반영은 관리자 승인 카드 이후 별도로 진행한다.

| 항목 | 위치·값 |
|---|---|
| 반입 번들 | `/opt/capstone-prereqs/harness2/` (root 0700): 공식 압축, `audit.json`, 설치기, 고정 소스 3개 |
| 공식 소스 | `/opt/capstone-harness2/vendor/6868817…/` (140파일, lock SHA 일치) |
| 설정·영수증 | `/etc/capstone-harness2/{audit.json,framework.lock.json,installation.json}` |
| 상태·보고서 | `/var/lib/capstone-harness2/{context.json,sources/,reports/}` |
| systemd | `capstone-harness2-context.service`(현재 모델·MCP 목록 수집) → `capstone-harness2-audit.service`(구조 점검), `capstone-harness2-audit.timer`(03:00 KST, Persistent=false) |

```sh
# 로컬: 설정 생성(기존 B는 legacy, 새 설치는 fresh)
./deploy.sh --harness-config --layout legacy > audit.json
# B(root): 사전검사 → 설치(준비+타이머 활성) → 검증
python3 -I -B /opt/capstone-prereqs/harness2/harness_maintenance.py check|install|verify \
  --source-root /opt/capstone-prereqs/harness2/source --bundle /opt/capstone-prereqs/harness2
# B(root): 관리자 요청 시 수동 점검
systemctl start capstone-harness2-audit.service
```

새 서버는 `HARNESS2_ENABLE=1`로 `deploy.sh`가 같은 `harness-check/install/verify`를 호출한다. 기존 설치는 덮어쓰지 않고 검증만 한다.

**11/10 설치 중 실패와 수정.** 첫 설치 후 수동 실행에서 수집 서비스가 `discovery_unavailable`로 끝나 점검이 `incomplete`였다. 같은 sandbox 옵션을 하나씩 바꿔 시험한 결과, `User=root`를 명시하고 `NoNewPrivileges=yes`를 함께 쓰면 wrapper의 `runuser`가 soc-ollama로 전환하지 못했다(`setuid` EPERM). 둘 중 하나만 있으면 정상이었다. `NoNewPrivileges`는 유지하고 수집 unit에서 `User=`/`Group=`만 제거했다(기본 root 실행; `deployment/review_chat.py`의 같은 사례와 동일). 직후 생성분만 제거하고 재설치했다.

**실측(11/10 17:29 KST, 2차 수동 실행).** 수집 16초: `observed`, 45도구, 학습 모델 `soc-qwen36:35b-balanced-q4km-20261108`, 모델/도구/채팅/보호 호출 0. 점검 3초: status `findings`. native/sdk/management 세 표면 모두 `official_validation_failed`(같은 진단 SHA `c7f6c0d2…`), 5개 공통 스킬 사본은 세 표면에서 동일, 중복 후보 0. 설치 전후 운영 48 manifest/보호 6 차이 0, 두 봇 연결·대기열 0을 확인했다.

**원인 분석·수정(11/10 17:36~17:39 KST).** B에서 같은 검증을 읽기 전용으로 재현한 결과, 공식 규칙 "skill이 always-on 문구에 이름이 없으면 호출되지 않는 dead weight"에 `soc-change`·`soc-investigate`·`soc-query`·`soc-recover`가 걸렸다(세 표면 동일). 실제 런타임은 모델이 always-on 문구를 보고 스킬을 호출하지 않고, 코드(`harness.workflow_names`→`workflow_contract.policy`)가 질문별로 스킬 본문을 주입한다. 따라서 실제 죽은 스킬이 아니라 점검 투영의 불일치였다. `server_audit.py`가 `scripts/workflow_contract.py`의 리터럴 `MARKERS` 키만 AST로 읽어 검증용 always-on 색인(`routing_index.md`)을 만들고, 관찰 원본 트리는 바꾸지 않는다. MARKERS에 없는 스킬은 계속 untriggered로 잡히며, 결과에 `routing_projection`(근거 파일·스킬)과 리터럴 없는 `finding_kinds` 분류를 남긴다. 재설치(기존 보고서 보존) 후 17:39 수동 실행: **세 표면 passed**(각 5스킬), 중복0·사본 차이0, 모델/도구/채팅/보호 호출·소스 쓰기0. 사후 48/6 차이0·양봇·큐0. 한계: MARKERS 등록이 각 스킬이 질문 분기에서 실제로 선택된다는 증명은 아니다.

**후속 실제 확인:** 11/14 09:42 KST Hermes 컨테이너에서 고정 `rule-b` 경로의 `get_harness_check_status`를 읽어 03:00 KST 정기 보고 `passed`(scope `structural checks`, 자동 채택false, 운영 변경 승인 필요)를 확인했다. 10:09 KST 타이머는 active·다음03:00, 서비스 최근 Result는 success였다. 따라서 위 설치 당시의 첫 정기 실행 미확인은 해소했다. `rule-b`의 상태 읽기1개와 `rule-write-b`의 요청/재동기화/확인3개 목록·스키마도 확인했으나, Ollama의 실제45개 허용 목록은 이4개를 정책에서 제외한다. [공개 원장](../peer-semantics/validation-r3.json).

남은 일: Hermes의 관리자 자연어 요청→도구 선택·카드 승인→고정 worker1회 실행→결과 읽기와 재동기화 E2E, Ollama의 승인 경계를 유지한 통합 후보다. 이번 확인은 보호 작업·채팅 게시·운영 배포0이며 구조 점검 통과를 품질 향상이나 정확도로 표시하지 않는다.

