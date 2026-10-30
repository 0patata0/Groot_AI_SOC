# 에이전트 파인튜닝 데이터셋 카탈로그 (2026-10-01)

**DEDALE 후속 검증 — 2026-10-30 KST:** 원본 ZIP 전체를 받지 않고 선택7시간 멤버를 읽어6,188,928행과5,581라벨을 연결했다. 제공 원시 JSONL MD57개·별도 객체 대조를 확인했으며 공식 평가기간과 검토 노출을 보존한다. [검사기/사용 경계](../finetuning/README.md) · [원장](../finetuning/DEDALE_LINKAGE_REVIEW.json). 신규 학습 편입은0이다.

## Attack Flow 분기 보존 후속 — 2026-10-30 KST

**출처 검토 후속:** [ATTACK_FLOW_SOURCE_REVIEW.json](ATTACK_FLOW_SOURCE_REVIEW.json)에 Maastricht18action·4condition의 원문 쪽수/객체SHA와 검토 상태를 기록했다. 17개는 한정 필요,5개는 사건 관측 수준의 지지이며 오류17개/정답5개 판정이 아니다. 앞선 부분 검토와 달리 SDBBot 사용은 원문 앞부분에서 확인했다. 원본의 추정 주석을 보존하고 전체 흐름의 사실 정답 생성은 계속 보류한다. PDF 본문·이미지를 학습 데이터나 저장소에 넣지 않는다.

기존 최소 변환기의 액션 BFS 나열을 제거하고 `attack_flow_graph.py`로 원본 그래프를 보존한다. 고정 CTID commit의 41개 파일을 Git blob/크기/SHA와 대조했다. 노드1,990개·연결2,113개, 조건147개·AND89개·OR29개와 참167/거짓10 연결을 보존했다. 그래프는 사건25개 외 캠페인·악성코드·훈련 등의 범주도 포함한다. 새 데이터41개나 시간순 정답41개가 아니다. [검증 원장](ATTACK_FLOW_GRAPH_REVIEW.json) · [고정 원본/공식 의미 정의](ATTACK_FLOW_SOURCE_SPEC.json).

```bash
python3 -B datasets/prep.py --stages attack-flow --attack-flow-output datasets/processed/reference/attack-flow-graphs-NEW
python3 -B -m unittest discover -s datasets/tests -p test_attack_flow_graph.py
```

독립 stage는 다른 자료와 STATS를 읽거나 갱신하지 않는다. `attack`/기본 전체 stage도 같은 파서를 사용하며, 출력 경로가 있으면 다른 stage 수행 전에 중단한다. `graphs.jsonl`·manifest·원본 LICENSE·변경 NOTICE를 새 디렉터리에 만든다. 이전 `knowledge/attack_flows.jsonl`은 이력으로 보존하며 재생성하지 않는다. 렌더링 정보와 명시된 구조 민감필드는 투영에서 제외하지만 모든 노드/연결·분기·인용·나머지 속성은 검증한다. 원본 UTC 등 시각 표기는 그대로 보존하며 처리 보고 시각은 KST다.

12개 회귀 검사와 별도 파서의 모든 연결 양끝·원문 속성 대조를 마쳤다. 조건의 일반 anchor에서 나온 연결1개는 참으로 추정하지 않는다. 해당 Maastricht 흐름은 공식 보고서의 관련 단락과 일부 기법/도구 표현이 일치한다고 확인할 수 없어 사실 정답 생성에서 보류한다. 그래프 자체의 보존과 사건 의미의 정확성은 별개다. STIX 완전 변환기·학습 QA·운영 모델 학습 완료로 표시하지 않으며 신규 학습 편입0이다.

아래 학습 보류/진행 문구는 당시 이력이다. 최신 학습·운영 판단은 [STATUS](../STATUS.md)를 따른다.

**현재: 학습 실행 보류·계획만 정리.** 사용자 지시로 재개 작업을 중지했고 기존35B를13:21:19KST복구했다. 본 학습은 미시작이며 학습 컨테이너/활성 복구타이머는 없다. Thor 학습 차단은 원복 상태를 유지하고, 다음 재개 지시가 있을 때만 원래설정의 시험→1024개1epoch/512step→복구/검증→후보비교·적재를 진행한다. [실행 계획](../PLAN.md) · [현재 상태](../STATUS.md).

이하 내용은 과거 시점의 기록이다.


**V5 실행 최신:** 원래 설정의 2-step 시험은 완료했으나 전체 학습 예상이 약3시간48분으로 기존 승인시간을 넘어 본 학습은 미시작이다. 재계산 해제안은 검증손실 차이/시간이득 미확인으로 제외하고 원래 설정으로 되돌렸다. 기존35B복구·실제중단합계약6분52초. 승인된이전HF26shard66.97GiB정리완료(base/adapter/설정·기존Ollama보존)·실제CPU276검사통과. **기존중단포함총4시간30분 연장안은 검토 준비만 완료했고 새승인전실행차단**한다. [시험·가중치·원천투입/한계](../finetuning/V5_EXECUTION_RESULTS.json) · [상세 현황](../STATUS.md).

이하 내용은 과거 준비·진행 시점의 기록이다.


**10/29 V5 신규 준비:** MITRE·CISA 원문 관측/제공자 정답으로 **1,280건(학습1,024/검증128/시험128)**을 별도 정제했다. 자체 사건 시나리오0건이며 질문·출력 형식은 프로젝트 작성이다. 출처1,324행 대조·보고서/주체 분할·재생성4해시·전체 토큰 보존을 확인했다. 이 자료는 **역사적 CTI 기법 매핑**용으로, 관제 업무 전체 숙련이나 독립 전문가 인증을 뜻하지 않는다. **GPU 학습·새 후보 등록은 아직 없다.** 기존 자체308 포함520건 및 R3/R4 학습 보류는 유지한다. [V5 준비·한계](../finetuning/V5_DATA_PREPARATION.json) · [최신 현황](../STATUS.md).

아래는 시점별 준비·검증 이력이다.


**후속 정정 2026-10-29T04:16:44.348253+09:00:** 자체작성308/520(59.23%)은 기관이 검증한 정답이 아니다. CPU/토큰/호출·출처 검사는 답변 의미의 독립 검수를 대신하지 않는다. 520건은 준비본 수로만 보존하고 학습 투입 확정에서 제외한다. 사용자 지시에 따라 외부 기관·학술 원천 및 공식 실제 사고 자료를 추가 수집하고, 자체작성 비중을 줄인 새 corpus/근거 검수를 먼저 수행한다. R3/R4 신규 학습은 실행 제어기에서 보류한다. [검수 상태](../finetuning/V4_DATA_REVIEW.json).


> **10/29 기관/직무 연계 전체 학습 준비:** 원격참조 AIT-LDS 행라벨·CISA·NIST/ENISA직무·실제 IDS 재조회를 포함해**332/94/94=520사례**. 실제tokenizer/Torch CPU검증으로 모든assistant턴766/202/202보존·학습입력중복57.9%감소(속도/품질향상 미검증). 전체1epoch/166step·독립복구 준비·GPU학습/운영전환미시작. 이후FW전체읽기MCP→복구가능한하네스정리→2x2비교로우수구성선택. [자료·한계](../finetuning/DATA_SOURCES.md) · [실제진행](../STATUS.md).

> **10/29 SOC 업무용 R3 준비:** 8개 관제 workflow+출처 연결 AIT 아카이브로264/60/60건을 준비했다. 원경보192개 대조·CPU696/168/168prefix 전부 보존/최장2710토큰·운영MCP37도구 계약일치 확인. ToolACE는 보조 후보로만 정제하고 핵심 혼합에서 제외했다. 개발 순차 평가/중단·복구 준비를 진행하며 새 GPU학습/후보적재/운영전환은 아직 없다. [자료·출처·검증한계](../finetuning/DATA_SOURCES.md).

> **10/29 과거 학습 출처 정리:** 12실행·3corpus/9분할SHA·AIT112원본행을대조하고BibTeX/기계판독이력표를연결했다. 초기혼합자료는일부2-step시험만,v1은AIT+합성,R2는합성이며준비량/실제학습량을분리한다. 과거batch ID/일부취득revision미기록도공개한다. [논문용출처·정정·검증한계](../finetuning/DATA_SOURCES.md). 추가반입분정제/새학습은이후단계다.

> **10/29 추가 자료의 학술·기관 근거 확인:** AIT/CSET·ToolACE/ICLR2025·APIGen/NeurIPS2024·PRIMUS/EMNLP2025와 MITRE/NIST 공식 자료를 확인했다. 기존ToolACE SHA/AIT MD5 3검사일치. 현재R2 192개는내부에이전트검수합성자료로기관인증/전문가정답이아니다. 새반입/학습/운영전환없음. [원출처·인용·검증/한계](../finetuning/DATA_SOURCES.md).

> **10/27 추가 학습자료 조사:** 한국어 도구 호출·보안 업무자료와보안특화8B·동일35B파생가중치14후보를검토했다. 우선순위는보유SOC경보/실제요청검수→방어과제→소량한국어보조이며평가원천·중복·과잉질문회귀를구분한다. 반입/학습/운영모델변경은미실행이다. [최신후보·보유자료선별](../finetuning/DATA_SOURCES.md) · [현재현황](../STATUS.md).

> **2026-10-27 현재35B 준비:** [thor35B 절차](../finetuning/THOR_35B.md)를 추가했다. 기존 train의 구조화 호출19,230개는 현행 MCP 전체 이름과 일치0개여서 일반 보조 corpus로 보존한다.37도구 스키마 감사기를 제공하지만 현 SOC 전용 trajectory 검수·학습은 아직 없다.

> **2026-10-27 로컬 재확인:** 기존30B용 `finetuning/data/`20,784행의 실제 존재·분할별 SHA 일치를 확인했다. 현재 운영은 thor-05의35B와 두 봇, MCP37도구/8서버이며 아래10/08의5서버 설명은 과거 이력이다. 공개 corpus를 현행 SOC 도구/승인 경로에 맞춰 검수한 학습셋이나 학습 완료 모델로 간주하지 않는다. [기존 학습 준비 폴더](../finetuning/README.md) · [현재 검증 범위](../STATUS.md).

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 기존30B LoRA 준비 데이터는 train18,872/validation980/test932개이며10/24 로컬 행 수·SHA 대조가 일치했다. 운영35B와 다른 후보이고 GPU 학습/실모델 비교는 아직 없다. 공개 corpus·지식·독립 평가·우리 SOC 검수 trajectory의 역할을 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

> 2026-10-02 별도 검증 폴더에서 작성된 고유 메모는 [검증 차이 기록](검증_차이_2026-10-02.md)에 보존했다. 그 폴더의 raw/processed 데이터는 이 디렉터리의 파일과 바이트 단위로 일치해 중복본을 정리했다. 검증 스크립트는 [validate_and_clean.py](validate_and_clean.py)로 옮겼다.

> 대상 에이전트: Hermes Agent(B) + `qwen3.6:35b`(DGX Ollama)로 **경보 이후 조사·상관분석·침해판단·대응(승인)** 을 한국어로 수행. 10/08 배포 기준 MCP는 읽기 `wazuh-ro`·`security-events`, IP 대응 `resp`, 승인형 로컬 룰 변경 `rule-a`·`rule-b`의 5서버다. 초기 17툴 목록은 전체 현행 목록이 아니므로 학습 데이터는 실제 도구 이름·스키마를 다시 조회해 맞춘다. [현재 MCP 구성](../infra/mcp/README.md).
> 파인튜닝 원칙(PLAN 4단계): **핵심 데이터 = 우리 시나리오 실측 트래젝터리**(Hermes 세션 → teacher 초안 → 사람 검수 → Qwen 챗 템플릿 → LoRA/QLoRA). 공개 데이터는 **보조**(툴콜 형식 능력·보안 추론·합성 원천). 없어도 프로젝트는 완결(확장 목표).
> 저장: `datasets/raw/`(gitignore, 342MB 반입 완료). 라이선스·용량·게이트 여부는 HF/Zenodo API 로 **실측 확인**(2026-10-01).

> **10/08 후속 요청 — 별도 장비용 준비 완료:** [finetuning/](../finetuning/README.md)에 이곳의 기존 processed 5개 소스를 정제해 train **18,872** / validation **980** / test **932**개, `Qwen/Qwen3-30B-A3B` 기본 NF4 LoRA 설정·학습기·어댑터 병합기·API 비교기를 준비했다. 이 Mac에서는 데이터 변환과 표준 라이브러리 검증만 했고 학습·패키지 설치·모델 다운로드·서버 업로드는 하지 않았다. 데이터와 모델 가중치는 Git에서 제외하며, 정확한 선택/제외 수·해시는 [준비 명세](../finetuning/preparation_summary.json)에 있다. 소스별 최대 5,000행의 첫 실험용 구성이고 전체 허용 행은 `--max-per-source 0`으로 재생성할 수 있다. 실제 GPU 실행·성능 비교는 아직 하지 않았다. 아래 두 문단은 이 준비 요청 **이전**의 검토 경위다.

> **앞선 10/08 학습 준비도·범위 검토:** 아래 공개 자료와 전처리 도구가 준비돼 있다는 사실을 실제 SOC 학습셋·파인튜닝 모델 완성으로 해석하지 않는다. 우리 현재 MCP 조사·승인 경로의 검수된 trajectory와 독립 평가셋은 후속 준비 항목이다. 사용자는 서버 업로드를 이번 검토 범위에서 제외했다. 직접 확인한 로컬 Mac은 M3·16 GiB이며, 지원되는 소형 모델의 양자화 LoRA부터 메모리·정확도·지연을 비교하는 안을 검토한다. 구체적 모델 선택·패키지 설치·학습·서버 변경은 아직 하지 않았다. 학습 시 임시 환경과 캐시를 격리하고 작업 후 정리한다는 기존 Mac 사용 제약을 따른다. [계획](../PLAN.md) · [MLX LoRA 문서](https://github.com/ml-explore/mlx-lm/blob/main/mlx_lm/LORA.md).

> **앞선 비교 우선순위(사용자 오타 정정 반영):** 사용자는 여기서 학습하지 말고 **30B 파인튜닝 모델과 현재 35B의 속도·정확도**를 먼저 비교하라고 했다. 직전 35B 표기는 오타였다고 정정했으므로 동일 35B의 튜닝 전후 비교로 해석했던 내용은 철회한다. 현재는 30B의 정확한 베이스/체크포인트와 학습에 쓰이지 않은 SOC 평가셋이 필요한 단계다. 실제 비교 실험이나 우열 판정은 아직 없으며, 학습 준비 제안은 참고로 보존한다.

---

## 1. 반입 완료 (`datasets/raw/`)

| 디렉터리 | 출처 | 라이선스 | 크기·샘플 | 형식 | 우리 용도 |
|---|---|---|---|---|---|
| `hermes-function-calling-v1/` | NousResearch (HF) | Apache-2.0 | 67MB · 11,578 (singleturn 1,893 / multiturn 1,893 / glaive 5,209 / json-mode 2,583) | ShareGPT(`system/human/gpt/tool`) + `tools` 필드, **Hermes 표준 `<tools>`/`<tool_call>`/`<tool_response>`** | **형식 능력** — 우리 런타임(Hermes)이 쓰는 툴콜 포맷 그대로. 다중턴·JSON 모드 포함 |
| `toolace/` | Team-ACE (HF) | Apache-2.0 | 37MB · 11,300 | `system` + `conversations(user/assistant/tool)`, 다중턴 | 형식 능력 보강(다양한 API, 중첩/병렬 호출) |
| `ait-ads/` | AIT (Zenodo 10.5281/zenodo.8263181) | **CC-BY-4.0** | zip 96MB(압축 해제 ~2.8GB) · 8개 환경 × (`*_wazuh.json` JSONL + `*_aminer.json`) + `labels.csv`(80행) | **Wazuh 경보 원본 스키마**(`rule.id/level/description/groups`, `agent`, `decoder`, `full_log`, `@timestamp`) — 우리 B 와 동일. `labels.csv` = 환경별 공격 단계·시각(`network_scans`→`service_scans`→`dirb`→…) | **합성 원천 1순위** — 실제 Wazuh 경보 묶음을 우리 MCP 툴 응답처럼 넣고, 공격 단계 라벨을 정답으로 조사 트래젝터리 합성. 다단계 공격(AIT-LDSv2) 8 변형 |
| `salad-soc/` (val 분할만) | nutthakorn7/SALAD-SOC (HF) | **CC-BY-4.0** | 138MB · ~416,756행 (전체 2.78M: train 645MB·test 138MB) | CSV 29열: 플로우 특징 + `alert_type`·`severity`·`mitre_tactic/technique`·`kill_chain_phase`·`triage_decision`(escalate/suppress/investigate)·`priority_score`·`alert_description`(NL) | 트리아지 결정·심각도·ATT&CK 매핑 **지도 라벨**. 플로우 기반(CIC-IDS2017/UNSW-NB15)이라 툴콜 트래젝터리엔 간접. test 분할은 **평가 전용**으로 분리 |

> AIT-ADS 주의: 논문은 Suricata 경보도 포함한다고 하나 zip 엔 `aminer`/`wazuh` 파일만 있음 — Suricata 경보가 Wazuh 수집본(`rule.groups`)에 섞여 있는지 압축 해제 후 확인 필요. 환경 이름(fox/harrison/…)별 공격 변형이 다름.

## 1-A. 재검증 결과 (2026-10-01, 2차 — 체크섬·전수 파싱·내용 분포)

| 검사 | 결과 |
|---|---|
| **공식 체크섬 대조** | **9/9 PASS** — HF LFS sha256(hermes 3파일·ToolACE·SALAD val), Zenodo md5(ait_ads.zip·labels.csv). 비-LFS 소형 2파일은 크기 일치 |
| hermes-fc-v1 전수 파싱 | 11,578 샘플 전부 파싱, 역할 오류 0, 툴콜 JSON 오류 0. glaive 에 **미정의 툴 호출 3건**(필터 대상). 툴콜 없는 응답 샘플(거절/확인 질문) 다수 — 정상 음성 예시 |
| hermes-fc-v1 **중복** | `func-calling-singleturn`(전부 3턴)과 `func-calling`(5턴 927·3턴 793·4턴 173)이 **793개를 공유**. 5파일 전체 교차중복 **836 → 고유 10,742**. **학습 전 conversations 해시로 dedupe 필수** |
| ToolACE 전수 파싱 | 11,300 샘플, 역할 오류 0, `tool` 턴 1,367, 다중턴(assistant≥2) 800 — 대부분 "호출 생성"만 있고 실행 결과 턴은 적음(형식 학습용) |
| AIT-ADS 무결성 | zip CRC PASS. `labels.csv` 79행 = 8환경 × 10단계(wheeler 9): `network_scans→service_scans→dirb→wpscan→webshell→cracking→reverse_shell→privilege_escalation→service_stop→dnsteal` |
| AIT-ADS Wazuh 전수 파싱(소형 2환경) | russellmitchell 41,488행 / shaw 68,539행, **파싱 오류 0**. level≥10 각 736 / 806 |
| **AIT-ADS Suricata 포함 여부(해소)** | **포함됨** — Wazuh 수집본 안에 `rule.groups: suricata, ids`, `decoder: json/snort`, **rule.id 86601**(Wazuh 의 Suricata 통합 룰 = 우리 B 로컬 룰의 베이스와 동일 id). 웹 룰 **31101/31151** 도 우리 C 시나리오 룰과 겹침 → 스키마·룰 id 수준에서 우리 스택과 호환 |
| SALAD val 전수 파싱 | 416,756행, 열 수 불일치 0, 중복 alert_id 0. **극심한 불균형**: suppress 78.8% / escalate 14.4% / investigate 6.9%, is_malicious 21%. 양성 행은 `mitre_technique` 없음(정상). `alert_description` 은 템플릿형 문장(언어 다양성 낮음) → **라벨 지도용으로만**, 양성 다운샘플 필요. CICIDS2017 편중(90.7%) |

**학습 전 처리 체크리스트**: hermes 5파일 해시 dedupe(→10,742) · glaive 미정의툴 3건 제거 · ToolACE 는 형식용으로만 · AIT-ADS 는 `labels.csv` 시각 구간으로 경보에 공격단계 라벨 부여 후 환경 단위로 train/holdout 분리 · SALAD 는 클래스 균형(양성 다운샘플) 후 트리아지 라벨만 사용, test 분할은 평가 전용.

## 1-B. 전처리 산출물 (2026-10-01) — `datasets/prep.py` → `datasets/processed/` (gitignore, 385MB)

재현: `python3 datasets/prep.py` (기본값: `--seed 42 --benign-ratio 1.0 --ait-normal-cap 20000 --ait-phase-cap 5000 --ait-window-pad 0 --ait-val wheeler --ait-holdout wilson`). 약 30초.

| 산출물 | 처리 | 결과(검증 PASS) |
|---|---|---|
| `hermes_fc_v1.dedup.jsonl` | 5파일 conversations 해시 dedupe(-836) + 미정의 툴 호출 제거(-3) | **10,739** 고유(파일별 singleturn 1,893 / multiturn 1,100 / glaive 5,204 / json-agentic 1,301 / json-single 1,241). `_source_file` 필드 추가 |
| `salad_val.balanced.csv` | 악성 전부 + 양성을 `source_dataset` 층화 다운샘플(1:1) | **177,096**행 = 악성 88,548 + 양성 88,548, 중복 id 0. triage: suppress 88,548 / escalate 59,979 / investigate 28,569 |
| `ait/<env>.labeled.jsonl` ×8 + `ait/split.json` | `labels.csv` 시각 구간으로 `phase_window` 라벨(`ait_env` 추가), **단계당 reservoir 상한 5,000**, normal 환경당 20,000 샘플, **환경 단위 분리** | train 6(fox·harrison·russellmitchell·santos·shaw·wardbeck) / val `wheeler` / holdout `wilson`, 환경 중복 0. 환경당 26~36K행, 총 279MB |

**AIT-ADS 라벨링에서 확인된 데이터 특성(중요)**
- **dirb 경보 홍수**: 큰 4환경(fox·harrison·wheeler·wilson)은 `dirb`(디렉터리 무차별)가 17~20분 돌며 요청마다 웹 로그 경보(31101)를 만들어 **40만 건(전체의 ~90%)**. 작은 4환경은 0.4분 → 4.4K. 라벨링 버그가 아니라 데이터 본성(논문의 alert flood). → 단계당 상한 5,000으로 억제(`--ait-phase-cap`), 희소 단계는 전부 보존(손실 0 검증).
- **희소 단계**: `webshell`·`reverse_shell`·`privilege_escalation`·`service_stop` 은 구간이 수 초~1분이라 Wazuh 경보가 **환경당 0~49건**(service_stop 은 거의 0). 이 단계의 트래젝터리 합성은 AMiner 경보(`*_aminer.json`, 미처리) 병합이나 `--ait-window-pad`(탐지 지연 보정, 기본 0)로 보강 필요.
- `phase_window` 는 **"그 단계 구간에 발생한 경보"** 라벨(구간 내 노이즈 포함) = 조사 트래젝터리의 컨텍스트/정답 단계용. 경보 단위 악성 여부 라벨이 아님.
- SALAD 는 val 분할만 균형화. train(645MB) 받으면 같은 정책 적용, test 는 평가 전용.

## 1-C. 2차 수집 (2026-10-01) — 반입·검증 완료, `datasets/raw/` 누적 2.3GB

검증: HF LFS sha256·Zenodo md5·크기 대조, 아카이브 CRC, 전수 파싱·구조·카운트 — **58/58 PASS**.

### 툴콜·에이전트 트레이스 (형식)
| 디렉터리 | 출처·라이선스 | 규모 | 형식·메모 |
|---|---|---|---|
| `glaive-fc-v2/` | glaiveai/glaive-function-calling-v2 · Apache-2.0 | 271MB · **112,960** | `{system, chat}` 문자열(USER/ASSISTANT/FUNCTION RESPONSE 마커, `<functioncall>`) → ShareGPT/Hermes 변환 필요(변환본 `hiyouga/glaive-function-calling-v2-sharegpt` 존재). hermes-fc-v1 의 glaive-5k 와 중복 가능 → dedupe |
| `hermes-agent-traces-filtered/` | DJLougen (lambda 트레이스 품질필터본) · Apache-2.0 | 366MB · **3,679** | **Hermes Agent 하네스** 다중턴, 전부 `<think>` 포함, 유효 assistant 툴콜 **67,963**(불량 0). 시스템 프롬프트의 형식 예시 `<tool_call>{"name": <function-name>…}` 는 플레이스홀더(파서에서 제외할 것) |

### 보안 도메인 지시 (학습)
| 디렉터리 | 출처·라이선스 | 규모 | 형식·메모 |
|---|---|---|---|
| `sevenllm/` | Multilingual-Multimodal-NLP/SEVENLLM-Dataset · Apache-2.0 | 190MB · train **91,401** / test 1,300 | `{id, category, instruction, input, output, thought}` — **28개 보안 이벤트 분석 과제**(Threat Analysis 8,301·Key Entity Recognition·Time Element·Malware Feature Extraction·Event Classification…), **`thought` 추론 필드 포함**. 이중언어: 중국어 포함 44,241(약 48%), 나머지 영어 → 영어 서브셋 우선, 중국어는 Qwen 이 처리 가능하나 출력은 한국어 teacher 변환 |
| `attacklm/` | Veedubin/attacklm-dataset(GitHub) · 레코드별 원출처 라이선스 명시 | 7.7MB · jsonl **46,209** 레코드(81 데이터파일, `questions.jsonl`·`balanced_*.jsonl`) | ATT&CK 근거 레드/블루 QA(Atomic·Sigma·Elastic·Splunk·Mordor·NIST IR 출처). 레코드의 `license` 필드로 필터 가능 |
| `salad-soc/` (train·test 추가) | nutthakorn7/SALAD-SOC · CC-BY-4.0 | train 645MB · **1,944,887** / test 138MB · 416,781 | val 과 동일 29열. train 은 `prep.py` 균형 정책 적용 대상, **test 는 평가 전용** |

### 평가 전용 (학습 금지 — 라이선스/누출)
| 디렉터리 | 출처·라이선스 | 규모 | 메모 |
|---|---|---|---|
| `cybermetric/` | tihanyin/CyberMetric · Apache-2.0 | 10,180 / 2,000 / 500 / 80 MCQ | `{question, answers, solution}` 보안 지식 MCQ |
| `cti-bench/` | AI4Sec/cti-bench · **CC-BY-NC-SA-4.0** | MCQ 2,500·RCM 1,000(+2021 1,000)·VSP 1,000·ATE 60·TAA 50 | CTI 추론 벤치(NeurIPS'24). **비상업 라이선스 → 평가만** |
| `secqa/` | zefang-liu/secqa · **CC-BY-NC-SA-4.0** | v1 test 110 / v2 test 100 (+dev/val) | 보안 MCQ. **평가만** |

### 룰·지식 원천 (합성·RAG용, 우리 스택 직결)
| 디렉터리 | 출처·라이선스 | 규모·검증 | 용도 |
|---|---|---|---|
| `wazuh-ruleset/` | wazuh/wazuh **v4.14.8** `ruleset/rules`+`decoders` (git sparse) · GPL-2.0 | 룰 xml 168 · `<rule id>` **4,515** · 디코더 120. **우리 경보 룰 31101/31151(web)·86601(suricata)·5710(sshd) 존재 확인** | 경보 룰 id → 의미/그룹/MITRE 설명 합성(에이전트가 "31101 이 뭔지" 아는 지식) |
| `et-open/` | Emerging Threats Open(suricata-7.0.3) · ET Open 라이선스(BSD계, 비상업 조항 확인) | 54 룰파일 · **52,536** alert 룰 | sid → 시그니처 설명 합성(A 에 반입된 것과 동일 계열) |
| `coreruleset/` | OWASP CRS **v4.29.0** · Apache-2.0 | 27 conf · **750** SecRule | WAF 룰 id(9xxxxx) → 공격 유형 설명(A WAF 와 동일 버전) |
| `sigma/` | SigmaHQ/sigma master · 룰 DRL-1.1(코드 MIT) | 룰 yml **4,244** | 탐지 로직·ATT&CK 태그 → "무엇을 조사할지" 합성 |
| `atomic-red-team/` | redcanaryco (git sparse `atomics/`) · MIT | 기법 **344** `T*.yaml`(354MB, 테스트 바이너리 포함) | 기법 → 실행 명령·기대 증거 쌍(공격→증거 합성) |
| `attack-stix/` | mitre-attack/attack-stix-data `enterprise-attack.json` · ATT&CK 이용약관 | 객체 26,086 · **활성 기법 697** | 기법/전술/탐지/완화 텍스트 |
| `cisa-kev/` | CISA KEV JSON(2026-09-30) · 공개 | **1,730** CVE(시나리오 CVE-2021-44228·CVE-2021-3156 포함 확인) | 취약점 우선순위 근거 |
| `loghub/` | loghub-2.0(Zenodo) Linux·Apache·OpenSSH · CC-BY-4.0 | 로그 23,921 / 51,977 / **638,946** 줄 | 리눅스·웹·SSH 원로그 이해(우리 호스트 로그와 동종) |

### 미확보·보류
- **CyberLLMInstruct**(54,928쌍, Apache-2.0): 공식 GitHub(Adelsamir01)엔 생성 스크립트만 있고 데이터 파일 없음 → 미확보. 논문이 "파인튜닝 시 안전성 저하"를 보고(pseudo-malicious) → 쓰더라도 방어 과제만 선별.
- **lambda/hermes-agent-reasoning-traces 원본**(1.6GB): 필터본으로 대체. **ToolMind**(4GB)·**OTRF Security-Datasets**(810MB, Windows 위주)·**AIT-LDSv2 원로그**: 보류.
- **Primus-Instruct/Reasoning**, **xLAM-60k**: HF 게이트(계정 동의+토큰) — 토큰 주시면 반입.

## 1-D. 전처리 확장 (2026-10-01) — `prep.py` 스테이지별 산출물, `datasets/processed/` 1.7GB (검증 15/15 PASS)

실행: `python3 datasets/prep.py [--stages hermes,glaive2,traces,sevenllm,attacklm,salad,ait,eval,knowledge]` (기본 전부, 외부 패키지 없음). 통계 `processed/STATS.json`.

### 학습용
| 산출물 | 처리 | 결과 |
|---|---|---|
| `hermes_fc_v1.dedup.jsonl` | (1-B) | 10,739 |
| `glaive_fc_v2.hermes.jsonl` | `{system,chat}` 문자열 → ShareGPT/Hermes(`<tools>` 시스템 블록, `<tool_call>` JSON(인자 dict 파싱), `<tool_response>`) 변환 → **중복 제거 키 = 사용자 발화 + 툴콜 객체 + 사용 가능한 툴 이름** → 내부중복 35,996·hermes 중복 7,252 제거 | **35,979**(툴콜 있는 대화만). 툴 없는 일반 잡담 **33,733**은 `glaive_fc_v2.chat_only.jsonl` 로 분리(학습 기본 제외) |
| `hermes_agent_traces.jsonl` | 툴콜 유효성(미정의 툴 30건 제거), hermes 중복 0 | **3,649**(assistant 툴콜 67,963) |
| `sevenllm_en.jsonl` / `sevenllm_all.jsonl` | (instruction,input,output) dedupe(-100) + `lang` 태그 | en **47,154** / all 91,301 (zh 44,141·ko 6), 28 범주 |
| `attacklm.jsonl` / `attacklm.permissive.jsonl` | 원천 버킷(`buckets/sources/**`)만(balanced 파생본·bench 제외) dedupe(-218), `license`·`source`·`mitre_ids` 보존 | **26,241** / 관대 라이선스만 **23,396**(Elastic-2.0 1,908·GPL-3.0 937 제외) |
| `salad_val.balanced.csv` / `salad_train.balanced.csv` | 2-pass 스트리밍: 악성 전부 + 양성 `source_dataset` 층화 reservoir(1:1) | 177,096 / **826,498**(악성 413,249). test 미처리(평가 전용) |
| `ait/<env>.labeled.jsonl` + `split.json` | (1-B) | 8환경, train 6 / val wheeler / holdout wilson |

**중복 제거 키 결정 근거(실측)**: glaive-v2 는 템플릿 반복이 심해 전체 대화 해시로는 4,884 만 잡히고, "사용자 발화+툴콜"만 쓰면 툴 맥락이 다른 거절 예시("항공편 예약해줘", 3,847개 그룹)까지 과잉 병합됨 → 툴 이름을 키에 포함. 독립 재계산으로 키 퇴화(빈 키) 0 확인.

### 평가 전용 (`processed/eval/`, 학습 금지)
`cybermetric.jsonl` 10,200(2000/500/80 은 10000 부분집합 → 질문 dedupe, `subsets` 태그) · `cti_mcq` 2,500 · `cti_rcm` 1,000 · `cti_rcm_2021` 1,000 · `cti_vsp` 1,000 · `cti_ate` 60 · `cti_taa` 50 · `secqa` 210 · `attacklm_bench` 100. 통일 스키마 `{source, question|prompt, options, answer}`. CTIBench·SecQA 는 CC-BY-NC-SA.

### 룰·지식 (`processed/knowledge/`, 합성·RAG 원천)
| 파일 | 건수 | 필드·메모 |
|---|---|---|
| `wazuh_rules.jsonl` | **4,515** | `rule_id, level, description, groups, mitre, if_sid, if_group, file` — 정규식 파서(파일이 다중 루트라 XML 파서 불가). 우리 룰 31101("Web server 400 error code", lv5)·86601("Suricata: Alert - $(alert.signature)") 확인 |
| `et_open_rules.jsonl` | **52,536** | `sid, msg, classtype, proto, src, dst, severity, cve, attack_target, reference`. Log4Shell JNDI 룰 7개(예 sid 2034716, CVE_2021_44228, Major) |
| `crs_rules.jsonl` | **622** (msg 354) | 백슬래시 연속행 결합 후 파싱. `id, msg, severity, tags, paranoia_level, attack, control`. 체인 룰(id 없음) 128 제외. 942100='SQL Injection Attack Detected via libinjection' CRITICAL PL1 |
| `sigma_rules.jsonl` | **3,783** (linux 248) | **최소 라인 파서**(PyYAML 없음): `title,id,status,description,level,logsource{product,category,service},tags,attack,falsepositives`. `regression_data/*/info.yml`(461, 테스트 메타) 제외 |
| `atomic_tests.jsonl` | **344 기법 / 1,839 테스트 (linux 385)** | **최소 파서**: 기법·display_name·테스트명·설명·플랫폼·executor·command. 중첩 YAML 이라 best-effort(`parser: minimal`) |
| `attack_techniques.jsonl` | **697** | `technique_id, name, description, tactics, platforms, detection, data_sources, is_subtechnique, url`. 최신 STIX 는 `x_mitre_detection` 이 비어 있는 기법 다수(ATT&CK 탐지 전략 체계로 이관) |
| `cisa_kev.jsonl` | **1,730** | 원본 필드 그대로(시나리오 CVE 2건 존재) |
| (loghub) | 미처리 | 원로그 3종은 raw 그대로(로그 이해 합성 시 사용) |

## 1-E. 방어(Defense) 지식 — ATT&CK 의 방어 레이어 + 방어 전용 데이터셋 (2026-10-01, `prep.py --stages defense`, 검증 8/8 PASS)

> 질문 "ATT&CK STIX 의 방어 쪽 데이터셋은 없나?" 에 대한 답: **ATT&CK STIX 자체에 방어 객체가 들어 있고**(v19.2: 완화책 `course-of-action`, 탐지 전략 `x-mitre-detection-strategy`, 분석 `x-mitre-analytic`, 데이터 컴포넌트, `mitigates`/`detects` 관계) 1-C 에선 공격 기법만 뽑았었다. 여기에 **D3FEND**(ATT&CK 의 공식 방어 대응 온톨로지), **CAR**, **CTID 통제 매핑**, **RE&CT**(대응 액션)를 더했다.

| 파일 (`processed/knowledge/`) | 출처·라이선스 | 건수 | 내용 |
|---|---|---|---|
| `attack_defense.jsonl` | ATT&CK v19.2 STIX · ATT&CK 이용약관 | **697 기법** (완화 보유 586 · 탐지전략 보유 **697 전부**) | 기법별 `mitigations[{id,name,how}]`(관계 설명 100% 존재) + `detection_strategies[{name, analytics[{name, description, platforms, log_sources{data_component,channel}, mutable_elements}]}]` + `data_components`. 예 T1190: 완화 8(M1016 취약점 스캔…), 탐지전략 "multi-signal correlation" 분석 7 — **Linux 분석 0220 = "access log 의심 요청 → 5xx/WAF 차단 급증 → 웹서버가 셸 생성/egress"**, 로그소스 `/var/log/apache2/access.log`·`execve`·HTTP 페이로드(SQLi/LFI/**JNDI**), 튜닝 `WebProcList/ChildToolList/BurstThreshold` → 우리 Wazuh 웹룰+Suricata+C 프로세스 조사와 1:1 |
| `attack_mitigations.jsonl` | 〃 | **44** | M-id, 이름, 설명, 적용 기법 수(M1031 네트워크 침입방지 59개) |
| `attack_detection_strategies.jsonl` / `attack_analytics.jsonl` | 〃 | **697 / 1,758**(Linux 358) | 전략→분석 전개 / 분석 단건(플랫폼·로그소스·튜닝). v18+ 에서 `x_mitre_detection` 텍스트를 대체한 체계 |
| `d3fend_mappings.jsonl` / `d3fend_by_technique.jsonl` | D3FEND full mappings(`next.d3fend.mitre.org` API) · MITRE 공개 | **16,164 매핑 / 426 공격기법 커버** | 공격기법(ID·아티팩트·관계) ↔ 방어기법(전술 Harden/Detect/Isolate/Deceive/Evict/Model/Restore, 기법, 아티팩트). 예 T1190: 14개(Detect: Application Protocol Command Analysis, Inbound Session Volume Analysis…) |
| `d3fend_techniques.jsonl` | `d3fend.csv` | **271** | D3FEND 기법 ID·전술·계층·정의 |
| `car_analytics.jsonl` | mitre-attack/car · Apache-2.0 | **102**(Linux 15) | 분석 제목·설명·플랫폼·커버리지(기법/서브기법/수준)·구현 수. 최소 YAML 파서 |
| `ctid_control_mappings.jsonl` | CTID Mappings Explorer · Apache-2.0 | **14,031**(nist_800_53 5,410·cri_profile 2,152·veris 1,270·kev 1,183·azure 972·csa_ccm 940·m365 806·gcp 540·aws 497·intel-vpro 261) | 프레임워크별 **최신 ATT&CK 버전** 파일만: 통제 ID·설명·그룹·`mapping_type`(mitigates/detects/exploitation_technique/secondary_impact…) ↔ 기법. 예 NIST 800-53 rev5(ATT&CK 16.1) T1190 통제 29개; **KEV: CVE-2021-44228 ↔ T1190(exploitation) + T1496/T1486/T1608.001(secondary impact)** |
| `react_response_actions.jsonl` / `react_stages.jsonl` | atc-project/atc-react · Apache-2.0 | **216 / 6** (preparation 103·identification 63·**containment 26**·eradication 8·recovery 14·lessons 2) | 대응 액션 ID·단계·설명·워크플로우. 예 **RA3101 "block external IP address"** = 우리 `block_ip` 와 동일 동작 → 에이전트 대응 어휘·정당화 근거 |

**에이전트 활용**: 조사 중 기법(ATT&CK id)이 잡히면 → (1) 탐지 전략·분석으로 "다음에 어떤 로그/프로세스를 봐야 하는지"(조사 계획), (2) 완화·D3FEND·통제로 "무엇을 권고할지"(대응 계획), (3) RE&CT 로 "어떤 대응 액션을 어떤 단계에서"(승인 요청 문구). 합성 트래젝터리의 판단 JSON(`attack_chain`/`actions`/`remediation`) 근거 텍스트로 직결.

**주의**: ATT&CK 분석(1,758)은 Windows/Linux/macOS 혼재 → Linux 358 우선. CTID 는 프레임워크마다 ATT&CK 기준 버전이 다름(기법 id 는 대체로 안정). CAR·RE&CT 는 최소 파서(`parser: minimal`). D3FEND 는 `d3fend.mitre.org/api/...` 가 404, `next.` 호스트에서 제공(실측).

## 1-F. ATT&CK 보강 (2026-10-01, `prep.py --stages attack`, 검증 11/11 PASS)

> "ATT&CK 부분도 보강됐나?" → 1-C(기법)·1-E(방어)에 더해 **STIX 에 남아 있던 위협 인텔 층과 텍스트→기법 라벨 데이터**를 채웠다. 이제 ATT&CK 는 기법·전술·방어·절차·행위자·사건체인·문장라벨까지 전 층 보유.

| 파일 | 출처·라이선스 | 건수 | 내용 |
|---|---|---|---|
| `knowledge/attack_procedures.jsonl` | ATT&CK v19.2 STIX `uses` 관계 | **17,136** (텍스트 100%) | 행위자(그룹 4,628·악성코드 10,493·툴 869·캠페인 1,146) → 기법의 **절차 예시**(실제 사용 서술). T1190 만 75건. 공격 서사 합성·귀속(attribution) 근거 |
| `knowledge/attack_groups.jsonl` | 〃 `intrusion-set` | **176** | id·이름·별칭·설명·사용 기법·소프트웨어 (예 G0016 APT29: 기법 66·소프트웨어 49) |
| `knowledge/attack_software.jsonl` | 〃 `malware`+`tool` | **825** | (예 S0002 Mimikatz 기법 17) |
| `knowledge/attack_campaigns.jsonl` | 〃 `campaign` | **56** | 시기·기법 |
| `knowledge/attack_tactics.jsonl` | 〃 `x-mitre-tactic` | **15** | 전술 설명 |
| `knowledge/attack_revoked_map.jsonl` | 〃 `revoked-by` | **157** | 폐기 id → 대체 id (CTID 14~16 매핑 등 **구버전 id 를 19.2 로 정규화**할 때 사용) |
| `knowledge/tram_sentences.jsonl` | CTID **TRAM** bootstrap+merged+tram2(single/multi) · Apache-2.0 | **47,805 문장** (라벨 22,286, 다중 799, 비라벨 25,519=음성) | **문장 → 기법 ID** 주석(disposition=accept 만). **미지 기법 ID 0**(활성+폐기 id 로 검증). 로그/경보 텍스트에서 `attack_chain` 을 뽑는 능력의 지도 데이터 |
| `knowledge/attack_flows.jsonl` | CTID **Attack Flow** corpus(.afb 빌더 포맷) · Apache-2.0 | **41 흐름**: 원본 scope상 사건 25, 악성코드 8, 캠페인 3, 행위자 2, 훈련계획 2, 공격트리 1 | **2026-10-30 정정:** 41개 모두 실제 독립 사건이라는 기존 설명은 잘못됐다. 기존 최소 변환본의 액션 952·직접 액션 간선 610은 전체 그래프가 아니다. 원본 조건 147·AND 89·OR 29, 연결 2,113개의 분기 의미를 보존하지 않으며 BFS 나열을 시간순 정답으로 사용할 수 없다. 기존 변환본은 이력으로 보존하고 학습 정답 사용을 보류한다. [전수 대조/한계](../finetuning/SOC_ADDITIONAL_DATA_REVIEW.json) |
| `reference/ttp_mapping.jsonl` | tumeteor/Security-TTP-Mapping | 3,519 | 절차 문장→기법. **라이선스 모호(README 배지 CC-BY-NC-SA vs 본문 CC-BY) → 학습 제외, 참고/평가용** |

**남은 ATT&CK 관련 공백(스크랩으로 안 됨, 작성 필요)**: 우리 시나리오↔기법 정답표(S1 T1595/T1190/T1110, S2 T1190/T1059/T1071, S3 T1068/T1548 등)를 `scenarios/alerts.md` 룰 매트릭스와 함께 ground truth 로 작성해야 한다. 한국어 ATT&CK 번역은 공식본 없음.

## 2. 추가 후보 (미반입 — 명령은 §6)

| 데이터셋 | 라이선스 | 게이트 | 크기 | 내용 | 우선순위 |
|---|---|---|---|---|---|
| `lambda/hermes-agent-reasoning-traces` | Apache-2.0 | 아니오 | 1.6GB parquet(Kimi-K2.5·GLM-5.1 트레이스) | **Hermes Agent 하네스** 다중턴 트래젝터리(`<think>`+`<tool_call>`+`<tool_response>`), 10K~100K | **높음** — 우리 런타임과 가장 닮은 트레이스. 용량 때문에 필요 시 |
| `DJLougen/hermes-agent-traces-filtered` | Apache-2.0 | 아니오 | 366MB jsonl · 3,679 | 위의 품질 필터본(추론 깊이·구조·툴콜 유효성) | **높음**(작은 대안) |
| `trendmicro-ailab/Primus-Instruct` | ODC-BY | **예**(HF 로그인+동의) | 4MB parquet(태스크별: `alert_explanation`, `security_doc_qa`, 의심 명령 분석, 쿼리 생성, Terraform 위험) | 전문가 큐레이션 보안 시나리오 + GPT-4o 응답 | **높음** — 경보 설명·명령 분석이 우리 과제와 직결 |
| `trendmicro-ailab/Primus-Reasoning` | ODC-BY | **예** | 9MB(`ctibench_o1`, `ctibench_deepseek-r1`) | CTI-Bench 추론 과정(o1/R1) | 중 — 추론 스타일 증류 |
| `Salesforce/xlam-function-calling-60k` | CC-BY-4.0 | **예** | 98MB · 60K, 3,673 API | APIGen 함수호출 | 중 — 형식 능력 추가(이미 hermes/ToolACE 로 충분할 수 있음) |
| `akseljoonas/ToolMind` | Apache-2.0 | 아니오 | 4GB | 추론 강화 대규모 툴사용 | 낮음(용량) |
| SALAD-SOC `train`/`test` | CC-BY-4.0 | 아니오 | 645MB / 138MB | 전체 분할 | 중 — 트리아지 라벨 확장 시 |
| AIT-LDSv2 (원 로그·PCAP) | CC-BY-4.0 | 아니오 | 수 GB(Zenodo) | AIT-ADS 의 원천 로그·pcap | 낮음 — Suricata 룰 재적용·재생(tcpreplay) 시 |
| Splunk BOTS v1/v2 | Splunk 공개(약관 확인) | 사이트 등록 | 수 GB | Suricata+호스트 로그 CTF형 조사 | 중 — 조사 시나리오 서사 원천 |
| `Veedubin/attacklm-dataset` (GitHub) | 레코드별 명시(Atomic/Sigma/Elastic 등 원출처 라이선스) | 아니오 | 24,652건 | MITRE ATT&CK 근거 레드/블루 QA, 출처·라이선스 전수 기재 | 중 — 탐지·기법 설명 지식 |
| Minerva-CTI (논문 2602.00513) | 확인 필요 | - | 32K train | Sigma→전술, Atomic→기법 등 16 CTI 과제 | 낮음 — 공개 여부 확인 후 |
| KISA 사이버보안 AI 데이터셋(악성코드·침해사고) | 국내 공개(신청/약관) | 예 | 대규모 | 국내 침해사고 데이터 | 확인 — 한국어 보안 데이터 유일 후보, AI허브 공지 확인 |
| HeegyuKim/open-korean-instructions | 각 세트별 | 아니오 | - | 일반 한국어 instruction 모음(보안 아님) | 낮음 — 한국어 응답 스타일 보강용 |

## 3. 합성 원천·지식 베이스 (툴/문서, 데이터셋 아님)
MITRE ATT&CK(STIX JSON), **Atomic Red Team**(MIT — 기법별 테스트 → "공격→기대 증거" 쌍 생성), **Sigma**(DRL — 탐지 로직 → 설명), CISA KEV(반입됨), NIST SP 800-61, D3FEND, CAPEC. 우리 `scenarios/`·`alerts.md` 매트릭스(룰 id↔시나리오)가 정답 라벨.

## 4. 우리 에이전트용 활용 설계
| 단계 | 데이터 | 목적 | 비고 |
|---|---|---|---|
| A 형식 | hermes-function-calling-v1 + ToolACE (+ hermes-agent-traces) | 선택 모델의 챗 템플릿·tool_calls·다중턴·JSON 출력 안정화 | **현재 Hermes가 노출하는 MCP 도구 이름·스키마**와 맞추고, 도구 이름만 바꾸지 말고 호출 인자·응답·판단의 의미까지 검수 |
| B 도메인 | Primus-Instruct(`alert_explanation` 등) + Primus-Reasoning + attacklm | 경보 해석·명령 분석·ATT&CK 매핑 추론 | ODC-BY 표기 |
| C 과제 합성 | **AIT-ADS wazuh.json + labels.csv** → "경보 묶음(툴 응답) → 조사 툴콜 → 판단 JSON(verdict/attack_chain/actions)" teacher 합성; SALAD 로 트리아지 결정 보강 | 우리 스키마·툴명 그대로 학습 | 공격 단계 라벨이 정답 체인 |
| D 핵심 | **우리 시나리오 실측 트래젝터리**(Hermes `sessions/`·`agent.log`) 검수본 | 실제 환경 분포 | 회차 독립성(`eval_reset`) 유지한 채 수집 |

- **포맷 변환**: ShareGPT(`from: human/gpt/tool`) → Qwen 챗 템플릿(`system/user/assistant(tool_calls)/tool`). `tools` 필드 → 시스템 `<tools>` 블록. Hermes 네이티브이므로 변환 손실 최소.
- **한국어**: 공개 데이터는 영어 → teacher 로 한국어 응답 생성/번역하되 **식별자(툴명·IP·룰id·경로·명령)는 원문 유지**(SOUL 규칙과 동일).
- **혼합 비율(초안)**: D 40% / C 30% / A 20% / B 10%. 평가 데이터(SALAD test, CTI-Bench, 우리 시나리오 holdout)는 학습에서 제외.
- **품질**: GPT-4o/o1 생성분은 teacher 편향 → 사람 검수 샘플링. 툴콜 유효성(스키마·인자) 자동 검증 후 포함.

## 5. 라이선스·주의
- CC-BY-4.0(AIT-ADS·SALAD·xLAM)·ODC-BY(Primus): **출처 표기** 필요(보고서·모델 카드). Apache-2.0(Hermes·ToolACE·lambda)·MIT(Atomic) 자유.
- 모델 Qwen3 = Apache-2.0. 파생 모델 공개 시 각 데이터 라이선스 고지.
- AIT/SALAD 는 합성·테스트베드 데이터라 개인정보 이슈 없음. Splunk BOTS 는 약관 확인.
- **학습/평가 누출 방지**: 같은 환경(AIT fox 등)이나 같은 시나리오를 train/test 에 나누어 쓰지 말 것.

## 6. 미반입분 다운로드 명령 (인터넷 되는 Mac 에서; Python urllib 은 CA 문제로 실패 → `curl` 사용)
```bash
cd datasets/raw
# Hermes 하네스 트레이스(필터본 366MB)
curl -L -o hermes-agent-traces-filtered.jsonl "https://huggingface.co/datasets/DJLougen/hermes-agent-traces-filtered/resolve/main/train.jsonl"
# SALAD 전체 train/test
curl -L -o salad-soc/salad_train.csv "https://huggingface.co/datasets/nutthakorn7/SALAD-SOC/resolve/main/salad_train.csv"
curl -L -o salad-soc/salad_test.csv  "https://huggingface.co/datasets/nutthakorn7/SALAD-SOC/resolve/main/salad_test.csv"
# 게이트(Primus·xLAM): HF 계정으로 데이터셋 페이지에서 약관 동의 후 토큰 사용
#   export HF_TOKEN=...   (토큰은 출력/커밋 금지)
curl -L -H "Authorization: Bearer $HF_TOKEN" -o primus-instruct-alert_explanation.parquet "https://huggingface.co/datasets/trendmicro-ailab/Primus-Instruct/resolve/main/alert_explanation.parquet"
# AIT-ADS 압축 해제(~2.8GB): unzip ait-ads/ait_ads.zip -d ait-ads/
```

## 7. 출처
- Hermes Function Calling V1: https://huggingface.co/datasets/NousResearch/hermes-function-calling-v1
- Hermes agent reasoning traces: https://huggingface.co/datasets/lambda/hermes-agent-reasoning-traces (필터본 https://huggingface.co/datasets/DJLougen/hermes-agent-traces-filtered)
- Primus 컬렉션(논문 2502.11191): https://huggingface.co/datasets/trendmicro-ailab/Primus-Instruct , https://huggingface.co/datasets/trendmicro-ailab/Primus-Reasoning
- AIT-ADS: https://zenodo.org/record/8263181 , 스크립트 https://github.com/ait-aecid/alert-data-set , 논문 https://dl.acm.org/doi/fullHtml/10.1145/3675741.3675748
- SALAD-SOC: https://huggingface.co/datasets/nutthakorn7/SALAD-SOC
- xLAM/APIGen: https://huggingface.co/datasets/Salesforce/xlam-function-calling-60k , ToolACE: https://huggingface.co/datasets/Team-ACE/ToolACE , ToolMind: https://huggingface.co/datasets/akseljoonas/ToolMind
- AttackLM dataset: https://github.com/Veedubin/attacklm-dataset , Minerva-CTI: https://arxiv.org/abs/2602.00513
- LLM 경보 트리아지 평가 하네스: https://github.com/Shubhmane9503/llm-alert-triage-eval
- KISA 사이버보안 AI 데이터셋 보도: https://www.edaily.co.kr/news/read?newsId=02561686629018088 , 한국어 instruction 모음: https://github.com/HeegyuKim/open-korean-instructions
