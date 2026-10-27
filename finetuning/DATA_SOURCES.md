# 데이터 출처와 사용 범위

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 기존30B LoRA 준비 데이터는 train18,872/validation980/test932개이며10/24 로컬 행 수·SHA 대조가 일치했다. 운영35B와 다른 후보이고 GPU 학습/실모델 비교는 아직 없다. 공개 corpus·지식·독립 평가·우리 SOC 검수 trajectory의 역할을 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

이 묶음은 이 프로젝트가 이미 확보한 `datasets/processed/` 파일에서 생성했다. 다음 출처·라이선스 표기는 기존 `datasets/README.md`의 수집 기록에 근거한다. 원본의 저작권/라이선스를 대체하거나 프로젝트가 모든 데이터를 새로 허가한다는 뜻이 아니다.

| 입력 파일 | 원출처 | 기존 수집 기록의 라이선스 |
|---|---|---|
| `hermes_fc_v1.dedup.jsonl` | [NousResearch/hermes-function-calling-v1](https://huggingface.co/datasets/NousResearch/hermes-function-calling-v1) | Apache-2.0 |
| `glaive_fc_v2.hermes.jsonl` | [glaiveai/glaive-function-calling-v2](https://huggingface.co/datasets/glaiveai/glaive-function-calling-v2) | Apache-2.0 |
| `hermes_agent_traces.jsonl` | [DJLougen/hermes-agent-traces-filtered](https://huggingface.co/datasets/DJLougen/hermes-agent-traces-filtered) | Apache-2.0 |
| `sevenllm_en.jsonl` | [Multilingual-Multimodal-NLP/SEVENLLM-Dataset](https://huggingface.co/datasets/Multilingual-Multimodal-NLP/SEVENLLM-Dataset) | Apache-2.0 |
| `attacklm.permissive.jsonl` | [Veedubin/attacklm-dataset](https://github.com/Veedubin/attacklm-dataset) 및 각 레코드 원출처 | 레코드별 BSD-3-Clause / Apache-2.0 / MIT / DRL-1.1 / Public-Domain / 복합 표기 |

AttackLM의 `permissive`는 기존 전처리 파일명이다. 위 라이선스들이 동일 조건이라는 뜻은 아니다. Elastic-2.0·GPL-3.0 레코드는 해당 입력에서 이미 제외돼 있으며 준비기에서도 레코드 라이선스 허용 목록을 검사한다. 레코드별 원출처·라이선스·MITRE ID를 provenance에 보존한다. 외부 재배포 시에는 원출처의 attribution/notice와 해당 조건도 함께 처리해야 한다.

이번 변환: ShareGPT/Hermes 텍스트 도구 호출을 구조화된 `messages`/`tools`로 통일, 도구 스키마·인자·응답 순서 검사, 명시적인 `<think>` 및 SEVENLLM `thought` 제외, 손상·과도한 길이 제외, 중복 제거, 소스별 최대 5,000행 선택, 질문 그룹별 train/validation/test 분할. 보안 내용의 정답성이나 유해성 전수를 사람이 검수한 것은 아니다. 모델 학습 결과를 운영에 쓰기 전에 업무 적합성·승인 정책 준수를 평가한다.

`processed/eval/`의 CyberMetric·CTI-Bench·SecQA·AttackLM bench와 `raw/sevenllm/test.jsonl`은 **동일 질문 차단용으로만 읽고 학습에 합치지 않았다.** AIT 원본 경보, SALAD CSV, knowledge/reference, 기타 미지정 파일도 자동으로 학습에 넣지 않았다. 대화형 정답으로 가공하는 별도 단계가 필요한 데이터다.

입력 파일·평가 제외 파일의 SHA256, 출처별 선택/탈락 수, 출력 SHA256은 `data/manifest.json` 및 Git 추적용 `preparation_summary.json`에서 확인한다. 라이선스·출처 메타데이터는 학습 텍스트에 넣지 않는다.

## 2026-10-27 현행 도구 대조

기존 공개 train18,872행의 구조화 호출19,230개는 현행 MCP 전체 이름과 일치0개였다. 모델별 새 학습 설정과 자료의 업무 적합성은 별개다. 현재 스키마 스냅샷·읽기 감사기는 [THOR_35B.md](THOR_35B.md)를 따르며 공개 원출처·라이선스/분할은 유지한다. 이름의 일괄 치환·현재상태 정답화·검수 없는 운영대화 편입은 수행하지 않았다.

## 추가 학습자료·가중치 후보 조사 — 2026-10-27 KST

사용자의 추가 자료 탐색 요청에 따라 원 제공자 카드·공개 미리보기를 확인했다. 아래 규모/라이선스/성능은 제공자 표기이며 전체 데이터 정답성·원본 파일 SHA·우리 tokenizer/37MCP 스냅샷·Thor/Ollama 호환 검증을 통과한 수치가 아니다. 후보 본문·가중치 다운로드, 계정 약관 동의, 패키지 설치, 학습·운영 모델 변경은 수행하지 않았다. 기존 corpus/분할·평가 제외 정책은 유지한다.

### 새로 확인한 학습·평가 후보

| 후보 | 제공자 규모/라이선스 | 이 프로젝트에서의 판단 |
|---|---|---|
| [Ko-Agent-Trajectories-1.0](https://huggingface.co/datasets/taejoon89/Ko-Agent-Trajectories-1.0) | SFT518,232 / robustness DPO33,323 / behavior DPO14,238 / eval9,936. 데이터CC-BY-4.0, 파이프라인Apache-2.0 | 한국어 다단계 호출·오류 복구 보조 후보. 제작자의Qwen3-8B 비사고모드 시험에서 과잉 확인 질문과 첫 호출 저하가 관측돼 전체 혼합은 권장하지 않는다. 행동 예시 검수·별도 평가 필요. 현재 학습기는 SFT이며 DPO쌍을 그대로 투입할 수 없다. |
| [ko-agentic-sft](https://huggingface.co/datasets/waylake/ko-agentic-sft) | 2,369대화: action1,583/no-action786. Apache-2.0 | 불필요한 도구 호출 억제·빈 결과 처리의 소규모 보조 후보. 가상 도구 응답/자리표시 URL은 사실 근거로 쓰지 않는다. 문자열action·user역할의도구결과를 현재messages/tools 계약으로 변환·검수한다. |
| [Primus-Instruct](https://huggingface.co/datasets/trendmicro-ailab/Primus-Instruct) | 보안496+일반339=835. ODC-BY | 경보 설명·의심 명령·보안 조회 쿼리에 가까운 우선 도메인 후보. HF계정 동의/접근권한이 필요한 gate가 현재도 존재한다. 이번에 동의·접근을 대신하지 않았다. |
| [xLAM-60k](https://huggingface.co/datasets/Salesforce/xlam-function-calling-60k) | 60,000예시/3,673API. CC-BY-4.0 | 기존 미반입 후보의 gate·출처를 재확인했다. 일반 호출 보조용이며 실제SOC판단/승인을 대체하지 않는다. query/tools/answers 구조 변환 및 기존자료 중복 확인 후 사용한다. |
| [qwen3.5-functioncalling-v2](https://huggingface.co/datasets/Mustafaege/qwen3.5-functioncalling-v2) | 카드약225K·영/한. Apache-2.0표기 | Glaive+Saxo 재포장이다. 기존Glaive와 원천 중복이 있어 수량만 더하지 않는다. 문자열 호출/도구 결과 역할 변환·원천별 조건 재확인이 필요해 후순위다. |
| [SOC-AgentBench](https://huggingface.co/datasets/alirezaaminzadeh/soc-agent-bench) | 120에피소드/12시나리오. Apache-2.0 | 이 프로젝트에서는 전체를 평가 전용으로 보류한다. Wazuh/Suricata 등 합성 로그와 별도7도구를 사용한다. 숨은 정답/금지행동을 모델 입력에 노출하지 않고 근거 누락·허위 관측·불필요 호출·무승인 행동을 채점한다. |
| [FunctionChat-Bench](https://github.com/kakao/functionchat-bench) | 한국어 도구 사용 평가 자료 | 즉시 호출/추가 질문/불가능한 도구 요청 거절의 회귀 확인용. 학습 원천으로 편입하지 않는다. |

[한국어ToolLLaMA 변환본](https://huggingface.co/datasets/gyung/toolllama-korean-function-calling)은1,524행(한국어762+영어762)이지만 원천이 `toolllama_G123_dfs_eval.json`으로 명시돼 학습 후보에서 제외한다. [ko-agentic-toolcall](https://huggingface.co/datasets/jungsanghyun/ko-agentic-toolcall)은 검색 카드에 규모가 나오지만 원본raw접근401/완전한라이선스를 확인하지 못해 미확인 후보로만 남긴다.

### 이미 학습된 가중치·LoRA

| 후보 | 확인한 제공자 정보 | 판단 |
|---|---|---|
| [Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct) | Cisco공식보안특화Instruct,Llama3.1기반8B,영어지원·카드other/NOTICE는Cisco변경분Apache-2.0+기반Llama3.1조건 | 경보해석의별도비교1순위. 현Qwen의LoRA가아니며독립모델로평가한다. 한국어·MCP호출·Ollama실적재/속도와전체라이선스조건검토는후속이다. |
| [Foundation-Sec-8B-Reasoning](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning) | Cisco공식보안추론8B,영어지원·카드other/NOTICE는Cisco변경분Apache-2.0+기반Llama3.1조건 | 복합사건판단비교후보. 추론토큰이응답지연에미치는영향을측정해야하며8B라는이유만으로35B보다빠르거나정확하다고판정하지않는다. |
| [Llama-Primus-Merged](https://huggingface.co/trendmicro-ailab/Llama-Primus-Merged) | TrendMicro공식보안코퍼스학습+Llama3.1-8B계열병합,카드MIT | 보안지식/트리아지의별도비교후보. 기반Llama조건과모델파일고지확인후반입한다. 한국어·현MCP·정확도우위는자체미검증이다. |
| [CyberStrike-OffSec-35B](https://huggingface.co/oyildirim/CyberStrike-OffSec-35B) | 같은Qwen3.6-35B-A3B계열의merged+adapter revision. 공격용 하네스300예시 학습,라이선스표기other | 우리MCP와 다른 실행 체계다. 모델 이름이 같아도 base commit·adapter 대상/shape·tokenizer·보호승인·Ollama 변환을 확인해야 한다. 제작자24상황평가에서도 구조화 호출은base22→후보18로 일부퇴보했다. 검증 없는 대체/병합 후보로 추천하지 않는다. |
| [Qwen3.6-35B-A3B-RFT](https://huggingface.co/shaneMattner/Qwen3.6-35B-A3B-RFT) | 같은모델계열의BF16 merged,코딩train1,616/val180. Apache-2.0 | SOC전용학습이 아니다. 제작자비교의base4bit/후보6bit조건이달라학습효과를분리하지못했다. 비교연구후순위,현재SOC우위근거없음. |

Cisco 두 후보의 [Instruct NOTICE](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct/blob/main/NOTICE.md) · [Reasoning NOTICE](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning/blob/main/NOTICE.md)도 직접 확인했다. Cisco 변경분의 Apache-2.0만으로 기반 Llama3.1 조건을 생략하지 않는다.

공식Cisco의1.1-Instruct발표는찾았으나해당HF경로는열리지않아이번다운로드가능후보로확정하지않았다.

이는제공자카드조사이며새모델적재/어댑터shape대조/자체A/B를실행한것이아니다. 다른base의LoRA를현재35B에곧바로합칠수있다고판정하지않는다.

### 보유 자료와 권장 선별 순서

기존 `preparation_summary.json`은원입력120,917행중구조검사/중복제외후적격106,511행,소스별5,000상한을거쳐최종20,784행을기록한다. 이숫자는이번에전체본문을재검사한결과가아니다. `datasets/processed/`의기존5개대화입력과AIT분할/SALAD train/ATT&CK방어자료,raw ToolACE경로의존재를직접확인했다. 현재학습에는AIT경보·SALAD CSV·지식자료가자동포함되지않았다.

권장순서: (1) 보유AIT/Wazuh·Suricata경보+실제성공/실패SOC요청을현행도구스키마에맞춰검수한trajectory, (2) Primus방어과제또는보유ATT&CK/CAR/RE&CT근거로작성·검수한경보설명, (3) 한국어보조자료의소량선별이다. 공개가상응답이나과거운영상태를현재사실로외우게하지않는다. 짧은질문의FW/IDS/WAF대상선택,모든요청항목조회,증거불충분/도구장애,승인전변경금지,적용/원복/사후검증,UTC/KST중복변환금지를필수축으로둔다.

원천·같은사건·번역쌍·질문변형단위로분할하고기존test및외부벤치를학습에서제외한다. 현MCP는보관스냅샷37도구(읽기28/보호9)기준이며반입전실제계약을다시대조한다. 소스별상한만해제하거나수십만행을추가하는것보다스키마/근거/누락검수와새사건평가를먼저수행한다. 선별·전처리·반입·GPU학습·정확도평가는모두다음단계이며이번조사완료와구분한다.

## SOC 선별 실행 — 2026-10-27 KST

후보 조사 뒤 현37MCP 계약을19:05:50 KST 재조회하고 검수 합성100대화와 기존 AIT 공개 실습 경보의 사실 추출112대화를 별도 준비했다. AIT 출처는 [AIT Alert Data Set](https://zenodo.org/records/8263181), CC-BY-4.0이며 각 원본파일/선택행 SHA를 로컬 manifest에 보존한다. rule.id·level·KST 시각·phase_window만 근거로 삼고 공격 시간대를 개별 경보의 악성 정답으로 확장하지 않는다. 여섯 환경 train72, wheeler validation20, wilson test20으로 분리했다. 합성100건은72/12/16으로 시나리오별 분리하며 injection·조회실패·KST 등의 미사용 평가를 둔다. 실제 운영 사건/사람 전수 검수 자료가 아니며 외부 한국어 대규모 corpus는 이번에 추가 반입하지 않았다.

최종 train144/validation32/test36대화(assistant prefix224/44/52), 길이1536에서 초과·정렬 오류0. `soc_dataset.py`가 실제 도구 인자/연결·명시 검수 출처·필수 사실·시나리오 및 첫 질문 중복을 검사한다. test 기반 재설계 시 새 독립 평가셋이 필요하다. 소스 cases·데이터·manifest는 로컬과 Thor `~/Capstone_Groot_training/qwen36-20261027/finetuning/`에 보존하고 Git에 추가하지 않는다. Cisco8B 고정 가중치는 Thor에만 내려받았으며 Qwen에 혼합하거나 LoRA로 적용하지 않는다. 최신 학습/비교 완료 여부는 [STATUS](../STATUS.md)를 따른다.
