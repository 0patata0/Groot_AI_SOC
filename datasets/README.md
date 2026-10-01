# 에이전트 파인튜닝 데이터셋 카탈로그 (2026-10-01)

> 대상 에이전트: Hermes Agent(B) + `qwen3.6:35b`(DGX Ollama), MCP 툴콜(읽기 14툴: Wazuh 경보/에이전트/프로세스/포트/취약점, 응답 3툴: `block_ip`/`unblock_ip`/`list_blocks`)로 **경보 이후 조사·상관분석·침해판단·대응(승인)** 을 한국어로 수행.
> 파인튜닝 원칙(PLAN 4단계): **핵심 데이터 = 우리 시나리오 실측 트래젝터리**(Hermes 세션 → teacher 초안 → 사람 검수 → Qwen 챗 템플릿 → LoRA/QLoRA). 공개 데이터는 **보조**(툴콜 형식 능력·보안 추론·합성 원천). 없어도 프로젝트는 완결(확장 목표).
> 저장: `datasets/raw/`(gitignore, 342MB 반입 완료). 라이선스·용량·게이트 여부는 HF/Zenodo API 로 **실측 확인**(2026-10-01).

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
| A 형식 | hermes-function-calling-v1 + ToolACE (+ hermes-agent-traces) | Hermes `<tool_call>` 포맷·다중턴·JSON 출력 안정화 | 툴 스키마를 **우리 17개 MCP 툴 시그니처**로 치환한 변형 생성 권장 |
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
