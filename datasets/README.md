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
