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
