# 데이터 출처와 사용 범위

## SOC 관제원 업무용 R3 자료 준비 — 2026-10-29

사용자의 목표는 관제 관리자가 수행하는 **조사 → 증거 대조 → 위험·불확실성 판단 → 변경안/승인 → 적용 후 확인 → 인계**다. 일반 API 호출 corpus 전체를 SOC 전문 정답으로 투입하지 않는다. 현재 [준비 원장](R3_DATA_PREPARATION.json)은 학습 전 상태다.

| 자료 | train | validation | test | 역할·근거 |
|---|---:|---:|---:|---|
| 자체 통제 관제 workflow | 192 | 48 | 48 | 8업무 유형·실제 MCP 계약/응답 원본 함수·로컬 승인/TTL 정책, 에이전트 작성/검수 |
| AIT 과거 로그 조사 | 72 | 12 | 12 | 2경보/사례·원ZIP 192개 객체 일치·가공파일/개행 포함 행 SHA·환경 단위 분리, CC-BY-4.0 |
| 합계 | **264** | **60** | **60** | assistant prefix **696/168/168**, 4K 안에서 제외/절단 0 |

8업무는 WAF/IDS 상관분석·IDS 재시작 승인안·수집 공백·실패 후 검증·복구 검증·임시 차단의 유지 승인·만료 확인·룰 설명 변경안이다. 원인 미확정, 누적 카운터, 관측 표본, 승인/실제 적용, 실제 엔진 적재를 구분한다. 임시 차단 `pending`은 이미 생성된 최초10분 차단의 **60분 유지 승인 대기**다. 룰/서비스 `pending`과 같다고 가르치지 않는다. 실패/확인 불가를 정상·완료로 바꾸지 않는다.

AIT 자료는 **2022년 시험장 아카이브**다. 현재 MCP의 최근 기간 조회로 위장하거나 현재 차단을 요청하지 않는다. `phase_window`는 구간 컨텍스트이며 `normal`도 정상 정답이 아니다. 기존 v1에 쓴 행은 제외했고 train의6환경·validation wheeler·test wilson을 유지한다. 증거 필드/시각은 기계 대조, 한국어 판단·우선순위·인계문은 에이전트 작성이며 독립 전문가 판정이 아니다. `ait_ads_2023`+`landauer2024ait_ads`를 함께 인용하고 가공 방법·선택 수·분할·한계를 논문에 기술한다.

[NIST SP800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)의 RS.AN-03/06/07/08, RS.MI-01, RC.RP-02/05/06을 절차 참고로 연결했다. BibTeX 키는 `nist_sp800_61r3`이며 ToolACE 보조 후보는 `liu2025toolace`와 `team_ace_toolace`로 논문/배포처를 구분한다. 이 문서가 우리 데이터의 정답을 인증하거나 우리 MCP·승인/TTL 구현을 요구한다는 뜻은 아니다. 원본문의 사건 분석/증거 보존/범위 판단/억제/복구 확인에 맞춰 자체 업무 예제를 작성했다.

ToolACE는 고정 원본11,300행에서 엄격한 AST literal-only/스키마·응답 연결·중복/평가 제외 검사 후10,019행(8,031/1,008/980)을 보조 후보로 정제했다. 대체 호출 형식518행 등은 지원하지 않아 제외했다. 이 후보의 전체 의미 검수/실토큰 검사는 미완료이며 **R3 핵심 train에는0건**이다. 임의 API를 운영 MCP 이름으로 바꾸지 않고 reversible alias를 보존한다. APIGen/PRIMUS 게이트 동의·본문 반입은 여전히 미실행이다.

실제 운영 재조회: A 공개 주소→B 내부10.200.10.10 경유,8서버/37도구 전부응답·고정 catalog와 이름/인자/설명 차이0. `a:suricata`는 `kind:runtime`, `metrics/codes/limits`다. 기존 일부 R2/20사례의 systemd `ActiveState` 가정은 실제 이 target과 다르므로 원점수/자료를 보존하고 [한계를 정정](QUALITY_RESULTS.md)했다. 새 센서/진단/룰 인벤토리는 실제 소스의 순수 투영 함수를 사용한다. 그 밖의 결과는 최소 필드 통제 fixture이며 전체 라이브 응답 채록이 아니다.

소스 재생성으로 source SHA와3분할 출력이 모두 일치했다. 학습 시 최장 입력2710/2706토큰, 전체37도구 개발 요청 최대9840+출력768은16K 요청예산 안이다. 학습에는 사례별 소수 도구를 제공하므로 실제 전체37도구 선택 능력으로 일반화했는지는 별도 평가해야 한다. 같은 생성기의 문구/ID holdout이며 독립 실사건/전문가 검증으로 확대하지 않는다.

순차 평가기 `operator_rollout.py`는 모델이 맞는 다음 호출을 생성한 경우에만 fixture를 제공한다. ID·scope·정확한 후보를 검사하되 사유 문장 암기는 요구하지 않는다. 다른 앵커로 같은 전체 파일을 만들면 동등한 수정안으로 허용한다. 준비하지 않은 유효한 조회 경로는 **미평가**이며 거짓 관측/자동 정답 주입/무조건 오답으로 대체하지 않는다. 자동 필수 문자열 판정 뒤 실제 원문 의미 검수가 필요하다. 테스트60건은 토큰 검사만 했고 모델 답변 생성/체크포인트 선택에 쓰지 않았다.

수정 기준의 학습 전 개발9건을 완료했다. 5건은 조회 생략/무관한 임시차단·가짜ID/근거 없는 적재방식/아카이브 원본·해시오해석 등의 중대오류를 원문으로 확인했고,4건은 지원하지 않는 대체 조회 경로로 미평가다. 전체 정확도 백분율로 제시하지 않는다. 초기 엄격 평가의 전체0은 평가기 한계가 섞인 수치다. 원본35B warm을 확인했다.

새48-step/2e-6는 제한 pilot 설정이며 전체696prefix 1epoch 학습 완료가 아니다. 새 successful_microbatch_lineage는 실제 성공 forward/backward의 record/prefix/행 SHA와 직전 optimizer step을 남긴다. 성공 microbatch가 이후 optimizer update/전체 실행 성공을 의미하지 않는다. GPU 학습/변환/후보등록/봇 전환은 아직 없다.

재생성에는 전체 repo의 `infra/mcp` 원본, 기존 AIT 원본·processed·v1 제외 목록이 필요하다. 이들은 자동 인터넷 취득/미확인 동의로 대체하지 않는다. 휴대용 pack은 정제 자료·명세·소스·테스트와 검사용 `contract_sources` 3개를 명시적으로 포함한다. 실제 MCP 서비스로 설치하는 파일이 아니며 새 서비스/포트/키/초기 deploy 변경은 없다.

```bash
python3 -B finetuning/prepare_soc_operator.py --output NEW_DATA --source-output NEW_SOURCE/cases.jsonl
python3 -B finetuning/train.py --config finetuning/config.qwen36-soc-v3.json --check
python3 -B finetuning/pack.py --config finetuning/config.qwen36-soc-v3.json --output TASK_TMP/r3.tar.gz
```

## 2026-10-29 과거 학습의 출처·실제 투입 이력

논문용 출처는 [기계 판독 이력표](TRAINING_PROVENANCE.json), [BibTeX](references.bib), [재검증기](audit_training_provenance.py)에 연결한다. 2026-10-29 Thor에서 읽은12개 완료 실행의 manifest/토큰 통계/Trainer 상태·어댑터 해시와 로컬 원본을 대조했다. 공개/기관 원천을 가공한 자료와 자체 합성 대화, 준비만 한 후보, 평가 자료를 구분한다. **아래 정정은 과거의 “공개 혼합 자료는 준비만 했다”는 포괄적 표현보다 우선한다.**

| 실제 실행 | 학습 원천과 인용 | 준비 풀/선택 범위 | 확인된 학습 |
|---|---|---|---|
| 10/27 초기35B smoke | [Nous Hermes FC v1](https://huggingface.co/datasets/NousResearch/hermes-function-calling-v1). 해당 준비 풀에 `glaive-function-calling-5k.json` 재포함 원천도 있음 | 일반 혼합 train18,872행 중 앞13행을 읽어32 prefix 허용. 앞13행은 전부 Nous 처리 파일에서 유래 | 2 optimizer steps, accumulation1.18,872행 전체나5개 원천 전부를 학습한 것이 아니다. 실제2개 prefix의 개별 ID/순서는 당시 미기록 |
| 10/27 v1 smoke/pilot/main | 자체 합성 대화 + [AIT 기관 원본](https://zenodo.org/records/8263181), `ait_ads_2023`와`landauer2024ait_ads` 함께 인용 | train144대화=자체합성72+AIT 추출72,224prefix. validation32=합성12+AIT20,test36=합성16+AIT20 | smoke32prefix풀/2step,pilot8step,본학습112step/기록epoch1. 서로 독립 실행이며 본학습을smoke어댑터의 연속학습으로 표시하지 않는다 |
| 10/28 R2 smoke/pilot | 자체 생성한 합성 SOC curriculum, 생성기·MCP 계약/소스SHA를 인용. 외부 기관 정답이라고 표기하지 않는다 | train192대화/390prefix,validation32/65,test32/65.전부합성 | 최장2prefix smoke2step, 별도pilot48step/accum2/기록epoch0.246153846.24/48체크포인트는 같은pilot의 중간/최종이며 서로 다른 전체학습으로 합산하지 않는다 |
| 10/28 메모리·드라이버 진단 | R2와 **동일한 데이터 해시**. 새 외부 학습자료가 아니다 | R2 train의 최장2prefix,eval8prefix | native/VMM/trace/선택loss/원본재현2step·native 별도1step. 품질 학습 완료/신규 사례 수로 중복 계상하지 않는다 |

첫 학습 적재 실패·작은 무작위 모델 호환성 fixture는 완료한35B 학습 자료로 합산하지 않는다. 실패 기록은 로컬에 보존하며 폐기된fixture를 실제SOC학습 원천으로 인용하지 않는다. 30B 설정은 준비된 후보였고 실제 위 실행의 기반은 고정35B다. 기반 모델은 `qwen36_35b_base`, revision `995ad96eacd98c81ed38be0c5b274b04031597b0`를 사용한다. 초기smoke의`base_revision_resolved`필드는null였으므로 당시확인필드를사후에채웠다고표시하지않는다. 기반모델의 전체사전학습데이터는우리가확인/복원한후속학습자료와다르다.

### 일반 혼합 준비 자료의 전체 원천

| 처리 입력 | 준비 train/validation/test | 1차 배포처·인용키 | 과거 실제 학습 관련성 |
|---|---:|---|---|
| Hermes FC v1 | 4612/178/210 | [Nous Research](https://huggingface.co/datasets/NousResearch/hermes-function-calling-v1), `nous_hermes_function_calling_v1` | 위 초기smoke의허용32prefix 원천. 포함된Glaive5k는레코드의`_source_file`로구분 |
| Glaive v2 | 4597/219/184 | [Glaive AI](https://huggingface.co/datasets/glaiveai/glaive-function-calling-v2), `glaive_function_calling_v2` | 준비됨. 초기smoke가읽은앞13행에는없고v1/R2에도미포함. Glaive5k재포함본과동일자료로표시하지않는다 |
| 필터된 Hermes traces | 639/89/56 | [DJLougen](https://huggingface.co/datasets/DJLougen/hermes-agent-traces-filtered)와 그 [Lambda 상위 원천](https://huggingface.co/datasets/lambda/hermes-agent-reasoning-traces), `djlougen_hermes_filtered`+`lambda_hermes_traces` | 준비됨. 양쪽 출처를 인용하며 실제실행결과라는제작자설명을우리실관제기록으로표현하지않음 |
| SEvenLLM 영어 | 4528/226/246 | [공식 데이터](https://huggingface.co/datasets/Multilingual-Multimodal-NLP/SEVENLLM-Dataset), [논문](https://arxiv.org/abs/2405.03446v2), `sevenllm_dataset`+`ji2024sevenllm` | 준비됨. `train.jsonl` 원천과학습제외한`test.jsonl`을분리. 이번인용은arXiv v2이며확인안한학회명을만들지않는다 |
| AttackLM 선별 | 4496/268/236 | [집계 저장소](https://github.com/Veedubin/attacklm-dataset), `attacklm_dataset` 및개별upstream키 | 준비됨. 집계자만인용하지않고원천17종URI/선언라이선스/수량을JSON에보존. DRL-1.1등을동일한permissive조건으로표현하지않음 |

이표의분할수는manifest의고정기록이며아래기계판독이력표와재검사한다. 공개카드Apache-2.0은기록하되원천별권리/고지/재배포조건을생략하지않는다. 과거취득당시commit/revision을남기지않은공개원천은미기록으로표시하고,현재웹main을당시버전으로대체하지않는다. 내용SHA와가공후파일SHA는보존되어있다. 실제학습에없는원천을‘학습에사용’이라고논문본문에쓰지않는다.

### 가공·정답·검수의 근거

- 일반 혼합: `datasets/prep.py` → `datasets/processed/` → `finetuning/prepare_data.py` → 고정`data/manifest.json`. ShareGPT/텍스트호출을구조화하고형식·스키마·호출순서·중복·길이·소스상한을검사한다. 명시think/SEvenLLM thought는제외했다. 이것은보안정답의전문가전수검증과다르다.
- v1 AIT: 공식zip → 환경별가공파일SHA → 원천행번호/개행포함행SHA → fact추출대화 → 분할SHA → run manifest → 어댑터SHA. 이번에train72/validation20/test20총112개 모두가공파일과공식zip내경보객체까지일치했다. 추가필드`ait_env`/`phase_window`를제거하고동일객체를대조했다. 시각변환·rule.id/level/phase 추출이목표이며단계창을개별악성정답으로바꾸지않는다. six train/wheeler validation/wilson test 환경분리를유지한다.
- v1 합성·R2: AI작업에이전트가작성/검수했다. v1과거메타데이터의`Operator-authored`/`independently checked`는사용자작성또는독립사람검수를뜻하는것이아니다. 원문은보존하고이해석정정을적용한다. 실제서버관측·기관인증·전문가정답이라고부르지않는다. R2는현재추적생성기로원천256대화를재생성해소스SHA `b89ddbc86a40dd55743513a255f7d35e05adad701fca4468f347f3a5980fdeae`와바이트일치했다.
- 3개corpus×3split=9개로컬manifest/서버파일SHA와12개실행의데이터해시가모두연결됐다. 과거batch별sampler인덱스를기록하지않아개별step의행ID는완전복원했다고주장하지않는다. 새로운실험은원천ID/행SHA/정규화ID/분할·prefix매핑과샘플사용기록을보강해야한다.
- 평가 자료와후보는분리한다. ToolACE/APIGen/PRIMUS는위과거학습에없다. 외부benchmark·AIT holdout·기존test·직전20개품질문항을다음train으로편입하지않는다. Cisco Foundation-Sec은별도사전학습모델비교이며Qwen LoRA 원천이아니다.

재검사: `python3 -B finetuning/audit_training_provenance.py --run-inventory LOCAL_THOR_INVENTORY.json --output NEW_AUDIT.json`. 무결성/출처연결검사이며정확도인증이아니다. 원문·실행원장·행별증거는로컬/Thor에보존하고공개Git에는요약JSON/인용/검사코드를넣는다. BibTeX는논문서식에맞춰사용하되확인안한저자/발행연도/학회명을채우지않는다.


## 2026-10-29 학회·기관 근거 확인과 추가 자료 우선순위

사용자는 추가 학습량보다 출처와 검증 근거를 요구했다. 아래는 **학회 정식 게재 또는 기관 공식 발행을 직접 확인한 자료**다. 논문 게재는 방법과 실험의 학술적 근거이며, 모든 데이터 행의 무오류·우리 SOC 성능·기관의 프로젝트 인증을 뜻하지 않는다. 연구용 합성 데이터도 생성·검증 과정이 명확하면 활용할 수 있으나 실제 침해 사건의 전문가 판정과 구분한다. 과거 후보 목록 전체가 이 기준을 통과했다는 뜻은 아니다.

| 자료 | 직접 확인한 근거 | 제공자 생성·검증 방식 | 우리 업무에 쓸 범위 | 확보/라이선스 상태 |
|---|---|---|---|---|
| AIT Alert Data Set | AIT Austrian Institute of Technology 연구진의 [기관 배포·논문/DOI 목록](https://zenodo.org/records/8263181), CSET 2024 논문 | 실험 시나리오의 로그에서 Wazuh·Suricata·AMiner 경보를 생성. 정상행위의 오탐도 포함하며 labels는 공격 단계의 시간 구간 | 경보 사실 추출·상관분석·미확인 판단. 단계 라벨을 개별 경보의 악성 정답으로 바꾸지 않는다 | 기존 원본 zip/labels 보유·이번 공식 MD5 2/2 일치. Zenodo API CC-BY-4.0 확인. 우리 MCP 대화 변환은 별도 검수 대상 |
| ToolACE | 연구진의 [ICLR 2025 정식 논문](https://proceedings.iclr.cc/paper_files/paper/2025/hash/663865ea167425c6c562cb0b6bcf76c7-Abstract-Conference.html)과 [공식 데이터](https://huggingface.co/datasets/Team-ACE/ToolACE) | 합성 도구 대화, 규칙 검사와 모델 검사 결합. 공개 부분집합 11,300개 | 도구 선택·인자·관련 없는 도구 처리 보조. 보안 사건의 악성/정상 정답을 제공하는 자료는 아니다 | 기존 원본 보유·이번 공식 LFS SHA256 일치. Apache-2.0 카드 표기. 현행 R2 학습에 추가 편입하지 않음 |
| APIGen / xLAM-60k | Salesforce AI Research의 [NeurIPS 2024 Datasets and Benchmarks 논문](https://proceedings.neurips.cc/paper_files/paper/2024/hash/61cce86d180b1184949e58939c4f983d-Abstract-Datasets_and_Benchmarks_Track.html)과 [공식 60K 배포](https://huggingface.co/datasets/Salesforce/xlam-function-calling-60k) | 형식·실행·의미의 3단계 검증을 거친 합성 함수 호출 자료 | 도구/인자 선택 보조. 우리 승인·차단·IDS 대상 판단은 따로 검사 | CC-BY-4.0, 접근 조건 동의 필요. 이번 파일 다운로드/동의/원본 SHA 검증/학습은 미실행 |
| PRIMUS-Instruct | Trend Micro AI Lab의 [EMNLP 2025 정식 논문](https://aclanthology.org/2025.emnlp-main.527/)과 [원 제공자 카드](https://huggingface.co/datasets/trendmicro-ailab/Primus-Instruct) | 전문가가 구성한 보안 업무 질문과 GPT-4o 응답. 카드의 보안496+일반339=835개. 전문가가 모든 답변을 승인한 실관제 정답셋이라고 해석하지 않는다 | 경보 설명·조회 쿼리·의심 명령 분석 등의 보안 문장/근거 활용 | ODC-BY, 접근 시 정보 공유/동의 조건. 이번 접근 동의/본문 수집·SHA/행별 검수는 미실행. [Trend Cybertron 명의 카드](https://huggingface.co/datasets/trend-cybertron/Primus-Instruct/blob/main/README.md)도 확인 |
| MITRE ATT&CK | [MITRE 공식 지식베이스](https://attack.mitre.org/) | 실제 관측을 토대로 전술/기법을 정리 | 기법 정의·근거 문서. 도구 호출 대화나 개별 경보의 공격 성공 정답으로 간주하지 않는다 | 기존 보유 STIX/지식 원천 있음. 정확한 버전·원천 이용 조건을 보존하고 최신 웹 문서를 기존 로컬판과 동일하다고 표시하지 않는다 |
| NIST SP 800-61 Rev.3 | [NIST 공식 최종 문서](https://csrc.nist.gov/pubs/sp/800/61/r3/final), 2025-04 | 사고 대응·위험 관리 권고 문서 | 조사·대응·복구 절차의 설계 근거. 학습 대화 정답셋과 구분 | 이번 공식 서지/초록 확인. 문서 전체 조항을 전수 검토하거나 현행 시스템의 NIST 준수를 검증한 것은 아니다 |

### 인용 가능한 서지

- Landauer, M., Skopik, F., Wurzenberger, M. (2024). *Introducing a New Alert Data Set for Multi-Step Attack Analysis*. CSET 2024. 데이터 DOI `10.5281/zenodo.8263181`, 논문 DOI `10.1145/3675741.3675748`. 기관 배포 페이지가 논문을 직접 연결한다. ACM 본문은 이번 도구 접근403으로 전수 읽지 않았으며 데이터 설명/서지만 확인했다.
- Liu, W. et al. (2025). *ToolACE: Winning the Points of LLM Function Calling*. ICLR 2025. 공식 학회 논문 페이지와 공개 데이터 카드를 대조했다.
- Liu, Z. et al. (2024). *APIGen: Automated PIpeline for Generating Verifiable and Diverse Function-Calling Datasets*. NeurIPS 2024, Datasets and Benchmarks Track. 학회 표기 DOI `10.52202/079017-1725`.
- Yu, Y.-C., Chiang, T.-H., Tsai, C.-W., Huang, C.-M., Tsao, W.-K. (2025). *Primus: A Pioneering Collection of Open-Source Datasets for Cybersecurity LLM Training*. EMNLP 2025, pp.10391–10413. DOI `10.18653/v1/2025.emnlp-main.527`.
- Nelson, A., Rekhi, S., Souppaya, M., Scarfone, K. (2025). *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile*. NIST SP 800-61 Rev.3. 문서의 일반 권고를 우리 고정 승인/보호 정책의 구체적 의무라고 임의 인용하지 않는다.

서지와 원본 링크는 위 표에 연결했다. 이번은 서지·공식 배포·검증 방식 확인으로, 모든 논문의 본문/부록 재현이나 데이터 전수 전문가 감사를 완료한 것이 아니다.

### 실제로 이번에 확인한 것

- 로컬 ToolACE `data.json` 37,154,735바이트의 SHA256 `ba12c083fca7e8da48c67ad5b895e495447da7c66e39a2e19742c082e6cb537e`가 공식 HF 파일 메타데이터의 LFS oid와 일치했다. AIT zip MD5 `43db6b1f0996e0024befd617706c50e9`, labels MD5 `60ff33796c77fd2136c4d1a4bc841bd9`도 공식 배포와 일치했다. 이는 파일 동일성 확인이며 내용 정답성 인증이 아니다. 공식 MD5는 현대적 보안 서명이나 진본성 증명으로 확대하지 않는다.
- 현행 R2 train192개는 전부 `synthetic_lab_fixture` / `agent_reviewed`다. 실제 전문가 전수 검수/기관 인증 자료가 아니다. 각각1개 도구 정의132대화,2개 정의60대화이며 실제 호출은37종 중19종이다. 나머지18종의 호출 예시 부재를 다시 확인했다. 과거 공개 corpus18,872 train행이나 후보 원문 규모를 현행 R2 학습량에 더하지 않는다.
- [직전 품질 시험](QUALITY_RESULTS.md)은 새 합성20사례·에이전트 검수이며 독립 실무 정확도가 아니다. 같은 HF control84점 대비 학습본76점이라는 불리한 결과도 보존한다. 과제 생성기·관측 제공/단일 턴·소규모 평가 한계를 명시한다. 외부 논문 점수를 우리 모델 점수로 옮기지 않는다.
- 개인 계정의 한국어 공개 합성 자료도 후보지만 이번의 학회/기관 우선 선정과 구분한다. Ko-Agent-Trajectories 제작자 카드 자체에도 첫 호출/과잉 확인 질문 퇴행이 있어 전체 혼합을 우선하지 않는다. 우리 팀이 원문/실험/독립 검증을 끝낸 것으로 표시하지 않는다.

### 추가 학습을 위한 사용 순서와 아직 남은 검증

우선 보유 AIT+ToolACE를 실제 MCP 계약과 구분해 선별하고, 접근 조건을 충족한 PRIMUS/APIGen을 보조 후보로 검토한다. 보안 개념은 MITRE/NIST/장비 공식 문서에 근거하고, 현재 장비 상태·룰 내용·제안 ID는 실제 관측만 정답 근거로 사용한다. 장비 문서는 [Wazuh 공식 규칙 문법](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)처럼 버전과 원 규칙 정의를 확인하며 임의 CRS 소속/악성 판정을 만들지 않는다.

다음 학습 대화는 전체/유사 도구 간 대상 선택, 필수 조회 누락 방지, 관측된 ID만 사용, 오류·빈목록 구분, 파일 선언/엔진 적재 분리, 승인·실행·사후 검증 분리를 포함한다. R2 길이2048과 직전 전체37도구 입력최대8999토큰의 차이를 확인했으므로 전체 도구 학습을 단순 추가하지 않는다. 실제 토큰·메모리 적합성 검증 또는 학습/실행에 일관된 도구 선택 구성이 필요하며, 이것을 점수 하락의 확정 원인으로 주장하지 않는다.

각 편입 예제에는 출처/논문·revision·원본/변환 SHA·원문 위치·도구 계약 버전·선별/제외 이유·생성/변환 방법·검수 주체와 범위를 기록한다. 구조 검사는 객관적 계약 검사, 실제 도구 관측은 환경 확인, 전문가 검수는 의미/판단 확인으로 구분한다. 전문가 검수가 없으면 그대로 표시한다. 사건·환경·문장틀을 분리하고 기존20개 품질 문항 및 외부 벤치마크를 학습에서 제외한다. 개발셋으로 후보를 선택한 후 새 미사용 평가와 실제 MCP/승인/적용·원복 E2E를 확인해야 운영 품질 근거가 된다.

이번은 조사와 기존 파일 대조 완료이며 새 corpus/가중치 다운로드·학습·서버 변경·운영 승격은 없다. 로컬 검사 근거는 `대화기록/검증/2026-10-29-data-evidence/`에 남기고 Git에는 요약·인용 링크만 반영한다. 아래는 과거 시점의 수집·후보 이력으로 보존한다.

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
