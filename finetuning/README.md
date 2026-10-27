# SOC 모델 파인튜닝 준비 폴더

> **10/27 19:31 SOC 학습 후속:** Thor 저장 루트를 `~/Capstone_Groot_training/qwen36-20261027`로 변경하고 원본·기존 결과를 보존했다. 현37도구에 맞춘212대화(144/32/36)·전체 prefix224/44/52 토큰 검사를 완료했으며, 자동복구를 갖춘2-step+8-step 제한 시험과 Cisco8B GGUF 비교 준비를 진행 중이다. 본 전체 학습·학습 모델 등록/운영 교체·정확도 우위는 미완료다. [현재 상태](../STATUS.md) · [새 경로·단계](THOR_35B.md).


> **10/27 추가 학습자료 조사:** 한국어 도구 호출·보안 업무자료와보안특화8B·동일35B파생가중치14후보를검토했다. 우선순위는보유SOC경보/실제요청검수→방어과제→소량한국어보조이며평가원천·중복·과잉질문회귀를구분한다. 반입/학습/운영모델변경은미실행이다. [후보·선별근거](DATA_SOURCES.md) · [현재현황](../STATUS.md).

> **10/27 18:00 학습 재개 결과:** CPU 파일 참조 누적으로 발생한35B 적재 메모리 문제를 보완해 실제2-step·평가·어댑터 저장까지 완료했다. 380텐서 finite/190 B행렬 갱신,78검사 통과. 추론은약2분56초만에 원래35B로 복구했다. 본 학습·변환/등록·운영 교체·SOC 정확도 비교는 미실행이며,현SOC 자료 보완과 장기 학습 시간대 결정이 남는다. 아래 정지/0step은 당시 이력이다. [상세 현황](../STATUS.md) · [적재 보완](THOR_35B.md).

> **2026-10-27 16:23 사용자 요청으로 일시정지:** 원본39파일 전체 체크섬·실토큰 검사 완료, 실제35B 적재 중 global OOM으로0/2step 종료. 추론은약81초만에 복구됐고 자동 대기 작업/timer는 종료됐다. 학습된 어댑터는 없으며 로더 메모리 peak 원인 분석/수정에서 재개한다. [현재 상태](../STATUS.md).

> **2026-10-27 실행 준비 진행:** Thor 기존 NGC25.08/별도 venv에서 패키지 검사·축소40층 LoRA GPU 역전파를 통과했다.71검사 통과. 전체35B 원본 다운로드 중/실토큰 검사 완료이며 메모리 확보 후2-step/본 학습을 진행한다. 전체35B 학습·학습 모델·운영 전환은 아직 없다. [Thor 실행 절차](THOR_35B.md) · [최신 상태](../STATUS.md). 아래 설치/반입 미실행은 과거 시점이다.

> **2026-10-27 현재35B/thor용 준비 추가:** [THOR_35B.md](THOR_35B.md)에 별도 BF16 LoRA 설정·전용 로더/자원 검사·설치 경로·현행 MCP 계약/자료 검사를 추가했다. 기존30B 기본 설정과 데이터는 보존하며35B는 `--config config.qwen36-thor.json`으로 선택한다.61검사 통과, 실제 GPU 학습은 미실행이다. 아래30B 준비 완료가35B 학습 완료를 뜻하지 않는다.

> **2026-10-27 로컬 재확인:** `data/`의 train18,872/validation980/test932행과 manifest SHA가 모두 일치한다. 학습·병합·평가 코드와 기존 `bundles/soc-finetuning.tar.gz`가 남아 있다. 설정은 여전히 `Qwen/Qwen3-30B-A3B`이며 현재 thor-05 운영 `qwen3.6:35b`와 다른 후보다. 이 폴더에 학습된 어댑터/가중치는 없다. 현재 MCP37도구/8서버에 맞춘 SOC trajectory 검수·대상 GPU 학습 호환 검사는 별도이며, SSH 연결·추론 성공을 학습 완료로 해석하지 않는다. 이번 확인에서 설치·다운로드·업로드·학습은 하지 않았다. [현재 상태](../STATUS.md).

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 기존30B LoRA 준비 데이터는 train18,872/validation980/test932개이며10/24 로컬 행 수·SHA 대조가 일치했다. 운영35B와 다른 후보이고 GPU 학습/실모델 비교는 아직 없다. 공개 corpus·지식·독립 평가·우리 SOC 검수 trajectory의 역할을 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

이 폴더를 충분한 메모리의 **Linux NVIDIA GPU 학습 장비**로 옮겨 실행한다. 로컬 Mac에서는 데이터 정제·코드 검증만 했으며 모델 다운로드·패키지 설치·학습·서버 업로드는 하지 않았다. 실제 GPU 학습과 병합은 대상 장비에서 아직 검증해야 한다.

기본 베이스는 **`Qwen/Qwen3-30B-A3B`**다. 총 30.5B·활성 3.3B인 공식 Qwen3 모델을 30B 후보의 준비용 기본값으로 골랐다. 현재 운영 중인 **`qwen3.6:35b`와 다른 모델**이다. 사용자가 정확한 30B 저장소명을 지정한 것은 아니므로 다른 후보를 쓰려면 `config.json`의 모델·revision과 LoRA 대상 모듈·템플릿 호환성을 함께 확인한다. 모델 이름만 바꾸면 모든 아키텍처가 지원된다고 보장하지 않는다.

**2026-10-08 실제 준비 결과:** 입력 120,917행에서 정제·소스별 상한을 적용해 20,784행을 선택했다. train 18,872 / validation 980 / test 932이며, 분할 사이 동일한 첫 사용자 질문 중복은 0이다. Hermes FC·Glaive·SEVENLLM·AttackLM 각 5,000행, Hermes traces 784행이다. 이는 토크나이저를 적용하기 전 수량이다.

## 포함 내용

| 파일 | 역할 |
|---|---|
| `data/train.jsonl`, `validation.jsonl`, `test.jsonl` | 기존 `datasets/`에서 정제·분할한 실제 데이터. Git에서는 제외 |
| `data/manifest.json`, `preparation_summary.json` | 입력/출력 SHA256, 출처별 개수, 제외 이유, 분할 정책. 후자는 Git 추적용 사본 |
| `prepare_data.py` | 표준 라이브러리만 쓰는 데이터 재생성기 |
| `config.json` | 베이스 모델·길이·학습률·LoRA 등 설정 |
| `setup_gpu.sh`, `requirements.txt` | 대상 Linux GPU 장비의 전용 가상환경 설치 |
| `train.py` | 데이터 검사, GPU 사전 검사, 명시적 학습 실행 |
| `merge_adapter.py` | 학습 완료 어댑터를 원본과 병합해 전체 모델 저장 |
| `evaluate.py` | 준비된 추론 API에서 같은 평가 입력을 재생하는 비교 도구 |
| `pack.py` | 코드·정제 데이터만 넣는 이관용 압축 파일 생성 |
| `DATA_SOURCES.md`, `tests/` | 출처·데이터 사용 범위와 로컬 검증 테스트 |

## 1. 이관하기

작업 폴더에 있는 `finetuning/` 전체를 복사하면 정제 데이터도 함께 이동한다. **Git clone만으로는 `data/`가 전달되지 않는다.** 가중치·환경·캐시를 제외한 묶음이 필요하면 프로젝트 루트에서:

```bash
python3 -B finetuning/pack.py
# finetuning/bundles/soc-finetuning.tar.gz 생성; 기존 파일은 덮어쓰지 않음
```

대상 학습 장비에서 압축을 풀고 `finetuning/`으로 이동한다. 이미 만들어진 `data/`로 학습할 때는 원본 `datasets/`를 다시 옮길 필요가 없다. 데이터를 **재생성**하려면 원본의 지정된 5개 파일과 평가 중복 차단용 파일들도 필요하다.

## 2. 대상 장비 환경 준비

Python 3.10~3.12(권장 3.11), NVIDIA CUDA GPU **1개**, 해당 PyTorch와 호환되는 드라이버를 사용한다. 기본 설정은 길이 2,048·마이크로 배치 1의 NF4 4비트 LoRA다. 준비 장비는 **GPU 메모리 48GB 이상을 보수적인 출발점**으로 고려하되 실행 보장값은 아니다. 30B MoE의 비양자화 층·활성값·학습 상태가 추가되므로 아래 소규모 실행으로 최대 메모리를 확인한다. 다중 GPU 분산 학습은 별도 설정이 필요하다.

일반 Linux x86_64:

```bash
cd finetuning
export CUDA_VISIBLE_DEVICES=0
bash setup_gpu.sh
source .venv/bin/activate
python -B train.py --check
```

설치 스크립트는 macOS에서 즉시 종료한다. Linux에서는 이 폴더 아래 `.venv/`, `.cache/`를 사용한다. PyTorch 2.8.0/cu128과 고정한 Transformers·PEFT·Accelerate·bitsandbytes를 설치하고 `pip check`, CUDA/NF4 커널 검사를 수행한다. 사전 검사 자체는 모델을 내려받거나 학습하지 않는다. 패키지 배포 메타데이터는 확인했지만 이 조합을 실제 GPU에서 통합 검증한 것은 아니다.

**ARM64·DGX Spark**는 제조사가 제공하는 CUDA PyTorch 환경을 먼저 준비하고 다음 경로를 사용한다. 기존 환경에 다른 패키지 충돌이 있거나 bitsandbytes 커널이 지원되지 않으면 사전 검사에서 멈춘다. 128GB 통합 메모리를 일반 GPU의 전용 VRAM과 동일하게 계산하지 않는다.

```bash
export CUDA_VISIBLE_DEVICES=0
bash setup_gpu.sh --use-system-torch
source .venv/bin/activate
python -B train.py --preflight
python -B train.py --check
```

두 설치 경로 모두 인터넷이 필요하다. 외부망이 없는 학습 장비에서는 동일 플랫폼의 승인된 경로로 wheel·원본 모델을 반입한 다음 전용 환경을 구성한다. `config.json`의 `model_name_or_path`를 **완전한 로컬 모델 폴더**로 바꾸고 `--offline`을 사용하면 Hugging Face 다운로드를 시도하지 않는다. 이번 준비 작업에는 이러한 반입·서버 업로드가 포함되지 않는다.

## 3. 먼저 2-step 실행, 이후 본 학습

아래부터 실제 모델 다운로드와 GPU 학습이 발생한다. **대상 학습 장비에서만 실행한다.** 기본 모델 캐시도 `.cache/huggingface/`에 둔다. 여유 디스크는 원본 가중치·다운로드 캐시·체크포인트·선택적 병합본까지 고려한다.

```bash
python -B train.py --train \
  --max-steps 2 --max-train-samples 32 --max-eval-samples 8 \
  --output-dir outputs/smoke

# 소규모 실행이 성공한 뒤, 새 출력 폴더로 본 학습
python -B train.py --train
```

`config.json` 기본값: 1 epoch, 길이 2,048, 배치 1 × gradient accumulation 16, learning rate 1e-4, LoRA r=16/alpha=32/dropout=0.05. LoRA 대상은 attention의 `q_proj/k_proj/v_proj/o_proj`다. MoE expert를 포함한 모든 선형층을 튜닝하는 설정은 아니다. 별도 속도/정확도 실측 후 조정한다.

원본 대화의 **각 assistant 턴까지의 이력을 개별 예제로 펼친다.** 각 예제에서는 마지막 assistant만 loss에 포함하고 앞선 user·system·tool·assistant 이력과 padding을 마스킹한다. 이렇게 대화 중간의 도구 호출과 도구 결과를 읽은 답변도 학습한다. 분할은 확장 전에 원본 질문 그룹별로 고정하므로 같은 대화의 턴이 train과 test에 흩어지지 않는다. 원본의 명시적 think 블록을 제거하고 non-thinking 템플릿을 사용한다. 긴 예시는 잘라서 툴 대화를 손상시키지 않고 통째로 제외하며, 정확한 토큰 길이/제외 개수는 대상 장비의 `tokenization_report.json`에 남긴다. 지금 준비된 원본 행 수가 최종 학습 예제 수와 같다고 가정하지 않는다. `max_train_samples`/`max_eval_samples`는 확장·길이 검사 후 채택한 예제 수를 제한한다.

출력 폴더가 이미 차 있으면 중단한다. 실패한 실행도 보고서를 남길 수 있으므로 재시도에는 새 `--output-dir`를 지정한다. 현재 스크립트는 자동 재개를 지원하지 않는다. `run_manifest.json`에는 데이터 해시·실제 베이스 revision·설정·패키지 버전·장비 정보를 저장한다. `revision: main`은 학습 시점에 해석되므로 반복 실험은 기록된 commit으로 고정한다.

## 4. 학습 결과는 어떤 파일인가?

기본 산출물은 전체 모델이 아닌 **LoRA 어댑터 폴더**다.

```text
outputs/qwen3-30b-soc-lora/
├── run_manifest.json
├── tokenization_report.json
├── train_results.json / eval_results.json
└── adapter/
    ├── adapter_model.safetensors   # 학습된 변경 가중치
    ├── adapter_config.json
    └── tokenizer 관련 파일
```

어댑터만으로는 독립 실행할 수 없다. **학습 때 사용한 동일한 원본 모델 + 어댑터**가 필요하다. 나중에 교수님께 전달할 때 어댑터·run_manifest·평가 결과와 정확한 원본 모델명/revision을 함께 보관한다.

원본과 합친 전체 모델 폴더가 필요하면 충분한 CPU RAM 또는 GPU 메모리의 장비에서:

```bash
python -B merge_adapter.py --check \
  --adapter outputs/qwen3-30b-soc-lora/adapter

python -B merge_adapter.py --merge \
  --adapter outputs/qwen3-30b-soc-lora/adapter \
  --output outputs/qwen3-30b-soc-merged
```

기본 병합은 CPU·BF16이며, 30.5B 가중치만 약 61GB(10진)이고 병합 작업용 메모리가 추가된다. 4비트 학습이 가능했던 장비에서 전체 BF16 병합도 된다고 가정하지 않는다. GPU에 충분한 메모리가 있으면 `--device cuda:0`, 필요하면 `--offline`을 지정한다. 병합은 원본 비양자화 체크포인트를 다시 로드한다.

결과는 `model-00001-of-....safetensors` 등 여러 가중치 조각, 인덱스, `config.json`, 토크나이저를 포함한 Hugging Face 모델 폴더다. 한 파일만 보내는 형태가 아니다. Ollama용 GGUF 변환·양자화·등록·운영 서버 업로드는 이번 범위 밖이며 아직 수행하지 않았다.

## 5. 현 35B와 비교하기

후보 학습과 추론 서버 준비가 끝난 뒤, **같은 `data/test.jsonl`**을 각 모델에 사용한다. 엔드포인트의 실제 모델 ID를 넣는다. 스크립트가 모델 서버를 설치하거나 시작하지는 않는다.

```bash
python -B evaluate.py --data data/test.jsonl \
  --base-url http://127.0.0.1:8000/v1 --model SERVED_MODEL_ID \
  --output outputs/eval-30b-tuned --limit 200 --seed 42 \
  --temperature 0 --max-tokens 512
```

35B와 미튜닝 30B도 각각 새로운 출력 폴더로 같은 명령을 실행한다. 세 모델을 비교하면 모델 크기/계열 차이와 튜닝 효과를 구분하는 데 도움이 된다. 인증은 필요할 때 `OPENAI_API_KEY` 환경변수로 전달한다. 토큰을 명령행 옵션이나 설정 파일에 넣지 않는다. 필요한 경우 `--request-extra-json`으로 해당 추론 서버가 지원하는 thinking 설정 등을 동일하게 맞춘다. 예를 들어 vLLM의 지원 버전에서는 `{"chat_template_kwargs":{"enable_thinking":false}}`를 별도 JSON 파일로 지정할 수 있다.

이 평가는 앞선 도구 응답을 고정한 **원본 대화의 마지막 assistant 한 턴 재생**이다. 실제 MCP 도구를 실행하지 않는다. `metrics.json`의 도구명/인자 정확 일치·일부 JSON Schema 검사·응답 완료 지연 p50/p95와 `details.jsonl`의 실제 응답을 검토한다. 현재 test 932행 중 마지막 턴이 도구 호출인 것은 32행뿐이며 `--limit 200` 표본에는 더 적게 포함될 수 있다. 도구 호출 성능을 판단하려면 별도의 충분한 SOC 평가셋이 필요하다. TTFT는 스트리밍하지 않아 **미측정(null)**이며, 생성 tokens/sec도 측정하지 않는다. 텍스트 완전 일치는 진단용으로만 제시한다. 이것을 한국어 SOC 판단 정확도나 Hermes 전체 조사 시간으로 보고하면 안 된다.

하드웨어·추론 엔진·양자화·입력 길이·출력 제한·thinking·모델 상주/워밍업 조건을 맞추고 별도로 기록한다. 현재 MCP의 승인 준수·근거 정확성·조사 완결성은 검수된 SOC 시나리오와 별도 E2E 평가가 필요하다. 이번에는 실모델 평가 요청을 보내지 않았고 성능 우열도 결론 내리지 않았다.

## 6. 데이터 재생성과 로컬 검증

기본값은 허용된 소스마다 최대 5,000개를 결정적으로 선택하는 첫 실험용 구성이다. 모든 허용 행을 사용하려면 0으로 바꾸고 새 출력 폴더를 지정한다.

```bash
# 프로젝트 루트에서; 모델/패키지 필요 없음
python3 -B finetuning/prepare_data.py \
  --datasets-dir datasets --output-dir finetuning/data-full --max-per-source 0

# 이후 config.json의 data_dir도 data-full로 수정해야 함
python3 -B -m unittest discover -s finetuning/tests -v
python3 -B finetuning/train.py --check
```

같은 첫 사용자 질문은 소스가 달라도 같은 split에 묶는다. 평가 전용 파일과 SEVENLLM 원본 test의 동일 질문은 제외한다. 이는 공백 정규화한 질문의 일치 검사이며, 의미가 유사한 질문이나 실제 공격 시나리오 단위 누출까지 제거했다는 보장은 아니다. 공개 자료의 일반 도구명을 현재 MCP 이름으로 무조건 치환하지 않았다. 우리 SOC 전용 데이터로 만들려면 실제 스키마와 검수한 trajectory가 추가로 필요하다. 자세한 출처·제외 범위는 [DATA_SOURCES.md](DATA_SOURCES.md), 수량은 [preparation_summary.json](preparation_summary.json)을 따른다.

참고: [Qwen 공식 모델 카드](https://huggingface.co/Qwen/Qwen3-30B-A3B), [PEFT 양자화 학습](https://huggingface.co/docs/peft/developer_guides/quantization), [PEFT 체크포인트](https://huggingface.co/docs/peft/developer_guides/checkpoint), [QLoRA 논문](https://arxiv.org/abs/2305.14314).
