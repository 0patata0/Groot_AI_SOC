# thor-05용 Qwen3.6-35B 학습 준비

2026-10-27: 코드·설정 준비와 로컬 검사 완료. **GPU 학습·학습된 모델·운영 배포는 아직 없다.** 기존 `config.json`의30B 실험과 정제 데이터·이전 압축파일은 보존했다.35B는 명시적으로 `--config config.qwen36-thor.json`을 선택한다.

## 현재 확인한 환경

14:24 KST SSH 읽기 점검: Linux aarch64, Ubuntu24.04, Python3.12.3, NVIDIA Thor SM110, driver595.78. 기본 Python의 torch/transformers/peft/accelerate는 미설치이며 PATH의 nvcc도 없다. 다른 컨테이너/사용자 환경까지 미설치라고 판단하지 않는다. 메모리 총약122.8GiB/가용78.65GiB, 디스크 여유약790.7GiB였고 Ollama `qwen3.6:35b`가약22GiB를 사용했다. 이 수치는 해당 시점 관측이다.

[공식 HF 모델](https://huggingface.co/Qwen/Qwen3.6-35B-A3B)의 revision `995ad96eacd98c81ed38be0c5b274b04031597b0`을 고정했다. 운영 Ollama의 GGUF 자체를 학습 입력으로 쓰지 않는다. 같은 모델 계열의 공식 원본 후보이며 운영 GGUF가 이 HF commit에서 변환됐다는 원본 이력까지 확인한 것은 아니다.

[해당 Transformers 구현](https://github.com/huggingface/transformers/blob/v5.4.0/src/transformers/models/qwen3_5_moe/modeling_qwen3_5_moe.py)에 맞춰 `Qwen3_5MoeForConditionalGeneration`을 사용한다.30B의 `AutoModelForCausalLM`만 그대로 쓰지 않는다. 언어 부분의 full attention40개와 DeltaNet projection150개를 실제 모듈 경로로 확인하고 LoRA를 붙인다. vision·MoE expert·base weight는 학습 대상에서 제외한다. 실제 모델 적재 시 예상 모듈 수나 학습 가능 파라미터 범위가 다르면 중단한다.

## 학습 방식과 환경 준비

35B 초안은 **BF16 LoRA**, 길이1024·micro batch1·gradient accumulation16·r16·학습률5e-5·non-thinking이다. fused MoE expert의 NF4 학습/메모리 호환을 검증하지 않았으므로 이 프로필은4비트 학습을 허용하지 않는다. k-bit 준비 함수가 동결 BF16 가중치를 FP32로 올리는 경로도 피한다. 기존30B NF4 경로는 유지한다.

35.5B 가중치만 BF16으로 약71GB이며 추가 활성값/학습 상태/OS 여유가 필요하다. **가용96GiB는 보수적인 작업 계획용 하한이며 실제 peak 메모리나 학습 성공 보장값이 아니다.** 현재 관측78.65GiB로는 이 하한을 충족하지 않는다. 공유 서버의 학습 시간대를 확보하고 운영 담당자가 자원을 조정한 뒤 새로 검사한다. 스크립트는 Ollama 종료·모델 unload·운영 설정 변경을 하지 않는다.

Thor SM110에서 실제 CUDA/BF16 forward/backward가 되는 NVIDIA 제공/검증 Python 환경을 먼저 선택한다. 일반 x86_64 CUDA wheel을 설치하는 기존 `setup_gpu.sh` 경로로 대체하지 않는다. [PyTorch CUDA13 지원 이슈](https://github.com/pytorch/pytorch/issues/159779)도 참고하되 버전명만으로 장치 호환을 판단하지 않는다. `setup_thor.sh`는 해당 연산을 먼저 검사한 후 별도 `.venv-qwen36-thor`에만 후보 라이브러리(transformers5.4.0/peft0.18.1/accelerate1.12.0)를 설치한다. 기존 torch 계열 버전을 constraints로 고정하고 `pip check`를 실행한다. 이 조합의 실제 GPU 통합 시험은 아직 없다.

대상 GPU 장비에서만:

```bash
cd finetuning
export CUDA_VISIBLE_DEVICES=0
# PYTHON_BIN에는 사전 검증한 Thor CUDA PyTorch Python을 지정한다.
bash setup_thor.sh
source .venv-qwen36-thor/bin/activate
python -B train.py --config config.qwen36-thor.json --preflight
python -B train.py --config config.qwen36-thor.json --check
```

기본 Python에는 torch가 없어 현재는 환경 준비 전 단계다. Mac에는 설치하지 않는다. 외부 다운로드가 불가능한 대상에서는 같은 플랫폼의 별도 승인 환경에서 의존성·원본 모델을 준비하고 반입해야 한다. 이 작업은 환경 설치·패키지 반입·원본 모델 다운로드를 수행하지 않았다. 완전한 로컬 HF 모델 폴더를 사용할 때는 별도 설정의 모델 경로와 `--offline`을 사용한다. 기존 모델명만 Ollama API 주소로 바꾸어 학습할 수는 없다.

사전 검사와 자원 확보 후에만 실행할2-step 예시:

```bash
python -B train.py --config config.qwen36-thor.json --train \
  --max-steps 2 --max-train-samples 32 --max-eval-samples 8 \
  --output-dir outputs/qwen36-smoke
```

`capacity_check`는 실제 GPU 메모리와 시스템 메모리 중 작은 가용값으로 평가한다. `--train`은 자원이 부족하면 모델 다운로드 전에 중단한다. 성공 후 peak 메모리·속도·토큰 제외 수·loss·어댑터를 검토하고 별도 출력 폴더로 본 학습을 진행한다. 자동 재개나 운영 전환은 없다. 빠른 DeltaNet 전용 커널을 추가하지 않았으며 기본 PyTorch 경로의 학습 성능도 미측정이다.

## 현재 MCP와 데이터의 관계

14:27 KST 기존 비특권 MCP 연결에서 **8서버37도구(읽기28/보호9)**의 `list_tools`만 조회해 `mcp_contract.json`에 이름·스키마·보호 여부를 저장했다. 모델 요청·MCP 기능 실행은0회다. 이는 시점이 있는 계약 스냅샷이며 향후 도구가 바뀌면 다시 수집·검수해야 한다. 자격·SSH 설정·토큰은 포함하지 않는다.

```bash
python3 -B audit_tools.py --data data/train.jsonl
```

실제 기존 train18,872행 중8,117행에 구조화 호출19,230개가 있었고 **현행 MCP의 전체 도구 이름과 일치한 호출은0개**였다. 이들은 공개 자료의 일반 함수다. 나머지10,755행에는 구조화 호출이 없다. 이를 현재 SOC 전용 학습셋으로 표시하거나 도구 이름만 기계적으로 치환하지 않는다. `--check` 성공은 파일 무결성·형식 검사이며 현행 MCP 학습 적합성 검수가 아니다.

현재 데이터는 일반 도구 호출/보안 언어 능력의 보조 자료로 보존한다. 현재 SOC에 맞춘 후속 자료에는 다음 근거가 필요하다.

- 실제 시점의37도구 스키마, user→assistant tool_calls→tool→assistant 연결, 호출/응답 ID·원문 해시와 출처.
- 짧은 질문의 장비 범위, 동적 이름→ID 확인, 기본/커스텀/엔진 적재 구분, KST·시각 미확인 처리.
- 조회 실패·누락·불확실성·승인 대기·적용/원복을 구분한 검수 답변. 이미 KST인 값의 재변환과 불필요한 호출을 줄이는 행동.
- 보호 호출은 스키마 통과만으로 승인됐다고 학습하지 않는다. 실제 승인 근거/TTL/보호 주소 조건과 실행 결과를 검수하고 비밀 값은 제거한다.
- 현재 IP·ID·상태를 고정 정답으로 외우게 하지 않는다. 잘못된 과거 봇 답변을 그대로 정답으로 채택하지 않는다. 사건/스레드 단위 분할과 별도 미사용 SOC 평가셋을 유지한다.

`audit_tools.py`는 이름·지원 가능한 JSON Schema 인자만 검사하며 미지원 제약·잘못된 인자는 확인 완료로 표시하지 않는다. 판단 정확성·승인 적합성·자료의 모든 민감정보 검수를 대신하지 않는다. 검수된 SOC trajectory를 자동 수집/합성하거나 train/test에 합치지는 않았다.

## 병합·이관·평가

학습 뒤 `merge_adapter.py`는 run manifest에 기록된 같은 모델 종류/정확 revision을 사용한다. 결과는 HF 모델 폴더이고 GGUF 변환·양자화·Ollama 등록·봇 전환은 별도다. 이번 범위는 텍스트 SOC 학습이며 비전 입력 학습/프로세서 내보내기까지 검증한 것이 아니다.

```bash
python3 -B pack.py --config config.qwen36-thor.json \
  --output bundles/soc-finetuning-qwen36-thor.tar.gz
```

이 명령은 두 프로필·데이터·새 로더/검사·MCP 계약·문서를 함께 묶는다. 압축을 푼 뒤35B 학습에는 계속 `--config config.qwen36-thor.json`을 명시한다. 기본 `config.json`은30B를 유지한다. 이전 압축파일은 덮어쓰지 않는다. 이 작업에서는 묶음을 임시 경로에서 검사 후 제거했으며 기존 사용자 압축파일은 보존한다. Git clone에는 학습 데이터가 포함되지 않는다.

비교는 같은35B 미튜닝/튜닝본을 기본으로 하고 동일 추론 엔진·양자화·thinking·워밍업/부하·하네스로 맞춘다. 기존 `evaluate.py`는 명시한 OpenAI 호환 API로 마지막 assistant1턴을 재생하고 MCP를 실행하지 않는다. 서버가 Qwen tool-call을 구조화 `tool_calls`로 반환하도록 준비해야 한다. 일반 test932행과 별도 SOC 미사용 평가셋을 구분하고, 누락·대상 오류·허위 적용·승인 위반은 별도 감점한다. 실제 조사/쓰기 E2E·TTFT·생성속도는 이 평가의 측정 범위가 아니다.

## 이번 검증 범위

61개 표준 라이브러리 검사 통과, 두 설정의 데이터/행 수·SHA 검사, shell 구문·Mac 설치 거절 검사, 실서버 Jinja로 공식35B 서식의3가지 대화 prefix/문자 마스킹 경계 확인. Jinja 검사는 실제 토크나이저 ID/모델 적재/학습 검사가 아니다. GPU 패키지 통합·원본 모델 다운로드·2-step 학습·병합/실모델 비교·운영 반영은 미실행이다. [최신 현황](../STATUS.md).
