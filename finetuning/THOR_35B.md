# thor-05용 Qwen3.6-35B 학습

2026-10-27: 사용자 지시로 학습 실행 준비에 착수했다. **격리 환경 설치·실제 GPU 축소 구조 검증 완료, 전체35B 원본 다운로드 중·데이터 토큰화 완료. 전체 모델 학습·운영 배포는 아직 없다.** 기존 `config.json`의30B 실험과 정제 데이터·이전 압축파일은 보존했다.35B는 명시적으로 `--config config.qwen36-thor.json`을 선택한다.

## 현재 확인한 환경

14:24 KST SSH 읽기 점검: Linux aarch64, Ubuntu24.04, Python3.12.3, NVIDIA Thor SM110, driver595.78. 기본 Python의 torch/transformers/peft/accelerate는 미설치이며 PATH의 nvcc도 없다. 다른 컨테이너/사용자 환경까지 미설치라고 판단하지 않는다. 메모리 총약122.8GiB/가용78.65GiB, 디스크 여유약790.7GiB였고 Ollama `qwen3.6:35b`가약22GiB를 사용했다. 이 수치는 해당 시점 관측이다.

[공식 HF 모델](https://huggingface.co/Qwen/Qwen3.6-35B-A3B)의 revision `995ad96eacd98c81ed38be0c5b274b04031597b0`을 고정했다. 운영 Ollama의 GGUF 자체를 학습 입력으로 쓰지 않는다. 같은 모델 계열의 공식 원본 후보이며 운영 GGUF가 이 HF commit에서 변환됐다는 원본 이력까지 확인한 것은 아니다.

[해당 Transformers 구현](https://github.com/huggingface/transformers/blob/v5.4.0/src/transformers/models/qwen3_5_moe/modeling_qwen3_5_moe.py)에 맞춰 `Qwen3_5MoeForConditionalGeneration`을 사용한다.30B의 `AutoModelForCausalLM`만 그대로 쓰지 않는다. 언어 부분의 full attention40개와 DeltaNet projection150개를 실제 모듈 경로로 확인하고 LoRA를 붙인다. vision·MoE expert·base weight는 학습 대상에서 제외한다. 실제 모델 적재 시 예상 모듈 수나 학습 가능 파라미터 범위가 다르면 중단한다.

## 학습 방식과 환경 준비

35B 초안은 **BF16 LoRA**, 길이1024·micro batch1·gradient accumulation16·r16·학습률5e-5·non-thinking이다. fused MoE expert의 NF4 학습/메모리 호환을 검증하지 않았으므로 이 프로필은4비트 학습을 허용하지 않는다. k-bit 준비 함수가 동결 BF16 가중치를 FP32로 올리는 경로도 피한다. 기존30B NF4 경로는 유지한다.

35.5B 가중치만 BF16으로 약71GB이며 추가 활성값/학습 상태/OS 여유가 필요하다. **가용96GiB는 보수적인 작업 계획용 하한이며 실제 peak 메모리나 학습 성공 보장값이 아니다.** 현재 관측78.65GiB로는 이 하한을 충족하지 않는다. 공유 서버의 학습 시간대를 확보하고 운영 담당자가 자원을 조정한 뒤 새로 검사한다. 스크립트는 Ollama 종료·모델 unload·운영 설정 변경을 하지 않는다.

Thor SM110에서 실제 CUDA/BF16 forward/backward가 되는 NVIDIA 제공/검증 Python 환경을 먼저 선택한다. 일반 x86_64 CUDA wheel을 설치하는 기존 `setup_gpu.sh` 경로로 대체하지 않는다. [PyTorch CUDA13 지원 이슈](https://github.com/pytorch/pytorch/issues/159779)도 참고하되 버전명만으로 장치 호환을 판단하지 않는다. `setup_thor.sh`는 해당 연산을 먼저 검사한 후 별도 `.venv-qwen36-thor`에만 후보 라이브러리(transformers5.4.0/peft0.18.1/accelerate1.12.0)를 설치한다. 기존 torch 계열 버전을 constraints로 고정하고 `pip check`를 실행한다. 이 조합은 아래 기존 NGC 컨테이너에서 패키지 검사·BF16 행렬과 축소 모델 구조 역전파까지 확인했다. 전체35B peak 메모리/학습 성능 검증은 별도다.

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

기본 Python에는 torch를 설치하지 않고 기존 NGC 컨테이너 안의 별도 venv를 사용했다. Mac에는 설치하지 않는다. 외부 다운로드가 불가능한 대상에서는 같은 플랫폼의 별도 승인 환경에서 의존성·원본 모델을 준비하고 반입해야 한다. 현재 환경 설치는 완료했고 원본 모델은 Thor에서 직접 다운로드 중이다. 폐쇄망 SOC A/B/C에 인터넷 패키지를 설치한 작업이 아니다. 완전한 로컬 HF 모델 폴더를 사용할 때는 별도 설정의 모델 경로와 `--offline`을 사용한다. 기존 모델명만 Ollama API 주소로 바꾸어 학습할 수는 없다.

사전 검사와 자원 확보 후에만 실행할2-step 예시:

```bash
python -B train.py --config config.qwen36-thor.json --train \
  --max-steps 2 --max-train-samples 32 --max-eval-samples 8 \
  --output-dir outputs/qwen36-smoke
```

Thor의 `capacity_check`는 `MemAvailable`과 컨테이너 cgroup 잔여 한도의 작은 값을 사용한다. CUDA raw free는 회수 가능한 CPU 페이지 캐시를 반영하지 않으므로 별도 기록한다. 일반 discrete GPU는 기존 system/CUDA/cgroup 최소값을 사용한다. 이 예산은 할당 성공 보장이 아니며 OS 전역 캐시를 강제로 지우지 않는다. [NVIDIA UMA 메모리 설명](https://nvidia.custhelp.com/app/answers/detail/a_id/5728) · [Tegra 메모리 구조](https://docs.nvidia.com/cuda/cuda-for-tegra-appnote/). `--train`은 자원이 부족하면 모델 다운로드 전에 중단한다. 성공 후 peak 메모리·속도·토큰 제외 수·loss·어댑터를 검토하고 별도 출력 폴더로 본 학습을 진행한다. 자동 재개나 운영 전환은 없다. 빠른 DeltaNet 전용 커널을 추가하지 않았으며 기본 PyTorch 경로의 학습 성능도 미측정이다.

## 현재 사용하는 격리 컨테이너 경로

기존 `nvcr.io/nvidia/pytorch:25.08-py3` arm64 이미지를 새로 받지 않고 digest `sha256:ace9a848c0ae543317e3c4763b6b4248961c47902625abfe3c77a0fb931c50fb`로 고정했다. [NVIDIA 25.08 설명](https://docs.nvidia.com/deeplearning/frameworks/pytorch-release-notes/rel-25-08.html). 관측 버전은 torch2.8.0a0+34c6371d24.nv25.8/CUDA13.0이다. `prepare`는 이미지의 torch 계열 버전을 constraints로 유지하면서 `/workspace/venv`만 변경하며 base Python·이미지는 보존한다. `install-report.json`에는 내려받은 패키지 버전·출처·해시가 남는다.

이 PyTorch의 `grouped_mm`는 SM90만 지원해 Thor SM110에서 실제 실패했다.35B 설정/학습·병합 로더에 `experts_implementation="eager"`를 명시한다. 축소 랜덤40층 구조에서 full attention40/DeltaNet150·LoRA gradient380개·finite loss/gradient·optimizer 갱신을 확인했다. 이는 전체35B의 정확도/성능 검증이 아니다. DeltaNet은 추가 커널 없는 PyTorch 경로를 사용한다.

학습 작업 폴더는 `~/capstone-training/qwen36-20261027`이며 소스/데이터·venv·base·manifest·stage log/status·outputs를 보존한다. 아래 명령은 Thor에서만 실행한다. 이미 완료/실행 중인 단계를 중복 실행하면 거절한다.

```bash
training_root="$HOME/capstone-training/qwen36-20261027"
python3 -B "$training_root/finetuning/thor_container.py" prepare --root "$training_root"
python3 -B "$training_root/finetuning/thor_container.py" download --root "$training_root"
python3 -B "$training_root/finetuning/thor_container.py" tokenize --root "$training_root"
# 다운로드/전체 checksum/토큰화 완료 및 메모리 확보 후:
python3 -B "$training_root/finetuning/thor_container.py" smoke --root "$training_root"
# 2-step 실제 결과와 소요시간/peak/손실/어댑터를 검토한 후:
python3 -B "$training_root/finetuning/thor_container.py" train --root "$training_root"
```

- 호스트 현재 UID, cap-drop ALL, no-new-privileges, 포트 공개0, 작업 폴더1개만 mount. 준비/다운로드는 network bridge, 토큰화/학습은 network none. CPU 전용 다운로드·토큰화에는 GPU를 노출하지 않는다.
- 준비/다운로드/토큰화는 CPU4·RAM12GiB, 학습은 CPU10·RAM112GiB, swap 추가 허용0. 상한은 자원을 예약하지 않으며 GPU 메모리를 다른 작업과 완전히 격리하지 않는다.
- `download_model.py`는 공개 HF 고정 commit의 메타데이터부터 받고 총71,926,864,255B 대상 파일의 크기와 LFS SHA256/Git blob hash를 검증한다. 각 단계는 durable container로 실행되어 SSH가 끊겨도 계속되며 KST status/log를 남긴다.
- `tokenize`는 검증된 메타데이터만으로 train/validation/test 전체 prefix·마스킹 경계·초과 길이 제외 수를 확인한다. 다운로드와 CPU 검사만 병행할 수 있다. 실제 가중치 학습에는 완료된 다운로드/검증/토큰화가 필요하며 본 학습에는 성공한 smoke가 추가로 필요하다.
- `smoke`는 accumulation1·2 optimizer step, train32/eval8 prefix 상한이다. 본 학습의 accumulation16과 다르므로 이 속도를 본 학습 전체 시간으로 그대로 환산하지 않는다. `train`은 원설정1epoch·전체 허용 prefix를 사용하고 별도 output에 어댑터를 저장한다. `progress.json`에 KST·step·예상 잔여시간·CUDA peak를 남기며 평가/저장까지 성공해야 completed다. 실패한 output·status를 자동 삭제하거나 학습을 자동 재실행하지 않는다.
- 현재 Ollama와 자원이 겹쳐96GiB 하한에 못 미친다. 단계 launcher는 추론 중지/재개를 하지 않는다. 이번에는 사용자가30분 이내2-step 시험/복구를 별도로 승인해, 다운로드·검증/소스SHA/다른GPU작업 부재를 확인하는 일회성 supervisor를 등록했다. 실제 중지 전에25분 호스트 복구 timer를 설정하고 시험 완료/실패 시 즉시복구한다. 본 학습 중 장시간 중단은 별도 시간대 결정이 필요하다. 학습 시간대·자원 확보 후 재검사하며 운영 모델/GGUF를 자동 교체하지 않는다.

오프라인 별도 학습 장비에는 같은 arm64 NGC 이미지와 digest 확인, 해당 이미지/플랫폼용 의존성 wheel과 `install-report.json`의 버전·SHA, 고정 HF snapshot/`base-manifest.json`, 명시적 `pack.py` 소스/데이터 묶음이 필요하다. 이번에는 기존 이미지와 Thor 직접 다운로드를 사용했으며 폐쇄망 신규 학습 환경 전체 반입/설치는 미검증이다. SOC 초기 설치 진입점은 계속 루트 `deploy.sh` 하나다. 학습 실행은 기존 외부 추론 장비의 별도 실험이며 SOC 초기 설치가 모델 학습을 자동 실행하지 않는다.

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

이전 준비 단계61개 표준 라이브러리 검사 통과, 두 설정의 데이터/행 수·SHA 검사, shell 구문·Mac 설치 거절 검사, 실서버 Jinja로 공식35B 서식의3가지 대화 prefix/문자 마스킹 경계 확인. Jinja 검사는 실제 토크나이저 ID/모델 적재/학습 검사가 아니다. 후속 실행 단계에서 GPU 환경/패키지 검사·축소 구조 LoRA 역전파를 확인했고 전체 원본 다운로드/실토큰 검사를 진행 중이다. 전체35B 적재·2-step/본 학습·병합/실모델 비교·운영 반영은 미실행이다. [최신 현황](../STATUS.md).

2026-10-27 15:13:56 실토큰 전분할 검사: train44,774 prefix 중35,253개, validation2,793중1,583개, test2,264중1,546개 허용. 길이초과 제외는 각각9,521/1,210/718개이며 prefix 정렬 오류0이다. 로컬/Thor71검사 통과. 추가 축소 랜덤 모델의 실제 Trainer2step·평가·어댑터 저장 통합 검증까지 성공했고 임시 랜덤 가중치는 제거했다. 전체35B 결과는 [STATUS](../STATUS.md)를 따른다.
