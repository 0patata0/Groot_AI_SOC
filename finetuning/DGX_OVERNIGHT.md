# DGX 독립 학습 실행 — 2026-11-01

> **11/1 15:52 후속:** 새자료8,695건의 GPU 준비 시험(2step·4microbatch·validation8) 완료 후 사용자 지시로 본학습/공유추론종료후 자동재개를 등록했습니다. 전체11/2 03:47KST·32시도 상한,4step저장·최신 완전checkpoint 재개이며 현재 모델 적재 중입니다. [실행 설정](OPERATOR_TRAINING_RUN_20261101.json) · [운용](OPERATOR_PREPARATION.md) · [현황](../STATUS.md).

> **10:48 KST 완료 확인:** 447건/1epoch·224step 본학습과 validation176건을 마치고10:05:56 KST에 정상 종료했다. 최종adapter 저장·checkpoint224 가중치 SHA 일치,부분checkpoint216의11파일 SHA를 확인했다. eval_loss0.596903은 실전 정답률이 아니며 원본 대비 관제품질·Thor 후보 적재는 아직이다. 아래 재개·중단 기록은 당시 이력으로 보존한다. [최신 상태·Git](../STATUS.md).

> **09:31 KST 재개 등록:** checkpoint168을 읽기 전용으로 복원하는 새 독립 실행과 제한 자동 재개를 추가했다. 현재 실제 진행·Git은 [STATUS](../STATUS.md), 실행 기준은 아래 [자동 재개](#11월1일-168단계-재개와-제한-자동-재시도)를 따른다.

> **09:20 KST 후속:** 오전재개는175/224step에서09:00:52 공유Ollama새worker감지로종료됐다.최신checkpoint168·최종검증미실행·현재자동재개없음.09:00:51 driver0x51도1건있어충돌예방완료가아니다.[최신근거·후속](../STATUS.md).아래등록/진행기록은당시이력으로보존한다.

> **08:27 KST 후속 실조회:** 전송/토큰/최장2건2step 시험 완료 후 본학습139/224step에서02:46 메모리 보호로 실패 종료했다. 가용15.81GiB<reserve16GiB,같은 시각NVIDIA0x51 할당 실패2건. checkpoint136을 보존했으며 최종validation/품질/Thor적재는 미완료다.06:30 cutoff 확인도 성공했으나 실제 학습은그보다일찍끝났다. 재개는 원인/저장본/실행경로 확인이 필요하며 이번현황조회에서는재실행하지않았다. [상세·Git](../STATUS.md).

현재 관측과 Git 게시 상태는 [STATUS](../STATUS.md)가 기준이다. 환경과 자료 준비 완료를 전체35B 본학습·모델 품질 완료로 표시하지 않는다.

## 이번 자료와 작업 범위

[편입 원장](GUIDE_ADMISSION_20261101.json): 보존한 Microsoft GUIDE v2 3,882사건/34,087행을 재검사했다. 분류 라벨 없는351사건, 사건 전체 투영이 너무 큰7사건, 실제4096토큰 초과2사건을 제외했다. 나머지3,522사건 중 이번 시간 예산에 맞춰 GUIDE train256/validation48/test48을 결정적·클래스 균형 표본으로 선별했다. 나머지3,170건은 후보로 보존한다.

| 분할 | 기존 자료 | 새 GUIDE | 합계 |
| --- | ---: | ---: | ---: |
| train | 191 | 256 | 447 |
| validation | 128 | 48 | 176 |
| test | 128 | 48 | 176 |

원 제공자의 IncidentGrade를 그대로 정답으로 사용한다. 질문·특징 선택은 프로젝트 작성이며 기관 인증 조사 답안이 아니다. 시간(KST)·Category·MitreTechniques·EntityType만 입력에 남기고 모든 원천 행을 해당 필드/중복 개수에 반영했다. 전체 원문을 보존한 것과 모든 원문 필드를 모델에 넣은 것은 다르다. 원본/제외 필드/행 ordinal·해시는 lineage와 Thor 원자료에 보존한다. 익명화 ID를 실제 IP·계정·해시로 사용하지 않는다.

정답·조치·LastVerdict/SuspicionLevel·EvidenceRole·ThreatFamily를 입력에서 제외했다. 업무 범위는 **과거 사건 사후 분류**다. 공개 파일이 판단 시점의 가용 정보를 입증하지 않으므로 실시간 결정·공격 성공·실행 가능한 MCP 조치의 정답으로 확장하지 않는다. 분류 라벨 없이 조치 라벨이 있는351사건도 원자료에 유지한다. 새 MCP 실행/승인 정답 생성0. GUIDE 조직·정확한 입력의 분할 간 중복0을 확인했다. 기존 CTI validation/test는 이미 사용된 개발 회귀이며, 새 GUIDE test는 모델 평가에 아직 사용하지 않았다.

## 환경

- DGX Spark GB10/SM121, Ubuntu24.04 aarch64, 기존 드라이버580.173.02.
- 이미지 `nvcr.io/nvidia/pytorch@sha256:417cbf33f87b5378849df37983552cd1f8bc8b62fe1ceabe004de816a55dff21` (25.11-py3).
- vendor Torch2.10.0a0+b558c986e8.nv25.11/CUDA13, transformers5.4.0/peft0.18.1/accelerate1.12.0. 별도 venv이며 host Python·드라이버는 변경하지 않는다.
- NGC nvidia-resiliency-ext의 빠진 배포 의존성은 pynvml13.0.1로 충족했다. 이는 기존 이미지의 의존성 호환용이며 공식 NVML binding은 nvidia-ml-py다. 해당 legacy 패키지와 TF32 API의 deprecation 경고는 별도 기록한다.
- 기본 BF16 실제 역전파와 랜덤 축소40층 구조의 LoRA190대상/gradient380개·2optimizer step을 확인했다. 전체35B의 최장 입력2건 시험은 별도 필수 단계다. DeltaNet은 기존과 같은 PyTorch fallback을 사용한다.

이미지 선택 근거는 [NVIDIA Spark fine-tuning playbook](https://github.com/NVIDIA/dgx-spark-playbooks/blob/main/nvidia/playbook-pytorch-fine-tune/README.md)와 [25.11 release notes](https://docs.nvidia.com/deeplearning/frameworks/pytorch-release-notes/rel-25-11.html)다. [NVIDIA UMA 안내](https://nvidia.custhelp.com/app/answers/detail/a_id/5728/)에 따라 Spark에서 cudaMemGetInfo가 제외하는 회수 가능한 캐시를 고려하고, 시스템 MemAvailable/총 CUDA 메모리/cgroup headroom의 최소값을 시작 예산으로 사용한다. swap은 더하지 않으며 이 값은 최대 할당 보장이 아니다. 호스트 전역 캐시 강제 비우기나 다른 서비스 중지는 하지 않는다. base 검증 뒤 이번 run의26개 가중치 파일에만 POSIX_FADV_DONTNEED를 적용해 읽기 캐시 회수를 권고한다. 이는 할당 보장이나 전체 캐시 삭제가 아니다.

## 단일 설치 진입점·재현

기존 DGX NVIDIA driver/Docker/container toolkit을 전제로 하는 추가 모드다. A/B/C의 초기 설치나 기존 운영 서버 덮어쓰기를 실행하지 않는다. OS부터 새 서버 전체 설치를 검증한 것으로 표시하지 않는다.

자료 준비 도구는 설치 진입점이 아니라 고정된 입력 묶음을 만든다. 자격·가중치는 넣지 않는다.

```sh
python3 -B finetuning/prepare_dgx_run.py \
  --output /TASK/bundle \
  --root /home/ACCOUNT/Capstone_Groot_training/dgx-20261031 \
  --uid 1000 --gid 1000 \
  --run-id capstone-dgx-20261031-r3 \
  --image nvcr.io/nvidia/pytorch@sha256:417cbf33f87b5378849df37983552cd1f8bc8b62fe1ceabe004de816a55dff21 \
  --deadline 2026-11-01T06:30:00+09:00 \
  --guide-mix finetuning/data-guide-mixed-20261101-r1
```

위 날짜는 이번 동결 실행의 예제이며 과거 시각이면 실행을 거절한다. bundle의 source/data/profiles/installer/control.json을 지정 root로 배치해 root 소유·쓰기 제한을 적용하고 workspace만 학습 UID 소유로 둔다. 정확한 파일 해시와 image digest를 먼저 확인한다. 재실행은 기존 기록을 덮어쓰지 않는 별도 검토된 run이 필요하다.

```sh
sudo bash RUN/installer/deploy.sh --training-dgx --config RUN/control.json --check
sudo bash RUN/installer/deploy.sh --training-dgx --config RUN/control.json --prepare-environment
sudo bash RUN/installer/deploy.sh --training-dgx --config RUN/control.json --apply
sudo bash RUN/installer/deploy.sh --training-dgx --config RUN/control.json --verify
```

`--prepare-environment`는 격리 venv/패키지와 실제 GPU의 작은 연산을 확인한다. 성공한 환경을 재사용하는 `--apply`는 root systemd 실행기를 설치한다. 실행기는 준비 확인→base 검증→모든 분할 토큰 검사→최장2건2-step→본학습→최종검증 순서로 진행한다. 외부 source/base transfer가 없으면 pinned public base를 DGX에서 직접 다운로드한다. 이번에는 Thor 원본71,926,864,255B를 직접 rsync하고 모든 artifact SHA/Git blob을 검증한다. Mac에는 가중치를 저장하지 않는다.

GUIDE 전처리는 `prepare_guide_sft.py`, 실제 토큰 편입은 `admit_guide_sft.py`로 재현한다. 정제 후보를 사전 해시 검증해 `guide-candidates/`에 배치한 준비 환경에서는 root 진입점의 `--admit-guide`로 CPU 전용·네트워크 없는 검사를 별도 실행할 수 있다. 이번에는 같은 내부 명령을 증분 배포해 실제 검사했다. root manifest에 source와 후보 입력 해시를 함께 기록해야 한다. 최초의 모듈 import 실패와 환경 의존성/UMA 예산 실패는 보존하고 수정 후 성공 기록을 분리했다.

## 독립 실행과 상한

- `capstone-dgx-20261031-r3.service`: 부모systemd/PID1, Restart=no. SSH/Mac 종료와 분리한다.
- `capstone-dgx-20261031-r3-deadline.timer`: **2026-11-01 06:30:00 Asia/Seoul**, Persistent=true. RuntimeMaxSec도 동일한 남은 시간으로 제한한다.
- **06:15 KST** 이후 새 단계를 시작하지 않는다. 학습 중에는 현재 optimizer step 뒤 저장·종료를 요청하고 최종 검증은 보류할 수 있다. **06:30 KST**에는 해당 run label/name의 컨테이너와 실행기만 종료한다.
- 실제 별도 GPU 없는 시험 컨테이너를 예약 타이머로 종료해 동작을 확인했다. 장비 전원·커널이 멈춘 경우까지 시간 정확성을 보장하는 장치는 아니다.
- 본학습은1epoch/447행/224step, batch1·accum2·LR5e-7·LoRA r16. 매8step 체크포인트, 최근2개 유지. `final_eval_only=true`이므로 본학습 후 검증176행을1회 평가한다. 어댑터·학습 state를 검증보다 먼저 저장한다.
- 호스트 가용16GiB reserve 감시, 컨테이너110GiB·swap0. GPU 단계 시작 전에 공유 Ollama 모델이 적재돼 있으면06:15까지 유휴를 기다린다. 학습 중 공유 모델이 새로 적재되면 우리 학습만 중단한다. 다른 서비스나 사용자의 작업을 종료하지 않는다.
- `completed`, `completed_training_validation_pending`, `stopped_deadline`, `failed`를 구분한다. 중단된 checkpoint를 완료 모델로 표시하지 않는다. 서버 재부팅 후 학습 자동 재개는 설정하지 않았다.

진행은 `supervisor-status.json`, `workspace/base-transfer.json`, `workspace/smoke|main/progress.json`, `*-status.json`, `*-memory-guard.json`에 남는다. 완료 후 평가·변환·Thor 후보 등록·동일 하네스 품질 비교가 필요하며 이번 실행은 운영 모델을 자동 선택하지 않는다.

## 반입·복구 범위

오프라인 환경의 필요 목록은 동일 digest의 NVIDIA ARM64 이미지 archive, 해당 CUDA vendor 환경의 torch 계열, requirements.qwen36-dgx.txt와 모든 전이 의존 wheel/해시, 고정 base revision `995ad96eacd98c81ed38be0c5b274b04031597b0`의39artifact/manifest, source/data/profiles/control SHA 묶음이다. 이번 DGX는 네트워크가 있어 직접 준비했다. 이 모드의 인터넷 없는 pip 설치나 신규 OS부터의 전체 설치는 이번 검증 범위가 아니다. 기존 A/B/C 오프라인 설치 목록을 변경한 것으로 표시하지 않는다.

이전 준비 source/data/profiles/control과 실패 영수증은 `before-guide-training/`, `environment-attempt1/`, `environment-attempt2/`에 보존한다. 원본35B·Thor 원자료·과거 학습 산출물도 보존한다. 실제 공유 모델 적재를 확인해 유휴 대기를 추가한 R2와 설치기 CPU-admission 경로 일치를 확인한 R3로 전송 대기 중 실행기만 갱신했다. 이전 pipeline-attempt1/2 기록을 보존했고 아직 전체35B 학습을 중단한 적은 없다. 중단은 root 진입점의 `--stop`으로 해당 run만 종료하며 체크포인트·원자료는 삭제하지 않는다. 작업별 Mac 전송/인증 helper·원자료 임시 복사본은 게시 후 정리하고 프로젝트 정제 데이터·출처/대화 근거는 보존한다.

## 11월1일 오전 재개

08:31 KST의후속journal조회에서직전중단10초전(02:46:26)공유Ollama가27B/262144context의llama-server를새로적재한사실을확인했다.약34,217MiB추가계획과기존학습의메모리사용이겹쳤다.이는동시적재경쟁근거이며드라이버0x51의모든내부실패조건을증명한것은아니다. `/api/ps`는적재완료전worker를놓칠수있어실제Ollama worker executable도조회한다. GPU단계poll은1초,기존16GiB reserve/110GiB컨테이너상한/swap0유지.추론/다른사용자프로세스에는신호를보내지않는다.

[Trainer공식재개계약](https://huggingface.co/docs/transformers/main_classes/trainer)과DGX설치5.4.0소스를대조했다.명시checkpoint의adapter/optimizer/scheduler/RNG/state를복원하고이미학습한batch를skip한다. `resume_training.py`는원실행manifest/11checkpoint파일hash·원데이터3분할·base manifest·학습설정을대조하며암묵latest/boolean재개·누락optimizer/변조·설정변경을거절한다.새출력디렉터리에만기록,원본checkpoint/base/venv는readonlymount다.재개ETA는이번프로세스에서증가한step만사용한다.라이브러리의재개후train_loss를전체학습품질점수로해석하지않는다.

서버내전용source staging에현재소스를SHA검사하여준비한후새입력묶음을만든다.아래root/account는예시이며과거deadline/기존run덮어쓰기/원체크포인트쓰기지시는아니다.

```sh
python3 -B SOURCE/prepare_dgx_resume.py \
  --parent /home/ACCOUNT/Capstone_Groot_training/dgx-20261031 \
  --root /home/ACCOUNT/Capstone_Groot_training/dgx-resume-20261101-r1 \
  --sources SOURCE --step 136 --run-id capstone-dgx-20261101-r1 \
  --deadline 2026-11-01T11:35:00+09:00
sudo bash RUN/installer/deploy.sh --training-dgx --config RUN/control.json --check-resume
sudo bash RUN/installer/deploy.sh --training-dgx --config RUN/control.json --apply
sudo bash RUN/installer/deploy.sh --training-dgx --config RUN/control.json --verify
```

입력묶음작성은관리자가검증한root소유source와기존root소유control을사용한다.실제설치진입점은root `deploy.sh`로유지한다. `--check-resume`는GPU/네트워크없는4GiB컨테이너에서380adapter텐서finite와실설치Trainer/PEFT의작은4step연속vs2step중단재개동등성을검사한다.동등성실패시GPU단계로진행하지않는다.첫검사의시험모델config float검증실패는수정후재시험했고원본실패기록은보존했다.

이번run은08:36:40 KST등록,11:20저장정리/11:35독립timer+RuntimeMaxSec상한이다.72GB원본을새로다운로드하지않고기존39파일을재검증한다.기존full35B smoke성공을확인하고CPU재개검사→base검증→token→main순서로실행한다.대기중공유worker가있으면11:20까지기다리고,학습도중새worker가뜨면우리run만중지한다.실패의자동재시도/공유모델강제unload는없다.실제GPU재개step과전체완료는[STATUS](../STATUS.md)를기준으로한다.

오프라인추가목록은 `resume_training.py`, `prepare_dgx_resume.py`, `check_resume_runtime.py`,39입력manifest및원checkpoint11파일/기존base/NGC환경이다.새외부패키지는없다.일반portable/Thor/evidence반입목록에도새train의존성을함께포함한다.복구는기존root진입점 `--stop`으로이번run만종료하며원checkpoint128/136·과거실행/실패·현재새checkpoint를보존한다.중지후직접원본에덮어쓰지않고다음별도run을준비한다.

## 11월1일 168단계 재개와 제한 자동 재시도

09:31 KST 새 `capstone-dgx-20261101-r2.service`를 등록했다. 기존 168단계 저장본에서 남은56단계와 validation176건을 진행한다. 등록과 실제 optimizer 재개·학습 완료는 [STATUS](../STATUS.md)에서 구분한다. Mac/SSH가 종료되어도 systemd가 실행하며 기존 상한 **11:20 KST 새 단계 금지·저장 정리 / 11:35 KST 독립 종료**를 유지한다. 공유 추론 서비스와 다른 사용자의 모델은 중지하지 않는다.

- `resource_root`는 최초 검증된 base/venv 실행을 가리키고 `resume_parent`는 실제 체크포인트 실행을 가리킨다. 재개 이력을 따라 원본 경로·이미지·UID/GID·입력 SHA를 대조하며 순환/경로변조를 거절한다. 원본 가중치·환경·직전 체크포인트는 읽기 전용으로 재사용한다.
- `retry_policy`는 이번 창에서 최대4회 실행, 연속60초 공유 worker/API 모델 없음과 호스트 가용96GiB 이상을 요구한다. 공유 추론 시작 또는 API 상태 확인 불가 시 우리 컨테이너만 종료하고, 조건이 회복되면 최신 정상 저장본부터 이어간다. 일반 학습 오류·비정상 수치·무결성 오류는 재시도하지 않는다. 서버 재부팅 후 자동 재시작은 설정하지 않는다.
- 각 시도는 `dgx-resume-20261101-r2-a1` 등의 별도 출력에 기록한다. 동일한 전용 container 이름/label과 원래 systemd/timer를 사용하며 동시에 여러 학습을 시작하지 않는다. 최상위 `supervisor-status.json`의 `current_attempt_root`를 따라 해당 시도의 상태·진행을 확인한다. 종료된 시도의 오래된 `training` 문구를 실행 중 근거로 사용하지 않는다.
- 저장 완료 callback 이후 `checkpoint-complete.json`에 파일 SHA·원본 manifest를 원자적으로 기록한다. 자동 재개는 이 marker와 실제 바이트가 맞는 최신 **부분** checkpoint만 사용한다. 저장 도중 종료되거나 파일이 바뀐 후보는 제외한다. 전체224단계 후 validation 중단 시216단계부터 마지막8단계를 다시 수행할 수 있으며,224에서 추가 optimizer step이 실행되는 경로는 사용하지 않는다.
- 공유 상태 API timeout0.5초/GPU poll0.25초로 조기 확인한다. 기존110GiB cgroup/swap0·호스트16GiB reserve는 유지한다. 추론의 급격한 메모리 할당과 검사 사이 경쟁은 남으며 드라이버 경고 완전 예방이나 이번 시간 내 학습 완료를 보장하지 않는다.

재개 bundle 준비에는 현재 source20파일(기존 목록 + `check_resume_runtime.py`, `prepare_dgx_resume.py`, `prepare_dgx_run.py`), 원본 환경/base, 부모checkpoint/manifest·동결 자료가 필요하다. 외부 패키지나 Mac 모델 다운로드는 추가하지 않는다. 예시는 다음과 같으며 설치 진입점은 계속 루트 `deploy.sh`다.

```sh
python3 -B SOURCE/prepare_dgx_resume.py \
  --parent /home/ACCOUNT/Capstone_Groot_training/dgx-resume-20261101-r1 \
  --root /home/ACCOUNT/Capstone_Groot_training/dgx-resume-20261101-r2 \
  --sources SOURCE --step 168 --run-id capstone-dgx-20261101-r2 \
  --deadline 2026-11-01T11:35:00+09:00 --retry-attempts 4 --idle-seconds 60
sudo bash RUN/installer/deploy.sh --training-dgx --config RUN/control.json --check-resume
sudo bash RUN/installer/deploy.sh --training-dgx --config RUN/control.json --apply
sudo bash RUN/installer/deploy.sh --training-dgx --config RUN/control.json --verify
```

실제 DGX CPU 검사에서 checkpoint168의380텐서 finite, 설치된 Trainer/PEFT의 연속4step과2+2step 재개의 비트 단위 동등성, 실제 `on_save` 이후 marker 검증을 확인했다. 로컬 학습682검사(679PASS/환경3skip)·설치218PASS. 자동 충돌 재시도는 격리 검사로 확인했으며 다른 사용자의 모델을 일부러 적재하여 운영 충돌을 재현하지 않았다. 전체 학습 완료·관제품질·Thor 후보 적재는 별도 단계다.

중지는 기존 `--stop`으로 최상위 run의 실행기/정확한 label 컨테이너만 종료한다. 원본/과거 실패·각 시도의 checkpoint와 제어기 snapshot을 보존한다. 자동 재개를 끈 별도 run을 만들 수 있으나 기존 실행 상태를 덮어쓰거나 보호 기준을 낮추지 않는다.

## 11월1일 본학습·validation 완료

10:47~10:48 KST 읽기 조회에서 최상위/시도 supervisor, main-status, progress의 completed와 systemd Result=success/exit0/MainPID0을 대조했다. 168단계에서 재개한 첫 시도가224/224에 도달해10:05:56 KST 종료했다. 실제 토큰 검사에서 train447/validation176건 모두 유지했고 최종 eval_loss는0.5969030857086182,eval_runtime은398.7065초다. 재개 후 train_loss를 전체 학습의 품질 점수로 해석하지 않는다.

최종 산출물은 `~/Capstone_Groot_training/dgx-resume-20261101-r2-a1/workspace/main/adapter/`다. 어댑터·설정·tokenizer·템플릿 등7파일 SHA를 로컬 검증 기록에 남겼다. `adapter_model.safetensors`는65,061,752B/380텐서이며 header와데이터offset 범위가 유효하고 checkpoint224 가중치와 SHA가 일치한다. 최종 SHA256은 `05953537d3f081c796f67f46ff6ecf93b526a9aaaaad16234068dfe73d028c67`이다. GPU에 모델을 올리거나 전체 텐서 수치 검사를 수행한 것은 아니다.

checkpoint216은 재개용 marker의11파일 SHA가 모두 일치한다. checkpoint224에는 `resume_training.mark_completed`가 의도적으로 부분 재개 marker를 만들지 않는다. 이 상태를 저장 실패로 오인하거나224부터 추가 학습을 수행하지 않는다. 최종 어댑터/원본 base·이전 저장본은 보존하고,후속 수치·호환 검증과 동일 하네스 독립 품질 평가 후 Thor 후보를 준비한다.

이번 조회는 서버 상태/파일의 읽기와 로컬 기록만 수행했다. 학습/공유추론 재시작·타이머 변경·패키지 설치·가중치 다운로드/반입·운영 모델 교체는 없었다. 보호기는 정상 종료했고 실행 중 최소가용 메모리35.86GiB를 기록했다.10:47 GPU0%/가용118.71GiB는 순간 관측이다. 11:35 KST 독립 타이머는 기존 대기를 유지한다. 코드/설치 경로 변경이 없어 회귀 테스트나 새 서버 설치 시험을 추가 실행하지 않았으며 이번 검증은 실서버 읽기 근거다.
