# DGX 독립 학습 실행 — 2026-11-01

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
