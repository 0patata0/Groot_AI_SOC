# 2026-10-31 근거 중심 독립 학습

현재 본학습 실행은 `soc-evidence-20261031-r2`이며 R1의 시험·복구 근거를 보존한다. 사용자가 요청한 학습 시작과 연결 해제 대비만 수행하며 봇·보안 정책·하네스·운영 모델 선택은 변경하지 않는다. 대상은 준비한 evidence-only 191행(기관 원자료 기반 관제 관측143, 기존 CTI 재사용48)의 전체1회, batch1/누적2로96 optimizer step이다. 기존 V5 어댑터를 이어 학습하지 않고 같은 원본 Qwen3.6-35B-A3B revision에서 새 LoRA를 시작한다.

## 데이터와 평가 범위

`prepare_evidence_run.py`는 고정한 R5 후보·출처 sidecar·분할·SHA를 검사하여 새 폴더에만 쓴다. 원 후보의 미편입 이력과 V3/V4 전체 보류는 보존한다. 관제 관측143행의 답변에는 원문에 근거한 프로젝트 작성 해석이 포함되며 기관 인증 답안·독립 전문가 정답으로 표시하지 않는다. GUIDE 미정제 자료와 선택적 하네스30행은 포함하지 않는다. 원1,197행 전체와 다른 후보는 보존한다.

기존 V5 validation/test 각128행은 이미 사용한 CTI 개발 회귀이며 새로운 최종 운영 평가가 아니다. 그룹/ID/정확 입력 중복0과 실제 토큰·정답 마스크를 검사한다. 단일 배합의 학습이므로 하네스 자료 유무의 동일 연산량 비교·전체 관제 성능 개선을 입증하지 않는다. CTI67/522기법만 이 배합에 있으므로 전체 범위 회귀와 중요 누락 평가가 운영 승격 전에 필요하다. 학습 완료나 loss 감소만으로 승격하지 않는다.

```sh
python3 -B finetuning/prepare_evidence_run.py --output finetuning/data-evidence-run-NEW
python3 -B -m unittest discover -s finetuning/tests -p 'test_durable_training.py'
```

출력은 로컬 전용이다. 기존 `pack.py`에는 실행 소스·문서·검사만 포함하며 후보/정답·실행 중 출력·가중치를 자동 포함하지 않는다. 실제 반입은 검수한 release.json과 그 파일 목록만 지정한다. 새 서버의 패키지/모델 설치를 대신하는 명령이 아니다.

## R1 시험과 R2 재개 근거

R1은09:30:39~09:34:20 KST 추론을 중지했고 최장2행·2step을 정상 완료했다. 처음 예상기는 validation35.098초를 포함한 train_runtime121.968초를 행당 학습 시간으로 나눈 뒤 validation 시간을 다시 더했다. 이 중복 계산으로 예상14,256.7초가 남은 상한을 약67초 넘어 본학습 시작 전 거절됐고 원35B 실제 생성까지 자동 복구했다. 당시 실패와 실행기는 덮어쓰지 않는다.

수정은 telemetry의 최초 optimizer step 완료 시각만 사용한다. 52.215초/34.059초 중 큰 값을191행 전체에 적용하고15% 여유, validation128행 시간과 모델 적재/저장300초를 별도로 한 번 더한다. 예상12,330.65초(약3시간25분)이며 완료 보장이 아니다. `prepare_evidence_retry.py`는 기존R1의 source/data/profile/시험 SHA·원35B 복구와 누적 중단 한도를 검증해 별도R2 폴더를 만든다. 이미 성공한 시험을 다시 학습하거나 원래 어댑터를 이어 붙이지 않는다. 이후 새 입력/수치 설정에 대한 자동 재사용은 허용하지 않는다.

## Thor 실행과 연결 해제

- 학습 루트: `~/Capstone_Groot_training/qwen36-20261027/runs/soc-evidence-20261031-r2`.
- root 전용 실행기: `/usr/local/libexec/capstone-soc-evidence-20261031-r2/`. 검수한 `durable_training_window.py`, 기존 `training_window.py` 복구 함수 및 release SHA를 root 소유·쓰기 제한으로 설치한다. LLM/MCP에 일반 sudo·Docker 권한을 위임하지 않는다.
- 상태: `/var/lib/capstone-soc-evidence-20261031-r2/`; 학습 로그/진행/어댑터는 실행 루트의 `main.log`, `main/progress.json`, `main/adapter/`에 남는다.
- 먼저 기존 이미지/venv로 CPU 토큰 검사를 수행하고 `durable_training_basecheck.py`로 원본 모델 전체 파일 체크섬을 다시 검증한다. GPU 메모리는 할당하지 않고 Ollama는 유지한다.
- 본 작업은 `capstone-soc-evidence-20261031-r2.service`의 systemd 서비스가 관리한다. SSH 종료·Mac 절전/전원 종료와 독립된다. Thor 전원/커널/디스크 자체 장애까지 무중단을 보장하지 않는다.
- 독립 `capstone-soc-evidence-20261031-r2-restore.timer`를 활성화한 뒤에만 Ollama를 중지한다. 종료·실패 시 즉시 복구하며, 별도 timer는240분 뒤 복구를 실행한다. 학습 제한235분·복구 작업 제한6분, supervisor242분·종료 정리7분이다. R1 실제 중단220.927초를 합쳐 최대4시간15분 이내의 중단 계획인지 검사한다.
- Ollama 중지 후 호스트 가용96GiB 이상을 다시 확인한다. container는 비특권 UID1000, 네트워크 없음, base/소스/자료/설정 읽기 전용, 메모리112GiB·호스트 가용12GiB 보호를 사용한다. 초기 디스크30GiB 및 실행 중12GiB 여유 기준을 유지한다.
- 최장2입력·2-step 시험이 성공하고 보수적 실측 예상이 남은 시간 안에 들어와야 191행 본학습으로 진행한다. R2는 같은 자료/소스/설정의 R1 성공 시험과 복구 영수증 SHA를 대조해 재사용하며 본학습은 원본 base에서 새로 시작한다. 실패/시간 초과/디스크·메모리 부족은 중단·복구하며 원본 증거를 덮어쓰거나 자동 재시도하지 않는다.
- 복구는 원래 `qwen3.6:35b`의 고정 digest와 실제1토큰 생성을 확인한다. 완료 후191개 고유 입력·모든 assistant target·96step·finite metric·LoRA380tensor를 검증하지만 품질 합격/자동 운영 등록은 하지 않는다.

## 조회와 중단

사용자가 다시 지시하기 전 별도 주기 보고를 예약하지 않는다. 필요할 때 운영자가 다음을 조회한다(시각은 KST).

```sh
systemctl status capstone-soc-evidence-20261031-r2.service
systemctl status capstone-soc-evidence-20261031-r2-restore.timer
journalctl -u capstone-soc-evidence-20261031-r2.service
```

긴급 중단은 해당 학습 service를 정상 stop하여 복구 finally를 실행한다. 별도 복구 경로는 root 실행기의 `restore --root <위 실행 루트>`다. 실행 중 소스/입력/결과를 삭제하거나 과거 V5 출력을 재사용하지 않는다. 학습 후 남긴 어댑터와 복구·검증 원장을 보존한다. 이번 운영 실측과 Git 결과는 [STATUS.md](../STATUS.md)에 별도로 기록한다.
