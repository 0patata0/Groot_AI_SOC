# DGX 예상시간 연장과 완료 즉시 종료

2026-11-02 사용자 승인에 따라 현재 학습량·모델·입력을 유지하고 종료 예상시간에 맞춰 실행 창을 이어간다. `capstone-dgx-20261102-followr6v2.service`는 DGX에서 Mac/SSH와 독립적으로 실행한다. 현재 r6의 PID·소스·17:15 KST 저장 정리/17:30 상한은 유지하며, 정상 기한 저장 종료 후 검증된 checkpoint로 새 실행을 시작한다. [최신 상태](../STATUS.md) · [적용 원장](OPERATOR_FOLLOW_20261102.json).

## 계산과 종료 조건

- 매60초 실제 서비스/PID·해당 label 컨테이너와 진행 파일을 함께 확인한다. 관측 실패는 같은 작업을 다시 확인하며 종료로 간주하지 않는다.
- 현재 시도의 단계당 시간과 최초 관측 이후 공유 대기/재적재를 포함한 전체 실효 시간 중 느린 값을 남은 단계에 곱한다. 기준값18초/단계, 최종검증30분·재적재/준비15분·저장15분 여유를 더해15분 단위로 올림한다. smoke8개 평가18.4066초의176개 단순 환산은 약7분이나 실제 길이/부하가 달라30분을 둔다. 완료 보장은 아니다.
- 각 새 창은 기존 설치기의24시간 상한을 유지한다. 정상 기한 종료·온전한 저장본·단계 증가가 확인되면 재계산해 이어간다. epoch·총단계·학습률·데이터·소스를 바꾸지 않는다.
- 전체 단계·유한한 최종 검증 손실·원래 데이터 해시·최종 어댑터를 확인하면 해당 기한 타이머와 관찰기도 종료한다. 학습 프로세스/GPU 컨테이너는 정상 완료 시 이미 종료한다. 서버·공유 Ollama는 유지한다.
- 수동 조기 중지·학습 오류·불완전 저장본·진행 없는 창은 자동 재시작하지 않는다. 학습만 완료되고 검증이 남으면 `validation_pending`으로 남기며 마지막 단계를 다시 학습하지 않는다.

실제 기한 도달 후 GPU 계승·전체 학습/검증·완료 즉시 종료는 발생 전까지 미검증이다. 격리 검사·서비스 등록을 전체 학습 성공으로 표시하지 않는다. 운영 모델 자동 교체는 없다.

## 반입 목록·단일 설치 진입점

추가 패키지/이미지/가중치 다운로드 없이 기존 검증 환경과 원 실행의 고정 source/data를 읽기로 재사용한다. 새 `/home/ACCOUNT/Capstone_Groot_training/별도정책폴더`에 다음3개를 반입한다.

| 파일 | 용도 |
|---|---|
| `deploy.sh` | 프로젝트 단일 초기 설치 진입점 |
| `finetuning/dgx_follow.py` | 관찰·ETA·자동 계승 |
| `follow.json` | 정확한 원 control/소스 SHA와 학습 계획에 결속한 정책 |

[설정 예제](config.dgx-follow.example.json)의 ACCOUNT·해시·시각·단계를 실제 검증값으로 채운다. 0해시는 승인 값이 아니다. root 소유·그룹/전체 쓰기 금지와 반입 SHA를 확인한다. 원 run 폴더·저장본을 덮어쓰거나 자격·패키지·원자료·가중치를 함께 전송하지 않는다.

```bash
sudo bash FOLLOW/deploy.sh --training-dgx-follow --config FOLLOW/follow.json --check
sudo bash FOLLOW/deploy.sh --training-dgx-follow --config FOLLOW/follow.json --apply
sudo bash FOLLOW/deploy.sh --training-dgx-follow --config FOLLOW/follow.json --verify
```

현재 구현은 진행 중인 checkpoint 계승 실행을 따른다. 미래의 별도 학습에도 사용자 승인 원칙을 적용하되 해당 입력·모델·총단계를 확인한 새 정책으로 결속한다. 이번 정책이 임의의 다른 학습을 허용하지 않는다.

## 중지·복구

```bash
sudo bash FOLLOW/deploy.sh --training-dgx-follow --config FOLLOW/follow.json --stop
```

관찰기만 정지하며 현재 학습은 유지한다. 학습까지 명시적으로 중지하려면 관찰기를 먼저 정지하고 `follow-status.json`의 `current_control`을 확인해 해당 run의 기존 `deploy.sh --training-dgx --config RUN/control.json --stop`을 사용한다. 원 run·저장본·소스를 보존하므로 기존 수동 검토/재개 방식으로 복구할 수 있다. 재부팅 후 미확인 실패를 무조건 재시작하지 않는다.
