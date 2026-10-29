# V5 학습본의 동일 조건 비교

R8 학습 완료는 1,024개 관측의 전체 투입과 가중치 저장을 검증한 결과다. 관제 정확도 향상·운영 승격은 별도다. 이 문서는 CTI 매핑 비교의 입력·실행·해석 기준이며 실제 결과는 [실행 원장](V5_EXECUTION_RESULTS.json)과 [현재 현황](../STATUS.md)을 따른다.

## 비교 조건

- 기준: `soc-qwen36:35b-base-q4km-20261027` — 동일 HF commit의 미학습 Q4_K_M.
- 후보: `soc-qwen36:35b-evidence-v5-q4km-20261029` — 검증한 R8 어댑터를 같은 BF16 base에 병합하고 동일 고정 변환기로 Q4_K_M 변환한다. 이 문서 작성 시 후보 변환이 진행 중이며 등록·평가는 아직 전이다.
- 운영 registry 원본 `qwen3.6:35b`는 보호·복구 대상이다. HF 파생 비교본과 채팅 서식이 다르므로 학습 효과의 주 비교군으로 대체하지 않는다.
- 두 비교본은 모델 digest·서식/system 해시·파라미터·renderer/parser/requires/messages·양자화·runner·capabilities를 대조한다. 후보의 전체 학습 완료/등록 영수증을 요구한다. 출처를 추가한 license는 추론 조건 비교에서 제외하며 원본 보존과 학습 출처 표기를 별도로 검증한다.
- 입력과 평가 코드 SHA를 고정한다. temperature0/seed42/context8192/output512·thinking off·JSON 출력·동일 순서/질문을 사용한다. 원본 정답 assistant 메시지는 요청에서 제외한다.

`evaluate_evidence_v5.py`와 기존32개 결과는 R8 동결 소스/이력으로 그대로 보존한다. 새 `evaluate_evidence_pair.py`는 같은 판정기를 사용하면서 실제 분할명을 기록한다. 입력·모델·서식이 달라지면 실행을 거절하고 기존 보고서/계획을 덮어쓰지 않는다.

## 개발과 최종 시험

먼저 기존 `soc-evidence-v5-evaluation/frozen-plan.json`의 validation32개를 양쪽에 다시 실행한다. 원 개발 선택 파일 SHA가 학습 전 동결값과 같아야 한다. 같은 시점의 기준선과 후보 응답을 보존하고 누락/추가ID·범위·출처·명칭을 검토한다.

최종 test128개는 별도 계획과 출력에 전체 평가한다. 일부만 골라 좋은 점수로 대체할 수 없다. test 응답을 보기 전에 후보와 기준을 고정하고 결과를 학습/체크포인트 선택에 재사용하지 않는다. 후보 수정이 필요하면 새로운 미사용 평가 자료가 필요하다. 준비만 한 계획을 실제 평가 완료로 집계하지 않는다.

```bash
python3 -B finetuning/evaluate_evidence_pair.py plan \
  --dataset finetuning/data-soc-evidence-v5-r3 \
  --frozen finetuning/V5_TRAINING_INPUTS.json \
  --development soc-evidence-v5-evaluation/frozen-plan.json \
  --registration exports/qwen36-soc-v5-gguf/registration-status.json \
  --split validation \
  --control soc-qwen36:35b-base-q4km-20261027 \
  --candidate soc-qwen36:35b-evidence-v5-q4km-20261029 \
  --plan soc-evidence-v5-evaluation/paired-development-plan.json

python3 -B finetuning/evaluate_evidence_pair.py run \
  --dataset finetuning/data-soc-evidence-v5-r3 \
  --plan soc-evidence-v5-evaluation/paired-development-plan.json \
  --output soc-evidence-v5-evaluation/paired-development.json
```

Thor의 `~/Capstone_Groot_training/qwen36-20261027`에서 실행하는 예시다. `--split test`에는 별도 `paired-test-plan.json`/`paired-test.json`을 사용한다. 실제 등록과 원자료 검증이 끝나기 전에는 실행하지 않는다.

## 완료와 복구 판정

평가는 기준/후보를 순차 실행하며 도구를 제공하거나 MCP를 실행하지 않는다. 모델별1토큰 워밍업은 평가 점수에서 분리한다. 원모델 digest와 기존 상주 context를 기록하며, 종료·실패 시 이번 평가가 올린 비교 모델만 내리고 원모델 실제1토큰 응답/registry 불변을 확인한다. 현재 원모델이 다른 context로 상주하면 그 값을 우선해 불필요한 재적재를 줄인다.

평가 단계는 신규 요청 시작 전60분 경과를 검사하고 개별API timeout은120초다. 진행 중 요청 종료와 정리·복구 시간은 별도이므로 서비스 중단 상한60분을 뜻하지 않는다. Ollama 서비스를 정지하거나 운영 봇 선택을 바꾸지 않는다. 공유 서버에서 실행하므로 일시적인 메모리/계산 경쟁은 가능하며 격리된 성능 벤치마크라고 하지 않는다.

`status=completed`는 두 평가군의 요청 완료다. 별도로 `restoration.status=verified`·복구오류 목록 비어 있음·전체 건수/ID 일치를 확인해야 작업 완료다. 오류가 있으면 부분 응답과 복구 상태를 저장하고 실패로 반환한다. 출력 제한으로 잘린 답은 JSON으로 파싱되더라도 엄격 완전 점수를 주지 않는다.

## 점수 해석과 운영 채택

엄격 완전·형식·기법ID precision/recall/F1·누락/추가ID를 각각 보고한다. 기관 원문 매핑이 비포괄적일 수 있어 정답집합 밖 ID를 모두 기술적 거짓으로 단정하지 않는다. 기존 [원문 의미 검수](review_evidence_results.py)와 전문가 검수의 유무를 함께 공개한다.

이 시험은 원문 CTI 기법 매핑 평가다. 장비별 실제 조회·FW 기본룰 포함 여부·쓰기 대상·승인·원복·KST·관제 공백은 별도 관제 시나리오와 실제 MCP/채팅 시험으로 검증한다. 보안상 치명적인 누락·허위 정상/완료·잘못된 변경 대상·승인 우회는 지연 개선보다 우선하는 탈락 조건이다. 기관 출처의 신뢰성과 실제 운영 품질을 혼동하지 않는다.

미학습/학습 모델 × 기존/정리한 하네스의2x2 비교는 이후 별도 단계다. 복구본·출처·원자료·동결된 R8 학습 소스는 유지한다.
