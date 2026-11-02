# 관제 학습 자료·실행 준비 — 2026-11-01

## 현재 실행과 명시 기한 연장 — 2026-11-02

후속 사용자 지시에 따라 진행 중인 r6는 그대로 유지하고 정상 완료를 확인한 뒤 후속 작업을 시작한다. [완료 확인 조건](../PLAN.md#다음-실행-순서)에 따라 전체단계·최종평가·가중치/계보와 실제 종료 상태를 함께 대조한다. 기한 종료나 오류 중단을 완료로 간주하지 않으며, 아래 설치/중지 명령은 필요 시 사용할 절차이지 현재 실행에 대한 추가 변경 지시가 아니다.

사용자 지시로 종료를 **11/2 17:30 KST**, 저장 정리를 **17:15 KST**로 연장했다. 기존 프로세스는 시작 시 읽은 기한을 유지하므로 기존 control/profile을 덮어쓰지 않고 검증된 checkpoint1172에서 `operator-main-20261102-r6`로 계승했다. 원실행·checkpoint·학습자료·계산 설정은 보존한다. 최신 단계는 [STATUS](../STATUS.md), 제어기/체크포인트/검증 근거는 [연장 원장](OPERATOR_TRAINING_EXTENSION_20261102.json)을 따른다. 아래11/1의03:47기한은 원실행 당시 이력이다.

설치 창의 기본 상한은12시간이다. 사용자가 더 긴 특정 기한을 승인한 **새 실행의 설치**에만 다음 옵션을 명시한다. 30분 초과~24시간 이하의 미래기한을 검사하며,24시간을 넘거나 `--apply` 이외 작업에 이 옵션을 사용하면 거절한다. 이미 실행 중인 작업의 인메모리 기한을 바꾸거나 무기한 재시작하는 옵션이 아니다.

```bash
sudo bash /home/ACCOUNT/Capstone_Groot_training/operator-main-20261102-r6/installer/deploy.sh --training-dgx --config /home/ACCOUNT/Capstone_Groot_training/operator-main-20261102-r6/control.json --apply --reviewed-window-hours 24
sudo bash /home/ACCOUNT/Capstone_Groot_training/operator-main-20261102-r6/installer/deploy.sh --training-dgx --config /home/ACCOUNT/Capstone_Groot_training/operator-main-20261102-r6/control.json --verify
```

위 `--apply`는 이미 등록한 r6에 다시 실행하지 않는다. 후속 연장도 새 디렉터리·새 run_id·완전 checkpoint를 사용한다. 중지는 해당 새 control로 같은 진입점의 `--stop`을 사용한다. 독립 hard timer, RuntimeMaxSec, 학습 내부 soft cutoff, 공유 추론 우선·최대32회 조건부 재개를 유지한다. 기존 timer는 이전 run만 대상으로 하며 이번 계승 후 비활성화했다. 자동 기한 연장이나 운영 모델 승격은 없다.

새 외부 패키지는 없다. 반입 소스는 기존 allowlist의 `dgx_supervisor.py`와 대응 installer 복사본, 데이터/프로필/체크포인트 검증 정보다. `pack.py`는 소스와 작은 연장 원장을 포함하고 가중치를 제외한다. 로컬42검사·DGX격리32검사 및 실제CPU checkpoint/Trainer 재개검증을 통과했다. GPU 실진행·전체학습완료·관제품질은 각각 별도 확인한다.

## 11/2 과적합·일반화 위험 검토

현재 r6의 과적합은 **확인되지 않았으며, 부재도 검증되지 않았다**. 아래는 기존 준비 원장·실행 설정을 대조한 위험 분석이며 새 품질 평가 결과가 아니다. 10:20 KST 읽기 관측에서 2,661/4,348단계 진행 중이고 `eval_results`는 아직 없다. 현재 학습·평가 일정·종료 기한을 변경하지 않았다.

| 확인 근거 | 해석과 한계 |
|---|---|
| 8,695대화·1epoch, 초기 learning rate 5e-7·LoRA r16 | 반복 노출을 제한하는 설정이나 과적합 방지를 보장하지 않음. 현재 학습 손실 한 점으로 판정하지 않음 |
| 학습 입력 exact 중복0, 기존 평가 exact 겹침0 | 알려진 출처 계열·사건/공유 경보 분리도 수행. 전체 출처의 의미상 유사 중복은 완전히 배제하지 못함 |
| CRS3,776 + Wazuh1,399 = 5,175건, 전체 대화의59.52% | 공급자 규칙 기대값 비중이 큼. 이는 자료 분포·업무 범위의 편향 위험이며 과적합이 발생했다는 직접 증거는 아님 |
| 명시적 MCP/실행기41건 = 대화0.47%·입력 토큰약1.93% | 완전 도구 대화35/첫 선택6. 격리 실행기24건은 모의 승인/장비를 포함하므로 운영 쓰기 증거로 확대하지 않음 |
| validation176·test176·추가 미학습31, `final_eval_only=True` | 최종 평가 전이라 train/validation 차이와 그 추세를 확인할 수 없음. 분리된 자료가 있다는 사실만으로 일반화를 입증하지 않음 |

공식 기관·공급자 출처는 근거 추적에 유용하지만 과적합이나 실제 관제 역량을 보장하지 않는다. 학습 자료 성능과 보지 않은 자료 성능을 구분하고, 모델 선택용 검증과 최종 시험을 분리한다([검증 곡선 원칙](https://scikit-learn.org/stable/modules/learning_curve.html)).

정상 완료 후에는 동일 모델·하네스에서 원본/학습본을 비교한다. 학습/validation 손실 차이와 보존된 checkpoint의 검증 성능을 가능한 범위에서 확인하고, 최종 test는 반복 튜닝 대상으로 쓰지 않는다. 별도 사건·규칙 계열과 새 짧은 표현·후속 문맥·다단계 조사·상관분석·승인 경계·허위 성공·중요 누락을 업무별로 평가한다. 실패가 모델 지식/판단인지 도구·권한·하네스 오류인지 구분하며 현재 후보 자동 운영 승격은 없다. 이전224step 후보의 원본 대비 동점은 이번 실행의 과적합 증거가 아니다.

## 11/1 준비·원실행 이력

**최종 준비 결과:** 15:36:36 KST 전체35B GPU 시험2/2step·4역전파·validation8 완료,최종adapter/checkpoint2 SHA 일치를 확인했습니다. 최대예약70.10GiB/최저가용44.92GiB·CUDA OOM/재시도0입니다. `release.json`을 발행했고,이후 사용자 지시로 아래 본학습을 시작했습니다. 아래 대기/모델적재 기록은 준비 당시 이력입니다.

로컬에서 출처 검수·정제·대화 구성을 마친 **8,695건**을 DGX 시험 묶음에 넣었다. 실제 토큰 검사와 반입 해시 검증은 통과했다. 첫 GPU 시험은 공유 추론 사용으로 시작 전 거절됐다. 이후 사용자 지시로 **공유 추론 종료 후 자동 시험하는 대기 unit을 등록**했다. 공유 추론 종료를 감지해 **15:24:37 KST 실행, 원본 무결성/토큰 재검사 후15:26 GPU 모델 적재 단계**에 진입했다. 시험 완료·본학습·Thor 적재·운영 교체는 아직이다. [검증 원장](OPERATOR_PREPARATION_20261101.json)과 [현재 현황](../STATUS.md)을 우선한다.

## 자료와 근거

| 출처·업무 | 최종 학습 대화 | 근거의 범위 |
|---|---:|---|
| 이전 근거 자료 + Microsoft GUIDE | 3,271 | 기존191 + GUIDE3,080. GUIDE는 익명화된 사건의 사후 분류이며 도구 실행 기록은 아님 |
| OWASP CRS | 3,776 | 공급자 회귀시험의 기대값. 실제 WAF 실행·차단 성공과 구분 |
| Wazuh | 1,399 | 공급자 규칙/레벨/decoder 기대값. 불일치는 무해 판정이 아니며 시간 상관분석 실행을 증명하지 않음 |
| CISA COUN7ER | 152 | 원문 Preparation/Risks 추출. 프로젝트가 질문과 표현을 구성했으며 CISA가 작성한 정답 대화가 아님 |
| Microsoft ExCyTIn | 16 | 명시된 경보와 정확한 typed entity 값이 일치한 연구 질문. 인과·공격 주체·최초 발생 정답으로 확대하지 않음 |
| Splunk attack_data | 40 | 공급자 실습 로그의 동일 account/principal/IP 연결과 KST 순서. 독립 실사건·침해 성공 정답이 아님 |
| 실제 MCP 읽기 | 17 | 당시 관측을 읽는 과정. 11개 전체 대화 + 긴 결과6개는 첫 도구 선택만 별도 학습 |
| 로컬 실행기 증거 | 24 | 실제 임시파일 변경·해시 검증 + 모의 승인 broker/장비. 기관 인증 자료나 운영 적용 성공이 아님 |
| **합계** | **8,695** | **완전한 도구 대화35개 + 도구 선택만6개** |

출처 버전·원문 URL·파일/행 위치·해시는 각 대화 provenance에 있다. 고정 출처 상세는 [공식 규칙/지침](DEFENSIVE_SOURCE_REVIEW.json), [Microsoft 조사](INVESTIGATION_SOURCE_REVIEW.json), [GUIDE·Splunk](JOINT_SOURCE_REVIEW.json), [이전 학습 출처](TRAINING_PROVENANCE.json)를 함께 참조한다. 원문 라이선스·NOTICE·MITRE attribution을 반입 묶음에 보존했다. OTRF 권리 충돌 자료, 근거가 부족한 인과 답변, 연구 모델의 미검수 답변은 편입하지 않았다.

작성한 모든 대화가 기관의 검수를 받았다는 의미는 아니다. 공급자 정답/원문/관측과 프로젝트의 질문·응답 표현을 구분했다. 검수는 원문 해시·기대값·typed field 전수 대조와 업무 유형별 검토이며 독립 전문가의 전건 검수는 수행하지 않았다.

## 검사·평가 분리

- 초기8,720후보 중 명시적 자격 패턴19개를 보류했다. 남은8,701개와 별도 첫 호출 fallback17개, 기존 평가352개를 실제 pinned tokenizer로 검사했다(총9,070).
- 긴 전체 대화12개를 잘라 쓰지 않았다. MCP6개만 별도 첫 호출 예제로 대체하고 CRS3/Splunk3은 제외해8,695건이다. 최대4,067/4,096tokens, 전체4,502,705tokens.
- 학습 입력 exact 중복0·기존 평가 exact 겹침0·명시적 자격 패턴0. 알려진 source family와 사건/공유경보 그룹을 분리했다. 모든 출처 사이의 의미상 중복이나 개인정보가 없다는 포괄적 보장은 아니다.
- 기존 validation176/test176을 그대로 유지했다. 추가 **31개**는 별도 source family에서 확보했고 전체 실제 토큰 검사 통과(최대2,245). 학습에는 포함하지 않는다. 모델의 답변을 평가한 결과는 아직 없다.
- 41개 도구 학습 예제의65호출 이름/인자는 현행 계약에 부합한다. 현행41도구 전부를 실행 검증했다는 의미는 아니며 raw Wazuh10개 스키마의 nullable/format 호환과 기존 후보의 JSON schema 오류는 별도 과제다.
- WAF/IDS/Wazuh 각각 승인대기·적용·거절·만료·후보해시불일치·원복·복구실패7종, 총21격리 실행과3변경안 대화를 구성했다. 운영 쓰기·외부 승인·채팅 게시0이다.

전 자료를1회 사용하는 비교 실험 설정이다. 명시적 MCP 대화는 건수의0.47%, 입력 토큰의약1.93%에 그친다. 많은 룰 기대값·사후 분류 자료만으로 관제주체 역량이 충분하다고 판정하지 않으며, 기존 치명 오류와 새로운 짧은 질문/다단계 조사를 별도 평가한다. 무작정 자체 시나리오를 반복 증식하지 않는다.

## 재현과 실행

로컬 `prepare_operator_sources.py` → `prepare_operator_mcp.py` → `prepare_operator_release.py`가 출처 대화·실행 증거·최종 후보를 만든다. 기존 폴더를 덮어쓰지 않고 새 `data-*` 경로를 사용한다. `prepare_operator_evaluation.py`는 공급자/프로젝트 평가 분할에서만 별도 문제를 구성한다. 실제 tokenizer 검사는 기존 DGX 환경의 CPU 전용 컨테이너로 수행하며 모델 가중치를 적재하지 않는다. 원자료 정제와 정답 작성은 GPU 서버에 맡기지 않는다.

`prepare_operator_run.py`는 최종 해시·토큰 영수증을 확인해 새 실행 묶음을 만든다. `environment_parent`는 검증된 원본 base/venv만 읽기 전용으로 재사용한다. 이전 adapter/optimizer를 재개하거나 원본 모델을 덮어쓰지 않는다. 이번 반입은55파일/28,460,890B, 네트워크 전송 gzip1,557,663B이며 가중치·패키지 신규 전송0이다. `control.json`의54입력과 제어 파일까지 서버에서 재읽기 해시가 일치했다.

원격 진입점은 묶음의 루트 `installer/deploy.sh` 한 곳이다. 먼저 `--training-dgx --config <run>/control.json --check`로 무결성을 검사한다. 즉시 시험은 `--smoke-only`(시작 당시 deadline까지30~60분), 공유 추론이 끝나기를 기다리는 시험은 `--queue-smoke`를 사용한다. 두 경로 모두 `purpose=preflight_only`만 허용하며 main 실행과 `--apply`를 거절한다.

이번 사용자 지시로 등록한 `capstone-dgx-20261101-r5queued-preflight.service`의 전체 기한은 **11/1 18:21:16 KST**다. 시험30분을 남기고 대기를 종료하므로 마지막 시험 시작 시점은 약17:51 KST다. 공유 추론 없음·MemAvailable≥96GiB가60초 유지되어야 시작한다. 상태 불명/메모리 부족도 대기하며 다른 서비스는 멈추지 않는다. 기한 내 조건이 충족되지 않으면 실패 기록을 남기고 종료한다. 기한을 늘리거나 동결 control을 수정하지 않고 새 검토 실행으로 이어간다.

시험은 최장4,067token 대화와3assistant/2tool의2,920token 대화를 사용한다. 2 optimizer step/누적2, 기존 validation에서8개 loss 평가다. GPU 시험 자식 프로세스는 최대30분이며 PID1 unit에는 전체 기한과 종료 후 자기 label 컨테이너만 제거하는 처리를 둔다. 시작 이후 실패/공유 추론 재개에는 무한 재시도하지 않는다. **실제 unit active·PPID1과 대기→실행 전환을 확인했고 SSH/Mac과 독립적으로 실행된다.** 이번 실행은15:24:37 시작되어15:54:37 KST에 시험 상한이 적용된다. 결과는 해당 run의 `preflight-queue.json`, `supervisor-status.json`, `workspace/*-status.json`과 로그에 남긴다. 상태 JSON의 관측 시각과 실제 unit 상태를 함께 확인한다.

시작 전 공유 Ollama가 비어 있고 MemAvailable≥96GiB여야 한다. 실행 중 다른 추론 적재를 감지하면 우리 학습만 중단한다. Ollama/다른 모델/방화벽을 멈추지 않는다. 신규 이미지나 서버 패키지는 설치하지 않고 기존 pinned 이미지·venv를 사용한다.

## 남은 순서와 복구

1. 유휴 DGX에서 전체35B 적재·최장/다중 도구 입력 GPU 시험, 실제 메모리·시간·loss 확인.
2. 성공한 runtime source·자료 SHA와 최종 검수 결과를 `release.json`으로 고정. 본학습 builder는 이 증거가 없으면 거절한다. 현재 release는 미발행이다.
3. 같은 pinned base에서 fresh LoRA 본학습.1epoch·누적2 기준4,348step 계획이며 새 실측 전 완료 시간을 확정하지 않는다. 한 실행은 기존 최대12시간 상한을 지키고 필요하면 검증된 checkpoint에서 같은 학습을 이어간다.
4. 동일 base/하네스 대조, 기존176+176 및 추가31문항, 별도 새 짧은 질문·승인/실패/원복 평가. 치명적 누락·잘못된 대상·승인 재사용·근거 없는 성공은 승격 거절 조건이다.
5. 품질이 확인된 가중치만 Thor 별도 후보로 적재하고 운영 비교. 원본 모델·과거 checkpoint는 보존하며 운영 자동 교체는 하지 않는다.

GPU 실행 성공, 실제 공격/탐지/승인 대응 E2E, 새 서버 전체 설치, 모델 품질 개선은 이번 정적·CPU·반입 검사로 대신하지 않는다. 원자료·정제대화·로컬 검증 원문·가중치는 Git에 넣지 않고 소스·작은 설정/검증 원장만 게시한다.

### 현재 시험의 상태 조회·취소

진행 중인 묶음은 재현을 위해 동결 상태로 유지했다. 시험 전용 unit을 올바르게 조회/중지하도록 수정한 관리 소스2파일은 `/home/ACCOUNT/Capstone_Groot_training/operator-preflight-20261101-r5-control`에 별도 반입하고 SHA/실제 `--verify`를 확인했다. 공개 경로의 `ACCOUNT`는 실제 DGX 로그인 계정으로 바꾼다. 정확한 경로는 로컬 반입 영수증에 보존한다. 현재 시험에는 다음 관리 진입점과 기존 control을 사용한다. `--stop`의 대상 선택은 격리 회귀검사로 검증했으며, 진행 중인 GPU 시험을 중지하는 실험은 하지 않았다. 후속 새 실행 묶음에는 이 수정이 기본 포함된다.

```bash
sudo bash /home/ACCOUNT/Capstone_Groot_training/operator-preflight-20261101-r5-control/installer/deploy.sh --training-dgx --config /home/ACCOUNT/Capstone_Groot_training/operator-preflight-20261101-r5-queued/control.json --verify
```

취소할 때만 마지막 `--verify`를 `--stop`으로 바꾼다. 해당 시험 unit과 그 소유 컨테이너만 정지하며 다른 추론 서비스는 건드리지 않는다. 진행 중 실행 소스의 해시와 후속 관리 소스의 해시는 검증 원장에 각각 기록했다.

## 승인된 본학습과 자동 재개 — 11/1 15:49 시작

[현재 실행 원장](OPERATOR_TRAINING_RUN_20261101.json). 사용자 “학습 시작, 공유 추론 완료 후 재시작” 지시를 반영했다. 8,695건 전체1epoch/4,348step·누적2,기존 validation176 전체 평가,별도 test176/새31문항은 학습하지 않는다. 실제 학습 구성의 save_steps는4이며,마지막 완전 저장 이후 연산은 재개 시 다시 수행될 수 있다.

`retry_policy={"max_attempts":32,"idle_seconds":60}`를 fresh main에도 적용한다. 이전에는 checkpoint 재개 실행만 이 정책을 지원했다. 첫 시도/첫 저장 전에는 검수된 동일 fresh base를 사용하고,완료 marker와 파일 SHA가 검증된 부분 checkpoint가 생기면 다음 시도부터 optimizer/RNG/scheduler를 함께 복원한다. 시도별 경로를 분리해 이전 파일을 덮어쓰지 않는다. 완료 step의 checkpoint는 추가 optimizer step을 만들지 않도록 재개 후보에서 제외한다.

공유 모델/로딩 워커 감지 또는 GPU 실행 중 공유 상태를 확인할 수 없을 때만 자기 컨테이너를 양보한다. 건강한 API·공유모델 없음·MemAvailable96GiB 이상을60초 확인해야 재시도한다. 데이터 오류·비정상loss·일반 메모리 실패를 공유 추론으로 추정해 무한 재시작하지 않는다. 지금 실행에서 일부러 다른 추론을 호출하거나 학습을 죽여 재개하는 실험은 하지 않았다. 격리 제어시험과 실제 DGX fresh 복제/해시/인계 검사를 완료했으며 실제 충돌이 발생하면 별도 기록한다.

종료기한은 **2026-11-02 03:47:48 KST**,학습 soft cutoff는15분 앞이다. 최초 포함 최대32회 시도이며 시간/횟수 상한에서 멈추고 checkpoint를 보존한다. 기한 자동 연장이나 새 실행 창 무한 생성은 하지 않는다. 소스는PID1에서실행돼SSH/Mac종료와무관하다. 서비스 Restart=no는 전체 프로세스의무조건재시작을금지하며,공유추론만대상으로한내부제어재시도와구분한다.

본학습 control/데이터/runtime 원장의 exact SHA가 GPU 준비완료 기록과 맞을 때만 중복 GPU smoke를 생략한다. fresh main의 준비/토큰/가중치·loss 계산 코드는 GPU시험본과 동일하고 이번 추가 변경은 호스트 자동재개 제어다. 새로운 runtime 검수 기록은 `release-main-control-v2.json`으로 보존하고 과거 `release.json`을 덮어쓰지 않았다.

현재 본학습의 단일 진입점은 아래와 같다. 공개 경로의ACCOUNT는 DGX로그인계정으로바꾼다. 조회는 `--verify`,해당실행만중지할때는 `--stop`이다.

```bash
sudo bash /home/ACCOUNT/Capstone_Groot_training/operator-main-20261101-r5/installer/deploy.sh --training-dgx --config /home/ACCOUNT/Capstone_Groot_training/operator-main-20261101-r5/control.json --verify
```

루트 `supervisor-status.json`은현재시도/재개위치,`-aN/workspace/main/progress.json`은실제학습단계,checkpoint-complete.json은부분저장완료증거다. 원본가중치/이전adapter/서비스/방화벽은유지한다. 본학습완료후최종validation과동일base품질비교를거쳐Thor후보를검토하며운영자동승격은없다.
