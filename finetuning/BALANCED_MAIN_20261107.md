# 균형 자료 본학습 독립 실행 — 2026-11-07 KST

사용자가 균형 후보1,220건을 선택해11/7 20:54 독립 실행기를 등록했다. **11/8 08:32:47 KST 사용자 요청에 따른 실제 조회에서02:57:06 KST 본학습 완료·610/610step·epoch1.0을 확인했다.** 공유 추론에 세 번 양보한 뒤168/380/588step에서 자동 재개했으며 네 번째 실행에서 완료됐다. 현재 MainPID0·inactive이며08:30 종료 타이머는 완료 기록을 유지했다. 09:16 가중치·재개 계보 검증을 마쳤고09:17 별도 CPU 내보내기를 시작했다.09:20 병합 검증 완료 후 projector 입력 누락으로 변환이 중단됐다. 누락 보완·27검사·실제 사전검사 뒤r2변환을09:46 완료했다.09:47 text/projector 전체 SHA 재대조 후 Thor 직접 반입을09:50 완료했으며, 09:59 별도 후보 등록까지 완료했다. 관제 문답 비교·운영 승격은 아직 미실행이다. [실행/완료 원장](BALANCED_MAIN_20261107.json) · [준비 검증](QUALITY_PREPARATION.md).

| 항목 | 확정 설정 |
|---|---|
| 자료 |균형1,220대화, validation176·test176 분리. 기존 전체8,719와 이전 가중치 보존 |
| 모델 |Qwen/Qwen3.6-35B-A3B revision995ad96eacd98c81ed38be0c5b274b04031597b0에서 새 LoRA. 이전 adapter/optimizer 이어쓰기 아님 |
| 학습량 |최대1epoch·610optimizer steps. learning_rate5e-7·r16·4096토큰·누적2 |
| 중간 검증 |64step마다validation176,4step마다복구 저장. min_delta0.001·개선 부족3회 조기 종료·최선 가중치 별도 보존 |
| 자원 보호 |공유 Ollama 적재/기동 감지 시 이 학습만 중단.96GiB 이상·60초 연속 유휴 후 완전한 체크포인트에서 재개,최대32회. 다른 오류는 임의 재시작하지 않음 |
| 실행 상한 |2026-11-08 08:30 KST·독립systemd 타이머. 약4~8시간 예상은 장문2step 사전시험을 기준으로 한 거친 범위이며, 공유 대기/중간평가/조기종료로 변동 |
| 위치 |DGX `~/Capstone_Groot_training/dgx-20261107-balancedmain` 및 실행별 `-aN` 형제 디렉터리 |
| 운영 경계 |공유 추론 서비스 중지0·Thor 운영 모델 교체0·공격시험0. 가중치/optimizer/데이터 Git 제외 |

기존13:46 실제35B 2step 성공 영수증을 **동일21개 runtime 소스와 같은 학습 SHA를 대조하여 재사용**했다. 새 GPU 사전시험을 실행한 것으로 세지 않는다. 이번 파이프라인은 고정 base SHA 검증→전수token 검사→학습/중간평가→최종validation loss와최선/최종adapter 보존을 이어서 수행한다. 이전 사전시험 adapter를 본학습 초기 가중치로 사용하지 않는다. 작은 복구·제어 검사27건도 재실행해 통과했다.

정제본은 로컬 통합cleaned 압축에서31파일을 안전 복원하고, 학습 묶음60파일을 압축 상태로 반입했다. 서버에서 압축 SHA·멤버·파일 SHA와59개 고정 입력을 다시 검사하고 단일 `deploy.sh --training-dgx --check/--apply`로 등록했다. 기존 검증본·학습 입력·서버 복구 가중치를 수정하지 않았다. 반입 임시 압축은 제거했다.

**검증 범위:** 여기서 자동 검증은 입력/토큰/손실/체크포인트 무결성이다. 관제 문답의 정확도·실제 MCP·승인형 변경·채팅 품질은 완료 후 별도 비교가 필요하다. test176은 토큰/형식 확인에만 사용하며 학습·조기종료·최선 선택에 쓰지 않는다. validation loss만으로 SOC 정확도·과적합 방지·운영 승격을 주장하지 않는다. 기존6개128step 비교 계획은 미실행 상태로 보존하며, 이번은 사용자가 선택한 별도 균형 본학습이다.

08:32 최초 완료 관측에서는 서비스·완료 원장·파일 존재/크기만 확인했으며 가중치 전체 SHA는 재계산하지 않았다. 이후09:16의 무결성·재개 계보 대조는 아래 후속 표로 구분한다. Thor 비교와 미사용 평가는 남아 있다.

Mac 이번 작업 임시157파일/34734127B는 전체 SHA와 실행 프로세스 부재를 확인한 뒤 제거했다. 통합 원본/정제 압축2개·프로젝트 소스·로컬 검증·DGX 실행 입력과 가중치를 보존했다. 새 Mac 패키지는 설치하지 않았다.

공개 실행/현황7문서 `0e9db7a`는20:59:49 KST 프로젝트 자격파일의 일회성 인증으로 푸시·실원격main 일치를 확인했다. 이 게시 영수증은 후속 문서 커밋으로 반영한다. 데이터·가중치·자격·로컬 검증은 게시하지 않았다.

## 11/8 완료 관측

| 항목 | 실제 확인 |
|---|---|
| 자료·학습량 | 1,220대화·610/610step·1epoch 완료 |
| 완료 시각 | 2026-11-08 02:57:06 KST |
| 재개 | 공유 추론 양보3회,168→380→588step의 저장본에서 재개 |
| 검증 손실 | step64 0.616084 → step610 0.547152. 학습 전 기본모델 비교값은 아님 |
| 최선 선택 원장 | step610, validation loss 기준. SOC 정확도/운영 승격 허용false |
| 저장 위치 | `~/Capstone_Groot_training/dgx-20261107-balancedmain-a4/workspace/main/adapter` 및 `quality-best/step-000000610` |
| 가중치 | adapter_model.safetensors 각65,061,752바이트 존재. 선택 원장의 SHA는 JSON에 기록, 이번에는 전체 가중치 재해시 미수행 |
| 남은 작업 | 무결성·재개 계보 점검, Thor 적재, 기본/학습 모델의 정확도·MCP·승인/채팅 비교 |

validation loss 감소만으로 관제 정확도 상승이나 과적합 부재를 주장하지 않는다. 재개된 마지막 segment의 train_runtime/train_loss를 전체 학습 시간·전체 평균 손실로 제시하지 않는다. GPU 본학습·내장 validation은 완료했지만 독립 test176의 업무 정확도 평가와 운영 적격 판정은 별개다. 08:36에는 사용자 마무리 지시로 일시정지했다. 이후 사용자가 재개하여 오늘17:00 KST까지 작업하며, 더 일찍 종료하라는 지시가 오면 그 시점에 마감한다.

## 11/8 가중치·재개 계보 검증과 내보내기

| 항목 | 09:20 KST까지 확인한 결과 |
|---|---|
| 고정 입력 | 59개 파일 SHA 일치, train1,220/validation176/test176의 내용·건수 일치 |
| 확정 학습 입력 | 재개 경계0→168→380→588→610을 대조해1,220개 고유 대화의 식별자·assistant turn 범위·입력 해시 전체 일치 |
| 미확정 계산 | 중단 직전1/8/4행은 다음 체크포인트에 확정되지 않아 학습 완료 건수에서 제외. 중복 확정 학습으로 세지 않음 |
| 최종·체크포인트·최선 | 세 adapter 전체 SHA 재계산 일치. 각65,061,752B, `5166b554636fc4ee90f19aaa462dcd4670038ce6b8b8ffd0cfc1bb463c09a158` |
| 적격 사전검사 | 기존 단일 deploy.sh 경로로380 finite 텐서·190 LoRA쌍·610step·base/분할/출처18개 고지 검증 |
| CPU 병합 | 1,045텐서 재대조·855보존·190모듈 변경·MTP19보존.09:20:22 완료 |
| 양자화 | 같은 고정 llama.cpp로 Q4_K_M 변환 중. 변환 완료·Thor 등록·추론 품질과 별도 |
| 자원·복구 경계 | 독립systemd/PID3037300·CPU2/메모리24GiB·네트워크/GPU없음·최대2시간. DGX 기존Ollama PID2510711/재시작0 유지 |

최초 내보내기 root는 `~/Capstone_Groot_training/dgx-balanced-export-20261108-r1`, 별도 후보 이름은 `soc-qwen36:35b-balanced-q4km-20261108`이다. 기존 base·학습 입력·가중치·도구는 읽기 전용이며 새 산출물만 기록한다. 현재 source10개90,503B와 작은 프로필만 반입했고 Mac에는 가중치나 패키지를 내려받지 않았다. Torch의 기존 pynvml 폐기예고 경고는 검사 성공과 함께 기록했으며 GPU 드라이버 오류로 판정하지 않는다.

Thor는 기존 원본35B를 유지한다. 기존 미학습Q4 export와canonical blob의 전체 SHA·크기·열린 쓰기 핸들 부재를 확인한 뒤, export 경로를 같은 내용의 hardlink로 원자 교체했다. 경로/내용은 보존하고 해당export의 소유자는Ollama 소유자로 바뀌며 mode0644·canonical 권한은 유지한다. 원래 uid/gid/mtime과 독립 복사본 복구 스크립트는 `/var/lib/capstone-model-storage/20261108-balanced/`에 보존한다. 전체SHA 사후 재검증·기존 모델digest/주PID 유지 확인, 약21.7GB를 회수해 가용46.8GB다. 원복 실행 자체는 미시험이다. 실제 품질·미사용176평가·운영 승격은 미완료다. 이전8,695건 학습 후보와 이번1,220건 균형 후보를 구분한다.

### 변환 입력 누락과 보완

09:25 최초변환은 base projector의 `conversion-status.json` 미준비로 실패했다. 학습/병합 실패가 아니며 기존 실패 상태·BF16 중간 산출물은r1에 보존했다. `convert_soc.py`는 이제 검증된 base projector의 상태·variant·고정 converter revision·단일artifact·길이/SHA·symlink 여부를 **새 출력 생성과 text변환 전에** 검사하고 사용 직전에 재검사한다. 누락/변경/중복/외부링크 회귀를 포함한27검사PASS/skip0이다. 단일deploy.sh·기존pack/source반입 경로를 그대로 사용한다.

후속 root `~/Capstone_Groot_training/dgx-balanced-export-20261108-r2`에는 기존 검증병합/18고지/receipt를 보존형hardlink·작은복사로 재사용하고 검증projector를 준비했다. 최초 preflight wrapper는 Docker의bash entrypoint 호출법을 잘못 사용해 변환 시작 전에 실패했으며, 호출·새 디렉터리 소유권을 바로잡은 뒤 동일 CPU 컨테이너의 실제 사전검사를 통과했다. 09:29:33 변환전용systemd를 시작했고09:29:41 PID3039388/컨테이너3039443·2CPU/24GiB/networknone·기존OllamaPID2510711/재시작0을 확인했다. 최대2시간·종료시자체컨테이너정리·학습/병합재실행0·운영승격0이다. 최종 GGUF 해시/Thor 반입/추론 품질은 아직 미확인이다.

### 09:47 변환 완료·전송 전 검증

09:46:22 KST r2 변환이 완료됐고 systemd MainPID0/Result=success, 기존 DGX Ollama PID2510711/재시작0을 확인했다. 09:47:27 전송 전 text/projector 전체 SHA를 다시 계산해 변환 영수증과 일치시켰다. text753/projector334텐서·qwen35moe·MTP nextn_predict_layers1·CPU 전용·학습 프로필/adapter/변환/출처18고지의 연결을 검증했다. 최초 실패 기록은 위 이력에 유지한다.

| 산출물 | 바이트 | SHA256 |
|---|---:|---|
| Q4_K_M |21,713,462,816|`0cc75a1b4b54c798ffeb253b48bab72cad7bcfa25444510944da852e02bbf48f`|
| 비전 projector |899,283,200|`daa33f8da67ddd23c452a2016c4900ff186315bceb4a95d8f99da41ad29f32a1`|

Thor에는 DGX에서 직접 정식 고정 호스트 키 SSH/rsync로 전송하며 Mac은 제어와 작은 검증 기록만 보관한다. 새 후보 디렉터리에서 전체 SHA·34개 설정/출처·기존 blob 불변·20GiB 잔여 공간을 확인한 후 별도 등록한다. 전송 시작은 등록·GPU 적재·품질 성공을 뜻하지 않는다. 현재 운영 모델 변경0이다.

09:50:31 KST Thor 반입 완료. 받은21,713,462,816B 전체 SHA·34메타데이터 SHA·기존base blob 불변을 재확인했다. 같은 내용20,920,083,968B를 서버의 기존blob에서 활용해 실제 새 데이터793,378,848B를 전송했으며 원본을 수정하지 않았다. 새Q4와canonical blob은같은inode로 등록시중복공간을 피했고 기존projector를 재사용했다. 잔여25,040,162,816B(20GiB 이상), 임시askpass/known_hosts/기준링크 제거.09:58 주Ollama PID715615/재시작0·두전송PID종료를 재확인했다.09:59 별도 새이름 등록을 시작했으며 아직 GPU적재/관제품질 평가와 운영승격은 미완료다.

09:59:35 단일 deploy.sh의 register 단계 완료,10:00 재조회로 MainPID0/Result=success·기존 모든 모델digest 불변·주PID715615/재시작0을 확인했다. 후보digest는 `7ac2a1dc6aa17746f522e81804ba2a76b25fc01e69d2460a083a0ec5cfa207c3`이며, text/projector blob·학습영수증/출처 고지·원본 runtime options·고정 HF template를 대조했다. HF 채팅 template는 운영 원본 template와 다르므로 같은HF 미학습군을 비교에 포함한다. GPU적재·응답 품질·운영봇 선택은 아직 실행하지 않았다.
