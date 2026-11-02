# DGX 학습본의 Thor 후보 내보내기

현재 후보는 8,695건/4,348step·validation176을 완료한 `soc-qwen36:35b-operator-q4km-20261103`이다. 11/3 CPU 병합·변환과 Thor 별도 등록·전체 GPU 적재를 확인했고 동일 하네스 비교를 진행한다. [현행 원장](OPERATOR_CANDIDATE_20261103.json) · [STATUS](../STATUS.md). 등록·적재·품질 합격·두 봇의 운영 선택을 구분한다.

과거 11/1의447건/224step 후보는 `soc-qwen36:35b-dgx-guide-q4km-20261101`이며 산출물과 당시 실패·점수를 보존한다. 아래 날짜가 있는 11/1 수치는 이번 본학습 결과가 아니다.

## 새 후보 프로필과 별도 Ollama

새 root의 `candidate-profile.json`은 정확한 `schema: 1`, `model`, `adapter_sha256`, `run_manifest_sha256`, `source_notices` 키를 갖는다. 모델 이름은 별도 `soc-qwen36:35b-...` 범위이며 운영 이름을 쓸 수 없다. `source_notices`는 고지 파일명→SHA256 사전이다. 이번에는 실제 학습의17개 고지를 모두 고정한다. profile SHA→완료 학습/adapter/run manifest→변환 receipt→등록 blob을 연결하고 어느 단계가 달라도 거절한다. 프로필이 없는 과거 root는 기존 이름과8개 고지 검증을 유지한다.

기본 API는 기존 `http://127.0.0.1:11434`다. 작업자가 준비한 격리 Ollama를 사용할 때만 register/preflight/warmup에 `--api-base-url http://127.0.0.1:11435`를 지정할 수 있다. 외부 주소·다른 포트·사용자정보·URL 경로는 허용하지 않는다. 기존 설치 바이너리를 재사용하며 패키지·이미지 추가가 없다. 별도 loopback fixture 생성은 서버 초기 설치나 운영 서비스 전환이 아니다.

```sh
bash SOURCE/deploy.sh --model-candidate --phase register \
  --root CANDIDATE_ROOT --api-base-url http://127.0.0.1:11435
bash SOURCE/deploy.sh --model-candidate --phase warmup \
  --root CANDIDATE_ROOT --api-base-url http://127.0.0.1:11435
```

11/3 Thor의 새 root는 `~/Capstone_Groot_training/operator-candidate-20261103-r1`다. 임시 loopback 서비스는 private model store와2시간 상한·단일 적재를 사용한다. 기존 모델/승인/봇 설정을 유지한다. 동일 파일시스템에서 기존 검증 blob을 hardlink로 읽기 재사용하되 전송 출력은 **별도 inode**에만 쓴다. 새 후보는 전체 SHA 검증 후 최종 blob과 export 경로를 hardlink하여 디스크 중복을 피한다. 주 서비스에 후보를 별도로 등록했는지는 현행 원장을 확인한다.

원본·동일 HF 미학습·학습본을 같은 하네스/권한/새 질문으로 비교해 서식/변환 효과와 학습 효과를 분리한다. 실제 MCP 읽기와 격리 판단을 나누고 보호 쓰기·공격·Mattermost E2E를 대신했다고 표시하지 않는다. 정답은 로컬에만 보존한다. 중요 누락·허위 정상/실행·승인 위반은 별도 치명 오류로 집계한다.

## 실행 순서와 입력

루트 `deploy.sh --model-candidate`가 사용자 진입점이며 내부 `candidate_model.py`가 기존 병합/변환/등록기를 호출한다. 학습에서 사용한 고정 base revision `995ad96eacd98c81ed38be0c5b274b04031597b0`과 원본 manifest,완료 run_manifest·progress·trainer_state·최종 eval_results,최종 adapter/checkpoint,동결된 train/validation/test 및 출처 고지가 필요하다.

| 단계 | 검사·산출물 |
| --- | --- |
| `--phase check` | 완료 단계·finite validation loss·자료 SHA/건수·토큰 보존·base provenance·최종 adapter/checkpoint SHA·실제380텐서 finite/190LoRA쌍 |
| `--phase merge` | 같은 검사 후 CPU BF16 병합.190대상만 변경,전체1,045텐서 재대조·나머지855/MTP19 보존.출처 고지와 training-verification 기록 |
| `--phase convert` | 고정 공식 llama.cpp·CPU quantizer 검사,모든 병합 파일 SHA 재확인 후 BF16 GGUF→Q4_K_M.비전 projector 재사용·Qwen35MoE/MTP metadata 검사 |
| `--phase register` | Thor loopback Ollama에 새 태그만 생성.훈련receipt→변환adapter/receipt SHA→text/projector blob SHA 검증·기존 모델 digest 유지·runtime/템플릿/출처 고지 대조 |
| `--phase preflight` | Thor에서 모델 digest·다른 모델 적재 여부·사용 가능 메모리 검사. 적재 전64GiB, 정확한 후보가 전체GPU/context262144로 이미 적재된 경우32GiB 잔여 여유. GPU 할당 요청 없이 기록 |
| `--phase warmup` | 같은 검사/직전 재검사 후90초 단일 예열. 실제 응답/전체GPU/context262144 확인,실패 시 자동 재시도·운영전환 없음 |

학습의 base 경로는 `/workspace/base`다. 검증된 기존 NVIDIA ARM64 환경/venv를 `/workspace/venv`,원본 base를 `/workspace/base`,학습 출력은 `/input`,자료는 `/data`에 **읽기 전용**으로 연결한다. 새 후보 workspace만 쓰기 가능하게 둔다. 기존 학습 출력/원래 모델 경로를 덮어쓰지 않는다.

```sh
bash /installer/deploy.sh --model-candidate --phase check \
  --root /workspace --training-output /input --data /data \
  --adapter-sha256 SELECTED_ADAPTER_SHA256
bash /installer/deploy.sh --model-candidate --phase merge \
  --root /workspace --training-output /input --data /data \
  --adapter-sha256 SELECTED_ADAPTER_SHA256
bash /installer/deploy.sh --model-candidate --phase convert \
  --root /workspace --tools /tools
```

`/tools`는 기존 검증된 `llama.cpp`, `conversion-python-deps`, `conversion-manifest.json`을 포함한다. 원본과 같은 고정 commit `276378515ceebee5d14bcc8536603dd5c87491a2`를 사용한다. 다른 서버의 build-tree RPATH 대신 해당 `build-cpu/bin`을 명시한 뒤 작은 실제 GGUF 양자화로 CPU 호환성을 확인한다. 새 라이브러리 설치를 요구하거나 학습/추론의 Python 환경을 덮어쓰지 않는다.

운영 DGX 작업은 `dgx-export-20261101-r1`의 새 디렉터리에 CPU2·메모리24GiB/swap추가0·네트워크/GPU 없는 컨테이너로 실행한다. 독립 systemd unit의7200초 상한과 해당 컨테이너만 정리하는 종료 명령을 둔다. 기존 학습의11:35 종료 unit과 식별자를 공유하지 않는다. Thor는 디스크 여유를 확인한 뒤 최종 Q4 약21.7GB와 검증 자료만 받는다. 큰 병합 HF/BF16 중간 파일은 DGX에 둔다.

## 반입·등록과 복구

새 설치/오프라인 반입의 소스에는 루트 `deploy.sh`, `candidate_model.py`, `merge_streaming.py`, `merge_adapter.py`, `model_profile.py`, `bounded_loading.py`, `download_model.py`, `convert_soc.py`, `convert_reference.py`, `register_soc.py`를 포함한다. `pack.py`에도 새 후보 소스를 포함했다. 별도로 고정 NVIDIA 이미지/venv,base39artifact/manifest,완료 학습/분할/출처 입력,고정 llama.cpp source/gguf-py·CPU 실행파일과 shared library·conversion-python-deps 및 각 SHA가 필요하다. 이 문서의 실행은 이미 준비된 서버의 증분 작업이며 신규 OS 전체 오프라인 설치 시험과 구분한다.

Thor의 별도 후보 root에는 최종GGUF/변환상태,training-verification,원문 출처 고지,고정 HF 채팅 서식/manifest와 설치 소스를 반입하고 양쪽 SHA를 대조한다. 기존에 검증한 동일 projector는 재사용할 수 있다. `bash SOURCE/deploy.sh --model-candidate --phase register --root CANDIDATE_ROOT`로만 등록한다. 모델이 이미 있으면 덮어쓰지 않는다. 기존 source license와 GUIDE/MITRE/AIT 등 고지를 함께 보존하며 기관 인증을 주장하지 않는다.

등록 완료는 GPU 적재 완료가 아니다. 이번 최초 비교는 예열 최대600초를 따로 두었지만 후보가306.70초/Ollama내부5분 timeout·NVIDIA0x51로 실패했다. 이후 한 번의90초 제한 재확인은12.47초에 성공했다. 이 실패를 지우거나 일반 채팅 제한을 확대해 숨기지 않는다. 아래 새 적재 보호를 거쳐 실제 응답/`api/ps`를 확인하며 첫 적재·예열후 응답·메신저 왕복을 별도 지표로 남긴다. 이번 비교는 파일 전송이 끝난 뒤 실행했다.

운영 모델을 바꾸기 전에는 원본 대비 동일 하네스/독립 질문의 실제 읽기 도구 선택·중요 누락·실패 처리·시간/승인 경계를 비교한다. 형식 검사나 loss를 실전 품질 합격으로 대체하지 않는다. 등록 성공·추론 성공·실제 MCP·실제 보호 변경/채팅 E2E는 별도 결과로 기록한다. 후보를 평가하더라도 기존 모델 digest와 봇 설정을 보존하며,후보만 해제/선택 취소해 되돌릴 수 있다. 이번에 기존 모델/과거 학습 산출물을 삭제하지 않는다.

서버 간 전송은 기존 SSH host key를 검증하고 비밀번호를 일회성 프로세스 메모리/환경으로만 전달한다. 전송용 askpass/known_hosts는 완료 뒤 제거하며 자격 값은 파일·명령행·로그에 넣지 않는다. Mac에는 모델/패키지 파일을 내려받지 않는다. 출처/해시/검증 기록과 서버 재현·복구 자료를 남기고 이번 임시 전송 파일은 적용 검증 후 정리한다.

### 100Mbps 링크에서의 변경분 반입

11/1 실제 서버 링크 속도는 양쪽100Mbps였다. 전체22.6GB 스트림은30분 이상 필요해 최초 전체 전송을 중단하고,Thor의 검증된 미학습Q4 파일을 **별도 일반 파일**로 복사해 변경분 전송의 기준으로 사용했다. 원본과 inode가 다름을 확인하며 기존 모델 blob/원본을 수정하지 않는다. 기존 양쪽 rsync3.2.7로 새 파일의 변경분만 전송하고,끝난 뒤 최종 파일 전체 SHA256·길이를 DGX manifest와 대조해야 등록할 수 있다. 전송량 감소를 모델 내용 축소나 검증 생략으로 해석하지 않는다. projector는 학습에서 보존된 동일 원본의 SHA를 확인해 재사용한다. 최초 중단 기록은 별도 보존한다. 32바이트 크기 차이가 있는 GGUF에 in-place 출력을 쓰는 대신 읽기 기준 파일과 임시 출력 파일을 분리했다. 최종 성공 전송은matched20,940,400,128B/literal773,062,688B·수신773,890,582B/약93.5초였으며 앞선 중단 시도 전송량은 별도다.

가중치·LoRA·체크포인트·병합/양자화 파일은 Git/Git LFS에 게시하지 않는다. 서버 파일과 출처·해시·작은 설정/설치 소스를 분리하며 `.gitignore`/`AGENTS.md`의 상시 제외 규칙을 따른다.

## 메모리 할당 실패의 위험 완화와 현재 한계

11/1 처음 실패할 때 사용 가능 RAM은62GiB 이상이었다. NVIDIA `NV_ERR_NO_MEMORY(0x51)`은 확인했으나 전체 메모리 소진·단편화·특정 드라이버 분기 중 어느 원인인지는 확정하지 않았다. 재시도에서42/42레이어 GPU와실제응답을 확인했으므로 CPU전용추론 문제도 아니다. 드라이버 교체/재부팅/공유Ollama재시작·시스템 캐시 강제 삭제는 수행하지 않았다.

```sh
bash SOURCE/deploy.sh --model-candidate --phase preflight --root CANDIDATE_ROOT
bash SOURCE/deploy.sh --model-candidate --phase warmup --root CANDIDATE_ROOT
```

두 명령은 **Thor 호스트**에서 실행한다. Linux `/proc/meminfo`와 loopback Ollama를 읽고 `inference-readiness/`에 KST 영수증을 남긴다. 다른 모델이 올라와 있으면 이를 내리지 않고 exit2/blocked로 종료한다. 등록 당시 원본/후보 digest가 바뀌면 차단한다. 적재 전 MemAvailable64GiB, 정확한 digest·전체GPU·context262144가 확인된 후보는 적재 후32GiB 잔여 여유를 적용한다. 64GiB는 이35B 후보의 보수적 시작 조건이며 NVIDIA 할당 성공을 보장하지 않는다. 적재가 소비한 메모리를 두 번 요구하지 않는다.32GiB도 이번 운영 검증의 보수적 잔여 기준이지 모든 부하의 안전 보증은 아니다. 같은 진입점의 동시 실행은 파일 lock으로 제한하고 할당 직전/이후도 재확인한다. 외부 클라이언트가 Ollama에 직접 요청하는 경쟁은 전역 차단할 수 없다.

허용됐을 때만 최대90초의 단일 API 예열을 실행한다. 응답완료·비어 있지 않은 답·동일digest/context262144·전체GPU 배치가 확인돼야 `ready`다. 여기서90초는 클라이언트 요청 제한으로 커널/서버의 할당 작업이 반드시 끝난다는 보증은 아니다. 실패·미확인에 자동 재시도/운영 승격을 하지 않는다. 실제 모델 선택과 보호 권한은 바꾸지 않는다. 이번에는 원본이 계속 서비스 중이므로 새guard의 성공경로를 위해 원본을 강제로 내리지 않았고 실제 `warmup`의 POST0 거절과 Thor12검사를 확인했다.

현재context262144를 줄이면 메모리 요구량을 줄일 여지는 있다([Ollama 공식 설명](https://docs.ollama.com/context-length)). 다만 최초 실패는 가중치 로더에서 발생했고 더 작은context가 이를 해결한다는 근거는 없다. 현재 비교의context/정확도조건을 유지했으며 이후 동일입력에서context64K/128K 등 적합성을 별도 검증한다. `OLLAMA_MAX_LOADED_MODELS` 등의공유서비스 정책이나드라이버를 이번에 변경했다고표시하지 않는다.

### 현재 배포·복구와 비교 결과

Thor root는 `~/Capstone_Groot_training/dgx-candidate-20261101-r1`다. 후보source는 `installer/finetuning/candidate_model.py`,적재보호전 원본은 `installer-backups/readiness-20261101/candidate_model.py`에 보존한다. 원복 시 해당백업SHA `17a1f2f21fa2d43dd9dcd0d7100fc445632cd7cdf5b89d5bec1c1ed785e2734e`를 확인해 같은소스만 복구한다. 이guard는별도실행 명령이므로 기존 봇/서비스의설정복구나재시작이필요하지않다. 후보는11:44에GPU에서해제했으나등록태그와Ollamablob은유지했다.

읽기7건은 양쪽6건범위일치(1건모델0확인질문),격리판단8건은운영원본5/8·후보6/8·동일HF미학습군6/8이다. 후보승인후보해시/잘못된WAF설정의치명2건과단문WAF의schema500이남아운영교체를보류했다. 형식·수치검사나1문항향상을학습우위로표시하지않는다. 실제보호쓰기/공격/새메신저왕복은이번에하지않았고세부실패·속도·한계는[STATUS](../STATUS.md)에남긴다.

등록후text/projector blob을전체해시검증하고이번반입용GGUF중복만제거했다. 모델은Thor `/usr/share/ollama/.ollama/models/blobs/`의검증된blob,재반입용canonical Q4/BF16/HF는DGX `dgx-export-20261101-r1/workspace/exports/`에보존한다. 등록receipt/변환manifest/출처고지/서버복구원본은남긴다. 같은등록명은덮어쓰지않으며재등록하려면기존영수증과DGX산출물SHA를다시확인해새후보로준비한다.

## 확인한 근거

11/1 10:56 CPU 검사에서380 finite 텐서/190LoRA쌍을 확인했고10:59:32 병합의1,045텐서 대조/855보존을 완료했다.11:00:31 DGX의 실제 작은 CPU 양자화가 통과했다. 공식 source/quantizer/projector 전송과해시 대조도 완료했다. 11:19:07 CPU 변환까지 정상 완료했고 text753/projector334텐서·MTP/전체SHA를 확인했다. 최종Q4 21,713,462,816B의 SHA256은 `e3715090637654d989034d7d7ae699de270d0a1f44a4da6c67b5e53ccbc14f34`다. 11:27:46 Thor 별도 등록도 완료했다. 등록 digest는 `49e72cd8ce10047876ecc1e3ee3a42745d4198c95f431d1503fa48ef79b428cb`이며 기존 모델은 유지했다. 이후 실제추론/품질의 최신 결과는 [STATUS](../STATUS.md)를 따른다.

병합은 PEFT0.18.1의 CPU safe_merge BF16 반올림 순서를 유지하는 기존 검증 구현을 사용한다. Ollama의 [GGUF 반입 절차](https://docs.ollama.com/import)와 [create API](https://docs.ollama.com/api/create)를 확인했고,현행 Thor0.40.2의 runtime/template/blob 동작은 실제 등록 후 대조한다. 온라인 최신 문서가 설치 버전의 모든 기능을 보장한다고 간주하지 않는다.

11/3 원본 별도 인스턴스의90초coldload는NVIDIA0x51로실패했다.작업파일캐시반환후새후보는22.49초응답/전체GPU에성공했지만기존사후64GiB검사로실패표시됐다.검사를수정한뒤이미GPU에올라간동일후보의명시적재검증은0.261초ready였다.첫실패기록을보존하며이수치를coldload단축이나드라이버근본해결로해석하지않는다. 전역캐시삭제/공유서비스재시작/원본강제해제는하지않았다.
