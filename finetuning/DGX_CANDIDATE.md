# DGX 학습본의 Thor 후보 내보내기

2026-11-01 완료된447건/224step·validation176 학습본을 별도 Ollama 모델로 준비한다. 모델명은 `soc-qwen36:35b-dgx-guide-q4km-20261101`이다. 이 이름의 등록은 두 봇의 운영 모델 선택을 바꾸지 않는다. 현재 진행/검증/Git은 [STATUS](../STATUS.md)가 기준이다.

## 실행 순서와 입력

루트 `deploy.sh --model-candidate`가 사용자 진입점이며 내부 `candidate_model.py`가 기존 병합/변환/등록기를 호출한다. 학습에서 사용한 고정 base revision `995ad96eacd98c81ed38be0c5b274b04031597b0`과 원본 manifest,완료 run_manifest·progress·trainer_state·최종 eval_results,최종 adapter/checkpoint,동결된 train/validation/test 및 출처 고지가 필요하다.

| 단계 | 검사·산출물 |
| --- | --- |
| `--phase check` | 완료 단계·finite validation loss·자료 SHA/건수·토큰 보존·base provenance·최종 adapter/checkpoint SHA·실제380텐서 finite/190LoRA쌍 |
| `--phase merge` | 같은 검사 후 CPU BF16 병합.190대상만 변경,전체1,045텐서 재대조·나머지855/MTP19 보존.출처 고지와 training-verification 기록 |
| `--phase convert` | 고정 공식 llama.cpp·CPU quantizer 검사,모든 병합 파일 SHA 재확인 후 BF16 GGUF→Q4_K_M.비전 projector 재사용·Qwen35MoE/MTP metadata 검사 |
| `--phase register` | Thor loopback Ollama에 새 태그만 생성.훈련receipt→변환adapter/receipt SHA→text/projector blob SHA 검증·기존 모델 digest 유지·runtime/템플릿/출처 고지 대조 |

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

운영 모델을 바꾸기 전에는 원본 대비 동일 하네스/독립 질문의 실제 읽기 도구 선택·중요 누락·실패 처리·시간/승인 경계를 비교한다. 형식 검사나 loss를 실전 품질 합격으로 대체하지 않는다. 등록 성공·추론 성공·실제 MCP·실제 보호 변경/채팅 E2E는 별도 결과로 기록한다. 후보를 평가하더라도 기존 모델 digest와 봇 설정을 보존하며,후보만 해제/선택 취소해 되돌릴 수 있다. 이번에 기존 모델/과거 학습 산출물을 삭제하지 않는다.

서버 간 전송은 기존 SSH host key를 검증하고 비밀번호를 일회성 프로세스 메모리/환경으로만 전달한다. 전송용 askpass/known_hosts는 완료 뒤 제거하며 자격 값은 파일·명령행·로그에 넣지 않는다. Mac에는 모델/패키지 파일을 내려받지 않는다. 출처/해시/검증 기록과 서버 재현·복구 자료를 남기고 이번 임시 전송 파일은 적용 검증 후 정리한다.

### 100Mbps 링크에서의 변경분 반입

11/1 실제 서버 링크 속도는 양쪽100Mbps였다. 전체22.6GB 스트림은30분 이상 필요해 최초 전체 전송을 중단하고,Thor의 검증된 미학습Q4 파일을 **별도 일반 파일**로 복사해 변경분 전송의 기준으로 사용했다. 원본과 inode가 다름을 확인하며 기존 모델 blob/원본을 수정하지 않는다. 기존 양쪽 rsync3.2.7로 새 파일의 변경분만 전송하고,끝난 뒤 최종 파일 전체 SHA256·길이를 DGX manifest와 대조해야 등록할 수 있다. 전송량 감소를 모델 내용 축소나 검증 생략으로 해석하지 않는다. projector는 학습에서 보존된 동일 원본의 SHA를 확인해 재사용한다. 최초 중단 기록은 별도 보존한다.

가중치·LoRA·체크포인트·병합/양자화 파일은 Git/Git LFS에 게시하지 않는다. 서버 파일과 출처·해시·작은 설정/설치 소스를 분리하며 `.gitignore`/`AGENTS.md`의 상시 제외 규칙을 따른다.

## 확인한 근거

11/1 10:56 CPU 검사에서380 finite 텐서/190LoRA쌍을 확인했고10:59:32 병합의1,045텐서 대조/855보존을 완료했다.11:00:31 DGX의 실제 작은 CPU 양자화가 통과했다. 공식 source/quantizer/projector 전송과해시 대조도 완료했다. 11:19:07 CPU 변환까지 정상 완료했고 text753/projector334텐서·MTP/전체SHA를 확인했다. 최종Q4 21,713,462,816B의 SHA256은 `e3715090637654d989034d7d7ae699de270d0a1f44a4da6c67b5e53ccbc14f34`다. 이후 등록/품질의 최신 결과는 [STATUS](../STATUS.md)를 따른다.

병합은 PEFT0.18.1의 CPU safe_merge BF16 반올림 순서를 유지하는 기존 검증 구현을 사용한다. Ollama의 [GGUF 반입 절차](https://docs.ollama.com/import)와 [create API](https://docs.ollama.com/api/create)를 확인했고,현행 Thor0.40.2의 runtime/template/blob 동작은 실제 등록 후 대조한다. 온라인 최신 문서가 설치 버전의 모든 기능을 보장한다고 간주하지 않는다.
