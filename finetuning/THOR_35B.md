# thor-05용 Qwen3.6-35B 학습

## 원인 추적 공백 보완·진단 모듈 격리 빌드 — 2026-10-28 21:18 KST

**커널 전체 교체 없이 실패 정보를 추가할 진단 패치를 작성하고 Thor에서 실제 `nvidia.ko` 빌드를 완료했다. 원래 0x51을 해결한 패치는 아니며 운영 적용 준비 완료로 표시하지 않는다.** [패치·검증기·운영 적용 경계](driver-diagnostics/README.md).

- 동일595.78/commit76b260e...의 세 소스에 실패 분기만 추가 계측했다. 공통 memdesc의 크기/정렬/주소 공간/페이지 정책, 메타데이터 실패 크기, OS 페이지 실패의 order/GFP/node/진행 위치, 최종 OS 반환 상태를 `GROOT_ALLOC`으로 남긴다. 할당/재시도/해제/반환·기존 오류는 보존하며 커널 상세 로그는 rate limit을 둔다. 주소/텐서/비밀 값은 기록하지 않는다.
- 공식 전체 소스24,899,961B를 작업 임시 경로로 받아 SHA/고정3파일을 대조하고 Thor 별도 폴더로 반입했다. 신규 패키지 설치0. 원본/패치 적용/역적용 바이트 일치와 변조·symlink 거부5검사 및 전용4검사 통과, 전체172검사 중 host Torch3건은 기존과 같이 생략했다. 이번에 새로운 실제Torch CPU 검사를 수행한 것으로 집계하지 않는다.
- 빌드는 일반 사용자·CPU2/메모리8GiB/15분 제한·네트워크/GPU 장치/모듈 로딩 금지·시스템 읽기 전용/별도 작업 경로만 쓰기로 수행했다. 첫 시도는 사용자 Git 설정 경로 문제, 다음 두 시도는 보호된 모듈 경로로 헤더 링크를 해석한 문제로 중단됐다. Git 설정은 프로세스에서만 제외하고, 격리 시작 전 확인한 실제 헤더 경로를 고정해 성공했다. 보호 기능과 기존 사용자 설정은 바꾸지 않았다. 실패/성공 로그는 구분해 보존한다.
- 실제 common RM 컴파일과 커널 모듈 연결 성공·21:16:06KST 완료. 모듈22,294,960B/SHA`a5ff6fe6f65277dfad773950cc7252ec58b33b5b5d0bf6af1e0c90a4f1fdde53`, version595.78/vermagic6.8.12-1021-tegra 일치다. **실행 커널 GCC13.2와 현재 컴파일러13.3 차이 경고**, 기존 소스의 주소 비교/선언 경고가 남아 있다. 숨기거나 오류0으로 쓰지 않는다.
- 후보는 unsigned이고 기존보다 `tsecriscv` 의존성이 추가됐다. 동일vermagic의 의존 모듈 파일은 이미 있으나 실행 ABI·서명 정책/전체 빌드 구성 일치가 검증된 것은 아니다. 운영 원본SHA`9ef9396ca6475c58152e8649d8fa437df1912141af2830955b21ebc81e466f88`와 기존 모듈/부팅 설정은 보존했다. 아직 deployable 후보로 승인 요청하지 않는다.
- 현재 DRM/modeset/UVM이 참조 중인 공유 GPU이므로 기존 짧은 학습 중단 승인을 드라이버 교체/화면 중단/재부팅 승인으로 확대하지 않는다. 이번에는 추론 stop·모듈 설치/언로드/로딩·initramfs/부팅/전역 정책 수정0·새GPU재현0이다. `deploy.sh` 자동 설치 제외, 휴대용 반입 목록은 진단 텍스트/검증기까지 포함한다.

남음: 정확한 빌드 도구체인·BSP 구성/의존 ABI·서명과 복구 콘솔/원복 경로를 검증한 유지보수 시험 환경에서 계측 모듈을 로드하고 원래0x51을 재현해야 한다. 그때 확인한 실패 분기에 맞춰 수정·반복 검증해야 근본 해결로 판정할 수 있다. 이번 빌드 성공은 원인 확정·경고 제거·실제 SOC 정확도/MCP/채팅/보호E2E·새 서버 전체 설치를 뜻하지 않는다. 기존 VMM/선택loss의 메모리 감소 효과와 운영 원35B는 유지한다.

## 드라이버 내부 실패 조건 점검 — 2026-10-28 20:53 KST

**원래 `NV_ERR_NO_MEMORY`(0x51)를 반환한 정확한 분기는 아직 특정하지 못했다.** 같은 595.78 공식 소스와 실제 커널 할당 스택을 대조했다. 이번에는 복구 가능한 하위 할당 실패를 관측했지만, 원래 경고는 재현되지 않았다. 기존 메모리 최적화는 유지하며 드라이버 원인 해결 완료로 표시하지 않는다.

- `mem_desc.c:1336`은 `_memdescAllocInternal`의 실패를 기록하는 공통 지점이다. 시스템 메모리 경로의 `nv_alloc_pages`에서는 할당 정보/페이지 표 생성 실패, `nv_alloc_system_pages`에서는 실제 페이지 블록 요청이 끝내 실패할 때 0x51을 반환할 수 있다. 다른 주소 공간·후속 단계도 있어 이 로그 한 줄로 어느 분기인지 정할 수 없다. `page_count`는 OS의 4KiB 페이지 수이며 요청 바이트는 `page_count*4096`이다. 큰 페이지 정책 값과 곱하면 오산이다.
- 이번 스택의 NVIDIA 할당 경로에서 `kvmalloc_node`의 2~32MiB 연속 블록 선호 요청 실패를 관측했다. 후속 CUDA 작업은 모두 성공했다. 소스의 vmalloc 대체 경로와 부합하지만 실제 대체 함수의 반환값까지 직접 추적한 것은 아니다. 이 실패를 원래의 최종 0x51 반환으로 간주하지 않는다.
- 실제 native 모델 1-step에서는 2MiB CPU THP 요청 실패144건과 NVIDIA/kvmalloc 경로 실패4건(2MiB1·4MiB1·8MiB2)을 관측했다. THP 스택은 `do_huge_pmd_anonymous_page`로 GPU 데이터 할당 실패와 구분한다. 실패 스택에 `nv_alloc_system_pages`가 직접 포함된 사례는 없었다. 관측 범위는 지정 PID/알려진 TID이며 서버 전체 모든 할당을 뜻하지 않는다.

| 실행한 진단 | 하위 페이지 요청 실패 | 관련 커널 경고 | 결과 |
|---|---:|---:|---|
| CUDA64MiB/2GiB·서비스 유지 | 0 | 별도 구간 집계 없음 | 할당/해제 성공 |
| 큰 할당+임시 작업 공간 | 8MiB2·16MiB1 | 0 | 모든 CUDA 요청 성공 |
| 8GiB 추가 요청 보호조건 확인 | 0 | 0 | 여유2GiB 조건으로 해당 요청 생략 |
| 허용 범위5.75GiB 작업 공간+첫 커널 실행 | 32MiB1 | 0 | 성공, 최대 동시 약74.16GiB |
| 실제 Torch dense log-softmax 역전파 모사 | 0 | 0 | 성공, 최대72.81GiB |
| 기존 native35B·전체loss·1-step/eval8 | THP144+기타4 | 0 | 정상 완료, 최대70.37GiB |

**앞선 12→3→0은 각 단기 실행에서 관측한 수치다. 이번에는 최적화를 끈 native 경로도 첫 step까지 경고0이므로, 개선 코드가 경고를 없앤 유일한 원인이라고 단정할 수 없다.** 이번 대조는 1-step으로 이전2-step보다 짧다. 메모리 peak70.37→66.87GiB 감소와 정답/기울기 보존 검증은 유효하지만 경고의 인과 검증과 분리한다. 풀·캐시·단편화 상태의 영향은 가능성으로 남긴다.

현재 커널6.8.12-1021-tegra에는 `CONFIG_KPROBES`, `CONFIG_FUNCTION_TRACER`, kernel/module BTF가 없다. 기존 tracefs의 정적 `mm_page_alloc`/CMA 이벤트·전용 인스턴스·PID/TID 제한 스택만 사용했다. 수집기의 overrun/commit-overrun/drop 및 읽기 오류0, native 원문 잘림0을 확인했고 전역 tracer/clock/동적 이벤트는 변경하지 않았다. 드라이버·커널 재빌드/교체, 전역 VM/THP/cache 변경, 임의 fault injection은 수행하지 않았다.

**이전 분류 정정:** 아래 18:43 결과의 “훈련73건/복구후1건”은 잘못된 분류다. 원문74건은 모두 훈련 구간이며, 0x51 73건과 별도 상태 전환 오류0x56 1건(18:12:34.003106 KST)이다. 복구 시작은18:14:34.859 KST로 복구 후 오류가 아니다. 0x56의 원인은 미확정이며 이전 기록은 당시 이력으로 보존한다.

다섯 중단 구간 합계216.20초, 가장 긴 native 구간146.53초 후20:35:23.989 KST 원래35B를 복구했다. 20:52:55 KST 서비스active·원digest 상주·관련 추가 커널 오류0·전용 타이머/작업 비활성·전용 trace 인스턴스/컨테이너 잔여0·복구 스크립트SHA불변을 재확인했다. 서버에는 root 전용 `/var/lib/capstone-driver-allocation-20261028/` 보고서와 학습 루트 `driver-allocation-20261028/native-01/`의 진단 결과를 보존한다. 새 운영 모델 등록/봇 전환·본학습·SOC 정확도/MCP/채팅·공격탐지대응E2E·새 서버 설치는 수행하지 않았다. 이번 변경은 문서이며 이전168검사/실제CPU3검사를 새 시험 결과로 중복 계산하지 않는다.

원래 경고가 다시 발생하는 조건에서 실패 요청 인자와 최종 반환 분기를 함께 수집해야 원인을 확정할 수 있다. 현재 커널 기능만으로 직접 함수 인자/반환 추적이 제한되어, 추가 계측은 별도 커널/드라이버 준비와 중단 범위 검토가 필요하다. 자동 재실험은 예약하지 않았다.

공식 근거: [NVIDIA Jetson39.2.1/595.78 고정 소스](https://gitlab.com/nvidia/nv-tegra/tegra/kernel-src/nv-unified-gpu-display-driver/-/blob/76b260e5967dfe9815b9054a4a4642f10672a763/src/nvidia/src/kernel/gpu/mem_mgr/mem_desc.c#L1336), [nv_alloc_pages/메타데이터](https://gitlab.com/nvidia/nv-tegra/tegra/kernel-src/nv-unified-gpu-display-driver/-/blob/76b260e5967dfe9815b9054a4a4642f10672a763/kernel-open/nvidia/nv.c#L391), [페이지 블록 실패 반환](https://gitlab.com/nvidia/nv-tegra/tegra/kernel-src/nv-unified-gpu-display-driver/-/blob/76b260e5967dfe9815b9054a4a4642f10672a763/kernel-open/nvidia/nv-vm.c#L990), [Linux kvmalloc fallback](https://raw.githubusercontent.com/torvalds/linux/v6.8/mm/util.c), [kprobe 구성 요건](https://docs.kernel.org/trace/kprobetrace.html).

아래는 앞선 각 시점의 기록이다.

## 개선 적용 결과·현재 사용 기준 — 2026-10-28 18:43 KST

**같은 고정35B/자료/LoRA와 최장2prefix·2-step/eval8에서 VMM+정답위치 projection의 경고0건을 확인했다.** 원래35B는18:36:27.146KST복구했고 중단은168.966844초다. 아래는 각각1회의짧은실행이며 캐시/단편화상태를동일하게고정한반복실험은아니다.

| 실제비교 | 기본 할당·기존loss | VMM만 | VMM+정답위치loss |
|---|---:|---:|---:|
| 같은 커널 할당 경고 | 12 | 3 | **0** |
| CUDA peak allocated(GiB) | 70.37 | 70.35 | **66.87** |
| CUDA peak reserved(GiB) | 71.88 | 71.60 | **67.05** |
| host 최저 가용(GiB) | 43.80 | 43.64 | **48.27** |
| 2-step/eval8·정상종료 | 완료 | 완료 | 완료 |
| 새PyTorch/host/cgroup OOM | 0 | 0 | 0 |

NVIDIA595.78의`mem_desc.c:1336`은내부메모리할당실패로그다. 공식소스에는큰페이지실패뒤작은페이지로재시도할수있는경로가있다. 실제실패요청의크기·페이지종류·fallback성공을직접관측한것은아니다. CPUtrace첫20경고가log-softmax역전파와겹치는상관을찾아불필요한큰임시텐서를줄였다. profiling실행자체는훈련73건/복구후1건으로달랐으므로위정량비교에서제외한다. 경고0단기결과를드라이버결함완전해결·장기누수없음으로확대하지않는다.

입력문맥1664/1582토큰은모두backbone을통과한다. LMhead와loss에서만causal정답이있는56/58개위치를선택하며학습114개·평가292개정답을전부보존했다. `supervised_positions`는전후정답개수를대조하고빈정답·충돌옵션을거부한다. 실제CPU의마스크/패딩/배치합집합·문맥을연결한모델에서손실과모든파라미터기울기동등성,실제Trainer2회누적/평가를검증했다. GPU부동소수계산의bit동일·새정확도우위를보장하는검사는아니다.

후속Thor훈련컨테이너는`PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True`를기본사용한다. 고정`qwen3_5_moe`프로필은`assistant_only_logits`기본True이며명시False를보존한다. 직접실행하는경우에도승인된중단/복구절차안에서같은프로세스할당설정을사용해야한다. 기본재현`soc-memory-smoke`는native,기본/VMM/trace대조단계의선택loss는False로유지해과거비교의의미를보존한다. 일반30B/NF4프로필에는선택loss기본값을넣지않는다. loss-only평가·기존mean/누적정규화계약을보존하고미검증조합은거부한다.

기본값동기화후로컬/Thor168검사중hostTorch3검사는생략했고동일기존이미지의GPU미노출실제3검사로확인했다. 실제개선옵션GPU2-step/eval8·완성어댑터380finite/190Bnonzero,기존R2 24/48checkpointSHA불변을검증했다. 어댑터SHA는`6d11e47463541aa6795dc2f22cab869ed911a3d1b422338485df723fe48b64e7`다. 새모델등록/봇전환은없으며원35B를유지한다. 이번완료는긴48-step본학습/모든길이·배치/장기안정성·독립정확도/MCP·채팅·보호E2E검증이아니다.

증거는서버`memory-fix-20261028/`의각비교audit/기본값·가중치검증과`outputs/soc-memory-loss/completion-loss-selection.jsonl`에보존했다. 대형CPUtrace는`outputs/soc-memory-trace/first-step-trace.json.gz`로보존하고압축복원SHA일치를확인한뒤raw만정리했다. 원본SHA`462758969a8c28ffd0332e98ba06c0308eef1e3687f1b65b2b720bb42ac0ae50`,gzipSHA`7f280e61ae6ad2afa7ffcf73771706358a3aaa2ea02aa78af8a30576c21f642a`다.18:43KST원35Bactive/digest상주·복구timer3개inactive·복구후추가관련커널경고0을확인했다. 아래항목은각시점의진행이력이다.

## 경고 연산·정답 위치 projection 수정안 — 2026-10-28 KST

CPU trace와 커널 절대시각을 맞춘 첫20개 경고는 `aten::_log_softmax_backward_data`/그 autograd 호출과 겹쳤다. 이것은 호출 구간의 상관 증거이며 실패 페이지 크기까지 추적한 것은 아니다. 추적 실행은 학습73건으로 비추적VMM3건보다 많았다. profiling과 실행 당시메모리 상태의 영향을 분리하지 못해 이 수치로 회귀/개선을 판단하지 않는다. 전체1,480,316,893B trace는 서버에서 스트리밍 해석했고 Mac에 받지 않았다.

기존 completion-only 학습은 prompt labels를-100으로 무시하지만, 각 입력 위치의 큰 어휘 logits와 log-softmax backward tensor는 계산한다. 새 `completion_loss.py`는 입력 문맥을 전부 backbone에 넣은 뒤 causal shift 후 실제 정답이 있는 위치만 LM head로 선택한다. 배치별 위치의 합집합을 사용하며 나머지 배치의-100은 유지한다. 정답 토큰 개수를 전후 대조하고 supervision이 없거나 외부 logits 옵션이 충돌하면 거부한다.

고정 Qwen conditional model의 `logits_to_keep`는 Tensor 선택을 지원하지만 자체 loss 호출은 kwargs의 shift_labels를 전달하지 않는다. 따라서 전용 Trainer가 선택된 logits와 정렬한 targets를 공식 `ForCausalLMLoss`에 명시 전달한다. 기존 mean loss·Trainer gradient accumulation 경계를 유지하며, 추가 num_items 정규화/label smoothing·임의 compute_loss_func·loss-only가 아닌평가는 거부한다. [고정 모델 구현](https://raw.githubusercontent.com/huggingface/transformers/v5.4.0/src/transformers/models/qwen3_5_moe/modeling_qwen3_5_moe.py) · [공식 loss 구현](https://raw.githubusercontent.com/huggingface/transformers/v5.4.0/src/transformers/loss/loss_utils.py).

실제 CPU Torch/Transformers에서 손실과 모든 파라미터 기울기를 기존 방식과 대조했다. 다른배치의 정답 위치·마스크 구멍/패딩·마지막토큰을 포함하고 누적 문맥을 갖는 backbone으로 문맥 gradient 보존을 확인했다. 실제 Trainer2회누적1step과 loss-only평가도 통과했다. 세 검사에서CUDA초기화0이며 host전체166검사는Torch3건생략/별도실제CPU3건완료로 구분한다. 최초toy fixture의label_names/ModelOutput계약오류는 실제학습과같게 고친 뒤통과했다.

새 `soc-memory-loss`/`--mode memory-loss`는 VMM과해당옵션만사용하며 profiler를끄고최장2prefix/2-step/eval8·6분학습제한/8분독립복구/기존35B유지를따른다. 새config/출력/상태로이전R2·기본/VMM/trace증거를보존한다. 아직35BGPU경고해결·기본활성화/장기시험·정확도개선평가는완료하지않았다.

## VMM 실제 결과·잔여 연산 추적 — 2026-10-28 18:02 KST

같은35B/자료/LoRA/2-step·최장2prefix·eval8의 VMM 비교를 완료했다. baseline과 manifest 차이는 output_dir뿐이며 data/학습파라미터는 같다. 기존12건 중 적재 때의 경고는 이번0건이지만 첫 연산에3건이 남았다. 한 번씩의 순차 비교이므로 캐시·단편화 상태도 달랐으며, 감소 전부를 설정 효과로 확정하지 않는다.

| 확인 항목 | 기본 재현 | VMM 비교 |
|---|---|---|
| 같은 NVRM 경고 | 12건(적재 중8/직후4) | 3건(첫 학습 연산 도중) |
| 2-step/평가·종료 | 완료·exit0 | 완료·exit0 |
| PyTorch 재시도/OOM·새 강제종료 | 각0 | 각0 |
| CUDA peak allocated/reserved | 70.37/71.88GiB | 70.35/71.60GiB |
| host 최저 가용 | 43.80GiB | 43.64GiB |
| 원35B 복구·실제중단 | 17:08:17KST·172.42초 | 18:01:18KST·174.50초 |

VMM에서는12표본 모두 실제 expandable segment2개였다. 사전할당은17:58:35.131~36.127KST, 적재완료17:59:46.883KST이며3건은17:59:55.395~55.471KST다. 이3건을 특정 cuBLAS/cuDNN/연산 또는 실패페이지 크기에 귀속할 증거는 아직 없다. 기존R2 24/48checkpoint SHA는 불변이고 새 모델 등록·운영전환은 없다.

이를 분리하려고 `soc-memory-trace`/`--mode memory-trace`를 준비했다. 같은VMM·2-step과 복구 경계를 유지하고 첫step의 CPU operator 시간만 별도 Chrome trace에 저장한다. 프로세스 내부 CPU 시간 기록이며 텐서값·shape·스택·GPU활동 프로파일을 저장하지 않는다. trace 절대기준시각을 커널 KST와 맞춰 겹치는 연산을 조사한다. 새 출력/상태와 root 복사본을 사용하고 기존재현은 보존한다. 로컬/Thor163검사·실제GPU미노출CPU profiler/시각기준·무중단check 완료, 실제추적은시작전이다. VMM의전체학습기본적용·잔여경고해결·장기안정성은미완료다.

## 경고의 의미·VMM 비교 경로 — 2026-10-28 KST

공식 Jetson39.2.1 태그의 `version.mk`는595.78/r595_00이며 실제 드라이버와 맞는다. 이 태그의 `mem_desc.c:1336`은 내부 메모리 할당 실패를 오류 수준으로 기록한다. `system_mem.c`는 기본 페이지 선택과 허용 조건에 따라 더 작은 페이지로 재시도할 수 있다. 따라서 이 메시지와 학습 성공이 함께 나타날 수 있지만, 이번12건의 내부 요청/페이지 크기·최종 재시도 성공을 직접 추적한 것은 아니다. [NVIDIA 공식 소스 안내](https://docs.nvidia.com/jetson/archives/r39.2.1/DeveloperGuide/SD/WorkingWithSources.html) · [할당 오류 위치](https://gitlab.com/nvidia/nv-tegra/tegra/kernel-src/nv-unified-gpu-display-driver/-/blob/76b260e5967dfe9815b9054a4a4642f10672a763/src/nvidia/src/kernel/gpu/mem_mgr/mem_desc.c#L1336) · [재시도 경로](https://gitlab.com/nvidia/nv-tegra/tegra/kernel-src/nv-unified-gpu-display-driver/-/blob/76b260e5967dfe9815b9054a4a4642f10672a763/src/nvidia/src/kernel/mem_mgr/system_mem.c#L227).

설치된 Transformers5.4.0 소스 SHA는 고정 공식 버전과 일치한다. 이 로더는 모델 전체 크기의 큰 텐서를 먼저 할당/반환해 캐시를 준비한다. 앞선 재현의 inactive split peak 약64.45GiB와 연결해 확인할 후보이며, 이 단계가12건 모두의 원인이라는 증거는 아직 없다. 새 hook은 실제 원래 함수를 그대로 호출하면서 사전 할당 시작/완료/실패 시각을 기록하고 종료·예외 후 함수를 복원한다.

작은 CUDA 단일 할당64MiB~2GiB는 모두 성공했다. 기존 오프라인 Torch 이미지에서도 기본 방식과 `PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True`를 각각 최대2GiB 할당·일부 쓰기·해제로 확인했다. VMM 방식의 실제 expandable segment2개, 양쪽 OOM/재시도0·커널 경고0이며 Ollama는 계속 active였다. 작은 시험이35B 전체 모델의 경고 해결을 입증하지는 않는다. 이 설정은 PyTorch의 실험적 기능이며 모델/길이가 달라질 때도 별도 검증해야 한다. [PyTorch2.8 메모리 설정](https://docs.pytorch.org/docs/2.8/notes/cuda.html#optimizing-memory-usage-with-pytorch-cuda-alloc-conf).

전용 `soc-memory-vmm` 컨테이너에만 해당 환경변수를 적용하고 `training_window.py --mode memory-vmm`로 비교한다. 기존 기본 방식/출력은 보존한다. 최장2prefix·2-step/accum1·eval8·6분 학습 제한·8분 독립 복구/복구실행6분·최대15분 한도와 원래35B digest 복구 조건을 유지한다. 새 출력은 `outputs/soc-memory-vmm`, config는 `config.soc-memory-vmm.run.local.json`, 상태는 `/var/lib/capstone-memory-vmm-20261028`, root 복사본은 `/usr/local/libexec/capstone-memory-vmm-window.py`다. 기존 결과와 같은 새 결과의 자동 덮어쓰기/재시도는 거부한다.

로컬/Thor160검사와 실제 GPU 미노출 Torch/Transformers hook·함수 복원·CUDA 초기화0 검증, 서비스 조작 없는 준비 check까지 완료했다. 새35B 비교 결과는 후속에 기록한다. GPU 할당 보호가 완전한 cgroup 제한으로 대체된 것은 아니므로 host12GiB guard를 유지한다. 운영 모델/드라이버/VM전역 설정은 바꾸지 않는다.

## 실제 메모리 재현 결과 — 2026-10-28 17:05~17:08 KST

**같은 NVRM `NV_ERR_NO_MEMORY` 경고 12건을 재현했으며, 학습은 2-step 모두 완료했다.** 최대15분 중단 승인 아래 6분 학습 제한·8분 독립 복구 타이머를 적용했다. 기존 `qwen3.6:35b`는 원래 digest로 복구됐고 실제 중단은172.42139초(2분52.42초)다. 경고의 정확한 내부 할당 원인은 미확정이다.

| 실제 GPU 실행·복구 확인 | 결과 |
|---|---|
| 별도 단계·출력 | `soc-memory-smoke` / `outputs/soc-memory-smoke/` |
| 입력·연산 | 같은 고정 R2 원본·프로필, 전체390 train prefix 검증 후 최장1664/1582토큰 2개 선택, 2-step/accumulation1, validation8 |
| 공유 추론 중단·복구 | 17:05:25.114144~17:08:17.535534 KST; 완료 즉시 복구 |
| 모델 적재 완료 | 17:06:47.109616 KST 진단 표본 |
| 같은 커널 경고 | 17:05:56.281989~17:06:47.820223 KST, 적재 중8건·완료 직후4건; 복구 구간0 |
| CUDA 최대 allocated/reserved | 70.37/71.88GiB, native allocator |
| PyTorch 할당 재시도·OOM | 10표본에서 각0; 모든 드라이버 내부 할당을 포괄하는 카운터는 아님 |
| 종료·host guard | Docker exit0/OOMKilled=false, 최저 가용43.80GiB, 12GiB 보호 여유 유지 |
| OOM-kill | host 누적1→1, cgroup oom/oom_kill0; 새 강제 종료0 |
| 기존 체크포인트 보존 | R2 24/48-step 어댑터 SHA 불변; 새 등록/운영 승격0 |

모델 적재 전→완료 시점에서 host MemAvailable은117.39→51.42GiB, CMA free는6.289→0.312MiB였다. 실행 마지막에는43.80GiB/1.773MiB였다. 처음→마지막 표본의 `allocstall_normal`은1921, `compact_stall`은3926, `compact_fail`은1937, `compact_success`는1989 증가했다. 이는 회수·압축 활동이 있었다는 관측이다. 실패 요청의 크기·메모리 종류·정렬을 모르므로 CMA 부족이나 단편화가 경고의 원인이라고 확정할 수 없다. Python OOM이 없었다는 사실 역시 드라이버 경고가 무해하다는 증거는 아니다.

cgroup peak는 약3.18GiB였지만 같은 프로세스의 CUDA peak allocated는70.37GiB였다. 따라서 이 Thor 실행에서 Docker112GiB cgroup 제한을 전체 GPU 메모리 사용량 제한과 같게 해석하지 않는다. 기존 host 가용 메모리 보호를 유지한다. 단일 짧은 재현은 장기 누수·하드웨어 정상 여부·본 학습 안정성을 판정하지 못한다.

증거는 Thor `~/Capstone_Groot_training/qwen36-20261027/memory-repro-20261028/reproduction-audit.json`, 새 출력의 `memory_telemetry.jsonl`·`progress.json`·`run_manifest.json`, 별도 window/restore 상태에 보존했다. 기존 R2 출력·실행config·원본 가중치는 보존했다. 재현용2-step 어댑터를 변환·등록하거나 봇에 적용하지 않았다. loss와2-step 성공은 정확도 개선 평가가 아니다.

남은 원인 조사는 실패한 드라이버 할당 요청의 종류·크기 확인과 같은 조건의 장기 안정성 검증이다. 드라이버/캐시/CMA 설정 변경, 재부팅, 추가 GPU 실험은 이번 재현에 포함하지 않았다. 실제 채팅·MCP·보호 변경 E2E도 실행하지 않았다. 아래 준비/점검 내용은 재현 전 시점의 이력이다.

> **메모리 재현 준비:** operator `training_window.py --mode memory-repro`와전용 `soc-memory-smoke`를추가했다. 최장2prefix/2step·새결과경로·6분학습제한/8분독립복구·기존35B유지,로컬/Thor155검사와무중단전제조건검증완료다. 공유추론최대15분중단확인은진행중이며아직GPU실행하지않았다. [실행상태](../STATUS.md).

## 메모리 점검 후속 — 2026-10-28 KST

**현재 추론은 가동 중이며, 경고의 정확한 할당 원인은 아직 확정하지 않았다.** Jetson Linux39.2.1/kernel6.8.12-1021-tegra/driver595.78에서 운영35B를 유지한 채 로그·자원만 점검했다. 새 GPU 학습이나 부하 재현은 하지 않았다.

| 실제 확인 범위 | 결과 |
|---|---|
| 15:38 KST 전체/가용 RAM | 약122.8/85.7GiB |
| 기존 Ollama GPU 프로세스 | 1개, 약29.6GiB로 보고됨; OS 수치와 합산하지 않음 |
| 15:51:24~15:51:56 KST, 5회 읽기 전용 관찰 | 가용85.66~85.69GiB; oom_kill/allocstall/compaction 카운터 증가0 |
| 오늘 NVRM 할당 경고 | 학습50건 + 비교 모델 적재2건 =52건 |
| 실제 OOM 종료 | 10/27 16:20:43 KST 실패한 첫 학습1건; 오늘 새 종료0 |
| 15:01:53~15:53:34 KST 커널 재조회 | 추가 NV_ERR_NO_MEMORY/Xid/OOM kill/page allocation failure0 |

학습50건은 긴2prefix smoke에49건,48-step pilot에1건이다. smoke2건은 가중치 적재 중,47건은 적재 완료11:03:23 직후11:03:24~31에 발생했다. pilot1건은 적재 완료11:06:27 뒤11:06:52에 발생했다. 당시 LoRA 설정·학습 초기화·첫 연산의 세부 경계를 남기지 않아 어느 내부 라이브러리 요청인지 분리할 수 없다. 두 단계는 exit0/가중치finite이며 host 가용 최저는 각각43.87/32.52GiB였다. 추론 적재2건은14:26:38/15:01:52이고 해당 모델은42/42층 GPU 적재 후 응답했다. 이를 메모리 부족이 무해하다는 판정으로 확대하지 않는다.

CMA는512MiB 중 약6.2MiB가 남아 있고 큰 연속 블록도 제한적이지만, 과거 실패 요청의 크기·주소 공간·요구 정렬·당시CMA를 기록하지 않아 CMA 부족/단편화를 원인으로 확정할 수 없다. 현재 NvMap clients가0K여도 GPU 사용0이 아니며, nvidia-smi 전체 메모리N/A도0으로 해석하지 않는다. PSI는 커널 CONFIG_PSI 비활성으로 미제공이다. VM 카운터는 부팅 이후 누적값이므로 어제 OOM1건을 오늘 장애로 합산하지 않는다.

Thor의 CPU/GPU는 같은 물리 DRAM을 사용하며, OS·CUDA·NVML의 계측 범위가 다르다. [CUDA for Tegra13.0](https://docs.nvidia.com/cuda/archive/13.0.0/cuda-for-tegra-appnote/index.html#estimating-total-allocatable-device-memory-on-an-integrated-gpu-device). KReclaimable은 회수 가능한 커널 할당 추정값이며 실제 즉시 할당 성공을 보장하지 않는다. [Linux proc 문서](https://www.kernel.org/doc/html/latest/filesystems/proc.html). 설치된R39.2.1의 공식 문서에도 CUDA 서버 종료 후 캐시가 남는 알려진 이슈5661165가 있지만, 이것이 이번 경고의 확정 원인이라는 증거는 없다. [NVIDIA 릴리스 노트](https://docs.nvidia.com/jetson/archives/r39.2.1/ReleaseNotes/Jetson_Linux_Release_Notes_r39.2.1.pdf).

### 다음 실행에 적용할 진단 기록

`train.py`는 `memory_telemetry.py`를 통해 새 출력 폴더의 `memory_telemetry.jsonl`과 `progress.json.memory`에 다음을 기록한다.

- 적재 전/후, 학습 시작·step/log·완료, Python 적재/학습 예외 시각(KST)과 단계.
- 현재/peak CUDA 할당·예약·미사용 분할 블록, `num_alloc_retries`와 `num_ooms`, CUDA free/total 및 allocator backend.
- host MemFree/MemAvailable/Cached/KReclaimable/CMA, 누적 VM 카운터, 관측 cgroup의 current/peak/max/events.
- 미제공·조회 실패·기록 실패를 상태로 남긴다. 오류 전문·환경 변수·사용자 데이터는 기록하지 않는다. CUDA를 초기화하거나 캐시/누적 카운터를 비우지 않는다.

PyTorch의 재시도 카운터는 실패 후 캐시 반환·재시도를, OOM 카운터는 던져진 OOM을 구분한다. 이 카운터는 해당 PyTorch allocator 범위이므로 드라이버나 다른 라이브러리 내부 오류 전체를 대표하지 않는다. [PyTorch2.8 문서](https://docs.pytorch.org/docs/2.8/generated/torch.cuda.memory.memory_stats.html).

로컬/Thor **150검사 통과**, 기존 학습 이미지의 GPU 미노출 CPU 컨테이너에서도 Torch2.8 import·CUDA 미초기화·실측 host/cgroup 기록을 확인했다. 호스트에는 Torch가 없어 최초 호스트 import 검사는 실패했고, 설치를 추가하지 않고 원래 컨테이너 환경에서 정정 검증했다. 컨테이너는 종료 후 자동 제거했다. 실제 GPU 실행에서 새 기록과 경고의 상관을 검증하는 단계, 장기 누수/최대 부하/메모리 소자 검사는 미완료다. 추론 설정·driver·96GiB 시작 기준·12GiB guard·가중치·학습 설정은 유지했다. 다음 승인된 실험에서 먼저 이 기록으로 실패 요청 유형을 구분하며 이번 점검으로 새 학습을 예약하지 않는다.


> **10/28 R2 비교 마감:** 기존 회귀의 호출13/16→16/16·필드29/36→36/36 회복. 새 질문은 원본 우위가 입증되지 않았고 누락·잘못된 대상이 남아 운영35B를 유지한다. 최종/회귀 완료·실제MCP/E2E 미실행·후속과 [세부 근거](R2_RESULTS.md)를 구분한다.

> **10/28 개발 비교 완료:** 두 후보 등록·원본/control/24/48 개발 비교를 끝냈다. 필수 도구27/30이 남아 운영 모델을 유지하며,24-step 사전 선택 후 미사용 최종·기존 회귀 시험 중이다. [실제 결과·제한](R2_RESULTS.md).

> **10/28 비교 진행:** 24-step 비교 태그/개발65턴 완료, 48-step CPU 양자화 중. 필수 도구27/30으로 미해결이 있어 원본35B를 유지한다. 시간 환산·선택 ID 채점 정정은 모든 모델에 동일 적용하며 미사용 최종/기존 회귀는 후보 선택 후 진행한다. [STATUS](../STATUS.md).

> **10/28 실제실행:** R2 2-step/48-step을완료하고38분16초만에원35B복구·timerinactive를확인했다.24/48checkpoint가중치는검증했고CPU비교변환중이다. 커널드라이버메모리경고50건은미해결이며정확도개선·새모델승격은아직없다. 아래실행전기록과현황을구분한다.

> **현행 v2 후보는 R2:** 자료 경로 `data-soc-source-v2-r2/cases.jsonl`·`data-soc-v2-r2/`, strict2048/390·65·65prefix/122검사다. 아래 최초v2 예제/1536 결과는 보존된 이력이며 다음 후보에는 R2를 사용한다. 새 GPU 실행은 operator 복구 제어기와 별도 중단 시간대 승인 후에만 진행한다.

> **10/27 21:40 SOC 비교 마감:** 본 학습224prefix/112-step·HF/GGUF 내보내기와 별도 모델 등록을 완료했다. 동일 HF 미학습본/학습본의 필요한 도구 호출은16/16→13/16, 요청 필드 최종 답변은36/36→29/36으로 퇴행해 이번 학습본은 운영 적용에서 제외한다. 기존35B는20:41 KST 복구/21:38 재확인했고 봇 선택은 유지했다. 저장 위치는 Thor `~/Capstone_Groot_training/qwen36-20261027`이다. 실제 토크나이저320prefix 검사 통과, 원인 확정·재학습·MCP/채팅/보호 E2E는 후속이다. 아래 시점별 진행 기록과 [최신 결과·검증 범위](../STATUS.md)를 구분한다.

> **10/27 20:54 SOC 본 학습 완료:** Thor `~/Capstone_Groot_training/qwen36-20261027`에서224prefix1epoch/112-step·검증·어댑터저장·전체HF내보내기를완료하고기존35B추론을57분37초만에복구했다.380tensorfinite·MTP19보존/93검사통과.동일HF 미학습GGUF는별도등록/52턴응답확인,학습본GGUF/등록·비교는진행중이다.운영봇교체와MCP/채팅/보호E2E는미실행이며 [상세현황](../STATUS.md)을따른다.


> **10/27 18:00 학습 재개 결과:** CPU 파일 참조 누적으로 발생한35B 적재 메모리 문제를 보완해 실제2-step·평가·어댑터 저장까지 완료했다. 380텐서 finite/190 B행렬 갱신,78검사 통과. 추론은약2분56초만에 원래35B로 복구했다. 본 학습·변환/등록·운영 교체·SOC 정확도 비교는 미실행이며,현SOC 자료 보완과 장기 학습 시간대 결정이 남는다. 아래 정지/0step은 당시 이력이다. [실측·잔여·Git](../STATUS.md).

> **2026-10-27 16:23 일시정지:** 원본39파일·71.93GB의 checksum과 실토큰 검사는 완료했다. 실제35B 시험은 가중치 적재 중 global OOM으로 실패해 optimizer0/2step이며, 기존 Ollama/35B는약81.4초만에 복구했다. 학습 대기 작업과 복구 timer는 종료됐고 사용자 요청으로 추가 수정/재시험을 중지했다. 아래 실행 준비 이력과 구분하며 [STATUS](../STATUS.md)의 재개 지점을 따른다.

시작 시96GiB 가용 계획 하한과 컨테이너112GiB 제한이 실제 통합 메모리 peak를 보장하지 못했다. 메모리 표본/커널 OOM 근거를 보존했으며 CPU/GPU 동시 적재·일시 버퍼·dtype 등 상세 원인은 재개 후 분석한다. 실패한 `smoke-status.json`·`outputs/smoke`·컨테이너를 자동 삭제/재실행하지 않는다. 전체 모델 학습·학습 어댑터·본 학습 시간 추정·병합/신규 Ollama 등록은 아직 없다.

실제 meta 구조 대조에서 필요한1,026텐서는 checkpoint에 모두 있었고, 추가19개 `mtp.*`는 [공식 로더](https://github.com/huggingface/transformers/blob/v5.4.0/src/transformers/models/qwen3_5_moe/modeling_qwen3_5_moe.py)가 제외한다. 이 로더의 모델 파라미터는35,107,181,936개이며 MTP 포함 원본 전체와 구분한다. 향후 내보내기/변환 시 보조 헤드와 비전/서식 보존 범위도 검증해야 한다.

2026-10-27: 사용자 지시로 학습 실행 준비에 착수했다. **격리 환경 설치·실제 GPU 축소 구조 검증 완료, 전체35B 원본 다운로드 중·데이터 토큰화 완료. 전체 모델 학습·운영 배포는 아직 없다.** 기존 `config.json`의30B 실험과 정제 데이터·이전 압축파일은 보존했다.35B는 명시적으로 `--config config.qwen36-thor.json`을 선택한다.

## 메모리 적재 보완 — 2026-10-27 재개

`bounded_loading.py`는 이 프로필의 Transformers5.4.0 적재 구간에만 적용한다. 기본 로더는 전체 safetensors slice/파일 참조를 적재 완료까지 유지한다. Thor의 GPU 복사 후 CPU 익명 메모리가 누적되는 현상을 실측해, 메타데이터만 보유하고 각 텐서를 읽을 때 파일을 다시 열어 복사 후 참조를 해제하도록 바꿨다. `HF_DEACTIVATE_ASYNC_LOAD=1`로 미리 적재하는 작업도 막는다. 체크포인트 바이트·dtype·모델 구조와 설치된 라이브러리 파일은 바꾸지 않으며, 로더 context 종료 시 원래 함수를 복구한다. 독립 학습/병합 프로세스용이며 멀티스레드 운영 추론에 적용하지 않는다. 라이브러리 버전을 바꾸면 재검증 전 실행을 거절한다.

동일한 실가중치2.102GB 제한 시험에서 CUDA 할당은 같았고 최종 CPU RssAnon은2,533,840KiB→481,272KiB로 감소했다. 작은4shard/21tensor의 적재 전후 완전 일치와 누락0도 확인했다. 순차 적재만으로는 실패했으므로 이 두 변경을 분리해 기록한다. 공식 [Transformers 로더](https://github.com/huggingface/transformers/blob/v5.4.0/src/transformers/core_model_loading.py)와 [safetensors0.6.2 파일 참조](https://github.com/huggingface/safetensors/blob/v0.6.2/bindings/python/src/lib.rs)를 대조했다. CUDA 내부의 private page 전환 세부 원리까지 검증한 것은 아니다.

`guarded_process.py`는0.25초마다 host MemAvailable을 확인하고12GiB 미만이거나 관측이 실패하면 이번 학습 자식 프로세스 그룹만 종료한다. 컨테이너 SIGTERM도 자식 정리/실패 상태 기록으로 연결한다. 이는 메모리 예약이나 global OOM의 수학적 방지 보장이 아니며,96GiB 시작 기준·112GiB 컨테이너 상한과 별도로 동작한다. 실제 추론 중단 시험은 독립25분 호스트 복구 timer를 먼저 확인하고, 시험 완료/실패/24분 제한 시 즉시 기존 Ollama/35B를 복구한다. 장기 본 학습은30분 시험 승인에 포함되지 않는다. 실패 시도와 중단 컨테이너는 별도 보존하고 자동 재시도하지 않는다.

마지막 optimizer step의 평가가 이미 수행됐다면 해당 지표를 저장하고 중복 평가를 생략한다. 이전 step의 평가나 비정상 수치는 재사용하지 않는다. 실제 CPU Trainer2step에서 평가 호출1회 유지,78개 검사를 통과했다. 전체35B 재시험은 이 소규모 후속 이후 다시 하지 않았다. 새 container 실행은 검증된 원본 manifest의 revision/SHA를 run manifest에 포함하며, 기존 smoke 산출물은 덮어쓰지 않고 별도 provenance로 출처를 보완했다.

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

학습 작업 폴더는 `~/Capstone_Groot_training/qwen36-20261027`이며 소스/데이터·venv·base·manifest·stage log/status·outputs를 보존한다. 아래 명령은 Thor에서만 실행한다. 이미 완료/실행 중인 단계를 중복 실행하면 거절한다.

```bash
training_root="$HOME/Capstone_Groot_training/qwen36-20261027"
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

## 현 SOC 전용 제한 시험 — 2026-10-27 KST

`config.qwen36-soc.json`은 같은 고정35B/BF16/eager/r16을 사용하며 길이1536·학습률2e-5·pilot8step/accumulation2다. 기존20,784행과30B 설정을 덮어쓰지 않는다. `soc_dataset.py`로 검수 source case의 도구/인자·출처·필수 사실·시나리오 분할을 검사해 별도212대화를 준비했다. 자료는 Git 제외이므로 clone만으로 재생성되지 않는다. 에이전트 검수 합성100건과 AIT 추출112건이며 실제 승인된 운영 동작의 기록이라고 주장하지 않는다.

```bash
training_root="$HOME/Capstone_Groot_training/qwen36-20261027"
# 같은 단계/출력의 재실행은 거절한다. 먼저 기록과 실행 중 작업을 확인한다.
python3 -B "$training_root/finetuning/thor_container.py" soc-tokenize --root "$training_root"
# 공유 추론 중단/독립 복구 timer·시간대·자원 확보는 운영자가 별도로 관리한다.
python3 -B "$training_root/finetuning/thor_container.py" soc-smoke --root "$training_root"
python3 -B "$training_root/finetuning/thor_container.py" soc-pilot --root "$training_root"
```

`pilot`은224개 train prefix 전체 epoch가 아니다. 평가에는44개 validation prefix를 모두 사용하며 test52개를 학습/validation에 합치지 않는다. 단기 결과의 loss 감소를 SOC 누락 해결이나 운영 적합성으로 해석하지 않는다. `pack.py --config config.qwen36-soc.json --output <새 파일>`은 공개 실행 소스와 로컬 SOC 원본/분할을 명시 목록으로 묶고 가중치/자격/결과는 제외한다.

`soc_evaluate.py`는 native `/api/chat`에서 heldout 시나리오의 처음/마지막 assistant를 정답 도구 결과 이력과 함께 재생한다. 실제 MCP 실행·연속 자율 조사·승인/적용·채팅 전송은 하지 않는다. 누락70/필수 사실60, 미등록/보호 오호출100점 감점과 HTTP 실패0점을 기록하지만 문자열 판정에는 수동 의미 검토가 필요하다. 중간 턴 누락을 숨길 수 있는 gold-context 평가이므로 실제 에이전트 E2E를 대체하지 않는다.

Cisco 비교본은 Qwen adapter가 아닌 별도 Llama계열8B다. 고정 원본/NOTICE·기반 Llama3.1 조건을 보존하고 기존 NGC 이미지에서 공식 llama.cpp `276378515ceebee5d14bcc8536603dd5c87491a2`를 CPU 전용으로 빌드한다. `convert_reference.py`가 BF16 GGUF→Q4_K_M 및 SHA를 기록하고 `reference_model.py`는 검증된 GGUF만 새 이름으로 등록한다. Thor Ollama0.40.2의 직접 safetensors import는 Q4_K_M 미지원/MLX 부재로 실패했으며 서비스를 교체하거나 MLX를 설치하지 않는다. 변환 의존성 sentencepiece0.2.1은 별도 작업 target에만 둔다. 기존 모델/봇 설정은 보존하고 등록·실제 추론·MCP/한국어 점수는 각각 검증한다.

### 전체 SOC 1회 학습

`config.qwen36-soc-main.json`은224train prefix/accumulation2의 전체1epoch(112step),44validation을 사용한다. pilot8step의 가중치에서 재개하지 않고 같은 고정 원본에 새 LoRA를 초기화한다. test는 사용하지 않는다. `soc-train`은 성공한pilot/전체토큰검사·원본 검증이 필요하고 별도 `outputs/soc-main/`에 기록한다. launcher는 추론을 중지하지 않으므로 공유 서버에서 자원/시간대와 독립 복구를 먼저 확보한다. 이번 운영자의 승인은 최대2시간이며105분 작업 제한·110분 독립 복구 timer·12GiB 보호를 적용했다. 일반 SOC LLM에 이 운영 권한을 위임하지 않는다.

```bash
# 승인된 시간대·복구/자원 준비가 끝난 Thor에서만:
python3 -B "$training_root/finetuning/thor_container.py" soc-train --root "$training_root"
python3 -B pack.py --config config.qwen36-soc-main.json --output <새 반입묶음 경로>
```

위 실행 예시를 현재 실행 중인 작업에 중복 적용하지 않는다. 전체 실행/드라이버/어댑터·복구·정확도 결과는 STATUS의 실제 완료 여부를 따른다.

### MTP·비전 보존 내보내기

`merge_streaming.py`는CPU에서 원본26shard를 순차 읽어 LoRA190대상만 바꾸고 나머지855tensor/MTP19개와 모든 검증된 원본 메타데이터를 복사한다. PEFT0.18.1 CPU safe_merge의 delta BF16 반올림 순서를 고정한다. 저장 뒤1,045개 전체 tensor의 이름·dtype·값을 다시 대조하고 파일 SHA를 남긴다. 첫 작은 불일치 fixture를 수정한 뒤 PEFT와 정확 일치했고 실제pilot35B 출력도 전체 검증/190모듈 변경·MTP19보존으로 완료했다. 기존 `merge_adapter.py`의 전체 모델 재구성과 구분하며 이 프로필의 내보내기에는 이 경로를 사용한다.

```bash
# 기존 고정 컨테이너 내부 CPU 전용·충분한 RAM/디스크·host reserve 보호 아래:
/workspace/venv/bin/python -B /workspace/finetuning/merge_streaming.py \
  --adapter /workspace/outputs/soc-main/adapter \
  --output /workspace/exports/qwen36-soc-main-hf \
  --base-manifest /workspace/base-manifest.json --threads 2
/workspace/venv/bin/python -B /workspace/finetuning/convert_soc.py --variant base
/workspace/venv/bin/python -B /workspace/finetuning/convert_soc.py --variant main
```

`main` 명령은 실제 본 학습 완료 후에만 실행한다. 출력이 있으면 덮어쓰지 않고 실패 근거도 보존한다. `convert_soc.py`는 같은 고정 공식 llama.cpp source/CPU binary를 확인하고 원본/병합 파일 SHA를 재검사한 뒤 BF16 GGUF→Q4_K_M을 변환한다. base는 비전 projector도 별도 변환하고 main은 보존 검증된 동일 projector를 재사용한다. MTP1층 포함 metadata를 검사한다. 현재 base 변환 진행 중이며 전체 변환/등록·실제 추론 검증은 미완료다. 원 registry GGUF와 HF commit의 원본 이력이 미확정이므로 같은 HF에서 같은 변환으로 만든 미학습본을 비교 기준으로 추가한다. 일반 기존 운영 모델과의 속도는 별도로 표시한다.

등록 준비에는 [Ollama create API](https://docs.ollama.com/api/create)와 [설치 버전0.40.2 GGUF projector 분류](https://github.com/ollama/ollama/blob/v0.40.2/server/create.go)를 대조했다. 실제 도구·시각·한국어 평가와 비전 입력 시험, 운영 모델 전환은 각각 구분한다. 새 패키지/GPU 권한을 SOC LLM에 위임하지 않는다.

### 동일 조건 비교본·등록·전체 개별 턴 평가

20:33 KST 동일 HF 원본의CPU GGUF/Q4_K_M 변환·체크섬 검증을 완료했다. text21,713,462,784B/projector899,283,200B이며 MTP1층을 포함한다. HF→GGUF의 fused expert·vision Conv3D 분리로 텐서 수가 달라지는 점은 정상 변환이며 원본 보존 검사와 구분한다. 새 모델 등록/실제 추론은 본 학습/기존 추론 복구 뒤 검증한다.

`register_soc.py --variant base`와 `--variant main`은 Thor 호스트의loopback API만 사용한다. 등록된 새 이름이 있거나 이전 시도 기록이 있으면 덮어쓰지 않는다. 전체GGUF SHA·텍스트/비전 파일을 확인하고 원본 system/7개 runtime parameter·renderer/parser·capabilities·runner를 대조한다. 유효 native 채팅 서식은 같은 고정 HF의 `chat_template.jinja`와 대조하며 원 registry의 Go placeholder와 동일하다고 표시하지 않는다. 기존 모든 model digest도 전후 비교하며 운영 봇 설정은 바꾸지 않는다. 직접 LoRA import는 설치된Ollama0.40.2에서 미지원이므로 병합 후GGUF를 사용한다.

전체test 평가에는 다음 옵션을 사용한다. 이는 원래 도구 관측 이력을 정답으로 제공하는 **개별 턴** 검사다. 호출이 실제 성공하거나 승인·적용되는 agent E2E는 아니다. 도구는 사례별 카탈로그 부분집합이며 전체37도구 중 선택도 검증하지 않는다. 동의어/유효한 추가 이름 필터 등 자동점수의 오감점은 수동 의미 검토로 구분한다.

```bash
python3 -B "$training_root/finetuning/soc_evaluate.py" \
  --model soc-qwen36:35b-base-q4km-20261027 \
  --cases "$training_root/finetuning/data-soc-source-v1/cases.jsonl" \
  --output "$training_root/soc-evaluation/matched-base-full.json" \
  --all-cases --all-turns
# 같은 입력/옵션으로 main-q4km 후보를 별도 출력에 평가한다.
```

오프라인 재현에는 기존 고정arm64 NGC 이미지/venv·고정HF snapshot 외에 공식 llama.cpp commit `276378515ceebee5d14bcc8536603dd5c87491a2`의전체 변환 source/gguf-py, CPU build와연결 shared library, `sentencepiece==0.2.1`의해당 Python/플랫폼 wheel 및 `conversion-install-report.json`의SHA가 필요하다. converter 의존성은 별도 target에만 설치하고 학습 venv/host Python을 덮지 않는다. source/data 반입목록은 `pack.py`에 포함되며 가중치/컴파일 결과/패키지 binary는별도이다. Mac 다운로드·패키지 설치는0이며 외부 학습 장비의 신규 전체 오프라인 설치를 실제 검증한 것은 아니다.

### 20:54 KST 실행 결과·서식 검증 보완

본 학습112step/1epoch·44validation·어댑터 저장/finite검사와기존추론복구·HF전체내보내기를완료했다.학습본GGUF변환은진행중이며최신별도등록/평가는STATUS를따른다. `register_soc.py`는모든FROM blob SHA를text/projector와대조하고,selected native template은고정HF서식과비교한다. 원registry의Go placeholder와표시가다르다는이유로검증에실패한첫시도는보존했다. 원래runtime옵션/다른모델digest는유지하며두HF파생모델의서식은동일하게맞춘다. 설치버전의 [selectedModelTemplate](https://github.com/ollama/ollama/blob/v0.40.2/server/routes.go) 동작과실제HF파일SHA를대조했다. 원등록본과새HF파생의서식차이를학습효과로해석하지않는다.

### 요청 필드 평가 보완

기존 `soc_evaluate.py`의자동점수는참고문장/인자완전일치도다. 요청밖의미확인해설이나이미KST인값의변환설명까지강제해정확한답을오감점한것을확인했다. 이값을정확도로사용하지않는다. `soc_assessment.py`를추가해고정5시험군의실제요청필드·관측값을별도검사한다. 호스트namefilter추가·날짜의KST표기형식차이를인정하고포트값은실제tool관측에서읽는다. AIT의phase_window누락도검사한다. 알수없는군/자연어판단은수동검토이며자동통과가아니다.

```bash
python3 -B "$training_root/finetuning/soc_assessment.py" \
  --report "$training_root/soc-evaluation/matched-base-full.json" \
  --cases "$training_root/finetuning/data-soc-source-v1/cases.jsonl" \
  --output "$training_root/soc-evaluation/matched-base-request-assessment.json"
```

21:12 KST 미학습본은도구16/16·요청필드36/36이며근거없는정보성서술1건은수동검토다. “기존6건누락”은요청밖설명을강제한평가오류로정정했으며원기록을보존한다. 학습참고답변/분할/가중치는바꾸지않고같은판정기로학습본을비교한다. 숫자/형식일치가전체관제품질·승인/적용/채팅E2E를보장하지않고,단일소규모시험의일반화/부하통제없는속도우위를주장하지않는다.


### 2026-10-27 본 학습 결과와 운영 적용 제외

112-step/1epoch를 완료하고 추론을57분36.53초만에 복구했다. 결과는 `outputs/soc-main/adapter/`, `exports/qwen36-soc-main-hf/`, `exports/qwen36-soc-main-gguf/`에 보존한다. 별도 등록 태그 `soc-qwen36:35b-main-q4km-20261027`는 비교용이며 운영 승인 모델이 아니다.

동일 HF/변환기/Q4_K_M/채팅 서식/입력으로 미학습본과 각52턴을 비교했다. 유효한 필수 호출은16/16→13/16, 요청 필드 최종 답변은36/36→29/36이다. 학습본은 IDS 호출3건, KST 그대로 표시4건, 조회 실패 답변1건을 누락하고 AIT 날짜2건을 하루 뒤로 틀렸다. 포트의 전체 확인 주장3건도 증거 범위보다 넓다. 미학습본의 근거 없는 정보성 서술1건도 별도로 남겼다. 본 비교는 운영 registry 원본과의 완전 동일 조건이나 실채팅/실제 도구 실행의 성공률이 아니다.

`soc_assessment.py`는 한글 날짜와 Markdown 필드 표시를 인정한다. 조회 불가를 빈 차단 목록으로 오인하지 않고, 정책 반복만 있는 답변은 수동 확인 대상으로 남긴다. 과거 평가 결과를 덮어쓰지 않고 양쪽 원 응답에 같은 수정 판정기를 적용했다. 실제 토크나이저320prefix의 content·108호출/144인자·마스킹·추론 시작 형식은 전수 통과해 해당 표현 손상은 발견되지 않았다. 원인은 미확정이며 loss만으로 학습 성공의 품질을 주장하지 않는다.

후속은 기존 train 자료의 응답 구체성·다양성 검토, 별도 버전 데이터와 validation 기반 학습률/업데이트 수 비교, 새로운 미사용 hold-out이다. 이번 test 답변을 학습하지 않으며 자동 재학습·운영 전환은 하지 않는다. 공유 추론을 다시 중단해야 할 실행은 구체적인 계획과 복구 제한을 갖춘 별도 시간대로 관리한다. 최초 본 학습 설정과 모든 결과는 보존한다.


### 학습 품질 개선 사전 감사 — 2026-10-27 21:47 KST

로컬 train144대화/224prefix/80개 정답 호출은 서로 다른7도구만 포함한다. AIT 사실 추출72대화, 합성9군 각8행이며 숫자를 가린 질문 형태는8군이1개/IDS군이3개다. `list_blocks`·이미KST값 그대로 표시·포트 조회의 train 예시는 없었다. 의도적으로 미학습 유형을 test에 둔 일반화 시험이며, 이 통계가 퇴행의 확정 원인은 아니다.

후속은 기존 자료/평가/가중치를 보존하고 새 버전의 다양한 독립 시나리오·구체적 실제 답변을 검수하는 것이다. 이미 본 test를 학습하지 않고 새 개발/최종 미사용 평가를 고정한다. 미학습 base에서 낮은 학습률 후보5e-6/1e-5와 짧은 업데이트 예산/중간 체크포인트를 비교한다. 이는 미검증 실험안이며 기존2e-5 설정을 바꾸거나 GPU 학습을 실행하지 않았다. 한 변수씩 비교해 자료/업데이트 영향과 BF16→Q4 양자화 영향을 구분한다. [SFT의 목표는 정답 시퀀스 NLL 최소화](https://huggingface.co/docs/trl/en/sft_trainer#looking-deeper-into-the-sft-method)이며 우리의 호출 성공/누락/허위 완료 평가는 별도로 확인한다. [Trainer의 평가·저장 설정](https://huggingface.co/docs/transformers/en/main_classes/trainer)을 사용하더라도 loss만으로 운영 승격하지 않는다. 이번에 서버 접속/공유 추론 중단/재학습은 하지 않았다.


### SOC v2 자료와 보수적 비교 경로

`soc_curriculum.py`는 live 도구/모델 호출 없이 agent-reviewed synthetic 관측의 소스 필드 투영을 만든다. 학습192/개발32/최종test32대화,390/65/65assistant prefix이며 기존v1을 보존한다. v2는16능력·19종 실제 호출 예시와160문장틀을 분리했다. 실제 운영 사례나 새로운 능력 OOD 평가가 아니다. 초기 초안은 로컬 archive/검증 보고서에 보존했고 아래 경로만 최종 검수 자료다.

```bash
python3 -B finetuning/soc_curriculum.py \
  --source-output finetuning/data-soc-source-v2/cases.jsonl \
  --output finetuning/data-soc-v2 \
  --previous-cases finetuning/data-soc-source-v1/cases.jsonl
python3 -B finetuning/pack.py --config finetuning/config.qwen36-soc-v2.json --output /작업별/임시경로/soc-v2.tar.gz
```

기존 출력 경로를 덮어쓰지 않는다. 새 클론에는 로컬 전용 v1/v2 자료가 없으므로 승인된 자료 반입이 필요하다. 기존test는 회귀용이며 train으로 복사하지 않는다. 개발 평가는 `soc_evaluate.py --split validation --all-cases --all-turns`로32대화65턴만 사용한다. 최종test는 개발 결과로 후보를 고정한 후 사용하며 자동 exact-string 점수는 수동 의미 검토 전 정확도가 아니다.

Thor에서는 `soc-v2-tokenize`가 GPU 없이 `/workspace/soc-v2-tokenization`에 검사한다. `soc-v2-smoke`는 원base의2-step/accum1·8prefix eval, 성공 후 `soc-v2-pilot`은 별도 원base에서lr5e-6/48step/accum2·eval/save24로 시작한다. 퇴행main/pilot어댑터를 이어 학습하지 않는다. 실제 업데이트는 최대96prefix로 전체390prefix epoch가 아니다. 상태/로그·출력은 `soc-v2-*`로 분리하고 소스 profile과 생성 runtime local config를 구분한다. 기존offline/112GiB/12GiB guard 및 선행/기존 흔적 차단을 유지한다.

```bash
python3 -B "$training_root/finetuning/thor_container.py" soc-v2-tokenize --root "$training_root"
# 아래 GPU 단계는 공유 추론 중단 시간대와 독립 복구 timer를 준비한 후에만 실행한다.
python3 -B "$training_root/finetuning/thor_container.py" soc-v2-smoke --root "$training_root"
python3 -B "$training_root/finetuning/thor_container.py" soc-v2-pilot --root "$training_root"
```

48-step은 최적값이나 점수 향상이 확인된 설정이 아니다. 새 자료와 보수 설정을 함께 보는 후보이므로 단일 원인의 효과로 해석하지 않는다. 자동 서비스 중단/재시도/모델 전환은 없다. 고정 final test, 정확한 변경 후보/승인/적용 근거, 실제MCP/채팅/보호E2E를 각각 검증한다.


### 현행 R2 실행과 operator 복구 경계

개발1차의 질문 모호성을 수정한R2를 별도 경로에 고정했다. 개발·최종split의 범위는 같지만 경보의 `phase_window` 필드를 명확히 하고 합성 출처 문구를 중립적 탐지 설명으로 바꿨다. 같은R2의 미학습 baseline을 다시 실행한다. 원자료·개발1차·초안은 유지하며 최종test는 아직 모델에 요청하지 않았다.

```bash
python3 -B finetuning/soc_curriculum.py \
  --source-output finetuning/data-soc-source-v2-r2/cases.jsonl \
  --output finetuning/data-soc-v2-r2 \
  --previous-cases finetuning/data-soc-source-v1/cases.jsonl
python3 -B finetuning/pack.py --config finetuning/config.qwen36-soc-v2.json --output /작업별/임시경로/soc-v2-r2.tar.gz
```

v2만max_length2048/require_all_prefixes:true로 설정했다. 첫1536검사의4개 제외는 학습 전에 발견해 보존했으며 최종R2는390/65/65개 전부 보존된다. 초과/정렬 실패를 조용히 무시하지 않는다. 학습 전 current corpus SHA를 가진 strict tokenization proof를 확인한다.

`training_window.py`는 검수된 root-owned operator 사본으로만 실제중단/복구를 실행한다. 일반 읽기 `check --root ...`는 현재자료/설정·토큰proof·개발 baseline·이전실행부재만검사하며 서비스작업이없다. operator는 파일 SHA/소유·부모권한을 대조한 뒤 `/usr/local/libexec/capstone-training-window-v2.py`를 root소유0755로 설치한다. MCP에 노출하거나 LLM의sudo/Docker범위를 늘리지 않는다. 상태는root소유 `/var/lib/capstone-training-v2-window`에 보존한다.

실행은 독립 `capstone-soc-v2-restore.timer`를50분으로 먼저 설정/active확인→Ollama중단→원base2-step→성공시별도원base48-step→즉시복구/기존35B재적재다. 학습deadline45분·공유중단상한계획60분이며 실패/SIGTERM에도복구한다. 다른GPU프로세스는이름만허용하지않고Ollama MainPID의자손인지확인한다. 실패이력을자동지우거나재시도하지않고,모델등록/봇전환은하지않는다. 실제실행전새중단승인을받고새제어기의실중단/복구결과를따로기록한다. 기존본학습복구성공을새제어기E2E로대신하지않는다.

root-owned사본의 `run --root ...`은 승인된operator만durable systemd service로 실행한다. 제어기자체독립timer와별개로service RuntimeMaxSec48분을둘수있다. 필요operator명령은실제경로/해시를검토한후사용하며공통초기설치기나운영에이전트권한을바꾸지않는다. 검수자료/원본가중치는이전과같이로컬전용반입이고Git clone만으로전달되지않는다.


### 10/28 승인된 smoke 입력 보완

공유중단최대60분/자동복구를별도로승인받았다. v2 smoke는 `smoke_longest_prefixes:true`, `--max-train-samples 2`로전체train390prefix를토큰검사한뒤최장2개만선택한다. CPU실측1664/1582토큰·eval8prefix이며2optimizerstep/accum1로둘다통과하도록한다. 학습길이상한2048을초기짧은예시만으로검증하지않기위한보완이다. strict coverage의390kept는전체검사수이고실제smoke학습은2개라는점을구분한다. 48-step pilot은별도base에서전체자료를사용가능한상태로시작하며최대96prefix를업데이트한다. 자료/분할/프로필SHA·개발/최종평가설정은불변이다. 로컬/Thor123검사통과와실GPU/복구결과는별도로기록한다.


### R2 체크포인트 비교와 판정

CPU streaming merge의입력은 `outputs/soc-v2-pilot/checkpoint-24`·`checkpoint-48`이다. 각각 `exports/qwen36-soc-v2-step24-hf`·`qwen36-soc-v2-step48-hf`로원본1045tensor보존/190모듈변경·vision/MTP보존을검사한다. `convert_soc.py --variant v2-step24|v2-step48`는HF병합manifest와해당checkpoint의global_step/adapterSHA를대조한뒤동일고정converter/Q4_K_M·baseprojector로변환한다.

`register_soc.py --variant v2-step24|v2-step48`는각각 `soc-qwen36:35b-v2-step24-q4km-20261028`·`soc-qwen36:35b-v2-step48-q4km-20261028`로만등록한다. 이전모델/태그/봇선택을덮어쓰지않고HF서식·원옵션/capabilities·blobSHA를확인한다. GPU학습/공유서비스중단은추가로하지않는다.

디스크예산상두후보를순차변환하며Q4등록검증후해당후보의 `qwen36-soc-bf16.gguf`만삭제한다. 삭제전bytes/SHA와 `intermediate-cleanup.json`을남기고원본base·어댑터/체크포인트·병합HF·최종Q4/projector와이전결과를보존한다. BF16GGUF는보존HF에서같은converter로재생성할수있다. 기존사용자모델/파일을삭제하지않는다.

개발평가는둘다동일R2 validation32대화/65gold-context턴·동일native옵션이다. `curriculum_assessment.py`는실제요청필드/관측값과동등후보를검사하고수동검토를남긴다. 필수조회와선택적인입력시간계산을구분하며올바른직접계산/기본인자/묶음읽기/표현차이를무조건누락으로세지않는다. critical오류·요청누락에큰감점을유지한다. 새학습응답을얻기전에준비한판정기로양쪽을평가하고gold문장/분할/가중치를바꾸지않는다. 평균원점수는일반의미정확도가아니며최종test는개발선택후처음실행한다.
