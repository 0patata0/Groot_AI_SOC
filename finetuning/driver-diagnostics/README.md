# Thor 595.78 실패 지점 진단 패치

이 패치는 원래 `NV_ERR_NO_MEMORY`의 발생 조건을 확인하기 위한 **진단 후보**다. 할당 실패를 고치거나 경고를 숨기지 않는다. 현재 운영 드라이버에는 적용하지 않았다. 최신 빌드/검증 결과는 [현황](../../STATUS.md)과 [실제 메모리 점검](../THOR_35B.md)을 따른다.

## 기록하는 내용

- 공통 `memdesc_return`: 상태 코드, 요청 크기, 정렬, 주소 공간, 페이지 크기 정책.
- `metadata_info`/`metadata_table`: 요청 크기와 페이지 표 메타데이터 크기.
- `system_pages`: OS 페이지 블록 요청 실패, order/GFP/node, 실패 블록 번호와 풀에서 받은 블록 수.
- `nv_alloc_pages_metadata`/`nv_alloc_pages_return`: OS 할당 함수의 반환 상태와 요청 조건.

원래 `NV_CHECK_OK`와 모든 할당·재시도·해제·반환 분기는 유지한다. 실패한 분기에만 `GROOT_ALLOC` 로그를 추가하며 주소·텐서·키·토큰을 기록하지 않는다. 커널 부분은 `pr_err_ratelimited`로 제한한다. RM 공통 로그는 기존 오류 한 건에 상세 한 줄을 추가한다. 로그가 제한·유실되면 모든 실패를 수집했다고 간주하지 않는다.

`system_pages` 실패 뒤 상위의 작은 페이지 재시도로 성공할 수 있다. 공통 반환 로그와 시간/PID/TID 및 상위 결과를 함께 대조해야 한다. 커널 로그의 시각은 수집할 때 KST로 변환하며 커널 시계 자체를 변경하지 않는다. 다른 경로의 실패까지 이 패치만으로 전부 분리하는 것은 아니다.

## 고정 소스 확인과 격리 빌드

대상은 NVIDIA `jetson_39.2.1`, commit `76b260e5967dfe9815b9054a4a4642f10672a763`, driver `595.78`이다. `manifest.json`에 세 파일의 전후 SHA와 패치 SHA를 고정했다. 다른 소스·수정본·내부 symlink는 거부한다. `check.py`는 파일을 읽기만 하며 다운로드·설치·패치 적용·모듈 로딩은 하지 않는다.

운영 소스와 분리한 전체 공식 소스 복사본에서만 진행한다. 아래 작업은 빌드까지만 수행한다.

```sh
python3 -B check.py --source /absolute/path/to/isolated-source
git -C /absolute/path/to/isolated-source apply --check /absolute/path/to/nvidia-595.78-allocation.patch
git -C /absolute/path/to/isolated-source apply /absolute/path/to/nvidia-595.78-allocation.patch
python3 -B check.py --source /absolute/path/to/isolated-source --expect-patched
```

Thor에서는 기존 `gcc-13`/make/정확한 실행 커널 헤더를 사용해 `kernel-open/nvidia/nv-kernel.o_binary` 목표를 먼저 빌드하고, `kernel-open`에서 `NV_KERNEL_MODULES=nvidia`로 모듈을 만든다. `CC=gcc-13`, `SYSSRC`와 `SYSOUT`에는 헤더의 실제 경로를 지정한다. CPU2/메모리8GiB/15분 제한, 일반 사용자, 읽기 전용 시스템·작업 폴더만 쓰기, GPU 장치/네트워크/모듈 로딩 금지로 격리한다. 빌드 중 운영 Ollama를 중지하지 않는다. 실패 로그와 성공 로그는 구분해 보존한다.

패치 역적용 검증과 체크섬·테스트는 컴파일/모듈 로딩 시험을 대신하지 않는다. 컴파일 성공·595.78/vermagic 일치도 실행 호환성이나 원래 경고 해결의 증거는 아니다.

## 운영 적용 경계

자동 설치기 `deploy.sh`는 이 진단 후보를 설치하지 않는다. `finetuning/pack.py`는 패치·검증기·목록·문서만 반입하며 공식 소스 압축파일과 빌드된 모듈을 포함하지 않는다. 기존 VMM/선택 loss와 운영35B는 유지한다.

실제 적용은 GPU/디스플레이 사용자 영향과 원본 모듈·관련 모듈 ABI·서명/검증 정책·로컬 복구 콘솔·유지보수 중단 범위를 확인한 뒤 별도로 결정한다. 원본 패키지/모듈/부팅 설정을 보존하고 정확한 복구 절차를 먼저 검증해야 한다. 현재 DRM/modeset/UVM 참조가 있어 강제 언로드나 추론 타이머만으로 안전한 원복을 보장하지 않는다. 서명 검증 해제·강제 모듈 로딩/언로드·운영 부팅 설정 변경은 이 경로에 없다.

다음 판정은 계측 드라이버가 실제 로드된 환경에서 원래 0x51이 재현될 때만 가능하다. 원인별 수정 후 동일 자료/모델/조건의 반복 대조와 원래 모델 복구를 확인해야 해결 완료로 표시한다.

근거: [NVIDIA 동일 버전 소스](https://gitlab.com/nvidia/nv-tegra/tegra/kernel-src/nv-unified-gpu-display-driver/-/tree/76b260e5967dfe9815b9054a4a4642f10672a763), [공식 모듈 빌드 절차](https://docs.nvidia.com/jetson/archives/r39.2.1/DeveloperGuide/SD/Kernel/KernelCustomization.html#building-the-nvidia-out-of-tree-modules). 원본 소스의 MIT 고지는 [NOTICE](NOTICE)에 보존한다.
