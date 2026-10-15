# SIEM용 Hermes 이미지 수동 준비

이 문서는 **Linux amd64 SIEM 서버 또는 별도의 Linux amd64 준비 서버에서 운영자가 직접 수행하는 사전 준비**다. `deploy.sh`와 역할 스크립트는 이 Dockerfile, `pip`, `uv`, `docker build/pull`을 호출하지 않는다. Mac에 패키지를 설치하거나 운영 Hermes의 데이터·환경·개인키를 빌드 입력으로 복사하지 않는다.

현재 Dockerfile은 정적 검토 및 포함 Python/셸 구문 검사만 마쳤다. 새 이미지의 실제 빌드·gateway 시작·Mattermost 연결 성공을 이번 문서 작성의 검증 결과로 표시하지 않는다. 다음 명령이 실제 대상에서 성공해야 준비된 이미지로 사용할 수 있다.

## 고정 입력과 확인 범위

[공식 릴리스](https://github.com/NousResearch/hermes-agent/releases/tag/v2026.9.24)는 `v2026.9.24`를 Hermes `v0.21.5`, commit `f97608f178d1ffeca59860195ab7da295f7c8e5f`로 설명하고 `nousresearch/hermes-agent:v2026.9.24` 이미지 이름을 제공한다. 저장소의 [기존 배포 계약](../infra/hermes/hermes_prestart_contract.py)은 해당 이름으로 사용한 Linux amd64 이미지의 **로컬 image ID**를 아래처럼 기록한다.

```text
sha256:2fd023efbb8d3d2b0ce1a73d028b07370cff34f567cfe0e999553e8c327ea283
```

이 값은 registry manifest digest로 확인된 값이 아니다. `nousresearch/hermes-agent@sha256:…` 주소로 치환하지 않는다. 태그의 현재 원격 바이트가 같다는 보장도 없다. 운영자가 받은 이미지가 이 ID와 다르거나 제공할 수 없다면 중단하고 새 버전의 소스·entrypoint·ABI를 따로 검토한다. 최신 upstream checkout을 가져와 해시 검사를 제거하는 방식은 지원하지 않는다.

| 항목 | 요구 계약 |
|---|---|
| 기반 이미지 | 위 로컬 image ID, `linux/amd64`, user `root`, cwd `/opt/hermes` |
| 시작 경로 | `/opt/hermes/docker/entrypoint-dispatch.sh`, `gateway run` |
| Python | `/opt/hermes/.venv/bin/python`, CPython 3.13, x86_64/glibc |
| 기존 실행 도구 | 이미지 안에 `uv`, `ssh`; 기존 Hermes 의존성 유지 |
| 원본 adapter SHA | `4f05be68777068d7b454187c7323f2c471aac6412b830f11761b4013eed702c8` |
| 원본 run_turn SHA | `5bdee5c82c00e02f664516f9da0af99674e23493ec2a30eff06cb03afc6718a0` |
| 패치 후 adapter SHA | `1bbe71e24cf7fd212f38b13cb421bb5b05c841ea4d70a061d6dcb57253e6c47b` |
| 패치 후 run_turn SHA | `d4dae0f3194f7b7d435aac2eb37d4697822612cd6955911d86bb61400ad2871a` |
| 가드 모듈 | 저장소 `korean_output_guard.py` → `/opt/hermes/capstone_korean_output_guard.py` |
| 문자 엔진 | `regex==2026.9.29`, 고정 CPython3.13 Linux x86_64 wheel 하나 |
| 설치 위치 | `/opt/capstone-guard-runtime/regex-2026.9.29/lib/python3.13/site-packages` |

파일 SHA가 다른 upstream은 [패처](../infra/hermes/patch_korean_output_guard.py)가 거절한다. 가드·패처·시험 소스와 wheel도 Dockerfile에 SHA를 고정했다. 소스를 수정하면 Dockerfile pin과 SIEM의 준비 이미지 검사를 함께 재검토한다. root 소유 코드·패키지와 읽기 전용 서비스 UID 권한을 유지하며 전역 Hermes Python 패키지를 교체하지 않는다.

## 1. Linux에서 기반 이미지 준비

Docker Engine과 BuildKit/Compose는 루트 README의 수동 설치 절차로 준비한다. 아래 태그 pull 또는 검증한 `docker save` 파일의 load 중 하나를 **운영자가 직접** 수행한다. load 파일은 별도 경로로 받은 SHA를 먼저 대조한다.

```bash
set -euo pipefail
# 온라인 준비 서버에서만: 운영자가 직접 받는다.
sudo docker pull --platform linux/amd64 nousresearch/hermes-agent:v2026.9.24
# 오프라인이면 위 명령 대신: sudo docker load -i /검증한/이미지.tar

base_id=sha256:2fd023efbb8d3d2b0ce1a73d028b07370cff34f567cfe0e999553e8c327ea283
test "$(sudo docker image inspect --format '{{.Id}}' nousresearch/hermes-agent:v2026.9.24)" = "$base_id"
sudo docker image inspect "$base_id" | python3 -c '
import json,sys
x=json.load(sys.stdin); assert len(x)==1; x=x[0]
assert x["Os"]=="linux" and x["Architecture"]=="amd64"
assert x["Config"]["User"]=="root" and x["Config"]["WorkingDir"]=="/opt/hermes"
assert x["Config"]["Entrypoint"]==["/opt/hermes/docker/entrypoint-dispatch.sh"]
print("reviewed_base_metadata_passed")'
sudo docker tag "$base_id" capstone-hermes-base:reviewed-20260924
```

첫 `test`나 검사 명령이 실패하면 다음 단계로 진행하지 않는다. 이 tag는 확인한 로컬 입력을 가리키는 별칭이며 다른 registry의 공식 이미지 이름이 아니다.

## 2. 작은 빌드 문맥과 wheel 준비

아래는 저장소 루트에서 Linux Bash로 실행한다. `set -e`를 켜고 명령 하나라도 실패하면 멈춘다. 빌드 문맥에는 공개 코드 여섯 파일과 wheel 하나만 넣는다. 저장소 전체, `.env`, 운영 DB, SSH 키를 Docker build 문맥으로 보내지 않는다.

```bash
set -euo pipefail
umask 077
repo=$(pwd -P)
ctx=$(mktemp -d /var/tmp/capstone-hermes-image.XXXXXXXX)
mkdir "$ctx/input"
cp deployment/hermes-image.Dockerfile "$ctx/Dockerfile"
for file in korean_output_guard.py patch_korean_output_guard.py \
  korean-output-guard-requirements.txt test_korean_output_guard.py \
  test_korean_output_guard_engine.py verify_korean_output_guard_runtime.py; do
  cp "infra/hermes/$file" "$ctx/input/$file"
done
```

인터넷이 되는 **Linux 준비 서버**에서 아래 표준 Python 다운로드를 수동 실행한다. [PyPI 파일 목록](https://pypi.org/project/regex/2026.9.29/#files)의 정확한 파일명·SHA와 저장소 [requirements](../infra/hermes/korean-output-guard-requirements.txt)를 함께 대조한다. 이미 검증한 wheel을 오프라인 반입했다면 동일 파일을 `$ctx/input/`에 복사하고 다음 SHA 검사를 수행한다. pip 설치, sdist 빌드, 다른 ABI 선택은 하지 않는다.

```bash
python3 -B - "$ctx/input" <<'PY'
import hashlib,json,pathlib,sys,urllib.parse,urllib.request
name='regex-2026.9.29-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl'
expected='d49c18f1ea294cf4adde2e5ac256e98c82ea9d708462ce4bf799dffa7cfe8a2c'
with urllib.request.urlopen('https://pypi.org/pypi/regex/2026.9.29/json',timeout=30) as r:
    metadata=json.loads(r.read(2*1024*1024))
matches=[x for x in metadata['urls'] if x['filename']==name]
assert len(matches)==1 and matches[0]['digests']['sha256']==expected
u=urllib.parse.urlsplit(matches[0]['url'])
assert u.scheme=='https' and u.hostname=='files.pythonhosted.org'
with urllib.request.urlopen(matches[0]['url'],timeout=60) as r: data=r.read(8*1024*1024+1)
assert len(data)<=8*1024*1024 and hashlib.sha256(data).hexdigest()==expected
with (pathlib.Path(sys.argv[1])/name).open('xb') as f: f.write(data)
print('reviewed_regex_wheel_received')
PY
printf '%s  %s\n' \
  d49c18f1ea294cf4adde2e5ac256e98c82ea9d708462ce4bf799dffa7cfe8a2c \
  "$ctx/input/regex-2026.9.29-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl" | sha256sum -c -
# 비밀 없는 입력만 UID995 build 시험이 읽을 수 있게 한다.
chmod 0755 "$ctx/input"
chmod 0644 "$ctx/input/"* "$ctx/Dockerfile"
```

## 3. 수동 오프라인 빌드·검증·ID 고정

```bash
sudo docker build --pull=false --network=none \
  --build-arg HERMES_BASE=capstone-hermes-base:reviewed-20260924 \
  --tag capstone-hermes:guarded-20261015 \
  --file "$ctx/Dockerfile" "$ctx" 2>&1 | tee "$ctx/build.log"

prepared_id=$(sudo docker image inspect --format '{{.Id}}' capstone-hermes:guarded-20261015)
test "${prepared_id#sha256:}" != "$prepared_id"
printf 'Prepared Hermes image ID: %s\n' "$prepared_id"
```

빌드는 정확 원본 소스 패치, 고정 wheel의 `uv --no-config ... --no-deps --no-index --require-hashes` 설치, 실제 UID995의 소스·부모 쓰기 불가, gateway/adapter import, 두 MCP toolset 선택을 검사한다. 기존 정책·엔진 unittest와 **가짜 HTTP 전송 검증기**도 실행하며 모델·실제 채팅·MCP 도구는 호출하지 않는다. 네트워크가 없는 `RUN`이므로 누락 패키지는 자동 다운로드로 해결되지 않는다. 전체 Hermes 의존성을 새로 설치하거나 upstream 코드의 해시 검사를 완화하지 않는다.

완료한 image ID를 `/opt/capstone-prereqs/siem.json`의 `hermes_image` 값에 넣는다. 예시는 `"hermes_image":"sha256:<실제 64자리 image ID>"`다. 이 파일에는 별도 비밀 값도 있으므로 출력하거나 빌드 입력으로 복사하지 않는다. SIEM 역할은 mutable tag 대신 이 ID를 요구하며, 첫 배포 전에 별도 네트워크 없는 image probe로 현재 저장소 가드 SHA·regex 버전·platform toolset 계약을 다시 검사한다. 실제 gateway는 새 `capstone-hermes` 계정의 UID/GID와 새 `/opt/data`를 사용한다. UID995 시험은 특정 기존 서버 계정을 새 서버에 복제한다는 뜻이 아니다.

다른 준비 서버에서 빌드했다면 운영자가 `docker save` → 파일 SHA 대조 → SIEM `docker load`를 수행하고, load 후 같은 ID인지 확인한다. 확인 후 빌드 로그와 최종 image inspect의 **ID·OS·아키텍처·entrypoint 메타데이터만** root 전용 증거 경로에 보존한다. 성공한 작업의 `$ctx`를 제거하고 디렉터리 부재를 확인한다. 실패한 빌드는 로그를 보존해 원인을 확인하며 실패 상태를 운영 이미지로 지정하지 않는다. 일반 Docker build cache나 다른 이미지까지 임의 `prune`하지 않는다.

```bash
# 성공 증거를 별도 보존한 뒤, 이번 작업의 문맥만 제거한다.
[[ $ctx =~ ^/var/tmp/capstone-hermes-image\.[A-Za-z0-9]{8}$ ]] || exit 1
test -d "$ctx" || exit 1
test ! -L "$ctx" || exit 1
rm -rf -- "$ctx"
test ! -e "$ctx"
unset ctx prepared_id base_id repo
```

이미지 준비는 첫 시작에 필요한 가드를 포함시키는 절차다. 이후 모든 임의 Docker 실행을 통제하는 공통 시작 정책, 실제 한국어 품질/모델의 도구 호출 정확도, 기존 운영 서버의 무인 재생성·복구 전체를 보장하지 않는다. 이식 범위와 실제 세 서버 검증 상태는 [루트 README](../README.md)를 따른다.
