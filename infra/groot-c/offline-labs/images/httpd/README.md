# Apache HTTP Server 파일 접근 실습 이미지

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../../STATUS.md) · [실행 계획](../../../../../PLAN.md).
> 현재 콘솔은 HTTP3개(Log4Shell/Apache2종)와 터미널3개(Redis/Samba/sudo), 총6항목이다. sudo는 별도 rootless의 UID1000·전역 단일 세션이며 종료 시 전체 중지한다. DVWA는 독립 유지한다. 환경 준비와 CVE 악용 성공을 구분하고 공격 재현은 보류한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

같은 Dockerfile로 Apache HTTP Server **2.4.49 / CVE-2021-41773**, **2.4.50 / CVE-2021-42013**의 독립 이미지를 만든다. 42013은 2.4.49에도 해당한다. 두 항목은 경로 정규화 결함과 불완전한 수정의 비교이며, 서로 무관한 취약점 유형 두 가지를 뜻하지 않는다. 영향 범위와 파일 접근 조건은 [Apache 공식 권고](https://httpd.apache.org/security/vulnerabilities_24.html)를 따른다.

이 폴더는 설정·한국어 안내 화면·공개 텍스트 fixture만 제공한다. 공격 요청, CGI, 명령 실행 기능, 외부 콜백, 익스플로잇 도구는 포함하지 않는다. 이미지 버전·정상 응답 확인과 취약점 재현·WAF 탐지·차단 검증은 별도 결과로 기록한다.

## 파일과 접근 범위

| 위치 | 용도 |
|---|---|
| `/lab/www/` | 문서 루트. 안내 화면, CSS, 빌드 시 생성하는 `health.txt`·`version.json` |
| `/lab/public/hello.txt` | 정상 Alias 예제. URL `/lab/alias/hello.txt` |
| `/lab/fixture/harmless.txt` | 비밀값 없는 공개 학습 표식. 별도 Alias·일반 공개 URL 없음 |
| 그 밖의 파일시스템 | 기본 접근 거부 |

설정은 `/`를 거부한 뒤 문서 루트·정상 Alias 디렉터리와 fixture의 `harmless.txt` 하나만 허용한다. 심볼릭 링크 추적, 디렉터리 목록, `.htaccess` 재정의는 켜지 않는다. CGI/CGID 모듈과 ScriptAlias·ExecCGI는 설정에 없다. 기존 이미지의 라이선스·NOTICE·기본 OS 고지는 삭제하지 않는다.

## 승인된 Linux/amd64 빌더에서 빌드

Mac에 Docker·패키지를 설치하지 않는다. 공식 기반 이미지를 별도 반입 절차로 검증·로드한 뒤 **대상 Linux/amd64 빌더**에서 아래 작업을 수행한다. 이 Dockerfile은 패키지 설치나 다운로드 명령을 실행하지 않는다. 기본 `FROM`은 공식 **amd64 manifest digest로 고정한 canonical 참조**이다.

운영 담당자가 확인한 C의 Docker 29.8.1은 containerd image store를 사용하며 `docker image inspect .Id`가 config digest와 다르게 manifest digest로 나타난다. 따라서 config digest를 모든 저장소에서 사용할 수 있는 image ID로 취급하지 않는다. legacy Docker archive의 비압축 레이어를 로드하면 manifest가 재생성될 수 있으므로, **공식 원본 compressed layer blob·config·manifest를 보존한 OCI archive**를 반입한다. 각 blob의 digest와 manifest→config 연결을 검증한 뒤 로드하고, `.RepoDigests`의 저장소명 정규화(`httpd` / `docker.io/library/httpd`)를 고려하여 아래 digest의 canonical 참조가 로컬에서 정확히 해석되는지 확인한다. `.Os`·`.Architecture`도 `linux`·`amd64`여야 한다. 태그 문자열만으로 동일 이미지를 판단하지 않는다.

| 대상 버전 | 고정 amd64 manifest digest | 원본 config digest |
|---|---|---|
| 2.4.49 | `sha256:4b5cb7697fea2aa6d398504c381b693a54ae9ad5e6317fcdbb7a2d9b8c3b1364` | `sha256:e91425f386186eb981e47f90780083cc2a16179f3ec45581fa7e5ba044b800fb` |
| 2.4.50 | `sha256:a0a1605656b89fe249c6306e5646d3d3c2d50606e134d411d8e8f732527cbdbb` | `sha256:bc9d3c5a7455df2d13d9093f31aaeda04adf4726b2f8a462f4669e9b67330c79` |

이 폴더를 작업 디렉터리로 하여, 해당 canonical 참조를 로컬에서 해석하는 빌더에서 실행한다.

```sh
docker build --network=none --pull=false \
  --build-arg HTTPD_BASE_IMAGE=docker.io/library/httpd@sha256:4b5cb7697fea2aa6d398504c381b693a54ae9ad5e6317fcdbb7a2d9b8c3b1364 \
  -t groot-labs/httpd:2.4.49 .

docker build --network=none --pull=false \
  --build-arg HTTPD_BASE_IMAGE=docker.io/library/httpd@sha256:a0a1605656b89fe249c6306e5646d3d3c2d50606e134d411d8e8f732527cbdbb \
  -t groot-labs/httpd:2.4.50 .
```

Dockerfile은 두 고정 manifest 참조와 classic 저장소용 config-digest ID 두 개만 받고, 기반 `HTTPD_VERSION`과 `httpd -v` 결과를 대조한다. **classic image store/builder에서 `.Id`가 표의 config digest와 같고 로컬 ID 기반 `FROM`을 지원함을 확인한 경우에만** `DOCKER_BUILDKIT=0`과 해당 full ID를 선택할 수 있다. containerd 저장소에서는 이 대체 경로를 가정하지 않는다. canonical 참조가 로컬에서 해석되지 않으면 반입을 수정하며, 임의 태그·최신 버전·새 네트워크 다운로드로 대체하지 않는다. `--network=none`은 빌드의 `RUN`에 적용되는 옵션으로, 기반 이미지 resolver의 네트워크 접근까지 차단한다는 뜻은 아니다.

완성 태그에 대해 **해당 Docker 저장소가 실제 보고하는 새 `.Id`**를 확인하여 `cve_list.json`의 `image_id`에 등록한다. 이를 config digest와 임의로 동일시하지 않는다. 기반 이미지와 파생 이미지의 식별자는 다르다. 컨테이너 포트는 `8080`, 시작 경로는 `/`이다. 호스트 포트는 기존 목록과 충돌하지 않는 loopback 포트로 운영자가 배정한다. 두 이미지가 버전별 화면을 자동 생성하며 `version.json`은 해당 빌드의 CVE ID·버전·CGI 비활성·fixture 경로를 제공한다.

## 런타임 계약

기존 offline-labs broker의 정책을 사용한다. 이미지 자체만으로 네트워크 격리가 완성되지는 않는다.

- `65532:65532`, 읽기 전용 루트, 모든 capability 제거, `no-new-privileges` 유지.
- 쓰기 가능한 경로는 broker가 제공하는 `/tmp` tmpfs만 사용한다. PID와 잠금 파일도 `/tmp`에 둔다.
- 설정·콘텐츠는 이미지에 포함한다. 호스트 파일, 인증정보, Docker 소켓, 추가 볼륨을 마운트하지 않는다.
- 내부 포트 `8080`, 호스트에는 `127.0.0.1`로만 게시한다. 승인된 bridge의 외부 송신 차단과 고정 DNS 정책을 유지한다.
- 메모리 512 MiB·CPU 1·PID 128·로그 회전 등 기존 broker 제한을 유지한다.

기본 이미지의 `80/tcp` 노출 메타데이터는 상속될 수 있지만 이 설정은 **8080에서만 수신**한다. `EXPOSE` 자체는 포트를 게시하지 않는다. 기동 명령은 기존 PID 삭제 helper 대신 `httpd -DFOREGROUND -f /usr/local/apache2/conf/httpd.conf`를 직접 사용한다.

## 무해한 검증

관리자가 준비한 격리 컨테이너에서 다음을 확인하고, 실제 image ID와 실행 조건·시각을 별도 배포 기록에 남긴다.

1. `httpd -t` 구문 검사가 성공하고 `httpd -v`가 선택한 버전과 일치한다. `httpd -M`에 CGI/CGID가 없고 실제 프로세스 UID/GID가 `65532:65532`인지 확인한다.
2. loopback의 `/health.txt`가 HTTP 200과 `groot-httpd-lab-ok`를 반환한다. `/version.json`의 버전·CVE, `/`의 한국어 안내·CSS를 확인한다.
3. `/lab/alias/hello.txt`는 공개 예제만 반환한다. `/lab/alias/`는 목록을 표시하지 않고, 존재하지 않는 경로는 파일 내용을 반환하지 않아야 한다.
4. 실제 읽기 전용·자원 제한·볼륨 부재·loopback 바인딩·외부 송신 차단을 broker 정책으로 확인한다. HTTP 접근 로그에는 쿼리·헤더·쿠키·인증값을 기록하지 않는다.
5. 같은 HTTPS 주소로 연결할 때 프록시의 경로 정규화와 WAF 모드를 별도로 확인한다. 일반 페이지가 열린다고 취약 요청의 경로 보존이나 취약점 재현이 확인된 것은 아니다. 공용 프록시의 보호를 전역으로 완화하지 않는다.

이 소스 작성 단계에서는 Docker 빌드·컨테이너 실행·취약점 재현을 수행하지 않았다. `source-provenance.json`의 결과는 registry 메타데이터와 공식 자료 확인 범위이며 native 검증 결과를 대신하지 않는다.

## 출처와 라이선스

[source-provenance.json](source-provenance.json)에 공식 이미지의 태그·멀티아키텍처 index digest·amd64 manifest digest·config digest를 구분해 기록했다. 실제 Docker `.Id`의 의미는 저장소 방식에 따라 확인하며, registry의 config digest만으로 추정하지 않는다. 당시 Dockerfile 커밋과 SHA256, Apache 공식 원본 보관 주소와 게시 체크섬도 기록했다. 원본 압축파일은 다운로드하지 않고 HEAD 및 공개 체크섬만 확인했다. 체크섬 파일에 남은 `-rc1` 이름과 별개로 해시값이 당시 Dockerfile의 값과 일치한다.

Apache 소프트웨어와 당시 Docker 패키징 저장소는 [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) 고지를 제공한다. 배포 시 기반 이미지의 LICENSE·NOTICE와 각 OS 패키지 고지를 보존한다. 이 폴더의 Dockerfile·Apache 설정·화면·fixture는 프로젝트가 추가한 실습용 변경이다. Docker Official Image의 유지 주체는 [Docker Community](https://hub.docker.com/_/httpd)이며 이 파생 이미지를 Apache 재단의 공식 실습 이미지로 표시하지 않는다.
