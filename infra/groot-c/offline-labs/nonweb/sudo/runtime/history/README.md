# 2026-10-22 rootless 준비·설치 스크립트 원본

이 디렉터리는 당시 작업 소스를 바이트 그대로 보존하는 **실행 이력 자료**다. 범용 설치기나 현재 서버에 다시 실행할 명령 모음이 아니다. Python 파일에는 import만으로 실행되는 최상위 코드가 있으므로 **실행·import하지 않는다.** 재구축은 운영자가 현재 환경과 고정 값, 변경 범위, 복구 절차를 검토한 별도 설치 절차로 진행한다.

| 파일 | 당시 용도·주의점 |
|---|---|
| `rootless-acquire.py` | Mac의 작업별 임시 디렉터리에서 공식 Ubuntu/Docker 자료를 다운로드했다. 출력은 스크립트 옆 `rootless-artifacts/`, CA 경로는 당시 Mac의 `/etc/ssl/cert.pem`이다. Mac에 패키지를 설치하는 스크립트는 아니다. 다운로드 SHA 확인과 C의 서명 검증은 별도 단계다. |
| `rootless-verify-artifacts.py` | C의 고정 임시 아카이브·SHA와 Ubuntu 키링 SHA, Docker 공개키 fingerprint를 사용해 InRelease→Packages→패키지 연결을 검증했다. 검증 임시 파일을 만들고 `gpgv`·`dpkg-deb`를 실행하므로 단순 파일 조회 스크립트가 아니다. |
| `rootless-install.py` | 검증 코드를 포함하고 C에 전용 사용자·패키지·설정·사용자 systemd 서비스를 설치하는 일회성 스크립트다. UID/GID **1991**, subordinate ID 범위, 운영 디렉터리, 기존 Docker unit·호스트 sudo 기준값이 고정돼 있다. 기존 설치가 있으면 거절하며 재실행 가능한 업그레이드 도구가 아니다. |
| `rootless-acceptance.py` | 당시 초기 검증 시도에 사용된 구버전이다. 이미지 OCI manifest와 런타임 config ID를 대조해 운영 설정·반입 메타데이터를 변경하고 `check/up/verify/stop/up/verify`를 실행한다. 실패 이력이 있는 이 소스의 존재나 내장 결과 필드를 최종 성공 증거로 해석하지 않는다. 최종 검증 결과는 상위 문서·별도 결과 기록을 따른다. |

`rootless-install-tail.py`는 설치 후반부의 중복 자료여서 보존하지 않았다. 원본의 비밀번호·토큰·개인키는 발견되지 않았다. 공개키 fingerprint, 공개 패키지 URL·SHA, 전용 서비스 계정과 고정 운영 경로는 재현 근거로 보존한다. 자격 파일·패키지 바이너리·다운로드 아카이브·실행 결과의 전체 환경은 포함하지 않는다.

[source-sha256.json](../source-sha256.json)은 이 네 원본과 추출 설정의 SHA를 기록한다. [provenance.json](../provenance.json)은 당시 `acquisition.json` 그대로이며, `signature_verified: false`는 **다운로드 단계에서는 아직 서명을 검증하지 않았음**을 뜻한다. 이후 서버 검증 결과를 소급해 이 원본에 덮어쓰지 않는다. URL의 현재 내용이나 릴리스 신선도는 이후 달라질 수 있으므로 그대로 재다운로드하면 같은 바이트가 나온다고 보장하지 않는다.

`../templates/`의 daemon JSON·사용자 unit·UID1991 delegate drop-in·AppArmor 설정은 원본 설치 코드의 문자열/JSON 식을 정적으로 읽어 추출했다. 설치 코드는 실행하지 않았다. 대상 경로와 추출 위치를 SHA 목록에 함께 남겼다. AppArmor의 해당 실행 파일 프로필은 `unconfined`에 `userns`를 허용하는 구성으로, 파일 접근을 제한하는 별도 샌드박스로 설명하지 않는다. 이 설정을 다른 UID·경로에 그대로 설치하지 않는다. 현재 운영 상태 확인이나 이후 publisher unit/timer의 검증은 이 원본 보존 작업의 범위가 아니다.


최종 후속 구성에는 `rootless-restrict-securityfs.py`의 전용 user@1991 securityfs 접근 제한이 추가됐다. `templates/user@1991.service.d/capstone-sudo.conf`는 이 변경까지 반영한 최종 템플릿이므로 초기 install 원문의 Delegate-only 상태와 구분한다. 호스트 전역 AppArmor 설정은 변경하지 않는다.

`rootless-retry.py`는 최종 고정 CLI의 native 26회귀와 7단계 동작 검증에 사용했다. `rootless-install-publisher.py`는 최초 상태 서비스 설치 시도이며 User=root/Group=root 명시 환경에서 runuser의 UID 전환이 거부된 실패 이력이 있다. `rootless-publisher-final-check.py`는 해당 두 줄만 제거하고 system manager 기본 root·publisher의 UID0 검사 아래에서 ready/needs_setup/ready를 확인한 후 timer를 활성화한 후속 코드다. 최종 templates에는 이 수정이 반영돼 있다. `rootless-final-evidence.py`는 최종 상태·보호 설정·운영 이미지 아카이브 해시를 읽어 대조한 코드다. 이 파일들도 실행 이력용이며 재실행 가능한 범용 설치기로 제공하지 않는다.

`rootless-cleanup.py`는 승인된 임시 다운로드 23파일과 전용 디렉터리 3개만 해시·소유권 확인 후 삭제한 실제 정리 코드다. 운영 이미지/계정/data/설정은 보존하며, 현재 이미 정리가 끝났으므로 재실행하지 않는다. 정리 결과는 `../cleanup-20261023.json`에 있다.
