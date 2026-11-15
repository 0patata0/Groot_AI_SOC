# API 출처와 사용 범위

| 원출처 | 확인한 내용 | 이 후보에서의 사용 |
|---|---|---|
| [systemd v255 공개 header](https://github.com/systemd/systemd/blob/v255/src/systemd/sd-journal.h) | 해당 버전의 journal API·플래그 | 최신 브랜치의 immutable 가정 옵션을 v255 기능으로 오인하지 않음 |
| [systemd v255 sd-journal 구현](https://github.com/systemd/systemd/blob/v255/src/libsystemd/sd-journal/sd-journal.c) | 명시 파일 열기의 flags=0 제약 | native anchor가 고른 실제 FD를 파일 인자로 복제 |
| [python-systemd235 journal Reader](https://github.com/systemd/python-systemd/blob/v235/systemd/journal.py) | Reader의 files 인자와 기본 인터페이스 | 설치 사전검사의 선언된 인자 확인. 실제 호스트 실행 증거와 별개 |

위 코드는 API 의미를 확인하는 공식 원출처다. Ubuntu의 실제 설치 바이너리·동작을 이 출처만으로 입증하지 않는다. A/B/C의 바인딩235·systemd255 관측과 실제 FD 기반 24시간 조회 결과는 [검증 원장](validation.json)에 따로 기록했다. 빈 `files=[]`는 설치된 바인딩에서 오류가 나므로 최종 코드에 포함하지 않았다. 별도 로그 파일 바이너리 파서를 만들거나 검증되지 않은 옵션을 활성화하지 않았다.
