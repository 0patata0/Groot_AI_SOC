# 실행 상태 해석의 근거

| 자료 | 확인한 범위 | 적용 한계 |
|---|---|---|
| [systemd255 D-Bus 문서](https://www.freedesktop.org/software/systemd/man/255/org.freedesktop.systemd1.html) | Service 속성의 ExecMain 실행 정보와 Result·MainPID의 서로 다른 의미. Result=success만으로 실행 여부·현재 기능 정상을 증명하지 않음 | 실제 B는 systemd255.4-1ubuntu8.18. 배포판 패치·다른 서버까지 같다고 가정하지 않음 |
| [Docker inspect 공식 문서](https://docs.docker.com/reference/cli/docker/inspect/) | 객체 종류별 상세 정보와 명시적 타입 선택 | unit 미발견을 Docker 객체로 매핑하는 근거가 아님. 기존 등록 MCP의 제한된 필드만 사용 |

공식 문서와 별도로 관리자231 경유 실제 MCP 원문·설치SHA·설정·모델digest를 보존한다. B의 같은 스냅샷 loaded unit187개·컨테이너7개에 Vector 항목이 없었으며, 이는 전체 설치·모든 프로세스의 부재 증명이 아니다. 원문은 로컬 전용이며 공개 원장에는 해시·범위·검증 결과만 둔다.

문서 열람과 실제 관측은 2026-11-16 KST이다. 본 검증은 새 공격이나 학습 자료 수집이 아니며 모델 일반 정확도를 주장하지 않는다.
