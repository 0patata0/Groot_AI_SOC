# 조회·해석 범위의 근거

| 자료 | 사용하는 근거 | 적용 한계 |
|---|---|---|
| [systemd255 D-Bus 공식 문서](https://www.freedesktop.org/software/systemd/man/255/org.freedesktop.systemd1.html) | LoadState와 ActiveState는 별개이고 FragmentPath는 unit을 읽은 경로다. 실행·로드·설치 설정을 구분한다 | not-found 한 속성으로 모든 물리 파일·프로세스의 부재를 증명한다는 문서가 아니다. 프로젝트의 보고 경계는 실제 반환 필드와 읽기 범위에 근거한 제한이다 |
| [Docker container ls 공식 문서](https://docs.docker.com/reference/cli/docker/container/ls/) | --all 목록과 --size의 크기 조회는 구분된다 | 실제 API 호출자를 이 문서만으로 식별하지 않는다. 기존 MCP 수집 코드와 로그의 요청 URI를 별도로 대조한다 |
| [공식 Harness² 고정 소스](https://github.com/google-research/harness2/tree/6868817518876de8fd170c6a8354daca273b6191) | 공식 tree.validate와 diff_summary로 편집 면·상시 문맥·스킬 재사용을 검사한다 | 구조 검사는 모델 정확도·운영 채택·권한 승인·실제 채팅 검증을 대신하지 않는다 |

실제 B의 설치 소스·MCP 응답·설정·학습 모델 digest는 관리자231 경유로 읽었다. 설치된 host_inventory.py의 SHA256은 `d3e6276349c2c04aa5e80e04cbaca6616c6b44e67c8cd2042bf2cb5c7e6ed204`이며 컨테이너 목록 명령에는 --size가 없다. 이것은 다른 호출자의 존재/부재나 과거500의 원인 판정이 아니다. 원문·출처 파일·전체 해시는 로컬 전용으로 보존한다.

문서 확인과 관측일은 2026-11-16 KST이다. Docker API v1.51 문서는 현재 실제 URI의 v1.56 호환성 근거로 채택하지 않았다. 새 공격·학습자료·정답 수집이 아니며 개발 관측은 독립 평가로 사용하지 않는다.
