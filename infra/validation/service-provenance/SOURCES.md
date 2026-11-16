# 출처와 관측 범위

| 출처 | 사용하는 근거 | 한계 |
|---|---|---|
| [systemd255 D-Bus 공식 문서](https://www.freedesktop.org/software/systemd/man/255/org.freedesktop.systemd1.html) | LoadState·ActiveState와 실제 실행/설치 설정을 구분 | not-found만으로 모든 파일·실제 프로세스·논리 구성요소 부재를 증명하지 않음 |
| [공식 Harness² 고정 소스](https://github.com/google-research/harness2/tree/6868817518876de8fd170c6a8354daca273b6191) | 공식 tree.validate·diff_summary로 편집 범위와 문맥 검사 | 모델 정확성·운영 승인·실제 채팅 검증을 대체하지 않음 |
| [부모 사실 조회 기록](../factual-service/README.md) | 기본 속성을 프로세스로 바꾼 응답·근거 없는 관련 컨테이너 표현·인용 오탐이 이번 개선의 출발 근거 | 당시 source/회귀/실제 관측과 이번 후보의 관측을 소급해서 합치지 않음 |
| [동결 source manifest](manifest.json)·[실행 입력](source-manifest.json) |643소스 및 모델 시험126입력(59소스/arm) SHA·검사 원본·버전 재현 | 권한·설정·패키지·운영 설치 완료를 인증하는 자료 아님 |

라이브 사실은 관리자231 경유 B에서 관측했다. 모델은 같은35B 학습본, access_mode는 hermes-parity다. 실제 응답의 원문·정확 요청/응답·해시·소스/권한·모델 메타데이터는 로컬 전용 검증에 보존한다. 공개 원장은 민감한 원문 대신 재현 코드·범위·수량·SHA와 한계를 남긴다.

Docker의 과거 HTTP500 4행은 이번 all 표본에도 실제로 존재했다. 모두 priority6인 반면 고정 errors 표본은0행이었다. 이는 이번 범위의 관측이며 모든 Docker 오류·로그 우선순위에 일반화하지 않는다. 오류 필터의 모든 원인이나 실제 API 호출자는 아직 조사하지 않았다. Canceled 문자열을 네트워크 장애나 정상 복구의 근거로 삼지 않는다. 새 자료 수집·SFT 편입·학습은 진행하지 않았다.
