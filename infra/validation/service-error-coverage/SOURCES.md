# 출처와 적용 한계

| 자료 | 사용하는 근거 | 한계 |
|---|---|---|
| [고정 오류 후보 코드](../../mcp/system_diagnostics.py)·[journal 구현](../../mcp/diagnostic_journal.py) | journal 우선순위와 고정 문자열 후보를 구분한다. 실행 입력의 정확 SHA는 별도 원장 | 설치 사본과 같다는 보장이나 현재 기본15분 표본을 과거 구간으로 바꾸는 근거 아님 |
| [동결 명세](manifest.json)·[실행 입력 SHA](source-manifest.json) | 최종643소스/5변경·R1/R2/R3 각126입력(arm별59소스)을 식별 | 중간 실제 응답·원문은 로컬 전용이며 공개 재현은 최종 회귀/구조만 |
| [공식 Harness² 고정 소스](https://github.com/google-research/harness2/tree/6868817518876de8fd170c6a8354daca273b6191) | tree.validate/diff_summary로 구조·편집 범위 검사 | 모델 정확도·운영 승인·실제 채팅을 대체하지 않음 |
| [부모 검증](../service-provenance/README.md) | 미확인 타입·원문 출처·사실 조회 확인을 계승 | 부모의 과거 관측/실패와 이번 소스를 소급해 바꾸지 않음 |

실제 관측은 관리자231 경유 B에서 수행했다. 같은 구간 errors0와 all12행/HTTP5004를 확인했으며,24시간 all에는 별도 DNS timeout도 있었다. 해당 관측과 고정 후보 코드의 범위가 필터 보완의 근거다. 현재 snapshot의 기본15분0은 다른 기간이라 그 값만으로 수집기의 누락·복구 완료를 확인하지 않는다. 수집 메타데이터의 동일 기간 대조는 남아 있다.

no such file or directory/Canceled 문자열은 직접 오류 정보이며 데이터 손실·삭제·호출자·지속 영향의 근거가 아니다. Docker active도 DNS 일시성이나 전체 기능 정상을 증명하지 않는다. 이번 자료는 개발/회귀 관측이며 SFT 편입·새 학습·독립 사고 정답 수집을 수행하지 않았다.
