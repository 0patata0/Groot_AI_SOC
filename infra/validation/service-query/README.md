# 서비스 조회의 대상·기간·출력 계약

패치는 당시 설치 원본에 대한 재현 자료다. 현재 정본이나 다른 서버에 무조건 적용하는 설치기가 아니며 영수증·승인·보호 검사를 대신하지 않는다. 실제 검증에서는 13개 원본 복제에 패치를 적용하고 역적용해 양쪽 SHA를 대조했다. 신규 설치는 기존 deploy.sh를 사용한다. 실제 새 OS 전체 설치는 하지 않았다.

[동작·사용·한계](../../hermes/service-query-contract.md) · [10원본/후보 SHA·실제 검증](../../hermes/query-completion/service-catalog.validation.json)


등록되지 않거나 대상이 모호한 요청을 현재 관측 완료로 처리하지 않는다. 명확한 등록 서비스의 현재 사실 조회와, 복합 원인·영향·전체 이력 조사·모든 새 표현의 처리·일반 정확도/SLO·새 OS 전체 설치는 별도 검증 범위다.


<!-- service-cause-candidate-20261119 -->

복합 원인 조사에는 별도 실패가 남아 있다. SDK 필수 조회 연결 후보는3반례와 회귀833검사·Linux 공식38/설치37검사를 통과했지만 실제 격리 실행에서 최종 보고가 수용되지 않았다. 후보 검증과 운영 적용을 구분하며 해당 후보를 배포하지 않는다. [원인·수행·미완료](../../hermes/service-query-contract.md) · [실제 실패·후보 검증](cause-completion.validation.json).

[미적용 SDK 연결 패치](cause-completion.patch)는 해당 원본 SHA에서만 재현하는 자료다. 현재 확정된 operating.patch를 대체하지 않는다.
<!-- /service-cause-candidate-20261119 -->


<!-- service-provenance-summary-in-archive -->


<!-- native-identity-boundary-20261119 -->

Hermes·공동 관리 경로의 최종 완료 경계에서 추가 공백을 확인했다. 서비스·컨테이너 목록을 모두 읽으면 pending은 비지만 논리 서비스의 실체가 확인됐다는 뜻은 아니다. 기존 chat_diagnostic_state는 이 미확인 상태를 최종 incomplete에 남기지 않았다. 이 때문에 짧은 요청에서 service_history_plan이 없을 때도 완료 방어가 유지되도록 정본에 4줄을 추가했다.

이번 변경은 정본과 집중검사에만 반영했다. 운영 파일·서비스·권한·모델을 바꾸지 않았고 새 모델 호출·MCP 도구 실행·채팅 게시·공격·학습도 하지 않았다. E17의 실제 SDK 단회 22.172초·partial 결과는 별도 근거로 유지한다. Native 전체 설치 사본 연결·SHA pin·영수증·복구·실제 채팅과 Vector의 실제 수집 경로 확인은 남아 있다. 15:50 KST 전에 기록·게시를 마치고 새 작업은 시작하지 않는다.

[Native 완료 경계 검증·미적용](native-identity.validation.json) · [E17 SDK 실제 관측](service-identity.validation.json) · [전체 경과](../../../archive/DIAGNOSTIC_HISTORY.md#native-identity-boundary-20261119).
<!-- /native-identity-boundary-20261119 -->
