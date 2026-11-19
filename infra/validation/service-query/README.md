# 서비스 조회의 대상·기간·출력 계약

패치는 당시 설치 원본에 대한 재현 자료다. 현재 정본이나 다른 서버에 무조건 적용하는 설치기가 아니며 영수증·승인·보호 검사를 대신하지 않는다. 실제 검증에서는 13개 원본 복제에 패치를 적용하고 역적용해 양쪽 SHA를 대조했다. 신규 설치는 기존 deploy.sh를 사용한다. 실제 새 OS 전체 설치는 하지 않았다.

[동작·사용·한계](../../hermes/service-query-contract.md) · [10원본/후보 SHA·실제 검증](../../hermes/query-completion/service-catalog.validation.json)


등록되지 않거나 대상이 모호한 요청을 현재 관측 완료로 처리하지 않는다. 명확한 등록 서비스의 현재 사실 조회와, 복합 원인·영향·전체 이력 조사·모든 새 표현의 처리·일반 정확도/SLO·새 OS 전체 설치는 별도 검증 범위다.


<!-- service-cause-candidate-20261119 -->

복합 원인 조사에는 별도 실패가 남아 있다. SDK 필수 조회 연결 후보는3반례와 회귀833검사·Linux 공식38/설치37검사를 통과했지만 실제 격리 실행에서 최종 보고가 수용되지 않았다. 후보 검증과 운영 적용을 구분하며 해당 후보를 배포하지 않는다. [원인·수행·미완료](../../hermes/service-query-contract.md) · [실제 실패·후보 검증](cause-completion.validation.json).

[미적용 SDK 연결 패치](cause-completion.patch)는 해당 원본 SHA에서만 재현하는 자료다. 현재 확정된 operating.patch를 대체하지 않는다.
<!-- /service-cause-candidate-20261119 -->


<!-- service-provenance-summary-in-archive -->


<!-- service-identity-completion-20261119 -->

SDK 격리 후보는 실제 설치 원본의 7파일을 바탕으로 만들었다. 등록된 진단에서 LoadState=not-found가 반환되면 모델이 같은 호스트의 서비스·컨테이너 목록 읽기를 선택한다. 목록을 모두 읽어도 논리 구성요소를 식별하지 못하면 partial과 추가 확인 필요를 유지한다. inactive/dead·Result=success 기본값을 실제 정지·실행 성공의 근거로 쓰지 않는다. 명시적 unit 조회와 호출자가 지정한 도구 범위는 유지한다.

후보는 SDK에만 연결한 시험본이다. Hermes·공동 관리 경로의 연결, 두 경로의 같은 계약 검증, 설치 영수증·복구·새 실제 채팅 확인을 마치기 전에는 운영 반영 후보로 승격하지 않는다. 앞선 E16의 복합 원인 조사 품질 문제도 해결된 것으로 처리하지 않는다. 보호 정책·권한·모델과 실행 중인 학습은 바꾸지 않았다.

[검증·운영 미적용](service-identity.validation.json) · [설치 원본 7파일 기준 패치](service-identity.patch) · [전체 경과·한계](../../../archive/DIAGNOSTIC_HISTORY.md#service-identity-completion-20261119).
<!-- /service-identity-completion-20261119 -->
