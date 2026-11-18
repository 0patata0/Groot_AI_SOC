# 서비스 조회의 대상·기간·출력 계약

패치는 당시 설치 원본에 대한 재현 자료다. 현재 정본이나 다른 서버에 무조건 적용하는 설치기가 아니며 영수증·승인·보호 검사를 대신하지 않는다. 실제 검증에서는 13개 원본 복제에 패치를 적용하고 역적용해 양쪽 SHA를 대조했다. 신규 설치는 기존 deploy.sh를 사용한다. 실제 새 OS 전체 설치는 하지 않았다.

[동작·사용·한계](../../hermes/service-query-contract.md) · [10원본/후보 SHA·실제 검증](../../hermes/query-completion/service-catalog.validation.json)


등록되지 않거나 대상이 모호한 요청을 현재 관측 완료로 처리하지 않는다. 명확한 등록 서비스의 현재 사실 조회와, 복합 원인·영향·전체 이력 조사·모든 새 표현의 처리·일반 정확도/SLO·새 OS 전체 설치는 별도 검증 범위다.


<!-- service-cause-candidate-20261119 -->

복합 원인 조사에는 별도 실패가 남아 있다. SDK 필수 조회 연결 후보는3반례와 회귀833검사·Linux 공식38/설치37검사를 통과했지만 실제 격리 실행에서 최종 보고가 수용되지 않았다. 후보 검증과 운영 적용을 구분하며 해당 후보를 배포하지 않는다. [원인·수행·미완료](../../hermes/service-query-contract.md) · [실제 실패·후보 검증](cause-completion.validation.json).

[미적용 SDK 연결 패치](cause-completion.patch)는 해당 원본 SHA에서만 재현하는 자료다. 현재 확정된 operating.patch를 대체하지 않는다.
<!-- /service-cause-candidate-20261119 -->


<!-- service-report-provenance-candidate-20261119 -->

현재 확정된 `operating.patch`는 유지한다. 새 `report-provenance.patch`는 특정14원본의 미적용 후보이며 양방향 복원 SHA를 확인했다. 운영 설치기에 직접 적용하지 않는다. 서비스 현재 조회의 기존 확정 결과는 유지한다. 원인·이력 조사는 현재 수집본과 실제 journal을 함께 읽으며 자동 선택한 최근 구간을 초기 확인 범위로 표시한다. 보고에서 근거를 넘는 문장을 제외하더라도 원래 판단·검토 상태와 조회 범위 안내를 유지한다. 모델·MCP·권한·보호 주소·승인·차단 TTL은 이번 보완의 변경 대상이 아니다. [검증·미적용·남은 문제](report-provenance.validation.json) · [공통 동작](../../hermes/service-query-contract.md).
<!-- /service-report-provenance-candidate-20261119 -->
