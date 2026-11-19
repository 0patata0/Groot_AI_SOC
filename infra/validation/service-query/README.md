# 서비스 조회의 대상·기간·출력 계약

패치는 당시 설치 원본에 대한 재현 자료다. 현재 정본이나 다른 서버에 무조건 적용하는 설치기가 아니며 영수증·승인·보호 검사를 대신하지 않는다. 실제 검증에서는 13개 원본 복제에 패치를 적용하고 역적용해 양쪽 SHA를 대조했다. 신규 설치는 기존 deploy.sh를 사용한다. 실제 새 OS 전체 설치는 하지 않았다.

[동작·사용·한계](../../hermes/service-query-contract.md) · [10원본/후보 SHA·실제 검증](../../hermes/query-completion/service-catalog.validation.json)


등록되지 않거나 대상이 모호한 요청을 현재 관측 완료로 처리하지 않는다. 명확한 등록 서비스의 현재 사실 조회와, 복합 원인·영향·전체 이력 조사·모든 새 표현의 처리·일반 정확도/SLO·새 OS 전체 설치는 별도 검증 범위다.


<!-- service-cause-candidate-20261119 -->

복합 원인 조사에는 별도 실패가 남아 있다. SDK 필수 조회 연결 후보는3반례와 회귀833검사·Linux 공식38/설치37검사를 통과했지만 실제 격리 실행에서 최종 보고가 수용되지 않았다. 후보 검증과 운영 적용을 구분하며 해당 후보를 배포하지 않는다. [원인·수행·미완료](../../hermes/service-query-contract.md) · [실제 실패·후보 검증](cause-completion.validation.json).

[미적용 SDK 연결 패치](cause-completion.patch)는 해당 원본 SHA에서만 재현하는 자료다. 현재 확정된 operating.patch를 대체하지 않는다.
<!-- /service-cause-candidate-20261119 -->


<!-- service-provenance-summary-in-archive -->


<!-- service-report-schema-recovery-20261119 -->

`schema-recovery.patch`는 기존 운영17원본에 대한 미적용 후보다. 앞선 `claim-types.patch`와 `report-provenance.patch`는 과거 후보로 보존하며 `operating.patch`의 확정을 대체하지 않는다. 격리한 실제 추론2회는69.798초와73.658초였으며 각각 읽기3회를 수행했다. 후속 시험에서는 형식 정정이 발동하지 않았고 원인·주기·기능 상태를 과도하게 단정하는 문장이 남아 내용 검증을 통과하지 못했다. 모델 호출은4회와5회였고 보호 작업·새 채팅·운영 변경은0이다. 응답 속도와 정확도의 개선을 입증하지 못했으므로 운영에 적용하지 않았다. 이후 참조 경계를 보완한 최종 후보의 실제 추론도 아직 수행하지 않았다. [검증·후보·미적용](schema-recovery.validation.json).
<!-- /service-report-schema-recovery-20261119 -->
