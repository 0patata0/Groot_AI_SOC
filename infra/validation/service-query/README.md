# 서비스 조회의 대상·기간·출력 계약

패치는 당시 설치 원본에 대한 재현 자료다. 현재 정본이나 다른 서버에 무조건 적용하는 설치기가 아니며 영수증·승인·보호 검사를 대신하지 않는다. 실제 검증에서는 13개 원본 복제에 패치를 적용하고 역적용해 양쪽 SHA를 대조했다. 신규 설치는 기존 deploy.sh를 사용한다. 실제 새 OS 전체 설치는 하지 않았다.

[동작·사용·한계](../../hermes/service-query-contract.md) · [10원본/후보 SHA·실제 검증](../../hermes/query-completion/service-catalog.validation.json)


등록되지 않거나 대상이 모호한 요청을 현재 관측 완료로 처리하지 않는다. 명확한 등록 서비스의 현재 사실 조회와, 복합 원인·영향·전체 이력 조사·모든 새 표현의 처리·일반 정확도/SLO·새 OS 전체 설치는 별도 검증 범위다.


<!-- service-cause-candidate-20261119 -->

복합 원인 조사에는 별도 실패가 남아 있다. SDK 필수 조회 연결 후보는3반례와 회귀833검사·Linux 공식38/설치37검사를 통과했지만 실제 격리 실행에서 최종 보고가 수용되지 않았다. 후보 검증과 운영 적용을 구분하며 해당 후보를 배포하지 않는다. [원인·수행·미완료](../../hermes/service-query-contract.md) · [실제 실패·후보 검증](cause-completion.validation.json).

[미적용 SDK 연결 패치](cause-completion.patch)는 해당 원본 SHA에서만 재현하는 자료다. 현재 확정된 operating.patch를 대체하지 않는다.
<!-- /service-cause-candidate-20261119 -->


<!-- service-provenance-summary-in-archive -->


<!-- service-phase-split-20261119 -->

조회 선택·최종 보고 분리 후보는 운영 미적용이다. 같은 실제 조회 자료로 통합81.025초·3호출, 분리37.830초·6호출을 측정했지만 각각 내용 검증 실패와 조회 요구/보고 준비 판단 반복으로 유효한 보고를 완성하지 못했다. Mac·Linux 각각998검사·공식 연계38·설치37통과와 실제 품질·속도 개선은 구분한다. 시험용4폴더를 정리했고 운영64파일·봇 연결·작업자·기존 Hermes 실행 식별자는 유지됐다. 이전 schema-recovery 후보도 미적용이며 확정 운영 패치를 대체하지 않는다.

[후보·실측·미완료](phase-split.validation.json) · [17원본 기준 미적용 패치](phase-split.patch).
<!-- /service-phase-split-20261119 -->
