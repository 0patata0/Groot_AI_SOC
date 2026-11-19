# 서비스 조회의 대상·기간·출력 계약

패치는 당시 설치 원본에 대한 재현 자료다. 현재 정본이나 다른 서버에 무조건 적용하는 설치기가 아니며 영수증·승인·보호 검사를 대신하지 않는다. 실제 검증에서는 13개 원본 복제에 패치를 적용하고 역적용해 양쪽 SHA를 대조했다. 신규 설치는 기존 deploy.sh를 사용한다. 실제 새 OS 전체 설치는 하지 않았다.

[동작·사용·한계](../../hermes/service-query-contract.md) · [10원본/후보 SHA·실제 검증](../../hermes/query-completion/service-catalog.validation.json)


등록되지 않거나 대상이 모호한 요청을 현재 관측 완료로 처리하지 않는다. 명확한 등록 서비스의 현재 사실 조회와, 복합 원인·영향·전체 이력 조사·모든 새 표현의 처리·일반 정확도/SLO·새 OS 전체 설치는 별도 검증 범위다.


<!-- service-cause-candidate-20261119 -->

복합 원인 조사에는 별도 실패가 남아 있다. SDK 필수 조회 연결 후보는3반례와 회귀833검사·Linux 공식38/설치37검사를 통과했지만 실제 격리 실행에서 최종 보고가 수용되지 않았다. 후보 검증과 운영 적용을 구분하며 해당 후보를 배포하지 않는다. [원인·수행·미완료](../../hermes/service-query-contract.md) · [실제 실패·후보 검증](cause-completion.validation.json).

[미적용 SDK 연결 패치](cause-completion.patch)는 해당 원본 SHA에서만 재현하는 자료다. 현재 확정된 operating.patch를 대체하지 않는다.
<!-- /service-cause-candidate-20261119 -->


<!-- service-provenance-summary-in-archive -->


<!-- native-identity-parity-20261119 -->

서비스 이름을 실제 구성요소와 구분하는 공통 조회 계약을 Hermes·Ollama·공동 관리 경로에 연결했다. 등록된 논리 서비스의 unit이 LoadState=not-found이면 같은 호스트의 서비스·컨테이너 목록을 확인한다. 목록 조회가 끝나도 구성요소가 확인되지 않으면 unresolved_service_lookup과 needs_review 또는 partial을 유지한다. 명시적인 unit 조회와 실제 loaded 서비스의 현재 상태 조회는 이 구분을 따른다.

| 새 대화 시험 | Hermes | Ollama | 확인 결과 |
|---|---:|---:|---|
| B 서버 Vector | 16.892초 | 11.652초 | 구성요소 미확인·추가 검토, 각 5읽기 |
| A 서버 Vector | 10.398초 | 13.549초 | loaded·active·running 관측, 각 2읽기 |

[검증·적용·한계](identity-parity.validation.json) · [설치 원본 23파일 기준 패치](identity-parity.patch).
<!-- /native-identity-parity-20261119 -->
