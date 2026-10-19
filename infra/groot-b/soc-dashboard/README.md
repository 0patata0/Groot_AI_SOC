# Groot SOC 통합 탐지 대시보드

Wazuh의 기존 `wazuh-alerts-*` 인덱스 패턴을 사용하는 통합 SOC 대시보드다. WAF·Suricata·Wazuh 기타 알림의 문서 수를 비교하며, 기본 시간 범위는 최근 7일이고 자동 갱신 간격은 30초다. 시간 표시는 기존 브라우저 시간대 설정을 따른다.

대시보드 ID는 `groot-soc-20261019-dashboard`이며 시각화 13개와 저장된 검색 1개를 연결한다. 같은 접두사의 새 객체만 사용하고 기존 객체·인덱스 패턴·전역 설정은 변경하지 않는다.

| 패널 | 집계 기준 |
|---|---|
| 전체·WAF·Suricata·Wazuh 기타·레벨 7 이상 | 선택 기간의 알림 문서 수 |
| 네트워크·웹 탐지 추이 | `timestamp` 시간 구간별 WAF·Suricata 알림 |
| 원천 비중 | WAF·Suricata·Wazuh 기타 |
| Suricata 시그니처 상위 8 | `data.alert.signature` |
| WAF 규칙 분류 | `100101` CRS 탐지, `100102` 이상 점수, `100103` 반복 탐지 |
| WAF·Suricata 출발지 상위 8 | `data.transaction.client_ip`, `data.src_ip` |
| Wazuh 기타 상위 8 | WAF·Suricata를 제외한 `rule.description` |
| 최근 레벨 7 이상 알림 | 시각·에이전트·룰 레벨·설명, 최신순 |

## 집계의 의미

알림 문서 수는 고유 공격 수가 아니다. 실습과 정상 관리 트래픽으로 발생한 탐지·오탐도 포함한다. WAF는 현재 DetectionOnly이며 탐지 건수나 HTTP 403을 차단 성공 건수로 해석하지 않는다. 레벨 7 이상은 이 화면의 확인 대상 기준이며 모든 이벤트의 공격 여부를 확정하는 기준이 아니다.

원본과 중복될 수 있는 정규화 관측·증거와 합성 검증을 제외하기 위해 모든 시각화, 저장된 검색, 대시보드에 다음 조건을 각각 넣는다. 개별 시각화를 열어도 같은 기본 조건을 유지한다.

```text
NOT rule.groups:(capstone_vector_evidence OR capstone_observation OR capstone_vector_canary OR capstone_validation OR package_shadow)
```

WAF는 `rule.groups:(waf OR modsecurity)`, Suricata는 `rule.groups:suricata`, Wazuh 기타는 이 세 그룹을 제외한 알림이다. 기타에는 인증·운영 상태 등 보안 공격이 아닌 알림도 포함한다. 그룹으로 표시되지 않은 과거 실습 이벤트까지 모두 제거했다는 의미는 아니다. 조회 기간을 바꾸거나 차트 항목을 클릭해 추가 필터를 적용할 수 있다.

## 소스와 복원

```sh
python3 -B infra/groot-b/soc-dashboard/build_dashboard.py
python3 -B infra/groot-b/soc-dashboard/build_dashboard.py --check
```

`generated/soc-dashboard.ndjson`은 가져오기용이며 `generated/soc-dashboard.json`은 같은 내용을 읽기 쉽게 출력한 파일이다. 생성기는 네트워크·인증·서버 변경을 하지 않고 고정 ID·참조·필드·공통 조건·그리드를 검사한다. 생성물에는 실제 로그·출발지 IP·계정 비밀값이 없다. 실제 운영 적용 후 내보낸 파일과 검증 근거는 아래 적용 기록에 구분해 보존한다.

다른 환경에 가져오려면 먼저 `timestamp`를 시간 필드로 사용하는 `wazuh-alerts-*` 인덱스 패턴과 같은 ID가 있는지 확인한다. Wazuh의 Dashboards management → Saved objects에서 NDJSON을 가져올 수 있다. 이 대시보드는 해당 인덱스 패턴을 외부 참조하며 파일에 기존 인덱스 패턴 전체를 복제하지 않는다. 기존 동일 ID가 있으면 비교 없이 덮어쓰지 않는다.

실측 대상은 Wazuh 4.14.8 / OpenSearch Dashboards 2.19.6이다. 현재 `opensearch_security.multitenancy.enabled: false`이므로 기존 기본 전역 영역에서 생성하며 API의 `securitytenant` 헤더를 생략한다. 이 설치 버전에서 명시한 `global` 문자열은 별도 tenant 요청으로 전달되어 403이 났다. 이를 해결하기 위해 권한이나 설정을 확대하지 않았다. 다중 tenant를 사용하는 다른 환경은 대상 영역을 먼저 확인해야 한다.

API 생성의 HTTP 200만으로 완료를 판단하지 않는다. 각 객체 오류와 재조회한 참조를 검사하고, 실제 브라우저에서 수치·차트·표와 기간·자동 갱신을 확인한다. 내보내기는 새 객체들만 대상으로 한다.

근거: [Wazuh 사용자 대시보드](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/creating-custom-dashboards.html), [Saved Objects API](https://docs.opensearch.org/latest/dashboards/management/saved-objects-api/), [2.19.6 Saved Objects 생성 계약](https://raw.githubusercontent.com/opensearch-project/OpenSearch-Dashboards/2.19.6/src/core/server/saved_objects/routes/create.ts). 속성 형식과 tenant 동작은 B에 설치된 2.19.6 소스와 라이브 API로 대조한다.

## 적용·검증 기록 — 2026-10-19

[운영 대시보드](https://wazuh.grootlab.duckdns.org/app/dashboards#/view/groot-soc-20261019-dashboard)는 23:12 KST에 생성했고, 23:16에 글자 크기·표 너비·축 표기를 보정했다. 신규 ID의 부재를 확인하고 덮어쓰기 없이 생성했으며 이후 보정은 자신이 생성한 객체만 version 조건으로 갱신했다. 브라우저에서 14개 패널의 수치·차트·출발지 표·최근 알림 표 표시, 최근 7일·30초 자동 갱신을 확인했다.

23:21 KST API 재검증에서 새 객체 15개의 속성·참조가 생성물과 일치하고, 기존 인덱스 패턴 7개가 불변이며 상태는 green이었다. 같은 시점의 최근 7일은 전체 15,000 / WAF 190 / Suricata 300 / 기타 14,510 / 레벨 7 이상 270문서였다. WAF·Suricata 그룹 중복은 0이고 세 원천 합계가 전체와 일치했다. 수치는 계속 갱신된다.

- [가져오기용 생성물](generated/soc-dashboard.ndjson) SHA-256: `913e4d94b2fc6da7c716e49d73e6299ee7ada38bf5daf39bdb0ef636856c3092`
- [최종 라이브 내보내기](live-export-20261019.ndjson) SHA-256: `c2d9572b796961fa17affea86ed9e803f684d7de3140ed46ab48ca5b75ed61d8`
- [적용·검증 근거](deployment-validation-20261019.json): 초기 생성과 최종 보정 이력을 구분한다.

소스·생성물·내보내기·검증 기록은 B의 `/var/backups/capstone-soc-dashboard/20261019/`에도 보존한다. 원본 로그·출발지 값·계정 정보는 내보내기에 포함하지 않았다. 신규 패키지 설치, 컨테이너 재시작, 수집/탐지 규칙 변경, 공격 실행은 하지 않았다. WAF 출발지는 프록시 관측 주소일 수 있으므로 원래 공격자 주소로 단정하지 않는다.

VPN 임시 허용은 **2026-10-20 23:59 KST**에 닫히지만 이 저장된 대시보드는 삭제되지 않는다. 기존 학과망 경로와 계정 인증은 유지한다.
