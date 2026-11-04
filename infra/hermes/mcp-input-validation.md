# Native MCP 입력 검증과 연결 오류 구분

2026-11-05 KST. 공통1.5.27/query1.19.22. 모델이 도구·인자를 선택하고 기존 MCP/승인 경계를 유지한다. [현황](../../STATUS.md) · [검증 원장](mcp-input-validation.json) · [앞선 SDK 조회 회복](incident-closure-minimum.md).

| 실제 문제 | 변경 |
|---|---|
| rule-b에a:waf·진단의requested_at_kst·IDS destination_ip 등 미지원 인자 | Native 관리 registry dispatch와 Mattermost pre-tool hook에서 실제 도구 스키마로 먼저 검사. 원래 plugin의 거부·변경 인자를 존중 |
| manager 로그를 agent 사건 이력으로 조회 | manager/agent 업무 차이를 공통 지침에 표시. manager level은 숫자 경보 레벨과 구별하고 실제 운영 API가 반환한6개 enum을 안내 |
| 잘못된 인자를 보낸 뒤 연결 장애로 집계 | 실제 MCP invalid-params(-32602) 응답을 읽기의 application error로 전달. 네트워크·다른 프로토콜 오류·보호 쓰기는 원래 예외/복구 경로 유지 |
| Rust/Python 예외 이름 차이 | 설치본은MCPError이며 Python SDK의McpError도 지원. 실제 예외 클래스와code를 대조하며 문자열만으로 통신 성공을 추정하지 않음 |

공통 구현은 `soc_management_run.py`의 `tool_input_schema`, `tool_input_rejection`, `read_protocol_error_result`다. Native 일반 채팅·관리 CLI가 같은 함수를 사용하고 SDK도 동일한 manager 입력 스키마를 광고/검증한다. 잘못된 인자를 자동 삭제·보정하거나 실제 도구를 대신 선택하지 않는다. 로컬 거절은 executed/mcp_executed=false와 예상 스키마를 반환한다. 스키마/검증기가 없으면 성공으로 통과시키지 않는다.

manager의level enum은 실제 Wazuh API400이 반환한critical/debug/debug2/error/info/warning을 근거로 한다. MCP 카탈로그가 이미 정의한 필드만 사용하고 서비스·도구·권한을 추가하지 않는다. 현재 manager 로그는 임의 과거 구간/agent 경보를 지원하지 않는다. 해당 업무는 실제search_wazuh_alerts를 사용해야 한다.

## 검증과 범위

서버 관리257·SDK216·Native390·설치38·review60=**961PASS/skip0**. 최초 추가8검사 뒤 Native chat pre-tool/실제Rust예외 호환2검사를 보강한 최종 집계이며 중간 반복을 더하지 않는다. 실제 새 서버 설치는 실행하지 않았다. Mac의jsonschema/설치된Native 의존성 검사 생략과 서버의 실제 의존성 통과를 구별한다.

Native 실제 UID995 관리 진입점과 현재 registry/MCP에서 과거 실패9인자를 재생했다. **9개 모두 로컬 거절·Native wire 호출0**이다. 하위 경계의 의도적 잘못된 읽기RPC1회는 실제-32602/application strike1로 유지됐고, 다음 올바른 manager 조회1회가 성공해 계수0이 됐다. 모델0·보호 쓰기0, 기존 회로 차단/재연결/승인 정책을 제거하거나 임의 초기화하지 않았다.

처음 경계 시험은 Rust의MCPError와 Python SDK의McpError 차이로 거절됐다. 실제 예외 클래스/코드를 관측한 뒤 수정·동일 실제 경계 시험을 통과했다. 단위 검사의 모듈 대역도 실제 import 방식으로 맞췄다. 설치 재검사의 잘못된 검색 경로/0tests는 실패로 보존한 뒤 정확한deployment/tests/test_soc_management.py의38검사를 확인했다. 이 중간 실패를 성공 집계에 더하지 않는다.

별도의 실제 과거 DVWA 사건 새 모델 재검토는149.645초·실제8조회/오류0·보호쓰기0, monitor/model_requested_followup·보고 전달1이었다. 실제웹등록/접근·인벤토리·agent002 사건/후속 구간 경보까지 읽었다. 이전13호출9오류와 달리 실행은 회복됐지만 단일 표본의 지연 향상이나 사건 종결 성공은 아니다.

보고서는 최초 차단 시각을 임시 만료 시각15:00:28과 같게 썼다. 실제상태API는temporary_expires_at/owned_deadline·관측/종료 시각을 제공하며 최초 적용 시각은 반환하지 않았다. 이 내용 오류는 확인된 잔여로 남긴다. 일반 인증 로그의 정상화·표본/기간·조치 필요성 표현도 의미 검증 대상이며 도구 오류0을 답변 전체 정확성으로 바꾸지 않는다. 위9거절/2RPC는 모델 도구 선택 정확도나 실제 침해 영향·사건 종결의 증명이 아니다. 입력 오류를 고쳐 재조회했어도 controller의 기존 엄격한 실패/근거 검사와 원문 감사는 유지한다.

## 배포·설치·복구

B의14대상 common/query/alignment·SDK·root참조/포함gate·영수증을 기존 소유권/모드·SHA 대조 후 갱신했다. root controller의 AST 변경은 포함gate 상수뿐이며 채널/설정 값과 나머지 로직은 같다. Native컨테이너1회·SDK/review각1회 재시작, 보호config7SHA·기존 모델·FW/TTL/승인·키/포트·일반 권한은 유지한다.

원본/후보/manifest와 독립15분 복구는 `/var/lib/capstone-native-input/20261105-r1/deployment`에 둔다. 관리 실행이나 SDK/review 대기·실행이 있으면 복구를 유예하고 실제 SHA drift는 덮어쓰지 않는다. 01:21:36 KST14파일·보호설정7SHA·실제gate/참조·양봇WS/worker heartbeat·4서비스를 확인해 확정했다. 독립 타이머를 해제하고confirmed recovery no-op을 확인했다. 실제 수동 복구/새 공격E2E는 미시험이다. 운영DB·승인·대화·가중치는 원복/정리 대상이 아니다.

단일deploy.sh의 기존 canonical 복사·source bundle·gate 렌더링 경로로 초기 설치에도 포함된다. 새파일 경로·패키지·이미지·포트·키 추가0이다. jsonschema와MCP는 현재 고정Native 이미지/SDK의 기존 의존성이며 오프라인 반입은 소스 갱신 범위다. 설치38은 소스/렌더 계약이며 실제 새3VM 전체 설치를 대신하지 않는다.
