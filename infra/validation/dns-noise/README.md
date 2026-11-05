# DuckDNS 정보성 경보와 상관 집계 후보

2026-11-05 KST. [현황](../../../STATUS.md) · [작은 원장](validation.json) · [정확 후보](candidate.xml) · [승인 카드](https://chat.grootlab.duckdns.org/soc/pl/ejs6odcpuifu7jc8m4a9ndpkdc). **운영 Wazuh 룰은 미적용**이다. 정확 후보 카드는10:10:56 KST 만료됐고10:12:23 실제 helper에서 expired와 운영 원본SHA 유지를 확인했다. 승인 없이 재발급·적용하지 않았다.

## 실제 원인과 반영 범위

| 구분 | 실제 확인 | 조치 상태 |
|---|---|---|
| 원본 센서 | 11/5 08:11 KST `chat.grootlab.duckdns.org` A/AAAA, A→설정 DNS리졸버 UDP/53. 같은 질의에 SID2022918/2042936이 함께 발생. 후자의 category는 Potentially Bad Traffic, 둘 다 metadata.signature_severity는 Informational | 원본 ET 룰·분류/경보를 삭제하거나 도메인 전체를 면제하지 않음 |
| 상관 규칙 | 100112가 parent86601을8건/120초로 집계. 실제 같은 DNS 조회의 두 SID와 저레벨 정보가 급증으로 나타남. 같은 native 대조에서 실제 high/medium 자식 반복은 parentSID 집계에 잡히지 않음 | 아래의 정확 후보를 준비·14조건 검증, 운영 적용 대기 |
| 읽기 도구 | 이전 MCP가 원본 metadata를 보내지 않아 category/severity만 보임 | security-events1.2.1에 제공자 심각도/신뢰도·flow/DNS 원필드와 의미·미확인 범위를 추가·실제 SDK계정 MCP5표본 Informational 확인 |
| 조사 절차 | DDNS·사설주소·분류명만으로 악성/정상/승인을 단정할 위험 | soc-investigate에 실제 질의/리졸버/자산·추가 행위·중복 SID 대조를 추가하고 세 프로필 SHA 동기화 |

category는 센서의 분류명, metadata는 공급자의 기록된 표지다. 둘 다 실제 C2·유출·프로세스의 승인 또는 무해성 판정이 아니다. MCP 원문 보존·범위/식별자 전달과 LLM의 사건 판단을 구분한다. 기대 서비스명처럼 보인다는 이유로 광역 suppress나 정상 판정을 하지 않는다.

## 정확 후보

정보성 형제 룰100115는 **정확 SID2개·severity2/3·원본 Informational**이 모두 있어야 레벨3 관찰로 기록한다. fallback100114와 high100110/medium100111에 공통 `capstone_ids_burst_candidate` 그룹을 각각 명시하고 100112가 그 그룹의 같은 출발지8회/120초를 집계한다. 부모의 사용자 정의 그룹이 자식에 자동 상속된다고 가정하지 않는다. generic burst 자체에 고정 T1595를 부여하던 항목은 제거하고 실제 기법 판단을 조사로 남긴다.

Wazuh의 [공식 규칙 문법](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html#if-matched-group)은 그룹 기반 빈도 집계를 정의한다. 이 환경의 실제 동작과 이전 누락은 동일 이미지의 별도 before/candidate 엔진으로 검증했다. 정상 DNS뿐 아니라 정보가 빠졌거나 severity가 바뀐 동일 SID와 다른 악성 DNS의 탐지를 확인했다. 이는 전체 공격·네트워크 E2E를 증명하지 않는다.

| 격리 native 조건 | 후보 결과 |
|---|---|
| 자체 조회의 두 SID 반복·다른 DDNS 정보성 | 레벨3 기록 유지, 공격 급증0 |
| high/medium 단건 | 기존100110/100111 유지 |
| high/medium 급증 | 실제8번째 경보에서100112 |
| DNS16건+공격1건 | 공격1건의 원래 경보만, 급증0 |
| DNS16건+공격 급증 | 실제 공격8번째(전체24번째)에100112 |
| 서로 다른 출발지 | 같은 출발지 급증으로 합치지 않음 |
| 메타데이터 누락·severity1 변경·다른 악성 DNS | 단건 탐지 유지, 누락/변경 동일 SID 급증도8번째 탐지 |

전체14조건·짝지은28개 private 시험 세션 삭제 확인. 최초 시험의 client 토큰 미재사용/사본 권한·설정/그룹 처리 오류는 실패로 보존했다. 최종 시험은 운영 agent/경보에 주입하지 않는 networknone 별도 이미지2개에서만 수행했다. 초기 잘못된 client 시험의 운영 logtest 세션은 토큰을 출력·보존하지 않아 일괄 삭제하지 않았다. 해당 세션의 즉시 삭제·실제 만료 기한은 확인하지 못했다. 운영 룰/agent/수집기 재시작은 시험에서 수행하지 않았다.

## MCP 검증 호환과 배포

정상적인 `<rule><group>name,</group></rule>`을 컨테이너 group으로 오인해 제안을 거절하던 구조 검사를 수정했다. leaf 분류 표지만 허용하며, 외부 일반 텍스트·빈/중첩/속성 있는 표지·command/active-response 금지는 유지한다. 서버67개 executor 검사와 native 검증을 별도로 확인했다. 기존 고정 helper 한 함수만 graft하고 나머지 AST·host/target/권한/정확 승인 검사를 유지했다. 최초 제안은 broker 제출 전 명시 거절, 수정 후 1개 IDS group의 부분 편집 카드가 실제 게시됐다. 결과 불명 호출을 재시도한 것이 아니다.

B context5파일09:41:48·report/helper6파일10:00:15 확정. 보호 설정7SHA·실제gate/참조·양봇 연결·4서비스 확인, 새 도구/키/포트/패키지·일반권한0. report/helper 변경은 채팅 재시작0이다. 기존 deploy.sh의 canonical helper/출력 모듈/스킬 복사 경로에 같은 코드가 포함된다. 새 OS 설치는 사용자 조건으로 수행하지 않았다.

정확 후보 SHA는 `da609dac82a6a4eefdd62336a56d9e53b0632c66f0b2c9779e79283d7e6866f0`, 원본은 `644b298348bf476e6f538267aab531b262ce895a191aac8df1ac47b0c1e80ec0`다. 카드 승인 후 기존 worker가 native 검사·Wazuh 매니저 재시작·SHA/건강을 확인한다. 초기 설치의 canonical local_rules.xml은 승인/운영 반영이 끝나기 전 바꾸지 않는다.

## 모델·표시 검증 한계

새 SDK 질문은69.360초/모델3·실제MCP1·쓰기0/partial였다. Informational은 실제 전달됐으나 모델이 이름/사설주소만으로 정상·서비스 초기화·광역 suppress를 주장한 초안은 근거 검사에 거절됐다. 정보 전달 성공을 사건 판단 성공으로 표시하지 않는다. 등록 서비스/발신 프로세스 근거와 정확한 판단·형식 보정은 계속 보완할 항목이다.

[사건 실패 표 보완](../../../infra/hermes/incident-report-fallback.md)은 별도다. 전체 모델 정확성·상관 해석·사건 종결·새 브라우저 렌더링·실제 새 DNS/공격 E2E는 미완료다.
