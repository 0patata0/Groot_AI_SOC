> 2026-11-05 IDS 영향 조사 보완 전의 과거 요약입니다. 현재 문서는 [STATUS](../STATUS.md)와 [PLAN](../PLAN.md)을 확인하세요.

# 인프라 현황 — 2026-11-05 13:45 KST

전체 목표는 **LLM 실전 관제 운용·논문 완성·2026-12-01 최종 발표**이며 active·미완료다. 핵심 기능11/9 마감 목표와 발표 작성은11월둘째주 리마인더 이후라는 조건을 유지한다. [계획](../PLAN.md) · [이번 작업 전 상세](../archive/STATUS-before-shared-status-20261105.md) · [전체 과거 이력](../archive/STATUS-history-20261101.md).

## 현재 우선 과제와 실제 결과

| 과제 | 완료·실제 확인 | 남은 범위 |
|---|---|---|
| 자동 후속 상태·실행 인자 | query1.19.28/common1.5.32. 모든 verify에 실제 연결 owned/shared 상태 요구·정확 ID 안내. 서버935PASS/skip0·B고유9SHA/보호7SHA/자동공유요구1·센서3·양WS/worker 확인 | operation2읽기/오류0·73.448초로 변경절차 completed이나 표0/목록형. IDS4읽기/오류0·190.519초·상태1/센서3충족, 호스트영향 미조회로 종결거절/needs_review. 이번 인자초과0MCP실패는49,963B 압축으로 수정. [원인·검증·복구](../infra/hermes/shared-status-verification.md) |
| 추가PCAP·양Kali 설명 | 새7PCAP/정답PDF2·모든파일/설명SHA양쪽동일. 232만100,006패킷 처리7/7·초기29경보. 실제HTTP97정상/3공격대조 모두예상응답, Native600초차단·카드·만료/302복구 확인 | 233송신0·새실행객체추출0/학습0. 정상DNS TLD3신호·midstream별도48HTTP복원/운영설정0. LLM검증/시각공백은아래. [파일·실제결과·한계](../infra/validation/pcap-web/PUBLIC_PCAP_20261105.md) |
| 표가 텍스트로 표시 | 공통 정규화기가 양끝 구분자 없는 머리글을 놓친 원인 수정. 사건관리/SDK/Native3복사본 배포·원 게시물 형식만 제자리 수정. 실제 Mattermost 내부 웹 앱에서 표1개/코드블록0·스크린샷 확인 | 셀·작성자·채널 유지, 중복 조사/게시0. 공개 HTTPS UI 경유와 모든 카드/초장문 행 전수는 별도. [원인·실제 게시·복구](../infra/hermes/web-impact-navigation.md) |
| 웹 영향 추가 조사 | 공통당시1.5.32/query1.19.27/security-events1.2.2. 실제 WAF 경로→등록 대상/agent→사건 구간 백엔드/호스트 읽기 안내·단계별 제한 continuation. 수집 agent와 출발지 구분·정정 보고 반복 축소 | run21 161.187초/7성공+1거절·추가조회0/needs_review. run22 214.360초/6성공·오류0/보호0·실제 대상/백엔드 조회까지 진행했으나 호스트/최종보고 전 시간초과·outcome_unknown. 판단·종결·지연 향상 미완료. [검증](../infra/hermes/web-impact-navigation.md) |
| 과거 웹 접근 근거 | 정제 이력에서 구간/서비스를 먼저 검색하도록 C3/B2파일 확정·85검사. 실제 MCP가 최근10k에서 빠진10/22 DVWA1행을 SHA동일 복구. 전체 정제14,143행/잘림false·최근10k는 유지 | 기존11/4 사건 구간은0행·malformed9/연속성 미확인. 모델 host/사후 판단·장기/전체 무손실 아님. 채팅/Apache 재시작0. [실제 검증·복구](../infra/mcp/web-history.md) |
| 필수 센서 구간 | 정확 소수점 시각·인자 안내/MCP 전 검사·같은 실제 읽기만 오류 회복. 이전 run20 필수3/3·4읽기/오류0 | 당시 본문 사실 검사 거절/표 대체. 입력 회복을 정확한 사건 판단/종결로 대체하지 않음. [이전 검증](../infra/hermes/required-sensor-scope.md) |
| DNS 정보·상관 | 원본 Informational/Bad Traffic metadata·DNS/flow 근거·동일 질의 중복 해석 구분. Wazuh100112 후보 격리14조건 PASS | 정확 카드 만료·운영 룰 미적용. 도메인 전체 면제 없음. [후보/실제 상태](../infra/validation/dns-noise/README.md) |
| 단문·담당·공통 스킬 | 일반 조회 Ollama 우선/partial만으로 Hermes 호출0. 출력·조회·조사·변경·복구5개 SKILL 공통 연결. 새 SDK FW11.681초/1MCP·Hermes 직접 상태조회34.147초/4MCP 표본 | 공유 GPU·채팅 평균 지연/전체 역할 품질 보장 아님. Native discovery·승인·역할 강제 유지. [스킬](../infra/hermes/workflow-skills.md) · [지연](../infra/hermes/lookup-latency.md) |
| 공개 웹·실제 대응 | WAF On/UI·API 경유·제어 관리자231/32+인증. 단일 DVWA SQLi WAF403→Wazuh→LLM4MCP→600초FW/카드→만료/정상HTTP 확인 | 첫 차단 약146.4초/1표본. 실제 Log4 앱503·등록 HTTP3개 기존 중지·다른 공격/유지·해제 승인/재차단·사건 종결 미완료. [경로](../infra/validation/web-policy/README.md) · [단일 E2E](../infra/validation/web-e2e/README.md) |
| 룰 중복·관리 경로 | IDS7쌍 전체 룰 격리 전후14조건/유지9경보 동일. Wazuh17쌍 중8쌍 양성/음성 확인. A관리접속 관리자231/32·내부 MCP B 한주소 | 운영 룰 통합 미적용·Windows9쌍/참조/업데이트 지속성·FW/egress/B·C 컨테이너 경로 잔여. [룰 감사](../infra/validation/rule-overlap/README.md) |
| 논문·초기 설치 | 로컬 초안에11/5 조회 회복·실패·수집자 혼동/영향 근거 한계를 반영하고 이전본 보존. 초기 설치는 단일deploy.sh의 기존 source 복사 경로 연결/계약39 PASS | 최신PDF/전체 제출물·미사용176독립평가/전 업무/새3VM 설치 미완료. NCSC/NIS 부분 대조는 인증 아님. [구축](../deployment/INSTALLER_READINESS.md) · [운영](../deployment/OPERATIONS.md) |

## 유지하는 운영 조건

| 항목 | 현재 기준 |
|---|---|
| 모델/역할 | B Ollama 신속 조회·분류, Hermes 복합 조사·변경 우선. Thor 원본qwen3.6:35b, 학습본 후보 보존·승격0. DGX 새 학습 예약0 |
| 권한/승인 | LLM이 조사·판단·변경안·승인·사후 확인 주도. MCP/worker가 보호 주소·정확 후보·증거·허용 작업 검증. 일반sudo/Docker/셸·설치 위임0 |
| 차단 | 최초600초·카드 유지 승인60분·실제 해제/원기한 뒤60초 cooldown·새 근거. 기존 지정 IDS Native 예외 유지, 다른 고정 자동차단 확대0 |
| 관리/시험 | Mac→관리자231→A→B/C. Kali 직접, 새 공격232만. 이번 새 공격0·보호 변경0·모델 교체0·새 OS설치0 |
| 자료/Git | 수집/정제/검수 로컬·학습DGX·검증 가중치 적재/추론Thor. 원본1+정제본1 무손실 압축. 비밀/대화/로컬검증/업무분담/발표·논문/가중치/압축본 Git 제외 |

## 다음 작업과 완료 기준

| 순서 | 다음 작업 | 완료 근거 |
|---|---|---|
|1| 실제 사건/operation 필수 조회·시각/상관 해석·조사 지연 | 후속 IDS의 상태/센서 누락은4성공조회로 회복했으나 당시 보호자산 경보/인용 미충족. operation2읽기/오류0로 절차 확인·보고는 목록형. WAF원문시각은offset이없어 생산TZ/수집시각·버퍼링 대조.100112 원문/inbox 모두230으로 불일치 기록 정정·룰 변경0. 룰후보 승인만료는 임의재발급/적용0 |
|2| 실서비스·보안경로·승인 E2E | 앱 가동 의도 확인·다른 정상/공격·LLM 판단·유지/해제/재차단·장애/복구, IDS/Wazuh 중복의 참조/지속성/정확 승인·독립 복구 |
|3| FW NAT·운영 하네스·제어 공백 | 기존 NAT6은 관리자231/현재 로더SHA로 재기준·kernel/TTL/원복 검증, Ansible2 별도 미확정. C/미등록 unit 고정 진단·승인형 제어·SDK 보호쓰기/혼합 동등성 |
|4| 독립 평가·장기 운용 |176 미사용 평가·원본/학습/하네스 비교, 장기 알림/Vector/수집 장애 무손실·복구, 표 UI 전 경로/자동 skill_manage 제한 연결 |
|5| 논문·발표 | 실제 성공/실패/미확인 근거·최신PDF/제출형식·독립평가. 발표 작성은11월둘째주 이후·최종12/1 |

OpenClaw/Harness²·SSL VPN/모바일·GPU 드라이버 장기 원인과 새 OS3대 전체 설치는 별도 검토다. 모든 공격 차단·보안 구멍0·LLM 전 업무 완료를 선언하지 않는다.

## 이번 배포·복구·정리·Git

| 범위 | 현재 결과 |
|---|---|
| 운영 반영 | B첫9파일13:26:52/13:28:05확정, 인자초과 발견 후 controller/receipt2만13:32:27추가·13:32:42 고유9SHA/보호7SHA/포함인자-원문 결속·양WS/worker·4서비스 확정. 첫 Native/SDK/review 각1재시작·두 번째 채팅 재시작0 |
| 검증/복구 | 고유935PASS/skip0·실제 operation/IDS 읽기 전용 재검토 각2/4MCP·보호0. 원본/manifest/복구2곳·독립15분타이머 해제/noop, 수동원복 미시험. 모델/FW/TTL/승인/키/포트/패키지/일반권한 변경0 |
| 보존/정리/Git | 운영DB·채팅·승인·실패 trace·원문로그/가중치 보존. 서버 시험437source/8log SHA대조·로그 로컬복사 후 제거, Mac자체30파일7,366,481B·SSH master/임시경로 정리·해당프로세스0.13:43 운영9SHA/보호7SHA·양WSworker/4서비스 재확인. 이번19공개경로 eecbdcc31a34754ea9a1d2aeb4d19edfe5fbcedb 커밋·푸시/13:46:05 KST 실제 원격main 일치 확인. 게시 영수증은 후속 문서 커밋으로 남기며 최종HEAD/원격 일치·관련경로 clean은 로컬 세션에 기록. 기존 NAT/Ansible8·topology5stage 보존 |

논문 원고5.12.3에 이번 조회 회복·인자 실패·출력/영향 미완료를 반영하고 이전3본/해시 보존. 최신PDF·독립평가·전체 관제·새OS설치·최종발표는 미완료이며 발표 작성은11월둘째주 이후다. 전체목표 active·미완료를 유지한다.
