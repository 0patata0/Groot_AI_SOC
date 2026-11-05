# 인프라 현황 — 2026-11-05 11:42 KST

전체 목표는 **LLM 실전 관제 운용·논문 완성·2026-12-01 최종 발표**이며 active·미완료다. 핵심 기능11/9 마감 목표와 발표 작성은11월둘째주 리마인더 이후라는 조건을 유지한다. [계획](PLAN.md) · [이번 작업 전 상세](archive/STATUS-before-impact-navigation-20261105.md) · [전체 과거 이력](archive/STATUS-history-20261101.md).

## 현재 우선 과제와 실제 결과

| 과제 | 완료·실제 확인 | 남은 범위 |
|---|---|---|
| 표가 텍스트로 표시 | 공통 정규화기가 양끝 구분자 없는 머리글을 놓친 원인 수정. 사건관리/SDK/Native3복사본 배포·원 게시물 형식만 제자리 수정. 실제 Mattermost 내부 웹 앱에서 표1개/코드블록0·스크린샷 확인 | 셀·작성자·채널 유지, 중복 조사/게시0. 공개 HTTPS UI 경유와 모든 카드/초장문 행 전수는 별도. [원인·실제 게시·복구](infra/hermes/web-impact-navigation.md) |
| 웹 영향 추가 조사 | 공통1.5.32/query1.19.27/security-events1.2.2. 실제 WAF 경로→등록 대상/agent→사건 구간 백엔드/호스트 읽기 안내·단계별 제한 continuation. 수집 agent와 출발지 구분·정정 보고 반복 축소 | run21 161.187초/7성공+1거절·추가조회0/needs_review. run22 214.360초/6성공·오류0/보호0·실제 대상/백엔드 조회까지 진행했으나 호스트/최종보고 전 시간초과·outcome_unknown. 판단·종결·지연 향상 미완료. [검증](infra/hermes/web-impact-navigation.md) |
| 과거 웹 접근 근거 | 실제 C DVWA 등록002/groot-web·당시 호스트7표본을 도구로 대조. 백엔드0행이어도 rows_truncated=true·malformed9 확인 | 최대10,000행 snapshot에서 과거 구간이 잘릴 수 있음. 사건 시간 기준 제한 조회 보완 필요. 운영자 직접 조회를 LLM 조사 성공으로 표시하지 않음 |
| 필수 센서 구간 | 정확 소수점 시각·인자 안내/MCP 전 검사·같은 실제 읽기만 오류 회복. 이전 run20 필수3/3·4읽기/오류0 | 당시 본문 사실 검사 거절/표 대체. 입력 회복을 정확한 사건 판단/종결로 대체하지 않음. [이전 검증](infra/hermes/required-sensor-scope.md) |
| DNS 정보·상관 | 원본 Informational/Bad Traffic metadata·DNS/flow 근거·동일 질의 중복 해석 구분. Wazuh100112 후보 격리14조건 PASS | 정확 카드 만료·운영 룰 미적용. 도메인 전체 면제 없음. [후보/실제 상태](infra/validation/dns-noise/README.md) |
| 단문·담당·공통 스킬 | 일반 조회 Ollama 우선/partial만으로 Hermes 호출0. 출력·조회·조사·변경·복구5개 SKILL 공통 연결. 새 SDK FW11.681초/1MCP·Hermes 직접 상태조회34.147초/4MCP 표본 | 공유 GPU·채팅 평균 지연/전체 역할 품질 보장 아님. Native discovery·승인·역할 강제 유지. [스킬](infra/hermes/workflow-skills.md) · [지연](infra/hermes/lookup-latency.md) |
| 공개 웹·실제 대응 | WAF On/UI·API 경유·제어 관리자231/32+인증. 단일 DVWA SQLi WAF403→Wazuh→LLM4MCP→600초FW/카드→만료/정상HTTP 확인 | 첫 차단 약146.4초/1표본. 실제 Log4 앱503·등록 HTTP3개 기존 중지·다른 공격/유지·해제 승인/재차단·사건 종결 미완료. [경로](infra/validation/web-policy/README.md) · [단일 E2E](infra/validation/web-e2e/README.md) |
| 룰 중복·관리 경로 | IDS7쌍 전체 룰 격리 전후14조건/유지9경보 동일. Wazuh17쌍 중8쌍 양성/음성 확인. A관리접속 관리자231/32·내부 MCP B 한주소 | 운영 룰 통합 미적용·Windows9쌍/참조/업데이트 지속성·FW/egress/B·C 컨테이너 경로 잔여. [룰 감사](infra/validation/rule-overlap/README.md) |
| 논문·초기 설치 | 로컬 초안에11/5 조회 회복·실패·수집자 혼동/영향 근거 한계를 반영하고 이전본 보존. 초기 설치는 단일deploy.sh의 기존 source 복사 경로 연결/계약39 PASS | 최신PDF/전체 제출물·미사용176독립평가/전 업무/새3VM 설치 미완료. NCSC/NIS 부분 대조는 인증 아님. [구축](deployment/INSTALLER_READINESS.md) · [운영](deployment/OPERATIONS.md) |

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
|1| 과거 백엔드 구간·실제 호스트 영향/조사 시간 | 사건 구간의 보존 범위·잘림을 명확히 하는 제한 조회, 실제 모델 호스트/사후 조사와 근거 있는 판단·보고. 원문 검사·기존 시간 한도 완화로 완료 처리하지 않음 |
|2| 실서비스·보안경로·승인 E2E | 앱 가동 의도 확인·다른 정상/공격·LLM 판단·유지/해제/재차단·장애/복구, IDS/Wazuh 중복의 참조/지속성/정확 승인·독립 복구 |
|3| FW NAT·운영 하네스·제어 공백 | 기존 NAT6은 관리자231/현재 로더SHA로 재기준·kernel/TTL/원복 검증, Ansible2 별도 미확정. C/미등록 unit 고정 진단·승인형 제어·SDK 보호쓰기/혼합 동등성 |
|4| 독립 평가·장기 운용 |176 미사용 평가·원본/학습/하네스 비교, 장기 알림/Vector/수집 장애 무손실·복구, 표 UI 전 경로/자동 skill_manage 제한 연결 |
|5| 논문·발표 | 실제 성공/실패/미확인 근거·최신PDF/제출형식·독립평가. 발표 작성은11월둘째주 이후·최종12/1 |

OpenClaw/Harness²·SSL VPN/모바일·GPU 드라이버 장기 원인과 새 OS3대 전체 설치는 별도 검토다. 모든 공격 차단·보안 구멍0·LLM 전 업무 완료를 선언하지 않는다.

## 이번 배포·복구·정리·Git

B1차18파일11:02:00·2차14파일11:23:52 확정, 현재 고유21파일 SHA·포함gate/reference·보호7SHA·양봇WS/worker·4서비스11:35:27 재확인. 두 번의 배포에서 Native/SDK/review 각2회 재시작, 설정SOUL·모델·FW/TTL·승인·키/포트·패키지·일반 권한 변경0. 고유 회귀1,059PASS/skip0: 서버관리282/SDK219/Native391/설치39/review60/workflow4/output7/events27/table12와 설치 Native에서 chunks18. 호스트의 installed-runtime1skip은 실제 컨테이너 검사로 해소했으며 중복 합산하지 않았다. 중간 설치 fixture1실패는 새 callback 인자 대조를 갱신해39재통과했다.

두 독립15분 복구 타이머 확정 해제/no-op, 원본/manifest/rollback2곳 보존·수동 원복 미시험. 시험 source/중간로그459파일6,503,664B를 SHA 대조·작은22파일 로컬 보존 후 제거. 실제 브라우저/프로필·Native 시험 임시 제거 확인, 운영DB/승인/채팅/실제trace/가중치 보존. Mac 자체37파일7,346,533B/임시 경로를 제거하고 해당 SSH 소켓 원래 부재·잔여 프로세스0을 확인했다. 기존 사용자 도구·publisher는 보존했다. 관련 공개22파일을42d1254fd9cc227baff9cb528606bca28c3e62a8로 커밋·푸시하고11:41:57 KST 실제 원격main 일치를 확인했다. 기존 NAT/Ansible8파일·topology5stage는 보존하며 이번 변경 외 파일은 커밋하지 않았다. 직전 게시68432aa와 이번 소스 게시를 구분하며, STATUS/작은 원장의 게시 영수증 보완2파일은 후속 문서 커밋·푸시로 반영한다. 그 최종HEAD/원격 일치·이번22경로와 기존 작업트리 상태는 로컬 세션 기록에 남긴다.
