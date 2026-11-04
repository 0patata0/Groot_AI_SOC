# 인프라 현황 — 2026-11-04 19:18 KST

전체 목표는 **LLM 실전 관제 운용·논문 완성·2026-12-01 최종 발표**이며 active·미완료다. 핵심 기능11/9 마감 목표와 발표 작성은11월둘째주 리마인더 이후라는 조건을 유지한다. [계획](PLAN.md) · [직전 상태](archive/STATUS-before-read-accuracy-ncsc-20261104.md) · [조회 지연 전](archive/STATUS-20261104-before-lookup-latency.md) · [하네스 정리 전](archive/STATUS-20261104-before-harness-cleanup.md) · [웹 E2E 전](archive/STATUS-20261104-before-web-e2e.md) · [표 보완 전](archive/STATUS-20261104-before-table-chunks.md) · [FW 대화 보완 전](archive/STATUS-20261104-before-fw-chat.md) · [FW 선택 전](archive/STATUS-20261104-before-fw-scope.md) · [룰 감사 전](archive/STATUS-20261104-before-rule-audit.md) · [웹 정책 적용 전](archive/STATUS-20261104-before-web-policy.md) · [과거 이력](archive/STATUS-history-20261101.md).

## 현재 우선 과제와 실제 결과

| 과제 | 구현·실제 확인 | 남은 범위 |
|---|---|---|
| 채팅 담당 분배 | 공통1.5.21/query1.19.16/review1.1.4 적용. 단순 조회·사건/공격 목록은 Ollama, partial만으로 Hermes 호출0. 직접 태그/사건·변경·명시 검증 구분. 실제 새 조회2건 Ollama 단독16.676/13.019초 | 새 조회 전용 프롬프트/저추론으로 직접 Hermes 같은 조회4MCP·4행/34.147초·보정0. 별도Vector 진단1회/48.611초. 각1표본이며 부하/캐시 분리·전체 평균 지연은 미검증. Native discovery 유지. [검증·복구](infra/hermes/lookup-latency.md) |
| 공통 출력·카드 | soc-output 단일 SKILL, 짧은 표 정규화·상태/조치/근거 분리. 실제 새 Hermes/Ollama4행씩 표 파서 정상. 서버1,048PASS/skip0·보호config5SHA/기존 broker PID 유지 | 브라우저 UI·새 정기 카드 게시·native UX/skill_manage의 실제 제한 연결은 잔여. 기존 broker 재시작0 |
| 조회 정확성 | 한국어 상태 필터·WAF 설정/시작값/정책 분리·단문 실제MCP·SDK 대상 바인딩 보완,903PASS/skip0. 실제 새 WAF Hermes26.314초·Ollama9.874초/각1MCP·보호쓰기0 | 중간 오답/미조회 후보는 실패로 보존. worker 메모리/개별 공격·평균 지연 보장 아님. [배포·복구·원출처](infra/hermes/read-accuracy.md) |
| 구축·운영 지침 | NCSC 기본지침2026.5.1·NIS AI가이드v2.0/공급망 번역 공식원문3개 SHA·조항/페이지 대조, 운영절차 신설·과거 WAF 우회/면제 안내 정정 | 부분 대조이며 기관 준수 인증 아님. 로그1년/백업복원·NTP/전체 관리 경로·인력 요건·새 설치 미검증. [대조표](deployment/SECURITY_GUIDELINES.md) · [운영](deployment/OPERATIONS.md) |
| 사건 근거·중복 | 반복 시각 JSON은 동일 요청/상태/기한만 요약, 변경/불명확 원문 유지. 인용한 누락 센서의 모델 재조회 범위 보완. Wazuh ID/상관 정의 구분 | 소스/격리검사·운영 배포 범위이며 새 공격 사건 종결 성공은 아직 미검증 |
| 공개 웹 보안 경로 |11/4 C11:36:56·A11:37:21 적용,11:39 각각 확정. Log4Shell UI/API와 등록 HTTP3개 모두 WAF,10031 DetectionOnly 예외 제거. 제어는 관리자231/32+새 HMAC 세션. A reload·C API만 재시작 | 실제 브라우저 인증→제어는 미검증. 관리형 HTTP3개는 기존 중지·등록 Log4 앱503, 별도 legacy 컨테이너와 구분. 단일 DVWA SQLi 경로는 아래 실검증 범위. [변경·검증·원복](infra/validation/web-policy/README.md) |
| 실제 공개 경로 검증 | Kali23214조건: UI/상태/세션200·DVWA302·채팅200, 익명 제어/위조 관리자 헤더403, 비공개/미등록404, UI/API 무해 canary403, C 직접 웹 시간 초과. 관리자231 challenge200·Wazuh302 | 시간 초과를 특정 DROP 카운터 증명으로 표시하지 않음. 정상 열람과 취약 서비스 가동·침해 여부를 구분 |
| WAF 대응 증거 | 이전 관리 ACL 전 proxy SHA가 남은 신뢰 기록 발견.11:41 검토한 proxy/vhost 두 SHA만 갱신, CID/binding/포트·요건 유지.11:42 실제 WAF/proxy writer3개씩 두 번 확인 | 이번 DVWA 단일 SQLi의 실제 원문→LLM MCP 차단/카드·만료는 확인. 전체 공격/승인 실행·종결은 미완료. 원복 시 정확 설정 재등록 필요 |
| 장비 룰 중복 | WAF654·조건/동작 중복 후보0. IDS52,497 정의의7쌍은 전체 룰·동일 이미지 격리 전후14/14조건 PASS, 대상 경보14→7·유지 경보9개 관측 동일. Wazuh API/native XML4,571·172파일,17쌍 조건/동작 동일 | 운영 삭제/통합 미적용. Wazuh native8쌍 양성+음성1 통과, Windows9쌍+음성1은 경로 미검증(partial). 외부 참조·vendor 업데이트 지속성·승인/원복·FW/egress 잔여. [근거](infra/validation/rule-overlap/README.md) |
| FW 표 분할·페이지 후속 |1.5.19/query1.19.14/context1.0.1,14:26:57 확정. 새 채팅10건: 양쪽16+3행/19개 조건·handle 실제MCP와 동일, 빈3페이지·이전페이지·새root확인질문. Native 분할 표 밖 행0·서버669PASS | 앞선 페이지 요청의 양쪽 생성 오답 발견·실제 근거 재구성으로 보완. UI 화면·단일 초장문 행의 표 유지·기타 필터/사건 업무는 별도 잔여. [검증·한계·복구](infra/hermes/chat-table-chunks.md) |
| 실제 DVWA 대응 |14:48:01.609 WAF Enabled942100/949110·403→Wazuh100102, LLM4MCP 성공→600초 차단·실제 카드/보고. 차단 중 같은 Kali232 TCP SYN DROP,15:00:28 기한 뒤 커널0·정상HTTP200·expired 결과 카드 | 첫 차단까지 약146.4초(1표본).4회 조사 뒤 needs_review/근거 부족. KEEP/RELEASE 승인·재차단/다른 공격·실제 Log4 앱 미시험. [근거·한계](infra/validation/web-e2e/README.md) |
| 자동 보고 표시 보완 | B15:11:14 한 파일 적용·15:12:14 확정. escape된 내부 제어 줄 숨김, strict 판정/승인 불변. 관리209·설치계약37 PASS, 보호6SHA·모델/서비스 재시작0 | 설치된 함수의 격리 송신2경우 검증. 수정 뒤 새 실제 Mattermost 보고 전달·수동 원복은 미시험 |
| Vector 사전 복구 |14:41 cursor guard 거절/재시작을 관측해 공격 보류.14:42 자동 복구·14:46:19 회전 완료·14:47:48 raw 양 active/pending0 후 시험 | 강제 재시작/CP 변경/guard 완화0. 전체 과거 무손실·장기 무장애로 확대하지 않음 |
| LLM 전 관제 업무 | 기존 필수 SOC 역할·두 봇 전문화 유지. 실제 SDK8서버/41도구 discovery·hermes-parity 성공, Native7서버 목록과 coverage 읽기 성공 | C 승인형 제어·미등록 unit 상세 journal·사건 종결 근거 부족·미등록 Socorro 언급/실습 추정·최초 차단 지연. 고정DetectionOnly 요약·한국어 연결 끊김 필터·SDK의 IDS 대상 고정은 보완/실조회 확인. 실제 worker 메모리 적재와 전 업무 종결은 별도 미검증. 도구 연결 성공을 전 업무 완료로 표시하지 않음. [업무별 범위](infra/validation/web-policy/SOC_CAPABILITIES.md) |
| 초기 설치·패키지 점검 | 단일deploy.sh·오프라인 SHA 기반. review2작업의 원격 허용목록 누락과 host-check/verify fixture3 정정. fakeSSH46/역할·작업명12조건 통과 | WAF 증거 자동등록 연결·전체 의존성 묶음·제품 프로필 미완성. 새3VM 실제 설치0. 구 lab_waf_mode 영수증 표시 잔여. [점검](deployment/INSTALLER_READINESS.md) |
| 관리 접속 | A SSH·Wazuh443/10443 관리자231/32, A 내부 SSH MCP B10.200.10.10/32.11/3 실제 경로 검증·11/4 세서버 재확인, 이번 공개웹 변경 뒤 관리자 접속/Wazuh도 유지 | B/C 컨테이너→호스트 관리·관리자 접속 경보 소음 예외·새 OS 전체 설치는 잔여. [정책](infra/groot-a/management-access.md) |

네이티브 동일 이미지·외부망 없는 WAF47요청(이전20+후보27), SQLi/XSS/JNDI의 실제 CRS·Enabled403·거부 메타데이터 보존, 가짜 인증자료의 bulk 감사 비복사를 검증했다. 이는 실제 앱 공격이 아니다. C 기존 vendor의 ASGI54, 로컬 배포6·portable TLS16·SOC 설치37·서비스50·bootstrap14·source bundle1·JS UI를 통과했다. bootstrap의 오래된 아이콘 fixture 누락을 수정했다. 운영 전체 설치/수동 원복/전 공격 유형 무누락은 검증하지 않았다.

## 유지하는 운영 상태

| 항목 | 현재 기준·완료 범위 |
|---|---|
| LLM 역할 | 조사·상관분석·위험 판단·변경안·정확 승인 요청·MCP 실행 후 확인·보고를 주도. 관리자만 보호 변경 승인. 일반 sudo/Docker/임의 셸·패키지 위임 없음 |
| 모델/배치 | B Ollama 신속 조회·분류, Hermes 복합 조사·변경 우선. Thor 원본 qwen3.6:35b, 공통 계약1.5.21/query1.19.16/context1.0.1. 가중치·모델/권한 변경0, 공통 표시 하네스는 위 범위로 보완 |
| 학습/품질 |11/2 4,348단계·학습8,695/평가176 완료, DGX→Thor 후보 적재·승격 없음. 고정1.5.14 원본18/24·동일HF20/24·학습19/24로 교체 근거 부족. 독립176 비교 잔여 |
| 차단 | 최초600초·관리자 유지 승인부터60분·정확 해제 승인 또는 만료, 실제 해제/원기한 뒤60초 cooldown·새 근거 필요·중복 연장 없음. 지정 IDS Native 예외와 LLM 조사 역할 유지 |
| 최근 MCP/사건 보완 | 공유 Native 참조·사건 구간/센서·KST 만료·영수증 해석 운영 반영. 실제 새 사건 MCP 오류0 표본·카드 대기 성공은 과거 검증으로 보존하며 사건 판단 전체 정확성을 뜻하지 않음 |
| 공격/PCAP | 공개11PCAP 두Kali 반입·SHA,232 오프라인11/156,160패킷·613경보. 실제97정상+검토 공격대조3/WAF403은 기존 결과. 경보 수를 정탐 수로 보지 않으며 원본58PCAP 출처 미확정·일부 공개 capture 정답 미확정 |

## 다음 작업과 완료 근거

| 순서 | 다음 작업 | 완료 근거 |
|---|---|---|
|1| 웹 실제 가동/공격·증거·대응, IDS7 통합의 지속성/별칭/승인·복구, Wazuh9쌍의 격리 EventChannel 검증, FW 우회·egress·B/C 컨테이너 관리 경로 | 단일 WAF→LLM→600초/카드/만료는 확인. 실제 앱·다른 공격·유지/해제 승인·재차단 대조와 사건 종결이 남음. 검증한 중복만 승인형 통합, 근거 없는 삭제 없음 |
|2| LLM 전 업무 공백 보완 | 최우선 실제 사건의 근거 인용/종결·중복 시각 JSON/미등록 자산명/분류·상관 혼동·임시 차단 지연 보완. C/고정 host 제어의 승인형 MCP·권한/검증/복구, 실제 브라우저 UI·단일 초장문 규칙 표시·단문/추가 요청·상관분석/종결·교차 검토 새 채팅 회귀 |
|3| FW NAT 통합·운영 하네스 후보 정리 | 기존 NAT6을 관리자231/현재 로더SHA로 재기준·kernel/TTL/복구 검증. 기존 peer4는 이번 인수·배포했고 Ansible2는 별도 미확정 |
|4| 독립 평가·보호쓰기/원복·장애/복구·재현 |176 미사용 평가, 원본/학습·하네스 조합 비교, 장기 알림/Vector·수집 장애 무손실, 데이터 원본1+정제본1 통합/SHA |
|5| 논문·최종 발표 | 논문은 실제 관측·공식 출처·미검증 한계·현행 배치 반영. 발표 작성은11월둘째주 이후·최종12/1 |

OpenClaw/Harness², SSL VPN/모바일, GPU 드라이버 장기 원인·새 OS3대 전체 설치는 별도 검토다. 모든 공격 차단·보안 구멍0·LLM 전 업무 완성을 선언하지 않는다.

## 복구·Git·로컬 정리

이번 단위는 B Native/SDK/관리 gate와 SDK 실행기16대상이다.18:44 최초 적용·중간 오답/미조회 확인 뒤 보완·19:11:31 source/보호8SHA·broker원PID·양WS/worker 확인 후 확정, 원복 timer 정지·confirmed recovery no-op. 원본/후보·중간SHA/복구는 `/var/lib/capstone-read-accuracy/20261104-r1/deployment`에 보존한다.903PASS/skip0, 실제 신규 설치·수동 원복·새 공격 E2E는 미실시다. 자세한 실패/최종 성공 표본은 read-accuracy 문서에 구분한다.

공식 지침 자료3개는 기존 Swift/PDFKit으로 확인하고 원문SHA·판본·페이지를 작은 대조표에 기록했다. Mac 새 패키지 설치0. 자체 공식PDF3개/Swift캐시/격리소스/스크립트 679파일·261162992B와 SSH mux를 정리하고 임시 부모 부재를 확인했다. 서버validation/mirror 각422파일·6,429,692B도 로그5개 SHA 내보내기 뒤 제거·실제 복구본/DB/채팅/승인 보존. 공개HEAD 설치기를 사용한 추가 격리 fakeSSH46PASS로 별도 NAT후보를 배제했다. 이번 공개33파일은 `367d8f84b3199cb8736af78beb5424ce10281711`로 커밋·푸시하고 2026-11-04T19:18:45.804263+09:00 실제 원격main 일치를 확인했다. 게시 확인 STATUS/작은 검증원장2파일은 후속 문서 커밋으로 보존한다. 직전416835f와 이번 소스 게시를 구분한다. 타 Ansible2/NAT6/topology5 stage는 미포함·보존한다. 자격·대화/검증 원문·업무분담·발표/논문·데이터/가중치는 Git 제외다. 전체 목표active·미완료다.
