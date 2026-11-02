# 인프라 현황 — 2026-11-03 03:50 KST

현재 상태와 활성 과제를 요약한다. [WAF 연동 전 기록](archive/STATUS-20261102-before-waf-evidence.md) · [11/2 정책 전환 전 기록](archive/STATUS-20261102-before-native-containment.md) · [11/1 이전 현황](archive/STATUS-history-20261101.md) · [계획](PLAN.md). [이번 배포·시험 원장](infra/mcp/containment-policy-20261102.json). 시각은 KST이며 관측 범위와 미완료를 구분한다.

## 현재 운영 정책과 검증

| 항목 | 현재 확인 | 한계·다음 확인 |
|---|---|---|
| WAF | **15:28:35 SecRuleEngine On 반영**, 같은 컨테이너·bind inode 유지, nginx 검사/reload·일반 DVWA302/Log4Shell308 | 15:46:59 Kali 단일 공격403·is_interrupted=true·engine=Enabled·941100/949110 확인. 기존 Env DetectionOnly는 기동 당시 값이며 고정된 후순위 include가On을 지정. compose/초기 설치 기본값도On |
| IDS→FW | 지정100110/level9·severity1 Native AR가 실제 flow_id/SID를 대조하고 공통 임시차단 호출하도록 A 배포 | LLM 대기 없는 선차단은11/2 명시 승인 예외. 전체 IDS 경보·일반 Wazuh 경보를 대상에 포함하지 않음. Wazuh flow_id 소수점0 문자열과 고정 프로그램 상대 경로 호환을 수정·15:53 반영. **15:53:31 Native 실제 차단·카드 게시 성공**, 관리자 유지 승인15:53:50·결정1회소비·실제FW 80/443 DROP·유지 결과 게시 확인. 이후16:44 별도 unblock 카드 승인으로 조기 해제·16:45 커널 부재/원기록released 확인. 이번 요청의 자연 만료 시험과 구분 |
| 공통 임시차단 | 최근5분 양방향 ingress TCP 공격 흐름1개·severity1/2·공격 분류·보호 주소·소유권 검증 | 모델측 추가 선조회·3흐름 조건 제거. WAF 실제 공격 거부도 기존 MCP로 검증.18:53:20 LLM/MCP→FW 실차단·카드 확인, 아래 검증 범위 참조 |
| 유지·해제 | 최초10분, **기존 관리자 카드**의 유지 승인 시 결정 시각부터60분, 카드 해제 승인 또는 만료. 중복 호출/채팅/봇 합의로 연장하지 않음 | 차단 기한 종료 후 재차단 대기60초. 이전 기록도 같은 간격을 적용하되 과거 서명 계획은 덮어쓰지 않음 |
| 내부망·실습 | 내부 IP·승인 실습이라는 사실로 자동 면제하지 않음. Kali233은 보호 목록에 추가하지 않음 | 명시적 관리·서비스 보호 주소와 일반 sudo/Docker 위임 금지 유지 |
| 두 봇 | 공통 단문 차단 목록 조회와 실제 영수증 표시 보완. **16:29:43 B1.19.9/계약1.5.13 배포·연결 검증 완료** | 현재 처리 중 요청이 끝난 뒤 독립 배포·복구 타이머 사용. 실제 Mattermost 새 게시/UI 왕복은 별도 |
| DVWA 접속 장애 | **15:43:02 C의 주입된 무기한 ping만TERM 종료**, PHP 세션 잠금 해제·Apache master 유지 | Kali HTTP302/login200·IP차단0 확인. 사용자 기존 로그인 세션의 잠금0 확인. 브라우저 재접속은 이후 명시 KEEP 차단과 구분. HTTPS는 vhost 미등록/자체서명 기본서버로 별도 미지원 |

검사: MCP495PASS·Ollama163PASS·Hermes380 중378PASS/2환경skip·설치36+16+1PASS. B 격리431PASS·A 격리434PASS와 임시 검사본 제거를 확인했다. 정적/격리 검사는 실제 공격·새 서버 전체 설치를 대신하지 않는다. A root 복구본과 SHA/CAS·독립 복구 타이머를 보존했다. 추가 패키지·이미지·포트·키0. 설치는 기존 루트 `deploy.sh` 경로에 같은 소스를 반영한다.

[차단/카드 기준](infra/mcp/approved-operations.md) · [Native 경계](infra/mcp/native-containment-ar.md) · [공통 하네스](infra/hermes/chat-harness.md) · [보고 근거 검사](infra/hermes/event-report-grounding.md).

## 기존 review 차단 해제

기존 `unblock_ip`에는 카드 승인/일회 소비/해제가 이미 구현돼 있었으나 Hermes review lead의 관리 실행 경로에서 제외돼 있었다. 별도 비동기 해제 MCP 추가안은 사용자 지시로 철회했고 배포하지 않았다. **기존 도구만** lead에 노출하고 자동 관리·peer/verify는 계속 차단한다. Ollama의 기존 직접 태그 lead 권한은 유지한다.

- B12파일 root복구본/CAS·독립복구타이머·유휴확인 후16:29:43 반영, 두 봇 인증 heartbeat·공동채널·파일SHA 확인. 승인 브로커 소스/서비스는 변경하지 않았다.
- 관리179PASS·root해제 소유권4PASS·Response 승인7PASS·MCP495PASS·review37PASS·native380 중378PASS/2skip·Ollama163PASS·설치36PASS·독립 source bundle1PASS. 실제 `UNBLOCKED` 텍스트 처리와 이후 IP 부재 재조회가 없으면 완료 금지 경계를 추가했다.
- 기존600초 카드 대기를 실행기가 먼저 끊지 않도록 review lead 한도만 정렬했다. MCP/API/패키지/포트/모델 추가0.
- 기존 사용자의 review 해제 요청으로 실제 list_blocks→unblock_ip→기존 해제 카드 게시·승인/일회소비를 확인했다. 첫 실행은 root helper가 response: 이외의 contain: 소유권을 거절해 물리 해제 실패. A helper를16:40:51 기존 도구 승인 뒤 정확 parent ID/IP/기한/소유권을 대조해 해제하고 원기록을released로 갱신하도록 수정했다. 알 수 없는 다른 소유권은 유지하며 일반 보호검사는 그대로다. 잘못된 보호주소 단정 대신 고정 reason_code를 반환한다. **최종판은 실제 list_blocks→unblock_ip→카드 승인/일회 소비→UNBLOCKED→list_blocks 성공**, 관리 실행completed로16:45:07 종료했다. A 커널0건·원기록released·Kali SSH 재접속을16:45 확인했다. 새 MCP/API·사용자 질문 게시·Codex 승인 클릭0.

## 조회와 응답 지연

| 시험 | 결과 | 해석 |
|---|---|---|
| 새 단문 `지금 FW 차단 목록만 보여줘` | Ollama1.19.6 16.75초·모델1/실제list_blocks1회·현재0건. 이전1.19.5는55.54초·조회0회/partial | 도구 범위 보완. 같은 부하/시각의 속도 비교가 아님 |
| 공동 Hermes | 1.19.6은기존 FW 제한 충돌로조회0회. 1.19.7 수정 후133.74초·실제list_blocks1회·현재0건/범위완료 | 정확 도구 호출은 복구됐으나 Hermes 지연 개선으로 표시하지 않음 |
| 표시 범위 | 현재 동적 차단 목록만 실제resp.list_blocks, 전체 FW 룰은resp.get_firewall_rules. 페이지50/전체·생략·오류 표시 | 무근거0건 금지. 실제 실행기/모델/MCP 시험이며 채팅 게시/UI0·보호 호출0 |

## WAF 원본 → LLM/MCP → FW 검증

| 항목 | 결과 | 남은 조건 |
|---|---|---|
| 구현·A 배포 | 기존 `temporarily_contain_ip`에 현재 managed WAF 세대·producer v2·공격 룰·실제403/Enabled·writer/FD/SHA 검증 추가.18:30 기본 반영 후 TLS포트·ACL·조기 real_ip 보완 | 신규 MCP/API·패키지·이미지·공개 포트0. WAF 거래는 TCP 흐름이 아닌 `http_transactions`로 구분 |
| HTTPS 신원·경계 | 프록시 `.3`→WAF `.2:8080` 고정 경로만 허용, server post-read에서 실제IP 복원. CID·원본inode/세대·수집cursor 보존 | Docker gateway·임의 전달 헤더 신뢰 제거. 고정 WAF/프록시 주소는 IP차단 보호 |
| 실제 VM 공격 | Kali233의 TLS8443 XSS403, 이후 HTTPS443 프록시 XSS403·실제 출발지233·WAF 거래1건 확인 | 시험기 SNI 누락은 공격 전 거절, ACL504와 location real_ip 지연은 수정 후 재시험. 광범위 공격 전체 성공을 뜻하지 않음 |
| LLM/FW/카드 | **18:53:20 `hermes-mcp`가 기존 도구를 호출**, sensor=`a:modsecurity`, 거래1/흐름0. 커널 contain 소유 차단과 기존 카드·60분유지/해제 버튼 확인 | 사용자/Native가 대신 차단한 결과가 아님. 기본 만료19:03:20 뒤19:04 커널0·원기록expired·만료결과게시·Kali SSH/HTTP200 복구 확인. Codex 승인 클릭0 |
| 지침·보고 | 일반채팅3사본과 자동조사 management/SOUL 총4사본 SHA 일치. 옛3흐름/오도구 이름 및 자동조사 prompt 최신화 | 기존 세션 기록은 덮어쓰지 않음. 후속 보고의 센서 도구 인용 누락으로 needs_review, 읽기 전용 새 세션 재시험의 도구 혼동을 확인해19:11 정확한 상태 조회 도구/인자 힌트를 추가. 새 읽기 재검증은 정확한3읽기 성공 뒤 native210초 시간초과·outcome_unknown. 종결 미완료 |
| 검사·설치 | 로컬 MCP507·설치37·controller76PASS. A 실제 운영 소스 일치105·B 내장 runner 보존76PASS. 기존 deploy.sh source bundle에 모듈/등록기/최신 지침 포함 | 새 서버 전체 managed/프록시 설치 시험과 전체 관제 무손실·모델 품질은 미실행 |

[구조·제한·복구](infra/mcp/waf-containment.md) · [작은 원장](infra/mcp/waf-containment-20261102.json). 단순403·스캐너/프로토콜·출처 미확인 로그만으로 IP를 차단하지 않는다. root 복구본은 유지한다.

## DGX 학습 — 본학습·최종 평가 완료

| 항목 | 실제 확인 | 남은 조건 |
|---|---|---|
| 본학습 | **4,348/4,348단계·1epoch 완료**,11/2 21:09:48 progress·21:09:51 controller completed | 같은 Qwen3.6-35B-A3B·train8,695건. 모델 성능 향상 판정과 구분 |
| 최종 평가 | 고정 validation176건·`eval_loss=0.31751391291618347`,393.726초.03:50 현재 파일/기록 대조 | 테스트176건의 독립 SOC 품질 점수는 아직 측정하지 않음. 손실을 정확도 점수로 환산하지 않음 |
| 계보·가중치 | 원본/현재 source·data각54파일·동일 학습수학·원controlSHA 유지. 최종 adapter7파일·run_manifest SHA를03:50 직접 재검사해21:09 완료 영수증과 일치 | 가중치 다운로드/커밋/Git LFS0. 최종 adapter약65MB는DGX 승인 경로에 유지 |
| 종료 | 학습 MainPID0·Resultsuccess·inactive·자기컨테이너0. follow completed/finished_early_without_waiting_for_deadline | 원래21:45 상한을 기다리지 않고 종료. 진행률 정기 조회 대상은 종료 |
| 운영 | Thor와 두 봇은 기존 원본35B 유지 | 미사용 SOC 평가·중요누락/승인/허위성공/도구·지연 비교, 변환·Thor 후보 적재·복구 검증 뒤 교체 판단 |

Git 승인 대기 동안 Codex가 매시간 조회한 것으로 표시하지 않는다. 완료 시각은 서버 기록이며03:49~03:50 현재 읽기·해시로 재확인했다. [완료·파일별SHA 원장](finetuning/OPERATOR_COMPLETION_20261103.json) · [실행 원장](finetuning/OPERATOR_TRAINING_EXTENSION_20261102.json) · [자동 계승](finetuning/OPERATOR_FOLLOW_20261102.json).

## 시연·관제와 잔여 과제

| 과제 | 완료 근거·현재 상태 | 남은 작업 |
|---|---|---|
| 기존 Kali17스크립트 | 11/2 VM 내부 제한 실행·원본17SHA 유지. SQLi/명령삽입/외부리다이렉트 악용 재현, 인증401·CSRF 거절 등 분리 | Nuclei템플릿 경로/표본0/로그인 오판·BlindSQLi·전체스캔 미완료. Log4Shell RCE 미시험 |
| 과거 실차단 | 12:49 LLM/MCP→A233 DROP, 승인KEEP 기한 후13:50 만료·재접속/13:51 임시 실행기 정리 | 새 Native/On 정책의 실제 차단·카드·만료와 별도 결과 |
| 반복 복구 알림 | 13:47 A/B에 진단 ID 중복 집계 방지·독립2실패/2성공·오류 종류 보존 배포. 격리69씩·자연 주기 확인 | 장기 알림 빈도·Vector guard 지연/수집 중단 구간 전체 무손실 미검증 |
| 모델·하네스 | 기존224step 후보와 원본 비교는 표본 작고 치명 오류가 남아 운영 교체 보류 | 본학습·최종validation완료. 다음은 미사용 평가, 누락/승인/허위성공/지연, 원본/학습본 × 기존/정리 하네스 비교·Thor 후보 검증 |
| 데이터 보관 | 전체 통합 원본1개+정제본1개 규칙/제외/문서 반영 | 기존 약7.7GB 일괄 압축 이전·전멤버 SHA/복원 검증 미실행. 진행 학습 입력 보존 |
| 논문·발표 | 기존 출처·실험 근거 보존.11/3 교수 시연 준비,12/1 최종 목표 활성 | 논문 초안 구성도·독립 평가·실전 검증 근거/한계 현행화. **발표 작성은11월둘째주 리마인더 이후** |

[자료 보관/복원](datasets/STORAGE_POLICY.md) · [저장소 정리](archive/REPOSITORY_CLEANUP.md) · [토폴로지 상세형](topology/토폴로지_상세.svg) · [버스형](topology/토폴로지_버스.svg). 도식은11/1 구성/11/2 배치 정리 시점의 스냅샷이며 이번On/Native 정책 검증 결과와 구분한다. 다른 작업의 topology 생성물5개는 수정·추적하지 않는다.

Google Harness² 운영 연동/전후 비교, SSL VPN·모바일 푸시, GPU 드라이버 실패 근본원인/후보 장기 안정성, 새 서버 전체 설치는 기존 미완료·보류를 유지한다. 계정 잔여율1%시 중지 조건은 유지하나 현재 도구로 잔여율은 확인할 수 없다. 전체 목표는 완료되지 않았다.

Kali 시험 실행기는710초 제한으로 종료됐고,16:45 카드 승인 해제 후 SSH 재접속·임시worker.py/log/pid 제거·원본17SHA 불변을 확인했다. probe79행과 원본SHA만 보존한다. Mac에는 패키지를 설치/다운로드하지 않았다.

## Git 반영

WAF 원본·전용 프록시·자동조사 보완과11/2 19:09 학습 관측은 `9579cfbc`로 커밋·푸시했고11/3 03:49:03 원격main 일치를 확인했다. 본학습 완료·최종 파일SHA와후속보고시간초과 기록은 `28160334`로 후속 커밋·푸시했고11/3 03:53:42 원격main 일치를 확인했다. 이 게시 확인 문구도 마지막 문서 커밋에 반영한다. 다른 작업의 topology5파일은 기존 stage를 보존했다. 가중치·데이터·자격·대화/검증·업무분담·발표/논문 자료는 Git 제외다.

서버의 이번 임시 격리시험 소스와 Kali 임시 실행기는 정리했고 운영 복구본·probe·실제 trace/DB는 보존했다. Mac 신규 패키지/가중치 반입0이며 작업 임시 스크립트·로그는 마지막 게시 확인 뒤 제거하고, 최종 삭제·Git SHA·원격 일치·기존 topology stage 보존 결과는 로컬 세션 기록에 남긴다.
