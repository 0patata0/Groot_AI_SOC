# 인프라 현황 — 2026-11-06 23:00 KST

전체 목표는 **LLM 실전 관제 운용·논문 완성·2026-12-01 최종 발표**이며 active·미완료다. 우선 목표는 정확한 최종 답변60초 안팎, 추가 목표30초다. 단순 이력/현재 비교는 아래 실측에서 달성했고 일반 원인·위험 조사는 아직 미달이다. [활성 계획](PLAN.md) · [직전 상태](archive/STATUS-before-diagnostic-navigation-20261106.md).

## 이번 완료와 남은 범위

| 항목 | 확인 결과 | 범위·남은 문제 |
|---|---|---|
| 단순 이력/현재 비교 | 직전 실제 Hermes25.532초·Ollama16.746초, 각4조회·2표 | 각1회, 원인·위험 판단과 구분. 최신 common39 Ollama22.266초·4읽기·2표·쓰기0/근거 일치 확인 |
| 원인 조사 재시험 | Hermes98.498→142.936초, 두 번 모두 품질 실패 | 현재 서비스 대상은 회복, 과거 진단 누락·무관 검색2회·보고 정정 잔여. 일반60초 미달 |
| 교차검토 | 직전/후속 Ollama worker73.546/72.623초·모두partial | 해당 사례의 근거 대조 미완료, 합의·원인 해결로 세지 않음 |
| 반영 | common1.5.39·진단1.2.3: 현재/과거 설명과 실제25서비스 target 안내 정정 | 도구 실행/권한/검증/결과 불변. 안내 정정이며 속도 향상 입증 아님 |
| 검증·운영 | 관련716PASS·skip0, B17파일SHA/보호8·양봇WS/worker·3서비스active·Bfailed0 | 4파일 변경·SDK20sourceSHA·독립15분원복확정. 기존단일deploy.sh 연결, 새OS 전체 설치 미실행 |
| 정리·Git | 서버 자체시험456파일7,026,948B 제거·부재확인 | DB/원문/trace/채팅/복구 보존. Mac 자체 임시16파일 4,107,310B 제거/부재확인. 이번 공개13파일 게시 마감 중 |

[안내 정정·실측·복구](infra/hermes/diagnostic-navigation.md) · [수치 원장](infra/hermes/diagnostic-navigation.validation.json) · [직전 비교](infra/hermes/systemd-comparison.md) · [반복 systemd 수정](infra/hermes/controller-contention.md). query82·security-events1.3.2·게이트65,345B·모델/학습/FW/TTL/권한/승인정책은 유지한다. 실제 응답 지연은 게시 시각→최종 게시 수정 시각이며, 뒤따른 교차검토 시간은 별도다.

## 그 밖의 운영 현황

| 영역 | 마지막 확인 범위 | 남은 범위 |
|---|---|---|
| FW·웹 경로 | NAT/IPv4 확정, HTTP Wazuh→HTTPS308·웹50r/s/동시50·429 보호, 차단 사유/FW IP·조건 표 반영.21:22 A/B/C failed unit0·IPv6수신0·A4테이블17체인102규칙 | capstone_fw 추가통합은 사용자 취소. 전체 DDoS/egress/모든 관리 경로·장기 재부팅 검증 별도. [FW](infra/mcp/fw-consolidation.md) · [웹](infra/validation/web-traffic/README.md) |
| Mattermost 표·단문 | 재개 후 실제 카드1표/양봇 각4표·코드블록0. 새 FW질문 Hermes12.097초/Ollama13.958초 각1회·102규칙 일치 | 공개 HTTPS/모바일/모든 과거 글·활성 차단 표·평균 지연 전수 미검증. [표·사유](infra/mcp/containment-display.md) |
| DNS·저장·호스트 | 지정230→168.126.63.1:53 및 정보성SID2만 예외, 원문16→native100115/level0 확인. 도메인/악성DNS 광역 면제0 | WAF 원문offset/수집 시점·세대/장기 연속성·전체 복구 검증 잔여. [DNS](infra/validation/dns-noise/README.md) |
| 웹 근거·필수 읽기 | 실제 등록 대상/agent와 호스트·백엔드 읽기 연결. 과거 DVWA1행 MCP 복구/정제14,143행·구간/서비스 우선 검색, 정확 사건 시각/인자 검증 | 최근/보관 표본은 전체 무손실이나 침해 부재 증명이 아님. 일부 과거구간0행·파싱 제외9·연속성 미확인. [이력 조회](infra/mcp/web-history.md) |
| 공개 웹·대응 | WAF On/UI·API 경유·제어 관리자231/32+인증. 단일 DVWA SQLi WAF403→Wazuh→LLM MCP→600초FW/카드→만료/302복구 | 실제 Log4 앱503/등록 HTTP3개 중지·다른 공격/유지/해제/재차단·사건 종결 미완료. [단일 E2E](infra/validation/web-e2e/README.md) |
| PCAP·룰 중복 | 새7PCAP/정답PDF2 양Kali 동일SHA,232의100,006패킷·97정상/3공격HTTP와600초 차단/만료 확인. 추가압축5종은 보관/설명만 | 공격시험 중단 유지. IDS7쌍 격리14조건/Wazuh8쌍 확인은 운영룰 통합 완료가 아님. [PCAP](infra/validation/pcap-web/PUBLIC_PCAP_20261105.md) · [룰](infra/validation/rule-overlap/README.md) |
| 논문·발표·설치 | 논문5.12.5와 이전본 보존. 호스팅 없는 발표 PDF20쪽/메모685초·전쪽 시각검수. 단일deploy.sh 설치 경로 정합 검사 | 이번 후속 실측/최신논문PDF·제출형식·리허설·미사용176 독립평가·새3VM 전체 설치 잔여. [설치](deployment/INSTALLER_READINESS.md) · [운영](deployment/OPERATIONS.md) |

## 다음 작업과 유지 조건

| 순서 | 다음 작업 | 완료 기준 |
|---|---|---|
|1| 일반 복합 판단 정확성·60초 안팎 | 단순 오늘 systemd 이력/현재 비교는 Hermes25.532/Ollama16.746초에 완료했다. 원인·위험 판단은 등록 서비스의 현재/과거 필수 읽기·호스트 결속·무관 조회와 보고 정정 비용을 보완해 다른 사건·새 채팅에서 검증한다. 제한된 비교1회 성공을 전체 복합 조사나 평균/p95 성과로 대체하지 않는다. |
|2| 실서비스·승인 E2E·관리 경로 | 앱 가동 의도/필요 가동 확인, 보호 변경의 정확 후보·독립 복구, SDK 보호쓰기/혼합 동등성. 새 공격은 재지시 전 수행하지 않음 |
|3| 독립 평가·장기 운용·발표 |176 미사용평가·원본/학습/하네스 비교, 수집/알림/백업 복구·무손실 한계, 논문/발표 실측 갱신 |

- B Ollama 신속 조회/분류, Hermes 복합 조사/변경 우선. Thor 원본qwen3.6:35b·학습본 승격0, DGX 새 학습 예약0.
- LLM이 조사·판단·변경안·승인·사후 확인을 주도하며 MCP/worker가 보호 주소·정확 후보·증거·허용 작업을 검증한다. 일반sudo/Docker/셸·설치 위임0.
- 최초 임시차단600초·카드 유지 승인60분·해제/원기한 뒤60초 cooldown·새 근거 유지. 지정 IDS Native 예외 확대0.
- 관리 경로 Mac→관리자231→A→B/C, Kali 직접. 공격·부하·PCAP재생 중단은 별도 재지시 전 유지. 새 전체 일시정지나 종료 시각은 지정되지 않았다.
- 수집/정제/검수 로컬·학습DGX·검증 가중치 적재/추론Thor. 원본1+정제본1 무손실 압축. 비밀/대화/로컬검증/업무분담/발표·논문/가중치/압축본 Git 제외.

모든 공격 차단·보안 구멍0·전 관제 업무 완료나 기관 준수 인증을 선언하지 않는다. OpenClaw/Harness²·SSL VPN/모바일·GPU 드라이버 장기 원인은 별도 검토다.
