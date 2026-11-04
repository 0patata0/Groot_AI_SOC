# 실제 DVWA 요청·LLM 대응·차단 만료 검증

2026-11-04 KST. 사용자에게 승인받은 실습 환경의 Kali232에서 프로젝트 작성 SQLi 필터링 요청 **1건**을 보냈다. 공개 악성 PCAP 재생·실제 침해·학습자료가 아니다. [현재 상태](../../../STATUS.md) · [작은 검증 원장](validation-20261104.json) · [웹 정책](../web-policy/README.md).

## 실제 확인

| 단계 | 직접 확인한 결과 |
|---|---|
| 사전 정상 조회 | Kali232의 DVWA 로그인200, Log4Shell 콘솔 HTTPS200/TLS 검증·공개 상태200. 등록된 Log4Shell 실습 앱은503이며 관리형 HTTP3개 모두 기존 중지 상태 |
| 실제 요청 차단 | A14:48:01.609, Kali232:59294→DVWA 로그인, ModSecurity Enabled·942100/949110·403·거래 ID/원문 SHA 연결 |
| 경보 수집 | B14:48:02.598 Wazuh100102. WAF 원문 audit 입력이며 정규화 파이프라인 전체 직렬 통과로 표시하지 않음 |
| 별도 IDS 관측 | 같은 응답의 역방향 A→232:59294 `GPL WEB_SERVER 403 Forbidden`/Wazuh100111. 이것을 인바운드 공격 flow나 Native IDS 선차단 성공으로 세지 않음 |
| LLM 조사·대응 | 첫 자동 조사에서 WAF 원문·Wazuh 요약→`temporarily_contain_ip`→`list_blocks`, MCP4회 모두 성공. Codex의 수동 차단이 아님 |
| 임시 IP 차단·카드 | A14:50:28 기준600초, 고정 기한15:00:28. Mattermost14:50:29.119 유지/해제 승인 카드·14:51:02.282 첫 보고 게시. 이번에는 카드를 승인·연장·해제하지 않음 |
| 실제 차단 효과 | 차단 중 같은 Kali232:43019→A80 TCP 연결3초 시간 초과, 같은 포트의 A `AGENT_BLOCK` SYN3개 대조. HTTP는 전송되지 않았으므로 정상 HTTP 거부 건수로 세지 않음 |
| 무응답 만료·복구 | A15:00:59 커널 차단 원소0, 같은 Kali에서 정상 DVWA HTTP200.15:18 기록은 expired·consumed, 실제 Mattermost 작업 결과 카드도 expired·버튼0 |
| 사건 종결 | 4회 조사 후 `needs_review / incident_disposition_evidence_missing`. 차단·만료 성공을 조사 종결 성공으로 표시하지 않음 |

첫 요청부터 FW 요청까지 약146.4초, 승인 카드147.5초, 첫 보고180.7초였다. 이는 단일 표본이며 모델/에이전트 전체 성능이나 전후 개선율이 아니다. Kali232는 Mac 대비 약7.6~8.1초 느렸고, A/B는 관측 범위에서 약1초 이내였다. 원시 시각을 보존하고 위 지연/기한은 A/B 시각으로 계산했다. 시계 스큐를 UTC/KST 변환 오류로 분류하지 않는다.

## 발견한 문제와 이번 수정

실제 첫 보고에서 Markdown으로 escape된 `INCIDENT\_DISPOSITION:` 제어 줄이 노출됐다. 기존의 일반 `MANAGEMENT_STATUS:` 줄은 이미 숨겨지고 있었다. `soc_management_controller.deliver()`의 전송 단계에서 일반/단일 escape 제어 줄을 숨기도록 보완했다. 일반 문장 속 단어·사건 본문·요청 ID는 유지한다. **사건 종결의 strict 구문·근거 검증·승인 권한은 완화하지 않는다.**

| 확인 | 범위 |
|---|---|
| 회귀 | 로컬 및 B 관리209 PASS, B 설치 계약37 PASS·skip0. 반복 실행은 합산하지 않음 |
| 설치된 함수 | 실제 운영 함수 AST의 격리 HTTP sender에서 일반/escape2경우 검증. 새 실제 Mattermost 보고로 수정 후 전달을 확인한 것은 아님 |
| 증분 배포 | B 한 파일,15:11:14 적용·15:12:14 확정. 함수 외 AST 동일, 보호 설정6개 SHA 동일, 모델/서비스 재시작0 |
| 초기 설치 연결 | 기존 `deployment/soc_management.py` bundle/render/write가 canonical 소스를 사용. 초기 설치기 수정/실행0, 실제 새 서버 전체 설치 미검증 |

첫 설치 계약 격리 시험은 prompt fixture 누락으로 실패했고, 누락4개를 보완하는 중 이미 존재하는 파일 assert도 한 번 실패했다. 원래 실패 로그를 보존한 뒤 동일 바이트를 확인하고 최종37개를 통과했다. 실제 설치 함수 송신 mock의 bytes/str 타입 오류도 mock을 수정해 재검증했다. 이를 제품 장애 또는 설치 성공으로 바꾸지 않는다.

다음은 실제 보고의 근거 인용/종결 판정과 중복 JSON fallback, 미등록 `Socorro` 언급·실습 가능성 추정·Wazuh 분류100102의 상관 룰 오명명, 최초 차단 지연을 보완해야 한다. 승인 KEEP/RELEASE 실행·새 공격 재차단/60초 cooldown·다른 공격 유형·Log4Shell 실제 앱은 이번 시험 범위 밖이다.

## 수집기 관측과 복구

사전 점검에서 실제 `capstone-vector` 재시작과 WAF publish_pending을 관측해 공격을 보류했다.14:41:19/53 guard의 `new_generation_cursor_unsafe` 거절 뒤14:42:28 자동 복구했고, 양 reader guard/출력 증가를 확인했다.14:46:19 예약 회전 완료·14:47:48 양 raw active/pending0을 확인한 뒤에만 요청을 보냈다. 강제 재시작·guard 완화·CP 초기화·원문 삭제0이다. 이 표본의 복구/수집을 전체 과거 무손실 또는 장기 무장애 증명으로 확대하지 않는다.

등록된 HTTP 앱의 중지/503과 별도 legacy Log4Shell 컨테이너의 실행 상태는 별개다. 콘솔200을 실제 취약 서비스 정상 가동이나 공격 성공으로 표시하지 않는다. 서비스 시작/컨테이너 재구성은 수행하지 않았다.

## 복구·증거·정리

운영 B의 `/var/lib/capstone-report-controls/20261104-r1/deployment`에 원본·후보·SHA·소유권/모드·검증을 보존한다. 독립15분 원복 타이머를 만들고 적용했으며 검증 확정 후 해제·확정 복구 no-op을 확인했다. 실제 수동 원복은 미실시다. 관리자231→A→B 경로에서 다음 고정 복구기를 사용할 수 있다.

```bash
python3 -B /var/lib/capstone-report-controls/20261104-r1/deployment/rollback.py --manual
```

복구는 자기 소스 변경만 되돌리며 동시 변경·DB/승인/대화·차단 기한을 덮어쓰지 않는다. 기존 초기 설치 영수증은 없었고 가짜 영수증을 만들지 않았다. 시험 fixture/로그는 SHA 대조·로컬 전용 보존 후 정리하고 운영 복구본/작은 최종 검사 영수증은 유지한다. Mac에 새 도구·패키지를 설치하지 않았다. 실제 채팅·원문·진단 코드/오류는 로컬 기록에 보존하며 Git/학습에 넣지 않는다. Git에는 이 문서·작은 원장과 코드/설정/현황만 남긴다.
