# LLM 보안관제 업무와 현재 실행 범위

2026-11-04 실제 MCP 조회 기준. 요구사항은 **B의 두 LLM 에이전트가 MCP를 통해 관제요원 업무를 주도하며 Mattermost 관리자의 기본 보고·추가 조사·조치 요청을 처리하는 것**이다. 이 문서는 기능 목록과 미완료 공백이며 전 업무 완료 선언이 아니다.

두 봇 공통 역할은 [SOUL](../../hermes/SOUL.groot.md)의 `SOC_ROLE_CONTRACT_V1`과 실행기의 고정 계약으로 전달된다. Ollama는 신속 조회·분류·타임라인, Hermes는 복합 상관분석·대응안·승인/사후 확인을 우선한다. 전문 역할은 다른 업무나 교차 검토를 거부할 이유가 아니다. 현재 추론은 Thor 원본35B이며 Mac/Codex 연결이 상시 관제의 전제는 아니다.

| 관제 업무 | 실제 도구·실행 경로 | 현재 확인 / 남은 완료 조건 |
|---|---|---|
| 상시 수집·장애 발견 | 고정 수집기/독립 감시, `get_system_diagnostics` | A/B/C41관측 대상+coverage enum42. 현재 진단과 과거 journal 표본 구분 필요; 장기 장애/재전송 무손실 별도 |
| 기본·정기·추가 보고 | Mattermost 요청/이력, 정기 보고·자동 사건 관리 | 이전 실제 채팅 시험 보존. 최신 전체 변경 뒤 새 채팅/장문·followup 회귀는 잔여 |
| FW·WAF·IDS·Wazuh 전체 룰 | `get_firewall_rules`, `get_security_rules` | 기본·커스텀·상관 조건 조회 지원. FW 특정 체인 요청에도 전체 표를 출력하는 범위 오류 잔여 |
| 사건 조사·증거 수집 | `search_modsecurity_alerts`, `search_suricata_alerts`, `search_wazuh_alerts` | 실제 발생 구간·주소·flow/transaction·원본 근거 연결. 단순403/경보로 침해 성공 또는 정상 단정 금지 |
| 자산·취약점·원인 조사 | Wazuh 읽기14도구, 시스템 진단 | 자산/프로세스/포트/SCA/취약점·오류 조회. 모든 미등록 unit의 상세 journal이나 외부 TI는 자동 제공되지 않음 |
| 상관분석·위험·오탐 판단 | 센서 원본과 Wazuh 상관 룰을 LLM이 연결 | 중요 누락·DNS/정찰·자산/센서 혼동·조사 종결 품질을 새 사건으로 평가해야 함 |
| 공격 의심 대응 | `temporarily_contain_ip`, `block_ip`, `unblock_ip`, `list_blocks` | 기존 실제600초 차단·유지/해제 카드·만료/60초 cooldown 검증. WAF 신뢰 해시 정정 뒤 새로운 실제 공격 전체 회귀는 잔여 |
| 룰 수정·서비스 복구 | 정확 SHA 편집 제안, `propose_service_action`, 상태 영수증 | WAF/IDS/Wazuh 지정 파일·서비스8대상. C 웹/일반 host unit의 승인형 제어는 아직 카탈로그 밖 |
| 승인·실행·사후 검증 | 정확 후보 카드·root worker·`get_operation_status`/변경 상태 | 카드 승인과 적용/효과 확인을 구분. 결과 불명·도구 실패를 성공으로 바꾸지 않음 |
| 동료 검증·인계 | 공통 review 채널의 lead/peer | 실제 상대 답변/근거를 확인. 미응답을 합의로 표시 금지. 기존 peer6 후보 운영 미반영 |

실제 SDK discover는8서버·41도구, `hermes-parity`로 성공했고 호출/모델 추론/게시/보호 쓰기0이다. Native SSH의7서버 도구 목록과 coverage 읽기도 성공했다. legacy Wazuh 서버는 초기 단순 파이프 시험에서 목록을 얻지 못했지만 SDK의 정상 handshake로14도구를 확인했다. 이를 도구 미등록으로 오판하지 않는다. 연결 성공은 자연어 판단·승인형 쓰기·Mattermost 전달 E2E의 성공을 대신하지 않는다.

현재 coverage 관측은37 ok·3 degraded·1 not_installed·0 unavailable였다. journal은 제한된 과거 표본도 포함하므로 이 숫자만으로 현재 장애3개나 전체 보안 정상이라고 결론내리지 않는다.

추가 제어는 업무별 고정 대상·동작·사전 검사·정확 승인·한 번 실행·사후 확인·복구 설계를 갖춘 MCP로 확장한다. 일반 sudo·Docker·임의 SSH/셸·패키지 설치를 봇에 주는 방식으로 전 업무 요구를 해결하지 않는다. 미지원 요청에서도 가능한 근거 조사·위험/대응안·필요 권한과 미완료 항목을 LLM이 먼저 준비한다.
