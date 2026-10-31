# 짧은 질문과 승인형 호스트 서비스 작업

2026-10-31 보완. 운영 반영·검증의 최신 범위는 [STATUS](../../STATUS.md)를 따른다.

## 조회 대상 결정

| 요청 | 처리 |
| --- | --- |
| 새 스레드 `룰 조회해줘` | FW/WAF/IDS/Wazuh 중 어느 장비인지 한 번 확인. 조회 성공으로 표시하지 않음 |
| 같은 스레드에서 위 질문에 `FW` | FW 현재 규칙 새 조회 |
| 같은 사용자의 직전 요청이 FW이고 이어서 `룰 조회해줘` | 대상만 FW로 이어받고 현재 근거 새 조회 |
| 명시한 다른 장비·여러 장비 | 현재 요청 우선. 여러 장비 중 하나를 추측하지 않음 |
| 다른 사용자/봇·다른 스레드·잘린 이력·쓰기 이력 | 대상·관측값·승인을 이어받지 않음 |
| `systemd failure 왜 떠?` | A/B/C 현재 failed unit 조회. 알려진 서비스는 별도 상태·분류된 오류 표본 조사 |

Hermes의 검증된 Mattermost 문맥과 Ollama 채팅 어댑터 모두 같은 사용자·스레드의 최근 요청만 대상 결정에 제공한다. 인용 자료는 명령이나 승인이 아니다. 모델은 제한된 도구 스키마에서 실제 호출을 선택하고, 근거·누락 검사는 공통 하네스가 수행한다. 현재 상태를 모델 가중치나 이전 답변으로 대신하지 않는다.

`a:systemd`, `b:systemd`, `c:systemd`는 root 수집기가 고정 `systemctl list-units --failed --all`로 수집한다. 이름·load/active/sub 상태와 총계만 반환하며 설명 원문은 제외한다. 최대16개 표시, 초과는 잘림·전체 건수를 명시한다. 이는 현재 메모리에 로드된 failed unit 목록이며 전체 설치 서비스나 과거 장애 이력이 아니다. 0개도 모든 서비스 정상을 입증하지 않는다. [systemctl 공식 범위](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

기존 systemd25+runtime13에 집계3개를 더해41관측 대상, `soc:coverage` 포함 enum42다. 수집 약60초·유효180초, 실제 관측 KST를 표시한다. 읽기 실패는 `unavailable`이며 0으로 치환하지 않는다. 미등록 unit도 이름은 발견할 수 있지만 상세 journal 조회·조치 권한이 자동 생성되지는 않는다.

## 승인형 추가 대상

| 대상 | 고정 unit | 허용 작업 | 검증 |
| --- | --- | --- | --- |
| `a:vector` | `capstone-vector.service` | restart | 설정·VRL 검사, 새로운 InvocationID/PID, 해당 실행의 최신 telemetry |
| `a:wazuh-agent` | `wazuh-agent.service` | restart | 호스트 설정4종 검사, 새 InvocationID, 호스트 프로세스·최신 connected 상태 |
| `b:wazuh-agent` | `wazuh-agent.service` | restart | 위와 동일. manager 컨테이너와 구분 |

기존 컨테이너5대상과 합계8대상이다. 새 서버 설치에서는 기존처럼 `a:chatproxy`를 제외하므로7대상이다. C는 이번에 읽기만 확장했다. Docker daemon/SSH/임의 unit 재시작, 패키지 설치, 임의 명령·환경·설정 편집은 허용하지 않는다. 등록 작업 외의 변경은 별도 검토한 실행 프로필·검증·복구 경로가 필요하다.

LLM이 진단과 위험 판단을 주도하고 `get_service_action_target`으로 근거를 읽은 뒤 `propose_service_action`으로 정확한 승인안을 준비한다. 관리자가 승인하면 기존 root worker가 상태·정책 SHA를 다시 대조하여 한 번 실행한다. 미승인·거부·만료·상태 변경·사전 검사 실패는 실행하지 않는다. 적용 후 확인 실패나 결과 불명은 성공으로 바꾸거나 자동 재실행하지 않는다. 서비스 restart에는 이전 실행 상태로 되돌리는 자동 원복이 없다.

관찰은 boot/InvocationID·unit/drop-in·설정/VRL 해시를 묶으며 민감한 설정 값·환경·명령 원문을 반환하지 않는다. Vector는 고정 작업 디렉터리와 세 경로 변수만 사용하여 `validate --no-environment`를 실행한다. Wazuh는 `wazuh-agentd`, `wazuh-logcollector`, `wazuh-syscheckd`, `wazuh-modulesd`의 `-t`를 사용한다. [Vector 검증](https://vector.dev/docs/administration/validating/) · [Wazuh 설정 검사](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/verifying-configuration.html).

## 배포·복구

초기 설치 진입점은 `deploy.sh` 그대로다. 기존 SOC renderer는 systemd 프로필에 컨테이너 ID를 붙이지 않으며 관리 controller/gate의 허용 대상도 함께 생성한다. 기존 키·계정·포트와 deb/wheel/image 목록은 유지하고 갱신 소스를 반입한다. 신규 패키지나 LLM의 일반 sudo 권한은 필요하지 않다.

운영 증분은 A/B/C root 백업·원본 SHA 확인 후 교체한다. B에서는 진행 중 채팅·승인이 없을 때 채팅 프로세스와 승인 브로커를 재기동한다. SOUL은 해당 허용 대상 문장만 교체하며 관리 controller의 기존 인라인 gate와 설정을 보존한다. source pin, SDK/Native 공통 사본·설치 영수증의 해당 파일을 함께 갱신한다. 과거 영수증의 다른 파일까지 전수 재인증한 것으로 표시하지 않는다.

복구 시 기록된 `/var/backups/capstone-short-systemd-{a,b,c}-…/manifest.json`의 경로·순서·소유권·권한·SHA를 확인하고 해당 백업 전체를 일관되게 복원한다. 채팅 모듈/grounding/source pin을 일부만 되돌리지 않는다. 복구 전 진행 중 요청·승인 상태를 확인하고 반영 후 MCP 조회와 채팅 연결을 재검증한다. 실제 승인→서비스 재시작 E2E와 새 서버 전체 설치 시험은 격리 검사나 읽기 성공으로 대신하지 않는다.
