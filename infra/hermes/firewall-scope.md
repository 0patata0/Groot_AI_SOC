# FW 선택 체인 조회 — 2026-11-04

아래는1.5.17 독립 실행의 이력이다. 이후 실제 후속 채팅에서 발견한 오류와1.5.18 보완·긴 표 분할 미완료는 [최신 실채팅 결과](firewall-chat.md)를 따른다.

공통 계약 `soc-chat-contract:1.5.17`을 기존 Hermes·Ollama에 증분 반영했다. `FW input 룰만 보여줘`에 전체 체인을 출력하거나 `FW input만 보여줘`를 정형 조회로 인식하지 못하던 문제를 보완했다. [현황](../../STATUS.md) · [원장](firewall-scope-validation-20261104.json) · [MCP 읽기 계약](../mcp/firewall-read.md).

| 요청 | 처리 |
|---|---|
| FW input만 보여줘 / 방화벽 인풋 룰 | INPUT hook의 시작 체인·규칙과 연결된 참조만 표시 |
| FW output 룰 / FW 포워드만 | 지정 OUTPUT/FORWARD 경로만 표시 |
| FW CAPSTONE-FWD 체인 룰 | 정확한 이름의 체인에서 시작. family/table이 다른 참조를 합치지 않음 |
| input 말고 output | INPUT 제외·OUTPUT 선택 유지 |
| 각각 표로 / 룰 조회해줘 / 2페이지 | 같은 사용자·스레드의 선택 범위 유지. 새 상태 요청은 새 읽기, 순수 재정리는 이전 관측임을 명시 |
| output만 / FW 전체 룰 | 새 hook 선택 또는 명시적 전체 범위로 전환 |

고정 `get_firewall_rules`의 스키마·명령·권한은 그대로다. 모델이 실제 도구와 페이지 인자를 선택하며 공통 하네스는 전체 영수증을 먼저 검증한다. 표시 선택을 위해 MCP를 미리 호출하지 않는다. jump/goto·집합/맵·verdict map을 따라 참조 체인을 고정점까지 수집하고 순환 참조도 종료한다. 다른 OUTPUT/FORWARD 체인은 제외하지만 요청 경로에서 직접 참조하는 체인은 누락하지 않는다. 미해결 참조·없는 체인·부분 페이지는 미확인으로 표시한다.

INPUT 목록은 앞단 PREROUTING·별도 네임스페이스를 포함한 전체 접근 판정이 아니다. 일반 FW 요약과 임시차단 목록, 실제 차단 효과는 계속 구분한다. 개별 조건은 기존 nft JSON 표·표시 페이지 상한을 유지한다. 포트/주소/동작 등 모든 자연어 필터를 새로 구현한 것은 아니다.

## 실제 검증 범위

| 검사 | 결과 | 한계 |
|---|---|---|
| 로컬 기존 전체 회귀 | SDK187개 중184통과/환경3skip, Hermes380개 중378통과/환경2skip | 이후 추가한 native 전용3개도 별도 통과. Mac 패키지 설치0 |
| 서버 기존 SDK/네이티브 환경 | SDK187·Hermes383, 합계570 통과·skip0 | 운영과 분리한 소스/fixture 복사본 검사 |
| 초기 설치 소스 연결 | 독립 source bundle·도구 계약2개 통과 | 기존 복사 경로를 재사용. 설치 코드 수정·새 OS 설치0 |
| 실제 Ollama 모델→MCP 읽기 |7.794초·1회·전체103규칙→INPUT1체인/14규칙, completed | private CLI, 채팅 왕복 시간 아님 |
| 실제 Hermes 모델→MCP 읽기 |21.544초·1회·같은 선택1체인/14규칙, completed | 별도 private Mattermost-platform 세션. 실제 채널 게시/UI 검증 아님 |
| 운영 확정 |4소스 사본+설치 영수증 SHA, 보호 설정5개 SHA·두 봇 인증된 웹소켓/worker 확인 | 수동 원복은 실행하지 않음 |

서버 첫 native 시험은 복사본의 MCP 소스, 다음은 `infra/groot-b/local_rules.xml` fixture 누락으로 실패했다. 필요한 원본만 보완해 최종383개 통과했고 실패 로그는 로컬에 보존했다. 이것을 운영 룰·권한·모델 실패로 판단하지 않았다. 새 질문을 학습자료로 편입하지 않았으며 두 단일 실행의 시간을 지연 개선율이나 에이전트 우위로 일반화하지 않는다.

## 배포·설치·복구

11/4 13:05:30 KST 적용 후13:08:42 KST 운영 검증을 확정했다. 관리자231→A→B로 source SHA/CAS를 확인해 `/opt/capstone-ollama-trial`과 Hermes 플러그인의 공통 harness/contract 사본4개, 관련 영수증1개만 교체했다. 큐 유휴와 management 실행 부재를 확인하고 두 소비자와 기존 Hermes를 각각 한 번 재시작했다. management timer를 재개했으며 모델·config/SOUL·운영 DB·MCP 권한·FW 룰을 변경하지 않았다.

루트 `deploy.sh`의 기존 canonical 소스 복사 경로가 같은 harness/contract를 사용한다. 독립 묶음 import에서 선택 범위를 확인했으며 새 상시 서비스·포트·키·이미지·deb/wheel은 없다. 오프라인 반입은 갱신된 프로젝트 소스를 사용하고 기존 서버를 초기 설치기로 덮어쓰지 않는다. 사용자 지시대로 신규 설치기 전체 실행은 하지 않았다.

root 복구본은 B `/var/lib/capstone-fw-scope/20261104-r1/deployment`에 보존한다. 원본·후보 바이트/권한/SHA·manifest·적용/확정 기록과 운영자용 apply/rollback을 포함한다. 독립15분 원복 타이머를 만들고 실제 검증 뒤 해제했으며, 확정 상태에서 recover no-op을 확인했다. 승인된 운영자의 수동 복구는 아래 명령이다.

```bash
python3 -B /var/lib/capstone-fw-scope/20261104-r1/deployment/rollback.py --manual
```

해당 배포 SHA인 파일만 원복하며 동시 변경은 보존한다. 진행 중인 요청이 있으면60초 뒤 독립 재시도를 등록한다. DB를 과거 복사본으로 되돌리지 않는다. 신규 패키지/가중치·실제 공격/쓰기·Mattermost 게시/표 UI 시험은 이번 범위 밖이며, 최종 임시 정리와 Git 게시 확인은 현황/원장에 별도로 기록한다.
