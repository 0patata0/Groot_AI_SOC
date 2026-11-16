# 소스와 관측 구분

| 대상 | 기준 |
|---|---|
| 실제 운영 대조 | 관리자231→A→B 경로, 설치32소스 SHA·같은3분 구간의 MCP3읽기·직접 원문 |
| 기본 코드 | Git `ddaae8bf0d398f32acc1926214a31323ce2043af`의 전체 추적2258파일 |
| 공통 분류 | [system_diagnostics.py](../../mcp/system_diagnostics.py)의 기준본, 실제 수정은 candidate.patch |
| 보관 색인 | [diagnostic_history.py](../../mcp/diagnostic_history.py)의 정제·트랜잭션·읽기 계약 |
| 원문 경로 | [CLI](../../mcp/diagnostic_journal.py)와 [Native](../../mcp/diagnostic_journal_native.py) 선택/한도 |
| MCP 계약 | [서버 소스](../../mcp/system-diagnostics-mcp.py)의 입력/권한 유지와 새 메타데이터 설명 |
| 공식 구조 | google-research/harness2 `6868817518876de8fd170c6a8354daca273b6191`, 구조만 검사 |
| 회귀 | 기존 진단128, 신규24, 호스트·런타임·설치·소비자8프로필. 정상/실패/정책 이전을 구성한 제품 검사 |

설치된 core와 journal은 Git 기준과 다르며 Native 파일은 설치되지 않았다. 따라서 패치를 운영 파일에 바로 덮는 절차가 아니다. 실제 메모리 내 비교는 후보 코드·등록된 Docker unit·같은 구간에 한정하며 원문·SQLite는 읽기 전용이었다. 원시 메시지는 정제 색인에 저장하지 않고 실제 발췌·영수증은 로컬 전용으로 보존했다.

학습35B 모델·설정·승인/보호·차단 TTL은 바꾸지 않았다. 모델 호출·보호 작업·채팅 게시·실제 캐시 게시·새 학습·공격0이다. 코드 결함 보완을 추가 학습이나 독립 사건 정답으로 표시하지 않는다.

파일별 수정 전/후 SHA, 전체 트리 ID와 패치·회귀 입력은 [manifest](manifest.json)·[source manifest](source-manifest.json)에 고정한다. 실제 시간·오류/성공·범위·생략은 [validation](validation.json)에 남긴다. 문서의 기준 소스 링크는 현재 저장소의 정본이며 미적용 후보 본문과 구분한다.
