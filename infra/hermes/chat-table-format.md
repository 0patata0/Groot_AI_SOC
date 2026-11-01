# Mattermost 표 경계 보정

2026-11-01. Native query plugin1.19.3과 공동 검토 채널에 [공통 보정기](chat_markdown.py)를 적용한다. 최종 운영 검증/Git 상태는 [STATUS](../../STATUS.md)를 따른다.

09:28 Hermes 답변은 설명 문장 다음 줄에 표를 바로 붙여 전송했다. 공식 Mattermost marked 파서 `467bc9e99fc75d69424188dfbea7fe0409a9fc15`에서 실제 원문은 table token0, 빈 줄 추가 후1로 재현했다. 09:30 Ollama 답변은 원래1이다. Hermes Mattermost adapter는 이미지 링크를 변환할 뿐 표를 텍스트로 바꾸는 기능은 없었다.

보정기는 앞뒤 파이프가 있는 정상적인 최상위 표의 헤더/구분선·열 개수를 확인하고, 문장과 붙은 표 앞뒤에 빈 줄만 추가한다. 셀·숫자·ID·주소·링크·규칙/승인 근거를 고치거나 모델/MCP를 다시 호출하지 않는다. fenced code(```/~~~), 들여쓴 코드·인용, pre/script/style/textarea 원문은 보존한다. 모양이 불완전한 표의 열을 추정하거나 코드를 표로 바꾸지 않는다.

- Hermes 단독 채널: query-completion 최종 응답의 Mattermost 표시 단계에서 보정한다. 도구 호출 본문과 다른 플랫폼은 유지한다.
- 공동 검토 채널: `review_channel_policy.render`에서 두 봇에 동일한 보정을 적용한다. 역할/원질문 링크/게시 식별자는 유지한다.
- 이미 게시된 메시지는 변경하지 않는다. 다음 답변부터 적용하며 단순한 표시 보정은 학습/추론 권한을 바꾸지 않는다.

초기 설치 진입점은 루트 `deploy.sh`다. SIEM 내부 설치기는 plugin에 `chat_markdown.py`를 함께 복사하며, review-chat 설치기의 고정 source 목록에도 같은 canonical 파일을 포함한다. 새로운 패키지·이미지·포트·비밀 설정은 없다. 오프라인 반입 시 갱신한 프로젝트 소스를 포함한다.

11/1 09:47 KST 운영 B에서 유휴 확인 후 runtime5파일과 review receipt를 반영하고 기존 Hermes 컨테이너/공동 채널 서비스를 다시 시작했다. `/var/backups/capstone-chat-markdown-20261101-r1/manifest.json`에 원본 SHA·모드/소유권·원복 경로를 보존하며 검토한 source/설치기는 `/opt/capstone-automation/releases/chat-markdown-20261101-r1`에 있다. 이 release는 부분 변경 snapshot이며 새 서버 설치에는 전체 프로젝트 소스가 필요하다. 복구는 유휴 상태에서 해당 manifest의 기존 파일/receipt만 되돌리고 새 formatter2개만 제거한 후 두 실행기를 재시작한다. DB/WAL·대화 이력·설정 파일은 원복 대상으로 덮어쓰지 않는다.

로컬검사: 순수표8 + query376(환경2skip) + review26 + SIEM43 + 배포218 =671실행/669PASS/2skip. 첫 query 검사의 인접 모듈 탐색 오류는 명시 파일 로딩으로 수정 후 통과했다. 실제 B UID995의 native 최종본문·원입력/코드 보존, 공동채널 receipt/유휴poll, Hermes 새 heartbeat/WebSocket 연결을 확인했다. 실제 채팅 원문2개를 보정해 공식 파서에서 둘 다 표1개로 인식했다. 채널 시험글 게시·기존글 수정·브라우저 UI 확인·새 서버 전체 설치는 수행하지 않았다.
