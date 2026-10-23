# 이전 PHP Log4Shell 웹 — 운영 이력

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../STATUS.md) · [실행 계획](../../../PLAN.md).
> 현재 콘솔은 HTTP3개(Log4Shell/Apache2종)와 터미널3개(Redis/Samba/sudo), 총6항목이다. sudo는 별도 rootless의 UID1000·전역 단일 세션이며 종료 시 전체 중지한다. DVWA는 독립 유지한다. 환경 준비와 CVE 악용 성공을 구분하고 공격 재현은 보류한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

2026-10-19 사용자 요청에 따라 기존 PHP 중계 화면·API·최초 설치기·검증기를 제거하고 [Spring Boot 실습 웹](../log4shell-app/README.md)으로 교체했다. 현재 소스와 실행 절차는 새 디렉터리를 따른다. 이 디렉터리의 JSON 세 개는 2026-10-15 당시의 검증 증거로 보존한다.

- `deployment-validation-20261015.json`: 최초 PHP 화면과 정상200/헤더누락400 검증.
- `route-tls-validation-20261015.json`: 이름 기반 경로·TLS 적용 당시 결과.
- `session-validation-20261015.json`: PHP의 HTTP/HTTPS 쿠키 분리 당시 결과.

이전 소스 복구본은 로컬 전용 대화기록의 자료 폴더에 보관했다. 서버 운영 원본·JAR·설정도 `/var/backups/capstone-log4shell-java/20261019-replace-php`에 보존했다. 과거 파일 해시나 시험 결과를 새 Java 웹의 증거로 해석하지 않는다.
