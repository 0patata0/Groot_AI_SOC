# 이전 PHP Log4Shell 웹 — 운영 이력

2026-10-19 사용자 요청에 따라 기존 PHP 중계 화면·API·최초 설치기·검증기를 제거하고 [Spring Boot 실습 웹](../log4shell-app/README.md)으로 교체했다. 현재 소스와 실행 절차는 새 디렉터리를 따른다. 이 디렉터리의 JSON 세 개는 2026-10-15 당시의 검증 증거로 보존한다.

- `deployment-validation-20261015.json`: 최초 PHP 화면과 정상200/헤더누락400 검증.
- `route-tls-validation-20261015.json`: 이름 기반 경로·TLS 적용 당시 결과.
- `session-validation-20261015.json`: PHP의 HTTP/HTTPS 쿠키 분리 당시 결과.

이전 소스 복구본은 로컬 전용 대화기록의 자료 폴더에 보관했다. 서버 운영 원본·JAR·설정도 `/var/backups/capstone-log4shell-java/20261019-replace-php`에 보존했다. 과거 파일 해시나 시험 결과를 새 Java 웹의 증거로 해석하지 않는다.
