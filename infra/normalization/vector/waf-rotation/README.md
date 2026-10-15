# WAF 원본 회전 격리 검증

이 디렉터리는 기존 Nginx·ModSecurity, Vector, Wazuh logcollector를 사용하는 **일회성 시험 도구**다. 운영 수집기나 회전 서비스가 아니며, 운영 copytruncate를 교체하지 않는다. Python 표준 라이브러리는 프로세스 실행과 증거 비교에만 사용한다.

## 검증 범위

- 네 세대에 실제 합성 HTTP 요청을 2/1/1/2개 기록한다. 각 세대는 서로 다른 audit/access 경로와 producer binding·설정 SHA를 가진다.
- 본문이 미완료인 요청이 구 worker에 연결됐음을 소켓과 파일 descriptor로 확인한다. 새 경로와 HUP 이후 그 요청을 완료해 구 audit/access inode의 늦은 기록을 재현한다.
- Vector의 audit/access 수집과 Wazuh의 audit 수집을 대조한다. Wazuh는 JSON을 재직렬화하므로 원문 바이트 SHA와 설치 cJSON이 재직렬화한 바이트 SHA를 구분해 대조한다.
- 구 writer의 두 파일이 모두 닫히고, 두 Vector 경로의 기록과 Wazuh 기록·논리 EOF가 일치한 뒤 인접 세대를 순서대로 공개한다.
- 수집기를 멈춘 동안 연속 두 번 회전한 경우와, 같은 private checkpoint를 재사용하는 정상 종료·재시작을 확인한다.
- 각 세대의 보관 원본을 설치된 WAF VRL 네 개로 별도 재생한다. 자세한 성공·음성 대조 기준은 [pair 검증 계약](PAIR-VERIFICATION.md)을 따른다.

Wazuh 4.14.8의 SIGTERM handler는 `exit(1)`로 종료한다. 정상 재시작 검증은 Wazuh에 대해 TERM 전송·강제 종료 없음·종료 코드 1·종료 후 checkpoint의 경로/offset/SHA 일치를 함께 요구한다. Vector는 종료 코드 0을 요구한다. [Wazuh 공식 종료 처리](https://github.com/wazuh/wazuh/blob/v4.14.8/src/shared/sig_op.c#L44-L69).

## 격리와 증거

기존 WAF 이미지의 바이너리를 private 설정으로 실행하며 별도 loopback-only network namespace를 사용한다. Wazuh는 별도 mount/network namespace, 설정, 큐, 상태 디렉터리를 쓴다. 운영 서비스에 신호를 보내거나 운영 로그에 시험 요청을 기록하지 않는다. 시작·종료 대상은 생성한 프로세스의 PID와 시작 시각으로 제한한다.

시험 원본과 producer 설정은 서버의 root 전용 작업 경로에 읽기전용 사본으로 보존하고 SHA를 대조한다. `0400` 권한은 root도 변경할 수 없는 immutable 속성을 뜻하지 않는다. Mac으로는 건수·검증 상태·SHA 등의 메타데이터만 가져온다. 실패 회차도 보존하며, 같은 출력 디렉터리를 덮어쓰지 않는다.

시험용 WAF는 모든 합성 요청을 기록하는 단일 audit 규칙을 사용한다. 운영 CRS 전체의 정책·부하를 재현하는 시험은 아니다.

이 시험의 writer UID는 root다. 운영 worker UID 101의 descriptor 접근 권한과 완전히 동일한 조건은 아니다. 성공 결과도 운영 회전 전환, 실시간 pair 결합 무누락, 원격 분석·색인 ACK, 강제 종료·재부팅 복구의 완료를 뜻하지 않는다.

## 실행 결과

2026-10-14 20:43~20:44 KST `run-05`가 전체 검증을 통과했다. 네 세대의 합성 요청 2/1/1/2개에서 audit/access 원본 각6건, Vector audit6/access6, Wazuh audit6이 일치했고 중복은0건이었다. 늦은 구worker 기록·연속 두 회전·인접 세대 공개3회·정상 재시작을 확인했다. Wazuh는 TERM/강제종료없음/rc1/최종checkpoint 일치, Vector는 TERM/강제종료없음/rc0이었다.

별도 세대별 VRL 재생도6건의 ID·원문/시간증거SHA·KST·정제 메타데이터가 모두 일치했다. 구 binding 음성 대조는4건격리·ready0, 실제2초 결합 만료 후 늦은access 대조는 audit격리1/access-only제외1/ready0이었다. 이는 실시간 결합의 무손실 보장이 아니다.

20:44:38 운영 대조에서 호스트 보호8파일과 WAF 설정/바이너리51파일, 컨테이너·서비스·Vector/logcollector PID와 운영 root/queue inode가 사전 기준과 같았다. 설치VRL4개의 SHA도 전후 같았다. 시험 프로세스와 실행용 임시 경로는 정리됐고 오류0·잔존writer0이었다. 원본 증거는 A에만 보관하며 Mac 패키지 설치는0건이다. [전체 메타데이터와 실패 회차 기록](validation-2026-10-14.json).

앞선 네 회차는 검증기의 복사 크기 제한, 시작 대기, offset 자료형, Wazuh 종료 계약을 보완하며 남긴 실패 증거다. 성공 회차로 덮어쓰지 않았다. run-02의 오류 위치와 run-04의 실제 종료 코드는 당시 보존되지 않아 추정과 확인 사실을 구분했다. 운영 copytruncate와 서비스 구성은 변경하지 않았다.
