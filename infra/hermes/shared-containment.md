# 여러 사건에서 기존 임시 차단 참조 — 2026-11-03 KST

Native IDS가 이미 차단한 IP를 WAF 조사 LLM이 `temporarily_contain_ip`로 확인하면 helper는 같은 request ID와 `duplicate:true`를 반환한다. 종전 컨트롤러는 이 정상 응답을 다른 사건의 변경 ID 충돌로 거절해, 모델의 최종 보고와 MCP 6회가 모두 있어도 `outcome_unknown`으로 기록했다.

이 오류는 학습자료나 모델 크기의 문제가 아니었다. 앞선 PCAP 보고의 ‘모델 최종 답변 없음’ 해석을 정정한다. 당시 DB의 빈 final_text/미완료 상태는 실제 관측이지만, private native trace에는 exit_code=0인 최종 보고가 있었다. 원문과 과거 상태는 덮어쓰지 않는다.

## 처리와 경계

| 항목 | 처리 |
|---|---|
| 기존 승인/차단 | `proposals.id`의 원소유 사건 하나를 유지 |
| 참조 허용 | 실제 성공한 A `temporarily_contain_ip` 응답이 `duplicate:true`, `kind:containment`, `target:a:incident-ip`이고 요청 IPv4와 응답 IP가 정확히 같을 때만 |
| 별도 원장 | `containment_references`에 현재 사건·원 request ID·IP·실제 응답 SHA·관측시각 보존. FK로 기존 사건/요청과 연결 |
| 상태 확인 | 해당 실행에서 원 request ID의 정확한 IP/target 상태를 실제로 읽어야 함. 참조 자체는 현재 차단 성공의 증거가 아님 |
| 승인 후속 | 원래 broker의 결정이 오면 기다리던 참조 사건도 읽기 전용 verify로 조사 재개 |
| 계속 거절 | 다른 IP·일반 룰/서비스 쓰기·비중복 응답·잘못된 대상의 cross-case ID 충돌 |

새 승인·차단 소유권·유지 권한을 만들거나 옮기지 않는다. 참조한 요청의 pending은 현재 FW 상태와 별개다. 기존 보호 주소·최초600초·유지/해제 카드·자연 만료·60초 재차단 대기·중복 연장 금지를 유지한다. LLM의 조사·판단·제안 역할과 실제 MCP 호출·서버 증거/승인 검증도 유지한다.

## 검증 범위

| 검증 | 실제 결과 |
|---|---|
| 컨트롤러 부분 |81 PASS. 아래185개에 포함되며 별도로 합산하지 않음 |
| 전체 management 회귀 | 로컬185/서버185 PASS, skip0 |
| 초기 설치 경로 계약 |37 PASS. 새 OS 전체 설치를 뜻하지 않음 |
| 실제 과거 trace 전후 재생 | 동일6 MCP·native 최종결과를 private DB 복제본에서 재생. 이전 protocol_error/outcome_unknown → 후보 waiting_approval/실행 완료. 원소유권 보존·참조1 |
| 새 Kali232 시험 |20:10 XSS/SQLi/경로탐색3 GET 모두403. IDS/WAF 두 실제 사건이 같은 Native 요청 `44e23dcd…`를 참조2개로 연결. 원소유 사건 유지 |
| 새 WAF 사건 |6 MCP 완료·실제 `waiting_approval`, 종전 ID 충돌 없음 |
| 새 IDS 사건 |10 MCP·프로토콜 실행은 완료됐으나 미래 until_kst 조회3건 실패로 `needs_review` 유지 |

과거 재생은 당시 pending 상태를 실제 영수증으로 복원한 격리 시험이다. 운영 DB 수정이나 실제 도구·차단의 재실행은 없다. 유효한 프로토콜·승인 대기는 모델 의미 판단의 정답이나 사건 해결 완료가 아니다. 자산명/센서명 혼용·과거 경보를 현재 구간에 섞는 오류와 미래 시각 조회·정정 후 오류 처리는 후속 과제로 남는다. [기계 원장](shared-containment-validation-20261103.json).

## 운영 반영·설치·복구

20:08:59 관리자231 경유로 B의 실제 컨트롤러 Store/Trace 7메서드만 기존 AST와 대조해 교체했다. 나머지 모듈과 내장 native gate·컨테이너 ID·신원·명령·모델 바이트는 보존했다. 컨트롤러 유휴를 확인하고 원본 hash/uid/gid/mode와 독립15분 CAS 복구 timer를 먼저 준비했다. Hermes 컨테이너 재시작·도구/권한·서비스/공개 포트·패키지 변경은 없다.

20:16:15 새 source SHA·참조2개/원소유권·FK 오류0·기존 timer 정상 확인 후 확정하고 복구 timer를 해제했다. 루트 복구는 `/var/lib/capstone-shared-containment/20261103-r1`에 보존한다. `rollback.py`는 파일 SHA가 이번 후보와 같고 컨트롤러가 유휴일 때만 이전 바이트/메타데이터로 복구하며, 실행 중이면 다음 주기로 미룬다. **실제 수동 원복은 미실시**다. SQLite·새 대화·참조 원장을 과거 DB로 되돌리거나 삭제하지 않는다.

기존 루트 `deploy.sh`→`deployment/soc_management.py`가 같은 canonical 컨트롤러를 포함한다. 기존 설치에서는 다음 정상 시작 시 `CREATE TABLE IF NOT EXISTS`로 참조 표만 추가한다. 초기 설치에서도 같은 코드로 표를 만든다. 새 패키지·오프라인 반입 항목·사용자 설치 진입점은 없다.

소스는 [컨트롤러](soc_management_controller.py)와 [회귀 검사](test_soc_management_controller.py)에 반영했다. 원문 trace·복제 DB·실제 도구 응답·대화는 Git 제외다. 공개 원장에는 출처·소스/증거 SHA·집계·상태와 한계만 남긴다.

검증 후 자체 private 재생 DB 복제본과 서버검사 작업본만 제거했다. 원문 운영 DB/trace·원소유 승인/차단·원본/후보 코드·복구 메타데이터·재생 결과/검사 로그는 보존한다.

20:25 추가조회:원래20:20:30 기한의차단은20:20:33 expired·커널집합부재였고두참조도expired였다. WAF후속은읽기전용verify로진행중이다. 즉시broker깨움의인과나사건전체종결을별도검증한것은아니다.

공유참조9파일 `618c08d`는20:23:40 KST 실제원격main일치확인했다. 자체Mac도우미19파일/임시부모와서버시험/재생클론10파일을정리했으며,게시확인보완은후속문서로게시한다.

후속21:09 시각/자산근거 보완에서는 공통검사와 오래된 자동관리 내장 gate도 동기화했다. 위20:08 단계의 게이트 유지/재시작0은 당시 범위이며 현행 사본·복구·새 검증은 [후속 문서](incident-context.md)를 따른다.
