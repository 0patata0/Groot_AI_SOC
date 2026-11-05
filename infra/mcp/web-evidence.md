# C 웹 백엔드의 제한된 읽기 근거

**11/5 현행:** [과거 시간 필터 보완](web-history.md)으로 실제 검색은 정제 이력14,143행을 대상으로 시간/서비스를 먼저 적용한다. 최근10,000행 스냅샷은 유지한다. 아래11/4 수집/실험은 당시 범위이며 새 동작·한계·복구/85검사는 후속 문서를 따른다.

2026-11-04 KST. 기존 `security-events` 서버에 `get_web_service_target`과 `search_web_access`를 추가했다. 경보 색인과 별도로 C Apache 접근 기록을 조사한다. LLM이 도구·인자를 선택하며 일반 셸·sudo·Docker·파일 경로 선택 권한은 추가하지 않는다. [현재 상태](../../STATUS.md) · [검증 원장](web-evidence-validation.json).

| 도구 | 실제 읽는 근거 | 한계 |
|---|---|---|
| `get_web_service_target` | C 설정 파일의 고정 경로·로컬 Wazuh 등록 ID/이름·Apache 프로세스 상태 | A 프런트 WAF의 실제 설정 적재·프록시 앱 가동·침해 부재 증명이 아님 |
| `search_web_access` | 고정 서비스의 KST 구간·선택 출발지와 일치하는 정제 접근 기록 | 반환/보관 색인은 전체 요청 수가 아님. 0행을 미도달·공격/침해 부재로 해석하지 않음 |

대상은 `c:dvwa`, `c:lab-console`, `c:lab-java`, `c:lab-httpd49`, `c:lab-httpd50`이다. 각 경로는 `/dvwa/`, `/_offline-labs/`, `/_offline-lab-java/`, `/_offline-lab-httpd49/`, `/_offline-lab-httpd50/`이다. 일반 Log4Shell이라는 명칭만으로 Java 앱과 관리 UI를 같은 대상으로 합치지 않는다.

`search_web_access`는 `target`만 주면 서버가 최근 60분을 계산한다. `lookback_minutes`는 1~1440, `limit`는 1~50이다. 정확한 구간은 초·`+09:00`을 포함한 `since_kst`와 `until_kst`를 함께 사용하며 상대 길이를 섞지 않는다. 구간 폭은 최대 24시간, 시작은 최근 14일 안이어야 한다. 기록이 그 기간 전체에 존재한다는 보장은 아니다.

```json
{"target":"c:dvwa","lookback_minutes":60,"limit":10}
```

## 근거와 개인정보 경계

C의 root publisher가 약 60초마다 고정 스냅샷을 만들고 읽기는 최대 180초 된 스냅샷만 허용한다. `access.log`와 최대 14개 회전을 확인하며 총 입력 8MiB, 보관 행 10,000개, 스냅샷 4MiB 상한을 적용한다. gzip CRC/EOF 실패의 부분 행은 버리고, 읽기 실패·잘림·변경 중 파일·파싱 제외를 표시한다. 실제 관측에서는 15파일·3,163,428바이트를 읽었고 10,000행 상한에 도달했다. 이는 보관 행 수이며 DVWA 요청 수가 아니다.

반환값은 시각·로그에 기록된 주소·메서드·경로·응답 코드/크기·해시·출처다. query 문자열·로그인 사용자·헤더·쿠키·referrer·User-Agent·본문은 반환하지 않는다. 경로는 최대 240자로 표시하고 잘림과 전체 경로 해시를 남긴다. `entry_sha256`은 로그 행 바이트의 식별자이며 고유 HTTP 거래 ID가 아니다. 같은 바이트 행을 임의로 하나의 요청으로 합치지 않는다. 출발지 주소의 실제 사용자 신원·프록시 전달 신뢰는 별도 근거가 필요하다.

파일별 inode·열 때 크기·읽은 바이트·정제 전 압축 해제 prefix SHA를 남긴다. 전체 파일 해시/회전 무손실·로깅 연속성을 검증했다고 표시하지 않는다. `actual_request_total_count=null`, `logging_continuity_verified=false`와 관측 나이를 유지한다. C의 `client.keys`에서는 등록 ID/이름만 읽고 비밀 필드는 출력·반출하지 않는다. 로컬 등록은 독립적인 목적지 신원 인증이 아니다.

파일은 root 소유·안전한 권한·일반 파일·단일 hardlink를 검사하고 디렉터리 fd와 `O_NOFOLLOW`로 연다. Ubuntu의 정확한 `/var/log` root:syslog 0775와 Wazuh의 정확한 등록 디렉터리/파일만 제한적으로 허용하며 다른 경로의 쓰기 권한은 거절한다. publisher만 Wazuh 보조 그룹으로 등록 파일을 읽으며 봇 계정에 그 그룹을 추가하지 않는다.

## 읽기 전용 연결·설치

| 위치 | 구성 |
|---|---|
| B | 기존 `/opt/mcp/security-events-mcp.py` 옆의 `web_evidence.py`·`web_evidence_client.py` |
| B→C | 기존 진단 private key와 pin된 C 호스트 키를 사용. private key는 B에 유지 |
| C | 새 `capstone-web-evidence` 계정, B 출발지 제한·publickey 전용·강제 명령·TTY/전달/사용자 RC 금지 |
| C reader | `/opt/capstone-web-evidence/read-web-evidence.py`. 고정 스냅샷/두 조회만 허용, 명령행·SSH 원격 명령·추가 JSON 인자 거절 |
| C publisher | `capstone-web-evidence.service/.timer`, root·capability 비움·외부 네트워크 금지·쓰기 경로 제한·CPU20%/96MiB/30초 |

기존 `capstone-diagnostics` 계정·강제 reader 프로토콜은 변경하지 않았다. 최초 설치는 루트 `deploy.sh`의 기존 service `diag-apply`가 `deployment/web_access_deploy.py`를 내부 호출하고, SIEM 역할이 MCP 보조 파일 2개를 설치한다. 추가 패키지·이미지·공개 포트·사용자 입력 키는 없다. 소스와 기존 Python/OpenSSH/systemd/Wazuh 그룹이 필요하다. 기존 B 보조 배포기도 6개 도구와 보조 파일·실패 복구를 함께 처리한다. 새 서버 전체 설치는 실행하지 않았다.

## 짧은 질문과 실제 검증

`DVWA 접근 기록 좀 보여줘` 같은 대상·업무가 명확한 단순 조회는 최근 1시간의 실제 `search_web_access` 읽기와 공통 표를 사용한다. 사건/공격/영향 조사, 쓰기, 복수·다른 서비스, 명시 기간·출발지·개수는 이 단순 경로로 축소하지 않는다. 읽기 영수증의 SHA·대상·구간·행 수/시각이 맞아야 표로 재구성하며, 이전 봇 문장을 근거로 쓰지 않는다. 분류는 호출·위험 판단을 대신하지 않는다.

첫 실제 두 봇 시험에서 도구 호출은 성공했지만 Ollama는 Apache active에 ‘정상’을 덧붙이고 잘림을 빠뜨렸으며, Hermes는 단순 조회에 불필요한 benign/위험 해소 판단을 붙였다. 원문은 로컬 감사에 보존했다. 공통1.5.25/query1.19.20에서 제한 누락/앱 정상 주장 검사를 추가하고 일반 조회의 사건 평가를 분리했다. 최종 새 worker 시험은 Ollama13.369초·Hermes45.335초/각1읽기·오류0·쓰기0이며 동일 범위 표/잘림/전체미확인을 보존했다. 중간 Hermes53.051초는 읽기 범위가 충족됐으나 내부 사건 상태 때문에 partial이었고 lead의 읽기 완료만 분리해 보완했다. 기존 사건 상태는 needs_review로 유지한다. 8서버43도구 실제 discovery는 모델/보호 호출·게시0이었다. 최신 Git 상태는 검증 원장과 STATUS를 따른다. 형식 검사만으로 모든 의미 오류가 해결됐다고 표시하지 않는다.

실제 MCP 10호출은 정상 읽기 8개(등록 대상5·접근 검색2·기존 Apache 진단1)와 금지 인자/미등록 대상 거절2개였다. 최초 사건 구간의 반환0행을 침해 부재로 판단하지 않았다. 새 공격·차단/해제·승인·앱 실행은 수행하지 않았다. 모델 시험은 운영 worker 경로의 새 세션이며 채팅 게시/UI 왕복·실제 공격 E2E와 구분한다.

## 복구

C 원본 준비·확정·복구 소스는 `/var/lib/capstone-web-evidence-deploy/20261104-r1`, B의 첫/후속 후보는 `/var/lib/capstone-asset-impact/20261104-r1/deployment`와 `deployment-r2`에 보존한다. 독립 타이머를 먼저 등록하고 검증 뒤 해제한다. C 복구는 새 publisher/계정을 비활성화하고 근거·소스를 보존하며 기존 Apache·진단 계정을 바꾸지 않는다. B 복구는 변경 SHA와 활성 실행을 대조해 자기 후보만 되돌리고 운영 DB·승인·채팅을 삭제하지 않는다. B 후속 후보를 되돌린 뒤 첫 후보 복구를 순서대로 적용해야 작업 전 상태가 된다. 확정 후 자동 복구는 no-op, 실제 수동 원복은 미시험이다.

C 승인형 제어·장기/전체 접근 로그 무손실·실제 앱/호스트 영향·SDK 사건 종결 검사 동등성·최초 차단 지연·전체 설치와 전 과정 시연은 별도 잔여다.
