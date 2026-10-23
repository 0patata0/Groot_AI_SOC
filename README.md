# Groot_AI_SOC

## 콘솔 개편·단일 초기 설치기 — 2026-10-23

메인에 수평 메뉴·큰 제목·서버 선화·실습 현황 띠를 적용했다. 메인과 Java·Apache 두 하위 실습 화면은 같은 차콜·웜그레이/웜화이트 팔레트를 공유한다. 외부 CDN 없이 동작하며 DVWA는 기존 독립 화면을 유지한다. 최신 서버 자산 SHA 일치와 공개 HTTP35개 검사를 통과했다. 선택한 HTTPS origin의 Secure 쿠키 회귀를 포함한 C native66개도 통과했다.

새3서버 초기 설정은 `bash deploy.sh --apply --batch --config deployment/site.local.conf` 하나로 시작한다. 승인된 로컬 deb·이미지 반입, SIEM→공통 키 전달→콘솔/웹3종·sudo→TLS/WAF 구성을 내부 helper로 연결했다. [준비물·실행 순서](deployment/bootstrap-guide.md). **새 VM3대 전체 적용은 아직 미실행**이며 운영 웹 검증과 구분한다.

## 실습 페이지 테마·DVWA 범위 정정 — 2026-10-23 적용 완료

Log4Shell HTTPS 주소의 **콘솔·Java·Apache 두 버전** HTML에 상단 단일 테마 버튼을 제공한다. 현재 모드인 `다크` 또는 `화이트`와 같은 16px 크기의 달·해 아이콘을 표시하고, 고정된 아이콘 자리·가운데 정렬한 글자 슬롯과 약180ms 색상 전환을 사용한다. `prefers-reduced-motion`을 존중하며 외부 CDN 없이 같은 사이트의 `localStorage`에 선택을 보존한다. 최신 자산의 서버 SHA 일치와 새로고침한 Safari에서 고정 아이콘·글자 가운데 정렬·양방향 전환을 확인했다. Java·Apache 두 버전의 테마 동작도 확인했다.

사용자는 **DVWA를 원래 독립 주소에서 그대로 유지**하도록 범위를 정정했다. 앞서 같은 Log4Shell 사이트에 연결한 것은 요청 범위를 잘못 확대한 작업이었다. 현재 카탈로그는 **Java·Apache 두 버전·sudo 총4항목**, 웹 실습은 관리형3개다. 추가했던 DVWA 프록시·카탈로그 연결·전용 예외 쿠키·테마 처리만 제거했으며, 원래 DVWA 앱·DB·독립 접속 경로는 유지했다. 10/22의 5항목 배포·검증 자료는 당시 이력으로 보존한다.

## 오프라인 실습 관리 웹 — 2026-10-22 배포·10/23 범위 정정 완료

기존 Log4Shell 주소를 **[Lab Console](https://log4shell.grootlab.duckdns.org/log4shell/)**로 전환했다. 로컬 `cve_list.json`과 준비된 Docker 이미지만 사용하며, **Log4Shell·Apache httpd 2.4.49/2.4.50** 3개는 관리형 웹 실습으로 실행·중지한다. **sudo CVE-2021-3156**은 웹 실행 없는 별도 rootless CLI 항목으로, rootless 런타임·무해한 환경 검증·정식 상태 발행 검증을 완료했다. 실제 권한 상승·호스트 탐지 시나리오는 검증하지 않았다. 키 없이 목록과 웹 실습을 사용할 수 있다. 선택 입력하는 차단 예외 키는 기존 Wazuh Dashboard 관리자 암호와 같으며, 일회용 HMAC 서명을 검증한 10분 세션 동안 해당 실습의 WAF 탐지는 기록하되 차단을 유예한다. [접속 방법·전체 소스·오프라인 설치/반입·복구](infra/groot-c/offline-labs/README.md).

FastAPI·고정 기능 broker·격리망을 C에 설치하고 기존 A/C 프록시를 전환했다. 기존 Java 컨테이너는 복구용으로 유지했다. 아래 10/19의 공개 Java 화면과 초기 구축 설명은 당시 이력이며, 새 관리 웹은 아래 단일 `deploy.sh`에서 내부 설치기를 자동 호출한다.

정정 후 C native 회귀 **64개**와 최종 HTTP **35개** 검사를 통과했다. 현재4항목·기존 DVWA 독립 주소200/테마 미주입·제거한 DVWA 경로404·실행/중지409, 기본 HMAC 세션·Apache 두 버전의 합성 차단/예외/복원·sudo 준비 상태를 확인했다.

10/22 당시 다중 실습 backend **64개**·공개 HTTPS **31개**·DVWA 예외 경계 **15개**, 합성 검사9건의 WAF→Wazuh alerts→Indexer 전달을 확인했다. 이 결과는 정정 전 구성의 이력이며 현재4항목의 최종 검증 결과로 대신하지 않는다. 실제 취약점 공격·탐지·차단 E2E는 수행하지 않았다. [공식 규칙 후보27개](infra/groot-c/offline-labs/rule-source-candidates.json)는 조사 자료이며 운영에 반영하지 않았다. 현재 단일 초기 설치 경로는 service schema7로4항목 콘솔·웹이미지3개·별도sudo 환경까지 구성한다. 새 VM3대 실제 적용 검증은 아직 미실행이다.

## 통합 SOC 대시보드 — 2026-10-19 생성 완료

학과 VPN에서 **[Groot SOC | 통합 탐지 현황](https://wazuh.grootlab.duckdns.org/app/dashboards#/view/groot-soc-20261019-dashboard)**을 연다. WAF·Suricata·Wazuh 기타 알림의 수치·추이·주요 탐지·출발지·최근 알림을 14개 패널로 표시한다. 기본 최근 7일, 30초 자동 갱신이며 실제 브라우저 표시와 API 재조회를 검증했다. [집계 의미·복원 파일·적용 근거](infra/groot-b/soc-dashboard/README.md). VPN 임시 접근 종료 시각은 아래와 같으며 저장된 대시보드는 유지한다.

2026 capstone project — nftables, Suricata, ModSecurity, Wazuh, Mattermost, Hermes 기반 실습 SOC.

현재 운영 이력은 [STATUS.md](STATUS.md), 진행 계획은 [PLAN.md](PLAN.md)에 있습니다. 날짜별 대화·작업 기록은 로컬 전용 `대화기록/`에 보관하며 Git에는 포함하지 않습니다. 이 문서의 새 환경 구축과 기존 운영 서버의 변경 이력을 구분합니다.

운영 목표는 **LLM을 SOC 관리 주체로 두는 것**입니다. 사건 조사·대응 판단·구체 변경안·승인 요청·결과 확인을 LLM이 맡고, 관리자는 보호된 변경을 승인하거나 거부합니다. 제한된 helper/worker는 허용 범위와 증거를 검증하고 실행합니다. 긴급 임시 선차단도 LLM 판단을 거칩니다. 2026-10-15 관리 경로 전환의 실제 적용·검증 범위는 STATUS의 해당 이력을 따릅니다. 2026-10-23 초기 설치기에는 승인형 운영 경로를 연결했으며, 소스·격리 회귀 검증과 새 VM 전체 설치 검증은 구분합니다. 새 VM 설치 시험은 아직 수행하지 않았습니다.

## 시연용 Wazuh VPN 접속 — 2026-10-20 23:59 KST까지

학과 VPN 연결 후 **[Wazuh Dashboard](https://wazuh.grootlab.duckdns.org/)**에 기존 계정으로 로그인한다. 10/19 22:55 KST 실제 VPN 인증서·로그인·대시보드 상태green과 종료 서비스의403을 검증했다. VPN 임시 허용은 **10/20 23:59:00 KST** 자동 종료되며 기존 학과망 접근은 유지한다. [적용 범위·자동 종료·검증 근거](infra/groot-a/wazuh-demo-access/README.md).

## Log4Shell Java 웹·초기 자동 빌드 — 2026-10-19 완료

기존 C 앱의 JAR·실행 환경을 직접 확인한 기록에서 Spring Boot **2.6.1**, Log4j API/Core 각각 **2.14.1**, Java **8u181**을 확인했습니다. 새 [Spring Boot 실습 웹](infra/groot-c/log4shell-app/README.md)은 화면과 로깅 API를 직접 제공하며, `/log4shell/`에서 입력한 요청 파라미터 또는 헤더를 변경 없이 기록합니다. API는 상태 조회로 받은 CSRF 토큰·쿠키를 사용하는 `POST /log4shell/api/log`이며 이전 앱의 `GET /` 계약과 다릅니다.

당시 초기 설치기는 service **schema6**로 Java JAR을 자동 빌드하거나 준비 JAR을 사용했습니다. 현재 schema7은 검증된 이미지와 통합 콘솔을 구성하며 이 항목은10/19 이력입니다. 기존 운영 C의 Java 웹 교체·정상 요청 검증은19:57 KST 완료했고, 컨테이너 재생성 자동화의 후속 결과는 [STATUS](STATUS.md)에 별도로 기록합니다. 무해한 요청의 응답·로그 확인, 새 VM 구축, 실제 공격·콜백·탐지 E2E는 서로 다른 검증 범위입니다. [이전 PHP 웹의 검증 이력](infra/groot-c/log4shell-ui/README.md)은 당시 결과로 보존합니다.

## 룰 개수·ID 조회 근거 반영 — 2026-10-16 21:00 KST

A/B 조회 실행기에 같은 파일 바이트·SHA로 계산한 집계를 추가하고, **21:00:20 KST** Hermes1.1·일반/관리 정책·현재 참조53개에 반영했습니다. 순수 커스텀 룰 목록·개수 요청은 LLM이 실제 조회한 응답의 원문·SHA와 집계가 일치해야 확정 목록으로 표시합니다. 확인된 **대상 파일 정의는 WAF10개, Suricata14개(로컬12+ET2), Wazuh19개(level0 포함)**입니다. 예비 ID·주석·체인 후속 조건을 별도 규칙으로 세지 않으며 실제 엔진 적재 수나 전체 CRS/ET 개수를 뜻하지 않습니다.

실제 모델 native 시험57.38초·API3회·읽기3회에서 정확한 개수·ID·저장 답변 일치를 확인했고,999개 오류 합성 시험과 플러그인150개 회귀도 통과했습니다. 기존 Hermes 컨테이너만 한 번 재시작한 뒤 **21:02:22 KST** 새 버전 등록·53개 정책 참조·DB·Mattermost/API 연결·heartbeat·timer를 확인했습니다. config·env·cron·다른 DB 내용과 승인 권한을 유지하고 새 패키지·보안 엔진 재시작은 없었습니다. **실제 Mattermost 새 게시·화면 E2E는 수행하지 않았습니다.** 복합 분석·사용자 지정 형식은 이 목록 처리 범위 밖이며 모든 답변의 정확도나 응답 시간을 보장하지 않습니다. [운영 범위](infra/hermes/query-completion/README.md) · [검증 근거](infra/hermes/rule-inventory-validation-20261016.json).

## 조회 실행 보완 적용·답변 정확도 개선 진행 중 — 2026-10-16

> 아래는 20:34의 1단계 당시 기록입니다. 이후 파일 정의 개수·ID 집계는 위21:00 후속에 반영했습니다.

조회를 약속한 뒤 도구 없이 끝나는 응답을 보완하는 1단계를 **20:34:01 KST** 운영 Hermes에 적용했습니다. 현재 세션 정책 참조 53개와 일반·관리용 SOUL을 갱신하고 같은 컨테이너를 한 번 재시작했으며, 20:34:41 Mattermost/API 연결·timer·실제 플러그인 등록을 확인했습니다. 기존 native 파일 8개, `.env`·cron·다른 DB 내용은 보존하고 config에는 플러그인만 추가했습니다. 최초 YAML 사전 검사 실패는 운영 변경 전에 중단했습니다.

최종 native 시험 2건에서 각각 실제 읽기 조회 3건과 최종 답변을 확인했고, 별도 미실행 경로는 조회 실패를 정직하게 안내했습니다. **규칙 개수·예비 규칙·상태 설명의 정확도는 아직 해결 중이며, 사용자 요청에 따라 2단계를 진행하고 있습니다.** 조회 실행 성공을 정확도나 응답 시간 보장으로 해석하지 않습니다. [동작·복구 범위](infra/hermes/query-completion/README.md) · [검증 근거](infra/hermes/rule-query-execution-validation-20261016.json) · [초기 설치기 반영](deployment/README.md).

## 채팅 답변 서식 — 2026-10-16 변경

SOC 채팅 답변은 **요약 → 확인 내역 → 조치 및 다음 단계** 순서를 유지하면서, 확인 내역을 표 대신 `- **대상명**: 상태 — 근거` 목록으로 작성합니다. 승인 안내는 대상·변경 전·변경 후·예상 영향·검증·승인 상태의 여섯 항목을 각각 한 줄에 씁니다. 표는 Markdown 문서·파일 본문이나 사용자가 명시적으로 표를 요청한 경우에만 사용하며, 파일을 제공하는 채팅 안내도 목록으로 씁니다. 승인 카드와 원문 로그·diff는 바꾸지 않습니다.

2026-10-16 19:13:42 KST에 현재 세션52개와 자동 관리용 SOUL에 반영했습니다. 초기 설치기는 같은 서식4개 지침만 복사하며 기존 읽기 전용 역할·MCP2개 권한을 유지합니다. SIEM 회귀31개·정책 갱신 회귀11개와 실제 모델의 합성 상태/승인 사례2개를 통과했습니다. 채팅 게시나 클라이언트 화면 렌더링 시험은 수행하지 않았으며 모든 출력의 서식·정확도를 보장하지 않습니다. [서식·문맥 안내](infra/hermes/mattermost-context/README.md) · [검증 근거](infra/hermes/chat-format-validation-20261016.json).

> 다음은 2026-10-15 최초 표 서식의 당시 기록입니다. 현재 채팅 서식은 위 목록 정책을 따릅니다.

SOC의 조사·상태 답변은 **요약 → 확인 내역 → 조치 및 다음 단계** 순서와 간결한 근거 표를 기본 서식으로 사용합니다. 초기 설치기도 같은 서식4개 지침만 [운영 정책](infra/hermes/SOUL.groot.md)에서 가져오며, 기존 읽기 전용 역할과 MCP2개의 권한은 유지합니다. 원문 구획 검사와 소스 해시 검증이 실패하면 설치를 중단합니다. 라이브 서식은2026-10-15 18:23:59에 반영했고 모델 표본을 확인했으나 모든 답변의 기계적 서식 강제나 정확도 보장은 아닙니다. [채널·스레드 문맥 안내](infra/hermes/mattermost-context/README.md).

## Bash 하나로 초기 설치

SSH·서버 주소·승인된 오프라인 반입물을 준비하고 저장소 루트에서 실행합니다.

```bash
cp deployment/config.example.conf deployment/site.local.conf
# 실제 서버 주소·SSH 경로·HTTPS 이름·허용 내부망·LLM 주소를 편집
bash deploy.sh --apply --batch --config deployment/site.local.conf
```

이 진입점 하나가 **반입물 검사 → 로컬 패키지/이미지 설치 → 역할 사전검사 → SIEM → 공통 키 전달 → service → security → 승인·대응/로그 처리/대시보드 → 전체 검증**을 호출합니다. 패키지·이미지는 인터넷에서 자동 다운로드하지 않고 서버에 반입한 파일만 사용합니다. 전체 저장소가 필요하며 내부 helper를 사용자가 따로 실행하지 않습니다. 향후 서버 변경 시 설치기·반입 목록·설정 예제·검증도 같은 작업에서 갱신합니다.

| 역할 | 초기 구성 |
|---|---|
| SIEM | Wazuh·Indexer·Dashboard, Mattermost/PostgreSQL, Hermes 읽기·승인 MCP, 승인 브로커·관리 경로, 상관관측·통합 SOC 대시보드 |
| service | 독립 DVWA/MariaDB, Lab Console·제한된 broker·nft guard, 웹 실습3개, 별도 sudo rootless·상태 발행, agent |
| security | Suricata·DVWA WAF, Log4Shell TLS·실습 WAF, agent, Vector 정제·회전·보존, 승인 worker·제한된 nft 대응 |

`--plan`은 네트워크 접근 없이 입력만 검증합니다. `--check`는 읽기 검사이며 빈 서버의 미설치 패키지를 보고할 수 있습니다. 기본 `--apply`가 로컬 deb와 이미지 archive까지 설치합니다. `--verify`는 기존 동일 구성만 검사합니다. 기존 운영 서버나 구형 schema6을 자동 덮어쓰지 않습니다.

| 준비·실행 문서 | 내용 |
|---|---|
| [단일 설치 전체 가이드](deployment/bootstrap-guide.md) | 정확한 순서, artifact manifest, 자동 설치 범위, 출력·실패 시 동작 |
| [설정 예제](deployment/config.example.conf) | 서버·HTTPS·허용 CIDR·서버 내 파일 경로 |
| [VM·네트워크·SSH 준비](deployment/setup-network-ssh.md) | 고정 주소·라우팅·키 검증·sudo |
| [패키지·이미지 반입 자료](deployment/setup-packages-artifacts.md) | 외부 Linux 준비 환경에서 공식 패키지·이미지 확보 |
| [Hermes 이미지 준비](deployment/hermes-image.md) | 기반 이미지·가드·의존성·빌드 |
| [실습 소스·이미지](infra/groot-c/offline-labs/README.md) |4항목 카탈로그·3개 웹이미지·차단 예외·테마·독립 DVWA |
| [sudo 초기 준비](infra/groot-c/offline-labs/nonweb/sudo/runtime/BOOTSTRAP.md) | 고정 rootless bundle·서명 검증·초기 구성 |

초기 성공 주소는 `LAB_PUBLIC_ORIGIN/log4shell/`, 독립 DVWA는 `http://SECURITY_HOST:WAF_PORT/dvwa/`, Wazuh는 `https://SIEM_HOST`, Mattermost는 `http://SIEM_HOST:8065`입니다. SIEM `admin` 암호를 Lab Console 차단 예외 키로 직접 연결하며, 원문은 SSH 파이프로 service에 전달합니다. 인증자료는 서버 root 전용 경로에 두며 Git·Mac 임시파일·로그에 기록하지 않습니다.

## 검증 범위와 운영 이식

셸 구문·가짜 SSH 전송 순서·오프라인 반입 검증·service schema7·TLS/WAF 설정·installer 실패 경로·sudo 고정 권한 계약을 회귀 검사합니다. 운영 서버에서 확인한 웹/HMAC/WAF canary/sudo 환경 결과와 새 초기 설치 시험은 구분합니다. **새 Ubuntu VM3대 전체 설치는 아직 미실행**입니다. 구현·격리 회귀를 실제 새 서버 설치 성공으로 표시하지 않습니다.

2026-10-23 설치기 소스에 승인형 쓰기 MCP·브로커·worker·제한된 nft 대응/Native AR, Vector 정제·원본 세대 회전·출력 유지관리·이전 부트 로컬 보관, Indexer 상관관측과 통합 SOC 대시보드를 연결합니다. **실제 새 VM 설치 시험은 사용자 요청으로 제외**했습니다. 위의10/16 읽기 MCP2개 설명은 기본 SIEM 단계의 이력이며, 이번 확장 단계가 승인·대응 경로를 추가합니다. 상세 계약과 검증 한계는 [초기 설치 가이드](deployment/bootstrap-guide.md)를 따릅니다.

다음 범위는 이번 설치기 통합에 포함하지 않습니다.

- 운영망 FORWARD/NAT 정책과 기존 운영 계정·승인 DB·수동 변경 이력 이관
- A→B 이전 로그 전송, 긴 장애 구간 무손실 회수·일반 백업
- DGX/Imperva 고정 주소 예외·정기 보고·실제 CVE 공격과 탐지/대응 E2E
- DNS/공개 인증서 발급·채팅 HTTPS·모바일 푸시·SSL VPN 자체 구축·모델 학습

Suricata는 기본 수동 탐지 모드이며 nft 대응은 LLM 조사·판단과 제한된 실행 경로를 거칩니다. LLM에 일반 sudo/Docker·패키지 설치 권한을 주지 않습니다. 이전 PHP·Java 직접 구동 설명은 각각의 README와 검증 이력에 보존합니다.
