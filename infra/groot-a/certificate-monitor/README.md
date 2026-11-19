# 채팅 인증서 만료 감시·수동 갱신

<!-- bootstrap-clock-gate-20261118 -->
<a id="bootstrap-clock-gate-20261118"></a>

단일deploy.sh의 사전검사에서 호스트 시간대가Asia/Seoul이고 NTP=yes·NTPSynchronized=yes인지 확인한다. 세 호스트의 준비 검사와 각 호스트의 패키지 적용 단계에서 같은 조건을 읽으며 역할별 실행·검증·내보내기 전에도 다시 확인한다. 누락·중복·다른 시간대·NTP 비활성·미동기·조회 실패는 준비 완료로 통과시키지 않는다. 시간·시간대·NTP 설정을 바꾸거나 서비스를 재시작하지 않는다.

역할 실행기의 시각 검사 결과는 표준 출력에 섞지 않는다. CA·등록 자격·키·진단 자료의 기존 파이프 전달 형식을 유지하며 검사 실패 시 뒤의 실행과 출력도 중단한다. 실제 Bash fixture에서 정상인 경우의 불투명한 전송 바이트 보존과 실패인 경우의 빈 출력·후속 실행 중단을 확인했다.

이 검사는 OS가 보고하는 시간 상태의 사전조건이다. 설정한 시간 원본의 신뢰성·절대UTC 정확도·호스트 사이의 오차·장기 동기화까지 측정한 결과가 아니다. 이후 상태가 바뀌면 다음 단계에서 중단될 수 있으며 이미 끝난 작업을 자동으로 되돌리지 않는다. 부분 설치는 기존 영수증과 실제 상태를 확인해 처리한다.

[시각 사전조건·검증 범위](../../../deployment/clock-readiness.validation.json)
<!-- /bootstrap-clock-gate-20261118 -->

<!-- chat-access-readiness-20261118 -->
<a id="chat-access-readiness-20261118"></a>

관리자231에서 채팅의 공개 이름으로443/TLS1.3 연결과 /api/v4/system/ping의200·OK를 확인했다. CA·호스트명 검증을 통과했고 제공 인증서 지문은 A의 저장 관측과 같았다. 다만 이름이192.168.16.230으로 해석됐으므로 관리자 LAN 경로의 결과다. 외부 인터넷·다른 VPN 경로·로그인·봇 대화의 성공으로 확대하지 않는다. 실제 정상 HTTP 요청은1개이며 자격 증명을 보내지 않았다.

관리자 호스트는 NTP=yes·NTPSynchronized=no였고 조회 컴퓨터보다46.486~47.051초 늦었다. 같은 방식으로 읽은 A의 상대 차이는-0.033~0.864초 범위였으며 NTP 동기화 상태는yes였다. 이 범위는 각 SSH 조회의 왕복 시간을 포함한 관측 한계다. 원래 원격 시각과 조회 컴퓨터의 수신 시각을 함께 보존하며 과거 원문 시각을 고쳐 쓰지 않는다.

관리자 timesyncd는 ntp.ubuntu.com을 사용하며 최근12개 journal 표본에 응답 시간 초과를 남겼다. 이 표본만으로 방화벽 차단 원인을 확정하지 않는다. 기존 프로젝트의 학내 시간 서버192.168.16.131에 정상 NTP 요청1개를 보냈고 원래 요청 timestamp와 연결된 응답·stratum3을 확인했다. 서버는 관리자 시계보다47.051976초 앞섰다. A의 실제 chrony도 같은131을 선택했고 Leap status는Normal이었다.

정확 변경안390a0f43은 관리자231의 /etc/systemd/timesyncd.conf.d/90-capstone-campus.conf 파일1개와 기존 timesyncd의1회 재시작만 포함한다. 학내131을 지정하고5분 내 확인하지 못하면 추가한 설정만 원복한다. NTP 보정으로 시계가 약47초 앞으로 이동할 수 있으며 원복 시 시계를 강제로 과거로 돌리지 않는다. 관리자에게 정확 승인을 요청했으며 실제 설정·시각 변경과 운영 NTP 서비스 재시작은 아직 수행하지 않았다.

최종 후보의 쓰기 없는 실물 사전 검사와 격리 파일의 원자 생성·기존 파일 보호, 실제 systemd 타이머·제한된 callback 실행을 확인했다. 첫 callback은 실행됐지만 완료 unit이 자동 정리된 뒤 속성을 확인해 시험이 실패했다. 다음 격리 fixture에만 RemainAfterExit=yes를 추가해 결과를 읽었고 시험 unit과 작업3파일439바이트를 제거했다. 실제 NTP 설정 원복·SSH 단절·재부팅은 검증하지 않았다. 운영 복구 완료로 표시하지 않는다.

[관리자 경로·시각·정확 변경안 원장](access-readiness-20261118.json)
<!-- /chat-access-readiness-20261118 -->

<!-- certificate-bootstrap-20261118 -->
<a id="certificate-bootstrap-20261118"></a>

단일 deploy.sh에 신규 A의 실습용 TLS와 B의 내부 채팅 TLS 감시를 연결했다. 기존 감시기에서 검증한 코어를 재사용하고 공개 인증서 경로·고정 엔드포인트·호스트 machine-id를 각각 결속한다. 실습 도메인과 채팅 도메인은 서로 다른 센서 이름·Wazuh 규칙으로 연결한다. 기존 운영 A의 두 파일과 타이머·인증서는 바꾸지 않았다.

초기 설치의 check는 입력·소스·호스트와 기존 설치 충돌을 검사한다. install은 기존 A lab-edge와 B 내부 TLS가 준비된 뒤, 관리 타이머와 진단 수집을 시작하기 전에 실행한다. 첫 실제 감시 결과가 verified여야 설치 영수증을 남기고 매일09:00 KST 타이머를 켠다. 부분 설치와 영수증·파일 변동은 자동으로 덮어쓰지 않고 중단한다.

A는 설치된 /opt/capstone/security/tls/lab.crt와 실습 프록시 /29의 .3:8443을 사용한다. B는 /etc/capstone-internal-tls/server.crt와 SIEM_HOST:8444를 사용한다. 공개 인증서 파일은 root:root/0444이며 개인키는 감시 서비스에서 접근할 수 없다. CA 신뢰·SAN과 hostname·실제 제공 인증서 지문을 대조한다. 자동 갱신이나 공개 DNS·외부443·HTTP·LLM 가용성까지 확인하는 기능은 아니다.

Wazuh는 capstone-security/실습 도메인과 capstone-siem-host/capstone-siem.internal을 한 쌍씩 검사한다. 100300~100311의12규칙을 기존 초기 규칙과 함께 구성하고 중복 ID를 거절한다. 기존 진단 도구에는 b:certificate-monitor 고정 읽기 대상을 추가했다. 도구 수·일반 명령 권한을 늘리지 않으며 새 대상의 운영 설치는 이번 작업에서 수행하지 않았다.

초기 설치기 연결의 로컬190검사와 Linux 합성52조건·두 역할의 유닛 구문 검사는 기존 근거로 보존한다. 후속으로 B의 기존 Wazuh4.14.8 이미지에서12규칙을 격리 적재하고112사례를 모두 통과했다. 새 검증기의 로컬 경계 검사4개와 기존 인증서 검사15개도 통과했다. 운영 매니저의 컨테이너·시작 시각·설정8파일 지문은 전후 같았다. 새 Ubuntu 전체 설치·운영 룰 적용·실제 경보 전달·독립 재구현은 미수행이다.
<!-- /certificate-bootstrap-20261118 -->

<!-- certificate-rules-native-20261118 -->
<a id="certificate-rules-native-20261118"></a>

기존51사례를 각 역할에 적용하고 센서·도메인 교차, 프로그램명·수집 위치 접미 조건, 메시지 hostname 차이를 추가해112사례를 구성했다. 기대 규칙이 있는54사례는 실제 규칙 ID와 위험도를 대조했고 나머지58사례는12규칙에 매칭되지 않음을 확인했다. 정상·30/14/7일·만료와 TLS 실패를 조합했으며 만료는 A100304/B100310·위험도10을 유지한다. unknown+verified는 원본의 상태 형식 대조이며 실제 정상 관측으로 집계하지 않는다.

시험은 기존 Linux amd64 이미지의 analysisd와 wazuh-db를 별도 컨테이너에서 실행했다. 이미지 다운로드 없이 network none·권한 제한·읽기 전용 입력5개·자원 제한을 사용했다. 기본 internal_options와 CDB6목록은 이미지 안의 공개 기본 파일에서 복원하고 시험 내부에서만 쓰기 권한을 부여했다. 운영 설정·데이터·키·소켓은 시험 컨테이너에 연결하지 않았다. 개인키 읽기·운영 재시작·새 공격·학습·모델 호출·채팅은0이다.

첫 전체 실행은44사례 통과 후85초 제한으로 끝났다. 그때까지 규칙 불일치는 없었고 시험 컨테이너와 파일을 제거했다. 제한을360초로 정정한 뒤 PID·시작 tick·boot ID와 실제 컨테이너를 추적했고 같은112사례를213.596초에 완료했다. 두 실행의 공통44사례를 중복 합산하지 않는다. 최종 엔진 시작의 오류·경고는0이며 시험 컨테이너와129파일251412바이트의 작업 경로를 제거하고 부재를 확인했다.
<!-- /certificate-rules-native-20261118 -->


검사 도구의 범위: [systemd255 유닛 검증](https://www.freedesktop.org/software/systemd/man/255/systemd-analyze.html) · [Wazuh 공식 로그 시험](https://documentation.wazuh.com/current/user-manual/reference/tools/wazuh-logtest.html).

## 현재 수정 후보와 운영 상태

<!-- certificate-scheduled-followup-20261119 -->
11/19 09:00 KST의 기존 인증서 감시 예약 실행을 확인했다. 서비스는 exit0/verified로 종료됐으며 상태 파일과 journal의 실행 식별자·인증서 지문이 일치했다. 메인 프로세스의 시작부터 종료까지는0.634134초였고 기존 실행파일·service·timer·공개 인증서4파일의 SHA는 승인된 적용본과 같았다. 타이머는 enabled/active이며 다음 예약은11/20 09:00 KST다.

관리자231 경유 A 관측과 B의 기존 mcp 계정에서 수행한2읽기를 대조했다. 현재 MCP의 시작·종료 단조 시각과 종료값이 A와 같았고08:59~09:02의 실제 journal은4표본을 반환했다. verified 이벤트의 원문 해시도 A의 같은 이벤트와 일치했다. 현재 스냅샷의 journal_status=unavailable·오류 건수null은 보존하며 별도 실시간 journal 표본과 구분한다. has_more=false도 전체 보존 이력이나 오류 부재를 증명하지 않는다.

이번에는 기존 예약 실행을 읽었으며 감시기를 수동 실행하거나 서비스·인증서·설정을 바꾸지 않았다. 새 TLS/HTTP 요청·개인키 읽기·모델 호출·봇 게시·공격·학습은0이다. 한 차례 예약 실행의 결과이며 장기 안정성, 외부 인터넷/DNS/443/HTTP, 새 봇 응답과 새 OS 전체 설치·운영12규칙 경보 전달은 별도다. 관리자 NTP390a와 응답 MCP1.2.1의 정확 승인 대기도 유지한다.

[예약 관측·MCP 대조·한계](readiness.validation.json)
<!-- /certificate-scheduled-followup-20261119 -->

첫 읽기에서 timedatectl에 쉼표로 묶은 속성 이름을 넘겨 출력이 비었다. 명령의 종료0만으로 시간 상태를 확인했다고 표시하지 않고 --property를3번 명시한 별도 읽기에서 Timezone=Asia/Seoul·NTP=yes·NTPSynchronized=yes를 확인했다. 이는09:48의 OS 보고 상태이며 절대UTC 정확도나09:00 당시 동기화 상태의 별도 측정이 아니다. 관측 스크립트의 가정만 바로잡았고 운영 감시기는 수정하지 않았다.

관리자231 경유로 정확 계획10a9be42f4bb316c8a6669ea598705ed88b9e19b34e5e38078bf2f76a759b9f7의 두 파일을 적용하고17:13:01 KST에 확정했다. 11/18 적용 직후 run은exit0/verified이며 상태·journal의 인증서 지문이 일치한다. 5분 독립 원복은 해제했고 원본·후보·제어기는 root 전용 복구 위치에 보존했다. 프록시와 인증서·개인키·매일09:00 KST 타이머는 바꾸지 않았다.

적용 전 11/18 09:00의 상태는 expiry_status=ok·probe_status=unavailable·reason=tls_timeout이었고 기존 MCP 검색에서 규칙100305의09:00:12.292 KST 경보1표본이 반환됐다. 이 과거 경보를 삭제하지 않으며 전체 구간 건수로 표현하지 않는다. A의 failed unit0·과거 Result=success/exit2는 인증서 검증 성공과 달랐다.

| 확인 | 실제 결과 |
|---|---|
| 운영 전체 cm_main/check를 격리 복제 | 10.3972초·tls_timeout 재현 |
| 후보 전체 cm_main/check를 격리 실행 | 0.472초·CA/hostname/SNI·leaf 지문 일치 |
| 기존 만료·오류·파일 보호 회귀 | Linux root26개 통과 |
| 적용·부분 실패·확정·원복 | Linux root14개 통과, 서비스 제어는 모의 |
| 실제 독립 타이머 | 발행 프로세스 종료 뒤 격리 파일2개 복구 |
| 실제 운영 적용 | 실행파일·service2개, oneshot1회·exit0/verified,17:13:01 확정 |
| 기존 MCP | 실제 설치 계정mcp에서 현재 상태와 journal4표본 확인 |
| 보호 범위 | 프록시 ID/시작 시각·인증서·타이머 SHA 유지, 개인키 읽기0 |

후보는 compose에 고정된172.18.0.3:8443을 조회하고 서비스에는 loopback 외 그/32만 허용한다. 인증서·개인키·프록시·공개 포트·매일09:00 KST 타이머·MCP·모델은 바꾸지 않는다. 이 검사는 프록시의 인증서 관측이다. 공개443·DNS·HTTP 가용성을 별도로 확인해야 한다. 기존 일회성 TLS 직접 연결의 약0.03초와 전체 entry의0.472초는 측정 범위가 다르며 채팅 응답 시간과 관계없다.

### 고정 호스트의 수동 적용과 복구

[rollout.py](rollout.py)는 수동 변경 제어기이며 기존 A의 두 파일에만 결속돼 있다. 새 MCP 도구나 LLM의 일반 root 권한을 추가하지 않는다. prepare가 원본·후보·자기 소스 SHA와 정확 계획을 root 전용 위치에 보존한다. apply의 approved-plan 인자는 계획 일치 검사이며 관리자 인증이나 승인 카드의 대체 수단이 아니다. 신뢰된 관리자가 별도의 정확 승인을 받은 뒤 관리자231 경유로 실행한다.

적용 직전 원본 SHA·소유권·모드·보호 파일과 감시기 inactive 상태를 확인한다. 먼저 A에5분 독립 원복 타이머를 활성화하고 두 파일을 원자적으로 교체한다. systemd 설정을 다시 읽고 감시기 oneshot만 한 번 실행한다. 신선한 verified 상태·exit0·실제 journal·MCP/보고를 확인한 뒤 기한 안에 confirm으로 확정한다. 미확정·부분 교체·연결 단절에서는 원복기가 두 원본만 복원한다. 이후 상태는 새로 관측해야 하며 과거 verified JSON을 현재 검증으로 승계하지 않는다. 나중의 다른 변경과 충돌하면 덮어쓰지 않고 실패를 남긴다. 복구본은 보존한다.

[check-native.py](check-native.py)는 root 소유의 고정 후보를 bind mount로 격리해 check만 실행한다. 운영 run이나 journal 발행을 하지 않는다. 상태 디렉터리는 사설 복사본이며 transient unit과 이번 임시 파일은 정리했다. 이 check 재현기는 적용 전 고정 SHA를 요구하므로 적용 후에는 운영 전제조건 변경으로 거절한다. 실제 SSH 단절·다음09:00 예약 실행·새 GUI 검수는 하지 않았다. 운영 run은 위 별도 절차로 확인했다.

### 실제 채팅에서 남은 오류

새 SDK 채팅은43.783초에 게시됐으나 성공으로 집계하지 않았다. a:certificate-monitor의 진단 조회는 성공했다. 이후 get_wazuh_agents:active를 추가 조회하고 최종 응답을 에이전트 ID·연결 상태 표로 대체했다. 실제 실행2읽기·보호된 변경0이며 기존 진단 MCP 기능 자체의 부재가 아니다. 공통 보완/출력 대상 선택의 정확 원인은 별도 재현·Harness²·회귀·새 채팅으로 수정한다.

직접 MCP 재검사의 첫 실행은 실제 설치 계정과 맞지 않아 unavailable을 반환했다. 존재하지 않는 capstone-mcp 계정으로 재시도했으나 역시 실패했다. 설치 계정mcp를 확인한 뒤 같은 도구로 성공했다. 이 두 시험 실패는 원문에 보존하며 첫 root 실행의 세부 원인을 단정하지 않는다. 현재 snapshot의 journal_status=unavailable과 별도 live journal4표본을 구분하며 오류 부재로 바꾸지 않는다.

### 초기 설치와 분리할 조건

기존 고정 감시기의 A machine-id·경로·채팅 도메인은 보존한다. 이식 소스는 단일deploy.sh에서 신규 A 실습 웹과 B 내부 채팅의 서로 다른 인증서·엔드포인트·센서에 결속했다. 소스 연결과 격리 엔진 검증을 마쳤으며 실제 새 OS 설치와 후임자의 독립 재구현은 남았다. 추가 패키지·이미지·포트·키는 도입하지 않았다.

[새 검증 원장](readiness.validation.json) · [이전 격리 검증](validation-2026-11-17.json) · [현재 상태](../../../STATUS.md).

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../STATUS.md) · [실행 계획](../../../PLAN.md).
> A는 외부/내부 관문이며 Suricata는 passive IDS다. DVWA의 DetectionOnly와 실습 HTTP 경로의 WAF 차단/요청별 예외를 구분한다. 이번 TLS 조회의 세 HTTPS 이름 만료는2027-01-13 13:25:12 KST이며 과거 인증서 값은 이력이다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

**2026-10-15 14:33:38 KST 공용 인증서 적용:** Mac의 일회성 private 환경에서 발급한 Let's Encrypt `*.grootlab.duckdns.org` 와일드카드 인증서 한 장을 A의 `chatduck.crt/key`에 설치하고 Nginx를 한 번 재로드했다. SAN은 채팅과 Log4Shell DuckDNS 이름을 모두 포함하며 만료는 **2027-01-13 13:25:12 KST**다. Mac 시스템 CA 검증을 켠 `curl`로 채팅 ping 200과 Log4Shell HTTPS의 `/dvwa/login.php`→`/log4shell/` 최종 200을 확인했다. A 감시기의 수동 실행도 `Result=success`·exit0으로 새 파일과 채팅 SNI를 검증했다. 배포 전 인증서는 A `/var/backups/capstone-log4shell-tls/20261015T143336+0900`에 보존했다. 아래 10:49 라이브 확인의 만료일은 **교체 전 채팅 단일 이름 인증서**의 이력이다. 감시기는 공유 파일 `chatduck.crt`의 만료일·지문을 매번 읽지만 `log4shell.grootlab.duckdns.org`의 SNI·경로는 주기 검사하지 않으므로 배포·갱신 때 별도로 검증한다. 자동 갱신은 없고 **2026년 12월 중순 재발급 준비**가 현재 일정이다.

**2026-10-15 10:49 KST 후속 확인:** 오늘 **09:00:00 KST 예약 실행·exit0**와 09:00:01의 `ok/verified` journal 1건, 같은 상태파일을 대조했다. 다음 예약은 10월 16일 09:00 KST다. 10:48:58 실제 TLS도 CA·hostname·제공 인증서 fingerprint 검증을 통과했고, 만료는 **2027-01-06 15:02:33 KST**로 동일하다. [A 실측](followup-a-2026-10-15.json).

B 설치 decoder/규칙 SHA는 유지됐고, 최근24시간 agent001의 인증서 규칙100300~100305 경보는0건이었다(60/60 shard 성공, timeout/부분결과 없음). 정상100300은 level0/no_log이므로 이 결과는 예상되며, **실제 경고의 원격 전달·색인 완료를 입증하지는 않는다.** 합성 경고 주입·인증서 교체·개인키 읽기·서비스 재시작은 없었다. [B 실측](followup-b-2026-10-15.json). 자동 갱신은 미구성이며 아래 12월 초 수동 갱신 계획을 유지한다. 다음 본문은 이전 시점 기록이다.

**2026-10-15 04:51:02 KST — A 설치·첫 관측 완료.** 고정 A에서 Linux root 합성 **26개**, 설치 전 실제 localhost TLS 검증, 설치 후 oneshot 관측이 모두 통과했다. 설치된 OpenSSL3.0.13이 CA·hostname을 검증했고 제공 중 leaf와 공개 인증서 fingerprint가 일치했다. 현재 만료는 **2027-01-06 15:02:33 KST**다.

- `/usr/local/sbin/capstone-cert-monitor` root0500과 두 systemd unit root0644를 설치했다. `/var/lib/capstone-cert-monitor/status.json`은 root0600이며 `expiry_status=ok`, `probe_status=verified`를 확인했다. 상태 SHA는 `1dfc989b514755c0e798af62a155468b3dd5c0a138b990f655586266c2642f36`이다.
- `capstone-cert-monitor.timer`는 **enabled/active**, 매일 **09:00 KST**, `Persistent=true`다. 이번 성공은 수동 첫 oneshot이며 **09:00 예약 실행은 아직 관측하지 않았다**.
- 공개 인증서 파일 SHA `0babec3a5fab7273df7b5a3be60346510e64db9656d52580fad35f2c2e8dd54a`는 전후 동일했다. 개인키 읽기·자동 재발급·다른 서비스 재시작은 0회다. 배포 소스·시험·상태와 영수증은 A의 `/var/backups/capstone-certificate-monitor-20261015/`에 보존했다.
- 운영 감시기 SHA는 `91c0ed1025beb3f7bbc59ec38b58c705add1637c8e5c69216eb489d62e65a540`, 일회성 배포 controller SHA는 `e5e7dae2e699987e11efa9c936be9fef89192ea785286ed2ba2051b109db96d8`이다.
- **B는 2026-10-15 04:59:47 KST에 전용 decoder·규칙 설치와 manager 재시작 1회를 완료했다.** native 합성 51개와 재시작 후 실제 A 상태 JSON을 사용한 logtest 1건이 통과했다. 후자는 `capstone_certificate_json` → `100300/level0`이며 정상 상태를 경보로 발행하지 않았다. 실제 만료 경보의 운영 종단 시험과 09:00 예약 실행은 아직 확인하지 않았다. 아래 B 기록에서 시험 범위와 초기 실패 이력을 구분한다.

**초안 작성 시점의 기록(아래 미배포 문구는 설치 전 상태):**

이 폴더는 **2026-10-15 작성한 미배포 후보**다. 운영 인증서·서비스는 변경하지 않았다. 새 패키지나 상주 수집기 없이 A의 Bash, OpenSSL, GNU coreutils, jq, logger, flock, systemd를 사용한다. 마지막 인증서 단계에서 부모 운영자가 실제 A의 파일 메타데이터와 바이너리 호환성을 확인한 뒤 배포한다. Wazuh 경보 연결·실제 주기 실행은 아직 검증하지 않았다.

대상은 `chat.grootlab.duckdns.org` 하나다. 읽는 파일은 `/home/groot_a/capstone/chatproxy/tls/chatduck.crt`(root:root,0644,regular,nlink1,최대64KiB), 연결은 SNI를 지정한 `127.0.0.1:443` 한 곳이다. 개인키·Docker socket·HTTP·모델·MCP·채팅·ACME API에는 접근하지 않는다. 기존 파일의 실제 소유·권한이 이 계약과 다르면 배포 전 확인하며 검사 조건을 조용히 완화하지 않는다.

## 검사와 결과

`monitor.sh`를 `/usr/local/sbin/capstone-cert-monitor` root:root0500으로 설치하는 계약이다. 공개 CLI는 `check|run`뿐이며 고정 A machine-id와 실행 파일·부모 권한을 확인한다. 전체 작업은 clean environment의 `timeout 29s` 및 1초 후 강제 종료로 제한하고, TLS 연결 자체는 10초+1초다. systemd도 `TimeoutStartSec=30s`, `TimeoutStopSec=1s`를 둔다. 커널의 중단 불가능 I/O까지 절대 30초 완료를 보장하는 뜻은 아니다.

1. 공개 인증서를 bounded snapshot으로 읽고 symlink·권한·파일 identity/size/mtime/ctime의 전후 일치를 검사한다.
2. DNS SAN과 hostname, notBefore/notAfter를 확인한다. 실제 `openssl x509 -checkend`로 **0/7/14/30일**을 순서대로 검사해 `expired`, `within_7_days`, `within_14_days`, `within_30_days`, `ok` 중 하나를 기록한다.
3. `openssl s_client -verify_return_error -verify_hostname`과 호스트 CA 파일로 TLS를 검증한다. 파일의 leaf DER SHA-256 fingerprint와 제공된 leaf fingerprint도 일치해야 `probe_status=verified`다. CA 오류·접속 실패·timeout·형식 오류는 `unavailable`, 서로 다른 인증서는 `mismatch`다. 인증서 만료가 이미 확인됐다면 TLS 실패가 그 `expiry_status=expired`를 지우지 않는다.
4. JSON에는 관측 KST/UTC, 고정 도메인, 상태·고정 원인 코드, 만료 KST/epoch·남은 초, 두 fingerprint만 있다. KST 문자열은 명시적 `+09:00`이며 같은 epoch와 대조한다. 원래 인증서의 UTC 유효기간은 바꾸지 않는다. 인증서 원문·진단 원문·개인키는 출력하지 않는다. `certificate_sha256`은 PEM 파일 SHA가 아니라 leaf DER fingerprint다.

`run`은 `/var/lib/capstone-cert-monitor` root0700의 `status.json`을 root0600으로 원자 교체·fsync하고 같은 JSON을 stdout과 `capstone-cert-monitor` journald 태그로 보낸다. unit은 stdout을 버려 explicit logger와 중복 journal을 만들지 않는다. `check`는 JSON stdout만 내며 상태파일과 journal을 갱신하지 않는다(잠금 및 private scratch는 사용). `.lock`으로 중복 실행을 막으며 scratch는 정상/오류 종료 때 정리한다. SIGKILL·전원 장애로 남은 private scratch는 다음 성공을 뜻하지 않는다.

검증 성공은 rc0, 관측 불가·불일치는 JSON을 저장한 후 rc2, 잠금 충돌은 rc75다. unit은 2/75를 예상 결과로 허용한다. 외부 timeout·프로세스 오류·저장 실패는 새 status를 보장하지 않으므로 **status.json의 시각과 timer/서비스 결과도 함께 확인**해야 한다. 옛 `ok`를 현재 정상으로 해석하지 않는다. 30일·14일·7일은 운영 알림 경계이며 인증서 자동 교체를 시작하지 않는다.

```sh
sudo /usr/local/sbin/capstone-cert-monitor check
sudo systemctl start capstone-cert-monitor.service
sudo journalctl -t capstone-cert-monitor --since '-2 days' -o cat --no-pager
sudo systemctl list-timers capstone-cert-monitor.timer
```

타이머는 `OnCalendar=*-*-* 09:00:00 Asia/Seoul`, `Persistent=true`다. 호스트가 꺼져 있던 예정 실행은 다음 활성화 때 보충될 수 있다. 서비스의 네트워크는 loopback IPv4만 허용하고 개인키 경로는 가린다. 기존 Vector maintenance/rotation에는 연결하지 않는다. B의 전용 규칙은 아래와 같이 설치·native 검증했으며, 정상 상태는 `no_log`다. 예약 실행부터 실제 경보 수신·색인까지는 별도 관측 범위다.

## B Wazuh 검증·설치 기록

**2026-10-15 04:59:47 KST 기준:** [전용 decoder](capstone_certificate_decoders.xml)와 [규칙](capstone_certificate_rules.xml)의 v3 native **51개 PASS** 뒤 같은 manager 컨테이너를 1회 재시작했다. 새 init PID는 `2267662`, analysisd PID는 `2268440`이며 필수 4종 프로세스 running, 기존 보호 파일 SHA 불변, A agent `001` Active를 확인했다. 재시작 후 실제 A의 정상 status를 PID 없는 프로그램명 형식으로 넣은 logtest도 전용 decoder와 `100300/level0`에 일치했다. 이는 실제 상태의 분류 확인이며 운영 입력에 합성 경보를 주입하거나 실제 만료 인증서의 종단 경보를 검증한 결과는 아니다.

설치 대상은 manager의 `/var/ossec/etc/decoders/capstone_certificate_decoders.xml`, `/var/ossec/etc/rules/capstone_certificate_rules.xml` 두 파일이다. B 호스트의 같은 파일은 `/var/lib/docker/volumes/single-node_wazuh_etc/_data/{decoders,rules}/` 아래에 있다. decoder 이름은 `capstone_certificate_json`, program은 정확히 `capstone-cert-monitor`, location은 정확히 `(groot-sec) any->journald`다. 도메인·schema와 canonical 13개 키도 검사한다. program/location 조건은 서명된 출처 증명이 아니다. 유효기간·fingerprint 판정은 A 감시기가 수행하고 B 규칙은 그 결과를 등급에 연결한다.

| 조건 | 규칙 | level |
| --- | --- | --- |
| `ok` + `verified` | `100300`, `no_log` | 0 |
| `within_30_days` + `verified` | `100301` | 3 |
| `within_14_days`, 허용된 모든 probe 상태 | `100302` | 5 |
| `within_7_days`, 허용된 모든 probe 상태 | `100303` | 7 |
| `expired`, 허용된 모든 probe 상태 | `100304` | 10 |
| `ok`/`within_30_days`/`unknown` + `mismatch`/`unavailable` | `100305` | 5 |

따라서 TLS 관측 실패가 7일 이내·만료 경보를 level5로 낮추지 않는다. 감시기가 생성하지 않는 `unknown` + `verified` 조합은 native 음성 경계로 검사했으며 base level0에 남는다고 해서 정상 관측으로 인정하지 않는다. 경보 leaf에는 `ignore=900`, `no_email_alert`, `no_full_log`가 있다. 51개에는 상태 조합, 다른 program/location, 추가·누락·중복 키와 잘못된 JSON 형식 거절이 포함된다.

초기 두 시도는 실패 소스·로그를 보존하고 추가한 파일을 자동 제거했으며 manager 재시작은 하지 않았다. 첫 시도는 program이 있는 syslog JSON에 기본 JSON decoder가 선택되지 않아 전용 `JSON_Decoder`를 추가했다. 두 번째는 Wazuh의 native XML 처리에서 `&gt;`가 location의 `>`로 변환되지 않아 일치하지 않았다. v3는 location 원문을 literal `>`로 고정해 51개 전체를 통과했다. 이 실패 이력은 최종 성공으로 덮어쓰지 않는다.

최종 소스 SHA-256은 decoder `3a7d37d2ce9979da70b196b17adcfed9f33285bb604979c2e7416b7a3c5d281c`, 규칙 `40dc486283cd5dc9e5aaf57bc79ed78be233528c44375914ea2620d31dc1df2d`, [시험](test-certificate-rules.py) `6444e7946b671528ff7d7e263ff5d576e984f4fb082c4207066e9af1da1906f2`다. **실제 만료 경보 종단 확인과 09:00 예약 실행 관측은 남아 있다.**

## 수동 갱신

**2026-10-15 A의 새 읽기 관측에서 현재 공개 인증서 만료를 2027-01-06 15:02:33 KST(+09:00), 즉 06:02:33 UTC로 재확인했다.** 이는 [2026-10-08 DNS 발급 기록](../../dns/README.md#채팅-인증서-배포-2026-10-08-라이브-직접-확인)과 같다. 해당 배포 전 읽기 관측 자체는 native 시험·배포 완료 증거가 아니었다. 이후 설치 결과는 맨 위 04:51:02 KST 기록을 따르며 정기 검사는 매일 **09:00 KST**다. A의 ACME/DuckDNS 외부 HTTPS 제한과 Mac 발급 상태 삭제 때문에 자동 갱신은 구성돼 있지 않다. 2026년 12월 초에 갱신을 준비하고, 경고가 없더라도 만료 전에 완료한다.

위 만료일과 12월 초 일정은 **와일드카드 배포 전 채팅 단일 이름 인증서** 기준이다. 10/15 배포 이후 현재 갱신 대상은 `*.grootlab.duckdns.org`, 만료는 **2027-01-13 13:25:12 KST**, 재발급 준비는 **2026년 12월 중순**이다. 감시기는 새 파일의 만료를 읽지만 Log4Shell SNI 검증으로 범위가 확대되지는 않는다.

1. 접근 가능한 관리자 장치의 **일회성 private 임시 환경**에서 DuckDNS DNS-01 절차로 `*.grootlab.duckdns.org` **와일드카드 단일 이름** 인증서를 새로 발급한다. 채팅·Log4Shell 개별 SAN을 같은 ACME 주문에 넣지 않는다(DuckDNS TXT 공유). Mac의 이전 ACME 계정·발급 상태는 삭제되므로 남은 상태를 전제로 `--renew`만 실행하지 않는다. 당시 공식 ACME 소스/CA 동작을 다시 확인하며 Homebrew 설치·영구 ACME 상태·무인 SSH 자격증명은 추가하지 않는다. 토큰·개인키는 출력하거나 저장소에 넣지 않는다.
2. `fullchain.pem`과 암호 없는 `privkey.pem`을 A의 root0700 임시 디렉터리로 전송한다. 기존 [deploy_chatduck_cert_A.sh](../deploy_chatduck_cert_A.sh)의 `--check-only`를 먼저 실행한다. 이 검사는 DNS SAN/hostname, 만료까지 24시간 초과, 중간 인증서를 포함한 체인, 키 일치 및 호스트 CA 신뢰를 요구한다. `--check-only`는 Docker나 운영 TLS 파일을 변경하지 않는다.
3. 현재 `chatproxy` CID와 `/etc/nginx/tls` bind가 `/home/groot_a/capstone/chatproxy/tls`를 가리키는지 확인한 뒤 같은 스크립트를 root로 실행한다. 아래 경로는 실제 root private 전송 경로로 바꾼다.

   ```sh
   sudo bash infra/groot-a/deploy_chatduck_cert_A.sh --check-only /ROOT_PRIVATE/fullchain.pem /ROOT_PRIVATE/privkey.pem
   sudo bash infra/groot-a/deploy_chatduck_cert_A.sh /ROOT_PRIVATE/fullchain.pem /ROOT_PRIVATE/privkey.pem
   ```

   배포기는 현재 nginx 설정을 검사하고, TLS 디렉터리의 `.chatduck-backup.<시각>.<고유값>/`에 기존 인증서·키를 각각0600으로 보존한다. 새 인증서0644·키0600을 파일별 rename으로 교체한 뒤 `nginx -t`와 reload를 실행한다. 제공 SNI leaf fingerprint 및 **CA 검증을 켠 Mattermost `/api/v4/system/ping`**까지 통과해야 성공한다. 감시기는 이 배포기를 자동 호출하지 않는다.
4. 교체 후 실패하면 배포기의 EXIT/HUP/INT/TERM 처리에서 백업 두 파일 복원과 nginx 구문 검사·reload를 시도한다. rollback reload 경고가 나오면 즉시 `chatproxy`를 확인한다. 성공 후 수동 복원이 필요하면 출력된 정확한 백업 디렉터리의 `chatduck.crt`·`chatduck.key`를 위 배포기의 입력으로 사용해 `--check-only`부터 다시 수행한다. 이전 인증서도 24시간 초과 유효기간과 CA 신뢰 검사를 통과해야 한다. 복원 시도 메시지만으로 제공 인증서 복구를 판정하지 말고 SNI fingerprint와 HTTPS ping을 다시 확인한다.
5. 감시기가 설치된 뒤에는 `capstone-cert-monitor check`의 `verified`, 기대 fingerprint·만료일도 확인한다. 공유 인증서를 제공하는 Log4Shell HTTPS의 SNI·CA 검증·HTTP 경로는 별도로 확인한다. 감시기는 채팅 이름 하나만 주기 검사하며 Log4Shell vhost 장애를 감지한다고 해석하지 않는다. 임시 발급·전송 자료는 정리하고 서버 백업과 비밀 없는 검증 메타데이터는 보존한다. Wazuh 및 내부 별칭의 별도 인증서는 이 절차에서 바꾸지 않는다.

기존 배포기는 컨테이너 이름 `chatproxy`를 사용하며, 고정 CID CAS나 두 파일을 묶은 원자 교체·fsync 기반 crash 복구를 제공하지 않는다. 실행 중 다른 인증서 배포를 겹치지 않게 하고 SIGKILL·호스트 중단 뒤에는 현재 파일·백업·실제 제공 인증서를 확인한 후 복구한다. 이 한계는 이번 감시 후보로 바뀌지 않는다.

## 합성 검증

```sh
bash test-monitor.sh /ABS/certificate-monitor/monitor.sh /EXISTING/PRIVATE/TEMP
```

기존 OpenSSL로 private EC 인증서를 생성해 31/30/15/14/8/7일, 만료·미래·다른 SAN·CN만 있는 인증서·형식 오류를 검사한다. TLS transport만 모의 응답으로 바꾸어 정확한 검증 옵션, 실패·timeout·다른 fingerprint·읽는 중 변경을 검사한다. OpenSSL의 CA/hostname 검증도 실제 합성 인증서로 확인한다. Linux root에서는 추가로 실제 flock/fsync/rename·status 권한·check의 비게시·scratch 정리·symlink 거절을 시험한다. 모의 TLS는 실제 A TLS handshake 성공의 증거가 아니다.

**배포 전 로컬 기록:** 2026-10-15 기존 OpenSSL3.6.4/GNU coreutils를 사용한 **22개 PASS**, Bash 구문 PASS였다. 이 시점에는 Linux root 전용 4개와 실제 A handshake·systemd timer를 아직 실행하지 않았다. 임시 합성 키/인증서/출력은 시험 finally에서 제거됐으며 새 패키지·운영 파일 접근·네트워크 연결은 0이다.

**A native 보완과 최종 결과:** 첫 후보는 A OpenSSL3.0.13에서 8개 통과 뒤 `wrong_hostname` 시험이 실패해 설치 전에 중단됐다. 이 버전의 `x509 -checkhost`는 `does NOT match certificate`를 출력하면서 rc0을 반환했다. v2는 DNS SAN 존재·rc0·정확한 `Hostname chat.grootlab.duckdns.org does match certificate` 문구를 모두 요구한다. 실패 소스/로그는 보존했으며, v2의 기존 **26개 전체 PASS** 뒤 실제 TLS와 설치를 진행했다. 실제 TLS 성공은 모의 transport 시험과 별도로 확인한 결과다.

옵션 근거: [OpenSSL3 s_client](https://docs.openssl.org/3.0/man1/openssl-s_client/)의 검증 오류 반환·hostname 검증, [OpenSSL3 x509](https://docs.openssl.org/3.0/man1/openssl-x509/)의 `-checkend`/fingerprint/SAN 출력.


<!-- service-query-20261118 -->

현재 상태만 묻는 짧은 요청과 호스트만 답하는 후속 요청을 같은 공통 계약으로 처리한다. 현재 조회에는 필요한 실제 읽기만 사용하고 요청하지 않은 journal을 추가하지 않는다. 모호한 대상은 확인하며 과거 수치·판단·승인을 새 근거로 이어받지 않는다. 운영10소스·영수증1개와 새8요청/6읽기를 확인했다. 기존 단일 deploy.sh의 복사·영수증 경로를 유지하며 새 패키지·포트·키·일반 권한은 없다. [동작·재현·한계](../../hermes/service-query-contract.md) · [실제 검증](../../hermes/query-completion/service-catalog.validation.json).
<!-- /service-query-20261118 -->


<!-- service-cause-candidate-20261119 -->

복합 원인 조사에는 별도 실패가 남아 있다. SDK 필수 조회 연결 후보는3반례와 회귀833검사·Linux 공식38/설치37검사를 통과했지만 실제 격리 실행에서 최종 보고가 수용되지 않았다. 후보 검증과 운영 적용을 구분하며 해당 후보를 배포하지 않는다. [원인·수행·미완료](../../hermes/service-query-contract.md) · [실제 실패·후보 검증](../../validation/service-query/cause-completion.validation.json).
<!-- /service-cause-candidate-20261119 -->


<!-- service-report-provenance-candidate-20261119 -->

이번 서비스 보고 후보는 실제 품질 검증을 통과하지 못해 운영에 적용하지 않았다. 서비스 현재 조회의 기존 확정 결과는 유지한다. 원인·이력 조사는 현재 수집본과 실제 journal을 함께 읽으며 자동 선택한 최근 구간을 초기 확인 범위로 표시한다. 보고에서 근거를 넘는 문장을 제외하더라도 원래 판단·검토 상태와 조회 범위 안내를 유지한다. 모델·MCP·권한·보호 주소·승인·차단 TTL은 이번 보완의 변경 대상이 아니다. [검증·미적용·남은 문제](../../validation/service-query/report-provenance.validation.json) · [공통 동작](../../hermes/service-query-contract.md).
<!-- /service-report-provenance-candidate-20261119 -->
