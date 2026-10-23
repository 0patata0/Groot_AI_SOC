# 팀원 접속 안내 — Groot SOC (2026-10-15 갱신)

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](STATUS.md) · [실행 계획](PLAN.md).
> 현재 구성은 A/B/C 역할 분리·MCP6서버·HTTP3/터미널3·단일 deploy.sh(service schema9)다.6CVE 공격·탐지 시험은 사용자 지시로 보류하고 LLM 진단/알림 실패 보완과 문서 정리를 우선한다. 실제 검증 범위와 새 서버 설치 제외를 함께 확인한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

> PC 에 아무 설정(hosts, ssh config)도 하지 않고 들어오는 방법. 학과 내부망(유선/무선)과 VPN 모두 해당.
> 계정·비밀번호는 팀장에게 직접 받는다(문서에 적지 않음).

**모바일 푸시 작업 마무리(10/13 사용자 요청):** 로그인·채팅은 정상이며 A/B 준비 설정과 `SendPushNotifications=false`를 유지한다. 추가 활성화·수신 검증은 보류했으며 푸시 복구 완료가 아니다. 서버 설정·타이머는 변경하지 않았다. 외부 통신 가능한 허용 경로를 확보하고 사용자가 재개를 요청하면 연결 검사→활성화→실제 Android·iOS 알림 수신을 검증한다.

**추후 발전과제 지정(2026-10-13 후속 사용자 결정):** 프로젝트 SSL VPN 원격접속과 모바일 푸시 알림 복구는 현재 완료 범위에서 제외하고 추가 작업을 보류한다. 프로젝트 VPN은 미구축이며 학교 GlobalProtect와의 이중 SSL VPN은 구조상 가능하지만 현재 환경의 동시 연결 호환성은 실측하지 않았다. 사용자는 학과망의 폐쇄적 정책으로 호환되지 않을 가능성을 들어 보류했다. Android·iOS 로그인·채팅 성공은 앞선 사용자 확인이며 푸시 성공을 뜻하지 않는다. 기존 A/B 설정·타이머와 `SendPushNotifications=false`를 유지하며, 상위 방화벽은 프로젝트에서 직접 변경할 수 없다.

## 웹
| 서비스 | 주소 | 비고 |
|---|---|---|
| 채팅(Mattermost) | `https://chat.grootlab.duckdns.org` | 데스크톱 앱은 "서버 추가" 에 같은 주소. SOC 알림·`/soc` 명령이 여기서 돈다 |
| 관제 대시보드(Wazuh) | `https://wazuh.grootlab.duckdns.org` | **학과망·현장 PC 에서만**. VPN 은 정책상 차단(403) |
| 웹 표적(DVWA) | `http://dvwa.grootlab.duckdns.org` | A 의 WAF 를 거쳐 C 로 간다. 공격 테스트는 VPN 으로 하지 말 것 |
| Log4Shell 요청 실습 | `http://log4shell.grootlab.duckdns.org/` | DVWA와 같은 HTTP80 경로. `/log4shell/`로 이동하며 정상200·헤더 누락400을 비교 |
| Log4Shell HTTPS(선택) | `https://log4shell.grootlab.duckdns.org/` | 채팅과 같은 공용 와일드카드 인증서. 인증서·경로 검증 완료, 실습 기본 주소는 위 HTTP |

- 채팅 DuckDNS 이름에는 2026-10-08부터 Let's Encrypt 공인 인증서가 적용돼 일반 HTTPS 검증을 통과한다. **채팅에서 인증서 경고가 뜨면 그대로 신뢰하지 말고** 접속 이름·네트워크 상태를 확인한다. Wazuh 대시보드 인증서는 별개다.
- **2026-10-15 인증서 후속:** 채팅·Log4Shell DuckDNS 이름을 함께 포함하는 `*.grootlab.duckdns.org` 공용 인증서를 A에 적용했다. Mac의 시스템 CA 검증에서 채팅 ping 200과 Log4Shell HTTPS의 잘못된 DVWA 경로→`/log4shell/` 최종 200을 확인했다. HTTP 주소를 실습 기본으로 유지하며, 내부 `*.groot.lab` 이름은 공인 인증서의 대상이 아니다. 인증서 경고가 나면 예외를 추가하지 말고 운영자에게 알린다.
- Mattermost 모바일 앱은 `https://chat.grootlab.duckdns.org`를 서버 주소로 사용한다. 학교 Wi-Fi 중 `192.168.16.230`으로 접근할 수 있는 내부망에서 사용한다. 일반 이동통신망만으로는 이 사설 IP에 직접 도달할 수 없다. 10/08 당시 휴대폰 로그인은 미확인이었으나 **10/13 사용자 확인으로 Android·iOS 모두 인증서 인식·로그인·채팅 성공**으로 갱신했다. 관리 SSH에서 휴대폰 화면을 직접 검증한 결과는 아니다.
- 휴대폰에서는 먼저 브라우저로 `https://chat.grootlab.duckdns.org/api/v4/system/ping`을 열어 인증서 경고 없이 `status: OK`가 나오는지 확인한 뒤, Mattermost 앱에 위 채팅 서버 주소를 등록해 로그인한다. Mac에서는 10/08 문서 점검 중에도 해당 ping의 HTTP 200·TLS 검증 성공을 확인했다.
- [GlobalProtect iOS/Android 앱 자체는 존재](https://docs.paloaltonetworks.com/globalprotect/getting-started/globalprotect-overview)하지만, **사용자 보고에 따르면 학교 관리자가 관리 범위 확대를 이유로 모바일 VPN 지원을 거절했다.** 사용자 휴대폰의 GlobalProtect 로그인도 실패했다. 따라서 이 프로젝트의 모바일 채팅 검증 경로에서 학교 VPN을 제외한다. 기술적 로그인 실패 원인이나 학교 포털 설정을 확인한 것은 아니다. 채팅 인증서와 학교 VPN 인증서는 별개다.
- **사용자 보고:** Mac의 이전 GlobalProtect 접속 문제는 학교 관리자가 GlobalProtect 인증서를 갱신한 뒤 해결됐다. 휴대폰 GlobalProtect 로그인 실패가 같은 원인인지는 확인되지 않았다.
- **모바일 알림 현황(10/13 11:49 KST 실측·후속 제약 반영):** 사용자가 확인한 Android·iOS의 인증서 인식·로그인·채팅은 정상이며, 알림 미수신이 남아 있다. B의 **푸시 서버 주소와 일반 알림 설정**, A의 B→TPNS TCP 443 한정 허용은 반영했다. URL은 공란이 아니지만 외부 요청에 회신이 없어 푸시 활성화는 `false`로 유지한다. 사용자는 **상위 방화벽을 우리가 변경할 수 없다고 정정**했으므로 상위 장비의 관리 접속 정보를 받아 직접 수정하는 계획은 제외했다. 학교에서 허용하는 기존 외부 프록시·중계 경로가 있는지 확인이 필요하다. 그런 경로도 없고 상위 정책도 바꿀 수 없으면 현재 망에서 공식 모바일 앱의 백그라운드 푸시를 복구할 수 없다. 임의 터널이나 Mac 상주 프록시는 설치하지 않는다. **모바일 푸시 복구 완료가 아니다.** [비활성 시 경고를 반환하는 공식 구현](https://github.com/mattermost/mattermost/blob/v11.11.1/server/channels/app/notification_push.go#L755) · [서버 적용 상태·현재 제약](infra/groot-b/README.md#모바일-푸시--dns-복구외부-https-경로-미확보-2026-10-13).
- **내부망 제약에 대한 사용자 추가 설명:** 프로젝트 VM은 상위 방화벽 뒤의 내부망 전용 환경이며 외부 통신이 선택적으로 허용된다. 직접 확인한 것은 B→DGX API HTTP 200·DNS 정상과 TPNS TCP 회신 없음까지이며 학교 방화벽의 개별 규칙을 열람한 것은 아니다. 프로젝트 내 인증서·TLS 설정을 더 바꿔도 이 통신 제약은 해소되지 않는다. 기존에 허용된 푸시 도달 경로가 확인되지 않은 현재 구성에서는 공식 모바일 푸시 미복구 상태를 유지하며, 이번 설명 반영으로 서버 설정은 추가 변경하지 않았다.
- **Wazuh 시간 표시(10/13 11:15 KST 적용):** 대시보드 시간대를 브라우저 설정에 따르는 `Browser`에서 `Asia/Seoul`로 고정하고 서버 설정 API로 확인했다. **이미 열어 둔 대시보드 페이지를 새로고침한다.** 원본 JSON·`full_log`의 UTC 문자열은 그대로 보존하므로 화면의 날짜 필드와 9시간 달라 보일 수 있다. 예를 들어 `02:05:20+0000`과 `11:05:20+09:00`은 같은 순간이며 원본 로그의 시간을 직접 고치지 않는다. [시간대 운영 기록](infra/groot-b/README.md#시간대-운영--대시보드-kst-고정원본-utc-보존-2026-10-13).
- 이름이 안 풀리면 학과 DNS 또는 DuckDNS 상태를 확인하고 팀장에게 알린다. PC 브라우저용 예비 경로로는 `192.168.16.230 chat.groot.lab wazuh.groot.lab dvwa.groot.lab log4shell.groot.lab`를 hosts에 넣을 수 있다. Log4Shell 예비 이름은 이름을 유지하므로 DNS 장애 때도 hosts 등록 후 `http://log4shell.groot.lab/` 또는 `http://192.168.16.230/log4shell/`를 사용한다. `chat.groot.lab`은 이번 공인 인증서의 대상 이름이 아니므로 Mattermost 모바일 앱에는 DuckDNS 채팅 주소를 사용한다.

**Log4Shell 접속 방법**

1. PC를 학과 내부망에 연결하거나 학교 VPN에 로그인한다. `192.168.16.230`에 도달할 수 있는 경로가 필요하다.
2. 브라우저에서 [Log4Shell 실습 화면 — HTTP](http://log4shell.grootlab.duckdns.org/)를 연다. 주소가 `/log4shell/`로 이동하고 **Log4Shell 요청 실습** 화면이 나타나는지 확인한다. DVWA 계정으로 로그인할 필요는 없다.
3. API 연결 준비가 끝나면 `X-Api-Version` 기본값 `1.0`을 유지하고 **정상 요청 보내기**를 누른다. 최근 응답에 앱의 `HTTP 200`과 `Hello, world!`가 표시된다.
4. **헤더 없이 요청**을 누르면 앱의 `HTTP 400`을 확인할 수 있다. 이 400은 필수 헤더 누락에 따른 실습 결과이며, 화면 접속 실패가 아니다. 요청 시각은 KST로 표시된다.

- **HTTPS 접속:** [Log4Shell 실습 화면 — HTTPS](https://log4shell.grootlab.duckdns.org/). 채팅과 같은 공용 인증서를 사용한다. HTTP 기본 주소에는 인증서가 사용되지 않는다.
- **DNS 문제 시 예비 주소:** [IP로 실습 화면 열기](http://192.168.16.230/log4shell/). IP 뒤의 `/log4shell/`까지 입력한다. IP 루트나 DVWA 전용 주소는 다른 화면으로 연결될 수 있다.
- **서버 관리 SSH:** Log4Shell은 C(service) 서버에 있다. `ssh -J groot_a@grootlab.duckdns.org groot_c@10.200.10.20`으로 A를 경유하며, 인증 시 A → C 순서로 각 서버의 자격정보를 사용한다. 브라우저 실습에는 SSH가 필요하지 않다.
- 앱의 내부8080 포트를 외부 접속 주소로 사용하지 않는다. 화면의 두 요청은 기본 동작 확인용이며, 공격 시나리오는 아래 안내처럼 별도 VM 실습망에서 진행한다. [화면 사용·구성 상세](infra/groot-c/log4shell-ui/README.md).

## SSH (셸) — 설정 파일 없이 아래 한 줄 그대로
| 대상 | 명령 | 비밀번호 입력 |
|---|---|---|
| A 게이트웨이 (groot-sec) | `ssh groot_a@grootlab.duckdns.org` | A 1회 |
| B SIEM·채팅·에이전트 (groot-siem) | `ssh -J groot_a@grootlab.duckdns.org groot_b@10.200.10.10` | A → B 순서로 2회 |
| C 웹 표적·Log4Shell (groot-web) | `ssh -J groot_a@grootlab.duckdns.org groot_c@10.200.10.20` | A → C 순서로 2회 |

- 주소는 IP 가 아니라 이름(`grootlab.duckdns.org`)이라 A 의 IP 가 바뀌어도 그대로 쓴다.
- B·C 는 반드시 A 를 거친다(`-J`). 다른 포트나 직결 경로는 없다.
- 처음 접속 때 호스트 키 확인 질문에 `yes`.

## 하지 말 것
- **공격성 트래픽(스캔·sqlmap 등)을 캠퍼스 VPN 을 통해 보내지 말 것** — 캠퍼스 방화벽이 그 PC↔서버 쌍을 차단해 버린다. 공격 시나리오는 VM 세그먼트(Kali)에서만.
- 관제 대시보드 계정·비밀번호를 채팅에 올리지 말 것.
