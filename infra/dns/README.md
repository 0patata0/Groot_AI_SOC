# 접속 이름과 채팅 인증서 — DuckDNS 대표 이름·hosts 예비 별칭

현재 대표 접속 이름은 공개 DNS의 `*.grootlab.duckdns.org`이며 사설 IP `192.168.16.230`을 반환한다(2026-09-28 학과망 이름 해석·접속 확인, 10/08 Mac 재확인). 학교망이나 PC VPN으로 해당 IP에 도달해야 하며 공개 DNS 등록이 인터넷 공개 접속을 뜻하지는 않는다. 내부 `*.groot.lab` 이름은 `groot.lab.hosts`를 이용한 hosts 예비 별칭으로 유지한다. A의 ACME·DuckDNS HTTPS egress 제한은 DNS 이름 해석과 별개다.

## 내부 별칭 (원본: `groot.lab.hosts`, 대표 DuckDNS 이름은 아래 참조)
| 이름 | → | 접근 |
|---|---|---|
| `dvwa.groot.lab` | 192.168.16.230:80 (WAF→DVWA) | 외부 오픈 웹서비스. 캠퍼스·VPN 모두 `http://dvwa.groot.lab/` |
| `wazuh.groot.lab` | 192.168.16.230:443 (A chatproxy→B:443, 출발지 allowlist) + :10443 DNAT | 관리포털. 학과망·VM세그먼트 `https://wazuh.groot.lab` / VPN·외부는 403(정책, 터널 없음) |
| `chat.groot.lab` | 192.168.16.230:443 (A chatproxy→B:8065) | Mattermost hosts 별칭. 캠퍼스·PC VPN `https://chat.groot.lab`; 대표 SiteURL은 `https://chat.grootlab.duckdns.org`. 내부 별칭 인증서는 공인 전환 대상이 아님 |

> WAF(nginx)는 `default_server`라 어떤 Host 헤더든 DVWA로 서빙 → 서버 변경 불필요(검증됨: Host `dvwa.groot.lab` → 302/200).

## 예비 접속: hosts 방식 (내부 별칭을 사용할 클라이언트별 1회)
각 클라이언트에서 원본을 /etc/hosts 에 주입(멱등):
```
sudo bash infra/dns/apply_hosts.sh
```
- Mac: 위 명령. 브라우저 `http://dvwa.groot.lab/`.
- Kali/캠퍼스 PC: repo의 `infra/dns/{apply_hosts.sh, groot.lab.hosts}` 복사 후 동일 실행. (또는 수동으로 `192.168.16.230 dvwa.groot.lab` 한 줄)
- 이름 추가/변경: `groot.lab.hosts` 만 수정하고 각 클라이언트에서 apply 재실행(기존 블록만 교체).

## 나중: dnsmasq 확장 (캠퍼스 세그먼트 클라이언트가 많아질 때)
같은 원본 파일을 그대로 재사용:
1. A(또는 B)에 dnsmasq 오프라인 설치(deb 반입). 설정: `addn-hosts=/etc/capstone/groot.lab.hosts`, `listen-address=10.200.10.1`(및 필요 시 192.168.16.230), `bind-interfaces`, `no-resolv`+상위 `server=168.126.63.1`(외부 이름 포워딩용, egress 막혀 있으니 사실상 내부만).
2. A 호스트 방화벽에 세그먼트→UDP/TCP 53 허용 룰 추가(`capstone-fw.nft` input 에 `iifname ens160 udp dport 53 accept` 등; 캠퍼스 세그먼트 대상이면 ens192 쪽도).
3. 클라이언트 resolver 를 그 DNS 로(캠퍼스 세그먼트 한정). **VPN 클라이언트는 A:53 도달 불가(22/80/443만)**이므로 내부 `*.groot.lab` 별칭에는 hosts가 필요하다.
- dnsmasq는 미래 확장안이며 현재 배포된 DNS 서버가 아니다. DuckDNS 대표 이름은 캠퍼스·PC VPN에서 hosts 없이 사용한다.

## 도달성 요약 (내부 `*.groot.lab` 이름 기준, 아래 DuckDNS 별칭 제외)
- PC VPN: hosts 내부 별칭 또는 DuckDNS 대표 이름으로 DVWA(80)·채팅(443)에 접근한다. 채팅은 SSH 터널이 필요 없고 Wazuh 대시보드는 VPN 출발지를 403으로 거부하는 정책이다.
- 학과망: A:80/443의 이름 기반 프록시를 사용한다. A:10443은 학과망에서 캠퍼스 FW에 막힌 실측이 있으므로 모든 포트가 열려 있다고 가정하지 않는다. VM 세그먼트의 10443 DNAT 도달성은 Kali 주소·라우팅과 별도 허용 소스 확인이 필요하다.
- 모바일: 사용자 보고상 학교 관리자가 GlobalProtect 모바일 지원을 거절했고 휴대폰 VPN 로그인도 실패했다. A에 도달하는 학교 내부 Wi-Fi에서 브라우저 HTTPS ping 후 Mattermost 앱 로그인을 검증한다. 실기기 성공은 아직 미확인이다.

## 팀원 무설정 접근 — 공개 DNS(DuckDNS) 별칭 (2026-09-28)
- 배경: 학과망·VPN → A 는 22/80/443 만 통과하고 53 도 막힘(실측) → 내부 DNS 서버는 팀원 PC 에 무용. 팀원 PC 가 이미 쓰는 학과 DNS 가 인터넷에 물어서 답을 받게 하는 방식만 "설정 0" 이 된다. 사설 IP 답을 학과 DNS 가 그대로 전달하는 것도 실측(nip.io).
- 채택: **DuckDNS `grootlab.duckdns.org` → 192.168.16.230** (하위 이름은 자동으로 같은 IP). 이름: `chat.grootlab.duckdns.org`(채팅), `wazuh.grootlab.duckdns.org`(관제, allowlist 동일·VPN 403), `dvwa.grootlab.duckdns.org`(웹표적, 80 WAF). 기존 `*.groot.lab`(hosts) 은 별칭으로 유지.
- A 측: `infra/groot-a/chatproxy.nginx.conf` 에 DuckDNS 이름용 server 블록 2개(별도 인증서 `tls/chatduck.*`, `tls/wazuhduck.*` → 기존 인증서 신뢰 무영향). B 측: Mattermost `MM_SITEURL`=DuckDNS 이름(대표), `MM_ALLOWCORSFROM`=두 Origin → 둘 다 웹소켓 101.
- 등록(1회, 팀장 계정): duckdns.org 로그인 → domains 에 `grootlab` 추가 → current ip 를 `192.168.16.230` 으로 설정 → update. 확인: `dig +short chat.grootlab.duckdns.org` → 192.168.16.230. IP 가 바뀌지 않으므로 갱신 클라이언트 불필요.
- 한계: DuckDNS/학과 DNS 장애 시 이름 해석 실패(hosts 별칭이 예비). 채팅 DuckDNS 이름은 2026-10-08부터 Let's Encrypt 공인 인증서를 사용한다. Wazuh 및 `*.groot.lab` 인증서는 이번 전환 대상이 아니다.

### DuckDNS 공인 인증서 전환 검토 (2026-10-06 당시 미적용)
- 공개 DNS의 `chat.grootlab.duckdns.org`·`wazuh.grootlab.duckdns.org`는 현재 `192.168.16.230`(사설 IP)을 가리킨다. A의 80번은 WAF, 443번은 Docker `chatproxy`가 사용한다. 일반 호스트 Nginx용 `certbot --nginx`와 HTTP-01 검증을 그대로 실행하지 않는다.
- DuckDNS의 [TXT API](https://www.duckdns.org/spec.jsp)로 DNS-01 검증용 TXT를 등록할 수 있다. 모바일 Mattermost 앱 접속이 목적이므로 우선 `chat.grootlab.duckdns.org` **단일 이름** 인증서를 권장했다. [`acme.sh` DuckDNS 플러그인](https://github.com/acmesh-official/acme.sh/blob/master/dnsapi/dns_duckdns.sh)을 사용할 수 있다. 채팅·Wazuh 모두 필요하면 `*.grootlab.duckdns.org` 와일드카드 **한 이름** 인증서도 가능하다(루트 `grootlab.duckdns.org`와 내부 `*.groot.lab`은 별개). DuckDNS 하위 이름의 TXT 값은 공유되므로 채팅·Wazuh 개별 이름을 한 주문에서 동시 검증하지 않는다.
- **2026-10-06 라이브 확인:** A에서 Let's Encrypt·DuckDNS HTTPS API 연결이 시간 초과됐고, 관리 Mac에서는 모두 HTTP 200이었다. 따라서 Mac에서 발급·갱신하고 A의 Docker 마운트 `chatproxy/tls/chatduck.crt`·`chatduck.key`에 체인·개인키를 권한 제한해 배포한다. A에서 `nginx -t` 후 프록시를 재로드하고, 갱신 시에도 이 배포·재로드를 반복해야 한다. 현재 SSH가 비밀번호 방식이라 무인 자동 배포는 별도 제한된 인증 경로 없이는 완성되지 않는다. DuckDNS 토큰과 개인키는 저장소에 넣지 않는다. 대시보드 출발지 허용목록은 유지한다. [Let's Encrypt의 DNS-01 설명](https://letsencrypt.org/docs/challenge-types/).
- 당시에는 Mac에 [Homebrew `acme.sh`](https://formulae.brew.sh/formula/acme.sh) 설치를 검토했으나, 10/08 사용자가 Mac에 도구·발급 상태를 남기지 않기를 요청해 설치하지 않았다. 아래가 실제 적용 결과다.

### 채팅 인증서 배포 (2026-10-08, 라이브 직접 확인)
- Mac에서 공식 `acme.sh` **3.1.6 태그 소스**를 `/private/tmp`의 권한 `700` 임시 디렉터리에서 직접 실행했다. `--home`·`--config-home`·`--cert-home`과 프로세스 `HOME`·`TMPDIR`를 모두 임시 디렉터리로 지정하고 `--install`은 실행하지 않았다. Git 무시 `CREDENTIALS.local.md`의 `DuckDNS_Token` 항목을 값 출력 없이 읽어 사용했고 파일 권한을 `600`으로 제한했다. Markdown 파일 전체를 `source`하지 않는다.
- `acme.sh --issue --server letsencrypt --dns dns_duckdns --keylength ec-256 -d chat.grootlab.duckdns.org`가 DNS-01 검증과 TXT 정리를 마쳤다. `--install-cert --ecc`로 임시 `fullchain.pem`·`privkey.pem`을 내보내 A에 전송했다. A의 [`deploy_chatduck_cert_A.sh`](../groot-a/deploy_chatduck_cert_A.sh) `--check-only`와 실제 배포가 모두 통과했고, Nginx 재로드 후 제공 중인 SNI 인증서와 CA 검증 Mattermost ping을 확인했다. Mac의 일반 `curl`도 HTTPS 검증 결과 0, HTTP 200, `status: OK`였다.
- 라이브 채팅 인증서: **Let's Encrypt YE1**, SAN `chat.grootlab.duckdns.org`, 만료 **2027-01-06 06:02:33 UTC**(15:02:33 KST). A `chatduck.crt/key`는 각각 `644/600`; 이전 인증서는 A의 제한된 백업 디렉터리에 남겼다. A 임시 전송 파일과 Mac 임시 ACME 소스·계정·인증서 사본은 삭제했다. Mac의 `~/.acme.sh`와 PATH의 `acme.sh`는 생성되지 않았다. 사용자가 넣은 Git 제외 토큰 파일은 남겨 두었다.
- **갱신은 미자동화:** Mac 임시 ACME 계정·상태를 삭제했으므로 다음에는 새 임시 디렉터리에서 재발급해 A로 다시 전송·배포해야 한다. 2026-12 초에 갱신을 준비하고 만료 전에 완료한다. A 사설 IP에 도달하는 학교 Wi-Fi의 실제 모바일 앱 로그인은 아직 시험하지 않았다. 사용자 보고에 따르면 학교 관리자가 관리 범위 확대를 이유로 모바일 GlobalProtect 지원을 거절했고 휴대폰 로그인도 실패했으므로 모바일 VPN 경로는 프로젝트 검증 계획에서 제외한다(기술적 원인 미확인). `chat.groot.lab`·Wazuh 인증서는 변경하지 않았다. 상세 [10/08 기록](../../대화기록/2026-10-08.md).
- **같은 날 문서 점검 중 Mac 재확인:** CA 검증을 생략하지 않은 `GET https://chat.grootlab.duckdns.org/api/v4/system/ping`이 HTTP 200·TLS 검증 결과 0, 접속 IP `192.168.16.230`을 반환했다. 이 결과는 Mac 경로의 확인이며 휴대폰 Wi-Fi·Mattermost 앱 성공을 뜻하지 않는다.
