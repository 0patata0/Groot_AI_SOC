# 내부 이름(groot.lab) — 현재 hosts 방식, 나중 dnsmasq 확장

이 망은 공개 DNS(168.126.63.1 KT)로 사설 IP를 못 가리키고 외부 egress도 막혀 있어, URL 접근은 **내부 이름 해석**으로만 가능하다. 단일 원본 `groot.lab.hosts` 하나로 지금(hosts)과 나중(dnsmasq)을 모두 커버한다.

## 이름 (단일 원본: `groot.lab.hosts`)
| 이름 | → | 접근 |
|---|---|---|
| `dvwa.groot.lab` | 192.168.16.230:80 (WAF→DVWA) | 외부 오픈 웹서비스. 캠퍼스·VPN 모두 `http://dvwa.groot.lab/` |
| `wazuh.groot.lab` | 192.168.16.230:443 (A chatproxy→B:443, 출발지 allowlist) + :10443 DNAT | 관리포털. 학과망·VM세그먼트 `https://wazuh.groot.lab` / VPN·외부는 403(정책, 터널 없음) |
| `chat.groot.lab` | 192.168.16.230:8065 (A→B:8065) | Mattermost. 캠퍼스 `http://chat.groot.lab:8065` / VPN 은 ssh 터널(`groot-mm`→18065). SiteURL=http://chat.groot.lab:8065 |

> WAF(nginx)는 `default_server`라 어떤 Host 헤더든 DVWA로 서빙 → 서버 변경 불필요(검증됨: Host `dvwa.groot.lab` → 302/200).

## 지금: hosts 방식 (클라이언트별 1회)
각 클라이언트에서 원본을 /etc/hosts 에 주입(멱등):
```
sudo bash infra/dns/apply_hosts.sh
```
- Mac: 위 명령. 브라우저 `http://dvwa.groot.lab/`.
- Kali/캠퍼스 PC: repo의 `infra/dns/{apply_hosts.sh, groot.lab.hosts}` 복사 후 동일 실행. (또는 수동으로 `192.168.16.230 dvwa.groot.lab` 한 줄)
- 이름 추가/변경: `groot.lab.hosts` 만 수정하고 각 클라이언트에서 apply 재실행(기존 블록만 교체).

## 나중: dnsmasq 확장 (캠퍼스 세그먼트 클라이언트가 많아질 때)
같은 원본 파일을 그대로 재사용:
1. A(또는 B)에 dnsmasq 오프라인 설치(deb 반입). 설정: `addn-hosts=/etc/capstone/groot.lab.hosts`, `listen-address=10.10.10.1`(및 필요 시 192.168.16.230), `bind-interfaces`, `no-resolv`+상위 `server=168.126.63.1`(외부 이름 포워딩용, egress 막혀 있으니 사실상 내부만).
2. A 호스트 방화벽에 세그먼트→UDP/TCP 53 허용 룰 추가(`capstone-fw.nft` input 에 `iifname ens160 udp dport 53 accept` 등; 캠퍼스 세그먼트 대상이면 ens192 쪽도).
3. 클라이언트 resolver 를 그 DNS 로(캠퍼스 세그먼트 한정). **VPN 클라이언트는 53 도달 불가(22/80/443만) → 계속 hosts 사용.**
- 즉 dnsmasq 는 캠퍼스 세그먼트 클라이언트에만 실익. VPN 브라우저(내 Mac)는 어느 경우든 hosts 필요.

## 도달성 요약
- VPN: 이름으로 `dvwa`(80)만 접근 가능(hosts 필요). 관리포털/채팅은 터널.
- 캠퍼스 세그먼트: 모든 포트 도달 → 이름+포트로 접근(hosts 또는 dnsmasq).
