# 관리자·MCP 관리 접속 — 2026-11-03

23:13:55 KST A에 증분 적용하고 **23:15:00 신규 관리자 경유 SSH로 확정**했다. A의 외부 SSH·Wazuh 웹 관리·10443은 관리자 `192.168.16.231/32`, 내부 A SSH는 B의 MCP 출발지 `10.200.10.10/32`로 제한한다. B/C의 기존 ens160 입력·Docker forward 정책은 재검증했으며 운영 소스는 변경하지 않았다. [작은 검증 원장](management-access-validation-20261103.json) · [현재 잔여](../../STATUS.md).

| 경로 | 변경 전 → 후 실제 관측 |
|---|---|
| 관리자231 → A SSH | 신규 인증·root 확인 성공 |
| 관리자231 → Wazuh 두 도메인 | 302 로그인 이동 유지, TLS 검증 성공 |
| 관리자231 → A10443 | timeout → TCP 연결 성공. 로그인 시험은 아님 |
| Kali232 → Wazuh 두 도메인 | 공개 도메인302 → 403, legacy도403. 관리자 위조 XFF/X-Real-IP로도403 |
| C → A22, A 내부22 | 연결 가능 → 거부, 내부 관리 guard DROP 카운터 증가 |
| Kali232 → Mattermost·DVWA·Log4Shell | 200·302·200 유지 |
| 실제 Hermes MCP | FW 전체 읽기·A/C systemd 진단3건 모두 성공 |
| 실제 Ollama CLI | FW1회·도구 오류/보호쓰기/채널게시0·7.62초. 요청한 input 범위를 무시한 전체 표 출력은 후속 문제 |

Nginx는 두 Wazuh 서버 블록에만 `allow 192.168.16.231; deny all;`을 적용한다. 공인 도메인은 시스템 CA로, legacy 자체서명 도메인은 인증된 관리 연결로 읽은 공개 인증서를 고정해 검증했다. 클라이언트가 제공한 전달 헤더를 관리자 신원으로 신뢰하지 않는다. 접근 규칙의 순서·상속은 [Nginx 공식 문서](https://nginx.org/en/docs/http/ngx_http_access_module.html)를 따른다.

관리 포트 출발지 검사는 기존 `prerouting_block`에서 주소 예외·established 허용보다 먼저 수행한다. `fib daddr type local`로 A 자신의 목적지만 검사하며 일반 라우팅 SSH를 이 규칙으로 막지 않는다. 외부22/10443과 내부22의 IPv6 관리 우회도 거부한다. 이는 IPv6 전체 테이블 삭제나 공개 웹의 IPv6 지원 검증이 아니다. `never_block`의 campus/VPN 보호와 관리 접속 허용 집합은 별개다.

Docker 게시 포트는 INPUT만으로 제한했다고 판단하지 않는다. 기존10443 DNAT와 정확한 CAPSTONE-FWD 출발지 규칙을 한 주소로 좁혔고, 공개443에서는 Wazuh 가상 호스트만 제한했다. Docker 소유 체인과 다른 NAT 규칙은 보존했다. [Docker 공식 경로 설명](https://docs.docker.com/engine/network/packet-filtering-firewalls/).

## 설치와 복구

기존 dual-NIC A 유지보수 진입점은 루트 `deploy.sh --management-access`다. **이 서버의 검토된 4파일·ens192/ens160·주소에 한정한 1회 이관**이며 일반 환경 자동탐지·전체 초기 설치 명령이 아니다. 다른 주소·토폴로지에 그대로 실행하지 않는다. 이미 적용한 서버에서는 `verify`를 사용한다.

```sh
# 기존 A에서 승인한 초기 이관만 실행. 현재 운영에는 재실행하지 않는다.
sudo ./deploy.sh --management-access apply
# 출력된 실제 directory를 아래 인수로 사용한다.
sudo ./deploy.sh --management-access verify --directory /var/lib/capstone-management-access/c65d6ee3bd13d319
sudo ./deploy.sh --management-access confirm --directory /var/lib/capstone-management-access/c65d6ee3bd13d319
# 필요할 때만 해당 이관을 수동 원복한다.
sudo ./deploy.sh --management-access rollback --directory /var/lib/capstone-management-access/c65d6ee3bd13d319
```

root 전용 디렉터리에 4파일의 전후 바이트·SHA·uid/gid/mode와 복구 코드를 보존한다. 15분 독립 systemd 타이머를 먼저 만들고, bind-mount inode를 유지해 설정을 기록한다. FW는 관리 집합·guard4개·10443 DNAT만 증분 변경하고 iptables도 기존 관리 forward1개만 교체한다. Nginx 구문 검사 후 reload하며 센서·Docker·SSH를 재시작하지 않는다. `agent_block` 집합·TTL·운영 DB/WAL·승인·채팅을 재로드하거나 복원하지 않는다. 원복은 전후 SHA가 아닌 외부 수정을 발견하면 덮어쓰지 않는다. 확정과 타이머 실행의 경합 및 이미 원본인 경우의 중복 복구는 무동작으로 처리한다.

**실제 운영 원복은 실행하지 않았다.** 격리 namespace에서 실제 증분 적용/역변경과16종 패킷·120초 차단 TTL 유지(119초 경과)를 검증했다. 운영에서는 신규 접속·허용/거부·일치한 DROP 카운터·설정 SHA·타이머 비활성·확정 후 recover 무동작을 확인했다.

새 환경의 root `deploy.sh`는 security 역할에도 `host_security.py`의 check/install/verify를 연결한다. 관리자 설정 CIDR·현재 인증된 설치자 peer와 SIEM 출발지만 SSH로 허용하고, 그 외 IPv4/IPv6 SSH는 established 허용 이전에 거부한다. `ADMIN_PROTECTED_CIDRS`는 SSH 허용으로 전용하지 않는다. B/C 기존 분리는 유지한다. 설정 예제의 관리·대시보드 허용은 현행231 한 주소로 갱신했으며 실제 새 환경 주소로 교체해야 한다. 이는 새3VM 전체 설치 성공을 뜻하지 않는다.

설치 회귀 중 기존 portable TLS 렌더러가 바뀐 공유 브리지 endpoint를 치환하지 못하는 오류도 수정했다. 새 WAF/edge 주소와 server 단계 real_ip 복원을 검증한16검사가 통과했다. 이 렌더러 수정은 운영 컨테이너 재구성이 아니다. 추가 deb/wheel/이미지0이며 기존 표준 라이브러리·OpenSSH·nft/iptables·Docker·systemd를 사용한다.

관리7·호스트7·portable TLS16·SOC 설치37·소스묶음1검사와 Linux native 구문/격리16조건이 통과했다. 패키지와 원자료 반입은 없다. NAT 통합6후보는 미적용이며 현재 로더의 새 SHA/관리 출발지를 기준으로 다시 검증해야 한다. B/C의 컨테이너→호스트 관리 경로·관리자 접속 경보 소음 예외·복잡 사건 판단은 별도 잔여다.

## 11월4일 게시·재확인

10:33:02 KST 소스26파일의4301dba 커밋과원격main일치를확인했다. 10:33 관리자경유 신규SSH로 A의4파일SHA·정책·복구무동작/타이머inactive와 B/C기존hostguard·3서버수집연결을읽기재검증했다. HTTP/MCP/패킷결과는위11/3시험이며밤사이상시감시를의미하지않는다. Mac자체임시18파일/312657B·부모/mux는10:34:50제거확인,비밀값없는도우미17개와원문은로컬전용보존·서버복구본은유지했다. 새패키지/다운로드0이다.
