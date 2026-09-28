# A 외부 IP 변경 런북 (2026-09-29 재변경용)

배경: 2026-09-28 에 IT 가 준 .71~.73 은 **다른 대역(VLAN) 서버 주소**라 통하지 않았고(.129·.131 무응답, 학과망 불통) 롤백함. 증상만으로는 "미등록"과 구분이 안 되므로 **새 주소의 서브넷/VLAN 이 게이트웨이 .129 와 같은지부터** 확인한다.
B·C 임시 NIC 가 남아 있으면 B·C 도 같은 절차(넷플랜 주소만)이고, 제거돼 있으면 **A 한 대만** 바꾸면 된다.

## 0. 사전 확인 (IT 배정 정보로)
- 새 주소가 `192.168.16.128/25`(게이트웨이 .129) 안인가? 마스크 255.255.255.128 그대로인가? 아니면 VLAN/포트그룹 변경이 먼저.
- 캠퍼스 방화벽의 학과망·VPN→A 22/80/443 허용 대상 IP 가 새 주소로 바뀌는가(IT 확인).

## 1. 보조주소로 먼저 검증 (무해, 본 주소 유지)
```
ssh groot-a
sudo /usr/local/sbin/apply_ext_ip_A.sh check <NEW>        # arping 비어있음 + 보조주소로 .129/.131 ping
```
학과망 Mac 에서: `nc -G 4 -z <NEW> 22` → 열림이면 통과. 안 열리면 여기서 멈추고 IT 와 확인(절대 본 전환하지 말 것).

## 2. 본 전환 (A 세션 끊김, 복귀 타이머 없음)
```
sudo /usr/local/sbin/apply_ext_ip_A.sh apply <NEW> 192.168.16.230
```
Mac: `~/.ssh/config` 의 `groot-a`·`groot-mcp-jump`·`groot-resp` HostName 을 <NEW> 로 → `ssh groot-a 'sudo /usr/local/sbin/apply_ext_ip_A.sh verify'`.

## 3. 클라이언트/외부 항목
- DuckDNS `grootlab` → <NEW> (팀장 계정). 확인: `dig +short chat.grootlab.duckdns.org`.
- hosts 사용자: `<NEW> dvwa.groot.lab wazuh.groot.lab chat.groot.lab`. 저장소 원본 `infra/dns/groot.lab.hosts` 갱신.
- 저장소 문서·스크립트의 옛 IP 일괄 치환(2026-09-28 커밋 ccf895f 의 파일 목록과 동일; 변경이력은 제외하고 항목 추가) 후 커밋.
- 검증: 채팅 `https://chat.grootlab.duckdns.org`(ping 200·웹소켓 101), 대시보드 302→로그인 200, DVWA 302, `ssh groot-b-int`/`groot-c-int`, B→DGX 200(Hermes), 에이전트 3 Active.

## 4. 하지 말 것
- 옛 IP 로 되돌리는 자동복구(데드맨) 걸지 않기 — 옛 주소가 회수됐을 수 있음. 실패 시 ESXi 콘솔로 수습.
- 학과망/VPN 에서 새 주소로 공격성 트래픽 보내지 않기(기존 규칙).
