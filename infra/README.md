# infra — Docker 기반 배포 (B-1)

각 ESXi VM(Groot_A/B/C)의 Docker Compose·설정·운영 문서. 아래 배포 순서는 최초 구축 이력이다. 현재 단계와 사양은 [PLAN.md](../PLAN.md), 호스트별 절차는 [A](groot-a/README.md)·[B](groot-b/README.md)·[C](groot-c/C_구축_표준설정.md) 문서를 참조한다.

시각 자료: [현재 배포 네트워크 토폴로지](diagrams/current-network-topology-2026-10-08.png) · [버스형 토폴로지 개념도](diagrams/bus-topology-concept-2026-10-08.png). 버스형 그림은 실제 물리 배선이 아니라 내부망을 설명하기 위한 재배치다.

## 현재 상태 (2026-10-08 라이브 확인·배포 기록 기준)
- B/C의 `ens192` vNIC는 제거됐고 기본 경로는 A(`10.200.10.1`)를 지난다. 외부망 주소 `.231`/`.232`는 과거 설치 주소다.
- A의 FW v2는 적용·확정됐다(`FORWARD=DROP`, `CAPSTONE-FWD` 14룰). WAF의 GROOT 커스텀 룰 마운트·`DetectionOnly`·`nginx -t` 통과와 Suricata의 ET+로컬 `all.rules`·Phase-A 수동 탐지 설정을 SSH로 재확인했다.
- B의 Wazuh 에이전트 000/001/002는 Active다. 신규 FW 접두어·WAF 100200대 전용 분류는 없지만, 보안 이벤트 읽기 조회에서 Suricata 로컬 SID `1000010`→Wazuh `100110`, ModSecurity CRS `920350`→Wazuh `100101`을 확인했다. 나머지 로컬 룰 분류와 시나리오별 공격 트래픽 실발화는 미검증이다. WAF `On`·IPS 인라인 차단 전환은 별도 작업이다.
- B Hermes에는 `wazuh-ro`·`security-events`·`resp`·`rule-a`·`rule-b` 총 5개 MCP 서버가 등록됐다. 10/08 약 12:58 KST 승인 브로커·A/B 룰 변경기·worker를 배포해 HMAC 통신·읽기 조회를 확인했다. 운영 룰 해시는 그대로이며 실제 Mattermost 승인 버튼→룰 적용·복구 E2E는 미검증이다. [MCP 운영 문서](mcp/README.md).
- 채팅 `https://chat.grootlab.duckdns.org`에는 10/08 Let's Encrypt 인증서를 배포했고 A와 Mac의 HTTPS 검증을 통과했다(만료 2027-01-06 15:02 KST). 자동 갱신은 없으므로 2026-12 초 재발급·A 재배포를 준비한다. 사용자 보고상 관리자가 모바일 GlobalProtect 지원을 거절해 모바일 VPN은 검증 경로에서 제외했다. A에 도달하는 학교 내부 Wi-Fi의 Mattermost 앱 로그인은 미검증이다. [인증서 운영 기록](dns/README.md).
- A/B/C 호스트는 `Asia/Seoul`(KST)·NTP 동기화 상태이며, 10/08 재확인했다. B 상태 요약은 09·21 KST다. 일부 컨테이너·원본 로그는 UTC로 표시될 수 있다.
- A의 n8n은 10/08 SSH 점검에서 컨테이너·이미지·서비스·프로세스·일반 설치 경로·5678 수신 흔적이 없어 현재 배포·가동된 근거가 없다. 자동화는 B Hermes·SOC 봇·systemd 타이머가 담당한다.
- A의 Log4Shell 시나리오 경로 토글은 현재 OFF다. 저장소 스크립트에는 `OBS_SEG` 관찰 룰이 있지만 A에 설치된 스크립트에는 없어 재배포·경로 검증이 필요하다.
- 저장소의 [groot-a/docker-compose.yml](groot-a/docker-compose.yml)은 초기 배포 템플릿으로, 위 라이브 WAF 룰 마운트와 Suricata `all.rules`·Phase-A 옵션이 반영되지 않았다. A에 재배포하기 전 라이브 Compose와 대조해야 한다. [10월 6일 기존 기록](../대화기록/2026-10-06.md)과 이번 SSH 재확인 내용을 구분한다.

```
infra/
├── groot-a/   # 보안장비: nftables(FW, 호스트) + Suricata(IPS) + ModSecurity(WAF)
├── groot-b/   # SIEM+MCP: Wazuh(공식 docker) + MCP Server
└── groot-c/   # 웹서버: DVWA 베어메탈 + CVE 실험 컨테이너 연동
```

## 배포 순서 (요약)
1. 네트워크·게이트웨이(Groot_A 호스트 nftables) → [PLAN.md](../PLAN.md) 1단계와 [A 운영 문서](groot-a/README.md)
2. `groot-a`: nftables 적용 후 `docker compose up -d` (Suricata·WAF)
3. `groot-c`: [C 표준 설정](groot-c/C_구축_표준설정.md)에 따라 베어메탈 DVWA와 Log4Shell 랩 컨테이너 구성·검증. 이전 DVWA/DB/CVE 통합 Compose 초안은 현 배포와 달라 제거했다.
4. `groot-b`: Wazuh 공식 single-node 배포 후 MCP Server, Agent를 A·C에 설치

## 공통 주의 (구축 시 확정 = TODO)
- 이미지 태그는 최신 확인 후 **고정(pin)** 한다(재현성).
- IP(2세그먼트): 내부망 `10.200.10.0/24` — Groot_A=`.1`(NAT GW)·Groot_B=`.10`·Groot_C=`.20`(ens160). A의 외부 `ens192`는 `192.168.16.230/25`(직결 `192.168.16.128/25`, GW `.129`)다. B/C의 옛 외부 주소 `.231`/`.232`는 제거됐다. A의 10443 DNAT 허용 소스와 저장소 `OBS_SEG`는 별도 `192.168.16.0/25`로 설정돼 있어 Kali 주소·라우팅 확인이 필요하다. 외부/DMZ/관리 3세그먼트 분리는 미채택.
- 자격증명·비밀번호는 `.env`로 분리하고 git에 커밋하지 않는다(`.gitignore`).
- 격리 실험 환경 전용. 외부에 노출 금지.
