# infra — Docker 기반 배포 (B-1)

각 ESXi VM(Groot_A/B/C)의 Docker Compose·설정·운영 문서. 아래 배포 순서는 최초 구축 이력이다. 현재 단계와 사양은 [PLAN.md](../PLAN.md), 호스트별 절차는 [A](groot-a/README.md)·[B](groot-b/README.md)·[C](groot-c/C_구축_표준설정.md) 문서를 참조한다.

## 현재 상태 (2026-10-06 기록 및 이번 SSH 재확인)
- B/C의 `ens192` vNIC는 제거됐고 기본 경로는 A(`10.200.10.1`)를 지난다. 외부망 주소 `.231`/`.232`는 과거 설치 주소다.
- A의 FW v2는 적용·확정됐다(`FORWARD=DROP`, `CAPSTONE-FWD` 14룰). WAF의 GROOT 커스텀 룰 마운트·`DetectionOnly`·`nginx -t` 통과와 Suricata의 ET+로컬 `all.rules`·Phase-A 수동 탐지 설정을 SSH로 재확인했다.
- B의 Wazuh 에이전트 000/001/002는 Active다. B의 `local_decoder.xml`·`local_rules.xml`에 신규 신호 전용 항목은 없지만, IPS 로컬 SID는 기존 Suricata 분류로 처리될 수 있어 **실제 분류는 미확인**이다. 공격 트래픽 실발화도 미검증이다. WAF `On`·IPS 인라인 차단 전환은 별도 작업이다.
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
