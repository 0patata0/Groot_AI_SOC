# infra — Docker 기반 배포 (B-1)

각 ESXi VM(Groot_A/B/C)에서 실행할 Docker Compose·설정 스타터. 배포 순서·검증은 [../인프라_구축순서.md](../인프라_구축순서.md), 사양은 [../PLAN.md](../PLAN.md) 1.5 참조.

```
infra/
├── groot-a/   # 보안장비: nftables(FW, 호스트) + Suricata(IPS) + ModSecurity(WAF)
├── groot-b/   # SIEM+MCP: Wazuh(공식 docker) + MCP Server
└── groot-c/   # 웹서버: DVWA + DB + CVE 취약 컨테이너
```

## 배포 순서 (요약)
1. 네트워크·게이트웨이(Groot_A 호스트 nftables) → 인프라_구축순서.md Phase 1~2
2. `groot-a`: nftables 적용 후 `docker compose up -d` (Suricata·WAF)
3. `groot-c`: `docker compose up -d` (DVWA·DB·CVE)
4. `groot-b`: Wazuh 공식 single-node 배포 후 MCP Server, Agent를 A·C에 설치

## 공통 주의 (구축 시 확정 = TODO)
- 이미지 태그는 최신 확인 후 **고정(pin)** 한다(재현성).
- IP(2세그먼트, 2026-09-29 실태): 내부망 `10.200.10.0/24` — Groot_A=`.1`(NAT GW)·Groot_B=`.10`·Groot_C=`.20`(ens160). 임시 외부망 `192.168.16.0/25` — A=`.230`·B=`.231`·C=`.232`(ens192, GW `.129`). 외부/DMZ/관리 3세그먼트 분리는 미채택.
- 자격증명·비밀번호는 `.env`로 분리하고 git에 커밋하지 않는다(`.gitignore`).
- 격리 실험 환경 전용. 외부에 노출 금지.
