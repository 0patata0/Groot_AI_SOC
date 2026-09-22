# 제안서 — Kubernetes(k3s) 변형 (suggestion_2)

이 문서는 [suggestion.md](suggestion.md)의 **오케스트레이션 k3s 변형**이다. 프로젝트 목표·배경·모델(Qwen3-30B-A3B)·MCP 보안경계·공격 시나리오(DVWA+CVE)·평가 방법은 suggestion.md와 동일하며, 여기서는 컨테이너를 Kubernetes(k3s)로 배포할 때 달라지는 구성만 서술한다. 실행 절차는 [PLAN_2.md](PLAN_2.md)·[인프라_구축순서_2.md](인프라_구축순서_2.md) 참조.

> 공유(변경 없음): 1장 배경, 2장 목표, 7장 AI Agent(DGX Spark), 9장 차별점, 10장 Policy Engine, 11장 Fine-tuning, 12장 취약점, 13장 시나리오, 14장 평가, 15·16장 → suggestion.md 그대로. 아래는 3~6·8장의 k3s 변형.

---

## 3v. 전체 시스템 구성 (k3s)

물리 배치(ESXi VM 3대 + Kali + DGX Spark)와 세그먼트(EXT/DMZ/MGMT)는 동일. 세 VM을 하나의 k3s 클러스터 노드로 묶고 역할 라벨로 파드를 고정한다.

```
    [ 공격자 노트북 : Kali ]  (EXT)
            |  공격 트래픽
            v
=========  ESXi 호스트 / k3s 클러스터  =========

노드 Groot_A  (role=security)   [FW는 호스트 nftables]
    |-- Suricata (DaemonSet, hostNetwork, IPS)
    +-- ingress-nginx + ModSecurity/OWASP CRS (WAF)
            |  Ingress 라우팅
            v
노드 Groot_C  (role=web)
    |-- DVWA (Deployment) + DB (StatefulSet)
    +-- CVE 취약 컨테이너 (Deployment, Log4Shell 등)
            |  로그 · 이벤트
            v
노드 Groot_B  (role=siem, k3s control-plane)
    |-- Wazuh (Indexer=StatefulSet, Manager/Dashboard=Deployment)
    +-- MCP Server (Deployment)                    [Secret 보유]

===============================================
            |  MCP 호출 (자격증명 없는 Agent)
            v
DGX Spark (클러스터 밖)                            [자격증명 없음]
    |-- vLLM (Qwen3-30B-A3B)
    |-- Agent Runtime (MCP Client)
    +-- Policy Engine
```

- 네임스페이스: security / web / siem. CNI는 Calico(NetworkPolicy 강제). 스토리지는 PVC(local-path 또는 Longhorn).
- FW(nftables)는 Groot_A 노드의 호스트 레벨로 유지하고, 파드 레벨 격리는 NetworkPolicy로 더한다.
- 자격증명 격리(A안)는 강화된다: MCP는 k8s Secret을 마운트하고, Agent는 클러스터 밖 DGX Spark라 물리적으로 분리된다.

## 4v. 보안장비 (Groot_A, role=security)

| 역할 | k8s 구현 | 비고 |
|---|---|---|
| FW | 호스트 nftables (k8s 밖) + Calico NetworkPolicy | 관문·NFQUEUE·agent_block 체인은 호스트에서. Response Tool이 규칙 조작 |
| IPS | Suricata DaemonSet (hostNetwork, NET_ADMIN/NET_RAW) | 초기 IDS(passive) → 안정화 후 inline(NFQUEUE) |
| WAF | ingress-nginx + ModSecurity v3 + OWASP CRS | Ingress로 DVWA 라우팅. 초기 DetectionOnly → On |

로그(eve.json, ModSec audit)는 hostPath/사이드카로 노출하여 Wazuh Agent가 수집한다.

## 5v. 메인서버 (Groot_C, role=web)

- DVWA: Deployment + Service. 진입은 WAF(Ingress) 경유가 정상 경로.
- DB: StatefulSet + PVC.
- CVE 취약 컨테이너: Deployment(Log4Shell). 권한상승용 취약 sudo는 노드 OS 레벨.
- 수집: 웹로그(hostPath/사이드카), Docker 대신 containerd 이벤트, FIM/Syscollector는 노드의 Wazuh Agent가 담당.

## 6v. SIEM — Wazuh (Groot_B, role=siem)

- Wazuh Kubernetes 매니페스트: Indexer(StatefulSet+PVC), Manager, Dashboard.
- Wazuh Agent: 각 노드(Groot_A/C)에 DaemonSet 또는 호스트 설치로 배치, Manager Service로 등록.
- Alert는 suggestion.md와 동일하게 Agent(DGX Spark)가 Indexer를 폴링. 클러스터 서비스 노출은 NodePort/klipper-lb를 MGMT로 한정.

## 8v. MCP 연동 (자격증명 격리 강화)

- MCP Server는 siem 네임스페이스 Deployment. 자격증명(Wazuh API 키, FW 접근)은 **k8s Secret**으로 주입하고 RBAC로 최소 권한.
- Tool 데이터 소스는 suggestion.md 8장과 동일(Wazuh Indexer/Server API, Suricata·WAF 이벤트, Groot_A FW 로그, NVD/KEV). 차이는 Response Tool의 서버 격리가 NetworkPolicy 격리 + 호스트 nftables 조작으로 구현된다는 점.
- 신뢰 경계: Agent(DGX Spark, 클러스터 밖, 자격증명 없음) → MCP Client → [경계] → MCP Server(Secret 보유, 클러스터 내). 물리·논리 이중 분리.

---

## 선정 기준 (요약)

- k3s가 유리: WAF(ingress-nginx+CRS), 선언적 배포·재현성, 자격증명 격리(Secret/RBAC).
- k3s가 불리: FW/IPS 네트워크 관문(호스트/특권 필요), Wazuh 운영 부담, 구축 시간.
- 결론: 오케스트레이션 학습을 과제 목표로 삼으면 k3s(B-2), 아니면 Compose(B-1, suggestion.md 본안). 비교표는 [PLAN_2.md](PLAN_2.md) 0.1 참조.
