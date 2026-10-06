# Agentic SOC 실행 계획 — Kubernetes(k3s) 변형 (PLAN_2)

> 상태(2026-09-22): **보류.** 마감 역산(11/24 freeze, 실측 버퍼) 결과 이 프로젝트는 B-1(Docker Compose)로 확정했다. 이 문서는 두 방식을 비교·검토한 근거로 보존한다(발표·보고서에서 "왜 Compose인가"의 답). 지도교수가 오케스트레이션을 평가 대상으로 명시하면 재검토.

이 문서는 [PLAN.md](../PLAN.md)(Docker Compose, B-1)의 **오케스트레이션 대안 B-2(k3s)** 버전이다. 아키텍처·모델·MCP 보안경계·공격 시나리오·평가 방법은 작성 당시 PLAN.md를 전제로 했으며, 여기서는 컨테이너를 k3s로 배포하는 방식의 차이·추가 작업·마찰점만 상세화한다.

- 공유(작성 당시): 네트워크/IP 설계와 세그먼트, 모델·보안장비·시나리오·평가 지표 → [PLAN.md](../PLAN.md)와 Git 이력에 보존된 삭제 전 `인프라_구축순서.md` 참조.
- 이 문서 고유: k3s 클러스터 토폴로지, 컴포넌트→k8s 리소스 매핑, k8s 특화 구축 순서, k8s 고유 리스크.

---

## 0. 언제 이 안(B-2)을 택하나

- 오케스트레이션 학습·선언적 배포가 과제 목표에 포함될 때.
- 그렇지 않으면 B-1(Compose)이 더 빠르고 안정적이다(특히 Suricata inline·Wazuh). 본 문서는 "B-2로 가기로 한 경우"의 실행안이다.

### 0.1 B-1(Compose) vs B-2(k3s) 비교표

| 관점 | B-1 Docker Compose (PLAN.md) | B-2 Kubernetes/k3s (본 문서) |
|---|---|---|
| 구축 시간·난이도 | 짧음 · 낮음 | 김 · 높음 |
| 오케스트레이션 학습 효과 | 낮음 | 높음(선언적 배포·RBAC·NetworkPolicy) |
| FW (nftables) | 호스트에 자연스럽게 | 호스트 유지(k8s 밖), 마찰 |
| IPS (Suricata inline) | 컨테이너 inline 단순 | 특권 DaemonSet·NFQUEUE 복잡 |
| WAF (ModSecurity+CRS) | nginx 컨테이너 | ingress-nginx+CRS로 자연스러움 (유리) |
| 앱(DVWA/DB/CVE) | compose 간단 | Deployment/StatefulSet, 약간 더 |
| Wazuh | all-in-one 간단 | 매니페스트·PVC·튜닝 부담 |
| MCP / 자격증명 격리 | 별도 프로세스 | Secret+RBAC, 오히려 강화 |
| 상태·스토리지 | 볼륨 마운트 | PVC/StorageClass 필요 |
| 네트워크 격리 | 세그먼트 + compose 네트워크 | + NetworkPolicy(Calico) 세밀 |
| 확장·재현성 | 중간 | 높음(선언적) |
| 디버깅 | 쉬움(docker logs) | 러닝커브(kubectl) |
| 일정 리스크 | 낮음 | 높음 |
| 권장 | 기본(안전) | 오케스트레이션 학습이 목표일 때 |

요약: WAF·앱·MCP·자격증명 격리는 k8s가 유리하거나 대등하고, FW/IPS 네트워크 관문과 Wazuh 운영·일정에서 k8s가 불리하다.

---

## 1. k3s 클러스터 토폴로지

물리(VM) 배치는 PLAN.md와 동일(Groot_A/B/C + Kali + DGX Spark). 세 VM을 하나의 k3s 클러스터 노드로 구성하고, 역할별로 노드 라벨을 붙여 파드를 고정 배치한다.

| 노드(VM) | k3s 역할 | 노드 라벨 | 올라가는 워크로드 |
|---|---|---|---|
| Groot_B | server (control-plane) | role=siem | Wazuh(Indexer/Manager/Dashboard), MCP Server |
| Groot_A | agent | role=security | Suricata(IPS), ModSecurity(WAF/ingress) |
| Groot_C | agent | role=web | DVWA, CVE 취약 컨테이너, DB |
| DGX Spark | 클러스터 밖 | - | vLLM + Agent Runtime + Policy Engine (k8s 미탑재) |

- 네임스페이스: `security`(WAF/IPS), `web`(DVWA/CVE), `siem`(Wazuh/MCP).
- CNI: k3s 기본 flannel은 NetworkPolicy를 강제하지 않으므로 **Calico로 교체**하여 파드 레벨 격리를 강제한다. VM NIC 세그먼트(EXT/DMZ/MGMT)는 그대로 유지되고, NetworkPolicy는 그 위에 더한다.
- 스토리지: Wazuh Indexer는 상태 저장이 필요하므로 PVC 사용. k3s 기본 local-path provisioner(단순) 또는 Longhorn(복제).

---

## 1.5 사양표 (B-2 k3s) — 오버헤드 반영

실제 ESXi 호스트: Xeon Gold 5215 20 논리CPU, RAM 256 GB(공유). C=vCPU. control-plane·Calico·PVC 오버헤드로 B-1보다 한 단계 높지만, 여전히 호스트의 절반 이하 CPU만 사용.

이 호스트에 Groot_A/B/C만 올린다(DGX Spark·Kali는 외부).

| 노드 | k3s 역할 | 목표 |
|---|---|---|
| Groot_B | server(control-plane)+siem | **4C / 18G / 180G** |
| Groot_A | agent+security | **3C / 8G / 70G** |
| Groot_C | agent+web | **2C / 8G / 70G** |
| 우리 몫 합계 | | **9C / 34G / 320G** (호스트 CPU ~45%, RAM ~13%) |

- B-1(PLAN.md 1.5) 대비: 오버헤드로 CPU 8→9, RAM 28→34G. RAM은 256G라 부담 없음.
- Wazuh Indexer가 병목 — RAM 18G 넉넉히 + StatefulSet PVC·메모리 limit 설정. CPU는 공유 배려로 보수적.
- 데이터스토어 여유 ≥ 350G 확인 필요. DGX Spark·Kali는 B-1과 동일(외부).

## 2. 컴포넌트 → k8s 리소스 매핑 (핵심 차이)

| 역할 | B-1 Compose | B-2 k3s | k8s 적합도 |
|---|---|---|---|
| FW | Groot_A 호스트 nftables | **호스트 nftables 유지(k8s 밖)** + Calico NetworkPolicy로 파드 격리 | 낮음 — 네트워크 관문은 노드 호스트 레벨 유지 |
| IPS | Suricata inline 컨테이너 | **DaemonSet**, hostNetwork + `NET_ADMIN`/`NET_RAW`, privileged. inline(NFQUEUE)은 난이도↑ → 초기 IDS(passive)로 | 낮음 — 특권·hostNetwork 필요 |
| WAF | ModSecurity+nginx 컨테이너 | **ingress-nginx + ModSecurity(OWASP CRS)** 로 자연스럽게 구현. Ingress 리소스로 DVWA 라우팅 | 높음 — k8s에 잘 맞음 |
| DVWA/DB | compose | **Deployment + Service**, DB는 StatefulSet+PVC | 높음 |
| CVE 컨테이너 | compose | **Deployment**(namespace web) | 높음 |
| Wazuh | all-in-one compose | **공식 Wazuh Kubernetes 매니페스트/Helm**. Indexer=StatefulSet+PVC, Manager=Deployment/StatefulSet, Dashboard=Deployment | 중간 — 공식 지원 있으나 무겁고 튜닝 필요 |
| MCP Server | Groot_B 컨테이너 | **Deployment**(namespace siem), 자격증명은 **k8s Secret**으로 주입 | 높음 |
| LLM/Agent | DGX Spark | **동일(클러스터 밖 DGX Spark)**. Agent가 MGMT로 클러스터의 Wazuh/MCP Service 접근 | - |

핵심: WAF·앱·Wazuh·MCP는 k8s로 깔끔해지지만, **FW/IPS 같은 네트워크 관문 계층이 k8s와 마찰**한다. 이 부분은 호스트 레벨로 남기거나 특권 DaemonSet으로 우회한다. 자격증명 격리(A안)는 오히려 강화된다 — MCP는 Secret을 마운트하고, Agent는 클러스터 밖 DGX Spark라 자격증명과 물리적으로 분리된다.

---

## 3. 구축 순서 (k8s 특화 부분만)

Phase 0~1(ESXi·VM·네트워크·게이트웨이)과 6(공격·검증)은 작성 당시 B-1 원본 `인프라_구축순서.md`를 전제로 했다(원본은 2026-10-06 삭제, Git 이력에서 확인). 아래는 당시 달라지는 Phase 2~5의 기록이다.

### Phase 2k. k3s 클러스터 부트스트랩
- [ ] Groot_B에 k3s server 설치(`--flannel-backend=none`로 Calico 사용 준비), Groot_A·Groot_C를 agent로 join
- [ ] Calico CNI 설치, 노드 라벨 부여(role=siem/security/web), 네임스페이스 3개 생성
- [ ] local-path 또는 Longhorn 스토리지클래스 확인
- ✅ `kubectl get nodes`에 3노드 Ready, 라벨 확인, 테스트 파드 스케줄

### Phase 3k. 보안장비 (Groot_A, role=security)
- [ ] FW: Groot_A 호스트 nftables는 k8s 밖에서 그대로 구성(관문·NFQUEUE·agent_block 체인) — 인프라 런북 2-2와 동일
- [ ] IPS: Suricata **DaemonSet**(nodeSelector role=security, hostNetwork, NET_ADMIN). 초기 IDS로 시작
- [ ] WAF: `ingress-nginx`(ModSecurity+OWASP CRS 활성) 배포, Ingress로 DVWA(web ns) 라우팅. 초기 DetectionOnly
- [ ] eve.json / ModSec audit log를 hostPath 볼륨으로 노출(Wazuh Agent가 수집)
- ✅ nmap 시 Suricata 이벤트, SQLi 시 ModSec 로그. Ingress 경유 DVWA 접근

### Phase 4k. 메인서버 (Groot_C, role=web)
- [ ] DVWA Deployment+Service, DB StatefulSet+PVC
- [ ] CVE 취약 컨테이너 Deployment(Log4Shell). 권한상승용 취약 sudo는 노드 OS 레벨
- [ ] 웹로그를 hostPath 또는 사이드카로 노출
- ✅ Ingress(WAF) 통해 DVWA 표시, 로그 생성

### Phase 5k. SIEM + MCP (Groot_B, role=siem)
- [ ] Wazuh Kubernetes 매니페스트로 Indexer(StatefulSet+PVC)/Manager/Dashboard 배포
- [ ] Wazuh Agent는 각 노드(Groot_A/C)에 **DaemonSet 또는 호스트 설치**로 배치, Manager(siem ns Service)로 등록
- [ ] Vulnerability Detection, Suricata/ModSec/웹 로그 수집 설정
- [ ] MCP Server Deployment(siem ns), 자격증명은 k8s **Secret**(Wazuh API 등). RBAC로 최소 권한
- [ ] Active Response가 Groot_A 호스트 nftables(agent_block)를 조작하도록 연결
- ✅ Dashboard 접근, Agent Active, 취약점에 CVE-2021-3156 매핑, DGX Spark에서 MCP Service 호출 성공

### Phase 5k+. LLM Agent (DGX Spark, 클러스터 밖)
- [ ] PLAN.md Phase 5와 동일. MGMT로 Wazuh Indexer/MCP Service(NodePort 또는 LoadBalancer/klipper-lb)에 접근
- ✅ 테스트 Alert 조사 완결

---

## 4. k8s 고유 리스크·마찰점

| 항목 | 내용 | 대응 |
|---|---|---|
| Suricata inline | 특권 DaemonSet·hostNetwork·NFQUEUE 연동 복잡 | 초기 IDS(passive)로 시작, 안정화 후 inline |
| NetworkPolicy 미강제 | k3s 기본 flannel은 정책 강제 안 함 | Calico로 교체 |
| Wazuh on k8s | Indexer 메모리·PVC·초기 튜닝 부담 | 리소스 request/limit 설정, 안 되면 Wazuh만 노드에 직접 설치(하이브리드) |
| 서비스 노출 | Agent(클러스터 밖)가 클러스터 서비스 접근 | NodePort 또는 klipper-lb, MGMT 세그먼트로 한정 |
| 구축 시간 | Compose 대비 김 | 일정 초과 시 B-1(Compose)로 회귀 — 아키텍처 동일해 전환 비용 낮음 |
| 상태 저장 | Indexer 데이터 유실 위험 | PVC + 백업, 스냅샷 |

---

## 5. B-1 ↔ B-2 전환성

아키텍처(Groot 역할, 네트워크, MCP 경계, 시나리오, 평가)가 동일하므로 두 안은 오케스트레이션 계층만 다르다. 따라서 B-2로 시작했다가 막히면 B-1(Compose)로 되돌리는 비용이 낮다. 반대도 성립. 평가 단계에서는 두 방식이 같은 시나리오·지표를 쓰므로 결과 비교에 영향이 없다.

---

## 진행 로그
### 2026-09-22
- k3s 대안 계획(PLAN_2) 신규 작성. PLAN.md(Compose)와 아키텍처 공유, 오케스트레이션만 k3s. 컴포넌트→k8s 리소스 매핑, k8s 특화 Phase 2k~5k, 고유 리스크 정리.
- 정직한 구분: WAF(ingress-nginx+ModSecurity)·앱·Wazuh·MCP는 k8s 적합, FW/IPS 네트워크 관문은 호스트/특권 DaemonSet으로 마찰.
