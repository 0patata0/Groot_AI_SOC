# 설계 대안 이력

이 문서는 과거 기록입니다. 현재 상태는 [STATUS](../STATUS.md), 실행 계획은 [PLAN](../PLAN.md)을 따릅니다. 같은 내용을 반복한 부분은 하나의 본문으로 연결했습니다. 서로 다른 날짜·판단·실패·정정은 합쳐 단정하지 않습니다. [정리·복원 안내](README.md).

## 교차 검토의 종류 참조·자유 서술 제한·수치 결속 (2026-11-14)

[세 설계 비교](../infra/validation/peer-proof-kinds/README.md)는 과거 조회 출처를 현재 근거와 분리하는 공통 경계를 실험했다. R1의 자유문장 우회, R2의 잘못된 분류, R3의 값 결속 뒤에도 남은 표본/전체 오독으로 모두 보류했다. 강제 값 결속은 의미 검증을 대신하지 않는다. 소스 정본/설치 입력은 유지하고 각 패치의6/6/7파일 복원 SHA를 확인했다. 모델 변경·보호 경계 완화로 통과 수를 높이지 않았다. 아래 k3s 전환 대안은 별개의 과거 기록이다.

| 원문 마지막 Git 기록(KST) | 보존한 문서 |
|---|---|
| 2026-10-06T14:43:26+09:00 | [인프라_구축순서_2.md](#source-5b415158725ce466) |
| 2026-10-06T14:43:26+09:00 | [PLAN_2.md](#source-a2270ebcec45d64e) |
| 2026-09-27T04:14:30+09:00 | [suggestion_2.md](#source-ecaa84fc6e2f7f15) |

<a id="source-5b415158725ce466"></a>

## 인프라_구축순서_2.md

<details>
<summary>당시 기록 펼치기 · 2026-10-06T14:43:26+09:00</summary>

<a id="source-5b415158725ce466-h0"></a>
<a id="record-7c11ace849c6198990db2bb0cf4d3cc53e812e66a3b23dc8f4da91a370969260"></a>

# 인프라 구축 순서 — Kubernetes(k3s) 변형 (런북 2)

작성 당시 B-1 원본 `인프라_구축순서.md`(Docker Compose)의 k3s 변형 기록이다. 원본은 2026-10-06 사용자가 삭제했으며 Git 이력에 남아 있다. Phase 0·1·6은 이 문서에 없으므로 **이 파일만으로 배포하지 않는다**. 아래는 당시 달라지는 Phase 2k~5k만 상세화한다.
관련: [PLAN_2.md](DESIGN_ALTERNATIVES.md#source-a2270ebcec45d64e) · [suggestion_2.md](DESIGN_ALTERNATIVES.md#source-ecaa84fc6e2f7f15)

각 단계 [작업 → 명령/설정 → ✅ 검증]. 검증 통과 후 다음 단계.

---



<a id="source-5b415158725ce466-h1"></a>
<a id="record-7ed3de1e9488ef1a5a7557c8650530b318b2de653803c464c80f62b657e3ac45"></a>

## 공유 전제 (원본과 동일)
- 세그먼트: EXT 192.168.10.0/24, DMZ 172.16.20.0/24, MGMT 10.10.10.0/24
- 노드: Groot_B(control-plane, role=siem, MGMT .10) / Groot_A(agent, role=security, EXT+DMZ+MGMT) / Groot_C(agent, role=web, DMZ+MGMT)
- FW(nftables)는 Groot_A 호스트 레벨(인프라_구축순서.md Phase 2-2와 동일) — k3s 밖
- LLM Agent는 DGX Spark(클러스터 밖, MGMT .50)

---



<a id="source-5b415158725ce466-h2"></a>
<a id="source-5b415158725ce466-h3"></a>
<a id="source-5b415158725ce466-h4"></a>
<a id="source-5b415158725ce466-h5"></a>
<a id="source-5b415158725ce466-h6"></a>
<a id="source-5b415158725ce466-h7"></a>
<a id="record-d887724ac338a62a9e8a46868b258639e3a7eddd2f16352528cdb319e07e6de9"></a>

## Phase 2k. k3s 클러스터 부트스트랩

### 2k-1. 사전 (모든 노드)
- [ ] Docker 대신 containerd(k3s 내장) 사용. swap off, 필요한 커널 모듈(br_netfilter) 로드
- [ ] 각 노드 시간 동기화(chrony), 호스트명·hosts 정리
- ✅ `swapoff -a`, `sysctl net.bridge.bridge-nf-call-iptables=1`

### 2k-2. k3s server (Groot_B) — flannel 끄고 Calico 준비
- [ ] `curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--flannel-backend=none --disable-network-policy --node-ip=10.10.10.10" sh -`
- [ ] node-token 확보(`/var/lib/rancher/k3s/server/node-token`)
- ✅ `kubectl get node` → Groot_B NotReady(CNI 미설치 상태 정상)

### 2k-3. Calico CNI
- [ ] Calico 매니페스트 적용, MGMT 대역과 충돌 없는 podCIDR 설정
- ✅ `kubectl get pods -n kube-system`의 calico 파드 Running, Groot_B Ready

### 2k-4. agent join (Groot_A, Groot_C)
- [ ] 각 노드: `curl -sfL https://get.k3s.io | K3S_URL=https://10.10.10.10:6443 K3S_TOKEN=<token> INSTALL_K3S_EXEC="--node-ip=<mgmt-ip>" sh -`
- ✅ `kubectl get nodes` → 3노드 Ready

### 2k-5. 라벨·네임스페이스·스토리지
- [ ] `kubectl label node groot-a role=security` / groot-b role=siem / groot-c role=web
- [ ] 네임스페이스: `kubectl create ns security web siem`
- [ ] 스토리지클래스 확인(local-path 기본) 또는 Longhorn 설치
- ✅ 라벨·네임스페이스 확인, 테스트 PVC 바인딩

---



<a id="source-5b415158725ce466-h10"></a>
<a id="source-5b415158725ce466-h11"></a>
<a id="source-5b415158725ce466-h8"></a>
<a id="source-5b415158725ce466-h9"></a>
<a id="record-74536189c4bc3923b97f03e804158da0462063e352a92bceeb0514758bacb72d"></a>

## Phase 3k. 보안장비 (role=security)

### 3k-1. FW (호스트 nftables)
- [ ] Groot_A 호스트에 nftables 관문 규칙(인프라_구축순서.md 2-2와 동일): EXT→DMZ 80/443, NFQUEUE, agent_block 체인
- ✅ `nft list ruleset` 정상, 정상 웹 통과

### 3k-2. IPS (Suricata DaemonSet)
- [ ] DaemonSet 매니페스트: nodeSelector role=security, hostNetwork:true, securityContext capabilities NET_ADMIN/NET_RAW, ET Open 룰, eve.json→hostPath
- [ ] 초기 IDS(passive, af-packet). 안정화 후 NFQUEUE inline 전환
- ✅ `kubectl -n security get ds`, Kali nmap 시 eve.json에 ET SCAN

### 3k-3. WAF (ingress-nginx + ModSecurity)
- [ ] ingress-nginx 배포(ModSecurity+OWASP CRS 활성 옵션), nodeSelector role=security
- [ ] Ingress 리소스로 DVWA(web ns Service) 라우팅. 초기 SecRuleEngine DetectionOnly
- [ ] ModSec audit log→hostPath
- ✅ Ingress 경유 DVWA 표시, SQLi 요청 시 audit log에 CRS 매칭

---



<a id="source-5b415158725ce466-h12"></a>
<a id="source-5b415158725ce466-h13"></a>
<a id="source-5b415158725ce466-h14"></a>
<a id="source-5b415158725ce466-h15"></a>
<a id="record-79a62b4a94c30ad3d840cfc6d3a695cf6a6d928d8d1241d00e678b0543f836cc"></a>

## Phase 4k. 메인서버 (role=web)

### 4k-1. DVWA + DB
- [ ] DVWA Deployment + Service(web ns), DB StatefulSet + PVC
- [ ] 웹로그 hostPath 또는 로그 사이드카
- ✅ Ingress(WAF) 통해 DVWA 접근, 로그 생성

### 4k-2. CVE 취약 컨테이너
- [ ] Log4Shell 취약 앱 Deployment. 권한상승용 취약 sudo는 Groot_C 노드 OS
- ✅ 취약 앱 기동, 버전 확인

### 4k-3. NetworkPolicy
- [ ] web ns: EXT/보안 네임스페이스에서 오는 정상 경로만 허용, 그 외 deny
- ✅ 정책 적용 후 비정상 경로 차단 확인

---



<a id="source-5b415158725ce466-h16"></a>
<a id="source-5b415158725ce466-h17"></a>
<a id="source-5b415158725ce466-h18"></a>
<a id="source-5b415158725ce466-h19"></a>
<a id="source-5b415158725ce466-h20"></a>
<a id="record-110a8731a3272ecfe25f11c19364c58cf78697b888c17a40f80e73baf1f87cea"></a>

## Phase 5k. SIEM + MCP (role=siem)

### 5k-1. Wazuh (k8s)
- [ ] Wazuh Kubernetes 매니페스트: Indexer StatefulSet+PVC, Manager, Dashboard(siem ns). 리소스 request/limit 설정
- ✅ Dashboard(MGMT NodePort) 접속, Indexer/Server API 응답

### 5k-2. Wazuh Agent (노드)
- [ ] Groot_A/C에 Agent DaemonSet 또는 호스트 설치, Manager Service로 등록
- [ ] 로그 소스: Suricata eve, ModSec audit(hostPath), 웹로그, FIM, Syscollector, Vulnerability Detection
- ✅ 두 노드 Agent Active, 취약점에 CVE-2021-3156 매핑

### 5k-3. MCP Server + Secret
- [ ] MCP Server Deployment(siem ns), 자격증명은 `kubectl create secret`로 생성해 env/volume 주입, RBAC 최소 권한
- [ ] Active Response가 Groot_A 호스트 nftables(agent_block) 조작하도록 연결
- ✅ DGX Spark에서 MCP Service(NodePort/MGMT) 읽기 Tool 호출 성공, Agent 측 자격증명 없음 확인

### 5k-4. LLM Agent (DGX Spark, 클러스터 밖)
- [ ] 인프라_구축순서.md Phase 5와 동일. MGMT로 Wazuh Indexer·MCP Service 접근
- ✅ 테스트 Alert 조사 완결

---



<a id="source-5b415158725ce466-h21"></a>
<a id="record-f067fe9a01227a71f777faa9ba46419dfbdd5ea10d6965f7dd0b4be275b0fb2e"></a>

## Phase 6. 공격·검증
- 인프라_구축순서.md Phase 6과 동일(Kali S1~S3, rule id 기록).

---



<a id="source-5b415158725ce466-h22"></a>
<a id="record-9c5d27ef5bd9a547a38a863b5915e4595cab462b41e1273293396d26a4eec68e"></a>

## k3s 특화 체크포인트
- Calico 안 깔면 NetworkPolicy가 무시된다(k3s 기본). 반드시 CNI 교체 후 정책 적용.
- Suricata inline은 hostNetwork+특권이 필요. 초기엔 IDS로 시작해 파이프라인부터 완성.
- Wazuh Indexer OOM 주의: PVC·메모리 limit 설정, 안 되면 Wazuh만 노드 직접 설치(하이브리드)로 회귀.
- 서비스 노출은 NodePort를 MGMT 세그먼트로 한정(EXT 노출 금지).
- 막히면 B-1(Compose, 인프라_구축순서.md)로 회귀 — 아키텍처 동일해 전환 비용 낮음.


</details>

<a id="source-a2270ebcec45d64e"></a>

## PLAN_2.md

<details>
<summary>당시 기록 펼치기 · 2026-10-06T14:43:26+09:00</summary>

<a id="source-a2270ebcec45d64e-h0"></a>
<a id="record-66b82fc4083af464416a67e90db0985e32d21bec3722253e72bfc9eb95811b3b"></a>

# Agentic SOC 실행 계획 — Kubernetes(k3s) 변형 (PLAN_2)

> 상태(2026-09-22): **보류.** 마감 역산(11/24 freeze, 실측 버퍼) 결과 이 프로젝트는 B-1(Docker Compose)로 확정했다. 이 문서는 두 방식을 비교·검토한 근거로 보존한다(발표·보고서에서 "왜 Compose인가"의 답). 지도교수가 오케스트레이션을 평가 대상으로 명시하면 재검토.

이 문서는 [PLAN.md](../PLAN.md)(Docker Compose, B-1)의 **오케스트레이션 대안 B-2(k3s)** 버전이다. 아키텍처·모델·MCP 보안경계·공격 시나리오·평가 방법은 작성 당시 PLAN.md를 전제로 했으며, 여기서는 컨테이너를 k3s로 배포하는 방식의 차이·추가 작업·마찰점만 상세화한다.

- 공유(작성 당시): 네트워크/IP 설계와 세그먼트, 모델·보안장비·시나리오·평가 지표 → [PLAN.md](../PLAN.md)와 Git 이력에 보존된 삭제 전 `인프라_구축순서.md` 참조.
- 이 문서 고유: k3s 클러스터 토폴로지, 컴포넌트→k8s 리소스 매핑, k8s 특화 구축 순서, k8s 고유 리스크.

---



<a id="source-a2270ebcec45d64e-h1"></a>
<a id="source-a2270ebcec45d64e-h2"></a>
<a id="record-66a10f09058b406eec592e0b158403f77570a4c47a0e6699e0a92e883b5e2ba2"></a>

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



<a id="source-a2270ebcec45d64e-h3"></a>
<a id="record-3e4ea95263587bf44551413a6ffb0964123caa0c00b59099d6fd556b31d657f0"></a>

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



<a id="source-a2270ebcec45d64e-h4"></a>
<a id="record-af1119822bccf97d2708d60a97d0c5475581a727fe2684f6e82b41e2dd10ff37"></a>

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



<a id="source-a2270ebcec45d64e-h5"></a>
<a id="record-82329a99a6c1ae28ff684e7ddf2de8dc02920b054aa28d2f4d5e4347858c2fe2"></a>

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



<a id="source-a2270ebcec45d64e-h10"></a>
<a id="source-a2270ebcec45d64e-h11"></a>
<a id="source-a2270ebcec45d64e-h6"></a>
<a id="source-a2270ebcec45d64e-h7"></a>
<a id="source-a2270ebcec45d64e-h8"></a>
<a id="source-a2270ebcec45d64e-h9"></a>
<a id="record-73c09105ef644fe3069bba52b93fa87320c96706fb69163c9f666e36379761dd"></a>

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



<a id="source-a2270ebcec45d64e-h12"></a>
<a id="record-e4b080126b84515033e7fe873d4c2d8c75c60f4e1b6b6bf7fdec6b60f78f5485"></a>

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



<a id="source-a2270ebcec45d64e-h13"></a>
<a id="record-f28f16da10dccb90d176393284cb9fd7a292c4e053665bbb2a47e7ba6a9635f5"></a>

## 5. B-1 ↔ B-2 전환성

아키텍처(Groot 역할, 네트워크, MCP 경계, 시나리오, 평가)가 동일하므로 두 안은 오케스트레이션 계층만 다르다. 따라서 B-2로 시작했다가 막히면 B-1(Compose)로 되돌리는 비용이 낮다. 반대도 성립. 평가 단계에서는 두 방식이 같은 시나리오·지표를 쓰므로 결과 비교에 영향이 없다.

---



<a id="source-a2270ebcec45d64e-h14"></a>
<a id="source-a2270ebcec45d64e-h15"></a>
<a id="record-2a1b6e80ea0dde4ce6b207d476f3c2248d5e4a1074335ee611a4d3f647d0fd92"></a>

## 진행 로그
### 2026-09-22
- k3s 대안 계획(PLAN_2) 신규 작성. PLAN.md(Compose)와 아키텍처 공유, 오케스트레이션만 k3s. 컴포넌트→k8s 리소스 매핑, k8s 특화 Phase 2k~5k, 고유 리스크 정리.
- 정직한 구분: WAF(ingress-nginx+ModSecurity)·앱·Wazuh·MCP는 k8s 적합, FW/IPS 네트워크 관문은 호스트/특권 DaemonSet으로 마찰.


</details>

<a id="source-ecaa84fc6e2f7f15"></a>

## suggestion_2.md

<details>
<summary>당시 기록 펼치기 · 2026-09-27T04:14:30+09:00</summary>

<a id="source-ecaa84fc6e2f7f15-h0"></a>
<a id="record-79f71f0c77e86b5427e216df692655b9488c6f7c6654322092d5fcde18c8d04f"></a>

# 제안서 — Kubernetes(k3s) 변형 (suggestion_2)

이 문서는 [suggestion.md](../suggestion.md)의 **오케스트레이션 k3s 변형**이다. 프로젝트 목표·배경·모델(Qwen3-30B-A3B)·MCP 보안경계·공격 시나리오(DVWA+CVE)·평가 방법은 suggestion.md와 동일하며, 여기서는 컨테이너를 Kubernetes(k3s)로 배포할 때 달라지는 구성만 서술한다. 실행 절차는 [PLAN_2.md](DESIGN_ALTERNATIVES.md#source-a2270ebcec45d64e)·[인프라_구축순서_2.md](DESIGN_ALTERNATIVES.md#source-5b415158725ce466) 참조.

> 공유(변경 없음): 1장 배경, 2장 목표, 7장 AI Agent(DGX Spark), 9장 차별점, 10장 Policy Engine, 11장 Fine-tuning, 12장 취약점, 13장 시나리오, 14장 평가, 15·16장 → suggestion.md 그대로. 아래는 3~6·8장의 k3s 변형.

---



<a id="source-ecaa84fc6e2f7f15-h1"></a>
<a id="record-1b59c6c084699287059edbca99ec14af7fd4ca6a88ab923e2ea69b91504ea8fb"></a>

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



<a id="source-ecaa84fc6e2f7f15-h2"></a>
<a id="record-a6aa6880c7cb031c3a8c94e624afba5a98bf75b73cd42729ebb669324e08912f"></a>

## 4v. 보안장비 (Groot_A, role=security)

| 역할 | k8s 구현 | 비고 |
|---|---|---|
| FW | 호스트 nftables (k8s 밖) + Calico NetworkPolicy | 관문·NFQUEUE·agent_block 체인은 호스트에서. Response Tool이 규칙 조작 |
| IPS | Suricata DaemonSet (hostNetwork, NET_ADMIN/NET_RAW) | 초기 IDS(passive) → 안정화 후 inline(NFQUEUE) |
| WAF | ingress-nginx + ModSecurity v3 + OWASP CRS | Ingress로 DVWA 라우팅. 초기 DetectionOnly → On |

로그(eve.json, ModSec audit)는 hostPath/사이드카로 노출하여 Wazuh Agent가 수집한다.



<a id="source-ecaa84fc6e2f7f15-h3"></a>
<a id="record-94fb1c040a793c5da3d8c64e21c6612d5cec03818d80f731626515c41da46141"></a>

## 5v. 메인서버 (Groot_C, role=web)

- DVWA: Deployment + Service. 진입은 WAF(Ingress) 경유가 정상 경로.
- DB: StatefulSet + PVC.
- CVE 취약 컨테이너: Deployment(Log4Shell). 권한상승용 취약 sudo는 노드 OS 레벨.
- 수집: 웹로그(hostPath/사이드카), Docker 대신 containerd 이벤트, FIM/Syscollector는 노드의 Wazuh Agent가 담당.



<a id="source-ecaa84fc6e2f7f15-h4"></a>
<a id="record-71e02cf20db63c9fb17df7142e7aacde21eff03e8c9407b6f5c0e2a666f86a56"></a>

## 6v. SIEM — Wazuh (Groot_B, role=siem)

- Wazuh Kubernetes 매니페스트: Indexer(StatefulSet+PVC), Manager, Dashboard.
- Wazuh Agent: 각 노드(Groot_A/C)에 DaemonSet 또는 호스트 설치로 배치, Manager Service로 등록.
- Alert는 suggestion.md와 동일하게 Agent(DGX Spark)가 Indexer를 폴링. 클러스터 서비스 노출은 NodePort/klipper-lb를 MGMT로 한정.



<a id="source-ecaa84fc6e2f7f15-h5"></a>
<a id="record-740030a2cf22066d5702e8fe7cad296dbdc1ba114e42dd11a5883cf02ef0a2de"></a>

## 8v. MCP 연동 (자격증명 격리 강화)

- MCP Server는 siem 네임스페이스 Deployment. 자격증명(Wazuh API 키, FW 접근)은 **k8s Secret**으로 주입하고 RBAC로 최소 권한.
- Tool 데이터 소스는 suggestion.md 8장과 동일(Wazuh Indexer/Server API, Suricata·WAF 이벤트, Groot_A FW 로그, NVD/KEV). 차이는 Response Tool의 서버 격리가 NetworkPolicy 격리 + 호스트 nftables 조작으로 구현된다는 점.
- 신뢰 경계: Agent(DGX Spark, 클러스터 밖, 자격증명 없음) → MCP Client → [경계] → MCP Server(Secret 보유, 클러스터 내). 물리·논리 이중 분리.

---



<a id="source-ecaa84fc6e2f7f15-h6"></a>
<a id="record-f8236da1d6d093e176b8108709d072ce54307206c85636319af4deb7784bf611"></a>

## 선정 기준 (요약)

- k3s가 유리: WAF(ingress-nginx+CRS), 선언적 배포·재현성, 자격증명 격리(Secret/RBAC).
- k3s가 불리: FW/IPS 네트워크 관문(호스트/특권 필요), Wazuh 운영 부담, 구축 시간.
- 결론: 오케스트레이션 학습을 과제 목표로 삼으면 k3s(B-2), 아니면 Compose(B-1, suggestion.md 본안). 비교표는 [PLAN_2.md](DESIGN_ALTERNATIVES.md#source-a2270ebcec45d64e) 0.1 참조.


</details>

## 2026-11-13 사건 조사 인용 안내 위치 — 세 방식 재생 비교

대표 사건 세션(11/12 21:52, 같은 사건 3회 실행)을 실제 시스템 프롬프트·메시지·운영 MCP 스키마로 Thor에서 재생했다(출력 1토큰, 4호출).

| 방식 | 프롬프트 처리 합계 | 판단 |
|---|---|---|
| A 현재: 성공 도구 목록을 시스템 메시지 끝에 추가 | 168.5초(운영 실측 168.4초와 일치) | 매 호출 맨 앞이 바뀌어 전체 재처리 |
| **B 채택: 목록이 바뀐 대화 위치에 실행 내 메모, 이후 요청에 같은 위치로 반복** | **57.7초** | 저장·실행 없음. 다음 실행에서는 첫 메모 앞까지 재사용 |
| C 메모를 대화 기록에 저장 | 54.4초 | 3초 더 빠르지만, 이전 실행의 안내가 다음 실행에 남아 인용 혼동 위험이 있어 제외 |
| (검토 후 제외) 도구 목록만 고정 | — | 이 세션의 재처리 원인이 아니었다. 단계별 도구 축소는 정확한 인자 선택을 돕는 장치이기도 하다 |
| (검토 후 제외) 끝에만 붙는 임시 안내 | — | 이 모델은 이전 프롬프트 끝에서만 이어 쓰므로 매 호출 안내가 바뀌면 같은 문제가 생긴다 |

근거·SHA·회귀는 [후보 문서](../infra/validation/citation-prefix/README.md)에 있다.

### 2026-11-13 추가 — 실제 생성 A/B 평가 결과

원복 뒤 실제 조사 판단 지점 5곳 × 시드 3회로 A(시스템 끝)와 B(대화 메모)를 실제 생성해 운영 검증 함수로 판정했다. 깨진 출력은 0/0이었다. 올바른 다음 단계는 11/15 대 13/15, 인용 오류는 2 대 0, 상태 줄 누락은 2 대 2였다. B가 나쁘다는 근거는 없어 B 유지를 권고한다(재적용은 승인과 운영 비율 감시를 조건으로 한다). [평가](../infra/validation/citation-prefix/README.md#실제-생성-정확도-ab-평가-2026-11-13-19392009-thor-운영-모델).

## 원문 분리·근거 조합·의미 검증기 미채택

원문만 먼저 speech act로 분류해도 후속 합성이 조건부 권고를 관측으로 바꾸고 실행 주체/표본 범위를 혼동했다. 허용 reference 조합만 JSON schema로 제한하면 거절은 줄지만 설명의 의미·완전성은 보장되지 않았다. 별도 검증기는 학습본/기본모델 모두 사전 표적 오류2/5·문장 누락0/1, 정상 통제7/7이라 연결하지 않았다. 새 후보 승격·추론 강화·모델 교체 없이 실패 패치/출력/사전 입력을 보존했다. [56리뷰·76생성 원장과 한계](../infra/validation/peer-source-first/README.md).

## 역사 문맥만 풍부하게 전달하는 후보 보류

일반 로그 본문은 제외하고 같은 요청의 감사 메타데이터를 전달했으나 fresh-only 참조 카탈로그 때문에 상대 한도/기간 확인이 검토자 값에 연결돼 거절되거나 오설명됐다. 답변 생성3/6 동률·범위 오류 잔여, 명시적 모순2/2 탐지는 유지했다. 단순 prompt 추가/메타데이터 전송만으로 정확성을 입증하지 못했으므로 후보를 패치로 보존·기본 소스 복구했다. 다음 typed origin/scope 참조 검토는 사용자 마감 지시로 미착수다. [후보·출력](../infra/validation/peer-source-context/README.md).

## 논문 PDF와 DOCX 출력 경로 통일

MD에서 Chrome PDF와 Pandoc/DOCX를 별도 생성하던 경로는 배치·쪽수가 달랐다. 수정본은 MD→편집 가능한 DOCX→공식 문서 렌더러 PDF의 같은 편집 경로를 사용하며 실제 제목/캡션 쪽수로 목차를 안정화한다. 기존 독립 생성기와 출력은 로컬 복구본/SHA로 보존했다. 이 변경은 논문 출력 도구이며 운영 하네스나 서버 경로 변경이 아니다.

## 2026-11-14T21:48:17.722062+09:00 사건별 완료 의무의 예방 후보

기존 meta에 사건별 단조 완료 요건을 두고 root metadata로만 전달하는 대안. 모델 판단·실제 도구 인용·조회/사건 종결을 구분하되 권한/재시도 확대0. 6조합반례×양군과 회귀는 통과했으나 실제 모델 형식 실패로 보류했다. typed 과거 참조 후보나 자동 정상판정을 섞지 않았다. [후보·분모·한계](../infra/validation/incident-completion/README.md).

## 2026-11-14T22:48:39.353793+09:00 공통 스킬 필드 안내의 개선과 한계

R2는필수3필드/basis20~2000/실제인용/상태관계를기존스킬한절로묶고중복정리. 모델의미해결판단은유지했지만상태enum오류가남아prompt만으로완전한형식보장불가. 다음구조화상태선택은아직구현하지않았으며판단자동선택·alias치환·권한/재시도확대금지. [입출력·분모·한계](../infra/validation/judgment-format/README.md).

## 판단 보존과 상태 선택의 분리 (2026-11-14)

[새 후보](../infra/validation/control-status/README.md)는 유효한 자기 판단과 실제 현재 조회가 결속된 경우에만 상태 형식을 정정한다. root·turn·모델·실제 dispatcher/완료 이벤트 원문을 기존 binder로 검사하고 nonce/enum decoder를 재사용한다. 정상/해결을 코드가 고르지 않으며 추가 근거는 기존 읽기 continuation으로 돌린다. 공통 SKILL의 절은 해당 단계에서만 로딩한다. 기존 none/2048을 새 추론 최적화로 쓰지 않는다. 의미 실험의 R3와 다른 후보다.

## 2026-11-15T01:48:00.843325+09:00 실제 로드 확인과 파일 전용 원복

기존 로그/PID만으로 query 메모리 버전을 입증하지 못해 추정한 hot reload 완료를 쓰지 않았다. [141 후보](../infra/validation/control-status/application/README.md)는 실제 gateway PID·시작 ticks·로드 시점·소스 SHA 관측을 추가하고 짧은 콜드 재시작 후 대조한다. 관측의 설치 상태는 플러그인 자기 관측이며 의미 정확도의 증명은 아니다. 원복은 코드/영수증만 되돌리고 새 사건/큐 DB를 과거 파일로 덮어쓰지 않는다. 운영자 도구는 모델/MCP에 노출하지 않으며 실제 권한/역할/도구 목록은 유지한다.
