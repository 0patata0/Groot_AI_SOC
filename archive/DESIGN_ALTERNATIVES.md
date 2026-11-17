# 설계 대안 이력

## 기존 exact model guard와 공통 호스트 계약 재사용 (2026-11-17)

모델명 접두 허용이나 새 도구 대신 기존 정확 모델 검사와 공통 호스트 파서를 재사용했다. 조회 원칙은 soc-query에 넣고 권한·인자는 결정적 검사로 유지한다. Native root SOUL과 실제 정규화 정책을 별개 감사 경로로 관측한다.49→50소스/census 증가는 기존 정책 관측이며 런타임 prompt 추가가 아니다. [검증·범위](../infra/validation/management-latency/README.md).

## 호명은 공통 분류에서만 정규화 (2026-11-17)

봇별 문장 예외 대신 단일 선행 호명을 공통 분류에서 정리하되 원문·담당·권한 검사는 보존했다. 최근0표본을 채우려고 기간을 확대하지 않고 표본 시각/조회 구간을 구분했다. H2의49소스는 이미 설치된 의존성 관측을 늘린 것이며 MCP 확장이 아니다. 모델 자유 서술의 표/지표 오류와 도구 선택 범위는 후속 공통 보완 대상으로 남긴다. [검증·범위](../infra/validation/management-latency/README.md).

## 기존 도구 구조를 유지한 사본 일치 (2026-11-17)

Malvex 전체 설치나 도구 확장 대신 기존 gate·조사/출력 스킬·핀을 두 봇에 이관했다. 설치본에 필요한 함수·문단만 옮기고 미승격 정본 전체 덮어쓰기를 피했다. 스킬 원칙과 결정적 권한 검사를 구분했으며 상태 재조회·서버 승인 경계를 유지한다. 새4채팅과 공식 구조 결과는 별도 근거다. [선택 이유·현재 한계](../infra/validation/management-latency/README.md).

## 원래 관리자와 실제 중계 출발지 구분 (2026-11-17)

B/C SSH에는 A 내부 주소가 보이므로 관리자 원본 CIDR을 그대로 복사하지 않는다. 공개 실습/WAF·다른 공격 룰·기존 인프라/whitelist는 보존한다. Wazuh의 실제2개 global 중 보호 목록 구간만 후보화했다. 이 관찰기의 A 프록시/threshold 상위 경로 신뢰는 미충족이며 자동 승인 근거로 삼지 않는다.

## 2026-11-17 Native 관리대역 NAT·로더 후보

운영 A의 기본 ip nat 헬퍼와 로컬 미커밋 inet 통합 대안이 달랐다. 원래9작업을 보존하고 별도 운영 기준 소스에서 복수 관리대역 변경·영구 로더 후보를 작성했다. Native18·로더7 합25검사/생략0, Linux 격리9조건 통과·패킷0·운영 FW 불변·시험 폴더 제거. 처음 시험용 nft 줄바꿈 구문 실패는 기록하고 수정했다. 전역 MCP/전체 승인/독립 원복/다른 장비/초기 설치 연결은 미완료다. [검증 범위](../infra/mcp/management-policy.md).

## 2026-11-17 전역 관리정책 공통 계약

관리 IP·대역을 전체 장비에 반영하라는 요구에 맞춰 순수 registry·14적용면·전체 후보/읽기 검증 계약을 작성했다. Mac34검사/생략0이며 단1누락·혼합 버전·승인 계획/후보 소스/경로 변경·미로드는 전체 완료를 막는다. 실제 장비 어댑터·MCP/카드/적용/원복·초기 설치 연결은 아직 없다. 새 IP/운영 변경은0이며 합성 기록을 실제 관측으로 표시하지 않는다. [범위와 원장](../infra/mcp/management-policy.md).

## 2026-11-17 인수 뒤 정리와 전체 관리정책

실제 collection/MCP/양봇 근거를 root 인수 기록에 남긴 뒤 공통 정리 결정을 고정한다. 응답 유실로 정상 서비스를 다시 멈추지 않고 초기 기록은 그대로 둔다. 관리대역 변경은 한 장비의 편집을 전역 성공으로 취급하지 않으며 접속 허용·차단 예외·경보 예외를 구분한 전체 정책이 필요하다. [검증 범위](../infra/validation/journal-composition/COORDINATOR.md).

## 2026-11-17 확정과 운영 인수의 분리

소스 확정 뒤 MCP·봇 인수는 별도다. 일부 확정의 독자 원복을 금지하고 전역 정지 근거·별도 정확 승인·공통 원복 결정을 요구한다. 준비만 한 원복은 서비스 무변경을 유지하며 복구 후 새 관측을 재차 덮지 않는다. [검증 범위](../infra/validation/journal-composition/COORDINATOR.md).

## 차이를 덧붙이지 않고 동결본으로 정본 통일 (2026-11-17)

새 패치를 다시 조합하지 않고 이미 검증한2,271파일 SHA0f625eaa…의 해당 바이트를 정본에 옮겼다. 스킬2개도 실행 계약을 보존했다. 선택36파일의 동일성과 작업 트리 전체 동일성을 구분한다. 과거 manifest/패치·현재 source 원문은 보존하며 초기 설치 소스의 일치와 신규 OS 전체 설치를 구분한다. [대조와 한계](../infra/validation/journal-composition/CANONICAL.md).

## 읽기 증거와 실제 전환의 분리 (2026-11-17)

기존 forced reader와 B→A/C 읽기 인증 경로에 임시 상태 조회만 중계하도록 준비했다. 새 키·TCP 포트·MCP 명령·sudo 권한을 추가하지 않는다. 전체 소스 계약은 전후 SHA·UID/GID/mode를 결속하고 판정기는 파일별 해시·권한도 대조한다. 새 관측15초·미래2초·호스트 간5초를 넘거나 일부만 확정되면 재개 불허다. 독립 서버의 물리적 원자 확정을 보장하지 않으며 실제 B 재개 차단은 후속 실행기에 남겼다. [설계와 경계](../infra/validation/journal-composition/WITNESS.md).

## 고정 초기 이력 유닛과 한도 대조 (2026-11-17)

초기24시간 수집을 고정 role/action의 별도 oneshot unit으로 등록했다. 정기 수집과 같은 메모리·스왑·태스크·FD 한도를 적용하고 이력의 시작 제한은150초로 둔다. 설치기는 실제 로드 값과 부분 수집 결과를 검사해 타이머 활성화 여부를 결정한다. 단일 deploy.sh와 기존 읽기 권한은 유지한다. [설계·실행·제약](../infra/validation/journal-composition/LIMITS.md). 소스·캐시의 조정 배포와 독립 원복은 아직 구현해야 한다.

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

## 2026-11-15T02:22:24.049396+09:00 평가자료범위·사용이력정정

공통평가감사에서전체레코드·실제입력·비assistant입력지문을분리해ID/정답교체재사용을식별한다.원장은확인된노출하한이며0일치=미사용/독립인증으로쓰지않는다.상시하네스나모델정책을바꾼것이아니다. [근거](../finetuning/EVALUATION_SCOPE.md).직전현재요약은Gitb826696에서복원한다.과거실험원문/학습분할/가중치는유지한다.

## 2026-11-15T03:12:45.602561+09:00 모델 구성요소와 운영 하네스의 분리 평가

공통역할/현재SDK/45스키마를준모델시험과실제운영의대상확인·도구축소·필수읽기/보정·게시를구분했다. 모델의무조회주장3개가있어도기존검사가검출하는범위와새채팅성공은별도증거다. 추가읽기분기를정답호출불일치만으로실패처리하거나미지원결과를만들어주지않는다. 전체16분모·미채점7·실제wireSHA와sourcefixture지문을보존하고정확도평균은내지않는다. [진단](../finetuning/WORKFLOW_DEVELOPMENT.md).

## 2026-11-15T03:54:33.032918+09:00 전체 기간과 바이트/시간 제한을 유지하는 조회

24h를6h구간최신순으로읽고cursor/원문SHA검증후결합한다. 공유20초·원래전체바이트제한을유지·어느구간실패도전체0으로바꾸지않는다. 엄격히더최신인충분한tail만has_more로조기종료. 반환총수/보존을인증하지않고범위를15분으로줄이는대체를채택하지않았다. [근거](../infra/validation/live-reads/README.md).

## journal 검색 비용 실험 미채택 (2026-11-15)

역순은 systemd255의 grep+lines가 이미 포함하고 실제 A 비용도 개선하지 못했다. 직접 unit 필드·시스템 journal 한정은 시간 초과가 남고 동등 범위도 인증하지 않아 채택하지 않았다. 동등 literal trie/precheck도 공유/명령 예산을 넘었다. RuntimeError만 검색하면 더 빠르지만 필요한 다른 오류를 제외하므로 해결안이 아니다. 기존 전체 기간·등록 대상·제한을 유지하며 경계 누락만 별도 수정했다. [현재 후보·반례·관측](../infra/validation/journal-reader/README.md).

## journal CPU·native 가능성 후속 (2026-11-15)

공식Reader의전체변환·선택필드·Pythonbyte정규식·동일PCRE2JIT와2동시를격리비교했다. 단일24h는11.5초내부한도실패·선택필드순차20초실패, JIT는19.295초로여유작음/FFI필요해우선도입하지않는다. 공용Reader2동시11.946초를표준응답/보안회귀를갖출다음구현방향으로정했다.64KiB내부정규화패킷/전역tail잘림은검증전제안이며운영반영이아니다. [정확 원장·조건](../infra/validation/journal-native/README.md).


## 2026-11-15T08:11:55.464522+09:00 journal 정확 적용·복구 준비

journal 적용은3파일전체의동시원자성을주장하지않는다. 실제구core/새journal조합이깨지는것을확인해 helper→core→journal과역방향의존복구를선택했다. reader정지·collector완료대기·각파일원자교체·backup/CAS/독립timer와중간라이브러리호환으로보완한다. 재부팅복구시험과단순coldload는구분한다. [설계/한계](../infra/validation/journal-adapter/application/README.md).


## 2026-11-15T09:11:40.469152+09:00 공통 짧은 조회·시각 표시 후속

시간 표시를 모델 계산과 분리하고 공통 호스트 파서를 재사용한다. 이는 도구 자동 선택·사건 정상 판단·승인 경계 변경이 아니다. DNS는 정확 인용 안내만으로 완료되지 않았고 guard 오탐/모델 오류를 분리해 추가 검증한다. 스킬 절에 안내를 두고 강제 권한은 코드에 유지한다. [후보](../infra/validation/common-read-contract/README.md).


## 2026-11-15T14:49:24.191213+09:00 공통 주장·조회 범위 개발 후보

공통 claim_modality는 명제에 붙은 부정·조건·계획·이중부정만 판독하며 위험 판단은 하지 않는다. diagnostic 기간 검사를 계획 문구가 우회하는 회귀를 확인해 호환 진입점에서 계획을 면제하지 않게 했다. 센서 그룹별 술어 결속·기존 첫 센서 helper 재사용·선택 상태 enum 검사/기존 skill 절을 택했고 권한·기본 예산은 유지했다. 그러나 실제 시도 없는 실패 주장과 미지원 다음 조치 제안은 아직 남아 채택을 보류했다. [설계·한계](../infra/validation/claim-modality/README.md).


## 2026-11-15T16:18:29.576405+09:00 실제 읽기 시도 결속 후보

성공 fact와 실패/미실행 시도를 분리하고 실제 callID/원장·SHA에 묶는 공통 view를 택했다. opaque text의 error 단어만으로 오류를 추정하지 않고 반환을 보안 정상으로 바꾸지 않는다. SDK 입력거절은 MCP수 밖에 두고 실제 순서가 없으면 마지막 결과를 추정하지 않는다. root 허용 검사와 기존 wire/예산은 유지하고 안내는 기존 스킬 절에 둔다. 그러나 명시 도구/센서 중심 문장 검사는 대상명 OS 실패를 놓쳐 전체 적용 보류했다. [설계·제약](../infra/validation/read-attempt-binding/README.md).


### 2026-11-15T16:50:00.878841+09:00 짧은 조회 의도·표본 후보

질문별 하드코딩 대신 공통 긍정 조회 동사 문법을 재사용했다. DNS는 실제 반환 질문/signature 표기 부분집합이며 서버 필터·전체DNS/정상판단이 아니다. 서비스 집계snapshot을 journal로 바꾸는 우회는 채택하지 않았다. [패치·재현·한계](../infra/validation/read-intent-scope/README.md). 기준 Git16180fd에서 복구하며 과거 원문/판정은 보존한다.

## 2026-11-15 OS 범위 후보와 매뉴얼 상세화

실제 읽기 완료의 tool-name만 대조하는 방식은 대상명 B systemd·view·기간 혼동을 놓쳤다. 공통 원장에 typed selector/응답범위/요청기간을 결속하고 명시 unit/container의 점을 해당 검사에서만 보존했다. 현재상태·오류이력·원문journal·실제서비스실패·조회실패를 구분한다. 일반자연어전부검증·별칭unit추정·과거aggregate권한확대는 하지 않는다. 논문은 날짜별 개발일지 대신 개념/목적/준비/실행/확인/복구를 채택하고 기존43쪽/9파일은 로컬SHA복구본으로 보존했다.

근거: [후보·검사·한계](../infra/validation/read-target-binding/README.md)·[현재 상태](../STATUS.md). 이전 현재상태/계획은 Git `3efcb39d62f114bd468cee7a3ac40e9638bcc49c`의 STATUS.md/PLAN.md 및 해당 검증 원장에서 복구한다. 로컬 원문은 대화기록의 read-target-binding/thesis-methods에 보존한다.

## 2026-11-15 실제 OS 조회4요청과 공통 계획 공백

새대상검사는같은실제무조회초안에부모[]/후보unobserved_read_success를검출한다. 이것은조회완수의대안이아니다. 필수계획/실제집계로그경로를보완해야하고과거요청을현재snapshot으로대체하거나다른unit/추정agentID로메우지않는다. 기존MCP의고정host·기간·마스킹·bytes/표본제한안에서집계기능확장여부검토·정확후보별도검증/승인.

[질문·호출/응답SHA·시간·한계](../infra/validation/read-target-live/README.md)·[현재상태](../STATUS.md). 로컬원문과계획재현은대화기록/검증/2026-11-15-read-target-live에보존한다.

## 2026-11-15 집계 journal 후속 후보와 실제 읽기 한계

[후보·원장](../infra/validation/host-journal/README.md). 원인은 짧은 host systemd 로그 요청의 필수 읽기 공백이며 공통 스키마/계획·실제 system journal·출처 표시·설치 사전검사를 격리 구현했다. 운용9소스/검사2개·공식 Harness²33구성/상시증가0·Mac1038중1032통과6생략/기존Hermes1121통과생략0·공개34소스씩SHA/AST재현/새19검사다.

A/B/C 자체 제한 서비스의21논리시험은15성공/6실패다. 최근errors/all·등록unit·인증소켓과9native/CLI전체응답일치는확인했지만24h errors는두backend모두시간제한이다. 실패를0건/정상/전체조회완료로치환하지않는다. 실제MCP·모델·채팅0/운영소스·기존서비스변경0·정확두계획불변. 원격자체7폴더725파일10,356,916B는출력44파일/전체SHA/종료확인후정리하고제거영수증을별도로보존한다. 논문매뉴얼56쪽15SHA·기존9/운영백업·G_Harness2보존. 새모델선택·긴검색가용성·정확새승인·실제로딩/채팅이후속조건이다.

추가 선택 근거: host 전체24h errors는 native와 고정CLI를 같은 제한 환경에서 각각 실행했으나 두 경로 모두 시간 제한이었다. all tail의 빠른 반환은 전체 오류 검색을 대체하지 않으므로 숨은 필터 축소·실패를0건으로 치환·시간 예산 확대는 채택하지 않았다. 최근 실제 읽기 구현은 보존하고 긴 검색의 비용과 실패 후 구간 선택을 다음 수용 조건으로 남긴다.

## 2026-11-15 호스트 journal 파일별 읽기 후보

priorityindex제거후보는6h11.761387초/24h12.021280초실패로기각했다. nativeanchor가고른모든FD의분할·inode보존·세대변화거절을채택후보로보존한다. 최신immutableflag/자체바이너리파서/파일시각제외/예산확대는쓰지않았다.

[후보·재현·원장](../infra/validation/host-journal-cost/README.md). 원문·SHA·실패후보·정리영수증·논문15SHA·기존9변경과두정확계획을보존한다.

## 2026-11-16 실제 journal 모델 검증·남은 의미 문제

모든필터후보를실패로해석하지않고실제주장/근거/검사거절을나눈다. 과거ExitCode보고를현재속성으로거절한범위문제와진짜재시작루프추론을별개로다룬다. 검사전체해제·자동정상/완료·가짜데이터·같은자료독립재채점은채택하지않는다.

[새4요청·재현·분모](../infra/validation/host-journal-model/README.md). 소비4관측은정답/SFT가아니며원래9/논문15SHA·두정확계획·framework/자료가중치를보존한다.

## 내부 시계와 등록 대상 확인의 선택 (2026-11-16)

외부clock 인자나 미래 유예를 추가하지 않고 내부정수µs 캡처를공유했다. 호스트미지정을모델추론으로채우지않고실제카탈로그에모호함이있으면사전확인한다. 기본/과거 메타데이터의정수초와수집관측을보존하고유닛부재를Docker상태로대체하지않는다. 다만후자의실제응답오류는남아추가typed읽기/근거검증이필요하다. [비교와한계](../infra/validation/diagnostic-read-boundaries/README.md).

## 2026-11-16 서비스 타입·실행 근거 공통 후보

unit not-found를 Docker 또는 다른 호스트로 바꾸는 대안은 사용하지 않는다. 같은 호스트의 실제 loaded unit·Docker 목록/실제 다음 페이지를 읽고 명시 unit은 유지한다. 실제 이전3질문의 inventory 도구는 노출되어 있었으므로 ‘도구 부재’ 가설은 정정했다. SDK 자동축소에는 기존 검증 callable만 예약하고 명시 tool subset은 확장하지 않는다. 안내는 기존2스킬, 강제 경계는 공통 계약/root/adapter가 맡는다.

## 2026-11-16 사실 조회·미확인 공통 후보

단순 상태·기간 로그에 원인 판단을 붙이는 대안 대신 실제 등록 이름/같은 기간 파서의 해석 결과를 재사용했다. ‘로그에서/로부터’의 명사 조사를 시간 경계와 분리한다. 원인/영향/비교·추가 대상은 계속 조사한다. unit not-found를 전체 파일/프로세스 부재나 실제 컨테이너 관계로 바꾸지 않는다. 새 인용 반례 때문에 임의 표 전체를 면제하는 방식도 채택하지 않는다. 기존2스킬 재사용·권한/승인 경계 불변.

## 2026-11-16 서비스 출처·미확인 조회 후보

관계/프로세스를 자유 문장으로 요약하는 대신 사실 조회의 미확인 schema/신뢰된 식별 문맥을 Native와SDK에 공통 결속했다. 단순 사실확인에는 해시/범위만 전달하고 원인 조사에는 원문을 유지한다. 임의 표 전체 검사 면제 대신 정확한 인증 원문 행만 의미 검사에서 구분하며 원래 승인·인용 검사는 전체 응답 유지. SDK의 용어정규화도 출처분리 뒤로 이동. 기존soc-query절·workflow section으로지시통합,도구/권한확대0.

## 2026-11-16 오류 원문·조사 완료 조건

원인질문errors0의추가원문을문구안내만하던대안은실제시험에서선택되지않았다. 같은대상/기간/한도의all을최소근거완료조건으로검사하고모델선택으로실제호출한다. 일반조회·명시오류표본만제약유지·원인/판단대체0. 원문메시지/시각/출처/우선순위/state는유지하고모델입력의행별3SHA중복만감사원본에둔다. 현재기본표본을별도그룹으로표시한다. 스키마오류는값수정/자동실행대신불신초안·필드경로로기존한도내정정. 공통스킬재사용·권한불변.


## 매뉴얼 실행 절차 강화 (2026-11-16)

날짜별 이력 대신 작업 목적에 따라 절을 고르고 수행/확인하도록 설명. 하네스 공통 계약/스킬·강제 경계 코드·구조/회귀/실제 채팅을 구분. 학습은 제어 파일/프로필·진도/완료·loss/운영 우위를 구분.


## 앱 선언 오류와 정책별 수집 범위 (2026-11-16)

journal 우선순위와 앱 선언 수준을 구분한다. JSON/logfmt 최상위 문자열만 새 app 경로로 분류하고 기존 high-priority 일반 분류는 유지해 커서 재분류 충돌을 막았다. 정상 구조화 전처리 후보는 제외하되 잘림을 숨기지 않는다. 정책 변경 시 이벤트는 보존하고 구 스캔 표식만 원자적으로 무효화·실패 롤백한다. 다른 정책의 스캔은 현 정책 완료 근거가 아니다. [근거](../infra/validation/application-error-filter/README.md).

## 조회·조사 소스 통합 (2026-11-16)

마이크로초 QueryClock을 유지하며 앱 정책 검사를 결합. 앱 분류는priority4..6, 과거앱표시는요청구간결속·현재표본은커서해시생성안함. 스킬크기한도를늘리지않고중복정리. 재귀후보 복사대신 전체2266→2271과 비교3소스의 평탄 재현 제공. [근거](../infra/validation/journal-composition/README.md).

## 운영 절차 중심 매뉴얼 보강 (2026-11-16)

날짜별 진행 이력 대신 목적/이유·준비·실행 순서·기대 결과·실패/복구를 사용한다. 설명문에 실제 대화 예와 직접 확인할 필드를 붙이고, 정본 소스와 설치 사본·학습/추론 경로를 구분했다. 미적용 후보는 성공 사례로 쓰지 않는다.


## 소스 대조·진단 캐시 복구 준비 (2026-11-16)

변경 뒤 관측을 잃는 단순 DB 덮어쓰기 대신 before/after 불변 사본·논리/바이트 SHA·root 고정 경로·정책/스키마·원자 교체·재복구 검증을 택했다. 서비스 제어/일반 권한을 helper에 넣지 않았다. CLI 후보 정상 로그 상한 문제는 grep을 좁혀 escaped severity를 누락시키는 대안으로 해결하지 않는다. 의미 분류 선행·한도/실제 A/B 검증 필요. [검증/절차](../infra/validation/journal-composition/README.md)·[현재](../STATUS.md).


## 수집 상한 선점 공백 보완 (2026-11-16)

grep축소 대신공통Native순회·등록unit표현식/분류후상한을택했다. snapshot/backfill이같은root전용메타데이터함수/공통요약검증을쓴다. JSONescape/중복/노이즈·기존byte/row/time/원문차단·정책v1 유지. UI필드/roleprompt복제/새스킬·도구0. 잘린CLI보다실제순차A2.15→4.51/B2.06→3.89초로느려졌으나범위검증이강화됐고채팅속도향상으로세지않음. 전체collector자원은격리read128/8과별도검증. [검증/재현](../infra/validation/journal-composition/README.md)·[현재](../STATUS.md).

## Malvex의 선택적 참고

고정커밋75d86748의 실행/파서/판정/skillgen 소스를 검토했다. 단계별 근거 보존·재처리·확인/가설 구분을 기존 실행기와 공통 스킬에 연결한다. 전체 프레임워크·병렬 분석자·자동 도구 설치·confirmed 필드 수용·자동 운영 스킬 등록은 도입하지 않았다. 소스 문서의 목적과 실제 검사 강도를 구분한다. [대조표·출처](../infra/validation/management-latency/README.md).


<a id="thesis-structure-20261117"></a>
## 2026-11-17 논문 구조와 재구현 명세

2025년 논문집 전체의 공통 형식을 추정하지 않고 첫 보안관제 논문의PDF11~12쪽 목차를 확인해6장 구조를 채택했다. 기존 절차의 제목만 바꾸지 않고 관련 연구·설계 이유·사건 식별·실제 함수/소스·입출력·결과 타당도를 보강했다. 일상 점검·조회·조사·승인의 사용자 순서는 부록으로 이동했다. 공개 기준 커밋4fcbbf4bf2ca89f8bea0b1bd69b67545e2b6f9c3을 고정하여 진행 중인 미채택 소스와 논문의 재현 기준을 섞지 않았다.


<a id="thesis-reproduction-kit-20261117"></a>
## 논문 전체 소스의 오프라인 복원 — 2026-11-17T20:19:07.665442+09:00

핵심 소스40개만 제공하는 방식에 전체 고정 소스 압축과 manifest를 추가했다. 압축의 파일별 SHA·크기·Git blob·권한·정확 목록을 검사한 뒤 메모리에 검증한 바이트만 새 디렉터리에 기록한다. tar의 일반 extractall이나 복원 코드 실행을 사용하지 않고 기존 출력은 거절한다. 파일 단위 재현과 실제 OS 설치를 별도 상태로 유지한다.


<a id="thesis-log-pipeline-20261117"></a>
## 논문 로그 정제 구현 보강 — 2026-11-17T20:41:14.830347+09:00

Vector는 WAF 두 입력의 신원·시각을 확인한 뒤 공통 메타데이터와 ready를 만들고 조건을 만족한 Suricata/nftables 부분집합만 evidence에 복사한다. 잘못된 쌍은 quarantine, 정상 access 단독은 의도적 제외다. 세 disk buffer의 block 정책은 공유 입력에 대기를 전파할 수 있고 telemetry는 별도 memory/drop_newest를 사용한다. 이 구조를 도식과 실제 변환 코드로 논문에 연결했다.


<a id="thesis-command-check-20261117"></a>
## 논문 실행 예제 실제 확인 — 2026-11-17T21:00:17.334686+09:00

호스트 식별용 문서 주소와 실습 접근 네트워크는 같은 검증 조건이 아니다. LAB_ALLOWED_CIDRS의 CIDR 목록은 RFC1918·개수·중복·proxy 중첩 조건을 따르며 all은 별도 명시 분기다. 두 번째 에이전트의 read-only 기본값과 hermes-parity 선택을 명시하고 실제 도구/승인 연결 완료와 구분했다.


<a id="thesis-harness-reproduction-20261117"></a>
## 논문 구조 재현 입력 확인 — 2026-11-17T21:41:20.509294+09:00

원래 Git 객체를 보유한 별도 체크아웃과 공식 고정 코드에서 기존 재현기를 그대로 실행한다. Git 이력을 흉내 내거나 원래 Framework/작업 폴더를 변경하지 않는다. 입력 확인은 읽기만 수행하고 테스트를 대신 실행하지 않으며 모델 자격을 복사하지 않은 Framework 사본을 요구한다. 구조 census와 실패 시 예외의 계약을 문서에 명시했다.


<a id="thesis-live-results-20261117"></a>
## 논문 후속 실제 채팅 결과 반영 — 2026-11-17T22:05:28.665982+09:00

채팅 응답 시간은 사용자 게시물과 최종 답변 갱신 시각의 차이로 정의하고 폴링 대기·SDK 내부 시간과 구분한다. 최종 구간 일치와 전체 요청 범위·도구 거절·표현 정확성을 나누어 판정한다. 고정 전체 소스4fcbbf4와 후속 결과35aa25f를 별도 원장으로 연결해 작업 폴더의 미게시 변경을 결과 소스로 승계하지 않는다.


<a id="presentation-refresh-20261117"></a>
## 최종발표 근거·출력 현행화 — 2026-11-17T23:12:53.118753+09:00

기존20장 구조·서체·색·편집 표/차트와 원형 이미지를 재사용한다. 구성도 안의 구형 모델 표기는11/5 원형임을 슬라이드에 명시하고 현재 관측을 인접 텍스트로 정정한다. 실제6대화와 입력 바이트의 새 literal 데이터에 맞는 workbook을 의도적으로 작성하며 과거 비교의 수식을 재사용했다고 주장하지 않는다.
