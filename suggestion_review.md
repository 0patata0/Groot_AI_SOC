# suggestion.md 검토 메모

GPT가 작성한 원본 제안서에서 기술적으로 틀리거나 검증되지 않은 부분과, 수정한 내용의 근거를 정리한다.

## 1. 반드시 고쳐야 했던 것 (그대로 두면 구현 단계에서 막힘)

### 1-1. Wazuh Agent 통신 방향
- 원본: EC2 Security Group inbound에 1514/1515 규칙을 둠.
- 사실: Wazuh Agent가 Manager로 **outbound** 접속한다(1514 데이터, 1515 등록). EC2에는 inbound 규칙이 필요 없고, 대신 **사내 VM 쪽에 inbound 1514/1515**가 열려 있어야 한다.
- 문제: 학교/기관망은 보통 외부 inbound를 막는다. 원본은 이 부분을 아예 다루지 않았다.
- 수정: EC2 inbound에서 제거. WireGuard/Tailscale VPN 또는 사내 포트포워딩을 명시하고, 안 될 경우 Manager를 AWS에 두는 대안을 추가.

### 1-2. Port Scan 시나리오가 탐지 불가능한 구조
- 원본: 외부 공격자가 Port Scan → Wazuh/Network Event.
- 사실: AWS Security Group은 허용되지 않은 포트를 인스턴스에 도달하기 전에 폐기한다. EC2 안의 Wazuh/Suricata는 80/443/22 외 포트 스캔을 볼 수 없다.
- 수정: 같은 VPC 안에 Attacker EC2를 두고, 실험 시에만 Attacker SG에서 오는 트래픽을 허용.

### 1-3. Suricata 누락
- 원본: 9장, 13장에서 "Suricata / Network Tool"을 쓰는데 구성도(3장)와 구성요소(5장)에는 없음. 5장의 "네트워크 관련 이벤트"는 Wazuh Agent가 스스로 만들 수 없다.
- 수정: EC2에 Suricata 설치, eve.json을 Wazuh Agent가 수집하도록 구성도와 5장에 명시.

### 1-4. Wazuh Indexer 누락 및 API 혼동
- 원본: Manager + Dashboard만 구성. Wazuh Tool → "Wazuh API"로 과거 Alert 검색.
- 사실: Wazuh 4.x는 Manager / Indexer / Dashboard 3개 구성요소이며 Dashboard는 Indexer 없이 동작하지 않는다. Alert는 Indexer(OpenSearch)에 저장되고, Manager의 Server API(55000)에는 Alert 검색 기능이 없다.
- 수정: Indexer 추가, Tool별 실제 호출 대상을 표로 명시(Alert 검색은 Indexer 9200, Syscollector/FIM/Active Response는 Server API 55000).

### 1-5. MITRE ATT&CK을 취약점 DB로 취급
- 원본: NVD / CISA KEV / MITRE ATT&CK → Vulnerability DB → CVE↔Asset 매핑.
- 사실: ATT&CK은 공격 기법(TTP) 분류 체계이지 CVE 데이터 소스가 아니다. 또한 CVE↔자산 매핑은 Wazuh 내장 Vulnerability Detection 모듈이 Syscollector 패키지 목록 기반으로 이미 수행한다.
- 수정: ATT&CK은 Agent의 공격 단계 식별로 이동(Wazuh Alert의 rule.mitre.id 활용). 취약점 계층은 Wazuh Vulnerability Detection + KEV/NVD 우선순위로 재구성. NVD API는 키 없이 호출 제한이 심하므로 API Key 필요 명시.

### 1-6. 평가 지표 오류
- 원본: MTTD, Detection Accuracy를 비교 지표로 사용.
- 사실: 1차 탐지(Alert 생성)는 Baseline과 Agentic SOC 모두 동일한 Wazuh 룰이 수행하므로 두 값이 같게 나온다. 비교 지표로 의미가 없다.
- 원본: 비교 대상인 "Rule/Playbook 기반 자동화"가 무엇인지 정의되지 않음.
- 수정: MTTD/Detection Accuracy 제외, Triage Accuracy / Compromise Detection / Response Appropriateness / Inference Cost 추가. Baseline을 "Wazuh 룰 + Active Response + 사람 수동 조사"로 정의. 오탐 평가용 정상 트래픽 시나리오(Scenario 0)와 반복 횟수, ground truth 정의 추가.

### 1-7. Fine-tuning 계획이 실행 불가능한 형태
- 원본: `[Input]/[Agent Action]/[Observation]` 같은 임의 텍스트 포맷의 학습 데이터 예시.
- 문제: 추론 시 vLLM에 넘기는 형식은 Qwen 채팅 템플릿의 tool calling 메시지(system/user/assistant tool_calls/tool)이다. 학습 포맷이 다르면 학습 효과가 추론에 전이되지 않는다.
- 문제: 모델 크기, 방법(LoRA/QLoRA/full), 데이터 확보 방법, 데이터 양이 전혀 없음.
- 수정: Qwen3-8B/14B + LoRA/QLoRA SFT, 채팅 템플릿 형식 그대로 사용, 데이터 생성 절차(시나리오 반복 → teacher 모델 초안 → 사람 검수) 명시. Fine-tuning을 "확장 목표"로 격하하여 없어도 프로젝트가 완결되도록 함.

## 2. 부정확한 표현 수정

| 원본 | 수정 | 이유 |
|---|---|---|
| Wazuh Agent ├─ 이벤트 탐지 | Agent는 수집만, 탐지는 Manager | 룰 매칭은 Manager에서 수행 |
| Alert → Qwen AI SOC Agent (경로 없음) | Integrator 모듈 custom 스크립트 → HTTP Webhook | Wazuh가 지원하는 표준 방법 |
| Network Tool → "Network API" | Suricata 이벤트(Indexer) + AWS VPC Flow Logs | 단일 EC2 환경에 별도 네트워크 장비가 없음 |
| Policy Engine (16장에만 등장) | 10장에 정의 추가 | 구성도에도 없던 요소 |
| 서버 격리 / 방화벽 정책 변경 (구현 방법 없음) | AWS API로 Security Group 교체 | 실제 실행 수단 명시 |
| 192.168.10.50 (사설 IP 예시) | 10.0.1.50 (VPC 대역) | 공격자가 VPC 내부에 있으므로 |

## 3. DGX Spark 관련 보완

원본은 DGX Spark를 단순히 "Qwen을 실행하는 장비"로만 언급. 다음 제약을 추가했다.

- GB10은 ARM64(Grace) CPU. Docker 이미지·Python wheel은 aarch64 빌드 필요. vLLM/Ollama/llama.cpp는 NVIDIA가 DGX Spark 실행 가이드를 제공하므로 실행 자체는 문제 없음.
- 128 GB 통합 메모리. 32B급 모델 여유, 70B급은 4-bit 양자화 필요. 전체 파라미터 Fine-tuning은 비현실적이고 LoRA/QLoRA만 가능.
- 메모리 대역폭이 데이터센터 GPU 대비 낮아 토큰 생성 속도가 제한적. Agent는 Alert당 Tool 호출을 여러 번 하므로 MTTI에 직접 영향. 모델 크기는 측정 후 결정하도록 함.

## 4. 추가한 안전성 항목

- 프롬프트 인젝션: 로그(User-Agent, URL)는 공격자가 조작 가능한 데이터다. Agent가 이를 지시로 따르면 대응이 조작된다. Policy Engine이 최종 결정하도록 하고, Scenario 5로 평가 항목에 포함.
- Policy Engine 규칙: 쓰기 동작 allowlist, 되돌릴 수 있는 자동 대응만 허용, 보호 IP 목록, Tool 호출/시간 상한.

## 5. 제거

- 문서 맨 앞/뒤의 GPT 대화 문구("좋아. 지금까지 논의한...", "이 버전에서는 특히...").

## 6. 남은 판단 사항 (팀에서 결정 필요)

- 사내망 inbound 가능 여부 확인. 불가하면 Wazuh Manager를 AWS로 옮기는 것이 가장 단순하다.
- Qwen 모델 버전과 크기: 제안서 작성 시점의 최신 Qwen3 계열 중 tool calling을 지원하는 모델을 확인해서 확정. DGX Spark에서 실제 토큰 속도를 먼저 재보고 결정.
- 프로젝트 기간 대비 범위: 환경 구축 + Agent + 평가만으로도 분량이 크다. Fine-tuning은 확장 목표로 두었다.
