# suggestion.md 검토 메모

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](STATUS.md) · [실행 계획](PLAN.md).
> 현재 구성은 A/B/C 역할 분리·MCP6서버·HTTP3/터미널3·단일 deploy.sh(service schema9)다.6CVE 공격·탐지 시험은 사용자 지시로 보류하고 LLM 진단/알림 실패 보완과 문서 정리를 우선한다. 실제 검증 범위와 새 서버 설치 제외를 함께 확인한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

GPT가 작성한 원본 제안서에서 기술적으로 틀리거나 검증되지 않은 부분과, 수정한 내용의 근거를 정리한다.

> 이 검토 이후 인프라를 **AWS에서 온프레미스 ESXi 2세그먼트로 전환**했다([PLAN.md](PLAN.md); 전환 경위는 `대화기록/대화_및_변경이력.md`, 예전 AWS 계획본은 `대화기록/PLAN_aws_backup_2026-09-22.md`). 아래의 "원본"은 GPT의 AWS 기반 제안서를 그대로 기록한 것이고, "수정"은 실제 배포(온프레미스 ESXi, `Groot_A`가 NAT 관문)에 맞춘 결론이다. AWS 관련 서술은 "왜 그 설계가 문제였는가 / 왜 온프레미스로 옮겼는가"의 근거로 남겨 둔다.

> **현행 안내(2026-10-08 기록):** 아래는 제안서 검토 경위이며 최신 운영 상태는 [STATUS.md](STATUS.md)를 따른다. 실제 Alert 트리거는 Hermes의 5분 Indexer 경보 폴링이고 아래 웹훅 표기는 검토 당시 대안이다. 9/28의 MCP 17툴 최초 배치 이후 `security-events` 읽기 2툴과 `rule-a`·`rule-b` 승인형 로컬 룰 변경 서버를 추가해 현재 5서버가 enabled다. 새 룰 변경은 배포·인증·조회까지만 검증했고 실제 승인→적용 E2E는 남았다. WAF는 DetectionOnly, Suricata는 passive이며 `isolate_host`는 미구현이다. 채팅 인증서는 10/08 배포 완료했고 모바일은 학교 내부 Wi-Fi에서 미검증이다.

> **2026-10-13 모바일 후속:** 위 10/08 기록 이후 사용자가 Android·iOS의 인증서 인식·로그인·채팅 성공을 확인했다. 프로젝트 서버의 모바일 푸시 복구는 사용자 승인으로 진행 중이며 실제 알림 수신은 아직 검증하지 않았다. 최신 적용 상태는 [B 운영 문서](infra/groot-b/README.md#모바일-푸시--dns-복구외부-https-경로-미확보-2026-10-13)를 따른다.

> **2026-10-13 최신 범위 정정:** 사용자가 프로젝트 SSL VPN 원격접속과 모바일 푸시를 추후 발전과제로 정했다. 두 항목은 현재 완료 범위에서 제외하며 재개 요청 전까지 추가 조사·구축·시험은 진행하지 않는다. VPN은 미구축·중첩 접속 호환성 미검증이고 학과 폐쇄 정책으로 호환이 어려울 것이라는 판단은 사용자 예상이다. Android·iOS 로그인·채팅은 기존 사용자 확인상 성공했고 푸시는 false·수신 미복구 상태다. 기존 배포 설정·타이머와 별도 인증서 갱신 관리는 유지한다. 위 복구 진행 중 서술은 결정 이전 이력이다. [발전과제](PLAN.md#추후-발전과제-2026-10-13-사용자-결정).

## 1. 반드시 고쳐야 했던 것 (그대로 두면 구현 단계에서 막힘)

### 1-1. Wazuh Agent 통신 방향
- 원본: EC2 Security Group inbound에 1514/1515 규칙을 둠.
- 사실: Wazuh Agent가 Manager로 **outbound** 접속한다(1514 데이터, 1515 등록). 즉 열어야 하는 것은 Agent 쪽 inbound 가 아니라 **Manager 쪽 inbound 1514/1515**다.
- 문제: 학교/기관망은 보통 외부 inbound를 막는다. 원본은 이 부분을 아예 다루지 않았다.
- 수정(실제 배포): 온프레미스 ESXi 한 호스트 안이라 인터넷 inbound 문제가 없다. Agent A(`001`)·C(`002`)가 내부망 `10.200.10.0/24`로 Manager(`Groot_B` `10.200.10.10`, 1514/1515)에 접속한다. VPN 터널·클라우드 우회는 불필요.

### 1-2. Port Scan 시나리오가 탐지 불가능한 구조
- 원본: 외부 공격자가 Port Scan → Wazuh/Network Event.
- 사실: AWS Security Group은 허용되지 않은 포트를 인스턴스에 도달하기 전에 폐기한다. EC2 안의 Wazuh/Suricata는 80/443/22 외 포트 스캔을 볼 수 없다.
- 수정(실제 배포): 온프레미스 ESXi에는 Security Group이 없어 이 제약이 사라진다. Kali(VM 세그먼트)의 스캔이 관문 `Groot_A`(Suricata IPS)에 그대로 도달·관측된다. 공격 트래픽은 캠퍼스 VPN 경유 금지 — VM 세그먼트 안에서만 발생시킨다.

### 1-3. Suricata 누락
- 원본: 9장, 13장에서 "Suricata / Network Tool"을 쓰는데 구성도(3장)와 구성요소(5장)에는 없음. 5장의 "네트워크 관련 이벤트"는 Wazuh Agent가 스스로 만들 수 없다.
- 수정: 관문 `Groot_A`에 Suricata 설치, `eve.json`을 `Groot_A`의 Wazuh Agent(`001`)가 수집하도록 구성도와 5장에 명시.

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
- 문제: 추론 시 추론 서버(`Ollama`)에 전달되는 형식은 Qwen 채팅 템플릿의 tool calling 메시지(system/user/assistant tool_calls/tool)이다. 학습 포맷이 다르면 학습 효과가 추론에 전이되지 않는다.
- 문제: 모델 크기, 방법(LoRA/QLoRA/full), 데이터 확보 방법, 데이터 양이 전혀 없음.
- 수정: Qwen3-8B/14B + LoRA/QLoRA SFT, 채팅 템플릿 형식 그대로 사용, 데이터 생성 절차(시나리오 반복 → teacher 모델 초안 → 사람 검수) 명시. Fine-tuning을 "확장 목표"로 격하하여 없어도 프로젝트가 완결되도록 함.

## 2. 부정확한 표현 수정

| 원본 | 수정 | 이유 |
|---|---|---|
| Wazuh Agent ├─ 이벤트 탐지 | Agent는 수집만, 탐지는 Manager | 룰 매칭은 Manager에서 수행 |
| Alert → Qwen AI SOC Agent (경로 없음) | Integrator 모듈 custom 스크립트 → HTTP Webhook | Wazuh가 지원하는 표준 방법 |
| Network Tool → "Network API" | Suricata 이벤트(Indexer) + `nftables` 로그 | 관문 `Groot_A`가 유일 검사 지점 — 별도 네트워크 장비가 없음 |
| Policy Engine (16장에만 등장) | 10장에 정의 추가 | 구성도에도 없던 요소 |
| 서버 격리 / 방화벽 정책 변경 (구현 방법 없음) | 응답(쓰기) MCP(`Groot_A`)의 `block_ip` → `nftables` `agent_block` | 실제 실행 수단 명시 |
| 192.168.10.50 (사설 IP 예시) | `10.200.10.x`(내부망) · `192.168.16.x`(VM 세그먼트) | 공격자·자산이 온프레미스 ESXi 세그먼트 안에 있으므로(VPC 아님) |

## 3. DGX Spark 관련 보완

원본은 DGX Spark를 단순히 "Qwen을 실행하는 장비"로만 언급. 다음 제약을 추가했다.

- GB10은 ARM64(Grace) CPU. Docker 이미지·Python wheel은 aarch64 빌드 필요. vLLM/Ollama/llama.cpp는 NVIDIA가 DGX Spark 실행 가이드를 제공하므로 실행 자체는 문제 없음.
- 128 GB 통합 메모리. 32B급 모델 여유, 70B급은 4-bit 양자화 필요. 전체 파라미터 Fine-tuning은 비현실적이고 LoRA/QLoRA만 가능.
- 메모리 대역폭이 데이터센터 GPU 대비 낮아 토큰 생성 속도가 제한적. Agent는 Alert당 Tool 호출을 여러 번 하므로 MTTI에 직접 영향. 모델 크기는 측정 후 `qwen3.6:35b`(tool calling+thinking)로 확정 — DGX Spark의 `Ollama`(엔드포인트 `211.170.162.110`/`.111`, `:11434` OpenAI 호환 `/v1`)에서 추론만 담당한다.

## 4. 추가한 안전성 항목

- 프롬프트 인젝션: 로그(User-Agent, URL)는 공격자가 조작 가능한 데이터다. Agent가 이를 지시로 따르면 대응이 조작된다. Policy Engine이 최종 결정하도록 하고, Scenario 5로 평가 항목에 포함.
- Policy Engine 규칙: 쓰기 동작 allowlist, 되돌릴 수 있는 자동 대응만 허용, 보호 IP 목록, Tool 호출/시간 상한.

## 5. 제거

- 문서 맨 앞/뒤의 GPT 대화 문구("좋아. 지금까지 논의한...", "이 버전에서는 특히...").

## 6. 남은 판단 사항 (팀에서 결정 필요)

> (아래는 검토 당시 미결이었고 현재는 모두 해소·확정된 항목이다. 결정 경위 기록으로 남긴다.)

- 사내망 inbound: **해소됨** — 온프레미스 ESXi 한 호스트로 전환해 인터넷 inbound 자체가 불필요. Wazuh Manager는 `Groot_B`(`10.200.10.10`)에 두고 Agent A(`001`)·C(`002`)가 내부망으로 접속(구축·검증 완료, Wazuh 4.14.8 가동·에이전트 2대 Active).
- Qwen 모델 버전과 크기: **확정** — DGX Spark의 `Ollama`에서 tool calling+thinking을 지원하는 `qwen3.6:35b` 채택. Hermes(에이전트 런타임, `Groot_B` 상주) ↔ DGX ↔ MCP(17툴) E2E 동작 확인.
- 프로젝트 기간 대비 범위: 환경 구축·에이전트 런타임(Hermes)·경보 트리거(5분 cron)·Tier 2 승인(온프레미스 Mattermost 버튼)까지 완료. 남은 것은 시나리오 실측·평가이며, Fine-tuning은 확장 목표로 유지.
