# 네트워크 토폴로지 이미지 (2026-10-08)

- [현재 배포 네트워크 토폴로지](current-network-topology-2026-10-08.png): A가 외부/내부망 관문이고, B·C는 `10.200.10.0/24` 내부망에 있는 실제 배포 구조를 표현한다.
- [버스형 토폴로지 개념도](bus-topology-concept-2026-10-08.png): 같은 A·B·C를 내부망 백본 중심으로 **논리적으로 재배치한 설명용 이미지**다. 실제 물리 배선이나 동축 버스를 뜻하지 않는다.

두 그림 모두 내장 `image_gen`으로 생성한 1672×941 PNG다. 표시된 DGX 점선은 A를 경유하는 **논리적 LLM 요청 경로**이며 B에서 DGX로 물리 전용선이 있다는 뜻이 아니다. 사실관계는 [2026-10-08 라이브 점검 기록](../../대화기록/2026-10-08.md)과 [현황](../../STATUS.md)을 기준으로 했다. 신규 룰 변경 경로의 실제 승인→적용 E2E는 아직 미검증이다.

**같은 날 후속 운영 결정:** 그림의 `학교 Wi-Fi / VPN`은 전체 사용자 접속 경로를 요약한 것으로, 모바일 VPN 지원을 뜻하지 않는다. 사용자 보고상 학교 관리자가 모바일 GlobalProtect 지원을 거절했고 휴대폰 VPN 로그인도 실패했다. 모바일 Mattermost 검증은 A에 도달하는 학교 내부 Wi-Fi에서 진행하며 아직 앱 로그인은 미검증이다. 채팅 DuckDNS 이름에는 10/08 Let's Encrypt 인증서를 배포했다. 아래 생성 프롬프트는 생성 당시 원문을 보존한다.

## 생성 프롬프트

### 현재 배포 구조

```text
Use case: infographic-diagram. Asset type: polished presentation-ready 16:9 network topology IMAGE for a Korean university cybersecurity capstone report. Create ONE clean, legible, flat vector-style network diagram on a white background, landscape. Title exactly: "현재 배포 네트워크 토폴로지". Show actual deployed two-segment layout, left-to-right, with clear compartment boundaries. Far left: "학교 Wi-Fi / VPN" user icon, arrow labeled "HTTPS 443" to gateway. Center: large emphasized gateway box "Groot_A" with external IP "192.168.16.230", internal IP "10.200.10.1"; three small role labels "nftables · NAT", "WAF · DetectionOnly", "Suricata · Passive". Between left and center, subtle band label "외부망". Right side inside a single pale-blue region labeled "내부망 10.200.10.0/24": upper box "Groot_B · 10.200.10.10" with role labels "Wazuh SIEM", "Mattermost · Hermes", "승인 브로커"; lower box "Groot_C · 10.200.10.20" with role labels "DVWA · Log4Shell". Solid arrows A->B labeled "채팅 프록시", A->C labeled "WAF 경유". Thin dotted arrow C->B labeled "Wazuh 로그". Top-right small cloud "DGX Spark · Ollama" connected to B with dotted arrow labeled "LLM 추론 (A 경유)". Use only those labels; spell all IP addresses and product names exactly as provided, no invented hosts or networks. Add small legend bottom: "실선: 서비스 트래픽   점선: 로그·제어 경로". Professional technical infographic, high contrast, generous whitespace, crisp Korean and English typography, accurately directed arrows, no 3D, no decorative server racks, no logo, no watermark. This is the ACTUAL network, not a physical bus topology.
```

### 버스형 개념도

```text
Use case: infographic-diagram. Asset type: polished presentation-ready 16:9 landscape IMAGE, companion to a clean current-network topology infographic. Create ONE crisp, flat vector-style schematic on white background. Korean title exactly: "버스형 토폴로지 개념도". Directly below title, conspicuous subtitle exactly: "논리적 재배치 · 실제 배선 아님". Center-lower half: ONE thick straight horizontal blue backbone with exact label "내부망 10.200.10.0/24". Three short perpendicular vertical drop lines connect this backbone to exactly three evenly spaced server boxes ABOVE it: left "Groot_A · 10.200.10.1" with roles "게이트웨이 · nftables/NAT" and "WAF · Suricata"; center "Groot_B · 10.200.10.10" with roles "Wazuh · Mattermost" and "Hermes · 승인 브로커"; right "Groot_C · 10.200.10.20" with role "DVWA · Log4Shell". Clearly show no direct external uplink on B or C. At far left OUTSIDE the internal backbone area, show "학교 Wi-Fi / VPN" user cloud feeding ONLY Groot_A through a labeled external-link arrow "외부 IP 192.168.16.230". A alone bridges the external side to the blue internal backbone. Small secondary cloud "DGX Spark · Ollama" near the external side with an unobtrusive dotted route labeled "LLM 추론 · A 경유" from B through A, without implying DGX sits on the internal backbone. Add a small bottom note exactly: "설명용 버스형 표현이며 실제 네트워크는 A를 관문으로 하는 2세그먼트 구조". Use only these labels, exactly spelled and no extra hosts or IPs. Make the bus topology shape visually unmistakable, perfectly clean 90-degree connectors, distinct solid network lines and dotted LLM route. No coax cable, terminators, physical bus claim, 3D racks, watermark or logo. High-contrast, generous whitespace, readable Korean/English text.
```
