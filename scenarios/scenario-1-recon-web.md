# 시나리오 1 — 외부 정찰 + 웹 공격 (DVWA, A 경유)

목표: Kali → Groot_A(FW+Suricata+WAF) → DVWA 경로에서 정찰·스캐너·SQLi·XSS·인증 무차별을 발생시키고, 각 단계가 우리 SOC에 뜨는지 확인한다. 절차는 `references.md`의 표준 문서를 따르고, 여기서는 **대상·기대 탐지·기대 대응**만 정의한다.

- 대상: `http://192.168.16.230/` → `/dvwa/` (A의 WAF가 C DVWA로 프록시)
- 선행조건: DVWA `low`, Kali는 세그먼트 직결(VPN 금지). WAF는 DetectionOnly(관찰) 상태 가정.
- 공격자 IP = `<KALI_IP>` (실행 시 기록). WAF 경유라 C 로그의 srcip는 mod_remoteip로 실제 Kali IP.

| 단계 | 능력(레퍼런스) | 대상 | 기대 탐지 (관찰 단계) | 기대 대응 |
|---|---|---|---|---|
| 1.1 정찰 | 포트/서비스 스캔 (Nmap, WSTG-INFO) | 192.168.16.230 | A 호스트 FW inbound drop 로그 → Wazuh **100128**, 60초 16+ → **100129**(스캔) | 스캔 소스 `agent_block add <KALI_IP>` |
| 1.2 웹 스캐너 | 웹 서버 스캐너 (Nikto) | `/`,`/dvwa/` | WAF CRS **913100**(scanner UA), Suricata ET 스캐너 룰, Wazuh 웹 4xx **31101** | (차단 전환 시) WAF 403 |
| 1.3 SQLi 자동 | sqlmap (WSTG-INPV-05, Wazuh SQLi PoC) | DVWA SQLi 페이지 | **Suricata sid 2008538**(sqlmap UA), CRS **942100**(libinjection), Wazuh **31103**(시도)/**31106**(성공 200), 로컬 **100102**(WAF 임계), 버스트 **100103** | `agent_block add <KALI_IP>` → 이후 타격 시 **100126/100127** |
| 1.4 SQLi 수동 | UNION/에러기반 (WSTG-INPV-05) | DVWA SQLi 페이지 | CRS 942xxx, Wazuh 31103 | 동일 |
| 1.5 XSS | 반사형 XSS (WSTG-INPV-01) | DVWA XSS 페이지 | CRS 941xxx, Wazuh **31105** | (차단 전환 시) WAF 403 |
| 1.6 인증 무차별 | 로그인 무차별 (Hydra, WSTG-ATHN-03) | DVWA `login.php` | 웹 로그 다발 4xx/POST → **31101** 다발, 로컬 WAF 버스트 **100103** | `agent_block add <KALI_IP>` |
| 1.7 (선택) SSH 무차별 | Hydra (Wazuh 무차별 PoC) | C의 SSH(내부) | Wazuh **5710/5712/5551** (PAM 상관) | `agent_block`(단, C는 내부 — 대응은 A 경계에서 소스 차단) |

## 검증 포인트
- 실행 직후 Wazuh Discover에서 `data.srcip: <KALI_IP>` + 시간창으로 위 룰 id가 실제로 뜨는지 대조.
- `agent_block add` 후: Kali에서 같은 요청 반복 → A에서 전부 drop(HTTP 000), Wazuh **100121**(차단) + **100126/100127**(차단 소스 계속 타격) 확인.
- `agent_block del` 또는 TTL 만료 후 정상화 확인.
- WAF `MODSEC_RULE_ENGINE=On` 전환 실험 시: 1.3/1.5가 **403**으로 바뀌고 audit.log의 rule id 동일 — "관찰 vs 차단" 비교표를 `alerts.md`에 기록.

## 주의
- 1.7 SSH 무차별은 C의 내부 IP(10.200.10.20)를 향하므로 A의 경계 탐지가 아니라 C 엔드포인트(agent 002) 탐지다. Kali가 C SSH에 직접 도달 가능한 경로가 있는지 먼저 확인(과도기엔 C ens192 192.168.16.232).
- 모든 파괴 없는 단계지만, DVWA 상태가 바뀌면 "Create/Reset Database"로 원복.
