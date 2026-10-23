# Groot_A IPS(Suricata) 개선점 — **검증 반영판** (FW·WAF·IPS 합본 대비)

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 이 문서의 제출/검사/적용 기록은 해당 날짜의 범위다. 공식 규칙 후보27개는 조사 자료이며 자동 설치·운영 반영 완료가 아니다. Suricata passive 탐지, DVWA WAF와 실습 WAF의 서로 다른 모드, 정확 후보 승인 경계를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

> **2026-10-08 후속 정정:** 이날 SSH로 ET+local 합본·Phase-A·로컬 SID 11개·passive 설정을 재확인했다. 10/06 후반 보안 이벤트 MCP와 Hermes 조회에서 로컬 SID `1000010`→Wazuh `100110` 인덱싱을 확인했다. 따라서 아래의 “local SID 분류 미확정”은 이전 점검 시점의 한계이며, 나머지 SID·시나리오 실발화는 여전히 미검증이다. 승인형 `rule-a` 배포로 Suricata 로컬 룰 변경 경로는 마련됐지만 실제 승인→적용 E2E와 ET Open 자동 갱신은 이번 배포의 완료 항목이 아니다. 9/29 감사 원문은 당시 기록으로 보존한다. [최신 상태](../STATUS.md) · [배포 기록](../대화기록/2026-10-08.md).

> **후속 상태(2026-10-06 이번 세션 SSH 재점검):** 이 문서의 “현재 상태”와 §2 수치는 2026-09-29 읽기 전용 감사 스냅샷이다. A에서 ET+local 합본 `/rules/all.rules`(47,694,450B, local SID 11개) 단일 `-S` 로딩과 Phase-A 옵션·threshold 파일, passive `-i ens192`를 재확인했다. 앞선 [세션 1 기록](../대화기록/2026-10-06.md)에는 eve `community_id` 생성도 확인돼 있다. 따라서 아래 “로컬 SID 0개”와 “community-id 없음”, `-S /rules/suricata.rules`는 **현재 상태가 아니다**. B manager의 local SID 분류 여부는 이번 점검에서 확정하지 못했으며 공격 실발화 검증도 필요하다. NFQUEUE 인라인/drop은 미완료다.
>
> 10월 6일 기록은 이 문서의 Phase A **전체 항목**이나 Phase B **전체 항목** 완료를 뜻하지 않는다. 실제 확인된 것은 위 합본 로딩과 `--set` 범위다. 아래 개선안·통합 변경표는 9월 29일 감사 당시의 제안으로 보존한다.

> 작성일 **2026-09-29** · 대상 **Groot_A (`groot-sec`)** · 계층 **IPS = Suricata 8.0.6 (Docker `jasonish/suricata:latest`)**
> 방식 **2026-09-29 읽기 전용 원격 점검(SSH)** — **당시 아무것도 변경하지 않았음.** 아래는 해당 시점에 식별·제안한 개선안이다.
> 점검자 security05@ync.ac.kr · 접속 근거 `팀접속안내.md`
>
> ---
> **📌 이 문서는 `GROOT_A_IPS_SURICATA_개선점.md`의 라이브 재검증(2026-09-29) 반영판이다.**
> - 원본 대비 **정정한 부분은 ✏️[정정]** 으로, **라이브로 확증된 값은 ✅[검증]** 으로 표기.
> - 상세 근거·판정표는 짝 문서 `GROOT_A_IPS_검증리포트.md` 참조.
> - **정정 요지 2건:** ① IPS-02 백엔드 L3 출발지 IP 오기(172.19.0.2→WAF 172.18.0.2, 실제 온-와이어 src=호스트 10.200.10.1) ② 발화이력에서 sqlmap(2008538) 제거(라이브엔 SSH스캔 2001219만 존재).
> - 러닝 카운터(총패킷·TLS·ARP·unknown_ethertype)는 재확인 시점값으로 갱신하고 "시점값"임을 명시. 구조·설정·룰카운트는 전부 EXACT 일치.

---

## 0. 이 문서를 쓰는 법 (FW·WAF·IPS 한 번에 적용하기 위한 규칙)

나중에 **FW(nftables) / WAF(ModSecurity+CRS) / IPS(Suricata)** 개선안을 **하나의 변경 세트로 합쳐 한 번에 적용**할 수 있도록,
모든 항목을 아래 **공통 레코드 스키마**로 적었다. FW·WAF 문서도 **같은 스키마 + 같은 `merge_tag` + 같은 Phase**로 작성하면
§7의 **통합 변경표(마스터 체인지셋)** 한 장으로 합쳐진다.

**공통 레코드 필드**

| 필드 | 뜻 |
|---|---|
| `ID` | 계층 접두사 + 번호 (IPS-01 …). FW-xx / WAF-xx 와 병합 |
| `심각도` | 🔴 High / 🟠 Medium / 🟡 Low (랩 맥락으로 보정됨) |
| `merge_tag` | 통합 시 묶는 축: `mode-flip` `custom-rules` `ruleset-tuning` `asset-vars` `visibility` `logging-siem` `lifecycle` `performance` `integration` `container-hardening` |
| `Phase` | A(무중단·정확도/로깅) · B(룰 파이프라인·무중단) · C(예방전환·창 필요) |
| `현재 상태` / `왜` / `개선안` / `적용 위치` / `선행조건` / `적용 리스크` / `난이도` | 아래 각 항목 참조 |

> **핵심 프레이밍:** Suricata가 지금 "탐지 전용(IDS/passive)"인 것은 **설계상 1단계**다(compose 주석 `1단계 IDS/passive`, WAF도 `DetectionOnly`).
> 따라서 대부분의 항목은 "설정이 틀렸다"가 아니라 **"2단계(예방/IPS)로 가려면 + 탐지 정확도를 높이려면 손봐야 할 것"** 이다.

---

## 1. 한 장 요약

지금 Suricata는 **정상 기동·무결(✅[검증] 52,483룰 로드, 실패 0, 커널드롭 0)** 이지만, **"IPS"라는 이름값을 아직 못 한다.** 진짜 손봐야 할 급소 5가지:

1. **가시성(visibility) — 최우선.** 센서가 `ens192`(외부/캠퍼스망)만 물고 있고 그 위 트래픽은 대부분 **암호문(✅[검증] TLS 플로우 2,651 vs HTTP 3 · *시점값 2026-09-29*)**. 실제 웹 공격 평문 구간(WAF→Groot_C:80)은 **감시하지 않는 `ens160`** 으로 흐른다 → 웹 공격 룰 ✅[검증] **7,301개**가 **볼 게 거의 없다.**
2. **룰 파이프라인 — 모든 것의 병목.** `-S /rules/suricata.rules`(✅[검증] 45.5MiB 단일 고정 파일, mtime Sep 26 동결)를 **배타 로드**해서 `suricata.yaml`의 `rule-files:`·`local.rules`·`suricata-update` 산출물을 **전부 무시**한다(✅[검증] 엔진 로그 "1 rule files processed"). 이걸 안 풀면 커스텀 룰·drop 전환·자동 업데이트가 **전부 불가**.
3. **예방 전환(IPS화).** 지금은 `-i`(수동 탭)이고 **룰 52,483개가 100% `alert`(✅[검증] drop 0)**. 인라인으로 바꿔도 **아무것도 차단 못 함.** Groot_A는 L3 라우팅/NAT 관문이라 인라인은 **NFQUEUE(`-q`)** 로 가야 하고, 그 뒤 **선별 drop 정책**이 필요.
4. **랩 전용 커스텀 시그니처 0개.** Log4Shell(C에 배포됨)·DVWA·attack_sim S0–S7에 대응하는 **고신뢰 로컬 룰이 하나도 없다**(✅[검증] 로컬 SID 100만대 0개) → 퍼플팀/ Wazuh가 물고 갈 **고정 SID**가 없음.
5. **룰 자동 업데이트 없음.** `suricata-update`가 2026-09-26 **한 번** 돌고 이후 **cron/timer 없음**(✅[검증] timer·cron 부재) + 로드 경로가 **읽기 전용** → 룰셋이 **영구 동결**, 시간이 갈수록 탐지력 저하.

성능은 현재 트래픽이 미미(✅[검증] 195k pkt·*시점값*, 커널드롭 0)해서 **급하지 않다.** attack_sim 부하시험 전 점검 항목으로 뒤로 뺀다.

---

## 2. 현재 상태 스냅샷 (✅ 2026-09-29 라이브 재확인 — 전 항목 EXACT 일치, 카운터는 시점값)

| 구분 | 값 |
|---|---|
| 엔진 | Suricata **8.0.6 RELEASE**, Docker `jasonish/suricata:**latest**`(digest d4fd70…), `network_mode: host`, caps NET_ADMIN/NET_RAW/SYS_NICE, restart unless-stopped |
| 실행 인자 | ✅ `-i ens192  -S /rules/suricata.rules  --set vars.address-groups.HOME_NET=[10.200.10.0/24,192.168.16.230/32]  --set stats.interval=60` (inspect Args와 EXACT 일치) |
| 동작 모드 | **AF_PACKET IDS/passive (단일 탭)** — ✅ `-q`/NFQUEUE 없음, af-packet `copy-mode: ips` 주석(yaml L732), `nfq.mode` 주석(L2063). eve `action:allowed` |
| 룰셋 | **ET Open 100%**, ✅ 47,684,589B(45.5MiB)/**144,875줄**, **활성 52,483개 전부 `alert`(drop/reject/pass 0)**, 비활성 주석 **19,491**, 로컬(SID 100만대) **0**, 중복 SID **0** |
| 인터페이스 | ✅ `ens160`=10.200.10.1/24(내부 DMZ, **미감시**) · `ens192`=192.168.16.230/25(감시 중, 외부/캠퍼스). default via 192.168.16.129(ens192), 10.200.10.0/24 via ens160 |
| 탐지 변수 | ✅ HOME_NET 위와 같음(--set), yaml 기본은 RFC1918. EXTERNAL_NET=`!$HOME_NET`(L24), HTTP_SERVERS=`$HOME_NET`(L27), HTTP_PORTS=`80`(L42), `threshold-file` **주석**(L2339), `community-id: false`(L157) |
| 로깅 | eve.json(alert/anomaly/http/dns/tls/fileinfo/ssh/dhcp/flow/stats) + fast.log, Wazuh(Groot_B)가 eve.json 수집 |
| 헬스 | ✅ 엔진 로그 "**52483 rules successfully loaded, 0 failed, 0 skipped**", **커널드롭 0**, 워커 스레드 **2개**, detect.profile `medium`. ✅ 발화 이력 = **`ET SCAN Potential SSH Scan`(sid 2001219)만** (src 192.168.10.230/.244 → 192.168.16.230:22) — *sqlmap(2008538)은 현 로그에 없음* |
| 배포 | 선언형: `/home/groot_a/capstone/secstack/docker-compose.yml` + `deploy_secstack.sh` (MON_IFACE 파라미터화) |
| 이웃 계층 | **FW** = 호스트 nftables. ✅ 커스텀 `inet capstone_fw`가 **input `policy drop`**(허용목록) + `never_block`(락아웃 가드) + **`agent_block`(TTL 셋, raw prerouting)** 운용, 별도 `capstone_gw/fwd`(DMZ 마스커레이드·`10443→B:443` DNAT). ✅ `iptables -P INPUT ACCEPT`로 보이지만 그건 Docker 테이블뿐, 실제 호스트 입력은 capstone_fw가 드롭. · **WAF** = ✅ ModSecurity v3.0.16+CRS 4.29.0, `SecRuleEngine DetectionOnly`, PL1/anomaly 5 |

> **📎 도커 브리지 사실(IPS-02 정정 근거):** ✅ `secstack_waf-net` = **172.18.0.2**(WAF, gw 172.18.0.1) · `chatproxy_chat-net` = **172.19.0.2**(chatproxy) · docker0=172.17.0.1. MASQUERADE 규칙 `-s 172.18.0.0/16 ! -o br-aaadd… → MASQUERADE` 존재.

---

## 3. 개선점 — 🔴 High (7)

### [IPS-01] 웹 공격 벡터 사각지대: ens192는 암호문만, 평문 HTTP 구간은 미감시 ens160으로 흐름  ✅[검증]
- **merge_tag** `visibility` · **Phase** B(감시망 확장) → C · **난이도** high · **원본ID** `ips-blind-to-web-attack-path`
- **현재 상태:** Suricata는 `ens192` 단일 수동 탭. ✅[검증] 앱계층 플로우 비율 **TLS 2,651 vs HTTP 3**(*시점값 2026-09-29; HTTP=3은 원본과 EXACT*). 프런트 웹은 HTTPS(443/8443)로 WAF에서 TLS 종단되고, 복호화된 요청(`WAF→groot-web:80`, Groot_C 10.200.10.20)은 **ens160으로 나가 ens192에 안 보임**. 웹 공격 룰 ✅[검증] **7,301개**가 볼 평문이 사실상 없음. ✏️[정정] 실제 발화 이력은 **SSH 스캔(sid 2001219)뿐**(sqlmap 2008538은 현 로그에 없음 — 과거 수동 프로브로 추정).
- **왜:** IPS의 존재 이유인 "웹/CVE 공격 트래픽"을 못 본다. 탐지 커버리지가 **검증되지 않은 가정** 상태 → *본 재검증으로 "백엔드 평문이 ens192에 사실상 안 보인다"가 flow.http=3으로 실증됨.*
- **개선안(식별만):** ① Suricata에 평문 백엔드 구간 제공 — `-i ens160` 추가(또는 af-packet 2번째 스탠자), 더 정밀하게는 WAF 컨테이너 업스트림 veth의 `WAF→10.200.10.20:80` 플로우만 미러. **단, 이것만으로는 부족**(→ IPS-02). ② S0–S7·Log4Shell 각각에 **기대 발화 SID 커버리지 매트릭스**를 만들어 attack_sim으로 실증. ③ 암호화된 프런트 구간은 **WAF/CRS를 웹 페이로드 센서로 명시**하고 Suricata는 TLS 메타데이터로(→ IPS-12).
- **적용 위치:** compose `suricata.command`(MON_IFACE/`-i ens160`)+`deploy_secstack.sh`, `suricata.yaml` af-packet 섹션, 룰셋 옆 커버리지 매트릭스 산출물.
- **선행조건:** IPS-02, IPS-05 · **적용 리스크:** 검사량 약 2배·NIC 간 라우팅 플로우 중복 카운트 가능 → IPS-02 먼저 검증할 것.

### [IPS-02] ens160을 물어도 ET 웹 룰은 안 터진다 — 리버스 프록시 백엔드는 masquerade로 src가 HOME_NET(EXTERNAL_NET 아님)  ✏️[정정]
- **merge_tag** `asset-vars` · **Phase** B · **난이도** med · **원본ID** `web-rule-direction-snat-trap`
- **현재 상태:** ET Open 웹 룰은 `alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS`(HTTP_SERVERS 기본=$HOME_NET). ✏️[정정] **리버스 프록시 WAF 컨테이너는 `172.18.0.2`**(원본의 "172.19.0.2"는 오기 — 172.19.0.2는 chatproxy). WAF가 `groot-web(10.200.10.20:80)`로 낼 때 트래픽은 **ens160으로 송출**되고 Docker MASQUERADE(`-s 172.18.0.0/16 ! -o br-aaadd… → MASQUERADE`)가 **출발지를 호스트 ens160 IP `10.200.10.1`로 재작성** → 이는 10.200.10.0/24=HOME_NET 안 → **방향 조건(EXTERNAL→HOME) 실패로 룰이 매칭 안 됨.** 진짜 클라이언트 IP는 XFF에만 남음. ✅[검증] 백엔드 평문이 사실상 안 보임(flow.http=3).
- **왜:** "ens160만 물면 웹 커버리지 생긴다"는 착각을 막는다. 방향(EXTERNAL→HOME)을 안 맞추면 7,301개 룰이 조용히 죽어 **가짜 안심**을 준다.
- **개선안(식별만):** 백엔드 구간 웹 탐지가 정말 필요하면 `HTTP_SERVERS=[10.200.10.20/32]` 고정 + 해당 플로우에서 캠퍼스/WAF-origin이 external로 잡히게 EXTERNAL_NET 재정의, 진짜 클라이언트는 `http.request_header`(XFF)로. 아니면 **웹 페이로드 탐지는 ModSecurity/CRS 몫으로 명시**하고 이 룰군에 웹 벡터를 기대하지 말 것. **※ masquerade로 백엔드 src가 10.200.10.1로 뭉개지므로 ens160 감시만으로는 클라이언트 식별 불가 — 반드시 XFF 상관 병행.**
- **적용 위치:** compose `--set vars.address-groups.*` 및 `suricata.yaml` vars.address-groups(HOME_NET/EXTERNAL_NET/HTTP_SERVERS).
- **선행조건:** IPS-01 · **적용 리스크:** HTTP_SERVERS 축소·EXTERNAL_NET 변형이 무관 룰을 침묵시키거나 이상한 교차-NIC 방향성을 만들 수 있음. 오설정 시 가짜 확신.

### [IPS-03] 배타 `-S` 46MB 고정 blob이 suricata-update 관리 모델을 대체 — 룰 정책이 검토·재현 불가, 로컬 편집/재생성이 조용히 무효화  ✅[검증]
- **merge_tag** `lifecycle` · **Phase** B · **난이도** high · **원본ID** `hand-merged-S-bypasses-managed-sources` · **⭐ 여러 항목의 선행 루트**
- **현재 상태:** `-S /rules/suricata.rules`는 **배타 단일 파일**로 `suricata.yaml`의 `rule-files:`를 덮어씀(✅[검증] inspect Args + 엔진 로그 "1 rule files processed"). 이 파일은 2026-09-26 한 번 생성 후 동결(✅ 45.5MiB/144,875줄, mtime Sep 26 12:59). `enable/disable/drop/modify.conf` 없음. 여기에 `local.rules`를 넣거나 `rule-files:`를 고쳐도 **로드 안 됨**, `suricata-update`가 `/var/lib/suricata/rules`에 써도 엔진에 **안 닿음**.
- **왜:** **선별 drop·로컬 시그니처·룰 큐레이션·자동 업데이트가 전부 이 구조 때문에 막혀 있다.** IPS-04/05/07/08의 공통 병목.
- **개선안(식별만):** `-S` 제거 → `suricata-update`가 `/var/lib/suricata/rules/suricata.rules`(rw 볼륨 `secstack_suricata-lib`)를 소유하고 `suricata.yaml`의 `default-rule-path`+`rule-files: [suricata.rules]`로 로드. 정책은 git로 추적하는 작은 `enable.conf/disable.conf/drop.conf/modify.conf`로 표현.
- **적용 위치:** compose `suricata.command`(`-S …` 삭제), `suricata.yaml` default-rule-path/rule-files, `/etc/suricata/{enable,disable,drop,modify}.conf`(rw 볼륨).
- **선행조건:** 없음(먼저 해야 함) · **적용 리스크:** 로드 대상 룰이 바뀜 → `suricata -T` + 경보수 새니티(sqlmap 프로브 재실행)로 검증. 경로 오설정 시 룰 0개 로드 가능.

### [IPS-04] 룰 52,483개 전부 `alert` — 인라인으로 가도 선별 drop 정책 없이는 아무것도 차단 못 함  ✅[검증]
- **merge_tag** `ruleset-tuning` · **Phase** C · **난이도** med · **원본ID** `all-rules-alert-never-drop`
- **현재 상태:** ✅[검증] 활성 룰 100% `alert`(drop/reject/pass 0). `alert` 룰은 인라인이어도 `action:allowed`로 통과시킴.
- **왜:** 1단계→2단계 전환의 최대 함정. 모드만 인라인으로 바꿔도 예방 효과 0.
- **개선안(식별만):** 2단계에서 `suricata-update drop.conf`로 **고신뢰 classtype/SID만 선별 drop**(공격 경로 관련 trojan-activity/command-and-control/exploit-kit + IP 평판부터), 노이즈·광범위 룰은 alert 유지, 호스트에서 재생성 후 `suricatasc -c reload-rules`로 반영. 전역 스위치가 아니라 **단계적 확대.**
- **적용 위치:** `/etc/suricata/drop.conf`(suricata-update) → 관리형 suricata.rules 재생성 → `update.yaml` reload-command.
- **선행조건:** IPS-05(NFQUEUE), IPS-03(관리형 소스) · **적용 리스크:** 과도한 drop.conf가 오탐 잦은 룰을 drop으로 만들어 정상 트래픽 차단. 좁게 시작해 단계 상향.

### [IPS-05] 2단계 인라인은 AF_PACKET 브리지가 아니라 NFQUEUE(`-q`)여야 함 — Groot_A가 L3 라우팅/NAT 관문이라서  ✅[검증]
- **merge_tag** `mode-flip` · **Phase** C · **난이도** med · **원본ID** `run-mode-nfqueue-not-afpacket-bridge` · **⭐ 예방 로드맵의 핵심 축**
- **현재 상태:** `-i ens192`(수동 탭). ✅[검증] `-q`/NFQUEUE·af-packet `copy-mode: ips`/`copy-iface` 주석. 호스트는 nftables DNAT/NAT + docker-proxy로 80/443/8443 발행(✅ nft prerouting DNAT·capstone_gw masquerade·capstone_fwd 확인).
- **왜:** af-packet `copy-mode:ips`는 L2 브리지라 호스트의 nftables DNAT/NAT를 깨뜨림. ens192/ens160은 서로 다른 라우팅 L3 세그먼트. **NFQUEUE는 라우팅 이후 netfilter와 자연스럽게 결합**하고, 컨테이너는 이미 `network_mode host`+NET_ADMIN/NET_RAW 보유.
- **개선안(식별만):** 2단계에서 `-i ens192` → `-q 0`(워커 2개면 `-q 0 -q 1` 분산), 이미 campus→DMZ를 스코프하는 nftables `DOCKER-USER/FORWARD` 경로에 `queue num 0` verdict 추가, `suricata.yaml` `nfq: { mode: accept }`. **compose + nftables를 한 변경 세트로 동시 커밋.** af-packet 브리지는 이 호스트에서 **하지 말 것.**
- **적용 위치:** compose `suricata.command`(`-i …`→`-q 0`), 호스트 nftables `DOCKER-USER/FORWARD`(`queue num 0`), `suricata.yaml` `nfq:`, `deploy_secstack.sh`.
- **선행조건:** 없음 · **적용 리스크:** 인라인 = 데이터 경로 초크포인트. 큐 규칙 오설정/엔진 정지 시 Groot_A 통과 트래픽 중단 → IPS-10(fail-open/게이트) 필수.

### [IPS-06] 랩 자체 공격(Log4Shell·DVWA·S0–S7)에 대한 로컬 커스텀 시그니처 0개 — 물고 갈 결정론적 고정 SID 없음  ✅[검증]/✏️[정정]
- **merge_tag** `custom-rules` · **Phase** B · **난이도** med · **원본ID** `no-local-signatures-for-lab-attacks`
- **현재 상태:** ✅[검증] 로컬 SID 대역(1,000,000–1,999,999) 비어 있음, 룰셋 100% ET Open. 배포된 Log4Shell(CVE-2021-44228)·DVWA·S0–S7 어디에도 튜닝된 고신뢰 룰 없음. ✏️[정정] 발화 이력은 **sid 2001219(ET SCAN SSH)뿐** (원본의 "2008538/2001219"에서 sqlmap 2008538은 현 로그에 없음).
- **왜:** 퍼플팀 검증·Wazuh 상관에 쓸 **안정적 랩 SID**가 없다. 자체 시나리오 탐지 여부를 증명할 수단 부재.
- **개선안(식별만):** 예약 SID 1000000–1000099에 버전관리 `local.rules` 작성, suricata-update `local` 소스로 등록해 재생성에도 살아남게: (a) 웹 호스트 향 Log4Shell 인바운드 JNDI + 난독화 변종, (b) Groot_C의 2차 LDAP/RMI/이상 DNS **egress**, (c) DVWA 경로(`/vulnerabilities/exec|sqli|fi|upload/`)+`security=low` 쿠키, (d) S0–S7 각 시나리오 고정 도구/UA/페이로드 마커 1개씩. 각 룰은 harness로 검증 후에만 drop 전환.
- **적용 위치:** `/home/groot_a/capstone/suricata/ruleset/local.rules`, `update.yaml` `local:` 소스(또는 `suricata-update add-source`).
- **선행조건:** IPS-03 (안 그러면 `-S` 하에서 무시/재생성시 소실) · **적용 리스크:** `${jndi`/`${` 과광범위 매칭은 정상 템플릿/JSON에 오탐 → 웹 dest·HOME_NET 스코프로 좁히고 S0–S7로 검증 후 drop.

### [IPS-07] 룰 업데이트 트리거 없음 + 연결된 reload-command가 무효 — ET Open 룰셋 영구 동결(읽기전용 `-S` 경로), 탐지력 조용히 붕괴  ✅[검증]
- **merge_tag** `lifecycle` · **Phase** B · **난이도** med · **원본ID** `no-update-automation-stale-ruleset`
- **현재 상태:** ✅[검증] 업데이트용 cron/systemd timer 없음, 룰셋 2026-09-26 이후 정적. `update.yaml`엔 `reload-command: suricatasc -c reload-rules`만 존재. `/rules`는 **읽기전용** 마운트인데 suricata-update는 `/var/lib/suricata/rules`(rw)에 씀 → 업데이트가 엔진에 **안 닿음**(reload해도 같은 동결 blob 재로드).
- **왜:** 위협 인텔은 매일 바뀌는데 룰은 고정 → 시간이 갈수록 새 위협 미탐.
- **개선안(식별만):** IPS-03로 배관부터 고친 뒤, groot-sec에 systemd timer+service로 매일(지터 포함) `docker exec suricata suricata-update` → `docker exec suricata suricatasc -c reload-rules`, added/removed/enabled 카운트를 로그로 남겨 변경 추적.
- **적용 위치:** `/etc/systemd/system/suricata-update.{timer,service}`(또는 `/etc/cron.d`), `update.yaml` reload-command 유지.
- **선행조건:** IPS-03 · **적용 리스크:** 매일 자동 업데이트가 회귀 SID(로드 오류/과탐)를 끌어올 수 있음 → suricata-update reload 게이팅 유지 + diff 로깅으로 되돌리기 가능하게.

---

## 4. 개선점 — 🟠 Medium (7)

### [IPS-08] egress/C2/trojan 룰 ~1.5만+개가 이 탭에선 구조적으로 발화 여지 적음 — 성능이 아니라 "커버리지 착시" 문제  ✅[검증]/✏️[표현 완화]
- **merge_tag** `visibility` · **Phase** B · **난이도** med · **원본ID** `outbound-c2-detection-inert`
- **현재 상태:** ✅[검증] classtype이 egress 중심(**trojan-activity 15,277 / domain-c2 9,987 / command-and-control 5,168** — EXACT, `$HOME_NET→$EXTERNAL_NET`). 그러나 on-wire 유효 HOME_NET은 192.168.16.230/32(비컨하는 관문이 아님). 비컨할 호스트(C/B)는 미감시 ens160. ✏️[완화] 원본의 "구조적으로 무력(inert)"은 다소 강함 → **"발화 여지가 적음(저가치)"** 이 정확(관문 자신이 털려 비컨하면 발화 가능).
- **왜:** 커버리지가 있어 보이지만 실제론 낮음(신호 명료도 저하). 단 **성능 레버는 아님**(커널드롭 0).
- **개선안(식별만):** 1차 해법은 **가시성(ens160 감시)**. 성능 목적의 맹목적 트리밍 금지. suricata-update enable/disable-conf로 **의도적 큐레이션**: web-application-attack/attempted-admin/scan/특정 exploit + TLS 메타 유지, 발화 여지 적은 egress군은 비활성화하거나 "인라인+egress 감시 단계용 예약"으로 근거와 함께 문서화.
- **적용 위치:** suricata-update `enable.conf/disable.conf`, 큐레이션 근거를 룰셋 디렉터리에 문서화.
- **선행조건:** IPS-01 · **적용 리스크:** egress 카테고리 비활성화 시 이후 egress 감시/인라인 단계에서 커버리지 손실 → 공격적 disable보다 "문서화+선별 enable" 선호.

### [IPS-09] HOME_NET이 ens192가 못 보는 10.200.10.0/24를 광고, 보호망 정의가 3개 계층에 흩어짐  ✅[검증]
- **merge_tag** `asset-vars` · **Phase** A(통합) · **난이도** med · **원본ID** `home-net-invisible-dmz`
- **현재 상태:** ✅[검증] `--set HOME_NET=[10.200.10.0/24,192.168.16.230/32]` vs yaml 기본 RFC1918(`[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]`) vs nftables 스코프 vs WAF `BACKEND=groot-web:80`(10.200.10.20) — 보호 자산이 3곳+에 인코딩. ens192는 10.200.10.0/24를 못 보므로 유효 on-wire HOME_NET=192.168.16.230/32.
- **왜:** (설계상 의도된 override이고 /32 절반은 정상 동작하므로 misconfig는 아님) 그러나 **단일 진실원(source of truth)** 부재로 3계층 정의가 어긋날 위험 + DMZ 절반은 ens160 감시 전까진 희망사항.
- **개선안(식별만):** `secstack/.env`의 단일 보호망 정의를 compose `--set HOME_NET`이 소비하고 nftables 스코프·WAF BACKEND과 교차 참조. ens160 감시 전까진 "10.200.10.0/24 절반은 aspirational, 유효 HOME_NET=192.168.16.230/32"로 주석. 인라인/ens160 도입 시 DMZ 절반이 실효화.
- **적용 위치:** compose `--set vars.address-groups.HOME_NET`(← `secstack/.env`), 2번째 인터페이스 추가 시 `suricata.yaml` af-packet.
- **선행조건:** IPS-01 · **적용 리스크:** HOME_NET 변경은 발화 룰 집합을 바꿈 → 기존 발화 탐지가 조용히 사라지지 않는지 재검증.

### [IPS-10] 계획된 인라인 NFQUEUE에 fail-open/헬스게이트/롤백 없음 — IPS 크래시 시 campus→DMZ 블랙홀
- **merge_tag** `integration` · **Phase** C · **난이도** low · **원본ID** `inline-nfqueue-fail-open-and-gating`
- **현재 상태:** 지금은 수동(`-i`)이라 정지해도 탐지만 멈춤. nfq fail-open 미설정, 룰 로드 ~12초, `restart: unless-stopped`, 배포는 단발 `docker compose up -d`로 헬스게이트/스크립트 롤백 없음.
- **왜:** 인라인 전환 후엔 리더 없는 nftables 큐 verdict가 기본 fail-closed → 12초 리로드 창·재기동이 통과 트래픽을 끊음.
- **개선안(식별만):** 전환 전에 `suricata.yaml` nfq `fail-open: yes` + nftables verdict에 `queue num 0 bypass`. FW+IPS+WAF 전환을 **런북**으로 감싸기: 전환 전 설정 스냅샷, 헬스게이트(룰 실패 0 / 커널드롭 0 유지 / 합성 campus→DMZ:443 통과 / 알려진 악성 프로브 drop 확인), 원커맨드 되돌리기(`-q`→`-i ens192`, 큐 규칙 제거, WAF `DetectionOnly` 복귀). fail-open은 점검 창에서 검증.
- **적용 위치:** `suricata.yaml` `nfq: { fail-open: yes }`, nftables `… queue num 0 bypass`, `deploy_secstack.sh`의 롤아웃/롤백 래퍼.
- **선행조건:** IPS-05 · **적용 리스크:** fail-open은 IPS 장애 시 **미검사 통과**(가용성>보안 트레이드오프) — 런북에 명시.

### [IPS-11] threshold-file 비활성 — 관리자 SSH 스캔 노이즈가 SOC 파이프라인 오염 + drop 전환 시 관리자 접근 자물쇠 위험  ✅[검증 EXACT]
- **merge_tag** `ruleset-tuning` · **Phase** A · **난이도** low · **원본ID** `add-threshold-config`
- **현재 상태:** ✅[검증] `# threshold-file: …` 주석 처리(yaml L2339), in-rule threshold만 활성. ✅[검증] 유일한 실경보 **sid 2001219**가 **관리자 호스트 192.168.10.230·192.168.10.244**에서 발생해(→192.168.16.230:22) 전량 Wazuh 유입(fast.log 4건/eve 8이벤트, 전부 `ET SCAN Potential SSH Scan`).
- **왜:** 노이즈가 SOC 신호를 흐리고, 나중에 스캔 룰을 drop으로 바꾸면 **관리자 SSH를 스스로 차단**할 수 있음.
- **개선안(식별만):** 관리형 threshold 소스 도입 — `/etc/suricata/threshold.in`(suricata-update가 threshold.config로 컴파일), threshold-file 주석 해제, `suppress gen_id 1, sig_id 2001219, track by_src, ip 192.168.10.0/24`로 **확인된 관리자망(192.168.10.0/24)** 만 억제(비관리자 출처엔 룰 유지). 이후 시끄러운 SID엔 rate_filter 추가. `suricatasc -c reload-rules`로 핫리로드. drop 전환 전 필수.
- **적용 위치:** `suricata.yaml` `threshold-file:` 주석 해제, `/etc/suricata/threshold.in`(rw 볼륨, 버전관리).
- **선행조건:** IPS-04(전) · **적용 리스크:** 과광범위 suppress가 진짜 SSH 공격을 가릴 수 있음 → `by_src`로 관리자 CIDR만, sid 2001219 전역 억제 금지. (✅ 관리자 src가 실제로 192.168.10.0/24임을 라이브 확인함.)

### [IPS-12] Suricata는 TLS 플로우를 복호화 못 함 — 웹 페이로드는 WAF/CRS에 위임하고, 암호 플로우는 JA3/JA4/SNI+확장 TLS 로깅으로 활용  ✅[검증]
- **merge_tag** `visibility` · **Phase** A · **난이도** low · **원본ID** `tls-cannot-decrypt-repurpose-ja3`
- **현재 상태:** ✅[검증] ens192의 TLS 플로우(2,651·시점값)는 인터셉트 없음 → 관측 가능한 신호는 핸드셰이크 메타(SNI, JA3/JA3S, cert)뿐. eve tls는 일반 설정, community-id false. fileinfo는 평문 없으니 이 탭에선 거의 무용.
- **왜:** 암호 트래픽에서 뽑을 수 있는 현실적 최대치가 메타데이터다.
- **개선안(식별만):** (a) ModSecurity/CRS를 웹 페이로드 센서로 명시(종단에서 평문을 보는 유일 지점). (b) `app-layer.protocols.tls.ja3-fingerprints: yes`(8.0.6은 JA4도) + eve `tls: { extended: yes }`로 SNI/JA3/JA4/cert를 Wazuh 위협인텔 매칭에 공급. dns eve는 저비용·고피벗이니 유지. ens192엔 file-store/force-hash **추가하지 말 것**(추출할 페이로드 없음).
- **적용 위치:** `suricata.yaml` eve-log `tls:` 서브블록 + `app-layer.protocols.tls`(ja3/ja4)(rw 볼륨).
- **선행조건:** 없음 · **적용 리스크:** JA3/JA4+확장 TLS는 소량 CPU·eve 볼륨 증가, JA3 기반 룰/인텔 없으면 효용 제한, 지문 드리프트로 주기 갱신 필요.

### [IPS-13] community-id 비활성 — agentic SOC의 교차도구 플로우 상관 저하  ✅[검증]
- **merge_tag** `logging-siem` · **Phase** A · **난이도** low · **원본ID** `enable-community-id`
- **현재 상태:** ✅[검증] eve-log `community-id: false`(yaml L157, seed 0 L159). eve.json과 WAF audit 로그가 **같은 Wazuh 매니저(Groot_B)** 로 들어가는데 1:1 플로우 조인용 community_id가 없음.
- **왜:** Suricata-eve ↔ ModSecurity-audit 조인 상관을 위한 표준 플로우 해시가 빠져 있음(5-튜플+타임스탬프 우회는 가능하나 취약). ※ **주의:** WAF↔Suricata는 DNAT/masquerade 경계 때문에 community-id/5-튜플이 양쪽에서 어긋날 수 있어(→IPS-02), 상관은 src_ip+시간+HTTP L7 병행 권장.
- **개선안(식별만):** `community-id: true`, `community-id-seed: 0` 유지(Zeek 기본과 일치해 교차도구 해시 정렬). 리빌드에도 살아남게 compose command에 `--set outputs.eve-log.community-id=true`. 출력 설정 변경이라 **reload-rules가 아니라 컨테이너 재시작** 필요.
- **적용 위치:** `suricata.yaml` eve-log `community-id`(rw `/etc/suricata`), 권장은 compose `--set` 플래그.
- **선행조건:** 없음 · **적용 리스크:** eve 레코드당 필드 1개 추가(무시할 수준) + 짧은 재시작(수동 모드라 잠깐 탐지 공백). 탐지 변화 없음.

### [IPS-14] 엔진 이미지 `:latest` + ET 룰셋 버전 미고정 — "8.0.6 랩" 문서와 달리 pull/업데이트마다 재현 불가  ✅[검증]
- **merge_tag** `container-hardening` · **Phase** A · **난이도** low · **원본ID** `image-and-ruleset-version-not-pinned`
- **현재 상태:** ✅[검증] `image: jasonish/suricata:latest`(현재 8.0.6, digest d4fd70…), ET Open은 2026-09-26 fetch분(버전 기록 없이 파일 mtime만 근거).
- **왜:** 선언형 배포라 `docker compose pull`이 일상 → `:latest` 이동이 룰 파싱/키워드/앱계층 동작을 조용히 바꿔 "8.0.6 문서화 랩"을 어긋나게 함.
- **개선안(식별만):** 이미지를 `jasonish/suricata:8.0.6`(가능하면 `@sha256` 다이제스트) 고정. suricata-update로 ET Open 버전 기록/고정, 마지막 정상본을 정책 파일과 함께 버전관리 → 랩 스냅샷 재현·불량 pull 되돌리기 가능. 둘 다 의도적으로만 bump.
- **적용 위치:** compose suricata `image:`, ET 버전 고정은 `update.yaml` 소스 설정/suricata-update 플래그.
- **선행조건:** 없음 · **적용 리스크:** 다이제스트 고정은 엔진 보안 픽스도 동결 → 주기적 검토형 다이제스트 bump 일정화.

---

## 5. 개선점 — 🟡 Low (6) · 대부분 attack_sim 부하시험 전 점검거리

### [IPS-15] HTTP_PORTS=`80`은 경미·잠재적 갭 — Suricata 8 앱계층 탐지는 포트 무관이라 "웹 실명"이 아님  ✅[검증]
- **merge_tag** `asset-vars` · **Phase** A · **원본ID** `http-ports-narrow` · **난이도** low
- **현재:** ✅[검증] HTTP_PORTS=`80`(yaml L42). `alert http` 앱계층 룰은 포트와 무관하게 HTTP 파싱 → 레거시 `$HTTP_PORTS` 키드 tcp 룰·FILE_DATA_PORTS(L48)만 영향. ens192의 유일 평문 HTTP는 :80, 443/8443은 어차피 TLS.
- **개선안:** ens192 범위에선 80 유지. **ens160이 범위에 들어오면** HTTP_PORTS를 DMZ HTTP 포트집합(최소 Groot_C :80 + 비80 웹 포트)으로, FILE_DATA_PORTS 정렬 — HOME_NET 변경과 같은 `--set`으로 병합.
- **적용 위치:** compose `--set vars.port-groups.HTTP_PORTS=[…]` 또는 yaml vars.port-groups · **선행:** IPS-01.

### [IPS-16] 룰 변경에 `docker compose up -d`(전체 ~12초 재시작) 사용 — 라이브 리로드가 이미 구성돼 있는데 미사용
- **merge_tag** `lifecycle` · **Phase** A · **원본ID** `reload-vs-restart-blind-window` · **난이도** low
- **현재:** 변경을 파일 편집 + `docker compose up -d`로 적용(전체 로드 ~12초). `update.yaml`에 reload-command 있으나 룰 편집엔 미사용.
- **개선안:** 룰만 바뀌면 `docker exec suricata suricatasc -c reload-rules`, `docker compose up -d`는 실행플래그/`--set`/yaml 변경 전용. `deploy_secstack.sh`에 분기 문서화, 리로드는 비피크에, unless-stopped가 먹통 엔진을 자동복구하도록 healthcheck 추가.
- **적용 위치:** 런북/`deploy_secstack.sh`, compose suricata 서비스 healthcheck(선택) · **선행:** 없음 · **리스크:** reload-rules는 yaml/실행플래그 변경 미반영임을 운영자가 알아야 함. 52k 라이브 리로드는 순간 메모리 ~2배·CPU 스파이크 → 비피크 실행.

### [IPS-17] flow/stats/decoder-anomaly 이벤트가 Wazuh로 가는 단일 eve.json을 희석  ✅[검증]
- **merge_tag** `logging-siem` · **Phase** A · **원본ID** `split-eve-outputs` · **난이도** med
- **현재:** ✅[검증] 단일 eve.json에 alert/anomaly/http/dns/tls/fileinfo/ssh/dhcp/flow/stats 전량이 Wazuh로. 저가치 flow/stats/decode-anomaly가 실경보(당일 SSH스캔 4건)를 압도. (L2 노이즈 arp 31,528+unknown_ethertype 10,887·시점값)
- **개선안:** Suricata 8 다중 eve-log 인스턴스 — Wazuh용(alert/http/tls/dns/fileinfo/ssh)과 비전송용(flow/stats/anomaly) 분리. 최소한 Wazuh 피드에서 stats+flow 제외, anomaly는 `types: [applayer]`로 제한해 ARP/unknown-ethertype L2 노이즈 이벤트 차단.
- **적용 위치:** `suricata.yaml` eve-log `types:`/2번째 eve-log 인스턴스, Wazuh agent localfile eve 경로 · **선행:** 없음 · **리스크:** flow를 SIEM에서 빼면 플로우 컨텍스트 손실 → 삭제 말고 비전송 파일로 보존.

### [IPS-18] eve `alert.metadata` 방출 확인 — ET Open의 MITRE/심각도 데이터가 agentic SOC에 닿는지
- **merge_tag** `logging-siem` · **Phase** A · **원본ID** `ensure-alert-metadata` · **난이도** low
- **현재:** ET Open 룰 100%가 metadata(mitre technique/signature_severity/attack_target) 보유. 그러나 eve `alert:` 서브객체 설정이 미확인이라 metadata 방출 여부 불명.
- **개선안:** eve-log `alert: { metadata: true }`(tagged-packets 유지) 후, 라이브 sid 2001219 이벤트로 alert.metadata 채워짐을 Wazuh 룰이 의존하기 전에 검증.
- **적용 위치:** `suricata.yaml` eve-log `alert: metadata:` · **선행:** 없음 · **리스크:** 경보당 크기 소폭 증가 외 단점 없음.

### [IPS-19] ens192 패킷 ~20%가 비-IP L2 노이즈(ARP + unknown-ethertype), 탐지 0 — 배치 신호  ✅[검증]
- **merge_tag** `performance` · **Phase** A · **원본ID** `l2-broadcast-noise-ens192` · **난이도** low
- **현재:** ✅[검증] decoder arp **31,528** / unknown_ethertype **10,887** (총 **195,370** pkt 중 = **21.7%**, *시점값 2026-09-29; 원본 24,896/8,609/~20%에서 러닝 카운터 증가*). ens192는 캠퍼스 /25 브로드캐스트 세그먼트, L2/ARP 룰 0, HOME_NET DMZ 절반은 여기 없음.
- **개선안:** 탐지할지/거를지 결정 — ARP스푸핑/L2 시나리오가 attack_sim에 중요하면 eve `arp` 출력(8.0 신규)+L2 시그니처, 아니면 스코프된 AF_PACKET BPF(`ip/ip6` 한정)로 L2 노이즈 제거. 커널드롭 0이라 비긴급.
- **적용 위치:** `suricata.yaml` af-packet `bpf-filter:`(또는 compose command 말미 BPF), 탐지 택시 outputs.eve `- arp` · **선행:** 없음 · **리스크:** ARP/L2 BPF 드롭은 향후 ARP스푸핑 가시성 상실, 과광범위 BPF는 원하는 트래픽 조용히 드롭 → 스코프·테스트.

### [IPS-20] 부하시험 준비: Hyperscan MPM 확인/고정, 미사용 SYS_NICE로 CPU 어피니티, pending-packets/ring 상향 — 전부 지연(커널드롭 0)
- **merge_tag** `performance` · **Phase** C(부하시험 체크리스트) · **원본ID** `mpm-perf-load-test-readiness` · **난이도** med
- **현재:** mpm-algo/spm-algo `auto`(선택 엔진 미로깅), 워커 2개(✅ 확인) unpinned(set-cpu-affinity: no)인데 SYS_NICE는 부여됨, max-pending-packets 기본 1024, detect.profile medium, af-packet ring 미튜닝, 컨테이너가 WAF/proxy/Wazuh와 호스트 CPU 공유. ✅[검증] 커널드롭 0 @ ~195k pkt.
- **개선안:** attack_sim 부하시험 **전에**: ① `docker exec suricata suricata --build-info | grep -i hyperscan` + 기동 MPM 라인 확인 → 컴파일돼 있을 때만 `mpm-algo: hs`/`spm-algo: hs` 고정(아니면 큐레이션에 의존, IPS-08), ② `threading.set-cpu-affinity: yes` + cpu-affinity로 WAF/proxy 코어와 분리해 워커 코어 예약(SYS_NICE 이미 있음, compose 변경 불필요), ③ max-pending-packets(~4096) 상향 + ens192 af-packet(use-mmap, tpacket-v3, ring/block 확대). 모든 노브는 실행 중 관측된 per-thread 커널드롭 기준으로 조정.
- **적용 위치:** `suricata.yaml`(mpm/spm-algo, threading.set-cpu-affinity+cpu-affinity, max-pending-packets, af-packet ring/block, detect.profile), 확인은 컨테이너 내 `suricata --build-info` · **선행:** 없음 · **리스크:** Hyperscan 미컴파일 시 `mpm-algo: hs` 고정은 init 오류, 코어 오핀은 경합 악화, ring/`profile: high`는 메모리↑(소형 VM OOM). build-info·vCPU 예산 먼저 확인.

---

## 6. 적용 순서 & 의존성 (합본 시 이 순서로 쌓기)

```
[선행 루트] IPS-03 (배타 -S 제거 → 관리형 suricata-update)
    ├─ IPS-06 로컬 시그니처(Log4Shell/DVWA/S0-S7)
    ├─ IPS-07 룰 자동 업데이트(timer + reload)
    ├─ IPS-04 선별 drop.conf ─────────┐
    └─ IPS-08 룰 큐레이션               │
                                        │
[가시성] IPS-01 ens160 감시 ── IPS-02 방향/HTTP_SERVERS 교정 ── IPS-09 HOME_NET 단일화 ── IPS-15 HTTP_PORTS
                                        │
[예방 전환·창 필요] IPS-05 NFQUEUE 인라인 ── IPS-04 drop ── IPS-10 fail-open/헬스게이트/롤백
```

- **의존 핵심:** `IPS-04(drop)`는 **IPS-05(인라인)+IPS-03(관리형 소스)** 이후. `IPS-06/07/08`은 **IPS-03** 이후. `IPS-11(threshold)`은 **IPS-04 전에**(자물쇠 방지).
- **Phase 배치 요약:**
  - **Phase A (무중단·지금 가능, 정확도/로깅/자산):** IPS-09, IPS-11, IPS-12, IPS-13, IPS-14, IPS-15, IPS-16, IPS-17, IPS-18, IPS-19
  - **Phase B (룰 파이프라인·무중단):** IPS-03 → IPS-06, IPS-07, IPS-08 · 가시성 IPS-01/IPS-02
  - **Phase C (예방 전환·점검 창 + 롤백):** IPS-05 → IPS-04 → IPS-10 · 부하시험 IPS-20

---

## 7. 통합 변경표 (FW·WAF·IPS 마스터 체인지셋 — 한 번에 적용용)

> IPS 행은 채워져 있고, **FW/WAF 행은 각 계층 문서에서 같은 스키마로 채워 넣으면** 이 표 한 장으로 합쳐진다.
> "탐지→차단 전환(flip)"은 **WAF·IPS·FW를 하나의 게이트 단계로 묶어** 스냅샷→적용→헬스게이트→(실패 시)원커맨드 롤백으로 실행.

| 변경ID | 계층 | merge_tag | Phase | 파일/위치 | 변경 요지 | 선행 | 롤백 |
|---|---|---|---|---|---|---|---|
| IPS-03 | IPS | lifecycle | B | compose `suricata.command`, suricata.yaml, `/etc/suricata/*.conf` | `-S` 제거→관리형 rule-files + enable/disable/drop/modify.conf | — | compose 이전본(백업 존재) |
| IPS-06 | IPS | custom-rules | B | `ruleset/local.rules`, `update.yaml` local 소스 | 랩 전용 고신뢰 SID 1000000~ 작성 | IPS-03 | 로컬 소스 제거+재생성 |
| IPS-07 | IPS | lifecycle | B | systemd timer/service on groot-sec | 일 단위 suricata-update+reload, diff 로깅 | IPS-03 | timer 비활성 |
| IPS-08 | IPS | ruleset-tuning | B | suricata-update enable/disable.conf | 관측 트래픽 기준 큐레이션 | IPS-01 | conf 비우고 재생성 |
| IPS-01 | IPS | visibility | B→C | compose command, suricata.yaml af-packet | ens160 평문 구간 감시 추가 | IPS-02,05 | `-i ens160` 제거 |
| IPS-02 | IPS | asset-vars | B | vars.address-groups | HTTP_SERVERS/EXTERNAL_NET 방향 교정 (백엔드 src=10.200.10.1 masq 고려) | IPS-01 | vars 복귀 |
| IPS-05 | IPS | mode-flip | C | compose command, **nftables**, suricata.yaml `nfq:` | `-i`→`-q 0` NFQUEUE 인라인 (FW와 동시 커밋) | — | `-q`→`-i ens192`+큐규칙 제거 |
| IPS-04 | IPS | ruleset-tuning | C | `/etc/suricata/drop.conf` | 고신뢰 룰 선별 drop | IPS-05,03 | drop.conf 비우고 재생성 |
| IPS-10 | IPS | integration | C | suricata.yaml `nfq:`, nftables, deploy 스크립트 | fail-open+bypass+헬스게이트+롤백 런북 | IPS-05 | — (안전장치 자체) |
| IPS-09 | IPS | asset-vars | A | `secstack/.env` → compose `--set` | 보호망 단일 진실원 | IPS-01 | .env/vars 복귀 |
| IPS-11 | IPS | ruleset-tuning | A | suricata.yaml `threshold-file`, `threshold.in` | 관리자 SSH 스캔 by_src suppress(192.168.10.0/24 ✅확인) | (IPS-04 전) | threshold.in 비우기 |
| IPS-12 | IPS | visibility | A | suricata.yaml eve `tls`, app-layer tls | JA3/JA4+확장 TLS 로깅, WAF=웹센서 명시 | — | 키 되돌리기 |
| IPS-13 | IPS | logging-siem | A | compose `--set` / suricata.yaml eve | community-id=true (재시작) | — | false 복귀 |
| IPS-14 | IPS | container-hardening | A | compose `image:`, update.yaml | 이미지 8.0.6@digest·ET 버전 고정 | — | 태그 복귀 |
| IPS-15 | IPS | asset-vars | A | vars.port-groups | (ens160 시) HTTP_PORTS/FILE_DATA_PORTS | IPS-01 | 80 복귀 |
| IPS-16 | IPS | lifecycle | A | deploy 스크립트, healthcheck | 룰변경=reload-rules 분기 | — | 문서/헬스체크 제거 |
| IPS-17 | IPS | logging-siem | A | suricata.yaml eve types, Wazuh localfile | eve 다중 인스턴스로 신호 분리 | — | 단일 eve 복귀 |
| IPS-18 | IPS | logging-siem | A | suricata.yaml eve `alert.metadata` | metadata 방출 확인/활성 | — | 키 되돌리기 |
| IPS-19 | IPS | performance | A | suricata.yaml af-packet bpf/eve arp | L2 노이즈 필터 또는 ARP 탐지 | — | BPF 제거 |
| IPS-20 | IPS | performance | C | suricata.yaml (mpm/threading/ring) | 부하시험 전 Hyperscan/어피니티/링 | — | 기본값 복귀 |
| **FW-xx** | FW | *(예: mode-flip, response-actuation, integration)* | *(A/B/C)* | *nftables capstone_fw* | *예: IPS-05용 `queue` verdict 추가, IPS/WAF 탐지→`agent_block` 연동, DMZ egress 필터, SSH 하드닝 (→ `GROOT_A_FW_NFTABLES_개선점.md`)* | — | *규칙셋 이전본* |
| **WAF-xx** | WAF | *(예: mode-flip, crs-tuning, custom-rules)* | *(A/B/C)* | *compose env, crs-setup/exclusion conf* | *예: `SecRuleEngine On` 전환, PL 상향+오탐 예외 튜닝, 랩 커스텀 룰(Log4Shell/DVWA), 이미지/CRS 버전 고정 (→ `GROOT_A_WAF_MODSEC_개선점.md`)* | — | *`DetectionOnly` 복귀* |

### 7.1 "탐지→차단 전환"은 하나의 게이트 단계 (3계층 공동)
- WAF `SecRuleEngine DetectionOnly→On` + IPS `NFQUEUE 인라인 + drop.conf`(IPS-05/04) + FW `INPUT default-deny / queue verdict`를 **동시에** 올린다.
- 절차(런북, IPS-10): ① 전 계층 설정 스냅샷 → ② 변경 적용(`deploy_secstack.sh` + nftables 커밋) → ③ **헬스게이트**(Suricata 룰 실패 0·커널드롭 0 유지, 합성 campus→DMZ:443 통과, 알려진 악성 프로브 차단, WAF audit에 차단 기록) → ④ 실패 시 **원커맨드 롤백**(WAF `DetectionOnly`, IPS `-q`→`-i ens192`+큐 규칙 제거, FW 이전 ruleset).
- **단일 진실원(IPS-09):** 보호망/자산 정의를 `secstack/.env` 한 곳에서 FW 스코프·WAF BACKEND·Suricata HOME_NET이 함께 참조 → 세 계층이 어긋나지 않게.
- **상관 주의(IPS-02/13):** WAF↔Suricata 조인은 DNAT/masquerade 경계에서 5-튜플·community-id가 어긋나므로 **src_ip+시간+HTTP L7** 병행.

---

## 8. 부록 — 점검·검증 방법 & 무결성 고지

- **접속:** `팀접속안내.md`의 `ssh groot_a@grootlab.duckdns.org`(호스트키 `SHA256:nWtZ…sy24`). Windows에서 비대화형 실행을 위해 PuTTY `plink`를 세션 스크래치패드에 임시 사용. **비밀번호는 이 문서에 기록하지 않음.**
- **수행한 것(원 점검 + 2026-09-29 재검증, 전부 읽기 전용):** `docker inspect/exec`, `suricatasc -c dump-counters`, 룰 파일 통계(`wc/grep -P/awk`), `suricata.yaml`·`update.yaml` grep, 로그(`suricata.log/stats.log/fast.log/eve.json`) 파싱, `ip addr/route`, `ss`, `nft list ruleset`, `iptables -t nat -S`/`iptables -S`, WAF `env`, compose 파일 열람.
- **2026-09-29 점검 중 변경한 것:** **없음.** 위 항목은 당시 "식별·제안"이다. 10월 6일 후속 적용 상태는 문서 상단 주석을 참조한다.
- **검증 결과(2026-09-29):** 구조·설정·룰카운트·이웃계층 **전 항목 EXACT 일치**. 정정 2건(IPS-02 IP 오기·sqlmap 발화이력)은 본문에 ✏️로 반영. 러닝 카운터(총패킷 195k·TLS 2,651·ARP 31,528·unknown_ethertype 10,887)는 시점값으로 갱신. 상세는 `GROOT_A_IPS_검증리포트.md`.
- **분석 방식:** (원본) 8개 관점 병렬 리뷰 → 적대적 검증(36→20건). (검증판) groot_a 라이브 재접속해 20개 findings의 정량·설정 주장을 EXACT 대조, 정적 리뷰의 가설(IPS-11 16/10 혼선)까지 라이브로 반증/확증.
