# Suricata IPS 룰셋 (ET Open) — 반입 기록

> **2026-10-24 직접 재확인:** Suricata는 `-S /rules/all.rules`로 ET+로컬 합본을 읽고 있다. 호스트 합본=ET+로컬 바이트·컨테이너 해시 일치, socket 통계52,497 loaded/failed0/skipped0을 확인했다. 로컬 파일 정의14개(자체12+ET override2)와 엔진 전체 카운터는 범위가 다르며 개별 룰 발화 E2E를 의미하지 않는다. `-S` 자체가 커스텀 비활성이라는 채팅 답변은 잘못됐다. 새 설치기도 같은 all.rules 경로이며 아래9/26 초기 템플릿을 운영에 재적용하지 않는다. [현재 상태](../../STATUS.md) · [공식 -S 의미](https://docs.suricata.io/en/suricata-8.0.2/command-line-options.html).

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../STATUS.md) · [실행 계획](../../PLAN.md).
> A는 외부/내부 관문이며 Suricata는 passive IDS다. DVWA의 DetectionOnly와 실습 HTTP 경로의 WAF 차단/요청별 예외를 구분한다. 이번 TLS 조회의 세 HTTPS 이름 만료는2027-01-13 13:25:12 KST이며 과거 인증서 값은 이력이다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

> **2026-10-13 19:54 최신 확인:** SID 1000000의 고정 Ollama 흐름 목적지를 `[211.170.162.110,211.170.162.111]:11434/TCP`·rev 2로 갱신해 기존 선택 6종 예외를 `.111`에도 적용했다. 원본 출발지 `192.168.16.230`·기존 guard·ET 원본을 유지했고 전체 검사와 기존/후보 각각 27개 PCAP 사례를 통과했다. 부분 편집의 실제 카드 승인 후 같은 컨테이너가 재시작했고 19:50:41 실제 로드 52,497·실패/skip 0, local SHA `82f41d65…`·all `8669bab4…`를 확인했다. 아래 `.110` 단독·이전 해시 설명은 당시 기록이다. [현재 룰](../../new_rule/GROOT_A_local.rules) · [회귀 검사 생성기](../mcp/validate_dgx_endpoint_transition.py).

> **현재 로딩 경로(2026-10-08 SSH·배포 기록):** A의 `/home/groot_a/capstone/suricata/ruleset/`을 컨테이너 `/rules`로 마운트하고, `suricata.rules`(ET)+`GROOT_A_local.rules`(로컬 SID 11개)를 합친 `all.rules`를 `-S /rules/all.rules`로 로드한다. 아래 스테이징·반입 절차는 9/26 기록이며 현재 로딩 경로와 다르다. ET 갱신 때에는 운영 합본 재작성·구문 검사·리로드까지 검증해야 한다. 배포된 승인형 `rule-a`는 로컬 룰 변경용이며 ET 자동 갱신 기능은 아니다. 실제 승인→적용 E2E는 미검증이다. [현재 운영 문서](README.md) · [승인형 변경 대상](../mcp/rule-change-deploy.md).

> **2026-10-13 13:18 후속:** 자체 로컬 SID 12개와 ET `2034806/2034802`의 정확한 local override(rev 3)를 운영 합본에 반영했다. ET 원본은 불변이고 로드 카운터 52,497·실패/skip 0이다. 카운터에는 같은 SID의 높은 rev로 대체된 두 정의도 포함된다. 현재 `-S` 실행에서는 hot reload가 거부돼 승인형 worker가 기존 컨테이너를 재시작하고 실제 로드 시각·룰 통계를 검증한다. 이번 지정 승인→자동 적용 E2E는 확인했고 실제 실패 복구는 미검증이다. **ET를 갱신할 때는 두 override를 새 원본과 대조해 guard 추가·rev+1만 한 파생본으로 재생성하고, 합본/회귀 검사와 승인 후 재시작까지 검증해야 한다.** ET 원본만 교체하거나 기존 override를 그대로 재사용하지 않는다. 최신 local SHA `cabbac45…`, all `ea160e90…`; [검증·복구 기록](../../대화기록/2026-10-13.md).

Suricata 8.0.6(jasonish/suricata:latest)용 **ET Open** 룰셋. 이 망은 outbound 웹 차단이라 `suricata-update` 온라인 갱신 불가 → **오프라인 반입**.

## 출처 / 버전 / 무결성
- 소스: `https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz` (+ `.md5`)
- 제공: Proofpoint / Emerging Threats
- 라이선스: **혼합** — sid 1–3464 및 1억번대 GPLv2, 그 외 BSD (`rules/BSD-License.txt`). 연구/캡스톤 사용 OK, 재배포만 주의.
- 무결성: `md5 = 351ba8767d2f85f300189a3151e3a354` (공개 .md5와 일치 확인)
- 반입일: 2026-09-26

## 리뷰 결과 (반입 전, 필수)
- 룰 54개 파일 / **52,483 룰**(alert/drop)
- ⚠️ **lua/luajit 코드실행 룰 0개**, `.lua` 스크립트 없음 → 실행 위험 없음 (LOW RISK)
- 부가: `compromised-ips.txt`, `dshield.rules`, `botcc.rules`, `drop.rules` = IP 평판/차단 콘텐츠 포함

## 스테이징 위치 (Groot_A)
- `~/capstone/suricata/emerging.rules.tar.gz` (원본), `~/capstone/suricata/rules/` (전개)
- Suricata 컨테이너 배치 시 이 `rules/`를 `/var/lib/suricata/rules`(또는 `/etc/suricata/rules`)로 read-only 마운트.

## 갱신
- ET는 평일 1회 갱신. 필요 시 인터넷 되는 곳에서 위 URL 재다운로드 → md5 검증 → scp `-O` 반입(홈디렉토리 교체). VM에서 직접 `suricata-update`는 egress 차단으로 불가.
