# Suricata IPS 룰셋 (ET Open) — 반입 기록

> **현재 로딩 경로(2026-10-08 SSH·배포 기록):** A의 `/home/groot_a/capstone/suricata/ruleset/`을 컨테이너 `/rules`로 마운트하고, `suricata.rules`(ET)+`GROOT_A_local.rules`(로컬 SID 11개)를 합친 `all.rules`를 `-S /rules/all.rules`로 로드한다. 아래 스테이징·반입 절차는 9/26 기록이며 현재 로딩 경로와 다르다. ET 갱신 때에는 운영 합본 재작성·구문 검사·리로드까지 검증해야 한다. 배포된 승인형 `rule-a`는 로컬 룰 변경용이며 ET 자동 갱신 기능은 아니다. 실제 승인→적용 E2E는 미검증이다. [현재 운영 문서](README.md) · [승인형 변경 대상](../mcp/rule-change-deploy.md).

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
