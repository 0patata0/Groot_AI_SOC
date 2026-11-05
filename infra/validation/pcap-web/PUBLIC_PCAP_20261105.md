# 추가 PCAP 반입·232 시험 — 2026-11-05 KST

사용자의 네 사이트에서 [이전11개](PUBLIC_PCAP.md)와 다른 자료7개를 선정해 두 Kali에 반입했다. 실제 시험은232에서만 했다. [출처/이용 조건](public-catalog-20261105.json) · [파일별 SHA·실측·한계](public-validation-20261105.json) · [전체 현황](../../../STATUS.md).

## 보관·설명

| 위치 | 내용 |
|---|---|
|232 `/home/att/Desktop/PCAP/public-20261105/` | imported/에7PCAP·정답PDF2개·출처, `PCAP_설명.txt`에 자료별 설명/해시/시험 결과·한계 |
|233 `/home/attack/Desktop/PCAP/public-20261105/` | 같은 원본·해제 파일·설명. 반입/무결성 확인만, 새 시험 송신0 |

PCAP 합계76,707,724B·100,006패킷이다. 양쪽 전 파일 크기/SHA와 설명문 SHA `206460251a706c821c433cf54e2e5522121731bb4ef5ccf4e277b7640a612587`를 대조했다. 기존 PCAP 폴더의 일반 파일205개를 확장자 없는 날짜별 snort.log까지 크기로 먼저 비교했고 동일 크기 후보0이었다. 기존 자료를 삭제하거나 출처 미확인을 임의로 보완하지 않았다.

| 추가 자료 | 출처·의미 | 패킷 | 오프라인 관측 |
|---|---|---:|---|
| Kongtuke 2026-09-11 | [MTA 감염 조사 연습](https://www.malware-traffic-analysis.net/2026/09/11/index.html) |73,779| LandUpdate808 도메인2·.cfd 정보2. 감염 전 과정/모든 C2 검증 아님 |
| FormBook 2026-08-09 | [MTA CnC 조사 연습](https://www.malware-traffic-analysis.net/2026/08/09/index.html) |22,473| SID2050745 CnC18·정보/추적4 |
| CTU Normal6 DNS | [정상 대학 노트북·DNS만 보존](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Normal-6-filtered/README.md) |1,720| .tk2/.biz1의 TLD 경보. 제공자 정상 표지와 개별 흐름 판단을 구분 |
| CTU Malware282-1 | [잠정 Strictor·프록시 없는 비교 캡처](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-282-1/README.md) |1,064| DNS/HTTP/TLS 관측·경보0. 전용 악성 흐름 정답 대조 미완료 |
| 큰 HTTP POST | [Netresec 목록](https://www.netresec.com/?page=PcapFiles)→[Wireshark HTTP 예제](https://wiki.wireshark.org/SampleCaptures#hypertext-transport-protocol-http) |220| 재조립 HTTP1·경보0. POST 본문 실웹 전송0 |
| TCP ECN HTTP | 같은 Wireshark 원제공처 |479| HTTP1·경보0 |
| HTTP302 redirect | 같은 Wireshark 원제공처 |271| 최초 HTTP0, 중간 세션용 별도 프로필에서 HTTP48·경보0 |

[CAIDA의 선정 대상 passive trace](https://www.caida.org/catalog/datasets/passive_dataset/)는 이용 조건/신청 대상이며 L4 이후 payload가 제거되어 HTTP 요청 시험에서 제외했다. 접근 제한을 우회하거나 신청·개인정보를 제출하지 않았다. MTA의 별도 malware/forensic 바이너리는 받지 않았다. CTU 인용 조건/README·MTA 설명/정답·Wireshark 출처를 보존하며 연구용 공개라는 이유로 포괄 재배포 허가나 모든 패킷의 정답을 가정하지 않는다. 학습자료 편입0이다.

## 오프라인 처리

Suricata8.0.6·현재 A CLI의 `-S /rules/all.rules`와 같은 룰 SHA `b808ceba89dead5d1de8bd4f17cd4370e2f0d565424d979672e25426a60f7f4b`를 기존232 사용자 도구로 처리했다. 실제 선택 파일이 아닌 `/rules/suricata.rules`와 구분했다. 각 PCAP마다 별도 프로세스·7/7 engine/tshark 성공,252.656초·경보29개다. 경보 수는 정탐 수/탐지율이 아니다.

캡처용 HOME_NET은 사설망과 CTU 정상 client147.32.83.53/32, 체크섬 검증은 offload 대응으로 껐다. 생산 환경과 같다고 표시하지 않는다. redirect 캡처는 frame1부터 HTTP여서 기본 프로필의 HTTP0을 정상 통과로 세지 않았다. 같은271패킷에 `stream.midstream:true`만 추가한 독립 출력 폴더에서48HTTP를 복원했다. 새 표본으로 중복 합산하지 않았으며 운영 IDS 설정은 변경하지 않았다. [실행기](public_offline.py) · [최초 프로필](public-offline-20261105.yaml). 원본은 두 VM에 그대로 보존한다.

## 실제 HTTP97:3·차단·복구

새 ECN/redirect의 GET·User-Agent를 랩 mount/Host로 바꿔 정상97건을 보냈고, 기존 사용자 반입2015PCAP의 다른 read-only SQLi-2/경로탐색-2/XSS-2를 마지막3건으로 보냈다. 이2015PCAP의 원 외부 제공처는 미확인이다. 새 악성 C2 캡처를 웹 공격으로 바꿔 탐지했다고 표시하지 않는다. [동일 실행기/날짜 선택](public_web_mixed.py).

| 구간 | 실제 확인·범위 |
|---|---|
| 정상97 | DVWA302 49·Log4Shell HTTP308 48, 연결 실패0. 최종 로그인/앱 건강·리다이렉트 후 동작은 별도 |
| 공격3 | 모두403·WAF Enabled. SQLi942160/10200, 경로탐색930100/930110/10500, XSS941100/941110/941160/941390/10300 및949110 |
| IDS/관제 |2009714 XSS·2011142 PHP 정보 신호, Wazuh100102/100110/100111/100121. 정보성 메타데이터를 추가 공격 확정으로 세지 않음 |
| IP 차단 | 기존 지정 IDS Native 예외로232 최초600초. 최초 kernel 소유 확인12:25:47 KST, 최초 패킷 DROP 시각 아님. LLM은6MCP로 기존 차단을 확인/재사용 |
| 강제성 |232 TCP 연결 timeout, 같은 agent_block DROP counter937→940/180B 증가. 집합에는232만 있었음 |
| 만료/복구 | 원기한12:35:46·실제closed12:35:47 KST·expired/커널부재.232 DVWA302 복구 확인. 수동 KEEP/RELEASE 승인0·예외 추가/강제 해제0 |

[실제 임시 차단 카드](https://chat.grootlab.duckdns.org/soc/pl/tkwfwj4qk3y3ty3ni7g5bjoddy) · [만료 결과 카드](https://chat.grootlab.duckdns.org/soc/pl/ymsyroxphbgozbp9e16w5fi8ro). 카드 존재/정책 만료 확인과 버튼 승인 실행 시험을 구분한다. 원래 외부 C2 목적지로 송신하거나 객체를 추출·실행하지 않았다. 공격을 마지막에 둔 제한된 순서로, 무작위 혼합의 정확성/성능 평가가 아니다.

## 남은 LLM·계측 문제

| 실제 사건 처리 | 관측 |
|---|---|
| 최초 IDS 조사 |143.306초·6MCP/오류0·승인 대기 보고 |
| 같은 IDS 후속 |83.538초·MCP0, shared_containment_verification_missing/needs_review. 과거 읽기를 현재 확인으로 재사용하지 않도록 거절됐지만 새 조회는 미완료 |
| WAF 조사 |214.234초·6MCP/오류0 뒤 시간초과·outcome_unknown |
| 연결 operation 조사 |178.785초·7MCP/오류4, model_tool_failure_requires_review |
| 추가 상관 사건 |214.328초·10MCP/오류2·시간초과.13:39 동일 원문ID/사건DB 재대조에서 출발지230 일치 확인. 기존230/232 불일치 기록은 오독으로 정정 |

따라서 WAF/IDS·차단·만료 성공을 LLM 사건 종결 성공으로 합산하지 않는다. 실제 실패 보고5개는 API 본문에 표6줄이 있으며 새 브라우저 UI 전수 확인은 하지 않았다. 원문 trace·실패/검사 거절은 로컬과 운영 DB에 보존했다. 같은 사건 순차 후속을 독립 평가로 세지 않는다.

12:37의 읽기 전용 계측에서 Mac 대비232 offset은 약−14.8초,233 약−22.4초였다. 이는 NTP 정확성 인증이 아니고 시계 변경은 하지 않았다. 클라이언트·센서·수집/색인 시각을 바로 빼서 지연으로 사용하지 않는다. WAF 표본12:27:06과 IDS12:25:46의 차이도 원천 사건 시각·수집 시각을 나누어 추가 확인한다. 정답PDF 전문/전 흐름 정답 대조·실제 Log4 앱·다른 공격/승인 실행·재차단/장기 무누락은 미완료다.

## 정리·소스 반영

양쪽 전송용 압축68,731,011B씩은 최종7PCAP/정답2/설명SHA를 다시 확인한 뒤 삭제했다. 원본 PCAP·설명/출처/정답·분석 결과·재현 소스는 보존한다. Mac 자체69파일/138,931,517B와 임시 경로·SSH소켓을 제거하고 해당 경로 프로세스0을 확인했다. 기존 사용자 도구·데이터 압축본·publisher·운영 DB/로그/채팅/승인·모델/가중치와 B/C복구본은 보존했다. Mac/Kali 신규 패키지 설치0이다.

현재 Git의 웹 실행기는 실제 실행본과 모듈 설명/미사용 ROOT 상수만 다르며 그 외 실행 AST 일치를 확인했다. 실제 실행본 SHA/원문은 Kali와 로컬 감사에 보존하고 현재 함수/CLI 동작을 바꿔 성공으로 표시하지 않았다. 관련 소스·설정·작은 원장/출처와 현황만 커밋하며 패킷/정답·원문 trace·논문/대화는 Git 제외다. 게시/원격 일치 영수증은 STATUS와 검증 원장에 별도 기록한다.

13:41 후속 정정·재검토: [자동 상태/실행 인자 검증](../../hermes/shared-status-verification.md)에서 operation2읽기/오류0·73.448초(보고 목록형), IDS상태1/센서3·오류0·190.519초(영향 미조회로 종결 거절)를 확인했다. 같은 사건의 개발 재검토이며 위 최초 시험/독립 평가와 합산하지 않는다. WAF 원문 time_stamp에는 시간대가 없으므로 outer Wazuh 시각과 의미를 나누어 추가 조사한다.
