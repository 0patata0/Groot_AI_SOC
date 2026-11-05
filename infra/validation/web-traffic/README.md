# HTTP 폭주 완화·Wazuh HTTP 호스트 분기

2026-11-05 19:45 운영 적용·19:48 확정. [현재 현황](../../../STATUS.md) · [검증 원장](validation-20261105.json).

| 설정 | 현재 동작 |
|---|---|
| IP별 웹 요청률 | 초당50·순간 초과100, nodelay |
| 서비스별 요청률 | 초당300·순간 초과600 |
| IP별 HTTP 처리 동시성 |50·초과429 |
| 임계값 초과 | 해당 요청429. 이 사실만으로 악성 판정/IP차단하지 않음 |
| Wazuh HTTP | wazuh.groot.lab / wazuh.grootlab.duckdns.org → 같은 호스트 HTTPS308·경로/쿼리 보존 |
| 기존 보안 | WAF On·실제 클라이언트 식별·MCP 증거 검증·관리자 ACL·기존 차단 TTL 유지 |

원인은 DNS 변경이 아니라 WAF80의 기본 서버가 Wazuh Host도 DVWA로 보내던 것이다. 실제 변경 전 `http://wazuh.grootlab.duckdns.org/`는302와DVWA로그인 경로를 반환했다. 변경 후 Kali232에서 두 관리 호스트의308을 확인했고 DVWA302·Log4Shell308을 유지했다. HTTPS Wazuh의 기존 관리자231/32 접근 제한은 유지한다. 이번에는 DNS 레코드·Docker 포트·NAT 정책을 추가 변경하지 않았다.

## 검증과 한계

| 범위 | 실제 결과 |
|---|---|
| 외부망 없는 격리 nginx | 정상8/8 HTTP200. 동시64요청은200×50/429×14. 순간240요청은200×106/429×134 |
| 격리 관리 호스트 | 요청 `/app/login?next=x`를 동일 호스트HTTPS로308·경로/쿼리 보존 |
| 운영 설정 | 기존 WAF 컨테이너 ID/PID/StartedAt 유지·nginx 검사/reload·엄격한 WAF 증거 구성 해시 재등록 성공 |
| 운영 소량 웹 | 정상 DVWA200·Log4HTTP308/HTTPS200·시험SQLi1건403. 이후 MCP가 새로운 WAF942100 근거를 검증하고 사유 카드를 게시 |
| 회귀 | 설치 렌더16·실제 프록시 경계2검사. 경계검사의 오래된3경로 기대치를 현재4경로에 맞춤 |

격리 시험은 운영 성능 한계 측정이나 대규모 DDoS 실전 검증이 아니다. 정상 서비스 전체/공유 NAT 사용자의 높은 부하와 임계값 튜닝은 미완료다. [NGINX 요청률 제한](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html)과 [동시성 제한](https://nginx.org/en/docs/http/ngx_http_limit_conn_module.html)을 사용한다. limit_conn은 헤더가 완성돼 처리 중인 요청을 세므로 SYN/미완성 헤더 폭주 전체를 보호한다고 주장하지 않는다. 회선 포화·다수 출발지 우회·상위망 트래픽 정화·종합DDoS E2E는 별도다. 새L3/L4 자동 IP차단 정책을 추가하지 않았다.

사용자가 공격 시험 중단을 지시했다. 별도 재지시 전 공격·부하·PCAP 재생은 진행하지 않는다. 기존 탐지·차단 정책은 유지한다.

## 적용·설치·복구

canonical은 [WAF 구성](../../groot-c/offline-labs/waf-log4shell-server.conf)이며 초기 설치의 기존 offline_security source 복사·nginx 검사 경로에서 사용한다. 운영 랩의 Wazuh 고정 별칭을 위한 분기이며 새 환경의 임의 관리 DNS 이름을 자동 발급하지 않는다. 신규3VM 전체 설치는 미시험이다.

기존 운영용 root 진입점은 `deploy.sh --web-traffic`→[web_traffic_guard.py](../../../deployment/web_traffic_guard.py)다. 정확한 기존 SHA·컨테이너·마운트·증거 정책을 대조하고 원본을 보존한 뒤 구성과 증거 정책을 함께 반영한다. 임의 경로를 받는 MCP나 LLM sudo 권한이 아니다. 원복은 A `/var/lib/capstone-web-traffic/run-1793875532443418329/recovery.py`와state.json에 보존했다.15분 독립 원복 타이머를 확인 후 중지했으며 root 수동 `rollback --directory ... --manual`은 후속 파일 변경/컨테이너 교체가 있으면 거절한다. 운영 수동 원복은 미시험이다. 새패키지/이미지/키 설치0·컨테이너 재생성0.
