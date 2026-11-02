# WAF 원본으로 기존 FW 임시차단 사용

`temporarily_contain_ip(ip, reason)` 한 도구가 Suricata 공격 흐름 또는 WAF 공격 거부를 검증한다. 새 MCP·API·데몬·일반 sudo 권한은 추가하지 않는다. WAF On은 HTTP 요청을 즉시 거부하고, LLM은 원본 경보를 판단해 기존 MCP로 FW IP 임시차단을 요청한다. 지정 Native IDS 예외와 WAF 경로는 구분한다.

| 검증 | 적용 조건 |
|---|---|
| WAF 공격 | 최근5분, `Enabled`, `is_interrupted=true`, HTTP403, 구체적인 공격 태그를 가진 룰. 단순403·anomaly 합계·스캐너/프로토콜 경보만으로는 불가 |
| 출처 | root 관리 active 현재 세대·정확한2 hardlink·장치/inode·구성 SHA·고정 CID·살아 있는 nginx writer/FD를 읽기 전후 확인. 회전·불일치·잘린 줄·모호한 거래는 거부 |
| 시각 | producer v2 바인딩과 명시적 offset/msec/audit 시각 일치. 결과는 KST, 원문은 변경하지 않음 |
| 주소 | audit의 실제 client IP와 고정 WAF 목적지·8080/8443. 요청 헤더를 별도 신원 근거로 사용하지 않음 |
| 집계 | WAF는 `http_transactions`, `independent_flows=0`. 거래 수를 TCP 흐름으로 부풀리지 않음 |
| 공통 보호 | live never_block·관리/인프라·gateway/DNS·현재 SSH 등 기존 보호·소유권 검증 그대로 |
| 임시/승인 | 최초600초. 기존 정확 후보 카드의 유지 승인 시 결정부터3600초, 해제 승인 또는 만료. 원래 기한 뒤 재차단 대기60초, 중복 무연장 |

## HTTPS 프록시 경계

기존 A:80 hairpin의 Docker gateway `172.18.0.1`을 신뢰하던 경로를 교체한다. `chatproxy`는 기존 WAF bridge에 고정 `172.18.0.3`으로 연결하고 WAF `172.18.0.2:8080`으로 직접 보낸다. 기존 chat-net 기본 경로는 `gw_priority: -1`로 보존한다. WAF는 server의 post-read 단계에서 주소를 복원해 ModSecurity phase1 거부보다 앞서 적용한다. location에만 두면 조기 차단 경보가 프록시 주소로 남는다. WAF 실습 경로는 이 프록시만 신뢰하며 gateway·직접 접속자가 보낸 신원 헤더는 신뢰하지 않는다.

`CAPSTONE-FWD`는 같은 검증 bridge의 `.3 → .2 TCP8080` NEW/ORIGINAL 한 경로만 허용한다. 기존 established 회신 허용을 사용한다. bridge 전체 허용이나 방화벽 전체 재적용은 필요 없다. 재부팅 적용 소스는 `infra/groot-a/fw-v2/capstone-nat.sh`, 프록시 영속 구성은 `chatproxy-compose.yml` 및 두 실습 nginx 설정이다.

운영자 전용 `configure_waf_evidence.py`는 검토·syntax/reload를 마친 두 컨테이너와 정확한 경로를 확인한 후 `/etc/rule-change/waf-evidence.json`에 작은 SHA manifest를 원자 저장한다. 기존 관리 권한으로만 실행하며 MCP·LLM sudo에 등록하지 않는다. reader는 프록시 CID·설정 SHA·현재 namespace의 고정 주소까지 재확인한다. 컨테이너 재생성·설정 변경으로 pin이 어긋나면 승인된 재검토·등록 전까지 WAF 증거를 거부한다.

## 설치·복구와 한계

루트 `deploy.sh`의 기존 SOC source bundle/renderer에 공통 reader·WAF reader·운영자 등록기를 포함했다. 추가 deb/wheel/image/키/공개 포트는 없다. 별도 사용자 설치 진입점은 만들지 않는다. 기존 A 반영은 원본 CID·bind inode·raw 세대·수집 cursor를 보존하는 증분 작업이다. **새 서버에서 managed 원본·producer v2·검증된 프록시를 처음부터 구성하고 전체 설치하는 시험은 미실행**이다. 코드 반입만으로 WAF 원본 검증이 준비됐다고 표시하지 않는다.

최근 현재 세대 최대16MiB·완결 줄만 읽는다. 이전 세대까지 전역 검색하거나 수집 ACK·전체 공격 탐지율을 보장하지 않는다. Suricata 오류 시 같은 로그의 불검증 legacy 복사본으로 우회하지 않으며, 독립적으로 검증된 WAF 증거만 사용할 수 있다. Native IDS 호출은 전용 `read_suricata_evidence`로 고정해 WAF 거래가 SID/flow 검증에 섞이지 않는다.

운영 복구본은 A `/var/backups/capstone-waf-containment-20261102-1830`, B `/var/backups/capstone-waf-policy-20261102-1833`에 보존한다. 최초 rollback은 원래 source/프록시/네트워크, 추가 forward rollback은 정확한 한 ACL을 복구한다. 현재 상태를 먼저 대조하고 운영자 복구로 실행한다. 진행 학습·수동 차단·다른 소유자의 기록을 삭제하지 않는다.

검사·실제 공격·LLM/MCP 호출·FW 차단·카드·만료는 각각 [현재 상태](../../STATUS.md)와 [작은 실행 원장](waf-containment-20261102.json)에서 구분한다. 원본 요청/쿠키/본문·개인 대화·전체 trace는 Git에 올리지 않는다.

공식 근거: [Nginx real IP 신뢰 주소와 원래 peer](https://nginx.org/en/docs/http/ngx_http_realip_module.html), [Docker 실행 중 network 연결·고정 IP·gateway 우선순위](https://docs.docker.com/reference/cli/docker/network/connect/).
