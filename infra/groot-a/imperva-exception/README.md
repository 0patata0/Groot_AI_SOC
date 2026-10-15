# Imperva 점검 요청의 좁은 CRS 예외

> 04:48 WAF 단계 마감: 서버 증거 319파일/2660278B를 /var/backups/capstone-waf-recreation-validation-20261015에 보존·해시대조·fsync한 뒤 stage5를 제거했다. Mac 임시 363파일/2879578B도 제거·경로부재 확인했다. 패키지 설치0. 마지막 인증서 단계에 착수한다.

## WAF 재생성 검증 완료 (2026-10-15 04:45 KST)

새 WAF6c72d5a5…의 실제 Imperva 예외·producer·template 연결과 원본 인계를 확인했다. Vector2627991·Wazuh1909632·Suricata1990031은 정상이고 원본은 gen1/rev6·gen4/rev13 active다. 세 점검 timer를 5분 간격 안에서 0·1·3분으로 분산하여 실제 예약 실행 exit0를 모두 확인했다. 04:45 양 시작가드가 통과했다. 일시적인 Suricata CP offset/hash 불일치는 후속 저장에서 해소됐으나 정확 원인은 미확정이며 가드·CP는 변경하지 않았다. 증거 보존·임시 정리 후 인증서 관리로 이동한다. 실제 자연 스캔 효과·원격 경보 ACK·호스트 재부팅은 별도 관찰 항목이다. 아래는 이전 시점 기록이다.


## WAF 새 컨테이너 전환 완료·마감 확인 중 (2026-10-15 04:31 KST)

새 WAF6c72d5a5…가 healthy이며 Imperva 예외·로그 producer·시작 template을 실제 읽기 전용 bind로 유지한다. Vector2627991과 Wazuh1909632가 실행 중이고 원본 상태는 Suricata gen1/rev6·WAF gen4/rev13 active다. 무해 요청1건의 v2 감사·KST 정제1행 및 Wazuh 로컬 소비를 확인했다. 기존 WAF는 정지 보존, CP·원문 수동 재작성은 없다. 자동 timer3개와 구형 배포 보호도 반영했고 다음 예약 실행·영구 증거 보존·임시 정리를 마감 확인한다. 실제 Imperva 자연 스캔 효과와 원격 보안경보 ACK, 호스트 재부팅은 이번 확인과 구분한다. 아래는 이전 시점 기록이다.


## 2026-10-14 19:13 KST 자연 요청 후속 확인

고정 cutoff **19:13:21 KST**까지 보존된 A 원천을 읽기 전용으로 확인했다. 적용 완료 05:49:41 이후 `.9`의 최소 access·표준 access 요청은 모두 **0건**이고, 최근 5시간도 0건이다. 적용 직후 기록된 전체 요청 1건은 기존 05:50:14 서비스 확인 요청이며, 05:50:15 이후에는 두 access 원천 모두 새 요청이 없었다. 따라서 **자연 스캔에서의 예외 효과는 아직 미관찰**이며, 경보가 없다는 이유만으로 효과를 검증했다고 판단하지 않는다. [후속 메타데이터](followup-2026-10-14.json).

audit·최소 access·현재 Docker 로그 17파일, 입력 117,782bytes(압축 해제 223,561bytes), 358행을 제한된 범위로 전수 대조했다. 표준 access를 담은 Docker 로그의 명시 시각 범위는 10월 5일~10월 14일 05:50:14이고 원천 prefix는 읽기 전후 같았다. 과거 `.9` audit 56건은 HTTP/1.0 42건·HTTP/1.1 14건이며 각 기존 예외의 audit 필드 형태와 맞았지만, offset 없는 감사 시각과 `request.uri`만으로 KST 구간이나 `REQUEST_URI_RAW`까지 확정하지 않았다. 실제 자연 요청이 들어와야 정확한 전체 조건과 탐지 유지 상태를 다시 검증할 수 있다.

WAF healthy, 동일 컨테이너와 호스트/컨테이너 예외 SHA를 확인했다. `RelevantOnly`의 audit 생략, 기존 copytruncate와 보관 공백 가능성은 남는다. 원문 스냅샷과 실행한 일회성 분석 소스는 A의 작업 증거에만 보관했으며 원문 반출·운영 변경·생성 요청·채팅 발송은 모두 없었다.

## 기존 적용 기록

**2026-10-14 05:49:41 KST 적용 완료.** 고정 운영자 Ansible이 early 예외 파일의 ModSecurity ID `10020`/`10021`을 설치하고 기존 WAF master를 graceful reload했다. 결과는 `ok=59, changed=9, failed=0, rescued=0`이며 백업은 `/var/backups/capstone-imperva-20261014-dxvcvejn`이다. 컨테이너 삭제·재생성·재시작과 엔진 모드 변경은 하지 않았다.

05:50:14 KST 배포 후 메타데이터에서 WAF healthy, 기존 container ID/StartedAt 유지, `nginx -t` 종료0과 **loaded 862**를 확인했다. 예외 원본은 root 소유·0444이고 SHA-256은 `d95e75f39d082053543b04de10d538154da4ce8b25e9333014b3b2d858b65f8d`다. 정상 loopback `HEAD /`, Host `groot-web`은302였으며 Vector·Wazuh agent·보관 timer·승인 worker timer도 active였다. `.9`는 `agent_block`에 없었다. 이 HEAD는 서비스 상태 확인이며 Imperva 점검 재현이나 공격 시험이 아니다. **적용 후 다음 자연 발생 Imperva 스캔은 아직 관측하지 않았다.**

현재 컨테이너에는 writable layer 파일을 설치했다. 실제 A의 `/home/groot_a/capstone/secstack/docker-compose.yml`에는 아래 **파일 하나의 read-only bind만 영구 반영**했고, 검증된 compose SHA는 `5f41d56c42f00d625b2ec3bec3f355f9599e8a38fa824f9baa193bcce2dd5d60`다. 새 bind는 다음 통제된 재생성에서 생긴다. 이번에 기존 컨테이너 mount가 바뀐 것은 아니다. 저장소의 [초기 compose 템플릿](../docker-compose.yml)은 현재 운영 구성을 모두 담고 있지 않으므로 그대로 재적용하지 않는다.

적용 전 [분리 native 결과](validation.json)는 **21개 전후 비교 시나리오·42요청 통과**다. 정상2종에서 원인이 된920280 또는920350 경보가 사라졌다. no-Host 점수가 사라지면서 그 사례의949110도 발생하지 않았지만, 949110 규칙 자체를 제외한 것은 아니다. 17개 조건 이탈 사례의 전체 탐지 ID 집합은 동일했다. 두 XSS 대조군은 선택한 프로토콜 ID만 빠지고 `10300`, CRS XSS와 `949110`이 남았다. 같은 기존 엔진을 loopback 전용 익명 netns에서 사용했으며 운영 WAF·외부망에 시험 요청을 보내지 않았다. 정적 테스트 응답200을 운영 upstream302 검증으로 해석하지 않는다. 시험 전후 hash 보존 목록은 base/setup/override/nginx/unicode **5파일**이며 CRS symlink 내부 전체 파일의 hash 검증은 아니다. 정상 완료 후 private tmp0·시험 namespace 잔여 프로세스0을 확인했다.

[시험 드라이버](test-native.py)는 이후 종료된 PGID 재사용을 피하도록 cleanup을 보강했다. 실제 실행 SHA와 보강 후 SHA, **보강 후 native 미재실행**을 결과 JSON에 구분했다. 강제 timeout에서 inner finally 실행을 보장하는 시험은 하지 않았다. 아래는 적용 설계와 정확한 범위이며, 예외 범위를 넓히거나 재생성 성공을 증명한 기록은 아니다.

## 근거와 선택

부모가 라이브에서 확인한 최근5시간4건은 `211.170.162.9 → 172.18.0.2:8080`, `GET /`, 요청 body0, 응답302다. HTTP/1.0·Host 없음3건에는920280/949110, HTTP/1.1·Host192.168.16.230 1건에는920350이 있었다. 네 건 모두 Content-Length와 Transfer-Encoding이 없었다. 이 표본은 해당 요청 형태의 점검 트래픽 근거이며 `.9`의 모든 트래픽이 안전하다는 근거가 아니다.

현재 GROOT 사용자 파일은 REQUEST948에 포함된다. 920280과920350이 phase1에서 먼저 실행되므로 거기에 넣은 런타임 제외는 늦다. 별도 early900 파일에서 해당 transaction에만 개별 ID를 제외하는 것이 맞다. CRS 공식도 조건부 runtime 예외를 본 규칙보다 먼저 포함하도록 안내한다. [CRS 제외 위치와 조건식](https://coreruleset.org/docs/2-how-crs-works/2-3-false-positives-and-tuning/)

| 방법 | 효과 | 한계·판단 |
|---|---|---|
| early CRS의 두 개 runtime 예외 | 알려진 점검 형태에서920280 또는920350만 발화하지 않게 함 | audit/Wazuh 잡음 원인에 직접 대응. phase1 시점 조건만 사용해야 함. 현재 최소 권장안 |
| Wazuh의 좁은 사후 분류 | WAF 원본 탐지는 그대로 두고 해당 사건의 경보 등급만 낮춤 | body/status까지 검사할 수 있으나 message 안에 다른 공격 규칙이 섞이지 않았는지 전부 검증해야 함. `.9+GET /+302`만으로 낮추면 공격을 숨길 수 있음. 현재 원본 ID 배열/문자열의 정확한 디코딩 계약과 native 회귀가 필요 |

Wazuh 분류만으로 WAF 원본 이벤트 생성이나 원본 수집량이 줄지는 않는다. 원문을 단순 regex로 검사해 허용 ID 중 하나가 들어 있다는 이유만으로 이벤트 전체를 예외 처리하지 않는다. 허용 집합 밖 SQLi/XSS 등 ruleId가 하나라도 있으면 일반 공격 경보를 유지해야 한다.

## 적용된 예외의 정확한 범위

`REQUEST-900-CAPSTONE-SCANNER.conf`의10020/10021 두 ID는 실제 포함 규칙과 충돌 검사를 거쳐 적용했다. 공통 조건은 실제 REMOTE_ADDR `.9`, SERVER_ADDR `172.18.0.2`, SERVER_PORT8080, GET, 변환하지 않은 REQUEST_URI_RAW 정확히 `/`, Content-Length 없음, Transfer-Encoding 없음이다. X-Forwarded-For나 Host를 출발지 신뢰 근거로 사용하지 않는다.

- HTTP/1.0이고 Host가 없을 때920280만 transaction에서 제외한다.
- HTTP/1.1이고 Host가 정확히 하나이며 값이192.168.16.230일 때920350만 제외한다.
- CL0도 현재 예외 대상이 아니다. 실제 점검 요청에 나타나면 별도 재검토한다.
- 949110 점수 판정·SQLi/XSS·일반 커스텀룰·감사 기능·DetectionOnly 설정은 바꾸지 않는다.

phase1은 요청 body를 읽기 전이며 응답302도 아직 알 수 없다. 따라서 실제 body0/302를 예외 조건으로 검사했다고 주장하지 않는다. 요청 framing header가 없는 형태에만 한정한다. 다른 악성 header·cookie 등이 있더라도 그 검사는 남아 있고, 다른 규칙의 점수가 임계치를 넘으면949110도 남는다. [ModSecurity 변수·단계 참조](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-(v3.x))

SERVER_ADDR `.2`를 고정한 것은 의도적이다. 재생성 때 컨테이너 IP가 바뀌면 예외가 적용되지 않아 기존 탐지로 돌아간다. 범위를 Docker subnet 전체로 넓히지 않는다. `.9`가 프록시를 겸할 가능성이 있어도 두 형식 이외 트래픽은 이번 예외에 들어가지 않는다.

## 현재 컨테이너 적용과 재생성 지속성

최소 지속성 원본은 저장소 파일과 A root 소유의 고정 호스트 파일이다. 실제 compose에는 그 파일 하나를 아래 목적지로 read-only bind하는 항목을 추가했다. 기존 GROOT948·auditdir 마운트를 유지하고 디렉터리 전체를 덮어쓰지 않는다. Docker CRS 공식도 tuning 파일의 bind 또는 컨테이너 복사를 안내한다. [공식 Docker CRS tuning](https://github.com/coreruleset/modsecurity-crs-docker/blob/main/README.md#modsecurity-crs-tuning)

```text
host: /etc/capstone-waf/REQUEST-900-CAPSTONE-SCANNER.conf
container: /etc/modsecurity.d/owasp-crs/rules/REQUEST-900-CAPSTONE-SCANNER.conf
mode: read-only bind for the next controlled recreation
```

현재 컨테이너에는 파일을 설치하고 검증된 graceful reload를 수행했다. `apply-a.yml`은 모든 성공 apply에서 같은 master를 reload한다. 파일/compose가 변경 없는 재적용이어도 reload는 수행하며, 이전 cp 후 reload 전 중단 상태를 별도 영속 marker 없이 복구한다. 파일 멱등성과 reload 유무를 구분해 보고한다. 이 작업은 기존 mount 목록에 새 mount를 추가하지 않는다. writable layer의 파일은 컨테이너 삭제·재생성 시 사라지므로 현재 파일 복사만으로 재생성 지속성이 완성됐다고 기록하면 안 된다. compose를 수정해도 재생성 전까지 실제 mount가 생기지는 않는다. 현재 오프라인 이미지·container identity와 기존 SHA를 고정하고, 향후 재생성 전에 `.2` 주소와 GROOT/정제 producer·transaction binding까지 함께 재검증한다.

영구 host 파일과 현재 컨테이너 파일은 root:root0444이며 호스트 `/etc/capstone-waf`는 root:root0755다. UID101 nginx가 읽을 수 있고 후보·백업·검증 임시 경로는 root가 관리한다. 적용 전 실제 포함 순서와10020/10021 충돌 확인, native nginx 검증 및 분리 네트워크 시험을 마쳤다. 실패하면 설치 전 파일 유무/SHA에 맞춰 이번 파일만 복구하고 native 검증·같은 master의 reload/새 worker 확인을 마친다. 그 사이 다른 운영자가 바꾼 파일은 CAS 불일치 시 덮어쓰지 않는다.

## 후속 회귀 범위와 배포 경계

이번에 실제 컨테이너 파일시스템과 별도 네트워크의 nginx로 위21개 시나리오를 검증했다. 다음 문장은 추가 회귀를 포함한 목표이며 모두 수행했다는 뜻은 아니다. 양성2종은 예외 전 원래 CRS ID가 발화하고 예외 후 해당 검사가 제외돼야 한다. 그 점수 감소로949110 경보가 사라지는 것과949110 규칙을 제외하는 것은 구별한다. 다른 source/destination/port, GET 이외, 다른 URI/query/absolute URI, protocol 변화, 다른 Host/중복 Host, CL0/양수·TE 조건은 예외가 적용되지 않아야 한다. 같은 `.9 GET /`에 독립 공격 header/cookie가 있으면 해당 공격 ID와 필요한949110을 보존하는지 검증한다. 공격성 시험을 운영 WAF 또는 상위 학과망으로 보내지 않는다.

배포 후보는 최초 이름 조회 뒤 실제 작업 전체를 고정64자리 container ID에 결속한다. compose는 root 전용 백업에서 후보를 만들고 실제 상대 경로 기준으로 `docker compose config --quiet`를 통과시킨 뒤, 현재 SHA·소유/권한을 다시 대조하여 원자 교체한다. 컨테이너에는 root 전용 임시 파일에 복사·SHA 확인 후 hardlink의 no-overwrite 성질로 새 경로를 설치하고 원래 임시 link를 즉시 제거한다. 복구 전에도 compose·host source·container rule의 SHA/메타데이터를 함께 확인하며 다른 변경이면 복구를 중단한다. 공유 flock에 참여하지 않는 동시 root 수동 변경 전체를 원자적으로 배제하는 일반 트랜잭션은 아니므로 해당 좁은 유지보수 시간 동안 수동 변경을 겹치지 않게 한다.

## 적용 후 읽기 재확인

2026-10-14 06:22:57~59 KST에 A/B 서비스와 기존 컨테이너 ID를 다시 대조했다. WAF healthy·호스트/컨테이너의 예외 파일 SHA 일치, 적용 시각 이후 `.9`의 새 WAF 색인 경보0건(54/54 shard 성공)을 확인했다. 다음 실제 Imperva 점검의 실행 자체는 확인하지 못했으므로 이를 자연 스캔 성공 검증으로 부르지 않는다. 과거 경보는 보존한다. [메타데이터](../../normalization/indexer-final-live-2026-10-14.json).
