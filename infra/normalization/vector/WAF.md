# WAF 패키지 정제와 시간 근거

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../STATUS.md) · [실행 계획](../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

**2026-10-14 20:44 KST 추가 검증 — writer 회전과 보관본 결합을 분리해 통과했다.** 운영 설정을 바꾸지 않은 별도 nginx/ModSecurity writer에서 4세대·6요청(2/1/1/2)을 생성했다. 이전 worker의 늦은 완료, reader 정지 중 연속 두 회전, 세 번의 인접 세대 공개, 동일 checkpoint 정상 재시작 후 요청까지 Vector audit/access 각각 6건·Wazuh audit 6건을 확인했고 중복은 0건이었다. Vector는 원문 행 SHA(줄바꿈 제외), Wazuh는 설치된 cJSON 재직렬화 SHA를 사용했다. Wazuh SIGTERM 종료 코드 1·최종 offset/SHA 저장과 Vector 종료 코드 0을 확인했으며 강제 종료를 정상 재시작으로 인정하지 않았다. [시험 상세](waf-rotation/README.md), [검증 JSON](waf-rotation/validation-2026-10-14.json).

원문 수집 뒤 별도 native Vector 시험으로 각 세대의 보관본 6쌍을 결합해 ID·KST 시각·SHA 일치를 확인했다. 다른 배포 ID를 준 4건은 격리했고, audit 격리를 관측한 뒤 실행 시작 기준 약2.51초에 access를 추가한 시험은 ready 0·quarantine 1·access 단독 제외 1이었다. 이 결합 시험은 root가 검증한 manifest에 따라 보관 파일의 source 경로 메타데이터를 원래 값으로 복원한 **오프라인 검증**이다. 새 운영 배포 ID 발행이나 회전 중 실시간 join 성공으로 해석하지 않는다.

현재 운영 copytruncate는 그대로다. 시험 writer UID 0과 운영 UID 101의 차이, 두 파일 공개 시점과 2초 TTL의 실시간 결합, 원격 수신 ACK, crash·재부팅 복구는 남은 범위다. 20:44:38 운영 보호59파일·서비스·PID/CID 불변을 확인했고 20:45:57 원본205파일을 A 영구 경로에 SHA 대조 보관했다. 소스 보관/작업경로 정리는 후속 마감으로 기록하며 아래 기존 운영 배포 이력과 구분한다.

2026-10-14 KST에 최소 nginx producer와 Vector의 WAF 정제 경로를 **운영 적용했다**. 기존 ModSecurity 감사 출력·Wazuh 원본 입력·DetectionOnly를 유지하며 Python 상시 수집기는 사용하지 않는다. WAF 정제 성공은 독립된 access 시간 근거와 정확한 짝 검증이 있을 때만 가능하고, 실패 행은 계속 격리한다. Wazuh WAF 상관 규칙 활성화나 자연 발생 WAF ready의 종단 관측을 이 적용과 같은 의미로 취급하지 않는다.

## 입력과 변환

```text
기존 ModSecurity JSON audit ─ waf_json_guard ─ waf_audit_part ─┐
                                                           ├─ reduce ─ waf_pair_normalize ─ waf_ready ─ 공통 후단
추가 nginx 최소 access JSON ─ waf_json_guard ─ waf_access_part┘
                 실패·짝 불일치 → 기존 비공개 quarantine sink
```

`waf_json_guard.vrl`은 먼저 Vector의 `parse_json`으로 구문·UTF-8을 검증한다. 이후 JSON 문자열과 구조 토큰만 검사해 네이티브 객체 변환에서 사라지는 중복 키 이력을 감시한다. 입력 128 KiB, 토큰 16,384개, 깊이 32가 상한이다. `\u0053erver`처럼 이스케이프가 다른 동등 키도 디코딩하여 비교한다. 서로 다른 객체의 같은 키는 허용한다. 중복 허용은 정확히 `transaction.response.headers.Server`의 **기존 값과 새 값이 모두 문자열**인 경우뿐이다. 해당 헤더는 정제 출력에 포함되지 않는다. 그 밖의 중복·잘못된 구문·한도 초과는 격리한다. 입력 상한보다 큰 행을 부분 JSON으로 사용하지 않는다.

audit와 access는 각각 지정된 파일 경로에서만 받는다. 다음 환경 값은 root 배포 설정이 제공하며 원문 필드로 덮어쓰지 않는다.

| 환경 값 | 계약 |
|---|---|
| `CAPSTONE_SENSOR` | 고정 센서 이름 |
| `WAF_AUDIT_PATH` | 기존 감사 파일의 정확한 호스트 경로 |
| `WAF_ACCESS_PATH` | 새 최소 access JSONL의 정확한 호스트 경로 |
| `WAF_INSTANCE_ID` | 실제 WAF 컨테이너 ID 64자리 전체 |
| `WAF_CONFIG_SHA256` | 검증·설치된 producer 설정 바이트의 SHA-256; 배포 기록에 해시 범위를 명시 |
| `WAF_DEPLOYMENT_BINDING` | 해당 컨테이너·설정·두 파일 경로에만 할당한 64자리 소문자 hex 배포 ID |

배포 ID는 양쪽 원문에도 기록한다. audit의 `unique_id`는 `배포ID-nginx_request_id`, access는 `deployment_binding`과 `request_id`를 분리해 기록한다. 현재 배포 ID와 다른 과거 원문은 격리한다. **컨테이너 교체, producer 설정 또는 경로 변경 때 새 배포 ID가 필수**다. root 배포 기록은 실제 전체 컨테이너 ID·설정 SHA·경로·배포 ID의 대응을 보관하고 실행 전 일치를 확인해야 한다. env만 새 값으로 바꾸고 이전 배포 ID를 재사용하면 과거 로그에 새 출처를 붙일 수 있으므로 허용하지 않는다. 이 대응은 운영자 배포 증거이며 로그 자체의 서명 또는 실행 중 Docker 신원 검증은 아니다.

## 최소 producer 변경

아래는 nginx `http` 문맥에 넣는 템플릿이다. `<DEPLOYMENT_BINDING>`은 root가 만든 새 배포 ID로 치환한다. 기존 `access_log`, 감사 설정, 보안 룰을 지우거나 대체하지 않는다. 실물 후보에서는 같은 문법으로 별도 nginx master의 `nginx -t`와 요청 검증을 마쳤다.

```nginx
log_format capstone_waf_evidence escape=json
  '{"capstone_waf_access_version":"1",'
  '"deployment_binding":"<DEPLOYMENT_BINDING>",'
  '"request_id":"$request_id",'
  '"time_iso8601":"$time_iso8601","msec":"$msec",'
  '"request_time":"$request_time",'
  '"source_ip":"$remote_addr","destination_ip":"$server_addr",'
  '"source_port":"$remote_port","destination_port":"$server_port",'
  '"http_method":"$request_method","http_status":"$status"}';

access_log /var/log/modsecurity/capstone-access.log capstone_waf_evidence;
modsecurity_transaction_id "<DEPLOYMENT_BINDING>-$request_id";
```

`$request_id`는 nginx가 생성한다. 클라이언트 `X-Request-ID` 값을 쓰지 않는다. 새 출력에는 URI, 쿼리, 본문, 요청/응답 헤더가 없다. producer가 생성하는 위 12개 필드만 허용하며 추가 필드도 격리한다. 기존 `access_log off` 또는 별도 server/location access 설정의 상속을 적용 전 확인해야 한다. 해당 위치에서 audit만 만들어지면 정제 성공으로 간주하지 않고 격리한다.

운영자 Ansible 후보는 [waf-producer/apply-a.yml](waf-producer/apply-a.yml)과 고정 root wrapper에 있다. 배포 파일은 [deployment.json](waf-producer/deployment.json)에 명시한 현재 전체 컨테이너 ID와 기존 nginx/커스텀 룰 SHA에 결속된다. root 신원·승인 worker 공유 lock → 별도 `nginx -t` → 기존 바이트/메타데이터 재대조 → 새 producer 원자 설치·graceful reload → 기존 master 보존과 새 worker/access FD 확인 순서다. 이미 같은 파일이 있어도 master+worker가 access FD를 열고 있어야 무변경 성공으로 판정한다. 설치 후 HUP 전에 중단된 경우 apply가 reload를 복구하고, check는 필요 여부만 반환한다.

검증 stage/config는 root:nginx 소유, 디렉터리 0750/파일 0640으로 nginx에게 읽기만 허용한다. 검증 stdout/stderr 파일만 nginx UID 101이 쓸 수 있다. 설치 직전 두 candidate SHA를 다시 대조한다. nginx가 쓸 수 있는 `conf.d`에 root 임시 파일을 만들지 않고, root 보호 stage의 검증 파일을 같은 파일시스템의 새 target으로 no-clobber hardlink한다. 이후 stage 링크를 제거하여 target은 단일 링크가 된다. 새 파일 설치 후 실패하면 자신이 설치한 바이트가 그대로일 때 제거하고 이전 native 설정 검증/HUP/새 worker 확인으로 복구한다. 다른 바이트로 바뀌었다면 임의 덮어쓰기/삭제를 거절한다. 이미 다른 producer 파일이 있으면 자동 교체하지 않는다.

컨테이너 안에서만 수정한 파일은 재생성 시 사라지므로 영구 root 프로젝트와 재생성 절차에도 같은 배포 계약이 필요하다. producer 적용 완료 뒤 설치 SHA·전체 컨테이너를 재대조하고 `/etc/capstone-vector/waf-binding.json`을 root 0600으로 기록한 다음 Vector env와 연결한다. 이 manifest는 `instance_id`, `configuration_sha256`, `deployment_binding`, `access_path`를 포함한다. 적용을 마치기 전 미리 활성 manifest로 기록하지 않는다.

추가 access 파일은 호스트의 기존 modsecurity 로그 디렉터리에 생긴다. A에서 확인한 `/etc/logrotate.d/capstone-secstack`의 `logs/modsec/*.log`에 맞추기 위해 이름을 `capstone-access.log`로 정한다. 내용은 JSONL이다. 읽기 권한, 실제 보존 기간과 디스크 한도를 적용 때 확인한다. 기존 `copytruncate` 한계가 새 access에 자동으로 해결되는 것은 아니다. 실제 `access_log off` 위치는 `/healthz`, `/metrics/nginx` 두 곳에서 확인했다.

## Vector 연결 계약

`tests-waf.toml`은 합성 source와 blackhole sink가 있는 **테스트 전용** 파일이다. 운영 파일로 설치하지 않는다. 운영 구성에는 다음 구성요소를 이식한다.

- 기존 audit source → `waf_json_guard.vrl` → `waf_audit_part.vrl`.
- 새 access file source → 같은 JSON guard → `waf_access_part.vrl`.
- `reduce`: 두 part 입력, `group_by=["waf_join_key"]`, `merge_strategies.waf_parts="array"`, `expire_after_ms=2000`, `end_every_period_ms=5000`, `flush_period_ms=100`, `max_events=4`.
- `waf_pair_normalize.vrl` → filter `.capstone_norm.source == "modsecurity"` → 기존 공통 정제 후단.
- 다섯 remap의 `.dropped`를 비공개 quarantine sink에 연결. `drop_on_error`, `drop_on_abort`, `reroute_dropped`는 모두 true. access-only 정상 출력은 filter에서 제외한다.

테스트 파일은 운영 `vector.toml` 또는 다른 topology와 병합하지 않고 아래처럼 단독 실행한다. 이 환경 값은 테스트 fixture 전용이며 운영 env 파일에 쓰면 안 된다. 파일명 상대경로 때문에 이 디렉터리에서 실행한다.

```sh
env CAPSTONE_SENSOR=groot-sec \
  WAF_AUDIT_PATH=/test/audit.log WAF_ACCESS_PATH=/test/access.jsonl \
  WAF_INSTANCE_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  WAF_CONFIG_SHA256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  WAF_DEPLOYMENT_BINDING=ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff \
  /usr/local/bin/vector test tests-waf.toml
```

audit와 access 각각 정확히 하나여야 한다. 센서·전체 컨테이너 ID·설정 SHA·배포 ID·request ID·주소/포트·method·status가 일치해야 한다. 누락, 여러 후보, 불일치는 격리한다. `RelevantOnly`에서는 일반 요청에 audit가 없는 것이 정상일 수 있으므로 **access 단독 한 건은 오류로 쌓지 않고 제외**한다. access 원본은 별도 파일에 남는다. audit 단독은 반드시 격리한다. 타임아웃 이후 늦게 도착한 짝을 자동으로 재조회하거나 재처리하지 않는다.

nginx `time_iso8601`의 명시 offset과 `msec` epoch가 같은 초인지 검사한다. audit의 offset 없는 asctime는 해당 요청의 nginx offset을 사용하되, `msec-request_time`에서 추정한 시작 시각 -2초부터 완료 시각 +1초 범위 안인지 확인한다. 임의 UTC/KST 가정은 없다. 정제 시각은 **nginx access 완료 시각**이며 `time_status=trusted_access_completion`, `time_basis=nginx_access_completion`으로 구별한다. 출력은 KST이다. 요청 시간은 1시간 이하만 허용한다.

ready는 허용 필드만 새로 만든다. 원문/URI/본문/헤더/매칭 data/message는 내보내지 않는다. rule ID와 severity만 보존하며 ModSecurity severity는 0–7 척도다. `action=observed`이고 HTTP 403이나 룰 매칭만으로 차단했다고 주장하지 않는다. 정보성 사항은 `time_basis`, `source_replay_deduplicated`, `omitted_response_server_duplicates`에 두며 정상 `quality_flags=[]`를 유지한다. source는 `modsecurity`, schema/pipeline은 `vector-1`/`vector`이다.

event ID는 센서·소스·전체 컨테이너 ID·배포 ID·request ID의 SHA-256으로 같은 배포의 재생 때 유지한다. 원문 해시는 Vector가 전달한 delimiter 없는 message 기준이다. 감사 파일 전체 바이트, 줄바꿈 또는 파일 세대의 증명이 아니다. 반복 전달을 자동 제거하지 않으며 Wazuh 영속 ACK나 exactly-once 처리도 제공하지 않는다.

## 검증과 남은 경계

- A의 Vector 0.59.0으로 중복 키·타입·시간·짝 결합·경로·과거 배포 거절 검증 **61개 native 회귀를 모두 통과**했다.
- 같은 WAF 컨테이너의 별도 `/tmp` 설정, `127.0.0.1:18997`만 듣는 nginx master에서 합성 요청을 보냈다. audit/access 각 한 건, 생성 ID와 배포 ID 일치, DetectionOnly, 명시 offset, 최소 필드만 출력됨을 확인했다. 이 실제 출력은 A 내부에서 Vector 후보까지 통과했다.
- 기존 운영 master PID와 시작 ticks, `/etc/nginx` 파일들의 SHA, 기존 audit inode와 기존 prefix SHA가 시험 전후 같았다. 기존 서비스 설정과 원본 감사 파일에 시험 이벤트를 쓰지 않았다. 합성 원문은 Mac이나 저장소로 가져오지 않았다.
- 분리 파일 source에서 audit FD 소비를 확인한 후 pair flush 전 Vector를 SIGKILL했다. access를 추가하고 같은 data_dir로 재시작하자 ready 1건, quarantine 0건이었다. 다음 정상 재기동에서 추가 ready는 0건이었다. 이 특정 장애에서 미완성 reduce 입력의 ACK/checkpoint 재생이 확인됐으며 모든 장애·전원 차단을 보증하는 결과는 아니다.

운영 producer 후보는 Ansible syntax와 root 보호 stage의 native check가 `changed=0`으로 통과했다. native 검사가 새 로그 경로를 여는 특성 때문에 비어 있는 `capstone-access.log`가 101:101/0640으로 미리 생성될 수 있다. 이는 producer 활성화 증거가 아니다. 최초 운영 install/reload 호출은 실행 전 자동 승인 검토에서 정확한 변경의 사용자 승인 확인 부족으로 거절되어, 당시에는 운영 `.conf`를 설치하거나 HUP하지 않았다. 이후 부모 담당자가 신뢰된 사용자 요청과 변경 범위를 대조하여 아래 후속 검토·실행을 진행했다. 운영 공격성 probe는 보내지 않았다.

후속 경과: 부모 담당자가 사용자 승인 범위를 구체화하여 재검토를 통과한 뒤 첫 apply를 실행했다. 03:20 KST의 이 시도는 설치/HUP 후 producer FD 검사에서 실패해 이전 설정으로 복구했다. 직접 재확인 결과 target 부재, 원래 nginx digest `99913d3d…e5aad`, 커스텀 룰 SHA `62c855cf…eebf`, 기존 master PID/start ticks, 컨테이너 healthy 및 native `nginx -t`가 모두 정상이었다. 원인은 container UID 0의 nginx `/proc` FD readlink 성공이 0개인 반면 같은 nginx UID 101에서는 14개였던 권한 차이다. 최종 helper는 FD 확인도 같은 UID로 실행한다. 이 수정 후 Ansible syntax/native check가 다시 `changed=0`으로 통과했고 manifest 복사 단계는 check에서 모두 건너뛴다. 재적용 결과는 별도 후속 검증으로 기록한다.

최종 적용: 부모 담당자가 해시를 고정한 root 실행 사본으로 보강본을 적용했고 producer 첫 실행 `changed=2`, 두 번째 `changed=0`, 실패 0을 확인했다. 기존 master 유지, 새 worker, master/worker의 추가 access FD, 기존 nginx/커스텀 룰 SHA, root 0600 binding manifest 검증이 통과했다. 이어서 Vector 통합은 native 89개 회귀와 binding 검증을 통과하고 첫 실행 `ok=42, changed=6, failed=0`으로 적용됐으며 서비스 active/running, NRestarts=0이었다. 두 번째 실행은 `ok=41, changed=0, failed=0`이며 PID·InvocationID가 유지됐다. 정제 서비스에 `MemoryHigh=384M`, `MemoryMax=512M`도 적용됐다.

직접 수행한 운영 요청은 loopback 일반 vhost의 **정상 HEAD /** 한 건뿐이며 HTTP 302를 받고 redirect를 따라가지 않았다. 추가 access 파일에 해당 HEAD 한 건이 기록됐고, 생성 request ID·현재 배포 ID·명시 offset·허용 12개 필드·민감 요청 필드 부재를 확인했다. `nginx -t`도 통과했다. 이후 서버 내부에서 같은 request ID를 대조해 **이 요청의 access 1건·audit 1건·Vector ready 1건**이 정확히 일치함을 확인했다. ready는 HEAD/302, `nginx_access_completion`, KST `+09:00`, DetectionOnly, 빈 quality_flags이며 원문·민감 요청 필드가 없다. 식별자 값이나 원문은 반입하지 않았다. 이는 운영 정상 요청 1건의 실제 결합 검증이며 자연 발생 표본 또는 공격 탐지 시험이 아니다. 높은 요청률, 여러 WAF 룰 및 장시간 관측은 별도 검증 대상이다.

producer를 먼저 적용하고 Vector를 나중에 바꾸는 전환 구간에는 기존 경로가 새 audit를 quarantine 처리한 뒤 ACK할 수 있다. 이 원문은 보존되지만 새 ready로 자동 승격되지 않는다. 전환 구간의 무손실 정제 승격을 주장하지 않는다.

`reduce` 상태는 메모리에 있다. `max_events`는 그룹당 한도이며 동시 request ID 그룹 수의 전역 상한은 아니다. TTL은 짧지만 대량 과거 재생이나 높은 요청률에 대한 메모리 부하/상한과 재시작 정책 검증이 필요하다. file sink write 완료는 fsync나 Wazuh 수신 증명이 아니다. raw copytruncate, file fingerprint 재생, 늦은 짝, 호스트 장애, source 보존기한 초과, 상관분석 중복·시간창은 별도로 다룬다. 운영 WAF 정제 편입과 Wazuh 상관 규칙 활성화는 각각 별도 상태로 보고한다.

분리 시험과 같은 날 A 직접 확인값은 RAM 6,068,184 KiB, available 4,788,164 KiB, 논리 CPU 2개, 기존 운영 Vector `MemoryCurrent=21,540,864 B`, `MemoryPeak=22,085,632 B`였다. 분리 후보는 pending audit 한 건에서 RSS/peak 48,496 KiB, 재시작 후 pair 한 건에서 49,824 KiB였다. `MemoryHigh=384M`, `MemoryMax=512M`는 이 baseline보다 큰 여유를 두면서 호스트를 보호하는 후보 한도다. 높은 동시 그룹 수를 소화한다는 용량 보장은 아니다. 한도 도달은 reclaim/처리 지연 또는 프로세스 OOM 종료를 유발할 수 있으므로 source 원본 보존, 재시작 제한, 운영 경보를 함께 검토한다.

공식 근거: [ModSecurity JSON 직렬화](https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.16/src/transaction.cc), [nginx connector의 transaction ID 설정](https://github.com/owasp-modsecurity/ModSecurity-nginx#modsecurity_transaction_id), [nginx log_format과 escape=json](https://nginx.org/en/docs/http/ngx_http_log_module.html), [nginx 내장 변수](https://nginx.org/en/docs/http/ngx_http_core_module.html#variables), [Vector reduce](https://vector.dev/docs/reference/configuration/transforms/reduce/), [VRL 함수](https://vector.dev/docs/reference/vrl/functions/).
