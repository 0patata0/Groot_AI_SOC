# 정제 스풀 전달과 수신 확인

**2026-10-14 정리:** Vector 운영 경로로 전환한 뒤 사용자 요청에 따라 이 문서에 나오는 이전 Python 구현 21개, 전용 테스트 16개와 합성 예제를 삭제했다. 아래 API·CLI·테스트 명령과 미배포/후속 계획은 각 검증 시점의 기록이며 현재 실행 지침이 아니다. 검증 결과와 JSON 증거는 보존했다. [삭제 목록·범위](RETIRED-2026-10-14.md), [현재 Vector 운영](vector/README.md), [현재 Wazuh 연결](wazuh-vector/)을 참조한다.

이 단계는 **A의 정제 스풀에서 B의 별도 시험용 SQLite inbox까지 전달하고, B의 영속 저장을 확인하는 구현·검증 범위**다. 기존 Wazuh 원천 입력, 운영 로그 회전, 보안 엔진 설정은 변경하지 않는다. Wazuh 분석 큐에 주입하거나 운영 `localfile`을 정제 입력으로 전환하는 작업은 후속 단계다. 아래 계약과 검증표에 이어 마지막 절에 실제 실행 결과를 구분해 기록했다.

관련 수집·보존 계약은 [COLLECTOR.md](COLLECTOR.md), 파일 세대의 종료·전체 해시 검증은 [ROTATION.md](ROTATION.md)를 따른다.

## 이번 전달의 완료 지점

```text
A 원천 로그
    → A 수집 스풀: 원문 + 최초 판정 + 원천 체크포인트
    → 배출 조건 검사: 검증 완료한 세대 / journal의 원자 보존 행
    → A outbox: 원문을 제외한 정제 envelope를 고정하여 보관
    → SSH 표준 입출력
    → B 별도 inbox: SQLite commit
    → durable_inbox receipt
    → A outbox: receipt 검증·보관

후속 단계: B inbox → Wazuh 입력 → 분석/상관 룰 → 색인/알림
```

| 표시 | 확인한 것 | 아직 확인하지 않은 것 |
|---|---|---|
| 수집 스풀의 `ready` | 정제·시각 검증과 로컬 저장 | 파일 세대의 배출 조건, 외부 전달 |
| outbox에 저장 | 배출 검사를 통과한 전송 바이트가 A에 보존됨 | B 수신 |
| receipt의 `stage=durable_inbox` | 지정 B inbox에 해당 바이트가 commit됨 | Wazuh 수신·분석·색인·알림 |
| A에 receipt 보관 | A도 일치하는 B 수신 확인을 영속 보관함 | 원문 삭제 허가, 이후 시스템 처리 |

`collector_delivery.py`는 inbox·outbox와 receipt를, `collector_delivery_gate.py`는 배출 조건을, `collector_delivery_transport.py`는 한 번의 제한된 SSH 교환을 담당한다. `delivery_stdio.py`는 inbox 초기화 또는 한 요청의 수신만 수행한다. 자동 재시도 daemon, 네트워크 listener, Wazuh 전송기, 만료·삭제 기능은 포함하지 않는다.

## Wazuh 자체의 ACK와 구별하는 이유

이 설명은 현재 검토 대상인 **Wazuh 4.14.8 소스**를 기준으로 한다. 다른 버전의 전송 방식이나 향후 HTTPS 연동을 현재 환경의 동작으로 간주하지 않는다.

일반 agent 이벤트의 TCP 송신 성공은 `send_msg()`가 호출하는 `OS_SendSecureTCP()`의 결과를 따른다. 해당 함수는 프레임을 `send()`한 바이트 수를 확인한다. 이 경로의 성공값에는 개별 이벤트의 원격 DB commit이나 분석 완료 확인이 들어 있지 않다. [agent 송신](https://github.com/wazuh/wazuh/blob/v4.14.8/src/client-agent/sendmsg.c#L20-L68), [TCP 송신 함수](https://github.com/wazuh/wazuh/blob/v4.14.8/src/os_net/os_net.c#L645-L661).

Agent 버퍼는 메모리에 할당하며, 가득 차면 새 메시지를 거절한다. dispatch 경로는 메시지를 꺼내 송신 함수를 호출한 뒤 메모리를 해제한다. 그러므로 agent 연결 상태나 버퍼 감소만으로 영속 수신을 증명할 수 없다. [버퍼 할당·포화 처리](https://github.com/wazuh/wazuh/blob/v4.14.8/src/client-agent/buffer.c#L55-L125), [dispatch와 해제](https://github.com/wazuh/wazuh/blob/v4.14.8/src/client-agent/buffer.c#L188-L228).

Manager의 일반 이벤트는 분석 큐에 넘기는 경로를 사용한다. 별도로 보이는 `HC_ACK`는 startup·keepalive 같은 제어 메시지 응답이므로, 이번 정제 이벤트가 보존·분석·색인됐다는 receipt로 사용할 수 없다. [일반 이벤트의 분석 큐 전달](https://github.com/wazuh/wazuh/blob/v4.14.8/src/remoted/secure.c#L882-L900), [제어 메시지 ACK](https://github.com/wazuh/wazuh/blob/v4.14.8/src/remoted/manager.c#L254-L363).

따라서 이번 새 receipt의 의미는 `durable_inbox`로 한정한다. `wazuh_analysis_confirmed`는 `false`이며 SSH 종료 코드 0, agent active, 알림 한 건 발생 중 어느 것도 이 의미를 확대하지 않는다.

## 전송 정보와 신뢰 경계

전송 envelope에는 정제된 `capstone_norm`, source key·설정 해시, 원천 record ID·원문 바이트 해시, 배출 근거 해시, 판정 revision, 대상 inbox ID, delivery ID를 담는다. 정제 JSON은 32KiB, LF를 포함한 전체 전송은 64KiB, receipt는 4KiB로 제한한다. 중복 JSON 키·비유한 숫자·예상하지 않은 envelope 필드·비정규 직렬화는 거절한다.

**원문 파일 행, 요청 본문·헤더·URI, 독립 시각 대조에 사용한 로그 원문은 전달하지 않는다.** 파일 위치와 해시는 A의 원문을 찾는 용도다. 정제 필드도 보안 이벤트의 IP·포트 등을 포함하므로 비공개 저장소와 인증된 전송을 사용한다. 전송 필드 허용 목록은 원문을 임의의 추가 JSON 필드로 넣는 것을 막으며, 원문을 다른 필드에 수동 삽입하는 별도 producer를 허용하는 계약은 아니다.

Inbox를 먼저 초기화해 생성한 32자리 ID를 송신 측에 고정한다. 다른 inbox, 비어 있는 새 DB, 의도하지 않은 재초기화를 같은 수신처로 인정하지 않는다. SSH는 이미 등록·검증된 호스트 키와 비대화형 인증을 요구한다. 호스트·receiver 경로·inbox 경로는 운영자가 정하는 고정 설정이며 이벤트 내용에서 명령이나 경로를 만들지 않는다. 운영 배포 시 전용 키의 수신 명령·경로 제한은 별도 구성해야 하며, 현재 모듈이 SSH 계정이나 키를 생성하지 않는다.

Receipt는 inbox ID, delivery ID, 전송 바이트의 SHA-256, event ID, 최초 수신 시각과 이 값들의 해시를 포함한다. 이 해시는 **전자서명이 아니다.** 응답 출처의 신뢰는 고정된 SSH 호스트와 receiver에 의존하며, 해시는 잘못된 응답·내용·대상 결속을 검출한다. receipt JSON의 해시만 맞다고 인증되지 않은 통신을 허용하지 않는다.

## 재시도, 충돌과 보존

Delivery ID는 source key·설정 해시·원천 record ID로 결정한다. 같은 원천 행을 다른 정제 revision이나 다른 배출 근거로 다시 포장해도 새 ID를 만들어 중복을 피하지 않는다. 실제 전송은 outbox에 저장한 바이트를 그대로 사용한다.

- **같은 ID·같은 바이트:** B는 최초 수신 행과 시각을 유지하고 같은 receipt를 돌려준다. 재수신 건수가 늘어도 inbox의 논리 이벤트 행은 늘리지 않는다.
- **같은 ID·다른 바이트:** `delivery_conflict`로 거절하며 먼저 보관한 내용을 덮어쓰지 않는다. 원문 또는 정제 내용을 수정한 재발행은 별도 정책 없이는 통과하지 않는다.
- **B commit 뒤 응답 유실:** A에는 ack가 없으므로 미확인 상태로 남는다. 같은 outbox 바이트를 다시 보내 B의 최초 receipt를 회수한다.
- **A의 receipt 저장 실패:** B에 저장됐더라도 A의 확인 완료로 처리하지 않는다. 이후 재시도해 동일 receipt를 다시 검증·저장할 수 있다.
- **이미 A가 확인한 항목:** 저장된 receipt를 다시 검증하고 추가 송신 없이 확인된 상태를 반환한다.

A 수집 스풀, A outbox, B inbox는 각각 별도 트랜잭션 경계다. B는 `synchronous=FULL` commit 후에 receipt를 만든다. A는 stage·수신처·ID·payload hash·receipt hash가 맞는 응답만 보관한다. 하나의 분산 트랜잭션으로 설명하지 않으며, 응답 유실을 중복에 안전한 재시도로 처리한다.

각 저장소는 기존 `Spool`의 비공개 권한·잠금·수량·용량 제한을 사용한다. 기본 논리 한도는 **저장소마다 64MiB**이며 물리 DB와 rollback journal 공간은 별도다. inbox 포화, outbox 포화, 잠금, 전송 시간 초과는 확인 실패로 남는다. ack만으로 A 원문·체크포인트·outbox 또는 B inbox를 삭제하지 않는다. 원천 수집 위치와 전달 확인 상태는 서로 다른 정보다.

SSH 교환은 기본 20초이며 API에서 60초 이내로 제한한다. 출력 초과·잘못된 응답·비정상 종료는 성공으로 인정하지 않는다. 오류 출력에는 원문·전송 payload 대신 고정 오류 코드만 사용한다. 장애가 계속될 때의 예약 재시도·보존 기간·용량 경보는 운영 연결 전에 정해야 한다.

## 파일 세대와 journal의 배출 조건

`ready`여도 모든 원천을 바로 배출하지 않는다. 수집기는 각 행의 원문·판정과 같은 트랜잭션에서 `proof.collection`에 설정 결속과 해당 행 뒤의 reader 상태를 남긴다. gate는 잠긴 같은 스풀에서 가져온 행과 현재 체크포인트를 대조한다. 체크포인트는 신뢰된 수집기만 변경한다는 전제다.

| 원천 상태 | 배출 조건 |
|---|---|
| manifest를 사용하는 파일 | 해당 행의 세대보다 현재 체크포인트의 소비 순번이 커야 한다. 이는 종료 증거와 archive 전체 SHA-256 검증 후 다음 세대 상태가 commit된 경계다. |
| 봉인됐지만 아직 앞부분만 읽은 파일 | EOF 검증·다음 세대 commit 전까지 보류한다. |
| 현재 쓰는 파일·manifest 없는 일반 파일 | 보류한다. EOF 관찰이나 `ready`만으로 배출하지 않는다. |
| kernel journal | 원자 보존된 canonical JSON·cursor·원문 해시·record ID와 현재 설정 결속을 검증한다. 파일 봉인 조건을 적용하지 않는다. |
| 과거 `proof.collection` 없는 행 | 보류한다. 현재 위치만으로 과거 원천 검증을 소급해서 만들지 않는다. |

파일 gate는 신뢰 UID의 manifest를 다시 열어 이력 prefix, 행의 장치·inode·generation·offset·바이트 범위와 닫힌 링크를 대조한다. 이력 rollback·fork·누락을 무시하지 않는다. archive 전체 해시는 reader가 EOF에서 검증하며 gate는 그 뒤 저장된 전환과 증거를 사용한다. 매 전송마다 archive 전체를 다시 읽는 구현은 아니다.

따라서 파일 이벤트는 **세대가 닫히고 끝까지 검증될 때까지 지연**된다. 회전 주기뿐 아니라 누적량·수집 실행 간격도 영향을 주며, 회전이 없으면 계속 대기한다. 낮은 지연이 필요하다는 이유로 봉인 조건을 끄기보다 writer별 안전한 회전과 전달 요구 시간을 함께 결정해야 한다. 운영 copytruncate가 유지된 현재 파일 경로는 자동 배출 대상으로 전환하지 않는다.

## 격리 재처리

`collector_reprocess.py`의 `reprocess_waf_record()`는 시간 근거가 부족했던 WAF 행에 대해 운영자가 명시한 attempt ID·사유·운영자 참조와 새 독립 근거로 재판정하는 범위다. 운영자 참조 문자열은 인증 수단이 아니며 호출자는 비공개 스풀과 근거를 읽을 권한을 이미 가져야 한다. 원래 `records` 행은 수정하지 않고 시도 이력을 추가한다. 원문·원문 해시·locator·최초 관찰 시각·event ID·`proof.collection`을 보존한다.

성공한 재판정은 `get_effective_record()`에서 사용하는 별도 결과이며 `processing_revision`으로 구별한다. 최초 판정은 revision 0이다. 이미 `ready`거나 성공적으로 재처리한 행을 다시 고치지 않고, 동일 attempt ID 재시도는 이전 결과를 반환한다. 실패한 재처리는 사유·운영자 참조·원문 결속·오류 이력을 남긴다. 행당 최대 8회이며 전체 시도 수·용량에도 스풀 한도를 적용한다. 최초 상태 통계와 재처리를 반영한 유효 상태 통계를 구별한다.

시간대가 확인돼 유효 상태가 `ready`가 되어도 위 파일 세대 gate는 그대로 적용한다. `quarantine`·`ignored` 자동 배출, UTC 추정, 이미 전송된 내용의 자동 교체는 하지 않는다. 재처리 성공 자체를 B 수신 확인으로 계산하지 않는다.

## 분리 시험의 통과 조건

이번 시험은 A→B의 별도 임시 inbox와 합성·통제된 입력을 사용한다. 운영 Wazuh 입력으로 연결하는 명령은 이 문서에 제공하지 않는다. 수신 프로세스 종료·재시작과 응답 유실을 직접 만들되 운영 receiver·daemon을 중단하지 않는다.

| 시험 | 필요한 관찰 |
|---|---|
| 정상 전달 | A의 고정 wire hash와 B 저장 hash, receipt stage·ID·hash가 모두 일치한다. |
| 원문 미전송 | 합성 원문에 넣은 식별 문자열이 wire·B DB·stdout에 없고 A 원문에는 남는다. 정제 허용 필드도 검사한다. |
| 응답 유실 | B commit 이후 첫 응답을 버린다. A는 미확인이고, 재전송 후 B의 유일 행 수·최초 수신 시각·receipt가 유지된다. |
| B 재시작 | receiver를 종료한 뒤 같은 DB·고정 inbox ID로 다시 열어 같은 payload를 재전송한다. 같은 receipt를 받고 한 행만 남는다. |
| A 재시작 | 같은 outbox를 다시 열어 미확인 바이트가 바뀌지 않는지와 저장된 ack의 재사용을 확인한다. |
| 충돌 | 같은 delivery ID에 다른 정제값·revision·원문 해시를 보낸다. 새 바이트를 거절하고 원래 행·receipt를 유지한다. |
| 잘못된 receipt | 다른 inbox·stage·delivery ID·hash, 잘린 JSON, 초과 크기, 비정상 종료에 A ack가 생기지 않는다. |
| 용량·저장 실패 | B 또는 A의 한도를 넘기거나 commit 전 실패를 만들고, 미확인 상태와 보존 자료가 유지되는지 확인한다. |
| 이전 archive gate | 미봉인·부분 수집·전체 해시 불일치·전환 commit 중단에서는 배출 0건이다. 올바른 재개 뒤 해당 세대만 풀린다. |
| 여러 차례 회전 | 중간 세대를 건너뛰지 않으며, 이후 checkpoint 진행·재시작에도 이미 고정된 outbox payload로 재시도한다. |
| 격리 재처리 | 원판정 불변, 실패·성공 이력, 동일 attempt 재시도, 재처리 뒤 세대 gate, 전송 충돌 정책을 함께 확인한다. |
| 운영 분리 | 운영 로그 경로·회전 설정·Wazuh 설정과 프로세스의 전후 상태를 대조하고 시험 파일·프로세스를 정리한다. |

결과에는 입력 수, 유일 delivery 수, 미확인·확인 수, payload/receipt 해시의 일치 여부, 재시작 후 DB 상태, 고정 오류 코드와 정리 여부를 기록한다. 원문 내용·SSH 인증 정보는 결과 파일에 넣지 않는다. 프로세스 중단·재시도 시험과 실제 전원 손실·디스크 손상 복구의 검증 범위도 구별한다.

## 기존 원천 입력을 정제 입력으로 바꾸기 전

기존 Wazuh의 raw `localfile`과 새 정제 입력은 서로 독립된 수집 경로다. Wazuh 4.14.8의 inode 변경 분기는 이전 파일을 닫고 새 파일을 여는 구조이며, 이 분기에는 이전 FD를 끝까지 읽는 단계가 없다. 정제 수집기의 종료 manifest는 Wazuh agent의 잔여 읽기까지 증명하지 않는다. [inode 변경 처리](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/logcollector.c#L675-L700), [JSON 읽기의 중단 조건](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/read_json.c#L34-L70).

| 전환 상황 | 누락·중복 조건과 후속 확인 |
|---|---|
| raw 중지 후 정제 수집을 기본 `end`로 시작 | 그 사이 로그와 이미 존재한 미완성 행이 시작 정책에 따라 제외될 수 있다. source별 정확한 시작 경계를 먼저 기록한다. |
| raw와 정제 입력을 동시에 운영 | 같은 사건이 서로 다른 decoder·룰에서 두 번 집계될 수 있다. 정제 `event_id` 존재만으로 Wazuh가 자동 중복 제거한다고 가정하지 않는다. |
| rename·늦은 이전 FD 기록 중 전환 | 새 수집기의 archive 보존과 별개로 기존 agent가 마지막 행을 수집했는지 확인한다. |
| 과거 스풀을 한꺼번에 재생 | 이벤트 시각과 처리 시각이 다르므로 상관 룰의 빈도·시간창·만료 경계가 달라질 수 있다. KST 형식 통일만으로 해결되지 않는다. |
| B inbox 수신 뒤 Wazuh 경로 장애 | `durable_inbox` 상태를 유지하되 Wazuh 완료로 올리지 않는다. 후속 publisher의 재시도·확인·보존 경계를 정한다. |

운영 이전에는 source generation·offset 또는 journal cursor의 전환 경계, 원문·정제의 공통 사건 대응표, 마지막 기존 입력과 첫 새 입력의 수량·시각을 검증해야 한다. 의도된 겹침 기간의 이중 경보 처리, 겹침을 끝낼 조건, 실패 시 되돌리는 위치까지 실제 agent·manager·상관 룰을 포함한 분리 시험으로 확인한다.

다음 작업은 B inbox에서 Wazuh로 넘기는 publisher와 완료 의미를 정의하고, 위 입력 이전·중복 집계·상관 시간창을 검증하는 것이다. 그 전에 자동 회전기나 정제 입력을 운영 경로에 활성화하지 않는다.


## 직접 검증 결과 — 2026-10-14 00:37~00:43 KST

전체285회귀가 통과했다. A/B 운영 설정의 해시·컨테이너 ID/시작 시각은 전후 같았고 원래 Wazuh 입력과 copytruncate를 유지했다. 새 패키지·계정·키·컨테이너·상시 서비스를 설치하지 않았다.

| 검사 | 실제 결과 |
|---|---|
| A 최근 kernel 표본 | 최근200건을 임시 스풀에 정제 보존, 그중3건 전송 선택. 전체 과거/후속 cursor 연속성 검증은 아님 |
| 설치 Suricata 분리 시험 | 합성 PCAP2건 중 폐쇄 세대1건 전달, 새 활성 세대1건 보류. 실제 운영 패킷 캡처/룰 변경 없음 |
| A→B 수신 응답 유실 | 첫 실제 수신 응답 폐기 → A outbox 재개방 → 같은 바이트 재전송 |
| 실제 통신·수신증 | 총5회 송신, `durable_inbox` 확인4건. 확인 후 같은 건 재호출은 송신0회 |
| B 독립 재개방 | 정확4행. A의 delivery ID/event ID/정제 SHA와 모두 일치 |
| 실제 WAF 격리 재처리 | 보관 원문4건을 먼저 격리하고 Docker/Nginx 접근 시각 근거를 다시 확인해4건 ready revision 생성 |
| WAF 불변·반복 | 8,432bytes SHA·각 행 원문/사건ID/최초 관측시각·체크포인트·원래 격리 판정 유지. 같은 attempt 재시도 추가 이력0 |
| WAF 전송 | 일반 archive는 trusted 회전 manifest가 없어4건 모두 배출 보류. 전송0건 |
| 정리 | A/B 시험 DB·파일·별도 엔진 프로세스 제거. Mac 작업 임시 폴더도 최종 정리 |

WAF 시각은 10/13 03:00:36·03:00:56·03:04:43·03:04:45 KST로 복구됐다. 이는 **이번 임시 스풀 내 재처리 전후 ID 보존**을 의미한다. 임시 스풀을 새로 만들 때의 파일 generation까지 이전 검증과 동일하다는 의미는 아니다.

실패한 시도도 결과 JSON에 보존했다. 첫 저널 시험은 처음200건이 부팅 로그라 보안 표본 부족으로 전송 전에 중단했다. 시험 범위를 최근200건으로 명시해 재검증했다. 자정 운영 회전 후 audit.log가 비어 있어 추가 WAF 시험이 중단됐으며, audit.log.1에서 이전 원문 SHA를 대조해 대상을 정정했다. 검증기의 Docker 경로를 `/usr/bin/docker`로 잘못 지정한 것도 실제 설치 경로 `/usr/local/bin/docker`로 수정하고 재검증했다. 파일 읽기 상한·교체 감지·재시도/재개봉 판정 대조를 보강한 최종 검증기로 WAF4건을 다시 확인했다.

실제 시험은 기존 관리 인증을 임시 환경과 askpass로 사용했고, B 공개 호스트 키는 검증된 기존 관리 SSH 경로에서 조회해 별도 임시 known_hosts에 고정했다. 기본 SSH helper가 요구하는 **전용 제한 키의 운영 구성은 아직 배포하지 않았다.** 인증 값은 결과에 기록하지 않았다.

[검증 집계·코드 해시·실패/복구·정리 근거](delivery-validation-2026-10-14.json). A handoff 당시 코드와 최종 WAF 검증 코드의 차이는 검증기 한 파일이며, 실제 사용한 버전 해시를 각각 보관했다. 이 결과는 B inbox까지의 확인이며 Wazuh 분석·색인·알림 또는 전원 장애/장기 부하 검증 결과가 아니다.
