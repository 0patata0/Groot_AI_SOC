# 파일 회전과 종료 증거 계약

**2026-10-14 20:44 KST 최신 정정 — WAF의 실제 두 reader 격리 시험 완료.** 새 audit/access 경로와 세대별 배포 ID를 사용하는 별도 nginx/ModSecurity writer에서 4세대·6요청(2/1/1/2)을 시험했다. 이전 worker의 늦은 기록, reader 정지 중 연속 두 회전, 세 번의 인접 세대 공개, 같은 checkpoint를 사용하는 정상 reader 재시작을 통과했다. Vector의 audit/access 입력은 각각 6건, Wazuh의 audit 입력은 6건을 정확히 수신했고 중복은 0건이었다. 이 결과는 아래 10/13 writer 시험과 12:22 Suricata 시험에 추가되는 별도의 검증이다. [WAF 상세 범위](vector/waf-rotation/README.md), [검증 결과](vector/waf-rotation/validation-2026-10-14.json).

Vector는 줄바꿈을 제외한 원문 행 SHA를 대조하고, Wazuh는 설치된 cJSON의 재직렬화 결과 SHA를 대조했다. Wazuh queue의 JSON 바이트를 원래 파일 바이트와 같다고 가정하지 않았다. 정상 재시작에서는 실제 SIGTERM 전달·강제 종료 없음과 함께 Wazuh의 종료 코드 1 및 최종 논리 offset/SHA, Vector의 종료 코드 0을 확인했다. 별도 보관본 결합 시험은 6건의 ID·KST 시각·SHA를 정확히 대조했고, 다른 배포 ID 4건은 격리했다. audit 격리를 관측하고 실행 시작 약2.51초 뒤 짝을 준 TTL 시험은 ready 0·quarantine 1·access 단독 제외 1이었다.

**운영 copytruncate는 유지한다.** 보관본 결합은 검증된 manifest로 원래 source 경로 메타데이터를 복원한 오프라인 시험이므로, 두 파일을 운영 중 공개할 때의 실시간 결합을 증명하지 않는다. 시험 writer는 UID 0이며 운영 UID 101 재현, 원격 수신 ACK, crash·재부팅 복구, 초기 운영 경로 이전과 자동 회전기 배포는 미완료다. 20:44:38 최종 postflight에서 운영 보호59파일·서비스·PID/CID 불변을 확인했다. 20:45:57 원본205파일을 A 영구 증거 경로에 SHA 대조 보관했으며 소스 보관/작업경로 정리는 후속 마감으로 기록한다.

**2026-10-14 12:22 KST 원천 Suricata 추가 검증:** 별도 offline writer와 실제 Vector/Wazuh private reader에서 지연 공개 회전은 각각6건·중복0, 연속2회전·정상재시작을 통과했다. 단순 rename 대조군에서는 늦은 옛파일 기록/중간 세대2건을 놓쳤다. 운영 copytruncate·기존 출력 회전기는 유지하며 이번 결과는 격리 검증이다. 강제 종료·재부팅·초기 checkpoint 이전·운영 Vector 완료 근거·WAF별 확인 후 운영 전환해야 한다. [실측·시도 이력·한계](vector/raw-rotation/README.md).

**2026-10-14 정리:** Vector 운영 경로로 전환한 뒤 사용자 요청에 따라 이 문서에 나오는 이전 Python 구현 21개, 전용 테스트 16개와 합성 예제를 삭제했다. 아래 API·CLI·테스트 명령과 미배포/후속 계획은 각 검증 시점의 기록이며 현재 실행 지침이 아니다. 검증 결과와 JSON 증거는 보존했다. [삭제 목록·범위](RETIRED-2026-10-14.md), [현재 Vector 운영](vector/README.md), [현재 Wazuh 연결](wazuh-vector/)을 참조한다.

**10/14 후속:** 폐쇄 세대의 전체 검증과 다음 checkpoint commit을 외부 배출 조건으로 연결했고, 별도 inbox 전달·수신 확인 및 격리 재처리까지 분리 검증했다. 운영 회전과 기존 Wazuh 경로는 유지하며 이후 조건은 [DELIVERY.md](DELIVERY.md)를 따른다. 아래 회전 시험 결과는 10/13 당시 기록이다.

**2026-10-13 23:47 KST 실제 설치본의 격리 시험 통과.** 운영 Suricata8.0.6·Nginx1.30.5/ModSecurity3.0.16 바이너리를 별도 시험 프로세스로 실행했다. Suricata 합성 PCAP2건과 WAF loopback 요청9건을 회전 전후 스풀에 모두 보존했고, 재오픈 추가 저장은0건이다. 전체227회귀가 통과했다. [검증 집계·시도 이력](rotation-validation-2026-10-13.json).

| 실제 시험 | 관찰 |
|---|---|
| Suricata rename → SIGHUP → 다음 PCAP | 동일 시험 프로세스가 새 inode에 기록, 이전 쓰기 FD0·새 쓰기 FD1 |
| WAF rename → USR1 | 이후2건도 이전 inode에 기록. 감사 로그 재열기 실패 |
| WAF 같은 감사 경로 → HUP | 이후2건도 이전 inode에 기록. 감사 로그 재열기 실패 |
| WAF 새 감사 경로 → HUP | 새 요청2건은 새 inode, 앞서 대기하던 요청1건은 이전 inode에 늦게 기록 |
| 이전 WAF 요청 완료 후 | 이전 쓰기 FD0 확인 후 봉인·manifest 발행, 남은 이전5건과 새2건을 순서대로 보존 |

WAF9건은 이번 회전 시험에서 별도 시간 근거 대조기를 연결하지 않아 **quarantine으로 원문을 보존**했다. 이를9건 정제 완료나 실제 운영 경보로 계산하지 않는다. Suricata2건은ready다. 새 master와 기존 worker를 구별해 시험 신호만 보냈고, 23:48 최종 조회에서 원래 운영 프로세스 목록·컨테이너 ID/시작 시각·설정 해시·운영 WAF 원문이 유지됨을 확인했다. 시험 프로세스·파일·호스트 임시 스풀은 모두 제거했다.

현재 구현은 **파일을 쓰는 프로세스가 이전 파일을 닫았다는 증거와 세대 순서를 확인한 뒤 수집 위치를 전환하는 사전 배포용 경로**다. `collector_rotation.py`가 manifest를 소비하고, `collector_rotation_proof.py`가 종료 관찰과 manifest 저장을 담당한다. 기본 수집·스풀 계약은 [COLLECTOR.md](COLLECTOR.md)를 따른다.

운영의 copytruncate 설정은 그대로이며 자동 운영 회전기는 배포하지 않았다. 실제 설치 바이너리를 사용하는 별도 프로세스·임시 로그 시험은 운영 daemon을 변경하는 작업과 구별한다. 위 결과는 격리 시험의 성공이며 운영 회전 정책 배포 완료를 뜻하지 않는다.

## 종료 관찰 모듈이 하는 일

manifest 발행 모듈은 **로그 rename, 엔진 reload·signal, chmod를 실행하지 않는다.** 별도의 writer별 제어 계층이 파일 보존, 설정 변경, 재오픈, 이전 writer 종료, archive 권한 고정을 끝낸 뒤 발행을 요청해야 한다.

발행 요청은 다음 순서로 검사한다.

1. 이전 archive와 다음 파일을 symlink 없이 열어 서로 다른 실제 장치·inode인지 확인한다. archive는 신뢰 UID 소유의 정규 파일, hardlink 없는 `nlink=1`, 권한 0400이어야 한다.
2. `/proc`에서 대상 inode의 쓰기 가능한 FD를 확인한다. 이전 inode의 쓰기 FD는 호스트 전체에서 0이어야 하고, 지정한 writer PID가 다음 inode의 쓰기 FD를 적어도 하나 가지고 있어야 한다. FD 내용은 읽지 않는다.
3. archive 전체 SHA-256을 계산한다. 이후 FD를 다시 검사하고 writer의 시작 tick, archive 크기·mtime·ctime, 두 경로의 inode가 바뀌지 않았는지 확인한다. PID 숫자만 같거나 관계없는 프로세스가 새 파일을 열었다는 이유로 통과시키지 않는다.
4. 기존 manifest에 순번과 이전 링크 해시를 연결해 한 세대를 추가한다. 비차단 잠금 아래 임시 파일을 쓰고 `fsync → atomic replace → 디렉터리 fsync`로 저장한다.

권한 부족 등으로 `/proc` 검사가 불완전하면 거절한다. 프로세스·FD 순회에도 한도가 있다. 이 검사는 두 번의 관찰이며 미래에 권한 있는 프로세스가 archive를 다시 열지 못한다는 절대적 증명은 아니다. 실제 writer 제어와 archive 보존 정책이 신뢰 경계를 구성한다.

## Manifest의 구조와 신뢰 범위

manifest는 이벤트 본문이나 LLM이 제공하는 승인 문자열이 아니다. 신뢰된 회전 제어 계층이 생성하는 운영 증거다. CLI의 `--rotation-manifest`는 기본적으로 **UID 0 소유 0700 디렉터리 안의 0600 정규 파일**만 받는다. symlink·hardlink를 거절한다. API의 다른 `trusted_uid` 값은 격리 시험의 신뢰 영역을 만들기 위한 선택이며 일반 writer에게 증거 발행 권한을 주는 운영 절차가 아니다.

| 필드 | 결속 대상 |
|---|---|
| `schema`, `chain_id` | manifest 형식과 하나의 회전 이력 |
| `source_binding`, `source_path` | source key·원천 종류·sensor·고정 절대 경로·manifest 경로·정책을 포함한 수집 설정 |
| `links[].sequence` | 1부터 연속하는 세대 전환 순번 |
| `links[].previous_sha256` | 직전 링크의 canonical JSON SHA-256. 첫 링크는 0을 64개 쓴 값 |
| `links[].closed` | archive basename, 장치·inode, 최종 크기, 전체 SHA-256 |
| `links[].next` | 바로 다음 세대의 장치·inode |
| `links[].proof` | 아래의 writer 종료 관찰 |

`proof`의 method는 `writer-fd-close-v1`이며 원천 종류, 64자리 container ID, 실제 writer PID·시작 tick, offset을 포함한 관찰 시각, 이전 쓰기 FD 수 0, 해당 writer의 다음 쓰기 FD 수, 설정 SHA-256을 담는다. container ID와 설정 해시는 운영 제어 계층이 제공하는 식별 정보다. 발행 모듈이 그것만으로 container·설정의 실제 연결 관계를 자동 증명하는 것은 아니다.

archive는 원천 파일과 같은 부모 디렉터리의 안전한 basename으로만 지정한다. 임의의 절대 경로나 `../`는 허용하지 않는다. 링크 사이의 `next`와 다음 `closed` inode가 같아야 하며, 순번 누락·순서 변경·순환·archive 이름 재사용을 거절한다. 기본 상한은 manifest 4MiB, 링크 4,096개, archive 한 개 512MiB다. 이력 자동 삭제·압축·링크 잘라내기는 구현하지 않았다.

## 수집기가 순서를 유지하는 방법

회전 모드는 파일 체크포인트를 `kind=rotation_file` 상태로 감싼다. 기존 generation·offset·anchor와 함께 `chain_id`, 마지막 소비 순번, 마지막 링크 해시를 저장한다. 소비한 prefix가 수정됐거나 manifest가 예전 상태로 되돌아가면 중지한다. 이전 일반 file checkpoint를 자동 변환하지 않는다. manifest 사용 여부나 경로도 설정 결속에 포함되므로 기존 스풀에 옵션만 추가해 우회 전환할 수 없다.

최초 실행의 기준은 **현재 active 파일**이다. `end`는 기존 내용을 제외하고, `beginning`은 현재 active 파일의 처음부터 읽는다. 둘 모두 이전 archive 전체를 자동 재생하는 옵션이 아니다. bootstrap 때 manifest의 마지막 `next` inode와 실제로 읽은 파일을 다시 대조하여, 이름을 확인한 직후 또 회전됐다는 이유로 뒤 세대를 기준점으로 잡지 않는다.

실행 사이에 `A → B → C`로 두 번 회전했어도 먼저 A archive, 다음 실행에서 B archive, 그다음 C를 읽는다. 현재 active 파일 이름만 보고 A에서 C로 건너뛰지 않는다. archive는 manifest의 정확한 basename으로 선택하므로 중간 파일을 임의의 디렉터리 검색 결과로 추측하지 않는다.

한 호출은 한 세대를 읽고 최대 한 번 전환한다. EOF에 도달하면 archive의 크기·inode·전체 SHA-256을 검사하고, 바로 다음 파일의 inode를 확인한 뒤 다음 체크포인트를 offset 0으로 만든다. 새 generation은 설정·chain·순번·다음 inode에서 결정하므로 마지막 행 저장 뒤 중단되어 재시도해도 같은 ID를 사용한다. 현재 행과 다음 상태의 원자 저장은 기존 스풀이 수행한다.

| 상태 | 결과 |
|---|---|
| 이름만 바뀌고 종료 증거가 아직 없음 | 이전 파일을 읽되 EOF에서 기다린다. 종료를 추정하지 않는다. |
| 중간 세대나 다음 inode가 없음·다름 | gap 또는 identity 오류로 중지한다. 최신 파일로 이동하지 않는다. |
| archive의 끝에 새 미완성 행이 남음 | 그 행을 버리지 않고 중지한다. 최초 `end` 정책으로 제외한 기존 조각은 구별한다. |
| copytruncate·anchor 변경 | 기존 잘림·변경 검사로 중지한다. manifest가 잘림을 승인하는 수단은 아니다. |
| 해시 불일치·이력 rollback·fork | 전환하지 않는다. 기존에 보존한 자료를 삭제하지 않는다. |

**전체 archive 해시는 EOF에서 검증한다.** 그 전에 앞부분이 스풀에 보존될 수 있다. 앞으로 Wazuh 전송기를 붙일 때에는, closed generation의 봉인·완료 검증 전 보존 행을 배출하지 않도록 별도의 완료 상태와 전송 조건을 설계해야 한다. 현재 로컬 보존 성공이나 `ready` 상태를 외부 수신 확인으로 해석하면 안 된다.

## Suricata 회전 후보

Suricata의 공식 회전 절차는 파일 rename과 SIGHUP을 사용한다. 다만 검토한 8.0.6 소스에서는 회전 요청 flag를 설정하고 다음 로그 쓰기 경로에서 다시 여는 동작이 있으므로, signal 전송 성공이나 잠깐의 EOF만으로 이전 FD가 닫혔다고 판단하지 않는다. [공식 회전 문서](https://docs.suricata.io/en/suricata-8.0.6/output/log-rotation.html), [재오픈 flag 처리](https://github.com/OISF/suricata/blob/suricata-8.0.6/src/util-logopenfile.c#L204-L235), [로그 재열기 요청](https://github.com/OISF/suricata/blob/suricata-8.0.6/src/unix-manager.c#L878-L883).

후보 제어 순서는 이전 inode 보존 → 해당 writer의 재오픈 요청 → 다음 로그가 새 inode에 기록되는지 확인 → 이전 쓰기 FD 종료 확인 → archive 봉인·manifest 발행이다. 격리 시험에서는 별도 Suricata 프로세스와 합성 PCAP으로 이 경계를 확인한다. 운영 트래픽을 기다리는 시간, 종료하지 않은 writer 처리, 원천 Wazuh 수집의 잔여 읽기는 별도 운영 전환 조건이다.

## ModSecurity audit 회전 후보

Nginx access/error 로그의 reopen과 ModSecurity audit writer를 동일한 파일 관리 방식으로 취급하지 않는다. 검토한 ModSecurity v3.0.16의 Serial writer는 `SharedFiles`를 통해 파일을 열며, 같은 pathname은 기존 핸들을 참조하고 마지막 참조가 해제될 때 닫는 구조다. 따라서 이름만 바꾸거나 같은 pathname으로 reload하는 동작이 audit FD 종료를 보장한다는 가정은 피한다. [Serial writer](https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.16/src/audit_log/writer/serial.cc), [SharedFiles의 경로별 핸들 관리](https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.16/src/utils/shared_files.cc).

격리 시험에서 통과한 후보는 **새 audit pathname을 지정한 설정과 HUP에 따른 새 writer 전환**이다. 이전 worker에서 아직 처리 중인 요청은 늦게 끝나면서 이전 archive에 기록할 수 있으므로, 새 파일에 로그가 생겼다고 즉시 이전 파일을 봉인하지 않는다. 마지막 이전 요청의 기록과 이전 inode의 모든 쓰기 FD 종료를 확인한 다음 manifest를 발행해야 한다. 실제 바이너리 격리 시험은 기존 audit writer, 늦게 완료되는 요청, 새 writer를 각각 구분해 확인하는 범위다.

새 pathname을 쓰는 엔진 설정과 수집기의 고정 `source_path` 사이에는 별도 연결 설계가 필요하다. 현재 발행 API의 `next_path`는 설정된 원천 경로여야 하고 reader도 그 경로의 실제 inode를 확인한다. source key를 새로 만들거나 symlink로 우회해 문제를 덮지 않는다. 운영 재시작·다음 회전에서도 설정과 manifest 순서가 유지되는지 검증하기 전에는 이 후보를 자동 운영 절차로 배포하지 않는다.

격리 연결 시험에서는 고유한 새 audit 파일에 고정 active 경로의 **hardlink alias**를 만들어 같은 inode를 가리키는 구성을 사용한다. 이때 active 파일의 `nlink=2`와 봉인 archive의 `nlink=1`을 구별한다. 운영에 사용하려면 alias의 원자적 교체, 이전 세대의 불필요한 링크 제거와 최종 봉인, 엔진 재시작, 기존 Wazuh 경로 이전까지 함께 검증해야 한다. 시험용 alias 연결 자체를 배포된 회전 정책으로 간주하지 않는다.

## 기존 Wazuh 원천 수집 경로의 한계

새 manifest가 보장하는 것은 **새 정제 수집기 자신의 위치 전환**이다. 이미 Suricata·WAF 원천 파일을 읽는 Wazuh agent의 `localfile` 위치를 함께 커밋하거나 그 수신 완료를 증명하지 않는다.

검토한 Wazuh 4.14.8의 inode 변경 분기는 이전 파일을 닫고 새 파일을 연다. 그 분기에 이전 FD의 잔여 내용을 끝까지 읽는 절차가 없으며 JSON 읽기에는 별도 중단 조건이 있다. 따라서 원천 파일의 늦은 마지막 행이 기존 agent에도 모두 수집됐다고 새 manifest만으로 판단할 수 없다. [inode 변경 처리](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/logcollector.c#L675-L700), [JSON 읽기 경로](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/read_json.c#L34-L70).

이 때문에 현재 운영 copytruncate를 곧바로 rename 방식으로 교체하지 않는다. 원천 입력 경로를 유지하거나 이전하는 선택을 먼저 정하고, 실제 agent를 포함해 마지막 행·회전 중 누적분·재시작·중복 여부를 검증해야 한다. 정제 입력을 추가하면 원천 경보와 같은 사건이 두 번 집계될 가능성도 별도로 확인한다.

## 다음 적용 조건

1. 실제 writer의 회전·지연 기록·종료 증거·스풀 재오픈은 위 격리 시험에서 통과했다. 중간 세대 여러 개·잘못된 이력·재시도는 합성 회귀로 검증했다. 운영 제어 계층의 여러 회전·엔진 재시작·실패 복구는 추가 검증한다.
2. 별도 B inbox까지의 출력·전송·수신 확인과 응답 유실 재시도는 10/14 검증했다. Wazuh 분석/색인 수신 확인과 확인 후 보존/삭제 정책은 별도다. `ready`·로컬 commit·EOF는 수신 확인을 대신하지 않는다.
3. WAF 시간 근거가 없던 격리 건의 명시적 재처리와 별도 판정 이력은 10/14 검증했다. 기타 격리 오류와 원문 보존 기간이 지난 경우의 복구는 후속이다.
4. 기존 Wazuh `localfile` 경로의 이전·잔여 읽기·중복 집계와 상관 룰 시간창을 실제 agent까지 포함해 시험한다.
5. 위 조건이 확인된 뒤 writer별 운영 회전기, 파일 보존, 실패 시 중단·복구 범위를 결정한다. 현 단계에는 이 자동 운영 제어 계층이 없다.
