# 정제 수집기 사전 배포 가이드

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../STATUS.md) · [실행 계획](../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

**2026-10-14 정리:** Vector 운영 경로로 전환한 뒤 사용자 요청에 따라 이 문서에 나오는 이전 Python 구현 21개, 전용 테스트 16개와 합성 예제를 삭제했다. 아래 API·CLI·테스트 명령과 미배포/후속 계획은 각 검증 시점의 기록이며 현재 실행 지침이 아니다. 검증 결과와 JSON 증거는 보존했다. [삭제 목록·범위](RETIRED-2026-10-14.md), [현재 Vector 운영](vector/README.md), [현재 Wazuh 연결](wazuh-vector/)을 참조한다.

**2026-10-14 00:43 KST — 전달·수신 확인과 격리 재처리 분리 검증 완료.** A→B 임시 inbox에 실제 journal3건·격리 Suricata1건을 보내고, 첫 응답 유실 뒤 재전송까지 총5회 통신에서 B의 유일4행·일치 수신증4개를 확인했다. WAF 보관 원문4건은 독립 시간 근거로 재처리하여 KST를 복구했고 원래 격리 판정·원문·사건ID·체크포인트를 보존했다. 전체285회귀 통과. `durable_inbox`는 B 저장 확인이며 Wazuh 분석/색인 확인은 아니다. 기존 Wazuh 입력과 copytruncate는 유지하며 다음은 Wazuh 전달·신규 상관/시간창·재전송 및 기존 입력의 이중 집계 검증이다. [전달 계약](DELIVERY.md).

**10/13 23:47 후속:** root 소유 manifest로 세대별 닫힘 근거·중간 파일 순서를 검증하는 선택 회전 모드를 추가했다. 전체227회귀와 실제 설치본의 분리 회전 시험이 통과했다. `--rotation-manifest`를 지정하지 않은 기존 경로는 회전 지점에서 계속 중단한다. 운영 copytruncate는 아직 유지한다. [회전 계약·실제 결과](ROTATION.md).

이 수집기는 원천 로그를 읽어 **정제 결과·보존할 입력·처리 위치를 로컬 SQLite 스풀에 함께 저장하는 사전 배포용 구현**이다. 한 번 실행하면 정해진 범위만 처리하고 종료한다. 기본 수집 CLI는 로컬 저장까지 수행한다. 별도 inbox로 보내는 출력·수신 확인과 명시적 WAF 격리 재처리는 추가했으며, Wazuh 전송·서비스 등록·자동 반복 실행·보존 기간 만료 삭제·스풀 비우기는 아직 구현하지 않았다.

파일 회전 정책과 Wazuh 중복 집계·시간창 검증이 남아 있으므로 운영 수집 경로에 연결하기 전 단계다. 테스트 통과만으로 무손실 운영이나 상관분석 정확도가 입증되는 것은 아니다.

## 구성과 처리 결과

| 파일 | 역할 |
|---|---|
| `collector.py` | 원천 설정 결속, 한 번의 수집, 정제·격리 판단, 행별 원자 저장 |
| `collector_file_reader.py` | Suricata EVE·ModSecurity audit JSONL의 inode·generation·offset 추적 |
| `collector_journal_reader.py` | kernel journal cursor 연속성 확인과 읽기 한도 |
| `collector_store.py` | 비공개 SQLite 스풀, 중복 재전달·충돌·용량 제한 |
| `collector_waf_evidence.py` | 시간대 없는 WAF 행과 독립 access 로그·Docker 시각 대조 |

스풀의 상태는 다음 의미다. 셋 모두 입력과 위치를 보존하며 용량을 사용한다.

| 상태 | 의미 |
|---|---|
| `ready` | 정제와 원천 시각 검증을 통과했다. Wazuh로 전송됐다는 뜻은 아니다. |
| `quarantine` | 잘못된 입력, 미확인 시각, WAF 시간 근거 부족 등으로 격리했다. 오류 코드를 함께 저장한다. |
| `ignored` | Suricata 비경보 EVE, 지원하지 않는 방화벽 prefix 등 정제 대상 밖이다. 입력을 삭제하거나 집계에서 조용히 누락시키지 않는다. |

`quarantine`은 자동 재처리하지 않는다. 근거가 나중에 생겨도 기존 레코드의 첫 판단을 덮어쓰지 않는다. 재처리·판정 이력·내보내기 정책은 별도로 구현해야 한다. 입력에는 민감한 요청 내용이 포함될 수 있으므로 상태 출력은 건수와 고정 오류 코드만 반환한다.

## 처음 읽는 위치와 재시작

CLI 기본값 `--start-at end`는 **최초 실행 시 이미 존재하는 내용을 제외하고 이후부터 수집하겠다는 명시적 시작 정책**이다. JSONL 파일 끝에 미완성 행이 있으면 그 행의 나머지도 다음 개행까지 제외한다. 이 결정은 bootstrap 체크포인트로 저장한다. 비어 있는 journal도 빈 bootstrap 상태를 저장하므로 다음 실행에서 새 로그를 다시 건너뛰지 않는다.

`--start-at beginning`은 기존 파일 또는 보존된 journal 이력을 처음부터 읽는 시험·재생용 선택이다. 이미 저장된 체크포인트가 있으면 `start-at`보다 체크포인트를 따른다. 옵션 변경으로 기존 위치를 초기화하지 않는다. 스풀이나 source key를 새로 만들면 별도의 수집 이력이 시작되므로, 운영 중 우회용으로 바꾸면 중복 집계가 생길 수 있다.

`source_key`, 원천 종류, `sensor`, 파일의 절대 경로, 수집 정책 버전을 설정 해시에 결속한다. 기존 source key의 설정이 달라지면 `source_configuration_changed`로 중지한다. 한 스풀은 프로세스 잠금으로 한 실행만 열 수 있다.

## 파일: 완전한 행, 회전과 중단 조건

파일 레코드 ID는 `file:<generation UUID>:<시작 offset>:<끝 offset>`이다. 같은 체크포인트에서 재시도하면 같은 ID가 나오고, 내용이 같더라도 다른 위치에 기록된 행은 별개로 남는다. 개행을 포함한 실제 파일 바이트를 저장한다. 미완성 행은 다음 실행까지 기다리며 JSON 일부를 완전한 이벤트로 해석하지 않는다.

기본 배치는 200행·1MiB이며 개별 행 한도도 개행 포함 1MiB다. 읽기에는 초과 판별용 1바이트, 변경 확인을 위한 재읽기, 제한된 fingerprint 읽기가 추가된다. 너무 큰 행은 `line_too_large`, 개별 행이 설정된 배치 바이트 한도에 들어가지 않으면 `batch_byte_limit`로 중지한다. 해당 행을 잘라 저장하거나 그 뒤로 위치를 넘기지 않는다. 앞서 안전하게 저장한 완전한 행은 유지한다.

체크포인트에는 경로, 장치·inode, generation, offset과 앞부분·직전 부분의 SHA-256 anchor가 들어간다. 이는 **관찰된** 잘림이나 재작성을 탐지하는 장치다. 관찰 사이에 copytruncate가 일어나고 파일이 같은 길이 이상으로 자라면서 확인하는 prefix·tail까지 같아졌다면 이를 완전히 증명할 수 없다. 현재 copytruncate 정책을 그대로 두고 무손실 수집을 보장할 수 없다.

| 상황 | 처리 |
|---|---|
| 파일 이름 변경 후 이전 inode가 같은 디렉터리에 남음 | 이전 파일의 남은 행부터 읽는다. 디렉터리 검색은 최대 1,024개 항목으로 제한한다. |
| 이전 inode에서 EOF 관찰 | `rotation_pending_close`로 멈춘다. EOF만으로 writer의 종료를 추정하지 않는다. 이전 FD에 늦게 추가된 행은 다음 조회에서 읽을 수 있다. |
| 이전 inode 유실 | `rotated_source_missing`으로 멈춘다. 새 파일의 처음으로 자동 이동하지 않는다. |
| 파일 크기 감소·anchor 불일치 | `source_truncated` 또는 `checkpoint_anchor_mismatch`로 멈춘다. gap을 숨기지 않는다. |
| 이전 파일이 미완성 행으로 끝남 | 회전 관련 중단 사유를 반환한다. 끝부분을 임의로 버리지 않는다. |
| 읽는 동안 재작성 확인 | 검증되지 않은 배치를 폐기하고 기존 체크포인트를 유지한다. |

하위 reader API의 `rotation_closed=True`는 **해당 이전 inode의 writer 종료를 외부에서 확인한 경우에만** 새 generation으로 전환한다. 전역 상시 허용 옵션이 아니다. 이 boolean 옵션은 CLI와 `collect_once()`에 노출하지 않는다. 새 선택 manifest 모드는 별도의 root 증거와 순서 검증을 통과한 경우에만 전환하며, manifest 없는 기본 모드는 계속 중지된다. 운영 통합에는 inode에 결속된 종료 확인 절차가 필요하다. 또한 그 사이 여러 차례 회전했다면 종료 확인만으로 중간 세대의 부재가 증명되지 않는다. 하위 API는 중간 세대를 자동 복원하지 않으므로, 전환을 승인하는 운영 계층이 매 세대의 순서와 누락 없음을 함께 확인해야 한다.

## Journal: cursor와 보존 바이트의 범위

Journal은 `_TRANSPORT=kernel` 조건으로 보존된 부팅 이력을 읽는다. 현재 부팅만 선택하는 `-k`는 사용하지 않는다. 다음 필드를 요청하며 journalctl이 자동으로 제공하는 메타데이터도 함께 유지한다.

```text
__CURSOR, __REALTIME_TIMESTAMP, __MONOTONIC_TIMESTAMP,
_BOOT_ID, _TRANSPORT, MESSAGE
```

이 경로의 `raw`는 **조회된 필드 값을 키 정렬·공백 없는 UTF-8 JSON과 LF로 직렬화한 바이트**다. journalctl 출력의 키 순서·이스케이프·공백이나 binary journal 파일 자체가 아니다. `MESSAGE`가 바이트 배열이면 그 값도 그대로 유지한다. `raw_bytes_sha256`와 스풀 `raw_sha256`은 이 canonical JSON 바이트를 대상으로 한다. 파일 JSONL의 실제 바이트 해시와 범위가 다르다.

이는 journalctl이 같은 cursor를 다시 출력할 때 JSON 키 순서를 바꾸는 문제를 처리하기 위한 계약이다. systemd 255는 [일반 Hashmap을 순회해 JSON 필드를 출력](https://github.com/systemd/systemd/blob/v255/src/shared/logs-show.c#L1006-L1074)한다. journal 체크포인트는 schema 2이며, 이전 출력 바이트 기준 schema 1과 섞어 사용하지 않는다. 원래 journal 파일 보존 정책을 대체하지 않는다.

재조회는 저장된 cursor를 포함해 읽은 뒤 cursor·부팅 ID·canonical 내용 해시가 같은지 먼저 확인한다. 해당 cursor가 vacuum으로 사라졌거나 내용이 달라지면 중지한다. 현재 위치나 최신 로그로 자동 점프하지 않는다. 기본 조회 제한은 200개 신규 레코드, cursor anchor를 포함한 출력 1MiB, 명령당 10초다. 출력이 잘리면 완전한 앞부분까지만 저장하며 잘린 행의 cursor로 진행하지 않는다.

## 저장 원자성, 재전달과 용량

각 행의 입력, 상태, 정제 결과, 시간 근거, 다음 체크포인트를 `synchronous=FULL` SQLite 트랜잭션 하나로 저장한다. 비교 후 갱신 방식으로 기존 상태가 예상과 다르면 거절한다. 여러 행의 배치 전체가 하나의 트랜잭션인 것은 아니다. 중간 행에서 용량이 부족하면 이미 저장한 앞부분은 유지하고 실패한 행 직전에서 재개한다.

같은 `(source_key, record_id)`와 같은 입력 해시가 다시 전달되면 재전달로 취급해 첫 관찰·정제·격리 결과를 유지한다. 같은 ID에 다른 입력이 들어오면 해당 트랜잭션을 거절한다. SID·IP·본문 내용이 비슷하다는 이유로 다른 이벤트를 합치지 않는다. 수량·용량 카운터도 같은 트랜잭션에 갱신하고, 다시 열 때 실제 집계와 대조한다.

기본 제한은 입력·정제값·근거·메타데이터·체크포인트를 합산한 **논리 용량 64MiB**, 레코드 100,000개다. 체크포인트 개수에도 같은 상한을 둔다. SQLite DB의 페이지 한도는 `2 × 논리 용량 + 64KiB`를 4KiB 단위로 올림한 값이다. 기본값에서는 128MiB + 64KiB다. DELETE rollback journal은 일시적으로 DB 크기에 준하는 추가 공간과 journal header 공간을 사용할 수 있으므로 논리 한도만큼만 디스크를 확보하면 충분하다는 의미가 아니다.

스풀 디렉터리는 현재 사용자 소유 0700, DB·잠금·journal 파일은 0600이어야 한다. 잘못된 권한을 자동 변경하지 않으며 symlink·hardlink·비정규 파일을 거절한다. 용량 초과 시 `backpressure`로 멈춘다. 오래된 로그를 자동 삭제하거나 체크포인트만 전진시키지 않는다. 더 작은 제한으로 다시 열어도 기존 자료를 지우지 않는다. SQLite 내구성 검증과 별개로 저장장치 장애·전원 손실 환경의 검증은 아직 운영 시험 범위다.

## WAF 시각 근거와 조회 예산

원천에 유효한 시간대가 있으면 이를 사용한다. 시간대가 없으면 UTC를 기본값으로 붙이지 않는다. 운영자가 audit 파일·sensor와 연결 관계를 확인한 **64자리 전체 로컬 WAF container ID**를 `--waf-container-id`로 지정한 경우에만 Docker 로그 대조기를 사용할 수 있다. 컨테이너 이름으로 대상을 자동 추측하지 않는다. 이 연결 관계는 운영자가 보증하는 설정이며 대조기가 mount 관계를 자동 증명하는 것은 아니다.

대조기는 audit의 IP·method·URI·응답 상태·초 단위 시각을 access 로그와 맞추고, access 로그의 명시적 offset과 Docker UTC 시각의 차이가 0초 이상 1초 미만인지 확인한다. 유일한 일치가 있어야 시간대를 보완한다. 이는 요청 필드의 교차 대조이며 유일한 transaction ID에 의한 증명은 아니다. 근거에는 source 설정 해시와 해당 audit 원문 해시를 결속하며 URI·요청 본문은 근거 요약에 복사하지 않는다.

CLI 기본 대조기는 실행당 최대 4회 조회한다. 각 명령은 15초·1MiB·5,001행 확인 한도로 제한된다. 따라서 대조 명령의 대기 예산은 최대 약 60초이며, 전체 실행 시간의 엄격한 60초 보장은 아니다. 파싱·파일 I/O·DB 저장 시간은 별도다. API의 `max_queries`는 1~16 범위이며 실패한 시도도 예산을 사용한다.

- **조회 예산 소진:** `time_evidence_query_budget`로 현재 행을 저장하지 않고 멈춘다. 기존 체크포인트를 유지하며 다음 실행의 새 대조기로 다시 시도한다. 예산 부족만으로 영구 격리하지 않는다.
- **근거 없음·복수 일치·조회 실패·시간 초과·출력 잘림:** 원문을 `quarantine`에 저장한다. 시간대를 추측하지 않으며 자동 재처리하지 않는다.
- **시간대 없는 행인데 대조기 미설정:** `time_evidence_unavailable`로 격리한다. 대조 없이 `ready`로 통과시키지 않는다.

## 운영 로그를 건드리지 않는 예제

프로젝트 루트에서 다음 예제를 실행하면 저장소의 합성 Suricata 예제 한 건으로 임시 파일과 스풀을 만들고 두 번 읽는다. 두 번째 실행은 같은 체크포인트를 사용한다. 임시 디렉터리는 끝나면 자동 삭제된다. 패키지 설치, Docker·journal 조회, 운영 서비스 실행은 하지 않는다.

```bash
python3 -B - <<'PY'
import json
from pathlib import Path
import subprocess
import sys
import tempfile

module_dir = Path('infra/normalization').resolve()
examples = [json.loads(line) for line in (module_dir / 'examples.jsonl').read_text().splitlines()]
event = next(item['event'] for item in examples if item['source'] == 'suricata')
with tempfile.TemporaryDirectory(prefix='capstone-collector-demo-') as temporary:
    directory = Path(temporary)
    source = directory / 'synthetic.jsonl'
    source.write_text(json.dumps(event) + '\n', encoding='utf-8')
    command = [sys.executable, '-B', str(module_dir / 'collector.py'),
               '--spool', str(directory / 'spool'), '--source-key', 'demo-suricata',
               '--kind', 'suricata', '--sensor', 'demo-a', '--path', str(source)]
    subprocess.run(command + ['--start-at', 'beginning'], check=True)
    subprocess.run(command, check=True)
PY
```

CLI 종료 코드는 0(이번 범위 처리 완료), 1(중단 사유 있음), 2(설정·저장소 오류)다. 코드 0이어도 `quarantine`이 있을 수 있으므로 출력 건수를 함께 확인해야 한다.

## 실제 적용 전 남은 검증

1. writer별 실제 바이너리의 분리 회전 시험은 후속 [ROTATION.md](ROTATION.md)에서 완료했다. 운영의 copytruncate를 바꾸기 전 기존 Wazuh 원천 경로 이전과 잔여 읽기, writer 제어 계층의 재시작/실패 복구를 검증해야 한다.
2. 회전의 마지막 행, 지연 append, 이전 파일 보존, 재시작 복구를 실제 writer와 함께 시험한 뒤 inode에 결속된 전환 확인 절차를 연결한다. 감지되지 않는 copytruncate 간격을 그대로 둔 채 배포 완료로 판단하지 않는다.
3. Wazuh의 기존 원천 경보와 추가 정제 입력이 같은 사건을 이중 집계하는지, 큐 부하가 얼마나 늘어나는지 검증한다. 스풀 내부 재전달 방지는 두 입력 경로의 경보 중복을 자동 해결하지 않는다.
4. 신규 상관 룰의 필드·빈도·시간창을 격리된 환경에서 시험한다. KST 시각을 출력하는 것만으로 Wazuh의 처리 시각 기반 시간창이나 과거 로그 재생 문제가 해결되지는 않는다.
5. 별도 inbox 전달/수신 확인과 WAF 시간 근거 재처리는 10/14 분리 검증을 완료했다. Wazuh 종단 확인·저장소 보존/비우기·예약 재시도·유실 커서 복구와 운영 연결 범위는 남아 있다.
