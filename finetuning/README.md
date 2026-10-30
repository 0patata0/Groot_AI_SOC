# SOC 모델 파인튜닝 준비 폴더

**관측 후보 답변 검수 — 2026-10-30 KST:** `refine_soc_observation_targets.py`는 고정 R1의17개 후보를 대조해 입력/근거94개는 보존하고10개 답변을 수정한다. 같은 시각의 선후 추측, 요청과 실행 성공의 혼동, 입력에 없는 필드 내용의 추정을 막고 관측별 근거를 연결한다. R1을 덮어쓰지 않으며 별도 R2에도 학습 미편입 상태와 출처 고지를 유지한다. [수정·30회귀·재현·별도 대조 결과](SOC_OBSERVATION_TARGET_REVIEW.json).

```sh
python3 -B finetuning/refine_soc_observation_targets.py \
  --source finetuning/data-soc-observation-candidate-20261030-r1 \
  --output /new/local-candidate-directory
python3 -B -m unittest discover -s finetuning/tests -p test_soc_observation_targets.py -v
```

원장의 R1 후보/lineage/고지 해시와 일치하는 로컬 자료가 필요하다. 결과를 생성했다고 학습에 편입하지 않는다. `check_soc_observation_tokens.py`는 R1/R2 각각의 후보·lineage 해시와 기록별 연결을 검증한 뒤 기존 Thor 환경의 고정 tokenizer로 전체 정답/마스크를 검사한다. **실제 tokenizer는 접속 시간 초과로 아직 실행하지 못했다.** 답변 크기가16,218→22,916B로 늘었으므로4096토큰 적합성을 별도 확인해야 한다. 고유답변14→17은 정확도 상승 수치가 아니다. 원천2종/기존학습환경6묶음·과거 관측 전용으로, 실제 MCP·승인·쓰기·원복 능력은 별도 검증한다. 후보 데이터는 Git/자동pack에서 제외하고 준비 소스·원장·검사만 포함한다.

이하 원문·입력 검수 이력을 보존한다.

**BETH 분할 검사:** `audit_beth_splits.py`는 고정 취득manifest의 ZIP/CSV를 스트림으로 읽어 CRC·SHA·전체행을 검증한다. 원문 특징 전체와 공통11특징 투영을 별도로 대조하고, 라벨을 해시에서 제외하여 상충하는 라벨 때문에 중복이 숨지 않게 한다. 빈칸/0·문자열·반복횟수를 보존하며 학습 편입·라벨 수정·자동분할은 하지 않는다. [실제114만여행·별도원본 검증](BETH_SPLIT_REVIEW.json).

```sh
python3 -B finetuning/audit_beth_splits.py   --manifest /path/acquisition.json --directory /path/downloads   --scratch /path/task-temp --output /new/path/beth-audit.json
```

원장의 `acquisition`과 같은 고정파일/해시를 준비하고 출력상위경로·scratch는 미리 만든다. 출력덮어쓰기/해시변경/비정상스키마는 거부한다. 파일전체를 추출하지 않으며 임시SQLite는 종료/오류시 정리한다. 성공종료는 검사완료이며 분할독립/정답/모델품질 보증이 아니다. 원문행·호스트간 중복을 `pairs`에서 확인하고 공유열투영을 전체열일치로 해석하지 않는다. Mac에 새의존성 설치가 필요없다.

공식분할1141078행과5월ubuntu199222행 전체를 별도구현으로 대조했다. 공식파일16열·5월파일13열 차이를 유지한다. 같은호스트명은 같은capture/boot라는 뜻이아니며 uptime을 KST날짜로변환하지 않는다. 9회귀통과·새학습/모델호출0. pack은검사기/원장만추가한다.

**추가 데이터 3종 검토 — 2026-10-30 KST:** CAM-LDS·BETH·RBD24의 기관/학술 출처와 이용 조건을 확인했습니다. CAM-LDS 제공 입력990개는198단계의 반복이며 고유 입력393개입니다. BETH 프로세스199,222행·DNS269행을 검수했고 다른 이름의 DNS파일2개가 동일함을 확인했습니다. 실제 인터넷 관측과 연구 시험망 자료를 구분하며 신규학습0입니다. [원장](SOC_EXTRA_CORPORA_REVIEW.json).

CAM-LDS의 Zenodo v2 로그와 GitHub v1 기반 입력을 혼합하지 않습니다. `pack.py`는 새 출처 원장만 포함하고 원본·검토 입력을 학습에 자동 편입하지 않습니다. BETH 프로세스 시각은 부팅 후 초여서 KST 날짜를 추정할 수 없으며 DNS의 UTC는 별도 변환 가능합니다. RBD24는 파일 목록/권리만 확인했고 Parquet 원행 검수는 미완료입니다. 출처가 검증되었다는 사실과 개별 정답/모델 품질 보증은 구분합니다.

**Hornet65 실제 원문 검수:** `inspect_hornet.py`는 완료된 선택취득manifest의gzip/raw해시·행수를확인하고conn/수집손실/notice/stats를집계한다. 결측은0/false로채우지않고원문Decimal시각자릿수를KST표시에보존한다. 198파일/20,728행·10회귀·공개CLI/독립전수대조완료. [출처·파일manifest·검증](HORNET_EVIDENCE_REVIEW.json).

```sh
python3 -B finetuning/inspect_hornet.py --manifest /path/acquisition.json \
  --directory /path/selected-gzip --own-ip OBSERVER_IP \
  --output /new/path/review.json
```

동일observer의주소가여럿이면 `--own-ip`를반복한다. 주소는원제공README로확인하고게이트웨이를자기주소로추정하지않는다. 원장 `acquisitions`의선택manifest와같은파일을출처URL에서재취득해CRC/SHA를확인한다. 기존출력은덮어쓰지않는다. pack에는검사기/원장만포함하고원문·검토과제는학습에자동편입하지않는다.

손실률0/ACK0/Too_Little_Traffic192건이동시에있고drop0도전체수집완전성증명이아니다. 두ZIP목록에SSH로그가없다는사실은센서장애나정상판정근거가아니다. 공통유입출발지1,137개를분할검수에반영하며 개별공격/정상정답은생성하지않았다. 개발과제1개의질문/기준은프로젝트작성이고검토노출상태다. 새학습/모델호출0.

**DEDALE flow·결측값 검수:** `inspect_dedale_flows.py`는 Zeek 원문 필드·미설정 표지·물리 좌표를 유지하고 제공 분류표의 전체 원문 필드를 반복 횟수까지 대조한다. 868,616행 중864,636행 일치, 결측→빈칸/0 차이3,980행을 확인했다. 과학표기는 정확한 마이크로초만 허용하며 자동 반올림/결측 대체는 없다. 15검사·CLI 전수 재현/독립 전수 대조 완료. [원장](DEDALE_FLOW_REVIEW.json).

```sh
python3 -B finetuning/inspect_dedale_flows.py \
  --conn /path/conn.log --labels /path/conn_labeled.csv \
  --output /new/path/flow-comparison.json
```

CLI 종료 성공은 검사가 실행됐다는 뜻이다. `full_core_matches`·`unmatched_labels`·`unmatched_raw`를 반드시 확인하며 불일치를 자동 수리하지 않는다. 출력 덮어쓰기는 거부한다. `assess_session`/`ntp_request_observation`은 서로 다른 시계를 자동 합치지 않는 검토 함수다. 전체 재현은 원장을 기준으로 동일4멤버 CRC/SHA를 먼저 확인한다. 처리용 `#open/#close`와 offset 없는 CSV `date`를 원본 이벤트 시각으로 대신하지 않는다.

conn↔SSH UID/양끝은 일치하나 host 수락이 종료5.308222초 뒤여서 상관은 후보로 남는다. NTP stratum0 INIT의 약6.924초 차이는 검증된 보정값이 아니다. 개발 사례1개는 공식 시험기간·검토 노출 자료이며 제공 라벨은 입력에서 분리했다. 모델 호출/학습 편입0, 기관 공식 정답이나 새 독립 평가 성능을 주장하지 않는다.

**DEDALE 시각·중복 후속:** `compare_dedale_clocks.py`는 공식 고정 ZIP2개를 원본 syslog672시간/5,017,693행과 경보1,465,627행 전체로 대조한다. 비시간 필드를 유지하고 `@version`/`pid` 타입2개와 시각 정밀도만 명시적으로 맞춘다. 원문 UTC시각과 epoch-ms의 동일성을 확인했으며 반복 횟수는 제거하지 않는다. 신규11검사/CLI재현·별도 전수검증 통과. [결과/출처](DEDALE_CLOCK_REVIEW.json).

```bash
python3 -B finetuning/compare_dedale_clocks.py \
  --alerts-zip /path/suricata_alerts.zip \
  --syslog-zip /path/system_logs_syslog.zip \
  --output /new/path/clock-comparison.json
```

프로젝트 루트에서 실행하며 출력의 상위 디렉터리는 먼저 존재해야 한다. 네트워크 다운로드나 서버 변경 없이 지정 파일을 읽고, 고정 SHA가 다른 입력과 기존 출력 덮어쓰기를 거부한다. 성공 종료는 비교 실행 완료이며, `representation_verified=true`, `remaining_export_instances=0`, `counts.not_in_export_or_excess=0`도 확인한다. 전체 원문 MD5와 모든 ZIP/BZ2 멤버 완독을 검증한다. 해제 원문을 디스크에 쓰지 않고, 경보 다중집합 인덱스에는 메모리를 사용한다. 증거 파일은 로컬 전용 경로에 보관한다.

현재 고정 파일에는 `inspect_alerts(..., timestamp_unit='epoch-ms')`를 사용할 근거가 생겼다. 다른 입력에 대한 기본값 `None`은 유지한다. 19,703개의 정규화 반복 중9,520개는 동일 원문 객체 반복이고10,183개는 서로 다른 정밀 원문이다. 시각만 줄여 중복 제거하지 않는다. 학습 편입·호스트↔IDS 사건 연결은 별도 검수 대상이다.

**DEDALE IDS·호스트 후속:** `inspect_dedale_network.py`는 Suricata syslog 요약의 센서·통신 양끝·룰ID·경보 우선순위를 구분하고, 호스트 라벨의 명시적 연결 필드를 조사한다. 경보1,465,627행 전수/독립 재대조와12회귀를 통과했다. [검증 원장](DEDALE_CORRELATION_REVIEW.json). 사건 연계·학습 편입은0이며 작성자 저장소 MIT/GPLv3 표기 충돌을 기록했다.

호출은 `inspect_alerts(bounded_lines(stream), timestamp_unit=None)`와 `inspect_host_records(bounded_lines(stream), source=member)`를 사용한다. 입력 취득·ZIP CRC/제공MD5·용량 한도는 호출자가 검증한다. 시각 단위 계약 없이 정수를 변환하지 않으며, `epoch-ms` 옵션 테스트 통과는 실제 데이터 단위 확인을 뜻하지 않는다. `host_transport_tuple`은 명시적 TCP/UDP·양끝 주소/포트만 허용한다. DNS 답변/unspecified 주소/부분 주소·시각만으로 사건을 연결하지 않는다. 이 도구는 해당 공개 자료 진단용이며 범용 로그 수집기나 운영 차단기/학습기 아니다. pack에는 자체 검사 소스·원장만 추가하고 원본/작성자 코드/다운로드물은 넣지 않는다.

**DEDALE 원문 연계 후속:** `link_dedale_labels.py`는 제공 라벨과 원본의 전체 JSON을 대조하며 시간·호스트만 같은 다른 이벤트를 제외한다. 선택7구간6,188,928행·5,581라벨을 연결했고 별도 원시 JSONL MD57개도 일치했다. 12회귀/기존Range6검사 통과. 학습 편입0이며 공식 시험기간/검토 노출 경계를 유지한다. [검증 원장](DEDALE_LINKAGE_REVIEW.json).

검사기는 `index_labels`로 제공 라벨의 좌표·전체 객체 해시를 만들고 `scan_raw_member(bounded_lines(stream), ...)`로 명시적 시간 구간을 대조한다. 원본 취득은 기존 `remote_zip.RemoteZip`의 지정 범위 읽기를 사용했다. 스트림 EOF와 압축/제공 체크섬 확인은 호출자 책임이며, 부분 다운로드·전체 ZIP 무결성·원문 라벨 정답성의 범위를 구분한다. 후보/원본/대화는 자동 pack에 넣지 않고 검사 소스와 원장만 묶는다.

**출처 의미 검수 후속:** [Maastricht 원문 대조](../datasets/ATTACK_FLOW_SOURCE_REVIEW.json)는22개 제어 노드의 사건 설명·기법/맥락·불확실성을 구분한 검토 원장이다. 신규 학습 입력이 아니며 현재 후보17개/R8입력/모델은 그대로 유지한다. 기관 자료의 출처와 개별 정답의 정확성을 같은 것으로 보지 않는다.

**Attack Flow 참조 정제 후속:** 기존 액션 BFS 변환을 제거하고 원본41흐름의 조건·AND/OR·연결2,113개를 보존하는 별도 파서를 연결했다. 12검사와 전수 독립 대조를 완료했다. [사용법](../datasets/README.md) · [검증/출처/한계](../datasets/ATTACK_FLOW_GRAPH_REVIEW.json). 파생 그래프는 원시 로그나 SFT 정답이 아니며 학습 입력/pack에 자동 포함하지 않는다. 원본의 표시 없는 분기와 인용 보고서로 확인되지 않은 표현은 검토 대상으로 남긴다.

**원문 기반 입력 후보 검수 — 2026-10-30 KST:** `prepare_soc_observation_inputs.py`는 해시로 고정한 AIT9·Linux-APT8 조사 초안을 입력 후보17개와 별도 출처 원장으로 만든다. 근거94개를 보존하고 반복 필드를 묶는다. 과거 자료의 첫 사용자 입력 완전일치 검사는 수행하지만 의미상 독립성을 보증하지 않는다. 후보는 기존 학습 환경에만 속하며 새 최종평가로 쓰지 않는다. [결과·권리·한계](SOC_OBSERVATION_INPUT_REVIEW.json).

프로젝트 루트에서 새 출력 경로를 지정한다. 기존 결과를 덮어쓰지 않는다.

```bash
python3 -B finetuning/prepare_soc_observation_inputs.py --ait-dir finetuning/data-ait-case-review-20261030-r3 --linux-dir finetuning/data-linux-apt-cases-20261030-r2 --output finetuning/data-soc-observation-candidate-NEW
```

`check_soc_observation_tokens.py`는 Thor의 기존 Transformers 환경에서 고정 Qwen revision의 tokenizer만 로컬로 읽는다. 모델 가중치·GPU·학습·네트워크 다운로드를 사용하지 않는다. 전체 답변·학습 마스크·4096토큰 한도를 검사하며 초과 자료를 자르거나 조용히 제외하지 않는다. 검토 자료와 소스를 명시적으로 반입한 뒤 다음과 같이 실행한다. Mac에는 관련 패키지를 설치하지 않는다.

```bash
python3 -B check_soc_observation_tokens.py --candidate-dir /path/to/candidate --base-dir "$HOME/Capstone_Groot_training/qwen36-20261027/base" --base-manifest "$HOME/Capstone_Groot_training/qwen36-20261027/base-manifest.json" --output /new/path/token-check.json
```

실제 tokenizer 검사는 Thor 연결 시간 초과로 미실행이다. 합성 tokenizer를 포함한16개 입력 단위검사 통과와 구분한다. 이후 상단 R2에서 반복 답변의 사건별 근거를 보완했고, V4/V5 여섯 파일 대조·전체 업무 배합·독립 평가는 남았다. 학습 편입은0이다. pack에는 준비/검사 소스·테스트·원장만 추가하고, 이 후보 데이터와 원문은 자동 포함하지 않는다. 질문·해석은 프로젝트 작성이며 기관 공식 정답이 아니다.

이하 이전 준비·검수 이력이다.

**Linux-APT 관제 조사 초안:** `prepare_linux_apt_cases.py`는 고정 원장에 해시가 등록된 `01-05-October.csv`와 `06-20-October.csv`를 읽어 원문 69개에 연결된 초안 8개를 만든다. 파일 크기·MD5·SHA·행 수를 확인한 뒤 원문 좌표, 최소 관측값, 사례별 별칭, 프로젝트 작성 해석과 출처 고지를 보존한다. 누락과 상충 근거를 드러내며 시간대·공격 성공·도구 실행을 만들어 넣지 않는다.

```sh
python3 -B finetuning/prepare_linux_apt_cases.py --source-dir /path/to/verified-csv --output /new/local-review-directory
python3 -B -m unittest discover -s finetuning/tests -p test_linux_apt_cases.py -v
```

출력의 `cases.jsonl`은 검토 초안이며 바로 SFT에 넣는 파일이 아니다. 같은 경로를 덮어쓰지 않으며, 원문 누락·해시 차이·검토한 사실관계의 차이가 있으면 오류로 중단한다. 공개 pack에는 소스·테스트·원장만 추가하며 원문과 초안은 학습 입력에 자동 포함하지 않는다. [결과·검증·한계](LINUX_APT_CASE_REVIEW.json).

**전수 검증 결과 — 2026-10-30 KST:** 17 CSV·122,563행·208,367,683B의 MD5/크기 검증을 완료했습니다. 139개 구조 그룹에서 245개 좌표를 골랐고 아래 도구는 정답/대화 생성을 하지 않습니다. 시간대 미상 122,563행·full_log 공백 973행·룰 주석 24,779행의 한계는 [원장](LINUX_APT_EVIDENCE_REVIEW.json)에 있습니다. 아래887행은 앞선 부분 검토 이력입니다. 전체 원시 로그와 검토 좌표는 학습 pack에 자동 포함하지 않습니다.

**Linux-APT 원본 검토 도구:** `prepare_linux_apt.py`는 [고정 파일 목록](LINUX_APT_SOURCE_SPEC.json)의 CSV를 메모리에서 읽고 제공 MD5/크기, 중복 문서·레코드, 시각과 룰 주석을 확인합니다. 정상/악성 정답이나 SFT 대화를 생성하지 않습니다. 원문·명령·계정/주소를 복사하지 않고 파일/논리 CSV행/물리행/SHA 및 구조 코드만 보존합니다. 상세 원문 검수에는 해당 좌표를 다시 조회해야 합니다.

```sh
python3 -B prepare_linux_apt.py --spec LINUX_APT_SOURCE_SPEC.json --output data-linux-apt-review-NEW
```

전체 파일을 내려받아 보존하는 명령이 아니지만 원격 원문 바이트를 읽는 네트워크 전송은 필요합니다. 기존 출력 폴더는 덮어쓰지 않습니다. 완전히 검증한 파일마다 체크포인트를 남기며, 실패 원인을 확인한 후 같은 명령에 `--resume`을 추가하면 검증 완료 파일은 다시 읽지 않습니다. 소스 목록·검사기 코드·체크포인트 해시가 다르면 재개를 거부합니다. 실패한 실행은 완료본이 아니며 실패 파일의 부분 집계는 재개에 사용하지 않습니다. 오프라인 회귀는 `python3 -B -m unittest discover -s tests -p test_linux_apt_evidence.py`로 실행합니다. 고정 source-family 전체와 Mendeley/SecCoRA 파생본은 같은 분할로 유지하며, 현재 분류는 학습 후보일 뿐 실제 편입이 아닙니다.

**추가 실제 데이터 원천 — 2026-10-30 KST:** Linux-APT·DEDALE·CTU-SME-11·Hornet65·AuditBench를 조사했습니다. Wazuh CSV 887행과 DEDALE 라벨 ZIP의 무결성/한 멤버 10,593행 형식을 확인했습니다. [출처·용도·제약](DATA_SOURCES.md) · [파일별 검증](SOC_ADDITIONAL_DATA_REVIEW.json). 기관 자료의 원행 수를 학습 대화 수로 세지 않으며 신규 편입은0입니다. 원시자료를 pack에 넣지 않고 검토 원장만 포함합니다. DEDALE 공식 시험 분할과 OpTC 파생 중복을 보존하고, 이용 조건 미확인 AuditBench/SecCoRA 등은 편입 보류입니다.

**OpTC 원본 검사기 — 2026-10-30 KST:** [OPTC_EVIDENCE_REVIEW.json](OPTC_EVIDENCE_REVIEW.json)에 실제 prefix31,797행과 시각/부분입력 한계를 기록했습니다. `inspect_optc_evidence.inspect_prefix`는 gzip 시작부분 bytes와 원본 크기를 받아 완전/부분 입력을 구분합니다. `scan_records`는 JSONL iterator를 끝까지 읽고 제한된 메타데이터만 보존하며, 전체 파일 무결성은 호출 측의 별도 검증이 필요합니다. 두 함수 모두 악성 정답·학습 대화를 만들지 않습니다.

```bash
python3 -B -m unittest discover -s finetuning/tests -p test_optc_evidence.py
```

Mac/Thor 최종11검사 통과. 서버의 전체 스트림 시도는 제공자 quota로 종료됐고 목표 사건 연결/신규 편입은 미완료입니다. 원장·검사 소스를 pack 목록에 추가했으며 원문 표본/초안을 자동 학습 입력으로 넣지 않습니다. [출처와 한계](DATA_SOURCES.md).

이하 이전 검토·작업 이력이다.

**추가 원천 검토 — 2026-10-30 KST:** [SOC_SOURCE_ACCESS_REVIEW.json](SOC_SOURCE_ACCESS_REVIEW.json)에 CMU 이용 조건 충돌/상세파일1개 누락, LANL 양식 대기, OpTC 정답102타임라인 항목과 선택 로그 위치를 기록했습니다. 원문·대화/학습 개수를 구분하며 신규 편입0입니다. [출처/한계](DATA_SOURCES.md). 원장만 재현pack의 소스 목록에 추가했고 원문·검토 초안은 학습 데이터로 자동 포함하지 않습니다.

이하 이전 검토·작업 이력이다.

**AIT 관제 질문/답변 초안 — 2026-10-30 KST:** [AIT_CASE_REVIEW.json](AIT_CASE_REVIEW.json)에9구간·25원행·14교차참조와 근거/한계를 기록했습니다. 초안은 로컬 `data-ait-case-review-20261030-r3/`에 있으며 학습 데이터·반입pack에는 포함하지 않습니다. 원문 기반 사실과 프로젝트 작성 판단/후속 조사를 구분하고 기존 train 환경만 사용합니다.

`prepare_ait_case_review.py`는 이전 원격 결과의 content/SHA envelope, 공개 `AIT_GAP_LINKAGE.json`, 그 원장에 해시가 고정된 AMiner 분석 JSON을 입력받습니다. 새 output 경로에만 `review-cases.jsonl`, `manifest.json`, `SOURCE_NOTICE.txt`를 씁니다. 출처·변형·권리 고지는 재생성할 때도 자동으로 보존합니다. 공개 원장에는 원시 로그/초안 전문을 포함하지 않습니다.

```bash
python3 -B finetuning/prepare_ait_case_review.py --results /path/results-r2-final.json --report finetuning/AIT_GAP_LINKAGE.json --aminer /path/aminer-comparison-r2.json --output /new/review-directory
python3 -B -m unittest discover -s finetuning/tests -p test_ait_case_review.py
```

Mac CPU8검사·25원행 별도 대조·R1/R2초안 바이트동일 확인. Thor 실행/전체pack·모델 평가/새학습은 이번 범위 밖입니다. 원문 쿼리 인수·전체 명령은 파생 투영에 복사하지 않으며 원문 좌표/SHA를 남깁니다. [출처·이용 범위](DATA_SOURCES.md).

이하 당시 이력입니다.

**원시 로그/라벨 연계 — 2026-10-30T01:46:51.694593+09:00:** [AIT_GAP_LINKAGE.json](AIT_GAP_LINKAGE.json)에5환경40쌍·원문1,942,943행/라벨623,514행의 연결 근거를 기록했습니다. 9경보0구간의7개는 제공자 라벨 근거/2개는 성공 미확정입니다. AMiner 관측과 학습모드도 분리했습니다. [출처·권리·집계 한계](DATA_SOURCES.md).

`link_ait_labels.link_pair`는 열린 원문/라벨 스트림을 순서대로 대조하며, 원문·라벨 SHA/행 좌표/제한된 검토 표본을 반환합니다. 실제 로그 헤더/명시 시각만 해석하고, 잘못된·중복·범위 밖 라벨은 실패시킵니다. 라벨 부재를 정상으로 바꾸지 않으며 질문·답변/도구 호출이나 학습을 생성하지 않습니다. 원격 범위 취득은 기존 `remote_zip.RemoteZip`를 사용했고 실행 코드/입력 SHA와 결과는 Thor의 별도 검토 폴더에 보존했습니다.

```bash
python3 -B -m unittest discover -s finetuning/tests -p test_ait_label_linkage.py
```

Mac/Thor CPU8검사와 실제 원문 전수 R2대조를 완료했습니다. 소스/검증 원장은 반입 allowlist에 포함하며,원자료/표본은 자동 학습 입력에 넣지 않습니다. 전체pack 생성/운영 봇·새 서버 설치 시험은 이번에 하지 않았습니다.

이하 당시 이력입니다.

**AIT 증거 준비 — 2026-10-30T01:11:08.558457+09:00:** 학습6환경의 원경보1,371,021행을 대조해 고유 원본450개/검토66묶음을 준비했습니다. 파싱 오류0·중첩585행·관측0 구간9개를 명시합니다. 원행/객체/단계/KST 독립 대조와 회귀9개 통과. [원장](AIT_EVIDENCE_REVIEW.json) · [출처/제약](DATA_SOURCES.md). 감독학습 대화·원시 LDS 연결·사건 정답 검수는 아직 전입니다.

기존 자료로 재현할 때는 새 출력 경로를 지정합니다. 의존성 설치·모델 호출·네트워크 요청이 없으며 기존 train/validation/test나 이전 산출물을 덮어쓰지 않습니다.

```bash
python3 -B finetuning/prepare_ait_evidence.py \
  --archive datasets/raw/ait-ads/ait_ads.zip \
  --labels datasets/raw/ait-ads/labels.csv \
  --split datasets/processed/ait/split.json \
  --output finetuning/data-ait-evidence-review-NEW --samples 12
python3 -B -m unittest discover -s finetuning/tests -p test_ait_evidence.py
```

추출 소스·검사·검증/후보 원장은 반입 allowlist에 포함했으며 원경보·검토 묶음은 자동 반입하거나 학습 입력에 섞지 않습니다. 이번에는 Thor 반입 및 전체 pack 생성 검증을 수행하지 않았습니다.

이하 당시 이력입니다.

**추가 관제 데이터 후보 — 2026-10-30T00:57:16.287495+09:00:** 신규 직접 도입3종(LANL·OpTC·BOTS)과 기존 확장2묶음(CMU CERT·AIT)을 조사했습니다. [출처·정답/권리 한계](DATA_SOURCES.md) · [후보 원장](SOC_DATA_CANDIDATES.json). 정답과 로그 문맥을 묶고 새 독립 평가를 분리한 뒤 학습안을 검토합니다. 신규 원시자료/정제/학습 편입0이며 기존 R8 입력·모델 선택은 변경하지 않았습니다.

이하 당시 이력입니다.

**최종 비교 완료 — 2026-10-30T00:40:22.883444+09:00:** R8 후보는 등록·실제추론이 가능하지만 미사용128문항에서 F1/누락/형식이 미학습 비교본보다 나빠 운영 승격하지 않는다. 기존35B/context262144의 실제응답/registry 복구 검증 완료. 후보·가중치·출처·실패/복구자료를 보존한다. 이미 실행한128개를 다시 미사용 시험이라고 하지 않으며 새 개선안은 별도 미사용 평가가 필요하다. [최종 비교표](V5_COMPARISON.md) · [실행 원장](V5_EXECUTION_RESULTS.json) · [현황](../STATUS.md).

이하 당시 이력이다.

**후보 등록 완료 — 2026-10-30T00:24:05.048706+09:00:** R8 병합/변환·최종SHA 검증 뒤 `soc-qwen36:35b-evidence-v5-q4km-20261029`를 평가용으로 등록했다. 기존35B/봇 선택은 유지한다. 첫 개발 비교의 후보 적재 시간 초과 후 자체 비교 모델을 순차 해제하도록 수정했고32×2 재시험/원모델복구를 완료했다. 엄격완전/누락은동일·F1은소폭개선으로 미사용test128×2 진행 중이며 운영 승격은 하지 않았다. [비교·실패 보존 기준](V5_COMPARISON.md) · [실행 원장](V5_EXECUTION_RESULTS.json) · [현재 상태](../STATUS.md).

이하 당시 이력이다.

**R8 완료 — 2026-10-29 23:12 KST:** 전체1,024관측/512단계·1epoch 완료, 원자료 lineage·380개 유한 텐서/190LoRA쌍을 검증했다. 기존35B는23:10 자동복구되고 원digest/실제응답을 재확인했다. 어댑터는 Thor `~/Capstone_Groot_training/qwen36-20261027/outputs/soc-v5-train/adapter/`에 보존한다. 병합/GGUF후보·운영 전환·최종 품질 비교는 미실행이며 완료된 실행을 재시작하지 않는다. [실행·복구 결과](V5_EXECUTION_RESULTS.json) · [현황/남은 작업](../STATUS.md).

아래 실행/재현 절차와 진행 문구는 해당 시점의 이력이다.

**R8 본 학습 진행 중:** 2026-10-29T18:08:24.204147+09:00 KST부터 원격독립 systemd/Docker로1,024건/512-step 실행. 예상완료 23:36 KST, 원35B자동복구·5시간후서버진행기록을설정했다. 이전R7동결은별도보존하고새프로필/참조를고정했다. [원격실행/확인](EVALUATION_REPRODUCTION.md) · [현재상태](../STATUS.md).

아래는 과거 기록이다.


**최신 재현 시험:** 실제8회 반복평가와 독립2-step 두 실행을 마쳤다. 결정적 프로필에서 380텐서/어댑터SHA 및 train/eval loss가 정확히 일치하며 원35B를자동복구했다. 관제 품질향상·전체학습 완료를 뜻하지 않는다. 본 학습은 예상5h28로 기존4h30승인을 초과해 새 입력 동결/중단 계획이 필요하다. [절차](EVALUATION_REPRODUCTION.md) · [결과](V5_REPRODUCTION_RESULTS.json) · [현재 상태](../STATUS.md).

아래는 과거 기록이다.


> **2026-10-29 r7:** 사용자4h30승인으로재개한2-step은완료했으나train_loss동일/eval_loss차이로본학습전에중단하고16:43:23KST원35B를자동복구했다. 입력/가중치·평가재현성점검이남아있으며허용치완화/본학습완료로대신하지않는다. FW MCP는양쪽실조회검증완료이며 [실제상태/Git](../STATUS.md)를따른다.

**현재: 학습 실행 보류·계획만 정리.** 사용자 지시로 재개 작업을 중지했고 기존35B를13:21:19KST복구했다. 본 학습은 미시작이며 학습 컨테이너/활성 복구타이머는 없다. Thor 학습 차단은 원복 상태를 유지하고, 다음 재개 지시가 있을 때만 원래설정의 시험→1024개1epoch/512step→복구/검증→후보비교·적재를 진행한다. [실행 계획](../PLAN.md) · [현재 상태](../STATUS.md).

이하 내용은 과거 시점의 기록이다.


**V5 실행 최신:** 원래 설정의 2-step 시험은 완료했으나 전체 학습 예상이 약3시간48분으로 기존 승인시간을 넘어 본 학습은 미시작이다. 재계산 해제안은 검증손실 차이/시간이득 미확인으로 제외하고 원래 설정으로 되돌렸다. 기존35B복구·실제중단합계약6분52초. 승인된이전HF26shard66.97GiB정리완료(base/adapter/설정·기존Ollama보존)·실제CPU276검사통과. **기존중단포함총4시간30분 연장안은 검토 준비만 완료했고 새승인전실행차단**한다. [시험·가중치·원천투입/한계](V5_EXECUTION_RESULTS.json) · [상세 현황](../STATUS.md).

이하 내용은 과거 준비·진행 시점의 기록이다.


**10/29 V5 신규 준비:** MITRE·CISA 원문 관측/제공자 정답으로 **1,280건(학습1,024/검증128/시험128)**을 별도 정제했다. 자체 사건 시나리오0건이며 질문·출력 형식은 프로젝트 작성이다. 출처1,324행 대조·보고서/주체 분할·재생성4해시·전체 토큰 보존을 확인했다. 이 자료는 **역사적 CTI 기법 매핑**용으로, 관제 업무 전체 숙련이나 독립 전문가 인증을 뜻하지 않는다. **GPU 학습·새 후보 등록은 아직 없다.** 기존 자체308 포함520건 및 R3/R4 학습 보류는 유지한다. [V5 준비·한계](V5_DATA_PREPARATION.json) · [최신 현황](../STATUS.md).

아래는 시점별 준비·검증 이력이다.


**후속 정정 2026-10-29T04:16:44.348253+09:00:** 자체작성308/520(59.23%)은 기관이 검증한 정답이 아니다. CPU/토큰/호출·출처 검사는 답변 의미의 독립 검수를 대신하지 않는다. 520건은 준비본 수로만 보존하고 학습 투입 확정에서 제외한다. 사용자 지시에 따라 외부 기관·학술 원천 및 공식 실제 사고 자료를 추가 수집하고, 자체작성 비중을 줄인 새 corpus/근거 검수를 먼저 수행한다. R3/R4 신규 학습은 실행 제어기에서 보류한다. [검수 상태](V4_DATA_REVIEW.json).


> **10/29 기관/직무 연계 전체 학습 준비:** 원격참조 AIT-LDS 행라벨·CISA·NIST/ENISA직무·실제 IDS 재조회를 포함해**332/94/94=520사례**. 실제tokenizer/Torch CPU검증으로 모든assistant턴766/202/202보존·학습입력중복57.9%감소(속도/품질향상 미검증). 전체1epoch/166step·독립복구 준비·GPU학습/운영전환미시작. 이후FW전체읽기MCP→복구가능한하네스정리→2x2비교로우수구성선택. [자료·한계](DATA_SOURCES.md) · [실제진행](../STATUS.md).

> **10/29 SOC 업무용 R3 준비:** 8개 관제 workflow+출처 연결 AIT 아카이브로264/60/60건을 준비했다. 원경보192개 대조·CPU696/168/168prefix 전부 보존/최장2710토큰·운영MCP37도구 계약일치 확인. ToolACE는 보조 후보로만 정제하고 핵심 혼합에서 제외했다. 개발 순차 평가/중단·복구 준비를 진행하며 새 GPU학습/후보적재/운영전환은 아직 없다. [자료·출처·검증한계](DATA_SOURCES.md).

> **10/29 과거 학습 출처 정리:** 12실행·3corpus/9분할SHA·AIT112원본행을대조하고BibTeX/기계판독이력표를연결했다. 초기혼합자료는일부2-step시험만,v1은AIT+합성,R2는합성이며준비량/실제학습량을분리한다. 과거batch ID/일부취득revision미기록도공개한다. [논문용출처·정정·검증한계](DATA_SOURCES.md). 추가반입분정제/새학습은이후단계다.

> **10/29 추가 자료의 학술·기관 근거 확인:** AIT/CSET·ToolACE/ICLR2025·APIGen/NeurIPS2024·PRIMUS/EMNLP2025와 MITRE/NIST 공식 자료를 확인했다. 기존ToolACE SHA/AIT MD5 3검사일치. 현재R2 192개는내부에이전트검수합성자료로기관인증/전문가정답이아니다. 새반입/학습/운영전환없음. [원출처·인용·검증/한계](DATA_SOURCES.md).

> **10/29 품질 비교 완료:** 새20사례·41턴/모델·37도구 동일조건에서 HF 미학습control84점, R2 24/48각76점, 운영 원본73점. 학습효과는같은HF대비각8점하락으로운영원본유지. 전체164요청성공·누락/장비추측·가짜ID잔여·실MCP/채팅/경고인과별도. [점수·사례·한계](QUALITY_RESULTS.md).

> **10/28 실제 시험 범위:** SSH만 가능해 진단 드라이버는 미로딩. 기존 native/dense2-step에서 원0x51 1건을 재현했으나 학습정상/원35B 2분48초복구·화면/드라이버유지다. 가중치finite/훈련손실동일은확인했지만 평가·가중치차이와 경고의 인과/정확도영향은미확정이다. 추론짧은3건정상/추가경고0·실SOC E2E미시험. [최신 근거·미완료](../STATUS.md). 아래는 이전 이력이다.

> **10/28 빌드/호환 전제 확인:** 공식검증 GCC13.2 격리 재빌드로 compiler mismatch0·입력444/출력96·추가의존입력79 CRC일치 확인. 현서명정책에서 unsigned 자체는 차단요인이 아니며 정책변경0/운영원35B유지다. 실제모듈적용·원래0x51 재현/해결은 미완료. [검증·적용 경계](driver-diagnostics/README.md). 아래는 이전 이력이다.

> **10/28 드라이버 후속 준비:** 실패 인자를 기록할 진단 패치/고정 소스 검증기와 Thor 격리 모듈 빌드를 완료했다. 원래0x51 해결·운영 적용은 미완료다. 컴파일러 차이/서명·의존 ABI 검증과 유지보수 환경이 남아 있으며 운영35B는 가동 유지했다. [범위·후속 조건](driver-diagnostics/README.md). 아래는 이전 이력이다.

> **10/28 드라이버 후속:** 복구된 연속 메모리/CPU THP 요청 실패를 확인했으나 원래0x51 분기는 미확정이다. native35B 1-step도 경고0이어서 이전12→0의 인과 확정과 메모리peak 감소를 구분한다. 프로파일러 원문은 훈련0x51 73건+다른 상태 오류1건/복구후0건으로 정정했다. 원35B 복구·전용 진단 정리 완료. [실측·제약·최신 정정](THOR_35B.md). 아래는 시점별 이력이다.

> **10/28 메모리 개선 완료 범위:** 같은35B2-step에서 경고12→0건·GPU최대할당70.37→66.87GiB, 정답누락0을확인했다. 검증한VMM/선택loss를후속학습기본값에반영·기존35B18:36:27KST복구. 긴본학습/드라이버원인완전규명은별도다. [현황·Git](../STATUS.md) · [근거·한계](THOR_35B.md).

> **10/28 잔여 경고 개선 준비:** log-softmax 역전파와 경고 시각이 겹침을 확인했다. 문맥·정답을 보존하고 정답 위치만 어휘 점수를 계산하는 수정안의 실제 손실/전체기울기·Trainer 누적/평가3검사 통과. 35B2-step 확인은 후속이다. [현황](../STATUS.md) · [근거](THOR_35B.md).

> **10/28 VMM 실제 비교:** 같은2-step에서 메모리 경고12→3건·추론2분54초복구. 첫 학습 연산에3건이 남아 미해결이며 CPU연산시각 추적 경로/163검사를 준비했다. [최신현황](../STATUS.md) · [근거](THOR_35B.md).

> **10/28 경고 개선 비교 준비:** Thor595.78 공식 소스에서 할당 실패 후 작은 페이지 재시도 경로를 확인했다. 최대2GiB 기본/VMM 시험은 성공·경고0, 로컬/Thor160검사 완료. 별도2-step VMM 비교를 준비했으며35B에서 개선 여부는 아직 미확정이다. [최신 현황](../STATUS.md) · [근거·절차](THOR_35B.md).

> **10/28 메모리 재현 완료:** 같은 커널 할당 경고 12건을 재현했다. 2-step은 정상 종료(OOM 종료0), 기존35B는 17:08:17 KST 복구·중단2분52초. 정확한 할당 원인은 미확정이며 추가 본 학습/모델 전환은 진행하지 않았다. [최신 결과](../STATUS.md) · [수치·제한](THOR_35B.md).

아래 항목은 당시 진행 이력이다.

> **10/28 메모리 재현 준비:** 최장2입력·2-step 전용경로/별도기록·자동복구를준비하고155검사·실서버무중단check를통과했다. 공유추론중단범위확인후실행하며현재GPU시험/중단은시작전이다. [최신상태](../STATUS.md).

> **10/28 메모리 점검:** 현재추론가동/가용약85.7GiB·오늘OOM종료0. 학습50+모델적재2건 경고의 정확한원인은미확정이며새단계별메모리진단을추가·로컬/Thor150검사/CPU컨테이너검증을완료했다. 실제GPU재현은별도승인실험에서확인한다. [근거·진단기록](THOR_35B.md).

> **10/28 R2 비교 마감:** 기존 회귀의 호출13/16→16/16·필드29/36→36/36 회복. 새 질문은 원본 우위가 입증되지 않았고 누락·잘못된 대상이 남아 운영35B를 유지한다. 최종/회귀 완료·실제MCP/E2E 미실행·후속과 [세부 근거](R2_RESULTS.md)를 구분한다.

> **10/28 개발 비교 완료:** 두 후보 등록·원본/control/24/48 개발 비교를 끝냈다. 필수 도구27/30이 남아 운영 모델을 유지하며,24-step 사전 선택 후 미사용 최종·기존 회귀 시험 중이다. [실제 결과·제한](R2_RESULTS.md).

> **10/28 평가 정정:** 정확한 시간 단위 환산과 선택적인 ID 재출력을 인정하고 HTTP 실패 분모를 보존한다. 로컬138검사 통과; 서버 생성 작업은 기존 frozen 기준을 완료한 뒤 모든 원문에 동일하게 재판정한다. 개발/최종/회귀와 실제 MCP·운영 승격을 구분한다. [STATUS](../STATUS.md).

> **10/28 R2 학습 완료:** 2-step→48-step·65validation과가중치검증을완료했고기존35B를11:40KST자동복구했다(중단38분16초). CPU24/48checkpoint비교준비중이며응답개선/운영교체는미검증이다. 드라이버메모리경고50건과실제검증·미완료범위는[STATUS](../STATUS.md)를따른다.

> **10/28 R2 학습 중단 승인:** 최대60분/자동복구승인을받았으며최장2prefix(1664·1582토큰) smoke 준비·로컬/Thor123검사를완료했다. 원base2-step→48-step/45분제한·50분독립복구·기존35B유지로진행한다. [실제진행·Git](../STATUS.md).

> **10/28 재개 확인:** R2 자료/strict520prefix·122검사 준비와개발65턴응답은완료했다. 원35B정상·새학습/window/timer실행없음을재확인했으며2-step→48-step GPU실험은새공유추론중단시간대확인후진행한다. 실제점수향상·운영교체와[완료범위/Git](../STATUS.md)를구분한다.

> **10/27 SOC 개선 R2 검증 완료:** 실제 다음 자료는 `data-soc-v2-r2`·192/32/32대화다. Thor2048토큰에서390/65/65prefix 전부 보존·로컬/Thor122검사 통과, operator 복구 제어기 준비를 완료했다. 원base lr5e-6/2-step→48-step 비교는 새 공유 추론 중단 승인 후 진행하며 아직 학습/점수개선/운영전환은 없다. [현재 근거와 실행 계획](../STATUS.md).

> **10/27 SOC 개선 v2 준비:** 합성 train192/개발32/최종test32·390/65/65prefix,19종 도구 예시와 문장틀 분리를 구현했다. 로컬115검사 통과·Thor CPU 토큰 검증 진행 중이며 새 학습/점수 개선·운영 전환은 아직 없다. 자료 생성/반입·개발 평가·별도2-step/48-step 경로와 [정확한 검증·후속 범위](../STATUS.md)를 따른다.

> **2026-10-27 21:47 KST 학습 개선 점검:** 로컬 train144대화의 실제 호출 예시는37도구 중7개이며 합성 질문의 형태 반복과 일부 능력의 train 예시 부재를 확인했다. 원인 확정/점수 개선 실측은 아니다. 새 검수 자료·독립 개발/미사용 평가·base부터 낮은 학습률/짧은 업데이트 비교를 준비하는 방향이며 이번 서버 중단·재학습·모델 변경은 없다. [완료 범위와 후속](../STATUS.md).

> **10/27 21:40 SOC 비교 마감:** 본 학습224prefix/112-step·HF/GGUF 내보내기와 별도 모델 등록을 완료했다. 동일 HF 미학습본/학습본의 필요한 도구 호출은16/16→13/16, 요청 필드 최종 답변은36/36→29/36으로 퇴행해 이번 학습본은 운영 적용에서 제외한다. 기존35B는20:41 KST 복구/21:38 재확인했고 봇 선택은 유지했다. 저장 위치는 Thor `~/Capstone_Groot_training/qwen36-20261027`이다. 실제 토크나이저320prefix 검사 통과, 원인 확정·재학습·MCP/채팅/보호 E2E는 후속이다. 아래 시점별 진행 기록과 [최신 결과·검증 범위](../STATUS.md)를 구분한다.

> **10/27 20:54 SOC 본 학습 완료:** Thor `~/Capstone_Groot_training/qwen36-20261027`에서224prefix1epoch/112-step·검증·어댑터저장·전체HF내보내기를완료하고기존35B추론을57분37초만에복구했다.380tensorfinite·MTP19보존/93검사통과.동일HF 미학습GGUF는별도등록/52턴응답확인,학습본GGUF/등록·비교는진행중이다.운영봇교체와MCP/채팅/보호E2E는미실행이며 [상세현황](../STATUS.md)을따른다.


> **10/27 추가 학습자료 조사:** 한국어 도구 호출·보안 업무자료와보안특화8B·동일35B파생가중치14후보를검토했다. 우선순위는보유SOC경보/실제요청검수→방어과제→소량한국어보조이며평가원천·중복·과잉질문회귀를구분한다. 반입/학습/운영모델변경은미실행이다. [후보·선별근거](DATA_SOURCES.md) · [현재현황](../STATUS.md).

> **10/27 18:00 학습 재개 결과:** CPU 파일 참조 누적으로 발생한35B 적재 메모리 문제를 보완해 실제2-step·평가·어댑터 저장까지 완료했다. 380텐서 finite/190 B행렬 갱신,78검사 통과. 추론은약2분56초만에 원래35B로 복구했다. 본 학습·변환/등록·운영 교체·SOC 정확도 비교는 미실행이며,현SOC 자료 보완과 장기 학습 시간대 결정이 남는다. 아래 정지/0step은 당시 이력이다. [상세 현황](../STATUS.md) · [적재 보완](THOR_35B.md).

> **2026-10-27 16:23 사용자 요청으로 일시정지:** 원본39파일 전체 체크섬·실토큰 검사 완료, 실제35B 적재 중 global OOM으로0/2step 종료. 추론은약81초만에 복구됐고 자동 대기 작업/timer는 종료됐다. 학습된 어댑터는 없으며 로더 메모리 peak 원인 분석/수정에서 재개한다. [현재 상태](../STATUS.md).

> **2026-10-27 실행 준비 진행:** Thor 기존 NGC25.08/별도 venv에서 패키지 검사·축소40층 LoRA GPU 역전파를 통과했다.71검사 통과. 전체35B 원본 다운로드 중/실토큰 검사 완료이며 메모리 확보 후2-step/본 학습을 진행한다. 전체35B 학습·학습 모델·운영 전환은 아직 없다. [Thor 실행 절차](THOR_35B.md) · [최신 상태](../STATUS.md). 아래 설치/반입 미실행은 과거 시점이다.

> **2026-10-27 현재35B/thor용 준비 추가:** [THOR_35B.md](THOR_35B.md)에 별도 BF16 LoRA 설정·전용 로더/자원 검사·설치 경로·현행 MCP 계약/자료 검사를 추가했다. 기존30B 기본 설정과 데이터는 보존하며35B는 `--config config.qwen36-thor.json`으로 선택한다.61검사 통과, 실제 GPU 학습은 미실행이다. 아래30B 준비 완료가35B 학습 완료를 뜻하지 않는다.

> **2026-10-27 로컬 재확인:** `data/`의 train18,872/validation980/test932행과 manifest SHA가 모두 일치한다. 학습·병합·평가 코드와 기존 `bundles/soc-finetuning.tar.gz`가 남아 있다. 설정은 여전히 `Qwen/Qwen3-30B-A3B`이며 현재 thor-05 운영 `qwen3.6:35b`와 다른 후보다. 이 폴더에 학습된 어댑터/가중치는 없다. 현재 MCP37도구/8서버에 맞춘 SOC trajectory 검수·대상 GPU 학습 호환 검사는 별도이며, SSH 연결·추론 성공을 학습 완료로 해석하지 않는다. 이번 확인에서 설치·다운로드·업로드·학습은 하지 않았다. [현재 상태](../STATUS.md).

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 기존30B LoRA 준비 데이터는 train18,872/validation980/test932개이며10/24 로컬 행 수·SHA 대조가 일치했다. 운영35B와 다른 후보이고 GPU 학습/실모델 비교는 아직 없다. 공개 corpus·지식·독립 평가·우리 SOC 검수 trajectory의 역할을 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

이 폴더를 충분한 메모리의 **Linux NVIDIA GPU 학습 장비**로 옮겨 실행한다. 로컬 Mac에서는 데이터 정제·코드 검증만 했으며 모델 다운로드·패키지 설치·학습·서버 업로드는 하지 않았다. 실제 GPU 학습과 병합은 대상 장비에서 아직 검증해야 한다.

기본 베이스는 **`Qwen/Qwen3-30B-A3B`**다. 총 30.5B·활성 3.3B인 공식 Qwen3 모델을 30B 후보의 준비용 기본값으로 골랐다. 현재 운영 중인 **`qwen3.6:35b`와 다른 모델**이다. 사용자가 정확한 30B 저장소명을 지정한 것은 아니므로 다른 후보를 쓰려면 `config.json`의 모델·revision과 LoRA 대상 모듈·템플릿 호환성을 함께 확인한다. 모델 이름만 바꾸면 모든 아키텍처가 지원된다고 보장하지 않는다.

**2026-10-08 실제 준비 결과:** 입력 120,917행에서 정제·소스별 상한을 적용해 20,784행을 선택했다. train 18,872 / validation 980 / test 932이며, 분할 사이 동일한 첫 사용자 질문 중복은 0이다. Hermes FC·Glaive·SEVENLLM·AttackLM 각 5,000행, Hermes traces 784행이다. 이는 토크나이저를 적용하기 전 수량이다.

## 포함 내용

| 파일 | 역할 |
|---|---|
| `data/train.jsonl`, `validation.jsonl`, `test.jsonl` | 기존 `datasets/`에서 정제·분할한 실제 데이터. Git에서는 제외 |
| `data/manifest.json`, `preparation_summary.json` | 입력/출력 SHA256, 출처별 개수, 제외 이유, 분할 정책. 후자는 Git 추적용 사본 |
| `prepare_data.py` | 표준 라이브러리만 쓰는 데이터 재생성기 |
| `config.json` | 베이스 모델·길이·학습률·LoRA 등 설정 |
| `setup_gpu.sh`, `requirements.txt` | 대상 Linux GPU 장비의 전용 가상환경 설치 |
| `train.py` | 데이터 검사, GPU 사전 검사, 명시적 학습 실행 |
| `merge_adapter.py` | 학습 완료 어댑터를 원본과 병합해 전체 모델 저장 |
| `evaluate.py` | 준비된 추론 API에서 같은 평가 입력을 재생하는 비교 도구 |
| `pack.py` | 코드·정제 데이터만 넣는 이관용 압축 파일 생성 |
| `DATA_SOURCES.md`, `tests/` | 출처·데이터 사용 범위와 로컬 검증 테스트 |

## 1. 이관하기

작업 폴더에 있는 `finetuning/` 전체를 복사하면 정제 데이터도 함께 이동한다. **Git clone만으로는 `data/`가 전달되지 않는다.** 가중치·환경·캐시를 제외한 묶음이 필요하면 프로젝트 루트에서:

```bash
python3 -B finetuning/pack.py
# finetuning/bundles/soc-finetuning.tar.gz 생성; 기존 파일은 덮어쓰지 않음
```

대상 학습 장비에서 압축을 풀고 `finetuning/`으로 이동한다. 이미 만들어진 `data/`로 학습할 때는 원본 `datasets/`를 다시 옮길 필요가 없다. 데이터를 **재생성**하려면 원본의 지정된 5개 파일과 평가 중복 차단용 파일들도 필요하다.

## 2. 대상 장비 환경 준비

Python 3.10~3.12(권장 3.11), NVIDIA CUDA GPU **1개**, 해당 PyTorch와 호환되는 드라이버를 사용한다. 기본 설정은 길이 2,048·마이크로 배치 1의 NF4 4비트 LoRA다. 준비 장비는 **GPU 메모리 48GB 이상을 보수적인 출발점**으로 고려하되 실행 보장값은 아니다. 30B MoE의 비양자화 층·활성값·학습 상태가 추가되므로 아래 소규모 실행으로 최대 메모리를 확인한다. 다중 GPU 분산 학습은 별도 설정이 필요하다.

일반 Linux x86_64:

```bash
cd finetuning
export CUDA_VISIBLE_DEVICES=0
bash setup_gpu.sh
source .venv/bin/activate
python -B train.py --check
```

설치 스크립트는 macOS에서 즉시 종료한다. Linux에서는 이 폴더 아래 `.venv/`, `.cache/`를 사용한다. PyTorch 2.8.0/cu128과 고정한 Transformers·PEFT·Accelerate·bitsandbytes를 설치하고 `pip check`, CUDA/NF4 커널 검사를 수행한다. 사전 검사 자체는 모델을 내려받거나 학습하지 않는다. 패키지 배포 메타데이터는 확인했지만 이 조합을 실제 GPU에서 통합 검증한 것은 아니다.

**ARM64·DGX Spark**는 제조사가 제공하는 CUDA PyTorch 환경을 먼저 준비하고 다음 경로를 사용한다. 기존 환경에 다른 패키지 충돌이 있거나 bitsandbytes 커널이 지원되지 않으면 사전 검사에서 멈춘다. 128GB 통합 메모리를 일반 GPU의 전용 VRAM과 동일하게 계산하지 않는다.

```bash
export CUDA_VISIBLE_DEVICES=0
bash setup_gpu.sh --use-system-torch
source .venv/bin/activate
python -B train.py --preflight
python -B train.py --check
```

두 설치 경로 모두 인터넷이 필요하다. 외부망이 없는 학습 장비에서는 동일 플랫폼의 승인된 경로로 wheel·원본 모델을 반입한 다음 전용 환경을 구성한다. `config.json`의 `model_name_or_path`를 **완전한 로컬 모델 폴더**로 바꾸고 `--offline`을 사용하면 Hugging Face 다운로드를 시도하지 않는다. 이번 준비 작업에는 이러한 반입·서버 업로드가 포함되지 않는다.

## 3. 먼저 2-step 실행, 이후 본 학습

아래부터 실제 모델 다운로드와 GPU 학습이 발생한다. **대상 학습 장비에서만 실행한다.** 기본 모델 캐시도 `.cache/huggingface/`에 둔다. 여유 디스크는 원본 가중치·다운로드 캐시·체크포인트·선택적 병합본까지 고려한다.

```bash
python -B train.py --train \
  --max-steps 2 --max-train-samples 32 --max-eval-samples 8 \
  --output-dir outputs/smoke

# 소규모 실행이 성공한 뒤, 새 출력 폴더로 본 학습
python -B train.py --train
```

`config.json` 기본값: 1 epoch, 길이 2,048, 배치 1 × gradient accumulation 16, learning rate 1e-4, LoRA r=16/alpha=32/dropout=0.05. LoRA 대상은 attention의 `q_proj/k_proj/v_proj/o_proj`다. MoE expert를 포함한 모든 선형층을 튜닝하는 설정은 아니다. 별도 속도/정확도 실측 후 조정한다.

원본 대화의 **각 assistant 턴까지의 이력을 개별 예제로 펼친다.** 각 예제에서는 마지막 assistant만 loss에 포함하고 앞선 user·system·tool·assistant 이력과 padding을 마스킹한다. 이렇게 대화 중간의 도구 호출과 도구 결과를 읽은 답변도 학습한다. 분할은 확장 전에 원본 질문 그룹별로 고정하므로 같은 대화의 턴이 train과 test에 흩어지지 않는다. 원본의 명시적 think 블록을 제거하고 non-thinking 템플릿을 사용한다. 긴 예시는 잘라서 툴 대화를 손상시키지 않고 통째로 제외하며, 정확한 토큰 길이/제외 개수는 대상 장비의 `tokenization_report.json`에 남긴다. 지금 준비된 원본 행 수가 최종 학습 예제 수와 같다고 가정하지 않는다. `max_train_samples`/`max_eval_samples`는 확장·길이 검사 후 채택한 예제 수를 제한한다.

출력 폴더가 이미 차 있으면 중단한다. 실패한 실행도 보고서를 남길 수 있으므로 재시도에는 새 `--output-dir`를 지정한다. 현재 스크립트는 자동 재개를 지원하지 않는다. `run_manifest.json`에는 데이터 해시·실제 베이스 revision·설정·패키지 버전·장비 정보를 저장한다. `revision: main`은 학습 시점에 해석되므로 반복 실험은 기록된 commit으로 고정한다.

## 4. 학습 결과는 어떤 파일인가?

기본 산출물은 전체 모델이 아닌 **LoRA 어댑터 폴더**다.

```text
outputs/qwen3-30b-soc-lora/
├── run_manifest.json
├── tokenization_report.json
├── train_results.json / eval_results.json
└── adapter/
    ├── adapter_model.safetensors   # 학습된 변경 가중치
    ├── adapter_config.json
    └── tokenizer 관련 파일
```

어댑터만으로는 독립 실행할 수 없다. **학습 때 사용한 동일한 원본 모델 + 어댑터**가 필요하다. 나중에 교수님께 전달할 때 어댑터·run_manifest·평가 결과와 정확한 원본 모델명/revision을 함께 보관한다.

원본과 합친 전체 모델 폴더가 필요하면 충분한 CPU RAM 또는 GPU 메모리의 장비에서:

```bash
python -B merge_adapter.py --check \
  --adapter outputs/qwen3-30b-soc-lora/adapter

python -B merge_adapter.py --merge \
  --adapter outputs/qwen3-30b-soc-lora/adapter \
  --output outputs/qwen3-30b-soc-merged
```

기본 병합은 CPU·BF16이며, 30.5B 가중치만 약 61GB(10진)이고 병합 작업용 메모리가 추가된다. 4비트 학습이 가능했던 장비에서 전체 BF16 병합도 된다고 가정하지 않는다. GPU에 충분한 메모리가 있으면 `--device cuda:0`, 필요하면 `--offline`을 지정한다. 병합은 원본 비양자화 체크포인트를 다시 로드한다.

결과는 `model-00001-of-....safetensors` 등 여러 가중치 조각, 인덱스, `config.json`, 토크나이저를 포함한 Hugging Face 모델 폴더다. 한 파일만 보내는 형태가 아니다. Ollama용 GGUF 변환·양자화·등록·운영 서버 업로드는 이번 범위 밖이며 아직 수행하지 않았다.

## 5. 현 35B와 비교하기

후보 학습과 추론 서버 준비가 끝난 뒤, **같은 `data/test.jsonl`**을 각 모델에 사용한다. 엔드포인트의 실제 모델 ID를 넣는다. 스크립트가 모델 서버를 설치하거나 시작하지는 않는다.

```bash
python -B evaluate.py --data data/test.jsonl \
  --base-url http://127.0.0.1:8000/v1 --model SERVED_MODEL_ID \
  --output outputs/eval-30b-tuned --limit 200 --seed 42 \
  --temperature 0 --max-tokens 512
```

35B와 미튜닝 30B도 각각 새로운 출력 폴더로 같은 명령을 실행한다. 세 모델을 비교하면 모델 크기/계열 차이와 튜닝 효과를 구분하는 데 도움이 된다. 인증은 필요할 때 `OPENAI_API_KEY` 환경변수로 전달한다. 토큰을 명령행 옵션이나 설정 파일에 넣지 않는다. 필요한 경우 `--request-extra-json`으로 해당 추론 서버가 지원하는 thinking 설정 등을 동일하게 맞춘다. 예를 들어 vLLM의 지원 버전에서는 `{"chat_template_kwargs":{"enable_thinking":false}}`를 별도 JSON 파일로 지정할 수 있다.

이 평가는 앞선 도구 응답을 고정한 **원본 대화의 마지막 assistant 한 턴 재생**이다. 실제 MCP 도구를 실행하지 않는다. `metrics.json`의 도구명/인자 정확 일치·일부 JSON Schema 검사·응답 완료 지연 p50/p95와 `details.jsonl`의 실제 응답을 검토한다. 현재 test 932행 중 마지막 턴이 도구 호출인 것은 32행뿐이며 `--limit 200` 표본에는 더 적게 포함될 수 있다. 도구 호출 성능을 판단하려면 별도의 충분한 SOC 평가셋이 필요하다. TTFT는 스트리밍하지 않아 **미측정(null)**이며, 생성 tokens/sec도 측정하지 않는다. 텍스트 완전 일치는 진단용으로만 제시한다. 이것을 한국어 SOC 판단 정확도나 Hermes 전체 조사 시간으로 보고하면 안 된다.

하드웨어·추론 엔진·양자화·입력 길이·출력 제한·thinking·모델 상주/워밍업 조건을 맞추고 별도로 기록한다. 현재 MCP의 승인 준수·근거 정확성·조사 완결성은 검수된 SOC 시나리오와 별도 E2E 평가가 필요하다. 이번에는 실모델 평가 요청을 보내지 않았고 성능 우열도 결론 내리지 않았다.

## 6. 데이터 재생성과 로컬 검증

기본값은 허용된 소스마다 최대 5,000개를 결정적으로 선택하는 첫 실험용 구성이다. 모든 허용 행을 사용하려면 0으로 바꾸고 새 출력 폴더를 지정한다.

```bash
# 프로젝트 루트에서; 모델/패키지 필요 없음
python3 -B finetuning/prepare_data.py \
  --datasets-dir datasets --output-dir finetuning/data-full --max-per-source 0

# 이후 config.json의 data_dir도 data-full로 수정해야 함
python3 -B -m unittest discover -s finetuning/tests -v
python3 -B finetuning/train.py --check
```

같은 첫 사용자 질문은 소스가 달라도 같은 split에 묶는다. 평가 전용 파일과 SEVENLLM 원본 test의 동일 질문은 제외한다. 이는 공백 정규화한 질문의 일치 검사이며, 의미가 유사한 질문이나 실제 공격 시나리오 단위 누출까지 제거했다는 보장은 아니다. 공개 자료의 일반 도구명을 현재 MCP 이름으로 무조건 치환하지 않았다. 우리 SOC 전용 데이터로 만들려면 실제 스키마와 검수한 trajectory가 추가로 필요하다. 자세한 출처·제외 범위는 [DATA_SOURCES.md](DATA_SOURCES.md), 수량은 [preparation_summary.json](preparation_summary.json)을 따른다.

참고: [Qwen 공식 모델 카드](https://huggingface.co/Qwen/Qwen3-30B-A3B), [PEFT 양자화 학습](https://huggingface.co/docs/peft/developer_guides/quantization), [PEFT 체크포인트](https://huggingface.co/docs/peft/developer_guides/checkpoint), [QLoRA 논문](https://arxiv.org/abs/2305.14314).

## 현재35B SOC 후속 경로

현재 저장 루트는 Thor `~/Capstone_Groot_training/qwen36-20261027`이다. 새 자료는212대화·train/validation/test144/32/36이며 Git 제외다. `soc_dataset.py`는 계약/출처/분할을 검사하고 `config.qwen36-soc-main.json`·`soc-train`은 전체224prefix1epoch를 별도 결과에 저장한다. `merge_streaming.py`는 MTP/비전이 빠지지 않게 원본 전체를 보존하며190개 LoRA만 병합하고, `convert_soc.py`는 같은 HF 미학습/학습본을 같은 GGUF/Q4_K_M으로 비교할 준비를 한다. 실제pilot HF 내보내기는 검증 완료, 본 학습과 base 변환은 진행 중이다. 단계별 명령/자원·검증 범위는 [THOR_35B](THOR_35B.md), 최신 완료 여부/Git은 [STATUS](../STATUS.md)를 따른다.
