# Vector 검증 기록 — 2026-10-14 KST

## 후속 운영 통합 검증

WAF producer·요청/배포 ID 결속과 공통 상관 메타데이터를 A 운영 Vector에 적용했다. native 기존19개+공통9개+WAF61개, 총89개가 통과했다. producer 첫 성공 적용changed2·재적용changed0, Vector 첫ok42/changed6·재적용ok41/changed0이었다. Vector 재실행 전후 PID와 InvocationID도 같았다.

03:29:04 KST 스냅샷에서 Vector active/running, MainPID1621310, NRestarts0, 현재 invocation ERROR0, memory약28MB(High384MiB/Max512MiB), 디스크18%·회전복구pending없음을 확인했다. 새 계약 출력11건은 nft10+ModSecurity1이며 모두fresh/KST, 허용 필드 위반0·재귀 leaf최대41이었다. B에서 관측한 JSON decoder field 초과 오류의 원천을 이 표본으로 확정하지 않으며 전역 필드 제한을 임의 상향하지 않았다. WAF 상세 출처/실물 검증은 [전용 검증 기록](WAF-VALIDATION-2026-10-14.json)을 따른다.

A helper·MCP·sudoers SHA는 기존과 일치했고 waf/suricata/chatproxy가 running이었다. [통합 JSON](pipeline-validation-2026-10-14.json), [실제 출력 회전](STORAGE.md), [Wazuh43개·Indexer 종단](../wazuh-vector/CORRELATION.md)을 참조한다. no_log 관찰을 운영 공격 경보 승격으로 표현하지 않는다. 첫 WAF 적용 실패/복구와 자동 승인 검토 재제출도 WAF 문서와 대화 기록에 남겼다.

## 최초 패키지 후보 검증 기록

아래22개 검사와 WAF 전부격리는 최초 적용 시점의 결과다. 후속 WAF 경로/89개 검사는 위 기록을 따른다.

대상은 A의 시험 후보 디렉터리이며 **이 검증에서 운영 서비스를 시작하거나 기존 로그·Wazuh 설정을 변경하지 않았다**. 설치와 운영 적용은 상위 작업 기록에서 별도로 확인한다.

- 실제 바이너리: `vector 0.59.0`, `x86_64-unknown-linux-musl`, commit `a3231c7`.
- 실제 journalctl: systemd `255.4-1ubuntu8.17`.
- `vector validate --no-environment vector.toml`: 통과.
- `vector test vector.toml tests.toml`: **22개 통과**.
- `systemd-analyze verify capstone-vector.service`: 통과.
- 시험 파일의 TOML은 로컬 Python 표준 `tomllib`로도 읽기 확인했다. Mac 패키지는 설치하지 않았다.

회귀시험은 명시적 시각의 KST 변환, offset/날짜/SID/severity 오류 격리, 유효하지 않은 IP 제거, flow tuple 분리, 보호 주소 메타데이터, 비 alert 선택 제외, kernel transport/cursor/시각 확인, 중복 SRC/DPT·다중 행·반복 prefix 격리, shadow 액션, WAF 반복 헤더 및 malformed 원문 보관을 확인한다. Vector native test가 생성하는 가상 source는 ACK를 지원하지 않아 ACK warning을 출력하지만 실제 file/journald source 검증 결과와 구분한다.

원본 파일의 최근 제한된 바이트 구간과 kernel journal 최근 500건에서 시험 표본을 골라 root 전용 임시 디렉터리에 복사했다. 실제 변환 파일을 그대로 사용하고 source/data/output만 시험 경로로 바꾸어 Vector를 실행했다. journal 표본은 원본 kernel 필드를 유지한 JSON fixture로 공급했으므로 **이 시험 자체는 production journald source의 재부팅·재시작 테스트가 아니다**.

| 실제 표본 | 입력 | 정제 출력 | 격리 |
|---|---:|---:|---:|
| Suricata alert | 3 | 3 | 0 |
| kernel nft | 10 | 10 | 0 |
| WAF audit | 4 | 0 | 4 |

모든 정제 출력은 `capstone_norm` 한 루트 객체였고 `vector-1`/`vector` marker, KST offset, 원문 필드 비전송을 확인했다. WAF는 전부 `normalized_eligible=false`였으며 정상 출력에는 없었다. 시험에 사용한 원문과 임시 data/output 디렉터리를 제거했다. 로그 원문은 터미널이나 이 문서에 출력하지 않았다.

확인된 호환성 제한 때문에 운영 후보는 `current_boot_only=true`다. Vector 0.59.0은 systemd 250~257의 all-boots follow를 거절한다. 파일 source는 새 회전 inode 앞부분을 건너뛰지 않도록 `read_from=beginning`을 사용하므로 초기 backfill 동안 Wazuh 상관 경보를 활성화하지 않는다.

아직 이 문서가 검증했다고 주장하지 않는 항목은 운영 Wazuh 수신·규칙·재시작, 실제 파일 회전의 무손실, 전원 장애 영속성, 출력 보존/회전, all-boots 미수집분 회수, WAF 정제와 독립 시각 증명이다. WAF 격리 검증 완료와 WAF 정제 연결 완료는 다르다.
