# 2026-10-15 읽기 전용 후속 관측

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../STATUS.md) · [실행 계획](../../../PLAN.md).
> 기존 서버의 운영 자동화와 새 서버 초기 설치는 구분한다. 지정 범위의 C1/B1/A2 재부팅 복구는10/24 검증 이력이 있으며 최초 실패·수동 복구도 보존한다. 현재6실습·MCP6서버를 기준으로 읽고 과거 후보/PID/시험 결과를 새 실측으로 해석하지 않는다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

[observe.py](observe.py)는 고정 A/B에서 운영자가 한 번 실행하는 stdlib 도구다. 서비스·Docker 상태 변경, HTTP/MCP/모델/채팅 호출, 운영 DB 연결·복원·체크포인트 수정은 없다. 설치할 상시 프로그램이 아니다. 부모가 소스 SHA를 검토·반입하고 실행하며, 이 후보 작성만으로 실제 관측 완료를 뜻하지 않는다.

**최종 실제 관측(2026-10-15 KST)**: v4 native 15개가 모두 통과했고 source `b3b4eb5668bd4d8ebd5e332fb99b59a1779ebb60a57d9633e63cc4ede422b27b`를 동결했다. [A 결과](results/imperva-2026-10-15.json)의 cutoff는 09:25:43.386507이며 82행/155,779B, invalid 0이다. 최근 24h access 9건 중 대상 IP 4건, 대상 timed audit 0건이고 최근 5h access는 0건이다. 시차를 검증할 수 없는 대상 audit 56건은 시간 창에서 제외했다. v3의 invalid 9건은 v2 access를 지원하지 않던 파서 가정 때문이며 v4에서 0건으로 정정됐다. 과거 실패·부분 결과는 그대로 보존한다.

[B 결과](results/hermes-2026-10-15.json)는 v3 source로 09:22:31.344234에 수행한 실제 관측이다. source pin 3개 일치, private DB quick_check 및 원본 불변·사본 제거를 확인했다. 최근 5h/24h 모두 user 1·assistant 8·tool 10 저장행과 delivered obligation 1건, 저장시각 간격 표본 1개(60.319994초), guard journal 0건이었다. 표본 1개의 p50/p95는 같은 값일 뿐 분포 성능 근거가 아니다. 실제 전송·승인 지연이나 한자 혼입률·교정 실패율은 이 결과로 확정하지 않는다. 두 결과 모두 원문/개별 파일 메타는 서버 private evidence에만 있고 repo에는 부모가 축소한 메타데이터만 보관한다.

2026-10-15 KST 부모 실행 결과: A의 Linux root에서 합성 11개가 모두 통과했다. 로컬에서 권한 때문에 skip한 private DB/WAL 사본·원본 불변·사본 제거 시험도 포함한다. 관측 source SHA `8cba4be079fe6b01b1d2382a8d537715b7e6533f3d948707983db613595315a5`를 유지했다. [검증 메타데이터](native-validation-2026-10-15.json)는 합성 native 통과이며, 실제 A/B 관측 결과와 모델 합성 평가 결과를 대신하지 않는다.

후속 실제 A 관측은 최초 Docker 읽기 호출에서 `FileNotFoundError`로 중단됐다. A/B의 실제 설치 경로는 `/usr/local/bin/docker`이며 후보가 `/usr/bin/docker`를 가정했다. 고정 실행 경로 한 곳만 정정하고 양 host의 정확 argv 회귀를 추가했다. v1 소스·실패 기록은 부모가 보존하며 새 v2 stage를 사용한다. 초기 합성 11개 통과가 live Docker 경로를 검증한 것으로 해석되지는 않는다.

v2의 실제 A 읽기는 WAF 이미지의 `/etc/modsecurity.d/owasp-crs` 디렉터리 alias에서 `NotADirectoryError`로 중단됐다. 부모 실측은 정확 `/opt/owasp-crs` symlink였다. v3는 이 고정 alias 한 개의 타입·target·메타를 전후 검증하고 `/opt/owasp-crs/rules/REQUEST-900-CAPSTONE-SCANNER.conf`를 root FD 상대 nofollow로 읽는다. 상대 target·다른 target·canonical 하위의 추가 symlink는 계속 거절하며 일반적인 symlink 허용으로 확장하지 않는다. 두 실패 시도와 소스는 보존한다.

v3는 A native 13개를 통과했다. 실제 A 82행 중 access v2 9행이 지원되지 않아 partial로 남았고 이를 정상 0건으로 처리하지 않았다. 실제 producer의 v1/v2는 같은 12개 문자열 필드를 사용하므로 v4는 두 버전만 허용하고 필드 집합·타입·32hex request ID/64hex binding·정확 ms/offset ISO 일치를 확인한다. `2-private` 등 다른 버전·다른 타입·시각 충돌은 거절한다. 이 형식 검사는 과거 access binding을 현재 배포와 같다고 가정하거나 audit와 요청별 결합을 증명하는 검사가 아니다.

부모가 수행한 B v3 실제 관측에서는 guard source 3개 일치와 private DB 검사·원본 불변을 확인했다. 최근 5h/24h는 각각 user 1·assistant 8·tool 10 저장행, delivery 1, 저장시각 간격 추정치 60.319994초, guard journal 0건이었다. 아래 분모·전송 지연 한계를 유지하며 실제 전송 완료 시간이나 언어 혼입률로 해석하지 않는다. 이후 A v4 실제 결과는 상단의 최종 관측과 결과 링크에 추가했다.

```sh
# A: 사전 검토한 소스에서 고정 MID/CID를 확인하고 실행한다.
python3 -B /ABS/observe.py a
# B: 아래 작업 폴더만 root0700으로 미리 준비한다. private DB 사본은 실행 종료 시 제거한다.
# /var/tmp/capstone-tools-followup-20261015/observation
python3 -B /ABS/observe.py b
# 합성 파싱·DB·경계 시험. Linux root이면 private WAL 사본 시험도 수행한다.
python3 -B /ABS/test-observe.py
```

stdout은 JSON 메타데이터뿐이다. 예외에도 원문 오류·SQL 값·stderr를 출력하지 않는다. 관측 시작의 cutoff를 고정해 최근 5시간·24시간을 함께 집계하고 KST와 epoch를 표시한다. 전체 90초, 개별 외부 읽기 명령 15~20초, 고정 stdout 상한이다. 읽기로 atime은 변할 수 있다. 실제 실패/변경/용량 상한을 정상 0건으로 숨기지 않는다. DB가 변하면 해당 부문은 unavailable이며 운영자는 새로운 읽기 관측을 별도로 실행할 수 있다.

## Imperva 자연 유입

고정 WAF CID의 동일 PID/start와 host/container 예외 SHA를 전후 확인한다. `/home/groot_a/capstone/secstack/logs/modsec/`의 audit·최소 access·숫자 gzip 회전본과 `capstone-managed/generation-*.jsonl`을 읽으며 hardlink alias는 dev/inode별 한 번만 센다. 파일당 저장/해제 각각 8MiB, 총 해제 32MiB, 256파일, 50,000행 상한이다. 동일 내용의 **별도 inode 복사본**까지 요청 단위로 dedupe하는 도구는 아니므로 결과는 보존 레코드 수다.

대상 IP `211.170.162.9`의 timed access/audit 건수·숫자 rule ID별 건수·10020/10021 감사 형상 건수만 내보낸다. v2 unique ID의 offset+epoch·audit clock 일치를 검증하고 원문 ID는 출력하지 않는다. 시차 없는 구 audit는 retained untimed 건수로만 남기며 UTC/KST를 추정해 시간 창에 넣지 않는다. 중복 Host는 보존해 예외 형상으로 잘못 세지 않는다. access에는 URI/Host/CL/TE가 없고 audit URI도 `REQUEST_URI_RAW`의 독립 증명이 아니다.

RelevantOnly·기존 retention/copytruncate·범위 밖 자료를 고려해 항상 `coverage_complete=false`다. 0건은 자연 요청·예외 효과가 증명됐다는 뜻이 아니다. 이번 도구가 요청을 생성하지 않지만, 주소만으로 외부 요청의 자연 유입 provenance를 완전히 증명하지도 않는다. alert/Indexer 조회는 별도 부모 작업이다.

## Hermes 운영 언어·시간 관측

고정 원래 Hermes CID와 guard/adapter/run_turn 3개 SHA, observer AWK SHA를 먼저 확인하며 달라지면 진단을 중단한다. `capstone-hermes-guard` journal tag의 4개 verdict와 chars 숫자 형태만 읽고 journal 수신 epoch를 사용한다. 메시지 내용·chars 개별 값·사용자/채널/세션 식별자를 내보내지 않는다. 20,000행/16MiB 상한을 넘으면 unavailable이다. 허용되지 않은 tag 내부 진단은 개수만 남긴다.

verdict에는 전체 응답 분모가 없다. `filtered`는 교정과 대체 안내를 구분하지 않으며 `retained`/`requested_foreign`에는 인용·외국어 요청 예외가 포함될 수 있다. 따라서 한자 혼입률·교정 실패율·대체 안내 발송 건수를 이 로그만으로 단정하지 않는다. 원문 대화 표면 검사를 새로 확장하지 않는다.

부모가 읽기로 확인한 실제 DB schema를 사용한다. 원본 `state.db`/`-wal`/`-shm`은 nofollow 안정 읽기와 전후 SHA·메타만 확인한다. 총 128MiB 이하 DB+WAL의 private 사본에만 SQLite를 연결하고 WAL을 반영한 `quick_check` 후 조회한다. 원본 SQLite 연결은 0이며 `immutable=1`로 활성 WAL을 무시하지 않는다. private SQLite가 만든 SHM은 private 폴더와 함께 제거한다.

`mattermost` 세션의 active 메시지에서 역할·timestamp·tool-call 유무만 SELECT한다. user 저장행부터 다음 user 전의 마지막 비도구 assistant 저장행까지의 차이를 표본으로 삼고 완료 저장시각이 창에 들어오는 표본의 p50/p95·최근 3개 초를 반환한다. 여러 assistant 후보가 있던 구간 수도 따로 남긴다. 이것은 **저장시각 간격 추정치**이며 실제 전송 지연·모델 실행시간·승인 소요시간이 아니다. 완료 표식 없는 마지막 assistant가 실제 최종 응답인지도 증명하지 않는다. 텍스트를 SELECT하지 않고 delivery obligations는 허용된 상태별 수만 센다. 세션과 메시지 ID는 조회 중 메모리 그룹화에만 쓰인다. 원본 DB/WAL/SHM이 조회 중 변하면 집계 결과는 반환하지 않는다.

source/operator 실행 기록은 부모의 날짜별 작업 기록과 server evidence에 보관한다. 현재 소스의 설치/서버 실행 여부와 결과는 별도 기록으로 갱신한다.
