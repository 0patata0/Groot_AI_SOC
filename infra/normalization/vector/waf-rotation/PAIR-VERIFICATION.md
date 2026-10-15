# 회전 보관본의 WAF pair 검증

`verify-pairs-a.py`는 A에 이미 설치된 Vector 0.59.0과 네 WAF VRL 파일을 그대로 실행하는 일회성 검증기다. Python 표준 라이브러리는 제한된 실행·원본 대조·결과 집계에만 사용한다. 새 상시 수집기, 패키지, 서비스, 컨테이너를 만들지 않는다.

2026-10-14 20:44 실제 검증 완료: 네 세대6건 재생과 구 binding/늦은 access 음성 대조가 모두 통과했다. 설치VRL·원본SHA는 전후 같고 private Vector 자식은 전부 회수됐다. 결과는 [검증 메타데이터](validation-2026-10-14.json)에 있다. 아래 후보 시점의 검사는 준비 이력이다.

후보 준비: 로컬 구문검사와 합성 계약 검사 6개를 통과했다. 계약 검사는 JSON 중복·비정상 값 거절, 별도 file 입력·출력 구성, 정확한 격리 원인, event ID·KST·원문 지문, 현재 저장소의 VRL SHA를 확인했다. 이 결과는 A의 native 실행 성공을 뜻하지 않는다. 실제 결과는 부모 실행기의 메타데이터와 서버의 `pair-tests/pair-validation.json`으로 별도 남긴다.

## 입력과 실행 경계

입력은 `run-probe-a.py`가 다음 위치에 보관한 `manifest.json` 하나다.

```text
/var/tmp/capstone-sequential-20261014/step1/run-<unique>/evidence/manifest.json
```

고정 A machine ID·root, private 디렉터리, symlink가 아닌 단일 링크 일반 파일을 요구한다. 각 세대의 감사·접근·producer 설정 사본은 root 소유 `0400`이며 manifest SHA와 대조한다. `0400`은 읽기전용 보관 권한이며 Linux immutable 속성이나 root 수정 불가능성을 뜻하지 않는다. 종료 뒤 입력 SHA와 설치된 네 VRL SHA를 다시 확인한다.

manifest는 네 세대의 binding·설정 SHA·원래 reader 경로·실제 writer 경로·보관 경로·원문 SHA·예상 request ID를 구분한다. 검증기에는 정확히 `[2, 1, 1, 2]`개의 요청이 필요하다. 원문과 request ID는 A에 남고 stdout 결과에는 건수·고정 판정·파일 SHA만 나온다.

Vector 입력은 각 세대의 **보관 파일**이다. 검증용 remap은 실제 보관 경로를 먼저 확인하고 `.source_file`을 manifest의 원래 reader 경로로 재구성한다. WAF 환경 변수도 그 세대의 binding·설정 SHA·원래 경로를 사용한다. 이 재구성은 시험용 메타데이터 연결이며 운영 binding 발행이나 당시 실시간 reader 경로의 신뢰성을 새로 증명하지 않는다.

별도 Vector의 data·checkpoint·ready·quarantine·로그는 모두 `evidence/pair-tests/` 아래에 생성한다. 운영 입력, 운영 ready, 운영 checkpoint, systemd, 기존 컨테이너에 쓰지 않는다. 호출자가 생성한 Vector 자식만 종료하고 회수한다. 시험 실패 로그와 원문은 서버의 private 경로에 보존하며, 부모 실행기는 실패 stdout의 고정 오류 코드도 별도로 보관한다.

## native 검증 항목

1. 네 세대를 각각 한 번에 읽어 총 6개 ready 결과를 확인한다. 정확한 request ID 집합, deployment binding, `event_id`, 감사·접근 원문의 줄 구분자 제외 SHA, KST 완료 시각, 주소·포트·HTTP 정보, rule/severity/engine, provenance, 빈 quality, 제외한 Server 중복 수를 모두 대조한다. 예상 밖 정제 필드도 거절한다.
2. 구 세대 원문에 새 binding·설정 환경을 적용한다. ready 0과 원문 4개 격리를 요구한다. 단순 개수뿐 아니라 감사·접근 각각의 원문 바이트/지문, `audit_part`/`access_part` 단계, 정확한 `waf_*_producer_binding` 실패 사유를 확인한다.
3. 별도 file 입력으로 감사 한 건만 먼저 넣는다. 실제 `waf_pair_cardinality` 격리를 관측하고 시작 후 2초 이상 지났음을 확인한 다음 접근 짝을 추가한다. 최종 ready 0, 원문 감사 보존 격리 1, 늦은 access-only 제외 1을 확인한다.

기존 reduce 설정인 2초 만료·100ms 만료 점검·5초 주기 flush·최대 4개 입력을 사용한다. 2초는 마지막으로 받은 이벤트 이후의 대기 시간이며 요청 처리시간이 아니다. [Vector reduce 공식 문서](https://vector.dev/docs/reference/configuration/transforms/reduce/)에 설명된 동작을 실제 별도 프로세스에서 확인한다. 격리 사유는 Vector 0.59.0의 legacy `metadata.dropped` 계약과 대조한다. [해당 버전 remap 구현](https://github.com/vectordotdev/vector/blob/v0.59.0/src/transforms/remap.rs)

## 결과 해석

세대별 보관본 재생 PASS는 원본과 당시 binding을 함께 보관했을 때 정제 결과를 재현할 수 있다는 뜻이다. 별도 raw reader 회전 시험과 합쳐도 **회전 중 실시간 audit/access 결합이 무손실이라는 뜻은 아니다.** alias 공개 지연, producer 설정 변경 시 환경 전환, 실제 pair 만료 후 복구는 별도 운영 연결 조건이다. TTL 음성 시험은 이 한계를 숨기지 않고 관측하기 위한 것이다.

일회성 실행은 부모의 단계별 조율 후 고정 manifest로만 수행한다. 이미 존재하는 `pair-tests/`를 덮어쓰지 않으므로 재시험이 필요하면 이전 결과를 보존하고 새로운 격리 증거 세대를 준비한다.
