# Evidence 규칙 후보 검증

**운영 검증 추가(2026-10-14):** 최종 B 전용 XML을 실제 manager에 배포하면서 전체104개 시나리오를 설치 후 재시작 전과 재시작 후 각각 통과했다. 53개 evidence 시나리오는 이 합계에 포함된다. 자연 Suricata1건의 A→manager→Indexer 일치도 별도로 확인했다. [배포 결과](../evidence-deployment-2026-10-14.json). 이 결과는 아래 후보/오프라인 검사와 구분한다.

2026-10-14 후보 준비 결과다. [후보 검증 JSON](../evidence-candidate-validation-2026-10-14.json)에 파일 SHA와 수행 범위를 기록했다. **이 결과는 운영 배포 또는 색인 성공 기록이 아니다.**

- `100260`은 정확한 A agent 전달 location `/var/log/capstone-vector/evidence/normalized.jsonl`, `vector-1`/`vector`, `groot-sec`, `evidence_lane=indexer-observation-v1`을 요구하는 level 1/no_log 기초다.
- 독립 leaf `100261`/`100262`는 각각 Suricata/nftables 관측만 level 3으로 기록하고 `no_full_log`·`no_email_alert`를 사용한다. 공격 확정·자동 차단·채팅 전송은 이 규칙의 역할이 아니다. 기존 ready의 빈도·교차 source 자식들과 상속 관계가 없다.
- fresh/적격/protected=false, 64자리 소문자 hex 사건·내용·상관 키, IPv4/IPv6 주소, 목적지 포트 1–65535, tcp/udp, source별 action, 빈 품질값과 명시 KST 시각 형식을 확인한다. `.110/.111`은 출발지·목적지 양쪽에서 제외한다. 기존 서비스 방향 계약을 따라 출발지 포트는 새 필수값으로 만들지 않았다.
- 기존 `100200` 이하 ready와 canary·health 규칙 전체는 추가 전 SHA `b693dbec37f1a1cd497390e0a36513a97bba37ef62c3798b18d1b2cc7229eaf2`와 동일하다. 첫 설명 주석만 현행 범위에 맞게 바뀌었다. 기존 51개 시나리오 실행은 유지한다.

오프라인 표준 라이브러리 회귀 **6개**, B에 이미 설치된 Ansible의 A/B playbook **syntax-check 2개**가 통과했다. 독립 읽기 리뷰에서 추가 blocker를 발견하지 않았다. 오프라인 패턴 검사는 실제 Wazuh 엔진 검증을 대체하지 않는다.

```sh
/usr/bin/python3 -B -m unittest discover -s infra/normalization/wazuh-vector/tests -p 'test_evidence_contract.py' -v
```

`test-evidence-manager.sh`는 문서용 주소만 담은 합성 사례 **53개**를 기존 manager의 `wazuh-logtest`에 직접 입력한다. 운영 수집 파일·저널에 쓰지 않는다. 이 시험은 후보 XML 설치 transaction에서 manager 재시작 전후 실행하도록 `apply-b.yml`에 추가했다. 기존 설치본의 logtest wrapper는 `-c`/별도 후보 config 옵션이 없어 후보 XML의 native 매칭 시험은 아직 수행하지 않았다. 부모의 운영 transaction 결과를 별도로 기록해야 한다.

실제 B decoder의 무변경 시험에서는 빈 배열 `[]`와 문자열 `"[]"`가 같은 필드 문자열로 해석됐다. 누락은 필드 자체가 없었고 비어있지 않은 배열은 다른 값이었다. 따라서 Wazuh 정규식만으로 원래 JSON 자료형을 보장한다고 주장하지 않는다. `decoder-string-array-limitation`, `decoder-string-bool-limitation` 두 사례는 그 구분 한계를 의도적으로 기록한다. **자료형과 빈 배열 검사, 신뢰할 수 있는 evidence 분기 생성은 Vector가 먼저 보장한다.** root가 관리하는 정확 경로·marker가 이 상류 신뢰 계약의 일부다.

KST 필드는 여기서 형식을 확인하며 실제 날짜의 유효성·현재 사건 시각창은 Indexer 조회에서 다시 검사해야 한다. 오래된 `fresh` 표기를 재전송했다고 현재 상관분석 대상이 되는 것은 아니다. 같은 키의 중복 관측은 이 leaf에서 삭제하지 않는다. Indexer의 stable-key 집합으로 개수를 계산한다.

A playbook은 root:root 0700 evidence 디렉터리와 0600 단일 link 파일이 이미 준비됐는지 확인한다. localfile은 ready와 같은 `only-future-events=no`, `max-size=2GB` 정책으로 별도 추가하고 canary의 future-only 설정은 유지한다. 전체 기존 config를 후보로 복사해 전용 managed 블록만 갱신하므로 raw 수집과 stats ignore를 편집하지 않는다. 실제 적용 전후 stats 블록 보존, 생성된 evidence leaf의 level 3·원문 제외·Indexer 수신은 아직 확인해야 한다.

공식 근거: [Wazuh rule options](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html#options), [공식 JSON decoder source](https://github.com/wazuh/wazuh/blob/v4.14.0/src/analysisd/decoders/plugins/json_decoder.c). 설치본 자료형 해석·지원 CLI 옵션은 문서 추정이 아니라 별도 무변경 실측이다.
