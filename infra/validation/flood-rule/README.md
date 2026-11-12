# 볼류메트릭 플러드 전용 Wazuh 룰 100113 후보

2026-11-13 KST. **후보·격리 검증까지이며 운영 룰에는 미적용**이다. 적용은 룰변경 승인 경로(`propose_rule_edit` → 관리자 카드 → `wazuh-analysisd -t`·매니저 재시작·읽기 확인)로만 한다. [현황 #7](../../../STATUS.md) · [작은 원장](validation.json) · [후보 룰](candidate-100113.xml) · [편집안](edit.json).

## 왜 필요한가

컨트롤러는 level≥9 경보만 수집한다. 실제 플러드 SID 1000090(ICMP)·1000091(SYN)은 `attempted-dos`·severity 2라 범용 medium 100111(level 6)로 끝나서 **컨트롤러에 도달하지 않는다**. 같은 출발지 8건/120초일 때만 범용 버스트 100112(level 12)가 올라가며, 이 룰은 플러드 전용이 아니다(누적 31건, 여러 날·여러 출발지). 그래서 컨트롤러의 플러드 상관 ②(`flood_rule_ids`)에 지정할 수 있는 플러드 전용 룰 ID가 없었다.

## 후보

| 항목 | 값 |
|---|---|
| 부모 | `if_sid 100111`(severity 2 medium 분기). severity 1인 같은 SID는 기존 100110(high·유일한 AR 대상)으로 유지 |
| 조건 | `alert.signature_id` pcre2 `^100009[01]$` — 두 SID만, 1000092·접두/접미 변형 불일치 |
| level | 10(컨트롤러 수집 경계 9 이상). B에는 level 기반 active-response가 없음(라이브 확인) |
| 분류 | `capstone_ids_burst_candidate`(기존 버스트 집계 유지) + `capstone_volumetric_flood`, MITRE T1498 |
| 위치 | **100111 뒤, 100112 바로 앞**. 기존 룰 문자는 바이트 그대로 유지 |

### 배치 순서가 필수인 이유(격리 검증에서 발견)

처음 후보(100112 **뒤**에 추가)는 격리 엔진에서 7/8이었다. 같은 출발지 플러드 8건이 모두 100113으로 끝나서 **출발지별 버스트 100112가 더는 발화하지 않았다**. 이 Wazuh 엔진에서 `if_matched_group` 상관 룰은 자기보다 **먼저 정의된** 그룹 구성원에만 연결된다. 100113을 100112 앞에 두자 9/9를 통과했다. 같은 출발지와 혼합 순서 모두 8번째 경보에서 100112가 유지됐다. 이 사실은 공식 문서의 일반 문법이 아니라 이 환경 이미지에서 관찰한 동작이다. 순서는 `test_defined_between_parent_and_burst_rule`로 고정했다.

## 검증

| 단계 | 결과 |
|---|---|
| 오프라인(`test_flood_rule_candidate.py`) | 7/7. 실행기 자체 `_validated_edits`·`_validate_candidate` 통과, 기준 SHA 결속, 100113만 추가, 형태·패턴·AR 없음·순서·회귀 사례 일관성 |
| 라이브 선확인(B 읽기전용, 관리자231 경유) | 운영 파일 SHA=리포(`5301922c…`), 100113 빈 ID, 앵커(100112 블록) 1회, level 기반 AR 없음, SID 디코드 필드 `alert.signature_id` |
| before 엔진(운영 매니저, 읽기전용 logtest) | 9/9. 시험 세션 전부 삭제, 경보 주입 없음 |
| candidate 엔진(동일 이미지·`--network none`·etc 임시 사본) | `wazuh-analysisd -t` rc 0, 9/9. 컨테이너·임시 사본 제거 확인, 운영 매니저 시작 시각 불변 |

| 사례 | before | candidate |
|---|---|---|
| ICMP/SYN 플러드 단건 | 100111 L6 | **100113 L10** T1498 |
| 다른 medium·high SID, 1000092 | 100111/100110 | 동일 |
| 플러드 SID지만 severity 1 | 100110 | 동일(AR 경로 불변) |
| 같은 출발지 플러드 8건 | 100111×7+100112 | 100113×7+**100112** |
| 같은 출발지 플러드·기타 혼합 8건 | 100111×7+100112 | 100111/100113 교대+**100112** |
| 두 출발지 플러드 8건 | 100111×8 | 100113×8, 버스트 없음 |

이는 합성 EVE 줄의 룰 판정 시험이다. 실제 Kali 플러드·센서·수집·컨트롤러 E2E가 아니다(공격 중단 유지).

## 적용 순서와 전제

Suricata 룰이 `threshold: type both, track by_dst`라 경보는 **SID·목적지별 5초에 1건**으로 제한된다. 수량은 작다. 그러나 다출발지 플러드에서는 경보마다 출발지가 달라질 수 있어, 컨트롤러가 출발지별로 사건을 나누면 사건 단편화(#7 병목)가 다시 생긴다. 따라서 다음 순서를 지킨다.

1. 컨트롤러 ②③ 운영 배포(T4, 관리자231 경유 리터럴패치).
2. 메타 `flood_rule_ids=100113` 지정. 룰이 아직 없으면 효과가 없어 안전하다.
3. 이 편집안으로 `propose_rule_edit`를 제출하고 관리자 카드 승인 후 적용한다(`base_sha256` 불일치 시 거부).
4. 적용 후 `infra/groot-b/local_rules.xml`을 운영과 동기화하고 해당 픽스처 테스트(`infra/mcp/test_rule_inventory.py`·`infra/hermes/query-completion/test_inventory_render.py`)를 갱신한다. 그 전까지 이 파일은 운영과 같은 기준본으로 두며 후보를 넣지 않는다.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -I -m unittest discover -s infra/validation/flood-rule -p 'test_*.py'
python3 -B infra/validation/flood-rule/flood_rule_regression.py generate   # 사례 JSON 출력(송신·주입 없음)
```

`native` 모드는 Wazuh 매니저 컨테이너 안에서 고정 SHA의 공식 logtest 클라이언트로만 실행하고 모든 세션을 삭제한다. 원문 결과는 로컬 `대화기록/검증/2026-11-13-flood-rules/`(Git 제외)에 있다.
