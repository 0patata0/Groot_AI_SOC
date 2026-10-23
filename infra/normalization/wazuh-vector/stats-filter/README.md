# Suricata 통계의 Wazuh 전송 제외

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

> **2026-10-15 대체 완료:** 이 ignore 방식은 Wazuh의 offset/hash 불일치를 유발해 제거했다. B의 decoder_order_size=1024 적용과 실제504/505필드·통계2주기 오류0/CP27표본 일치로 대체했다. 재배포 시 이 구형 ignore를 다시 적용하지 않는다. [원인·CP 수정](../../vector/raw-operations/checkpoint-diagnosis/README.md), [대체 디코더 설정](../stats-decoder-capacity/README.md). 아래는 과거 적용 기록이다.

2026-10-14 04:23:57 KST에 A agent에 적용했다. Suricata가 쓰는 원본 `eve.json`과 보안 경보·flow·DNS·HTTP 입력은 유지하고, 고정 형식의 정기 `event_type=stats`만 Wazuh 전송 전에 제외한다. Vector도 원본을 계속 읽는다. 새 서비스나 패키지, Python 상시 처리기는 추가하지 않았다.

## 원인과 조치 근거

B의 설치 Wazuh 4.14.8 기본 `analysisd.decoder_order_size`는256이었다. Suricata 최근1,500행 중 통계 최대504개 leaf에 agent의 `capstone.source` 라벨1개가 붙는다. 매분 정기 stats 시각과 manager의 필드 초과249건이 일치했다. 같은 표본의 alert 최대48개·정제41개와 구분한다. 통계 필드를 참조하는 설치 규칙은 검색되지 않았다.

설치 manager의 분리 logtest에서 합성256개까지 전부 추출하고257/504개 입력은256개까지만 추출하는 경계를 확인했다. 이 시험이 만든19:18:22 UTC 오류1건·19:18:23 오류248건은 자연 발생 통계 오류와 구분한다. logtest 오류는 stdout이 아니라 manager 진단 로그에 기록됐다.

[공식 옵션](https://documentation.wazuh.com/current/user-manual/reference/internal-options.html#analysisd)과 [4.14.8 JSON 읽기 구현](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/read_json.c#L91-L101)을 대조했다. native `ignore`는 JSON parse/label 추가 전에 검사한다. 전역 제한값을 높이지 않고, 원본 통계는 보관하면서 Wazuh 분석용 전송만 제외한다.

## 적용 계약

`before.xml` 또는 `after.xml`이 전체 agent 설정 안에 정확히 한 번 있어야 한다. 검토하지 않은 다른 형식은 자동 수정하지 않는다. `after.xml`의 PCRE2는 시작부터 timestamp→event_type stats→stats 객체의 고정 순서를 요구한다. 다른 순서나 형식의 통계는 전송되므로 source 형식 변경 후 오류 재발을 확인해야 한다. 임의 위치의 stats 문자열이나 alert payload를 이유로 보안 이벤트를 제외하지 않는다.

- root·고정 A machine ID·Ansible2.21.x를 요구한다. MCP/LLM에는 실행 권한을 추가하지 않는다.
- Vector 유지보수·Wazuh 배포·승인 worker의 기존 lock을 공유한다. 경합75는 변경 없는 유예다.
- 원본 전체 설정 SHA/소유권/권한을 기록하고 candidate native 검증 후 설치 직전 다시 대조한다.
- `ansible.builtin.copy`의 원자 교체·원본 백업을 사용한다. 변경됐을 때만 기존 Wazuh agent를 재시작한다.
- 실패 복원은 실제 config가 방금 설치한 candidate와 같을 때만 진행한다. 그 사이 다른 변경이 있으면 덮어쓰지 않는다.
- 필수 agentd/logcollector·서비스 active·manager 연결과 최종 SHA를 확인한다. 실제 실패 복구 시험을 수행했다는 뜻은 아니다.

```sh
# A root, 이 폴더의 상위에 기존 ansible.cfg와 inventory.ini 필요
bash run-a.sh syntax
bash run-a.sh apply
```

## 실제 검증

native 설정 검사·PCRE2 양성1/음성7 통과. 마지막 최근1,500행 대조에서 stats127개만 일치했고 alert19개 및 다른1,354개는 제외하지 않았다. 시험 패턴과 설치 XML이 같음도 검사한다. 실제 agent queue에 합성 경보를 넣지 않았다.

첫 Ansible `ok=25 changed=4 failed=0`, 반복 `ok=24 changed=0 failed=0`이었다. 변경된 localfile은 Suricata1개이며 다른9개는 XML 바이트가 같았다. 최종 config SHA는 `6198f7860c2dc6b5f21bc54a22c2df506c0adb2cacae697e7cafd4300a6b93e0`, 원본은 `740fb0d8ea45e1b302d11862f55f2d9f29e86bdd22f5a5e202f04d3ffb36e21e`다. 백업은 `/var/ossec/etc/ossec.conf.1631221.2026-10-14@04:23:57~`이다.

A Vector/agent active·manager connected, WAF/Suricata/chatproxy의 ID·시작 시각이 같았다. B manager와 decoder override도 변경하지 않았다. 적용 뒤 원본에 매분 통계가 계속 기록됐으며 신규 필드 초과 오류가 중단됐다. 최종 관찰 길이와 집계는 [검증 JSON](validation-2026-10-14.json)에 기록한다. 향후 다른 원천의 필드 초과까지 방지하는 조치는 아니다.
