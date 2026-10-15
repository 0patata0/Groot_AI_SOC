# Native Wazuh → 기존 Containment 연결

**2026-10-15 설치·설정 활성화 완료, 실제 차단 E2E는 미시험**이다. A 새3파일 설치 후 Linux native69개와 실제 managed current generation 4,015건의 읽기를 확인했다. B는 agent001/rule100110에 한정한 연결의 native 설정3개 통과 후08:31:30 KST 같은CID 재시작·ready를 확인했다. A는08:47 KST CP 정합성 수정과 함께 `<disabled>no</disabled>`를 적용하고 agent를 한 번만 stop/start했으며,08:49:07 후조건에서 활성화·guard PASS·checkpoint 직접 수정0을 확인했다.

[Wazuh stateless AR](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)의 `add` 알림을 기존 `/usr/local/sbin/rule-change-executor` stdin `contain-ip` 요청으로만 변환한다. 별도 승인 플랫폼은 없고 기존 root helper SHA `d937c7def4d2938d7655e445cb5cf9cd7858837aebebaf4278feae5fb69965a2`도 그대로다. **적격 운영 경보에 의한 실제 차단·자동 만료·유지/해제 승인 카드 end-to-end는 실행하지 않았다.** 설치·활성화를 그 시험 성공으로 확대하지 않는다.

## 고정 범위

`native-containment-ar.xml`의 manager 연결은 command `capstone-containment`, `timeout_allowed=no`, `defined-agent` 001, rule100110 하나다. `level`·`rules_group`를 추가하면 Wazuh가 조건을 OR로 해석해 범위가 넓어지므로 쓰지 않는다. [공식 설정 의미](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html)

A adapter도 native envelope/add·agent001·rule100110/level9·정확 Suricata eve 위치·5분 이내 명시 시간대·외부 IPv4를 검사한다. `data.src_ip`는 재검증을 시작할 힌트다. 경보 한 건만으로 차단을 허용하지 않는다. DGX/사설·예약·관리 주소 보호 및 최근5분의 독립적인 양방향 TCP severity1 공격 flow3개는 **기존 `incident_containment.validated_evidence`·live backend가 다시 판단**한다. 기존 600초 임시 TTL, 자동 만료, 반복 연장 금지, HMAC/nonce/일회소비를 사용한 3600초 유지 또는 해제 승인을 그대로 사용한다. 기존 승인 카드 발송은 실제 적격 사건에서만 기존 흐름대로 발생하며, 이번 합성 검증에서는 메시지·nft·HTTP 호출이 없다.

AR에는 Wazuh timeout/delete/repeated_offenders를 추가하지 않는다. 커널 TTL·소유 태그와 기존 root worker가 해제를 관리한다. adapter는 shell/sudo/임의 명령·경로·token을 받지 않고 고정 helper만 실행한다. helper 실패·360초 timeout·중단은 결과 불명/거절로 남기며 자동 재호출하지 않는다. stdout에는 고정 상태와 helper 종료 코드만 남고 원문·IP·승인 내용은 내보내지 않는다. 설치 Wazuh의 실제 적격 경보 envelope부터 adapter와 기존 차단 정책까지의 연결은 미시험으로 남긴다.

## Managed 원천 보완

이전 reader는 `.1`/현재 파일의 nlink1만 허용해 managed generation/active/eve **3개** hardlink 구조를 거절했다. 설치된 `managed_suricata_evidence.py`는 다음 조건에서만 현재 generation을 읽는다. 실제 읽기4,015건·6,498,609B·nlink3를 확인했으며 이전 세대나 공격 적격성 전체를 검증했다는 뜻은 아니다.

- 고정 A machine/현재 boot, root0600 canonical 단일 state, schema1·정확 active/pending=null/proof=null 계약.
- root0711 managed 디렉터리, 정확 generation basename/dev/inode, 세 경로의 regular/nofollow/UID998:GID998/0644/nlink3 일치. 남은 publish 임시 링크는 거절.
- 실제 Vector config/env 및 Wazuh config SHA가 root state pins와 일치. 원래 config 메타도 전후 동일해야 한다.
- 기존 Vector 공통 lock에 nonblocking shared lock을 잡고 상태·설정을 전후 대조. 다른 회전 작업이 lock을 잡았거나 상태가 pending이면 보류.
- pre-stat EOF 기준 마지막16MiB, 최대32768행/행256KiB/검사5초. 같은 고정 범위를 두 번 읽어 일치 확인; 이후 append는 허용하지만 잘린 첫 행·미완료 마지막 행은 제외. 잘못된/중복키 JSON은 공격 증거에 포함하지 않는다.

`incident_containment.py`의 접점만 보완한다. managed root가 어떤 형태로든 존재하면 root 고정 extension의 검증한 바이트를 불러오며 오류 시 legacy로 우회하지 않는다. managed root 없는 기존 환경의 reader는 그대로다. **현재 세대만** 읽으므로 회전 직후 이전 세대에 걸친5분 전체성이나 완전 탐지·원격 ACK를 주장하지 않는다. 부족하면 기존 3-flow 기준에서 거절한다. runtime coordinator/state/checkpoint는 수정하지 않는다.

## 수행한 설치·활성화 순서

1. 부모 운영자가 기존 incident 원본 SHA `e22114ad94d2a11294bf329174f5eb8e9879bdb5c8d053025889624f9e42152f` 및 실제 root:root0750/nlink1을 확인·백업했다. 새 reader `/opt/rule-change/managed_suricata_evidence.py` root:root0400, adapter `/var/ossec/active-response/bin/capstone-containment` root:root0750를 source SHA와 결속해 설치했고 incident는 원래0750으로 한 접점만 CAS했다. 기존 helper/sudoers/broker는 그대로다.
2. A 기존 Linux Python에서 **신규33+기존Containment36=69개 PASS**와 실제 root 경로·managed3link 읽기를 확인했다. 시험의 모델·nft·채팅 호출은0이다. 모의 flow3개가 기존정책을 통과하는 것과 실제 운영 차단은 구별한다.
3. B manager에 정확 command/AR 두 블록만 추가하여 native 설정3개, 같은CID bounded restart 및 필수5프로세스·agent001 active를 확인했다. 이 시점에는 아직 A disabled=yes였고 이후 A 단계와 구분한다.
4. A CP 정합성 수정과 충돌하지 않도록 한 번의 통제된 config CAS/agent restart에서 stats-ignore 제거와 AR disabled=no만 결합했다. 아래 readiness 영수증 SHA와 설치3파일을 재대조했고, 이후 후조건은 `active_response_config_enabled=true`, `native_stop_calls=1`, `native_start_calls=1`, `checkpoint_rewritten=false`였다. 실패 시 권한을 우회하거나 설정을 추정해 재시도하지 않는다.

설치된3파일 SHA는 incident `ab51cfeb5416a278f20c3cd569ed582c5a6f239e91b480a2ed89e1c06cba980c`, managed reader `06d36cdbf61de5ed08e8e6c3cc829a7d01648e10f04f5c6253818ea89be3d4df`, adapter `d7b603e542b68e8290c37e9214427a56a181c5cee15daee3d2cd5a7ca8e8989e`다. 보호 IP·독립3-flow 기준·600초 TTL·기존 유지/해제 승인 정책은 변경하지 않았다.

readiness 파일은 `/var/lib/capstone-automation/native-containment/ready.json`(root400, 부모root700, regular/nlink1)이며 정확9키다. 단일 canonical sorted JSON+LF로 fsync 후 게시한다.

```json
{"agent_id":"001","automatic_test_containment_executed":false,"installed_sha256":{"/opt/rule-change/incident_containment.py":"<64hex>","/opt/rule-change/managed_suricata_evidence.py":"<64hex>","/var/ossec/active-response/bin/capstone-containment":"<64hex>"},"machine_id":"096e90b6243e438aa8a7b392be754732","manager_configuration_verified":true,"native_tests_passed":true,"policy":"capstone-native-containment-ready-v1","rule_id":"100110","schema_version":1}
```

실제 readiness SHA는 `83b05b8080ae1d9cd34a951032db3970aded81fc1b606a4e05744ccce8b9a35f`다. 이 파일 자체는 A 활성화나 공격 차단의 증거가 아니라 설치와 B 설정 준비의 근거다. A 활성화는 별도 CP controller 후조건으로 확인했다. 원본 metadata는 부모 evidence의 `ar-install-a.json`(SHA7608292f…), `ar-ready-b-v2.json`(24d4cc73…), `cp-final.json`(558add2c…)에 보존돼 있다. 실제 적격 자연 공격/차단·만료·유지·해제 end-to-end와 카드 발송 시험은 별도로 남는다.
