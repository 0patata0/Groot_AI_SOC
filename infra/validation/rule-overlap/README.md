# 장비 룰 중복·참조 검증

2026-11-04 KST 관측이다. **조건 중복 감사와 격리 시험까지이며 운영 룰 통합·삭제는 미적용**이다. 신규 설치도 실행하지 않았다. [기계 판독 원장](validation.json) · [현황](../../../STATUS.md) · [초기 설치 읽기 점검](../../../deployment/INSTALLER_READINESS.md).

| 장비 | 실제 확인 | 판정·한계 |
|---|---|---|
| WAF | 웹 정책 배포 후 정의654개·동일 조건/동작 후보0 | 앞선 웹 정책 검증 결과. 이번에 모든 웹 공격을 재시험한 것은 아님 |
| Suricata | ET52,483+local14 정의, 조건/동작 동일7쌍. 전체 소스를 설치된 동일 이미지로 전후 재생 | 양쪽14/14조건 통과. 대상 경보14→7, 제거 대상 외9개 경보 관측 지문 동일. 해당 합성 표본의 결과이며 모든 공격 무누락 증명이 아님 |
| Wazuh | 공식 API4,571과 설치된 Wazuh XML 파서4,571·172파일 일치. 조건/동작 동일17쌍 | 14쌍은 ID 외 정의도 같고3쌍은 설명 차이. 모든 정의가 중복 경보를 생성한다는 뜻은 아님 |
| Wazuh native | named/osquery/FortiMail8쌍 양성·osquery 음성1개 통과 | Windows9쌍 양성+음성1개는 EventChannel 경로 미검증. 전체19세션의 상태는 partial이며 모두 명시 삭제 |

## Suricata 후보와 회귀

| 남길 SID 후보 | 별칭 제거 후보 | 합성 시험 |
|---|---|---|
|2031294|2031293|FireEye 응답 패턴|
|2014493|2013684|dtdns HTTP host·정보성 신호|
|2022484|2022949|RIG 응답 바이트|
|2009486|2016471|WEBC2 User-Agent·flowbit 부수 효과 유지|
|2047884|2045358|Raspberry Robin DNS|
|2016534|2016535|MSIL URI와 헤더 제외 조건|
|2066629|2066625|MaskGram POST 헤더 인접 조건|

검사는 action·header·flow·content·PCRE·threshold·flowbit 등 조건/동작을 보존하고 SID·msg·rev·metadata·reference만 비교에서 제외했다. 이 제외는 이름·분류 근거가 불필요하다는 뜻이 아니다. 운영 통합 시 별칭·참조·보고 의미를 보존해야 한다. 설정5파일의 후보 SID 직접 참조는 없었지만 모든 외부 연계의 부재까지 증명한 것은 아니다. ET와 local에 동시에 존재하는2034806/2034802는 기존 좁은 API 흐름 오탐 방지 rev3 override이므로 이번7쌍과 구분해 보존했다.

`suricata_regression.py`는 검토한 ET SHA에서만 별칭7행을 제거한 **시험 파일**을 만든다. 원본 ET·local·PCAP·EVE 바이너리는 Git에 포함하지 않는다. PCAP은 시험용 주소의134패킷·14조건이며 송신 기능은 없다. 프로젝트 작성 회귀 표본으로 학습자료에 편입하지 않는다.

```bash
python3 -B infra/validation/rule-overlap/suricata_regression.py generate \
  --et /reviewed-source/suricata.rules --output /new-test-directory
python3 -B infra/validation/rule-overlap/suricata_regression.py check \
  --eve /completed-before/eve.json --phase before
python3 -B infra/validation/rule-overlap/suricata_regression.py check \
  --eve /completed-candidate/eve.json --phase candidate
```

실제 시험은 before=`ET+local`, candidate=`후보ET+같은local`을 바이트 그대로 연결했다. 기존 설치 이미지·원래 설정을 사용하고 HOME_NET만198.18.0.0/24로 고정했다. 내부 실행은 `timeout --signal=TERM --kill-after=5s 180s /usr/bin/suricata -c /etc/suricata/suricata.yaml --runmode single --set unix-command.enabled=no --set stats.enabled=yes --set vars.address-groups.HOME_NET=[198.18.0.0/24] -r /input/traffic.pcap -S /input/<phase>.rules -l /out`였다. 검증 컨테이너는 network=none·read-only·UID/GID998·cap-drop ALL·no-new-privileges·1GiB/1CPU·128PID·32MiB tmpfs로 제한하고 소스는 읽기 전용으로 연결했다. 설치기나 운영 컨테이너에 이 시험 명령을 연결하지 않았다.

첫 시도는 이미지 설정의998/600 권한과 시험 계정 불일치로 실패했다. 다음35초 실행 한도는 전체 룰 컴파일 전에 만료돼 해당 시험 컨테이너를 제거했다. 이후 실행/관측을 분리하고180초 내부 제한으로 양쪽 exit0·약38초 완료를 확인했다. 실패 원문을 로컬에 보존했으며 성공으로 덮지 않았다. 종료 뒤 시험 컨테이너0·서버 임시29파일/191,075,067B 제거·부모 부재, 운영 컨테이너 ID/시작 시각·ET/local/결합 SHA 불변을 확인했다.

## Wazuh 후보와 native 한계

| native 양성 경로 확인8쌍 | Windows EventChannel 미검증9쌍 |
|---|---|
|12122/12127, 24038/24039, 24105/24106, 24123/24124, 24127/24128, 24131/24132, 44681/44682, 44711/44715|60700/60701, 60729/60737, 60731/60742, 60732/60745, 60843/60845, 60862/60864, 62163/62192, 62206/62210, 92022/92030|

기존 룰 파일은 설치된 `wazuh.core.utils.load_wazuh_xml`로 읽었다. 일반 XML 파서의 vendor escape/comment 처리 실패를 운영 파일 오류로 판단하지 않았다. 4,571개에서 후보 ID를 참조하는 if_sid/if_matched_sid는0이며 Suricata signature_id 필드 조건도0이었다. 외부 연계·과거 사건 참조·앞뒤 시간 상태 전체를 대체하는 검사는 아니다. 설명이 다른44711/44715·60700/60701·60732/60745는 문구만으로 실제 사건 종류/피해를 단정하지 않는다.

`wazuh_regression.py`는 기본 실행 시 합성 입력 구조만 검사한다. B에서 운영자가 명시적으로 `--native`를 주면 설치된 first-party WazuhLogtest 클래스로 독립 시험 세션을 사용한다. 검토한 native client SHA가 다르면 거절한다. 입력/후보는19개로 제한하고 세션 토큰은 출력하지 않으며 finally에서 세션을 삭제한다. MCP의 일반 Docker/셸 권한을 추가하지 않는다.

```bash
python3 -B infra/validation/rule-overlap/wazuh_regression.py
# 기존 B에서 운영자가 별도 검사할 때만:
python3 -B infra/validation/rule-overlap/wazuh_regression.py --native
```

실측 결과는 pass9·fail0·EventChannel 미검증10·세션 정리 실패0이다. partial이면 CLI는2를 반환한다. Windows JSON이 generic json decoder로 처리되거나1002를 반환한 것을 Windows 룰 성공/실패 판정으로 세지 않는다. 실제 EventChannel 경로가 별도로 필요하다는 한계는 [Wazuh 유지보수자 이슈30472](https://github.com/wazuh/wazuh/issues/30472)와 [native 시험 경로 설명40614](https://github.com/wazuh/wazuh/issues/40614)도 참고한다. 운영60000 decoder를 바꾸거나 실제 분석 큐에 가짜 사건을 주입하지 않았다. 다음 검증은 별도 격리 엔진/agent EventChannel 경로여야 한다.

Wazuh vendor 소스는 삭제하지 않았다. 변경은 [공식 custom rule 지침](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html)의 업데이트/사용자 규칙 경계를 고려해 유지 가능한 방식으로 준비해야 한다. 새 후보 전후 native·상관/AR·외부 참조·업데이트 지속성·정확 승인·독립 원복 검증이 남는다.

## 적용 범위와 다음 단계

이번 공개 파일은 감사/회귀 도구·합성 입력·작은 원장이다. 룰/초기 설치/서비스 설정 변경·운영 재시작·실제 패킷 송신·채팅 게시·모델/권한 변경은0이다. 별도 승인 없이 vendor 룰 삭제나 운영 배포로 연결하지 않는다. 임시 도우미와 원문은 로컬 검증 기록으로 보존하고 작업용 복사본만 정리한다. 정상·악성 실웹→센서→LLM 조사·카드/대응 E2E와 FW/NAT/관리 경로 감사는 여전히 별도 작업이다.
