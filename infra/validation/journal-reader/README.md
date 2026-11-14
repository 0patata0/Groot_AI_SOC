# journal reader 제한 환경과 시각 경계 검증

**A/B/C의 운영 reader와 같은 보안·자원 제한으로 후보를 읽었다. B/C는 반환했으나 A의24시간 오류 검색은 여전히 시간 초과다. 운영 적용 준비 완료로 판정하지 않는다.** [결과 원장](validation.json) · [후보 설명](../../mcp/journal-window-slices.md) · [현재 상태](../../../STATUS.md).

## 실제 journal 결과

| 검증 | 결과 | 의미·한계 |
|---|---|---|
| 최신 후보·A rule-worker24시간 | command_timeout·12.123초 | 원인 조회 실패가 남음. 빈 결과나 정상으로 바꾸지 않음 |
| 최신 후보·B rule-worker24시간 | 13.500초·표본0·기존 validator 통과 | 전체 건수 null·보존 확인 false. 오류 부재나 채팅 지연 개선 입증 아님 |
| 최신 후보·C Apache24시간 | 0.305초·표본0·기존 validator 통과 | 위와 같은 표본 한계. A/B와 다른 unit의 시간이며 호스트 성능 순위가 아님 |
| A 기존 로그의1마이크로초 구간 | 0.097초·해당 로그1건·기존 validator 통과 | native journalctl의 소수점 Unix 시각 지원 확인. 합성 로그를 쓰지 않음 |

고정24시간은 `2026-11-14T03:24:10.795222+09:00`부터 `2026-11-15T03:24:10.795222+09:00`까지다. 각1회·디스크 캐시/부하 비통제이며 모델·Mattermost 큐/전달을 포함하지 않는다. 후보 SHA는 `8f6cdafdb3829ba6c43648a99829f2bee3f28da8190ff1166574025ecca2054c`, 운영 A/B/C는 모두 기존 `8336e073a249f9a31d4ea5fd90d506f126aada2bf93ec0dcfa47fc135383c1cc`다.

관리자231→A→B/C 경유로 원본·unit 파일/실행 인자·socket 권한·machine-id 결속·설치 이력을 확인했다. root·기존 그룹·NoNewPrivileges·cap_dac_read_search·ProtectSystem=strict·PrivateTmp/PrivateNetwork·AF_UNIX·128MiB/8tasks를 유지한 별도 일회성 unit이다. 결과 쓰기만 자체 폴더에 허용하고 운영 reader의 소켓을 새로 bind하지 않았다. 후보 함수를 호출하고 **기존 모듈의 validator**로 검증했다. 실제 MCP·모델·채팅은0이며 운영 reader 재시작도 없다.

## 시각 경계의 누락 방지

이전 후보는 native 검색 시각을 초 단위로 넓힌 뒤 Python에서 마이크로초 범위를 재검사했다. 요청 종료 직후의 같은 초에 로그100개가 몰리면 native `--lines=limit+1`을 채워 범위 안의 로그2개가 밀려나는 반례를 재현했다. 반환 표본의 한계를 밝히더라도 필요한 근거를 빠뜨릴 수 있어 수정했다.

현재 후보는 `--since=@초.마이크로초`·`--until=@초.마이크로초`를 정수 연산으로 구성한다. 요청·각 분할의 native 경계도 정확히 유지하며 기존 재검사·경계 중복 제거·cursor 충돌 거절을 계속 적용한다. 범위를 넓히거나 기간·행·전체 바이트·공유20초·명령12초·마스킹·UID/rate 제한을 줄이지 않았다. 이전 모듈에 대한 새 반례는 의도한 누락 실패1개를 확인했고, 수정본은 journal33/진단43/이력24/인벤토리15/설치20, **135검사 통과·생략0**이다. 이 검사는 실제 OS 전체 설치가 아니다.

## 채택하지 않은 비용 실험

초기 분할 후보 `e1726ed8…`는 같은 제한 환경에서 A12.123초 실패, B13.147초/C0.669초 반환이었다. A의 역순 검색, unit 필드 직접 검색, 같은 literal의 trie, anchored precheck, 시스템 journal 한정도 모두 명령 또는 공유 시간예산을 넘겨 채택하지 않았다. 필드 직접 검색/시스템 한정의 범위 동등성을 운영 변경 근거로 인증하지 않는다. 단일 `RuntimeError` 검색은 약3.973초였으나 필요한 다른 오류를 빼므로 해결안이 아니다.

설치된 systemd는255.4-1ubuntu8.18이다. [공식255 매뉴얼](https://www.freedesktop.org/software/systemd/man/255/journalctl.html)과 [해당 버전 소스](https://github.com/systemd/systemd/blob/v255/src/journal/journalctl.c)를 참조했다. `--grep`과 양수 `--lines`의 조합은 이미 역순을 포함하므로 별도 `--reverse`를 성능 해결로 간주하지 않았다. 시간 초과가 정규식 필터 단계에 집중된 것은 직접 관측이며, 특정 내부 함수가 단독 원인이라는 프로파일 결과는 없다.

## 시험 오류·정리와 다음 단계

첫 A unit은 PrivateTmp가 `/var/tmp`를 가려226/NAMESPACE로 시작하지 못했다. 자체 `/var/lib` 경로로 정정했다. 다음 A의 `a:waf`는 runtime 관측 대상이며 journal unit이 아니어서 올바르게 거절됐다. 등록된 `a:rule-worker`로 정정하고 B/C 대상도 실제 스키마와 대조했다. 두 오류를 운영 장애·모델 오답으로 집계하지 않으며 원문과 정정 순서를 보존한다. 이전 B의 `active.json` 부재는 `prepared.json`과 운영 증분 영수증을 대조했으며 초기 설치를 다시 실행하거나 이력을 소급 작성하지 않았다.

일회성 unit15개 종료·PID 부재, 파일별 SHA/원문 보존 후 자체59파일424,793바이트를 제거했다. A/B/C의 운영3소스·unit 파일·reader PID/시작 ticks는 전후 그대로이며 모두 active다. journal/사건 DB·운영 복구본·기존19파일 PREPARED 계획은 보존했다. Mac 자체 임시59파일933,944바이트도 최소재현15소스 보존 뒤 제거·부재 확인했다. 재사용할 C 접속 helper는 로컬 소스로 보존한다. 새 패키지·이미지·포트·권한·서비스 정책 변경0이다.

현재 소스는 **경계 누락 수정·격리 검증 단계**다. A의 긴 검색을 해결하고 같은 범위·정답·제한을 확인한 뒤 정확 적용/원복 계획을 만들며, 승인 후 운영 reader·실제 비특권 MCP·새 봇 채팅·확정을 검증해야 한다. 적용 서비스/원복 타이머는 만들지 않았다. 공식 Harness²는 하네스 변경이 없는 이번 백엔드 검증에 사용하지 않았으며, 하네스 후속은 정해진 Harness² 절차를 따른다.

## 후속 비용 실험

[공식API·최대2개 읽기](../journal-native/README.md)는 같은24h11.946초·구간검사합32004/선택0·동일표본cursorSHA를 확인했다. 요약 프로토타입이며 위8f6c 후보·운영 source는 그대로다. 표준MCP응답·마스킹·파일실패·전체byte·고용량/취소·A/B/C·설치/승인/운영 검증이 남는다.
