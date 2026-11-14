# journal native API의 비용·가능성 실험

**A의 같은24시간 오류 후보를 공식 API와 최대2개 동시 읽기로11.95초에 검사한 격리 요약 프로토타입이다. 표준 MCP 응답 어댑터·운영 적용은 아직 없다.** [수치·실패·한계 원장](validation.json) · [현재 경계 후보](../../mcp/journal-window-slices.md) · [현황](../../../STATUS.md).

## 직접 관측

| 경로 | 결과 | 해석 |
|---|---|---|
| 기존 고정 grep6시간 |12.010초 timeout, child user9.749+system1.681=11.430 CPU초 |해당 실행의 major fault·블록 입력0. 네트워크 전송보다 로컬 검색 비용을 먼저 점검한 근거이며 특정 함수만의 병목이라는 profiler 증거는 아님 |
| 기존 고정 grep15분 |0.923초·반환 표본0 |기간을 줄이면 빨라지지만24시간 요청의 해결안으로 쓰지 않음 |
| 공식 Reader public API |6시간5.692초, 단일24시간은11.5초 내부 시험 한도 실패 |읽기 API 교체만으로 충분하지 않음 |
| 필요한 필드만 읽기·Python bytes regex |전체20초 실패 |버전 고정 C binding 시험, 그대로 채택 안 함 |
| 같은 PCRE2 패턴 JIT·순차8검색 |24시간4분할19.295초 반환 |20초 예산 여유가 작고 FFI가 필요해 우선 도입안으로 택하지 않음 |
| 공식 Reader public API·2개 동시 |24시간4분할11.946초 반환 |각 child5.410/6.174/5.890/5.763초. 요청 범위 보존·전체20초/개별12초 유지 |
| 기존1마이크로초 표본 |동일한 커서 기반 SHA·1건, 병렬 프로토타입의 선행 읽기0.123초 |전체 응답·마스킹·실제 MCP의 동등 검증을 뜻하지 않음 |

고정 구간은 `2026-11-14T03:24:10.795222+09:00`~`2026-11-15T03:24:10.795222+09:00`다. 병렬 시험의 구간 검사량 합은 **32,004회·선택된 오류 후보0개**다. 분할 경계 중복이 가능하므로 고유 로그·전체 경보 수가 아니다. 확인 가능한 source를 순회한 시험이며 journal 보존·모든 파일의 완전성·전체 오류 부재를 인증하지 않는다. 최종 운영 계약에서도 전체 건수 null/보존 미확인·비신뢰 증거를 유지해야 한다.

각 변형1회·부하/디스크 캐시 비통제다. 실제 MCP/모델·Mattermost 수신/큐/전달0, 봇 응답시간·p95·학습 우위로 환산하지 않는다. 현재 canonical8f6c와 운영8336은 그대로이며 그 코드의 A 시간 초과가 해결됐다는 뜻도 아니다.

## 환경과 출처

관리자231→A에서 기존 `python3-systemd 235-1build4`, `libsystemd0 255.4-1ubuntu8.18`, `libpcre2-8-0 10.42-4ubuntu2.1`을 확인했다. 설치0, B/C 의존성은 이번에 새로 대조하지 않았다. [공식 Python binding](https://github.com/systemd/python-systemd/tree/v235), [systemd255 unit 필터](https://github.com/systemd/systemd/blob/v255/src/shared/logs-show.c), [PCRE2 호출부](https://github.com/systemd/systemd/blob/v255/src/shared/pcre2-util.c), [공식 JIT 설명](https://www.pcre.org/current/doc/html/pcre2jit.html)을 참조했다. 입력은 root core의 고정 pattern과 등록된 A unit이며 임의 unit·정규식·경로를 요청자에게 허용하지 않았다.

별도 unit은 기존 root/group·NoNewPrivileges·cap_dac_read_search·AF_UNIX·PrivateNetwork/PrivateTmp·ProtectSystem=strict·128MiB/8tasks 설정을 유지했다. 독립 시험 여러 개를 담은 unit watchdog45/65초와, 각 조회의20초/12초는 구분한다. 병렬2개의 부모/스레드/자식은 최대5tasks다. A는 관측 시2CPU·affinity2, 가용 메모리 약4.46GiB였다. 시험 unit 종료 기록은23.150 CPU초·메모리peak `2.8M`이며 공유 mmap을 포함한 프로세스 RSS와 같은 지표가 아니다.

공식 API public 메서드는 전체 필드 변환과 EOF 처리 특성이 있다. production의 실패/빈 결과를 혼동하지 않도록 버전 고정 저수준 binding 사용 여부와 호환성을 추가 검증해야 한다. 현재 프로토타입의64KiB MESSAGE/250,000회 스캔/11.5초 내부 안전장치를 최종 도구 계약으로 인증하지 않았다. 성공1회만으로 이를 초기 설치 입력이나 운영 source로 승격하지 않았다.

## 다음 구현의 필수 조건

- 현재25개 등록 systemd unit·A/B/C 역할을 공통으로 처리한다. 프로토타입의 A 고정 조건을 production 예외로 복사하지 않는다. `journal_scope=all`과 오류 후보를 구분하고 debug를 임의 누락하지 않는다.
- 기존 unit의 서비스 자체·PID1/UNIT·root/OBJECT·coredump 조건, 정확한 KST/마이크로초·우선순위·마스킹·cursor/SHA/중복 충돌 검사를 보존한다. 고정 오류 pattern과 native 선택의 동등성을 양성·음성·변형 입력으로 대조한다.
- 전체 필드 변환의 빈 dict를 EOF로 잘못 읽거나, 접근 불가/손상 파일·중간 읽기 실패를0건으로 바꾸지 않는다. 기존 journalctl의 경고/실패 감지를 유지할 전후 접근 검사와 child stderr 검증이 필요하다.
- 동시2개·전체20초·개별12초·요청 전체 바이트·128MiB/8tasks를 유지한다. 단일 실패·취소·종료·남은 child를 검증하고 오래된 불필요한 조회를 무제한 선행 실행하지 않는다.
- 병렬 source가 마스킹 전 큰 출력을 쌓지 않게 한다. 공통 정규화/마스킹을 child 안에서 수행해 내부 패킷을64KiB 안에 두는 방안을 검토하되, 조기 잘림이 전역 최신 tail을 바꾸거나 오래된 로그를 앞당기면 기각한다. 정렬 경계/누락 witness·중복·동일시각·대형/이진/다중 필드 반례가 필요하다. 현재 이 방식은 설계 제안이지 구현 완료가 아니다.
- 표준 응답·기존 validator·고용량/오류 반례·실제 Linux source를 통과한 뒤 같은 작업에서 `deploy.sh`의 내부 source/설정·오프라인 의존 목록을 맞춘다. A/B/C 패키지/원본 SHA·권한·정확 적용/원복·관리자 승인·실제 비특권 MCP·새 채팅·확정은 별도 단계다.

## 실패·정리

처음 임시 경로와 basename/절대경로 비교 오류는 로컬에서 실행 전 정정했다. 첫 JIT의 함수명이 결과 목록과 충돌한 TypeError도 측정 실패로 보존했다. 이름을 구분하고 고정 literal·NUL·양성/음성 smoke 뒤 JIT2를 측정했다. 이를 라이브러리/운영 장애·모델 오답으로 세지 않는다.

A의 별도 unit7개 종료·PID 부재와 source/manifest SHA를 확인하고28파일222,046B·7폴더를 제거했다. A의 진단3source/unit/reader PID·시작ticks는 전후 같고 active다. B의 기존19파일 PREPARED·before19 SHA와 두 채팅/자동조사timer도06:05에 확인했다. 운영 source/서비스/DB·권한·패키지·공격·새 학습 변경0이다. 최소재현12소스와 실험 원문은 로컬 기록에 보존하고 Mac 자체 임시26파일405,428B를 제거·부재 확인했다. 기존 복구본·G_Harness2·자료/가중치와 원래 다른9파일을 보존한다.
