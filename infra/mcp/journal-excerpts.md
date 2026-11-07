# 제한된 서비스 journal 조회 후보

2026-11-08. 기존 `get_system_diagnostics`에 `view="journal"`을 추가하는 **구현·격리 검증 후보**다. 운영 A/B/C 적용과 두 봇의 자연어 채팅 시험은 아직 하지 않았다. 현재 운영 MCP1.2.8과 후보1.3.0을 구분한다. [검증 원장](journal-excerpts.validation.json) · [현재 상태](../../STATUS.md).

정제 이력에는 본문이 없어 모델이 오류 원문을 요청해도 실제 근거를 가져오지 못했다. 이 기능은 실제 journal의 메시지를 읽되 비밀 값과 비정상 형식을 처리한 `message_excerpt`를 제공한다. 기존 메타데이터를 원문처럼 재작성하지 않는다.

| 입력 | 제한 |
|---|---|
| `target` | 기존 등록 systemd25개 중 하나, 서버 역할 일치 필수 |
| `view` | `journal`, 생략 시 기존 스냅샷/정제 이력 유지 |
| `since_kst`, `until_kst` | 둘 다 필수, 초/선택적 마이크로초와 `+09:00`, 최근30일 안의 최대24시간 |
| `journal_scope` | 기본 `errors`: 고정 오류 후보 필터. `all`: 모든 우선순위의 제한 표본 |
| `limit` | 1~50, 기본20. 최신 순 표본이며 전체 보존 건수가 아님 |

```json
{"target":"b:management","view":"journal","since_kst":"2026-11-06T16:20:00+09:00","until_kst":"2026-11-06T16:40:00+09:00","journal_scope":"errors","limit":50}
```

`errors`는 priority0~3과 priority4~6 중 기존 오류 문자열 후보를 합친다. 모든 오류의 완전한 분류·탐지를 뜻하지 않는다. `all`에도 보존 범위·행/바이트 상한이 있으므로0행을 무장애·침해 부재로 해석하지 않는다. 과거 원문은 현재 서비스 가동이나 복구 완료의 증거가 아니다.

## 권한·전송·반환

- A/B/C의 `capstone-journal-reader.service`가 root로 고정 읽기만 수행한다. 연결은 root 소유 `/run/capstone-journal/read.sock`(0660, 기존 진단 그룹)으로 제한하며 외부 TCP 포트를 열지 않는다.
- 클라이언트는 socket 서버의 root UID를 확인하고, 서버는 `SO_PEERCRED`로 기존 MCP/강제 읽기 계정 또는 root를 확인한다. 계정에 journal 그룹·일반 sudo·셸·Docker 권한을 부여하지 않는다. A/C는 기존 호스트 키 고정 SSH 강제 reader를 경유한다.
- unit·명령·파일 경로·정규식·SSH 옵션을 호출자에게 받지 않는다. 등록 target은 고정 `journalctl` argv로만 변환한다. source query의 초 단위 경계를 넓힌 경우 반환 전 마이크로초 구간을 재검증한다.
- 입력4KiB, journal 각 조회1MiB, 조회 합계 최대8초, 메시지8KiB, 결과60,000바이트, 계정당10회/분·전체30회/분이다. 바이트 제한으로 일부 행을 빼면 `response_size_limited`와 `has_more`를 명시한다. 큰 메시지·비문자 메시지는 사유와 함께 본문을 미반환한다.
- 메시지의 password/token/key·인증/쿠키·URL 자격·환경/HTTP 본문·개인키·불투명 문자열을 마스킹한다. 알려진 고정 진단 코드·등록 unit은 보존한다. 임의 비밀을 모두 탐지한다고 보장하지 않는다. 제어 문자·방향 전환 문자도 처리한다.
- 원문 메시지 SHA·반환 excerpt SHA·커서 SHA·시각·우선순위·변형/미반환 상태를 구분한다. 마스킹 전 본문·환경·커서 자체는 별도 파일에 저장하거나 반환하지 않는다. 감사에는 요청 대상/기간·결과 건수/해시·고정 실패 코드만 남긴다.
- `raw_messages_returned=false`, `redacted_excerpts_returned=true`다. 원문 바이트와 동일한 자료라고 주장하지 않는다. 반환 로그는 신뢰하지 않는 증거이며 지시·승인으로 취급하지 않는다.

## 실제 검증과 발견한 실패

Mac 표준 라이브러리104검사(기존43·이력24·원문17·설치20), B Linux83검사(원문16까지)를 확인했다. 마지막 강제 reader 연결 검사는 Mac에서 추가했으며 Linux83개에 포함하지 않는다. 새 패키지 설치는 없었다.

첫 후보는 열린 파일 한도를64개로 제한해 journal 파일 일부를 건너뛰었다. stderr 경고로 조회를 거절했고 이를0건으로 반환하지 않았다. 한도를1,024개로 조정했으며, grep뿐 아니라 모든 journal 모드에서 stderr가 발생하면 부분 자료를 성공으로 반환하지 않도록 검사했다. 상한을 없애거나 오류를 숨기지 않았다.

B의 운영과 분리한 동일 sandbox 서비스에서 실제 `mcp` 계정→Unix socket→고정 journal 조회→후보 MCP 응답을 확인했다.

| 시험 | 결과 | 시간 |
|---|---|---|
| 11/6 16:20~16:40 KST 오류 후보 | 32행, 그중 원문 `controller_already_running`8행, 메시지/반환 SHA 확인 | 0.452초 |
| 같은 구간 all·limit1 | 1행·has_more=true | 0.301초 |
| `/etc/shadow` 경로 인자 삽입 | isError=true·unavailable, 파일 조회 없음 | 0.265초 |

각1회 도구 시험이며 봇 채팅 지연·일반 오류 판단 정확도·A/C 실제 전송은 측정하지 않았다. 임시 서비스·socket·반입 소스를 제거했고 마스킹된 시험 결과와 해시 원장만 root 전용 검증 위치에 보존했다. 운영 봇·원본35B·FW/승인·학습 상태는 변경하지 않았다.

## 설치와 남은 적용

초기 진입점 `deploy.sh`의 기존 진단 설치 단계가 `diagnostic_journal.py`와 역할별 고정 service를 배포·활성화·검증하도록 맞췄다. Python 표준 라이브러리·기존 systemd/journalctl/SSH를 사용해 새 패키지·이미지·설정 비밀이 없다. 별도 관리용 설치 진입점은 만들지 않았다. 실제 새 OS 전체 설치는 미시험이다.

다음은 A/B/C 사전 상태·정확 후보 SHA·독립 원복을 준비한 증분 배포, A/C 강제 reader·B 실제 MCP SDK 호출 검증, 양봇의 필수 원문 조회/후속 판단/표시 연결이다. 현재 하네스는 새 `journal_excerpt`를 메타데이터와 구분해 표시하는 보완도 필요하다. 새 기능 이름만 노출하고 전체 조사를 완료했다고 선언하지 않는다.
