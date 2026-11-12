# Wazuh rule 203(에이전트 버퍼 가득 참) 근본 원인과 B rootcheck 후보

2026-11-13 KST. **02:15 사용자 승인으로 B에 적용했다.** 재시작 직후 스캔에서 효과를 확인했으며 최종 판정은 다음 12시간 주기(약 14:15 KST) rootcheck에서 한다. 적용은 관리자231 경유로 기존 설치기 동작(`siem_host_agent.py tune-rootcheck --layout groot`)을 실행했다. [현황 #7](../../../STATUS.md) · [작은 원장](validation.json) · [11/10 1차 분석·버퍼 확대](../../hermes/latency-and-queue-20261110.md#2-에이전트-큐가-가득-찼다-wazuh-에이전트-버퍼).

## 경과

| 시점 | 내용 |
|---|---|
| 11/10 | rule 203 "Agent event queue is full. Events may be lost."를 B 에이전트 버퍼 포화로 확인. B 버퍼를 기본 5000/500에서 **20000/1000**으로 키움(18:44, `tune-buffer`). 효과 확인은 다음 rootcheck로 미룸 |
| 11/11~13 | 버퍼 확대 후에도 **11/11 06:45·11/12 13:38·11/13 01:43에 재발**. 1차 조치로는 해결되지 않음 |
| 11/13 | 근본 원인 확인(아래)과 후보 작성 |

## 근본 원인 (라이브 B 읽기전용 관측)

| 근거 | 관측값 |
|---|---|
| 에이전트 로그 | 01:39:32 rootcheck 시작 → 01:39:47 버퍼 90%→가득 참 → 01:39:54 회복. 같은 주기의 SCA·FIM에는 경고 없음 |
| 매니저 rootcheck 결과(agent 003 `pm_event`) | 마지막 스캔 **24,488건**. 전부 "File … is owned by root and has written permissions to anyone"이며 경로는 **`/var/lib/docker/rootfs` 17,105건 + `/var/lib/docker/containerd` 7,373건** |
| Docker 저장 방식 | `overlayfs` + `driver-type io.containerd.snapshotter.v1`(containerd 이미지 저장소). 이미지 계층이 위 두 경로에 있음 |
| 현재 rootcheck 제외 | 패키지 기본 `/var/lib/containerd`·`/var/lib/docker/overlay2`뿐이라 위 두 경로가 빠짐 |
| 두 경로 제외 시 잔여(`find` 추정) | **20건** |
| 에이전트 상태 | 현 기동 이후 생성 162,577건·전송 152,170건(제어 메시지 포함). 최소 약 10,400건이 전송되지 못함 |

결론적으로 12시간마다 rootcheck가 컨테이너 이미지 내부 파일 약 2.4만 건을 보고해 20000 버퍼를 약 15초 만에 넘기고, 그동안 다른 이벤트(journald·FIM 등)도 유실될 수 있다. 버퍼를 더 키우는 것은 근본 해결이 아니다. 2.4만 건은 호스트 관점에서 의미 없는 노이즈이고, 진짜 호스트 이상을 묻어 버린다.

## 후보

`deployment/siem_host_agent.py`

- `ROOTCHECK_IGNORE = ('/var/lib/docker/rootfs', '/var/lib/docker/containerd')`와 `tuned_rootcheck()`를 추가했다. rootcheck 블록이 정확히 1개이고 `disabled=no`·`check_sys=yes`일 때만, **없는 ignore 줄만** 기존 ignore 뒤에 추가한다. 다른 바이트는 유지하며 반복 적용해도 결과가 같다. 조건이 다르면 거부한다.
- 새 설치 후보(`candidate()`)에 같은 변환을 적용한다.
- 기존 설치는 `tune-buffer`와 공유하는 `_tune()` 흐름을 쓰는 **`tune-rootcheck`** 동작으로 적용한다. 순서는 영수증 검증 → 백업(`ossec.conf.before-rootcheck-<시각>`) → 4개 데몬 `-t` → 재시작 → 연결 확인 → 영수증 `config_sha256` 재결속이며, 실패하면 원래 설정으로 복원한다.
- rootcheck 자체·`check_sys`·호스트 경로·Docker named volume(`/var/lib/docker/volumes`, 영구 데이터)은 계속 검사한다. 버퍼 값과 다른 수집 설정은 바꾸지 않는다.

| 검증 | 결과 |
|---|---|
| 로컬 테스트(`deployment/tests/test_siem_host_agent.py`) | 19/19. 삽입 위치·바이트 보존·멱등, ignore 일부/전무 배치, 블록 없음·중복·비활성·check_sys 꺼짐 거부, 새 설치 후보 포함, `tune-rootcheck` 성공(백업·`-t` 4회·재시작·영수증)·문법 실패 복원·이미 적용 시 무변경 |
| 라이브 드라이런(B 읽기전용, 01:59) | 영수증 SHA=라이브 설정(`53ef9794…`). 변경은 **ignore 2줄 추가뿐**(제안 SHA `157594ee…`). 임시 사본 문법검사는 agentd·logcollector·syscheckd(rootcheck 파서) 통과. modulesd는 `-c` 미지원이라 실제 적용 시 제자리 `-t`로 검사함. 임시 사본 삭제·라이브 불변 확인 |

## 적용 결과 (11/13 02:15, 사용자 승인, 관리자231 경유)

커밋 `1d5fa39`의 `siem_host_agent.py`(SHA `5a1cfbe5…`)를 그대로 B에서 `tune-rootcheck --layout groot`로 실행했다. 설정 SHA는 `53ef9794…`→`157594ee…`로 바뀌었고 드라이런 예측과 같다. ignore 2줄이 추가됐고, 백업 `ossec.conf.before-rootcheck-20261113T021501`, 4데몬 `-t`, 재시작(02:15:07 active), 연결, 영수증 재결속을 확인했다.

| 항목 | 적용 전(01:39 스캔) | 적용 후(02:15:05~02:16:25 스캔) |
|---|---|---|
| rootcheck 결과 | 24,488건 | **8건**(`/var/lib/capstone-harness-updates/…`) |
| 컨테이너 이미지 경로 | 24,480건 | **0건** |
| 버퍼 경고·rule 202~205 | 90%→가득 참 약 7초 | **없음** |
| 에이전트 생성/전송 | 최소 약 10,400건 미전송(직전 기동 이후) | 995/1,001(제어 포함), 미전송 없음 |
| 매니저의 에이전트 상태 | — | 3개 모두 Active |

재시작 직후 스캔은 11/10 재시작 때 포화를 일으킨 바로 그 시작 스캔이다. 그래서 이번 결과는 같은 조건에서의 비교다. 최종 판정은 다음 12시간 주기 rootcheck(약 11/13 14:15 KST)에서 rule 203이 없는지로 한다(미확인).

## 적용과 효과 확인 절차

1. 관리자231 경유로 B에서 `python3 -B deployment/siem_host_agent.py tune-rootcheck --layout groot`를 실행한다(설치 경로의 동일 코드 사용).
2. 재시작하면 수 분 안에 rootcheck가 다시 돈다. 11/10 재시작 때는 약 1분 뒤에 돌았다. 그 스캔에서 다음을 확인한다.
   - 에이전트 로그: `Ending rootcheck scan` 전후로 `Agent buffer` 경고가 없는지
   - `pm_event`: 새 스캔 결과에 두 경로가 없고 수십 건 이하인지
   - `wazuh-agentd.state`: 생성과 전송의 차이가 늘지 않는지
3. 재시작 직후 `scan_on_start` 일괄 전송으로 한 번 포화할 수 있다(11/10 18:44 사례). 따라서 최종 판정은 **다음 12시간 주기 rootcheck**에서 rule 203이 없는지로 한다.
4. 실패 시 `_tune`이 자동 복원한다. 수동 복구는 `/var/lib/capstone-siem-host-agent/ossec.conf.before-rootcheck-*` 백업으로 한다.

## 함께 드러난 사항 (조치 미실행)

- **누구나 쓰기 가능한 민감 백업(B)**: `/home/groot_b/capstone/wazuh/single-node/secbak-20260926-121235/` 아래 Wazuh 인덱서 보안 설정 백업 10개(internal_users.yml·roles.yml·config.yml 등)가 root 소유·o+w다. 파일 내용은 열지 않았다. 이 파일들은 잔여 추정용 읽기전용 `find`로 찾은 것이다. rootcheck는 적용 전후 어느 스캔에서도 이 파일들을 보고하지 않았으므로(정정: 처음에는 "rootcheck 노이즈에 묻혀 있던" 것으로 적었음) rootcheck만으로는 드러나지 않는 실제 호스트 이상이다. 권한 축소나 백업 정리는 보호 변경이라 별도 승인이 필요하다. 그 밖에 `/var/lib/capstone-harness-updates/20261103-r1/validation/native/*` 8개, `/opt/capstone-automation/venv/.lock`, `/var/backups/capstone-hermes-reasoning-20261015/…/guard-final-validation.json`도 o+w다.
- **A(groot-sec)의 203**: 10/29 17:02~04(47), 11/2 14:42~44(36·15:19 1), 11/5 17:54~55(23), 10/31 03시(1). rootcheck는 19건뿐이라 원인이 아니다. 각 2~3분 집중이며 A는 Suricata eve·ModSecurity·Vector 정규화 로그를 수집하는 센서이고 버퍼는 기본 5000/500이다. 시험 트래픽으로 센서 로그가 폭주한 구간으로 **추정**하며, 시험 시간대와의 대조는 정황 증거다. 11/5 이후에는 재발이 없다(공격 시험 중단). 공격 시 탐지 이벤트 유실 위험이므로 A 버퍼 상향 후보가 필요하다. 다만 11/10 분석대로 A 에이전트 설정 SHA가 수집 가드 고정값(`wazuh_config_sha256`)에 묶여 있어 같은 단계에서 갱신해야 한다. 이번 후보에는 포함하지 않았다.
