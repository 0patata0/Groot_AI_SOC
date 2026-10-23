# Suricata 원본 회전의 native 격리 시험

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 현재 운영 경로는 Vector v2와 세대별 원본 회전·출력 유지관리·이전 부트 로컬 보존이다. Python 수집기·WAF v1 결합/초기 회전 시험은 과거 단계다. A→B 이전 로그의 일부 자동 이관과 전체 과거 로그 무손실 회수 완료를 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

**2026-10-14 20:44 KST 관련 단계 갱신:** 아래 Suricata 시험과 별도로 [WAF 전용 격리 시험](../waf-rotation/README.md)도 통과했다. 새 audit/access 경로·새 배포 ID를 쓰는 4세대 6요청(2/1/1/2)에서 늦은 이전 worker 기록, reader 정지 중 연속 두 회전, 세 번의 인접 공개, 동일 checkpoint 정상 재시작을 확인했다. Vector audit/access 각각 6건·Wazuh audit 6건, 중복 0건이다. Vector의 원문 행 SHA와 Wazuh의 native cJSON 재직렬화 SHA를 구분했고, Wazuh SIGTERM 종료 코드 1·최종 offset/SHA 및 Vector 종료 코드 0으로 정상 종료를 확인했다. [WAF 검증 결과](../waf-rotation/validation-2026-10-14.json).

별도 보관본 결합은 6쌍의 ID·KST 시각·SHA 일치, 잘못된 배포 ID 4건 격리, audit 격리를 관측한 뒤 실행 시작 약2.51초에 짝을 추가한 사례의 ready 0·quarantine 1·access 단독 제외 1을 확인했다. 이는 신뢰 manifest로 source 메타데이터를 복원한 오프라인 시험이며 실시간 join 검증이 아니다. 운영 copytruncate는 유지하고 UID 101 writer 재현·원격 ACK·crash/재부팅 복구는 미완료다. 이번 WAF 회차는 20:44:38 운영 보호59파일·서비스·PID/CID 불변을 확인했고 20:45:57 원본205파일을 A 영구 경로에 SHA 대조 보관했다. 소스 보관/작업경로 정리는 후속 마감으로 기록한다. 아래 Suricata 시험 이력과 소스는 변경하지 않았다.

**2026-10-14 native 격리 시험 통과, 12:22 KST 정리 재확인. 운영 copytruncate는 유지한다.** 기존 Suricata 8.0.6·Vector 0.59.0·Wazuh 4.14.8의 설치 바이너리를 별도 프로세스로 실행했다. 고정 alias를 지연 공개한 Vector·Wazuh는 합성 6개를 각각 정확히 한 번 수신했다. 단순 rename 대조군은 두 reader 모두 늦은 행과 중간 세대의 2개가 빠져 4개를 수신했다. 전체 결과·시도 이력·소스 SHA는 [검증 JSON](validation-2026-10-14.json)에 보존한다. 새로운 수집 서비스나 Python collector, 운영 자동 회전기를 배포한 결과가 아니다.

## 확인하려는 전환 조건

Suricata가 쓰는 `logs/eve.json`과 두 reader가 읽는 `reader/eve.json`을 같은 inode의 hardlink로 시작한다. writer 파일은 rename/create하고 다음 합성 PCAP 쓰기로 재오픈을 유발한다. reader 이름은 이전 세대에 둔다. 다음 조건을 모두 확인한 뒤에만 reader 이름을 다음 **인접 세대**의 inode로 원자 교체한다.

1. 정확한 시험 writer의 PID·시작 tick·컨테이너 PID namespace·설정 경로가 일치하고 이전 쓰기 FD가 0이다.
2. Vector의 별도 파일 sink와 Wazuh의 별도 Unix datagram queue에 이전 세대의 마지막 표식이 도착했다.
3. Wazuh의 private `file_status.json`에 해당 경로가 하나이며, 논리 offset이 파일 크기와 같고 prefix SHA1이 전체 파일 SHA1과 같다. 임시 읽기 FD의 끝 위치만으로 통과시키지 않는다.
4. 이전 archive를 보존하면서 다음 세대 hardlink를 `rename`으로 공개한다. 두 번 회전했다면 중간 archive부터 순서대로 공개한다.

이것은 **시험에서 관찰한 로컬 reader 완료**다. 운영 Vector sink의 ACK, Wazuh agentd/manager/Indexer 수신 확인, 강제 종료·전원 장애 영속성을 뜻하지 않는다. 운영용 자동 제어기는 아직 없으며 성공해도 기존 raw 회전을 곧바로 교체하지 않는다.

## 시험 순서

| 단계 | 확인 |
|---|---|
| 빈 파일에서 시작 | 두 private Wazuh가 각각 빈 inode를 연 뒤 첫 PCAP을 넣는다. 초기 EOF 시작으로 표식이 누락되는 오해를 피한다. |
| 단순 rename 대조군 | naive Wazuh가 새 빈 파일을 연 뒤 이전 writer에 PCAP을 하나 더 준다. 실제 시험에서는 Vector·Wazuh 대조군 모두 늦은 41002가 빠졌고, 고정 alias 경로 두 reader에는 남았다. |
| writer 재오픈 | 시험 Suricata에만 HUP을 보낸 뒤 다음 PCAP이 새 inode에 기록되고 이전 쓰기 FD가 사라지는지 확인한다. |
| 첫 지연 공개 | 이전 alias의 두 reader 완료를 확인한 다음 새 세대를 공개한다. |
| 두 번 회전·reader 일시 정지 | private Vector와 좋은 Wazuh만 SIGSTOP한 사이 두 세대를 더 만든다. 재개 후 중간 세대를 건너뛰지 않고 순서대로 공개한다. 대조군은 중간 41004도 빠졌으며, 지연 공개한 두 reader는 보존했다. |
| graceful 재시작 | private Wazuh 상태 저장과 정상 종료 후 Vector·Wazuh를 같은 private checkpoint로 재시작한다. 다음 표식까지 전체 6개가 각각 정확히 한 번 관찰되는지 대조한다. |
| 정리·운영 불변 | 시험 PID만 종료하고 두 임시 경로를 제거한다. 원래 Vector/Wazuh PID·시작 tick, Suricata container init, 운영 Wazuh root/queue inode가 같아야 한다. |

PCAP은 198.18.0.0/15의 고정 합성 Ethernet/IPv4/UDP 한 패킷이며 **네트워크로 송신하지 않는다**. source port 41001~41006만 결과의 표식으로 쓴다. 기존 컨테이너에서 `-r`, `--pcap-file-continuous`, `--runmode single`, `-S` 전용 룰, private PID/config/log 경로를 사용한다. 운영 Suricata의 PID 1이나 host main에는 신호를 보내지 않는다.

## Wazuh와 파일 격리

`wazuh-isolated.sh prepare`는 root 전용 `/var/tmp/capstone-raw-rotation.XXXXXX/{wazuh,naive-wazuh}`에 실행 파일·라이브러리·internal options만 복사한다. 운영 `ossec.conf`, `client.keys`, 원문 로그는 복사하지 않는다. 각각 합성 localfile 하나와 `remote_commands=0`만 설정한다.

`launch`는 clean environment에서 mount·network namespace를 만들고, **rprivate를 먼저 강제한 뒤** `/var/ossec` 전체를 private prefix로 bind한다. foreground exec의 PID는 호출자의 `$!`와 같고 private PID/state/queue를 사용한다. private queue 수신기는 같은 시험 Vector의 `unix_datagram` source다. 운영 manager에 연결하지 않는다. 경로 기반 Unix socket은 private 경로만 쓰며 외부 네트워크 인터페이스는 구성하지 않는다.

호스트 작업 경로와 기존 Suricata 컨테이너 `/tmp/capstone-raw-rotation.XXXXXX`를 만든다. reader alias는 writer와 같은 파일시스템인 컨테이너 임시 디렉터리에 둔다. 호스트 reader는 `/proc/<container-init>/root/tmp/...`로 합성 파일만 읽는다. 정상·실패 모두 확인 가능한 시험 프로세스를 종료한 뒤 이 두 경로를 정리한다. PID 확인 전 writer 시작에 실패해 안전한 종료를 증명하지 못하면 디렉터리를 보존하고 `cleanup_verified=false`로 보고한다. 무관한 프로세스를 이름으로 찾아 종료하지 않는다.

## 실행 파일과 현재 검증

- `preflight-a.sh`: 고정 A machine-id에서 버전·설치 파일 SHA·container/PID/root/queue inode만 읽는다. 운영 로그 본문은 출력하지 않는다.
- `make-pcap.sh`: 고정 합성 PCAP 생성. Mac 기존 Bash·stdlib로 7개 포트의 86byte 길이·PCAP 길이·UDP 포트·표식을 확인했다. 해당 임시 파일은 즉시 제거했다.
- `wazuh-isolated.sh`: private 복사·namespace foreground 실행 helper.
- `run-probe-a.sh`: 위 전체 시나리오. JSON 요약을 출력하며 실패 시 고정 합성 시험의 짧은 진단만 포함한다. 운영 로그 원문은 출력하지 않는다.

읽기 전용 A preflight는 Suricata 8.0.6, Vector 0.59.0, container main PID1534179를 확인했다. Wazuh 실행 파일 SHA256은 `bd4e4c31e8846a6bc43f7ffc4b8eec7df312ee9d31b02ad69106c413144d4b21`이다. 모든 shell 파일의 `bash -n`에 이어 실제 바이너리의 private 설정 검사·namespace·writer 재오픈·두 reader 검증을 통과했다. 최종 시험 writer hostPID1752894/시작 tick137593364는 종료됐고 호스트·컨테이너 시험 디렉터리는 각각 0개다. 원래 운영 PID와 Wazuh root·queue inode는 유지됐다.

처음 3번은 시험 구성 문제를 수정하며 중지했다. 1차의 `pcap-file.delay=0`은 오류 로그 후 기본 30초를 유지했고, 2차에서도 기본 30초가 시험의 20초 제한보다 길었다. 설치 버전 소스를 확인해 유효값 `delay=1`로 수정했다. 3차는 Wazuh 두 reader가 실제로 읽고 논리 offset을 저장했지만 시험용 Unix datagram 어댑터가 끝의 NUL을 JSON 본문으로 해석했다. 마지막 NUL 한 개를 framing으로 제거하고 control message를 구별한 4차가 통과했다. 1~3차도 시험 프로세스·파일 정리를 확인했으며, 이를 운영 엔진 장애나 운영 이벤트 손실로 기록하지 않는다. [Suricata PCAP delay의 기본값·허용 범위](https://github.com/OISF/suricata/blob/suricata-8.0.6/src/source-pcap-file.c#L324-L343), [Wazuh native queue 송신](https://github.com/wazuh/wazuh/blob/v4.14.8/src/shared/mq_op.c).

## 성공 뒤에도 필요한 운영 전환 검토

최소한 writer 경로와 reader alias의 초기 이전, 두 reader checkpoint의 출발 위치, 미공개 archive의 root 보존·용량 한도·재부팅 후 순서 복구, alias 교체 직전/직후 crash, 강제 reader 종료, 운영 Vector 완료 근거, 복구 실패 시 보류 정책을 결정해야 한다. 기존 입력 경로를 바꾸는 과정의 restart·미수집 구간도 별도로 검증한다. Suricata HUP이 새 YAML 설정을 읽어 writer 경로까지 바꾼다고 가정하지 않는다. 현재 probe의 메모리 순서는 영속 회전 이력이 아니며 자동 재실행하면 이전 운영 세대를 복구해 주는 코드도 아니다. WAF Serial audit에는 Suricata HUP 결과를 일반화하지 않는다.

근거: [Suricata 8.0.6 offline/continuous PCAP 옵션](https://docs.suricata.io/en/suricata-8.0.6/command-line-options.html), [Suricata 로그 회전](https://docs.suricata.io/en/suricata-8.0.6/output/log-rotation.html), [Wazuh 4.14.8 main의 home·foreground·queue 처리](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/main.c), [Wazuh inode 변경·중복 inode·논리 위치 처리](https://github.com/wazuh/wazuh/blob/v4.14.8/src/logcollector/logcollector.c), [Vector Unix datagram source](https://vector.dev/docs/reference/configuration/sources/socket/). 과거 writer 단독 시험과 현 운영 출력 회전은 [ROTATION](../../ROTATION.md) 및 [STORAGE](../STORAGE.md)를 구별해서 읽는다.
