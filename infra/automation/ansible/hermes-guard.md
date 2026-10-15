# Hermes 언어 가드의 고정 Ansible 재적용

## 2026-10-14 19:15 KST 읽기 관찰

고정 cutoff **19:15:03 KST** 기준 최근 5시간(14:15:03~19:15:03)과 observer 시작(02:57:21) 이후를 대조했다. Hermes의 container ID·StartedAt·가드/통합 소스 SHA는 기존 배포와 같고, observer는 `active/running`, 재적용 timer는 `active/waiting`, 마지막 재적용은 `success/0`이었다. 변경·재시작·모델 호출·채팅 발송은 하지 않았다.

두 구간 모두 `filtered/retained/requested_foreign/oversize` 진단은 각각 **0건**이었다. 현재 `gateway.log` 133,477바이트에도 가드 marker나 필터 형식 불일치가 없었다. 다만 **최근 5시간은 저장 assistant와 Mattermost 송신 ledger도 모두 0건**이어서 실제 사용 중 재발 여부를 판정할 표본이 없다. observer 시작 이후 저장 assistant는 12건(cron 9, Mattermost 3), Mattermost 송신 ledger는 `delivered` 2건이며, 이 제한된 저장 범위에서 고정 대체 안내 문구는 0건이었다.

전체 송신 원문을 수집하거나 한자·일본어 표면과 검증된 원문 인용을 재분류하지 않았다. 저장 assistant는 최종 송신 기록과 다르고 ledger는 독립 cron 전송 등 모든 경로의 분모가 아니다. `filtered`도 교정 성공과 대체 안내를 구분하지 않으므로 **교정 실패율·혼입률 0% 또는 전체 송신 무혼입을 뜻하지 않는다**. 가드 상태 확인은 완료했으며, 실제 사용 표본을 통한 재발 확인은 남아 있다. [관찰 메타데이터](hermes-observation-2026-10-14.json).

## 적용 경로

이 경로는 B 관리자가 실행하는 고정 playbook이다. MCP 도구·sudoers·LLM 권한에 연결하지 않는다. 가드 핵심, 현재 요청의 문맥과 원문 인용 보존, 조각 교정 및 전송 차단 정책은 기존 Python을 유지한다. 백업·복사·중지·시작·오류 복구 순서는 `ansible.builtin` 작업으로 이관했다. 기존 Python 배포기를 Ansible에서 호출하는 형태가 아니다.

2026-10-14 B에 적용했고 03:10:49 KST까지 최종 확인했다. 컨테이너를 생성하거나 이미지를 교체하는 기능은 없다.

같은 날 후속으로 운영 task를 읽은 **분리 native 복구 16개·경계 회귀 7개**를 통과했다. 실제 Docker 동작은 임시 파일 대역이므로 운영 재생성·강제 장애 검증과 구분한다. [시험 계약·결과·남은 공백](hermes-recovery-validation.md)을 참조한다. 운영 소스와 서비스는 변경하지 않았다.

04:34 KST에는 accepted 원본 백업에서 목표 패치 재생성과 별도 임시 target의 고정 regex cold 복원/실제 UID 검증도 완료했다. 실제 재생성은 하지 않았다. 재생성은 위 문서의 **시작 전 파일 검증 절차**를 별도로 준비해야 하며, 설정 수정·`rm -f`·즉시 기동을 포함한 과거 `deploy_gateway_B.sh`를 현재 서비스에 그대로 재실행하지 않는다.

## 실행 범위

```sh
# B root, 이미 설치된 Ansible 2.21.x만 사용
sh hermes-guard-local-b.sh syntax "$(cat /etc/machine-id)"
sh hermes-guard-local-b.sh check "$(cat /etc/machine-id)"
sh hermes-guard-local-b.sh apply "$(cat /etc/machine-id)"
```

`check`는 운영 코드·컨테이너 상태를 변경하지 않는다. wrapper의 root 전용 lock/temp 디렉터리 준비는 발생할 수 있다. `apply`는 설정이 이미 목표 상태인 경우 Hermes를 재시작하지 않고 실제 설치본의 가짜 HTTP 검증을 수행한다. timer/관찰 서비스와 영구 재적용 번들을 설치한다. 영구 번들의 같은 wrapper를 컨테이너 재생성 직후 관리자가 직접 실행할 수 있다.

```sh
sh /opt/capstone-automation/hermes-guard/project/infra/automation/ansible/hermes-guard-local-b.sh apply "$(cat /etc/machine-id)"
```

이미지 전체 SHA, entrypoint/command, `/opt/hermes-data` → `/opt/data` bind, 서비스 UID, CPython 3.13/x86_64를 검증한다. adapter/run_turn는 검토한 원본 두 SHA 또는 완전히 패치된 두 SHA만 허용한다. 부분 패치·알 수 없는 소스·알 수 없는 기존 core는 중단한다. core 자체도 playbook에 고정한 SHA와 일치해야 한다.

원본 wheel은 root 전용 `/opt/capstone-automation/artifacts/`에 보관한다. 정확한 버전·파일명·SHA는 [가드 lock](../../hermes/korean-output-guard-requirements.txt)을 따른다. target이 없는 새 컨테이너에서만 기존 `uv`로 `--no-config --no-deps --no-index --only-binary=:all: --require-hashes --no-cache --link-mode=copy`를 사용해 고정 regex를 복원한다. 기존 Hermes 프로젝트 의존성이나 전역 패키지는 바꾸지 않는다. 다른 ABI/이미지에는 자동으로 대응하지 않는다.

## 보존과 실패 처리

- heartbeat 45초 미만, 활성 agent/work 없음, 만료되지 않은 turn lease 0을 확인하고, 실제 중지 직전에 다시 확인한다. 처리 중인 요청이 있으면 재시도 때까지 적용을 보류한다.
- Mattermost draft 표면 4종의 `false` 설정을 읽기 확인한다. 모델/MCP/토큰/설정 파일을 재직렬화하거나 수정하지 않는다. 미리 안전하게 설정되지 않았다면 자동 변경 대신 중단한다.
- 순수 SHA 패처가 root 전용 임시 후보를 만들고 문법을 확인한다. Ansible이 원본 코드 백업을 보관하고 기존 컨테이너의 전체 ID에만 stop/copy/start를 실행한다.
- 컨테이너 정지 후 설정·SOUL·cron·DB/WAL/SHM의 바이트 SHA/소유권/권한을 기록하고, 시작 직전에 다시 대조한다. 설치 파일은 `docker cp`로 다시 읽어 정확한 SHA를 확인한다. 다른 컨테이너나 보안 worker는 재시작하지 않는다.
- 실패 시 native `block/rescue`가 원본 통합 파일과 기존 core를 복구하고 검증한다. 원래 core가 없던 원본 소스였다면 검증된 원본 통합을 시작한 후 새로 추가한 미사용 core를 제거한다. 설치된 고정 regex target은 복구용 의존성으로 남는다.
- 후보를 시작한 이후 gateway가 DB를 정상 갱신할 수 있으므로 옛 DB를 복원하지 않는다. 시작 전까지의 보존과 재시작 후 동작 검증을 구분한다. 복구 파일/보존 검증이 실패하면 정지 상태를 유지해 수동 확인을 요구한다.
- 정상 재적용은 가짜 HTTP 전송 검증 11개와 새 heartbeat를 확인한다. 실제 사용자 메시지를 게시하지 않는다. 모델 교정까지 확인하려면 기존 runtime verifier의 `--model`을 별도로 사용한다.

Ansible `rescue`는 전원 장애·Ansible 프로세스 강제 종료·unreachable/구문 오류를 트랜잭션처럼 되돌리지 못한다. 적용 중 강제 종료 후에는 root 전용 `/var/backups/hermes-ansible-guard-*`와 실제 컨테이너 상태를 관리자가 확인해야 한다. 이러한 장애를 일부러 유발한 운영 복구 시험은 별도다. [Ansible 공식 오류 처리](https://docs.ansible.com/projects/ansible-core/devel/playbook_guide/playbooks_blocks.html).

`update_rule_edit_policy_B.py`의 SQLite 여러 테이블·prompt cache migration은 이 자동화에 넣지 않는다. 단순 파일 치환으로 바꾸면 기존 대화 참조의 일관성이 깨질 수 있어, 검증된 별도 수동 유지보수 경로로 유지한다. 기존 `deploy_korean_output_guard_B.py`는 native 운영 경로 이관과 반복 적용 검증 후 미사용 중복 배포기로 삭제했다. 과거 배포 기록과 root 전용 복구 백업은 보존한다. 패처와 필수 읽기/런타임 검증은 계속 유지한다.

## 재생성 감지의 한계

`capstone-hermes-guard-reapply.timer`가 부팅 후 약 2분, 이후 작업 종료 약 5분마다 전체 container ID를 비교한다. 같은 ID는 빠르게 종료하고, 관리자가 새로 만든 `hermes`가 검토한 계약을 만족할 때만 같은 playbook을 적용한다. root 전용 lock이 동시 실행을 막는다. lock 경합의 75만 systemd에서 성공한 유예로 취급하며 고정 `deployment_busy` verdict를 남긴다. 미지 소스·유휴 조건·설정 검증 거절은 여전히 실패다. [systemd timer 공식 설명](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html).

**시작 전 강제 적용을 보장하지 않는다.** 재생성 직후 탐지 전까지의 시간, 바쁜 세션/오래된 heartbeat로 인한 유예, 알 수 없는 이미지·소스 거절로 인해 가드 미적용 구간이 5분보다 길어질 수 있다. 서비스의 실패는 journald/systemd에 남는다. 무가드 응답이 없어야 하는 운영 절차에서는 관리자가 채팅 사용을 열기 전에 위 고정 apply를 직접 실행하고 통과를 확인해야 한다. 이번 작업은 이미지/entrypoint/컨테이너 구성을 변경하거나 실제 재생성 시험을 수행하지 않는다.

## 본문 없는 장기 관찰

`capstone-hermes-guard-observe.service`는 기존 `gateway.log`의 새 행을 `tail -n 0 -F`로 따라가며, 정확한 logger 접두와 허용된 verdict/숫자만 awk로 다시 구성해 `capstone-hermes-guard` journald 태그에 기록한다. 원래 행·대화·HTTP/모델 본문·예외 문자열은 출력하지 않는다. 합성 비밀 문자열이 붙거나 다른 logger인 행은 제외한다. 로그 형식이 달라지면 수집이 조용히 누락될 수 있으므로 포맷 변경 시 재검토한다.

```sh
journalctl -t capstone-hermes-guard --since '-24 hours' -o cat --no-pager |
  awk '{for(i=1;i<=NF;i++) if($i ~ /^verdict=/) n[$i]++} END {for(k in n) print k,n[k]}'
systemctl status capstone-hermes-guard-reapply.timer capstone-hermes-guard-observe.service
```

이는 개입·원문 보존·명시적 외국어 요청 예외의 **관측 건수**다. 정상 한국어 응답은 현재 core가 진단 로그를 내지 않으며, 한 응답에 여러 전송 검사도 있을 수 있다. 따라서 전체 응답 대비 혼입률·고유 대화 건수로 해석하지 않는다. 서비스 중단 구간/과거 행은 소급 수집하지 않고, 재시작/회전 상황의 누락 가능성도 있다. journald 보존 정책을 전역 변경하거나 모바일/외부 알림을 새로 연결하지 않는다.

## 검증 상태

2026-10-14 후보 단계에서 B의 기존 Ansible 2.21.5로 syntax 및 `--check`가 `ok=21 changed=0 failed=0`으로 통과했다. read-only 보존 helper의 회귀 5개가 Mac/B에서 모두 통과했고, 실제 B 설치 소스의 임시 사본으로 패처 후보 SHA 2개를 재현했다. 합성 한 줄을 추가한 미지 소스는 거절됐다. 현재 설치본을 실제 서비스 UID로 검증한 가짜 HTTP 11개도 통과했으며 실제 채팅 게시 0건이다. 로그의 모의 HTTP 400은 thread-fallback 회귀가 의도적으로 만든 응답이다.

metadata filter는 Mac/B 모두 정상 행만 재구성하며 다른 logger·추가 본문·비밀 예시를 제외했다. 독립 검토에서 발견한 사전 조건 실패 시의 불필요한 rescue 진입은 수정했다. 최신 소스/설정·유휴·container ID 검사를 mutation block 밖에서 완료하므로 거절된 요청은 중지/복구 작업에 들어가지 않는다. 이 기록은 실제 native apply, 컨테이너 재생성, 장애 유발 rollback, 장기 실사용 완료를 뜻하지 않는다.

### 운영 적용과 최종 확인

- 첫 native apply `ok=41 changed=9 failed=0`, 영구 경로의 반복 apply `ok=40 changed=0 failed=0`. 기존 core/통합 SHA가 같아 후보 교체·Hermes stop/start는 모두 생략했다. metadata observer는 **02:57:21 KST** 시작했고 timer/observer는 enabled/active다.
- timer 최초 실행이 설치 작업의 lock과 겹쳐 exit 75를 실패로 표시했다. 이를 위 유예 정책으로 보완한 apply는 `changed=3`, 보완 후 반복도 **03:06:22 KST `changed=0`**이었다. 실제 lock을 잡은 합성 job은 `Result=success/ExecMainStatus=75`, lock 해제 후 동일 컨테이너 job은 `success/0`으로 확인했다.
- 03:00:24 KST에는 컨테이너 ID/image/StartedAt·config/.env/SOUL/cron 바이트/권한·DB 본체 바이트/권한·99 sessions/1,021 messages가 최초 기준과 모두 같았다. 최종에도 config/.env/SOUL 및 컨테이너 시작 시각은 같았다.
- 03:06:22의 전체 보존 대조는 자연 실행 데이터가 늘어 실패했다. 이후 기준 시각 이후 세션 2개가 모두 `source=cron`임을 확인했다(03:01:31~03:02:28, 03:07:30~03:08:32). 변경 파일은 `cron/jobs.json`뿐이고 last_status=ok/last_run 시각과 일치한다. DB quick_check=ok이며 WAL에 반영된 정상 새 대화를 옛 DB로 덮어쓰지 않았다.
- 실제 서비스 UID의 설치본 가짜 HTTP **11개 통과**, 실제 채팅 게시 0건. .111 `/api/tags`에서 기존 `qwen3.6:35b` 존재, MCP 5개 initialize/tools-list 모두 성공(8/8/2/14/3 도구)했다. 실제 보안 도구 호출은 0건이며 주 모델을 바꾸지 않았다.
- native `--check`에 합성 미지 image/source 조건을 주었을 때 둘 다 **changed=0/rescued=0**으로 거절했다. 실제 컨테이너 image/source는 수정하지 않았다. root 영구 bundle/state/config 트리의 소유권·쓰기권한·symlink 검사도 이상 0건이었다.
- **02:57:21~03:10:49 KST** 관찰 구간(최근 30분 journal 조회)에서 filtered/retained/requested_foreign/oversize 관측 수는 각각 **0**이었다. 정상 응답 전체 분모가 없으므로 혼입률 0%를 뜻하지 않는다. 해당 짧은 구간에 metadata 이벤트가 없었다는 관측이다.

새 컨테이너를 실제 생성하는 시험과 강제 장애 rollback은 수행하지 않았다. 코드가 같아 새 코드 백업 디렉터리도 만들지 않았고 기존 01:37 배포의 root 복구 백업은 그대로 유지했다. 기존 Python 배포기는 현재 실행 참조가 없어 제거했다. [검증 요약 JSON](hermes-validation-2026-10-14.json).
