# 운영자용 고정 Ansible 배포

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../STATUS.md) · [실행 계획](../../../PLAN.md).
> 기존 서버의 운영 자동화와 새 서버 초기 설치는 구분한다. 지정 범위의 C1/B1/A2 재부팅 복구는10/24 검증 이력이 있으며 최초 실패·수동 복구도 보존한다. 현재6실습·MCP6서버를 기준으로 읽고 과거 후보/PID/시험 결과를 새 실측으로 해석하지 않는다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

> 2026-10-15 05:00 최신: WAF 새CID6c72d5a5…·호스트bind·로그인계·양가드를 검증했다. 원본상태는 Suricata gen1/rev6·WAF gen4/rev13, Vector2627991·Wazuh1909632 실행이다. 원본/출력점검timer를5분주기의0·1·3분으로분산해자연실행exit0를모두확인했다. Hermes단계와마지막인증서감시까지완료했으며관리범위·LLM권한은확대하지않았다. [현재WAF실측·정리](../../groot-a/imperva-exception/recreation-validation-2026-10-15.json). 아래는 각 시점의 이력이다.

## 2026-10-15 최신 후속 — 4단계 Hermes 첫 시작·복귀 완료

[고정 Hermes prestart 역할](roles/hermes_prestart/README.md)의 실제 `exercise`를 완료했다. 시작하지 않은 후보에 가드·regex를 설치하고 readback한 뒤 첫 시작·readiness를 확인했으며, 고정 시험 실패 후 원래 컨테이너로 복귀했다. 최종 `rolled-back/revision22`, 원래 CID `6c2ed13aea89…`/PID2248019 running, 후보 `47aa31c88f9d…` exited 보존이다. 각각 실제 UID995의 가짜 HTTP 11개·MCP5 initialize/tools-list·새 heartbeat·DB 검사를 통과했고 강제 종료·DB/WAL 복원·두 번째 cutover는 없었다.

실행본은 B root 전용 `/opt/capstone-automation/releases/hermes-prestart-20261015-f93793c125bf`이며 helper native64개·Ansible 구문 검사와 [실제 결과](hermes-prestart-validation-2026-10-15.json)를 구분해 보존한다. 원래 plan SHA는 유지했고 최종 receipt SHA는 `38458901be81b3a3f02f6378ddedea3f43e6186fbdb2659747b6cf52180689f4`다. 고정 대상 운영자 경로의 실증이며 공통 Docker admission 장치·임의 crash 자동 복구는 아니다. 변경 명령을 자동 재시도하지 않고, LLM/MCP의 실행 권한도 확대하지 않았다. 아래의 4단계 미착수 표현은 해당 시각의 기록이다.

구형 Hermes 배포 경로의 사전 거절도 [고정 플레이북](hermes-legacy-guard-b.yml)으로 B에 적용했다. 실제 `/home/groot_b/capstone/hermes/deploy_hermes_B.sh`는 SHA `6065fa7f…649460`, 기존 UID/GID1000·0664를 유지하며 같은 바이트의 root0400 사본에서 `prep/test/all` 모두 exit78을 확인했다. native41개·syntax 통과, Ansible `ok28/changed5/failed0`, 적용 후 SHA·운영 PID2248019 불변이다. 저장소 `deploy_gateway_B.sh`의 차단은 향후 복사본용이며 B 운영 사본 배포와 구분한다. 컨테이너를 변경하지 않았고 이 스크립트 차단을 직접 Docker 실행까지 통제하는 공통 admission 장치로 확대하지 않는다.

## 2026-10-15 02:15 KST 최신 상태 — 관리 원천 타이머 운영 확인 완료

**02:15:39 KST 3단계 운영 검증과 세 타이머 활성화를 완료했다.** 두 raw 타이머의 첫 실행은 `not_due`였으며, 유지관리 정상 daily 회전으로 ready·evidence·telemetry 세 파일을 보존·교체한 뒤 maintenance만 다시 활성화해 `not_due` 첫 실행을 확인했다. 추가 force나 checkpoint 편집은 없었고 세 타이머는 enabled/waiting이다. 최종 Vector PID2406117/Invocation `12314ddc66e14e0083b08db2e51fc831`, Wazuh1909632, WAF2377669·healthy, raw state5/11 active와 양 가드·health 검증을 확인했다. [실제 결과·한계](../../normalization/vector/raw-operations/README.md).

이 작업은 고정 운영자 wrapper와 기존 runtime의 검증·활성화다. **구형 `vector_shadow`/`vector-storage-a.yml`의 managed state·migration barrier 사전 거절은 유지**하며, 현재 설치본을 v1 Ansible로 덮어쓰지 않는다. MCP·LLM 권한이나 패키지 설치 범위는 확대하지 않았다. 최종 소스·증거 보관과 임시물 정리를 완료했다(아래 정리 후속 기록). 4단계는 구현 준비 중이고 운영 전환은 없으며 인증서 관리는 마지막이다. 호스트 재부팅·새 WAF CID·새 적격 보안 사건 ACK는 이번 완료 범위가 아니다. 아래는 이전 시점의 배포 기록이다.

**02:19:46 KST 정리 후속:** A의 작업 자료 515파일·4,621,609B와 격리 시험 자료 8파일·98,071B를 보관한 뒤 stage3·시험 fixture·미사용 v1 recovery guard를 제거했다. migration 시작 가드는 유지했고 정리 전후 운영 상태 불변·서비스 신호 0회를 확인했다. Mac의 해당 임시 트리 650파일·55디렉터리·5,318,295B와 B 조회 임시파일 2개도 제거했으며 영구 증거는 유지했다. **이 문구는 267파일·2,077,701B 소스 스냅샷 이후에 추가한 기록**으로 그 스냅샷에 포함된 문서 바이트와 구분한다. **02:20:55 KST 최종 점검도 완료했다.** 두 migration guard는 ready이며 storage 정상·Vector active·recovery=no·collection=[]·binding 검증 및 상태 코드 없음, 세 타이머 enabled/active/waiting을 확인했다.

## 이전 시점 기록 — 2026-10-15 현재 운영 경계 — managed raw/v2는 별도 운영자 경로

A의 원본 회전·WAF v2 초기 전환과 실제 두 원천 회전을 완료했고, 01:48:58 KST 같은 CID의 WAF 재시작도 통과했다. 현재 Suricata는 gen1/revision5, WAF는 gen3/revision11의 active 상태다. WAF master2377669·healthy, Vector2368467·Wazuh logcollector1909632 유지가 확인됐다. 원본·출력 회전 timer는 활성화 사전 검사 2회/enable 0회 상태로 대기한다. [현재 운영 결과와 남은 경계](../../normalization/vector/raw-operations/README.md).

**기존 `vector_shadow` role와 `vector-storage-a.yml`은 현재 A에 재배포하는 경로가 아니다.** `/var/lib/capstone-raw-operations`, `/var/lib/capstone-raw-migration`, 초기 전환의 `migration.json` 중 하나라도 있으면 최초 변경 전에 거절한다. v1 role는 `waf-producer-deployment-1` manifest만 허용하므로 v2 manifest를 v1 구성으로 덮어쓸 수도 없다. 파일이 잘못됐다는 이유로 barrier/state를 지우거나 구판 감시기·maintenance를 다시 복사하지 않는다.

현재 raw runtime·WAF v2·maintenance 보완은 [검토한 초기 전환 및 후속 CAS 절차](../../normalization/vector/raw-operations/INITIAL-MIGRATION.md)를 사용하는 관리자 전용 경로다. Ansible/MCP/LLM에 임의 컨테이너 구성·패키지 설치 권한을 추가하지 않았다. 아래 최초 Vector 역할·명령·멱등성 수치는 이전 구성의 이력으로 보존하며, 관리 상태를 제거해 다시 실행하는 지침이 아니다.

4단계 Hermes는 읽기 전용 사전 확인만 했고 새 운영 변경은 미착수다. 인증서 관리는 마지막 순서이며 실제 호스트 재부팅은 0회다. 이번 raw 회전 관찰 구간의 자연 적격 보안 사건 ACK 표본도 0건이므로 로컬 gate를 원격 수신증으로 표시하지 않는다.

첫 관리 대상은 A의 `capstone-vector.service`와 해당 정제 설정이다. 원본 보안 로그를 읽어 전용 출력 경로에 기록하는 병행 수집기만 배포한다. 기존 Wazuh 입력 이전과 MCP 권한 변경은 이 플레이북의 작업에 포함되지 않는다.

## 2026-10-14 후속 관리 대상

기존 Vector 배포 외에 [출력 회전·용량 timer](../../normalization/vector/STORAGE.md), [Wazuh 전용 입력·상관 관찰](../../normalization/wazuh-vector/CORRELATION.md), [Hermes 언어 가드 설치·재생성 감지](hermes-guard.md)를 운영자 전용 경로로 적용했다. Ansible은 LLM의 도구나 일반 sudo 대체로 공개하지 않는다. 아래 최초 Vector 배포 수치는 당시 검증 기록이다.

**06:09 KST 현재 기준:** 적격 이벤트의 독립 [evidence 분기](../../normalization/vector/EVIDENCE.md)를 적용했다. ready/no_log를 유지하며 evidence 사본만 별도 Wazuh 관찰 규칙으로 연결한다. ready·quarantine·evidence의 disk buffer3개 설정 합계는805,306,464byte(약768MiB), telemetry는 별도 memory buffer다. 네 출력 회전은 ready/evidence 두 Wazuh reader의 EOF·SHA를 확인한다. 현재 검증은 main49+WAF61=**native110개**, **jq18개**, 분리 실제 FD/checkpoint **reader9개**다.

05:58:51~06:01:27 적용은 동결208개 source SHA와 고정15개 관리 파일의 root 백업·기존/후보 SHA 복구 조건을 확인한 운영자 절차였다. 한 Ansible 호출에서 Vector→storage playbook을 실행한 **최종 누적** recap은 첫 `ok68 changed5`, 재적용 `ok67 changed0`이다. Vector playbook 직후의 중간 recap(`ok49 changed3`, 재적용 `ok48 changed0`)과 합산하지 않는다. 재적용 PID/Invocation과 보호 설정은 유지됐으며 실제 rollback은 필요하지 않았다. 별도06:06 두 reader 운영 회전도 통과했다. 이 한정된 배포의 복구 준비를 일반 playbook의 자동 트랜잭션 보장으로 확대하지 않는다.

WAF 통합 Vector 후보는 root0600 배포 manifest를 읽고 실제 읽은 바이트SHA·현재 컨테이너 fullID·producer 설정 SHA와 일치해야 한다. native 검증 뒤 설치 직전에 같은 조건을 다시 확인하며, 검증한 env 사본을 설치한다. **04:49 당시** 검증은 main/상관28개·수집8개·별도 WAF61개(총97개)와 jq16개였으며 현재 수치는 위 후속 기록을 따른다. WAF producer는 기존 nginx에 고정 최소 로깅 설정을 추가하는 별도 운영자 배포이며 컨테이너 재생성이나 보안 룰 교체를 수행하지 않는다. 실제 적용 상태는 [WAF 문서](../../normalization/vector/WAF.md)에 기록한다.

04:49 후속 wrapper는 Vector와 storage 두 플레이북을 같은 lock으로 순차 실행한다. 실제 Vector changed4/storage changed2 뒤 두 재적용changed0이었다. [Hermes 복구16개·고정 wheel cold복원 검증](hermes-recovery-validation.md)과 [시작 전 가드 계획](hermes-prestart-plan.md)은 실제 운영 컨테이너 재생성 완료와 구분한다.

## Vector 플레이북 실행 경계

- 운영자가 A에서 root로 실행한다. Hermes, `rulechg`, MCP 도구에는 Ansible 실행 권한이나 이 컨트롤러의 키를 제공하지 않는다.
- 기존 MCP helper의 후보 SHA-256·최종 diff·HMAC·nonce·승인자 제한·승인 1회 소비는 그대로 유지한다. Ansible 실행 결과나 `--check` 출력을 관리자의 룰 변경 승인으로 취급하지 않는다.
- Vector 플레이북에는 package/pip 설치, 임의 shell, Docker 소켓/컨테이너 생성·재구성, sudoers/SSH/기존 룰 파일 변경 태스크가 없다. Vector 패키지 준비는 운영자가 수행한다. 별도 Hermes 가드 플레이북은 격리 target이 없을 때 서버에 보관한 고정 wheel을 검증해 복원한다. 이 작업도 운영자 전용이며 LLM에 패키지 설치 권한을 부여하지 않는다.
- 기존 root helper, MCP 전면, SSH 강제 명령, 승인 설정, sudoers, worker unit/timer의 파일 해시·소유자·권한을 배포 전후 대조한다. 이 검사는 보호 경로 보존의 추가 확인이며 승인 프로토콜 전체 회귀시험을 대신하지 않는다.
- 플레이북은 root 운영자용 구성 관리 도구다. Ansible 변수·코드 자체를 공격자가 바꿀 수 있는 상태에 대한 보안 경계는 아니다. 전체 프로젝트와 컨트롤러는 root 소유이며 일반 사용자가 수정할 수 없어야 한다.

## 컨트롤러 준비

Mac에는 패키지를 설치하지 않는다. A의 전용 `/opt/capstone-automation/venv`에 운영자가 Ansible을 준비한다. 최상위 요구사항은 `requirements-controller.txt`이며 추가 Galaxy collection을 사용하지 않는다. 실제 2026-10-14 설치에는 [controller-linux-x86_64.lock](controller-linux-x86_64.lock)의 ansible-core 2.21.5 및 모든 의존 패키지 버전·SHA-256을 고정하고 `pip --require-hashes`로 설치했다. [wheel-manifest.json](wheel-manifest.json)은 A의 Linux x86_64/Python 3.12용 설치 파일 근거이며 다른 플랫폼의 wheel 해시로 간주하지 않는다. 서버의 운영 설치 기록 `/opt/capstone-automation/controller.lock`은 그대로 유지한다. 컨트롤러 Python 지원 범위는 3.12–3.14, 대상 Python은 3.9–3.14이다. 설치 준비는 운영자 작업이며 이 플레이북이나 LLM 도구가 수행하지 않는다.

프로젝트의 상대 경로를 유지해 서버에 복사한다.

```text
<operator-owned-checkout>/infra/
  automation/ansible/                 # 이 디렉터리
  normalization/vector/              # 검토한 config, VRL, tests, service
```

`/usr/local/bin/vector`는 운영자가 검증한 바이너리로 미리 준비한다. 플레이북은 설치된 바이너리에서 `--version`, `validate`, `test`를 실행한다. 자동 업데이트나 바이너리 다운로드를 수행하지 않는다.

## 고정 관리 대상

| 종류 | 경로 |
|---|---|
| 설정·VRL·환경 파일 | `/etc/capstone-vector/` |
| systemd unit | `/etc/systemd/system/capstone-vector.service` |
| Vector 체크포인트·디스크 버퍼 | `/var/lib/capstone-vector/` |
| 정제·증거·격리·수집 상태 출력 | `/var/log/capstone-vector/{ready,evidence,quarantine,telemetry}/` |
| 운영자 후보·Ansible 임시 경로 | `/var/lib/capstone-automation/ansible/` |

센서명과 원본 경로는 `vector-shadow-a.yml`에 명시한다. 환경 파일에는 자격증명이 없으며 `0600`, 데이터·로그·후보 디렉터리는 `0700`이다. 기존 파일에 `copy`/`template` 변경이 있으면 Ansible 백업을 생성한다. 기존 백업·체크포인트·출력은 자동 삭제하지 않는다.

evidence 최초 도입은 빈 root0600 파일 선생성→B 규칙→A localfile·빈 reader FD 확인→Vector writer/maintenance 순서로 수행했다. Vector 역할만 먼저 실행하는 것이 전체 Wazuh 연결 전제까지 검증하는 것은 아니다. Wazuh 설정 변경은 별도 고정 플레이북이 맡으며 MCP/LLM 권한을 확대하지 않는다.

## 실행과 검증

**다음 명령은 기존 v1 배포 계약의 기록이다. 현재 managed raw가 설치된 A에서는 사전 barrier가 배포를 거절하며, 최신 적용은 위 운영자 전용 경로를 따른다.**

아래 `A_MACHINE_ID`는 운영자가 별도로 확인한 A의 `/etc/machine-id` 값으로 바꾼다. 호출한 호스트에서 값을 자동 채워 넣으면 잘못된 호스트 실행 방지 목적이 사라진다.

```sh
sh run-vector-local-a.sh syntax A_MACHINE_ID
sh run-vector-local-a.sh check A_MACHINE_ID
sh run-vector-local-a.sh apply A_MACHINE_ID
sh tests/verify-idempotency.sh A_MACHINE_ID
```

wrapper는 root·machine-id·고정 컨트롤러 경로를 검사하고, 같은 호스트의 동시 배포를 `flock`으로 막는다. 별도 임의 Ansible 인자는 전달하지 않는다. 이 wrapper도 MCP 실행 대상으로 등록하지 않는다.

`syntax`는 Ansible 구문 검사다. `check`는 변경 예상만 확인하며 후보 검증·서비스 재시작을 하지 않는다. 최초 check에서 디렉터리가 없으면 예측 파일 작업이 실패할 수 있으므로 이를 실제 배포 검증 성공으로 기록하지 않는다. wrapper의 root 전용 임시 디렉터리/lock 준비는 check/syntax에서도 수행한다.

`apply`는 후보를 root 전용 위치에 고정한 뒤 Vector 설정 검사·합성 입력 단위시험·systemd unit 검사를 모두 통과시킨다. 실제 배포는 검사한 후보 파일을 사용한다. 파일이 변경될 때만 Vector를 재시작하며 변경이 없으면 기존 서비스의 시작·활성 상태를 보장한다. 기존 Wazuh, Suricata, WAF, Hermes는 재시작하지 않는다.

멱등성 스크립트는 실제 apply를 두 번 수행하고 두 번째 recap에서 `changed=0`, `unreachable=0`, `failed=0`을 요구한다. 실제 원본 경보 생성·분석 완료나 전송 확인을 증명하는 시험은 아니다. Vector 출력은 병행 관찰 결과이며 Wazuh 수신확인으로 표현하지 않는다.

## 실패와 복구

후보 검사에 실패하면 운영 설정을 복사하거나 서비스를 재시작하지 않는다. 파일 배포 중 실패 또는 시작 실패에서는 Ansible이 중단하며, 백업 파일과 실패 단계로 운영자가 복구 여부를 판단한다. 여러 설정 파일과 서비스 실행을 하나의 원자적 트랜잭션으로 묶거나 자동 롤백한다고 주장하지 않는다. 기존 설정 백업은 각 대상 파일 옆의 Ansible `backup_file`이며, 새로 만든 파일은 이전 백업이 없을 수 있다. 복구 시에도 Vector 체크포인트·출력 파일을 삭제하지 않는다.

현재 첫 역할은 Vector에 한정한다. 이후 기존 승인 worker의 실행 부분을 Ansible로 옮길 때에도 root helper가 승인된 정확한 후보·현재 원본·한 번만 소비하는 결정을 검증한 뒤 고정 작업만 호출해야 한다. 일반 `ansible-playbook`이나 임의 extra-vars를 LLM에 열어 주는 방식으로 확대하지 않는다.

## 근거와 검증 기록

- [ansible-core 지원표](https://docs.ansible.com/projects/ansible-core/devel/reference_appendices/release_and_maintenance.html#ansible-core-support-matrix)
- [2.21.5 공식 PyPI 배포](https://pypi.org/project/ansible-core/2.21.5/)
- [Ansible copy: backup·검증·원자적 쓰기](https://docs.ansible.com/projects/ansible/latest/collections/ansible/builtin/copy_module.html)
- [Vector CLI: validate·test](https://vector.dev/docs/reference/cli/)

2026-10-14: Mac에서 새 패키지 없이 JSON 문법의 YAML 파일 파싱·셸 구문 검사를 통과했다. A의 ansible-core 2.21.5로 실제 `--syntax-check`를 통과한 뒤, 검증된 Vector 0.59.0 후보를 `/opt/capstone-automation/project/infra/`에 root 전용으로 보관하고 운영자 승인 범위에서 적용했다.

01:37:59 KST 검증 완료: 첫 apply는 `ok=28 changed=7 failed=0`, 동일 입력의 두 번째 apply는 `ok=27 changed=0 failed=0`이었다. 후보의 Vector 설정·22개 native test·systemd unit 검사를 통과했고, 31.46초 관찰에서 서비스 active/running·재시작 0·현재 invocation의 오류/경고 0을 확인했다. 두 번째 apply에서도 MainPID와 invocation이 같았다. 기존 waf/suricata/chatproxy 컨테이너 ID·시작시각과 MCP helper/승인 설정/sudoers/worker 파일 해시·권한은 보존됐다.

관찰 시 ready 20건(Suricata 5, nftables 15)이었고 JSON 오류·원문 필드 노출·KST 형식 오류는 0건이었다. 당시 quarantine 파일은 아직 생성되지 않았으며 실제 관찰 0건을 WAF 격리 기능의 실시간 검증 성공으로 해석하지 않는다. 합성 WAF 격리 시험은 Vector 모듈의 별도 기록을 참조한다. 이 배포는 기존 Wazuh 입력을 전환하지 않았다. 후속 Wazuh 연결은 별도의 작업 기록으로 구분한다.

원문 없이 건수·해시·권한을 기록한 [배포 검증 JSON](validation-2026-10-14.json)을 참조한다. 서버에는 `/opt/capstone-automation/vector-deployment-validation-20261014.json`과 첫/두 번째 apply 로그가 root 전용으로 남아 있다. 출력 건수는 해당 시점의 한정된 스냅샷이며 이후 계속 증가할 수 있다.
