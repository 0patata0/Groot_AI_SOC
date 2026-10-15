# 실제 agent001 burst 검증

## 최신 완료 상태 — 2026-10-14 18:56 KST

사용자가 정확한 260행 시험에 명시적으로 승인한 뒤 A/B 최신 preflight를 다시 통과했다. 준비했던 동일 20개 ID로 총 260행·230,560bytes를 **한 번만** 추가했다. 기존 52행의 바이트 SHA와 inode를 보존했고 파일은 312행이 됐다. 각 13행 안에는 인위적인 간격을 넣지 않았으며 20회 writer 호출 사이의 자연 실행 간격은 있었다.

20개 run 모두 첫 읽기에서 manager 2건/Indexer 2건이 정확히 일치했다. 총 40건은 `100293` 20건과 `100294` 20건이며 level 3, 중복·과거 시나리오 추가 경보 0건이다. strict TLS·hostname 검증, 57/57 shard 성공, timeout 없음, 규칙·시나리오·출처·키·사건 ID의 canonical tuple 일치를 확인했다. 조회는 11.3초, 입력 재전송은 0회다. A/B 보호 설정·룰·컨테이너 identity와 SOC 통지 조건도 전후 같았다.

[실제 검증 메타데이터](live-validation-2026-10-14.json)에 A run별 append 범위/SHA와 B 20개 개별 결과·전체 집계를 보존했다. 원문과 인증 정보는 반출하지 않았다. 이번 시험은 배포 후 실제 agent001 경로의 성공 근거이며, 일반 트래픽 전체의 영구적인 무손실 보장이나 과거 누락 원인의 소급 확정은 아니다.

## 직전 거절 이력 — 명시 승인 전

B의 두 옵션 실제 적용 후 18:49:47 KST `b-preflight`가 통과했다. 옵션 SHA `f77426cb…`, 동일 manager CID와 기존 설정·규칙 SHA, level 3 및 자동 대응/통지 제외 조건을 확인했다. 이어 A의 합성 260행 송신을 요청했지만 **자동 승인 검토가 프로세스 생성 전에 거절했다. 해당 호출로 추가한 입력은 0건이며, 새 run의 manager/Indexer 대조도 실행하지 않았다.**

거절 이유는 운영 canary 파일에 정확히 260행을 추가하여 실제 처리 경로를 실행하는 작업에 대한 직접 사용자 승인이 확인되지 않았다는 것이다. 직전 전송 재시도 지시를 이 운영 입력 승인으로 확대하지 않았고 우회하지 않았다. [호출 및 거절 기록](live-input-attempt-2026-10-14.json)은 당시 사실로 보존했다. 이후 사용자가 “승인할테니까 진행해봐”라고 명시 승인하여 위 한 번의 실제 송신과 읽기 대조를 완료했다.

## 준비 이력 — 2026-10-14 18:45 KST

사용자의 재시도 지시 후 후보를 반입했다. A/B 각각 driver와 미사용 run manifest 2파일·23,362bytes, A canary bundle 11파일·35,702bytes를 SHA 대조했다. B canary bundle은 같은 서버에 보관한 기존 11파일을 SHA 확인 후 재사용했다. **새 운영 입력은 여전히 0건이며, 실제 20회 송신과 색인 대조는 B 배포 완료 후 지시를 기다린다.**

B의 기존 jq/Python으로 집계 합성 10개와 timeout 회귀 4개를 통과했다. leader가 종료하고 자손이 pipe를 잡은 조건은 `waitid(WNOWAIT)` 및 제한된 정리로 5.207초에 끝났고 활성 자손 0·시험 디렉터리 삭제를 확인했다. SOC report/summary 최소 5, 실제 자동 monitor 스크립트 기본 10 및 script/.env/container override 없음도 확인했다. 수동 인증 HTTP 요청의 level 선택까지 금지한다는 뜻은 아니다.

A 읽기 preflight에서 기존 canary 52행·46,112bytes와 SHA, reader FD 1개, 20개 새 ID 미사용, Docker/Vector 경로를 확인했다. [native 준비 결과](native-preparation-2026-10-14.json)와 [실제로 실행한 합성 검사 소스](native-preparation-executed.sh)를 보존했다. driver의 새 SHA는 `e2704de2…`이며 아래 초기 검증의 `5035657d…`를 대체한다. 초기 기록은 그대로 남긴다.

**초기 준비 이력:** 18:25 KST에는 로컬 후보만 작성한 상태였고 서버 전송·실행·새 운영 입력 모두 0이었다. 당시 [로컬 검증 기록](validation-2026-10-14.json)의 구문·합성 집계 10개는 운영 실행 검증을 대신하지 않는다.

## 고정 범위

`e2e-burst.py`는 이번 작업용 일회성 운영자 도구다. 서버의 기존 Python 표준 라이브러리·jq·Docker CLI·coreutils와 이미 검증한 canary writer/verifier를 호출한다. 상시 데몬, 새 패키지, 새 권한 또는 일반 원격 실행 인터페이스를 설치하지 않는다. `run-manifest.json`에는 아직 사용하지 않은 32자리 run ID 20개와 시나리오별 SHA 키만 있다.

- A: 각 run의 13행을 `burst` 한 번으로 append한다. 총 260행이며 각 13행 안의 인위적인 3초 간격은 없다. 20회 호출 사이에는 자연 실행 간격이 있다.
- A: 기존 파일의 inode·접두 바이트 SHA를 보존하고, run별 append 범위 SHA·13행·시나리오 `5/2/5/1`과 총 260행을 재대조한다. 원래 writer의 reader·flock·미사용 ID 검사를 유지한다.
- B: 아직 확인되지 않은 run만 읽기 재조회한다. 입력은 재전송하지 않는다. 조회 예산은 약 180초이며 마지막 전체 조회를 위한 35초를 남긴다. 각 명령에도 별도 timeout이 있다. 최종 보호 상태 대조의 짧은 실행 시간은 추가될 수 있다.
- B: run마다 `100293`·`100294` 각 1건, 총 manager 40건/Indexer 40건을 요구한다. 규칙·시나리오·출처·상관 키·허용 사건 ID·dedupe 키의 결속 및 양쪽 canonical tuple을 대조한다. 반복 경보 ID는 원래 입력 1~5 중 하나이고 교차 경보는 nft 입력 2여야 한다.
- B: 기존 CA·관리자 client 인증서를 서버 내부에서 사용하고 TLS hostname 검증을 유지한다. 정확한 total, 전체 shard 성공, timeout/조기 종료 없음, level 3, 중복/과거 시나리오 추가 경보 0을 요구한다. manager 대조 범위는 현재 `alerts.json` 끝 10,000행·16MiB다.
- B: 실제 active-response/integration 블록 0, canary level 3와 no-email/no-full-log, SOC 보고·요약·monitor 최소 level 5를 읽기 확인한다. 설정·룰·컨테이너 identity가 실행 전후 같아야 한다.

검증이 실패하면 부분 송신 또는 부분 확인 상태를 남기고 종료한다. 같은 A 작업 디렉터리로 재실행할 수 없다. **누락 경보를 채우기 위해 입력을 다시 보내지 않는다.** 재조회가 필요하면 보존한 run ID로 기존 읽기 전용 verifier를 사용한다. 파일 append·sync·reader EOF는 분석 또는 색인 ACK가 아니다.

## 승인 후 준비 순서

현재 자동 승인 검토의 반입 제한을 해소한 뒤, 아래 경로와 새로 확인한 SHA를 대조하고 진행한다. 이 문서는 미실행 후보의 준비 절차이며 운영 성공 기록이 아니다. 기존 task stage는 마감 때 제거했으므로 재개 시 필요한 파일과 최신 pin을 새로 준비해야 한다.

1. B Ansible 적용 및 같은 manager CID 재시작, worker 1/1·기존 104 native 검사·서비스 건강 확인을 마친다.
2. A/B 기존 canary 소스와 이 후보를 SHA manifest로 대조하여 root 소유로 배치한다. task root 및 후보 디렉터리는 `0700`, JSON pin/manifest는 `0600` 단일 일반 파일이어야 한다. driver에 임의 경로나 다른 호스트를 넘기는 옵션은 없다.
3. B 최신 pin과 A 최신 pin을 각각 root 전용 파일에 기록한다. 이 저장소에는 배포가 완료되지 않은 예상 pin을 만들지 않았다.
4. B `b-preflight`, A `a-preflight` 결과와 같은 run manifest SHA를 확인한다. 운영 담당자가 B 준비 완료를 확인한 뒤 A `a-send`를 한 번만 실행한다.
5. A source 결과를 확보한 후 B `b-verify`를 실행한다. 원문·인증 정보는 서버에만 두고 결과 JSON의 메타데이터만 회수한다. 운영 소스와 시험 원문 보관·작업 임시물 정리는 별도 마감 절차로 한다.

실행 당시 고정 서버 경로(마감 후 task stage는 별도 보관·정리 대상):

```text
/var/tmp/capstone-correlation-fix-20261014/
  e2e/e2e-stage/{e2e-burst.py,run-manifest.json}
  canary/canary-candidate/{source.sha256,history-replay-b/,tests/,fixtures/}
  e2e-pins-a.json
  e2e-pins-b.json
  e2e-preflight-a.json / e2e-preflight-b.json
  e2e-a/                         # source append 메타데이터
  e2e-b/                         # run별 읽기 결과 및 전체 대조 메타데이터
```

A pin의 정확한 키는 `ossec_conf_sha256`, `vector_config_sha256`, `waf_container_id`, `suricata_container_id`다. B pin은 `manager_id`, `ossec_conf_sha256`, `local_rules_sha256`, `vector_rules_sha256`, `options_sha256`다. 모두 64자리 소문자 hex이며 B 옵션 SHA는 **적용 후 실제 파일** 값이어야 한다. source bundle의 `source.sha256` 자체도 운영 담당자가 보관한 검증 SHA와 먼저 대조해야 한다.

공개 모드는 `a-preflight`, `a-send`, `b-preflight`, `b-verify` 네 가지뿐이다. 어떤 모드도 Indexer에 문서를 쓰거나 Wazuh 설정·규칙·서비스를 변경하지 않는다. `a-send`만 기존 canary 입력 파일에 승인된 합성 260행을 추가한다.

## 현재 검증과 한계

`test-e2e-contract.py`는 driver를 import하거나 실행하지 않고 AST에서 집계 jq 식만 읽는다. 기존 jq로 20 run/40 tuple 정상·역순 및 누락·중복·run/시나리오/키/출처 변조를 검사하여 10개 통과했다. 기존 writer/verifier의 B native 42+5 회귀 결과는 [별도 기록](../../tests/canary-fix-validation-2026-10-14.json)에 있다.

초기 초안 이후 독립 리뷰에서 timeout 정리 경계를 보완했고 Linux 실제 경로·권한·합성 집계·timeout 정리와 위 20회 실제 송수신을 확인했다. 격리 agent000 부하 결과와 실제 agent001 전송 결과는 별도로 기록한다. 이 20회 성공이 일반 트래픽의 무손실이나 과거 누락의 소급 원인 확정을 뜻하지 않는다.
