# 원본 과대 행 감시의 B 규칙 배포

기존 `capstone_vector_rules.xml`에 `100252`와 `100253` 두 블록만 추가하는 관리자 전용 Ansible 절차다. 두 규칙은 level 3·ignore 900·no_email_alert이며, 이 경로는 LLM/MCP나 sudoers에 노출하지 않는다. 원본 수집·상관 규칙·분석기 1/1 옵션·권한은 변경하지 않는다.

2026-10-14 21:16:46 KST에 B 운영 적용을 완료했고, 21:20:14 KST의 독립 사후 점검도 통과했다. Mac에는 패키지를 설치하지 않았다.

## 운영 적용 결과

| 확인 항목 | 2026-10-14 실측 결과 |
|---|---|
| 기존 규칙 검증 | baseline 104개 통과 |
| 후보 설치 후 검증 | 확장 native 116개 통과 |
| manager 재시작 후 검증 | 확장 native 116개 통과 |
| 재시작 범위 | 같은 전체 CID `45b85672e0fe16fd14616e608c99b683e2f651b049efcd71da2b45367b057806`의 manager만 1회 재시작 |
| 필수 프로세스 | analysisd·remoted·db·logcollector 모두 실행 중, status rc 1은 비활성 선택 서비스에 따른 허용 범위 |
| 분석기 설정·상태 | `event_threads=1`, `rule_matching_threads=1` 유지, 전체 Threads 44 |
| 사후 상태 표본 | 누적 `events_dropped=0`, 조회한 15개 queue usage 모두 0.0 |
| 보호 범위 | 비교한 7개 파일 중 규칙 파일만 변경, 다른 6개 파일의 SHA·소유권·권한 동일. 다른 5개 컨테이너 상태도 동일 |
| 운영 시험 입력·외부 메시지 | 0건. native 합성 검사만 수행 |

규칙 파일은 `20848771f884e5dfdc144a7cc104b056e8d4b5caab8627703df0d1d569701900`에서 `9f76264a8038c5c377b4c24a53ab2e3acc0eaf3fce7632df07f921cabdd26995`로 변경됐다. 추가된 `100252`·`100253` 두 블록을 제거하면 이전 바이트의 SHA와 일치한다. 두 규칙의 level 3·ignore 900·no_email_alert 및 기존 SOC 자동 알림·차단 제한을 사후에 확인했다.

백업과 거래 자료는 B의 `/var/backups/capstone-raw-line-health-co5uu1do`에 남겼다. 적용 메타데이터는 `step2-apply-b.json`, 독립 사후 점검 메타데이터는 `step2-postflight-b.json`으로 기록했다. 이 문서 갱신 시점에는 전체 증거의 영구 보관과 작업용 임시 파일 정리를 마감 중이다.

이번 적용은 정상 경로로 완료되어 **실제 rollback은 실행하지 않았다**. 누적 drop 0과 queue 0은 사후 한 시점의 관측이며, 장기 무손실이나 처리 완료의 보장은 아니다. 운영 원천에 과대 로그를 주입하거나 외부 알림을 보내는 종단 시험도 수행하지 않았다.

## 고정 입력과 명령

부모 디렉터리의 기존 `ansible.cfg`, `inventory.ini`, 후보 XML, `tests/` 네 스크립트와 합성 `fixtures/`가 필요하다. 관리자가 확인한 B `preflight.json`은 이 디렉터리의 root 0600 단일 링크 파일로 둔다. 이는 비밀이나 로그 원문을 포함하지 않는 읽기 전용 메타데이터다.

preflight 형식은 2026-10-14 20:57 조회와 같다. `at_kst`는 마이크로초와 UTC offset이 있는 ISO 문자열, `manager_id`는 전체 64자리 ID, `protected`는 고정 파일별 `sha256/uid/gid/mode`, `options_1_1=true`, `new_rule_ids_absent=[100252,100253]`를 포함한다. 조회 시각이 30분을 넘으면 적용을 거절한다. 최초 적용 전에는 새 조회로 갱신한다. 같은 거래 범위의 재실행은 원래 preflight와 후보를 사용하며, 이미 설치된 정확 후보도 허용한다.

```sh
bash raw-line-health/run-b.sh syntax
bash raw-line-health/run-b.sh check
bash raw-line-health/run-b.sh apply
```

실행 위치는 B의 root가 보호하는 프로젝트 사본이다. wrapper는 B machine ID, 기존 두 공유 잠금, 파일 소유권과 권한을 확인하고 환경을 비운 뒤 이미 설치된 Ansible 2.21을 호출한다. `syntax`는 문법 검사, `check`는 신원·메타데이터·정확 후보 확인이다. 둘 다 native 검사나 적용 성공을 뜻하지 않는다.

## 적용과 실패 복구

1. 현재 전체 manager ID와 etc volume, 기존 규칙 SHA·uid/gid/mode, 설정·승인 경계를 대조한다. 두 추가 블록을 제거한 후보 바이트의 SHA가 원래 `20848771…1900`과 같아야 한다.
2. root 0700 거래 디렉터리에 원본·후보·합성 검증 자료를 준비한다. 기존 세 스크립트는 복사본의 고정 manager 할당 한 줄만 전체 CID로 바꾸고, health 스크립트는 검증된 CID 환경 입력을 사용한다. 운영 파일이나 입력 큐에 합성 로그를 쓰지 않는다.
3. 기존 네 스크립트의 baseline 104개를 실행한다. 새 health 시험은 `--baseline`에서 원래 18개만 사용한다. native `analysisd -t`도 성공해야 한다.
4. 설치 직전 identity/보호 파일/원본을 다시 비교한다. 이 검증은 mutation block 밖에 있어 사전 거절에 rollback이나 restart가 발생하지 않는다.
5. 후보 파일만 원자 교체하고 `analysisd -t`와 확장 native 116개를 실행한다. 같은 전체 CID를 한 번 재시작한 뒤 필수 네 프로세스와 native 116개, 설정·권한 불변을 다시 확인한다. 선택적으로 비활성인 Wazuh 서비스 때문에 status의 rc 1도 가능하므로 rc 0/1과 필수 프로세스를 함께 요구한다. timeout·필수 프로세스 누락은 거절한다.
6. 실패하면 CID·보호 파일이 같고 현재 규칙 SHA가 원본 또는 이번 후보인 경우에만 root 전용 백업을 복구한다. 운영 restart를 이미 시도했을 때만 복구 restart를 한다. 복구 후 건강·native 설정·baseline·원본 SHA가 확인돼도 원래 배포 결과는 실패로 반환한다. 불명확한 응답이나 외부 변경에는 무조건 덮어쓰지 않는다.

이미 정확한 후보가 있으면 규칙 파일과 manager를 변경하거나 재시작하지 않고 확장 suite를 검사한다. 매 실행의 검증·백업 자료는 새 거래 디렉터리에 남으므로 전체 Ansible recap의 `changed=0`을 주장하지 않는다. 멱등 범위는 운영 규칙 바이트와 컨테이너 재시작이다. 정상 경로의 restart는 한 번이며, 실패 복구에서 한 번 더 필요할 수 있다.

`/var/backups/capstone-raw-line-health-*`의 root 전용 자료는 자동 삭제하지 않는다. 이 배포기는 전원 장애 후 자동 복구나 Docker restart 응답 유실의 영속 거래 조정기를 제공하지 않는다. 적용 담당자는 결과와 실제 상태를 대조해 보관·정리를 완료해야 한다.
