# 채팅 인증서 만료 감시·수동 갱신

**2026-10-15 10:49 KST 후속 확인:** 오늘 **09:00:00 KST 예약 실행·exit0**와 09:00:01의 `ok/verified` journal 1건, 같은 상태파일을 대조했다. 다음 예약은 10월 16일 09:00 KST다. 10:48:58 실제 TLS도 CA·hostname·제공 인증서 fingerprint 검증을 통과했고, 만료는 **2027-01-06 15:02:33 KST**로 동일하다. [A 실측](followup-a-2026-10-15.json).

B 설치 decoder/규칙 SHA는 유지됐고, 최근24시간 agent001의 인증서 규칙100300~100305 경보는0건이었다(60/60 shard 성공, timeout/부분결과 없음). 정상100300은 level0/no_log이므로 이 결과는 예상되며, **실제 경고의 원격 전달·색인 완료를 입증하지는 않는다.** 합성 경고 주입·인증서 교체·개인키 읽기·서비스 재시작은 없었다. [B 실측](followup-b-2026-10-15.json). 자동 갱신은 미구성이며 아래 12월 초 수동 갱신 계획을 유지한다. 다음 본문은 이전 시점 기록이다.

**2026-10-15 04:51:02 KST — A 설치·첫 관측 완료.** 고정 A에서 Linux root 합성 **26개**, 설치 전 실제 localhost TLS 검증, 설치 후 oneshot 관측이 모두 통과했다. 설치된 OpenSSL3.0.13이 CA·hostname을 검증했고 제공 중 leaf와 공개 인증서 fingerprint가 일치했다. 현재 만료는 **2027-01-06 15:02:33 KST**다.

- `/usr/local/sbin/capstone-cert-monitor` root0500과 두 systemd unit root0644를 설치했다. `/var/lib/capstone-cert-monitor/status.json`은 root0600이며 `expiry_status=ok`, `probe_status=verified`를 확인했다. 상태 SHA는 `1dfc989b514755c0e798af62a155468b3dd5c0a138b990f655586266c2642f36`이다.
- `capstone-cert-monitor.timer`는 **enabled/active**, 매일 **09:00 KST**, `Persistent=true`다. 이번 성공은 수동 첫 oneshot이며 **09:00 예약 실행은 아직 관측하지 않았다**.
- 공개 인증서 파일 SHA `0babec3a5fab7273df7b5a3be60346510e64db9656d52580fad35f2c2e8dd54a`는 전후 동일했다. 개인키 읽기·자동 재발급·다른 서비스 재시작은 0회다. 배포 소스·시험·상태와 영수증은 A의 `/var/backups/capstone-certificate-monitor-20261015/`에 보존했다.
- 운영 감시기 SHA는 `91c0ed1025beb3f7bbc59ec38b58c705add1637c8e5c69216eb489d62e65a540`, 일회성 배포 controller SHA는 `e5e7dae2e699987e11efa9c936be9fef89192ea785286ed2ba2051b109db96d8`이다.
- **B는 2026-10-15 04:59:47 KST에 전용 decoder·규칙 설치와 manager 재시작 1회를 완료했다.** native 합성 51개와 재시작 후 실제 A 상태 JSON을 사용한 logtest 1건이 통과했다. 후자는 `capstone_certificate_json` → `100300/level0`이며 정상 상태를 경보로 발행하지 않았다. 실제 만료 경보의 운영 종단 시험과 09:00 예약 실행은 아직 확인하지 않았다. 아래 B 기록에서 시험 범위와 초기 실패 이력을 구분한다.

**초안 작성 시점의 기록(아래 미배포 문구는 설치 전 상태):**

이 폴더는 **2026-10-15 작성한 미배포 후보**다. 운영 인증서·서비스는 변경하지 않았다. 새 패키지나 상주 수집기 없이 A의 Bash, OpenSSL, GNU coreutils, jq, logger, flock, systemd를 사용한다. 마지막 인증서 단계에서 부모 운영자가 실제 A의 파일 메타데이터와 바이너리 호환성을 확인한 뒤 배포한다. Wazuh 경보 연결·실제 주기 실행은 아직 검증하지 않았다.

대상은 `chat.grootlab.duckdns.org` 하나다. 읽는 파일은 `/home/groot_a/capstone/chatproxy/tls/chatduck.crt`(root:root,0644,regular,nlink1,최대64KiB), 연결은 SNI를 지정한 `127.0.0.1:443` 한 곳이다. 개인키·Docker socket·HTTP·모델·MCP·채팅·ACME API에는 접근하지 않는다. 기존 파일의 실제 소유·권한이 이 계약과 다르면 배포 전 확인하며 검사 조건을 조용히 완화하지 않는다.

## 검사와 결과

`monitor.sh`를 `/usr/local/sbin/capstone-cert-monitor` root:root0500으로 설치하는 계약이다. 공개 CLI는 `check|run`뿐이며 고정 A machine-id와 실행 파일·부모 권한을 확인한다. 전체 작업은 clean environment의 `timeout 29s` 및 1초 후 강제 종료로 제한하고, TLS 연결 자체는 10초+1초다. systemd도 `TimeoutStartSec=30s`, `TimeoutStopSec=1s`를 둔다. 커널의 중단 불가능 I/O까지 절대 30초 완료를 보장하는 뜻은 아니다.

1. 공개 인증서를 bounded snapshot으로 읽고 symlink·권한·파일 identity/size/mtime/ctime의 전후 일치를 검사한다.
2. DNS SAN과 hostname, notBefore/notAfter를 확인한다. 실제 `openssl x509 -checkend`로 **0/7/14/30일**을 순서대로 검사해 `expired`, `within_7_days`, `within_14_days`, `within_30_days`, `ok` 중 하나를 기록한다.
3. `openssl s_client -verify_return_error -verify_hostname`과 호스트 CA 파일로 TLS를 검증한다. 파일의 leaf DER SHA-256 fingerprint와 제공된 leaf fingerprint도 일치해야 `probe_status=verified`다. CA 오류·접속 실패·timeout·형식 오류는 `unavailable`, 서로 다른 인증서는 `mismatch`다. 인증서 만료가 이미 확인됐다면 TLS 실패가 그 `expiry_status=expired`를 지우지 않는다.
4. JSON에는 관측 KST/UTC, 고정 도메인, 상태·고정 원인 코드, 만료 KST/epoch·남은 초, 두 fingerprint만 있다. KST 문자열은 명시적 `+09:00`이며 같은 epoch와 대조한다. 원래 인증서의 UTC 유효기간은 바꾸지 않는다. 인증서 원문·진단 원문·개인키는 출력하지 않는다. `certificate_sha256`은 PEM 파일 SHA가 아니라 leaf DER fingerprint다.

`run`은 `/var/lib/capstone-cert-monitor` root0700의 `status.json`을 root0600으로 원자 교체·fsync하고 같은 JSON을 stdout과 `capstone-cert-monitor` journald 태그로 보낸다. unit은 stdout을 버려 explicit logger와 중복 journal을 만들지 않는다. `check`는 JSON stdout만 내며 상태파일과 journal을 갱신하지 않는다(잠금 및 private scratch는 사용). `.lock`으로 중복 실행을 막으며 scratch는 정상/오류 종료 때 정리한다. SIGKILL·전원 장애로 남은 private scratch는 다음 성공을 뜻하지 않는다.

검증 성공은 rc0, 관측 불가·불일치는 JSON을 저장한 후 rc2, 잠금 충돌은 rc75다. unit은 2/75를 예상 결과로 허용한다. 외부 timeout·프로세스 오류·저장 실패는 새 status를 보장하지 않으므로 **status.json의 시각과 timer/서비스 결과도 함께 확인**해야 한다. 옛 `ok`를 현재 정상으로 해석하지 않는다. 30일·14일·7일은 운영 알림 경계이며 인증서 자동 교체를 시작하지 않는다.

```sh
sudo /usr/local/sbin/capstone-cert-monitor check
sudo systemctl start capstone-cert-monitor.service
sudo journalctl -t capstone-cert-monitor --since '-2 days' -o cat --no-pager
sudo systemctl list-timers capstone-cert-monitor.timer
```

타이머는 `OnCalendar=*-*-* 09:00:00 Asia/Seoul`, `Persistent=true`다. 호스트가 꺼져 있던 예정 실행은 다음 활성화 때 보충될 수 있다. 서비스의 네트워크는 loopback IPv4만 허용하고 개인키 경로는 가린다. 기존 Vector maintenance/rotation에는 연결하지 않는다. B의 전용 규칙은 아래와 같이 설치·native 검증했으며, 정상 상태는 `no_log`다. 예약 실행부터 실제 경보 수신·색인까지는 별도 관측 범위다.

## B Wazuh 검증·설치 기록

**2026-10-15 04:59:47 KST 기준:** [전용 decoder](capstone_certificate_decoders.xml)와 [규칙](capstone_certificate_rules.xml)의 v3 native **51개 PASS** 뒤 같은 manager 컨테이너를 1회 재시작했다. 새 init PID는 `2267662`, analysisd PID는 `2268440`이며 필수 4종 프로세스 running, 기존 보호 파일 SHA 불변, A agent `001` Active를 확인했다. 재시작 후 실제 A의 정상 status를 PID 없는 프로그램명 형식으로 넣은 logtest도 전용 decoder와 `100300/level0`에 일치했다. 이는 실제 상태의 분류 확인이며 운영 입력에 합성 경보를 주입하거나 실제 만료 인증서의 종단 경보를 검증한 결과는 아니다.

설치 대상은 manager의 `/var/ossec/etc/decoders/capstone_certificate_decoders.xml`, `/var/ossec/etc/rules/capstone_certificate_rules.xml` 두 파일이다. B 호스트의 같은 파일은 `/var/lib/docker/volumes/single-node_wazuh_etc/_data/{decoders,rules}/` 아래에 있다. decoder 이름은 `capstone_certificate_json`, program은 정확히 `capstone-cert-monitor`, location은 정확히 `(groot-sec) any->journald`다. 도메인·schema와 canonical 13개 키도 검사한다. program/location 조건은 서명된 출처 증명이 아니다. 유효기간·fingerprint 판정은 A 감시기가 수행하고 B 규칙은 그 결과를 등급에 연결한다.

| 조건 | 규칙 | level |
| --- | --- | --- |
| `ok` + `verified` | `100300`, `no_log` | 0 |
| `within_30_days` + `verified` | `100301` | 3 |
| `within_14_days`, 허용된 모든 probe 상태 | `100302` | 5 |
| `within_7_days`, 허용된 모든 probe 상태 | `100303` | 7 |
| `expired`, 허용된 모든 probe 상태 | `100304` | 10 |
| `ok`/`within_30_days`/`unknown` + `mismatch`/`unavailable` | `100305` | 5 |

따라서 TLS 관측 실패가 7일 이내·만료 경보를 level5로 낮추지 않는다. 감시기가 생성하지 않는 `unknown` + `verified` 조합은 native 음성 경계로 검사했으며 base level0에 남는다고 해서 정상 관측으로 인정하지 않는다. 경보 leaf에는 `ignore=900`, `no_email_alert`, `no_full_log`가 있다. 51개에는 상태 조합, 다른 program/location, 추가·누락·중복 키와 잘못된 JSON 형식 거절이 포함된다.

초기 두 시도는 실패 소스·로그를 보존하고 추가한 파일을 자동 제거했으며 manager 재시작은 하지 않았다. 첫 시도는 program이 있는 syslog JSON에 기본 JSON decoder가 선택되지 않아 전용 `JSON_Decoder`를 추가했다. 두 번째는 Wazuh의 native XML 처리에서 `&gt;`가 location의 `>`로 변환되지 않아 일치하지 않았다. v3는 location 원문을 literal `>`로 고정해 51개 전체를 통과했다. 이 실패 이력은 최종 성공으로 덮어쓰지 않는다.

최종 소스 SHA-256은 decoder `3a7d37d2ce9979da70b196b17adcfed9f33285bb604979c2e7416b7a3c5d281c`, 규칙 `40dc486283cd5dc9e5aaf57bc79ed78be233528c44375914ea2620d31dc1df2d`, [시험](test-certificate-rules.py) `6444e7946b671528ff7d7e263ff5d576e984f4fb082c4207066e9af1da1906f2`다. **실제 만료 경보 종단 확인과 09:00 예약 실행 관측은 남아 있다.**

## 수동 갱신

**2026-10-15 A의 새 읽기 관측에서 현재 공개 인증서 만료를 2027-01-06 15:02:33 KST(+09:00), 즉 06:02:33 UTC로 재확인했다.** 이는 [2026-10-08 DNS 발급 기록](../../dns/README.md#채팅-인증서-배포-2026-10-08-라이브-직접-확인)과 같다. 해당 배포 전 읽기 관측 자체는 native 시험·배포 완료 증거가 아니었다. 이후 설치 결과는 맨 위 04:51:02 KST 기록을 따르며 정기 검사는 매일 **09:00 KST**다. A의 ACME/DuckDNS 외부 HTTPS 제한과 Mac 발급 상태 삭제 때문에 자동 갱신은 구성돼 있지 않다. 2026년 12월 초에 갱신을 준비하고, 경고가 없더라도 만료 전에 완료한다.

1. 접근 가능한 관리자 장치의 **일회성 private 임시 환경**에서 기존 DuckDNS DNS-01 절차로 `chat.grootlab.duckdns.org` 단일 이름 인증서를 발급한다. Mac의 예전 ACME 계정·발급 상태는 삭제됐으므로 남은 상태를 전제로 `--renew`만 실행하지 않는다. 당시 공식 ACME 소스/CA 동작을 다시 확인하며 Homebrew 설치·영구 ACME 상태·무인 SSH 자격증명은 추가하지 않는다. 토큰·개인키는 출력하거나 저장소에 넣지 않는다.
2. `fullchain.pem`과 암호 없는 `privkey.pem`을 A의 root0700 임시 디렉터리로 전송한다. 기존 [deploy_chatduck_cert_A.sh](../deploy_chatduck_cert_A.sh)의 `--check-only`를 먼저 실행한다. 이 검사는 DNS SAN/hostname, 만료까지 24시간 초과, 중간 인증서를 포함한 체인, 키 일치 및 호스트 CA 신뢰를 요구한다. `--check-only`는 Docker나 운영 TLS 파일을 변경하지 않는다.
3. 현재 `chatproxy` CID와 `/etc/nginx/tls` bind가 `/home/groot_a/capstone/chatproxy/tls`를 가리키는지 확인한 뒤 같은 스크립트를 root로 실행한다. 아래 경로는 실제 root private 전송 경로로 바꾼다.

   ```sh
   sudo bash infra/groot-a/deploy_chatduck_cert_A.sh --check-only /ROOT_PRIVATE/fullchain.pem /ROOT_PRIVATE/privkey.pem
   sudo bash infra/groot-a/deploy_chatduck_cert_A.sh /ROOT_PRIVATE/fullchain.pem /ROOT_PRIVATE/privkey.pem
   ```

   배포기는 현재 nginx 설정을 검사하고, TLS 디렉터리의 `.chatduck-backup.<시각>.<고유값>/`에 기존 인증서·키를 각각0600으로 보존한다. 새 인증서0644·키0600을 파일별 rename으로 교체한 뒤 `nginx -t`와 reload를 실행한다. 제공 SNI leaf fingerprint 및 **CA 검증을 켠 Mattermost `/api/v4/system/ping`**까지 통과해야 성공한다. 감시기는 이 배포기를 자동 호출하지 않는다.
4. 교체 후 실패하면 배포기의 EXIT/HUP/INT/TERM 처리에서 백업 두 파일 복원과 nginx 구문 검사·reload를 시도한다. rollback reload 경고가 나오면 즉시 `chatproxy`를 확인한다. 성공 후 수동 복원이 필요하면 출력된 정확한 백업 디렉터리의 `chatduck.crt`·`chatduck.key`를 위 배포기의 입력으로 사용해 `--check-only`부터 다시 수행한다. 이전 인증서도 24시간 초과 유효기간과 CA 신뢰 검사를 통과해야 한다. 복원 시도 메시지만으로 제공 인증서 복구를 판정하지 말고 SNI fingerprint와 HTTPS ping을 다시 확인한다.
5. 감시기가 설치된 뒤에는 `capstone-cert-monitor check`의 `verified`, 기대 fingerprint·만료일도 확인한다. 임시 발급·전송 자료는 정리하고 서버 백업과 비밀 없는 검증 메타데이터는 보존한다. Wazuh 및 내부 별칭의 별도 인증서는 이 절차에서 바꾸지 않는다.

기존 배포기는 컨테이너 이름 `chatproxy`를 사용하며, 고정 CID CAS나 두 파일을 묶은 원자 교체·fsync 기반 crash 복구를 제공하지 않는다. 실행 중 다른 인증서 배포를 겹치지 않게 하고 SIGKILL·호스트 중단 뒤에는 현재 파일·백업·실제 제공 인증서를 확인한 후 복구한다. 이 한계는 이번 감시 후보로 바뀌지 않는다.

## 합성 검증

```sh
bash test-monitor.sh /ABS/certificate-monitor/monitor.sh /EXISTING/PRIVATE/TEMP
```

기존 OpenSSL로 private EC 인증서를 생성해 31/30/15/14/8/7일, 만료·미래·다른 SAN·CN만 있는 인증서·형식 오류를 검사한다. TLS transport만 모의 응답으로 바꾸어 정확한 검증 옵션, 실패·timeout·다른 fingerprint·읽는 중 변경을 검사한다. OpenSSL의 CA/hostname 검증도 실제 합성 인증서로 확인한다. Linux root에서는 추가로 실제 flock/fsync/rename·status 권한·check의 비게시·scratch 정리·symlink 거절을 시험한다. 모의 TLS는 실제 A TLS handshake 성공의 증거가 아니다.

**배포 전 로컬 기록:** 2026-10-15 기존 OpenSSL3.6.4/GNU coreutils를 사용한 **22개 PASS**, Bash 구문 PASS였다. 이 시점에는 Linux root 전용 4개와 실제 A handshake·systemd timer를 아직 실행하지 않았다. 임시 합성 키/인증서/출력은 시험 finally에서 제거됐으며 새 패키지·운영 파일 접근·네트워크 연결은 0이다.

**A native 보완과 최종 결과:** 첫 후보는 A OpenSSL3.0.13에서 8개 통과 뒤 `wrong_hostname` 시험이 실패해 설치 전에 중단됐다. 이 버전의 `x509 -checkhost`는 `does NOT match certificate`를 출력하면서 rc0을 반환했다. v2는 DNS SAN 존재·rc0·정확한 `Hostname chat.grootlab.duckdns.org does match certificate` 문구를 모두 요구한다. 실패 소스/로그는 보존했으며, v2의 기존 **26개 전체 PASS** 뒤 실제 TLS와 설치를 진행했다. 실제 TLS 성공은 모의 transport 시험과 별도로 확인한 결과다.

옵션 근거: [OpenSSL3 s_client](https://docs.openssl.org/3.0/man1/openssl-s_client/)의 검증 오류 반환·hostname 검증, [OpenSSL3 x509](https://docs.openssl.org/3.0/man1/openssl-x509/)의 `-checkend`/fingerprint/SAN 출력.
