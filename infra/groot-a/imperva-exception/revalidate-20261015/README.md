# 2026-10-15 Imperva 예외 격리 재검증

현재 **로컬 순수 14개와 A의 run-02 native 21쌍/42요청이 통과**했다. [실측 메타데이터](validation-2026-10-15.json)의 시험 소스 SHA는 `9cc774e18ea79a82e5e83e2d183fdc0e578bae6403772220e87a034f0870c98e`이며 현재 `run-native.py`와 일치한다. 양성2개에서 해당 CRS 경보가 제외되고, 조건 이탈17개는 baseline/candidate의 전체 룰 ID 집합이 같으며, XSS2개는 커스텀 `10300`·CRS XSS·`949110`을 유지했다. 이는 설치된 예외 원본의 격리 검증이며 운영 자연 요청의 예외 적중은 아직 입증하지 못했다.

native 결과에서 UID/GID101 writer 두 개는 강제 종료 없이 exit0으로 종료했다. private netns는 전후 동일한 lo만 유지했고 외부 인터페이스/default route0, 운영 요청·신호0, 운영 서비스·소스 불변이었다. cleanup 오류0·남은 private writer0·private 경로 제거를 확인했다. 합성 원문과 실행 증거는 A `/var/backups/capstone-imperva-revalidate-20261015`에 보존했으며 임시 stage는 제거됐다. 이 문서의 독립 확인은 보존된 메타데이터 전수 대조이며 원문 재조회는 수행하지 않았다.

자연 관측의 고정 cutoff는 **2026-10-15 10:21:38 KST**다. 확인 가능한 보존 범위에서 `.9` access는 최근24시간4건·최근5시간0건, 검증된 시간대가 있는 대응 audit는 두 구간 모두0건이다. `coverage_complete=false`이며, RelevantOnly·최소 access 필드·보존 공백 때문에 exact exception hit를 입증한 것으로 판정하지 않는다.

첫 native run-01은 source `086d64b9…`에서 private 설정의 운영 경로 잔존 검사로 nginx 시작 전에 거절됐다. 요청0·writer0·cleanup 오류0·private 경로 제거를 실측했다. 주석의 경로와 활성 설정을 구별하지 않던 검사를 보완했으며 활성 경로 거절은 유지한다. 통과한 후속판은 추가로 Docker inspect 명시 metadata projection, private 원본 삭제 직전 init/starttick·work inode 대조, 보존본 SHA·하위 디렉터리 fsync를 적용했다. 첫 실패 증거는 별도로 보존했고 run-02의 새 output에서만 재검증했다.

`run-native.py`는 현 WAF CID `6c72d5a5…`, 기존 이미지, 원본 예외 SHA `d95e75f3…`를 고정한다. 기존 `../test-native.py`의 21개 case/request와 `../../../normalization/vector/waf-rotation/run-probe-a.py`의 PID·pidfd·비상 정리 함수를 SHA 검증 후 재사용하며, 두 원본은 수정하지 않는다. 실제 실행 시 저장소 상대 배치를 보존해야 한다.

운영자는 A의 기존 Python/nginx/ModSecurity/ip/nsenter/unshare만 사용한다. 새 컨테이너·패키지·운영 설정 변경·reload·서비스 신호·외부 HTTP 요청은 없다. 기존 rule-change/vector 공유 lock 두 개를 shared/nonblocking으로 잡아 참가하는 운영 변경과 회전이 겹치지 않게 한다. 다른 운영자가 이 lock을 갖고 있으면 새 시도 전에 보류한다.

새 익명 netns에서 lo만 확인한 뒤 `.9`, `.8`, `172.18.0.2`, `.3`을 lo에만 올린다. host·운영 WAF와 다른 namespace이며 외부 인터페이스/default route가 없음을 전후 검증한다. 운영 네트워크에는 이 주소를 등록하거나 패킷을 보내지 않는다. host의 interface/address/route도 읽기 전후 대조한다.

현 setup의 포함 순서대로 public config를 private 설정 하나로 펼친다. override의 정확 `Include /var/log/modsecurity/capstone-managed/audit-path.conf` 한 줄을 제거하고 audit/debug/tmp/data/upload를 모두 private UID101 디렉터리로 돌린다. `nginx -t`도 이 private 설정으로 실행한다. baseline은 설치된 `REQUEST-900-CAPSTONE-SCANNER.conf` 하나만 제외하며 candidate는 해당 파일의 **원본 바이트 그대로** 포함한다. private `SecAuditEngine On`은 42개 합성 원문을 빠짐없이 검증하기 위한 시험 전용 설정이다.

두 private nginx를 UID/GID101로 순차 실행해 21쌍/42요청을 보낸다. 양성2개는 해당 CRS ID가 사라지고, 이탈17개는 전체 ID 집합이 같으며, XSS2개는 `10300`/CRS XSS/`949110`이 유지되어야 한다. 이 fixture의 정적 HTTP200을 운영 upstream302 증거로 해석하지 않는다. SQLi 전체/중복 Host 전체 회귀나 실사용 탐지율을 주장하지 않는다.

```sh
# 향후 별도 재검증 예시다. 완료된 run-01/run-02 경로는 재사용하지 않는다.
# 먼저 source SHA와 아래 두 의존성 SHA를 검토한다. root가 전용 부모를 준비한다.
# /var/tmp/capstone-imperva-revalidate-20261015 : root:root 0700
python3 -B /ABS/infra/groot-a/imperva-exception/revalidate-20261015/test-offline.py
python3 -B /ABS/infra/groot-a/imperva-exception/revalidate-20261015/run-native.py \
  --output /var/tmp/capstone-imperva-revalidate-20261015/run-NEXT
```

기존 output은 재사용하지 않는다. 성공/실패 result, synthetic audit, private 설정·로그와 명령 진단은 A root-only output에 보존하며 stdout은 메타데이터만 내보낸다. private nginx 종료와 증거 복사 후에만 해당 private tree를 제거한다. outer 240초 뒤 TERM으로 finally 정리를 요청하고 30초 내 종료하지 않으면 검증된 별도 namespace/PID/start-ticks 대상만 비상 정리하며 파일은 보존한다. 강제 종료·정리 오류는 성공이 아니다. 로그collector/Vector/manager/Indexer 검증은 이번 범위에 포함하지 않는다.

의존성:

- `imperva-exception/test-native.py`: `64ac65da6ab011a438f7791da9c93b6b46fe140c9b506be1303af3aefcbf48d7`
- `vector/waf-rotation/run-probe-a.py`: `ae12559a4641e596c647bc009a7f0d68906e2890d8201d18fca75537e324f7fe`

자연 효과 확인은 별도로 기존 bounded 관측기의 상세 access/audit와 B 경보를 대조해야 한다. nolog 예외·RelevantOnly·최소 access 필드 한계 때문에 자연 audit0/경보0을 exact chain-hit로 바꾸어 기록하지 않는다.
