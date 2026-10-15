# 설치 순서

> **15분 자연 주기 확인:** 09:33:15~09:33:22 KST, Invocationc9e8e4e93b5b4ba593138707ef77bdc1, exit0/new0/reused18/13,741건. 첫활성화실행에이어실제다음주기를확인했다.

이 폴더는 root 운영자가 실행한 일회성 설치 도구다. **2026-10-15 runtime native33·설치 helper20 PASS 후 B 키09:14/A 설치09:14:52/B 설치09:15:09 KST 완료**를 확인했다. 설치 도구 자체는 계정·키·sudoers·unit까지만 만들었고, 실제18배치 보존·재사용 검증·timer 활성화는 부모 운영자의 별도 단계였다. 첫 자동 실행은09:18:04 exit0·신규0/재사용18로 끝났으며 이후15분 자연 주기 관측과 영구 증거 정리는 아직 대기다. [최신 결과](../validation-2026-10-15.json)를 참고한다. 아래 명령은 수행 순서 기록이며 기존 설치에 다시 실행하지 않는다. 기존 파일이나 같은 단계의 backup이 있으면 중단하고 자동 재실행/원복하지 않는다.

전체 `history-auto-transfer/`를 같은 상대 구조로 양 서버의 root 전용 stage에 전달한다. 상위 디렉터리는 root 소유·비root 쓰기 금지, 파일은 root:root0400·regular·nlink1이어야 한다. `/var/tmp`의 sticky 공유 anchor만 예외이며 그 아래는 모두 root 전용이어야 한다. root가 별도 확인한 배포 파일 SHA와 `source-pins.sha256`을 대조한다. 부모의 설치된 수동 receiver 5개는 복사하거나 수정하지 않는다.

1. B에서 `bash deploy/test-native.sh`로 공개키·no-replace 게시 helper의 **20개 격리 시험 PASS**를 확인했다. 합성 key는 private fixture 안에만 있었고 끝나면 제거했다. 실제 계정/sudoers/SSH/systemd는 호출하지 않았다. 이 시험은 Mac에서 실행하지 않았다.
2. B에서 `timeout --kill-after=5s 180s bash -p deploy/deploy-b.sh key`를 한 번 실행한다. `/etc/capstone-history-transfer/id_ed25519`는 B root0600으로만 남는다. 영수증의 공개키와 `/var/backups/capstone-history-transfer-20261015/b-key/public.key`만 A로 전달한다. private key를 출력·전달·백업 source에 포함하지 않는다.
3. A에서 root0400·단일 링크로 전달된 공개키 파일의 SHA를 고정하여 `timeout --kill-after=5s 180s bash -p deploy/deploy-a.sh /absolute/public.key EXPECTED_SHA256`를 한 번 실행한다. `capstone-hist` 계정·group·home·고정 helper·sudoers 부재를 확인하고, 잠긴 암호/강제 명령/source IP 제한/명령 digest가 있는 sudo 항목을 설치한다. 새 계정으로 실제 sudo 거절 시험과 `sshd -T` 유효 정책을 검사한다. sshd reload와 raw 읽기 전송은 없다.
4. 기존 신뢰 접속으로 확보한 A ed25519 **공개 host key**를 B의 별도 root0400·단일 링크 파일로 전달하고 SHA를 고정한다. `timeout --kill-after=5s 180s bash -p deploy/deploy-b.sh install /absolute/host-public.key EXPECTED_SHA256`를 한 번 실행한다. strict known_hosts·B runtime·새 상태 디렉터리·service/timer를 설치한다. `systemd-analyze verify`와 `daemon-reload` 후 timer disabled/inactive를 요구한다. 이 단계에서는 receiver와 기존 receipt를 변경하지 않는다.
5. 부모 운영자가 실제 제한 SSH 성공/거절, 최초 pull과 기존 수신기 영수증·원본 불변, 동일 배치 재실행·영수증 재사용을 확인한 뒤 timer를 활성화한다. 15분 뒤 자연 실행은 별도 증거로 확인한다.

공개키 입력은 ed25519 정확 한 줄/최종 LF/1KiB 이하/SHA/owner/mode/nlink/native `ssh-keygen` 검증을 통과해야 한다. 각 단계는 root0700의 독점 backup에 source와 intent를 내구 보존한 뒤 변경하며, 공개 파일은 같은 디렉터리 임시 파일의 SHA/fsync 후 hardlink no-replace 방식으로 게시한다. 마지막 temp 링크를 제거하고 nlink1·SHA·부모 fsync를 다시 확인한다. 복사본과 실제 설치 파일은 별도 inode다.

실패 영수증은 고정 phase/exit와 `inspect_required`, `automatic_retry:false`만 기록한다. 사용자 생성·키 생성·systemd reload처럼 외부 상태를 바꾸는 명령은 각각 30초 제한이며 운영자는 전체 180초 제한을 적용한다. 강제 종료되면 영수증이 없을 수 있으므로 backup·현재 파일·계정을 직접 점검하고 남은 작업을 판정해야 한다. 부분 설치를 삭제하거나 동일 스크립트를 무조건 다시 실행하지 않는다. 기존 공유 관리자 수동 편집까지 원자적으로 배제하는 배포 트랜잭션은 아니다.
