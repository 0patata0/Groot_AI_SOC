# 승인 카드 콜백 출처 고정 IP 후보

2026-11-13 KST. **후보·드라이런까지이며 운영 B에는 미적용**이다. 운영 B 적용은 채팅 컨테이너 재생성(약 1분 채팅 중단)이 필요하다. 사용자 승인 후 관리자231 경유로 `apply_b.py`를 1회 실행한다. [현황 #7](../../../STATUS.md) · [작은 원장](validation.json) · [사고 기록](../../../archive/DIAGNOSTIC_HISTORY.md).

## 문제

승인 브로커(soc-bot)는 Mattermost 카드 버튼 콜백의 TCP 출처를 `RULE_MM_SOURCE_CIDRS`(설치 때 확인한 Mattermost 컨테이너 IP /32) 하나로만 허용한다. 그런데 채팅 네트워크 주소가 동적이라 11/12 정전 복구 재부팅에서 시작 순서가 바뀌었다. mm-app 172.19.0.3이 172.19.0.2로 바뀌었고, 172.19.0.3은 mm-postgres가 받았다. 그 결과 재부팅 이후 카드 승인이 모두 "허용되지 않은 콜백 출처입니다"로 거부됐다. 11/13 07:35 허용값을 현재 IP로 즉시 수정해 복구했지만, 다음 재부팅에서 같은 일이 생길 수 있다. 새 설치 검증(`callback_source_changed`)은 드리프트를 감지만 하고 막지는 못한다.

## 후보

| 대상 | 변경 |
|---|---|
| 운영 B(`/home/groot_b/capstone/mattermost/docker-compose.yml` = 리포 `infra/groot-b/mattermost-compose.yml`) | `mm-net`에 현재 서브넷·게이트웨이(172.19.0.0/16, 172.19.0.1)를 명시하고, 동적 할당은 `ip_range 172.19.128.0/17`로 분리한다. **mm-app 172.19.0.2·mm-postgres 172.19.0.3 고정**([후보 compose](mattermost-compose.candidate.yml)). 현재 주소와 같아 브로커 허용값(172.19.0.2/32)·콜백 URL(172.19.0.1:8090)·Mattermost SSRF 예외(172.19.0.1)는 그대로다 |
| 새 설치(`deployment/roles/siem.sh`) | 새 설정 `CHAT_SUBNET`(기본 `172.30.248.0/28`, 사설 /24~/29). 게이트웨이=첫 주소, **Mattermost=둘째·Postgres=셋째·Hermes=넷째 고정**. 사전검사에서 SIEM_HOST 포함·다른 Docker 네트워크·인터페이스·라우트와의 겹침을 거부한다(`offline_security.py`의 `conflicts()`와 같은 규칙, 자기 채팅 네트워크만 예외). 단일 진입점 `deploy.sh`의 기본값·허용 키·전달 목록, `config.example.conf`, `configuration-guide.md`를 함께 갱신했다 |

## 검증

| 항목 | 결과 |
|---|---|
| 운영 compose = 리포 | 바이트 동일(`a9d599df…`) |
| 운영 B 읽기전용 드라이런(08:07) | 후보 `config --quiet` rc 0. `--dry-run up -d` 계획: 두 컨테이너 정지 → 네트워크 삭제·재생성 → 두 컨테이너 재생성·기동. 현재 compose는 변경 없음(Running). 실제 컨테이너 기동 시각 불변, 임시 파일 삭제 |
| 테스트(`deployment/tests/test_chat_static_ip.py`) | 11/11. 기본 배치, 잘못된·공인·과대·과소 서브넷과 SIEM_HOST 포함 거부, 자기 네트워크 재실행 허용, 다른 Docker·인터페이스·라우트 겹침 거부, compose의 세 서비스 고정 배선·리스트형 네트워크 제거, `deploy.sh` 전달, B 후보의 고정 주소·게이트웨이·동적 범위 분리, **네트워크 정의 외 변경 없음**, 적용 스크립트의 SHA·주소·브로커 값 일치 |
| 설치기 전체 | 337개 중 실패 1(다른 작업의 미추적 `test_firewall_nat`, 무관) |

## 운영 B 적용 방법(승인 후)

`apply_b.py <후보 경로>`를 root로 1회 실행한다. SSH 시간 제한을 피하려고 `systemd-run`으로 분리해 실행한다.

1. 사전조건: 운영 compose·후보 SHA 일치, 현재 주소가 mm-app .2·postgres .3, 브로커 허용값 172.19.0.2/32, Mattermost 정상. 하나라도 다르면 **무변경 거부**한다.
2. compose 백업(`docker-compose.yml.bak-staticip-<시각>`, 소유·권한 유지) → 후보로 교체 → `docker compose up -d`(네트워크·두 컨테이너 재생성).
3. 확인: mm-app healthy, `10.200.10.10:8065/api/v4/system/ping` 200, 주소 .2/.3, 네트워크 IPAM의 `ip_range`, 브로커 허용값 불변.
4. 실패하면 백업 compose로 되돌리고 `up -d`를 1회 다시 실행해 결과를 기록한다. 그 이상의 재시도는 없다.
5. 적용 뒤 승인 카드 1건으로 콜백을 확인하고, 다음 재부팅 뒤에도 주소가 유지되는지 본다.

진행 중인 승인 카드가 없는 시간에 실행한다. 재생성 중에는 채팅·카드 버튼·Hermes 채팅 연결이 잠시 끊긴다.
