# SSH를 통한 외부 추론 연결

사용자 진입점은 루트 `deploy.sh`다. 선택 설정 `LLM_TUNNEL_CONFIG`가 비어 있으면 기존 직접 API 연결을 유지한다. 설정하면 SIEM 역할이 `deployment/inference_tunnel.py`의 사전검사·설치·실제 API 검증을 호출한다. 운영 서버는 초기 설치기로 덮어쓰지 않고 백업 후 해당 구성만 증분 반영한다.

2026-10-27 전환 작업은 기존 `qwen3.6:35b`를 thor에 준비하고 B의 `10.200.10.10:11435`에서 SSH로 thor의 `127.0.0.1:11434`에 연결하는 구성이다. 실제 전환·검사 완료 여부는 [STATUS](../STATUS.md)를 따른다. 모델 태그만 같다는 이유로 동일 모델이라 판단하지 않고 가중치·projector·템플릿·추론 파라미터를 대조한다. 모델은 외부 추론 서버가 직접 받으며 A/B/C에서 온라인 APT를 실행하지 않는다.

## 관리자가 준비할 항목

- B에 기존 OpenSSH client, Python3, iproute2, systemd가 필요하다. 추가 deb/wheel/컨테이너는 없다. 소스 묶음에 새 모듈과 갱신한 역할·설정 예제를 포함한다.
- B에서만 생성한 Ed25519 개인키를 `/etc/capstone-inference/id_ed25519`에 root:root0600으로 둔다. 상위 경로는 root 소유·그룹/전체 쓰기 금지다. 개인키를 Mac 또는 봇에 복사하지 않는다.
- 외부 추론 서버에 전용 계정을 준비하고 공개키에 출발지, `restrict,port-forwarding,permitopen="127.0.0.1:11434",command="/bin/false"`를 제한한다. SSH `Match User`에서 공개키만 허용하고 `AllowTcpForwarding local`, `PermitOpen 127.0.0.1:11434`, `PermitListen none`, `MaxSessions 0`, `ForceCommand /bin/false`, `PermitTTY no`, agent/X11/stream-local forwarding 비활성화를 적용한다. 출발지 제한은 실제 NAT 후 주소를 사용한다.
- API는 추론 서버의 loopback에 유지한다. 사이트 경계에서는 B의 해당 추론 SSH 주소·포트만 허용한다. B의11435는 로컬 프로세스와 허가한 Hermes bridge 경로에서만 접근하게 하며 다른 호스트의 접속은 방화벽으로 차단한다. 모듈 자체가 방화벽을 개방하지 않는다.
- 독립 경로로 확인한 외부 서버의 Ed25519 host key를 아래 설정에 넣는다. 추론 서버 주소는 `LOG_PROTECTED_IPS`에도 넣어 자동 대응의 보호 대상에 포함한다. API URL이 B 주소이므로 외부 목적지를 별도로 명시해야 한다.

설정 파일은 B의 `/etc/capstone-inference/tunnel.json`에 root:root0600으로 준비한다. 아래 주소·키는 실제 확인 값으로 바꾼다. 이 구현은 IPv4, 비특권 포트1024~65535, 사설 B listener, Ed25519만 허용한다.

```json
{
  "schema": 1,
  "remote_host": "192.0.2.40",
  "remote_port": 8022,
  "remote_user": "capstone-inference",
  "listen_host": "10.200.10.10",
  "listen_port": 11435,
  "host_key": "ssh-ed25519 REPLACE_WITH_VERIFIED_PUBLIC_HOST_KEY"
}
```

`site.local.conf`에서 `LLM_TUNNEL_CONFIG=/etc/capstone-inference/tunnel.json`, `LLM_BASE_URL=http://<SIEM_HOST>:11435/v1`, `LLM_MODEL=qwen3.6:35b`를 설정한다. 신규 서버의 root 설치기가 전용 systemd 서비스·고정 목적지 SSH 설정·host pin·설치 영수증을 생성한다. 기존 임의 파일이나 다른 설정의 영수증은 덮어쓰지 않는다. `started_verification_required`는 실제 API 확인 완료가 아니며 이후 verify가 실패하면 설치 성공으로 처리하지 않는다.

## 운영 검증과 복구

Hermes 일반 채팅·자동 관리·Ollama 봇·공동 검토·모델 건강검사의 URL을 함께 대조한다. 일반 채팅의 비추론 설정과 관리 작업의 별도 추론 예산, 기존 MCP·승인 범위는 유지한다. 관리 코드의 무결성 pin과 Hermes 이미지의 가드 pin도 소스 변경과 함께 맞춘다. 날짜가 명시된 과거 Ansible 전환/관찰 영수증은 이전 버전의 기록으로 보존하며 새 가드에 재실행하지 않는다.

먼저 모델/도구 호출을 직접 시험하고, 터널의 원격 명령·다른 목적지·역방향 포워딩 거절, B/Hermes 접속, 타 호스트 접속 차단, 서비스 재시작 후 API 복귀를 확인한다. 이후 운영 URL과 관련 코드를 백업·원자적 교체하고 봇 인증/작업 대기열·새 채팅·건강검사를 확인한다. 실패하면 변경 전 URL/코드를 함께 복원한다. 자동으로 다른 모델이나 기존 DGX로 전환하지 않는다.

모델 건강검사는3분 주기·최대4토큰·요청별10분 유지로 구성한다. 실제 첫 적재 약58초가 관측되어 기본5분 해제보다 앞서 갱신하며 URL/모델 SHA가 다른 과거 성공 캐시는 재사용하지 않는다. 전역 Ollama 설정·다른 모델은 변경하지 않는다. 장기 유휴·장애/재부팅 후 적재 지연의 완전 제거를 뜻하지 않는다.

추론 서버/API 또는 터널이 중단되면 모델 사용 불가로 보고한다. 기존 감시의 A 장애 기록·재전송 대기열과 복구 후 채팅 알림을 유지하며 외부 독립 알림이나 모델 고가용성을 새로 제공하는 구성은 아니다. 재부팅·장기 부하·새3VM 전체 설치·공격/대응 E2E는 별도 검증이다.
