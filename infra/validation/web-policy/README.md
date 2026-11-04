# 공개 웹 검사·관리 인증

2026-11-04 운영 반영. 실제 범위와 남은 과제는 [STATUS](../../../STATUS.md), SOC 역할은 [업무별 실행 범위](SOC_CAPABILITIES.md)를 따른다.

## 변경과 확인

| 구분 | 이전 문제 | 현재 결과 |
|---|---|---|
| Log4Shell UI·API | A에서 C로 직접 전달해 WAF 미경유 | UI·API·등록 HTTP3개 모두 기존 WAF 경유, A가 신뢰 헤더를 덮어씀 |
| 인증과 검사 | 요청별10031이 DetectionOnly로 전환 |10031 제거, 인증 여부와 관계없이10030/CRS On |
| 웹 제어 | 익명도 실습 실행·중지·터미널 가능 | 관리자231/32와600초 IP 결속 HMAC 세션 모두 필요 |
| 감사 | 새 관리 경로에 쿠키·proof·터미널 입력 복사 위험 | 검사 자체는 유지하고 bulk 헤더·본문 감사 사본 제외. 메타데이터·실제 탐지 메시지는 유지 |
| WAF 대응 증거 | 프록시 신뢰 SHA가 이전 관리 ACL 변경 전 값 | 검토한 현재 프록시·WAF vhost SHA 재등록, 실제 writer 두 번 검증 |

SQLi/XSS/JNDI3건은 설치된 동일 WAF 이미지의 외부망 없는 컨테이너에서 실제 CRS 탐지·403·Enabled를 확인했다. 전체 네이티브47요청은 이전20+후보27이고 실제 앱 대신 고립 backend을 사용했다. C의 기존 vendor로 ASGI54검사, 로컬 배포6·portable TLS16·SOC 설치37·서비스 설치50·bootstrap14·source bundle1·JS UI를 검증했다. bootstrap의 예전 아이콘 fixture 누락도 정정했다. 새 OS 전체 설치는 실행하지 않았다.

실제 Kali232 직접 SSH에서14조건을 확인했다. UI·상태·세션200, DVWA302, 채팅200; 관리자 challenge·stop·옛 쿠키/위조 관리자 주소403; 비공개 교환·미등록 경로404; UI/API 무해 canary403; C 내부 웹 직접 연결은 시간 초과다. 시간 초과는 접근 불가 관측이며 특정 DROP 룰의 직접 증명은 아니다. 관리자231의 challenge200·Wazuh302와 신규 경유 SSH도 확인했다. 실제 브라우저 인증→제어 E2E와 새 악성 공격의 센서→LLM→카드/대응 전체 회귀는 별도다.

관리형 HTTP3개는 검증 당시 모두 기존 중지 상태였다. 콘솔200을 실제 취약 서비스3개의 가동으로 표시하지 않는다. WAF/IDS/FW 전체 우회 부재나 일반 공격 탐지율100%를 주장하지 않는다.

## 기존 서버 배포와 복구

사용자 진입점은 루트 `deploy.sh` 하나다. 이는 고정 A/C 기존 배포용 운영자 유지보수 기능이며 MCP나 LLM의 일반 셸 권한이 아니다. 신규 설치는 기존 역할별 설치가 같은 최신 소스를 반입한다.

```sh
sudo bash deploy.sh --web-security prepare --role a --source-root /검토한/저장소
sudo bash deploy.sh --web-security prepare --role c --source-root /검토한/저장소
sudo bash deploy.sh --web-security apply --directory /출력된/정확한/change-경로 --approved-plan-sha256 승인한SHA
sudo bash deploy.sh --web-security verify --directory /출력된/정확한/change-경로
sudo bash deploy.sh --web-security confirm --directory /출력된/정확한/change-경로
```

`prepare`는 원본 바이트·권한·SHA·컨테이너 식별자와 후보를 root 전용 `/var/lib/capstone-web-security/change-*`에 보존한다. 실행 코드까지 계획 SHA에 결속한다. `apply`는 정확 SHA와 현재 원본을 대조하고15분 독립 systemd 복구 타이머를 먼저 가동한다. A는 bind inode를 유지하고 두 Nginx 문법 검사/reload만, C는 관리 API 서비스만 재시작한다. 외부 검증 뒤 `confirm`이 확정 표식을 먼저 남기고 타이머를 끈다. 확정 뒤 자동 복구는 무동작이며 운영 수동 원복은 이번에 실행하지 않았다.

실제 확정 경로는 A `change-822c1487022f414f`, C `change-913fdb0a9c0c4d8e`다. 승인된 원래 recovery.py/manifest를 수정하지 않는다. 코드가 다른 새 checkout으로 기존 원복 코드를 대체하지 않는다.

```sh
sudo python3 -I -B /var/lib/capstone-web-security/change-정확한ID/recovery.py rollback --directory /var/lib/capstone-web-security/change-정확한ID
```

다른 변경이 뒤에 적용됐다면 역순으로 복구한다. 현재 source/컨테이너가 승인 프로필과 다르면 강제로 덮지 않는다. DB·승인·모델·차단 TTL은 원복 대상이 아니다. A의 이전 관리 ACL 백업은 전체 proxy SHA가 옛 값이므로 이번 웹 변경을 먼저 복구해야 한다.

**WAF 신뢰 등록은 설정 변경/원복과 함께 처리한다.** `/etc/rule-change/waf-evidence.json`은 sensor/proxy CID·현재 설정을 엄격히 검사하며 불일치 때 증거를 거부한다. 이번 재등록은 CID·binding·목적지·포트·증거 요건을 유지하고 승인된 proxy/vhost 두 SHA만 바꿨다. 변경 전/후 JSON과 검토한 enrollment 코드를 A의 위 복구 디렉터리에 보존한다. 변경 전 등록 자체가 이미 옛 proxy SHA였으므로 그 파일만 복사해 원복하면 안 된다. 원복 시 복원된 정확 설정을 재검토·등록하고 writer/원본 증거를 다시 확인한다. A의 정확한 이전3파일 프로필을 복구·대조한 뒤에만 같은 디렉터리의 `enroll-reviewed-before-profile.py`를 root로 실행해 이전3개 경로의 등록을 재생성할 수 있다. 이 파일은 변경 전 Git 원본을 보존한 운영자 도구이며 이번에 실행하지 않았다. 현재4개 경로를 등록할 때는 `enroll-reviewed-waf.py`가 보존돼 있다. 등록만으로 과거 거부 요청이 소급 실행되지는 않는다.

## 초기 설치·추가 의존성

`deploy.sh`의 source bundle에는 `deployment/`·`infra/`가 포함된다. 기존 service bootstrap이 새 API·UI와 관리자 CIDR을 설치하고 security renderer가 UI/API를 포함한4개 WAF 경로를 렌더링한다. 관리자 CIDR은 신규 설치의 `MANAGEMENT_ALLOWED_CIDRS`를 사용한다. 공개 `LAB_ALLOWED_CIDRS=all`은 웹 열람 범위이고 제어 권한은 아니다. 추가 deb/wheel/이미지·포트·일반 sudo 위임은 없다.

ModSecurity의 요청별 제어와 감사 부분 설정은 [공식 동작](https://modsecurity.org/docs/3-reference-manual/3-5-actions/#ctl)을 기준으로 실제 설치 이미지에서 검증했다. bulk 감사 제외는 모든 탐지 메시지에 임의 비밀 값이 절대 포함되지 않는다는 보증이 아니므로 실제 키를 공격 문자열에 넣거나 로그/채팅으로 전달하지 않는다.
