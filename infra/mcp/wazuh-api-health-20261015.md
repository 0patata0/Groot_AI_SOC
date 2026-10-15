# Wazuh API 재시작 표시 복구·전체 서버 점검 — 2026-10-15

**17:20~17:40 KST 점검에서 Wazuh API 장애를 복구하고 설명 정책을 반영했다.** API의 `restarting` 표시는 실제 다섯 데몬의 반복 재시작이 아니라 남아 있던 재시작 상태 파일 때문이었다. 따라서 앞선 프로세스 정상 확인만으로 LLM의 오류 응답까지 정상이라고 판단할 수 없었다. A/B/C의 다른 운영 서비스에서는 현재 재시작 루프·OOM·systemd 실패를 발견하지 않았다. 아래 수치는 해당 시점의 관측이며 지속적인 무장애·무손실 보장이 아니다.

## API 장애 원인과 적용

- **직접 확인:** 17:20 B의 API 인증이 HTTP500·Wazuh 오류1017을 반환했다. 상세 내용은 node01의 `wazuh-modulesd`, `wazuh-analysisd`, `wazuh-execd`, `wazuh-db`, `wazuh-remoted`가 `restarting`이라는 것이었다. 실제 프로세스는 09:10:57~58 KST부터 실행 중이었다.
- **직접 확인:** UTC00:10:45에 생성된 `.restart` 표시가 남아 있었다. **이전 작업 기록과 대조:** 09:10의 `wazuh-control restart` 도중 컨테이너가 09:10:50에 재기동된 이력과 시간이 맞는다. 중단된 시작/재시작 절차가 상태 표시를 남긴 것으로 판단한다.
- **복구:** 17:24:38.520263 KST에 파일 목록·mtime·inode, 실제 PID·기동 ticks, 공식 시작 스크립트의 잠금을 대조하고 백업한 뒤 오래된 상태 표시만 제거했다. 데몬·컨테이너 재시작은 0회다. 백업은 `/var/backups/capstone-wazuh-api/20261015T1727`이며 **디렉터리 접미사는 식별명이지 실제 실행 시각이 아니다.** 앞선 `1724`·`1726` 시도는 안전 검사에서 `PermissionError`로 변경 전에 거절됐다.
- **미구현:** 이번 조치는 잔존 상태 파일의 수동 복구다. 시작/재시작 완료 후 API readiness 검증과 상태 불일치의 안전한 처리 코드는 아직 보강하지 않았다. 이후 같은 현상에서 파일을 무조건 삭제하거나 서비스를 반복 재시작하는 방식으로 운영하지 않는다.

## 복구 후 조회 검증

| 시각(KST) | 직접 확인한 결과 |
|---|---|
| 17:25 | API 인증·manager status·agents가 HTTP200, A/C 에이전트 Active |
| 17:25 | 직전24시간 경보 6,209건, 조회 대상60개 shard 모두 성공. 해당 검색 범위의 시점별 집계이며 전체 보안 이벤트 무손실을 뜻하지 않음 |
| 17:29 | 실제 Hermes UID995 환경에서 MCP 에이전트3개 조회 성공, 직전24시간 Suricata·WAF 각각3건 표본 조회 성공, 취약점·remoted 읽기 성공 |
| 17:30 | Dashboard의 에이전트 모니터링 성공 기록 |
| 17:33까지 | 조사한 Hermes·Dashboard 로그에서 복구 후 같은 API 오류 재발을 관측하지 않음 |

Hermes의 `get_wazuh_cluster_health`가 클러스터 비활성을 반환하는 것은 단일 manager의 설정이다. 이를 manager·agent 중단이나 권한 부족으로 단정하면 안 된다. 또한 기간별 공격/보안 경보와 현재 CVE 인벤토리는 별개 자료다.

## 서버별 현재 상태

| 대상 | 점검 결과 |
|---|---|
| A security, 17:23~17:25 | systemd failed0. WAF healthy·DetectionOnly, Suricata passive, chatproxy running. 운영 컨테이너 Restarting=false·RestartCount0, 최근3시간 lifecycle 이벤트0. Wazuh5프로세스 running·connected·buffer0. Suricata EVE 실시간 기록·kernel_drops/errors/invalid0. Vector heartbeat17:25:36, ready/evidence17:25:37, 해당 buffer0. 디스크18%·inode4%·메모리 available 약4.6GiB·swap0·OOM없음 |
| B siem | systemd failed0·OOM없음, 디스크26%·메모리 available 약12GB. manager의 관측 queue/drop0, Mattermost·DB·파일 저장소 확인 성공. API는 위 복구 후 정상 |
| C service, 17:23~17:24 | systemd failed0·pending jobs0. Apache·Docker·MariaDB·Wazuh active/running·NRestarts0. 에이전트 connected·ACK17:23:30·buffer0. Log4Shell 컨테이너 running·RestartCount0·최근3시간 lifecycle 이벤트0. 디스크15%·inode3%·메모리 available4,974MiB·swap0. 최근3시간 error급 journal·kernel OOM/I/O/segfault 일치0. Asia/Seoul·NTP동기화 정상 |
| 웹 경로 | A 경유 Log4Shell·DVWA HTTP200, Mattermost HTTPS ping200·CA 검증 성공. C 직접 Log4Shell UI200, backend 정상 헤더 GET200·헤더 누락400(예상 동작). A WAF·chatproxy nginx 설정 검사 성공 |
| DGX .110/.111 | 두 Ollama `/api/tags` HTTP200. **DGX 서버에 SSH하여 OS·GPU·프로세스 전체를 점검한 것은 아님** |

A의 `waf-before-20261015`는 종료된 이전 보관 컨테이너(exit0)다. 과거 health 상태를 현재 WAF 장애로 계산하지 않았다. 주기적 oneshot의 `inactive/dead`도 마지막 Result=success와 활성 timer를 함께 확인했다. C의 `fwupd-refresh.timer`는 enabled/active이며 service는 inactive·Result=success·ExecMainStatus101이었다. 과거 중지 범위는 A/B였으므로 C를 새 장애로 분류하지 않았으며 이번 점검에서는 정책을 변경하지 않았다.

## 남은 문제와 관측된 경고

| 항목 | 현재 판단·후속 |
|---|---|
| CTI 취약점 피드 | `content-updater` 시간 초과 반복, 마지막 관측17:23:10. 기존 취약점4,841건은 읽히지만 최신 피드 반영은 보장할 수 없다. 가장 최근 `detected_at`이9/26이라는 사실은 피드 갱신 시각과 다르다. CTI 연결과 승인 가능한 오프라인 피드 반입 경로를 조사해야 함 |
| MCP CVE 표시 | MCP에서는 CVE가 `Unknown`으로 나오지만 Indexer의 `vulnerability.id`는 존재한다. 원천 데이터 소실로 단정하지 않고 도구의 표시 매핑을 후속 수정해야 함 |
| Indexer yellow | 단일 노드, primary90개 모두 STARTED. unassigned4개는 모두 시스템 경보 인덱스의 replica로, 현재 primary 손실 증거가 아니다. 노드 장애 시 복제본으로 보호할 수 없는 한계는 유지됨 |
| Mattermost 푸시 | 최근1시간 시간 초과138건. 이미 보류한 모바일 외부 통신 문제 지속. 제품공지 조회 시간 초과2건·게시물 속성 파싱 경고1건은 단발성 관측 |
| A 원천 행 검사 | 16:33:02 `collection_raw_line_scan_unavailable`1건. 17:23:02에는 binding 일치·세 원천 안정·`statuses=[]`로 회복. 당시 상세 원인은 확정하지 않음 |
| A 네트워크 경고 | 14:26~14:27 제거된 veth 인터페이스 조회와 notification PID 경고. 현재 네트워크 장애·최근 반복 증거 없음 |
| Wazuh 대시보드 인증서 | self-signed로 일반 CA 검증 실패. 기존 별도 인증서 구성으로 기록된 제한이며 현재 재시작 문제와 구분. 인증서 후속은 보류 순서를 유지 |

복구 전 Hermes 경고17건 중 API 인증500 관련7건 외 도구 인자·URL 관련10건은 상세 원인을 확정하지 않았다. Dashboard 오류23건은 모두 API 복구 전이었으며 이후 모니터링 성공을 확인했다. 통신 성공 표본만으로 과거 누락이나 장시간 안정성까지 판정하지 않는다.

## LLM 설명 정책과 다음 순서

`infra/hermes/SOUL.groot.md`에 API1017과 실제 프로세스 상태, 클러스터 비활성과 권한 오류, 기간별 경보와 현재 CVE를 구분하는 지침3개를 추가했다. 기존 정책 업데이트 테스트7개와 블록 구조 검사를 통과한 뒤 **17:36:20.973752 KST 라이브에 적용했다.** 17:34 첫 시도는 새 활성 채팅 lease 때문에 변경 전에 거절됐으며,17:35:50 idle을 확인하고 재시도했다.

기존42개 대화 세션의 정책 프롬프트 참조만 갱신하고 DB integrity 정상·다른 테이블 불변·cron 바이트 불변을 확인했다. 기존 Hermes 컨테이너만 stop/start1회 후17:36:21 running을 확인했고 관리 timer도 active로 복원했다. manager·보안 컨테이너 재시작은0회다. 정책 백업은 `/var/backups/capstone-wazuh-api/policy-20261015/rule-edit-policy-fse1sznh`, 정책 블록 SHA-256은 `89ae6e46aaaea5d5bdd123919737b3b768ed3ffc9caaeec842747b8cbb8e9085`다. 17:38 Mattermost/API 연결 connected·needs_attention=false, gateway heartbeat 갱신·active_agents0·현재42세션 정책 참조·DB quick_check=ok를 확인했다. 17:40 별도 자동 관리 실행용 SOUL에도 같은 블록을 반영하고 관리 timer를 복원했다. 완료된 관리 사건의 과거 세션은 변경하지 않았다. 실제 .111 모델의 격리 평가에서 클러스터 비활성 설명은13.017초에 정확히 반환됐다. API1017 사례는1024토큰 한도에서 빈 출력/length였으며, 평가에만4096한도를 적용한 재시험은14.873초에 실제 프로세스 재시작을 단정할 수 없다고 답했다. 운영 모델 설정·토큰 한도는 변경하지 않았고 평가의 도구 호출·채팅 전송은0이다. **이 표본 통과는 자연 대화 전체의 정확도를 보장하지 않는다.**

1. 설명 정책의 채팅 연결과 두 격리 해석 사례 확인은 완료했다. 자연 대화 품질은 계속 관측한다.
2. manager 시작/재시작 이후 API readiness 검증과 잔존 상태 감시를 보강한다. 현재는 미구현이다.
3. CTI 피드 연결 실패를 조사하고 승인된 직접 연결 또는 오프라인 반입 방식을 검토한다.
4. MCP의 CVE 필드 매핑을 수정·검증하고 단일 노드 Indexer의 백업·복구·이중화 계획을 이어간다.

실제 공격 E2E, 기존 영속 큐·장애 복구와 보관 과제는 별도로 남아 있다. 모바일 푸시·프로젝트 VPN·대시보드 인증서 보류 결정을 변경하지 않았다. 이번 점검에 Mac 패키지 설치는 없으며 작업 임시파일 정리와 대화기록 갱신은 전체 작업 마감에서 확인한다.

CTI 후속에는 [공식 오프라인 취약점 피드 절차](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/configuring-scans.html#offline-vulnerability-detection)를 적용할 수 있다. 외부 접근 가능한 별도 서버에서 최신 스냅샷을 반입하고 내부 `offline-url`로 공급하는 방식이며, 이번 점검에서 다운로드·설정 변경·피드 교체는 하지 않았다.
