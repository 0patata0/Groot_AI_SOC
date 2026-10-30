# 데이터 출처와 사용 범위

## Linux-APT 원문 조사 초안 후속 — 2026-10-30 KST

> **Attack Flow 별도 후속:** [고정 원본/의미 정의](../datasets/ATTACK_FLOW_SOURCE_SPEC.json)와 [그래프 검증 원장](../datasets/ATTACK_FLOW_GRAPH_REVIEW.json)에 조건147·AND89·OR29와 전체2,113연결의 보존 결과를 기록했다. MITRE CTID corpus의 인용 자료를 포함하며 Apache-2.0 원문 LICENSE/변경 NOTICE를 보존한다. 기존41개를 새 원천/독립 사건으로 중복 집계하지 않는다. 조건 ordinary anchor1개는 참/거짓을 추측하지 않으며 Maastricht 표현 일부는 공식 대학 공개 Fox-IT 보고서 관련 단락만으로 뒷받침되지 않아 사실 정답 생성을 보류한다. 이 후속 작업이 아래의 ‘새 파서 미구현’ 과거 기록을 갱신한다. 학습 편입은0이다.

> **후속 입력 검수:** [원장](SOC_OBSERVATION_INPUT_REVIEW.json)은 AIT9·Linux-APT8 초안을 입력 후보17개로 정리한 결과다. 근거94개의 원문 좌표·해시 연결과 관측값을 보존했다. 제공자 주석은 주석으로 남기되 phase_label·의미 있는 사건ID·검토 답변은 입력에 복사하지 않는다. 주석 없는 기법 예측 평가가 아닌 근거 검토 과제이며 질문·해석은 프로젝트 작성이다.
>
> AIT LDS의 CC-BY-NC-SA-4.0와 ADS의 CC-BY-4.0, Linux-APT의 CC-BY-4.0를 구분하며 출처 고지 두 파일을 그대로 보존했다. 기존 학습 환경6묶음/원천2종으로 새 독립 사건17개나 최종평가로 세지 않는다. 완전히 같은 답변4개(고유 답변14개)가 있어 배합 검토가 남았다. 33개 과거파일·42,830행에서 첫 사용자 입력 완전일치0건이나 V4/V5 여섯 파일은 미확인이다. 아카이브를 포함한 검사 행 수는 고유 학습 건수가 아니다. 약43% 입력 바이트 감소는 토큰/속도 개선이 아니며 실제 tokenizer 검사는 접속 문제로 미실행이다. 신규 학습 편입은0이다.

[원장](LINUX_APT_CASE_REVIEW.json)에 CSV 2개의 원문 69개와 조사 초안 8개를 연결했다. 데이터·논문 출처는 기존 Linux-APT DOI를 따르며 질문·해석·추가 조사는 프로젝트 작성이다. 기관 공식 QA, 독립 사건 8개 또는 새 학습 편입으로 세지 않는다. 감사 결과에 제어문자 뒤의 식별 값이 섞인 사례, decoder와 FIM 원문이 다른 사례, SELinux 설명과 AppArmor 원문이 다른 사례를 원문 해시와 좌표로 검증했다.

큐 해석은 [Wazuh v4.5.2 공식 룰](https://github.com/wazuh/wazuh/blob/v4.5.2/ruleset/rules/0016-wazuh_rules.xml)의 해시와 [현재 큐 문서](https://documentation.wazuh.com/current/user-manual/manager/wazuh-server-queue.html)를 별도로 확인했다. 큐 정상 복귀는 유실 로그 재수집의 증거가 아니다. 69행의 시간대는 미상으로 보존한다. 출발지와 보고 에이전트가 같다는 사실만으로 동일 세션이나 공격 성공을 단정하지 않는다. 자료에 없는 정답·실운영 정상 판정·도구 실행은 추가하지 않았다.

이전 122,563행 전수 검증과 이번 69행 맥락 검수는 범위가 다르다. 큐 사례만 선택 CSV의 대상 룰 전수이며 나머지는 명시된 일부 기록이다. 같은 원천과 파생본을 같은 분할에 두고, 독립 최종 평가와 입력 길이·문항을 검수하는 일이 남았다.

이하 이전 출처 이력이다.

## Linux-APT 전수 확인 후속 — 2026-10-30T09:04:02.365903+09:00

[공식 원본](https://zenodo.org/records/10685642)의 17 CSV **122,563행 / 208,367,683B**를 제공 MD5·크기와 대조하고 SHA256을 남겼다. [공개 검사 원장](LINUX_APT_EVIDENCE_REVIEW.json)과 [고정 파일 목록](LINUX_APT_SOURCE_SPEC.json)으로 재현한다. 아래887행은 최초 부분 검토 이력이며 이 후속 검토가 확인 범위를 확장한다.

- [원 논문 표1](https://pmc.ncbi.nlm.nih.gov/articles/PMC11220842/)의 개별17파일 수는 전부 실측과 일치한다. 합본 표기122,565와 가공본125,899, 본문125,898은 서로 구분한다. 합본/가공본 자체의 차이는 아직 대조하지 않았으며 추가 독립 자료로 합산하지 않는다. 논문 라이선스CC BY-NC4.0와 원본 데이터 메타데이터CC BY4.0도 별개다.
- 룰 주석 24,779행, SCA MITRE 참조 870행은 서로 다른 종류의 메타데이터다. 제공자는 TTP태그로 분류하는 방식을 제안하지만, [Wazuh4.5.2 PAM](https://github.com/wazuh/wazuh/blob/v4.5.2/ruleset/rules/0085-pam_rules.xml)·[SSH룰](https://github.com/wazuh/wazuh/blob/v4.5.2/ruleset/rules/0095-sshd_rules.xml)은 일반 인증 성공에도T1078/T1021을 붙인다. 태그만으로 실제 침해 성공/악성 여부를 확정하지 않는다.
- 시간대 미상 122,563행은 원래 벽시각을 보존하고 KST값은 비워둔다. full_log 공백 973행은 누락으로 표시한다. 원본의 과거T1562.001은 기존 ATT&CK 원장에서T1685 연결을 별도 기록하며, [현재 MITRE 항목](https://attack.mitre.org/techniques/T1685/)과 구분한다.
- 245개는 139개 구조 그룹에서 고른 **검토용 좌표**이며 독립 사건/정제 학습 사례가 아니다. 원문 로그·명령·개인 식별 값은 복사하지 않는다. 기법 예측에서는 룰 MITRE/전술/설명 등 답을 드러내는 필드를 입력에서 분리해야 한다. 원본 구간·실험 맥락 검수, 같은 원천의 파생본 중복 방지, 독립 최종평가 확보가 남았다. 신규 학습 편입0.

이하 최초5원천 검토와 이전 출처 이력이다.

## 실제 공개 로그를 가진 추가 원천 — 2026-10-30 KST

사용자의 추가 수집 지시에 따라 기존 AIT/CMU/LANL/OpTC/BOTS 외에 **5개 원천을 검토**했다. [파일·버전·체크섬·이용 조건 원장](SOC_ADDITIONAL_DATA_REVIEW.json). 아래 수량은 원본 관측·제공자 집계이며 학습 대화나 독립 사건 수가 아니다. 신규 학습 편입은 **0**이다.

| 자료와 1차 출처 | 실제 확인한 범위 | 관제 용도와 한계 |
|---|---|---|
| **[Linux-APT-2024](https://zenodo.org/records/10685642)** · [Data in Brief 논문](https://doi.org/10.1016/j.dib.2024.110290) | 공식 17 CSV·룰 XML 목록. 작은 CSV 2개 **887행**과 XML의 제공 MD5/자체 SHA256 확인. 메타데이터 CC BY 4.0 | Wazuh/Linux 경보 해석에 가장 직접적이다. 실습 공격을 실행해 수집한 로그이며 실제 피해기업 침해 기록은 아니다. `rule.mitre.id`가 채워진 표본은 100행이고 **룰 파생 라벨**이다. 태그 부재를 정상으로, SCA 준수기준의 MITRE 참조를 공격 발생으로 바꾸지 않는다. 기법 예측 평가에서는 정답 라벨 열을 입력에서 분리해야 한다. |
| **[DEDALE](https://doi.org/10.57745/Y5JLDG)** · Inria/DGA · [ESORICS 2025 워크숍 논문](https://doi.org/10.1007/978-3-032-16092-8_1) | 정부 연구저장소 V2.1, CC BY 4.0. 라벨 ZIP **2,669,407B**, 제공 MD5·5멤버 CRC 확인. 한 JSONL 멤버 **10,593행** 형식 확인 | 약 40 Windows/Linux VM의 4주 시험망 로그로 호스트·Suricata·Zeek 상관조사에 적합하다. 공식 앞 2주는 정상 학습/교정, 뒤 2주는 시험 권장이다. 공격 라벨을 자동 학습 편입하지 않는다. class1은 class1+2의 부분집합이므로 중복 합산 금지. 전체 호스트 원본과의 행 연결은 미검증이다. |
| **[CTU-SME-11](https://zenodo.org/records/7958259)** · CTU/Stratosphere · [대학 학위논문](https://dspace.cvut.cz/handle/10467/109254?show=full) | 11장비·7일. 공식 집계 CSV MD5 검증: **99,993,509흐름**, 정상 1,608,273·악성 98,319,252·미상 65,984. CC BY 4.0 | 기업망을 모사한 네트워크에서 수집했다. 원시 로그는 이번에 미취득. 한 Ubuntu 장비에 **97.84%**가 몰려 있어 전체 행을 그대로 학습하면 편향이 크다. 장비·날짜 선별과 미상 라벨 보존 필요. 학위논문 자료이며 저널 심사 완료 자료로 표시하지 않는다. |
| **[CTU Hornet 65 Niner](https://data.mendeley.com/datasets/nt4p9zsv5k/1)** · CTU · [Data in Brief 논문](https://doi.org/10.1016/j.dib.2024.111261) | 실제 인터넷 노출 서버 9대·65일, 논문 집계 **12,477,164흐름**. CC BY 4.0, 날짜/시간별 Zeek 파일 목록 확인 | 실제 유입 스캔·SSH 접근 관측에 유용하다. 공격 성공의 완전한 정답집은 아니다. 관리 트래픽도 있어 모든 흐름을 악성으로 간주할 수 없다. 직접 파일 요청은 TLS 인증서 체인 오류가 재현돼 원시 검증 미완료이며 검증을 우회하지 않았다. |
| **[AuditBench](https://github.com/aanand300/auditlogsbench)** · [연구자 논문 v2](https://arxiv.org/abs/2606.10281v2) | commit `369ad441f2876245d0db19990c77ccbcb74a0a3a`의 데이터 파일 135개·약196MB 및 정답 파일 6개 존재 확인. 본문·정답은 취득하지 않음 | 연구실 25·OpTC 파생 26 시나리오의 분류·횡적이동·지속성·유출 평가. OpTC와 같은 원천인 부분을 독립 사례로 세지 않는다. **프리프린트이며 저장소 데이터 이용허락을 확인하지 못해 학습·재배포 보류**. 논문 CC BY가 데이터에도 자동 적용되지는 않는다. |

**선별 순서:** Linux-APT의 작은 사건 묶음과 룰 라벨 한계 검수 → DEDALE의 공식 분할을 유지한 상관조사 평가 → CTU-SME 장비/날짜 선별 → Hornet 원문 무결성 확인. 기관·논문 출처는 추적성의 근거이며 개별 라벨의 정확성이나 모델 성능 보증이 아니다. 원문에 없는 성공 여부·정답을 자체 작성해 채우지 않는다.

**중복·보류:** SecCoRA의 Linux-APT 부분은 같은 원천의 파생본이다. 확인한 저장소에 LICENSE가 없고 일부 출처/연락처가 placeholder여서 별도 허용 자료로 편입하지 않는다. IoT-23은 상위 CC-BY/FAQ와 확인한 개별 README의 별도 승인 문구가 달라 해당 미러의 학습 사용을 보류한다. CISA 새 PDF 3개는 HTTP403으로 원문 미확보다. 검색 요약을 정답으로 쓰지 않는다.

**기존 Attack Flow 정정:** 원본 41개 모두 공식 commit `6c26db9bbb34fcfd655f4fa7edfaa5a018c108ae`의 Git blob과 일치하지만 신규 파일은 0개다. 원본 scope상 사건은 25개이며 나머지는 캠페인·악성코드·훈련 등이다. 기존 최소 변환본은 조건·AND/OR·분기를 보존하지 않고 직접 액션 간선 610개만 집계한다. 전체 2,113연결을 BFS 시간순 정답으로 해석하지 않는다. 원본/과거 변환본은 보존하고 [데이터 README](../datasets/README.md)를 정정했다. 새 파서나 재처리본을 배포한 것은 아니다.

**취득·운영 범위:** 작은 원본 총 **3,795,872B**를 메모리에서 검증하고 URL/해시/집계만 기록했다. 대용량 전체 파일·패키지·가중치를 Mac에 설치/보존하지 않았다. 기존 R8 입력과 가중치, 운영 모델 선택은 변경하지 않았다. Thor SSH는 재시도에서도 timeout이라 이번 운영 상태를 확인하지 못했다. 출처 기록은 반입 소스 목록에만 추가했으며 실제 Thor 반입·새 학습·실제 MCP/채팅/공격 E2E는 미실행이다.

이하 이전 검토 이력이다.

## OpTC 실제 로그 형식 확인·확장 조회 제한 — 2026-10-30 KST

[원장](OPTC_EVIDENCE_REVIEW.json). [공식 제공자 저장소](https://github.com/FiveDirections/OpTC-data/tree/5b108604f11f767aa11ea79ff827595f3fad15fd)가 연결한 Drive 원본2개에서 **각 첫1MiB**를 HTTP206으로 읽었다. 전체 약1TB나 선택 압축파일 전체를 받은 것이 아니다. 실제 완전행31,797개를 독립 JSON/시각/SHA 검사와 대조했다.

| 확인 범위 | early 파일 앞부분 | last 파일 앞부분 |
|---|---:|---:|
| 완전 JSON 행 | 16,510 | 15,287 |
| 파싱 실패 / 시간대 불명 | 0 / 0 | 0 / 0 |
| 마지막 미완성 행 바이트 | 456 | 474 |
| 인접 행의 시각 역전 | 6,118 | 5,353 |
| 목표 Sysclient0201 행 | 0 | 0 |

실제 `timestamp`는 모든 표본에서 `-04:00` 오프셋을 가진 ISO 문자열이었다. 문서의 숫자형 예시나 파일명의12월 날짜를 실제 사건 시각으로 간주하면 안 된다. 근거 원시시각을 보존하면서 출력용 KST만 한 번 변환한다. 두 파일의31,797 event ID는 표본 안에서 고유했지만, 제공자가 고지한 같은 프로세스의 의미상 중복 문제가 해결됐다는 뜻은 아니다. 시각 역전11,471회가 있어 임계시각을 넘긴 한 행만 보고 뒤의 기록을 생략하지 않는다.

미완성 마지막 행은 파싱 실패/정상으로 처리하지 않고 별도로 보존한 바이트 수·SHA로 표시했다. gzip 전체 trailer/CRC와 원본 전체SHA는 미검증이다. 원본의 전체 `Content-Range` 크기와 선택 prefix SHA를 구분한다. 형식 투영은 관측된 Sysclient0205의17개 표본을 원행 좌표/UUID/SHA·KST와 별도 대조했지만, 이는 목표 Sysclient0201의 사건을 대체하거나 정상 정답을 만드는 작업이 아니다. raw 명령·쿼리·비밀번호는 투영에 넣지 않았다.

Thor에서는 CPU1코어/nice10·독립720초 제한으로 선택 파일을 스트림 대조하려 했으나 첫 원본 요청이 기대한 데이터 응답을 주지 않아 중단됐다. 후속 확인에서 두 파일 모두 **Google Drive 다운로드 할당량 초과 HTML**을 반환했다. 확인한 종료 PID 상태와 Ollama active는 원장에 KST 시각으로 기록했다. 원본 압축파일 저장0·완전파일 검증0이고, 제공 제한을 우회하거나 자동 재요청하지 않았다. Mac/Thor 최종11검사·Mac prefix31,797행 독립 대조는 완료했으며 원시자료/사건 정답/새 모델 검증 완료와 구분한다.

현재 목표 사건 연결은 미완료다. 앞부분에서 호스트가 없다는 사실은 원본 전체 부재가 아니며, 정답 보고서의 시간대와 실제 로그 시간대의 일치도 아직 가설이다. 기관 제공 자료라는 이유로 완전성·정답성·관제 성능을 보증하지 않는다. 신규 학습 편입/GPU/운영 모델 변경은0이며 quota 해소 후 해당 연결을 검증하거나 다른 접근 가능한 근거를 준비한다. 권리·인용·원본 commit은 앞선 [접근 검토 원장](SOC_SOURCE_ACCESS_REVIEW.json)을 유지한다.

이하 이전 검토·작업 이력이다.

## CMU 이용 조건·누락 재검토와 OpTC 선택 경로 — 2026-10-30 KST

[검증 원장](SOC_SOURCE_ACCESS_REVIEW.json). 기존 CMU의 “CC BY 4.0” 기록은 공식 저장소 **메타데이터를 확인한 결과**였다. 이번에 동일 SHA의 `answers.tar.bz2` 내부 `answers/license.txt`에서 배포·파생물 제한과 논문 최소 인용 예외를 확인했다. 두 표시의 우선관계를 임의로 정하지 않고, 제공자의 설명을 확인할 때까지 학습 편입·데이터 파생물 공개를 보류한다. 확인한 공식 페이지에는 이를 해소하는 설명이 없었다. [CMU SEI](https://www.sei.cmu.edu/library/insider-threat-test-dataset/) · [고정 버전 메타데이터](https://api.figshare.com/v2/articles/12841247/versions/1).

정답 master는 헤더를 제외한191항목/9release/5시나리오군이다. 그러나 전체194파일에서 master와 안내3개를 빼면 상세CSV는190개이고, master가 참조하는 `r6.1-4.csv`는 없다. 앞선 “고유 상세191”은 참조 문자열 수이며 실제 연결 완료 수가 아니었다. 고유basename 대조190개·중복0/누락1개를 재확인했다. 모든 상세 내용을 검수한 것은 아니다. 한 상세파일19행의 혼합 가변열 형식만 확인했다. 답안에는 이미 사건별 관측이 들어 있지만 정상 배경 전체를 대신하지 않는다. 새로 받은 약1.25MB 원본·원문복사는 제거했고 이후2회는 메모리에서만 검산했다.

| 원천 | 이번 확인 | 현재 제약 / 다음 단계 |
|---|---|---|
| CMU CERT | master191항목, 대응 상세파일190개 | 이용 조건 불일치·누락1개 해결 전 학습 보류 |
| LANL cyber1 | 기관 공식 다운로드 양식·권리/시각 조건 | 이메일·연구 목적 제출에 대한 사용자 응답 대기; 미제출·원본 미취득 |
| OpTC | GitHub 정답7쪽/시각 항목102개, Drive 대상 로그2파일 위치/크기 | 원본 로그와 실제 사건 연결·시간대 확인 전; 학습 편입0 |

[LANL 공식 자료](https://csr.lanl.gov/data/cyber1/)의 익명 상대시각은 실제 KST 날짜로 복원할 수 없다. 알려진 공격 인증 목록에 없는 행을 정상 정답으로 간주하지 않는다. 양식에 임의 이메일을 넣거나 접근 절차를 우회하지 않았다.

[OpTC 고정 제공자 저장소](https://github.com/FiveDirections/OpTC-data/tree/5b108604f11f767aa11ea79ff827595f3fad15fd)는 DARPA 지원의 격리 시험망 자료다. 제공자 public-domain/Distribution A 고지와 정확성 무보증을 함께 보존한다. 정답 보고서는9/23·24·25의37/47/18항목(총102)을 포함한다. 연결된 여러 날짜/호스트의 활동이므로 독립 사건102건 또는 완성된 학습 문항으로 세지 않는다. GitHub PDF와 Drive 텍스트의 시각 순서는 같지만 본문·바이트는 같지 않아서 동일판이라고 주장하지 않는다. GitHub commit/PDF SHA를 기준판으로 고정했다.

첫 대상은 `ecar/evaluation/23Sep19-red/AIA-201-225`의 Sysclient0201이다. 파일2개는109,692,169B와2,217,842,713B로, 메타데이터만 확인했다. 약1TB 전체나 이 로그파일들은 받지 않았다. 파일명의12월 시각을9월 사건 시각으로 해석하지 않으며 원본의 실제timestamp/시간대·호스트/UUID를 확인한 뒤 보고서와 연결한다. gzip은 부분범위만으로 임의 시각을 찾기 어려울 수 있어 전송량을0으로 약속하지 않는다. 보고서의 시간대도 확인 전이며 임의 KST 변환을 하지 않는다.

[제공자 정정사항](https://github.com/FiveDirections/OpTC-data/blob/5b108604f11f767aa11ea79ff827595f3fad15fd/errata.md)의 중복 프로세스·누락 해시·acuity·경로 표기를 적용해야 한다. Drive 정정 파일의 대체 압축 안내만으로 이 의미상 문제를 해결했다고 표시하지 않는다. 시뮬레이션 주소/도메인은 현재 차단 대상이 아니며, 성공·실패·미확인/관측 누락을 구분하는 조사 연습에 사용한다. 현재 MCP 호출·승인/적용/원복의 정답은 별도 실검증이 필요하다.

새 GPU학습·모델 선택/서버 변경·신규 학습 편입은0이다. 데이터 확보/정제/검수 후 새 평가 분할과 실행 계획을 정한다.

이하 이전 검토·작업 이력이다.

## AIT 원문 기반 관제 초안과 해석 검수 — 2026-10-30 KST

[검증 원장](AIT_CASE_REVIEW.json)의 **9구간·5환경·25원행·14교차참조**를 조사 질문/답변으로 구성했다. 사건·로그는 기관 시험자료에서 왔고 질문/답변은 프로젝트 에이전트가 작성했다. 기관 공식 Q&A나 독립 전문가 검수본으로 표시하지 않는다. 학습 편입은0이며9개 구간은 독립 사건9건 또는 새 평가 자료가 아니다.

| 구간 유형 | 초안 수 | 관제에서 구분할 사항 |
|---|---:|---|
| reverse_shell | 2 | 라벨이 없어도 HTTP 요청에 셸/TCP 접속 문자열이 있다. 요청 흔적과 연결/실행 성공을 구분한다. |
| webshell | 2 | 제공자 webshell_cmd 라벨·명령 배열·같은 원행의 AMiner 관측을 대조한다. HTTP200이나 동일 원행 반복을 성공 증거로 확대하지 않는다. |
| service_stop | 5 | START/STOP·각 이벤트 결과·일지dnsteal_stop의 다른 시각을 구분한다. 유출 성공/일반 서비스 장애/침해 제거 완료는 미확정이다. |

원 논문은 DNS 유출을 다른 웹 침입 단계와 분리해 먼저 실행하는 설계를 설명한다. 따라서 발견한 시각 차이만으로 자료 오류라 판정하거나 전체 공격을 한 줄의 시간순 인과관계로 맞추지 않았다. [저자 논문 §3.2.3·4.1](https://arxiv.org/html/2203.08580v1), [정식 출판 DOI](https://doi.org/10.1109/TDSC.2022.3201582).

추가로 [고정 LDS v2.0](https://zenodo.org/records/5789064)의 fox ZIP에서 실제 서비스 정의, 배포 템플릿/설정과 `rules/audit.yaml`을 부분 읽기했다. `exfil.service`는 특정unit의 프로세스 이벤트를 선택하므로 시작·종료 모두 라벨에 포함된다. fox 정의를 다른4환경에서도 직접 확인했다고 확대하지 않는다. 지정 멤버 CRC/SHA는 확인했으나 전체 ZIP MD5는 계산하지 않았다. 약5.3MB의 ZIP목록/선택파일 전송은 메모리에서 처리했고, 선택한 정의 텍스트와 해시는 로컬 출처 근거로 보존했다. 외부 코드는 실행하지 않았다.

이 초안은 증거 구분·추가 조사·인계 연습용이다. 실제 장비 MCP 출력/승인/차단/복구의 정답을 제공하지 않는다. ADS의 CC BY4.0, LDS 파생물의 CC BY-NC-SA4.0과 두 논문 인용을 유지한다. 원문 쿼리/전체명령을 생략한 투영과 KST 변환·선택·프로젝트 작성 답변은 변형 내역으로 고지했다. Mac CPU8검사와25원행 별도대조를 완료했지만 독립 전문가/모델품질 검수·학습은 아직이다.

이하 이전 검증 이력이다.

## 경보0 구간의 원시 로그·라벨 대조 완료 — 2026-10-30T01:46:51.694593+09:00

[검증 원장](AIT_GAP_LINKAGE.json). 같은 AIT 학습 환경5개의 **원문/라벨40쌍·원문1,942,943행·제공자 라벨623,514행**을 Thor에서 HTTPS range로 읽어, 모든 라벨 행 번호를 대응 원문에 연결했다. 선택240행의 원문 SHA를 별도 대조했고234행에는 제공자 라벨이 있다. 기관 원자료의 정확한 선택 범위이며 독립 사건/학습 대화 수가 아니다.

아래9개 구간의 Wazuh/Suricata 경보는 모두0이었다. 원시 로그는 명시적 시간대가 있는 행만 구간에 집계했다.

| 환경 | 제공 단계 구간 | 원문 행 | 제공자 라벨 행 | AMiner 관측 객체 |
|---|---|---:|---:|---:|
| fox | webshell | 18 | 17 | 2 |
| fox | reverse_shell | 3 | 0 | 1 |
| fox | service_stop | 2 | 2 | 2 |
| russellmitchell | reverse_shell | 2 | 0 | 3 |
| russellmitchell | service_stop | 2 | 2 | 2 |
| santos | service_stop | 2 | 2 | 3 |
| shaw | webshell | 9 | 9 | 2 |
| shaw | service_stop | 2 | 2 | 2 |
| wardbeck | service_stop | 2 | 2 | 2 (학습 모드) |

7구간에는 제공자 라벨이 연결된 원문이 있고, 리버스셸2구간은 원문/AMiner 관측이 있지만 해당 원문 라벨0이라 성공 여부를 확정하지 않는다. SERVICE_START/STOP의 res=success도 해당 이벤트 결과일 뿐 전체 공격 성공·탈취·운영 장애의 정답이 아니다. AMiner 원본5멤버24,199객체를 확인했고9구간19관측 중 wardbeck의2개는 TrainingMode=true다. 모든9구간에서 AMiner RawLogData와 LDS 원문의 동일 문자열이 표본에서 연결됐지만, **관측 수를 운영 탐지율로 사용하지 않는다**. AIT의 역사적 시험장 결과이며 현재 SOC 서버의 공백을 직접 측정한 결과가 아니다.

원문 시각 추출도 보완했다. 본문의 audit 형태 문자열을 로그 헤더로 오인할 수 있는 반례를 재현해 실제 audit/Apache 헤더에만 매칭하고 JSON은 최상위 명시 시각을 사용한다. 연도/시간대가 없는 syslog 등은 미확정으로 보존한다. Mac/Thor CPU8검사 통과 후 새경로 R2로 전수재실행했고,40쌍의 원문/라벨 SHA·집계·선택 결과가 이전 실행과 전부 같았다. 처음 결과/스크립트 SHA를 보존하며 이번 자료에서 실제 오인 시각이 발견됐다고 주장하지 않는다.

- 원출처: [AIT-ADS](https://doi.org/10.5281/zenodo.8263181), CC-BY-4.0·[CSET 2024 논문](https://doi.org/10.1145/3675741.3675748); [AIT-LDS v2.0](https://doi.org/10.5281/zenodo.5789064), CC-BY-NC-SA-4.0·[IEEE TDSC 논문](https://doi.org/10.1109/TDSC.2022.3201582). 원천/가공·인용·비상업/동일조건을 보존하며 원자료·모델 공개배포를 수행하지 않는다.
- 무결성 범위: 공식 버전 URL/TLS·선택 멤버 전체 CRC/SHA·공식 메타데이터 재대조. 거대한 LDS ZIP 전체를 받거나 제공 MD5를 계산하지 않았다. 인덱스와 두 실행 합계104,488,803B를 Thor에서 전송했다. 원문 전체 파일은 디스크에 저장하지 않고 검토 표본·출처·SHA만 보존한다.
- 보존/운용: Thor `~/Capstone_Groot_training/qwen36-20261027/institutional-review-20261030-r2`에 수정 코드/원자료 연결 결과를 보존한다. R2는01:41:29 KST 종료,01:42:17 동일PID 종료/Ollama active 확인. GPU학습·서비스 중지·운영 모델/봇/장비 정책 변경0. Mac 신규 패키지·모델·원시 아카이브 다운로드0.
- 남음: 사실/판단/미확정을 분리한 관제 질문·답변 검수, 현행 MCP/승인·사후확인 trajectory 검수와 다른 원천의 미사용 최종평가. 이번 감독학습 대화 편입0/독립 전문가 검수없음. 기존 AIT 시험환경과 사용 완료 V5 test128은 새 미사용 평가로 재활용하지 않는다.

이하 이전 출처·검증 이력이다.

## AIT 원본 증거 묶음 검증 — 2026-10-30T01:11:08.558457+09:00

기존 공식 AIT-ADS 아카이브와 labels.csv의 제공 MD5를 재대조하고 SHA256을 기록했다. 학습 환경6개의 Wazuh/Suricata 원본 **1,371,021행**을 끝까지 읽어 ZIP CRC·멤버 SHA를 확인했다. 파싱/명시 시간대 오류0, 복수 단계 일치585행이다. 기존 `datasets/prep.py`는 여러 구간이 맞아도 첫 구간만 선택하고 구간 밖을 `normal`로 표시한다. 과거 입력/가중치를 덮어쓰지 않고, 별도 [추출기](prepare_ait_evidence.py)는 모든 구간 일치를 보존하고 구간 밖을 `outside_published_phase_windows`로 표기한다. 어느 표기도 개별 악성/정상 정답으로 사용하지 않는다.

- 60개 제공 단계+환경별 구간 밖6개로 **검토 묶음66개**, 비어 있지 않은 묶음57개. 표본454회/고유 원본 좌표450개를 선별했으며 여러 단계가 맞으면 같은 경보가 재등장한다. 독립 사건450건이나 신규 학습 대화66건이 아니다.
- Wazuh·Suricata 관측을 모두 담은 묶음37개. Wazuh rule.id/level과 Suricata signature_id/severity를 별도 필드로 유지한다. 시각 동시성이나 같은 단계만으로 동일 행위자·인과관계·공격 성공을 결론내리지 않는다.
- **관측0 구간9개:** fox의 webshell/reverse_shell/service_stop, russellmitchell의 reverse_shell/service_stop, santos의 service_stop, shaw의 webshell/service_stop, wardbeck의 service_stop. 해당 공개 경보 자료에 관측이 없다는 뜻이며 공격 부재/실패를 뜻하지 않는다. 다음은 원시 LDS 로그·행 라벨과 연결하는 작업이다.
- 추출기와 독립된 재검사로450원행 SHA/원객체/정확한 KST/모든 단계 일치 및6멤버 SHA를 대조했다. 회귀9검사 통과. wheeler/wilson 멤버 내용은 열지 않았고 AMiner도 범위 밖이다. 전체 ZIP의 바이트 해시는 확인했지만 모든 센서·시험 환경의 내용 검증 완료로 확대하지 않는다.

[검증 원장](AIT_EVIDENCE_REVIEW.json)의 환경 분할/소스·산출물 SHA를 따른다. 검토 자료는 로컬 `finetuning/data-ait-evidence-review-20261030/`에 있으며 Git 제외다. 기관 원경보를 보존한 증거 자료이고 감독학습용 질문·답변/MCP trajectory는 아직0건이다. 기존 학습 경보와 중복될 수 있으므로 새로운 독립 평가 자료로 쓰지 않는다. 원시 로그 연결·사건 판단 검수·별도 미사용 평가 확보가 남는다. 새 다운로드/패키지 설치·Thor 접속/반입·GPU학습·운영 모델 변경은 하지 않았다.

이하 이전 출처/후보 조사 이력이다.

## 추가 관제 자료 후보 — 2026-10-30T00:57:16.287495+09:00

사용자 “데이터 좀 더 없나?” 요청에 따라 제공기관 원문과 기존 취득 원장을 대조했다. **신규 직접 도입 후보 3종 + 기존 자료 확장 2묶음**이며 이번 신규 학습 편입은 0건이다. [후보·권리·정답 범위·취득 상태 원장](SOC_DATA_CANDIDATES.json). 기관 출처 확인과 정답 완전성·학습 효과를 구분한다.

| 자료 / 원출처 | 활용할 관제 업무 | 근거와 규모 | 현재 상태·제약 |
|---|---|---|---|
| [LANL 다중 보안 이벤트](https://csr.lanl.gov/data/cyber1/) | 인증·프로세스·DNS·흐름 대조, 침해 경로 조사 | 국립연구소 비식별 로그 58일, 약16.48억 이벤트/압축12GB; red-team 인증 이벤트 표시; DOI10.17021/1179829 | 신규 후보. 저작권 포기 고지·인용 안내 확인. 전체 정상/악성 정답이 아니며 상대시간을 실제 KST 날짜로 만들지 않는다. |
| [DARPA OpTC / Five Directions](https://github.com/FiveDirections/OpTC-data) | 호스트·네트워크 상관분석, 공격 시간선 | 격리 시험망 수집500호스트, 압축 약1TB; red-team ground truth/정정표 제공 | 신규 후보. public-domain 공개 고지. 공격별 파일 선별이 필요하고 중복 프로세스·누락 해시 등 알려진 오류가 있다. MITLL 배포로 표기하지 않는다. |
| [Splunk BOTS 3](https://github.com/splunk/botsv3) | SOC 조사, 클라우드/APT 사건 분석 | 제공사 실습320.1MB, pre-indexed Splunk, CC0-1.0 | 신규 후보. [공식 발표](https://www.splunk.com/en_us/blog/security/botsv3-dataset-released.html)는 정답/힌트를 이메일 요청 방식으로 안내한다. 아직 정답집·추출 경로 미확보; 이메일 발송/설치 없음. |
| [CMU SEI/CERT](https://www.sei.cmu.edu/library/insider-threat-test-dataset/) | 내부자 행위·사용자 활동 대조 | 기관 합성 시험망, DOI10.1184/R1/12841247.v1·CC-BY-4.0 재확인 | 기존 답안키1.25MB 취득 이력/학습0건. 같은 release의 로그 문맥과 연결 필요. 194아카이브 멤버는 사건 수가 아니다. |
| [AIT ADS](https://zenodo.org/records/8263181) / [LDS v2.0](https://zenodo.org/records/5789064) | 현재 Wazuh·Suricata 경보 조사, 오탐·공격 단계 대조 | 8시험환경·ADS 약265.6만 경보/96.2MB; 학회·학술지 근거 | 기존 자료 확장. ADS CC-BY-4.0/LDS CC-BY-NC-SA-4.0를 구분. 공격 시간구간만으로 개별 경보를 악성으로 단정하지 않는다. |

우선순위는 현재 장비와 맞는 **AIT의 증거 연결 보강 → CMU 정답과 로그 결합 → LANL 선별 조사 사례**다. BOTS는 공식 정답·추출 조건, OpTC는 작은 파일 선별 가능성을 먼저 확인한다. 최신 V5는 CTI 기법 매핑 과제라 이 자료들을 자동 혼합하지 않는다. 원출처의 사실·정답과 프로젝트가 가공한 질문/MCP 동작·승인 조건을 별도로 표시하며, 필요한 관제 절차는 검수한 실제 실행 근거로 보완한다.

행 수를 독립 사건/학습 대화 수로 환산하지 않는다. 사건·환경·캠페인과 파생 데이터끼리 묶어 분할하고 과거 AIT 검증/시험 환경 및 사용 완료 V5 test128은 새 미사용 평가로 재활용하지 않는다. 대용량은 필요한 파일/구간만 선택하되 단일 gzip 스트리밍은 많은 바이트를 전송할 수 있다. URL만 참조한다고 가중치 학습이 되는 것은 아니다.

보조 후보 [OTRF](https://github.com/OTRF/Security-Datasets)는 README의 GPL-3.0 표기와 LICENSE의 MIT 불일치를 발견해 적용 범위 확인 전 보류한다. [Cyber Defense Benchmark](https://arxiv.org/abs/2604.19533v3)는 위협 헌팅 평가 설계 참고용 preprint이며 독립 검수/동료심사 완료 자료로 주장하지 않는다. 이번에는 공개 설명과 메타데이터만 확인했으며 신규 원시 로그 다운로드·Thor 반입·학습·운영 전환은 없다.

이하 과거 출처·사용 이력을 보존한다.

## 미사용 시험 완료와 출처 신뢰성의 한계 — 2026-10-30T00:40:22.883444+09:00

학습에 넣지 않은 test128관측의 양쪽 응답 생성을 완료했다. 후보의 원문 기준 누락이111→114·JSON정상128→127로 나빠져 운영 승격하지 않는다. 기관 원천의 출처/라이선스가 확인됐다는 사실이 학습 효과·관제 업무 적합성을 보증하지 않는 실측 결과다. 기관 원라벨의 비포괄성·프로젝트 작성 질문/형식·독립 전문가 검수 미수행을 함께 공개한다.

test128은 이제 평가에 사용된 자료이며 앞으로 미사용/비오염 최종시험으로 재표시하지 않는다. 원답/실패와 보고서SHA를 보존했고 점수 개선을 위해 모델/채점·출력제한을 사후 변경하지 않았다. [실행/계보](V5_EXECUTION_RESULTS.json) · [비교 기준](V5_COMPARISON.md).

이하 당시 이력이다.

## 학습본 출처 고지의 등록 확인 — 2026-10-30T00:24:05.048706+09:00

R8 전체1,024관측 학습본을 병합/Q4_K_M 변환해00:07 KST 새 후보명으로 등록했다. 원본 라이선스와 MITRE ATT&CK 라이선스·CISA 원문 출처를 모델의 고지에 포함하고 SHA `e87da8db178706ad024012ddae35937c0aa92bbe0b2b8cedaa0505c167d437e6`를 확인했다. 출처 고지는 기관의 모델 인증을 뜻하지 않는다. 실제 개발32문항 재시험과 복구는 완료했고00:26 KST 응답 전에 고정한 미사용 test128×2 생성을 시작했다. 아직 전수 채점 완료 전이며 이 답을 학습/체크포인트 선택에 재사용하지 않는다. [모델/자료 연결·실측](V5_EXECUTION_RESULTS.json)의 `post_training_comparison`을 참조한다.

아래 학습량·한계와 과거 이력은 그대로 보존한다.

## R8 실제 전체 학습 완료 — 2026-10-29 23:12 KST

기관 원천 V5의 **train1,024개 각각1회·1epoch/512단계**를 완료했고 실제 성공 microbatch/원자료/정답·프로필 연결을 재검증했다. validation128은 평가에 사용했으며 test128 답변 생성·채점은 아직 하지 않았다. 준비량1,280과 실제 학습량1,024를 구분한다. 자체 사건 시나리오0,프로젝트 작성 질문/형식·기관라벨의 비포괄성·독립전문가검수 미수행이라는 한계는 그대로다.

현재 결과는 CTI 근거 매핑 학습의 완료와 유한 가중치 검증이다. 전체 SOC 역량·공인 모델 인증·관제 정확도 향상을 입증한 것이 아니다. [실제 투입/결과](V5_EXECUTION_RESULTS.json)의 `active_run.completion`을 현재 기준으로 읽고, 아래 초기 투입0/부분학습/중지 문장은 당시 이력으로 보존한다.

이하 시점별 이력이다.

## 실행 상태 후속 — 2026-10-29 20:51 KST

사용자 요청으로 진행 확인을 재개했다. R8은 **277/512 optimizer단계**, 성공 microbatch555·고유관측555·중복0의 중간 실행 기록을 확인했다. 준비된 train1,024개 전체를 이미 학습했다고 집계하지 않는다. 256단계 중간평가 후 계속 진행 중이며 최종 가중치·완료·학습 후 품질 검증은 아직 없다. 원자료·분할·질문/정답·출처·고정 실행 소스는 불변이다. [현재 실행/과거 이력](V5_EXECUTION_RESULTS.json).

이하 이전 확인 시점의 이력이다.

## 최신 실행 정정 — 2026-10-29 19:01 KST

사용자 재개 지시로 **R8 본 학습은18:08 KST 시작했고,19:01 실조회에서92/512단계**였다. 동일 기관 원천의 train1,024/validation128/test128 및 결정적 프로필로 실행 중이다. 아래 ‘학습 보류·GPU투입0’은 이전 준비/중지 시점의 기록이며 현재 실행 상태가 아니다. [실행 원장](V5_EXECUTION_RESULTS.json)의 `active_run`을 현재 기준으로 읽는다.

현재 epoch 완료·최종1,024행 투입 검증·새 후보 등록·학습 후 품질 검증은 미완료다. 준비된 총량을 이미 학습한 양으로 집계하지 않는다. 원자료/분할/정답/출처·고정 실행 소스는 바꾸지 않았고, 실행 중 파일을 서버에 재배포하지 않았다. 이 자료는 CTI 기법 매핑 업무 일부를 다루며 기관 인증 관제 모델이나 관제 전 업무 학습본을 뜻하지 않는다.

이하 문장은 각 준비·실행 당시 이력이다.

**현재 실행 상태 정정:** 사용자가 학습을 나중으로 미루고 계획만 요청했다. 재개했던 checkpointed smoke는 성공역전파2개/진행step2 후 평가·저장중 사용자 중지로 종료했으며, 본 학습1024개 전체 투입/완성후보 등록은 없다. 이전완료2-step시험·0-step코드오류와별도실행으로[실행원장](V5_EXECUTION_RESULTS.json)에연결했다. 원천1280/분할·출처라벨·라이선스는불변이며현재학습/예약은없다. 다음사용자재개지시전에는[계획](../PLAN.md)만유지한다.


**V5 실제 투입 후속:** [실행원장](V5_EXECUTION_RESULTS.json)에원run_manifest/Trainer/lineageSHA를연결했다. 같은학습관측2개를checkpointed/uncheckpointed각2-step에사용했으며총4개독립사건이나학습1,024개전체투입으로집계하지않는다. 중간NameError시도는성공microbatch0이다. 원문/분할SHA·출처1324행대조·원LICENSE는불변,새관제전체학습/독립전문가인증은아니다. 기존TRAINING_PROVENANCE의3corpus/12실행은보존하고이신규원장을별도연결했다. 추가GPU본학습은공유중단시간연장확인전미시작이다.


## V5: 원 제공자 관측·기법 매핑 직접 사용 (2026-10-29 KST)

[V5 준비원장](V5_DATA_PREPARATION.json)과[고정 입력/소스SHA](V5_TRAINING_INPUTS.json)가 실제 준비량/검증 범위의 기준이다. 이 단계는 관제원의 **위협 인텔리전스 근거 연결/분류/인계** 일부를 다룬다. 트리아지·다중센서 상관·라이브 재조회·변경안/승인·적용 후 검증 전체를 학습했다고 하지 않는다. 이전 NIST/ENISA 역할 연결은 업무 범위 근거이며 이번 정답 인증이 아니다.

| 원 제공자/고정 자료 | 이번 채택 | 근거와 한계 |
|---|---:|---|
| [MITRE ATT&CK STIX 고정commit](https://github.com/mitre-attack/attack-stix-data/tree/c2494b29dd268c46a5d0ea0990553e4327cd2253) | 1,208관측(3분할 합계) | actor/campaign→technique의 원문과 관계 라벨. 6,027원관계는 독립사건6,027개가 아님. 인용보고서 전부의 원본문을 개별 검증한 것은 아님. |
| [CISA/FBI 공동 AA23-061A BlackSuit/Royal](https://www.cisa.gov/sites/default/files/2024-09/aa23-061a-stopransomware-blacksuit-royal-ransomware_5.pdf) | train15관측 | p22–24 표18–23의17행을 원문/ID 계수 대조. 1문맥모호·1역사적 부모명 표기변형을 보수적으로 보류. |
| [CISA 공동 AA24-038A Volt Typhoon](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf) | validation49관측 | p37–45 표5–17의67행. 문맥모호6행과 p38 T1583.003 Botnet/Virtual Private Server ID·제목 충돌을 보류. 동일관측은 여러 라벨을 병합하며 중복질문으로 늘리지 않음. |
| [CISA/FBI/HHS/MS-ISAC AA24-131A Black Basta](https://www.cisa.gov/sites/default/files/2024-05/aa24-131a-joint-csa-stopransomware-black-basta_1.pdf) | test8관측 | p4–5 표2–6의8행. 전체보고서 단위 미학습 holdout. |

CISA3종 모두를 train에 넣지 않았다. CISA 합계72관측과 MITRE1,208=1,280건, 학습1,024/검증128/시험128이다. 풀6,038 중4,758은 미선택 후보로 남으며 학습량에 합산하지 않는다. 이전 실제v1 144대화/R2가용192대화보다 큰 **학습1,024대화**를 준비했지만 GPU투입량은 아직0이다. 기존18,872준비풀과 전체학습을 혼동하지 않는다.

정답은 원 제공자의 기법ID/원문명칭을 기계적으로 연결하고 출처 식별자·`reported_mapping_only`/`not_assessed` 범위를 학습한다. 사건 이야기0개, 질문문구·system지침·JSON형식은 프로젝트 작성, 독립 전문가 검수0이다. 기관 출처의 신뢰성이 모든 제공자 라벨의 완전성/무오류나 이 프로젝트의 운용 정확성을 보장하지 않는다. 과거 공격 보고를 현재 서버 침해/조치 완료로 바꾸지 않는다.

분할은 주체·캠페인 귀속·공유 인용 URL·CISA보고서 연결 성분을 사용한다. 같은 원문·그룹·인용보고서 교차누출0을 별도 검증기로 검사했다. CISA92행은 pdftotext layout 파서와 별도 bbox단어ID 집계가 일치했다. 시각검수는 Royalp23/Voltp38/Bastap4 대표3페이지만이며, 14표영역페이지 전체의 시각검수로 확대하지 않는다. ATT&CK14/15 원본은 같은commit의14.0/15.0JSON을 감사 참조로 고정했으나 CISA의 정확한patch버전으로 단정하지 않는다. T1484.001은 부모명 표기차이 가능성이 있고, T1583.003/Botnet은 실제ID·명칭불일치로 구분한다. 에이전트가 정답ID를 임의 정정하지 않았다.

MITRE 원LICENSE와 `SOURCE_ATTRIBUTION.json`을 dataset 및 후보 등록 고지에 보존한다. CISA/제3자 원고지 유지·TLP:CLEAR를 저작권 라이선스로 해석하지 않음. 이 작업은 내부 연구용 정제/학습 준비이며 corpus/가중치 공개배포 승인을 뜻하지 않는다. 대용량 AIT 원격참조 이력은 아래에 보존하지만 이번 V5에 새로 혼합하지 않았다. CMU답안키/ToolACE/USENIX원자료도 V5핵심에 미편입이다.

학습전32개 개발응답은 JSON32/32·엄격원문완전3/32·정확기법ID macroF1 0.1233이다. 원라벨누락34중7은 상위기법만 답변했고, 원정답집합밖45ID 모두를 기술적 거짓으로 판정하지 않는다. 원문라벨 비포괄성/명칭 버전/대체 해석은 별도 의미검수 대상이다. 해당 수치를 전체SOC정확도나 두운영봇 점수로 쓰지 않는다. 시험128답변은 아직 생성하지 않았다.


## 외부 기관·실제 사고 원천 확대 — 2026-10-29T04:31:32.380166+09:00

사용자 지시에 따라 자체작성308건을 중심 학습자료로 투입하는 기존 계획은 보류했다. 다음 수는 **학습 확정 사례 수가 아니라 새로 확보한 원천의 재고**다. [원천·해시·보류사유](SOURCE_EXPANSION.json).

| 원천 | 확인·확보 범위 | 현재 사용 상태 |
|---|---|---|
| [MITRE 공식 ATT&CK STIX](https://github.com/mitre-attack/attack-stix-data/tree/c2494b29dd268c46a5d0ea0990553e4327cd2253) | 55,271,014B JSON/고정commit·LICENSE, 유효행위주체/캠페인→기법6027개 연결·동일주체/기법/설명 중복0·230주체 | CTI 매핑 원천, 6027개 독립 사고가 아님. 하위 인용URL 개별 전수 검증 전·정부/학술 도메인 참조704개는 URL분류일 뿐 본문검증 수가 아님 |
| [CMU SEI/CERT](https://www.sei.cmu.edu/library/insider-threat-test-dataset/) | 공식 KiltHub DOI10.1184/R1/12841247.v1, CC-BY-4.0·정답키1,254,678B/MD5 및 제공SHA256 대조·README 확보 | 기관이 생성한 합성 시험망, 실제 사건과 구분. 대용량로그 미취득·로그문맥/정답 연결 전·학습편입0 |
| [CISA 공동 사고보고](https://www.cisa.gov/news-events/cybersecurity-advisories) | AA24-038A Volt Typhoon, AA23-061A BlackSuit/Royal, AA24-131A Black Basta 공식 PDF3종·개별 URL/SHA 보존 | 실제 관측을 기술한 기관보고. 절/표·주장단위 근거추출 전·3개 독립 피해사건 수라고 세지 않음 |
| [USENIX Security2024 실SOC 연구](https://www.usenix.org/conference/usenixsecurity24/presentation/yang-limin) | 학회 논문/저자 저장소의 원자료 접근조건 확인 | 연구자 허가·소속/사용목적 신청 필요. 신청·메일 발송·원자료 취득0, 미승인 자료로 합성 정답을 대체하지 않음 |
| VERIS Community DB | 공식 유지관리 저장소 commit/README/LICENSE만 확인 | 커뮤니티·AI보조 코딩을 일차기관 정답으로 채택하지 않음·편입0 |

학습유효수는 이후 근거 연결·중복·사건/보고서 단위 분할·역할 적합성·권리 검수 후 집계한다. 원천 레코드를 여러 질문으로 복제해 유효 사건 수를 늘리지 않는다. 이전 실제 v1 학습은144대화, R2는192가용대화 중48step 부분학습이며 초기18,872행은 준비풀이다. 규모 비교에도 이 구분을 유지한다.


**후속 정정 2026-10-29T04:16:44.348253+09:00:** 자체작성308/520(59.23%)은 기관이 검증한 정답이 아니다. CPU/토큰/호출·출처 검사는 답변 의미의 독립 검수를 대신하지 않는다. 520건은 준비본 수로만 보존하고 학습 투입 확정에서 제외한다. 사용자 지시에 따라 외부 기관·학술 원천 및 공식 실제 사고 자료를 추가 수집하고, 자체작성 비중을 줄인 새 corpus/근거 검수를 먼저 수행한다. R3/R4 신규 학습은 실행 제어기에서 보류한다. [검수 상태](V4_DATA_REVIEW.json).


## 추가 기관 자료·공식 관제 직무·전체 대화 학습 준비 — 2026-10-29

현재 선택본은 **520사례: train332 / validation94 / test94**다. 실제 GPU 학습은 아직 시작하지 않았다. [준비 원장](V4_DATA_PREPARATION.json) · [동결 실행 입력](V4_TRAINING_INPUTS.json) · [공식 직무 매핑](SOC_ROLE_MATRIX.json) · [동일 비교 기준](V4_ASSESSMENT_POLICY.json).

### 현재 선택본의 원천별 목록

아래 수는 원천의 전체 레코드 수가 아니라 이번에 가공한 대화 수다. 원시 로그 한 행이나 같은 공격 흐름에서 만든 여러 대화를 독립된 실제 사건으로 세지 않는다.

| 원천 | 가공 대화 수 | 근거·조건 | 사용 내용 |
|---|---:|---|---|
| [AIT Alert Data Set](https://zenodo.org/records/8263181) | 96 (72/12/12) | AIT, CC-BY-4.0; CSET 2024 논문 DOI 10.1145/3675741.3675748 | Wazuh·Suricata 경보의 원필드/시각·불확실성 조사 |
| [AIT Log Data Set V2.0](https://zenodo.org/records/5789064) | 54 (18/18/18) | AIT/TU Wien, CC-BY-NC-SA-4.0; IEEE TDSC/Transactions on Reliability 논문 | 원시 호스트 로그와 제공자 행 라벨을 연결한 조사 |
| [CISA KEV](https://github.com/cisagov/kev-data) | 60 (36/12/12) | CISA 공식 고정 스냅샷, CC0-1.0 | 알려진 악용 취약점 우선순위·로컬 자산 영향 미확인 구분 |
| 프로젝트 작성 관제 시나리오 | 308 (204/52/52) | 에이전트 작성·기계 검증, 독립 관제 전문가 검수 없음 | 관제8업무288 + 포렌식 기능 공백20; NIST/ENISA 직무·절차 참고 |
| 실제 서버 MCP 관측에서 작성한 예시 | 2 (2/0/0) | 2026-10-29 02:44 KST 시각 고정, 비밀 값 제외 | IDS 상태를 기억으로 답하지 않고 현재 재조회 |
| **합계** | **520 (332/94/94)** | **GPU 미학습** | 학습/검증/시험 순서 |

AIT-ADS는 AIT-LDS에서 파생되므로 두 자료를 독립 운영망에서 얻은 두 실사건 집합이라고 표현하지 않는다. 환경 단위 분할을 유지한다. NIST/ENISA는 직무·절차의 근거이며 위308개 대화의 기관 제공 정답이 아니다. 논문은 원천의 연구 근거와 가공 방법을 함께 인용하며 프로젝트 답변 품질은 별도 검증한다.


| 구성 | train | validation | test | 성격 |
|---|---:|---:|---:|---|
| 1차 관제8workflow+AIT-ADS 아카이브 | 264 | 60 | 60 | 기존 불변 R3 입력 보존 |
| AIT-LDS 원문/행 라벨 분석 | 18 | 18 | 18 | 각 환경 공격 연관9+제공자 비공격9, 로그 행은 독립 사건 수가 아님 |
| CISA KEV 수집본 분석/자산 영향 확인 | 36 | 12 | 12 | 공급자 그룹별 분할, 현재 자산 취약/침해 단정 금지 |
| 포렌식 기능 공백·증거 인계 | 12 | 4 | 4 | 도구 없는 이미징/해시/수집 완료를 지어내지 않는 통제 사례 |
| 실제 IDS 관측의 현재 재조회 | 2 | 0 | 0 | 02:44KST 캡처, 실행값을 상수로 기억하지 않고 MCP 재조회 |

NIST NICE 구성요소 **v2.2.0**의 Defensive Cybersecurity `PD-WRL-001`, Incident Response `PD-WRL-003`, Vulnerability Analysis `PD-WRL-007`를 원본 JSON으로 확인했다. 역할별 task 소속43/29/15, 중복을 뺀75업무 중16개 task를8학습 능력 영역에 프로젝트가 매핑했다. ENISA ECSF2.2절의 Cyber Incident Responder/SOC Analyst와 교차 확인했다. 기관 인증·전체75업무 구현·전문가 숙련을 뜻하지 않는다. 포렌식 이미지 수집처럼 현 MCP에 없는 작업은 공백과 이관을 학습한다. 최신 역할 ID와 옛 PR-CIR 체계를 섞지 않는다.

AIT-LDS v2.0(doi:10.5281/zenodo.5789064)은 AIT/TU Wien의 시험장 원시 로그와 행 단위 규칙 라벨이다. 공식 레코드가 지정한 논문은 IEEE TDSC **10.1109/TDSC.2022.3201582** 및 IEEE Transactions on Reliability **10.1109/TR.2020.3031317**다. 원문/행 라벨을 직접 연결해54사례를 추출했다. 제공자 규칙 라벨이며 독립 사람이 검수한 실제 운영 사건 정답으로 포장하지 않는다. **CC-BY-NC-SA-4.0**로, 기존 AIT-ADS의 CC-BY-4.0와 구분한다. 캡스톤 비상업 연구 목적으로 기록하고 출처/가공/동일조건을 보존하며 데이터·가중치 공개를 이 작업이 수행하지 않는다.

대용량53GB 전체 전송은 저속으로 중지했다(미완성304MiB 기록 후 제거). 사용자 지시대로 **원격 참조 방식**으로 필요한33 member만 읽었다. 최종 성공 선택 요청의 기록된 payload는16,279,456B이며 실패/메타데이터/이전 전송까지 포함한 총 대역 사용량이 아니다. 선택member CRC·SHA와 행/라벨 대조 및 공식 파일 메타데이터 재확인 범위다. 전체ZIP MD5는 계산하지 않았다. 제공 서버의 ETag/Last-Modified는 없었으며 있다고 만들지 않는다. short-range 응답은 거절하고 제한 재시도/부분 읽기 조립을 검증했다. 재현 후 검증/실패 선택 캐시42파일16,986,518B를 제거, 파생 SFT·메타데이터·원행/라벨 SHA·실패/성공 영수증은 보존했다. 재생성은 새 원격 참조 스냅샷에서 수행하며 전송 이력의 임의 retry 폴더 이름에 의존하지 않는다.

CISA 공식 `cisagov/kev-data`의 commit **30a09b6f3f7e2f03618cc8c95d212966d3c14e6e**, catalog2026.10.27/1760개를 LICENSE·schema·원본 JSON SHA와 함께 고정했다. CC0-1.0다. KEV 수록은 알려진 악용 취약점의 참고 근거이며 우리 자산 설치·노출·취약 버전·침해를 증명하지 않는다. catalog dueDate도 우리 조직의 확정 마감으로 자동 적용하지 않는다. 카탈로그 버전·필드 날짜·현재 영향 미확인과 후속 자산/버전 확인을 보고한다.

라이브 자료는 비밀 값 없이 실제 `a:suricata`의 runtime 관측을2train사례로 추가했다. 관측시각과 근거를 붙이고 새 질문에서는 현재 도구를 다시 호출한다. 과거 스냅샷·누적 카운터·규칙 적재 수를 영구 현재 사실로 사용하지 않는다. FW 전체읽기 도구는 이37도구 계약에 아직 없으며, 사용자가 지정한 순서대로 학습/적재 이후 추가한다. 추가 뒤 두 비교 후보 모두 같은 도구를 받는다.

전체 대화별 assistant-only 감독 구성은 실제 tokenizer/Torch CPU245검사에서 생략 없이 통과했다. train332대화의766 assistant턴(검증94/202턴·시험94/202턴)을 모두 보존하고, train backbone 입력은1,229,759→517,758토큰(중복 감소 약57.9%)이다. 정답 토큰106,549개는 원 prefix 방식의 합집합과 일치한다. **대화 단위 샘플링/평균 손실 가중치는 prefix별 평균과 다르므로 손실 목적 전체가 동일하다고 주장하지 않는다.** GPU 시간/품질 향상은 미검증이다. max2710토큰/4K, 절단0. 전체332대화1회/166optimizer-step·accum2/lr2e-6를 동결했다. 이전48step 설정은 제한 pilot 준비 이력이며 실행하지 않았다.

공유Ollama 중단은 새 확인 전 미시작이다. 2-step 최장 입력 시험→측정상 제한 안에 들어갈 때 본 학습, 165분 학습 한도·170분 독립 복구·최대3시간 검토 계획이다. 모델의 기본revision/고정이미지/선택loss/VMM·메모리 보호를 유지한다. 복구check는 서비스 동작 없이 통과했고 실제 GPU/복구 타이머 가동은 아직 없다.

학습 전 개발12건은 실제MCP를 실행하지 않는 순차 관측 시험이다. 유효한 대체조회4분기는 fixture가 없어 미평가이며 전체 정확도0%로 쓰지 않는다. 조회생략·가짜ID·잘못된 종결은 중대 오류다. ‘수행할 수 없음’과 ‘미완료’, 출처가 뒷받침하는 구체 제품명과 generic `Multiple Products` 같은 표현 차이는 원문 인용/근거로 동일하게 검수한다. 새 데이터의 test94건은 토큰 검사만 했고 모델 답변 생성/선택에 사용하지 않았다. 준비·기관출처·CPU검증은 독립 전문가 판정/실SOC E2E/새서버전체설치를 대신하지 않는다.

최종 순서는 학습/동일HF품질검증/Thor적재→전체FW읽기MCP·두봇검증→버전/설정 복구점을 확보한 하네스 정리→미학습/학습×기존/정리2x2 비교다. 안전·필수근거·정확도를 우선하고 기존 구성이 더 좋으면 유지한다. 승인/권한/보호주소/대상·해시 검증은 모델 학습만으로 제거하지 않는다.

재현 도구: `institutional_sources.py`(공식 직무/CISA snapshot), `acquire_institutional.py --method range`(명시적 제한 참조), `prepare_institutional.py`(원행·라벨/공급자분할/라이브시각), `dialogue_encoding.py`(assistant 전체 구간). 새스냅샷·기존 동결 core cases·캡처 입력이 필요하며 원본이 캐시에 없으면 묵시적 전체 다운로드로 바꾸지 않는다. 준비 자료·가중치·원문·보고서는 Git에서 제외한다.

> **2026-10-29T02:30:04.996942+09:00 추가 수집 방식 결정:** 사용자가 대용량/저속 원본의 전체 다운로드 대신 원격 참조 학습을 지시했다. 필요한 원문·행 라벨만 HTTPS 범위 요청으로 읽어 최소 정제 SFT를 생성하며 출처URL/버전/행/해시와 실제 읽은 범위를 남긴다. 전체ZIP 체크섬 미검증과 선택member CRC/SHA·라벨행 대조를 구분한다. 원문 취득 캐시는 정제/검증 후 제거하고 파생 학습자료·출처 원장은 보존한다. 원본을 전혀 읽지 않는 학습/0바이트 전송이나 전체 자료 정답 보장을 뜻하지 않는다.

## SOC 관제원 업무용 R3 자료 준비 — 2026-10-29

사용자의 목표는 관제 관리자가 수행하는 **조사 → 증거 대조 → 위험·불확실성 판단 → 변경안/승인 → 적용 후 확인 → 인계**다. 일반 API 호출 corpus 전체를 SOC 전문 정답으로 투입하지 않는다. 현재 [준비 원장](R3_DATA_PREPARATION.json)은 학습 전 상태다.

| 자료 | train | validation | test | 역할·근거 |
|---|---:|---:|---:|---|
| 자체 통제 관제 workflow | 192 | 48 | 48 | 8업무 유형·실제 MCP 계약/응답 원본 함수·로컬 승인/TTL 정책, 에이전트 작성/검수 |
| AIT 과거 로그 조사 | 72 | 12 | 12 | 2경보/사례·원ZIP 192개 객체 일치·가공파일/개행 포함 행 SHA·환경 단위 분리, CC-BY-4.0 |
| 합계 | **264** | **60** | **60** | assistant prefix **696/168/168**, 4K 안에서 제외/절단 0 |

8업무는 WAF/IDS 상관분석·IDS 재시작 승인안·수집 공백·실패 후 검증·복구 검증·임시 차단의 유지 승인·만료 확인·룰 설명 변경안이다. 원인 미확정, 누적 카운터, 관측 표본, 승인/실제 적용, 실제 엔진 적재를 구분한다. 임시 차단 `pending`은 이미 생성된 최초10분 차단의 **60분 유지 승인 대기**다. 룰/서비스 `pending`과 같다고 가르치지 않는다. 실패/확인 불가를 정상·완료로 바꾸지 않는다.

AIT 자료는 **2022년 시험장 아카이브**다. 현재 MCP의 최근 기간 조회로 위장하거나 현재 차단을 요청하지 않는다. `phase_window`는 구간 컨텍스트이며 `normal`도 정상 정답이 아니다. 기존 v1에 쓴 행은 제외했고 train의6환경·validation wheeler·test wilson을 유지한다. 증거 필드/시각은 기계 대조, 한국어 판단·우선순위·인계문은 에이전트 작성이며 독립 전문가 판정이 아니다. `ait_ads_2023`+`landauer2024ait_ads`를 함께 인용하고 가공 방법·선택 수·분할·한계를 논문에 기술한다.

[NIST SP800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)의 RS.AN-03/06/07/08, RS.MI-01, RC.RP-02/05/06을 절차 참고로 연결했다. BibTeX 키는 `nist_sp800_61r3`이며 ToolACE 보조 후보는 `liu2025toolace`와 `team_ace_toolace`로 논문/배포처를 구분한다. 이 문서가 우리 데이터의 정답을 인증하거나 우리 MCP·승인/TTL 구현을 요구한다는 뜻은 아니다. 원본문의 사건 분석/증거 보존/범위 판단/억제/복구 확인에 맞춰 자체 업무 예제를 작성했다.

ToolACE는 고정 원본11,300행에서 엄격한 AST literal-only/스키마·응답 연결·중복/평가 제외 검사 후10,019행(8,031/1,008/980)을 보조 후보로 정제했다. 대체 호출 형식518행 등은 지원하지 않아 제외했다. 이 후보의 전체 의미 검수/실토큰 검사는 미완료이며 **R3 핵심 train에는0건**이다. 임의 API를 운영 MCP 이름으로 바꾸지 않고 reversible alias를 보존한다. APIGen/PRIMUS 게이트 동의·본문 반입은 여전히 미실행이다.

실제 운영 재조회: A 공개 주소→B 내부10.200.10.10 경유,8서버/37도구 전부응답·고정 catalog와 이름/인자/설명 차이0. `a:suricata`는 `kind:runtime`, `metrics/codes/limits`다. 기존 일부 R2/20사례의 systemd `ActiveState` 가정은 실제 이 target과 다르므로 원점수/자료를 보존하고 [한계를 정정](QUALITY_RESULTS.md)했다. 새 센서/진단/룰 인벤토리는 실제 소스의 순수 투영 함수를 사용한다. 그 밖의 결과는 최소 필드 통제 fixture이며 전체 라이브 응답 채록이 아니다.

소스 재생성으로 source SHA와3분할 출력이 모두 일치했다. 학습 시 최장 입력2710/2706토큰, 전체37도구 개발 요청 최대9840+출력768은16K 요청예산 안이다. 학습에는 사례별 소수 도구를 제공하므로 실제 전체37도구 선택 능력으로 일반화했는지는 별도 평가해야 한다. 같은 생성기의 문구/ID holdout이며 독립 실사건/전문가 검증으로 확대하지 않는다.

순차 평가기 `operator_rollout.py`는 모델이 맞는 다음 호출을 생성한 경우에만 fixture를 제공한다. ID·scope·정확한 후보를 검사하되 사유 문장 암기는 요구하지 않는다. 다른 앵커로 같은 전체 파일을 만들면 동등한 수정안으로 허용한다. 준비하지 않은 유효한 조회 경로는 **미평가**이며 거짓 관측/자동 정답 주입/무조건 오답으로 대체하지 않는다. 자동 필수 문자열 판정 뒤 실제 원문 의미 검수가 필요하다. 테스트60건은 토큰 검사만 했고 모델 답변 생성/체크포인트 선택에 쓰지 않았다.

수정 기준의 학습 전 개발9건을 완료했다. 5건은 조회 생략/무관한 임시차단·가짜ID/근거 없는 적재방식/아카이브 원본·해시오해석 등의 중대오류를 원문으로 확인했고,4건은 지원하지 않는 대체 조회 경로로 미평가다. 전체 정확도 백분율로 제시하지 않는다. 초기 엄격 평가의 전체0은 평가기 한계가 섞인 수치다. 원본35B warm을 확인했다.

새48-step/2e-6는 제한 pilot 설정이며 전체696prefix 1epoch 학습 완료가 아니다. 새 successful_microbatch_lineage는 실제 성공 forward/backward의 record/prefix/행 SHA와 직전 optimizer step을 남긴다. 성공 microbatch가 이후 optimizer update/전체 실행 성공을 의미하지 않는다. GPU 학습/변환/후보등록/봇 전환은 아직 없다.

재생성에는 전체 repo의 `infra/mcp` 원본, 기존 AIT 원본·processed·v1 제외 목록이 필요하다. 이들은 자동 인터넷 취득/미확인 동의로 대체하지 않는다. 휴대용 pack은 정제 자료·명세·소스·테스트와 검사용 `contract_sources` 3개를 명시적으로 포함한다. 실제 MCP 서비스로 설치하는 파일이 아니며 새 서비스/포트/키/초기 deploy 변경은 없다.

```bash
python3 -B finetuning/prepare_soc_operator.py --output NEW_DATA --source-output NEW_SOURCE/cases.jsonl
python3 -B finetuning/train.py --config finetuning/config.qwen36-soc-v3.json --check
python3 -B finetuning/pack.py --config finetuning/config.qwen36-soc-v3.json --output TASK_TMP/r3.tar.gz
```

## 2026-10-29 과거 학습의 출처·실제 투입 이력

논문용 출처는 [기계 판독 이력표](TRAINING_PROVENANCE.json), [BibTeX](references.bib), [재검증기](audit_training_provenance.py)에 연결한다. 2026-10-29 Thor에서 읽은12개 완료 실행의 manifest/토큰 통계/Trainer 상태·어댑터 해시와 로컬 원본을 대조했다. 공개/기관 원천을 가공한 자료와 자체 합성 대화, 준비만 한 후보, 평가 자료를 구분한다. **아래 정정은 과거의 “공개 혼합 자료는 준비만 했다”는 포괄적 표현보다 우선한다.**

| 실제 실행 | 학습 원천과 인용 | 준비 풀/선택 범위 | 확인된 학습 |
|---|---|---|---|
| 10/27 초기35B smoke | [Nous Hermes FC v1](https://huggingface.co/datasets/NousResearch/hermes-function-calling-v1). 해당 준비 풀에 `glaive-function-calling-5k.json` 재포함 원천도 있음 | 일반 혼합 train18,872행 중 앞13행을 읽어32 prefix 허용. 앞13행은 전부 Nous 처리 파일에서 유래 | 2 optimizer steps, accumulation1.18,872행 전체나5개 원천 전부를 학습한 것이 아니다. 실제2개 prefix의 개별 ID/순서는 당시 미기록 |
| 10/27 v1 smoke/pilot/main | 자체 합성 대화 + [AIT 기관 원본](https://zenodo.org/records/8263181), `ait_ads_2023`와`landauer2024ait_ads` 함께 인용 | train144대화=자체합성72+AIT 추출72,224prefix. validation32=합성12+AIT20,test36=합성16+AIT20 | smoke32prefix풀/2step,pilot8step,본학습112step/기록epoch1. 서로 독립 실행이며 본학습을smoke어댑터의 연속학습으로 표시하지 않는다 |
| 10/28 R2 smoke/pilot | 자체 생성한 합성 SOC curriculum, 생성기·MCP 계약/소스SHA를 인용. 외부 기관 정답이라고 표기하지 않는다 | train192대화/390prefix,validation32/65,test32/65.전부합성 | 최장2prefix smoke2step, 별도pilot48step/accum2/기록epoch0.246153846.24/48체크포인트는 같은pilot의 중간/최종이며 서로 다른 전체학습으로 합산하지 않는다 |
| 10/28 메모리·드라이버 진단 | R2와 **동일한 데이터 해시**. 새 외부 학습자료가 아니다 | R2 train의 최장2prefix,eval8prefix | native/VMM/trace/선택loss/원본재현2step·native 별도1step. 품질 학습 완료/신규 사례 수로 중복 계상하지 않는다 |

첫 학습 적재 실패·작은 무작위 모델 호환성 fixture는 완료한35B 학습 자료로 합산하지 않는다. 실패 기록은 로컬에 보존하며 폐기된fixture를 실제SOC학습 원천으로 인용하지 않는다. 30B 설정은 준비된 후보였고 실제 위 실행의 기반은 고정35B다. 기반 모델은 `qwen36_35b_base`, revision `995ad96eacd98c81ed38be0c5b274b04031597b0`를 사용한다. 초기smoke의`base_revision_resolved`필드는null였으므로 당시확인필드를사후에채웠다고표시하지않는다. 기반모델의 전체사전학습데이터는우리가확인/복원한후속학습자료와다르다.

### 일반 혼합 준비 자료의 전체 원천

| 처리 입력 | 준비 train/validation/test | 1차 배포처·인용키 | 과거 실제 학습 관련성 |
|---|---:|---|---|
| Hermes FC v1 | 4612/178/210 | [Nous Research](https://huggingface.co/datasets/NousResearch/hermes-function-calling-v1), `nous_hermes_function_calling_v1` | 위 초기smoke의허용32prefix 원천. 포함된Glaive5k는레코드의`_source_file`로구분 |
| Glaive v2 | 4597/219/184 | [Glaive AI](https://huggingface.co/datasets/glaiveai/glaive-function-calling-v2), `glaive_function_calling_v2` | 준비됨. 초기smoke가읽은앞13행에는없고v1/R2에도미포함. Glaive5k재포함본과동일자료로표시하지않는다 |
| 필터된 Hermes traces | 639/89/56 | [DJLougen](https://huggingface.co/datasets/DJLougen/hermes-agent-traces-filtered)와 그 [Lambda 상위 원천](https://huggingface.co/datasets/lambda/hermes-agent-reasoning-traces), `djlougen_hermes_filtered`+`lambda_hermes_traces` | 준비됨. 양쪽 출처를 인용하며 실제실행결과라는제작자설명을우리실관제기록으로표현하지않음 |
| SEvenLLM 영어 | 4528/226/246 | [공식 데이터](https://huggingface.co/datasets/Multilingual-Multimodal-NLP/SEVENLLM-Dataset), [논문](https://arxiv.org/abs/2405.03446v2), `sevenllm_dataset`+`ji2024sevenllm` | 준비됨. `train.jsonl` 원천과학습제외한`test.jsonl`을분리. 이번인용은arXiv v2이며확인안한학회명을만들지않는다 |
| AttackLM 선별 | 4496/268/236 | [집계 저장소](https://github.com/Veedubin/attacklm-dataset), `attacklm_dataset` 및개별upstream키 | 준비됨. 집계자만인용하지않고원천17종URI/선언라이선스/수량을JSON에보존. DRL-1.1등을동일한permissive조건으로표현하지않음 |

이표의분할수는manifest의고정기록이며아래기계판독이력표와재검사한다. 공개카드Apache-2.0은기록하되원천별권리/고지/재배포조건을생략하지않는다. 과거취득당시commit/revision을남기지않은공개원천은미기록으로표시하고,현재웹main을당시버전으로대체하지않는다. 내용SHA와가공후파일SHA는보존되어있다. 실제학습에없는원천을‘학습에사용’이라고논문본문에쓰지않는다.

### 가공·정답·검수의 근거

- 일반 혼합: `datasets/prep.py` → `datasets/processed/` → `finetuning/prepare_data.py` → 고정`data/manifest.json`. ShareGPT/텍스트호출을구조화하고형식·스키마·호출순서·중복·길이·소스상한을검사한다. 명시think/SEvenLLM thought는제외했다. 이것은보안정답의전문가전수검증과다르다.
- v1 AIT: 공식zip → 환경별가공파일SHA → 원천행번호/개행포함행SHA → fact추출대화 → 분할SHA → run manifest → 어댑터SHA. 이번에train72/validation20/test20총112개 모두가공파일과공식zip내경보객체까지일치했다. 추가필드`ait_env`/`phase_window`를제거하고동일객체를대조했다. 시각변환·rule.id/level/phase 추출이목표이며단계창을개별악성정답으로바꾸지않는다. six train/wheeler validation/wilson test 환경분리를유지한다.
- v1 합성·R2: AI작업에이전트가작성/검수했다. v1과거메타데이터의`Operator-authored`/`independently checked`는사용자작성또는독립사람검수를뜻하는것이아니다. 원문은보존하고이해석정정을적용한다. 실제서버관측·기관인증·전문가정답이라고부르지않는다. R2는현재추적생성기로원천256대화를재생성해소스SHA `b89ddbc86a40dd55743513a255f7d35e05adad701fca4468f347f3a5980fdeae`와바이트일치했다.
- 3개corpus×3split=9개로컬manifest/서버파일SHA와12개실행의데이터해시가모두연결됐다. 과거batch별sampler인덱스를기록하지않아개별step의행ID는완전복원했다고주장하지않는다. 새로운실험은원천ID/행SHA/정규화ID/분할·prefix매핑과샘플사용기록을보강해야한다.
- 평가 자료와후보는분리한다. ToolACE/APIGen/PRIMUS는위과거학습에없다. 외부benchmark·AIT holdout·기존test·직전20개품질문항을다음train으로편입하지않는다. Cisco Foundation-Sec은별도사전학습모델비교이며Qwen LoRA 원천이아니다.

재검사: `python3 -B finetuning/audit_training_provenance.py --run-inventory LOCAL_THOR_INVENTORY.json --output NEW_AUDIT.json`. 무결성/출처연결검사이며정확도인증이아니다. 원문·실행원장·행별증거는로컬/Thor에보존하고공개Git에는요약JSON/인용/검사코드를넣는다. BibTeX는논문서식에맞춰사용하되확인안한저자/발행연도/학회명을채우지않는다.


## 2026-10-29 학회·기관 근거 확인과 추가 자료 우선순위

사용자는 추가 학습량보다 출처와 검증 근거를 요구했다. 아래는 **학회 정식 게재 또는 기관 공식 발행을 직접 확인한 자료**다. 논문 게재는 방법과 실험의 학술적 근거이며, 모든 데이터 행의 무오류·우리 SOC 성능·기관의 프로젝트 인증을 뜻하지 않는다. 연구용 합성 데이터도 생성·검증 과정이 명확하면 활용할 수 있으나 실제 침해 사건의 전문가 판정과 구분한다. 과거 후보 목록 전체가 이 기준을 통과했다는 뜻은 아니다.

| 자료 | 직접 확인한 근거 | 제공자 생성·검증 방식 | 우리 업무에 쓸 범위 | 확보/라이선스 상태 |
|---|---|---|---|---|
| AIT Alert Data Set | AIT Austrian Institute of Technology 연구진의 [기관 배포·논문/DOI 목록](https://zenodo.org/records/8263181), CSET 2024 논문 | 실험 시나리오의 로그에서 Wazuh·Suricata·AMiner 경보를 생성. 정상행위의 오탐도 포함하며 labels는 공격 단계의 시간 구간 | 경보 사실 추출·상관분석·미확인 판단. 단계 라벨을 개별 경보의 악성 정답으로 바꾸지 않는다 | 기존 원본 zip/labels 보유·이번 공식 MD5 2/2 일치. Zenodo API CC-BY-4.0 확인. 우리 MCP 대화 변환은 별도 검수 대상 |
| ToolACE | 연구진의 [ICLR 2025 정식 논문](https://proceedings.iclr.cc/paper_files/paper/2025/hash/663865ea167425c6c562cb0b6bcf76c7-Abstract-Conference.html)과 [공식 데이터](https://huggingface.co/datasets/Team-ACE/ToolACE) | 합성 도구 대화, 규칙 검사와 모델 검사 결합. 공개 부분집합 11,300개 | 도구 선택·인자·관련 없는 도구 처리 보조. 보안 사건의 악성/정상 정답을 제공하는 자료는 아니다 | 기존 원본 보유·이번 공식 LFS SHA256 일치. Apache-2.0 카드 표기. 현행 R2 학습에 추가 편입하지 않음 |
| APIGen / xLAM-60k | Salesforce AI Research의 [NeurIPS 2024 Datasets and Benchmarks 논문](https://proceedings.neurips.cc/paper_files/paper/2024/hash/61cce86d180b1184949e58939c4f983d-Abstract-Datasets_and_Benchmarks_Track.html)과 [공식 60K 배포](https://huggingface.co/datasets/Salesforce/xlam-function-calling-60k) | 형식·실행·의미의 3단계 검증을 거친 합성 함수 호출 자료 | 도구/인자 선택 보조. 우리 승인·차단·IDS 대상 판단은 따로 검사 | CC-BY-4.0, 접근 조건 동의 필요. 이번 파일 다운로드/동의/원본 SHA 검증/학습은 미실행 |
| PRIMUS-Instruct | Trend Micro AI Lab의 [EMNLP 2025 정식 논문](https://aclanthology.org/2025.emnlp-main.527/)과 [원 제공자 카드](https://huggingface.co/datasets/trendmicro-ailab/Primus-Instruct) | 전문가가 구성한 보안 업무 질문과 GPT-4o 응답. 카드의 보안496+일반339=835개. 전문가가 모든 답변을 승인한 실관제 정답셋이라고 해석하지 않는다 | 경보 설명·조회 쿼리·의심 명령 분석 등의 보안 문장/근거 활용 | ODC-BY, 접근 시 정보 공유/동의 조건. 이번 접근 동의/본문 수집·SHA/행별 검수는 미실행. [Trend Cybertron 명의 카드](https://huggingface.co/datasets/trend-cybertron/Primus-Instruct/blob/main/README.md)도 확인 |
| MITRE ATT&CK | [MITRE 공식 지식베이스](https://attack.mitre.org/) | 실제 관측을 토대로 전술/기법을 정리 | 기법 정의·근거 문서. 도구 호출 대화나 개별 경보의 공격 성공 정답으로 간주하지 않는다 | 기존 보유 STIX/지식 원천 있음. 정확한 버전·원천 이용 조건을 보존하고 최신 웹 문서를 기존 로컬판과 동일하다고 표시하지 않는다 |
| NIST SP 800-61 Rev.3 | [NIST 공식 최종 문서](https://csrc.nist.gov/pubs/sp/800/61/r3/final), 2025-04 | 사고 대응·위험 관리 권고 문서 | 조사·대응·복구 절차의 설계 근거. 학습 대화 정답셋과 구분 | 이번 공식 서지/초록 확인. 문서 전체 조항을 전수 검토하거나 현행 시스템의 NIST 준수를 검증한 것은 아니다 |

### 인용 가능한 서지

- Landauer, M., Skopik, F., Wurzenberger, M. (2024). *Introducing a New Alert Data Set for Multi-Step Attack Analysis*. CSET 2024. 데이터 DOI `10.5281/zenodo.8263181`, 논문 DOI `10.1145/3675741.3675748`. 기관 배포 페이지가 논문을 직접 연결한다. ACM 본문은 이번 도구 접근403으로 전수 읽지 않았으며 데이터 설명/서지만 확인했다.
- Liu, W. et al. (2025). *ToolACE: Winning the Points of LLM Function Calling*. ICLR 2025. 공식 학회 논문 페이지와 공개 데이터 카드를 대조했다.
- Liu, Z. et al. (2024). *APIGen: Automated PIpeline for Generating Verifiable and Diverse Function-Calling Datasets*. NeurIPS 2024, Datasets and Benchmarks Track. 학회 표기 DOI `10.52202/079017-1725`.
- Yu, Y.-C., Chiang, T.-H., Tsai, C.-W., Huang, C.-M., Tsao, W.-K. (2025). *Primus: A Pioneering Collection of Open-Source Datasets for Cybersecurity LLM Training*. EMNLP 2025, pp.10391–10413. DOI `10.18653/v1/2025.emnlp-main.527`.
- Nelson, A., Rekhi, S., Souppaya, M., Scarfone, K. (2025). *Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile*. NIST SP 800-61 Rev.3. 문서의 일반 권고를 우리 고정 승인/보호 정책의 구체적 의무라고 임의 인용하지 않는다.

서지와 원본 링크는 위 표에 연결했다. 이번은 서지·공식 배포·검증 방식 확인으로, 모든 논문의 본문/부록 재현이나 데이터 전수 전문가 감사를 완료한 것이 아니다.

### 실제로 이번에 확인한 것

- 로컬 ToolACE `data.json` 37,154,735바이트의 SHA256 `ba12c083fca7e8da48c67ad5b895e495447da7c66e39a2e19742c082e6cb537e`가 공식 HF 파일 메타데이터의 LFS oid와 일치했다. AIT zip MD5 `43db6b1f0996e0024befd617706c50e9`, labels MD5 `60ff33796c77fd2136c4d1a4bc841bd9`도 공식 배포와 일치했다. 이는 파일 동일성 확인이며 내용 정답성 인증이 아니다. 공식 MD5는 현대적 보안 서명이나 진본성 증명으로 확대하지 않는다.
- 현행 R2 train192개는 전부 `synthetic_lab_fixture` / `agent_reviewed`다. 실제 전문가 전수 검수/기관 인증 자료가 아니다. 각각1개 도구 정의132대화,2개 정의60대화이며 실제 호출은37종 중19종이다. 나머지18종의 호출 예시 부재를 다시 확인했다. 과거 공개 corpus18,872 train행이나 후보 원문 규모를 현행 R2 학습량에 더하지 않는다.
- [직전 품질 시험](QUALITY_RESULTS.md)은 새 합성20사례·에이전트 검수이며 독립 실무 정확도가 아니다. 같은 HF control84점 대비 학습본76점이라는 불리한 결과도 보존한다. 과제 생성기·관측 제공/단일 턴·소규모 평가 한계를 명시한다. 외부 논문 점수를 우리 모델 점수로 옮기지 않는다.
- 개인 계정의 한국어 공개 합성 자료도 후보지만 이번의 학회/기관 우선 선정과 구분한다. Ko-Agent-Trajectories 제작자 카드 자체에도 첫 호출/과잉 확인 질문 퇴행이 있어 전체 혼합을 우선하지 않는다. 우리 팀이 원문/실험/독립 검증을 끝낸 것으로 표시하지 않는다.

### 추가 학습을 위한 사용 순서와 아직 남은 검증

우선 보유 AIT+ToolACE를 실제 MCP 계약과 구분해 선별하고, 접근 조건을 충족한 PRIMUS/APIGen을 보조 후보로 검토한다. 보안 개념은 MITRE/NIST/장비 공식 문서에 근거하고, 현재 장비 상태·룰 내용·제안 ID는 실제 관측만 정답 근거로 사용한다. 장비 문서는 [Wazuh 공식 규칙 문법](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)처럼 버전과 원 규칙 정의를 확인하며 임의 CRS 소속/악성 판정을 만들지 않는다.

다음 학습 대화는 전체/유사 도구 간 대상 선택, 필수 조회 누락 방지, 관측된 ID만 사용, 오류·빈목록 구분, 파일 선언/엔진 적재 분리, 승인·실행·사후 검증 분리를 포함한다. R2 길이2048과 직전 전체37도구 입력최대8999토큰의 차이를 확인했으므로 전체 도구 학습을 단순 추가하지 않는다. 실제 토큰·메모리 적합성 검증 또는 학습/실행에 일관된 도구 선택 구성이 필요하며, 이것을 점수 하락의 확정 원인으로 주장하지 않는다.

각 편입 예제에는 출처/논문·revision·원본/변환 SHA·원문 위치·도구 계약 버전·선별/제외 이유·생성/변환 방법·검수 주체와 범위를 기록한다. 구조 검사는 객관적 계약 검사, 실제 도구 관측은 환경 확인, 전문가 검수는 의미/판단 확인으로 구분한다. 전문가 검수가 없으면 그대로 표시한다. 사건·환경·문장틀을 분리하고 기존20개 품질 문항 및 외부 벤치마크를 학습에서 제외한다. 개발셋으로 후보를 선택한 후 새 미사용 평가와 실제 MCP/승인/적용·원복 E2E를 확인해야 운영 품질 근거가 된다.

이번은 조사와 기존 파일 대조 완료이며 새 corpus/가중치 다운로드·학습·서버 변경·운영 승격은 없다. 로컬 검사 근거는 `대화기록/검증/2026-10-29-data-evidence/`에 남기고 Git에는 요약·인용 링크만 반영한다. 아래는 과거 시점의 수집·후보 이력으로 보존한다.

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../STATUS.md) · [실행 계획](../PLAN.md).
> 기존30B LoRA 준비 데이터는 train18,872/validation980/test932개이며10/24 로컬 행 수·SHA 대조가 일치했다. 운영35B와 다른 후보이고 GPU 학습/실모델 비교는 아직 없다. 공개 corpus·지식·독립 평가·우리 SOC 검수 trajectory의 역할을 구분한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

이 묶음은 이 프로젝트가 이미 확보한 `datasets/processed/` 파일에서 생성했다. 다음 출처·라이선스 표기는 기존 `datasets/README.md`의 수집 기록에 근거한다. 원본의 저작권/라이선스를 대체하거나 프로젝트가 모든 데이터를 새로 허가한다는 뜻이 아니다.

| 입력 파일 | 원출처 | 기존 수집 기록의 라이선스 |
|---|---|---|
| `hermes_fc_v1.dedup.jsonl` | [NousResearch/hermes-function-calling-v1](https://huggingface.co/datasets/NousResearch/hermes-function-calling-v1) | Apache-2.0 |
| `glaive_fc_v2.hermes.jsonl` | [glaiveai/glaive-function-calling-v2](https://huggingface.co/datasets/glaiveai/glaive-function-calling-v2) | Apache-2.0 |
| `hermes_agent_traces.jsonl` | [DJLougen/hermes-agent-traces-filtered](https://huggingface.co/datasets/DJLougen/hermes-agent-traces-filtered) | Apache-2.0 |
| `sevenllm_en.jsonl` | [Multilingual-Multimodal-NLP/SEVENLLM-Dataset](https://huggingface.co/datasets/Multilingual-Multimodal-NLP/SEVENLLM-Dataset) | Apache-2.0 |
| `attacklm.permissive.jsonl` | [Veedubin/attacklm-dataset](https://github.com/Veedubin/attacklm-dataset) 및 각 레코드 원출처 | 레코드별 BSD-3-Clause / Apache-2.0 / MIT / DRL-1.1 / Public-Domain / 복합 표기 |

AttackLM의 `permissive`는 기존 전처리 파일명이다. 위 라이선스들이 동일 조건이라는 뜻은 아니다. Elastic-2.0·GPL-3.0 레코드는 해당 입력에서 이미 제외돼 있으며 준비기에서도 레코드 라이선스 허용 목록을 검사한다. 레코드별 원출처·라이선스·MITRE ID를 provenance에 보존한다. 외부 재배포 시에는 원출처의 attribution/notice와 해당 조건도 함께 처리해야 한다.

이번 변환: ShareGPT/Hermes 텍스트 도구 호출을 구조화된 `messages`/`tools`로 통일, 도구 스키마·인자·응답 순서 검사, 명시적인 `<think>` 및 SEVENLLM `thought` 제외, 손상·과도한 길이 제외, 중복 제거, 소스별 최대 5,000행 선택, 질문 그룹별 train/validation/test 분할. 보안 내용의 정답성이나 유해성 전수를 사람이 검수한 것은 아니다. 모델 학습 결과를 운영에 쓰기 전에 업무 적합성·승인 정책 준수를 평가한다.

`processed/eval/`의 CyberMetric·CTI-Bench·SecQA·AttackLM bench와 `raw/sevenllm/test.jsonl`은 **동일 질문 차단용으로만 읽고 학습에 합치지 않았다.** AIT 원본 경보, SALAD CSV, knowledge/reference, 기타 미지정 파일도 자동으로 학습에 넣지 않았다. 대화형 정답으로 가공하는 별도 단계가 필요한 데이터다.

입력 파일·평가 제외 파일의 SHA256, 출처별 선택/탈락 수, 출력 SHA256은 `data/manifest.json` 및 Git 추적용 `preparation_summary.json`에서 확인한다. 라이선스·출처 메타데이터는 학습 텍스트에 넣지 않는다.

## 2026-10-27 현행 도구 대조

기존 공개 train18,872행의 구조화 호출19,230개는 현행 MCP 전체 이름과 일치0개였다. 모델별 새 학습 설정과 자료의 업무 적합성은 별개다. 현재 스키마 스냅샷·읽기 감사기는 [THOR_35B.md](THOR_35B.md)를 따르며 공개 원출처·라이선스/분할은 유지한다. 이름의 일괄 치환·현재상태 정답화·검수 없는 운영대화 편입은 수행하지 않았다.

## 추가 학습자료·가중치 후보 조사 — 2026-10-27 KST

사용자의 추가 자료 탐색 요청에 따라 원 제공자 카드·공개 미리보기를 확인했다. 아래 규모/라이선스/성능은 제공자 표기이며 전체 데이터 정답성·원본 파일 SHA·우리 tokenizer/37MCP 스냅샷·Thor/Ollama 호환 검증을 통과한 수치가 아니다. 후보 본문·가중치 다운로드, 계정 약관 동의, 패키지 설치, 학습·운영 모델 변경은 수행하지 않았다. 기존 corpus/분할·평가 제외 정책은 유지한다.

### 새로 확인한 학습·평가 후보

| 후보 | 제공자 규모/라이선스 | 이 프로젝트에서의 판단 |
|---|---|---|
| [Ko-Agent-Trajectories-1.0](https://huggingface.co/datasets/taejoon89/Ko-Agent-Trajectories-1.0) | SFT518,232 / robustness DPO33,323 / behavior DPO14,238 / eval9,936. 데이터CC-BY-4.0, 파이프라인Apache-2.0 | 한국어 다단계 호출·오류 복구 보조 후보. 제작자의Qwen3-8B 비사고모드 시험에서 과잉 확인 질문과 첫 호출 저하가 관측돼 전체 혼합은 권장하지 않는다. 행동 예시 검수·별도 평가 필요. 현재 학습기는 SFT이며 DPO쌍을 그대로 투입할 수 없다. |
| [ko-agentic-sft](https://huggingface.co/datasets/waylake/ko-agentic-sft) | 2,369대화: action1,583/no-action786. Apache-2.0 | 불필요한 도구 호출 억제·빈 결과 처리의 소규모 보조 후보. 가상 도구 응답/자리표시 URL은 사실 근거로 쓰지 않는다. 문자열action·user역할의도구결과를 현재messages/tools 계약으로 변환·검수한다. |
| [Primus-Instruct](https://huggingface.co/datasets/trendmicro-ailab/Primus-Instruct) | 보안496+일반339=835. ODC-BY | 경보 설명·의심 명령·보안 조회 쿼리에 가까운 우선 도메인 후보. HF계정 동의/접근권한이 필요한 gate가 현재도 존재한다. 이번에 동의·접근을 대신하지 않았다. |
| [xLAM-60k](https://huggingface.co/datasets/Salesforce/xlam-function-calling-60k) | 60,000예시/3,673API. CC-BY-4.0 | 기존 미반입 후보의 gate·출처를 재확인했다. 일반 호출 보조용이며 실제SOC판단/승인을 대체하지 않는다. query/tools/answers 구조 변환 및 기존자료 중복 확인 후 사용한다. |
| [qwen3.5-functioncalling-v2](https://huggingface.co/datasets/Mustafaege/qwen3.5-functioncalling-v2) | 카드약225K·영/한. Apache-2.0표기 | Glaive+Saxo 재포장이다. 기존Glaive와 원천 중복이 있어 수량만 더하지 않는다. 문자열 호출/도구 결과 역할 변환·원천별 조건 재확인이 필요해 후순위다. |
| [SOC-AgentBench](https://huggingface.co/datasets/alirezaaminzadeh/soc-agent-bench) | 120에피소드/12시나리오. Apache-2.0 | 이 프로젝트에서는 전체를 평가 전용으로 보류한다. Wazuh/Suricata 등 합성 로그와 별도7도구를 사용한다. 숨은 정답/금지행동을 모델 입력에 노출하지 않고 근거 누락·허위 관측·불필요 호출·무승인 행동을 채점한다. |
| [FunctionChat-Bench](https://github.com/kakao/functionchat-bench) | 한국어 도구 사용 평가 자료 | 즉시 호출/추가 질문/불가능한 도구 요청 거절의 회귀 확인용. 학습 원천으로 편입하지 않는다. |

[한국어ToolLLaMA 변환본](https://huggingface.co/datasets/gyung/toolllama-korean-function-calling)은1,524행(한국어762+영어762)이지만 원천이 `toolllama_G123_dfs_eval.json`으로 명시돼 학습 후보에서 제외한다. [ko-agentic-toolcall](https://huggingface.co/datasets/jungsanghyun/ko-agentic-toolcall)은 검색 카드에 규모가 나오지만 원본raw접근401/완전한라이선스를 확인하지 못해 미확인 후보로만 남긴다.

### 이미 학습된 가중치·LoRA

| 후보 | 확인한 제공자 정보 | 판단 |
|---|---|---|
| [Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct) | Cisco공식보안특화Instruct,Llama3.1기반8B,영어지원·카드other/NOTICE는Cisco변경분Apache-2.0+기반Llama3.1조건 | 경보해석의별도비교1순위. 현Qwen의LoRA가아니며독립모델로평가한다. 한국어·MCP호출·Ollama실적재/속도와전체라이선스조건검토는후속이다. |
| [Foundation-Sec-8B-Reasoning](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning) | Cisco공식보안추론8B,영어지원·카드other/NOTICE는Cisco변경분Apache-2.0+기반Llama3.1조건 | 복합사건판단비교후보. 추론토큰이응답지연에미치는영향을측정해야하며8B라는이유만으로35B보다빠르거나정확하다고판정하지않는다. |
| [Llama-Primus-Merged](https://huggingface.co/trendmicro-ailab/Llama-Primus-Merged) | TrendMicro공식보안코퍼스학습+Llama3.1-8B계열병합,카드MIT | 보안지식/트리아지의별도비교후보. 기반Llama조건과모델파일고지확인후반입한다. 한국어·현MCP·정확도우위는자체미검증이다. |
| [CyberStrike-OffSec-35B](https://huggingface.co/oyildirim/CyberStrike-OffSec-35B) | 같은Qwen3.6-35B-A3B계열의merged+adapter revision. 공격용 하네스300예시 학습,라이선스표기other | 우리MCP와 다른 실행 체계다. 모델 이름이 같아도 base commit·adapter 대상/shape·tokenizer·보호승인·Ollama 변환을 확인해야 한다. 제작자24상황평가에서도 구조화 호출은base22→후보18로 일부퇴보했다. 검증 없는 대체/병합 후보로 추천하지 않는다. |
| [Qwen3.6-35B-A3B-RFT](https://huggingface.co/shaneMattner/Qwen3.6-35B-A3B-RFT) | 같은모델계열의BF16 merged,코딩train1,616/val180. Apache-2.0 | SOC전용학습이 아니다. 제작자비교의base4bit/후보6bit조건이달라학습효과를분리하지못했다. 비교연구후순위,현재SOC우위근거없음. |

Cisco 두 후보의 [Instruct NOTICE](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct/blob/main/NOTICE.md) · [Reasoning NOTICE](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning/blob/main/NOTICE.md)도 직접 확인했다. Cisco 변경분의 Apache-2.0만으로 기반 Llama3.1 조건을 생략하지 않는다.

공식Cisco의1.1-Instruct발표는찾았으나해당HF경로는열리지않아이번다운로드가능후보로확정하지않았다.

이는제공자카드조사이며새모델적재/어댑터shape대조/자체A/B를실행한것이아니다. 다른base의LoRA를현재35B에곧바로합칠수있다고판정하지않는다.

### 보유 자료와 권장 선별 순서

기존 `preparation_summary.json`은원입력120,917행중구조검사/중복제외후적격106,511행,소스별5,000상한을거쳐최종20,784행을기록한다. 이숫자는이번에전체본문을재검사한결과가아니다. `datasets/processed/`의기존5개대화입력과AIT분할/SALAD train/ATT&CK방어자료,raw ToolACE경로의존재를직접확인했다. 현재학습에는AIT경보·SALAD CSV·지식자료가자동포함되지않았다.

권장순서: (1) 보유AIT/Wazuh·Suricata경보+실제성공/실패SOC요청을현행도구스키마에맞춰검수한trajectory, (2) Primus방어과제또는보유ATT&CK/CAR/RE&CT근거로작성·검수한경보설명, (3) 한국어보조자료의소량선별이다. 공개가상응답이나과거운영상태를현재사실로외우게하지않는다. 짧은질문의FW/IDS/WAF대상선택,모든요청항목조회,증거불충분/도구장애,승인전변경금지,적용/원복/사후검증,UTC/KST중복변환금지를필수축으로둔다.

원천·같은사건·번역쌍·질문변형단위로분할하고기존test및외부벤치를학습에서제외한다. 현MCP는보관스냅샷37도구(읽기28/보호9)기준이며반입전실제계약을다시대조한다. 소스별상한만해제하거나수십만행을추가하는것보다스키마/근거/누락검수와새사건평가를먼저수행한다. 선별·전처리·반입·GPU학습·정확도평가는모두다음단계이며이번조사완료와구분한다.

## SOC 선별 실행 — 2026-10-27 KST

후보 조사 뒤 현37MCP 계약을19:05:50 KST 재조회하고 검수 합성100대화와 기존 AIT 공개 실습 경보의 사실 추출112대화를 별도 준비했다. AIT 출처는 [AIT Alert Data Set](https://zenodo.org/records/8263181), CC-BY-4.0이며 각 원본파일/선택행 SHA를 로컬 manifest에 보존한다. rule.id·level·KST 시각·phase_window만 근거로 삼고 공격 시간대를 개별 경보의 악성 정답으로 확장하지 않는다. 여섯 환경 train72, wheeler validation20, wilson test20으로 분리했다. 합성100건은72/12/16으로 시나리오별 분리하며 injection·조회실패·KST 등의 미사용 평가를 둔다. 실제 운영 사건/사람 전수 검수 자료가 아니며 외부 한국어 대규모 corpus는 이번에 추가 반입하지 않았다.

최종 train144/validation32/test36대화(assistant prefix224/44/52), 길이1536에서 초과·정렬 오류0. `soc_dataset.py`가 실제 도구 인자/연결·명시 검수 출처·필수 사실·시나리오 및 첫 질문 중복을 검사한다. test 기반 재설계 시 새 독립 평가셋이 필요하다. 소스 cases·데이터·manifest는 로컬과 Thor `~/Capstone_Groot_training/qwen36-20261027/finetuning/`에 보존하고 Git에 추가하지 않는다. Cisco8B 고정 가중치는 Thor에만 내려받았으며 Qwen에 혼합하거나 LoRA로 적용하지 않는다. 최신 학습/비교 완료 여부는 [STATUS](../STATUS.md)를 따른다.
