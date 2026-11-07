# 공개 패킷 자료의 추가 학습 후보 검수 — 2026-11-07 KST

사용자가 지정한 네 사이트를 재검토했다. 이번 범위는 **로컬 수집·정제·검수 → DGX 정제 후보 반입**이며 학습·모델 교체·Kali 추가 반입·패킷 재생은 하지 않는다. [저장 규칙](../datasets/STORAGE_POLICY.md) · [현황](../STATUS.md).

## 선정과 보류

| 원출처 | 검토 결과 | 이번 처리 |
|---|---|---|
| [Stratosphere CTU-13](https://www.stratosphereips.org/datasets-ctu13) | 대학 통제 실험에서 정상·배경·봇 통신을 함께 수집. 제공자가 권장하는 양방향 흐름과 라벨 의미를 확인 | 시나리오5/7/11의 흐름 CSV와 README만 수집. 로컬 정제 후 DGX 후보 반입 |
| [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/training-exercises.html) | 최근2026 다섯 연습은 기존 PCAP 반입 기록에 있음. [기존 기록](../infra/validation/pcap-web/PUBLIC_PCAP_20261105.md). 공개 연습/정답을 포괄적인 모델학습·재배포 허가로 해석하지 않음 | 이번 재다운로드/학습 반입 제외. 기존 개발 시험과 독립 평가 중복 확인 및 명시 이용조건 필요 |
| [Netresec 목록](https://www.netresec.com/?page=PcapFiles) | 원제공자가 아닌 색인. FIRST2015는4.4GB이며 기존 출처 미확인2015자료와 대조 필요. [Nitroba](https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/)는 교육용 조사 시나리오와 제공 SHA가 있으나 교사용 정답은 접근 제한 | 원출처/정답/중복 미해결 후보는 보류. 정답 제한 우회·대형 파일 다운로드0 |
| [CAIDA DDoS2007](https://www.caida.org/catalog/datasets/ddos-20070804_dataset/) | 현재 공개 다운로드 가능. 약1시간 공격·피해자 응답이며 정상 트래픽은 대부분 제거되고 payload가 없음. 전체5.3GB압축. 자료별 AUA·인용·발표물 보고 조건 있음 | 정상/악성 균형 자료나 HTTP 공격 정답으로 사용하지 않음. 별도 DDoS 관측 후보로 기록, 이번 다운로드/반입0 |

CAIDA가 모두 신청제라는 일반화는 하지 않는다. 이전에 제외한 passive trace와 이번 공개 DDoS 자료는 서로 다르다. 외부 서비스에 신청·이메일·발표물 보고는 하지 않았다.

## 선정 자료의 근거와 한계

| 사례 | 공식 설명·원문 좌표 | 제공자의 잠정 계열 | 보완할 관제 업무 |
|---|---|---|---|
| CTU-13 시나리오5 | [Capture46 README](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-46/README.html), detailed-bidirectional-flow-labels/capture20110815-2.binetflow | Virut | 통신 방향·다중 목적지/프로토콜·정상 배경과 감염 호스트 흐름 구분 |
| CTU-13 시나리오7 | [Capture48 README](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-48/README.html), detailed-bidirectional-flow-labels/capture20110816-2.binetflow | Sogou | 소수의 봇 흐름과 많은 배경 흐름 속 근거 찾기·불확실성 보존 |
| CTU-13 시나리오11 | [Capture52 README](https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-52/README.html), detailed-bidirectional-flow-labels/capture20110818-2.binetflow | RBot | 여러 감염 호스트·ICMP 급증·통신 연결과 시간 순서 조사 |

서지: Garcia, S.; Grill, M.; Stiborek, J.; Zunino, A. (2014). *An empirical comparison of botnet detection methods*. Computers & Security,45,100–123. [DOI10.1016/j.cose.2014.05.011](https://doi.org/10.1016/j.cose.2014.05.011). 공식 사이트의 서지 연결을 확인했으며 논문 전문을 이번에 재검수했다고 표시하지 않는다. 각 README의 프로젝트·저자 인용 조건과 [공식 FAQ](https://www.stratosphereips.org/datasets-faq)의 인용 안내를 보존했다. 임의로 CC 라이선스나 공인 정확도 인증을 붙이지 않는다.

- 라벨은 제공자 분석이며 본 프로젝트의 새 전문가 정답이 아니다. `From-Botnet`은 감염 호스트 출발 근거이지 모든 연결의 공격 성공 증거가 아니다. `To-Botnet`, `To-Normal`, Background를 각각 악성/정상으로 단정하지 않는다. DNS·웹서버 등 정상 라벨도 제공자가 신뢰 한계를 명시했다.
- Capture48 설명에는8월16일 Sogou와 일치하지 않는8월10일 Neris 문단이 있다. 그 문단을 시간선·정답으로 사용하지 않는다. README의 일부 호스트 흐름 합계와 CSV 행 수도 다르므로 원문을 보존하고 실제 CSV 수를 별도로 보고한다.
- 2011년 통제 실험이다. 최신 기업 침해 대응·호스트 로그·복구·승인 업무 전체를 대표하지 않는다. 패킷 원문/HTTP payload는 이번에 수집하지 않아 페이로드 확인이나 공격 성공을 학습 정답으로 만들 수 없다.

## 정제와 누수 경계

[수집·정제 코드](pcap_source_candidates.py)는 HTTPS 검증을 유지하고 CSV 스키마·유한한 비음수 값·주소/시간을 검사한다. ARP의 IP 주소와 MAC 주소 표현을 모두 처리한다. 첫 로컬 후보의 ARP189행 오제외를 바로잡고 재생성했으며 잘못된 후보는 반입하지 않는다. IPX/RARP 등 비IP 프레임 주소를 IP로 강제 해석하지 않는다.

전체 유효·중복 없는 행을 유지하며 표본추출하지 않는다. 관측값과 제공자 판단을 별도 파일로 분리한다. 원 IP/호스트 이름·악성코드 계열·정답 라벨은 모델 관측 입력에 넣지 않는다. 호스트는 동일한 대체 식별자로 연결하고 원본 CSV/행 번호/SHA는 로컬 원본과 후보 manifest에서 추적한다. 대체 식별자는 비가역 익명화라고 주장하지 않는다. 원 시각의 timezone이 CSV만으로 확정되지 않아 임의 KST 변환을 하지 않고 `unverified`로 표시한다. 수집·작업 시각은 KST다.

현재/과거 검증의 DNS 정보성 경보 과대해석, 행위 주체/목적지 혼동, 근거 없는 정상/성공 판단을 보완할 후보이며 원문/라벨 대조와 조사 요약 평가에 연결한다. 도구 라우팅·스키마·권한 오류를 이 학습으로 고쳤다고 표시하지 않는다. 개선 여부는 이 자료와 겹치지 않는 사건의 오판·누락·근거 연결·정상 오탐으로 검증해야 한다.

세 캡처는 대학망과 호스트를 공유하므로 서로 완전히 독립인 최종 평가로 쪼개지 않는다. `CTU-13-shared-campus-and-hosts` 하나의 누수 그룹이며 전체 train/validation/test 미배정이다. 기존 로컬 raw/processed/data-*의 텍스트에서 CTU-13 이름·파일명·SHA를 검색해 일치0을 확인했으나 파생·이름 없는 동일 사건을 모두 배제한 증명은 아니다. 과거 평가/파생자료의 의미 중복 대조 전에는 최종 평가나 학습 적격으로 승격하지 않는다.

12:19 최초 반입은 **정제된 근거 후보**였으며 원 흐름 후보의 학습 allowlist는 계속 빈 목록이다. 후속 사용자 지시로 별도 근거대화24건을 로컬에서 구성·검수하고 통합8,719건을 확정했다. 실제 토큰/마스크·DGX반입은 [학습 준비 결과](PCAP_TRAINING_PREPARATION.md)를 따른다. 실제학습0이며350,000여 흐름을 같은 수의 독립 사건이나 학습 문답으로 세지 않는다.

## 보관과 검증

원본과 정제본은 `datasets/archives/original.tar.gz`, `cleaned.tar.gz` 두 고정 경로를 사용한다. 기존 대규모 자료의 통합 이전은 별도 미완료이고 삭제하지 않는다. 이번 신규 후보만 해당 보관소에 등록한다. [검증 코드](verified_archive.py)는 압축 전체SHA·manifestSHA·허용 멤버·크기·파일별SHA와 새 경로 복원 결과를 확인한다. 절대/상위 경로·링크·장치·중복/예상 밖 멤버를 거절한다. 서버에는 정제본만 보내며 확인 뒤 전송용 압축은 제거한다.

공개 원장에는 출처·집계·SHA·검증·반입 상태만 기록한다. 데이터 본문·대화/평가 정답·자격·가중치는 Git에 넣지 않는다. [작은 검수 원장](PCAP_LEARNING_REVIEW.json).

반입 확인: **2026-11-07 12:19 KST**, DGX `~/Capstone_Groot_training/pcap-candidates-20261107/verified`. 원본351,160행과 정제351,160행 전수 대조·관측 중복0·식별자 충돌0·회귀14검사 통과. 압축29,109,734B/SHA `4914723bc6a389577a7f98799138d2f59b5de92dc88fe3526daf78cb1620c60d`, 서버10파일 복원/개별SHA 일치. 서버 전송용 압축 제거·원본 전송0·학습0. 첫 SSH 재접속 실패 뒤 사용자 VPN 재연결로 검증 완료.
