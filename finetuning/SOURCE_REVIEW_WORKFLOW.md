# 관제 학습자료 수집·동시 검수

**통합 보관(11/1 확정):** 자료는 [원본1개·정제본1개 압축 규칙](../datasets/STORAGE_POLICY.md)으로 통합 보관합니다. 아래 새 디렉터리 생성 방식은 검수/정제 작업 공간이며 날짜별 영구 압축본을 늘리는 방식이 아닙니다. 정제본 압축만 서버로 반입하고 해제 전후 SHA·허용 멤버를 검증합니다.

> **11/1 15:52 후속:** 새자료8,695건의 GPU 준비 시험(2step·4microbatch·validation8) 완료 후 사용자 지시로 본학습/공유추론종료후 자동재개를 등록했습니다. 전체11/2 03:47KST·32시도 상한,4step저장·최신 완전checkpoint 재개이며 현재 모델 적재 중입니다. [실행 설정](OPERATOR_TRAINING_RUN_20261101.json) · [운용](OPERATOR_PREPARATION.md) · [현황](../STATUS.md).

**후속 실측:** 공유 추론이 종료되어15:24 KST 시험이 시작됐고15:26 GPU 모델 적재 단계에 진입했습니다. 시험 상한15:54 KST·본학습 자동 시작0이며 결과 검증은 아직입니다.

> **11/1 15:23 KST 후속:** 로컬 자료 구성8,695건·실제 CPU 토큰·평가 분리와 DGX 반입을 완료했습니다. 공유 추론 종료 후 GPU 시험만 자동 진행하는 독립 대기를 등록했고 전체18:21 KST/시험30분 상한입니다. 본학습 자동 시작·운영 전환은 없습니다. [재현과 한계](OPERATOR_PREPARATION.md) · [검증 원장](OPERATOR_PREPARATION_20261101.json) · [현재 현황](../STATUS.md).

## 실행 위치와 최신 MCP 근거 — 2026-11-01 14:34 KST

수집·정제·검수·학습 대화 구성은 **로컬**에서 진행한다. 완성된 자료의 학습은 DGX, 검증한 가중치의 적재·추론은 Thor에서 진행한다. 기존 DGX CPU 환경에서 수행한 손실 검사3개는 학습 실행 검증이며 정제 작업이 아니다.

현재 계약은 [11/1 실조회 스냅샷](mcp_contract.20261101.json)에 별도로 보존했다. 기존37도구 파일은 과거 학습 재현용으로 유지한다. 새 목록41개에는 FW 전체 규칙, A/B 전체 보안 규칙, 과거 Wazuh 경보 조회4개가 추가됐고 기존8개 계약도 달라졌다. 실제 읽기17건의 도구명·인자·결과 SHA·KST 관측시각을 로컬에서 검증했다. 읽기 결과 원문은 ignored 자료로만 보존하며 **수집 성공은 학습 정답/기관 인증/운영 품질 합격을 뜻하지 않는다.** Wazuh 계열10개 raw schema의 nullable/format은 기존 엄격 학습 감사기가 지원하지 않는 항목을 포함하므로 별도 호환성 검토가 남는다. 이번17회 호출 대상의 인자 검사는 모두 통과했다.

`capture_training_mcp.py`의 기본 모드는 B의 기존 `soc-ollama` 계정·환경에서 고정된 읽기만 수행하고 JSON을 반환한다. 보호 도구 메타데이터는 조회하지만 해당 도구 호출·모델 호출·채팅 게시·자료 정제는 하지 않는다. 초기 설치기나 GPU 실행기가 아니며 운영 소스/설정을 바꾸지 않는다. 결과 파일은 로컬 `data-*`에 보관한다. 다음은 **로컬 확인** 명령이다.

```bash
python3 -B finetuning/capture_training_mcp.py --verify finetuning/data-soc-ready-20261101-r4/live-mcp-capture.json
```

새 계약 파일이 필요하면 `--catalog <새 파일 경로>`를 명시한다. 기존 파일 덮어쓰기는 거절한다. 오류/누락/중복/보호 호출/해시 변경을 성공으로 처리하지 않는다. 과거 라이브 상태를 미래의 현재 상태로 암기시키지 않고, 실제 도구 결과를 읽는 과정과 출처·관측시각을 학습 대화에 연결해야 한다. 최종 혼합/토큰·의미 검수와 본학습 준비는 계속 별도 단계다.

## 조사 자료 확대와 정제 후 반입 — 2026-11-01 13:12 KST

[고정 출처](INVESTIGATION_SOURCE_SPEC.json) · [최종 검수·정제·반입 원장](INVESTIGATION_SOURCE_REVIEW.json). 사용자의 지시에 따라 **수집→동시 검수→정제→묶음 검증→반입** 순서를 적용했다. 이번 추가 원자료를 DGX에 먼저 전송하지 않았다.

| 출처/처리 | 결과 | 해석 |
|---|---|---|
| Microsoft ExCyTIn/ACESEvals | 질문1,017개(train418/test599), 선택4테이블32CSV·8,383행 | 기관 연구/모의 Azure 환경의 그래프 기반 생성 질문. 최신 논문7,542건과 다른 고정artifact 버전 |
| Microsoft SABER-Sim | 8원사건·40변형, 탐지/보안설정/복구/위협정보160과제·869모의관측 | ExCyTIn과 원천계열 중복. 공격실행 과제·스크립트/컨테이너는 실행하지 않음 |
| 연구용 agentic-pcap | 44조사·3,464도구호출 검수 | 저자모델 답변/실패기록이며 기관검수 정답 아님. 이번 정제·반입·학습 제외 |
| 최종 정제 후보 | 조사349개, 모의관측615개, 연결 근거행847개 | **학습 전 소스 후보**; SFT messages나 검증된 MCP 실행 궤적이 아님 |
| 평가 보존 | 조사186개, 모의관측126개, 연결 근거행92개 | 사건134/166 및 모든 파생변형 보존, 실제모델 평가 미실행 |
| 제외 | 질문482개·관측128개=610항목 | 사유 중복 가능. 원제공test 학습제외·정답노출·근거미연결·중복/공통문자열 등 |

Microsoft Research/저자 저장소는 ExCyTIn의 ICML2026채택을 명시한다. 원논문/공식저장소/버전/원문해시를 인용하며, 자체 가공이나 우리 정답의 품질이 기관 인증을 받았다고 쓰지 않는다. 저장소MIT/NOTICE, 데이터카드CDLA-Permissive-2.0, 프레임워크 투명성 문서의MIT 표기를 함께 보존한다. CDLA전문도 정제묶음에 동봉했다.

### 검수에서 바로잡은 항목

- ZIP280,428,179B를 통째로 받지 않고 정확한HTTPS Range로 선택회원만 읽었다. 선택CSV전송5,254,663B 외에 디렉터리/probe/SQL형식참고 요청은 별도다. ZIP CRC32와 각파일SHA는 검증했고 전체ZIP SHA는 제공값만 기록했다.
- 초기 일반CSV 파싱은 잘못된10,472행을 반환했다. 공급자SQL의`FIELDS TERMINATED BY '❖'`, 쌍따옴표·다중행을 대조한 뒤32파일을 엄격히 재파싱해8,383행/열불일치0을 확인했다. SQL은읽기만했으며실행하지않았다. 초기영수증은보존하고`review/csv-review.json`을최종계수로사용한다.
- 전체질문 정답입력노출10개·선택로그에정답텍스트미연결21개를 보류했다. 텍스트연결996개도 인과적 정답을 전수검증한 건수는 아니다. 최종후보는 질문/관측/공급자답후보/근거행을 분리하고 공급자checkpoint의 추정서술을 학습답변으로 복사하지 않는다.
- 모의관측의AttackTechnique/AttackTechniques/SubTechniques/Techniques를입력과분리했다. 전체중복관측107개와과거보존자료의정확문자열공유21개를보류했다. 공통해시/문자열은의미중복확정과다르므로원자료를삭제하지않는다.
- **사건번호만으로 분리하지 않는다.** 32CSV전체의SystemAlertId/AlertId대조에서5/34/38/39/55/322가연결돼한쪽으로묶었다. 독립연결요소134/166을평가보존하고나머지공급자test454개는학습제외했다. 초기134/55예약·후보283개는실제평가/학습/반입전에정정했다. 선택테이블의공유경보교차0이며전체원시로그·의미독립성까지입증한것은아니다.
- 연구trace의completed상태를실행성공으로보지않았다. 비정상exit92·명시오류1·exit미상50을기록했다. 라벨규약`Attack N detected`를정규화하면33/44일치하며, 이는저자QwenBF16실험의문자열대조로우리학습모델성능/전문가정답이아니다. 전체44개를이번학습반입에서제외했다.

### 재현·검증

아래는 소스 검수 유틸리티다. Mac 패키지 설치·원자료 명령 실행·운영 서비스 변경은 하지 않는다. 기존Python/PyYAML을 사용하며 원문과 정제본은ignored `data-*`에만쓴다.

```bash
python3 -B finetuning/collect_defensive_sources.py --phase plan --spec finetuning/INVESTIGATION_SOURCE_SPEC.json --root finetuning/data-investigation-expansion-20261101-r2
python3 -B finetuning/collect_defensive_sources.py --phase collect --root finetuning/data-investigation-expansion-20261101-r2
python3 -B finetuning/collect_excytin_evidence.py --phase collect --root finetuning/data-investigation-expansion-20261101-r2
python3 -B finetuning/review_investigation_sources.py --root finetuning/data-investigation-expansion-20261101-r2 --history-root finetuning
python3 -B finetuning/prepare_investigation_candidates.py --root finetuning/data-investigation-expansion-20261101-r2 --output finetuning/data-investigation-clean-20261101-r2
python3 -B finetuning/prepare_investigation_candidates.py --validate --root finetuning/data-investigation-clean-20261101-r2
```

기존정제묶음은덮어쓰지않는다. 새재현에는다른`data-*`출력을지정한다. 연구trace가필요하면`collect_investigation_traces.py --phase plan`/`collect`를같은원자료root에별도로실행하며,그결과는정제묶음에포함하지않는다. 전체732검사729PASS/3기존환경skip,후속관련18PASS. 실제묶음검증에서15payload파일SHA·질문근거포인터·분할·정답필드제외통과;manifest/validation포함17파일을전송했다.

정제본만 `/root/Capstone_Groot_training/source-collections/20261101-investigation-clean-r2`에8,421,068B로저장하고전파일재읽기SHA확인했다. 압축전송718,651B/SHA`2e90b2fed41fb50497728e2417e675bf7c9ee1dd77e380b86cd2de0f5584baea`. 이전R1자료의`~/...`는실조회상root홈이며정확한위치는`/root/Capstone_Groot_training/source-collections/20261101-soc-source-expansion-r1`이다. 기존운영파일/권한은변경하지않았다.

**남은 단계:** 인과관계/사후정보·정답 의미 검수, 현재MCP스키마·정확후보승인/사후검증/원복과의연결, 토큰/개인정보검수, 독립평가. `ready_for_gpu_training=false`·새SFT편입0·GPU학습0·운영변경0. 단순분류/로그수량을관제전과정학습완료로환산하지않는다.

이하 앞선 수집 이력을 보존한다.

2026-11-01 KST. [실측·출처 원장](DEFENSIVE_SOURCE_REVIEW.json), [고정 Git 출처](DEFENSIVE_SOURCE_SPEC.json), [사건 보고서 후보](INCIDENT_SOURCE_SPEC.json).

수집 기준은 **이전 평가의 실패 보완과 관제 업무의 미검증 영역**이다. 이번 후보의 승인 대상 불일치·잘못된 WAF 설정값, 기존 모델의 무조회 단정·탐지/차단 혼동을 우선한다. 여기에 사건 조사·상관분석·오탐 배제·영향 평가·대응·복구·보고를 함께 다룬다. 룰 시험만으로 관제 전체를 학습했다고 표시하지 않는다. 정책은 루트 `AGENTS.md`에 지속 적용한다.

## 확보한 자료와 용도

| 원출처 | 이번 실제 확보 | 보완할 업무 | 한계·조건 |
|---|---:|---|---|
| OWASP CRS 고정 commit | 회귀시험 5,221건 | 요청·탐지 근거, 룰별 판단 | 실제 사건 아님. 5,159건 정적 연결, 62건 보류. Apache-2.0 |
| Wazuh v4.14.8 | 회귀시험 2,055건 | 장비/시스템 로그·룰/레벨 연결 | 실제 사건 아님. 1,787건 정적 연결, 268건 보류. GPL-2.0·파일별 고지 유지 |
| ModSecurity 공식 문서 | 526개 절 | 설정 문법·DetectionOnly의 의미 | 질의응답 정답 세트가 아닌 참고문서. Apache-2.0 |
| NIST SP800-53 rev5 OSCAL | 481개 통제/강화항목 | 변경 승인·감사·사후확인 | 프로젝트의 정확 후보 해시 승인 규약은 별도. CC0·NIST 고지 유지 |
| CISA COUN7ER | 152개 대응 지침 | 조사·격리·제거·복구·부작용 검토 | MIT·ATT&CK 고지 유지. 각 조치는 실제 성공사례/실행권한이 아님 |
| ANSSI CERT-FR | 보고서 4건·116쪽 | Houken/APT28/Turla 조사, 웹 정보유출 대응 | 정답 구간·이용조건 추가 검토. TLP/PAP CLEAR를 저작권 허가로 간주하지 않음 |

Git 원자료 971파일/19,538,600B와 PDF4개/5,055,884B를 확보했다. 시험행·문서 절·통제·보고서는 단위가 달라 합쳐서 동일한 학습 건수로 세지 않는다. Suricata-verify는 README/LICENSE만 확보했으며 새 시험자료는0이다.

ASD ACSC의 APT40 조사·네트워크 침해 사례·BianLian·BADCANDY·연례보고서·로그 상관/대응·복구 등11개 페이지는 원출처를 확인했으나 파일 다운로드가 시간 초과/연결 종료로 실패했다. Mac의 환경 제한 해제 실행과 DGX의 읽기 probe에서도 동일 문제가 있었으며 확보 건수에 포함하지 않는다. 웹 공개와 CC-BY-4.0 표기에도 제3자 자료/로고/별도 제외 내용은 따로 검토한다.

SIABench는 논문과 저자 저장소를 확인했다. 현재 저장소의 SIA25/alert35 JSON 목록은 논문 전체 alert135와 구분한다. LICENSE 부재·제3자 플랫폼 원자료 조건 때문에 메타데이터만 보존하고 독립 평가 후보로 둔다. 논문은 현재 확인한 arXiv 사전공개본이며 학회 채택을 확인한 것으로 쓰지 않는다. CISA CSAF는 취약점 권고/업체 재게시 자료로, 실제 침해사고 정답 세트로 취급하지 않는다.

## 검수와 편입 상태

- 수집 즉시 고정 commit/tree·Git blob·크기·SHA256·UTF-8·안전한 YAML/JSON 파싱을 대조한다. 다운로드한 명령·샘플·시험 입력을 실행하지 않는다.
- Wazuh의 `pass/fail`은 `rule:level:decoder` 기대 튜플의 일치/불일치다. `fail`을 정상/오탐 판정으로 바꾸지 않는다. 제공 시험은 각 로그를 별도 subprocess에서 실행하므로 이를 상관분석 시퀀스 성공으로 확대하지 않는다.
- CRS는 전체 stage 순서와 공급자의 룰 문맥을 보존한다. 서로 다른 룰을 검사하는 같은 요청은 자동으로 정답 충돌이 아니다. 같은 룰 문맥에서 충돌한 기대값은 보류한다. 기대 로그 ID는 차단·침해 성공의 증거가 아니다.
- 표준 XML로 해석되지 않는 Wazuh 파일1개와 주석뿐인 CRS YAML1개를 기록했다. 정의 연결이 안 되거나 튜플 의미가 불확실한 자료는 보류한다. 공급자 원문을 임의로 고치지 않는다.
- 같은 관측값으로 연결된 규칙 계열은 통째로 같은 분할에 둔다. 정적 연결 자료의 임시 분할은 CRS 학습후보4,051/평가보존1,108, Wazuh1,400/387이다. 최종 SFT 분할은 아니다.
- 로컬 보관 과거 JSONL의 고유 내용83개/34,037행과 새 입력 값8,715개를 정확값 기준으로 대조해 일치0을 확인했다. 이 결과는 부분문자열·의미중복·서버에만 있는 과거 자료까지의 독립성을 보증하지 않는다.
- PDF 원본/페이지 좌표/본문을 저장하고 주요 본문·표4쪽을 시각 대조했다. 80쪽 문서의 마지막 희소 페이지와 도표 해석, 전체 의미 검수는 남아 있다. 본문 전체를 그대로 입력에 넣으면 사후 결론이 유출되므로 관측 근거와 판단 정답 구간을 분리해야 한다.

**새 SFT 편입0·GPU 학습0·운영 변경0.** 정적 연결6,946건은 공급자 정답과 정의를 연결한 원자료 후보이며 장비 재현, 전문가 전수 판정, 토큰 검사를 통과한 학습행이 아니다. 코드의 JSON schema 오류·권한·환경 실패는 별도 수정 대상이다.

## 재현과 저장 위치

기존 Python 환경을 사용한다. Git/YAML 검수는 PyYAML, HTML 추출은 lxml, PDF 읽기는 PyMuPDF를 사용한다. Mac에 패키지를 새로 설치하지 않았다. 의존성이 없는 대상에서는 승인된 서버 환경을 사용하며, 현재 수집기는 추출 실패를 보류로 남긴다.

```bash
python3 -B finetuning/collect_defensive_sources.py --phase plan --root finetuning/data-source-expansion-20261101-r1
python3 -B finetuning/collect_defensive_sources.py --phase collect --root finetuning/data-source-expansion-20261101-r1
python3 -B finetuning/review_defensive_sources.py --root finetuning/data-source-expansion-20261101-r1 --history-root finetuning
python3 -B finetuning/collect_incident_sources.py --phase review --root finetuning/data-source-expansion-20261101-r1
```

사건 보고서를 새로 받으려면 마지막 명령의 `--phase collect`를 사용한다. 실패 목록을 계속 보존하며, 재사용 파일은 기존 수집 영수증의 SHA와 일치해야 한다. `data-*`만 출력 대상으로 쓰고 원자료/파생자료는 Git에 넣지 않는다. 이들은 데이터 유틸리티이며 서버 초기 설치 진입점 `deploy.sh`는 그대로 유지한다. `pack.py`에는 재현 코드·고정 출처·작은 검수 원장만 포함하고 이번 원문/모델 가중치를 자동 편입하지 않는다.

DGX 보존 위치: `~/Capstone_Groot_training/source-collections/20261101-soc-source-expansion-r1`. 신규 디렉터리에 원자료·메타데이터·감사 이력1,016파일/72,908,160B를 반입하고 전파일을 재읽어 SHA256을 확인했다. 압축본 SHA는 원장에 기록한다. 기존 학습 디렉터리·모델·추론 서비스는 변경하지 않았다. 로컬에는 ignored `finetuning/data-source-expansion-20261101-r1` 검수 사본을 보존한다.

## 다음 학습의 편입 조건

1. 기관 자료의 관측 사실/추정/권고·제3자 인용·이용조건을 구간별로 분리하고, 기관 원문과 프로젝트 작성 질문/주석의 저자를 구분한다.
2. 실제 엔진/설정/참조 데이터에 맞춘 룰 재현과, 현재 MCP 계약을 쓰는 조사→판단→승인→사후확인 대화를 준비한다. 위험한 조치의 승인 경계는 공식 일반 지침이 대신하지 않는다.
3. 과거 사건·기관·규칙 계열·의미 중복·평가 정답 유출·개인정보/비밀값·실제 토큰 한도를 검사한다. 이전 비교8문항을 정답째 학습에 넣지 않는다.
4. 룰 시험이 실제 사건 조사·정상/오탐·복구 자료를 압도하지 않도록 역할별 수량과 혼합 비중을 검토한다. 미검증 분야는 별도 평가를 만든다.
5. 독립 질문에서 치명적 누락/승인 오류·근거 없는 정상 판정과 응답 시간을 원본 대비 재비교한다. 확보량·loss만으로 운영 교체하지 않는다.


## 2026-11-01 R3: 넓은 로그 수집과 한 번의 학습을 위한 통합 준비

고정 버전은 `JOINT_SOURCE_SPEC.json`, 실측/보류/반입 영수증은 `JOINT_SOURCE_REVIEW.json`이다. Splunk 공식 연구팀의 Apache-2.0 시험 기록은 탐지 조사 근거로 수집한다. 시험 시나리오에 공격 이름이 있다는 이유로 모든 이벤트에 악성 라벨을 붙이지 않는다. OTRF는 LICENSE/배지 MIT 대 README 하단 GPL-3.0 충돌을 다시 확인해, 로컬 원자료 검수만 보존하고 최종 서버 묶음에서는 제외했다. CTI-REALM은 Microsoft MIT 저장소의 50개 평가 정의만 보존한다. HF 카드/라이선스와 제3자 CTI/Sigma 권리 미확인 데이터는 학습 자료가 아니다.

```sh
python3 -B finetuning/collect_defensive_sources.py --root finetuning/data-joint-expansion-20261101-r3 --spec finetuning/JOINT_SOURCE_SPEC.json --phase plan
python3 -B finetuning/collect_defensive_sources.py --root finetuning/data-joint-expansion-20261101-r3 --phase collect
python3 -B finetuning/collect_soc_event_sources.py --root finetuning/data-joint-expansion-20261101-r3 --phase plan
python3 -B finetuning/collect_soc_event_sources.py --root finetuning/data-joint-expansion-20261101-r3 --phase collect
python3 -B finetuning/prepare_soc_event_candidates.py --root finetuning/data-joint-expansion-20261101-r3 --output finetuning/data-soc-events-clean-NEW
python3 -B finetuning/prepare_joint_soc_bundle.py --phase prepare-sft --output finetuning/data-joint-sft-NEW
```

출력은 기존 경로를 덮어쓰지 않는 새 이름으로 만든다. 메타데이터는 고정Git blob, LFS 실데이터는 포인터OID/SHA와 크기를 검증한다. 전송한도는 파일16MiB/총384MiB이며 Linux·웹·DNS·방화벽·네트워크와 정상 기록을 먼저 선정한 뒤 작은 완전 파일로 범위를 확장했다. 큰 파일·범위외·누락경로는 `event-plan.json`에 사유와 참조를 남긴다. 사용자는 많은 자료를 요청했지만 대용량을 일부 바이트만 잘라 완전 사건이라고 부르지 않는다. 원문 명령·공격 시뮬레이션은 실행하지 않는다.

`prepare_soc_event_candidates.py`는 승인된 출처만 정제/반입 대상으로 삼는다. 알려진 같은 공급자ID/공유파일을 같은 분할로 묶고 관측 정답표시/명시적 비밀필드·문자열을 제거한다. 잘못된 JSON/긴 레코드는 파일째 보류하며 잘라서 성공 처리하지 않는다. JSON record와 여러 줄 text block을 구분한다. 분할간 정확 중복은 전부 제외, 같은 분할 중복은 하나만 보존한다. 이 검사는 전체 과거 의미중복이나 최종 개인정보 검수를 대신하지 않는다. 사건ID·공급자라벨·출처경로는 별도 lineage이며 입력 정답으로 사용하지 않는다.

SFT 확대는 GUIDE train만 사용한다. 이전 후보·검수·분할 SHA, 원라벨/특징/원천 행수와 조직 분할을 확인하고 이전447건에서 GUIDE256을 중복 재추가하지 않는다. 기존 근거191 + GUIDE train후보3082를 검사했다. `check_joint_tokens.py BASE`는 표준입력에 `{"split":"train","row":...}` JSONL을 받고 실제 기존 encoder/tokenizer로 전수 토큰 검사한다. 기존 DGX 격리환경을 CPU전용, network none, weights 읽기/적재 없이 사용했고 토크나이저4파일을 원base manifest와 재대조했다. 새 설치를 Mac에 수행하지 않는다.

```sh
python3 -B finetuning/prepare_joint_soc_bundle.py --phase admit-sft --output finetuning/data-joint-sft-NEW --token-report TOKEN_REPORT.json
python3 -B finetuning/prepare_joint_soc_bundle.py --phase assemble --output finetuning/data-joint-bundle-NEW --sft finetuning/data-joint-sft-NEW --events finetuning/data-soc-events-clean-NEW
python3 -B finetuning/validate_joint_soc_bundle.py --root finetuning/data-joint-bundle-NEW
```

R3 최종 SFT는3271/176/176(긴train2건제외,최대4067/4096), 새근거는train26079/eval9224블록이다. 기존 회귀시험/공식참고/ExCyTIn정제본도 모듈별로 통합했다. `sft/train.jsonl`만 source/token 검사된 부분집합이며, 전체묶음 `BATCH-PLAN.json`은 `ready_for_gpu_training=false`다. 후보/평가폴더를 glob하여 학습loader에 넣지 않는다. 전과정MCP학습·관제품질향상·안전한승인경계는 아직 입증하지 않았다.

최종 반입은 `/root/Capstone_Groot_training/source-collections/20261101-joint-clean-r3`에 새 디렉터리로만 수행했다. 394파일/373611669B, 압축29546900B를 메모리에서 전송하고 서버에 전체SHA 재읽기 검증; `TRANSFER-MANIFEST.json`은 별도1파일이다. 원자료·OTRF관측·추정도구trace·모델가중치는 이 반입에 없다. 기존 운영서비스/포트/이미지설치는 변경하지 않았으며 초기설치기나 신규서버 전체설치 검증을 실행한 것이 아니다. 로컬 초기정제본은 라이선스정정 감사이력으로 보존한다.

다음은 사건별 인과정답/최종privacy/과거의미중복 → 현재MCP도구계약/실제결과와정확승인·사후검증·원복 근거 → 최종역할/클래스혼합비율·시간예산을 확정하는 일이다. 이를 통과한 자료를 한 번의 검토된 학습 실행으로 연결하며 자료 개수만으로 품질을 보증하지 않는다.
