# 공개 PCAP 반입·232 시험 — 2026-11-03 KST

사용자가 제공한 네 사이트를 확인하고 11개 캡처를 선정했다. 두 Kali에 같은 파일을 보관하고 **이번 새 시험은 192.168.16.232에서만** 수행했다. 233에서는 반입·무결성 검증만 했다. 원래 외부 목적지로 패킷을 보내거나 PCAP에서 실행 파일을 추출·실행하지 않았다.

## 출처와 선정

| 출처 | 선정 자료 | 구분·이용 근거 |
|---|---|---|
| [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/training-exercises.html) | 2026-10-01 Natureforce, 2026-02-28 Easy As 123, 2026-01-31 Lumma, 2025-01-22 Fake Software | 제작자의 감염 분석 연습 4개. 공식 설명·정답 PDF 4개 보관. 감염 캡처 전체의 모든 패킷을 악성으로 간주하지 않음 |
| [Netresec 목록](https://www.netresec.com/?page=PcapFiles) → [Wireshark 원제공처](https://wiki.wireshark.org/SampleCaptures#hypertext-transport-protocol-http) | HTTP, gzip, chunked gzip, JPEG HTTP | 프로토콜 대조 4개. Netresec은 탐색 경로이며 실제 원제공처는 Wireshark. 공인 무해 실사건 집합으로 표시하지 않음 |
| [Stratosphere](https://www.stratosphereips.org/datasets-malware) | CTU-Normal-4-only-DNS, CTU-Normal-13, CTU-Malware-Capture-Botnet-281-1 | 정상 2개·감염 사례 1개. 각 README의 설명·인용 조건 보존. 281-1의 악성 이름은 제작자도 잠정 표기 |
| [CAIDA](https://www.caida.org/catalog/datasets/passive_dataset/) | 이번 반입 제외 | 접근 신청 대상이며 전송계층 이후 payload가 없다. 공개 OC48도 사용 양식과 조건이 있고 payload가 제거된다. HTTP 공격 재생에 맞지 않아 신청·개인정보 제출·다운로드하지 않음 |

[선정 목록·공식 URL·조건](public-catalog-20261103.json) · [파일별 크기/SHA·결과](public-validation-20261103.json).

11개 PCAP은 **99,096,119B**, 내려받은 PCAP 압축·설명·정답 파일은 30개/88,804,169B다. 전송 압축 SHA와 전 멤버의 크기/SHA를 확인하고 안전하게 해제한 다음, 복원된 11개 PCAP과 PDF 4개까지 양쪽 해시 일치를 확인했다. 독립적으로 제공된 원제작자 체크섬이 있는 것으로 표시하지 않는다.

보관 위치:

- 232: `/home/att/Desktop/PCAP/public-20261103/imported/`
- 233: `/home/attack/Desktop/PCAP/public-20261103/imported/`
- 232 분석 결과: 같은 상위 폴더의 `offline-r1/`, `web-mixed-r1/`

기존 날짜별 58개 PCAP은 그대로 보존한다. Netresec의 FIRST 2015 4.4GB 자료와 기존 58개가 같은 원본인지는 확인하지 못했다. 이름·용량이 유사하다는 이유로 출처를 확정하거나 전체 자료를 다시 받지 않았다. 이번 자료는 검증 전용이며 학습자료에 편입하지 않았다. 원본·패킷/HTTP 내용·정답 PDF는 Git에 올리지 않는다.

## 232 오프라인 검사

A의 기존 이미지에서 읽은 Suricata **8.0.6**, 실제 합본 룰 SHA `b808ceba89dead5d1de8bd4f17cd4370e2f0d565424d979672e25426a60f7f4b`를 사용했다. 232 일반 `att` 권한의 독립 실행 파일·의존성 묶음으로 실행했고 서비스·수신 포트·root 권한을 추가하지 않았다. 11개를 각각 새 프로세스로 처리해 흐름 상태를 섞지 않았다. 전체 410.363초, **156,160패킷**, 엔진·tshark 모두 11/11 정상 종료다.

| PCAP | 패킷 | 경보 | 실제 해석 |
|---|---:|---:|---|
| Natureforce | 42,497 | 6 | 공식 설명의 `107.175.82.242:9000` EXE 전달과 2016141/2018959/2021076 일치. CNCmachineRMS 전용 C2 경보는 미관측 |
| Easy As 123 | 15,512 | 531 | 공식 `45.131.214.85:443`과 NetSupport Checkin/Response 2035892/2035895 일치. 반복 경보를 독립 사건 수로 세지 않음 |
| Lumma | 51,181 | 51 | 공식 `153.92.1.49:80`과 지문수집 2066606 일치. 관련 DNS/SNI 경보도 관측 |
| Fake Software | 39,427 | 23 | 여러 탐지 신호 관측. 정답 PDF를 이용한 전 흐름 정답 대조는 미실시 |
| CTU Normal DNS | 5,966 | 0 | 제공자가 정상으로 설명한 DNS 캡처, 실제 DNS 처리 확인 |
| CTU Normal HTTPS | 949 | 0 | 정상 비교용 HTTPS 캡처, TLS 처리 확인 |
| CTU Malware 281-1 | 64 | 0 | 악성 흐름의 확정 근거 부족. 통과나 검증된 미탐으로 판정하지 않음 |
| Wireshark HTTP | 43 | 0 | 프로토콜 대조 |
| Wireshark gzip | 10 | 0 | 프로토콜 대조 |
| Wireshark chunked | 28 | 0 | 프로토콜 대조 |
| Wireshark JPEG | 483 | 2 | 2016879: 오래된 Windows NT 5.0 표기 정보성 신호. 악성 확정이 아님 |

이 검사는 캡처 사설망의 HOME_NET과 별도 최소 설정을 사용했다. 운영 CLI의 HOME_NET, threshold, 실시간 트래픽 조건과 동일한 시험이 아니다. 캡처 offload 호환을 위해 checksum 검증을 껐다. 경보 합계 613건을 정탐 613건이나 탐지율로 표시하지 않는다. 정보성 룰의 severity도 악성 정답이 아니다.

[실행기](public_offline.py) · [고정 설정](public-offline-20261103.yaml) · [도구 이미지/49멤버 SHA](public-tool-20261103.json) · [이미지에서 도구 묶음 구성](build_public_tool.py). 도구 구성만 A에서 관리자 경유로 수행했고 새 PCAP 분석은 전부 232에서 했다. `-r`로 읽기만 수행하며 FW·WAF·LLM의 운영 동작을 대신 검증하지 않는다.

## 232 실제 웹 97:3 대조

19:37:41~19:38:06, 새 Wireshark chunked/JPEG 캡처의 GET `/`·User-Agent를 lab mount와 Host에 맞춰 97회 전송했다. 뒤이어 기존에 검토한 SQLi·경로탐색·XSS 원본 프레임 대조 3건을 전송했다. **새 악성 C2 캡처를 웹 공격으로 바꿔 성공했다고 표시한 시험이 아니다.**

| 항목 | 결과 |
|---|---|
| 전송 | 시도 100, 실제 정상 97 + 공격 대조 3, 연결 실패 0 |
| 정상 응답 | DVWA 302 49건, Log4Shell 308 48건. 리다이렉트 이후 앱/인증 검증은 별도 |
| SQLi | 403·Enabled, 942100/942160/10200 |
| 경로탐색 | 403·Enabled, 930100/930110/10500 |
| XSS | 403·Enabled, 941100/941110/941160/941390/10300 |
| IDS | XSS 2009714, 실제 정상 반복의 1000002 경보 0. curl 반복에는 정보성 2002825 1건 |
| FW | 19:38:09.525에 232 임시 차단 추가. 기존 600초 TTL·19:48:09 기한과 소유 태그 확인 |
| Wazuh | 100102(WAF), 100110/100111(IDS), 100121(대응 상태) 확인 |
| 승인 | 실제 [유지/해제 카드](https://chat.grootlab.duckdns.org/soc/pl/tyirz5gqef8djqymbqioq3973w) 게시. 이번에 유지/해제 승인을 대신 누르지 않음 |

[실제 실행 소스](public_web_mixed.py). 공격을 마지막에 배치한 제한된 순서 시험이며 임의 혼합 순서의 성능 평가가 아니다. WAF 요청별 ID·URI SHA·실제 룰을 대조했다. 19:49:04 재조회에서 원기한 종료 뒤 상태 `expired`·19:48:11 종결·FW 집합 부재를 확인했고, 별도 정상 GET도 302로 복구됐다. 테스트 IP의 차단 예외를 추가하거나 임의로 조기 해제하지 않았다.

## LLM 조사에서 남은 문제

- WAF 사건은 MCP 6회 완료 뒤에도 최종 답변 없이 `outcome_unknown`이었다.
- IDS 사건은 실제 읽기 6회 후 `monitor` 보고를 냈지만, 232를 예전 장비명으로 부르고 19:37~38 구간에 없는 과거 SID1000002를 근거에 섞었다. 스캔·실행 시도의 확정도 실제 증거 범위를 넘는다.
- 따라서 센서·차단·카드 성공을 LLM 조사 품질 성공으로 합산하지 않는다. 다음 보완은 자산 주소 재할당 메모리, 사건별 시간/flow 근거 결속, 정보성 신호와 공격 구분, 미완료 조사 종료다. 이번 실험을 이유로 모델/봇 하네스·권한을 수정하지 않았다.

## 반입 검증·정리

[반입 검증기](public_import.py)는 절대경로·상위경로·링크·중복·예상 밖 멤버·SHA 불일치를 거절한다. 실제 30파일/복원 해시 검증과 별도로 6개 거절 조건을 확인했다. 패킷/정답 파일만 허용하며 PCAP 내 실행 객체를 추출하지 않는다.

232 DNS 조회 실패로 Mac 작업 임시 폴더에서 다운로드한 뒤 고정 호스트 키로 두 Kali에 직접 SCP했다. 반입·복원 검증 후 Mac 다운로드 36파일/231,865,005B와 양쪽 전송용 바깥 압축을 삭제·부재 확인했다. A에서 만든 도구 전송용 2파일/폴더도 제거했다. 원래 PCAP/정답/출처 설명, Kali 독립 분석 도구, 서버 복구본·실험 증거는 보존한다. Mac 신규 패키지 설치는 없다.

최종 읽기에서 운영 Suricata PID1577695·local/합본SHA와정확후보의 primary/all 백업SHA를확인했다. 종료된자체실패제안unit만 reset-failed했고 실패원문은보존했다. 232 시험worker/Suricata 프로세스잔여0을확인했다.

게시확인: IDS수정9파일 `57b754d`와공개PCAP13파일 `c875813`을각각푸시·원격main일치확인했다. 자체Mac임시도우미65파일은로컬검증사본을보존한후삭제했고작업임시부모도없다. 공개파일후속확인보완은별도문서커밋으로게시한다.

후속정정(20:16 KST): 당시WAF건의원문native 최종보고/exit_code0은존재했고,DB와게시에서outcome_unknown이된원인은공유Native차단ID를컨트롤러가다른사건소유권충돌로거절한것이었다. [후속수정/실검증](../../hermes/shared-containment.md)을따른다. 이전보고의관측상태와당시모델문장/시간·자산오류는보존한다.

후속21:16 KST: [시각/자산근거 보완](../../hermes/incident-context.md)을9복사본에반영했다. 새232 대조에서IDS8/WAF6 MCP오류0·정확한사건구간/수집자구분·승인대기보고를확인했으나시간도구입력/만료시각오답과사건종결은남는다. 위19:45의하네스미변경/잔여는당시범위로보존한다.
