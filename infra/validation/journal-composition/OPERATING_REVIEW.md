# 운영 후보 검토 — 2026-11-20

완료된 resume은 기존 영수증 alias와 원래 nonce·plan·host·immutable SHA, 새 peer 근거와 현재 서비스/컨테이너를 확인한 뒤 같은 상태를 반환한다. 서비스 상태가 달라지거나 영수증이 바뀌면 새 intent를 만들지 않고 거절한다. 기존 pending resume의 응답 유실 복구와 완료된 요청의 재확인을 구분한다.

임시 reader는 baseline에서 기존 프로토콜을, 확정한 candidate에서 SHA로 고정한 새 정상 프로토콜을 실행한다. 인수를 마친 candidate 정리는 정상 reader를 설치하고 MCP launcher를 원복한다. baseline 정리는 기존 reader와 launcher를 복구한다. 최종 current는 정상 reader의 실제 SHA·소유자·권한도 대조한다.50경로·정상 reader3개·helper19·control39·보호51을 같은 plan/bundle에 결속한다.



| 항목 | 고정 내용 |
| --- | --- |
| 상태 | `미승인·운영 미적용` |
| release_id | `807ea69fe0f040618726f94e91bcfad1` |
| plan SHA256 | `0a3de6ee7dc20b041a7af97cee9e0241420584f03bee0f57fca02d6ab9221b16` |
| bundle 파일 SHA256 | `8a48b4689b75ff0f633163ab851fb6e1cf1388ce8da71fadaf427249c6e58258` |
| 앱 원문 Git | `2f56a932695a5168673a0289f3f825b73f99cb5d` |
| static manifest SHA256 | `5ce38d8b638c4ea33cee1c761c350afe81f134b8939d7d83ccc4eef43398c1dd` |
| 정상 reader SHA256 | `ab1410845fa6ce375bd6346b6442c8049b0de3704b3e4c4a397ef960e03207f3` |
| 대상/보호/도움 코드 | `50경로 / 보호51 / helper19 / control39 / 정상 reader3` |
| static payload | `44대상 + 정상 reader 원문 / 24blob / 2,104,764B` |
| 기존 모델·컨테이너 | `변경0 / 기존 B→Thor 추론 유지` |
| 승인 유효기간 | `최대1800초 / 정확 release·plan·bundle 결속` |
| 반입 root 전용 파일 | `normal-reader.py 0600·root:root / 호스트별 정상 reader SHA와 일치` |

| 호스트 | 고정 변경 경로 | before SHA256 → temporary/candidate SHA256 | mode |
| --- | --- | --- | --- |
| A | `/etc/systemd/system/capstone-diagnostic-history-backfill.service` | `None` → `7475e7fa254afe5da9760ea54b01dac1d7a0dc958a9daaf3537eb7e79dd8f718` | `0644` |
| A | `/etc/systemd/system/capstone-system-diagnostics.service` | `5eedbadbc162f68601fe029c1a0635dca749055501786c33831fd2b017b909f0` → `370b97d6dea075bf8f5ceabc9c9fbf12eb871a4157a5a304a1664636f10347be` | `0644` |
| A | `/opt/capstone-diagnostics/diagnostic_history.py` | `b9e605805524d4f59e52b1a3b3d48bc307e5d079da7cca3ca49ea5688dee4d2d` → `71d242a9b9e4e26845e4df14a7bcb891f023b412e75cd275f47779dc6afc077b` | `0644` |
| A | `/opt/capstone-diagnostics/diagnostic_journal.py` | `8336e073a249f9a31d4ea5fd90d506f126aada2bf93ec0dcfa47fc135383c1cc` → `002ee71d913fc9de13b7a9a09246879a798af94e2a1376f3ecbfea062c9666ac` | `0644` |
| A | `/opt/capstone-diagnostics/diagnostic_journal_native.py` | `None` → `1940fe0d2d17ec8abd6e5c7e57f6d51b5c45fe97154534d68f3e66b1f8ed7209` | `0644` |
| A | `/opt/capstone-diagnostics/read-system-diagnostics.py` | `ab1410845fa6ce375bd6346b6442c8049b0de3704b3e4c4a397ef960e03207f3` → `b7dc0fe36f1e92e043974eea5934c75a151f0c7ffd0c15472eb593e827a016e4` | `0550` |
| A | `/opt/capstone-diagnostics/system_diagnostics.py` | `e72f3fddfd828404c51b00cee688026ac8fbebc83ad246f29a25f5d299707b0d` → `24aa6d5fb7c9558d96c6f54bc61023ac830cb29321eb422aac60963a367fd09c` | `0644` |
| B | `/etc/capstone-ollama-trial/receipt.json` | `e4e340b4c40f9dd049d773c17e1a094bb91ed840d998937c336780c8909a3af2` → `681a739771f4107408f5bd117382e7506bc59c0112595bf86411a71d8dd07ed7` | `0600` |
| B | `/etc/capstone-review-chat/receipt.json` | `377a5043365d3deeb24db42925a828d005a10d928260eca4e091d37a5c80119d` → `ed629a45eae677915c01996f885525c752276e8eb460c677daf785591f2dd0cc` | `0600` |
| B | `/etc/systemd/system/capstone-diagnostic-history-backfill.service` | `None` → `c1ae062e6488021dd248b0e19ef68c53ac423b72b59bcffb1487081a46ea4321` | `0644` |
| B | `/etc/systemd/system/capstone-system-diagnostics.service` | `d53de01e10d4a6c255d37dcd546c87967a9e308468615d2e321f005d8d471043` → `ca37a1906ef6a2d02c105923de86d804df621455d89b6cef5a83106d7c07a9b8` | `0644` |
| B | `/opt/capstone-diagnostics/diagnostic_history.py` | `b9e605805524d4f59e52b1a3b3d48bc307e5d079da7cca3ca49ea5688dee4d2d` → `71d242a9b9e4e26845e4df14a7bcb891f023b412e75cd275f47779dc6afc077b` | `0644` |
| B | `/opt/capstone-diagnostics/diagnostic_journal.py` | `8336e073a249f9a31d4ea5fd90d506f126aada2bf93ec0dcfa47fc135383c1cc` → `002ee71d913fc9de13b7a9a09246879a798af94e2a1376f3ecbfea062c9666ac` | `0644` |
| B | `/opt/capstone-diagnostics/diagnostic_journal_native.py` | `None` → `1940fe0d2d17ec8abd6e5c7e57f6d51b5c45fe97154534d68f3e66b1f8ed7209` | `0644` |
| B | `/opt/capstone-diagnostics/read-system-diagnostics.py` | `967e7b5b88745a22f0554660f2dceab9904a415081b08264b750f9bccf14cc37` → `aaf326d64e8d4f206e343d38f3090ffa6225bb669114116c9210553a0eac3797` | `0550` |
| B | `/opt/capstone-diagnostics/system_diagnostics.py` | `e72f3fddfd828404c51b00cee688026ac8fbebc83ad246f29a25f5d299707b0d` → `24aa6d5fb7c9558d96c6f54bc61023ac830cb29321eb422aac60963a367fd09c` | `0644` |
| B | `/opt/capstone-management/skill-soc-investigate.md` | `ba74a53678619a232a8b3f419e4865806469944359bd36eb94123c9445372ad1` → `00fcf6abe47a638fe12f90cbddaed97e93c3c151bb480746e6a01b3be7337a4d` | `0644` |
| B | `/opt/capstone-management/skill-soc-query.md` | `41a33ec4c151d193d0489d8c168d1dd2635539c10896bd5c5dbe7234a609a7f9` → `d6027a48a51877212bd414f5dfac098db80b906db575f0f29d030f3e19d01232` | `0644` |
| B | `/opt/capstone-management/soc_management_controller.py` | `97b517c654372c056dc891e7f2b2dd12fe021e7335f7014d94facbc0c79eb2b9` → `cf739c79a2aea6ebeb143f57faca9239e3e1df33284e404dab306d65b8c466f3` | `0644` |
| B | `/opt/capstone-management/soc_management_run.py` | `47c97bf9dd1cd8aa0a508327a53088f3f0a55d95f17f6b635defd47a34b6fc69` → `67a91b4bde70a2a1aa1ce38a3f2dd51e0998a57793eb5f1c10c458f00293fa97` | `0644` |
| B | `/opt/capstone-management/workflow_contract.py` | `6b578846fe5496f4e1ae7395e1a09286d0bf4f94944be2be2398af19f1d631d3` → `5ce616f0efe4ffef6343bf2e232d09aa39d95ab6218b2c672b57b91ad15ceb07` | `0644` |
| B | `/opt/capstone-ollama-trial/chat_contract.py` | `3daa8aed29510adf42949894cb208c189e8b55aa65ff7359871762da69558fd2` → `62bf832c4b194966726edc1a62eb54b8b128db7e247477a653d43d2557a89d17` | `0640` |
| B | `/opt/capstone-ollama-trial/grounding.py` | `47c97bf9dd1cd8aa0a508327a53088f3f0a55d95f17f6b635defd47a34b6fc69` → `67a91b4bde70a2a1aa1ce38a3f2dd51e0998a57793eb5f1c10c458f00293fa97` | `0640` |
| B | `/opt/capstone-ollama-trial/harness.py` | `1dcb96faaefaba74e166df98f4cca6f94d816a61d4c2e51656630e77fcb83822` → `c37c7016c03660527a05b4543a601ecc5b934cd199b4272da49e269658fd43f0` | `0640` |
| B | `/opt/capstone-ollama-trial/query_grounding.py` | `98949624fd7a47153eda3a53d87ff259acc546fcac9e3a817f531f823d00cf92` → `fcb86634a3f52b3af9a0f0f40ac277088c0d5693ad715943a22fd2014291f513` | `0640` |
| B | `/opt/capstone-ollama-trial/read_contract.py` | `fef53a915b6d9c20cde2c543136205407d2e5dcd7cc5e76a32b0251f37893d49` → `597c1e5cce4f9f14cc780be3057f4a2cd1d4d6d21aa36b2bf9a8622348a8b04d` | `0640` |
| B | `/opt/capstone-ollama-trial/runtime.py` | `98ef62be9c6a6893b46525310b88d921bd22a8a6bcd2c411dde8d2ff6b3b1b87` → `1adf674375ae7f7ee25d04ccb48b71812218f3d554766c82403ac7798b920c76` | `0640` |
| B | `/opt/capstone-ollama-trial/skill-soc-investigate.md` | `ba74a53678619a232a8b3f419e4865806469944359bd36eb94123c9445372ad1` → `00fcf6abe47a638fe12f90cbddaed97e93c3c151bb480746e6a01b3be7337a4d` | `0640` |
| B | `/opt/capstone-ollama-trial/skill-soc-query.md` | `41a33ec4c151d193d0489d8c168d1dd2635539c10896bd5c5dbe7234a609a7f9` → `d6027a48a51877212bd414f5dfac098db80b906db575f0f29d030f3e19d01232` | `0640` |
| B | `/opt/capstone-ollama-trial/workflow_contract.py` | `6b578846fe5496f4e1ae7395e1a09286d0bf4f94944be2be2398af19f1d631d3` → `5ce616f0efe4ffef6343bf2e232d09aa39d95ab6218b2c672b57b91ad15ceb07` | `0640` |
| B | `/opt/capstone-review-chat/review_channel_worker.py` | `1cff48cc325f5facb09c73f5c7721c2a03a5e2a903309f022349dcfcef962002` → `1ee66cdd161c87eaeddb75abdba49c48f1b21655ab4b4fc91f78a2c43ada5205` | `0644` |
| B | `/opt/hermes-data/management-code/run.py` | `47c97bf9dd1cd8aa0a508327a53088f3f0a55d95f17f6b635defd47a34b6fc69` → `67a91b4bde70a2a1aa1ce38a3f2dd51e0998a57793eb5f1c10c458f00293fa97` | `0644` |
| B | `/opt/hermes-data/plugins/groot-query-completion/__init__.py` | `98949624fd7a47153eda3a53d87ff259acc546fcac9e3a817f531f823d00cf92` → `fcb86634a3f52b3af9a0f0f40ac277088c0d5693ad715943a22fd2014291f513` | `0600` |
| B | `/opt/hermes-data/plugins/groot-query-completion/alignment.py` | `9742525a117731936db43be546408c50b6f8f44825152af38d1c422b2d0b0410` → `bbb938d546d2ced5cadb970faf76d527a5395ef36b36dbb297d3c18b4bc9fe47` | `0600` |
| B | `/opt/hermes-data/plugins/groot-query-completion/chat_contract.py` | `3daa8aed29510adf42949894cb208c189e8b55aa65ff7359871762da69558fd2` → `62bf832c4b194966726edc1a62eb54b8b128db7e247477a653d43d2557a89d17` | `0600` |
| B | `/opt/hermes-data/plugins/groot-query-completion/chat_harness.py` | `1dcb96faaefaba74e166df98f4cca6f94d816a61d4c2e51656630e77fcb83822` → `c37c7016c03660527a05b4543a601ecc5b934cd199b4272da49e269658fd43f0` | `0600` |
| B | `/opt/hermes-data/plugins/groot-query-completion/grounding.py` | `47c97bf9dd1cd8aa0a508327a53088f3f0a55d95f17f6b635defd47a34b6fc69` → `67a91b4bde70a2a1aa1ce38a3f2dd51e0998a57793eb5f1c10c458f00293fa97` | `0600` |
| B | `/opt/hermes-data/plugins/groot-query-completion/read_contract.py` | `fef53a915b6d9c20cde2c543136205407d2e5dcd7cc5e76a32b0251f37893d49` → `597c1e5cce4f9f14cc780be3057f4a2cd1d4d6d21aa36b2bf9a8622348a8b04d` | `0600` |
| B | `/opt/hermes-data/plugins/groot-query-completion/skill-soc-investigate.md` | `ba74a53678619a232a8b3f419e4865806469944359bd36eb94123c9445372ad1` → `00fcf6abe47a638fe12f90cbddaed97e93c3c151bb480746e6a01b3be7337a4d` | `0600` |
| B | `/opt/hermes-data/plugins/groot-query-completion/skill-soc-query.md` | `41a33ec4c151d193d0489d8c168d1dd2635539c10896bd5c5dbe7234a609a7f9` → `d6027a48a51877212bd414f5dfac098db80b906db575f0f29d030f3e19d01232` | `0600` |
| B | `/opt/hermes-data/plugins/groot-query-completion/workflow_contract.py` | `6b578846fe5496f4e1ae7395e1a09286d0bf4f94944be2be2398af19f1d631d3` → `5ce616f0efe4ffef6343bf2e232d09aa39d95ab6218b2c672b57b91ad15ceb07` | `0600` |
| B | `/opt/mcp/run-wazuh-ro.sh` | `5702374983e3cd02029ffc39ff3e153f1d068d16aa9f45add26cecc4f9d4ab0c` → `5d952661fae1f4324e6cf9273acd16eef837e47486b3ef4953d5540ee67fa8c7` | `0750` |
| B | `/opt/mcp/system-diagnostics-mcp.py` | `7ea5dbe0fe1ce188bade41a56ba24f1c3bce54443d38d1dd3823a1203135b964` → `81bb24ffa355646ca2d19cd99f2b694f45430c03f3d35bc20b7aab41094a695a` | `0550` |
| C | `/etc/systemd/system/capstone-diagnostic-history-backfill.service` | `None` → `e7290ee1fa223c1ed7cc055dc268780caaef11756f51f034844eaaf1678936fe` | `0644` |
| C | `/etc/systemd/system/capstone-system-diagnostics.service` | `5952f4e6bcea69bea1dbacc6d1902ca679043caa95c73907e0ebf77cd17bbd76` → `671645ed2cd489da113e762104cca50e4701f8ee01490b3e0aef271d62af7df6` | `0644` |
| C | `/opt/capstone-diagnostics/diagnostic_history.py` | `b9e605805524d4f59e52b1a3b3d48bc307e5d079da7cca3ca49ea5688dee4d2d` → `71d242a9b9e4e26845e4df14a7bcb891f023b412e75cd275f47779dc6afc077b` | `0644` |
| C | `/opt/capstone-diagnostics/diagnostic_journal.py` | `8336e073a249f9a31d4ea5fd90d506f126aada2bf93ec0dcfa47fc135383c1cc` → `002ee71d913fc9de13b7a9a09246879a798af94e2a1376f3ecbfea062c9666ac` | `0644` |
| C | `/opt/capstone-diagnostics/diagnostic_journal_native.py` | `None` → `1940fe0d2d17ec8abd6e5c7e57f6d51b5c45fe97154534d68f3e66b1f8ed7209` | `0644` |
| C | `/opt/capstone-diagnostics/read-system-diagnostics.py` | `ab1410845fa6ce375bd6346b6442c8049b0de3704b3e4c4a397ef960e03207f3` → `6acf1315d709820a01c2031b6ce9bf54b81601bb1c36d9e1a13429f2304d22ae` | `0550` |
| C | `/opt/capstone-diagnostics/system_diagnostics.py` | `e72f3fddfd828404c51b00cee688026ac8fbebc83ad246f29a25f5d299707b0d` → `24aa6d5fb7c9558d96c6f54bc61023ac830cb29321eb422aac60963a367fd09c` | `0644` |

50개 경로의 변경안에 정상 reader의 원문과 재개 영수증 검증을 결속했다. Mac270검사·생략0·수정 전2실패·공식 Harness² 구조91→138을 확인했다. 잠금 보류·완료 응답 유실 모의·durable intent 직후 SIGKILL은 별도 PID1의 root CLI로 구분하고, 승인 없는 쓰기 재시도는 허용하지 않는다. Native의 최종 결과는 별도 원장으로 확인한다.

새 검토안의 정확 승인 후 관리자231 경유 반입·적용→새 수집→실제 MCP→Hermes·Ollama 새 채팅→확정 또는 복구→정리/current를 확인해야 한다. 합성 소비자와 합성 인수 근거는 실제 운영 인수를 대신하지 않는다. 실제 재부팅/장기 복구·전체 OS 승인·관리 주소 정책·논문 목차91불일치·독립 재구현·새OS 전체 설치·최종 발표는 계속 남는다. 공격·학습·발표자료 추가 제작 중단과 Kali 오프라인 설치 완료를 유지한다.

[변경안](infra/validation/journal-composition/OPERATING_REVIEW.md) · [근거와 미수행](infra/validation/journal-composition/operating-refreeze.validation.json)

[검증·정리와 미수행](operating-refreeze.validation.json) · [이전 앱 검증](current-application.validation.json)
