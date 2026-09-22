# capstone_Groot_B — SIEM(Wazuh) + MCP Server

## Wazuh (공식 docker 사용 권장)
Wazuh는 인증서 생성·이미지 구성이 복잡하므로 직접 compose를 쓰지 말고 **공식 wazuh-docker single-node** 배포를 사용한다.

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b vX.Y.Z   # TODO: 안정 버전 태그
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```
- 접속: https://<Groot_B MGMT IP> (Dashboard), Server API 55000, Indexer 9200
- 리소스: Indexer가 병목 → RAM 16G 할당(PLAN.md 1.5). `OPENSEARCH_JAVA_OPTS` 힙 절반 이하로 설정.
- Agent 등록: Groot_A/C에 Agent 설치, Manager=이 VM MGMT IP.

## MCP Server (자격증명 보유 — A안)
- Groot_B에서 Agent(DGX Spark)와 **별도 프로세스**로 실행. 자격증명(Wazuh API 키, FW 접근, Slack)은 여기 `.env`/시크릿에만.
- 코드는 리포의 `../../mcp-server/`(예정)에 둔다. Tool: Wazuh/Server/Network/CVE/Response.
- 배포 스타터(예정): `docker-compose.yml`로 MCP Server 컨테이너 1개, `.env`로 자격증명 주입, MGMT에서만 노출.

## 검증
- [ ] Dashboard 접속, Server API/Indexer 응답
- [ ] Groot_A/C Agent Active
- [ ] Vulnerability Detection에서 Groot_C의 CVE-2021-3156 매핑 확인
- [ ] DGX Spark에서 MCP 읽기 Tool 호출 성공, Agent 프로세스에 자격증명 없음 확인
