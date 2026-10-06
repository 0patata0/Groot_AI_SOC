# archive — 보류/대안 문서

여기 문서들은 **폐기가 아니라 보류(deferred)** 상태로 보존한다. 현재 확정안은 최상위 `PLAN.md`(Docker Compose, B-1)이며, 아래는 Kubernetes(k3s, B-2) 대안안이다.

- `PLAN_2.md` — k3s 실행계획 (PLAN.md와 아키텍처 공유, 오케스트레이션만 k3s)
- `suggestion_2.md` — k3s 변형 제안서
- `인프라_구축순서_2.md` — k3s 구축 순서

> 결정 배경: 보안장비 inline 검사·Wazuh 안정성 때문에 캡스톤 마감엔 Compose(B-1) 확정. 오케스트레이션 학습을 목표로 삼을 경우 이 문서들로 k3s 전환 검토 가능.
> 참고: 이 문서들의 `suggestion.md` 등 최상위 링크는 `../`로 봐야 한다(이동 전 경로 기준으로 작성됨).

> 2026-10-06 정리: B-1 원본 `인프라_구축순서.md`는 사용자가 직접 삭제했다. 아래 k3s 변형 문서는 당시의 비교·설계 기록이며, 원본 Phase를 참조하는 부분만으로는 배포 절차가 완결되지 않는다. 현재 구성은 [PLAN.md](../PLAN.md)와 [infra/README.md](../infra/README.md)를 따른다.
