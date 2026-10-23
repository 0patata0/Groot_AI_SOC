# Hermes 평가용 상태 리셋 절차

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../STATUS.md) · [실행 계획](../../PLAN.md).
> 현재 구성은 MCP6서버와 고정 진단25대상이다. 자연어 도구 선택·무근거 완료/SILENT 알림 보완의 실제 검증 상태는 STATUS 최상단을 따른다. 정확 후보 승인과 일반 sudo/Docker/임의 shell 금지는 유지한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->

Hermes는 크로스세션 메모리 + 자기개선 스킬이 있어, 그냥 두면 시나리오 반복 측정 시 **회차가 서로 영향**을 준다(이전 조사에서 학습). 통제된 측정(시나리오 × 10회 등)에서는 회차마다 상태를 초기화해 **독립적(i.i.d.)** 으로 만든다.

## 상태가 저장되는 위치
- 기본 `~/.hermes/` (또는 `HERMES_HOME` 환경변수 경로)
  - `state.db`, `state.db-wal`, `state.db-shm` (세션/메시지 DB)
  - `memories/` (지속 메모리)
- 스킬: `/skills` 명령으로 관리(pending/diff/approve/reject, approval on|off)

## 방법 1 — 회차마다 완전 초기 상태 (측정 권장)
```bash
# 각 측정 회차:
export HERMES_HOME=$(mktemp -d)      # 매 회차 깨끗한 상태
# (config.example.yaml을 $HERMES_HOME/config.yaml로 복사)
# ... 시나리오 실행 + 지표 수집 ...
rm -rf "$HERMES_HOME"                 # 정리
```
장점: 완전 독립. 이전 회차 흔적 0.

## 방법 2 — 고정 HERMES_HOME에서 DB만 삭제
```bash
# 반드시 Hermes 중지 후! (리셋 시 메모리 flush 덮어쓰기 버그: Issue #2670)
pkill -f hermes        # 또는 서비스 stop
rm -f  ~/.hermes/state.db ~/.hermes/state.db-wal ~/.hermes/state.db-shm
rm -rf ~/.hermes/memories/*
# 다시 시작
```

## 측정 중 학습 자체를 끄기 (권장 병행)
config.yaml:
```yaml
memory:
  memory_enabled: false
# 스킬 자기개선 off: 런타임 `/skills approval off`
# 또는 agent.disabled_toolsets: [memory, skills]  (키는 공식 config 문서 확인)
```

## 두 가지 실험으로 나누기 (추천 설계)
- **주 실험(공정 비교)**: 학습 끔 + 회차마다 리셋 → 정상상태 성능을 Baseline과 비교(MTTI/정확도 등). 회차 독립.
- **보조 실험(자기개선 효과)**: 학습 켬 + 같은 시나리오 반복 → 회차가 지날수록 개선되는지(학습 곡선)를 별도 지표로 보고. Hermes의 self-improving이 SOC 조사에 도움 되는지 검증(보너스 findings).

주의: Issue #2670(리셋 시 메모리 flush가 라이브 메모리를 덮어씀)이 있으니, 삭제는 **항상 Hermes 정지 상태**에서. 공식 레포/이슈로 최신 상태 확인.
