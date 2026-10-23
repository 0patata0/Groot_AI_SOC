These are administrator integration checks, not installers or SOC/MCP tools.

<!-- current-project-context:2026-10-24 -->
> **현행 기준 — 2026-10-24:** [라이브 확인·완료/미완료](../../../../STATUS.md) · [실행 계획](../../../../PLAN.md).
> 현재 콘솔은 HTTP3개(Log4Shell/Apache2종)와 터미널3개(Redis/Samba/sudo), 총6항목이다. sudo는 별도 rootless의 UID1000·전역 단일 세션이며 종료 시 전체 중지한다. DVWA는 독립 유지한다. 환경 준비와 CVE 악용 성공을 구분하고 공격 재현은 보류한다.
> 아래 날짜·PID·시험 수치·완료 문구는 각 기록 당시의 범위로 보존한다. 이번에 전수 재시험한 결과가 아니다.
<!-- /current-project-context -->
They are separate from the nine pinned production runtime files and are not
run by `deploy.sh`. They use Python's standard library, the existing verified
HTTPS certificate store, and an explicitly supplied administrative SSH helper.

`terminal_duration.py --run` requires an unused, not-deployed Samba environment
and zero observed terminal clients/workers. It creates only Samba, opens two
own HTTPS sessions, and measures the unchanged 300-second input idle and
1800-second lifetime limits in real time. Inputs are only `id` and benign echo.
Capabilities remain in memory; reports retain timing/state/process metadata.
Only its own sessions and proven test container are cleaned up. The public
stop API has no atomic CID compare-and-stop primitive: container cleanup uses
an exclusive test window, repeated exact CID observations and no observed
foreign session, with this limitation recorded in the result.

`sudo_restart_check.py --run` prepares one own UID1000 sudo terminal and writes
a `ready_for_root_restart` handshake. Root separately restarts the one fixed
terminal service. The check verifies old-capability rejection, a changed daemon
PID, the same test CID stopped with PID0, intact guards and other labs. It never
restarts services or hosts. `sudo_reopen_check.py --run` then performs at most
one ordinary reopen/id/own-close check. The original sudo runtime intentionally
retires an exactly receipted stopped CID before creating a new one.

All three commands require `--remote-helper`, `--progress` and `--report` paths.
The read-only `terminal_duration_probe.py` inspects only fixed C namespaces and
process identities; it emits neither capability/process tags nor PTY bodies.
Neither tests nor probes receive an administrator key or bypass cookie.

The observed 2026-10-23 duration run completed after midnight KST. Its original
checker report is preserved separately. Review found swapped lower/upper RTT
labels after execution; the final report assesses saved ack ages with conservative
phase bounds, and a reverse patch reconstructs the exact observed checker.
Future checker bounds were corrected after completion without rerunning or
altering the product, server clock or configured limits. Host reboot evidence
is maintained by the separate root task.
