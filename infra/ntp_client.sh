#!/bin/bash
# Groot_B / Groot_C: 시계를 A(10.200.10.1, chrony)에 동기 — systemd-timesyncd 클라이언트. 게이트형, 멱등(리뷰 반영 2026-09-26). sudo bash 로 실행.
# 구조: A ← 캠퍼스 192.168.16.131 ; B/C ← A. ens192 제거 후에도 내부망 경로라 그대로 유효.
# 시계 기준은 timesyncd→A 하나뿐: VMware Tools timesync(주기 동기)는 끄고 확인. 성공 판정은 "재시작 후 A로부터 실제 응답 수신"으로.
set -euo pipefail
SRV=${NTP_SERVER:-10.200.10.1}
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*"; exit 1; }

say "G0 preflight"
[ "$(id -u)" = 0 ] || die "run as root"
ip -br addr show ens160 | grep -qE '10\.10\.10\.(10|20)/' || die "ens160 is not an internal 10.200.10.x address"
[ ! -x /usr/sbin/chronyd ] || die "chronyd is installed on this host — timesyncd would not start (this script is for B/C clients)"
python3 - "$SRV" <<'PY' || die "$SRV does not answer NTP (is chrony on A up and synced?)"
import socket, struct, sys, time
ip = sys.argv[1]; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(b"\x1b" + 47 * b"\0", (ip, 123)); d, _ = s.recvfrom(48)
except socket.timeout: print("  no reply from", ip); sys.exit(2)
w = struct.unpack("!12I", d); li = d[0] >> 6; st = d[1]; xmt = w[10] - 2208988800 + w[11] / 2**32
print("  %s answers: leap=%d stratum=%d offset=%+.3fs" % (ip, li, st, xmt - time.time()))
sys.exit(0 if (0 < st < 16 and li != 3) else 1)
PY
if grep -qE '^(NTP|FallbackNTP)=' /etc/systemd/timesyncd.conf 2>/dev/null; then echo "  note: main timesyncd.conf sets servers; drop-in resets the list first"; fi
echo "ok"

say "P1 timesyncd -> $SRV only (reset idiom so nothing else is appended)"
mkdir -p /etc/systemd/timesyncd.conf.d
cat > /etc/systemd/timesyncd.conf.d/capstone.conf <<EOF
# capstone: 내부 NTP 서버 A(chrony)만 사용. 캠퍼스망은 외부 NTP(UDP 123) 차단이라 기본 서버는 영구 미동기.
[Time]
NTP=
NTP=$SRV
FallbackNTP=
FallbackNTP=$SRV
PollIntervalMinSec=32
PollIntervalMaxSec=256
EOF
if command -v vmware-toolbox-cmd >/dev/null; then
  vmware-toolbox-cmd timesync disable >/dev/null 2>&1 || true
  st=$(vmware-toolbox-cmd timesync status 2>/dev/null || true); echo "  tools timesync: ${st:-unknown}"   # exit code = state (1 when Disabled), so no || echo
  [ "$st" = Disabled ] || die "VMware Tools timesync still '${st:-unknown}'"
fi
timedatectl set-ntp true
systemctl restart systemd-timesyncd

say "V1 fresh reply from $SRV after restart + kernel synchronized"
for i in $(seq 1 20); do timedatectl timesync-status 2>/dev/null | grep -qE '^ *Packet count: [1-9]' && break; sleep 3; done
timedatectl timesync-status 2>/dev/null | grep -E 'Server|Stratum|Offset|Packet count' | sed 's/^/  /' || true
timedatectl timesync-status 2>/dev/null | grep -qE "^ *Server: $SRV " || die "not using $SRV"
timedatectl timesync-status 2>/dev/null | grep -qE '^ *Packet count: [1-9]' || { journalctl -u systemd-timesyncd --no-pager -n 8; die "no NTP reply from $SRV since restart"; }
for i in $(seq 1 10); do [ "$(timedatectl show -p NTPSynchronized --value)" = yes ] && break; sleep 3; done
[ "$(timedatectl show -p NTPSynchronized --value)" = yes ] || die "kernel clock not marked synchronized"
echo "  now: $(date -u '+%F %T UTC')"
echo; echo "== NTP_CLIENT_DONE =="
