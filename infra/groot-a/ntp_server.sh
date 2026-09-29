#!/bin/bash
# Groot_A: 내부망 NTP 서버(chrony) 구성 — 게이트형, 멱등(적대적 리뷰 3관점 반영 2026-09-26). sudo bash 로 실행.
# 구조(사용자 결정): A ← 192.168.16.131(캠퍼스 시간 서버, 192.168.16.0/24에서 유일한 NTP 응답자) ; B/C ← A(10.200.10.1)
# 전제(최초 1회): /tmp/ntp/ 에 chrony·tzdata-legacy(·libcap2-bin) deb + SHA256SUMS(우분투 아카이브 인덱스 값). 오프라인 dpkg 설치.
#   - chrony 는 systemd-timesyncd 패키지와 'time-daemon' 충돌 → timesyncd 패키지를 먼저 제거(apt 가 하던 일을 수동으로).
#   - tzdata-legacy 는 tzdata 와 동일 버전 고정 → G0 에서 검사.
# 이후 A의 시계 기준은 chrony 하나: VMware Tools timesync(주기 동기)는 끄고 확인. (스냅샷 복원/재개 시 1회성 호스트 보정은 vmx 설정 영역 — README 참고)
set -euo pipefail
UP=${NTP_UPSTREAM:-192.168.16.131}
D=${DEB_DIR:-/tmp/ntp}
say(){ echo; echo "== $* =="; }; die(){ echo "!! ABORT: $*"; exit 1; }
installed(){ dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }

say "G0 preflight"
[ "$(id -u)" = 0 ] || die "run as root"
NEED=0; for p in tzdata-legacy chrony; do installed $p || NEED=1; done
if [ $NEED = 1 ]; then
  [ -f "$D/SHA256SUMS" ] || die "$D/SHA256SUMS missing (stage the debs; /tmp is wiped at boot)"
  ( cd "$D" && sha256sum -c --quiet SHA256SUMS ) || die "deb sha256 mismatch vs Ubuntu archive index"
  set -- "$D"/chrony_*.deb; [ -e "$1" ] || die "chrony deb missing in $D"
  want=$(dpkg-deb -f "$D"/tzdata-legacy_*.deb Version 2>/dev/null || true); have=$(dpkg-query -W -f='${Version}' tzdata 2>/dev/null || true)
  installed tzdata-legacy || [ "$have" = "$want" ] || die "installed tzdata $have != tzdata-legacy $want (version-locked): stage tzdata_${want}_all.deb too"
  echo "  debs verified; tzdata $have == tzdata-legacy $want"
else echo "  chrony already installed — skipping deb checks"; fi
python3 - "$UP" <<'PY' || die "upstream $UP unusable (no reply, or unsynchronised: leap=3/stratum 0|16)"
import socket, struct, sys, time
ip = sys.argv[1]; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(b"\x1b" + 47 * b"\0", (ip, 123)); d, _ = s.recvfrom(48)
except socket.timeout: print("  no reply from", ip); sys.exit(2)
w = struct.unpack("!12I", d); li = d[0] >> 6; st = d[1]
xmt = w[10] - 2208988800 + w[11] / 2**32; rdelay = w[1] / 65536; rdisp = w[2] / 65536   # w[3] is the ref id
print("  upstream %s: leap=%d stratum=%d offset=%+.3fs rootdelay=%.3fs rootdisp=%.3fs refid=%s" % (ip, li, st, xmt - time.time(), rdelay, rdisp, ".".join(str(b) for b in d[12:16])))
sys.exit(0 if (0 < st < 16 and li != 3) else 1)
PY
ip -br addr show ens160 | grep -q '10\.10\.10\.1/' || die "ens160 is not 10.200.10.1"
if nft list ruleset 2>/dev/null | grep -q 'hook input'; then echo "  note: nft input hook exists — ensure udp/123 from 10.200.10.0/24 is allowed"; fi
echo "ok"

say "P1 packages (offline dpkg): remove systemd-timesyncd (time-daemon conflict), install debs"
if [ $NEED = 1 ]; then
  if installed systemd-timesyncd; then
    systemctl disable --now systemd-timesyncd >/dev/null 2>&1 || true
    dpkg -r systemd-timesyncd >/dev/null 2>&1 || dpkg -r --force-depends systemd-timesyncd >/dev/null 2>&1 || die "cannot remove systemd-timesyncd (conflicts with chrony)"
    echo "  systemd-timesyncd package removed"
  fi
  DEBS=()
  for p in libcap2-bin tzdata-legacy chrony; do
    if installed $p; then echo "  $p already installed"; continue; fi
    set -- "$D"/${p}_*.deb; [ -e "$1" ] || die "$p not installed and no deb in $D"; DEBS+=("$1")
  done
  if [ ${#DEBS[@]} -gt 0 ]; then
    LOG=$(mktemp)
    if DEBIAN_FRONTEND=noninteractive dpkg -i "${DEBS[@]}" >"$LOG" 2>&1; then grep -E 'Setting up|Unpacking' "$LOG" | sed 's/^/  /'; rm -f "$LOG"
    else cat "$LOG"; rm -f "$LOG"; die "dpkg -i failed"; fi
  fi
fi
installed chrony || die "chrony not installed"
[ -z "$(dpkg -C 2>/dev/null)" ] || { dpkg -C; die "dpkg reports broken packages after install"; }
chronyd --version | head -1 | sed 's/^/  /'

say "P2 chrony.conf (upstream $UP, serve 10.200.10.0/24 on ens160 only, local fallback)"
[ -f /etc/chrony/chrony.conf ] || : > /etc/chrony/chrony.conf
[ -f /etc/chrony/chrony.conf.orig ] || cp -a /etc/chrony/chrony.conf /etc/chrony/chrony.conf.orig
cat > /etc/chrony/chrony.conf <<EOF
# capstone Groot_A — 내부망 NTP 서버 (generated $(date -u +%F)). 원본: chrony.conf.orig
# 상류: 캠퍼스 시간 서버(192.168.16.0/24에서 유일한 NTP 응답자). 하류: B/C (10.200.10.0/24, systemd-timesyncd → 10.200.10.1)
server $UP iburst
# 서버 소켓은 내부 인터페이스에만(캠퍼스 세그먼트에 NTP 서비스 노출 안 함). 상류 질의용 클라이언트 소켓은 별개.
bindaddress 10.200.10.1
allow 10.200.10.0/24
# 상류 불통 시에도 내부에 시간을 계속 제공(내부 일관성 우선; stratum 10 으로 표시됨)
local stratum 10
driftfile /var/lib/chrony/chrony.drift
keyfile /etc/chrony/chrony.keys
ntsdumpdir /var/lib/chrony
logdir /var/log/chrony
maxupdateskew 100.0
rtcsync
# VM: 호스트 보정 등으로 1s 이상 벗어나면 언제든 step (slew 로 수십 분 끌지 않음)
makestep 1 -1
leapsectz right/UTC
sourcedir /etc/chrony/sources.d
EOF
chronyd -p -f /etc/chrony/chrony.conf >/dev/null 2>&1 || die "chrony.conf failed to parse"

say "P3 single time source: VMware Tools timesync off (verified), chrony on"
if command -v vmware-toolbox-cmd >/dev/null; then
  vmware-toolbox-cmd timesync disable >/dev/null 2>&1 || true
  st=$(vmware-toolbox-cmd timesync status 2>/dev/null || true); echo "  tools timesync: ${st:-unknown}"   # exit code = state (1 when Disabled), so no || echo
  [ "$st" = Disabled ] || die "VMware Tools timesync still '${st:-unknown}' — disable it (or tools.syncTime=FALSE in the .vmx)"
fi
systemctl enable --now chrony >/dev/null; systemctl restart chrony; sleep 6
systemctl is-active chrony >/dev/null || { journalctl -u chrony --no-pager -n 20; die "chrony not active"; }

say "V1 tracking (Reference ID must be $UP, Leap status Normal) — 선택까지 1~2분 걸릴 수 있음(local stratum 10 이 먼저 잡힘)"
for i in $(seq 1 45); do chronyc -n tracking 2>/dev/null | grep -q "Reference ID.*($UP)" && break; sleep 4; done
chronyc -n tracking | grep -E 'Reference ID|Stratum|System time|Last offset|Leap status' | sed 's/^/  /' || true
chronyc -n tracking | grep -q "Reference ID.*($UP)" || { chronyc -n sources -v | tail -5; die "not synced to $UP (upstream answered in G0 but chrony did not select it — check rootdisp/leap above)"; }
chronyc -n sources | sed 's/^/  /' || true

say "V2 serving: udp/123 bound on 10.200.10.1 and answers a self-query"
ss -ulnp | grep -E '10\.10\.10\.1:123 ' | sed 's/^/  /' || die "chronyd is not listening on 10.200.10.1:123 (bindaddress/allow)"
python3 - <<'PY' || die "chrony does not answer on 10.200.10.1:123"
import socket, struct, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
try:
    s.sendto(b"\x1b" + 47 * b"\0", ("10.200.10.1", 123)); d, _ = s.recvfrom(48)
except socket.timeout: sys.exit(2)
w = struct.unpack("!12I", d); li = d[0] >> 6; st = d[1]; xmt = w[10] - 2208988800 + w[11] / 2**32
print("  10.200.10.1 answers: leap=%d stratum=%d offset=%+.3fs" % (li, st, xmt - time.time()))
sys.exit(0 if (0 < st < 16 and li != 3) else 1)
PY
echo; echo "== NTP_SERVER_DONE =="
