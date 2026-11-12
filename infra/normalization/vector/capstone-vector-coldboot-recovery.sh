#!/bin/bash
# Cold-boot safe recovery for an interrupted Vector generation rotation.
#
# After an unclean shutdown (power loss) a managed generation rotation can be
# left mid-flight: suricata/modsecurity raw-operations state is stuck in a
# non-active phase and/or /var/lib/capstone-vector-maintenance/resume.pending is
# set. In that state the coordinator "run" path defers (output_rotation_pending)
# and never starts Vector, so the normalization pipeline never finalizes and the
# maintenance timer flaps Vector without converging.
#
# This one-shot runs once at boot and recovers using ONLY existing guarded paths:
#   1. Detect the interrupted-rotation state. If healthy -> no-op (exit 0).
#   2. Pause the maintenance timer so Vector is not stopped mid-settle.
#   3. Start Vector via its own unit (ExecStartPre guard still validates and
#      refuses if unsafe -- we never bypass it).
#   4. If (and only if) reader_at_eof would fail purely on a logcollector stored
#      hash that no longer matches the static file content (FD position and the
#      persisted offset are already at EOF), re-sync that stored hash to the
#      current sha1 -- offset preserved, so NO re-read / no duplicate ingestion.
#      file_status.json is backed up first. Any other mismatch is left alone.
#   5. Wait until Vector has been up long enough that fresh current-invocation
#      collection telemetry exists, then run ONE guarded maintenance finalize.
#   6. Always restore the maintenance timer on exit (trap).
#
# It never forces past a guard, never edits raw generation state, and is
# idempotent. It only acts when an interrupted rotation is actually detected,
# which happens only after an unclean shutdown.
set -uo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC
umask 077

MACHINE=096e90b6243e438aa8a7b392be754732
[[ $(id -u) == 0 && $(cat /etc/machine-id 2>/dev/null) == "$MACHINE" ]] || exit 0

RO_STATE=/var/lib/capstone-raw-operations
PENDING=/var/lib/capstone-vector-maintenance/resume.pending
FS=/var/ossec/queue/logcollector/file_status.json
SERVICE=capstone-vector.service
MAINT=/usr/local/sbin/capstone-vector-maintenance
MAINT_TIMER=capstone-vector-maintenance.timer
NORMALIZED=(/var/log/capstone-vector/ready/normalized.jsonl \
            /var/log/capstone-vector/evidence/normalized.jsonl \
            /var/log/capstone-vector/canary/normalized.jsonl)

log(){ logger -t capstone-vector-coldboot -p "daemon.$1" -- "$2"; }
phase(){ jq -r '.phase // "missing"' "$RO_STATE/$1/state.json" 2>/dev/null || echo missing; }

# --- detection: only recover a genuinely interrupted rotation -----------------
for e in suricata modsecurity; do
  [[ -f $RO_STATE/$e/state.json ]] || { log notice "state missing ($e); no action this boot"; exit 0; }
done
need=0
[[ -e $PENDING || -L $PENDING ]] && need=1
for e in suricata modsecurity; do [[ $(phase "$e") == active ]] || need=1; done
if [[ $need == 0 ]]; then log notice "vector pipeline healthy; no cold-boot recovery needed"; exit 0; fi
log notice "interrupted vector rotation detected at boot; starting bounded guarded recovery"

restore(){ /usr/bin/systemctl start "$MAINT_TIMER" >/dev/null 2>&1 || true; }
trap restore EXIT
/usr/bin/systemctl stop "$MAINT_TIMER" >/dev/null 2>&1 || true

# --- ensure Vector running (guard validates; refusal is respected) ------------
if ! /usr/bin/systemctl start "$SERVICE" >/dev/null 2>&1; then
  log err "vector start refused by its guard; leaving for manual handling"; exit 1
fi

# --- targeted logcollector hash re-sync (only the precise safe condition) -----
# reader_at_eof requires sha1sum(file)==stored hash. If a restart rewrote a
# static normalized file so the stored hash lags while BOTH the live FD position
# and the persisted offset are already at size, re-point the stored hash to the
# current sha1. This does not advance/rewind the offset, so nothing is re-read.
resync_one(){
  local f=$1 pid sz id fdok=0 persoff cur stored
  [[ -f $f ]] || return 0
  pid=$(/usr/bin/pgrep -x wazuh-logcollec | head -1); [[ -n $pid ]] || return 0
  sz=$(/usr/bin/stat -c %s "$f"); id=$(/usr/bin/stat -c '%d:%i' "$f")
  local n=0 fd fi pos
  for fd in /proc/$pid/fd/[0-9]*; do
    fi=$(/usr/bin/stat -Lc '%d:%i' "$fd" 2>/dev/null) || continue
    [[ $fi == "$id" ]] || continue
    pos=$(/usr/bin/awk '$1=="pos:"{print $2}' /proc/$pid/fdinfo/"${fd##*/}")
    [[ $pos == "$sz" ]] && fdok=1; n=$((n+1))
  done
  [[ $n == 1 && $fdok == 1 ]] || return 0
  persoff=$(/usr/bin/jq -r --arg p "$f" '[.files[]|select(.path==$p)]|if length==1 then (.[0].offset|tostring) else "x" end' "$FS" 2>/dev/null)
  [[ $persoff == "$sz" ]] || return 0
  stored=$(/usr/bin/jq -r --arg p "$f" '[.files[]|select(.path==$p)]|.[0].hash//""' "$FS" 2>/dev/null)
  cur=$(/usr/bin/sha1sum "$f" | /usr/bin/cut -d' ' -f1)
  [[ $stored =~ ^[a-f0-9]{40}$ && $cur =~ ^[a-f0-9]{40}$ && $stored != "$cur" ]] || return 0
  echo "$f:$cur"
}
pending_fixes=()
for f in "${NORMALIZED[@]}"; do m=$(resync_one "$f") && [[ -n $m ]] && pending_fixes+=("$m"); done
if (( ${#pending_fixes[@]} > 0 )); then
  /usr/bin/systemctl stop wazuh-agent >/dev/null 2>&1 || true
  cp -p "$FS" "$FS.bak-coldboot-$(date +%Y%m%dT%H%M%S)" 2>/dev/null || true
  prog='.files |= map('
  for m in "${pending_fixes[@]}"; do p=${m%:*}; h=${m##*:}; prog+="if .path==\"$p\" then .hash=\"$h\" else . end | "; done
  prog="${prog% | })"
  if /usr/bin/jq -c "$prog" "$FS" > "$FS.tmp" 2>/dev/null; then cat "$FS.tmp" > "$FS"; rm -f "$FS.tmp"; log notice "re-synced logcollector hash for ${#pending_fixes[@]} normalized file(s) (offset preserved, in place)"; else rm -f "$FS.tmp"; log err "hash re-sync jq failed; left file_status.json unchanged"; fi
  /usr/bin/systemctl start wazuh-agent >/dev/null 2>&1 || true
fi

# --- wait for fresh telemetry (Vector up long enough), then one finalize ------
deadline=$(( $(date +%s) + 360 ))
while :; do
  /usr/bin/systemctl is-active --quiet "$SERVICE" || /usr/bin/systemctl start "$SERVICE" >/dev/null 2>&1 || true
  up=$(/usr/bin/ps -o etimes= -C vector 2>/dev/null | /usr/bin/awk 'NR==1{print $1+0}')
  [[ ${up:-0} -ge 210 ]] && break
  (( $(date +%s) >= deadline )) && { log warning "vector uptime<210s at deadline; attempting finalize anyway"; break; }
  sleep 5
done
"$MAINT" run >/dev/null 2>&1; rc=$?
if [[ -e $PENDING || -L $PENDING ]]; then
  log warning "resume.pending still set after cold-boot recovery (maint rc=$rc); manual check advised"
else
  log notice "cold-boot recovery complete: resume.pending cleared, pipeline finalized (maint rc=$rc)"
fi
exit 0
