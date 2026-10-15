#!/bin/bash
# Operator-run isolated experiment, NOT an operating rotator. Linux A only.
# All inputs are synthetic offline PCAPs. No production daemon receives signals.
set -euo pipefail
umask 077
PATH=/usr/local/bin:/usr/bin:/bin
export PATH LC_ALL=C
[[ $# == 0 && $EUID == 0 && $(uname -s) == Linux ]] || exit 64
[[ $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 65
HERE=$(cd -- "$(dirname -- "$0")" && pwd -P)
for tool in docker vector jq unshare mount stat sha256sum sha1sum timeout sync readlink cp ln mv; do command -v "$tool" >/dev/null; done
stage= cstage= host_cstage= vp= wp= np= writer= exec_pid=
writer_start= vp_start= wp_start= np_start= phase=initializing
completed=false cleanup_ok=true
proc_start() { [[ -r /proc/$1/stat ]] && awk '{print $22}' /proc/"$1"/stat 2>/dev/null; }
proc_state() { awk '{print $3}' /proc/"$1"/stat 2>/dev/null || true; }
same_process() { [[ -n $1 && -n $2 && $(proc_start "$1") == "$2" ]]; }
signal_child() {
    local pid=$1 tick=$2 sig=$3
    same_process "$pid" "$tick" || return 1
    # Vector/Wazuh are direct children; their shell job is not reaped until wait.
    kill -"$sig" "$pid"
}
stop_child() {
    local pid=$1 tick=$2
    [[ -n $pid ]] || return 0
    if same_process "$pid" "$tick"; then
        kill -CONT "$pid" 2>/dev/null || true
        kill -TERM "$pid" 2>/dev/null || true
        for _ in {1..100}; do
            [[ ! -r /proc/$pid/stat ]] && break
            [[ $(proc_state "$pid") == Z ]] && break
            sleep 0.1
        done
        if same_process "$pid" "$tick" && [[ $(proc_state "$pid") != Z ]]; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
    wait "$pid" 2>/dev/null || true
    ! same_process "$pid" "$tick"
}
writer_identity() {
    same_process "$writer" "$writer_start" || return 1
    [[ $writer != "$init" && $(readlink /proc/"$writer"/ns/pid) == "$container_pidns" ]] || return 1
    tr '\0' '\n' < /proc/"$writer"/cmdline | grep -Fx -- "$cstage/suricata.yaml" >/dev/null
}
signal_writer() { writer_identity && kill -"$1" "$writer"; }
cleanup() {
    local saved=$? diagnostics='[]' log
    trap - EXIT HUP INT TERM
    stop_child "${np:-}" "${np_start:-}" || cleanup_ok=false
    stop_child "${wp:-}" "${wp_start:-}" || cleanup_ok=false
    stop_child "${vp:-}" "${vp_start:-}" || cleanup_ok=false
    if [[ -n ${writer:-} ]]; then
        if writer_identity; then
            signal_writer TERM || cleanup_ok=false
            for _ in {1..100}; do
                same_process "$writer" "$writer_start" || break
                [[ $(proc_state "$writer") == Z ]] && break
                sleep 0.1
            done
            if writer_identity && [[ $(proc_state "$writer") != Z ]]; then signal_writer KILL || cleanup_ok=false; fi
        fi
        [[ -z $exec_pid ]] || wait "$exec_pid" 2>/dev/null || true
        if same_process "$writer" "$writer_start" && [[ $(proc_state "$writer") != Z ]]; then cleanup_ok=false; fi
    elif [[ -n ${exec_pid:-} ]]; then
        # A startup failure before the writer PID is known cannot safely prove
        # container cleanup. Leave its private directory for operator recovery.
        cleanup_ok=false
    fi
    if [[ $completed != true && -n ${stage:-} ]]; then
        # These logs belong only to fixed synthetic test configurations. Never
        # read operating logs. Bound diagnostics before deleting the fixture.
        diagnostics=$(
            for log in "$stage/suricata-validate.log" "$stage/vector-validate.log" "$stage/suricata.stdout" "$stage/suricata.stderr" "$stage/vector.stderr" "$stage/wazuh/stderr" "$stage/naive-wazuh/stderr"; do
                [[ ! -f $log ]] || tail -c 2048 "$log"
            done | jq -Rsc 'split("\n") | map(select(length>0)) | .[-20:]'
        )
    fi
    if [[ $cleanup_ok == true ]]; then
        [[ -z ${host_cstage:-} ]] || rm -rf -- "$host_cstage"
        [[ -z ${stage:-} ]] || rm -rf -- "$stage"
    fi
    if [[ $completed != true || $cleanup_ok != true ]]; then
        jq -nc --arg phase "$phase" --argjson cleanup "$cleanup_ok" --arg stage "${stage:-}" --arg container_stage "${cstage:-}" --argjson diagnostics "$diagnostics" \
            '{status:"failed",phase:$phase,cleanup_verified:$cleanup,host_test_path:$stage,container_test_path:$container_stage,synthetic_test_diagnostics:$diagnostics,operating_rotator_deployed:false}'
        exit 1
    fi
    printf '%s\n' "$result"
    exit "$saved"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
stage=$(mktemp -d /var/tmp/capstone-raw-rotation.XXXXXX)
cid=$(docker inspect --format '{{.Id}}' suricata)
[[ $cid =~ ^[0-9a-f]{64}$ ]]
init=$(docker inspect --format '{{.State.Pid}}' "$cid")
[[ $init =~ ^[0-9]+$ && $init -gt 1 ]]
container_pidns=$(readlink /proc/"$init"/ns/pid)
container_init_start=$(proc_start "$init")
host_mountns=$(readlink /proc/self/ns/mnt)
operating_root=$(stat -Lc '%d:%i' /var/ossec)
operating_queue=$(stat -Lc '%d:%i' /var/ossec/queue/sockets/queue)
operating_vector=$(systemctl show capstone-vector.service --property=MainPID --value)
operating_wazuh=$(cat /var/ossec/var/run/wazuh-logcollector-*.pid)
[[ $operating_vector =~ ^[0-9]+$ && $operating_wazuh =~ ^[0-9]+$ ]]
operating_vector_start=$(proc_start "$operating_vector")
operating_wazuh_start=$(proc_start "$operating_wazuh")
# mktemp inside the existing container only allocates synthetic private files.
cstage=$(docker exec --user 0 "$cid" mktemp -d /tmp/capstone-raw-rotation.XXXXXX)
[[ $cstage =~ ^/tmp/capstone-raw-rotation\.[A-Za-z0-9]{6}$ ]]
host_cstage=/proc/$init/root$cstage
mkdir "$host_cstage/pcaps" "$host_cstage/logs" "$host_cstage/reader" "$stage/data" "$stage/observed"
active=$host_cstage/logs/eve.json
alias=$host_cstage/reader/eve.json
: > "$active"
ln -- "$active" "$alias"
# Alias lives in the same container temporary filesystem as the writer file.
[[ $(stat -Lc '%d:%i' "$active") == $(stat -Lc '%d:%i' "$alias") ]]
cat > "$host_cstage/suricata.yaml" <<EOF
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[198.18.0.0/15]"
    EXTERNAL_NET: "any"
default-log-dir: "$cstage/logs"
stats:
  enabled: no
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      threaded: false
      types: [alert]
logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes
unix-command:
  enabled: no
pcap-file:
  checksum-checks: no
  delay: 1
  poll-interval: 1
  delete-when-done: false
EOF
printf '%s\n' 'alert udp 198.18.0.1 any -> 198.18.0.2 9100 (msg:"CAPSTONE OFFLINE ROTATION FIXTURE"; content:"TEST"; sid:9900991; rev:1;)' > "$host_cstage/test.rules"
phase=validate_private_writer
docker exec --user 0 "$cid" /usr/bin/suricata -T -c "$cstage/suricata.yaml" -S "$cstage/test.rules" \
    -l "$cstage/logs" > "$stage/suricata-validate.log" 2>&1
prefix=$stage/wazuh
naive_prefix=$stage/naive-wazuh
bash "$HERE/wazuh-isolated.sh" prepare "$prefix" "$alias"
bash "$HERE/wazuh-isolated.sh" prepare "$naive_prefix" "$active"
cat > "$stage/vector.toml" <<EOF
data_dir = "$stage/data"
[sources.good]
type = "file"
include = ["$alias"]
read_from = "beginning"
fingerprint.strategy = "device_and_inode"
max_line_bytes = 1048576
max_read_bytes = 262144
[sources.naive]
type = "file"
include = ["$active"]
read_from = "beginning"
fingerprint.strategy = "device_and_inode"
max_line_bytes = 1048576
max_read_bytes = 262144
[sources.wazuh_queue]
type = "socket"
mode = "unix_datagram"
path = "$prefix/queue/sockets/queue"
socket_file_mode = 384
[sources.naive_wazuh_queue]
type = "socket"
mode = "unix_datagram"
path = "$naive_prefix/queue/sockets/queue"
socket_file_mode = 384
[transforms.good_marker]
type = "remap"
inputs = ["good"]
source = 'event = parse_json!(.message); . = {"lane":"vector_good", "port":to_int!(event.src_port)}'
[transforms.naive_marker]
type = "remap"
inputs = ["naive"]
source = 'event = parse_json!(.message); . = {"lane":"vector_naive", "port":to_int!(event.src_port)}'
[transforms.wazuh_marker]
type = "remap"
inputs = ["wazuh_queue", "naive_wazuh_queue"]
drop_on_error = true
drop_on_abort = true
source = '''
parts = parse_regex!(string!(.message), r'^[^:]+:(?P<path>[^:]+):(?P<body>.*)$')
lane = if parts.path == "$alias" { "wazuh_good" } else if parts.path == "$active" { "wazuh_naive" } else { abort }
# Native SendMSG sends the terminating NUL; it is transport framing, not JSON.
event = parse_json!(replace(string!(parts.body), r'\x00$', ""))
. = {"lane":lane, "port":to_int!(event.src_port)}
'''
[sinks.markers]
type = "file"
inputs = ["good_marker", "naive_marker", "wazuh_marker"]
path = "$stage/observed/{{ lane }}.jsonl"
encoding.codec = "json"
EOF
vector validate --no-environment "$stage/vector.toml" > "$stage/vector-validate.log" 2>&1
start_vector() {
    VECTOR_LOG=warn vector --config "$stage/vector.toml" > "$stage/vector.stdout" 2> "$stage/vector.stderr" &
    vp=$!; vp_start=$(proc_start "$vp")
    for _ in {1..100}; do
        if [[ -S $prefix/queue/sockets/queue && -S $naive_prefix/queue/sockets/queue ]]; then return 0; fi
        same_process "$vp" "$vp_start"; sleep 0.1
    done
    return 1
}
start_wazuh() {
    local pfx pid tick
    [[ $1 == good || $1 == naive ]]
    pfx=$prefix
    [[ $1 == good ]] || pfx=$naive_prefix
    bash "$HERE/wazuh-isolated.sh" launch "$pfx" > "$pfx/stdout" 2> "$pfx/stderr" &
    pid=$!; tick=$(proc_start "$pid")
    if [[ $1 == good ]]; then wp=$pid; wp_start=$tick; else np=$pid; np_start=$tick; fi
    for _ in {1..100}; do
        if [[ -e $pfx/var/run/wazuh-logcollector-$pid.pid ]]; then break; fi
        same_process "$pid" "$tick"; sleep 0.1
    done
    [[ $(cat "$pfx/var/run/wazuh-logcollector-$pid.pid") == "$pid" ]]
    [[ $(readlink /proc/"$pid"/exe) == "$pfx/bin/wazuh-logcollector" ]]
    [[ $(readlink /proc/"$pid"/cwd) == "$pfx" ]]
    [[ $(readlink /proc/"$pid"/ns/mnt) != "$host_mountns" ]]
    [[ $(stat -Lc '%d:%i' /proc/"$pid"/root/var/ossec) == $(stat -Lc '%d:%i' "$pfx") ]]
    [[ $(stat -Lc '%d:%i' /var/ossec) == "$operating_root" ]]
    [[ $(stat -Lc '%d:%i' /var/ossec/queue/sockets/queue) == "$operating_queue" ]]
}
fd_count() {
    local pid=$1 path=$2 mode=$3 devino fd info flags access count=0
    devino=$(stat -Lc '%d:%i' "$path")
    for fd in /proc/"$pid"/fd/*; do
        [[ $(stat -Lc '%d:%i' "$fd" 2>/dev/null || true) == "$devino" ]] || continue
        flags=$(awk '$1=="flags:" {print $2}' /proc/"$pid"/fdinfo/"${fd##*/}")
        [[ $flags =~ ^[0-7]+$ ]] || return 1
        access=$((8#$flags & 3))
        if [[ $mode == write && $access != 0 || $mode == read && $access == 0 ]]; then ((count+=1)); fi
    done
    printf '%s\n' "$count"
}
wait_fd() {
    local path=$1 pid=${2:-$wp} tick
    tick=$(proc_start "$pid")
    for _ in {1..1000}; do
        same_process "$pid" "$tick"
        [[ $(fd_count "$pid" "$path" read) == 1 ]] && return 0
        sleep 0.1
    done
    return 1
}
ports() { if [[ -f $stage/observed/$1.jsonl ]]; then jq -sc '[.[].port] | sort' "$stage/observed/$1.jsonl"; else printf '[]\n'; fi; }
wait_port() {
    local lane=$1 port=$2
    for _ in {1..1000}; do
        if [[ -f $stage/observed/$lane.jsonl ]] && jq -se --argjson port "$port" 'any(.[]; .port==$port)' "$stage/observed/$lane.jsonl" >/dev/null; then return 0; fi
        same_process "$vp" "$vp_start"; same_process "$wp" "$wp_start"
        sleep 0.1
    done
    return 1
}
wait_eof() {
    local size sum state
    size=$(stat -Lc '%s' "$alias"); sum=$(sha1sum "$alias"); sum=${sum%% *}
    for _ in {1..1000}; do
        if state=$(jq -er --arg path "$alias" '[.files[] | select(.path==$path)] | if length==1 then .[0] | [.offset,.hash] | @tsv else error("ambiguous") end' "$prefix/queue/logcollector/file_status.json" 2>/dev/null); then
            [[ $state == "$size"$'\t'"$sum" && $(fd_count "$wp" "$alias" read) == 1 ]] && return 0
        fi
        same_process "$wp" "$wp_start"; sleep 0.1
    done
    return 1
}
emit_pcap() {
    local port=$1 file
    local -a files=("$active")
    bash "$HERE/make-pcap.sh" "$port" "$host_cstage/input-$port.pcap"
    # Atomic discovery only after the complete PCAP has been written.
    mv -- "$host_cstage/input-$port.pcap" "$host_cstage/pcaps/$port.pcap"
    for file in "$host_cstage/logs"/archive-*.json; do [[ ! -f $file ]] || files+=("$file"); done
    for _ in {1..200}; do
        if jq -se --argjson port "$port" 'any(.[]; .src_port==$port)' "${files[@]}" 2>/dev/null >/dev/null; then return 0; fi
        writer_identity; sleep 0.1
    done
    return 1
}
writer_reopened() {
    local old=$1
    for _ in {1..100}; do
        writer_identity
        if [[ $(fd_count "$writer" "$old" write) == 0 && $(fd_count "$writer" "$active" write) -ge 1 ]]; then return 0; fi
        sleep 0.1
    done
    return 1
}
publish() {
    local next=$1 old=$2 last_port=$3
    [[ $(stat -Lc '%d:%i' "$alias") == $(stat -Lc '%d:%i' "$old") ]]
    [[ $(fd_count "$writer" "$old" write) == 0 ]]
    wait_port vector_good "$last_port"
    wait_port wazuh_good "$last_port"
    wait_eof
    [[ $(fd_count "$writer" "$old" write) == 0 ]]
    # Preserve old generation. Publish one adjacent retained generation only.
    ln -- "$next" "$host_cstage/reader/next"
    mv -T -- "$host_cstage/reader/next" "$alias"
    sync -f "$host_cstage/reader"
    wait_fd "$alias"
}
phase=start_private_readers
start_vector
start_wazuh good
start_wazuh naive
wait_fd "$alias"
wait_fd "$active" "$np"
phase=start_offline_writer
docker exec --user 0 "$cid" /usr/bin/suricata -c "$cstage/suricata.yaml" -S "$cstage/test.rules" \
    -l "$cstage/logs" -r "$cstage/pcaps" --pcap-file-continuous --runmode single -k none \
    --pidfile "$cstage/test.pid" > "$stage/suricata.stdout" 2> "$stage/suricata.stderr" &
exec_pid=$!
for _ in {1..100}; do
    [[ ! -s $host_cstage/test.pid ]] || break
    kill -0 "$exec_pid"; sleep 0.1
done
namespace_writer=$(cat "$host_cstage/test.pid")
[[ $namespace_writer =~ ^[0-9]+$ && $namespace_writer -gt 1 ]]
matches=()
while read -r candidate; do
    [[ $candidate =~ ^[0-9]+$ && $candidate != "$init" ]] || continue
    [[ $(awk '/^NSpid:/ {print $NF}' /proc/"$candidate"/status) == "$namespace_writer" ]] || continue
    [[ $(readlink /proc/"$candidate"/ns/pid) == "$container_pidns" ]] || continue
    matches+=("$candidate")
done < <(docker top "$cid" -eo pid,args | awk -v path="$cstage/suricata.yaml" '{for(i=2;i<=NF;i++) if($i==path) print $1}')
[[ ${#matches[@]} == 1 ]]
writer=${matches[0]}; writer_start=$(proc_start "$writer")
writer_identity
phase=initial_record
emit_pcap 41001
wait_port vector_good 41001
wait_port wazuh_good 41001
wait_port wazuh_naive 41001
phase=naive_rename_then_late_old_write
mv -- "$active" "$host_cstage/logs/archive-0.json"
: > "$active"
# Let the naive reader open the new empty inode BEFORE the old writer's late row.
wait_fd "$active" "$np"
[[ $(fd_count "$writer" "$host_cstage/logs/archive-0.json" write) -ge 1 ]]
emit_pcap 41002
wait_port vector_good 41002
wait_port wazuh_good 41002
phase=first_writer_reopen
signal_writer HUP
emit_pcap 41003
writer_reopened "$host_cstage/logs/archive-0.json"
wait_port wazuh_naive 41003
naive_missed_late=$(ports wazuh_naive | jq 'index(41002)==null')
[[ $naive_missed_late == true ]]
phase=first_gated_publication
publish "$active" "$host_cstage/logs/archive-0.json" 41002
wait_port vector_good 41003
wait_port wazuh_good 41003
phase=two_rotations_readers_paused
signal_child "$wp" "$wp_start" STOP
signal_child "$vp" "$vp_start" STOP
mv -- "$active" "$host_cstage/logs/archive-1.json"
: > "$active"
signal_writer HUP
emit_pcap 41004
writer_reopened "$host_cstage/logs/archive-1.json"
mv -- "$active" "$host_cstage/logs/archive-2.json"
: > "$active"
signal_writer HUP
emit_pcap 41005
writer_reopened "$host_cstage/logs/archive-2.json"
signal_child "$vp" "$vp_start" CONT
signal_child "$wp" "$wp_start" CONT
phase=ordered_generation_catchup
publish "$host_cstage/logs/archive-2.json" "$host_cstage/logs/archive-1.json" 41003
wait_port vector_good 41004
wait_port wazuh_good 41004
publish "$active" "$host_cstage/logs/archive-2.json" 41004
wait_port vector_good 41005
wait_port wazuh_good 41005
phase=graceful_reader_restart
wait_eof
stop_child "$np" "$np_start"; np=; np_start=
stop_child "$wp" "$wp_start"; wp=; wp_start=
stop_child "$vp" "$vp_start"; vp=; vp_start=
start_vector
start_wazuh good
start_wazuh naive
wait_fd "$alias"
emit_pcap 41006
wait_port vector_good 41006
wait_port wazuh_good 41006
wait_eof
phase=final_exact_marker_comparison
expected='[41001,41002,41003,41004,41005,41006]'
vector_ports=$(ports vector_good)
wazuh_ports=$(ports wazuh_good)
[[ $vector_ports == "$expected" && $wazuh_ports == "$expected" ]]
[[ $(cat "$host_cstage/logs"/archive-*.json "$active" | jq -sc '[.[].src_port]|sort') == "$expected" ]]
[[ $(stat -Lc '%d:%i' /var/ossec) == "$operating_root" ]]
[[ $(stat -Lc '%d:%i' /var/ossec/queue/sockets/queue) == "$operating_queue" ]]
same_process "$operating_vector" "$operating_vector_start"
same_process "$operating_wazuh" "$operating_wazuh_start"
[[ $(docker inspect --format '{{.State.Pid}}' "$cid") == "$init" ]]
same_process "$init" "$container_init_start"
source_hashes=$(sha256sum "$host_cstage/logs"/archive-*.json | awk '{print $1}' | jq -Rsc 'split("\n")|map(select(length>0))')
result=$(jq -nc --argjson good_vector "$vector_ports" --argjson good_wazuh "$wazuh_ports" \
    --argjson naive "$(ports wazuh_naive)" --argjson naive_vector "$(ports vector_naive)" \
    --arg cid "$cid" --argjson writer "$writer" --arg tick "$writer_start" --argjson hashes "$source_hashes" \
    '{status:"passed",kind:"native_raw_rotation_isolated",synthetic_only:true,offline_packets_only:true,container_id:$cid,test_writer_host_pid:$writer,test_writer_start_ticks:$tick,gated_vector_ports:$good_vector,gated_wazuh_queue_ports:$good_wazuh,naive_wazuh_queue_ports:$naive,naive_vector_ports:$naive_vector,closed_generation_sha256:$hashes,late_old_write_missing_from_naive_wazuh:true,closed_writer_fd_verified:true,logical_eof_and_sha_verified:true,two_pending_generations_published_in_order:true,graceful_reader_restart_verified:true,forced_crash_or_power_loss_tested:false,operating_pids_unchanged:true,operating_wazuh_root_and_queue_unchanged:true,operating_rotator_deployed:false,manager_or_indexer_ack:false,cleanup_verified:true}')
completed=true
