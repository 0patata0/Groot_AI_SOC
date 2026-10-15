#!/bin/bash
# Native Linux /proc fixtures only: no Docker, journal, service or production file.
set -euo pipefail
umask 077
PATH=/usr/bin:/bin
export PATH LC_ALL=C
[[ $# == 0 && $EUID == 0 && $(uname -s) == Linux ]] || exit 64
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$directory/writer-gates.sh"
stage=$(mktemp -d /var/tmp/capstone-writer-gates-fixture.XXXXXX)
pids=() ticks=()
cleanup() {
    local i actual
    for i in "${!pids[@]}"; do
        actual=$(awk '{sub(/^.*\) /, ""); print $20}' "/proc/${pids[$i]}/stat" 2>/dev/null || true)
        if [[ $actual == "${ticks[$i]}" ]]; then kill -TERM "${pids[$i]}" 2>/dev/null || true; fi
        wait "${pids[$i]}" 2>/dev/null || true
        actual=$(awk '{sub(/^.*\) /, ""); print $20}' "/proc/${pids[$i]}/stat" 2>/dev/null || true)
        [[ $actual != "${ticks[$i]}" ]] || return 1
    done
    rm -rf -- "$stage"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
: > "$stage/target"
dev=$(stat -c %d "$stage/target") ino=$(stat -c %i "$stage/target")
for mode in read write; do
    /bin/bash -c 'if [[ $1 == read ]]; then exec 7<"$2"; else exec 7<>"$2"; fi; exec /bin/sleep 90' \
      fixture "$mode" "$stage/target" > /dev/null 2>&1 &
    pid=$!; pids+=("$pid")
    tick=$(awk '{sub(/^.*\) /, ""); print $20}' "/proc/$pid/stat")
    ticks+=("$tick")
    for attempt in $(seq 1 100); do
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
        [[ -e /proc/$pid/fd/7 && ( $exe == /usr/bin/sleep || $exe == /bin/sleep ) ]] && break
        sleep 0.01
    done
    [[ -e /proc/$pid/fd/7 && ( $exe == /usr/bin/sleep || $exe == /bin/sleep ) ]]
done
readonly_pid=${pids[0]} writable_pid=${pids[1]}
native=$(_wg_proc_identity "$writable_pid")
jq -e '.exe=="/usr/bin/sleep" or .exe=="/bin/sleep"' <<< "$native" >/dev/null
passed=1
# Change only the executable assertion of a private process. FD, ticks, UID,
# namespaces and descriptor metadata still come from the installed Linux kernel.
eval "$(declare -f _wg_proc_identity | sed '1s/_wg_proc_identity/_fixture_native_proc_identity/')"
_wg_proc_identity() {
    local record
    record=$(_fixture_native_proc_identity "$1") || return 1
    jq -c '.exe="/usr/sbin/nginx"' <<< "$record"
}
fixture_cid=$(printf 'a%.0s' {1..64})
fixture_image=sha256:$(printf 'b%.0s' {1..64})
_wg_container() {
    jq -nc --arg cid "$fixture_cid" --arg image "$fixture_image" --argjson pid "$fixture_pid" \
      '{cid:$cid,image:$image,pid:$pid,running:true,started_at:"synthetic",restart_count:0}'
}
_wg_members() { jq -nc --argjson pid "$fixture_pid" '[$pid]'; }
set_expected() {
    fixture_pid=$1
    expected=$(_wg_init_identity waf "$(_wg_container waf)")
}
invoke() {
    local expected_rc=$1 actual_rc=0; shift
    result=$(_wg_gate "$@") || actual_rc=$?
    [[ $actual_rc == "$expected_rc" ]] || { printf 'failed_case=%s\n' "$case_name"; exit 1; }
}
case_name=writable_exact; set_expected "$writable_pid"; invoke 10 waf "$expected" "$dev" "$ino"
jq -e '.status=="open" and .writable_fd_count==1 and .matching_fd_count==1 and .membership_stable and (.processes|length)==1' <<< "$result" >/dev/null
passed=$((passed+1))
case_name=read_only_exact; set_expected "$readonly_pid"; invoke 0 waf "$expected" "$dev" "$ino"
jq -e '.status=="closed" and .writable_fd_count==0 and .matching_fd_count==1' <<< "$result" >/dev/null
passed=$((passed+1))
case_name=unmatched_large_inode; invoke 0 waf "$expected" "$dev" 18446744073709551615
jq -e '.status=="closed" and .matching_fd_count==0 and .target.inode=="18446744073709551615"' <<< "$result" >/dev/null
passed=$((passed+1))
for field in cid start_ticks uid gid mount_ns pid_ns pid; do
    case_name="wrong_$field"
    case $field in
      cid) changed=$(jq '.cid=("c"*64)' <<< "$expected") ;;
      start_ticks) changed=$(jq '.start_ticks="1"' <<< "$expected") ;;
      uid|gid|pid) changed=$(jq --arg key "$field" '.[$key]+=1' <<< "$expected") ;;
      mount_ns) changed=$(jq '.mount_ns="mnt:[1]"' <<< "$expected") ;;
      pid_ns) changed=$(jq '.pid_ns="pid:[1]"' <<< "$expected") ;;
    esac
    invoke 1 waf "$changed" "$dev" "$ino"
    [[ -z $result ]]; passed=$((passed+1))
done
for bad in invalid_source multi_json negative_inode; do
    case_name=$bad
    case $bad in
      invalid_source) invoke 1 other "$expected" "$dev" "$ino" ;;
      multi_json) invoke 1 waf "$expected $expected" "$dev" "$ino" ;;
      negative_inode) invoke 1 waf "$expected" "$dev" -1 ;;
    esac
    [[ -z $result ]]; passed=$((passed+1))
done
(
    case_name=inaccessible_fd
    _wg_fd_meta() { return 1; }
    invoke 1 waf "$expected" "$dev" "$ino"; [[ -z $result ]]
)
passed=$((passed+1))
(
    case_name=membership_changed
    : > "$stage/membership_calls"
    _wg_members() {
        printf '.\n' >> "$stage/membership_calls"
        if [[ $(wc -l < "$stage/membership_calls") == 1 ]]; then
            jq -nc --argjson pid "$fixture_pid" '[$pid]'
        else jq -nc --argjson pid "$fixture_pid" '[$pid,$pid+1]'; fi
    }
    invoke 1 waf "$expected" "$dev" "$ino"; [[ -z $result ]]
)
passed=$((passed+1))
(
    case_name=process_start_changed
    : > "$stage/process_calls"
    _wg_proc_identity() {
        printf '.\n' >> "$stage/process_calls"
        if [[ $(wc -l < "$stage/process_calls") -lt 3 ]]; then
            _fixture_native_proc_identity "$1" | jq -c '.exe="/usr/sbin/nginx"'
        else _fixture_native_proc_identity "$1" | jq -c '.exe="/usr/sbin/nginx"|.start_ticks="1"'; fi
    }
    invoke 1 waf "$expected" "$dev" "$ino"; [[ -z $result ]]
)
passed=$((passed+1))
(
    case_name=container_restart_changed
    : > "$stage/container_calls"
    _wg_container() {
        printf '.\n' >> "$stage/container_calls"
        local count; count=$(wc -l < "$stage/container_calls")
        jq -nc --arg cid "$fixture_cid" --arg image "$fixture_image" --argjson pid "$fixture_pid" --argjson count "$count" \
          '{cid:$cid,image:$image,pid:$pid,running:true,started_at:"synthetic",restart_count:($count-1)}'
    }
    invoke 1 waf "$expected" "$dev" "$ino"; [[ -z $result ]]
)
passed=$((passed+1))
(
    case_name=fd_access_mode_changed
    : > "$stage/fd_calls"
    _wg_fd_numbers() { printf '[7]\n'; }
    _wg_fd_meta() {
        printf '.\n' >> "$stage/fd_calls"
        if [[ $(wc -l < "$stage/fd_calls") == 1 ]]; then printf '%s:%s:0\n' "$dev" "$ino"
        else printf '%s:%s:2\n' "$dev" "$ino"; fi
    }
    invoke 1 waf "$expected" "$dev" "$ino"; [[ -z $result ]]
)
passed=$((passed+1))
(
    case_name=fd_number_set_changed
    : > "$stage/fd_number_calls"
    _wg_fd_numbers() {
        printf '.\n' >> "$stage/fd_number_calls"
        if [[ $(wc -l < "$stage/fd_number_calls") == 1 ]]; then printf '[7]\n'; else printf '[]\n'; fi
    }
    invoke 1 waf "$expected" "$dev" "$ino"; [[ -z $result ]]
)
passed=$((passed+1))
cleanup
trap - EXIT
jq -nc --argjson passed "$passed" '{suite:"native_writer_gates_private_proc",passed:$passed,failed:0,
  actual_linux_proc_fd_checks:true,container_metadata_synthetic:true,docker_called:false,
  public_A_wrapper_executed:false,services_changed:false,private_processes_reaped:true,fixture_removed:true}'
