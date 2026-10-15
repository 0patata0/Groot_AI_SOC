#!/bin/bash
# Root/Linux synthetic files and mocked service/gate boundaries only.
# This does not start/stop any service/container or read operational raw data.
set -euo pipefail
export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC
umask 077
[[ $# == 0 && $EUID == 0 && $OSTYPE == linux* ]] || exit 64
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$here/coordinator.sh"
stage=$(mktemp -d /var/tmp/capstone-raw-coordinator-test.XXXXXXXX)
cleanup() {
    [[ $stage =~ ^/var/tmp/capstone-raw-coordinator-test\.[A-Za-z0-9]{8}$ &&
       -d $stage && ! -L $stage && $(stat -c %u:%g:%a "$stage") == 0:0:700 ]] || return 1
    rm -rf -- "$stage"
}
trap cleanup EXIT
passed=0
run_case() {
    local name=$1; shift
    if ( "$@" ) > "$stage/stdout" 2> "$stage/stderr"; then passed=$((passed+1))
    else printf '{"status":"failed","case":"%s","passed":%s}\n' "$name" "$passed"; exit 1; fi
}

# The dispatcher is the actual production function. Only mutation and native
# gates are replaced. Persist phase in a private file to cross process/attempt
# boundaries and record each visited stage; do not pretend to test systemd.
dispatch_case() {
    local fail=$1 initial=${2:-active}
    printf '%s\n' "$initial" > "$stage/phase"
    : > "$stage/visits"
    ro_engine() { RO_ENGINE=$1; }
    ro_load() { RO_PHASE=$(cat "$stage/phase"); }
    ro_reconcile_link() { return 0; }
    ro_reconcile_stop_intent() { return 0; }
    ro_vector_status() { printf '{"ActiveState":"active"}\n'; }
    ro_validate() { return 0; }
    advance() {
        local name=$1 next=$2
        printf '%s\n' "$name" >> "$stage/visits"
        printf '%s\n' "$next" > "$stage/phase"
        RO_PHASE=$next
        if [[ $fail == "$name" ]]; then ro_refuse synthetic_after_commit; return 2; fi
    }
    ro_new_generation() { advance allocate switch_pending; }
    ro_switch_writer() { advance switch old_closed; }
    ro_drain() { advance drain readers_drained; }
    ro_prepare_publication() { advance prepare publish_pending; }
    ro_publish() { advance publish active; }
    local rc=0
    ro_operation run suricata || rc=$?
    if [[ $fail != none ]]; then [[ $rc == 2 ]] || return 1; else [[ $rc == 0 ]] || return 1; fi
    fail=none
    ro_operation resume suricata || return 1
    [[ $(cat "$stage/phase") == active ]] || return 1
    local expected
    case $initial in
      active) expected=$'allocate\nswitch\ndrain\nprepare\npublish' ;;
      switch_pending) expected=$'switch\ndrain\nprepare\npublish' ;;
      old_closed) expected=$'drain\nprepare\npublish' ;;
      readers_drained) expected=$'prepare\npublish' ;;
      publish_pending) expected=publish ;;
    esac
    [[ $(cat "$stage/visits") == "$expected" ]]
}
run_case dispatch_complete dispatch_case none
for step in allocate switch drain prepare publish; do run_case "resume_after_$step" dispatch_case "$step"; done
for phase in switch_pending old_closed readers_drained publish_pending; do run_case "resume_from_$phase" dispatch_case none "$phase"; done

not_due_case() {
    ro_engine() { RO_ENGINE=$1; }
    ro_load() { RO_PHASE=active; }
    ro_validate() { return 0; }
    ro_reconcile_link() { return 0; }
    ro_reconcile_stop_intent() { return 0; }
    ro_vector_status() { printf '{"ActiveState":"active"}\n'; }
    ro_new_generation() { return 10; }
    ro_switch_writer() { return 99; }
    ro_operation run suricata
}
run_case not_due_is_noop not_due_case

# Test the actual pending/new guard decision and its exact reason-based
# fallback. Captured SHA change must refuse even when all native gates pass.
guard_case() {
    local vector_mode=$1 wazuh_mode=$2 final_same=$3 expected_rc=$4
    RO_ENGINE=suricata RO_ALIAS_KIND=new RO_ALIAS=$stage/alias
    RO_CURRENT=$stage/old RO_NEXT=$stage/new RO_OLD_DEV=1 RO_OLD_INO=10 RO_NEW_DEV=1 RO_NEW_INO=11
    RO_CP=$stage/cp RO_WAZUH_CP=$stage/file_status.json
    RO_STATE='{"proof":{"old_closed":{"bytes":100},"readers_drained":{"wazuh_offset":100,"wazuh_sha1":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}'
    RO_STATE_SHA=$(printf 'b%.0s' {1..64})
    ro_load() { return 0; }
    ro_validate() { return 0; }
    ro_prefix_distinct() { return 0; }
    : > "$stage/gate-visits"
    cg_vector_current() {
        printf 'vector_current\n' >> "$stage/gate-visits"
        case $vector_mode in
          current) printf '{"verdict":"pass"}\n'; return 0 ;;
          missing) printf '{"verdict":"defer","reason":"vector_checkpoint_match_missing"}\n'; return 2 ;;
          malformed) printf '{"verdict":"defer","reason":"vector_checkpoint_invalid"}\n'; return 2 ;;
          duplicate) printf '{"verdict":"defer","reason":"vector_checkpoint_invalid"}\n'; return 2 ;;
          short) printf '{"verdict":"defer","reason":"offset_beyond_source"}\n'; return 2 ;;
        esac
    }
    cg_vector_eof() { printf 'vector_old_eof\n' >> "$stage/gate-visits"; [[ $vector_mode == missing ]]; }
    cg_wazuh_cold() {
        printf 'wazuh_%s\n' "$5" >> "$stage/gate-visits"
        if [[ $wazuh_mode == different ]]; then printf '{"verdict":"pass","reason":"different_prefix"}\n'; return 0; fi
        if [[ $5 == 10 ]]; then
            if [[ $wazuh_mode == same_old ]]; then printf '{"offset":100,"stored_sha1":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n'
            else printf '{"offset":50,"stored_sha1":"cccccccccccccccccccccccccccccccccccccccc"}\n'; fi
            return 2
        fi
        [[ $wazuh_mode == advanced ]] || return 2
        printf '{"verdict":"pass","reason":"existing_inode_resume"}\n'
    }
    raw_state_read_twice() {
        local value=$RO_STATE_SHA
        [[ $final_same == yes ]] || value=$(printf 'd%.0s' {1..64})
        jq -nc --arg sha "$value" '{sha256:$sha}'
    }
    local rc=0
    ro_guard_one vector || rc=$?
    [[ $rc == "$expected_rc" ]] || return 1
    if [[ $vector_mode == current ]]; then ! grep -q '^vector_old_eof$' "$stage/gate-visits" || return 1; fi
    if [[ $vector_mode == malformed || $vector_mode == duplicate || $vector_mode == short ]]; then
        [[ $(cat "$stage/gate-visits") == vector_current ]] || return 1
    fi
}
run_case current_cp_old_expired guard_case current different yes 0
run_case new_cp_missing_old_eof guard_case missing different yes 0
run_case invalid_cp_no_fallback guard_case malformed different yes 2
run_case duplicate_cp_no_fallback guard_case duplicate different yes 2
run_case out_of_bounds_cp_no_fallback guard_case short different yes 2
run_case same_old_prefix_refused guard_case current same_old yes 2
run_case advanced_new_cursor guard_case current advanced yes 0
run_case advanced_invalid_cursor guard_case current bad_advanced yes 2
run_case concurrent_state_change guard_case current different no 2

# Exercise real coreutils atomic hardlink replacement and interrupted staging
# link cleanup against private files, with the exact state-bound inode.
link_case() {
    local mode=$1 path=$stage/link-$1
    mkdir -m 711 "$path"
    RO_MANAGED=$path
    printf 'old\n' > "$path/old"
    printf 'new\n' > "$path/new"
    ln "$path/old" "$path/alias"
    RO_NEXT=$path/new RO_PHASE=publish_pending
    RO_NEW_DEV=$(stat -c %d "$path/new") RO_NEW_INO=$(stat -c %i "$path/new")
    local old_identity new_identity expected rc=0
    old_identity=$(ro_devino "$path/old") new_identity=$(ro_devino "$path/new")
    if [[ $mode == replaced ]]; then
        ro_replace_link "$path/alias" "$old_identity" "$path/new" || return 1
        [[ $(ro_devino "$path/alias") == "$new_identity" && -f $path/old && $(cat "$path/old") == old && ! -e $path/.publish-link ]]
    elif [[ $mode == conflict ]]; then
        ro_replace_link "$path/alias" 1:1 "$path/new" && return 1
        [[ $(ro_devino "$path/alias") == "$old_identity" && ! -e $path/.publish-link ]]
    elif [[ $mode == recover ]]; then
        ln "$path/new" "$path/.publish-link"
        ro_reconcile_link || return 1
        [[ ! -e $path/.publish-link && -f $path/new && $(ro_devino "$path/alias") == "$old_identity" ]]
    elif [[ $mode == wrong_pending ]]; then
        ln "$path/old" "$path/.publish-link"
        ro_reconcile_link && return 1
        [[ -f $path/.publish-link && $(ro_devino "$path/alias") == "$old_identity" ]]
    else return 1; fi
}
for mode in replaced conflict recover wrong_pending; do run_case "link_$mode" link_case "$mode"; done

prefix_case() {
    local mode=$1 expected=$2 path=$stage/prefix-$1
    mkdir -m 700 "$path"
    RO_CURRENT=$path/old RO_NEXT=$path/new
    printf 'same-prefix-longer\n' > "$RO_CURRENT"
    case $mode in
      empty) : > "$RO_NEXT" ;;
      short_same) printf 'same-' > "$RO_NEXT" ;;
      short_distinct) printf 'DIFF-' > "$RO_NEXT" ;;
      full_same) cp "$RO_CURRENT" "$RO_NEXT" ;;
      longer_same) cat "$RO_CURRENT" > "$RO_NEXT"; printf 'more\n' >> "$RO_NEXT" ;;
      zero_cursor) : > "$RO_NEXT" ;;
    esac
    RO_OLD_DEV=$(stat -c %d "$RO_CURRENT") RO_OLD_INO=$(stat -c %i "$RO_CURRENT")
    RO_NEW_DEV=$(stat -c %d "$RO_NEXT") RO_NEW_INO=$(stat -c %i "$RO_NEXT")
    local offset rc=0
    offset=$(stat -c %s "$RO_CURRENT"); [[ $mode != zero_cursor ]] || offset=0
    RO_STATE=$(jq -nc --argjson offset "$offset" '{proof:{readers_drained:{wazuh_offset:$offset}}}')
    ro_prefix_distinct || rc=$?
    [[ $rc == "$expected" ]]
}
for mode in empty short_same full_same longer_same; do run_case "common_prefix_$mode" prefix_case "$mode" 2; done
for mode in short_distinct zero_cursor; do run_case "common_prefix_$mode" prefix_case "$mode" 0; done

cleanup
[[ ! -e $stage ]]
trap - EXIT
printf '{"status":"passed","cases":%s,"synthetic_only":true,"dispatch_and_guard_mock_boundaries":true,"native_hardlink_mutations":true,"systemd_or_docker_called":false,"operational_files_touched":false,"fixture_removed":true}\n' "$passed"
