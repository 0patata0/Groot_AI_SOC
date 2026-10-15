#!/bin/bash
# Linux root, synthetic keys/files only. No account, sudoers, SSH or unit calls.
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C TZ=Asia/Seoul
[[ $(uname -s) == Linux && $EUID == 0 ]] || exit 64
directory=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
stage=$(mktemp -d /var/tmp/capstone-history-install-test.XXXXXXXX)
identity=$(stat -c '%d:%i:%u:%g:%a' "$stage")
case_name=setup passed=0
cleanup() {
    local rc=$?
    trap - EXIT
    if [[ -d $stage && ! -L $stage && $(stat -c '%d:%i:%u:%g:%a' "$stage") == "$identity" ]]; then
        rm -rf -- "$stage"
    else rc=1; fi
    if ((rc)); then
        printf '{"status":"failed","case":"%s","exit":%s}\n' "$case_name" "$rc"
    else
        printf '{"schema_version":1,"status":"passed","cases":%s,"synthetic_only":true,"network_calls":0,"account_changes":0,"unit_calls":0,"fixture_removed":true}\n' "$passed"
    fi
    exit "$rc"
}
trap cleanup EXIT
source "$directory/common.sh"
timeout --kill-after=1s 5s ssh-keygen -q -t ed25519 -N '' -C synthetic-fixture -f "$stage/key"
ssh-keygen -y -f "$stage/key" | awk '{print $1 " " $2}' > "$stage/public.key"
chmod 400 "$stage/public.key"
public=$(cat "$stage/public.key")
public_sha=$(hd_sha "$stage/public.key")
reject() { local rc=0; "$@" > /dev/null 2>&1 || rc=$?; ((rc!=0)); }
setup_case() {
    rm -rf -- "$stage/case"
    mkdir -m 700 "$stage/case"
    cp "$stage/public.key" "$stage/case/public.key"
    chmod 400 "$stage/case/public.key"
}
run_case() {
    case_name=$1; shift
    set +e
    (set -euo pipefail; setup_case; "$@") > "$stage/case.log" 2>&1
    local rc=$?
    set -e
    ((rc==0)) || return "$rc"
    passed=$((passed+1))
}
valid_public() { [[ $(hd_public "$stage/case/public.key" "$public_sha") == "$public" ]]; }
wrong_sha() { reject hd_public "$stage/case/public.key" "$(printf '0%.0s' {1..64})"; }
wrong_mode() { chmod 600 "$stage/case/public.key"; reject hd_public "$stage/case/public.key" "$public_sha"; }
symlink_key() { rm "$stage/case/public.key"; ln -s "$stage/public.key" "$stage/case/public.key"; reject hd_public "$stage/case/public.key" "$public_sha"; }
hardlink_key() { ln "$stage/case/public.key" "$stage/case/other"; reject hd_public "$stage/case/public.key" "$public_sha"; }
second_no_lf() { printf '%s' "$public" >> "$stage/case/public.key"; reject hd_public "$stage/case/public.key" "$(hd_sha "$stage/case/public.key")"; }
missing_lf() { printf '%s' "$public" > "$stage/case/public.key"; reject hd_public "$stage/case/public.key" "$(hd_sha "$stage/case/public.key")"; }
bad_native_key() { printf 'ssh-ed25519 AAAA\n' > "$stage/case/public.key"; reject hd_public "$stage/case/public.key" "$(hd_sha "$stage/case/public.key")"; }
wrong_type() { sed 's/ssh-ed25519/ssh-rsa/' "$stage/public.key" > "$stage/case/public.key"; reject hd_public "$stage/case/public.key" "$(hd_sha "$stage/case/public.key")"; }
unsafe_parent() { chmod 777 "$stage/case"; reject hd_public "$stage/case/public.key" "$public_sha"; }
wrong_owner() { chown 65534:65534 "$stage/case/public.key"; reject hd_public "$stage/case/public.key" "$public_sha"; }
key_with_comment() { printf '%s synthetic-comment\n' "$public" > "$stage/case/public.key"; [[ $(hd_public "$stage/case/public.key" "$(hd_sha "$stage/case/public.key")") == "$public" ]]; }
publish_valid() {
    hd_publish "$stage/public.key" "$stage/case/new" 400
    [[ $(hd_sha "$stage/case/new") == "$public_sha" && $(stat -c '%u:%g:%a:%h' "$stage/case/new") == 0:0:400:1 ]]
    [[ $(find "$stage/case" -maxdepth 1 -name '.history-install-*' | wc -l) == 0 ]]
}
publish_existing() { reject hd_publish "$stage/public.key" "$stage/case/public.key" 600; [[ $(hd_sha "$stage/case/public.key") == "$public_sha" && $(stat -c %a "$stage/case/public.key") == 400 ]]; }
publish_dangling() { ln -s "$stage/missing" "$stage/case/new"; reject hd_publish "$stage/public.key" "$stage/case/new" 400; [[ -L $stage/case/new && ! -e $stage/missing ]]; }
publish_unsafe_parent() { chmod 777 "$stage/case"; reject hd_publish "$stage/public.key" "$stage/case/new" 400; [[ ! -e $stage/case/new ]]; }
directory_create() { hd_newdir "$stage/case/new" 755; [[ $(stat -c '%u:%g:%a' "$stage/case/new") == 0:0:755 ]]; }
directory_existing() { reject hd_newdir "$stage/case" 755; [[ $(stat -c %a "$stage/case") == 700 ]]; }
directory_wrong_mode() { reject hd_dir "$stage/case" 755; }
record_exclusive() {
    HD_BACKUP=$stage/case
    printf '{"synthetic":true}\n' | hd_record result.json
    local before
    before=$(hd_sha "$stage/case/result.json")
    reject bash -c 'set -euo pipefail; source "$1"; HD_BACKUP=$2; printf changed | hd_record result.json' fixture "$directory/common.sh" "$stage/case"
    [[ $(hd_sha "$stage/case/result.json") == "$before" && $(stat -c '%u:%g:%a:%h' "$stage/case/result.json") == 0:0:400:1 ]]
}
for name in valid_public wrong_sha wrong_mode symlink_key hardlink_key second_no_lf missing_lf bad_native_key wrong_type unsafe_parent wrong_owner key_with_comment publish_valid publish_existing publish_dangling publish_unsafe_parent directory_create directory_existing directory_wrong_mode record_exclusive; do
    run_case "$name" "$name"
done
[[ $passed == 20 ]]
