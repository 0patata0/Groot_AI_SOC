#!/bin/bash
# Root/Linux private synthetic files only. No production reads, SSH, containers,
# units, source/checkpoint deletion or existing history transfer changes.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
[[ $# == 0 && $EUID == 0 && $OSTYPE == linux* ]] || exit 64
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
source "$here/bundle-lib.sh"
umask 077
stage=$(mktemp -d /var/tmp/capstone-lifecycle-native.XXXXXXXX)
cleanup() {
    [[ $stage =~ ^/var/tmp/capstone-lifecycle-native\.[A-Za-z0-9]{8}$ && -d $stage && ! -L $stage &&
       $(stat -c '%u:%g:%a' "$stage") == 0:0:700 ]] || return 1
    rm -rf -- "$stage"
}
trap cleanup EXIT
mkdir -m 700 "$stage/raw" "$stage/archives" "$stage/work"
source_file=$stage/raw/generation-0000000001.jsonl
meta=$stage/source.json
reset() {
    rm -f -- "$source_file" "$stage/raw/extra" "$meta"
    printf '%s\n' '{"event_type":"synthetic-retention","sequence":1}' '{"event_type":"synthetic-retention","sequence":2}' > "$source_file"
    chmod 400 "$source_file"
    jq -ncS --arg base "${source_file##*/}" --arg sha "$(lc_sha "$source_file")" --arg sha1 "$(sha1sum "$source_file" | cut -d ' ' -f1)" \
      --argjson dev "$(stat -c %d "$source_file")" --argjson ino "$(stat -c %i "$source_file")" --argjson bytes "$(stat -c %s "$source_file")" '
      {basename:$base,device:$dev,inode:$ino,bytes:$bytes,sha256:$sha,sha1:$sha1,uid:0,gid:0,mode:"0400",links:1,stable:true}' > "$meta"
    chmod 400 "$meta"
}
passed=0
run() {
    local name=$1 rc; shift
    # Execute outside any if/! condition so errexit inside setup is effective.
    set +e
    (set -e; reset; "$@") > "$stage/stdout" 2> "$stage/stderr"
    rc=$?
    set -e
    if (( rc!=0 )); then printf '{"status":"failed","case":"%s","passed":%s,"exit":%s}\n' "$name" "$passed" "$rc"; exit 1; fi
    passed=$((passed+1))
}
pack() { lc_pack "$source_file" "$meta" "$stage/archives/$1" "$stage/work"; }
reject_pack() {
    local name=$1 before rc=0
    before=$(lc_identity "$source_file")
    # Deliberately conditional: library safety must not depend on errexit.
    pack "$name" > "$stage/rejected" 2>/dev/null || rc=$?
    [[ $rc != 0 && ! -e $stage/archives/$name && $(lc_identity "$source_file") == "$before" ]]
}
positive() {
    local sha before
    sha=$(lc_sha "$source_file"); before=$(lc_identity "$source_file")
    pack good > "$stage/archive.json"
    lc_verify_bundle "$stage/archives/good" "$stage/work" > "$stage/reverified.json"
    cmp "$stage/archive.json" "$stage/reverified.json"
    [[ $(lc_sha "$source_file") == "$sha" && $(lc_identity "$source_file") == "$before" ]]
    [[ $(find "$stage/work" -mindepth 1 -maxdepth 1 -printf '.\n' | wc -l) == 0 ]]
    jq -e --arg sha "$sha" '.local_restore_sha256==$sha and .source.sha256==$sha' "$stage/archive.json" >/dev/null
}
run gzip_roundtrip positive
extra_link() {
    ln "$source_file" "$stage/raw/extra"
    jq -cS '.links=2' "$meta" > "$stage/next"; cat "$stage/next" > "$meta"
    reject_pack two-links
    [[ $(stat -c %h "$source_file") == 2 ]]
}
run source_hardlink_refused extra_link
wrong_sha() { jq -cS '.sha256=("0"*64)' "$meta" > "$stage/next"; cat "$stage/next" > "$meta"; reject_pack bad-sha; }
run source_sha_refusal wrong_sha
wrong_inode() { jq -cS '.inode+=1' "$meta" > "$stage/next"; cat "$stage/next" > "$meta"; reject_pack bad-inode; }
run source_inode_refusal wrong_inode
writable() { chmod 600 "$source_file"; reject_pack writable; }
run writable_refusal writable
linked_meta() { ln "$meta" "$stage/meta-link"; reject_pack linked-meta; rm "$stage/meta-link"; }
run hardlinked_metadata_refusal linked_meta
existing() {
    mkdir -m 700 "$stage/archives/exists"
    printf sentinel > "$stage/archives/exists/payload.jsonl.gz"
    local before rc=0; before=$(lc_sha "$stage/archives/exists/payload.jsonl.gz")
    pack exists >/dev/null 2>&1 || rc=$?
    [[ $rc != 0 && $(lc_sha "$stage/archives/exists/payload.jsonl.gz") == "$before" ]]
}
run no_replace_existing_bundle existing
verify_failure() {
    local name=$1 kind=$2 rc=0
    pack "$name" >/dev/null
    case "$kind" in
      payload) printf x >> "$stage/archives/$name/payload.jsonl.gz" ;;
      manifest) jq -cS '.source.sha256=("0"*64)' "$stage/archives/$name/manifest.json" > "$stage/next"; cat "$stage/next" > "$stage/archives/$name/manifest.json" ;;
      extra) : > "$stage/archives/$name/extra" ;;
      symlink) mv "$stage/archives/$name/payload.jsonl.gz" "$stage/gzip-target"; ln -s "$stage/gzip-target" "$stage/archives/$name/payload.jsonl.gz" ;;
      hardlink) ln "$stage/archives/$name/payload.jsonl.gz" "$stage/gzip-extra" ;;
      unsafe_mode) chmod 600 "$stage/archives/$name/manifest.json" ;;
      duplicate) sed 's/"schema_version":1/"schema_version":1,"schema_version":1/' "$stage/archives/$name/manifest.json" > "$stage/next"; cat "$stage/next" > "$stage/archives/$name/manifest.json" ;;
    esac
    lc_verify_bundle "$stage/archives/$name" "$stage/work" >/dev/null 2>&1 || rc=$?
    [[ $rc != 0 && -f $source_file ]]
    [[ $(find "$stage/work" -mindepth 1 -maxdepth 1 -printf '.\n' | wc -l) == 0 ]]
}
for kind in payload manifest extra symlink hardlink unsafe_mode duplicate; do run "bundle_$kind" verify_failure "bad-${kind//_/-}" "$kind"; done
sync_failure() {
    local rc=0
    sync() { return 1; }
    pack sync-failure > "$stage/sync-result" 2>/dev/null || rc=$?
    [[ $rc != 0 && ! -s $stage/sync-result && -f $source_file ]]
}
run conditional_fsync_failure sync_failure
public_refusal() {
    local rc=0
    /bin/bash "$here/bundle-lib.sh" >/dev/null || rc=$?
    [[ $rc == 78 ]]
}
run no_public_mutation_cli public_refusal
cleanup
trap - EXIT
printf '{"status":"passed","cases":%s,"fixture_removed":true,"private_gzip_restore":true,"ssh_or_service_calls":false,"operational_files_touched":false,"source_deletion":false}\n' "$passed"
