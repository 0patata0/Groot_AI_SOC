#!/bin/bash
# Offline bounded policy evaluation. Does not collect live evidence, write a
# receipt, authorize deletion, access SSH, or invoke any operating service.
set -euo pipefail
export LC_ALL=C
[[ $# == 1 ]] || exit 64
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
state_schema=$here/../../../normalization/vector/raw-operations/state.jq
state_sha=3db6baef5c679521bdc257cbe1aca66fd6884714f734a1778ca27b249e40a775
fail() { printf '{"status":"refused","reason":"%s","delete_authorized":false}\n' "$1"; exit 65; }
hash() { local v; v=$(sha256sum -- "$1") || return 1; printf '%s\n' "${v%% *}"; }
[[ -f $state_schema && ! -L $state_schema && $(hash "$state_schema") == "$state_sha" ]] || fail state_schema_pin
[[ -f $1 && ! -L $1 ]] || fail snapshot_file
bytes=$(wc -c < "$1") || fail snapshot_read
(( bytes>0 && bytes<=4194304 )) || fail snapshot_size
umask 077
work=$(mktemp -d "${TMPDIR:-/tmp}/capstone-lifecycle-policy.XXXXXXXX")
trap 'rm -f -- "$work/input.json" "$work/canonical.json" "$work/program.jq" "$work/output.json" "$work/rows" "$work/row"; rmdir -- "$work"' EXIT
cat -- "$1" > "$work/input.json" || fail snapshot_read
[[ $(wc -c < "$work/input.json") == "$bytes" ]] || fail snapshot_changed
jq -cS . "$work/input.json" > "$work/canonical.json" 2>/dev/null || fail invalid_json
cmp -s -- "$work/input.json" "$work/canonical.json" || fail noncanonical_json
jq -se 'length==1 and (.[0]|type=="object")' "$work/input.json" >/dev/null || fail multiple_documents
{ printf 'def valid_raw_state:\n(\n'; cat -- "$state_schema"; printf '\n);\n'; cat -- "$here/policy.jq"; } > "$work/program.jq"
# Check the schema before following any declared hashes; these are JSON values,
# never filenames or executable input. Hashes are of canonical bytes plus LF.
jq -cS -f "$work/program.jq" "$work/input.json" > "$work/output.json" 2>/dev/null || fail invalid_snapshot_schema
jq -c '.chain[]?,.current[]?|{expected:.sha256,value:.state}' "$work/input.json" > "$work/rows" || fail state_rows
while IFS= read -r row; do
    expected=$(jq -r .expected <<< "$row") || fail state_rows
    jq -cS .value <<< "$row" > "$work/row" || fail state_rows
    [[ $(hash "$work/row") == "$expected" ]] || fail state_digest_mismatch
done < "$work/rows"
if jq -e '.first_verified!=null' "$work/input.json" >/dev/null; then
    jq -cS .first_verified.record "$work/input.json" > "$work/row"
    [[ $(hash "$work/row") == "$(jq -r .first_verified.sha256 "$work/input.json")" ]] || fail first_receipt_digest_mismatch
fi
cat -- "$work/output.json"
