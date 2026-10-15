#!/bin/bash
# One fixed benign loopback request after the new WAF's first start. Root only.
# The containing release pins this file and supplies its sibling wrapper SHA.
set -euo pipefail
umask 077
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=Asia/Seoul
[[ $# == 1 && $1 =~ ^[a-f0-9]{64}$ && $EUID == 0 &&
   $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 77
project=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
wrapper=$project/waf-recreate-cutover-local-a.sh
parent=$project
while [[ $parent != / ]]; do
    [[ -d $parent && ! -L $parent && $(stat -c %u:%g "$parent") == 0:0 ]] || exit 77
    (( (8#$(stat -c %a "$parent") & 0022)==0 )) || exit 77
    parent=${parent%/*}; [[ -n $parent ]] || parent=/
done
[[ -f $wrapper && ! -L $wrapper && $(stat -c %u:%g:%a:%h "$wrapper") == 0:0:400:1 &&
   $(sha256sum "$wrapper" | cut -d' ' -f1) == "$1" ]] || exit 77
WRAPPER_SHA=$1
source "$wrapper"
EXPECTED_CID=6c72d5a5b8229fc3b6e010c9d046d97ac5c13437cae045c72a330fe0d6d82f81
PROBE=$WRC_WORK/benign-probe
phase=preflight http_attempted=false curl_rc=null
finish_probe() {
    local rc=$?
    trap - EXIT
    if (( rc!=0 )); then
        if [[ -d $PROBE && ! -L $PROBE && ! -e $PROBE/result.json && ! -e $PROBE/failure.json ]]; then
            jq -ncS --arg phase "$phase" --argjson attempted "$http_attempted" --argjson curl_rc "$curl_rc" \
              '{status:"refused",phase:$phase,http_attempted:$attempted,curl_exit:$curl_rc,automatic_retry:false,inspect_required:true}' |
              wrc_new "$PROBE/failure.json" 400 || true
        fi
        jq -nc --arg phase "$phase" --argjson attempted "$http_attempted" \
          '{status:"refused",phase:$phase,http_attempted:$attempted,automatic_retry:false,raw_exported:false}'
    fi
    exit "$rc"
}
trap finish_probe EXIT
for lock in /var/lib/rule-change/.lock /var/lib/capstone-automation/ansible/vector.lock; do
    wrc_file "$lock" 600 4096 || exit 75
done
exec 8<>/var/lib/rule-change/.lock
exec 9<>/var/lib/capstone-automation/ansible/vector.lock
flock -n 8 && flock -n 9 || exit 75
wrc_load && [[ $WRC_NEW == "$EXPECTED_CID" ]] && wrc_blocked && wrc_old_stopped &&
  wrc_original_sources && wrc_old_eof && wrc_new_writer || exit 75
wrc_json "$WRC_WORK/start-new.json" 400 && wrc_json "$WRC_WORK/start-new.intent.json" 400 &&
  wrc_json "$WRC_WORK/new-running.json" 400 && wrc_json "$WRC_WORK/prepare-new-details.json" 400 || exit 75
jq -e --arg sha "$(wrc_sha "$WRC_WORK/start-new.intent.json")" \
  '.schema_version==1 and .phase=="start-new" and .status=="verified" and .intent_sha256==$sha' "$WRC_WORK/start-new.json" >/dev/null
jq -e --arg cid "$EXPECTED_CID" --arg boot "$WRC_BOOT" \
  '.phase=="start-new" and .new_cid==$cid and .boot_id==$boot and .armed==true and .automatic_retry==false' "$WRC_WORK/start-new.intent.json" >/dev/null
[[ ! -e $PROBE && ! -L $PROBE ]] || exit 75
binding=$(jq -er '.new_binding|select(type=="string" and test("^[a-f0-9]{64}$"))' "$WRC_WORK/prepare-new-details.json")
new=$WRC_RAW/capstone-managed/generation-0000000004.jsonl
old=$WRC_RAW/capstone-managed/generation-0000000003.jsonl
pid=$(jq -er '.state.Pid|select(type=="number" and .>1)' "$WRC_WORK/new-running.json")
identity=$(writer_identity waf | jq -ce .identity)
jq -ne --argjson id "$identity" --arg cid "$EXPECTED_CID" --argjson pid "$pid" \
  '$id.cid==$cid and $id.pid==$pid and $id.uid==101 and $id.gid==101' >/dev/null
[[ $(readlink "/proc/$pid/exe") == /usr/sbin/nginx ]]
named=$(wrc_inspect "$EXPECTED_CID")
jq -ne --argjson now "$named" --slurpfile first "$WRC_WORK/new-running.json" \
  '$now.cid==$first[0].cid and $now.state.Pid==$first[0].state.Pid and $now.state.StartedAt==$first[0].state.StartedAt and
   $now.name=="/waf" and $now.state.Running and ($now.state.Restarting|not) and $now.state.Health.Status=="healthy" and
   $now.networks["secstack_waf-net"].IPAddress=="172.18.0.2"' >/dev/null
[[ -f $new && ! -L $new && $(stat -c %u:%g:%a:%h "$new") == 101:101:644:1 ]]
new_id=$(stat -c %d:%i "$new"); before_bytes=$(stat -c %s "$new")
(( before_bytes<=33554432 ))
old_meta=$(stat -c %d:%i:%u:%g:%a:%h:%s:%y:%z "$old")
old_sha=$(wrc_sha "$old"); alias_meta=$(stat -c %d:%i:%u:%g:%a:%h "$WRC_RAW/audit.log")
mkdir -m 700 "$PROBE" && sync -- "$PROBE" "$WRC_WORK"
snapshot() {
    local output=$1 bytes=$2
    timeout --signal=TERM --kill-after=1s 10s dd if="$new" of="$output" iflag=count_bytes,fullblock count="$bytes" status=none
    [[ $(stat -c %s "$output") == "$bytes" && $(stat -c %d:%i "$new") == "$new_id" ]]
    chmod 400 "$output" && sync -- "$output" "$PROBE"
}
snapshot "$PROBE/before.jsonl" "$before_bytes"
before_sha=$(wrc_sha "$PROBE/before.jsonl")
jq -ncS --arg cid "$EXPECTED_CID" --arg wrapper "$WRAPPER_SHA" --argjson identity "$identity" \
  --arg inode "$new_id" --argjson bytes "$before_bytes" --arg sha "$before_sha" --arg old "$old_sha" \
  '{schema_version:1,candidate_cid:$cid,wrapper_sha256:$wrapper,writer_identity:$identity,new_identity:$inode,new_bytes:$bytes,new_sha256:$sha,old_sha256:$old,http_calls:0}' |
  wrc_new "$PROBE/before.json" 400
phase=native_configuration_check
native_rc=0
(ulimit -f 128; timeout --signal=TERM --kill-after=1s 15s /usr/local/bin/docker exec --user 101:101 "$EXPECTED_CID" nginx -t) \
  > "$PROBE/native-nginx.log" 2>&1 || native_rc=$?
chmod 400 "$PROBE/native-nginx.log" && sync -- "$PROBE/native-nginx.log" "$PROBE"
[[ $native_rc == 0 && $(stat -c %s "$PROBE/native-nginx.log") -le 65536 ]]
wrc_old_stopped && wrc_blocked && wrc_original_sources && wrc_new_writer || exit 75
[[ $(writer_identity waf | jq -cS .identity) == "$(jq -cS . <<< "$identity")" ]]
phase=http_intent
start_ms=$(date +%s%3N)
jq -ncS --arg cid "$EXPECTED_CID" --argjson pid "$pid" --argjson start_ms "$start_ms" \
  --arg before "$(wrc_sha "$PROBE/before.json")" \
  '{schema_version:1,policy:"single-benign-waf-firststart-v1",candidate_cid:$cid,pid:$pid,start_epoch_ms:$start_ms,
    before_sha256:$before,method:"POST",url:"http://127.0.0.1:8080/50x.html",body_bytes:0,max_requests:1,automatic_retry:false}' |
  wrc_new "$PROBE/http.intent.json" 400
phase=http_once http_attempted=true curl_rc=0
(ulimit -f 128; timeout --signal=TERM --kill-after=1s 12s /usr/bin/nsenter --target "$pid" --net -- \
  /usr/bin/curl --disable --silent --show-error --noproxy '*' --max-time 10 --request POST --data-binary '' \
  --output "$PROBE/response.body" --write-out '%{http_code} %{local_port}\n' http://127.0.0.1:8080/50x.html) \
  > "$PROBE/http.status" 2> "$PROBE/http.stderr" || curl_rc=$?
end_ms=$(date +%s%3N)
for file in response.body http.status http.stderr; do
    [[ ! -e $PROBE/$file ]] || { chmod 400 "$PROBE/$file"; sync -- "$PROBE/$file"; }
done
sync -- "$PROBE"
phase=after_snapshot
[[ $(stat -c %d:%i:%u:%g:%a:%h "$new") == "$new_id:101:101:644:1" ]]
after_bytes=$(stat -c %s "$new")
(( after_bytes>=before_bytes && after_bytes<=33554432 && after_bytes-before_bytes<=8388608 ))
snapshot "$PROBE/after.jsonl" "$after_bytes"
cmp -s -n "$before_bytes" "$PROBE/before.jsonl" "$PROBE/after.jsonl"
dd if="$PROBE/after.jsonl" of="$PROBE/appended.jsonl" iflag=skip_bytes,count_bytes skip="$before_bytes" count="$((after_bytes-before_bytes))" status=none
chmod 400 "$PROBE/appended.jsonl" && sync -- "$PROBE/appended.jsonl" "$PROBE"
phase=postconditions
[[ $curl_rc == 0 && $(cat "$PROBE/http.status") =~ ^405\ ([1-9][0-9]{0,4})$ ]]
local_port=${BASH_REMATCH[1]}; (( local_port<=65535 ))
[[ $(stat -c %d:%i:%u:%g:%a:%h:%s:%y:%z "$old") == "$old_meta" && $(wrc_sha "$old") == "$old_sha" &&
   $(stat -c %d:%i:%u:%g:%a:%h "$WRC_RAW/audit.log") == "$alias_meta" ]]
wrc_blocked && wrc_old_stopped && wrc_original_sources && wrc_old_eof && wrc_new_writer || exit 75
[[ $(writer_identity waf | jq -cS .identity) == "$(jq -cS . <<< "$identity")" ]]
phase=audit_validation
[[ $(tail -c 1 "$PROBE/appended.jsonl" | od -An -tu1 | tr -d ' \n') == 10 ]]
jq -sce --arg binding "$binding" --argjson port "$local_port" --argjson start "$start_ms" --argjson end "$end_ms" '
  length as $total|
  map(.transaction|select(.request.method=="POST" and .request.uri=="/50x.html" and
    .client_ip=="127.0.0.1" and .client_port==$port))|
  select(length==1)|.[0] as $t|
  select($t.response.http_code==405 and $t.host_ip=="127.0.0.1" and $t.host_port==8080 and $t.messages==[])|
  ($t.unique_id|capture("^v2:(?<binding>[a-f0-9]{64}):(?<request>[a-f0-9]{32}):(?<msec>[0-9]{10,12}\\.[0-9]{3}):(?<iso>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}:[0-9]{2})$")) as $id|
  select($id.binding==$binding)|(($id.msec|tonumber)*1000|floor) as $ms|
  ($id.iso|capture("^(?<wall>[0-9T:-]{19})(?<sign>[+-])(?<hours>[0-9]{2}):(?<minutes>[0-9]{2})$")) as $iso|
  select(($iso.hours|tonumber)<=23 and ($iso.minutes|tonumber)<=59)|
  (($iso.wall+"Z"|fromdateiso8601)-
    ((($iso.hours|tonumber)*3600+($iso.minutes|tonumber)*60)*(if $iso.sign=="+" then 1 else -1 end))) as $seconds|
  select($ms>=($start-2000) and $ms<=($end+2000) and $ms>=($seconds*1000) and $ms<($seconds*1000+1000))|
  {matched_rows:1,total_appended_rows:$total,http_status:405,messages:0,new_binding_v2_verified:true,unique_id_verified:true,iso_epoch_verified:true}
  ' "$PROBE/appended.jsonl" > "$PROBE/audit-proof.json"
chmod 400 "$PROBE/audit-proof.json" && sync -- "$PROBE/audit-proof.json" "$PROBE"
phase=complete
jq -ncS --arg cid "$EXPECTED_CID" --argjson pid "$pid" --argjson before "$before_bytes" --argjson after "$after_bytes" \
  --arg before_sha "$before_sha" --arg after_sha "$(wrc_sha "$PROBE/after.jsonl")" --arg raw_sha "$(wrc_sha "$PROBE/appended.jsonl")" \
  --slurpfile proof "$PROBE/audit-proof.json" \
  '{schema_version:1,status:"benign_probe_verified",candidate_cid:$cid,writer_pid:$pid,http_requests:1,http_status:405,
    audit_rows:1,total_appended_rows:$proof[0].total_appended_rows,messages:0,new_binding_v2_verified:true,unique_id_verified:true,
    iso_epoch_verified:true,new_before_bytes:$before,new_after_bytes:$after,
    new_before_sha256:$before_sha,new_after_sha256:$after_sha,appended_sha256:$raw_sha,old_sealed_unchanged:true,
    alias_unchanged:true,prefix_preserved:true,raw_exported:false,checkpoint_written:false,container_signals:0,automatic_retry:false}' |
  wrc_new "$PROBE/result.json" 400
cat "$PROBE/result.json"
