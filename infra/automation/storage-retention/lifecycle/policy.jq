# Pure metadata policy. valid_raw_state is the SHA-pinned existing state.jq.
# No observation in this file is an authenticated live observation by itself.
def hex64: type=="string" and test("^[0-9a-f]{64}$");
def uint: type=="number" and floor==. and .>=0 and .<=9007199254740991;
def exact($names): type=="object" and keys==($names|sort);
def wrapped_state:
  exact(["sha256","state"]) and (.sha256|hex64) and (.state|valid_raw_state);
def ordinary_transition($a;$b):
  $b.revision==$a.revision+1 and $a.engine==$b.engine and
  $a.machine_id==$b.machine_id and $a.boot_id==$b.boot_id and
  $a.source_pins==$b.source_pins and
  ([$a.phase,$b.phase] as $p|any([
    ["active","switch_pending"],["switch_pending","old_closed"],
    ["old_closed","readers_drained"],["readers_drained","publish_pending"],
    ["publish_pending","active"]][];.==$p)) and
  (if $a.phase=="publish_pending" then $b.current==$a.pending and $b.pending==null
   else $b.current==$a.current and
     (if $a.phase=="active" then true else $b.pending==$a.pending end) and
     (if $a.proof.old_closed==null then true else $b.proof.old_closed==$a.proof.old_closed end) and
     (if $a.proof.readers_drained==null then true else $b.proof.readers_drained==$a.proof.readers_drained end)
   end);
def source_shape:
  exact(["basename","bytes","device","gid","inode","links","mode","sha1","sha256","stable","uid"]) and
  (.basename|type=="string" and test("^generation-[0-9]{10}\\.jsonl$")) and
  all([.bytes,.device,.inode,.links,.uid,.gid][];uint) and .bytes<=2147483648 and .inode>0 and
  (.mode|type=="string") and (.sha256|hex64) and
  (.sha1|type=="string" and test("^[0-9a-f]{40}$")) and (.stable|type=="boolean");
def identity($s):
  {basename:$s.basename,bytes:$s.bytes,device:$s.device,inode:$s.inode,sha256:$s.sha256};
def first_shape:
  exact(["schema_version","policy","machine_id","engine","source","publish_state_sha256","successor_state_sha256","first_verified_at_epoch"]) and
  .schema_version==1 and .policy=="capstone-sealed-raw-first-v1" and
  .machine_id=="096e90b6243e438aa8a7b392be754732" and
  (.engine|IN("suricata","modsecurity")) and
  (.source|exact(["basename","bytes","device","inode","sha256"]) and
    (.basename|type=="string") and all([.bytes,.device,.inode][];uint) and (.sha256|hex64)) and
  (.publish_state_sha256|hex64) and (.successor_state_sha256|hex64) and
  (.first_verified_at_epoch|uint) and .first_verified_at_epoch>0;
def first_wrapper: exact(["sha256","record"]) and (.sha256|hex64) and (.record|first_shape);
def archive_shape:
  exact(["schema_version","policy","source","gzip_sha256","gzip_bytes","manifest_sha256","local_restore_sha256","local_restore_bytes"]) and
  .schema_version==1 and .policy=="capstone-sealed-raw-archive-v1" and
  (.source|exact(["basename","bytes","device","inode","sha256"])) and
  all([.gzip_sha256,.manifest_sha256,.local_restore_sha256][];hex64) and
  all([.gzip_bytes,.local_restore_bytes][];uint) and .gzip_bytes>0 and .gzip_bytes<=2155872256;
def remote_shape:
  exact(["schema_version","policy","receiver_machine_id","stage","manifest_sha256","gzip_sha256","gzip_bytes","restored_sha256","restored_bytes","received_at_epoch","restore_verified_at_epoch"]) and
  .schema_version==1 and .policy=="capstone-sealed-raw-receipt-v1" and
  .receiver_machine_id=="1e143067c98a44ffba6eaa925dc038d7" and
  .stage=="remote_preserved_and_restore_verified" and
  all([.manifest_sha256,.gzip_sha256,.restored_sha256][];hex64) and
  all([.gzip_bytes,.restored_bytes,.received_at_epoch,.restore_verified_at_epoch][];uint) and
  .received_at_epoch>0 and .restore_verified_at_epoch>=.received_at_epoch;
def input_shape:
  exact(["schema_version","policy","machine_id","engine","observed_at_epoch","capture","source","current","chain","aliases","first_verified","archive","remote"]) and
  .schema_version==1 and .policy=="capstone-sealed-raw-snapshot-v1" and
  .machine_id=="096e90b6243e438aa8a7b392be754732" and (.engine|IN("suricata","modsecurity")) and
  (.observed_at_epoch|uint) and .observed_at_epoch>0 and
  (.capture|exact(["complete","stable","shared_lock_held","host_pins_match","raw_guards_passed","intents_absent","writer_fd_zero","references_clear"]) and all(.[];type=="boolean")) and
  (.source|source_shape) and
  (.current|exact(["suricata","modsecurity"]) and all(.[];wrapped_state)) and
  (.chain|type=="array" and (length==0 or length>=4) and length<=1024 and all(.[];wrapped_state)) and
  (.aliases|type=="array" and length==2 and (map(.engine)|sort)==["modsecurity","suricata"] and
    all(.[];exact(["engine","device","inode","writer_device","writer_inode"]) and
      all([.device,.inode,.writer_device,.writer_inode][];uint))) and
  (.first_verified==null or (.first_verified|first_wrapper)) and
  (.archive==null or (.archive|archive_shape)) and (.remote==null or (.remote|remote_shape));

if (input_shape|not) then error("invalid_snapshot_schema") else . end |
. as $x | .chain as $chain | $chain[0].state as $closed |
$chain[2] as $publication | $chain[3] as $successor |
([ if (.capture.complete and .capture.stable and .capture.shared_lock_held and .capture.writer_fd_zero|not)
      then "stable_locked_read_or_writer_closure_unavailable" else empty end,
   if .source.uid!=0 or .source.gid!=0 or .source.mode!="0400" or .source.links!=1 or .source.stable!=true
      then "source_not_sealed_for_copy" else empty end] | unique) as $copy_blocked |
([ if (all(.capture[];.==true)|not) then "capture_or_reference_proof_unavailable" else empty end,
   if .source.uid!=0 or .source.gid!=0 or .source.mode!="0400" or .source.links!=1 or .source.stable!=true
      then "source_not_immutable_single_link" else empty end,
   if any(.current|to_entries[];.value.state.engine!=.key or .value.state.phase!="active")
      then "engine_not_active" else empty end,
   if [$chain[0].state.phase,$chain[1].state.phase,$chain[2].state.phase,$chain[3].state.phase] !=
      ["old_closed","readers_drained","publish_pending","active"] then "missing_closed_drain_publish_active" else empty end,
   if any(range(1;($chain|length)); . as $i|ordinary_transition($chain[$i-1].state;$chain[$i].state)|not)
      then "unsupported_or_incomplete_history_transition" else empty end,
   if $chain[-1]!=$x.current[$x.engine] or any($chain[];.state.engine!=$x.engine)
      then "history_not_bound_to_current" else empty end,
   if ($chain|length)<4 then "missing_payload_consumption_proof"
      elif identity($x.source)!={basename:$closed.current.basename,device:$closed.current.device,inode:$closed.current.inode,
       bytes:$closed.proof.old_closed.bytes,sha256:$closed.proof.old_closed.sha256} or
       $x.source.sha1!=$publication.state.proof.readers_drained.wazuh_sha1
      then "sealed_payload_or_eof_hash_mismatch" else empty end,
   if any($x.current[]; [.state.current.device,.state.current.inode]==[$x.source.device,$x.source.inode]) or
      any($x.aliases[]; [.device,.inode]==[$x.source.device,$x.source.inode] or
                           [.writer_device,.writer_inode]==[$x.source.device,$x.source.inode])
      then "source_still_referenced" else empty end,
   if any($x.aliases[]; . as $a|[$a.device,$a.inode]!=
       [$x.current[$a.engine].state.current.device,$x.current[$a.engine].state.current.inode])
      then "alias_not_bound_to_active_state" else empty end
 ] | unique) as $blocked |
# Writer pointers must select the same current generation too. This separately
# covers the Suricata active hardlink and WAF audit-path.conf target.
($blocked + [if any($x.aliases[];. as $a|[$a.writer_device,$a.writer_inode]!=
        [$x.current[$a.engine].state.current.device,$x.current[$a.engine].state.current.inode])
      then "writer_not_bound_to_active_state" else empty end] | unique) as $blocked |
{schema_version:1,policy:"capstone-sealed-raw-first-v1",machine_id:$x.machine_id,engine:$x.engine,
 source:identity($x.source),publish_state_sha256:$publication.sha256,successor_state_sha256:$successor.sha256,
 first_verified_at_epoch:$x.observed_at_epoch} as $new_first |
($x.first_verified.record // null) as $old_first |
($blocked + $copy_blocked + [
  if $old_first!=null and ($old_first|del(.first_verified_at_epoch))!=($new_first|del(.first_verified_at_epoch))
    then "first_receipt_binding_conflict" else empty end,
  if $old_first!=null and $x.observed_at_epoch<$old_first.first_verified_at_epoch
    then "clock_before_first_verified" else empty end
] | unique) as $blocked |
($old_first // $new_first) as $first |
($x.observed_at_epoch-$first.first_verified_at_epoch) as $age |
($x.archive!=null and
 $x.archive.source==identity($x.source) and
 $x.archive.local_restore_sha256==$x.source.sha256 and $x.archive.local_restore_bytes==$x.source.bytes) as $local_ok |
($local_ok and $x.remote!=null and $x.remote.manifest_sha256==$x.archive.manifest_sha256 and
 $x.remote.gzip_sha256==$x.archive.gzip_sha256 and $x.remote.gzip_bytes==$x.archive.gzip_bytes and
 $x.remote.restored_sha256==$x.source.sha256 and $x.remote.restored_bytes==$x.source.bytes and
 $x.remote.restore_verified_at_epoch<=$x.observed_at_epoch) as $remote_ok |
{schema_version:1,policy:"capstone-sealed-raw-lifecycle-decision-v1",engine:$x.engine,
 source:identity($x.source),status:(if ($blocked|length)==0 then "sealed_proof_verified" elif ($copy_blocked|length)==0 then "archive_copy_only" else "review_required" end),
 reasons:$blocked,archive_copy_reasons:$copy_blocked,archive_copy_eligible:(($copy_blocked|length)==0),
 first_verified_receipt:(if ($blocked|length)==0 then $first else null end),
 first_receipt_action:(if ($blocked|length)>0 then "none" elif $old_first==null then "create_exclusive" else "preserve_exact" end),
 retention_seconds:2592000,age_seconds:(if $age>=0 then $age else null end),
 retention_elapsed:($age>=2592000 and ($blocked|length)==0),local_archive_restore_verified:$local_ok,
 remote_archive_restore_verified:$remote_ok,
 deletion_review_ready:(($blocked|length)==0 and $age>=2592000 and $remote_ok),
 delete_authorized:false,automatic_deletion:false,backups_delete_authorized:false,
 observation_authenticated:false,checkpoint_modified:false}
