# Structural/binding validation only. Actual writer/reader proofs are checked by
# the coordinator and checkpoint gates; this file does not authorize startup.
def hex($n): type=="string" and test("^[0-9a-f]{"+($n|tostring)+"}$");
def uint($max): type=="number" and floor==. and .>=0 and .<=$max;
def generation:
  type=="object" and keys==["basename","device","inode","number","writer_config_sha256"] and
  (.number|uint(4294967295)) and (.device|uint(9007199254740991)) and
  (.inode|uint(9007199254740991)) and .inode>0 and
  (.writer_config_sha256|hex(64)) and
  .basename==("generation-"+(("0000000000"+(.number|tostring))[-10:])+".jsonl");
def pins:
  type=="object" and keys==["container_id","engine_config_sha256","producer_format_sha256",
                           "vector_config_sha256","vector_env_sha256","wazuh_config_sha256"] and
  all(.[];hex(64));
def closed:
  type=="object" and keys==["boot_id","bytes","device","inode","sha256","writer_fd_zero","writer_pid","writer_start_ticks"] and
  (.boot_id|hex(32)) and (.bytes|uint(2147483648)) and
  (.device|uint(9007199254740991)) and (.inode|uint(9007199254740991)) and .inode>0 and
  (.sha256|hex(64)) and .writer_fd_zero==true and
  (.writer_pid|uint(2147483647)) and .writer_pid>1 and
  (.writer_start_ticks|uint(9007199254740991)) and .writer_start_ticks>0;
def drained:
  type=="object" and keys==["vector_checkpoint_sha256","vector_offset","vector_stopped",
                           "wazuh_checkpoint_sha256","wazuh_offset","wazuh_sha1"] and
  (.vector_checkpoint_sha256|hex(64)) and (.wazuh_checkpoint_sha256|hex(64)) and
  (.vector_offset|uint(2147483648)) and (.wazuh_offset|uint(2147483648)) and
  (.wazuh_sha1|hex(40)) and .vector_stopped==true;
def publication:
  type=="object" and keys==["decision","new_prefix_sha1","old_offset","old_sha1","source_bytes","wazuh_checkpoint_sha256"] and
  (.new_prefix_sha1|hex(40)) and (.old_sha1|hex(40)) and (.wazuh_checkpoint_sha256|hex(64)) and
  (.old_offset|uint(2147483648)) and (.source_bytes|uint(2147483648)) and
  ((.decision=="different_prefix" and .old_offset>0 and .new_prefix_sha1!=.old_sha1) or
   (.decision=="saved_zero" and .old_offset==0 and
    .old_sha1=="da39a3ee5e6b4b0d3255bfef95601890afd80709" and .new_prefix_sha1==.old_sha1));

type=="object" and
keys==["boot_id","current","engine","machine_id","pending","phase","policy","proof","revision","schema_version","source_pins"] and
.schema_version==1 and .policy=="capstone-raw-operations-v1" and
.machine_id=="096e90b6243e438aa8a7b392be754732" and (.boot_id|hex(32)) and
(.engine|IN("suricata","modsecurity")) and (.revision|uint(2147483647)) and
(.phase|IN("active","switch_pending","old_closed","readers_drained","publish_pending")) and
(.source_pins|pins) and (.current|generation) and
(.proof|type=="object" and keys==["old_closed","publish_guard","readers_drained"]) and
(
  if .phase=="active" then
    .pending==null and .proof=={old_closed:null,publish_guard:null,readers_drained:null}
  else
    (.pending|generation) and .pending.number==(.current.number+1) and
    [.pending.device,.pending.inode]!=[.current.device,.current.inode] and
    (if .phase=="switch_pending" then .proof.old_closed==null else
       (.proof.old_closed|closed) and
       [.proof.old_closed.device,.proof.old_closed.inode]==[.current.device,.current.inode] end) and
    (if .phase|IN("switch_pending","old_closed") then .proof.readers_drained==null else
       (.proof.readers_drained|drained) and
       .proof.readers_drained.vector_offset==.proof.old_closed.bytes and
       .proof.readers_drained.wazuh_offset==.proof.old_closed.bytes end) and
    (if .phase!="publish_pending" then .proof.publish_guard==null else
       (.proof.publish_guard|publication) and
       .proof.publish_guard.old_offset==.proof.old_closed.bytes and
       .proof.publish_guard.old_sha1==.proof.readers_drained.wazuh_sha1 end)
  end
)
