# Native checkpoint projections. Run stream_guard before normal parsing:
# jq -nce --stream --arg mode stream_guard -f this-file snapshot.json
# This rejects duplicate keys (including empty/nonempty container duplicates),
# multiple documents, excessive nesting/events and nonfinite numbers. jq's
# ordinary last-key-wins parsing must not disagree with Wazuh's cJSON reader.
def uint($max): type=="number" and isfinite and floor==. and .>=0 and .<=$max;
def decimal: type=="string" and test("^(0|[1-9][0-9]{0,15})$") and (tonumber|uint(9007199254740991));
def bounded_string($max): type=="string" and length<=$max and (explode|all(.>=32 and .!=127));
def stamp:
  # Native DateTime<Utc> serialization uses Z. Reject noncanonical dates rather
  # than accepting a timestamp serde/chrono could fail to restore.
  type=="string" and length<=40 and
  ((try (capture("^(?<y>[0-9]{4})-(?<m>[0-9]{2})-(?<d>[0-9]{2})T(?<h>[0-9]{2}):(?<min>[0-9]{2}):(?<s>[0-9]{2})(\\.[0-9]{1,9})?Z$") |
    with_entries(.value|=tonumber) | . as $p |
    ($p.y>=1 and $p.m>=1 and $p.m<=12 and $p.d>=1 and $p.h<=23 and $p.min<=59 and $p.s<=59) and
    ($p.d<=([31,(if ($p.y%4==0 and ($p.y%100!=0 or $p.y%400==0)) then 29 else 28 end),31,30,31,30,31,31,30,31,30,31][$p.m-1]))
  ) catch false) // false);
def fingerprint:
  type=="object" and
  (if keys==["dev_inode"] then
    (.dev_inode|type=="array" and length==2 and all(.[];uint(9007199254740991))) and .dev_inode[1]>0
   elif keys==["first_line_checksum"] then (.first_line_checksum|uint(9007199254740991))
   elif keys==["first_lines_checksum"] then (.first_lines_checksum|uint(9007199254740991))
   else false end);
def stream_guard:
  reduce inputs as $event ({closed:{},events:0,leaves:0};
    .events+=1 |
    if .events>20000 or ($event|type)!="array" or
       (($event|length)!=1 and ($event|length)!=2) or
       ($event[0]|type)!="array" or ($event[0]|length)>16 then error("checkpoint_stream_invalid") else . end |
    $event[0] as $path |
    if (all($path[]; (type=="number" and uint(9007199254740991)) or
       (type=="string" and (explode|all(.>=32 and .<=126))))|not)
    then error("checkpoint_key_invalid") else . end |
    if ($event|length)==2 then
      .closed as $closed |
      if any(range(0;($path|length)+1); . as $n | ($closed[($path[:$n]|tojson)]//false)) then
        error("checkpoint_duplicate_key_or_document")
      elif ($event[1]|type)=="number" and ($event[1]|isfinite|not) then error("checkpoint_nonfinite")
      else .closed[($path|tojson)]=true | .leaves+=1 end
    else .closed[($path[:-1]|tojson)]=true end
  ) |
  if .leaves>0 and .closed["[]"]==true then true else error("checkpoint_document_incomplete") end;

if $mode=="stream_guard" then stream_guard
elif $mode=="vector" then
  if type!="array" or length!=1 then error("checkpoint_document_count") else .[0] end |
  if type!="object" or keys!=["checkpoints","version"] or .version!="1" or
     (.checkpoints|type)!="array" or (.checkpoints|length)>4096 or
     (all(.checkpoints[];
       type=="object" and keys==["fingerprint","modified","position"] and
       (.fingerprint|fingerprint) and (.position|uint(9007199254740991)) and (.modified|stamp))|not)
  then error("vector_checkpoint_shape") else . end |
  [.checkpoints[] | select(.fingerprint.dev_inode==[$device,$inode])] |
  if length==0 then {match_count:0}
  elif length!=1 then error("vector_checkpoint_match_count") else {offset:.[0].position} end
elif $mode=="wazuh" then
  if type!="array" or length!=1 then error("checkpoint_document_count") else .[0] end |
  # A Linux checkpoint can also contain a journald cursor. It is neither
  # interpreted nor emitted here. Strict streaming validation covers all keys.
  if type!="object" or ([keys[]|select(ascii_downcase=="files")])!=["files"] or
     (.files|type)!="array" or (.files|length)>1024 or
     (all(.files[];
       type=="object" and keys==["hash","offset","path"] and
       (.path|bounded_string(4096)) and (.hash|type=="string" and test("^[0-9a-f]{40}$")) and
       (.offset|decimal))|not)
  then error("wazuh_checkpoint_shape") else . end |
  [.files[] | select(.path==$logical)] |
  if length!=1 then error("wazuh_checkpoint_match_count")
  else {offset:(.[0].offset|tonumber),sha1:.[0].hash} end
else error("checkpoint_mode_invalid") end
