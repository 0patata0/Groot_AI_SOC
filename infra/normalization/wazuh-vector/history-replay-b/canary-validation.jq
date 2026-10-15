# Native jq 1.6-compatible validation for the existing thirteen-row canary.
# Input membership is checked per rule/scenario. Concurrent analysis may attach
# the repeat alert to any of its five input rows, rather than always row five.
def canary_uint:
  type == "number" and . >= 0 and floor == .;

def canary_record_valid($rid; $repeat_key; $cross_key):
  . as $r | .data.capstone_norm as $n | .data.capstone_validation as $v |
  ($r.rule.level == 3 and $r.agent.id == "001" and
   $r.location == "/var/log/capstone-vector/canary/normalized.jsonl" and
   $v.run_id == $rid and $v.kind == "correlation-e2e" and
   $n.schema_version == "vector-1" and $n.pipeline == "vector" and
   $n.sensor == "capstone-canary" and
   ($n.event_id | type) == "string" and
   $n.correlation_dedupe_key == $n.event_id and
   (if $r.rule.id == "100293" then
      $v.scenario == "canary-repeat" and $n.source == "suricata" and
      $n.correlation_key == $repeat_key and ($n.event_id | test("^0{63}[1-5]$"))
    elif $r.rule.id == "100294" then
      $v.scenario == "canary-cross" and $n.source == "nftables" and
      $n.correlation_key == $cross_key and $n.event_id == (("0" * 63) + "2")
    else false end));

def canary_tuple:
  {rule_id: .rule.id, level: .rule.level, agent_id: .agent.id, location: .location,
   kind: .data.capstone_validation.kind, run_id: .data.capstone_validation.run_id,
   scenario: .data.capstone_validation.scenario, source: .data.capstone_norm.source,
   sensor: .data.capstone_norm.sensor, schema_version: .data.capstone_norm.schema_version,
   pipeline: .data.capstone_norm.pipeline,
   correlation_key: .data.capstone_norm.correlation_key,
   correlation_dedupe_key: .data.capstone_norm.correlation_dedupe_key,
   event_id: .data.capstone_norm.event_id};

def canary_records($rid; $repeat_key; $cross_key):
  if type == "array" and length == 2 and
     ([.[].rule.id] | sort) == ["100293", "100294"] and
     all(.[]; canary_record_valid($rid; $repeat_key; $cross_key))
  then map(canary_tuple) | sort_by(.rule_id)
  else error("canary_record_contract") end;

def canary_indexer($rid; $repeat_key; $cross_key):
  if .timed_out == false and (.terminated_early // false) == false and
     (._shards.total | canary_uint) and ._shards.total > 0 and
     (._shards.successful | canary_uint) and ._shards.successful == ._shards.total and
     ._shards.failed == 0 and .hits.total.relation == "eq" and
     .hits.total.value == 2 and (.hits.hits | type) == "array" and
     (.hits.hits | length) == 2
  then [.hits.hits[]._source] | canary_records($rid; $repeat_key; $cross_key)
  else error("canary_indexer_response_contract") end;

# Input is only the bounded current manager tail. Non-matching runs are ignored;
# all records for the selected run must satisfy the same two-record contract.
def canary_manager($rid; $repeat_key; $cross_key):
  [.[] | select(.data.capstone_validation.run_id? == $rid)] |
  canary_records($rid; $repeat_key; $cross_key);

def canary_pair($manager; $indexer):
  if ($manager | type) == "array" and ($indexer | type) == "array" and
     ($manager | length) == 2 and ($indexer | length) == 2 and $manager == $indexer
  then true else error("canary_manager_indexer_tuple_mismatch") end;
