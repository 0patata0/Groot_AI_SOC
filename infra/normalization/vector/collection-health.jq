# Input is at most the final 1MiB of the metadata file. Drop the two edge
# fragments; malformed complete interior records are an explicit health error.
def valid:
  type == "object" and (keys == ["capstone_collection_health"]) and
  (.capstone_collection_health | type == "object" and
   .schema_version == "1" and (.value | type == "number") and .value >= 0 and
   (.observed_unix | type == "number") and (.observed_unix | floor) == .observed_unix and
   (.vector_pid | type == "string") and (.vector_pid | test("^[0-9]{1,10}$")) and
   (.invocation_id | type == "string") and (.invocation_id | test("^[a-f0-9]{32}$")) and
   (.observed_at_kst | type == "string") and (.observed_at_kst | endswith("+09:00")) and
   (.labels | type == "object" and
    all(to_entries[]; (.key == "error_code" or .key == "error_type" or .key == "stage" or .key == "intentional" or .key == "buffer_type" or .key == "reached_eof") and
      (.value | type == "string" and length <= 80 and test("^[A-Za-z0-9_.:-]+$")) and
      (if .key == "reached_eof" then .value == "true" or .value == "false" else true end))));

def known_metric:
  . as $name |
  ["uptime_seconds", "component_errors_total", "component_discarded_events_total", "files_unwatched_bytes_unread_total", "files_unwatched_with_unknown_bytes_total", "buffer_size_bytes", "buffer_size_events", "buffer_discarded_events_total"] | index($name) != null;
def known_component:
  . as $name | ["vector", "suricata_eve", "waf_audit", "waf_access", "kernel_journal", "normalized", "quarantine", "evidence"] | index($name) != null;
def loss_metric:
  . as $name | ["component_discarded_events_total", "buffer_discarded_events_total", "files_unwatched_bytes_unread_total", "files_unwatched_with_unknown_bytes_total"] | index($name) != null;

(split("\n") | .[1:-1] | map(select(length > 0) | try fromjson catch null)) as $all |
if any($all[]; (try valid catch false) | not) then
  ["collection_telemetry_invalid"]
else
  [$all[] | .capstone_collection_health] as $records |
  if any($records[]; (.metric | known_metric | not) or (.component | known_component | not)) then
    ["collection_telemetry_invalid"]
  else
    [$records[] | select(.vector_pid==$pid and .invocation_id==$invocation and .observed_unix >= ($started-5))] as $epoch |
    [$epoch[] | select(.observed_unix > ($now+5))] as $future |
    [$epoch[] | select(.metric=="uptime_seconds" and .component=="vector")] | sort_by(.observed_unix) | last as $heartbeat |
    if ($future|length)>0 then ["collection_telemetry_invalid"]
    elif $heartbeat==null then
      if ($now-$started)<180 then [] else ["collection_telemetry_missing"] end
    elif ($now-$heartbeat.observed_unix)>180 then ["collection_telemetry_stale"]
    else
      ($epoch | group_by([.component,.metric,.labels]) | map(sort_by(.observed_unix) | last)) as $latest |
      [
        (if any($latest[]; .metric=="component_errors_total" and .value>0) then "collection_error_seen" else empty end),
        (if any($latest[]; (.metric | loss_metric) and .value>0) then "collection_loss_signal_seen" else empty end),
        (if any($latest[]; .metric=="buffer_size_bytes" and .value>=201326616) then "collection_buffer_pressure" else empty end)
      ]
    end
  end
end
