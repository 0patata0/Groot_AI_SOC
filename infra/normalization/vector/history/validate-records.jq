# JSONL, one journal object per physical line. Only metadata leaves this filter.
def record_ok($boot; $until):
  type == "object" and
  ._BOOT_ID == $boot and ._TRANSPORT == "kernel" and
  (.__CURSOR | type == "string" and length > 0 and length <= 2048 and test("^[!-~]+$")) and
  (.__REALTIME_TIMESTAMP | type == "string" and test("^[0-9]{1,16}$")) and
  (.__MONOTONIC_TIMESTAMP | type == "string" and test("^[0-9]{1,16}$")) and
  ((.__REALTIME_TIMESTAMP | tonumber) <= ($until | tonumber));
reduce inputs as $line (
  {count:0,first_cursor:null,last_cursor:null,first_realtime:null,last_realtime:null,
   first_monotonic:null,last_monotonic:null,cursors:{}};
  ($line | fromjson) as $r |
  if ($r | record_ok($boot; $until)) | not then error("invalid_record") else . end |
  if .count >= $max_records or .cursors[$r.__CURSOR] then error("record_limit_or_duplicate_cursor") else . end |
  if .last_monotonic != null and ($r.__MONOTONIC_TIMESTAMP|tonumber) < (.last_monotonic|tonumber)
  then error("monotonic_order") else . end |
  .count += 1 | .cursors[$r.__CURSOR] = true |
  if .count == 1 then .first_cursor=$r.__CURSOR | .first_realtime=$r.__REALTIME_TIMESTAMP |
    .first_monotonic=$r.__MONOTONIC_TIMESTAMP else . end |
  .last_cursor=$r.__CURSOR | .last_realtime=$r.__REALTIME_TIMESTAMP |
  .last_monotonic=$r.__MONOTONIC_TIMESTAMP
) | del(.cursors)
