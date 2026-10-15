def n: type == "number" and floor == . and . >= 0 and . <= 9007199254740991;
def maybe: . == null or n;
select(type == "object" and
  (keys | sort) == (["schema_version","policy","machine_id","host","observed_at_utc","status","reason","scan_status",
    "used_percent","available_bytes","raw_bytes","backup_bytes","history_bytes","raw_archive_review_due_count",
    "backup_review_due_count","retention_days","automatic_deletion","checkpoint_changed"] | sort) and
  .schema_version == 1 and .policy == "capstone-storage-retention-v1" and
  .machine_id == "1e143067c98a44ffba6eaa925dc038d7" and .host == "b" and .retention_days == 90 and
  .automatic_deletion == false and .checkpoint_changed == false and
  (.observed_at_utc | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")) and
  ([.used_percent,.available_bytes,.raw_bytes,.backup_bytes,.history_bytes,
    .raw_archive_review_due_count,.backup_review_due_count] | all(maybe)) and
  (.used_percent == null or .used_percent <= 100) and
  (.scan_status == "complete" or .scan_status == "unavailable") and
  (.scan_status != "complete" or ([.used_percent,.available_bytes,.raw_bytes,.backup_bytes,.history_bytes,
    .raw_archive_review_due_count,.backup_review_due_count] | all(. != null))))
| . as $v
| (if (.used_percent != null and .used_percent >= 90) or
       (.available_bytes != null and .available_bytes < 2147483648) or
       (.raw_bytes != null and .raw_bytes >= 5368709120) or
       (.backup_bytes != null and .backup_bytes >= 2147483648) then "critical"
   elif .scan_status == "unavailable" then "unavailable"
   elif (.used_percent != null and .used_percent >= 80) or
        (.raw_bytes != null and .raw_bytes >= 4294967296) or
        (.backup_bytes != null and .backup_bytes >= 1073741824) then "warning"
   else "ok" end) as $expected
| select(.status == $expected and .reason == ({ok:"healthy",warning:"capacity_warning",
    critical:"capacity_critical",unavailable:"scan_unavailable"}[$expected]))
