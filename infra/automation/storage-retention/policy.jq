def n: type == "number" and floor == . and . >= 0 and . <= 9007199254740991;
def maybe: . == null or n;
if type != "object" or
   (keys | sort) != (["used_percent","available_bytes","raw_bytes","backup_bytes","history_bytes",
    "raw_archive_review_due_count","backup_review_due_count","scan_status"] | sort) or
   ([.used_percent,.available_bytes,.raw_bytes,.backup_bytes,.history_bytes,
     .raw_archive_review_due_count,.backup_review_due_count] | all(maybe) | not) or
   (.used_percent != null and .used_percent > 100) or
   (.scan_status != "complete" and .scan_status != "unavailable") or
   (.scan_status == "complete" and ([.used_percent,.available_bytes,.raw_bytes,.backup_bytes,
       .history_bytes,.raw_archive_review_due_count,.backup_review_due_count] | any(. == null)))
then error("invalid_measurement")
else . end
| . as $m
| (if (.used_percent != null and .used_percent >= 90) or
       (.available_bytes != null and .available_bytes < 2147483648) or
       (.raw_bytes != null and .raw_bytes >= 5368709120) or
       (.backup_bytes != null and .backup_bytes >= 2147483648) then "critical"
   elif .scan_status == "unavailable" then "unavailable"
   elif (.used_percent != null and .used_percent >= 80) or
        (.raw_bytes != null and .raw_bytes >= 4294967296) or
        (.backup_bytes != null and .backup_bytes >= 1073741824) then "warning"
   else "ok" end) as $status
| $m + {schema_version:1,policy:"capstone-storage-retention-v1",machine_id:$machine,
    host:$host,observed_at_utc:$observed,status:$status,
    reason:({ok:"healthy",warning:"capacity_warning",critical:"capacity_critical",
             unavailable:"scan_unavailable"}[$status]),
    retention_days:(if $host=="a" then 30 else 90 end),
    automatic_deletion:false,checkpoint_changed:false}
