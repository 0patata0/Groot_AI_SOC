def hex64: type == "string" and test("^[a-f0-9]{64}$");
def integer_between($low; $high): type == "number" and floor == . and . >= $low and . <= $high;
type == "object" and
(.policy == "previous-kernel-batch-v1" or .policy == "previous-kernel-continuation-v1") and
(.batch_id | hex64) and .batch_id == $id and
.status == "complete_batch" and .reason == "verified" and
(.boot_id | type == "string" and test("^[a-f0-9]{32}$")) and
(.until_epoch_us | type == "string" and test("^[1-9][0-9]{0,15}$")) and
(.selection | type == "object") and
.selection.transport == "kernel" and
(.selection.max_records | integer_between(1; 1000)) and
(.selection.max_bytes | integer_between(1; 33554432)) and
(.selection.capture_validation_budget_ms | integer_between(1; 15000)) and
.selection.finalization_in_budget == false and
(.bytes | integer_between(1; 33554432)) and .bytes <= .selection.max_bytes and
(.records | integer_between(1; 1000)) and .records <= .selection.max_records and
.physical_newlines == .records and .records_verified == true and
(.sha256 | hex64) and .sha256 == $payload_sha and
(.record_metadata | type == "object") and .record_metadata.count == .records and
(.source_range_exhausted | type == "boolean") and
(.captured_bytes_including_verification | integer_between(1; 33554432)) and
.captured_bytes_including_verification >= .bytes and
.captured_bytes_including_verification <= .selection.max_bytes and
.producer_exit == 0 and .consumer_exit == 0 and
.original_ack_boundary_known == false and .operational_checkpoint_changed == false and
.reinjected == false and .remote_receipt == false and
if .policy == "previous-kernel-batch-v1" then
  .selection.order == "oldest" and (has("parent") | not)
else
  .selection.order == "after_verified_parent_cursor" and
  .continuation_boundary_verified == true and .continuation_phase == "verified" and
  (.parent | type == "object" and keys == ["batch_id", "manifest_sha256", "payload_sha256"]) and
  (.parent.batch_id | hex64) and (.parent.payload_sha256 | hex64) and (.parent.manifest_sha256 | hex64)
end
