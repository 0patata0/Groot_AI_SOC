# Persistent job metadata only. Raw journal fields/cursors never enter this file.
def hex($n): type == "string" and test("^[0-9a-f]{"+($n|tostring)+"}$");
def uint($max): type == "number" and floor == . and . >= 0 and . <= $max;
def head:
  type == "object" and keys == ["batch_id","manifest_sha256","payload_sha256"] and
  all(.[]; hex(64));
type == "object" and
keys == ["attempts","batches","boot_id","bytes","current_boot_at_discovery","head",
         "last_reason","pending_id","policy","records","schema_version","status","until_epoch_us"] and
.schema_version == 1 and .policy == "bounded-previous-kernel-auto-v1" and
(.boot_id | hex(32)) and (.current_boot_at_discovery | hex(32)) and
.boot_id != .current_boot_at_discovery and
(.until_epoch_us | type == "string" and test("^[1-9][0-9]{0,15}$")) and
(.status | IN("ready","inflight","complete","blocked")) and
(.attempts | uint(3)) and (.batches | uint(256)) and
(.records | uint(256000)) and (.bytes | uint(1073741824)) and
(.last_reason | type == "string" and test("^[a-z_]{1,64}$")) and
(.head == null or (.head | head)) and
(.pending_id == null or (.pending_id | hex(64))) and
((.batches == 0 and .head == null and .records == 0 and .bytes == 0) or
 (.batches > 0 and (.head | head) and .records > 0 and .bytes > 0)) and
((.status == "inflight" and (.pending_id | hex(64)) and .attempts >= 1) or
 (.status != "inflight" and .pending_id == null)) and
(.status != "complete" or .head != null)
