# Input is the scanner envelope. Invalid/ambiguous metadata is unavailable.
def integer: type=="number" and floor==. and .>=0;
def optional_integer: .==null or integer;
def row_valid:
  type=="object" and
  (keys|sort)==(["source","verdict","reason","observed_positive","file_stable","complete_snapshot_range",
    "full_file_scan","range_start","range_end","snapshot_bytes","scanned_bytes","max_line_bytes",
    "line_limit_bytes","scan_budget_bytes","timeout_seconds","leading_fragment_possible"]|sort) and
  (.source=="suricata" or .source=="waf_audit" or .source=="waf_access") and
  (.verdict=="oversize" or .verdict=="within_scanned_range" or .verdict=="inconclusive") and
  (.reason|IN("limit_exceeded","range_within_limit","file_changed","source_unavailable","metadata_mismatch",
             "open_identity_changed","path_rejected","scan_timeout","scan_error","scanner_output_invalid","scanner_failed")) and
  (.observed_positive|type=="boolean") and (.file_stable|type=="boolean") and
  (.complete_snapshot_range|type=="boolean") and (.full_file_scan|type=="boolean") and
  (.leading_fragment_possible==null or (.leading_fragment_possible|type=="boolean")) and
  all([.range_start,.range_end,.snapshot_bytes,.scanned_bytes,.max_line_bytes][];optional_integer) and
  .line_limit_bytes==1048576 and .scan_budget_bytes==33554432 and .timeout_seconds==5 and
  (if .max_line_bytes==null then .observed_positive==false
   else .observed_positive==(.max_line_bytes>.line_limit_bytes) end) and
  (if .range_start==null then .range_end==null and .snapshot_bytes==null and .leading_fragment_possible==null
   else .range_end==.snapshot_bytes and .range_start==([0,.snapshot_bytes-.scan_budget_bytes]|max) and
        .leading_fragment_possible==(.range_start>0) and
        (.scanned_bytes==null or .scanned_bytes<=.range_end-.range_start) and
        (.max_line_bytes==null or (.scanned_bytes!=null and .max_line_bytes<=.scanned_bytes)) end) and
  (if .verdict=="inconclusive" then .complete_snapshot_range==false and .full_file_scan==false
   else .file_stable and .complete_snapshot_range and .range_start!=null and
        .scanned_bytes==.range_end-.range_start and .max_line_bytes!=null and
        .max_line_bytes<=.scanned_bytes and .full_file_scan==(.range_start==0) and
        (if .verdict=="oversize" then .observed_positive and .reason=="limit_exceeded"
         else (.observed_positive|not) and .reason=="range_within_limit" end) end);
def valid:
  type=="object" and .schema_version==1 and .scope=="periodic_snapshot_tail" and
  (.sources|type=="array" and length==3) and
  ([.sources[].source]|sort)==["suricata","waf_access","waf_audit"] and all(.sources[];row_valid);
def statuses_for_envelope:
if (try valid catch false) then
  ([if any(.sources[];.observed_positive) then "collection_raw_line_oversize_seen" else empty end,
    if any(.sources[];.verdict=="inconclusive") then "collection_raw_line_scan_unavailable" else empty end])
else ["collection_raw_line_scan_unavailable"] end;
# One envelope only. A concatenated JSON stream must not yield several results
# that a caller could accidentally treat as the most recent/healthy one.
[.,inputs] | if length==1 then .[0]|statuses_for_envelope
else ["collection_raw_line_scan_unavailable"] end
