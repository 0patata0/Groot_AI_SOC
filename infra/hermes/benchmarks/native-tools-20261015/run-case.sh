#!/usr/bin/env bash
# Run one synthetic request; no returned tool is executed. Existing curl/jq only.
set -euo pipefail
umask 077
[[ $# == 3 ]] || { echo 'usage: run-case.sh REQUEST_JSON EXPECTED_TARGET NEW_OUTPUT_DIR' >&2; exit 64; }
request=$(realpath -- "$1")
expected=$2
out=$3
[[ "$expected" == a:waf || "$expected" == b:wazuh-manager ]] || exit 64
mkdir -- "$out"
cp -- "$request" "$out/request.json"
# Failed/partial responses stay private for diagnosis; no unconditional EXIT deletion.
start=$(date '+%Y-%m-%dT%H:%M:%S%z')
set +e
curl -q --connect-timeout 5 --max-time 90 --retry 0 --silent --show-error \
  -H 'Content-Type: application/json' --data-binary "@$out/request.json" \
  --output "$out/response.private.tmp" --write-out '%{json}' \
  http://211.170.162.111:11434/v1/chat/completions > "$out/timing.json" 2> "$out/curl.stderr"
rc=$?
set -e
raw_retained=false
if [[ -f "$out/response.private.tmp" ]]; then
  raw_retained=true
  sha256sum "$out/response.private.tmp" | cut -d ' ' -f1 > "$out/response.sha256"
fi
[[ "$rc" == 0 ]] || {
  jq -n --argjson rc "$rc" --argjson retained "$raw_retained" \
    '{curl_exit:$rc,pass:false,failure:"transport_failed",raw_retained:$retained}' | tee "$out/result.json"
  exit "$rc"
}
set +e
jq -s --arg target "$expected" --arg started "$start" --slurpfile timing "$out/timing.json" '
  def object_or_empty: if type=="object" then . else {} end;
  def array_or_empty: if type=="array" then . else [] end;
  def string_length: if type=="string" then length else 0 end;
  def counter: if type=="number" and .>=0 and floor==. then . else null end;
  . as $documents | (.[0] | object_or_empty) as $r |
  ($r.choices | array_or_empty) as $choices |
  ($choices[0] | object_or_empty) as $choice |
  ($choice.message | object_or_empty) as $m |
  ($m.tool_calls | array_or_empty) as $tc |
  ($timing[0] | object_or_empty) as $t |
  (try (
    ($documents|length)==1 and ($documents[0]|type)=="object" and
    ($timing|length)==1 and $t.http_code==200 and
    ($r.choices|type)=="array" and ($choices|length)==1 and
    ($choice.message|type)=="object" and $m.role=="assistant" and
    $choice.finish_reason=="tool_calls" and
    ($m.tool_calls|type)=="array" and ($tc|length)==1 and
    ($tc[0]|type)=="object" and ($tc[0].id|type)=="string" and
    ($tc[0].id|length)>0 and $tc[0].type=="function" and
    ($tc[0].function|type)=="object" and
    $tc[0].function.name=="get_service_action_target" and
    ($tc[0].function.arguments|type)=="string" and
    (($tc[0].function.arguments|fromjson)=={target:$target})
  ) catch false) as $pass |
  {started:$started,http_status:($t.http_code|counter),seconds:$t.time_total,
   response_documents:($documents|length),choice_count:($choices|length),
   assistant_role:($m.role=="assistant"),
   finish_reason:(if (["tool_calls","stop","length","content_filter"] | index($choice.finish_reason)) != null
                  then $choice.finish_reason else "unknown" end),
   usage:{prompt_tokens:($r.usage.prompt_tokens|counter),
          completion_tokens:($r.usage.completion_tokens|counter),
          total_tokens:($r.usage.total_tokens|counter)},
   content_characters:($m.content|string_length),
   reasoning_characters:(($m.reasoning // $m.reasoning_content)|string_length),
   tool_call_count:($tc|length),pass:$pass,raw_retained:($pass|not),
   actual_tools_executed:0}' \
  "$out/response.private.tmp" > "$out/result.json" 2> "$out/classification.stderr"
classification_rc=$?
set -e
if [[ "$classification_rc" != 0 ]]; then
  jq -n --argjson rc "$classification_rc" \
    '{pass:false,failure:"response_classification_failed",classification_exit:$rc,raw_retained:true}' > "$out/result.json"
  cat -- "$out/result.json"
  exit 74
fi
# Metadata contains lengths/counts only. Successful raw bodies are deliberately removed.
if jq -e '.pass == true' "$out/result.json" >/dev/null; then
  rm -- "$out/response.private.tmp"
fi
cat -- "$out/result.json"
