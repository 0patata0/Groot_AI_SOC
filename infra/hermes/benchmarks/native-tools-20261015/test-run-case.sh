#!/usr/bin/env bash
# Full runner with a local curl stub: no HTTP/model/tool calls, no new packages.
set -euo pipefail
umask 077
base=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
taskdir=$(mktemp -d "${TMPDIR:-/tmp}/capstone-native-tools-test.XXXXXX")
trap 'rm -rf -- "$taskdir"' EXIT
mkdir "$taskdir/bin"
printf '{}\n' > "$taskdir/request.json"
cat > "$taskdir/bin/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == -q ]] || exit 99
destination=''
while (($#)); do
  if [[ $1 == --output ]]; then destination=$2; shift 2; else shift; fi
done
[[ -n $destination ]] || exit 99
cp -- "$MOCK_RESPONSE" "$destination"
printf '{"http_code":200,"time_total":0.125}\n'
exit "${MOCK_CURL_EXIT:-0}"
MOCK
chmod 700 "$taskdir/bin/curl"
jq -n '{choices:[{message:{role:"assistant",content:"PRIVATE_MARKER",
  reasoning:"PRIVATE_MARKER",tool_calls:[{id:"call-1",type:"function",
  function:{name:"get_service_action_target",arguments:"{\"target\":\"a:waf\"}"}}]},
  finish_reason:"tool_calls"}],usage:{prompt_tokens:12,completion_tokens:8,total_tokens:20}}' > "$taskdir/valid.json"
passed=0
run_case() {
  local name=$1 target=$2 wanted=$3 wanted_rc=$4 fixture=$5 curl_rc=${6:-0} rc
  set +e
  PATH="$taskdir/bin:$PATH" MOCK_RESPONSE="$fixture" MOCK_CURL_EXIT="$curl_rc" \
    bash "$base/run-case.sh" "$taskdir/request.json" "$target" "$taskdir/$name" \
    > "$taskdir/$name.stdout" 2> "$taskdir/$name.stderr"
  rc=$?
  set -e
  if [[ $rc != "$wanted_rc" ]]; then
    printf 'fixture_failed name=%s actual_rc=%s expected_rc=%s\n' "$name" "$rc" "$wanted_rc" >&2
    exit 1
  fi
  jq -se --argjson wanted "$wanted" 'length==1 and .[0].pass==$wanted and
    (.[0]|has("content")|not) and (.[0]|has("tool_calls")|not)' "$taskdir/$name.stdout" >/dev/null || return 1
  ! grep -q PRIVATE_MARKER "$taskdir/$name.stdout" || return 1
  [[ -s "$taskdir/$name/response.sha256" ]] || return 1
  if [[ $wanted == true ]]; then
    [[ ! -e "$taskdir/$name/response.private.tmp" ]] || return 1
    jq -e '.raw_retained==false and .actual_tools_executed==0' "$taskdir/$name/result.json" >/dev/null || return 1
  else
    cmp -- "$fixture" "$taskdir/$name/response.private.tmp" || return 1
    jq -e '.raw_retained==true' "$taskdir/$name/result.json" >/dev/null || return 1
  fi
  passed=$((passed+1))
}
mutate() { jq "$2" "$taskdir/valid.json" > "$taskdir/$1.json"; }
run_case valid_a a:waf true 0 "$taskdir/valid.json"
mutate valid_b '.choices[0].message.tool_calls[0].function.arguments="{\"target\":\"b:wazuh-manager\"}"'
run_case valid_b b:wazuh-manager true 0 "$taskdir/valid_b.json"
mutate truncated '.choices[0].finish_reason="length"'
run_case truncated a:waf false 0 "$taskdir/truncated.json"
mutate text_only '.choices[0].message.content=(.choices[0].message.tool_calls|tojson) | del(.choices[0].message.tool_calls)'
run_case text_only a:waf false 0 "$taskdir/text_only.json"
mutate choices '.choices += .choices'
run_case choices a:waf false 0 "$taskdir/choices.json"
mutate role '.choices[0].message.role="user"'
run_case role a:waf false 0 "$taskdir/role.json"
mutate id '.choices[0].message.tool_calls[0].id=""'
run_case id a:waf false 0 "$taskdir/id.json"
mutate call_type '.choices[0].message.tool_calls[0].type="text"'
run_case call_type a:waf false 0 "$taskdir/call_type.json"
mutate args '.choices[0].message.tool_calls[0].function.arguments="{\"target\":\"a:waf\",\"action\":\"restart\"}"'
run_case args a:waf false 0 "$taskdir/args.json"
cat "$taskdir/valid.json" "$taskdir/valid.json" > "$taskdir/multiple.json"
run_case multiple a:waf false 0 "$taskdir/multiple.json"
printf '{PRIVATE_MARKER\n' > "$taskdir/malformed.json"
run_case malformed a:waf false 74 "$taskdir/malformed.json"
run_case transport a:waf false 28 "$taskdir/valid.json" 28
[[ $passed == 12 ]]
printf '{"status":"passed","cases":%s,"model_calls":0,"tool_calls":0,"packages_installed":0}\n' "$passed"
