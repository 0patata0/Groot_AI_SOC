#!/bin/bash
# Fixed administrator-only five-file metadata CAS. No Docker/systemd mutations,
# alias publication, reader CP writes, raw writes, signal retry or rollback.
# Native Ansible owns candidate preparation and the surrounding lifecycle.
WR_BASE=/var/backups/capstone-waf-recreation-20261015/rebind
WR_LIBRARY=/usr/local/lib/capstone-raw-operations
WR_STATE=/var/lib/capstone-raw-operations
WR_LOCK=/var/lib/capstone-automation/ansible/vector.lock
WR_MANAGED=/home/groot_a/capstone/secstack/logs/modsec/capstone-managed
WR_ALIAS=/home/groot_a/capstone/secstack/logs/modsec/audit.log
WR_NAMES=(vector.env raw-line-binding.json waf-binding.json suricata-state.json modsecurity-state.json)
WR_TARGETS=(/etc/capstone-vector/vector.env /etc/capstone-vector/raw-line-binding.json /etc/capstone-vector/waf-binding.json /var/lib/capstone-raw-operations/suricata/state.json /var/lib/capstone-raw-operations/modsecurity/state.json)
WR_REASON=unspecified
wr_fail() { WR_REASON=$1; return 65; }
wr_sha() { local x; x=$(/usr/bin/sha256sum -- "$1") || return 1; printf '%s\n' "${x%% *}"; }
wr_meta() { /usr/bin/stat -c '%d:%i:%u:%g:%a:%h:%s:%y:%z' -- "$1"; }
wr_parents() {
    local p=$1 mode
    while [[ $p != / ]]; do
        [[ -d $p && ! -L $p && $(/usr/bin/stat -c %u:%g "$p") == 0:0 ]] || return 1
        mode=$(/usr/bin/stat -c %a "$p") || return 1
        (( (8#$mode & 0022)==0 )) || return 1
        p=${p%/*}; [[ -n $p ]] || p=/
    done
}
wr_file() {
    [[ -f $1 && ! -L $1 && $(/usr/bin/stat -c %u:%g:%a:%h "$1") == "0:0:$2:1" &&
       $(/usr/bin/stat -c %s "$1") -le ${3:-32768} ]] && wr_parents "${1%/*}"
}
wr_json() {
    wr_file "$1" "$2" "${3:-32768}" &&
      /usr/bin/jq -se 'length==1' "$1" >/dev/null 2>&1 &&
      /usr/bin/cmp -s -- "$1" <(/usr/bin/jq -cS . "$1" 2>/dev/null)
}
wr_plan() {
    local i n p old new
    [[ -d $WR_BASE && ! -L $WR_BASE && $(/usr/bin/stat -c %u:%g:%a "$WR_BASE") == 0:0:700 ]] || return 1
    wr_json "$WR_BASE/plan.json" 400 16384 || return 1
    /usr/bin/jq -e '
      def hex($n): type=="string" and test("^[a-f0-9]{"+($n|tostring)+"}$");
      def integer: type=="number" and floor==. and .>=0 and .<=9007199254740991;
      keys==["authority","boot_id","files","machine_id","policy","schema_version"] and
      .schema_version==1 and .policy=="capstone-waf-rebind-metadata-v1" and
      .machine_id=="096e90b6243e438aa8a7b392be754732" and (.boot_id|hex(32)) and
      (.files|type=="array" and length==5) and
      [.files[].name]==["vector.env","raw-line-binding.json","waf-binding.json","suricata-state.json","modsecurity-state.json"] and
      all(.files[];keys==["after_sha256","before_sha256","name"] and
        (.before_sha256|hex(64)) and (.after_sha256|hex(64)) and .before_sha256!=.after_sha256) and
      (.authority|keys==["barrier_sha256","new_binding","new_container","new_producer_sha256","old_container","runtime_sha256","stop_proof_sha256","unit_execstartpre_sha256","wazuh"] and
        (.barrier_sha256|hex(64)) and (.stop_proof_sha256|hex(64)) and
        (.new_binding|hex(64)) and (.new_producer_sha256|hex(64)) and
        (.unit_execstartpre_sha256|keys==["vector","wazuh"] and all(.[];hex(64))) and
        (.runtime_sha256|keys==["checkpoint-gates.jq","checkpoint-gates.sh","coordinator.sh","guard.sh","state-lib.sh","state.jq","writer-gates.sh"] and all(.[];hex(64))) and
        (.old_container|keys==["cid","image","pid","start_ticks"] and (.cid|hex(64)) and
          (.image|test("^sha256:[a-f0-9]{64}$")) and (.pid|integer) and .pid>1 and
          (.start_ticks|type=="string" and test("^[1-9][0-9]{0,19}$"))) and
        (.new_container|keys==["identity","image","started_at"] and
          (.image|type=="string" and test("^sha256:[a-f0-9]{64}$")) and
          (.started_at|type=="string" and length>10 and length<100) and
          (.identity|keys==["cid","gid","mount_ns","pid","pid_ns","start_ticks","uid"] and
            (.cid|hex(64)) and .uid==101 and .gid==101 and (.pid|integer) and .pid>1 and
            (.start_ticks|type=="string" and test("^[1-9][0-9]{0,19}$")) and
            (.mount_ns|type=="string" and test("^mnt:\\[[0-9]+\\]$")) and
            (.pid_ns|type=="string" and test("^pid:\\[[0-9]+\\]$")))) and
        .old_container.cid!=.new_container.identity.cid and .old_container.image==.new_container.image and
        (.wazuh|keys==["invocation_id","pid","start_ticks"] and (.invocation_id|hex(32)) and
          (.pid|integer) and .pid>1 and (.start_ticks|type=="string" and test("^[1-9][0-9]{0,19}$"))))
      ' "$WR_BASE/plan.json" >/dev/null 2>&1 || return 1
    WR_PLAN_SHA=$(wr_sha "$WR_BASE/plan.json") || return 1
    for i in 0 1 2 3 4; do
        n=${WR_NAMES[$i]}
        for p in before after; do
            wr_file "$WR_BASE/$p/$n" 400 16384 || return 1
            [[ $(wr_sha "$WR_BASE/$p/$n") == "$(/usr/bin/jq -r --argjson i "$i" --arg key "${p}_sha256" '.files[$i][$key]' "$WR_BASE/plan.json")" ]] || return 1
            [[ $i == 0 ]] || wr_json "$WR_BASE/$p/$n" 400 16384 || return 1
        done
    done
    wr_candidates || return 1
    wr_file "$WR_BASE/new-producer.conf" 400 16384 &&
      [[ $(wr_sha "$WR_BASE/new-producer.conf") == "$(/usr/bin/jq -r .authority.new_producer_sha256 "$WR_BASE/plan.json")" ]] || return 1
    # Exactly two literal binding replacements; reverting them must reproduce
    # the previously pinned stable producer bytes, without exporting the text.
    old=$(/usr/bin/jq -r .deployment_binding "$WR_BASE/before/waf-binding.json")
    new=$(/usr/bin/jq -r .authority.new_binding "$WR_BASE/plan.json")
    /usr/bin/jq -ne --rawfile raw "$WR_BASE/new-producer.conf" --arg new "$new" '($raw|split($new)|length)==3' >/dev/null || return 1
    p=$(/usr/bin/jq -nj --rawfile raw "$WR_BASE/new-producer.conf" --arg new "$new" --arg old "$old" \
      '$raw|split($new)|join($old)' | /usr/bin/sha256sum) || return 1
    [[ ${p%% *} == "$(/usr/bin/jq -r .configuration_sha256 "$WR_BASE/before/waf-binding.json")" ]] || return 1
    wr_json "$WR_BASE/stop-proof.json" 400 4096 &&
      [[ $(wr_sha "$WR_BASE/stop-proof.json") == "$(/usr/bin/jq -r .authority.stop_proof_sha256 "$WR_BASE/plan.json")" ]] || return 1
    /usr/bin/jq -e --slurpfile plan "$WR_BASE/plan.json" '
      keys==["after_status","before_status","boot_id","invocation_id","new_cid","old_cid","old_state_sha256","policy","schema_version","start_usec","stop_armed","stopped_clean"] and
      .schema_version==1 and .policy=="capstone-waf-rebind-vector-stop-v1" and
      .boot_id==$plan[0].boot_id and .old_cid==$plan[0].authority.old_container.cid and
      .new_cid==$plan[0].authority.new_container.identity.cid and
      (.invocation_id|type=="string" and test("^[a-f0-9]{32}$")) and
      (.start_usec|type=="string" and test("^[1-9][0-9]{0,17}$")) and
      .old_state_sha256==$plan[0].files[4].before_sha256 and
      (all([.before_status,.after_status][];
        keys==["ActiveState","ExecMainStartTimestampMonotonic","ExecMainStatus","InvocationID","MainPID","Result","SubState"] and all(.[];type=="string"))) and
      .before_status.ActiveState=="active" and .before_status.SubState=="running" and
      (.before_status.MainPID|test("^[1-9][0-9]*$")) and .before_status.Result=="success" and
      .before_status.InvocationID==.invocation_id and .before_status.ExecMainStartTimestampMonotonic==.start_usec and
      .after_status.ActiveState=="inactive" and .after_status.SubState=="dead" and .after_status.MainPID=="0" and
      .after_status.Result=="success" and .after_status.ExecMainStatus=="0" and
      (.after_status.InvocationID=="" or .after_status.InvocationID==.invocation_id) and
      .after_status.ExecMainStartTimestampMonotonic==.start_usec and
      .stop_armed==true and .stopped_clean==true' "$WR_BASE/stop-proof.json" >/dev/null 2>&1
}
wr_candidates() {
    local e side old_env new_env
    for e in suricata modsecurity; do
        for side in before after; do
            /usr/bin/jq -e -f "$WR_LIBRARY/state.jq" "$WR_BASE/$side/$e-state.json" >/dev/null 2>&1 || return 1
            /usr/bin/jq -e --arg e "$e" '.engine==$e' "$WR_BASE/$side/$e-state.json" >/dev/null || return 1
        done
    done
    old_env=$(wr_sha "$WR_BASE/before/vector.env") && new_env=$(wr_sha "$WR_BASE/after/vector.env") || return 1
    /usr/bin/jq -ne --slurpfile p "$WR_BASE/plan.json" \
      --slurpfile s "$WR_BASE/before/suricata-state.json" --slurpfile sn "$WR_BASE/after/suricata-state.json" \
      --slurpfile w "$WR_BASE/before/modsecurity-state.json" --slurpfile wn "$WR_BASE/after/modsecurity-state.json" \
      --slurpfile b "$WR_BASE/before/waf-binding.json" --slurpfile bn "$WR_BASE/after/waf-binding.json" \
      --slurpfile l "$WR_BASE/before/raw-line-binding.json" --slurpfile ln "$WR_BASE/after/raw-line-binding.json" \
      --arg old "$old_env" --arg new "$new_env" '
      $s[0] as $s|$sn[0] as $sn|$w[0] as $w|$wn[0] as $wn|$b[0] as $b|$bn[0] as $bn|$l[0] as $l|$ln[0] as $ln|
      $s.phase=="active" and $w.phase=="active" and $s.revision==5 and $w.revision==11 and
      $s.current.number==1 and $w.current.number==3 and
      $s.source_pins.vector_env_sha256==$old and $w.source_pins.vector_env_sha256==$old and
      $w.source_pins.container_id==$p[0].authority.old_container.cid and
      $sn==($s|.revision=6|.source_pins.vector_env_sha256=$new) and
      $wn.revision==12 and $wn.phase=="publish_pending" and $wn.current==$w.current and
      $wn.pending.number==4 and $wn.boot_id==$p[0].boot_id and
      ($wn|del(.revision,.phase,.pending,.proof,.source_pins,.boot_id))==($w|del(.revision,.phase,.pending,.proof,.source_pins,.boot_id)) and
      $wn.source_pins==($w.source_pins|.container_id=$p[0].authority.new_container.identity.cid|
        .producer_format_sha256=$bn.configuration_sha256|.vector_env_sha256=$new) and
      $wn.proof.old_closed.boot_id==$p[0].boot_id and
      $wn.proof.old_closed.writer_pid==$p[0].authority.old_container.pid and
      ($wn.proof.old_closed.writer_start_ticks|tostring)==$p[0].authority.old_container.start_ticks and
      $w.source_pins.vector_config_sha256==$s.source_pins.vector_config_sha256 and
      $w.source_pins.wazuh_config_sha256==$s.source_pins.wazuh_config_sha256 and
      $b.schema=="waf-producer-deployment-2" and $b.schema_version==2 and
      $b.machine_id==$p[0].machine_id and $b.container_name=="waf" and
      $b.instance_id==$w.source_pins.container_id and $b.configuration_sha256==$w.source_pins.producer_format_sha256 and
      $b.audit_path=="/home/groot_a/capstone/secstack/logs/modsec/audit.log" and
      $b.access_path=="/home/groot_a/capstone/secstack/logs/modsec/capstone-access.log" and
      $bn.instance_id==$p[0].authority.new_container.identity.cid and
      $bn.deployment_binding==$p[0].authority.new_binding and $bn.configuration_sha256==$p[0].authority.new_producer_sha256 and
      ($bn.deployment_binding|type=="string" and test("^[a-f0-9]{64}$")) and $bn.deployment_binding!=$b.deployment_binding and
      ($bn.configuration_sha256|type=="string" and test("^[a-f0-9]{64}$")) and $bn.configuration_sha256!=$b.configuration_sha256 and
      ($bn|del(.instance_id,.configuration_sha256,.deployment_binding))==($b|del(.instance_id,.configuration_sha256,.deployment_binding)) and
      $l=={schema_version:1,policy:"periodic-snapshot-tail-v1",vector_config_sha256:$w.source_pins.vector_config_sha256,vector_env_sha256:$old} and
      $ln==($l|.vector_env_sha256=$new)' >/dev/null 2>&1 || return 1
    # The three binding lines are the only byte changes. Never source the env.
    /usr/bin/jq -Rsen --rawfile old "$WR_BASE/before/vector.env" --rawfile new "$WR_BASE/after/vector.env" \
      --slurpfile b "$WR_BASE/before/waf-binding.json" --slurpfile a "$WR_BASE/after/waf-binding.json" '
      def frame: endswith("\n") and (contains("\r")|not) and (contains("\u0000")|not);
      def keys: ["WAF_INSTANCE_ID","WAF_CONFIG_SHA256","WAF_DEPLOYMENT_BINDING"];
      def wanted($m): [$m.instance_id,$m.configuration_sha256,$m.deployment_binding];
      def check($m): . as $text | all(range(0;3); . as $i|
        ([$text|split("\n")[]|select(startswith(keys[$i]+"="))])==[keys[$i]+"="+wanted($m)[$i]]);
      def replace($m): split("\n")|map(. as $line|
        if startswith("WAF_INSTANCE_ID=") then "WAF_INSTANCE_ID="+$m.instance_id
        elif startswith("WAF_CONFIG_SHA256=") then "WAF_CONFIG_SHA256="+$m.configuration_sha256
        elif startswith("WAF_DEPLOYMENT_BINDING=") then "WAF_DEPLOYMENT_BINDING="+$m.deployment_binding
        else $line end)|join("\n");
      ($old|frame and check($b[0])) and ($new|frame and check($a[0])) and ($old|replace($a[0]))==$new and
      ([$old|split("\n")[]|select(startswith("WAF_AUDIT_PATH="))])==["WAF_AUDIT_PATH=/home/groot_a/capstone/secstack/logs/modsec/audit.log"] and
      ([$old|split("\n")[]|select(startswith("WAF_ACCESS_PATH="))])==["WAF_ACCESS_PATH=/home/groot_a/capstone/secstack/logs/modsec/capstone-access.log"]
      ' >/dev/null 2>&1
}
wr_prefix() {
    local i n actual old new seen_before=false prefix=0
    for i in 0 1 2 3 4; do
        n=${WR_NAMES[$i]}
        wr_file "${WR_TARGETS[$i]}" 600 16384 || return 1
        actual=$(wr_sha "${WR_TARGETS[$i]}") || return 1
        old=$(/usr/bin/jq -r --argjson i "$i" '.files[$i].before_sha256' "$WR_BASE/plan.json") || return 1
        new=$(/usr/bin/jq -r --argjson i "$i" '.files[$i].after_sha256' "$WR_BASE/plan.json") || return 1
        if [[ $actual == "$new" ]]; then [[ $seen_before == false ]] || return 1; prefix=$((prefix+1))
        elif [[ $actual == "$old" ]]; then seen_before=true
        else return 1; fi
    done
    WR_PREFIX=$prefix
}
wr_atomic() {
    local path=$1 source=$2 mode=$3 expected=$4 temp digest current before_meta
    digest=$(wr_sha "$source") || return 1
    if [[ $expected == absent ]]; then [[ ! -e $path && ! -L $path ]] || return 1
    else wr_file "$path" "$mode" && [[ $(wr_sha "$path") == "$expected" ]] || return 1
        before_meta=$(wr_meta "$path") || return 1; fi
    temp=$(/usr/bin/mktemp "${path%/*}/.next.XXXXXXXX") || return 1
    /bin/cat -- "$source" > "$temp" && /bin/chmod "$mode" "$temp" &&
      [[ $(wr_sha "$temp") == "$digest" ]] && /bin/sync -- "$temp" || return 1
    if [[ $expected == absent ]]; then
        /bin/mv -T -n -- "$temp" "$path" && [[ ! -e $temp ]] || return 1
    else
        wr_file "$path" "$mode" && [[ $(wr_sha "$path") == "$expected" && $(wr_meta "$path") == "$before_meta" ]] || return 1
        /bin/mv -T -- "$temp" "$path" || return 1
    fi
    /bin/sync -- "$path" "${path%/*}" && wr_file "$path" "$mode" && [[ $(wr_sha "$path") == "$digest" ]]
}
wr_record() {
    local name=$1 content=$2 mode=$3 expected=$4 tmp
    tmp=$(/usr/bin/mktemp "$WR_BASE/.record.XXXXXXXX") || return 1
    printf '%s\n' "$content" > "$tmp" && /bin/chmod 600 "$tmp" || return 1
    wr_atomic "$WR_BASE/$name" "$tmp" "$mode" "$expected" || return 1
    /bin/rm -- "$tmp"
}
wr_intent_read() {
    wr_json "$WR_BASE/intent.json" 600 4096 || return 1
    /usr/bin/jq -e --arg sha "$WR_PLAN_SHA" '
      keys==["attempted","complete","plan_sha256","policy","prefix","schema_version"] and
      .schema_version==1 and .policy=="capstone-waf-rebind-metadata-v1" and .plan_sha256==$sha and
      (.prefix|type=="number" and floor==. and .>=0 and .<=5) and
      (.complete|type=="boolean") and (.complete==false or (.prefix==5 and .attempted==null)) and
      (.attempted==null or (.prefix<5 and .attempted==["vector.env","raw-line-binding.json","waf-binding.json","suricata-state.json","modsecurity-state.json"][.prefix]))
      ' "$WR_BASE/intent.json" >/dev/null 2>&1 || return 1
    WR_INTENT_SHA=$(wr_sha "$WR_BASE/intent.json") || return 1
}
wr_intent_set() {
    local prefix=$1 attempted=$2 complete=$3 expected=${4:-$WR_INTENT_SHA} value
    value=$(/usr/bin/jq -ncS --arg sha "$WR_PLAN_SHA" --argjson prefix "$prefix" --arg attempted "$attempted" --argjson complete "$complete" \
      '{schema_version:1,policy:"capstone-waf-rebind-metadata-v1",plan_sha256:$sha,prefix:$prefix,
        attempted:(if $attempted=="" then null else $attempted end),complete:$complete}') || return 1
    wr_record intent.json "$value" 600 "$expected" && wr_intent_read
}
wr_receipt() {
    local i=$1 n value path
    n=${WR_NAMES[$i]}; path="receipts/$i-$n.json"
    value=$(/usr/bin/jq -ncS --arg sha "$WR_PLAN_SHA" --argjson i "$i" --slurpfile p "$WR_BASE/plan.json" \
      '{schema_version:1,plan_sha256:$sha,index:$i,file:$p[0].files[$i],verified_after:true}') || return 1
    if [[ -e $WR_BASE/$path || -L $WR_BASE/$path ]]; then
        wr_json "$WR_BASE/$path" 400 4096 && /usr/bin/cmp -s "$WR_BASE/$path" <(printf '%s\n' "$value") &&
          /bin/sync -- "$WR_BASE/$path" "$WR_BASE/receipts"
    else wr_record "$path" "$value" 400 absent; fi
}
wr_history() {
    local i=$1 e rev sha dir archive source
    (( i>=3 )) || return 0
    [[ $i == 3 ]] && e=suricata || e=modsecurity
    source=$WR_BASE/before/$e-state.json
    rev=$(/usr/bin/jq -r .revision "$source") && sha=$(wr_sha "$source") || return 1
    dir=$WR_STATE/$e/history; archive=$dir/$rev-$sha.json
    wr_parents "$dir" && [[ $(/usr/bin/stat -c %u:%g:%a "$dir") == 0:0:700 ]] || return 1
    (( $(/usr/bin/find "$dir" -mindepth 1 -maxdepth 1 -printf '.\n' | /usr/bin/wc -l)<1024 )) || return 1
    if [[ -e $archive || -L $archive ]]; then
        wr_file "$archive" 400 16384 && [[ $(wr_sha "$archive") == "$sha" ]] || return 1
    else wr_atomic "$archive" "$source" 400 absent || return 1; fi
    /bin/sync -- "$archive" "$dir"
}
wr_apply() {
    local i n old observed committed attempted
    wr_plan && wr_prefix || { wr_fail invalid_plan_or_target_prefix; return 65; }
    wr_preconditions full || { wr_fail live_precondition_refused; return 65; }
    if [[ ! -e $WR_BASE/intent.json && ! -L $WR_BASE/intent.json ]]; then
        [[ $WR_PREFIX == 0 ]] || { wr_fail unowned_partial_publication; return 65; }
        wr_intent_set 0 '' false absent || { wr_fail intent_publish_uncertain; return 65; }
    else wr_intent_read || { wr_fail invalid_intent; return 65; }; fi
    committed=$(/usr/bin/jq -r .prefix "$WR_BASE/intent.json")
    attempted=$(/usr/bin/jq -r '.attempted//""' "$WR_BASE/intent.json")
    if (( WR_PREFIX!=committed )); then
        [[ $WR_PREFIX == $((committed+1)) && $committed -lt 5 && $attempted == "${WR_NAMES[$committed]}" ]] ||
          { wr_fail intent_target_prefix_conflict; return 65; }
        wr_history "$committed" && /bin/sync -- "${WR_TARGETS[$committed]}" "${WR_TARGETS[$committed]%/*}" &&
          wr_receipt "$committed" && wr_intent_set "$WR_PREFIX" '' false || { wr_fail recovered_publication_sync_failed; return 65; }
    fi
    for ((i=0;i<WR_PREFIX;i++)); do wr_history "$i" && wr_receipt "$i" || return 65; done
    for ((i=WR_PREFIX;i<5;i++)); do
        n=${WR_NAMES[$i]}
        wr_plan && wr_prefix && [[ $WR_PREFIX == "$i" ]] && wr_preconditions light || { wr_fail before_cas_conflict; return 65; }
        wr_intent_set "$i" "$n" false && wr_history "$i" || { wr_fail prepublication_durability_failed; return 65; }
        old=$(/usr/bin/jq -r --argjson i "$i" '.files[$i].before_sha256' "$WR_BASE/plan.json") || return 65
        wr_atomic "${WR_TARGETS[$i]}" "$WR_BASE/after/$n" 600 "$old" || { wr_fail publication_outcome_unknown_inspect_required; return 65; }
        wr_prefix && [[ $WR_PREFIX == $((i+1)) ]] && wr_preconditions light && wr_receipt "$i" &&
          wr_intent_set "$WR_PREFIX" '' false || { wr_fail postpublication_verification_failed; return 65; }
    done
    wr_plan && wr_prefix && [[ $WR_PREFIX == 5 ]] && wr_preconditions full || { wr_fail final_verification_failed; return 65; }
    wr_intent_set 5 '' true || { wr_fail completion_sync_uncertain; return 65; }
    # Actual lifecycle and alias publication are deliberately not authorized here.
    local result
    result=$(/usr/bin/jq -ncS --arg sha "$WR_PLAN_SHA" \
      '{schema_version:1,policy:"capstone-waf-rebind-metadata-v1",status:"metadata_applied",plan_sha256:$sha,files:5,
        alias_published:false,reader_start_authorized:false,signals_sent:0,raw_written:false,checkpoint_written:false}') || return 65
    if [[ -e $WR_BASE/result.json || -L $WR_BASE/result.json ]]; then
        wr_json "$WR_BASE/result.json" 400 && /usr/bin/cmp -s "$WR_BASE/result.json" <(printf '%s\n' "$result") &&
          /bin/sync -- "$WR_BASE/result.json" "$WR_BASE" || return 65
    else wr_record result.json "$result" 400 absent || return 65; fi
    printf '%s\n' "$result"
}

# The test replaces this live boundary explicitly after sourcing the library;
# fixture execution never invokes wr_main or reads production paths.
wr_show() {
    local unit=$1 value; shift
    value=$(/usr/bin/timeout --kill-after=1s 5s /usr/bin/systemctl show "$unit" "$@" 2>/dev/null) || return 1
    (( ${#value}<=16384 )) || return 1
    printf '%s\n' "$value" | /usr/bin/jq -Rsce '
      split("\n")|map(select(length>0)|split("="))|
      select(length>0 and all(.[];length==2) and (map(.[0])|unique|length)==length)|
      map({key:.[0],value:.[1]})|from_entries'
}
wr_ticks() {
    [[ $1 =~ ^[1-9][0-9]{0,9}$ ]] || return 1
    /usr/bin/awk '{sub(/^.*\) /, ""); if($1=="Z"||$1=="X"||NF<20)exit 1;print $20}' "/proc/$1/stat"
}
wr_container() {
    /usr/bin/timeout --kill-after=1s 8s /usr/local/bin/docker inspect --format \
      '{"cid":{{json .Id}},"image":{{json .Image}},"name":{{json .Name}},"running":{{json .State.Running}},"pid":{{json .State.Pid}},"restarting":{{json .State.Restarting}},"paused":{{json .State.Paused}},"dead":{{json .State.Dead}},"started_at":{{json .State.StartedAt}}}' "$1" 2>/dev/null
}
wr_barriers() {
    local role unit file actual expected source
    expected=$(printf '[Service]\nExecStartPre=/usr/bin/false\n' | /usr/bin/sha256sum); expected=${expected%% *}
    [[ $expected == "$(/usr/bin/jq -r .authority.barrier_sha256 "$WR_BASE/plan.json")" ]] || return 1
    for role in vector wazuh; do
        [[ $role == vector ]] && unit=capstone-vector.service || unit=wazuh-agent.service
        file=/etc/systemd/system/$unit.d/99-capstone-waf-rebind-block.conf
        wr_file "$file" 644 1024 && [[ $(wr_sha "$file") == "$expected" ]] || return 1
        actual=$(/usr/bin/timeout --kill-after=1s 5s /usr/bin/systemctl show "$unit" --value -p ExecStartPre 2>/dev/null) || return 1
        (( ${#actual}<=16384 )) &&
          [[ $actual == *"argv[]=/bin/bash /usr/local/lib/capstone-raw-operations/guard.sh $role ;"* ]] || return 1
        [[ $(printf '%s\n' "$actual" | /usr/bin/awk -F 'argv\\[\\]=/usr/bin/false ;' '{n+=NF-1}END{print n}') == 1 ]] || return 1
        source=$(printf '%s\n' "$actual" | /usr/bin/sha256sum) || return 1
        [[ ${source%% *} == "$(/usr/bin/jq -r --arg r "$role" '.authority.unit_execstartpre_sha256[$r]' "$WR_BASE/plan.json")" ]] || return 1
        [[ $(/usr/bin/timeout --kill-after=1s 5s /usr/bin/systemctl show "$unit" --value -p NeedDaemonReload 2>/dev/null) == no ]] || return 1
    done
}
wr_services() {
    local unit status pid ticks inv marker
    for unit in capstone-raw-operations@suricata.timer capstone-raw-operations@modsecurity.timer capstone-vector-maintenance.timer; do
        status=$(wr_show "$unit" -p ActiveState -p UnitFileState) || return 1
        /usr/bin/jq -e 'keys==["ActiveState","UnitFileState"] and .ActiveState=="inactive" and .UnitFileState=="disabled"' <<< "$status" >/dev/null || return 1
    done
    for unit in capstone-raw-operations@suricata.service capstone-raw-operations@modsecurity.service capstone-vector-maintenance.service; do
        status=$(wr_show "$unit" -p ActiveState -p MainPID -p SubState) || return 1
        /usr/bin/jq -e 'keys==["ActiveState","MainPID","SubState"] and .MainPID=="0" and
          ((.ActiveState=="inactive" and .SubState=="dead") or (.ActiveState=="failed" and .SubState=="failed"))' <<< "$status" >/dev/null || return 1
    done
    for marker in /var/lib/capstone-vector-maintenance/resume.pending "$WR_STATE/vector-stop-intent.json" \
      "$WR_STATE/suricata/writer-reopen-intent.json" "$WR_STATE/modsecurity/writer-reopen-intent.json"; do
        [[ ! -e $marker && ! -L $marker ]] || return 1
    done
    status=$(wr_show capstone-vector.service -p ActiveState -p SubState -p MainPID -p Result -p ExecMainStatus -p InvocationID -p ExecMainStartTimestampMonotonic) || return 1
    /usr/bin/jq -e --slurpfile proof "$WR_BASE/stop-proof.json" '
      keys==["ActiveState","ExecMainStartTimestampMonotonic","ExecMainStatus","InvocationID","MainPID","Result","SubState"] and
      .ActiveState=="inactive" and .SubState=="dead" and .MainPID=="0" and .Result=="success" and .ExecMainStatus=="0" and
      .ExecMainStartTimestampMonotonic==$proof[0].start_usec and
      (.InvocationID=="" or .InvocationID==$proof[0].invocation_id)' <<< "$status" >/dev/null || return 1
    status=$(wr_show wazuh-agent.service -p ActiveState -p SubState -p InvocationID) || return 1
    /usr/bin/jq -e --slurpfile p "$WR_BASE/plan.json" '.ActiveState=="active" and .SubState=="running" and
      .InvocationID==$p[0].authority.wazuh.invocation_id' <<< "$status" >/dev/null || return 1
    pid=$(/usr/bin/jq -r .authority.wazuh.pid "$WR_BASE/plan.json")
    ticks=$(/usr/bin/jq -r .authority.wazuh.start_ticks "$WR_BASE/plan.json")
    [[ $(wr_ticks "$pid") == "$ticks" && $(/usr/bin/readlink "/proc/$pid/exe") == /var/ossec/bin/wazuh-logcollector ]]
}
wr_writers() {
    local old new actual identity expected path sha cid
    old=$(/usr/bin/jq -r .authority.old_container.cid "$WR_BASE/plan.json") || return 1
    actual=$(wr_container "$old") || return 1
    /usr/bin/jq -e --slurpfile p "$WR_BASE/plan.json" '
      .cid==$p[0].authority.old_container.cid and .image==$p[0].authority.old_container.image and
      .name=="/waf-before-20261015" and .running==false and .pid==0 and .restarting==false and .paused==false and .dead==false
      ' <<< "$actual" >/dev/null || return 1
    actual=$(wr_container waf) || return 1
    /usr/bin/jq -e --slurpfile p "$WR_BASE/plan.json" '
      .cid==$p[0].authority.new_container.identity.cid and .image==$p[0].authority.new_container.image and
      .name=="/waf" and .running==true and .pid==$p[0].authority.new_container.identity.pid and
      .started_at==$p[0].authority.new_container.started_at and .restarting==false and .paused==false and .dead==false
      ' <<< "$actual" >/dev/null || return 1
    identity=$(writer_identity waf) || return 1
    /usr/bin/jq -e --slurpfile p "$WR_BASE/plan.json" '.status=="observed" and .identity==$p[0].authority.new_container.identity' <<< "$identity" >/dev/null || return 1
    cid=$(/usr/bin/jq -r .authority.new_container.identity.cid "$WR_BASE/plan.json") || return 1
    for path in /etc/modsecurity.d/modsecurity-override.conf /etc/nginx/conf.d/zz-capstone-evidence.conf; do
        if [[ $path == /etc/modsecurity.d/modsecurity-override.conf ]]; then
            expected=$(/usr/bin/jq -r .source_pins.engine_config_sha256 "$WR_BASE/after/modsecurity-state.json")
        else expected=$(/usr/bin/jq -r .authority.new_producer_sha256 "$WR_BASE/plan.json"); fi
        actual=$(/usr/bin/timeout --kill-after=1s 8s /usr/local/bin/docker exec --user 0 "$cid" /usr/bin/sha256sum -- "$path" 2>/dev/null) || return 1
        [[ $actual == "$expected  $path" ]] || return 1
    done
}
wr_raw() {
    local scope=$1 old new od oi nd ni size hash pointer expected identity oldproof newproof rc=0 common newsize
    local managed=$WR_MANAGED alias=$WR_ALIAS parent=$WR_MANAGED
    while [[ $parent != / ]]; do [[ -d $parent && ! -L $parent ]] || return 1; parent=${parent%/*}; [[ -n $parent ]] || parent=/; done
    [[ $(/usr/bin/stat -c %u:%g:%a "$managed") == 0:0:711 ]] || return 1
    old=$managed/$(/usr/bin/jq -r .current.basename "$WR_BASE/after/modsecurity-state.json")
    new=$managed/$(/usr/bin/jq -r .pending.basename "$WR_BASE/after/modsecurity-state.json")
    od=$(/usr/bin/jq -r .current.device "$WR_BASE/after/modsecurity-state.json")
    oi=$(/usr/bin/jq -r .current.inode "$WR_BASE/after/modsecurity-state.json")
    nd=$(/usr/bin/jq -r .pending.device "$WR_BASE/after/modsecurity-state.json")
    ni=$(/usr/bin/jq -r .pending.inode "$WR_BASE/after/modsecurity-state.json")
    size=$(/usr/bin/jq -r .proof.old_closed.bytes "$WR_BASE/after/modsecurity-state.json")
    hash=$(/usr/bin/jq -r .proof.old_closed.sha256 "$WR_BASE/after/modsecurity-state.json")
    [[ -f $old && ! -L $old && -f $new && ! -L $new && -f $alias && ! -L $alias &&
       $(/usr/bin/stat -c %d:%i:%u:%g:%a:%h:%s "$old") == "$od:$oi:0:0:400:2:$size" &&
       $(/usr/bin/stat -c %d:%i "$alias") == "$od:$oi" &&
       $(/usr/bin/stat -c %d:%i:%u:%g:%a:%h "$new") == "$nd:$ni:101:101:644:1" ]] || return 1
    pointer=$managed/audit-path.conf
    [[ -f $pointer && ! -L $pointer && $(/usr/bin/stat -c %u:%g:%a:%h "$pointer") == 0:0:444:1 &&
       $(wr_sha "$pointer") == "$(/usr/bin/jq -r .pending.writer_config_sha256 "$WR_BASE/after/modsecurity-state.json")" ]] || return 1
    /usr/bin/cmp -s "$pointer" <(printf 'SecAuditLog /var/log/modsecurity/capstone-managed/%s\n' "${new##*/}") || return 1
    newsize=$(/usr/bin/stat -c %s "$new") || return 1
    (( size<=536870912 && newsize<=2147483648 )) || return 1
    if (( size>0 )); then
        common=$size; (( newsize>=common )) || common=$newsize
        (( common>0 )) || return 1
        /usr/bin/cmp -s -n "$common" "$old" "$new" || rc=$?
        [[ $rc == 1 ]] || return 1
    fi
    [[ $scope == full ]] || return 0
    [[ $(wr_sha "$old") == "$hash" ]] || return 1
    identity=$(/usr/bin/jq -cS .authority.new_container.identity "$WR_BASE/plan.json") || return 1
    oldproof=$(writer_gate waf "$identity" "$od" "$oi") || return 1
    rc=0; newproof=$(writer_gate waf "$identity" "$nd" "$ni") || rc=$?
    [[ $rc == 10 ]] || return 1
    /usr/bin/jq -ne --argjson a "$oldproof" --argjson b "$newproof" --argjson id "$identity" \
      --arg od "$od" --arg oi "$oi" --arg nd "$nd" --arg ni "$ni" '
      def members: .processes|map(del(.scanned_fd_count,.matching_fd_count,.writable_fd_count))|sort_by(.pid);
      $a.status=="closed" and $a.writable_fd_count==0 and $b.status=="open" and $b.writable_fd_count>0 and
      $a.identity==$id and $b.identity==$id and $a.target=={device:$od,inode:$oi} and $b.target=={device:$nd,inode:$ni} and
      $a.membership_stable==true and $b.membership_stable==true and ($a|members)==($b|members)' >/dev/null || return 1
    cg_sealed_lines "$old" "$od" "$oi" "$size" 1048576 >/dev/null &&
      cg_vector_eof /var/lib/capstone-vector/waf_audit "$old" "$od" "$oi" "$size" >/dev/null &&
      cg_wazuh_eof /var/ossec/queue/logcollector/file_status.json "$alias" "$old" "$od" "$oi" "$size" >/dev/null &&
      cg_wazuh_cold /var/ossec/queue/logcollector/file_status.json "$alias" "$new" "$od" "$oi" >/dev/null || return 1
    [[ $(wr_sha "$old") == "$hash" && $(/usr/bin/stat -c %d:%i:%s "$old") == "$od:$oi:$size" &&
       $(/usr/bin/stat -c %d:%i "$alias") == "$od:$oi" && $(/usr/bin/stat -c %d:%i "$new") == "$nd:$ni" ]]
}
wr_preconditions() {
    local name expected path
    [[ $(/usr/bin/tr -d '-' < /proc/sys/kernel/random/boot_id) == "$(/usr/bin/jq -r .boot_id "$WR_BASE/plan.json")" ]] || return 1
    [[ $(/usr/bin/stat -Lc %d:%i:%u:%g:%a:%h /proc/$$/fd/9) == "$(/usr/bin/stat -c %d:%i:%u:%g:%a:%h "$WR_LOCK")" ]] || return 1
    /usr/bin/flock -n 9 || return 1
    for name in coordinator.sh guard.sh state-lib.sh state.jq checkpoint-gates.sh checkpoint-gates.jq writer-gates.sh; do
        expected=$(/usr/bin/jq -r --arg name "$name" '.authority.runtime_sha256[$name]' "$WR_BASE/plan.json") || return 1
        wr_file "$WR_LIBRARY/$name" 400 131072 && [[ $(wr_sha "$WR_LIBRARY/$name") == "$expected" ]] || return 1
    done
    for name in vector_config wazuh_config; do
        [[ $name == vector_config ]] && path=/etc/capstone-vector/vector.toml || path=/var/ossec/etc/ossec.conf
        expected=$(/usr/bin/jq -r --arg key "${name}_sha256" '.source_pins[$key]' "$WR_BASE/before/modsecurity-state.json") || return 1
        [[ -f $path && ! -L $path && $(wr_sha "$path") == "$expected" ]] || return 1
    done
    wr_barriers && wr_services && wr_writers && wr_raw "$1"
}
wr_context() {
    local name hash line
    [[ $EUID == 0 && $OSTYPE == linux* && $(/usr/bin/cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || return 1
    wr_parents "$WR_BASE" && wr_parents "$WR_LIBRARY" && wr_file "$WR_LOCK" 600 4096 || return 1
    [[ $(/usr/bin/stat -Lc %d:%i:%u:%g:%a:%h /proc/$$/fd/9 2>/dev/null) == "$(/usr/bin/stat -c %d:%i:%u:%g:%a:%h "$WR_LOCK")" ]] || return 1
    /usr/bin/flock -n 9 || return 1
    while read -r hash name; do
        wr_file "$WR_LIBRARY/$name" 400 131072 && [[ $(wr_sha "$WR_LIBRARY/$name") == "$hash" ]] || return 1
    done <<'PINS'
9f9ad7996bc0bec3b6b35d00b0f6c7776b346d24c39aef8b7e74ebdd65049592 coordinator.sh
7f78865f4be32dbd647b46f15c4d5118471ef5eca607e6f966aa4579b9b3037e guard.sh
d754d17726310a56c77e5d37c41f0ae3883881dfbc91bfa20b7ef916fe428f3a state-lib.sh
3db6baef5c679521bdc257cbe1aca66fd6884714f734a1778ca27b249e40a775 state.jq
92acb7ce322d109bc7e70c32bb42a17cf5cddd1b7f5b6d7f23871e89cbaa4af6 checkpoint-gates.sh
ebc3022b44dae2a79845e35b5b26439d369162715644a720ce35257a1e22d8e6 checkpoint-gates.jq
c8a4f766c8cff125115f4d6413b746309004d608fdc1db370ec4dfe456cb1667 writer-gates.sh
PINS
    source "$WR_LIBRARY/checkpoint-gates.sh" && source "$WR_LIBRARY/writer-gates.sh"
}
wr_prepare_env() {
    # Preserve empty lines (including split's final empty item) and all
    # unrelated bytes. An empty line's split("=")[0] is null in jq.
    /usr/bin/jq -nj --rawfile raw "$WR_BASE/before/vector.env" --slurpfile d "$WR_BASE/descriptor.json" '
      ($d[0].authority|{WAF_INSTANCE_ID:.new_container.identity.cid,WAF_CONFIG_SHA256:.new_producer_sha256,WAF_DEPLOYMENT_BINDING:.new_binding}) as $u|
      $raw|split("\n")|map(. as $line|($line|split("=")[0] // "") as $key|
        if $u|has($key) then $key+"="+$u[$key] else $line end)|join("\n")'
}
wr_prepare() {
    local i n source before_meta expected od oi nd ni old new bytes hash pointer oldpid oldticks boot p v w cold
    local managed=$WR_MANAGED alias=$WR_ALIAS
    wr_json "$WR_BASE/descriptor.json" 400 16384 && wr_json "$WR_BASE/stop-proof.json" 400 4096 &&
      wr_file "$WR_BASE/new-producer.conf" 400 16384 || { wr_fail prepare_input_invalid; return 65; }
    /usr/bin/jq -e '
      def hex: type=="string" and test("^[a-f0-9]{64}$");
      keys==["authority","boot_id","expected_before_sha256","machine_id","policy","schema_version"] and
      .schema_version==1 and .policy=="capstone-waf-rebind-metadata-v1" and
      .machine_id=="096e90b6243e438aa8a7b392be754732" and (.boot_id|type=="string" and test("^[a-f0-9]{32}$")) and
      (.expected_before_sha256|keys==["modsecurity-state.json","raw-line-binding.json","suricata-state.json","vector.env","waf-binding.json"] and all(.[];hex)) and
      (.authority.new_binding|hex) and (.authority.new_producer_sha256|hex)
      ' "$WR_BASE/descriptor.json" >/dev/null || return 65
    [[ $(wr_sha "$WR_BASE/new-producer.conf") == "$(/usr/bin/jq -r .authority.new_producer_sha256 "$WR_BASE/descriptor.json")" ]] || return 65
    # A previous partial prepare is evidence, never silently regenerated.
    for n in plan.json before after receipts intent.json result.json; do
        [[ ! -e $WR_BASE/$n && ! -L $WR_BASE/$n ]] || { wr_fail prepare_artifact_exists_inspect_required; return 65; }
    done
    for n in before after receipts; do /bin/mkdir -m 700 "$WR_BASE/$n" && /bin/sync -- "$WR_BASE" || return 65; done
    for i in 0 1 2 3 4; do
        n=${WR_NAMES[$i]}; source=${WR_TARGETS[$i]}
        expected=$(/usr/bin/jq -r --arg n "$n" '.expected_before_sha256[$n]' "$WR_BASE/descriptor.json") || return 65
        wr_file "$source" 600 16384 && [[ $(wr_sha "$source") == "$expected" ]] || return 65
        before_meta=$(wr_meta "$source") || return 65
        /bin/cat -- "$source" > "$WR_BASE/before/$n" && /bin/chmod 400 "$WR_BASE/before/$n" &&
          /bin/sync -- "$WR_BASE/before/$n" "$WR_BASE/before" || return 65
        [[ $(wr_sha "$WR_BASE/before/$n") == "$expected" && $(wr_sha "$source") == "$expected" &&
           $(wr_meta "$source") == "$before_meta" ]] || return 65
    done
    for n in suricata modsecurity; do
        wr_json "$WR_BASE/before/$n-state.json" 400 16384 &&
          /usr/bin/jq -e -f "$WR_LIBRARY/state.jq" "$WR_BASE/before/$n-state.json" >/dev/null || return 65
    done
    /usr/bin/jq -e '.phase=="active" and .revision==11 and .current.number==3' "$WR_BASE/before/modsecurity-state.json" >/dev/null || return 65
    /usr/bin/jq -e '.phase=="active" and .revision==5 and .current.number==1' "$WR_BASE/before/suricata-state.json" >/dev/null || return 65
    old=$managed/$(/usr/bin/jq -r .current.basename "$WR_BASE/before/modsecurity-state.json")
    new=$managed/generation-0000000004.jsonl
    od=$(/usr/bin/jq -r .current.device "$WR_BASE/before/modsecurity-state.json")
    oi=$(/usr/bin/jq -r .current.inode "$WR_BASE/before/modsecurity-state.json")
    [[ -f $new && ! -L $new && -f $old && ! -L $old ]] || return 65
    nd=$(/usr/bin/stat -c %d "$new") && ni=$(/usr/bin/stat -c %i "$new") && bytes=$(/usr/bin/stat -c %s "$old") || return 65
    (( bytes<=536870912 )) || return 65
    hash=$(wr_sha "$old") || return 65
    cg_sealed_lines "$old" "$od" "$oi" "$bytes" 1048576 >/dev/null || return 65
    v=$(cg_vector_eof /var/lib/capstone-vector/waf_audit "$old" "$od" "$oi" "$bytes") &&
      w=$(cg_wazuh_eof /var/ossec/queue/logcollector/file_status.json "$alias" "$old" "$od" "$oi" "$bytes") &&
      cold=$(cg_wazuh_cold /var/ossec/queue/logcollector/file_status.json "$alias" "$new" "$od" "$oi") || return 65
    [[ $(wr_sha "$old") == "$hash" ]] || return 65
    /usr/bin/jq -e '.reason=="saved_zero" or .reason=="different_prefix"' <<< "$cold" >/dev/null || return 65
    pointer=$(printf 'SecAuditLog /var/log/modsecurity/capstone-managed/generation-0000000004.jsonl\n' | /usr/bin/sha256sum); pointer=${pointer%% *}
    # Fixed line replacement: jq handles the raw bytes; no shell eval/env source.
    # jq -r adds one LF; use -j so the original final LF is preserved exactly.
    wr_prepare_env > "$WR_BASE/after/vector.env" || return 65
    expected=$(wr_sha "$WR_BASE/after/vector.env") || return 65
    /usr/bin/jq -cS --arg env "$expected" '.vector_env_sha256=$env' "$WR_BASE/before/raw-line-binding.json" > "$WR_BASE/after/raw-line-binding.json" || return 65
    /usr/bin/jq -cS --slurpfile d "$WR_BASE/descriptor.json" '.instance_id=$d[0].authority.new_container.identity.cid|
      .configuration_sha256=$d[0].authority.new_producer_sha256|.deployment_binding=$d[0].authority.new_binding' \
      "$WR_BASE/before/waf-binding.json" > "$WR_BASE/after/waf-binding.json" || return 65
    /usr/bin/jq -cS --arg env "$expected" '.revision=6|.source_pins.vector_env_sha256=$env' \
      "$WR_BASE/before/suricata-state.json" > "$WR_BASE/after/suricata-state.json" || return 65
    /usr/bin/jq -cS --slurpfile d "$WR_BASE/descriptor.json" --arg env "$expected" --arg pathsha "$pointer" \
      --argjson dev "$nd" --argjson ino "$ni" --argjson bytes "$bytes" --arg hash "$hash" \
      --argjson v "$v" --argjson w "$w" --argjson cold "$cold" '
      .revision=12|.phase="publish_pending"|.boot_id=$d[0].boot_id|
      .source_pins.container_id=$d[0].authority.new_container.identity.cid|
      .source_pins.producer_format_sha256=$d[0].authority.new_producer_sha256|.source_pins.vector_env_sha256=$env|
      .pending={basename:"generation-0000000004.jsonl",number:4,device:$dev,inode:$ino,writer_config_sha256:$pathsha}|
      .proof.old_closed={boot_id:$d[0].boot_id,bytes:$bytes,device:.current.device,inode:.current.inode,sha256:$hash,
        writer_fd_zero:true,writer_pid:$d[0].authority.old_container.pid,writer_start_ticks:($d[0].authority.old_container.start_ticks|tonumber)}|
      .proof.readers_drained={vector_checkpoint_sha256:$v.checkpoint_sha256,vector_offset:$v.offset,vector_stopped:true,
        wazuh_checkpoint_sha256:$w.checkpoint_sha256,wazuh_offset:$w.offset,wazuh_sha1:$w.stored_sha1}|
      .proof.publish_guard={decision:$cold.reason,new_prefix_sha1:$cold.prefix_sha1,old_offset:$cold.offset,
        old_sha1:$cold.stored_sha1,source_bytes:$cold.source_identity.bytes,wazuh_checkpoint_sha256:$cold.checkpoint_sha256}' \
      "$WR_BASE/before/modsecurity-state.json" > "$WR_BASE/after/modsecurity-state.json" || return 65
    p='[]'
    for n in "${WR_NAMES[@]}"; do
        /bin/chmod 400 "$WR_BASE/after/$n" && /bin/sync -- "$WR_BASE/after/$n" || return 65
        p=$(/usr/bin/jq -ncS --argjson p "$p" --arg n "$n" --arg before "$(wr_sha "$WR_BASE/before/$n")" \
          --arg after "$(wr_sha "$WR_BASE/after/$n")" '$p+[{name:$n,before_sha256:$before,after_sha256:$after}]') || return 65
    done
    /bin/sync -- "$WR_BASE/after" || return 65
    /usr/bin/jq -cS --argjson files "$p" 'del(.expected_before_sha256)|.files=$files' "$WR_BASE/descriptor.json" > "$WR_BASE/plan.json" &&
      /bin/chmod 400 "$WR_BASE/plan.json" && /bin/sync -- "$WR_BASE/plan.json" "$WR_BASE" || return 65
    wr_plan && wr_prefix && [[ $WR_PREFIX == 0 ]] && wr_preconditions full || { wr_fail prepared_artifacts_not_authorized; return 65; }
    /usr/bin/jq -ncS --arg sha "$WR_PLAN_SHA" '{status:"prepared",plan_sha256:$sha,files:5,operating_files_changed:0,reader_start_authorized:false}'
}
wr_execute() {
    [[ $# == 1 && ( $1 == prepare || $1 == inspect || $1 == apply ) ]] || { wr_fail invalid_arguments; return 65; }
    wr_context || { wr_fail fixed_host_source_or_lock_refused; return 65; }
    case $1 in
      prepare) wr_prepare ;;
      apply) wr_apply ;;
      inspect)
        wr_plan && wr_prefix || { wr_fail invalid_plan_or_target_prefix; return 65; }
        local intent=false
        if [[ -e $WR_BASE/intent.json || -L $WR_BASE/intent.json ]]; then wr_intent_read || return 65; intent=true; fi
        /usr/bin/jq -ncS --arg sha "$WR_PLAN_SHA" --argjson prefix "$WR_PREFIX" --argjson intent "$intent" \
          '{status:"observed",plan_sha256:$sha,after_prefix:$prefix,intent_present:$intent,
            live_preconditions_checked:false,reader_start_authorized:false,signals_sent:0}'
        ;;
    esac
}
wr_main() {
    local self=${BASH_SOURCE[0]} rc=0
    [[ $# == 1 && ( $1 == prepare || $1 == inspect || $1 == apply ) ]] || { wr_fail invalid_arguments; return 65; }
    [[ $self == /* ]] && wr_file "$self" 400 131072 || { wr_fail executable_metadata_refused; return 65; }
    # A clean child keeps inherited FD9 but bounds the complete operation,
    # including native gates and fsync. A timeout never triggers rollback/retry.
    /usr/bin/timeout --signal=TERM --kill-after=2s 300s \
      /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC \
      /bin/bash -c 'set -uo pipefail; umask 077; source "$1"; wr_execute "$2"' \
      waf-rebind-metadata "$self" "$1" || rc=$?
    if (( rc==124 || rc==137 )); then WR_REASON=bounded_execution_timeout_inspect_required
    elif (( rc!=0 )); then WR_REASON=bounded_execution_refused_inspect_required; fi
    return "$rc"
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    set -uo pipefail
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TZ=UTC
    umask 077
    rc=0; wr_main "$@" || rc=$?
    if (( rc!=0 )); then /usr/bin/jq -nc --arg reason "$WR_REASON" '{status:"refused",reason:$reason,signals_sent:0,reader_start_authorized:false}'; fi
    exit "$rc"
fi
