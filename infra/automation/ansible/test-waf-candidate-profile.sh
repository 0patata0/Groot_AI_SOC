#!/bin/bash
# Native jq boundary tests against root-private captured metadata; no Docker calls.
set -euo pipefail
[[ $# == 0 && $EUID == 0 && $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]] || exit 77
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
base=/var/backups/capstone-waf-recreation-20261015
[[ $(sha256sum "$base/before-inspect.json" | cut -d ' ' -f1) == fd0bd4029be0999c467e70404257b681a98a4c4c3a9136f65303451d88eccdf8 ]]
[[ $(sha256sum "$base/image-inspect.json" | cut -d ' ' -f1) == ebc43957a8e89697e4aae61430adef03e440d55d39b117e69c67dc76fe97b5b8 ]]
umask 077
scratch=$(mktemp -d /var/tmp/capstone-waf-profile-test.XXXXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
jq --slurpfile image "$base/image-inspect.json" '
  .[0] | .Id=("a"*64) | .Name="/waf-prestart-20261015" |
  .State.Status="created" | .State.Pid=0 | .State.Running=false |
  .State.Restarting=false | .State.StartedAt="0001-01-01T00:00:00Z" | .RestartCount=0 |
  .Config.Hostname=("a"*12) | .Config.Image=.Image |
  .Config.Labels=(($image[0][0].Config.Labels // {}) + {"capstone.waf.recreation":"20261015"}) |
  .Config.Env |= reverse |
  .HostConfig.RestartPolicy={Name:"no",MaximumRetryCount:0} | .HostConfig.OomKillDisable=false |
  reduce ["BlkioDeviceReadBps","BlkioDeviceReadIOps","BlkioDeviceWriteBps",
          "BlkioDeviceWriteIOps","BlkioWeightDevice","Devices","DnsOptions","DnsSearch"][] as $key
    (.; .HostConfig[$key]=[]) |
  .HostConfig.Binds += [
    "/etc/capstone-waf/REQUEST-900-CAPSTONE-SCANNER.conf:/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-CAPSTONE-SCANNER.conf:ro",
    "/etc/capstone-waf/zz-capstone-evidence-v2.conf:/etc/nginx/conf.d/zz-capstone-evidence.conf:ro",
    "/etc/capstone-waf/modsecurity-override-v2.conf.template:/etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template:ro"] |
  .Mounts=(.HostConfig.Binds|map(split(":")|{Type:"bind",Source:.[0],Destination:.[1],RW:(.[2]=="rw"),Propagation:"rprivate"})) |
  .NetworkSettings.Networks["secstack_waf-net"].IPAMConfig={IPv4Address:"172.18.0.2"} |
  .NetworkSettings.Networks["secstack_waf-net"].Aliases=["waf"] |
  .NetworkSettings.Networks["secstack_waf-net"].EndpointID="" |
  .NetworkSettings.Networks["secstack_waf-net"].IPAddress="" | [.]
' "$base/before-inspect.json" > "$scratch/good.json"
check() { jq -e --slurpfile before "$base/before-inspect.json" --slurpfile image "$base/image-inspect.json" -f "$here/waf-candidate-profile.jq" "$1" >/dev/null 2>&1; }
check "$scratch/good.json"
count=1
# The original null representation is also equivalent, but only for these eight
# reviewed empty-list defaults. Missing, scalar, and nonempty values are not.
jq 'reduce ["BlkioDeviceReadBps","BlkioDeviceReadIOps","BlkioDeviceWriteBps",
             "BlkioDeviceWriteIOps","BlkioWeightDevice","Devices","DnsOptions","DnsSearch"][] as $key
      (.; .[0].HostConfig[$key]=null)' "$scratch/good.json" > "$scratch/null.json"
check "$scratch/null.json"
count=$((count+1))
for filter in \
 '.[0].HostConfig.Privileged=true' \
 '.[0].HostConfig.PortBindings["8080/tcp"][0].HostPort="81"' \
 '.[0].Config.Env += ["EXTRA=unreviewed"]' \
 '.[0].Config.Env += [.[0].Config.Env[0]]' \
 '.[0].Config.Labels["unreviewed"]="yes"' \
 '.[0].Image="sha256:unreviewed"' \
 '.[0].HostConfig.Binds[2] |= sub(":ro$";":rw")' \
 '.[0].Mounts[2].RW=true' \
 '.[0].Mounts[2].Source="/unreviewed-source"' \
 '.[0].Mounts[2].Destination="/unreviewed-destination"' \
 '.[0].Mounts += [.[0].Mounts[2]]' \
 '.[0].NetworkSettings.Networks["secstack_waf-net"].IPAMConfig.IPv4Address="172.18.0.3"' \
 '.[0].HostConfig.RestartPolicy.Name="unless-stopped"' \
 '.[0].State.Pid=1234' \
 '.[0].State.Running=true' \
 '.[0].Config.User="root"'; do
 jq "$filter" "$scratch/good.json" > "$scratch/bad.json"
 if check "$scratch/bad.json"; then printf 'rejected_case_failed:%s\n' "$count"; exit 1; fi
 count=$((count+1))
done
for key in BlkioDeviceReadBps BlkioDeviceReadIOps BlkioDeviceWriteBps BlkioDeviceWriteIOps BlkioWeightDevice Devices DnsOptions DnsSearch; do
 for mode in nonempty missing scalar; do
  jq --arg key "$key" --arg mode "$mode" '
    if $mode=="nonempty" then .[0].HostConfig[$key]=["unreviewed"]
    elif $mode=="missing" then del(.[0].HostConfig[$key])
    else .[0].HostConfig[$key]=false end' "$scratch/good.json" > "$scratch/bad.json"
  if check "$scratch/bad.json"; then printf 'empty_default_case_failed:%s:%s\n' "$key" "$mode"; exit 1; fi
  count=$((count+1))
 done
done
# A neighboring null array outside the reviewed allowlist stays byte-structural.
jq '.[0].HostConfig.CapAdd=[]' "$scratch/good.json" > "$scratch/bad.json"
if check "$scratch/bad.json"; then printf 'unlisted_null_normalization_failed\n'; exit 1; fi
count=$((count+1))
printf '{"tests":%s,"result":"PASS","docker_calls":0,"operating_mutations":0}\n' "$count"
