# Pure comparison of the fixed stopped candidate against the actual saved WAF.
# No environment values are emitted. The caller pins the saved baseline SHA.
def envmap:
  . as $rows | map(capture("^(?<key>[^=]+)=(?<value>.*)$")) as $pairs |
  if ($pairs | map(.key) | unique | length) != ($rows | length)
  then error("duplicate environment name") else $pairs | from_entries end;
def cfg: del(.Hostname,.Image,.Labels,.Env);
def host: del(.Binds,.RestartPolicy,.OomKillDisable);
def empty_array_defaults:
  ["BlkioDeviceReadBps","BlkioDeviceReadIOps","BlkioDeviceWriteBps",
   "BlkioDeviceWriteIOps","BlkioWeightDevice","Devices","DnsOptions","DnsSearch"];
def candidate_host:
  host | reduce empty_array_defaults[] as $key
    (.; if .[$key] == [] then .[$key] = null else . end);
$before[0][0] as $old | .[0] as $new |
($old.Id == "02fb9ec3db38b01ccc49b61c7ca57d41e745d691cf0acd97a8b9978b16e1f41e") and
($old.Image == "sha256:411cc97544ec0af886d3bc2a230564c2d28f08a800152617507476cda6ae9650") and
($new.Id | type == "string" and test("^[a-f0-9]{64}$")) and
($new.Id != $old.Id) and ($new.Name == "/waf-prestart-20261015") and
($new.Image == $old.Image) and
($new.State.Status == "created" and $new.State.Pid == 0 and
 $new.State.Running == false and $new.State.Restarting == false and
 $new.State.StartedAt == "0001-01-01T00:00:00Z") and
($new.RestartCount == 0) and
(($new.Config | cfg) == ($old.Config | cfg)) and
($new.Config.Hostname == $new.Id[0:12]) and
($new.Config.Image == $old.Image) and
($new.Config.Labels == (($image[0][0].Config.Labels // {}) + {"capstone.waf.recreation":"20261015"})) and
(($new.Config.Env | envmap) == ($old.Config.Env | envmap)) and
(all(empty_array_defaults[]; . as $key |
  ($old.HostConfig | has($key)) and ($new.HostConfig | has($key)) and
  $old.HostConfig[$key] == null and
  ($new.HostConfig[$key] == null or $new.HostConfig[$key] == []))) and
(($new.HostConfig | candidate_host) == ($old.HostConfig | host)) and
($new.HostConfig.RestartPolicy == {Name:"no",MaximumRetryCount:0}) and
($old.HostConfig.OomKillDisable == null and $new.HostConfig.OomKillDisable == false) and
(($new.HostConfig.Binds | sort) == (($old.HostConfig.Binds + [
 "/etc/capstone-waf/REQUEST-900-CAPSTONE-SCANNER.conf:/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-CAPSTONE-SCANNER.conf:ro",
 "/etc/capstone-waf/zz-capstone-evidence-v2.conf:/etc/nginx/conf.d/zz-capstone-evidence.conf:ro",
 "/etc/capstone-waf/modsecurity-override-v2.conf.template:/etc/nginx/templates/modsecurity.d/modsecurity-override.conf.template:ro"
]) | sort)) and
($new.NetworkSettings.Networks | keys == ["secstack_waf-net"]) and
($new.NetworkSettings.Networks["secstack_waf-net"] as $net |
 $net.IPAMConfig.IPv4Address == "172.18.0.2" and
 (($net.IPAMConfig.IPv6Address // "") == "") and
 (($net.IPAMConfig.LinkLocalIPs // []) == []) and
 (($net.IPAMConfig | keys) - ["IPv4Address","IPv6Address","LinkLocalIPs"] == []) and
 ($net.Aliases | sort == ["waf"]) and
 (($net.EndpointID // "") == "") and (($net.IPAddress // "") == "")) and
(($new.Mounts | map({Type,Source,Destination,RW,Propagation}) | sort_by(.Destination)) ==
 ($new.HostConfig.Binds | map(split(":") |
   {Type:"bind",Source:.[0],Destination:.[1],RW:(.[2]=="rw"),Propagation:"rprivate"}) | sort_by(.Destination)))
