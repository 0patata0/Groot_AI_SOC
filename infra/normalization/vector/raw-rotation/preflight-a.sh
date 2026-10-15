#!/bin/bash
# Read-only metadata; no source log contents, namespace, service, or signal.
set -euo pipefail
umask 077
PATH=/usr/local/bin:/usr/bin:/bin
export PATH LC_ALL=C
[[ $# == 0 && $EUID == 0 && $(uname -s) == Linux ]]
[[ $(cat /etc/machine-id) == 096e90b6243e438aa8a7b392be754732 ]]
for tool in docker vector jq unshare mount stat sha256sum sha1sum timeout sync base64 readlink; do command -v "$tool" >/dev/null; done
cid=$(docker inspect --format '{{.Id}}' suricata)
[[ $cid =~ ^[0-9a-f]{64}$ ]]
init=$(docker inspect --format '{{.State.Pid}}' "$cid")
[[ $init =~ ^[0-9]+$ && $init -gt 1 ]]
[[ -x /var/ossec/bin/wazuh-logcollector && -d /var/ossec/lib ]]
for path in /var/ossec /var/ossec/queue/sockets/queue /var/ossec/bin/wazuh-logcollector; do
    [[ ! -L $path ]]
done
vector_version=$(vector --version)
suricata_version=$(docker exec "$cid" /usr/bin/suricata -V)
binary_sha=$(sha256sum /var/ossec/bin/wazuh-logcollector); binary_sha=${binary_sha%% *}
private_pid=$(awk '/^NSpid:/ {print $NF}' /proc/"$init"/status)
queue_id=$(stat -Lc '%d:%i' /var/ossec/queue/sockets/queue)
root_id=$(stat -Lc '%d:%i' /var/ossec)
lib_count=$(find /var/ossec/lib -maxdepth 1 -type f | wc -l)
jq -nc --arg cid "$cid" --argjson init "$init" --argjson nspid "$private_pid" \
    --arg vector "$vector_version" --arg suricata "$suricata_version" --arg sha "$binary_sha" \
    --arg queue "$queue_id" --arg root "$root_id" --argjson libs "$lib_count" \
    '{kind:"raw_rotation_readonly_preflight",container_id:$cid,container_init_host_pid:$init,container_init_namespace_pid:$nspid,vector_version:$vector,suricata_version:$suricata,wazuh_binary_sha256:$sha,wazuh_root_devino:$root,wazuh_queue_devino:$queue,wazuh_private_library_files:$libs,changes:false}'
