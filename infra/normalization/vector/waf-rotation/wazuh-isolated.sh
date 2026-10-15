#!/bin/bash
# Private WAF audit Wazuh logcollector fixture only. This is NOT an operational service wrapper.
# No client keys, agent/manager config, credentials, or source logs are copied.
set -euo pipefail
umask 077
PATH=/usr/local/bin:/usr/bin:/bin
export PATH LC_ALL=C
[[ $EUID == 0 && $(uname -s) == Linux ]] || exit 64
[[ $# -ge 2 && ( $1 == prepare || $1 == launch ) ]] || exit 64
mode=$1 prefix=$2
[[ $prefix =~ ^/var/tmp/capstone-waf-rotation\.[A-Za-z0-9_-]{6,20}/(wazuh|naive-wazuh)$ ]] || exit 65
stage=${prefix%/*}
[[ -d $stage && ! -L $stage && $(stat -c '%u:%a' "$stage") == 0:700 ]] || exit 65
if [[ $mode == prepare ]]; then
    [[ $# == 3 && ! -e $prefix && ! -L $prefix ]] || exit 65
    input=$3
    [[ $input =~ ^/proc/[1-9][0-9]*/root/tmp/capstone-waf-rotation\.[A-Za-z0-9_-]{6,20}/(reader|naive)/audit\.json$ ]] || exit 65
    private_root=${input%/*/*}
    [[ -d $private_root && ! -L $private_root && $(stat -c '%u:%a' "$private_root") == 0:700 ]] || exit 65
    [[ -f $input && ! -L $input && $(stat -c %u "$input") == 0 ]] || exit 65
    [[ -d /var/ossec && ! -L /var/ossec && -d /var/ossec/lib && ! -L /var/ossec/lib ]]
    [[ -f /var/ossec/bin/wazuh-logcollector && ! -L /var/ossec/bin/wazuh-logcollector && -x /var/ossec/bin/wazuh-logcollector ]]
    [[ -f /var/ossec/etc/internal_options.conf && ! -L /var/ossec/etc/internal_options.conf ]]
    mkdir -m 700 "$prefix"
    mkdir -p "$prefix/bin" "$prefix/etc/shared" "$prefix/logs" "$prefix/var/run" "$prefix/queue/sockets" "$prefix/queue/logcollector" "$prefix/lib"
    cp -- /var/ossec/bin/wazuh-logcollector "$prefix/bin/"
    cp -a -- /var/ossec/lib/. "$prefix/lib/"
    cp -- /var/ossec/etc/internal_options.conf "$prefix/etc/internal_options.conf"
    # Keep the installed scan/check timing; no command collection is configured.
    printf 'logcollector.remote_commands=0\n' > "$prefix/etc/local_internal_options.conf"
    cat > "$prefix/etc/ossec.conf" <<CONFIG
<ossec_config>
  <localfile><log_format>json</log_format><location>$input</location><only-future-events>no</only-future-events></localfile>
</ossec_config>
CONFIG
    # A restart reuses private offsets, but the executable/config must stay unchanged.
    (cd "$prefix"; sha256sum bin/wazuh-logcollector etc/internal_options.conf etc/local_internal_options.conf etc/ossec.conf > prepared.sha256)
    chmod 400 "$prefix/prepared.sha256"
    exit 0
fi
[[ $# == 2 && -d $prefix && ! -L $prefix && $(stat -c '%u:%a' "$prefix") == 0:700 ]] || exit 65
[[ -f $prefix/prepared.sha256 && ! -L $prefix/prepared.sha256 && $(stat -c '%u:%a:%h' "$prefix/prepared.sha256") == 0:400:1 ]]
(cd "$prefix"; sha256sum --check --status prepared.sha256)
[[ -d $prefix/queue/sockets && ! -L $prefix/queue/sockets ]]
# The caller starts the private queue receiver first. Refuse missing/aliased sockets.
[[ -S $prefix/queue/sockets/queue && ! -L $prefix/queue/sockets/queue ]]
private_root_inode=$(stat -Lc '%d:%i' "$prefix")
private_queue_inode=$(stat -Lc '%d:%i' "$prefix/queue/sockets/queue")
[[ $private_root_inode != "$(stat -Lc '%d:%i' /var/ossec)" ]]
[[ $private_queue_inode != "$(stat -Lc '%d:%i' /var/ossec/queue/sockets/queue)" ]]
host_mountns=$(readlink /proc/self/ns/mnt)
host_netns=$(readlink /proc/self/ns/net)
# No --fork or PID namespace: exec retains the caller's $! PID for exact wait/cleanup.
# The bind mount is in this new private namespace only. AF_UNIX pathname socket
# delivery stays on the fixture receiver; no network interface is configured.
exec env -i PATH="$PATH" LC_ALL=C unshare --mount --net --propagation private \
    /bin/bash --noprofile --norc -c '
        set -euo pipefail
        umask 077
        prefix=$1 host_mountns=$2 host_netns=$3 root_inode=$4 queue_inode=$5
        [[ $(readlink /proc/self/ns/mnt) != "$host_mountns" && $(readlink /proc/self/ns/net) != "$host_netns" ]]
        mount --make-rprivate /
        mount --bind "$prefix" /var/ossec
        [[ $(stat -Lc "%d:%i" /var/ossec) == "$root_inode" ]]
        [[ $(stat -Lc "%d:%i" /var/ossec/queue/sockets/queue) == "$queue_inode" ]]
        [[ $(awk "NR>2 {gsub(/:/,\"\",\$1); print \$1}" /proc/net/dev) == lo ]]
        export LD_LIBRARY_PATH="$prefix/lib"
        exec "$prefix/bin/wazuh-logcollector" -f -c "$prefix/etc/ossec.conf"
    ' bash "$prefix" "$host_mountns" "$host_netns" "$private_root_inode" "$private_queue_inode"
