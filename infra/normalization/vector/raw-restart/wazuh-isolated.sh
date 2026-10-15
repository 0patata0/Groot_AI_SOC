#!/bin/bash
# One-shot synthetic restart fixture. Never an operational agent wrapper.
set -euo pipefail
umask 077
PATH=/usr/local/bin:/usr/bin:/bin
export PATH LC_ALL=C
[[ $EUID == 0 && $(uname -s) == Linux ]] || exit 64
[[ $# -ge 2 && ( $1 == prepare || $1 == launch ) ]] || exit 64
mode=$1 prefix=$2
[[ $prefix =~ ^/var/tmp/capstone-raw-restart\.[A-Za-z0-9_-]{6,20}/(default|recover)/wazuh$ ]] || exit 65
profile_dir=${prefix%/*}
stage=${profile_dir%/*}
profile=${profile_dir##*/}
for directory in "$stage" "$profile_dir"; do
    [[ -d $directory && ! -L $directory && $(stat -c '%u:%a' "$directory") == 0:700 ]] || exit 65
done
input=$profile_dir/reader.json
if [[ $mode == prepare ]]; then
    [[ $# == 2 && ! -e $prefix && ! -L $prefix ]] || exit 65
    [[ -f $input && ! -L $input && $(stat -c '%u:%a:%h' "$input") == 0:600:2 ]] || exit 65
    [[ -d /var/ossec && ! -L /var/ossec && -d /var/ossec/lib && ! -L /var/ossec/lib ]]
    [[ -f /var/ossec/bin/wazuh-logcollector && ! -L /var/ossec/bin/wazuh-logcollector && -x /var/ossec/bin/wazuh-logcollector ]]
    [[ -f /var/ossec/etc/internal_options.conf && ! -L /var/ossec/etc/internal_options.conf ]]
    mkdir -m 700 "$prefix"
    mkdir -p "$prefix/bin" "$prefix/etc/shared" "$prefix/logs" "$prefix/var/run" "$prefix/queue/sockets" "$prefix/queue/logcollector" "$prefix/lib"
    cp -- /var/ossec/bin/wazuh-logcollector "$prefix/bin/"
    cp -a -- /var/ossec/lib/. "$prefix/lib/"
    cp -- /var/ossec/etc/internal_options.conf "$prefix/etc/internal_options.conf"
    # Installed scan/check timing stays intact; no command source or live agent
    # configuration, client key, state or socket is copied.
    printf 'logcollector.remote_commands=0\n' > "$prefix/etc/local_internal_options.conf"
    future=''
    [[ $profile == default ]] || future='<only-future-events max-size="2GB">no</only-future-events>'
    cat > "$prefix/etc/ossec.conf" <<CONFIG
<ossec_config>
  <localfile><log_format>json</log_format><location>$input</location>$future</localfile>
</ossec_config>
CONFIG
    (cd "$prefix"; sha256sum bin/wazuh-logcollector etc/internal_options.conf etc/local_internal_options.conf etc/ossec.conf > prepared.sha256)
    chmod 400 "$prefix/prepared.sha256"
    exit 0
fi
[[ $# == 2 && -d $prefix && ! -L $prefix && $(stat -c '%u:%a' "$prefix") == 0:700 ]] || exit 65
[[ -f $prefix/prepared.sha256 && ! -L $prefix/prepared.sha256 && $(stat -c '%u:%a:%h' "$prefix/prepared.sha256") == 0:400:1 ]]
(cd "$prefix"; sha256sum --check --status prepared.sha256)
[[ -S $prefix/queue/sockets/queue && ! -L $prefix/queue/sockets/queue ]]
private_root_inode=$(stat -Lc '%d:%i' "$prefix")
private_queue_inode=$(stat -Lc '%d:%i' "$prefix/queue/sockets/queue")
[[ $private_root_inode != "$(stat -Lc '%d:%i' /var/ossec)" ]]
[[ $private_queue_inode != "$(stat -Lc '%d:%i' /var/ossec/queue/sockets/queue)" ]]
host_mountns=$(readlink /proc/self/ns/mnt)
host_netns=$(readlink /proc/self/ns/net)
# Exec keeps the direct child's PID. There is no PID namespace, fork, manager
# connection or external network interface. The bind exists only in this mount
# namespace, and rprivate is set before any bind mount.
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
