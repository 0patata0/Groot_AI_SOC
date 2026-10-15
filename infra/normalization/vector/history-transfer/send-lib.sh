#!/bin/bash
# Private native transport used by the fixed operator wrapper and isolated test.
hs_send() (
    set -euo pipefail
    umask 077
    local source=$1 id=$2 payload_sha=$3 manifest_sha=$4 work file expected before after maximum
    [[ $# == 4 && $id =~ ^[a-f0-9]{64}$ && $payload_sha =~ ^[a-f0-9]{64}$ && $manifest_sha =~ ^[a-f0-9]{64}$ ]]
    [[ ${CAPSTONE_AUTH_FD_PATH:-} =~ ^/proc/[0-9]+/fd/[0-9]+$ ]]
    [[ -d $source && ! -L $source && $(stat -c %u "$source") == 0 && $(stat -c %a "$source") == 700 ]]
    before=''
    for file in kernel.jsonl manifest.json; do
        [[ -f $source/$file && ! -L $source/$file && $(stat -c %u "$source/$file") == 0 && $(stat -c %a "$source/$file") == 400 && $(stat -c %h "$source/$file") == 1 ]]
        if [[ $file == kernel.jsonl ]]; then expected=$payload_sha; maximum=33554432; else expected=$manifest_sha; maximum=65536; fi
        (( $(stat -c %s "$source/$file") > 0 && $(stat -c %s "$source/$file") <= maximum ))
        [[ $(sha256sum "$source/$file" | cut -d ' ' -f1) == "$expected" ]]
        before+=$(stat -c '%d:%i:%s:%y:%z:%u:%g:%a:%h' "$source/$file")
    done
    work=$(mktemp -d /var/tmp/capstone-history-send.XXXXXX)
    trap 'rm -rf -- "$work"' EXIT
    printf '%s\n' '10.200.10.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGnNzpwR6mSVOqn/qTqDvBruxT05UGc7IeXewOSIjkeR' > "$work/known_hosts"
    printf '%s\n' '#!/bin/sh' 'exec /bin/cat -- "$CAPSTONE_AUTH_FD_PATH"' > "$work/askpass"
    cat > "$work/ssh" <<'SSH'
#!/bin/bash
set -euo pipefail
directory=${0%/*}
exec /usr/bin/ssh -F /dev/null \
 -o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$directory/known_hosts" \
 -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no -o VerifyHostKeyDNS=no \
 -o HostKeyAlgorithms=ssh-ed25519 -o PreferredAuthentications=password \
 -o PubkeyAuthentication=no -o PasswordAuthentication=yes -o NumberOfPasswordPrompts=1 \
 -o ConnectionAttempts=1 -o ConnectTimeout=10 -o IdentityAgent=none -o ControlPath=none \
 -o ForwardAgent=no -o ClearAllForwardings=yes -o LogLevel=ERROR -o RequestTTY=no "$@"
SSH
    chmod 500 "$work/ssh" "$work/askpass"
    chmod 400 "$work/known_hosts"
    export SSH_ASKPASS="$work/askpass" SSH_ASKPASS_REQUIRE=force DISPLAY=capstone:0
    /usr/bin/timeout --kill-after=2s 60s /usr/bin/rsync --quiet --fsync --protect-args \
        --timeout=20 --perms --chmod=F600,D700 --rsync-path=/usr/bin/rsync -e "$work/ssh" \
        -- "$source/kernel.jsonl" "$source/manifest.json" \
        "groot_b@10.200.10.10:/var/tmp/capstone-history-upload-20261014/$id/$payload_sha-$manifest_sha/"
    after=''
    for file in kernel.jsonl manifest.json; do
        if [[ $file == kernel.jsonl ]]; then expected=$payload_sha; else expected=$manifest_sha; fi
        [[ $(sha256sum "$source/$file" | cut -d ' ' -f1) == "$expected" ]]
        after+=$(stat -c '%d:%i:%s:%y:%z:%u:%g:%a:%h' "$source/$file")
    done
    [[ $before == "$after" ]]
    jq -cn --arg id "$id" --arg payload "$payload_sha" --arg manifest "$manifest_sha" \
        '{stage:"transport_completed_not_receipt",batch_id:$id,payload_sha256:$payload,manifest_sha256:$manifest}'
)
