#!/usr/bin/env python3
"""A: stop logging benign DHCP client broadcasts as SPOOF. Run as root, once.

Usage: apply_a.py <candidate capstone-fw.nft>
1. Live: insert ONE drop rule (no log) directly before the ens192 SPOOF log
   rule. No table reload, so agent_block containment elements are untouched.
2. Persistence: replace /etc/nftables.d/capstone-fw.nft with the reviewed
   candidate (original backed up) after an `nft -c` check of the same
   delete+include transaction that capstone-nat.sh uses at boot/re-apply.
Any failure after step 1 removes the inserted rule and restores the file.
The packets stay dropped exactly as before; only the SPOOF log line goes.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time

LIVE = '/etc/nftables.d/capstone-fw.nft'
CURRENT_SHA = 'f820c798320979788a37f9574fd625ac34fa93971ea6893d226b4f70ad18c9cb'
CANDIDATE_SHA = 'da3dd8523b2e0ea8a7a4c878ea0b44b0d00cddbf31b30d8c9d4a0ab8d1b816ac'
SPOOF_LOG = ('iifname "ens192" ip saddr @spoof_src_ext update @spoof_meter '
             '{ ip saddr limit rate 6/minute burst 3 packets } log prefix "SPOOF " level notice')
RULE = ('iifname "ens192" ip saddr 0.0.0.0 ip daddr 255.255.255.255 udp sport 68 udp dport 67 '
        'counter drop comment "DHCP client broadcast from 0.0.0.0 (RFC 2131); A serves no DHCP on ens192 - never logged"')
out = {'started': time.strftime('%Y-%m-%dT%H:%M:%S%z')}


def sh(argv, data=None, timeout=30):
    r = subprocess.run(argv, input=data, capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout + r.stderr).strip()


def chain():
    rc, o = sh(['nft', '-a', 'list', 'chain', 'inet', 'capstone_fw', 'prerouting_block'])
    assert rc == 0, 'chain_unreadable'
    rows = []
    for line in o.splitlines():
        m = re.match(r'\s*(.*?) # handle (\d+)$', line)
        if m:
            rows.append((re.sub(r'counter packets \d+ bytes \d+', 'counter', m.group(1)), int(m.group(2))))
    return rows


def check_file(path):
    with tempfile.TemporaryDirectory(prefix='spoof-tx-', dir='/var/tmp') as d:
        tx = os.path.join(d, 'tx.nft')
        open(tx, 'w').write('table inet capstone_fw\ndelete table inet capstone_fw\ninclude "%s"\n' % path)
        return sh(['nft', '-c', '-f', tx])


def main():
    candidate = open(sys.argv[1], 'rb').read()
    assert hashlib.sha256(candidate).hexdigest() == CANDIDATE_SHA, 'candidate_changed'
    original = open(LIVE, 'rb').read()
    assert hashlib.sha256(original).hexdigest() == CURRENT_SHA, 'live_file_changed_no_change'
    rows = chain()
    anchors = [h for text, h in rows if text == SPOOF_LOG]
    assert len(anchors) == 1, 'spoof_log_rule_not_unique_no_change'
    assert not any('udp sport 68 udp dport 67' in text for text, _ in rows), 'dhcp_rule_already_present_no_change'
    rc, o = check_file(os.path.realpath(sys.argv[1]))
    assert rc == 0, 'candidate_file_check_failed_no_change:' + o[-200:]
    st = os.stat(LIVE)
    backup = '/var/backups/capstone-fw-dhcp-noise-' + time.strftime('%Y%m%dT%H%M%S')
    os.mkdir(backup, 0o700)
    with open(os.path.join(backup, 'capstone-fw.nft'), 'xb') as f:
        f.write(original)
    out['backup'] = backup
    # nft joins its arguments and parses them; the quoted comment stays one token (no shell involved).
    rc, o = sh(['nft', 'insert', 'rule', 'inet', 'capstone_fw', 'prerouting_block', 'handle', str(anchors[0]), RULE])
    assert rc == 0, 'live_insert_failed_no_change:' + o[-200:]
    inserted = None
    try:
        rows = chain()
        texts = [t for t, _ in rows]
        i = texts.index(SPOOF_LOG)
        assert i > 0 and 'udp sport 68 udp dport 67' in texts[i - 1] and texts[i - 1].endswith('never logged"'), 'live_position_wrong'
        inserted = rows[i - 1][1]
        out['inserted_handle'] = inserted
        tmp = LIVE + '.dhcpnoise.tmp'
        with open(tmp, 'xb') as f:
            f.write(candidate); f.flush(); os.fsync(f.fileno())
        os.chown(tmp, st.st_uid, st.st_gid); os.chmod(tmp, st.st_mode & 0o7777)
        os.replace(tmp, LIVE)
        rc, o = check_file(LIVE)
        assert rc == 0, 'persistent_file_check_failed'
        out['persistent_sha16'] = hashlib.sha256(open(LIVE, 'rb').read()).hexdigest()[:16]
    except Exception:
        if inserted is not None:
            sh(['nft', 'delete', 'rule', 'inet', 'capstone_fw', 'prerouting_block', 'handle', str(inserted)])
        with open(LIVE + '.restore.tmp', 'xb') as f:
            f.write(original)
        os.chown(LIVE + '.restore.tmp', st.st_uid, st.st_gid); os.chmod(LIVE + '.restore.tmp', st.st_mode & 0o7777)
        os.replace(LIVE + '.restore.tmp', LIVE)
        out['restored'] = True
        raise
    out['chain_rule_count'] = len(chain())
    out['status'] = 'applied'


if __name__ == '__main__':
    try:
        main()
    except AssertionError as e:
        out['status'] = 'refused'; out['reason'] = str(e)
    except Exception as e:
        out['status'] = 'error'; out['reason'] = type(e).__name__ + ':' + str(e)[:200]
    out['finished'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
    print(json.dumps(out, ensure_ascii=False))
