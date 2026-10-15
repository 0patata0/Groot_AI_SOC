#!/usr/bin/env python3
"""One fixed A/container/job syntax test. No rule publication or service signal.

Reuses SHA-pinned namespace/fsync/process cleanup primitives from the previously
verified initial migration helper. Never calls that helper's migration CLI.
"""
from contextlib import ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import re
import signal
import stat
import sys
import time
import types

SOURCE = Path('/var/tmp/capstone-tools-followup-20261015/suricata-native-source')
HELPER = SOURCE / 'deploy-raw-operations-a.py'
HELPER_SHA = '6dcf1556f89c8882a422cf92a3c8caa90bbdcdf71b809d0224587fe45b17db15'
EVIDENCE = Path('/var/tmp/capstone-tools-followup-20261015/suricata-native-v6')
JOB = Path('/tmp/capstone-suricata-update-20261015-0819000000000004')
CANDIDATE_SHA = '0da12c9990b80e346f18cb7c370960010bc5fccc8a740dc2d1892c3664afb436'
MID = '096e90b6243e438aa8a7b392be754732'
PINS = {
    '/usr/bin/suricata': 'c2f2ec727be9d6f925e9164b59786ba5bf6f6b61452a6901a4013c996a06aa8d',
    '/etc/suricata/suricata.yaml': '8c234811ce9a8d49f3a55c0c7e62c72f28431ad392c75deae910aa917c225ad1',
    '/rules/suricata.rules': 'f11a97da8db542030b5767860eb7e5c4d5045d57385baf5b1cca6ff540faef97',
    '/rules/GROOT_A_local.rules': '82f41d6532f5b2333178ea51e92ce5c2beedd1052c6a585deb6b91e42bcbe9cf',
    '/rules/all.rules': '8669bab4923070dac1ed474f4c96c6a90ad92a794518a19fc628bc8354619da6'}


def need(value, code):
    if not value:
        raise ValueError(code)


def load_helper():
    path = HELPER.parent
    while path != Path('/'):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode), 'source_ancestor_not_directory')
        path = path.parent
    need(SOURCE.stat().st_uid == 0 and stat.S_IMODE(SOURCE.stat().st_mode) == 0o700, 'source_root_invalid')
    fd = os.open(HELPER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
             stat.S_IMODE(info.st_mode) == 0o400 and info.st_nlink == 1 and info.st_size < 131072, 'helper_metadata')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(131073)
        need(len(raw) == info.st_size and hashlib.sha256(raw).hexdigest() == HELPER_SHA, 'helper_sha')
    finally:
        os.close(fd)
    module = types.ModuleType('capstone_pinned_shadow_helper')
    module.__file__ = str(HELPER)
    exec(compile(raw, str(HELPER), 'exec'), module.__dict__)
    return module


def lock(stack, path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    stack.callback(os.close, fd)
    info = os.fstat(fd)
    need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and
         stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, 'lock_metadata')
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    need(os.stat(path, follow_symlinks=False).st_ino == info.st_ino, 'lock_path_changed')


def protected(p, root):
    result = {}
    for path, expected in PINS.items():
        raw, meta = p.snapshot(path, root, max_bytes=128*1024*1024 if path == '/usr/bin/suricata' else 64*1024*1024)
        need(p.sha(raw) == expected, 'suricata_pin_changed')
        result[path] = {'sha256': expected, 'metadata': meta}
    # Raw payload is never opened. Its permitted growth is not a config change.
    for path in ('/var/log/suricata/eve.json', '/var/log/suricata/capstone-managed/active.jsonl'):
        with p.parent_fd(path, root) as (parent, leaf):
            info = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 998 and
                 stat.S_IMODE(info.st_mode) == 0o644, 'raw_identity_invalid')
            result[path] = {'device': info.st_dev, 'inode': info.st_ino,
                            'uid': info.st_uid, 'gid': info.st_gid,
                            'mode': stat.S_IMODE(info.st_mode), 'links': info.st_nlink}
    return result


def run():
    need(len(sys.argv) == 1 and sys.platform == 'linux' and os.geteuid() == 0, 'fixed_linux_root_required')
    need(Path('/etc/machine-id').read_text().strip() == MID, 'fixed_machine_required')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    def interrupted(signum, frame):
        raise ValueError('native_check_interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    p = load_helper()
    result = {'schema_version': 1, 'status': 'incomplete', 'candidate_sha256': CANDIDATE_SHA,
              'helper_sha256': HELPER_SHA, 'runner_sha256': p.sha(Path(__file__).read_bytes()),
              'rules_published': False, 'service_signals': 0, 'network_traffic': False,
              'native_replay_verified': False, 'native_syntax_verified': False,
              'private_tree_removed': False, 'suricata_protected_unchanged': False}
    start = time.monotonic()
    with ExitStack() as stack:
        lock(stack, '/var/lib/rule-change/.lock')
        lock(stack, '/var/lib/capstone-automation/ansible/vector.lock')
        p.private_dir(EVIDENCE)
        observation = p.container('suricata')
        need(observation['pid'] == 1990031, 'fixed_suricata_pid_changed')
        need(sum(m['Source'] == '/home/groot_a/capstone/suricata/ruleset' and
                 m['Destination'] == '/rules' and m['Type'] == 'bind' and m['RW'] is False
                 for m in observation['mounts']) == 1, 'rules_readonly_mount_changed')
        with p.container_root('suricata', observation) as root:
            before = protected(p, root)
            raw_result, _ = p.snapshot(JOB / 'result.json', root, max_bytes=16384)
            generated, _ = p.snapshot(JOB / 'output/suricata.rules', root, max_bytes=64*1024*1024)
            upstream = p.parse(raw_result)
            need(upstream['status'] == 'candidate_compared_native_test_pending' and
                 upstream['protected_files_unchanged'] is True and upstream['rules_published'] is False and
                 upstream['comparison']['active_rule_maps_equal'] is True and
                 upstream['comparison']['input_effective_rules'] == upstream['comparison']['output_active_rules'] == 52495 and
                 upstream['generated_sha256'] == CANDIDATE_SHA == p.sha(generated) and
                 len(generated) == upstream['generated_bytes'] == 35666630, 'upstream_candidate_not_verified')
            result['updater_result_sha256'] = p.sha(raw_result)
            p.write_new(EVIDENCE / 'before.json', p.canonical({'container': observation, 'protected': before}))
            stage = Path('/tmp/capstone-update-native-v6-' + str(time.time_ns()))
            p.private_dir(stage, root)
            with p.parent_fd(stage, root) as (parent, leaf):
                info = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                stage_identity = (info.st_dev, info.st_ino)
            result['private_stage'] = str(stage)
            try:
                for relative in ('candidate', 'private', 'private/var_log', 'private/run', 'private/tmp',
                                 'private/var_log/suricata', 'private/var_log/suricata/capstone-managed'):
                    p.private_dir(stage / relative, root)
                for relative in ('var_log', 'run', 'var_log/suricata', 'var_log/suricata/capstone-managed'):
                    with p.parent_fd(stage / 'private' / relative, root) as (parent, leaf):
                        os.chmod(leaf, 0o755, dir_fd=parent)
                        if relative.startswith('var_log/suricata'):
                            os.chown(leaf, 998, 998, dir_fd=parent)
                with p.parent_fd(stage / 'private/tmp', root) as (parent, leaf):
                    os.chmod(leaf, 0o1777, dir_fd=parent)
                p.write_new(stage / 'private/var_log/suricata/capstone-managed/active.jsonl', b'', 0o644, root)
                with p.parent_fd(stage / 'private/var_log/suricata/capstone-managed/active.jsonl', root) as (parent, leaf):
                    os.chown(leaf, 998, 998, dir_fd=parent)
                config, _ = p.snapshot('/etc/suricata/suricata.yaml', root)
                p.write_new(stage / 'candidate/suricata_yaml', config, root_fd=root)
                p.write_new(stage / 'candidate/all.rules', generated, 0o644, root)
                anchor = '  /usr/bin/mount -o remount,bind,ro /etc/suricata/suricata.yaml\n'
                need(p.SHADOW_SCRIPT.count(anchor) == 1, 'shadow_patch_anchor_changed')
                script = p.SHADOW_SCRIPT.replace(anchor, anchor +
                    '  /usr/bin/mount --bind "$stage/candidate/all.rules" /rules/all.rules\n'
                    '  /usr/bin/mount -o remount,bind,ro /rules/all.rules\n', 1)
                need(script.count('exec /usr/bin/suricata -T -c ') == 1, 'shadow_command_anchor_changed')
                script = script.replace('exec /usr/bin/suricata -T -c ', 'exec /usr/bin/suricata -T -v -c ', 1)
                # Original helper validates visible root+proc RO before writable
                # private overlays; the candidate bind survives /tmp masking.
                p.write_new(stage / 'check.sh', script.encode(), 0o500, root)
                p.write_new(EVIDENCE / 'native-check.sh', script.encode(), 0o400)
                need(p.container('suricata') == observation, 'container_changed_before_native')
                root_info = os.fstat(root)
                result['native_returncode'], _ = p.command([
                    '/usr/bin/nsenter', '--target', str(observation['pid']), '--mount', '--root', '--wdns=/', '--',
                    '/usr/bin/unshare', '--mount', '--net', '--pid', '--fork', '--kill-child=KILL', '--',
                    '/bin/bash', '--noprofile', '--norc', str(stage / 'check.sh'), str(stage), 'suricata',
                    '%s:%s' % (root_info.st_dev, root_info.st_ino)], timeout=180, log=EVIDENCE / 'native.log')
                log, _ = p.snapshot(EVIDENCE / 'native.log', max_bytes=4*1024*1024)
                result['native_log_sha256'] = p.sha(log)
                try:
                    engine_log, _ = p.snapshot(stage / 'private/var_log/suricata/suricata.log', root, max_bytes=4*1024*1024)
                    p.write_new(EVIDENCE / 'engine-private.log', engine_log)
                except FileNotFoundError:
                    engine_log = b''
                totals = set(re.findall(rb'(\d+) rule files processed\. (\d+) rules successfully loaded, (\d+) rules failed, (\d+) rules skipped', log + b'\n' + engine_log))
                result['exact_rule_count_verified'] = totals == {(b'1', b'52495', b'0', b'0')}
                result['native_syntax_verified'] = result['native_returncode'] == 0 and result['exact_rule_count_verified']
                need(result['native_syntax_verified'], 'native_config_test_or_count_failed')
            except Exception as exc:
                result['reason'] = str(exc) if isinstance(exc, (ValueError, p.Refused)) else type(exc).__name__
            finally:
                try:
                    result['suricata_protected_unchanged'] = p.container('suricata') == observation and protected(p, root) == before
                except Exception:
                    result['suricata_protected_unchanged'] = False
                try:
                    mounts, _ = p.snapshot(stage / 'mount-targets', root, max_bytes=65536)
                    p.write_new(EVIDENCE / 'private-mount-targets.txt', mounts)
                except FileNotFoundError:
                    pass
                except Exception:
                    result['mount_metadata_preserved'] = False
                try:
                    # command() reaps its verified private group; pid namespace
                    # kill-child removes test descendants before this deletion.
                    p.remove_private_tree(root, stage, stage_identity)
                    result['private_tree_removed'] = True
                except Exception:
                    result['private_tree_removed'] = False
            result['status'] = ('native_syntax_verified' if result['native_syntax_verified'] and
                result['suricata_protected_unchanged'] and result['private_tree_removed'] else 'rejected')
            result['seconds'] = round(time.monotonic() - start, 3)
            p.write_new(EVIDENCE / 'result.json', p.canonical(result))
    print(p.canonical(result).decode(), end='')
    return 0 if result['status'] == 'native_syntax_verified' else 1


if __name__ == '__main__':
    try:
        sys.exit(run())
    except Exception as exc:
        print(json.dumps({'status': 'rejected_before_completion', 'reason': type(exc).__name__}, sort_keys=True))
        sys.exit(1)
