#!/usr/bin/env python3
"""Finite synthetic Wazuh 4.14.8 checkpoint observation, never a service.

Reuse the SHA-pinned raw-restart isolation/child cleanup implementation. Only
private synthetic JSON and a copied logcollector are used; no native checkpoint
is edited. A completed observation is not proof of the historical incident.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import socket
import stat
import sys
import time
import types

PINS = {
    'run-probe-a.py': '4886142c41408978438cdee641ba50c2e6eb27fee119e743802a176fd5d9ea83',
    'wazuh-isolated.sh': 'a9001ac1fb2755dcb94409817d44038665fbfb0c508469e0a428747cef6593cd',
}
OUTPUT = Path('/var/tmp/capstone-checkpoint-diagnosis-20261015')
MID = '096e90b6243e438aa8a7b392be754732'
MAX_CHUNK = 65536 - 256 - 1
IGNORE = r'^\{"timestamp":"[0-9T:.+-]+","event_type":"stats","stats":\{'


def trusted_file(path, expected):
    info = path.lstat()
    if not (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
            info.st_uid == info.st_gid == 0 and not stat.S_IMODE(info.st_mode) & 0o022):
        raise RuntimeError('dependency_metadata_invalid')
    raw = path.read_bytes()
    if len(raw) > 131072 or hashlib.sha256(raw).hexdigest() != expected:
        raise RuntimeError('dependency_sha_invalid')
    return raw


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--reuse', required=True, type=Path)
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    if not (sys.platform == 'linux' and os.geteuid() == 0 and
            Path('/etc/machine-id').read_text().strip() == MID):
        raise RuntimeError('fixed_A_root_required')
    if not (args.reuse.is_absolute() and args.output.parent == OUTPUT and
            re.fullmatch(r'run-[A-Za-z0-9_-]{1,40}', args.output.name)):
        raise RuntimeError('paths_rejected')
    for directory in (args.reuse, OUTPUT):
        for part in (directory, *directory.parents):
            s = part.lstat()
            if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or (
                    part != Path('/var/tmp') and stat.S_IMODE(s.st_mode) & 0o022):
                raise RuntimeError('directory_not_trusted')
    if stat.S_IMODE(OUTPUT.stat().st_mode) != 0o700:
        raise RuntimeError('output_parent_mode')
    sources = {name: trusted_file(args.reuse / name, digest) for name, digest in PINS.items()}
    module = types.ModuleType('checkpoint_diagnosis_isolation')
    module.__file__ = str(args.reuse / 'run-probe-a.py')
    exec(compile(sources['run-probe-a.py'], module.__file__, 'exec'), module.__dict__)
    m = module
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))

    class Observation(m.Profile):
        def append_bytes(self, raw):
            m.need(self.source.stat().st_size + len(raw) <= 2 * 1024 * 1024, 'fixture_size_limit')
            with self.source.open('ab') as f:
                f.write(raw); f.flush(); os.fsync(f.fileno())

        def append(self, sequences):
            self.append_bytes(b''.join(self.row(n) for n in sequences))

        def sample(self, label):
            try:
                cp = self.state()
            except (FileNotFoundError, json.JSONDecodeError, m.Refused):
                return None  # Native writer can be between truncate and write.
            raw = m.bounded(self.source)
            m.need(cp['offset'] <= len(raw), 'private_offset_beyond_source')
            cp.update(label=label, source_bytes=len(raw), source_sha256=m.sha(raw),
                      prefix_sha1=hashlib.sha1(raw[:cp['offset']]).hexdigest(),
                      eof_sha1=hashlib.sha1(raw).hexdigest())
            cp['prefix_matches'] = cp['hash'] == cp['prefix_sha1']
            cp['hash_matches_current_eof'] = cp['hash'] == cp['eof_sha1']
            return cp

        def observe(self, label, seconds, require_eof=False):
            deadline = time.monotonic() + seconds
            seen, identities = [], set()
            while time.monotonic() < deadline:
                self.collect(.025)
                m.need(self.child and self.child.live(), 'private_reader_exited_early')
                row = self.sample(label)
                if row:
                    key = (row['offset'], row['hash'], row['source_bytes'])
                    if key not in identities:
                        identities.add(key); seen.append(row)
                    if require_eof and row['offset'] == row['source_bytes'] and row['prefix_matches']:
                        break
            m.need(seen, 'no_native_checkpoint_observed')
            if require_eof:
                m.need(seen[-1]['offset'] == seen[-1]['source_bytes'] and
                       seen[-1]['prefix_matches'], 'private_checkpoint_did_not_recover')
            self.result.setdefault('observations', []).append({'label': label, 'states': seen})
            self.owner.save()
            return seen

        def execute(self):
            m.write_new(self.generation, b'')
            os.link(self.generation, self.source)
            m.command(['/bin/bash', str(args.reuse / 'wazuh-isolated.sh'), 'prepare', str(self.prefix)],
                      self.evidence, 'prepare', 45)
            # Private timing only: expose disk checkpoints without waiting the
            # operating vcheck interval. Installed options/files remain intact.
            options = self.prefix / 'etc/local_internal_options.conf'
            options.write_bytes(b'logcollector.remote_commands=0\nlogcollector.vcheck_files=1\n'
                                b'logcollector.loop_timeout=1\n')
            manifest = ''.join(hashlib.sha256((self.prefix / name).read_bytes()).hexdigest() + '  ' + name + '\n'
                               for name in ('bin/wazuh-logcollector', 'etc/internal_options.conf',
                                            'etc/local_internal_options.conf', 'etc/ossec.conf'))
            (self.prefix / 'prepared.sha256').write_text(manifest)
            # Reproduce the actual Suricata localfile filter, then compare an
            # otherwise identical private reader with that filter absent.
            config = self.prefix / 'etc/ossec.conf'
            value = config.read_text()
            m.need(value.count('</localfile>') == value.count('</location>') == 1, 'private_config_shape')
            future = '<only-future-events max-size="2GB">no</only-future-events>'
            if self.name == 'default':
                m.need('<only-future-events' not in value, 'unexpected_future_setting')
                value = value.replace('</location>', '</location>' + future)
                value = value.replace('</localfile>', '<ignore type="pcre2">' + IGNORE + '</ignore></localfile>')
            m.need(value.count(future) == 1, 'only_future_settings_not_matched')
            config.write_text(value)
            self.result.update(only_future_events='no', max_size='2GB')
            manifest = ''.join(hashlib.sha256((self.prefix / name).read_bytes()).hexdigest() + '  ' + name + '\n'
                               for name in ('bin/wazuh-logcollector', 'etc/internal_options.conf',
                                            'etc/local_internal_options.conf', 'etc/ossec.conf'))
            (self.prefix / 'prepared.sha256').write_text(manifest)
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            self.socket.bind(str(self.prefix / 'queue/sockets/queue'))
            os.chmod(self.prefix / 'queue/sockets/queue', 0o600)
            self.start(); self.append([1])
            self.wait(lambda: self.counts()[1] == 1, 'baseline_queue_missing')
            baseline = self.observe('baseline', 6, require_eof=True)[-1]
            stats = m.compact({'timestamp': '2026-10-15T05:00:00.000000+0900',
                              'event_type': 'stats', 'stats': {'fixture': 1}, 'seq': 10})
            self.expected[10] = stats
            bad = stats + b'\n'
            m.need(re.search(IGNORE, stats.decode()) and len(bad) < MAX_CHUNK and
                   isinstance(json.loads(bad), dict), 'stats_fixture_invalid')
            before_counts = self.counts()
            self.append_bytes(bad)
            samples = self.observe('after_stats_input', 6, require_eof=self.name == 'recover')
            if self.name == 'default':
                m.need(self.counts() == before_counts, 'ignored_stats_delivered')
            else:
                m.need(self.counts()[10] == 1, 'unfiltered_stats_not_delivered_once')
            self.result['input_case'] = {'shape': 'valid_stats_object', 'ignore_configured': self.name == 'default',
                'bytes_including_lf': len(bad),
                'nul_count': bad.count(b'\0'), 'lf_terminated': bad.endswith(b'\n'),
                'native_chunk_bytes': MAX_CHUNK}
            mismatches = [r for r in samples if not r['prefix_matches']]
            self.result['mismatch_observed'] = bool(mismatches)
            self.result['old_offset_hash_ahead_observed'] = any(
                r['offset'] == baseline['offset'] and r['hash_matches_current_eof'] for r in mismatches)
            if self.name == 'recover':
                m.need(not mismatches, 'unfiltered_checkpoint_mismatch')
            self.append([2])
            self.wait(lambda: self.counts()[2] == 1, 'following_valid_queue_missing')
            self.observe('following_valid_input', 6, require_eof=True)
            self.stop(require_eof=True)
            self.result['valid_queue_counts'] = dict(self.counts())
            self.owner.save()

    probe = m.Probe(args.output)
    probe.result.update(kind='native_wazuh_checkpoint_diagnosis',
                        live_incident_cause_proved=False, changed_private_timing=True,
                        production_guard_changed=False, dependency_sha256=PINS)
    m.write_new(args.output / Path(__file__).name, Path(__file__).read_bytes(), 0o400)

    def interrupted(_sig, _frame):
        raise m.Refused('fixture_interrupted_or_deadline')
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        signal.signal(sig, interrupted)
    signal.alarm(180)
    try:
        probe.result['operating_before'] = m.operating_snapshot(args.output, 'operating-before')
        probe.save()
        for name in ('default', 'recover'):
            profile = Observation(probe, name)
            probe.profiles.append(profile); profile.execute()
        probe.result['status'] = 'completed_observations'
    except BaseException as error:
        probe.result.update(status='failed', failure_code=str(error) if isinstance(error, m.Refused) else type(error).__name__)
    finally:
        signal.alarm(0)
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, signal.SIG_IGN)
        probe.cleanup()
    print(json.dumps(probe.result, sort_keys=True))
    return 0 if probe.result['status'] == 'completed_observations' else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({'status': 'refused', 'reason': str(error) if isinstance(error, RuntimeError) else type(error).__name__}))
        sys.exit(1)
