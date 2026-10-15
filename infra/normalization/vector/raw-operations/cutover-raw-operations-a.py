#!/usr/bin/env python3
"""Finite administrator-only initial migration; not a service or MCP tool.

Each explicit phase requires the exact immutable preparation plan and root on
fixed A. inspect does not create a ledger. Signal uncertainty never retries a
restart/HUP/stop automatically. Runtime handles subsequent ordinary rotations.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

HERE = Path(__file__).absolute().parent
PREPARATION_SHA256 = '6dcf1556f89c8882a422cf92a3c8caa90bbdcdf71b809d0224587fe45b17db15'
# Verify dependency bytes BEFORE executing any of them, including the inspect
# and invalid-argument paths. Missing/changed source is a fixed refusal.
try:
    _fd = os.open(HERE / 'deploy-raw-operations-a.py', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        _metadata = os.fstat(_fd)
        if not stat.S_ISREG(_metadata.st_mode) or _metadata.st_nlink != 1 or _metadata.st_size > 1048576:
            raise RuntimeError('preparation_source_metadata')
        _source = os.read(_fd, 1048577)
        if len(_source) != _metadata.st_size or hashlib.sha256(_source).hexdigest() != PREPARATION_SHA256:
            raise RuntimeError('preparation_source_hash')
    finally:
        os.close(_fd)
except (OSError, RuntimeError) as _error:
    if __name__ == '__main__':
        print('{"status":"refused","reason":"preparation_dependency_unavailable",'
              '"operating_mutations":false,"raw_exported":false}')
        sys.exit(2)
    raise RuntimeError('preparation_dependency_unavailable') from _error
spec = importlib.util.spec_from_loader('raw_prepare', loader=None)
p = importlib.util.module_from_spec(spec)
p.__file__ = str(HERE / 'deploy-raw-operations-a.py')
exec(compile(_source, p.__file__, 'exec'), p.__dict__)
LEDGER = p.BACKUP / 'migration.json'
PHASES = ('prepared', 'barrier_installed', 'legacy_excluded', 'suricata_writer_switched', 'waf_writer_switched',
          'readers_paused', 'readers_bootstrapped', 'guards_installed')
OPERATIONS = {'install-barrier': ('prepared', 'barrier_installed'),
              'apply-legacy': ('barrier_installed', 'legacy_excluded'),
              'apply-suricata': ('legacy_excluded', 'suricata_writer_switched'),
              'apply-waf-writer': ('suricata_writer_switched', 'waf_writer_switched'),
              'prepare-readers': ('waf_writer_switched', 'readers_paused'),
              'apply-readers': ('readers_paused', 'readers_bootstrapped'),
              'install-guards': ('readers_bootstrapped', 'guards_installed')}
UNITS = ('capstone-raw-operations', 'capstone-raw-operations@.service',
         'capstone-raw-operations@.timer', 'vector-start-guard.conf', 'wazuh-start-guard.conf')
BARRIER_ROOT = Path('/var/lib/capstone-raw-migration')
BARRIER = BARRIER_ROOT / 'start-barrier.json'
BARRIER_LIBRARY = Path('/usr/local/lib/capstone-raw-migration')
BARRIER_SOURCES = ('migration-start-guard.sh',)
DROPIN_NAME = '90-capstone-raw-start.conf'
SCANNER = Path('/usr/local/sbin/capstone-vector-raw-lines')
SCANNER_V1 = '6e694ee02ed983e105d38dfd22fa2f27b11e4ef4e678a670e10c7394ebb9f3ea'
RECOVERY_PREVIOUS_SOURCE = '9a17d6fac16240dbd98039253b806b5e115e2569e7f8ea0e38c472b61c956b83'
RECOVERY_PREVIOUS_LEDGER = '78f9261b6347ef43622428ad041e9bffb841c4c6d99804406052c8831b873343'
RECOVERY_RECEIPT = p.BACKUP / 'v1-recovery-receipt.json'
RECOVERY_EVIDENCE = p.BACKUP / 'recovery-evidence'
VECTOR_STATUS_FIELDS = {'ActiveState', 'SubState', 'InvocationID', 'MainPID', 'Result',
                        'ExecMainStatus', 'ExecMainStartTimestampMonotonic'}


def recovery_prestart_proof(proof, receipt):
    fields = {'schema_version', 'policy', 'status', 'reason', 'machine_id', 'boot_id',
              'authority_sha256', 'guard_sha256', 'plan_sha256', 'ledger_sha256', 'barrier_sha256',
              'checkpoints_rewritten', 'delivery_acknowledged', 'read_only',
              'raw_current_proofs', 'output_eof_proofs'}
    p.require(isinstance(proof, dict) and set(proof) == fields and
              type(proof['schema_version']) is int and proof['schema_version'] == 1 and
              proof['policy'] == 'capstone-v1-vector-recovery-20261015' and proof['status'] == 'pass' and
              proof['reason'] == 'verified_v1_start_only' and proof['machine_id'] == receipt['machine_id'] and
              proof['boot_id'] == receipt['boot_id'] and proof['plan_sha256'] == receipt['plan_sha256'] and
              proof['ledger_sha256'] == receipt['previous_ledger_sha256'] and
              proof['authority_sha256'] == receipt['evidence_sha256']['authority.json'] and
              proof['guard_sha256'] == receipt['guard_sha256'] and
              isinstance(proof['barrier_sha256'], str) and re.fullmatch('[a-f0-9]{64}', proof['barrier_sha256']) and
              proof['checkpoints_rewritten'] is False and proof['delivery_acknowledged'] is False and
              proof['read_only'] is True, 'recovery_prestart_binding_invalid')
    raw = proof['raw_current_proofs']
    p.require(isinstance(raw, list) and len(raw) == 3 and all(isinstance(item, dict) for item in raw),
              'recovery_raw_proof_invalid')
    identities = []
    for item in raw:
        identity = item.get('source_identity')
        p.require(item.get('gate') == 'vector_current' and item.get('verdict') == 'pass' and
                  item.get('reason') == 'current_offset_valid' and item.get('source_stable') is True and
                  isinstance(identity, dict) and type(identity.get('bytes')) is int and identity['bytes'] >= 0 and
                  type(identity.get('device')) is int and type(identity.get('inode')) is int and
                  type(item.get('offset')) is int and 0 <= item['offset'] <= identity['bytes'] and
                  isinstance(item.get('checkpoint_sha256'), str) and
                  re.fullmatch('[a-f0-9]{64}', item['checkpoint_sha256']), 'recovery_raw_proof_invalid')
        identities.append((identity.get('device'), identity.get('inode')))
    p.require(sorted(identities) == [(64512, 1441879), (64512, 1441881), (64512, 1441928)],
              'recovery_raw_identity_invalid')
    outputs = proof['output_eof_proofs']
    p.require(isinstance(outputs, list) and len(outputs) == 2 and
              all(isinstance(item, dict) for item in outputs), 'recovery_output_proof_invalid')
    paths = []
    for item in outputs:
        p.require(set(item) == {'path', 'device', 'inode', 'bytes', 'fd_count', 'position', 'empty_native_fd'} and
                  isinstance(item['path'], str) and
                  all(type(item[key]) is int for key in ('device', 'inode', 'bytes', 'fd_count', 'position')) and
                  item['device'] > 0 and item['inode'] > 0 and item['bytes'] >= 0 and item['fd_count'] == 1 and
                  item['position'] == item['bytes'] and
                  item['empty_native_fd'] is (item['bytes'] == 0), 'recovery_output_proof_invalid')
        paths.append(item['path'])
    p.require(sorted(paths) == ['/var/log/capstone-vector/evidence/normalized.jsonl',
                               '/var/log/capstone-vector/ready/normalized.jsonl'],
              'recovery_output_paths_invalid')


def recovery_authority_and_timer(authority, timer, receipt, proof):
    keys = {'schema_version', 'policy', 'machine_id', 'boot_id', 'plan_sha256', 'ledger_sha256',
            'cutover_sha256', 'prepare_sha256', 'guard_sha256', 'barrier_sha256',
            'issued_uptime_seconds', 'expiry_uptime_seconds', 'wazuh_pid', 'wazuh_start_ticks'}
    p.require(isinstance(authority, dict) and set(authority) == keys and
              type(authority['schema_version']) is int and authority['schema_version'] == 1 and
              authority['policy'] == proof['policy'] and authority['machine_id'] == receipt['machine_id'] and
              authority['boot_id'] == receipt['boot_id'] and authority['plan_sha256'] == receipt['plan_sha256'] and
              authority['ledger_sha256'] == receipt['previous_ledger_sha256'] and
              authority['cutover_sha256'] == receipt['previous_cutover_sha256'] and
              authority['prepare_sha256'] == PREPARATION_SHA256 and
              authority['guard_sha256'] == receipt['guard_sha256'] and
              authority['barrier_sha256'] == proof['barrier_sha256'] and
              type(authority['issued_uptime_seconds']) is int and authority['issued_uptime_seconds'] >= 0 and
              type(authority['expiry_uptime_seconds']) is int and
              0 < authority['expiry_uptime_seconds'] - authority['issued_uptime_seconds'] <= 900 and
              type(authority['wazuh_pid']) is int and 1 < authority['wazuh_pid'] < 2147483648 and
              type(authority['wazuh_start_ticks']) is int and
              0 < authority['wazuh_start_ticks'] <= 9007199254740991,
              'recovery_authority_binding_invalid')
    p.require(isinstance(timer, dict) and set(timer) == {'schema_version', 'unit', 'unit_sha256',
              'previous_unit_file_state', 'previous_active_state', 'current_unit_file_state', 'current_active_state'} and
              type(timer['schema_version']) is int and timer['schema_version'] == 1 and
              timer['unit'] == 'capstone-vector-maintenance.timer' and
              timer['previous_unit_file_state'] == 'enabled' and timer['previous_active_state'] == 'active' and
              timer['current_unit_file_state'] == 'disabled' and timer['current_active_state'] == 'inactive' and
              isinstance(timer['unit_sha256'], str) and re.fullmatch('[a-f0-9]{64}', timer['unit_sha256']),
              'recovery_timer_evidence_invalid')


def maintenance_paused():
    """An explicit operator pause, including reboot persistence; never stop it here."""
    rc, raw = p.command(['/usr/bin/systemctl', 'show', 'capstone-vector-maintenance.timer',
                          '-p', 'ActiveState', '-p', 'UnitFileState'])
    fields = dict(line.split('=', 1) for line in raw.decode('ascii').splitlines())
    p.require(rc == 0 and fields == {'ActiveState': 'inactive', 'UnitFileState': 'disabled'},
              'maintenance_timer_not_paused')
    value = unit_status('capstone-vector-maintenance.service')
    p.require(value['ActiveState'] in ('inactive', 'failed') and value['MainPID'] == '0',
              'maintenance_service_still_running')


def recovery_receipt(plan, before, ledger, expected_sha):
    """Validate an administrator's narrowly bound recovery record, not a start permit."""
    p.require(isinstance(expected_sha, str) and re.fullmatch('[a-f0-9]{64}', expected_sha),
              'recovery_receipt_sha_required')
    value, raw, _ = read_json(RECOVERY_RECEIPT)
    keys = {'schema_version', 'policy', 'machine_id', 'boot_id', 'plan_sha256', 'before_sha256',
            'previous_ledger_sha256', 'previous_cutover_sha256', 'old_vector_invocation_id',
            'vector_after', 'vector_start_ticks', 'evidence_sha256', 'guard_sha256',
            'completed_at_epoch', 'raw_deleted', 'checkpoint_rewritten', 'maintenance_rotation_repeated'}
    p.require(isinstance(value, dict) and set(value) == keys and p.sha(raw) == expected_sha and
              type(value['schema_version']) is int and value['schema_version'] == 1 and
              value['policy'] == 'capstone-raw-v1-recovery-1' and value['machine_id'] == p.MID and
              value['boot_id'] == ledger['boot_id'] == before['boot_id'] and
              value['plan_sha256'] == ledger['plan_sha256'] and
              value['before_sha256'] == plan['before_sha256'] and
              value['previous_ledger_sha256'] == RECOVERY_PREVIOUS_LEDGER and
              value['previous_cutover_sha256'] == RECOVERY_PREVIOUS_SOURCE and
              value['old_vector_invocation_id'] == before['units']['capstone-vector.service']['InvocationID'] and
              all(value[key] is False for key in ('raw_deleted', 'checkpoint_rewritten', 'maintenance_rotation_repeated')),
              'recovery_receipt_binding_invalid')
    status = value['vector_after']
    p.require(isinstance(status, dict) and set(status) == VECTOR_STATUS_FIELDS and
              all(isinstance(item, str) for item in status.values()) and
              status['ActiveState'] == 'active' and status['SubState'] == 'running' and
              status['Result'] == 'success' and status['ExecMainStatus'] == '0' and
              re.fullmatch('[a-f0-9]{32}', status['InvocationID']) and
              status['InvocationID'] != value['old_vector_invocation_id'] and
              re.fullmatch('[1-9][0-9]{0,9}', status['MainPID']) and int(status['MainPID']) > 1 and
              re.fullmatch('[1-9][0-9]{0,19}', status['ExecMainStartTimestampMonotonic']) and
              isinstance(value['vector_start_ticks'], str) and
              re.fullmatch('[1-9][0-9]{0,19}', value['vector_start_ticks']) and
              type(value['completed_at_epoch']) is int and value['completed_at_epoch'] > 0 and
              isinstance(value['guard_sha256'], str) and re.fullmatch('[a-f0-9]{64}', value['guard_sha256']),
              'recovery_reader_record_invalid')
    evidence = value['evidence_sha256']
    p.require(isinstance(evidence, dict) and set(evidence) ==
              {'authority.json', 'prestart.json', 'pending.before', 'timer-before.json'},
              'recovery_evidence_shape_invalid')
    decoded_evidence = {}
    for name, digest in evidence.items():
        p.require(isinstance(digest, str) and re.fullmatch('[a-f0-9]{64}', digest),
                  'recovery_evidence_hash_invalid')
        data, _ = p.snapshot(RECOVERY_EVIDENCE / name, expected=(digest, 0, 0, 0o400))
        if name == 'pending.before':
            p.require(data == b'pending\n' and digest == p.sha(b'pending\n'), 'recovery_pending_evidence_invalid')
        else:
            decoded = p.parse(data)
            p.require(isinstance(decoded, dict) and p.canonical(decoded) == data,
                      'recovery_metadata_not_canonical')
            decoded_evidence[name] = decoded
    recovery_prestart_proof(decoded_evidence['prestart.json'], value)
    recovery_authority_and_timer(decoded_evidence['authority.json'], decoded_evidence['timer-before.json'],
                                 value, decoded_evidence['prestart.json'])
    # The exact reviewed guard that supplied prestart evidence is retained with it.
    p.snapshot(RECOVERY_EVIDENCE / 'v1-recovery-guard.sh',
               expected=(value['guard_sha256'], 0, 0, 0o400))
    return value


def effective_before(plan, before, ledger):
    """Only the Vector invocation changes; immutable preparation evidence stays intact."""
    reference = ledger.get('v1_recovery')
    if reference is None:
        return before
    p.require(isinstance(reference, dict) and set(reference) == {'receipt_sha256', 'previous_ledger_sha256'} and
              reference['previous_ledger_sha256'] == RECOVERY_PREVIOUS_LEDGER,
              'recovery_ledger_reference_invalid')
    receipt = recovery_receipt(plan, before, ledger, reference['receipt_sha256'])
    return dict(before, units=dict(before['units'], **{
        'capstone-vector.service': dict(before['units']['capstone-vector.service'], **receipt['vector_after'])}))


def accept_v1_recovery(plan, before, old, receipt_sha):
    """One metadata-only source upgrade for the verified midnight maintenance incident."""
    ledger = old[0]
    receipt = recovery_receipt(plan, before, ledger, receipt_sha)
    existing = ledger.get('v1_recovery')
    if existing is not None:
        p.require(existing == {'receipt_sha256': receipt_sha,
                              'previous_ledger_sha256': RECOVERY_PREVIOUS_LEDGER},
                  'different_recovery_already_accepted')
        effective_before(plan, before, ledger)
        return old
    p.require(p.sha(old[1]) == RECOVERY_PREVIOUS_LEDGER and ledger['sequence'] == 6 and
              ledger['phase'] == 'legacy_excluded' and ledger['cutover_sha256'] == RECOVERY_PREVIOUS_SOURCE and
              ledger['intent']['operation'] == 'apply-suricata' and ledger['intent']['signal_armed'] is True,
              'recovery_source_upgrade_not_this_incident')
    p.snapshot(p.BACKUP / 'source/cutover-raw-operations-a.py',
               expected=(RECOVERY_PREVIOUS_SOURCE, 0, 0, 0o400))
    maintenance_paused()
    p.require(not os.path.lexists('/var/lib/capstone-vector-maintenance/resume.pending') and
              not os.path.lexists(p.STATE), 'recovery_not_complete')
    require_barrier(ledger)  # Original blocked guard/drop-in restored, no lasting bypass.
    _, marker_raw, _ = read_json(BARRIER, 0o600)
    proof, _, _ = read_json(RECOVERY_EVIDENCE / 'prestart.json')
    p.require(proof['barrier_sha256'] == p.sha(marker_raw), 'recovery_barrier_proof_changed')
    timer, _, _ = read_json(RECOVERY_EVIDENCE / 'timer-before.json')
    timer_raw, timer_info = p.snapshot('/etc/systemd/system/capstone-vector-maintenance.timer')
    p.require(p.sha(timer_raw) == timer['unit_sha256'] and timer_info['uid'] == timer_info['gid'] == 0 and
              not timer_info['mode'] & 0o022, 'recovery_timer_unit_changed')
    p.require(unit_status('capstone-vector.service') == receipt['vector_after'], 'recovery_reader_changed')
    identity = p.proc_identity(int(receipt['vector_after']['MainPID']), p.VECTOR)
    p.require(str(identity['start_ticks']) == receipt['vector_start_ticks'], 'recovery_reader_pid_reused')
    actual = p.container('suricata'); expected = ledger['containers']['suricata']
    p.require(actual['cid'] == expected['cid'] and actual['mounts'] == expected['mounts'] and
              actual['process'] != expected['process'], 'recovery_suricata_identity_invalid')
    reference = {'receipt_sha256': receipt_sha, 'previous_ledger_sha256': RECOVERY_PREVIOUS_LEDGER}
    proposed = dict(ledger, v1_recovery=reference)
    protected(plan, effective_before(plan, before, proposed),
              dict(proposed, containers=dict(ledger['containers'], suricata=actual)))
    source, info = p.snapshot(Path(__file__).absolute())
    p.require(info['uid'] == info['gid'] == 0 and not info['mode'] & 0o022, 'recovery_source_untrusted')
    durable_create(p.BACKUP / 'source/cutover-v1-recovery.py', source)
    updated = dict(proposed, sequence=ledger['sequence'] + 1, cutover_sha256=p.sha(source))
    # Phase, armed signal, original before/plan and all operating files are unchanged.
    return ledger_commit(old, updated)


def read_json(path, mode=0o400):
    raw, info = p.snapshot(path)
    p.require((info['uid'], info['gid'], info['mode']) == (0, 0, mode), 'private_metadata_permissions')
    value = p.parse(raw)
    p.require(p.canonical(value) == raw, 'private_metadata_not_canonical')
    return value, raw, info


def candidate(name, plan):
    raw, info = p.snapshot(p.BACKUP / 'candidate' / name)
    p.require(info['uid'] == 0 and info['gid'] == 0 and info['mode'] == 0o400 and
              p.sha(raw) == plan['candidate_sha256'][name], 'candidate_sha_changed')
    return raw


def ensure_directory(path, mode=0o700):
    """Resume only this fixed root-owned directory creation; never chmod foreign state."""
    if not os.path.lexists(path):
        p.private_dir(path)
    value = path.lstat()
    p.require(stat.S_ISDIR(value.st_mode) and value.st_uid == value.st_gid == 0 and
              stat.S_IMODE(value.st_mode) in (0o700, mode), 'owned_directory_conflict')
    os.chmod(path, mode)
    p.fsync_dir(path); p.fsync_dir(path.parent)


def durable_create(path, raw, mode=0o400):
    """Create-exclusively, or re-fsync the exact already published value.

    Only the deterministic root-owned temporary file may be repaired after a
    short write. Unknown bytes and any existing final conflict are preserved.
    """
    temporary = path.with_name('.migration-create-' + path.name)
    if os.path.lexists(path) and os.path.lexists(temporary):
        final_stat, temp_stat = path.lstat(), temporary.lstat()
        p.require(stat.S_ISREG(final_stat.st_mode) and stat.S_ISREG(temp_stat.st_mode) and
                  (final_stat.st_dev, final_stat.st_ino, final_stat.st_nlink) ==
                  (temp_stat.st_dev, temp_stat.st_ino, 2) and final_stat.st_nlink == 2 and
                  (final_stat.st_uid, final_stat.st_gid, stat.S_IMODE(final_stat.st_mode)) == (0, 0, mode),
                  'creation_link_conflict')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            p.require(os.read(fd, len(raw) + 1) == raw and p.identity(os.fstat(fd)) == p.identity(final_stat),
                      'creation_link_content_conflict')
            os.fsync(fd)
        finally:
            os.close(fd)
        temporary.unlink(); p.fsync_dir(path.parent)
    if os.path.lexists(path):
        current, info = p.snapshot(path)
        p.require(current == raw and (info['uid'], info['gid'], info['mode']) == (0, 0, mode),
                  'existing_artifact_conflict')
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        p.fsync_dir(path.parent)
        return
    if os.path.lexists(temporary):
        previous, info = p.snapshot(temporary)
        p.require(info['uid'] == info['gid'] == 0 and info['mode'] in (mode, 0o600) and
                  raw.startswith(previous), 'temporary_artifact_conflict')
        temporary.unlink(); p.fsync_dir(temporary.parent)
    p.write_new(temporary, raw, mode)
    # Hardlink publishes without replacement, unlike os.replace on a new file.
    os.link(temporary, path, follow_symlinks=False)
    p.fsync_dir(path.parent)
    temporary.unlink(); p.fsync_dir(path.parent)


def ensure_replacement(path, raw, old_digest, uid, gid, mode, root_fd=None):
    current, info = p.snapshot(path, root_fd)
    p.require((info['uid'], info['gid'], info['mode']) == (uid, gid, mode), 'replacement_permissions_conflict')
    digest = p.sha(current)
    if digest == p.sha(raw):
        # Re-fsync a rename found after an interrupted previous invocation.
        with p.parent_fd(path, root_fd) as (directory, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            os.fsync(directory)
        return info
    p.require(digest == old_digest, 'replacement_old_or_candidate_sha_conflict')
    return atomic_replace(path, raw, current, info, uid, gid, mode, root_fd)


def atomic_replace(path, raw, old_raw, old_info, uid, gid, mode, root_fd=None):
    """Same-directory publication with exact named-file CAS, never follows links."""
    with p.parent_fd(path, root_fd) as (directory, leaf):
        temporary = '.capstone-initial-' + leaf
        try:
            abandoned = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            abandoned = None
        if abandoned is not None:
            try:
                meta = os.fstat(abandoned)
                data = os.read(abandoned, len(raw) + 1)
                owner_ok = (meta.st_uid, meta.st_gid) == (uid, gid) or \
                    (meta.st_uid == meta.st_gid == 0 and meta.st_size == 0 and stat.S_IMODE(meta.st_mode) == 0o600)
                p.require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1 and owner_ok and
                          stat.S_IMODE(meta.st_mode) in (0o600, mode) and raw.startswith(data) and
                          len(data) == meta.st_size, 'replacement_temporary_conflict')
            finally:
                os.close(abandoned)
            os.unlink(temporary, dir_fd=directory); os.fsync(directory)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            view = memoryview(raw)
            while view:
                n = os.write(fd, view)
                p.require(n > 0, 'candidate_short_write')
                view = view[n:]
            os.fsync(fd)
            current, info = p.snapshot(path, root_fd)
            p.require(current == old_raw and info == old_info, 'configuration_cas_conflict')
            os.replace(temporary, leaf, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            os.close(fd)
        actual, info = p.snapshot(path, root_fd, (p.sha(raw), uid, gid, mode))
        return info


def unit_status(unit):
    rc, raw = p.command(['/usr/bin/systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'SubState',
                          '-p', 'InvocationID', '-p', 'MainPID', '-p', 'Result',
                          '-p', 'ExecMainStatus', '-p', 'ExecMainStartTimestampMonotonic'])
    p.require(rc == 0, 'unit_metadata_unavailable')
    return dict(line.split('=', 1) for line in raw.decode('ascii').splitlines())


def logged_command(argv, label, timeout=30):
    p.require(re.fullmatch('[a-z][a-z0-9-]{0,50}', label), 'invalid_diagnostic_label')
    directory = p.BACKUP / 'operator-logs'
    ensure_directory(directory)
    p.require(len(list(directory.iterdir())) < 64, 'diagnostic_attempt_limit')
    return p.command(argv, timeout=timeout, log=directory / ('%s-%s.log' % (label, time.time_ns())))


def barrier_value(old):
    ledger = old[0]
    return {'schema_version': 1, 'policy': 'capstone-raw-migration-start-v1', 'machine_id': p.MID,
            'phase': 'blocked', 'plan_sha256': ledger['plan_sha256'], 'armed_boot_id': ledger['boot_id'],
            'armed_ledger_sha256': p.sha(old[1]), 'release': None}


def require_barrier(ledger, allow_released=False):
    value, _, _ = read_json(BARRIER, 0o600)
    p.require(value['policy'] == 'capstone-raw-migration-start-v1' and value['machine_id'] == p.MID and
              value['plan_sha256'] == ledger['plan_sha256'] and
              value['phase'] in (('blocked', 'released') if allow_released else ('blocked',)),
              'startup_barrier_not_bound')
    _, marker_raw, _ = read_json(BARRIER, 0o600)
    p.snapshot(BARRIER_LIBRARY / 'migration-start-guard.sh',
                         expected=(ledger['unit_sha256']['migration-start-guard.sh'], 0, 0, 0o400))
    rc, report = p.command(['/bin/bash', str(BARRIER_LIBRARY / 'migration-start-guard.sh'), 'inspect'])
    p.require(rc == 0 and p.parse(report).get('barrier_sha256') == p.sha(marker_raw),
              'startup_barrier_schema_invalid')
    for unit, reader in (('capstone-vector.service', 'vector'), ('wazuh-agent.service', 'wazuh')):
        target = Path('/etc/systemd/system') / (unit + '.d') / DROPIN_NAME
        artifact = unit_artifact(reader + '-start-guard.conf', ledger)
        temporary = artifact.replace(b'/usr/local/lib/capstone-raw-operations/guard.sh',
                                     b'/usr/local/lib/capstone-raw-migration/migration-start-guard.sh')
        actual, info = p.snapshot(target)
        permitted = (temporary, artifact) if allow_released and value['phase'] == 'released' else (temporary,)
        p.require(actual in permitted and (info['uid'], info['gid'], info['mode']) == (0, 0, 0o644),
                  'startup_dropin_changed')
        rc, output = p.command(['/usr/bin/systemctl', 'show', unit, '-p', 'DropInPaths', '-p', 'ExecStartPre'])
        text = output.decode('utf-8')
        effective = [line.split(b'/bin/bash ', 1)[1].decode() for artifact_bytes in permitted
                     for line in artifact_bytes.splitlines() if line.startswith(b'ExecStartPre=')]
        p.require(rc == 0 and str(target) in text and any(value in text for value in effective),
                  'startup_barrier_not_effective')
    return value


def install_barrier(plan, before, old):
    protected(plan, before, old[0])
    old = begin(old, 'install-barrier')
    marker = barrier_value(old)
    ensure_directory(BARRIER_ROOT)
    ensure_directory(BARRIER_LIBRARY, 0o755)
    durable_create(BARRIER_LIBRARY / 'migration-start-guard.sh', unit_artifact('migration-start-guard.sh', old[0]))
    durable_create(BARRIER, p.canonical(marker), 0o600)
    for unit, reader in (('capstone-vector.service', 'vector'), ('wazuh-agent.service', 'wazuh')):
        directory = Path('/etc/systemd/system') / (unit + '.d')
        ensure_directory(directory, 0o755)
        p.require(all(path.name in (DROPIN_NAME, '.migration-create-' + DROPIN_NAME)
                      for path in directory.iterdir()), 'unrelated_reader_dropin_present')
        source = unit_artifact(reader + '-start-guard.conf', old[0])
        p.require(source.count(b'/usr/local/lib/capstone-raw-operations/guard.sh') == 1,
                  'fixed_final_guard_template_changed')
        temporary = source.replace(b'/usr/local/lib/capstone-raw-operations/guard.sh',
                                   b'/usr/local/lib/capstone-raw-migration/migration-start-guard.sh')
        durable_create(directory / DROPIN_NAME, temporary, 0o644)
    rc, _ = logged_command(['/usr/bin/systemctl', 'daemon-reload'], 'barrier-daemon-reload')
    p.require(rc == 0, 'barrier_reload_failed')
    require_barrier(old[0])
    for reader in ('vector', 'wazuh'):
        rc, output = p.command(['/bin/bash', str(BARRIER_LIBRARY / 'migration-start-guard.sh'), reader])
        p.require(rc != 0, 'blocked_guard_unexpectedly_passed')
    protected(plan, before, old[0])
    return finish(old, 'install-barrier', {'marker_sha256': p.sha(p.canonical(marker)),
                  'readers_remained_running': True, 'new_starts_blocked': True})


def load_plan(expected, inspection=False):
    p.require(re.fullmatch('[0-9a-f]{64}', expected), 'plan_sha_required')
    plan, raw, _ = read_json(p.BACKUP / 'plan.json')
    p.require(p.sha(raw) == expected and plan['phase'] == 'prepared' and
              plan['machine_id'] == p.MID and plan['native']['waf']['exit_code'] == 0 and
              plan['native']['suricata']['exit_code'] == 0, 'prepared_plan_invalid')
    p.require(inspection or plan['boot_id'] == Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-', ''),
              'prepared_boot_changed')
    before, original, _ = read_json(p.BACKUP / 'before.json')
    p.require(p.sha(original) == plan['before_sha256'], 'before_evidence_changed')
    installer, _ = p.snapshot(HERE / 'deploy-raw-operations-a.py')
    p.require(p.sha(installer) == plan['installer_sha256'], 'preparation_source_changed')
    for name, digest in plan['source_sha256'].items():
        source, info = p.snapshot(p.BACKUP / 'source' / name)
        p.require(info['uid'] == info['gid'] == 0 and info['mode'] == 0o400 and
                  p.sha(source) == digest, 'prepared_runtime_source_changed')
    for name in plan['candidate_sha256']:
        candidate(name, plan)
    return plan, before


def new_ledger(plan_sha, before):
    source, _ = p.snapshot(Path(__file__).absolute())
    durable_create(p.BACKUP / 'source/cutover-raw-operations-a.py', source)
    units = {}
    for name in (*UNITS, *BARRIER_SOURCES):
        data, info = p.snapshot(HERE / name)
        p.require(info['uid'] == info['gid'] == 0 and not info['mode'] & 0o022, 'unit_source_untrusted')
        durable_create(p.BACKUP / 'source' / name, data)
        units[name] = p.sha(data)
    scanner, _ = p.snapshot(SCANNER, expected=(SCANNER_V1, 0, 0, 0o755))
    durable_create(p.BACKUP / 'original/scanner', scanner)
    ledger = {'schema_version': 1, 'machine_id': p.MID, 'boot_id': before['boot_id'],
              'plan_sha256': plan_sha, 'cutover_sha256': p.sha(source), 'sequence': 0,
              'phase': 'prepared', 'intent': None, 'containers': before['containers'],
              'completed': [], 'unit_sha256': units, 'raw_deleted': False, 'checkpoint_rewritten': False}
    ensure_directory(p.BACKUP / 'migration-history')
    durable_create(LEDGER, p.canonical(ledger), 0o600)
    return read_json(LEDGER, 0o600)


def ledger_read(plan_sha, inspection=False, recovery_upgrade=False):
    ledger, raw, info = read_json(LEDGER, 0o600)
    source, _ = p.snapshot(Path(__file__).absolute())
    permitted_source = ledger['cutover_sha256'] == p.sha(source)
    if recovery_upgrade and not permitted_source:
        permitted_source = (ledger['cutover_sha256'] == RECOVERY_PREVIOUS_SOURCE and
                            p.sha(raw) == RECOVERY_PREVIOUS_LEDGER)
    p.require(ledger['plan_sha256'] == plan_sha and permitted_source and
              ledger['phase'] in PHASES and (inspection or ledger['boot_id'] ==
              Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-', '')),
              'migration_binding_changed')
    return ledger, raw, info


def ledger_commit(old, new):
    ledger, raw, info = old
    p.require(new['sequence'] == ledger['sequence'] + 1, 'migration_sequence_invalid')
    archive = p.BACKUP / 'migration-history' / ('%04d-%s.json' % (ledger['sequence'], p.sha(raw)))
    durable_create(archive, raw)
    atomic_replace(LEDGER, p.canonical(new), raw, info, 0, 0, 0o600)
    return read_json(LEDGER, 0o600)


def begin(old, operation, metadata=None):
    ledger = old[0]
    p.require(ledger['phase'] == OPERATIONS[operation][0],
              'phase_or_uncertain_intent_requires_inspect')
    if ledger['intent'] is not None:
        p.require(ledger['intent']['operation'] == operation, 'different_operation_pending')
        return old
    updated = dict(ledger, sequence=ledger['sequence'] + 1,
                   intent={'operation': operation, 'started_at_epoch': int(time.time()),
                           'metadata': metadata or {}, 'signal_armed': False,
                           'automatic_signal_replay_allowed': False})
    return ledger_commit(old, updated)


def arm_signal(old):
    ledger = old[0]
    p.require(ledger['intent'] is not None and ledger['intent']['signal_armed'] is False,
              'signal_already_armed_no_automatic_replay')
    updated = dict(ledger, sequence=ledger['sequence'] + 1,
                   intent=dict(ledger['intent'], signal_armed=True))
    return ledger_commit(old, updated)


def finish(old, operation, result, containers=None):
    ledger = old[0]
    p.require(ledger['intent']['operation'] == operation, 'phase_intent_changed')
    entry = {'operation': operation, 'finished_at_epoch': int(time.time()), 'result': result}
    updated = dict(ledger, sequence=ledger['sequence'] + 1, phase=OPERATIONS[operation][1],
                   intent=None, completed=ledger['completed'] + [entry],
                   containers=containers or ledger['containers'])
    return ledger_commit(old, updated)


def protected(plan, before, ledger, allow_paused=False, allow_state=False, allow_released=False):
    """Before each phase compare all original/candidate configs and exact CID."""
    maintenance_paused()
    changed = set()
    if PHASES.index(ledger['phase']) >= PHASES.index('legacy_excluded'):
        changed.add('logrotate')
    if PHASES.index(ledger['phase']) >= PHASES.index('suricata_writer_switched'):
        changed.add('suricata_yaml')
    if PHASES.index(ledger['phase']) >= PHASES.index('waf_writer_switched'):
        changed.update(('waf_override', 'waf_producer'))
    if PHASES.index(ledger['phase']) >= PHASES.index('readers_bootstrapped'):
        changed.update(('vector', 'environment', 'waf_binding', 'line_binding'))
    pending = ledger['intent']['operation'] if ledger['intent'] else None
    released = False
    if ledger['phase'] != 'prepared':
        released = require_barrier(ledger, allow_released=allow_released)['phase'] == 'released'
    partial = {'apply-legacy': {'logrotate'}, 'apply-suricata': {'suricata_yaml'},
               'apply-waf-writer': {'waf_override', 'waf_producer'},
               'apply-readers': {'vector', 'environment', 'waf_binding', 'line_binding'}}.get(pending, set())
    for key, (path, old_sha, uid, gid, mode) in p.HOST.items():
        digest = plan['candidate_sha256'][key] if key in changed else old_sha
        value, info = p.snapshot(path)
        permitted = {digest} | ({plan['candidate_sha256'][key]} if key in partial else set())
        p.require(p.sha(value) in permitted and (info['uid'], info['gid'], info['mode']) == (uid, gid, mode),
                  'host_protected_config_changed')
    for key, (name, path, old_sha, uid, gid, mode) in p.ENGINE.items():
        digest = plan['candidate_sha256'][key] if key in changed else old_sha
        with p.container_root(name, ledger['containers'][name]) as root:
            value, info = p.snapshot(path, root)
            permitted = {digest} | ({plan['candidate_sha256'][key]} if key in partial else set())
            p.require(p.sha(value) in permitted and (info['uid'], info['gid'], info['mode']) == (uid, gid, mode),
                      'engine_protected_config_changed')
    for name, digest in p.BASELINE_VRL.items():
        p.snapshot(p.CONFIG / 'transforms' / name, expected=(digest, 0, 0, 0o600))
    p.require(not os.path.lexists('/var/lib/capstone-vector-maintenance/resume.pending') and
              (allow_state or not os.path.lexists(p.STATE)), 'initial_state_or_maintenance_conflict')
    for name in ('capstone-vector.service', 'wazuh-agent.service'):
        value = unit_status(name)
        if allow_released and released and value['ActiveState'] == 'active':
            # install_guards separately proves the exact release and invokes
            # both pinned normal guards before accepting such an auto-start.
            continue
        if allow_paused and name == 'capstone-vector.service':
            p.require(value['ActiveState'] == 'inactive' and value['Result'] == 'success' and
                      value['ExecMainStatus'] == '0', 'vector_not_cleanly_paused')
        else:
            p.require(value['ActiveState'] == 'active' and value['InvocationID'] ==
                      before['units'][name]['InvocationID'], 'reader_invocation_changed')


@contextmanager
def logrotate_lock():
    path = Path('/var/lib/logrotate/status')
    with p.parent_fd(path) as (directory, leaf):
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            info = os.fstat(fd)
            p.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                      not stat.S_IMODE(info.st_mode) & 0o022, 'logrotate_state_identity_invalid')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            p.require(unit_status('logrotate.service')['ActiveState'] == 'inactive', 'logrotate_busy')
            yield
        finally:
            os.close(fd)


def apply_legacy(plan, before, old):
    with logrotate_lock():
        protected(plan, before, old[0])
        path, digest, uid, gid, mode = p.HOST['logrotate']
        old = begin(old, 'apply-legacy')
        ensure_replacement(path, candidate('logrotate', plan), digest, uid, gid, mode)
        # --debug reads rules/state but does not rotate or rewrite status.
        rc, _ = logged_command(['/usr/sbin/logrotate', '--debug', '/etc/logrotate.conf'], 'logrotate-debug')
        p.require(rc == 0, 'logrotate_candidate_native_failed')
        return finish(old, 'apply-legacy', {'configuration_sha256': plan['candidate_sha256']['logrotate'],
                       'raw_aliases_excluded': True, 'raw_rotated': False})


def initial_link(name):
    fixed = p.CONTAINERS[name]
    alias = Path(fixed['raw'])
    managed = alias.parent / 'capstone-managed'
    ensure_directory(managed, 0o711)
    permitted = {'generation-0000000000.jsonl', 'active.jsonl'} if name == 'suricata' else {
        'generation-0000000000.jsonl', 'generation-0000000001.jsonl', 'audit-path.conf',
        '.migration-create-generation-0000000001.jsonl', '.migration-create-audit-path.conf'}
    p.require(all(path.name in permitted for path in managed.iterdir()), 'managed_directory_unknown_file')
    with p.parent_fd(alias) as (parent, leaf):
        info = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        p.require(stat.S_ISREG(info.st_mode) and
                  (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
                  (fixed['device'], fixed['inode'], fixed['uid'], fixed['uid'], 0o644), 'raw_identity_changed')
        target = managed / 'generation-0000000000.jsonl'
        destinations = [target] + ([managed / 'active.jsonl'] if name == 'suricata' else [])
        present = 0
        for destination in destinations:
            if os.path.lexists(destination):
                value = destination.lstat()
                p.require(stat.S_ISREG(value.st_mode) and (value.st_dev, value.st_ino) ==
                          (fixed['device'], fixed['inode']), 'managed_hardlink_conflict')
                present += 1
        p.require(info.st_nlink == 1 + present, 'raw_extra_hardlink')
        for destination in destinations:
            if not os.path.lexists(destination):
                os.link(alias, destination, follow_symlinks=False)
                p.fsync_dir(managed)
        after = alias.lstat()
        expected_links = 3 if name == 'suricata' else 2
        p.require((after.st_dev, after.st_ino, after.st_nlink) ==
                  (fixed['device'], fixed['inode'], expected_links), 'raw_link_publication_conflict')
        p.fsync_dir(managed)
        return p.identity(after)


def replace_engine(name, key, plan, expected_container):
    _, path, digest, uid, gid, mode = p.ENGINE[key]
    with p.container_root(name, expected_container) as root:
        return ensure_replacement(path, candidate(key, plan), digest, uid, gid, mode, root)


def apply_suricata(plan, before, old):
    expected = old[0]['containers']['suricata']
    armed = bool(old[0]['intent'] and old[0]['intent'].get('signal_armed'))
    if not armed:
        protected(plan, before, old[0])
        old = begin(old, 'apply-suricata', {'signal': 'same_container_restart_once'})
        initial_link('suricata')
        replace_engine('suricata', 'suricata_yaml', plan, expected)
        p.require(p.container('suricata') == expected, 'suricata_changed_before_restart')
        old = arm_signal(old)
        rc, _ = logged_command([p.DOCKER, 'restart', '--time', '30', expected['cid']], 'suricata-restart', 90)
        p.require(rc == 0, 'suricata_restart_uncertain_inspect_required')
    else:
        p.require(old[0]['intent']['operation'] == 'apply-suricata', 'different_signal_intent')
        require_barrier(old[0])
    actual = p.container('suricata')
    p.require(actual['cid'] == expected['cid'] and actual['mounts'] == expected['mounts'] and
              actual['process'] != expected['process'], 'suricata_restart_identity_not_proven')
    with p.container_root('suricata', actual) as root:
        p.snapshot(p.ENGINE['suricata_yaml'][1], root,
                   (plan['candidate_sha256']['suricata_yaml'], 998, 998, 0o600))
    linked_after = Path(p.CONTAINERS['suricata']['raw']).lstat()
    p.require((linked_after.st_dev, linked_after.st_ino, linked_after.st_nlink) ==
              (p.CONTAINERS['suricata']['device'], p.CONTAINERS['suricata']['inode'], 3),
              'suricata_raw_not_preserved')
    initial_link('suricata')
    writer_open('suricata', linked_after.st_dev, linked_after.st_ino)
    containers = dict(old[0]['containers'], suricata=actual)
    protected(plan, before, dict(old[0], containers=containers))
    return finish(old, 'apply-suricata', {'same_cid': True, 'raw_inode_preserved': True,
                  'source_aliases': 3, 'reader_restarted': False}, containers)


def apply_waf_writer(plan, before, old):
    protected(plan, before, old[0])
    old = begin(old, 'apply-waf-writer', {'signal': 'same_container_hup_once',
                 'new_generation': 1, 'old_vector_format_preserved': True})
    linked = initial_link('waf')
    managed = Path(p.CONTAINERS['waf']['raw']).parent / 'capstone-managed'
    new = managed / 'generation-0000000001.jsonl'
    if not os.path.lexists(new):
        p.write_new(new, b'', 0o644)
    new_meta = new.lstat()
    p.require(stat.S_ISREG(new_meta.st_mode) and new_meta.st_nlink == 1 and
              stat.S_IMODE(new_meta.st_mode) == 0o644 and
              ((new_meta.st_uid == new_meta.st_gid == 0 and new_meta.st_size == 0) or
               new_meta.st_uid == new_meta.st_gid == 101), 'new_writer_generation_conflict')
    if new_meta.st_uid == 0:
        os.chown(new, 101, 101)
    with new.open('rb') as handle:
        os.fsync(handle.fileno())
    durable_create(managed / 'audit-path.conf', candidate('audit_path', plan), 0o444)
    expected = old[0]['containers']['waf']
    replace_engine('waf', 'waf_producer', plan, expected)
    replace_engine('waf', 'waf_override', plan, expected)
    if not old[0]['intent']['signal_armed']:
        rc, _ = logged_command([p.DOCKER, 'exec', '--user', '0', expected['cid'], '/usr/sbin/nginx', '-t'],
                              'waf-config-before-hup')
        p.require(rc == 0 and p.container('waf') == expected, 'waf_changed_or_native_check_failed')
        old = arm_signal(old)
        rc, _ = logged_command([p.DOCKER, 'kill', '--signal=HUP', expected['cid']], 'waf-hup', 20)
        p.require(rc == 0 and p.container('waf') == expected, 'waf_hup_uncertain_inspect_required')
    writer_open('waf', new.stat().st_dev, new.stat().st_ino)
    return finish(old, 'apply-waf-writer', {'same_cid_master': True, 'v1_inode_preserved': True,
                'v1_vector_still_running': True, 'v2_audit_generation': 1,
                'temporary_v2_access_quarantine_possible': True, 'publish_permitted': False})


def gate(name, *arguments):
    allowed = {'cg_vector_eof', 'cg_vector_current', 'cg_wazuh_eof', 'cg_wazuh_cold',
               'cg_sealed_lines', 'writer_identity', 'writer_gate'}
    p.require(name in allowed, 'unknown_gate')
    library = 'writer-gates.sh' if name.startswith('writer_') else 'checkpoint-gates.sh'
    script = 'set -euo pipefail; source "$1"; shift; name=$1; shift; "$name" "$@"'
    rc, output = p.command(['/bin/bash', '--noprofile', '--norc', '-c', script, 'initial-gate',
                            str(p.BACKUP / 'source' / library), name, *map(str, arguments)], timeout=35)
    p.require(rc == 0, 'native_gate_' + name + '_deferred')
    result = p.parse(output)
    p.require(type(result) is dict, 'native_gate_shape_invalid')
    return result


def writer_open(name, device, inode):
    expected = gate('writer_identity', name)['identity']
    script = 'set -uo pipefail; source "$1"; shift; writer_gate "$@"'
    rc, raw = p.command(['/bin/bash', '--noprofile', '--norc', '-c', script, 'initial-open-writer',
                        str(p.BACKUP / 'source/writer-gates.sh'), name,
                        json.dumps(expected, separators=(',', ':')), str(device), str(inode)], timeout=20)
    value = p.parse(raw)
    p.require(rc == 10 and value['status'] == 'open' and value['writable_fd_count'] > 0 and
              value['identity'] == expected and expected['cid'] == p.CONTAINERS[name]['cid'],
              'new_writer_open_not_proven_no_signal_retry')
    return value


def raw_hash(path, expected_links=None):
    with p.parent_fd(path) as (directory, leaf):
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(fd)
            p.require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= 536870912 and
                      (expected_links is None or before.st_nlink == expected_links), 'sealed_source_metadata_invalid')
            digest = p.hashlib.sha256()
            remain = before.st_size
            deadline = time.monotonic() + 15
            while remain:
                p.require(time.monotonic() < deadline, 'sealed_source_hash_timeout')
                data = os.read(fd, min(1048576, remain))
                p.require(data, 'sealed_source_short_read')
                digest.update(data); remain -= len(data)
            after = os.fstat(fd)
            current = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
            p.require(p.identity(before) == p.identity(after) == p.identity(current), 'sealed_source_changed')
            return p.identity(before), digest.hexdigest()
        finally:
            os.close(fd)


def waf_paths():
    alias = Path(p.CONTAINERS['waf']['raw'])
    managed = alias.parent / 'capstone-managed'
    return alias, managed / 'generation-0000000000.jsonl', managed / 'generation-0000000001.jsonl'


def distinct_prefix(current, pending, size):
    new = pending.lstat()
    p.require(stat.S_ISREG(new.st_mode) and (new.st_uid, new.st_gid, new.st_nlink,
              stat.S_IMODE(new.st_mode)) == (101, 101, 1, 0o644) and 0 < new.st_size <= 2147483648,
              'new_generation_empty_or_invalid')
    if size:
        rc, _ = p.command(['/usr/bin/cmp', '-s', '-n', str(min(size, new.st_size)), '--',
                           str(current), str(pending)], timeout=30)
        p.require(rc == 1, 'new_generation_common_prefix_ambiguous')
    return p.identity(new)


def prior_result(ledger, operation):
    selected = [row['result'] for row in ledger['completed'] if row['operation'] == operation]
    p.require(len(selected) == 1, 'migration_prior_phase_missing')
    return selected[0]


def pause_is_owned(status, recorded):
    return (status['ActiveState'] == 'inactive' and status['Result'] == 'success' and
            status['ExecMainStatus'] == '0' and
            status['ExecMainStartTimestampMonotonic'] == recorded['ExecMainStartTimestampMonotonic'] and
            status['InvocationID'] in ('', recorded['InvocationID']))


def access_identity():
    path = p.BASE / 'modsec/capstone-access.log'
    info = path.lstat()
    p.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
              (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) ==
              (64512, 1441928, 101, 101, 0o640), 'access_source_identity_changed')
    return path, p.identity(info)


def old_reader_proofs(proof):
    alias, current, pending = waf_paths(); fixed = p.CONTAINERS['waf']
    gate('writer_gate', 'waf', json.dumps(proof['writer'], separators=(',', ':')),
         fixed['device'], fixed['inode'])
    info, digest = raw_hash(current, 2)
    p.require((info['device'], info['inode'], info['bytes'], digest) ==
              (fixed['device'], fixed['inode'], proof['old_source']['bytes'], proof['old_source_sha256']),
              'old_source_content_changed')
    v = gate('cg_vector_eof', '/var/lib/capstone-vector/waf_audit', current,
             fixed['device'], fixed['inode'], info['bytes'])
    w = gate('cg_wazuh_eof', '/var/ossec/queue/logcollector/file_status.json', alias, current,
             fixed['device'], fixed['inode'], info['bytes'])
    access, access_meta = access_identity()
    p.require(access_meta['bytes'] >= proof['access_prefix_bytes'], 'old_access_prefix_truncated')
    a = gate('cg_vector_current', '/var/lib/capstone-vector/waf_access', access,
             access_meta['device'], access_meta['inode'])
    p.require(a['offset'] >= proof['access_prefix_bytes'], 'old_access_checkpoint_pending')
    return info, v, w, a


def prepare_readers(plan, before, old):
    # The native logrotate state lock prevents the old access prefix from being
    # copytruncated during the audit+access EOF/TTL/stop proof. No rotation runs.
    with logrotate_lock():
        intent = old[0]['intent']
        armed = bool(intent and intent.get('signal_armed'))
        protected(plan, before, old[0], allow_paused=armed)
        alias, current, pending = waf_paths(); fixed = p.CONTAINERS['waf']
        if intent is None:
            writer = gate('writer_identity', 'waf')['identity']
            p.require(writer['cid'] == fixed['cid'], 'waf_writer_binding_changed')
            gate('writer_gate', 'waf', json.dumps(writer, separators=(',', ':')), fixed['device'], fixed['inode'])
            raw_info, digest = raw_hash(current, 2)
            p.require((raw_info['device'], raw_info['inode'], raw_info['uid'], raw_info['gid'], raw_info['mode']) ==
                      (fixed['device'], fixed['inode'], 101, 101, 0o644), 'old_generation_changed')
            distinct_prefix(current, pending, raw_info['bytes'])
            gate('cg_sealed_lines', current, raw_info['device'], raw_info['inode'], raw_info['bytes'], 1048576)
            _, access = access_identity()
            status = unit_status('capstone-vector.service')
            p.require(status['ActiveState'] == 'active' and status['InvocationID'] ==
                      before['units']['capstone-vector.service']['InvocationID'], 'reader_changed_before_pause')
            proof = {'vector_before_stop': status, 'writer': writer, 'old_source': raw_info,
                     'old_source_sha256': digest, 'access_prefix_bytes': access['bytes']}
            # Both native sources must be fully consumed BEFORE starting the
            # 3s allowance for v1 reduce's 2s TTL, not only after the stop.
            old_reader_proofs(proof)
            old = begin(old, 'prepare-readers', proof)
        proof = old[0]['intent']['metadata']; status = proof['vector_before_stop']
        if not armed:
            old_reader_proofs(proof)
            time.sleep(3)
            info, _, _, _ = old_reader_proofs(proof)
            p.require((info['uid'], info['gid'], info['mode']) in
                      ((101, 101, 0o644), (0, 0, 0o644), (0, 0, 0o400)), 'old_seal_permissions_changed')
            os.chown(current, 0, 0); os.chmod(current, 0o400)
            with current.open('rb') as handle:
                os.fsync(handle.fileno())
            p.fsync_dir(current.parent)
            p.require(unit_status('capstone-vector.service') == status, 'reader_invocation_raced_before_stop')
            old = arm_signal(old)
            # An armed-but-active restart refuses rather than sending another
            # stop: the first signal may have completed or never been sent.
            p.require(unit_status('capstone-vector.service') == status, 'reader_changed_after_stop_intent')
            rc, _ = logged_command(['/usr/bin/systemctl', 'stop', 'capstone-vector.service'],
                                   'initial-vector-stop', 50)
            p.require(rc == 0, 'initial_vector_stop_uncertain_no_signal_retry')
        p.require(pause_is_owned(unit_status('capstone-vector.service'), status),
                  'initial_vector_stop_uncertain_no_signal_retry')
        sealed, v, w, a = old_reader_proofs(proof)
        p.require((sealed['uid'], sealed['gid'], sealed['mode']) == (0, 0, 0o400), 'old_seal_not_complete')
        cold = gate('cg_wazuh_cold', '/var/ossec/queue/logcollector/file_status.json', alias,
                    pending, fixed['device'], fixed['inode'])
        p.require(cold['reason'] in ('saved_zero', 'different_prefix'), 'pending_generation_not_distinct')
        new_info = distinct_prefix(current, pending, sealed['bytes'])
        result = dict(proof, old_source=sealed, pending_source=new_info, vector_eof=v, wazuh_eof=w,
                      publication=cold, v1_reduce_grace_seconds=3, both_sources_eof_before_grace=True,
                      access_checkpoint_offset=a['offset'], local_eof_is_manager_receipt=False)
        return finish(old, 'prepare-readers', result)


def bootstrap_states(plan, ledger, proof):
    current = proof['old_source']; pending = proof['pending_source']; writer = proof['writer']
    def generation(number, info, config_sha):
        return {'number': number, 'basename': 'generation-%010d.jsonl' % number,
                'device': info['device'], 'inode': info['inode'], 'writer_config_sha256': config_sha}
    common = {'schema_version': 1, 'policy': 'capstone-raw-operations-v1', 'machine_id': p.MID,
              'boot_id': ledger['boot_id'], 'revision': 0}
    source_common = {'vector_config_sha256': plan['candidate_sha256']['vector'],
                     'vector_env_sha256': plan['candidate_sha256']['environment'],
                     'wazuh_config_sha256': p.HOST['wazuh'][1]}
    suri_hash = plan['candidate_sha256']['suricata_yaml']
    suri_info = {'device': p.CONTAINERS['suricata']['device'], 'inode': p.CONTAINERS['suricata']['inode']}
    suri = dict(common, engine='suricata', phase='active', pending=None,
                current=generation(0, suri_info, suri_hash),
                source_pins=dict(source_common, container_id=p.CONTAINERS['suricata']['cid'],
                    engine_config_sha256=suri_hash, producer_format_sha256=suri_hash),
                proof={'old_closed': None, 'readers_drained': None, 'publish_guard': None})
    old_path = b'SecAuditLog /var/log/modsecurity/capstone-managed/generation-0000000000.jsonl\n'
    cold = proof['publication']; v = proof['vector_eof']; w = proof['wazuh_eof']
    waf = dict(common, engine='modsecurity', phase='publish_pending',
        current=generation(0, current, p.sha(old_path)),
        pending=generation(1, pending, plan['candidate_sha256']['audit_path']),
        source_pins=dict(source_common, container_id=p.CONTAINERS['waf']['cid'],
            engine_config_sha256=plan['candidate_sha256']['waf_override'],
            producer_format_sha256=plan['candidate_sha256']['waf_producer']),
        proof={'old_closed': {'boot_id': ledger['boot_id'], 'bytes': current['bytes'],
            'device': current['device'], 'inode': current['inode'], 'sha256': proof['old_source_sha256'],
            'writer_fd_zero': True, 'writer_pid': writer['pid'], 'writer_start_ticks': int(writer['start_ticks'])},
            'readers_drained': {'vector_checkpoint_sha256': v['checkpoint_sha256'],
                'wazuh_checkpoint_sha256': w['checkpoint_sha256'], 'vector_offset': v['offset'],
                'wazuh_offset': w['offset'], 'wazuh_sha1': w['stored_sha1'], 'vector_stopped': True},
            'publish_guard': {'decision': cold['reason'], 'new_prefix_sha1': cold['prefix_sha1'],
                'old_offset': cold['offset'], 'old_sha1': cold['stored_sha1'],
                'source_bytes': cold['source_identity']['bytes'], 'wazuh_checkpoint_sha256': cold['checkpoint_sha256']}})
    status = proof['vector_before_stop']
    marker = {key: waf[key] for key in ('engine', 'boot_id', 'revision', 'phase', 'current', 'pending', 'source_pins')}
    marker.update(schema_version=1, state_sha256=p.sha(p.canonical(waf)),
                  invocation_id=status['InvocationID'], start_usec=status['ExecMainStartTimestampMonotonic'])
    return suri, waf, marker


def sealed_bootstrap_proof(proof):
    p.require(pause_is_owned(unit_status('capstone-vector.service'), proof['vector_before_stop']),
              'initial_pause_no_longer_owned')
    alias, current, pending = waf_paths(); fixed = p.CONTAINERS['waf']
    gate('writer_gate', 'waf', json.dumps(proof['writer'], separators=(',', ':')), fixed['device'], fixed['inode'])
    sealed, digest = raw_hash(current, 2)
    p.require((sealed['device'], sealed['inode'], sealed['uid'], sealed['gid'], sealed['mode'], digest, sealed['bytes']) ==
              (fixed['device'], fixed['inode'], 0, 0, 0o400, proof['old_source_sha256'], proof['old_source']['bytes']),
              'sealed_generation_changed')
    updated = dict(proof)
    updated['vector_eof'] = gate('cg_vector_eof', '/var/lib/capstone-vector/waf_audit', current,
                                fixed['device'], fixed['inode'], sealed['bytes'])
    updated['wazuh_eof'] = gate('cg_wazuh_eof', '/var/ossec/queue/logcollector/file_status.json', alias,
                               current, fixed['device'], fixed['inode'], sealed['bytes'])
    updated['publication'] = gate('cg_wazuh_cold', '/var/ossec/queue/logcollector/file_status.json', alias,
                                 pending, fixed['device'], fixed['inode'])
    p.require(updated['publication']['reason'] in ('saved_zero', 'different_prefix'), 'pending_generation_ambiguous')
    updated['pending_source'] = distinct_prefix(current, pending, sealed['bytes'])
    p.require(all(updated['pending_source'][k] == proof['pending_source'][k] for k in ('device', 'inode')),
              'pending_generation_replaced')
    return updated


def runtime_artifact(name, plan):
    raw, info = p.snapshot(p.BACKUP / 'source' / name)
    p.require((info['uid'], info['gid'], info['mode']) == (0, 0, 0o400) and
              p.sha(raw) == plan['source_sha256'][name], 'runtime_source_changed')
    return raw


def apply_readers(plan, before, old):
    pending_operation = old[0]['intent'] is not None
    protected(plan, before, old[0], allow_paused=True, allow_state=pending_operation)
    proof = sealed_bootstrap_proof(prior_result(old[0], 'prepare-readers'))
    if not pending_operation:
        suri, waf, marker = bootstrap_states(plan, old[0], proof)
        old = begin(old, 'apply-readers', {'bootstrap': {'suricata': suri, 'modsecurity': waf, 'marker': marker},
                    'source_stop_intent_sequence': old[0]['sequence']})
    frozen = old[0]['intent']['metadata']['bootstrap']
    p.require(set(frozen) == {'suricata', 'modsecurity', 'marker'}, 'bootstrap_metadata_invalid')
    suri, waf, marker = frozen['suricata'], frozen['modsecurity'], frozen['marker']
    # Reusing an interrupted transaction never regenerates state from a later,
    # growing source. Exact states/marker were frozen in the durable intent.
    p.require(waf['pending']['device'] == proof['pending_source']['device'] and
              waf['pending']['inode'] == proof['pending_source']['inode'] and
              marker['state_sha256'] == p.sha(p.canonical(waf)), 'frozen_bootstrap_binding_invalid')
    for name, value in (('suricata', suri), ('modsecurity', waf)):
        target = p.BACKUP / ('bootstrap-' + name + '.json')
        durable_create(target, p.canonical(value))
        rc, _ = p.command(['/usr/bin/jq', '-e', '-f', str(p.BACKUP / 'source/state.jq'), str(target)])
        p.require(rc == 0, 'bootstrap_state_schema_rejected')
    durable_create(p.BACKUP / 'bootstrap-marker.json', p.canonical(marker))
    # The blocked temporary guard remains effective through every partial
    # config/runtime/state publication, including a crash after any one rename.
    require_barrier(old[0])
    ensure_directory(p.RUNTIME, 0o755)
    runtime_names = ('coordinator.sh', 'guard.sh', 'state-lib.sh', 'state.jq', 'checkpoint-gates.sh',
                     'checkpoint-gates.jq', 'writer-gates.sh', 'line-length-lib-v2.sh')
    allowed = set(runtime_names) | {'.migration-create-' + name for name in runtime_names}
    p.require(all(path.name in allowed for path in p.RUNTIME.iterdir()), 'runtime_unknown_artifact')
    for name in runtime_names:
        durable_create(p.RUNTIME / name, runtime_artifact(name, plan))
    durable_create(p.CONFIG / 'transforms/waf_audit_context.vrl', candidate('waf_audit_context', plan))
    for key in ('vector', 'environment', 'waf_binding', 'line_binding'):
        path, digest, uid, gid, mode = p.HOST[key]
        ensure_replacement(Path(path), candidate(key, plan), digest, uid, gid, mode)
    ensure_replacement(SCANNER, runtime_artifact('raw-line-scan-v2.sh', plan), SCANNER_V1, 0, 0, 0o755)
    ensure_directory(p.STATE)
    allowed_state = {'suricata', 'modsecurity', 'vector-stop-intent.json', '.migration-create-vector-stop-intent.json'}
    p.require(all(path.name in allowed_state for path in p.STATE.iterdir()), 'initial_state_unknown_artifact')
    for name, value in (('suricata', suri), ('modsecurity', waf)):
        for relative in (name, name + '/history', name + '/staging'):
            ensure_directory(p.STATE / relative)
        engine = p.STATE / name
        p.require(all(path.name in ('history', 'staging', 'state.json', '.migration-create-state.json')
                      for path in engine.iterdir()) and not any((engine / 'history').iterdir()) and
                      not any((engine / 'staging').iterdir()), 'initial_state_already_advanced')
        durable_create(engine / 'state.json', p.canonical(value), 0o600)
    durable_create(p.STATE / 'vector-stop-intent.json', p.canonical(marker), 0o600)
    protected(plan, before, old[0], allow_paused=True, allow_state=True)
    p.require(pause_is_owned(unit_status('capstone-vector.service'), proof['vector_before_stop']),
              'reader_started_during_bootstrap')
    return finish(old, 'apply-readers', {'suricata_initial_phase': 'active',
                    'waf_initial_phase': 'publish_pending', 'v1_raw_reinterpreted': False,
                    'old_checkpoint_rewritten': False, 'runtime_marker_sha256': p.sha(p.canonical(marker)),
                    'stopped_invocation_id': marker['invocation_id'], 'vector_started': False})


def unit_artifact(name, ledger):
    data, info = p.snapshot(p.BACKUP / 'source' / name)
    p.require(info['uid'] == info['gid'] == 0 and info['mode'] == 0o400 and
              p.sha(data) == ledger['unit_sha256'][name], 'unit_artifact_changed')
    return data


def release_proof(old, plan):
    states = {}
    for engine in ('suricata', 'modsecurity'):
        value, raw, _ = read_json(p.STATE / engine / 'state.json', 0o600)
        expected, _, _ = read_json(p.BACKUP / ('bootstrap-' + engine + '.json'))
        p.require(value == expected, 'bootstrap_state_advanced_before_handoff')
        states[engine] = p.sha(raw)
    for name in ('coordinator.sh', 'guard.sh', 'state-lib.sh', 'state.jq', 'checkpoint-gates.sh',
                 'checkpoint-gates.jq', 'writer-gates.sh', 'line-length-lib-v2.sh'):
        source = runtime_artifact(name, plan)
        p.snapshot(p.RUNTIME / name, expected=(p.sha(source), 0, 0, 0o400))
    guard = runtime_artifact('guard.sh', plan)
    p.snapshot(p.CONFIG / 'transforms/waf_audit_context.vrl',
               expected=(plan['candidate_sha256']['waf_audit_context'], 0, 0, 0o400))
    p.snapshot(SCANNER, expected=(plan['source_sha256']['raw-line-scan-v2.sh'], 0, 0, 0o755))
    marker, marker_raw, _ = read_json(p.STATE / 'vector-stop-intent.json', 0o600)
    bootstrap, _, _ = read_json(p.BACKUP / 'bootstrap-marker.json')
    p.require(marker == bootstrap, 'runtime_stop_intent_changed')
    return {'boot_id': old[0]['boot_id'], 'ledger_sha256': p.sha(old[1]),
            'runtime_guard_sha256': p.sha(guard), 'suricata_state_sha256': states['suricata'],
            'modsecurity_state_sha256': states['modsecurity'], 'readers_verified': ['vector', 'wazuh']}


def install_guards(plan, before, old):
    resuming = bool(old[0]['intent'] and old[0]['intent']['operation'] == 'install-guards')
    barrier, _, _ = read_json(BARRIER, 0o600)
    released = barrier['phase'] == 'released'
    if released:
        p.require(resuming and barrier['release'] == release_proof(old, plan),
                  'released_barrier_not_this_handoff')
        for reader in ('vector', 'wazuh'):
            rc, _ = logged_command(['/bin/bash', str(p.RUNTIME / 'guard.sh'), reader],
                                   'released-' + reader + '-guard', 115)
            p.require(rc == 0, 'released_reader_guard_refused')
    protected(plan, before, old[0], allow_paused=True, allow_state=True, allow_released=resuming)
    proof = prior_result(old[0], 'prepare-readers')
    p.require(released or pause_is_owned(unit_status('capstone-vector.service'), proof['vector_before_stop']),
              'reader_pause_changed_before_guard_install')
    old = begin(old, 'install-guards')
    durable_create(Path('/usr/local/sbin/capstone-raw-operations'), unit_artifact('capstone-raw-operations', old[0]), 0o500)
    for suffix in ('service', 'timer'):
        name = 'capstone-raw-operations@.' + suffix
        durable_create(Path('/etc/systemd/system') / name, unit_artifact(name, old[0]), 0o644)
    rc, _ = logged_command(['/usr/bin/systemd-analyze', 'verify', 'capstone-raw-operations@suricata.service',
                           'capstone-raw-operations@modsecurity.service', 'capstone-vector.service',
                           'wazuh-agent.service'], 'units-native-verify', 30)
    p.require(rc == 0, 'native_unit_verify_failed')
    marker, raw, info = read_json(BARRIER, 0o600)
    release = release_proof(old, plan)
    if marker['phase'] == 'blocked':
        # These direct read-only probes do not enter through the temporary
        # barrier and do not start either service. Both states must be ready.
        for reader in ('vector', 'wazuh'):
            rc, _ = logged_command(['/bin/bash', str(p.RUNTIME / 'guard.sh'), reader],
                                   'initial-' + reader + '-guard', 115)
            p.require(rc == 0, 'initial_reader_guard_refused')
        protected(plan, before, old[0], allow_paused=True, allow_state=True)
        p.require(pause_is_owned(unit_status('capstone-vector.service'), proof['vector_before_stop']),
                  'reader_pause_changed_before_release')
        p.require(release_proof(old, plan) == release, 'release_state_changed_during_guard')
        released = dict(marker, phase='released', release=release)
        atomic_replace(BARRIER, p.canonical(released), raw, info, 0, 0, 0o600)
    else:
        p.require(marker['phase'] == 'released' and marker['release'] == release,
                  'released_barrier_not_this_handoff')
    # A released temporary guard delegates to the pinned final guard. Therefore
    # every crash point while replacing/reloading the SAME drop-in remains gated.
    require_barrier(old[0], allow_released=True)
    for unit, reader in (('capstone-vector.service', 'vector'), ('wazuh-agent.service', 'wazuh')):
        target = Path('/etc/systemd/system') / (unit + '.d') / DROPIN_NAME
        final = unit_artifact(reader + '-start-guard.conf', old[0])
        temporary = final.replace(b'/usr/local/lib/capstone-raw-operations/guard.sh',
                                  b'/usr/local/lib/capstone-raw-migration/migration-start-guard.sh')
        ensure_replacement(target, final, p.sha(temporary), 0, 0, 0o644)
    rc, _ = logged_command(['/usr/bin/systemctl', 'daemon-reload'], 'final-guard-daemon-reload')
    p.require(rc == 0, 'daemon_reload_failed')
    require_barrier(old[0], allow_released=True)
    for unit, reader in (('capstone-vector.service', 'vector'), ('wazuh-agent.service', 'wazuh')):
        rc, result = p.command(['/usr/bin/systemctl', 'show', unit, '-p', 'ExecStartPre'])
        p.require(rc == 0 and '/usr/local/lib/capstone-raw-operations/guard.sh ' + reader in result.decode() and
                  'migration-start-guard.sh' not in result.decode(), 'final_guard_not_effective')
    protected(plan, before, old[0], allow_paused=True, allow_state=True, allow_released=True)
    for reader in ('vector', 'wazuh'):
        rc, _ = logged_command(['/bin/bash', str(p.RUNTIME / 'guard.sh'), reader],
                               'final-' + reader + '-guard', 115)
        p.require(rc == 0, 'final_reader_guard_refused')
    final_status = unit_status('capstone-vector.service')
    p.require(final_status['ActiveState'] == 'active' or
              pause_is_owned(final_status, proof['vector_before_stop']), 'reader_handoff_state_uncertain')
    return finish(old, 'install-guards', {'guards_installed': True, 'barrier_released': True,
                    'explicit_vector_start_sent': False, 'vector_active_after_release': final_status['ActiveState'] == 'active',
                    'timers_enabled': False,
                    'handoff_command': 'capstone-raw-operations resume modsecurity'})


def main():
    recovery = len(sys.argv) == 4 and sys.argv[1] == 'accept-v1-recovery'
    ordinary = len(sys.argv) == 3 and sys.argv[1] in ('inspect', *OPERATIONS)
    p.require(recovery or ordinary, 'phase_not_implemented_or_invalid')
    p.require(os.geteuid() == 0 and sys.platform == 'linux' and
              Path('/etc/machine-id').read_text().strip() == p.MID, 'fixed_A_root_required')
    os.umask(0o077)
    operation, plan_sha = sys.argv[1:3]
    with p.shared_lock():
        plan, before = load_plan(plan_sha, inspection=operation == 'inspect')
        if not os.path.lexists(LEDGER):
            p.require(not recovery, 'recovery_requires_existing_ledger')
            if operation == 'inspect':
                print(json.dumps({'status': 'prepared_not_started', 'plan_sha256': plan_sha,
                                  'reader_cutover_implemented': True})); return
            old = new_ledger(plan_sha, before)
        else:
            old = ledger_read(plan_sha, inspection=operation == 'inspect', recovery_upgrade=recovery)
        if recovery:
            old = accept_v1_recovery(plan, before, old, sys.argv[3])
        elif operation != 'inspect':
            before = effective_before(plan, before, old[0])
            p.require(old[0]['intent'] is None or old[0]['intent']['operation'] == operation,
                      'different_operation_pending')
            handlers = {'install-barrier': install_barrier, 'apply-legacy': apply_legacy,
                        'apply-suricata': apply_suricata, 'apply-waf-writer': apply_waf_writer,
                        'prepare-readers': prepare_readers, 'apply-readers': apply_readers,
                        'install-guards': install_guards}
            old = handlers[operation](plan, before, old)
        print(json.dumps({'status': 'observed' if operation == 'inspect' else 'phase_completed',
              'phase': old[0]['phase'], 'sequence': old[0]['sequence'],
              'pending_intent': None if old[0]['intent'] is None else old[0]['intent']['operation'],
              'migration_sha256': p.sha(old[1]), 'reader_cutover_implemented': True,
              'raw_deleted': False, 'checkpoint_rewritten': False, 'raw_exported': False}))


if __name__ == '__main__':
    try:
        main()
    except (p.Refused, OSError, KeyError, ValueError) as error:
        code = str(error) if isinstance(error, p.Refused) else 'migration_failed_inspect_required'
        print(json.dumps({'status': 'refused', 'reason': code,
                          'automatic_signal_retry': False, 'raw_exported': False}))
        sys.exit(2)
