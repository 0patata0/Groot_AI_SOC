#!/usr/bin/env python3
"""Fixed B prestart verifier and durable journal. No subprocess/Docker/network API.

All lifecycle operations belong to the adjacent native Ansible role. An armed
operation is never issued twice: ambiguous failures require explicit read-only
inspection and an operator decision. Database files are only read, never restored.
"""
from __future__ import annotations
import argparse
import base64
import csv
import contextlib
import datetime
import math
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import time
import tempfile
import types
import zipfile

MID = '1e143067c98a44ffba6eaa925dc038d7'
OLD = '6c2ed13aea89404463061ea2032084bdd159ae784aff4e7bd9eea7406ba9b30b'
IMAGE = 'sha256:2fd023efbb8d3d2b0ce1a73d028b07370cff34f567cfe0e999553e8c327ea283'
CONTRACT_SHA = 'b9cb0dfdbbfb600cb9e1d9c7b24f9e138190e2aef0c1e3d41862c4676d737554'
CHECKS_SHA = '74843987843dd5ef447d09896ba894ea580da2e5dc56b9bf0d48749f091e0cb5'
WHEEL_SHA = 'd49c18f1ea294cf4adde2e5ac256e98c82ea9d708462ce4bf799dffa7cfe8a2c'
WHEEL = '/opt/capstone-automation/artifacts/regex-2026.9.29-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl'
REGEX_REL = 'capstone-guard-runtime/regex-2026.9.29/lib/python3.13/site-packages'
FILES = {
 'capstone_korean_output_guard.py': 'a6b977d2c670ded98f61639a480702ed06d4a866b705e7d10705a056b974895c',
 'plugins/platforms/mattermost/adapter.py': '1bbe71e24cf7fd212f38b13cb421bb5b05c841ea4d70a061d6dcb57253e6c47b',
 'gateway/run_turn.py': 'd4dae0f3194f7b7d435aac2eb37d4697822612cd6955911d86bb61400ad2871a',
}
IMMUTABLE = ('config.yaml', '.env', 'SOUL.md')
PROTECTED = IMMUTABLE + ('cron/jobs.json', 'state.db', 'state.db-wal', 'state.db-shm')
RUNTIME_CHECKS = [
 'pinned_unicode_package_engine', 'send', 'edit', 'caption', 'direct_api_and_input_preserved',
 'verified_raw_split_preserved', 'thread_fallback_verified_raw_preserved',
 'thread_retry_rejects_previous_turn_marker', 'transport_failed_repair_blocks_foreign_prose',
 'standalone_cron', 'queued_request_language_reset',
]
TRANSITIONS = {
 'create': ('planned', 'created'), 'install': ('created', 'guarded'),
 'stop-old': ('guarded', 'old-stopped'), 'retain-old': ('old-stopped', 'old-retained'),
 'name-new': ('old-retained', 'names-switched'), 'start-new': ('names-switched', 'new-started'),
 'stop-new': ('new-started', 'new-stopped'), 'park-new': ('new-stopped', 'new-parked'),
 'restore-name': ('new-parked', 'old-named'), 'start-old': ('old-named', 'old-started'),
}

class Refused(ValueError): pass

def need(value, code):
    if not value: raise Refused(code)

def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                       separators=(',', ':')) + '\n').encode()

def sha(data): return hashlib.sha256(data).hexdigest()

def pairs(items):
    out = {}
    for key, value in items:
        need(key not in out, 'duplicate_json_key'); out[key] = value
    return out

def parse(raw):
    try: return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(Refused('nonfinite_json')))
    except (ValueError, TypeError): raise Refused('invalid_json') from None

def trusted_parent(path):
    for parent in reversed(path.absolute().parents):
        value = parent.lstat()
        need(stat.S_ISDIR(value.st_mode) and value.st_uid == 0 and not value.st_mode & 0o022,
             'unsafe_parent')

def read(path, limit=16*1024*1024, *, mode=None, trusted=True):
    path = Path(path)
    if trusted: trusted_parent(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
             'unsafe_file')
        if trusted:
            need(before.st_uid == 0 and before.st_gid == 0 and not before.st_mode & 0o022,
                 'unsafe_owner_mode')
        if mode is not None: need(stat.S_IMODE(before.st_mode) == mode, 'wrong_file_mode')
        chunks = []; total = 0
        while True:
            chunk = os.read(fd, min(1024*1024, limit+1-total))
            if not chunk: break
            chunks.append(chunk); total += len(chunk)
            need(total <= limit, 'file_too_large')
        after = os.fstat(fd); named = path.lstat()
        fields = lambda v:(v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns,v.st_uid,v.st_gid,v.st_mode,v.st_nlink)
        need(fields(before) == fields(after) == fields(named), 'file_changed')
        return b''.join(chunks)
    finally: os.close(fd)

def load_module(name, filename, digest):
    raw = read(Path(__file__).with_name(filename))
    need(sha(raw) == digest, 'dependency_hash_mismatch')
    module = types.ModuleType(name)
    exec(compile(raw, filename, 'exec'), module.__dict__)
    return module

def contract(): return load_module('prestart_contract', 'hermes_prestart_contract.py', CONTRACT_SHA)

def durable(path, raw, *, expected=None, mode=0o600):
    """Exclusive create or exact-CAS replacement, with file and directory fsync."""
    path = Path(path); trusted_parent(path)
    if expected is None: need(not os.path.lexists(path), 'receipt_exists')
    else: need(sha(read(path, mode=mode)) == expected, 'receipt_cas_conflict')
    temp = path.with_name('.' + path.name + '.' + os.urandom(8).hex())
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        if expected is None:
            os.link(temp, path, follow_symlinks=False); temp.unlink()
        else:
            need(sha(read(path, mode=mode)) == expected, 'receipt_cas_conflict')
            os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.lexists(temp): temp.unlink()

def profile(info, *, candidate=False, candidate_started=False):
    # Original plan fingerprint is unchanged. Only the explicit candidate path
    # accepts the exact three native-create defaults observed and reviewed on B.
    c = contract()
    if candidate: config, host = c.candidate_comparison_fields(info,started=candidate_started)
    else: config, host = dict(info['Config']), info['HostConfig']
    config.pop('Hostname', None); config.pop('Image', None)
    config['Env'] = c.environment(config['Env'])
    return sha(canonical({'Image':info['Image'], 'Config':config,
                          'HostConfig':host, 'Mounts':info['Mounts'],
                          'Networks':c._networks(info)}))

def proven_stopped(info):
    return contract()._proven_stopped(info['State'])

def running(info):
    s = info['State']
    return s.get('Running') is True and s.get('Restarting') is False and s.get('Paused') is False and \
        s.get('Dead') is False and s.get('OOMKilled') is False and type(s.get('Pid')) is int and s['Pid'] > 1

def check_containers(plan, items, new_id=None, *, candidate_started=False):
    need(type(items) is list and 1 <= len(items) <= 128, 'container_inventory_invalid')
    ids = [x.get('Id') for x in items]
    need(len(ids) == len(set(ids)) and all(re.fullmatch('[0-9a-f]{64}', x or '') for x in ids), 'container_identity_invalid')
    result = {x['Id']:x for x in items}; need(OLD in result, 'original_missing')
    allowed = {OLD} | ({new_id} if new_id else set())
    for item in items:
        uses = any(m.get('Source') in {'/','/opt','/opt/hermes-data'} or
                   str(m.get('Source','')).startswith('/opt/hermes-data/') or
                   m.get('Destination') == '/opt/data' for m in item.get('Mounts', []))
        if uses: need(item['Id'] in allowed, 'unexpected_data_mount_user')
        if item['Id'] in allowed:
            need(profile(item, candidate=item['Id'] == new_id, candidate_started=candidate_started) == plan['profile_sha256'], 'container_profile_changed')
    if new_id: need(new_id in result, 'candidate_missing')
    need(sum(running(result[x]) for x in allowed) <= 1, 'two_gateways_running')
    return result

def immutable_equal(a, b):
    need(set(a) == set(PROTECTED) and set(b) == set(PROTECTED), 'snapshot_shape')
    need(all(canonical(a[k]) == canonical(b[k]) for k in IMMUTABLE), 'protected_configuration_changed')

def validate_runtime(result):
    need(type(result) is dict and result.get('passed') == 11 and
         result.get('real_chat_posts') == 0 and result.get('runtime_checks') == RUNTIME_CHECKS,
         'runtime_checks_incomplete')
    engine = result.get('unicode_engine')
    need(type(engine) is dict and engine.get('package') == 'regex' and
         engine.get('version') == '2026.9.29', 'unicode_engine_unverified')

def validate_mcp(value):
    need(type(value) is dict and set(value) == {'uid','gid','servers','initialize','tools_list','tools_call','model_calls','chat_posts','parents_write_protected'}, 'mcp_shape')
    baseline = {'wazuh-ro','security-events','resp','rule-a','rule-b'}
    need(type(value['servers']) is dict and set(value['servers']) in (baseline, baseline | {'system-diagnostics'}), 'mcp_servers')
    count = len(value['servers'])
    need(value['uid'] == 995 and value['gid'] == 986 and value['initialize'] == value['tools_list'] == count and
         value['tools_call'] == value['model_calls'] == value['chat_posts'] == 0 and value['parents_write_protected'] is True, 'mcp_unverified')
    for row in value['servers'].values():
        need(type(row) is dict and set(row) == {'tools','names_sha256'} and type(row['tools']) is int and 1 <= row['tools'] <= 100 and
             isinstance(row['names_sha256'], str) and
             re.fullmatch('[0-9a-f]{64}',row['names_sha256']), 'mcp_toolset')
    if 'system-diagnostics' in value['servers']:
        need(value['servers']['system-diagnostics'] == {'tools': 1,
             'names_sha256': sha(canonical(['get_system_diagnostics']))}, 'diagnostic_toolset')
    return value

def init_plan(token, original, snapshot, boot, mcp=None):
    need(re.fullmatch('[0-9a-f]{12}', token or '') and re.fullmatch('[0-9a-f]{32}', boot or ''), 'invalid_token_boot')
    contract().validate_baseline(original)
    need(running(original), 'original_not_running')
    immutable_equal(snapshot, snapshot)
    return parse(canonical({'schema_version':1, 'policy':'hermes-fixed-prestart-v1', 'machine_id':MID,
            'boot_id':boot, 'token':token, 'old_id':OLD, 'image':IMAGE,
            'candidate_name':'hermes-prestart-' + token, 'retained_name':'hermes-retained-' + token,
            'mcp':validate_mcp(mcp), 'profile_sha256':profile(original), 'snapshot':snapshot, 'baseline':original}))

def initial(plan):
    return {'schema_version':1, 'plan_sha256':sha(canonical(plan)), 'revision':0,
            'phase':'planned', 'candidate_id':None, 'intent':None, 'proofs':{},
            'database_restore':False, 'original_container_deleted':False}

def validate_ledger(plan, ledger):
    need(set(ledger) == {'schema_version','plan_sha256','revision','phase','candidate_id','intent','proofs','database_restore','original_container_deleted'}, 'ledger_schema')
    need(ledger['schema_version'] == 1 and ledger['plan_sha256'] == sha(canonical(plan)) and
         type(ledger['revision']) is int and ledger['revision'] >= 0 and ledger['database_restore'] is False and
         ledger['original_container_deleted'] is False, 'ledger_invalid')

def validate_docker_host(evidence):
    # Fixed B native observation. Persisted as part of every action proof;
    # existing plan bytes and its original profile digest remain unchanged.
    need(canonical(evidence.get('docker_host')) == canonical(
        {'oom_kill_disable':False,'cgroup_version':'2'}), 'docker_host_capability_changed')

def candidate_started_phase(ledger):
    return ledger['phase'] in {'new-started','new-stopped','new-parked','old-named','old-started','committed','rolled-back'}

def arm(plan, ledger, action, evidence):
    validate_ledger(plan, ledger)
    need(action in TRANSITIONS and ledger['phase'] == TRANSITIONS[action][0], 'wrong_phase')
    need(ledger['intent'] is None, 'action_already_armed_no_retry')
    need(evidence.get('boot_id') == plan['boot_id'], 'boot_changed')
    validate_docker_host(evidence)
    members = check_containers(plan, evidence['containers'], ledger['candidate_id'],
                               candidate_started=candidate_started_phase(ledger))
    old = members[OLD]; new = members.get(ledger['candidate_id'])
    need(old['State']['StartedAt'] == plan['baseline']['State']['StartedAt'], 'original_process_changed')
    if action in {'create','install','stop-old'}:
        need(old['State']['Pid'] == plan['baseline']['State']['Pid'], 'original_process_changed')
    immutable_equal(plan['snapshot'], evidence['snapshot'])
    need(evidence.get('database_ok') is True, 'database_unverified')
    names = {x['Name'] for x in evidence['containers']}
    if action == 'create':
        need(running(old) and old['Name'] == '/hermes' and '/' + plan['candidate_name'] not in names and
             '/' + plan['retained_name'] not in names, 'create_precondition')
    elif action in {'install','stop-old'}:
        contract().validate_created(plan['baseline'], new, expected_new_id=ledger['candidate_id'], expected_name=plan['candidate_name'])
        need(running(old) and old['Name'] == '/hermes', 'old_changed')
        if action == 'stop-old':
            need(evidence.get('idle', {}).get('idle') is True and evidence['idle'].get('active_leases') == 0 and
                 -5 <= evidence['idle'].get('heartbeat_age_seconds', 99) < 15, 'idle_not_fresh')
            need(type(evidence['idle'].get('observed_at_epoch')) in (int,float) and
                 0 <= time.time()-evidence['idle']['observed_at_epoch'] < 5, 'idle_observation_expired')
            need(evidence.get('guard_sha256') == ledger['proofs']['guard_sha256'], 'guard_readback_changed')
    elif action == 'retain-old':
        need(proven_stopped(old) and old['Name'] == '/hermes' and proven_stopped(new) and
             new['Name'] == '/' + plan['candidate_name'] and '/' + plan['retained_name'] not in names, 'retain_precondition')
    elif action == 'name-new':
        need(proven_stopped(old) and old['Name'] == '/' + plan['retained_name'] and proven_stopped(new) and
             new['Name'] == '/' + plan['candidate_name'] and '/hermes' not in names, 'name_new_precondition')
    elif action == 'start-new':
        need(proven_stopped(old) and old['Name'] == '/' + plan['retained_name'] and proven_stopped(new) and
             new['Name'] == '/hermes' and new['State']['Status'] == 'created', 'firststart_precondition')
        need(canonical(evidence['snapshot']) == canonical(ledger['proofs']['stopped_snapshot']), 'stopped_data_changed')
        need(evidence.get('guard_sha256') == ledger['proofs']['guard_sha256'], 'guard_readback_changed')
    elif action == 'stop-new':
        need(proven_stopped(old) and old['Name'] == '/' + plan['retained_name'] and
             new['Name'] == '/hermes' and (running(new) or proven_stopped(new)) and
             new['State']['StartedAt'] == ledger['proofs'].get('start-' + ledger['candidate_id'], {}).get('started_at'),
             'fallback_stop_precondition')
    elif action == 'park-new':
        need(proven_stopped(old) and proven_stopped(new) and old['Name'] == '/' + plan['retained_name'] and
             new['Name'] == '/hermes', 'fallback_park_precondition')
    elif action == 'restore-name':
        need(proven_stopped(old) and proven_stopped(new) and old['Name'] == '/' + plan['retained_name'] and
             new['Name'] == '/' + plan['candidate_name'] and '/hermes' not in names, 'fallback_name_precondition')
    elif action == 'start-old':
        need(proven_stopped(old) and old['Name'] == '/hermes' and proven_stopped(new) and
             new['Name'] == '/' + plan['candidate_name'], 'fallback_start_precondition')
        need(canonical(evidence['snapshot']) == canonical(ledger['proofs']['fallback_snapshot']), 'fallback_data_changed')
    out = parse(canonical(ledger)); out['revision'] += 1
    out['intent'] = {'heartbeat_epoch':evidence.get('heartbeat_epoch'), 'action':action, 'before_sha256':sha(canonical(evidence)), 'boot_id':plan['boot_id'],
                     'old_id':OLD, 'candidate_id':ledger['candidate_id'], 'issued_at_ns':time.time_ns()}
    return out

def finish(plan, ledger, action, evidence):
    validate_ledger(plan, ledger)
    need(ledger['intent'] is not None and ledger['intent']['action'] == action and
         ledger['phase'] == TRANSITIONS[action][0], 'unarmed_action')
    need(evidence.get('boot_id') == plan['boot_id'], 'boot_changed')
    validate_docker_host(evidence)
    new_id = ledger['candidate_id']
    if action == 'create':
        matches = [x for x in evidence['containers'] if x.get('Name') == '/' + plan['candidate_name']]
        need(len(matches) == 1, 'created_identity_missing'); new_id = matches[0]['Id']
        need(evidence.get('command_container_id') == new_id, 'create_receipt_mismatch')
    members = check_containers(plan, evidence['containers'], new_id,
                               candidate_started=action == 'start-new' or candidate_started_phase(ledger))
    old, new = members[OLD], members[new_id]
    if action != 'start-old':
        need(old['State']['StartedAt'] == plan['baseline']['State']['StartedAt'], 'original_process_changed')
    immutable_equal(plan['snapshot'], evidence['snapshot'])
    need(evidence.get('database_ok') is True, 'database_unverified')
    out = parse(canonical(ledger)); proofs = out['proofs']
    if action in {'create','install'}:
        contract().validate_created(plan['baseline'], new, expected_new_id=new_id, expected_name=plan['candidate_name'])
        need(running(old) and old['Name'] == '/hermes', 'original_changed')
        if action == 'install':
            need(re.fullmatch('[0-9a-f]{64}', evidence.get('guard_sha256','')), 'guard_proof_missing')
            proofs['guard_sha256'] = evidence['guard_sha256']
    elif action == 'stop-old':
        need(proven_stopped(old) and old['Name'] == '/hermes' and proven_stopped(new), 'original_stop_unproved')
        proofs['stopped_snapshot'] = evidence['snapshot']
    elif action == 'retain-old':
        need(proven_stopped(old) and old['Name'] == '/' + plan['retained_name'] and proven_stopped(new), 'retain_unproved')
    elif action == 'name-new':
        need(proven_stopped(old) and old['Name'] == '/' + plan['retained_name'] and
             proven_stopped(new) and new['Name'] == '/hermes', 'name_new_unproved')
    elif action == 'start-new':
        need(proven_stopped(old) and old['Name'] == '/' + plan['retained_name'] and
             new['Name'] == '/hermes' and (running(new) or (proven_stopped(new) and
             new['State'].get('Status') == 'exited' and
             new['State'].get('StartedAt') != '0001-01-01T00:00:00Z' and
             new['State'].get('FinishedAt') not in {None,'0001-01-01T00:00:00Z'})), 'candidate_start_unproved')
        proofs['start-' + new_id] = {'id':new_id, 'pid':new['State']['Pid'], 'started_at':new['State']['StartedAt'],
                                       'previous_heartbeat':ledger['intent']['heartbeat_epoch']}
    elif action == 'stop-new':
        need(proven_stopped(new) and new['Name'] == '/hermes' and proven_stopped(old), 'candidate_stop_unproved')
        proofs['fallback_snapshot'] = evidence['snapshot']
    elif action == 'park-new':
        need(proven_stopped(new) and new['Name'] == '/' + plan['candidate_name'] and proven_stopped(old), 'candidate_park_unproved')
    elif action == 'restore-name':
        need(proven_stopped(new) and new['Name'] == '/' + plan['candidate_name'] and
             proven_stopped(old) and old['Name'] == '/hermes', 'original_name_unproved')
    elif action == 'start-old':
        need(proven_stopped(new) and new['Name'] == '/' + plan['candidate_name'] and
             running(old) and old['Name'] == '/hermes', 'original_start_unproved')
        need(old['State']['StartedAt'] != plan['baseline']['State']['StartedAt'], 'original_start_not_new')
        proofs['start-' + OLD] = {'id':OLD, 'pid':old['State']['Pid'], 'started_at':old['State']['StartedAt'],
                                 'previous_heartbeat':ledger['intent']['heartbeat_epoch']}
    out.update(candidate_id=new_id, intent=None, phase=TRANSITIONS[action][1], revision=ledger['revision']+1)
    proofs[action] = sha(canonical(evidence))
    return out

def ready(plan, ledger, evidence, *, commit=False):
    validate_ledger(plan, ledger)
    need(ledger['intent'] is None and ledger['phase'] in {'new-started','old-started'}, 'readiness_wrong_phase')
    validate_docker_host(evidence)
    members = check_containers(plan, evidence['containers'], ledger['candidate_id'],candidate_started=True)
    active = ledger['candidate_id'] if ledger['phase'] == 'new-started' else OLD
    inactive = OLD if active != OLD else ledger['candidate_id']
    need(running(members[active]) and members[active]['Name'] == '/hermes' and proven_stopped(members[inactive]), 'readiness_identity')
    need(evidence.get('boot_id') == plan['boot_id'] and evidence.get('database_ok') is True, 'readiness_database_boot')
    immutable_equal(plan['snapshot'], evidence['snapshot'])
    need(evidence.get('idle', {}).get('idle') is True and evidence['idle'].get('active_leases') == 0 and
         -5 <= evidence['idle'].get('heartbeat_age_seconds',99) < 15, 'readiness_heartbeat')
    start = ledger['proofs'].get('start-' + active, {})
    need(start.get('id') == active and start.get('pid') == members[active]['State']['Pid'] and
         start.get('started_at') == members[active]['State']['StartedAt'], 'started_identity_changed')
    heartbeat = evidence.get('heartbeat_epoch')
    need(type(heartbeat) in (int,float) and math.isfinite(heartbeat) and
         heartbeat >= timestamp(start['started_at']) and heartbeat != start.get('previous_heartbeat'),
         'new_heartbeat_unverified')
    need(evidence.get('runtime_uid') == 995 and evidence.get('runtime_gid') == 986, 'runtime_uid_mismatch')
    validate_runtime(evidence['runtime'])
    need(canonical(validate_mcp(evidence.get('mcp'))) == canonical(plan['mcp']), 'mcp_baseline_changed')
    need(evidence.get('guard_sha256') == ledger['proofs']['guard_sha256'], 'guard_readback_changed')
    out = parse(canonical(ledger)); out['revision'] += 1
    out['proofs']['readiness-' + active] = sha(canonical(evidence))
    if commit: out['phase'] = 'committed' if active != OLD else 'rolled-back'
    return out

def verify_tree(root, wheel):
    """Check stopped-container readback. Never import candidate Python or .so."""
    root = Path(root); result = {}
    for rel, digest in FILES.items():
        raw = read(root / 'hermes' / rel, mode=0o644)
        need(sha(raw) == digest, 'guard_source_mismatch'); compile(raw, rel, 'exec')
        result['hermes/' + rel] = digest
    wheel_raw = read(wheel, limit=2*1024*1024)
    need(sha(wheel_raw) == WHEEL_SHA, 'wheel_hash_mismatch')
    package = root / REGEX_REL
    files = {str(p.relative_to(package)):p for p in package.rglob('*') if not p.is_dir()}
    with zipfile.ZipFile(io.BytesIO(wheel_raw)) as archive:
        wanted = {x.filename for x in archive.infolist() if not x.is_dir()}
        extras = {'regex-2026.9.29.dist-info/' + x for x in ('INSTALLER','REQUESTED','uv_cache.json')}
        need(set(files) == wanted | extras | {'.lock'}, 'regex_tree_shape')
        # uv's site-packages lock is not wheel/RECORD content. Only the observed
        # empty root:root 0644, regular single-link file is accepted and hashed.
        raw_files = {name:read(path, limit=0 if name == '.lock' else 4*1024*1024,
                              mode=0o644) for name,path in files.items()}
        need(raw_files['.lock'] == b'', 'regex_uv_lock_nonempty')
        for name in wanted - {'regex-2026.9.29.dist-info/RECORD'}:
            need(raw_files[name] == archive.read(name), 'regex_wheel_payload_mismatch')
    record = 'regex-2026.9.29.dist-info/RECORD'
    rows = list(csv.reader(io.StringIO(raw_files[record].decode())))
    need(len(rows) == 13 and len({r[0] for r in rows if len(r)==3}) == 13, 'regex_record_shape')
    need({r[0] for r in rows} == set(raw_files)-{'.lock'}, 'regex_record_paths')
    for name, encoded, size in rows:
        need(name in raw_files, 'regex_record_path')
        if name == record: need(encoded == size == '', 'regex_record_self')
        else:
            wanted = 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(raw_files[name]).digest()).decode().rstrip('=')
            need(encoded == wanted and size == str(len(raw_files[name])), 'regex_record_digest')
    result.update({REGEX_REL+'/'+name:sha(raw) for name,raw in raw_files.items()})
    return {'guard_sha256':sha(canonical(result)), 'files':len(result), 'native_code_executed':False}

def timestamp(value):
    if type(value) in (float,int):
        need(math.isfinite(value), 'heartbeat_invalid'); return float(value)
    try:
        parsed = datetime.datetime.fromisoformat(str(value).replace('Z','+00:00'))
        need(parsed.tzinfo is not None, 'heartbeat_invalid')
        return parsed.timestamp()
    except (ValueError,TypeError): raise Refused('heartbeat_invalid') from None

def capture_data(data, scratch, checks, *, now=None):
    """Never opens the operating DB with SQLite. WAL is replayed in a private copy.

    The entire fixed source set must be stable across the copy and private query.
    Original bytes/owner/mode are untouched; only atime from reads can advance.
    """
    now = time.time() if now is None else now
    data, scratch = Path(data), Path(scratch)
    before = checks.snapshot(data)
    need(sum(x.get('size',0) for x in before.values()) <= 128*1024*1024, 'data_snapshot_too_large')
    with tempfile.TemporaryDirectory(prefix='sqlite-check-',dir=scratch) as temporary:
        private = Path(temporary)
        for name in ('state.db','state.db-wal'):
            meta = before[name]
            if meta['exists']:
                raw = read(data/name, limit=128*1024*1024, trusted=False)
                need(sha(raw) == meta['sha256'] and len(raw) == meta['size'], 'database_copy_changed')
                path = private/name
                with path.open('xb') as stream: stream.write(raw)
                path.chmod(0o600)
        # No immutable=1: a retained WAL must participate in this snapshot.
        with contextlib.closing(sqlite3.connect(f'file:{private}/state.db?mode=ro',uri=True,timeout=5)) as db:
            need(db.execute('PRAGMA quick_check').fetchone() == ('ok',), 'database_unverified')
            leases = db.execute('SELECT count(*) FROM session_turn_leases WHERE expires_at>?',(now,)).fetchone()[0]
        need(canonical(checks.snapshot(data)) == canonical(before), 'data_changed_during_validation')
    gateway = parse(read(data/'gateway_state.json', trusted=False))
    heartbeat = timestamp(gateway.get('updated_at'))
    return {'snapshot':before,'database_ok':True,'active_leases':leases,'heartbeat_epoch':heartbeat,
            'gateway_running':gateway.get('gateway_state') == 'running',
            'active_agents':gateway.get('active_agents'),'active_work':bool(gateway.get('active_work')),
            'observed_at_epoch':now}

def data_evidence(scratch):
    checks = load_module('guard_checks', 'hermes_guard_checks.py', CHECKS_SHA)
    result = capture_data('/opt/hermes-data',scratch,checks)
    result['boot_id'] = Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-','')
    return result

def idle_evidence(scratch):
    result = data_evidence(scratch)
    age = time.time()-result['heartbeat_epoch']
    need(result['gateway_running'] and result['active_agents'] == 0 and not result['active_work'] and
         result['active_leases'] == 0 and -5 <= age < 15, 'gateway_not_idle_or_stale')
    return {'idle':True,'active_leases':0,'heartbeat_age_seconds':age,'observed_at_epoch':time.time()}

def paths(token):
    need(re.fullmatch('[0-9a-f]{12}', token or ''), 'invalid_token')
    return Path('/var/backups/hermes-prestart-' + token)

def input_evidence():
    raw = sys.stdin.buffer.read(2*1024*1024+1)
    need(len(raw) <= 2*1024*1024, 'input_too_large')
    return parse(raw)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('init','arm','finish','ready','commit','inspect','tree','data','heartbeat','idle','project'))
    parser.add_argument('--token', required=True); parser.add_argument('--action', choices=tuple(TRANSITIONS))
    args = parser.parse_args()
    try:
        need(os.geteuid() == 0 and Path('/etc/machine-id').read_text().strip() == MID, 'wrong_host')
        root = paths(args.token); trusted_parent(root / 'ledger.json')
        need(stat.S_IMODE(root.lstat().st_mode) == 0o700, 'transaction_directory_mode')
        if args.operation == 'data': result = data_evidence(root)
        elif args.operation == 'idle': result = idle_evidence(root)
        elif args.operation == 'project':
            payload = input_evidence(); values = payload['containers']; wanted = {OLD,payload.get('candidate_id')}
            need(type(values) is list and len(values) <= 128, 'container_inventory_invalid')
            result = [x if x.get('Id') in wanted or x.get('Name') == '/hermes-prestart-' + args.token else {k:x[k] for k in ('Id','Name','Mounts','State')} for x in values]
        elif args.operation == 'tree': result = verify_tree(root / 'readback', WHEEL)
        elif args.operation == 'init':
            evidence = input_evidence()
            validate_docker_host(evidence)
            original = [x for x in evidence['containers'] if x.get('Id') == OLD]
            need(len(original) == 1, 'original_missing')
            plan = init_plan(args.token, original[0], evidence['snapshot'], evidence['boot_id'], evidence.get('mcp'))
            check_containers(plan, evidence['containers'])
            need(evidence.get('database_ok') is True, 'database_unverified')
            # Persist private original environment only in this operator directory.
            durable(root / 'plan.json', canonical(plan))
            env = contract().environment(original[0]['Config']['Env'])
            durable(root / 'container.env', ''.join(k+'='+v+'\n' for k,v in env.items()).encode())
            ledger = initial(plan); durable(root / 'ledger.json', canonical(ledger))
            result = {'phase':ledger['phase'], 'revision':0, 'plan_sha256':ledger['plan_sha256']}
        else:
            plan = parse(read(root / 'plan.json', mode=0o600))
            raw = read(root / 'ledger.json', mode=0o600); ledger = parse(raw)
            validate_ledger(plan, ledger)
            if args.operation == 'heartbeat':
                need(ledger['phase'] in {'new-started','old-started'} and ledger['intent'] is None, 'heartbeat_wrong_phase')
                active = ledger['candidate_id'] if ledger['phase'] == 'new-started' else OLD
                start = ledger['proofs']['start-' + active]
                result = idle_evidence(root)
                gateway = parse(read('/opt/hermes-data/gateway_state.json', trusted=False))
                epoch = timestamp(gateway.get('updated_at'))
                need(epoch >= timestamp(start['started_at']) and epoch != start['previous_heartbeat'], 'new_heartbeat_unverified')
            elif args.operation == 'inspect':
                result = {k:ledger[k] for k in ('phase','revision','candidate_id','intent','plan_sha256')}
            else:
                evidence = input_evidence()
                if args.operation in {'arm','finish'}:
                    need(args.action is not None, 'action_required')
                    updated = {'arm':arm,'finish':finish}[args.operation](plan,ledger,args.action,evidence)
                else: updated = ready(plan,ledger,evidence,commit=args.operation=='commit')
                # Preserve the exact private evidence whose digest is in this revision.
                evidence_path = root / ('evidence-%06d.json' % updated['revision'])
                evidence_bytes = canonical(evidence)
                if evidence_path.exists(): need(read(evidence_path,mode=0o600) == evidence_bytes, 'evidence_conflict')
                else: durable(evidence_path,evidence_bytes)
                # Append the old exact revision before advancing. Never edit evidence history.
                history = root / ('revision-%06d.json' % ledger['revision'])
                if history.exists(): need(read(history,mode=0o600) == raw, 'history_conflict')
                else: durable(history,raw)
                durable(root / 'ledger.json',canonical(updated),expected=sha(raw))
                result = {k:updated[k] for k in ('phase','revision','candidate_id','intent','plan_sha256')}
        print(canonical(result).decode(),end=''); return 0
    except Exception as exc:
        code = str(exc) if type(exc) is Refused and re.fullmatch('[a-z0-9_]+',str(exc)) else 'prestart_verification_failed'
        print(json.dumps({'error':code})); return 1

if __name__ == '__main__': raise SystemExit(main())
