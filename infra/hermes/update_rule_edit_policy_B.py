#!/usr/bin/env python3
"""Patch only the rule policy of stopped Hermes; never starts/stops containers.

Run as root on B. Backups contain conversation data and remain root-only.
There is deliberately no restore CLI: after Hermes resumes, restoring an old
database would discard new messages. Failure recovery below is transaction-local.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import sqlite3
import stat
import subprocess
import tempfile
import time

START = '<!-- rule-change-policy:start -->'
END = '<!-- rule-change-policy:end -->'
OLD_CRON = 'never call propose_rule_change,'
NEW_CRON = 'never call propose_rule_edit, propose_rule_change,'
DATA = Path('/opt/hermes-data')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode), 'expected regular non-symlink file: ' + str(path))
    return st


def block(text, start=START, end=END):
    require(text.count(start) == text.count(end) == 1, 'policy markers missing or ambiguous')
    a, b = text.index(start), text.index(end)
    require(a < b, 'policy marker order invalid')
    return text[a:b + len(end)]


def replace_block(text, policy):
    old = block(text)
    return text.replace(old, policy, 1)


def atomic(path, data, metadata):
    fd, tmp = tempfile.mkstemp(prefix='.rule-policy-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
            out.flush()
            os.fchown(out.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(out.fileno(), stat.S_IMODE(metadata.st_mode))
            os.fsync(out.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      default=lambda v: {'__bytes__': v.hex()} if isinstance(v, bytes) else str(v)).encode()


def quoted(name):
    return '"' + name.replace('"', '""') + '"'


def fingerprints(db, selected):
    """Fingerprint every table, omitting only permitted prompt references."""
    result = {}
    tables = [row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for name in sorted(tables):
        if name == 'system_prompts':
            continue
        cursor = db.execute('SELECT * FROM ' + quoted(name))
        columns = [c[0] for c in cursor.description]
        rows = []
        for row in cursor:
            record = dict(zip(columns, row))
            if name == 'sessions' and record.get('id') in selected:
                record.pop('system_prompt', None)
                record.pop('system_prompt_hash', None)
            rows.append(json_bytes(record))
        digest = hashlib.sha256()
        for row in sorted(rows):
            digest.update(len(row).to_bytes(8, 'big'))
            digest.update(row)
        result[name] = {'rows': len(rows), 'sha256': digest.hexdigest()}
    schema = list(db.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name'))
    result['__schema__'] = sha(json_bytes(schema))
    return result


def current_sessions(db, mirror):
    require(isinstance(mirror, dict), 'session mirror must be an object')
    entries = [v for v in mirror.values() if isinstance(v, dict)]
    require(entries and all(v.get('platform') == 'mattermost' and isinstance(v.get('session_id'), str)
                            for v in entries), 'unexpected mirror platform or session ID')
    mirrored = {v['session_id'] for v in entries}
    require(len(mirrored) == len(entries), 'duplicate mirror session IDs')
    routed = [json.loads(row[0]) for row in db.execute(
        'SELECT entry_json FROM gateway_routing WHERE scope=?', ('/opt/data/sessions',))]
    require(routed and all(v.get('platform') == 'mattermost' and isinstance(v.get('session_id'), str)
                          for v in routed), 'unexpected routing platform or session ID')
    ids = {v['session_id'] for v in routed}
    require(len(ids) == len(routed) and ids == mirrored, 'routing and mirror session IDs differ')
    require(db.execute('SELECT count(*) FROM session_turn_leases WHERE expires_at>?',
                       (time.time(),)).fetchone()[0] == 0, 'active session lease exists')
    return ids


def cron_patch(raw):
    content = json.loads(raw)
    jobs = content if isinstance(content, list) else content.get('jobs', content)
    jobs = list(jobs.values()) if isinstance(jobs, dict) else jobs
    require(isinstance(jobs, list), 'unsupported cron JSON shape')
    selected = [v for v in jobs if isinstance(v, dict) and v.get('name') == 'soc-alert-watch']
    require(len(selected) == 1, 'expected one soc-alert-watch job')
    prompt = selected[0].get('prompt')
    require(isinstance(prompt, str), 'cron prompt missing')
    if prompt.count(NEW_CRON) == 1 and OLD_CRON not in prompt:
        return raw
    require(prompt.count(OLD_CRON) == 1 and NEW_CRON not in prompt, 'cron policy anchor ambiguous')
    require(raw.count(OLD_CRON.encode()) == 1, 'cron JSON raw anchor ambiguous')
    selected[0]['prompt'] = prompt.replace(OLD_CRON, NEW_CRON, 1)
    updated = raw.replace(OLD_CRON.encode(), NEW_CRON.encode(), 1)
    require(json.loads(updated) == content, 'cron patch altered another field')
    return updated


def stopped_identity():
    output = subprocess.check_output(['/usr/local/bin/docker', 'inspect', 'hermes'], timeout=15)
    info = json.loads(output)
    require(len(info) == 1, 'Hermes container identity ambiguous')
    info = info[0]
    state = info['State']
    require(state.get('Running') is False and state.get('Restarting') is False
            and state.get('Paused') is False and state.get('Status') in ('exited', 'created'),
            'Hermes must already be stopped; this script never stops it')
    return info['Id'], state.get('StartedAt'), state.get('FinishedAt')


def replace_cached_memory(text, old, new):
    """Refresh only the known native memory frame, preserving user/history text."""
    pattern = r'(?ms)^MEMORY \(your personal notes\) \[[^\n]+\]\n[═]+\n(.*?)(?=\nConversation started:|\nUSER \(user profile\)|\Z)'
    frames = list(re.finditer(pattern, text))
    require(len(frames) <= 1, 'ambiguous native memory frames')
    if not frames:
        return text
    frame = frames[0]
    require(frame.group(1).strip() == old.strip(), 'cached memory differs from reviewed source')
    budget = re.search(r'/([0-9,]+) chars\]', frame.group())
    require(budget is not None, 'native memory budget missing')
    maximum = int(budget[1].replace(',', ''))
    count = len(new.strip())
    require(0 < count <= maximum <= 65536, 'updated memory exceeds native budget')
    header = frame.group()[:frame.start(1) - frame.start()]
    header = re.sub(r'\[\d+% — [0-9,]+/[0-9,]+ chars\]',
                    '[' + str(count * 100 // maximum) + '% — ' + format(count, ',') + '/' + format(maximum, ',') + ' chars]', header)
    return text[:frame.start()] + header + new.strip() + '\n' + text[frame.end():]


def update(data, policy_file, backup_parent, dry_run=False, stopped_check=stopped_identity,
           management_prompt=None, preserve_cron=False, memory_file=None):
    """Core is injectable only for isolated tests; production CLI uses fixed data."""
    require(not (preserve_cron and management_prompt is not None),
            'preserve_cron conflicts with management_prompt')
    identity = stopped_check()

    def still_stopped():
        require(stopped_check() == identity, 'Hermes identity/lifecycle changed during update')

    source = policy_file.read_text(encoding='utf-8')
    policy = block(source)
    new_memory = memory_file.read_text(encoding='utf-8') if memory_file is not None else None
    old_memory = None
    def transform(text):
        updated = replace_block(text, policy)
        if management_prompt is not None:
            start, end = '<!-- bounded-operations-policy:start -->', '<!-- bounded-operations-policy:end -->'
            updated = updated.replace(block(updated, start, end), block(source, start, end), 1)
        if new_memory is not None:
            updated = replace_cached_memory(updated, old_memory, new_memory)
        return updated
    files = {'SOUL.md': data / 'SOUL.md', 'jobs.json': data / 'cron/jobs.json',
             'sessions.json': data / 'sessions/sessions.json'}
    if memory_file is not None:
        files['MEMORY.md'] = data / 'memories/MEMORY.md'
    metadata = {name: regular(path) for name, path in files.items()}
    original = {name: path.read_bytes() for name, path in files.items()}
    if new_memory is not None:
        old_memory = original['MEMORY.md'].decode('utf-8')
        require(0 < len(new_memory.strip()) <= 2200, 'reviewed memory snapshot bounds')
    new_soul = transform(original['SOUL.md'].decode('utf-8')).encode('utf-8')
    if preserve_cron:
        new_jobs = original['jobs.json']
    elif management_prompt is None:
        new_jobs = cron_patch(original['jobs.json'])
    else:
        prompt = management_prompt.read_text(encoding='utf-8')
        require(100 < len(prompt.encode()) < 65536, 'management prompt bounds')
        cron = json.loads(original['jobs.json'])
        jobs = cron.get('jobs', cron) if isinstance(cron, dict) else cron
        jobs = list(jobs.values()) if isinstance(jobs, dict) else jobs
        selected = [job for job in jobs if job.get('name') == 'soc-alert-watch']
        require(len(selected) == 1, 'expected one soc-alert-watch job')
        selected[0]['prompt'], selected[0]['enabled'] = prompt, False
        # Durable controller replaces the latest-five fingerprint cron; leave
        # the original job and schedule present but disabled for audit/rollback.
        new_jobs = (json.dumps(cron, ensure_ascii=False, indent=2) + '\n').encode()
    db_path = data / 'state.db'
    db_metadata = regular(db_path)
    side_metadata = {suffix: regular(Path(str(db_path) + suffix)) for suffix in ('-wal', '-shm')
                     if Path(str(db_path) + suffix).exists()}
    db = sqlite3.connect(db_path, timeout=10)
    backup = None
    changed_files = []
    committed = False
    try:
        require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'DB integrity check failed')
        ids = current_sessions(db, json.loads(original['sessions.json']))
        before = fingerprints(db, ids)
        old_blobs = dict(db.execute('SELECT hash,prompt FROM system_prompts'))
        refs, updates = [], []
        for session_id in sorted(ids):
            rows = db.execute('SELECT system_prompt_hash,system_prompt FROM sessions WHERE id=?',
                              (session_id,)).fetchall()
            require(len(rows) == 1, 'current session is missing or ambiguous')
            old_hash, inline = rows[0]
            require(old_hash in old_blobs, 'session prompt blob missing')
            prompt = old_blobs[old_hash]
            require(sha(prompt.encode()) == old_hash, 'stored prompt hash mismatch')
            require(inline is None or inline == prompt, 'inline prompt differs from blob')
            new_prompt = transform(prompt)
            new_hash = sha(new_prompt.encode())
            refs.append({'id': session_id, 'system_prompt_hash': old_hash, 'system_prompt': inline})
            updates.append((session_id, new_hash, new_prompt, inline is not None))
        still_stopped()
        if dry_run:
            return {'dry_run': True, 'sessions': len(ids), 'policy_sha256': sha(policy.encode())}
        parent_stat = backup_parent.lstat()
        require(stat.S_ISDIR(parent_stat.st_mode) and parent_stat.st_uid == os.geteuid()
                and not (stat.S_IMODE(parent_stat.st_mode) & 0o022), 'backup parent must be root-controlled')
        backup = Path(tempfile.mkdtemp(prefix='rule-edit-policy-', dir=backup_parent))
        os.chmod(backup, 0o700)
        for name, raw in original.items():
            (backup / name).write_bytes(raw)
            os.chmod(backup / name, 0o600)
        with sqlite3.connect(backup / 'state.db') as saved:
            db.backup(saved)
        os.chmod(backup / 'state.db', 0o600)
        (backup / 'old-prompt-references.json').write_bytes(json_bytes(refs))
        manifest = {'table_fingerprints': before, 'files': {
            name: {'sha256': sha(raw), 'uid': metadata[name].st_uid,
                   'gid': metadata[name].st_gid, 'mode': stat.S_IMODE(metadata[name].st_mode)}
            for name, raw in original.items()}, 'db_uid': db_metadata.st_uid,
            'db_gid': db_metadata.st_gid, 'sessions': len(ids)}
        (backup / 'manifest.json').write_bytes(json_bytes(manifest))
        for path in backup.iterdir():
            os.chmod(path, 0o600)
        db.execute('BEGIN IMMEDIATE')
        require(fingerprints(db, ids) == before and dict(db.execute('SELECT hash,prompt FROM system_prompts')) == old_blobs,
                'database changed between backup and transaction')
        require(current_sessions(db, json.loads(files['sessions.json'].read_bytes())) == ids,
                'current session membership changed')
        for ref in refs:
            require(db.execute('SELECT system_prompt_hash,system_prompt FROM sessions WHERE id=?',
                               (ref['id'],)).fetchone() == (ref['system_prompt_hash'], ref['system_prompt']),
                    'session prompt reference changed before transaction')
        for session_id, new_hash, prompt, has_inline in updates:
            db.execute('INSERT OR IGNORE INTO system_prompts(hash,prompt) VALUES(?,?)', (new_hash, prompt))
            require(db.execute('SELECT prompt FROM system_prompts WHERE hash=?', (new_hash,)).fetchone() == (prompt,),
                    'new prompt hash collision or corrupt blob')
            db.execute('UPDATE sessions SET system_prompt_hash=?,system_prompt=? WHERE id=?',
                       (new_hash, prompt if has_inline else None, session_id))
        for session_id, new_hash, prompt, has_inline in updates:
            require(db.execute('SELECT system_prompt_hash,system_prompt FROM sessions WHERE id=?',
                               (session_id,)).fetchone() == (new_hash, prompt if has_inline else None),
                    'updated session prompt reference mismatch')
        require(fingerprints(db, ids) == before, 'unrelated database contents changed')
        after_blobs = dict(db.execute('SELECT hash,prompt FROM system_prompts'))
        require(all(after_blobs.get(k) == v for k, v in old_blobs.items()), 'old prompt blob changed')
        require(set(after_blobs) == set(old_blobs) | {item[1] for item in updates}, 'unexpected prompt blob added')
        require(db.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'updated DB integrity failed')
        still_stopped()
        file_updates = [('SOUL.md', new_soul), ('jobs.json', new_jobs)]
        if new_memory is not None:
            file_updates.append(('MEMORY.md', new_memory.encode('utf-8')))
        for name, updated in file_updates:
            require(files[name].read_bytes() == original[name], 'file changed during update: ' + name)
            changed_files.append(name)
            atomic(files[name], updated, metadata[name])
        require(files['sessions.json'].read_bytes() == original['sessions.json'], 'session mirror changed')
        require(files['SOUL.md'].read_bytes() == new_soul and files['jobs.json'].read_bytes() == new_jobs,
                'policy file verification failed')
        if new_memory is not None:
            require(files['MEMORY.md'].read_bytes() == new_memory.encode('utf-8'), 'memory file verification failed')
        still_stopped()
        db.commit()
        committed = True
        return {'sessions': len(ids), 'policy_sha256': sha(policy.encode()), 'backup_dir': str(backup),
                'database_integrity': 'ok', 'unrelated_tables_unchanged': True,
                'memory_file_updated': new_memory is not None,
                'cached_memory_frames_refreshed': sum(1 for ref in refs if new_memory is not None
                    and 'MEMORY (your personal notes)' in old_blobs[ref['system_prompt_hash']])}
    except BaseException:
        if not committed:
            db.rollback()
            if changed_files:
                # Never restore files against a restarted/live Hermes process.
                still_stopped()
                for name in reversed(changed_files):
                    atomic(files[name], original[name], metadata[name])
        raise
    finally:
        db.close()
        # SQLite may create WAL/SHM as root. Preserve prior owners and modes;
        # new sidecars inherit the DB's original ownership/mode.
        for suffix in ('', '-wal', '-shm'):
            path = Path(str(db_path) + suffix)
            if path.exists():
                regular(path)
                saved = db_metadata if not suffix else side_metadata.get(suffix, db_metadata)
                os.chown(path, saved.st_uid, saved.st_gid)
                os.chmod(path, stat.S_IMODE(saved.st_mode))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy-file', required=True, type=Path)
    parser.add_argument('--backup-dir', required=True, type=Path,
                        help='existing root-controlled parent; a private child backup is created')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--management-prompt', type=Path,
                        help='also replace bounded policy and disable the superseded alert-watch cron')
    parser.add_argument('--preserve-cron', action='store_true',
                        help='update only the rule policy; preserve every cron byte and setting')
    parser.add_argument('--memory-file', type=Path,
                        help='root-reviewed replacement for the existing MEMORY.md and matching current prompt frames')
    args = parser.parse_args()
    require(os.geteuid() == 0, 'run as root')
    os.umask(0o077)
    source = regular(args.policy_file)
    require(source.st_uid == 0 and not (stat.S_IMODE(source.st_mode) & 0o022),
            'policy source must be root-owned and not writable by others')
    if args.management_prompt is not None:
        pstat = regular(args.management_prompt)
        require(pstat.st_uid == 0 and not stat.S_IMODE(pstat.st_mode) & 0o022,
                'management prompt must be root-controlled')
    if args.memory_file is not None:
        mstat = regular(args.memory_file)
        require(mstat.st_uid == 0 and not stat.S_IMODE(mstat.st_mode) & 0o022,
                'memory snapshot must be root-controlled')
    result = update(DATA, args.policy_file, args.backup_dir, args.dry_run,
                    management_prompt=args.management_prompt, preserve_cron=args.preserve_cron,
                    memory_file=args.memory_file)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
