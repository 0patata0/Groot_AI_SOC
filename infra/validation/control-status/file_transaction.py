"""Exact file replacement for the reviewed status candidate; no CLI or services.

The operator wrapper pins this module, the plan and all candidate bytes. This
module has no approval, model, MCP, shell, service or database API. A different
filesystem root is only for isolated tests and is never read from a plan/env.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import uuid


TARGETS = frozenset({
    '/opt/capstone-management/soc_management_run.py',
    '/opt/hermes-data/management-code/run.py',
    '/opt/hermes-data/plugins/groot-query-completion/grounding.py',
    '/opt/capstone-ollama-trial/grounding.py',
    '/opt/hermes-data/plugins/groot-query-completion/__init__.py',
    '/opt/capstone-ollama-trial/query_grounding.py',
    '/opt/capstone-ollama-trial/harness.py',
    '/opt/hermes-data/plugins/groot-query-completion/chat_harness.py',
    '/opt/capstone-management/workflow_contract.py',
    '/opt/capstone-ollama-trial/workflow_contract.py',
    '/opt/hermes-data/plugins/groot-query-completion/workflow_contract.py',
    '/opt/capstone-management/skill-soc-investigate.md',
    '/opt/capstone-ollama-trial/skill-soc-investigate.md',
    '/opt/hermes-data/plugins/groot-query-completion/skill-soc-investigate.md',
    '/opt/capstone-management/soc_management_controller.py',
    '/opt/capstone-review-chat/review_channel.py',
    '/opt/capstone-review-chat/review_channel_worker.py',
    '/etc/capstone-ollama-trial/receipt.json',
    '/etc/capstone-review-chat/receipt.json',
})
MAX_BYTES = 2 * 1024 * 1024
HEX = re.compile(r'[0-9a-f]{64}\Z')


class Refused(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refused(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def directory(path):
    """Open every directory component without following a symlink."""
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'unsafe_directory')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def read(path):
    path = Path(path)
    parent = directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_size <= MAX_BYTES, 'unsafe_file')
            raw = stream.read(MAX_BYTES + 1)
            after = os.fstat(stream.fileno())
        need((before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) ==
             (after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns)
             and len(raw) == after.st_size, 'file_changed_during_read')
        return raw, after
    finally:
        os.close(parent)


def metadata(st):
    return st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)


class FileSet:
    def __init__(self, rows, storage, *, filesystem_root=Path('/')):
        need(isinstance(rows, list) and len(rows) == len(TARGETS), 'file_count')
        seen = set()
        for row in rows:
            need(isinstance(row, dict) and set(row) == {
                'target', 'before_sha256', 'after_sha256', 'uid', 'gid', 'mode'}, 'row_shape')
            need(row['target'] in TARGETS and row['target'] not in seen, 'target_scope')
            seen.add(row['target'])
            need(all(isinstance(row[k], str) and HEX.fullmatch(row[k])
                     for k in ('before_sha256', 'after_sha256')), 'digest_shape')
            need(row['before_sha256'] != row['after_sha256'], 'unchanged_target')
            need(all(type(row[k]) is int and 0 <= row[k] < 65534 for k in ('uid', 'gid'))
                 and type(row['mode']) is int and row['mode'] in (0o600, 0o640, 0o644), 'file_metadata')
        need(seen == TARGETS, 'target_scope')
        self.rows = [dict(r) for r in sorted(rows, key=lambda r: r['target'])]
        self.root = Path(filesystem_root)
        self.storage = Path(storage)
        for path in (self.root, self.storage, self.storage / 'candidates', self.storage / 'backups'):
            fd = directory(path)
            os.close(fd)

    def target(self, row):
        return self.root / row['target'].lstrip('/')

    def check(self, allowed):
        states = []
        for row in self.rows:
            raw, st = read(self.target(row))
            digest = sha(raw)
            need(metadata(st) == (row['uid'], row['gid'], row['mode']), 'target_metadata_changed')
            need(digest in {row[k] for k in allowed}, 'target_bytes_changed')
            states.append(digest)
        return states

    def payloads(self, kind, digest_key):
        result = {}
        for row in self.rows:
            digest = row[digest_key]
            raw, _ = read(self.storage / kind / (digest + '.data'))
            need(sha(raw) == digest, 'stored_bytes_changed')
            result[digest] = raw
        return result

    def backup(self):
        self.check(('before_sha256',))
        for row in self.rows:
            raw, _ = read(self.target(row))
            need(sha(raw) == row['before_sha256'], 'target_bytes_changed')
            path = self.storage / 'backups' / (row['before_sha256'] + '.data')
            if path.exists():
                saved, _ = read(path)
                need(sha(saved) == row['before_sha256'], 'stored_bytes_changed')
                continue
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        fd = directory(self.storage / 'backups')
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        self.payloads('backups', 'before_sha256')

    def replace(self, row, data, expected_digest):
        path = self.target(row)
        raw, original = read(path)
        need(sha(raw) == expected_digest and metadata(original) ==
             (row['uid'], row['gid'], row['mode']), 'target_changed_before_replace')
        fd = directory(path.parent)
        temp = '.capstone-status-' + uuid.uuid4().hex
        created = False
        try:
            out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            created = True
            with os.fdopen(out, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fchmod(stream.fileno(), row['mode'])
                os.fchown(stream.fileno(), row['uid'], row['gid'])
                os.fsync(stream.fileno())
            current = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            need(metadata(current) == (row['uid'], row['gid'], row['mode'])
                 and current.st_nlink == 1 and stat.S_ISREG(current.st_mode)
                 and (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) ==
                 (original.st_dev, original.st_ino, original.st_size, original.st_mtime_ns),
                 'target_changed_before_replace')
            os.replace(temp, path.name, src_dir_fd=fd, dst_dir_fd=fd)
            created = False
            os.fsync(fd)
        finally:
            if created:
                os.unlink(temp, dir_fd=fd)
            os.close(fd)

    def apply(self):
        self.check(('before_sha256',))
        data = self.payloads('candidates', 'after_sha256')
        self.backup()
        for row in self.rows:
            self.replace(row, data[row['after_sha256']], row['before_sha256'])
        self.check(('after_sha256',))

    def restore(self):
        states = self.check(('before_sha256', 'after_sha256'))
        if states == [row['before_sha256'] for row in self.rows]:
            return 0
        data = self.payloads('backups', 'before_sha256')
        count = 0
        for row, current in zip(self.rows, states):
            if current == row['after_sha256']:
                self.replace(row, data[row['before_sha256']], current)
                count += 1
        self.check(('before_sha256',))
        return count
