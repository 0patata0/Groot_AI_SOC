"""Operator-only backup/restore of the fixed diagnostic metadata cache.

The release coordinator must first stop the diagnostic timer and wait for its
collector and readers to exit. This module does not authorize a deployment,
stop services, alter source files, execute shell commands, or restore chat,
incident, approval or raw-journal databases. A different filesystem root is an
explicit Python argument for isolated tests only, never a plan/env/CLI input.
"""
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid

CACHE = Path('/var/lib/capstone-diagnostics/journal-history.sqlite3')
MAX_BYTES = 32 * 1024 * 1024
MAX_ROWS = 100000
POLICY = 'application-severity-v1'
COLUMNS = {
    'metadata': [('key', 'TEXT'), ('value', 'TEXT')],
    'events': [('id', 'TEXT'), ('at_us', 'INTEGER'), ('unit', 'TEXT'), ('error', 'TEXT')],
    'windows': [('since_us', 'INTEGER'), ('until_us', 'INTEGER'), ('truncated', 'INTEGER')],
}
OBJECTS = {
    ('table', 'metadata', 'metadata'), ('table', 'events', 'events'),
    ('table', 'windows', 'windows'), ('index', 'event_window', 'events'),
    ('index', 'sqlite_autoindex_metadata_1', 'metadata'),
    ('index', 'sqlite_autoindex_events_1', 'events'),
    ('index', 'sqlite_autoindex_windows_1', 'windows'),
}
ORDERS = {'metadata': 'key', 'events': 'id', 'windows': 'since_us,until_us'}


class Refused(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise Refused(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def identity(st):
    return tuple(getattr(st, key) for key in (
        'st_dev', 'st_ino', 'st_nlink', 'st_uid', 'st_gid', 'st_mode',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


class Cache:
    def __init__(self, host, gid, storage, *, filesystem_root=Path('/')):
        need(host in ('a', 'b', 'c') and type(gid) is int and 0 <= gid < 65534, 'cache_host_or_group')
        self.host, self.gid = host, gid
        self.root, self.storage = Path(filesystem_root), Path(storage)
        need(self.root.is_absolute() and '..' not in self.root.parts, 'filesystem_root')
        self.production = self.root == Path('/')
        self.owner = 0 if self.production else os.getuid()
        need(not self.production or os.getuid() == os.geteuid() == 0, 'root_operator_required')
        need(self.storage.is_absolute() and self.storage.is_relative_to(self.root), 'storage_path')
        if self.production:
            need(self.storage.is_relative_to('/var/lib/capstone-journal-release')
                 and len(self.storage.relative_to('/var/lib/capstone-journal-release').parts) >= 2,
                 'fixed_release_storage_required')
        self.path = self.root / CACHE.relative_to('/')
        for path in (self.path.parent, self.storage):
            fd = self.directory(path)
            try:
                st = os.fstat(fd)
                if path == self.storage:
                    need(stat.S_IMODE(st.st_mode) == 0o700, 'private_storage_required')
            finally:
                os.close(fd)

    def directory(self, path):
        path = Path(path)
        need(path.is_absolute() and '..' not in path.parts and path.is_relative_to(self.root), 'unsafe_directory')
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in (None, *path.relative_to(self.root).parts):
                if part is not None:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd); fd = child
                st = os.fstat(fd)
                need(st.st_uid == self.owner and not stat.S_IMODE(st.st_mode) & 0o022,
                     'untrusted_directory')
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read(self, path, *, database=False):
        path = Path(path); parent = self.directory(path.parent)
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                     and before.st_uid == self.owner and 0 < before.st_size <= MAX_BYTES,
                     'unsafe_cache_file')
                expected = (self.gid, 0o640) if database else (self.owner_gid(), 0o600)
                need((before.st_gid, stat.S_IMODE(before.st_mode)) == expected, 'cache_file_metadata')
                raw = stream.read(MAX_BYTES + 1); after = os.fstat(stream.fileno())
                current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                need(identity(before) == identity(after) == identity(current)
                     and len(raw) == before.st_size, 'cache_file_changed_during_read')
                return raw, after
        finally:
            os.close(parent)

    def owner_gid(self):
        return 0 if self.production else os.getgid()

    def no_sidecars(self):
        parent = self.directory(self.path.parent)
        try:
            for suffix in ('-wal', '-shm', '-journal'):
                try:
                    os.stat(self.path.name + suffix, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise Refused('cache_sidecar_present')
        finally:
            os.close(parent)

    def inspect(self, path, *, live=False):
        path = Path(path)
        if live:
            self.no_sidecars()
        raw, before = self.read(path, database=live)
        need(raw.startswith(b'SQLite format 3\0'), 'not_sqlite_cache')
        db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=2)
        try:
            db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA trusted_schema=OFF')
            db.execute('BEGIN')
            need(db.execute('PRAGMA journal_mode').fetchone() == ('delete',), 'cache_requires_delete_mode')
            need(db.execute('PRAGMA quick_check').fetchall() == [('ok',)], 'cache_integrity_failed')
            objects = set(db.execute('SELECT type,name,tbl_name FROM sqlite_master'))
            need(objects == OBJECTS, 'cache_schema_objects')
            counts, fingerprints = {}, {}
            for table, columns in COLUMNS.items():
                fields = [(row[1], row[2]) for row in db.execute('PRAGMA table_info(' + table + ')')]
                need(fields == columns, 'cache_schema_columns')
                count = db.execute('SELECT count(*) FROM ' + table).fetchone()[0]
                need(count <= (64 if table == 'metadata' else MAX_ROWS), 'cache_row_bound')
                counts[table] = count; digest = hashlib.sha256()
                for row in db.execute('SELECT * FROM ' + table + ' ORDER BY ' + ORDERS[table]):
                    chunk = canonical(row); digest.update(len(chunk).to_bytes(8, 'big')); digest.update(chunk)
                fingerprints[table] = digest.hexdigest()
            metadata = dict(db.execute('SELECT key,value FROM metadata'))
            need(metadata.get('schema') == '1' and metadata.get('host') == self.host, 'cache_host_or_schema')
            need(metadata.get('source_filter_policy') in (None, POLICY), 'cache_filter_policy')
            # Acquire the SQLite read lock before copying committed DELETE-mode
            # bytes. Reject an earlier/later file generation rather than combining it.
            locked_raw, after = self.read(path, database=live)
            need(identity(before) == identity(after) and raw == locked_raw, 'cache_changed_during_snapshot')
            if live:
                self.no_sidecars()
            return raw, after, {
                'sha256': sha(raw), 'bytes': len(raw), 'host': self.host,
                'metadata': metadata, 'counts': counts, 'table_sha256': fingerprints,
                'logical_sha256': sha(canonical(fingerprints)),
            }
        finally:
            db.close()

    def save(self, name, raw):
        need(name in ('before.sqlite3', 'before.json', 'after.sqlite3', 'after.json', 'restored.json'),
             'fixed_artifact_name')
        parent = self.directory(self.storage)
        try:
            try:
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            except FileExistsError:
                saved, _ = self.read(self.storage / name)
                need(saved == raw, 'immutable_backup_changed')
                return
            with os.fdopen(fd, 'wb') as stream:
                os.fchown(stream.fileno(), self.owner, self.owner_gid())
                os.fchmod(stream.fileno(), 0o600)
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.fsync(parent)
        finally:
            os.close(parent)

    def saved(self, kind):
        need(kind in ('before', 'after'), 'fixed_snapshot_kind')
        data, _, record = self.inspect(self.storage / (kind + '.sqlite3'))
        raw, _ = self.read(self.storage / (kind + '.json'))
        need(raw == canonical(record), 'cache_backup_receipt_mismatch')
        return data, record

    def prepare(self):
        raw, _, record = self.inspect(self.path, live=True)
        need(record['metadata'].get('source_filter_policy') is None, 'legacy_baseline_required')
        self.save('before.sqlite3', raw); self.save('before.json', canonical(record))
        saved, proof = self.saved('before')
        need(saved == raw and proof == record, 'baseline_not_verified')
        return record

    def restore(self):
        baseline, before = self.saved('before')
        current, original, post = self.inspect(self.path, live=True)
        if current == baseline:
            parent = self.directory(self.storage)
            present = []
            try:
                for name in ('after.sqlite3', 'after.json'):
                    try:
                        os.stat(name, dir_fd=parent, follow_symlinks=False)
                        present.append(True)
                    except FileNotFoundError:
                        present.append(False)
            finally:
                os.close(parent)
            need(all(present) or not any(present), 'cache_post_backup_incomplete')
            result = {'changed': False, 'baseline_sha256': before['sha256'], 'post_preserved': all(present)}
            if all(present):
                _, saved = self.saved('after')
                result['post_sha256'] = saved['sha256']
            return result
        # Preserve new observations before restoring the pre-release cache.
        # No incident/chat/approval DB is in this module's path allowlist.
        self.save('after.sqlite3', current); self.save('after.json', canonical(post))
        preserved, proof = self.saved('after')
        need(preserved == current and proof == post, 'post_cache_not_preserved')
        parent = self.directory(self.path.parent); temporary = '.journal-release-' + uuid.uuid4().hex
        created = False
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent); created = True
            with os.fdopen(fd, 'wb') as stream:
                stream.write(baseline); stream.flush()
                os.fchown(stream.fileno(), self.owner, self.gid)
                os.fchmod(stream.fileno(), 0o640); os.fsync(stream.fileno())
            self.no_sidecars()
            need(identity(os.stat(self.path.name, dir_fd=parent, follow_symlinks=False)) == identity(original),
                 'cache_changed_before_restore')
            os.replace(temporary, self.path.name, src_dir_fd=parent, dst_dir_fd=parent)
            created = False; os.fsync(parent)
        finally:
            if created:
                os.unlink(temporary, dir_fd=parent)
            os.close(parent)
        restored, _, check = self.inspect(self.path, live=True)
        need(restored == baseline and check == before, 'cache_restore_verification_failed')
        receipt = {'changed': True, 'baseline_sha256': before['sha256'],
                   'post_sha256': post['sha256'], 'post_preserved': True}
        self.save('restored.json', canonical(receipt))
        return receipt
