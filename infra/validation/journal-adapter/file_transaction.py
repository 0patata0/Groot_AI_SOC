"""Operator-only replacement of exactly three journal implementation files.

The separate runtime pins this source, plan, candidate and backup bytes. This
module neither grants approval nor controls services. A test filesystem root is
an explicit Python argument only; no environment, plan or CLI may select it.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import uuid

CODE = '/opt/capstone-diagnostics/'
NEW = CODE + 'diagnostic_journal_native.py'
TARGETS = frozenset(CODE + name for name in (
    'system_diagnostics.py', 'diagnostic_journal.py', 'diagnostic_journal_native.py'))
MAX_BYTES = 131072
HEX = re.compile('[0-9a-f]{64}\\Z')


def need(value, code):
    if not value:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def directory(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'unsafe_directory')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def identity(st):
    return tuple(getattr(st, key) for key in (
        'st_dev', 'st_ino', 'st_nlink', 'st_uid', 'st_gid', 'st_mode',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def metadata(st):
    return st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)


def read(path, *, absent=False):
    path = Path(path); parent = directory(path.parent)
    try:
        try:fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        except FileNotFoundError:
            need(absent, 'required_file_missing')
            return None, None
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and 0 < before.st_size <= MAX_BYTES, 'unsafe_file')
            raw = stream.read(MAX_BYTES + 1); after = os.fstat(stream.fileno())
            current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            need(identity(before) == identity(after) == identity(current)
                 and len(raw) == before.st_size, 'file_changed_during_read')
            return raw, after
    finally:os.close(parent)


class FileSet:
    def __init__(self, rows, storage, *, filesystem_root=Path('/')):
        need(isinstance(rows, list) and len(rows) == 3, 'file_count')
        seen = set()
        for row in rows:
            need(isinstance(row, dict) and set(row) == {
                'target','before_sha256','after_sha256','uid','gid','mode'}, 'row_shape')
            need(row['target'] in TARGETS and row['target'] not in seen, 'target_scope')
            seen.add(row['target'])
            before = row['before_sha256']
            need((before is None and row['target'] == NEW or isinstance(before,str) and HEX.fullmatch(before))
                 and isinstance(row['after_sha256'],str) and HEX.fullmatch(row['after_sha256'])
                 and before != row['after_sha256'], 'digest_shape')
            need(all(type(row[k]) is int and 0 <= row[k] < 65534 for k in ('uid','gid'))
                 and type(row['mode']) is int and row['mode'] == 0o644, 'file_metadata')
        need(seen == TARGETS, 'target_scope')
        self.rows = sorted((dict(r) for r in rows), key=lambda r:r['target'])
        self.root, self.storage = Path(filesystem_root), Path(storage)
        for path in (self.root,self.storage,self.storage/'candidates',self.storage/'backups'):
            os.close(directory(path))

    def target(self, row):
        return self.root / row['target'].lstrip('/')

    def check(self, allowed):
        values = []
        for row in self.rows:
            raw, st = read(self.target(row), absent=row['before_sha256'] is None)
            digest = sha(raw) if raw is not None else None
            need(digest in {row[k] for k in allowed}, 'target_bytes_changed')
            need(st is None or metadata(st) == (row['uid'],row['gid'],row['mode']), 'target_metadata_changed')
            values.append(digest)
        return values

    def payloads(self, kind, key):
        values = {}
        for row in self.rows:
            digest = row[key]
            if digest is None:continue
            raw, st = read(self.storage/kind/(digest+'.data'))
            need(sha(raw) == digest and stat.S_IMODE(st.st_mode) == 0o600, 'stored_bytes_changed')
            values[digest] = raw
        return values

    def backup(self):
        self.check(('before_sha256',))
        for row in self.rows:
            raw, _ = read(self.target(row), absent=row['before_sha256'] is None)
            if raw is None:continue
            need(sha(raw) == row['before_sha256'], 'target_bytes_changed')
            path = self.storage/'backups'/(sha(raw)+'.data')
            if path.exists():
                saved, _ = read(path); need(saved == raw, 'stored_bytes_changed'); continue
            fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        fd = directory(self.storage/'backups')
        try:os.fsync(fd)
        finally:os.close(fd)
        self.payloads('backups','before_sha256')

    def replace(self, row, data, expected):
        path = self.target(row); raw, original = read(path, absent=row['before_sha256'] is None)
        need((sha(raw) if raw is not None else None) == expected
             and (original is None or metadata(original) == (row['uid'],row['gid'],row['mode'])),
             'target_changed_before_replace')
        parent = directory(path.parent); temp = '.capstone-journal-native-'+uuid.uuid4().hex
        created = False
        try:
            fd = os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
            created = True
            with os.fdopen(fd,'wb') as stream:
                stream.write(data); stream.flush(); os.fchmod(stream.fileno(),row['mode'])
                os.fchown(stream.fileno(),row['uid'],row['gid']); os.fsync(stream.fileno())
            if original is None:
                # Atomic create-if-absent; never replace an unobserved helper.
                os.link(temp,path.name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
                os.unlink(temp,dir_fd=parent); created = False
            else:
                current = os.stat(path.name,dir_fd=parent,follow_symlinks=False)
                need(identity(current) == identity(original), 'target_changed_before_replace')
                os.replace(temp,path.name,src_dir_fd=parent,dst_dir_fd=parent); created = False
            os.fsync(parent)
        finally:
            if created:os.unlink(temp,dir_fd=parent)
            os.close(parent)

    def apply(self):
        self.check(('before_sha256',)); data = self.payloads('candidates','after_sha256'); self.backup()
        # Every cold-loadable intermediate must work: the old journal accepts
        # the new core's extra binding; the new journal requires that binding.
        order = (NEW,CODE+'system_diagnostics.py',CODE+'diagnostic_journal.py')
        rows = sorted(self.rows,key=lambda row:order.index(row['target']))
        for row in rows:self.replace(row,data[row['after_sha256']],row['before_sha256'])
        self.check(('after_sha256',))

    def restore(self):
        values = self.check(('before_sha256','after_sha256'))
        if values == [r['before_sha256'] for r in self.rows]:return 0
        data = self.payloads('backups','before_sha256'); count = 0
        pairs = sorted(zip(self.rows,values),key=lambda pair:(pair[0]['target'] == NEW,pair[0]['target']))
        for row,current in pairs:
            if current == row['before_sha256']:continue
            if row['before_sha256'] is not None:self.replace(row,data[row['before_sha256']],current)
            else:
                path = self.target(row); raw, st = read(path)
                need(sha(raw) == current and metadata(st) == (row['uid'],row['gid'],row['mode']),
                     'target_changed_before_remove')
                parent = directory(path.parent)
                try:
                    need(identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False)) == identity(st),
                         'target_changed_before_remove')
                    os.unlink(path.name,dir_fd=parent); os.fsync(parent)
                finally:os.close(parent)
            count += 1
        self.check(('before_sha256',)); return count
