"""Read-only source witness for an operator's fixed diagnostic release.

No deployment, source/cache writes, service control, approval, model, TCP or
shell API. The existing forced SSH reader may relay only this bounded query.
A filesystem root override is a Python fixture argument, never a CLI/request.
"""
from datetime import datetime, timedelta, timezone
import argparse
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import struct

KST = timezone(timedelta(hours=9))
BASE = Path('/var/lib/capstone-journal-release')
SOCKET = Path('/run/capstone-journal-release-status/reader.sock')
CACHE = Path('/var/lib/capstone-diagnostics/journal-history.sqlite3')
CORE = '/opt/capstone-diagnostics/'
COMMON = frozenset(CORE + n for n in ('system_diagnostics.py', 'diagnostic_history.py',
    'diagnostic_journal.py', 'diagnostic_journal_native.py')) | frozenset(
    '/etc/systemd/system/' + n for n in ('capstone-system-diagnostics.service',
                                       'capstone-diagnostic-history-backfill.service'))
B_TARGETS = frozenset({
    '/etc/capstone-ollama-trial/receipt.json', '/etc/capstone-review-chat/receipt.json',
    '/opt/capstone-management/skill-soc-investigate.md', '/opt/capstone-management/skill-soc-query.md',
    '/opt/capstone-management/soc_management_controller.py', '/opt/capstone-management/soc_management_run.py',
    '/opt/capstone-management/workflow_contract.py',
    '/opt/capstone-ollama-trial/chat_contract.py', '/opt/capstone-ollama-trial/grounding.py',
    '/opt/capstone-ollama-trial/harness.py', '/opt/capstone-ollama-trial/query_grounding.py',
    '/opt/capstone-ollama-trial/read_contract.py', '/opt/capstone-ollama-trial/runtime.py',
    '/opt/capstone-ollama-trial/skill-soc-investigate.md', '/opt/capstone-ollama-trial/skill-soc-query.md',
    '/opt/capstone-ollama-trial/workflow_contract.py', '/opt/capstone-review-chat/review_channel_worker.py',
    '/opt/hermes-data/management-code/run.py',
    '/opt/hermes-data/plugins/groot-query-completion/__init__.py',
    '/opt/hermes-data/plugins/groot-query-completion/alignment.py',
    '/opt/hermes-data/plugins/groot-query-completion/chat_contract.py',
    '/opt/hermes-data/plugins/groot-query-completion/chat_harness.py',
    '/opt/hermes-data/plugins/groot-query-completion/grounding.py',
    '/opt/hermes-data/plugins/groot-query-completion/read_contract.py',
    '/opt/hermes-data/plugins/groot-query-completion/skill-soc-investigate.md',
    '/opt/hermes-data/plugins/groot-query-completion/skill-soc-query.md',
    '/opt/hermes-data/plugins/groot-query-completion/workflow_contract.py',
    '/opt/mcp/system-diagnostics-mcp.py',
})
TARGETS = {'a': COMMON, 'b': COMMON | B_TARGETS, 'c': COMMON}
OPTIONAL = frozenset({CORE + 'diagnostic_journal_native.py',
                     '/etc/systemd/system/capstone-diagnostic-history-backfill.service'})
PHASES = frozenset({'staged', 'armed', 'quiesced', 'backed_up', 'applying', 'applied',
    'verified', 'confirming', 'confirmed', 'rolling_back', 'rolled_back', 'failed'})
HEX = re.compile(r'[0-9a-f]{64}\Z')
RELEASE = re.compile(r'[0-9a-f]{32}\Z')
MAX_SOURCE = 2 * 1024 * 1024
MAX_REPLY = 65536


class Refused(ValueError):
    pass


def need(value, code):
    if not value: raise Refused(code)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def source_contract(host, release_id, rows):
    return hashlib.sha256(canonical({'schema':1,'host':host,'release_id':release_id,
                                    'rows':sorted(rows,key=lambda r:r['target'])})).hexdigest()


def parsed(raw):
    def pairs(items):
        value = {}
        for k, v in items:
            need(k not in value, 'duplicate_key'); value[k] = v
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refused('nonfinite')))


def request(value):
    need(isinstance(value, dict) and set(value) == {'schema', 'host', 'release_id'}, 'request_shape')
    need(type(value['schema']) is int and value['schema'] == 1 and isinstance(value['host'], str) and value['host'] in TARGETS,
         'request_identity')
    need(isinstance(value['release_id'], str) and RELEASE.fullmatch(value['release_id']), 'release_id')
    return value['host'], value['release_id']


def stamp(st):
    return tuple(getattr(st, k) for k in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode',
                                        'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def root_directory(path):
    """Open a fixed production directory without trusting symlink ancestors."""
    need(path.is_absolute() and '..' not in path.parts, 'directory_scope')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in (None, *path.relative_to('/').parts):
            if part is not None:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = child
            st = os.fstat(fd)
            need(st.st_uid == 0 and not st.st_mode & 0o022, 'untrusted_root_directory')
        return fd
    except BaseException:
        os.close(fd); raise


class Witness:
    def __init__(self, config, gid, *, filesystem_root=Path('/')):
        need(isinstance(config, dict) and set(config) == {'schema', 'host', 'release_id', 'rows', 'reader_uid'},
             'config_shape')
        self.host, self.release_id = request({k:config[k] for k in ('schema', 'host', 'release_id')})
        need(type(gid) is int and 0 <= gid < 65534 and type(config['reader_uid']) is int
             and 0 <= config['reader_uid'] < 65534, 'reader_identity')
        self.gid, self.reader_uid = gid, config['reader_uid']
        self.root = Path(filesystem_root)
        need(self.root.is_absolute() and '..' not in self.root.parts, 'filesystem_root')
        self.fixture = self.root != Path('/')
        self.owner = os.getuid() if self.fixture else 0
        need(self.fixture or os.getuid() == os.geteuid() == 0, 'root_witness_required')
        need(isinstance(config['rows'], list) and len(config['rows']) == len(TARGETS[self.host]), 'row_count')
        self.rows = []
        for row in config['rows']:
            need(isinstance(row, dict) and set(row) == {'target', 'before_sha256', 'after_sha256', 'uid', 'gid', 'mode'}, 'row_shape')
            need(isinstance(row['target'], str) and row['target'] in TARGETS[self.host], 'target_scope')
            before, after = row['before_sha256'], row['after_sha256']
            need((before is None and row['target'] in OPTIONAL or isinstance(before, str) and HEX.fullmatch(before))
                 and isinstance(after, str) and HEX.fullmatch(after), 'digest_shape')
            need(all(type(row[k]) is int and 0 <= row[k] < 65534 for k in ('uid', 'gid'))
                 and type(row['mode']) is int and row['mode'] in (0o550,0o600,0o640,0o644,0o755), 'file_metadata')
            self.rows.append(dict(row))
        need({r['target'] for r in self.rows} == TARGETS[self.host], 'target_set')
        need(any(r['before_sha256'] != r['after_sha256'] for r in self.rows), 'unchanged_release')
        self.rows.sort(key=lambda r:r['target'])
        self.storage = self.root / BASE.relative_to('/') / self.release_id / self.host

    def directory(self, path):
        need(path.is_relative_to(self.root) and '..' not in path.parts, 'directory_scope')
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            traversed = self.root
            for part in (None, *path.relative_to(self.root).parts):
                if part is not None:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd); fd = child
                    traversed /= part
                st = os.fstat(fd)
                # Hermes-owned plugin directories are valid; source bytes and
                # metadata still have to match the complete pinned row set.
                need(stat.S_IMODE(st.st_mode) & 0o022 == 0, 'writable_parent')
                owners = {self.owner}
                if not self.fixture and traversed.is_relative_to('/opt/hermes-data'):
                    owners |= {r['uid'] for r in self.rows if r['target'].startswith('/opt/hermes-data/')}
                need(st.st_uid in owners, 'directory_owner')
            return fd
        except BaseException:
            os.close(fd); raise

    def read(self, path, *, limit=MAX_SOURCE, absent=False):
        parent = self.directory(path.parent)
        try:
            try:fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            except FileNotFoundError:
                need(absent, 'required_file_missing'); return None, None
            with os.fdopen(fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit, 'unsafe_file')
                raw = stream.read(limit + 1); after = os.fstat(stream.fileno())
                current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                need(stamp(before) == stamp(after) == stamp(current) and len(raw) == before.st_size, 'file_changed')
                again = self.directory(path.parent)
                try:
                    a,b = os.fstat(parent),os.fstat(again)
                    need((a.st_dev,a.st_ino)==(b.st_dev,b.st_ino),'directory_changed')
                finally:os.close(again)
                return raw, before
        finally:os.close(parent)

    def cache(self):
        path = self.root / CACHE.relative_to('/')
        try:
            parent = self.directory(path.parent)
            try:
                st = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == self.owner
                     and stat.S_IMODE(st.st_mode) == 0o640 and st.st_gid == self.gid
                     and 0 < st.st_size <= 32 * 1024 * 1024, 'cache_metadata')
                for suffix in ('-wal','-shm','-journal'):
                    try:os.stat(path.name + suffix, dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError:continue
                    raise Refused('cache_sidecar')
                db = sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, timeout=1)
                try:
                    db.execute('PRAGMA query_only=ON');db.execute('PRAGMA trusted_schema=OFF');db.execute('BEGIN')
                    db.set_progress_handler(lambda: 1, 100000)
                    pairs = db.execute('SELECT key,value FROM metadata LIMIT 65').fetchall()
                    need(len(pairs) <= 64 and len({r[0] for r in pairs}) == len(pairs), 'cache_metadata_bound')
                    values = dict(pairs)
                    need(values.get('schema')=='1' and values.get('host')==self.host, 'cache_identity')
                    policy=values.get('source_filter_policy')
                    need(policy in (None,'application-severity-v1'), 'cache_policy')
                    need(stamp(os.stat(path.name, dir_fd=parent, follow_symlinks=False))==stamp(st), 'cache_changed')
                    return {'status':'observed','source_filter_policy':policy}
                finally:db.close()
            finally:os.close(parent)
        except (OSError,ValueError,sqlite3.Error):
            return {'status':'unavailable','source_filter_policy':None}

    def answer(self, query):
        host, release_id = request(query)
        need((host,release_id)==(self.host,self.release_id), 'release_mismatch')
        files=[];identities=[];old=True;new=True
        for row in self.rows:
            path=self.root/row['target'].lstrip('/')
            raw, st=self.read(path,absent=row['target'] in OPTIONAL)
            digest=hashlib.sha256(raw).hexdigest() if raw is not None else None
            uid=os.getuid() if self.fixture else row['uid']
            gid=os.getgid() if self.fixture else row['gid']
            metadata=st is None or (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))==(uid,gid,row['mode'])
            old &= digest==row['before_sha256'] and metadata
            new &= digest==row['after_sha256'] and metadata
            files.append({'target':row['target'],'sha256':digest,'metadata_matches':bool(metadata)})
            identities.append(stamp(st) if st is not None else None)
        # The overlapping read intervals establish one coherent file-set
        # observation even when an unprivileged plugin owner edits a file.
        for row,expected in zip(self.rows,identities):
            _,st=self.read(self.root/row['target'].lstrip('/'),absent=row['target'] in OPTIONAL)
            need((stamp(st) if st is not None else None)==expected,'source_set_changed')
        foreign=any(f['sha256'] not in (r['before_sha256'],r['after_sha256']) or not f['metadata_matches'] for f,r in zip(files,self.rows))
        generation='baseline' if old else 'candidate' if new else 'foreign' if foreign else 'mixed'
        phase='unknown'
        try:
            raw,st=self.read(self.storage/'state.json',limit=65536)
            need(st.st_uid==self.owner and stat.S_IMODE(st.st_mode)==0o600,'state_metadata')
            value=parsed(raw)
            need(value['host']==self.host and value['release_id']==self.release_id and value['phase'] in PHASES,'state_identity')
            phase=value['phase']
        except (OSError,ValueError,KeyError):pass
        result={'schema':1,'kind':'release_status','host':self.host,'release_id':self.release_id,
                'source_contract_sha256':source_contract(self.host,self.release_id,self.rows),
                'observed_at_kst':datetime.now(KST).isoformat(),'generation':generation,'phase':phase,
                'files':files,'cache':self.cache(),'mutation_performed':False,'isolated_filesystem':self.fixture}
        need(len(canonical(result))<=MAX_REPLY,'reply_bound')
        return result


def reply_to(witness, client):
    """One bounded local read. A fixture can exercise the same kernel path."""
    client.settimeout(2)
    try:
        _,uid,_=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        need(uid in (0,witness.reader_uid),'reader_uid')
        raw,_,flags,_=client.recvmsg(4097)
        need(raw and len(raw)<=4096 and not flags&socket.MSG_TRUNC,'request_bound')
        reply=witness.answer(parsed(raw))
        client.sendall(canonical(reply))
    except (OSError,ValueError,KeyError,TypeError,RecursionError,sqlite3.Error):
        try:client.sendall(b'{"schema":1,"status":"unavailable","reason":"release_status_unavailable"}')
        except OSError:pass


def serve(witness):
    need(not witness.fixture and os.getuid()==os.geteuid()==0,'production_server_required')
    parent=SOCKET.parent;fd=root_directory(parent)
    try:st=os.fstat(fd)
    finally:os.close(fd)
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and st.st_gid==witness.gid
         and stat.S_IMODE(st.st_mode)==0o750,'socket_directory')
    need(not os.path.lexists(SOCKET),'socket_exists')
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    try:
        listener.bind(str(SOCKET));bound=(SOCKET.lstat().st_dev,SOCKET.lstat().st_ino)
        os.chown(SOCKET,0,witness.gid);os.chmod(SOCKET,0o660);listener.listen(4)
        while True:
            client,_=listener.accept()
            with client:
                reply_to(witness,client)
    finally:
        listener.close()
        if 'bound' in locals() and os.path.lexists(SOCKET):
            current=SOCKET.lstat()
            if stat.S_ISSOCK(current.st_mode) and current.st_uid==0 and (current.st_dev,current.st_ino)==bound:
                os.unlink(SOCKET)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host',choices=tuple(TARGETS),required=True)
    p.add_argument('--release-id',required=True)
    args=p.parse_args();need(RELEASE.fullmatch(args.release_id),'release_id')
    need(os.getuid()==os.geteuid()==0,'root_witness_required')
    root=BASE/args.release_id/args.host
    # Config is staged by the operator; no request, environment or CLI selects
    # a target path, filesystem root, executable or candidate byte stream.
    parent=root_directory(root)
    try:
        st=os.fstat(parent);need(stat.S_IMODE(st.st_mode)==0o700,'private_config_directory')
        fd=os.open('witness.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        with os.fdopen(fd,'rb') as f:
            st=os.fstat(f.fileno());need(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_nlink==1
                                      and stat.S_IMODE(st.st_mode)==0o600 and 0<st.st_size<=65536,'witness_config')
            raw=f.read(65537)
            need(len(raw)==st.st_size and stamp(st)==stamp(os.fstat(f.fileno()))
                 ==stamp(os.stat('witness.json',dir_fd=parent,follow_symlinks=False)),'config_changed')
            config=parsed(raw)
    finally:os.close(parent)
    need(config['host']==args.host and config['release_id']==args.release_id,'config_identity')
    serve(Witness(config,grp.getgrnam('capstone-diagnostics').gr_gid))


if __name__=='__main__':
    try:main()
    except (OSError,ValueError,KeyError,TypeError,RecursionError,sqlite3.Error):
        raise SystemExit(1) from None
