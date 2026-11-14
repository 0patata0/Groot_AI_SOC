"""Exact operator release template; not an MCP, bot, installer or shell tool.

An operator renders BASE/HOST, pins this file in the full three-host plan and
stages root-only candidates/backups. The full plan SHA is the approval binding.
The unrendered template refuses. No environment selects a target or test root.
"""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys
import time
import types
import uuid

BASE = '__DEPLOYMENT_BASE__'
HOST = '__HOST__'
KST = timezone(timedelta(hours=9))
JOURNAL = 'capstone-journal-reader.service'
COLLECTOR = 'capstone-system-diagnostics.service'
TIMER = 'capstone-system-diagnostics.timer'
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'}
TERMINAL = ('COMMITTED','ROLLED_BACK','APPLY_FAILED_ROLLED_BACK')


def need(value, code):
    if not value:raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def now():
    return datetime.now(KST).isoformat()


def parsed(raw):
    def pairs(items):
        value = {}
        for key,item in items:
            need(key not in value,'duplicate_json_key'); value[key] = item
        return value
    return json.loads(raw,object_pairs_hook=pairs)


def run(argv, *, timeout=30, data=None):
    result = subprocess.run(argv,input=data,stdin=None if data is not None else subprocess.DEVNULL,
        capture_output=True,timeout=timeout,env=ENV,close_fds=True)
    need(result.returncode == 0 and len(result.stdout) <= 131072
         and len(result.stderr) <= 4096,'fixed_command_failed')
    return result.stdout


def safe_directory(path, *, private=False):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts,'unsafe_directory')
    for current in (path,*path.parents):
        st = current.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022,
             'unsafe_directory')
    if private:need(stat.S_IMODE(path.lstat().st_mode) == 0o700,'private_directory_required')


def read_root(path, *, maximum=131072, private=False):
    path = Path(path); safe_directory(path.parent)
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as source:
        st = os.fstat(source.fileno())
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
             and not st.st_mode & 0o022 and 0 < st.st_size <= maximum
             and (not private or stat.S_IMODE(st.st_mode) == 0o600),'unsafe_file')
        raw = source.read(maximum+1); end = os.fstat(source.fileno())
        identity = lambda s:(s.st_dev,s.st_ino,s.st_nlink,s.st_uid,s.st_gid,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(len(raw) == st.st_size and identity(st) == identity(end) == identity(path.lstat()),
             'file_changed_during_read')
        return raw


def validate_protected(protected):
    fixed = {'/opt/capstone-diagnostics/'+name for name in (
        'diagnostic_history.py','runtime_health.py','read-system-diagnostics.py','host_inventory.py')}
    fixed.update('/etc/systemd/system/'+name for name in (JOURNAL,COLLECTOR,TIMER))
    need(isinstance(protected,dict) and fixed <= set(protected) and len(protected) <= 64
        and all(path in fixed or re.fullmatch(
            r'/etc/systemd/system/capstone-system-diagnostics\.service\.d/[A-Za-z0-9_.-]+\.conf',path)
            or re.fullmatch(r'/var/lib/capstone-diagnostics/installation/[A-Za-z0-9_.+-]+\.json',path)
            for path in protected),'protected_scope')
    for row in protected.values():
        need(isinstance(row,dict) and set(row) == {'sha256','uid','gid','mode'}
            and isinstance(row['sha256'],str) and re.fullmatch('[0-9a-f]{64}',row['sha256'])
            and type(row['uid']) is int and row['uid'] == 0
            and type(row['gid']) is int and 0 <= row['gid'] < 65534
            and type(row['mode']) is int and 0 < row['mode'] <= 0o777 and not row['mode'] & 0o022,
            'protected_metadata')


def execute_apply(actor, files):
    actor.preflight(); files.check(('before_sha256',))
    actor.arm_rollback()
    try:
        actor.quiesce(); files.apply(); actor.resume(); actor.ready(candidate=True)
        files.check(('after_sha256',)); actor.mark('APPLIED')
        return True
    except Exception as exc:
        current = files.check(('before_sha256','after_sha256'))
        if current != [row['before_sha256'] for row in files.rows]:
            actor.quiesce(); files.restore()
        # A busy collector before any file write only needs its timer resumed.
        # Do not spend another90s waiting or restart its still-running process.
        actor.resume(); actor.ready(candidate=False)
        files.check(('before_sha256',))
        actor.mark('APPLY_FAILED_ROLLED_BACK',error_type=type(exc).__name__)
        actor.disarm(); return False


def execute_rollback(actor, files):
    if actor.phase() in TERMINAL:return False
    actor.preflight(rollback=True); files.check(('before_sha256','after_sha256'))
    actor.quiesce(); count = files.restore(); actor.resume(); actor.ready(candidate=False)
    files.check(('before_sha256',)); actor.mark('ROLLED_BACK',restored_files=count)
    actor.disarm(); return True


def validate_proof(proof, state, plan_sha, host, reader, current):
    need(isinstance(proof,dict) and set(proof) == {
        'schema','plan_sha256','host','applied_at_kst','observed_at_kst','reader',
        'mcp_evidence_sha256','chat_evidence_sha256','verdict'}
        and type(proof['schema']) is int and proof['schema'] == 1
        and proof['plan_sha256'] == plan_sha and proof['host'] == host
        and proof['applied_at_kst'] == state['at_kst'] and proof['reader'] == reader
        and proof['verdict'] == 'passed','validation_proof_binding')
    for key in ('mcp_evidence_sha256','chat_evidence_sha256'):
        values = proof[key]
        need(isinstance(values,list) and 1 <= len(values) <= 32 and len(set(values)) == len(values)
            and all(isinstance(s,str) and re.fullmatch('[0-9a-f]{64}',s) for s in values),
            'validation_evidence_required')
    observed = datetime.fromisoformat(proof['observed_at_kst'])
    applied = datetime.fromisoformat(state['at_kst'])
    need(observed.utcoffset() == timedelta(hours=9) and applied <= observed <= current
         and current-observed <= timedelta(minutes=5),'validation_proof_stale')


class Actor:
    def __init__(self, approved_sha):
        need(sys.platform == 'linux' and os.getuid() == os.geteuid() == 0,'Linux_root_required')
        need(HOST in ('a','b','c') and re.fullmatch('/var/lib/capstone-journal-native/[0-9a-f]{16}-'+HOST,BASE),
             'unbound_template')
        self.base = Path(BASE); safe_directory(self.base,private=True)
        raw = read_root(self.base/'plan.json',private=True)
        need(re.fullmatch('[0-9a-f]{64}',approved_sha) and sha(raw) == approved_sha,'approval_plan_mismatch')
        self.plan_sha = approved_sha; self.plan = parsed(raw)
        need(set(self.plan) == {'schema','bundle_id','prepared_at_kst','files_module_sha256',
            'runtime_template_sha256','source_commit','hosts','limits','access_mode'}
            and type(self.plan['schema']) is int and self.plan['schema'] == 1
            and set(self.plan['hosts']) == {'a','b','c'} and re.fullmatch('[0-9a-f]{64}',self.plan['bundle_id']),
            'plan_shape')
        need(self.plan['limits'] == {'rollback_seconds':900,'apply_runtime_seconds':300,
            'rollback_runtime_seconds':180,
            'query_seconds':20,'child_seconds':12,'memory_bytes':134217728,'tasks':8}
            and self.plan['access_mode'] == 'Mac-admin231-A-B_or_C','plan_limits')
        self.host = self.plan['hosts'][HOST]
        need(isinstance(self.host,dict) and set(self.host) == {
            'base','role','observed_at_kst','machine_id_sha256','runtime_sha256',
            'files','protected','services','reader_account'}
            and self.host['role'] == {'a':'security','b':'siem','c':'service'}[HOST]
            and set(self.host['services']) == {JOURNAL,COLLECTOR,TIMER},'host_plan_shape')
        validate_protected(self.host['protected'])
        need(self.host['base'] == str(self.base) and self.base.name == self.plan['bundle_id'][:16]+'-'+HOST
            and sha(read_root(Path(__file__),private=True)) == self.host['runtime_sha256'], 'runtime_binding')
        need(sha(read_root('/etc/machine-id',maximum=128)) == self.host['machine_id_sha256'],'machine_changed')
        code = read_root(self.base/'file_transaction.py',private=True)
        need(sha(code) == self.plan['files_module_sha256'],'file_module_changed')
        module = types.ModuleType('exact_journal_file_transaction')
        module.__file__ = str(self.base/'file_transaction.py')
        exec(compile(code,module.__file__,'exec'),module.__dict__)
        rows = self.host['files']
        need(all(row['uid'] == row['gid'] == 0 and row['mode'] == 0o644
                 and (row['before_sha256'] is None) == (row['target'] == module.NEW) for row in rows),
             'fixed_file_metadata_required')
        self.files = module.FileSet(rows,self.base)
        for folder in ('candidates','backups'):safe_directory(self.base/folder,private=True)
        self.files.payloads('candidates','after_sha256')
        self.timer = 'capstone-journal-native-rollback-'+self.plan['bundle_id'][:16]+'-'+HOST

    @contextmanager
    def lock(self):
        fd = os.open(self.base/'lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            st = os.fstat(fd)
            need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
                 and stat.S_IMODE(st.st_mode) == 0o600,'unsafe_lock')
            fcntl.flock(fd,fcntl.LOCK_EX); yield
        finally:os.close(fd)

    def state(self):
        result = parsed(read_root(self.base/'state.json',private=True))
        need(result.get('schema') == 1 and result.get('plan_sha256') == self.plan_sha
             and result.get('host') == HOST and result.get('phase') in (
                 'PREPARED','APPLIED',*TERMINAL),'release_state_invalid')
        return result

    def phase(self):return self.state()['phase']

    def mark(self, phase, **extra):
        self.state()
        value = {'schema':1,'host':HOST,'plan_sha256':self.plan_sha,'phase':phase,'at_kst':now(),**extra}
        if phase == 'APPLIED':value.update(reader=self.reader(),read_probe=self.last_read)
        raw = (json.dumps(value,sort_keys=True)+'\n').encode()
        temp = self.base/('.state-'+uuid.uuid4().hex)
        fd = os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'wb') as out:out.write(raw); out.flush(); os.fsync(out.fileno())
            os.replace(temp,self.base/'state.json')
            fd = os.open(self.base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
        finally:
            if temp.exists():temp.unlink()

    def unit(self, name):
        need(name in (JOURNAL,COLLECTOR,TIMER),'unit_scope')
        raw = run(['/usr/bin/systemctl','show',name,'-p','MainPID','-p','ActiveState',
            '-p','SubState','-p','UnitFileState','-p','DropInPaths']).decode()
        return dict(line.split('=',1) for line in raw.splitlines())

    def reader(self):
        current = self.unit(JOURNAL); need(current['ActiveState'] == 'active','journal_not_active')
        pid = int(current['MainPID']); need(pid > 1,'reader_pid_invalid')
        ticks = int((Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[19])
        return {'pid':pid,'start_ticks':ticks}

    def protected(self):
        account = self.host['reader_account']
        need(account['name'] == ('mcp' if HOST == 'b' else 'capstone-diagnostics'), 'reader_account_changed')
        actual = pwd.getpwnam(account['name'])
        need(actual.pw_uid > 0 and actual.pw_gid > 0
             and actual.pw_uid == account['uid'] and actual.pw_gid == account['gid'], 'reader_account_changed')
        for path,row in self.host['protected'].items():
            raw = read_root(path); st = Path(path).lstat()
            need(sha(raw) == row['sha256'] and (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))
                 == (row['uid'],row['gid'],row['mode']),'protected_file_changed')
        for name,saved in self.host['services'].items():
            current = self.unit(name)
            need(current['DropInPaths'] == saved['DropInPaths']
                 and current['UnitFileState'] == saved['UnitFileState'],
                 'service_profile_changed')

    def preflight(self, rollback=False):
        self.protected()
        if rollback:return
        need(self.phase() == 'PREPARED','not_prepared')
        expected = self.host['services'][JOURNAL]
        need(self.reader() == {'pid':int(expected['MainPID']),'start_ticks':expected['start_ticks']}
            and self.unit(TIMER)['ActiveState'] == 'active','initial_services_changed')

    def arm_rollback(self):
        run(['/usr/bin/systemd-run','--unit='+self.timer,'--on-active=900s','--timer-property=AccuracySec=1s',
            '--property=Type=exec','--property=RuntimeMaxSec=180','--property=TimeoutStopSec=5',
            '--property=Restart=no','--property=KillMode=control-group','--',
            '/usr/bin/python3','-I','-B',str(self.base/'release.py'),'rollback',self.plan_sha])
        active = run(['/usr/bin/systemctl','show',self.timer+'.timer','-p','ActiveState']).decode()
        need(active.strip() == 'ActiveState=active','rollback_not_armed')

    def disarm(self):run(['/usr/bin/systemctl','stop',self.timer+'.timer'])

    def quiesce(self):
        run(['/usr/bin/systemctl','stop',TIMER])
        deadline = time.monotonic()+90
        while self.unit(COLLECTOR)['ActiveState'] in ('active','activating','deactivating'):
            need(time.monotonic() < deadline,'collector_busy'); time.sleep(.2)
        run(['/usr/bin/systemctl','stop',JOURNAL],timeout=35)
        need(self.unit(JOURNAL)['MainPID'] == '0','reader_not_stopped')

    def resume(self):
        run(['/usr/bin/systemctl','start',JOURNAL],timeout=25)
        run(['/usr/bin/systemctl','start',TIMER])

    def ready(self, candidate):
        self.protected(); self.reader()
        need(self.unit(TIMER)['ActiveState'] == 'active','collector_timer_not_active')
        self.files.check(('after_sha256' if candidate else 'before_sha256',))
        # Root supervises an existing nonprivileged reader, not a new grant.
        user = self.host['reader_account']['name']
        need(user == ('mcp' if HOST == 'b' else 'capstone-diagnostics'),'reader_account_changed')
        end = datetime.now(KST)-timedelta(seconds=1)
        request = {'target':{'a':'a:rule-worker','b':'b:rule-worker','c':'c:apache'}[HOST],
            'view':'journal','since_kst':(end-timedelta(minutes=15)).isoformat(),
            'until_kst':end.isoformat(),'journal_scope':'all','limit':1}
        raw = run(['/usr/sbin/runuser','-u',user,'--','/usr/bin/python3','-I','-B',
            '/opt/capstone-diagnostics/read-system-diagnostics.py'],timeout=30,
            data=(json.dumps(request)+'\n').encode())
        value = parsed(raw)
        need(value.get('status') == 'observed' and value.get('target') == request['target']
            and value.get('requested_window_total_count') is None
            and value.get('journal_retention_verified') is False,'reader_probe_failed')
        self.last_read = {'request':request,'response_sha256':sha(raw),'account':user}

    def commit(self):
        state = self.state(); need(state['phase'] == 'APPLIED','not_applied')
        self.ready(candidate=True)
        proof = parsed(read_root(self.base/'validation-proof.json',private=True))
        validate_proof(proof,state,self.plan_sha,HOST,self.reader(),datetime.now(KST))
        self.mark('COMMITTED',validation_proof_sha256=sha(read_root(self.base/'validation-proof.json',private=True)),
                  reader=self.reader(),read_probe=self.last_read)
        self.disarm()


def main():
    need(len(sys.argv) == 3 and sys.argv[1] in ('observe','apply','rollback','commit'),'fixed_action_required')
    actor = Actor(sys.argv[2])
    with actor.lock():
        action = sys.argv[1]
        if action == 'apply':execute_apply(actor,actor.files)
        elif action == 'rollback':execute_rollback(actor,actor.files)
        elif action == 'commit':actor.commit()
        actor.protected()
        current = actor.files.check(('before_sha256','after_sha256'))
        print(json.dumps({'at_kst':now(),'host':HOST,'state':actor.state(),'current_source_sha256':current,
            'journal':actor.unit(JOURNAL),'timer':actor.unit(TIMER),'no_database_restore':True}))


if __name__ == '__main__':
    try:main()
    except Exception as exc:
        # Never log supplied values, command stderr or journal messages.
        reason = str(exc) if isinstance(exc,ValueError) and re.fullmatch('[a-z_]{1,63}',str(exc)) else type(exc).__name__
        print(json.dumps({'status':'refused_or_failed','reason':reason}),file=sys.stderr)
        raise SystemExit(1)
