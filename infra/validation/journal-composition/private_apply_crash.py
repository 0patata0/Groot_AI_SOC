"""Interrupt only this test's own fixed apply child after real replacements.

No operator module or backend is patched. Linux x86_64 ptrace observes the
child's actual renameat/renameat2 exits; SIGKILL is sent after two approved
source targets contain their exact after bytes. This is a process-loss test,
not power-loss durability or an operating-host reboot.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import sys
import tempfile
import time


class Registers(ctypes.Structure):
    _fields_ = [(name,ctypes.c_ulonglong) for name in (
        'r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx','rsi','rdi',
        'orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs')]


def interrupt(runtime, role, release_id, plan_sha, rows, proofs, env):
    def need(value,reason):
        if not value:
            raise RuntimeError(reason)
    need(platform.system()=='Linux' and platform.machine()=='x86_64' and os.getuid()==os.geteuid()==0,
         'owned_x86_64_root_trace_required')
    need(Path('/proc/self/uid_map').read_text().split()==['0','0','65536'], 'private_user_namespace_required')
    need(Path('/etc/capstone-proof-role').read_text().strip()==role, 'owned_role_required')
    expected = Path('/var/lib/capstone-journal-release')/release_id/role/'release_runtime.py'
    need(runtime==expected and len(release_id)==32 and len(plan_sha)==64, 'fixed_apply_subject')
    targets = {row['target']:row for row in rows if row['target'] not in (
        '/opt/capstone-diagnostics/read-system-diagnostics.py','/opt/mcp/run-wazuh-ro.sh')}
    started=time.monotonic()
    libc = ctypes.CDLL(None,use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    def trace(operation,pid,address=0,data=0):
        ctypes.set_errno(0)
        result=libc.ptrace(ctypes.c_uint(operation),ctypes.c_uint(pid),ctypes.c_void_p(address),ctypes.c_void_p(data))
        if result == -1 and ctypes.get_errno():
            raise OSError(ctypes.get_errno(),'owned_child_ptrace')
        return result
    with tempfile.TemporaryFile() as stdin, tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        stdin.write(json.dumps(proofs,sort_keys=True,separators=(',',':')).encode());stdin.seek(0)
        child=os.fork()
        if child==0:
            try:
                for source,target in ((stdin.fileno(),0),(stdout.fileno(),1),(stderr.fileno(),2)):
                    os.dup2(source,target)
                os.closerange(3,65536)
                trace(0,0)
                os.kill(os.getpid(),signal.SIGSTOP)
                os.execve('/usr/bin/python3',['/usr/bin/python3','-I','-B',str(runtime),
                    '--host',role,'--release-id',release_id,'--plan-sha256',plan_sha,'--operation','apply'],dict(env))
            except BaseException as error:
                os.write(2,('owned_apply_exec_'+type(error).__name__+':'+str(error)[:512]).encode())
                os._exit(127)
        observed=[]
        renames=[]
        syscall_stops=0
        checkpoint=None
        killed=False
        cleanup_killed=False
        final=None
        failure=None
        previous_alarm=signal.getsignal(signal.SIGALRM)
        alarm_changed=False
        def deadline(_signal,_frame):
            raise RuntimeError('owned_apply_trace_deadline')
        try:
            need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'owned_trace_no_inherited_alarm')
            signal.signal(signal.SIGALRM,deadline)
            alarm_changed=True
            signal.setitimer(signal.ITIMER_REAL,45)
            pid,status=os.waitpid(child,0)
            if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                final=status
            need(pid==child and os.WIFSTOPPED(status),'trace_child_initial_stop')
            trace(0x4200,child,0,0x1|0x00100000)  # TRACESYSGOOD and EXITKILL
            deliver=0
            while True:
                trace(24,child,0,deliver)  # PTRACE_SYSCALL
                # A blocking wait avoids adding half a millisecond at each
                # of thousands of syscall stops. The parent's real-time alarm
                # still bounds the entire owned trace, including this wait.
                pid,status=os.waitpid(child,0)
                if os.WIFEXITED(status) or os.WIFSIGNALED(status):
                    final=status
                    break
                stop=os.WSTOPSIG(status)
                deliver=0 if stop in (signal.SIGTRAP,signal.SIGTRAP|0x80,signal.SIGSTOP) else stop
                if stop != signal.SIGTRAP|0x80:
                    continue
                syscall_stops+=1
                registers=Registers()
                trace(12,child,0,ctypes.addressof(registers))
                if registers.orig_rax not in (264,316):
                    continue
                # Linux 5.3+ explicitly identifies entry/exit stops. Avoid
                # inferring the phase from a register return-value sentinel.
                information=ctypes.create_string_buffer(88)
                available=trace(0x420e,child,ctypes.sizeof(information),ctypes.addressof(information))
                need(available>=24 and int.from_bytes(information.raw[4:8],'little')==0xc000003e,
                     'owned_syscall_info_architecture')
                if information.raw[0]!=2:  # PTRACE_SYSCALL_INFO_EXIT
                    continue
                need(available>=33,'owned_syscall_exit_info')
                returned=int.from_bytes(information.raw[24:32],'little',signed=True)
                need(returned==ctypes.c_longlong(registers.rax).value,'owned_syscall_exit_register_match')
                event={'syscall':registers.orig_rax,'returncode':returned,
                       'new_dirfd':ctypes.c_longlong(registers.rdx).value}
                renames.append(event)
                del renames[:-32]
                try:
                    fd=os.open('/proc/'+str(child)+'/mem',os.O_RDONLY|os.O_NOFOLLOW)
                    try:
                        name=os.pread(fd,256,registers.r10).split(b'\0',1)[0].decode()
                    finally:
                        os.close(fd)
                    if os.path.isabs(name):
                        directory='/'
                    elif event['new_dirfd']==-100:
                        directory=os.readlink('/proc/'+str(child)+'/cwd')
                    else:
                        directory=os.readlink('/proc/'+str(child)+'/fd/'+str(event['new_dirfd']))
                    target=os.path.normpath(os.path.join(directory,name))
                    event['target']=target
                except (OSError,UnicodeError) as error:
                    event['resolution_error']=type(error).__name__+':'+str(error)[:256]
                    continue
                if returned!=0 or target not in targets or target in observed:
                    continue
                row=targets[target]
                need(hashlib.sha256(Path(target).read_bytes()).hexdigest()==row['after_sha256'],
                     'observed_replacement_after_bytes')
                observed.append(target)
                if len(observed)==2:
                    state_path=runtime.parent/'state.json'
                    checkpoint=json.loads(state_path.read_text())
                    need(checkpoint['phase']=='applying' and checkpoint['pending']['name']=='apply',
                         'durable_apply_intent_before_crash')
                    os.kill(child,signal.SIGKILL)
                    _,final=os.waitpid(child,0)
                    killed=True
                    break
        except BaseException as error:
            failure=type(error).__name__+':'+str(error)[:512]
        finally:
            if alarm_changed:
                signal.setitimer(signal.ITIMER_REAL,0)
                signal.signal(signal.SIGALRM,previous_alarm)
            if final is None:
                try:
                    os.kill(child,signal.SIGKILL)
                    cleanup_killed=True
                except ProcessLookupError:
                    pass
                _,final=os.waitpid(child,0)
        stdout.seek(0);stderr.seek(0)
        out=stdout.read(65537);error=stderr.read(8193)
        bounded=len(out)<=65536 and len(error)<=8192
        if not bounded:
            failure=failure or 'traced_apply_output_bound'
        success=killed and os.WIFSIGNALED(final) and os.WTERMSIG(final)==signal.SIGKILL and failure is None
        terminal={'wait_status':final,'reaped':True,'cleanup_sent_sigkill':cleanup_killed}
        if os.WIFEXITED(final):
            terminal['exit_code']=os.WEXITSTATUS(final)
        elif os.WIFSIGNALED(final):
            terminal['signal']=os.WTERMSIG(final)
        try:
            reply=json.loads(out) if bounded and out.strip() else None
        except (ValueError,UnicodeError):
            reply=None
        diagnostics={'terminal':terminal,'syscall_stops':syscall_stops,'rename_exits':renames,
                     'elapsed_seconds':time.monotonic()-started,
                     'wait_strategy':'blocking_waitpid_with_45s_parent_alarm',
                     'stdout_bytes':os.fstat(stdout.fileno()).st_size,
                     'stderr_bytes':os.fstat(stderr.fileno()).st_size,
                     'stdout_json':reply,'stdout_prefix':None if reply is not None else out[:2048].decode(errors='replace'),
                     'stderr':error[:8192].decode(errors='replace'),'output_within_bounds':bounded}
        return {'status':'interrupted_after_real_replacements'if success else'failed',
                'reason':None if success else failure or 'apply_did_not_reach_two_real_replacements',
                'child_pid':child,'signal':terminal.get('signal'),'actual_replacements':observed,
                'pending_checkpoint':checkpoint,'backend_patched':False,
                'source_or_runtime_patched':False,'host_reboot':False,'diagnostics':diagnostics}


def main():
    # Keep ptrace/fork in a single-threaded helper; the controller may have a
    # console-drain thread. No operating credential environment is inherited.
    try:
        raw=sys.stdin.buffer.read(262145)
        if len(raw)>262144:
            raise RuntimeError('owned_trace_input_bound')
        value=json.loads(raw)
        if not isinstance(value,dict) or set(value)!={'runtime','role','release_id','plan_sha256','rows','proofs'}:
            raise RuntimeError('owned_trace_input_shape')
        environment={'PATH':'/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin','LANG':'C','LC_ALL':'C',
                     'PYTHONDONTWRITEBYTECODE':'1','SYSTEMD_PAGER':'','SYSTEMD_COLORS':'0'}
        result=interrupt(Path(value['runtime']),value['role'],value['release_id'],value['plan_sha256'],
                         value['rows'],value['proofs'],environment)
    except Exception as error:
        result={'status':'failed','reason':type(error).__name__+':'+str(error)[:512]}
    print(json.dumps(result,sort_keys=True))
    return 0 if result['status']=='interrupted_after_real_replacements'else 1


if __name__=='__main__':
    raise SystemExit(main())
