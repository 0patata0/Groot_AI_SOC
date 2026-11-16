"""Entry boundaries and owned bounded child I/O; no operating service calls."""
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).parent
spec=importlib.util.spec_from_file_location('release_runtime_tested',HERE/'release_runtime.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class RuntimeTests(unittest.TestCase):
    def args(self,*extra):return ['--host','b','--release-id','a'*32,'--plan-sha256','b'*64,*extra]

    def test_arguments_cannot_select_path_program_environment_or_fixtures(self):
        for extra in ('--filesystem-root','--command','--path','--environment'):
            with patch.object(sys,'stderr'),self.assertRaises(SystemExit):m.arguments(self.args('--operation','status',extra,'anything'))

    def test_deadline_and_dispatch_arguments_have_one_operation_scope(self):
        with self.assertRaisesRegex(ValueError,'operator_argument_scope'):m.arguments(self.args('--operation','status','--deadline-kst','2026-11-17T06:00:00+09:00'))
        with self.assertRaisesRegex(ValueError,'operator_argument_scope'):m.arguments(self.args('--operation','initialize'))
        with self.assertRaisesRegex(ValueError,'operator_argument_scope'):m.arguments(self.args('--operation','verify','--action','arm'))

    def test_checkout_cannot_be_used_as_production_root_entry(self):
        with patch.object(m.sys,'platform','linux'),patch.object(m.os,'getuid',return_value=0),patch.object(m.os,'geteuid',return_value=0):
            with self.assertRaisesRegex(ValueError,'fixed_operator_entry_required'):m.bootstrap('b','a'*32,'b'*64)

    def test_nonroot_and_invalid_release_identity_are_denied_before_private_io(self):
        with patch.object(m.sys,'platform','linux'),patch.object(m.os,'getuid',return_value=10001),patch.object(m.os,'geteuid',return_value=10001):
            with self.assertRaisesRegex(ValueError,'root_operator_required'):m.bootstrap('b','a'*32,'b'*64)
        with patch.object(m.sys,'platform','linux'),patch.object(m.os,'getuid',return_value=0),patch.object(m.os,'geteuid',return_value=0):
            with self.assertRaisesRegex(ValueError,'operator_identity'):m.bootstrap('b','../outside','b'*64)

    def test_bounded_child_preserves_only_json_result_and_fixed_environment(self):
        code='import json,os,sys;v=sys.stdin.buffer.read();print(json.dumps({"size":len(v),"secret_env_present":"SHOULD_NOT_PASS"in os.environ}))'
        env={'PATH':'/usr/bin:/bin','LANG':'C','PYTHONDONTWRITEBYTECODE':'1'}
        with patch.dict(os.environ,{'SHOULD_NOT_PASS':'fixture only'}):
            value=m.bounded([sys.executable,'-I','-B','-c',code],b'{}',env)
        self.assertEqual(value,{'size':2,'secret_env_present':False})

    def test_oversize_stdout_terminates_owned_child(self):
        code='import sys,time;sys.stdout.buffer.write(b"x"*70000);sys.stdout.buffer.flush();time.sleep(60)'
        with self.assertRaisesRegex(ValueError,'peer_reply_bound'):m.bounded([sys.executable,'-I','-B','-c',code],b'{}',{'PATH':'/usr/bin:/bin'})

    def test_oversize_stderr_never_echoes_child_contents(self):
        code='import sys,time;sys.stderr.buffer.write(b"fixture diagnostic"*1000);sys.stderr.buffer.flush();time.sleep(60)'
        with self.assertRaisesRegex(ValueError,'^peer_error_bound$'):m.bounded([sys.executable,'-I','-B','-c',code],b'{}',{'PATH':'/usr/bin:/bin'})

    def test_nonzero_child_does_not_return_success_json(self):
        code='import sys;print("{}");sys.exit(2)'
        with self.assertRaisesRegex(ValueError,'peer_observation_unavailable'):m.bounded([sys.executable,'-I','-B','-c',code],b'{}',{'PATH':'/usr/bin:/bin'})

    def test_duplicate_json_fields_are_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate_key'):m.parsed(b'{"schema":1,"schema":2}')

    def test_noop_recovery_does_not_request_peer_reads_or_restart_services(self):
        from unittest.mock import Mock
        state={'phase':'rolled_back','facts':{'services_untouched':True}}
        ctl=Mock();ctl.execute.return_value=state
        context=Mock();context.lifecycle=ctl
        args=SimpleNamespace(host='b',release_id='a'*32,plan_sha256='b'*64,operation='recover')
        with patch.object(m,'arguments',return_value=args),patch.object(m,'Context',return_value=context),patch('builtins.print'):
            m.main()
        ctl.execute.assert_called_once_with('recover',proofs=None);context.peers.assert_not_called()

    def test_current_is_a_read_only_completion_check_not_a_lifecycle_resume(self):
        from unittest.mock import Mock
        context=Mock();context.completion.current.return_value={'status':'verified','mutation_performed':False}
        args=SimpleNamespace(host='b',release_id='a'*32,plan_sha256='b'*64,operation='current')
        with patch.object(m,'arguments',return_value=args),patch.object(m,'Context',return_value=context),patch('builtins.print'):
            m.main()
        context.completion.current.assert_called_once_with();context.lifecycle.execute.assert_not_called();context.peers.assert_not_called()


if __name__=='__main__':unittest.main()
