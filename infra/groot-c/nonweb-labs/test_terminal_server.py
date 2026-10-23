"""Isolated terminal contract tests. No host shell, Docker daemon or actual PTY is used."""
import base64
from collections import deque
import importlib.util
import json
from pathlib import Path
import subprocess
import threading
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('nonweb_terminal_tested', Path(__file__).with_name('terminal_server.py'))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
OWNER = 'a' * 64
CID = 'b' * 64
SID = 'c' * 64


def runtime_result(lab='redis'):
    return {'ok': True, 'schema': 1, 'lab': lab, 'cve_id': t.LABS[lab], 'status': 'running',
            'verification': 'environment_only', 'image_present': True, 'container_id': CID,
            'exec_user': '1000:1000' if lab == 'sudo' else '10001:10001',
            'deployment_allowed': True, 'safety_error': None}


def bare_session():
    item = t.Session.__new__(t.Session)
    item.lab, item.owner, item.cid, item.tag = 'redis', OWNER, CID, 'd' * 64
    item.docker, item.master = '/usr/bin/docker', 123
    item.condition, item.write_lock = threading.Condition(), threading.Lock()
    item.chunks, item.first, item.end = deque(), 0, 0
    item.closed = item.exited = False
    item.created = item.activity = 100.0
    item.process = mock.Mock(pid=999)
    item.reader = mock.Mock()
    return item


class RuntimeDispatchTests(unittest.TestCase):
    def test_fixed_launcher_arguments_and_action_timeouts(self):
        for action, timeout in [('up', 210), ('getcontainer', 90), ('status', 45), ('stop', 45)]:
            with self.subTest(action=action), mock.patch.object(t, 'trusted', return_value='/opt/capstone-nonweb-labs/lab.sh'), \
                 mock.patch.object(t.subprocess, 'run', return_value=mock.Mock(returncode=0, stdout=json.dumps(runtime_result()).encode())) as run:
                result = t.call_runtime(action, 'redis')
                self.assertTrue(result['ok'])
                self.assertEqual(run.call_args.args[0], ['/bin/bash', '/opt/capstone-nonweb-labs/lab.sh', action, 'redis'])
                self.assertEqual(run.call_args.kwargs['timeout'], timeout)
                self.assertNotIn('shell', run.call_args.kwargs)

    def test_unknown_actions_labs_and_shell_payload_do_not_dispatch(self):
        with mock.patch.object(t.subprocess, 'run') as run:
            for action, lab in [('exec', 'redis'), ('up', 'redis;id'), ('up', 'unknown'), ('/bin/sh', 'samba')]:
                with self.subTest(action=action, lab=lab), self.assertRaises(t.Refused): t.call_runtime(action, lab)
        run.assert_not_called()

    def test_sudo_uses_fixed_rootless_adapter_not_rootful_launcher(self):
        with mock.patch.object(t, 'sudo_adapter') as adapter, mock.patch.object(t.subprocess, 'run') as run:
            adapter.return_value.runtime.return_value = runtime_result('sudo')
            self.assertEqual(t.call_runtime('status', 'sudo'), runtime_result('sudo'))
        adapter.return_value.runtime.assert_called_once_with('status', 'sudo')
        run.assert_not_called()

    def test_failed_mismatched_and_oversized_runtime_results_are_refused(self):
        invalid = [b'not-json', b'x' * 32769, json.dumps({'ok': False, 'lab': 'redis'}).encode()]
        for patch in ({'schema': 2}, {'ok': False}, {'lab': 'samba'}, {'cve_id': 'CVE-2021-3156'}):
            invalid.append(json.dumps({**runtime_result(), **patch}).encode())
        for value in invalid:
            with self.subTest(size=len(value)), mock.patch.object(t, 'trusted', return_value='/fixture/lab.sh'), \
                 mock.patch.object(t.subprocess, 'run', return_value=mock.Mock(returncode=0, stdout=value)), self.assertRaises(t.Refused):
                t.call_runtime('status', 'redis')

    def test_duplicate_runtime_json_keys_refused(self):
        with mock.patch.object(t, 'trusted', return_value='/fixture/lab.sh'), \
             mock.patch.object(t.subprocess, 'run', return_value=mock.Mock(returncode=0, stdout=b'{"ok":true,"ok":false}')), self.assertRaises(t.Refused):
            t.call_runtime('status', 'redis')


class SessionTests(unittest.TestCase):
    def test_sudo_session_uses_adapter_argv_and_uid_1000_only(self):
        argv = ['/usr/sbin/runuser', '-u', 'capstone-sudo', '--', 'fixed-rootless-client', CID]
        with mock.patch.object(t, 'sudo_adapter') as adapter, \
             mock.patch.object(t.pty, 'openpty', return_value=(10, 11)), \
             mock.patch.object(t.os, 'set_blocking'), mock.patch.object(t.os, 'close'), \
             mock.patch.object(t.fcntl, 'ioctl'), mock.patch.object(t.threading, 'Thread'), \
             mock.patch.object(t.subprocess, 'Popen') as popen:
            adapter.return_value.exec_argv.return_value = argv
            t.Session('sudo', OWNER, 24, 80, '/usr/bin/docker', lambda *_: runtime_result('sudo'))
        adapter.return_value.exec_argv.assert_called_once_with(CID)
        self.assertEqual(popen.call_args.args[0], argv)
        self.assertNotIn('shell', popen.call_args.kwargs)
        with self.assertRaises(t.Refused), mock.patch.object(t.subprocess, 'Popen') as popen:
            t.Session('sudo', OWNER, 24, 80, '/usr/bin/docker', lambda *_: {**runtime_result('sudo'), 'exec_user': '0:0'})
        popen.assert_not_called()

    def test_sudo_close_stops_exact_container_and_retires_fd_even_on_failure(self):
        for fails in (False, True):
            item = bare_session(); item.lab = 'sudo'
            with mock.patch.object(t, 'sudo_adapter') as adapter, mock.patch.object(t.os, 'close') as close, \
                 mock.patch.object(t.subprocess, 'run') as rootful:
                if fails:
                    adapter.return_value.stop_exact.side_effect = ValueError('fixture')
                    with self.assertRaises(t.Refused): item.close()
                else:
                    item.close()
                adapter.return_value.stop_exact.assert_called_once_with(CID)
                close.assert_called_once_with(123)
                rootful.assert_not_called()

    def test_session_exec_is_fixed_uid_full_cid_and_in_container_helper(self):
        runtime = mock.Mock(return_value=runtime_result())
        with mock.patch.object(t.pty, 'openpty', return_value=(10, 11)), \
             mock.patch.object(t.os, 'set_blocking') as blocking, mock.patch.object(t.os, 'close'), \
             mock.patch.object(t.fcntl, 'ioctl'), mock.patch.object(t.threading, 'Thread'), \
             mock.patch.object(t.subprocess, 'Popen') as popen:
            item = t.Session('redis', OWNER, 24, 80, '/usr/bin/docker', runtime)
        runtime.assert_called_once_with('getcontainer', 'redis')
        argv = popen.call_args.args[0]
        self.assertEqual(argv[:4], ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock', 'exec'])
        self.assertEqual(argv[argv.index('--user') + 1], '10001:10001')
        self.assertEqual(argv[-3:-1], [CID, '/lab/terminal-session.sh'])
        self.assertEqual(argv[-1], item.tag)
        self.assertNotIn(OWNER, argv)
        self.assertNotIn('shell', popen.call_args.kwargs)
        blocking.assert_called_once_with(10, False)

    def test_invalid_cid_and_root_user_rejected_before_process_spawn(self):
        with mock.patch.object(t.subprocess, 'Popen') as popen:
            for changes in ({'container_id': 'short'}, {'container_id': CID + ';id'}, {'exec_user': '0:0'}):
                with self.subTest(changes=changes), self.assertRaises(t.Refused):
                    t.Session('redis', OWNER, 24, 80, '/usr/bin/docker', lambda *_: {**runtime_result(), **changes})
        popen.assert_not_called()

    def test_process_spawn_failure_closes_both_pty_descriptors(self):
        with mock.patch.object(t.pty, 'openpty', return_value=(10, 11)), \
             mock.patch.object(t.os, 'set_blocking'), mock.patch.object(t.os, 'close') as close, \
             mock.patch.object(t.fcntl, 'ioctl'), mock.patch.object(t.subprocess, 'Popen', side_effect=OSError('fixture')):
            with self.assertRaises(OSError): t.Session('redis', OWNER, 24, 80, '/usr/bin/docker', lambda *_: runtime_result())
        self.assertEqual([x.args[0] for x in close.call_args_list], [10, 11])

    def test_reader_has_bounded_buffer_and_poll_reports_lost_prefix(self):
        item = bare_session()
        chunks = [b'x' * 8192] * 40 + [b'']
        with mock.patch.object(t.select, 'select', return_value=([123], [], [])), mock.patch.object(t.os, 'read', side_effect=chunks):
            item.read()
        self.assertLessEqual(sum(map(len, item.chunks)), t.BUFFER)
        self.assertGreater(item.first, 0)
        result = item.poll(0)
        self.assertTrue(result['truncated'])
        self.assertLessEqual(len(base64.b64decode(result['data'])), 24576)
        self.assertEqual(result['cursor'], item.first + 24576)
        self.assertTrue(item.exited)

    def test_cursor_is_strict_integer_and_no_future_offset(self):
        item = bare_session(); item.exited = True
        for cursor in (-1, 1, True, '0'):
            with self.subTest(cursor=cursor), self.assertRaises(t.Refused): item.poll(cursor)
        self.assertTrue(item.poll(0)['closed'])

    def test_input_is_raw_pty_bytes_and_partial_writes_are_completed(self):
        item = bare_session()
        data = b'echo fixture; $(whoami)\n'
        with mock.patch.object(t.os, 'write', side_effect=[3, len(data) - 3]) as write, \
             mock.patch.object(t.select, 'select', return_value=([], [123], [])), \
             mock.patch.object(t.subprocess, 'Popen') as popen:
            item.input(base64.b64encode(data).decode())
        self.assertEqual(write.call_args_list[0].args, (123, data))
        self.assertEqual(write.call_args_list[1].args, (123, data[3:]))
        popen.assert_not_called()

    def test_input_would_block_retries_until_bounded_deadline(self):
        item = bare_session()
        with mock.patch.object(t.os, 'write', side_effect=BlockingIOError) as write, \
             mock.patch.object(t.select, 'select', return_value=([], [123], [])), \
             mock.patch.object(t.time, 'monotonic', side_effect=[100, 100, 100, 103]):
            with self.assertRaises(t.Refused): item.input('eA==')
        self.assertEqual(write.call_count, 1)

    def test_input_rejects_bad_base64_empty_large_and_closed_session(self):
        item = bare_session()
        for value in ('%', '', base64.b64encode(b'a' * 2049).decode(), 'a' * 2733, None):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(t.Refused): item.input(value)
        item.closed = True
        with self.assertRaises(t.Refused): item.input('eA==')

    def test_nonwritable_pty_fails_without_unbounded_write(self):
        item = bare_session()
        with mock.patch.object(t.select, 'select', return_value=([], [], [])), mock.patch.object(t.os, 'write') as write:
            with self.assertRaises(t.Refused): item.input('eA==')
        write.assert_not_called()

    def test_resize_only_signals_owned_process_group(self):
        item = bare_session()
        with mock.patch.object(t.fcntl, 'ioctl') as ioctl, mock.patch.object(t.os, 'killpg') as kill:
            item.resize(30, 100)
        self.assertEqual(ioctl.call_args.args[0], 123)
        kill.assert_called_once_with(999, t.signal.SIGWINCH)

    def test_delayed_fd_users_recheck_closed_after_acquiring_io_lock(self):
        # Force an input, resize or selected reader to wait for the FD lock,
        # then close the session before it can acquire it. A reused numeric
        # descriptor must not receive even one read, write, ioctl or signal.
        class ObservedLock:
            def __init__(self):
                self.lock = threading.Lock()
                self.attempted = threading.Event()

            def __enter__(self):
                self.attempted.set()
                self.lock.acquire()

            def __exit__(self, *_):
                self.lock.release()

        for operation in ('input', 'resize', 'read'):
            with self.subTest(operation=operation):
                item = bare_session()
                lock = item.write_lock = ObservedLock()
                closing = threading.Event()
                errors = []

                def delayed():
                    try:
                        if operation == 'input':
                            item.input('eA==')
                        elif operation == 'resize':
                            item.resize(24, 80)
                        else:
                            item.read()
                    except Exception as error:
                        errors.append(error)

                with mock.patch.object(t.select, 'select', return_value=([123], [123], [])), \
                     mock.patch.object(t.os, 'read', return_value=b'') as read, \
                     mock.patch.object(t.os, 'write', return_value=1) as write, \
                     mock.patch.object(t.fcntl, 'ioctl') as ioctl, \
                     mock.patch.object(t.os, 'killpg') as kill, \
                     mock.patch.object(t.os, 'close') as close, \
                     mock.patch.object(t.subprocess, 'run', side_effect=lambda *a, **k: closing.set()):
                    lock.lock.acquire()
                    worker = threading.Thread(target=delayed)
                    closer = threading.Thread(target=item.close)
                    try:
                        worker.start()
                        waiting = lock.attempted.wait(1)
                        closer.start()
                        marked_closed = closing.wait(1)
                    finally:
                        lock.lock.release()
                        worker.join(2)
                        if closer.ident is not None:
                            closer.join(2)
                    self.assertTrue(waiting, 'FD user did not enter the common lock')
                    self.assertTrue(marked_closed)
                    self.assertFalse(worker.is_alive())
                    self.assertFalse(closer.is_alive())
                    read.assert_not_called()
                    write.assert_not_called()
                    ioctl.assert_not_called()
                    kill.assert_not_called()
                    close.assert_called_once_with(123)
                    if operation == 'read':
                        self.assertEqual(errors, [])
                    else:
                        self.assertEqual(len(errors), 1)
                        self.assertIsInstance(errors[0], t.Refused)
                        self.assertEqual(str(errors[0]), 'terminal_closed')

    def test_close_does_not_release_fd_during_inflight_write(self):
        item = bare_session()
        writing, release, closing = threading.Event(), threading.Event(), threading.Event()
        errors = []

        def write(fd, data):
            writing.set()
            if not release.wait(2):
                raise AssertionError('write fixture not released')
            return len(data)

        def input_thread():
            try:
                item.input('eA==')
            except Exception as error:
                errors.append(error)

        with mock.patch.object(t.select, 'select', return_value=([], [123], [])), \
             mock.patch.object(t.os, 'write', side_effect=write), \
             mock.patch.object(t.os, 'close') as close, \
             mock.patch.object(t.subprocess, 'run', side_effect=lambda *a, **k: closing.set()):
            worker = threading.Thread(target=input_thread)
            closer = threading.Thread(target=item.close)
            try:
                worker.start()
                self.assertTrue(writing.wait(1))
                closer.start()
                self.assertTrue(closing.wait(1))
                close.assert_not_called()
            finally:
                release.set()
                worker.join(2)
                if closer.ident is not None:
                    closer.join(2)
            self.assertFalse(worker.is_alive())
            self.assertFalse(closer.is_alive())
            self.assertEqual(errors, [])
            close.assert_called_once_with(123)

    def test_close_timeout_still_closes_local_pty_and_kills_cli(self):
        item = bare_session(); item.process.wait.side_effect = [subprocess.TimeoutExpired('docker', 3), None]
        with mock.patch.object(t.subprocess, 'run', side_effect=subprocess.TimeoutExpired('docker', 8)) as run, \
             mock.patch.object(t.os, 'close') as close:
            item.close(); item.close()
        argv = run.call_args.args[0]
        self.assertEqual(argv[-3:], [CID, '/lab/terminal-close.sh', item.tag])
        self.assertEqual(argv[argv.index('--user') + 1], '10001:10001')
        close.assert_called_once_with(123)
        item.process.kill.assert_called_once()
        self.assertTrue(item.closed)

    def test_already_exited_cli_is_not_a_cleanup_error(self):
        item = bare_session(); item.process.terminate.side_effect = ProcessLookupError
        with mock.patch.object(t.subprocess, 'run'), mock.patch.object(t.os, 'close'):
            item.close()
        self.assertTrue(item.closed)


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.factory = mock.Mock(side_effect=lambda lab, owner, *_: mock.Mock(lab=lab, owner=owner, created=100, activity=100))
        self.runtime = mock.Mock(side_effect=lambda action, lab: runtime_result(lab))
        self.manager = t.Manager('/usr/bin/docker', self.runtime, self.factory)

    def opening(self, owner=OWNER, lab='redis'):
        return self.manager.handle({'action': 'terminal_open', 'owner': owner, 'lab': lab, 'rows': 24, 'cols': 80})

    def test_dimensions_reject_bool_and_extreme_values(self):
        for rows, cols in [(True, 80), (24, False), (1, 80), (101, 80), (24, 19), (24, 301)]:
            with self.subTest(rows=rows, cols=cols), self.assertRaises(t.Refused): t.dimensions({'rows': rows, 'cols': cols})
        self.assertEqual(t.dimensions({'rows': 2, 'cols': 20}), (2, 20))

    def test_owner_mismatch_cannot_poll_write_resize_or_close(self):
        opened = self.opening(); sid = opened['session_id']
        for action, fields in [('terminal_poll', {'cursor': 0}), ('terminal_input', {'data': 'eA=='}),
                               ('terminal_resize', {'rows': 24, 'cols': 80}), ('terminal_close', {})]:
            with self.subTest(action=action), self.assertRaises(t.Refused):
                self.manager.handle({'action': action, 'owner': 'f' * 64, 'session_id': sid, **fields})
        self.assertIn(sid, self.manager.sessions)

    def test_two_sessions_per_owner_and_global_limit(self):
        self.opening(); self.opening()
        with self.assertRaisesRegex(t.Refused, 'terminal_limit'): self.opening()
        for digit in ('1', '2', '3'):
            self.opening(digit * 64); self.opening(digit * 64)
        self.assertEqual(len(self.manager.sessions), 8)
        with self.assertRaisesRegex(t.Refused, 'terminal_limit'): self.opening('4' * 64)

    def test_sudo_has_one_global_session_and_close_serializes_full_stop(self):
        sid = self.opening(lab='sudo')['session_id']
        item = self.manager.sessions[sid]
        with self.assertRaisesRegex(t.Refused, 'terminal_limit'):
            self.opening(owner='f' * 64, lab='sudo')
        def closed():
            self.assertTrue(self.manager.runtime_lock.locked())
        item.close.side_effect = closed
        self.manager.handle({'action': 'terminal_close', 'owner': OWNER, 'session_id': sid})
        self.assertNotIn(sid, self.manager.sessions)
        self.opening(lab='sudo')

    def test_failed_sudo_cleanup_blocks_open_until_successful_explicit_stop(self):
        sid = self.opening(lab='sudo')['session_id']
        self.manager.sessions[sid].close.side_effect = ValueError('fixture')
        with self.assertRaises(t.Refused):
            self.manager.handle({'action': 'terminal_close', 'owner': OWNER, 'session_id': sid})
        with self.assertRaisesRegex(t.Refused, 'terminal_operation_failed'):
            self.opening(lab='sudo')
        self.manager.handle({'action': 'stop', 'lab': 'sudo'})
        self.opening(lab='sudo')

    def test_restart_reestablishes_sudo_cleanup_before_new_terminal(self):
        self.runtime.side_effect = None
        self.runtime.return_value = {**runtime_result('sudo'), 'status': 'stopped'}
        self.manager.prepare_sudo()
        self.runtime.assert_called_once_with('stop', 'sudo')
        self.assertFalse(self.manager.sudo_cleanup_failed)
        self.opening(lab='sudo')

    def test_restart_cleanup_failure_blocks_sudo_but_other_labs_work(self):
        self.runtime.side_effect = ValueError('fixture')
        self.manager.prepare_sudo()
        self.assertTrue(self.manager.sudo_cleanup_failed)
        with self.assertRaisesRegex(t.Refused, 'terminal_operation_failed'):
            self.opening(lab='sudo')
        self.opening(lab='redis')

    def test_lifecycle_response_whitelist_discards_unrelated_fields(self):
        self.runtime.side_effect = None
        self.runtime.return_value = {**runtime_result(), 'secret': 'test-only-not-a-secret', 'exec_user': '10001:10001', 'deployment_allowed': True, 'safety_error': None}
        response = self.manager.handle({'action': 'status', 'lab': 'redis'})
        self.assertEqual(set(response), {'ok', 'schema', 'lab', 'cve_id', 'status', 'verification', 'image_present', 'container_id'})

    def test_stop_closes_only_selected_lab_sessions_before_runtime_stop(self):
        first = self.opening(lab='redis')['session_id']; second = self.opening(lab='samba')['session_id']
        one, two = self.manager.sessions[first], self.manager.sessions[second]
        self.manager.handle({'action': 'stop', 'lab': 'redis'})
        one.close.assert_called_once(); two.close.assert_not_called()
        self.assertNotIn(first, self.manager.sessions); self.assertIn(second, self.manager.sessions)
        self.runtime.assert_called_once_with('stop', 'redis')

    def test_inflight_runtime_operation_blocks_terminal_open(self):
        self.manager.runtime_lock.acquire()
        try:
            with self.assertRaisesRegex(t.Refused, 'operation_in_progress'): self.opening()
        finally:
            self.manager.runtime_lock.release()
        self.factory.assert_not_called()

    def test_factory_failure_releases_operation_lock(self):
        self.factory.side_effect = t.Refused('terminal_not_running')
        with self.assertRaises(t.Refused): self.opening()
        self.assertTrue(self.manager.runtime_lock.acquire(False))
        self.manager.runtime_lock.release()
        self.assertEqual(self.manager.sessions, {})

    def test_unknown_action_extra_command_and_invalid_owner_are_refused(self):
        for request in ({'action': 'exec', 'command': 'id'}, {'action': 'deploy', 'lab': 'redis', 'command': 'id'},
                        {'action': 'terminal_open', 'owner': 'bad', 'lab': 'redis', 'rows': 24, 'cols': 80}):
            with self.subTest(request=request), self.assertRaises(t.Refused): self.manager.handle(request)
        self.runtime.assert_not_called(); self.factory.assert_not_called()

    def test_stale_sessions_are_reaped_with_independent_age_or_idle_limits(self):
        one = mock.Mock(created=0, activity=3000)
        two = mock.Mock(created=3000, activity=0)
        safe = mock.Mock(created=2999, activity=2999)
        self.manager.sessions = {'one': one, 'two': two, 'safe': safe}
        with mock.patch.object(t.time, 'sleep', side_effect=[None, StopIteration]), mock.patch.object(t.time, 'monotonic', return_value=3000):
            with self.assertRaises(StopIteration): self.manager.reap()
        self.assertEqual(self.manager.sessions, {'safe': safe})
        one.close.assert_called_once(); two.close.assert_called_once(); safe.close.assert_not_called()


if __name__ == '__main__':
    unittest.main()
