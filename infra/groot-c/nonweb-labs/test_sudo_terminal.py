"""Fixed rootless adapter boundaries; no Docker daemon or host changes."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('tested_sudo_terminal', Path(__file__).with_name('sudo_terminal.py'))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
CID, OTHER = 'a' * 64, 'b' * 64
IMAGE = 'sha256:' + 'c' * 64
CONFIG = {'schema': 1, 'operator_uid': 1991, 'image_id': IMAGE,
          'deb_sha256': 'd' * 64, 'preparation_sha256': 'e' * 64}


def result(status='running', cid=CID):
    return {'schema': 1, 'cve_id': t.CVE, 'status': status, 'container_id': cid,
            'environment_ready': True, 'isolation': {'host_uid_for_container_root': 1991}}


def normalized(status='running', cid=CID):
    return {'ok': True, 'schema': 1, 'lab': 'sudo', 'cve_id': t.CVE,
            'status': status, 'verification': 'environment_only', 'image_present': True,
            'container_id': cid, 'exec_user': '1000:1000', 'deployment_allowed': True}


def context():
    lab, publisher = mock.Mock(), mock.Mock()
    lab.running_isolation.return_value = {'host_uid_for_container_root': 1991}
    lab.docker_binary.return_value = '/usr/local/bin/docker'
    return lab, publisher, dict(CONFIG)


class RuntimeTests(unittest.TestCase):
    def test_only_fixed_lab_and_actions_dispatch(self):
        adapter = t.Adapter()
        with mock.patch.object(adapter, '_context') as called:
            for action, lab in [('exec', 'sudo'), ('up', 'redis'), ('stop;id', 'sudo'), ('up', 'sudo;id')]:
                with self.subTest(action=action, lab=lab), self.assertRaises(t.Rejected):
                    adapter.runtime(action, lab)
        called.assert_not_called()

    def test_running_status_requires_fresh_package_and_root_host_attestation(self):
        adapter = t.Adapter(); lab, publisher, config = context()
        with mock.patch.object(adapter, '_context', return_value=(lab, publisher, config)), \
             mock.patch.object(adapter, '_cli', side_effect=[result(), result()]) as cli, \
             mock.patch.object(adapter, '_inspect', side_effect=[{'image': True}, {'State': {'Running': True}},
                                                              {'State': {'Running': True}}]):
            value = adapter.runtime('status')
        self.assertEqual(value, normalized())
        self.assertEqual(cli.call_args_list, [mock.call('status'), mock.call('verify')])
        lab.image_contract.assert_called_once()
        self.assertEqual(lab.container_contract.call_count, 2)
        publisher.ready_contract.assert_called_once()
        lab.running_isolation.assert_called_once()

    def test_failed_root_map_or_changed_container_never_authorizes_a_terminal(self):
        for mismatch in ('root_map', 'cid', 'stopped_during_verify'):
            adapter = t.Adapter(); lab, publisher, config = context()
            values = [result(), result(cid=OTHER if mismatch == 'cid' else CID)]
            inspected = [{'image': True}, {'State': {'Running': True}},
                         {'State': {'Running': mismatch != 'stopped_during_verify'}}]
            if mismatch == 'root_map':
                lab.running_isolation.side_effect = t.Rejected('host_root_mapping')
            with self.subTest(mismatch=mismatch), \
                 mock.patch.object(adapter, '_context', return_value=(lab, publisher, config)), \
                 mock.patch.object(adapter, '_cli', side_effect=values), \
                 mock.patch.object(adapter, '_inspect', side_effect=inspected), self.assertRaises(t.Rejected):
                adapter.runtime('getcontainer')

    def test_stopped_or_absent_container_cannot_open_but_status_is_valid(self):
        for status, cid in [('not_created', None), ('stopped', CID)]:
            adapter = t.Adapter(); lab, publisher, config = context()
            with self.subTest(status=status), \
                 mock.patch.object(adapter, '_context', return_value=(lab, publisher, config)), \
                 mock.patch.object(adapter, '_cli', return_value=result(status, cid)), \
                 mock.patch.object(adapter, '_inspect', return_value={'State': {'Running': False}}):
                value = adapter.runtime('status')
                self.assertEqual(value['status'], 'not_deployed' if cid is None else 'stopped')
                with self.assertRaises(t.Rejected):
                    adapter.runtime('getcontainer')
            publisher.ready_contract.assert_not_called()

    def test_malformed_full_cids_rejected(self):
        for cid in ('short', CID + ';id', None, True):
            adapter = t.Adapter(); lab, publisher, config = context()
            with self.subTest(cid=cid), mock.patch.object(adapter, '_context', return_value=(lab, publisher, config)), \
                 mock.patch.object(adapter, '_cli', return_value=result(cid=cid)), \
                 mock.patch.object(adapter, '_inspect'), self.assertRaises(t.Rejected):
                adapter.runtime('status')

    def test_exec_is_fixed_rootless_uid_and_cid_with_no_host_shell(self):
        adapter = t.Adapter(); lab, publisher, config = context()
        with mock.patch.object(adapter, 'runtime', return_value=normalized()) as runtime, \
             mock.patch.object(adapter, '_context', return_value=(lab, publisher, config)), \
             mock.patch.object(t, 'operator_prefix', return_value=['/usr/sbin/runuser', '-u', 'capstone-sudo', '--']):
            argv = adapter.exec_argv(CID)
        runtime.assert_called_once_with('getcontainer')
        self.assertEqual(argv[:4], ['/usr/sbin/runuser', '-u', 'capstone-sudo', '--'])
        self.assertEqual(argv[4:8], ['/usr/local/bin/docker', '--host', t.SOCKET, 'exec'])
        self.assertEqual(argv[argv.index('--user') + 1], '1000:1000')
        self.assertEqual(argv[-8:], [CID, '/usr/bin/timeout', '--foreground', '--signal=TERM',
                                   '--kill-after=2s', '1800s', '/bin/sh', '-i'])
        self.assertNotIn('unix:///var/run/docker.sock', argv)
        self.assertNotIn('0:0', argv)
        self.assertNotIn('-c', argv)

    def test_replacement_before_exec_is_never_opened(self):
        adapter = t.Adapter()
        with mock.patch.object(adapter, 'runtime', return_value=normalized(cid=OTHER)), \
             mock.patch.object(t, 'operator_prefix') as prefix, self.assertRaises(t.Rejected):
            adapter.exec_argv(CID)
        prefix.assert_not_called()

    def test_stop_exact_checks_identity_then_only_the_constant_locked_stop(self):
        adapter = t.Adapter()
        with mock.patch.object(adapter, '_stop_context') as check, \
             mock.patch.object(adapter, '_operator', return_value=(0, result('stopped'))) as run, \
             mock.patch.object(t, 'executable', side_effect=str):
            self.assertTrue(adapter.stop_exact(CID))
        check.assert_called_once_with(CID)
        self.assertEqual(run.call_args.args[0], ['/usr/bin/python3', '-B', '-c', t.EXACT_STOP, CID])

    def test_changed_receipt_never_reaches_the_stop_child(self):
        adapter = t.Adapter(); lab, publisher, config = context()
        with mock.patch.object(adapter, '_context', return_value=(lab, publisher, config)), \
             mock.patch.object(adapter, '_receipt', return_value={'container_id': OTHER}), \
             mock.patch.object(adapter, '_operator') as run, self.assertRaises(t.Rejected):
            adapter.stop_exact(CID)
        run.assert_not_called()

    def test_stop_uses_no_package_probe_and_root_attests_the_owned_container(self):
        adapter = t.Adapter(); lab, publisher, config = context()
        with mock.patch.object(adapter, '_context', return_value=(lab, publisher, config)), \
             mock.patch.object(adapter, '_receipt', return_value={'container_id': CID}), \
             mock.patch.object(adapter, '_operator', return_value=(0, {})), \
             mock.patch.object(adapter, '_inspect', return_value={'State': {'Running': True}}), \
             mock.patch.object(adapter, '_cli') as cli:
            adapter._stop_context(CID)
        cli.assert_not_called()
        lab.daemon_contract.assert_called_once_with({}, resources=False)
        lab.container_contract.assert_called_once()
        lab.running_isolation.assert_called_once()

    def test_bad_exact_stop_reply_does_not_confirm_success(self):
        for value in (result('running'), result('stopped', OTHER), {'schema': True}, None):
            adapter = t.Adapter()
            with self.subTest(value=value), mock.patch.object(adapter, '_stop_context'), \
                 mock.patch.object(adapter, '_operator', return_value=(0, value)), \
                 mock.patch.object(t, 'executable', side_effect=str), self.assertRaises(t.Rejected):
                adapter.stop_exact(CID)

    def test_explicit_stop_is_idempotent_and_can_report_a_missing_image_after_stopping(self):
        adapter = t.Adapter(); lab, publisher, config = context()
        with mock.patch.object(adapter, '_context', return_value=(lab, publisher, config)), \
             mock.patch.object(adapter, '_receipt', return_value={'container_id': CID}), \
             mock.patch.object(adapter, 'stop_exact', return_value=True) as stop, \
             mock.patch.object(adapter, '_inspect', side_effect=[{'State': {'Running': False}}, OSError(),
                                                              {'State': {'Running': False}}, OSError()]):
            first, second = adapter.runtime('stop'), adapter.runtime('stop')
        self.assertEqual(first, second)
        self.assertEqual(first['status'], 'stopped')
        self.assertFalse(first['image_present'])
        self.assertFalse(first['deployment_allowed'])
        self.assertEqual(stop.call_args_list, [mock.call(CID), mock.call(CID)])


class SourceAndProcessTests(unittest.TestCase):
    def source_fixture(self):
        lab = ('def config_at(path, uid):\n return ' + repr(CONFIG) + '\n').encode()
        pub = b'# fixed publisher fixture\n'
        config = json.dumps(CONFIG).encode()
        manifest = {'schema': 1, 'profile': t.PROFILE, 'state': 'complete', 'image_id': IMAGE,
                    'source_sha256': {'lab.py': hashlib.sha256(lab).hexdigest(),
                                      'publish.py': hashlib.sha256(pub).hexdigest()},
                    'files': {str(t.CONFIG): {'sha256': hashlib.sha256(config).hexdigest(), 'mode': 0o644}}}
        files = {t.MANIFEST: json.dumps(manifest).encode(), t.BASE / 'lab.py': lab,
                 t.BASE / 'publish.py': pub, t.CONFIG: config}
        return files, manifest

    def test_original_bootstrap_source_and_configuration_pins_are_required(self):
        files, manifest = self.source_fixture()
        with mock.patch.object(t, 'root_file', side_effect=lambda path, *a, **k: files[path]), \
             mock.patch.object(t, 'SOURCE_PINS', manifest['source_sha256']), \
             mock.patch.object(t, 'APPROVED_CONFIG', CONFIG), \
             mock.patch.object(t.os, 'getuid', return_value=0), mock.patch.object(t.os, 'geteuid', return_value=0):
            self.assertEqual(t.Adapter()._context()[2], CONFIG)
        for change in ('source', 'config', 'profile', 'image', 'incomplete'):
            changed = copy.deepcopy(manifest)
            if change == 'source': changed['source_sha256']['lab.py'] = 'f' * 64
            if change == 'config': changed['files'][str(t.CONFIG)]['sha256'] = 'f' * 64
            if change == 'profile': changed['profile'] = 'other'
            if change == 'image': changed['image_id'] = 'sha256:' + 'f' * 64
            if change == 'incomplete': changed['state'] = 'installing'
            altered = dict(files, **{})
            altered[t.MANIFEST] = json.dumps(changed).encode()
            with self.subTest(change=change), mock.patch.object(t, 'root_file', side_effect=lambda path, *a, **k: altered[path]), \
                 mock.patch.object(t, 'SOURCE_PINS', manifest['source_sha256']), \
                 mock.patch.object(t, 'APPROVED_CONFIG', CONFIG), \
                 mock.patch.object(t.os, 'getuid', return_value=0), mock.patch.object(t.os, 'geteuid', return_value=0), \
                 self.assertRaises(t.Rejected):
                t.Adapter()._context()

    def test_nonroot_adapter_and_duplicate_manifest_keys_refused(self):
        with mock.patch.object(t.os, 'getuid', return_value=1991), self.assertRaises(t.Rejected):
            t.Adapter()._context()
        files, manifest = self.source_fixture()
        for malformed in (b'{"schema":1,"schema":1}', b'null'):
            files[t.MANIFEST] = malformed
            with self.subTest(manifest=malformed), mock.patch.object(t.os, 'getuid', return_value=0), \
                 mock.patch.object(t.os, 'geteuid', return_value=0), \
                 mock.patch.object(t, 'SOURCE_PINS', manifest['source_sha256']), \
                 mock.patch.object(t, 'root_file', side_effect=lambda path, *a, **k: files[path]), self.assertRaises(t.Rejected):
                t.Adapter()._context()

    def test_distribution_python_symlink_is_allowed_only_with_a_root_owned_safe_target(self):
        link = types.SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
        for owner, mode in ((0, 0o755), (1991, 0o755), (0, 0o775)):
            target = types.SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=owner)
            with self.subTest(owner=owner, mode=mode), mock.patch.object(t, 'root_parents'), \
                 mock.patch.object(Path, 'lstat', return_value=link), \
                 mock.patch.object(Path, 'resolve', return_value=Path('/usr/bin/python3.12')), \
                 mock.patch.object(Path, 'stat', return_value=target):
                if owner == 0 and mode == 0o755:
                    self.assertEqual(t.executable('/usr/bin/python3'), '/usr/bin/python3')
                else:
                    with self.assertRaises(t.Rejected): t.executable('/usr/bin/python3')

    def test_missing_bootstrap_receipt_accepts_only_the_compiled_approved_legacy_pins(self):
        files, manifest = self.source_fixture()
        def read(path, *args, **kwargs):
            if path == t.MANIFEST: raise FileNotFoundError()
            return files[path]
        for approved in (True, False):
            adapter = t.Adapter()
            with self.subTest(approved=approved), mock.patch.object(t, 'root_file', side_effect=read), \
                 mock.patch.object(t, 'SOURCE_PINS', manifest['source_sha256']), \
                 mock.patch.object(t, 'APPROVED_CONFIG', CONFIG if approved else {**CONFIG, 'image_id': 'other'}), \
                 mock.patch.object(t.os, 'getuid', return_value=0), mock.patch.object(t.os, 'geteuid', return_value=0):
                if approved:
                    adapter._context()
                    self.assertEqual(adapter.installation_mode, 'approved_legacy')
                else:
                    with self.assertRaises(t.Rejected): adapter._context()

    def test_output_is_size_bounded_and_child_is_in_dedicated_process_group(self):
        with tempfile.TemporaryDirectory() as work:
            def spawn(argv, **kwargs):
                kwargs['stdout'].write(b'{"ok":true}')
                return mock.Mock(pid=123, wait=mock.Mock(return_value=0))
            with mock.patch.object(t, 'OUTPUT', Path(work)), mock.patch.object(t, 'root_parents'), \
                 mock.patch.object(t, 'operator_prefix', return_value=['fixed-runuser']), \
                 mock.patch.object(t, 'executable', side_effect=str), \
                 mock.patch.object(t.subprocess, 'Popen', side_effect=spawn) as popen:
                code, value = t.Adapter()._operator(['fixed-probe'], 15)
            self.assertEqual((code, value), (0, {'ok': True}))
            self.assertTrue(popen.call_args.kwargs['start_new_session'])
            self.assertEqual(popen.call_args.kwargs['stderr'], subprocess.DEVNULL)
            self.assertNotIn('shell', popen.call_args.kwargs)

    def test_oversized_or_malformed_output_is_refused(self):
        for raw in (b'x' * t.LIMIT, b'not-json', b'{"ok":true,"ok":false}'):
            with self.subTest(length=len(raw)), tempfile.TemporaryDirectory() as work:
                def spawn(argv, **kwargs):
                    kwargs['stdout'].write(raw)
                    return mock.Mock(pid=123, wait=mock.Mock(return_value=0))
                with mock.patch.object(t, 'OUTPUT', Path(work)), mock.patch.object(t, 'root_parents'), \
                     mock.patch.object(t, 'operator_prefix', return_value=[]), \
                     mock.patch.object(t, 'executable', side_effect=str), \
                     mock.patch.object(t.subprocess, 'Popen', side_effect=spawn), self.assertRaises(t.Rejected):
                    t.Adapter()._operator(['fixed-probe'], 15)

    def test_timed_out_probe_kills_only_its_own_host_process_group(self):
        process = mock.Mock(pid=4321)
        process.wait.side_effect = [subprocess.TimeoutExpired('fixed-probe', 15), 0]
        with tempfile.TemporaryDirectory() as work, mock.patch.object(t, 'OUTPUT', Path(work)), \
             mock.patch.object(t, 'root_parents'), mock.patch.object(t, 'operator_prefix', return_value=[]), \
             mock.patch.object(t, 'executable', side_effect=str), \
             mock.patch.object(t.subprocess, 'Popen', return_value=process), \
             mock.patch.object(t.os, 'killpg') as kill, self.assertRaises(t.Rejected):
            t.Adapter()._operator(['fixed-probe'], 15)
        kill.assert_called_once_with(4321, t.signal.SIGKILL)

    def test_cli_rejects_extra_commands(self):
        for argv in (['adapter'], ['adapter', 'shell'], ['adapter', 'check', 'id']):
            with self.subTest(argv=argv), mock.patch.object(t.sys, 'argv', argv), \
                 mock.patch.object(t, 'Adapter') as adapter, self.assertRaises(t.Rejected):
                t.main()
            adapter.assert_not_called()


class LockedStopTests(unittest.TestCase):
    def run_child(self, current_cid):
        with tempfile.TemporaryDirectory() as work:
            home = Path(work); state = home / '.local/state/capstone-sudo-lab'; state.mkdir(parents=True)
            runtime = mock.Mock()
            runtime.inventory.return_value = {'Id': current_cid}
            runtime.run.return_value = result('stopped')
            lab = types.SimpleNamespace(require=t.need, HASH=t.HEX, config_at=lambda *a: CONFIG,
                  trusted_parents=lambda *a: None, Lab=lambda *a: runtime, Docker=lambda *a: object())
            original_stat, original_fstat = Path.stat, t.os.fstat
            def metadata(path, *args, **kwargs):
                if path == state: return types.SimpleNamespace(st_uid=1991, st_mode=stat.S_IFDIR | 0o700)
                return original_stat(path, *args, **kwargs)
            def fstat(fd):
                m = original_fstat(fd)
                return types.SimpleNamespace(st_uid=1991, st_nlink=1, st_mode=stat.S_IFREG | 0o600,
                                             st_size=m.st_size)
            with mock.patch.object(importlib.util, 'spec_from_file_location'), \
                 mock.patch.object(importlib.util, 'module_from_spec', return_value=lab), \
                 mock.patch.object(t.os, 'getuid', return_value=1991), mock.patch.object(t.os, 'geteuid', return_value=1991), \
                 mock.patch.object(t.pwd, 'getpwuid', return_value=types.SimpleNamespace(pw_dir=str(home))), \
                 mock.patch.object(Path, 'stat', metadata), mock.patch.object(t.os, 'fstat', side_effect=fstat), \
                 mock.patch.object(sys, 'argv', ['-c', CID]), contextlib.redirect_stdout(io.StringIO()):
                try:
                    exec(compile(t.EXACT_STOP, '<fixed-exact-stop>', 'exec'), {})
                except t.Rejected:
                    self.assertNotEqual(current_cid, CID)
                else:
                    self.assertEqual(current_cid, CID)
            return runtime

    def test_same_owned_cid_is_stopped_under_the_operator_lock(self):
        runtime = self.run_child(CID)
        runtime.run.assert_called_once_with('stop')

    def test_replacement_after_parent_attestation_is_not_stopped(self):
        runtime = self.run_child(OTHER)
        runtime.run.assert_not_called()


class OperationBudgetTests(unittest.TestCase):
    def test_runtime_stop_and_nested_exact_stop_share_the_original_deadline(self):
        adapter = t.Adapter(); lab, publisher, config = context(); clock = [100.0]
        waits = []
        def receipt(*args):
            clock[0] = 120.0  # Twenty seconds already spent before exact stop.
            return {'container_id': CID}
        def check(cid):
            clock[0] = 135.0  # Its fresh ownership/root attestation consumes 15s.
        def spawn(argv, **kwargs):
            kwargs['stdout'].write(json.dumps(result('stopped')).encode())
            def wait(timeout):
                waits.append(timeout)
                clock[0] += 4.0
                return 0
            return mock.Mock(pid=123, wait=wait)
        with tempfile.TemporaryDirectory() as work, mock.patch.object(t, 'OUTPUT', Path(work)), \
             mock.patch.object(t.time, 'monotonic', side_effect=lambda: clock[0]), \
             mock.patch.object(adapter, '_context', return_value=(lab, publisher, config)), \
             mock.patch.object(adapter, '_receipt', side_effect=receipt), \
             mock.patch.object(adapter, '_stop_context', side_effect=check), \
             mock.patch.object(adapter, '_inspect', return_value={'State': {'Running': False}}), \
             mock.patch.object(t, 'root_parents'), mock.patch.object(t, 'operator_prefix', return_value=[]), \
             mock.patch.object(t, 'executable', side_effect=str), \
             mock.patch.object(t.subprocess, 'Popen', side_effect=spawn):
            self.assertEqual(adapter.runtime('stop')['status'], 'stopped')
        self.assertEqual(waits, [5.0])
        self.assertEqual(clock[0], 139.0)
        self.assertIsNone(adapter.deadline)

    def test_multiple_status_probes_consume_one_budget_and_expire_before_ready(self):
        adapter = t.Adapter(); lab, publisher, config = context(); clock = [100.0]
        waits, children = [], []
        responses = [result(), [{'image': True}], [{'State': {'Running': True}}], result()]
        durations = [12.0, 10.0, 10.0, 12.0]
        def spawn(argv, **kwargs):
            index = len(children)
            kwargs['stdout'].write(json.dumps(responses[index]).encode())
            process = mock.Mock(pid=500 + index)
            process.expired = False
            def wait(timeout):
                if process.expired: return 0  # Reaped after the group kill.
                waits.append(timeout)
                if durations[index] > timeout:
                    clock[0] += timeout
                    process.expired = True
                    raise subprocess.TimeoutExpired(argv, timeout)
                clock[0] += durations[index]
                return 0
            process.wait.side_effect = wait
            children.append(process)
            return process
        with tempfile.TemporaryDirectory() as work, mock.patch.object(t, 'OUTPUT', Path(work)), \
             mock.patch.object(t.time, 'monotonic', side_effect=lambda: clock[0]), \
             mock.patch.object(adapter, '_context', return_value=(lab, publisher, config)), \
             mock.patch.object(t, 'root_parents'), mock.patch.object(t, 'operator_prefix', return_value=[]), \
             mock.patch.object(t, 'executable', side_effect=str), \
             mock.patch.object(t.subprocess, 'Popen', side_effect=spawn), \
             mock.patch.object(t.os, 'killpg') as kill, self.assertRaises(t.Rejected):
            adapter.runtime('status')
        self.assertEqual(waits, [40.0, 15, 15, 8.0])
        self.assertEqual(clock[0], 140.0)
        self.assertEqual(len(children), 4)
        kill.assert_called_once_with(503, t.signal.SIGKILL)
        publisher.ready_contract.assert_not_called()
        lab.running_isolation.assert_not_called()
        self.assertIsNone(adapter.deadline)

    def test_expired_budget_does_not_spawn_another_probe(self):
        adapter = t.Adapter(); adapter.deadline = 100.0
        with tempfile.TemporaryDirectory() as work, mock.patch.object(t, 'OUTPUT', Path(work)), \
             mock.patch.object(t.time, 'monotonic', return_value=101.0), \
             mock.patch.object(t, 'root_parents'), mock.patch.object(t, 'operator_prefix', return_value=[]), \
             mock.patch.object(t, 'executable', side_effect=str), \
             mock.patch.object(t.subprocess, 'Popen') as popen, self.assertRaises(t.Rejected):
            adapter._operator(['fixed-probe'], 15)
        popen.assert_not_called()


if __name__ == '__main__':
    unittest.main()
