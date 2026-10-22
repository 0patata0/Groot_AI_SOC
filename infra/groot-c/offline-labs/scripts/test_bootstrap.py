"""Preflight fixture tests: no host service, network, packages or Docker used."""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import bootstrap as b


class FixtureHost(b.Host):
    def __init__(self, root):
        self.root = root
        self.calls = []
        self.accounts = False
        self.unit = 'not-found'
        self.networks = ''
        self.tables = {'nftables': []}
        self.container = None
        self.image = {'Id': 'sha256:' + 'a' * 64, 'Os': 'linux', 'Architecture': 'amd64', 'Config': {}}
        self.version = '29.8.1'

    def path(self, value):
        return self.root / str(value).lstrip('/')

    def account_exists(self):
        return self.accounts

    def check_platform(self):
        pass

    def tool(self, name):
        return ('/usr/sbin/' if name in ('nft', 'useradd', 'nologin') else '/usr/bin/') + name

    def run(self, args, input=None):
        self.calls.append((list(args), input))
        command = Path(args[0]).name
        if command == 'systemctl':
            assert args[1:4] == ['show', '--property=LoadState', '--value']
            return self.unit
        if command == 'nft':
            if args[1:] == ['-j', 'list', 'tables']:
                return json.dumps(self.tables)
            assert args[1:] == ['--check', '-f', '-'] and input == b.RULES
            return ''
        assert args[1:3] == ['--host', 'unix:///var/run/docker.sock']
        action = args[3:]
        if action[0] == 'info':
            return json.dumps({'version': self.version, 'os': 'linux', 'arch': 'x86_64', 'security': []})
        if action[:2] == ['network', 'ls']:
            return self.networks
        if action[:2] == ['container', 'ls']:
            return 'b' * 64 if self.container else ''
        if action[:2] == ['container', 'inspect']:
            return json.dumps(self.container)
        if action[:2] == ['image', 'inspect']:
            return json.dumps([self.image])
        raise AssertionError('unexpected or mutating command: ' + repr(args))


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / 'source'; self.source.mkdir()
        self.wheels = self.root / 'wheels'; self.wheels.mkdir()
        self.host = FixtureHost(self.root / 'host')
        for name in ('/opt', '/etc/systemd/system', '/var/lib', '/run', '/proc/net'):
            self.host.path(name).mkdir(parents=True, exist_ok=True)
        for name in ('tcp', 'tcp6'):
            self.host.path('/proc/net/' + name).write_text('sl local_address rem_address st\n')
        self.catalog = [{'cve_id': 'CVE-2021-44228', 'software': 'fixture', 'vulnerable_version': '1',
                         'image_tag': 'fixture/lab:1', 'image_id': 'sha256:' + 'a' * 64,
                         'host_port': 18081, 'container_port': 8080},
                        {'cve_id': 'CVE-2021-3156', 'type': 'local-cli', 'software': 'sudo', 'vulnerable_version': '1'}]
        (self.source / 'cve_list.json').write_text(json.dumps(self.catalog))
        for name in ('app.py', 'broker.py', 'guard.py', 'manifest.py', 'practice_mode.py', 'challenge.py',
                     'static/index.html', 'static/app.js', 'static/app.css', 'static/theme.js', 'static/theme.css'):
            target = self.source / name; target.parent.mkdir(exist_ok=True); target.write_text('fixture')
        for name in b.UNITS:
            target = self.source / 'scripts/bootstrap-units' / name
            target.parent.mkdir(parents=True, exist_ok=True); target.write_text('[Service]\n')
        self.make_wheel({'module.py': b'# fixture\n'})
        self.args = argparse.Namespace(origin=None, manifest=None, admin_key_file=None, wheel_directory=str(self.wheels))
        self.source_patch = patch.object(b, 'SOURCE', self.source); self.source_patch.start()
        self.addCleanup(self.source_patch.stop)
        # Host-owned directory checks are tested separately; this fixture runs
        # as the normal developer account and never touches actual root paths.
        self.owner_patch = patch.object(b, 'root_directory'); self.owner_patch.start()
        self.addCleanup(self.owner_patch.stop)

    def make_wheel(self, contents):
        path = self.wheels / 'fixture-1-py3-none-any.whl'
        with zipfile.ZipFile(path, 'w') as archive:
            for name, data in contents.items():
                archive.writestr(name, data)
        raw = path.read_bytes()
        (self.source / 'wheel-inventory.json').write_text(json.dumps([
            {'file': path.name, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}]))

    def check(self):
        return b.preflight(self.args, self.host)

    def test_read_only_success_pins_local_image_and_defaults_loopback(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        plan = self.check()
        after = {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(b.summary(plan)['origins'], list(b.LOOPBACK_ORIGINS))
        self.assertEqual(b.summary(plan)['managed_images_checked'], 1)
        self.assertIn('static/theme.js', plan['source'])
        self.assertIn('module.py', plan['wheels'])
        self.assertTrue(self.host.calls)

    def test_origin_accepts_only_https_authority_and_no_shell_or_url_credentials(self):
        self.args.origin = 'https://training.example.test:8443'
        self.assertEqual(b.summary(self.check())['origins'][0], self.args.origin)
        for value in ('http://training.example.test', 'https://user:secret@x.test', 'https://x.test/',
                      'https://x.test/path', 'https://x.test?x=1', 'https://x.test#x',
                      'https://x.test\nENV=x', 'https://x.test:99999', 'https://x..test', 'https://x.test,$()'):
            with self.subTest(value=value), self.assertRaises(b.Failure):
                b.public_origin(value)

    def test_all_conflicts_fail_before_apply(self):
        for name in (b.TARGET, b.CONFIG, b.STATE / 'runtime.json', b.STATE / 'broker.lock',
                     b.STATE / 'install-state.json', b.STATE / 'nonweb-status.json', '/run/capstone-offline-labs'):
            path = self.host.path(name); path.parent.mkdir(parents=True, exist_ok=True); path.touch()
            with self.subTest(name=str(name)), self.assertRaisesRegex(b.Failure, 'conflict'):
                self.check()
            path.unlink()
        self.host.accounts = True
        with self.assertRaisesRegex(b.Failure, 'account_or_group_conflict'):
            self.check()

    def test_unit_network_nft_and_image_conflicts(self):
        mutations = [('unit', 'loaded'), ('networks', 'bridge\noffline-labs\n'),
                     ('tables', {'nftables': [{'table': {'family': 'inet', 'name': 'capstone_offline_labs'}}]}),
                     ('version', '27.5.1'), ('image', {**self.host.image, 'Id': 'sha256:' + 'b' * 64}),
                     ('image', {**self.host.image, 'Config': {'Volumes': {'/data': {}}}})]
        for name, value in mutations:
            original = getattr(self.host, name); setattr(self.host, name, value)
            with self.subTest(name=name), self.assertRaises(b.Failure):
                self.check()
            setattr(self.host, name, original)

    def test_listener_and_docker_published_ports_and_names_are_checked(self):
        self.host.path('/proc/net/tcp').write_text('header\n0: 00000000:46A1 00000000:0000 0A\n')
        with self.assertRaisesRegex(b.Failure, 'listening_port_conflict'):
            self.check()
        self.host.path('/proc/net/tcp').write_text('header\n')
        for container in ({'name': '/foreign', 'ports': {'8080/tcp': [{'HostPort': '18081'}]}},
                          {'name': '/offline-lab-cve-2021-44228', 'ports': {}}):
            self.host.container = container
            with self.assertRaisesRegex(b.Failure, 'conflict'):
                self.check()

    def test_source_nested_symlinks_and_missing_theme_rejected(self):
        link = self.source / 'static/link'; link.symlink_to(self.root)
        with self.assertRaisesRegex(b.Failure, 'source_symlink'):
            self.check()
        link.unlink(); (self.source / 'static/theme.js').unlink()
        with self.assertRaisesRegex(b.Failure, 'required_source_missing'):
            self.check()

    def test_independent_nonweb_source_is_not_installed(self):
        target = self.source / 'nonweb/sudo/lab.py'
        target.parent.mkdir(parents=True)
        target.write_text('rootless installer owns this')
        self.assertNotIn('nonweb/sudo/lab.py', self.check()['source'])
        (target.parent / 'symlink').symlink_to(self.root)
        with self.assertRaisesRegex(b.Failure, 'source_symlink'):
            self.check()

    def test_manifest_duplicate_keys_extra_keys_and_console_port_rejected(self):
        manifest = self.source / 'cve_list.json'
        for value in ('[{"cve_id":"CVE-2021-44228","cve_id":"CVE-2021-44228"}]',
                      json.dumps([{**self.catalog[0], 'host_port': 18090}]),
                      json.dumps([{**self.catalog[0], 'command': 'shell'}])):
            manifest.write_text(value)
            with self.assertRaises(ValueError):
                self.check()

    def test_wheel_hash_traversal_symlink_and_overlap_are_preflight_errors(self):
        path = self.wheels / 'fixture-1-py3-none-any.whl'
        path.write_bytes(path.read_bytes() + b'tamper')
        with self.assertRaisesRegex(b.Failure, 'wheel_size'):
            self.check()
        for contents in ({'../escaped.py': b'x'}, {'a': b'file', 'a/b.py': b'x'},
                         {'unsafe.data/purelib/a.py': b'x'}):
            self.make_wheel(contents)
            with self.assertRaises(b.Failure):
                self.check()
        link = zipfile.ZipInfo('module.py'); link.external_attr = 0o120777 << 16
        self.make_wheel({link: b'outside'})
        with self.assertRaisesRegex(b.Failure, 'unsafe_wheel_entry'):
            self.check()

    def test_private_key_mode_and_content_are_not_printed(self):
        path = self.root / 'key'; path.write_bytes(b'test-private-key\n'); path.chmod(0o600)
        actual = path.stat()
        fake = type('Stat', (), {'st_uid': 0, 'st_gid': 0, 'st_mode': 0o100600, 'st_size': actual.st_size})()
        with patch.object(b, 'regular', return_value=fake):
            self.assertEqual(b.key_bytes(path), b'test-private-key\n')
            fake.st_mode = 0o100644
            with self.assertRaisesRegex(b.Failure, 'private_root_key'):
                b.key_bytes(path)
        plan = self.check(); plan['key'] = b'test-private-key\n'
        self.assertNotIn('test-private-key', json.dumps(b.summary(plan)))

    def test_main_check_never_calls_apply_and_failure_reports_code_only(self):
        with patch.object(b, 'preflight', return_value=self.check()), patch.object(b, 'apply') as apply:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(b.main(['--check', str(self.wheels)]), 0)
            self.assertTrue(json.loads(output.getvalue())['read_only'])
            apply.assert_not_called()
        with patch.object(b, 'preflight', side_effect=OSError('secret fixture input')), patch.object(b, 'apply') as apply:
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                self.assertEqual(b.main(['--apply', str(self.wheels)]), 1)
            self.assertNotIn('secret fixture input', output.getvalue())
            apply.assert_not_called()

    def test_apply_failure_preserves_partial_state_and_stops_commands(self):
        plan = self.check()
        state = self.root / 'state'
        host = FixtureHost(self.root / 'host')
        def failed(args, input=None):
            host.calls.append(args)
            raise b.Failure('fixture_useradd_failure')
        host.run = failed
        with patch.object(b, 'STATE', state), patch.object(b.os, 'fchown'), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(b.Failure):
                b.apply(plan, host)
        recorded = json.loads((state / 'install-state.json').read_text())
        self.assertEqual(recorded['status'], 'failed_partial')
        self.assertEqual(recorded['stage'], 'create_account')
        self.assertEqual(len(host.calls), 1)
        self.assertFalse(recorded['automatic_cleanup'])

    def test_concurrent_install_receipt_is_never_overwritten(self):
        plan = self.check()
        state = self.root / 'state'; state.mkdir()
        receipt = state / 'install-state.json'; receipt.write_bytes(b'other installer owns this')
        with patch.object(b, 'STATE', state), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(FileExistsError):
                b.apply(plan, self.host)
        self.assertEqual(receipt.read_bytes(), b'other installer owns this')

    def test_success_receipt_covers_source_vendor_units_and_selected_manifest_without_key(self):
        plan = self.check()
        # An explicit selected manifest must replace the source catalog in both
        # installation locations, while its original input tree is untouched.
        plan['manifest'] = json.dumps([self.catalog[0]]).encode()
        plan['labs'] = [plan['labs'][0]]
        plan['key'] = b'private-fixture-key\n'
        target, config, state, units = [self.root / name for name in ('installed', 'config', 'state', 'units')]
        def response(url, **kwargs):
            data = plan['manifest'] if url.endswith('/api/list') else json.dumps({
                'deployment_allowed': True, 'safety_error': None, 'labs': plan['labs']}).encode()
            return io.BytesIO(data)
        opener = SimpleNamespace(open=response)
        original = (self.source / 'cve_list.json').read_bytes()
        with patch.object(b, 'TARGET', target), patch.object(b, 'CONFIG', config), \
             patch.object(b, 'STATE', state), patch.object(b, 'UNIT_DIRECTORY', units), \
             patch.object(b.os, 'fchown'), patch.object(b.os, 'chown'), \
             patch.object(b.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=991, pw_gid=991)), \
             patch.object(b.urllib.request, 'build_opener', return_value=opener), \
             patch.object(self.host, 'run', side_effect=lambda args, **kw: 'active\n' * len(b.UNITS) if args[1] == 'is-active' else ''):
            result = b.apply(plan, self.host)
        receipt = json.loads((state / 'install-state.json').read_text())
        self.assertTrue(result['ok'])
        self.assertEqual((receipt['schema'], receipt['status'], receipt['stage']), (1, 'installed', 'complete'))
        for name, expected in receipt['files'].items():
            path = Path(name)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected['sha256'])
            self.assertEqual(format(path.stat().st_mode & 0o777, '04o'), expected['mode'])
        for name in ('static/theme.js', 'static/theme.css', 'vendor/module.py'):
            self.assertIn(str(target / name), receipt['files'])
        for name in b.UNITS:
            self.assertIn(str(units / name), receipt['files'])
        self.assertEqual((target / 'cve_list.json').read_bytes(), plan['manifest'])
        self.assertEqual((config / 'cve_list.json').read_bytes(), plan['manifest'])
        self.assertEqual((self.source / 'cve_list.json').read_bytes(), original)
        self.assertEqual((config / 'admin-token').read_bytes(), plan['key'])
        self.assertNotIn(str(config / 'admin-token'), receipt['files'])
        self.assertNotIn('private-fixture-key', json.dumps(receipt) + json.dumps(result))


if __name__ == '__main__':
    unittest.main()
