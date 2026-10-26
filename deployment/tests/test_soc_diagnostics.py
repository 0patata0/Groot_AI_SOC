"""Readonly diagnostic deployment contracts with fake I/O; no host mutations."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

DEPLOYMENT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DEPLOYMENT))
import soc_diagnostics as d

HOSTS = {'SECURITY_HOST': '10.42.0.1', 'SIEM_HOST': '10.42.0.10', 'SERVICE_HOST': '10.42.0.20'}
KEY = 'ssh-ed25519 ' + base64.b64encode(b'\0\0\0\x0bssh-ed25519\0\0\0\x20' + b'x' * 32).decode()


def settings(port=22):
    return {'schema': 1, 'source': Path('/approved/source'), 'hosts': dict(HOSTS), 'ssh_port': port}


def identities():
    return [{'schema': 1, 'status': 'ready', 'role': role, 'host': d.ROLE_HOST[role],
             'address': HOSTS[d.HOST_ENV[role]], 'ssh_host_ed25519': KEY}
            for role in ('security', 'service')]


def hc():
    tools = ['mcp-' + name for name in ('wazuh-ro', 'security-events', 'rule-a', 'rule-b', 'resp')]
    return {'mcp_servers': {name: {'existing': True} for name in ('wazuh-ro', 'security-events', 'rule-a', 'rule-b', 'resp')},
            'toolsets': list(tools), 'platform_toolsets': {'mattermost': list(tools), 'cli': list(tools)},
            'security': {'allow_lazy_installs': False}}


class Profiles(unittest.TestCase):
    def test_private_distinct_hosts_and_custom_ssh_port(self):
        env = {**HOSTS, 'CAPSTONE_SOURCE': '/approved/source', 'SSH_PORT': '2222'}
        self.assertEqual(d.settings(env), settings(2222))
        for change in ({'SECURITY_HOST': '8.8.8.8'}, {'SERVICE_HOST': HOSTS['SIEM_HOST']},
                       {'SSH_PORT': '0'}, {'SSH_PORT': '65536'}, {'CAPSTONE_ROOT': '/tmp/root'},
                       {'CAPSTONE_SOURCE': 'relative'}):
            with self.subTest(change=change), self.assertRaises((ValueError, KeyError)):
                d.settings({**env, **change})

    def test_source_bundle_includes_exact_runtime_sources_and_installer(self):
        source = {name: b'# fixture\n' for name in d.SOURCES}
        def read(path, *args, **kwargs):
            return b'# installer\n' if str(path).endswith('/deployment/soc_diagnostics.py') else source[Path(path).name]
        with mock.patch.object(d.common, 'read', side_effect=read):
            bundle = d.source_bundle(settings())
        self.assertEqual(set(bundle), set(d.SOURCES) | {'soc_diagnostics.py'})
        source['system_diagnostics.py'] = b'def invalid(:\n'
        with mock.patch.object(d.common, 'read', side_effect=read), self.assertRaises(SyntaxError):
            d.source_bundle(settings())

    def test_profile_binds_machine_role_hosts_and_sources(self):
        with mock.patch.object(d.common, 'read', return_value=('a' * 32 + '\n').encode()), \
             mock.patch.object(d, 'source_bundle', return_value={'fixed.py': b'fixed'}):
            value = d.profile(settings(), 'service')
        self.assertEqual(value['host'], 'c')
        self.assertEqual(value['machine_id'], 'a' * 32)
        self.assertEqual(value['source_sha256'], {'fixed.py': d.common.digest(b'fixed')})
        with mock.patch.object(d.common, 'read', return_value=b'wrong'), self.assertRaises(ValueError):
            d.profile(settings(), 'service')

    def test_units_collect_only_the_fixed_role_and_write_only_snapshot_state(self):
        for role in d.ROLE_HOST:
            docs = d.unit_documents(role)
            self.assertEqual(set(docs), {d.SERVICE, d.TIMER})
            service, timer = docs[d.SERVICE].decode(), docs[d.TIMER].decode()
            self.assertIn('--collect --role ' + role + '\n', service)
            self.assertIn('ReadWritePaths=/var/lib/capstone-diagnostics\n', service)
            self.assertIn('NoNewPrivileges=yes', service)
            self.assertIn('ProtectSystem=strict', service)
            self.assertIn('TimeoutStartSec=85', service)
            self.assertIn('TimeoutStopSec=5', service)
            self.assertIn('OnUnitActiveSec=60s', timer)
            for forbidden in ('sudo ', 'docker ', 'journalctl ', 'SSH', '/etc/sudoers'):
                self.assertNotIn(forbidden, service)
        with self.assertRaises(ValueError): d.unit_documents('service;id')

    def test_check_never_installs_or_starts_services(self):
        with mock.patch.object(d, 'source_bundle'), mock.patch.object(d.sys, 'platform', 'linux'), \
             mock.patch.object(d.os, 'geteuid', return_value=0), \
             mock.patch.object(d.common, 'read', return_value=KEY.encode()), \
             mock.patch.object(Path, 'is_file', return_value=True), \
             mock.patch.object(Path, 'exists', return_value=False), \
             mock.patch.object(Path, 'is_symlink', return_value=False), \
             mock.patch.object(d.os.path, 'lexists', return_value=False), \
             mock.patch.object(d, 'account_absent'), mock.patch.object(d.common, 'run') as run:
            self.assertEqual(d.check(settings(), 'service')['files_written'], 0)
        run.assert_not_called()


class PublicTransport(unittest.TestCase):
    def stream(self):
        return {'schema': 1, 'hosts': dict(HOSTS), 'ssh_port': 22, 'reader_public_key': KEY}

    def test_export_stream_contains_a_public_key_only(self):
        value = self.stream()
        self.assertEqual(d.public_stream(settings(), json.dumps(value).encode()), KEY)
        for change in ({'private_key': 'secret'}, {'schema': True}, {'hosts': {}}, {'ssh_port': True},
                       {'reader_public_key': 'ssh-rsa wrong'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                d.public_stream(settings(), json.dumps({**value, **change}).encode())
        with self.assertRaises(ValueError): d.public_stream(settings(), b'x' * 16385)

    def test_host_keys_are_controller_received_and_pinned_for_custom_ports(self):
        config, known = d.transport_config(settings(2222), identities())
        self.assertEqual(config, {'schema': 1, 'hosts': {'a': HOSTS['SECURITY_HOST'], 'c': HOSTS['SERVICE_HOST']}, 'ssh_port': 2222})
        self.assertIn(('[10.42.0.1]:2222 ' + KEY).encode(), known)
        self.assertIn(('[10.42.0.20]:2222 ' + KEY).encode(), known)
        self.assertNotIn(b'known_hosts', known)

    def test_foreign_duplicate_or_forged_host_receipts_refused(self):
        for row in ([identities()[0]] * 2, identities()[:1],
                    [dict(identities()[0], address='10.42.0.99'), identities()[1]],
                    [dict(identities()[0], ssh_host_ed25519='ssh-rsa wrong'), identities()[1]],
                    [dict(identities()[0], role='service'), identities()[1]]):
            with self.subTest(row=row), self.assertRaises(ValueError):
                d.transport_config(settings(), row)

    def test_ssh_has_fixed_reader_identity_and_no_remote_command(self):
        argv = d.ssh_argv(settings(2222), 'a')
        self.assertEqual(argv[:6], ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-p', '2222'])
        self.assertEqual(argv[-1], 'capstone-diagnostics@10.42.0.1')
        self.assertIn('StrictHostKeyChecking=yes', argv)
        self.assertIn('IdentitiesOnly=yes', argv)
        self.assertIn(str(d.KEYDIR / 'id_ed25519'), argv)
        self.assertNotIn('sudo', argv)
        for host in ('b', '10.42.0.1', 'a;id'):
            with self.subTest(host=host), self.assertRaises(ValueError): d.ssh_argv(settings(), host)

    def test_reader_account_is_forced_without_sudo_or_shell_arguments(self):
        calls = []
        with mock.patch.object(Path, 'exists', return_value=False), \
             mock.patch.object(d, 'install_common', return_value=997), \
             mock.patch.object(d, 'source_bundle', return_value={'read-system-diagnostics.py': b'#reader'}), \
             mock.patch.object(d.common, 'run'), mock.patch.object(d.common, 'mkdir'), \
             mock.patch.object(d.common, 'write', side_effect=lambda path, raw, *a: calls.append((str(path), raw))), \
             mock.patch.object(d, 'profile', return_value={'fixed': True}), \
             mock.patch.object(d, 'installed_record', return_value={'sha256': 'f' * 64}), \
             mock.patch.object(d, 'verify_ssh_policy'), \
             mock.patch.object(d, 'verify'), mock.patch.object(d, 'reader_public', return_value={'status': 'ready'}):
            d.apply_reader(settings(), 'service', json.dumps(self.stream()).encode())
        keys = next(raw for path, raw in calls if path.endswith('/authorized_keys')).decode()
        self.assertIn('from="10.42.0.10",restrict,command="/opt/capstone-diagnostics/read-snapshot"', keys)
        sshd = next(raw for path, raw in calls if path.endswith('63-capstone-diagnostics.conf')).decode()
        self.assertIn('DisableForwarding yes', sshd)
        self.assertIn('PermitTTY no', sshd)
        self.assertIn('PasswordAuthentication no', sshd)
        self.assertIn('PubkeyAuthentication yes', sshd)
        self.assertNotIn('PermitUserEnvironment', sshd)
        wrapper = next(raw for path, raw in calls if path.endswith('/read-snapshot')).decode()
        self.assertIn('SSH_ORIGINAL_COMMAND', wrapper)
        self.assertIn('exec /usr/bin/env -i', wrapper)
        self.assertFalse(any('sudoers' in path for path, _ in calls))

    def test_effective_ssh_policy_requires_publickey_only_and_global_user_environment_disabled(self):
        values = {'pubkeyauthentication': 'yes', 'authenticationmethods': 'publickey',
                  'passwordauthentication': 'no', 'kbdinteractiveauthentication': 'no',
                  'disableforwarding': 'yes', 'permittty': 'no', 'x11forwarding': 'no',
                  'permituserrc': 'no', 'permituserenvironment': 'no', 'usepam': 'yes',
                  'forcecommand': '/opt/capstone-diagnostics/read-snapshot'}
        raw = lambda mapping: ''.join(key + ' ' + value + '\n' for key, value in mapping.items()).encode()
        with mock.patch.object(d.common, 'run', return_value=raw(values)):
            d.verify_ssh_policy(settings(), 'service')
        for key, value in [('permituserenvironment', 'yes'), ('passwordauthentication', 'yes'),
                           ('forcecommand', '/bin/sh'), ('pubkeyauthentication', 'no')]:
            with self.subTest(key=key), mock.patch.object(d.common, 'run', return_value=raw({**values, key: value})), \
                 self.assertRaises(ValueError):
                d.verify_ssh_policy(settings(), 'service')

    def test_changed_key_or_partial_reader_cannot_be_silently_adopted(self):
        with mock.patch.object(Path, 'exists', return_value=True), \
             mock.patch.object(d.common, 'read', return_value=json.dumps({'reader_public_key': 'other'}).encode()), \
             mock.patch.object(d, 'install_common') as install, self.assertRaises(ValueError):
            d.apply_reader(settings(), 'service', json.dumps(self.stream()).encode())
        install.assert_not_called()


class HermesAndBounds(unittest.TestCase):
    def test_adds_only_one_readonly_mcp_to_both_platforms_and_management_data(self):
        before = hc(); result = d.hermes_configuration(before)
        self.assertEqual(set(result['mcp_servers']), set(before['mcp_servers']) | {'system-diagnostics'})
        entry = result['mcp_servers']['system-diagnostics']
        self.assertEqual(entry['args'][-2:], ['siem-readonly', 'system-diagnostics'])
        self.assertFalse(entry['tools']['resources'])
        self.assertFalse(entry['tools']['prompts'])
        for tools in [result['toolsets'], *result['platform_toolsets'].values()]:
            self.assertEqual(tools[-1], 'mcp-system-diagnostics')
            self.assertNotIn('terminal', tools)
        self.assertEqual(before, hc())

    def test_unexpected_or_already_extended_hermes_configuration_refused(self):
        for value in ({}, {'mcp_servers': {}}, d.hermes_configuration(hc()), {**hc(), 'platform_toolsets': {}}):
            with self.subTest(value=value), self.assertRaises(ValueError): d.hermes_configuration(value)

    def test_reader_subprocess_is_bounded_and_has_no_inherited_environment(self):
        with tempfile.TemporaryDirectory() as work:
            def spawn(argv, **kwargs):
                kwargs['stdout'].write(b'{"schema":1}')
                return mock.Mock(pid=4000, wait=mock.Mock(return_value=0))
            with mock.patch.object(d, 'PRIVATE', Path(work)), mock.patch.object(d.subprocess, 'Popen', side_effect=spawn) as popen:
                self.assertEqual(d.bounded_reader(['fixed-reader']), b'{"schema":1}')
            self.assertEqual(popen.call_args.args[0][:5], ['/usr/sbin/runuser', '-u', 'capstone-mcp', '--', '/usr/bin/env'])
            self.assertIn('--fsize=131073:131073', popen.call_args.args[0])
            self.assertTrue(popen.call_args.kwargs['start_new_session'])
            self.assertNotIn('shell', popen.call_args.kwargs)
        with self.assertRaises(ValueError): d.bounded_reader(['fixed-reader'], 'root')

    def test_only_two_reviewed_nonroot_mcp_installation_bindings_are_allowed(self):
        for value in ('capstone-mcp', 'mcp'):
            with self.subTest(account=value), mock.patch.object(d, 'MCP_USER', value):
                self.assertEqual(d.mcp_account(), value)
        for value in ('root', 'ubuntu', 'mcp;id'):
            with self.subTest(account=value), mock.patch.object(d, 'MCP_USER', value), self.assertRaises(ValueError):
                d.mcp_account()

    def test_timeout_kills_only_the_reader_process_group(self):
        child = mock.Mock(pid=4000)
        child.wait.side_effect = [subprocess.TimeoutExpired('fixed-reader', 40), 0]
        with tempfile.TemporaryDirectory() as work, mock.patch.object(d, 'PRIVATE', Path(work)), \
             mock.patch.object(d.subprocess, 'Popen', return_value=child), \
             mock.patch.object(d.os, 'killpg') as kill, self.assertRaises(ValueError):
            d.bounded_reader(['fixed-reader'])
        kill.assert_called_once_with(4000, d.signal.SIGKILL)

    def test_source_or_profile_drift_blocks_verification_before_a_service_call(self):
        with mock.patch.object(d.common, 'read', return_value=json.dumps({'profile': {'old': True}}).encode()), \
             mock.patch.object(d, 'profile', return_value={'new': True}), \
             mock.patch.object(d.common, 'run') as run, self.assertRaises(ValueError):
            d.verify(settings(), 'service')
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
