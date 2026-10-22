import copy
import importlib.util
import json
import lzma
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location('sudo_' + name, BASE / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


lab, prepare = module('lab'), module('prepare')
publisher = module('publish')
CONFIG = {'schema': 1, 'operator_uid': 1001, 'image_id': 'sha256:' + 'a' * 64,
          'deb_sha256': 'b' * 64, 'preparation_sha256': 'c' * 64}
CID = 'd' * 64
INFO = {'SecurityOptions': ['name=rootless', 'name=seccomp,profile=builtin'],
        'CgroupVersion': '2', 'CgroupDriver': 'systemd', 'OSType': 'linux', 'Architecture': 'x86_64'}


def image_fixture():
    return {'Id': CONFIG['image_id'], 'Os': 'linux', 'Architecture': 'amd64',
            'Config': {'User': '1000:1000', 'Entrypoint': ['/usr/bin/sleep'], 'Cmd': ['infinity'],
                       'WorkingDir': '/tmp', 'Env': lab.ENV, 'Labels': lab.expected_labels(CONFIG)}}


def container_fixture():
    config = copy.deepcopy(image_fixture()['Config'])
    config['Healthcheck'] = {'Test': ['NONE']}
    return {'Id': CID, 'Name': '/' + lab.NAME, 'Image': CONFIG['image_id'], 'Config': config,
            'AppArmorProfile': 'unconfined',
            'State': {'Running': True, 'Pid': 1234}, 'NetworkSettings': {'Networks': {'none': {}}},
            'Mounts': [], 'HostConfig': {
                'ReadonlyRootfs': True, 'Privileged': False, 'PublishAllPorts': False,
                'NetworkMode': 'none', 'IpcMode': 'private', 'CgroupnsMode': 'private',
                'Memory': lab.MEMORY, 'MemorySwap': lab.MEMORY, 'NanoCpus': 500000000, 'PidsLimit': 64,
                'CapDrop': ['ALL'], 'CapAdd': ['SETUID', 'SETGID'],
                'SecurityOpt': ['no-new-privileges=false', 'apparmor=unconfined'], 'Tmpfs': lab.TMPFS,
                'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0},
                'LogConfig': {'Type': 'json-file', 'Config': {'max-size': '1m', 'max-file': '2'}}}}


class Contracts(unittest.TestCase):
    def test_only_root_owned_fixed_docker_paths_are_selected(self):
        regular = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_nlink=1)
        with patch.object(lab.Path, 'lstat', return_value=regular), \
             patch.object(lab, 'trusted_parents') as parents, \
             patch.object(lab.os, 'access', return_value=True):
            self.assertEqual(lab.docker_binary(), '/usr/local/bin/docker')
            parents.assert_called_once_with(Path('/usr/local/bin'), {0})
        with patch.object(lab.Path, 'lstat', side_effect=[FileNotFoundError(), regular]), \
             patch.object(lab, 'trusted_parents'), patch.object(lab.os, 'access', return_value=True):
            self.assertEqual(lab.docker_binary(), '/usr/bin/docker')
        for changes in [{'st_uid': 1001}, {'st_mode': stat.S_IFREG | 0o775},
                        {'st_mode': stat.S_IFLNK | 0o777}, {'st_mode': stat.S_IFREG | 0o644},
                        {'st_nlink': 2}]:
            changed = types.SimpleNamespace(**dict(vars(regular), **changes))
            with self.subTest(changes=changes), patch.object(lab.Path, 'lstat', return_value=changed), \
                 patch.object(lab, 'trusted_parents'), patch.object(lab.os, 'access', return_value=True), \
                 self.assertRaises(lab.Rejected):
                lab.docker_binary()
        with patch.object(lab.Path, 'lstat', side_effect=FileNotFoundError()), self.assertRaises(lab.Rejected):
            lab.docker_binary()
        with patch.object(lab.Path, 'lstat', return_value=regular), \
             patch.object(lab, 'trusted_parents', side_effect=lab.Rejected('unsafe_parent_directory')), \
             self.assertRaises(lab.Rejected):
            lab.docker_binary()

    def test_rootless_and_enforced_resource_prerequisites(self):
        lab.daemon_contract(INFO)
        for key, value in [('SecurityOptions', ['name=seccomp,profile=builtin']),
                           ('SecurityOptions', ['name=rootless']), ('CgroupVersion', '1'),
                           ('SecurityOptions', ['name=rootless', 'name=seccomp,profile=custom']),
                           ('CgroupDriver', 'none'), ('Architecture', 'aarch64')]:
            changed = dict(INFO, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(lab.Rejected):
                lab.daemon_contract(changed)

    def test_stop_can_bypass_broken_resource_delegation_only(self):
        lab.daemon_contract(dict(INFO, CgroupDriver='none'), resources=False)
        with self.assertRaises(lab.Rejected):
            lab.daemon_contract(dict(INFO, SecurityOptions=[]), resources=False)

    def test_pinned_provenance_and_image_contract(self):
        lab.image_contract(image_fixture(), CONFIG)
        for path, value in [(('Id',), 'sha256:' + 'f' * 64), (('Config', 'User'), '0'),
                            (('Config', 'Volumes'), {'/host': {}}),
                            (('Config', 'OnBuild'), ['RUN whoami']),
                            (('Config', 'Labels'), {})]:
            changed = copy.deepcopy(image_fixture())
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(lab.Rejected):
                lab.image_contract(changed, CONFIG)

    def test_runtime_rejects_host_access_and_changed_policy(self):
        lab.container_contract(container_fixture(), CONFIG, CID)
        canonical = container_fixture()
        canonical['HostConfig']['CapAdd'] = ['CAP_SETUID', 'CAP_SETGID']
        canonical['AppArmorProfile'] = ''
        lab.container_contract(canonical, CONFIG, CID)
        changes = {'Privileged': True, 'Binds': ['/etc:/host'], 'Devices': [{'PathOnHost': '/dev/sda'}],
                   'PortBindings': {'80/tcp': [{'HostPort': '80'}]}, 'NetworkMode': 'host',
                   'PidMode': 'host', 'UsernsMode': 'host', 'CapAdd': ['SYS_ADMIN'],
                   'SecurityOpt': ['seccomp=unconfined'], 'Memory': 0, 'PidsLimit': -1,
                   'ReadonlyRootfs': False, 'Sysctls': {'kernel.example': '1'}}
        for key, value in changes.items():
            changed = container_fixture()
            changed['HostConfig'][key] = value
            with self.subTest(key=key), self.assertRaises(lab.Rejected):
                lab.container_contract(changed, CONFIG, CID)

    def test_uid_zero_is_never_host_root(self):
        self.assertEqual(lab.zero_mapping('0 1001 1\n1 100000 65536\n'), 1001)
        for value in ['0 0 4294967295', '0 -1 100', '1 100000 65536', '0 1000 1\n0 2000 1',
                      '0 1001 1\n1 0 1', '0 1001 1\n1 1001 65536',
                      '0 1001 2\n1 100000 65536', '0 4294967295 2']:
            with self.subTest(value=value), self.assertRaises(lab.Rejected):
                lab.zero_mapping(value)

    def test_actual_cgroup_limits(self):
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            for name, value in {'memory.max': str(lab.MEMORY), 'memory.swap.max': '0',
                                'pids.max': '64', 'cpu.max': '50000 100000'}.items():
                (work / name).write_text(value)
            lab.cgroup_contract(work)
            (work / 'cpu.max').write_text('max 100000')
            with self.assertRaises(ValueError):
                lab.cgroup_contract(work)

    def test_host_proc_mapping_seccomp_caps_and_expected_operator(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            proc = root/'proc/1234'
            proc.mkdir(parents=True)
            (root/'proc/self').mkdir()
            for name in ('uid_map', 'gid_map'):
                (root/'proc/self'/name).write_text('0 0 4294967295\n')
                (proc/name).write_text('0 1001 1\n1 231072 65536\n')
            (proc/'cmdline').write_bytes(b'/usr/bin/sleep\x00infinity\x00')
            (proc/'stat').write_text('1234 (sleep) ' + '0 ' * 19 + '12345\n')
            group = '/user.slice/user-1001.slice/docker-' + CID + '.scope'
            (proc/'cgroup').write_text('0::' + group + '\n')
            cg = root/'cgroup'/group.lstrip('/')
            cg.mkdir(parents=True)
            for name, value in {'memory.max': str(lab.MEMORY), 'memory.swap.max': '0',
                                'pids.max': '64', 'cpu.max': '50000 100000'}.items():
                (cg/name).write_text(value)
            status = {'NSpid': '1234 1', 'NoNewPrivs': '0', 'Seccomp': '2',
                      'CapBnd': '00000000000000c0', 'Uid': '232071 232071 232071 232071',
                      'Gid': '232071 232071 232071 232071'}
            def write_status(values):
                (proc/'status').write_text(''.join(k + ':\t' + v + '\n' for k, v in values.items()))
            def mapped_path(value):
                value = str(value)
                if value == '/proc' or value.startswith('/proc/'):
                    return root/'proc'/value.removeprefix('/proc').lstrip('/')
                if value == '/sys/fs/cgroup':
                    return root/'cgroup'
                return Path(value)
            write_status(status)
            with patch.object(lab, 'Path', side_effect=mapped_path), \
                 patch.object(lab.pwd, 'getpwuid', return_value=types.SimpleNamespace(pw_gid=1001)):
                evidence = lab.running_isolation(container_fixture(), CONFIG)
                self.assertEqual(evidence['host_uid_for_container_root'], 1001)
                self.assertEqual(evidence['host_gid_for_container_root'], 1001)
                self.assertEqual(evidence['mapping_verification'], 'initial-host-proc-uid-gid-maps')
                for invalid in (group + '/child', group + '-extra', '/spoof-' + CID + '.scope'):
                    (proc/'cgroup').write_text('0::' + invalid + '\n')
                    with self.subTest(cgroup=invalid), self.assertRaises(lab.Rejected):
                        lab.running_isolation(container_fixture(), CONFIG)
                (proc/'cgroup').write_text('0::' + group + '\n')
                for key, value in [('Seccomp','0'), ('CapBnd','00000000002000c0'),
                                   ('NoNewPrivs','1'), ('Uid','0 0 0 0'), ('Gid','0 0 0 0')]:
                    write_status(dict(status, **{key:value}))
                    with self.subTest(key=key), self.assertRaises(lab.Rejected):
                        lab.running_isolation(container_fixture(), CONFIG)
                write_status(status)
                for name in ('uid_map', 'gid_map'):
                    original = (proc/name).read_text()
                    (proc/name).write_text('0 1002 1\n1 231072 65536\n')
                    with self.subTest(name=name), self.assertRaises(lab.Rejected):
                        lab.running_isolation(container_fixture(), CONFIG)
                    (proc/name).write_text(original)

    def test_fixed_create_has_no_generic_execution_or_mount(self):
        args = lab.create_args(CONFIG)
        self.assertIn('--network=none', args)
        self.assertIn('--pull=never', args)
        self.assertIn('--security-opt=no-new-privileges=false', args)
        self.assertIn('--security-opt=apparmor=unconfined', args)
        self.assertEqual(args[-2:], [CONFIG['image_id'], 'infinity'])
        self.assertFalse(any(x.startswith(('--publish', '--mount', '--volume', '--privileged')) for x in args))

    def test_unmanaged_name_is_never_adopted(self):
        docker = types.SimpleNamespace(run=lambda args: CID)
        with tempfile.TemporaryDirectory() as work, self.assertRaises(lab.Rejected):
            lab.Lab(CONFIG, docker, Path(work)).inventory()

    def test_up_failed_isolation_stops_exact_container(self):
        calls = []
        def run(args):
            calls.append(args)
            if args[0] == 'info':
                return json.dumps(INFO)
            if args[:2] == ['container', 'logs']:
                return json.dumps({'schema': 1, 'package': 'sudo', 'version': lab.VERSION, 'architecture': 'amd64', 'setuid_binary': True, 'attack_tested': False})
            return ''
        docker = types.SimpleNamespace(run=run, inspect=lambda kind, key: image_fixture())
        with tempfile.TemporaryDirectory() as work:
            instance = lab.Lab(CONFIG, docker, Path(work))
            with patch.object(instance, 'inventory', return_value=container_fixture()), \
                 patch.object(lab, 'running_isolation', side_effect=lab.Rejected('mapping_not_verified')), \
                 self.assertRaises(lab.Rejected):
                instance.run('up')
        self.assertEqual(calls[-1], ['container', 'stop', '--time', '5', CID])
        self.assertFalse(any('exec' in call for call in calls))

    def test_post_start_contract_failure_stops_exact_container(self):
        calls = []
        def run(args):
            calls.append(args)
            return json.dumps(INFO) if args[0] == 'info' else ''
        stopped = container_fixture()
        stopped['State']['Running'] = False
        docker = types.SimpleNamespace(run=run, inspect=lambda kind, key: image_fixture())
        with tempfile.TemporaryDirectory() as work:
            instance = lab.Lab(CONFIG, docker, Path(work))
            with patch.object(instance, 'inventory', side_effect=[stopped, lab.Rejected('changed')]), \
                 patch.object(instance, 'retire_stopped'), patch.object(instance, 'register'), \
                 self.assertRaises(lab.Rejected):
                instance.run('up')
        self.assertFalse(any(call[:2] == ['container', 'start'] for call in calls))

    def test_retire_requires_exact_stopped_receipt_and_never_forces(self):
        calls = []
        docker = types.SimpleNamespace(run=lambda args: calls.append(args))
        stopped = container_fixture()
        stopped['State'] = {'Running': False, 'Pid': 0, 'Status': 'exited'}
        with tempfile.TemporaryDirectory() as work:
            instance = lab.Lab(CONFIG, docker, Path(work))
            instance.register(CID)
            instance.retire_stopped(stopped)
            self.assertEqual(calls, [['container', 'rm', CID]])
            self.assertFalse(instance.receipt.exists())
            history = json.loads((Path(work)/('retired-' + CID + '.json')).read_text())
            self.assertEqual(history['container_id'], CID)
            self.assertEqual(history['image_id'], CONFIG['image_id'])
        for change in [{'Running': True}, {'Pid': 1234}, {'Status': 'restarting'}, {'Paused': True}]:
            with tempfile.TemporaryDirectory() as work:
                instance = lab.Lab(CONFIG, docker, Path(work))
                instance.register(CID)
                changed = copy.deepcopy(stopped)
                changed['State'].update(change)
                with self.subTest(change=change), self.assertRaises(lab.Rejected):
                    instance.retire_stopped(changed)
                self.assertTrue(instance.receipt.exists())
        self.assertEqual(calls, [['container', 'rm', CID]])

    def test_inventory_never_claims_attack_or_environment_verified(self):
        docker = types.SimpleNamespace(run=lambda args: json.dumps(INFO), inspect=lambda kind, key: image_fixture())
        with tempfile.TemporaryDirectory() as work:
            instance = lab.Lab(CONFIG, docker, Path(work))
            with patch.object(instance, 'inventory', return_value=container_fixture()):
                result = instance.run('status')
        self.assertFalse(result['environment_ready'])
        self.assertFalse(result['attack_tested'])
        self.assertFalse(result['host_scenario_verified'])


class Provenance(unittest.TestCase):
    def setUp(self):
        self.source = json.loads((BASE / 'source.json').read_text())
        self.deb = b'synthetic-test-artifact-not-a-package'
        self.record = ('Package: sudo\nVersion: 1.8.31-1ubuntu1\nArchitecture: amd64\n'
                       'Filename: ' + self.source['deb_path'] + '\nSize: ' + str(len(self.deb)) +
                       '\nSHA256: ' + prepare.sha(self.deb) + '\n\n')
        self.packages = lzma.compress(self.record.encode())
        self.release = ('Origin: Ubuntu\nSuite: focal\nCodename: focal\nSHA256:\n ' +
                        prepare.sha(self.packages) + ' ' + str(len(self.packages)) +
                        ' main/binary-amd64/Packages.xz\n')

    def test_signed_hash_chain_and_exact_package_selection(self):
        prepare.release_entry(self.release, self.source, self.packages)
        self.assertEqual(prepare.package_entry(self.packages, self.source, self.deb)['Version'], lab.VERSION)
        for artifact in (self.packages + b'x', self.packages[:-1]):
            with self.assertRaises(ValueError):
                prepare.release_entry(self.release, self.source, artifact)
        with self.assertRaises(ValueError):
            prepare.package_entry(self.packages, self.source, self.deb + b'x')

    def test_xz_concatenated_empty_and_split_streams_and_valid_padding(self):
        record = self.record.encode()
        half = len(record) // 2
        for packed in [self.packages + lzma.compress(b''),
                       lzma.compress(record[:half]) + lzma.compress(record[half:]),
                       self.packages + b'\x00' * 4 + lzma.compress(b'') + b'\x00' * 8]:
            with self.subTest(size=len(packed)):
                self.assertEqual(prepare.package_entry(packed, self.source, self.deb)['Version'], lab.VERSION)

    def test_xz_truncation_garbage_bad_padding_and_other_formats_rejected(self):
        for packed in [b'', self.packages[:-1], self.packages + b'garbage',
                       self.packages + b'\x00', self.packages + lzma.compress(b'')[:-1],
                       lzma.compress(self.record.encode(), format=lzma.FORMAT_ALONE)]:
            with self.subTest(size=len(packed)), self.assertRaises(ValueError):
                prepare.decompress_packages(packed)

    def test_xz_output_budget_applies_across_streams_and_limits_empty_streams(self):
        with patch.object(prepare, 'MAX_PACKAGES', 10):
            self.assertEqual(prepare.decompress_packages(lzma.compress(b'12345') + lzma.compress(b'67890')), b'1234567890')
            for packed in [lzma.compress(b'x' * 11), lzma.compress(b'x' * 6) + lzma.compress(b'x' * 5)]:
                with self.assertRaises(ValueError):
                    prepare.decompress_packages(packed)
        with patch.object(prepare, 'MAX_XZ_STREAMS', 2), self.assertRaises(ValueError):
            prepare.decompress_packages(lzma.compress(b'') * 3)

    def test_wrong_suite_or_patch_or_duplicate_package_rejected(self):
        with self.assertRaises(ValueError):
            prepare.release_entry(self.release.replace('Suite: focal', 'Suite: jammy'), self.source, self.packages)
        for record in [self.record.replace('1ubuntu1\n', '1ubuntu1.2\n'), self.record * 2]:
            with self.assertRaises(ValueError):
                prepare.package_entry(lzma.compress(record.encode()), self.source, self.deb)

    def test_bad_signature_creates_no_context(self):
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            for name, data in [('InRelease', b'invalid-signature'), ('Packages.xz', self.packages),
                               ('sudo.deb', self.deb), ('keyring.gpg', b'synthetic-keyring')]:
                (work / name).write_bytes(data)
            args = types.SimpleNamespace(inrelease=work/'InRelease', packages_xz=work/'Packages.xz',
                                         deb=work/'sudo.deb', keyring=work/'keyring.gpg', output=work/'output',
                                         keyring_sha256=prepare.sha(b'synthetic-keyring'))
            with patch.object(prepare.shutil, 'which', return_value='/usr/bin/gpgv'), \
                 patch.object(prepare.subprocess, 'run', return_value=types.SimpleNamespace(returncode=1)), \
                 self.assertRaises(ValueError):
                prepare.prepare(args)
            self.assertFalse(args.output.exists())

    def test_pinned_base_consistency(self):
        self.assertIn('FROM ' + self.source['base_image'], (BASE/'Dockerfile').read_text())
        self.assertEqual(self.source['base_image'], 'ubuntu@' + lab.BASE_DIGEST)


class Publisher(unittest.TestCase):
    def test_probe_output_is_file_limited_before_read(self):
        account = types.SimpleNamespace(pw_name='capstone-sudo', pw_gid=1991,
                                        pw_dir='/var/lib/capstone-sudo-runtime', pw_shell='/usr/sbin/nologin')
        limiter = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0, st_nlink=1)
        def child(command, **kwargs):
            self.assertEqual(command[-4:], ['/usr/bin/prlimit', '--fsize=131072:131072', '--', 'fixed-probe'])
            kwargs['stdout'].write(b'{"ok":true}')
            kwargs['stdout'].flush()
            return types.SimpleNamespace(returncode=0)
        with tempfile.TemporaryDirectory() as work, patch.object(publisher, 'RECEIPT', Path(work)/'status'), \
             patch.object(publisher.pwd, 'getpwuid', return_value=account), \
             patch.object(publisher.Path, 'lstat', return_value=limiter), \
             patch.object(publisher, 'root_parents'), patch.object(publisher.os, 'fchown') as owner, \
             patch.object(publisher.subprocess, 'run', side_effect=child):
            self.assertEqual(publisher.operator_run(['fixed-probe'], 10), (0, {'ok': True}))
            self.assertEqual(owner.call_args.args[1:], (0, 0))
        def oversized(command, **kwargs):
            kwargs['stdout'].write(b'x' * 131072)
            kwargs['stdout'].flush()
            return types.SimpleNamespace(returncode=0)
        with tempfile.TemporaryDirectory() as work, patch.object(publisher, 'RECEIPT', Path(work)/'status'), \
             patch.object(publisher.pwd, 'getpwuid', return_value=account), \
             patch.object(publisher.Path, 'lstat', return_value=limiter), \
             patch.object(publisher, 'root_parents'), patch.object(publisher.os, 'fchown'), \
             patch.object(publisher.subprocess, 'run', side_effect=oversized), self.assertRaises(ValueError):
            publisher.operator_run(['fixed-probe'], 10)

    def test_new_receipt_has_explicit_root_group_and_ttl(self):
        with tempfile.TemporaryDirectory() as work, patch.object(publisher, 'RECEIPT', Path(work)/'status'), \
             patch.object(publisher, 'root_parents'), patch.object(publisher.os, 'fchown') as owner, \
             patch.object(publisher.time, 'time', return_value=100):
            result = publisher.atomic_receipt('needs_setup')
            self.assertEqual(result['expires_at'], 400)
            self.assertEqual(owner.call_args.args[1:], (0, 0))
            self.assertEqual(stat.S_IMODE((Path(work)/'status').stat().st_mode), 0o600)

    def test_receipt_never_discards_or_renews_other_labs(self):
        receipt = {'schema': 1, 'checked_at': 100, 'expires_at': 400,
                   'labs': {publisher.CVE: {'status': 'ready'}}}
        publisher.existing_contract(receipt)
        changed = copy.deepcopy(receipt)
        changed['labs']['CVE-2000-0001'] = {'status': 'ready'}
        with self.assertRaises(ValueError):
            publisher.existing_contract(changed)
        for changes in [{'schema': True}, {'expires_at': 701}, {'checked_at': True},
                        {'labs': {publisher.CVE: {'status': 'ready', 'command': 'extra'}}}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                publisher.existing_contract(dict(receipt, **changes))

    def test_publisher_requires_fresh_full_environment_proof(self):
        value = {'schema': 1, 'cve_id': publisher.CVE, 'checked_at': 100,
                 'status': 'running', 'environment_ready': True, 'package_verified': True,
                 'isolation_verified': True, 'verification': 'environment_only',
                 'attack_tested': False, 'host_scenario_verified': False,
                 'container_id': CID, 'image_id': CONFIG['image_id']}
        publisher.ready_contract(value, CONFIG, 101)
        for changes in [{'status': 'stopped'}, {'checked_at': 0}, {'checked_at': 102},
                        {'checked_at': True}, {'environment_ready': False}, {'package_verified': False},
                        {'isolation_verified': False}, {'image_id': 'sha256:'+'f'*64},
                        {'container_id': CID[:12]}, {'attack_tested': True}]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                publisher.ready_contract(dict(value, **changes), CONFIG, 101)

    def test_atomic_publisher_preserves_unrelated_lab_receipt(self):
        with tempfile.TemporaryDirectory() as work:
            target = Path(work)/'nonweb-status.json'
            original = b'original-other-lab-file'
            target.write_bytes(original)
            other = {'schema': 1, 'checked_at': 100, 'expires_at': 400,
                     'labs': {'CVE-2000-0001': {'status': 'ready'}}}
            with patch.object(publisher, 'RECEIPT', target), patch.object(publisher, 'root_parents'), \
                 patch.object(publisher, 'root_file', return_value=json.dumps(other).encode()), \
                 self.assertRaises(ValueError):
                publisher.atomic_receipt('ready')
            self.assertEqual(target.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
