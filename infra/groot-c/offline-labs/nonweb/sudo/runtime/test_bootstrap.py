import copy
from contextlib import ExitStack
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('sudo_bootstrap_tested', HERE / 'bootstrap.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


def tar_bytes(items):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for name, value, kind in items:
            info = tarfile.TarInfo(name)
            if kind == 'symlink':
                info.type = tarfile.SYMTYPE
                info.linkname = '/etc/shadow'
                archive.addfile(info)
            else:
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
    return output.getvalue()


def image_archive(change=None):
    layer = b'synthetic-layer'
    image = {'os': 'linux', 'architecture': 'amd64', 'rootfs': {'diff_ids': ['sha256:' + 'e' * 64]}, 'config': {}}
    if change:
        image.update(change)
    config = b.json_bytes(image)
    config_id = 'sha256:' + b.sha(config)
    manifest = b.json_bytes({'config': {'digest': config_id},
                            'layers': [{'digest': 'sha256:' + b.sha(layer), 'size': len(layer)}]})
    manifest_id = 'sha256:' + b.sha(manifest)
    entries = [('index.json', b.json_bytes({'manifests': [{'digest': manifest_id}]}), 'file'),
               ('blobs/sha256/' + manifest_id[7:], manifest, 'file'),
               ('blobs/sha256/' + config_id[7:], config, 'file'),
               ('blobs/sha256/' + b.sha(layer), layer, 'file')]
    return entries, manifest_id, config_id


class ManifestAndArtifacts(unittest.TestCase):
    def fixture(self):
        files = {name: ('synthetic:' + name).encode() for name in b.INPUTS}
        files['preparation.json'] = b.json_bytes({'schema': 1, 'package': 'sudo',
            'package_version': '1.8.31-1ubuntu1', 'architecture': 'amd64', 'deb_sha256': b.DEB_SHA,
            'keyring_sha256': b.KEYRING_SHA, 'release_signature_verified': True,
            'inrelease_sha256': b.sha(files['sudo.InRelease']), 'packages_sha256': b.sha(files['sudo.Packages.xz'])})
        manifest = {'schema': 1, 'profile': b.PROFILE,
                    'files': {name: {'sha256': b.sha(data), 'size': len(data)} for name, data in files.items()}}
        pins = {name: (b.sha(files[name]), len(files[name])) for name in b.PINS}
        return manifest, files, pins

    def test_exact_manifest_schema_and_names(self):
        manifest, _, _ = self.fixture()
        b.validate_manifest(manifest)
        for change in ({'schema': True}, {'profile': 'arbitrary'}, {'extra': 1}, {'files': {}},
                       {'files': dict(manifest['files'], **{'../escape': {'sha256': 'a' * 64, 'size': 1}})}):
            with self.subTest(change=change), self.assertRaises(b.Rejected):
                b.validate_manifest(dict(manifest, **change))

    def test_manifest_hash_does_not_override_reviewed_pin(self):
        manifest, files, pins = self.fixture()
        def read(path, *args, **kwargs):
            return b.json_bytes(manifest) if path.name == 'manifest.json' else files[path.name]
        with patch.object(b, 'parents'), patch.object(b, 'read', side_effect=read), \
             patch.object(b.Path, 'iterdir', return_value=[Path(n) for n in b.INPUTS | {'manifest.json'}]), \
             patch.object(b, 'PINS', pins):
            b.read_bundle(Path('/opt/capstone-prereqs/sudo'))
            files[b.EXTRAS] = b'unreviewed-but-manifest-matches'
            manifest['files'][b.EXTRAS] = {'sha256': b.sha(files[b.EXTRAS]), 'size': len(files[b.EXTRAS])}
            with self.assertRaisesRegex(b.Rejected, 'reviewed_artifact_pin_mismatch'):
                b.read_bundle(Path('/opt/capstone-prereqs/sudo'))

    def test_preparation_cannot_point_to_different_signed_inputs(self):
        manifest, files, pins = self.fixture()
        prep = json.loads(files['preparation.json'])
        prep['inrelease_sha256'] = 'f' * 64
        files['preparation.json'] = b.json_bytes(prep)
        manifest['files']['preparation.json'] = {'sha256': b.sha(files['preparation.json']), 'size': len(files['preparation.json'])}
        pins['preparation.json'] = (b.sha(files['preparation.json']), len(files['preparation.json']))
        def read(path, *args, **kwargs):
            return b.json_bytes(manifest) if path.name == 'manifest.json' else files[path.name]
        with patch.object(b, 'parents'), patch.object(b, 'read', side_effect=read), \
             patch.object(b.Path, 'iterdir', return_value=[Path(n) for n in b.INPUTS | {'manifest.json'}]), \
             patch.object(b, 'PINS', pins), self.assertRaisesRegex(b.Rejected, 'preparation_input_mismatch'):
            b.read_bundle(Path('/opt/capstone-prereqs/sudo'))

    def test_manifest_size_and_duplicate_keys_fail(self):
        manifest, _, _ = self.fixture()
        for size in (-1, True, 0, 64 * 1024 * 1024 + 1):
            changed = copy.deepcopy(manifest)
            changed['files']['sudo.deb']['size'] = size
            with self.subTest(size=size), self.assertRaises(b.Rejected):
                b.validate_manifest(changed)
        with self.assertRaises(b.Rejected):
            b.parsed('{"schema":1,"schema":1}')

    def test_bundle_rejects_non_opt_and_traversal(self):
        for value in ('relative', '/tmp/package', '/opt/../etc/sudo'):
            with self.subTest(value=value), self.assertRaises(b.Rejected):
                b.read_bundle(Path(value))

    def test_oci_manifest_config_layer_chain(self):
        entries, manifest, config = image_archive()
        image, diffids = b.verify_oci(tar_bytes(entries), manifest, config)
        self.assertEqual(image['architecture'], 'amd64')
        self.assertEqual(diffids, ['sha256:' + 'e' * 64])
        corrupted = list(entries)
        corrupted[-1] = (entries[-1][0], b'changed-layer', 'file')
        with self.assertRaisesRegex(b.Rejected, 'oci_layer_digest'):
            b.verify_oci(tar_bytes(corrupted), manifest, config)
        with self.assertRaises(b.Rejected):
            b.verify_oci(tar_bytes(entries), 'sha256:' + 'a' * 64, config)

    def test_oci_rejects_duplicate_path_symlink_traversal_and_wrong_arch(self):
        entries, manifest, config = image_archive()
        for addition in ([entries[0]], [('bad', b'', 'symlink')], [('../etc/shadow', b'x', 'file')]):
            with self.subTest(addition=addition), self.assertRaises(b.Rejected):
                b.verify_oci(tar_bytes(entries + addition), manifest, config)
        entries, manifest, config = image_archive({'architecture': 'arm64'})
        with self.assertRaisesRegex(b.Rejected, 'oci_platform'):
            b.verify_oci(tar_bytes(entries), manifest, config)

    def test_extras_only_extracts_pinned_regular_three_binaries(self):
        values = {name: name.encode() for name in b.BINARY_PINS}
        pins = {name: (b.sha(data), len(data)) for name, data in values.items()}
        items = [('./usr/bin/' + name, data, 'file') for name, data in values.items()]
        with patch.object(b, 'BINARY_PINS', pins), patch.object(b, 'run', return_value=tar_bytes(items)):
            self.assertEqual(b.extract_binaries({b.EXTRAS: b'deb'}, {'dpkg-deb': '/usr/bin/dpkg-deb'}), values)
        for bad in (items[:-1], items + [items[0]], [(items[0][0], b'', 'symlink')] + items[1:]):
            with patch.object(b, 'BINARY_PINS', pins), patch.object(b, 'run', return_value=tar_bytes(bad)), self.assertRaises(b.Rejected):
                b.extract_binaries({b.EXTRAS: b'deb'}, {'dpkg-deb': '/usr/bin/dpkg-deb'})

    def test_untrusted_public_key_is_rejected(self):
        with self.assertRaises(b.Rejected):
            b.docker_key(b'not-a-public-key')


class IdentityAndFilesystem(unittest.TestCase):
    def test_regular_root_single_link_nonwritable_contract(self):
        original = {'st_mode': stat.S_IFREG | 0o600, 'st_uid': 0, 'st_nlink': 1}
        b.metadata(types.SimpleNamespace(**original), mode=0o600)
        for mutation in ({'st_uid': 1000}, {'st_nlink': 2}, {'st_mode': stat.S_IFLNK | 0o777},
                         {'st_mode': stat.S_IFREG | 0o666}):
            with self.subTest(mutation=mutation), self.assertRaises(b.Rejected):
                b.metadata(types.SimpleNamespace(**dict(original, **mutation)))

    def test_subordinate_range_conflicts_are_not_reallocated(self):
        b.subids('existing:100000:65536\n')
        b.subids('existing:100000:65536\ncapstone-sudo:231072:65536\n', managed=True)
        for text in ('other:231072:1', 'other:220000:65536', 'capstone-sudo:231072:65536',
                     'bad:0:65536', 'bad:300000:0'):
            with self.subTest(text=text), self.assertRaises(b.Rejected):
                b.subids(text)
        with self.assertRaises(b.Rejected):
            b.subids('capstone-sudo:231072:65536\ncapstone-sudo:231072:65536', managed=True)

    def test_initial_namespace_is_required(self):
        with patch.object(b.Path, 'read_text', return_value='0 0 4294967295\n'):
            b.initial_namespace()
        with patch.object(b.Path, 'read_text', side_effect=['0 0 4294967295', '0 1000 1']), self.assertRaises(b.Rejected):
            b.initial_namespace()

    def test_existing_account_or_uid_fails_closed(self):
        with patch.object(b.pwd, 'getpwnam', return_value=object()), self.assertRaisesRegex(b.Rejected, 'identity_conflict'):
            b.account(False)
        with patch.object(b.pwd, 'getpwnam', side_effect=KeyError), \
             patch.object(b.pwd, 'getpwuid', side_effect=KeyError), \
             patch.object(b.grp, 'getgrnam', side_effect=KeyError), \
             patch.object(b.grp, 'getgrgid', side_effect=KeyError):
            b.account(False)

    def test_managed_identity_has_no_additional_groups_and_locked_password(self):
        user = types.SimpleNamespace(pw_uid=1991, pw_gid=1991, pw_dir=str(b.HOME), pw_shell='/usr/sbin/nologin')
        with patch.object(b.pwd, 'getpwnam', return_value=user), \
             patch.object(b.grp, 'getgrnam', return_value=types.SimpleNamespace(gr_gid=1991)), \
             patch.object(b.os, 'getgrouplist', return_value=[1991]), patch.object(b, 'run', return_value=b'capstone-sudo L 10/23/2026'):
            b.account(True)
            with patch.object(b.os, 'getgrouplist', return_value=[1991, 998]), self.assertRaises(b.Rejected):
                b.account(True)
            with patch.object(b, 'run', return_value=b'capstone-sudo P 10/23/2026'), self.assertRaises(b.Rejected):
                b.account(True)

    def test_managed_manifest_rejects_partial_foreign_and_source_changed(self):
        m = types.SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0)
        with patch.object(b.Path, 'lstat', return_value=m), patch.object(b, 'read', return_value=b'{"schema":1,"profile":"x","state":"preparing"}'), self.assertRaises(b.Rejected):
            b.read_managed({'lab.py': b'x'})
        good = {'schema': 1, 'profile': b.PROFILE, 'state': 'complete', 'image_id': b.IMAGE,
                'source_sha256': {'lab.py': b.sha(b'x')}, 'files': {}, 'bundle_manifest_sha256': 'a' * 64,
                'baseline': {}, 'completed_at': 1}
        with patch.object(b.Path, 'lstat', return_value=m), patch.object(b, 'read', return_value=b.json_bytes(good)), patch.object(b, 'managed_files', return_value=[]):
            b.read_managed({'lab.py': b'x'})
            with self.assertRaisesRegex(b.Rejected, 'source_changed'):
                b.read_managed({'lab.py': b'changed'})

    def test_state_directory_rejects_nonroot_group_symlink_and_open_mode(self):
        for mode, uid, gid in ((stat.S_IFDIR | 0o755, 0, 0), (stat.S_IFLNK | 0o700, 0, 0),
                               (stat.S_IFDIR | 0o700, 1991, 0), (stat.S_IFDIR | 0o700, 0, 1991)):
            m = types.SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid)
            with patch.object(b.Path, 'lstat', return_value=m), self.assertRaisesRegex(b.Rejected, 'state_directory'):
                b.read_managed({})

    def test_umask_077_keeps_new_binary_parents_traversable(self):
        with tempfile.TemporaryDirectory(prefix='sudo-bootstrap-test-') as temporary:
            target = Path(temporary) / 'opt' / 'dedicated' / 'bin'
            previous = os.umask(0o077)
            try:
                with patch.object(b, 'parents'), patch.object(b.os, 'chown'):
                    b.mkdir(target)
            finally:
                os.umask(previous)
            for path in (target, target.parent, target.parent.parent):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)

    def test_subid_append_rechecks_current_inode_bytes_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory(prefix='sudo-bootstrap-test-') as temporary:
            path = Path(temporary) / 'subuid'
            original = b'existing:100000:65536\n'
            path.write_bytes(original)
            with patch.object(b, 'parents'), patch.object(b, 'metadata'):
                b.append_subids(path, original)
                self.assertEqual(path.read_bytes(), original + b'capstone-sudo:231072:65536\n')
                with self.assertRaisesRegex(b.Rejected, 'subid_file_changed'):
                    b.append_subids(path, original)
                link = Path(temporary) / 'link'
                link.symlink_to(path)
                with self.assertRaises(OSError):
                    b.append_subids(link, path.read_bytes())

    def test_operator_command_uses_only_dedicated_socket_environment(self):
        command = b.operator(['/usr/bin/true'])
        self.assertEqual(command[:4], ['/usr/sbin/runuser', '-u', 'capstone-sudo', '--'])
        self.assertIn('XDG_RUNTIME_DIR=/run/user/1991', command)
        self.assertIn('-i', command)
        with self.assertRaises(b.Rejected):
            b.lab_command('arbitrary-shell')


class ControllerFlow(unittest.TestCase):
    def common(self):
        return [patch.object(b.os, 'geteuid', return_value=0), patch.object(b.os, 'getuid', return_value=0),
                patch.object(b, 'source_inputs', return_value={'lab.py': b'x'}),
                patch.object(b, 'discover_tools', return_value={})]

    def test_managed_apply_only_verifies_and_never_reinstalls(self):
        with self.common()[0], self.common()[1], self.common()[2], self.common()[3], \
             patch.object(b.Path, 'exists', return_value=True), \
             patch.object(b, 'verify_runtime', return_value={'container_id': 'a' * 64}) as verify, \
             patch.object(b, 'read_bundle') as bundle, patch.object(b, 'install') as install:
            result = b.execute('apply', Path('/opt/prereqs'))
            self.assertTrue(result['managed_existing'])
            verify.assert_called_once()
            bundle.assert_not_called()
            install.assert_not_called()

    def test_unmanaged_verify_never_installs(self):
        with self.common()[0], self.common()[1], self.common()[2], self.common()[3], \
             patch.object(b.Path, 'exists', return_value=False), patch.object(b.Path, 'is_symlink', return_value=False), \
             patch.object(b, 'host_check') as host, patch.object(b, 'install') as install, self.assertRaises(b.Rejected):
            b.execute('verify', Path('/opt/prereqs'))
        host.assert_not_called()
        install.assert_not_called()

    def test_check_creates_no_runtime_and_never_reports_environment_ready(self):
        lab = types.SimpleNamespace(image_contract=lambda *args: None)
        with self.common()[0], self.common()[1], self.common()[2], self.common()[3], \
             patch.object(b.Path, 'exists', return_value=False), patch.object(b.Path, 'is_symlink', return_value=False), \
             patch.object(b, 'host_check'), patch.object(b, 'fresh_paths'), \
             patch.object(b, 'read_bundle', return_value=({'schema': 1}, {'sudo-image.tar': b'x'})), \
             patch.object(b, 'verify_signatures'), patch.object(b, 'verify_oci', return_value=({'os': 'linux', 'architecture': 'amd64', 'config': {}}, [])), \
             patch.object(b, 'module', return_value=lab), patch.object(b, 'extract_binaries'), \
             patch.object(b, 'install') as install:
            value = b.execute('check', Path('/opt/prereqs'))
        self.assertEqual(value['status'], 'prerequisites_ready')
        self.assertFalse(value['environment_ready'])
        self.assertFalse(value['attack_tested'])
        install.assert_not_called()

    def test_signature_failure_prevents_any_install(self):
        with self.common()[0], self.common()[1], self.common()[2], self.common()[3], \
             patch.object(b.Path, 'exists', return_value=False), patch.object(b.Path, 'is_symlink', return_value=False), \
             patch.object(b, 'host_check'), patch.object(b, 'fresh_paths'), \
             patch.object(b, 'read_bundle', return_value=({}, {})), \
             patch.object(b, 'verify_signatures', side_effect=b.Rejected('signature_invalid')), \
             patch.object(b, 'install') as install, self.assertRaises(b.Rejected):
            b.execute('apply', Path('/opt/prereqs'))
        install.assert_not_called()

    def test_nonroot_refused_before_source_or_runtime_access(self):
        with patch.object(b.os, 'geteuid', return_value=1991), patch.object(b, 'source_inputs') as source, self.assertRaises(b.Rejected):
            b.execute('check', Path('/opt/prereqs'))
        source.assert_not_called()


class InstallationFlow(unittest.TestCase):
    def simulated_install(self, failure=None):
        # Real local file writes under TemporaryDirectory; every privileged
        # operation, /etc access, Docker call and host attestation is mocked.
        with tempfile.TemporaryDirectory(prefix='sudo-bootstrap-install-test-') as temporary, ExitStack() as stack:
            root = Path(temporary)
            paths = {'STATE': root/'state', 'HOME': root/'home', 'BIN': root/'opt/runtime/bin',
                     'CONFIG': root/'etc/config', 'INSTALLED': root/'opt/app/nonweb/sudo',
                     'WEBSTATE': root/'webstate', 'AA': root/'etc/apparmor-profile',
                     'DROPIN': root/'etc/dropin/config', 'PUB_UNIT': root/'etc/publisher.service',
                     'PUB_TIMER': root/'etc/publisher.timer'}
            paths['USER_UNIT'] = paths['HOME']/'.config/systemd/user/capstone-sudo-docker.service'
            for name, path in paths.items(): stack.enter_context(patch.object(b, name, path))
            for name in ('parents', 'metadata', 'append_subids'):
                stack.enter_context(patch.object(b, name))
            stack.enter_context(patch.object(b.os, 'chown'))
            stack.enter_context(patch.object(b.os, 'fchown'))
            stack.enter_context(patch.object(b, 'read', return_value=b'existing:100000:65536\n'))
            before = {'protected': 'unchanged'}
            stack.enter_context(patch.object(b, 'baseline', side_effect=[before, {'changed': True}] if failure == 'baseline' else [before, before]))
            proof = {'container_id': 'a'*64}
            verify = stack.enter_context(patch.object(b, 'verify_runtime', return_value=proof,
                                                     side_effect=b.Rejected('attestation_failed') if failure == 'verify' else None))
            stack.enter_context(patch.object(b, 'lab_command', return_value=proof))
            fake = types.SimpleNamespace(image_contract=lambda *a: None, ready_contract=lambda *a: None)
            stack.enter_context(patch.object(b, 'module', return_value=fake))
            commands=[]
            def command(args, **kwargs):
                commands.append([str(x) for x in args])
                if 'image' in args and 'inspect' in args:
                    return b.json_bytes([{'RootFS': {'Layers': ['layer']}}])
                if failure == 'useradd' and str(args[0]).endswith('/useradd'):
                    raise b.Rejected('useradd_failed')
                return b''
            stack.enter_context(patch.object(b, 'run', side_effect=command))
            tools={x:'/usr/bin/'+x for x in ('groupadd','useradd','apparmor_parser','systemctl','loginctl','docker','dockerd')}
            source={name:(b.SOURCE/name).read_bytes() for name in b.SOURCE_FILES}
            files={'preparation.json': b'{}', 'sudo-image.tar':b'synthetic-image'}
            if failure:
                with self.assertRaises(b.Rejected):
                    b.install(tools,source,{},files,{x:b'x' for x in b.BINARY_PINS},['layer'],{})
            else:
                self.assertEqual(b.install(tools,source,{},files,{x:b'x' for x in b.BINARY_PINS},['layer'],{}),proof)
            value=json.loads((paths['STATE']/'manifest.json').read_bytes())
            return value,commands,verify.call_count

    def test_complete_manifest_follows_host_checks_and_preserves_recovery_inputs(self):
        value, commands, checks = self.simulated_install()
        self.assertEqual(value['state'], 'complete')
        self.assertEqual(checks, 1)
        self.assertTrue(any(name.endswith('/recovery/sudo-image.tar') for name in value['files']))
        self.assertTrue(any('capstone-sudo-status.timer' in c and 'enable' in c for c in commands))
        self.assertFalse(any('apt' in c[0] or 'sysctl' in c[0] for c in commands))

    def test_failed_final_attestation_never_leaves_complete_state(self):
        value, _, checks = self.simulated_install('verify')
        self.assertEqual(value['state'], 'verification_failed')
        self.assertEqual(checks, 1)

    def test_protected_host_drift_or_partial_user_creation_keeps_manual_recovery_state(self):
        for failure in ('baseline', 'useradd'):
            with self.subTest(failure=failure):
                value, _, checks = self.simulated_install(failure)
                self.assertEqual(value['state'], 'preparing')
                self.assertEqual(checks, 0)


if __name__ == '__main__':
    unittest.main()
