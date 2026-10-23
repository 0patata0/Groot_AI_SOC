"""Offline lifecycle/ownership/archive regressions; no Docker or network operations."""
import copy
import configparser
import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('nonweb_bootstrap_test', HERE / 'bootstrap.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
r = b.r


def config():
    return {'schema': 1, 'profile': r.PROFILE,
            'images': {lab: {'image_id': 'sha256:' + char * 64,
                            'start_sha256': 'c' * 64, 'verifier_sha256': 'd' * 64}
                       for lab, char in [('redis', 'a'), ('samba', 'b')]},
            'source_sha256': {name: 'e' * 64 for name in r.SOURCE_FILES}}


def container(lab='redis', cid='1' * 64):
    s = r.LABS[lab]
    return {'Id': cid, 'Name': '/capstone-nonweb-' + lab, 'Image': config()['images'][lab]['image_id'],
            'State': {'Running': True}, 'Mounts': [],
            'Config': {'User': s['user'], 'WorkingDir': '/lab', 'Entrypoint': ['/lab/start.sh'], 'Cmd': [],
                       'Labels': {'com.docker.compose.project': r.PROJECT, 'com.docker.compose.service': lab,
                                  'com.docker.compose.oneoff': 'False', 'io.capstone.managed': 'nonweb-v1',
                                  'io.capstone.lab': lab}},
            'NetworkSettings': {'Networks': {r.network_name(lab): {}}},
            'HostConfig': {'ReadonlyRootfs': True, 'Privileged': False, 'PublishAllPorts': False,
                           'Tmpfs': dict(s['tmpfs']), 'NetworkMode': r.network_name(lab),
                           'RestartPolicy': {'Name': 'no'}, 'IpcMode': 'private', 'CapDrop': ['ALL'],
                           'CapAdd': list(s['caps']), 'SecurityOpt': ['no-new-privileges:true'],
                           'Memory': s['memory'], 'NanoCpus': s['cpus'], 'PidsLimit': s['pids'],
                           'LogConfig': {'Type': 'json-file', 'Config': {'max-size': '10m', 'max-file': '3'}}}}


def network(lab='redis', cid='1' * 64):
    return {'Id': ('3' if lab == 'redis' else '4') * 64, 'Name': r.network_name(lab), 'Driver': 'bridge',
            'Internal': True, 'EnableIPv6': False, 'Options': r.network_options(lab),
            'Labels': {'com.docker.compose.project': r.PROJECT, 'com.docker.compose.network': lab,
                       'io.capstone.managed': 'nonweb-v1'}, 'Containers': {cid: {}} if cid else {}}


def rec(lab='redis', cid='1' * 64):
    return {'schema': 1, 'lab': lab, 'container_id': cid,
            'image_id': config()['images'][lab]['image_id'], 'verified_at': 123}


class DockerFixture:
    def __init__(self, items=None):
        self.items = [container()] if items is None else items
        self.calls = []

    def ids(self, *args):
        self.calls.append(args)
        if args[:2] == ('container', 'ls'):
            expr = args[-1]
            if 'project=' in expr:
                return [x['Id'] for x in self.items]
            return [x['Id'] for x in self.items if expr == 'name=^' + x['Name'] + '$']
        return [network(x['Config']['Labels']['com.docker.compose.service'], x['Id'])['Id']
                for x in self.items if 'project=' in args[-1] or args[-1] == 'name=^' + r.network_name(x['Config']['Labels']['com.docker.compose.service']) + '$']

    def inspect(self, cid):
        return next(x for x in self.items if x['Id'] == cid)

    def json(self, *args):
        return [network(x['Config']['Labels']['com.docker.compose.service'], x['Id'])
                for x in self.items if network(x['Config']['Labels']['com.docker.compose.service'], x['Id'])['Id'] == args[-1]]

    def run(self, *args, **kwargs):
        self.calls.append(args)
        if args[:2] == ('container', 'rm'):
            self.items = [x for x in self.items if x['Id'] != args[-1]]
        if args[:2] == ('container', 'stop'):
            self.inspect(args[-1])['State']['Running'] = False
        return mock.Mock(stdout=b'', returncode=0)


def guard_document():
    entries = [{'metainfo': {'version': 'fixture'}}, {'table': {'family': 'inet', 'name': r.TABLE}}]
    for name, rows in r.expected_guard_rules().items():
        entries.append({'chain': {'family': 'inet', 'table': r.TABLE, 'name': name, 'type': 'filter',
                                  'hook': name, 'prio': -20, 'policy': 'accept'}})
        for row in rows:
            entries.append({'rule': {'family': 'inet', 'table': r.TABLE, 'chain': name, 'expr': row}})
    return {'nftables': entries}


def archive_bytes(oci=False, tags=None, corrupt_layer=False, link=False):
    layer = b'harmless archive-layer fixture'
    conf = json.dumps({'os': 'linux', 'architecture': 'amd64', 'config': {},
                       'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + r.digest(layer)]}}).encode()
    config_id = r.digest(conf)
    layer_id = r.digest(layer)
    cfgpath, layerpath = 'blobs/sha256/' + config_id, 'blobs/sha256/' + layer_id
    oci_raw = json.dumps({'schemaVersion': 2, 'config': {'digest': 'sha256:' + config_id, 'size': len(conf)},
                          'layers': [{'digest': 'sha256:' + layer_id, 'size': len(layer)}]}).encode()
    image_id = 'sha256:' + (r.digest(oci_raw) if oci else config_id)
    files = {'manifest.json': json.dumps([{'Config': cfgpath, 'RepoTags': tags,
                                          'Layers': [layerpath]}]).encode(), cfgpath: conf,
             layerpath: b'corrupt' if corrupt_layer else layer,
             'blobs/sha256/' + r.digest(oci_raw): oci_raw}
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as tar:
        for name, raw in files.items():
            info = tarfile.TarInfo(name); info.size = len(raw); tar.addfile(info, io.BytesIO(raw))
        if link:
            info = tarfile.TarInfo('bad'); info.type = tarfile.SYMTYPE; info.linkname = '/etc/shadow'; tar.addfile(info)
    return output.getvalue(), image_id


class RuntimeContractTest(unittest.TestCase):
    def test_both_exact_runtime_profiles(self):
        for lab in r.LABS:
            r.validate_container(container(lab), lab, config())
            r.validate_network(network(lab), lab, '1' * 64)

    def test_host_ports_binds_extra_devices_and_namespaces_refused(self):
        changes = {'PortBindings': {'6379/tcp': [{'HostPort': '6379'}]}, 'Binds': ['/tmp:/host'],
                   'Devices': [{'PathOnHost': '/dev/kmsg'}], 'Privileged': True, 'PidMode': 'host',
                   'NetworkMode': 'host', 'ExtraHosts': ['host:10.0.0.1'], 'UsernsMode': 'host',
                   'ReadonlyRootfs': False, 'RestartPolicy': {'Name': 'always'}}
        for key, value in changes.items():
            item = container(); item['HostConfig'][key] = value
            with self.subTest(key=key), self.assertRaises(r.Rejected):
                r.validate_container(item, 'redis', config())

    def test_user_entrypoint_image_and_capability_drift_refused(self):
        for area, key, value in [('Config', 'User', '0:0'), ('Config', 'Entrypoint', ['/bin/sh']),
                                 ('HostConfig', 'CapAdd', ['SYS_ADMIN']), ('HostConfig', 'SecurityOpt', [])]:
            item = container(); item[area][key] = value
            with self.subTest(key=key), self.assertRaises(r.Rejected):
                r.validate_container(item, 'redis', config())
        item = container(); item['Image'] = 'sha256:' + '0' * 64
        with self.assertRaises(r.Rejected): r.validate_container(item, 'redis', config())

    def test_network_internal_bridge_and_sole_member_required(self):
        for key, value in [('Internal', False), ('Driver', 'host'), ('EnableIPv6', True),
                           ('Containers', {'2' * 64: {}}), ('Options', {})]:
            item = network(); item[key] = value
            with self.subTest(key=key), self.assertRaises(r.Rejected):
                r.validate_network(item, 'redis', '1' * 64)

    def test_samba_accepts_only_equivalent_optional_cap_prefix(self):
        expected = r.LABS['samba']['caps']
        for caps in (expected, ['CAP_' + x for x in reversed(expected)],
                     ['CAP_CHOWN', 'DAC_OVERRIDE', 'SETUID', 'CAP_SETGID']):
            item = container('samba'); item['HostConfig']['CapAdd'] = caps
            with self.subTest(caps=caps): r.validate_container(item, 'samba', config())

    def test_cap_prefix_does_not_accept_duplicates_extra_or_malformed_caps(self):
        expected = r.LABS['samba']['caps']
        for caps in (expected + ['CAP_SYS_ADMIN'], expected + ['CAP_CHOWN'],
                     expected + ['CHOWN'], ['CAP_CAP_CHOWN', *expected[1:]],
                     ['cap_chown', *expected[1:]], ['CAP_CHOWN ', *expected[1:]],
                     [None, *expected[1:]], 'CAP_CHOWN', {}, expected[:-1]):
            item = container('samba'); item['HostConfig']['CapAdd'] = caps
            with self.subTest(caps=caps), self.assertRaisesRegex(r.Rejected, 'container_privileges'):
                r.validate_container(item, 'samba', config())
        item = container(); item['HostConfig']['CapAdd'] = ['CAP_CHOWN']
        with self.assertRaisesRegex(r.Rejected, 'container_privileges'):
            r.validate_container(item, 'redis', config())

    def test_full_receipt_id_required_even_for_owned_labels(self):
        with mock.patch.object(r, 'receipt', return_value=rec(cid='2' * 64)):
            with self.assertRaisesRegex(r.Rejected, 'unrecorded_container'):
                r.inventory(DockerFixture(), config())

    def test_unrecorded_matching_container_is_not_adopted(self):
        with mock.patch.object(r, 'receipt', return_value=None):
            with self.assertRaisesRegex(r.Rejected, 'unrecorded_container'):
                r.inventory(DockerFixture(), config())

    def test_renamed_project_container_refused(self):
        item = container(); item['Name'] = '/someone-else'
        with mock.patch.object(r, 'receipt', return_value=rec()), self.assertRaises(r.Rejected):
            r.inventory(DockerFixture([item]), config())

    def test_additional_project_service_refused(self):
        item = container(cid='2' * 64); item['Config']['Labels']['com.docker.compose.service'] = 'unexpected'
        with mock.patch.object(r, 'receipt', return_value=rec()), self.assertRaises(r.Rejected):
            r.inventory(DockerFixture([container(), item]), config())

    def test_duplicate_project_service_refused(self):
        with mock.patch.object(r, 'receipt', return_value=rec()), self.assertRaises(r.Rejected):
            r.inventory(DockerFixture([container(), container(cid='2' * 64)]), config())

    def test_valid_inventory_uses_receipt(self):
        with mock.patch.object(r, 'receipt', side_effect=lambda lab: rec() if lab == 'redis' else None):
            self.assertEqual(r.inventory(DockerFixture(), config())['redis']['Id'], '1' * 64)

    def test_guard_exact_order_priority_and_drop_required(self):
        r.validate_guard(guard_document())
        for mutation in ('remove', 'priority', 'accept', 'interface'):
            document = guard_document()
            if mutation == 'remove': document['nftables'].pop()
            if mutation == 'priority': document['nftables'][2]['chain']['prio'] = 10
            if mutation == 'accept': document['nftables'][-1]['rule']['expr'][-1] = {'accept': None}
            if mutation == 'interface': document['nftables'][-1]['rule']['expr'][0]['match']['right'] = 'docker0'
            with self.subTest(mutation=mutation), self.assertRaises(r.Rejected): r.validate_guard(document)

    def test_guard_failure_blocks_up_before_compose(self):
        with mock.patch.object(r, 'inventory', return_value={}), mock.patch.object(r, 'guard', side_effect=r.Rejected('guard_missing')), mock.patch.object(r, 'compose') as compose:
            with self.assertRaisesRegex(r.Rejected, 'guard_missing'): r.action('up', 'redis', config(), DockerFixture([]))
            compose.assert_not_called()

    def test_missing_image_does_not_create(self):
        with mock.patch.object(r, 'inventory', return_value={}), mock.patch.object(r, 'guard'), mock.patch.object(r, 'image_present', return_value=False), mock.patch.object(r, 'compose') as compose:
            with self.assertRaisesRegex(r.Rejected, 'image_missing'): r.action('up', 'redis', config(), DockerFixture([]))
            compose.assert_not_called()

    def test_image_override_never_calls_docker(self):
        docker = DockerFixture()
        with self.assertRaisesRegex(r.Rejected, 'image_override_forbidden'):
            r.action('up', 'redis', config(), docker, 'sha256:' + 'f' * 64)
        self.assertEqual(docker.calls, [])

    def test_stop_works_when_guard_missing_and_only_removes_exact_recorded_id(self):
        docker = DockerFixture()
        with mock.patch.object(r, 'receipt', side_effect=lambda lab: rec() if lab == 'redis' else None), mock.patch.object(r, 'guard', side_effect=r.Rejected('guard_missing')) as guard, mock.patch.object(r, 'image_present', return_value=True):
            result = r.action('stop', 'redis', config(), docker)
        self.assertEqual(result['status'], 'not_deployed')
        self.assertIn(('container', 'rm', '1' * 64), docker.calls)
        guard.assert_not_called()

    def test_status_does_not_hide_running_lab_on_guard_failure(self):
        with mock.patch.object(r, 'receipt', return_value=rec()), mock.patch.object(r, 'inventory', return_value={'redis': container()}), mock.patch.object(r, 'image_present', return_value=True), mock.patch.object(r, 'guard', side_effect=r.Rejected('guard_missing')):
            result = r.action('status', 'redis', config(), DockerFixture())
        self.assertEqual(result['status'], 'running')
        self.assertFalse(result['deployment_allowed'])
        self.assertEqual(result['safety_error'], 'guard_missing')

    def test_verifier_contract_rejects_false_readiness_wrong_package_and_attack_claim(self):
        base = {'schema': 1, 'lab': 'redis', 'software_version': '5.0.7', 'package_version': '5:5.0.7-2', 'service_ready': True, 'attack_tested': False}
        r.validate_verification(base, 'redis')
        for key, value in [('schema', True), ('service_ready', False), ('package_version', '5.0.7'), ('attack_tested', True)]:
            changed = {**base, key: value}
            with self.subTest(key=key), self.assertRaises(r.Rejected): r.validate_verification(changed, 'redis')

    def test_verified_running_up_is_idempotent(self):
        with mock.patch.object(r, 'inventory', return_value={'redis': container()}), mock.patch.object(r, 'guard'), mock.patch.object(r, 'image_present', return_value=True), mock.patch.object(r, 'verify_instance', return_value=123), mock.patch.object(r, 'record') as record, mock.patch.object(r, 'receipt', return_value=rec()), mock.patch.object(r, 'compose') as compose:
            result = r.action('up', 'redis', config(), DockerFixture())
        compose.assert_not_called()
        record.assert_called_once_with('redis', '1' * 64, config(), 123)
        self.assertEqual(result['exec_user'], '10001:10001')

    def test_getcontainer_requires_fresh_protocol_verification(self):
        with mock.patch.object(r, 'inventory', return_value={'redis': container()}), mock.patch.object(r, 'guard'), mock.patch.object(r, 'image_present', return_value=True), mock.patch.object(r, 'verify_instance', side_effect=r.Rejected('image_verification_failed')), mock.patch.object(r, 'record') as record:
            with self.assertRaisesRegex(r.Rejected, 'image_verification_failed'):
                r.action('getcontainer', 'redis', config(), DockerFixture())
        record.assert_not_called()

    def test_privileged_shell_or_unknown_lab_not_an_action(self):
        for action, lab in [('exec', 'redis'), ('up', 'unknown'), ('/bin/sh', 'samba')]:
            with self.assertRaises(r.Rejected): r.action(action, lab, config(), DockerFixture())


class BundleTest(unittest.TestCase):
    def test_archive_config_and_oci_ids_both_supported_with_complete_binding(self):
        for oci in (False, True):
            raw, image = archive_bytes(oci=oci)
            self.assertRegex(b.validate_archive(io.BytesIO(raw), image), '[a-f0-9]{64}')

    def test_archive_retagging_other_image_is_forbidden(self):
        raw, image = archive_bytes(tags=['ubuntu:latest'])
        with self.assertRaisesRegex(r.Rejected, 'archive_tags_or_layers'): b.validate_archive(io.BytesIO(raw), image)

    def test_archive_layer_tampering_and_symlinks_are_rejected(self):
        for changes in ({'corrupt_layer': True}, {'link': True}):
            raw, image = archive_bytes(**changes)
            with self.subTest(changes=changes), self.assertRaises(r.Rejected): b.validate_archive(io.BytesIO(raw), image)

    def test_unrelated_archive_image_id_rejected(self):
        raw, _ = archive_bytes()
        with self.assertRaises(r.Rejected): b.validate_archive(io.BytesIO(raw), 'sha256:' + 'f' * 64)

    def test_source_pins_include_terminal_runtime_and_compose(self):
        inputs = {name: b'fixture' for name in r.SOURCE_FILES}
        manifest = {'images': config()['images']}
        result = b.configuration(manifest, inputs)
        self.assertEqual(set(result['source_sha256']), set(r.SOURCE_FILES))
        r.validate_config(result)

    def test_config_cannot_set_command_path_or_unbounded_lab(self):
        for key in ('command', 'binds', 'source_root'):
            changed = config(); changed[key] = 'unsafe'
            with self.subTest(key=key), self.assertRaises(r.Rejected): r.validate_config(changed)
        changed = config(); changed['images']['redis']['image_id'] = 'redis:latest'
        with self.assertRaises(r.Rejected): r.validate_config(changed)

    def test_prior_partial_install_is_not_adopted_or_deleted(self):
        with mock.patch.object(b, 'RECEIPT') as path, mock.patch.object(r, 'read', return_value=b'{"schema":1,"state":"partial"}'):
            path.exists.return_value = True
            with self.assertRaisesRegex(r.Rejected, 'partial_install_requires_operator_review'): b.installed_state()

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(r.Rejected): r.parsed('{"schema":1,"schema":2}')

    def test_oci_index_cannot_import_a_second_unreviewed_image(self):
        raw, image = archive_bytes(oci=True)
        source = io.BytesIO(raw)
        output = io.BytesIO()
        with tarfile.open(fileobj=source) as old, tarfile.open(fileobj=output, mode='w') as new:
            for item in old:
                new.addfile(item, old.extractfile(item))
            index = json.dumps({'schemaVersion': 2, 'manifests': [
                {'digest': image, 'size': 1}, {'digest': 'sha256:' + 'f' * 64, 'size': 1}]}).encode()
            info = tarfile.TarInfo('index.json'); info.size = len(index); new.addfile(info, io.BytesIO(index))
        with self.assertRaisesRegex(r.Rejected, 'archive_multiple_oci_images'):
            b.validate_archive(io.BytesIO(output.getvalue()), image)

    def test_readonly_check_never_applies_and_permits_not_yet_created_console_account(self):
        with mock.patch.object(sys, 'argv', ['bootstrap.py', '--check']), \
             mock.patch.object(b, 'source_inputs', return_value={}), \
             mock.patch.object(b, 'read_bundle', return_value=({}, 'a' * 64)), \
             mock.patch.object(b, 'configuration', return_value=config()), \
             mock.patch.object(r, 'Docker', return_value='docker'), \
             mock.patch.object(b, 'platform_check') as preflight, \
             mock.patch.object(b, 'installed_state', return_value=None), \
             mock.patch.object(b, 'check_vacant') as vacant, \
             mock.patch.object(b, 'apply') as apply, \
             mock.patch.object(r, 'write') as write, \
             mock.patch('builtins.print'):
            b.main()
        preflight.assert_called_once_with('docker', account_required=False)
        vacant.assert_called_once_with('docker')
        apply.assert_not_called()
        write.assert_not_called()

    def test_completed_apply_verifies_without_reinstalling(self):
        with mock.patch.object(sys, 'argv', ['bootstrap.py', '--apply']), \
             mock.patch.object(b, 'source_inputs', return_value={}), \
             mock.patch.object(b, 'read_bundle', return_value=({}, 'a' * 64)), \
             mock.patch.object(b, 'configuration', return_value=config()), \
             mock.patch.object(r, 'Docker', return_value='docker'), \
             mock.patch.object(b, 'platform_check'), \
             mock.patch.object(b, 'installed_state', return_value={'state': 'complete'}), \
             mock.patch.object(b, 'verify_installed', return_value={'state': 'complete'}) as verify, \
             mock.patch.object(b, 'apply') as apply, mock.patch('builtins.print'):
            b.main()
        verify.assert_called_once()
        apply.assert_not_called()

    def test_load_failure_records_partial_phase_and_never_enables_services(self):
        manifest = {'images': {'redis': {'image_id': 'sha256:' + 'a' * 64, 'archive': 'redis-image.tar'}}}
        docker = mock.Mock(binary='/usr/bin/docker')
        fake_file = mock.MagicMock()
        with mock.patch.object(Path, 'mkdir'), mock.patch.object(r, 'write') as write, \
             mock.patch.object(r, 'image_present', return_value=False), \
             mock.patch.object(b, 'read_bundle', return_value=(manifest, 'a' * 64)), \
             mock.patch.object(os, 'open', return_value=99), \
             mock.patch.object(os, 'fdopen', return_value=fake_file), \
             mock.patch.object(b.subprocess, 'run', return_value=mock.Mock(returncode=1)), \
             mock.patch.object(r, 'command') as command:
            with self.assertRaisesRegex(r.Rejected, 'image_load_failed'):
                b.apply(Path('/opt/bundle'), manifest, 'a' * 64, {}, config(), docker)
        command.assert_not_called()
        last = json.loads(write.call_args.args[1])
        self.assertEqual((last['state'], last['phase']), ('partial', 'load_images'))

    def test_first_publication_occurs_after_actual_flock_release(self):
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / 'operation.lock'
            @contextlib.contextmanager
            def installation_lock():
                with lock_path.open('w') as stream:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    yield
            def activation(*args):
                # An independently opened publisher descriptor must acquire the
                # same inode; this fails if main keeps the installation lock.
                with lock_path.open('r') as stream:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return {'state': 'complete'}
            with mock.patch.object(sys, 'argv', ['bootstrap.py', '--apply']), \
                 mock.patch.object(b, 'source_inputs', return_value={}), \
                 mock.patch.object(b, 'read_bundle', return_value=({}, 'a' * 64)), \
                 mock.patch.object(b, 'configuration', return_value=config()), \
                 mock.patch.object(r, 'Docker', return_value='docker'), \
                 mock.patch.object(b, 'platform_check'), \
                 mock.patch.object(b, 'installed_state', return_value=None), \
                 mock.patch.object(b, 'check_vacant'), \
                 mock.patch.object(r, 'operation_lock', installation_lock), \
                 mock.patch.object(b, 'apply', return_value={'state': 'partial'}), \
                 mock.patch.object(b, 'activate', side_effect=activation) as activate, \
                 mock.patch('builtins.print'):
                b.main()
            activate.assert_called_once()

    def test_daemon_restart_preserves_shared_lifecycle_lock_directory(self):
        unit = configparser.ConfigParser(interpolation=None)
        unit.read(HERE / 'terminal.service')
        service = unit['Service']
        self.assertEqual(service['RuntimeDirectory'], r.RUN.name)
        self.assertEqual(service['RuntimeDirectoryMode'], '0750')
        self.assertEqual(service['RuntimeDirectoryPreserve'], 'yes')
        self.assertEqual((service['User'], service['Group']), ('root', 'capstone-labs'))
        self.assertEqual(service['AmbientCapabilities'], 'CAP_SETUID')
        self.assertEqual(service['ProtectHome'], 'tmpfs')
        self.assertEqual(service['TemporaryFileSystem'], '/run/user:ro,mode=0755')
        self.assertEqual(service['BindReadOnlyPaths'], '/run/user/1991')
        self.assertIn('/var/lib/capstone-sudo-runtime/.local/state/capstone-sudo-lab', service['ReadWritePaths'])
        self.assertEqual(service['ExecStopPost'], '/usr/bin/python3 -IB /opt/capstone-nonweb-labs/sudo_terminal.py stop')

    def test_activation_publishes_before_enabling_daemon_or_timer(self):
        events = []
        def command(args, **kwargs):
            events.append(tuple(args[1:]))
            if args[1] == 'start':
                self.assertEqual(kwargs.get('timeout'), 120)
        with mock.patch.object(r, 'write'), mock.patch.object(r, 'executable', return_value='/bin/systemctl'), \
             mock.patch.object(r, 'command', side_effect=command), \
             mock.patch.object(b, 'verify_publication', side_effect=lambda **kw: events.append(('published', kw['require_stopped']))), \
             mock.patch.object(b, 'verify_installed', return_value={'state': 'complete'}):
            result = b.activate({'state': 'partial'}, config(), {}, 'a' * 64, 'docker')
        self.assertEqual(events, [('start', b.PUB_UNIT), ('published', True),
                                  ('enable', '--now', b.TERMINAL_UNIT, b.PUB_TIMER)])
        self.assertEqual(result['state'], 'complete')

    def test_first_publication_failure_leaves_partial_without_daemon_or_timer(self):
        with mock.patch.object(r, 'write') as write, \
             mock.patch.object(r, 'executable', return_value='/bin/systemctl'), \
             mock.patch.object(r, 'command', side_effect=r.Rejected('publication_failed')) as command, \
             mock.patch.object(b, 'verify_installed') as verify:
            with self.assertRaisesRegex(r.Rejected, 'publication_failed'):
                b.activate({'state': 'partial'}, config(), {}, 'a' * 64, 'docker')
        self.assertEqual(command.call_args.args[0], ['/bin/systemctl', 'start', b.PUB_UNIT])
        self.assertEqual(command.call_count, 1)
        verify.assert_not_called()
        last = json.loads(write.call_args.args[1])
        self.assertEqual((last['state'], last['phase']), ('partial', 'initial_publication'))

    def test_publication_requires_fresh_exact_labs_and_stopped_initial_state(self):
        value = {'schema': 1, 'checked_at': 100, 'expires_at': 400,
                 'labs': {x['cve_id']: {'status': 'needs_setup'} for x in r.LABS.values()}}
        with mock.patch.object(b.time, 'time', return_value=101), \
             mock.patch.object(r, 'read', side_effect=lambda *a, **kw: r.json_bytes(value)):
            b.verify_publication(require_stopped=True)
            for changed in ({'expires_at': 100}, {'checked_at': 102}, {'expires_at': 401},
                            {'labs': {}}, {'extra': True}):
                bad = {**value, **changed}
                with self.subTest(changed=changed), mock.patch.object(r, 'read', return_value=r.json_bytes(bad)):
                    with self.assertRaises(r.Rejected): b.verify_publication()
            value['labs']['CVE-2022-0543']['status'] = 'ready'
            b.verify_publication()
            with self.assertRaises(r.Rejected): b.verify_publication(require_stopped=True)
            value['labs']['CVE-2022-0543']['status'] = 'error'
            with self.assertRaises(r.Rejected): b.verify_publication()

    def test_compose_uses_both_distinct_installed_ids_without_pull_or_build(self):
        docker = mock.Mock(binary='/usr/bin/docker')
        with mock.patch.object(r, 'command') as command:
            r.compose(docker, config(), 'redis')
        args = command.call_args.args[0]
        self.assertIn('--no-deps', args)
        self.assertIn('--no-build', args)
        self.assertEqual(args[args.index('--pull') + 1], 'never')
        self.assertEqual(command.call_args.kwargs['env']['REDIS_IMAGE'], config()['images']['redis']['image_id'])
        self.assertEqual(command.call_args.kwargs['env']['SAMBA_IMAGE'], config()['images']['samba']['image_id'])


if __name__ == '__main__':
    unittest.main()
