"""Synthetic boundary checks, using the recorded B profile without secrets."""
import copy
import json
from pathlib import Path
import unittest

import hermes_prestart_contract as contract

NEW_ID = 'b' * 64
NEW_NAME = 'hermes-prestart-0123456789ab'
OLD_NAME = 'hermes-retained-0123456789ab'


def fixture():
    record = json.loads((Path(__file__).parents[1] / 'automation/ansible/'
                        'hermes-prestart-inspect-2026-10-14.json').read_text())
    config = record['container_config']
    config.pop('hostname_is_container_prefix')
    config.pop('label_keys')
    config.update(Hostname=contract.OLD_ID[:12], Image=contract.IMAGE_TAG,
                  Labels={'org.opencontainers.image.revision': 'synthetic-revision'},
                  Env=['HERMES_HOME=/opt/data', 'HERMES_UID=995', 'HERMES_GID=986',
                       'SYNTHETIC_SECRET=never-print-this'])
    host = record['host_config']
    host['ConsoleSize'] = [0, 0]
    old = {'Id': contract.OLD_ID, 'Image': contract.IMAGE, 'Name': '/hermes',
           'Config': config, 'HostConfig': host,
           'State': {'Running': True, 'OOMKilled': False, 'Restarting': False,
                     'Paused': False, 'Dead': False, 'Pid': 123, 'Status': 'running',
                     'StartedAt': '2026-10-13T16:37:16.547543503Z'},
           'Mounts': [{'Type': 'bind', 'Source': '/opt/hermes-data', 'Destination': '/opt/data',
                       'RW': True, 'Propagation': 'rprivate', 'Mode': ''}],
           'NetworkSettings': {'Networks': {'bridge': {'IPAMConfig': None, 'Aliases': None,
                'Links': None, 'DriverOpts': None, 'GwPriority': 0, 'IPAddress': '172.17.0.2'}}}}
    new = copy.deepcopy(old)
    new.update(Id=NEW_ID, Name='/' + NEW_NAME)
    new['Config'].update(Hostname=NEW_ID[:12], Image=contract.IMAGE)
    new['Config'].update(AttachStdout=True, AttachStderr=True)
    new['HostConfig']['OomKillDisable'] = False
    new['State'].update(Running=False, Pid=0, Status='created', StartedAt='0001-01-01T00:00:00Z')
    new['NetworkSettings']['Networks']['bridge']['IPAddress'] = ''
    return old, new


class PrestartContractTests(unittest.TestCase):
    def compare(self, old, new):
        return contract.validate_created(old, new, expected_new_id=NEW_ID, expected_name=NEW_NAME)

    def recover(self, old, new, **changes):
        args = dict(expected_new_id=NEW_ID, protected_unchanged=True, database_ok=True,
                    retained_name=OLD_NAME, candidate_name=NEW_NAME)
        args.update(changes)
        return contract.recovery_decision(old, new, **args)

    def test_recorded_profile_and_created_equivalence(self):
        old, new = fixture()
        self.assertTrue(self.compare(old, new)['never_started'])
        new['Config']['Env'].reverse()
        self.assertTrue(self.compare(old, new)['equivalent'])

    def test_wrong_image_mount_environment_or_host_option_refused(self):
        for field in ('image', 'bind', 'environment', 'privileged', 'new_unknown'):
            with self.subTest(field=field):
                old, new = fixture()
                if field == 'image': new['Image'] = 'sha256:' + 'c' * 64
                if field == 'bind': new['Mounts'][0]['Source'] = '/other-data'
                if field == 'environment': new['Config']['Env'][-1] = 'SYNTHETIC_SECRET=different'
                if field == 'privileged': new['HostConfig']['Privileged'] = True
                if field == 'new_unknown': new['HostConfig']['UnexpectedFeature'] = 1
                with self.assertRaises(contract.ContractError): self.compare(old, new)

    def test_only_complete_typed_native_cli_defaults_are_accepted(self):
        for section,key,value in [('Config','AttachStdout',False),('Config','AttachStderr',False),
                                  ('Config','AttachStdout',1),('Config','AttachStderr',1),
                                  ('HostConfig','OomKillDisable',None),('HostConfig','OomKillDisable',0),
                                  ('HostConfig','OomKillDisable',True)]:
            with self.subTest(section=section,key=key,value=value):
                old,new=fixture();new[section][key]=value
                with self.assertRaisesRegex(contract.ContractError,'candidate_cli_defaults_mismatch'):
                    self.compare(old,new)

    def test_candidate_defaults_do_not_relax_stdin_tty_or_original(self):
        for key in ('AttachStdin','OpenStdin','StdinOnce','Tty'):
            old,new=fixture();new['Config'][key]=True
            with self.assertRaises(contract.ContractError):self.compare(old,new)
        for section,key,value in [('Config','AttachStdout',True),('Config','AttachStderr',True),
                                  ('HostConfig','OomKillDisable',False)]:
            old,new=fixture();old[section][key]=value
            with self.assertRaises(contract.ContractError):self.compare(old,new)

    def test_candidate_mapping_preserves_both_original_inspect_objects(self):
        old,new=fixture();before=copy.deepcopy((old,new))
        self.compare(old,new)
        self.assertEqual((old,new),before)
        with self.assertRaisesRegex(contract.ContractError,'candidate_is_original'):
            contract.candidate_comparison_fields(old)

    def test_unknown_nondefault_baseline_option_refused(self):
        old, _ = fixture()
        old['HostConfig']['UnreviewedMount'] = {'path': '/unexpected'}
        with self.assertRaisesRegex(contract.ContractError, '^unknown_host_option$'):
            contract.validate_baseline(old)

    def test_boolean_integer_confusion_and_nonfinite_values_refused(self):
        old, new = fixture()
        new['HostConfig']['Privileged'] = 0
        with self.assertRaises(contract.ContractError): self.compare(old, new)
        old['HostConfig']['Unknown'] = float('nan')
        with self.assertRaises(contract.ContractError): contract.validate_baseline(old)

    def test_duplicate_or_multiline_environment_refused_without_value_in_error(self):
        for values in (['TOKEN=synthetic-secret', 'TOKEN=other'], ['TOKEN=secret\ntrailing']):
            with self.assertRaises(contract.ContractError) as caught:
                contract.environment(values)
            self.assertEqual(str(caught.exception), 'invalid_environment')

    def test_ever_started_or_ambiguous_candidate_refused(self):
        for key, value in (('StartedAt', '2026-10-14T00:00:00Z'), ('Running', True),
                           ('Restarting', True), ('Pid', 42), ('Status', 'exited')):
            with self.subTest(key=key):
                old, new = fixture(); new['State'][key] = value
                with self.assertRaises(contract.ContractError): self.compare(old, new)

    def test_new_must_be_proven_stopped_before_any_old_recovery(self):
        for state in ({'Running': True}, {'Restarting': True}, {'Pid': 42},
                      {'Status': 'restarting'}, {'Paused': True}, {'Dead': True}):
            old, new = fixture(); new['State'].update(state)
            self.assertEqual(self.recover(old, new)['intent'], 'manual_review')
        old, new = fixture(); del new['State']['Running']
        self.assertEqual(self.recover(old, new)['intent'], 'manual_review')

    def test_rollback_retains_database_and_handles_already_running_old(self):
        old, new = fixture()
        self.assertEqual(self.recover(old, new), {'intent': 'keep_original', 'database_restore': False})
        old['Name'] = '/' + OLD_NAME
        old['State'].update(Running=False, Pid=0, Status='exited')
        new['Name'] = '/hermes'
        self.assertEqual(self.recover(old, new),
                         {'intent': 'restore_original_name_then_start', 'database_restore': False})

    def test_protected_drift_bad_database_or_name_conflict_require_manual_review(self):
        old, new = fixture()
        for changes in ({'protected_unchanged': False}, {'database_ok': False},
                        {'protected_unchanged': 1}):
            self.assertEqual(self.recover(old, new, **changes)['intent'], 'manual_review')
        new['Name'] = '/hermes'
        self.assertEqual(self.recover(old, new)['intent'], 'manual_review')


if __name__ == '__main__':
    unittest.main()
