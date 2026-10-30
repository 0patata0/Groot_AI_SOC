"""Synthetic regression fixtures only; these are not corpus/training examples."""
import copy
import csv
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prepare_linux_apt_cases import read_source, raw_facts, project_records, interpret, DESCRIPTIONS


def row(text, **extra):
    value = {'_source.full_log': text, '_source.rule.id': '203',
             '_source.rule.description': DESCRIPTIONS['203'], '_source.decoder.name': 'wazuh',
             '_source.manager.name': 'private-manager', '_source.agent.id': '007',
             '_source.agent.name': 'private-host',
             '_source.timestamp': 'Oct 7, 2023 @ 19:50:10.853'}
    value.update(extra)
    return value


def source(rows):
    keys = sorted(set().union(*(x.keys() for x in rows)))
    stream = io.StringIO(newline='')
    writer = csv.DictWriter(stream, fieldnames=keys)
    writer.writeheader()
    writer.writerows(rows)
    data = stream.getvalue().encode()
    entry = {'name': 'fixture.csv', 'url': 'https://example.invalid/fixture.csv',
             'bytes': len(data), 'md5': hashlib.md5(data).hexdigest()}
    checked = {'rows': len(rows), 'sha256': hashlib.sha256(data).hexdigest()}
    return data, entry, checked


def evidence(rows):
    records = read_source(*source(rows))
    return project_records(records, list(records))


class CasesTests(unittest.TestCase):
    def test_verified_source_and_multiline_exact_coordinates(self):
        data, entry, checked = source([row('first\nsecond')])
        records = read_source(data, entry, checked)
        binding = records[1][1]
        self.assertEqual((binding['physical_start_line'], binding['physical_end_line']), (2, 3))
        self.assertEqual(binding['csv_record_bytes_sha256'],
                         hashlib.sha256(b''.join(data.splitlines(keepends=True)[1:3])).hexdigest())
        for damaged in (data + b'!', data.replace(b'first', b'wrong')):
            with self.assertRaisesRegex(ValueError, 'integrity'):
                read_source(damaged, entry, checked)

    def test_source_total_cannot_silently_truncate(self):
        data, entry, checked = source([row('record')])
        checked['rows'] = 2
        with self.assertRaisesRegex(ValueError, 'row count'):
            read_source(data, entry, checked)

    def test_coordinates_missing_or_repeated_fail(self):
        records = read_source(*source([row('record')]))
        for numbers in ([2], [1, 1]):
            with self.assertRaisesRegex(ValueError, 'coordinates'):
                project_records(records, numbers)

    def test_clock_unknown_preserved_sorted_without_kst_invention(self):
        values = evidence([row('late', **{'_source.timestamp': 'Oct 7, 2023 @ 20:00:00'}),
                           row('early', **{'_source.timestamp': 'Oct 7, 2023 @ 19:00:00'})])
        self.assertEqual([x['source']['csv_record_number'] for x in values], [2, 1])
        self.assertTrue(all(x['time']['timestamp_kst'] is None for x in values))
        with self.assertRaisesRegex(ValueError, 'clock'):
            evidence([row('changed source format', **{'_source.timestamp': '2023-10-07T19:00:00Z'})])

    def test_entity_aliases_keep_equality_and_do_not_copy_payloads(self):
        values = evidence([row('password=fixture-secret COMMAND=private-command',
                               **{'_source.data.srcip': '192.0.2.123',
                                  '_source.data.dstuser': 'private-account',
                                  '_source.rule.description': 'private-description'}),
                           row('other', **{'_source.data.srcip': '192.0.2.123'})])
        self.assertEqual(values[0]['reported_entities']['source'], values[1]['reported_entities']['source'])
        self.assertIsNone(values[1]['reported_entities']['destination_user'])
        rendered = json.dumps(values)
        for value in ('fixture-secret', 'private-command', 'private-host', '192.0.2.123',
                      'private-account', 'private-manager', 'private-description'):
            self.assertNotIn(value, rendered)

    def test_absent_agent_does_not_merge_into_known_identity(self):
        values = evidence([row("wazuh: Agent buffer: 'normal'.", **{'_source.agent.id': ''})])
        self.assertIsNone(values[0]['reported_entities']['agent'])
        with self.assertRaisesRegex(ValueError, 'agent'):
            interpret('queue', values)

    def test_queue_recovery_is_not_zero_loss_or_backfill(self):
        values = evidence([row("wazuh: Agent buffer: 'full'."),
                           row("wazuh: Agent buffer: 'normal'.",
                               **{'_source.timestamp': 'Oct 7, 2023 @ 19:51:00'})])
        findings, _ = interpret('queue', values)
        self.assertEqual(findings['observed_returns_to_normal'], 1)
        self.assertIsNone(findings['lost_events'])
        self.assertFalse(findings['backfill_verified'])

    def test_flooded_is_recognized_and_unrecovered_is_not_normal(self):
        values = evidence([row("wazuh: Agent buffer: 'flooded'.")])
        self.assertEqual(values[0]['raw_observations']['buffer_state'], 'flooded')
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            interpret('queue', values)
        with self.assertRaisesRegex(ValueError, 'Unrecognized'):
            interpret('queue', evidence([row('unrecognized buffer message')]))

    def test_authentication_missing_pid_or_different_source_rejects_linkage(self):
        rows = []
        for i, text in enumerate(('Invalid user fixture', 'authentication failure',
                                  'Accepted password for fixture', 'Accepted publickey for fixture'), 1):
            rows.append(row(f'sshd[{i}]: {text}',
                            **{'_source.data.srcip': '192.0.2.1',
                               '_source.data.dstuser': 'fixture' if i > 2 else ''}))
        observations = evidence(rows)
        findings, _ = interpret('auth', observations)
        self.assertFalse(findings['compromise_proven'])
        self.assertFalse(findings['same_session_proven'])
        for mutation in ('source', 'pid'):
            changed = copy.deepcopy(observations)
            if mutation == 'source':
                changed[-1]['reported_entities']['source'] = 'source-2'
            else:
                del changed[-1]['raw_observations']['ssh_pid']
            with self.assertRaisesRegex(ValueError, 'relation'):
                interpret('auth', changed)

    def test_deleted_decoder_does_not_override_file_event(self):
        rows = [row(f"File '/private/path' {event}\nMode: realtime",
                    **{'_source.decoder.name': 'syscheck_deleted',
                       '_source.syscheck.event': event}) for event in ('added', 'modified')]
        values = evidence(rows)
        self.assertFalse(interpret('fim', values)[0]['decoder_name_is_deletion_evidence'])
        values[0]['raw_observations']['structured_file_event'] = 'deleted'
        with self.assertRaisesRegex(ValueError, 'FIM'):
            interpret('fim', values)

    def test_apparmor_raw_module_differs_from_selinux_description(self):
        values = evidence([row('type=AVC apparmor="DENIED" operation="capable"',
                               **{'_source.rule.id': '80730',
                                  '_source.rule.description': DESCRIPTIONS['80730']})])
        self.assertEqual(interpret('apparmor', values)[0]['observed_module'], 'AppArmor')

    def test_audit_result_control_separator_does_not_copy_identity(self):
        value = row('type=CONFIG_CHANGE op=add_rule res=1\x1dAUID="private-identity"',
                    **{'_source.data.audit.res': '1\x1dAUID="private-identity"'})
        facts = raw_facts(value)
        self.assertEqual(facts['audit_result'], '1')
        self.assertEqual(facts['structured_audit_result_status'], 'noncanonical')
        self.assertNotIn('private-identity', json.dumps(facts))
        self.assertTrue(interpret('audit_config', evidence([value]))[0]['structured_result_needs_parser_review'])

    def test_daemon_success_does_not_assert_restart_or_attack_success(self):
        findings, _ = interpret('audit_stop', evidence([row('type=DAEMON_END op=terminate res=success')]))
        self.assertFalse(findings['subsequent_restart_verified'])
        self.assertNotIn('attack_success', findings)

    def test_account_order_is_observed_without_invented_approval(self):
        rows = [row(text, **{'_source.timestamp': f'Oct 5, 2023 @ 17:30:2{i}'})
                for i, text in enumerate(('new group:', 'new user:', 'changed user information'))]
        self.assertFalse(interpret('account', evidence(rows))[0]['approval_evidence_present'])

    def test_missing_log_remains_missing(self):
        values = evidence([row(' \t', **{'_source.decoder.name': 'sca'})])
        findings, _ = interpret('missing_raw', values)
        self.assertTrue(findings['raw_log_missing'])
        self.assertFalse(findings['raw_attack_evidence_available'])


if __name__ == '__main__':
    unittest.main()
