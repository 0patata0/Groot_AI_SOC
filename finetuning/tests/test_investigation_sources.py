import hashlib
import io
from pathlib import Path
import stat
import sys
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from collect_defensive_sources import select_path
from collect_excytin_evidence import RemoteZip, member_record, selected, validate_range, csv_records, verify_metadata
from collect_investigation_traces import verify
from review_investigation_sources import incident_id, partition, separate_labels, trace_stats, target_present, capture_label, quarantine_observable_duplicates, incident_components
from prepare_investigation_candidates import scrub_secrets, normalize_row, eligible_question


class InvestigationSourceTests(unittest.TestCase):
    def test_source_license_cannot_silently_change(self):
        value=b'license';verify_metadata(value,hashlib.sha256(value).hexdigest())
        with self.assertRaises(ValueError):verify_metadata(b'changed',hashlib.sha256(value).hexdigest())

    def test_shared_alert_families_link_transitively(self):
        self.assertEqual(incident_components({'a':{'x'},'b':{'x','y'},'c':{'y'},'d':{'z'}}),[['a','b','c'],['d']])

    def test_preparation_excludes_leaked_or_provider_test_rows(self):
        row={'provisional_partition':'training_source_candidate','issues':[],
             'target_text_present_in_selected_logs':True,'training_admitted':False}
        self.assertTrue(eligible_question(row))
        self.assertFalse(eligible_question({**row,'issues':['target_already_in_input']}))
        self.assertFalse(eligible_question({**row,'provisional_partition':'provider_test_excluded_from_training'}))

    def test_embedded_json_labels_secrets_and_empty_values(self):
        result, labels, redactions=normalize_row({'Entities':'[{"AttackTechnique":"T0000","ClientSecret":"fixture-secret"}]','missing':''})
        self.assertIsNone(result['missing'])
        self.assertEqual(len(labels),1)
        self.assertEqual(len(redactions),1)
        self.assertEqual(result['Entities'][0]['ClientSecret'],'[REDACTED_CREDENTIAL_FIELD]')
        with self.assertRaises(ValueError):normalize_row({'Entities':'[{malformed'})

    def test_duplicate_observation_across_partition_held(self):
        rows = [{'input':{'event':'same'},'provisional_partition':'training'},
                {'input':{'event':'same'},'provisional_partition':'evaluation'}]
        result = quarantine_observable_duplicates(rows)
        self.assertEqual(result['cross_partition_rows_held'], 2)
        self.assertIn('cross_partition_observable_overlap', rows[0]['issues'])

    def test_target_ip_boundary_not_substring(self):
        self.assertFalse(target_present('1.2.3.4', '11.2.3.40'))
        self.assertTrue(target_present('1.2.3.4', 'address="1.2.3.4"'))
        self.assertFalse(target_present('a@example.test', 'aa@example.test'))

    def test_capture_label_contract_not_freeform_success_guess(self):
        self.assertEqual(capture_label('Attack 1 detected'), capture_label('Attack 1'))
        self.assertNotEqual(capture_label('Maybe Attack 1 detected'), capture_label('Attack 1'))
        self.assertNotEqual(capture_label('Attack 10 detected'), capture_label('Attack 1'))

    def test_provider_csv_delimiter_multiline_and_source_line(self):
        data = '\ufeffA❖B\n1❖"a,b\ncontinued"\n2❖value\n'.encode()
        parsed = csv_records(data)
        self.assertEqual(parsed[0], (2, {'A':'1','B':'a,b\ncontinued'}))
        self.assertEqual(parsed[1][0], 4)
        for bad in ('A,B\n1,2\n', 'A❖A\n1❖2\n', 'A❖B\n1❖2❖3\n', 'A❖B\n1\n'):
            with self.assertRaises(ValueError): csv_records(bad.encode())

    def test_defensive_selection_excludes_attack_execution(self):
        prefix = 'domains/eval_ranges/saber_sim_incident_34_v1/'
        self.assertTrue(select_path('microsoft_aces', prefix+'tasks/incident_34_v1_remediation.yaml'))
        self.assertTrue(select_path('microsoft_aces', prefix+'docker/scenarios/incident_34_v1/inputs/attack_corpus/AuditLogs.json'))
        for p in ('tasks/incident_34_v1_attack.yaml', 'tools/incident_34_v1/attack_chain.yaml', 'setup.py'):
            self.assertFalse(select_path('microsoft_aces', prefix+p))
        self.assertFalse(select_path('microsoft_aces', 'domains/excytin/tasks/legacy_train_set/incident_34/x.yaml'))

    def test_range_requires_206_and_exact_bounds(self):
        validate_range(206, 'bytes 4-7/10', 4, 7, 10)
        for status, header in ((200, None), (206, 'bytes 0-3/10'), (206, 'bytes 4-7/11')):
            with self.subTest(status=status, header=header), self.assertRaises(ValueError):
                validate_range(status, header, 4, 7, 10)

    def test_range_budget_prevents_whole_archive_fetch(self):
        remote = RemoteZip(size=100, budget=10)
        with self.assertRaises(ValueError): remote.read()
        with self.assertRaises(ValueError): remote.seek(-1)
        self.assertEqual(remote.seek(-2, 2), 98)

    def test_zip_paths_and_symlinks_rejected(self):
        for name in ('../out.csv', '/out.csv', 'a/../out.csv'):
            with self.assertRaises(ValueError): member_record(zipfile.ZipInfo(name))
        item = zipfile.ZipInfo('data.csv'); item.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(ValueError): member_record(item)
        item = zipfile.ZipInfo('data.csv'); item.flag_bits = 1
        with self.assertRaises(ValueError): member_record(item)

    def test_only_selected_evidence_tables(self):
        self.assertTrue(selected('data/csv_files/incident_34/SecurityAlert.csv'))
        self.assertFalse(selected('data/sql_files/incident_34.sql'))
        self.assertFalse(selected('data/csv_files/incident_34/DeviceEvents.csv'))

    def test_hf_git_and_lfs_integrity(self):
        data = b'{"messages": []}\n'
        git = hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        verify(data, {'size': len(data), 'oid': git})
        verify(data, {'size': len(data), 'lfs': {'size': len(data), 'oid': hashlib.sha256(data).hexdigest()}})
        with self.assertRaises(ValueError): verify(data, {'size':len(data), 'oid':'0'*40})
        with self.assertRaises(ValueError): verify(data+b' ', {'size':len(data), 'oid':git})

    def test_incident_variants_stay_with_base_case(self):
        self.assertEqual(incident_id('domains/eval_ranges/saber_sim_incident_134_v5/tasks/x.yaml'), '134')
        self.assertEqual(incident_id('data/csv_files/incident_134/AlertInfo.csv'), '134')
        self.assertEqual(partition('134', 'train'), 'reserved_evaluation_family')
        self.assertEqual(partition('134', 'test'), 'reserved_evaluation_family')
        self.assertEqual(partition('34', 'test'), 'provider_test_excluded_from_training')
        self.assertEqual(partition('34', 'train'), 'training_source_candidate')

    def test_labels_removed_recursively_and_kept_separately(self):
        original = {'AttackTechnique':'T0000', 'Nested':[{'Techniques':['T0001'], 'Operation':'read'}],
                    'SensitivityLabel':'confidential', 'ResultType':'Success'}
        observable, labels = separate_labels(original)
        self.assertEqual(len(labels), 2)
        self.assertNotIn('AttackTechnique', observable)
        self.assertNotIn('Techniques', observable['Nested'][0])
        self.assertEqual(observable['ResultType'], 'Success')
        self.assertEqual(observable['SensitivityLabel'], 'confidential')
        self.assertIn('AttackTechnique', original)

    def test_completed_tool_is_not_exit_success(self):
        value = {'messages':[{'parts':[
            {'type':'tool', 'tool':'bash', 'callID':'a', 'state':{'status':'completed','input':{},'output':'failed','metadata':{'exit':2}}},
            {'type':'tool', 'tool':'bash', 'callID':'b', 'state':{'status':'error','input':{},'error':'unavailable'}},
            {'type':'tool', 'tool':'bash', 'callID':'c', 'state':{'status':'completed','input':{},'output':'ok'}}]}]}
        stats = trace_stats(value)
        self.assertEqual(stats['tool_calls'], 3)
        self.assertEqual(stats['input_output_pairs'], 2)
        self.assertEqual(stats['nonzero_exit'], 1)
        self.assertEqual(stats['explicit_errors'], 1)
        self.assertEqual(stats['unknown_exit'], 2)

    def test_duplicate_tool_call_identity_is_held(self):
        part = {'type':'tool','callID':'same','tool':'bash','state':{}}
        self.assertTrue(trace_stats({'messages':[{'parts':[part,part]}]})['issues'])


if __name__ == '__main__': unittest.main()
