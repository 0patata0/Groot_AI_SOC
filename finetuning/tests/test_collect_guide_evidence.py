import csv
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import collect_guide_evidence as G


def csv_stream(records):
    buf = io.StringIO(newline='')
    writer = csv.writer(buf)
    writer.writerow(G.COLUMNS)
    for record in records:
        writer.writerow([record.get(k, '') for k in G.COLUMNS])
    buf.seek(0)
    return buf


class Collection(unittest.TestCase):
    def test_late_rows_and_duplicates_are_retained_with_source_coordinates(self):
        first = {'OrgId': '2', 'IncidentId': '5', 'IncidentGrade': 'TruePositive',
                 'AlertTitle': 'quoted, field\nsecond line'}
        last = dict(first, ActionGrouped='ContainAccount', EntityType='User')
        stream = csv_stream([first, {'OrgId': '9', 'IncidentId': '5'}, first, last])
        out = io.BytesIO()
        result = G.scan(stream, out, {'9'}, modulus=1)
        records = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([r['record_ordinal'] for r in records], [1, 3, 4])
        self.assertEqual([r['record'] for r in records],
                         [{k: r.get(k, '') for k in G.COLUMNS} for r in [first, first, last]])
        self.assertEqual(result['selected_incidents'], 1)
        self.assertEqual(result['selected_duplicate_records_preserved'], 1)
        self.assertTrue(result['transport_eof_must_be_verified_separately'])
        self.assertGreater(records[0]['csv_end_line'], 2)

    def test_same_incident_id_in_different_orgs_is_not_merged(self):
        result = G.scan(csv_stream([{'OrgId':'1','IncidentId':'5'},
                                   {'OrgId':'2','IncidentId':'5'}]), io.BytesIO(), set(), modulus=1)
        self.assertEqual(result['selected_incidents'], 2)

    def test_conflicting_and_missing_labels_are_preserved_not_normalized(self):
        records = [{'OrgId':'1','IncidentId':'5','IncidentGrade':x}
                   for x in ['TruePositive','FalsePositive','']]
        result = G.scan(csv_stream(records), io.BytesIO(), set(), modulus=1)
        group = result['groups'][0]
        self.assertTrue(group['conflicting_nonempty_grades'])
        self.assertEqual(group['grades'][''], 1)
        self.assertEqual(group['rows'], 3)

    def test_output_limit_does_not_claim_success_or_silently_drop_rows(self):
        with self.assertRaisesRegex(ValueError, 'output limit'):
            G.scan(csv_stream([{'OrgId':'1','IncidentId':'5'}]), io.BytesIO(), set(),
                   modulus=1, output_limit=1)

    def test_invalid_key_or_width_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'incident key'):
            G.scan(csv_stream([{'OrgId':'1','IncidentId':''}]), io.BytesIO(), set())
        stream=csv_stream([])
        stream.seek(0, 2);stream.write('1,2\n');stream.seek(0)
        with self.assertRaisesRegex(ValueError, 'CSV width'):
            G.scan(stream, io.BytesIO(), set())

    def test_reserved_org_always_excluded_and_selection_is_stable(self):
        self.assertFalse(G.selected_key('1','5',{'1'},modulus=1))
        self.assertEqual(G.selected_key('2','5',set()), G.selected_key('2','5',set()))
        self.assertTrue(G.selected_key('1','5',set(),modulus=1))

    def test_ranking_schema_and_per_org_coverage(self):
        data=('OrgId,IncidentId,QueueRank\n'+''.join(
            f'{org},{rank},{rank}\n' for org in range(499) for rank in range(1,21))).encode()
        with patch.object(G,'RANK_BYTES',len(data)), patch.object(G,'RANK_SHA',G.sha(data)):
            self.assertEqual(len(G.reserved_organizations(data)),499)
        for wrong in [data.replace(b'QueueRank', b'Rank'), data.replace(b'0,2,2\n',b'0,1,2\n')]:
            with patch.object(G,'RANK_BYTES',len(wrong)), patch.object(G,'RANK_SHA',G.sha(wrong)):
                with self.assertRaises(ValueError):G.reserved_organizations(wrong)


class Transport(unittest.TestCase):
    def read(self, actual, expected, prefix=b'abcd', deadline=None):
        raw=G.VerifiedReader(io.BytesIO(actual),expected,G.sha(prefix),prefix_bytes=4,
                             deadline=deadline)
        data=io.BufferedReader(raw,buffer_size=3).read()
        return raw,data

    def test_eof_and_full_digest(self):
        raw,data=self.read(b'abcdefg',7)
        self.assertEqual(data,b'abcdefg')
        self.assertTrue(raw.complete)
        self.assertEqual(raw.digest.hexdigest(),hashlib.sha256(data).hexdigest())

    def test_truncation_oversize_and_prefix_change_fail(self):
        for actual,expected in [(b'abcde',7),(b'abcdefgh',7),(b'xbcdxyz',7)]:
            with self.assertRaises(ValueError):self.read(actual,expected)

    def test_elapsed_deadline_fails_instead_of_accepting_partial(self):
        with self.assertRaises(TimeoutError):self.read(b'abcdefg',7,deadline=0)


if __name__ == '__main__':
    unittest.main()
