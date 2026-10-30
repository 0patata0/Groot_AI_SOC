import io
import unittest
from inspect_dedale_flows import ZeekTSV, CSVRecords, connection_key, seconds_us, labeled_seconds_us, assess_session, ntp_request_observation


def tsv(body='1\tu1\n', fields='ts\tuid', types='time\tstring', close=True):
    return (r'#separator \x09'+'\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n#open\tunknown-zone\n#fields\t'+fields+'\n#types\t'+types+'\n'+body+('#close\tunknown-zone\n' if close else '')).encode()


class FlowEvidenceTests(unittest.TestCase):
    def test_field_names_and_unset_values_are_preserved(self):
        p=ZeekTSV(io.BytesIO(tsv('-\t(empty)\n')),path='conn');row=list(p)[0]
        self.assertEqual(row['fields'],{'ts':'-','uid':'(empty)'})
        self.assertTrue(p.complete);self.assertEqual(p.summary()['rows'],1)

    def test_incomplete_close_and_row_width_fail(self):
        for data in [tsv(close=False),tsv('1\tu1\textra\n')]:
            with self.assertRaises(ValueError):list(ZeekTSV(io.BytesIO(data),path='conn'))

    def test_duplicate_header_and_fields_fail(self):
        for data in [tsv().replace(b'#types',b'#path\tconn\n#types'),tsv(fields='ts\tts')]:
            with self.assertRaises(ValueError):list(ZeekTSV(io.BytesIO(data),path='conn'))

    def test_content_after_close_is_not_silently_skipped(self):
        with self.assertRaises(ValueError):list(ZeekTSV(io.BytesIO(tsv()+b'1\tu2\n'),path='conn'))

    def test_csv_multiline_provenance(self):
        data=b'date;label;step;attack_step;tactic;technique;comments\nx;1;1;fixture;t;tech;"line one\nline two"\n'
        p=CSVRecords(io.BytesIO(data));row=list(p)[0]
        self.assertEqual(row['line'],2);self.assertEqual(row['end_line'],3)
        self.assertEqual(row['byte_offset'],data.index(b'\nx;')+1)
        self.assertEqual(row['fields']['comments'],'line one\nline two')

    def test_unknown_csv_label_and_missing_column_fail(self):
        for row in ['x;3;1;a;t;t;c','x;1;1;a;t;t']:
            with self.assertRaises(ValueError):list(CSVRecords(io.BytesIO(('date;label;step;attack_step;tactic;technique;comments\n'+row+'\n').encode())))

    def test_microseconds_are_exact_not_float(self):
        self.assertEqual(seconds_us('1736508842.108849'),1736508842108849)
        for value in ['1.0000001','NaN','-','1e3']:
            with self.assertRaises(ValueError):seconds_us(value)

    def test_labeled_field_mapping_requires_full_raw_fields(self):
        raw={'ts':'1.200000','duration':'0.1','id.orig_h':'192.0.2.1','uid':'a'}
        labeled={'ts':'1.2','duration':'0.100000','ip_src':'192.0.2.1','uid':'a','label':'1'}
        self.assertEqual(connection_key(raw),connection_key(labeled,labeled=True,expected_fields=raw))
        with self.assertRaises(ValueError):connection_key({**labeled,'other':'x'},labeled=True,expected_fields=raw)

    def test_label_scientific_notation_is_exact_without_float_rounding(self):
        raw={'ts':'1736508842.108849','duration':'0.000085','uid':'a'}
        labeled={**raw,'duration':'8.5e-05','label':'1'}
        self.assertEqual(connection_key(raw),connection_key(labeled,labeled=True,expected_fields=raw))
        for value in ['0.10000000000000001','1e10000','1e-10000','NaN','-1']:
            with self.assertRaises(ValueError):labeled_seconds_us(value)

    def test_missing_measurement_does_not_equal_measured_zero(self):
        raw={'ts':'1','duration':'-','orig_bytes':'-','resp_bytes':'-'}
        label={**raw,'duration':'0','orig_bytes':'0','resp_bytes':'0','label':'0'}
        self.assertNotEqual(connection_key(raw),connection_key(label,labeled=True,expected_fields=raw))

    def test_unset_service_does_not_equal_empty_csv_field(self):
        raw={'ts':'1','duration':'1','service':'-'}
        label={**raw,'service':'','label':'0'}
        self.assertNotEqual(connection_key(raw),connection_key(label,labeled=True,expected_fields=raw))

    def session(self):
        conn={'uid':'a','ts':'10.000000','duration':'2.000000','proto':'tcp','id.orig_h':'192.0.2.1','id.orig_p':'123','id.resp_h':'192.0.2.2','id.resp_p':'22'}
        return conn,{**conn,'ts':'10.100000'}

    def test_late_host_event_remains_clock_conflict(self):
        conn,ssh=self.session();r=assess_session(conn,ssh,host_timestamp='1970-01-01T00:00:17Z')
        self.assertFalse(r['host_inside_raw_network_interval']);self.assertEqual(r['host_after_network_end_us'],5000000)
        self.assertEqual(r['clock_adjustment_applied_us'],0)

    def test_reused_uid_wrong_endpoint_is_rejected(self):
        conn,ssh=self.session()
        with self.assertRaises(ValueError):assess_session(conn,{**ssh,'id.orig_p':'124'},host_timestamp='1970-01-01T00:00:11Z')

    def test_missing_duration_cannot_be_replaced_by_zero(self):
        conn,ssh=self.session()
        with self.assertRaises(ValueError):assess_session({**conn,'duration':'-'},ssh,host_timestamp='1970-01-01T00:00:11Z')

    def test_ntp_unsynchronized_observation_is_not_correction(self):
        row={'ts':'10.000000','xmt_time':'16.924000','mode':'3','stratum':'0','ref_id':'INIT'}
        r=ntp_request_observation(row);self.assertEqual(r['declared_transmit_minus_capture_us'],6924000)
        self.assertFalse(r['usable_as_authoritative_clock_correction'])
        with self.assertRaises(ValueError):ntp_request_observation({**row,'mode':'4'})


if __name__=='__main__':unittest.main()
